// frz_watchdog.go — FRZ external watchdog for Angerona Anti-Suspension Heartbeat.
//
// Build:
//     cd AngeronaSuite/frz
//     build.bat
//
// Usage (launched by frz_heartbeat.py):
//     frz_watchdog_v2.exe <target_pid> <mmap_path>
//
// Behaviour:
//     Every POLL_MS milliseconds:
//       1. Check that <target_pid> is still running.
//          If not → exit cleanly (normal shutdown).
//       2. Read and authenticate the fixed v2 heartbeat record using the
//          protected shutdown.key beside <mmap_path>. Invalid/legacy records
//          fail closed without authorizing a kill or clean-stop decision.
//       3. If the timestamp has NOT advanced for FREEZE_THRESHOLD_S seconds AND
//          the flag is 1 (running) → thread-suspension attack assumed → trigger:
//             a. netsh emergency network isolation (blocks all but loopback).
//             b. taskkill /F on the target PID.
//             c. Write a one-line alert to <mmap_dir>/frz_alert.txt.
//             d. This process exits.
//
// Security notes:
//   - Runs as a DETACHED_PROCESS; not in the Python process group, so a
//     TerminateJobObject on the parent job does not kill this watchdog.
//   - Network isolation targets all profiles, keeps loopback (127.x.x.x) reachable
//     so Ollama (:11434) and local IPC (:65432) survive.
//   - This binary must be code-signed in production to prevent tampering.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	POLL_MS            = 250             // polling interval
	FREEZE_THRESHOLD   = 2 * time.Second // clock-frozen window before action
	MMAP_SIZE          = 32
	MAGIC              = uint32(0x41574447) // "AWDG"
	FLAG_RUNNING       = uint32(0x00000001)
	FLAG_V2_AUTH       = uint32(0x80000000)
	FLAG_KNOWN         = FLAG_RUNNING | FLAG_V2_AUTH
	heartbeatComponent = "frz-core"
)

var authContext = []byte("angerona-resilience-heartbeat-v2\x00")

// ── pid liveness (Windows API) ───────────────────────────────────────────────
func pidAlive(pid uint32) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	err = windows.GetExitCodeProcess(handle, &code)
	if err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

// ── emergency isolation ──────────────────────────────────────────────────────
func isolateNetwork() {
	// Block all inbound + outbound except loopback.
	// netsh sets the policy immediately; does NOT require a reboot.
	cmd := exec.Command("netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", "blockinbound,blockoutbound")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()

	// Allow-rule for loopback so Ollama and IPC remain reachable.
	loopback := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=Angerona-FRZ-Loopback",
		"dir=out", "action=allow",
		"remoteip=127.0.0.0/8",
		"enable=yes", "profile=any")
	loopback.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = loopback.Run()
}

func killTarget(pid uint32) {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(handle)
	_ = windows.TerminateProcess(handle, 1)
}

type heartbeatRecord struct {
	magic   uint32
	tsNs    uint64
	pid     uint32
	proof   uint64
	counter uint32
	flags   uint32
}

// ── mmap read ────────────────────────────────────────────────────────────────
// We use Windows file mapping to read the shared region independently of Python.
func readMmapRecord(path string) (record heartbeatRecord, err error) {
	pathw, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return record, err
	}
	fh, err := windows.CreateFile(
		pathw,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return record, err
	}
	defer windows.CloseHandle(fh)

	mh, err := windows.CreateFileMapping(fh, nil, windows.PAGE_READONLY, 0, MMAP_SIZE, nil)
	if err != nil {
		return record, err
	}
	defer windows.CloseHandle(mh)

	addr, err := windows.MapViewOfFile(mh, windows.FILE_MAP_READ, 0, 0, MMAP_SIZE)
	if err != nil {
		return record, err
	}
	defer windows.UnmapViewOfFile(addr)

	buf := (*[MMAP_SIZE]byte)(unsafe.Pointer(addr))[:]
	record.magic = binary.LittleEndian.Uint32(buf[0:4])
	record.tsNs = binary.LittleEndian.Uint64(buf[4:12])
	record.pid = binary.LittleEndian.Uint32(buf[12:16])
	record.proof = binary.LittleEndian.Uint64(buf[16:24])
	record.counter = binary.LittleEndian.Uint32(buf[24:28])
	record.flags = binary.LittleEndian.Uint32(buf[28:32])
	return record, nil
}

func loadAuthority(mmapPath string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(mmapPath), "shutdown.key"))
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("shutdown authority is malformed")
	}
	return key, nil
}

func componentKey(authority []byte) []byte {
	mac := hmac.New(sha256.New, authority)
	mac.Write(authContext)
	mac.Write([]byte(heartbeatComponent))
	return mac.Sum(nil)
}

func authenticateRecord(record heartbeatRecord, authority []byte, targetPID uint32) bool {
	if record.magic != MAGIC || record.pid != targetPID || record.flags&FLAG_V2_AUTH == 0 {
		return false
	}
	if record.flags & ^FLAG_KNOWN != 0 {
		return false
	}
	component := []byte(heartbeatComponent)
	payload := make([]byte, 2+len(component)+8+4+4+4)
	binary.LittleEndian.PutUint16(payload[0:2], uint16(len(component)))
	copy(payload[2:], component)
	offset := 2 + len(component)
	binary.LittleEndian.PutUint64(payload[offset:offset+8], record.tsNs)
	offset += 8
	binary.LittleEndian.PutUint32(payload[offset:offset+4], record.pid)
	offset += 4
	binary.LittleEndian.PutUint32(payload[offset:offset+4], record.counter)
	offset += 4
	binary.LittleEndian.PutUint32(payload[offset:offset+4], record.flags)

	mac := hmac.New(sha256.New, componentKey(authority))
	mac.Write(payload)
	expected := mac.Sum(nil)[:8]
	actual := make([]byte, 8)
	binary.LittleEndian.PutUint64(actual, record.proof)
	return hmac.Equal(actual, expected)
}

// ── alert file ───────────────────────────────────────────────────────────────
func writeAlert(mmapPath string, pid uint32, reason string) {
	alertPath := filepath.Join(filepath.Dir(mmapPath), "frz_alert.txt")
	line := fmt.Sprintf("[%s] FRZ TRIGGERED: PID %d — %s\n",
		time.Now().UTC().Format(time.RFC3339), pid, reason)
	_ = os.WriteFile(alertPath, []byte(line), 0644)
}

// ── main ─────────────────────────────────────────────────────────────────────
func main() {
	runtime.LockOSThread()

	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: frz_watchdog_v2.exe <pid> <mmap_path>")
		os.Exit(1)
	}
	pidArg, err := strconv.ParseUint(os.Args[1], 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad pid: %v\n", err)
		os.Exit(1)
	}
	targetPID := uint32(pidArg)
	mmapPath := os.Args[2]
	authority, err := loadAuthority(mmapPath)
	if err != nil {
		writeAlert(mmapPath, targetPID, "authenticated v2 heartbeat unavailable: "+err.Error())
		fmt.Fprintln(os.Stderr, "FRZ: refusing unauthenticated heartbeat:", err)
		os.Exit(3)
	}

	var lastTS uint64
	var lastCounter uint32
	frozenSince := time.Time{}

	ticker := time.NewTicker(POLL_MS * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if !pidAlive(targetPID) {
			// Target exited cleanly.
			os.Exit(0)
		}

		record, err := readMmapRecord(mmapPath)
		if err != nil {
			// mmap not ready yet — skip
			continue
		}
		if !authenticateRecord(record, authority, targetPID) {
			writeAlert(mmapPath, targetPID,
				"legacy, forged, or malformed heartbeat rejected; no control action authorized")
			fmt.Fprintln(os.Stderr, "FRZ: rejected unauthenticated heartbeat")
			os.Exit(3)
		}
		if record.flags&FLAG_RUNNING == 0 {
			// Clean shutdown signal written by Python
			os.Exit(0)
		}

		if lastTS != 0 && (record.tsNs < lastTS ||
			(record.tsNs == lastTS && record.counter < lastCounter)) {
			writeAlert(mmapPath, targetPID,
				"authenticated heartbeat replay/regression rejected; no control action authorized")
			fmt.Fprintln(os.Stderr, "FRZ: rejected replayed heartbeat")
			os.Exit(3)
		}
		advanced := record.tsNs > lastTS || record.counter != lastCounter
		lastTS = record.tsNs
		lastCounter = record.counter
		if advanced {
			// Clock is advancing — reset frozen timer
			frozenSince = time.Time{}
			continue
		}

		// Timestamp unchanged
		if frozenSince.IsZero() {
			frozenSince = time.Now()
			continue
		}
		if time.Since(frozenSince) >= FREEZE_THRESHOLD {
			reason := fmt.Sprintf("heartbeat frozen for %.1fs (last ts=%d)",
				time.Since(frozenSince).Seconds(), record.tsNs)
			writeAlert(mmapPath, targetPID, reason)
			isolateNetwork()
			killTarget(targetPID)
			fmt.Printf("FRZ: emergency action taken — %s\n", reason)
			os.Exit(2)
		}
	}
}
