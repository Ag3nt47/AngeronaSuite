// frz_watchdog.go — FRZ external watchdog for Angerona Anti-Suspension Heartbeat.
//
// Build:
//     cd AngeronaSuite/frz
//     go build -ldflags="-s -w" -o ../frz_watchdog.exe frz_watchdog.go
//
// Usage (launched by frz_heartbeat.py):
//     frz_watchdog.exe <target_pid> <mmap_path>
//
// Behaviour:
//     Every POLL_MS milliseconds:
//       1. Check that <target_pid> is still running.
//          If not → exit cleanly (normal shutdown).
//       2. Read the uint64 nanosecond timestamp at offset 0 of <mmap_path>.
//          Also read the uint32 flag at offset 12: flag=0 means clean shutdown.
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
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	POLL_MS           = 250             // polling interval
	FREEZE_THRESHOLD  = 2 * time.Second // clock-frozen window before action
	MMAP_SIZE         = 16             // bytes: uint64 ts + uint32 pid + uint32 flag
	TS_OFFSET         = 0
	PID_OFFSET        = 8
	FLAG_OFFSET       = 12
)

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

// ── mmap read ────────────────────────────────────────────────────────────────
// We use Windows file mapping to read the shared region independently of Python.
func readMmapTimestamp(path string) (tsNs uint64, flag uint32, err error) {
	pathw, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
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
		return 0, 0, err
	}
	defer windows.CloseHandle(fh)

	mh, err := windows.CreateFileMapping(fh, nil, windows.PAGE_READONLY, 0, MMAP_SIZE, nil)
	if err != nil {
		return 0, 0, err
	}
	defer windows.CloseHandle(mh)

	addr, err := windows.MapViewOfFile(mh, windows.FILE_MAP_READ, 0, 0, MMAP_SIZE)
	if err != nil {
		return 0, 0, err
	}
	defer windows.UnmapViewOfFile(addr)

	buf := (*[MMAP_SIZE]byte)(unsafe.Pointer(addr))[:]
	tsNs = binary.LittleEndian.Uint64(buf[TS_OFFSET : TS_OFFSET+8])
	flag = binary.LittleEndian.Uint32(buf[FLAG_OFFSET : FLAG_OFFSET+4])
	return tsNs, flag, nil
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
		fmt.Fprintln(os.Stderr, "usage: frz_watchdog.exe <pid> <mmap_path>")
		os.Exit(1)
	}
	pidArg, err := strconv.ParseUint(os.Args[1], 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad pid: %v\n", err)
		os.Exit(1)
	}
	targetPID := uint32(pidArg)
	mmapPath := os.Args[2]

	var lastTS atomic.Uint64
	frozenSince := time.Time{}

	ticker := time.NewTicker(POLL_MS * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if !pidAlive(targetPID) {
			// Target exited cleanly.
			os.Exit(0)
		}

		tsNs, flag, err := readMmapTimestamp(mmapPath)
		if err != nil {
			// mmap not ready yet — skip
			continue
		}
		if flag == 0 {
			// Clean shutdown signal written by Python
			os.Exit(0)
		}

		prev := lastTS.Swap(tsNs)
		if tsNs != prev {
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
				time.Since(frozenSince).Seconds(), tsNs)
			writeAlert(mmapPath, targetPID, reason)
			isolateNetwork()
			killTarget(targetPID)
			fmt.Printf("FRZ: emergency action taken — %s\n", reason)
			os.Exit(2)
		}
	}
}
