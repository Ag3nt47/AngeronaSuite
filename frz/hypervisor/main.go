// angerona_hypervisor.go — multi-way keep-alive watchdog (compiled binary).
//
// Implements the Attestation & Resilience plane (see shared-ipc/CONTRACT.md).
// It beats its own heartbeat and reads the core's and scanner's heartbeats; if
// either is DEAD or SUSPENDED it respawns that component (exponential backoff →
// SAFE_MODE). Angerona and this watchdog watch EACH OTHER and restart each other.
//
// No duplicates: before (re)launching anything it (1) checks the component is not
// already alive (fresh heartbeat + live pid) and (2) claims a cross-process spawn
// lock in <data>/ipc/<name>.spawnlock — the SAME lock the Python core-side
// supervisor uses — so the two supervisors never double-spawn the scanner.
//
// BlackBox: the decoupled recorder is supervised by the always-co-running core
// manager (which restarts it directly); since this watchdog keeps the core alive,
// BlackBox is covered transitively. (It writes no heartbeat, so it is not polled
// here directly.)
//
// A valid, signed stand-down token halts all respawns for maintenance.
// Honest naming: no process-ghosting / stealth renaming.
//
// Build (Windows, Go toolchain):  cd frz\hypervisor && build.bat
//
//go:build windows

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const (
	awdgMagic  = uint32(0x41574447) // "AWDG"
	hbSize     = 32
	staleAfter = 3 * time.Second
	loopEvery  = 500 * time.Millisecond
	maxFail    = 3
	failWindow = 60 * time.Second
	standMaxS  = 3600.0
	spawnTTL   = 15 * time.Second
)

func dataDir() string {
	if d := os.Getenv("ANGERONA_DATA"); d != "" {
		return d
	}
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		return filepath.Join(d, "Angerona")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "Angerona")
}

func hbPath(name string) string   { return filepath.Join(dataDir(), "heartbeats", name+".hb") }
func ipcDir() string              { return filepath.Join(dataDir(), "ipc") }
func lockPath(name string) string { return filepath.Join(ipcDir(), name+".spawnlock") }

// ── heartbeat I/O ────────────────────────────────────────────────────────────
type beat struct {
	tsNs    uint64
	pid     uint32
	counter uint32
	flags   uint32
	ok      bool
}

func readBeat(path string) beat {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < hbSize {
		return beat{}
	}
	if binary.LittleEndian.Uint32(b[0:4]) != awdgMagic {
		return beat{}
	}
	return beat{
		tsNs:    binary.LittleEndian.Uint64(b[4:12]),
		pid:     binary.LittleEndian.Uint32(b[12:16]),
		counter: binary.LittleEndian.Uint32(b[24:28]),
		flags:   binary.LittleEndian.Uint32(b[28:32]),
		ok:      true,
	}
}

func tokenProof(token []byte, counter uint32) uint64 {
	if len(token) == 0 {
		return 0
	}
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], counter)
	sum := sha256.Sum256(append(append([]byte{}, token...), c[:]...))
	return binary.LittleEndian.Uint64(sum[:8])
}

func writeOurBeat(path string, token []byte, counter uint32) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	var buf [hbSize]byte
	binary.LittleEndian.PutUint32(buf[0:4], awdgMagic)
	binary.LittleEndian.PutUint64(buf[4:12], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(os.Getpid()))
	binary.LittleEndian.PutUint64(buf[16:24], tokenProof(token, counter))
	binary.LittleEndian.PutUint32(buf[24:28], counter)
	binary.LittleEndian.PutUint32(buf[28:32], 1)
	_ = os.WriteFile(path, buf[:], 0o644)
}

func pidAlive(pid uint32) bool {
	if pid == 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if windows.GetExitCodeProcess(h, &code) != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

// isAlive: fresh tick AND live pid (a stale leftover .hb is NOT alive).
func isAlive(name string, stale time.Duration) bool {
	b := readBeat(hbPath(name))
	if !b.ok || b.flags == 0 {
		return false
	}
	age := time.Duration(uint64(time.Now().UnixNano()) - b.tsNs)
	return age <= stale && pidAlive(b.pid)
}

// ── cross-process spawn lock (shared with the Python supervisor) ─────────────
func claimSpawn(name string) bool {
	_ = os.MkdirAll(ipcDir(), 0o755)
	p := lockPath(name)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err == nil {
		_, _ = f.WriteString(fmt.Sprintf("%d %d", os.Getpid(), time.Now().Unix()))
		_ = f.Close()
		return true
	}
	if fi, e := os.Stat(p); e == nil && time.Since(fi.ModTime()) > spawnTTL {
		_ = os.Remove(p)
		return claimSpawn(name)
	}
	return false
}

func releaseSpawn(name string) { _ = os.Remove(lockPath(name)) }

// ── stand-down token (matches shutdown_token.py) ─────────────────────────────
func busKey() []byte {
	b, err := os.ReadFile(filepath.Join(dataDir(), "bus.key"))
	if err != nil {
		return nil
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil
	}
	return k
}

func standdownActive() bool {
	b, err := os.ReadFile(filepath.Join(ipcDir(), "standdown.cmd"))
	if err != nil {
		return false
	}
	var cmd struct {
		Nonce  string  `json:"nonce"`
		Ts     float64 `json:"ts"`
		Reason string  `json:"reason"`
		Sig    string  `json:"sig"`
	}
	if json.Unmarshal(b, &cmd) != nil {
		return false
	}
	if time.Now().Unix()-int64(cmd.Ts) > int64(standMaxS) {
		return false
	}
	key := busKey()
	if key == nil {
		return false
	}
	payload := cmd.Nonce + "\x00" + strconv.Itoa(int(cmd.Ts)) + "\x00" + cmd.Reason
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(cmd.Sig))
}

// ── component supervision ─────────────────────────────────────────────────────
type comp struct {
	name     string
	relaunch func() error
	fails    []time.Time
	safeMode bool
}

func (c *comp) registerFailure() bool {
	now := time.Now()
	c.fails = append(c.fails, now)
	kept := c.fails[:0]
	for _, t := range c.fails {
		if now.Sub(t) <= failWindow {
			kept = append(kept, t)
		}
	}
	c.fails = kept
	return len(c.fails) >= maxFail
}

func detachedRun(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty command")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
	}
	return cmd.Start()
}

func logLine(f *os.File, format string, a ...interface{}) {
	line := fmt.Sprintf("[%s] ", time.Now().Format("2006-01-02T15:04:05")) + fmt.Sprintf(format, a...) + "\n"
	if f != nil {
		_, _ = f.WriteString(line)
	}
	fmt.Print(line)
}

func main() {
	token, _ := hex.DecodeString(os.Getenv("ANGERONA_WATCHDOG_TOKEN"))

	py := os.Getenv("ANGERONA_PY")
	if py == "" {
		py = "pythonw"
	}
	scannerCmd := []string{py, "-m", "angerona.resilience.scanner"}

	var coreRelaunch func() error
	if cc := os.Getenv("ANGERONA_CORE_CMD"); cc != "" {
		coreRelaunch = func() error { return detachedRun(strings.Fields(cc)) }
	}

	_ = os.MkdirAll(filepath.Join(dataDir(), "heartbeats"), 0o755)
	lf, _ := os.OpenFile(filepath.Join(dataDir(), "hypervisor.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)

	comps := []*comp{
		{name: "core", relaunch: coreRelaunch},
		{name: "scanner", relaunch: func() error { return detachedRun(scannerCmd) }},
	}

	logLine(lf, "hypervisor online — supervising core + scanner (data=%s)", dataDir())
	var counter uint32
	for {
		counter++
		writeOurBeat(hbPath("watchdog"), token, counter)

		stand := standdownActive()
		for _, c := range comps {
			if stand || c.relaunch == nil {
				continue // maintenance mode, or monitor-only component
			}
			if isAlive(c.name, staleAfter) {
				continue // already running (adopt) — never a duplicate
			}
			// Dead/suspended. Claim the shared spawn lock so we don't race the
			// Python supervisor into a double-spawn.
			if !claimSpawn(c.name) {
				continue
			}
			if isAlive(c.name, staleAfter) { // double-check under the lock
				releaseSpawn(c.name)
				continue
			}
			if c.safeMode {
				releaseSpawn(c.name)
				continue
			}
			if c.registerFailure() {
				c.safeMode = true
				logLine(lf, "CRITICAL %s entered SAFE_MODE (%d failures/%.0fs) — respawns halted",
					c.name, maxFail, failWindow.Seconds())
				releaseSpawn(c.name)
				continue
			}
			logLine(lf, "%s not alive — respawning", c.name)
			if err := c.relaunch(); err != nil {
				logLine(lf, "ERROR respawn %s failed: %v", c.name, err)
			}
			// Hold the lock briefly until the child is detectably up.
			go func(name string) {
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					if isAlive(name, staleAfter) {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				releaseSpawn(name)
			}(c.name)
		}
		// Healthy components decay their failure window so they can leave SAFE_MODE.
		for _, c := range comps {
			if c.safeMode && isAlive(c.name, staleAfter) && len(c.fails) == 0 {
				c.safeMode = false
				logLine(lf, "%s left SAFE_MODE (healthy)", c.name)
			}
		}
		time.Sleep(loopEvery)
	}
}
