// angerona_hypervisor.go — multi-way keep-alive watchdog (compiled binary).
//
// Implements the Attestation & Resilience plane described in shared-ipc/CONTRACT.md.
// It is the ACTIVE HEALER for the ecosystem: it beats its own heartbeat and reads
// the core's and scanner's heartbeats; if either is DEAD or SUSPENDED it respawns
// that component (with exponential backoff → SAFE_MODE). A valid, signed
// stand-down token halts all respawns so an operator can perform maintenance.
//
// It is byte-compatible with angerona.resilience (Python): AWDG 32-byte
// heartbeats, and the HMAC-SHA256 stand-down token over the shared bus.key.
//
// Honest naming: this binary is called what it is. No process-ghosting/stealth
// renaming (that is a defense-evasion technique and is out of scope).
//
// Build (on Windows, with the Go toolchain):
//     cd frz\hypervisor
//     go mod tidy          // fetches golang.org/x/sys
//     go build -ldflags "-s -w" -o ..\angerona_watchdog.exe .
//
// Config via environment:
//     ANGERONA_DATA        data root (default %LOCALAPPDATA%\Angerona)
//     ANGERONA_PY          python launcher for the scanner (default "pythonw")
//     ANGERONA_CORE_CMD    command line to relaunch the Angerona core (optional;
//                          if unset, the core is monitored but not respawned by
//                          the hypervisor — the core respawns the scanner itself)
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
	staleAfter = 3 * time.Second // heartbeat freeze ⇒ suspended
	loopEvery  = 500 * time.Millisecond
	maxFail    = 3
	failWindow = 60 * time.Second
	standMaxS  = 3600.0
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

func hbPath(name string) string { return filepath.Join(dataDir(), "heartbeats", name+".hb") }

// ── heartbeat I/O (file-backed; coherent for small fixed records) ────────────
type beat struct {
	tsNs    uint64
	pid     uint32
	proof   uint64
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
		proof:   binary.LittleEndian.Uint64(b[16:24]),
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

func writeOurBeat(path string, token []byte, counter uint32, running uint32) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	var buf [hbSize]byte
	binary.LittleEndian.PutUint32(buf[0:4], awdgMagic)
	binary.LittleEndian.PutUint64(buf[4:12], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(os.Getpid()))
	binary.LittleEndian.PutUint64(buf[16:24], tokenProof(token, counter))
	binary.LittleEndian.PutUint32(buf[24:28], counter)
	binary.LittleEndian.PutUint32(buf[28:32], running)
	_ = os.WriteFile(path, buf[:], 0o644)
}

// ── process liveness (Windows) ───────────────────────────────────────────────
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
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

// ── stand-down token (matches shutdown_token.py exactly) ─────────────────────
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
	b, err := os.ReadFile(filepath.Join(dataDir(), "ipc", "standdown.cmd"))
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
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(cmd.Sig))
}

// ── component supervision ─────────────────────────────────────────────────────
type comp struct {
	name     string
	relaunch func() error // nil ⇒ monitored only, not respawned here
	prevCnt  uint32
	prevAt   time.Time
	fails    []time.Time
	safeMode bool
	seen     bool
}

func (c *comp) classify() string {
	b := readBeat(hbPath(c.name))
	now := time.Now()
	if !b.ok {
		return "dead"
	}
	if b.flags == 0 {
		return "stopped"
	}
	if !c.seen || b.counter != c.prevCnt {
		c.prevCnt, c.prevAt, c.seen = b.counter, now, true
		return "alive"
	}
	if now.Sub(c.prevAt) < staleAfter {
		return "alive"
	}
	if pidAlive(b.pid) {
		return "suspended"
	}
	return "dead"
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
	tokenHex := os.Getenv("ANGERONA_WATCHDOG_TOKEN")
	token, _ := hex.DecodeString(tokenHex)

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
		writeOurBeat(hbPath("watchdog"), token, counter, 1)

		stand := standdownActive()
		for _, c := range comps {
			state := c.classify()
			if stand || c.relaunch == nil {
				continue // maintenance mode, or monitor-only component
			}
			if state == "dead" || state == "suspended" {
				if c.safeMode {
					continue
				}
				if c.registerFailure() {
					c.safeMode = true
					logLine(lf, "CRITICAL %s entered SAFE_MODE (%d failures/%.0fs) — respawns halted",
						c.name, maxFail, failWindow.Seconds())
					continue
				}
				logLine(lf, "%s is %s — respawning", c.name, state)
				if err := c.relaunch(); err != nil {
					logLine(lf, "ERROR respawn %s failed: %v", c.name, err)
				}
			} else if state == "alive" {
				// healthy → let it leave SAFE_MODE once the window clears
				if c.safeMode && len(c.fails) == 0 {
					c.safeMode = false
					logLine(lf, "%s left SAFE_MODE (healthy)", c.name)
				}
			}
		}
		time.Sleep(loopEvery)
	}
}
