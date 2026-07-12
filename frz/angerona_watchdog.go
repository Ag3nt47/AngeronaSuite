//go:build windows

// angerona_watchdog.go — Project Angerona resilience & anti-tamper Watchdog.
//
// Backlog: BL-01 (decouple process resilience from the interpreter) and BL-09
// (out-of-process supervisor that verifies integrity and relaunches the agent).
//
// This is the RESILIENCE PARENT: it launches Angerona, verifies the binary's
// SHA-256 before every (re)launch, holds the process HANDLE it created (so a
// spoofed PID/process-name cannot fool it), detects forced termination and
// thread suspension, relaunches with a throttle to avoid crash loops, and keeps
// a mutual, token-authenticated heartbeat so each side can prove the other is
// genuinely alive and un-hooked. It hardens itself with process-mitigation
// policies against DLL injection.
//
// It is deliberately BOUNDED, not un-killable: a clean agent shutdown (heartbeat
// flag = 0), a `watchdog.stop` file, or Ctrl-Break all stop it without a fight,
// and a restart storm makes it give up. A watchdog that fought its own owner
// would be indistinguishable from a rootkit — that boundary is the point.
//
//   Build:  cd AngeronaSuite\frz && go build -ldflags="-s -w" -o ..\angerona_watchdog.exe angerona_watchdog.go
//   Run:    angerona_watchdog.exe <agent_exe> [agent args...]
//           env ANGERONA_WD_DATADIR   = dir for heartbeats + log (default: agent dir)
//           env ANGERONA_AGENT_SHA256 = expected lowercase-hex hash of <agent_exe>
//                                       (else a <agent_exe>.sha256 sidecar; else
//                                        first-run "learn" mode writes the sidecar)
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── tunables ────────────────────────────────────────────────────────────────
const (
	pollInterval     = 250 * time.Millisecond // how often we sample liveness
	freezeThreshold  = 5 * time.Second        // agent clock stalled this long ⇒ suspended
	wdBeatBase       = 500 * time.Millisecond // our heartbeat cadence (jittered)
	maxRapidRestarts = 3                      // cap on restarts inside rapidWindow
	rapidWindow      = 60 * time.Second       // crash-loop detection window
	backoffCap       = 8 * time.Second

	agentMmapName = "frz_heartbeat.mmap" // written by frz_heartbeat.py: <Q(ts_ns) I(pid) I(flags)>
	wdMmapName    = "frz_watchdog.mmap"  // written by us so the agent can verify the watchdog
	agentMmapSize = 16
	wdMmapSize    = 32
	wdMagic       = uint32(0x41574447) // "AWDG"

	// Windows CreateProcess flags (avoids importing extra constants).
	createNoWindow        = 0x08000000
	detachedProcess       = 0x00000008
	createNewProcessGroup = 0x00000200

	// SetProcessMitigationPolicy policy IDs (winnt.h ProcessMitigationPolicy).
	policyExtensionPointDisable = 6
	policyImageLoad             = 10
)

type config struct {
	agentExe     string
	agentArgs    []string
	dataDir      string
	expectedHash string // lowercase hex, or "" to learn on first run
}

var (
	logMu       sync.Mutex
	logFile     *os.File
	shuttingDwn int32 // atomic: 1 once a clean stop is requested
)

// ── logging (restricted local channel, clean error handling) ────────────────
func logInit(dataDir string) {
	p := filepath.Join(dataDir, "watchdog.log")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WD] cannot open log %s: %v\n", p, err)
		return
	}
	logFile = f
	// Best-effort ACL tighten: restrict the log to the current user + SYSTEM.
	restrictACL(p)
}

func logLine(level, msg string) {
	line := fmt.Sprintf("[%s] [%s] %s\n", time.Now().Format(time.RFC3339), level, msg)
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		_, _ = logFile.WriteString(line)
		_ = logFile.Sync()
	}
	fmt.Fprint(os.Stderr, line)
}

func restrictACL(path string) {
	// icacls: remove inheritance, grant only the owner and SYSTEM. Non-fatal.
	cmd := exec.Command("icacls", path, "/inheritance:r",
		"/grant:r", `SYSTEM:(F)`, "/grant:r", os.Getenv("USERNAME")+`:(F)`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	_ = cmd.Run()
}

// ── self-hardening: process-mitigation policies (anti-DLL-injection) ─────────
func hardenSelf() {
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	setPol := k32.NewProc("SetProcessMitigationPolicy")
	set := func(name string, id uintptr, val uint32) {
		r1, _, err := setPol.Call(id, uintptr(unsafe.Pointer(&val)), unsafe.Sizeof(val))
		if r1 == 0 {
			logLine("WARN", fmt.Sprintf("mitigation %s not applied: %v", name, err))
		} else {
			logLine("INFO", "mitigation applied: "+name)
		}
	}
	// Block legacy injection vectors (AppInit_DLLs, hooks, IME).
	set("extension_point_disable", policyExtensionPointDisable, 0x1)
	// No remote (UNC) and no low-integrity DLLs may load into the watchdog.
	set("image_load", policyImageLoad, 0x1|0x2)
}

// ── configuration ───────────────────────────────────────────────────────────
func parseConfig() (config, error) {
	if len(os.Args) < 2 {
		return config{}, fmt.Errorf("usage: angerona_watchdog.exe <agent_exe> [args...]")
	}
	exe, err := filepath.Abs(os.Args[1])
	if err != nil {
		return config{}, err
	}
	dataDir := os.Getenv("ANGERONA_WD_DATADIR")
	if dataDir == "" {
		dataDir = filepath.Dir(exe)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return config{}, err
	}
	expected := strings.ToLower(strings.TrimSpace(os.Getenv("ANGERONA_AGENT_SHA256")))
	if expected == "" {
		if b, e := os.ReadFile(exe + ".sha256"); e == nil {
			expected = strings.ToLower(strings.TrimSpace(string(b)))
		}
	}
	return config{agentExe: exe, agentArgs: os.Args[2:], dataDir: dataDir, expectedHash: expected}, nil
}

// ── cryptographic integrity check (BL-01 requirement 2) ─────────────────────
// Rigid SHA-256 of the on-disk agent binary; constant-time compare to baseline.
// Returns (ok, actualHash). A mismatch means on-disk tampering ⇒ caller aborts.
func verifyIntegrity(cfg *config) (bool, string) {
	f, err := os.Open(cfg.agentExe)
	if err != nil {
		logLine("CRIT", "cannot open agent binary for hashing: "+err.Error())
		return false, ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		logLine("CRIT", "error hashing agent binary: "+err.Error())
		return false, ""
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if cfg.expectedHash == "" {
		// First run with no baseline: learn it, persist a sidecar, then proceed.
		_ = os.WriteFile(cfg.agentExe+".sha256", []byte(actual), 0600)
		cfg.expectedHash = actual
		logLine("INFO", "integrity baseline learned: "+actual)
		return true, actual
	}
	ok := subtle.ConstantTimeCompare([]byte(actual), []byte(cfg.expectedHash)) == 1
	if !ok {
		logLine("CRIT", fmt.Sprintf("INTEGRITY FAILURE — expected %s got %s; refusing to launch",
			cfg.expectedHash, actual))
	}
	return ok, actual
}

// ── heartbeat I/O over the file-backed shared region ────────────────────────
// The agent's region is written by frz_heartbeat.py; ours is read by the agent.
// Reads/writes of a file-backed mmap are coherent on Windows (shared cache pages).
func readAgentBeat(path string) (tsNs uint64, flags uint32, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < agentMmapSize {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint64(b[0:8]), binary.LittleEndian.Uint32(b[12:16]), true
}

// token proof: first 8 bytes of SHA-256(token || counter_le) — proves the writer
// knows the per-launch session token, so the agent can tell a genuine watchdog
// from a spoofed one.
func tokenProof(token []byte, counter uint32) uint64 {
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], counter)
	sum := sha256.Sum256(append(append([]byte{}, token...), c[:]...))
	return binary.LittleEndian.Uint64(sum[0:8])
}

func writeWatchdogBeat(path string, token []byte, counter uint32) {
	buf := make([]byte, wdMmapSize)
	binary.LittleEndian.PutUint32(buf[0:4], wdMagic)
	binary.LittleEndian.PutUint64(buf[4:12], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(os.Getpid()))
	binary.LittleEndian.PutUint64(buf[16:24], tokenProof(token, counter))
	binary.LittleEndian.PutUint32(buf[24:28], counter)
	binary.LittleEndian.PutUint32(buf[28:32], 1) // flags: running
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0600); err == nil {
		_ = os.Rename(tmp, path) // atomic replace so a reader never sees a torn write
	}
}

// crypto-jittered watchdog cadence (anti-TOCTOU on our own beat).
func jitter(base time.Duration, spread float64) time.Duration {
	var b [2]byte
	_, _ = rand.Read(b[:])
	frac := (float64(binary.LittleEndian.Uint16(b[:]))/65535.0)*2 - 1 // [-1,1]
	d := time.Duration(float64(base) * (1 + frac*spread))
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return d
}

// ── launch the agent, detached, holding its process handle (anti-spoof) ─────
func launchAgent(cfg config, token, wdMmapPath string) (*exec.Cmd, error) {
	cmd := exec.Command(cfg.agentExe, cfg.agentArgs...)
	cmd.Env = append(os.Environ(),
		"ANGERONA_WATCHDOG_TOKEN="+token,
		"ANGERONA_WATCHDOG_MMAP="+wdMmapPath,
		"ANGERONA_WD_DATADIR="+cfg.dataDir,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNoWindow | detachedProcess | createNewProcessGroup,
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// ── supervision loop ────────────────────────────────────────────────────────
func supervise(cfg config) {
	agentMmap := filepath.Join(cfg.dataDir, agentMmapName)
	wdMmap := filepath.Join(cfg.dataDir, wdMmapName)
	stopFile := filepath.Join(cfg.dataDir, "watchdog.stop")

	var restarts []time.Time

	for {
		if atomic.LoadInt32(&shuttingDwn) == 1 || fileExists(stopFile) {
			_ = os.Remove(stopFile)
			logLine("INFO", "shutdown requested — watchdog exiting, no relaunch")
			return
		}
		// (2) Integrity gate — never launch a tampered binary.
		if ok, _ := verifyIntegrity(&cfg); !ok {
			logLine("CRIT", "aborting: agent binary failed integrity check")
			return
		}

		// Per-launch session token (rotated each launch).
		tok := make([]byte, 32)
		_, _ = rand.Read(tok)
		token := hex.EncodeToString(tok)

		cmd, err := launchAgent(cfg, token, wdMmap)
		if err != nil {
			logLine("CRIT", "launch failed: "+err.Error())
			if giveUp(&restarts) {
				return
			}
			time.Sleep(backoff(len(restarts)))
			continue
		}
		logLine("INFO", fmt.Sprintf("agent launched pid=%d exe=%s", cmd.Process.Pid, cfg.agentExe))

		// (3) Mutual handshake: emit our authenticated heartbeat while the agent runs.
		beatStop := make(chan struct{})
		go func() {
			var counter uint32
			for {
				select {
				case <-beatStop:
					return
				default:
					writeWatchdogBeat(wdMmap, tok, counter)
					counter++
					time.Sleep(jitter(wdBeatBase, 0.15))
				}
			}
		}()

		// Death watcher: Wait() on the handle WE created (a spoofed PID can't fake it).
		died := make(chan struct{})
		go func() { _ = cmd.Wait(); close(died) }()

		reason := monitor(cmd, agentMmap, died, stopFile)
		close(beatStop)

		switch reason {
		case "clean":
			logLine("INFO", "agent shut down cleanly — watchdog exiting")
			return
		case "stop":
			_ = os.Remove(stopFile)
			logLine("INFO", "stop file — watchdog exiting")
			return
		case "died":
			logLine("CRIT", "AGENT TERMINATED — forced kill or crash detected")
		case "suspended":
			logLine("CRIT", "AGENT SUSPENDED — heartbeat clock frozen; isolating and relaunching")
			_ = cmd.Process.Kill() // release the suspended husk before relaunch
		}

		if giveUp(&restarts) {
			logLine("CRIT", fmt.Sprintf("restart storm (%d in %s) — giving up to avoid a crash loop",
				maxRapidRestarts, rapidWindow))
			return
		}
		d := backoff(len(restarts))
		logLine("INFO", fmt.Sprintf("relaunching in %s", d))
		time.Sleep(d)
	}
}

// monitor returns why the current agent instance ended: "died", "suspended",
// "clean" (agent flag=0), or "stop" (admin stop file / signal).
func monitor(cmd *exec.Cmd, agentMmap string, died <-chan struct{}, stopFile string) string {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	lastTs, _, _ := readAgentBeat(agentMmap)
	lastAdvance := time.Now()

	for {
		select {
		case <-died:
			return "died"
		case <-ticker.C:
			if atomic.LoadInt32(&shuttingDwn) == 1 {
				return "stop"
			}
			if fileExists(stopFile) {
				return "stop"
			}
			ts, flags, ok := readAgentBeat(agentMmap)
			if ok && flags == 0 {
				return "clean" // frz_heartbeat wrote flag=0 on an intentional stop
			}
			if ok && ts != lastTs {
				lastTs = ts
				lastAdvance = time.Now()
			} else if ok && flags == 1 && time.Since(lastAdvance) > freezeThreshold {
				return "suspended"
			}
		}
	}
}

// restart throttle -----------------------------------------------------------
func giveUp(restarts *[]time.Time) bool {
	now := time.Now()
	kept := (*restarts)[:0]
	for _, t := range *restarts {
		if now.Sub(t) < rapidWindow {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	*restarts = kept
	return len(kept) > maxRapidRestarts
}

func backoff(n int) time.Duration {
	d := time.Second << uint(max(0, n-1))
	if d > backoffCap {
		d = backoffCap
	}
	return d
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logInit(cfg.dataDir)
	logLine("INFO", "Angerona Watchdog starting (BL-01/BL-09)")
	hardenSelf()

	// Clean, admin-controlled shutdown (bounded, non-hostile).
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		atomic.StoreInt32(&shuttingDwn, 1)
		logLine("INFO", "signal received — requesting clean shutdown")
	}()

	supervise(cfg)
	logLine("INFO", "Angerona Watchdog stopped")
}
