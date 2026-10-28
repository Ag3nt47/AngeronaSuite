//go:build windows

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestChillAgentArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"nil", nil, []string{"--chill"}},
		{"empty", []string{}, []string{"--chill"}},
		{"absent", []string{"-m", "angerona", "--headless"}, []string{"-m", "angerona", "--headless", "--chill"}},
		{"existing", []string{"--chill", "--headless"}, []string{"--headless", "--chill"}},
		{"duplicates", []string{"--chill", "--headless", "--chill", "--chill"}, []string{"--headless", "--chill"}},
		{"exactOnly", []string{"--CHILL", "--chill=true", "path with spaces", ""}, []string{"--CHILL", "--chill=true", "path with spaces", "", "--chill"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Spare capacity catches append-based mutations beyond the slice length.
			backing := append(append([]string{}, tc.args...), "sentinel", "spare")
			before := append([]string{}, backing...)
			args := backing[:len(tc.args)]
			got := chillAgentArgs(args)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
			if !reflect.DeepEqual(chillAgentArgs(got), got) {
				t.Fatal("normalization is not idempotent")
			}
			got[0] = "changed result"
			if !reflect.DeepEqual(backing, before) {
				t.Fatalf("input backing array changed: %#v", backing)
			}
		})
	}
}

type capturedLaunch struct {
	Args     []string
	Token    string
	Mmap     string
	DataDir  string
	Recovery string
	External string
}

// A harmless subprocess of this test binary records the exact launched argv.
func TestWatchdogLaunchHelper(t *testing.T) {
	if os.Getenv("ANGERONA_TEST_LAUNCH_HELPER") != "1" {
		return
	}
	payload, err := json.Marshal(capturedLaunch{
		Args: os.Args, Token: os.Getenv("ANGERONA_WATCHDOG_TOKEN"),
		Mmap: os.Getenv("ANGERONA_WATCHDOG_MMAP"), DataDir: os.Getenv("ANGERONA_WD_DATADIR"),
		Recovery: os.Getenv("ANGERONA_SUPERVISED_RECOVERY"), External: os.Getenv("ANGERONA_EXTERNAL_WATCHDOG"),
	})
	if err != nil || os.WriteFile(os.Getenv("ANGERONA_TEST_LAUNCH_CAPTURE"), payload, 0600) != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestLaunchAgentChillArguments(t *testing.T) {
	for _, flags := range [][]string{nil, {"--chill"}, {"--chill", "--chill"}} {
		t.Run(string(rune('0'+len(flags))), func(t *testing.T) {
			temp := t.TempDir()
			capture := filepath.Join(temp, "child.json")
			t.Setenv("ANGERONA_TEST_LAUNCH_HELPER", "1")
			t.Setenv("ANGERONA_TEST_LAUNCH_CAPTURE", capture)
			args := []string{"-test.run=^TestWatchdogLaunchHelper$", "--", "--headless", "argument with spaces"}
			args = append(args, flags...)
			before := append([]string{}, args...)
			cfg := config{agentExe: os.Args[0], agentArgs: args, dataDir: temp, recovery: len(flags) == 2}
			mmap := filepath.Join(temp, "test.mmap")
			cmd, err := launchAgent(cfg, "test-session-token", mmap)
			if err != nil {
				t.Fatal(err)
			}
			if cmd.Process == nil || cmd.Process.Pid <= 0 {
				t.Fatal("launch did not retain the created process")
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
			payload, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			var got capturedLaunch
			if err := json.Unmarshal(payload, &got); err != nil {
				t.Fatal(err)
			}
			want := []string{cfg.agentExe, "-test.run=^TestWatchdogLaunchHelper$", "--", "--headless", "argument with spaces", "--chill"}
			if !reflect.DeepEqual(got.Args, want) {
				t.Fatalf("launched argv %#v, want %#v", got.Args, want)
			}
			if got.Token != "test-session-token" || got.Mmap != mmap || got.DataDir != temp {
				t.Fatalf("watchdog child environment changed: %#v", got)
			}
			wantRecovery := "0"
			if cfg.recovery {
				wantRecovery = "1"
			}
			if got.Recovery != wantRecovery || got.External != "1" {
				t.Fatalf("explicit/recovery launch flags changed: %#v", got)
			}
			if !reflect.DeepEqual(args, before) {
				t.Fatalf("configured arguments mutated: %#v", args)
			}
		})
	}
}

func signedStop(t *testing.T, path string, key []byte, ts int64) {
	t.Helper()
	nonce := "0123456789abcdef0123456789abcdef"
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "angerona-watchdog-stop-v1\x00%s\x00%d", nonce, ts)
	raw, err := json.Marshal(map[string]any{"schema": 1, "nonce": nonce, "ts": ts, "sig": hex.EncodeToString(mac.Sum(nil))})
	if err != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("could not create bounded stop fixture")
	}
}

func TestStopRequiresCurrentSessionProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watchdog.stop")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if os.WriteFile(path, []byte(""), 0600) != nil {
		t.Fatal("fixture write")
	}
	if authenticatedStop(path, key) {
		t.Fatal("empty flag granted stop authority")
	}
	signedStop(t, path, key, time.Now().Unix())
	if !authenticatedStop(path, key) {
		t.Fatal("valid stop refused")
	}
	if authenticatedStop(path, make([]byte, 32)) {
		t.Fatal("different session accepted")
	}
	signedStop(t, path, key, time.Now().Add(-2*time.Hour).Unix())
	if authenticatedStop(path, key) {
		t.Fatal("stale stop accepted")
	}
	signedStop(t, path, key, time.Now().Add(time.Hour).Unix())
	if authenticatedStop(path, key) {
		t.Fatal("future stop accepted")
	}
	if os.WriteFile(path, make([]byte, 4097), 0600) != nil {
		t.Fatal("fixture write")
	}
	if authenticatedStop(path, key) {
		t.Fatal("oversized stop accepted")
	}
}

func TestSignedStopWinsConcurrentProcessDeath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watchdog.stop")
	key := make([]byte, 32)
	signedStop(t, path, key, time.Now().Unix())
	died := make(chan struct{})
	close(died)
	if reason := monitor(nil, filepath.Join(dir, "missing.mmap"), died, path, key); reason != "stop" {
		t.Fatalf("exit was incorrectly restartable: %s", reason)
	}
}
