//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
	Args    []string
	Token   string
	Mmap    string
	DataDir string
}

// A harmless subprocess of this test binary records the exact launched argv.
func TestWatchdogLaunchHelper(t *testing.T) {
	if os.Getenv("ANGERONA_TEST_LAUNCH_HELPER") != "1" {
		return
	}
	payload, err := json.Marshal(capturedLaunch{
		Args: os.Args, Token: os.Getenv("ANGERONA_WATCHDOG_TOKEN"),
		Mmap: os.Getenv("ANGERONA_WATCHDOG_MMAP"), DataDir: os.Getenv("ANGERONA_WD_DATADIR"),
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
			cfg := config{agentExe: os.Args[0], agentArgs: args, dataDir: temp}
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
			if !reflect.DeepEqual(args, before) {
				t.Fatalf("configured arguments mutated: %#v", args)
			}
		})
	}
}
