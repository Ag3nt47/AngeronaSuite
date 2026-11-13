//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func commandFixture(t *testing.T) (*runnerFixture, commandHost, *int) {
	f := newRunnerFixture(t)
	f.config.Schema = 2
	f.config.LauncherArgs = []string{"--engine-service"}
	base := filepath.Join(t.TempDir(), "ProgramData")
	install := filepath.Join(t.TempDir(), "install")
	f.config.LauncherPath = filepath.Join(install, "Angerona.exe")
	f.config.WorkingDirectory = install
	f.control = filepath.Join(base, "Angerona", "control")
	path := filepath.Join(base, "Angerona", "watchdog3", "config.json")
	raw, err := json.Marshal(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.files[path] = raw
	for _, directory := range []string{filepath.Join(base, "Angerona"), filepath.Dir(path)} {
		f.directories[directory] = true
	}
	mutations := new(int)
	host := commandHost{
		AdmitSelf:   func() (io.Closer, error) { return inertCloser{}, nil },
		ProgramData: func() (string, error) { return base, nil }, ReadAdmin: f.read, ReadPrivate: f.read,
		CheckAdminDirectory: func(path string) error { return f.ops().CheckAdminDirectory(path) }, CheckPrivateDirectory: func(string) error { return nil },
		EnsurePrivateDirectory: func(string) error { *mutations++; return nil }, ValidateService: func(configuration) error { return nil }, Harden: func() error { *mutations++; return nil },
		AcquireInstance: func(string) (io.Closer, error) { *mutations++; return inertCloser{}, nil },
		Run:             func(configuration, string, []byte, runnerIO) error { *mutations++; return nil }, IO: func(string, []byte) runnerIO { return f.ops() },
	}
	return f, host, mutations
}

func TestCommandVersionAndHelpNeverReadAuthority(t *testing.T) {
	for _, argument := range []string{"--version", "--help"} {
		t.Run(argument, func(t *testing.T) {
			var out, errs bytes.Buffer
			if code := runCommand([]string{argument}, &out, &errs, commandHost{}); code != 0 {
				t.Fatalf("informational command failed: %d", code)
			}
			if argument == "--version" && !strings.Contains(out.String(), "native Go") {
				t.Fatal("native runtime not identified")
			}
		})
	}
}

func TestCommandValidationIsReadOnlyAndChecksFixedPath(t *testing.T) {
	f, host, mutations := commandFixture(t)
	var out, errs bytes.Buffer
	if code := runCommand([]string{"--validate-only"}, &out, &errs, host); code != 0 {
		t.Fatalf("valid fixture rejected %d: %s", code, errs.String())
	}
	if *mutations != 0 || len(f.created) != 0 || !strings.Contains(out.String(), "No supervision started") {
		t.Fatal("validation mutated or launched")
	}
	if code := runCommand([]string{"--validate-only", "--config", filepath.Join(f.config.DataDir, "config.json")}, &out, &errs, host); code != 3 {
		t.Fatal("alternate config acquired launch authority")
	}
	if *mutations != 0 {
		t.Fatal("invalid config validation mutated")
	}
}

func TestCommandNormalSetupAndNoCommandLineSecrets(t *testing.T) {
	_, host, mutations := commandFixture(t)
	var out, errs bytes.Buffer
	if code := runCommand(nil, &out, &errs, host); code != 0 {
		t.Fatalf("normal inert setup rejected: %d %s", code, errs.String())
	}
	if *mutations != 6 {
		t.Fatalf("normal setup bypassed fixed stages: %d", *mutations)
	} // harden + three dirs + instance + loop.
	before := *mutations
	if code := runCommand([]string{"--token", "sensitive-test-only"}, &out, &errs, host); code != 2 {
		t.Fatal("secret/command injection option accepted")
	}
	if *mutations != before {
		t.Fatal("invalid CLI started supervision")
	}
}

func TestCommandMalformedExistingAuthorityNeverCreatesReplacement(t *testing.T) {
	f, host, mutations := commandFixture(t)
	var out, errs bytes.Buffer
	f.files[filepath.Join(f.config.DataDir, "shutdown.key")] = []byte("broken")
	if code := runCommand(nil, &out, &errs, host); code != 4 || *mutations != 0 {
		t.Fatal("malformed authority was repaired or launched")
	}
	if bytes.Contains(errs.Bytes(), []byte(f.config.DataDir)) {
		t.Fatal("private path escaped CLI error")
	}
}

func TestCommandInstanceCleanupUncertaintyIsNotSuccess(t *testing.T) {
	_, host, _ := commandFixture(t)
	closed := 0
	host.AcquireInstance = func(string) (io.Closer, error) {
		return inertCloser{onClose: func() { closed++ }, err: errors.New("private cleanup detail")}, nil
	}
	var out, errs bytes.Buffer
	if code := runCommand(nil, &out, &errs, host); code != 1 || closed != 1 {
		t.Fatalf("uncertain instance cleanup reported success: %d, %d", code, closed)
	}
	if strings.Contains(errs.String(), "private cleanup detail") {
		t.Fatal("raw cleanup detail escaped")
	}
}
