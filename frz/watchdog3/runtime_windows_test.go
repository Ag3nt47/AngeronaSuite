//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The copied test image accepts the one fixed production argument as a bounded
// inert native helper. It writes only to its private fixture data root and exits;
// it never imports or launches Angerona, runs a shell, or installs persistence.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--chill" {
		payload, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "environment": os.Environ(), "mitigation_supported": hardenSelf() == nil})
		if err := os.WriteFile(filepath.Join(os.Getenv("ANGERONA_DATA"), "inert-child.json"), payload, 0600); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func nativeFixture(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private")
	if err := ensurePrivateDirectory(root); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ipc", "heartbeats", "diagnostics"} {
		if err := ensurePrivateDirectory(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestNativePrivateFilesAreBoundedAndRetainCustody(t *testing.T) {
	root := nativeFixture(t)
	path := filepath.Join(root, "diagnostics", "frame.json")
	if err := writePrivateFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(path, []byte("second")); err != nil {
		t.Fatal("atomic replacement", err)
	}
	raw, err := readPrivateFile(path, 6)
	if err != nil || string(raw) != "second" {
		t.Fatal(string(raw), err)
	}
	if _, err := readPrivateFile(path, 5); err == nil {
		t.Fatal("oversize read accepted")
	}
	if _, err := readPrivateFile(filepath.Join(root, "missing"), 6); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing-file identity lost", err)
	}
	if err := writePrivateFile(path, []byte{}); err != nil {
		t.Fatal(err)
	}
	raw, err = readPrivateFile(path, 6)
	if err != nil || raw == nil || len(raw) != 0 {
		t.Fatal("existing empty file lost its identity", raw, err)
	}
	if err := appendPrivateFile(path, []byte("one\n"), 8); err != nil {
		t.Fatal(err)
	}
	if err := appendPrivateFile(path, []byte("two\n"), 8); err != nil {
		t.Fatal(err)
	}
	if err := appendPrivateFile(path, []byte("overflow\n"), 8); err == nil {
		t.Fatal("append exceeded bound")
	}
	raw, err = readPrivateFile(path, 8)
	if err != nil || string(raw) != "one\ntwo\n" {
		t.Fatal("overflow altered original", string(raw), err)
	}
}

func TestNativeHeldImageAndParentsRejectWriteOrReplacement(t *testing.T) {
	root := nativeFixture(t)
	path := filepath.Join(root, "owned.bin")
	if err := writePrivateFile(path, []byte("inert original")); err != nil {
		t.Fatal(err)
	}
	hold, err := openHeld(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	if err := os.WriteFile(path, []byte("changed"), 0600); err == nil {
		t.Fatal("held image admitted a writer")
	}
	if err := os.Rename(path, path+".moved"); err == nil {
		t.Fatal("held image was renamed")
	}
	if err := os.Rename(root, root+".moved"); err == nil {
		t.Fatal("held ancestor was renamed")
	}
	raw, err := io.ReadAll(hold.file)
	if err != nil || string(raw) != "inert original" {
		t.Fatal(string(raw), err)
	}
}

func TestNativeHardLinkAndBroadACLRefuseAuthority(t *testing.T) {
	root := nativeFixture(t)
	path := filepath.Join(root, "secret.key")
	if err := writePrivateFile(path, []byte("inert")); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias.key")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFile(path, 64); err == nil {
		t.Fatal("hard-linked authority admitted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFile(path, 64); err == nil {
		t.Fatal("world-readable/writable authority admitted")
	}
}

func TestNativeAdminCustodyIsNotSatisfiedByUserPrivateData(t *testing.T) {
	root := nativeFixture(t)
	path := filepath.Join(root, "config.json")
	if err := writePrivateFile(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateDirectory(root); err != nil {
		t.Fatal(err)
	}
	if err := checkAdminDirectory(root); err == nil {
		t.Fatal("user-owned directory became install authority")
	}
	if _, err := readAdminFile(path, 64); err == nil {
		t.Fatal("user-owned config became install authority")
	}
}

func TestNativeJunctionCannotRedirectAProtectedRead(t *testing.T) {
	root := nativeFixture(t)
	outside := filepath.Join(root, "outside")
	if err := ensurePrivateDirectory(outside); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outside, "sentinel")
	if err := writePrivateFile(sentinel, []byte("inert outside sentinel")); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "junction")
	windowsRoot, err := windows.GetWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(windowsRoot, "System32", "cmd.exe"), "/d", "/c", "mklink", "/J", link, outside)
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native junction fixture: %v %s", err, output)
	}
	defer func() {
		if err := os.Remove(link); err != nil {
			t.Error(err)
		}
	}()
	if _, err := readPrivateFile(filepath.Join(link, "sentinel"), 64); err == nil {
		t.Fatal("junction target was admitted")
	}
	if err := ensurePrivateDirectory(link); err == nil {
		t.Fatal("junction was accepted as a private directory")
	}
	after, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sentinel)
	if err != nil || string(raw) != "inert outside sentinel" || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("outside target changed", err)
	}
}

func TestNativeSingleInstanceAndSpawnClaimsExcludeDuplicates(t *testing.T) {
	root := nativeFixture(t)
	first, err := acquireInstance(root)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := acquireInstance(root); !errors.Is(err, errAlreadyRunning) {
		if second != nil {
			second.Close()
		}
		t.Fatal("duplicate instance admitted", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := acquireInstance(root)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	claim, err := claimSpawnLocks(root)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := claimSpawnLocks(root); err == nil {
		duplicate.Close()
		t.Fatal("duplicate spawn admitted")
	}
	if err := os.Remove(filepath.Join(root, "ipc", "core.spawnlock")); err == nil {
		t.Fatal("active claim could be stolen")
	}
	if err := claim.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"core", "watchdog"} {
		if _, err := os.Stat(filepath.Join(root, "ipc", name+".spawnlock")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned claim not retired", err)
		}
	}
}

func TestNativeStaleSpawnRecoveryPreservesLiveOrUnknownOwners(t *testing.T) {
	root := nativeFixture(t)
	path := filepath.Join(root, "ipc", "core.spawnlock")
	old := time.Now().Add(-time.Minute)
	for _, pid := range []string{strconv.Itoa(os.Getpid()), "not-a-pid", "0"} {
		if err := writePrivateFile(path, []byte(pid+" "+strconv.FormatFloat(float64(old.Unix()), 'f', 1, 64))); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		if claim, err := claimSpawnLocks(root); err == nil {
			claim.Close()
			t.Fatal("live or unrecognized owner was removed")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal("held claim disappeared", err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePrivateFile(path, []byte("4294967295 "+strconv.FormatFloat(float64(old.Unix()), 'f', 1, 64))); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	claim, err := claimSpawnLocks(root)
	if err != nil {
		t.Fatal("proven dead stale owner was not recoverable", err)
	}
	if err := claim.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativePeerGenerationSurvivesPIDOnlyObservation(t *testing.T) {
	self, err := openPeer(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	if self.PID != uint32(os.Getpid()) || self.BirthTicks == 0 {
		t.Fatal("native creation identity missing")
	}
	if present, err := self.Present(); err != nil || !present {
		t.Fatal(present, err)
	}
	again, err := openPeer(self.PID)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if again.BirthTicks != self.BirthTicks {
		t.Fatal("generation changed across native handles")
	}
	if _, err := openPeer(^uint32(0)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing process became present", err)
	}
}

func inertImage(t *testing.T, root string) (*pathHold, string) {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "inert.exe")
	// Fixture images can exceed diagnostic-output bounds; the private fixture
	// directory supplies custody. Production still requires admin image custody.
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	hold, err := openHeld(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hold.Close() })
	return hold, hex.EncodeToString(digest[:])
}

func TestNativePinnedLaunchRejectsMismatchAndHonorsFinalStopGate(t *testing.T) {
	root := nativeFixture(t)
	hold, digest := inertImage(t, root)
	gateCalls := 0
	if process, err := startPinnedImage(hold, strings.Repeat("0", 64), []string{"--chill"}, root, root, "", func() error { gateCalls++; return nil }); err == nil || process != nil || gateCalls != 0 {
		t.Fatal("digest mismatch crossed dispatch gate")
	}
	denied := errors.New("inert verified STOP")
	if process, err := startPinnedImage(hold, digest, []string{"--chill"}, root, root, "", func() error { gateCalls++; return denied }); !errors.Is(err, denied) || process != nil || gateCalls != 1 {
		t.Fatal("STOP gate did not block", process, err)
	}
	if _, err := os.Stat(filepath.Join(root, "inert-child.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("blocked launch produced output", err)
	}
}

func TestNativeLaunchRetainsExactChildAndSanitizesEnvironment(t *testing.T) {
	root := nativeFixture(t)
	hold, digest := inertImage(t, root)
	t.Setenv("SystemRoot", `Z:\untrusted-root`)
	t.Setenv("PATH", `Z:\untrusted-path`)
	t.Setenv("PYTHONPATH", "inert-injected-canary")
	t.Setenv("ANGERONA_WATCHDOG_TEST_CANARY", "must-not-cross")
	child, err := startPinnedImage(hold, digest, []string{"--chill"}, root, root, "attack", func() error { return nil })
	if err != nil || child == nil {
		t.Fatal(child, err)
	}
	defer child.Close()
	if child.PID == 0 || child.BirthTicks == 0 {
		t.Fatal("actual created generation not retained")
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		present, err := child.Present()
		if err != nil {
			t.Fatal(err)
		}
		if !present {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inert child did not retire")
		}
		time.Sleep(10 * time.Millisecond)
	}
	raw, err := readPrivateFile(filepath.Join(root, "inert-child.json"), 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	var proof struct {
		PID         uint32   `json:"pid"`
		Environment []string `json:"environment"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	if proof.PID != child.PID {
		t.Fatal("completion belongs to another process")
	}
	joined := strings.Join(proof.Environment, "\n")
	for _, forbidden := range []string{"untrusted-root", "untrusted-path", "PYTHONPATH=", "must-not-cross"} {
		if strings.Contains(joined, forbidden) {
			t.Fatal("ambient launch authority crossed", forbidden)
		}
	}
	if !strings.Contains(joined, "ANGERONA_RECOVERY_PRESSURE=attack") || !strings.Contains(joined, "ANGERONA_SUPERVISED_RECOVERY=1") {
		t.Fatal("recovery context missing")
	}
	if present, err := child.Present(); err != nil || present {
		t.Fatal("exact native child remains active", present, err)
	}
	// A retained handle preserves the exited kernel process object. That must
	// not turn its old Python-compatible spawn claim into a permanent hold.
	old := time.Now().Add(-time.Minute)
	claimPath := filepath.Join(root, "ipc", "core.spawnlock")
	if err := writePrivateFile(claimPath, []byte(strconv.FormatUint(uint64(child.PID), 10)+" "+strconv.FormatInt(old.Unix(), 10))); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(claimPath, old, old); err != nil {
		t.Fatal(err)
	}
	claim, err := claimSpawnLocks(root)
	if err != nil {
		t.Fatal("retained exited owner blocked stale recovery", err)
	}
	if err := claim.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativePathAliasesAreRejected(t *testing.T) {
	for _, path := range []string{`\\server\share\x`, `\\?\C:\x`, `C:relative`, `C:\x\..\secret`, `C:\x:stream`, `C:\NUL`, `C:\x.`, `C:\x `} {
		if _, err := localPath(path); err == nil {
			t.Fatal("ambiguous path admitted", path)
		}
	}
}

func TestNativeCleanupFailurePropagatesAndHoldsFurtherAllocation(t *testing.T) {
	for _, kind := range []string{"file-close", "parent-handle-close"} {
		t.Run(kind, func(t *testing.T) {
			root := nativeFixture(t)
			path := filepath.Join(root, "diagnostics", "owned.json")
			if err := writePrivateFile(path, []byte("inert")); err != nil {
				t.Fatal(err)
			}
			originalFile, originalNative := fileClose, nativeClose
			t.Cleanup(func() {
				fileClose = originalFile
				nativeClose = originalNative
				custodyMu.Lock()
				custodyHold = nil
				custodyMu.Unlock()
			})
			injected := errors.New("inert close-failure proof")
			failed := false
			closeCalls := 0
			fileClose = func(file *os.File) error {
				closeCalls++
				err := originalFile(file)
				if kind == "file-close" && !failed {
					failed = true
					return errors.Join(err, injected)
				}
				return err
			}
			nativeClose = func(handle windows.Handle) error {
				closeCalls++
				err := originalNative(handle)
				if kind == "parent-handle-close" && !failed {
					failed = true
					return errors.Join(err, injected)
				}
				return err
			}
			// The real close still runs, so no native fixture object is leaked.
			raw, err := readPrivateFile(path, 64)
			if !errors.Is(err, injected) || raw != nil || custodyReady() == nil {
				t.Fatal("unknown retirement was reported as success", raw, err)
			}
			before := closeCalls
			if _, err := readPrivateFile(path, 64); err == nil {
				t.Fatal("held read allocated again")
			}
			if peer, err := openPeer(uint32(os.Getpid())); peer != nil || err == nil {
				t.Fatal("held runtime opened another process")
			}
			if lock, err := acquireInstance(root); lock != nil || err == nil {
				t.Fatal("held runtime allocated another instance")
			}
			if claim, err := claimSpawnLocks(root); claim != nil || err == nil {
				t.Fatal("held runtime allocated another claim")
			}
			if err := writePrivateFile(filepath.Join(root, "must-not-exist"), []byte("inert")); err == nil {
				t.Fatal("held runtime published again")
			}
			if closeCalls != before {
				t.Fatal("held runtime allocated/retired more handles or retried an unknown close")
			}
			if _, err := os.Stat(filepath.Join(root, "must-not-exist")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("held output appeared", err)
			}
		})
	}
}
