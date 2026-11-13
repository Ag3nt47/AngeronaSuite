package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type inertProcess struct {
	pid       uint32
	birth     uint64
	present   bool
	uncertain bool
	closed    int
	closeErr  error
}

func (p *inertProcess) ID() uint32    { return p.pid }
func (p *inertProcess) Birth() uint64 { return p.birth }
func (p *inertProcess) Present() (bool, error) {
	if p.uncertain {
		return false, errors.New("inert uncertain process")
	}
	return p.present, nil
}
func (p *inertProcess) Close() error { p.closed++; return p.closeErr }

type inertCloser struct {
	onClose func()
	err     error
}

func (c inertCloser) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.err
}

type runnerFixture struct {
	t                      *testing.T
	config                 configuration
	control                string
	key                    []byte
	now                    time.Time
	files                  map[string][]byte
	directories            map[string]bool
	processes              map[uint32]*inertProcess
	opened                 []uint32
	created                []*inertProcess
	events                 []string
	locksClosed            int
	ledgerFail, appendFail bool
	onClaim                func()
	onLaunch               func(func() error) (processRef, error)
	onWrite                func(string)
	reads                  []string
	configurationErr       error
}

func newRunnerFixture(t *testing.T) *runnerFixture {
	fixture := &runnerFixture{t: t, config: configuration{Schema: 1, DataDir: filepath.Join(t.TempDir(), "data"), LauncherPath: "fixed-Angerona.exe", LauncherSHA256: strings.Repeat("a", 64), LauncherArgs: []string{"--chill"}, WorkingDirectory: "fixed-install"}, control: "fixed-admin-control", key: make([]byte, 32), now: time.Unix(1700000000, 125000000), files: map[string][]byte{}, directories: map[string]bool{}, processes: map[uint32]*inertProcess{}}
	for index := range fixture.key {
		fixture.key[index] = byte(index)
	}
	fixture.files[filepath.Join(fixture.config.DataDir, "shutdown.key")] = []byte(hex.EncodeToString(fixture.key))
	return fixture
}

func (f *runnerFixture) read(path string, limit int) ([]byte, error) {
	f.reads = append(f.reads, path)
	raw, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	if len(raw) > limit {
		return nil, errors.New("inert read bound")
	}
	return append([]byte{}, raw...), nil
}
func (f *runnerFixture) ops() runnerIO {
	return runnerIO{
		ReadPrivate: f.read, ReadAdmin: f.read,
		WritePrivate: func(path string, raw []byte) error {
			if f.onWrite != nil {
				f.onWrite(path)
			}
			if strings.HasSuffix(path, "watchdog3-ledger.json") && f.ledgerFail {
				return errors.New("sensitive private fixture path must not leak")
			}
			f.events = append(f.events, "write:"+filepath.Base(path))
			f.files[path] = append([]byte(nil), raw...)
			return nil
		},
		AppendPrivate: func(path string, raw []byte, limit int) error {
			if f.appendFail {
				return errors.New("inert append failed")
			}
			if len(f.files[path])+len(raw) > limit {
				return errors.New("inert outbox full")
			}
			f.events = append(f.events, "append")
			f.files[path] = append(f.files[path], raw...)
			return nil
		},
		CheckPrivateDirectory: func(string) error { return nil }, CheckAdminDirectory: func(path string) error {
			if f.directories[path] {
				return nil
			}
			return errors.New("inert admin directory custody invalid")
		},
		Exists: func(path string) (bool, error) { return f.directories[path], nil },
		ClaimLocks: func(string) (io.Closer, error) {
			f.events = append(f.events, "claim")
			if f.onClaim != nil {
				f.onClaim()
			}
			return inertCloser{onClose: func() { f.locksClosed++; f.events = append(f.events, "release") }}, nil
		},
		OpenPeer: func(pid uint32) (processRef, error) {
			f.opened = append(f.opened, pid)
			p := f.processes[pid]
			if p == nil || !p.present {
				return nil, os.ErrNotExist
			}
			return p, nil
		},
		Launch: func(config configuration, pressure string, gate func() error) (processRef, error) {
			if f.onLaunch != nil {
				return f.onLaunch(gate)
			}
			if err := gate(); err != nil {
				return nil, err
			}
			f.events = append(f.events, "create")
			p := &inertProcess{pid: uint32(9000 + len(f.created)), birth: fixtureBirth(f.now), present: true}
			f.created = append(f.created, p)
			return p, nil
		},
		CheckConfiguration: func() error { return f.configurationErr }, Now: func() time.Time { return f.now }, OwnPID: 123,
	}
}
func fixtureBirth(now time.Time) uint64 { return 116444736000000000 + uint64(now.UnixNano()/100) }
func (f *runnerFixture) runner() *nativeRunner {
	f.t.Helper()
	r, err := newNativeRunner(f.config, f.control, f.key, f.now, f.ops())
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}
func (f *runnerFixture) tick(r *nativeRunner, after time.Duration) supervisorDecision {
	f.now = time.Unix(1700000000, 125000000).Add(after)
	return r.tick(f.now)
}
func (f *runnerFixture) ready(r *nativeRunner) { f.tick(r, 0); f.tick(r, 181*time.Second) }
func (f *runnerFixture) frame(name string, pid, counter uint32, stamp time.Time) {
	raw, err := encodeHeartbeat(f.key, name, heartbeatRecord{uint64(stamp.UnixNano()), pid, counter, heartbeatV2 | heartbeatRunning})
	if err != nil {
		f.t.Fatal(err)
	}
	f.files[filepath.Join(f.config.DataDir, "heartbeats", name+".hb")] = raw
}

func TestRunnerPersistsBeforeLaunchAndRetainsCreatedGeneration(t *testing.T) {
	f := newRunnerFixture(t)
	r := f.runner()
	f.ready(r)
	decision := f.tick(r, 202*time.Second)
	if decision.State != "launched" || len(f.created) != 1 || f.locksClosed != 1 {
		t.Fatalf("recovery not executed once: %+v", decision)
	}
	createdAt := -1
	persistedAt := -1
	for index, event := range f.events {
		if event == "create" {
			createdAt = index
		}
		if event == "write:watchdog3-ledger.json" {
			persistedAt = index
		}
	}
	// The periodic checkpoint may follow CreateProcess; inspect its predecessor.
	if createdAt < 0 {
		t.Fatal("no create event")
	}
	persistedAt = -1
	for index := 0; index < createdAt; index++ {
		if f.events[index] == "write:watchdog3-ledger.json" {
			persistedAt = index
		}
	}
	if persistedAt < 0 {
		t.Fatal("launch preceded durable ledger")
	}
	saved, err := decodeLedger(f.key, f.files[r.ledgerPath()])
	if err != nil || saved.Attempts != 1 {
		t.Fatalf("attempt not authenticated: %+v %v", saved, err)
	}
	f.tick(r, 500*time.Second)
	if len(f.created) != 1 || f.created[0].closed != 0 {
		t.Fatal("live launched generation was forgotten without heartbeats")
	}
}

func TestRunnerSTOPAndFinalGatePreventLaunch(t *testing.T) {
	for _, where := range []string{"before-decision", "before-create"} {
		t.Run(where, func(t *testing.T) {
			f := newRunnerFixture(t)
			r := f.runner()
			vectors := loadProtocolVectors(t)
			stopPath := filepath.Join(f.config.DataDir, "ipc", "standdown.cmd")
			if where == "before-decision" {
				f.files[stopPath] = []byte(vectors.Stop["legacy_operator"])
			} else {
				f.onLaunch = func(gate func() error) (processRef, error) {
					f.files[stopPath] = []byte(vectors.Stop["legacy_operator"])
					if err := gate(); err != nil {
						return nil, err
					}
					t.Fatal("late STOP did not veto CreateProcess")
					return nil, nil
				}
			}
			f.ready(r)
			decision := f.tick(r, 202*time.Second)
			if len(f.created) != 0 {
				t.Fatal("STOP allowed a child")
			}
			if where == "before-decision" && decision.State != "standdown" {
				t.Fatalf("STOP not observed: %+v", decision)
			}
			if where == "before-create" && decision.State != "launch_failed" {
				t.Fatalf("late STOP not held: %+v", decision)
			}
		})
	}
}

func TestRunnerFreshPeerUnderSpawnLockVetoesLaunch(t *testing.T) {
	f := newRunnerFixture(t)
	r := f.runner()
	f.ready(r)
	f.onClaim = func() {
		f.processes[456] = &inertProcess{pid: 456, birth: fixtureBirth(f.now.Add(-time.Second)), present: true}
		f.frame("core", 456, 1, f.now)
	}
	decision := f.tick(r, 202*time.Second)
	if decision.State != "launch_failed" || len(f.created) != 0 || f.locksClosed != 1 {
		t.Fatalf("fresh peer did not veto locked launch: %+v", decision)
	}
}

func TestRunnerInvalidLedgerIsPreservedAndWriteFailureBlocksLaunch(t *testing.T) {
	for _, kind := range []string{"invalid-existing", "write-failure", "changed-after-load"} {
		t.Run(kind, func(t *testing.T) {
			f := newRunnerFixture(t)
			path := filepath.Join(f.config.DataDir, "diagnostics", "watchdog3-ledger.json")
			if kind == "invalid-existing" {
				f.files[path] = []byte(`{"forged":true}`)
			}
			r := f.runner()
			if kind == "write-failure" {
				f.ledgerFail = true
			}
			f.ready(r)
			if kind == "changed-after-load" {
				f.files[path] = []byte(`{"forged":true}`)
			}
			decision := f.tick(r, 202*time.Second)
			if len(f.created) != 0 || r.ledgerErr == nil {
				t.Fatalf("unsafe ledger authorized launch: %+v", decision)
			}
			if kind != "write-failure" && !bytes.Equal(f.files[path], []byte(`{"forged":true}`)) {
				t.Fatal("invalid evidence overwritten")
			}
			status := f.files[filepath.Join(f.config.DataDir, "diagnostics", "status_watchdog3.json")]
			if bytes.Contains(status, []byte("sensitive private fixture path")) {
				t.Fatal("raw diagnostic error escaped status")
			}
		})
	}
}

func TestRunnerOutboxLossNeverAbandonsApprovedRecovery(t *testing.T) {
	for _, kind := range []string{"capacity", "tampered-chain", "append-failure"} {
		t.Run(kind, func(t *testing.T) {
			f := newRunnerFixture(t)
			path := filepath.Join(f.config.DataDir, "diagnostics", "watchdog3-peer-alerts.jsonl")
			if kind == "tampered-chain" {
				f.files[path] = []byte("{\"forged\":true}\n")
			}
			if kind == "capacity" {
				previous := alertGenesis
				raw := []byte{}
				index := uint64(0)
				for {
					line, mac, err := makeAlert(f.key, previous, "HIGH", strings.Repeat("x", 512), map[string]any{"state": "dead"}, f.now, fmt.Sprintf("%016x", index))
					if err != nil {
						t.Fatal(err)
					}
					if len(raw)+len(line) > maxAlertFile {
						break
					}
					raw = append(raw, line...)
					previous = mac
					index++
				}
				// Consume remaining capacity with a final valid record carrying details.
				f.files[path] = raw
			}
			// Existing evidence belongs to a prior run with a genuine ledger.
			checkpoint, err := encodeLedger(f.key, supervisorSnapshot{Schema: 1, Stops: []int64{}})
			if err != nil {
				t.Fatal(err)
			}
			f.files[filepath.Join(f.config.DataDir, "diagnostics", "watchdog3-ledger.json")] = checkpoint
			r := f.runner()
			if kind == "append-failure" {
				f.appendFail = true
			}
			original := append([]byte(nil), f.files[path]...)
			f.ready(r)
			decision := f.tick(r, 202*time.Second)
			if decision.State != "launched" || len(f.created) != 1 {
				t.Fatalf("logging loss became launch authority: %+v", decision)
			}
			if r.alertErr == nil {
				t.Fatal("expected explicit alert evidence gap")
			}
			// Capacity loss must not become a session-long give-up after one try.
			last := 202 * time.Second
			for attempt := 1; attempt < 10; attempt++ {
				f.created[len(f.created)-1].present = false
				f.tick(r, last+181*time.Second)
				last += 202 * time.Second
				next := f.tick(r, last)
				if next.State != "launched" || len(f.created) != attempt+1 {
					t.Fatalf("recovery gave up after logging loss: %+v", next)
				}
			}
			if kind == "tampered-chain" && !bytes.Equal(f.files[path], original) {
				t.Fatal("tampered log erased")
			}
			status := f.files[filepath.Join(f.config.DataDir, "diagnostics", "status_watchdog3.json")]
			var snapshot map[string]any
			if err := json.Unmarshal(status, &snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot["coverage_gap"] != true || snapshot["alert_chain_verified"] != false {
				t.Fatal("logging loss not visible in status")
			}
		})
	}
}

func TestRunnerChangedAuthorityAndConfigurationCannotLaunch(t *testing.T) {
	for _, kind := range []string{"authority", "configuration"} {
		t.Run(kind, func(t *testing.T) {
			f := newRunnerFixture(t)
			r := f.runner()
			f.ready(r)
			if kind == "authority" {
				f.files[filepath.Join(f.config.DataDir, "shutdown.key")] = []byte(strings.Repeat("f", 64))
			} else {
				f.configurationErr = errors.New("inert config changed")
			}
			if decision := f.tick(r, 202*time.Second); decision.State != "held" || len(f.created) != 0 {
				t.Fatalf("changed authority allowed launch: %+v", decision)
			}
		})
	}
}

func TestRunnerBindsReusedPIDToNewBirthWithoutResettingTimestampHistory(t *testing.T) {
	f := newRunnerFixture(t)
	r := f.runner()
	oldBirth := f.now.Add(-time.Minute)
	old := &inertProcess{pid: 456, birth: fixtureBirth(oldBirth), present: true}
	f.processes[456] = old
	f.frame("core", 456, 100, f.now)
	if observed := r.observePeer(0); !observed.Authenticated || observed.IdentityUnknown {
		t.Fatal("initial generation rejected")
	}
	old.present = false
	f.now = f.now.Add(2 * time.Second)
	newProcess := &inertProcess{pid: 456, birth: fixtureBirth(f.now.Add(-time.Second)), present: true}
	f.processes[456] = newProcess
	if observed := r.observePeer(0); !observed.IdentityUnknown || !observed.ProcessPresent {
		t.Fatal("old frame lent liveness to reused PID")
	}
	if old.closed != 1 || newProcess.closed != 0 {
		t.Fatal("generation custody not retained")
	}
	f.frame("core", 456, 1, f.now)
	if observed := r.observePeer(0); !observed.Authenticated || observed.IdentityUnknown {
		t.Fatalf("genuine new generation counter cannot restart: %+v", observed)
	}
	f.frame("core", 456, 2, f.now.Add(time.Second))
	if observed := r.observePeer(0); !observed.Authenticated || observed.IdentityUnknown {
		t.Fatal("new generation did not advance")
	}
	// A subsequent rollback remains rejected despite the permitted counter reset.
	f.frame("core", 456, 3, f.now.Add(-time.Minute))
	if observed := r.observePeer(0); !observed.IdentityUnknown {
		t.Fatal("timestamp history was reset on PID reuse")
	}
}

func TestRunnerKeepsOldLiveHandleAcrossMissingInvalidAndChangedHeartbeat(t *testing.T) {
	for _, kind := range []string{"missing", "invalid", "changed-pid"} {
		t.Run(kind, func(t *testing.T) {
			f := newRunnerFixture(t)
			r := f.runner()
			old := &inertProcess{pid: 456, birth: fixtureBirth(f.now.Add(-time.Minute)), present: true}
			f.processes[456] = old
			f.frame("core", 456, 100, f.now)
			r.observePeer(0)
			path := r.heartbeatPath("core")
			switch kind {
			case "missing":
				delete(f.files, path)
			case "invalid":
				f.files[path] = []byte("forged")
			case "changed-pid":
				f.frame("core", 567, 1, f.now.Add(time.Second))
			}
			observed := r.observePeer(0)
			if !observed.ProcessPresent || old.closed != 0 || launchable([2]peerObservation{observed, {Missing: true}}) {
				t.Fatal("existing exact generation no longer blocks duplicate")
			}
			if len(f.opened) != 1 {
				t.Fatal("changed heartbeat acquired an unrelated generation before old exit")
			}
		})
	}
}

func TestRunnerAdminPresenceNeverFallsBackToLegacy(t *testing.T) {
	f := newRunnerFixture(t)
	r := f.runner()
	vectors := loadProtocolVectors(t)
	f.directories[f.control] = true
	f.files[filepath.Join(f.config.DataDir, "ipc", "standdown.cmd")] = []byte(vectors.Stop["legacy_operator"])
	decision, err := r.readStop(f.now)
	if err == nil || decision.Active {
		t.Fatal("incomplete admin directory became a legacy stop")
	}
	for _, path := range f.reads {
		if strings.HasSuffix(path, "standdown.cmd") {
			t.Fatal("legacy command read despite existing admin authority")
		}
	}
}

func TestRunnerCleanupUncertaintyReturnsErrorWithoutKillingPeers(t *testing.T) {
	f := newRunnerFixture(t)
	r := f.runner()
	core := &inertProcess{pid: 456, birth: fixtureBirth(f.now), present: true, closeErr: errors.New("private close detail")}
	created := &inertProcess{pid: 789, birth: fixtureBirth(f.now), present: true}
	r.peers[0].retained = core
	r.launched = created
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runSupervision(ctx, r); err == nil {
		t.Fatal("uncertain cleanup reported success")
	}
	if core.closed != 1 || created.closed != 1 || !core.present || !created.present {
		t.Fatal("cleanup did not close only its retained references exactly once")
	}
	raw := f.files[r.heartbeatPath("watchdog3")]
	record, err := decodeHeartbeat(f.key, "watchdog3", raw)
	if err != nil || record.Flags&heartbeatRunning != 0 {
		t.Fatal("final heartbeat not marked non-running")
	}
}
