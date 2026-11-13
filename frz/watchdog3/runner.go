package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type processRef interface {
	ID() uint32
	Birth() uint64
	Present() (bool, error)
	Close() error
}

// Production supplies only retained Win32 implementations. Tests supply inert
// private stores/process references; no alternate launch command is a CLI option.
type runnerIO struct {
	ReadPrivate           func(string, int) ([]byte, error)
	ReadAdmin             func(string, int) ([]byte, error)
	WritePrivate          func(string, []byte) error
	AppendPrivate         func(string, []byte, int) error
	CheckPrivateDirectory func(string) error
	CheckAdminDirectory   func(string) error
	Exists                func(string) (bool, error)
	ClaimLocks            func(string) (io.Closer, error)
	OpenPeer              func(uint32) (processRef, error)
	ObserveService        func(configuration) (serviceObservation, error)
	Launch                func(configuration, string, func() error) (processRef, error)
	CheckConfiguration    func() error
	Now                   func() time.Time
	OwnPID                uint32
}

type watchedProcess struct {
	retained processRef
	replay   heartbeatReplay
}

type nativeRunner struct {
	config                  configuration
	controlRoot             string
	authority               []byte
	ops                     runnerIO
	supervisor              *supervisor
	service                 *serviceSupervisor
	peers                   [2]watchedProcess
	launched                processRef
	ledgerRaw               []byte
	ledgerExists            bool
	ledgerErr               error
	alertPrevious           string
	alertErr                error
	runtimeErr              error
	heartbeatCounter        uint32
	heartbeatPublished      bool
	lastStatus              time.Time
	lastState, lastPressure string
	lastDecision            supervisorDecision
}

func parseInstallAuthority(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 128 {
		return nil, errors.New("install authority unavailable")
	}
	for _, b := range raw {
		if b > 127 {
			return nil, errors.New("install authority encoding is invalid")
		}
	}
	encoded := strings.TrimSpace(string(raw))
	if len(encoded) != 64 {
		return nil, errors.New("install authority has invalid length")
	}
	key, err := hex.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("install authority is malformed")
	}
	return key, nil
}

func newNativeRunner(config configuration, controlRoot string, key []byte, now time.Time, ops runnerIO) (*nativeRunner, error) {
	if len(key) != 32 || ops.ReadPrivate == nil || ops.ReadAdmin == nil || ops.WritePrivate == nil || ops.AppendPrivate == nil || ops.CheckPrivateDirectory == nil || ops.CheckAdminDirectory == nil || ops.Exists == nil || ops.ClaimLocks == nil || ops.OpenPeer == nil || ops.Launch == nil || ops.CheckConfiguration == nil || ops.Now == nil || ops.OwnPID == 0 {
		return nil, errors.New("native supervision dependencies unavailable")
	}
	r := &nativeRunner{config: config, controlRoot: controlRoot, authority: append([]byte(nil), key...), ops: ops, supervisor: newSupervisor(now), alertPrevious: alertGenesis}
	if config.Schema == 2 {
		if ops.ObserveService == nil {
			return nil, errors.New("native SCM observation unavailable")
		}
		r.service = &serviceSupervisor{base: r.supervisor}
	}
	raw, err := ops.ReadPrivate(r.ledgerPath(), maximumLedgerBytes)
	if err == nil {
		r.ledgerExists = true
		r.ledgerRaw = append([]byte(nil), raw...)
		saved, decodeErr := decodeLedger(key, raw)
		if decodeErr != nil {
			r.ledgerErr = decodeErr
		} else {
			r.ledgerErr = r.supervisor.Restore(saved, now)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		r.ledgerErr = errors.New("restart ledger unavailable")
	}
	alerts, err := ops.ReadPrivate(r.alertPath(), maxAlertFile)
	if err == nil {
		r.alertPrevious, r.alertErr = recoverAlertTail(key, alerts)
	} else if !errors.Is(err, os.ErrNotExist) {
		r.alertErr = errors.New("alert chain unavailable")
	}
	// Evidence of an earlier run without its ledger is not a fresh installation.
	if !r.ledgerExists && r.alertPrevious != alertGenesis && r.alertErr == nil {
		r.ledgerErr = errors.New("restart ledger missing from an existing run")
	}
	return r, nil
}

func (r *nativeRunner) ledgerPath() string {
	return filepath.Join(r.config.DataDir, "diagnostics", "watchdog3-ledger.json")
}
func (r *nativeRunner) alertPath() string {
	return filepath.Join(r.config.DataDir, "diagnostics", "watchdog3-peer-alerts.jsonl")
}
func (r *nativeRunner) heartbeatPath(name string) string {
	return filepath.Join(r.config.DataDir, "heartbeats", name+".hb")
}

func (r *nativeRunner) authorityCurrent() error {
	if err := r.ops.CheckConfiguration(); err != nil {
		return errors.New("installed configuration changed or unavailable")
	}
	if err := r.ops.CheckPrivateDirectory(r.config.DataDir); err != nil {
		return errors.New("data custody unavailable")
	}
	raw, err := r.ops.ReadPrivate(filepath.Join(r.config.DataDir, "shutdown.key"), 128)
	if err != nil {
		return errors.New("install authority unavailable")
	}
	key, err := parseInstallAuthority(raw)
	if err != nil || !hmac.Equal(key, r.authority) {
		return errors.New("install authority changed or unavailable")
	}
	return nil
}

func optionalRead(path string, reader func(string, int) ([]byte, error), bound int) ([]byte, error) {
	raw, err := reader(path, bound)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return []byte{}, nil
	}
	return raw, nil
}

func (r *nativeRunner) readStop(now time.Time) (stopDecision, error) {
	if err := r.authorityCurrent(); err != nil {
		return stopDecision{}, err
	}
	exists, err := r.ops.Exists(r.controlRoot)
	if err != nil {
		return stopDecision{}, errors.New("control directory unavailable")
	}
	input := stopInputs{AdminPresent: exists, CustodyValid: true}
	if exists {
		if err := r.ops.CheckAdminDirectory(r.controlRoot); err != nil {
			return stopDecision{}, errors.New("administrator control custody unavailable")
		}
		input.AdminPublic, err = r.ops.ReadAdmin(filepath.Join(r.controlRoot, "stop-authority.pub"), 128)
		if err != nil {
			return stopDecision{}, errors.New("administrator public authority unavailable")
		}
		input.AdminEpoch, err = r.ops.ReadAdmin(filepath.Join(r.controlRoot, "epoch.json"), maxControlFile)
		if err != nil {
			return stopDecision{}, errors.New("administrator epoch unavailable")
		}
		input.AdminCommand, err = optionalRead(filepath.Join(r.controlRoot, "stop.cmd"), r.ops.ReadAdmin, maxControlFile)
	} else {
		input.LegacyCommand, err = optionalRead(filepath.Join(r.config.DataDir, "ipc", "standdown.cmd"), r.ops.ReadPrivate, maxControlFile)
	}
	if err != nil {
		return stopDecision{}, errors.New("STOP command unavailable")
	}
	return verifyStop(input, r.authority, now)
}

func birthTimestamp(birth uint64) (uint64, bool) {
	const epoch uint64 = 116444736000000000
	if birth <= epoch {
		return 0, false
	}
	delta := birth - epoch
	if delta > uint64(math.MaxInt64)/100 {
		return 0, false
	}
	return delta * 100, true
}

func (r *nativeRunner) observePeer(index int) peerObservation {
	state := &r.peers[index]
	result := peerObservation{}
	if state.retained != nil {
		present, err := state.retained.Present()
		if err != nil {
			result.IdentityUnknown = true
			return result
		}
		if present {
			result.ProcessPresent = true
		} else {
			if err := state.retained.Close(); err != nil {
				result.IdentityUnknown = true
				return result
			}
			state.retained = nil
		}
	}
	name := []string{"core", "watchdog"}[index]
	raw, err := r.ops.ReadPrivate(r.heartbeatPath(name), heartbeatSize)
	if errors.Is(err, os.ErrNotExist) {
		result.Missing = true
		return result
	}
	if err != nil {
		return result
	}
	record, err := decodeHeartbeat(r.authority, name, raw)
	if err != nil {
		return result
	}
	result.Authenticated = true
	result.PID = record.PID
	result.Counter = record.Counter
	result.TimestampNS = record.TimestampNS
	result.Running = record.Flags&heartbeatRunning != 0
	if state.retained != nil && state.retained.ID() != record.PID {
		result.IdentityUnknown = true
		return result
	}
	if state.retained == nil {
		process, err := r.ops.OpenPeer(record.PID)
		if errors.Is(err, os.ErrNotExist) {
			if err := state.replay.accept(record); err != nil {
				result.Authenticated = false
			}
			return result
		}
		if err != nil || process == nil {
			result.IdentityUnknown = true
			return result
		}
		state.retained = process
	}
	result.ProcessPresent = true
	result.BirthTicks = state.retained.Birth()
	birth, ok := birthTimestamp(result.BirthTicks)
	if !ok || record.TimestampNS > uint64(math.MaxInt64) || record.TimestampNS < birth {
		result.IdentityUnknown = true
		return result
	}
	if err := state.replay.acceptBound(record, result.BirthTicks, birth); err != nil {
		result.Authenticated = false
	}
	return result
}

func (r *nativeRunner) observe() [2]peerObservation {
	peers := [2]peerObservation{r.observePeer(0), r.observePeer(1)}
	if r.launched != nil {
		present, err := r.launched.Present()
		if err != nil {
			peers[0].IdentityUnknown = true
		} else if !present {
			if err := r.launched.Close(); err != nil {
				peers[0].IdentityUnknown = true
			} else {
				r.launched = nil
			}
		} else if peers[0].Authenticated && peers[1].Authenticated && peers[0].ProcessPresent && peers[1].ProcessPresent && !peers[0].IdentityUnknown && !peers[1].IdentityUnknown {
			if err := r.launched.Close(); err != nil {
				peers[0].IdentityUnknown = true
			} else {
				r.launched = nil
			}
		} else {
			peers[0].IdentityUnknown = true
		}
	}
	return peers
}

func launchable(peers [2]peerObservation) bool {
	for _, peer := range peers {
		if peer.ProcessPresent || peer.IdentityUnknown || (!peer.Authenticated && !peer.Missing) {
			return false
		}
	}
	return true
}

func (r *nativeRunner) persistLedger(now time.Time) error {
	if r.ledgerErr != nil {
		return r.ledgerErr
	}
	current, err := r.ops.ReadPrivate(r.ledgerPath(), maximumLedgerBytes)
	if r.ledgerExists {
		if err != nil || !bytes.Equal(current, r.ledgerRaw) {
			r.ledgerErr = errors.New("restart ledger changed or unavailable")
			return r.ledgerErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		r.ledgerErr = errors.New("unexpected restart ledger object")
		return r.ledgerErr
	}
	raw, err := encodeLedger(r.authority, r.supervisor.Snapshot(now))
	if err != nil {
		r.ledgerErr = err
		return err
	}
	if err := r.ops.WritePrivate(r.ledgerPath(), raw); err != nil {
		r.ledgerErr = errors.New("restart ledger persistence failed")
		return r.ledgerErr
	}
	verified, err := r.ops.ReadPrivate(r.ledgerPath(), maximumLedgerBytes)
	if err != nil || !bytes.Equal(verified, raw) {
		r.ledgerErr = errors.New("restart ledger readback failed")
		return r.ledgerErr
	}
	r.ledgerExists = true
	r.ledgerRaw = append([]byte(nil), raw...)
	return nil
}

func (r *nativeRunner) appendAlert(level, msg string, details map[string]any, now time.Time) error {
	if r.alertErr != nil {
		return r.alertErr
	}
	raw, err := r.ops.ReadPrivate(r.alertPath(), maxAlertFile)
	if errors.Is(err, os.ErrNotExist) {
		if r.alertPrevious != alertGenesis {
			r.alertErr = errors.New("alert evidence disappeared")
			return r.alertErr
		}
		raw = nil
	} else if err != nil {
		r.alertErr = errors.New("alert evidence unavailable")
		return r.alertErr
	}
	tail, err := recoverAlertTail(r.authority, raw)
	if err != nil || tail != r.alertPrevious {
		r.alertErr = errors.New("alert evidence changed or failed authentication")
		return r.alertErr
	}
	identity := make([]byte, 8)
	if _, err := rand.Read(identity); err != nil {
		r.alertErr = errors.New("alert identity unavailable")
		return r.alertErr
	}
	line, mac, err := makeAlert(r.authority, r.alertPrevious, level, msg, details, now, hex.EncodeToString(identity))
	if err != nil {
		return err
	}
	if len(raw)+len(line) > maxAlertFile {
		r.alertErr = errors.New("alert evidence capacity reached")
		return r.alertErr
	}
	if err := r.ops.AppendPrivate(r.alertPath(), line, maxAlertFile); err != nil {
		r.alertErr = errors.New("alert append failed")
		return r.alertErr
	}
	verified, err := r.ops.ReadPrivate(r.alertPath(), maxAlertFile)
	if err != nil || len(verified) != len(raw)+len(line) || !bytes.Equal(verified[:len(raw)], raw) || !bytes.Equal(verified[len(raw):], line) {
		r.alertErr = errors.New("alert append readback failed")
		return r.alertErr
	}
	r.alertPrevious = mac
	return nil
}

func (r *nativeRunner) checkEvidence() error {
	if r.ledgerErr != nil {
		return errors.New("recovery evidence is held")
	}
	if !r.ledgerExists {
		return errors.New("restart ledger has not been persisted")
	}
	raw, err := r.ops.ReadPrivate(r.ledgerPath(), maximumLedgerBytes)
	if err != nil || !bytes.Equal(raw, r.ledgerRaw) {
		r.ledgerErr = errors.New("restart ledger changed or unavailable")
		return r.ledgerErr
	}
	return nil
}

func (r *nativeRunner) finalGate() error {
	stop, err := r.readStop(r.ops.Now())
	if err != nil {
		return err
	}
	if stop.Active {
		return errors.New("verified STOP blocks recovery")
	}
	if err := r.checkEvidence(); err != nil {
		return err
	}
	if !launchable(r.observe()) {
		return errors.New("peer generation blocks duplicate launch")
	}
	return nil
}

func (r *nativeRunner) attempt(now time.Time) error {
	locks, err := r.ops.ClaimLocks(r.config.DataDir)
	if err != nil {
		return errors.New("peer spawn claim unavailable")
	}
	if locks == nil {
		return errors.New("peer spawn claim unavailable")
	}
	defer func() {
		if locks.Close() != nil {
			r.runtimeErr = errors.New("peer spawn claim release unverified")
		}
	}()
	if err := r.finalGate(); err != nil {
		return err
	}
	if err := r.persistLedger(now); err != nil {
		return err
	}
	pressure, counts := r.supervisor.pressure(now)
	// Logging loss is visible evidence, never authority to abandon recovery.
	// A full/corrupt outbox is preserved and no further appends are attempted.
	r.appendAlert("HIGH", "Native watchdog recovery attempt", map[string]any{"attempts": r.supervisor.attempts, "restart_10m": counts[0], "restart_1h": counts[1], "restart_24h": counts[2], "pressure": pressure}, now)
	process, err := r.ops.Launch(r.config, pressure, r.finalGate)
	if process != nil {
		r.launched = process
		if err != nil || process.Birth() == 0 {
			r.runtimeErr = errors.New("created process identity unverified")
		}
		return nil
	} // Even an identity/close error means a child was created.
	if err != nil {
		return errors.New("pinned native recovery launch failed")
	}
	return errors.New("native launcher returned no retained process")
}

func (r *nativeRunner) heartbeat(now time.Time, running bool) error {
	r.heartbeatCounter++
	flags := heartbeatV2
	if running {
		flags |= heartbeatRunning
	}
	raw, err := encodeHeartbeat(r.authority, "watchdog3", heartbeatRecord{uint64(now.UnixNano()), r.ops.OwnPID, r.heartbeatCounter, flags})
	if err != nil {
		return err
	}
	return r.ops.WritePrivate(r.heartbeatPath("watchdog3"), raw)
}

func (r *nativeRunner) tick(now time.Time) supervisorDecision {
	if r.service != nil {
		return r.tickService(now)
	}
	stop, stopErr := r.readStop(now)
	peers := r.observe()
	r.heartbeatPublished = false
	gateErr := stopErr
	if stopErr == nil {
		if err := r.heartbeat(now, true); err != nil {
			gateErr = errors.New("native heartbeat publication failed")
		} else {
			r.heartbeatPublished = true
		}
	}
	if stopErr == nil && r.ledgerErr == nil && !r.ledgerExists {
		r.persistLedger(now)
	}
	if gateErr == nil && !stop.Active {
		if r.ledgerErr != nil {
			gateErr = r.ledgerErr
		}
	}
	decision := r.supervisor.Step(now, peers, stop, gateErr, func() error { return r.attempt(now) })
	if stopErr == nil && (decision.State != r.lastState || decision.Pressure != r.lastPressure || decision.Attempted) {
		level := "MEDIUM"
		if decision.Error != nil {
			level = "HIGH"
		}
		if decision.Pressure == "attack" {
			level = "CRITICAL"
		}
		r.appendAlert(level, "Native watchdog supervision decision", map[string]any{"state": decision.State, "core_state": decision.Peers[0], "watchdog_state": decision.Peers[1], "attempted": decision.Attempted, "pressure": decision.Pressure, "restart_10m": decision.Counts[0], "restart_1h": decision.Counts[1], "restart_24h": decision.Counts[2]}, now)
	}
	r.lastState, r.lastPressure, r.lastDecision = decision.State, decision.Pressure, decision
	if r.lastStatus.IsZero() || now.Sub(r.lastStatus) >= 5*time.Second {
		if stopErr == nil && r.ledgerErr == nil {
			r.persistLedger(now)
		}
		r.writeStatus(now, decision, stop, stopErr)
		r.lastStatus = now
	}
	return decision
}

func (r *nativeRunner) writeStatus(now time.Time, decision supervisorDecision, stop stopDecision, stopErr error) {
	core, watchdog := decision.Peers[0], decision.Peers[1]
	if core == "" {
		core = "unavailable"
	}
	if watchdog == "" {
		watchdog = "unavailable"
	}
	status := map[string]any{"schema": 1, "component": "watchdog3", "state": decision.State, "pid": r.ops.OwnPID, "ts": float64(now.UnixNano()) / 1e9, "ts_iso": now.UTC().Format(time.RFC3339), "protocol": 2, "core_state": core, "watchdog_state": watchdog, "stop_active": stop.Active, "stop_source": stop.Source, "authority_verified": stopErr == nil, "ledger_authenticated": r.ledgerErr == nil, "alert_chain_verified": r.alertErr == nil, "runtime_verified": r.runtimeErr == nil, "heartbeat_published": r.heartbeatPublished, "coverage_gap": core != "alive" || watchdog != "alive" || stopErr != nil || r.ledgerErr != nil || r.alertErr != nil || r.runtimeErr != nil, "restart_pressure": decision.Pressure, "restart_10m": decision.Counts[0], "restart_1h": decision.Counts[1], "restart_24h": decision.Counts[2], "retry_after_s": decision.RetryAfter.Seconds(), "response_authority": false, "resource_snapshot": "unavailable"}
	raw, err := json.Marshal(status)
	if err == nil && len(raw) <= 16*1024 {
		if r.ops.WritePrivate(filepath.Join(r.config.DataDir, "diagnostics", "status_watchdog3.json"), raw) != nil {
			r.runtimeErr = errors.New("status publication gap")
		}
	}
}

func (r *nativeRunner) close(now time.Time) error {
	var first error
	if r.authorityCurrent() == nil {
		if r.heartbeat(now, false) != nil {
			first = errors.New("final heartbeat publication unavailable")
		}
	} else {
		first = errors.New("final authority unavailable")
	}
	for index := range r.peers {
		if r.peers[index].retained != nil {
			if err := r.peers[index].retained.Close(); err != nil && first == nil {
				first = err
			}
			r.peers[index].retained = nil
		}
	}
	if r.launched != nil {
		if err := r.launched.Close(); err != nil && first == nil {
			first = err
		}
		r.launched = nil
	}
	return first
}

func runSupervision(ctx context.Context, r *nativeRunner) (result error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() {
		if r.close(r.ops.Now()) != nil && result == nil {
			result = errors.New("native handle cleanup or final heartbeat could not be verified")
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		r.tick(r.ops.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
