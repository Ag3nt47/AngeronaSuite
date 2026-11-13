package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"time"
)

func (r *nativeRunner) observeService() (serviceObservation, error) {
	o, err := r.ops.ObserveService(r.config)
	o.State = safeServiceState(o.State)
	if r.launched != nil {
		present, e := r.launched.Present()
		if e != nil {
			o.IdentityUnknown = true
		} else if !present {
			if r.launched.Close() != nil {
				o.IdentityUnknown = true
			} else {
				r.launched = nil
			}
		} else if o.State == "stopped" {
			o.IdentityUnknown = true
		}
	}
	return o, err
}
func serviceStartEligible(o serviceObservation) bool {
	return o.State == "stopped" && o.Win32ExitCode != 0 && !o.ProcessPresent && !o.IdentityUnknown && o.PID == 0
}
func (r *nativeRunner) finalServiceGate() error {
	stop, err := r.readStop(r.ops.Now())
	if err != nil {
		return err
	}
	if stop.Active {
		return errors.New("verified STOP blocks service recovery")
	}
	if err := r.checkEvidence(); err != nil {
		return err
	}
	o, err := r.observeService()
	if err != nil || !serviceStartEligible(o) {
		return errors.New("fresh service state blocks recovery")
	}
	return nil
}
func (r *nativeRunner) attemptService(now time.Time) error {
	locks, err := r.ops.ClaimLocks(r.config.DataDir)
	if err != nil || locks == nil {
		return errors.New("service spawn claim unavailable")
	}
	defer func() {
		if locks.Close() != nil {
			r.runtimeErr = errors.New("service spawn claim release unverified")
		}
	}()
	if err := r.finalServiceGate(); err != nil {
		return err
	}
	if err := r.persistLedger(now); err != nil {
		return err
	}
	pressure, counts := r.supervisor.pressure(now)
	r.appendAlert("HIGH", "Native watchdog service recovery attempt", map[string]any{"attempts": r.supervisor.attempts, "restart_10m": counts[0], "restart_1h": counts[1], "restart_24h": counts[2], "pressure": pressure}, now)
	p, err := r.ops.Launch(r.config, pressure, r.finalServiceGate)
	if p != nil {
		r.launched = p
		if err != nil {
			r.runtimeErr = errors.New("service recovery result needs observation")
		}
		return nil
	}
	if err != nil {
		return errors.New("fixed SCM service recovery failed")
	}
	return errors.New("service recovery returned no retained reference")
}
func (r *nativeRunner) tickService(now time.Time) supervisorDecision {
	stop, stopErr := r.readStop(now)
	o, oErr := r.observeService()
	r.heartbeatPublished = false
	gateErr := stopErr
	if stopErr == nil {
		if r.heartbeat(now, true) != nil {
			gateErr = errors.New("native heartbeat publication failed")
		} else {
			r.heartbeatPublished = true
		}
	}
	if stopErr == nil && r.ledgerErr == nil && !r.ledgerExists {
		r.persistLedger(now)
	}
	if gateErr == nil && !stop.Active && r.ledgerErr != nil {
		gateErr = r.ledgerErr
	}
	d := r.service.Step(now, o, oErr, stop, gateErr, func() error { return r.attemptService(now) })
	if stopErr == nil && (d.State != r.lastState || d.Pressure != r.lastPressure || d.Attempted) {
		level := "MEDIUM"
		if d.Error != nil {
			level = "HIGH"
		}
		if d.Pressure == "attack" {
			level = "CRITICAL"
		}
		r.appendAlert(level, "Native watchdog service supervision decision", map[string]any{"state": d.State, "service_state": o.State, "attempted": d.Attempted, "pressure": d.Pressure, "restart_10m": d.Counts[0], "restart_1h": d.Counts[1], "restart_24h": d.Counts[2]}, now)
	}
	r.lastState, r.lastPressure, r.lastDecision = d.State, d.Pressure, d
	if r.lastStatus.IsZero() || now.Sub(r.lastStatus) >= 5*time.Second {
		if stopErr == nil && r.ledgerErr == nil {
			r.persistLedger(now)
		}
		r.writeServiceStatus(now, d, o, stop, stopErr, oErr)
		r.lastStatus = now
	}
	return d
}
func (r *nativeRunner) writeServiceStatus(now time.Time, d supervisorDecision, o serviceObservation, stop stopDecision, stopErr, oErr error) {
	status := map[string]any{"schema": 2, "component": "watchdog3", "state": d.State, "pid": r.ops.OwnPID, "ts": float64(now.UnixNano()) / 1e9, "ts_iso": now.UTC().Format(time.RFC3339), "protocol": 2, "supervision_mode": "scm-service", "service_name": "AngeronaProtection", "service_state": o.State, "service_pid": o.PID, "service_identity_verified": oErr == nil && !o.IdentityUnknown && o.ProcessPresent && o.PID != 0 && o.BirthTicks != 0, "service_heartbeat_available": false, "liveness_proof": false, "core_peer_observation": "unavailable", "watchdog_peer_observation": "unavailable", "stop_active": stop.Active, "stop_source": stop.Source, "authority_verified": stopErr == nil, "ledger_authenticated": r.ledgerErr == nil, "alert_chain_verified": r.alertErr == nil, "runtime_verified": r.runtimeErr == nil, "heartbeat_published": r.heartbeatPublished, "coverage_gap": true, "win32_exit_code": o.Win32ExitCode, "service_exit_code": o.ServiceExitCode, "restart_pressure": d.Pressure, "restart_10m": d.Counts[0], "restart_1h": d.Counts[1], "restart_24h": d.Counts[2], "retry_after_s": d.RetryAfter.Seconds(), "response_authority": false, "resource_snapshot": "unavailable"}
	raw, err := json.Marshal(status)
	if err == nil && len(raw) <= 16*1024 {
		if r.ops.WritePrivate(filepath.Join(r.config.DataDir, "diagnostics", "status_watchdog3.json"), raw) != nil {
			r.runtimeErr = errors.New("status publication gap")
		}
	}
}
