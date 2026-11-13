package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func serviceFixture(t *testing.T) (*runnerFixture, *nativeRunner, *serviceObservation) {
	f := newRunnerFixture(t)
	f.config.Schema = 2
	f.config.LauncherArgs = []string{"--engine-service"}
	observation := &serviceObservation{State: "stopped", Win32ExitCode: 1067}
	ops := f.ops()
	ops.ObserveService = func(configuration) (serviceObservation, error) { return *observation, nil }
	r, err := newNativeRunner(f.config, f.control, f.key, f.now, ops)
	if err != nil {
		t.Fatal(err)
	}
	return f, r, observation
}

func TestServiceRunnerCleanSCMStopAlwaysWins(t *testing.T) {
	for _, stale := range []uint32{0, 5, 1066} {
		t.Run(time.Duration(stale).String(), func(t *testing.T) {
			f, r, observation := serviceFixture(t)
			observation.Win32ExitCode = 0
			observation.ServiceExitCode = stale
			for _, after := range []time.Duration{0, 181 * time.Second, 202 * time.Second, 24 * time.Hour} {
				if decision := f.tick(r, after); decision.State != "stopped_clean" || decision.Attempted {
					t.Fatalf("normal SCM stop became recovery: %+v", decision)
				}
			}
			if len(f.created) != 0 {
				t.Fatal("clean SCM STOP restarted")
			}
		})
	}
}

func TestServiceRunnerPendingRunningAndUnknownNeverDuplicate(t *testing.T) {
	for _, state := range []string{"running", "start_pending", "stop_pending", "pause_pending", "continue_pending", "paused", "unknown"} {
		t.Run(state, func(t *testing.T) {
			f, r, observed := serviceFixture(t)
			observed.State = state
			if state == "running" {
				observed.PID = 456
				observed.BirthTicks = fixtureBirth(f.now.Add(-time.Minute))
				observed.ProcessPresent = true
			}
			f.ready(r)
			decision := f.tick(r, 202*time.Second)
			if len(f.created) != 0 || decision.Attempted {
				t.Fatalf("existing service state started duplicate: %+v", decision)
			}
			if state == "running" && decision.State != "observed_running" {
				t.Fatalf("native process observation lost: %+v", decision)
			}
			var status map[string]any
			if err := json.Unmarshal(f.files[filepath.Join(f.config.DataDir, "diagnostics", "status_watchdog3.json")], &status); err != nil {
				t.Fatal(err)
			}
			if status["liveness_proof"] != false || status["service_heartbeat_available"] != false || status["core_peer_observation"] != "unavailable" {
				t.Fatal("SCM process presence was presented as Python liveness")
			}
			if len(f.opened) != 0 {
				t.Fatal("service mode probed fabricated Python peers")
			}
		})
	}
}

func TestServiceRunnerFailedStopRecoversAndRetainsPendingServiceReference(t *testing.T) {
	f, r, observation := serviceFixture(t)
	f.ready(r)
	decision := f.tick(r, 202*time.Second)
	if decision.State != "service_start_requested" || len(f.created) != 1 || f.locksClosed != 1 {
		t.Fatalf("SCM failure not recovered once: %+v", decision)
	}
	saved, err := decodeLedger(f.key, f.files[r.ledgerPath()])
	if err != nil || saved.Attempts != 1 {
		t.Fatal("SCM attempt not durably authenticated before start", err)
	}
	observation.State = "start_pending"
	f.tick(r, 500*time.Second)
	if len(f.created) != 1 || f.created[0].closed != 0 {
		t.Fatal("pending SCM reference forgotten")
	}
	observation.State = "running"
	observation.PID = 456
	observation.BirthTicks = fixtureBirth(f.now.Add(-time.Second))
	observation.ProcessPresent = true
	if next := f.tick(r, 501*time.Second); next.State != "observed_running" || r.supervisor.attempts != 0 {
		t.Fatalf("real SCM running observation did not reset backoff: %+v", next)
	}
	for _, path := range f.reads {
		if strings.HasSuffix(path, "core.hb") || strings.HasSuffix(path, "watchdog.hb") {
			t.Fatal("service mode synthesized Python heartbeat coverage")
		}
	}
}

func TestServiceRunnerFinalSTOPAndFreshCleanSCMStateVetoStart(t *testing.T) {
	for _, kind := range []string{"signed-stop", "clean-scm-stop", "running-under-lock"} {
		t.Run(kind, func(t *testing.T) {
			f, r, observed := serviceFixture(t)
			f.ready(r)
			if kind == "running-under-lock" {
				f.onClaim = func() {
					observed.State = "running"
					observed.PID = 456
					observed.BirthTicks = fixtureBirth(f.now)
					observed.ProcessPresent = true
				}
			} else {
				f.onLaunch = func(gate func() error) (processRef, error) {
					if kind == "signed-stop" {
						vectors := loadProtocolVectors(t)
						f.files[filepath.Join(f.config.DataDir, "ipc", "standdown.cmd")] = []byte(vectors.Stop["legacy_operator"])
					} else {
						observed.Win32ExitCode = 0
					}
					if err := gate(); err != nil {
						return nil, err
					}
					t.Fatal("final service gate did not veto start")
					return nil, nil
				}
			}
			if decision := f.tick(r, 202*time.Second); decision.State != "launch_failed" || len(f.created) != 0 {
				t.Fatalf("fresh authority/state did not block start: %+v", decision)
			}
			if f.locksClosed != 1 {
				t.Fatal("own spawn claim not released")
			}
		})
	}
}

func TestServiceRunnerLoggingGapKeepsRetryingButLedgerFailureHolds(t *testing.T) {
	f, r, _ := serviceFixture(t)
	f.appendFail = true
	f.ready(r)
	if decision := f.tick(r, 202*time.Second); decision.State != "service_start_requested" {
		t.Fatalf("outbox failure abandoned SCM recovery: %+v", decision)
	}
	last := 202 * time.Second
	for attempt := 1; attempt < 10; attempt++ {
		f.created[len(f.created)-1].present = false
		f.tick(r, last+181*time.Second)
		last += 202 * time.Second
		if decision := f.tick(r, last); decision.State != "service_start_requested" || len(f.created) != attempt+1 {
			t.Fatalf("SCM recovery permanently gave up after log loss: %+v", decision)
		}
	}
	if r.alertErr == nil {
		t.Fatal("logging gap not retained")
	}
	f.created[len(f.created)-1].present = false
	f.ledgerFail = true
	f.tick(r, last+181*time.Second)
	f.tick(r, last+202*time.Second)
	if len(f.created) != 10 || r.ledgerErr == nil {
		t.Fatal("failed durable ledger did not block start")
	}
}

func TestServiceSupervisorStormNeverGivesUpAndBackoffIsBounded(t *testing.T) {
	start := time.Unix(1700000000, 0)
	s := serviceSupervisor{base: newSupervisor(start)}
	failed := serviceObservation{State: "stopped", Win32ExitCode: 1067}
	calls := 0
	launch := func() error { calls++; return errors.New("inert start failure") }
	s.Step(start, failed, nil, stopDecision{}, nil, launch)
	s.Step(start.Add(181*time.Second), failed, nil, stopDecision{}, nil, launch)
	now := start.Add(202 * time.Second)
	for attempt := 0; attempt < 50; attempt++ {
		decision := s.Step(now, failed, nil, stopDecision{}, nil, launch)
		if !decision.Attempted || decision.RetryAfter > 60*time.Second || decision.RetryAfter <= 0 {
			t.Fatalf("storm stopped or backoff escaped cap: %+v", decision)
		}
		now = now.Add(decision.RetryAfter)
	}
	if calls != 50 || s.base.attempts != 50 {
		t.Fatal("storm permanently stopped supervision")
	}
	pressure, _ := s.base.pressure(now)
	if pressure != "attack" {
		t.Fatal("storm did not escalate")
	}
}
