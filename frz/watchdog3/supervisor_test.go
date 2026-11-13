package main

import (
	"errors"
	"testing"
	"time"
)

func absentPeers() [2]peerObservation { return [2]peerObservation{{Missing: true}, {Missing: true}} }
func livePeer(now time.Time, pid uint32, birth uint64, count uint32) peerObservation {
	return peerObservation{Authenticated: true, Running: true, ProcessPresent: true, PID: pid, BirthTicks: birth, Counter: count, TimestampNS: uint64(now.UnixNano())}
}
func TestBothGoneRequireStartupAndContinuousGrace(t *testing.T) {
	start := time.Unix(1750000000, 0)
	s := newSupervisor(start)
	launched := 0
	launch := func() error { launched++; return nil }
	for _, seconds := range []int{0, 20, 179} {
		d := s.Step(start.Add(time.Duration(seconds)*time.Second), absentPeers(), stopDecision{}, nil, launch)
		if d.State != "startup_grace" || launched != 0 {
			t.Fatalf("premature launch: %+v", d)
		}
	}
	if d := s.Step(start.Add(startupGrace), absentPeers(), stopDecision{}, nil, launch); d.State != "both_down_grace" {
		t.Fatal(d)
	}
	if d := s.Step(start.Add(startupGrace+bothDownGrace-time.Nanosecond), absentPeers(), stopDecision{}, nil, launch); d.Attempted {
		t.Fatal("grace bypassed")
	}
	if d := s.Step(start.Add(startupGrace+bothDownGrace), absentPeers(), stopDecision{}, nil, launch); d.State != "launched" || launched != 1 {
		t.Fatal(d)
	}
	if d := s.Step(start.Add(startupGrace+bothDownGrace+time.Second), absentPeers(), stopDecision{}, nil, launch); d.Attempted || launched != 1 {
		t.Fatal("duplicate launch while starting")
	}
}
func TestPresentSuspendedAndAmbiguousPeersNeverPermitReplacement(t *testing.T) {
	start := time.Unix(1750000000, 0)
	for _, kind := range []string{"present", "frozen", "stopped", "invalid", "missing-retained", "unknown", "reused"} {
		t.Run(kind, func(t *testing.T) {
			s := newSupervisor(start)
			p := livePeer(start, 99, 9001, 1)
			s.Step(start, [2]peerObservation{p, {Missing: true}}, stopDecision{}, nil, nil)
			now := start.Add(300 * time.Second)
			switch kind {
			case "present":
				p = livePeer(now, 99, 9001, 2)
			case "stopped":
				p.Running = false
			case "invalid":
				p.Authenticated = false
			case "missing-retained":
				p.Authenticated = false
				p.Missing = true
			case "unknown":
				p.ProcessPresent = false
				p.IdentityUnknown = true
			case "reused":
				p.BirthTicks++
			}
			calls := 0
			for i := 0; i < 5; i++ {
				d := s.Step(now.Add(time.Duration(i)*time.Minute), [2]peerObservation{p, {Missing: true}}, stopDecision{}, nil, func() error { calls++; return nil })
				if d.Attempted || calls != 0 {
					t.Fatalf("existing or ambiguous generation replaced: %+v", d)
				}
			}
		})
	}
}
func TestLivenessNeedsAdvancingGenerationAndRejectsReplay(t *testing.T) {
	start := time.Unix(1750000000, 0)
	s := newSupervisor(start)
	p := livePeer(start, 55, 6001, 1)
	if got := s.classify(0, p, start); got != "starting" {
		t.Fatal(got)
	}
	p.Counter++
	p.TimestampNS = uint64(start.Add(time.Second).UnixNano())
	if got := s.classify(0, p, start.Add(time.Second)); got != "alive" {
		t.Fatal(got)
	}
	p.Counter--
	if got := s.classify(0, p, start.Add(2*time.Second)); got != "replay" {
		t.Fatal(got)
	}
	p.Counter++
	p.BirthTicks++
	if got := s.classify(0, p, start.Add(3*time.Second)); got != "starting" {
		t.Fatal("PID reuse inherited liveness", got)
	}
	p.TimestampNS = uint64(start.Add(24 * time.Hour).UnixNano())
	p.Counter++
	if got := s.classify(0, p, start.Add(4*time.Second)); got != "clock_unknown" {
		t.Fatal(got)
	}
}
func TestStopAndInvalidAuthorityBlockEveryLaunch(t *testing.T) {
	start := time.Unix(1750000000, 0)
	for _, invalid := range []bool{false, true} {
		s := newSupervisor(start)
		now := start.Add(10 * time.Minute)
		calls := 0
		var authorityErr error
		stop := stopDecision{Active: !invalid}
		if invalid {
			authorityErr = errors.New("invalid fixture authority")
		}
		for i := 0; i < 100; i++ {
			d := s.Step(now.Add(time.Duration(i)*time.Minute), absentPeers(), stop, authorityErr, func() error { calls++; return nil })
			if d.Attempted || calls != 0 {
				t.Fatal("STOP or held authority bypassed")
			}
		}
	}
}
func TestBackoffNeverGivesUpAndEscalatesPersistedPressure(t *testing.T) {
	start := time.Unix(1750000000, 0)
	s := newSupervisor(start)
	now := start.Add(startupGrace)
	s.Step(now, absentPeers(), stopDecision{}, nil, nil)
	now = now.Add(bothDownGrace)
	for i := 0; i < 100; i++ {
		d := s.Step(now, absentPeers(), stopDecision{}, nil, func() error { return errors.New("inert denied launch") })
		if !d.Attempted || d.State != "launch_failed" || d.RetryAfter < time.Second || d.RetryAfter > maximumBackoff {
			t.Fatalf("attempt %d: %+v", i, d)
		}
		if i >= 4 && d.Pressure != "attack" {
			t.Fatal("restart storm not escalated")
		}
		now = now.Add(d.RetryAfter)
	}
	restored := newSupervisor(now)
	if err := restored.Restore(s.Snapshot(now), now); err != nil {
		t.Fatal(err)
	}
	if level, _ := restored.pressure(now); level != "attack" {
		t.Fatal("pressure lost across restart")
	}
	if restored.backoff != maximumBackoff {
		t.Fatal("backoff reset across restart")
	}
}
func TestPressureWindowsAndCorruptLedgerAreBounded(t *testing.T) {
	now := time.Unix(1750000000, 0)
	s := newSupervisor(now)
	s.stops = []int64{now.Add(-9 * time.Minute).UnixNano(), now.Add(-5 * time.Minute).UnixNano(), now.UnixNano()}
	if level, c := s.pressure(now); level != "elevated" || c[0] != 3 {
		t.Fatal(level, c)
	}
	s.stops = append(s.stops, now.UnixNano(), now.UnixNano())
	if level, _ := s.pressure(now); level != "attack" {
		t.Fatal(level)
	}
	for _, bad := range []supervisorSnapshot{{Schema: 2}, {Schema: 1, Stops: []int64{-1}}, {Schema: 1, RetryAfterNS: -1}, {Schema: 1, Stops: make([]int64, 65)}} {
		if err := s.Restore(bad, now); err == nil {
			t.Fatal("malformed pressure accepted")
		}
	}
	fresh := newSupervisor(now)
	if err := fresh.Restore(newSupervisor(now).Snapshot(now), now); err != nil {
		t.Fatal("empty ledger rejected", err)
	}
}
func TestRegressedObservationClockCannotTriggerRecovery(t *testing.T) {
	now := time.Unix(1750000000, 0)
	s := newSupervisor(now)
	s.Step(now.Add(time.Hour), absentPeers(), stopDecision{}, nil, nil)
	d := s.Step(now.Add(time.Minute), absentPeers(), stopDecision{}, nil, func() error { t.Fatal("launched under regressed clock"); return nil })
	if d.State != "held" {
		t.Fatal(d)
	}
}

func TestFutureAuthenticatedRecordCannotAuthorizeGonePeerReplacement(t *testing.T) {
	now := time.Unix(1750000000, 0)
	for _, stamp := range []uint64{uint64(now.Add(time.Hour).UnixNano()), ^uint64(0)} {
		s := newSupervisor(now)
		peers := absentPeers()
		peers[0] = peerObservation{Authenticated: true, PID: 77, Counter: 2, TimestampNS: stamp, Running: true}
		for i := 0; i < 5; i++ {
			d := s.Step(now.Add(5*time.Minute+time.Duration(i)*time.Minute), peers, stopDecision{}, nil, func() error { t.Fatal("future record authorized launch"); return nil })
			if d.Peers[0] != "clock_unknown" || d.Attempted {
				t.Fatal(d)
			}
		}
	}
}
