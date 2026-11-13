package main

import (
	"errors"
	"time"
)

const (
	startupGrace          = 180 * time.Second
	bothDownGrace         = 20 * time.Second
	maximumBackoff        = 60 * time.Second
	pressureHorizon       = 24 * time.Hour
	maximumPressureEvents = 64
)

// A missing record differs from an invalid one. ProcessPresent includes any
// still-retained previously authenticated generation, even if its current
// heartbeat disappears. IdentityUnknown must never grant replacement authority.
type peerObservation struct {
	Authenticated, Missing, Running, ProcessPresent, IdentityUnknown bool
	PID, Counter                                                     uint32
	BirthTicks, TimestampNS                                          uint64
}

type trackedPeer struct {
	pid      uint32
	birth    uint64
	counter  uint32
	stamp    uint64
	changed  time.Time
	advanced bool
}

type supervisorDecision struct {
	State      string
	Peers      [2]string
	Attempted  bool
	Pressure   string
	Counts     [3]int
	RetryAfter time.Duration
	Error      error
}

// This bounded snapshot is authenticated by the caller before Restore. Wall
// times are storage values only; all in-process deadlines use monotonic time.
type supervisorSnapshot struct {
	Schema       int     `json:"schema"`
	Stops        []int64 `json:"stops"`
	Attempts     uint32  `json:"attempts"`
	RetryAfterNS int64   `json:"retry_after_ns"`
}

type supervisor struct {
	started, last, bothDownSince, nextAttempt, settleUntil time.Time
	peers                                                  [2]trackedPeer
	stops                                                  []int64
	attempts                                               uint32
	backoff                                                time.Duration
	hadHealthy, recordedDown                               bool
}

func newSupervisor(now time.Time) *supervisor {
	return &supervisor{started: now, settleUntil: now.Add(startupGrace)}
}

func (s *supervisor) classify(index int, p peerObservation, now time.Time) string {
	if p.IdentityUnknown {
		return "identity_unknown"
	}
	if !p.Authenticated {
		if p.ProcessPresent {
			return "present_unverified"
		}
		if p.Missing {
			return "missing"
		}
		return "unauthenticated"
	}
	if p.PID == 0 || p.TimestampNS == 0 {
		return "unauthenticated"
	}
	if p.TimestampNS > uint64(1<<63-1) {
		return "clock_unknown"
	}
	age := now.Sub(time.Unix(0, int64(p.TimestampNS)))
	if age < -5*time.Second {
		return "clock_unknown"
	}
	if !p.ProcessPresent {
		return "dead"
	}
	if p.BirthTicks == 0 {
		return "identity_unknown"
	}
	previous := &s.peers[index]
	if previous.pid != p.PID || previous.birth != p.BirthTicks {
		*previous = trackedPeer{pid: p.PID, birth: p.BirthTicks, counter: p.Counter, stamp: p.TimestampNS, changed: now}
		return "starting"
	}
	// Authentication belongs to the codec; progression is bound again here to
	// this retained process generation and the monotonic observation clock.
	if p.TimestampNS < previous.stamp || (p.Counter < previous.counter && !(previous.counter > 0xffff0000 && p.Counter < 0x0000ffff)) {
		return "replay"
	}
	stale := 12 * time.Second
	if index == 1 {
		stale = 10 * time.Second
	}
	if p.Counter != previous.counter {
		previous.counter, previous.stamp, previous.changed, previous.advanced = p.Counter, p.TimestampNS, now, true
	}
	previous.stamp = p.TimestampNS
	if !p.Running {
		return "present_stopped"
	}
	if age >= stale || now.Sub(previous.changed) >= stale {
		return "suspended"
	}
	if !previous.advanced {
		return "starting"
	}
	return "alive"
}

func (s *supervisor) pressure(now time.Time) (string, [3]int) {
	cut := now.Add(-pressureHorizon).UnixNano()
	kept := s.stops[:0]
	counts := [3]int{}
	for _, stamp := range s.stops {
		if stamp < cut {
			continue
		}
		kept = append(kept, stamp)
		age := now.UnixNano() - stamp
		if age <= int64(10*time.Minute) {
			counts[0]++
		}
		if age <= int64(time.Hour) {
			counts[1]++
		}
		counts[2]++
	}
	s.stops = kept
	if counts[1] >= 5 || counts[2] >= 12 || s.attempts >= 5 {
		return "attack", counts
	}
	if counts[0] >= 3 {
		return "elevated", counts
	}
	return "", counts
}

func (s *supervisor) Step(now time.Time, peers [2]peerObservation, stop stopDecision, stopErr error, launch func() error) supervisorDecision {
	d := supervisorDecision{}
	if now.IsZero() || now.Before(s.started) || (!s.last.IsZero() && now.Before(s.last)) {
		d.State, d.Error = "held", errors.New("monotonic observation clock regressed")
		return d
	}
	s.last = now
	d.Pressure, d.Counts = s.pressure(now)
	if stopErr != nil {
		s.bothDownSince = time.Time{}
		d.State, d.Error = "held", stopErr
		return d
	}
	if stop.Active {
		s.bothDownSince = time.Time{}
		d.State = "standdown"
		return d
	}
	blocked, healthy := false, false
	for i, p := range peers {
		d.Peers[i] = s.classify(i, p, now)
		if d.Peers[i] == "alive" {
			healthy = true
		}
		// No existing, suspended, ambiguous or invalid generation is replaced.
		if p.ProcessPresent || p.IdentityUnknown || (!p.Authenticated && !p.Missing) || (p.Authenticated && d.Peers[i] != "dead") {
			blocked = true
		}
	}
	if healthy {
		s.hadHealthy = true
		s.recordedDown = false
		s.attempts = 0
		s.backoff = 0
		s.nextAttempt = time.Time{}
	}
	if blocked {
		s.bothDownSince = time.Time{}
		d.State = "observing"
		return d
	}
	if now.Before(s.settleUntil) {
		d.State, d.RetryAfter = "startup_grace", s.settleUntil.Sub(now)
		return d
	}
	if s.bothDownSince.IsZero() {
		s.bothDownSince = now
		if s.hadHealthy && !s.recordedDown {
			s.stops = append(s.stops, now.UnixNano())
			if len(s.stops) > maximumPressureEvents {
				s.stops = s.stops[len(s.stops)-maximumPressureEvents:]
			}
			s.recordedDown = true
			d.Pressure, d.Counts = s.pressure(now)
		}
	}
	if now.Sub(s.bothDownSince) < bothDownGrace {
		d.State, d.RetryAfter = "both_down_grace", bothDownGrace-now.Sub(s.bothDownSince)
		return d
	}
	if now.Before(s.nextAttempt) {
		d.State, d.RetryAfter = "backoff", s.nextAttempt.Sub(now)
		return d
	}
	if launch == nil {
		d.State, d.Error = "held", errors.New("fixed launcher is unavailable")
		return d
	}
	d.Attempted = true
	if s.attempts < ^uint32(0) {
		s.attempts++
	}
	if s.backoff == 0 {
		s.backoff = time.Second
	} else if s.backoff < maximumBackoff {
		s.backoff *= 2
	}
	if s.backoff > maximumBackoff {
		s.backoff = maximumBackoff
	}
	s.nextAttempt = now.Add(s.backoff)
	d.Pressure, d.Counts = s.pressure(now)
	if err := launch(); err != nil {
		d.State, d.Error, d.RetryAfter = "launch_failed", err, s.backoff
		return d
	}
	s.settleUntil = now.Add(startupGrace)
	s.bothDownSince = time.Time{}
	d.State, d.RetryAfter = "launched", startupGrace
	return d
}

func (s *supervisor) Snapshot(now time.Time) supervisorSnapshot {
	s.pressure(now)
	retry := int64(0)
	if !s.nextAttempt.IsZero() {
		retry = s.nextAttempt.UnixNano()
	}
	return supervisorSnapshot{Schema: 1, Stops: append([]int64{}, s.stops...), Attempts: s.attempts, RetryAfterNS: retry}
}

func (s *supervisor) Restore(saved supervisorSnapshot, now time.Time) error {
	if saved.Schema != 1 || len(saved.Stops) > maximumPressureEvents || saved.RetryAfterNS < 0 {
		return errors.New("invalid restart ledger")
	}
	last := int64(0)
	for _, stamp := range saved.Stops {
		if stamp <= 0 || stamp < last || stamp > now.UnixNano()+int64(5*time.Second) {
			return errors.New("invalid restart ledger")
		}
		last = stamp
	}
	s.stops = append([]int64{}, saved.Stops...)
	s.attempts = saved.Attempts
	if saved.Attempts > 0 {
		s.backoff = time.Second
		for i := uint32(1); i < saved.Attempts && s.backoff < maximumBackoff; i++ {
			s.backoff *= 2
		}
		if s.backoff > maximumBackoff {
			s.backoff = maximumBackoff
		}
	}
	remaining := time.Unix(0, saved.RetryAfterNS).Sub(now)
	if remaining < 0 {
		remaining = 0
	}
	if remaining > maximumBackoff {
		remaining = maximumBackoff
	}
	s.nextAttempt = now.Add(remaining)
	s.pressure(now)
	return nil
}
