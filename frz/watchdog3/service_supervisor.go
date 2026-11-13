package main

import (
	"errors"
	"time"
)

// SCM state is observation, not a fabricated Python heartbeat or liveness proof.
type serviceObservation struct {
	State                           string
	PID                             uint32
	BirthTicks                      uint64
	ProcessPresent, IdentityUnknown bool
	Win32ExitCode, ServiceExitCode  uint32
}
type serviceSupervisor struct {
	base         *supervisor
	failureSince time.Time
}

func safeServiceState(state string) string {
	switch state {
	case "stopped", "start_pending", "stop_pending", "running", "continue_pending", "pause_pending", "paused":
		return state
	default:
		return "unknown"
	}
}

func (s *serviceSupervisor) Step(now time.Time, o serviceObservation, oErr error, stop stopDecision, stopErr error, launch func() error) supervisorDecision {
	b := s.base
	d := supervisorDecision{}
	if now.IsZero() || now.Before(b.started) || (!b.last.IsZero() && now.Before(b.last)) {
		d.State, d.Error = "held", errors.New("monotonic observation clock regressed")
		return d
	}
	b.last = now
	d.Pressure, d.Counts = b.pressure(now)
	if stopErr != nil {
		s.failureSince = time.Time{}
		d.State, d.Error = "held", stopErr
		return d
	}
	if stop.Active {
		s.failureSince = time.Time{}
		d.State = "standdown"
		return d
	}
	if oErr != nil || o.IdentityUnknown {
		s.failureSince = time.Time{}
		d.State, d.Error = "held", errors.New("service observation unavailable")
		return d
	}
	switch safeServiceState(o.State) {
	case "running":
		s.failureSince = time.Time{}
		if !o.ProcessPresent || o.PID == 0 || o.BirthTicks == 0 {
			d.State, d.Error = "held", errors.New("running service identity unavailable")
			return d
		}
		b.hadHealthy = true
		b.recordedDown = false
		b.attempts = 0
		b.backoff = 0
		b.nextAttempt = time.Time{}
		d.State = "observed_running"
		return d
	case "start_pending", "stop_pending", "continue_pending", "pause_pending", "paused":
		s.failureSince = time.Time{}
		d.State = "service_pending"
		return d
	case "stopped":
		// A successful SCM STOP wins, including stale service-specific data.
		if o.Win32ExitCode == 0 {
			s.failureSince = time.Time{}
			b.hadHealthy = false
			b.recordedDown = false
			d.State = "stopped_clean"
			return d
		}
		if o.ProcessPresent || o.PID != 0 {
			s.failureSince = time.Time{}
			d.State, d.Error = "held", errors.New("stopped service retains ambiguous process")
			return d
		}
	default:
		s.failureSince = time.Time{}
		d.State, d.Error = "held", errors.New("service state unknown")
		return d
	}
	if now.Before(b.settleUntil) {
		d.State, d.RetryAfter = "startup_grace", b.settleUntil.Sub(now)
		return d
	}
	if s.failureSince.IsZero() {
		s.failureSince = now
		if b.hadHealthy && !b.recordedDown {
			b.stops = append(b.stops, now.UnixNano())
			if len(b.stops) > maximumPressureEvents {
				b.stops = b.stops[len(b.stops)-maximumPressureEvents:]
			}
			b.recordedDown = true
			d.Pressure, d.Counts = b.pressure(now)
		}
	}
	if now.Sub(s.failureSince) < bothDownGrace {
		d.State, d.RetryAfter = "service_failure_grace", bothDownGrace-now.Sub(s.failureSince)
		return d
	}
	if now.Before(b.nextAttempt) {
		d.State, d.RetryAfter = "backoff", b.nextAttempt.Sub(now)
		return d
	}
	if launch == nil {
		d.State, d.Error = "held", errors.New("fixed service recovery unavailable")
		return d
	}
	d.Attempted = true
	if b.attempts < ^uint32(0) {
		b.attempts++
	}
	if b.backoff == 0 {
		b.backoff = time.Second
	} else if b.backoff < maximumBackoff {
		b.backoff *= 2
	}
	if b.backoff > maximumBackoff {
		b.backoff = maximumBackoff
	}
	b.nextAttempt = now.Add(b.backoff)
	d.Pressure, d.Counts = b.pressure(now)
	if err := launch(); err != nil {
		d.State, d.Error, d.RetryAfter = "launch_failed", err, b.backoff
		return d
	}
	b.settleUntil = now.Add(startupGrace)
	s.failureSince = time.Time{}
	d.State, d.RetryAfter = "service_start_requested", startupGrace
	return d
}
