"""Quiet recorder waits must reduce idle work without delaying evidence or stop."""
from __future__ import annotations

from types import SimpleNamespace
import threading

import pytest

from angerona.core import background_pacing, storage
from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.storage import AsyncFlightRecorder, BatchRecordResult, DLQReplayResult


class _Recorder:
    authority = BusAuthority(b"q" * 32)

    def __init__(self):
        self.primary, self.overflow = [], []
        self.persisted = threading.Event()
        self.overflowed = threading.Event()

    def record_batch_bus(self, events):
        self.primary.extend(events)
        self.persisted.set()
        return BatchRecordResult(len(events), 0)

    def _route_batch_to_dlq(self, events):
        self.overflow.extend(events)
        self.overflowed.set()
        return len(events)

    def _route_to_dlq(self, event):
        self.overflow.append(event)
        self.overflowed.set()
        return True


@pytest.fixture
def quiet(monkeypatch):
    state = SimpleNamespace(quiet=True)
    monkeypatch.setattr(background_pacing, "get_pacing_controller",
                        lambda: SimpleNamespace(chill_active=lambda: state.quiet))
    return state


def _observe_get(monkeypatch, pending):
    entered = threading.Event()
    timeouts = []
    original = pending.get

    def observed(*args, **kwargs):
        timeouts.append(kwargs.get("timeout"))
        entered.set()
        return original(*args, **kwargs)

    monkeypatch.setattr(pending, "get", observed)
    return entered, timeouts


def test_long_empty_waits_end_immediately_on_stop_without_storing_wake_tokens(quiet, monkeypatch):
    recorder = _Recorder()
    worker = AsyncFlightRecorder(recorder)
    monkeypatch.setattr(worker, "_idle_wait_seconds", lambda: 60.0)
    primary, primary_timeouts = _observe_get(monkeypatch, worker._queue)
    overflow, overflow_timeouts = _observe_get(monkeypatch, worker._overflow_queue)
    try:
        assert worker.start()
        assert primary.wait(2.0) and overflow.wait(2.0)
        assert primary_timeouts == overflow_timeouts == [60.0]
        # This must wake both real queue waits rather than waiting sixty seconds.
        assert worker.stop(2.0)
        assert not recorder.primary and not recorder.overflow
        metrics = worker.metrics()
        assert metrics.queue_depth == metrics.overflow_queue_depth == 0
        assert metrics.accepted == metrics.persisted == metrics.overflow_dlq == 0
        assert worker.stop(0.0)
    finally:
        worker.stop(2.0)


def test_chill_first_event_wakes_now_and_keeps_short_batch_flush(quiet, monkeypatch):
    recorder = _Recorder()
    worker = AsyncFlightRecorder(recorder, flush_interval=0.02)
    entered, timeouts = _observe_get(monkeypatch, worker._queue)
    try:
        assert worker.start() and entered.wait(2.0)
        assert timeouts[0] == 5.0
        worker.submit(Event("test", "critical evidence", Severity.CRITICAL))
        assert recorder.persisted.wait(2.0), "event waited for the five-second idle deadline"
        assert len(recorder.primary) == 1 and recorder.authority.verify(recorder.primary[0])
        assert any(0 < timeout <= 0.020001 for timeout in timeouts), timeouts
        assert worker.stop(2.0)
        assert worker.metrics().dlq_failures == 0
    finally:
        worker.stop(2.0)


def test_chill_overflow_lane_wakes_without_waiting_for_idle_deadline(quiet, monkeypatch):
    recorder = _Recorder()
    worker = AsyncFlightRecorder(recorder)
    entered, timeouts = _observe_get(monkeypatch, worker._overflow_queue)
    try:
        assert worker.start() and entered.wait(2.0)
        assert timeouts[0] == 5.0
        worker._primary_saturated.set()
        worker.submit(Event("test", "signed overflow evidence", Severity.HIGH))
        assert recorder.overflowed.wait(2.0), "overflow waited for the idle deadline"
        assert len(recorder.overflow) == 1 and recorder.authority.verify(recorder.overflow[0])
        assert worker.stop(2.0)
        metrics = worker.metrics()
        assert metrics.overflow_queued == metrics.overflow_dlq == 1
        assert metrics.overflow_synchronous == metrics.dlq_failures == 0
    finally:
        worker.stop(2.0)


def test_idle_policy_restores_full_mode_without_changing_batch_deadline(quiet):
    worker = AsyncFlightRecorder(_Recorder(), flush_interval=0.07)
    assert worker._idle_wait_seconds() == 5.0
    quiet.quiet = False
    assert worker._idle_wait_seconds() == 1.0
    assert worker._flush_interval == 0.07


def test_quiet_disk_replay_is_sparse_but_forced_replay_and_full_mode_restore(quiet, monkeypatch):
    calls = []
    recorder = _Recorder()
    recorder.replay_dlq = lambda **kwargs: (calls.append(kwargs) or DLQReplayResult(0, 0, 0, 0, 0, 0))
    worker = AsyncFlightRecorder(recorder)
    clock = [100.0]
    monkeypatch.setattr(storage.time, "monotonic", lambda: clock[0])
    worker._maybe_replay()
    assert len(calls) == 1
    clock[0] = 129.0
    worker._maybe_replay()
    assert len(calls) == 1
    worker._maybe_replay(force=True)
    assert len(calls) == 2
    quiet.quiet = False
    clock[0] = 131.0
    worker._maybe_replay()
    assert len(calls) == 3
    assert calls == [{"max_segments": 1}] * 3
    assert worker._replay_failures == 0
