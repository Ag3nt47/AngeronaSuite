"""Deterministic advisory analysis cadence; no sensors, I/O or wall-time claims."""
from queue import Queue
import threading
import time as real_time
from types import SimpleNamespace

import pytest

from angerona.core import sentinel_lens as lens


def wait_until(predicate):
    deadline = real_time.monotonic() + 3
    while not predicate() and real_time.monotonic() < deadline:
        real_time.sleep(.001)
    assert predicate()


def event(number):
    return SimpleNamespace(module="Inert Lens Fixture", message=f"item-{number}",
                           severity=1, ts=float(number), details={}, hmac_sig="")


class PollQueue(Queue):
    """A next blocking-poll handshake observes the completed preceding turn."""
    def __init__(self, service):
        super().__init__(maxsize=service._queue_capacity)
        self.service = service
        self.last_processed = -1
        self.polls = 0

    def get(self, block=True, timeout=None):
        if block:
            self.last_processed = self.service.health()["processed_records"]
            self.polls += 1
        return super().get(block=block, timeout=timeout)


@pytest.fixture
def harness(monkeypatch):
    clock = SimpleNamespace(now=100.0)
    monkeypatch.setattr(lens, "time", SimpleNamespace(
        monotonic=lambda: clock.now, time=real_time.time,
    ))
    calls = []
    def build(events, **_bounds):
        messages = tuple(row.message for row in events)
        calls.append(messages)
        return {"fixture_messages": messages, "advisory_only": True}
    monkeypatch.setattr(lens, "build_sentinel_snapshot", build)
    services = []
    def make(**options):
        service = lens.SentinelLensService(None, queue_capacity=16, **options)
        calls.clear()  # Constructor's empty initial snapshot is not an analysis turn.
        service._queue = PollQueue(service)
        services.append(service)
        assert service.start()
        wait_until(lambda: service._queue.polls > 0)
        return service
    yield clock, calls, make
    for service in services:
        assert service.stop(timeout=3)
        assert not service._thread.is_alive()


def completed_turn(service, count):
    wait_until(lambda: service._queue.last_processed >= count)


def assert_preserved(service, count):
    health = service.health()
    assert health["accepted"] == health["processed_records"] == count
    assert health["queue_dropped"] == health["analysis_rejections"] == 0
    assert health["remediation_execution"] is False
    assert health["network_listener"] is False


def test_spaced_arrivals_coalesce_until_nominal_analysis_interval(harness, monkeypatch):
    clock, calls, make = harness
    service = make(analysis_interval=.20)
    for number, stamp in enumerate((100.0, 100.0625, 100.125)):
        clock.now = stamp
        assert service.submit_event(event(number))
        completed_turn(service, number + 1)
    assert calls == [], f"Premature full graph builds: {calls!r}"
    assert_preserved(service, 3)
    original = service._consume
    def due_with_fourth_record(source, payload):
        result = original(source, payload)
        clock.now = 100.25
        return result
    monkeypatch.setattr(service, "_consume", due_with_fourth_record)
    assert service.submit_event(event(3))
    completed_turn(service, 4)
    assert calls == [("item-3", "item-2", "item-1", "item-0")]
    assert_preserved(service, 4)


def test_dirty_idle_worker_publishes_when_due_without_a_new_arrival(harness):
    clock, calls, make = harness
    service = make(analysis_interval=.20)
    for number in range(3):
        assert service.submit_event(event(number))
        completed_turn(service, number + 1)
    assert calls == []
    clock.now = 100.25
    wait_until(lambda: service.revision() == 1)
    assert calls == [("item-2", "item-1", "item-0")]
    assert_preserved(service, 3)


def test_sustained_backlog_analyzes_when_due_without_an_idle_flush(harness, monkeypatch):
    clock, calls, make = harness
    service = make(batch_size=2, analysis_interval=.20)
    entered, release = threading.Event(), threading.Event()
    original = service._consume
    def consume(source, payload):
        if not entered.is_set():
            entered.set()
            assert release.wait(3)
        result = original(source, payload)
        clock.now += .0625
        return result
    monkeypatch.setattr(service, "_consume", consume)
    try:
        assert service.submit_event(event(0))
        assert entered.wait(3)
        for number in range(1, 6):
            assert service.submit_event(event(number))
        release.set()
        completed_turn(service, 6)
        assert calls == [("item-3", "item-2", "item-1", "item-0")]
        assert_preserved(service, 6)
        assert service.stop(3)
        assert calls[-1] == tuple(f"item-{number}" for number in reversed(range(6)))
        assert len(calls) == 2
    finally:
        release.set()


def test_idle_worker_does_not_rebuild_without_dirty_records(harness):
    clock, calls, make = harness
    service = make()
    clock.now = 101.0
    polls = service._queue.polls
    wait_until(lambda: service._queue.polls >= polls + 2)
    assert calls == []
    assert service.submit_event(event(0))
    completed_turn(service, 1)
    assert calls == [("item-0",)]
    clock.now = 102.0
    polls = service._queue.polls
    wait_until(lambda: service._queue.polls >= polls + 2)
    assert calls == [("item-0",)]
    assert service.stop(3)
    assert len(calls) == 1


def test_stop_flushes_dirty_records_before_interval_and_retires_worker(harness):
    clock, calls, make = harness
    service = make(analysis_interval=10.0)
    for number in range(3):
        assert service.submit_event(event(number))
        completed_turn(service, number + 1)
    assert calls == []
    assert service.stop(3)
    assert clock.now == 100.0  # Stop bypasses the advisory cadence without a clock advance.
    assert calls == [("item-2", "item-1", "item-0")]
    assert_preserved(service, 3)
    assert not service._thread.is_alive()
    assert service.health()["clean_shutdown"] is True
    assert service.stop(3)
    assert len(calls) == 1
    assert not service.submit_event(event(3))
    assert service.health()["stopped_rejections"] == 1


@pytest.mark.parametrize("interval, expected_builds", [(None, 2), (.20, 8)])
def test_default_advisory_cadence_coalesces_work_but_explicit_override_remains(
    harness, monkeypatch, interval, expected_builds,
):
    """Two simulated seconds: count full builds, with every input retained/processed."""
    clock, calls, make = harness
    options = {} if interval is None else {"analysis_interval": interval}
    service = make(max_events=8, **options)
    original = service._consume
    def consume(source, payload):
        result = original(source, payload)
        clock.now += .0625  # Exactly representable: sixteen input turns per second.
        return result
    monkeypatch.setattr(service, "_consume", consume)
    for number in range(32):
        assert service.submit_event(event(number))
        completed_turn(service, number + 1)
    assert len(calls) == expected_builds
    assert calls[-1] == tuple(f"item-{number}" for number in reversed(range(24, 32)))
    assert_preserved(service, 32)
    assert service.health()["retained_events"] == service.health()["retained_capacity"] == 8
    assert service.stop(3)
    assert len(calls) == expected_builds  # No duplicate rebuild after a clean final batch.
    assert not service._thread.is_alive()
