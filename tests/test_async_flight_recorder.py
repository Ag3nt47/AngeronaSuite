from __future__ import annotations

import json
import threading
import time

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import (
    AsyncFlightRecorder,
    BatchRecordResult,
    FlightRecorder,
)


def _recorder(tmp_path, monkeypatch) -> FlightRecorder:
    authority = BusAuthority(b"a" * 32)
    monkeypatch.setattr(
        "angerona.core.storage.BusAuthority.load",
        classmethod(lambda cls: authority),
    )
    return FlightRecorder(tmp_path / "events.db")


def test_async_bus_callback_batches_and_drains_signed_events(
    tmp_path, monkeypatch
) -> None:
    recorder = _recorder(tmp_path, monkeypatch)
    async_recorder = AsyncFlightRecorder(
        recorder, queue_capacity=32, batch_size=8, flush_interval=0.01
    )
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(async_recorder.submit)
    try:
        assert async_recorder.start()
        assert not async_recorder.start()
        for index in range(20):
            bus.publish(Event("test", f"event-{index}", Severity.HIGH))
        assert async_recorder.stop(timeout=2.0)
        assert async_recorder.stop(timeout=0.0)

        stored = recorder.recent(30)
        assert len(stored) == 20
        assert all(recorder.authority.verify(event) for event in stored)
        metrics = async_recorder.metrics()
        assert metrics.accepted == 20
        assert metrics.persisted == 20
        assert metrics.queue_depth == 0
        assert metrics.batches < metrics.persisted
        assert not metrics.running
    finally:
        async_recorder.stop()
        recorder.close()


def test_queue_overflow_is_signed_and_routed_to_dlq_without_sqlite() -> None:
    authority = BusAuthority(b"b" * 32)
    worker_entered = threading.Event()
    release_worker = threading.Event()
    dlq: list[Event] = []

    class BlockingRecorder:
        def __init__(self) -> None:
            self.authority = authority

        def record_batch_bus(self, events):
            events = list(events)
            worker_entered.set()
            assert release_worker.wait(2.0)
            return BatchRecordResult(len(events), 0)

        def _route_to_dlq(self, event):
            dlq.append(event)
            return True

    async_recorder = AsyncFlightRecorder(
        BlockingRecorder(), queue_capacity=1, batch_size=1, flush_interval=0.01
    )
    assert async_recorder.start()
    async_recorder.submit(Event("test", "worker"))
    assert worker_entered.wait(1.0)
    async_recorder.submit(Event("test", "queued"))
    started = time.perf_counter()
    async_recorder.submit(Event("test", "overflow"))
    elapsed = time.perf_counter() - started
    assert elapsed < 0.05
    assert [event.message for event in dlq] == ["overflow"]
    assert authority.verify(dlq[0])
    assert async_recorder.metrics().overflow_dlq == 1
    release_worker.set()
    assert async_recorder.stop(2.0)


def test_batch_storage_failure_preserves_every_event_in_dlq(
    tmp_path, monkeypatch
) -> None:
    recorder = _recorder(tmp_path, monkeypatch)
    monkeypatch.setattr(recorder, "_DLQ_RETRIES", 1)

    real_db = recorder._db

    class FailedDatabase:
        @staticmethod
        def executemany(*_args, **_kwargs):
            raise RuntimeError("simulated storage failure")

        @staticmethod
        def rollback():
            return None

    recorder._db = FailedDatabase()
    events = [Event("test", f"lost-{index}") for index in range(3)]
    try:
        result = recorder.record_batch_bus(events)
        assert result == BatchRecordResult(0, 3)
        lines = (tmp_path / "dlq_events.json").read_text(
            encoding="utf-8"
        ).splitlines()
        payloads = [json.loads(line) for line in lines]
        assert [item["message"] for item in payloads] == [
            "lost-0", "lost-1", "lost-2"
        ]
        assert all(item["hmac_sig"] for item in payloads)
    finally:
        recorder._db = real_db
        recorder.close()
