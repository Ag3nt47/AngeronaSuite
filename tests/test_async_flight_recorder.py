from __future__ import annotations

import dataclasses
import json
import threading
import time

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import (
    AsyncFlightRecorder,
    BatchRecordResult,
    FlightRecorder,
    RecorderAdmissionRejected,
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
    dlq_written = threading.Event()
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
            dlq_written.set()
            return True

    async_recorder = AsyncFlightRecorder(
        BlockingRecorder(), queue_capacity=1, batch_size=1, flush_interval=0.01
    )
    assert async_recorder.start()
    async_recorder.submit(Event("test", "worker"))
    assert worker_entered.wait(1.0)
    async_recorder.submit(Event("test", "queued"))
    async_recorder.submit(Event("test", "overflow"))
    assert dlq_written.wait(1.0)
    assert [event.message for event in dlq] == ["overflow"]
    assert authority.verify(dlq[0])
    assert async_recorder.metrics().overflow_dlq == 1
    release_worker.set()
    assert async_recorder.stop(2.0)


def test_parallel_overflow_flood_accounts_for_every_delivery_without_publisher_io() -> None:
    authority = BusAuthority(b"c" * 32)
    worker_entered = threading.Event()
    release_worker = threading.Event()
    dlq_entered = threading.Event()
    release_dlq = threading.Event()
    primary: list[Event] = []
    dlq: list[Event] = []
    dlq_batch_sizes: list[int] = []
    synchronous_calls: list[str] = []

    class FloodRecorder:
        def __init__(self) -> None:
            self.authority = authority

        def record_batch_bus(self, events):
            batch = list(events)
            worker_entered.set()
            assert release_worker.wait(60.0)
            primary.extend(batch)
            return BatchRecordResult(len(batch), 0)

        def _route_batch_to_dlq(self, events):
            batch = list(events)
            dlq_entered.set()
            assert release_dlq.wait(60.0)
            dlq_batch_sizes.append(len(batch))
            dlq.extend(batch)
            return len(batch)

        def _route_to_dlq(self, event):
            synchronous_calls.append(event.message)
            raise AssertionError("publishers must not perform DLQ writes")

    async_recorder = AsyncFlightRecorder(
        FloodRecorder(), queue_capacity=1, batch_size=1,
        overflow_queue_capacity=4096, dlq_batch_size=512,
        flush_interval=0.005,
    )
    publisher_count = 8
    per_publisher = 1000
    admitted = [[] for _ in range(publisher_count)]
    rejected = [[] for _ in range(publisher_count)]

    def publish(publisher: int) -> None:
        for sequence in range(per_publisher):
            message = f"{publisher}:{sequence}"
            try:
                async_recorder.submit(Event("flood", message, Severity.HIGH))
            except RecorderAdmissionRejected as error:
                assert error.reason == "saturated"
                rejected[publisher].append(message)
            else:
                admitted[publisher].append(message)

    threads = [
        threading.Thread(target=publish, args=(publisher,))
        for publisher in range(publisher_count)
    ]
    try:
        assert async_recorder.start()
        async_recorder.submit(Event("test", "worker"))
        assert worker_entered.wait(5.0)
        async_recorder.submit(Event("test", "queued"))
        for thread in threads:
            thread.start()
        assert dlq_entered.wait(5.0)
        publisher_deadline = time.monotonic() + 20.0
        for thread in threads:
            thread.join(max(0.0, publisher_deadline - time.monotonic()))
        assert not any(thread.is_alive() for thread in threads)
        saturated = async_recorder.metrics()
        assert saturated.queue_depth == 1
        assert saturated.overflow_queue_depth == saturated.overflow_queue_capacity == 4096
        assert saturated.admission_rejected > 0
    finally:
        release_worker.set()
        release_dlq.set()
        cleanup_deadline = time.monotonic() + 10.0
        for thread in threads:
            if thread.ident is not None:
                thread.join(max(0.0, cleanup_deadline - time.monotonic()))
        assert async_recorder.stop(10.0)

    metrics = async_recorder.metrics()
    overflow_count = publisher_count * per_publisher
    admitted_messages = {message for rows in admitted for message in rows}
    rejected_messages = {message for rows in rejected for message in rows}
    assert len(primary) == 2
    assert len(dlq) == len(admitted_messages)
    assert {event.message for event in dlq} == admitted_messages
    assert admitted_messages.isdisjoint(rejected_messages)
    assert len(admitted_messages) + len(rejected_messages) == overflow_count
    assert metrics.overflow_queue_depth == 0
    assert metrics.overflow_queue_capacity == 4096
    assert metrics.overflow_queued == len(dlq)
    assert metrics.admission_rejected == len(rejected_messages)
    assert metrics.rejection_saturated == len(rejected_messages)
    assert metrics.coverage_gap is bool(rejected_messages)
    assert metrics.overflow_synchronous == 0
    assert not synchronous_calls
    assert sum(dlq_batch_sizes) == metrics.overflow_queued
    assert len(dlq_batch_sizes) < max(2, metrics.overflow_queued // 8)
    assert max(dlq_batch_sizes, default=0) > 1
    assert metrics.dlq_failures == 0
    assert all(authority.verify(event) for event in dlq)


def test_exhausted_overflow_lane_rejects_without_waiting_for_storage() -> None:
    authority = BusAuthority(b"d" * 32)
    worker_entered = threading.Event()
    release_worker = threading.Event()
    dlq_entered = threading.Event()
    release_dlq = threading.Event()
    publisher_done = threading.Event()
    rejections = []
    primary: list[Event] = []
    dlq: list[Event] = []
    write_threads = []

    class SaturatedRecorder:
        def __init__(self) -> None:
            self.authority = authority

        def record_batch_bus(self, events):
            batch = list(events)
            write_threads.append(threading.current_thread().name)
            worker_entered.set()
            assert release_worker.wait(5.0)
            primary.extend(batch)
            return BatchRecordResult(len(batch), 0)

        def _route_batch_to_dlq(self, events):
            batch = list(events)
            write_threads.append(threading.current_thread().name)
            dlq_entered.set()
            assert release_dlq.wait(5.0)
            dlq.extend(batch)
            return len(batch)

        def _route_to_dlq(self, event):
            raise AssertionError("publisher attempted synchronous disk I/O")

    async_recorder = AsyncFlightRecorder(
        SaturatedRecorder(), queue_capacity=1, batch_size=1,
        overflow_queue_capacity=1, dlq_batch_size=1, flush_interval=0.005,
    )
    def publish_rejected():
        try:
            async_recorder.submit(Event("test", "unadmitted"))
        except RecorderAdmissionRejected as error:
            rejections.append(error.reason)
        finally:
            publisher_done.set()

    publisher = threading.Thread(target=publish_rejected, name="recorder-publisher")
    try:
        assert async_recorder.start()
        async_recorder.submit(Event("test", "worker"))
        assert worker_entered.wait(2.0)
        async_recorder.submit(Event("test", "queued"))
        async_recorder.submit(Event("test", "overflow-worker"))
        assert dlq_entered.wait(2.0)
        async_recorder.submit(Event("test", "overflow-queued"))
        publisher.start()
        assert publisher_done.wait(2.0)
        assert not release_worker.is_set() and not release_dlq.is_set()
        assert rejections == ["saturated"]

        metrics = async_recorder.metrics()
        assert metrics.queue_depth == metrics.overflow_queue_depth == 1
        assert metrics.admission_rejected == metrics.rejection_saturated == 1
        assert metrics.rejection_stopping == metrics.rejection_unavailable == 0
        assert metrics.coverage_gap
        assert metrics.overflow_synchronous == metrics.dlq_failures == 0
        assert not primary and not dlq
    finally:
        release_worker.set()
        release_dlq.set()
        if publisher.ident is not None:
            publisher.join(3.0)
        assert async_recorder.stop(5.0)
    assert [event.message for event in primary] == ["worker", "queued"]
    assert [event.message for event in dlq] == ["overflow-worker", "overflow-queued"]
    assert all(authority.verify(event) for event in primary + dlq)
    assert set(write_threads) == {"angerona-flight-recorder", "angerona-flight-dlq"}


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


def test_stop_timeout_is_bounded_while_dlq_storage_is_blocked() -> None:
    authority = BusAuthority(b"e" * 32)
    primary_entered = threading.Event()
    release_primary = threading.Event()
    writer_entered = threading.Event()
    release_writer = threading.Event()

    class BlockedDLQRecorder:
        def __init__(self) -> None:
            self.authority = authority

        @staticmethod
        def record_batch_bus(events):
            batch = list(events)
            primary_entered.set()
            assert release_primary.wait(5.0)
            return BatchRecordResult(len(batch), 0)

        @staticmethod
        def _route_batch_to_dlq(events):
            batch = list(events)
            writer_entered.set()
            assert release_writer.wait(5.0)
            return len(batch)

        @staticmethod
        def _route_to_dlq(_event):
            return True

    async_recorder = AsyncFlightRecorder(
        BlockedDLQRecorder(), queue_capacity=1,
        overflow_queue_capacity=2, flush_interval=0.005,
    )
    assert async_recorder.start()
    async_recorder.submit(Event("test", "primary-worker"))
    assert primary_entered.wait(1.0)
    async_recorder.submit(Event("test", "primary-queued"))
    async_recorder.submit(Event("test", "blocked-dlq"))
    assert writer_entered.wait(1.0)

    started = time.perf_counter()
    assert not async_recorder.stop(timeout=0.05)
    assert time.perf_counter() - started < 0.25

    release_primary.set()
    release_writer.set()
    assert async_recorder.stop(timeout=2.0)


def test_full_spool_replays_capacity_without_overflow_worker_deadlock(
    tmp_path, monkeypatch
) -> None:
    recorder = _recorder(tmp_path, monkeypatch)
    monkeypatch.setattr(recorder, "DLQ_SEGMENT_BYTES", 1)
    monkeypatch.setattr(recorder, "DLQ_MAX_SEGMENTS", 1)
    monkeypatch.setattr(recorder, "DLQ_MAX_BYTES", 1024 * 1024)

    def signed(message: str) -> Event:
        event = Event("capacity-test", message, Severity.HIGH)
        return dataclasses.replace(
            event, hmac_sig=recorder.authority.sign(event)
        )

    try:
        assert recorder._route_to_dlq(signed("first"))
        assert recorder.dlq_status()["segments"] == 1

        result: list[bool] = []
        writer = threading.Thread(
            target=lambda: result.append(
                recorder._route_to_dlq(signed("second"))
            ),
            daemon=True,
        )
        writer.start()
        writer.join(2.0)

        assert not writer.is_alive(), "full spool capacity path deadlocked"
        assert result == [True]
        replayed = recorder.replay_dlq(max_segments=1)
        assert replayed.failures == 0
        assert {event.message for event in recorder.recent(10)} == {
            "first", "second",
        }
    finally:
        recorder.close()
