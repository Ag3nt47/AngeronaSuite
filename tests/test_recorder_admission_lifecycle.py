"""Recorder admission stays memory-only through saturation and lifecycle races."""
from __future__ import annotations

import dataclasses
import threading

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus
from angerona.core.storage import (
    AsyncFlightRecorder,
    BatchRecordResult,
    RecorderAdmissionRejected,
)


class _MemoryRecorder:
    authority = BusAuthority(b"a" * 32)

    def __init__(self):
        self.primary = []
        self.overflow = []

    def record_batch_bus(self, events):
        assert threading.current_thread().name == "angerona-flight-recorder"
        self.primary.extend(events)
        return BatchRecordResult(len(events), 0)

    def _route_batch_to_dlq(self, events):
        assert threading.current_thread().name == "angerona-flight-dlq"
        self.overflow.extend(events)
        return len(events)

    def _route_to_dlq(self, _event):
        raise AssertionError("no publisher may perform synchronous DLQ I/O")


def _signed(recorder, message):
    event = Event("admission-test", message)
    return dataclasses.replace(event, hmac_sig=recorder.authority.sign(event))


def test_rejections_before_start_and_after_stop_remain_latched_across_restart():
    recorder = _MemoryRecorder()
    worker = AsyncFlightRecorder(recorder, batch_size=1)
    with pytest.raises(RecorderAdmissionRejected) as before_start:
        worker.submit(_signed(recorder, "before-start"))
    assert before_start.value.reason == "unavailable"
    assert not recorder.primary and not recorder.overflow

    try:
        assert worker.start()
        assert worker.stop(3.0)
        with pytest.raises(RecorderAdmissionRejected) as after_stop:
            worker.submit(_signed(recorder, "after-stop"))
        assert after_stop.value.reason == "stopping"
        assert worker.start()
        snapshot = worker.recovery_snapshot()
        assert snapshot["healthy"]
        assert snapshot["coverage_gap"]
        assert snapshot["admission_rejected"] == 2
        assert snapshot["rejection_unavailable"] == 1
        assert snapshot["rejection_stopping"] == 1
        assert snapshot["rejection_saturated"] == 0
        original = _signed(recorder, "admitted-after-restart")
        assert worker.submit(original) is None
        assert worker.stop(3.0)
        assert recorder.primary == [original]
        assert recorder.primary[0] is original
        assert recorder.authority.verify(original)
        metrics = worker.metrics()
        assert metrics.accepted == metrics.persisted == 1
        assert metrics.admission_rejected == 2
        assert metrics.coverage_gap
        assert metrics.dlq_failures == metrics.overflow_synchronous == 0
        assert metrics.accepted + metrics.overflow_queued + metrics.admission_rejected == 3
        assert metrics.queue_depth == metrics.overflow_queue_depth == 0
    finally:
        assert worker.stop(3.0)


def test_eventbus_counts_rejected_recorder_delivery_and_delivers_other_subscribers():
    recorder = _MemoryRecorder()
    worker = AsyncFlightRecorder(recorder)
    bus = EventBus()
    bus.arm(recorder.authority)
    observed = []
    bus.subscribe(worker.submit)
    bus.subscribe(observed.append)

    bus.publish(Event("admission-test", "still delivered elsewhere"))

    assert len(observed) == 1
    assert observed[0].message == "still delivered elsewhere"
    assert recorder.authority.verify(observed[0])
    assert bus.recent(1) == observed
    subscriber_metrics = bus.subscriber_metrics()
    assert sum(row.deliveries for row in subscriber_metrics) == 2
    assert sum(row.failures for row in subscriber_metrics) == 1
    snapshot = worker.recovery_snapshot()
    assert snapshot["admission_rejected"] == snapshot["rejection_unavailable"] == 1
    assert snapshot["coverage_gap"]
    assert snapshot["dlq_failures"] == 0
    assert not recorder.primary and not recorder.overflow
    assert worker.stop(0.0)


def test_no_live_workers_reject_without_queuing_to_retired_owners(monkeypatch):
    recorder = _MemoryRecorder()
    worker = AsyncFlightRecorder(recorder)
    monkeypatch.setattr(worker, "_run", lambda: None)
    monkeypatch.setattr(worker, "_run_dlq", lambda: None)
    assert worker.start()
    worker._thread.join(3.0)
    worker._dlq_thread.join(3.0)
    assert not worker._thread.is_alive() and not worker._dlq_thread.is_alive()
    with pytest.raises(RecorderAdmissionRejected) as unavailable:
        worker.submit(_signed(recorder, "retired-workers"))
    assert unavailable.value.reason == "unavailable"
    assert worker.metrics().queue_depth == worker.metrics().overflow_queue_depth == 0
    assert not recorder.primary and not recorder.overflow
    assert worker.stop(0.0)


def test_thread_start_does_not_hold_admission_lock(monkeypatch):
    recorder = _MemoryRecorder()
    worker = AsyncFlightRecorder(recorder)
    start_entered = threading.Event()
    release_start = threading.Event()
    publisher_done = threading.Event()
    start_results = []
    rejection_reasons = []
    real_start = threading.Thread.start

    def gated_start(thread):
        real_start(thread)
        if thread.name == "angerona-flight-dlq":
            start_entered.set()
            assert release_start.wait(5.0)

    def publish():
        try:
            worker.submit(_signed(recorder, "during-start"))
        except RecorderAdmissionRejected as error:
            rejection_reasons.append(error.reason)
        finally:
            publisher_done.set()

    monkeypatch.setattr(threading.Thread, "start", gated_start)
    starter = threading.Thread(target=lambda: start_results.append(worker.start()),
                               name="recorder-starter")
    publisher = threading.Thread(target=publish, name="recorder-publisher")
    try:
        starter.start()
        assert start_entered.wait(2.0)
        publisher.start()
        assert publisher_done.wait(2.0)
        assert not release_start.is_set()
        assert rejection_reasons == ["unavailable"]
        assert not recorder.primary and not recorder.overflow
    finally:
        release_start.set()
        starter.join(3.0)
        if publisher.ident is not None:
            publisher.join(3.0)
        assert worker.stop(3.0)
    assert start_results == [True]
    assert not starter.is_alive() and not publisher.is_alive()
    assert worker.metrics().admission_rejected == 1


def test_admission_that_precedes_stop_is_drained_before_success(monkeypatch):
    recorder = _MemoryRecorder()
    worker = AsyncFlightRecorder(recorder, batch_size=1)
    put_entered = threading.Event()
    release_put = threading.Event()
    stop_called = threading.Event()
    publish_results = []
    stop_results = []
    original = _signed(recorder, "admitted-before-stop")
    real_put = worker._queue.put_nowait

    def gated_put(event):
        if event is original:
            put_entered.set()
            assert release_put.wait(5.0)
        real_put(event)

    def stop():
        stop_called.set()
        stop_results.append(worker.stop(3.0))

    monkeypatch.setattr(worker._queue, "put_nowait", gated_put)
    publisher = threading.Thread(target=lambda: publish_results.append(worker.submit(original)))
    stopper = threading.Thread(target=stop)
    try:
        assert worker.start()
        publisher.start()
        assert put_entered.wait(2.0)
        stopper.start()
        assert stop_called.wait(2.0)
        release_put.set()
        publisher.join(3.0)
        stopper.join(3.0)
        assert not publisher.is_alive() and not stopper.is_alive()
        assert publish_results == [None]
        assert stop_results == [True]
        assert recorder.primary == [original]
        assert recorder.primary[0] is original
        metrics = worker.metrics()
        assert metrics.accepted == metrics.persisted == 1
        assert metrics.admission_rejected == 0
        assert metrics.queue_depth == metrics.overflow_queue_depth == 0
    finally:
        release_put.set()
        if publisher.ident is not None:
            publisher.join(3.0)
        if stopper.ident is not None:
            stopper.join(3.0)
        assert worker.stop(3.0)


def test_all_stop_callers_fence_replacement_until_final_generation_checks(monkeypatch):
    recorder = _MemoryRecorder()
    worker = AsyncFlightRecorder(recorder)
    waiting = [threading.Event(), threading.Event()]
    for pending, entered in zip((worker._queue, worker._overflow_queue), waiting):
        original_get = pending.get

        def observed_get(*args, _original=original_get, _entered=entered, **kwargs):
            _entered.set()
            return _original(*args, **kwargs)

        monkeypatch.setattr(pending, "get", observed_get)
    monkeypatch.setattr(worker, "_idle_wait_seconds", lambda: 60.0)
    assert worker.start()
    assert all(entered.wait(2.0) for entered in waiting)
    old_primary, old_dlq = worker._thread, worker._dlq_thread
    generation = worker._worker_generation
    real_join = old_primary.join
    retired = [threading.Event(), threading.Event()]
    release_join = [threading.Event(), threading.Event()]
    stop_results = [None, None]
    late_wake_entered = threading.Event()
    release_late_wake = threading.Event()
    real_wake = worker._wake_idle

    def gated_wake(pending):
        if (threading.current_thread().name == "recorder-stopper-1"
                and pending is worker._queue):
            late_wake_entered.set()
            assert release_late_wake.wait(5.0)
        real_wake(pending)

    def gated_join(timeout=None):
        real_join(timeout)
        index = int(threading.current_thread().name.rsplit("-", 1)[1])
        assert not old_primary.is_alive() and not old_dlq.is_alive()
        retired[index].set()
        assert release_join[index].wait(5.0)

    def stop(index):
        stop_results[index] = worker.stop(3.0)

    monkeypatch.setattr(old_primary, "join", gated_join)
    monkeypatch.setattr(worker, "_wake_idle", gated_wake)
    callers = [threading.Thread(target=stop, args=(index,), name=f"recorder-stopper-{index}")
               for index in range(2)]
    try:
        # One caller owns a wake insertion while its consumer is still alive.
        # The other retires both consumers before that delayed insertion runs.
        callers[1].start()
        assert late_wake_entered.wait(2.0)
        callers[0].start()
        assert retired[0].wait(2.0)
        release_late_wake.set()
        assert retired[1].wait(2.0)
        assert worker._queue.qsize() == 1
        assert worker._stop_callers == 2
        assert not worker.start() and not worker.recover()
        assert worker._worker_generation == generation
        with pytest.raises(RecorderAdmissionRejected) as stopping:
            worker.submit(_signed(recorder, "during-stop-finalization"))
        assert stopping.value.reason == "stopping"

        release_join[0].set()
        callers[0].join(3.0)
        assert stop_results[0] is False
        assert worker._stop_callers == 1
        assert worker._thread is old_primary and worker._dlq_thread is old_dlq
        assert not worker.start() and not worker.recover()
        assert worker._queue.qsize() == 1

        release_join[1].set()
        callers[1].join(3.0)
        assert stop_results == [False, True]
        assert worker._stop_callers == 0
        assert worker._queue.empty() and worker._overflow_queue.empty()
        assert worker.start()
        assert worker._worker_generation > generation
        assert worker._thread is not old_primary and worker._dlq_thread is not old_dlq
        assert worker.recovery_snapshot()["coverage_gap"]
    finally:
        release_late_wake.set()
        for release in release_join:
            release.set()
        for caller in callers:
            if caller.ident is not None:
                caller.join(3.0)
        assert worker.stop(3.0)


def test_stop_discards_only_retired_wakes_preserving_original_queue_order(monkeypatch):
    recorder = _MemoryRecorder()
    worker = AsyncFlightRecorder(recorder, queue_capacity=4, overflow_queue_capacity=4,
                                 batch_size=1, dlq_batch_size=1)
    with monkeypatch.context() as retired:
        retired.setattr(worker, "_run", lambda: None)
        retired.setattr(worker, "_run_dlq", lambda: None)
        assert worker.start()
        worker._thread.join(3.0)
        worker._dlq_thread.join(3.0)
        assert not worker._thread.is_alive() and not worker._dlq_thread.is_alive()

    primary = [_signed(recorder, "primary-first"), _signed(recorder, "primary-second")]
    overflow = [_signed(recorder, "overflow-first"), _signed(recorder, "overflow-second")]
    for pending, originals in ((worker._queue, primary), (worker._overflow_queue, overflow)):
        pending.put_nowait(originals[0])
        worker._wake_idle(pending)
        pending.put_nowait(originals[1])
        worker._wake_idle(pending)

    try:
        assert not worker.stop(0.0)
        assert worker._thread is None and worker._dlq_thread is None
        for pending, originals in ((worker._queue, primary), (worker._overflow_queue, overflow)):
            assert pending.qsize() == 2
            retained = [pending.get_nowait(), pending.get_nowait()]
            assert all(actual is expected for actual, expected in zip(retained, originals))
            for original in retained:
                pending.put_nowait(original)
        assert worker.start()
        assert worker.stop(3.0)
        assert recorder.primary == primary
        assert recorder.overflow == overflow
        assert all(actual is expected for actual, expected in zip(recorder.primary, primary))
        assert all(actual is expected for actual, expected in zip(recorder.overflow, overflow))
        metrics = worker.metrics()
        assert metrics.queue_depth == metrics.overflow_queue_depth == 0
    finally:
        assert worker.stop(3.0)
