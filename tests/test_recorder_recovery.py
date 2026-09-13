from __future__ import annotations

import threading

import pytest

from angerona.core.eventbus import BusAuthority, Event
from angerona.core.storage import AsyncFlightRecorder, BatchRecordResult, FlightRecorder


class _ExitBetweenBatches(BaseException):
    """Controlled worker exit after delivery and before another queue read."""


@pytest.mark.parametrize("lane", ["primary", "dlq"])
@pytest.mark.parametrize("restart", ["recover", "start"])
def test_restart_preserves_live_peer_and_queued_signed_delivery(
    tmp_path, monkeypatch, lane, restart
):
    authority = BusAuthority(b"r" * 32)
    monkeypatch.setattr(
        "angerona.core.storage.BusAuthority.load",
        classmethod(lambda cls: authority),
    )
    recorder = FlightRecorder(tmp_path / "events.db")
    worker = AsyncFlightRecorder(
        recorder, batch_size=1, dlq_batch_size=1, flush_interval=0.005
    )
    target_name = "_run" if lane == "primary" else "_run_dlq"
    thread_name = "_thread" if lane == "primary" else "_dlq_thread"
    peer_name = "_dlq_thread" if lane == "primary" else "_thread"
    pending = worker._queue if lane == "primary" else worker._overflow_queue
    original_run = getattr(worker, target_name)
    original_get = pending.get
    between_batches = threading.Event()
    release_exit = threading.Event()
    reads = 0

    def stop_after_first_batch(*args, **kwargs):
        nonlocal reads
        if reads == 1:
            reads += 1
            between_batches.set()
            assert release_exit.wait(3.0)
            raise _ExitBetweenBatches()
        event = original_get(*args, **kwargs)
        reads += 1
        return event

    def controlled_worker():
        try:
            original_run()
        except _ExitBetweenBatches:
            pass

    monkeypatch.setattr(pending, "get", stop_after_first_batch)
    monkeypatch.setattr(worker, target_name, controlled_worker)
    try:
        assert worker.start()
        if lane == "dlq":
            worker._primary_saturated.set()
        worker.submit(Event("recovery-test", "before-worker-exit"))
        assert between_batches.wait(2.0)
        worker.submit(Event("recovery-test", "queued-during-worker-exit"))
        assert pending.qsize() == 1
        old_worker = getattr(worker, thread_name)
        live_peer = getattr(worker, peer_name)
        release_exit.set()
        old_worker.join(2.0)
        assert not old_worker.is_alive()
        assert live_peer.is_alive()
        snapshot = worker.recovery_snapshot()
        assert not snapshot["healthy"]
        assert not snapshot["stopping"]
        assert snapshot["worker_alive"] is (lane != "primary")
        assert snapshot["dlq_worker_alive"] is (lane != "dlq")
        with worker._metrics_lock:
            worker._dlq_failures = 4
            worker._replay_failures = 2

        # Concurrent repair requests must produce exactly one replacement,
        # keeping the surviving worker and the queued Event objects intact.
        barrier = threading.Barrier(8)
        results = []

        def restart_worker():
            barrier.wait(timeout=3.0)
            results.append(getattr(worker, restart)())

        callers = [threading.Thread(target=restart_worker) for _ in range(8)]
        for caller in callers:
            caller.start()
        for caller in callers:
            caller.join(3.0)
        assert not any(caller.is_alive() for caller in callers)
        assert results.count(True) == 1
        assert results.count(False) == 7
        assert getattr(worker, peer_name) is live_peer
        assert getattr(worker, thread_name) is not old_worker
        assert pending is (worker._queue if lane == "primary" else worker._overflow_queue)
        recovered = worker.recovery_snapshot()
        assert recovered["healthy"]
        assert recovered["dlq_failures"] == 4
        assert recovered["replay_failures"] == 2
        assert worker.stop(3.0)
        stored = recorder.recent(10)
        assert sorted(event.message for event in stored) == [
            "before-worker-exit", "queued-during-worker-exit",
        ]
        assert all(authority.verify(event) for event in stored)
        assert not worker.recover()
    finally:
        release_exit.set()
        worker.stop(3.0)
        recorder.close()


def test_snapshot_avoids_storage_reads_and_preserves_cumulative_failures():
    class UnreadableRecorder:
        def dlq_status(self):
            raise AssertionError("recovery polling must not read the spool")

        def __getattr__(self, name):
            raise AssertionError(f"unexpected recorder access: {name}")

    worker = AsyncFlightRecorder(UnreadableRecorder())
    worker._dlq_failures = 7
    worker._replay_failures = 3
    worker._replay_quarantined = 2
    expected = {
        "healthy": False,
        "stopping": False,
        "worker_alive": False,
        "dlq_worker_alive": False,
        "dlq_failures": 7,
        "replay_failures": 3,
        "replay_quarantined": 2,
    }
    assert worker.recovery_snapshot() == expected
    assert worker.recovery_snapshot() == expected
    assert worker.stop(0.0)
    expected["stopping"] = True
    assert not worker.recover()
    assert worker.recovery_snapshot() == expected
    assert worker._thread is None and worker._dlq_thread is None


def test_recovery_and_explicit_start_refuse_to_revive_a_draining_peer():
    primary_entered = threading.Event()
    release_primary = threading.Event()
    dlq_entered = threading.Event()
    release_dlq = threading.Event()

    class BlockedRecorder:
        authority = BusAuthority(b"s" * 32)

        def record_batch_bus(self, events):
            primary_entered.set()
            assert release_primary.wait(3.0)
            return BatchRecordResult(len(events), 0)

        def _route_batch_to_dlq(self, events):
            dlq_entered.set()
            assert release_dlq.wait(3.0)
            return len(events)

    worker = AsyncFlightRecorder(
        BlockedRecorder(), queue_capacity=1, batch_size=1, flush_interval=0.005
    )
    try:
        assert worker.start()
        worker.submit(Event("recovery-test", "primary"))
        assert primary_entered.wait(2.0)
        worker.submit(Event("recovery-test", "queued"))
        worker.submit(Event("recovery-test", "overflow"))
        assert dlq_entered.wait(2.0)
        primary = worker._thread
        dlq = worker._dlq_thread
        assert not worker.stop(0.0)
        snapshot = worker.recovery_snapshot()
        assert snapshot["stopping"]
        assert not snapshot["healthy"]
        assert snapshot["worker_alive"] and snapshot["dlq_worker_alive"]
        assert not worker.recover()
        assert not worker.start()
        assert worker._stop.is_set()
        assert worker._thread is primary and worker._dlq_thread is dlq
        release_primary.set()
        release_dlq.set()
        assert worker.stop(3.0)
        assert not worker.recover()
        # A deliberate lifecycle restart is allowed after the drain completes.
        assert worker.start()
        assert worker.recovery_snapshot()["healthy"]
    finally:
        release_primary.set()
        release_dlq.set()
        assert worker.stop(3.0)
