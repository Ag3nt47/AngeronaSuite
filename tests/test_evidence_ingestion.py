import threading
import time

import pytest

from angerona.core.eventbus import Event
from angerona.core.evidence_ingestion import EvidenceIngestionWorker
from angerona.core.evidence_store import EvidenceEnvelope, EvidenceStore


def _envelope(identifier: str) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        event_id=identifier, observed_at=time.time(), category="process",
        activity="start", severity=1, message=identifier, module="test",
    )


def test_start_stop_are_idempotent_and_shutdown_drains(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        worker = EvidenceIngestionWorker(
            store, queue_capacity=20, batch_size=4, flush_interval=0.01
        )
        assert worker.start()
        assert not worker.start()
        for index in range(10):
            assert worker.submit(_envelope(str(index)))
        assert worker.stop(drain_timeout=2)
        assert worker.stop(drain_timeout=2)
        assert store.count() == 10
        metrics = worker.metrics()
        assert metrics.persisted == 10
        assert metrics.queue_depth == 0
        assert not metrics.running


def test_submit_never_waits_and_reports_full_queue(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        worker = EvidenceIngestionWorker(store, queue_capacity=1)
        started = time.perf_counter()
        assert worker.submit(_envelope("one"))
        assert not worker.submit(_envelope("two"))
        assert time.perf_counter() - started < 0.1
        metrics = worker.metrics()
        assert metrics.accepted == 1
        assert metrics.dropped_full == 1


def test_batches_duplicates_and_event_normalization(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        worker = EvidenceIngestionWorker(
            store, queue_capacity=10, batch_size=3, flush_interval=0.01
        )
        worker.start()
        same = _envelope("same")
        assert worker.submit(same)
        assert worker.submit(same)
        assert worker.submit_event(Event(module="DNS", message="lookup"))
        assert worker.stop(drain_timeout=2)
        metrics = worker.metrics()
        assert metrics.persisted == 2
        assert metrics.duplicates == 1
        assert metrics.batches >= 1


def test_worker_rejects_non_local_store(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db", local_only=False)
    try:
        with pytest.raises(ValueError, match="local-only"):
            EvidenceIngestionWorker(store)
    finally:
        store.close()


def test_stop_timeout_is_explicit(tmp_path):
    class SlowStore:
        local_only = True

        def __init__(self):
            self.release = threading.Event()

        def append(self, _item):
            self.release.wait(1)
            return True

    store = SlowStore()
    worker = EvidenceIngestionWorker(store, flush_interval=0.001)
    worker.start()
    worker.submit(_envelope("slow"))
    time.sleep(0.02)
    assert not worker.stop(drain_timeout=0.001)
    store.release.set()
    assert worker.stop(drain_timeout=1)
