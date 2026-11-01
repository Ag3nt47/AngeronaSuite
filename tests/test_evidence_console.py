from types import SimpleNamespace

from angerona.core.commands import CommandConsole
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.evidence_ingestion import EvidenceIngestionWorker
from angerona.core.evidence_store import EvidenceStore
from angerona.core.storage import AsyncFlightRecorder


class _Manager:
    modules = {}


def _console(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db")
    worker = EvidenceIngestionWorker(
        store, queue_capacity=16, batch_size=4, flush_interval=0.01
    )
    worker.start()
    console = CommandConsole(
        _Manager(), EventBus(), SimpleNamespace(),
        evidence_store=store, evidence_ingestion=worker,
    )
    return console, store, worker


def test_ehunt_is_typed_bounded_and_renders_results(tmp_path):
    console, store, worker = _console(tmp_path)
    try:
        assert worker.submit_event(Event(
            "DNS Sensor", "suspicious lookup", Severity.HIGH,
            details={"domain": "example.invalid"},
        ))
        assert worker.stop(drain_timeout=2)

        result = console.run("ehunt module=DNS severity=3 limit=10")
        assert "Normalized evidence: 1 result" in result
        assert "suspicious lookup" in result
        assert console.run("ehunt severity=99") == (
            "severity must be 0, 1, 2, 3, or 4"
        )
        assert "unsupported evidence field" in console.run("ehunt sql=select")
    finally:
        worker.stop(drain_timeout=2)
        store.close()


def test_ingestion_status_is_operator_visible(tmp_path):
    console, store, worker = _console(tmp_path)
    try:
        text = console.run("ingest-status")
        assert "Normalized evidence ingestion" in text
        assert "queue:" in text
        assert "dropped-full/failed/batches:" in text
    finally:
        worker.stop(drain_timeout=2)
        store.close()


def test_recorder_delivery_rejection_is_visible_and_not_presented_as_durable_history():
    bus = EventBus()
    recorder = AsyncFlightRecorder(SimpleNamespace(authority=BusAuthority(b"c" * 32)))
    bus.subscribe(recorder.submit)
    bus.publish(Event("fixture", "recorder not started"))
    console = CommandConsole(_Manager(), bus, SimpleNamespace(), flight_recorder_worker=recorder)
    text = console.run("ingest-status")
    assert "recorder delivery rejections: 1 (saturated=0, stopping=0, unavailable=1)" in text
    assert "recorder admission coverage gap: True" in text
    assert "process-lifetime counters, not a durable loss journal" in text
    assert "overflow-DLQ/storage-DLQ/failures: 0/0/0" in text
