from types import SimpleNamespace

from angerona.core.commands import CommandConsole
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.evidence_ingestion import EvidenceIngestionWorker
from angerona.core.evidence_store import EvidenceStore


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
