from types import SimpleNamespace

import pytest

from angerona.core.eventbus import Event, EventBus
from angerona.core.status_report import StatusReporter
from angerona.core.telemetry_coverage import TelemetryCoverageAccountant


def test_sequence_gaps_duplicates_and_regressions_are_explicit():
    ledger = TelemetryCoverageAccountant(stale_after_s=10, clock=lambda: 5)
    for sequence in (10, 11, 14, 14, 13):
        ledger.observe("process", sequence, observed_at=4)

    coverage = ledger.snapshot()["process"]
    assert coverage.status == "degraded"
    assert coverage.accepted == 3
    assert coverage.missing == 2
    assert coverage.duplicates == 1
    assert coverage.regressions == 1
    assert coverage.last_sequence == 14


def test_unsequenced_and_stale_sensors_never_look_healthy():
    ledger = TelemetryCoverageAccountant(stale_after_s=10)
    ledger.observe("legacy", None, observed_at=100)
    ledger.observe("dns", 1, observed_at=100)

    snapshot = ledger.snapshot(now=111)
    assert snapshot["legacy"].status == "unknown"
    assert snapshot["legacy"].unsequenced == 1
    assert snapshot["dns"].status == "degraded"
    assert "stale" in snapshot["dns"].reason


def test_eventbus_shape_and_invalid_sequence_are_safely_accounted():
    ledger = TelemetryCoverageAccountant(clock=lambda: 2)
    ledger.observe_event(
        Event("dns-module", "query", ts=1, details={"sensor_id": "dns", "sensor_sequence": 7})
    )
    ledger.observe_event(
        Event("dns-module", "query", ts=2, details={"sensor_id": "dns", "sensor_sequence": "8"})
    )

    coverage = ledger.snapshot(now=2)["dns"]
    assert coverage.status == "healthy"
    assert coverage.last_sequence == 7
    assert coverage.unsequenced == 1


def test_sensor_cardinality_is_bounded_and_eviction_visible():
    ledger = TelemetryCoverageAccountant(max_sensors=2)
    ledger.observe("a", 1)
    ledger.observe("b", 1)
    ledger.observe("c", 1)

    assert set(ledger.snapshot()) == {"b", "c"}
    assert ledger.evicted_sensors == 1


def test_live_bus_observations_are_exposed_in_status_diagnostics(tmp_path):
    bus = EventBus()
    ledger = TelemetryCoverageAccountant(clock=lambda: 3)
    bus.subscribe(ledger.observe_event)
    bus.publish(Event("dns", "one", ts=1, details={"sensor_sequence": 4}))
    bus.publish(Event("dns", "three", ts=2, details={"sensor_sequence": 6}))

    storage = SimpleNamespace(count_since=lambda _since: 0)
    manager = SimpleNamespace(modules={}, is_enabled=lambda _name: False)
    config = SimpleNamespace(
        data_dir=tmp_path, ollama_host="local", ollama_model="test"
    )
    reporter = StatusReporter(
        bus, storage, manager, config, telemetry_coverage=ledger
    )

    snapshot = reporter._snapshot()
    dns = snapshot["telemetry_coverage"]["sensors"]["dns"]
    assert dns["status"] == "degraded"
    assert dns["missing"] == 1
    assert "does not prove complete collection" in snapshot["telemetry_coverage"]["limitation"]
    assert "TELEMETRY COVERAGE" in reporter._render_text(snapshot)


def test_authenticated_checkpoint_preserves_sequence_and_rejects_tamper(tmp_path):
    key = b"t" * 32
    path = tmp_path / "coverage.json"
    coverage = TelemetryCoverageAccountant(max_sensors=4, stale_after_s=100)
    coverage.observe("sensor-a", 10, observed_at=1)
    coverage.observe("sensor-a", 12, observed_at=2)
    coverage.save_checkpoint(path, key)
    restored = TelemetryCoverageAccountant.load_checkpoint(path, key)
    state = restored.snapshot(now=3)["sensor-a"]
    assert state.last_sequence == 12
    assert state.missing == 1
    restored.observe("sensor-a", 13, observed_at=3)
    assert restored.snapshot(now=4)["sensor-a"].accepted == 3

    raw = bytearray(path.read_bytes())
    raw[len(raw) // 2] ^= 1
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        TelemetryCoverageAccountant.load_checkpoint(path, key)


def test_incomplete_checkpoint_fails_closed(tmp_path):
    path = tmp_path / "coverage.json"
    path.write_text('{"payload":')
    with pytest.raises(ValueError, match="invalid or incomplete"):
        TelemetryCoverageAccountant.load_checkpoint(path, b"t" * 32)
