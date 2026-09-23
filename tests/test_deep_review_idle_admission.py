"""Inert resource-exhaustion fixtures; no live sensors or native responses."""
from __future__ import annotations

import json

import pytest

from angerona.core.detection_packages import DetectionPackage, seal_package
from angerona.core.detection_registry import DetectionPackageRegistry
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules import detection_runtime as runtime


def _package():
    return DetectionPackage(seal_package({
        "schema_version": 1, "id": "org.angerona.idle-admission", "version": "1.0.0",
        "owner": "Angerona tests", "description": "Inert admission fixture",
        "telemetry": ["process.creation"], "attack": ["T1059.001"],
        "severity": "high", "confidence": 85,
        "logic": {"type": "sigma-subset", "detection": {
            "selection": {"cmdline|contains": "fixture-marker"}, "condition": "selection",
        }},
        "fixtures": [
            {"name": "hit", "event": {"cmdline": "fixture-marker"}, "expected_match": True},
            {"name": "miss", "event": {"cmdline": "benign"}, "expected_match": False},
        ],
        "performance": {"max_eval_ms": 50, "max_events_per_second": 1000},
        "rollback": {"previous_digest": None, "instructions": "Restore predecessor"},
        "expires_at": "2099-01-01T00:00:00Z",
    }))


def _event(index, severity=Severity.INFO):
    return Event("fixture", "observed", severity, ts=100.0, details={
        "event_id": f"fixture-{index}", "cmdline": "fixture-marker",
    })


@pytest.mark.parametrize("severity", [Severity.INFO, Severity.HIGH, Severity.CRITICAL])
def test_unconfigured_flood_has_constant_retained_state_and_keeps_bus_delivery(monkeypatch, severity):
    bus = EventBus(ring_size=8, priority_ring_size=8)
    module = runtime.DetectionRuntimeModule()
    module.bind(bus)
    delivered = 0

    def receive(_event):
        nonlocal delivered
        delivered += 1

    def forbidden(*_args, **_kwargs):
        raise AssertionError("unconfigured engine normalized an event")

    monkeypatch.setattr(module.engine, "_queue_event", forbidden)
    bus.subscribe(module._on_event)
    bus.subscribe(receive)
    for index in range(20_000):
        bus.publish(_event(index, severity))
    snapshot = module.engine.snapshot()
    assert snapshot.unconfigured_events_skipped == delivered == 20_000
    assert snapshot.active_drops == snapshot.shadow_drops == snapshot.invalid_events_rejected == 0
    assert not module.engine._claimed_ids
    assert not module.engine._source_cursors
    assert snapshot.active_queue_depth == snapshot.shadow_queue_depth == 0
    assert len(bus.recent()) == 8
    if severity >= Severity.HIGH:
        assert len(bus.priority_since(0)[1]) == 8
        assert bus.priority_since(0)[2] is True


def test_rule_activation_admits_first_subsequent_event_and_shadow_stays_alert_inert():
    module = runtime.DetectionRuntimeModule()
    bus = EventBus()
    module.bind(bus)
    module._on_event(_event(0))
    module.engine.bind_shadow(_package())
    module._on_event(_event(1, Severity.HIGH))
    assert module.engine.process() == (0, 1)
    snapshot = module.engine.snapshot()
    assert snapshot.unconfigured_events_skipped == 1
    assert len(snapshot.shadow_observations) == 1
    assert snapshot.shadow_observations[0].matched
    assert snapshot.shadow_observations[0].event_id.startswith("runtime-2-")
    assert bus.recent() == []


def test_shadow_flood_preserves_active_lane_and_exposes_exact_loss(tmp_path):
    engine = runtime.DetectionRuntimeEngine(active_capacity=8, shadow_capacity=8)
    package = _package()
    registry = DetectionPackageRegistry(tmp_path / "registry", require_signed=False)
    source = tmp_path / "package.json"
    source.write_text(json.dumps(package.document), encoding="utf-8")
    assert registry.stage(source).ok
    assert registry.activate(package.package_id, package.document["digest"]).ok
    engine.sync_active_from_registry(
        registry, package_id=package.package_id,
        expected_digest=package.document["digest"], activation_epoch=1,
    )
    engine.bind_shadow(package)
    for index in range(2000):
        engine.submit_shadow(_event(index))
    assert engine.submit_configured(_event(2001, Severity.CRITICAL), source_cursor=2001)
    assert engine.process(max_active=8, max_shadow=0) == (1, 0)
    snapshot = engine.snapshot()
    assert snapshot.active_findings == 1
    assert snapshot.active_drops == 0
    assert snapshot.shadow_drops == 1993
    assert snapshot.shadow_queue_depth == 8


def test_nested_oversized_payload_stops_normalizing_before_expansion(monkeypatch):
    class CountedList(list):
        visits = 0

        def __iter__(self):
            for item in super().__iter__():
                type(self).visits += 1
                yield item

    leaves = CountedList(["x" * 4096] * 256)
    branches = CountedList([leaves] * 256)
    event = Event("fixture", "AI transcript flood", details={"transcript": branches})
    engine = runtime.DetectionRuntimeEngine()
    assert engine.submit(event) is False
    assert engine.snapshot().invalid_events_rejected == 1
    assert CountedList.visits < 100
    assert len(event.details["transcript"]) == 256


def test_direct_submit_retains_validation_even_without_configured_rules():
    engine = runtime.DetectionRuntimeEngine()
    assert engine.submit(Event("fixture", "invalid", details={"value": float("nan")})) is False
    assert engine.snapshot().invalid_events_rejected == 1
    assert engine.snapshot().unconfigured_events_skipped == 0


def test_normalization_keeps_legitimate_nested_event_identity_and_data():
    details = {"large": [["a" * 1024] * 64] * 3, "unicode": "\u2603", "nil": None}
    event = Event("fixture", "unicode fixture", Severity.HIGH, 100.0, details)
    queued = runtime.DetectionRuntimeEngine._queue_event(event, source_cursor=5)
    actual = queued.event()
    for key, value in details.items():
        assert actual[key] == value
    assert actual["event_id"].startswith("runtime-5-")
    assert len(queued.event_json.encode("utf-8")) < runtime.MAX_RUNTIME_EVENT_BYTES


def test_module_self_test():
    ok, note = runtime.DetectionRuntimeModule().self_test()
    assert ok, note
