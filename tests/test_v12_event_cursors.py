from __future__ import annotations

from pathlib import Path

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.module_base import BaseModule


ROOT = Path(__file__).resolve().parents[1]


class _PollingModule(BaseModule):
    name = "Cursor Regression Probe"

    def run(self) -> None:
        return


def _event(label: str, *, severity: Severity = Severity.INFO) -> Event:
    # Identical timestamps are intentional. Wall-clock values are evidence,
    # not an ordering or uniqueness primitive.
    return Event("producer", label, severity, 1000.0, {"label": label})


def test_module_cursor_delivers_same_timestamp_burst_once_in_publication_order() -> None:
    bus = EventBus(ring_size=16)
    module = _PollingModule()
    module.bind(bus)

    for label in ("one", "two", "three", "four"):
        bus.publish(_event(label))

    first, overflow = module.poll_bus_events()
    second, repeated_overflow = module.poll_bus_events()

    assert [event.message for event in first] == ["one", "two", "three", "four"]
    assert overflow is False
    assert second == []
    assert repeated_overflow is False


def test_priority_cursor_survives_general_info_flood_without_losing_alerts() -> None:
    bus = EventBus(ring_size=2, priority_ring_size=8)
    module = _PollingModule()
    module.bind(bus)

    bus.publish(_event("high-one", severity=Severity.HIGH))
    for index in range(20):
        bus.publish(_event(f"noise-{index}"))
    bus.publish(_event("critical-two", severity=Severity.CRITICAL))

    events, overflow = module.poll_bus_events(priority=True)

    assert [event.message for event in events] == ["high-one", "critical-two"]
    assert overflow is False


def test_general_cursor_surfaces_retention_overflow_as_incomplete_evidence() -> None:
    bus = EventBus(ring_size=2)
    module = _PollingModule()
    module.bind(bus)
    for label in ("one", "two", "three"):
        bus.publish(_event(label))

    retained, overflow = module.poll_bus_events()

    assert [event.message for event in retained] == ["two", "three"]
    assert overflow is True
    assert module.health == 60
    assert module._bus_overflow_count == 1
    assert any(
        event.details.get("finding_code") == "module.eventbus.retention_overflow"
        for event in bus.recent(4)
    )


def test_security_pollers_do_not_reintroduce_timestamp_watermarks() -> None:
    migrated = (
        "ai_triage.py",
        "amsi_bridge.py",
        "behavioral_tuner.py",
        "cloud_escalation.py",
        "compliance_mapper.py",
        "counter_agentic.py",
        "dynamic_resource.py",
        "fast_path.py",
        "forensics.py",
        "mobile_bridge.py",
        "siem_forwarder.py",
    )
    module_root = ROOT / "src" / "angerona" / "modules"
    for name in migrated:
        source = (module_root / name).read_text(encoding="utf-8")
        if name == "siem_forwarder.py":
            assert "read_bus_events(" in source
            assert "commit_bus_cursor(" in source
        else:
            assert "poll_bus_events(" in source
        assert "_last_ts" not in source
        assert "_cursor_ts" not in source
