from __future__ import annotations

from types import SimpleNamespace

from angerona.core.enterprise_readiness import assess, render_text
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.engines.mcp_server import _make_tools


class _Manager:
    def __init__(self, *, unsigned: bool = False) -> None:
        self.modules = {
            "Sensor": SimpleNamespace(
                status="running",
                health=100,
                health_state="ok",
                health_note="",
                category="Endpoint",
                version="1.0.0",
                description="test",
            )
        }
        self._unsigned = unsigned

    def capability_inventory(self):
        return [{
            "name": "Sensor",
            "status": "running",
            "health": 100,
            "enabled": True,
            "origin": "builtin",
            "trust": "release",
        }]

    def extension_security_summary(self):
        return {
            "unsigned_development_override": self._unsigned,
            "loaded_external": 0,
            "signed_external": 0,
            "rejected_external": 0,
        }


class _ProofLog:
    def verify_receipt_chain(self, limit=2_000):
        return {
            "valid": True,
            "verified_receipts": 3,
            "reason": "retained receipt chain verified",
        }

    def recent(self, limit=20):
        return []


def _config(**changes):
    defaults = {
        "require_signed_aar": True,
        "aria_voice_cloud_tts": False,
        "aria_cloud_fallback": False,
        "alert_analysis_cloud_fallback": False,
        "aria_push_enabled": False,
        "aria_inbox_enabled": False,
        "aria_research_egress": False,
        "teams_bot_enabled": False,
        "mobile_enabled": False,
    }
    defaults.update(changes)
    return SimpleNamespace(**defaults)


def test_readiness_is_honest_about_enterprise_fleet_gaps() -> None:
    bus = EventBus()
    bus._authority = object()  # assessment only needs the public armed-state property
    report = assess(_Manager(), bus, _config(), _ProofLog())

    assert report["percent"] == 70
    assert report["band"] == "strong standalone foundation"
    assert report["summary"]["gaps"] == 4
    assert {
        row["id"] for row in report["controls"] if row["status"] == "gap"
    } == {
        "fleet.enrollment",
        "fleet.rbac",
        "fleet.policy",
        "fleet.scale",
    }
    text = render_text(report)
    assert "Signed capability extension gate" in text
    assert "mTLS endpoint enrollment" in text


def test_unsigned_override_and_optional_egress_are_visible_warnings() -> None:
    bus = EventBus()
    report = assess(
        _Manager(unsigned=True),
        bus,
        _config(aria_cloud_fallback=True),
        _ProofLog(),
    )
    by_id = {row["id"]: row for row in report["controls"]}
    assert by_id["telemetry.integrity"]["status"] == "gap"
    assert by_id["extensions.trust"]["status"] == "warn"
    assert by_id["privacy.egress"]["status"] == "warn"


def test_mcp_enterprise_tools_use_canonical_event_fields() -> None:
    bus = EventBus()
    bus.publish(Event(
        "ETW",
        "process creation",
        Severity.HIGH,
        10.0,
        {"pid": 42, "process_path": r"C:\sample.exe", "mitre": "T1059"},
    ))
    manager = _Manager()
    tools = _make_tools(SimpleNamespace(), bus, manager, _config())

    alerts = tools["get_recent_alerts"].fn(limit=10)
    modules = tools["get_module_status"].fn()
    graph = tools["get_causal_incident_graph"].fn(max_events=10)

    assert alerts[0]["module"] == "ETW"
    assert alerts[0]["details"]["pid"] == 42
    assert alerts[0]["mitre_tags"] == ["T1059"]
    assert modules[0]["health_pct"] == 100
    assert graph["stats"]["incidents"] == 1
    assert "get_enterprise_readiness" in tools
