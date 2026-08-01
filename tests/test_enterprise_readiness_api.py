from __future__ import annotations

import json
from types import SimpleNamespace

from angerona.core.enterprise_readiness import assess, evidence_pack, render_text
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


def test_readiness_credits_local_foundations_and_keeps_external_gates() -> None:
    bus = EventBus()
    bus._authority = object()  # assessment only needs the public armed-state property
    report = assess(_Manager(), bus, _config(), _ProofLog())

    assert report["assessment_version"] == 4
    assert report["percent"] == 73
    assert report["band"] == "strong standalone foundation"
    assert report["summary"]["gaps"] == 0
    assert report["summary"]["external_gates"] == 4
    assert {
        row["id"] for row in report["external_gates"]
    } == {
        "production.transport",
        "production.identity",
        "production.availability",
        "production.publisher",
    }
    text = render_text(report)
    assert "Signed capability extension gate" in text
    assert "Endpoint identity and enrollment foundation" in text
    assert "Mutual Transport Layer Security (mTLS)" in text
    assert "not included in local score" in text


def test_enterprise_evidence_pack_is_deterministic_bounded_and_public_safe() -> None:
    bus = EventBus()
    bus._authority = object()
    report = assess(_Manager(), bus, _config(), _ProofLog())
    report["controls"].append({
        "id": "test.privacy",
        "name": "Privacy check",
        "status": "warn",
        "score": 0,
        "max_score": 1,
        "detail": r"C:\Users\Agent47\secret.txt api_key=abcdefghijklmnop1234",
        "action": "Remove local identifiers",
    })

    first = evidence_pack(report)
    second = evidence_pack(report)

    assert first == second
    assert first["schema"] == "angerona.enterprise-evidence/v1"
    assert len(first["evidence_sha256"]) == 64
    encoded = str(first)
    assert "Agent47" not in encoded
    assert r"C:\Users" not in encoded
    assert "abcdefghijklmnop1234" not in encoded


def test_readiness_exports_clock_quality_and_api_contract_without_tenant_identity() -> None:
    bus = EventBus()
    bus._authority = object()
    runtime = {
        "fleet_service": "running",
        "endpoint_identity": "active",
        "registered_devices": 3,
        "fleet_ingestion": "degraded",
        "stored_events": 42,
        "duplicate_retries": 7,
        "uncertain_clock_events": 2,
        "fleet_api_contract_sha256": "a" * 64,
    }
    report = assess(_Manager(), bus, _config(), _ProofLog(), runtime)
    packed = evidence_pack(report)

    assert packed["runtime"]["fleet_ingestion"] == "degraded"
    assert packed["runtime"]["stored_events"] == 42
    assert report["runtime"]["duplicate_retries"] == 7
    assert packed["runtime"]["duplicate_retries"] == 7
    assert packed["runtime"]["uncertain_clock_events"] == 2
    assert packed["runtime"]["fleet_api_contract_sha256"] == "a" * 64
    assert "tenant" not in json.dumps(packed["runtime"]).casefold()


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


def test_extension_summary_failure_is_unknown_and_never_passes() -> None:
    extension_error = type("ExtensionSummary" + "X" * 2_000, (RuntimeError,), {})

    class _BrokenExtensionManager(_Manager):
        def extension_security_summary(self):
            raise extension_error("do not expose this exception message")

    report = assess(
        _BrokenExtensionManager(), EventBus(), _config(), _ProofLog()
    )
    control = next(
        row for row in report["controls"] if row["id"] == "extensions.trust"
    )

    assert control["status"] == "gap"
    assert control["score"] == 0
    assert "ExtensionSummary" in control["detail"]
    assert "do not expose" not in control["detail"]
    assert len(control["detail"]) < 250


def test_absent_or_disabled_module_inventory_cannot_pass_health() -> None:
    class _InventoryManager(_Manager):
        def __init__(self, inventory):
            super().__init__()
            self._inventory = inventory

        def capability_inventory(self):
            return self._inventory

    empty = assess(
        _InventoryManager([]), EventBus(), _config(), _ProofLog()
    )
    disabled = assess(
        _InventoryManager([{
            "name": "Dormant sensor",
            "status": "stopped",
            "health": 100,
            "enabled": False,
        }]),
        EventBus(),
        _config(),
        _ProofLog(),
    )

    empty_health = next(
        row for row in empty["controls"]
        if row["id"] == "operations.module_health"
    )
    disabled_health = next(
        row for row in disabled["controls"]
        if row["id"] == "operations.module_health"
    )
    assert (empty_health["status"], empty_health["score"]) == ("warn", 0)
    assert (disabled_health["status"], disabled_health["score"]) == ("warn", 0)


def test_inactive_probe_stays_developing_and_library_controls_are_warnings() -> None:
    class _EmptyManager(_Manager):
        def capability_inventory(self):
            return []

    class _EmptyProofLog:
        def verify_receipt_chain(self, limit=2_000):
            return {
                "valid": True,
                "verified_receipts": 0,
                "reason": "no retained receipts",
            }

    report = assess(
        _EmptyManager(),
        EventBus(),
        _config(require_signed_aar=False),
        _EmptyProofLog(),
    )
    by_id = {row["id"]: row for row in report["controls"]}

    assert report["percent"] < 70
    assert report["band"] == "developing foundation"
    assert len(report["external_gates"]) == 4
    for control_id in (
        "incidents.causal_graph",
        "storage.bounds",
        "interop.ocsf",
        "audit.export",
    ):
        assert by_id[control_id]["status"] == "warn"
    audit = by_id["audit.export"]
    assert "HMAC authentication" in audit["detail"]
    assert "signed audit export" not in (
        audit["name"] + " " + audit["detail"]
    ).casefold()


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
