"""Pre-existing persistence remains urgent evidence without claiming execution."""
from __future__ import annotations

import copy
from dataclasses import asdict, replace
import json
from types import SimpleNamespace

import pytest

from angerona.core import alert_ack, drill_resolution, process_allowlist, threat
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.persistence_sweep import PersistenceSweepModule


def _legacy_details():
    return {
        "change": "baseline_enrollment",
        "surface": "HKCU\\Run",
        "entry": "SyntheticStartup",
        "value": "powershell -enc SQBFAFgA",
        "mitre": "T1547.001",
        "baseline_trust": "unreviewed",
        "response_authorized": False,
    }


def _signed(details, *, module="Persistence Sweep", severity=Severity.HIGH):
    authority = BusAuthority(b"p" * 32)
    unsigned = Event(module, "Synthetic retained startup evidence", severity, details=details)
    event = replace(unsigned, hmac_sig=authority.sign(unsigned))
    return event, authority


def _evidence_bytes(event):
    return json.dumps(asdict(event), sort_keys=True, separators=(",", ":")).encode("utf-8")


@pytest.mark.parametrize(("surface", "entry", "value", "mitre", "severity"), [
    ("HKCU\\Run", "SyntheticEncoded", "powershell -enc SQBFAFgA", "T1547.001", Severity.CRITICAL),
    ("HKLM\\Run", "SyntheticTemporary", r"C:\Users\Test\AppData\Local\Temp\x.exe",
     "T1547.001", Severity.HIGH),
    ("HKLM\\Winlogon", "Shell", "explorer.exe,synthetic.exe", "T1547.004", Severity.CRITICAL),
])
def test_real_baseline_emit_keeps_risk_evidence_unreviewed(
    monkeypatch, surface, entry, value, mitre, severity,
):
    module = PersistenceSweepModule()
    bus = EventBus(ring_size=50)
    authority = BusAuthority(b"b" * 32)
    bus.arm(authority)
    module.bind(bus)
    baseline = {surface: {entry: value}}
    original = copy.deepcopy(baseline)
    module._values[f"{surface}\x00{entry}\x00mitre"] = mitre
    monkeypatch.setattr(module, "_sweep", lambda include_slow: baseline)
    monkeypatch.setattr(module, "sleep", lambda _seconds: module.stop())

    module.run()

    event, = [row for row in bus.recent(20) if row.details.get("change") == "baseline_enrollment"]
    assert event.severity == severity
    assert event.details == {
        "change": "baseline_enrollment", "surface": surface, "entry": entry,
        "value": value, "mitre": mitre, "baseline_trust": "unreviewed",
        "disposition": "observation", "finding_kind": "observation",
        "active_attack": False, "response_authority": "observe-only",
        "response_authorized": False,
    }
    assert value in event.message
    assert threat.event_disposition(event) == "observation"
    assert not threat.is_active_threat(event)
    assert authority.verify(event)
    assert module._baseline == original and baseline == original
    assert module.health < 100 and module._thread is None
    enrollment = [row for row in bus.recent(20)
                  if row.details.get("finding_code") == "persistence.baseline.unreviewed"]
    assert len(enrollment) == 1
    assert enrollment[0].details["baseline_trust"] == "unreviewed"
    assert enrollment[0].details["response_authorized"] is False


@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL])
def test_legacy_projection_preserves_original_bytes_signature_and_priority(severity):
    event, authority = _signed(_legacy_details(), severity=severity)
    before = _evidence_bytes(event)
    bus = EventBus(ring_size=2, priority_ring_size=10)
    bus.arm(authority)
    bus.publish(event)
    retained = bus.recent(1)[0]
    for index in range(5):
        bus.publish(Event("Telemetry", f"Synthetic noise {index}"))

    assert retained not in bus.recent(2)
    assert retained in threat.recent_threat_candidates(bus, 2)
    assert threat.event_disposition(retained) == "observation"
    assert not threat.is_active_threat(retained)
    assert retained.severity == severity
    assert _evidence_bytes(event) == before
    assert _evidence_bytes(retained) == before
    assert event.hmac_sig == retained.hmac_sig and authority.verify(retained)


@pytest.mark.parametrize("extra", [
    {"active_attack": True}, {"active_exploitation": True},
    {"disposition": "active"}, {"finding_kind": "active"},
    {"response_contract": {}}, {"response_contract": None},
    {"response_authority": "enrolled"}, {"threat_intel_corroborated": True},
    {"entropy_corroborated": True}, {"breach_confirmed": True},
    {"malware_confirmed": True}, {"spyware_confirmed": True},
    {"unknown_future_field": None}, {"active_attack": False},
    {"threat_intel_corroborated": False},
])
def test_conflicting_or_unknown_metadata_never_matches_legacy_projection(extra):
    event, authority = _signed({**_legacy_details(), **extra})
    before = _evidence_bytes(event)
    assert threat.event_disposition(event) == "active"
    assert threat.is_active_threat(event)
    assert authority.verify(event) and _evidence_bytes(event) == before


@pytest.mark.parametrize(("disposition", "expected"), [
    ("observation", "observation"), ("exposure", "exposure"), ("active", "active"),
])
def test_explicit_disposition_keeps_existing_precedence(disposition, expected):
    event, _authority = _signed({**_legacy_details(), "disposition": disposition})
    assert threat.event_disposition(event) == expected
    for active_key in ("active_attack", "active_exploitation"):
        active, _authority = _signed({**event.details, active_key: True})
        assert threat.event_disposition(active) == "active"


@pytest.mark.parametrize(("key", "value"), [
    ("change", "added"), ("change", "modified"), ("change", "removed"),
    ("change", "BASELINE_ENROLLMENT"), ("change", None),
    ("baseline_trust", "trusted"), ("baseline_trust", "UNREVIEWED"),
    ("baseline_trust", False), ("response_authorized", True),
    ("response_authorized", 0), ("response_authorized", "false"),
    ("surface", None), ("entry", 1), ("value", []), ("mitre", 1547),
])
def test_near_match_or_wrong_primitive_type_keeps_active_classification(key, value):
    event, _authority = _signed({**_legacy_details(), key: value})
    assert threat.event_disposition(event) == "active"


@pytest.mark.parametrize("missing", list(_legacy_details()))
def test_partial_legacy_details_are_not_reclassified(missing):
    details = _legacy_details()
    del details[missing]
    event, _authority = _signed(details)
    assert threat.event_disposition(event) == "active"


def test_other_producer_and_lower_severity_keep_existing_classification():
    for module in ("Other Persistence Detector", "Persistence Sweep Backup"):
        event, _authority = _signed(_legacy_details(), module=module)
        assert threat.event_disposition(event) == "active"
    for severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM):
        event, _authority = _signed(_legacy_details(), severity=severity)
        assert threat.event_disposition(event) == "informational"


def test_legacy_projection_refuses_nonplain_mapping_or_string_fields():
    class DetailMapping(dict):
        pass

    class Text(str):
        pass

    event, _authority = _signed(DetailMapping(_legacy_details()))
    assert threat.event_disposition(event) == "active"
    for key in ("change", "surface", "entry", "value", "mitre", "baseline_trust"):
        details = _legacy_details()
        details[key] = Text(details[key])
        event, _authority = _signed(details)
        assert threat.event_disposition(event) == "active"


def test_baseline_observation_stays_visible_without_inflating_cached_active_counts(monkeypatch, tmp_path):
    from angerona.core.status_report import StatusReporter

    monkeypatch.setattr(alert_ack, "acked_signatures", lambda: set())
    monkeypatch.setattr(process_allowlist, "policy_snapshot", lambda: ())
    monkeypatch.setattr(process_allowlist, "is_event_allowed", lambda *_, **__: False)
    monkeypatch.setattr(drill_resolution, "resolution_snapshot", lambda: {})
    monkeypatch.setattr(drill_resolution, "is_resolved_event", lambda *_, **__: False)
    bus = EventBus(ring_size=10)
    bus.arm(BusAuthority(b"s" * 32))
    bus.publish(Event("Persistence Sweep", "Synthetic startup configuration", Severity.CRITICAL,
                      details=_legacy_details()))
    baseline = bus.recent(1)[0]
    reporter = StatusReporter(
        bus, SimpleNamespace(count_since=lambda _: 1),
        SimpleNamespace(modules={}, is_enabled=lambda _: False),
        SimpleNamespace(data_dir=tmp_path, runtime_chill_active=False,
                        ollama_host="local", ollama_model="synthetic"),
    )

    snapshot = reporter._snapshot()

    assert snapshot["counts"]["active_critical_10m"] == 0
    assert snapshot["counts"]["alerts_24h"] == 1
    assert snapshot["recent_events"][0]["severity"] == "Critical"
    assert snapshot["recent_events"][0]["disposition"] == "observation"
    assert bus.verify(baseline)
