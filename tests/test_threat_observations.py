"""Indicator calibration keeps signed evidence without inventing an attack."""
from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.threat import (
    active_threat_events,
    event_disposition,
    is_active_threat,
    threat_label_from_active,
)


@pytest.mark.parametrize(("module", "details", "expected"), [
    ("Ransomware Heuristics", {
        "path": "song.mp3", "entropy": 7.96, "threshold": 7.9,
        "active_attack": True, "detector_policy": "reviewed-semantic-indicator",
    }, "observation"),
    ("Ransomware Heuristics", {
        "transition": "changed", "active_attack": True,
        "detector_policy": "authenticated-content-transition",
    }, "observation"),
    ("Ransomware Heuristics", {
        "transition": "missing", "active_attack": True,
        "detector_policy": "authenticated-content-transition",
    }, "observation"),
    ("Memory Injection Scanner", {
        "proc_name": "ChatGPT.exe", "active_attack": True,
        "detector_policy": "rwx-memory-indicator-alert-only",
    }, "observation"),
    ("C2 Beacon Detector", {
        "active_attack": True, "threat_intel_corroborated": False,
        "detector_policy": "cadence-indicator-alert-only",
    }, "observation"),
    ("Network Protocol Deep Decoder", {
        "qname": "backgroundtaskhost.exe", "suspicious": True,
        "verdict": "DGA/tunneling-suspect", "reasons": ["entropy 3.61"],
    }, "observation"),
    ("AV Telemetry Bridge", {
        "disposition": "health", "continuity_complete": False,
        "response_authorized": False, "reason_code": "defender.channel.read_error",
    }, "health"),
    ("Kernel-Boundary Posture Ledger", {
        "user_mode_observation": True, "risks": ["HVCI is not running"],
        "evidence_sha256": "a" * 64,
    }, "exposure"),
])
def test_legacy_records_leave_active_list_without_rewriting_evidence(
    module, details, expected,
) -> None:
    authority = BusAuthority(b"o" * 32)
    unsigned = Event(module, "original detector evidence", Severity.HIGH, details=details)
    event = replace(unsigned, hmac_sig=authority.sign(unsigned))
    before = copy.deepcopy(event)
    confirmed = Event("AV Telemetry Bridge", "malware detected", Severity.CRITICAL,
                      details={"eid": 1116, "active_attack": True})

    assert event_disposition(event) == expected
    assert active_threat_events([event, confirmed]) == [confirmed]
    assert event == before
    assert authority.verify(event)


@pytest.mark.parametrize("module", ["Memory Injection Scanner", "Unknown Detector"])
def test_critical_and_explicit_exploitation_are_not_downgraded(module) -> None:
    details = {"active_attack": True, "detector_policy": "rwx-memory-indicator-alert-only"}
    critical = Event(module, "corroborated evidence", Severity.CRITICAL, details=details)
    explicit = Event(module, "exploitation", Severity.HIGH,
                     details={**details, "active_exploitation": True})
    assert is_active_threat(critical)
    assert is_active_threat(explicit)


@pytest.mark.parametrize("disposition", ["observation", "health", "exposure"])
def test_unrelated_disposition_never_overrides_explicit_active_evidence(disposition) -> None:
    event = Event("Process Guard", "confirmed hostile action", Severity.HIGH,
                  details={"active_attack": True, "disposition": disposition})
    assert is_active_threat(event)


def test_legacy_policy_does_not_hide_other_producers_or_corroboration() -> None:
    policy = {"detector_policy": "cadence-indicator-alert-only",
              "threat_intel_corroborated": False, "active_attack": True}
    assert is_active_threat(Event("Other Sensor", "evidence", Severity.HIGH, details=policy))
    assert is_active_threat(Event("C2 Beacon Detector", "evidence", Severity.HIGH,
                                  details={**policy, "threat_intel_corroborated": True}))
    assert is_active_threat(Event("Ransomware Heuristics", "canary touched", Severity.HIGH,
                                  details={"active_attack": True, "canary": True}))


def test_health_marker_requires_the_defender_continuity_record() -> None:
    event = Event("AV Telemetry Bridge", "malware", Severity.HIGH,
                  details={"disposition": "health", "eid": 1116})
    assert is_active_threat(event)


def test_snapshot_label_never_reloads_allowlists(monkeypatch) -> None:
    from angerona.core import process_allowlist

    def forbidden():
        raise AssertionError("presentation label reread authoritative policy")

    monkeypatch.setattr(process_allowlist, "policy_snapshot", forbidden)
    high = Event("AV Telemetry Bridge", "detected", Severity.HIGH)
    critical = Event("AV Telemetry Bridge", "detected", Severity.CRITICAL)
    assert threat_label_from_active([])[0] == "Secure"
    assert threat_label_from_active([high])[0] == "High"
    assert threat_label_from_active(iter([high, critical]))[0] == "Critical"


def test_observation_only_refresh_does_not_load_response_policy(monkeypatch) -> None:
    from angerona.core import alert_ack, drill_resolution, process_allowlist

    calls = []
    monkeypatch.setattr(alert_ack, "acked_signatures", lambda: calls.append("ack") or set())
    monkeypatch.setattr(process_allowlist, "policy_snapshot", lambda: calls.append("policy") or ())
    monkeypatch.setattr(drill_resolution, "resolution_snapshot", lambda: calls.append("drill") or {})
    observation = Event("Ransomware Heuristics", "entropy", Severity.INFO,
                        details={"disposition": "observation", "active_attack": False})
    expired = Event("Detector", "old detection", Severity.HIGH, ts=0)
    assert active_threat_events([observation, expired]) == []
    assert calls == []
    active = Event("AV Telemetry Bridge", "detected", Severity.HIGH, details={"eid": 1116})
    assert active_threat_events([active]) == [active]
    assert calls == ["ack", "policy", "drill"]
