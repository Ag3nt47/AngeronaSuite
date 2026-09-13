"""Serious sensor coverage warnings must not trigger Chill Mode threat wakeups."""
from copy import deepcopy
from dataclasses import replace

import pytest

from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.threat import active_threat_events, event_disposition, is_active_threat


COVERAGE = [
    ("Process Egress Lease Guard", {
        "schema": "angerona.process-egress-guard-status.v1",
        "audit_complete": False, "lost_records": 0,
        "observation_only": True, "enforcement_performed": False,
    }),
    ("Temporal Tradecraft Correlator", {
        "schema": "angerona.temporal-tradecraft.v1",
        "finding_code": "temporal.coverage.overflow", "temporal_state": "overflow",
        "continuity_reason": "bounded temporal evidence capacity was exceeded",
        "persistence_status": "authenticated",
    }),
    ("Audit Log Integrity Guard", {
        "source_channel": "Microsoft-Windows-Sysmon/Operational",
        "sensor_state": "blind", "error_class": "error", "reader_error_code": 15007,
    }),
    ("AegisPath Exposure Graph Guard", {
        "schema": "angerona.aegis-path.graph-health.v1",
        "observation_only": True, "enforcement_performed": False,
        "snapshot_available": False, "snapshot_valid": False,
        "coverage_reason": "no-snapshot",
    }),
    ("Driver Provenance Guard", {
        "schema": "angerona.driver-provenance-coverage.v1",
        "reason_code": "inventory-unavailable", "driver_control_performed": False,
    }),
]


def coverage_event(module, details):
    return Event(module, "Coverage evidence", Severity.CRITICAL, details={
        "response_authorized": False, "response_authority": "observe-only", **details,
    })


@pytest.mark.parametrize("module,details", COVERAGE)
def test_coverage_keeps_signed_warning_without_waking_chill(module, details):
    authority = BusAuthority(b"c" * 32)
    event = coverage_event(module, details)
    event = replace(event, hmac_sig=authority.sign(event))
    original = deepcopy(event)
    assert event_disposition(event) == "health"
    assert active_threat_events([event]) == []
    assert event == original
    assert event.severity == Severity.CRITICAL
    assert authority.verify(event)


@pytest.mark.parametrize("module,details", COVERAGE)
@pytest.mark.parametrize("flag", ["active_attack", "active_exploitation"])
def test_explicit_attack_evidence_still_wakes_chill(module, details, flag):
    assert is_active_threat(coverage_event(module, {**details, flag: True}))


@pytest.mark.parametrize("module,details", COVERAGE)
def test_unknown_producer_and_response_authority_fail_closed(module, details):
    assert is_active_threat(coverage_event("Other Detector", details))
    assert is_active_threat(coverage_event(module, {**details, "response_authorized": True}))
    if "schema" in details:
        assert is_active_threat(coverage_event(module, {**details, "schema": "unknown.v2"}))


@pytest.mark.parametrize("module,details", [
    ("Process Egress Lease Guard", {
        "schema": "angerona.process-egress-audit.v1", "broker_allowed": False,
        "event_token": "denied", "observation_only": True,
    }),
    ("Temporal Tradecraft Correlator", {
        "schema": "angerona.temporal-tradecraft.v1", "temporal_state": "blind",
        "finding_code": "temporal.ssh.persistence", "signal_kinds": ["ssh-key-added"],
    }),
    ("Audit Log Integrity Guard", {
        "source_channel": "Security", "event_id": 1102,
        "classification": "audit-log-cleared", "record_id": 42,
    }),
    ("Audit Log Integrity Guard", {
        "sensor_state": "untrusted", "telemetry_quality": "untrusted",
        "source_channel": "Security", "error_class": "CheckpointIntegrityError",
    }),
    ("Driver Provenance Guard", {
        "schema": "angerona.driver-provenance-assessment.v1",
        "risk_codes": ["vulnerable-driver"], "evidence_sha256": "a" * 64,
    }),
])
def test_findings_and_integrity_errors_remain_active(module, details):
    assert is_active_threat(coverage_event(module, details))


@pytest.mark.parametrize("persistence", ["authenticated", "untrusted", "unavailable"])
def test_ambiguous_temporal_blindness_remains_active(persistence):
    assert is_active_threat(coverage_event("Temporal Tradecraft Correlator", {
        "schema": "angerona.temporal-tradecraft.v1",
        "finding_code": "temporal.coverage.blind", "temporal_state": "blind",
        "continuity_reason": "one or more admitted sensor sources are blind or unauthenticated",
        "persistence_status": persistence,
    }))


@pytest.mark.parametrize("valid,reason", [
    (False, "snapshot-digest-invalid"),
    (True, "coverage_manifest_digest_invalid"),
])
def test_graph_receipt_and_manifest_failures_remain_active(valid, reason):
    assert is_active_threat(coverage_event("AegisPath Exposure Graph Guard", {
        "schema": "angerona.aegis-path.graph-health.v1",
        "observation_only": True, "enforcement_performed": False,
        "snapshot_available": True, "snapshot_valid": valid,
        "semantic_coverage_verified": False,
        "coverage_reason": reason, "semantic_coverage_reasons": [reason],
    }))


@pytest.mark.parametrize("error_class,code", [("ValueError", None), ("error", 15005), ("error", None)])
def test_audit_malformed_or_unknown_errors_remain_active(error_class, code):
    assert is_active_threat(coverage_event("Audit Log Integrity Guard", {
        "source_channel": "Security", "sensor_state": "blind",
        "error_class": error_class, "reader_error_code": code,
    }))


def test_native_missing_channel_producer_emits_exact_reader_evidence(tmp_path):
    pywintypes = pytest.importorskip("pywintypes")
    from angerona.modules.audit_log_guard import AuditLogIntegrityGuard

    module = AuditLogIntegrityGuard(data_root=tmp_path, checkpoint_key=b"a" * 32)
    emitted = []
    module.emit = lambda message, severity, **details: emitted.append(
        Event(module.name, message, severity, details=details))

    def unavailable(*_args):
        raise pywintypes.error(15007, "EvtQuery", "Fixture channel unavailable")

    module._source = unavailable
    module._checkpoints = {}
    module._poll_channel("Microsoft-Windows-Sysmon/Operational", (4, 16, 255))
    assert len(emitted) == 1
    assert emitted[0].details["reader_error_code"] == 15007
    assert event_disposition(emitted[0]) == "health"
