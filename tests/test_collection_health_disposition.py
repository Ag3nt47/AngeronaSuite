"""Collector uncertainty must preserve warnings without inventing live attacks."""
from copy import deepcopy
from dataclasses import replace

import pytest

from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.threat import active_threat_events, event_disposition, is_active_threat


NOTICES = [
    ("Self-Integrity Monitor", {
        "disposition": "health", "acl_status": "collection-failed", "acl_path": "D:/state",
    }),
    ("Persistence Sweep", {
        "finding_code": "persistence.collector.incomplete", "response_authorized": False,
        "coverage": {"tasks": {"status": "unknown", "error": "fixture unavailable"}},
    }),
    ("Sysmon Event Bridge", {
        "disposition": "health", "state": "generation-gap-replay",
        "current_generation": "a" * 64, "cursor": 48731, "oldest_record": 41360,
        "newest_record": 79881, "replay_from": 41360, "cursor_persistence": "durable",
    }),
]


@pytest.mark.parametrize("module,details", NOTICES)
def test_retained_signed_collector_notice_is_health_without_rewriting(module, details):
    authority = BusAuthority(b"h" * 32)
    unsigned = Event(module, "Original retained evidence", Severity.HIGH, details=details)
    event = replace(unsigned, hmac_sig=authority.sign(unsigned))
    before = deepcopy(event)
    assert event_disposition(event) == "health"
    assert active_threat_events([event]) == []
    assert event == before
    assert event.severity == Severity.HIGH
    assert authority.verify(event)


@pytest.mark.parametrize("module,details", NOTICES)
@pytest.mark.parametrize("override", [
    {"active_attack": True}, {"active_exploitation": True},
    {"response_authorized": True}, {"response_contract": {}}, {"tamper": True},
    {"schema": "unknown.v2"},
])
def test_explicit_findings_and_unknown_contracts_remain_active(module, details, override):
    assert is_active_threat(Event(module, "Evidence", Severity.HIGH,
                                 details={**details, **override}))


@pytest.mark.parametrize("module,details", NOTICES)
def test_same_health_label_cannot_suppress_another_producer(module, details):
    assert is_active_threat(Event("Other Detector", "Evidence", Severity.HIGH, details=details))


@pytest.mark.parametrize("state", ["cursor-untrusted-replay", "delivery-gap", "unknown"])
def test_sysmon_integrity_or_delivery_failures_remain_active(state):
    module, details = NOTICES[2]
    assert is_active_threat(Event(module, "Evidence", Severity.HIGH,
                                 details={**details, "state": state}))


@pytest.mark.parametrize("override", [
    {"coverage": {}}, {"coverage": {"tasks": {"status": "complete", "error": ""}}},
    {"coverage": {"tasks": {"status": [], "error": ""}}},
    {"finding_code": "persistence.changed"}, {"response_authorized": 0},
])
def test_malformed_or_non_coverage_persistence_records_fail_closed(override):
    module, details = NOTICES[1]
    assert is_active_threat(Event(module, "Evidence", Severity.HIGH,
                                 details={**details, **override}))


@pytest.mark.parametrize("override", [{"state": []}, {"cursor": True},
                                      {"current_generation": "?" * 64}])
def test_malformed_sysmon_health_records_fail_closed(override):
    module, details = NOTICES[2]
    assert is_active_threat(Event(module, "Evidence", Severity.HIGH,
                                 details={**details, **override}))


def test_acl_weakness_and_runtime_mutation_still_raise_active_incidents():
    assert is_active_threat(Event("Self-Integrity Monitor", "Mutation", Severity.CRITICAL,
                                 details={"tamper": True, "target": "core.enforce"}))
    assert event_disposition(Event("Self-Integrity Monitor", "Weak ACL", Severity.HIGH,
                                   details={"hardening": True})) == "exposure"
