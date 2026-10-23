"""An unbound Fleet store is a coverage gap; genuine Fleet failures stay active."""
from copy import deepcopy
from dataclasses import replace

import pytest

from angerona.core.eventbus import BusAuthority, EventBus, Severity
from angerona.core.threat import active_threat_events, event_disposition, is_active_threat
from angerona.modules.fleet_health_monitor import FleetHealthMonitorModule


def actual_tick(*, fail=False):
    authority = BusAuthority(b"f" * 32)
    bus = EventBus()
    bus.arm(authority)
    module = FleetHealthMonitorModule()
    module.bind(bus)
    if fail:
        def unavailable():
            raise ValueError("inert custody verification failed")
        module.observe_once = unavailable
    module._tick()
    return module, bus, bus.recent(1)[0], authority


def test_actual_signed_unbound_producer_stays_high_health_without_hostile_verdict():
    module, bus, event, authority = actual_tick()
    before = deepcopy(event)
    assert module.health == 35 and event.severity is Severity.HIGH
    assert event.details["finding_code"] == "fleet.coverage.unbound"
    assert event.details["fabric_bound"] is False
    assert event_disposition(event) == "health"
    assert not is_active_threat(event) and not active_threat_events([event])
    assert event == before and authority.verify(event) and bus.verify(event)
    # The producer still deduplicates unchanged health warnings.
    module._tick()
    assert len(bus.recent(10)) == 1


def test_actual_custody_error_from_same_producer_remains_active():
    module, bus, event, _authority = actual_tick(fail=True)
    assert module.health == 25 and event.severity is Severity.HIGH
    assert event.details["custody_authenticated"] is False
    assert event.details["integrity_failure"] == "inert custody verification failed"
    assert "finding_code" not in event.details
    assert event_disposition(event) == "active" and is_active_threat(event)
    assert bus.verify(event)


@pytest.mark.parametrize("change", [
    {"active_attack": True}, {"active_exploitation": True},
    {"response_authorized": True}, {"response_authority": "privileged-service"},
    {"response_contract": {"actions": ["isolate_host"]}}, {"target": "endpoint"},
    {"tamper": True}, {"integrity_failure": "custody MAC failed"},
    {"custody_authenticated": False}, {"stats_authenticated": False},
    {"history_chain_status": "untrusted"}, {"fabric_bound": True},
    {"missing_devices": 1}, {"reported_drops": 1}, {"transport_enabled": True},
    {"transport_available": True}, {"remote_shell_available": True},
    {"arbitrary_command_available": True}, {"observation_only": False},
    {"enforcement_performed": True}, {"schema": "unknown.v2"},
    {"finding_code": "fleet.custody.failed"}, {"health_percent": True},
    {"evidence_rows": False}, {"evidence_rows": 0.0}, {"exact_reason": ""},
    {"unknown_evidence": "other finding"},
])
def test_contradictory_attack_response_bound_and_malformed_fields_fail_closed(change):
    _module, _bus, event, authority = actual_tick()
    candidate = replace(event, details={**event.details, **change}, hmac_sig="")
    candidate = replace(candidate, hmac_sig=authority.sign(candidate))
    assert authority.verify(candidate)
    assert event_disposition(candidate) == "active" and is_active_threat(candidate)


@pytest.mark.parametrize("removed", ["finding_code", "fabric_bound", "observation_only", "transport_available"])
def test_incomplete_or_legacy_contract_is_not_guessed_safe(removed):
    _module, _bus, event, _authority = actual_tick()
    details = dict(event.details)
    del details[removed]
    assert is_active_threat(replace(event, details=details))


def test_unknown_source_cannot_borrow_fleet_coverage_contract():
    _module, _bus, event, _authority = actual_tick()
    assert is_active_threat(replace(event, module="Other Detector"))
