"""Only exact unavailable network telemetry is health; path changes stay active.

All snapshots are bounded synthetic input to the real pure evaluator and module
publisher. No interface discovery, networking, baseline store or response runs.
"""
from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from angerona.core.chill_mode import ChillPolicy
from angerona.core.chill_runtime import ChillRuntimeController
from angerona.core.eventbus import BusAuthority, EventBus, Severity
from angerona.core.network_trust import (
    COLLECTION_SOURCES, DefaultRouteObservation, NetworkLinkObservation,
    NetworkSnapshot, evaluate_network_trust,
)
from angerona.core.threat import active_threat_events, event_disposition, is_active_threat
from angerona.modules.network_trust_monitor import NetworkTrustMonitorModule

KEY = b"network-coverage-fixture-key-00001"
COMPLETE = tuple(sorted(COLLECTION_SOURCES))


@pytest.fixture(autouse=True)
def private_resolution_state(monkeypatch):
    from angerona.core import alert_ack, drill_resolution, process_allowlist
    monkeypatch.setattr(alert_ack, "acked_signatures", lambda: set())
    monkeypatch.setattr(process_allowlist, "policy_snapshot", lambda: ())
    monkeypatch.setattr(process_allowlist, "is_event_allowed", lambda *_a, **_k: False)
    monkeypatch.setattr(drill_resolution, "resolution_snapshot", lambda: {})
    monkeypatch.setattr(drill_resolution, "is_resolved_event", lambda *_a, **_k: False)


def link(**changes):
    fields = dict(
        interface_id="private-synthetic-ethernet", kind="ethernet", interface_index=7,
        dns_servers=("192.0.2.53",), dhcp_server="192.0.2.1",
        default_routes=(), gateway_identities=(), profile_category="public",
        collection_complete=COMPLETE,
    )
    fields.update(changes)
    return NetworkLinkObservation(**fields)


def snapshot(observation):
    return NetworkSnapshot((observation,), collection_complete=COMPLETE)


def publisher(bus=None):
    bus = bus or EventBus()
    bus.arm(BusAuthority(b"N" * 32))
    module = NetworkTrustMonitorModule(
        privacy_key=KEY,
        observer=lambda: pytest.fail("This pure publication fixture must not discover the host"),
    )
    module.bind(bus)
    assert module._baseline_store is None
    return module, bus


def actual_notice(*, baseline_unproven=False, bus=None):
    current = link(collection_complete=tuple(x for x in COMPLETE if x != "dns"))
    previous = None
    if baseline_unproven:
        route = DefaultRouteObservation("192.0.2.1", selected=True, interface_index=7)
        prior = link(default_routes=(route,))  # No resolved gateway identity.
        previous = evaluate_network_trust(snapshot(prior), KEY).baseline
        current = replace(current, default_routes=(route,))
    result = evaluate_network_trust(snapshot(current), KEY, previous)
    module, bus = publisher(bus)
    module._publish_evaluation(result)
    events = [e for e in bus.recent(50)
              if e.details.get("finding_type") == "network.telemetry_incomplete"]
    assert len(events) == 1 and bus.verify(events[0])
    return module, bus, events[0], result


def controller_boundary(bus, monkeypatch):
    policy = ChillPolicy(clock=lambda: 10.0)
    policy.enable()
    controller = ChillRuntimeController(
        SimpleNamespace(modules={}), bus, SimpleNamespace(runtime_chill_active=True),
        policy=policy, clock=lambda: 10.0, release_models=lambda *_a: None,
    )
    wakes = []
    monkeypatch.setattr(controller, "_begin_wake", lambda count, **kw: wakes.append((count, kw)))
    return controller, wakes


@pytest.mark.parametrize("baseline_unproven", [False, True])
def test_actual_signed_coverage_keeps_high_warning_and_untrusted_path(baseline_unproven):
    module, bus, event, result = actual_notice(baseline_unproven=baseline_unproven)
    original = deepcopy(event)
    assert event.severity is Severity.HIGH
    assert event.details["trust_label"] == "untrusted"
    assert event.details["endpoint_resources_trusted"] is False
    assert event.details["response_authorized"] is False
    evidence = event.details["evidence"]
    assert ("baseline_gateway_evidence_unproven" in evidence) is baseline_unproven
    assert event_disposition(event) == "health"
    assert not is_active_threat(event) and active_threat_events([event]) == []
    assert event == original and bus.verify(event)
    before = len(bus.recent(100))
    module._publish_evaluation(result)
    assert len(bus.recent(100)) == before  # Existing unchanged-finding cadence remains.
    retained = replace(event, details=json.loads(json.dumps(event.details)))
    assert bus.verify(retained) and event_disposition(retained) == "health"


def test_signed_network_coverage_does_not_trigger_chill_wake(monkeypatch):
    bus = EventBus()
    bus.arm(BusAuthority(b"N" * 32))
    controller, wakes = controller_boundary(bus, monkeypatch)
    _module, _bus, event, _result = actual_notice(bus=bus)
    controller.poll_once()
    assert wakes == [] and not controller.policy.escalated
    assert controller.policy.awake_until == 0.0 and bus.verify(event)
    assert controller._wake_thread is None and controller._release_thread is None


@pytest.mark.parametrize("kind", ["dns", "dhcp", "gateway"])
def test_actual_dns_dhcp_and_gateway_changes_stay_active(kind, monkeypatch):
    route = DefaultRouteObservation("192.0.2.1", selected=True, interface_index=7)
    original = link(default_routes=(route,), gateway_identities=("192.0.2.1|02:11:22:33:44:55",))
    previous = evaluate_network_trust(snapshot(original), KEY).baseline
    changes = {
        "dns": {"dns_servers": ("192.0.2.54",)},
        "dhcp": {"dhcp_server": "192.0.2.2"},
        "gateway": {"gateway_identities": ("192.0.2.1|02:66:77:88:99:aa",)},
    }
    result = evaluate_network_trust(snapshot(replace(original, **changes[kind])), KEY, previous)
    bus = EventBus()
    bus.arm(BusAuthority(b"N" * 32))
    controller, wakes = controller_boundary(bus, monkeypatch)
    _module, bus = publisher(bus)
    _module._publish_evaluation(result)
    expected = {"dns": "network.dns_drift", "dhcp": "network.dhcp_drift",
                "gateway": "network.gateway_identity_drift"}[kind]
    finding = next(e for e in bus.recent(100) if e.details.get("finding_type") == expected)
    expected_severity = Severity.CRITICAL if kind == "gateway" else Severity.HIGH
    assert finding.severity is expected_severity and bus.verify(finding)
    assert finding.details["response_authorized"] is False
    assert event_disposition(finding) == "active" and is_active_threat(finding)
    controller.poll_once()
    assert len(wakes) == 1 and wakes[0][0] >= 1 and controller.policy.escalated
    assert controller._wake_thread is None  # Capture only the final wake boundary.


@pytest.mark.parametrize("change", [
    "active", "exploitation", "response", "authority", "contract", "tamper", "target",
    "unknown-field", "wrong-schema", "other-rule", "trusted-resources", "raw-identifiers",
    "response-int", "identifiers-int", "trust-label", "link-kind", "token-length",
    "token-hex", "recommendations-type", "recommendations-value", "evidence-type",
    "evidence-extra", "missing-type", "missing-empty", "missing-too-many", "missing-untyped",
    "missing-unknown", "missing-duplicate", "missing-unsorted", "baseline-false",
    "baseline-int", "baseline-without-missing", "missing-field", "wrong-message",
    "different-producer", "critical", "raw-severity-int", "health-label",
])
def test_other_network_findings_and_malformed_envelopes_remain_active(change):
    _module, _bus, event, _result = actual_notice()
    d = deepcopy(event.details)
    kwargs = {"details": d, "hmac_sig": ""}
    if change == "active": d["active_attack"] = True
    elif change == "exploitation": d["active_exploitation"] = True
    elif change == "response": d["response_authorized"] = True
    elif change == "authority": d["response_authority"] = "privileged-service"
    elif change == "contract": d["response_contract"] = {"actions": ["isolate_host"]}
    elif change == "tamper": d["tamper"] = True
    elif change == "target": d["target"] = "local-host"
    elif change == "unknown-field": d["future_evidence"] = "not-reviewed"
    elif change == "wrong-schema": d["schema"] = "unknown.v2"
    elif change == "other-rule": d["finding_type"] = "network.dns_drift"
    elif change == "trusted-resources": d["endpoint_resources_trusted"] = True
    elif change == "raw-identifiers": d["local_network_identifiers_omitted"] = False
    elif change == "response-int": d["response_authorized"] = 0
    elif change == "identifiers-int": d["local_network_identifiers_omitted"] = 1
    elif change == "trust-label": d["trust_label"] = "gateway-attested"
    elif change == "link-kind": d["link_kind"] = "other"
    elif change == "token-length": d["path_token"] = "tok_" + "a" * 25
    elif change == "token-hex": d["path_token"] = "tok_" + "Z" * 24
    elif change == "recommendations-type": d["recommendations"] = tuple(d["recommendations"])
    elif change == "recommendations-value": d["recommendations"] = ["trust-all-resources"]
    elif change == "evidence-type": d["evidence"] = []
    elif change == "evidence-extra": d["evidence"]["tamper"] = True
    elif change == "missing-type": d["evidence"]["missing_sources"] = "dns"
    elif change == "missing-empty": d["evidence"]["missing_sources"] = ()
    elif change == "missing-too-many": d["evidence"]["missing_sources"] = ("dns",) * 11
    elif change == "missing-untyped": d["evidence"]["missing_sources"] = ({},)
    elif change == "missing-unknown": d["evidence"]["missing_sources"] = ("future-source",)
    elif change == "missing-duplicate": d["evidence"]["missing_sources"] = ("dns", "dns")
    elif change == "missing-unsorted": d["evidence"]["missing_sources"] = ("routes-ipv4", "dns")
    elif change == "baseline-false": d["evidence"]["baseline_gateway_evidence_unproven"] = False
    elif change == "baseline-int": d["evidence"]["baseline_gateway_evidence_unproven"] = 1
    elif change == "baseline-without-missing": d["evidence"]["baseline_gateway_evidence_unproven"] = True
    elif change == "missing-field": del d["local_network_identifiers_omitted"]
    elif change == "wrong-message": kwargs["message"] = "Zero-trust network finding: the DNS resolver set changed"
    elif change == "different-producer": kwargs["module"] = "Other Network Detector"
    elif change == "critical": kwargs["severity"] = Severity.CRITICAL
    elif change == "raw-severity-int": kwargs["severity"] = int(Severity.HIGH)
    elif change == "health-label": d["disposition"] = "health"
    else: raise AssertionError(change)
    candidate = replace(event, **kwargs)
    assert event_disposition(candidate) == "active" and is_active_threat(candidate)
