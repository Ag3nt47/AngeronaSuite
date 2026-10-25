from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.core import net_interfaces
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.threat import event_disposition, is_active_threat
from angerona.modules import fast_path


def connection(local, remote, status="ESTABLISHED"):
    return SimpleNamespace(
        laddr=SimpleNamespace(ip=local),
        raddr=SimpleNamespace(ip=remote),
        status=status,
    )


def sample_connections(monkeypatch, connections):
    calls = []

    class Process:
        def __init__(self, pid):
            calls.append(pid)

        def net_connections(self, *, kind):
            assert kind == "inet"
            return connections

    monkeypatch.setattr(
        net_interfaces, "psutil",
        SimpleNamespace(Process=Process, CONN_ESTABLISHED="ESTABLISHED"),
    )
    monkeypatch.setattr(
        net_interfaces, "interface_type_for_local_ip",
        lambda value: {
            "10.1.1.1": net_interfaces.VIRTUAL_VPN,
            "192.168.1.2": net_interfaces.PHYSICAL,
            "127.0.0.1": net_interfaces.LOOPBACK,
        }[value],
    )
    return calls


def producer(monkeypatch, finding):
    # In-memory installation authority only; no config, key file or host query.
    authority = BusAuthority(b"v" * 32)
    bus = EventBus()
    bus.arm(authority)
    module = fast_path.FastPathModule()
    module.bind(bus)
    monkeypatch.setattr(fast_path, "detect_split_tunnel", lambda _pid: finding)
    return module, bus


def test_concurrent_connections_preserve_context_without_claiming_bypass(monkeypatch):
    calls = sample_connections(monkeypatch, [
        connection("10.1.1.1", "1.1.1.1"),
        connection("192.168.1.2", "8.8.8.8"),
    ])
    finding = net_interfaces.detect_split_tunnel(4242)
    assert calls == [4242]
    assert finding["vpn_destinations"] == ["1.1.1.1"]
    assert finding["physical_external_destinations"] == ["8.8.8.8"]
    assert finding["finding_kind"] == finding["disposition"] == "exposure"
    assert finding["active_attack"] is False
    assert finding["response_authorized"] is False
    assert finding["response_authority"] == "observe-only"
    assert finding["observation_only"] is True
    assert finding["process_identity_bound"] is False
    assert "unconfirmed" in finding["reason"]
    assert "response_contract" not in finding


@pytest.mark.parametrize("connections", [
    [],
    [connection("10.1.1.1", "1.1.1.1")],
    [connection("192.168.1.2", "8.8.8.8")],
    [connection("10.1.1.1", "1.1.1.1"), connection("192.168.1.2", "192.168.1.1")],
    [connection("10.1.1.1", "1.1.1.1"), connection("192.168.1.2", "8.8.8.8", "SYN_SENT")],
    [connection("10.1.1.1", "1.1.1.1"), connection("127.0.0.1", "8.8.8.8")],
])
def test_incomplete_topology_does_not_manufacture_observation(monkeypatch, connections):
    sample_connections(monkeypatch, connections)
    assert net_interfaces.detect_split_tunnel(4242) is None


def test_unavailable_sampler_does_not_manufacture_observation(monkeypatch):
    def unavailable(_pid):
        raise PermissionError("inert denied fixture")

    monkeypatch.setattr(net_interfaces, "psutil", SimpleNamespace(Process=unavailable))
    assert net_interfaces.detect_split_tunnel(4242) is None


def test_signed_topology_observation_never_grants_response_authority(monkeypatch):
    # A helper hint cannot promote socket metadata or smuggle a typed action.
    module, bus = producer(monkeypatch, {
        "vpn_destinations": ["1.1.1.1"],
        "physical_external_destinations": ["8.8.8.8"],
        "active_attack": True,
        "response_authorized": True,
        "response_contract": {"version": 1, "actions": ["terminate_process"]},
    })
    module._check_split_tunnel(Event("Inert network fixture", "socket metadata"), 4242)
    event, = bus.recent(10)
    assert bus.verify(event)
    assert event.severity == Severity.MEDIUM
    assert event.details["pid"] == 4242
    assert event.details["finding_kind"] == event.details["disposition"] == "exposure"
    assert event.details["response_authorized"] is False
    assert event.details["active_attack"] is False
    assert event.details["response_authority"] == "observe-only"
    assert event.details["process_identity_bound"] is False
    assert "response_contract" not in event.details
    assert event_disposition(event) == "exposure"
    assert not is_active_threat(event)


def test_topology_repeat_is_deduplicated(monkeypatch):
    module, bus = producer(monkeypatch, {"vpn_destinations": ["1.1.1.1"]})
    event = Event("Inert network fixture", "socket metadata")
    module._check_split_tunnel(event, 4242)
    module._check_split_tunnel(event, 4242)
    assert len(bus.recent(10)) == 1


def test_network_event_does_not_promote_topology_but_other_ioc_still_critical(monkeypatch):
    module, bus = producer(monkeypatch, {
        "vpn_destinations": ["1.1.1.1"],
        "physical_external_destinations": ["8.8.8.8"],
    })
    event = Event("Inert high-confidence sensor", "fixture", Severity.HIGH, details={
        "pid": 4242,
        "raddr": "8.8.8.8",
        "command_line": "sekurlsa::logonpasswords",
    })
    module._check_event(event)
    outputs = bus.recent(10)
    assert len(outputs) == 2
    context, = [item for item in outputs if item.severity == Severity.MEDIUM]
    strong, = [item for item in outputs if item.severity == Severity.CRITICAL]
    assert event_disposition(context) == "exposure"
    assert not is_active_threat(context)
    assert strong.details["rule_label"] == "Mimikatz / credential dumping tool"
    assert is_active_threat(strong)
    assert all(bus.verify(item) for item in outputs)


def test_low_severity_network_context_stays_exposure(monkeypatch):
    module, bus = producer(monkeypatch, {"vpn_destinations": ["1.1.1.1"]})
    event = Event("Inert socket sensor", "fixture", Severity.LOW, details={
        "pid": 4242, "interface_type": net_interfaces.VIRTUAL_VPN,
    })
    module._check_event(event)
    observation, = bus.recent(10)
    assert observation.severity == Severity.MEDIUM
    assert event_disposition(observation) == "exposure"
    assert not is_active_threat(observation)


def test_empty_sampler_result_leaves_other_rules_available(monkeypatch):
    module, bus = producer(monkeypatch, None)
    module._check_event(Event("Inert sensor", "fixture", Severity.HIGH, details={
        "pid": 4242, "raddr": "8.8.8.8", "command_line": "sekurlsa::logonpasswords",
    }))
    event, = bus.recent(10)
    assert event.severity == Severity.CRITICAL
    assert event.details["rule_label"] == "Mimikatz / credential dumping tool"
