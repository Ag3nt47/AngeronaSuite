"""Offline wiring/continuity regressions; no native collectors or host changes."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules import amsi_bridge as amsi
from angerona.modules import network_protocol_decoder as dns
from angerona.modules import beacon_detector as beacon
from angerona.telemetry.sensors import ConnectionList, ConnectionSnapshot


@pytest.mark.parametrize("field", ["command_line", "cmdline", "script_block"])
def test_script_consumer_accepts_explicit_bounded_text_aliases(field):
    text = "powershell.exe -NoProfile -Command Write-Output benign-fixture"
    ev = SimpleNamespace(details={field: text})
    assert amsi.AMSIBridgeModule._extract_script_content(None, ev) == text


@pytest.mark.parametrize("details", [None, [], {"cmdline": {}}, {"cmdline": b"powershell"},
                                        {"cmdline": "powershell" + "x" * (64 * 1024)},
                                        {"cmdline": "ordinary-fixture.exe"}])
def test_script_alias_never_coerces_malformed_oversize_or_unrelated_text(details):
    assert amsi.AMSIBridgeModule._extract_script_content(None, SimpleNamespace(details=details)) is None


def native_dns(**changes):
    details = {"eid": 22, "sensor_source": "sysmon-native", "raw_sensor_evidence": True,
               "query_name": "kq3v9z7x1p4m8n2b5w0c.example.com", **changes}
    return Event("Sysmon Event Bridge", "native DNS fixture", Severity.INFO, details=details)


def test_actual_sysmon22_shape_reaches_lexical_decoder_without_response_authority():
    instance, bus = dns.NetworkProtocolDecoderModule(), EventBus()
    instance.bind(bus)
    instance._on_event(native_dns())
    assert instance.stats()["dns_seen"] == 1
    lead = bus.recent(1)[0]
    assert lead.details["disposition"] == "observation"
    assert lead.details["active_attack"] is False
    assert lead.details.get("response_authorized") is not True
    assert "response_contract" not in lead.details
    assert "detector_receipt" not in lead.details


@pytest.mark.parametrize("changes", [{"eid": 3}, {"eid": "22"}, {"eid": True},
                                     {"sensor_source": "psutil"}, {"fallback": True},
                                     {"raw_sensor_evidence": "True"}, {"query_name": {}}])
def test_native_dns_guard_refuses_wrong_eid_source_fallback_and_shape(changes):
    instance = dns.NetworkProtocolDecoderModule()
    instance._on_event(native_dns(**changes))
    assert instance.stats()["dns_seen"] == 0


def test_native_dns_other_module_cannot_impersonate_sysmon():
    instance = dns.NetworkProtocolDecoderModule()
    ev = native_dns()
    instance._on_event(Event("Other Sensor", ev.message, ev.severity, details=ev.details))
    assert instance.stats()["dns_seen"] == 0


def test_native_dns_requires_existing_mesh_authentication():
    instance, bus = dns.NetworkProtocolDecoderModule(), EventBus()
    bus.activate_mesh()
    instance.bind(bus)
    bus.subscribe(instance._on_event)
    bus.publish(native_dns())
    assert instance.stats()["dns_seen"] == 0
    publish = bus.enroll_mesh_publisher("Sysmon Event Bridge", "a" * 64)
    publish(native_dns(query_name="www.microsoft.com"))
    assert instance.stats()["dns_seen"] == 1
    assert instance.stats()["flagged"] == 0


@pytest.mark.parametrize("address,external", [
    ("8.8.8.8", True), ("2001:4860:4860::8888", True), ("[2001:4860:4860::8888]", True),
    ("10.0.0.1", False), ("172.16.0.1", False), ("192.168.1.1", False),
    ("127.0.0.1", False), ("100.64.1.1", False), ("fd00::1", False),
    ("fc00::1", False), ("[fe80::1]", False), ("::1", False),
    ("::ffff:192.168.1.1", False), ("ff02::1", False), ("0.0.0.0", False),
    ("invalid.example", False), ("172.invalid", False), ("fe80::1%3", False),
])
def test_beacon_external_address_classification(address, external):
    assert beacon._is_external(address) is external


@pytest.mark.parametrize("endpoint,ip", [
    ("8.8.8.8:443", "8.8.8.8"), ("[2001:4860:4860::8888]:443", "2001:4860:4860::8888"),
    ("2001:4860:4860::8888:443", "2001:4860:4860::8888"),
    ("[::1]:443", "::1"), ("[::1]:65536", None), ("bad:443", None),
    ("[::1:443", None), ("8.8.8.8:https", None), (None, None),
])
def test_beacon_endpoint_parser(endpoint, ip):
    assert beacon._peer_ip(endpoint) == ip


@pytest.fixture
def polling(monkeypatch):
    state = {"now": 1000.0, "birth": 900.0, "present": True, "complete": True,
             "intel": False, "denied": False, "ip": "8.8.8.8", "captured": None}

    class Process:
        def __init__(self, _pid):
            if state["denied"]:
                raise PermissionError("offline fixture denied")

        def name(self):
            return "benign-fixture.exe"

        def create_time(self):
            return state["birth"]

    def snapshot():
        rows = ({"pid": 42, "status": "ESTABLISHED", "raddr": f"{state['ip']}:443"},) if state["present"] else ()
        captured = state["now"] if state["captured"] is None else state["captured"]
        return ConnectionList(ConnectionSnapshot(rows, captured, state["complete"], len(rows), 0,
                                                "" if state["complete"] else "offline coverage gap"))

    monkeypatch.setattr(beacon, "list_connections", snapshot)
    monkeypatch.setattr(beacon.psutil, "Process", Process)
    monkeypatch.setattr(beacon.time, "time", lambda: state["now"])
    monkeypatch.setattr(beacon, "is_ip_flagged", lambda _ip: state["intel"])
    instance, bus = beacon.BeaconDetectorModule(), EventBus()
    instance.bind(bus)
    return state, instance, bus


def test_same_socket_is_not_repeatedly_counted_as_beacon(polling):
    state, instance, bus = polling
    for index in range(6):
        state["now"] = 1000.0 + index * 60
        assert instance._poll_once().complete
    assert sum(len(rows) for rows in instance._callbacks.values()) == 1
    assert not bus.recent(10)


def test_reused_pid_same_endpoint_starts_distinct_birth_history(polling):
    state, instance, _bus = polling
    instance._poll_once()
    state.update(now=1060.0, birth=1001.0)
    instance._poll_once()
    assert len(instance._callbacks) == 2
    assert {key[1] for key in instance._callbacks} == {900.0, 1001.0}
    assert (42, 1001.0, "8.8.8.8") in instance._seen_instances


def test_repeated_incomplete_rows_never_fabricate_new_callbacks(polling):
    state, instance, bus = polling
    state["complete"] = False
    for index in range(7):
        state["now"] = 1000.0 + index * 60
        assert not instance._poll_once().complete
    assert instance._callbacks == {}
    assert instance._seen_instances == set()
    assert not bus.recent(10)
    state["complete"] = True
    assert instance._poll_once().complete
    assert instance._callbacks == {}  # recovery seeds; uncertain reappearance is not a callback
    assert instance._continuity_epoch == 1


def test_gap_retains_prior_inventory_and_separates_new_cadence_epoch(polling):
    state, instance, _bus = polling
    instance._poll_once()
    prior = set(instance._seen_instances)
    state.update(now=1060.0, complete=False, present=False)
    instance._poll_once()
    assert instance._seen_instances == prior
    state.update(now=1120.0, complete=True)
    instance._poll_once()
    state.update(now=1180.0, present=True)
    instance._poll_once()
    assert {key[4] for key in instance._callbacks} == {0, 1}
    assert all(len(rows) == 1 for rows in instance._callbacks.values())


def test_native_snapshot_older_than_new_process_birth_is_unavailable(polling):
    state, instance, bus = polling
    state.update(captured=800.0, birth=900.0)
    result = instance._poll_once()
    assert not result.complete
    assert result.identity_failures == 1
    assert not instance._callbacks and not bus.recent(10)


def test_clock_regression_holds_cadence_then_starts_new_epoch(polling):
    state, instance, _bus = polling
    instance._poll_once()
    state["now"] = 999.0
    result = instance._poll_once()
    assert not result.complete and "clock" in result.error
    state["now"] = 1001.0
    assert instance._poll_once().complete
    assert instance._continuity_epoch == 1
    assert sum(len(rows) for rows in instance._callbacks.values()) == 1


def test_normal_cadence_stays_observation_until_threat_intel_corroborates(polling):
    state, instance, bus = polling
    for index in range(6):
        state.update(now=1000.0 + index * 60, present=True, intel=index >= 4)
        instance._poll_once()
        state["present"] = False
        instance._poll_once()
    records = bus.recent(10)
    assert len(records) == 2
    advisory = next(row for row in records if row.severity == Severity.MEDIUM)
    authorized = next(row for row in records if row.severity == Severity.HIGH)
    assert "response_contract" not in advisory.details
    assert authorized.details["response_contract"]["targets"]["process_create_time"] == 900.0
    assert authorized.details["response_contract"]["targets"]["remote_ips"] == ["8.8.8.8"]
