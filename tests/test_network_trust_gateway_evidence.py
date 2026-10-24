"""Inert gateway evidence gates: no native commands or real profile state."""
from types import SimpleNamespace

import pytest

from angerona.core.network_trust import (
    COLLECTION_SOURCES,
    DefaultRouteObservation,
    NetworkLinkObservation,
    NetworkSnapshot,
    NetworkTrustBaselineStore,
    NetworkTrustEvaluator,
    evaluate_network_trust,
    load_network_purpose_keys,
)
from angerona.modules import network_trust_monitor as monitor


KEY = b"gateway-evidence-test-key-00000001"
COMPLETE = tuple(sorted(COLLECTION_SOURCES))
BOUND = "gateway-identities-interface-bound"
GATEWAY = "192.0.2.1"
OLD_MAC = "02:11:22:33:44:55"
NEW_MAC = "02:11:22:33:44:66"


def link(**changes):
    values = {
        "interface_id": "inert-ethernet",
        "kind": "ethernet",
        "interface_index": 7,
        "interface_epoch": "inert-epoch",
        "default_routes": (DefaultRouteObservation(
            GATEWAY, "ipv4", 10, selected=True, interface_index=7
        ),),
        "gateway_identities": (GATEWAY + "|" + OLD_MAC,),
        "collection_complete": COMPLETE,
    }
    values.update(changes)
    return NetworkLinkObservation(**values)


def snapshot(value, complete=COMPLETE):
    return NetworkSnapshot((value,), collection_complete=complete)


def baseline(value=None):
    return evaluate_network_trust(snapshot(value or link()), KEY).baseline


def rules(result):
    return {finding.rule_id for finding in result.findings}


def assert_unknown(result):
    assert "network.gateway_identity_drift" not in rules(result)
    coverage = [finding for finding in result.findings
                if finding.rule_id == "network.telemetry_incomplete"]
    assert coverage and all(finding.severity == "high" for finding in coverage)
    assert result.telemetry_complete is False
    assert result.paths[0].trust_label == "untrusted"
    assert result.paths[0].telemetry_quality == "incomplete"
    assert all(finding.event_details()["response_authorized"] is False
               for finding in result.findings)


def test_missing_routes_and_zero_gateway_evidence_is_coverage_not_mac_change():
    incomplete = tuple(item for item in COMPLETE
                       if item not in {"routes-ipv4", "routes-ipv6", BOUND})
    current = link(default_routes=(), gateway_identities=(),
                   collection_complete=incomplete)
    result = evaluate_network_trust(snapshot(current, incomplete), KEY, baseline())
    assert_unknown(result)
    assert "network.default_route_drift" in rules(result)


def test_two_resolved_interface_bound_samples_keep_real_mac_change_critical():
    result = evaluate_network_trust(snapshot(link(
        gateway_identities=(GATEWAY + "|" + NEW_MAC,),
    )), KEY, baseline())
    findings = [finding for finding in result.findings
                if finding.rule_id == "network.gateway_identity_drift"]
    assert len(findings) == 1 and findings[0].severity == "critical"
    assert result.telemetry_complete is True
    details = findings[0].event_details()
    assert details["response_authority"] == "observe-only"
    assert details["response_authorized"] is False
    assert GATEWAY not in repr(result) and NEW_MAC not in repr(result)


@pytest.mark.parametrize("missing", ["interfaces", "addresses", "neighbors",
                                     "routes-ipv4", "routes-ipv6"])
@pytest.mark.parametrize("level", ["link", "global"])
def test_partial_current_evidence_cannot_claim_mac_change(missing, level):
    complete = tuple(item for item in COMPLETE if item != missing)
    current = link(gateway_identities=(GATEWAY + "|" + NEW_MAC,),
                   collection_complete=complete if level == "link" else COMPLETE)
    result = evaluate_network_trust(
        snapshot(current, complete if level == "global" else COMPLETE), KEY, baseline()
    )
    assert_unknown(result)


@pytest.mark.parametrize("missing", ["neighbors", "routes-ipv4", "routes-ipv6", BOUND])
def test_partial_prior_or_legacy_context_cannot_be_inferred_from_opaque_tokens(missing):
    complete = tuple(item for item in COMPLETE if item != missing)
    previous = baseline(link(collection_complete=complete))
    evaluator = NetworkTrustEvaluator(KEY, previous)
    result = evaluator.evaluate(snapshot(link(
        gateway_identities=(GATEWAY + "|" + NEW_MAC,),
    )))
    assert_unknown(result)
    assert evaluator.baseline is previous
    coverage = next(finding for finding in result.findings
                    if finding.rule_id == "network.telemetry_incomplete")
    assert dict(coverage.evidence)["baseline_gateway_evidence_unproven"] is True


@pytest.mark.parametrize("missing", ["interfaces", "addresses", "neighbors",
                                     "routes-ipv4", "routes-ipv6"])
def test_partial_global_prior_never_serializes_bound_identity_provenance(missing):
    partial = tuple(item for item in COMPLETE if item != missing)
    previous = evaluate_network_trust(snapshot(link(), partial), KEY).baseline
    assert BOUND not in previous.paths[0].collection_complete
    result = evaluate_network_trust(snapshot(link(
        gateway_identities=(GATEWAY + "|" + NEW_MAC,),
    )), KEY, previous)
    assert_unknown(result)


def test_legacy_v2_shape_stays_parseable_without_inventing_bound_provenance():
    legacy = baseline(link(collection_complete=tuple(
        item for item in COMPLETE if item != BOUND
    )))
    serialized = NetworkTrustBaselineStore._serialize_baseline(legacy)
    restored = NetworkTrustBaselineStore._parse_baseline(serialized)
    assert restored == legacy
    result = evaluate_network_trust(snapshot(link()), KEY, restored)
    assert_unknown(result)
    assert BOUND not in restored.paths[0].collection_complete


@pytest.mark.parametrize("identity", [
    GATEWAY + "|unresolved",
    GATEWAY + "|00:00:00:00:00:00",
    GATEWAY + "|ff:ff:ff:ff:ff:ff",
    GATEWAY + "|01:11:22:33:44:55",
    GATEWAY + "|not-a-mac",
    "192.0.2.99|" + NEW_MAC,
])
def test_unusable_neighbor_identity_stays_unknown(identity):
    assert_unknown(evaluate_network_trust(
        snapshot(link(gateway_identities=(identity,))), KEY, baseline()
    ))


def test_empty_or_ambiguous_neighbor_set_stays_unknown():
    for identities in ((), (GATEWAY + "|" + OLD_MAC, GATEWAY + "|" + NEW_MAC)):
        assert_unknown(evaluate_network_trust(
            snapshot(link(gateway_identities=identities)), KEY, baseline()
        ))


@pytest.mark.parametrize("interface_index", [None, 8])
def test_unknown_or_wrong_route_interface_cannot_claim_gateway_change(interface_index):
    current = link(default_routes=(DefaultRouteObservation(
        GATEWAY, "ipv4", 10, selected=True, interface_index=interface_index
    ),), gateway_identities=(GATEWAY + "|" + NEW_MAC,))
    assert_unknown(evaluate_network_trust(snapshot(current), KEY, baseline()))


def test_zero_native_interface_index_is_unknown_even_when_route_agrees():
    current = link(interface_index=0, default_routes=(DefaultRouteObservation(
        GATEWAY, "ipv4", 10, selected=True, interface_index=0
    ),), gateway_identities=(GATEWAY + "|" + NEW_MAC,))
    assert_unknown(evaluate_network_trust(snapshot(current), KEY, baseline()))


def test_complete_route_disappearance_is_not_a_changed_mac_or_new_baseline():
    previous = baseline()
    evaluator = NetworkTrustEvaluator(KEY, previous)
    result = evaluator.evaluate(snapshot(link(default_routes=(), gateway_identities=())))
    assert_unknown(result)
    assert "network.default_route_drift" in rules(result)
    assert evaluator.baseline is previous


def test_unknown_sample_does_not_hide_a_later_real_change():
    previous = baseline()
    evaluator = NetworkTrustEvaluator(KEY, previous)
    missing = tuple(item for item in COMPLETE if item != "neighbors")
    assert_unknown(evaluator.evaluate(snapshot(link(
        gateway_identities=(GATEWAY + "|unresolved",), collection_complete=missing
    ))))
    assert evaluator.baseline is previous
    changed = evaluator.evaluate(snapshot(link(
        gateway_identities=(GATEWAY + "|" + NEW_MAC,),
    )))
    assert "network.gateway_identity_drift" in rules(changed)


def test_unrelated_dns_loss_does_not_hide_complete_bound_gateway_change():
    current = link(gateway_identities=(GATEWAY + "|" + NEW_MAC,),
                   collection_complete=tuple(item for item in COMPLETE if item != "dns"))
    result = evaluate_network_trust(snapshot(current), KEY, baseline())
    assert "network.gateway_identity_drift" in rules(result)
    assert result.telemetry_complete is False


def test_new_adapter_is_path_addition_not_a_mac_change_on_the_old_adapter():
    current = link(interface_id="second-inert-adapter", interface_index=8,
                   default_routes=(DefaultRouteObservation(
                       GATEWAY, "ipv4", 10, selected=True, interface_index=8
                   ),), gateway_identities=(GATEWAY + "|" + NEW_MAC,))
    result = evaluate_network_trust(snapshot(current), KEY, baseline())
    assert "network.path_added" in rules(result)
    assert "network.gateway_identity_drift" not in rules(result)


def test_same_name_replacement_adapter_cannot_reuse_old_gateway_identity_context():
    previous = baseline()
    evaluator = NetworkTrustEvaluator(KEY, previous)
    current = link(interface_index=8, default_routes=(DefaultRouteObservation(
        GATEWAY, "ipv4", 10, selected=True, interface_index=8
    ),), gateway_identities=(GATEWAY + "|" + NEW_MAC,))
    result = evaluator.evaluate(snapshot(current))
    assert_unknown(result)
    assert "network.default_route_drift" in rules(result)
    assert evaluator.baseline is previous


def test_new_gateway_route_is_not_a_mac_change_on_the_previous_gateway():
    previous = baseline()
    evaluator = NetworkTrustEvaluator(KEY, previous)
    gateway = "198.51.100.1"
    current = link(default_routes=(DefaultRouteObservation(
        gateway, "ipv4", 10, selected=True, interface_index=7
    ),), gateway_identities=(gateway + "|" + NEW_MAC,))
    result = evaluator.evaluate(snapshot(current))
    assert_unknown(result)
    assert "network.default_route_drift" in rules(result)
    assert evaluator.baseline is previous


def parse_neighbors(monkeypatch, text, complete=True, system="Windows"):
    monkeypatch.setattr(monitor, "os", SimpleNamespace(name="nt" if system == "Windows" else "posix"))
    monkeypatch.setattr(monitor.platform, "system", lambda: system)
    monkeypatch.setattr(monitor, "_run_observation_command_result", lambda _args:
                        monitor._CommandObservation(text, complete, "ok" if complete else "unavailable"))
    return monitor._neighbor_identities()


def test_windows_neighbor_parser_keeps_same_ip_on_two_interfaces_separate(monkeypatch):
    rows, complete = parse_neighbors(monkeypatch, "\n".join([
        "Interface: 192.0.2.10 --- 0x7",
        "  192.0.2.1  02-11-22-33-44-55 dynamic",
        "Interface: 192.0.2.20 --- 0x8",
        "  192.0.2.1  02-11-22-33-44-66 dynamic",
    ]))
    assert complete is True
    assert rows == {(7, GATEWAY): OLD_MAC, (8, GATEWAY): NEW_MAC}


@pytest.mark.parametrize("header", ["", "Interface: 192.0.2.20 --- invalid",
                                    "Interface: not-an-ip --- 0x8"])
def test_unscoped_or_malformed_header_cannot_reuse_previous_interface(monkeypatch, header):
    text = "\n".join([
        "Interface: 192.0.2.10 --- 0x7",
        "  192.0.2.1  02-11-22-33-44-55 dynamic",
        header,
        "  192.0.2.2  02-11-22-33-44-66 dynamic",
    ]) if header else "  192.0.2.2  02-11-22-33-44-66 dynamic"
    rows, complete = parse_neighbors(monkeypatch, text)
    assert complete is False
    assert (7, "192.0.2.2") not in rows


def test_conflicting_identity_on_one_interface_is_ambiguous_not_last_writer_wins(monkeypatch):
    rows, complete = parse_neighbors(monkeypatch, "\n".join([
        "Interface: 192.0.2.10 --- 0x7",
        "  192.0.2.1  02-11-22-33-44-55 dynamic",
        "  192.0.2.1  02-11-22-33-44-66 dynamic",
        "  192.0.2.1  02-11-22-33-44-55 dynamic",
    ]))
    assert complete is False
    assert (7, GATEWAY) not in rows


def test_unreadable_neighbor_provider_is_explicitly_incomplete(monkeypatch):
    rows, complete = parse_neighbors(monkeypatch, "", complete=False)
    assert rows == {} and complete is False


@pytest.mark.parametrize("system,text", [
    ("Linux", "192.0.2.1 dev eth7 lladdr 02:11:22:33:44:55 FAILED"),
    ("Linux", "192.0.2.1 dev eth7 lladdr 02:11:22:33:44:55 INCOMPLETE"),
    ("Windows", "Interface: 192.0.2.10 --- 0x7\n  192.0.2.1 02-11-22-33-44-55 invalid"),
    ("Windows", "Interface: 192.0.2.10 --- 0x0\n  192.0.2.1 02-11-22-33-44-55 dynamic"),
])
def test_failed_neighbor_state_or_zero_index_cannot_establish_resolved_mapping(monkeypatch, system, text):
    monkeypatch.setattr(monitor.socket, "if_nametoindex", lambda _name: 7)
    rows, complete = parse_neighbors(monkeypatch, text, system=system)
    assert rows == {} and complete is False


@pytest.mark.parametrize("system,text", [
    ("Linux", "\n".join([
        "192.0.2.1 dev eth7 lladdr 02:11:22:33:44:55 REACHABLE",
        "192.0.2.1 dev eth7 FAILED",
        "192.0.2.1 dev eth7 lladdr 02:11:22:33:44:55 REACHABLE",
    ])),
    ("Linux", "\n".join([
        "192.0.2.1 dev eth7 lladdr 02:11:22:33:44:55 REACHABLE",
        "192.0.2.1 dev eth7 INCOMPLETE",
        "192.0.2.1 dev eth7 lladdr 02:11:22:33:44:55 REACHABLE",
    ])),
    ("Windows", "\n".join([
        "Interface: 192.0.2.10 --- 0x7",
        "  192.0.2.1 02-11-22-33-44-55 dynamic",
        "  192.0.2.1 (incomplete) invalid",
        "  192.0.2.1 02-11-22-33-44-55 dynamic",
    ])),
    ("Darwin", "\n".join([
        "? (192.0.2.1) at 02:11:22:33:44:55 on eth7 ifscope [ethernet]",
        "? (192.0.2.1) at (incomplete) on eth7 ifscope [ethernet]",
        "? (192.0.2.1) at 02:11:22:33:44:55 on eth7 ifscope [ethernet]",
    ])),
])
def test_failed_row_without_mac_invalidates_earlier_mapping_and_cannot_restore_it(monkeypatch, system, text):
    monkeypatch.setattr(monitor.socket, "if_nametoindex", lambda _name: 7)
    rows, complete = parse_neighbors(monkeypatch, text, system=system)
    assert (7, GATEWAY) not in rows and complete is False


@pytest.mark.parametrize("system,text", [
    ("Linux", "192.0.2.1 dev eth7 lladdr 02:11:22:33:44:55 REACHABLE"),
    ("Darwin", "? (192.0.2.1) at 02:11:22:33:44:55 on eth7 ifscope [ethernet]"),
])
def test_posix_neighbor_rows_keep_their_interface_index(monkeypatch, system, text):
    monkeypatch.setattr(monitor.socket, "if_nametoindex", lambda name: {"eth7": 7}[name])
    rows, complete = parse_neighbors(monkeypatch, text, system=system)
    assert complete is True and rows == {(7, GATEWAY): OLD_MAC}


def observed_link(monkeypatch, neighbors, neighbor_complete=True):
    addresses = {"inert-ethernet": (SimpleNamespace(
        family=monitor.socket.AF_INET, address="192.0.2.10"
    ),)}
    monkeypatch.setattr(monitor.psutil, "net_if_addrs", lambda: addresses)
    monkeypatch.setattr(monitor.psutil, "net_if_stats", lambda: {
        "inert-ethernet": SimpleNamespace(isup=True)
    })
    monkeypatch.setattr(monitor.psutil, "boot_time", lambda: 1.0)
    monkeypatch.setattr(monitor, "classify_interfaces", lambda: {"inert-ethernet": "Physical"})
    monkeypatch.setattr(monitor, "_windows_wlan", lambda: ({}, True))
    monkeypatch.setattr(monitor, "_windows_profiles", lambda: ({}, True))
    monkeypatch.setattr(monitor, "_windows_interface_settings", lambda: ({}, True))
    monkeypatch.setattr(monitor, "_system_dns_servers", lambda: ((), True))
    monkeypatch.setattr(monitor, "_windows_dhcp_servers", lambda: ((), True))
    monkeypatch.setattr(monitor, "_default_routes", lambda _local: (
        {"inert-ethernet": list(link().default_routes)}, frozenset({"ipv4", "ipv6"})
    ))
    monkeypatch.setattr(monitor, "_neighbor_identities", lambda: (neighbors, neighbor_complete))
    monkeypatch.setattr(monitor.socket, "if_nametoindex", lambda _name: 7)
    return monitor.observe_system_network()


def test_observer_cannot_borrow_neighbor_identity_from_another_adapter(monkeypatch):
    current = observed_link(monkeypatch, {(8, GATEWAY): NEW_MAC})
    assert current.links[0].gateway_identities == (GATEWAY + "|unresolved",)
    assert BOUND not in current.links[0].collection_complete
    assert_unknown(evaluate_network_trust(current, KEY, baseline()))


def test_observer_admits_marker_only_for_complete_same_interface_mapping(monkeypatch):
    current = observed_link(monkeypatch, {(7, GATEWAY): NEW_MAC})
    assert current.links[0].gateway_identities == (GATEWAY + "|" + NEW_MAC,)
    assert BOUND in current.links[0].collection_complete
    assert "network.gateway_identity_drift" in rules(
        evaluate_network_trust(current, KEY, baseline())
    )


def test_monitor_does_not_rewrite_legacy_baseline_or_enrollment(tmp_path):
    privacy, baseline_key, enrollment_key = load_network_purpose_keys(
        tmp_path, master_key=KEY[:32]
    )
    del privacy
    baseline_path = tmp_path / "sensor-baselines" / "network-trust.json"
    epoch_path = tmp_path / "continuity-epochs" / "network-trust.json"
    store = NetworkTrustBaselineStore(baseline_path, baseline_key=baseline_key,
                                     enrollment_key=enrollment_key, enrollment_path=epoch_path)
    assert store.load() == (None, "missing")
    legacy = baseline(link(collection_complete=tuple(item for item in COMPLETE if item != BOUND)))
    assert store.save(legacy, trusted=True)
    before = (baseline_path.read_bytes(), epoch_path.read_bytes())
    module = monitor.NetworkTrustMonitorModule(
        privacy_key=KEY, data_root=tmp_path,
        observer=lambda: snapshot(link(gateway_identities=(GATEWAY + "|" + NEW_MAC,))),
        gateway_loader=lambda: None,
    )
    module._tick()
    assert (baseline_path.read_bytes(), epoch_path.read_bytes()) == before
    assert module.health == 40
    assert module._evaluator.baseline == legacy
