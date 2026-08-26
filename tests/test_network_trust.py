import hashlib
import hmac
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.platforms import declared_platforms_from_source
from angerona.core.eventbus import EventBus
from angerona.core.network_trust import (
    COLLECTION_SOURCES,
    DefaultRouteObservation,
    MAX_LINKS,
    NetworkLinkObservation,
    NetworkSnapshot,
    NetworkTrustBaseline,
    NetworkTrustEvaluator,
    evaluate_network_trust,
    self_test,
)
from angerona.core.personal_sentinel_gateway import (
    GatewayEnrollment,
    GatewayMonitorBinding,
    GatewayTransportResponse,
)
from angerona.modules.network_trust_monitor import NetworkTrustMonitorModule
import angerona.modules.network_trust_monitor as network_trust_monitor


KEY = b"network-trust-test-privacy-key-01"
COMPLETE = tuple(sorted(COLLECTION_SOURCES))


def test_network_monitor_ast_preflight_admits_linux_and_macos(
    tmp_path: Path,
) -> None:
    source = Path(network_trust_monitor.__file__)
    declared = declared_platforms_from_source(source)

    assert {"linux", "macos"}.issubset(declared)
    assert set(NetworkTrustMonitorModule.supported_platforms) == declared

    legacy = tmp_path / "legacy_undeclared_module.py"
    legacy.write_text("VALUE = 1\n", encoding="utf-8")
    assert declared_platforms_from_source(legacy) == frozenset({"windows"})


def _link(**overrides):
    values = {
        "interface_id": "Wi-Fi raw adapter name",
        "kind": "wifi",
        "interface_index": 7,
        "active": True,
        "loopback": False,
        "interface_epoch": "epoch-one",
        "ssid": "Sensitive Home SSID",
        "bssid": "00:11:22:33:44:55",
        "wifi_security": "WPA3-SAE CCMP",
        "dns_servers": ("192.168.10.2",),
        "dhcp_server": "192.168.10.1",
        "default_routes": (
            DefaultRouteObservation(
                "192.168.10.1", "ipv4", 10, selected=True, interface_index=7
            ),
        ),
        "gateway_identities": ("192.168.10.1|aa:bb:cc:dd:ee:ff",),
        "profile_category": "private",
        "gateway_attestation": "untrusted",
        "collection_complete": COMPLETE,
    }
    values.update(overrides)
    return NetworkLinkObservation(**values)


def _snapshot(*links):
    return NetworkSnapshot(tuple(links), collection_complete=COMPLETE)


def test_every_active_physical_path_is_untrusted_despite_private_profile_or_ssid():
    result = evaluate_network_trust(_snapshot(_link()), KEY)
    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.trust_label == "untrusted"
    assert path.endpoint_resources_trusted is False
    assert path.response_authorized is False
    assert "network.profile_trust_mismatch" in {
        finding.rule_id for finding in result.findings
    }


def test_gateway_attestation_labels_path_but_never_trusts_endpoint_resources():
    result = evaluate_network_trust(_snapshot(_link(
        gateway_attestation="gateway-attested",
        default_routes=(DefaultRouteObservation(
            "192.168.10.1", "ipv4", 10, selected=True, attested=True,
            interface_index=7,
        ),),
    )), KEY)
    path = result.paths[0]
    assert path.trust_label == "gateway-attested"
    assert path.endpoint_resources_trusted is False
    assert path.event_details()["zero_trust_default"] is True
    assert "network.profile_trust_mismatch" not in {
        finding.rule_id for finding in result.findings
    }


def test_loopback_inactive_and_nonphysical_links_do_not_gain_path_status():
    snapshot = _snapshot(
        _link(interface_id="loop", loopback=True),
        _link(interface_id="down", active=False),
        _link(interface_id="vpn", kind="other"),
    )
    result = evaluate_network_trust(snapshot, KEY)
    assert result.paths == ()
    assert result.findings == ()


def test_dns_dhcp_route_gateway_profile_and_epoch_drift_are_detected():
    evaluator = NetworkTrustEvaluator(KEY)
    evaluator.evaluate(_snapshot(_link()))
    changed = _link(
        interface_epoch="epoch-two",
        dns_servers=("10.20.30.40",),
        dhcp_server="10.20.30.1",
        default_routes=(DefaultRouteObservation(
            "10.20.30.1", "ipv4", 1, selected=True
        ),),
        gateway_identities=("10.20.30.1|ff:ee:dd:cc:bb:aa",),
        profile_category="public",
    )
    result = evaluator.evaluate(_snapshot(changed))
    rules = {finding.rule_id for finding in result.findings}
    assert {
        "network.interface_epoch_changed",
        "network.dns_drift",
        "network.dhcp_drift",
        "network.default_route_drift",
        "network.gateway_identity_drift",
        "network.profile_category_drift",
    }.issubset(rules)


def test_disconnect_does_not_erase_tokenized_epoch_before_reconnection():
    evaluator = NetworkTrustEvaluator(KEY)
    evaluator.evaluate(_snapshot(_link(interface_epoch="epoch-one")))
    evaluator.evaluate(_snapshot())
    result = evaluator.evaluate(_snapshot(_link(interface_epoch="epoch-two")))
    assert "network.interface_epoch_changed" in {
        finding.rule_id for finding in result.findings
    }
    assert "network.path_added" not in {
        finding.rule_id for finding in result.findings
    }


def test_new_physical_path_is_explicit_bounded_interface_set_drift():
    original = _link()
    initial = evaluate_network_trust(_snapshot(original), KEY)
    added = _link(
        interface_id="Ethernet newly observed raw name",
        interface_index=8,
        kind="ethernet",
        ssid="",
        bssid="",
        wifi_security="unknown",
        default_routes=(),
        profile_category="public",
    )

    result = evaluate_network_trust(_snapshot(original, added), KEY, initial.baseline)
    additions = [
        finding for finding in result.findings
        if finding.rule_id == "network.path_added"
    ]

    assert len(additions) == 1
    assert dict(additions[0].evidence) == {
        "current_path_count": 2,
        "interface_set_changed": True,
        "new_path_count": 1,
        "previous_path_count": 1,
    }
    assert additions[0].response_authorized is False
    assert "Ethernet newly observed raw name" not in repr(additions[0])
    stable = evaluate_network_trust(_snapshot(original), KEY, initial.baseline)
    assert "network.path_added" not in {
        finding.rule_id for finding in stable.findings
    }
    empty_enrollment = evaluate_network_trust(
        _snapshot(added), KEY, NetworkTrustBaseline()
    )
    assert "network.path_added" in {
        finding.rule_id for finding in empty_enrollment.findings
    }


def test_multiple_and_concurrent_default_routes_are_flagged_by_family():
    first = _link(default_routes=(
        DefaultRouteObservation("192.168.10.1", "ipv4", 10),
        DefaultRouteObservation("192.168.10.254", "ipv4", 20),
    ))
    second = _link(
        interface_id="Ethernet raw adapter name",
        kind="ethernet",
        ssid="",
        bssid="",
        wifi_security="unknown",
        profile_category="public",
        default_routes=(DefaultRouteObservation("10.0.0.1", "ipv4", 30),),
    )
    result = evaluate_network_trust(_snapshot(first, second), KEY)
    rules = [finding.rule_id for finding in result.findings]
    assert "network.multiple_default_routes" in rules
    assert rules.count("network.concurrent_default_paths") == 2


@pytest.mark.parametrize(
    ("security", "expected"),
    [
        ("Open", "network.wifi_security_weak"),
        ("WEP", "network.wifi_security_weak"),
        ("WPA-Personal TKIP", "network.wifi_security_weak"),
        ("unknown", "network.wifi_security_unknown"),
        ("vendor-undocumented-mode", "network.wifi_security_unknown"),
    ],
)
def test_weak_and_unknown_wifi_security_fail_toward_a_finding(security, expected):
    result = evaluate_network_trust(_snapshot(
        _link(wifi_security=security, profile_category="public"),
    ), KEY)
    assert expected in {finding.rule_id for finding in result.findings}


def test_results_baseline_and_event_details_never_retain_raw_identifiers():
    raw_values = (
        "Wi-Fi raw adapter name",
        "Sensitive Home SSID",
        "00:11:22:33:44:55",
        "192.168.10.1",
        "192.168.10.2",
        "aa:bb:cc:dd:ee:ff",
    )
    result = evaluate_network_trust(_snapshot(_link()), KEY)
    representation = repr(result)
    details = repr([
        *(path.event_details() for path in result.paths),
        *(finding.event_details() for finding in result.findings),
    ])
    assert all(value not in representation for value in raw_values)
    assert all(value not in details for value in raw_values)
    assert all(path.path_token.startswith("tok_") for path in result.paths)
    assert all(
        finding.event_details()["response_authorized"] is False
        for finding in result.findings
    )


def test_evaluator_and_observations_enforce_strict_bounds():
    with pytest.raises(ValueError):
        evaluate_network_trust(_snapshot(_link()), b"short")
    with pytest.raises(ValueError):
        NetworkLinkObservation("x" * 513, "ethernet")
    with pytest.raises(ValueError):
        NetworkLinkObservation("eth", "ethernet", dns_servers=tuple(
            f"10.0.0.{index}" for index in range(33)
        ))
    with pytest.raises(ValueError):
        NetworkSnapshot(tuple(
            NetworkLinkObservation(f"eth-{index}", "ethernet")
            for index in range(MAX_LINKS + 1)
        ))
    with pytest.raises(ValueError):
        NetworkSnapshot((
            NetworkLinkObservation("duplicate", "ethernet"),
            NetworkLinkObservation("duplicate", "ethernet"),
        ))


def test_monitor_eventbus_output_is_tokenized_and_observe_only():
    raw = _link(wifi_security="open")
    module = NetworkTrustMonitorModule(privacy_key=KEY)
    bus = EventBus()
    module.bind(bus)
    result = evaluate_network_trust(_snapshot(raw), KEY)
    module._publish_evaluation(result)
    events = bus.recent(20)
    assert events
    representation = repr(events)
    assert "Sensitive Home SSID" not in representation
    assert "00:11:22:33:44:55" not in representation
    assert "192.168.10.1" not in representation
    assert all(event.details.get("response_authorized") is False for event in events)
    assert all(event.details.get("response_authority") == "observe-only" for event in events)


class _GatewayTransport:
    certificate = b"network-trust-integration-certificate"

    def __init__(self, *, fail=False):
        self.fail = fail
        self.requests = []

    def send(self, request):
        self.requests.append(request)
        if self.fail:
            raise RuntimeError("private raw endpoint failure")
        sent = json.loads(request.body.decode("utf-8"))
        now = float(sent["issued_at"])
        body = json.dumps({
            "schema_version": 1,
            "nonce": sent["nonce"],
            "attested_at": now - 0.1,
            "expires_at": now + 20,
            "policy_digest": sent["policy_digest"],
            "path_status": "gateway-attested",
        }, separators=(",", ":")).encode("utf-8")
        return GatewayTransportResponse(
            200,
            {"content-type": "application/json"},
            body,
            self.certificate,
            "192.168.10.1",
            True,
        )


def _gateway_binding(endpoint="https://192.168.10.1:9443/v1/attest"):
    transport_pin = hashlib.sha256(_GatewayTransport.certificate).hexdigest()
    return GatewayMonitorBinding(
        "Wi-Fi raw adapter name",
        GatewayEnrollment(
            endpoint,
            transport_pin,
            hashlib.sha256(b"policy").hexdigest(),
        ),
    )


def test_monitor_invokes_explicit_gateway_enrollment_and_feeds_verified_path_label():
    transport = _GatewayTransport()
    snapshot = _snapshot(_link())
    module = NetworkTrustMonitorModule(
        observer=lambda: snapshot,
        privacy_key=KEY,
        gateway_loader=lambda: _gateway_binding(),
        gateway_transport=transport,
    )
    bus = EventBus()
    module.bind(bus)
    attested_snapshot = module._apply_gateway_attestation(snapshot)
    assert len(transport.requests) == 1
    assert attested_snapshot.links[0].gateway_attestation == "gateway-attested"
    result = module._evaluator.evaluate(attested_snapshot)
    module._publish_evaluation(result)
    assert result.paths[0].trust_label == "gateway-attested"
    assert result.paths[0].endpoint_resources_trusted is False
    events = bus.recent(20)
    assert any(event.details.get("attestation_success") is True for event in events)
    assert "192.168.10.1" not in repr(events)
    assert all(event.details.get("response_authorized") is False for event in events)


def test_gateway_absence_unreachable_or_wrong_path_all_remain_untrusted():
    snapshot = _snapshot(_link())
    absent = NetworkTrustMonitorModule(
        privacy_key=KEY,
        gateway_loader=lambda: None,
        gateway_transport=_GatewayTransport(),
    )
    assert absent._apply_gateway_attestation(snapshot).links[0].gateway_attestation == "untrusted"

    unreachable_transport = _GatewayTransport(fail=True)
    unreachable = NetworkTrustMonitorModule(
        privacy_key=KEY,
        gateway_loader=lambda: _gateway_binding(),
        gateway_transport=unreachable_transport,
    )
    unreachable_bus = EventBus()
    unreachable.bind(unreachable_bus)
    failed = unreachable._apply_gateway_attestation(snapshot)
    assert failed.links[0].gateway_attestation == "untrusted"
    assert unreachable_transport.requests
    assert unreachable_bus.recent(1)[0].details["reason_code"] == "transport-failed"

    wrong_path_transport = _GatewayTransport()
    wrong_path = NetworkTrustMonitorModule(
        privacy_key=KEY,
        gateway_loader=lambda: _gateway_binding("https://192.168.10.254/v1/attest"),
        gateway_transport=wrong_path_transport,
    )
    wrong_bus = EventBus()
    wrong_path.bind(wrong_bus)
    rejected = wrong_path._apply_gateway_attestation(snapshot)
    assert rejected.links[0].gateway_attestation == "untrusted"
    assert wrong_path_transport.requests == []
    assert wrong_bus.recent(1)[0].details["reason_code"] == "path-binding-rejected"


def test_monitor_rejects_collector_asserted_attestation_without_enrollment():
    forged = _snapshot(_link(gateway_attestation="gateway-attested"))
    module = NetworkTrustMonitorModule(
        privacy_key=KEY,
        gateway_loader=lambda: None,
        gateway_transport=_GatewayTransport(),
    )
    result = module._apply_gateway_attestation(forged)
    assert result.links[0].gateway_attestation == "untrusted"


def test_restart_uses_authenticated_baseline_and_detects_offline_dns_drift(tmp_path):
    (tmp_path / "bus.key").write_text((b"m" * 32).hex(), encoding="ascii")
    first_snapshot = _snapshot(_link())
    first = NetworkTrustMonitorModule(
        observer=lambda: first_snapshot,
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    first.bind(EventBus())
    first._tick()
    assert first._baseline_state == "provisional"

    changed = _snapshot(_link(dns_servers=("10.20.30.40",)))
    second_bus = EventBus()
    second = NetworkTrustMonitorModule(
        observer=lambda: changed,
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    second.bind(second_bus)
    second._tick()
    assert second._baseline_state == "provisional"
    assert any(
        event.details.get("finding_type") == "network.dns_drift"
        for event in second_bus.recent(30)
    )
    assert second.health < 100


def test_added_path_is_authenticated_provisional_before_restart_drift(tmp_path):
    (tmp_path / "bus.key").write_text((b"p" * 32).hex(), encoding="ascii")
    original = _link()
    added = _link(
        interface_id="Ethernet newly observed raw name",
        interface_index=8,
        kind="ethernet",
        ssid="",
        bssid="",
        wifi_security="unknown",
        default_routes=(),
        profile_category="public",
    )
    current = {"snapshot": _snapshot(original)}
    bus = EventBus()
    module = NetworkTrustMonitorModule(
        observer=lambda: current["snapshot"],
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    module.bind(bus)
    module._tick()
    module._tick()
    cursor_path = tmp_path / "sensor-baselines" / "network-trust.json"
    enrolled = json.loads(cursor_path.read_text(encoding="utf-8"))
    assert enrolled["revision"] == 2
    assert enrolled["trusted"] is True
    assert len(enrolled["paths"]) == 1

    current["snapshot"] = _snapshot(original, added)
    module._tick()
    provisional = json.loads(cursor_path.read_text(encoding="utf-8"))
    assert module._baseline_state == "provisional"
    assert provisional["revision"] == 3
    assert provisional["trusted"] is False
    assert len(provisional["paths"]) == 2
    assert len(provisional["pending_path_tokens"]) == 1
    assert any(
        event.details.get("finding_type") == "network.path_added"
        for event in bus.recent(50)
    )

    changed_added = _link(
        interface_id="Ethernet newly observed raw name",
        interface_index=8,
        kind="ethernet",
        ssid="",
        bssid="",
        wifi_security="unknown",
        dns_servers=("203.0.113.53",),
        default_routes=(),
        profile_category="public",
    )
    restarted_bus = EventBus()
    restarted = NetworkTrustMonitorModule(
        observer=lambda: _snapshot(original, changed_added),
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    restarted.bind(restarted_bus)
    restarted._tick()

    unchanged = json.loads(cursor_path.read_text(encoding="utf-8"))
    assert restarted._baseline_state == "provisional"
    assert unchanged["revision"] == 3
    assert any(
        event.details.get("finding_type") == "network.dns_drift"
        for event in restarted_bus.recent(50)
    )


def test_added_path_requires_stable_restart_sample_then_stops_rewriting(tmp_path):
    (tmp_path / "bus.key").write_text((b"q" * 32).hex(), encoding="ascii")
    original = _link()
    added = _link(
        interface_id="Ethernet stable raw name",
        interface_index=8,
        kind="ethernet",
        ssid="",
        bssid="",
        wifi_security="unknown",
        default_routes=(),
        profile_category="public",
    )
    current = {"snapshot": _snapshot(original)}
    module = NetworkTrustMonitorModule(
        observer=lambda: current["snapshot"],
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    module.bind(EventBus())
    module._tick()
    module._tick()
    current["snapshot"] = _snapshot(original, added)
    module._tick()

    cursor_path = tmp_path / "sensor-baselines" / "network-trust.json"
    assert json.loads(cursor_path.read_text(encoding="utf-8"))["revision"] == 3
    stable_bus = EventBus()
    confirmation = {"snapshot": _snapshot(original)}
    stable = NetworkTrustMonitorModule(
        observer=lambda: confirmation["snapshot"],
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    stable.bind(stable_bus)
    stable._tick()
    absent = json.loads(cursor_path.read_text(encoding="utf-8"))
    assert stable._baseline_state == "provisional"
    assert absent["revision"] == 3
    assert stable.health == 40

    confirmation["snapshot"] = _snapshot(original, added)
    stable._tick()
    promoted = json.loads(cursor_path.read_text(encoding="utf-8"))
    assert stable._baseline_state == "trusted"
    assert promoted["revision"] == 4
    assert promoted["trusted"] is True
    assert promoted["pending_path_tokens"] == []
    assert not any(
        event.details.get("finding_type") == "network.path_added"
        for event in stable_bus.recent(50)
    )

    stable._tick()
    unchanged = json.loads(cursor_path.read_text(encoding="utf-8"))
    assert unchanged["revision"] == 4
    assert stable._persisted_baseline is not None
    assert len(stable._persisted_baseline.paths) == 2


def test_legacy_provisional_paths_require_active_migration_confirmation(tmp_path):
    (tmp_path / "bus.key").write_text((b"s" * 32).hex(), encoding="ascii")
    module = NetworkTrustMonitorModule(
        observer=lambda: _snapshot(_link()),
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    module.bind(EventBus())
    module._tick()
    store = module._baseline_store
    assert store is not None
    cursor = json.loads(store.path.read_text(encoding="utf-8"))
    cursor["schema"] = 1
    cursor.pop("pending_path_tokens")
    cursor["hmac_sha256"] = hmac.new(
        store._baseline_key,
        store._signed_body(cursor),
        hashlib.sha256,
    ).hexdigest()
    store.path.write_bytes(store._canonical(cursor))

    restarted = NetworkTrustMonitorModule(
        observer=lambda: _snapshot(),
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    assert restarted._persisted_baseline is not None
    assert len(restarted._persisted_baseline.pending_path_tokens) == 1
    restarted.bind(EventBus())
    restarted._tick()

    unchanged = json.loads(store.path.read_text(encoding="utf-8"))
    assert restarted._baseline_state == "provisional"
    assert restarted.health == 40
    assert unchanged["schema"] == 1
    assert unchanged["revision"] == 1


def test_added_path_cannot_evict_authenticated_history_at_link_bound(tmp_path):
    (tmp_path / "bus.key").write_text((b"r" * 32).hex(), encoding="ascii")

    def ethernet(index):
        return _link(
            interface_id=f"Ethernet bounded raw name {index}",
            interface_index=index + 1,
            kind="ethernet",
            ssid="",
            bssid="",
            wifi_security="unknown",
            default_routes=(),
            profile_category="public",
        )

    enrolled_links = tuple(ethernet(index) for index in range(MAX_LINKS))
    current = {"snapshot": _snapshot(*enrolled_links)}
    bus = EventBus()
    module = NetworkTrustMonitorModule(
        observer=lambda: current["snapshot"],
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    module.bind(bus)
    module._tick()
    module._tick()
    cursor_path = tmp_path / "sensor-baselines" / "network-trust.json"
    before = json.loads(cursor_path.read_text(encoding="utf-8"))
    assert before["revision"] == 2
    assert len(before["paths"]) == MAX_LINKS

    replacement = ethernet(MAX_LINKS)
    current["snapshot"] = _snapshot(*enrolled_links[1:], replacement)
    module._tick()

    after = json.loads(cursor_path.read_text(encoding="utf-8"))
    assert after == before
    assert module._baseline_state == "trusted"
    assert module.health == 30
    assert any(
        event.details.get("finding_type") == "network.path_added"
        for event in bus.recent(200)
    )


def test_missing_after_enrollment_and_incomplete_first_sample_fail_closed(tmp_path):
    (tmp_path / "bus.key").write_text((b"n" * 32).hex(), encoding="ascii")
    incomplete = NetworkSnapshot((
        _link(collection_complete=()),
    ), collection_complete=())
    module = NetworkTrustMonitorModule(
        observer=lambda: incomplete,
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    module.bind(EventBus())
    module._tick()
    assert module.health < 100
    assert not (tmp_path / "sensor-baselines" / "network-trust.json").exists()

    complete = NetworkTrustMonitorModule(
        observer=lambda: _snapshot(_link()),
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    complete.bind(EventBus())
    complete._tick()
    baseline_path = tmp_path / "sensor-baselines" / "network-trust.json"
    assert baseline_path.exists()
    baseline_path.unlink()
    restarted = NetworkTrustMonitorModule(
        observer=lambda: _snapshot(_link()),
        data_root=tmp_path,
        gateway_loader=lambda: None,
    )
    assert restarted._baseline_state == "untrusted"


def test_gateway_attestation_rejects_lower_metric_and_ipv6_bypass_paths():
    transport = _GatewayTransport()
    competing = _snapshot(_link(default_routes=(
        DefaultRouteObservation("192.168.10.1", "ipv4", 50, interface_index=7),
        DefaultRouteObservation(
            "192.168.10.254", "ipv4", 5, selected=True, interface_index=7
        ),
    )))
    module = NetworkTrustMonitorModule(
        observer=lambda: competing,
        privacy_key=KEY,
        gateway_loader=lambda: _gateway_binding(),
        gateway_transport=transport,
    )
    module.bind(EventBus())
    assert module._apply_gateway_attestation(competing).links[0].gateway_attestation == "untrusted"
    assert transport.requests == []

    standby_bypass = _snapshot(_link(default_routes=(
        DefaultRouteObservation(
            "192.168.10.1", "ipv4", 5, selected=True, interface_index=7
        ),
        DefaultRouteObservation("192.168.10.254", "ipv4", 50, interface_index=7),
    )))
    assert module._apply_gateway_attestation(standby_bypass).links[0].gateway_attestation == "untrusted"
    assert transport.requests == []

    dual_stack = _snapshot(_link(default_routes=(
        DefaultRouteObservation(
            "192.168.10.1", "ipv4", 5, selected=True, interface_index=7
        ),
        DefaultRouteObservation(
            "fd00::1", "ipv6", 5, selected=True, interface_index=7
        ),
    )))
    assert module._apply_gateway_attestation(dual_stack).links[0].gateway_attestation == "untrusted"
    assert transport.requests == []


def test_gateway_attestation_rechecks_route_context_after_exchange():
    initial = _snapshot(_link())
    changed = _snapshot(_link(default_routes=(
        DefaultRouteObservation(
            "192.168.10.1", "ipv4", 9, selected=True, interface_index=7
        ),
    )))
    transport = _GatewayTransport()
    module = NetworkTrustMonitorModule(
        observer=lambda: changed,
        privacy_key=KEY,
        gateway_loader=lambda: _gateway_binding(),
        gateway_transport=transport,
    )
    bus = EventBus()
    module.bind(bus)
    result = module._apply_gateway_attestation(initial)
    assert len(transport.requests) == 1
    assert result.links[0].gateway_attestation == "untrusted"
    assert bus.recent(1)[0].details["reason_code"] == "route-context-changed"


def test_inventory_child_output_is_stopped_at_the_in_flight_cap():
    result = network_trust_monitor._run_observation_command_result([
        sys.executable,
        "-c",
        f"import sys;sys.stdout.write('x'*{network_trust_monitor.MAX_COMMAND_OUTPUT + 4096})",
    ])
    assert result.complete is False
    assert result.reason == "output-limit"
    assert result.text == ""


def test_windows_route_rejections_are_accounted_per_address_family():
    rows = [
        {
            "InterfaceAlias": "Ethernet",
            "InterfaceIndex": 7,
            "AddressFamily": "IPv4",
            "NextHop": "192.0.2.1",
            "RouteMetric": 5,
            "InterfaceMetric": 10,
        },
        {
            "InterfaceAlias": "",
            "InterfaceIndex": 7,
            "AddressFamily": "IPv6",
            "NextHop": "2001:db8::1",
            "RouteMetric": 5,
            "InterfaceMetric": 10,
        },
    ]
    routes, complete = network_trust_monitor._parse_windows_default_routes(
        json.dumps(rows)
    )

    assert set(complete) == {"ipv4"}
    assert len(routes["Ethernet"]) == 1
    assert routes["Ethernet"][0].family == "ipv4"


def test_route_row_caps_are_detected_before_candidates_are_sliced(monkeypatch):
    windows_rows = [
        {
            "InterfaceAlias": "Ethernet",
            "InterfaceIndex": 7,
            "AddressFamily": "IPv4",
            "NextHop": f"192.0.2.{index + 1}",
            "RouteMetric": index,
            "InterfaceMetric": 1,
        }
        for index in range(17)
    ]
    windows_routes, windows_complete = (
        network_trust_monitor._parse_windows_default_routes(json.dumps(windows_rows))
    )
    assert len(windows_routes["Ethernet"]) == 16
    assert "ipv4" not in windows_complete

    monkeypatch.setattr(
        network_trust_monitor.socket,
        "if_nametoindex",
        lambda name: int(name.removeprefix("eth")) + 1,
    )
    linux_text = "\n".join(
        f"default via 192.0.2.1 dev eth{index} metric {index}"
        for index in range(network_trust_monitor.MAX_ROUTE_ROWS_PER_FAMILY + 1)
    )
    linux_routes, linux_complete = (
        network_trust_monitor._parse_linux_default_routes(linux_text, "ipv4")
    )
    assert sum(len(values) for values in linux_routes.values()) == 64
    assert linux_complete is False


def test_observer_marks_omitted_interface_and_route_family_incomplete(monkeypatch):
    names = [f"if-{index:03d}" for index in range(MAX_LINKS + 1)]
    addresses = {
        name: (SimpleNamespace(family=network_trust_monitor.socket.AF_INET,
                               address=f"10.0.0.{index + 1}"),)
        for index, name in enumerate(names)
    }
    stats = {name: SimpleNamespace(isup=True) for name in names}
    routes = {
        names[0]: [DefaultRouteObservation(
            "192.0.2.1", "ipv4", 1, selected=True, interface_index=1
        )],
        names[-1]: [DefaultRouteObservation(
            "192.0.2.254", "ipv4", 50, interface_index=MAX_LINKS + 1
        )],
    }
    monkeypatch.setattr(network_trust_monitor.psutil, "net_if_addrs", lambda: addresses)
    monkeypatch.setattr(network_trust_monitor.psutil, "net_if_stats", lambda: stats)
    monkeypatch.setattr(network_trust_monitor.psutil, "boot_time", lambda: 1.0)
    monkeypatch.setattr(
        network_trust_monitor, "classify_interfaces",
        lambda: {name: "Physical" for name in names},
    )
    monkeypatch.setattr(network_trust_monitor, "_windows_wlan", lambda: ({}, True))
    monkeypatch.setattr(network_trust_monitor, "_windows_profiles", lambda: ({}, True))
    monkeypatch.setattr(
        network_trust_monitor, "_windows_interface_settings", lambda: ({}, True)
    )
    monkeypatch.setattr(
        network_trust_monitor, "_system_dns_servers", lambda: ((), True)
    )
    monkeypatch.setattr(
        network_trust_monitor, "_windows_dhcp_servers", lambda: ((), True)
    )
    monkeypatch.setattr(
        network_trust_monitor,
        "_default_routes",
        lambda _local: (routes, frozenset({"ipv4", "ipv6"})),
    )
    monkeypatch.setattr(
        network_trust_monitor, "_neighbor_identities", lambda: ({}, True)
    )
    monkeypatch.setattr(
        network_trust_monitor.socket,
        "if_nametoindex",
        lambda name: int(name.rsplit("-", 1)[1]) + 1,
    )

    snapshot = network_trust_monitor.observe_system_network()

    assert len(snapshot.links) == MAX_LINKS
    assert names[-1] not in {link.interface_id for link in snapshot.links}
    assert "interfaces" not in snapshot.collection_complete
    assert "routes-ipv4" not in snapshot.collection_complete
    assert "routes-ipv6" in snapshot.collection_complete
    assert all("interfaces" not in link.collection_complete for link in snapshot.links)
    assert NetworkTrustMonitorModule._selected_route_context(
        snapshot, names[0], "192.0.2.1"
    ) is None


@pytest.mark.parametrize("missing_source", ["interfaces", "routes-ipv4"])
def test_gateway_attestation_rejects_incomplete_pre_exchange_inventory(missing_source):
    complete = tuple(source for source in COMPLETE if source != missing_source)
    snapshot = NetworkSnapshot(_snapshot(_link()).links, collection_complete=complete)
    transport = _GatewayTransport()
    module = NetworkTrustMonitorModule(
        privacy_key=KEY,
        gateway_loader=lambda: _gateway_binding(),
        gateway_transport=transport,
    )
    bus = EventBus()
    module.bind(bus)

    result = module._apply_gateway_attestation(snapshot)

    assert result.links[0].gateway_attestation == "untrusted"
    assert transport.requests == []
    assert bus.recent(1)[0].details["reason_code"] == "path-binding-rejected"


@pytest.mark.parametrize("missing_source", ["interfaces", "routes-ipv4"])
def test_gateway_attestation_rejects_incomplete_post_exchange_inventory(missing_source):
    initial = _snapshot(_link())
    complete = tuple(source for source in COMPLETE if source != missing_source)
    incomplete = NetworkSnapshot(initial.links, collection_complete=complete)
    transport = _GatewayTransport()
    module = NetworkTrustMonitorModule(
        observer=lambda: incomplete,
        privacy_key=KEY,
        gateway_loader=lambda: _gateway_binding(),
        gateway_transport=transport,
    )
    bus = EventBus()
    module.bind(bus)

    result = module._apply_gateway_attestation(initial)

    assert len(transport.requests) == 1
    assert result.links[0].gateway_attestation == "untrusted"
    assert bus.recent(1)[0].details["reason_code"] == "route-context-changed"


def test_network_trust_self_tests_are_offline_and_pass():
    assert self_test()[0] is True
    assert NetworkTrustMonitorModule(privacy_key=KEY).self_test()[0] is True
