from __future__ import annotations

from angerona.core.community_id import community_id_v1
from angerona.core.security_interop import _suricata, _zeek
from angerona.modules import network_monitor
from angerona.modules.network_monitor import _native_community_id


def test_official_corelight_tcp_reference_vector_and_direction_invariance() -> None:
    expected = "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert community_id_v1(
        "128.232.110.120", "66.35.250.204", 34855, 80, "tcp"
    ) == expected
    assert community_id_v1(
        "66.35.250.204", "128.232.110.120", 80, 34855, 6
    ) == expected


def test_ipv6_udp_and_sctp_are_direction_invariant() -> None:
    for protocol in ("udp", 132):
        forward = community_id_v1("2001:db8::2", "2001:db8::1", 5353, 53, protocol)
        reverse = community_id_v1("2001:db8::1", "2001:db8::2", 53, 5353, protocol)
        assert forward.startswith("1:")
        assert reverse == forward


def test_invalid_or_unsupported_tuples_refuse_correlation() -> None:
    assert community_id_v1("192.0.2.1", "2001:db8::1", 1, 2, "tcp") == ""
    assert community_id_v1("192.0.2.1", "192.0.2.2", -1, 2, "tcp") == ""
    assert community_id_v1("192.0.2.1", "192.0.2.2", True, 2, "tcp") == ""
    assert community_id_v1("192.0.2.1", "192.0.2.2", 1, 2, "icmp") == ""
    assert community_id_v1("192.0.2.1%zone", "192.0.2.2", 1, 2, "tcp") == ""
    assert community_id_v1("192.0.2.1", "192.0.2.2", 1, 2, "tcp", seed=65_536) == ""


def test_interop_preserves_suricata_id_and_computes_complete_zeek_tuple() -> None:
    upstream = "1:suricata-provided-id="
    suricata = _suricata({
        "event_type": "flow", "src_ip": "192.0.2.1", "dest_ip": "192.0.2.2",
        "src_port": 1000, "dest_port": 443, "proto": "TCP",
        "community_id": upstream,
    })
    assert suricata.attributes["community_id"] == upstream
    assert suricata.subject["id"] == upstream

    zeek = _zeek({
        "_path": "conn", "uid": "native-zeek-id",
        "id.orig_h": "128.232.110.120", "id.resp_h": "66.35.250.204",
        "id.orig_p": 34855, "id.resp_p": 80, "proto": "tcp",
    })
    expected = "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert zeek.attributes["community_id"] == expected
    assert zeek.attributes["uid"] == "native-zeek-id"
    assert zeek.subject["id"] == expected


def test_native_network_evidence_gets_same_flow_identifier() -> None:
    forward = _native_community_id({
        "laddr": "128.232.110.120:34855", "raddr": "66.35.250.204:80",
    })
    reverse = _native_community_id({
        "laddr": "66.35.250.204:80", "raddr": "128.232.110.120:34855",
    })
    assert forward == reverse == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert _native_community_id({"laddr": "incomplete", "raddr": "192.0.2.2:443"}) == ""


def test_network_monitor_emits_community_id_without_changing_severity(monkeypatch) -> None:
    connection = {
        "pid": 42, "status": "ESTABLISHED",
        "laddr": "128.232.110.120:34855", "raddr": "66.35.250.204:80",
    }
    snapshots = iter(([], [connection]))
    monkeypatch.setattr(
        network_monitor,
        "list_connections",
        lambda **_kwargs: next(snapshots),
    )
    module = network_monitor.NetworkMonitorModule()
    emitted: list[tuple[str, object, dict[str, object]]] = []
    monkeypatch.setattr(
        module, "emit", lambda message, severity, **details: emitted.append(
            (message, severity, details)
        ),
    )
    monkeypatch.setattr(module, "sleep", lambda _seconds: module.stop())

    module.run()

    flow = next(details for _message, _severity, details in emitted if details)
    assert flow["community_id"] == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert next(severity for _message, severity, details in emitted if details).name == "LOW"
