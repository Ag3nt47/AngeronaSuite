from __future__ import annotations

import pytest

from angerona.modules.network_monitor import (
    NetworkMonitorModule,
    _block_remote_contract,
    _is_local,
)


def test_ipv4_mapped_ipv6_is_classified_by_embedded_address() -> None:
    assert _is_local("::ffff:8.8.8.8") is False
    assert _is_local("::ffff:192.168.10.25") is True
    assert _is_local("::ffff:127.0.0.1") is True


def test_ipv6_and_zone_classification_is_explicit() -> None:
    assert _is_local("2001:4860:4860::8888") is False
    assert _is_local("fe80::1234%12") is True
    assert _is_local("fd00::42") is True
    assert _is_local("::") is True


def test_malformed_endpoint_cannot_be_promoted_to_external() -> None:
    assert _is_local("not-an-ip") is True


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.10.10.10",
        "169.254.10.2",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fd00::1",
        "ff02::1",
        "::ffff:192.168.1.4",
        "not-an-ip",
    ],
)
def test_corroboration_never_authorizes_non_global_firewall_targets(value: str) -> None:
    assert _block_remote_contract(
        value,
        corroborated=True,
        classification="threat-intel-ioc",
    ) == {}


def test_mapped_public_firewall_target_is_canonicalized() -> None:
    result = _block_remote_contract(
        "::ffff:8.8.8.8",
        corroborated=True,
        classification="threat-intel-ioc",
    )
    assert result["response_contract"]["targets"]["remote_ips"] == ["8.8.8.8"]


def test_connection_identity_includes_process_birth_and_local_socket() -> None:
    cache: dict[int, float | None] = {}
    first = {
        "pid": 4242,
        "process_create_time": 100.0,
        "laddr": "10.0.0.5:50000",
        "raddr": "8.8.8.8:443",
    }
    reused = {**first, "process_create_time": 200.0}
    other_socket = {**first, "laddr": "10.0.0.5:50001"}

    first_key = NetworkMonitorModule._connection_key(first, cache)
    assert first_key != NetworkMonitorModule._connection_key(reused, cache)
    assert first_key != NetworkMonitorModule._connection_key(other_socket, cache)
