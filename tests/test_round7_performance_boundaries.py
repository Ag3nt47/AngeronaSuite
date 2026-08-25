from __future__ import annotations

import socket

from angerona.core import url_policy
from angerona.core.eventbus import EventBus
from angerona.modules import network_monitor, ransomware_heuristics


def test_loopback_ip_literal_never_calls_dns_resolver() -> None:
    calls = 0

    def resolver(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("an IP literal must not enter DNS resolution")

    assert url_policy.validate_url(
        "http://127.0.0.1:11434/api/chat",
        url_policy.LOCAL_SERVICE_POLICY,
        resolver=resolver,
    ) == "127.0.0.1"
    assert calls == 0


def test_loopback_hostname_still_resolves_and_is_pinned(monkeypatch) -> None:
    calls = 0

    def resolver(_host, port, **kwargs):
        nonlocal calls
        calls += 1
        return [
            (socket.AF_INET, kwargs["type"], 6, "", ("127.0.0.1", port))
        ]

    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    pinned = url_policy.local_service_url(
        "http://localhost:11434", "/api/chat"
    )

    assert pinned == "http://127.0.0.1:11434/api/chat"
    assert calls == 1


def test_network_novelty_prune_reuses_maps_when_nothing_expires() -> None:
    module = network_monitor.NetworkMonitorModule()
    now = 10_000.0
    module._known_pid_hosts = {(42, "203.0.113.4"): now}
    module._known_hosts = {"203.0.113.4": now}
    pid_map = module._known_pid_hosts
    host_map = module._known_hosts

    module._prune_state(set(), now)

    assert module._known_pid_hosts is pid_map
    assert module._known_hosts is host_map
    assert module._known_pid_hosts == {(42, "203.0.113.4"): now}
    assert module._known_hosts == {"203.0.113.4": now}


def test_ransomware_flood_normalizes_each_directory_once(monkeypatch) -> None:
    module = ransomware_heuristics.RansomwareHeuristicsModule()
    module.bind(EventBus())
    raw_directory = ".\\watched"
    module._rename_times.extend(
        [(1_000.0, raw_directory)] * ransomware_heuristics.RENAME_THRESHOLD
    )
    calls = 0
    original = ransomware_heuristics.os.path.abspath

    def counted(path):
        nonlocal calls
        calls += 1
        return original(path)

    monkeypatch.setattr(ransomware_heuristics.os.path, "abspath", counted)

    module._check_rename_rate(1_000.0)

    assert calls == 1
    assert not module._rename_times
