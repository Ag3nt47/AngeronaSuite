"""Remote endpoint collection preserves delivery without redundant table scans."""
from __future__ import annotations

import socket
from collections import namedtuple
from types import SimpleNamespace

import pytest

from angerona.modules import memory_timemachine as mtm


Conn = namedtuple("Conn", "pid laddr raddr")


class _Proc:
    info = {"pid": 731}

    def __init__(self, connections):
        self._connections = connections
        self.connection_calls = 0

    def as_dict(self, attrs):
        return {"cmdline": ["worker"], "exe": "worker.exe",
                "name": "worker.exe", "cwd": "C:/work"}

    def connections(self):
        self.connection_calls += 1
        return self._connections


def _fixture(monkeypatch, bulk_rows, *, bulk_error=False, platform="nt"):
    # Replace this module's reference instead of changing process-wide os.name:
    # pathlib and the test runner must retain the actual host platform.
    monkeypatch.setattr(mtm, "os", SimpleNamespace(name=platform, environ=mtm.os.environ))
    remote = Conn(731, ("127.0.0.1", 7301), ("1.1.1.1", 443))
    local_only = Conn(731, ("0.0.0.0", 7302), ())
    proc = _Proc([remote, local_only])
    calls = []

    def net_connections(kind):
        calls.append(kind)
        if bulk_error:
            raise OSError("table unavailable")
        return bulk_rows

    monkeypatch.setattr(mtm, "psutil", SimpleNamespace(
        net_connections=net_connections,
        process_iter=lambda _attrs: iter([proc]),
    ))
    module = mtm.MemoryTimeMachineModule()
    return module, proc, calls, remote, local_only


def test_tcp_snapshot_matches_full_inet_carving_without_udp_queries(monkeypatch):
    remote = Conn(731, ("127.0.0.1", 7301), ("1.1.1.1", 443))
    listener = Conn(731, ("0.0.0.0", 7302), ())
    module, proc, calls, _, _ = _fixture(monkeypatch, [remote, listener])
    udp = Conn(731, ("0.0.0.0", 7303), ())
    expected = module._process_strings(proc, [remote, listener, udp])

    module._sweep()

    assert calls == ["tcp"]
    assert proc.connection_calls == 0
    assert module.delta_queue.get_nowait()["delta"] == list(dict.fromkeys(expected))
    assert module._last_sweep_collector_failures == 0


def test_posix_inet_snapshot_retains_connected_udp_remote_strings(monkeypatch):
    udp = SimpleNamespace(
        pid=731, laddr=("127.0.0.1", 7303), raddr=("8.8.8.8", 53),
        type=socket.SOCK_DGRAM,
    )
    module, proc, calls, _, _ = _fixture(monkeypatch, [udp], platform="posix")

    def net_connections(kind):
        calls.append(kind)
        # Linux reports connected UDP peers through inet, but a TCP-only
        # request would silently omit this previously observable evidence.
        return [udp] if kind == "inet" else []

    monkeypatch.setattr(mtm.psutil, "net_connections", net_connections)
    expected = module._process_strings(proc, [udp])

    module._sweep()

    assert calls == ["inet"]
    assert proc.connection_calls == 0
    delivered = module.delta_queue.get_nowait()["delta"]
    assert delivered == list(dict.fromkeys(expected))
    assert f"{udp.laddr}->{udp.raddr}" in delivered
    assert module._last_sweep_collector_failures == 0


def test_unattributed_listener_retains_gap_without_rescanning_every_pid(monkeypatch):
    remote = Conn(731, ("127.0.0.1", 7301), ("1.1.1.1", 443))
    listener = Conn(None, ("0.0.0.0", 7302), ())
    module, proc, calls, _, _ = _fixture(monkeypatch, [remote, listener])

    module._sweep()

    assert calls == ["tcp"]
    assert proc.connection_calls == 0
    assert str(remote.raddr) in " ".join(module.delta_queue.get_nowait()["delta"])
    assert module._last_sweep_collector_failures == 1
    assert "collector gaps" in module.health_note


def test_unattributed_listener_keeps_one_query_on_a_large_process_table(monkeypatch):
    monkeypatch.setattr(mtm, "os", SimpleNamespace(name="nt", environ=mtm.os.environ))
    processes = []
    rows = [Conn(None, ("0.0.0.0", 7302), ())]
    for pid in range(1, 513):
        remote = Conn(pid, ("127.0.0.1", pid + 10_000), ("1.1.1.1", 443))
        proc = _Proc([remote])
        proc.info = {"pid": pid}
        processes.append(proc)
        rows.append(remote)
    calls = []

    def net_connections(kind):
        calls.append(kind)
        return rows

    monkeypatch.setattr(mtm, "psutil", SimpleNamespace(
        net_connections=net_connections,
        process_iter=lambda _attrs: iter(processes),
    ))
    module = mtm.MemoryTimeMachineModule()

    module._sweep()

    assert calls == ["tcp"]
    assert sum(proc.connection_calls for proc in processes) == 0
    assert module.delta_queue.qsize() == len(processes)
    delivered = [module.delta_queue.get_nowait() for _ in processes]
    assert {payload["pid"] for payload in delivered} == set(range(1, 513))
    for payload in delivered:
        remote = rows[payload["pid"]]
        assert f"{remote.laddr}->{remote.raddr}" in payload["delta"]
    assert module._last_sweep_collector_failures == 1


@pytest.mark.parametrize("bulk_error", [False, True])
def test_remote_ownership_loss_and_bulk_failure_keep_per_process_fallback(
    monkeypatch, bulk_error,
):
    unknown = Conn(None, ("127.0.0.1", 7301), ("1.1.1.1", 443))
    module, proc, calls, remote, _ = _fixture(
        monkeypatch, [unknown], bulk_error=bulk_error,
    )

    module._sweep()

    assert calls == ["tcp"]
    assert proc.connection_calls == 1
    assert str(remote.raddr) in " ".join(module.delta_queue.get_nowait()["delta"])
    assert module._last_sweep_collector_failures == 1
    assert "collector gaps" in module.health_note
