from __future__ import annotations

import threading

import pytest

from angerona.core.durable_outbox import DurableOutbox, OutboxStats
from angerona.modules.ipc_guard import IpcGuardModule, _IpcGeneration, _MAX_CONNECTIONS
from angerona.modules.remote_bridge import RemoteBridge


class _FragmentedSocket:
    def __init__(self, payload: bytes, fragment_bytes: int = 1) -> None:
        self.payload = payload
        self.fragment_bytes = fragment_bytes
        self.closed = False

    def recv(self, maximum: int) -> bytes:
        width = min(maximum, self.fragment_bytes, len(self.payload))
        chunk, self.payload = self.payload[:width], self.payload[width:]
        return chunk

    def close(self) -> None:
        self.closed = True


class _FailingThread:
    def __init__(self, *args, **kwargs) -> None:
        del args, kwargs

    def start(self) -> None:
        raise RuntimeError("injected thread startup failure")


def test_durable_outbox_stats_preserve_every_state_in_one_snapshot(tmp_path) -> None:
    queue = DurableOutbox(
        tmp_path / "stats.sqlite3", b"s" * 32, max_attempts=1
    )
    for index in range(3):
        queue.enqueue(f"item-{index}", {"i": index}, now=float(index))

    first, second = queue.claim("worker", now=10, limit=2)
    queue.acknowledge(first.item_id, "worker")
    queue.retry(second.item_id, "worker", "terminal", now=10)

    assert queue.stats() == OutboxStats(
        pending=1,
        leased=0,
        dead_letter=1,
        delivered_tombstones=1,
        retained_bytes=len(b'{"i":1}') + len(b'{"i":2}'),
    )
    queue.close()


def test_remote_bridge_fragmented_frame_assembly_is_exact() -> None:
    payload = bytes(range(256)) * 4096
    fragmented = _FragmentedSocket(payload, fragment_bytes=7)

    assert RemoteBridge._recvn(fragmented, len(payload)) == payload
    assert fragmented.payload == b""


def test_remote_bridge_thread_start_failure_releases_admission(monkeypatch) -> None:
    bridge = RemoteBridge()
    conn = _FragmentedSocket(b"")
    assert bridge._connections.acquire(blocking=False)
    monkeypatch.setattr("angerona.modules.remote_bridge.threading.Thread", _FailingThread)

    with pytest.raises(RuntimeError, match="injected thread startup failure"):
        bridge._start_connection_helper(conn, ("127.0.0.1", 1))

    assert conn.closed
    assert not bridge._active_connections
    assert not bridge._connection_threads
    acquired = sum(
        bridge._connections.acquire(blocking=False) for _ in range(16)
    )
    assert acquired == 16


def test_ipc_thread_start_failure_releases_connection_capacity(monkeypatch) -> None:
    module = IpcGuardModule()
    generation = _IpcGeneration(threading.Event())
    conn = _FragmentedSocket(b"")

    class _OneConnectionServer:
        def accept(self):
            return conn, ("127.0.0.1", 2)

    generation.srv = _OneConnectionServer()  # type: ignore[assignment]
    monkeypatch.setattr("angerona.modules.ipc_guard.threading.Thread", _FailingThread)
    module._accept_loop(generation)

    assert conn.closed
    assert not generation.connections
    assert not generation.helpers
    acquired = sum(
        generation.connection_slots.acquire(blocking=False)
        for _ in range(_MAX_CONNECTIONS)
    )
    assert acquired == _MAX_CONNECTIONS
    assert module.denied == 1
