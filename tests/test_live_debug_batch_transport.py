"""Bounded byte batches preserve diagnostic order, loss and native ownership."""
from contextlib import contextmanager
import os
import secrets
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import live_debug as debug
from angerona.core.eventbus import BusAuthority, EventBus


def frame(seq, size=400):
    return dict(protocol=debug.PROTOCOL, kind="diagnostic", run_id="a" * 32,
                seq=seq, ts=1.0, message="x" * size)


class CapturedPipe:
    def __init__(self):
        self.writes = []

    def write(self, raw):
        self.writes.append(raw)


def decoded(writes):
    return [debug._decode(line) for line in b"".join(writes).splitlines()]


def test_batch_preserves_every_frame_in_order_with_bounded_native_writes():
    records = [frame(index) for index in range(1, 201)]
    pipe = CapturedPipe()
    debug._NamedPipeServer._write_records(pipe, records)
    assert decoded(pipe.writes) == records
    assert len(pipe.writes) <= 2
    assert all(0 < len(raw) <= 64 * 1024 for raw in pipe.writes)
    assert all(len(line) + 1 <= debug.MAX_FRAME_BYTES
               for raw in pipe.writes for line in raw.splitlines())


def test_near_limit_frames_coalesce_and_split_without_changing_frame_bound():
    records = [dict(frame(index, 7900), fixture_payload=["y" * 7900] * 3)
               for index in range(1, 6)]
    assert all(31000 < len(debug._encode(record)) <= debug.MAX_FRAME_BYTES
               for record in records)
    pipe = CapturedPipe()
    debug._NamedPipeServer._write_records(pipe, records)
    assert len(pipe.writes) == 3
    assert decoded(pipe.writes) == records
    # The normal reader may split a batch anywhere, including inside a frame.
    client = debug.LiveDebugClient(debug.endpoint_for_pid(123), 123)
    stream = b"".join(pipe.writes)
    chunks = iter(stream[index:index + 137] for index in range(0, len(stream), 137))
    client._pipe = SimpleNamespace(read=lambda _timeout: next(chunks))
    client._run_id = "a" * 32
    assert [client.read(2) for _ in records] == records


def test_empty_page_writes_nothing_and_oversized_frame_remains_an_error():
    pipe = CapturedPipe()
    debug._NamedPipeServer._write_records(pipe, [])
    assert pipe.writes == []
    with pytest.raises(debug.LiveDebugError, match="frame bound"):
        debug._NamedPipeServer._write_records(pipe, [frame(1, 40000)])
    assert pipe.writes == []


def test_failed_native_batch_does_not_write_later_frames_or_fabricate_success():
    class FailedPipe(CapturedPipe):
        def write(self, raw):
            if len(self.writes) == 1:
                raise debug.LiveDebugError("controlled incomplete native write")
            super().write(raw)
    pipe = FailedPipe()
    with pytest.raises(debug.LiveDebugError, match="incomplete native write"):
        debug._NamedPipeServer._write_records(pipe, [frame(index, 8000)
                                                    for index in range(1, 31)])
    assert len(pipe.writes) == 1
    assert [row["seq"] for row in decoded(pipe.writes)] == list(range(1, 9))


@pytest.mark.skipif(os.name != "nt", reason="Windows server loop")
@pytest.mark.parametrize("fail", [False, True])
def test_retention_gap_precedes_frames_and_cursor_advances_only_after_complete_page(monkeypatch, fail):
    import win32pipe
    server = debug._NamedPipeServer(None)
    calls, client_deltas = [], []
    records = [frame(index) for index in range(5, 8)]
    class Service:
        run_id = "a" * 32
        def _client_delta(self, amount):
            client_deltas.append(amount)
        def _hello(self):
            return dict(frame(0), kind="hello")
        def recent(self, cursor, limit):
            assert limit == 100
            calls.append(cursor)
            if len(calls) > 1:
                server.stop_event.set()
                return dict(records=[], gap=0, cursor=7, first_seq=5)
            return dict(records=records, gap=4, cursor=7, first_seq=5)
    class Pipe(CapturedPipe):
        handle = object()
        def connect_server(self, timeout):
            assert timeout == 1.0
        def write(self, raw):
            if fail and self.writes:
                server.stop_event.set()
                raise OSError("controlled disconnected reader")
            super().write(raw)
    pipe = Pipe()
    server.service = Service()
    monkeypatch.setattr(win32pipe, "DisconnectNamedPipe", lambda _handle: None)
    server._serve_client_loop(pipe)
    assert client_deltas == [1, -1]
    if fail:
        assert calls == [0]
        assert len(pipe.writes) == 1
    else:
        rows = decoded(pipe.writes)
        assert calls == [0, 7]
        assert [row["seq"] for row in rows] == [0, 4, 5, 6, 7]
        assert rows[1]["kind"] == "gap" and rows[1]["lost_records"] == 4


@contextmanager
def native_pair():
    import win32con
    import win32file
    import win32pipe
    endpoint = rf"\\.\pipe\Angerona.TestBatch.{os.getpid()}.{secrets.token_hex(8)}"
    server = debug._Pipe(win32pipe.CreateNamedPipe(
        endpoint, 2 | win32file.FILE_FLAG_OVERLAPPED | 0x80000,
        8, 1, 64 * 1024, 0, 1000, debug._pipe_attributes(),
    ))
    client = None
    try:
        client = debug._Pipe(win32file.CreateFile(
            endpoint, win32con.GENERIC_READ, 0, None, win32con.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED, None,
        ))
        server.connect_server(.25)
        yield server, client
    finally:
        if client is not None:
            assert client.close(timeout=1)
        assert server.close(timeout=1)


@pytest.mark.skipif(os.name != "nt", reason="Windows native scalar I/O")
def test_native_scalar_synchronous_status_keeps_exact_byte_count(monkeypatch):
    import win32file
    statuses = {"read": [], "write": []}
    for name, attribute in (("read", "ReadFile"), ("write", "WriteFile")):
        original = getattr(win32file, attribute)
        def recorded(*args, _original=original, _name=name):
            result = _original(*args)
            statuses[_name].append(result[0])
            return result
        monkeypatch.setattr(win32file, attribute, recorded)
    with native_pair() as (server, client):
        server.write(b"inert synchronous bytes", timeout=1)
        assert client.read(timeout=1) == b"inert synchronous bytes"
    assert statuses == {"read": [0], "write": [0]}


@pytest.mark.skipif(os.name != "nt", reason="Windows native pending I/O")
def test_native_scalar_pending_read_completes_then_retires(monkeypatch):
    import win32file
    submitted = threading.Event()
    original = win32file.ReadFile
    statuses, values, errors = [], [], []
    def recorded(*args):
        result = original(*args)
        statuses.append(result[0])
        submitted.set()
        return result
    monkeypatch.setattr(win32file, "ReadFile", recorded)
    with native_pair() as (server, client):
        def reader():
            try:
                values.append(client.read(2))
            except BaseException as exc:
                errors.append(exc)
        worker = threading.Thread(target=reader, daemon=False)
        worker.start()
        try:
            assert submitted.wait(1) and statuses == [997]
            server.write(b"pending read completion", timeout=1)
            worker.join(3)
            assert not worker.is_alive() and not errors
            assert values == [b"pending read completion"]
        finally:
            client.cancel()
            worker.join(3)
            assert not worker.is_alive()


@pytest.mark.skipif(os.name != "nt", reason="Windows native pending write")
def test_native_pending_write_retains_buffer_until_full_drain(monkeypatch):
    import win32file
    submitted = threading.Event()
    original = win32file.WriteFile
    statuses, errors = [], []
    def recorded(*args):
        result = original(*args)
        statuses.append(result[0])
        submitted.set()
        return result
    monkeypatch.setattr(win32file, "WriteFile", recorded)
    payload = b"inert pending payload" * 16000
    with native_pair() as (server, client):
        def writer():
            try:
                server.write(payload, timeout=2)
            except BaseException as exc:
                errors.append(exc)
        worker = threading.Thread(target=writer, daemon=False)
        worker.start()
        try:
            assert submitted.wait(1) and statuses == [997]
            received = bytearray()
            deadline = time.monotonic() + 3
            while len(received) < len(payload) and time.monotonic() < deadline:
                received.extend(client.read(.25))
            worker.join(3)
            assert not worker.is_alive() and not errors
            assert bytes(received) == payload
        finally:
            server.cancel()
            worker.join(3)
            assert not worker.is_alive()


@pytest.mark.skipif(os.name != "nt", reason="Windows native multi-client batching")
def test_native_slow_reader_does_not_hold_fast_client_or_hide_disconnect(tmp_path):
    bus = EventBus()
    bus.arm(BusAuthority(secrets.token_bytes(32)))
    service = debug.LiveDebugService(bus, tmp_path, enabled=True, export_logs=False)
    clients = []
    assert service.start(), service.status()
    try:
        for number in range(2000):
            service._append(dict(kind="diagnostic", source="inert-fixture", message="x" * 400))
        slow = debug.LiveDebugClient(service.endpoint, os.getpid(), service.birth)
        clients.append(slow)
        slow.connect()
        assert slow.read(1)["kind"] == "hello"
        fast = debug.LiveDebugClient(service.endpoint, os.getpid(), service.birth)
        clients.append(fast)
        fast.connect()
        hello = fast.read(1)
        assert hello["kind"] == "hello"
        target, last = hello["status"]["cursor"], 0
        deadline = time.monotonic() + 12
        while last < target and time.monotonic() < deadline:
            row = fast.read(.25)
            if row is not None and row["kind"] != "heartbeat":
                last = row["seq"]
        assert last >= target
        deadline = time.monotonic() + 4
        while service.status()["client_count"] > 1 and time.monotonic() < deadline:
            time.sleep(.01)
        assert service.status()["client_count"] == 1
        # The timed-out reader must report the failed connection, never success.
        disconnected = False
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                slow.read(.25)
            except debug.LiveDebugError:
                disconnected = True
                break
        assert disconnected
    finally:
        for client in clients:
            client.close()
        assert service.stop(timeout=2)
        assert all(not thread.is_alive() for thread in service._server.threads)
        assert all(pipe._handle_closed for pipe in service._server.pipes)
