"""Native response-retirement checks; no service installation or host mutations."""
from __future__ import annotations
from contextlib import closing
import hashlib
import os
import secrets
import struct
import threading
import time
from types import SimpleNamespace
import uuid

import pytest

from angerona.core import privileged_pipe as transport


def owner_sid():
    import win32api
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        return win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, 1)[0])
    finally:
        token.Close()


@pytest.fixture
def native_server():
    if os.name != "nt":
        pytest.skip("native Windows response retirement")
    import win32api
    import win32security
    user = owner_sid()
    seen = []

    def dispatch(request, peer):
        try:
            token = win32security.OpenThreadToken(win32api.GetCurrentThread(), 8, True)
        except Exception as error:
            assert error.winerror == 1008
        else:
            token.Close()
            raise AssertionError("dispatch retained impersonation")
        assert peer.user_sid == user and peer.pid == os.getpid()
        assert peer.authentication_id and peer.birth > 0
        seen.append(request)
        return {"diagnostic": "owned-response"}

    server = transport.PrivilegedPipeServer(dispatch, server_sid=user, allowed_sids=[user],
        endpoint=r"\\.\pipe\Angerona.Test.ResponseReceipt." + uuid.uuid4().hex)
    server.start()
    try:
        yield server, seen
    finally:
        assert server.stop(3), server.error
        assert all(not thread.is_alive() and not thread.daemon for thread in server.threads)


def client(server):
    return transport.PrivilegedPipeClient(endpoint=server.endpoint, expected_pid=os.getpid(),
        _server_verifier=lambda process, pid: None)


def raw_client(server):
    import win32file
    import win32pipe
    win32pipe.WaitNamedPipe(server.endpoint, 1000)
    return transport._Pipe(win32file.CreateFile(server.endpoint, transport.CLIENT_ACCESS, 0, None, 3,
        win32file.FILE_FLAG_OVERLAPPED | 0x110000, None))


def request(pipe):
    nonce = secrets.token_hex(16)
    transport._write_frame(pipe, dict(protocol=transport.PROTOCOL, nonce=nonce,
        request={"operation": "status"}))
    return nonce


def test_native_scheduled_late_reader_retains_response_until_nonce_digest_receipt(
    native_server, monkeypatch,
):
    import win32pipe
    server, seen = native_server
    wrote, waiting_receipt, disconnected = (threading.Event() for _ in range(3))
    write, read, disconnect = transport._write_frame, transport._read_frame, win32pipe.DisconnectNamedPipe

    def observed_write(pipe, value, timeout=3.0):
        result = write(pipe, value, timeout)
        if value.get("ok") is True:
            wrote.set()
        return result

    def observed_read(pipe, timeout=3.0):
        if threading.current_thread() is threading.main_thread():
            assert waiting_receipt.wait(3)
            assert wrote.is_set() and not disconnected.is_set()
        elif wrote.is_set():
            waiting_receipt.set()
        return read(pipe, timeout)

    def observed_disconnect(handle):
        result = disconnect(handle)
        disconnected.set()
        return result

    monkeypatch.setattr(transport, "_write_frame", observed_write)
    monkeypatch.setattr(transport, "_read_frame", observed_read)
    monkeypatch.setattr(win32pipe, "DisconnectNamedPipe", observed_disconnect)
    assert client(server).exchange({"operation": "status"}) == {"diagnostic": "owned-response"}
    assert disconnected.wait(3)
    assert len(seen) == server.accepted == 1 and server.rejected == 0


@pytest.mark.parametrize("bad", ["nonce", "digest", "extra", "replayed_request"])
def test_native_invalid_or_replayed_receipt_cannot_dispatch_twice_and_listener_recovers(
    native_server, monkeypatch, bad,
):
    import win32pipe
    server, seen = native_server
    disconnected = threading.Event()
    disconnect = win32pipe.DisconnectNamedPipe

    def observed_disconnect(handle):
        result = disconnect(handle)
        disconnected.set()
        return result

    monkeypatch.setattr(win32pipe, "DisconnectNamedPipe", observed_disconnect)
    with closing(raw_client(server)) as pipe:
        nonce = request(pipe)
        response = transport._read_frame(pipe)
        receipt = transport._response_receipt(response)
        if bad == "nonce":
            receipt["nonce"] = "0" * 32
        elif bad == "digest":
            receipt["received_sha256"] = "0" * 64
        elif bad == "extra":
            receipt["request"] = {"operation": "status"}
        else:
            receipt = dict(protocol=transport.PROTOCOL, nonce=nonce, request={"operation": "status"})
        transport._write_frame(pipe, receipt)
        assert disconnected.wait(3)
        assert len(seen) == 1 and server.accepted == 1 and server.rejected == 1
    assert client(server).exchange({"operation": "status"}) == {"diagnostic": "owned-response"}
    assert len(seen) == server.accepted == 2


def test_native_nonreader_receipt_wait_cancels_and_owners_retire(native_server, monkeypatch):
    server, seen = native_server
    wrote = threading.Event()
    original_write = transport._write_frame

    def observed_write(pipe, value, timeout=3.0):
        result = original_write(pipe, value, timeout)
        if value.get("ok") is True:
            wrote.set()
        return result

    monkeypatch.setattr(transport, "_write_frame", observed_write)
    pipe = raw_client(server)
    try:
        request(pipe)
        assert wrote.wait(3)
        assert len(seen) == 1
        started = time.monotonic()
        assert server.stop(1), server.error
        assert time.monotonic() - started < 1.5
    finally:
        pipe.close()


@pytest.mark.parametrize("bad", ["partial", "oversized"])
def test_native_incomplete_receipt_then_peer_disconnect_cannot_add_authority(
    native_server, monkeypatch, bad,
):
    import win32pipe
    server, seen = native_server
    disconnected = threading.Event()
    disconnect = win32pipe.DisconnectNamedPipe

    def observed_disconnect(handle):
        result = disconnect(handle)
        disconnected.set()
        return result

    monkeypatch.setattr(win32pipe, "DisconnectNamedPipe", observed_disconnect)
    pipe = raw_client(server)
    try:
        request(pipe)
        response = transport._read_frame(pipe)
        assert response["ok"] is True
        raw = (struct.pack("!I", 77) + b"{" if bad == "partial"
               else struct.pack("!I", transport.MAX_FRAME + 1))
        pipe.write(raw)
    finally:
        pipe.close()
    assert disconnected.wait(4)
    assert len(seen) == server.accepted == 1 and server.rejected == 1
    assert client(server).exchange({"operation": "status"}) == {"diagnostic": "owned-response"}
    assert len(seen) == server.accepted == 2


def test_native_nonreader_is_released_by_existing_three_second_response_budget(
    native_server, monkeypatch,
):
    import win32pipe
    server, seen = native_server
    wrote, disconnected = threading.Event(), threading.Event()
    original_write, original_disconnect = transport._write_frame, win32pipe.DisconnectNamedPipe

    def observed_write(pipe, value, timeout=3.0):
        result = original_write(pipe, value, timeout)
        if value.get("ok") is True:
            wrote.set()
        return result

    def observed_disconnect(handle):
        result = original_disconnect(handle)
        disconnected.set()
        return result

    monkeypatch.setattr(transport, "_write_frame", observed_write)
    monkeypatch.setattr(win32pipe, "DisconnectNamedPipe", observed_disconnect)
    pipe = raw_client(server)
    try:
        request(pipe)
        assert wrote.wait(3)
        started = time.monotonic()
        assert disconnected.wait(4)
        assert time.monotonic() - started < 4.2
        assert len(seen) == server.accepted == 1 and server.rejected == 1
    finally:
        pipe.close()


def test_response_receipt_shares_write_deadline_without_extending_it(monkeypatch):
    clock = [0.0]
    observed = []
    response = dict(protocol=transport.PROTOCOL, nonce="a" * 32, ok=True, result={"diagnostic": True})

    def write(raw, timeout):
        observed.append(("write", timeout))
        clock[0] = 2.25

    def read(timeout):
        observed.append(("read", timeout))
        receipt = transport._response_receipt(response)
        raw = transport.canonical(receipt)
        return struct.pack("!I", len(raw)) + raw

    monkeypatch.setattr(transport, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    transport._write_response_until_received(SimpleNamespace(write=write, read=read), response)
    assert observed == [("write", 3.0), ("read", .75)]


def test_receipt_binds_written_bytes_when_backend_owned_result_changes_after_write():
    response = dict(protocol=transport.PROTOCOL, nonce="c" * 32, ok=True,
                    result={"diagnostic": "before-write"})
    original = transport.canonical(response)

    def write(raw, timeout):
        assert raw == struct.pack("!I", len(original)) + original
        response["result"]["diagnostic"] = "changed-after-write"

    def read(timeout):
        receipt = dict(protocol=transport.PROTOCOL, nonce="c" * 32,
                       received_sha256=hashlib.sha256(original).hexdigest())
        raw = transport.canonical(receipt)
        return struct.pack("!I", len(raw)) + raw

    transport._write_response_until_received(SimpleNamespace(write=write, read=read), response)


def test_expired_response_write_does_not_open_an_extra_receipt_wait(monkeypatch):
    clock = [0.0]
    response = dict(protocol=transport.PROTOCOL, nonce="b" * 32, ok=True, result={})

    def write(raw, timeout):
        clock[0] = 3.0

    def read(timeout):
        pytest.fail("expired response budget was extended")

    monkeypatch.setattr(transport, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    with pytest.raises(TimeoutError, match="receipt deadline"):
        transport._write_response_until_received(SimpleNamespace(write=write, read=read), response)
