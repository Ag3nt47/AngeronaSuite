"""Shared native handle/OS peer resource faults; no installed authority."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from angerona.core import native_broker_custody as native
from angerona.core import native_pipe_custody


@pytest.fixture(autouse=True)
def fixture_holds(monkeypatch):
    monkeypatch.setattr(native, "_RETIREMENT_HOLDS", [])
    monkeypatch.setattr(native_pipe_custody, "_RETIREMENT_HOLDS", [])


def test_native_custody_closes_other_handles_independently_and_never_retries_uncertainty():
    class Handle:
        def __init__(self, bad=False):
            self.bad, self.closed, self.detached = bad, 0, 0
        def Close(self):
            self.closed += 1
            if self.bad:
                raise RuntimeError("Ambiguous native close fixture")
        def Detach(self):
            self.detached += 1
            return 123
    good, bad = Handle(), Handle(True)
    owner = native.NativeCustodyOwner()
    owner.add(good)
    owner.add(bad)
    assert not owner.close() and not owner.close()
    assert good.closed == bad.closed == 1 and bad.detached == 1
    assert native._RETIREMENT_HOLDS == [owner]
    with pytest.raises(PermissionError):
        native.NativeCustodyOwner()



@pytest.mark.parametrize("failed", ["token", "process"])
def test_strict_peer_capture_closes_all_known_handles_and_holds_ambiguous_native_owner(monkeypatch, failed):
    import win32api
    import win32event
    import win32pipe
    import win32process
    import win32security
    calls = []
    class Handle:
        def __init__(self, kind):
            self.kind = kind
        def Close(self):
            calls.append(self.kind)
            if self.kind == failed:
                raise RuntimeError("Simulated peer CloseHandle ambiguity")
        def Detach(self):
            return 101
    token, process = Handle("token"), Handle("process")
    user = win32security.ConvertStringSidToSid("S-1-5-21-100-200-300-1")
    logon = win32security.ConvertStringSidToSid("S-1-5-5-1-2")
    monkeypatch.setattr(native.wire, "_impersonate", lambda _handle: None)
    monkeypatch.setattr(native.wire, "_revert", lambda: calls.append("revert"))
    monkeypatch.setattr(win32security, "OpenThreadToken", lambda *_args: token)
    def info(_token, kind):
        if kind == win32security.TokenUser:
            return user, 0
        if kind == win32security.TokenGroups:
            return [(logon, 0xC0000000)]
        return {"AuthenticationId": "fixture-auth"}
    monkeypatch.setattr(win32security, "GetTokenInformation", info)
    monkeypatch.setattr(win32api, "OpenProcess", lambda *_args: process)
    monkeypatch.setattr(win32pipe, "GetNamedPipeClientProcessId", lambda _handle: 1234)
    monkeypatch.setattr(win32process, "GetProcessTimes", lambda _process: {"CreationTime": SimpleNamespace(timestamp=lambda: 100.0)})
    monkeypatch.setattr(win32event, "WaitForSingleObject", lambda *_args: 258)
    with pytest.raises(PermissionError, match="cleanup"):
        native._capture_native_peer(object())
    assert calls == ["revert", "process", "token"]
    owner = native._RETIREMENT_HOLDS[0]
    assert owner.rows[0]["handle"] is token and owner.rows[1]["handle"] is process
    assert not owner.close() and calls == ["revert", "process", "token"]


def test_overlapping_native_close_cannot_report_clean_before_first_close_finishes():
    entered, finish = threading.Event(), threading.Event()
    calls = []
    def pending_close():
        calls.append(1)
        entered.set()
        assert finish.wait(3)
    owner = native.NativeCustodyOwner()
    handle = SimpleNamespace(Close=pending_close)
    owner.add(handle)
    result = []
    thread = threading.Thread(target=lambda: result.append(owner.close()))
    thread.start()
    try:
        assert entered.wait(2)
        assert not owner.close()
    finally:
        finish.set()
        thread.join(3)
    assert not thread.is_alive() and result == [False] and calls == [1]
    assert not owner.close() and native._RETIREMENT_HOLDS == [owner]


def test_native_open_reservation_survives_overlapping_stop_before_handle_publication():
    entered, finish = threading.Event(), threading.Event()
    closed, errors = [], []
    handle = SimpleNamespace(Close=lambda: closed.append(1))
    def opener():
        entered.set()
        assert finish.wait(3)
        return handle
    owner = native.NativeCustodyOwner()
    def open_reserved():
        try:
            owner.open(opener)
        except PermissionError:
            errors.append(1)
    thread = threading.Thread(target=open_reserved)
    thread.start()
    try:
        assert entered.wait(2)
        assert not owner.close()
    finally:
        finish.set()
        thread.join(3)
    assert not thread.is_alive() and errors == [1] and owner.rows[0]["handle"] is handle
    assert not owner.close() and not owner.close() and closed == [1]
    assert native._RETIREMENT_HOLDS == [owner]


def test_unknown_native_open_failure_never_allows_replacement_or_clean_close():
    owner = native.NativeCustodyOwner()
    def unknown():
        raise RuntimeError("Simulated unknown native open admission")
    with pytest.raises(RuntimeError):
        owner.open(unknown)
    assert not owner.close() and owner._pending_open[0] is unknown
    with pytest.raises(PermissionError):
        native.NativeCustodyOwner()


def test_revert_to_self_failure_is_fatal_and_sticky_even_after_token_close(monkeypatch):
    import win32security
    closed = []
    token = SimpleNamespace(Close=lambda: closed.append(1))
    user = win32security.ConvertStringSidToSid("S-1-5-21-100-200-300-1")
    logon = win32security.ConvertStringSidToSid("S-1-5-5-1-2")
    monkeypatch.setattr(native.wire, "_impersonate", lambda _handle: None)
    def unknown_revert():
        raise RuntimeError("Simulated unknown RevertToSelf completion")
    monkeypatch.setattr(native.wire, "_revert", unknown_revert)
    monkeypatch.setattr(win32security, "OpenThreadToken", lambda *_args: token)
    def info(_token, kind):
        return (user, 0) if kind == win32security.TokenUser else [(logon, 0xC0000000)] if kind == win32security.TokenGroups else {"AuthenticationId": "fixture"}
    monkeypatch.setattr(win32security, "GetTokenInformation", info)
    with pytest.raises(native.wire.PeerAuthenticationError) as error:
        native._capture_native_peer(object())
    assert error.value.fatal and closed == [1] and native.native_broker_retirement_held()
    assert native._RETIREMENT_HOLDS[0].rows[0]["handle"] is token


def test_server_stop_during_native_startup_never_closes_beneath_handle_publication(monkeypatch):
    import win32pipe
    from angerona.core import live_debug
    entered, finish = threading.Event(), threading.Event()
    closed, opened, errors = [], [], []
    handle = SimpleNamespace(Close=lambda: closed.append(1))
    def native_open(*_args):
        opened.append(1)
        entered.set()
        assert finish.wait(3)
        assert closed == []
        return handle
    monkeypatch.setattr(win32pipe, "CreateNamedPipe", native_open)
    monkeypatch.setattr(native.wire, "_attributes", lambda *_args: None)
    monkeypatch.setattr(live_debug, "_cancel_pipe_io", lambda _handle: None)
    subject = "S-1-5-21-100-200-300-1"
    server = native.RetainedBrokerPipeServer(lambda *_args: pytest.fail("Stopped startup dispatched"),
        server_sid=subject, allowed_sids=[subject], endpoint=r"\\.\pipe\Angerona.Modeled.Startup")
    def start():
        try:
            server.start()
        except PermissionError:
            errors.append(1)
    worker = threading.Thread(target=start)
    worker.start()
    try:
        assert entered.wait(2)
        assert not server.stop(0) and closed == []
    finally:
        finish.set()
        worker.join(3)
    assert not worker.is_alive() and errors == [1]
    assert opened == closed == [1] and not server.threads
    assert not server.stop(0) and native._RETIREMENT_HOLDS == [server]
