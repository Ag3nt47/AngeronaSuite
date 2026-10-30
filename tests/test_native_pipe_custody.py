"""Resource fault models only; no host service, endpoint or policy writes."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from angerona.core import native_pipe_custody as native


@pytest.fixture(autouse=True)
def fixture_holds(monkeypatch):
    monkeypatch.setattr(native, "_RETIREMENT_HOLDS", [])


@pytest.mark.parametrize("scenario", ["completed", "cancelled", "unknown-io", "event-close"])
def test_strict_pipe_keeps_event_overlapped_buffer_and_main_handle_until_known_retirement(monkeypatch, scenario):
    import pywintypes
    import win32event
    import win32file
    from angerona.core import live_debug
    class Handle:
        def __init__(self, event=False):
            self.event, self.closed, self.detached = event, 0, 0
        def Close(self):
            self.closed += 1
            if self.event and scenario == "event-close":
                raise RuntimeError("Simulated event CloseHandle ambiguity")
        def Detach(self):
            self.detached += 1
            return 101
    main, event = Handle(), Handle(True)
    monkeypatch.setattr(pywintypes, "OVERLAPPED", lambda: SimpleNamespace())
    monkeypatch.setattr(win32event, "CreateEvent", lambda *_args: event)
    monkeypatch.setattr(live_debug, "_cancel_pipe_io", lambda _handle: None)
    def result(_handle, _overlap, wait):
        if scenario == "unknown-io":
            raise pywintypes.error(6, "fixture", "unknown native ownership")
        if scenario == "cancelled":
            raise pywintypes.error(995 if wait else 996, "fixture", "cancelled or pending")
        return 0
    monkeypatch.setattr(win32file, "GetOverlappedResult", result)
    pipe = native.RetainedPipe(main)
    overlap = pipe._overlap()
    buffer = bytearray(b"retained fixture I/O bytes")
    pipe._io_owners[id(overlap)]["buffer"] = buffer
    if scenario in {"unknown-io", "event-close"}:
        with pytest.raises(PermissionError):
            pipe._retire_overlap(overlap)
        assert not pipe.close(0) and main.closed == 0
        assert pipe._io_owners[id(overlap)]["buffer"] is buffer
        assert pipe._io_owners[id(overlap)]["overlap"] is overlap
        assert event.closed == (1 if scenario == "event-close" else 0)
        assert any(owner is pipe for owner in native._RETIREMENT_HOLDS)
    else:
        pipe._retire_overlap(overlap)
        assert pipe.close(0) and event.closed == main.closed == 1 and not pipe._io_owners
        assert not native._RETIREMENT_HOLDS


def test_strict_pipe_rechecks_io_hold_after_waiting_for_owner_lock(monkeypatch):
    from angerona.core import live_debug
    handle = SimpleNamespace(Close=lambda: pytest.fail("Closed main handle beneath unproven I/O"))
    monkeypatch.setattr(live_debug, "_cancel_pipe_io", lambda _handle: None)
    pipe = native.RetainedPipe(handle)
    entered, finish = threading.Event(), threading.Event()
    def native_owner():
        with pipe._io_lock:
            entered.set()
            assert finish.wait(3)
            pipe._hold_io()
    thread = threading.Thread(target=native_owner)
    thread.start()
    result = []
    closer = threading.Thread(target=lambda: result.append(pipe.close(2)))
    try:
        assert entered.wait(2)
        closer.start()
    finally:
        finish.set()
        thread.join(3)
        closer.join(3)
    assert not thread.is_alive() and not closer.is_alive() and result == [False]


class ModelHandle:
    def __init__(self, bad=False):
        self.closed, self.detached, self.bad = 0, 0, bad
    def Close(self):
        self.closed += 1
        if self.bad:
            raise RuntimeError("Ambiguous native close fixture")
    def Detach(self):
        self.detached += 1
        return 123


@pytest.mark.parametrize("operation", ["connect", "read", "write"])
def test_unknown_native_admission_retains_exact_overlapped_event_and_buffer(monkeypatch, operation):
    import pywintypes
    import win32event
    import win32file
    import win32pipe
    from angerona.core import live_debug
    main, event = ModelHandle(), ModelHandle()
    buffer = bytearray(b"owned read fixture")
    stop = threading.Event()
    monkeypatch.setattr(pywintypes, "OVERLAPPED", lambda: SimpleNamespace())
    monkeypatch.setattr(win32event, "CreateEvent", lambda *_args: event)
    monkeypatch.setattr(live_debug, "_cancel_pipe_io", lambda _handle: None)
    monkeypatch.setattr(win32file, "AllocateReadBuffer", lambda _size: buffer)
    def unknown(*_args):
        raise RuntimeError("Unknown FFI admission fixture")
    def unproven(*_args):
        raise pywintypes.error(6, "fixture", "Unknown native operation retirement")
    monkeypatch.setattr(win32file, "GetOverlappedResult", unproven)
    monkeypatch.setattr(win32file, "ReadFile", unknown)
    monkeypatch.setattr(win32file, "WriteFile", unknown)
    monkeypatch.setattr(win32pipe, "ConnectNamedPipe", unknown)
    pipe = native.RetainedPipe(main, on_hold=stop.set)
    with pytest.raises(PermissionError, match="I/O retirement"):
        if operation == "connect":
            pipe._connect_server(1)
        elif operation == "read":
            pipe._read(1)
        else:
            pipe._write(b"retained write fixture", 1)
    assert stop.is_set() and pipe.retirement_held and not pipe.close(0)
    assert main.closed == event.closed == 0
    record = next(iter(pipe._io_owners.values()))
    assert record["overlap"].hEvent is event
    assert record["buffer"] is buffer if operation == "read" else record["buffer"] == b"retained write fixture" if operation == "write" else record["buffer"] is None
    assert native._RETIREMENT_HOLDS == [pipe]


@pytest.mark.parametrize("code", [0, 535])
def test_synchronous_or_already_connected_never_waits_on_unsubmitted_irp(monkeypatch, code):
    import pywintypes
    import win32event
    import win32pipe
    import win32file
    from angerona.core import live_debug
    main, event = ModelHandle(), ModelHandle()
    monkeypatch.setattr(pywintypes, "OVERLAPPED", lambda: SimpleNamespace())
    monkeypatch.setattr(win32event, "CreateEvent", lambda *_args: event)
    monkeypatch.setattr(win32pipe, "ConnectNamedPipe", lambda *_args: code)
    monkeypatch.setattr(win32file, "GetOverlappedResult", lambda *_args: pytest.fail("No IRP was submitted"))
    monkeypatch.setattr(live_debug, "_cancel_pipe_io", lambda _handle: None)
    pipe = native.RetainedPipe(main)
    pipe._connect_server(1)
    assert pipe.close(0) and main.closed == event.closed == 1


def test_main_handle_close_ambiguity_is_sticky_and_never_retried(monkeypatch):
    from angerona.core import live_debug
    main, stop = ModelHandle(True), threading.Event()
    monkeypatch.setattr(live_debug, "_cancel_pipe_io", lambda _handle: None)
    pipe = native.RetainedPipe(main, on_hold=stop.set)
    assert not pipe.close(0) and not pipe.close(0)
    assert main.closed == main.detached == 1 and stop.is_set()
    assert not pipe.close_proven and not pipe.cleanup_proven and pipe.retirement_held
    assert pipe._ambiguous_handle is main and pipe._discarded_number == 123
    assert native.native_pipe_retirement_held()
