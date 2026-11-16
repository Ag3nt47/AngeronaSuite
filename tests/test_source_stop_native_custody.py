"""Inert token/process adapters exercise close ownership without native calls."""
from __future__ import annotations

import gc
import sys
from types import ModuleType, SimpleNamespace
import weakref

import pytest

from angerona.resilience import source_stop as stop


@pytest.fixture
def native(tmp_path, monkeypatch):
    from angerona.core import privilege, windows_engine_custody, windows_process_lease

    state = SimpleNamespace(events=[], tokens=[], natives=[], next_handle=60000,
                            token_error=None, process_error=None, identity_error=None)
    identity = SimpleNamespace(pid=4242, birth_ticks=134000000000004242,
                               image=str(tmp_path / "python.exe"))
    class Token:
        def Close(self):
            state.events.append(("token-close", id(self)))
            if state.token_error is not None:
                raise state.token_error
    class Native:
        def __init__(self):
            state.natives.append(weakref.ref(self))
            self.api = SimpleNamespace(OpenProcess=lambda rights, inherit, pid:
                                       self.open(pid, rights, inherit))
            self.ctypes = SimpleNamespace(get_last_error=lambda: 87)
        def open(self, pid, rights, inherit):
            assert pid == identity.pid and rights == 0x101000 and inherit is False
            state.next_handle += 1
            state.events.append(("process-open", state.next_handle))
            return state.next_handle
        def identity(self, handle):
            state.events.append(("process-identity", handle))
            if state.identity_error is not None:
                raise state.identity_error
            return identity
        def wait(self, handle, milliseconds):
            assert milliseconds == 0
            state.events.append(("process-wait", handle))
            return True
        def close(self, handle):
            state.events.append(("process-close", handle))
            if state.process_error is not None:
                raise state.process_error
    def token(*_args):
        result = Token()
        state.tokens.append(weakref.ref(result))
        state.events.append(("token-open", id(result)))
        return result
    def module(name, **attributes):
        result = ModuleType(name)
        result.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, result)
        return result
    class WinError(OSError):
        winerror = 1008
    module("pywintypes", error=WinError)
    module("win32api", GetCurrentThread=lambda: "inert-thread",
           GetCurrentProcess=lambda: "inert-process")
    module("win32con", TOKEN_QUERY=8)
    info = {1: ("S-1-5-21-11-22-33-1001", 0), 2: 2,
            3: [("S-1-5-4", 0)], 4: 0}
    module("win32security", OpenThreadToken=token, OpenProcessToken=token,
           GetTokenInformation=lambda _token, kind: info[kind],
           ConvertSidToStringSid=lambda value: value,
           TokenUser=1, TokenSessionId=2, TokenGroups=3, TokenElevation=4)
    monkeypatch.setattr(stop, "os", SimpleNamespace(name="nt", getpid=lambda: identity.pid, environ={}))
    monkeypatch.setattr(stop.sys, "frozen", False, raising=False)
    monkeypatch.setattr(stop, "_NATIVE_CLOSE_HOLDS", [])
    monkeypatch.setattr(privilege, "_validated_watchdog_context", lambda _environment: {})
    monkeypatch.setattr(windows_engine_custody, "active_engine_custody", lambda: None)
    monkeypatch.setattr(windows_process_lease, "_Native", Native)
    state.identity = identity
    state.issuer = {"pid": identity.pid, "birth": identity.birth_ticks, "image": identity.image}
    return state


def _events(state, name):
    return tuple(value for operation, value in state.events if operation == name)


@pytest.mark.parametrize("process_fails", [False, True])
def test_token_close_failure_still_attempts_process_cleanup_and_retains_owners(native, process_fails):
    native.token_error = OSError("inert token close acknowledgement lost")
    if process_fails:
        native.process_error = OSError("inert process close acknowledgement lost")
    assert stop._effective_identity() is None
    assert len(_events(native, "token-close")) == 1
    assert _events(native, "process-close") == _events(native, "process-open")
    assert [hold.operation for hold in stop._NATIVE_CLOSE_HOLDS] == (
        ["token", "process"] if process_fails else ["token"])
    held = stop._NATIVE_CLOSE_HOLDS[0]
    assert held.token is native.tokens[0]() and held.native is native.natives[0]()
    assert held.handle == _events(native, "process-open")[0]
    gc.collect()
    assert native.tokens[0]() is held.token and native.natives[0]() is held.native
    assert len(_events(native, "token-close")) == 1


def test_process_close_failure_retains_exact_adapter_and_handle_without_retry(native):
    native.process_error = OSError("inert process close acknowledgement lost")
    assert stop._effective_identity() is None
    held, = stop._NATIVE_CLOSE_HOLDS
    assert held.operation == "process"
    assert held.token is native.tokens[0]() and held.native is native.natives[0]()
    assert held.handle == _events(native, "process-open")[0]
    before = tuple(native.events)
    native.token_error = native.process_error = None  # Uncertainty remains sticky.
    for _ in range(12):
        assert stop._effective_identity() is None
        assert stop._closing_core_exited(native.issuer) is None
        assert not stop.source_runtime_admitted()
    assert tuple(native.events) == before
    gc.collect()
    assert native.natives[0]() is held.native and native.tokens[0]() is held.token
    assert _events(native, "process-close") == (held.handle,)


def test_token_close_failure_stops_future_admission_probes_from_opening_more(native):
    native.token_error = OSError("inert token close failure")
    assert stop._effective_identity() is None
    before = tuple(native.events)
    native.token_error = None
    for _ in range(12):
        assert stop._effective_identity() is None
        assert stop._closing_core_exited(native.issuer) is None
    assert tuple(native.events) == before


def test_retirement_probe_close_failure_preserves_native_owner_and_never_claims_exit(native):
    native.process_error = OSError("inert retirement close acknowledgement lost")
    assert stop._closing_core_exited(native.issuer) is None
    held, = stop._NATIVE_CLOSE_HOLDS
    assert held.operation == "retirement-process" and held.token is None
    assert held.native is native.natives[0]()
    assert held.handle == _events(native, "process-open")[0]
    before = tuple(native.events)
    native.process_error = None
    for _ in range(12):
        assert stop._closing_core_exited(native.issuer) is None
        assert stop._effective_identity() is None
    assert tuple(native.events) == before
    gc.collect()
    assert native.natives[0]() is held.native


def test_successful_native_probes_close_each_owner_and_do_not_poison_admission(native):
    first = stop._effective_identity()
    second = stop._effective_identity()
    assert first == second and stop._valid_identity(first)
    assert len(_events(native, "token-close")) == 2
    assert _events(native, "process-close") == _events(native, "process-open")
    assert stop._NATIVE_CLOSE_HOLDS == []
    assert stop._closing_core_exited(native.issuer) is True
    assert stop._NATIVE_CLOSE_HOLDS == []


def test_interrupted_token_close_still_cleans_process_then_preserves_interrupt(native):
    native.token_error = KeyboardInterrupt("inert interrupted close")
    with pytest.raises(KeyboardInterrupt, match="inert interrupted close"):
        stop._effective_identity()
    assert len(_events(native, "token-close")) == 1
    assert _events(native, "process-close") == _events(native, "process-open")
    held, = stop._NATIVE_CLOSE_HOLDS
    assert held.operation == "token" and held.token is native.tokens[0]()
    assert stop._effective_identity() is None


def test_process_cleanup_failure_does_not_erase_an_original_probe_interrupt(native):
    native.identity_error = KeyboardInterrupt("inert interrupted query")
    native.process_error = OSError("inert process close acknowledgement lost")
    with pytest.raises(KeyboardInterrupt, match="inert interrupted query"):
        stop._effective_identity()
    assert len(_events(native, "token-close")) == 1
    assert _events(native, "process-close") == _events(native, "process-open")
    held, = stop._NATIVE_CLOSE_HOLDS
    assert held.operation == "process" and held.native is native.natives[0]()


def test_ordinary_protocol_fixture_can_still_replace_the_single_identity_probe(native, monkeypatch):
    native.process_error = OSError("inert close failure")
    assert stop._effective_identity() is None and stop._NATIVE_CLOSE_HOLDS
    fixture_identity = stop._Identity("S-1-5-21-11-22-33-1001", 2,
                                     native.identity.pid, native.identity.birth_ticks,
                                     native.identity.image)
    monkeypatch.setattr(stop, "_effective_identity", lambda: fixture_identity)
    assert stop.source_runtime_admitted()
