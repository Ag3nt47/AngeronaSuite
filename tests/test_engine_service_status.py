"""Closed service status catalog and an isolated native pipe, never SCM install."""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import threading
from types import SimpleNamespace
import uuid

import pytest

from angerona.core import engine_service_status as status
from angerona.core import headless, windows_engine_custody
from angerona.core import native_pipe_custody
from angerona.core import native_broker_custody
from angerona.core.privileged_pipe import NativePeer

USER = "S-1-5-21-100-200-300-1001"
OTHER = "S-1-5-21-100-200-300-1002"


@pytest.fixture
def isolated_modeled_pipe_holds(monkeypatch):
    # Fault models retain inert owners only; restore the real registry on exit.
    monkeypatch.setattr(native_pipe_custody, "_RETIREMENT_HOLDS", [])
    monkeypatch.setattr(native_broker_custody, "_RETIREMENT_HOLDS", [])


@pytest.fixture
def control(monkeypatch):
    custody = SimpleNamespace(root=Path("modeled-private-service"), service_sid="S-1-5-80-1-2-3-4-5")
    monkeypatch.setattr(status, "active_engine_custody", lambda: custody)
    monkeypatch.setattr(status, "_RETIREMENT_HOLD", None)
    users = {USER}
    instance = status.ServiceStatusControl(custody, _read_policy=lambda _owner: frozenset(users))
    instance.attach(SimpleNamespace(modules={
        "one": SimpleNamespace(enabled=True, status="running"),
        "two": SimpleNamespace(enabled=True, status="degraded"),
        "three": SimpleNamespace(enabled=False, status="stopped"),
    }), None, SimpleNamespace(runtime_chill_active=True), None)
    try:
        yield instance, users, custody
    finally:
        instance.close()


def peer(user=USER):
    return NativePeer(user, "S-1-5-5-1-2", "123", 4321, 1.0)


def test_only_bounded_counts_cross_the_service_boundary(control):
    instance, _users, _custody = control
    instance.ready()
    result = instance.dispatch({"operation": "status"}, peer())
    assert result["modules"] == dict(discovered=3, sampled=3, truncated=False, enabled=2, running=1)
    assert result["mode"] == "chill"
    assert result["authority"] == result["mutating_operations"] == []
    assert result["protection_verified"] is False
    assert result["event_text_available"] is result["storage_access_available"] is False
    assert len(status.canonical(result)) < status.MAX_STATUS


@pytest.mark.parametrize("message", [
    {"operation": "events"}, {"operation": "settings"}, {"operation": "settings_patch", "settings": {}},
    {"operation": "stop_engine"}, {"operation": "module_enable", "name": "one", "enabled": False},
    {"operation": "status", "path": "bus.key"}, {"operation": "sql", "query": "SELECT * FROM events"},
])
def test_authenticated_os_user_never_gets_generic_control_or_storage(control, message):
    instance, _users, _custody = control
    with pytest.raises(PermissionError):
        instance.dispatch(message, peer())


def test_revocation_and_stopped_custody_apply_to_each_request(control, monkeypatch):
    instance, users, _custody = control
    assert instance.dispatch({"operation": "status"}, peer())["state"] == "starting"
    users.clear()
    with pytest.raises(PermissionError, match="revoked"):
        instance.dispatch({"operation": "status"}, peer())
    users.add(USER)
    monkeypatch.setattr(status, "active_engine_custody", lambda: None)
    with pytest.raises(PermissionError):
        instance.dispatch({"operation": "status"}, peer())


def test_sampling_is_bounded_and_says_when_the_module_view_is_partial(control):
    instance, _users, _custody = control
    instance._manager.modules = {str(index): SimpleNamespace(enabled=True, status="running")
                                 for index in range(status.MAX_MODULES + 5)}
    result = instance.dispatch({"operation": "status"}, peer())
    assert result["modules"]["sampled"] == result["modules"]["running"] == status.MAX_MODULES
    assert result["modules"]["discovered"] == status.MAX_MODULES + 5
    assert result["modules"]["truncated"] is True


def test_missing_enrollment_or_squatted_status_pipe_does_not_prevent_protection(control):
    instance, _users, _custody = control
    def absent(_owner):
        raise FileNotFoundError("inert absent enrollment")
    instance._read_policy = absent
    assert instance.start() is False and instance.transport_state == "policy-unavailable"
    instance._read_policy = lambda _owner: frozenset({USER})
    calls = []
    class Squatted:
        def start(self):
            raise OSError("inert first-instance pipe already exists")
        def stop(self):
            calls.append("retired")
            return True
    instance._server_factory = lambda *_a, **_k: Squatted()
    assert instance.start() is False and instance.transport_state == "transport-unavailable"
    assert calls == ["retired"]


@pytest.mark.parametrize("failure", ["false", "raise"])
def test_pending_native_shutdown_cannot_be_reported_clean_by_a_second_close(control, failure):
    instance, _users, _custody = control
    calls = []
    def stop():
        calls.append("stop")
        if failure == "raise":
            raise OSError("inert owned-stop failure")
        return False
    instance._server = SimpleNamespace(stop=stop)
    for _ in range(2):
        with pytest.raises(RuntimeError, match="retirement remains unproven"):
            instance.close()
    assert calls == ["stop"]
    assert instance._server is not None and status._RETIREMENT_HOLD is instance
    instance._server = None  # Only the inert failed owner's expected diagnostic.
    instance._retirement_error = False  # The expected inert fixture diagnostic only.


@pytest.mark.parametrize("failure", ["false", "raise"])
def test_failed_start_retains_its_unretired_owner_and_blocks_replacement(control, failure):
    instance, _users, _custody = control
    calls = []
    class Unretired:
        def start(self):
            raise OSError("inert partial start")
        def stop(self):
            calls.append("stop")
            if failure == "raise":
                raise OSError("inert partial-stop failure")
            return False
    server = Unretired()
    instance._server_factory = lambda *_a, **_k: server
    with pytest.raises(RuntimeError, match="startup I/O retirement"):
        instance.start()
    assert instance._server is server and status._RETIREMENT_HOLD is instance
    with pytest.raises(RuntimeError, match="retirement remains unproven"):
        instance.close()
    with pytest.raises(RuntimeError, match="owner is already"):
        instance.start()
    assert calls == ["stop"]
    instance._server = None  # Inert fixture cleanup, never a native retirement claim.
    instance._retirement_error = False


@pytest.mark.parametrize("stage", ["startup", "request"])
def test_policy_close_uncertainty_fences_control_and_stops_listener_without_claiming_cleanup(control, monkeypatch, stage):
    instance, _users, _custody = control
    monkeypatch.setattr(status, "_POLICY_RETIREMENT_HOLD", ())
    reads, stops = [], []
    def policy(_owner):
        reads.append(True)
        if stage == "startup" or len(reads) > 1:
            status._POLICY_RETIREMENT_HOLD = (object(),)  # Inert ambiguous owner.
            raise PermissionError("inert policy handle retirement remains unproven")
        return frozenset({USER})
    instance._read_policy = policy
    instance._server_factory = lambda *_a, **_k: SimpleNamespace(
        start=lambda: None, stop=lambda: stops.append(True) or True)
    try:
        if stage == "startup":
            assert instance.start() is False  # Protection can still start.
        else:
            assert instance.start()
            with pytest.raises(PermissionError):
                instance.dispatch({"operation": "status"}, peer())
        assert instance._retirement_error and status._RETIREMENT_HOLD is instance
        for _ in range(2):
            with pytest.raises(RuntimeError, match="retirement remains unproven"):
                instance.close()
        assert stops == ([] if stage == "startup" else [True])
    finally:
        status._POLICY_RETIREMENT_HOLD = ()  # Inert fixture diagnostics only.
        instance._retirement_error = False


def test_ambiguous_pipe_close_never_becomes_a_clean_second_close(isolated_modeled_pipe_holds):
    calls = []
    class Handle:
        def Close(self):
            calls.append("close")
            raise OSError("inert ambiguous native close")
        def Detach(self):
            calls.append("detach")
    pipe = status._ServiceStatusPipe(Handle())
    pipe.cancel = lambda: None  # Inert handle never reaches CancelIoEx/Win32.
    assert pipe.close() is False and pipe.close() is False
    assert calls == ["close", "detach"] and pipe.close_proven is False


@pytest.mark.skipif(os.name != "nt", reason="Modeled overlapped APIs; no handle reaches Windows")
@pytest.mark.parametrize("failure", ["event-close", "unknown-io"])
def test_auxiliary_native_uncertainty_retains_status_pipe_client_and_listener(monkeypatch, failure, isolated_modeled_pipe_holds):
    import pywintypes
    import win32event
    import win32file

    calls = []
    class Handle:
        def Close(self):
            calls.append("main-close")
        def Detach(self):
            calls.append("main-detach")
    class Event:
        def Close(self):
            calls.append("event-close")
            if failure == "event-close":
                raise OSError("modeled ambiguous event close")
        def Detach(self):
            calls.append("event-detach")
            return 123  # Diagnostic number only; never passed to Windows.
    def result(*_args):
        if failure == "unknown-io":
            error = OSError("modeled unknown IRP retirement")
            error.winerror = 6
            raise error
        return 0
    event, buffer = Event(), bytearray(b"inert owned buffer")
    monkeypatch.setattr(pywintypes, "OVERLAPPED", lambda: SimpleNamespace(hEvent=None))
    monkeypatch.setattr(win32event, "CreateEvent", lambda *_a: event)
    monkeypatch.setattr(win32file, "AllocateReadBuffer", lambda _size: buffer)
    monkeypatch.setattr(win32file, "ReadFile", lambda *_a: (0, buffer))
    monkeypatch.setattr(win32file, "GetOverlappedResult", result)
    server = status._ServiceStatusPipeServer(lambda *_a: {}, server_sid=USER, allowed_sids={USER})
    pipe = status._ServiceStatusPipe(Handle(), on_hold=server._native_hold)
    pipe.cancel = lambda: pipe.closed.set()
    pipe._wait = lambda *_a: 0
    server.pipes.append(pipe)
    from angerona.core.live_debug import LiveDebugError
    with pytest.raises(LiveDebugError):
        pipe.read(.1)
    assert pipe.retirement_held and not pipe.cleanup_proven
    assert native_pipe_custody._RETIREMENT_HOLDS == [pipe]
    record, = pipe._io_owners.values()
    assert record["buffer"] is buffer and record["overlap"].hEvent is event
    assert server.stop_event.is_set() and "unproven" in server.error
    assert pipe.close(timeout=0) is False and pipe.close(timeout=0) is False
    assert "main-close" not in calls
    assert calls.count("event-close") == (1 if failure == "event-close" else 0)
    native = status._ServiceStatusNativeClient(endpoint=status.ENDPOINT, _server_verifier=lambda *_a: None)
    client = object.__new__(status.EngineServiceStatusClient)
    client._client = native
    assert client.cleanup_proven is False and client.cleanup_state == "unproven"
    with pytest.raises(status.ServiceClientCleanupError):
        client.status()
    with pytest.raises((PermissionError, status.BrokerPipeError)):
        status._ServiceStatusPipeServer(lambda *_a: {}, server_sid=USER, allowed_sids={USER}).start()


@pytest.mark.skipif(os.name != "nt", reason="Modeled captured OS identity handles, no native token reads")
@pytest.mark.parametrize("failure", ["token", "process"])
def test_status_listener_never_dispatches_peer_with_unproven_native_handle_retirement(monkeypatch, failure, isolated_modeled_pipe_holds):
    import win32api
    import win32pipe
    import win32process
    import win32security
    import win32event
    from angerona.core import privileged_pipe as wire

    calls, dispatched = [], []
    class Handle:
        def __init__(self, name):
            self.name = name
        def Close(self):
            calls.append(self.name + "-close")
            if self.name == failure:
                raise OSError("modeled native identity close uncertainty")
        def Detach(self):
            calls.append(self.name + "-detach")
            return 99  # Never used as a native handle.
    token, process = Handle("token"), Handle("process")
    monkeypatch.setattr(wire, "_impersonate", lambda _handle: calls.append("impersonate"))
    monkeypatch.setattr(wire, "_revert", lambda: calls.append("revert"))
    monkeypatch.setattr(win32api, "GetCurrentThread", lambda: "inert-thread")
    monkeypatch.setattr(win32security, "OpenThreadToken", lambda *_a: token)
    original_convert = win32security.ConvertSidToStringSid
    monkeypatch.setattr(win32security, "ConvertSidToStringSid",
        lambda value: value if type(value) is str else original_convert(value))
    def information(_token, kind):
        if kind == win32security.TokenUser:
            return USER, 0
        if kind == win32security.TokenGroups:
            return [("S-1-5-5-1-2", 0xC0000000)]
        return {"AuthenticationId": "123"}
    monkeypatch.setattr(win32security, "GetTokenInformation", information)
    monkeypatch.setattr(win32pipe, "GetNamedPipeClientProcessId", lambda _handle: 42)
    monkeypatch.setattr(win32api, "OpenProcess", lambda *_a: process)
    monkeypatch.setattr(win32process, "GetProcessTimes", lambda _handle: {"CreationTime": SimpleNamespace(timestamp=lambda: 1.0)})
    monkeypatch.setattr(win32event, "WaitForSingleObject", lambda *_a: 258)
    monkeypatch.setattr(wire, "_read_frame", lambda _pipe: dict(protocol=wire.PROTOCOL, nonce="a" * 32, request={"operation": "status"}))
    monkeypatch.setattr(wire, "_write_response_until_received", lambda *_a: pytest.fail("Unretired peer reached status response"))
    server = status._ServiceStatusPipeServer(lambda *_a: dispatched.append(True), server_sid=USER, allowed_sids={USER})
    pipe = SimpleNamespace(handle="inert-pipe", connect_server=lambda _timeout: None,
        close=lambda *_args, **_kw: True, cancel=lambda: None)
    server.pipes.append(pipe)
    server._serve(pipe)
    assert dispatched == [] and server.stop_event.is_set()
    assert calls.index("revert") < calls.index("process-close") < calls.index("token-close")
    assert calls.count("process-close") == calls.count("token-close") == 1
    assert native_broker_custody.native_broker_retirement_held() and not server.stop()
    original = list(calls)
    assert not server.stop() and calls == original
    client = status.EngineServiceStatusClient()
    assert not client.cleanup_proven and client.cleanup_state == "unproven"
    with pytest.raises(status.ServiceClientCleanupError):
        client.status()


def test_shared_native_hold_rejects_control_replacement_and_retains_current_server(monkeypatch, isolated_modeled_pipe_holds):
    custody = SimpleNamespace(root=Path("inert"), service_sid=USER)
    monkeypatch.setattr(status, "active_engine_custody", lambda: custody)
    monkeypatch.setattr(status, "_RETIREMENT_HOLD", None)
    native_pipe_custody._RETIREMENT_HOLDS.append(object())  # Inert explicit fault model.
    owner = status.ServiceStatusControl(custody, _read_policy=lambda _owner: {USER})
    server = SimpleNamespace(stop=lambda: True)
    owner._server = server
    with pytest.raises(RuntimeError, match="retirement remains unproven"):
        owner.close()
    assert status._RETIREMENT_HOLD is owner and owner._retirement_error
    # Even a clean server result cannot establish process-wide native cleanup.
    with pytest.raises(RuntimeError):
        status.ServiceStatusControl(custody, _read_policy=lambda _owner: {USER}).start()


@pytest.mark.skipif(os.name != "nt", reason="Modeled terminal cancellation, no native handles")
def test_known_cancelled_irp_closes_event_and_main_once_without_false_hold(monkeypatch, isolated_modeled_pipe_holds):
    import pywintypes
    import win32event
    import win32file

    calls = []
    class Handle:
        def __init__(self, name):
            self.name = name
        def Close(self):
            calls.append(self.name)
    event = Handle("event")
    monkeypatch.setattr(pywintypes, "OVERLAPPED", lambda: SimpleNamespace(hEvent=None))
    monkeypatch.setattr(win32event, "CreateEvent", lambda *_a: event)
    monkeypatch.setattr(win32file, "AllocateReadBuffer", lambda _size: bytearray(8))
    monkeypatch.setattr(win32file, "ReadFile", lambda *_a: (0, b""))
    def cancelled(*_a):
        error = OSError("modeled terminal ERROR_OPERATION_ABORTED")
        error.winerror = 995
        raise error
    monkeypatch.setattr(win32file, "GetOverlappedResult", cancelled)
    pipe = status._ServiceStatusPipe(Handle("main"))
    pipe.cancel = lambda: pipe.closed.set()
    def timeout(*_a):
        raise TimeoutError("inert I/O deadline")
    pipe._wait = timeout
    with pytest.raises(TimeoutError):
        pipe.read(.1)
    assert not pipe._io_owners and not native_pipe_custody.native_pipe_retirement_held()
    assert pipe.close(timeout=0) and pipe.close(timeout=0) and pipe.cleanup_proven
    assert calls == ["event", "main"]


@pytest.mark.skipif(os.name != "nt", reason="Modeled native handle admission, no handle reaches Windows")
@pytest.mark.parametrize("failure", ["pipe", "process"])
def test_client_unknown_native_open_retains_admission_and_rejects_cleanup_claim(monkeypatch, failure, isolated_modeled_pipe_holds):
    import win32api
    import win32file
    import win32pipe

    calls = []
    class Handle:
        def Close(self):
            calls.append("pipe-close")
    class Pipe:
        def __init__(self, handle):
            self.handle = handle
        def close(self, timeout):
            self.handle.Close()
            return True
    def create(*_a):
        calls.append("pipe-open")
        if failure == "pipe":
            raise OSError("modeled unknown FFI return before handle publication")
        return Handle()
    def process(*_a):
        calls.append("process-open")
        raise OSError("modeled unknown process admission")
    monkeypatch.setattr(win32pipe, "WaitNamedPipe", lambda *_a: None)
    monkeypatch.setattr(win32file, "CreateFile", create)
    monkeypatch.setattr(win32pipe, "GetNamedPipeServerProcessId", lambda _handle: 42)
    monkeypatch.setattr(win32api, "OpenProcess", process)
    monkeypatch.setattr(status, "_ServiceStatusPipe", Pipe)
    monkeypatch.setattr(status, "_CLIENT_RETIREMENT_HOLDS", [])
    monkeypatch.setattr(status, "_CLIENT_SLOTS", threading.BoundedSemaphore(1))
    client = status.EngineServiceStatusClient()
    with pytest.raises(status.ServiceClientCleanupError):
        client.status()
    assert not client.cleanup_proven and client.cleanup_state == "unproven"
    owner, = native_broker_custody._RETIREMENT_HOLDS
    assert owner.uncertain and owner._pending_open is not None
    assert calls.count("pipe-close") == (1 if failure == "process" else 0)
    original = list(calls)
    with pytest.raises(status.ServiceClientCleanupError):
        client.status()
    assert calls == original


@pytest.mark.parametrize("failure", ["pipe", "process", "verifier"])
def test_client_retains_native_close_uncertainty_and_never_retries_or_replaces_it(monkeypatch, failure):
    monkeypatch.setattr(status, "_CLIENT_RETIREMENT_HOLDS", [])
    calls = []
    class Pipe:
        def close(self, timeout):
            assert timeout == 3.0
            calls.append("pipe-close")
            return failure != "pipe"
    class Process:
        def Close(self):
            calls.append("process-close")
            if failure == "process":
                raise OSError("inert process handle close uncertainty")
        def Detach(self):
            calls.append("process-detach")
            raise OSError("inert detach uncertainty")
    native = status._ServiceStatusNativeClient(endpoint=status.ENDPOINT, _server_verifier=lambda *_a: None)
    native._pipe, native._process = Pipe(), Process()
    native._verifier_unproven = failure == "verifier"
    client = object.__new__(status.EngineServiceStatusClient)
    client._client = native
    assert native._finish_owned_request() is False
    original = tuple(calls)
    assert native._finish_owned_request() is False and tuple(calls) == original
    assert client.cleanup_proven is False and client.cleanup_state == "unproven"
    assert status._CLIENT_RETIREMENT_HOLDS == [native]
    with pytest.raises(status.ServiceClientCleanupError, match="held"):
        client.status()
    assert tuple(calls) == original
    assert native._pipe is not None if failure == "pipe" else native._pipe is None
    assert native._process is not None if failure == "process" else native._process is None


@pytest.mark.skipif(os.name != "nt", reason="Modeled Win32 seams, no numeric handle reaches Windows")
@pytest.mark.parametrize("variation", ["valid", "wrong-nonce", "verifier-refused"])
def test_strict_client_keeps_server_proof_nonce_and_retirement_before_return(monkeypatch, variation):
    import win32api
    import win32file
    import win32pipe
    import win32process
    import win32event

    monkeypatch.setattr(status, "_CLIENT_RETIREMENT_HOLDS", [])
    calls, writes = [], []
    class Handle:
        def Close(self):
            calls.append("process-close")
    process, raw = Handle(), object()
    class Pipe:
        def __init__(self, handle):
            assert handle is raw
        def close(self, timeout):
            calls.append("pipe-close")
            return True
    monkeypatch.setattr(win32pipe, "WaitNamedPipe", lambda *_a: None)
    monkeypatch.setattr(win32file, "CreateFile", lambda *_a: raw)
    monkeypatch.setattr(status, "_ServiceStatusPipe", Pipe)
    monkeypatch.setattr(win32pipe, "GetNamedPipeServerProcessId", lambda handle: 77)
    monkeypatch.setattr(win32api, "OpenProcess", lambda rights, inherit, pid:
        process if (rights, inherit, pid) == (0x101000, False, 77) else pytest.fail("Wrong process rights"))
    monkeypatch.setattr(win32process, "GetProcessTimes", lambda _handle:
        {"CreationTime": SimpleNamespace(timestamp=lambda: 1000.0)})
    monkeypatch.setattr(win32event, "WaitForSingleObject", lambda *_a: 258)
    monkeypatch.setattr(status, "_write_frame", lambda _pipe, value, _timeout:
        writes.append(value) if "verified" in calls else pytest.fail("Payload preceded native server proof"))
    def response(_pipe, _timeout):
        return dict(protocol=status.PROTOCOL, nonce="0" * 32 if variation == "wrong-nonce" else writes[0]["nonce"],
                    ok=True, result={"inert": True})
    monkeypatch.setattr(status, "_read_frame", response)
    def verify(_process, pid):
        assert _process is process and pid == 77
        if variation == "verifier-refused":
            raise PermissionError("inert untrusted service")
        calls.append("verified")
    native = status._ServiceStatusNativeClient(endpoint=status.ENDPOINT, _server_verifier=verify)
    if variation == "valid":
        assert native.exchange({"operation": "status"}) == {"inert": True}
        assert len(writes) == 2 and "received_sha256" in writes[1]
    else:
        with pytest.raises((PermissionError, status.BrokerPipeError)):
            native.exchange({"operation": "status"})
        assert len(writes) == (0 if variation == "verifier-refused" else 1)
    assert calls[-2:] == ["pipe-close", "process-close"]
    assert native.cleanup_proven is True and not native._poisoned


@pytest.mark.parametrize("detach_fails", [False, True])
def test_policy_handle_close_uncertainty_retains_owner_and_prevents_further_opens(monkeypatch, detach_fails):
    monkeypatch.setattr(status, "_POLICY_RETIREMENT_HOLD", ())
    calls = []
    class Handle:
        def __init__(self, name, fails):
            self.name, self.fails = name, fails
        def Close(self):
            calls.append((self.name, "close"))
            if self.fails:
                raise OSError("inert native file close uncertainty")
        def Detach(self):
            calls.append((self.name, "detach"))
            if detach_fails:
                raise OSError("inert detach uncertainty")
    primary, named = Handle("primary", False), Handle("named", True)
    with pytest.raises(PermissionError, match="retirement remains unproven"):
        status._close_policy_handles([primary, named])
    assert status._POLICY_RETIREMENT_HOLD == (named,)
    assert calls == [("named", "close"), ("named", "detach"), ("primary", "close")]
    with pytest.raises(PermissionError, match="retirement is held"):
        status.read_console_policy(SimpleNamespace(root="no file read allowed"))
    assert len(calls) == 3  # No second close or numeric retry.


def test_source_headless_cannot_request_a_service_profile_from_a_label(monkeypatch):
    monkeypatch.setattr(windows_engine_custody, "active_engine_custody", lambda: None)
    monkeypatch.setattr(headless.Config, "load", lambda: pytest.fail("unadmitted service read configuration"))
    with pytest.raises(PermissionError, match="admitted custody"):
        headless.run_headless(service_custody=SimpleNamespace(root="service"))


def test_service_profile_requires_read_only_runtime_control_before_config(control, monkeypatch):
    instance, _users, owner = control
    monkeypatch.setattr(windows_engine_custody, "active_engine_custody", lambda: owner)
    monkeypatch.setattr(headless.Config, "load", lambda: pytest.fail("wrong control admitted configuration"))
    with pytest.raises(PermissionError):
        headless.run_headless(service_custody=owner, runtime_control=SimpleNamespace())
    class StopBeforeStorage(RuntimeError):
        pass
    def stop_at_config():
        raise StopBeforeStorage("inert accepted guard, before storage")
    monkeypatch.setattr(headless.Config, "load", stop_at_config)
    with pytest.raises(StopBeforeStorage):
        headless.run_headless(service_custody=owner, runtime_control=instance)


@pytest.mark.skipif(os.name != "nt", reason="Canonical Windows SID parser")
@pytest.mark.parametrize("users", [[], [USER, USER], ["S-1-1-0"], ["S-1-5-32-544"], ["S-1-5-18"], [USER] * 65])
def test_enrollment_rejects_broad_groups_duplicate_users_and_unbounded_lists(users):
    with pytest.raises((ValueError, PermissionError)):
        status.parse_console_policy(dict(schema=status.POLICY_SCHEMA, allowed_user_sids=users))


@pytest.mark.skipif(os.name != "nt", reason="Canonical Windows SID parser")
def test_exact_enrollment_schema_preserves_individual_users_only():
    assert status.parse_console_policy(dict(schema=status.POLICY_SCHEMA, allowed_user_sids=[USER, OTHER])) == {USER, OTHER}
    with pytest.raises(PermissionError):
        status.parse_console_policy(dict(schema=status.POLICY_SCHEMA, allowed_user_sids=[USER], endpoint="elsewhere"))


@pytest.mark.parametrize("change", [
    {"bus_key": "forbidden"}, {"authority": ["trust"]}, {"protection_verified": True},
    {"modules": {"discovered": 1, "sampled": 1, "truncated": False, "enabled": 1, "running": 2}},
])
def test_status_client_rejects_added_secret_fields_authority_and_false_counts(control, change):
    instance, _users, _custody = control
    result = deepcopy(instance.dispatch({"operation": "status"}, peer()))
    result.update(change)
    client = object.__new__(status.EngineServiceStatusClient)
    client._client = SimpleNamespace(exchange=lambda _request: result, cleanup_proven=True)
    with pytest.raises(PermissionError):
        client.status()


def test_production_client_binds_fixed_pipe_to_native_service_verifier(monkeypatch):
    captured = []
    monkeypatch.setattr(status, "_ServiceStatusNativeClient", lambda **kwargs: captured.append(kwargs))
    status.EngineServiceStatusClient()
    assert captured == [{"endpoint": status.ENDPOINT, "_server_verifier": status.verify_protection_service_process}]


@pytest.mark.skipif(os.name != "nt", reason="Read-only lease on an isolated public enrollment fixture")
def test_policy_read_pins_exact_file_and_refuses_concurrent_write(tmp_path):
    import pywintypes
    import win32con
    import win32file

    path = tmp_path / "console-policy.json"
    raw = status.canonical(dict(schema=status.POLICY_SCHEMA, allowed_user_sids=[USER]))
    path.write_bytes(raw)
    checks = []
    def verify(target):
        assert target == path
        checks.append(target)
        if len(checks) == 2:
            with pytest.raises(pywintypes.error) as held:
                competing = win32file.CreateFile(str(path), win32con.GENERIC_WRITE,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                    None, win32con.OPEN_EXISTING, win32con.FILE_ATTRIBUTE_NORMAL, None)
                competing.Close()
            assert held.value.winerror == 32  # Real sharing violation, not ACL denial.
    owner = SimpleNamespace(root=tmp_path, verify_private_path=verify)
    assert status.read_console_policy(owner) == {USER}
    assert checks == [path, path] and path.read_bytes() == raw


@pytest.mark.skipif(os.name != "nt", reason="Read failure on an owned isolated native file")
def test_policy_read_error_closes_its_single_native_owner_without_crt_transfer(tmp_path, monkeypatch):
    import win32file

    path = tmp_path / "console-policy.json"
    path.write_bytes(status.canonical(dict(schema=status.POLICY_SCHEMA, allowed_user_sids=[USER])))
    opened = []
    original = win32file.CreateFile
    def create(*args):
        handle = original(*args)
        opened.append(handle)
        return handle
    def read(handle, limit):
        assert handle is opened[0] and limit == status.MAX_POLICY + 1
        raise OSError("inert ReadFile failure")
    monkeypatch.setattr(win32file, "CreateFile", create)
    monkeypatch.setattr(win32file, "ReadFile", read)
    with pytest.raises(OSError, match="ReadFile failure"):
        status.read_console_policy(SimpleNamespace(root=tmp_path, verify_private_path=lambda _path: None))
    assert len(opened) == 1 and int(opened[0]) == 0


@pytest.mark.skipif(os.name != "nt", reason="Owned isolated native pipe, no SCM deployment")
def test_native_read_only_pipe_authenticates_real_os_user_and_retires_its_workers(monkeypatch):
    import win32api
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        actual_sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally:
        token.Close()
    # This server is explicitly synthetic: current test user, private unique
    # pipe, inert enrollment. It does not impersonate an installed service.
    endpoint = r"\\.\pipe\Angerona.Test.Protection.Status." + uuid.uuid4().hex
    monkeypatch.setattr(status, "ENDPOINT", endpoint)
    owner = SimpleNamespace(service_sid=actual_sid, root=Path("inert"))
    monkeypatch.setattr(status, "active_engine_custody", lambda: owner)
    control = status.ServiceStatusControl(owner, _read_policy=lambda _owner: frozenset({actual_sid}))
    verified = []
    def modeled_service_proof(_process, pid):
        assert pid == os.getpid()
        verified.append(pid)
    try:
        assert control.start()
        control.attach(SimpleNamespace(modules={}), None, SimpleNamespace(runtime_chill_active=True), None)
        control.ready()
        client = object.__new__(status.EngineServiceStatusClient)
        client._client = status._ServiceStatusNativeClient(endpoint=endpoint, _server_verifier=modeled_service_proof)
        result = client.status()
        assert result["state"] == "ready" and result["authority"] == []
        assert verified == [os.getpid()]
        assert client.cleanup_proven is True and client.cleanup_state == "retired"
        server = control._server
    finally:
        control.close()
    assert not any(thread.is_alive() for thread in server.threads)
    assert all(pipe.closed.is_set() and pipe.close_proven for pipe in server.pipes)
