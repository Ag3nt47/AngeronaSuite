"""Real local pipe/OS token tests; no service installation or host mutation."""
from __future__ import annotations

import os
import struct
import threading
import time
import uuid

import pytest

from angerona.core import privileged_pipe as transport
from angerona.core.engine_transport import canonical


def _native_user():
    import win32api
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        return win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally:
        token.Close()


@pytest.fixture
def server():
    if os.name != "nt":
        pytest.skip("Windows native named pipes")
    seen = []
    user = _native_user()
    def dispatch(request, peer):
        import win32api
        import win32security
        # The callback must have no impersonation token at all.
        try:
            token = win32security.OpenThreadToken(win32api.GetCurrentThread(), 8, True)
        except Exception as error:
            assert error.winerror == 1008
        else:
            token.Close()
            pytest.fail("Dispatch ran while still impersonating the client")
        seen.append((request, peer))
        return {"subject": peer.user_sid, "logon": peer.logon_sid, "pid": peer.pid}
    instance = transport.PrivilegedPipeServer(dispatch, server_sid=user, allowed_sids=[user],
        endpoint=r"\\.\pipe\Angerona.Test.ResponseBroker." + uuid.uuid4().hex)
    instance.start()
    try:
        yield instance, seen
    finally:
        assert instance.stop(5), instance.error
        assert all(not thread.is_alive() and not thread.daemon for thread in instance.threads)


def _client(server, **kwargs):
    return transport.PrivilegedPipeClient(endpoint=server.endpoint, expected_pid=os.getpid(),
        _server_verifier=lambda process, pid: None, **kwargs)


def test_native_os_token_revert_and_repeated_connect_disconnect(server):
    instance, seen = server
    for number in range(12):
        result = _client(instance).exchange({"operation": "status", "sequence": number})
        assert result["subject"] == _native_user()
        assert result["pid"] == os.getpid()
        assert result["logon"].startswith("S-1-5-5-")
    assert len(seen) == 12
    assert all(peer.authentication_id and peer.birth > 0 for _, peer in seen)


def test_production_client_rejects_missing_package_pins_before_payload(server):
    instance, seen = server
    client = transport.PrivilegedPipeClient(endpoint=instance.endpoint)
    with pytest.raises(transport.BrokerPipeError, match="pins are not provisioned"):
        client.exchange({"operation": "status"})
    assert seen == [] and client.server_identity is None


@pytest.mark.parametrize("mismatch", ["pid", "birth", "verifier"])
def test_client_identity_failure_never_sends_request(server, mismatch):
    instance, seen = server
    client = _client(instance)
    if mismatch == "pid":
        client.expected_pid += 1
    elif mismatch == "birth":
        client.expected_birth = 1
    else:
        def deny(process, pid):
            raise PermissionError("untrusted installed identity")
        client._server_verifier = deny
    with pytest.raises((transport.BrokerPipeError, PermissionError)):
        client.exchange({"operation": "status", "sensitive": "must-not-cross"})
    assert seen == [] and client.server_identity is None


def test_impersonation_failure_never_dispatches_and_listener_recovers(server, monkeypatch):
    instance, seen = server
    original = transport._impersonate
    def deny(handle):
        raise transport.PeerAuthenticationError("injected native refusal")
    monkeypatch.setattr(transport, "_impersonate", deny)
    with pytest.raises(Exception):
        _client(instance).exchange({"operation": "status"}, timeout=.5)
    assert seen == [] and not instance.stop_event.is_set()
    monkeypatch.setattr(transport, "_impersonate", original)
    assert _client(instance).exchange({"operation": "status"})["pid"] == os.getpid()


def test_reversion_failure_is_fatal_without_backend_dispatch(server, monkeypatch):
    instance, seen = server
    original = transport._revert
    def reverted_but_reported_failed():
        # Do not leave the test process impersonated; reproduce fatal contract.
        original()
        raise transport.PeerAuthenticationError("injected failed reversion", fatal=True)
    monkeypatch.setattr(transport, "_revert", reverted_but_reported_failed)
    with pytest.raises(Exception):
        _client(instance).exchange({"operation": "status"}, timeout=.5)
    assert instance.stop_event.wait(2) and "reversion failed" in instance.error
    assert seen == [] and instance.accepted == 0


def test_first_instance_collision_and_four_non_daemon_owners(server):
    instance, _ = server
    duplicate = transport.PrivilegedPipeServer(lambda request, peer: {}, server_sid=_native_user(),
        allowed_sids=[_native_user()], endpoint=instance.endpoint)
    with pytest.raises(Exception):
        duplicate.start()
    assert duplicate.stop()
    assert len(instance.pipes) == 4 and len(instance.threads) == 4


def test_stop_cancels_a_connected_client_that_never_sends_a_frame(server):
    import win32file
    import win32pipe
    instance, seen = server
    win32pipe.WaitNamedPipe(instance.endpoint, 1000)
    handle = win32file.CreateFile(instance.endpoint, transport.CLIENT_ACCESS, 0, None, 3,
        win32file.FILE_FLAG_OVERLAPPED | 0x110000, None)
    try:
        start = time.monotonic()
        assert instance.stop(2)
        assert time.monotonic() - start < 2.5
        assert seen == []
    finally:
        handle.Close()


def test_partial_start_interrupt_cleans_owned_native_instances(monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows native named pipes")
    original = threading.Thread.start
    calls = []
    def interrupted(thread):
        calls.append(thread)
        if len(calls) == 2:
            raise KeyboardInterrupt("injected second thread start")
        return original(thread)
    monkeypatch.setattr(threading.Thread, "start", interrupted)
    user = _native_user()
    instance = transport.PrivilegedPipeServer(lambda request, peer: {}, server_sid=user,
        allowed_sids=[user], endpoint=r"\\.\pipe\Angerona.Test.ResponseBroker." + uuid.uuid4().hex)
    with pytest.raises(KeyboardInterrupt):
        instance.start()
    assert instance.stop() and all(not thread.is_alive() for thread in instance.threads)


def test_stop_reports_inflight_callback_as_pending_and_retains_owner():
    if os.name != "nt":
        pytest.skip("Windows native named pipes")
    entered, release = threading.Event(), threading.Event()
    outcome = []
    user = _native_user()
    def blocked(request, peer):
        entered.set()
        assert release.wait(5)
        return {}
    instance = transport.PrivilegedPipeServer(blocked, server_sid=user, allowed_sids=[user],
        endpoint=r"\\.\pipe\Angerona.Test.ResponseBroker." + uuid.uuid4().hex)
    instance.start()
    def exchange():
        try:
            _client(instance).exchange({"operation": "status"})
        except Exception as error:
            outcome.append(type(error).__name__)
    client = threading.Thread(target=exchange)
    try:
        client.start()
        assert entered.wait(3), outcome
        assert not instance.stop(.02)
        assert "shutdown pending" in instance.error
        assert any(thread.is_alive() and not thread.daemon for thread in instance.threads)
    finally:
        release.set()
        client.join(5)
        assert not client.is_alive()
        assert instance.stop(5)


def test_granular_client_access_excludes_named_pipe_instance_creation():
    assert not transport.CLIENT_ACCESS & 0x4
    if os.name == "nt":
        import win32security
        user = _native_user()
        service = "S-1-5-80-1-2-3-4-5"
        descriptor = transport._attributes(service, [user]).SECURITY_DESCRIPTOR
        acl = descriptor.GetSecurityDescriptorDacl()
        grants = [acl.GetAce(index) for index in range(acl.GetAceCount())]
        user_grants = [ace[1] for ace in grants if win32security.ConvertSidToStringSid(ace[2]) == user]
        assert user_grants == [transport.CLIENT_ACCESS]


class MemoryPipe:
    def __init__(self, raw):
        self.parts = iter(raw)
    def read(self, timeout):
        return next(self.parts, b"")


@pytest.mark.parametrize("raw", [
    [struct.pack("!I", transport.MAX_FRAME + 1)],
    [struct.pack("!I", 0)],
    [struct.pack("!I", 2) + b"{}suffix"],
    [struct.pack("!I", 13) + b'{"x":1,"x":2}'],
    [struct.pack("!I", 2) + b"[]"],
])
def test_frame_bounds_trailing_data_duplicate_keys_and_wrong_type(raw):
    with pytest.raises(Exception):
        transport._read_frame(MemoryPipe(raw))


def test_fragmented_frame_is_decoded_exactly():
    raw = canonical({"operation": "status"})
    wire = struct.pack("!I", len(raw)) + raw
    assert transport._read_frame(MemoryPipe([wire[:2], wire[2:6], wire[6:]])) == {"operation": "status"}


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -1, 0, True, 31])
def test_timeout_validation_occurs_before_native_open(timeout):
    if os.name != "nt":
        pytest.skip("Windows client")
    with pytest.raises(ValueError, match="finite"):
        transport.PrivilegedPipeClient().exchange({}, timeout=timeout)
