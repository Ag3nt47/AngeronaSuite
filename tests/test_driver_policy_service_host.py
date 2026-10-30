"""Exact v2 host composition; SCM/package/pipe/policy boundaries are inert."""
from __future__ import annotations

import threading

import pytest

from angerona.core import response_service_host as host
from angerona.core import driver_policy_service as service
from angerona.core import privileged_pipe
from angerona.core import native_pipe_custody
from angerona.core import native_broker_custody
from angerona.core.engine_transport import canonical, private_directory
import test_driver_policy_service as fixture
import test_windows_driver_policy as policy_fixture


SERVICE = "S-1-5-80-1-2-3-4-5"


@pytest.fixture(autouse=True)
def isolate_native_owners(monkeypatch):
    monkeypatch.setattr(service, "_OWNERS", [])
    monkeypatch.setattr(service, "_HOLDS", [])
    monkeypatch.setattr(service, "_FILE_HOLD", [])
    monkeypatch.setattr(native_broker_custody, "_RETIREMENT_HOLDS", [])
    monkeypatch.setattr(native_pipe_custody, "_RETIREMENT_HOLDS", [])


def provision_policy(pin=None):
    value = {"schema": host.PROVISION_SCHEMA, "allowed_user_sids": [policy_fixture.peer(i).user_sid for i in (1, 2, 3)],
             "credentials": [fixture.public_credential(i) for i in (1, 2, 3)], "candidates": []}
    if pin is not None:
        value["schema"] = host.DRIVER_PROVISION_SCHEMA
        value["driver_policy"] = {"profile": "own-unsigned-multiple-policy", "manifest_sha256": pin}
    return value


class InertNativeListener:
    def __init__(self, dispatch, **kwargs):
        self.dispatch, self.kwargs = dispatch, kwargs
        self.stop_event = threading.Event()
        self.error = ""
        self.started = False
    def start(self):
        self.started = True
    def stop(self, _timeout=3):
        self.stop_event.set()
        return True


@pytest.fixture
def host_state(monkeypatch, tmp_path):
    import win32service
    from angerona.core import engine_windows_service

    root = private_directory(tmp_path / "ResponseBroker")
    manifest, audit, enforce = fixture.provision(root / "DriverPolicy")
    public = provision_policy(policy_fixture.digest(canonical(manifest)))
    fixture.write(root / "provisioning.json", canonical(public))
    package = private_directory(tmp_path / "Package")
    image = package / "Angerona.exe"
    fixture.write(image, b"INERT package image; never executed")
    monkeypatch.setattr(engine_windows_service, "require_package_service", lambda: None)
    monkeypatch.setattr(host, "native_service_sid", lambda: SERVICE)
    monkeypatch.setattr(host, "verify_service_token", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(host, "verify_service_registration", lambda *_args: None)
    monkeypatch.setattr(host, "verify_protected_path", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(host, "_fixed_state_root", lambda: root)
    monkeypatch.setattr(win32service, "OpenSCManager", lambda *_args: object())
    monkeypatch.setattr(win32service, "OpenService", lambda *_args: object())
    monkeypatch.setattr(win32service, "CloseServiceHandle", lambda *_args: None)
    monkeypatch.setattr(privileged_pipe, "_package_path", lambda _name: package)
    monkeypatch.setattr(privileged_pipe, "_native_package_string", lambda *_args: "Inert.fixture.package")
    monkeypatch.setattr(privileged_pipe, "_process_image", lambda _process: image)
    monkeypatch.setattr(host, "PrivilegedPipeServer", InertNativeListener)
    monkeypatch.setattr(service, "DriverPolicyPipeServer", InertNativeListener)
    native = policy_fixture.Native()
    monkeypatch.setattr(service.policy, "WindowsNativeDriverPolicyApi", lambda *_args, **_kwargs: native)
    value = {"root": root, "public": public, "manifest": manifest, "native": native, "audit": audit, "enforce": enforce}
    yield value
    for owner in tuple(service._OWNERS):
        owner.stop(3)


def test_exact_v1_remains_diagnostic_only_with_no_mutators():
    users, backend, pin = host._parse_runtime_policy(provision_policy())
    assert users and pin is None and isinstance(backend, host.DiagnosticBroker)
    assert backend.dispatch({"operation": "status"}, policy_fixture.peer())["mutating_operations"] == []
    with pytest.raises(PermissionError):
        backend.dispatch({"operation": "driver.execute", "plan_id": "a" * 32}, policy_fixture.peer())


@pytest.mark.parametrize("variation", ["extra", "wrong-profile", "wrong-pin", "caller-path", "missing", "unknown-version"])
def test_only_exact_installer_v2_profile_can_select_driver_backend(variation):
    value = provision_policy("a" * 64)
    if variation == "extra":
        value["native_factory"] = "caller-code"
    elif variation == "wrong-profile":
        value["driver_policy"]["profile"] = "signed-UEFI-arbitrary"
    elif variation == "wrong-pin":
        value["driver_policy"]["manifest_sha256"] = "Z" * 64
    elif variation == "caller-path":
        value["driver_policy"]["path"] = "C:\\outside"
    elif variation == "missing":
        del value["driver_policy"]
    else:
        value["schema"] = "angerona.response-service.provisioning.v3"
    with pytest.raises(PermissionError):
        host._parse_runtime_policy(value)


def test_production_host_factory_composes_retained_v2_runtime_without_native_probe(host_state):
    runtime = host.prepare_runtime()
    assert isinstance(runtime, service.DriverPolicyServiceRuntime)
    assert runtime._listener.stop_event is runtime.stop_event and not host_state["native"].calls
    runtime.start()
    try:
        assert runtime._listener.started and not runtime._thread.daemon
        status = runtime.dispatch({"operation": "driver.status"}, policy_fixture.peer())
        assert status["state"] == "configured" and not status["kernel_prevention_verified"]
        result = fixture.submit(runtime, {"operation": "driver.prepare", "material_id": host_state["audit"].identity,
            "action": "audit", "original_id": "", "review_id": ""})
        assert result["state"] == "completed" and not host_state["native"].calls
    finally:
        assert runtime.stop(3)


def test_profile_revocation_changes_hold_existing_runtime_and_cannot_autoreconstruct(host_state):
    runtime = host.prepare_runtime()
    runtime.start()
    original = canonical(host_state["public"])
    host_state["public"]["allowed_user_sids"].pop()
    path = host_state["root"] / "provisioning.json"
    path.write_bytes(canonical(host_state["public"]))
    assert runtime.dispatch({"operation": "driver.status"}, policy_fixture.peer())["state"] == "held"
    with pytest.raises(PermissionError):
        runtime._listener.dispatch({"operation": "driver.status"}, policy_fixture.peer())
    path.write_bytes(original)
    assert runtime.dispatch({"operation": "driver.status"}, policy_fixture.peer())["state"] == "held"
    with pytest.raises(PermissionError):
        host.prepare_runtime()
    assert not host_state["native"].calls


def test_v1_production_factory_does_not_open_driver_catalog_or_keys(host_state, monkeypatch):
    path = host_state["root"] / "provisioning.json"
    path.write_bytes(canonical(provision_policy()))
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Diagnostic v1 tried to construct a driver runtime")
    monkeypatch.setattr(service, "DriverPolicyServiceRuntime", forbidden)
    listener = host.prepare_runtime()
    assert isinstance(listener, InertNativeListener) and not service._OWNERS
    assert listener.dispatch({"operation": "status"}, policy_fixture.peer())["state"] == "diagnostic-only"


def test_guard_native_close_uncertainty_fences_dispatch_and_retains_runtime_leases(host_state, monkeypatch):
    import win32service
    runtime = host.prepare_runtime()
    runtime.start()
    calls = []
    def ambiguous(handle):
        calls.append(handle)
        if len(calls) == 1:
            raise RuntimeError("Simulated SCM close return ambiguity")
    monkeypatch.setattr(win32service, "CloseServiceHandle", ambiguous)
    with pytest.raises(PermissionError):
        runtime._listener.dispatch({"operation": "driver.status"}, policy_fixture.peer())
    assert len(calls) == 2 and native_broker_custody._RETIREMENT_HOLDS
    assert not runtime.stop(3) and runtime._journal.ready()
    assert service._OWNERS == service._HOLDS == [runtime]
    assert len(calls) == 2  # No second native close attempt after the sticky hold.
    # All native handles here are modeled objects; the worker has retired.
    # Release disposable test-state leases without pretending product cleanup.
    runtime._broker.close()
    runtime._journal.close()
    runtime._authority.close()


def test_actual_token_guard_retains_close_failure_and_fences_further_native_admission(monkeypatch):
    import win32security
    calls = []
    class Token:
        def Close(self):
            calls.append("close")
            raise RuntimeError("Simulated token CloseHandle ambiguity")
        def Detach(self):
            calls.append("detach")
            return 101
    token = Token()
    sid = win32security.ConvertStringSidToSid(SERVICE)
    system = win32security.ConvertStringSidToSid("S-1-5-18")
    def open_token(*_args):
        calls.append("open")
        return token
    def info(_token, kind):
        return (system, 0) if kind == win32security.TokenUser else [(sid, 4)]
    monkeypatch.setattr(win32security, "OpenProcessToken", open_token)
    monkeypatch.setattr(win32security, "GetTokenInformation", info)
    with pytest.raises(PermissionError, match="cleanup"):
        host.verify_service_token(object(), SERVICE)
    assert calls == ["open", "close", "detach"] and native_broker_custody._RETIREMENT_HOLDS[0].rows[0]["handle"] is token
    with pytest.raises(PermissionError, match="retirement"):
        host.verify_service_token(object(), SERVICE)
    assert calls == ["open", "close", "detach"]
