"""Modeled service admission/order and read-only native ACL parsing.

No test installs a service, changes a machine/process ACL, or consumes installed
keys. A signed virtual-account deployment needs separate clean-VM acceptance.
"""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import stat
import sys
import threading
from types import SimpleNamespace

import pytest

from angerona.core import data_paths, engine_windows_service, hardening
from angerona.core import windows_engine_custody as custody
from angerona.core.windows_process_lease import ProcessObjectIdentity

SERVICE = "S-1-5-80-1-2-3-4-5"
USER = "S-1-5-21-100-200-300-1001"
SYSTEM = "S-1-5-18"
ADMIN = "S-1-5-32-544"
INSTALLER = "S-1-5-80-9-8-7-6-5"
IMAGE = Path(r"C:\Program Files\WindowsApps\Angerona_1\Angerona.exe")
ROOT = Path(r"C:\ProgramData\Angerona\Protection")
WRITERS = frozenset({SYSTEM, ADMIN, INSTALLER})


def private_descriptor(*, extra=(), protected=True):
    return custody.AccessDescriptor(SERVICE, protected,
        ((0, 0, 0x1F01FF, SERVICE), (0, 0, 0x1F01FF, SYSTEM), *extra))


def registration(**changes):
    value = custody.ServiceRegistration(os.getpid(), 4, 0x10, f'"{IMAGE}" --engine-service',
        custody.SERVICE_ACCOUNT, 3, custody.AccessDescriptor(SYSTEM, True,
            ((0, 0, 0xF01FF, SYSTEM), (0, 0, 0x2008D, USER))))
    return replace(value, **changes)


def token(**changes):
    return replace(custody.TokenObservation(SERVICE, SERVICE, 0, ((SERVICE, 4),), ((SERVICE, 0),)), **changes)


class Native:
    """Explicit inert native seam; none of these paths/handles reaches Win32."""
    def __init__(self):
        self.observed = ProcessObjectIdentity(os.getpid(), 134377000000000000, str(IMAGE))
        self.reg, self.tok = registration(), token()
        self.proc_acl = private_descriptor(extra=((0, 0, 0x121000, USER),), protected=False)
        self.calls = []
        self.closed = 0
        self.refuse = None

    def identity(self):
        self.calls.append("identity")
        return self.observed

    def service_sid(self):
        return SERVICE

    def installed_writers(self):
        return WRITERS

    def registration(self):
        return self.reg

    def token(self):
        return self.tok

    def process_descriptor(self):
        return self.proc_acl

    def package_root(self):
        return IMAGE.parent

    def verify_path(self, path, **options):
        self.calls.append((Path(path), options))
        if Path(path) == self.refuse:
            raise PermissionError("inert unsafe path")
        return Path(path)

    def close(self):
        self.closed += 1


@pytest.fixture
def admitted(monkeypatch):
    native = Native()
    monkeypatch.setattr(custody, "_ACTIVE", None)
    monkeypatch.setattr(sys, "argv", [str(IMAGE), "--engine-service"])
    monkeypatch.setattr(engine_windows_service, "require_package_service", lambda: native.calls.append("package-admission"))
    monkeypatch.setattr(custody, "fixed_state_root", lambda: ROOT)
    result = custody.prepare_engine_custody(_native=native)
    try:
        yield result, native
    finally:
        result.close()


def test_native_admission_precedes_active_profile_and_retains_exact_owner(admitted):
    result, native = admitted
    assert native.calls[0] == "package-admission"
    assert custody.active_engine_custody() is result
    assert result.root == ROOT and result.identity is native.observed
    verified = [call for call in native.calls if type(call) is tuple]
    assert [row[0] for row in verified] == [IMAGE.parent, IMAGE, ROOT]
    assert verified[-1][1]["private"] is True
    result.close()
    assert custody.active_engine_custody() is None and native.closed == 1
    result.close()
    assert native.closed == 1


@pytest.mark.parametrize("change", [
    {"pid": 999999}, {"state": 2}, {"state": True}, {"service_type": 0x20},
    {"account": "LocalSystem"}, {"account": r"NT AUTHORITY\LocalService"}, {"sid_type": 1},
    {"command": f'"{IMAGE}" --engine-service --chill'},
    {"command": f'"{IMAGE.parent / "Other.exe"}" --engine-service'},
    {"command": f'"{IMAGE}" --engine-console'},
])
def test_service_name_or_packaging_does_not_replace_actual_scm_binding(change):
    with pytest.raises(PermissionError):
        custody.verify_registration(registration(**change), pid=os.getpid(), image=IMAGE,
                                     service_sid=SERVICE, installed_writers=WRITERS)


@pytest.mark.parametrize("change", [
    {"user": USER}, {"owner": ADMIN}, {"session": 1}, {"session": False},
    {"restricted": ()}, {"restricted": ((SERVICE, 0x10),)},
    {"groups": ((ADMIN, 4),)},
])
def test_current_virtual_token_required_beyond_configured_service_account(change):
    with pytest.raises(PermissionError):
        custody.verify_token(token(**change), SERVICE)


@pytest.mark.parametrize("mask", [0x10, 0x20, 0x40, 0x800, 1, 0x40000, 0x10000000, 0x80000000])
def test_desktop_cannot_get_process_memory_suspend_or_security_mutation_rights(mask):
    with pytest.raises(PermissionError, match="outside"):
        custody.check_descriptor(private_descriptor(extra=((0, 0, mask, USER),)),
            frozenset({SYSTEM, ADMIN, SERVICE}), outside_allowed=0x121000)


def test_query_metadata_is_separate_from_private_file_access():
    descriptor = private_descriptor(extra=((0, 0, 0x121000, USER),), protected=False)
    custody.check_descriptor(descriptor, frozenset({SYSTEM, ADMIN, SERVICE}), outside_allowed=0x121000)
    with pytest.raises(PermissionError):
        custody.check_descriptor(descriptor, frozenset({SYSTEM, ADMIN, SERVICE}), service_sid=SERVICE)
    for bad in (replace(private_descriptor(), protected=False),
                replace(private_descriptor(), owner=USER),
                replace(private_descriptor(), entries=((1, 0, 0x1F01FF, SERVICE),)),
                replace(private_descriptor(), entries=((5, 0, 1, SYSTEM),))):
        with pytest.raises(PermissionError):
            custody.check_descriptor(bad, frozenset({SYSTEM, ADMIN, SERVICE}), protected=True, service_sid=SERVICE)


def test_admission_failure_closes_exact_observer_and_never_installs_profile(monkeypatch):
    native = Native()
    native.refuse = ROOT
    monkeypatch.setattr(custody, "_ACTIVE", None)
    monkeypatch.setattr(sys, "argv", [str(IMAGE), "--engine-service"])
    monkeypatch.setattr(engine_windows_service, "require_package_service", lambda: None)
    monkeypatch.setattr(custody, "fixed_state_root", lambda: ROOT)
    with pytest.raises(PermissionError, match="unsafe path"):
        custody.prepare_engine_custody(_native=native)
    assert custody.active_engine_custody() is None and native.closed == 1


def test_service_root_and_key_profile_ignore_desktop_environment(admitted, tmp_path, monkeypatch):
    result, native = admitted
    result._root = tmp_path  # Model only a disposable service-private test tree.
    for name in ("ANGERONA_DATA", "ANGERONA_DIAG_DIR", "PROGRAMDATA", "ANGERONA_HOME", "ANGERONA_DATA_DRIVE", "TEMP", "TMP"):
        monkeypatch.setenv(name, str(tmp_path / "untrusted"))
    monkeypatch.setattr(data_paths, "_create_admin_directory_atomic", lambda *_a: pytest.fail("service must not rewrite admin ACLs"))
    monkeypatch.setattr(hardening.subprocess, "run", lambda *_a, **_k: pytest.fail("service key verification invoked icacls"))
    assert data_paths.data_dir(create=False) == tmp_path
    assert data_paths.configure_runtime_environment() == tmp_path
    assert os.environ["ANGERONA_DATA"] == str(tmp_path)
    assert os.environ["ANGERONA_DIAG_DIR"] == str(tmp_path / "diagnostics")
    assert os.environ["TEMP"] == os.environ["TMP"] == str(tmp_path / "tmp")
    key = tmp_path / "bus.key"
    assert hardening.prepare_sensitive_key(key, required=True) is False
    key.write_bytes(b"private fixture original")
    assert hardening.prepare_sensitive_key(key, required=True)
    assert hardening.secure_sensitive_file(key, required=True)
    native.refuse = key
    before = tuple(tmp_path.iterdir())
    with pytest.raises(PermissionError):
        hardening.prepare_sensitive_key(key, required=True)
    with pytest.raises(PermissionError):
        hardening.secure_sensitive_file(key, required=False)
    assert tuple(tmp_path.iterdir()) == before and key.read_bytes() == b"private fixture original"


def test_private_path_never_accepts_outside_root_or_changed_generation(admitted):
    result, native = admitted
    with pytest.raises(PermissionError):
        result.verify_private_path(ROOT.parent / "desktop.key")
    native.observed = replace(native.observed, birth_ticks=native.observed.birth_ticks + 1)
    with pytest.raises(PermissionError):
        result.verify_private_path(ROOT / "bus.key")


def test_cleanup_uncertainty_is_sticky_without_reclosing_a_numeric_handle(admitted):
    result, native = admitted
    def ambiguous():
        native.closed += 1
        raise OSError("inert native close ambiguity")
    native.close = ambiguous
    for _ in range(2):
        with pytest.raises(PermissionError, match="cleanup remains unproven"):
            result.close()
    assert native.closed == 1 and custody.active_engine_custody() is None
    result._close_error = ""  # Expected inert fixture diagnostic only.


def test_failed_custody_cannot_import_config_or_start_singleton_or_graph(monkeypatch):
    import builtins

    def refused():
        raise PermissionError("inert SCM admission failure")
    monkeypatch.setattr(custody, "prepare_engine_custody", refused)
    original = builtins.__import__
    seen = []
    def guarded(name, *args, **kwargs):
        seen.append(name)
        if name in {"headless", "singleton", "data_paths", "angerona.core.config"}:
            pytest.fail("service imported runtime before custody: " + name)
        return original(name, *args, **kwargs)
    with monkeypatch.context() as local:
        local.setattr(builtins, "__import__", guarded)
        with pytest.raises(PermissionError, match="SCM admission"):
            engine_windows_service._run_protected_engine(threading.Event())
    assert "headless" not in seen


@pytest.mark.parametrize("failure", ["graph", "pipe", "lease"])
def test_service_keeps_singleton_and_custody_when_graph_or_native_cleanup_is_pending(monkeypatch, failure):
    from angerona.core import engine_service_status, headless, singleton

    events, admissions = [], []
    owner = SimpleNamespace(close=lambda: events.append("custody"))
    def acquire():
        admissions.append(True)
        return owner
    monkeypatch.setattr(custody, "prepare_engine_custody", acquire)
    monkeypatch.setattr(engine_windows_service, "_SERVICE_RETIREMENT_HOLD", None)
    monkeypatch.setattr(data_paths, "configure_runtime_environment", lambda: None)
    def close_lease():
        events.append("lease")
        if failure == "lease":
            raise OSError("inert uncertain lease close")
    lease = SimpleNamespace(close=close_lease)
    monkeypatch.setattr(singleton, "acquire_single_instance", lambda: lease)
    class Control:
        graph_retirement_pending = False
        def start(self):
            pass
        def close(self):
            events.append("control")
            if failure == "pipe":
                raise RuntimeError("inert native pipe retirement pending")
    control = Control()
    monkeypatch.setattr(engine_service_status, "ServiceStatusControl", lambda _owner: control)
    def graph(**kwargs):
        if failure == "graph":
            kwargs["runtime_control"].graph_retirement_pending = True
            raise headless.HeadlessRetirementPending("inert pending writer")
        return 0
    monkeypatch.setattr(headless, "run_headless", graph)
    with pytest.raises((RuntimeError, OSError)):
        engine_windows_service._run_protected_engine(threading.Event())
    assert engine_windows_service._SERVICE_RETIREMENT_HOLD == (owner, lease, control)
    assert events == (["control", "lease"] if failure == "lease" else ["control"])
    with pytest.raises(RuntimeError, match="previous service graph"):
        engine_windows_service._run_protected_engine(threading.Event())
    assert admissions == [True]


def test_package_and_exact_invocation_are_checked_before_any_native_admission(monkeypatch):
    monkeypatch.setattr(custody, "_ACTIVE", None)
    monkeypatch.setattr(custody, "_NativeCustody", lambda: pytest.fail("unadmitted invocation queried the service"))
    def package_refused():
        raise PermissionError("inert publisher pin absent")
    monkeypatch.setattr(engine_windows_service, "require_package_service", package_refused)
    with pytest.raises(PermissionError, match="publisher pin"):
        custody.prepare_engine_custody()
    monkeypatch.setattr(engine_windows_service, "require_package_service", lambda: None)
    monkeypatch.setattr(sys, "argv", [str(IMAGE), "--engine-service", "--automatic-start"])
    with pytest.raises(PermissionError, match="exact fresh"):
        custody.prepare_engine_custody()


@pytest.mark.skipif(os.name != "nt", reason="Inert SCM seams with real native security descriptor parsing")
@pytest.mark.parametrize("fail_close", [False, True])
def test_native_scm_reads_fixed_registration_and_attempts_both_closes(monkeypatch, fail_close):
    import win32security
    import win32service

    calls = []
    monkeypatch.setattr(custody, "_NATIVE_RETIREMENT_HOLD", None)
    class Handle:
        def __init__(self, name):
            self.name = name
        def Close(self):
            calls.append(self)
            if fail_close and self.name == "service":
                raise OSError("inert SCM close uncertainty")
        def Detach(self):
            pass
    scm, service = Handle("scm"), Handle("service")
    def open_scm(machine, database, access):
        assert (machine, database, access) == (None, None, 1)
        return scm
    def open_service(owner, name, access):
        assert owner is scm and (name, access) == (custody.SERVICE_NAME, 0x20005)
        return service
    monkeypatch.setattr(win32service, "OpenSCManager", open_scm)
    monkeypatch.setattr(win32service, "OpenService", open_service)
    monkeypatch.setattr(win32service, "QueryServiceStatusEx", lambda handle: {"ProcessId": os.getpid(), "CurrentState": 4})
    monkeypatch.setattr(win32service, "QueryServiceConfig", lambda handle:
        (0x10, 2, 1, f'"{IMAGE}" --engine-service', "", 0, [], custody.SERVICE_ACCOUNT, "Protection"))
    def sid_type(handle, level):
        assert handle is service and level == 5
        return 3
    monkeypatch.setattr(win32service, "QueryServiceConfig2", sid_type)
    monkeypatch.setattr(win32service, "QueryServiceObjectSecurity", lambda *_a:
        win32security.ConvertStringSecurityDescriptorToSecurityDescriptor("O:SYD:P(A;;GA;;;SY)", 1))
    native = object.__new__(custody._NativeCustody)
    if fail_close:
        with pytest.raises(custody.ServiceCustodyCleanupError, match="retirement"):
            native.registration()
    else:
        value = native.registration()
        custody.verify_registration(value, pid=os.getpid(), image=IMAGE,
                                     service_sid=SERVICE, installed_writers=WRITERS)
    assert calls == [service, scm]


def test_native_observer_close_is_single_attempt_and_keeps_auxiliary_uncertainty(monkeypatch):
    monkeypatch.setattr(custody, "_NATIVE_RETIREMENT_HOLD", None)
    calls = []
    class Auxiliary:
        def Close(self):
            calls.append("auxiliary-close")
            raise OSError("inert auxiliary close failure")
        def Detach(self):
            calls.append("auxiliary-detach")
            raise OSError("inert auxiliary detach failure")
    auxiliary = Auxiliary()
    with pytest.raises(custody.ServiceCustodyCleanupError):
        custody._close_auxiliary([auxiliary])
    native = object.__new__(custody._NativeCustody)
    native.process, native._close_error = 901, ""  # Inert; no Win32 call.
    def close_process(handle):
        assert handle == 901
        calls.append("process-close")
        raise OSError("inert native process close failure")
    native.native = SimpleNamespace(close=close_process)
    for _ in range(2):
        with pytest.raises(custody.ServiceCustodyCleanupError):
            native.close()
    assert calls == ["auxiliary-close", "auxiliary-detach", "process-close"]
    assert native.process is None and custody._NATIVE_RETIREMENT_HOLD == (auxiliary, native)


@pytest.mark.parametrize("reused", [False, True])
def test_status_client_proves_retained_native_peer_without_reading_private_state(monkeypatch, reused):
    from angerona.core import windows_process_lease

    native = Native()
    retained = native.observed
    if reused:
        retained = replace(retained, birth_ticks=retained.birth_ticks + 1)
    monkeypatch.setattr(windows_process_lease._Native, "identity", lambda _self, handle: retained)
    observed = []
    def observer(pid):
        observed.append(pid)
        return native
    monkeypatch.setattr(custody, "_NativeCustody", observer)
    monkeypatch.setattr(custody, "fixed_state_root", lambda: pytest.fail("status client touched private service state"))
    if reused:
        with pytest.raises(PermissionError, match="retained native"):
            custody.verify_protection_service_process(901, native.observed.pid)
    else:
        custody.verify_protection_service_process(901, native.observed.pid)
    assert observed == [native.observed.pid] and native.closed == 1
    assert [row[0] for row in native.calls if type(row) is tuple] == [IMAGE.parent, IMAGE]


def test_native_private_ancestry_keeps_service_sid_grants_but_refuses_desktop_read(monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows path and native descriptor composition")
    native = object.__new__(custody._NativeCustody)
    target = ROOT / "nested" / "bus.key"
    monkeypatch.setattr(custody, "fixed_state_root", lambda: ROOT)
    def info(path, *_a, **_k):
        return SimpleNamespace(st_mode=stat.S_IFREG if path == target else stat.S_IFDIR,
                               st_nlink=1, st_file_attributes=0)
    monkeypatch.setattr(Path, "lstat", info)
    def descriptor(path):
        return private_descriptor(protected=path == ROOT) if path.is_relative_to(ROOT) else custody.AccessDescriptor(
            SYSTEM, False, ((0, 0, 0x1F01FF, SYSTEM), (0, 0, 0x1200A9, USER)))
    native.path_descriptor = descriptor
    assert native.verify_path(target, directory=False, service_sid=SERVICE,
                              installed_writers=WRITERS, private=True) == target
    native.path_descriptor = lambda path: private_descriptor(extra=((0, 0, 1, USER),)) if path == target else descriptor(path)
    with pytest.raises(PermissionError, match="outside"):
        native.verify_path(target, directory=False, service_sid=SERVICE, installed_writers=WRITERS, private=True)


@pytest.mark.skipif(os.name != "nt", reason="Read-only native known-folder query")
def test_known_programdata_root_cannot_be_redirected_by_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    root = custody.fixed_state_root()
    assert root.is_absolute() and not root.is_relative_to(tmp_path)
    assert root.parts[-2:] == ("Angerona", "Protection")
