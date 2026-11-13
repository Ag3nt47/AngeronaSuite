"""Inert control-namespace tests; no UAC, host ACL edits or real authority writes."""
from types import SimpleNamespace
import sys

import pytest

from angerona.resilience import control_authority as ca, shutdown_token as token


def _security(monkeypatch, *, owner="S-1-5-32-544", aces=()):
    flags = []
    acl = SimpleNamespace(GetAceCount=lambda: len(aces), GetAce=lambda i: aces[i])
    descriptor = SimpleNamespace(GetSecurityDescriptorOwner=lambda: owner,
                                 GetSecurityDescriptorDacl=lambda: acl)
    def get(_path, _kind, requested):
        flags.append(requested)
        return descriptor
    security = SimpleNamespace(SE_FILE_OBJECT=1, DACL_SECURITY_INFORMATION=4,
        OWNER_SECURITY_INFORMATION=1, GetNamedSecurityInfo=get,
        ConvertSidToStringSid=str, SDDL_REVISION_1=1,
        ConvertStringSecurityDescriptorToSecurityDescriptor=lambda s, _r: s)
    monkeypatch.setattr(ca, "os", SimpleNamespace(name="nt"))
    monkeypatch.setitem(sys.modules, "win32security", security)
    return security, flags


@pytest.mark.parametrize("owner,expected", [("S-1-5-21-fixture", True), ("S-1-5-18", False)])
def test_owner_authority_is_checked_even_with_admin_only_dacl(tmp_path, monkeypatch, owner, expected):
    _security_module, flags = _security(monkeypatch, owner=owner,
        aces=(((0, 0), 0x1F01FF, "S-1-5-32-544"),))
    assert ca.user_writable(tmp_path) is expected
    assert flags == [5]  # DACL + owner, rather than a DACL-only verdict.


def test_unknown_allow_ace_is_unverifiable_not_protected(tmp_path, monkeypatch):
    _security(monkeypatch, aces=(((9, 0), 0x2, "S-1-5-21-fixture"),))
    assert ca.user_writable(tmp_path) is None


def test_inherit_only_creation_rights_do_not_replace_existing_namespace(tmp_path, monkeypatch):
    _security(monkeypatch, aces=(((0, 8), 0x1F01FF, "S-1-3-0"),
                               ((0, 0), 0x4, "S-1-5-32-545")))
    assert ca.user_writable(tmp_path, _mask=ca._ANCESTOR_REPLACE_MASK) is False
    assert ca.user_writable(tmp_path) is True


@pytest.mark.parametrize("public", [False, True])
def test_atomic_file_owner_precedes_secret_bytes(tmp_path, monkeypatch, public):
    _security(monkeypatch)
    events = []
    class Attributes:
        pass
    class Handle:
        def Close(self):
            events.append("closed")
    def create(path, access, share, attributes, disposition, flags, template):
        descriptor = attributes.SECURITY_DESCRIPTOR
        assert descriptor.startswith("O:BAG:BAD:P")
        assert (";;;BU)" in descriptor) is public
        assert share == 0 and disposition == 1
        events.append("admin-owned-exclusive-create")
        return Handle()
    def write(_handle, raw):
        assert events == ["admin-owned-exclusive-create"]
        events.append("write")
        return 0, len(raw)
    monkeypatch.setitem(sys.modules, "pywintypes", SimpleNamespace(SECURITY_ATTRIBUTES=Attributes))
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(GENERIC_WRITE=0x40000000,
        CREATE_NEW=1, FILE_ATTRIBUTE_NORMAL=0x80, FILE_FLAG_OPEN_REPARSE_POINT=0x200000))
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(CreateFile=create,
        WriteFile=write, FlushFileBuffers=lambda _h: events.append("flushed")))
    target = tmp_path / "inert.key"
    ca._create_authority_file(target, b"inert fixture", enforce_acl=True, public_read=public)
    assert events == ["admin-owned-exclusive-create", "write", "flushed", "closed"]
    assert not target.exists()  # The Win32 adapter is entirely fake.


def test_unsafe_existing_namespace_refused_before_key_creation(tmp_path, monkeypatch):
    root = tmp_path / ("Angerona" if ca.os.name == "nt" else "angerona") / "control"
    root.mkdir(parents=True)
    paths = ca.Paths(root)
    monkeypatch.setattr(ca, "_paths", lambda _root: paths)
    monkeypatch.setattr(ca, "_known_program_data", lambda: tmp_path)
    monkeypatch.setattr(ca, "is_admin", lambda: True)
    monkeypatch.setattr(ca, "user_writable", lambda p, **_k: p == root.parent)
    monkeypatch.setattr(ca, "_restrict", lambda *_: pytest.fail("unsafe namespace reached ACL repair"))
    monkeypatch.setattr(ca, "_create_authority_file", lambda *_a, **_k: pytest.fail("unsafe namespace reached key write"))
    with pytest.raises(ValueError, match="owner or ACL"):
        ca.provision()
    assert list(root.iterdir()) == []


def test_unknown_production_acl_never_honors_an_otherwise_valid_stop(tmp_path, monkeypatch):
    root = tmp_path / "control"
    ca.provision(root, require_admin=False)
    ca.issue("operator-stop", "fixture", root=root, require_admin=False)
    paths = ca.Paths(root)
    monkeypatch.setattr(ca, "_paths", lambda _root: paths)
    monkeypatch.setattr(ca, "_verified_production_paths", lambda *_a, **_k: None)
    monkeypatch.setattr(ca, "user_writable", lambda *_a, **_k: None)
    state = ca.status()
    assert state["state"] == "compromised" and state["stop_active"] is False


def test_missing_public_marker_with_authority_residue_cannot_reopen_legacy(tmp_path):
    root = tmp_path / "control"
    ca.provision(root, require_admin=False)
    original = (root / "stop-authority.key").read_bytes()
    (root / "stop-authority.pub").unlink()
    assert ca.provisioned(root)
    assert ca.status(root)["state"] == "compromised"
    with pytest.raises(FileExistsError):
        ca.provision(root, require_admin=False)
    assert (root / "stop-authority.key").read_bytes() == original


def test_unrelated_private_key_read_access_holds_issuer(tmp_path, monkeypatch):
    paths = ca.Paths(tmp_path)
    for path in (paths.private, paths.public, paths.epoch):
        path.write_bytes(b"inert preserved authority")
    monkeypatch.setattr(ca, "_verified_production_paths", lambda *_a, **_k: None)
    monkeypatch.setattr(ca, "user_writable", lambda p, **k:
                        p == paths.private and k.get("_mask") == ca._SECRET_READ_MASK)
    with pytest.raises(ValueError, match="private key read access"):
        ca._verified_issuer(paths, enforce=True)
    assert paths.private.read_bytes() == b"inert preserved authority"


def test_unknown_authority_probe_does_not_fall_back_to_user_hmac(tmp_path, monkeypatch):
    monkeypatch.setattr(token, "_ADMIN_CACHE", {"until": 0.0, "active": False})
    def unavailable(*_a, **_k):
        raise PermissionError("inert namespace denial")
    monkeypatch.setattr(ca, "provisioned", unavailable)
    monkeypatch.setattr(token, "_load_key", lambda: pytest.fail("legacy key fallback"))
    assert token.is_standdown_requested() is False
    authority = token._admin_authority()
    assert authority is not None and authority.unavailable
    with pytest.raises(authority.AdminApprovalRequired):
        token.request_standdown()
    with pytest.raises(RuntimeError, match="could not be verified"):
        token.clear_standdown_for_storage(tmp_path)


def test_source_control_helper_never_elevates_writable_python(monkeypatch):
    monkeypatch.delattr(ca.sys, "frozen", raising=False)
    with pytest.raises(ca.AdminApprovalRequired, match="verified installed"):
        ca._helper_command("provision")


def test_known_folder_failure_is_compromised_not_absent(monkeypatch):
    def unavailable():
        raise OSError("inert known-folder failure")
    monkeypatch.setattr(ca, "_known_program_data", unavailable)
    assert ca.provisioned()
    assert ca.status()["state"] == "compromised"


@pytest.mark.parametrize("leaf", ["epoch.json", "stop-authority.pub", "stop.cmd", "deadman.json", "stop-authority.pub.tmp"])
def test_provision_preserves_interrupted_authority_without_private_key(tmp_path, leaf):
    root = tmp_path / "control"
    root.mkdir()
    residue = root / leaf
    residue.write_bytes(b"preserved interrupted authority")
    with pytest.raises(FileExistsError):
        ca.provision(root, require_admin=False)
    assert residue.read_bytes() == b"preserved interrupted authority"
    assert not (root / "stop-authority.key").exists()


@pytest.mark.parametrize("trusted,image", [(False, "Angerona.exe"), (True, "wrong.exe"), (True, "Angerona.exe")])
def test_frozen_control_requires_process_bound_installed_image(tmp_path, monkeypatch, trusted, image):
    from angerona.core import windows_package_identity as package
    monkeypatch.setattr(ca.sys, "frozen", True, raising=False)
    monkeypatch.setattr(package, "verify_current_msix_authority", lambda:
                        SimpleNamespace(trusted=trusted, reason="inert untrusted package"))
    monkeypatch.setattr(package, "require_current_package_image", lambda _name: tmp_path / image)
    if trusted and image == "Angerona.exe":
        executable, arguments = ca._helper_command("stop")
        assert executable == str(tmp_path / image)
        assert arguments == "--control-authority stop"
    else:
        with pytest.raises(ca.AdminApprovalRequired):
            ca._helper_command("stop")


@pytest.mark.parametrize("query_ok,close_ok,wait_code,expected", [
    (True, True, 0, 7),
    (False, True, 0, "exit could not be verified"),
    (True, False, 0, "handle could not be retired"),
    (True, True, 258, "did not finish"),
])
def test_control_helper_native_completion_requires_verified_exit_and_retirement(
        tmp_path, monkeypatch, query_ok, close_ok, wait_code, expected):
    import ctypes
    from ctypes import wintypes
    from angerona.core import privilege

    sentinel = (1 << 40) + 123
    calls = []
    class Native:
        def __init__(self, function):
            self.function = function
        def __call__(self, *args):
            return self.function(*args)
    def execute(pointer):
        info = pointer._obj
        assert info.lpDirectory == str(tmp_path)
        info.hProcess = sentinel
        calls.append("launch")
        return True
    def wait(handle, _timeout):
        assert handle == sentinel
        calls.append("wait")
        return wait_code
    def query(handle, pointer):
        assert handle == sentinel
        calls.append("query")
        if query_ok:
            pointer._obj.value = 7
        return query_ok
    def close(handle):
        assert handle == sentinel
        calls.append("close")
        return close_ok
    kernel = SimpleNamespace(WaitForSingleObject=Native(wait),
                             GetExitCodeProcess=Native(query), CloseHandle=Native(close))
    shell = SimpleNamespace(ShellExecuteExW=Native(execute))
    monkeypatch.setattr(ca, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(ca.ctypes, "windll", SimpleNamespace(kernel32=kernel, shell32=shell), raising=False)
    monkeypatch.setattr(ca, "_helper_command", lambda _action:
                        (str(tmp_path / "Angerona.exe"), "--control-authority stop"))
    monkeypatch.setattr(privilege, "sanitize_privileged_bootstrap_environment", lambda: None)
    if type(expected) is int:
        assert ca.request_elevated("stop", timeout_s=1) == expected
    else:
        with pytest.raises(ca.AdminApprovalRequired, match=expected):
            ca.request_elevated("stop", timeout_s=1)
    assert calls[-1] == "close"
    assert kernel.WaitForSingleObject.argtypes == [wintypes.HANDLE, wintypes.DWORD]
    assert kernel.GetExitCodeProcess.argtypes == [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    assert kernel.CloseHandle.argtypes == [wintypes.HANDLE]
    assert kernel.GetExitCodeProcess.restype is wintypes.BOOL


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), 0, -1, 3601])
def test_control_helper_rejects_invalid_timeout_before_launch(monkeypatch, timeout):
    monkeypatch.setattr(ca, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(ca, "_helper_command", lambda _action: pytest.fail("invalid timeout reached launch"))
    with pytest.raises(ValueError, match="timeout"):
        ca.request_elevated("stop", timeout_s=timeout)
