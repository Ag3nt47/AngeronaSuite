"""Native credential ACL proof, fail-closed fallback, and actual Windows custody."""
from __future__ import annotations

import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from angerona.core import secure_store


USER = "S-1-5-21-123-456-789-1001"
TRUSTED = frozenset({USER, "S-1-5-18", "S-1-5-32-544"})
FULL = 0x001F01FF


class ACL:
    def __init__(self, entries=()):
        self.entries = list(entries)

    def GetAceCount(self):
        return len(self.entries)

    def GetAce(self, index):
        return self.entries[index]

    def AddAccessAllowedAce(self, _revision, mask, principal):
        self.entries.append(((0, 0), mask, principal))


class Descriptor:
    def __init__(self, *, owner=USER, protected=True, acl=None):
        self.owner, self.protected, self.acl = owner, protected, acl

    def GetSecurityDescriptorOwner(self):
        return self.owner

    def GetSecurityDescriptorControl(self):
        return (0x1000 if self.protected else 0, 1)

    def GetSecurityDescriptorDacl(self):
        return self.acl


def exact_descriptor():
    return Descriptor(acl=ACL([((0, 0), FULL, sid) for sid in sorted(TRUSTED)]))


SECURITY = SimpleNamespace(ConvertSidToStringSid=str, SE_DACL_PROTECTED=0x1000,
                           ACCESS_ALLOWED_ACE_TYPE=0)


@pytest.mark.parametrize("corruption", ["owner", "unprotected", "null-dacl", "missing-grant",
                                       "untrusted", "duplicate", "partial-mask", "inherited",
                                       "inherit-only", "deny", "callback"])
def test_exact_acl_proof_rejects_incomplete_or_broader_descriptors(corruption):
    descriptor = exact_descriptor()
    if corruption == "owner":
        descriptor.owner = "S-1-1-0"
    elif corruption == "unprotected":
        descriptor.protected = False
    elif corruption == "null-dacl":
        descriptor.acl = None
    elif corruption == "missing-grant":
        descriptor.acl.entries.pop()
    else:
        header, mask, sid = descriptor.acl.entries[0]
        if corruption == "untrusted":
            sid = "S-1-1-0"
        elif corruption == "duplicate":
            sid = descriptor.acl.entries[1][2]
        elif corruption == "partial-mask":
            mask = 0x120089
        elif corruption == "inherited":
            header = (0, 0x10)
        elif corruption == "inherit-only":
            header = (0, 0x08)
        elif corruption == "deny":
            header = (1, 0)
        elif corruption == "callback":
            header = (9, 0)
        descriptor.acl.entries[0] = (header, mask, sid)
    assert not secure_store._private_acl_matches(descriptor, USER, TRUSTED, SECURITY)
    assert secure_store._private_acl_matches(exact_descriptor(), USER, TRUSTED, SECURITY)


@pytest.fixture
def native(monkeypatch):
    state = SimpleNamespace(descriptor=Descriptor(protected=False, acl=ACL()),
                            handles=[], sets=[], opens=[], info_calls=0, fault=None,
                            token_closed=False, user=USER)

    class Handle:
        closed = False

        def Close(self):
            self.closed = True

    class Token:
        def Close(self):
            state.token_closed = True

    def open_file(*args):
        state.opens.append(args)
        handle = Handle()
        state.handles.append(handle)
        return handle

    def file_info(_handle):
        state.info_calls += 1
        flags = 0x400 if state.fault == "reparse" else 0x10 if state.fault == "directory" else 0x80
        links = 2 if state.fault == "hardlink" else 1
        inode = 7
        if ((state.fault == "held-identity" and state.info_calls == 2)
                or (state.fault == "path-identity" and state.info_calls == 3)):
            inode = 8
        return (flags, None, None, None, 1, 0, 10, links, 0, inode)

    def set_security(*args):
        state.sets.append(args)
        if state.fault == "api":
            raise OSError("inert native ACL update failure")
        if state.fault == "late-import-error":
            raise ImportError("inert failure after native imports succeeded")
        if state.fault != "readback":
            owner = "S-1-1-0" if state.fault == "owner-readback" else state.descriptor.owner
            state.descriptor = Descriptor(owner=owner, acl=args[5])

    security = SimpleNamespace(**vars(SECURITY), OpenProcessToken=lambda *_args: Token(),
                               GetTokenInformation=lambda *_args: (state.user, 0), TokenUser=1,
                               GetSecurityInfo=lambda *_args: state.descriptor,
                               SetSecurityInfo=set_security, ConvertStringSidToSid=str,
                               ACL=ACL, ACL_REVISION=2, SE_FILE_OBJECT=1,
                               OWNER_SECURITY_INFORMATION=1, DACL_SECURITY_INFORMATION=4,
                               PROTECTED_DACL_SECURITY_INFORMATION=0x80000000)
    constants = SimpleNamespace(READ_CONTROL=0x20000, WRITE_DAC=0x40000, TOKEN_QUERY=8,
                                FILE_SHARE_READ=1, FILE_SHARE_WRITE=2, OPEN_EXISTING=3,
                                FILE_FLAG_OPEN_REPARSE_POINT=0x200000)
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(GetCurrentProcess=lambda: -1))
    monkeypatch.setitem(sys.modules, "win32con", constants)
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(
        CreateFile=open_file, GetFileInformationByHandle=file_info))
    monkeypatch.setitem(sys.modules, "win32security", security)
    monkeypatch.setattr(secure_store, "_path_traverses_reparse", lambda _path: False)
    monkeypatch.setattr(secure_store.sys, "platform", "win32")
    monkeypatch.setattr(secure_store.subprocess, "run", lambda *_a, **_k: pytest.fail(
        "Available native APIs must never use the legacy subprocess fallback"))
    return state


def test_native_restricts_exact_dacl_and_preserves_owner_and_handle_custody(native):
    secure_store._native_private_acl(Path("inert-credential"))
    assert len(native.sets) == 1
    update = native.sets[0]
    assert update[2] == 0x80000004
    assert update[3:5] == (None, None), "Owner and group must not be reassigned"
    assert secure_store._private_acl_matches(native.descriptor, USER, TRUSTED, SECURITY)
    assert native.token_closed and all(handle.closed for handle in native.handles)
    assert len(native.handles) == 2  # Retained inode plus fresh pathname identity proof.
    assert all(args[2] == 3 and args[5] == 0x200000 for args in native.opens)


def test_already_private_acl_is_freshly_verified_without_rewriting(native):
    native.descriptor = exact_descriptor()
    secure_store._native_private_acl(Path("inert-credential"))
    assert native.sets == []
    # A later call must observe revocation instead of reusing the first proof.
    native.descriptor.protected = False
    secure_store._native_private_acl(Path("inert-credential"))
    assert len(native.sets) == 1
    assert all(handle.closed for handle in native.handles)


def test_system_token_deduplicates_trusted_sid_without_changing_owner(native):
    native.user = native.descriptor.owner = "S-1-5-18"
    secure_store._native_private_acl(Path("inert-credential"))
    assert native.descriptor.acl.GetAceCount() == 2
    assert secure_store._private_acl_matches(
        native.descriptor, "S-1-5-18", frozenset({"S-1-5-18", "S-1-5-32-544"}), SECURITY)


@pytest.mark.parametrize("fault", ["reparse", "directory", "hardlink", "owner", "api",
                                  "late-import-error", "readback", "owner-readback",
                                  "held-identity", "path-identity"])
def test_native_faults_never_fall_back_or_leak_handles(native, fault):
    native.fault = fault
    if fault == "owner":
        native.descriptor.owner = "S-1-1-0"
    with pytest.raises((OSError, ImportError)):
        secure_store._native_private_acl(Path("inert-credential"))
    native.info_calls = 0
    assert secure_store._private_acl(Path("inert-credential")) is None
    assert all(handle.closed for handle in native.handles)
    if fault in {"reparse", "directory", "hardlink", "owner"}:
        assert native.sets == []


def test_native_refuses_reparse_ancestor_before_open(native, monkeypatch):
    monkeypatch.setattr(secure_store, "_path_traverses_reparse", lambda _path: True)
    secure_store._private_acl(Path("inert-credential"))
    assert native.handles == [] and native.sets == []


def test_only_missing_dependency_selects_legacy_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_store.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "win32api", None)
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    monkeypatch.setenv("USERNAME", "fixture-user")
    monkeypatch.setenv("USERDOMAIN", "fixture-domain")
    utility = tmp_path / "System32/icacls.exe"
    utility.parent.mkdir()
    utility.write_bytes(b"inert")
    target = tmp_path / "credential"
    target.write_bytes(b"inert")
    calls = []
    monkeypatch.setattr(secure_store.subprocess, "run", lambda *a, **k: calls.append((a, k)))
    assert secure_store._private_acl(target) is None
    assert len(calls) == 1 and "/inheritance:r" in calls[0][0][0]
    assert "fixture-domain\\fixture-user:(F)" in calls[0][0][0]
    monkeypatch.setattr(secure_store, "_path_traverses_reparse", lambda _path: True)
    secure_store._private_acl(target)
    assert len(calls) == 1


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows file security descriptors")
def test_actual_native_acl_rename_reverification_and_no_subprocess(tmp_path, monkeypatch):
    security = pytest.importorskip("win32security")
    target = tmp_path / "credential.tmp"
    target.write_bytes(b"inert protected fixture")
    before = security.GetFileSecurity(str(target), security.OWNER_SECURITY_INFORMATION)
    owner = security.ConvertSidToStringSid(before.GetSecurityDescriptorOwner())
    monkeypatch.setenv("USERNAME", "untrusted-environment-name")
    monkeypatch.setenv("USERDOMAIN", "untrusted-environment-domain")
    monkeypatch.setattr(secure_store.subprocess, "run", lambda *_a, **_k: pytest.fail("Native ACL spawned a process"))
    secure_store._native_private_acl(target)
    descriptor = security.GetFileSecurity(str(target), 5)
    import win32api
    token = security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        user = security.ConvertSidToStringSid(security.GetTokenInformation(token, security.TokenUser)[0])
    finally:
        token.Close()
    trusted = frozenset({user, "S-1-5-18", "S-1-5-32-544"})
    assert secure_store._private_acl_matches(descriptor, owner, trusted, security)
    final = tmp_path / "credential.dpapi"
    os.replace(target, final)
    monkeypatch.setattr(security, "SetSecurityInfo", lambda *_a, **_k: pytest.fail("Already private inode was rewritten"))
    secure_store._native_private_acl(final)
    assert final.read_bytes() == b"inert protected fixture"


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows file identity and link count")
def test_actual_native_rejects_hardlink_without_mutating_its_dacl(tmp_path):
    security = pytest.importorskip("win32security")
    target, alias = tmp_path / "credential", tmp_path / "alias"
    target.write_bytes(b"inert")
    os.link(target, alias)
    before = security.ConvertSecurityDescriptorToStringSecurityDescriptor(
        security.GetFileSecurity(str(target), 5), 1, 5)
    with pytest.raises(PermissionError, match="single-link"):
        secure_store._native_private_acl(target)
    after = security.ConvertSecurityDescriptorToStringSecurityDescriptor(
        security.GetFileSecurity(str(alias), 5), 1, 5)
    assert before == after and alias.read_bytes() == b"inert"


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows DPAPI and ACL integration")
def test_actual_dpapi_write_keeps_both_acl_boundaries_and_fsync(tmp_path, monkeypatch):
    security = pytest.importorskip("win32security")
    import win32api
    token = security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        user = security.ConvertSidToStringSid(security.GetTokenInformation(token, security.TokenUser)[0])
    finally:
        token.Close()
    trusted = frozenset({user, "S-1-5-18", "S-1-5-32-544"})
    acl, synced = [], []
    original_acl, original_sync = secure_store._private_acl, os.fsync

    def harden(path):
        acl.append(Path(path))
        original_acl(path)
        descriptor = security.GetFileSecurity(str(path), 5)
        owner = security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
        assert owner in trusted
        assert secure_store._private_acl_matches(descriptor, owner, trusted, security)

    def sync(descriptor):
        synced.append(descriptor)
        return original_sync(descriptor)

    monkeypatch.setattr(secure_store, "_private_acl", harden)
    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(secure_store.subprocess, "run", lambda *_a, **_k: pytest.fail("DPAPI native ACL spawned a process"))
    path = secure_store.write_secret_map({"ANGERONA_TEST_NATIVE_ACL": "inert-credential"}, tmp_path)
    assert len(acl) == 2 and acl[0].name.endswith(".tmp") and acl[1] == path
    assert synced and b"inert-credential" not in path.read_bytes()
    assert secure_store.read_secret_values(("ANGERONA_TEST_NATIVE_ACL",), tmp_path, strict=True) == {
        "ANGERONA_TEST_NATIVE_ACL": "inert-credential"}
