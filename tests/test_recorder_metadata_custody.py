"""Owned temporary files and inert native-failure models, never a host profile."""
from __future__ import annotations

import ctypes
import os
import threading
from types import SimpleNamespace

import pytest

from angerona.core import file_lease, recorder_metadata_custody as custody
from angerona.core import startup_recovery


@pytest.fixture(autouse=True)
def modeled_hold_isolation(monkeypatch):
    # These lists contain only the inert fault models in this test process.
    monkeypatch.setattr(custody, "_RETIREMENT_HOLDS", [])
    monkeypatch.setattr(file_lease, "_PRIVATE_RETIREMENT_HOLDS", [])


@pytest.fixture
def private_root(tmp_path):
    root = tmp_path / "private-archive"
    assert startup_recovery.private_directory(root, create=True)
    return root


class FakeApi:
    """Model raw ownership and ordering, not real Windows custody acceptance."""
    def __init__(self):
        self.events = []
        self.path = None
        self.converted_fd = None
        self.verify_error = None
        self.aux_close_ok = True
        self.raw_close_ok = True

    def attributes(self, owner):
        self.events.append("attributes-TokenUser")
        owner.resource(123, self.close_aux)
        return "protected-TokenUser-SY-BA", "TokenUser", "expected-DACL"

    def open_file(self, owner, path, access, create_new, attributes):
        self.events.append(("create", attributes, create_new, access))
        self.path = path
        if create_new:
            path.touch(exist_ok=False)
        owner.raw_handle = 900
        return 900

    def verify(self, owner, handle, user, expected, *, created):
        self.events.append("verify-before-transfer")
        assert self.path.read_bytes() == b""
        if self.verify_error:
            raise self.verify_error

    def to_fd(self, handle, flags):
        self.events.append("transfer")
        self.converted_fd = os.open(self.path, flags & (os.O_WRONLY | os.O_RDWR))
        return self.converted_fd

    def close_handle(self, value):
        self.events.append(("raw-close", value))
        return self.raw_close_ok

    def close_aux(self, value):
        self.events.append(("aux-close", value))
        return self.aux_close_ok


@pytest.fixture
def model(tmp_path, monkeypatch):
    api = FakeApi()
    monkeypatch.setattr(custody, "_windows_platform", lambda: True)
    monkeypatch.setattr(custody, "_windows_api", lambda: api)
    monkeypatch.setattr(startup_recovery, "private_directory", lambda *_a, **_k: True)
    monkeypatch.setattr(startup_recovery, "private_repair_file", lambda *_a: True)
    return api, tmp_path / "new-metadata"


def test_raw_native_transfer_has_one_owner_and_verifies_before_any_data(model):
    api, path = model
    descriptor = custody.open_private_metadata(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        assert path.read_bytes() == b""
        assert api.events.index("verify-before-transfer") < api.events.index("transfer")
        assert not any(isinstance(e, tuple) and e[0] == "raw-close" for e in api.events)
        os.write(descriptor, b"fixture bytes only")
    finally:
        os.close(descriptor)
    assert path.read_bytes() == b"fixture bytes only" and not custody.metadata_retirement_held()


def test_unknown_crt_transfer_retains_exact_raw_owner_and_never_retries(model):
    api, path = model
    def transfer_then_error(handle, flags):
        descriptor = os.open(path, os.O_WRONLY)
        os.close(descriptor)  # Known model fixture resource, not a product retry.
        api.events.append("transfer-took-effect")
        raise OSError("modeled outcome unknown after CRT admission")
    api.to_fd = transfer_then_error
    with pytest.raises(custody.MetadataCreationUncertain) as error:
        custody.open_private_metadata(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    owner = error.value.owner
    assert owner in custody._RETIREMENT_HOLDS and owner.transfer_pending and owner.raw_handle == 900
    assert not owner.retire() and not owner.retire()
    assert api.events.count("transfer-took-effect") == 1
    assert ("raw-close", 900) not in api.events and ("aux-close", 123) not in api.events
    with pytest.raises(PermissionError, match="retirement"):
        custody.open_private_metadata(path.parent / "replacement", os.O_CREAT | os.O_EXCL | os.O_WRONLY)


def test_unknown_native_create_admission_retains_buffers_and_auxiliary_owner(model):
    api, path = model
    def fail_after_admission(owner, *_args):
        def unknown():
            raise RuntimeError("modeled FFI admission uncertainty")
        return owner.call("CreateFileW", unknown)
    api.open_file = fail_after_admission
    with pytest.raises(custody.MetadataCreationUncertain) as error:
        custody.open_private_metadata(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    owner = error.value.owner
    assert owner.pending_native[0] == "CreateFileW" and owner in custody._RETIREMENT_HOLDS
    assert not owner.retire() and ("aux-close", 123) not in api.events


def test_auxiliary_close_failure_closes_known_fd_once_but_never_claims_clean(model):
    api, path = model
    api.aux_close_ok = False
    with pytest.raises(custody.MetadataCreationUncertain) as error:
        custody.open_private_metadata(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    owner = error.value.owner
    with pytest.raises(OSError):
        os.fstat(api.converted_fd)
    assert api.events.count(("aux-close", 123)) == 1
    assert not owner.retire() and api.events.count(("aux-close", 123)) == 1
    assert ("raw-close", 900) not in api.events and custody.metadata_retirement_held()


def test_known_verification_refusal_closes_raw_once_and_preserves_empty_original(model):
    api, path = model
    api.verify_error = PermissionError("native owner or rights differ")
    with pytest.raises(PermissionError, match="rights differ"):
        custody.open_private_metadata(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    assert path.read_bytes() == b"" and api.events.count(("raw-close", 900)) == 1
    assert "transfer" not in api.events and not custody.metadata_retirement_held()


def test_raw_close_false_is_sticky_and_never_retried(model):
    api, path = model
    api.verify_error, api.raw_close_ok = PermissionError("private refusal"), False
    with pytest.raises(custody.MetadataCreationUncertain) as error:
        custody.open_private_metadata(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    owner = error.value.owner
    assert not owner.retire() and not owner.retire()
    assert api.events.count(("raw-close", 900)) == 1 and owner.ambiguous_numbers == [900]
    assert api.events.count(("aux-close", 123)) == 1


def test_overlapping_retirement_cannot_publish_clean_while_native_close_is_pending():
    entered, release = threading.Event(), threading.Event()
    calls, results = [], []
    owner = custody._CreationOwner(None)
    def close(value):
        calls.append(value)
        entered.set()
        assert release.wait(5)
        return True
    owner.resource(123, close)
    worker = threading.Thread(target=lambda: results.append(owner.retire()), daemon=False)
    worker.start()
    try:
        assert entered.wait(5)
        assert owner.retire() is False
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive() and results == [False] and calls == [123]
    assert owner.retire() is False and calls == [123] and custody.metadata_retirement_held()


def test_fd_close_error_after_failed_identity_check_is_not_retried(model, monkeypatch):
    api, path = model
    original = custody._plain_path
    calls = []
    def identity(item, **kwargs):
        result = original(item, **kwargs)
        if item == path:
            return SimpleNamespace(st_dev=result.st_dev, st_ino=result.st_ino + 1)
        return result
    real_close = os.close
    def close_then_error(descriptor):
        calls.append(descriptor)
        real_close(descriptor)
        raise OSError("modeled close completed before its error")
    monkeypatch.setattr(custody, "_plain_path", identity)
    monkeypatch.setattr(custody, "_close_fd", close_then_error)
    with pytest.raises(custody.MetadataCreationUncertain) as error:
        custody.open_private_metadata(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    assert calls == [api.converted_fd]
    assert not error.value.owner.retire() and calls == [api.converted_fd]


def test_sd_uses_token_user_even_when_default_owner_is_administrators(monkeypatch):
    """Execute real SD-construction logic with inert TokenUser/TokenOwner data."""
    from ctypes import wintypes as w
    events, buffers = [], []
    token_user = "S-1-5-21-100-200-300-1001"
    default_owner = "S-1-5-32-544"
    def function(callback):
        return callback
    def open_token(_process, _access, output):
        ctypes.cast(output, ctypes.POINTER(w.HANDLE))[0] = 101
        return 1
    def information(_token, kind, output, _size, used):
        events.append(("token-information", kind))
        assert kind == 1  # TokenUser; never choose TokenOwner/default Administrators.
        ctypes.cast(used, ctypes.POINTER(w.DWORD))[0] = 64
        if output is not None:
            ctypes.cast(output, ctypes.POINTER(w.LPVOID))[0] = 0x1234
            return 1
        return 0
    def sid_text(sid, output):
        assert sid == 0x1234
        text = ctypes.create_unicode_buffer(token_user)
        buffers.append(text)
        ctypes.cast(output, ctypes.POINTER(w.LPWSTR))[0] = ctypes.cast(text, w.LPWSTR)
        return 1
    def descriptor(text, _revision, output, _size):
        events.append(("sddl", text))
        ctypes.cast(output, ctypes.POINTER(w.LPVOID))[0] = 0x5678
        return 1
    kernel = SimpleNamespace(GetCurrentProcess=function(lambda: -1), CloseHandle=function(lambda _v: 1),
        LocalFree=function(lambda _v: None), CreateFileW=function(lambda *_a: 900))
    adv = SimpleNamespace(OpenProcessToken=function(open_token), GetTokenInformation=function(information),
        ConvertSidToStringSidW=function(sid_text),
        ConvertStringSecurityDescriptorToSecurityDescriptorW=function(descriptor),
        GetSecurityInfo=function(lambda *_a: 0), EqualSid=function(lambda *_a: 1),
        GetSecurityDescriptorControl=function(lambda *_a: 1), GetSecurityDescriptorDacl=function(lambda *_a: 1))
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, **_k: kernel if name == "kernel32" else adv, raising=False)
    api = custody._WindowsApi()
    owner = custody._CreationOwner(api)
    attributes, user_sid, _expected = api.attributes(owner)
    expected = f"O:{token_user}D:P(A;;FA;;;{token_user})(A;;FA;;;SY)(A;;FA;;;BA)"
    assert ("sddl", expected) in events and default_owner not in expected
    assert not attributes.inherit and user_sid == 0x1234
    assert owner.retire()


@pytest.mark.parametrize("access", [os.O_WRONLY, os.O_RDWR])
def test_actual_new_file_is_private_before_first_write_and_never_overwritten(private_root, access):
    target = private_root / "pending.json"
    descriptor = custody.open_private_metadata(target, os.O_CREAT | os.O_EXCL | access)
    try:
        assert target.stat().st_size == 0 and startup_recovery.private_repair_file(target)
        if os.name == "nt":
            import win32security
            security = win32security.GetFileSecurity(str(target), 5)
            assert security.GetSecurityDescriptorControl()[0] & 0x1000
        else:
            assert target.stat().st_mode & 0o777 == 0o600
        os.write(descriptor, b"private fixture original")
    finally:
        os.close(descriptor)
    with pytest.raises(FileExistsError):
        custody.open_private_metadata(target, os.O_CREAT | os.O_EXCL | access)
    assert target.read_bytes() == b"private fixture original"


def test_actual_private_lease_uses_verified_creator_and_keeps_second_writer_out(private_root):
    path = private_root / ".writer.lock"
    with file_lease.ExclusiveFileLease(path, opener=custody.open_private_metadata) as first:
        assert first.held and path.stat().st_size == 1 and startup_recovery.private_repair_file(path)
        with pytest.raises(file_lease.ExclusiveFileLeaseError):
            file_lease.ExclusiveFileLease(path, opener=custody.open_private_metadata)
    assert path.read_bytes() == b"\0"


def test_default_lease_does_not_call_private_creator(tmp_path, monkeypatch):
    def forbidden(*_a, **_k):
        pytest.fail("Default authority lease unexpectedly changed custody policy")
    monkeypatch.setattr(custody, "open_private_metadata", forbidden)
    path = tmp_path / "legacy-default.lock"
    with file_lease.ExclusiveFileLease(path) as first:
        assert first.held and path.stat().st_size == 1
        with pytest.raises(file_lease.ExclusiveFileLeaseError):
            file_lease.ExclusiveFileLease(path)
    assert path.read_bytes() == b"\0"
    with file_lease.ExclusiveFileLease(path) as next_owner:
        assert next_owner.held


def test_private_lease_constructor_close_failure_retains_exact_owner(private_root, monkeypatch):
    path = private_root / ".writer.lock"
    original_fstat, original_close = os.fstat, os.close
    descriptors, closes = [], []
    def opener(*args):
        descriptor = custody.open_private_metadata(*args)
        descriptors.append(descriptor)
        return descriptor
    def invalid_identity(descriptor):
        if descriptor in descriptors:
            raise ValueError("modeled validation failure after private open")
        return original_fstat(descriptor)
    def close_then_error(descriptor):
        closes.append(descriptor)
        original_close(descriptor)
        raise OSError("modeled descriptor close uncertainty")
    monkeypatch.setattr(file_lease.os, "fstat", invalid_identity)
    monkeypatch.setattr(file_lease.os, "close", close_then_error)
    with pytest.raises(file_lease.PrivateLeaseRetirementHeld) as error:
        file_lease.ExclusiveFileLease(path, opener=opener)
    owner = error.value.owner
    assert owner in file_lease._PRIVATE_RETIREMENT_HOLDS and closes == descriptors
    with pytest.raises(file_lease.PrivateLeaseRetirementHeld):
        owner.close()
    assert closes == descriptors


def test_private_lease_relative_and_absolute_names_share_sticky_retirement_fence(private_root, monkeypatch):
    monkeypatch.chdir(private_root.parent)
    relative = os.path.join(private_root.name, ".writer.lock")
    absolute = private_root / ".writer.lock"
    owner = file_lease.ExclusiveFileLease(relative, opener=custody.open_private_metadata)
    real_close, calls = os.close, []
    def close_then_error(descriptor):
        calls.append(descriptor)
        real_close(descriptor)
        raise OSError("modeled close happened before its failure was observable")
    monkeypatch.setattr(file_lease.os, "close", close_then_error)
    with pytest.raises(file_lease.PrivateLeaseRetirementHeld) as error:
        owner.close()
    assert error.value.owner is owner and len(calls) == 1
    for path in (relative, absolute):
        with pytest.raises(file_lease.PrivateLeaseRetirementHeld) as blocked:
            file_lease.ExclusiveFileLease(path, opener=custody.open_private_metadata)
        assert blocked.value.owner is owner
    assert owner._private_candidate == absolute and len(calls) == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows native fixture custody")
def test_existing_extra_principal_is_held_without_acl_rewrite_or_lease_byte(private_root):
    import win32security
    path = private_root / ".writer.lock"
    descriptor = custody.open_private_metadata(path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
    os.close(descriptor)
    before = win32security.GetFileSecurity(str(path), 5)
    sid = win32security.ConvertSidToStringSid(before.GetSecurityDescriptorOwner())
    wide = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)", 1)
    # The fixture file is already protected and user-owned. Change only its
    # DACL; do not pass a high unsigned security-info mask through PyLong/C long.
    win32security.SetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION, wide)
    expected = win32security.GetFileSecurity(str(path), 5)
    text_before = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(expected, 1, 5)
    assert not startup_recovery.private_repair_file(path)
    with pytest.raises(PermissionError, match="not private"):
        file_lease.ExclusiveFileLease(path, opener=custody.open_private_metadata)
    text_after = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
        win32security.GetFileSecurity(str(path), 5), 1, 5)
    assert text_before == text_after and path.read_bytes() == b""


def test_existing_hardlink_is_refused_without_writing_original(private_root):
    original, link = private_root / "original", private_root / ".writer.lock"
    original.write_bytes(b"fixture original")
    try:
        os.link(original, link)
    except OSError as exc:
        pytest.skip("Temporary filesystem does not support fixture hardlinks: " + type(exc).__name__)
    with pytest.raises((PermissionError, file_lease.ExclusiveFileLeaseError)):
        file_lease.ExclusiveFileLease(link, opener=custody.open_private_metadata)
    assert original.read_bytes() == b"fixture original" and link.read_bytes() == b"fixture original"
