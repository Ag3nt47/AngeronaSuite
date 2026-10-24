"""Real Windows deny-delete readers and refusal of unsafe credential retries."""
from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys

import pytest

from angerona.core import secure_store
from angerona.core.eventbus import Event, Severity
from angerona.modules.adversary_combat import AdversaryCombat, JournalIntegrityError, _JOURNAL_CONTEXT


_PREFIX = b"ANGERONA-INERT-REPLACE-TEST\0"


def _private_test_directory(path):
    if os.name != "nt":
        return
    import win32api
    import win32security as security
    token = security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        user = security.GetTokenInformation(token, security.TokenUser)[0]
    finally:
        token.Close()
    acl = security.ACL()
    for sid in {security.ConvertSidToStringSid(user), "S-1-5-18", "S-1-5-32-544"}:
        acl.AddAccessAllowedAceEx(2, 3, 0x001F01FF, security.ConvertStringSidToSid(sid))
    security.SetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
                                 security.DACL_SECURITY_INFORMATION
                                 | security.PROTECTED_DACL_SECURITY_INFORMATION,
                                 None, None, acl, None)


@pytest.fixture
def inert(monkeypatch, tmp_path):
    from types import SimpleNamespace

    monkeypatch.setattr(secure_store, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(secure_store, "_protect_bytes", lambda value: _PREFIX + value)
    monkeypatch.setattr(secure_store, "_unprotect_bytes", lambda value:
                        value[len(_PREFIX):] if value.startswith(_PREFIX) else None)
    _private_test_directory(tmp_path)
    # Leave the real ACL, filesystem, store transaction and atomic rename intact.
    secure_store.write_secret_map({"INERT_UNRELATED": "preserve"}, tmp_path)
    return tmp_path


def _sharing_error(code=5):
    error = PermissionError(errno.EACCES, "inert native sharing failure")
    if code is not None:
        error.winerror = code
    return error


def _pair(root):
    source, destination = root / "candidate.tmp", root / "target.bin"
    source.write_bytes(b"candidate protected bytes")
    destination.write_bytes(b"original protected bytes")
    secure_store._private_acl(source)
    secure_store._private_acl(destination)
    return source, destination


@pytest.mark.skipif(sys.platform != "win32", reason="Uses actual Windows deny-delete sharing")
@pytest.mark.parametrize("release_after_failure", [True, False])
def test_actual_rollback_caller_handles_transient_reader_and_preserves_persistent_hold(
    inert, monkeypatch, release_after_failure,
):
    key = b"inert fixture authority bytes!!!"[:32].ljust(32, b"!")
    (inert / "bus.key").write_text(key.hex(), encoding="ascii")
    module = AdversaryCombat(inert)
    module._journal_key_cache = hmac.new(key, _JOURNAL_CONTEXT, hashlib.sha256).digest()
    module._read_journal(strict=True)
    image = str(inert / "never-executed.exe")
    action = module._action("isolate_program", image, Event("Inert", "fixture", Severity.HIGH),
                            "combat-0123456789ab", reversible=True,
                            details={"pid": 999999, "create_time": 1.0, "exe": image,
                                     "rules": ["Angerona-Combat-Program-999999-0123abcd"]})
    module._journal_intent(action)
    protected = inert / "secrets.dpapi"
    real_replace = os.replace
    reader = []
    failures, undo_calls, emitted = [], [], []
    original_undo = module._append_undo_phase

    def append_undo(*args, **kwargs):
        if args[0] != "undo_intent":
            return original_undo(*args, **kwargs)
        # This ordinary reader is the real Windows share-delete collision.
        with protected.open("rb") as held:
            assert held.read(1)
            reader.append(held)
            return original_undo(*args, **kwargs)

    def replace(source, destination):
        try:
            return real_replace(source, destination)
        except PermissionError as exc:
            if Path(destination) == protected and reader:
                failures.append((exc.winerror, exc.errno))
                if release_after_failure:
                    reader[-1].close()
            raise

    monkeypatch.setattr(module, "_append_undo_phase", append_undo)
    monkeypatch.setattr(module, "_undo_record", lambda _record: undo_calls.append(True) or (True, ""))
    monkeypatch.setattr(module, "emit", lambda message, severity, **details: emitted.append(details))
    monkeypatch.setattr(secure_store.os, "replace", replace)
    module._rollback_uncertain_reversible_mutation(action, "program firewall postcondition failed",
                                                  release_custody=lambda: None)
    assert failures and all(code in {5, 32} and number == errno.EACCES for code, number in failures)
    anchor = module._validated_recovery_anchor(module._read_recovery_anchor_value())
    witness = module._read_recovery_witness()
    assert secure_store.read_secret_values(("INERT_UNRELATED",), inert, strict=True) == {
        "INERT_UNRELATED": "preserve"}
    if release_after_failure:
        records, legacy = module._read_journal(strict=True)
        assert not legacy and len(records) == anchor["last_journal_sequence"] == witness["last_journal_sequence"] == 5
        assert [r["record_type"] for r in records] == ["intent", "orphan", "undo_intent", "undo_commit", "failure"]
        assert len(failures) == 1 and undo_calls == [True] and not module._mutation_blocked
        assert module._pending_recovery_records() == {}
    else:
        assert len(failures) == 7 and undo_calls == [] and module._mutation_blocked
        assert anchor["last_journal_sequence"] == witness["last_journal_sequence"] == 2
        assert len(module.receipt_path.read_bytes().splitlines()) == 3
        assert emitted[-1]["recovery_cause_types"] == ["JournalIntegrityError", "PermissionError"]
        assert emitted[-1]["recovery_cause_codes"] == [{
            "cause_index": 1, "winerror": failures[-1][0], "errno": errno.EACCES,
            "boundary": "credential-atomic-replace"}]
        with pytest.raises(JournalIntegrityError, match="incomplete anchor transaction"):
            module._read_journal(strict=True)


@pytest.mark.parametrize("code", [None, 33, 87])
def test_unknown_permission_failures_never_retry(inert, monkeypatch, code):
    source, destination = _pair(inert)
    calls, sleeps = [], []

    def fail(*_args):
        calls.append(True)
        raise _sharing_error(code)

    monkeypatch.setattr(secure_store.os, "replace", fail)
    monkeypatch.setattr(secure_store.time, "sleep", sleeps.append)
    with secure_store.secret_transaction(inert), pytest.raises(PermissionError):
        secure_store._replace_credential_file(source, destination, inert)
    assert calls == [True] and not sleeps
    assert source.read_bytes() == b"candidate protected bytes"
    assert destination.read_bytes() == b"original protected bytes"


@pytest.mark.skipif(os.name != "nt", reason="Windows-specific classified retry")
@pytest.mark.parametrize("code", [5, 32])
def test_classified_failure_has_seven_attempts_and_fixed_sleep_budget(inert, monkeypatch, code):
    source, destination = _pair(inert)
    calls, sleeps = [], []

    def fail(*_args):
        calls.append(True)
        raise _sharing_error(code)

    monkeypatch.setattr(secure_store.os, "replace", fail)
    monkeypatch.setattr(secure_store.time, "sleep", sleeps.append)
    with secure_store.secret_transaction(inert), pytest.raises(PermissionError) as raised:
        secure_store._replace_credential_file(source, destination, inert)
    assert len(calls) == 7 and sum(sleeps) == pytest.approx(0.7)
    assert raised.value.angerona_write_boundary == "credential-atomic-replace"
    assert source.read_bytes() == b"candidate protected bytes"
    assert destination.read_bytes() == b"original protected bytes"


@pytest.mark.skipif(os.name != "nt", reason="Windows-specific classified retry")
@pytest.mark.parametrize("change", ["source-content", "source-replaced", "source-hardlinked",
                                   "destination-content", "destination-replaced", "published-then-error"])
def test_changed_custody_or_possible_publication_refuses_retry(inert, monkeypatch, change):
    source, destination = _pair(inert)
    real_replace = os.replace
    calls, sleeps = [], []

    def fail(src, dst):
        calls.append(True)
        if change == "source-content":
            source.write_bytes(b"other candidate bytes")
        elif change == "source-replaced":
            new = inert / "other-source.tmp"
            new.write_bytes(source.read_bytes())
            real_replace(new, source)
        elif change == "source-hardlinked":
            os.link(source, inert / "source-alias.bin")
        elif change == "destination-content":
            destination.write_bytes(b"concurrent protected generation")
        elif change == "destination-replaced":
            new = inert / "other-destination.tmp"
            new.write_bytes(destination.read_bytes())
            real_replace(new, destination)
        else:
            real_replace(src, dst)
        raise _sharing_error(32)

    monkeypatch.setattr(secure_store.os, "replace", fail)
    monkeypatch.setattr(secure_store.time, "sleep", sleeps.append)
    with secure_store.secret_transaction(inert), pytest.raises(OSError):
        secure_store._replace_credential_file(source, destination, inert)
    assert calls == [True] and not sleeps
    if change == "destination-content":
        assert destination.read_bytes() == b"concurrent protected generation"
    elif change == "published-then-error":
        assert destination.read_bytes() == b"candidate protected bytes" and not source.exists()
    else:
        assert destination.read_bytes() == b"original protected bytes"


def test_transaction_required_before_publication(inert, monkeypatch):
    source, destination = _pair(inert)
    calls = []
    monkeypatch.setattr(secure_store.os, "replace", lambda *_args: calls.append(True))
    with pytest.raises(RuntimeError, match="transaction is absent"):
        secure_store._replace_credential_file(source, destination, inert)
    assert not calls


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows security descriptors")
@pytest.mark.parametrize("target", ["source", "destination", "parent"])
@pytest.mark.parametrize("change", ["dacl", "control"])
def test_native_security_drift_refuses_retry_without_repair(inert, monkeypatch, target, change):
    import win32security as security
    source, destination = _pair(inert)
    path = {"source": source, "destination": destination, "parent": inert}[target]
    original = security.GetFileSecurity(str(path), 5)
    calls, sleeps = [], []

    def fail(*_args):
        calls.append(True)
        acl = security.ACL()
        prior = original.GetSecurityDescriptorDacl()
        for index in range(prior.GetAceCount()):
            header, mask, principal = prior.GetAce(index)
            acl.AddAccessAllowedAceEx(2, header[1], mask, principal)
        flags = security.PROTECTED_DACL_SECURITY_INFORMATION
        if change == "dacl":
            acl.AddAccessAllowedAce(2, 0x120089, security.ConvertStringSidToSid("S-1-1-0"))
        else:
            flags = security.UNPROTECTED_DACL_SECURITY_INFORMATION
        security.SetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
                                     security.DACL_SECURITY_INFORMATION | flags,
                                     None, None, acl, None)
        with pytest.raises(PermissionError, match="outside private custody"):
            secure_store._credential_security_state(path, directory=target == "parent")
        raise _sharing_error(32)

    monkeypatch.setattr(secure_store.os, "replace", fail)
    monkeypatch.setattr(secure_store.time, "sleep", sleeps.append)
    try:
        with secure_store.secret_transaction(inert), pytest.raises(OSError):
            secure_store._replace_credential_file(source, destination, inert)
        assert calls == [True] and not sleeps
        # The helper must report changed custody, never repair it silently.
        with pytest.raises(PermissionError):
            secure_store._credential_security_state(path, directory=target == "parent")
        assert destination.read_bytes() == b"original protected bytes"
    finally:
        security.SetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
                                     security.DACL_SECURITY_INFORMATION
                                     | security.PROTECTED_DACL_SECURITY_INFORMATION,
                                     None, None, original.GetSecurityDescriptorDacl(), None)


@pytest.mark.skipif(os.name != "nt", reason="Native owner/control descriptor inspection")
@pytest.mark.parametrize("target", ["source", "destination", "parent"])
def test_owner_drift_from_native_provider_refuses_retry(inert, monkeypatch, target):
    import win32file
    import win32security as security
    source, destination = _pair(inert)
    path = {"source": source, "destination": destination, "parent": inert}[target]
    original_get = security.GetSecurityInfo
    original_owner = security.GetFileSecurity(str(path), 1).GetSecurityDescriptorOwner()
    changed, calls, sleeps = [False], [], []

    def get_security(handle, *args):
        descriptor = original_get(handle, *args)
        current = Path(win32file.GetFinalPathNameByHandle(handle, 0).removeprefix("\\\\?\\"))
        if changed[0] and current == path:
            # Inert provider fault: change only the returned descriptor, never
            # the real owner (which could require privileges in a test).
            descriptor.SetSecurityDescriptorOwner(security.ConvertStringSidToSid("S-1-1-0"), False)
        return descriptor

    def fail(*_args):
        calls.append(True)
        changed[0] = True
        raise _sharing_error(32)

    monkeypatch.setattr(security, "GetSecurityInfo", get_security)
    monkeypatch.setattr(secure_store.os, "replace", fail)
    monkeypatch.setattr(secure_store.time, "sleep", sleeps.append)
    with secure_store.secret_transaction(inert), pytest.raises(PermissionError):
        secure_store._replace_credential_file(source, destination, inert)
    assert calls == [True] and not sleeps
    with pytest.raises(PermissionError, match="outside private custody"):
        secure_store._credential_security_state(path, directory=target == "parent")
    assert security.GetFileSecurity(str(path), 1).GetSecurityDescriptorOwner() == original_owner


@pytest.mark.skipif(os.name != "nt", reason="Native trusted directory descriptor")
def test_parent_proof_accepts_protected_system_admin_subset_and_child_inheritance(inert, monkeypatch):
    import win32security as security
    original_get = security.GetSecurityInfo

    def get_security(*args):
        descriptor = original_get(*args)
        acl = security.ACL()
        for principal in ("S-1-5-18", "S-1-5-32-544"):
            acl.AddAccessAllowedAceEx(2, 3, 0x001F01FF, security.ConvertStringSidToSid(principal))
        descriptor.SetSecurityDescriptorDacl(True, acl, False)
        return descriptor

    monkeypatch.setattr(security, "GetSecurityInfo", get_security)
    assert secure_store._credential_security_state(inert, directory=True) is not None


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows inherited route and reader collision")
def test_inherited_trusted_parent_retries_actual_reader_only_with_protected_chain(inert, monkeypatch):
    parent = inert / "inherited-runtime"
    parent.mkdir()
    source, destination = _pair(parent)
    chain = secure_store._credential_parent_security_state(parent)
    assert len(chain) == 2 and not chain[0][1][2] & 0x1000 and chain[1][1][2] & 0x1000
    real_replace, failures = os.replace, []

    def replace(src, dst):
        try:
            return real_replace(src, dst)
        except PermissionError as exc:
            failures.append(exc.winerror)
            held.close()
            raise

    monkeypatch.setattr(secure_store.os, "replace", replace)
    with destination.open("rb") as held:
        with secure_store.secret_transaction(inert):
            secure_store._replace_credential_file(source, destination, inert)
    assert len(failures) == 1 and failures[0] in {5, 32}
    assert not source.exists() and destination.read_bytes() == b"candidate protected bytes"
    assert secure_store._credential_parent_security_state(parent) == chain


@pytest.mark.skipif(os.name != "nt", reason="Native inheritance-route custody")
@pytest.mark.parametrize("change", ["dacl", "control", "owner-provider"])
def test_inheritance_route_security_drift_refuses_retry(inert, monkeypatch, change):
    import win32file
    import win32security as security
    parent = inert / "inherited-runtime"
    parent.mkdir()
    source, destination = _pair(parent)
    original = security.GetFileSecurity(str(inert), 5)
    original_get = security.GetSecurityInfo
    prior_chain = secure_store._credential_parent_security_state(parent)
    changed, calls, sleeps = [False], [], []

    def get_security(handle, *args):
        descriptor = original_get(handle, *args)
        current = Path(win32file.GetFinalPathNameByHandle(handle, 0).removeprefix("\\\\?\\"))
        if changed[0] and change == "owner-provider" and current == inert:
            descriptor.SetSecurityDescriptorOwner(security.ConvertStringSidToSid("S-1-1-0"), False)
        return descriptor

    def fail(*_args):
        calls.append(True)
        changed[0] = True
        if change != "owner-provider":
            acl = security.ACL()
            prior = original.GetSecurityDescriptorDacl()
            for index in range(prior.GetAceCount()):
                header, mask, principal = prior.GetAce(index)
                acl.AddAccessAllowedAceEx(2, header[1], mask, principal)
            control = (security.UNPROTECTED_DACL_SECURITY_INFORMATION if change == "control"
                       else security.PROTECTED_DACL_SECURITY_INFORMATION)
            if change == "dacl":
                acl.AddAccessAllowedAceEx(2, 3, 0x001F01FF, security.ConvertStringSidToSid("S-1-1-0"))
            security.SetNamedSecurityInfo(str(inert), security.SE_FILE_OBJECT,
                                         security.DACL_SECURITY_INFORMATION | control,
                                         None, None, acl, None)
        # Isolate the security route gate from ordinary leaf metadata checks.
        try:
            assert secure_store._credential_parent_security_state(parent) != prior_chain
        except PermissionError:
            pass
        raise _sharing_error(32)

    monkeypatch.setattr(security, "GetSecurityInfo", get_security)
    monkeypatch.setattr(secure_store.os, "replace", fail)
    monkeypatch.setattr(secure_store.time, "sleep", sleeps.append)
    try:
        with secure_store.secret_transaction(inert), pytest.raises(PermissionError):
            secure_store._replace_credential_file(source, destination, inert)
        assert calls == [True] and not sleeps
        assert destination.read_bytes() == b"original protected bytes"
    finally:
        security.SetNamedSecurityInfo(str(inert), security.SE_FILE_OBJECT,
                                     security.DACL_SECURITY_INFORMATION
                                     | security.PROTECTED_DACL_SECURITY_INFORMATION,
                                     None, None, original.GetSecurityDescriptorDacl(), None)


@pytest.mark.skipif(os.name != "nt", reason="Native conservative inheritance-route admission")
@pytest.mark.parametrize("unsafe", ["outsider-read", "outsider-inheritable-write", "deny", "inherit-only"])
def test_unknown_or_untrusted_inheritance_route_never_authorizes_retry(inert, monkeypatch, unsafe):
    import pywintypes
    import win32security as security
    parent = inert / "inherited-runtime"
    parent.mkdir()
    source, destination = _pair(parent)
    original = security.GetFileSecurity(str(inert), 5)
    acl = security.ACL()
    owner = original.GetSecurityDescriptorOwner()
    if unsafe.startswith("outsider"):
        prior = original.GetSecurityDescriptorDacl()
        for index in range(prior.GetAceCount()):
            header, mask, principal = prior.GetAce(index)
            acl.AddAccessAllowedAceEx(2, header[1], mask, principal)
        acl.AddAccessAllowedAceEx(2, 0 if unsafe == "outsider-read" else 3,
                                 0x120089 if unsafe == "outsider-read" else 0x001F01FF,
                                 security.ConvertStringSidToSid("S-1-1-0"))
    elif unsafe == "deny":
        acl.AddAccessDeniedAce(2, 0x001F01FF, owner)
    else:
        acl.AddAccessAllowedAceEx(2, 8, 0x001F01FF, owner)
    calls, sleeps = [], []

    def fail(*_args):
        calls.append(True)
        raise _sharing_error(32)

    monkeypatch.setattr(secure_store.os, "replace", fail)
    monkeypatch.setattr(secure_store.time, "sleep", sleeps.append)
    try:
        security.SetNamedSecurityInfo(str(inert), security.SE_FILE_OBJECT,
                                     security.DACL_SECURITY_INFORMATION
                                     | security.PROTECTED_DACL_SECURITY_INFORMATION,
                                     None, None, acl, None)
        with pytest.raises((PermissionError, pywintypes.error)):
            secure_store._credential_parent_security_state(parent)
        with pytest.raises((PermissionError, pywintypes.error)):
            secure_store._credential_security_state(inert, directory=True, allow_inherited_directory=True)
        with pytest.raises((PermissionError, pywintypes.error)):
            with secure_store.secret_transaction(inert):
                secure_store._replace_credential_file(source, destination, inert)
        assert len(calls) <= 1 and not sleeps
    finally:
        security.SetNamedSecurityInfo(str(inert), security.SE_FILE_OBJECT,
                                     security.DACL_SECURITY_INFORMATION
                                     | security.PROTECTED_DACL_SECURITY_INFORMATION,
                                     None, None, original.GetSecurityDescriptorDacl(), None)


def test_unproven_inheritance_route_has_exact_directory_bound(monkeypatch, tmp_path):
    calls = []

    def unprotected(path, **_kwargs):
        calls.append(path)
        return ((0, 1, 1, 1, 1), b"inert-private-unprotected-descriptor", 0)

    monkeypatch.setattr(secure_store, "_credential_security_state", unprotected)
    parent = tmp_path.joinpath(*["nested"] * 40)
    with pytest.raises(PermissionError, match="unavailable or too deep"):
        secure_store._credential_parent_security_state(parent)
    assert len(calls) == 32


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows read-only denial")
def test_actual_readonly_native_access_denial_never_retries(inert, monkeypatch):
    import win32file
    source, destination = _pair(inert)
    win32file.SetFileAttributes(str(destination), 1)
    calls, sleeps = [], []
    try:
        with pytest.raises(PermissionError) as native:
            os.replace(source, destination)
        assert native.value.winerror == 5
        monkeypatch.setattr(secure_store.os, "replace", lambda *_args: calls.append(True))
        monkeypatch.setattr(secure_store.time, "sleep", sleeps.append)
        with secure_store.secret_transaction(inert), pytest.raises(PermissionError, match="writable"):
            secure_store._replace_credential_file(source, destination, inert)
        assert not calls and not sleeps
        assert destination.read_bytes() == b"original protected bytes"
    finally:
        win32file.SetFileAttributes(str(destination), 0x80)


@pytest.mark.skipif(os.name != "nt", reason="Native private retry proof")
def test_missing_native_security_proof_allows_no_retry(inert, monkeypatch):
    source, destination = _pair(inert)
    calls, sleeps = [], []

    def unavailable(*_args, **_kwargs):
        raise ImportError("inert native provider unavailable")

    def fail(*_args):
        calls.append(True)
        raise _sharing_error(32)

    monkeypatch.setattr(secure_store, "_credential_security_state", unavailable)
    monkeypatch.setattr(secure_store.os, "replace", fail)
    monkeypatch.setattr(secure_store.time, "sleep", sleeps.append)
    with secure_store.secret_transaction(inert), pytest.raises(PermissionError):
        secure_store._replace_credential_file(source, destination, inert)
    assert calls == [True] and not sleeps


@pytest.mark.skipif(os.name != "nt", reason="Windows-specific classified retry topology")
def test_changed_ancestor_identity_refuses_retry_even_with_original_leaf_and_parent(inert, monkeypatch):
    ancestor = inert / "original-ancestor"
    parent = ancestor / "publication"
    parent.mkdir(parents=True)
    _private_test_directory(parent)
    source, destination = _pair(parent)
    identities = (source.stat().st_ino, destination.stat().st_ino, parent.stat().st_ino)
    calls, sleeps = [], []

    def fail(*_args):
        calls.append(True)
        moved = inert / "retired-ancestor"
        ancestor.rename(moved)
        ancestor.mkdir()
        (moved / "publication").rename(parent)
        assert identities == (source.stat().st_ino, destination.stat().st_ino, parent.stat().st_ino)
        raise _sharing_error(32)

    monkeypatch.setattr(secure_store.os, "replace", fail)
    monkeypatch.setattr(secure_store.time, "sleep", sleeps.append)
    with secure_store.secret_transaction(inert), pytest.raises(PermissionError, match="custody changed"):
        secure_store._replace_credential_file(source, destination, inert)
    assert calls == [True] and not sleeps


@pytest.mark.parametrize("lost_at", ["first-failure", "sleep"])
@pytest.mark.skipif(os.name != "nt", reason="Windows-specific classified retry transaction")
def test_transaction_loss_refuses_next_replace(inert, monkeypatch, lost_at):
    source, destination = _pair(inert)
    calls, sleeps, lost = [], [], [False]
    original_assert = secure_store._assert_transaction

    def assert_transaction(root):
        original_assert(root)
        if lost[0]:
            raise RuntimeError("inert transaction custody lost")

    def fail(*_args):
        calls.append(True)
        if lost_at == "first-failure":
            lost[0] = True
        raise _sharing_error(32)

    def sleep(seconds):
        sleeps.append(seconds)
        lost[0] = True

    monkeypatch.setattr(secure_store, "_assert_transaction", assert_transaction)
    monkeypatch.setattr(secure_store.os, "replace", fail)
    monkeypatch.setattr(secure_store.time, "sleep", sleep)
    with pytest.raises(RuntimeError, match="custody lost"):
        with secure_store.secret_transaction(inert):
            secure_store._replace_credential_file(source, destination, inert)
    assert calls == [True]
    assert sleeps == ([] if lost_at == "first-failure" else [0.02])


def test_failure_diagnostics_omit_unknown_codes_and_exception_text(inert, monkeypatch):
    module = AdversaryCombat(inert, rollback_anchor={})
    details = []
    monkeypatch.setattr(module, "emit", lambda message, severity, **data: details.append(data))
    failure = PermissionError("inert-secret-and-path-must-not-be-exported")
    failure.winerror, failure.errno = 123456, True
    failure.angerona_write_boundary = "inert-secret-and-path-must-not-be-exported"
    module._trip_mutation_circuit({}, "fixed boundary failure", cause=failure)
    assert details[-1]["recovery_cause_types"] == ["PermissionError"]
    assert "recovery_cause_codes" not in details[-1]
    assert "inert-secret-and-path" not in json.dumps(details)
