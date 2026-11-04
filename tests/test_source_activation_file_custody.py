"""Real private-file custody and explicitly inert close-fault boundaries.

Positive cases use actual temporary files/native rename; adapters delegate real
I/O unless a case explicitly models a failed/ambiguous syscall acknowledgement.
No test grants source activation, runtime retirement, or update authority.
"""
from __future__ import annotations

import errno
import os
import sys
from types import SimpleNamespace

import pytest

from angerona.core import source_activation_file as files


_REAL_OS = os


class _View:
    def __init__(self, original, **overrides):
        self.original = original
        self.overrides = overrides

    def __getattr__(self, name):
        if name in self.overrides:
            return self.overrides[name]
        return getattr(self.original, name)


@pytest.fixture(autouse=True)
def isolated_test_close_holds(monkeypatch):
    # Each unit gets its own list. Fault cases prove sticky admission within the
    # unit; no real ambiguous handle is created or discarded by test teardown.
    holds = []
    monkeypatch.setattr(files, "_CLOSE_HOLDS", holds)
    return holds


def _os_view(monkeypatch, **overrides):
    monkeypatch.setattr(files, "os", _View(_REAL_OS, **overrides))


def _seed(path, raw=b"original private bytes"):
    files.write_new(path, raw)
    return path


def _object_id(path):
    info = path.stat()
    return info.st_dev, info.st_ino


@pytest.mark.parametrize("raw", [b"", b"private\x00bytes\xff" * 19])
def test_exclusive_write_and_retained_read_round_trip(tmp_path, raw):
    path = tmp_path / "staged.bin"
    files.write_new(path, raw)
    with files.RetainedFile(path) as held:
        assert held.read(len(raw)) == raw
        assert (held.initial["device"], held.initial["inode"]) == tuple(
            str(value) for value in _object_id(path)
        )
        held.check()
    assert files.read_exact(path, len(raw)) == raw


def test_exclusive_write_never_replaces_existing_destination(tmp_path):
    target = _seed(tmp_path / "existing")
    original_id = _object_id(target)
    with pytest.raises(FileExistsError):
        files.write_new(target, b"replacement")
    assert _object_id(target) == original_id
    assert target.read_bytes() == b"original private bytes"


def test_actual_publication_and_reverse_rename_keep_both_file_objects(tmp_path):
    target = _seed(tmp_path / "canonical", b"old revision")
    stage = _seed(tmp_path / "stage", b"new revision")
    backup = tmp_path / "backup"
    old_id, new_id = _object_id(target), _object_id(stage)
    with files.RetainedFile(target, mutation=True) as old:
        with files.RetainedFile(stage, mutation=True) as new:
            old_stamp, new_stamp = dict(old.initial), dict(new.initial)
            old.rename(backup)
            new.rename(target)
            assert _object_id(backup) == old_id
            assert _object_id(target) == new_id
            assert files.identity(backup.lstat()) == old_stamp
            assert files.identity(target.lstat()) == new_stamp
            assert old.read(64) == b"old revision"
            assert new.read(64) == b"new revision"
            new.rename(stage)
            old.rename(target)
            assert _object_id(target) == old_id
            assert _object_id(stage) == new_id
            assert files.identity(target.lstat()) == old_stamp
            assert files.identity(stage.lstat()) == new_stamp
            assert old.read(64) == b"old revision"
            assert new.read(64) == b"new revision"
    assert not backup.exists()
    assert target.read_bytes() == b"old revision"
    assert stage.read_bytes() == b"new revision"


@pytest.mark.skipif(os.name != "nt", reason="Windows native rename metadata")
@pytest.mark.parametrize("change_modified", [False, True])
def test_native_rename_repairs_only_a_changed_creation_time(tmp_path, monkeypatch, change_modified):
    import ctypes
    import msvcrt
    from ctypes import wintypes

    source = _seed(tmp_path / "stage")
    target = tmp_path / "canonical"
    native_rename = files.RetainedFile._information
    setter = ctypes.WinDLL("kernel32", use_last_error=True).SetFileTime
    filetime = ctypes.POINTER(wintypes.FILETIME)
    setter.argtypes = (wintypes.HANDLE, filetime, filetime, filetime)
    setter.restype = wintypes.BOOL

    def rename_then_change_times(held, kind, request):
        native_rename(held, kind, request)
        # Simulate the timestamp transition on the real retained descriptor even
        # when the test volume does not support Windows filename tunneling.
        altered = ctypes.byref(wintypes.FILETIME(0, 0x01D00000))
        assert setter(msvcrt.get_osfhandle(held.fd), altered, None,
                      altered if change_modified else None)

    monkeypatch.setattr(files.RetainedFile, "_information", rename_then_change_times)
    with files.RetainedFile(source, mutation=True) as held:
        original = dict(held.initial)
        if change_modified:
            with pytest.raises(files.ActivationFileError, match="identity changed"):
                held.rename(target)
            observed = files.identity(target.lstat())
            assert observed["birth_ns"] != original["birth_ns"]
            assert observed["modified_ns"] != original["modified_ns"]
            with pytest.raises(files.ActivationFileError, match="identity changed"):
                held.check()
        else:
            held.rename(target)
            assert files.identity(target.lstat()) == original
            assert held.read(64) == b"original private bytes"
        assert held.path == target


def test_rename_refuses_preexisting_destination_without_losing_custody(tmp_path):
    source = _seed(tmp_path / "source", b"source")
    target = _seed(tmp_path / "destination", b"unrelated")
    source_id, target_id = _object_id(source), _object_id(target)
    with files.RetainedFile(source, mutation=True) as held:
        with pytest.raises(files.ActivationFileError, match="destination"):
            held.rename(target)
        held.check()
        assert held.path == source
        assert held.read(64) == b"source"
    assert _object_id(source) == source_id
    assert _object_id(target) == target_id
    assert target.read_bytes() == b"unrelated"


def test_native_no_replace_refuses_destination_raced_after_name_check(
    tmp_path, monkeypatch
):
    source = _seed(tmp_path / "source", b"source")
    target = tmp_path / "raced"
    source_id = _object_id(source)
    raced = []

    def lexists(path):
        if _REAL_OS.path.normcase(str(path)) == _REAL_OS.path.normcase(str(target)):
            assert not raced
            target.write_bytes(b"raced unrelated bytes")
            raced.append(_object_id(target))
            return False
        return _REAL_OS.path.lexists(path)

    with files.RetainedFile(source, mutation=True) as held:
        _os_view(monkeypatch, path=_View(_REAL_OS.path, lexists=lexists))
        with pytest.raises(OSError):
            held.rename(target)
        held.check()
        assert held.path == source
        assert held.read(64) == b"source"
    assert raced == [_object_id(target)]
    assert _object_id(source) == source_id
    assert target.read_bytes() == b"raced unrelated bytes"


def test_actual_delete_affects_only_the_retained_object(tmp_path):
    target = _seed(tmp_path / "delete-me")
    other = _seed(tmp_path / "keep-me", b"keep")
    other_id = _object_id(other)
    with files.RetainedFile(target, mutation=True) as held:
        held.delete()
    assert not target.exists()
    assert _object_id(other) == other_id
    assert other.read_bytes() == b"keep"


def test_plain_path_rejects_traversal_even_when_it_resolves_inside(tmp_path):
    child = tmp_path / "child"
    child.mkdir()
    target = _seed(tmp_path / "file")
    with pytest.raises(files.ActivationFileError, match="traversal"):
        files.plain_path(child / ".." / target.name)


def test_real_hard_link_is_rejected_before_read_or_mutation(tmp_path):
    source = _seed(tmp_path / "source")
    alias = tmp_path / "hard-link"
    try:
        _REAL_OS.link(source, alias)
    except (NotImplementedError, OSError) as error:
        if isinstance(error, NotImplementedError) or getattr(error, "errno", None) in (
            errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP,
        ):
            pytest.skip("This temporary filesystem does not support hard links")
        raise
    assert source.stat().st_nlink == 2
    for path in (source, alias):
        with pytest.raises(files.ActivationFileError, match="single-link"):
            files.RetainedFile(path)
    assert source.read_bytes() == alias.read_bytes() == b"original private bytes"


@pytest.mark.parametrize("directory_alias", [False, True])
def test_real_symbolic_link_or_redirected_parent_is_rejected(
    tmp_path, directory_alias
):
    parent = tmp_path / "real-parent"
    parent.mkdir()
    source = _seed(parent / "source")
    alias = tmp_path / "symbolic-link"
    try:
        alias.symlink_to(parent if directory_alias else source,
                         target_is_directory=directory_alias)
    except (NotImplementedError, OSError) as error:
        if isinstance(error, NotImplementedError) or getattr(error, "errno", None) in (
            errno.EPERM, errno.EACCES, errno.ENOTSUP, errno.EOPNOTSUPP,
        ) or getattr(error, "winerror", None) == 1314:
            pytest.skip("Actual symlink creation is unavailable for this test token")
        raise
    redirected = alias / "source" if directory_alias else alias
    with pytest.raises(files.ActivationFileError, match="redirected"):
        files.RetainedFile(redirected)
    assert source.read_bytes() == b"original private bytes"


def test_actual_held_object_mutation_invalidates_snapshot(tmp_path):
    source = _seed(tmp_path / "mutable", b"before")
    original_id = _object_id(source)
    with files.RetainedFile(source, writable=True) as held:
        _REAL_OS.lseek(held.fd, 0, _REAL_OS.SEEK_END)
        assert _REAL_OS.write(held.fd, b"-changed") == len(b"-changed")
        _REAL_OS.fsync(held.fd)
        with pytest.raises(files.ActivationFileError, match="identity changed"):
            held.check()
        with pytest.raises(files.ActivationFileError):
            held.read(64)
    assert _object_id(source) == original_id
    assert source.read_bytes() == b"before-changed"


def test_name_replacement_is_prevented_or_rejected_as_changed_object(tmp_path):
    source = _seed(tmp_path / "source", b"original")
    replacement = _seed(tmp_path / "replacement", b"replacement")
    original_id, replacement_id = _object_id(source), _object_id(replacement)
    with files.RetainedFile(source) as held:
        try:
            _REAL_OS.replace(replacement, source)
        except PermissionError as error:
            # The Windows retained share contract can prevent the race itself.
            # This branch proves prevention and does not claim a replaced inode.
            if _REAL_OS.name != "nt" or getattr(error, "winerror", None) not in (5, 32):
                raise
            assert _object_id(source) == original_id
            assert _object_id(replacement) == replacement_id
            assert held.read(64) == b"original"
        else:
            assert _object_id(source) == replacement_id != original_id
            with pytest.raises(files.ActivationFileError, match="identity changed"):
                held.check()
            with pytest.raises(files.ActivationFileError):
                held.read(64)


def test_bound_rejection_occurs_before_any_payload_read(tmp_path, monkeypatch):
    source = _seed(tmp_path / "bounded", b"12345678")
    with files.RetainedFile(source) as held:
        def forbidden_read(*_args):
            raise AssertionError("Oversized file reached payload read")
        _os_view(monkeypatch, read=forbidden_read)
        with pytest.raises(files.ActivationFileError, match="byte bound"):
            held.read(7)
        held.check()


def test_actual_partial_reads_are_collected_to_exact_bytes(tmp_path, monkeypatch):
    payload = bytes(range(200))
    source = _seed(tmp_path / "short-reads", payload)
    calls = []

    def read(fd, count):
        calls.append(count)
        return _REAL_OS.read(fd, min(count, 7))

    _os_view(monkeypatch, read=read)
    assert files.read_exact(source, len(payload)) == payload
    assert len(calls) > 2
    assert all(0 < count <= 65536 for count in calls)


def test_early_eof_refuses_even_with_unchanged_real_identity(tmp_path, monkeypatch):
    source = _seed(tmp_path / "incomplete", b"real complete file")
    original_id = _object_id(source)
    reads = []

    def read(fd, count):
        reads.append(count)
        return _REAL_OS.read(fd, 2) if len(reads) == 1 else b""

    _os_view(monkeypatch, read=read)
    with pytest.raises(files.ActivationFileError, match="incomplete"):
        files.read_exact(source, 64)
    assert len(reads) == 2
    assert _object_id(source) == original_id
    assert source.read_bytes() == b"real complete file"


def test_partial_writes_fsync_and_close_precede_real_readback(tmp_path, monkeypatch):
    target = tmp_path / "partial-writes"
    events = []
    real_read_exact = files.read_exact

    def write(fd, raw):
        count = _REAL_OS.write(fd, raw[:3])
        events.append(("write", count))
        return count

    def fsync(fd):
        _REAL_OS.fsync(fd)
        events.append(("fsync", fd))

    def close(fd):
        _REAL_OS.close(fd)
        events.append(("close", fd))

    def read_exact(path, limit):
        assert events[-2][0] == "fsync" and events[-1][0] == "close"
        events.append(("readback", limit))
        return real_read_exact(path, limit)

    _os_view(monkeypatch, write=write, fsync=fsync, close=close)
    monkeypatch.setattr(files, "read_exact", read_exact)
    files.write_new(target, b"elevenbytes")
    assert sum(value for kind, value in events if kind == "write") == 11
    assert [kind for kind, _value in events].count("fsync") == 1
    assert [kind for kind, _value in events].count("readback") == 1
    assert target.read_bytes() == b"elevenbytes"


def test_zero_write_is_not_retried_or_claimed_published(tmp_path, monkeypatch):
    target = tmp_path / "zero-write"
    calls = []

    def write(fd, raw):
        calls.append((fd, bytes(raw)))
        return 0

    def forbidden_fsync(_fd):
        raise AssertionError("Incomplete write reached fsync")

    def forbidden_readback(*_args):
        raise AssertionError("Incomplete write reached readback")

    _os_view(monkeypatch, write=write, fsync=forbidden_fsync)
    monkeypatch.setattr(files, "read_exact", forbidden_readback)
    with pytest.raises(files.ActivationFileError, match="incomplete"):
        files.write_new(target, b"not-written")
    assert len(calls) == 1
    assert target.read_bytes() == b""


def test_fsync_failure_preserves_original_error_and_prevents_readback(
    tmp_path, monkeypatch
):
    target = tmp_path / "fsync-refusal"
    fault = OSError("inert fsync refusal")
    closes = []

    def fsync(_fd):
        raise fault

    def close(fd):
        _REAL_OS.close(fd)
        closes.append(fd)

    def forbidden_readback(*_args):
        raise AssertionError("Unproven durability reached readback")

    _os_view(monkeypatch, fsync=fsync, close=close)
    monkeypatch.setattr(files, "read_exact", forbidden_readback)
    with pytest.raises(OSError) as result:
        files.write_new(target, b"written-but-sync-unproven")
    assert result.value is fault
    assert len(closes) == 1
    assert target.read_bytes() == b"written-but-sync-unproven"


def test_append_refreshes_identity_only_after_real_fsync(tmp_path, monkeypatch):
    source = _seed(tmp_path / "journal", b"intent\n")
    original_id = _object_id(source)
    with files.RetainedFile(source, writable=True) as held:
        before = dict(held.initial)
        events = []

        def fsync(fd):
            assert held.initial == before
            _REAL_OS.fsync(fd)
            events.append("durable")

        _os_view(monkeypatch, fsync=fsync)
        held.append(b"commit\n", 64)
        assert events == ["durable"]
        assert held.initial["bytes"] == len(b"intent\ncommit\n")
        assert held.read(64) == b"intent\ncommit\n"
        assert _object_id(source) == original_id
        held.check()


def test_append_bound_precedes_payload_write(tmp_path, monkeypatch):
    source = _seed(tmp_path / "journal", b"intent")
    with files.RetainedFile(source, writable=True) as held:
        before = dict(held.initial)

        def forbidden_write(*_args):
            raise AssertionError("Oversized append reached write")

        _os_view(monkeypatch, write=forbidden_write)
        with pytest.raises(files.ActivationFileError, match="journal exceeds"):
            held.append(b"too-much", 7)
        assert held.initial == before
        assert held.read(64) == b"intent"


def test_failed_append_fsync_cannot_refresh_snapshot(tmp_path, monkeypatch):
    source = _seed(tmp_path / "journal", b"intent")
    with files.RetainedFile(source, writable=True) as held:
        before = dict(held.initial)
        fault = OSError("inert append fsync refusal")

        def fsync(_fd):
            raise fault

        _os_view(monkeypatch, fsync=fsync)
        with pytest.raises(OSError) as result:
            held.append(b"-uncommitted", 64)
        assert result.value is fault
        assert held.initial == before
        with pytest.raises(files.ActivationFileError, match="identity changed"):
            held.check()
    assert source.read_bytes() == b"intent-uncommitted"


def test_retained_close_lost_ack_is_sticky_and_never_retries_numeric_fd(
    tmp_path, monkeypatch, isolated_test_close_holds
):
    source = _seed(tmp_path / "retained")
    held = files.RetainedFile(source)
    original_fd = held.fd
    calls = []

    def close(fd):
        calls.append(fd)
        _REAL_OS.close(fd)
        raise OSError("inert lost close acknowledgement after actual close")

    _os_view(monkeypatch, close=close)
    with pytest.raises(files.ActivationFileCloseHeld):
        held.close()
    assert held.fd == -1 and held.close_held
    assert isolated_test_close_holds == [(held, original_fd)]
    with pytest.raises(files.ActivationFileError, match="unavailable"):
        held.check()
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"still-open")
    other_fd = _REAL_OS.open(unrelated, _REAL_OS.O_RDONLY)
    try:
        with pytest.raises(files.ActivationFileCloseHeld):
            held.close()
        assert calls == [original_fd]
        assert _REAL_OS.read(other_fd, 64) == b"still-open"
    finally:
        _REAL_OS.close(other_fd)
    with pytest.raises(files.ActivationFileCloseHeld, match="Prior"):
        files.RetainedFile(source)


def test_exclusive_close_lost_ack_blocks_readback_and_all_new_admission(
    tmp_path, monkeypatch, isolated_test_close_holds
):
    target = tmp_path / "exclusive"
    closes = []

    def close(fd):
        closes.append(fd)
        _REAL_OS.close(fd)
        raise OSError("inert lost exclusive close acknowledgement")

    def forbidden_readback(*_args):
        raise AssertionError("Unproven close reached publication verification")

    _os_view(monkeypatch, close=close)
    monkeypatch.setattr(files, "read_exact", forbidden_readback)
    with pytest.raises(files.ActivationFileCloseHeld):
        files.write_new(target, b"actual private bytes")
    assert len(closes) == 1
    assert isolated_test_close_holds == [("exclusive-write", target, closes[0])]
    assert target.read_bytes() == b"actual private bytes"
    next_path = tmp_path / "must-not-open"
    with pytest.raises(files.ActivationFileCloseHeld, match="Prior"):
        files.write_new(next_path, b"denied")
    with pytest.raises(files.ActivationFileCloseHeld, match="Prior"):
        files.RetainedFile(target)
    assert closes == [closes[0]]
    assert not next_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows CRT adoption boundary")
@pytest.mark.parametrize("case", ["not-adopted", "close-unproven", "ambiguous"])
def test_inert_native_adoption_fault_retains_uncertain_custody_without_retry(
    tmp_path, monkeypatch, isolated_test_close_holds, case
):
    # Inert lowest adapter only: no arbitrary real numeric handle is opened or
    # closed. Genuine file/rename/read/append positives are exercised above.
    import ctypes
    import msvcrt

    source = _seed(tmp_path / "native-adoption")
    calls = []
    raw_handle = 0x6F10

    class NativeFunction:
        def __init__(self, function):
            self.function = function

        def __call__(self, *args):
            return self.function(*args)

    def create(*_args):
        calls.append("create")
        return raw_handle

    def close(raw):
        assert raw == raw_handle
        calls.append("native-close")
        return case != "close-unproven"

    api = SimpleNamespace(CreateFileW=NativeFunction(create),
                          CloseHandle=NativeFunction(close))
    error = KeyboardInterrupt("inert ambiguous adoption") if case == "ambiguous" else OSError("inert nonadopting CRT refusal")

    def adopt(raw, _flags):
        assert raw == raw_handle
        calls.append("adopt")
        raise error

    monkeypatch.setattr(files, "ctypes", _View(ctypes, WinDLL=lambda *_a, **_k: api))
    monkeypatch.setitem(sys.modules, "msvcrt", _View(msvcrt, open_osfhandle=adopt))
    with pytest.raises(type(error)) as result:
        files.RetainedFile(source)
    assert result.value is error
    assert calls == (["create", "adopt"] if case == "ambiguous" else
                     ["create", "adopt", "native-close"])
    if case == "not-adopted":
        assert isolated_test_close_holds == []
    else:
        assert len(isolated_test_close_holds) == 1
        owner, retained_api, retained_raw = isolated_test_close_holds[0]
        assert owner.close_held and retained_api is api and retained_raw == raw_handle
        with pytest.raises(files.ActivationFileCloseHeld, match="Prior"):
            files.RetainedFile(source)
        assert calls == (["create", "adopt"] if case == "ambiguous" else
                         ["create", "adopt", "native-close"])


def test_actual_activation_lock_excludes_second_owner_and_reacquires_after_close(tmp_path):
    path = tmp_path / "activation.lock"
    first = files.ActivationLock(path)
    original_id = _object_id(path)
    try:
        # Windows may refuse the incompatible writable open before CRT lock;
        # POSIX reaches flock. Both are genuine native exclusion, not a stub.
        with pytest.raises((OSError, files.ActivationFileError)):
            files.ActivationLock(path)
        assert first.retained.read(1) == b"\0"
        first.retained.check()
        assert _object_id(path) == original_id
    finally:
        first.close()
    with files.ActivationLock(path) as later:
        assert later.retained.read(1) == b"\0"
        assert _object_id(path) == original_id


@pytest.mark.parametrize("raw", [b"X", b"", b"\0\0"])
def test_actual_activation_lock_rejects_wrong_bytes_without_replacing_file(tmp_path, raw):
    path = tmp_path / "activation.lock"
    path.write_bytes(raw)
    original_id = _object_id(path)
    with pytest.raises(files.ActivationFileError, match="lock is invalid"):
        files.ActivationLock(path)
    assert path.read_bytes() == raw
    assert _object_id(path) == original_id


_OW_PROFILE = ((0, 3, 2032127, "S-1-3-4"),
               (0, 3, 2032127, "S-1-5-18"),
               (0, 3, 2032127, "S-1-5-32-544"))


@pytest.mark.parametrize("order", [(0, 1, 2), (0, 2, 1), (1, 0, 2),
                                   (1, 2, 0), (2, 0, 1), (2, 1, 0)])
def test_owner_rights_classifier_accepts_only_exact_profile_permutations(order):
    profile = tuple(_OW_PROFILE[index] for index in order)
    assert files._matches_owner_rights_acl(owner_matches_current=True,
                                          protected=True, entries=profile) is True


@pytest.mark.parametrize("case", ["owner", "owner-int", "unprotected", "extra-ace",
    "missing-ace", "duplicate-sid", "foreign-sid", "deny", "inherited", "mask-subset",
    "bool-type", "list", "extra-field"])
def test_owner_rights_classifier_refuses_each_profile_authority_gap(case):
    entries = list(_OW_PROFILE)
    owner, protected = True, True
    if case == "owner":
        owner = False
    elif case == "owner-int":
        owner = 1
    elif case == "unprotected":
        protected = False
    elif case == "extra-ace":
        entries.append((0, 3, 2032127, "S-1-1-0"))
    elif case == "missing-ace":
        entries.pop()
    elif case == "duplicate-sid":
        entries[0] = entries[1]
    elif case == "foreign-sid":
        entries[0] = (0, 3, 2032127, "S-1-1-0")
    elif case == "deny":
        entries[0] = (1, 3, 2032127, "S-1-3-4")
    elif case == "inherited":
        entries[0] = (0, 19, 2032127, "S-1-3-4")
    elif case == "mask-subset":
        entries[0] = (0, 3, 1, "S-1-3-4")
    elif case == "bool-type":
        entries[0] = (False, 3, 2032127, "S-1-3-4")
    elif case == "extra-field":
        entries[0] = (0, 3, 2032127, "S-1-3-4", "unexpected")
    profile = entries if case == "list" else tuple(entries)
    assert files._matches_owner_rights_acl(owner_matches_current=owner,
                                          protected=protected, entries=profile) is False


@pytest.mark.skipif(os.name != "nt", reason="Native Windows OWNER RIGHTS ACL")
def test_explicit_native_owner_rights_directory_passes_exact_read_only_query(tmp_path):
    import pywintypes
    import win32api
    import win32file
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    try:
        user, _attributes = win32security.GetTokenInformation(token, win32security.TokenUser)
        sid = win32security.ConvertSidToStringSid(user)
    finally:
        token.Close()

    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"O:{sid}D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1,
    )
    directory = tmp_path / "native-owner-rights"
    win32file.CreateDirectory(str(directory), attributes)

    flags = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION

    def read_acl():
        descriptor = win32security.GetFileSecurity(str(directory), flags)
        return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, 1, flags)

    original_id, original_acl = _object_id(directory), read_acl()
    assert files.private_owner_rights_directory(directory) is True
    assert (_object_id(directory), read_acl()) == (original_id, original_acl)
    assert not files._CLOSE_HOLDS


@pytest.mark.skipif(os.name != "nt" or sys.implementation.name != "cpython",
                    reason="Actual Windows CPython 0700 ACL profile")
def test_windows_mkdir_mode0700_matches_cpython_security_support(tmp_path):
    private = tmp_path / "real-cpython-0700"
    private.mkdir(mode=0o700)
    original_id = _object_id(private)
    # CVE-2024-4030 was backported at these patch levels. Older Windows
    # builds ignore 0700 and the resulting inherited ACL must be refused.
    minimum_patch = {(3, 10): 15, (3, 11): 10, (3, 12): 4}.get(sys.version_info[:2], 0)
    assert files.private_owner_rights_directory(private) is (sys.version_info[2] >= minimum_patch)
    assert _object_id(private) == original_id
    assert not files._CLOSE_HOLDS
