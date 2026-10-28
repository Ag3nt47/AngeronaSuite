"""Cleanup uses disposable fixtures only; no operator recovery copy is opened."""
from __future__ import annotations

import os
import stat
import threading
from types import SimpleNamespace

import pytest

from angerona.core import shadow_cache_cleanup as cleanup


@pytest.fixture
def cache(tmp_path):
    root = tmp_path / "shadow_cache"
    root.mkdir(mode=0o700)
    return root


def key(root, name="a" * 64):
    directory = root / name
    directory.mkdir(mode=0o700)
    return directory


def test_only_recognized_recovery_artifacts_are_removed(cache):
    directory = key(cache)
    items = {
        "1234567890123456789.bak": b"recovery",
        ".1234567890123456789.0123456789abcdef0123456789abcdef.tmp": b"partial",
        "_source.txt": b"D:\\Documents\\source.txt",
    }
    for name, payload in items.items():
        (directory / name).write_bytes(payload)
    result = cleanup.cleanup_cache(cache)
    assert result["complete"]
    assert result["removed_files"] == 3
    assert result["removed_bytes"] == sum(map(len, items.values()))
    assert result["removed_directories"] == 1 and not directory.exists()
    again = cleanup.cleanup_cache(cache)
    assert again["complete"] and again["removed_files"] == 0


def test_unknown_key_content_preserves_entire_key_and_source_metadata(cache):
    directory = key(cache)
    for name in ("1.bak", "_source.txt", "authenticated-receipt.json"):
        (directory / name).write_bytes(b"preserved")
    result = cleanup.cleanup_cache(cache)
    assert not result["complete"] and result["removed_files"] == 0
    assert all(path.read_bytes() == b"preserved" for path in directory.iterdir())


@pytest.mark.parametrize("name", ["report.json", "alerts", "A" * 64, "a" * 63, "a" * 65])
def test_unknown_root_entries_are_preserved_while_valid_key_is_cleaned(cache, name):
    unknown = cache / name
    unknown.write_bytes(b"evidence")
    valid = key(cache, "b" * 64) / "1.bak"
    valid.write_bytes(b"copy")
    result = cleanup.cleanup_cache(cache)
    assert not result["complete"] and result["removed_files"] == 1
    assert unknown.read_bytes() == b"evidence" and not valid.exists()


@pytest.mark.parametrize("name", ["-1.bak", "file.bak", "1.bak.keep", ".1.bad.tmp", "1.bak.extra"])
def test_unrecognized_artifact_names_are_never_deleted(cache, name):
    directory = key(cache)
    path = directory / name
    path.write_bytes(b"unknown")
    assert not cleanup.cleanup_cache(cache)["complete"]
    assert path.read_bytes() == b"unknown"


def test_pinned_version_preserves_copies_and_metadata(cache):
    directory = key(cache)
    for name in ("1.bak", "1.bak.keep", "_source.txt"):
        (directory / name).write_bytes(b"preserved")
    assert cleanup.cleanup_cache(cache)["removed_files"] == 0
    assert len(list(directory.iterdir())) == 3


def test_hardlinks_are_preserved(cache, tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"external original")
    linked = key(cache) / "1.bak"
    try:
        os.link(original, linked)
    except OSError:
        pytest.skip("hardlinks unavailable")
    result = cleanup.cleanup_cache(cache)
    assert not result["complete"] and result["removed_files"] == 0
    assert linked.read_bytes() == original.read_bytes() == b"external original"


@pytest.mark.parametrize("location", ["ancestor", "key", "file"])
def test_symlinks_never_escape_cache(cache, tmp_path, location):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "1.bak"
    target.write_bytes(b"outside")
    try:
        if location == "ancestor":
            alias = tmp_path / "alias"
            alias.symlink_to(tmp_path, target_is_directory=True)
            requested = alias / "shadow_cache"
        elif location == "key":
            (cache / ("a" * 64)).symlink_to(outside, target_is_directory=True)
            requested = cache
        else:
            (key(cache) / "1.bak").symlink_to(target)
            requested = cache
    except OSError:
        pytest.skip("symlink creation unavailable")
    result = cleanup.cleanup_cache(requested)
    assert not result["complete"] and result["removed_files"] == 0
    assert target.read_bytes() == b"outside"


def test_cancellation_before_and_between_deletions_preserves_remaining(cache, monkeypatch):
    directory = key(cache)
    for name in ("1.bak", "2.bak", "_source.txt"):
        (directory / name).write_bytes(b"copy")
    stopped = threading.Event()
    stopped.set()
    result = cleanup.cleanup_cache(cache, stopped=stopped)
    assert not result["complete"] and result["removed_files"] == 0
    assert "cancelled" in result["reason"]
    stopped.clear()
    original = cleanup._remove

    def cancel_after_first(*args):
        original(*args)
        stopped.set()

    monkeypatch.setattr(cleanup, "_remove", cancel_after_first)
    result = cleanup.cleanup_cache(cache, stopped=stopped)
    assert not result["complete"] and result["removed_files"] == 1
    assert (directory / "_source.txt").exists()
    assert len(list(directory.iterdir())) == 2


def test_entry_bound_reports_remaining_and_later_invocation_completes(cache, monkeypatch):
    path = key(cache) / "1.bak"
    path.write_bytes(b"copy")
    monkeypatch.setattr(cleanup, "MAX_ENTRIES", 1)
    result = cleanup.cleanup_cache(cache)
    assert not result["complete"] and result["removed_files"] == 0
    assert "entry bound" in result["reason"] and path.exists()
    monkeypatch.setattr(cleanup, "MAX_ENTRIES", 100)
    assert cleanup.cleanup_cache(cache)["complete"] and not path.exists()


def test_cooperative_time_bound_preserves_all_files(cache, monkeypatch):
    path = key(cache) / "1.bak"
    path.write_bytes(b"copy")
    monkeypatch.setattr(cleanup, "MAX_SECONDS", 0)
    result = cleanup.cleanup_cache(cache)
    assert not result["complete"] and "time bound" in result["reason"]
    assert path.read_bytes() == b"copy"


def test_changed_file_identity_after_inventory_is_preserved(cache, monkeypatch):
    directory = key(cache)
    path = directory / "1.bak"
    path.write_bytes(b"old")
    metadata = directory / "_source.txt"
    metadata.write_bytes(b"source")
    original = cleanup._remove

    def change_before_open(parent, name, identity, *args):
        if name == "1.bak":
            path.write_bytes(b"new longer replacement")
        return original(parent, name, identity, *args)

    monkeypatch.setattr(cleanup, "_remove", change_before_open)
    result = cleanup.cleanup_cache(cache)
    assert not result["complete"] and result["removed_files"] == 0
    assert path.read_bytes() == b"new longer replacement" and metadata.exists()


def test_changed_key_identity_after_inventory_is_refused(cache, monkeypatch):
    directory = key(cache)
    path = directory / "1.bak"
    path.write_bytes(b"copy")
    original = cleanup._Directory.stat
    calls = []

    def changed(parent, name):
        info = original(parent, name)
        if parent.path == cache and name == directory.name:
            calls.append(True)
            if len(calls) > 1:
                return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev,
                                       st_ino=info.st_ino + 1, st_uid=getattr(info, "st_uid", 0),
                                       st_file_attributes=getattr(info, "st_file_attributes", 0))
        return info

    monkeypatch.setattr(cleanup._Directory, "stat", changed)
    result = cleanup.cleanup_cache(cache)
    assert not result["complete"] and result["removed_files"] == 0
    assert path.read_bytes() == b"copy"


def test_existing_empty_key_directories_are_removed(cache):
    directories = [key(cache, symbol * 64) for symbol in "abc"]
    result = cleanup.cleanup_cache(cache)
    assert result["complete"] and result["removed_directories"] == 3
    assert result["removed_files"] == result["removed_bytes"] == 0
    assert not any(path.exists() for path in directories)


def test_closed_parent_guard_cannot_be_reused(cache):
    directory = key(cache)
    with cleanup._held_directory(cache) as parent:
        assert parent._guard_active
    assert not parent._guard_active
    with pytest.raises(ValueError, match="matching active"):
        with cleanup._held_directory(directory, parent):
            pytest.fail("closed parent guard was reused")
    assert directory.exists()


def test_mismatched_active_parent_guard_is_refused(cache, tmp_path):
    directory = key(cache)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    with cleanup._held_directory(other) as parent:
        with pytest.raises(ValueError, match="matching active"):
            with cleanup._held_directory(directory, parent):
                pytest.fail("mismatched parent guard was reused")
    assert directory.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows ancestor-handle reuse")
def test_windows_children_reuse_only_the_live_matching_ancestor_guard(cache, monkeypatch):
    from angerona.core import source_sandbox

    for symbol in "abc":
        key(cache, symbol * 64)
    original = source_sandbox._hold_plain_directories
    guarded = []

    def record(*paths):
        guarded.extend(paths)
        return original(*paths)

    monkeypatch.setattr(source_sandbox, "_hold_plain_directories", record)
    result = cleanup.cleanup_cache(cache)
    assert result["complete"] and result["removed_directories"] == 3
    # One parent-only absence check and one root lifetime retain all ancestors.
    # Child keys retain their own native final handles without another rewalk.
    assert guarded == [cache.parent.parent, cache.parent]


def test_new_child_before_directory_removal_is_preserved(cache, monkeypatch):
    directory = key(cache)
    original = cleanup._CacheDirectory.remove_empty

    def add_child(held, *args):
        (directory / "evidence.json").write_bytes(b"preserved")
        return original(held, *args)

    monkeypatch.setattr(cleanup._CacheDirectory, "remove_empty", add_child)
    result = cleanup.cleanup_cache(cache)
    assert not result["complete"] and result["removed_directories"] == 0
    assert (directory / "evidence.json").read_bytes() == b"preserved"


def test_late_unknown_entry_preserves_source_mapping(cache, monkeypatch):
    directory = key(cache)
    (directory / "1.bak").write_bytes(b"copy")
    (directory / "_source.txt").write_bytes(b"source")
    original = cleanup._remove

    def add_after_copy_removal(*args):
        original(*args)
        (directory / "evidence.json").write_bytes(b"evidence")

    monkeypatch.setattr(cleanup, "_remove", add_after_copy_removal)
    result = cleanup.cleanup_cache(cache)
    assert not result["complete"] and result["removed_files"] == 1
    assert (directory / "_source.txt").exists()
    assert (directory / "evidence.json").read_bytes() == b"evidence"


def test_reparse_file_metadata_is_refused_even_if_not_a_symlink(cache, monkeypatch):
    path = key(cache) / "1.bak"
    path.write_bytes(b"copy")
    original = cleanup._Directory.stat

    def reparse(directory, name):
        info = original(directory, name)
        if name == "1.bak":
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    monkeypatch.setattr(cleanup._Directory, "stat", reparse)
    result = cleanup.cleanup_cache(cache)
    assert not result["complete"] and path.read_bytes() == b"copy"


@pytest.mark.skipif(os.name != "nt", reason="Windows file-handle sharing custody")
def test_windows_deletion_holds_exact_file_against_other_writers_and_renames(cache, monkeypatch):
    path = key(cache) / "1.bak"
    path.write_bytes(b"copy")
    original = cleanup._CacheFile.delete
    witnessed = []

    def verify_held(file, expected):
        with pytest.raises(OSError):
            with path.open("wb"):
                pass
        with pytest.raises(OSError):
            path.rename(path.with_name("replacement"))
        witnessed.append(True)
        return original(file, expected)

    monkeypatch.setattr(cleanup._CacheFile, "delete", verify_held)
    result = cleanup.cleanup_cache(cache)
    assert result["complete"] and witnessed == [True] and not path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory-handle sharing custody")
def test_windows_empty_directory_removal_pins_the_exact_key(cache, monkeypatch):
    directory = key(cache)
    original = cleanup._CacheDirectory.remove_empty
    witnessed = []

    def verify_held(held, *args):
        with pytest.raises(OSError):
            directory.rename(cache / ("b" * 64))
        witnessed.append(True)
        return original(held, *args)

    monkeypatch.setattr(cleanup._CacheDirectory, "remove_empty", verify_held)
    result = cleanup.cleanup_cache(cache)
    assert result["complete"] and witnessed == [True] and not directory.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows writable directory-handle exclusion")
def test_windows_guards_deny_writable_root_and_key_directory_handles(cache, monkeypatch):
    import ctypes
    from ctypes import wintypes

    directory = key(cache)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    opener = kernel.CreateFileW
    opener.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    opener.restype = wintypes.HANDLE
    closer = kernel.CloseHandle
    closer.argtypes = (wintypes.HANDLE,)
    closer.restype = wintypes.BOOL
    invalid = wintypes.HANDLE(-1).value

    def writable(path):
        return opener(str(path), 0x40000000, 7, None, 3, 0x02000000 | 0x00200000, None)

    # Establish that the account can open both owned directories for writing;
    # refusal during cleanup must come from custody, not fixture permissions.
    for path in (cache, directory):
        handle = writable(path)
        assert handle != invalid
        closer(handle)
    original = cleanup._CacheDirectory.remove_empty
    witnessed = []

    def verify_held(held, *args):
        for path in (cache, directory):
            handle = writable(path)
            if handle != invalid:
                closer(handle)
                pytest.fail("cleanup allowed a writable directory handle")
            assert ctypes.get_last_error() == 32  # ERROR_SHARING_VIOLATION
        witnessed.append(True)
        return original(held, *args)

    monkeypatch.setattr(cleanup._CacheDirectory, "remove_empty", verify_held)
    result = cleanup.cleanup_cache(cache)
    assert result["complete"] and witnessed == [True] and not directory.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows read-only recovery artifacts")
def test_windows_readonly_versions_and_interrupted_temporary_copies_are_deleted(cache):
    directory = key(cache)
    paths = [directory / "123.bak", directory / (".123." + "a" * 32 + ".tmp")]
    metadata = directory / "_source.txt"
    metadata.write_bytes(b"source")
    for path in paths:
        path.write_bytes(b"read-only recovery")
        path.chmod(stat.S_IREAD)
        assert path.stat().st_file_attributes & 1
    result = cleanup.cleanup_cache(cache)
    try:
        assert result["complete"], result
        assert result["removed_files"] == 3 and result["removed_directories"] == 1
        assert not directory.exists()
    finally:
        for path in paths:
            if path.exists():
                path.chmod(stat.S_IWRITE | stat.S_IREAD)


@pytest.mark.skipif(os.name != "nt", reason="Windows read-only attribute preservation")
@pytest.mark.parametrize("kind", ["unknown", "pinned", "hardlink"])
def test_windows_unapproved_readonly_files_keep_their_bytes_and_attributes(cache, tmp_path, kind):
    directory = key(cache)
    path = directory / ("evidence.json" if kind == "unknown" else "123.bak")
    path.write_bytes(b"preserved read-only data")
    if kind == "pinned":
        (directory / "123.bak.keep").write_bytes(b"investigation pin")
    linked = tmp_path / "original"
    if kind == "hardlink":
        os.link(path, linked)
    path.chmod(stat.S_IREAD)
    before = path.stat().st_file_attributes
    try:
        result = cleanup.cleanup_cache(cache)
        assert not result["complete"] and result["removed_files"] == 0
        assert path.read_bytes() == b"preserved read-only data"
        assert path.stat().st_file_attributes == before
        if kind == "hardlink":
            assert linked.read_bytes() == b"preserved read-only data"
            assert linked.stat().st_file_attributes == before
    finally:
        path.chmod(stat.S_IWRITE | stat.S_IREAD)


@pytest.mark.skipif(os.name != "nt", reason="Windows FileDispositionInfoEx support boundary")
def test_unsupported_readonly_disposition_preserves_original_attributes(cache, monkeypatch):
    path = key(cache) / "123.bak"
    path.write_bytes(b"read-only recovery")
    path.chmod(stat.S_IREAD)
    before = path.stat().st_file_attributes
    original = cleanup._CacheFile._set_information
    attempted = []

    def unsupported(file, kind, value):
        if kind == 21:
            attempted.append(value.flags)
            raise OSError(50, "FileDispositionInfoEx unsupported")
        return original(file, kind, value)

    monkeypatch.setattr(cleanup._CacheFile, "_set_information", unsupported)
    try:
        result = cleanup.cleanup_cache(cache)
        assert not result["complete"] and result["removed_files"] == 0
        assert attempted == [0x11]
        assert path.read_bytes() == b"read-only recovery"
        assert path.stat().st_file_attributes == before
    finally:
        path.chmod(stat.S_IWRITE | stat.S_IREAD)


def test_single_artifact_deletion_is_identity_bound_and_preserves_source_mapping(cache):
    directory = key(cache)
    path = directory / "123.bak"
    path.write_bytes(b"prior version")
    metadata = directory / "_source.txt"
    metadata.write_bytes(b"source mapping")
    expected = cleanup._identity(path.lstat())
    assert cleanup.delete_cache_file(path, expected_identity=expected)
    assert not path.exists() and metadata.read_bytes() == b"source mapping"
    assert directory.is_dir()


def test_single_artifact_refuses_changed_identity_and_cancellation(cache):
    path = key(cache) / "123.bak"
    path.write_bytes(b"prior")
    expected = cleanup._identity(path.lstat())
    path.write_bytes(b"replacement longer")
    with pytest.raises(ValueError, match="changed"):
        cleanup.delete_cache_file(path, expected_identity=expected)
    stopped = threading.Event()
    stopped.set()
    assert not cleanup.delete_cache_file(path, expected_identity=cleanup._identity(path.lstat()), stopped=stopped)
    assert path.read_bytes() == b"replacement longer"


@pytest.mark.parametrize("name", ["_source.txt", "evidence.json", "123.bak.keep"])
def test_single_artifact_never_admits_metadata_or_unknown_names(cache, name):
    path = key(cache) / name
    path.write_bytes(b"preserved")
    with pytest.raises(ValueError, match="select one"):
        cleanup.delete_cache_file(path, expected_identity=cleanup._identity(path.lstat()))
    assert path.read_bytes() == b"preserved"


def test_single_artifact_requires_explicit_prior_identity(cache):
    path = key(cache) / "123.bak"
    path.write_bytes(b"preserved")
    with pytest.raises(ValueError, match="previously observed"):
        cleanup.delete_cache_file(path, expected_identity=None)
    assert path.read_bytes() == b"preserved"


@pytest.mark.skipif(os.name == "nt", reason="POSIX read-only cache descriptor")
def test_posix_readonly_recovery_copy_uses_readonly_held_descriptor(cache, monkeypatch):
    path = key(cache) / "123.bak"
    path.write_bytes(b"read-only recovery")
    path.chmod(0o444)
    original = cleanup.os.open
    observed = []

    def record(name, flags, *args, **kwargs):
        if name == "123.bak":
            observed.append(flags & os.O_ACCMODE)
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(cleanup.os, "open", record)
    result = cleanup.cleanup_cache(cache)
    assert result["complete"] and result["removed_files"] == 1
    assert observed == [os.O_RDONLY] and not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory permission custody")
def test_posix_publicly_writable_cache_is_refused(cache):
    path = key(cache) / "1.bak"
    path.write_bytes(b"copy")
    cache.chmod(0o777)
    try:
        result = cleanup.cleanup_cache(cache)
        assert not result["complete"] and path.read_bytes() == b"copy"
    finally:
        cache.chmod(0o700)


def test_absent_cache_does_not_create_it(tmp_path):
    path = tmp_path / "shadow_cache"
    assert cleanup.cleanup_cache(path)["complete"] and not path.exists()


@pytest.mark.parametrize("path", ["shadow_cache", "C:/", "//server/share/shadow_cache"])
def test_nonlocal_or_relative_boundaries_are_refused(path):
    result = cleanup.cleanup_cache(path)
    assert not result["complete"] and result["removed_files"] == 0
