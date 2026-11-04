"""Private file fixtures and explicit-key AAR readers; no host scan or action."""
from __future__ import annotations

import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.shark import aar_report as aar


def test_bounded_read_holds_actual_descriptor_and_closes_it(tmp_path, monkeypatch):
    path = tmp_path / "member.json"
    payload = b"inert exact fixture bytes" * 20
    path.write_bytes(payload)
    opened, requests = [], []
    real_open, real_read = os.open, os.read

    def open_file(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def read_file(descriptor, size):
        assert descriptor == opened[0]
        requests.append(size)
        return real_read(descriptor, size)

    def unbounded(_path):
        raise AssertionError("Unbounded Path.read_bytes was used")

    monkeypatch.setattr(os, "open", open_file)
    monkeypatch.setattr(os, "read", read_file)
    monkeypatch.setattr(Path, "read_bytes", unbounded)
    assert aar._read_bounded_report_member(path, 1024) == payload
    assert requests and max(requests) <= 1025
    with pytest.raises(OSError):
        os.fstat(opened[0])


@pytest.mark.parametrize("length", [0, 1025])
def test_empty_or_oversized_member_is_rejected_before_open(tmp_path, monkeypatch, length):
    path = tmp_path / "member.json"
    path.write_bytes(b"x" * length)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Rejected member was opened")

    monkeypatch.setattr(os, "open", forbidden)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)


def test_missing_member_does_not_initialize_parent_or_file(tmp_path):
    path = tmp_path / "absent" / "report.json"
    with pytest.raises(OSError):
        aar._read_bounded_report_member(path, 1024)
    assert not path.parent.exists()


def test_growth_between_named_stat_and_open_is_rejected_before_read(tmp_path, monkeypatch):
    path = tmp_path / "member.json"
    path.write_bytes(b"initial")
    real_open = os.open
    descriptors = []

    def grown_open(*args, **kwargs):
        with path.open("ab") as stream:
            stream.write(b"x" * 2048)
        descriptor = real_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def forbidden(*_args):
        raise AssertionError("Changed member was read")

    monkeypatch.setattr(os, "open", grown_open)
    monkeypatch.setattr(os, "read", forbidden)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_growth_during_read_cannot_allocate_more_than_limit_plus_one(tmp_path, monkeypatch):
    path = tmp_path / "member.json"
    path.write_bytes(b"initial")
    real_read = os.read
    returned = []

    def growing_read(descriptor, size):
        value = real_read(descriptor, size)
        returned.append(len(value))
        if len(returned) == 1:
            with path.open("ab") as stream:
                stream.write(b"x" * 8192)
        return value

    monkeypatch.setattr(os, "read", growing_read)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)
    assert sum(returned) <= 1025


def test_substitution_between_stat_and_open_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "member.json"
    path.write_bytes(b"original")
    original_open = os.open
    moved = tmp_path / "old-member.json"
    calls = []

    def replaced_open(*args, **kwargs):
        path.rename(moved)
        path.write_bytes(b"new-file")
        return original_open(*args, **kwargs)

    monkeypatch.setattr(os, "open", replaced_open)
    monkeypatch.setattr(os, "read", lambda *_args: calls.append(True))
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)
    assert not calls and moved.read_bytes() == b"original"


@pytest.mark.skipif(not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"), reason="POSIX FIFO race fixture")
def test_regular_file_swapped_to_fifo_cannot_block_open(tmp_path, monkeypatch):
    path = tmp_path / "member.json"
    path.write_bytes(b"regular before open")
    original_open = os.open

    def fifo_open(candidate, flags, *args, **kwargs):
        assert flags & os.O_NONBLOCK  # Fail before attempting a blocking FIFO.
        path.unlink()
        os.mkfifo(path)
        return original_open(candidate, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", fifo_open)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)


def test_named_identity_substitution_after_read_is_rejected(tmp_path, monkeypatch):
    path, other = tmp_path / "member.json", tmp_path / "other.json"
    path.write_bytes(b"original")
    other.write_bytes(b"different")
    replacement = other.lstat()
    original_lstat, original_read = Path.lstat, os.read
    read_done = []

    def read_file(descriptor, size):
        value = original_read(descriptor, size)
        read_done.append(True)
        return value

    def changed_name(candidate, *args, **kwargs):
        if candidate == path and read_done:
            return replacement
        return original_lstat(candidate, *args, **kwargs)

    # A real descriptor/read with a modeled final name replacement also works
    # on Windows filesystems that refuse rename while the CRT handle is open.
    monkeypatch.setattr(os, "read", read_file)
    monkeypatch.setattr(Path, "lstat", changed_name)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)


def test_positive_short_reads_are_accumulated_and_premature_eof_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "member.json"
    payload = b"positive short reads are ordinary"
    path.write_bytes(payload)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda descriptor, size: real_read(descriptor, min(size, 3)))
    assert aar._read_bounded_report_member(path, 1024) == payload
    calls = []

    def premature(descriptor, size):
        calls.append(True)
        return real_read(descriptor, min(size, 3)) if len(calls) == 1 else b""

    monkeypatch.setattr(os, "read", premature)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)


def test_file_metadata_change_during_read_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "member.json"
    path.write_bytes(b"same bytes, changed write time")
    info, real_read = path.stat(), os.read
    changed = []

    def read_file(descriptor, size):
        value = real_read(descriptor, size)
        if not changed:
            changed.append(True)
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        return value

    monkeypatch.setattr(os, "read", read_file)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)


def test_hardlinked_member_is_rejected_without_reading(tmp_path, monkeypatch):
    path = tmp_path / "member.json"
    path.write_bytes(b"linked fixture")
    try:
        os.link(path, tmp_path / "alias.json")
    except OSError as error:
        pytest.skip("This fixture filesystem cannot create a hardlink: " + type(error).__name__)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Hardlinked member was opened")

    monkeypatch.setattr(os, "open", forbidden)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)


@pytest.mark.parametrize("target,kind", [("member", "reparse"), ("parent", "reparse"),
    ("member", "symlink"), ("parent", "symlink")])
def test_redirected_member_or_parent_metadata_is_rejected_before_open(tmp_path, monkeypatch, target, kind):
    path = tmp_path / "member.json"
    path.write_bytes(b"ordinary fixture")
    unsafe_path = path if target == "member" else path.parent
    info = unsafe_path.lstat()
    values = {key: getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns")}
    values["st_file_attributes"] = getattr(info, "st_file_attributes", 0)
    if kind == "reparse":
        values["st_file_attributes"] |= 0x400
    else:
        values["st_mode"] = stat.S_IFLNK | 0o777
    unsafe = SimpleNamespace(**values)
    real_lstat = Path.lstat

    def observed(candidate, *args, **kwargs):
        return unsafe if candidate == unsafe_path else real_lstat(candidate, *args, **kwargs)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Redirected member/parent was opened")

    monkeypatch.setattr(Path, "lstat", observed)
    monkeypatch.setattr(os, "open", forbidden)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)


def test_read_exception_closes_the_exact_descriptor(tmp_path, monkeypatch):
    path = tmp_path / "member.json"
    path.write_bytes(b"inert fixture")
    descriptors = []
    real_open = os.open

    def open_file(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def unavailable(*_args):
        raise OSError("fixture read failure")

    monkeypatch.setattr(os, "open", open_file)
    monkeypatch.setattr(os, "read", unavailable)
    with pytest.raises(OSError):
        aar._read_bounded_report_member(path, 1024)
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


@pytest.fixture
def report(tmp_path, monkeypatch):
    key = b"b" * 32
    key_path = tmp_path / "bus.key"
    key_path.write_text(key.hex(), encoding="ascii")
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    row = aar.StepVerdict("Inert fixture", "fixture", "No host action", 100.0, True, category="unmonitored")
    result = aar._write_report(tmp_path, {"run_id": "bounded-reader-fixture", "kind": "shark", "status": "completed"},
        [row], "Inert bounded reader fixture")
    return result, key


def test_explicit_key_uses_bounded_reads_through_both_bundle_and_handoff_recheck(report, monkeypatch):
    handoff, key = report
    calls = []
    original = aar._read_bounded_report_member

    def bounded(path, limit):
        calls.append((path.name, limit))
        return original(path, limit)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Explicit read fell back to an unbounded read or install key")

    monkeypatch.setattr(aar, "_read_bounded_report_member", bounded)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(report_attest, "_load_key", forbidden)
    aar._read_bound_report_bundle(handoff.report_directory, "shark_aar", verification_key=key)
    aar._load_head_journal(handoff.report_directory / "shark_aar.heads.jsonl", "shark_aar", verification_key=key)
    assert aar.verified_aar_handoff_text(handoff, verification_key=key) == handoff.text
    assert len(calls) == 8
    assert all(limit == (16 * 1024 * 1024 if name.endswith(".heads.jsonl") else 4 * 1024 * 1024)
        for name, limit in calls)


def test_default_callers_keep_old_mock_signatures_and_omit_new_options(report, monkeypatch):
    handoff, _key = report
    original_bundle, original_journal = aar._read_bound_report_bundle, aar._load_head_journal
    original_verify, original_lease = report_attest.verify, aar.ExclusiveFileLease
    calls = []

    def bundle(root, basename):
        calls.append("bundle")
        return original_bundle(root, basename)

    def journal(path, basename):
        calls.append("journal")
        return original_journal(path, basename)

    def verify(document):
        calls.append("verify")
        return original_verify(document)

    def lease(path):
        calls.append("lease")
        return original_lease(path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Default reader was changed to the explicit-only read seam")

    monkeypatch.setattr(aar, "_read_bound_report_bundle", bundle)
    monkeypatch.setattr(aar, "_load_head_journal", journal)
    monkeypatch.setattr(report_attest, "verify", verify)
    monkeypatch.setattr(aar, "ExclusiveFileLease", lease)
    monkeypatch.setattr(aar, "_read_bounded_report_member", forbidden)
    assert aar.verified_aar_handoff_text(handoff) == handoff.text
    assert {"bundle", "journal", "verify", "lease"}.issubset(calls)
