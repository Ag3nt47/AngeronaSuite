from __future__ import annotations

import contextlib
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import process_allowlist as policy
from angerona.modules import self_integrity


def snapshot(path: Path, digest: str):
    return ((path.name.casefold(), policy._normal_path(str(path)), digest),)


def test_unchanged_current_bytes_are_allowed_and_leave_no_persistent_file_lock(tmp_path):
    candidate = tmp_path / "reviewed.bin"
    candidate.write_bytes(b"reviewed")
    expected = hashlib.sha256(b"reviewed").hexdigest()
    approved = snapshot(candidate, expected)
    assert policy.executable_sha256(candidate) == expected
    assert policy.is_digest_pinned_allowed(candidate.name, str(candidate), policy=approved)
    candidate.write_bytes(b"tampered")
    assert not policy.is_digest_pinned_allowed(candidate.name, str(candidate), policy=approved)


def test_same_size_edit_with_restored_mtime_cannot_reuse_a_cached_digest(tmp_path):
    candidate = tmp_path / "reviewed.bin"
    candidate.write_bytes(b"reviewed")
    expected = policy.executable_sha256(candidate)
    before = candidate.stat()
    candidate.write_bytes(b"tampered")
    os.utime(candidate, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert candidate.stat().st_size == before.st_size
    assert candidate.stat().st_mtime_ns == before.st_mtime_ns
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() != expected
    assert not policy.is_digest_pinned_allowed(
        candidate.name, str(candidate), policy=snapshot(candidate, expected)
    )


def test_swap_read_restore_cannot_authorize_an_unreviewed_named_file(monkeypatch, tmp_path):
    candidate, displaced, reviewed = (tmp_path / name for name in ("candidate.bin", "displaced.bin", "reviewed.bin"))
    candidate.write_bytes(b"unreviewed executable bytes")
    reviewed.write_bytes(b"reviewed executable bytes")
    expected = hashlib.sha256(reviewed.read_bytes()).hexdigest()
    before = candidate.stat()
    original_open = policy._open_hash_stream

    @contextlib.contextmanager
    def swapped_open(path):
        assert path == candidate
        candidate.rename(displaced)
        reviewed.rename(candidate)
        try:
            with original_open(candidate) as stream:
                yield stream
        finally:
            candidate.rename(reviewed)
            displaced.rename(candidate)

    monkeypatch.setattr(policy, "_open_hash_stream", swapped_open)
    assert not policy.is_digest_pinned_allowed(
        candidate.name, str(candidate), policy=snapshot(candidate, expected)
    )
    assert policy._hash_identity(before) == policy._hash_identity(candidate.stat())
    assert candidate.read_bytes() == b"unreviewed executable bytes"


def test_initial_size_limit_rejects_before_open(monkeypatch, tmp_path):
    candidate = tmp_path / "oversize.bin"
    candidate.write_bytes(b"12345")
    monkeypatch.setattr(policy, "_MAX_EXECUTABLE_BYTES", 4)
    monkeypatch.setattr(policy, "_open_hash_stream", lambda _path: pytest.fail("oversize file opened"))
    with pytest.raises(ValueError, match="bounded"):
        policy.executable_sha256(candidate)


@pytest.mark.parametrize("mode", ["growth", "truncated"])
def test_read_cannot_extend_past_initial_size_or_accept_premature_eof(monkeypatch, tmp_path, mode):
    candidate = tmp_path / "changing.bin"
    candidate.write_bytes(b"1234")
    original_open = policy._open_hash_stream
    reads = []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, maximum):
            reads.append(maximum)
            if mode == "truncated":
                return b""
            # Model a producer that keeps extending the readable stream. The
            # verifier must stop after the original size plus one EOF probe.
            return b"x" * maximum

    monkeypatch.setattr(policy, "_open_hash_stream", lambda path: Reader(original_open(path)))
    with pytest.raises(ValueError, match="grew|changed"):
        policy.executable_sha256(candidate)
    assert sum(reads) <= 5


def test_hash_read_budget_fails_closed_without_waiting_for_a_large_scan(monkeypatch, tmp_path):
    candidate = tmp_path / "budget.bin"
    candidate.write_bytes(b"1234")
    clock = iter((0.0, 1.0, 2.0, 3.0))
    monkeypatch.setattr(policy, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    monkeypatch.setattr(policy, "_HASH_READ_BUDGET_SECONDS", 2.0)
    with pytest.raises(ValueError, match="read budget"):
        policy.executable_sha256(candidate)


def test_hardlinked_file_cannot_confer_digest_pinned_trust(tmp_path):
    candidate, alias = tmp_path / "candidate.bin", tmp_path / "alias.bin"
    candidate.write_bytes(b"reviewed")
    os.link(candidate, alias)
    expected = hashlib.sha256(b"reviewed").hexdigest()
    assert not policy.is_digest_pinned_allowed(
        candidate.name, str(candidate), policy=snapshot(candidate, expected)
    )


def test_access_denial_remains_untrusted(monkeypatch, tmp_path):
    candidate = tmp_path / "denied.bin"
    candidate.write_bytes(b"reviewed")

    def deny(_path):
        raise PermissionError("inert access denial")

    monkeypatch.setattr(policy, "_open_hash_stream", deny)
    assert not policy.is_digest_pinned_allowed(
        candidate.name, str(candidate), policy=snapshot(candidate, hashlib.sha256(b"reviewed").hexdigest())
    )


def test_symbolic_parent_is_not_accepted_as_an_approved_path(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    candidate = actual / "candidate.bin"
    candidate.write_bytes(b"reviewed")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"host cannot create symbolic link fixture: {exc}")
    with pytest.raises(ValueError, match="reparse|symlink"):
        policy.executable_sha256(alias / candidate.name)


@pytest.mark.skipif(os.name != "nt", reason="Windows retained handle denies write and delete sharing")
def test_native_windows_file_cannot_be_written_or_replaced_during_hash(monkeypatch, tmp_path):
    candidate = tmp_path / "reviewed.bin"
    other = tmp_path / "other.bin"
    candidate.write_bytes(b"reviewed")
    other.write_bytes(b"tampered")
    original_open = policy._open_hash_stream
    checked = []

    @contextlib.contextmanager
    def checked_open(path):
        with original_open(path) as stream:
            with pytest.raises(OSError):
                candidate.write_bytes(b"tampered")
            with pytest.raises(OSError):
                os.replace(other, candidate)
            checked.append(True)
            yield stream

    monkeypatch.setattr(policy, "_open_hash_stream", checked_open)
    assert policy.executable_sha256(candidate) == hashlib.sha256(b"reviewed").hexdigest()
    assert checked == [True]
    # The lease lasts for this call only; approved application updates can
    # proceed immediately after hashing returns.
    candidate.write_bytes(b"updated")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO substitution")
def test_fifo_substituted_before_open_is_rejected_without_waiting_for_a_writer(monkeypatch, tmp_path):
    candidate, original = tmp_path / "candidate.bin", tmp_path / "original.bin"
    candidate.write_bytes(b"reviewed")
    original_open = policy._open_hash_stream

    @contextlib.contextmanager
    def fifo_open(path):
        candidate.rename(original)
        os.mkfifo(candidate)
        try:
            with original_open(path) as stream:
                yield stream
        finally:
            candidate.unlink()
            original.rename(candidate)

    monkeypatch.setattr(policy, "_open_hash_stream", fifo_open)
    with pytest.raises(ValueError, match="changed before"):
        policy.executable_sha256(candidate)


def test_hash_custody_helpers_are_mandatory_and_wrapped_source_evidence_is_project_code(monkeypatch):
    helper = "angerona.core.process_allowlist:_open_hash_stream"
    wrapped = "angerona.core.process_allowlist:_hold_plain_directories.__wrapped__"
    engine = self_integrity.SelfIntegrityEngine()
    assert helper in engine._targets and wrapped in engine._targets
    assert engine.arm() == engine.expected_count
    assert engine.evidence(wrapped)["source_file"].replace("\\", "/").endswith(
        "/angerona/core/source_sandbox.py"
    )
    resolve = self_integrity._resolve
    monkeypatch.setattr(self_integrity, "_resolve", lambda spec: None if spec == helper else resolve(spec))
    unavailable = self_integrity.SelfIntegrityEngine()
    assert unavailable.arm() == unavailable.expected_count - 1
    assert helper in unavailable.unresolved
    assert any(helper in finding and "mandatory coverage unavailable" in finding for finding in unavailable.check())
