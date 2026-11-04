"""Verification never bootstraps a profile, key or coordination lock."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from angerona.core import data_paths, report_attest
from angerona.core.file_lease import ExclusiveFileLease, ExclusiveFileLeaseError


def test_explicit_existing_verification_key_does_not_read_the_profile(monkeypatch):
    key = b"r" * 32
    signed = {"inert": "fixture"}
    signed[report_attest.SIG_FIELD] = report_attest.sign_doc(signed, key=key)
    def forbidden():
        raise AssertionError("Explicit verification consulted local key state")
    monkeypatch.setattr(report_attest, "_load_key", forbidden)
    assert report_attest.verify(signed, key=key) == "ok"
    assert report_attest.verify(signed, key=b"s" * 32) == "bad"
    assert report_attest.verify({"inert": "unsigned"}, key=key) == "unsigned"


@pytest.mark.parametrize("key", ["x" * 32, bytearray(b"x" * 32), False, 1, b"", b"x" * 31, b"x" * 33])
def test_invalid_explicit_key_never_falls_back_to_local_key(monkeypatch, key):
    def forbidden():
        raise AssertionError("Invalid explicit key fell back to install key")
    monkeypatch.setattr(report_attest, "_load_key", forbidden)
    with pytest.raises((TypeError, ValueError)):
        report_attest.verify({}, key=key)


def test_resolve_data_dir_does_not_mutate_environment_or_create_profile(tmp_path, monkeypatch):
    absent = tmp_path / "absent" / "profile"
    monkeypatch.setenv("ANGERONA_DATA", str(absent))
    monkeypatch.setattr(data_paths, "_elevated_source_runtime", lambda: False)
    before = dict(os.environ)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Pure profile resolution attempted creation")
    monkeypatch.setattr(Path, "mkdir", forbidden)
    assert data_paths.resolve_data_dir() == absent.resolve()
    assert not absent.exists() and before == dict(os.environ)


def test_existing_only_lease_never_creates_missing_parent_or_lock(tmp_path):
    path = tmp_path / "absent" / "writer.lock"
    with pytest.raises(ExclusiveFileLeaseError):
        ExclusiveFileLease(path, existing_only=True)
    assert not path.parent.exists()


def test_existing_only_lease_rejects_empty_without_initializing_it(tmp_path):
    path = tmp_path / "writer.lock"
    path.write_bytes(b"")
    with pytest.raises(ExclusiveFileLeaseError):
        ExclusiveFileLease(path, existing_only=True)
    assert path.read_bytes() == b""


def test_existing_only_lease_keeps_exclusion_and_does_not_write(tmp_path, monkeypatch):
    path = tmp_path / "writer.lock"
    path.write_bytes(b"\0")
    before = path.stat().st_mtime_ns
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Existing-only lease attempted initialization")
    monkeypatch.setattr(Path, "mkdir", forbidden)
    monkeypatch.setattr(os, "write", forbidden)
    with ExclusiveFileLease(path, existing_only=True):
        with pytest.raises(ExclusiveFileLeaseError):
            ExclusiveFileLease(path, existing_only=True)
    assert path.read_bytes() == b"\0" and path.stat().st_mtime_ns == before
