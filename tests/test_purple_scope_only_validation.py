"""Fresh scope-only validation retains real reads; it never returns authority."""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path

import pytest

from angerona.modules import purple_guard as purple


def _forbidden(*_args, **_kwargs):
    raise AssertionError("Scope-only validation reached discarded identity formatting")


def test_scope_only_reads_hashes_and_closes_before_returning_non_authority(tmp_path, monkeypatch):
    marker = tmp_path / "_redteam_scope_probe.txt"
    payload = b"fixed inert scope marker\n" * 3000
    marker.write_bytes(payload)
    real_read, real_sha256 = os.read, hashlib.sha256
    reads, updates, digests = [], [], []

    def read(descriptor, size):
        chunk = real_read(descriptor, size)
        reads.append((descriptor, len(chunk)))
        return chunk

    class Digest:
        def __init__(self, actual):
            self.actual = actual

        def update(self, chunk):
            updates.append(len(chunk))
            return self.actual.update(chunk)

        def hexdigest(self):
            return self.actual.hexdigest()

    def sha256(*args, **kwargs):
        digest = Digest(real_sha256(*args, **kwargs))
        digests.append(digest)
        return digest

    real_resolve = Path.resolve

    def resolve(path, *args, **kwargs):
        if path == marker:
            return _forbidden()
        return real_resolve(path, *args, **kwargs)

    monkeypatch.setattr(purple.os, "read", read)
    monkeypatch.setattr(purple.hashlib, "sha256", sha256)
    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(purple, "_sha256", _forbidden)
    descriptor, result = purple._marker_path_identity(marker, hold=False, scope_only=True)
    assert descriptor is None and result is purple._MARKER_SCOPE_ONLY_OK
    assert len(digests) == 1 and sum(updates) == len(payload)
    assert sum(size for _descriptor, size in reads) == len(payload)
    assert reads
    for captured in {descriptor for descriptor, _size in reads}:
        with pytest.raises(OSError) as closed:
            os.fstat(captured)
        assert closed.value.errno == errno.EBADF
    assert not isinstance(result, dict) and not hasattr(result, "sha256")
    with pytest.raises(TypeError):
        json.dumps(result)


def test_default_explicit_false_and_held_identity_still_match_real_bytes(tmp_path):
    marker = tmp_path / "_redteam_full_identity.txt"
    payload = b"unchanged full identity proof"
    marker.write_bytes(payload)
    descriptor, default = purple._marker_path_identity(marker, hold=False)
    assert descriptor is None and type(default) is dict
    assert default["path"] == str(marker.resolve(strict=False))
    assert default["sha256"] == hashlib.sha256(payload).hexdigest()
    assert default["size"] == len(payload) and default["link_count"] == 1
    assert default["regular"] is True and default["no_follow"] is True
    assert len(default["identity_sha256"]) == 64
    assert purple._marker_path_identity(marker, hold=False, scope_only=False) == (None, default)
    # Truthy non-True values do not opt into the new non-authority result.
    assert purple._marker_path_identity(marker, hold=False, scope_only=1) == (None, default)
    held, current = purple._marker_path_identity(marker, hold=True)
    assert held is not None
    try:
        assert current == default
        assert os.fstat(held).st_size == len(payload)
    finally:
        os.close(held)
    marker.write_bytes(b"new bytes must get a new full identity")
    _descriptor, changed = purple._marker_path_identity(marker, hold=False)
    assert changed["sha256"] != default["sha256"]
    assert changed["identity_sha256"] != default["identity_sha256"]


@pytest.mark.parametrize("hold,delete_access", [(True, False), (False, True), (True, True)])
def test_scope_only_cannot_retain_or_delete_and_refuses_before_path_admission(
    tmp_path, monkeypatch, hold, delete_access,
):
    marker = tmp_path / "_redteam_invalid_scope.txt"
    marker.write_bytes(b"inert")
    monkeypatch.setattr(purple, "Path", _forbidden)
    with pytest.raises(ValueError, match="cannot retain or delete"):
        purple._marker_path_identity(marker, hold=hold, delete_access=delete_access, scope_only=True)


@pytest.mark.parametrize("mutation", ["truncate", "same-size-change"])
def test_scope_only_still_refuses_real_midread_mutation(tmp_path, monkeypatch, mutation):
    marker = tmp_path / "_redteam_changed_scope.txt"
    payload = b"inert" * 30000 if mutation == "truncate" else b"inert marker"
    marker.write_bytes(payload)
    before = marker.stat(follow_symlinks=False)
    real_read = os.read
    changed = False

    def read(descriptor, size):
        nonlocal changed
        chunk = real_read(descriptor, size)
        held = os.fstat(descriptor)
        if chunk and not changed and (held.st_dev, held.st_ino) == (before.st_dev, before.st_ino):
            changed = True
            marker.write_bytes(b"" if mutation == "truncate" else b"X" * len(payload))
            os.utime(marker, ns=(before.st_atime_ns, before.st_mtime_ns + 3_000_000_000))
        return chunk

    monkeypatch.setattr(purple.os, "read", read)
    assert purple._marker_path_identity(marker, hold=False, scope_only=True) == (None, {})
    assert changed, "The real open/read path must reach the injected filesystem race"


@pytest.mark.parametrize("unsafe", ["directory", "hardlink", "oversize"])
def test_scope_only_preserves_real_type_link_and_size_refusals(tmp_path, unsafe):
    marker = tmp_path / "_redteam_unsafe_scope.txt"
    if unsafe == "directory":
        marker.mkdir()
    else:
        marker.write_bytes(b"X" * (1024 * 1024 + 1) if unsafe == "oversize" else b"inert")
        if unsafe == "hardlink":
            os.link(marker, tmp_path / "outside-scope-alias.txt")
    assert purple._marker_path_identity(marker, hold=False, scope_only=True) == (None, {})
    assert purple._marker_path_identity(marker, hold=False) == (None, {})


def test_scope_inventory_uses_only_fresh_non_authority_results(tmp_path, monkeypatch):
    markers = [tmp_path / ("_redteam_scope_" + str(index) + ".txt") for index in range(2)]
    for marker in markers:
        marker.write_bytes(b"inert inventory marker")
    original = purple._marker_path_identity
    calls = []

    def read(path, **kwargs):
        result = original(path, **kwargs)
        calls.append((path, kwargs, result))
        return result

    monkeypatch.setattr(purple, "_marker_path_identity", read)
    monkeypatch.setattr(purple, "_sha256", _forbidden)
    assert purple._validation_target_markers_safe(tmp_path) is True
    assert len(calls) == 2
    assert all(kwargs == {"hold": False, "scope_only": True} for _path, kwargs, _result in calls)
    assert all(result == (None, purple._MARKER_SCOPE_ONLY_OK) for _path, _kwargs, result in calls)
    # Scope acceptance cannot consume an identity-looking dict from a wrong route.
    monkeypatch.setattr(purple, "_marker_path_identity", lambda *_args, **_kwargs: (None, {"regular": True}))
    assert purple._validation_target_markers_safe(tmp_path) is False
