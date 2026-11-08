"""Retained directory identity survives unrelated activity outside its inventory."""
from __future__ import annotations

import contextlib
from dataclasses import replace
import os

import pytest

from angerona.core import source_activation_storage as storage


def _advance_modified(path):
    info = path.stat()
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))


def test_ancestor_custody_allows_real_unrelated_sibling_creation(tmp_path):
    state = tmp_path / "updates"
    state.mkdir()
    before = storage._stamp(tmp_path)
    with storage._held_chain(state):
        (tmp_path / "unrelated-sibling").mkdir()
        (tmp_path / "unrelated-sibling" / "other-job.txt").write_bytes(b"another job")
        _advance_modified(tmp_path)
        assert storage._stamp(tmp_path) != before
    assert (tmp_path / "unrelated-sibling" / "other-job.txt").read_bytes() == b"another job"


def test_public_storage_review_survives_sibling_activity_outside_inventory(tmp_path, monkeypatch):
    source, state = tmp_path / "source", tmp_path / "updates"
    source.mkdir()
    state.mkdir()
    actual_usage = storage.shutil.disk_usage
    observed = []

    def usage(path):
        if not observed:
            before = storage._stamp(tmp_path)
            (tmp_path / "another-job.log").write_bytes(b"independent temporary output")
            _advance_modified(tmp_path)
            observed.append((before, storage._stamp(tmp_path)))
        return actual_usage(path)

    monkeypatch.setattr(storage.shutil, "disk_usage", usage)
    review = storage.review_source_update_storage(source, state)
    assert observed[0][0] != observed[0][1]
    assert review["entries"] == review["retained_bytes"] == 0
    assert review["policy_status"] == "ready"
    assert review["automatic_deletion"] is review["startup_inhibited"] is False


def test_inventory_still_rejects_new_child_inside_the_reviewed_directory(tmp_path, monkeypatch):
    source, state = tmp_path / "source", tmp_path / "updates"
    source.mkdir()
    state.mkdir()
    actual_held = storage._held_node
    changed = []

    @contextlib.contextmanager
    def held(path, *, directory):
        with actual_held(path, directory=directory) as before:
            yield before
            if path == state and directory and not changed:
                (state / "unexpected-file.bin").write_bytes(b"must remain for review")
                _advance_modified(state)
                changed.append(True)

    monkeypatch.setattr(storage, "_held_node", held)
    with pytest.raises(storage.SourceActivationStorageHeld, match="storage directory changed after inventory"):
        storage.review_source_update_storage(source, state)
    assert changed and (state / "unexpected-file.bin").read_bytes() == b"must remain for review"


def test_real_directory_replacement_is_denied_or_detected(tmp_path):
    target, moved = tmp_path / "held", tmp_path / "original"
    target.mkdir()
    before = storage._stamp(target)
    replaced = denied = detected = False
    try:
        with storage._held_node(target, directory=True):
            try:
                target.rename(moved)
            except OSError:
                assert os.name == "nt"
                denied = True
            else:
                replaced = True
                target.mkdir()
    except storage.SourceActivationStorageHeld:
        detected = True
    assert denied or replaced and detected
    assert storage._stamp(moved if replaced else target)[:2] == before[:2]


def test_regular_file_content_change_still_holds_review(tmp_path):
    target = tmp_path / "record.json"
    target.write_bytes(b"original")
    with pytest.raises(storage.SourceActivationStorageHeld, match="storage object changed during review"):
        with storage._held_node(target, directory=False):
            target.write_bytes(b"tampered")  # Same size, separate mtime evidence.
            _advance_modified(target)
    assert target.read_bytes() == b"tampered"


def test_hardlinked_regular_data_stays_refused(tmp_path):
    target, alias = tmp_path / "record.json", tmp_path / "alias.json"
    target.write_bytes(b"original")
    os.link(target, alias)
    with pytest.raises((storage.SourceActivationStorageHeld, storage.file_api.ActivationFileError)):
        with storage._held_node(target, directory=False):
            pytest.fail("Hardlinked storage data was admitted")


@pytest.mark.skipif(os.name != "nt", reason="Native Windows retained handle identities")
@pytest.mark.parametrize("field", ["volume", "index", "attributes"])
def test_native_directory_identity_or_attribute_change_stays_held(tmp_path, monkeypatch, field):
    from tools import windows_publication_runtime as runtime

    actual_identity = runtime._handle_identity
    calls = []

    def identity(handle):
        value = actual_identity(handle)
        calls.append(value)
        return replace(value, **{field: getattr(value, field) ^ 1}) if len(calls) > 1 else value

    monkeypatch.setattr(runtime, "_handle_identity", identity)
    with pytest.raises(storage.SourceActivationStorageHeld, match="storage object changed during review"):
        with storage._held_node(tmp_path, directory=True):
            pass


@pytest.mark.skipif(os.name != "nt", reason="Native Windows retained handle identities")
@pytest.mark.parametrize("field", ["size", "links"])
def test_native_directory_child_metadata_does_not_change_custody(tmp_path, monkeypatch, field):
    from tools import windows_publication_runtime as runtime

    actual_identity = runtime._handle_identity
    calls = []

    def identity(handle):
        value = actual_identity(handle)
        calls.append(value)
        return replace(value, **{field: getattr(value, field) + 1}) if len(calls) > 1 else value

    monkeypatch.setattr(runtime, "_handle_identity", identity)
    with storage._held_node(tmp_path, directory=True):
        pass
    assert len(calls) == 2


@pytest.mark.skipif(os.name != "nt", reason="Native Windows retained handle identities")
@pytest.mark.parametrize("field", ["volume", "index", "size", "links", "attributes"])
def test_native_regular_file_full_identity_changes_stay_held(tmp_path, monkeypatch, field):
    from tools import windows_publication_runtime as runtime

    target = tmp_path / "record.json"
    target.write_bytes(b"unchanged")
    actual_identity = runtime._handle_identity
    calls = []

    def identity(handle):
        value = actual_identity(handle)
        calls.append(value)
        return replace(value, **{field: getattr(value, field) ^ 1}) if len(calls) > 1 else value

    monkeypatch.setattr(runtime, "_handle_identity", identity)
    with pytest.raises(storage.SourceActivationStorageHeld, match="storage object changed during review"):
        with storage._held_node(target, directory=False):
            pass
    assert target.read_bytes() == b"unchanged"
