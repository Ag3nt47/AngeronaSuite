from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import durable_outbox
from angerona.core.durable_outbox import DurableOutbox, OutboxIntegrityError
from angerona.modules.av_telemetry_bridge import AVTelemetryBridgeModule


@pytest.fixture
def bridge(tmp_path):
    module = AVTelemetryBridgeModule(tmp_path, continuity_key=b"w" * 32)
    assert module._open_continuity_state()
    yield module
    module._close_continuity_state()


def test_unchanged_witness_and_empty_claim_reuse_only_verified_state(bridge, monkeypatch):
    bridge._enqueue_outbox("fixture", {"text": "inert fixture"})
    original = bridge._outbox_state_witness()
    outbox = bridge._outbox
    outbox.complete_pending("fixture")
    original = bridge._outbox_state_witness()
    monkeypatch.setattr(outbox, "_verify_row", lambda *_a, **_k: pytest.fail("unchanged rows reverified"))
    assert outbox.claim("reader") == ()
    assert bridge._outbox_state_witness() == original
    assert bridge._outbox_state_witness() == original


def test_authenticated_local_mutation_invalidates_witness(bridge):
    before = bridge._outbox_state_witness()
    bridge._outbox.enqueue("fixture", {"text": "inert fixture"})
    after = bridge._outbox_state_witness()
    assert after != before
    assert bridge._outbox_state_witness() == after


@pytest.mark.parametrize("external", [False, True])
def test_tampered_rows_cannot_hide_behind_witness_cache(bridge, external):
    bridge._enqueue_outbox("fixture", {"text": "inert fixture"})
    before = bridge._outbox_state_witness()
    outbox = bridge._outbox
    connection = sqlite3.connect(outbox.path) if external else outbox._db
    try:
        connection.execute("UPDATE durable_outbox SET state='delivered' WHERE item_id='fixture'")
        connection.commit()
        with pytest.raises(OutboxIntegrityError, match="authentication"):
            bridge._outbox_state_witness()
        assert bridge._outbox_witness_cache[-1] == before
    finally:
        connection.execute("UPDATE durable_outbox SET state='pending' WHERE item_id='fixture'")
        connection.commit()
        if external:
            connection.close()


def test_external_valid_change_invalidates_cache(bridge):
    before = bridge._outbox_state_witness()
    other = DurableOutbox(bridge._outbox.path, bridge._outbox._key)
    try:
        other.enqueue("external-fixture", {"fixture": "signed external writer"})
        assert bridge._outbox_state_witness() != before
    finally:
        other.close()


def test_external_change_during_witness_cannot_cache_stale_snapshot(bridge, monkeypatch):
    outbox = bridge._outbox
    outbox.enqueue("first", {"fixture": 1})
    other = DurableOutbox(outbox.path, outbox._key)
    original_verify = outbox._verify_row
    changed = False

    def verify(raw, **kwargs):
        nonlocal changed
        result = original_verify(raw, **kwargs)
        if not changed:
            changed = True
            other.enqueue("during-snapshot", {"fixture": 2})
        return result

    monkeypatch.setattr(outbox, "_verify_row", verify)
    try:
        observed = bridge._outbox_state_witness()
        assert changed
        bridge._outbox_witness_cache = None
        assert bridge._outbox_state_witness() == observed
    finally:
        other.close()


def test_external_change_during_cached_backing_check_reauthenticates(bridge, monkeypatch):
    outbox = bridge._outbox
    before = bridge._outbox_state_witness()
    other = DurableOutbox(outbox.path, outbox._key)
    original_backing = outbox._backing_file_state_locked
    changed = False

    def backing():
        nonlocal changed
        if not changed:
            changed = True
            other.enqueue("during-cache-check", {"fixture": "signed writer"})
        return original_backing()

    monkeypatch.setattr(outbox, "_backing_file_state_locked", backing)
    try:
        assert bridge._outbox_state_witness() != before
    finally:
        other.close()


def test_connection_replacement_cannot_reuse_colliding_change_counters(bridge, tmp_path):
    first = bridge._outbox
    first.enqueue("first", {"fixture": 1})
    witness = bridge._outbox_state_witness()
    second = DurableOutbox(tmp_path / "second.db", b"s" * 32)
    second.enqueue("second", {"fixture": 2})
    try:
        assert first._verified_change_token_locked() == second._verified_change_token_locked()
        bridge._outbox = second
        assert bridge._outbox_state_witness() != witness
    finally:
        bridge._outbox = first
        second.close()


@pytest.mark.parametrize("suffix", ["", "-wal"])
def test_raw_backing_write_with_restored_mtime_cannot_reuse_witness(bridge, suffix):
    bridge._enqueue_outbox("fixture", {"text": "inert fixture"})
    outbox = bridge._outbox
    witness = bridge._outbox_state_witness()
    token = outbox._verified_change_token_locked()
    path = Path(str(outbox.path) + suffix)
    original_stat = path.stat()
    offset = original_stat.st_size - 1
    assert offset > 0
    with path.open("r+b") as stream:
        stream.seek(offset)
        original_byte = stream.read(1)
        stream.seek(offset)
        stream.write(bytes([original_byte[0] ^ 1]))
        stream.flush()
        os.fsync(stream.fileno())
    os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    try:
        assert path.stat().st_size == original_stat.st_size
        assert path.stat().st_mtime_ns == original_stat.st_mtime_ns
        assert outbox._verified_change_token_locked() == token
        with pytest.raises(RuntimeError, match="backing files changed"):
            bridge._outbox_state_witness()
        assert bridge._outbox_witness_cache[-1] == witness
    finally:
        with path.open("r+b") as stream:
            stream.seek(offset)
            stream.write(original_byte)
            stream.flush()
            os.fsync(stream.fileno())


def test_backing_file_identity_change_rejects_old_sqlite_connection(bridge, monkeypatch):
    outbox = bridge._outbox
    bridge._outbox_state_witness()
    original_stamp = durable_outbox._backing_file_stamp

    def replaced_identity(path):
        stamp = original_stamp(path)
        if path == outbox.path:
            return (stamp[0], stamp[1] + 1, *stamp[2:])
        return stamp

    # Windows denies replacement while SQLite holds the database open. Model
    # the filesystem identity returned after a replacement on permitting hosts.
    monkeypatch.setattr(durable_outbox, "_backing_file_stamp", replaced_identity)
    with pytest.raises(OutboxIntegrityError, match="file identity changed"):
        bridge._outbox_state_witness()


def test_canonical_backing_path_change_rejects_old_connection(bridge, monkeypatch):
    outbox = bridge._outbox
    bridge._outbox_state_witness()
    original_resolve = Path.resolve

    def redirected(path, *args, **kwargs):
        resolved = original_resolve(path, *args, **kwargs)
        return resolved.with_name("redirected.db") if path == outbox.path else resolved

    monkeypatch.setattr(Path, "resolve", redirected)
    with pytest.raises(OutboxIntegrityError, match="path or file identity changed"):
        bridge._outbox_state_witness()


@pytest.mark.parametrize("suffix", ["", "-wal"])
def test_reparse_backing_file_is_rejected_even_with_unchanged_sqlite_tokens(
    bridge, monkeypatch, suffix
):
    bridge._outbox_state_witness()
    target = Path(str(bridge._outbox.path) + suffix)
    original_lstat = Path.lstat

    def redirected(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if path == target:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    monkeypatch.setattr(Path, "lstat", redirected)
    with pytest.raises(OutboxIntegrityError, match="unredirected"):
        bridge._outbox_state_witness()


def test_external_wal_checkpoint_invalidates_and_reauthenticates_witness(bridge):
    bridge._enqueue_outbox("fixture", {"text": "inert fixture"})
    outbox = bridge._outbox
    witness = bridge._outbox_state_witness()
    token = outbox._verified_change_token_locked()
    other = sqlite3.connect(outbox.path)
    try:
        assert other.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
        assert outbox._verified_change_token_locked() != token
        assert bridge._outbox_state_witness() == witness
    finally:
        other.close()


def test_unstable_authentication_tokens_fail_in_bounded_attempts(bridge, monkeypatch):
    outbox = bridge._outbox
    calls = []
    real_data_version = outbox._data_version_locked

    def changing_version():
        calls.append(True)
        return len(calls)

    monkeypatch.setattr(outbox, "_data_version_locked", changing_version)
    with pytest.raises(OutboxIntegrityError, match="changed repeatedly"):
        bridge._outbox_state_witness()
    assert len(calls) == 6
    monkeypatch.setattr(outbox, "_data_version_locked", real_data_version)


def test_tombstone_pruning_uses_ordered_index_without_sorting_payloads(bridge):
    outbox = bridge._outbox
    plan = outbox._db.execute(
        "EXPLAIN QUERY PLAN SELECT item_id,payload_json,state_signature "
        "FROM durable_outbox WHERE state='delivered' "
        "ORDER BY created_at DESC LIMIT -1 OFFSET ?", (outbox.delivered_tombstones,),
    ).fetchall()
    descriptions = [str(row[-1]) for row in plan]
    assert any("idx_durable_outbox_tombstones" in item for item in descriptions)
    assert not any("TEMP B-TREE" in item for item in descriptions)
