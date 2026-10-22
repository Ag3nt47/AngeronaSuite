"""Inert-file evidence custody, authentication, and explicit restoration."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import spyware_quarantine as module
from angerona.core.engine_transport import private_directory
from angerona.core.spyware_quarantine import EncryptedQuarantine, QuarantineError


KEY = b"k" * 32
PAYLOAD = b"inert spywareguard forensic marker\x00\x01\x02" * 13


def _fixture(tmp_path, **kwargs):
    source = tmp_path / "inert-marker.bin"
    source.write_bytes(PAYLOAD)
    vault = EncryptedQuarantine(tmp_path / "vault", KEY, **kwargs)
    return vault, source, hashlib.sha256(PAYLOAD).hexdigest()


def _archive(vault, receipt):
    return vault.root / (receipt["receipt_id"] + ".aq")


def test_roundtrip_uses_random_authenticated_encryption_and_keeps_source(tmp_path):
    vault, source, digest = _fixture(tmp_path)
    first = vault.seal_file(source, digest)
    second = vault.seal_file(source, digest.upper())
    assert first["receipt_id"] != second["receipt_id"]
    assert first["status"] == "encrypted_copy"
    assert first["source_removed"] is False and first["plaintext_remains"] is True
    assert source.read_bytes() == PAYLOAD
    assert _archive(vault, first).read_bytes() != _archive(vault, second).read_bytes()
    assert PAYLOAD not in _archive(vault, first).read_bytes()
    assert KEY not in _archive(vault, first).read_bytes()
    destination = private_directory(tmp_path / "restored") / "marker.bin"
    result = vault.restore(first["receipt_id"], destination)
    assert result["status"] == "restored" and result["payload_verified"]
    assert destination.read_bytes() == PAYLOAD
    assert _archive(vault, first).exists()


def test_empty_file_roundtrip(tmp_path):
    vault, source, _digest = _fixture(tmp_path)
    source.write_bytes(b"")
    receipt = vault.seal_file(source, hashlib.sha256(b"").hexdigest())
    destination = private_directory(tmp_path / "restored") / "empty.bin"
    vault.restore(receipt["receipt_id"], destination)
    assert destination.read_bytes() == b""


@pytest.mark.parametrize("target", ["metadata", "payload"])
def test_tampering_fails_before_creating_restore_file(tmp_path, target):
    vault, source, digest = _fixture(tmp_path)
    receipt = vault.seal_file(source, digest)
    archive = _archive(vault, receipt)
    raw = bytearray(archive.read_bytes())
    index = len(module._MAGIC) + 16 if target == "metadata" else len(raw) - 1
    raw[index] ^= 1
    archive.write_bytes(raw)
    destination = private_directory(tmp_path / "restored") / "marker.bin"
    with pytest.raises(QuarantineError, match="authentication"):
        vault.restore(receipt["receipt_id"], destination)
    assert not destination.exists()
    assert source.read_bytes() == PAYLOAD


def test_wrong_key_and_receipt_rename_are_rejected(tmp_path):
    vault, source, digest = _fixture(tmp_path)
    receipt = vault.seal_file(source, digest)
    wrong = EncryptedQuarantine(vault.root, b"w" * 32)
    destination = private_directory(tmp_path / "restored") / "marker.bin"
    with pytest.raises(QuarantineError, match="authentication"):
        wrong.restore(receipt["receipt_id"], destination)
    replacement_id = "a" * 32
    _archive(vault, receipt).rename(vault.root / (replacement_id + ".aq"))
    with pytest.raises(QuarantineError, match="authentication"):
        vault.restore(replacement_id, destination)
    assert not destination.exists()


@pytest.mark.parametrize("receipt_id", ["../escape", "A" * 32, "/etc/passwd", "a" * 31, None, "a" * 32 + ".aq"])
def test_receipt_identifiers_cannot_traverse_paths(tmp_path, receipt_id):
    vault, _source, _digest = _fixture(tmp_path)
    with pytest.raises(QuarantineError, match="identifier"):
        vault.restore(receipt_id, tmp_path / "escape")


def test_bad_hash_and_oversize_are_rejected_before_archive_creation(tmp_path, monkeypatch):
    vault, source, digest = _fixture(tmp_path, max_file_bytes=len(PAYLOAD) - 1)
    monkeypatch.setattr(vault, "_read", lambda *_args: pytest.fail("oversized file was read"))
    with pytest.raises(QuarantineError, match="byte limit"):
        vault.seal_file(source, digest)
    assert list(vault.root.iterdir()) == []
    second = EncryptedQuarantine(tmp_path / "second-vault", KEY)
    with pytest.raises(QuarantineError, match="SHA-256"):
        second.seal_file(source, "0" * 64)
    assert list(second.root.iterdir()) == [] and source.read_bytes() == PAYLOAD


def test_delete_request_is_rejected_without_read_or_mutation(tmp_path, monkeypatch):
    vault, source, digest = _fixture(tmp_path)
    monkeypatch.setattr(vault, "_source", lambda *_args: pytest.fail("delete request opened source"))
    with pytest.raises(QuarantineError, match="Source removal is unsupported"):
        vault.seal_file(source, digest, remove_source=True)
    assert source.read_bytes() == PAYLOAD and list(vault.root.iterdir()) == []


def test_restore_never_overwrites_existing_destination(tmp_path):
    vault, source, digest = _fixture(tmp_path)
    receipt = vault.seal_file(source, digest)
    destination = private_directory(tmp_path / "restored") / "marker.bin"
    destination.write_bytes(b"existing evidence")
    with pytest.raises(FileExistsError):
        vault.restore(receipt["receipt_id"], destination)
    assert destination.read_bytes() == b"existing evidence"


def test_hardlinks_and_reparse_metadata_are_rejected(tmp_path):
    vault, source, digest = _fixture(tmp_path)
    alias = tmp_path / "alias.bin"
    try:
        os.link(source, alias)
    except OSError:
        pytest.skip("hardlinks unavailable")
    with pytest.raises((QuarantineError, OSError), match="single-link|hard-link"):
        vault.seal_file(source, digest)
    assert alias.read_bytes() == PAYLOAD and list(vault.root.iterdir()) == []
    with pytest.raises(QuarantineError, match="non-reparse"):
        module._regular(SimpleNamespace(st_mode=0o100600, st_nlink=1, st_file_attributes=0x400))


def test_link_root_and_source_refused_without_following(tmp_path):
    vault, source, digest = _fixture(tmp_path)
    alias = tmp_path / "source-link"
    try:
        alias.symlink_to(source)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(QuarantineError, match="link or reparse"):
        vault.seal_file(alias, digest)
    root_alias = tmp_path / "root-link"
    root_alias.symlink_to(vault.root, target_is_directory=True)
    with pytest.raises(QuarantineError, match="link or reparse"):
        EncryptedQuarantine(root_alias, KEY)
    assert list(vault.root.iterdir()) == []


def test_name_swap_cannot_report_success_or_delete_replacement(tmp_path, monkeypatch):
    vault, source, digest = _fixture(tmp_path)
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"unrelated replacement")
    parked = tmp_path / "parked.bin"
    real_read = vault._read

    def read_and_swap(stream, count, deadline):
        result = real_read(stream, count, deadline)
        # Windows denies the rename while the source is held. POSIX allows
        # it, and the post-read identity proof must reject the substitution.
        source.rename(parked)
        replacement.rename(source)
        return result

    monkeypatch.setattr(vault, "_read", read_and_swap)
    with pytest.raises((QuarantineError, OSError)):
        vault.seal_file(source, digest)
    if parked.exists():
        assert parked.read_bytes() == PAYLOAD and source.read_bytes() == b"unrelated replacement"
    else:
        assert source.read_bytes() == PAYLOAD and replacement.read_bytes() == b"unrelated replacement"
    assert list(vault.root.iterdir()) == []


def test_source_modification_during_read_cannot_succeed(tmp_path, monkeypatch):
    vault, source, digest = _fixture(tmp_path)
    real_read = vault._read

    def read_and_change(stream, count, deadline):
        result = real_read(stream, count, deadline)
        source.write_bytes(b"altered after bounded read")
        return result

    monkeypatch.setattr(vault, "_read", read_and_change)
    with pytest.raises((QuarantineError, OSError)):
        vault.seal_file(source, digest)
    assert list(vault.root.iterdir()) == []


def test_read_deadline_and_inventory_are_bounded(tmp_path, monkeypatch):
    vault, source, digest = _fixture(tmp_path, max_entries=1)
    ticks = iter([1.0, 12.0])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    with pytest.raises(QuarantineError, match="deadline"):
        vault.seal_file(source, digest)
    monkeypatch.undo()
    receipt = vault.seal_file(source, digest)
    with pytest.raises(QuarantineError, match="full"):
        vault.seal_file(source, digest)
    assert vault.snapshot()["archive_count"] == 1
    (vault.root / "unrelated-clutter").write_bytes(b"inert")
    with pytest.raises(QuarantineError, match="entry limit"):
        vault.list_receipts()
    assert _archive(vault, receipt).exists()


def test_dashboard_lists_authenticated_metadata_with_honest_payload_scope(tmp_path):
    vault, source, digest = _fixture(tmp_path)
    receipts = [vault.seal_file(source, digest) for _ in range(3)]
    snapshot = vault.snapshot(limit=2)
    assert snapshot["archive_count"] == 3 and snapshot["truncated"]
    assert snapshot["source_removal_supported"] is False
    assert len(snapshot["items"]) == 2 and len(snapshot["limitations"]) >= 3
    assert all(item["status"] == "encrypted_copy" and item["payload_verified"] is False
               for item in snapshot["items"])
    assert all(item["integrity"] == "metadata_authenticated_payload_unverified"
               for item in snapshot["items"])
    archive = _archive(vault, receipts[0])
    raw = bytearray(archive.read_bytes())
    raw[len(module._MAGIC) + 16] ^= 1
    archive.write_bytes(raw)
    assert any(item["status"] == "integrity_error" for item in vault.list_receipts())


@pytest.mark.parametrize("kwargs", [dict(key=b"short"), dict(key="k" * 32),
    dict(max_file_bytes=0), dict(read_timeout=float("nan")), dict(read_timeout=0),
    dict(max_entries=0)])
def test_invalid_keys_and_limits_create_no_vault(tmp_path, kwargs):
    options = {"key": KEY, **kwargs}
    with pytest.raises(QuarantineError):
        EncryptedQuarantine(tmp_path / "vault", **options)
    assert not (tmp_path / "vault").exists()


def test_invalid_list_limits_are_refused(tmp_path):
    vault, _source, _digest = _fixture(tmp_path)
    for limit in (0, 101, True, "10"):
        with pytest.raises(QuarantineError, match="list limit"):
            vault.list_receipts(limit=limit)


def test_replacement_of_private_staging_object_cannot_publish(tmp_path, monkeypatch):
    vault, source, digest = _fixture(tmp_path)
    real_pin = module._PinnedFileMove

    def substitute_before_pin(path):
        if path.name.startswith(".quarantine-pending-"):
            path.rename(path.with_name(path.name + "-parked"))
            path.write_bytes(b"unrelated replacement object")
        return real_pin(path)

    monkeypatch.setattr(module, "_PinnedFileMove", substitute_before_pin)
    with pytest.raises(QuarantineError, match="staging object changed"):
        vault.seal_file(source, digest)
    assert not list(vault.root.glob("*.aq"))
    assert source.read_bytes() == PAYLOAD


def test_forged_archive_length_is_refused_before_large_read(tmp_path):
    vault, source, digest = _fixture(tmp_path)
    receipt = vault.seal_file(source, digest)
    archive = _archive(vault, receipt)
    raw = bytearray(archive.read_bytes())
    start = len(module._MAGIC) + 12
    raw[start:start + 4] = b"\xff\xff\xff\xff"
    archive.write_bytes(raw)
    destination = private_directory(tmp_path / "restored") / "marker.bin"
    with pytest.raises(QuarantineError, match="metadata exceeds"):
        vault.restore(receipt["receipt_id"], destination)
    assert not destination.exists()


def test_restore_reparse_parent_is_refused_before_archive_read(tmp_path, monkeypatch):
    vault, source, digest = _fixture(tmp_path)
    receipt = vault.seal_file(source, digest)
    destination = tmp_path / "redirected" / "marker.bin"
    real_check = module._path_traverses_reparse
    monkeypatch.setattr(module, "_path_traverses_reparse", lambda path:
                        Path(path) == destination or real_check(path))
    monkeypatch.setattr(vault, "_open_archive", lambda *_a, **_k: pytest.fail("unsafe restore read archive"))
    with pytest.raises(QuarantineError, match="link or reparse"):
        vault.restore(receipt["receipt_id"], destination)
    assert not destination.exists()
