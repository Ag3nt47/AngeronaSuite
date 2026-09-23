from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from angerona.core import recovery_drill as drill

ENCRYPTION = hashlib.sha256(b"test-only-recovery-encryption").digest()
AUDIT = hashlib.sha256(b"test-only-recovery-audit").digest()


def run_fixture(tmp_path):
    return drill.fixture_drill(tmp_path, encryption_key=ENCRYPTION, audit_key=AUDIT)


def verify(root):
    return drill.verify_drill(Path(root), encryption_key=ENCRYPTION, audit_key=AUDIT)


def test_actual_encrypted_fixture_restores_and_rechecks_all_bytes(tmp_path):
    result = run_fixture(tmp_path)
    root = Path(result["directory"])
    receipt = result["receipt"]
    assert receipt["status"] == "passed"
    assert receipt["file_count"] == 3
    assert receipt["checks"]["tampered_archive_rejected"] is True
    assert receipt["scope"]["independent_failure_domain"] is False
    assert receipt["scope"]["offline_or_offsite_proven"] is False
    assert receipt["scope"]["live_paths_modified"] is False
    assert not (root / "snapshots").exists()
    assert not list(tmp_path.glob(".fixture-*"))
    assert not (root / "tampered-negative-control.angerona").exists()
    assert verify(root)["valid"] is True
    assert b"Angerona inert recovery drill" not in (root / "backup.angerona").read_bytes()
    assert ENCRYPTION.hex() not in (root / "receipt.json").read_text(encoding="utf-8")
    assert AUDIT.hex() not in (root / "receipt.json").read_text(encoding="utf-8")


def test_selected_sources_are_unchanged_and_existing_paths_never_overwritten(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "important.txt").write_bytes(b"original")
    (source / "nested").mkdir()
    (source / "nested" / "empty").write_bytes(b"")
    existing = tmp_path / "restored"
    existing.mkdir()
    (existing / "important.txt").write_bytes(b"do not touch")
    result = drill.run_drill(source, ["important.txt", "nested/empty"], tmp_path,
                            encryption_key=ENCRYPTION, audit_key=AUDIT)
    assert (source / "important.txt").read_bytes() == b"original"
    assert (existing / "important.txt").read_bytes() == b"do not touch"
    assert verify(result["directory"])["file_count"] == 2


def test_post_restore_tampering_fails_fresh_receipt_verification(tmp_path):
    root = Path(run_fixture(tmp_path)["directory"])
    path = root / "restored" / "item0000.bin"
    original = path.read_bytes()
    path.write_bytes(b"X" + original[1:])
    with pytest.raises(ValueError, match="hash verification"):
        verify(root)


def test_post_receipt_archive_tampering_fails_even_when_restored_files_are_intact(tmp_path):
    root = Path(run_fixture(tmp_path)["directory"])
    path = root / "backup.angerona"
    data = path.read_bytes()
    path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    with pytest.raises(Exception):
        verify(root)


def test_receipt_authentication_rejects_forged_success(tmp_path):
    root = Path(run_fixture(tmp_path)["directory"])
    path = root / "receipt.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["payload"]["scope"]["independent_failure_domain"] = True
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="authentication"):
        verify(root)


def test_unexpected_restored_file_fails_inventory_check(tmp_path):
    root = Path(run_fixture(tmp_path)["directory"])
    (root / "restored" / "extra.txt").write_text("not verified", encoding="utf-8")
    with pytest.raises(ValueError, match="inventory"):
        verify(root)


@pytest.mark.parametrize("selection", [["../escape"], ["same", "SAME"], [], ["x"] * 65])
def test_invalid_selections_fail_before_creating_drill(tmp_path, selection):
    with pytest.raises(ValueError):
        drill.run_drill(tmp_path, selection, tmp_path, encryption_key=ENCRYPTION, audit_key=AUDIT)
    assert not list(tmp_path.glob("drill-*"))


def test_source_hardlink_is_rejected(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    original = source / "input"
    original.write_bytes(b"private")
    os.link(original, source / "alias")
    with pytest.raises(ValueError, match="linked"):
        drill.run_drill(source, ["input"], tmp_path, encryption_key=ENCRYPTION, audit_key=AUDIT)
    assert original.read_bytes() == b"private"


def test_oversized_input_is_rejected_before_copy(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "input").write_bytes(b"0123456789")
    monkeypatch.setattr(drill, "MAX_FILE_BYTES", 8)
    with pytest.raises(ValueError, match="byte limit"):
        drill.run_drill(source, ["input"], tmp_path, encryption_key=ENCRYPTION, audit_key=AUDIT)


def test_aggregate_size_budget_applies_to_snapshot_copy(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a", "b"):
        (source / name).write_bytes(b"012345")
    monkeypatch.setattr(drill, "MAX_TOTAL_BYTES", 10)
    with pytest.raises(ValueError, match="byte limit"):
        drill.run_drill(source, ["a", "b"], tmp_path, encryption_key=ENCRYPTION, audit_key=AUDIT)


def test_same_key_for_encryption_and_audit_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="distinct"):
        drill.fixture_drill(tmp_path, encryption_key=ENCRYPTION, audit_key=ENCRYPTION)


def test_restore_drill_never_calls_live_restore_approval_path(tmp_path, monkeypatch):
    from angerona.core.backup_restore import EncryptedBackupManager
    def forbidden(*args, **kwargs):
        raise AssertionError("A drill must not fabricate live restore authorization")
    monkeypatch.setattr(EncryptedBackupManager, "authorize_restore", forbidden)
    monkeypatch.setattr(EncryptedBackupManager, "apply_restore", forbidden)
    assert run_fixture(tmp_path)["receipt"]["status"] == "passed"


def test_receipt_rechecks_restored_bytes_after_archive_negative_control(tmp_path, monkeypatch):
    original = drill._verify_files
    calls = []
    def check(root, items):
        calls.append(root)
        if len(calls) == 2:
            (root / items[0]["stored_name"]).write_bytes(b"changed between checks")
        return original(root, items)
    monkeypatch.setattr(drill, "_verify_files", check)
    with pytest.raises(ValueError, match="hash verification"):
        run_fixture(tmp_path)
    assert len(calls) == 2
    assert not list(tmp_path.glob("drill-*/receipt.json"))


def test_dedicated_recovery_keys_are_scrubbed_not_published(monkeypatch):
    from angerona.core import secure_store
    monkeypatch.setenv(drill.ENCRYPTION_SECRET, "inherited-untrusted-value")
    monkeypatch.setenv(drill.AUDIT_SECRET, "inherited-untrusted-value")
    monkeypatch.setattr(secure_store, "read_secret_map", lambda *args, **kwargs: {})
    secure_store.load_into_environment()
    assert drill.ENCRYPTION_SECRET not in os.environ
    assert drill.AUDIT_SECRET not in os.environ


def test_partial_protected_key_pair_never_replaces_existing_key(monkeypatch):
    from angerona.core import secure_store
    monkeypatch.setattr(secure_store, "read_secret_values", lambda *args, **kwargs: {
        drill.ENCRYPTION_SECRET: ENCRYPTION.hex()})
    monkeypatch.setattr(secure_store, "write_secret_map", lambda *args, **kwargs: pytest.fail("overwrote key"))
    with pytest.raises(ValueError, match="missing or incomplete"):
        drill.protected_keys(create=True)


def test_selection_iterator_is_consumed_only_to_the_bound(tmp_path):
    def selections():
        for index in range(65):
            yield f"item-{index}"
        pytest.fail("unbounded caller input was consumed")
    with pytest.raises(ValueError, match="1 and 64"):
        drill.run_drill(tmp_path, selections(), tmp_path, encryption_key=ENCRYPTION, audit_key=AUDIT)
