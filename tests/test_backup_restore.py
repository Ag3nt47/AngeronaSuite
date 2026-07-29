import json
import sqlite3

import pytest

from angerona.core.backup_restore import (
    BackupSelection, EncryptedBackupManager, RestorePlan,
)


def _manager(clock=lambda: 100.0):
    return EncryptedBackupManager(b"e" * 32, b"a" * 32, clock=clock)


def _source(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "settings.json").write_text(
        json.dumps({"eco_mode": True, "password": "never-exported-plaintext"}),
        encoding="utf-8",
    )
    db = sqlite3.connect(root / "events.db")
    db.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, message TEXT)")
    db.execute("INSERT INTO events(message) VALUES('signed audit event')")
    db.commit()
    db.close()
    return root


def test_encrypted_backup_verifies_and_hides_plaintext(tmp_path):
    root = _source(tmp_path)
    archive = tmp_path / "angerona.abk"
    manager = _manager()
    receipt = manager.create(
        archive, root,
        (
            BackupSelection("settings.json", privacy_class="restricted"),
            BackupSelection("events.db", kind="sqlite"),
            BackupSelection("missing.db", required=False),
        ),
        backup_id="backup-001",
    )
    assert manager.verify_receipt(receipt)
    raw = archive.read_bytes()
    assert b"never-exported-plaintext" not in raw
    assert b"settings.json" not in raw
    verified = manager.verify(archive)
    assert verified.manifest.backup_id == "backup-001"
    assert len(verified.manifest.items) == 2
    assert verified.archive_sha256 == receipt.archive_sha256


def test_restore_requires_offline_two_person_approval_and_preserves_rollback(tmp_path):
    root = _source(tmp_path)
    archive = tmp_path / "angerona.abk"
    manager = _manager()
    manager.create(
        archive, root,
        (BackupSelection("settings.json"),),
        backup_id="backup-001",
    )
    target = tmp_path / "restore"
    target.mkdir()
    (target / "settings.json").write_text("old-state", encoding="utf-8")
    plan = manager.plan_restore(
        archive, target, plan_id="restore-001", requested_by="operator-001",
    )
    with pytest.raises(PermissionError, match="two distinct"):
        manager.authorize_restore(plan, ("operator-001", "reviewer-001"))
    authorization = manager.authorize_restore(
        plan, ("reviewer-001", "reviewer-002")
    )
    with pytest.raises(PermissionError, match="offline"):
        manager.apply_restore(plan, authorization, app_offline=False)
    receipt = manager.apply_restore(plan, authorization, app_offline=True)
    assert manager.verify_restore_receipt(receipt)
    assert "eco_mode" in (target / "settings.json").read_text(encoding="utf-8")
    rollback = target / receipt.rollback_scope / "settings.json"
    assert rollback.read_text(encoding="utf-8") == "old-state"


def test_tamper_wrong_key_and_changed_plan_fail_closed(tmp_path):
    root = _source(tmp_path)
    archive = tmp_path / "angerona.abk"
    manager = _manager()
    manager.create(
        archive, root, (BackupSelection("settings.json"),),
        backup_id="backup-001",
    )
    with pytest.raises(ValueError, match="authentication"):
        EncryptedBackupManager(b"x" * 32, b"a" * 32).verify(archive)

    raw = bytearray(archive.read_bytes())
    raw[-32] ^= 1
    archive.write_bytes(raw)
    with pytest.raises(ValueError, match="authentication"):
        manager.verify(archive)


def test_paths_symlinks_and_in_root_destination_are_rejected(tmp_path, monkeypatch):
    from angerona.core import backup_restore as module

    root = _source(tmp_path)
    manager = _manager()
    with pytest.raises(ValueError, match="safe relative"):
        BackupSelection("../outside")
    with pytest.raises(ValueError, match="outside"):
        manager.create(
            root / "backup.abk", root,
            (BackupSelection("settings.json"),), backup_id="backup-001",
        )
    link = root / "linked.json"
    link.write_text("link-target-placeholder", encoding="utf-8")
    original = module._has_reparse_component
    monkeypatch.setattr(
        module, "_has_reparse_component",
        lambda checked_root, relative: (
            relative.as_posix() == "linked.json"
            or original(checked_root, relative)
        ),
    )
    with pytest.raises(ValueError, match="symlink"):
        manager.create(
            tmp_path / "backup.abk", root,
            (BackupSelection("linked.json"),), backup_id="backup-001",
        )


def test_restore_plan_authentication_binds_every_field(tmp_path):
    root = _source(tmp_path)
    archive = tmp_path / "angerona.abk"
    manager = _manager()
    manager.create(
        archive, root, (BackupSelection("settings.json"),),
        backup_id="backup-001",
    )
    plan = manager.plan_restore(
        archive, tmp_path / "restore",
        plan_id="restore-001", requested_by="operator-001",
    )
    changed = RestorePlan(**{
        **plan.__dict__, "target_root": str(tmp_path / "other"),
    })
    with pytest.raises(ValueError, match="authentication"):
        manager.authorize_restore(changed, ("reviewer-001", "reviewer-002"))


def test_interrupted_restore_puts_previous_file_back(tmp_path, monkeypatch):
    from angerona.core import backup_restore as module

    root = _source(tmp_path)
    archive = tmp_path / "angerona.abk"
    manager = _manager()
    manager.create(
        archive, root, (BackupSelection("settings.json"),),
        backup_id="backup-001",
    )
    target = tmp_path / "restore"
    target.mkdir()
    destination = target / "settings.json"
    destination.write_text("old-state", encoding="utf-8")
    plan = manager.plan_restore(
        archive, target, plan_id="restore-001", requested_by="operator-001",
    )
    authorization = manager.authorize_restore(
        plan, ("reviewer-001", "reviewer-002")
    )
    original = module.replace_with_retry
    calls = []

    def fail_install(source, output, **kwargs):
        calls.append((source, output))
        if len(calls) == 2:
            raise PermissionError("simulated storage interruption")
        return original(source, output, **kwargs)

    monkeypatch.setattr(module, "replace_with_retry", fail_install)
    with pytest.raises(PermissionError, match="interruption"):
        manager.apply_restore(plan, authorization, app_offline=True)
    assert destination.read_text(encoding="utf-8") == "old-state"
