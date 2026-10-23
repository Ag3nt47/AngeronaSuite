from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.backup_restore import BackupSelection, EncryptedBackupManager
from angerona.core.engine_transport import private_directory
from angerona.core.recovery_assurance import RecoveryCopyStatement, SCHEMA
from angerona.core.recovery_drill import verify_external_restore
from angerona.core.recovery_workflow import RecoveryWorkflow

ENCRYPTION = hashlib.sha256(b"inert workflow encryption").digest()
AUDIT = hashlib.sha256(b"inert workflow audit").digest()


@pytest.fixture
def backup(tmp_path):
    source = tmp_path / "external-source"
    source.mkdir()
    (source / "nested").mkdir()
    (source / "nested" / "document.txt").write_bytes(b"INERT RECOVERABLE DATA\n")
    (source / "empty").write_bytes(b"")
    archive = tmp_path / "external.angerona"
    receipt = EncryptedBackupManager(ENCRYPTION, AUDIT).create(archive, source,
        [BackupSelection("nested/document.txt"), BackupSelection("empty")],
        backup_id="inert-backup-001", source_scope="inert-test")
    key = Ed25519PrivateKey.generate()
    statement = RecoveryCopyStatement(schema=SCHEMA, copy_id="copy-external-001",
        failure_domain="independently-enrolled-fixture", media_class="offline-media",
        source_revision="a" * 40, archive_sha256=receipt.archive_sha256,
        manifest_sha256=receipt.manifest_sha256, created_at=time.time() - 30,
        verified_at=time.time() - 20, restore_tested_at=time.time() - 10,
        size_bytes=archive.stat().st_size, online=False, writable=False, immutable=True,
        separate_identity=True, encrypted=True, offsite=True, air_gapped=True)
    evidence = tmp_path / "external-evidence.json"
    evidence.write_text(json.dumps({"signer_id": "independent-fixture-authority",
        "statement": asdict(statement), "signature": base64.urlsafe_b64encode(
            key.sign(statement.canonical())).rstrip(b"=").decode()}))
    profile = private_directory(tmp_path / "profile")
    workflow = RecoveryWorkflow(profile, source_revision="a" * 40,
                                 key_loader=lambda: (ENCRYPTION, AUDIT))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return workflow, archive, evidence, key, public, source


def enroll(backup):
    workflow, _archive, _evidence, _key, public, _source = backup
    workflow.enroll_authority("independent-fixture-authority", public)
    return workflow


def test_no_io_constructor_or_automatic_enrollment(tmp_path, monkeypatch):
    from angerona.core import recovery_workflow as core
    monkeypatch.setattr(core, "private_directory", lambda *_: (_ for _ in ()).throw(AssertionError("IO")))
    workflow = core.RecoveryWorkflow(tmp_path)
    assert workflow.snapshot()["status"] == "deployment-required"
    assert workflow.snapshot()["latest_verified_revision"] is None
    assert not workflow.snapshot()["schedule_enabled"]


def test_real_external_encrypted_restore_and_fresh_inventory_proof(backup):
    workflow, archive, evidence, _key, _public, source = backup
    enroll(backup)
    result = workflow.restore(archive, evidence)
    root = Path(result["directory"])
    assert (root / "restored/nested/document.txt").read_bytes() == b"INERT RECOVERABLE DATA\n"
    assert (root / "restored/empty").read_bytes() == b""
    assert (source / "nested/document.txt").read_bytes() == b"INERT RECOVERABLE DATA\n"
    proof = result["proof"]
    assert proof["actual_restored_bytes_reread"] and not proof["live_paths_modified"]
    assert proof["duration_seconds"] > 0 and len(proof["inventory"]) == 2
    assert not proof["physical_independence_proven"]
    checked = verify_external_restore(root, encryption_key=ENCRYPTION, audit_key=AUDIT)
    assert checked["valid"]
    snapshot = workflow.snapshot()
    assert snapshot["latest_verified_revision"] == "a" * 40
    assert snapshot["separate_identity_claimed_by_signer"] is True
    assert snapshot["physical_independence_proven"] is False
    assert snapshot["latest_restore_seconds"] > 0
    assert snapshot["finding_codes"], "One local proof must not become three independent copies"
    raw = (root / "restore-proof.json").read_bytes()
    assert ENCRYPTION.hex().encode() not in raw and AUDIT.hex().encode() not in raw


def test_unenrolled_or_aliased_signer_cannot_be_imported(backup):
    workflow, _archive, evidence, _key, public, _source = backup
    with pytest.raises(ValueError, match="not trusted"):
        workflow.import_evidence(evidence)
    enroll(backup)
    with pytest.raises(ValueError, match="aliases"):
        workflow.enroll_authority("alias-of-same-key", public)
    with pytest.raises(ValueError, match="replaced"):
        workflow.enroll_authority("independent-fixture-authority", b"x" * 32)


def test_actual_archive_and_signed_evidence_binding_reject_tampering(backup):
    workflow, archive, evidence, _key, _public, _source = backup
    enroll(backup)
    data = archive.read_bytes()
    archive.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    with pytest.raises(ValueError, match="differs"):
        workflow.restore(archive, evidence)
    assert workflow.snapshot()["latest_verified_revision"] is None


def test_recheck_detects_changed_actual_restore_and_proof(backup):
    workflow, archive, evidence, _key, _public, _source = backup
    enroll(backup)
    result = workflow.restore(archive, evidence)
    root = Path(result["directory"])
    assert workflow.recheck()["valid"]
    (root / "restored/nested/document.txt").write_bytes(b"CHANGED")
    with pytest.raises(ValueError, match="hash verification"):
        workflow.recheck()
    value = json.loads((root / "restore-proof.json").read_text())
    value["payload"]["duration_seconds"] = 0
    (root / "restore-proof.json").write_text(json.dumps(value))
    with pytest.raises(ValueError, match="authentication"):
        workflow.recheck()


def test_restart_recheck_requires_real_proof_and_never_resumes_old_schedule(backup):
    workflow, archive, evidence, _key, _public, _source = backup
    enroll(backup)
    workflow.restore(archive, evidence)
    workflow.configure_schedule(True)
    restarted = RecoveryWorkflow(workflow.data_root, source_revision="a" * 40,
                                 key_loader=lambda: (ENCRYPTION, AUDIT))
    assert restarted.snapshot()["latest_verified_revision"] is None
    assert not restarted.snapshot()["schedule_enabled"]
    assert restarted.recheck()["valid"]
    assert restarted.snapshot()["latest_verified_revision"] == "a" * 40
    assert not restarted.snapshot()["schedule_enabled"]
    (workflow.root / "latest-local-restore.json").write_text('{"restore_id":"../outside"}')
    invalid = RecoveryWorkflow(workflow.data_root, key_loader=lambda: (ENCRYPTION, AUDIT))
    with pytest.raises(ValueError, match="valid local"):
        invalid.recheck()


def test_one_shot_keys_are_wiped_and_cannot_enable_recurring_unlock(backup):
    workflow, archive, evidence, _key, _public, _source = backup
    enroll(backup)
    keys = (bytearray(ENCRYPTION), bytearray(AUDIT))
    workflow.restore(archive, evidence, keys=keys)
    assert not any(keys[0]) and not any(keys[1])
    assert workflow.snapshot()["fresh_unlock_required"] is True
    with pytest.raises(ValueError, match="reusable"):
        workflow.configure_schedule(True)


@pytest.mark.parametrize("operation", ["restore", "recheck"])
def test_later_one_shot_unlock_revokes_existing_recurring_schedule(backup, operation):
    workflow, archive, evidence, _key, _public, _source = backup
    enroll(backup)
    workflow.restore(archive, evidence)
    workflow.configure_schedule(True)
    keys = (bytearray(ENCRYPTION), bytearray(AUDIT))
    if operation == "restore":
        workflow.restore(archive, evidence, keys=keys)
    else:
        workflow.recheck(keys=keys)
    snapshot = workflow.snapshot()
    assert snapshot["schedule_enabled"] is False
    assert snapshot["schedule_status"] == "fresh-unlock-required"
    assert snapshot["next_drill_at"] is None and workflow._due is None
    assert all(not any(key) for key in keys)


def test_guard_assessment_and_workflow_share_explicit_private_profile(backup, monkeypatch):
    from types import SimpleNamespace
    from angerona.core import data_paths
    from angerona.modules.immutable_recovery_guard import ImmutableRecoveryGuardModule

    workflow, _archive, evidence, _key, _public, _source = backup
    enroll(backup)
    workflow.import_evidence(evidence)
    monkeypatch.setattr(data_paths, "data_dir", lambda: (_ for _ in ()).throw(
        AssertionError("assessment must not read another profile")))
    module = ImmutableRecoveryGuardModule(source_revision="a" * 40)
    module.bind_manager(SimpleNamespace(config=SimpleNamespace(data_dir=workflow.data_root)))
    result, errors, _digest = module.observe_once()
    assert result.verified_copies == 1 and not errors
    assert module._get_workflow().root == workflow.root


def test_runtime_only_schedule_is_optin_paced_and_workspace_held(backup):
    workflow, archive, evidence, _key, _public, _source = backup
    enroll(backup)
    clock = [10.0]
    workflow.monotonic = lambda: clock[0]
    workflow.restore(archive, evidence)
    first = workflow.snapshot()["last_restore_directory"]
    workflow.tick()
    assert workflow.snapshot()["last_restore_directory"] == first
    workflow.configure_schedule(True, 1)
    clock[0] += 3599
    workflow.tick()
    assert workflow.snapshot()["last_restore_directory"] == first
    clock[0] += 1
    workflow.continue_work = lambda: False
    workflow.tick()
    assert workflow.snapshot()["schedule_status"] == "workspace-held"
    assert workflow.snapshot()["last_restore_directory"] == first
    workflow.continue_work = lambda: True
    workflow.tick()
    assert workflow.snapshot()["last_restore_directory"] != first


def test_cancellation_before_import_leaves_no_recovery_files(backup):
    workflow, archive, evidence, _key, _public, _source = backup
    workflow.continue_work = lambda: False
    with pytest.raises(InterruptedError):
        workflow.restore(archive, evidence)
    assert not workflow.root.exists()


def test_stale_genuinely_signed_copy_is_not_a_current_restore(backup):
    workflow, archive, evidence, key, _public, _source = backup
    enroll(backup)
    raw = json.loads(evidence.read_text())
    raw["statement"].update(created_at=time.time() - 9 * 86400,
        verified_at=time.time() - 8 * 86400, restore_tested_at=time.time() - 8 * 86400)
    statement = RecoveryCopyStatement(**raw["statement"])
    raw["signature"] = base64.urlsafe_b64encode(key.sign(statement.canonical())).rstrip(b"=").decode()
    evidence.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="stale"):
        workflow.restore(archive, evidence)
    assert workflow.snapshot()["latest_verified_revision"] is None
    assert not list(workflow.drills.iterdir())


def test_linked_evidence_and_artifact_retention_are_held_without_deletion(backup, tmp_path):
    import os
    from angerona.core.recovery_workflow import MAX_RETAINED_DRILLS

    workflow, archive, evidence, _key, _public, _source = backup
    enroll(backup)
    alias = tmp_path / "evidence-alias.json"
    os.link(evidence, alias)
    with pytest.raises(ValueError, match="linked"):
        workflow.import_evidence(alias)
    alias.unlink()
    for index in range(MAX_RETAINED_DRILLS):
        (workflow.drills / f"retained-{index}").mkdir()
    with pytest.raises(ValueError, match="retention"):
        workflow.restore(archive, evidence)
    assert len(list(workflow.drills.iterdir())) == MAX_RETAINED_DRILLS


def test_missing_original_keys_never_generates_new_keys(backup):
    workflow, archive, evidence, _key, _public, _source = backup
    enroll(backup)
    workflow.key_loader = lambda: (_ for _ in ()).throw(ValueError("existing keys missing"))
    with pytest.raises(ValueError, match="keys missing"):
        workflow.restore(archive, evidence)
    assert not list(workflow.drills.iterdir())


def test_real_guard_worker_queue_stays_off_qt_and_ugcap_stop_cancels_owned_work(backup):
    import threading
    from types import SimpleNamespace

    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    from angerona.core.eventbus import EventBus
    from angerona.gui.recovery_panel import RecoveryPanel
    from angerona.modules.immutable_recovery_guard import ImmutableRecoveryGuardModule

    workflow, archive, evidence, _key, _public, _source = backup
    enroll(backup)
    guard = ImmutableRecoveryGuardModule(source_revision="a" * 40)
    manager = SimpleNamespace(config=SimpleNamespace(data_dir=workflow.data_root), ugcap_paused=False,
                              modules={guard.name: guard})
    guard.bind(EventBus())
    guard.bind_manager(manager)
    guard._workflow = workflow
    workflow.continue_work = guard._continue_recovery
    entered, release = threading.Event(), threading.Event()
    original = workflow.restore
    captured = []
    def blocked(*args, **kwargs):
        captured.extend(kwargs.get("keys") or ())
        entered.set()
        assert release.wait(4)
        return original(*args, **kwargs)
    workflow.restore = blocked
    guard.start()
    panel = RecoveryPanel(manager)
    panel.show()
    app = QApplication.instance()
    app.processEvents()
    beats = []
    timer = QTimer()
    timer.setInterval(5)
    timer.timeout.connect(lambda: beats.append(time.monotonic()))
    try:
        assert guard.wait_for_first_cycle(3)
        panel.archive.setText(str(archive))
        panel.evidence.setText(str(evidence))
        panel.encryption_key.setText(ENCRYPTION.hex())
        panel.audit_key.setText(AUDIT.hex())
        panel.restore_button.click()
        assert not panel.encryption_key.text() and not panel.audit_key.text()
        assert entered.wait(3)
        timer.start()
        deadline = time.monotonic() + .15
        while time.monotonic() < deadline:
            app.processEvents()
            time.sleep(.002)
        assert len(beats) >= 3
        manager.ugcap_paused = True
        began = time.monotonic()
        guard.stop()
        panel.close()
        assert time.monotonic() - began < .2
    finally:
        release.set()
        guard.stop()
        if guard._thread is not None:
            guard._thread.join(5)
        panel.close()
        timer.stop()
    assert guard._thread is None or not guard._thread.is_alive()
    assert captured and all(not any(key) for key in captured)
    assert not list(workflow.drills.iterdir())
    assert workflow.snapshot()["status"] == "held"


def test_recovery_panel_cached_only_and_missing_module_controls(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from angerona.core import recovery_drill
    from angerona.gui.recovery_panel import RecoveryPanel

    monkeypatch.setattr(recovery_drill, "protected_keys", lambda **_kwargs:
        (_ for _ in ()).throw(AssertionError("No key IO on Qt")))
    missing = RecoveryPanel(SimpleNamespace(modules={}))
    try:
        assert not missing.restore_button.isEnabled()
        assert "unknown" in missing.status.text()
    finally:
        missing.close()


def test_guard_worker_restart_revokes_runtime_only_recurring_optin(backup):
    from types import SimpleNamespace
    from angerona.core.eventbus import EventBus
    from angerona.modules.immutable_recovery_guard import ImmutableRecoveryGuardModule

    workflow, archive, evidence, _key, _public, _source = backup
    enroll(backup)
    workflow.restore(archive, evidence)
    workflow.configure_schedule(True)
    guard = ImmutableRecoveryGuardModule(source_revision="a" * 40)
    guard.bind(EventBus())
    guard.bind_manager(SimpleNamespace(config=SimpleNamespace(data_dir=workflow.data_root), ugcap_paused=False))
    guard._workflow = workflow
    workflow.continue_work = guard._continue_recovery
    guard.start()
    try:
        assert guard.wait_for_first_cycle(3)
    finally:
        guard.stop()
        if guard._thread is not None:
            guard._thread.join(5)
    assert guard._thread is None or not guard._thread.is_alive()
    assert workflow.snapshot()["schedule_enabled"] is False
    assert workflow.snapshot()["next_drill_at"] is None
