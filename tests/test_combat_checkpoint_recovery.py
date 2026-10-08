"""An exact unchanged inert marker may finish accounting, never an action."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from angerona.core import combat_checkpoint_recovery as recovery, secure_store
from angerona.core.eventbus import Event, Severity
from angerona.modules.adversary_combat import AdversaryCombat, JournalIntegrityError, _PinnedFileMove
from angerona.shark.run_manifest import RED_TEAM_COMPREHENSIVE_PLAN


def _fixture(tmp_path, monkeypatch, *, change=None, extra_pending=False):
    (tmp_path / "bus.key").write_text((b"k" * 32).hex(), encoding="ascii")
    protected = tmp_path / "secrets.dpapi"
    protected.write_bytes(b"inert protected-store fixture")
    values = {"UNRELATED_SECRET": "must survive"}
    monkeypatch.setattr(secure_store, "read_secret_values", lambda names, *_a, **_k: {
        key: values[key] for key in names if key in values
    })

    def write(updates, _root):
        values.update(updates)
        protected.write_text(json.dumps(values), encoding="utf-8")
        return protected

    monkeypatch.setattr(secure_store, "write_secret_map", write)
    module = recovery.existing_installation(tmp_path)
    module._read_journal(strict=True)
    startup = module._action(
        "activate_honeypots", "Smart Deception", Event("Adversary Combat", "startup", Severity.INFO),
        "startup", reversible=True, details={"module": "Smart Deception"},
    )
    module._journal_intent(startup)
    module._journal_failure(startup, "inert fixture: no module was started")
    if extra_pending:
        another = module._action(
            "activate_honeypots", "Smart Deception", Event("Adversary Combat", "startup", Severity.INFO),
            "startup", reversible=True, details={"module": "Smart Deception"},
        )
        module._journal_intent(another)
    entry = next(row for row in RED_TEAM_COMPREHENSIVE_PLAN if row["marker_token"] == "credential_store_probe")
    marker = tmp_path / "drill-sandbox" / f"_redteam_{entry['marker_token']}_1234abcd.txt"
    marker.parent.mkdir()
    payload = (
        "ANGERONA RED TEAM comprehensive drill — fixed inert marker.\n"
        f"Tactic: {entry['tactic']}\nTechnique: {entry['technique']}\n"
        "No named ATT&CK behavior was executed.\n"
    ).encode("utf-8")
    marker.write_bytes(payload)
    destination = tmp_path / "combat-quarantine" / "combat-123456789abc" / marker.name
    with _PinnedFileMove(marker) as pinned:
        identity = pinned.identity
    details = {"original": str(marker), "quarantine": str(destination),
               "file_identity": identity, "source_identity": identity,
               "sha256": hashlib.sha256(payload).hexdigest(), "source_link_count": 1,
               "move_strategy": "rename"}
    event = Event("Purple Remediation Guard", "inert marker", Severity.HIGH)
    kwargs = {"action": "quarantine_file", "target": str(marker), "event": event,
              "combat_id": "combat-123456789abc", "reversible": True, "details": details}
    if change is not None:
        change(kwargs)
    action = module._action(**kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(module, "_advance_recovery_anchor", lambda _record: (_ for _ in ()).throw(
            OSError("inert interrupted checkpoint")))
        with pytest.raises(JournalIntegrityError):
            module._journal_intent(action)
    return module, marker, destination, values


def _authority(module):
    paths = (module.receipt_path, module.data_root / "secrets.dpapi", module.recovery_witness_path,
             module.data_root / "bus.key")
    return {path: path.read_bytes() for path in paths}


def test_repair_keeps_evidence_and_target_then_normal_reconcile_records_no_effect(tmp_path, monkeypatch):
    module, marker, destination, values = _fixture(tmp_path, monkeypatch)
    before, target = _authority(module), marker.read_bytes()
    report = recovery.inspect_drill_checkpoint(module)
    assert report["checkpoint_sequence"] == 2 and report["journal_records"] == 3
    assert _authority(module) == before

    result = recovery.recover_drill_checkpoint(module, expected_token=report["review_token"])

    assert result["recovered"] and not result["rearmed"]
    assert result["host_actions_executed"] == 0
    assert result["checkpoint_sequence"] == 3
    assert marker.read_bytes() == target and not destination.exists()
    assert module.receipt_path.read_bytes() == before[module.receipt_path]
    assert (tmp_path / "bus.key").read_bytes() == before[tmp_path / "bus.key"]
    assert values["UNRELATED_SECRET"] == "must survive"
    backup = Path(result["backup_directory"])
    for path, raw in before.items():
        if path.name == "bus.key":
            assert not (backup / path.name).exists()
        else:
            assert (backup / path.name).read_bytes() == raw
    monkeypatch.setattr(module, "_undo_record", lambda *_a: pytest.fail("No effect may be undone"))
    assert module._reconcile_state() is True
    records, legacy = module._read_journal(strict=True)
    assert not legacy and records[-1]["record_type"] == "failure"
    assert "no observed postcondition" in records[-1]["error"]
    assert module._pending_recovery_records() == {}
    assert module.receipt_path.read_bytes().startswith(before[module.receipt_path])


@pytest.mark.parametrize("mutation", ["content", "identity", "hardlink", "destination", "missing", "tampered_journal", "partial_line", "witness"])
def test_ambiguous_changed_or_applied_work_never_changes_authority(tmp_path, monkeypatch, mutation):
    module, marker, destination, _values = _fixture(tmp_path, monkeypatch)
    if mutation == "content":
        marker.write_bytes(b"different inert content")
    elif mutation == "identity":
        raw = marker.read_bytes()
        marker.rename(marker.with_suffix(".saved"))
        marker.write_bytes(raw)
    elif mutation == "hardlink":
        os.link(marker, marker.with_suffix(".alias"))
    elif mutation == "destination":
        destination.parent.mkdir(parents=True)
        destination.write_bytes(marker.read_bytes())
    elif mutation == "missing":
        marker.unlink()
    elif mutation == "tampered_journal":
        raw = module.receipt_path.read_bytes().replace(b"Purple Remediation Guard", b"Purple Remediation Gourd")
        module.receipt_path.write_bytes(raw)
    elif mutation == "partial_line":
        module.receipt_path.write_bytes(module.receipt_path.read_bytes().rstrip(b"\n"))
    elif mutation == "witness":
        module.recovery_witness_path.write_bytes(b"{}")
    before = _authority(module)
    with pytest.raises((recovery.CheckpointRecoveryRefused, JournalIntegrityError, OSError)):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == before
    assert not list(tmp_path.glob("combat-drill-recovery-*"))


@pytest.mark.parametrize("change", [
    lambda args: args.update(reversible=False),
    lambda args: args.update(event=Event("Unrelated Detector", "fixture", Severity.HIGH)),
    lambda args: args["details"].update(move_strategy="cross_volume_copy"),
    lambda args: args["details"].update(source_link_count=True),
    lambda args: args["details"].update(source_identity="different-object"),
])
def test_signed_but_wrong_recovery_contract_is_refused(tmp_path, monkeypatch, change):
    module, _marker, _destination, _values = _fixture(tmp_path, monkeypatch, change=change)
    before = _authority(module)
    with pytest.raises(recovery.CheckpointRecoveryRefused):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == before


def test_another_pending_action_prevents_recovery(tmp_path, monkeypatch):
    module, _marker, _destination, _values = _fixture(tmp_path, monkeypatch, extra_pending=True)
    before = _authority(module)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="exactly one"):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == before


def test_token_change_and_backup_failure_never_advance_authority(tmp_path, monkeypatch):
    module, _marker, _destination, _values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="changed"):
        recovery.recover_drill_checkpoint(module, expected_token="0" * 64)
    assert _authority(module) == before
    monkeypatch.setattr(recovery, "_backup", lambda *_a: (_ for _ in ()).throw(OSError("fixture backup failure")))
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="backup failed"):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == before


def test_destination_appearing_during_backup_blocks_checkpoint(tmp_path, monkeypatch):
    module, marker, destination, _values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    backup = recovery._backup

    def changed(module, plan):
        directory = backup(module, plan)
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"unrelated destination occupant")
        return directory

    monkeypatch.setattr(recovery, "_backup", changed)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="occupied"):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == before
    assert marker.exists()


def test_live_process_recheck_blocks_apply_without_authority_change(tmp_path, monkeypatch):
    module, _marker, _destination, _values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)

    def running():
        raise ValueError("Stop Angerona before applying checkpoint recovery")

    with pytest.raises(recovery.CheckpointRecoveryRefused, match="Stop Angerona"):
        recovery.recover_drill_checkpoint(module, before_commit=running)
    assert _authority(module) == before


def test_existing_installation_never_enrolls_missing_authority(tmp_path):
    with pytest.raises(FileNotFoundError):
        recovery.existing_installation(tmp_path)
    assert not list(tmp_path.iterdir())


def test_size_budget_precedes_any_hash_scan(tmp_path, monkeypatch):
    module, marker, _destination, _values = _fixture(tmp_path, monkeypatch)
    with marker.open("r+b") as stream:
        stream.truncate(1024 * 1024)
    monkeypatch.setattr(_PinnedFileMove, "sha256", lambda *_a: pytest.fail("Unbounded file hash"))
    before = _authority(module)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="byte budget"):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == before


def test_signed_name_only_marker_cannot_recover(tmp_path, monkeypatch):
    def substitute(args):
        payload = b"ordinary operator content, not an inert catalog marker"
        Path(args["target"]).write_bytes(payload)
        args["details"]["sha256"] = hashlib.sha256(payload).hexdigest()

    module, _marker, _destination, _values = _fixture(tmp_path, monkeypatch, change=substitute)
    before = _authority(module)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="fixed comprehensive"):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == before


def test_signed_original_outside_suite_sandbox_is_refused(tmp_path, monkeypatch):
    def relocate(args):
        old = Path(args["target"])
        outside = old.parent.parent / old.name
        old.rename(outside)
        args["target"] = str(outside)
        args["details"]["original"] = str(outside)

    module, _marker, _destination, _values = _fixture(tmp_path, monkeypatch, change=relocate)
    before = _authority(module)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="location"):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == before


def test_protected_input_changed_during_backup_is_not_overwritten(tmp_path, monkeypatch):
    module, _marker, _destination, _values = _fixture(tmp_path, monkeypatch)
    backup = recovery._backup
    expected = {}

    def changed(module, plan):
        directory = backup(module, plan)
        protected = module.data_root / "secrets.dpapi"
        protected.write_bytes(protected.read_bytes() + b" ")
        expected.update(_authority(module))
        return directory

    monkeypatch.setattr(recovery, "_backup", changed)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="changed"):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == expected


def test_private_backup_acl_failure_blocks_checkpoint(tmp_path, monkeypatch):
    from angerona.core import engine_transport

    module, _marker, _destination, _values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    monkeypatch.setattr(engine_transport, "verify_private", lambda *_a, **_k: (
        _ for _ in ()).throw(engine_transport.EngineError("fixture ACL failure")))
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="backup failed"):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == before


def test_malformed_nondict_journal_receives_typed_refusal(tmp_path, monkeypatch):
    module, _marker, _destination, _values = _fixture(tmp_path, monkeypatch)
    module.receipt_path.write_bytes(b"[]\n")
    before = _authority(module)
    with pytest.raises(JournalIntegrityError, match="malformed"):
        recovery.recover_drill_checkpoint(module)
    assert _authority(module) == before
