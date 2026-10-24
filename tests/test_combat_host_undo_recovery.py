"""Stopped host-undo closure with real HMACs and inert OS/credential providers."""
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import time

import pytest

from angerona.core import combat_checkpoint_recovery as recovery, secure_store
from angerona.core.eventbus import Event, Severity
from angerona.modules.adversary_combat import JournalIntegrityError


def _fixture(tmp_path, monkeypatch):
    (tmp_path / "bus.key").write_text((b"h" * 32).hex(), encoding="ascii")
    protected = tmp_path / "secrets.dpapi"
    protected.write_bytes(b"inert existing protected store")
    values = {"UNRELATED_SECRET": "preserve"}
    monkeypatch.setattr(secure_store, "read_secret_values", lambda names, *_a, **_k: {
        name: values[name] for name in names if name in values
    })

    def write(updates, _root):
        values.update(updates)
        protected.write_text(json.dumps(values), encoding="utf-8")
        return protected

    monkeypatch.setattr(secure_store, "write_secret_map", write)
    module = recovery.existing_installation(tmp_path)
    module._read_journal(strict=True)
    event = Event("Spyware Guard", "inert fixture", Severity.CRITICAL)
    startup = module._action("activate_honeypots", "Smart Deception", event, "startup",
                             reversible=True, details={"module": "Smart Deception"})
    module._journal_intent(startup)
    module._journal_commit(startup)

    def rollback(kind, number, *, incomplete=False):
        exe = str(tmp_path / "owned-inert.exe")
        details = ({"pid": 2468, "create_time": 1234.5, "exe": exe,
                    "rules": ["Angerona-Combat-Program-2468-0123abcd"]}
                   if kind == "isolate_program" else {
                       "rules": [f"Angerona-Combat-Host-{number:010x}-out",
                                 f"Angerona-Combat-Host-{number:010x}-in"],
                       "aar_origin": "inert-fixture", "trigger_digest": "a" * 64,
                   })
        action = module._action(kind, exe if kind == "isolate_program" else "all remote network traffic",
                                event, f"combat-{number:012x}", reversible=True, details=details)
        module._journal_intent(action)
        error = ("program firewall postcondition failed" if kind == "isolate_program"
                 else recovery._HOST_INCOMPLETE)
        orphan = module._append_journal({
            **asdict(action), "record_type": "orphan", "status": "orphaned",
            "orphaned_at": time.time(), "error": error, "rollback_state": "pending",
        })
        undo = {"record_type": "undo_intent", "undo_id": f"undo-{number:016x}",
                "undo_of": action.action_id, "action": kind, "phase_at": time.time(),
                "status": "pending", "error": "", "recovery": True,
                "bound_record_hmac": orphan["record_hmac"]}
        if incomplete:
            with monkeypatch.context() as patch:
                patch.setattr(module, "_advance_recovery_anchor", lambda _: (
                    _ for _ in ()).throw(OSError("inert interrupted undo checkpoint")))
                with pytest.raises(JournalIntegrityError):
                    module._append_journal(undo)
            return
        module._append_journal(undo)
        module._append_journal({**undo, "record_type": "undo_commit", "status": "undone",
                                "phase_at": time.time()})
        module._append_journal({"record_type": "failure", "action_id": action.action_id,
                                "combat_id": action.combat_id, "action": kind,
                                "failed_at": time.time(), "status": "failed",
                                "error": error + "; uncertain mutation rolled back"})

    rollback("isolate_program", 1)
    rollback("isolate_host", 2)
    rollback("isolate_host", 3, incomplete=True)
    monkeypatch.setattr(recovery, "_native_firewall_rule_absent", lambda _: True)
    # No test permits the recovery path to reach any host mutation/reconciliation.
    for method in ("_undo_record", "_run_firewall", "_reconcile_state"):
        monkeypatch.setattr(module, method, lambda *_a, **_k: pytest.fail("host action/rearm invoked"))
    return module, values


def _authority(module):
    return {path: path.read_bytes() for path in (
        module.receipt_path, module.data_root / "secrets.dpapi", module.recovery_witness_path,
        module.data_root / "bus.key")}


def _apply(module, token=None, guard=lambda: None):
    token = token or recovery.inspect_host_undo_checkpoint(module)["review_token"]
    return recovery.recover_host_undo_checkpoint(module, expected_token=token, before_commit=guard)


def _rewrite(module, mutate):
    records = [json.loads(line) for line in module.receipt_path.read_bytes().splitlines()]
    mutate(records)
    previous, rebound = "0" * 64, {}
    for index, record in enumerate(records, 1):
        old_hmac = record["record_hmac"]
        if record.get("bound_record_hmac") in rebound:
            record["bound_record_hmac"] = rebound[record["bound_record_hmac"]]
        record.update(sequence=index, previous_hmac=previous)
        record["record_hmac"] = module._record_hmac({k: v for k, v in record.items() if k != "record_hmac"})
        previous = rebound[old_hmac] = record["record_hmac"]
    module.receipt_path.write_bytes(b"".join(module._canonical_record(r) + b"\n" for r in records))


def test_full_history_closure_preserves_prefix_keys_backups_and_never_rearms(tmp_path, monkeypatch):
    module, values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    with pytest.raises(JournalIntegrityError, match="incomplete anchor transaction"):
        module._read_journal(strict=True)
    with pytest.raises(recovery.CheckpointRecoveryRefused):
        recovery.inspect_rollback_checkpoint(module)
    report = recovery.inspect_host_undo_checkpoint(module)
    assert report["journal_records"] == 15 and report["checkpoint_sequence"] == 14
    assert _authority(module) == before
    guards = []
    result = _apply(module, report["review_token"], lambda: guards.append(True))
    assert len(guards) == 5
    assert result["recovered"] and result["checkpoint_sequence"] == result["witness_sequence"] == 17
    assert result["pending_actions"] == result["pending_undos"] == result["host_actions_executed"] == 0
    assert result["rearmed"] is False and module._response_initialized is False
    raw = module.receipt_path.read_bytes()
    assert raw.startswith(before[module.receipt_path]) and len(raw.splitlines()) == 17
    records, legacy = module._read_journal(strict=True)
    assert not legacy and module._pending_recovery_records() == {}
    assert records[-2]["record_type"] == "undo_commit" and records[-2]["undo_id"] == records[-3]["undo_id"]
    assert records[-1]["record_type"] == "failure" and records[-1]["error"] == recovery._HOST_NO_EFFECT
    assert values["UNRELATED_SECRET"] == "preserve"
    assert (tmp_path / "bus.key").read_bytes() == before[tmp_path / "bus.key"]
    backup = Path(result["backup_directory"])
    for path, original in before.items():
        if path.name == "bus.key":
            assert not (backup / path.name).exists()
        else:
            assert (backup / path.name).read_bytes() == original
    with pytest.raises(recovery.CheckpointRecoveryRefused):
        recovery.inspect_host_undo_checkpoint(module)
    fresh = recovery.existing_installation(tmp_path)
    for method in ("_intent_effect_present", "_undo_record", "_run_firewall", "_firewall_rule_exists"):
        monkeypatch.setattr(fresh, method, lambda *_a, **_k: pytest.fail("completed closure attempted host work"))
    assert fresh._reconcile_state() is True
    assert fresh._mutation_blocked is False and fresh._response_initialized is False


@pytest.mark.parametrize("mutation", [
    lambda r: r[-1].update(undo_of="act-ffffffffffffffff"),
    lambda r: r[-1].update(recovery=False),
    lambda r: r[-1].update(error="unavailable"),
    lambda r: r[-1].update(undo_id=r[4]["undo_id"]),
    lambda r: r[-1].update(phase_at=True),
    lambda r: r[-1].update(phase_at=time.time() + 86400),
    lambda r: r[-1].update(bound_record_hmac="0" * 64),
    lambda r: r[-2].update(error="different failure"),
    lambda r: r[-2].update(rollback_state="unknown"),
    lambda r: r[-2].update(mutation_started=True),
    lambda r: r[-2]["details"].update(aar_origin="unbound origin"),
    lambda r: r[-3].update(reversible=False),
    lambda r: r[-3].update(target="other host target"),
    lambda r: r[-3].update(applied_at=True),
    lambda r: r[-3].update(trigger_ts="yesterday"),
    lambda r: r[-3].update(trigger_module={}),
    lambda r: r[-3]["details"].update(rules=["unrelated-out", "unrelated-in"]),
    lambda r: r[-3]["details"].update(rules=["Angerona-Combat-Host-0000000003-out"] * 2),
    lambda r: r[-3]["details"].update(rules=["Angerona-Combat-Host-0000000003-out", "Angerona-Combat-Host-0000000004-in"]),
    lambda r: r[0].update(journal_version=True),
    lambda r: r[0].update(action="terminate_process"),
    lambda r: r[1].update(action_id="act-ffffffffffffffff"),
    lambda r: r[1].update(committed_at=True),
    lambda r: r.insert(2, dict(r[0])),
])
def test_signed_semantic_confusion_is_refused_without_writes(tmp_path, monkeypatch, mutation):
    module, _ = _fixture(tmp_path, monkeypatch)
    _rewrite(module, mutation)
    before = _authority(module)
    with pytest.raises(recovery.CheckpointRecoveryRefused):
        recovery._host_undo_records(module, before[module.receipt_path])
    with pytest.raises(recovery.CheckpointRecoveryRefused):
        recovery.inspect_host_undo_checkpoint(module)
    assert _authority(module) == before


@pytest.mark.parametrize("observation", [False, None, 0, 1, "absent"])
def test_both_native_observations_must_be_exact_true_before_any_write(tmp_path, monkeypatch, observation):
    module, _ = _fixture(tmp_path, monkeypatch)
    token = recovery.inspect_host_undo_checkpoint(module)["review_token"]
    queries = []

    def query(rule):
        queries.append(rule)
        return True if rule.endswith("-out") else observation

    monkeypatch.setattr(recovery, "_native_firewall_rule_absent", query)
    before = _authority(module)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="natively absent"):
        _apply(module, token)
    assert len(queries) == 2 and _authority(module) == before
    assert not list(tmp_path.glob("combat-host-undo-recovery-*"))


@pytest.mark.parametrize("changed", ["key", "protected", "witness", "partial", "hardlink"])
def test_stale_token_or_unsafe_input_never_advances(tmp_path, monkeypatch, changed):
    module, _ = _fixture(tmp_path, monkeypatch)
    token = recovery.inspect_host_undo_checkpoint(module)["review_token"]
    if changed == "key":
        (tmp_path / "bus.key").write_text((b"x" * 32).hex(), encoding="ascii")
    elif changed == "protected":
        (tmp_path / "secrets.dpapi").write_bytes(b"new protected generation")
    elif changed == "witness":
        module.recovery_witness_path.write_bytes(b"{}")
    elif changed == "partial":
        module.receipt_path.write_bytes(module.receipt_path.read_bytes().rstrip(b"\n"))
    else:
        os.link(module.receipt_path, tmp_path / "alias.jsonl")
    before = _authority(module)
    with pytest.raises((JournalIntegrityError, OSError, ValueError)):
        _apply(module, token)
    assert _authority(module) == before


@pytest.mark.parametrize("stage", ["backup", "protected", "journal", "native", "guard"])
def test_final_prewrite_boundary_is_compare_and_swap(tmp_path, monkeypatch, stage):
    module, _ = _fixture(tmp_path, monkeypatch)
    token = recovery.inspect_host_undo_checkpoint(module)["review_token"]
    original_backup = recovery._backup_host_undo
    expected = _authority(module)

    def backup(current, plan):
        if stage == "backup":
            raise OSError("inert backup failure")
        directory = original_backup(current, plan)
        if stage == "protected":
            (tmp_path / "secrets.dpapi").write_bytes(b"concurrent protected generation")
        elif stage == "journal":
            current.receipt_path.write_bytes(current.receipt_path.read_bytes() + b" ")
        elif stage == "native":
            monkeypatch.setattr(recovery, "_native_firewall_rule_absent", lambda _: False)
        expected.update(_authority(current))
        return directory

    calls = []

    def guard():
        calls.append(True)
        if stage == "guard" and len(calls) == 2:
            raise ValueError("new application generation detected")

    monkeypatch.setattr(recovery, "_backup_host_undo", backup)
    with pytest.raises((JournalIntegrityError, OSError, ValueError)):
        _apply(module, token, guard)
    assert _authority(module) == expected


@pytest.mark.parametrize("boundary,observation", [(3, False), (3, None), (4, False), (4, None), (5, False), (5, None)])
def test_rule_reappearance_or_unknown_during_checkpoint_advances_stays_held(
    tmp_path, monkeypatch, boundary, observation,
):
    module, _ = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    token = recovery.inspect_host_undo_checkpoint(module)["review_token"]
    calls = []

    def query(rule):
        calls.append(rule)
        return observation if (len(calls) + 1) // 2 >= boundary else True

    monkeypatch.setattr(recovery, "_native_firewall_rule_absent", query)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="natively absent"):
        _apply(module, token)
    assert module.receipt_path.read_bytes().startswith(before[module.receipt_path])
    assert len(module.receipt_path.read_bytes().splitlines()) == 17
    anchor = module._validated_recovery_anchor(module._read_recovery_anchor_value())
    assert anchor["last_journal_sequence"] == 14 + boundary - 3
    fresh = recovery.existing_installation(tmp_path)
    for method in ("_intent_effect_present", "_undo_record", "_run_firewall"):
        monkeypatch.setattr(fresh, method, lambda *_a, **_k: pytest.fail("host action after held recovery"))
    assert fresh._reconcile_state() is False and fresh._mutation_blocked is True


@pytest.mark.parametrize("stage", [
    "partial-undo", "partial-failure", "batch-fsynced", "anchor-witness",
    "checkpoint-391", "undo-checkpoint", "checkpoint-392", "failure-witness",
])
def test_interrupted_writes_retain_evidence_and_refuse_generic_retry(tmp_path, monkeypatch, stage):
    module, _ = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    token = recovery.inspect_host_undo_checkpoint(module)["review_token"]
    original_append = module._append_pinned_journal_bytes
    original_witness, original_advance = module._write_recovery_witness, module._advance_recovery_anchor
    witness_count, advance_count = [], []

    def witness(anchor):
        witness_count.append(True)
        if ((stage == "anchor-witness" and len(witness_count) == 1)
                or (stage == "undo-checkpoint" and len(witness_count) == 2)
                or (stage == "failure-witness" and len(witness_count) == 3)):
            raise OSError("inert witness boundary failure")
        return original_witness(anchor)

    def append(payload):
        if stage in {"partial-undo", "partial-failure", "batch-fsynced"}:
            lines = payload.splitlines(keepends=True)
            partial = (lines[0][:len(lines[0]) // 2] if stage == "partial-undo" else
                       lines[0] + lines[1][:len(lines[1]) // 2] if stage == "partial-failure" else payload)
            original_append(partial)
            raise OSError("inert append boundary failure")
        return original_append(payload)

    def advance(record):
        advance_count.append(True)
        original_advance(record)
        if ((stage == "checkpoint-391" and len(advance_count) == 1)
                or (stage == "checkpoint-392" and len(advance_count) == 2)):
            raise OSError("inert completed checkpoint interruption")

    monkeypatch.setattr(module, "_write_recovery_witness", witness)
    monkeypatch.setattr(module, "_append_pinned_journal_bytes", append)
    monkeypatch.setattr(module, "_advance_recovery_anchor", advance)
    with pytest.raises((JournalIntegrityError, OSError)):
        _apply(module, token)
    assert module.receipt_path.read_bytes().startswith(before[module.receipt_path])
    assert (tmp_path / "bus.key").read_bytes() == before[tmp_path / "bus.key"]
    assert module._response_initialized is False
    fresh = recovery.existing_installation(tmp_path)
    with pytest.raises(JournalIntegrityError):
        recovery.inspect_host_undo_checkpoint(fresh)
    with pytest.raises(JournalIntegrityError):
        recovery.inspect_rollback_checkpoint(fresh)
    host_attempts = []
    for method in ("_intent_effect_present", "_undo_record", "_run_firewall"):
        monkeypatch.setattr(fresh, method, lambda *_a, **_k: host_attempts.append(True))
    assert fresh._reconcile_state() is False
    assert fresh._mutation_blocked is True and fresh._response_initialized is False
    assert not host_attempts
    backups = list(tmp_path.glob("combat-host-undo-recovery-*"))
    assert len(backups) == 1
    for path, original in before.items():
        if path.name != "bus.key":
            assert (backups[0] / path.name).read_bytes() == original


def test_capacity_and_reviewed_token_guard_are_required_before_first_write(tmp_path, monkeypatch):
    from angerona.modules import adversary_combat

    module, _ = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    for token, guard in (("", lambda: None), ("0" * 64, None), ("0" * 64, lambda: None)):
        with pytest.raises(recovery.CheckpointRecoveryRefused):
            recovery.recover_host_undo_checkpoint(module, expected_token=token, before_commit=guard)
        assert _authority(module) == before
    monkeypatch.setattr(adversary_combat, "_MAX_JOURNAL_BYTES", len(before[module.receipt_path])
                        + 2 * (adversary_combat._MAX_JOURNAL_LINE_BYTES + 1) - 1)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="closure capacity"):
        recovery.inspect_host_undo_checkpoint(module)
    assert _authority(module) == before


def test_cli_defaults_read_only_and_blocks_standalone_blackbox(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace
    from tools import recover_combat_host_undo as cli
    import psutil

    module, _ = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    monkeypatch.setattr(cli, "existing_installation", lambda _: module)
    monkeypatch.setattr(cli, "_require_core_stopped", lambda: None)
    monkeypatch.setattr(psutil, "process_iter", lambda _: [])
    monkeypatch.setattr("sys.argv", ["recover", "--data-root", str(tmp_path)])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["eligible"] is True
    assert _authority(module) == before
    process = SimpleNamespace(pid=123, info={"name": "python.exe"},
                              cmdline=lambda: ["python.exe", r"C:\source\blackbox_recorder.py"])
    monkeypatch.setattr(psutil, "process_iter", lambda _: [process])
    monkeypatch.setattr("sys.argv", ["recover", "--data-root", str(tmp_path), "--apply", "--expected-token", "0" * 64])
    assert cli.main() == 1
    assert "Stop Black Box" in json.loads(capsys.readouterr().out)["error"]
    assert _authority(module) == before
