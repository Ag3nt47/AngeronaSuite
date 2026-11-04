"""Real signed AAR and SQLite receipts; only registry I/O is an inert fixture."""
from __future__ import annotations

import copy
import json
import sys

import pytest

from angerona.core import patch_center, patch_controls, remediation_log, report_attest
from angerona.modules import remediation_actions as actions
from angerona.modules.posture_hardening import PostureHardening
from angerona.shark import aar_report


class InertRegistry:
    HKEY_LOCAL_MACHINE = "fixture-HKLM"
    KEY_READ = 1
    KEY_SET_VALUE = 2
    REG_DWORD = 4

    def __init__(self):
        self.values, self.writes = {}, []

    def OpenKey(self, _hive, subkey, _reserved, _access):
        return subkey

    CreateKeyEx = OpenKey

    def QueryValueEx(self, key, name):
        if (key, name) not in self.values:
            raise FileNotFoundError(name)
        return self.values[key, name]

    def SetValueEx(self, key, name, _reserved, value_type, value):
        self.writes.append((key, name, value, value_type))
        self.values[key, name] = value, value_type

    def DeleteValue(self, key, name):
        self.writes.append((key, name, None, None))
        self.values.pop((key, name), None)

    def CloseKey(self, _key):
        return


def _report(root, run_id="patch-inert-1", technique="T1112"):
    history = {"run_id": run_id, "kind": "shark", "status": "completed"}
    rows = [aar_report.StepVerdict("Registry fixture", technique + " inert fixture", "No native attack", 100.0, True)]
    return aar_report._write_report(root, history, rows, aar_report.render(history, rows))


@pytest.fixture
def context(tmp_path, monkeypatch):
    key = tmp_path / "bus.key"
    key.write_text((b"t" * 32).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    monkeypatch.setattr(PostureHardening, "_log_attempt", lambda *_a, **_kw: None)
    registry = InertRegistry()
    monkeypatch.setitem(sys.modules, "winreg", registry)
    # Portability adapter removes only the host-platform check. The real fixed
    # catalog/classifier, native transaction methods and durable ledger remain.
    monkeypatch.setattr(actions.RegistryHardeningAction, "matches", lambda self, weakness:
        len(self._candidates(weakness)) == 1
        and self._candidates(weakness)[0].control_id != "windows.process_injection.mitigation")
    authority = {"allowed": True}
    def allowed():
        return authority["allowed"], "Inert installed-authority fixture" if authority["allowed"] else "Source Observe is held"
    monkeypatch.setattr(patch_center, "protect_authority", allowed)
    def require():
        if not authority["allowed"]:
            raise PermissionError("Source Observe is held")
    monkeypatch.setattr(patch_controls, "_require_authority", require)
    def prohibited(*_a, **_kw):
        raise AssertionError("No host subprocess is permitted in this fixture")
    monkeypatch.setattr(actions, "run_hidden", prohibited)
    store = remediation_log.RemediationLog(tmp_path / "flight-recorder.db")
    monkeypatch.setattr(remediation_log, "_SINGLETON", store)
    posture = PostureHardening(data_dir=tmp_path)
    monkeypatch.setattr(posture, "emit", lambda *_a, **_kw: None)
    handoff = _report(tmp_path)
    service = patch_center.PatchReviewService(posture, handoff)
    control = actions.RegistryHardeningAction()._candidates({"mitre_id": "T1112"})[0]
    identity = control.subkey, control.value_name
    registry.values[identity] = (0, 4)
    try:
        yield posture, service, registry, identity, authority, store
    finally:
        store.close()


def _plan(service):
    snapshot = service.snapshot()
    gap = snapshot["gaps"][0]
    return service.build_plan(gap["gap_id"], gap["controls"][0]["control_id"])


def _apply(service):
    plan = _plan(service)
    return service.apply(plan["plan_id"], approved=True)


def _undo(service, attempt_id):
    review = service.review_rollback(attempt_id)
    if review.get("ok") is not True:
        return review
    return service.rollback(attempt_id, approved=True, rollback_plan_id=review["rollback_plan_id"])


def _retain_recovery_reason(posture, store, recovered, attempt_id, basename):
    attempt = next((row for row in posture.patch_memory_snapshot()["attempts"]
                    if row.get("attempt_id") == attempt_id), {})
    identifiers = {value for value in (attempt.get("transaction_id"),
        attempt.get("rollback_transaction_id"), recovered.get("transaction_id")) if type(value) is int}
    diagnostic = {"recovered": recovered, "attempt": attempt,
        "transactions": {str(identifier): store.transaction(identifier) for identifier in sorted(identifiers)}}
    encoded = json.dumps(diagnostic, sort_keys=True, indent=2, allow_nan=False)
    if len(encoded.encode("utf-8")) > 64 * 1024:
        raise AssertionError("Recovery fixture diagnostic exceeded its bounded budget")
    path = posture.data_dir / basename
    path.write_text(encoded, encoding="utf-8")
    return f"Exact recovery diagnostic: {path}\n" + encoded


def test_one_reviewed_control_produces_native_readback_and_bound_committed_receipt(context):
    posture, service, registry, identity, _, store = context
    posture.record_weakness("T1112", "Practice does not close this host finding", "High")
    plan = _plan(service)
    assert registry.writes == []
    result = service.apply(plan["plan_id"], approved=True)
    assert result["ok"] is True and result["state"] == "applied-verified"
    record, attempt = result["record"], result["attempt"]
    proof = record["proof_receipt"]
    assert store.verify_committed_application(record["transaction_id"], proof["receipt_hash"], proof["receipt_id"],
        expected_mitre="T1112", expected_action="registry_hardening") is True
    assert record["patch_binding"] == {key: attempt[key]
        for key in ("run_id", "report_sha256", "gap_id", "plan_sha256", "control_id")}
    assert registry.values[identity] == (1, 4) and len(registry.writes) == 1
    assert result["gap_closed"] is False
    assert posture.weaknesses()[0]["status"] == "VULNERABLE"
    assert posture.patch_memory_snapshot()["gaps"][0]["status"] == "OPEN"
    assert service.apply(plan["plan_id"], approved=True)["ok"] is False


@pytest.mark.parametrize("approved", [False, None, 1, "true"])
def test_apply_requires_literal_explicit_review_approval(context, approved):
    _, service, registry, _, _, store = context
    result = service.apply(_plan(service)["plan_id"], approved=approved)
    assert result["ok"] is False and not registry.writes and not store.unresolved_transactions()


def test_source_observe_authority_holds_even_a_valid_reviewed_plan(context):
    _, service, registry, _, authority, _ = context
    plan = _plan(service)
    authority["allowed"] = False
    result = service.apply(plan["plan_id"], approved=True)
    assert result["state"] == "held" and "Source Observe" in result["reason"] and not registry.writes


def test_authority_revocation_at_native_dispatch_barrier_prevents_effect(context, monkeypatch):
    _, service, registry, _, authority, _ = context
    plan = _plan(service)
    original = actions.RegistryHardeningAction.begin_transaction
    def begin(action, weakness, quarantine):
        record = original(action, weakness, quarantine)
        authority["allowed"] = False
        return record
    monkeypatch.setattr(actions.RegistryHardeningAction, "begin_transaction", begin)
    result = service.apply(plan["plan_id"], approved=True)
    assert result["ok"] is False and not registry.writes


def test_native_state_change_after_review_is_held_without_overwriting_external_value(context):
    _, service, registry, identity, _, _ = context
    plan = _plan(service)
    registry.values[identity] = (7, 4)
    result = service.apply(plan["plan_id"], approved=True)
    assert result["ok"] is False and registry.values[identity] == (7, 4) and not registry.writes


def test_newer_current_report_invalidates_old_review_and_dispatch(context):
    posture, service, registry, _, _, _ = context
    plan = _plan(service)
    _report(posture.data_dir, "patch-inert-new-generation")
    result = service.apply(plan["plan_id"], approved=True)
    assert result["ok"] is False and not registry.writes


def test_expired_review_is_consumed_without_native_write(context):
    _, service, registry, _, _, _ = context
    plan = _plan(service)
    service._plans[plan["plan_id"]]["created"] -= 301
    result = service.apply(plan["plan_id"], approved=True)
    assert result["ok"] is False and not registry.writes


def test_genuine_incomplete_writer_handoff_is_read_only_even_with_host_authority(context):
    posture, _, registry, _, _, _ = context
    history = {"run_id": "incomplete-patch-fixture", "kind": "shark", "status": "incomplete"}
    rows = [aar_report.StepVerdict("Unfinished fixture", "T1112 fixture", "No host action", 100.0, True)]
    handoff = aar_report._write_report(posture.data_dir, history, rows, aar_report.render(history, rows))
    assert aar_report.verified_aar_handoff_text(handoff)
    service = patch_center.PatchReviewService(posture, handoff)
    assert service.snapshot()["report_state"] == "diagnostic"
    with pytest.raises(ValueError, match="Diagnostic"):
        service.build_plan("a" * 64, "windows.registry.base_object_auditing")
    assert not registry.writes


def test_mutated_immutable_handoff_cannot_supply_patchable_gaps(context):
    from dataclasses import replace
    posture, service, registry, _, _, _ = context
    changed = replace(service.handoff, report_sha256="f" * 64)
    forged = patch_center.PatchReviewService(posture, changed)
    assert forged.snapshot()["gaps"] == []
    with pytest.raises(ValueError):
        forged.build_plan("a" * 64, "windows.registry.base_object_auditing")
    assert not registry.writes


def test_exact_selected_gap_and_supported_control_are_required(context):
    _, service, registry, _, _, _ = context
    snapshot = service.snapshot()
    with pytest.raises(ValueError, match="gap"):
        service.build_plan("f" * 64, "windows.registry.base_object_auditing")
    with pytest.raises(ValueError):
        service.build_plan(snapshot["gaps"][0]["gap_id"], "windows.wdigest.disable_cleartext")
    assert not registry.writes


def test_fresh_retest_reports_regression_and_does_not_close_gap(context):
    posture, service, registry, identity, _, _ = context
    applied = _apply(service)
    attempt_id = applied["attempt"]["attempt_id"]
    assert service.retest(attempt_id)["state"] == "postcondition-current"
    registry.values[identity] = (3, 4)
    regressed = service.retest(attempt_id)
    assert regressed["state"] == "postcondition-regressed"
    assert regressed["retained_commit_verified"] is True and regressed["native_postcondition_current"] is False
    assert regressed["gap_closed"] is False and posture.patch_memory_snapshot()["gaps"][0]["status"] == "OPEN"


@pytest.mark.parametrize("prior", ["value", "missing"])
def test_manual_undo_restores_exact_retained_prior_with_its_own_committed_inverse(context, prior):
    posture, service, registry, identity, _, store = context
    if prior == "missing":
        registry.values.pop(identity)
    original = _apply(service)
    undone = _undo(service, original["attempt"]["attempt_id"])
    assert undone["ok"] is True and undone["state"] == "rollback-applied"
    assert registry.values.get(identity) == ((0, 4) if prior == "value" else None)
    record, proof = undone["record"], undone["record"]["proof_receipt"]
    assert store.verify_committed_application(record["transaction_id"], proof["receipt_hash"], proof["receipt_id"],
        expected_mitre="T1112", expected_action="registry_control_rollback") is True
    assert record["original_transaction_id"] == original["record"]["transaction_id"]
    assert undone["gap_closed"] is False
    assert posture.patch_memory_snapshot()["attempts"][0]["state"] == "rolled-back"


def test_manual_undo_refuses_external_state_conflict(context):
    _, service, registry, identity, _, _ = context
    original = _apply(service)
    registry.values[identity] = (9, 4)
    writes = len(registry.writes)
    result = _undo(service, original["attempt"]["attempt_id"])
    assert result["ok"] is False and registry.values[identity] == (9, 4) and len(registry.writes) == writes


def test_manual_undo_requires_its_own_concrete_review_and_is_single_use(context):
    _, service, registry, identity, _, _ = context
    original = _apply(service)
    attempt_id = original["attempt"]["attempt_id"]
    assert service.rollback(attempt_id, approved=True)["ok"] is False
    review = service.review_rollback(attempt_id)
    assert review["before"] == 1 and review["restore_present"] is True and review["restore_value"] == 0
    assert registry.values[identity] == (1, 4)
    assert service.rollback(attempt_id, approved=True, rollback_plan_id=review["rollback_plan_id"])["ok"] is True
    writes = len(registry.writes)
    assert service.rollback(attempt_id, approved=True, rollback_plan_id=review["rollback_plan_id"])["ok"] is False
    assert len(registry.writes) == writes


def test_native_fact_without_terminal_commit_is_not_patched_and_has_exact_recovery(context):
    posture, service, registry, identity, _, store = context
    store._db.executescript("""
      CREATE TRIGGER fail_patch_receipt BEFORE INSERT ON remediation_log
      WHEN NEW.trigger = 'AngeronaPatch' AND NEW.outcome = 'applied'
      BEGIN SELECT RAISE(ABORT, 'inert terminal failure'); END;
    """)
    result = _apply(service)
    attempt = result["attempt"]
    assert result["ok"] is False and registry.values[identity] == (1, 4)
    assert attempt["native_postcondition"] is True and attempt["recovery_required"] is True
    assert store.transaction(attempt["transaction_id"])["state"] == "RECOVERY_REQUIRED"
    from angerona.core.patch_recovery import verify_recovery_handoff
    assert verify_recovery_handoff(store, attempt["transaction_id"], attempt["recovery_handoff_receipt"],
        expected_mitre="T1112", expected_action="registry_hardening") is True
    retained_record = store.transaction(attempt["transaction_id"])["record"]
    assert retained_record["native_postcondition_before_commit"] is True
    assert retained_record["verified"] is False and retained_record["failed_terminal_commit"]["result"] == "applied"
    assert posture.patch_memory_snapshot()["gaps"][0]["status"] == "OPEN"
    store._db.execute("DROP TRIGGER fail_patch_receipt")
    store._db.commit()
    recovered = service.recover(attempt["attempt_id"], approved=True)
    assert recovered["ok"] is True and recovered["state"] == "ROLLED_BACK", _retain_recovery_reason(
        posture, store, recovered, attempt["attempt_id"], "interrupted-commit-recovery.json")
    assert registry.values[identity] == (0, 4) and not store.unresolved_transactions()


def test_interrupted_inverse_compensates_to_pre_undo_patch_and_never_claims_undo(context):
    posture, service, registry, identity, _, store = context
    original = _apply(service)
    store._db.executescript("""
      CREATE TRIGGER fail_undo_receipt BEFORE INSERT ON remediation_log
      WHEN NEW.trigger = 'AngeronaPatchRollback' AND NEW.outcome = 'applied'
      BEGIN SELECT RAISE(ABORT, 'inert inverse terminal failure'); END;
    """)
    result = _undo(service, original["attempt"]["attempt_id"])
    assert result["ok"] is False and result["state"] == "recovery-required"
    assert registry.values[identity] == (0, 4)
    attempt = posture.patch_memory_snapshot()["attempts"][0]
    assert attempt["rollback_recovery_required"] is True and type(attempt["rollback_transaction_id"]) is int
    from angerona.core.patch_recovery import verify_recovery_handoff
    assert store.transaction(attempt["rollback_transaction_id"])["state"] == "RECOVERY_REQUIRED"
    assert verify_recovery_handoff(store, attempt["rollback_transaction_id"], attempt["rollback_recovery_handoff_receipt"],
        expected_mitre="T1112", expected_action="registry_control_rollback") is True
    store._db.execute("DROP TRIGGER fail_undo_receipt")
    store._db.commit()
    recovered = service.recover(attempt["attempt_id"], approved=True)
    assert recovered["ok"] is True and recovered["state"] == "ROLLED_BACK", _retain_recovery_reason(
        posture, store, recovered, attempt["attempt_id"], "interrupted-inverse-recovery.json")
    assert registry.values[identity] == (1, 4) and not store.unresolved_transactions()
    retained = posture.patch_memory_snapshot()["attempts"][0]
    assert retained["state"] == "applied-verified" and retained["watch_state"] == "failed-undo-compensated"


@pytest.mark.parametrize("phase", ["application", "inverse", "compensation"])
def test_dual_terminal_and_handoff_fault_retains_exact_owner_without_unproved_reconciliation(context, phase, monkeypatch):
    posture, service, registry, identity, _, store = context
    original = _apply(service) if phase == "inverse" else None
    if phase == "compensation":
        monkeypatch.setattr(actions.RegistryHardeningAction, "verify", lambda *_args: False)
    trigger = "AngeronaPatchRollback" if phase == "inverse" else "AngeronaPatch"
    # trigger comes only from the fixed test enum, never a report or user text.
    store._db.executescript("""
      CREATE TRIGGER fail_both_terminal_receipts BEFORE INSERT ON remediation_log
      WHEN NEW.trigger = '%s' AND NEW.outcome IN ('applied','rolled_back','recovery_required')
      BEGIN SELECT RAISE(ABORT, 'inert dual commit fault'); END;
    """ % trigger)
    result = (_undo(service, original["attempt"]["attempt_id"]) if original else _apply(service))
    assert result["ok"] is False
    attempt = posture.patch_memory_snapshot()["attempts"][0]
    transaction_id = attempt.get("rollback_transaction_id") if original else attempt["transaction_id"]
    transaction = store.transaction(transaction_id)
    assert transaction["state"] == "MUTATING" and transaction["transaction_id"] == transaction_id
    assert registry.values[identity] == ((1, 4) if phase == "application" else (0, 4))
    record = result["record"]
    assert record["native_postcondition_before_commit"] is (phase != "compensation")
    assert record["recovery_handoff_verified"] is False
    assert "inert dual commit fault" in record["recovery_handoff_error"]
    writes = len(registry.writes)
    recovered = service.recover(attempt["attempt_id"], approved=True)
    assert recovered["ok"] is False and recovered["state"] == "held", _retain_recovery_reason(
        posture, store, recovered, attempt["attempt_id"], "dual-fault-held-recovery.json")
    assert store.transaction(transaction_id)["state"] == "MUTATING" and len(registry.writes) == writes
    assert posture.patch_memory_snapshot()["gaps"][0]["status"] == "OPEN"


def test_recovery_handoff_reader_rejects_wrong_identity_metadata_and_uncommitted_projection(context):
    _, service, _, _, _, store = context
    from angerona.core.patch_recovery import verify_recovery_handoff
    store._db.executescript("""
      CREATE TRIGGER fail_initial_applied BEFORE INSERT ON remediation_log
      WHEN NEW.trigger='AngeronaPatch' AND NEW.outcome='applied'
      BEGIN SELECT RAISE(ABORT, 'inert applied-only fault'); END;
    """)
    result = _apply(service)
    attempt = result["attempt"]
    proof = attempt["recovery_handoff_receipt"]
    verify = lambda **changes: verify_recovery_handoff(store, changes.get("transaction_id", attempt["transaction_id"]),
        changes.get("proof", proof), expected_mitre=changes.get("mitre", "T1112"),
        expected_action=changes.get("action", "registry_hardening"))
    assert verify() is True
    assert verify(transaction_id=True) is False and verify(mitre="T1055") is False
    assert verify(action="registry_control_rollback") is False
    assert verify(proof={**proof, "receipt_hash": "0" * 64}) is False
    assert store.verify_committed_application(attempt["transaction_id"], proof["receipt_hash"], proof["receipt_id"],
        expected_mitre="T1112", expected_action="registry_hardening") is False
    store._db.execute("BEGIN")
    assert verify() is False
    store._db.rollback()
    store._db.execute("UPDATE remediation_transactions SET trigger='unbound-trigger' WHERE id=?", (attempt["transaction_id"],))
    store._db.commit()
    assert verify() is False


def test_failed_rollback_terminal_commit_recovers_from_freshly_verified_prior_without_second_write(context, monkeypatch):
    _, service, registry, identity, _, store = context
    real_verify = actions.RegistryHardeningAction.verify
    monkeypatch.setattr(actions.RegistryHardeningAction, "verify", lambda *_args: False)
    store._db.executescript("""
      CREATE TRIGGER fail_rolled_back_terminal BEFORE INSERT ON remediation_log
      WHEN NEW.trigger='AngeronaPatch' AND NEW.outcome='rolled_back'
      BEGIN SELECT RAISE(ABORT, 'inert rollback terminal fault'); END;
    """)
    result = _apply(service)
    assert result["ok"] is False and registry.values[identity] == (0, 4)
    attempt = result["attempt"]
    assert store.transaction(attempt["transaction_id"])["state"] == "RECOVERY_REQUIRED"
    monkeypatch.setattr(actions.RegistryHardeningAction, "verify", real_verify)
    writes = len(registry.writes)
    recovered = service.recover(attempt["attempt_id"], approved=True)
    assert recovered["ok"] is True and recovered["state"] == "ROLLED_BACK", recovered
    assert len(registry.writes) == writes and registry.values[identity] == (0, 4)
    retained = store.transaction(attempt["transaction_id"])["record"]
    assert retained["rollback"]["changed"] is False and retained["rollback"]["retained_prior_already_verified"] is True


def test_recovery_refuses_external_native_conflict_and_preserves_reconciliation_hold(context):
    posture, service, registry, identity, _, store = context
    store._db.executescript("""
      CREATE TRIGGER fail_applied_for_conflict BEFORE INSERT ON remediation_log
      WHEN NEW.trigger='AngeronaPatch' AND NEW.outcome='applied'
      BEGIN SELECT RAISE(ABORT, 'inert conflict handoff fixture'); END;
    """)
    result = _apply(service)
    attempt = result["attempt"]
    registry.values[identity] = (7, 4)
    writes = len(registry.writes)
    recovered = service.recover(attempt["attempt_id"], approved=True)
    assert recovered["ok"] is False and recovered["state"] == "RECONCILING", recovered
    assert registry.values[identity] == (7, 4) and len(registry.writes) == writes
    assert store.transaction(attempt["transaction_id"])["recovery_active"] is True
    assert posture.patch_memory_snapshot()["gaps"][0]["status"] == "OPEN"


def test_same_native_prior_value_cannot_authorize_recovery_across_mismatched_record_identity(context):
    _, service, registry, _, _, store = context
    store._db.executescript("""
      CREATE TRIGGER fail_applied_for_identity BEFORE INSERT ON remediation_log
      WHEN NEW.trigger='AngeronaPatch' AND NEW.outcome='applied'
      BEGIN SELECT RAISE(ABORT, 'inert identity handoff fixture'); END;
    """)
    result = _apply(service)
    attempt = result["attempt"]
    transaction = store.transaction(attempt["transaction_id"])
    changed = copy.deepcopy(transaction["record"])
    changed["subkey"] = r"SOFTWARE\FixtureDifferentObject"
    registry.values[changed["subkey"], changed["name"]] = (changed["prior"], changed["prior_type"])
    store._db.execute("UPDATE remediation_transactions SET record_json=? WHERE id=?",
        (json.dumps(changed), attempt["transaction_id"]))
    store._db.commit()
    writes = len(registry.writes)
    recovered = service.recover(attempt["attempt_id"], approved=True)
    assert recovered["ok"] is False and recovered["state"] == "held", recovered
    assert store.transaction(attempt["transaction_id"])["state"] == "RECOVERY_REQUIRED"
    assert len(registry.writes) == writes


def test_attempt_index_failure_before_effect_blocks_dispatch(context, monkeypatch):
    posture, service, registry, _, _, _ = context
    plan = _plan(service)
    monkeypatch.setattr(posture._patch_memory, "record_attempt", lambda _row: {"stored": False})
    result = service.apply(plan["plan_id"], approved=True)
    assert result["state"] == "held" and not registry.writes


def test_attempt_index_failure_after_effect_preserves_genuine_native_and_journal_proof(context, monkeypatch):
    posture, service, _, _, _, store = context
    real = posture._patch_memory.record_attempt
    count = []
    def record(row):
        count.append(row["state"])
        if len(count) > 1:
            raise OSError("inert advisory index failure")
        return real(row)
    monkeypatch.setattr(posture._patch_memory, "record_attempt", record)
    result = _apply(service)
    assert result["ok"] is True and result["memory"]["stored"] is False
    proof = result["record"]["proof_receipt"]
    assert store.verify_committed_application(result["record"]["transaction_id"], proof["receipt_hash"], proof["receipt_id"],
        expected_mitre="T1112", expected_action="registry_hardening") is True


def test_t1055_current_signed_report_has_no_executable_control_or_fake_closure(context):
    posture, _, registry, _, _, store = context
    service = patch_center.PatchReviewService(posture, _report(posture.data_dir, "injection-fixture", "T1055"))
    snapshot = service.snapshot()
    assert snapshot["report_state"] == "verified-practice" and snapshot["gaps"][0]["controls"] == []
    with pytest.raises(ValueError, match="supported"):
        service.build_plan(snapshot["gaps"][0]["gap_id"], "windows.process_injection.mitigation")
    posture.record_weakness("T1055", "Authenticated gap cannot make a DWORD real protection", "High")
    assert actions.plan_remediation(posture.weaknesses())[0]["executable"] is False
    assert posture.apply_vetted_remediation(apply=True)["applied"] == 0
    assert posture.weaknesses()[0]["status"] == "VULNERABLE" and not registry.writes
    assert not store.unresolved_transactions()


def test_old_t1055_value_retains_undo_but_no_verify_or_committed_protection_credit(context):
    _, _, registry, _, _, store = context
    action = actions.RegistryHardeningAction()
    control = next(row for row in action._CONTROLS if row.control_id == "windows.process_injection.mitigation")
    weakness = {"mitre_id": "T1055", "control_id": control.control_id}
    legacy = {"action": action.key, "mitre": "T1055", "control_id": control.control_id,
        "subkey": control.subkey, "name": control.value_name, "prior_present": True,
        "prior": 7, "prior_type": 4, "new": control.dword, "compensation_ready": True,
        "mutation_started": False, "verified": True, "ok": True}
    owner = store.prepare_transaction(trigger="historical-inert-legacy", mitre="T1055",
        action_key=action.key, action_title=action.title, host_level=True, record=legacy)
    legacy.update(transaction_id=owner.transaction_id, mutation_started=True)
    store.transition_transaction(owner, state="MUTATING", record=legacy)
    completion = store.finish_transaction(owner, result="applied", record=legacy)
    record = completion.pop("record")
    record["proof_receipt"] = completion
    assert store.verify_committed_application(record["transaction_id"], completion["receipt_hash"], completion["receipt_id"],
        expected_mitre="T1055", expected_action=action.key) is True
    registry.values[control.subkey, control.value_name] = control.dword, 4
    assert action.verify(weakness, record) is False
    assert PostureHardening.committed_patch_record(store, record,
        expected_mitre="T1055", expected_action=action.key) is False
    with pytest.raises((ValueError, PermissionError)):
        action.begin_transaction(weakness, store._path.parent)
    with pytest.raises(PermissionError):
        action.apply_transactional(weakness, store._path.parent, copy.deepcopy(record))
    assert action.rollback(record)["ok"] is True
    assert registry.values[control.subkey, control.value_name] == (7, 4)
