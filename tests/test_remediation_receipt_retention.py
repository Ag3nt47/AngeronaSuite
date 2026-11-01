"""Every committed receipt participates in existing prefix retention."""
from __future__ import annotations

from pathlib import Path

import pytest

from angerona.core import remediation_log, report_attest
from angerona.modules import remediation_actions as actions


class _InertRecoveryAction(actions.RemediationAction):
    key = "inert_retention_recovery"
    title = "Inert receipt retention recovery"
    host_level = False
    durable_transaction = True
    reversible = True

    def rollback(self, record):
        return {"ok": True, "marker": record.get("marker")}

    def verify_rollback(self, record):
        return record.get("marker") == "inert"


@pytest.fixture
def ledger(tmp_path: Path, monkeypatch):
    key = tmp_path / "bus.key"
    key.write_text(bytes(range(32)).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    store = remediation_log.RemediationLog(tmp_path / "ledger.db")
    try:
        yield store
    finally:
        store.close()


def _pending(store, *, action="inert_retention", marker="inert"):
    record = {"action": action, "mitre": "T1112", "compensation_ready": True,
              "mutation_started": False, "marker": marker}
    owner = store.prepare_transaction(
        trigger="inert-retention", mitre="T1112", action_key=action,
        action_title="Inert retention fixture", host_level=False, record=record,
    )
    record.update(transaction_id=owner.transaction_id, mutation_started=True, ok=True)
    store.transition_transaction(owner, state="MUTATING", record=record)
    return owner, record


def _finish(store):
    owner, record = _pending(store)
    proof = store.finish_transaction(owner, result="applied", record=record)
    return owner, proof


def _snapshot(store):
    return dict(store._db.execute(
        "SELECT id, record_json || char(0) || receipt_json || char(0) || receipt_hash "
        "FROM remediation_log ORDER BY id"
    ).fetchall())


def _claim(store):
    action = _InertRecoveryAction()
    owner, record = _pending(store, action=action.key)
    store.finish_transaction(owner, result="rollback_failed", record=record)
    coordinator = store._bind_recovery_coordinator((action,))
    claimed = store._claim_reconciliation(coordinator, owner.transaction_id)
    capability = claimed["capability"]
    proof = store._issue_verified_recovery_proof(
        coordinator, capability, action=action,
        operation="verified_rollback", evidence={"ok": True, "marker": "inert"},
    )
    return action, coordinator, capability, proof


def test_durable_only_receipts_trigger_existing_prefix_retention(ledger, monkeypatch):
    monkeypatch.setattr(remediation_log, "MAX_ROWS", 3)
    monkeypatch.setattr(remediation_log, "PRUNE_EVERY", 2)
    retained = {}
    for _ in range(6):
        before = _snapshot(ledger)
        owner, _proof = _finish(ledger)
        assert owner._retired
        after = _snapshot(ledger)
        assert all(before[row_id] == value for row_id, value in after.items() if row_id in before)
        retained = after
    assert list(retained) == [4, 5, 6]
    status = ledger.verify_receipt_chain()
    assert status["valid"] is True and status["verified_receipts"] == 3


def test_reconciliation_receipt_reaches_cadence_and_preserves_chain(ledger, monkeypatch):
    monkeypatch.setattr(remediation_log, "MAX_ROWS", 3)
    monkeypatch.setattr(remediation_log, "PRUNE_EVERY", 4)
    for _ in range(2):
        ledger.log(trigger="inert", record={"marker": "old"})
    _action, coordinator, capability, proof = _claim(ledger)
    before = _snapshot(ledger)
    assert len(before) == 3 and ledger._writes == 3
    result = ledger._finish_reconciliation(coordinator, capability, proof)
    after = _snapshot(ledger)
    assert list(after) == [2, 3, 4]
    assert all(before[row_id] == value for row_id, value in after.items() if row_id in before)
    assert result["receipt_authenticated"] is True
    assert capability._retired and proof._retired
    assert ledger.verify_receipt_chain()["valid"] is True


def test_mixed_receipts_prune_only_prefix_and_leave_unresolved_custody_unchanged(ledger, monkeypatch):
    monkeypatch.setattr(remediation_log, "MAX_ROWS", 4)
    monkeypatch.setattr(remediation_log, "PRUNE_EVERY", 2)
    ledger.log(trigger="inert", record={"marker": "legacy"})
    _finish(ledger)
    _action, coordinator, capability, proof = _claim(ledger)
    ledger._finish_reconciliation(coordinator, capability, proof)
    owner, _record = _pending(ledger)
    original_transaction = ledger._db.execute(
        "SELECT * FROM remediation_transactions WHERE id=?", (owner.transaction_id,),
    ).fetchone()
    original_claims = ledger._db.execute(
        "SELECT * FROM remediation_reconciliation_claims",
    ).fetchall()
    for _ in range(4):
        before = _snapshot(ledger)
        ledger.log(trigger="inert", record={"marker": "optional"})
        after = _snapshot(ledger)
        removed = sorted(set(before) - set(after))
        assert not removed or removed == sorted(before)[:len(removed)]
        assert all(before[row_id] == value for row_id, value in after.items() if row_id in before)
    assert len(_snapshot(ledger)) == 4
    assert ledger.verify_receipt_chain()["valid"] is True
    assert ledger._db.execute(
        "SELECT * FROM remediation_transactions WHERE id=?", (owner.transaction_id,),
    ).fetchone() == original_transaction
    assert ledger._db.execute("SELECT * FROM remediation_reconciliation_claims").fetchall() == original_claims
    assert owner._retired is False
    assert ledger.transaction(owner.transaction_id)["state"] == "MUTATING"


def test_prefix_retention_preserves_an_active_reconciliation_claim(ledger, monkeypatch):
    monkeypatch.setattr(remediation_log, "MAX_ROWS", 3)
    monkeypatch.setattr(remediation_log, "PRUNE_EVERY", 2)
    _action, coordinator, capability, proof = _claim(ledger)
    transaction = ledger._db.execute("SELECT * FROM remediation_transactions").fetchall()
    claims = ledger._db.execute("SELECT * FROM remediation_reconciliation_claims").fetchall()
    assert len(claims) == 1
    for _ in range(5):
        ledger.log(trigger="inert", record={"marker": "optional audit"})
    assert ledger._db.execute("SELECT * FROM remediation_transactions").fetchall() == transaction
    assert ledger._db.execute("SELECT * FROM remediation_reconciliation_claims").fetchall() == claims
    assert capability._retired is proof._retired is False
    assert ledger.verify_receipt_chain()["valid"] is True
    # Recovery custody binds its transaction record, not a retired audit-row ID.
    ledger._finish_reconciliation(coordinator, capability, proof)
    assert capability._retired and proof._retired
    assert ledger.transaction(capability.transaction_id)["state"] == "ROLLED_BACK"


@pytest.mark.parametrize("writer", ["log", "ordinary", "reconciliation"])
def test_failed_postcommit_retention_cannot_invalidate_committed_result(ledger, monkeypatch, writer):
    monkeypatch.setattr(remediation_log, "MAX_ROWS", 2)
    monkeypatch.setattr(remediation_log, "PRUNE_EVERY", 1)
    ledger.log(trigger="inert", record={"marker": "one"})
    ledger.log(trigger="inert", record={"marker": "two"})
    if writer == "reconciliation":
        _action, coordinator, capability, proof = _claim(ledger)
    ledger._db.executescript("""
        CREATE TRIGGER fail_retention BEFORE DELETE ON remediation_log
        BEGIN SELECT RAISE(ABORT, 'inert retention failure'); END;
    """)
    if writer == "log":
        result = ledger.log(trigger="inert", record={"marker": "committed"})
    elif writer == "ordinary":
        owner, result = _finish(ledger)
        assert owner._retired
        assert ledger.transaction(owner.transaction_id)["state"] == "APPLIED"
    else:
        result = ledger._finish_reconciliation(coordinator, capability, proof)
        assert capability._retired and proof._retired
        assert ledger.transaction(capability.transaction_id)["state"] == "ROLLED_BACK"
        assert ledger._db.execute("SELECT COUNT(*) FROM remediation_reconciliation_claims").fetchone()[0] == 0
    assert result["receipt_authenticated"] is True
    assert ledger.recent(1)[0]["receipt_hash"] == result["receipt_hash"]
    assert ledger.recent(1)[0]["receipt_authenticity"] is True
    assert ledger._db.in_transaction is False
    # A failed maintenance transaction must not poison the next intent/receipt.
    ledger._db.execute("DROP TRIGGER fail_retention")
    ledger._db.commit()
    owner, following = _finish(ledger)
    assert owner._retired and following["receipt_authenticated"] is True
    assert ledger.verify_receipt_chain()["valid"] is True


@pytest.mark.parametrize("writer", ["ordinary", "reconciliation"])
def test_terminal_capabilities_retire_before_optional_maintenance(ledger, monkeypatch, writer):
    monkeypatch.setattr(remediation_log, "PRUNE_EVERY", 1)
    if writer == "ordinary":
        owner, record = _pending(ledger)
    else:
        _action, coordinator, capability, witness = _claim(ledger)
    observations = []
    def held_maintenance():
        if writer == "ordinary":
            assert owner._retired
        else:
            assert capability._retired and witness._retired
            assert capability.transaction_id not in ledger._recovery_proofs
        observations.append("retired-before-maintenance")
        raise OSError("inert maintenance failure")
    monkeypatch.setattr(ledger, "_prune_locked", held_maintenance)
    if writer == "ordinary":
        result = ledger.finish_transaction(owner, result="applied", record=record)
    else:
        result = ledger._finish_reconciliation(coordinator, capability, witness)
    assert observations == ["retired-before-maintenance"]
    assert result["receipt_authenticated"] is True
    assert ledger._db.in_transaction is False
