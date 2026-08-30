from __future__ import annotations

import copy
import json
import pickle
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from angerona.core import remediation_log, report_attest
from angerona.modules import remediation_actions as actions


class _ReceiptAuthorityAction(actions.RemediationAction):
    key = "receipt_authority_fixture"
    title = "inert receipt authority fixture"
    host_level = False
    reversible = True
    durable_transaction = True

    def rollback(self, record: dict) -> dict:
        del record
        return {"ok": True, "fixture": "inert"}

    def verify_rollback(self, record: dict) -> bool:
        return record.get("marker") is not None


_RECEIPT_AUTHORITY_ACTION = _ReceiptAuthorityAction()


def _bind_recovery(store: remediation_log.RemediationLog, action=None):
    selected = action or _RECEIPT_AUTHORITY_ACTION
    coordinator = store._bind_recovery_coordinator((selected,))
    return selected, coordinator


def _claim_recovery(
    store: remediation_log.RemediationLog,
    transaction_id: int,
    action=None,
):
    selected, coordinator = _bind_recovery(store, action)
    return selected, coordinator, store._claim_reconciliation(
        coordinator, transaction_id
    )


def _verified_rollback_proof(store, coordinator, capability, action):
    return store._issue_verified_recovery_proof(
        coordinator,
        capability,
        action=action,
        operation="verified_rollback",
        evidence={"ok": True, "fixture": "inert"},
    )


def _prepare_recovery(
    store: remediation_log.RemediationLog,
    marker: str = "fixture",
    *,
    action_key: str = "receipt_authority_fixture",
) -> int:
    record = {
        "action": action_key,
        "compensation_ready": True,
        "mutation_started": False,
        "marker": marker,
    }
    owner = store.prepare_transaction(
        trigger="receipt-authority-test",
        mitre="T0001",
        action_key=action_key,
        action_title="inert receipt authority fixture",
        host_level=False,
        record=record,
    )
    transaction_id = owner.transaction_id
    record["mutation_started"] = True
    store.transition_transaction(owner, state="MUTATING", record=record)
    store.finish_transaction(owner, result="rollback_failed", record=record)
    assert store.transaction(transaction_id)["state"] == "RECOVERY_REQUIRED"
    return transaction_id


def test_recovery_capability_is_digest_only_redacted_and_nonserializable(
    tmp_path: Path,
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "recovery-capability.db")
    transaction_id = _prepare_recovery(store)
    _action, _coordinator, claim = _claim_recovery(store, transaction_id)

    assert claim["claimed"] is True
    capability = claim["capability"]
    assert type(capability) is remediation_log.RecoveryCapability
    assert capability.transaction_id == transaction_id
    raw_secret_hex = bytes(capability._secret).hex()
    assert raw_secret_hex not in repr(capability)
    assert "<redacted>" in repr(capability)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(capability)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)

    public = store.transaction(transaction_id)
    unresolved = store.unresolved_transactions()
    assert public is not None and public["state"] == "RECONCILING"
    assert unresolved[0]["state"] == "RECONCILING"
    public_json = json.dumps({"transaction": public, "unresolved": unresolved})
    for forbidden in (
        "claim_id",
        "reconciliation_claim_id",
        "record_sha256",
        "capability_sha256",
        raw_secret_hex,
    ):
        assert forbidden not in public_json
    assert set(claim) == {"claimed", "capability", "transaction"}

    stored_digest, stored_record = store._db.execute(
        "SELECT recovery_capability_sha256, t.record_json "
        "FROM remediation_reconciliation_claims c "
        "JOIN remediation_transactions t ON t.id = c.transaction_id "
        "WHERE c.transaction_id = ?",
        (transaction_id,),
    ).fetchone()
    assert len(stored_digest) == 64
    assert raw_secret_hex not in stored_record
    assert stored_digest not in stored_record
    store.close()


def test_recovery_capability_rejects_cross_transaction_stale_and_owner_crossover(
    tmp_path: Path,
) -> None:
    first = remediation_log.RemediationLog(tmp_path / "first-recovery.db")
    second = remediation_log.RemediationLog(tmp_path / "second-recovery.db")
    first_id = _prepare_recovery(first, "first")
    second_id = _prepare_recovery(second, "second")
    first_action, first_coordinator, first_claim = _claim_recovery(first, first_id)
    second_action, second_coordinator, second_claim = _claim_recovery(
        second, second_id
    )
    first_capability = first_claim["capability"]
    second_capability = second_claim["capability"]
    first_proof = _verified_rollback_proof(
        first, first_coordinator, first_capability, first_action
    )

    with pytest.raises(RuntimeError, match="different store|unavailable"):
        second._finish_reconciliation(
            first_coordinator,
            first_capability,
            first_proof,
        )
    with pytest.raises(TypeError, match="recovery capability"):
        first._finish_reconciliation(
            first_coordinator,
            first_id,
            first_proof,
        )
    with pytest.raises(TypeError, match="owner capability"):
        first.transition_transaction(
            first_capability,
            state="MUTATING",
            record=first_claim["transaction"]["record"],
        )

    proof = first._finish_reconciliation(
        first_coordinator,
        first_capability,
        first_proof,
    )
    assert proof["receipt_hash"]
    assert first.transaction(first_id)["state"] == "ROLLED_BACK"
    with pytest.raises(RuntimeError, match="capability is unavailable"):
        first._finish_reconciliation(
            first_coordinator,
            first_capability,
            first_proof,
        )

    second_proof = _verified_rollback_proof(
        second, second_coordinator, second_capability, second_action
    )
    second._finish_reconciliation(
        second_coordinator,
        second_capability,
        second_proof,
    )
    assert second.transaction(second_id)["state"] == "ROLLED_BACK"
    first.close()
    second.close()


def test_recovery_capability_is_bound_to_retained_record_tamper(
    tmp_path: Path,
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "record-binding.db")
    transaction_id = _prepare_recovery(store)
    action, coordinator, claim = _claim_recovery(store, transaction_id)
    capability = claim["capability"]
    proof = _verified_rollback_proof(store, coordinator, capability, action)
    original = store._db.execute(
        "SELECT record_json FROM remediation_transactions WHERE id = ?",
        (transaction_id,),
    ).fetchone()[0]
    store._db.execute(
        "UPDATE remediation_transactions SET record_json = ? WHERE id = ?",
        ('{"tampered":true}', transaction_id),
    )
    store._db.commit()

    with pytest.raises(RuntimeError, match="retained record changed"):
        store._finish_reconciliation(
            coordinator,
            capability,
            proof,
        )
    assert store.transaction(transaction_id)["state"] == "RECONCILING"
    assert store._db.execute(
        "SELECT COUNT(*) FROM remediation_reconciliation_claims "
        "WHERE transaction_id = ?",
        (transaction_id,),
    ).fetchone()[0] == 1

    store._db.execute(
        "UPDATE remediation_transactions SET record_json = ? WHERE id = ?",
        (original, transaction_id),
    )
    store._db.commit()
    completion = store._finish_reconciliation(
        coordinator,
        capability,
        proof,
    )
    assert completion["receipt_hash"]
    store.close()


def test_crashed_recovery_claim_stays_fail_closed_after_restart(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "crashed-recovery.db"
    store = remediation_log.RemediationLog(db_path)
    transaction_id = _prepare_recovery(store)
    _action, _coordinator, claim = _claim_recovery(store, transaction_id)
    assert claim["claimed"] is True
    assert pickle.dumps(claim["transaction"])
    store.close()
    del claim

    restarted = remediation_log.RemediationLog(db_path)
    public = restarted.transaction(transaction_id)
    assert public is not None and public["state"] == "RECONCILING"
    assert public["recovery_active"] is True
    _action, coordinator = _bind_recovery(restarted)
    retry = restarted._claim_reconciliation(coordinator, transaction_id)
    assert retry["claimed"] is False
    assert set(retry) == {"claimed", "transaction"}
    assert retry["transaction"]["state"] == "RECONCILING"
    restarted.close()


@pytest.mark.parametrize("failure_mode", ["serialization", "insert"])
def test_ordinary_terminal_receipt_failure_rolls_back_and_capability_survives(
    monkeypatch, tmp_path: Path, failure_mode: str
) -> None:
    store = remediation_log.RemediationLog(tmp_path / f"ordinary-{failure_mode}.db")
    record = {"compensation_ready": True, "mutation_started": False}
    owner = store.prepare_transaction(
        trigger="atomic-terminal-test",
        mitre="T0002",
        action_key="atomic_terminal_fixture",
        action_title="immutable fixture title",
        host_level=True,
        record=record,
    )
    record["mutation_started"] = True
    store.transition_transaction(owner, state="MUTATING", record=record)

    if failure_mode == "serialization":
        real_create = remediation_log.create_receipt

        def cyclic_receipt(**kwargs):
            receipt, receipt_hash = real_create(**kwargs)
            receipt["cycle"] = receipt
            return receipt, receipt_hash

        with monkeypatch.context() as scoped:
            scoped.setattr(remediation_log, "create_receipt", cyclic_receipt)
            with pytest.raises(ValueError, match="Circular reference"):
                store.finish_transaction(owner, result="applied", record=record)
    else:
        store._db.execute(
            """
            CREATE TRIGGER reject_atomic_terminal_receipt
            BEFORE INSERT ON remediation_log
            WHEN NEW.outcome = 'applied'
            BEGIN
                SELECT RAISE(ABORT, 'injected receipt insert failure');
            END
            """
        )
        store._db.commit()
        with pytest.raises(Exception, match="injected receipt insert failure"):
            store.finish_transaction(owner, result="applied", record=record)
        store._db.execute("DROP TRIGGER reject_atomic_terminal_receipt")
        store._db.commit()

    retained = store.transaction(owner.transaction_id)
    assert retained is not None and retained["state"] == "MUTATING"
    assert store.recent(100) == []
    _, owner_digest = owner._proof()
    assert store._db.execute(
        "SELECT owner_capability_sha256 FROM remediation_transactions WHERE id = ?",
        (owner.transaction_id,),
    ).fetchone()[0] == owner_digest

    proof = store.finish_transaction(owner, result="applied", record=record)
    assert proof["receipt_hash"]
    assert store.transaction(owner.transaction_id)["state"] == "APPLIED"
    assert len(store.recent(100)) == 1
    store.close()


def test_fixed_terminal_semantics_bind_immutable_metadata_and_record(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(report_attest, "_load_key", lambda: b"k" * 32)
    store = remediation_log.RemediationLog(tmp_path / "fixed-terminal.db")
    record = {
        "transaction_state": "recovery_required",
        "recovery_required": True,
        "verified": False,
        "rollback_failed": True,
        "mutation_started": True,
    }
    owner = store.prepare_transaction(
        trigger="immutable-trigger",
        mitre="T0003",
        action_key="immutable_action",
        action_title="immutable action title",
        host_level=True,
        record=record,
    )
    store.transition_transaction(owner, state="MUTATING", record=record)
    with pytest.raises(TypeError):
        store.finish_transaction(
            owner,
            result="applied",
            record=record,
            state="ROLLED_BACK",
        )
    proof = store.finish_transaction(owner, result="applied", record=record)
    committed = proof["record"]
    assert committed["transaction_state"] == "applied"
    assert committed["recovery_required"] is False
    assert committed["verified"] is True
    assert committed["rollback_failed"] is False
    retained = store.transaction(owner.transaction_id)
    audit = store.recent(1)[0]
    assert retained["record"] == committed
    assert audit["record"] == committed
    assert audit["trigger"] == "immutable-trigger"
    assert audit["action_key"] == "immutable_action"
    assert audit["action_title"] == "immutable action title"
    assert audit["host_level"] is True
    assert audit["outcome"] == "applied"
    assert audit["verified"] is True
    assert audit["receipt_hash"] == proof["receipt_hash"]
    assert store.verify_receipt_chain()["valid"] is True
    store.close()


def test_recovery_receipt_failure_retains_claim_and_same_capability_can_retry(
    tmp_path: Path,
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "recovery-receipt-failure.db")
    transaction_id = _prepare_recovery(store)
    action, coordinator, claim = _claim_recovery(store, transaction_id)
    capability = claim["capability"]
    recovery_proof = _verified_rollback_proof(
        store, coordinator, capability, action
    )
    receipts_before = len(store.recent(100))
    store._db.execute(
        """
        CREATE TRIGGER reject_recovery_receipt
        BEFORE INSERT ON remediation_log
        WHEN NEW.trigger = 'explicit_reconciliation'
        BEGIN
            SELECT RAISE(ABORT, 'injected recovery receipt failure');
        END
        """
    )
    store._db.commit()
    with pytest.raises(Exception, match="injected recovery receipt failure"):
        store._finish_reconciliation(
            coordinator,
            capability,
            recovery_proof,
        )
    assert store.transaction(transaction_id)["state"] == "RECONCILING"
    assert len(store.recent(100)) == receipts_before
    store._db.execute("DROP TRIGGER reject_recovery_receipt")
    store._db.commit()
    proof = store._finish_reconciliation(
        coordinator,
        capability,
        recovery_proof,
    )
    assert proof["receipt_hash"]
    assert store.transaction(transaction_id)["state"] == "ROLLED_BACK"
    store.close()


class _PausedRecoveryAction(actions.RemediationAction):
    key = "paused_recovery_fixture"
    title = "inert paused recovery fixture"
    host_level = False
    reversible = True
    durable_transaction = True

    def __init__(self, rollback_started: threading.Event, release: threading.Event):
        self.rollback_started = rollback_started
        self.release = release
        self.pause_recovery = False
        self.rollback_calls = 0
        self.dispatches = 0

    def matches(self, weakness: dict) -> bool:
        return weakness.get("kind") == "paused-recovery"

    def begin_transaction(self, weakness: dict, quarantine_dir: Path) -> dict:
        del weakness, quarantine_dir
        return {
            "action": self.key,
            "compensation_ready": True,
            "mutation_started": False,
            "prior_state": "inert-prior",
        }

    def apply_transactional(
        self, weakness: dict, quarantine_dir: Path, transaction: dict
    ) -> dict:
        del weakness, quarantine_dir
        self.dispatches += 1
        transaction.update({"mutation_started": True, "ok": False})
        return transaction

    def verify(self, weakness: dict, record: dict) -> bool:
        del weakness, record
        return False

    def rollback(self, record: dict) -> dict:
        del record
        self.rollback_calls += 1
        if self.pause_recovery:
            self.rollback_started.set()
            assert self.release.wait(timeout=5)
            return {"ok": True}
        return {"ok": False}

    def verify_rollback(self, record: dict) -> bool:
        return self.pause_recovery and record.get("prior_state") == "inert-prior"


class _SuccessfulTerminalAction(actions.RemediationAction):
    key = "successful_terminal_fixture"
    title = "inert successful terminal fixture"
    host_level = False
    reversible = True
    durable_transaction = True

    def __init__(self) -> None:
        self.dispatches = 0

    def matches(self, weakness: dict) -> bool:
        return weakness.get("kind") == "successful-terminal"

    def begin_transaction(self, weakness: dict, quarantine_dir: Path) -> dict:
        del weakness, quarantine_dir
        return {
            "action": self.key,
            "compensation_ready": True,
            "mutation_started": False,
            "prior_state": "inert-prior",
        }

    def apply_transactional(
        self, weakness: dict, quarantine_dir: Path, transaction: dict
    ) -> dict:
        del weakness, quarantine_dir
        self.dispatches += 1
        transaction.update({"mutation_started": True, "ok": True})
        return transaction

    def verify(self, weakness: dict, record: dict) -> bool:
        del weakness, record
        return True


def test_apply_path_receipt_failure_keeps_mutating_circuit_and_blocks_dispatch(
    monkeypatch, tmp_path: Path
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "apply-receipt-failure.db")
    action = _SuccessfulTerminalAction()
    monkeypatch.setattr(remediation_log, "get_log", lambda: store)
    monkeypatch.setattr(actions, "ACTIONS", [action])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())
    monkeypatch.setattr(actions, "DOMINANT_PROPOSAL_ACTIONS", ())
    store._db.execute(
        """
        CREATE TRIGGER reject_apply_receipt
        BEFORE INSERT ON remediation_log
        WHEN NEW.outcome = 'applied'
        BEGIN
            SELECT RAISE(ABORT, 'injected apply receipt failure');
        END
        """
    )
    store._db.commit()

    first = actions.apply_remediation(
        [{"kind": "successful-terminal"}],
        tmp_path,
        apply=True,
        allow_host=True,
    )
    assert first["applied"] == 0
    assert first["skipped"] == 1
    assert action.dispatches == 1
    assert first["records"][0]["recovery_required"] is True
    assert "injected apply receipt failure" in first["records"][0]["journal_error"]
    transaction_id = first["records"][0]["transaction_id"]
    retained = store.transaction(transaction_id)
    assert retained is not None and retained["state"] == "MUTATING"
    assert store.recent(100) == []

    second = actions.apply_remediation(
        [{"kind": "successful-terminal"}],
        tmp_path,
        apply=True,
        allow_host=True,
    )
    assert second["applied"] == 0
    assert second["skipped"] == 1
    assert second["records"][0]["mutation_started"] is False
    assert second["records"][0]["recovery_required"] is True
    assert action.dispatches == 1
    assert store.transaction(transaction_id)["state"] == "MUTATING"
    store.close()


def test_synchronized_public_inspection_cannot_forge_recovery_finish(
    monkeypatch, tmp_path: Path
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "synchronized-a07.db")
    rollback_started = threading.Event()
    release = threading.Event()
    action = _PausedRecoveryAction(rollback_started, release)
    monkeypatch.setattr(remediation_log, "get_log", lambda: store)
    monkeypatch.setattr(actions, "ACTIONS", [action])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())
    monkeypatch.setattr(actions, "DOMINANT_PROPOSAL_ACTIONS", ())

    failed = actions.apply_remediation(
        [{"kind": "paused-recovery"}], tmp_path, apply=True, allow_host=True
    )
    transaction_id = failed["records"][0]["transaction_id"]
    assert store.transaction(transaction_id)["state"] == "RECOVERY_REQUIRED"
    action.rollback_calls = 0
    action.pause_recovery = True

    with ThreadPoolExecutor(max_workers=1) as pool:
        winner_future = pool.submit(
            actions.reconcile_remediation_transaction,
            transaction_id,
            authorized=True,
        )
        assert rollback_started.wait(timeout=5)
        public = store.transaction(transaction_id)
        assert public is not None and public["state"] == "RECONCILING"
        assert "reconciliation_claim_id" not in public
        assert not hasattr(store, "claim_reconciliation")
        assert not hasattr(store, "finish_reconciliation")
        with pytest.raises(TypeError, match="recovery coordinator"):
            store._finish_reconciliation(
                object(),
                transaction_id,
                object(),
            )
        blocked = actions.apply_remediation(
            [{"kind": "paused-recovery"}],
            tmp_path,
            apply=True,
            allow_host=True,
        )
        assert blocked["applied"] == 0
        assert action.dispatches == 1
        assert store.transaction(transaction_id)["state"] == "RECONCILING"
        release.set()
        winner = winner_future.result(timeout=5)

    assert winner["ok"] is True
    assert winner["state"] == "ROLLED_BACK"
    assert winner["proof_receipt"]["receipt_hash"]
    assert action.rollback_calls == 1
    assert action.dispatches == 1
    store.close()


class _VerifierFailureAction(actions.RemediationAction):
    key = "verifier_failure_fixture"
    title = "inert verifier failure fixture"
    host_level = False
    reversible = True
    durable_transaction = True

    def __init__(self) -> None:
        self.rollback_calls = 0
        self.verify_calls = 0

    def rollback(self, record: dict) -> dict:
        del record
        self.rollback_calls += 1
        return {"ok": True, "fixture": "inert"}

    def verify_rollback(self, record: dict) -> bool:
        del record
        self.verify_calls += 1
        return False


def test_public_caller_cannot_claim_or_assert_a_fake_rollback(tmp_path: Path) -> None:
    store = remediation_log.RemediationLog(tmp_path / "a09-public-denial.db")
    transaction_id = _prepare_recovery(store)

    assert not hasattr(store, "claim_reconciliation")
    assert not hasattr(store, "finish_reconciliation")
    with pytest.raises(TypeError, match="recovery coordinator"):
        store._claim_reconciliation(object(), transaction_id)
    with pytest.raises(TypeError, match="recovery coordinator"):
        store._finish_reconciliation(object(), object(), object())
    retained = store.transaction(transaction_id)
    assert retained is not None and retained["state"] == "RECOVERY_REQUIRED"
    assert store.recent(100)[0]["outcome"] == "rollback_failed"
    store.close()


def test_failed_recovery_verifier_keeps_one_durable_claim_locked(
    monkeypatch, tmp_path: Path
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "a09-verifier-lock.db")
    action = _VerifierFailureAction()
    transaction_id = _prepare_recovery(store, action_key=action.key)
    monkeypatch.setattr(remediation_log, "get_log", lambda: store)
    monkeypatch.setattr(actions, "ACTIONS", [action])

    first = actions.reconcile_remediation_transaction(
        transaction_id, authorized=True
    )
    second = actions.reconcile_remediation_transaction(
        transaction_id, authorized=True
    )

    assert first["ok"] is False and first["state"] == "RECONCILING"
    assert second["ok"] is False and second["state"] == "RECONCILING"
    assert action.rollback_calls == 1
    assert action.verify_calls == 1
    assert store.transaction(transaction_id)["state"] == "RECONCILING"
    assert store._db.execute(
        "SELECT COUNT(*) FROM remediation_reconciliation_claims "
        "WHERE transaction_id = ?",
        (transaction_id,),
    ).fetchone()[0] == 1
    store.close()


def test_recovery_authority_rejects_cross_store_coordinator_and_capability(
    tmp_path: Path,
) -> None:
    first = remediation_log.RemediationLog(tmp_path / "a09-first.db")
    second = remediation_log.RemediationLog(tmp_path / "a09-second.db")
    action = _RECEIPT_AUTHORITY_ACTION
    first_id = _prepare_recovery(first, "first")
    second_id = _prepare_recovery(second, "second")
    first_coordinator = first._bind_recovery_coordinator((action,))
    second_coordinator = second._bind_recovery_coordinator((action,))
    first_claim = first._claim_reconciliation(first_coordinator, first_id)

    with pytest.raises(RuntimeError, match="different store|unavailable"):
        first._claim_reconciliation(second_coordinator, first_id)
    with pytest.raises(RuntimeError, match="different store|unavailable"):
        second._claim_reconciliation(first_coordinator, second_id)
    with pytest.raises(RuntimeError, match="claim is unavailable|capability"):
        second._issue_verified_recovery_proof(
            second_coordinator,
            first_claim["capability"],
            action=action,
            operation="verified_rollback",
            evidence={"ok": True},
        )
    assert first.transaction(first_id)["state"] == "RECONCILING"
    assert second.transaction(second_id)["state"] == "RECOVERY_REQUIRED"
    first.close()
    second.close()
