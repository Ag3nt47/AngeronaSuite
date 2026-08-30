from __future__ import annotations

import os
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

import pytest

from angerona.core import remediation_log
from angerona.modules import remediation_actions as actions


class _DurableTestAction(actions.RemediationAction):
    key = "durable_test_action"
    title = "inert durable transaction fixture"
    host_level = False
    reversible = True
    durable_transaction = True

    def __init__(self, store=None) -> None:
        self.store = store
        self.dispatches = 0
        self.recovery_can_close = False
        self.succeed = False

    def matches(self, weakness: dict) -> bool:
        return weakness.get("kind") == "durable-test"

    def begin_transaction(self, weakness: dict, quarantine_dir: Path) -> dict:
        del weakness, quarantine_dir
        return {
            "action": self.key,
            "prior_state": "fixture-prior",
            "compensation_identity": "fixture-object-1",
            "compensation_ready": True,
            "transaction_state": "prepared",
            "mutation_started": False,
        }

    def apply_transactional(
        self, weakness: dict, quarantine_dir: Path, transaction: dict
    ) -> dict:
        del weakness, quarantine_dir
        if self.store is not None:
            retained = self.store.transaction(transaction["transaction_id"])
            assert retained is not None
            assert retained["state"] == "MUTATING"
        self.dispatches += 1
        transaction["mutation_started"] = True
        transaction["ok"] = self.succeed
        return transaction

    def verify(self, weakness: dict, record: dict) -> bool:
        del weakness, record
        return self.succeed

    def rollback(self, record: dict) -> dict:
        del record
        return {"ok": self.recovery_can_close}

    def verify_rollback(self, record: dict) -> bool:
        return (
            self.recovery_can_close
            and record.get("prior_state") == "fixture-prior"
            and record.get("compensation_identity") == "fixture-object-1"
        )


def test_executable_actions_fail_closed_without_database_custody(
    monkeypatch, tmp_path: Path
) -> None:
    action = _DurableTestAction()
    monkeypatch.setattr(remediation_log, "get_log", lambda: None)
    monkeypatch.setattr(actions, "ACTIONS", [action])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())
    monkeypatch.setattr(actions, "DOMINANT_PROPOSAL_ACTIONS", ())

    result = actions.apply_remediation(
        [{"kind": "durable-test"}], tmp_path, apply=True, allow_host=True
    )

    assert result["applied"] == 0
    assert result["skipped"] == 1
    assert action.dispatches == 0
    assert "database custody is unavailable" in result["records"][0]["reason"]


def test_recovery_circuit_survives_calls_and_restart_until_exact_reconciliation(
    monkeypatch, tmp_path: Path
) -> None:
    db_path = tmp_path / "remediation-custody.db"
    store = remediation_log.RemediationLog(db_path)
    action = _DurableTestAction(store)
    holder = {"store": store}
    monkeypatch.setattr(remediation_log, "get_log", lambda: holder["store"])
    monkeypatch.setattr(actions, "ACTIONS", [action])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())
    monkeypatch.setattr(actions, "DOMINANT_PROPOSAL_ACTIONS", ())

    first = actions.apply_remediation(
        [{"kind": "durable-test", "mitre_id": "T0001"}],
        tmp_path,
        apply=True,
        allow_host=True,
    )
    assert first["applied"] == 0
    assert first["records"][0]["transaction_state"] == "rollback_failed"
    assert first["records"][0]["recovery_required"] is True
    transaction_id = first["records"][0]["transaction_id"]
    assert store.transaction(transaction_id)["state"] == "RECOVERY_REQUIRED"
    assert action.dispatches == 1

    second = actions.apply_remediation(
        [{"kind": "durable-test"}], tmp_path, apply=True, allow_host=True
    )
    assert second["applied"] == 0
    assert action.dispatches == 1
    assert second["records"][0]["recovery_required"] is True

    store.close()
    restarted = remediation_log.RemediationLog(db_path)
    holder["store"] = restarted
    action.store = restarted
    third = actions.apply_remediation(
        [{"kind": "durable-test"}], tmp_path, apply=True, allow_host=True
    )
    assert third["applied"] == 0
    assert action.dispatches == 1
    assert restarted.transaction(transaction_id)["state"] == "RECOVERY_REQUIRED"

    denied = actions.reconcile_remediation_transaction(transaction_id)
    assert denied["ok"] is False
    assert restarted.transaction(transaction_id)["state"] == "RECOVERY_REQUIRED"

    action.recovery_can_close = True
    reconciled = actions.reconcile_remediation_transaction(
        transaction_id, authorized=True
    )
    assert reconciled["ok"] is True
    assert reconciled["transaction_id"] == transaction_id
    assert reconciled["state"] == "ROLLED_BACK"
    assert reconciled["proof_receipt"]["receipt_hash"]
    assert restarted.unresolved_transactions() == []

    action.succeed = True
    final = actions.apply_remediation(
        [{"kind": "durable-test"}], tmp_path, apply=True, allow_host=True
    )
    assert final["applied"] == 1
    assert action.dispatches == 2
    restarted.close()


def test_oversized_prepared_record_blocks_before_dispatch(
    monkeypatch, tmp_path: Path
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "bounded.db")

    class Oversized(_DurableTestAction):
        def begin_transaction(self, weakness: dict, quarantine_dir: Path) -> dict:
            record = super().begin_transaction(weakness, quarantine_dir)
            record["oversized"] = "x" * (remediation_log.MAX_TRANSACTION_RECORD_BYTES + 1)
            return record

    action = Oversized(store)
    monkeypatch.setattr(remediation_log, "get_log", lambda: store)
    monkeypatch.setattr(actions, "ACTIONS", [action])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())
    monkeypatch.setattr(actions, "DOMINANT_PROPOSAL_ACTIONS", ())

    result = actions.apply_remediation(
        [{"kind": "durable-test"}], tmp_path, apply=True, allow_host=True
    )

    assert result["applied"] == 0
    assert result["skipped"] == 1
    assert action.dispatches == 0
    assert "64 KiB" in store.recent(1)[0]["record"]["error"]
    store.close()


def test_concurrent_batches_have_one_database_serialized_dispatch(
    monkeypatch, tmp_path: Path
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "concurrent-custody.db")
    initial_inspect = store.unresolved_transactions
    inspected = threading.Barrier(2)
    dispatch_started = threading.Event()
    release_dispatch = threading.Event()
    dispatch_lock = threading.Lock()

    def synchronized_inspect():
        result = initial_inspect()
        inspected.wait(timeout=5)
        return result

    monkeypatch.setattr(store, "unresolved_transactions", synchronized_inspect)

    class BlockingSuccess(_DurableTestAction):
        def apply_transactional(
            self, weakness: dict, quarantine_dir: Path, transaction: dict
        ) -> dict:
            del weakness, quarantine_dir
            retained = store.transaction(transaction["transaction_id"])
            assert retained is not None and retained["state"] == "MUTATING"
            with dispatch_lock:
                self.dispatches += 1
            transaction["mutation_started"] = True
            dispatch_started.set()
            assert release_dispatch.wait(timeout=5)
            transaction["ok"] = True
            return transaction

        def verify(self, weakness: dict, record: dict) -> bool:
            del weakness, record
            return True

    action = BlockingSuccess(store)
    monkeypatch.setattr(remediation_log, "get_log", lambda: store)
    monkeypatch.setattr(actions, "ACTIONS", [action])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())
    monkeypatch.setattr(actions, "DOMINANT_PROPOSAL_ACTIONS", ())

    def apply_once(index: int) -> dict:
        return actions.apply_remediation(
            [{"kind": "durable-test", "mitre_id": f"T000{index}"}],
            tmp_path,
            apply=True,
            allow_host=True,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(apply_once, index) for index in (1, 2)]
        assert dispatch_started.wait(timeout=5)
        completed, _ = wait(futures, timeout=5, return_when=FIRST_COMPLETED)
        assert len(completed) == 1
        blocked_while_first_is_live = next(iter(completed)).result()
        blocked_record = blocked_while_first_is_live["records"][0]
        assert blocked_record["blocked"] is True
        assert blocked_record["recovery_required"] is True
        assert blocked_record["mutation_started"] is False
        assert len(blocked_record["blocking_transactions"]) == 1
        blocking_id = blocked_record["blocking_transactions"][0]
        assert store.transaction(blocking_id)["state"] == "MUTATING"
        release_dispatch.set()
        results = [future.result(timeout=5) for future in futures]

    assert action.dispatches == 1
    assert sum(result["applied"] for result in results) == 1
    assert sum(result["skipped"] for result in results) == 1
    applied = next(result for result in results if result["applied"] == 1)
    assert applied["records"][0]["transaction_id"] == blocking_id
    assert store.transaction(blocking_id)["state"] == "APPLIED"
    assert initial_inspect() == []
    store.close()


def test_two_reconciliation_callers_execute_exactly_one_compensation(
    monkeypatch, tmp_path: Path
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "reconciliation-claim.db")
    rollback_started = threading.Event()
    release_rollback = threading.Event()

    class BlockingRecovery(_DurableTestAction):
        def __init__(self) -> None:
            super().__init__(store)
            self.block_reconciliation = False
            self.rollback_calls = 0

        def rollback(self, record: dict) -> dict:
            del record
            self.rollback_calls += 1
            if self.block_reconciliation:
                rollback_started.set()
                assert release_rollback.wait(timeout=5)
            return {"ok": self.recovery_can_close}

    action = BlockingRecovery()
    monkeypatch.setattr(remediation_log, "get_log", lambda: store)
    monkeypatch.setattr(actions, "ACTIONS", [action])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())
    monkeypatch.setattr(actions, "DOMINANT_PROPOSAL_ACTIONS", ())

    failed = actions.apply_remediation(
        [{"kind": "durable-test"}], tmp_path, apply=True, allow_host=True
    )
    transaction_id = failed["records"][0]["transaction_id"]
    assert store.transaction(transaction_id)["state"] == "RECOVERY_REQUIRED"

    action.rollback_calls = 0
    action.recovery_can_close = True
    action.block_reconciliation = True
    with ThreadPoolExecutor(max_workers=2) as pool:
        winner_future = pool.submit(
            actions.reconcile_remediation_transaction,
            transaction_id,
            authorized=True,
        )
        assert rollback_started.wait(timeout=5)
        loser_future = pool.submit(
            actions.reconcile_remediation_transaction,
            transaction_id,
            authorized=True,
        )
        loser = loser_future.result(timeout=5)
        assert loser["ok"] is False
        assert loser["state"] == "RECONCILING"
        assert loser["recovery_required"] is True
        assert action.rollback_calls == 1
        assert store.transaction(transaction_id)["state"] == "RECONCILING"
        release_rollback.set()
        winner = winner_future.result(timeout=5)

    assert winner["ok"] is True
    assert winner["state"] == "ROLLED_BACK"
    assert winner["proof_receipt"]["receipt_hash"]
    assert action.rollback_calls == 1
    assert store.transaction(transaction_id)["state"] == "ROLLED_BACK"
    store.close()


def test_same_database_separate_connections_admit_only_one_prepared_row(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "shared-object.db"
    first = remediation_log.RemediationLog(db_path)
    second = remediation_log.RemediationLog(db_path)
    ready = threading.Barrier(2)

    def prepare(store: remediation_log.RemediationLog, suffix: str):
        ready.wait(timeout=5)
        try:
            return store.prepare_transaction(
                trigger="same-path-race",
                mitre=f"T000{suffix}",
                action_key="durable_test_action",
                action_title="inert durable transaction fixture",
                host_level=False,
                record={"compensation_ready": True, "suffix": suffix},
            )
        except remediation_log.RemediationCircuitOpen as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(prepare, (first, second), ("1", "2"))
        )

    owners = [
        item
        for item in results
        if isinstance(item, remediation_log.TransactionOwnerCapability)
    ]
    transaction_ids = [owner.transaction_id for owner in owners]
    blocked = [
        item for item in results if isinstance(item, remediation_log.RemediationCircuitOpen)
    ]
    assert len(transaction_ids) == 1
    assert len(blocked) == 1
    assert blocked[0].transaction_ids == (transaction_ids[0],)
    assert first.transaction(transaction_ids[0])["state"] == "PREPARED"
    first.close()
    second.close()


def test_owner_capability_is_digest_only_and_enforces_the_fixed_state_graph(
    tmp_path: Path,
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "owner-capability.db")
    foreign = remediation_log.RemediationLog(tmp_path / "foreign-owner.db")
    record = {"compensation_ready": True, "fixture": "owner-bound"}
    owner = store.prepare_transaction(
        trigger="owner-capability-test",
        mitre="T0001",
        action_key="durable_test_action",
        action_title="inert durable transaction fixture",
        host_level=False,
        record=record,
    )
    foreign_owner = foreign.prepare_transaction(
        trigger="foreign-owner-test",
        mitre="T0002",
        action_key="durable_test_action",
        action_title="inert durable transaction fixture",
        host_level=False,
        record=record,
    )

    retained = store.transaction(owner.transaction_id)
    assert retained is not None and retained["state"] == "PREPARED"
    assert "owner" not in retained
    raw_secret_hex = bytes(owner._secret).hex()
    assert raw_secret_hex not in repr(owner)
    _, expected_digest = owner._proof()
    stored_digest, stored_record = store._db.execute(
        "SELECT owner_capability_sha256, record_json "
        "FROM remediation_transactions WHERE id = ?",
        (owner.transaction_id,),
    ).fetchone()
    assert stored_digest == expected_digest
    assert raw_secret_hex not in stored_record
    assert expected_digest not in stored_record

    with pytest.raises(TypeError, match="owner capability"):
        store.transition_transaction(
            owner.transaction_id,
            state="MUTATING",
            record=record,
        )
    with pytest.raises(ValueError, match="invalid remediation transaction state"):
        store.transition_transaction(owner, state="PREPARED", record=record)
    with pytest.raises(ValueError, match="invalid remediation transaction state"):
        store.transition_transaction(owner, state="APPLIED", record=record)
    with pytest.raises(RuntimeError, match="owner, state, or custody"):
        store.transition_transaction(foreign_owner, state="MUTATING", record=record)
    assert store.transaction(owner.transaction_id)["state"] == "PREPARED"

    store.transition_transaction(owner, state="MUTATING", record=record)
    proof = store.finish_transaction(owner, result="applied", record=record)
    assert proof["receipt_hash"]
    assert store.transaction(owner.transaction_id)["state"] == "APPLIED"
    cleared_digest = store._db.execute(
        "SELECT owner_capability_sha256 FROM remediation_transactions WHERE id = ?",
        (owner.transaction_id,),
    ).fetchone()[0]
    assert cleared_digest is None
    with pytest.raises(RuntimeError, match="owner capability is unavailable"):
        store.finish_transaction(owner, result="applied", record=record)

    store.close()
    foreign.close()


def test_wrong_owner_cannot_terminalize_live_work_or_authorize_second_dispatch(
    monkeypatch, tmp_path: Path
) -> None:
    store = remediation_log.RemediationLog(tmp_path / "owner-race.db")
    foreign = remediation_log.RemediationLog(tmp_path / "owner-race-foreign.db")
    foreign_owner = foreign.prepare_transaction(
        trigger="foreign-owner",
        mitre="T0002",
        action_key="durable_test_action",
        action_title="inert durable transaction fixture",
        host_level=False,
        record={"compensation_ready": True},
    )
    dispatch_started = threading.Event()
    release_dispatch = threading.Event()

    class BlockingSuccess(_DurableTestAction):
        def apply_transactional(
            self, weakness: dict, quarantine_dir: Path, transaction: dict
        ) -> dict:
            del weakness, quarantine_dir
            self.dispatches += 1
            transaction["mutation_started"] = True
            dispatch_started.set()
            assert release_dispatch.wait(timeout=5)
            transaction["ok"] = True
            return transaction

        def verify(self, weakness: dict, record: dict) -> bool:
            del weakness, record
            return True

    action = BlockingSuccess(store)
    monkeypatch.setattr(remediation_log, "get_log", lambda: store)
    monkeypatch.setattr(actions, "ACTIONS", [action])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())
    monkeypatch.setattr(actions, "DOMINANT_PROPOSAL_ACTIONS", ())

    with ThreadPoolExecutor(max_workers=1) as pool:
        first_future = pool.submit(
            actions.apply_remediation,
            [{"kind": "durable-test", "mitre_id": "T0001"}],
            tmp_path,
            True,
            True,
        )
        assert dispatch_started.wait(timeout=5)
        live = store.unresolved_transactions()
        assert len(live) == 1 and live[0]["state"] == "MUTATING"
        transaction_id = live[0]["transaction_id"]

        with pytest.raises(RuntimeError, match="owner, state, or custody"):
            store.finish_transaction(
                foreign_owner,
                result="applied",
                record={"forced_terminal": True},
            )
        assert store.transaction(transaction_id)["state"] == "MUTATING"

        second = actions.apply_remediation(
            [{"kind": "durable-test", "mitre_id": "T0002"}],
            tmp_path,
            apply=True,
            allow_host=True,
        )
        assert second["applied"] == 0
        assert second["skipped"] == 1
        assert second["records"][0]["recovery_required"] is True
        assert second["records"][0]["mutation_started"] is False
        assert action.dispatches == 1
        assert store.transaction(transaction_id)["state"] == "MUTATING"

        release_dispatch.set()
        first = first_future.result(timeout=5)

    assert first["applied"] == 1
    assert action.dispatches == 1
    assert store.transaction(transaction_id)["state"] == "APPLIED"
    store.close()
    foreign.close()


def test_hardlink_alias_opens_custody_circuit_before_dispatch(
    monkeypatch, tmp_path: Path
) -> None:
    db_path = tmp_path / "single-authority.db"
    alias_path = tmp_path / "database-alias.db"
    store = remediation_log.RemediationLog(db_path)
    action = _DurableTestAction(store)
    monkeypatch.setattr(remediation_log, "get_log", lambda: store)
    monkeypatch.setattr(actions, "ACTIONS", [action])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())
    monkeypatch.setattr(actions, "DOMINANT_PROPOSAL_ACTIONS", ())

    try:
        os.link(db_path, alias_path)
    except OSError as exc:
        store.close()
        pytest.skip(f"filesystem hard links unavailable: {exc}")
    try:
        result = actions.apply_remediation(
            [{"kind": "durable-test"}], tmp_path, apply=True, allow_host=True
        )
        assert result["applied"] == 0
        assert result["skipped"] == 1
        assert action.dispatches == 0
        assert result["records"][0]["mutation_started"] is False
        assert "exactly one filesystem link" in result["records"][0]["reason"]
        with pytest.raises(
            remediation_log.RemediationCustodyError,
            match="exactly one filesystem link",
        ):
            remediation_log.RemediationLog(alias_path)
    finally:
        alias_path.unlink(missing_ok=True)
        store.close()


def test_process_log_singleton_rejects_a_different_canonical_database(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(remediation_log, "_SINGLETON", None)
    db_path = tmp_path / "singleton.db"
    store = remediation_log.init_log(db_path)

    assert remediation_log.init_log(tmp_path / "." / "singleton.db") is store
    with pytest.raises(RuntimeError, match="different canonical database"):
        remediation_log.init_log(tmp_path / "other.db")

    store.close()


def test_exact_technique_and_control_candidates_never_use_composite_text(
    monkeypatch,
) -> None:
    registry = actions.RegistryHardeningAction()
    monkeypatch.setattr(
        registry, "matches", lambda weakness: len(registry._candidates(weakness)) == 1
    )
    monkeypatch.setattr(actions, "ACTIONS", [registry])
    monkeypatch.setattr(
        actions,
        "DOMINANT_PROPOSAL_ACTIONS",
        (actions.DefenderHardeningAction(),),
    )
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())

    script_logging = {
        "mitre_id": "T1562.011",
        "name": "PowerShell script block logging disabled",
    }
    decision = actions.classify_remediation(script_logging)
    assert decision.action is registry
    assert decision.proposal is None
    assert actions.DefenderHardeningAction().matches(script_logging) is False

    composite = {
        "mitre_id": "T1548.002",
        "name": "credential UAC bypass with LSASS WDigest wording",
    }
    candidates = registry._candidates(composite)
    assert len(candidates) == 1
    assert candidates[0].control_id == "windows.uac.secure_desktop_consent"

    ambiguous = {"mitre_id": "T1003.001", "name": "credential dumping"}
    assert len(registry._candidates(ambiguous)) == 2
    assert registry._entry(ambiguous) is None
    assert actions.classify_remediation(ambiguous).action is None

    exact = {
        "mitre_id": "T1003.001",
        "control_id": "windows.lsass.run_as_ppl",
        "name": "misleading WDigest UAC text",
    }
    assert registry._candidates(exact)[0].control_id == "windows.lsass.run_as_ppl"
    assert actions.classify_remediation(exact).action is registry

    mismatched = {
        "mitre_id": "T1562.011",
        "control_id": "windows.uac.secure_desktop_consent",
    }
    assert registry._candidates(mismatched) == ()
    assert actions.classify_remediation(mismatched).action is None

    conflicting = {
        "mitre_id": "T1562.011",
        "mitre": "T1548.002",
        "control_id": "windows.powershell.script_block_logging",
    }
    assert registry._candidates(conflicting) == ()
    assert actions.classify_remediation(conflicting).action is None
