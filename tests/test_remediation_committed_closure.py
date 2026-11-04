"""Local receipt custody, not native-success booleans, authorizes finding closure."""
from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path

import pytest

from angerona.core import remediation_log, report_attest
from angerona.core.remediation_receipts import GENESIS_HASH, create_receipt, receipt_hash
from angerona.modules import remediation_actions as actions
from angerona.modules.posture_hardening import PostureHardening


class _InertSuccessfulAction(actions.RemediationAction):
    key = "inert_committed_closure"
    title = "Inert committed closure fixture"
    host_level = False
    reversible = True
    durable_transaction = True

    def __init__(self):
        self.dispatches = 0

    def matches(self, weakness):
        return weakness.get("mitre_id") == "T1112"

    def begin_transaction(self, weakness, quarantine_dir):
        del weakness, quarantine_dir
        return {"action": self.key, "compensation_ready": True,
                "mutation_started": False, "prior_state": "inert"}

    def apply_transactional(self, weakness, quarantine_dir, transaction):
        del weakness, quarantine_dir
        self.dispatches += 1
        transaction.update(ok=True, mutation_started=True)
        return transaction

    def verify(self, weakness, record):
        del weakness, record
        return True

    def rollback(self, record):
        raise AssertionError("successful inert fixture must not enter compensation")


@pytest.fixture
def context(tmp_path: Path, monkeypatch):
    key = tmp_path / "bus.key"
    key.write_text(bytes(range(32)).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    store = remediation_log.RemediationLog(tmp_path / "flight-recorder.db")
    monkeypatch.setattr(remediation_log, "_SINGLETON", store)
    action = _InertSuccessfulAction()
    monkeypatch.setattr(actions, "ACTIONS", [action])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())
    monkeypatch.setattr(actions, "DOMINANT_PROPOSAL_ACTIONS", ())

    def no_host_command(*_args, **_kwargs):
        raise AssertionError("closure fixtures must not run host commands")

    monkeypatch.setattr(actions, "run_hidden", no_host_command)
    # This diagnostic logger otherwise uses global data_dir rather than the
    # constructor's private test directory. Never write install diagnostics.
    monkeypatch.setattr(PostureHardening, "_log_attempt", lambda *_a, **_kw: None)
    module = PostureHardening(data_dir=tmp_path)
    events = []
    monkeypatch.setattr(module, "emit", lambda message, *_a, **kw: events.append((message, kw)))
    module.record_weakness("T1112", "Inert registry finding", "HIGH")
    try:
        yield store, action, module, events
    finally:
        store.close()


def _verify(store, record, **overrides):
    proof = record["proof_receipt"]
    arguments = {"transaction_id": record["transaction_id"],
                 "receipt_hash": proof["receipt_hash"], "receipt_id": proof["receipt_id"],
                 "expected_mitre": record["mitre"], "expected_action": record["action"]}
    arguments.update(overrides)
    return store.verify_committed_application(**arguments)


def _proof_events(events):
    return [fields for _message, fields in events if fields.get("relation") == "verification-proof"]


def test_terminal_insert_failure_preserves_native_fact_without_closing_finding(context):
    store, action, module, events = context
    store._db.executescript("""
        CREATE TRIGGER fail_terminal_receipt BEFORE INSERT ON remediation_log
        WHEN NEW.outcome = 'applied'
        BEGIN SELECT RAISE(ABORT, 'inert terminal failure'); END;
    """)
    result = module.apply_vetted_remediation(apply=True)
    record = result["records"][0]
    assert action.dispatches == 1 and result["applied"] == 0
    assert record["native_postcondition_before_commit"] is True
    assert record["verified"] is False
    assert record["recovery_required"] is True and "inert terminal failure" in record["journal_error"]
    assert store.transaction(record["transaction_id"])["state"] == "RECOVERY_REQUIRED"
    from angerona.core.patch_recovery import verify_recovery_handoff
    assert verify_recovery_handoff(store, record["transaction_id"], record["recovery_handoff_receipt"],
        expected_mitre="T1112", expected_action=action.key) is True
    assert module.weaknesses()[0]["status"] == "VULNERABLE"
    assert not _proof_events(events)


def test_signed_committed_application_closes_and_emits_bound_proof(context):
    store, action, module, events = context
    result = module.apply_vetted_remediation(apply=True)
    record = result["records"][0]
    assert result["applied"] == action.dispatches == 1
    assert record["verified"] is True and _verify(store, record) is True
    assert module.weaknesses()[0]["status"] == "PATCHED"
    assert _proof_events(events) == [{
        "mitre": "T1112", "verified": True, "relation": "verification-proof",
        "receipt_id": record["proof_receipt"]["receipt_id"],
        "receipt_hash": record["proof_receipt"]["receipt_hash"],
        "correlation_id": record["proof_receipt"]["receipt_id"],
    }]


def test_unsigned_commit_cannot_close_even_when_native_postcondition_passed(context, monkeypatch):
    store, action, module, events = context
    monkeypatch.setattr(report_attest, "attest", lambda body: dict(body))
    result = module.apply_vetted_remediation(apply=True)
    record = result["records"][0]
    assert result["applied"] == action.dispatches == 1 and record["verified"] is True
    assert record["proof_receipt"]["receipt_authenticated"] is False
    assert store.transaction(record["transaction_id"])["state"] == "APPLIED"
    assert _verify(store, record) is False
    assert module.weaknesses()[0]["status"] == "VULNERABLE"
    assert not _proof_events(events)


@pytest.mark.parametrize("changes", [
    {"transaction_id": True}, {"transaction_id": 0}, {"transaction_id": -1},
    {"transaction_id": 2**63}, {"transaction_id": "1"},
    {"receipt_hash": "0" * 64}, {"receipt_hash": "f" * 65},
    {"receipt_id": "RCP-" + "0" * 32}, {"receipt_id": True},
    {"expected_mitre": "T1113"}, {"expected_action": "another_action"},
])
def test_reader_rejects_wrong_or_malformed_identity(context, changes):
    store, _, module, _ = context
    record = module.apply_vetted_remediation(apply=True)["records"][0]
    assert _verify(store, record, **changes) is False


@pytest.mark.parametrize("change", [
    {"verified": "true"}, {"verified": 1}, {"transaction_state": "mutating"},
    {"recovery_required": True}, {"journal_error": "inert journal failure"},
    {"proof_receipt": None}, {"proof_receipt": "not a proof"},
    {"proof_receipt": {"receipt_authenticated": True}}, {"action": None},
    {"mitre": "T1113"},
])
def test_posture_does_not_close_from_claimed_or_malformed_result(context, monkeypatch, change):
    store, _, module, events = context
    record = copy.deepcopy(module.apply_vetted_remediation(apply=True)["records"][0])
    module.record_weakness("T1112", "Inert registry finding", "HIGH")
    events.clear()
    record.update(change)
    monkeypatch.setattr(actions, "apply_remediation", lambda *_a, **_kw: {"records": [record]})
    module.apply_vetted_remediation(apply=True)
    assert module.weaknesses()[0]["status"] == "VULNERABLE"
    assert not _proof_events(events)
    assert store.transaction(1)["state"] == "APPLIED"


def test_unavailable_authentication_read_never_closes(context, monkeypatch):
    store, _, module, events = context
    def fail_read(*_a, **_kw):
        raise OSError("inert unavailable proof reader")
    monkeypatch.setattr(store, "verify_committed_application", fail_read)
    record = module.apply_vetted_remediation(apply=True)["records"][0]
    assert record["verified"] is True
    assert module.weaknesses()[0]["status"] == "VULNERABLE"
    assert not _proof_events(events)


@pytest.mark.parametrize("table,column,value", [
    ("remediation_log", "mitre", "T1113"),
    ("remediation_log", "action_key", "another_action"),
    ("remediation_log", "action_title", "another title"),
    ("remediation_log", "outcome", "reconciled_applied"),
    ("remediation_log", "verified", 0),
    ("remediation_log", "host_level", 1),
    ("remediation_log", "ts", 0.0),
    ("remediation_transactions", "trigger", "another trigger"),
    ("remediation_transactions", "state", "ROLLED_BACK"),
    ("remediation_transactions", "record_json", '{"changed":"unbound"}'),
])
def test_valid_receipt_signature_does_not_authenticate_unbound_sql_columns(
    context, table, column, value,
):
    store, _, module, _ = context
    record = module.apply_vetted_remediation(apply=True)["records"][0]
    # Table and column are fixed test parameters, never imported report text.
    store._db.execute(f"UPDATE {table} SET {column} = ? WHERE id = 1", (value,))
    store._db.commit()
    assert store.recent(1)[0]["receipt_authenticity"] is True
    assert _verify(store, record) is False


def test_signed_reconciled_applied_still_requires_passed_verification(context):
    store, _, module, _ = context
    record = module.apply_vetted_remediation(apply=True)["records"][0]
    encoded = store._db.execute("SELECT receipt_json FROM remediation_log").fetchone()[0]
    receipt = json.loads(encoded)
    receipt.update(outcome="reconciled_applied", verification="not-run", trigger="explicit_reconciliation")
    receipt.pop("_angerona_hmac", None)
    receipt = report_attest.attest(receipt)
    digest = receipt_hash(receipt)
    store._db.execute(
        "UPDATE remediation_log SET outcome=?, trigger=?, receipt_json=?, receipt_hash=?",
        ("reconciled_applied", "explicit_reconciliation", json.dumps(receipt), digest),
    )
    store._db.commit()
    record["proof_receipt"].update(receipt_hash=digest)
    assert store.recent(1)[0]["receipt_authenticity"] is True
    assert _verify(store, record) is False


def test_genuine_signed_reconciliation_uses_its_explicit_trigger(context):
    store, _, _, _ = context
    action = _InertSuccessfulAction()
    action.reversible = False
    record = {"action": action.key, "mitre": "T1112", "compensation_ready": True,
              "mutation_started": False, "marker": "inert"}
    owner = store.prepare_transaction(
        trigger="original-inert-trigger", mitre="T1112", action_key=action.key,
        action_title=action.title, host_level=False, record=record,
    )
    record.update(transaction_id=owner.transaction_id, mutation_started=True, ok=False)
    store.transition_transaction(owner, state="MUTATING", record=record)
    store.finish_transaction(owner, result="recovery_required", record=record)
    coordinator = store._bind_recovery_coordinator((action,))
    capability = store._claim_reconciliation(coordinator, owner.transaction_id)["capability"]
    assert action.verify({}, record) is True  # Inert postcondition; no host action.
    witness = store._issue_verified_recovery_proof(
        coordinator, capability, action=action, operation="verified_postcondition",
        evidence={"verified": True},
    )
    proof = store._finish_reconciliation(coordinator, capability, witness)
    record = proof.pop("record")
    record["proof_receipt"] = proof
    assert store.recent(1)[0]["trigger"] == "explicit_reconciliation"
    assert _verify(store, record) is True


@pytest.mark.parametrize("field", ["record_json", "receipt_json"])
def test_oversized_legacy_json_is_not_materialized_by_closure_reader(context, monkeypatch, field):
    store, _, module, _ = context
    record = module.apply_vetted_remediation(apply=True)["records"][0]
    bound = (remediation_log.MAX_TRANSACTION_RECORD_BYTES if field == "record_json"
             else remediation_log.MAX_APPLICATION_RECEIPT_BYTES)
    oversized = json.dumps({"padding": "é" * bound}, ensure_ascii=False)
    store._db.execute(f"UPDATE remediation_log SET {field}=?", (oversized,))
    store._db.commit()
    original_loads = json.loads
    def bounded_loads(value, *args, **kwargs):
        assert value != oversized, "oversized legacy JSON reached Python deserialization"
        return original_loads(value, *args, **kwargs)
    monkeypatch.setattr(remediation_log.json, "loads", bounded_loads)
    assert _verify(store, record) is False


def _maximum_supported_application(store):
    action = "inert_committed_closure"
    base = {"action": action, "mitre": "T1112", "compensation_ready": True,
            "mutation_started": False}
    owner = store.prepare_transaction(
        trigger="🛡" * 256, mitre="T1112", action_key=action,
        action_title="Inert Unicode boundary", host_level=False, record=base,
    )
    record = dict(base, transaction_id=owner.transaction_id, payload="", padding="")
    record.update(mutation_started=True, ok=True)
    normalized = remediation_log._normalized_terminal_record(record, result="applied")
    available = remediation_log.MAX_TRANSACTION_RECORD_BYTES - len(
        remediation_log._encode_transaction_record(normalized).encode("utf-8")
    )
    # Each astral codepoint uses twelve ASCII bytes in the existing SQL JSON
    # encoder. Keep exact full-size output without truncating a signed record.
    record["payload"], record["padding"] = "🛡" * (available // 12), "x" * (available % 12)
    store.transition_transaction(owner, state="MUTATING", record=record)
    proof = store.finish_transaction(owner, result="applied", record=record)
    record = proof.pop("record")
    record["proof_receipt"] = proof
    encoded = store._db.execute("SELECT record_json FROM remediation_log").fetchone()[0]
    assert len(encoded.encode("utf-8")) == remediation_log.MAX_TRANSACTION_RECORD_BYTES
    return record


@pytest.mark.parametrize("encoding", ["UTF-8", "UTF-16le"])
def test_maximum_supported_unicode_record_and_receipt_overhead_remain_readable(context, tmp_path, encoding):
    store, _, _, _ = context
    additional = None
    try:
        if encoding == "UTF-16le":
            path = tmp_path / "utf16-ledger.db"
            seed = sqlite3.connect(path)
            try:
                seed.execute("PRAGMA encoding='UTF-16le'")
                seed.execute("CREATE TABLE encoding_fixture (marker TEXT)")
                seed.commit()
            finally:
                seed.close()
            additional = store = remediation_log.RemediationLog(path)
        record = _maximum_supported_application(store)
        assert _verify(store, record) is True
    finally:
        if additional is not None:
            additional.close()


def test_authentic_uncommitted_terminal_rows_are_not_committed_closure(context):
    store, _, _, _ = context
    action = "inert_committed_closure"
    record = {"action": action, "mitre": "T1112", "compensation_ready": True,
              "mutation_started": False}
    owner = store.prepare_transaction(
        trigger="inert-staged", mitre="T1112", action_key=action,
        action_title="Inert staged terminal", host_level=False, record=record,
    )
    record.update(transaction_id=owner.transaction_id, mutation_started=True, ok=True)
    store.transition_transaction(owner, state="MUTATING", record=record)
    normalized = remediation_log._normalized_terminal_record(record, result="applied")
    encoded = remediation_log._encode_transaction_record(normalized)
    receipt, digest = create_receipt(
        ts=1000.0, trigger="inert-staged", mitre="T1112", action_key=action,
        outcome="applied", verified=1, host_level=False,
        record=normalized, previous_hash=GENESIS_HASH,
    )
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        store._db.execute(
            "UPDATE remediation_transactions SET state='APPLIED', updated_ts=?, "
            "record_json=?, owner_capability_sha256=NULL WHERE id=?",
            (1000.0, encoded, owner.transaction_id),
        )
        store._insert_receipt_locked(
            ts=1000.0, trigger="inert-staged", mitre="T1112", action_key=action,
            action_title="Inert staged terminal", outcome="applied", verified=1,
            host_level=False, record_json=encoded,
            receipt_json=json.dumps(receipt), receipt_hash=digest,
        )
    claimed = dict(normalized, proof_receipt={"receipt_id": receipt["receipt_id"], "receipt_hash": digest})
    assert store.recent(1)[0]["receipt_authenticity"] is True
    changes = store._db.total_changes
    assert _verify(store, claimed) is False
    assert store._db.in_transaction is True and store._db.total_changes == changes
    assert store._db.execute("SELECT state FROM remediation_transactions").fetchone()[0] == "APPLIED"
    # Only the fixture owner resolves its staged transaction, never the reader.
    store._db.rollback()
    assert store.transaction(owner.transaction_id)["state"] == "MUTATING"
    assert _verify(store, claimed) is False
    proof = store.finish_transaction(owner, result="applied", record=record)
    committed = proof.pop("record")
    committed["proof_receipt"] = proof
    assert _verify(store, committed) is True


@pytest.mark.parametrize("field,value", [("action", "x" * 129), ("mitre", "T" * 33)])
def test_truncated_receipt_metadata_does_not_authorize_full_identity(context, field, value):
    store, _, _, _ = context
    record = {"action": "inert_committed_closure", "mitre": "T1112",
              "compensation_ready": True, "mutation_started": False}
    record[field] = value
    owner = store.prepare_transaction(
        trigger="inert-long-metadata", mitre=record["mitre"], action_key=record["action"],
        action_title="Inert metadata bound", host_level=False, record=record,
    )
    record.update(transaction_id=owner.transaction_id, mutation_started=True, ok=True)
    store.transition_transaction(owner, state="MUTATING", record=record)
    proof = store.finish_transaction(owner, result="applied", record=record)
    record = proof.pop("record")
    record["proof_receipt"] = proof
    assert store.recent(1)[0]["receipt_authenticity"] is True
    assert _verify(store, record) is False


def test_reader_denies_missing_pruned_or_custody_changed_evidence(context, monkeypatch):
    store, _, module, _ = context
    record = module.apply_vetted_remediation(apply=True)["records"][0]
    original = store._assert_db_custody_locked
    monkeypatch.setattr(store, "_assert_db_custody_locked",
                        lambda: (_ for _ in ()).throw(remediation_log.RemediationCustodyError("inert")))
    assert _verify(store, record) is False
    monkeypatch.setattr(store, "_assert_db_custody_locked", original)
    store._db.execute("DELETE FROM remediation_log")
    store._db.commit()
    assert _verify(store, record) is False
