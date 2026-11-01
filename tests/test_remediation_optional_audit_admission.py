"""Optional audit admission uses owned temporary SQLite and inert actions only."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
from types import SimpleNamespace

import pytest

from angerona.core import remediation_log, report_attest
from angerona.core.remediation_receipts import receipt_hash
from angerona.modules import remediation_actions as actions


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    key = tmp_path / "bus.key"
    key.write_text(bytes(range(32)).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    store = remediation_log.RemediationLog(tmp_path / "flight-recorder.db")
    monkeypatch.setattr(remediation_log, "_SINGLETON", store)
    monkeypatch.setattr(remediation_log.time, "time", lambda: 1793500000.0)
    monkeypatch.setattr(actions, "run_hidden", lambda *_a, **_kw: pytest.fail("native command"))
    try:
        yield store
    finally:
        store.close()


def _stored_size(store):
    row = store._db.execute(
        "SELECT trigger,mitre,action_key,action_title,outcome,record_json,receipt_json,receipt_hash "
        "FROM remediation_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return 32 + sum(len(value.encode("utf-8")) for value in row if value is not None)


def _state(store):
    return (
        store._db.execute("SELECT * FROM remediation_log ORDER BY id").fetchall(),
        store._db.execute("SELECT * FROM remediation_transactions ORDER BY id").fetchall(),
        store._db.execute("SELECT * FROM remediation_reconciliation_claims").fetchall(),
        store._writes, store._db.in_transaction,
    )


def _counts(store, **changes):
    expected = dict(attempted=0, recorded=0, rejected=0, rejected_oversize=0,
                    rejected_invalid=0, unavailable=0, persistence_unknown=0, pending=0)
    expected.update(changes)
    snapshot = store.optional_audit_snapshot()
    for name, value in expected.items():
        assert snapshot[name] == value
    assert snapshot["scope"] == "instance-lifetime"
    assert snapshot["durable"] is snapshot["response_authorized"] is False
    assert snapshot["attempted"] == sum(snapshot[name] for name in (
        "recorded", "rejected", "unavailable", "persistence_unknown", "pending"
    ))
    return snapshot


def test_exact_whole_entry_limit_and_one_byte_over_preserve_chain_and_state(ledger):
    first = ledger.log(record={"text": ""})
    assert set(first) == {"receipt_id", "receipt_hash", "receipt_authenticated"}
    padding = remediation_log.OPTIONAL_AUDIT_ENTRY_LIMIT_BYTES - _stored_size(ledger)
    accepted = ledger.log(record={"text": "a" * padding})
    assert _stored_size(ledger) == 65536
    assert accepted["receipt_authenticated"] is True
    before = _state(ledger)

    with pytest.raises(remediation_log.OptionalAuditRejected) as held:
        ledger.log(record={"text": "a" * (padding + 1)})

    assert held.value.reason == "entry_too_large"
    assert held.value.entry_bytes == 65537 and held.value.limit_bytes == 65536
    assert _state(ledger) == before
    ledger.log(record={"text": "following signed entry"})
    proof = ledger.verify_receipt_chain()
    assert proof["valid"] is True and proof["verified_receipts"] == 3
    assert _counts(ledger, attempted=4, recorded=3, rejected=1,
                   rejected_oversize=1)["coverage_gap"] is True


@pytest.mark.parametrize("field", ["trigger", "mitre", "action_key", "action_title", "outcome"])
def test_raw_metadata_is_included_even_when_receipt_metadata_is_shorter(ledger, field):
    before = _state(ledger)
    with pytest.raises(remediation_log.OptionalAuditRejected) as held:
        ledger.log(**{field: "雪" * 23000})
    assert held.value.reason == "entry_too_large" and held.value.entry_bytes > 69000
    assert "雪" not in str(held.value)
    assert _state(ledger) == before
    _counts(ledger, attempted=1, rejected=1, rejected_oversize=1)


def test_actual_escaped_json_receipt_hash_and_scalar_overhead_are_counted(ledger):
    ledger.log(trigger="雪", action_title="é", record={"text": "雪" * 10})
    raw = ledger._db.execute(
        "SELECT trigger,action_title,record_json,receipt_json,receipt_hash FROM remediation_log"
    ).fetchone()
    assert raw[0] == "雪" and raw[1] == "é"
    assert raw[2] == json.dumps({"text": "雪" * 10}, default=str)
    assert "\\u96ea" in raw[2] and "_angerona_hmac" in raw[3] and len(raw[4]) == 64
    # The record alone fits, but the actual receipt and metadata make it too big.
    record = {"text": "a" * (65536 - 40)}
    assert len(json.dumps(record).encode("utf-8")) < 65536
    with pytest.raises(remediation_log.OptionalAuditRejected) as held:
        ledger.log(record=record)
    assert held.value.entry_bytes > 65536
    assert _counts(ledger, attempted=2, recorded=1, rejected=1,
                   rejected_oversize=1)["scalar_allowance_bytes"] == 32


def test_actual_receipt_serialization_is_measured_instead_of_an_estimated_overhead(ledger, monkeypatch):
    original = remediation_log.create_receipt

    def expanded_receipt(**kwargs):
        receipt, _digest = original(**kwargs)
        receipt["fixture_extension"] = "x" * 65536
        receipt = report_attest.attest(receipt)
        return receipt, receipt_hash(receipt)

    monkeypatch.setattr(remediation_log, "create_receipt", expanded_receipt)
    before = _state(ledger)
    with pytest.raises(remediation_log.OptionalAuditRejected) as held:
        ledger.log(record=None)
    assert held.value.entry_bytes > 65536 and _state(ledger) == before
    _counts(ledger, attempted=1, rejected=1, rejected_oversize=1)


def test_existing_oversized_legacy_history_is_not_rewritten_or_deleted(ledger):
    legacy = json.dumps({"old": "x" * 70000})
    ledger._db.execute("INSERT INTO remediation_log(ts,record_json) VALUES (?,?)", (1.0, legacy))
    ledger._db.commit()
    before = ledger._db.execute("SELECT * FROM remediation_log WHERE id=1").fetchone()

    assert ledger.log(record={"new": "within limit"})["receipt_authenticated"] is True

    assert ledger._db.execute("SELECT * FROM remediation_log WHERE id=1").fetchone() == before
    _counts(ledger, attempted=1, recorded=1)


@pytest.mark.parametrize("arguments", [
    {"trigger": None}, {"mitre": 123}, {"mitre": 0}, {"mitre": False}, {"action_key": b"blob"},
    {"action_title": ["not text"]}, {"outcome": True}, {"verified": 1.0},
    {"verified": 2**63}, {"verified": -(2**63) - 1}, {"record": ["not a dict"]},
    {"record": {("invalid", "key"): "value"}}, {"record": {"bad": "\ud800"}},
])
def test_invalid_entries_are_typed_before_insert_without_private_error_data(ledger, arguments):
    before = _state(ledger)
    with pytest.raises(remediation_log.OptionalAuditRejected) as held:
        ledger.log(**arguments)
    assert held.value.reason == "invalid_entry" and held.value.entry_bytes is None
    assert "not text" not in str(held.value) and "value" not in str(held.value)
    assert _state(ledger) == before
    _counts(ledger, attempted=1, rejected=1, rejected_invalid=1)


def test_circular_record_is_a_bounded_invalid_entry_without_insert(ledger):
    record = {}
    record["cycle"] = record
    before = _state(ledger)
    with pytest.raises(remediation_log.OptionalAuditRejected) as held:
        ledger.log(record=record)
    assert held.value.reason == "invalid_entry" and _state(ledger) == before
    _counts(ledger, attempted=1, rejected=1, rejected_invalid=1)


@pytest.mark.parametrize("field", ["trigger", "mitre", "action_key", "action_title", "outcome"])
@pytest.mark.parametrize("mechanism", ["conform", "registered"])
def test_text_subclasses_cannot_bind_different_bytes_than_the_entry_measurement(
    ledger, field, mechanism
):
    calls = []

    class AdaptedText(str):
        def __conform__(self, _protocol):
            calls.append("conform")
            return "x" * 70000

    def adapter(_value):
        calls.append("registered")
        return "x" * 70000

    adapter_key = (AdaptedText, sqlite3.PrepareProtocol)
    missing = object()
    original = sqlite3.adapters.get(adapter_key, missing)
    if mechanism == "registered":
        sqlite3.register_adapter(AdaptedText, adapter)
    before = _state(ledger)
    try:
        with pytest.raises(remediation_log.OptionalAuditRejected) as held:
            ledger.log(**{field: AdaptedText("") if field == "mitre" else AdaptedText("small")})
        assert held.value.reason == "invalid_entry" and calls == []
        assert _state(ledger) == before
        _counts(ledger, attempted=1, rejected=1, rejected_invalid=1)
    finally:
        if original is missing:
            sqlite3.adapters.pop(adapter_key, None)
        else:
            sqlite3.adapters[adapter_key] = original


@pytest.mark.parametrize("kind", [str, int, float, type(None)])
def test_known_builtin_adapters_cannot_change_accounted_text_scalar_or_null_bytes(ledger, kind):
    calls = []

    def adapter(_value):
        calls.append(True)
        return "x" * 70000

    key = (kind, sqlite3.PrepareProtocol)
    missing = object()
    original = sqlite3.adapters.get(key, missing)
    before = _state(ledger)
    sqlite3.register_adapter(kind, adapter)
    try:
        with pytest.raises(remediation_log.OptionalAuditRejected) as held:
            ledger.log(record=None)
        assert held.value.reason == "invalid_entry" and calls == []
    finally:
        if original is missing:
            sqlite3.adapters.pop(key, None)
        else:
            sqlite3.adapters[key] = original
    # No parameterized SQLite assertions run while the custom adapter exists.
    assert _state(ledger) == before
    _counts(ledger, attempted=1, rejected=1, rejected_invalid=1)


def test_unrelated_adapters_remain_allowed_and_are_not_executed(ledger):
    class Unrelated:
        pass

    key = (Unrelated, sqlite3.PrepareProtocol)
    missing = object()
    original = sqlite3.adapters.get(key, missing)
    sqlite3.register_adapter(Unrelated, lambda _value: pytest.fail("unrelated adapter invoked"))
    try:
        assert ledger.log(record=None)["receipt_authenticated"] is True
    finally:
        if original is missing:
            sqlite3.adapters.pop(key, None)
        else:
            sqlite3.adapters[key] = original
    _counts(ledger, attempted=1, recorded=1)


@pytest.mark.parametrize("verified", [False, True, -1, 0, 1, -(2**63), 2**63 - 1])
def test_ordinary_integer_and_legacy_boolean_verified_values_remain_accepted(ledger, verified):
    result = ledger.log(mitre=None, verified=verified, host_level=True)
    row = ledger._db.execute("SELECT mitre,verified,host_level FROM remediation_log").fetchone()
    assert row == ("-", int(verified), 1)
    assert result["receipt_authenticated"] is True
    _counts(ledger, attempted=1, recorded=1)


def test_snapshot_is_copied_and_never_uses_sql_paths_clocks_or_writer_lock(ledger, monkeypatch):
    ledger.log(record={"observed": "before cached read"})

    class Forbidden:
        def __enter__(self):
            pytest.fail("writer lock entered")

        def __getattr__(self, name):
            pytest.fail(f"database access: {name}")

    with monkeypatch.context() as patch:
        patch.setattr(ledger, "_lock", Forbidden())
        patch.setattr(ledger, "_db", Forbidden())
        patch.setattr(ledger, "_path", Forbidden())
        patch.setattr(ledger, "_assert_db_custody_locked", lambda: pytest.fail("path work"))
        patch.setattr(remediation_log.time, "time", lambda: pytest.fail("wall clock"))
        patch.setattr(remediation_log.time, "monotonic", lambda: pytest.fail("monotonic clock"))
        view = ledger.optional_audit_snapshot()
        view["attempted"] = 99
        assert ledger.optional_audit_snapshot()["attempted"] == 1
    _counts(ledger, attempted=1, recorded=1)
    second = remediation_log.RemediationLog(ledger._path.parent / "other.db")
    try:
        assert second.optional_audit_snapshot()["attempted"] == 0
    finally:
        second.close()


def test_pending_call_is_visible_without_waiting_for_the_sqlite_writer_lock(ledger, monkeypatch):
    entered = threading.Event()
    errors = []
    original = ledger._note_optional_audit

    def note(result, reason=""):
        original(result, reason)
        if result == "attempted":
            entered.set()

    def write():
        try:
            ledger.log(record={"text": "owned concurrent fixture"})
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(ledger, "_note_optional_audit", note)
    worker = threading.Thread(target=write, name="OptionalAuditPendingFixture")
    ledger._lock.acquire()
    try:
        worker.start()
        assert entered.wait(3)
        _counts(ledger, attempted=1, pending=1)
    finally:
        ledger._lock.release()
        if worker.ident is not None:
            worker.join(5)
    assert not worker.is_alive() and not errors
    _counts(ledger, attempted=1, recorded=1)


@pytest.mark.parametrize("commit_then_raise", [False, True])
def test_commit_exception_is_persistence_unknown_without_retry_or_loss_claim(
    ledger, commit_then_raise
):
    original = ledger._db

    class Fault:
        commits = 0

        def __getattr__(self, name):
            return getattr(original, name)

        def commit(self):
            self.commits += 1
            if commit_then_raise:
                original.commit()
            raise sqlite3.OperationalError("private fixture database error")

    fault = Fault()
    ledger._db = fault
    with pytest.raises(sqlite3.OperationalError):
        ledger.log(record={"text": "unknown commit outcome"})
    assert fault.commits == 1
    with closing(sqlite3.connect(str(ledger._path))) as reader:
        assert reader.execute("SELECT COUNT(*) FROM remediation_log").fetchone()[0] == int(commit_then_raise)
    view = _counts(ledger, attempted=1, persistence_unknown=1)
    assert view["coverage_gap"] is True and "private" not in json.dumps(view)
    original.rollback()  # Retire only this fixture's uncommitted transaction.


def test_successful_commit_stays_recorded_when_separate_retention_fails(ledger, monkeypatch):
    monkeypatch.setattr(remediation_log, "PRUNE_EVERY", 1)
    monkeypatch.setattr(ledger, "_prune_locked", lambda: (_ for _ in ()).throw(OSError("fixture")))
    assert ledger.log()["receipt_authenticated"] is True
    assert ledger.verify_receipt_chain()["valid"] is True
    _counts(ledger, attempted=1, recorded=1)


class _InertAction(actions.RemediationAction):
    key = "optional_audit_inert"
    title = "Optional audit inert fixture"
    host_level = False
    durable_transaction = True
    reversible = True
    proposal_reason = "inert proposal"

    def begin_transaction(self, weakness, quarantine_dir):
        del weakness, quarantine_dir
        return {"action": self.key, "compensation_ready": True, "marker": "inert",
                "mutation_started": False}

    def apply_transactional(self, *_args):
        pytest.fail("optional audit branches must not dispatch mutation")

    def verify(self, *_args):
        return True

    def rollback(self, record):
        return {"ok": record.get("marker") == "inert"}

    def verify_rollback(self, record):
        return record.get("marker") == "inert"


def _pending(store, action):
    record = action.begin_transaction({}, None)
    record["mitre"] = "T1112"
    owner = store.prepare_transaction(trigger="inert", mitre="T1112", action_key=action.key,
        action_title=action.title, host_level=False, record=record)
    record.update(transaction_id=owner.transaction_id, mutation_started=True, ok=True)
    store.transition_transaction(owner, state="MUTATING", record=record)
    return owner, record


def test_tiny_optional_cap_cannot_block_terminal_or_reconciliation_receipts(ledger, monkeypatch):
    monkeypatch.setattr(remediation_log, "OPTIONAL_AUDIT_ENTRY_LIMIT_BYTES", 1)
    with pytest.raises(remediation_log.OptionalAuditRejected):
        ledger.log(record={"optional": "held"})
    action = _InertAction()
    owner, record = _pending(ledger, action)
    before = _state(ledger)
    with pytest.raises(remediation_log.OptionalAuditRejected):
        ledger.log(record={"optional": "cannot change a live owner"})
    assert _state(ledger) == before and owner._retired is False
    applied = ledger.finish_transaction(owner, result="applied", record=record)
    assert applied["receipt_authenticated"] is True and owner._retired
    owner, record = _pending(ledger, action)
    ledger.finish_transaction(owner, result="rollback_failed", record=record)
    coordinator = ledger._bind_recovery_coordinator((action,))
    capability = ledger._claim_reconciliation(coordinator, owner.transaction_id)["capability"]
    witness = ledger._issue_verified_recovery_proof(
        coordinator, capability, action=action, operation="verified_rollback",
        evidence={"ok": True, "marker": "inert"},
    )
    before = _state(ledger)
    with pytest.raises(remediation_log.OptionalAuditRejected):
        ledger.log(record={"optional": "cannot change a recovery claim"})
    assert _state(ledger) == before and capability._retired is witness._retired is False
    result = ledger._finish_reconciliation(coordinator, capability, witness)
    assert result["receipt_authenticated"] is True and capability._retired and witness._retired
    assert ledger.verify_receipt_chain()["verified_receipts"] == 3
    _counts(ledger, attempted=3, rejected=3, rejected_oversize=3)


BRANCHES = ["proposal", "skipped", "dry_run", "host_gate", "circuit", "prepare", "mutating"]


@pytest.mark.parametrize("branch", BRANCHES)
@pytest.mark.parametrize("audit_result", ["recorded", "rejected", "unavailable", "exception", "none", "partial"])
def test_all_optional_audit_branches_surface_results_without_dispatching_actions(
    ledger, tmp_path, monkeypatch, branch, audit_result
):
    action = _InertAction()
    action.host_level = branch == "host_gate"

    class InertLedger:
        def unresolved_transactions(self):
            return [{"transaction_id": 9}] if branch == "circuit" else []

        def prepare_transaction(self, **_kwargs):
            if branch == "prepare":
                raise RuntimeError("inert preparation failure")
            return SimpleNamespace(transaction_id=9)

        def transition_transaction(self, *_args, **_kwargs):
            assert branch == "mutating"
            raise RuntimeError("inert transition failure")

        def finish_transaction(self, *_args, **_kwargs):
            pytest.fail("no mutation completion in these optional branches")

        def log(self, **kwargs):
            if audit_result == "exception":
                raise sqlite3.OperationalError("private simulated commit uncertainty")
            if audit_result == "none":
                return None
            if audit_result == "partial":
                return {"receipt_authenticated": True}
            return ledger.log(**kwargs)

    source = InertLedger()
    if audit_result == "unavailable":
        source.log = None
    if audit_result == "rejected":
        monkeypatch.setattr(remediation_log, "OPTIONAL_AUDIT_ENTRY_LIMIT_BYTES", 1)
    monkeypatch.setattr(remediation_log, "get_log", lambda: source)
    decision = (actions.RemediationDecision(proposal=action) if branch == "proposal"
                else actions.RemediationDecision(reason="no vetted action") if branch == "skipped"
                else actions.RemediationDecision(action=action))
    monkeypatch.setattr(actions, "classify_remediation", lambda _w: decision)

    result = actions.apply_remediation([{"mitre_id": "T1112"}], tmp_path,
        apply=branch != "dry_run", allow_host=False, trigger="inert")

    expected = "persistence_unknown" if audit_result in {"exception", "none", "partial"} else audit_result
    assert result["applied"] == 0
    assert result["skipped"] == int(branch != "dry_run")
    assert result["optional_audit"] == {
        "schema": 1, "attempted": 1, "recorded": int(expected == "recorded"),
        "rejected": int(expected == "rejected"), "unavailable": int(expected == "unavailable"),
        "persistence_unknown": int(expected == "persistence_unknown"), "response_authorized": False,
    }
    assert "private" not in json.dumps(result["optional_audit"])
    assert all("proof_receipt" not in record for record in result["records"])


def test_unsigned_writer_ack_is_recorded_but_never_grants_authentication(ledger, tmp_path, monkeypatch):
    monkeypatch.setattr(report_attest, "attest", lambda body: dict(body))
    monkeypatch.setattr(actions, "classify_remediation", lambda _w: actions.RemediationDecision())
    result = actions.apply_remediation([{}], tmp_path, apply=False)
    assert result["optional_audit"]["recorded"] == 1
    assert result["optional_audit"]["response_authorized"] is False
    assert ledger.recent(1)[0]["receipt_authenticity"] is False


def test_rejected_optional_audit_cannot_close_posture_finding(ledger, tmp_path, monkeypatch):
    from angerona.modules.posture_hardening import PostureHardening

    action = _InertAction()
    action.host_level = True
    monkeypatch.setattr(remediation_log, "OPTIONAL_AUDIT_ENTRY_LIMIT_BYTES", 1)
    monkeypatch.setattr(actions, "_auto_apply_enabled", lambda: False)
    monkeypatch.setattr(actions, "classify_remediation", lambda _w: actions.RemediationDecision(action=action))
    monkeypatch.setattr(PostureHardening, "_log_attempt", lambda *_a, **_kw: None)
    module = PostureHardening(data_dir=tmp_path)
    events = []
    monkeypatch.setattr(module, "emit", lambda *_a, **kwargs: events.append(kwargs))
    module.record_weakness("T1112", "Inert audit finding", "HIGH")

    result = module.apply_vetted_remediation(apply=True)

    assert result["applied"] == 0 and result["optional_audit"]["rejected"] == 1
    assert module.weaknesses()[0]["status"] == "VULNERABLE"
    assert not any(event.get("relation") == "verification-proof" for event in events)
    assert ledger._db.execute("SELECT COUNT(*) FROM remediation_transactions").fetchone() == (0,)
