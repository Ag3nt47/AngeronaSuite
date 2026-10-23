from dataclasses import replace
import base64
import hashlib
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from angerona.core.approval_identity import ApprovalIdentityVerifier, PrincipalCredential, SignedPrincipalProof

import pytest

from angerona.core.response_broker import (
    ResponseBroker,
    ResponseOperation,
    ResponseProposal,
)


def _private(alias):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("inert-test:" + alias).encode()).digest())


def _proof(broker, digest, alias):
    record = broker._identity_verifier.credentials[alias]
    unsigned = SignedPrincipalProof.unsigned(record, digest, 100, 1000, "1" * 32)
    return replace(unsigned, signature=base64.urlsafe_b64encode(_private(alias).sign(unsigned.signing_bytes())).decode().rstrip("="))


def _proposal(*, dry_run=False, now=100.0, proposal_id="proposal-001"):
    return ResponseProposal(
        proposal_id,
        "endpoint.isolate",
        {"reason": "confirmed beacon"},
        "device-001",
        "analyst-001",
        now,
        now + 300,
        dry_run,
    )


def _broker(tmp_path, clock=lambda: 101.0, extra_credentials=()):
    calls = []

    def validate(arguments):
        if set(arguments) != {"reason"} or not arguments["reason"]:
            raise ValueError("reason required")

    records = []
    for alias in ("analyst-001", "analyst-002", "analyst-003"):
        private = _private(alias)
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        records.append(PrincipalCredential(alias, "fixture-issuer", alias, public))
    broker = ResponseBroker(b"k" * 32, clock=clock,
        identity_verifier=ApprovalIdentityVerifier([*records, *extra_credentials], clock=clock),
        state_path=tmp_path / "broker" / "state.json")
    broker.register(
        ResponseOperation(
            "endpoint.isolate",
            "high",
            "Restrict endpoint networking",
            "Restore the previous firewall policy",
            validate,
            lambda arguments: calls.append(arguments) or {"isolated": True},
            verify_outcome=lambda arguments, result: arguments in calls and result.get("isolated") is True,
        )
    )
    return broker, calls


def _approve_both(broker, proposal):
    for alias in ("analyst-002", "analyst-003"):
        broker.approve(proposal, _proof(broker, proposal.digest, alias))


@pytest.mark.parametrize("stage", ["handler", "receipt-write"])
def test_close_retains_exclusive_custody_through_active_action_and_receipt(tmp_path, monkeypatch, stage):
    from angerona.core.file_lease import ExclusiveFileLeaseError
    broker, calls = _broker(tmp_path)
    proposal = _proposal()
    _approve_both(broker, proposal)
    entered, release = threading.Event(), threading.Event()
    outcome = []
    lease = broker._lease
    retired = []
    close_lease = lease.close
    monkeypatch.setattr(lease, "close", lambda: retired.append(True) or close_lease())
    if stage == "handler":
        operation = broker._operations[proposal.operation_id]
        def blocked(arguments):
            entered.set()
            assert release.wait(5)
            return operation.handler(arguments)
        broker._operations[proposal.operation_id] = replace(operation, handler=blocked)
    else:
        save = broker._save_state
        def blocked():
            if broker._receipts:
                entered.set()
                assert release.wait(5)
            save()
        monkeypatch.setattr(broker, "_save_state", blocked)
    def run():
        try:
            outcome.append(broker.execute(proposal))
        except BaseException as error:
            outcome.append(error)
    thread = threading.Thread(target=run)
    try:
        thread.start()
        assert entered.wait(3), outcome
        began = time.monotonic()
        assert broker.close(.01) is False
        status = broker.approval_status()
        assert time.monotonic() - began < .5
        assert status["closing"] and status["shutdown_pending"] and status["durable"]
        with pytest.raises(ExclusiveFileLeaseError):
            _broker(tmp_path)
        assert retired == []
    finally:
        release.set()
        thread.join(5)
        assert not thread.is_alive()
        assert broker.close(1)
    assert retired == [True]
    assert len(outcome) == 1 and not isinstance(outcome[0], BaseException), outcome
    assert broker.verify_receipt(outcome[0]) and len(calls) == 1
    assert not broker.approval_status()["shutdown_pending"]
    restarted, later_calls = _broker(tmp_path)
    try:
        assert restarted.execute(proposal) == outcome[0] and later_calls == []
    finally:
        restarted.close()


def test_reentrant_zero_timeout_close_does_not_release_its_own_action(tmp_path):
    from angerona.core.file_lease import ExclusiveFileLeaseError
    broker, _calls = _broker(tmp_path)
    proposal = _proposal()
    _approve_both(broker, proposal)
    operation = broker._operations[proposal.operation_id]
    observed = []
    def close_from_handler(arguments):
        observed.append(broker.close(0))
        assert broker.approval_status()["shutdown_pending"]
        with pytest.raises(ExclusiveFileLeaseError):
            _broker(tmp_path)
        return operation.handler(arguments)
    broker._operations[proposal.operation_id] = replace(operation, handler=close_from_handler)
    try:
        receipt = broker.execute(proposal)
        assert observed == [False] and broker.verify_receipt(receipt)
        assert broker.close(0) and not broker.approval_status()["durable"]
    finally:
        broker.close()


@pytest.mark.parametrize("queued", ["execute", "approve"])
def test_close_rejects_already_queued_work_before_validator_or_mutation(tmp_path, monkeypatch, queued):
    broker, calls = _broker(tmp_path)
    first, next_plan = _proposal(), _proposal(proposal_id="proposal-002")
    _approve_both(broker, first)
    entered, release, queued_lock = threading.Event(), threading.Event(), threading.Event()
    outcome, rejected, validations = [], [], []
    operation = broker._operations[first.operation_id]
    def blocked(arguments):
        entered.set()
        assert release.wait(5)
        return operation.handler(arguments)
    def validate(arguments):
        validations.append(dict(arguments))
        operation.validator(arguments)
    broker._operations[first.operation_id] = replace(operation, handler=blocked, validator=validate)
    real_lock = broker._lock
    class ObservedLock:
        def acquire(self, *args, **kwargs):
            if threading.current_thread().name == "queued-broker-work":
                queued_lock.set()
            return real_lock.acquire(*args, **kwargs)
        def release(self):
            return real_lock.release()
    monkeypatch.setattr(broker, "_lock", ObservedLock())
    def run():
        try:
            outcome.append(broker.execute(first))
        except BaseException as error:
            outcome.append(error)
    def queue():
        try:
            if queued == "execute":
                broker.execute(next_plan)
            else:
                broker.approve(next_plan, _proof(broker, next_plan.digest, "analyst-002"))
        except BaseException as error:
            rejected.append(error)
    owner = threading.Thread(target=run)
    waiter = threading.Thread(target=queue, name="queued-broker-work")
    try:
        owner.start()
        assert entered.wait(3), outcome
        waiter.start()
        assert queued_lock.wait(3), rejected
        assert not broker.close(.01)
        waiter.join(1)
        assert not waiter.is_alive() and len(rejected) == 1 and isinstance(rejected[0], PermissionError)
        assert owner.is_alive() and len(validations) == 1 and calls == []
    finally:
        release.set()
        owner.join(5)
        if waiter.ident is not None:
            waiter.join(5)
        assert not owner.is_alive() and not waiter.is_alive()
        broker.close(1)
    assert len(outcome) == 1 and not isinstance(outcome[0], BaseException), outcome
    assert len(calls) == 1 and len(validations) == 1


@pytest.mark.parametrize("change", ["proposal-expired", "proof-expired", "revoked", "clock-rollback", "closing"])
def test_durable_burn_rechecks_live_authority_before_handler_and_keeps_attempt_spent(tmp_path, monkeypatch, change):
    clock = [101.0]
    broker, calls = _broker(tmp_path, clock=lambda: clock[0])
    proposal = _proposal()
    for alias in ("analyst-002", "analyst-003"):
        proof = _proof(broker, proposal.digest, alias)
        if change == "proof-expired":
            unsigned = replace(proof, expires_at=102.0, signature="")
            proof = replace(unsigned, signature=base64.urlsafe_b64encode(
                _private(alias).sign(unsigned.signing_bytes())).decode().rstrip("="))
        broker.approve(proposal, proof)
    save = broker._save_state
    def after_burn():
        save()
        if not broker._attempts or broker._receipts:
            return
        if change == "proposal-expired":
            clock[0] = 401
        elif change == "proof-expired":
            clock[0] = 103
        elif change == "revoked":
            broker._identity_verifier.revoke("analyst-002")
        elif change == "clock-rollback":
            clock[0] = 100.5
        elif change == "closing":
            assert broker.close(0) is False
    monkeypatch.setattr(broker, "_save_state", after_burn)
    try:
        with pytest.raises(PermissionError):
            broker.execute(proposal)
        assert calls == [] and broker._attempts[proposal.proposal_id] == proposal.digest
    finally:
        broker.close()
    restarted, later_calls = _broker(tmp_path)
    try:
        with pytest.raises(PermissionError, match="Prior response attempt"):
            restarted.execute(proposal)
        assert later_calls == []
    finally:
        restarted.close()


def test_high_risk_response_requires_two_distinct_nonrequester_approvals(tmp_path):
    broker, calls = _broker(tmp_path)
    proposal = _proposal()
    broker.approve(proposal, _proof(broker, proposal.digest, "analyst-002"))
    with pytest.raises(PermissionError, match="2 approval"):
        broker.execute(proposal)
    broker.approve(proposal, _proof(broker, proposal.digest, "analyst-003"))
    receipt = broker.execute(proposal)
    assert receipt.executed and calls == [{"reason": "confirmed beacon"}]
    assert broker.verify_receipt(receipt)
    assert not broker.verify_receipt(replace(receipt, target_id="device-002"))
    assert not broker.verify_receipt(replace(receipt, receipt_hmac="malformed"))
    assert not ResponseBroker(b"x" * 32).verify_receipt(receipt)


def test_dry_run_validates_but_never_executes_or_requires_approval(tmp_path):
    broker, calls = _broker(tmp_path)
    receipt = broker.execute(_proposal(dry_run=True))
    assert not receipt.executed
    assert receipt.outcome == "previewed"
    assert not calls


def test_response_is_idempotent_and_conflicts_fail_closed(tmp_path):
    broker, calls = _broker(tmp_path)
    proposal = _proposal()
    broker.approve(proposal, _proof(broker, proposal.digest, "analyst-002"))
    broker.approve(proposal, _proof(broker, proposal.digest, "analyst-003"))
    first = broker.execute(proposal)
    assert broker.execute(proposal) == first
    assert len(calls) == 1
    conflicting = ResponseProposal(
        proposal.proposal_id,
        proposal.operation_id,
        {"reason": "different"},
        proposal.target_id,
        proposal.requested_by,
        proposal.created_at,
        proposal.expires_at,
        False,
    )
    with pytest.raises(ValueError, match="conflicts"):
        broker.execute(conflicting)


def test_requester_cannot_self_approve_and_expiry_is_enforced(tmp_path):
    broker, _calls = _broker(tmp_path, clock=lambda: 500.0)
    proposal = _proposal()
    with pytest.raises(PermissionError, match="own"):
        broker.approve(proposal, _proof(broker, proposal.digest, "analyst-001"))
    with pytest.raises(PermissionError, match="expired"):
        broker.execute(proposal)


def test_response_contract_rejects_type_coercion_and_nonfinite_clock(tmp_path):
    with pytest.raises(ValueError, match="dry-run"):
        _proposal(dry_run=0)
    with pytest.raises(ValueError, match="JSON-safe"):
        ResponseProposal(
            "proposal-001",
            "endpoint.isolate",
            {"reason": object()},
            "device-001",
            "analyst-001",
            100,
            200,
            True,
        )
    broker, _calls = _broker(tmp_path, clock=lambda: float("nan"))
    with pytest.raises(ValueError, match="clock"):
        broker.approve(_proposal(), _proof(broker, _proposal().digest, "analyst-002"))


def test_legacy_labels_cannot_authorize_but_preview_stays_available():
    broker = ResponseBroker(b"k" * 32, clock=lambda: 110)
    broker.register(ResponseOperation("endpoint.isolate", "high", "Isolate", "Restore",
                                      lambda _args: None, lambda _args: pytest.fail("No authority")))
    assert broker.approval_status()["state"] == "unavailable"
    with pytest.raises(PermissionError, match="identity unavailable"):
        broker.approve(_proposal(), "analyst-002")
    assert not broker.execute(_proposal(dry_run=True)).executed


@pytest.mark.parametrize("same_key,same_subject", [(True, False), (False, True)])
def test_aliases_and_rotations_cannot_supply_two_live_approvals(tmp_path, same_key, same_subject):
    first = _private("analyst-002")
    private = first if same_key else _private("rotated")
    record = PrincipalCredential("operator-alias", "fixture-issuer",
        "analyst-002" if same_subject else "other-operator",
        private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    broker, calls = _broker(tmp_path, extra_credentials=[record])
    proposal = _proposal()
    assert broker.approve(proposal, _proof(broker, proposal.digest, "analyst-002")) == 1
    unsigned = SignedPrincipalProof.unsigned(record, proposal.digest, 100, 1000, "2" * 32)
    proof = replace(unsigned, signature=base64.urlsafe_b64encode(private.sign(unsigned.signing_bytes())).decode().rstrip("="))
    assert broker.approve(proposal, proof) == 1
    with pytest.raises(PermissionError, match="2 approval"):
        broker.execute(proposal)
    assert calls == []
    broker.close()


def test_revocations_and_terminal_receipts_survive_real_store_restart(tmp_path):
    proposal = _proposal()
    broker, calls = _broker(tmp_path)
    for alias in ("analyst-002", "analyst-003"):
        broker.approve(proposal, _proof(broker, proposal.digest, alias))
    receipt = broker.execute(proposal)
    assert receipt.outcome == "completed" and len(calls) == 1
    broker.close()
    restored, later_calls = _broker(tmp_path)
    assert restored.execute(proposal) == receipt and later_calls == []
    restored.revoke_credential("analyst-003")
    restored.close()
    revoked, final_calls = _broker(tmp_path)
    new_proposal = replace(proposal, proposal_id="proposal-002")
    revoked.approve(new_proposal, _proof(revoked, new_proposal.digest, "analyst-002"))
    with pytest.raises(PermissionError, match="revoked"):
        revoked.approve(new_proposal, _proof(revoked, new_proposal.digest, "analyst-003"))
    with pytest.raises(PermissionError, match="2 approval"):
        revoked.execute(new_proposal)
    assert final_calls == []
    revoked.close()


def test_uncertain_action_is_burned_before_handler_and_cannot_replay_after_restart(tmp_path):
    proposal = _proposal()
    broker, calls = _broker(tmp_path)
    def fail(_arguments):
        calls.append("attempted")
        raise OSError("inert action uncertainty")
    operation = broker._operations[proposal.operation_id]
    broker._operations[proposal.operation_id] = replace(operation, handler=fail)
    for alias in ("analyst-002", "analyst-003"):
        broker.approve(proposal, _proof(broker, proposal.digest, alias))
    with pytest.raises(OSError, match="uncertainty"):
        broker.execute(proposal)
    broker.close()
    restored, later_calls = _broker(tmp_path)
    with pytest.raises(PermissionError, match="Prior response attempt"):
        restored.execute(proposal)
    assert calls == ["attempted"] and later_calls == []
    restored.close()


def test_outcome_verifier_is_required_and_failed_postcondition_is_not_success(tmp_path):
    proposal = _proposal()
    broker, calls = _broker(tmp_path)
    operation = broker._operations[proposal.operation_id]
    broker._operations[proposal.operation_id] = replace(operation, verify_outcome=None)
    for alias in ("analyst-002", "analyst-003"):
        broker.approve(proposal, _proof(broker, proposal.digest, alias))
    with pytest.raises(PermissionError, match="outcome verifier"):
        broker.execute(proposal)
    assert calls == []
    broker._operations[proposal.operation_id] = replace(operation, verify_outcome=lambda _args, _result: False)
    receipt = broker.execute(proposal)
    assert receipt.executed and receipt.outcome == "verification-failed" and len(calls) == 1
    assert broker.execute(proposal) == receipt and len(calls) == 1
    broker.close()


def test_deleted_or_tampered_state_cannot_reset_live_authority(tmp_path):
    broker, _calls = _broker(tmp_path)
    path = broker._state_path
    broker.close()
    path.unlink()
    with pytest.raises(ValueError, match="missing or inconsistent"):
        _broker(tmp_path)


def test_nested_arguments_cannot_change_after_approval_while_handler_runs(tmp_path):
    import threading
    entered, release = threading.Event(), threading.Event()
    broker, calls = _broker(tmp_path)
    proposal = replace(_proposal(), arguments={"reason": {"value": "approved"}})
    approved_digest = proposal.digest
    operation = broker._operations[proposal.operation_id]
    outcomes, errors = [], []
    def handler(arguments):
        entered.set()
        if not release.wait(10):
            raise TimeoutError("inert test barrier")
        calls.append(arguments)
        return {"isolated": True}
    broker._operations[proposal.operation_id] = replace(operation, handler=handler)
    for alias in ("analyst-002", "analyst-003"):
        broker.approve(proposal, _proof(broker, approved_digest, alias))
    def execute():
        try:
            outcomes.append(broker.execute(proposal))
        except BaseException as error:
            errors.append(error)
    worker = threading.Thread(target=execute)
    worker.start()
    try:
        assert entered.wait(5)
        proposal.arguments["reason"]["value"] = "changed after approval"
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive() and not errors
    assert calls == [{"reason": {"value": "approved"}}]
    assert outcomes[0].proposal_digest == approved_digest
    broker.close()
