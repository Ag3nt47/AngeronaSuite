import pytest

from angerona.core.response_broker import (
    ResponseBroker, ResponseOperation, ResponseProposal,
)


def _proposal(*, dry_run=False, now=100.0, proposal_id="proposal-001"):
    return ResponseProposal(
        proposal_id, "endpoint.isolate", {"reason": "confirmed beacon"},
        "device-001", "analyst-001", now, now + 300, dry_run,
    )


def _broker(clock=lambda: 101.0):
    calls = []

    def validate(arguments):
        if set(arguments) != {"reason"} or not arguments["reason"]:
            raise ValueError("reason required")

    broker = ResponseBroker(b"k" * 32, clock=clock)
    broker.register(ResponseOperation(
        "endpoint.isolate", "high", "Restrict endpoint networking",
        "Restore the previous firewall policy", validate,
        lambda arguments: calls.append(arguments) or {"isolated": True},
    ))
    return broker, calls


def test_high_risk_response_requires_two_distinct_nonrequester_approvals():
    broker, calls = _broker()
    proposal = _proposal()
    broker.approve(proposal, "analyst-002")
    with pytest.raises(PermissionError, match="2 approval"):
        broker.execute(proposal)
    broker.approve(proposal, "analyst-003")
    receipt = broker.execute(proposal)
    assert receipt.executed and calls == [{"reason": "confirmed beacon"}]
    assert broker.verify_receipt(receipt)


def test_dry_run_validates_but_never_executes_or_requires_approval():
    broker, calls = _broker()
    receipt = broker.execute(_proposal(dry_run=True))
    assert not receipt.executed
    assert receipt.outcome == "previewed"
    assert not calls


def test_response_is_idempotent_and_conflicts_fail_closed():
    broker, calls = _broker()
    proposal = _proposal()
    broker.approve(proposal, "analyst-002")
    broker.approve(proposal, "analyst-003")
    first = broker.execute(proposal)
    assert broker.execute(proposal) == first
    assert len(calls) == 1
    conflicting = ResponseProposal(
        proposal.proposal_id, proposal.operation_id, {"reason": "different"},
        proposal.target_id, proposal.requested_by, proposal.created_at,
        proposal.expires_at, False,
    )
    with pytest.raises(ValueError, match="conflicts"):
        broker.execute(conflicting)


def test_requester_cannot_self_approve_and_expiry_is_enforced():
    broker, _calls = _broker(clock=lambda: 500.0)
    proposal = _proposal()
    with pytest.raises(PermissionError, match="own"):
        broker.approve(proposal, "analyst-001")
    with pytest.raises(PermissionError, match="expired"):
        broker.execute(proposal)
