from angerona.core.usb_policy import UsbApprovalPolicy


def test_cancelled_approval_stays_gated_across_pin_reset() -> None:
    policy = UsbApprovalPolicy(pin_loader=lambda: "246810")
    approval = policy.request("Z:\\")
    assert policy.verify(approval.approval_id, "246810").approved

    policy.cancel(approval.approval_id)
    assert policy._trust_state_for_target("Z:\\file.txt") == "denied"
    policy._on_pin_reset()

    assert not policy.verify(approval.approval_id, "246810").approved
    assert policy._trust_state_for_target("Z:\\file.txt") == "pending"
    replacement = policy.pending()[0]
    assert replacement.approval_id != approval.approval_id
    policy.cancel(approval.approval_id)
    assert policy._trust_state_for_target("Z:\\file.txt") == "pending"
    assert policy.verify(replacement.approval_id, "246810").approved
    policy.remove("Z:\\")
    replacement = policy.request("Z:\\")
    assert replacement.approval_id != approval.approval_id
    assert policy.verify(replacement.approval_id, "246810").approved


def test_identity_lookup_rechecks_concurrent_request_cancellation() -> None:
    policy = UsbApprovalPolicy(
        pin_loader=lambda: "246810", require_identity=True,
    )
    approval = policy.request("Y:\\", volume_id="test-volume")
    assert policy.verify(approval.approval_id, "246810").approved

    def identity_with_cancellation(_mount):
        policy.cancel(approval.approval_id)
        return "test-volume"

    policy._identity_provider = identity_with_cancellation
    assert policy._trust_state_for_target("Y:\\file.txt") == "denied"


def test_stale_cancel_does_not_change_new_insertion() -> None:
    policy = UsbApprovalPolicy(pin_loader=lambda: "246810")
    old = policy.request("X:\\")
    policy.remove("X:\\")
    new = policy.request("X:\\")
    assert policy.verify(new.approval_id, "246810").approved

    policy.cancel(old.approval_id)

    assert policy.trust_state("X:\\") == "trusted"
