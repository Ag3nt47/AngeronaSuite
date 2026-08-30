from __future__ import annotations

from angerona.core.eventbus import EventBus
from angerona.core.usb_policy import UsbApprovalPolicy, active_usb_scan_authorization
from angerona.modules import usb_monitor
from angerona.modules.usb_monitor import USBMonitorModule


def _module_with_identity(current: dict[str, str]) -> USBMonitorModule:
    module = USBMonitorModule()
    module._identity_provider = lambda mount: current.get(mount, "")
    module._approval_policy = UsbApprovalPolicy(
        pin_loader=lambda: "246810",
        identity_provider=lambda mount: module._identity_provider(mount),
        require_identity=True,
    )
    module._policy_result = module._policy_result.__class__(
        supported=False,
        user_enforced=False,
        machine_requested=False,
        machine_enforced=None,
        verified_values=0,
    )
    return module


def test_unknown_identity_revokes_trust_and_never_overwrites_last_known() -> None:
    current = {"E:\\": "volume-a"}
    module = _module_with_identity(current)
    module._mount_provider = lambda: {"E:\\": "removable"}
    module._drive_provider = lambda: {}
    bus = EventBus()
    module.bind(bus)

    module._check()
    approval = module.pending_approvals()[0]
    assert module._approval_policy.verify(approval.approval_id, "246810").approved
    assert module.trust_state("E:\\") == "trusted"

    current["E:\\"] = ""
    module._check()

    assert module.trust_state("E:\\") != "trusted"
    assert module._known_identities["E:\\"] == "volume-a"
    assert "E:\\" in module._identity_blind_mounts
    assert any(
        event.details.get("reason") == "volume_identity_unavailable"
        for event in bus.recent(30)
    )

    current["E:\\"] = "volume-b"
    module._check()
    assert module.trust_state("E:\\") != "trusted"
    assert module._known_identities["E:\\"] == "volume-b"
    assert "E:\\" not in module._identity_blind_mounts


def test_production_policy_cannot_approve_mount_without_identity() -> None:
    policy = UsbApprovalPolicy(
        pin_loader=lambda: "246810",
        identity_provider=lambda _mount: "",
        require_identity=True,
    )
    request = policy.request("E:\\", volume_id="")

    decision = policy.verify(request.approval_id, "246810")

    assert decision.approved is False
    assert decision.reason == "identity_unavailable"
    assert policy.trust_state("E:\\") == "identity_unavailable"


def test_every_active_scan_authorization_revalidates_live_insertion_identity() -> None:
    current = {"identity": "volume-a"}
    policy = UsbApprovalPolicy(
        pin_loader=lambda: "246810",
        identity_provider=lambda _mount: current["identity"],
        require_identity=True,
    )
    request = policy.request("X:\\", volume_id="volume-a")
    assert policy.verify(request.approval_id, "246810").approved
    assert active_usb_scan_authorization("X:\\sample.bin") == (True, "trusted")

    current["identity"] = ""
    allowed, reason = active_usb_scan_authorization("X:\\sample.bin")

    assert allowed is False
    assert reason == "identity_unavailable"
    assert policy.trust_state("X:\\") == "identity_unavailable"


def test_approval_time_identity_swap_is_revoked_before_trust_return(
    monkeypatch,
) -> None:
    observations = iter(("volume-a", "volume-b"))
    module = USBMonitorModule()
    module._identity_provider = lambda _mount: next(observations)
    module._approval_policy = UsbApprovalPolicy(
        pin_loader=lambda: "246810",
        identity_provider=lambda mount: module._identity_provider(mount),
        require_identity=True,
    )
    request = module._approval_policy.request("E:\\", volume_id="volume-a")
    monkeypatch.setattr(usb_monitor, "_has_autorun", lambda _mount: False)

    decision = module.approve_media(request.approval_id, "246810")

    assert decision.approved is False
    assert decision.reason == "identity_changed_during_scan"
    assert module.trust_state("E:\\") == "untrusted"
