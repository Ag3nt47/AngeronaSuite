from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from angerona.core.eventbus import EventBus
from angerona.core.security_scan_center import ScanFinding, ScanResult
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


def _auto_review_module(monkeypatch, mountpoint):
    identity = {"current": "volume-a"}
    module = _module_with_identity({})
    module._identity_provider = lambda _mount: identity["current"]
    module._mount_provider = lambda: {mountpoint: "removable"}
    module._drive_provider = lambda: {}
    monkeypatch.setattr(usb_monitor, "_has_autorun", lambda _mount: False)
    monkeypatch.setattr(usb_monitor, "_supports_automatic_file_review", lambda _mount: True)
    monkeypatch.setattr(usb_monitor, "_automatic_scan_identity", lambda _mount: identity["current"])
    bus = EventBus()
    module.bind(bus)
    module._check()
    return module, identity, bus


def test_automatic_volume_identity_requires_native_guid(monkeypatch) -> None:
    probe = usb_monitor._WindowsVolumeProbe()
    api = SimpleNamespace(
        GetVolumeNameForVolumeMountPointW=lambda *_args: False,
        GetVolumeInformationW=lambda *_args: True,
    )
    monkeypatch.setattr(probe, "_api", lambda: api)
    assert probe.volume_identity("T:\\")  # Legacy manual approval fallback remains available.
    assert probe.volume_identity("T:\\", require_guid=True) == ""


def test_automatic_file_review_runs_once_after_exact_pin_approval(monkeypatch) -> None:
    module, _, bus = _auto_review_module(monkeypatch, "Q:\\")
    calls = []
    finding = ScanFinding("yara.match.example", "high", "Malware signatures", "Synthetic signature match")

    class Scanner:
        def __init__(self, **options):
            assert options["max_files"] == 64
            assert options["max_total_bytes"] == 16 * 1024**2
            self.authorize = options["usb_authorizer"]

        def scan_path(self, mountpoint, *, cancellation):
            calls.append(mountpoint)
            assert not cancellation.cancelled
            assert self.authorize(Path(mountpoint)) == (True, "trusted")
            assert self.authorize(Path(mountpoint) / "unselected.exe") == (False, "approval-ended")
            return ScanResult("local_path_scan", "completed", True, True, 1, 2, "Synthetic",
                              (finding,), {"files_scanned": 4, "yara_status": "active"})

    monkeypatch.setattr(usb_monitor, "SecurityScanCenter", Scanner)
    module._run_pending_media_scan()
    assert not calls and not module.recent_media_scan_results()
    approval = module.pending_approvals()[0]
    assert module.approve_media(approval.approval_id, "246810").approved
    assert not calls  # The approval caller never performs the file review.
    assert module.approve_media(approval.approval_id, "246810").reason == "already_approved"
    module._run_pending_media_scan()
    module._run_pending_media_scan()

    assert calls == [approval.mountpoint]
    result, = module.recent_media_scan_results()
    assert result.approval_id == approval.approval_id
    assert result.state == "completed" and result.files_scanned == 4
    assert result.findings == (finding,) and result.action_taken == "none"
    event, = [item for item in bus.recent(8) if item.details.get("event_type") == "usb_media_scan_result"]
    assert event.details["response_authorized"] is False
    assert event.details["active_attack"] is False


def test_automatic_file_review_holds_before_opening_a_replacement_volume(monkeypatch) -> None:
    module, identity, _ = _auto_review_module(monkeypatch, "R:\\")
    calls = []
    monkeypatch.setattr(usb_monitor, "SecurityScanCenter", lambda **options: calls.append(options))
    approval = module.pending_approvals()[0]
    assert module.approve_media(approval.approval_id, "246810").approved
    identity["current"] = "volume-b"
    module._check()
    module._run_pending_media_scan()

    assert not calls
    result, = module.recent_media_scan_results()
    assert result.approval_id == approval.approval_id and result.state == "held"
    assert not result.findings
    assert module.pending_approvals()[0].approval_id != approval.approval_id


def test_automatic_file_review_drops_late_findings_after_identity_loss(monkeypatch) -> None:
    module, identity, _ = _auto_review_module(monkeypatch, "S:\\")
    finding = ScanFinding("yara.match.late", "high", "Malware signatures", "Synthetic late match")

    class Scanner:
        def __init__(self, **_options):
            pass

        def scan_path(self, _mountpoint, *, cancellation):
            assert not cancellation.cancelled
            identity["current"] = "volume-b"
            assert cancellation.cancelled
            identity["current"] = "volume-a"
            return ScanResult("local_path_scan", "completed", True, True, 1, 2, "Synthetic",
                              (finding,), {"files_scanned": 4, "yara_status": "active"})

    monkeypatch.setattr(usb_monitor, "SecurityScanCenter", Scanner)
    approval = module.pending_approvals()[0]
    assert module.approve_media(approval.approval_id, "246810").approved
    module._run_pending_media_scan()

    result, = module.recent_media_scan_results()
    assert result.state == "cancelled" and not result.findings
    assert result.files_scanned == 0 and result.action_taken == "none"
    assert module.trust_state(approval.mountpoint) != "trusted"
