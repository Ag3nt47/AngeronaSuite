from __future__ import annotations

from angerona.core.eventbus import EventBus, Severity
from angerona.core.usb_policy import (
    UsbApprovalPolicy,
    WindowsAutoRunPolicy,
    active_usb_scan_authorization,
)
from angerona.modules import usb_monitor


class _Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def test_usb_pin_gate_enrolls_then_locks_until_explicit_reset() -> None:
    clock = _Clock()
    configured = {"pin": None}
    policy = UsbApprovalPolicy(
        pin_loader=lambda: configured["pin"],
        pin_writer=lambda pin: configured.__setitem__("pin", pin),
        clock=clock,
        max_attempts=3,
        lockout_seconds=30,
    )
    request = policy.request("E:\\", policy_enforced=True)
    assert request.state == "pending"

    unavailable = policy.verify(request.approval_id, "123456")
    assert not unavailable.approved
    assert unavailable.reason == "pin_not_configured"
    assert unavailable.state == "enrollment_required"
    assert unavailable.attempts_remaining == 0
    assert policy.trust_state("E:\\") == "enrollment_required"

    enrolled = policy.configure_pin("246810", "246810")
    assert enrolled.updated
    assert configured["pin"] == "246810"
    assert policy.trust_state("E:\\") == "pending"

    locked = policy.verify(request.approval_id, "000000")
    assert locked.reason == "locked"
    assert locked.attempts_remaining == 0
    assert policy.pin_reset_required()
    assert policy.verify(request.approval_id, "246810").reason == "locked"

    # A timer and device reinsertion cannot bypass the session latch.
    clock.value += 31
    assert policy.verify(request.approval_id, "246810").reason == "locked"
    assert policy.remove("E:\\")
    replacement = policy.request("E:\\")
    assert replacement.state == "locked"

    reset = policy.configure_pin("135790", "135790")
    assert reset.updated
    assert not policy.pin_reset_required()
    assert policy.trust_state("E:\\") == "pending"
    approved = policy.verify(replacement.approval_id, "135790")
    assert approved.approved
    assert policy.trust_state("E:\\") == "trusted"

    assert policy.remove("E:\\")
    assert policy.trust_state("E:\\") == "untrusted"
    assert not policy.verify(replacement.approval_id, "135790").approved


def test_usb_pin_confirmation_failure_never_calls_protected_writer() -> None:
    writes: list[str] = []
    policy = UsbApprovalPolicy(
        pin_loader=lambda: None,
        pin_writer=writes.append,
    )

    assert policy.configure_pin("123", "123").reason == "invalid_format"
    assert policy.configure_pin("123456", "654321").reason == "confirmation_mismatch"
    assert writes == []


def test_usb_approval_views_and_decisions_never_expose_pin() -> None:
    policy = UsbApprovalPolicy(pin_loader=lambda: "987654")
    request = policy.request("/media/usb", autorun_present=False)
    decision = policy.verify(request.approval_id, "987654")

    serialized = repr(request.event_details()) + repr(decision.event_details())
    assert "987654" not in serialized
    assert request.event_details()["raw_device_access_blocked"] is False
    assert decision.event_details()["scope"] == "angerona-workflows-only"


def test_live_usb_scan_authorization_tracks_exact_mount_state(tmp_path) -> None:
    mount = tmp_path / "usb"
    mount.mkdir()
    child = mount / "folder"
    policy = UsbApprovalPolicy(pin_loader=lambda: "987654")
    request = policy.request(mount)

    assert active_usb_scan_authorization(child) == (False, "pending")
    assert policy.verify(request.approval_id, "987654").approved
    assert active_usb_scan_authorization(child) == (True, "trusted")
    assert policy.remove(mount)
    assert active_usb_scan_authorization(child) == (None, "untracked")


def test_usb_trust_is_revoked_when_volume_identity_changes() -> None:
    policy = UsbApprovalPolicy(pin_loader=lambda: "987654")
    first = policy.request("E:\\", volume_id="volume-a")
    assert policy.verify(first.approval_id, "987654").approved

    replacement = policy.request("E:\\", volume_id="volume-b")

    assert replacement.approval_id != first.approval_id
    assert replacement.state == "pending"
    assert policy.trust_state("E:\\") == "pending"
    assert not policy.verify(first.approval_id, "987654").approved


class _Key:
    def __init__(self, registry, hive, path) -> None:
        self.registry = registry
        self.hive = hive
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None


class _Registry:
    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_SET_VALUE = 1
    KEY_READ = 2
    KEY_WOW64_64KEY = 4
    REG_DWORD = 4

    def __init__(self) -> None:
        self.values: dict[tuple[str, str, str], tuple[int, int]] = {}

    def CreateKeyEx(self, hive, path, _reserved, _access):
        return _Key(self, hive, path)

    def OpenKey(self, hive, path, _reserved, _access):
        return _Key(self, hive, path)

    def SetValueEx(self, key, name, _reserved, kind, value) -> None:
        self.values[(key.hive, key.path, name)] = (value, kind)

    def QueryValueEx(self, key, name):
        try:
            return self.values[(key.hive, key.path, name)]
        except KeyError as exc:
            raise FileNotFoundError(name) from exc


def test_windows_autorun_policy_writes_and_verifies_exact_deny_values() -> None:
    registry = _Registry()
    policy = WindowsAutoRunPolicy(
        registry=registry,
        platform="win32",
        admin_check=lambda: True,
    )
    result = policy.enforce(include_machine=True)

    assert result.enforced
    assert result.verified_values == 6
    for path, name, value in policy.USER_VALUES:
        assert registry.values[("HKCU", path, name)] == (value, registry.REG_DWORD)
    for path, name, value in policy.MACHINE_VALUES:
        assert registry.values[("HKLM", path, name)] == (value, registry.REG_DWORD)

    first = policy.USER_VALUES[0]
    registry.values[("HKCU", first[0], first[1])] = (0, registry.REG_DWORD)
    drift = policy.verify(include_machine=True)
    assert not drift.enforced
    assert any("NoDriveTypeAutoRun" in item for item in drift.errors)


def test_autorun_policy_is_observation_only_and_non_mutating_off_windows() -> None:
    registry = _Registry()
    result = WindowsAutoRunPolicy(
        registry=registry,
        platform="linux",
        admin_check=lambda: True,
    ).enforce(include_machine=True)
    assert not result.supported
    assert not result.enforced
    assert registry.values == {}


def test_usb_monitor_emits_pending_gate_before_content_access(monkeypatch) -> None:
    bus = EventBus()
    module = usb_monitor.USBMonitorModule()
    module.bind(bus)
    module._approval_policy = UsbApprovalPolicy(pin_loader=lambda: "246810")
    module._mount_provider = lambda: {"E:\\": "removable"}
    content_reads: list[str] = []

    def _probe(path: str) -> bool:
        content_reads.append(path)
        return True

    monkeypatch.setattr(usb_monitor, "_has_autorun", _probe)
    module._check()

    assert content_reads == []
    event = bus.recent(1)[0]
    assert event.severity == Severity.MEDIUM
    assert event.details["event_type"] == "usb_approval_required"
    assert event.details["approval_state"] == "pending"
    assert event.details["content_inspected"] is False
    assert event.details["raw_device_access_blocked"] is False

    approval = module.pending_approvals()[0]
    decision = module.approve_media(approval.approval_id, "246810")
    assert decision.approved
    assert content_reads == [decision.mountpoint]
    risk = bus.recent(1)[0]
    assert risk.details["event_type"] == "usb_media_risk"
    assert risk.details["autorun"] is True
    assert "246810" not in repr(risk.details)

    module._mount_provider = lambda: {}
    module._check()
    assert module.trust_state("E:\\") == "untrusted"


def test_usb_monitor_reports_first_failure_as_reset_required_lock() -> None:
    bus = EventBus()
    module = usb_monitor.USBMonitorModule()
    module.bind(bus)
    module._approval_policy = UsbApprovalPolicy(pin_loader=lambda: "246810")
    approval = module._approval_policy.request("Q:\\")

    decision = module.approve_media(approval.approval_id, "000000")

    assert decision.reason == "locked"
    event = bus.recent(1)[0]
    assert event.details["event_type"] == "usb_pin_lockout"
    assert "after an invalid PIN" in event.message
    assert "explicitly in Settings" in event.message


def test_fixed_usb_disk_is_detected_by_native_bus_metadata(monkeypatch) -> None:
    class _Partition:
        mountpoint = "E:\\"
        opts = "rw,fixed"
        fstype = "NTFS"

    class _Psutil:
        @staticmethod
        def disk_partitions(*, all):
            assert all is False
            return [_Partition()]

    class _Probe:
        retained: set[str] | None = None

        @staticmethod
        def external_kind(mountpoint):
            assert mountpoint == "E:\\"
            return "usb"

        def retain(self, mountpoints):
            self.retained = set(mountpoints)

    probe = _Probe()
    monkeypatch.setattr(usb_monitor, "psutil", _Psutil())
    monkeypatch.setattr(usb_monitor.sys, "platform", "win32")
    monkeypatch.setattr(usb_monitor, "_WINDOWS_VOLUME_PROBE", probe)

    assert usb_monitor._removable_mounts() == {"E:\\": "usb (NTFS)"}
    assert probe.retained == {"E:\\"}


def test_new_fixed_drive_letter_fails_closed_without_prompting_startup_disks(
    monkeypatch,
) -> None:
    bus = EventBus()
    module = usb_monitor.USBMonitorModule()
    module.bind(bus)
    module._approval_policy = UsbApprovalPolicy(pin_loader=lambda: "246810")
    module._mount_provider = lambda: {}  # simulate psutil/native USB classification miss
    local_snapshots = iter(
        [
            {"C:\\": "fixed", "D:\\": "fixed"},
            {"C:\\": "fixed", "D:\\": "fixed", "E:\\": "fixed"},
            {"C:\\": "fixed", "D:\\": "fixed", "E:\\": "fixed"},
            {"C:\\": "fixed", "D:\\": "fixed"},
        ]
    )
    module._drive_provider = lambda: next(local_snapshots)
    content_reads: list[str] = []
    monkeypatch.setattr(
        usb_monitor,
        "_has_autorun",
        lambda path: content_reads.append(path) or False,
    )

    module._check()
    assert module.pending_approvals() == ()
    assert bus.recent(10) == []

    module._check()
    pending = module.pending_approvals()
    assert len(pending) == 1
    assert pending[0].mountpoint == "e:\\"
    assert content_reads == []
    event = bus.recent(1)[0]
    assert event.details["event_type"] == "usb_approval_required"
    assert event.details["present_at_start"] is False
    assert event.details["content_inspected"] is False
    assert "new drive; unclassified" in event.details["media_type"]

    # A continuing native/psutil classification miss must not revoke the gate.
    module._check()
    assert len(module.pending_approvals()) == 1
    assert module.trust_state("E:\\") == "pending"

    module._check()
    assert module.pending_approvals() == ()
    assert module.trust_state("E:\\") == "untrusted"
    assert bus.recent(1)[0].details["event_type"] == "usb_media_removed"


def test_same_drive_letter_device_swap_revokes_prior_trust() -> None:
    bus = EventBus()
    module = usb_monitor.USBMonitorModule()
    module.bind(bus)
    module._approval_policy = UsbApprovalPolicy(pin_loader=lambda: "246810")
    module._mount_provider = lambda: {"E:\\": "removable"}
    module._drive_provider = lambda: {"E:\\": "removable"}
    identities = iter(("volume-a", "volume-b"))
    module._identity_provider = lambda _mount: next(identities)

    module._check()
    first = module.pending_approvals()[0]
    assert module.approve_media(first.approval_id, "246810").approved
    assert module.trust_state("E:\\") == "trusted"

    module._check()

    pending = module.pending_approvals()
    assert len(pending) == 1
    assert pending[0].approval_id != first.approval_id
    assert module.trust_state("E:\\") == "pending"
    assert any(
        event.details.get("reason") == "volume_identity_changed"
        for event in bus.recent(10)
    )
