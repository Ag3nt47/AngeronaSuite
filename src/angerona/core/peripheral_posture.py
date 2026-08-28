"""Read-only peripheral and DMA posture with explicit unknown states.

The collector never enables, disables, ejects, installs, or reconfigures a
device.  OS controls and hardware topology are not equivalent to trustworthy
firmware, so every assessment explicitly disclaims malicious-device-firmware
coverage.  Administrator/kernel compromise can also falsify these local
observations; independent hardware attestation remains a separate control.
"""
from __future__ import annotations

import json
import math
import os
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Callable, Mapping, Sequence


POSTURE_SCHEMA = "angerona.peripheral-dma-posture.v1"
CONTROL_STATES = frozenset({"enabled", "disabled", "not-applicable", "unknown"})
PRESENCE_STATES = frozenset({"present", "absent", "unknown"})
THUNDERBOLT_AUTHORIZATION = frozenset(
    {"secure-connect", "user-authorized", "open", "not-present", "unknown"}
)
REMOVABLE_CONTROLS = frozenset(
    {"blocked", "read-only", "allowlisted", "allowed", "not-applicable", "unknown"}
)
DEVICE_INSTALL_CONTROLS = frozenset(
    {"blocked-unapproved", "allowlisted", "allowed", "not-applicable", "unknown"}
)
PLATFORMS = frozenset({"windows", "linux", "macos"})
COLLECTION_SOURCES = frozenset(
    {
        "linux-iommu",
        "linux-removable",
        "linux-thunderbolt",
        "macos-system-profiler",
        "windows-deviceguard",
        "windows-pnp",
        "windows-removable-policy",
    }
)
MAX_COLLECTION_SOURCES = 16
MAX_WINDOWS_OUTPUT_BYTES = 64 * 1024


class PeripheralPostureRejected(ValueError):
    """Peripheral posture did not satisfy the bounded evidence contract."""


def _state(value: object, allowed: frozenset[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise PeripheralPostureRejected(f"{field} has an invalid state")
    return value


def _safe_observed_at(value: object) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0 <= float(value) <= 32_503_680_000
    ):
        raise PeripheralPostureRejected("peripheral observation time is invalid")
    return float(value)


@dataclass(frozen=True)
class PeripheralPostureSnapshot:
    schema: str
    platform: str
    kernel_dma_protection: str
    iommu: str
    thunderbolt: str
    thunderbolt_authorization: str
    usb4: str
    removable_storage: str
    removable_storage_control: str
    device_install_control: str
    collection_complete: bool
    collection_sources: tuple[str, ...]
    observed_at: float

    def __post_init__(self) -> None:
        if self.schema != POSTURE_SCHEMA:
            raise PeripheralPostureRejected("peripheral posture schema is invalid")
        if self.platform not in PLATFORMS:
            raise PeripheralPostureRejected("peripheral platform is invalid")
        _state(self.kernel_dma_protection, CONTROL_STATES, "kernel_dma_protection")
        _state(self.iommu, CONTROL_STATES, "iommu")
        _state(self.thunderbolt, PRESENCE_STATES, "thunderbolt")
        _state(
            self.thunderbolt_authorization,
            THUNDERBOLT_AUTHORIZATION,
            "thunderbolt_authorization",
        )
        _state(self.usb4, PRESENCE_STATES, "usb4")
        _state(self.removable_storage, PRESENCE_STATES, "removable_storage")
        _state(
            self.removable_storage_control,
            REMOVABLE_CONTROLS,
            "removable_storage_control",
        )
        _state(
            self.device_install_control,
            DEVICE_INSTALL_CONTROLS,
            "device_install_control",
        )
        if type(self.collection_complete) is not bool:
            raise PeripheralPostureRejected("collection_complete must be boolean")
        if (
            not isinstance(self.collection_sources, tuple)
            or len(self.collection_sources) > MAX_COLLECTION_SOURCES
            or len(set(self.collection_sources)) != len(self.collection_sources)
            or tuple(sorted(self.collection_sources)) != self.collection_sources
            or any(source not in COLLECTION_SOURCES for source in self.collection_sources)
        ):
            raise PeripheralPostureRejected("peripheral collection sources are invalid")
        _safe_observed_at(self.observed_at)
        if self.thunderbolt == "absent" and self.thunderbolt_authorization not in {
            "not-present",
            "unknown",
        }:
            raise PeripheralPostureRejected(
                "absent Thunderbolt hardware cannot have an active authorization mode"
            )

    @classmethod
    def unknown(cls, platform: str, observed_at: float) -> "PeripheralPostureSnapshot":
        return cls(
            POSTURE_SCHEMA,
            platform,
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            False,
            (),
            observed_at,
        )


@dataclass(frozen=True)
class PeripheralPostureAssessment:
    state: str
    severity: str
    health: int
    risks: tuple[str, ...]
    unknown: tuple[str, ...]
    response_authorized: bool = False
    malicious_firmware_protection_claimed: bool = False

    def event_details(self, snapshot: PeripheralPostureSnapshot) -> dict[str, object]:
        return {
            "schema": "angerona.peripheral-dma-assessment.v1",
            "platform": snapshot.platform,
            "state": self.state,
            "risk_codes": list(self.risks),
            "unknown_fields": list(self.unknown),
            "collection_complete": snapshot.collection_complete,
            "collection_sources": list(snapshot.collection_sources),
            "kernel_dma_protection": snapshot.kernel_dma_protection,
            "iommu": snapshot.iommu,
            "thunderbolt": snapshot.thunderbolt,
            "thunderbolt_authorization": snapshot.thunderbolt_authorization,
            "usb4": snapshot.usb4,
            "removable_storage": snapshot.removable_storage,
            "removable_storage_control": snapshot.removable_storage_control,
            "device_install_control": snapshot.device_install_control,
            "raw_device_identifiers_omitted": True,
            "device_control_performed": False,
            "observation_only": True,
            "malicious_firmware_protection_claimed": False,
            "firmware_and_kernel_tampering_out_of_scope": True,
            "response_authorized": False,
            "response_authority": "observe-only",
        }


def assess_peripheral_posture(
    snapshot: PeripheralPostureSnapshot,
) -> PeripheralPostureAssessment:
    if not isinstance(snapshot, PeripheralPostureSnapshot):
        raise TypeError("peripheral posture contract is invalid")
    risks: list[str] = []
    unknown: list[str] = []

    for field in ("kernel_dma_protection", "iommu"):
        value = getattr(snapshot, field)
        if value == "disabled":
            risks.append(f"{field.replace('_', '-')}-disabled")
        elif value == "unknown":
            unknown.append(field)
    for field in ("thunderbolt", "usb4", "removable_storage"):
        if getattr(snapshot, field) == "unknown":
            unknown.append(field)

    if snapshot.thunderbolt == "present":
        if snapshot.thunderbolt_authorization == "open":
            risks.append("thunderbolt-open-authorization")
        elif snapshot.thunderbolt_authorization == "unknown":
            unknown.append("thunderbolt_authorization")
        if snapshot.platform == "windows" and snapshot.kernel_dma_protection == "disabled":
            risks.append("thunderbolt-present-without-kernel-dma-protection")
        if snapshot.platform == "linux" and snapshot.iommu == "disabled":
            risks.append("thunderbolt-present-without-iommu")
    elif snapshot.thunderbolt == "unknown":
        unknown.append("thunderbolt_authorization")

    if snapshot.usb4 == "present":
        dma_control = (
            snapshot.kernel_dma_protection
            if snapshot.platform == "windows"
            else snapshot.iommu
        )
        if dma_control == "disabled":
            risks.append("usb4-present-without-dma-isolation")
        elif dma_control == "unknown":
            unknown.append("usb4_dma_isolation")

    if snapshot.removable_storage == "present":
        if snapshot.removable_storage_control == "allowed":
            risks.append("removable-storage-unrestricted")
        elif snapshot.removable_storage_control == "unknown":
            unknown.append("removable_storage_control")
    elif snapshot.removable_storage == "unknown":
        unknown.append("removable_storage_control")

    external_present = snapshot.thunderbolt == "present" or snapshot.usb4 == "present"
    any_peripheral_present = external_present or snapshot.removable_storage == "present"
    if any_peripheral_present:
        if snapshot.device_install_control == "allowed":
            risks.append("unapproved-device-installation-allowed")
        elif snapshot.device_install_control == "unknown":
            unknown.append("device_install_control")
    elif snapshot.device_install_control == "unknown":
        unknown.append("device_install_control")

    if not snapshot.collection_complete:
        unknown.append("collection_complete")
    risks = sorted(set(risks))
    unknown = sorted(set(unknown))
    critical = any(
        code in risks
        for code in {
            "thunderbolt-present-without-iommu",
            "thunderbolt-present-without-kernel-dma-protection",
            "usb4-present-without-dma-isolation",
        }
    )
    if critical:
        state, severity = "dma-exposure-detected", "critical"
    elif risks:
        state, severity = "peripheral-control-risk", "high"
    elif unknown:
        state, severity = "peripheral-posture-unknown", "medium"
    else:
        state, severity = "peripheral-posture-observed", "info"
    health = max(5, 100 - 22 * len(risks) - 7 * len(unknown))
    return PeripheralPostureAssessment(
        state,
        severity,
        health,
        tuple(risks),
        tuple(unknown),
    )


def _platform_name(value: str | None = None) -> str:
    candidate = (value or sys.platform).casefold()
    if candidate.startswith("win"):
        return "windows"
    if candidate.startswith("linux"):
        return "linux"
    if candidate.startswith("darwin") or candidate.startswith("mac"):
        return "macos"
    raise PeripheralPostureRejected("unsupported peripheral posture platform")


def _windows_probe() -> Mapping[str, object] | None:
    """Run fixed, read-only inventory and policy queries with no raw IDs returned."""
    if os.name != "nt":
        return None
    try:
        from angerona.core.privilege import trusted_powershell_path

        powershell = trusted_powershell_path().resolve(strict=True)
    except Exception:
        # Never fall back to PATH search for an interpreter used by a security
        # sensor.  Missing trusted tooling is an explicit UNKNOWN posture.
        return None
    script = r"""
$pnpOk = $false; $policyOk = $false; $removableComplete = $false
$thunderbolt = $null; $usb4 = $null; $removable = $null
$removablePolicy = 'unknown'; $installPolicy = 'unknown'
try {
  $devices = @(Get-PnpDevice -PresentOnly -ErrorAction Stop)
  $pnpOk = $true
  $thunderbolt = [bool]@($devices | Where-Object {
    ([string]$_.FriendlyName) -match '(?i)thunderbolt'
  }).Count
  $usb4 = [bool]@($devices | Where-Object {
    ([string]$_.FriendlyName) -match '(?i)usb\s*4|usb4'
  }).Count
  $disks = @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop)
  $removableComplete = $true
  $removable = [bool]@($disks | Where-Object {
    ([string]$_.InterfaceType) -eq 'USB' -or ([string]$_.MediaType) -match '(?i)removable'
  }).Count
} catch { }
try {
  $denyAll = Get-ItemPropertyValue -LiteralPath (
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
  ) -Name Deny_All -ErrorAction SilentlyContinue
  if ($denyAll -eq 1) { $removablePolicy = 'blocked' }
  $denyUnspecified = Get-ItemPropertyValue -LiteralPath (
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
  ) -Name DenyUnspecified -ErrorAction SilentlyContinue
  if ($denyUnspecified -eq 1) { $installPolicy = 'blocked-unapproved' }
  $policyOk = $true
} catch { }
[pscustomobject]@{
  pnp_complete = $pnpOk; policy_complete = $policyOk
  thunderbolt_complete = $false; usb4_complete = $false
  removable_complete = $removableComplete
  thunderbolt_present = $thunderbolt; usb4_present = $usb4
  removable_present = $removable; removable_control = $removablePolicy
  device_install_control = $installPolicy
} | ConvertTo-Json -Compress
"""
    command = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "$ErrorActionPreference='Stop'; " + script,
    ]
    try:
        from angerona.core.win import run_hidden

        result = run_hidden(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        output = (result.stdout or "").strip()
        if (
            result.returncode != 0
            or not output
            or len(output.encode("utf-8")) > MAX_WINDOWS_OUTPUT_BYTES
        ):
            return None
        value = json.loads(output)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _presence(value: object, *, complete: bool) -> str:
    # A positive, bounded observation is useful even when the collector cannot
    # prove its negative coverage.  A negative becomes ``absent`` only when the
    # source explicitly says enumeration for that device family was complete.
    if value is True:
        return "present"
    if value is False and complete:
        return "absent"
    return "unknown"


def _windows_snapshot(
    probe: Mapping[str, object] | None,
    observed_at: float,
) -> PeripheralPostureSnapshot:
    if not isinstance(probe, Mapping):
        return PeripheralPostureSnapshot.unknown("windows", observed_at)
    pnp_complete = probe.get("pnp_complete") is True
    policy_complete = probe.get("policy_complete") is True
    dma_complete = probe.get("dma_complete") is True
    thunderbolt_complete = probe.get("thunderbolt_complete") is True
    usb4_complete = probe.get("usb4_complete") is True
    removable_complete = probe.get("removable_complete") is True
    kernel_dma_value = probe.get("kernel_dma_protection")
    kernel_dma = (
        "enabled"
        if kernel_dma_value is True and dma_complete
        else "disabled"
        if kernel_dma_value is False and dma_complete
        else "unknown"
    )
    iommu_value = probe.get("iommu")
    iommu = (
        "enabled"
        if iommu_value is True and dma_complete
        else "disabled"
        if iommu_value is False and dma_complete
        else "unknown"
    )
    removable_control = probe.get("removable_control", "unknown")
    if removable_control not in REMOVABLE_CONTROLS:
        removable_control = "unknown"
    install_control = probe.get("device_install_control", "unknown")
    if install_control not in DEVICE_INSTALL_CONTROLS:
        install_control = "unknown"
    sources: list[str] = []
    if pnp_complete:
        sources.append("windows-pnp")
    if policy_complete:
        sources.append("windows-removable-policy")
    if dma_complete:
        sources.append("windows-deviceguard")
    # Windows exposes Kernel DMA Protection in system posture UI, but there is
    # no stable value in the bounded PnP/policy query above.  It remains unknown
    # rather than inferring protection from VBS or hardware capability.
    return PeripheralPostureSnapshot(
        POSTURE_SCHEMA,
        "windows",
        kernel_dma,
        iommu,
        _presence(
            probe.get("thunderbolt_present"), complete=thunderbolt_complete
        ),
        "unknown",
        _presence(probe.get("usb4_present"), complete=usb4_complete),
        _presence(probe.get("removable_present"), complete=removable_complete),
        str(removable_control),
        str(install_control),
        (
            pnp_complete
            and policy_complete
            and dma_complete
            and thunderbolt_complete
            and usb4_complete
            and removable_complete
        ),
        tuple(sorted(sources)),
        observed_at,
    )


def _bounded_entries(path: Path, limit: int = 1024) -> tuple[Path, ...] | None:
    try:
        if not path.is_dir():
            return None
        # Stop after the first over-budget row.  Materializing ``iterdir()``
        # before checking its length allowed a hostile or faulty provider to
        # make an observe-only probe consume unbounded memory and directory
        # traversal time.
        entries = tuple(islice(path.iterdir(), limit + 1))
        if len(entries) > limit:
            return None
        return entries
    except OSError:
        return None


def _read_small_text(path: Path, maximum: int = 64) -> str | None:
    try:
        if not path.is_file():
            return None
        with path.open("rb") as handle:
            payload = handle.read(maximum + 1)
        if len(payload) > maximum:
            return None
        return payload.decode("utf-8", "strict").strip().casefold()
    except (OSError, UnicodeError):
        return None


def _read_stable_small_text(path: Path, maximum: int = 64) -> str | None:
    """Read one regular file without following aliases or hiding replacement.

    Linux sysfs inventories are security evidence: a missing, invalid, linked,
    or replaced attribute is an explicit completeness failure rather than a
    negative observation.
    """

    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            return None
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(os.fspath(path), flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                return None
            payload = os.read(descriptor, maximum + 1)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if (
            not stat.S_ISREG(after.st_mode)
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or len(payload) > maximum
        ):
            return None
        return payload.decode("utf-8", "strict").strip().casefold()
    except (OSError, UnicodeError):
        return None


def _linux_snapshot(sys_root: Path, observed_at: float) -> PeripheralPostureSnapshot:
    iommu_entries = _bounded_entries(sys_root / "kernel" / "iommu_groups")
    if iommu_entries is None:
        iommu = "unknown"
    elif iommu_entries:
        iommu = "enabled"
    else:
        # An empty directory does not distinguish disabled IOMMU from a machine
        # without a device assigned to a group.
        iommu = "unknown"

    thunderbolt_root = sys_root / "bus" / "thunderbolt" / "devices"
    thunderbolt_entries = _bounded_entries(thunderbolt_root)
    if thunderbolt_entries is None:
        thunderbolt = "unknown"
        authorization = "unknown"
        thunderbolt_complete = False
        usb4 = "unknown"
    else:
        device_entries = tuple(
            entry for entry in thunderbolt_entries if not entry.name.startswith("domain")
        )
        thunderbolt = "present" if thunderbolt_entries else "absent"
        if thunderbolt == "absent":
            authorization = "not-present"
            thunderbolt_complete = True
        else:
            domains = tuple(
                entry for entry in thunderbolt_entries if entry.name.startswith("domain")
            )
            security_values = tuple(
                _read_stable_small_text(domain / "security") for domain in domains
            )
            security_states = {
                "none": "open",
                "user": "user-authorized",
                "secure": "secure-connect",
            }
            definite = tuple(
                security_states[value]
                for value in security_values
                if value in security_states
            )
            thunderbolt_complete = bool(domains) and len(definite) == len(domains)
            # An open controller is a decisive positive finding even when a
            # sibling domain is unreadable.  Otherwise, incomplete evidence
            # must not let a readable secure domain mask an unknown one.
            if "open" in definite:
                authorization = "open"
            elif not thunderbolt_complete:
                authorization = "unknown"
            elif "user-authorized" in definite:
                authorization = "user-authorized"
            else:
                authorization = "secure-connect"
        usb4 = (
            "present"
            if any("usb4" in entry.name.casefold() for entry in device_entries)
            else "unknown"
        )

    block_entries = _bounded_entries(sys_root / "block")
    if block_entries is None:
        removable = "unknown"
        removable_complete = False
    else:
        flags = [_read_stable_small_text(entry / "removable", 8) for entry in block_entries]
        known = [flag for flag in flags if flag in {"0", "1"}]
        removable_complete = bool(block_entries) and len(known) == len(block_entries)
        # A positive flag is useful even when a sibling was unreadable, but
        # complete absence requires a stable valid zero from every entry.
        removable = (
            "present"
            if "1" in known
            else "absent"
            if removable_complete
            else "unknown"
        )
    sources = []
    if iommu_entries is not None:
        sources.append("linux-iommu")
    if thunderbolt_complete:
        sources.append("linux-thunderbolt")
    if removable_complete:
        sources.append("linux-removable")
    return PeripheralPostureSnapshot(
        POSTURE_SCHEMA,
        "linux",
        "not-applicable",
        iommu,
        thunderbolt,
        authorization,
        usb4,
        removable,
        "unknown",
        "unknown",
        len(sources) == 3,
        tuple(sorted(sources)),
        observed_at,
    )


def _macos_probe() -> Mapping[str, object] | None:
    command = [
        "/usr/sbin/system_profiler",
        "SPThunderboltDataType",
        "SPUSBDataType",
        "-json",
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        output = result.stdout or ""
        if result.returncode != 0 or len(output.encode("utf-8")) > 512 * 1024:
            return None
        value = json.loads(output)
        if not isinstance(value, dict):
            return None
        thunderbolt_rows = value.get("SPThunderboltDataType")
        usb_rows = value.get("SPUSBDataType")
        return {
            "complete": isinstance(thunderbolt_rows, list) and isinstance(usb_rows, list),
            "thunderbolt_present": bool(thunderbolt_rows),
            "usb4_present": "usb4" in output.casefold() or "usb 4" in output.casefold(),
        }
    except Exception:
        return None


def _macos_snapshot(
    probe: Mapping[str, object] | None,
    observed_at: float,
) -> PeripheralPostureSnapshot:
    complete = isinstance(probe, Mapping) and probe.get("complete") is True
    return PeripheralPostureSnapshot(
        POSTURE_SCHEMA,
        "macos",
        "not-applicable",
        "unknown",
        _presence(
            probe.get("thunderbolt_present") if isinstance(probe, Mapping) else None,
            complete=complete,
        ),
        "unknown",
        _presence(
            probe.get("usb4_present") if isinstance(probe, Mapping) else None,
            complete=complete,
        ),
        "unknown",
        "unknown",
        "unknown",
        False,
        ("macos-system-profiler",) if complete else (),
        observed_at,
    )


def observe_system_peripheral_posture(
    *,
    platform_name: str | None = None,
    windows_probe: Callable[[], Mapping[str, object] | None] | None = None,
    macos_probe: Callable[[], Mapping[str, object] | None] | None = None,
    sys_root: Path | str = "/sys",
    clock: Callable[[], float] = time.time,
) -> PeripheralPostureSnapshot:
    """Collect bounded, read-only posture for the current or injected platform."""
    platform = _platform_name(platform_name)
    try:
        observed_at = _safe_observed_at(clock())
    except Exception as exc:
        raise PeripheralPostureRejected("peripheral posture clock is invalid") from exc
    if platform == "windows":
        probe = (windows_probe or _windows_probe)()
        return _windows_snapshot(probe, observed_at)
    if platform == "linux":
        return _linux_snapshot(Path(sys_root), observed_at)
    probe = (macos_probe or _macos_probe)()
    return _macos_snapshot(probe, observed_at)


def snapshot_from_mapping(value: Mapping[str, object]) -> PeripheralPostureSnapshot:
    """Parse a strict snapshot from an external sensor boundary."""
    if not isinstance(value, Mapping) or set(value) != set(
        PeripheralPostureSnapshot.__dataclass_fields__
    ):
        raise PeripheralPostureRejected("peripheral posture document shape is invalid")
    document = dict(value)
    sources = document.get("collection_sources")
    if isinstance(sources, Sequence) and not isinstance(sources, (str, bytes)):
        document["collection_sources"] = tuple(sources)
    try:
        return PeripheralPostureSnapshot(**document)
    except TypeError as exc:
        raise PeripheralPostureRejected("peripheral posture document types are invalid") from exc


__all__ = [
    "COLLECTION_SOURCES",
    "CONTROL_STATES",
    "DEVICE_INSTALL_CONTROLS",
    "PLATFORMS",
    "POSTURE_SCHEMA",
    "PRESENCE_STATES",
    "PeripheralPostureAssessment",
    "PeripheralPostureRejected",
    "PeripheralPostureSnapshot",
    "REMOVABLE_CONTROLS",
    "THUNDERBOLT_AUTHORIZATION",
    "assess_peripheral_posture",
    "observe_system_peripheral_posture",
    "snapshot_from_mapping",
]
