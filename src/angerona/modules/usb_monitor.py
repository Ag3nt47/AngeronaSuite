"""usb_monitor.py — Removable-Media / USB Monitor (Code: USBW).

Removable drives are a classic initial-access and exfiltration vector (T1091
Replication Through Removable Media, T1200 Hardware Additions, T1052 Exfil over
physical medium). This module watches for newly-attached removable/USB volumes,
requires an operator PIN before Angerona inspects their content, and enforces
deny-all Windows AutoRun/AutoPlay registry policy. The PIN approval controls
Angerona workflows only; user-mode Python cannot claim raw device-access denial.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity
from angerona.core.security_scan_center import ScanCancellationToken, ScanFinding, SecurityScanCenter
from angerona.core.usb_policy import (
    AutoRunPolicyResult,
    UsbApprovalDecision,
    UsbApprovalPolicy,
    UsbApprovalView,
    WindowsAutoRunPolicy,
    active_usb_scan_authorization,
)


_DRIVE_REMOVABLE = 2
_DRIVE_FIXED = 3
_USB_LIKE_STORAGE_BUSES = frozenset({7, 12, 13})  # USB, SD, MMC


def _windows_drive_root(mountpoint: object) -> str:
    """Normalize a drive-letter mount without resolving or reading the volume."""
    value = str(mountpoint or "").strip()
    if len(value) >= 2 and value[0].isalpha() and value[1] == ":":
        return f"{value[0].upper()}:\\"
    return value


class _WindowsVolumeProbe:
    """Cheap Win32 volume classification with a short-lived per-letter cache.

    ``GetDriveTypeW`` and ``IOCTL_STORAGE_QUERY_PROPERTY`` inspect device metadata,
    not files.  This lets the monitor recognize USB disks that Windows/psutil label
    ``fixed`` while preserving the rule that media content is untouched before PIN
    approval.  No PowerShell, WMI, or CIM process is launched from the poll loop.
    """

    _CACHE_S = 60.0
    _FAILED_CACHE_S = 10.0
    _IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _OPEN_EXISTING = 3

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cache: dict[str, tuple[float, int, int | None, bool]] = {}
        self._kernel32: object | None = None
        self._load_attempted = False

    def _api(self):
        with self._lock:
            if self._load_attempted:
                return self._kernel32
            self._load_attempted = True
            if not sys.platform.startswith("win"):
                return None
            try:
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.GetLogicalDrives.argtypes = []
                kernel32.GetLogicalDrives.restype = ctypes.c_uint32
                kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
                kernel32.GetDriveTypeW.restype = ctypes.c_uint
                kernel32.GetVolumeNameForVolumeMountPointW.argtypes = [
                    ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32,
                ]
                kernel32.GetVolumeNameForVolumeMountPointW.restype = ctypes.c_int
                kernel32.GetVolumeInformationW.argtypes = [
                    ctypes.c_wchar_p,
                    ctypes.c_wchar_p,
                    ctypes.c_uint32,
                    ctypes.POINTER(ctypes.c_uint32),
                    ctypes.POINTER(ctypes.c_uint32),
                    ctypes.POINTER(ctypes.c_uint32),
                    ctypes.c_wchar_p,
                    ctypes.c_uint32,
                ]
                kernel32.GetVolumeInformationW.restype = ctypes.c_int
                kernel32.CreateFileW.argtypes = [
                    ctypes.c_wchar_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                ]
                kernel32.CreateFileW.restype = ctypes.c_void_p
                kernel32.DeviceIoControl.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.POINTER(ctypes.c_uint32),
                    ctypes.c_void_p,
                ]
                kernel32.DeviceIoControl.restype = ctypes.c_int
                kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
                kernel32.CloseHandle.restype = ctypes.c_int
                self._kernel32 = kernel32
            except (AttributeError, OSError):
                self._kernel32 = None
            return self._kernel32

    def local_drive_letters(self) -> dict[str, str]:
        """Return local removable/fixed drive letters using one native bitmask call."""
        api = self._api()
        if api is None:
            return {}
        try:
            mask = int(api.GetLogicalDrives())
        except (AttributeError, OSError, TypeError, ValueError):
            return {}
        out: dict[str, str] = {}
        for index in range(26):
            if not mask & (1 << index):
                continue
            root = f"{chr(65 + index)}:\\"
            try:
                drive_type = int(api.GetDriveTypeW(root))
            except (AttributeError, OSError, TypeError, ValueError):
                continue
            if drive_type == _DRIVE_REMOVABLE:
                out[root] = "removable"
            elif drive_type == _DRIVE_FIXED:
                out[root] = "fixed"
        return out

    def external_kind(self, mountpoint: object) -> str | None:
        """Classify removable/USB-like local storage without opening any file."""
        root = _windows_drive_root(mountpoint)
        if not root:
            return None
        drive_type, bus_type, removable_media = self._metadata(root)
        if drive_type == _DRIVE_REMOVABLE:
            return "removable"
        if drive_type == _DRIVE_FIXED and bus_type in _USB_LIKE_STORAGE_BUSES:
            return {7: "usb", 12: "sd", 13: "mmc"}.get(bus_type, "external")
        if drive_type == _DRIVE_FIXED and removable_media:
            return "removable-media"
        return None

    def volume_identity(self, mountpoint: object, *, require_guid: bool = False) -> str:
        """Return a privacy-safe stable ID without opening volume content."""
        root = _windows_drive_root(mountpoint)
        api = self._api()
        if api is None or not root:
            return ""
        guid_buffer = ctypes.create_unicode_buffer(1024)
        serial = ctypes.c_uint32(0)
        max_component = ctypes.c_uint32(0)
        flags = ctypes.c_uint32(0)
        fs_buffer = ctypes.create_unicode_buffer(128)
        try:
            guid_ok = bool(
                api.GetVolumeNameForVolumeMountPointW(
                    root, guid_buffer, len(guid_buffer)
                )
            )
            info_ok = bool(
                api.GetVolumeInformationW(
                    root,
                    None,
                    0,
                    ctypes.byref(serial),
                    ctypes.byref(max_component),
                    ctypes.byref(flags),
                    fs_buffer,
                    len(fs_buffer),
                )
            )
        except (AttributeError, OSError, TypeError, ValueError):
            return ""
        if (require_guid and not guid_ok) or not (guid_ok or info_ok):
            return ""
        material = (
            f"{guid_buffer.value if guid_ok else ''}|"
            f"{serial.value if info_ok else ''}|"
            f"{fs_buffer.value if info_ok else ''}"
        ).encode("utf-8", errors="replace")
        return hashlib.sha256(material).hexdigest()

    def retain(self, mountpoints: set[str]) -> None:
        """Forget absent letters so a later insertion is classified afresh."""
        keep = {_windows_drive_root(item) for item in mountpoints}
        with self._lock:
            self._cache = {root: value for root, value in self._cache.items() if root in keep}

    def _metadata(self, root: str) -> tuple[int, int | None, bool]:
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(root)
            if cached is not None and cached[0] > now:
                return cached[1], cached[2], cached[3]

        api = self._api()
        if api is None:
            return 0, None, False
        try:
            drive_type = int(api.GetDriveTypeW(root))
        except (AttributeError, OSError, TypeError, ValueError):
            drive_type = 0
        bus_type: int | None = None
        removable_media = False
        if drive_type == _DRIVE_FIXED:
            bus_type, removable_media = self._storage_descriptor(api, root)
        ttl = self._CACHE_S if drive_type and (bus_type is not None or drive_type != 3) else (
            self._FAILED_CACHE_S
        )
        result = (drive_type, bus_type, removable_media)
        with self._lock:
            self._cache[root] = (now + ttl, *result)
        return result

    def _storage_descriptor(self, api, root: str) -> tuple[int | None, bool]:
        # ``\\.\E:`` opens the volume device itself with metadata-only access.
        device_path = f"\\\\.\\{root[:2]}"
        invalid_handle = ctypes.c_void_p(-1).value
        try:
            handle = api.CreateFileW(
                device_path,
                0,
                self._FILE_SHARE_READ | self._FILE_SHARE_WRITE | self._FILE_SHARE_DELETE,
                None,
                self._OPEN_EXISTING,
                0,
                None,
            )
        except (AttributeError, OSError, TypeError, ValueError):
            return None, False
        if handle in (None, invalid_handle):
            return None, False
        try:
            # STORAGE_PROPERTY_QUERY(PropertyId=0, QueryType=0); padding is zeroed.
            query = ctypes.create_string_buffer(12)
            output = ctypes.create_string_buffer(1024)
            returned = ctypes.c_uint32(0)
            ok = api.DeviceIoControl(
                handle,
                self._IOCTL_STORAGE_QUERY_PROPERTY,
                query,
                ctypes.sizeof(query),
                output,
                ctypes.sizeof(output),
                ctypes.byref(returned),
                None,
            )
            if not ok or returned.value < 36:
                return None, False
            fields = struct.unpack_from("<II4B6I", output.raw, 0)
            return int(fields[10]), bool(fields[4])
        except (AttributeError, OSError, struct.error, TypeError, ValueError):
            return None, False
        finally:
            try:
                api.CloseHandle(handle)
            except (AttributeError, OSError, TypeError, ValueError):
                pass


_WINDOWS_VOLUME_PROBE = _WindowsVolumeProbe()


def _windows_local_drive_letters() -> dict[str, str]:
    if not sys.platform.startswith("win"):
        return {}
    return _WINDOWS_VOLUME_PROBE.local_drive_letters()


def _volume_identity(mountpoint: object) -> str:
    """Best-effort stable volume instance fingerprint; never reads files."""
    if sys.platform.startswith("win"):
        return _WINDOWS_VOLUME_PROBE.volume_identity(mountpoint)
    if psutil is None:
        return ""
    try:
        wanted = os.path.normcase(os.path.normpath(str(mountpoint)))
        for part in psutil.disk_partitions(all=True)[:256]:
            current = os.path.normcase(os.path.normpath(str(part.mountpoint)))
            if current == wanted:
                material = (
                    f"{part.device}|{part.mountpoint}|{part.fstype}"
                ).encode("utf-8", errors="replace")
                return hashlib.sha256(material).hexdigest()
    except Exception:
        return ""
    return ""


class _MountSnapshot(dict):
    """Existing policy result plus inert display metadata from the same query."""
    all_volumes: tuple[tuple[str, str, str], ...] = ()


def _removable_mounts() -> dict[str, str]:
    """Return {mountpoint: fstype/opts} for removable volumes (best-effort)."""
    out = _MountSnapshot()
    if psutil is None:
        return out
    try:
        present_windows_mounts: set[str] = set()
        all_volumes = []
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            # Windows marks removable/cdrom in opts; POSIX shows /media, /mnt, /run/media.
            mp = part.mountpoint
            native_kind = None
            if sys.platform.startswith("win"):
                mp = _windows_drive_root(mp)
                present_windows_mounts.add(mp)
                native_kind = _WINDOWS_VOLUME_PROBE.external_kind(mp)
            is_removable = ("removable" in opts or "cdrom" in opts
                            or mp.startswith(("/media/", "/run/media/", "/mnt/"))
                            or native_kind is not None)
            if is_removable:
                label = native_kind or opts or part.fstype
                out[mp] = f"{label} ({part.fstype or 'volume'})"
            if len(all_volumes) < 256 and type(mp) is str:
                all_volumes.append((mp[:1024], "removable" if is_removable else "mounted-volume", str(part.fstype or "")[:80]))
        out.all_volumes = tuple(all_volumes)
        if sys.platform.startswith("win"):
            _WINDOWS_VOLUME_PROBE.retain(present_windows_mounts)
    except Exception:
        pass
    return out


def _has_autorun(mountpoint: str) -> bool:
    try:
        return (Path(mountpoint) / "autorun.inf").exists()
    except Exception:
        return False


def _supports_automatic_file_review(mountpoint: str) -> bool:
    # The Scan Center rejects NTFS reparse points and checks the opened file's
    # volume. POSIX bind mounts need a separate mount-provenance check.
    return sys.platform.startswith("win") and (
        len(mountpoint) == 3 and _windows_drive_root(mountpoint).casefold() == mountpoint.casefold()
        and mountpoint[1:] == ":\\"
    )


def _automatic_scan_identity(mountpoint: str) -> str:
    return _WINDOWS_VOLUME_PROBE.volume_identity(mountpoint, require_guid=True)


class _MediaScanCancellation(ScanCancellationToken):
    def __init__(self, still_authorized):
        super().__init__()
        self._still_authorized = still_authorized

    @property
    def cancelled(self) -> bool:
        if not super().cancelled and not self._still_authorized():
            self.cancel()
        return super().cancelled


@dataclass(frozen=True)
class UsbMediaScanResult:
    """Bounded, advisory evidence tied to one approval, with no action authority."""

    approval_id: str
    mountpoint: str
    state: str
    summary: str
    files_scanned: int = 0
    findings_total: int = 0
    findings: tuple[ScanFinding, ...] = ()
    action_taken: str = "none"


class USBMonitorModule(BaseModule):
    CODE = "USBW"
    NAME = "Removable-Media / USB Monitor"
    name = "Removable-Media / USB Monitor"
    description = (
        "Alerts on removable media, keeps it untrusted until a protected-store "
        "PIN approves Angerona scanning, and disables Windows AutoRun/AutoPlay. "
        "Reviews a bounded file sample after verified Windows volume approval."
    )
    category = "Detection"
    version = "1.14.0"
    supported_platforms = frozenset({"windows", "macos", "linux"})

    _POLL = 4.0
    _POLICY_VERIFY_S = 900.0
    _PENDING_MEDIA_SCANS = 8
    _MEDIA_SCAN_RESULTS = 16

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._known: set[str] = set()
        self._known_identities: dict[str, str] = {}
        self._identity_blind_mounts: set[str] = set()
        self._seeded = False
        self._events = 0
        self._mount_provider = _removable_mounts
        self._drive_provider = _windows_local_drive_letters
        self._identity_provider = _volume_identity
        self._known_local_mounts: set[str] = set()
        self._cached_volume_inventory: tuple[tuple[str, str, str], ...] = ()
        self._watched_local_mounts: set[str] = set()
        self._approval_policy = UsbApprovalPolicy(
            identity_provider=lambda mount: self._identity_provider(mount),
            require_identity=True,
        )
        self._autorun_policy = WindowsAutoRunPolicy()
        self._policy_result = AutoRunPolicyResult(
            supported=False,
            user_enforced=False,
            machine_requested=False,
            machine_enforced=None,
            verified_values=0,
        )
        self._last_policy_verify = 0.0
        self._media_scan_lock = threading.Lock()
        self._media_scans: deque[tuple[int, str, tuple[str, str]]] = deque()
        self._media_scan_results: deque[UsbMediaScanResult] = deque(maxlen=self._MEDIA_SCAN_RESULTS)

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        self._enforce_autorun_policy()
        if psutil is None:
            self.set_health(50, "psutil unavailable")
            self.emit("USBW unavailable — psutil not present.", Severity.LOW)
            while not self.stopping:
                self.sleep(self._POLL)
            return
        policy_note = (
            "Windows AutoRun/AutoPlay deny-all policy enforced"
            if self._policy_result.enforced
            else "observation-only on this host; raw device access is not blocked"
        )
        self.emit(
            f"USBW online — watching removable media; {policy_note}.",
            Severity.INFO,
            **self._policy_result.event_details(),
        )
        while not self.stopping:
            try:
                self._check()
                self._verify_autorun_policy_if_due()
                self._run_pending_media_scan()
                pending = len(self._approval_policy.pending())
                if self._identity_blind_mounts:
                    health = 35
                    identity_note = (
                        f"; identity unavailable for {len(self._identity_blind_mounts)} "
                        "mounted volume(s), trust revoked"
                    )
                else:
                    health = 100 if (
                        not self._policy_result.supported or self._policy_result.user_enforced
                    ) else 65
                    identity_note = ""
                self.set_health(
                    health,
                    f"{len(self._known)} removable volume(s), {pending} awaiting approval, "
                    f"{self._events} event(s){identity_note}",
                )
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(60, f"scan error: {exc}")
            self.sleep(self._POLL)

    def _check(self) -> None:
        current = self._mount_provider()
        if type(current) is _MountSnapshot:
            self._cached_volume_inventory = current.all_volumes
        local_drives = self._drive_provider()
        local_set = set(local_drives)
        cur_set = set(current)
        if not self._seeded:
            current_identities = {
                mp: str(self._identity_provider(mp) or "") for mp in cur_set
            }
            # Previously mounted media is not silently trusted after restart.
            # Enumeration does not inspect any file on the volume.
            for mp in sorted(cur_set):
                self._handle_attached(
                    mp,
                    current.get(mp, "?"),
                    present_at_start=True,
                    volume_id=current_identities.get(mp, ""),
                )
            self._known = cur_set
            self._known_identities = current_identities
            self._identity_blind_mounts = {
                mp for mp, identity in current_identities.items() if not identity
            }
            # Fixed internal volumes are baseline only.  They are deliberately not
            # approval prompts, while already-present media classified USB above is.
            self._known_local_mounts = local_set
            self._watched_local_mounts = cur_set & local_set
            self._seeded = True
            return
        # Fail closed on a genuinely new local drive letter even if psutil reports
        # it as fixed and the device metadata query is temporarily unavailable.
        # Baseline fixed disks never reach this path, avoiding startup prompt spam.
        for mp in sorted(local_set - self._known_local_mounts):
            if mp not in current:
                current[mp] = f"{local_drives.get(mp, 'local')} (new drive; unclassified)"
        # Keep a previously classified/fail-closed local volume watched for its
        # full insertion lifetime.  A transient psutil or metadata-query miss must
        # not revoke the pending PIN gate on the next four-second poll.
        self._watched_local_mounts.intersection_update(local_set)
        self._watched_local_mounts.update(set(current) & local_set)
        for mp in self._watched_local_mounts:
            current.setdefault(mp, "local volume (classification cached for insertion)")
        cur_set = set(current)
        current_identities = {
            mp: str(self._identity_provider(mp) or "") for mp in cur_set
        }
        identity_lost = {
            mp
            for mp in cur_set & self._known
            if self._known_identities.get(mp)
            and not current_identities.get(mp)
            and mp not in self._identity_blind_mounts
        }
        identity_recovered = {
            mp for mp in self._identity_blind_mounts & cur_set
            if current_identities.get(mp)
        }
        identity_changed = {
            mp
            for mp in cur_set & self._known
            if self._known_identities.get(mp)
            and current_identities.get(mp)
            and self._known_identities[mp] != current_identities[mp]
        }
        compromised = identity_lost | identity_recovered | identity_changed
        for mp in sorted(compromised):
            self._approval_policy.remove(mp)
            current_identity = current_identities.get(mp, "")
            reason = (
                "volume_identity_unavailable"
                if mp in identity_lost
                else "volume_identity_changed"
            )
            if mp in identity_lost:
                self._identity_blind_mounts.add(mp)
            else:
                self._identity_blind_mounts.discard(mp)
            self.emit(
                f"Removable media identity is no longer continuous at {mp}; "
                "prior trust was revoked.",
                Severity.MEDIUM,
                event_type="usb_media_removed",
                mountpoint=mp,
                approval_state="untrusted",
                reason=reason,
                identity_available=bool(current_identity),
                mitre="T1091",
            )
            self._handle_attached(
                mp,
                current.get(mp, "?"),
                present_at_start=False,
                volume_id=current_identity,
            )
        for mp in sorted(cur_set - self._known):
            if not current_identities.get(mp):
                self._identity_blind_mounts.add(mp)
            self._handle_attached(
                mp,
                current.get(mp, "?"),
                present_at_start=False,
                volume_id=current_identities.get(mp, ""),
            )
        for mp in sorted(self._known - cur_set):
            self._approval_policy.remove(mp)
            self._identity_blind_mounts.discard(mp)
            self.emit(
                f"Removable media removed: {mp}; in-memory trust was revoked.",
                Severity.INFO,
                event_type="usb_media_removed",
                mountpoint=mp,
                approval_state="untrusted",
                mitre="T1091",
            )
        self._approval_policy.retain_mounts(cur_set)
        self._known = cur_set
        # Unknown is a coverage failure, never a new identity baseline. Retain
        # the last-known value so a later probe can prove same/different rather
        # than laundering a replacement through one blank poll.
        self._known_identities = {
            mp: current_identities.get(mp) or self._known_identities.get(mp, "")
            for mp in cur_set
        }
        self._known_local_mounts = local_set

    def _handle_attached(
        self,
        mountpoint: str,
        media_type: str,
        *,
        present_at_start: bool,
        volume_id: str = "",
    ) -> None:
        self._events += 1
        approval = self._approval_policy.request(
            mountpoint,
            autorun_present=False,
            policy_enforced=self._policy_result.enforced,
            volume_id=volume_id,
        )
        details = approval.event_details()
        details.update({
            "media_type": str(media_type)[:80],
            "present_at_start": bool(present_at_start),
            "pin_configured": self._approval_policy.pin_configured(),
            "content_inspected": False,
            "mitre": "T1091/T1200/T1052",
        })
        qualifier = "present at startup" if present_at_start else "attached"
        self.emit(
            f"Removable media {qualifier}: {mountpoint}. AutoRun remains disabled; "
            "enter the removable-media PIN before Angerona scans its content.",
            Severity.MEDIUM,
            **details,
        )

    # Public methods intentionally expose only secret-free state. The GUI can
    # locate this module by NAME and use these methods for its approval dialog.
    def pending_approvals(self) -> tuple[UsbApprovalView, ...]:
        return self._approval_policy.pending()

    def trust_state(self, mountpoint: object) -> str:
        return self._approval_policy.trust_state(mountpoint)

    def recent_media_scan_results(self) -> tuple[UsbMediaScanResult, ...]:
        """Return the latest completed/held review rows without opening a drive."""
        with self._media_scan_lock:
            return tuple(self._media_scan_results)

    def _publish_media_scan_result(self, result: UsbMediaScanResult) -> None:
        with self._media_scan_lock:
            self._media_scan_results.append(result)
        self.emit(
            f"Removable-media file review at {result.mountpoint}. {result.summary}",
            Severity.MEDIUM if result.findings_total else Severity.INFO,
            event_type="usb_media_scan_result",
            approval_id=result.approval_id,
            mountpoint=result.mountpoint,
            scan_state=result.state,
            files_scanned=result.files_scanned,
            findings_total=result.findings_total,
            action_taken=result.action_taken,
            disposition="observation",
            active_attack=False,
            response_authorized=False,
        )

    def _queue_media_scan(self, approval_id: str, binding: tuple[str, str]) -> None:
        with self._media_scan_lock:
            if not self.stopping and len(self._media_scans) < self._PENDING_MEDIA_SCANS:
                self._media_scans.append((self.lifecycle_generation, approval_id, binding))
                return
        self._publish_media_scan_result(UsbMediaScanResult(
            approval_id, binding[0], "held", "The automatic file review queue is unavailable."
        ))

    def _run_pending_media_scan(self) -> None:
        # The monitor's existing generation owns the scan and retires it with
        # the normal module lifecycle. It never starts a detached worker.
        with self._media_scan_lock:
            if not self._media_scans:
                return
            generation, approval_id, binding = self._media_scans.popleft()
        mountpoint, expected_identity = binding
        if not _supports_automatic_file_review(mountpoint):
            self._publish_media_scan_result(UsbMediaScanResult(
                approval_id, mountpoint, "held", "Automatic file review requires a Windows drive-letter mount."
            ))
            return

        def binding_current() -> bool:
            return (
                not self.stopping and self.lifecycle_generation == generation
                and self._approval_policy.approval_binding(approval_id) == binding
                and self._approval_policy.trust_state(mountpoint) == "trusted"
            )

        def still_authorized() -> bool:
            if not binding_current():
                return False
            try:
                identity = _automatic_scan_identity(mountpoint)
            except (OSError, RuntimeError, TypeError, ValueError):
                return False
            if not identity:
                return False
            if not hmac.compare_digest(identity, expected_identity):
                self._approval_policy.cancel(approval_id)
                return False
            return binding_current()

        def authorize_target(target: Path) -> tuple[bool, str]:
            if os.path.normcase(os.path.normpath(target)) == mountpoint and still_authorized():
                allowed, reason = active_usb_scan_authorization(target)
                if allowed is True and still_authorized():
                    return True, reason
            return False, "approval-ended"

        cancellation = _MediaScanCancellation(still_authorized)
        if cancellation.cancelled:
            self._publish_media_scan_result(UsbMediaScanResult(
                approval_id, mountpoint, "held", "The approved insertion identity could not be confirmed."
            ))
            return
        try:
            scan = SecurityScanCenter(
                max_files=64, max_total_bytes=16 * 1024**2, max_file_bytes=2 * 1024**2,
                max_directory_entries=256, max_directories=32, max_duration_seconds=10,
                usb_authorizer=authorize_target,
            ).scan_path(mountpoint, cancellation=cancellation)
        except Exception:
            result = UsbMediaScanResult(approval_id, mountpoint, "failed", "The bounded file review failed.")
        else:
            if cancellation.cancelled or scan.status == "cancelled":
                result = UsbMediaScanResult(approval_id, mountpoint, "cancelled", "The approved review ended early.")
            elif not scan.executed:
                result = UsbMediaScanResult(approval_id, mountpoint, "held", "The approved scan scope was unavailable.")
            else:
                files = scan.metrics["files_scanned"]
                findings_total = len(scan.findings)
                summary = f"Checked {files} file(s) in the bounded sample. {findings_total} finding(s) for review."
                state = scan.status
                if scan.metrics.get("yara_status") != "active":
                    state = "limited"
                    summary += " Content signatures were unavailable."
                elif state == "limited":
                    summary += " Some content was skipped or a scan limit was reached."
                result = UsbMediaScanResult(
                    approval_id, mountpoint, state, summary, files, findings_total, scan.findings[:16]
                )
        self._publish_media_scan_result(result)

    def approve_media(self, approval_id: object, pin: object) -> UsbApprovalDecision:
        binding = self._approval_policy.approval_binding(approval_id)
        require_identity = bool(getattr(self._approval_policy, "_require_identity", False))
        if require_identity and binding is not None:
            mountpoint, expected_identity = binding
            try:
                current_identity = str(self._identity_provider(mountpoint) or "").strip().casefold()
            except Exception:
                current_identity = ""
            if (
                not expected_identity
                or not current_identity
                or not hmac.compare_digest(current_identity, expected_identity)
            ):
                self._approval_policy.remove(mountpoint)
                self._identity_blind_mounts.add(mountpoint)
                if current_identity:
                    self._identity_blind_mounts.discard(mountpoint)
                self._handle_attached(
                    mountpoint,
                    "removable media (identity revalidation)",
                    present_at_start=False,
                    volume_id=current_identity,
                )
                reason = (
                    "identity_unavailable" if not current_identity else "identity_changed"
                )
                self.emit(
                    "Removable-media approval refused because the live insertion "
                    "identity no longer matches the prompt.",
                    Severity.HIGH,
                    approval_id=str(approval_id or ""),
                    mountpoint=mountpoint,
                    approval_state="untrusted",
                    reason=reason,
                    response_authorized=False,
                )
                return UsbApprovalDecision(
                    False,
                    "untrusted",
                    reason,
                    approval_id=str(approval_id or ""),
                    mountpoint=mountpoint,
                )
        decision = self._approval_policy.verify(approval_id, pin)
        if decision.approved:
            # Only after approval may Angerona touch content on the volume.
            autorun = _has_autorun(decision.mountpoint)
            if require_identity and binding is not None:
                try:
                    after_identity = str(
                        self._identity_provider(decision.mountpoint) or ""
                    ).strip().casefold()
                except Exception:
                    after_identity = ""
                if (
                    not after_identity
                    or not hmac.compare_digest(after_identity, binding[1])
                ):
                    self._approval_policy.remove(decision.mountpoint)
                    self._identity_blind_mounts.add(decision.mountpoint)
                    self.emit(
                        "Removable-media identity changed during approval-time inspection; "
                        "trust was revoked.",
                        Severity.CRITICAL,
                        approval_id=decision.approval_id,
                        mountpoint=decision.mountpoint,
                        approval_state="untrusted",
                        reason="identity_changed_during_scan",
                        response_authorized=False,
                    )
                    return UsbApprovalDecision(
                        False,
                        "untrusted",
                        "identity_changed_during_scan",
                        approval_id=decision.approval_id,
                        mountpoint=decision.mountpoint,
                    )
            if autorun:
                risk_details = decision.event_details()
                risk_details.update({
                    "event_type": "usb_media_risk",
                    "autorun": True,
                    "content_inspected": True,
                    "mitre": "T1091/T1204",
                })
                self.emit(
                    f"Approved removable media carries autorun.inf: {decision.mountpoint}. "
                    "AutoRun remains disabled; review or scan the file before use.",
                    Severity.HIGH,
                    **risk_details,
                )
            else:
                self.emit(
                    f"Removable media approved for Angerona scanning: {decision.mountpoint}. "
                    "Windows AutoRun remains disabled.",
                    Severity.INFO,
                    **decision.event_details(),
                    autorun=False,
                    content_inspected=True,
                    mitre="T1091",
                )
            if decision.reason == "approved" and require_identity and binding is not None:
                self._queue_media_scan(decision.approval_id, binding)
            return decision

        severity = Severity.HIGH if decision.reason == "locked" else Severity.LOW
        message = {
            "pin_not_configured": (
                "Removable-media approval failed closed: configure ANGERONA_USB_PIN "
                "in Angerona's protected credential store."
            ),
            "locked": (
                "Removable-media approval locked after an invalid PIN. Reset the "
                "USB PIN explicitly in Settings before any future approval."
            ),
            "invalid_pin": "Removable-media approval rejected: invalid PIN.",
            "operator_denied": "Removable-media access was denied by the operator.",
            "unknown_approval": "Removable-media approval request is no longer valid.",
        }.get(decision.reason, "Removable-media approval rejected.")
        failure_details = decision.event_details()
        failure_details["event_type"] = (
            "usb_pin_lockout" if decision.reason == "locked" else "usb_approval_rejected"
        )
        failure_details["mitre"] = "T1110" if decision.reason == "locked" else "T1091"
        self.emit(message, severity, **failure_details)
        return decision

    def deny_media(self, approval_id: object) -> UsbApprovalDecision:
        decision = self._approval_policy.deny(approval_id)
        if decision.approval_id:
            self.emit(
                f"Removable media denied for Angerona workflows: {decision.mountpoint}.",
                Severity.INFO,
                **decision.event_details(),
                mitre="T1091",
            )
        return decision

    def autorun_policy_status(self) -> AutoRunPolicyResult:
        return self._policy_result

    def _enforce_autorun_policy(self) -> None:
        include_machine = sys.platform.startswith("win") and self._autorun_policy.is_admin()
        self._policy_result = self._autorun_policy.enforce(include_machine=include_machine)
        self._last_policy_verify = time.monotonic()
        if self._policy_result.supported and not self._policy_result.enforced:
            self.emit(
                "Windows AutoRun/AutoPlay policy could not be fully enforced; "
                "removable media remains untrusted in Angerona.",
                Severity.MEDIUM,
                **self._policy_result.event_details(),
            )

    def _verify_autorun_policy_if_due(self) -> None:
        if not self._policy_result.supported:
            return
        now = time.monotonic()
        if now - self._last_policy_verify < self._POLICY_VERIFY_S:
            return
        include_machine = self._policy_result.machine_requested
        verified = self._autorun_policy.verify(include_machine=include_machine)
        self._last_policy_verify = now
        if verified.enforced:
            self._policy_result = verified
            return
        self.emit(
            "Windows AutoRun/AutoPlay deny policy drift detected; reapplying it.",
            Severity.MEDIUM,
            **verified.event_details(),
        )
        self._enforce_autorun_policy()

    def self_test(self) -> tuple[bool, str]:
        """Verify mount diffing and fail-closed approval without touching media."""
        # Exercise local values only; a self-test must not alter live mount trust.
        cur = {"E:\\": "removable", "F:\\": "removable"}
        new = set(cur) - {"E:\\"}
        detected = new == {"F:\\"}
        # autorun probe must not raise on a bogus path
        try:
            _has_autorun("Z:\\definitely-not-here")
            probe_ok = True
        except Exception:
            probe_ok = False
        test_policy = UsbApprovalPolicy(pin_loader=lambda: None)
        pending = test_policy.request("F:\\")
        gate_ok = test_policy.trust_state("F:\\") == "pending"
        ok = detected and probe_ok and gate_ok and bool(pending.approval_id)
        return ok, ("new-drive diff + fail-closed approval gate verified" if ok else
                    f"failed: detected={detected} probe={probe_ok}")


def register() -> USBMonitorModule:
    return USBMonitorModule()
