"""Fail-closed removable-media approval and Windows AutoRun policy helpers.

The approval gate deliberately separates two different controls:

* Windows AutoRun/AutoPlay is disabled at the operating-system policy layer and
  is never re-enabled merely because an operator approves a drive.
* Angerona keeps an in-memory trust decision for each currently mounted volume.
  That decision lets the UI and Angerona scanners gate their own workflows, but
  it is not a claim that user-mode Python can deny every raw operating-system
  read. True device-access denial needs an enterprise device-control policy or
  a separately reviewed kernel/minifilter implementation.

The PIN is read from Angerona's current-user protected credential store under a
dedicated ``ANGERONA_USB_PIN`` key. It is never persisted in settings, copied
into an event, or retained by this module.
"""
from __future__ import annotations

import hmac
import os
import re
import secrets
import sys
import threading
import time
import weakref
from dataclasses import dataclass
from typing import Callable, Iterable


USB_PIN_SECRET = "ANGERONA_USB_PIN"
_PIN_RE = re.compile(r"[0-9]{4,12}\Z")
_DUMMY_PIN = "000000"
_ACTIVE_POLICIES: weakref.WeakSet = weakref.WeakSet()
_ACTIVE_POLICIES_LOCK = threading.Lock()


def _path_is_within_mount(target: object, mountpoint: str) -> bool:
    """Compare paths lexically without opening removable-media content."""
    try:
        candidate = os.path.normcase(os.path.abspath(os.fspath(target)))
        mount = os.path.normcase(os.path.abspath(mountpoint))
        return os.path.commonpath((candidate, mount)) == mount
    except (OSError, TypeError, ValueError):
        return False


def active_usb_scan_authorization(target: object) -> tuple[bool | None, str]:
    """Return the live Angerona authorization for a path on watched media.

    ``None`` means no active USB policy currently owns the target.  ``False``
    is a fail-closed decision for a watched but unapproved volume, and ``True``
    means every matching live policy records that exact mount as trusted.
    This lookup uses path strings and in-memory state only; it never opens the
    selected file or directory.
    """
    with _ACTIVE_POLICIES_LOCK:
        policies = tuple(_ACTIVE_POLICIES)
    states: list[str] = []
    for policy in policies:
        try:
            state = policy._trust_state_for_target(target)
        except Exception:
            # A broken/stale policy must not manufacture authorization.
            continue
        if state is not None:
            states.append(state)
    if not states:
        return None, "untracked"
    denied = next((state for state in states if state != "trusted"), None)
    if denied is not None:
        return False, denied
    return True, "trusted"


def _protected_usb_pin() -> str | None:
    """Return the USB PIN only from Angerona's protected OS credential store."""
    try:
        from angerona.core.secure_store import read_secret_map

        value = read_secret_map(strict=True).get(USB_PIN_SECRET, "")
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    text = str(value)
    return text if _PIN_RE.fullmatch(text) else None


def usb_pin_configured() -> bool:
    """Return protected credential readiness without exposing the credential."""
    return _protected_usb_pin() is not None


def _write_protected_usb_pin(pin: str) -> None:
    """Persist only through Angerona's verified OS-protected credential path."""
    from angerona.core.config import write_env_keys

    write_env_keys({USB_PIN_SECRET: pin})


@dataclass(frozen=True)
class UsbPinChangeResult:
    """Secret-free result from PIN enrollment/reset."""

    updated: bool
    reason: str


def _validate_pin_change(pin: object, confirmation: object) -> tuple[str, str]:
    candidate = str(pin or "")
    repeated = str(confirmation or "")
    if _PIN_RE.fullmatch(candidate) is None:
        return "", "invalid_format"
    if _PIN_RE.fullmatch(repeated) is None or not hmac.compare_digest(
        candidate.encode("ascii"), repeated.encode("ascii")
    ):
        return "", "confirmation_mismatch"
    return candidate, ""


def _notify_pin_reset() -> None:
    """Clear session lockouts and revoke trust after a protected PIN change."""
    with _ACTIVE_POLICIES_LOCK:
        policies = tuple(_ACTIVE_POLICIES)
    for policy in policies:
        try:
            policy._on_pin_reset()
        except Exception:
            # One stale policy object must not prevent the credential update from
            # revoking trust in the remaining live policies.
            continue


def configure_usb_pin(
    pin: object,
    confirmation: object,
    *,
    writer: Callable[[str], None] | None = None,
) -> UsbPinChangeResult:
    """Create/reset the PIN in protected storage, then revoke current trust.

    The PIN exists here only long enough to validate and hand to the existing
    OS-protected credential writer. It is never written to settings, logs,
    events, or policy state.
    """
    candidate, reason = _validate_pin_change(pin, confirmation)
    if reason:
        return UsbPinChangeResult(False, reason)
    try:
        (writer or _write_protected_usb_pin)(candidate)
    except Exception:
        return UsbPinChangeResult(False, "protected_store_unavailable")
    _notify_pin_reset()
    return UsbPinChangeResult(True, "pin_configured")


def _mount_key(mountpoint: object) -> str:
    text = str(mountpoint or "").strip()
    if not text or len(text) > 512 or any(ord(char) < 32 for char in text):
        raise ValueError("invalid removable-media mount point")
    return os.path.normcase(os.path.normpath(text))


@dataclass(frozen=True)
class UsbApprovalView:
    """Secret-free state safe to pass through the EventBus or GUI."""

    approval_id: str
    mountpoint: str
    detected_at: float
    autorun_present: bool
    state: str
    attempts_remaining: int
    locked_until: float
    policy_enforced: bool

    def event_details(self) -> dict[str, object]:
        return {
            "event_type": "usb_approval_required",
            "approval_id": self.approval_id,
            "mountpoint": self.mountpoint,
            "detected_at": self.detected_at,
            "autorun": self.autorun_present,
            "approval_state": self.state,
            "attempts_remaining": self.attempts_remaining,
            "locked_until": self.locked_until,
            "pin_required": True,
            "autorun_policy_enforced": self.policy_enforced,
            # User-mode approval does not pretend to be a device-control driver.
            "raw_device_access_blocked": False,
            "scope": "angerona-workflows-only",
        }


@dataclass(frozen=True)
class UsbApprovalDecision:
    approved: bool
    state: str
    reason: str
    approval_id: str = ""
    mountpoint: str = ""
    attempts_remaining: int = 0
    locked_until: float = 0.0

    def event_details(self) -> dict[str, object]:
        return {
            "event_type": "usb_approval_decision",
            "approval_id": self.approval_id,
            "mountpoint": self.mountpoint,
            "approval_state": self.state,
            "approved": self.approved,
            "reason": self.reason,
            "attempts_remaining": self.attempts_remaining,
            "locked_until": self.locked_until,
            "raw_device_access_blocked": False,
            "scope": "angerona-workflows-only",
        }


@dataclass
class _ApprovalRecord:
    approval_id: str
    mountpoint: str
    detected_at: float
    autorun_present: bool
    state: str
    attempts_remaining: int
    locked_until: float
    policy_enforced: bool
    volume_id: str = ""

    def view(self) -> UsbApprovalView:
        return UsbApprovalView(
            approval_id=self.approval_id,
            mountpoint=self.mountpoint,
            detected_at=self.detected_at,
            autorun_present=self.autorun_present,
            state=self.state,
            attempts_remaining=self.attempts_remaining,
            locked_until=self.locked_until,
            policy_enforced=self.policy_enforced,
        )


class UsbApprovalPolicy:
    """Thread-safe, bounded PIN gate for currently mounted removable media."""

    def __init__(
        self,
        *,
        pin_loader: Callable[[], str | None] | None = None,
        clock: Callable[[], float] = time.time,
        max_attempts: int = 3,
        lockout_seconds: float = 300.0,
        max_mounts: int = 64,
        pin_writer: Callable[[str], None] | None = None,
    ) -> None:
        if not 1 <= int(max_attempts) <= 10:
            raise ValueError("max_attempts must be between 1 and 10")
        if not 1.0 <= float(lockout_seconds) <= 86400.0:
            raise ValueError("lockout_seconds must be between 1 and 86400")
        if not 1 <= int(max_mounts) <= 512:
            raise ValueError("max_mounts must be between 1 and 512")
        self._pin_loader = pin_loader or _protected_usb_pin
        self._pin_writer = pin_writer
        self._clock = clock
        self._max_attempts = int(max_attempts)
        self._lockout_seconds = float(lockout_seconds)
        self._max_mounts = int(max_mounts)
        self._by_id: dict[str, _ApprovalRecord] = {}
        self._by_mount: dict[str, str] = {}
        self._pin_reset_required = False
        self._lock = threading.RLock()
        with _ACTIVE_POLICIES_LOCK:
            _ACTIVE_POLICIES.add(self)

    def pin_configured(self) -> bool:
        """Return credential readiness without exposing or caching the PIN."""
        try:
            value = self._pin_loader()
        except Exception:
            return False
        return isinstance(value, str) and _PIN_RE.fullmatch(value) is not None

    def pin_reset_required(self) -> bool:
        """Return whether an invalid attempt latched this session closed."""
        with self._lock:
            return self._pin_reset_required

    def configure_pin(
        self, pin: object, confirmation: object
    ) -> UsbPinChangeResult:
        """Enroll/reset via protected storage; never approve attached media."""
        return configure_usb_pin(
            pin,
            confirmation,
            writer=self._pin_writer,
        )

    def request(
        self,
        mountpoint: object,
        *,
        autorun_present: bool = False,
        policy_enforced: bool = False,
        volume_id: object = "",
    ) -> UsbApprovalView:
        key = _mount_key(mountpoint)
        identity = str(volume_id or "").strip().casefold()
        if len(identity) > 256 or any(ord(char) < 32 for char in identity):
            raise ValueError("invalid removable-media volume identity")
        now = float(self._clock())
        pin_ready = self.pin_configured()
        with self._lock:
            existing_id = self._by_mount.get(key)
            if existing_id:
                existing = self._by_id.get(existing_id)
                if existing is not None:
                    if identity and existing.volume_id != identity:
                        # An unknown→known identity may attach safely while the
                        # request is still pending. Once trusted, any identity
                        # transition requires a brand-new approval.
                        if existing.volume_id or existing.state == "trusted":
                            self._remove_locked(key)
                        else:
                            existing.volume_id = identity
                            return existing.view()
                    else:
                        return existing.view()
            # Bound memory even if a broken mount provider invents many paths.
            if len(self._by_mount) >= self._max_mounts:
                oldest = min(self._by_id.values(), key=lambda item: item.detected_at)
                self._remove_locked(oldest.mountpoint)
            approval_id = secrets.token_urlsafe(24)
            record = _ApprovalRecord(
                approval_id=approval_id,
                mountpoint=key,
                detected_at=now,
                autorun_present=bool(autorun_present),
                state=(
                    "locked"
                    if self._pin_reset_required
                    else "pending"
                ),
                attempts_remaining=(
                    1
                    if not self._pin_reset_required and pin_ready
                    else 0
                ),
                locked_until=0.0,
                policy_enforced=bool(policy_enforced),
                volume_id=identity,
            )
            self._by_id[approval_id] = record
            self._by_mount[key] = approval_id
            return record.view()

    def verify(self, approval_id: object, presented_pin: object) -> UsbApprovalDecision:
        token = str(approval_id or "")
        candidate = str(presented_pin or "").strip()
        # Always perform a bounded timing-safe comparison, even if the store is
        # unavailable or input is malformed. This avoids a trivial fast oracle.
        try:
            expected = self._pin_loader()
        except Exception:
            expected = None
        valid_expected = isinstance(expected, str) and _PIN_RE.fullmatch(expected) is not None
        compare_target = expected if valid_expected else _DUMMY_PIN
        candidate_for_compare = candidate if _PIN_RE.fullmatch(candidate) else _DUMMY_PIN
        matched = hmac.compare_digest(
            candidate_for_compare.encode("ascii"), compare_target.encode("ascii")
        )

        with self._lock:
            record = self._by_id.get(token)
            if record is None:
                return UsbApprovalDecision(False, "untrusted", "unknown_approval")
            if record.state == "trusted":
                return self._decision(record, True, "already_approved")
            if record.state == "denied":
                return self._decision(record, False, "operator_denied")
            if self._pin_reset_required or record.state == "locked":
                record.state = "locked"
                record.attempts_remaining = 0
                record.locked_until = 0.0
                return self._decision(record, False, "locked")
            if not valid_expected:
                # A missing/corrupt protected credential cannot approve media.
                record.state = "enrollment_required"
                record.attempts_remaining = 0
                return self._decision(record, False, "pin_not_configured")
            if matched and _PIN_RE.fullmatch(candidate):
                record.state = "trusted"
                record.attempts_remaining = 1
                record.locked_until = 0.0
                return self._decision(record, True, "approved")
            # A single incorrect value locks the entire removable-media session.
            # Removal/reinsertion cannot bypass it; only an explicit protected
            # PIN reset calls _on_pin_reset().
            self._pin_reset_required = True
            for active in self._by_id.values():
                active.state = "locked"
                active.attempts_remaining = 0
                active.locked_until = 0.0
            return self._decision(record, False, "locked")

    def deny(self, approval_id: object) -> UsbApprovalDecision:
        token = str(approval_id or "")
        with self._lock:
            record = self._by_id.get(token)
            if record is None:
                return UsbApprovalDecision(False, "untrusted", "unknown_approval")
            record.state = "denied"
            record.locked_until = 0.0
            return self._decision(record, False, "operator_denied")

    def pending(self) -> tuple[UsbApprovalView, ...]:
        with self._lock:
            rows = []
            for record in self._by_id.values():
                if record.state in {"enrollment_required", "pending", "locked"}:
                    rows.append(record.view())
            return tuple(sorted(rows, key=lambda item: item.detected_at))

    def trust_state(self, mountpoint: object) -> str:
        try:
            key = _mount_key(mountpoint)
        except ValueError:
            return "untrusted"
        with self._lock:
            token = self._by_mount.get(key)
            record = self._by_id.get(token or "")
            return record.state if record is not None else "untrusted"

    def _trust_state_for_target(self, target: object) -> str | None:
        """Return state when ``target`` belongs to a mount owned by this policy."""
        with self._lock:
            matches = [
                mountpoint
                for mountpoint in self._by_mount
                if _path_is_within_mount(target, mountpoint)
            ]
            if not matches:
                return None
            # Prefer the most-specific mount if nested mount points exist.
            mountpoint = max(matches, key=len)
            token = self._by_mount.get(mountpoint, "")
            record = self._by_id.get(token)
            return record.state if record is not None else "untrusted"

    def remove(self, mountpoint: object) -> bool:
        """Forget every decision when media is removed; trust never persists."""
        try:
            key = _mount_key(mountpoint)
        except ValueError:
            return False
        with self._lock:
            return self._remove_locked(key)

    def retain_mounts(self, mountpoints: Iterable[object]) -> None:
        current: set[str] = set()
        for mountpoint in mountpoints:
            try:
                current.add(_mount_key(mountpoint))
            except ValueError:
                continue
        with self._lock:
            for key in tuple(self._by_mount):
                if key not in current:
                    self._remove_locked(key)

    def _on_pin_reset(self) -> None:
        """Revoke attached-media trust and clear only the session lock latch."""
        with self._lock:
            self._pin_reset_required = False
            for record in self._by_id.values():
                record.state = "pending"
                record.attempts_remaining = 1
                record.locked_until = 0.0

    def _remove_locked(self, mountpoint: str) -> bool:
        token = self._by_mount.pop(mountpoint, None)
        if token is None:
            return False
        self._by_id.pop(token, None)
        return True

    @staticmethod
    def _decision(
        record: _ApprovalRecord, approved: bool, reason: str
    ) -> UsbApprovalDecision:
        return UsbApprovalDecision(
            approved=approved,
            state=record.state,
            reason=reason,
            approval_id=record.approval_id,
            mountpoint=record.mountpoint,
            attempts_remaining=record.attempts_remaining,
            locked_until=record.locked_until,
        )


@dataclass(frozen=True)
class AutoRunPolicyResult:
    supported: bool
    user_enforced: bool
    machine_requested: bool
    machine_enforced: bool | None
    verified_values: int
    errors: tuple[str, ...] = ()

    @property
    def enforced(self) -> bool:
        return self.supported and self.user_enforced and (
            not self.machine_requested or self.machine_enforced is True
        )

    def event_details(self) -> dict[str, object]:
        return {
            "event_type": "usb_autorun_policy",
            "supported": self.supported,
            "user_scope_enforced": self.user_enforced,
            "machine_scope_requested": self.machine_requested,
            "machine_scope_enforced": self.machine_enforced,
            "verified_values": self.verified_values,
            "errors": list(self.errors),
        }


class WindowsAutoRunPolicy:
    """Apply and verify exact Windows values that disable AutoRun/AutoPlay."""

    USER_VALUES = (
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
         "NoDriveTypeAutoRun", 0xFF),
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
         "NoDriveAutoRun", 0x03FFFFFF),
        (r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
         "DisableAutoplay", 1),
    )
    MACHINE_VALUES = (
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
         "NoDriveTypeAutoRun", 0xFF),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
         "NoDriveAutoRun", 0x03FFFFFF),
        (r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
         "NoAutoplayfornonVolume", 1),
    )

    def __init__(
        self,
        *,
        registry=None,
        platform: str | None = None,
        admin_check: Callable[[], bool] | None = None,
    ) -> None:
        self._platform = platform or sys.platform
        self._registry = registry
        self._admin_check = admin_check or self.is_admin

    @staticmethod
    def is_admin() -> bool:
        if not sys.platform.startswith("win"):
            return False
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    def enforce(self, *, include_machine: bool = False) -> AutoRunPolicyResult:
        registry = self._registry_module()
        if registry is None:
            return AutoRunPolicyResult(False, False, include_machine, None, 0)
        errors: list[str] = []
        user_ok, user_count = self._write_scope(
            registry, registry.HKEY_CURRENT_USER, "HKCU", self.USER_VALUES, errors
        )
        machine_requested = bool(include_machine)
        machine_ok: bool | None = None
        machine_count = 0
        if machine_requested:
            if not self._admin_check():
                machine_ok = False
                errors.append("HKLM policy not applied: administrator rights unavailable")
            else:
                machine_ok, machine_count = self._write_scope(
                    registry, registry.HKEY_LOCAL_MACHINE, "HKLM",
                    self.MACHINE_VALUES, errors,
                )
        return AutoRunPolicyResult(
            True, user_ok, machine_requested, machine_ok,
            user_count + machine_count, tuple(errors),
        )

    def verify(self, *, include_machine: bool = False) -> AutoRunPolicyResult:
        registry = self._registry_module()
        if registry is None:
            return AutoRunPolicyResult(False, False, include_machine, None, 0)
        errors: list[str] = []
        user_ok, user_count = self._verify_scope(
            registry, registry.HKEY_CURRENT_USER, "HKCU", self.USER_VALUES, errors
        )
        machine_ok: bool | None = None
        machine_count = 0
        if include_machine:
            machine_ok, machine_count = self._verify_scope(
                registry, registry.HKEY_LOCAL_MACHINE, "HKLM",
                self.MACHINE_VALUES, errors,
            )
        return AutoRunPolicyResult(
            True, user_ok, bool(include_machine), machine_ok,
            user_count + machine_count, tuple(errors),
        )

    def _registry_module(self):
        if not self._platform.startswith("win"):
            return None
        if self._registry is not None:
            return self._registry
        try:
            import winreg

            return winreg
        except ImportError:
            return None

    @staticmethod
    def _write_scope(registry, hive, label, specs, errors: list[str]) -> tuple[bool, int]:
        count = 0
        for path, name, expected in specs:
            try:
                access = registry.KEY_SET_VALUE
                if label == "HKLM":
                    access |= getattr(registry, "KEY_WOW64_64KEY", 0)
                with registry.CreateKeyEx(hive, path, 0, access) as key:
                    registry.SetValueEx(key, name, 0, registry.REG_DWORD, expected)
                # Verify every write instead of assuming SetValueEx succeeded.
                read_access = registry.KEY_READ
                if label == "HKLM":
                    read_access |= getattr(registry, "KEY_WOW64_64KEY", 0)
                with registry.OpenKey(hive, path, 0, read_access) as key:
                    value, kind = registry.QueryValueEx(key, name)
                if kind != registry.REG_DWORD or int(value) != expected:
                    raise OSError("value did not verify")
                count += 1
            except (OSError, PermissionError, ValueError, TypeError) as exc:
                errors.append(f"{label} {name}: {exc}")
        return count == len(specs), count

    @staticmethod
    def _verify_scope(registry, hive, label, specs, errors: list[str]) -> tuple[bool, int]:
        count = 0
        for path, name, expected in specs:
            try:
                access = registry.KEY_READ
                if label == "HKLM":
                    access |= getattr(registry, "KEY_WOW64_64KEY", 0)
                with registry.OpenKey(hive, path, 0, access) as key:
                    value, kind = registry.QueryValueEx(key, name)
                if kind != registry.REG_DWORD or int(value) != expected:
                    raise OSError("value is not the deny-all policy")
                count += 1
            except (OSError, PermissionError, ValueError, TypeError) as exc:
                errors.append(f"{label} {name}: {exc}")
        return count == len(specs), count
