"""
remediation_actions.py — vetted, reversible active-remediation library.

Why this exists: the Posture Hardening loop used to *stage* an LLM-authored
PowerShell script and never run it (review-gated), so a red-team finding never
actually got fixed. Auto-running a 2B-model's freehand PowerShell is exactly the
poisoning / DoS vector called out in the threat assessment. The safe way to get
REAL active patching is a library of deterministic, idempotent, REVERSIBLE
actions the AI *selects from* (not authors), applied with a backup, a verify
step, and rollback-on-failure, behind an explicit opt-in.

Nothing here runs system-modifying actions unless a caller passes apply=True AND
(for host-level changes) the opt-in env ANGERONA_AUTO_REMEDIATE=1 is set. The
default is a dry-run PLAN so you can see exactly what would change first.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
import weakref
from dataclasses import asdict, dataclass
from pathlib import Path, PureWindowsPath
from typing import Callable, Mapping

from angerona.core.win import run_hidden

try:
    import psutil as _psutil
except Exception:
    _psutil = None

# Processes we never suspend/kill — destabilising Windows itself is not remediation.
_SYSTEM_NEVER_KILL: frozenset[str] = frozenset({
    "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "svchost.exe",
    "ntoskrnl.exe", "system", "registry",
})


def _auto_apply_enabled() -> bool:
    return os.environ.get("ANGERONA_AUTO_REMEDIATE", "0") == "1"


def _first_path_in(weakness: dict) -> str | None:
    """Best-effort extraction of a file path a weakness refers to."""
    for k in ("path", "artifact", "file"):
        if weakness.get(k):
            return str(weakness[k])
    msg = str(weakness.get("detect_message") or weakness.get("name") or "")
    for tok in msg.replace("\\", "/").split():
        if ("/" in tok or ":" in tok) and "." in tok:
            return tok.strip("'\"")
    return None


def _first_ip_in(weakness: dict) -> str | None:
    """Return one explicit globally routable peer, never a display-text guess."""
    import ipaddress

    values = [
        str(weakness[key]).strip()
        for key in ("remote_ip", "raddr")
        if weakness.get(key) is not None
    ]
    if len(values) != 1:
        return None
    candidate = values[0]
    # Host:port text is ambiguous for IPv6 and is not an exact target contract.
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    # Never automatically propose blocking local/private, multicast, reserved,
    # documentation, or other infrastructure-like address classes.
    if not address.is_global or address.is_multicast:
        return None
    return str(address)


class RemediationAction:
    key = "base"
    title = "base"
    reversible = True
    host_level = False        # True = changes the OS (registry/services); gated by opt-in
    durable_transaction = False

    def matches(self, weakness: dict) -> bool:
        return False

    def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
        raise NotImplementedError

    def begin_transaction(self, weakness: dict, quarantine_dir: Path) -> dict:
        """Create the retained record before an executable action can mutate.

        Actions with multi-step compensation data may extend this record before
        their first external call.  The generic runner always has a record to
        audit and pass to rollback, even when ``apply`` raises.
        """
        del weakness, quarantine_dir
        return {
            "action": self.key,
            "transaction_state": "prepared",
            "mutation_started": False,
            "compensation_ready": False,
        }

    def apply_transactional(
        self, weakness: dict, quarantine_dir: Path, transaction: dict
    ) -> dict:
        """Run a legacy single-step action inside a retained transaction."""
        transaction["mutation_started"] = True
        transaction["transaction_state"] = "mutation_started"
        result = self.apply(weakness, quarantine_dir)
        if not isinstance(result, dict):
            raise TypeError("remediation action returned a non-dict record")
        transaction.update(result)
        return transaction

    def rollback(self, record: dict) -> dict:
        return {"ok": False, "error": "not reversible"}

    def verify_rollback(self, record: dict) -> bool:
        """Prove the exact retained pre-state was restored."""
        del record
        return False

    def verify(self, weakness: dict, record: dict) -> bool:
        # Every registered mutation must prove its own exact postcondition.
        # A permissive base implementation can turn a command failure into a
        # false PATCHED receipt, so unknown actions fail closed.
        return False


def _expected_process_identity(weakness: dict) -> dict | None:
    """Extract the sensor-bound process identity required for PID mutation."""
    try:
        pid = int(weakness.get("pid"))
        created = float(
            weakness.get("process_create_time")
            or weakness.get("pid_create_time")
            or weakness.get("create_time")
        )
    except (TypeError, ValueError):
        return None
    if pid <= 4 or pid in {os.getpid(), os.getppid()} or created <= 0:
        return None
    exe = str(
        weakness.get("exe")
        or weakness.get("process_path")
        or weakness.get("image")
        or ""
    ).strip()
    name = str(
        weakness.get("process_name")
        or weakness.get("proc_name")
        or weakness.get("name")
        or ""
    ).strip().casefold()
    if not exe and not name:
        return None
    return {
        "pid": pid,
        "create_time": created,
        "exe": os.path.normcase(os.path.abspath(exe)) if exe else "",
        "name": name,
    }


def _compare_process_identity(process, expected: dict) -> bool | None:
    """Return True/False for a proven match/mismatch, None when unreadable."""
    try:
        if int(process.pid) != int(expected["pid"]):
            return False
        if abs(float(process.create_time()) - float(expected["create_time"])) > 0.001:
            return False
        current_name = str(process.name() or "").casefold()
        if expected.get("name") and current_name != expected["name"]:
            return False
        if expected.get("exe"):
            current_exe = os.path.normcase(os.path.abspath(str(process.exe() or "")))
            if current_exe != expected["exe"]:
                return False
        return current_name not in _SYSTEM_NEVER_KILL
    except Exception:
        return None


def _process_matches_identity(process, expected: dict) -> bool:
    """Revalidate a retained psutil Process immediately before mutation."""
    return _compare_process_identity(process, expected) is True


def _no_such_process(exc: Exception) -> bool:
    cls = getattr(_psutil, "NoSuchProcess", ()) if _psutil is not None else ()
    return bool(cls) and isinstance(exc, cls)


# ── 1. Legacy file quarantine (PROPOSAL ONLY) ───────────────────────────────
class QuarantineFileAction(RemediationAction):
    key = "quarantine_file"
    title = "Review exact-object quarantine for the flagged file"
    proposal_only = True
    executable = False
    proposal_reason = (
        "Automatic legacy path quarantine is disabled: a pathname does not bind "
        "the detected file object. Use the exact-object response broker with "
        "sensor-bound volume/file identity, digest, and authenticated rollback custody."
    )
    reversible = False
    host_level = False

    def matches(self, weakness: dict) -> bool:
        return bool(_first_path_in(weakness))

    def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
        del weakness, quarantine_dir
        return {
            "ok": False,
            "action": self.key,
            "proposal_only": True,
            "executable": False,
            "reason": self.proposal_reason,
        }

    def rollback(self, record: dict) -> dict:
        del record
        return {"ok": False, "proposal_only": True, "reason": self.proposal_reason}

    def verify(self, weakness: dict, record: dict) -> bool:
        del weakness, record
        return False


# ── 2. Disable a vulnerable driver's service (REAL, host-level, reversible) ──
_BYOVD_SCHEMA = "angerona.byovd-service-target.v1"
_BYOVD_APPROVAL_SCHEMA = "angerona.byovd-disable-approval.v1"
_BYOVD_HEX64 = re.compile(r"[0-9a-f]{64}")
_BYOVD_THUMBPRINT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_BYOVD_SERVICE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_BYOVD_TOKEN = re.compile(r"[A-Za-z0-9:._-]{8,256}")
_BYOVD_ID = re.compile(r"[A-Za-z0-9_.:-]{8,128}")
_CRITICAL_DRIVER_SERVICES = frozenset(
    {
        "acpi",
        "afd",
        "bindflt",
        "bootvid",
        "cng",
        "disk",
        "dxgkrnl",
        "fileinfo",
        "fltmgr",
        "ksecdd",
        "mountmgr",
        "mup",
        "ndis",
        "netbt",
        "ntfs",
        "partmgr",
        "pci",
        "refs",
        "spaceport",
        "storahci",
        "storport",
        "tcpip",
        "tdx",
        "volmgr",
        "volsnap",
        "wdf01000",
        "win32k",
    }
)


@dataclass(frozen=True)
class ByovdPolicyEntry:
    """One immutable exact-hash/signer authorization policy entry."""

    policy_id: str
    image_sha256: str
    signer_thumbprints: tuple[str, ...]
    service_names: tuple[str, ...]
    valid_until: float

    def __post_init__(self) -> None:
        if not _BYOVD_ID.fullmatch(self.policy_id):
            raise ValueError("BYOVD policy ID is invalid")
        if not _BYOVD_HEX64.fullmatch(self.image_sha256):
            raise ValueError("BYOVD policy image hash is invalid")
        if (
            type(self.signer_thumbprints) is not tuple
            or not self.signer_thumbprints
            or len(self.signer_thumbprints) > 16
            or any(
                not isinstance(value, str)
                or not _BYOVD_THUMBPRINT.fullmatch(value)
                for value in self.signer_thumbprints
            )
        ):
            raise ValueError("BYOVD policy signer pin set is invalid")
        if (
            type(self.service_names) is not tuple
            or not self.service_names
            or len(self.service_names) > 32
            or any(
                not isinstance(value, str) or not _BYOVD_SERVICE.fullmatch(value)
                for value in self.service_names
            )
            or any(value.casefold() in _CRITICAL_DRIVER_SERVICES for value in self.service_names)
        ):
            raise ValueError("BYOVD policy service allow-list is invalid")
        if not math.isfinite(self.valid_until) or self.valid_until <= 0:
            raise ValueError("BYOVD policy expiry is invalid")


@dataclass(frozen=True)
class ByovdServiceTarget:
    """Live typed evidence for one exact Windows driver-service object."""

    schema: str
    service_name: str
    service_type: int
    service_object_id: str
    start_type: int
    image_path: str
    image_identity: str
    image_sha256: str
    signer_status: str
    signer_thumbprint: str
    observed_at: float

    def __post_init__(self) -> None:
        if self.schema != _BYOVD_SCHEMA:
            raise ValueError("BYOVD target schema is invalid")
        if not isinstance(self.service_name, str) or not _BYOVD_SERVICE.fullmatch(
            self.service_name
        ):
            raise ValueError("BYOVD target service name is invalid")
        if self.service_name.casefold() in _CRITICAL_DRIVER_SERVICES:
            raise ValueError("critical driver services cannot be disabled")
        if type(self.service_type) is not int or self.service_type not in {1, 2}:
            raise ValueError("target is not an exact kernel/filesystem driver service")
        if not isinstance(self.service_object_id, str) or not _BYOVD_TOKEN.fullmatch(
            self.service_object_id
        ):
            raise ValueError("BYOVD service object identity is invalid")
        if type(self.start_type) is not int or self.start_type not in {0, 1, 2, 3, 4}:
            raise ValueError("BYOVD service start type is invalid")
        if (
            not isinstance(self.image_path, str)
            or len(self.image_path) > 32_767
            or not PureWindowsPath(self.image_path).is_absolute()
        ):
            raise ValueError("BYOVD image path must be an exact absolute Windows path")
        if not isinstance(self.image_identity, str) or not _BYOVD_TOKEN.fullmatch(
            self.image_identity
        ):
            raise ValueError("BYOVD image object identity is invalid")
        if not isinstance(self.image_sha256, str) or not _BYOVD_HEX64.fullmatch(
            self.image_sha256
        ):
            raise ValueError("BYOVD image digest is invalid")
        if self.signer_status != "valid":
            raise ValueError("BYOVD image signature is not valid")
        if not isinstance(
            self.signer_thumbprint, str
        ) or not _BYOVD_THUMBPRINT.fullmatch(self.signer_thumbprint):
            raise ValueError("BYOVD signer thumbprint is invalid")
        if not math.isfinite(self.observed_at) or self.observed_at < 0:
            raise ValueError("BYOVD observation time is invalid")


@dataclass(frozen=True)
class ByovdDisableApproval:
    """Authenticated, expiring operator approval for one target digest."""

    schema: str
    target: ByovdServiceTarget
    policy_id: str
    target_sha256: str
    approval_id: str
    approved_at: float
    expires_at: float
    authenticator: str


def _byovd_target_digest(target: ByovdServiceTarget) -> str:
    encoded = json.dumps(
        asdict(target), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _byovd_same_live_identity(
    expected: ByovdServiceTarget,
    current: ByovdServiceTarget,
    *,
    expected_start_type: int | None = None,
) -> bool:
    expected_value = asdict(expected)
    current_value = asdict(current)
    expected_value.pop("observed_at")
    current_value.pop("observed_at")
    if expected_start_type is not None:
        expected_value["start_type"] = expected_start_type
    return hmac.compare_digest(
        json.dumps(
            expected_value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8"),
        json.dumps(
            current_value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8"),
    )


class ByovdResponseAuthority:
    """Mint/verify exact BYOVD response approvals behind a trusted observer.

    The observer must collect live service-registry type/object identity, opened
    image identity/hash and Authenticode signer evidence.  This authority adds
    immutable hash/signer/service policy pins, freshness, exact operator digest
    confirmation, authentication and single-use claiming.  An absent authority
    disables the response action completely.
    """

    def __init__(
        self,
        key: bytes,
        policies: tuple[ByovdPolicyEntry, ...],
        observer: Callable[[str], ByovdServiceTarget],
        *,
        clock: Callable[[], float] = time.time,
        max_evidence_age_s: float = 30.0,
    ) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("BYOVD response authority key must be at least 32 bytes")
        if not policies or len(policies) > 1024:
            raise ValueError("BYOVD response policy must be bounded and non-empty")
        policy_map = {item.policy_id: item for item in policies}
        if len(policy_map) != len(policies):
            raise ValueError("duplicate BYOVD response policy ID")
        if not callable(observer) or not callable(clock):
            raise TypeError("BYOVD observer and clock must be callable")
        if not math.isfinite(max_evidence_age_s) or not 1 <= max_evidence_age_s <= 300:
            raise ValueError("BYOVD evidence freshness bound is invalid")
        self._key = bytes(key)
        self._policies: Mapping[str, ByovdPolicyEntry] = policy_map
        self._observer = observer
        self._clock = clock
        self._max_evidence_age_s = float(max_evidence_age_s)
        self._claimed: set[str] = set()
        self._lock = threading.Lock()

    @staticmethod
    def target_digest(target: ByovdServiceTarget) -> str:
        if type(target) is not ByovdServiceTarget:
            raise TypeError("an exact BYOVD target is required")
        return _byovd_target_digest(target)

    def _now(self) -> float:
        value = float(self._clock())
        if not math.isfinite(value) or value < 0:
            raise ValueError("BYOVD authority time is invalid")
        return value

    def _policy_for(
        self, target: ByovdServiceTarget, policy_id: str, now: float
    ) -> ByovdPolicyEntry:
        policy = self._policies.get(policy_id)
        if policy is None or now >= policy.valid_until:
            raise PermissionError("BYOVD hash/signer policy is unavailable or expired")
        if (
            not hmac.compare_digest(target.image_sha256, policy.image_sha256)
            or target.signer_thumbprint not in policy.signer_thumbprints
            or target.service_name.casefold()
            not in {name.casefold() for name in policy.service_names}
        ):
            raise PermissionError("BYOVD target does not match pinned hash/signer/service policy")
        return policy

    def _observe(self, service_name: str, now: float) -> ByovdServiceTarget:
        if not _BYOVD_SERVICE.fullmatch(service_name):
            raise ValueError("BYOVD service name is invalid")
        if service_name.casefold() in _CRITICAL_DRIVER_SERVICES:
            raise PermissionError("critical driver services cannot be disabled")
        target = self._observer(service_name)
        if type(target) is not ByovdServiceTarget:
            raise TypeError("BYOVD observer returned an invalid target contract")
        if target.service_name.casefold() != service_name.casefold():
            raise ValueError("BYOVD observer returned another service")
        age = now - target.observed_at
        if not -2.0 <= age <= self._max_evidence_age_s:
            raise PermissionError("BYOVD target evidence is stale or future-dated")
        return target

    def prepare(
        self, service_name: str, policy_id: str
    ) -> tuple[ByovdServiceTarget, str]:
        """Return fresh typed evidence and the digest an operator must approve."""
        now = self._now()
        target = self._observe(service_name, now)
        self._policy_for(target, policy_id, now)
        return target, _byovd_target_digest(target)

    def approve(
        self,
        target: ByovdServiceTarget,
        *,
        policy_id: str,
        approval_id: str,
        approved_target_sha256: str,
        ttl_s: float = 60.0,
    ) -> ByovdDisableApproval:
        """Mint only after the operator echoes the exact displayed target digest."""
        if type(target) is not ByovdServiceTarget:
            raise TypeError("an exact BYOVD target is required")
        if not _BYOVD_ID.fullmatch(approval_id):
            raise ValueError("BYOVD approval ID is invalid")
        if not math.isfinite(ttl_s) or not 5 <= ttl_s <= 120:
            raise ValueError("BYOVD approval lifetime is invalid")
        now = self._now()
        live = self._observe(target.service_name, now)
        if not _byovd_same_live_identity(target, live):
            raise PermissionError("BYOVD target changed before approval")
        self._policy_for(live, policy_id, now)
        digest = _byovd_target_digest(target)
        if (
            not _BYOVD_HEX64.fullmatch(approved_target_sha256)
            or not hmac.compare_digest(digest, approved_target_sha256)
        ):
            raise PermissionError("operator approval is not bound to the exact BYOVD target")
        core = {
            "schema": _BYOVD_APPROVAL_SCHEMA,
            "target": asdict(target),
            "policy_id": policy_id,
            "target_sha256": digest,
            "approval_id": approval_id,
            "approved_at": now,
            "expires_at": now + float(ttl_s),
        }
        authenticator = hmac.new(
            self._key,
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return ByovdDisableApproval(
            **{**core, "target": target}, authenticator=authenticator
        )

    def _approval_authentic(self, approval: ByovdDisableApproval, now: float) -> bool:
        if type(approval) is not ByovdDisableApproval:
            return False
        if type(approval.target) is not ByovdServiceTarget:
            return False
        core = asdict(approval)
        authenticator = core.pop("authenticator", "")
        expected = hmac.new(
            self._key,
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return (
            approval.schema == _BYOVD_APPROVAL_SCHEMA
            and _BYOVD_HEX64.fullmatch(approval.target_sha256) is not None
            and hmac.compare_digest(approval.target_sha256, _byovd_target_digest(approval.target))
            and hmac.compare_digest(str(authenticator), expected)
            and approval.approved_at <= now < approval.expires_at
            and 0 < approval.expires_at - approval.approved_at <= 120
        )

    def verify(self, approval: ByovdDisableApproval) -> bool:
        try:
            now = self._now()
            if not self._approval_authentic(approval, now):
                return False
            self._policy_for(approval.target, approval.policy_id, now)
            live = self._observe(approval.target.service_name, now)
            return _byovd_same_live_identity(approval.target, live)
        except Exception:
            return False

    def claim(self, approval: ByovdDisableApproval) -> bool:
        """Atomically consume one still-live exact approval immediately pre-mutation."""
        if not self.verify(approval):
            return False
        with self._lock:
            if approval.approval_id in self._claimed:
                return False
            self._claimed.add(approval.approval_id)
            return True

    def live_identity_matches(
        self,
        target: ByovdServiceTarget,
        *,
        expected_start_type: int,
    ) -> bool:
        try:
            now = self._now()
            live = self._observe(target.service_name, now)
            return _byovd_same_live_identity(
                target, live, expected_start_type=expected_start_type
            )
        except Exception:
            return False


class DisableDriverServiceAction(RemediationAction):
    key = "disable_driver_service"
    title = "Review vulnerable driver service disablement (BYOVD)"
    proposal_reason = (
        "Automatic BYOVD service mutation is unavailable: even an authenticated "
        "exact-target approval, query, ChangeServiceConfigW, and postcondition "
        "proof must share one held SCM service handle and a held image-object identity."
    )
    reversible = False
    host_level = True
    durable_transaction = False

    def __init__(self, authority: ByovdResponseAuthority | None = None) -> None:
        self._authority = authority

    @staticmethod
    def _approval(weakness: dict) -> ByovdDisableApproval | None:
        value = weakness.get("byovd_disable_approval")
        return value if type(value) is ByovdDisableApproval else None

    def matches(self, weakness: dict) -> bool:
        # Typed records may receive an operator-visible proposal.  This matcher
        # cannot grant execution authority because this action is intentionally
        # absent from ACTIONS.
        return self._approval(weakness) is not None

    def begin_transaction(self, weakness: dict, quarantine_dir: Path) -> dict:
        del weakness, quarantine_dir
        raise PermissionError(self.proposal_reason)

    def apply_transactional(
        self, weakness: dict, quarantine_dir: Path, transaction: dict
    ) -> dict:
        del weakness, quarantine_dir
        transaction.update(
            {
                "ok": False,
                "changed": False,
                "proposal_only": True,
                "mutation_started": False,
                "error": self.proposal_reason,
            }
        )
        return transaction

    def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
        del weakness, quarantine_dir
        return {
            "ok": False,
            "action": self.key,
            "changed": False,
            "proposal_only": True,
            "mutation_started": False,
            "error": self.proposal_reason,
        }

    def rollback(self, record: dict) -> dict:
        del record
        return {"ok": False, "proposal_only": True, "error": self.proposal_reason}

    def verify_rollback(self, record: dict) -> bool:
        del record
        return False

    def verify(self, weakness: dict, record: dict) -> bool:
        del weakness, record
        return False


def _hay(weakness: dict) -> str:
    return " ".join(str(weakness.get(k, "")) for k in
                    ("mitre_id", "mitre", "name", "technique", "category",
                     "detect_message")).lower()


_MITRE_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?", re.IGNORECASE)


def _exact_mitre_id(weakness: dict) -> str | None:
    """Return one exact ATT&CK identifier, refusing conflicting/free-text IDs."""
    values = []
    for key in ("mitre_id", "mitre"):
        value = weakness.get(key)
        if value is None:
            continue
        candidate = str(value).strip().upper()
        if _MITRE_ID.fullmatch(candidate) is None:
            return None
        values.append(candidate)
    if not values or len(set(values)) != 1:
        return None
    return values[0]


@dataclass(frozen=True)
class _RegistryControl:
    control_id: str
    techniques: frozenset[str]
    subkey: str
    value_name: str
    dword: int
    why: str


def _exact_control_id(weakness: dict) -> str | None:
    values = []
    for key in ("control_id", "security_control", "remediation_control"):
        value = weakness.get(key)
        if value is not None:
            values.append(str(value).strip().casefold())
    if not values:
        return None
    if not values[0] or len(set(values)) != 1:
        return ""
    return values[0]


# ── 3. Registry hardening (REAL, host-level, reversible) ────────────────────
class RegistryHardeningAction(RemediationAction):
    key = "registry_hardening"
    title = "Apply a vetted registry hardening"
    reversible = True
    host_level = True
    durable_transaction = True

    # Exact typed allow-list.  Free text never selects a registry target.  When
    # one technique maps to multiple controls (T1003.001), an explicit control
    # ID is required and ambiguity remains manual-review only.
    _CONTROLS = (
        _RegistryControl(
            "windows.lsass.run_as_ppl",
            frozenset({"T1003.001"}),
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL",
            1,
            "Run LSASS as a Protected Process (blocks credential dumping)",
        ),
        _RegistryControl(
            "windows.wdigest.disable_cleartext",
            frozenset({"T1003.001"}),
            r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential",
            0,
            "Disable WDigest cleartext credential caching",
        ),
        _RegistryControl(
            "windows.powershell.script_block_logging",
            frozenset({"T1562.011"}),
            r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "EnableScriptBlockLogging",
            1,
            "Re-enable PowerShell script-block logging",
        ),
        _RegistryControl(
            "windows.process_injection.mitigation",
            frozenset({"T1055"}),
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            "MitigationOptions",
            0x100,
            "Set process-injection mitigation flag",
        ),
        _RegistryControl(
            "windows.uac.secure_desktop_consent",
            frozenset({"T1548.002"}),
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ConsentPromptBehaviorAdmin",
            2,
            "Restore UAC to 'Prompt for consent on secure desktop'",
        ),
        _RegistryControl(
            "windows.autorun.disable_all_drives",
            frozenset({"T1547.001"}),
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun",
            0xFF,
            "Disable autorun on all drive types",
        ),
        _RegistryControl(
            "windows.registry.base_object_auditing",
            frozenset({"T1112"}),
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "auditbaseobjects",
            1,
            "Enable base-object auditing for registry change detection",
        ),
    )

    def _candidates(self, w: dict) -> tuple[_RegistryControl, ...]:
        technique = _exact_mitre_id(w)
        control_id = _exact_control_id(w)
        if technique is None or control_id == "":
            return ()
        candidates = tuple(
            control for control in self._CONTROLS if technique in control.techniques
        )
        if control_id is not None:
            candidates = tuple(
                control for control in candidates if control.control_id == control_id
            )
        return candidates

    def _entry(self, w: dict):
        candidates = self._candidates(w)
        if len(candidates) != 1:
            return None
        control = candidates[0]
        return control.subkey, control.value_name, control.dword, control.why

    def matches(self, w: dict) -> bool:
        return os.name == "nt" and len(self._candidates(w)) == 1

    @staticmethod
    def _read_state(subkey: str, value_name: str) -> tuple[bool, object, int | None]:
        import winreg

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ
            )
            try:
                value, value_type = winreg.QueryValueEx(key, value_name)
            finally:
                winreg.CloseKey(key)
            return True, value, int(value_type)
        except FileNotFoundError:
            return False, None, None

    @staticmethod
    def _state_matches(
        observed: tuple[bool, object, int | None],
        *,
        present: bool,
        value: object,
        value_type: int | None,
    ) -> bool:
        actual_present, actual_value, actual_type = observed
        if actual_present is not present:
            return False
        if not present:
            return True
        return actual_type == value_type and actual_value == value

    def begin_transaction(self, w: dict, quarantine_dir: Path) -> dict:
        del quarantine_dir
        import winreg

        candidates = self._candidates(w)
        if len(candidates) != 1:
            raise ValueError("exactly one typed registry control is required")
        control = candidates[0]
        prior_present, prior, prior_type = self._read_state(
            control.subkey, control.value_name
        )
        if prior_present and (
            prior_type != winreg.REG_DWORD or not isinstance(prior, int)
        ):
            raise ValueError("registry prior state is not an exact DWORD")
        return {
            "ok": False,
            "action": self.key,
            "technique": _exact_mitre_id(w),
            "control_id": control.control_id,
            "subkey": control.subkey,
            "name": control.value_name,
            "prior_present": prior_present,
            "prior": prior,
            "prior_type": prior_type,
            "new": int(control.dword),
            "why": control.why,
            "transaction_state": "prepared",
            "mutation_started": False,
            "compensation_ready": True,
        }

    def apply_transactional(
        self, w: dict, quarantine_dir: Path, transaction: dict
    ) -> dict:
        del w, quarantine_dir
        import winreg

        live = self._read_state(transaction["subkey"], transaction["name"])
        if not self._state_matches(
            live,
            present=bool(transaction.get("prior_present")),
            value=transaction.get("prior"),
            value_type=transaction.get("prior_type"),
        ):
            transaction.update({
                "ok": False,
                "external_conflict": True,
                "transaction_state": "external_conflict",
                "mutation_started": False,
                "error": "registry state changed after review; mutation refused",
            })
            return transaction
        transaction["mutation_started"] = True
        transaction["transaction_state"] = "mutation_started"
        k = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            transaction["subkey"],
            0,
            winreg.KEY_SET_VALUE,
        )
        try:
            winreg.SetValueEx(
                k,
                transaction["name"],
                0,
                winreg.REG_DWORD,
                int(transaction["new"]),
            )
        finally:
            winreg.CloseKey(k)
        after = self._read_state(transaction["subkey"], transaction["name"])
        transaction["ok"] = self._state_matches(
            after,
            present=True,
            value=int(transaction["new"]),
            value_type=winreg.REG_DWORD,
        )
        transaction["external_conflict"] = False
        transaction["transaction_state"] = (
            "applied" if transaction["ok"] else "postcondition_failed"
        )
        return transaction

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        try:
            transaction = self.begin_transaction(w, quarantine_dir)
        except Exception as exc:
            return {"ok": False, "action": self.key, "error": str(exc)}
        return self.apply_transactional(w, quarantine_dir, transaction)

    def rollback(self, record: dict) -> dict:
        import winreg
        try:
            live = self._read_state(record["subkey"], record["name"])
            if not self._state_matches(
                live,
                present=True,
                value=int(record["new"]),
                value_type=winreg.REG_DWORD,
            ):
                return {
                    "ok": False,
                    "external_conflict": True,
                    "error": (
                        "registry state no longer equals Angerona's committed "
                        "postcondition; stale rollback refused"
                    ),
                }
            k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, record["subkey"], 0,
                                   winreg.KEY_SET_VALUE)
            try:
                if not record.get("prior_present"):
                    try:
                        winreg.DeleteValue(k, record["name"])
                    except FileNotFoundError:
                        pass
                else:
                    if record.get("prior_type") != winreg.REG_DWORD:
                        return {"ok": False, "error": "invalid retained registry type"}
                    winreg.SetValueEx(
                        k,
                        record["name"],
                        0,
                        winreg.REG_DWORD,
                        int(record["prior"]),
                    )
            finally:
                winreg.CloseKey(k)
            verified = self._state_matches(
                self._read_state(record["subkey"], record["name"]),
                present=bool(record.get("prior_present")),
                value=record.get("prior"),
                value_type=record.get("prior_type"),
            )
            return {"ok": verified, "external_conflict": False}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def verify_rollback(self, record: dict) -> bool:
        import winreg

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, record["subkey"], 0, winreg.KEY_READ
            )
            try:
                try:
                    value, value_type = winreg.QueryValueEx(key, record["name"])
                    present = True
                except FileNotFoundError:
                    value, value_type, present = None, None, False
            finally:
                winreg.CloseKey(key)
        except FileNotFoundError:
            value, value_type, present = None, None, False
        except Exception:
            return False
        if not record.get("prior_present"):
            return present is False
        return (
            present
            and value_type == record.get("prior_type")
            and value == record.get("prior")
        )

    def verify(self, w: dict, record: dict) -> bool:
        import winreg
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, record["subkey"], 0, winreg.KEY_READ)
            try:
                val, _ = winreg.QueryValueEx(k, record["name"])
            finally:
                winreg.CloseKey(k)
            return int(val) == int(record["new"])
        except Exception:
            return False


# ── 4. ACL lockdown of a flagged staging directory (REAL, reversible) ───────
class LockdownAclAction(RemediationAction):
    key = "lockdown_acl"
    title = "Lock down a flagged directory's ACL"
    reversible = True
    host_level = True

    def _dir(self, w: dict):
        p = _first_path_in(w)
        return p if p and Path(p).is_dir() else None

    def matches(self, w: dict) -> bool:
        return os.name == "nt" and self._dir(w) is not None

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        target = self._dir(w)
        Path(quarantine_dir).mkdir(parents=True, exist_ok=True)
        backup = str(Path(quarantine_dir) / f"acl_{int(time.time())}.bak")
        parent = str(Path(target).parent)
        saved = run_hidden(
            ["icacls", target, "/save", backup, "/t"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if saved.returncode != 0 or not Path(backup).exists():
            return {
                "ok": False,
                "action": self.key,
                "target": target,
                "error": "ACL backup could not be verified",
                "rc": saved.returncode,
            }
        changed = run_hidden(
            [
                "icacls", target, "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F",
                f"{os.getenv('USERNAME', 'Administrators')}:(OI)(CI)F", "/t",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "ok": changed.returncode == 0,
            "action": self.key,
            "target": target,
            "acl_backup": backup,
            "parent": parent,
            "rc": changed.returncode,
        }

    def rollback(self, record: dict) -> dict:
        try:
            result = run_hidden(
                ["icacls", record["parent"], "/restore", record["acl_backup"]],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {"ok": result.returncode == 0, "rc": result.returncode}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


# ── 5. Windows Defender baseline (PROPOSAL ONLY) ─────────────────────────
class DefenderHardeningAction(RemediationAction):
    key = "defender_hardening"
    title = "Review and restore the Windows Defender baseline"
    proposal_only = True
    executable = False
    proposal_reason = (
        "Automatic Defender preference mutation is disabled: the current response "
        "catalog cannot retain and verify the exact prior state of every affected "
        "preference or guarantee rollback. Review the host's managed security policy "
        "and use an independently authorized administration channel."
    )
    reversible = False
    host_level = True

    def matches(self, w: dict) -> bool:
        technique = _exact_mitre_id(w)
        # T1562.011 is the exact script-block-logging control handled by the
        # registry catalog.  It must never be swallowed by broad T1562 text.
        if technique == "T1562.011":
            return False
        if technique == "T1562" or (
            technique is not None and technique.startswith("T1562.")
        ):
            return True
        return _exact_control_id(w) in {
            "windows.defender.baseline",
            "windows.amsi.integrity",
        }

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        del w, quarantine_dir
        return {
            "ok": False,
            "action": self.key,
            "proposal_only": True,
            "executable": False,
            "reason": self.proposal_reason,
        }

    def rollback(self, record: dict) -> dict:
        del record
        return {"ok": False, "proposal_only": True, "reason": self.proposal_reason}

    def verify(self, w: dict, record: dict) -> bool:
        del w, record
        return False


# ── 6. Network isolation — block a malicious remote IP (REAL, reversible) ────
class NetworkIsolationAction(RemediationAction):
    key = "network_isolation"
    title = "Block a malicious remote IP at the host firewall"
    reversible = True
    host_level = True
    durable_transaction = True
    proposal_only = True
    executable = False
    proposal_reason = (
        "Automatic weakness-row firewall mutation is disabled. Use the typed "
        "response broker with an authenticated, single-use capability bound to "
        "one exact globally routable peer and a separately verified rollback."
    )

    def matches(self, w: dict) -> bool:
        return os.name == "nt" and _first_ip_in(w) is not None

    def begin_transaction(self, w: dict, quarantine_dir: Path) -> dict:
        del quarantine_dir
        ip = _first_ip_in(w)
        if ip is None:
            raise ValueError("a validated remote IP is required for network isolation")
        rule = f"Angerona-Block-{ip}-{time.time_ns()}"
        rules = {direction: f"{rule}-{direction}" for direction in ("out", "in")}
        for name in rules.values():
            result = run_hidden(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0 or name.casefold() in str(
                result.stdout or ""
            ).casefold():
                raise RuntimeError("generated firewall compensation identity already exists")
        return {
            "ok": False,
            "action": self.key,
            "ip": ip,
            "rule": rule,
            "rules": rules,
            "attempted_rules": {},
            "returncodes": {},
            "transaction_state": "prepared",
            "mutation_started": False,
            "compensation_ready": True,
        }

    def apply_transactional(
        self, w: dict, quarantine_dir: Path, transaction: dict
    ) -> dict:
        del w, quarantine_dir
        ip = transaction["ip"]
        # Outbound + inbound block scoped to this one remote IP. Fully reversible
        # (delete the named rule). netsh is deterministic — nothing model-authored.
        for direction in ("out", "in"):
            named = transaction["rules"][direction]
            # A timeout does not prove the command had no effect. Retain the
            # exact rule identity before dispatch so compensation can delete it.
            transaction["attempted_rules"][direction] = named
            transaction["mutation_started"] = True
            transaction["transaction_state"] = "mutation_started"
            result = run_hidden(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={named}", f"dir={direction}", "action=block",
                    f"remoteip={ip}", "enable=yes",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            transaction["returncodes"][direction] = result.returncode
        transaction["ok"] = (
            all(code == 0 for code in transaction["returncodes"].values())
            and len(transaction["returncodes"]) == 2
        )
        return transaction

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        try:
            transaction = self.begin_transaction(w, quarantine_dir)
        except Exception as exc:
            return {"ok": False, "action": self.key, "error": str(exc)}
        return self.apply_transactional(w, quarantine_dir, transaction)

    def rollback(self, record: dict) -> dict:
        try:
            rules = record.get("attempted_rules") or record.get("rules") or {
                "legacy": record.get("rule", "")
            }
            results = []
            for name in rules.values():
                if not name:
                    continue
                result = run_hidden(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                results.append(result.returncode)
            return {"ok": bool(results) and all(code == 0 for code in results), "returncodes": results}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def verify_rollback(self, record: dict) -> bool:
        rules = record.get("rules")
        if not isinstance(rules, dict) or set(rules) != {"in", "out"}:
            return False
        try:
            for name in rules.values():
                result = run_hidden(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "show",
                        "rule",
                        f"name={name}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if result.returncode == 0 or name.casefold() in str(
                    result.stdout or ""
                ).casefold():
                    return False
            return True
        except Exception:
            return False

    def verify(self, w: dict, record: dict) -> bool:
        del w
        if not record.get("ok") or set(record.get("rules") or {}) != {"in", "out"}:
            return False
        try:
            for direction, name in record["rules"].items():
                result = run_hidden(
                    ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}", "verbose"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                output = str(result.stdout or "").casefold()
                wanted = "in" if direction == "in" else "out"
                if (
                    result.returncode != 0
                    or name.casefold() not in output
                    or record["ip"].casefold() not in output
                    or not re.search(rf"direction\s*:\s*{wanted}(?:bound)?\b", output)
                ):
                    return False
            return True
        except Exception:
            return False


# ── 7. AV-telemetry-aware file quarantine (G2-G) ────────────────────────────
class AVDetectionQuarantineAction(RemediationAction):
    """Explain why a legacy Defender pathname cannot authorize quarantine."""
    key = "av_quarantine"
    title = "Review exact-object quarantine for the Defender detection"
    proposal_only = True
    executable = False
    proposal_reason = QuarantineFileAction.proposal_reason
    reversible = False
    host_level = False

    def matches(self, weakness: dict) -> bool:
        if not weakness.get("threat_name"):
            return False
        return bool(_first_path_in(weakness))

    def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
        del weakness, quarantine_dir
        return {
            "ok": False,
            "action": self.key,
            "proposal_only": True,
            "executable": False,
            "reason": self.proposal_reason,
        }

    def rollback(self, record: dict) -> dict:
        del record
        return {"ok": False, "proposal_only": True, "reason": self.proposal_reason}

    def verify(self, weakness: dict, record: dict) -> bool:
        del weakness, record
        return False


# ── 8. Suspend a suspicious process (REAL, reversible, requires psutil) ──────
class SuspendProcessAction(RemediationAction):
    """Suspend (freeze) the offending process without killing it — preserves memory
    for forensics.  Reversible: rollback resumes the process.  Skipped for any
    process in the System32 never-kill list."""
    key = "suspend_process"
    title = "Suspend the suspicious process (reversible)"
    reversible = True
    host_level = True
    durable_transaction = True
    proposal_only = True
    executable = False
    proposal_reason = (
        "Automatic weakness-row process suspension is disabled. Use Adversary "
        "Combat's authenticated exact PID/create-time/image response contract."
    )

    def _pid(self, w: dict) -> int | None:
        v = w.get("pid")
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    def matches(self, w: dict) -> bool:
        expected = _expected_process_identity(w)
        if _psutil is None or expected is None:
            return False
        try:
            return _process_matches_identity(_psutil.Process(expected["pid"]), expected)
        except Exception:
            return False

    def begin_transaction(self, w: dict, quarantine_dir: Path) -> dict:
        del quarantine_dir
        expected = _expected_process_identity(w)
        pid = expected["pid"] if expected else self._pid(w)
        if expected is None or _psutil is None:
            raise ValueError("sensor-bound PID identity is required")
        proc = _psutil.Process(pid)
        if not _process_matches_identity(proc, expected):
            raise RuntimeError("process identity changed before suspend")
        prior_status = str(proc.status() or "").casefold()
        if prior_status == "stopped" or not prior_status:
            raise RuntimeError("process suspension prior state is not safely reversible")
        return {
            "ok": False,
            "action": self.key,
            **expected,
            "name": str(proc.name() or "").casefold(),
            "prior_suspended": False,
            "prior_status": prior_status,
            "transaction_state": "prepared",
            "mutation_started": False,
            "compensation_ready": True,
        }

    def apply_transactional(
        self, w: dict, quarantine_dir: Path, transaction: dict
    ) -> dict:
        del w, quarantine_dir
        try:
            proc = _psutil.Process(transaction["pid"])
            if not _process_matches_identity(proc, transaction):
                raise RuntimeError("process identity changed before suspend")
            transaction["mutation_started"] = True
            transaction["transaction_state"] = "mutation_started"
            proc.suspend()
            transaction["ok"] = True
        except Exception as exc:
            transaction["ok"] = False
            transaction["error"] = str(exc)
        return transaction

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        try:
            transaction = self.begin_transaction(w, quarantine_dir)
        except Exception as exc:
            return {"ok": False, "action": self.key, "error": str(exc)}
        return self.apply_transactional(w, quarantine_dir, transaction)

    def rollback(self, record: dict) -> dict:
        try:
            process = _psutil.Process(record["pid"])
            if not _process_matches_identity(process, record):
                return {"ok": False, "error": "process identity changed before resume"}
            process.resume()
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def verify_rollback(self, record: dict) -> bool:
        if record.get("prior_suspended") is not False:
            return False
        try:
            process = _psutil.Process(record["pid"])
            return (
                _process_matches_identity(process, record)
                and str(process.status() or "").casefold() != "stopped"
            )
        except Exception:
            return False

    def verify(self, w: dict, record: dict) -> bool:
        if not record.get("ok"):
            return False
        try:
            process = _psutil.Process(record["pid"])
            return _process_matches_identity(process, record) and process.status() == "stopped"
        except Exception:
            return False


# ── 9. Kill a process (CRITICAL/ransomware only — irreversible) ───────────────
class KillProcessAction(RemediationAction):
    """Hard-terminate the process.  Used when suspension alone is insufficient
    (active ransomware, worm, credential harvester actively exfiltrating).
    Only matches when mitre/technique context strongly indicates active malware."""
    key = "kill_process"
    title = "Terminate the malicious process (hard-kill)"
    reversible = False
    host_level = True
    durable_transaction = True
    proposal_only = True
    executable = False
    proposal_reason = (
        "Automatic weakness-row process termination is disabled. Use Adversary "
        "Combat's authenticated exact PID/create-time/image response contract."
    )

    _TRIGGERS = ("ransomware", "t1486", "worm", "t1041", "t1210",
                 "cryptominer", "keylogger", "exfil")

    def _pid(self, w: dict) -> int | None:
        v = w.get("pid")
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    def matches(self, w: dict) -> bool:
        expected = _expected_process_identity(w)
        if _psutil is None or expected is None:
            return False
        try:
            if not _process_matches_identity(_psutil.Process(expected["pid"]), expected):
                return False
        except Exception:
            return False
        h = _hay(w)
        return any(t in h for t in self._TRIGGERS)

    def begin_transaction(self, w: dict, quarantine_dir: Path) -> dict:
        del quarantine_dir
        expected = _expected_process_identity(w)
        pid = expected["pid"] if expected else self._pid(w)
        if expected is None or _psutil is None:
            raise ValueError("sensor-bound PID identity is required")
        proc = _psutil.Process(pid)
        if not _process_matches_identity(proc, expected):
            raise RuntimeError("process identity changed before termination")
        return {
            "ok": False,
            "action": self.key,
            **expected,
            "name": str(proc.name() or "").casefold(),
            "transaction_state": "prepared",
            "mutation_started": False,
            # Irreversible actions retain the exact identity needed to prove
            # their postcondition during separately authorized reconciliation.
            "compensation_ready": True,
        }

    def apply_transactional(
        self, w: dict, quarantine_dir: Path, transaction: dict
    ) -> dict:
        del w, quarantine_dir
        try:
            proc = _psutil.Process(transaction["pid"])
            if not _process_matches_identity(proc, transaction):
                raise RuntimeError("process identity changed before termination")
            transaction["mutation_started"] = True
            transaction["transaction_state"] = "mutation_started"
            proc.kill()
            transaction["ok"] = True
        except Exception as exc:
            transaction["ok"] = False
            transaction["error"] = str(exc)
        return transaction

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        try:
            transaction = self.begin_transaction(w, quarantine_dir)
        except Exception as exc:
            return {"ok": False, "action": self.key, "error": str(exc)}
        return self.apply_transactional(w, quarantine_dir, transaction)

    def verify(self, w: dict, record: dict) -> bool:
        if not record.get("ok"):
            return False
        try:
            process = _psutil.Process(record["pid"])
            # A reused PID is not proof that our target survived. The original
            # identity is gone, so only a proven mismatch is a success. An
            # AccessDenied/read error is unknown and therefore fails closed.
            return _compare_process_identity(process, record) is False
        except Exception as exc:
            return _no_such_process(exc)


# ── 10. Persistence cleanup — remove a Run/RunOnce entry (reversible) ────────
class PersistenceCleanupAction(RemediationAction):
    """Compatibility stub for legacy ambiguous autorun findings.

    A value name alone cannot authorize registry mutation: hive, 32/64-bit
    view, full subkey, registry type, and an expected data digest are all part
    of identity. Until the response catalog carries that typed evidence and a
    quarantined rollback export, autorun cleanup remains manual-review only.
    """
    key = "persistence_cleanup"
    title = "Remove malicious startup persistence entry (Run/RunOnce)"
    reversible = True
    host_level = True

    _RUN_KEYS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]

    def _entry(self, w: dict):
        name = w.get("run_key_value") or w.get("persistence_entry")
        if not name:
            return None, None
        h = _hay(w)
        for trigger in ("t1547", "persistence", "run key", "autorun", "startup"):
            if trigger in h:
                return name, self._RUN_KEYS[0]
        return None, None

    def matches(self, w: dict) -> bool:
        del w
        return False

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        del w, quarantine_dir
        return {
            "ok": False,
            "action": self.key,
            "proposal_only": True,
            "error": (
                "Automatic autorun deletion is disabled: require typed hive/view/subkey/name/"
                "type/data-digest identity and a verified rollback export."
            ),
        }

    def rollback(self, record: dict) -> dict:
        del record
        return {"ok": False, "proposal_only": True}

    def verify(self, w: dict, record: dict) -> bool:
        del w, record
        return False


# ── registry of vetted actions (most specific first) ────────────────────────
ACTIONS: list[RemediationAction] = [
    # Ambiguous Run/RunOnce value-name deletion is deliberately not registered.
    # BYOVD disablement remains proposal-only until a single held SCM service
    # handle spans approval, mutation, and postcondition verification.
    RegistryHardeningAction(),       # credential-access / UAC bypass → registry fix
    # Defender preference changes stay proposal-only until exact prior-state
    # custody, full postcondition proof, and reliable rollback exist.
    # ACL lockdown stays proposal-only until a locale-independent descriptor
    # verifier can prove and restore the exact DACL, owner, and inheritance.
    # Pathname-only quarantine stays proposal-only until it can reuse the
    # exact-object broker's pinned identity and authenticated rollback record.
]

# These entries may explain an operator-visible response proposal, but are
# deliberately outside ACTIONS and therefore cannot reach apply_remediation's
# mutation path even when both host-apply gates are enabled.
PROPOSAL_ONLY_ACTIONS: tuple[RemediationAction, ...] = (
    DefenderHardeningAction(),
    KillProcessAction(),
    SuspendProcessAction(),
    NetworkIsolationAction(),
    AVDetectionQuarantineAction(),
    QuarantineFileAction(),
    DisableDriverServiceAction(),
)

# Explicit safety classifications are evaluated before any generic executable
# matcher.  A Defender/T1562 record can therefore never be turned into a file,
# process, network, registry, or service mutation by adding target-shaped data.
DOMINANT_PROPOSAL_ACTIONS: tuple[RemediationAction, ...] = (
    PROPOSAL_ONLY_ACTIONS[0],
)


class _RecoveryCoordinator:
    """Private orchestration boundary for one store and vetted registry.

    The capability is deliberately unavailable through public recovery,
    inspection, action, or ledger APIs.  This is an in-process least-authority
    boundary for ordinary callers, not a Python sandbox: arbitrary
    introspective code already executing with Angerona's token remains outside
    the isolation promise and should be placed behind authenticated IPC.
    """

    __slots__ = (
        "_capability",
        "_registry_object",
        "_registry_snapshot",
        "_store_ref",
    )

    def __init__(self, store, registry: list[RemediationAction]) -> None:
        snapshot = tuple(registry)
        self._store_ref = weakref.ref(store)
        self._registry_object = registry
        self._registry_snapshot = snapshot
        self._capability = store._bind_recovery_coordinator(snapshot)

    def require_current(self, store, registry: list[RemediationAction]) -> None:
        if self._store_ref() is not store:
            raise RuntimeError("recovery coordinator store binding changed")
        if self._registry_object is not registry:
            raise RuntimeError("recovery action registry object changed after binding")
        if len(registry) != len(self._registry_snapshot) or any(
            current is not retained
            for current, retained in zip(registry, self._registry_snapshot)
        ):
            raise RuntimeError("recovery action registry changed after binding")

    def action_for(self, action_key: str) -> RemediationAction | None:
        matches = [
            action for action in self._registry_snapshot if action.key == action_key
        ]
        return matches[0] if len(matches) == 1 else None


_RECOVERY_COORDINATORS_LOCK = threading.Lock()
_RECOVERY_COORDINATORS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _recovery_coordinator_for(store) -> _RecoveryCoordinator:
    """Return the sole coordinator bound to this store and exact registry."""
    with _RECOVERY_COORDINATORS_LOCK:
        coordinator = _RECOVERY_COORDINATORS.get(store)
        if coordinator is None:
            coordinator = _RecoveryCoordinator(store, ACTIONS)
            _RECOVERY_COORDINATORS[store] = coordinator
        else:
            coordinator.require_current(store, ACTIONS)
        return coordinator


@dataclass(frozen=True)
class RemediationDecision:
    """One typed, fail-closed classification for a weakness record."""

    action: RemediationAction | None = None
    proposal: RemediationAction | None = None
    reason: str = ""
    rejected_matches: tuple[str, ...] = ()


def _matching_actions(
    weakness: dict, catalog: tuple[RemediationAction, ...] | list[RemediationAction]
) -> tuple[RemediationAction, ...]:
    matches = []
    for action in catalog:
        try:
            if action.matches(weakness):
                matches.append(action)
        except Exception:
            # Classification errors cannot authorize a fallback mutation.
            continue
    return tuple(matches)


def classify_remediation(weakness: dict) -> RemediationDecision:
    """Resolve one non-overlapping action decision, with denials first.

    Generic signal records may retain legacy matchers for compatibility, but
    overlapping matches are rejected instead of resolved by list ordering.
    """
    dominant = _matching_actions(weakness, DOMINANT_PROPOSAL_ACTIONS)
    if len(dominant) == 1:
        return RemediationDecision(
            proposal=dominant[0], reason=dominant[0].proposal_reason
        )
    if len(dominant) > 1:
        keys = tuple(sorted(action.key for action in dominant))
        return RemediationDecision(
            reason="ambiguous dominant safety classifications; manual review required",
            rejected_matches=keys,
        )

    executable = _matching_actions(weakness, ACTIONS)
    if len(executable) == 1:
        return RemediationDecision(action=executable[0])
    if len(executable) > 1:
        keys = tuple(sorted(action.key for action in executable))
        return RemediationDecision(
            reason="ambiguous executable action matches; typed manual review required",
            rejected_matches=keys,
        )

    proposals = _matching_actions(weakness, PROPOSAL_ONLY_ACTIONS[1:])
    if len(proposals) == 1:
        return RemediationDecision(
            proposal=proposals[0], reason=proposals[0].proposal_reason
        )
    if len(proposals) > 1:
        keys = tuple(sorted(action.key for action in proposals))
        return RemediationDecision(
            reason="ambiguous proposal-only matches; manual review required",
            rejected_matches=keys,
        )
    return RemediationDecision(reason="no vetted action; manual review required")


def select_action(weakness: dict) -> RemediationAction | None:
    """Return only a unique executable classification."""
    return classify_remediation(weakness).action


def select_proposal_action(weakness: dict) -> RemediationAction | None:
    """Return explanatory, non-executable guidance for a known response gap."""
    return classify_remediation(weakness).proposal


def plan_remediation(weaknesses: list[dict]) -> list[dict]:
    """Dry-run: what WOULD be done, per weakness. No changes."""
    plan = []
    for w in weaknesses:
        decision = classify_remediation(w)
        a = decision.action
        proposal = decision.proposal
        item = {
            "mitre": w.get("mitre_id") or w.get("mitre"),
            "action": a.key if a else (proposal.key if proposal else None),
            "title": (
                a.title if a else proposal.title if proposal
                else "no vetted action — manual review"
            ),
            "proposal_only": bool(proposal),
            "executable": bool(a),
        }
        if proposal:
            item["reason"] = proposal.proposal_reason
        elif decision.reason:
            item["reason"] = decision.reason
        if decision.rejected_matches:
            item["rejected_matches"] = list(decision.rejected_matches)
        plan.append(item)
    return plan


def apply_remediation(weaknesses: list[dict], quarantine_dir, apply: bool = False,
                      allow_host: bool | None = None, log=None,
                      trigger: str = "", db_path=None) -> dict:
    """Apply vetted actions. Safe by default:
      * apply=False  → dry-run plan only (no changes).
      * apply=True   → applies non-host actions (e.g. quarantine).
      * host-level actions (registry/services) additionally require allow_host
        (defaults to the ANGERONA_AUTO_REMEDIATE opt-in). Every applied action is
        verified; a failed verify triggers an automatic rollback.
      * trigger — caller label written to the remediation_log (e.g. "PostureHardening")
      * db_path — durable transaction/audit custody; executable actions fail
        closed when no initialized remediation database is available
    Returns {'applied','skipped','records'} — records support later rollback."""
    if allow_host is None:
        allow_host = _auto_apply_enabled()
    qdir = Path(quarantine_dir)
    records, applied, skipped = [], 0, 0
    mutation_circuit_open = False

    # ── audit log (init on first call if db_path supplied) ───────────────────
    try:
        from angerona.core.remediation_log import get_log, init_log
        if db_path is not None:
            _rlog = init_log(db_path)
        else:
            _rlog = get_log()
    except Exception:
        _rlog = None

    custody_error = ""
    unresolved: list[dict] = []
    if apply:
        required_custody_api = (
            "prepare_transaction",
            "transition_transaction",
            "finish_transaction",
            "unresolved_transactions",
        )
        if _rlog is None or any(
            not callable(getattr(_rlog, name, None)) for name in required_custody_api
        ):
            custody_error = (
                "durable remediation database custody is unavailable; "
                "all executable actions are disabled"
            )
        else:
            try:
                # Ordinary apply calls only inspect.  They never promote,
                # abandon, or compensate a PREPARED/MUTATING transaction that
                # may still belong to a live caller.
                unresolved = list(_rlog.unresolved_transactions())
            except Exception as exc:
                custody_error = f"durable remediation custody check failed: {exc}"

    def _log(level, msg):
        if log:
            try:
                log(level, msg)
            except Exception:
                pass

    def _audit(mitre, action, outcome, verified=-1, rec=None):
        if _rlog is not None:
            try:
                return _rlog.log(
                    trigger=trigger or "remediation_actions",
                    mitre=mitre or "-",
                    action_key=action.key if action else "none",
                    action_title=action.title if action else "no vetted action",
                    outcome=outcome,
                    verified=verified,
                    host_level=action.host_level if action else False,
                    record=rec,
                )
            except Exception:
                pass
        return None

    def _finish_owned(owner, result: str, rec: dict) -> dict:
        completion = _rlog.finish_transaction(owner, result=result, record=rec)
        committed_record = completion.pop("record")
        rec.clear()
        rec.update(committed_record)
        return completion

    for w in weaknesses:
        mitre = w.get("mitre_id") or w.get("mitre") or "-"
        decision = classify_remediation(w)
        action = decision.action
        if action is None:
            proposal = decision.proposal
            skipped += 1
            if proposal is not None:
                rec = {
                    "proposal_only": True,
                    "executable": False,
                    "reason": proposal.proposal_reason,
                }
                _log(
                    "INFO",
                    f"PROPOSAL ONLY {proposal.key} for {mitre}: "
                    f"{proposal.proposal_reason}",
                )
                _audit(mitre, proposal, "proposal_only", verified=-1, rec=rec)
            else:
                rec = {"reason": decision.reason}
                if decision.rejected_matches:
                    rec["rejected_matches"] = list(decision.rejected_matches)
                _audit(mitre, None, "skipped", rec=rec)
            continue
        if not apply:
            _log("INFO", f"PLAN {action.key} for {mitre}")
            _audit(mitre, action, "dry_run")
            continue
        if action.host_level and not allow_host:
            _log("INFO", f"SKIP host-level {action.key} (set ANGERONA_AUTO_REMEDIATE=1 to allow)")
            skipped += 1
            _audit(mitre, action, "skipped")
            continue

        if custody_error or unresolved or mutation_circuit_open:
            if custody_error:
                reason = custody_error
            elif unresolved:
                ids = [int(item["transaction_id"]) for item in unresolved[:8]]
                reason = (
                    "persistent remediation recovery is required for transaction(s) "
                    + ", ".join(str(item) for item in ids)
                )
            else:
                reason = "prior action left host state unknown; mutation circuit is open"
            rec = {
                "action": action.key,
                "mitre": mitre,
                "transaction_state": "recovery_required",
                "recovery_required": True,
                "mutation_started": False,
                "reason": reason,
            }
            skipped += 1
            records.append(rec)
            _log("CRITICAL", f"BLOCKED {action.key}: mutation circuit is open")
            _audit(mitre, action, "recovery_required", verified=0, rec=rec)
            continue

        try:
            rec = action.begin_transaction(w, qdir)
            if not isinstance(rec, dict):
                raise TypeError("remediation transaction initializer returned non-dict")
            if not action.durable_transaction or rec.get("compensation_ready") is not True:
                raise RuntimeError(
                    "action has no exact durable compensation/postcondition record"
                )
            rec["mitre"] = mitre
            transaction_owner = _rlog.prepare_transaction(
                trigger=trigger or "remediation_actions",
                mitre=mitre,
                action_key=action.key,
                action_title=action.title,
                host_level=bool(action.host_level),
                record=rec,
            )
            transaction_id = transaction_owner.transaction_id
            rec["transaction_id"] = transaction_id
        except Exception as exc:
            skipped += 1
            circuit_blocked = getattr(exc, "circuit_open", False) is True
            rec = {
                "action": action.key,
                "mitre": mitre,
                "transaction_state": (
                    "recovery_required" if circuit_blocked else "apply_failed"
                ),
                "mutation_started": False,
                "error": str(exc),
            }
            if circuit_blocked:
                rec.update(
                    {
                        "recovery_required": True,
                        "blocked": True,
                        "blocking_transactions": list(
                            getattr(exc, "transaction_ids", ())
                        ),
                        "reason": (
                            "a durable remediation transaction is already unresolved; "
                            "this action was not dispatched"
                        ),
                    }
                )
                records.append(rec)
            _log("CRITICAL", f"{action.key} transaction preparation failed: {exc}")
            _audit(
                mitre,
                action,
                "recovery_required" if circuit_blocked else "apply_failed",
                verified=0,
                rec=rec,
            )
            continue

        try:
            rec["transaction_state"] = "mutating"
            _rlog.transition_transaction(
                transaction_owner,
                state="MUTATING",
                record=rec,
            )
        except Exception as exc:
            skipped += 1
            rec.update(
                {
                    "transaction_state": "apply_failed",
                    "mutation_started": False,
                    "error": f"durable MUTATING transition failed: {exc}",
                }
            )
            _log("CRITICAL", f"{action.key} blocked before mutation: {exc}")
            _audit(mitre, action, "apply_failed", verified=0, rec=rec)
            continue

        apply_error = None
        try:
            rec = action.apply_transactional(w, qdir, rec)
            if not isinstance(rec, dict):
                raise TypeError("remediation action returned a non-dict transaction")
        except Exception as exc:
            apply_error = str(exc)
            rec["apply_error"] = apply_error
            rec["ok"] = False

        verified = False
        if apply_error is None and rec.get("ok") is True:
            try:
                verified = action.verify(w, rec) is True
            except Exception as exc:
                rec["verification_error"] = str(exc)
        rec["verified"] = verified

        if verified:
            try:
                proof = _finish_owned(
                    transaction_owner, "applied", rec
                )
            except Exception as exc:
                rec.update(
                    {
                        "transaction_state": "recovery_required",
                        "recovery_required": True,
                        "journal_error": str(exc),
                    }
                )
                mutation_circuit_open = True
                skipped += 1
                records.append(rec)
                _log("CRITICAL", f"{action.key} terminal journal write failed: {exc}")
                continue
            applied += 1
            _log("INFO", f"APPLIED {action.key}: {rec}")
            rec["proof_receipt"] = proof
            records.append(rec)
            continue

        skipped += 1
        # An action can prove that it made no change. Otherwise, once dispatch
        # began, failure/timeout is potentially partial and must be compensated.
        if rec.get("changed") is False or not rec.get("mutation_started"):
            try:
                proof = _finish_owned(
                    transaction_owner, "apply_failed_no_change", rec
                )
            except Exception as exc:
                rec.update(
                    {
                        "transaction_state": "recovery_required",
                        "recovery_required": True,
                        "journal_error": str(exc),
                    }
                )
                mutation_circuit_open = True
                records.append(rec)
                _log("CRITICAL", f"{action.key} terminal journal write failed: {exc}")
                continue
            rec["proof_receipt"] = proof
            _log("CRITICAL", f"{action.key} apply failed before mutation: {rec}")
            continue

        if not action.reversible:
            mutation_circuit_open = True
            records.append(rec)
            try:
                proof = _finish_owned(
                    transaction_owner, "recovery_required", rec
                )
            except Exception as exc:
                rec.update(
                    {
                        "transaction_state": "recovery_required",
                        "recovery_required": True,
                        "journal_error": str(exc),
                    }
                )
                _log("CRITICAL", f"{action.key} terminal journal write failed: {exc}")
                continue
            rec["proof_receipt"] = proof
            _log("CRITICAL", f"{action.key} failed after irreversible dispatch: {rec}")
            continue

        try:
            rollback = action.rollback(rec)
        except Exception as exc:
            rollback = {"ok": False, "error": str(exc)}
        rec["rollback"] = rollback
        rollback_verified = False
        if isinstance(rollback, dict) and rollback.get("ok") is True:
            try:
                rollback_verified = action.verify_rollback(rec) is True
            except Exception as exc:
                rec["rollback_verification_error"] = str(exc)
        rec["rollback_verified"] = rollback_verified
        if rollback_verified:
            try:
                proof = _finish_owned(
                    transaction_owner, "rolled_back", rec
                )
            except Exception as exc:
                rec.update(
                    {
                        "transaction_state": "recovery_required",
                        "recovery_required": True,
                        "journal_error": str(exc),
                    }
                )
                mutation_circuit_open = True
                records.append(rec)
                _log("CRITICAL", f"{action.key} terminal journal write failed: {exc}")
                continue
            _log("CRITICAL", f"{action.key} failed and exact rollback succeeded: {rec}")
            rec["proof_receipt"] = proof
            continue

        mutation_circuit_open = True
        records.append(rec)
        try:
            proof = _finish_owned(
                transaction_owner, "rollback_failed", rec
            )
        except Exception as exc:
            rec.update(
                {
                    "transaction_state": "recovery_required",
                    "recovery_required": True,
                    "journal_error": str(exc),
                }
            )
            _log("CRITICAL", f"{action.key} terminal journal write failed: {exc}")
            continue
        _log("CRITICAL", f"{action.key} rollback failed; recovery required: {rec}")
        rec["proof_receipt"] = proof
    return {"applied": applied, "skipped": skipped, "records": records}


def reconcile_remediation_transaction(
    transaction_id: int,
    *,
    authorized: bool = False,
    db_path=None,
) -> dict:
    """Run the sole reviewed recovery coordinator for one circuit entry.

    Public callers can request recovery but cannot claim ledger authority,
    choose a terminal outcome, replace the retained record, or manufacture a
    rollback assertion.  The private coordinator is bound once to this exact
    store and action-registry snapshot.  It claims, invokes the exact registered
    control, verifies the rollback/postcondition, obtains a store-issued proof,
    and atomically finishes.  Any failed step leaves the claim ``RECONCILING``.
    """
    if authorized is not True:
        return {"ok": False, "error": "explicit recovery authorization is required"}
    try:
        from angerona.core.remediation_log import get_log, init_log

        store = init_log(db_path) if db_path is not None else get_log()
    except Exception as exc:
        return {"ok": False, "error": f"durable remediation custody unavailable: {exc}"}
    if store is None:
        return {"ok": False, "error": "durable remediation custody unavailable"}
    try:
        coordinator = _recovery_coordinator_for(store)
        claim = store._claim_reconciliation(
            coordinator._capability, int(transaction_id)
        )
    except Exception as exc:
        return {"ok": False, "error": f"transaction claim failed: {exc}"}
    transaction = claim.get("transaction")
    if claim.get("claimed") is not True:
        current_state = transaction.get("state") if transaction else "missing"
        return {
            "ok": False,
            "transaction_id": int(transaction_id),
            "state": current_state,
            "recovery_required": current_state in {
                "PREPARED",
                "MUTATING",
                "RECOVERY_REQUIRED",
                "RECONCILING",
            },
            "error": (
                "transaction is already being reconciled"
                if current_state == "RECONCILING"
                else "transaction is not available for explicit reconciliation"
            ),
        }
    recovery_capability = claim.get("capability")
    action = coordinator.action_for(str(transaction.get("action_key") or ""))
    if action is None:
        return {
            "ok": False,
            "transaction_id": int(transaction_id),
            "state": "RECONCILING",
            "recovery_required": True,
            "error": "exact remediation action is unavailable; claim remains locked",
        }
    record = dict(transaction.get("record") or {})
    if action.reversible:
        try:
            rollback = action.rollback(record)
            verified = (
                isinstance(rollback, dict)
                and rollback.get("ok") is True
                and action.verify_rollback(record) is True
            )
        except Exception as exc:
            rollback, verified = {"ok": False, "error": str(exc)}, False
        record["rollback"] = rollback
        record["rollback_verified"] = verified
        if not verified:
            return {
                "ok": False,
                "recovery_required": True,
                "transaction_id": int(transaction_id),
                "state": "RECONCILING",
                "error": "exact rollback could not be verified; claim remains locked",
            }
        target = "ROLLED_BACK"
        operation = "verified_rollback"
        evidence = rollback
    else:
        try:
            verified = action.verify({}, record) is True
        except Exception:
            verified = False
        if not verified:
            return {
                "ok": False,
                "recovery_required": True,
                "transaction_id": int(transaction_id),
                "state": "RECONCILING",
                "error": "irreversible action postcondition could not be verified",
            }
        target = "APPLIED"
        operation = "verified_postcondition"
        evidence = {"verified": True}
    try:
        recovery_proof = store._issue_verified_recovery_proof(
            coordinator._capability,
            recovery_capability,
            action=action,
            operation=operation,
            evidence=evidence,
        )
        completion = store._finish_reconciliation(
            coordinator._capability,
            recovery_capability,
            recovery_proof,
        )
        completion.pop("record")
    except Exception as exc:
        return {
            "ok": False,
            "recovery_required": True,
            "transaction_id": int(transaction_id),
            "state": "RECONCILING",
            "error": f"durable reconciliation commit failed: {exc}",
        }
    return {
        "ok": True,
        "transaction_id": int(transaction_id),
        "state": target,
        "proof_receipt": completion,
    }
