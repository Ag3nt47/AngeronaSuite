"""Staged Windows prevention, with a deliberately closed Logon-audit writer.

Reading policy grants no authority. Mutation is a protected-backend composition:
durable signed approvals -> durable intent -> single-use capability -> native
compare-and-set -> independent native readback. The diagnostic SCM service does
not install this consumer. No source UI, registry flag, shell or elevation path
can provision it. Same-process Python composition is not an OS security boundary.
Windows has no cross-writer audit-policy transaction: checks/readback detect
observed drift but cannot serialize an independent domain-policy writer.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import ctypes
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Mapping
import uuid

from .approval_identity import SignedPrincipalProof, principal_id
from .engine_transport import canonical, create_private_file, decode, private_directory, verify_private
from .file_lease import ExclusiveFileLease
from .privileged_pipe import NativePeer
from .response_broker import ResponseBroker, ResponseOperation, ResponseProposal
from .response_capability import PrivilegedOpcode, ResponseCapabilityAuthority

# Microsoft auditing-constants: Audit_Logon_Logon. Only this subcategory is writable.
LOGON_GUID = "0cce9215-69ae-11d9-bed3-505054503030"
RESOURCE = "windows-audit-logon"
PLAN_TTL = 300.0
_HEX = re.compile(r"[0-9a-f]{32}\Z")
_FIELDS = frozenset({"plan_id", "subcategory", "expected_bits", "target_bits",
                     "created_at", "expires_at", "restore_of"})
_DOMAIN = b"Angerona-Windows-Prevention-Journal-v1\0"

CATALOG = (
    ("Logon audit policy", "Staged native backend", "Enable successful and failed Logon auditing. "
     "Native policy readback proves configuration; fresh authenticated Security events are separate evidence. "
     "Domain policy can subsequently replace local settings.",
     "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon"),
    ("Memory integrity / HVCI", "Guided manual · held", "Review driver compatibility and recovery before enabling. "
     "Configured registry values are insufficient: Win32_DeviceGuard.SecurityServicesRunning must include 2. "
     "This panel has no reviewed HVCI writer or runtime collector.",
     "https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"),
    ("Vulnerable driver blocklist", "Guided manual · held", "Review Microsoft's driver block rules and compatibility. "
     "General Code Integrity enforcement alone does not prove this particular blocklist is active. "
     "No blocklist change or verified effective-state collector is installed here.",
     "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules"),
    ("LSA protection", "Guided manual · held", "Review plug-in compatibility and UEFI recovery implications. "
     "A requested registry setting does not prove the running LSA process is protected. No writer is installed.",
     "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"),
    ("App Control for Business", "Guided manual · held", "Begin with audit mode, validate allowed applications and "
     "maintain a tested signed-policy recovery route. Enforcement and firmware-bound changes require a separately "
     "reviewed backend; this panel does not deploy policy.",
     "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/"),
    ("Secure Boot", "Guided manual · held", "Check firmware support, encryption recovery keys and a tested physical "
     "recovery path before firmware changes. This application does not modify firmware or infer Secure Boot from configuration.",
     "https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot"),
)


def _bits(value):
    if type(value) is not int or value not in (0, 1, 2, 3):
        raise ValueError("Audit bits must be an integer from zero through three")
    return value


def _now(clock):
    value = clock()
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("Prevention clock is unavailable")
    return value


@dataclass(frozen=True)
class LogonAuditPlan:
    plan_id: str
    subcategory: str
    expected_bits: int
    target_bits: int
    created_at: float
    expires_at: float
    restore_of: str = ""

    def __post_init__(self):
        validate_arguments(asdict(self))

    @property
    def opcode(self):
        return PrivilegedOpcode.LOGON_AUDIT_RESTORE if self.restore_of else PrivilegedOpcode.LOGON_AUDIT_CONFIGURE


def validate_arguments(arguments: Mapping, *, now=None):
    if type(arguments) is not dict or set(arguments) != _FIELDS:
        raise ValueError("Exact Logon plan schema required")
    if not isinstance(arguments["plan_id"], str) or not _HEX.fullmatch(arguments["plan_id"]):
        raise ValueError("Invalid plan identity")
    if arguments["subcategory"] != LOGON_GUID:
        raise ValueError("Only the fixed Logon audit subcategory is supported")
    _bits(arguments["expected_bits"])
    _bits(arguments["target_bits"])
    restore = arguments["restore_of"]
    if not isinstance(restore, str) or (restore and not _HEX.fullmatch(restore)):
        raise ValueError("Invalid recovery purpose")
    if restore == arguments["plan_id"]:
        raise ValueError("Recovery must reference a distinct original plan")
    if not restore and arguments["target_bits"] != 3:
        raise ValueError("Configure can only enable both success and failure auditing")
    created, expires = arguments["created_at"], arguments["expires_at"]
    if (type(created) not in (int, float) or type(expires) not in (int, float)
            or not math.isfinite(created) or not math.isfinite(expires)
            or not 0 <= created < expires <= created + PLAN_TTL):
        raise ValueError("Invalid bounded plan lifetime")
    if now is not None and (not created <= now < expires):
        raise PermissionError("Prevention plan expired or clock moved backwards")


def prepare_logon_plan(bits: int, *, clock=time.time) -> LogonAuditPlan:
    bits = _bits(bits)
    if bits == 3:
        raise ValueError("Success and failure policy is already configured; no change is needed")
    now = _now(clock)
    return LogonAuditPlan(secrets.token_hex(16), LOGON_GUID, bits, 3, now, now + PLAN_TTL)


class _WindowsAuditApi:
    """Fixed local native API only; no privilege enabling, remote target or shell."""

    def __init__(self):
        if os.name != "nt":
            raise OSError("Windows audit APIs unavailable on this platform")
        from ctypes import wintypes

        class Guid(ctypes.Structure):
            _fields_ = [("data1", wintypes.DWORD), ("data2", wintypes.WORD),
                        ("data3", wintypes.WORD), ("data4", ctypes.c_ubyte * 8)]

        class Policy(ctypes.Structure):
            _fields_ = [("subcategory", Guid), ("information", wintypes.ULONG), ("category", Guid)]

        self._policy = Policy
        self._guid = Guid.from_buffer_copy(uuid.UUID(LOGON_GUID).bytes_le)
        self._dll = ctypes.WinDLL("advapi32", use_last_error=True)
        self._dll.AuditQuerySystemPolicy.argtypes = [ctypes.POINTER(Guid), wintypes.ULONG,
                                                     ctypes.POINTER(ctypes.POINTER(Policy))]
        self._dll.AuditQuerySystemPolicy.restype = wintypes.BOOLEAN
        self._dll.AuditSetSystemPolicy.argtypes = [ctypes.POINTER(Policy), wintypes.ULONG]
        self._dll.AuditSetSystemPolicy.restype = wintypes.BOOLEAN
        self._dll.AuditFree.argtypes = [ctypes.c_void_p]
        self._dll.AuditFree.restype = None

    def query_bits(self):
        pointer = ctypes.POINTER(self._policy)()
        if not self._dll.AuditQuerySystemPolicy(ctypes.byref(self._guid), 1, ctypes.byref(pointer)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not pointer or bytes(pointer.contents.subcategory) != bytes(self._guid):
                raise ValueError("Native audit response subcategory mismatch")
            raw = int(pointer.contents.information)
            if raw not in (0, 1, 2, 3, 4):
                raise ValueError("Unknown or contradictory native audit flags")
            return raw & 3
        finally:
            if pointer:
                self._dll.AuditFree(pointer)

    def set_bits(self, target):
        # Zero means UNCHANGED to AuditSetSystemPolicy: NONE (4) is required for rollback to off.
        policy = self._policy()
        policy.subcategory = self._guid
        policy.information = _bits(target) or 4
        if not self._dll.AuditSetSystemPolicy(ctypes.byref(policy), 1):
            raise ctypes.WinError(ctypes.get_last_error())


def inspect_logon_policy(*, native=None, clock=time.time):
    """Read-only, one native query. Must be called on a worker, not a Qt paint path."""
    try:
        bits = _bits((native if native is not None else _WindowsAuditApi()).query_bits())
        return dict(state="configured" if bits == 3 else "partial", bits=bits, checked_at=_now(clock),
                    scope="local-system-policy", runtime="unknown", event_collection="unknown",
                    reason="Native policy configuration only; effective per-user/domain policy and fresh event collection are unverified")
    except Exception as exc:
        denied = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in (5, 1314)
        return dict(state="denied" if denied else "unavailable", bits=None, checked_at=_now(clock),
                    scope="local-system-policy", runtime="unknown", event_collection="unknown",
                    reason="Native Logon policy query denied" if denied else "Native Logon policy query unavailable")


class PreventionJournal:
    """Bounded authenticated intent/recovery journal; key/state belong to installed backend.

    ACL/owner/installation validation is the service composition's responsibility.
    HMAC detects local modification, not rollback of the entire protected state.
    """
    def __init__(self, path: Path, key: bytes):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("Protected journal key required")
        self.path, self._key = Path(path), key
        if not self.path.is_absolute() or ".." in self.path.parts or str(self.path).startswith(("\\\\", "//")):
            raise ValueError("Prevention journal requires a fixed absolute local backend path")
        private_directory(self.path.parent)
        self._lease = ExclusiveFileLease(self.path.with_suffix(".lease"))
        self._lock = threading.RLock()
        self._rows = {}
        self._failed = False
        try:
            marker = self.path.with_suffix(".enrolled")
            anchor = hmac.new(key, _DOMAIN + b"enrollment", hashlib.sha256).hexdigest().encode("ascii")
            if marker.exists():
                verify_private(marker)
                with marker.open("rb") as stream:
                    stored_anchor = stream.read(65)
                if stored_anchor != anchor or not self.path.exists():
                    raise ValueError("Prevention enrollment/state missing")
                verify_private(self.path)
                with self.path.open("rb") as stream:
                    raw = stream.read(256 * 1024 + 1)
                if len(raw) > 256 * 1024:
                    raise ValueError("Prevention journal byte bound exceeded")
                document = decode(raw)
                if set(document) != {"schema", "rows", "hmac"} or document["schema"] != "angerona.windows-prevention.v1":
                    raise ValueError("Prevention journal schema invalid")
                rows = document["rows"]
                mac = hmac.new(key, _DOMAIN + canonical(rows), hashlib.sha256).hexdigest()
                if not isinstance(document["hmac"], str) or not hmac.compare_digest(document["hmac"], mac):
                    raise ValueError("Prevention journal authentication failed")
                if type(rows) is not dict or len(rows) > 128:
                    raise ValueError("Prevention journal record bound exceeded")
                for identity, row in rows.items():
                    if (type(row) is not dict or set(row) != {"arguments", "phase", "restore_attempt"}
                            or identity != row["arguments"].get("plan_id")
                            or row["phase"] not in {"intent", "configured", "uncertain", "cancelled", "restored", "verification-failed"}
                            or not isinstance(row["restore_attempt"], str)
                            or (row["restore_attempt"] and not _HEX.fullmatch(row["restore_attempt"]))):
                        raise ValueError("Prevention journal record invalid")
                    validate_arguments(row["arguments"])
                self._rows = rows
            else:
                if self.path.exists():
                    raise ValueError("Prevention enrollment marker missing")
                descriptor = create_private_file(marker)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(anchor)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._save()
        except BaseException:
            self.close()
            raise

    def close(self):
        with self._lock:
            self._failed = True
            self._lease.close()

    def ready(self):
        return not self._failed and self._lease.held

    def authorize_intent(self, arguments):
        """The capability consumer also requires the exact persisted intent."""
        with self._lock:
            row = self._rows.get(arguments["plan_id"])
            if not self.ready() or row is None or row["phase"] != "intent" or row["arguments"] != arguments:
                raise PermissionError("Exact durable prevention intent required")
            if arguments["restore_of"]:
                original = self._rows.get(arguments["restore_of"])
                if (original is None or original["restore_attempt"] != arguments["plan_id"]
                        or arguments["expected_bits"] != original["arguments"]["target_bits"]
                        or arguments["target_bits"] != original["arguments"]["expected_bits"]):
                    raise PermissionError("Exact original recovery intent required")

    def _save(self):
        if self._failed or not self._lease.held:
            raise PermissionError("Prevention journal closed or degraded")
        from .atomic_io import replace_with_retry
        raw = canonical(dict(schema="angerona.windows-prevention.v1", rows=self._rows,
                             hmac=hmac.new(self._key, _DOMAIN + canonical(self._rows), hashlib.sha256).hexdigest()))
        if len(raw) > 256 * 1024:
            self._failed = True
            raise ValueError("Prevention journal byte bound exceeded")
        temporary = self.path.with_name("." + self.path.name + "." + secrets.token_hex(8))
        try:
            descriptor = create_private_file(temporary)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if self.path.exists():
                verify_private(self.path)
            replace_with_retry(temporary, self.path)
        except BaseException:
            self._failed = True
            raise
        finally:
            temporary.unlink(missing_ok=True)

    def original(self, identity):
        with self._lock:
            if self._failed:
                raise PermissionError("Prevention journal unavailable")
            row = self._rows.get(identity)
            if (row is None or row["arguments"]["restore_of"] or row["phase"] == "cancelled"
                    or row["restore_attempt"]):
                raise PermissionError("No unspent authenticated original recovery intent")
            return dict(row["arguments"])

    def begin(self, arguments):
        validate_arguments(arguments)
        with self._lock:
            identity = arguments["plan_id"]
            if identity in self._rows or len(self._rows) >= 128:
                raise PermissionError("Prevention intent replay or journal full")
            original_id = arguments["restore_of"]
            if original_id:
                original = self.original(original_id)
                if (arguments["expected_bits"] != original["target_bits"]
                        or arguments["target_bits"] != original["expected_bits"]):
                    raise PermissionError("Recovery does not match authenticated original prior state")
                self._rows[original_id]["restore_attempt"] = identity
            self._rows[identity] = dict(arguments=dict(arguments), phase="intent", restore_attempt="")
            self._save()  # Durable original/prior state before any native mutation.

    def finish(self, arguments, phase):
        with self._lock:
            row = self._rows[arguments["plan_id"]]
            if phase == "cancelled":
                # Only _apply's definitely non-dispatched path selects this
                # phase. Keep the cancelled child identity burned, but release
                # its exact original for a NEW independently approved recovery.
                if row["phase"] != "intent" or row["arguments"] != arguments:
                    raise PermissionError("Only an exact pending intent can be cancelled")
                if arguments["restore_of"]:
                    original = self._rows[arguments["restore_of"]]
                    if (original["restore_attempt"] != arguments["plan_id"]
                            or original["arguments"]["restore_of"]
                            or arguments["expected_bits"] != original["arguments"]["target_bits"]
                            or arguments["target_bits"] != original["arguments"]["expected_bits"]):
                        raise PermissionError("Cancelled recovery does not own the original intent")
                    original["restore_attempt"] = ""
            row["phase"] = phase
            if phase == "configured" and arguments["restore_of"]:
                self._rows[arguments["restore_of"]]["phase"] = "restored"
            self._save()


class NativeLogonAuditExecutor:
    """Installed PrivilegedService executor; never registered by the source UI.

    The enclosing service MUST consume the capability before execute, and the
    guard MUST revalidate the protected installed service, not a request flag.
    This object is deliberately unconfigured without that trusted guard.
    """
    def __init__(self, *, native=None, journal=None, installed_guard=None, clock=time.time):
        self._native, self._journal, self._guard, self._clock = native, journal, installed_guard, clock

    def execute(self, opcode, resource, parameters):
        if self._guard is None or self._guard() is not True:
            raise PermissionError("Installed protected prevention consumer unavailable")
        arguments = dict(parameters)
        validate_arguments(arguments, now=_now(self._clock))
        plan = LogonAuditPlan(**arguments)
        if type(opcode) is not PrivilegedOpcode or opcode is not plan.opcode or resource != RESOURCE:
            raise PermissionError("Prevention opcode/resource/purpose mismatch")
        if self._journal is None:
            raise PermissionError("Protected prevention intent journal unavailable")
        self._journal.authorize_intent(arguments)
        native = self._native if self._native is not None else _WindowsAuditApi()
        if _bits(native.query_bits()) != plan.expected_bits:
            raise PermissionError("Native Logon policy changed since preview")
        native.set_bits(plan.target_bits)
        return dict(plan_id=plan.plan_id, requested_bits=plan.target_bits,
                    observed_bits=_bits(native.query_bits()), scope="local-system-policy")


class WindowsPreventionBackend:
    """Protected composition only; no authority, registry or consumer from requests.

    The optional consumer accepts a capability plus the closed opcode/resource/
    arguments, and must deliver them through the capability-consuming service.
    The currently shipped diagnostic service supplies no such consumer.
    """
    def __init__(self, broker: ResponseBroker, journal: PreventionJournal, *, native,
                 capabilities: ResponseCapabilityAuthority | None = None, consumer=None, clock=time.time):
        self.broker, self.journal = broker, journal
        self._native, self._capabilities, self._consumer, self._clock = native, capabilities, consumer, clock
        self._lock = threading.RLock()
        self._cancel = None
        self._clock_lock = threading.Lock()
        self._last_wall = None
        self._clock_failed = False
        for opcode in (PrivilegedOpcode.LOGON_AUDIT_CONFIGURE, PrivilegedOpcode.LOGON_AUDIT_RESTORE):
            broker.register(ResponseOperation(opcode.value, "high", "Configure the fixed native Logon audit policy",
                "Restore exactly the authenticated original bits with a separately signed recovery proposal and CAS",
                lambda arguments, operation=opcode: self._validate_for(operation, arguments), self._apply, self._verify))

    def status(self):
        configured = (self._consumer is not None and self._capabilities is not None
                      and self._capabilities.health().state == "ready"
                      and self._capabilities.health().reason == "durable-epoch-bound-authority-ready"
                      and self.journal.ready()
                      and not self._clock_failed
                      and self.broker.approval_status()["state"] == "configured")
        return dict(state="configured" if configured else "held",
                    reason="Installed consumer and durable authenticated approvals required" if not configured else
                    "Backend composed; native preconditions and two independent signed approvals still required")

    def _validate(self, arguments):
        validate_arguments(arguments, now=self._stamp())
        if arguments["restore_of"]:
            original = self.journal.original(arguments["restore_of"])
            if (arguments["expected_bits"] != original["target_bits"]
                    or arguments["target_bits"] != original["expected_bits"]):
                raise PermissionError("Recovery purpose does not match durable original state")

    def _stamp(self):
        with self._clock_lock:
            stamp = _now(self._clock)
            if self._clock_failed or (self._last_wall is not None and stamp < self._last_wall):
                self._clock_failed = True
                raise PermissionError("Prevention clock rollback detected; backend review required")
            self._last_wall = stamp
            return stamp

    def _validate_for(self, opcode, arguments):
        self._validate(arguments)
        if LogonAuditPlan(**arguments).opcode is not opcode:
            raise PermissionError("Signed operation does not match configure/recovery purpose")

    @staticmethod
    def _actor(peer):
        if type(peer) is not NativePeer:
            raise PermissionError("OS-authenticated native pipe peer required")
        parts = peer.user_sid.split("-") if isinstance(peer.user_sid, str) else []
        if (not 4 <= len(parts) <= 18 or parts[:2] != ["S", "1"]
                or peer.user_sid in {"S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545"}
                or any(not part.isascii() or not part.isdecimal() or str(int(part)) != part for part in parts[2:])):
            raise PermissionError("Canonical native Windows user SID required")
        # Production NativePeer is captured by pipe impersonation, never parsed from a request.
        return principal_id("windows-token", peer.user_sid)

    def proposal(self, plan: LogonAuditPlan, peer: NativePeer, *, dry_run=False):
        self._validate(asdict(plan))
        identity = "prevention-" + plan.plan_id + ("-preview" if dry_run else "")
        return ResponseProposal(identity, plan.opcode.value, asdict(plan), RESOURCE,
                                self._actor(peer), plan.created_at, plan.expires_at, dry_run)

    def prepare_restore(self, original_id):
        original = self.journal.original(original_id)
        if _bits(self._native.query_bits()) != original["target_bits"]:
            raise PermissionError("Current native policy does not match the recoverable target; review required")
        now = self._stamp()
        return LogonAuditPlan(secrets.token_hex(16), LOGON_GUID, original["target_bits"], original["expected_bits"],
                              now, now + PLAN_TTL, original_id)

    def approve(self, proposal, proof, peer):
        self._actor(peer)
        if (proposal.target_id != RESOURCE
                or proposal.operation_id not in {PrivilegedOpcode.LOGON_AUDIT_CONFIGURE.value, PrivilegedOpcode.LOGON_AUDIT_RESTORE.value}):
            raise PermissionError("Only a fixed prevention proposal can be approved here")
        self._validate_for(PrivilegedOpcode(proposal.operation_id), dict(proposal.arguments))
        if (type(proof) is not SignedPrincipalProof or proof.issuer != "windows-token"
                or proof.subject != peer.user_sid):
            raise PermissionError("Approval credential must match the actual native pipe user SID")
        return self.broker.approve(proposal, proof)

    def execute(self, proposal, peer, *, cancel=None):
        with self._lock:
            if proposal.requested_by != self._actor(peer) or proposal.target_id != RESOURCE:
                raise PermissionError("Prevention requester/target does not match native peer")
            if proposal.operation_id not in {PrivilegedOpcode.LOGON_AUDIT_CONFIGURE.value, PrivilegedOpcode.LOGON_AUDIT_RESTORE.value}:
                raise PermissionError("Prevention operation unavailable")
            if not proposal.dry_run and self.status()["state"] != "configured":
                raise PermissionError("Installed prevention capability consumer unavailable; operation held")
            self._cancel = cancel
            try:
                self._check_cancel()
                return self.broker.execute(proposal)
            finally:
                self._cancel = None

    def _check_cancel(self):
        if self._cancel is not None and self._cancel.is_set():
            raise PermissionError("Queued prevention work cancelled before mutation")

    def _apply(self, arguments):
        self._check_cancel()
        if self.status()["state"] != "configured":
            raise PermissionError("Prevention consumer unavailable")
        self.journal.begin(dict(arguments))
        dispatched = False
        try:
            self._check_cancel()
            if _bits(self._native.query_bits()) != arguments["expected_bits"]:
                raise PermissionError("Native Logon policy changed since preview")
            self._check_cancel()
            plan = LogonAuditPlan(**arguments)
            capability = self._capabilities.issue(opcode=plan.opcode, resource=RESOURCE, parameters=arguments)
            self._check_cancel()
            dispatched = True
            self._consumer(capability=capability, opcode=plan.opcode, resource=RESOURCE, parameters=dict(arguments))
            return dict(plan_id=plan.plan_id, prior_bits=plan.expected_bits, requested_bits=plan.target_bits,
                        scope="local-system-policy", event_collection="unknown", runtime="unknown")
        except BaseException:
            cancelled = not dispatched and self._cancel is not None and self._cancel.is_set()
            self.journal.finish(arguments, "cancelled" if cancelled else "uncertain")
            raise

    def _verify(self, arguments, _result):
        try:
            matched = _bits(self._native.query_bits()) == arguments["target_bits"]
            self.journal.finish(arguments, "configured" if matched else "verification-failed")
            return matched
        except Exception:
            self.journal.finish(arguments, "uncertain")
            return False
