"""Process-bound, fail-closed capabilities for narrowly scoped egress.

This module is a policy primitive, not a firewall.  A privileged network
adapter can call :class:`ProcessEgressLeaseBroker` immediately before it opens
or admits a connection, then enforce the returned decision.  Process and path
facts always come from injected observers; a requesting process cannot assert
its own executable, start identity, user, or gateway posture.

Leases deliberately retain only an executable digest and opaque identity/name
tokens.  DNS names are HMAC-tokenized and pinned to one canonical destination
IP.  A valid lease still grants no general network trust and no Angerona
response authority.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import secrets
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Callable, Mapping, Protocol


LEASE_SCHEMA = "angerona.process-egress-lease.v1"
AUDIT_SCHEMA = "angerona.process-egress-audit.v1"
MAX_LEASE_BYTES = 16 * 1024
MAX_TTL_SECONDS = 300
MAX_CONNECTIONS = 32
MAX_BYTE_BUDGET = 128 * 1024 * 1024
MAX_ACTIVE_LEASES = 1024
MAX_AUDIT_RECORDS = 512
CLOCK_ROLLBACK_TOLERANCE_MS = 1_000

EGRESS_PURPOSES = frozenset(
    {
        "online-ai",
        "operator-diagnostic",
        "personal-sentinel",
        "release-update",
        "threat-intelligence",
        "trusted-time",
    }
)
IDENTITY_TOKEN_LABELS = frozenset({"process-start", "user"})
PROTOCOLS = frozenset({"tcp", "udp"})
DECISION_CODES = frozenset(
    {
        "allowed",
        "byte-budget-exhausted",
        "clock-rollback",
        "connection-budget-exhausted",
        "connection-replay",
        "destination-ip-mismatch",
        "destination-port-mismatch",
        "dns-pin-mismatch",
        "gateway-attestation-required",
        "lease-expired",
        "lease-invalid",
        "lease-not-yet-valid",
        "lease-state-mismatch",
        "path-observation-unavailable",
        "path-token-mismatch",
        "process-executable-mismatch",
        "process-id-mismatch",
        "process-observation-unavailable",
        "protocol-mismatch",
        "pid-reuse-detected",
        "unknown-lease",
        "user-token-mismatch",
    }
)

_LEASE_DOMAIN = b"angerona/process-egress-lease/v1\x00"
_DNS_DOMAIN = b"angerona/process-egress-dns/v1\x00"
_LEASE_ID_DOMAIN = b"angerona/process-egress-id/v1\x00"
_AUDIT_DOMAIN = b"angerona/process-egress-audit/v1\x00"
_HEX = frozenset("0123456789abcdef")


class EgressLeaseRejected(ValueError):
    """An egress lease request or signed document failed closed."""


class ClockRollbackDetected(RuntimeError):
    """The broker clock moved backwards beyond its small tolerance."""


def _is_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in _HEX for character in value)
    )


def _require_token(value: object, field: str) -> str:
    if not _is_hex(value, 64):
        raise EgressLeaseRejected(f"{field} must be a lowercase SHA-256 token")
    return str(value)


def _require_path_token(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("tok_"):
        raise EgressLeaseRejected("path_token is invalid")
    suffix = value[4:]
    if not 24 <= len(suffix) <= 64 or any(character not in _HEX for character in suffix):
        raise EgressLeaseRejected("path_token is invalid")
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise EgressLeaseRejected("egress document is not canonicalizable") from exc


def _canonical_ip(value: object) -> str:
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        raise EgressLeaseRejected("destination_ip is invalid")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise EgressLeaseRejected("destination_ip is invalid") from exc
    if address.is_unspecified or address.is_multicast:
        raise EgressLeaseRejected("destination_ip cannot be unspecified or multicast")
    return address.compressed.casefold()


def _normalized_dns_name(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 253 or "\x00" in value:
        raise EgressLeaseRejected("dns_name is invalid")
    candidate = value.rstrip(".")
    try:
        normalized = candidate.encode("idna").decode("ascii").casefold()
    except UnicodeError as exc:
        raise EgressLeaseRejected("dns_name is invalid") from exc
    if not normalized or len(normalized) > 253:
        raise EgressLeaseRejected("dns_name is invalid")
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        raise EgressLeaseRejected("dns_name is invalid")
    return normalized


def _dns_token(key: bytes, dns_name: object) -> str:
    normalized = _normalized_dns_name(dns_name)
    return hmac.new(
        key, _DNS_DOMAIN + normalized.encode("ascii"), hashlib.sha256
    ).hexdigest()


def opaque_identity_token(key: bytes, label: str, raw_identity: str) -> str:
    """Create a purpose-separated token for a trusted observer.

    The raw identity is not returned or retained.  This helper is intended for
    observer adapters that turn OS process-start/user identifiers into the
    opaque fields consumed by the broker.
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise EgressLeaseRejected("identity token key must contain exactly 32 bytes")
    if label not in IDENTITY_TOKEN_LABELS:
        raise EgressLeaseRejected("identity token label is not in the closed catalog")
    if (
        not isinstance(raw_identity, str)
        or not raw_identity
        or len(raw_identity) > 1024
        or "\x00" in raw_identity
    ):
        raise EgressLeaseRejected("raw identity is invalid")
    domain = b"angerona/process-egress-identity/v1\x00" + label.encode("ascii") + b"\x00"
    return hmac.new(key, domain + raw_identity.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class ProcessIdentity:
    """Trusted current process identity returned by an injected observer."""

    pid: int
    executable_sha256: str
    process_start_token: str
    user_token: str

    def __post_init__(self) -> None:
        if type(self.pid) is not int or not 1 <= self.pid <= 2**31 - 1:
            raise EgressLeaseRejected("pid is invalid")
        _require_token(self.executable_sha256, "executable_sha256")
        _require_token(self.process_start_token, "process_start_token")
        _require_token(self.user_token, "user_token")


@dataclass(frozen=True)
class GatewayPathIdentity:
    """Current first-hop identity returned by an injected path observer."""

    path_token: str
    gateway_attested: bool

    def __post_init__(self) -> None:
        _require_path_token(self.path_token)
        if type(self.gateway_attested) is not bool:
            raise EgressLeaseRejected("gateway_attested must be boolean")


class ProcessIdentityObserver(Protocol):
    def __call__(self, pid: int) -> ProcessIdentity | None: ...


class GatewayPathObserver(Protocol):
    def __call__(self, path_token: str) -> GatewayPathIdentity | None: ...


@dataclass(frozen=True)
class EgressLease:
    schema: str
    key_id: str
    lease_id: str
    purpose: str
    pid: int
    executable_sha256: str
    process_start_token: str
    user_token: str
    dns_name_token: str
    destination_ip: str
    destination_port: int
    protocol: str
    path_token: str
    gateway_attested: bool
    issued_at_ms: int
    expires_at_ms: int
    max_connections: int
    max_bytes: int
    mac: str

    def __post_init__(self) -> None:
        if self.schema != LEASE_SCHEMA:
            raise EgressLeaseRejected("egress lease schema is invalid")
        if not _is_hex(self.key_id, 16):
            raise EgressLeaseRejected("egress lease key_id is invalid")
        _require_token(self.lease_id, "lease_id")
        if self.purpose not in EGRESS_PURPOSES:
            raise EgressLeaseRejected("egress purpose is not in the closed catalog")
        ProcessIdentity(
            self.pid,
            self.executable_sha256,
            self.process_start_token,
            self.user_token,
        )
        _require_token(self.dns_name_token, "dns_name_token")
        canonical_ip = _canonical_ip(self.destination_ip)
        if canonical_ip != self.destination_ip:
            raise EgressLeaseRejected("destination_ip is not canonical")
        if type(self.destination_port) is not int or not 1 <= self.destination_port <= 65535:
            raise EgressLeaseRejected("destination_port is invalid")
        if self.protocol not in PROTOCOLS:
            raise EgressLeaseRejected("protocol is invalid")
        _require_path_token(self.path_token)
        if type(self.gateway_attested) is not bool:
            raise EgressLeaseRejected("gateway_attested must be boolean")
        for field, value in (
            ("issued_at_ms", self.issued_at_ms),
            ("expires_at_ms", self.expires_at_ms),
        ):
            if type(value) is not int or not 0 <= value <= 32_503_680_000_000:
                raise EgressLeaseRejected(f"{field} is invalid")
        if not self.issued_at_ms < self.expires_at_ms:
            raise EgressLeaseRejected("egress lease validity interval is invalid")
        if self.expires_at_ms - self.issued_at_ms > MAX_TTL_SECONDS * 1000:
            raise EgressLeaseRejected("egress lease TTL exceeds its bound")
        if type(self.max_connections) is not int or not 1 <= self.max_connections <= MAX_CONNECTIONS:
            raise EgressLeaseRejected("connection budget is invalid")
        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_BYTE_BUDGET:
            raise EgressLeaseRejected("byte budget is invalid")
        _require_token(self.mac, "mac")

    def signing_body(self) -> dict[str, object]:
        document = asdict(self)
        document.pop("mac")
        return document

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_json(self) -> bytes:
        return _canonical(self.to_dict())

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "EgressLease":
        if not isinstance(value, Mapping) or set(value) != _LEASE_FIELDS:
            raise EgressLeaseRejected("egress lease document has an invalid shape")
        try:
            return cls(**dict(value))
        except TypeError as exc:
            raise EgressLeaseRejected("egress lease document has invalid types") from exc

    @classmethod
    def from_json(cls, payload: bytes | str) -> "EgressLease":
        raw = payload.encode("utf-8") if isinstance(payload, str) else payload
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_LEASE_BYTES:
            raise EgressLeaseRejected("egress lease document exceeds its bound")
        try:
            value = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise EgressLeaseRejected("egress lease document is invalid JSON") from exc
        if not isinstance(value, dict):
            raise EgressLeaseRejected("egress lease document must be an object")
        lease = cls.from_mapping(value)
        if lease.to_json() != raw:
            raise EgressLeaseRejected("egress lease JSON is not canonical")
        return lease


_LEASE_FIELDS = frozenset(EgressLease.__dataclass_fields__)


@dataclass(frozen=True)
class EgressAttempt:
    """One connection admission request supplied by an enforcement adapter."""

    pid: int
    dns_name: str
    destination_ip: str
    destination_port: int
    protocol: str
    path_token: str
    connection_nonce: str
    requested_bytes: int

    def __post_init__(self) -> None:
        if type(self.pid) is not int or not 1 <= self.pid <= 2**31 - 1:
            raise EgressLeaseRejected("attempt pid is invalid")
        _normalized_dns_name(self.dns_name)
        canonical_ip = _canonical_ip(self.destination_ip)
        object.__setattr__(self, "destination_ip", canonical_ip)
        if type(self.destination_port) is not int or not 1 <= self.destination_port <= 65535:
            raise EgressLeaseRejected("attempt destination port is invalid")
        protocol = self.protocol.casefold() if isinstance(self.protocol, str) else ""
        if protocol not in PROTOCOLS:
            raise EgressLeaseRejected("attempt protocol is invalid")
        object.__setattr__(self, "protocol", protocol)
        _require_path_token(self.path_token)
        _require_token(self.connection_nonce, "connection_nonce")
        if type(self.requested_bytes) is not int or not 1 <= self.requested_bytes <= MAX_BYTE_BUDGET:
            raise EgressLeaseRejected("attempt byte reservation is invalid")


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    reason_code: str
    lease_id: str
    purpose: str
    remaining_connections: int
    remaining_bytes: int
    enforcement_performed: bool = False

    def __post_init__(self) -> None:
        if type(self.allowed) is not bool or self.reason_code not in DECISION_CODES:
            raise EgressLeaseRejected("egress decision is invalid")
        if self.purpose not in EGRESS_PURPOSES | {"unknown"}:
            raise EgressLeaseRejected("egress decision purpose is invalid")
        if (
            type(self.remaining_connections) is not int
            or not 0 <= self.remaining_connections <= MAX_CONNECTIONS
            or type(self.remaining_bytes) is not int
            or not 0 <= self.remaining_bytes <= MAX_BYTE_BUDGET
        ):
            raise EgressLeaseRejected("egress decision budget is invalid")
        if type(self.enforcement_performed) is not bool or self.enforcement_performed:
            raise EgressLeaseRejected("the policy broker cannot claim enforcement")


@dataclass(frozen=True)
class EgressAuditRecord:
    schema: str
    event_token: str
    lease_id: str
    purpose: str
    allowed: bool
    reason_code: str
    gateway_attested: bool | None
    observed_at_ms: int
    enforcement_performed: bool = False

    def __post_init__(self) -> None:
        if self.schema != AUDIT_SCHEMA:
            raise EgressLeaseRejected("egress audit schema is invalid")
        _require_token(self.event_token, "event_token")
        _require_token(self.lease_id, "lease_id")
        if self.purpose not in EGRESS_PURPOSES | {"unknown"}:
            raise EgressLeaseRejected("egress audit purpose is invalid")
        if type(self.allowed) is not bool or self.reason_code not in DECISION_CODES:
            raise EgressLeaseRejected("egress audit decision is invalid")
        if self.gateway_attested is not None and type(self.gateway_attested) is not bool:
            raise EgressLeaseRejected("egress audit path posture is invalid")
        if type(self.observed_at_ms) is not int or self.observed_at_ms < 0:
            raise EgressLeaseRejected("egress audit time is invalid")
        if type(self.enforcement_performed) is not bool or self.enforcement_performed:
            raise EgressLeaseRejected("broker audit cannot claim enforcement")


@dataclass(frozen=True)
class EgressAuditBatch:
    records: tuple[EgressAuditRecord, ...]
    complete: bool
    lost_records: int = 0
    reason: str = ""

    def __post_init__(self) -> None:
        if len(self.records) > MAX_AUDIT_RECORDS:
            raise EgressLeaseRejected("egress audit batch exceeds its bound")
        if type(self.complete) is not bool:
            raise EgressLeaseRejected("egress audit completeness is invalid")
        if type(self.lost_records) is not int or not 0 <= self.lost_records <= 2**31 - 1:
            raise EgressLeaseRejected("egress lost-record count is invalid")
        if not isinstance(self.reason, str) or len(self.reason) > 160 or "\x00" in self.reason:
            raise EgressLeaseRejected("egress audit reason is invalid")


@dataclass
class _LeaseUsage:
    fingerprint: str
    expires_at_ms: int
    used_connections: int = 0
    used_bytes: int = 0
    seen_nonces: set[str] | None = None

    def __post_init__(self) -> None:
        if self.seen_nonces is None:
            self.seen_nonces = set()


class ProcessEgressLeaseBroker:
    """Mint and validate least-privilege egress capabilities.

    ``authorize`` only returns a decision.  The injected caller remains
    responsible for binding that decision to an OS socket/firewall primitive
    without a time-of-check/time-of-use gap.
    """

    def __init__(
        self,
        authority_key: bytes,
        *,
        process_observer: ProcessIdentityObserver,
        path_observer: GatewayPathObserver,
        clock: Callable[[], float] = time.time,
        nonce_factory: Callable[[], bytes] = lambda: secrets.token_bytes(32),
        require_gateway_attestation: bool = True,
    ) -> None:
        if not isinstance(authority_key, bytes) or len(authority_key) != 32:
            raise EgressLeaseRejected("egress authority requires exactly 32 key bytes")
        if not callable(process_observer) or not callable(path_observer):
            raise EgressLeaseRejected("egress observations must be injected callables")
        if not callable(clock) or not callable(nonce_factory):
            raise EgressLeaseRejected("egress clock and nonce source must be callable")
        if type(require_gateway_attestation) is not bool:
            raise EgressLeaseRejected("gateway attestation policy must be boolean")
        self._key = authority_key
        self.key_id = hashlib.sha256(authority_key).hexdigest()[:16]
        self._process_observer = process_observer
        self._path_observer = path_observer
        self._clock = clock
        self._nonce_factory = nonce_factory
        self._require_gateway = require_gateway_attestation
        self._lock = threading.RLock()
        self._last_clock_ms: int | None = None
        self._clock_unsafe = False
        self._serial = 0
        self._leases: dict[str, _LeaseUsage] = {}
        self._audit: deque[EgressAuditRecord] = deque()
        self._lost_audit = 0

    def _checked_now_locked(self) -> int:
        if self._clock_unsafe:
            raise ClockRollbackDetected("egress clock is quarantined after rollback")
        try:
            raw = self._clock()
            numeric = float(raw)
        except (TypeError, ValueError) as exc:
            self._clock_unsafe = True
            raise ClockRollbackDetected("egress clock is invalid") from exc
        if not math.isfinite(numeric) or not 0 <= numeric <= 32_503_680_000:
            self._clock_unsafe = True
            raise ClockRollbackDetected("egress clock is invalid")
        current = int(numeric * 1000)
        if (
            self._last_clock_ms is not None
            and current + CLOCK_ROLLBACK_TOLERANCE_MS < self._last_clock_ms
        ):
            self._clock_unsafe = True
            raise ClockRollbackDetected("egress clock rollback detected")
        self._last_clock_ms = max(current, self._last_clock_ms or current)
        return current

    def _sign(self, body: Mapping[str, object]) -> str:
        return hmac.new(self._key, _LEASE_DOMAIN + _canonical(body), hashlib.sha256).hexdigest()

    def _fingerprint(self, lease: EgressLease) -> str:
        return hashlib.sha256(lease.to_json()).hexdigest()

    def _verify_signature(self, lease: EgressLease) -> bool:
        return lease.key_id == self.key_id and hmac.compare_digest(
            lease.mac, self._sign(lease.signing_body())
        )

    def _prune_locked(self, now_ms: int) -> None:
        expired = [
            lease_id
            for lease_id, usage in self._leases.items()
            if now_ms >= usage.expires_at_ms
        ]
        for lease_id in expired:
            self._leases.pop(lease_id, None)

    def issue(
        self,
        *,
        pid: int,
        purpose: str,
        dns_name: str,
        destination_ip: str,
        destination_port: int,
        protocol: str,
        path_token: str,
        ttl_seconds: int = 60,
        max_connections: int = 1,
        max_bytes: int = 1_048_576,
    ) -> EgressLease:
        """Issue a lease from independently observed process/path evidence."""
        if type(pid) is not int or not 1 <= pid <= 2**31 - 1:
            raise EgressLeaseRejected("pid is invalid")
        if purpose not in EGRESS_PURPOSES:
            raise EgressLeaseRejected("egress purpose is not in the closed catalog")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise EgressLeaseRejected("egress lease TTL is invalid")
        if type(max_connections) is not int or not 1 <= max_connections <= MAX_CONNECTIONS:
            raise EgressLeaseRejected("connection budget is invalid")
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTE_BUDGET:
            raise EgressLeaseRejected("byte budget is invalid")
        canonical_ip = _canonical_ip(destination_ip)
        if type(destination_port) is not int or not 1 <= destination_port <= 65535:
            raise EgressLeaseRejected("destination port is invalid")
        normalized_protocol = protocol.casefold() if isinstance(protocol, str) else ""
        if normalized_protocol not in PROTOCOLS:
            raise EgressLeaseRejected("protocol is invalid")
        canonical_path = _require_path_token(path_token)
        identity = self._process_observer(pid)
        if not isinstance(identity, ProcessIdentity) or identity.pid != pid:
            raise EgressLeaseRejected("trusted process observation is unavailable")
        path = self._path_observer(canonical_path)
        if not isinstance(path, GatewayPathIdentity) or path.path_token != canonical_path:
            raise EgressLeaseRejected("trusted path observation is unavailable")
        if self._require_gateway and not path.gateway_attested:
            raise EgressLeaseRejected("gateway-attested path is required")

        with self._lock:
            now_ms = self._checked_now_locked()
            self._prune_locked(now_ms)
            if len(self._leases) >= MAX_ACTIVE_LEASES:
                raise EgressLeaseRejected("active egress lease capacity is exhausted")
            nonce = self._nonce_factory()
            if not isinstance(nonce, bytes) or not 16 <= len(nonce) <= 64:
                raise EgressLeaseRejected("egress nonce source returned invalid entropy")
            self._serial += 1
            seed = (
                nonce
                + now_ms.to_bytes(8, "big")
                + self._serial.to_bytes(8, "big")
                + identity.process_start_token.encode("ascii")
            )
            lease_id = hmac.new(self._key, _LEASE_ID_DOMAIN + seed, hashlib.sha256).hexdigest()
            unsigned: dict[str, object] = {
                "schema": LEASE_SCHEMA,
                "key_id": self.key_id,
                "lease_id": lease_id,
                "purpose": purpose,
                "pid": pid,
                "executable_sha256": identity.executable_sha256,
                "process_start_token": identity.process_start_token,
                "user_token": identity.user_token,
                "dns_name_token": _dns_token(self._key, dns_name),
                "destination_ip": canonical_ip,
                "destination_port": destination_port,
                "protocol": normalized_protocol,
                "path_token": canonical_path,
                "gateway_attested": path.gateway_attested,
                "issued_at_ms": now_ms,
                "expires_at_ms": now_ms + ttl_seconds * 1000,
                "max_connections": max_connections,
                "max_bytes": max_bytes,
            }
            lease = EgressLease(**unsigned, mac=self._sign(unsigned))
            self._leases[lease_id] = _LeaseUsage(
                self._fingerprint(lease), lease.expires_at_ms
            )
            return lease

    def _append_audit_locked(
        self,
        lease: EgressLease | None,
        attempt: EgressAttempt | None,
        decision: EgressDecision,
        now_ms: int,
        gateway_attested: bool | None,
    ) -> None:
        nonce = attempt.connection_nonce if attempt is not None else "0" * 64
        material = _canonical(
            {
                "lease_id": decision.lease_id,
                "nonce": nonce,
                "reason": decision.reason_code,
                "observed_at_ms": now_ms,
                "remaining_connections": decision.remaining_connections,
                "remaining_bytes": decision.remaining_bytes,
            }
        )
        event_token = hmac.new(self._key, _AUDIT_DOMAIN + material, hashlib.sha256).hexdigest()
        record = EgressAuditRecord(
            schema=AUDIT_SCHEMA,
            event_token=event_token,
            lease_id=decision.lease_id,
            purpose=lease.purpose if lease is not None else "unknown",
            allowed=decision.allowed,
            reason_code=decision.reason_code,
            gateway_attested=gateway_attested,
            observed_at_ms=now_ms,
        )
        if len(self._audit) >= MAX_AUDIT_RECORDS:
            self._audit.popleft()
            self._lost_audit = min(2**31 - 1, self._lost_audit + 1)
        self._audit.append(record)

    def _decision_locked(
        self,
        *,
        lease: EgressLease | None,
        attempt: EgressAttempt | None,
        allowed: bool,
        reason: str,
        now_ms: int,
        usage: _LeaseUsage | None,
        gateway_attested: bool | None,
    ) -> EgressDecision:
        if lease is None:
            lease_id, purpose = "0" * 64, "unknown"
            remaining_connections = 0
            remaining_bytes = 0
        else:
            lease_id, purpose = lease.lease_id, lease.purpose
            remaining_connections = max(
                0, lease.max_connections - (usage.used_connections if usage else 0)
            )
            remaining_bytes = max(0, lease.max_bytes - (usage.used_bytes if usage else 0))
        decision = EgressDecision(
            allowed,
            reason,
            lease_id,
            purpose,
            remaining_connections,
            remaining_bytes,
        )
        self._append_audit_locked(
            lease, attempt, decision, now_ms, gateway_attested
        )
        return decision

    def authorize(self, lease: object, attempt: object) -> EgressDecision:
        """Validate and consume one connection/byte reservation atomically."""
        with self._lock:
            try:
                now_ms = self._checked_now_locked()
            except ClockRollbackDetected:
                now_ms = self._last_clock_ms or 0
                typed_lease = lease if isinstance(lease, EgressLease) else None
                typed_attempt = attempt if isinstance(attempt, EgressAttempt) else None
                return self._decision_locked(
                    lease=typed_lease,
                    attempt=typed_attempt,
                    allowed=False,
                    reason="clock-rollback",
                    now_ms=now_ms,
                    usage=None,
                    gateway_attested=None,
                )
            if not isinstance(lease, EgressLease) or not isinstance(attempt, EgressAttempt):
                return self._decision_locked(
                    lease=None,
                    attempt=None,
                    allowed=False,
                    reason="lease-invalid",
                    now_ms=now_ms,
                    usage=None,
                    gateway_attested=None,
                )
            if not self._verify_signature(lease):
                return self._decision_locked(
                    lease=lease,
                    attempt=attempt,
                    allowed=False,
                    reason="lease-invalid",
                    now_ms=now_ms,
                    usage=None,
                    gateway_attested=None,
                )
            usage = self._leases.get(lease.lease_id)
            if usage is None:
                return self._decision_locked(
                    lease=lease,
                    attempt=attempt,
                    allowed=False,
                    reason="unknown-lease",
                    now_ms=now_ms,
                    usage=None,
                    gateway_attested=None,
                )
            if not hmac.compare_digest(usage.fingerprint, self._fingerprint(lease)):
                return self._decision_locked(
                    lease=lease,
                    attempt=attempt,
                    allowed=False,
                    reason="lease-state-mismatch",
                    now_ms=now_ms,
                    usage=usage,
                    gateway_attested=None,
                )
            if now_ms < lease.issued_at_ms:
                reason = "lease-not-yet-valid"
            elif now_ms >= lease.expires_at_ms:
                reason = "lease-expired"
            elif attempt.pid != lease.pid:
                reason = "process-id-mismatch"
            elif _dns_token(self._key, attempt.dns_name) != lease.dns_name_token:
                reason = "dns-pin-mismatch"
            elif attempt.destination_ip != lease.destination_ip:
                reason = "destination-ip-mismatch"
            elif attempt.destination_port != lease.destination_port:
                reason = "destination-port-mismatch"
            elif attempt.protocol != lease.protocol:
                reason = "protocol-mismatch"
            elif attempt.path_token != lease.path_token:
                reason = "path-token-mismatch"
            else:
                reason = ""
            if reason:
                return self._decision_locked(
                    lease=lease,
                    attempt=attempt,
                    allowed=False,
                    reason=reason,
                    now_ms=now_ms,
                    usage=usage,
                    gateway_attested=None,
                )

            try:
                identity = self._process_observer(attempt.pid)
            except Exception:
                identity = None
            if not isinstance(identity, ProcessIdentity) or identity.pid != attempt.pid:
                reason = "process-observation-unavailable"
            elif identity.process_start_token != lease.process_start_token:
                reason = "pid-reuse-detected"
            elif identity.executable_sha256 != lease.executable_sha256:
                reason = "process-executable-mismatch"
            elif identity.user_token != lease.user_token:
                reason = "user-token-mismatch"
            else:
                reason = ""
            if reason:
                return self._decision_locked(
                    lease=lease,
                    attempt=attempt,
                    allowed=False,
                    reason=reason,
                    now_ms=now_ms,
                    usage=usage,
                    gateway_attested=None,
                )

            try:
                path = self._path_observer(attempt.path_token)
            except Exception:
                path = None
            if not isinstance(path, GatewayPathIdentity) or path.path_token != attempt.path_token:
                reason = "path-observation-unavailable"
                gateway_attested = None
            elif self._require_gateway and not path.gateway_attested:
                reason = "gateway-attestation-required"
                gateway_attested = path.gateway_attested
            elif path.gateway_attested != lease.gateway_attested:
                reason = "gateway-attestation-required"
                gateway_attested = path.gateway_attested
            else:
                reason = ""
                gateway_attested = path.gateway_attested
            if reason:
                return self._decision_locked(
                    lease=lease,
                    attempt=attempt,
                    allowed=False,
                    reason=reason,
                    now_ms=now_ms,
                    usage=usage,
                    gateway_attested=gateway_attested,
                )

            assert usage.seen_nonces is not None
            if attempt.connection_nonce in usage.seen_nonces:
                reason = "connection-replay"
            elif usage.used_connections >= lease.max_connections:
                reason = "connection-budget-exhausted"
            elif usage.used_bytes + attempt.requested_bytes > lease.max_bytes:
                reason = "byte-budget-exhausted"
            else:
                reason = ""
            if reason:
                return self._decision_locked(
                    lease=lease,
                    attempt=attempt,
                    allowed=False,
                    reason=reason,
                    now_ms=now_ms,
                    usage=usage,
                    gateway_attested=gateway_attested,
                )

            usage.seen_nonces.add(attempt.connection_nonce)
            usage.used_connections += 1
            usage.used_bytes += attempt.requested_bytes
            return self._decision_locked(
                lease=lease,
                attempt=attempt,
                allowed=True,
                reason="allowed",
                now_ms=now_ms,
                usage=usage,
                gateway_attested=gateway_attested,
            )

    def drain_audit(self, maximum: int = 128) -> EgressAuditBatch:
        """Drain a bounded, sanitized view for an observation-only module."""
        if type(maximum) is not int or not 1 <= maximum <= MAX_AUDIT_RECORDS:
            raise EgressLeaseRejected("egress audit drain bound is invalid")
        with self._lock:
            records = tuple(self._audit.popleft() for _ in range(min(maximum, len(self._audit))))
            lost = self._lost_audit
            self._lost_audit = 0
            complete = not self._audit and lost == 0
            reason = "" if complete else (
                "audit-queue-overflow" if lost else "audit-records-remain"
            )
            return EgressAuditBatch(records, complete, lost, reason)

__all__ = [
    "AUDIT_SCHEMA",
    "CLOCK_ROLLBACK_TOLERANCE_MS",
    "DECISION_CODES",
    "EGRESS_PURPOSES",
    "IDENTITY_TOKEN_LABELS",
    "EgressAttempt",
    "EgressAuditBatch",
    "EgressAuditRecord",
    "EgressDecision",
    "EgressLease",
    "EgressLeaseRejected",
    "GatewayPathIdentity",
    "LEASE_SCHEMA",
    "MAX_BYTE_BUDGET",
    "MAX_CONNECTIONS",
    "MAX_TTL_SECONDS",
    "ProcessEgressLeaseBroker",
    "ProcessIdentity",
    "opaque_identity_token",
]
