"""Local-first fleet enrollment, posture evidence, and rollout planning.

Fleet Fabric deliberately stops before remote execution.  It composes the
existing fleet inventory and policy primitives into a durable coordination
store, but it has no generic command, script, shell, or path-bearing job
surface.  A coordinator transport is not implemented here; configuration is
reported as unavailable unless a complete mutual-TLS shape passes strict local
validation, and even then the result is configuration readiness rather than a
socket or dispatch authority.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import sqlite3
import ssl
import stat
import threading
import time
import base64
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from angerona.core.fleet_control_plane import FleetControlPlane
from angerona.core.policy_bundle import EffectivePolicy

SCHEMA_ID = "angerona.fleet-fabric.v1"
CUSTODY_SCHEMA_ID = "angerona.fleet-fabric-custody.v1"
MAX_GRANT_TTL_SECONDS = 15 * 60
MAX_HEALTH_REASON_BYTES = 2_048
MAX_TARGET_DEVICES = 10_000
MAX_DASHBOARD_ROWS = 500
MAX_TRANSPORT_FILE_BYTES = 4 * 1024 * 1024
DEFAULT_HEALTH_FRESHNESS_SECONDS = 5 * 60
MAX_HEALTH_FRESHNESS_SECONDS = 24 * 60 * 60
ZERO_DIGEST = "0" * 64

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_EXECUTION_KEYS = frozenset({
    "argv", "cmd", "command", "commandline", "executable", "file_path",
    "filepath", "path", "powershell", "remote_shell", "script", "shell",
    "working_directory",
})
_CHANGE_CONTEXT_KEYS = frozenset({
    "approval_reference", "change_window", "owner", "summary", "ticket",
})
_ROLLOUT_STATES = frozenset({
    "staged", "canary", "general-ready", "halted", "completed", "cancelled",
})


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("fleet fabric records must use finite JSON values") from exc


def _identifier(value: object, label: str) -> str:
    rendered = str(value)
    if not _ID.fullmatch(rendered):
        raise ValueError(f"invalid {label}")
    return rendered


def _digest(value: object, label: str) -> str:
    rendered = str(value)
    if not _SHA256.fullmatch(rendered):
        raise ValueError(f"invalid {label}")
    return rendered


def _timestamp(value: object, label: str) -> float:
    try:
        rendered = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"invalid {label}") from exc
    if not math.isfinite(rendered) or rendered < 0:
        raise ValueError(f"invalid {label}")
    return rendered


def _hmac(key: bytes, domain: bytes, value: Any) -> str:
    return hmac.new(key, domain + b"\x00" + _canonical(value), hashlib.sha256).hexdigest()


def _decode_b64(value: object, expected_bytes: int, label: str) -> bytes:
    if not isinstance(value, str) or len(value) > 256:
        raise ValueError(f"invalid {label}")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"invalid {label}") from exc
    if len(raw) != expected_bytes or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError(f"invalid {label}")
    return raw


def _public_key_digest(public_key_ed25519: str) -> str:
    return hashlib.sha256(
        _decode_b64(public_key_ed25519, 32, "Ed25519 public key")
    ).hexdigest()


def _reject_execution_shape(value: object, *, depth: int = 0) -> None:
    """Reject command-like keys in analyst context at every bounded depth."""
    if depth > 8:
        raise ValueError("rollout context exceeds nesting budget")
    if isinstance(value, Mapping):
        if len(value) > 32:
            raise ValueError("rollout context exceeds item budget")
        for key, item in value.items():
            normalized = str(key).strip().casefold().replace("-", "_")
            if normalized in _FORBIDDEN_EXECUTION_KEYS:
                raise ValueError("arbitrary command, script, shell, or path fields are forbidden")
            _reject_execution_shape(item, depth=depth + 1)
        return
    if isinstance(value, (tuple, list)):
        if len(value) > 32:
            raise ValueError("rollout context exceeds item budget")
        for item in value:
            _reject_execution_shape(item, depth=depth + 1)
        return
    if value is None or type(value) in (str, int, float, bool):
        if isinstance(value, str) and len(value.encode("utf-8")) > 2_048:
            raise ValueError("rollout context string exceeds byte budget")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("rollout context must use finite values")
        return
    raise ValueError("rollout context must contain plain JSON values")


def _validate_change_context(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("rollout change context must be a mapping")
    unknown = {str(key) for key in value} - _CHANGE_CONTEXT_KEYS
    if unknown:
        raise ValueError(
            "arbitrary context keys are forbidden; only non-executable change metadata is accepted"
        )
    _reject_execution_shape(value)
    if any(not isinstance(item, (str, bool, int)) for item in value.values()):
        raise ValueError("rollout change metadata values must be bounded scalars")


def effective_policy_hash(policy: EffectivePolicy) -> str:
    """Hash the existing typed effective-policy representation without resolving it again."""
    if not isinstance(policy, EffectivePolicy):
        raise TypeError("policy must be an EffectivePolicy")
    return hashlib.sha256(_canonical(asdict(policy))).hexdigest()


@dataclass(frozen=True)
class CoordinatorTransportConfig:
    """Configuration shape only; Fleet Fabric never opens a coordinator socket."""

    enabled: bool = False
    endpoint: str = "https://127.0.0.1:9443"
    bind_host: str = "127.0.0.1"
    server_name: str = ""
    expected_peer_sha256: str = ""
    ca_bundle: Path | None = None
    client_certificate: Path | None = None
    client_private_key: Path | None = None

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("transport enabled flag must be boolean")


@dataclass(frozen=True)
class TransportReadiness:
    enabled: bool
    loopback_bind: bool
    mtls_complete: bool
    configuration_valid: bool
    transport_available: bool
    endpoint_scope: str
    reason: str


def _is_loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value.casefold() == "localhost"


def _safe_transport_file(value: Path | None, label: str) -> Path:
    if value is None:
        raise ValueError(f"{label} is required")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{label} must use an absolute path")
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    attributes = int(getattr(info, "st_file_attributes", 0))
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        or not 0 < info.st_size <= MAX_TRANSPORT_FILE_BYTES
    ):
        raise ValueError(f"{label} must be one bounded regular file")
    for parent in path.parents:
        try:
            parent_info = parent.lstat()
        except OSError as exc:
            raise ValueError(f"{label} parent is unavailable") from exc
        parent_attributes = int(getattr(parent_info, "st_file_attributes", 0))
        if (
            stat.S_ISLNK(parent_info.st_mode)
            or parent_attributes
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ValueError(f"{label} may not traverse a link or reparse point")
    return path


def validate_transport_config(config: CoordinatorTransportConfig) -> TransportReadiness:
    """Validate fail-closed mTLS material without creating network capability."""
    if not isinstance(config, CoordinatorTransportConfig):
        raise TypeError("transport config must use CoordinatorTransportConfig")
    bind_host = str(config.bind_host).strip()
    loopback_bind = _is_loopback(bind_host)
    parsed = urlsplit(str(config.endpoint).strip())
    endpoint_host = str(parsed.hostname or "")
    endpoint_scope = "loopback" if _is_loopback(endpoint_host) else "remote"
    if not config.enabled:
        return TransportReadiness(
            False,
            loopback_bind,
            False,
            loopback_bind and endpoint_scope == "loopback",
            False,
            endpoint_scope,
            "disabled-by-default",
        )
    try:
        if not loopback_bind:
            raise ValueError("coordinator client bind must remain loopback")
        if (
            parsed.scheme != "https"
            or not endpoint_host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or parsed.port is None
            or not 1 <= parsed.port <= 65_535
        ):
            raise ValueError("coordinator endpoint must be an exact HTTPS authority")
        if not config.server_name or config.server_name.casefold() != endpoint_host.casefold():
            raise ValueError("server name must exactly bind the coordinator endpoint")
        _digest(config.expected_peer_sha256, "expected coordinator certificate digest")
        ca = _safe_transport_file(config.ca_bundle, "CA bundle")
        cert = _safe_transport_file(config.client_certificate, "client certificate")
        key = _safe_transport_file(config.client_private_key, "client private key")
        if len({os.path.normcase(str(item)) for item in (ca, cert, key)}) != 3:
            raise ValueError("mTLS trust, certificate, and key files must be distinct")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca))
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    except (OSError, ssl.SSLError, ValueError) as exc:
        return TransportReadiness(
            True,
            loopback_bind,
            False,
            False,
            False,
            endpoint_scope,
            f"fail-closed: {str(exc)[:240]}",
        )
    return TransportReadiness(
        True,
        True,
        True,
        True,
        False,
        endpoint_scope,
        "mTLS configuration validated; coordinator transport is not implemented",
    )


@dataclass(frozen=True)
class EnrollmentGrant:
    tenant_id: str
    device_id: str
    grant_id: str
    device_public_key_sha256: str
    issued_at: float
    expires_at: float
    nonce: str
    grant_hmac: str
    schema: str = SCHEMA_ID

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant ID")
        _identifier(self.device_id, "device ID")
        _identifier(self.grant_id, "grant ID")
        _digest(self.device_public_key_sha256, "device public-key digest")
        issued = _timestamp(self.issued_at, "grant issue time")
        expires = _timestamp(self.expires_at, "grant expiry time")
        if not issued < expires <= issued + MAX_GRANT_TTL_SECONDS:
            raise ValueError("enrollment grant expiry must be within fifteen minutes")
        if not re.fullmatch(r"[0-9a-f]{32}", self.nonce):
            raise ValueError("invalid enrollment grant nonce")
        if not _SHA256.fullmatch(self.grant_hmac):
            raise ValueError("invalid enrollment grant authenticator")
        if self.schema != SCHEMA_ID:
            raise ValueError("unsupported enrollment grant schema")

    def unsigned(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("grant_hmac")
        return value

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


def enrollment_possession_challenge(grant: EnrollmentGrant) -> bytes:
    """Return the exact inert challenge an enrolled device must sign locally."""
    if not isinstance(grant, EnrollmentGrant):
        raise TypeError("enrollment challenge requires EnrollmentGrant")
    return _canonical({
        "schema": SCHEMA_ID,
        "purpose": "fleet-enrollment-ed25519-possession-v1",
        "tenant_id": grant.tenant_id,
        "device_id": grant.device_id,
        "grant_id": grant.grant_id,
        "grant_digest": grant.digest,
        "nonce": grant.nonce,
    })


@dataclass(frozen=True)
class EnrollmentProof:
    tenant_id: str
    device_id: str
    grant_id: str
    grant_digest: str
    public_key_ed25519: str
    signature_ed25519: str
    schema: str = SCHEMA_ID

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant ID")
        _identifier(self.device_id, "device ID")
        _identifier(self.grant_id, "grant ID")
        _digest(self.grant_digest, "grant digest")
        _decode_b64(self.public_key_ed25519, 32, "Ed25519 public key")
        _decode_b64(self.signature_ed25519, 64, "Ed25519 possession signature")
        if self.schema != SCHEMA_ID:
            raise ValueError("unsupported enrollment proof schema")


@dataclass(frozen=True)
class EnrollmentReceipt:
    tenant_id: str
    device_id: str
    grant_id: str
    grant_digest: str
    enrolled_at: float
    binding_generation: int
    device_authentication: str
    receipt_hmac: str
    schema: str = SCHEMA_ID

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant ID")
        _identifier(self.device_id, "device ID")
        _identifier(self.grant_id, "grant ID")
        _digest(self.grant_digest, "grant digest")
        _timestamp(self.enrolled_at, "enrollment time")
        if type(self.binding_generation) is not int or self.binding_generation < 1:
            raise ValueError("invalid device binding generation")
        if self.device_authentication != "ed25519-possession-proof-v1":
            raise ValueError("enrollment receipt requires Ed25519 device authentication")
        _digest(self.receipt_hmac, "enrollment receipt authenticator")
        if self.schema != SCHEMA_ID:
            raise ValueError("unsupported enrollment receipt schema")


@dataclass(frozen=True)
class FleetHealthSample:
    tenant_id: str
    device_id: str
    sample_id: str
    device_public_key_sha256: str
    observed_at: float
    desired_policy_hash: str
    effective_policy_hash: str
    health_percent: int
    health_reason: str
    queue_capacity: int
    queue_depth: int
    accepted_total: int
    dropped_total: int
    dropped_since_previous: int
    rejected_total: int
    rollout_id: str = ""
    rollout_generation: int = 0

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant ID")
        _identifier(self.device_id, "device ID")
        _identifier(self.sample_id, "health sample ID")
        _digest(self.device_public_key_sha256, "device public-key digest")
        _timestamp(self.observed_at, "health observation time")
        _digest(self.desired_policy_hash, "desired policy hash")
        _digest(self.effective_policy_hash, "effective policy hash")
        if type(self.health_percent) is not int or not 0 <= self.health_percent <= 100:
            raise ValueError("health percent must be an integer from 0 through 100")
        if not isinstance(self.health_reason, str):
            raise ValueError("health reason must be text")
        if len(self.health_reason.encode("utf-8")) > MAX_HEALTH_REASON_BYTES:
            raise ValueError("health reason exceeds byte budget")
        if self.health_percent < 100 and not self.health_reason.strip():
            raise ValueError("health below 100 requires an exact reason")
        counters = (
            self.queue_capacity,
            self.queue_depth,
            self.accepted_total,
            self.dropped_total,
            self.dropped_since_previous,
            self.rejected_total,
        )
        if any(type(item) is not int or item < 0 for item in counters):
            raise ValueError("health queue and loss counters must be non-negative integers")
        if not 1 <= self.queue_capacity <= 1_000_000 or self.queue_depth > self.queue_capacity:
            raise ValueError("health queue snapshot exceeds its declared capacity")
        if self.dropped_since_previous > self.dropped_total:
            raise ValueError("health loss delta exceeds cumulative loss")
        if self.desired_policy_hash != self.effective_policy_hash and self.health_percent == 100:
            raise ValueError("policy drift cannot claim 100 percent health")
        if self.rollout_id:
            _identifier(self.rollout_id, "health rollout ID")
            if type(self.rollout_generation) is not int or self.rollout_generation < 1:
                raise ValueError("rollout-bound health requires a positive generation")
        elif self.rollout_generation != 0:
            raise ValueError("health rollout generation requires a rollout ID")


def health_possession_payload(
    sample: FleetHealthSample,
    *,
    binding_generation: int,
    sequence: int,
    previous_evidence_digest: str,
) -> bytes:
    """Return the exact health envelope bytes an enrolled device must sign."""
    if not isinstance(sample, FleetHealthSample):
        raise TypeError("health possession payload requires FleetHealthSample")
    if type(binding_generation) is not int or binding_generation < 1:
        raise ValueError("invalid device binding generation")
    if type(sequence) is not int or sequence < 1:
        raise ValueError("health sequence must be positive")
    previous = _digest(previous_evidence_digest, "previous health evidence digest")
    return _canonical({
        "schema": SCHEMA_ID,
        "purpose": "fleet-health-ed25519-envelope-v1",
        "sample": asdict(sample),
        "binding_generation": binding_generation,
        "sequence": sequence,
        "previous_evidence_digest": previous,
    })


@dataclass(frozen=True)
class SignedFleetHealthEnvelope:
    sample: FleetHealthSample
    binding_generation: int
    sequence: int
    previous_evidence_digest: str
    signature_ed25519: str

    def __post_init__(self) -> None:
        if not isinstance(self.sample, FleetHealthSample):
            raise ValueError("signed health envelope requires a typed sample")
        health_possession_payload(
            self.sample,
            binding_generation=self.binding_generation,
            sequence=self.sequence,
            previous_evidence_digest=self.previous_evidence_digest,
        )
        _decode_b64(self.signature_ed25519, 64, "Ed25519 health signature")


@dataclass(frozen=True)
class FleetHealthEvidence:
    sample: FleetHealthSample
    recorded_at: float
    binding_generation: int
    sequence: int
    sequence_gap: int
    previous_evidence_digest: str
    device_signature_ed25519: str
    evidence_hmac: str

    def __post_init__(self) -> None:
        if not isinstance(self.sample, FleetHealthSample):
            raise ValueError("health evidence requires a typed sample")
        _timestamp(self.recorded_at, "health record time")
        if type(self.binding_generation) is not int or self.binding_generation < 1:
            raise ValueError("invalid health binding generation")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("invalid health sequence")
        if type(self.sequence_gap) is not int or self.sequence_gap < 0:
            raise ValueError("invalid health sequence gap")
        _digest(self.previous_evidence_digest, "previous health evidence digest")
        _decode_b64(self.device_signature_ed25519, 64, "Ed25519 health signature")
        _digest(self.evidence_hmac, "health evidence authenticator")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class HealthSnapshot:
    tenant_id: str
    items: tuple[FleetHealthEvidence, ...]
    total_rows: int
    truncated: bool
    retention_drops: int
    reported_drops: int
    backpressure_devices: int
    unhealthy_devices: int
    enrolled_devices: int
    reporting_devices: int
    fresh_devices: int
    missing_devices: int
    stale_devices: int
    missing_device_ids: tuple[str, ...]
    stale_device_ids: tuple[str, ...]
    freshness_seconds: int
    sequence_gaps: int
    stats_authenticated: bool
    history_chain_status: str


@dataclass(frozen=True)
class FleetRolloutPlan:
    tenant_id: str
    rollout_id: str
    policy_bundle_id: str
    group_id: str
    desired_policy_hash: str
    previous_policy_hash: str
    target_device_ids: tuple[str, ...]
    canary_device_ids: tuple[str, ...]
    minimum_health_percent: int
    max_canary_failures: int
    created_at: float
    change_context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_device_ids", tuple(self.target_device_ids))
        object.__setattr__(self, "canary_device_ids", tuple(self.canary_device_ids))
        object.__setattr__(self, "change_context", dict(self.change_context))
        _identifier(self.tenant_id, "tenant ID")
        _identifier(self.rollout_id, "rollout ID")
        _identifier(self.policy_bundle_id, "policy bundle ID")
        _identifier(self.group_id, "group ID")
        _digest(self.desired_policy_hash, "desired policy hash")
        _digest(self.previous_policy_hash, "previous policy hash")
        if self.desired_policy_hash == self.previous_policy_hash:
            raise ValueError("rollout desired policy must differ from its rollback baseline")
        if (
            not self.target_device_ids
            or len(self.target_device_ids) > MAX_TARGET_DEVICES
            or len(self.target_device_ids) != len(set(self.target_device_ids))
        ):
            raise ValueError("rollout targets must be unique and bounded")
        if (
            not self.canary_device_ids
            or len(self.canary_device_ids) != len(set(self.canary_device_ids))
            or not set(self.canary_device_ids) <= set(self.target_device_ids)
        ):
            raise ValueError("canaries must be a unique non-empty target subset")
        for device_id in self.target_device_ids:
            _identifier(device_id, "rollout device ID")
        if (
            type(self.minimum_health_percent) is not int
            or not 1 <= self.minimum_health_percent <= 100
            or type(self.max_canary_failures) is not int
            or not 0 <= self.max_canary_failures < len(self.canary_device_ids)
        ):
            raise ValueError("invalid canary health or failure budget")
        _timestamp(self.created_at, "rollout creation time")
        _validate_change_context(self.change_context)
        if len(_canonical(asdict(self))) > 256 * 1024:
            raise ValueError("rollout plan exceeds byte budget")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class CanaryFinding:
    device_id: str
    reason: str
    observed_policy_hash: str = ""

    def __post_init__(self) -> None:
        _identifier(self.device_id, "canary device ID")
        if not isinstance(self.reason, str) or not self.reason or len(self.reason) > 2_048:
            raise ValueError("canary finding requires one bounded reason")
        if self.observed_policy_hash:
            _digest(self.observed_policy_hash, "observed policy hash")


@dataclass(frozen=True)
class RolloutEvaluation:
    tenant_id: str
    rollout_id: str
    desired_policy_hash: str
    state: str
    version: int
    evaluated_at: float
    canary_started_at: float
    canary_generation: int
    findings: tuple[CanaryFinding, ...]
    evaluation_hmac: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        _identifier(self.tenant_id, "tenant ID")
        _identifier(self.rollout_id, "rollout ID")
        _digest(self.desired_policy_hash, "desired policy hash")
        if self.state not in {"general-ready", "halted"}:
            raise ValueError("invalid rollout evaluation state")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("invalid rollout evaluation version")
        _timestamp(self.evaluated_at, "rollout evaluation time")
        started = _timestamp(self.canary_started_at, "canary start time")
        if started > self.evaluated_at:
            raise ValueError("canary evaluation predates activation")
        if type(self.canary_generation) is not int or self.canary_generation < 1:
            raise ValueError("invalid canary generation")
        if len(self.findings) > MAX_TARGET_DEVICES or any(
            not isinstance(item, CanaryFinding) for item in self.findings
        ):
            raise ValueError("rollout findings are invalid or oversized")
        _digest(self.evaluation_hmac, "rollout evaluation authenticator")


@dataclass(frozen=True)
class RollbackPlan:
    tenant_id: str
    rollout_id: str
    from_policy_hash: str
    restore_policy_hash: str
    target_device_ids: tuple[str, ...]
    reason: str
    execution_authorized: bool = False
    response_authority: str = "proposal-only"

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_device_ids", tuple(self.target_device_ids))
        _identifier(self.tenant_id, "tenant ID")
        _identifier(self.rollout_id, "rollout ID")
        _digest(self.from_policy_hash, "rollback source policy hash")
        _digest(self.restore_policy_hash, "rollback restore policy hash")
        if not self.target_device_ids or len(self.target_device_ids) > MAX_TARGET_DEVICES:
            raise ValueError("rollback targets must be non-empty and bounded")
        for device_id in self.target_device_ids:
            _identifier(device_id, "rollback device ID")
        if not isinstance(self.reason, str) or not self.reason or len(self.reason) > 2_048:
            raise ValueError("rollback plan requires one bounded reason")
        if self.execution_authorized is not False or self.response_authority != "proposal-only":
            raise ValueError("Fleet Fabric rollback plans must remain proposal-only")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


class FleetFabricStore:
    """Tenant-isolated store: Ed25519 device proofs, HMAC-sealed local rows."""

    def __init__(
        self,
        path: Path,
        tenant_keys: Mapping[str, bytes],
        *,
        control_plane: FleetControlPlane | None = None,
        transport_config: CoordinatorTransportConfig | None = None,
        max_grants: int = 10_000,
        max_enrolled_devices: int = 100_000,
        max_health_evidence: int = 50_000,
        max_rollouts: int = 5_000,
        health_freshness_seconds: int = DEFAULT_HEALTH_FRESHNESS_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not tenant_keys:
            raise ValueError("at least one tenant key is required")
        self._keys: dict[str, bytes] = {}
        for tenant_id, key in tenant_keys.items():
            tenant = _identifier(tenant_id, "tenant ID")
            if not isinstance(key, bytes) or len(key) < 32:
                raise ValueError("tenant keys must contain at least 32 bytes")
            self._keys[tenant] = bytes(key)
        if not 1 <= int(max_grants) <= 500_000:
            raise ValueError("grant bound must be between 1 and 500000")
        if not 1 <= int(max_health_evidence) <= 500_000:
            raise ValueError("health evidence bound must be between 1 and 500000")
        if not 1 <= int(max_enrolled_devices) <= 500_000:
            raise ValueError("enrolled device bound must be between 1 and 500000")
        if not 1 <= int(max_rollouts) <= 100_000:
            raise ValueError("rollout bound must be between 1 and 100000")
        if (
            type(health_freshness_seconds) is not int
            or not 30 <= health_freshness_seconds <= MAX_HEALTH_FRESHNESS_SECONDS
        ):
            raise ValueError("health freshness must be from 30 through 86400 seconds")
        if not callable(clock):
            raise TypeError("fleet fabric clock must be callable")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._control_plane = control_plane
        self._transport_config = transport_config or CoordinatorTransportConfig()
        self._max_grants = int(max_grants)
        self._max_enrolled_devices = int(max_enrolled_devices)
        self._max_health = int(max_health_evidence)
        self._max_rollouts = int(max_rollouts)
        self._health_freshness = health_freshness_seconds
        self._clock = clock
        self._last_clock: float | None = None
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS fabric_grants(
          tenant_id TEXT NOT NULL, grant_id TEXT NOT NULL, device_id TEXT NOT NULL,
          grant_json TEXT NOT NULL, state TEXT NOT NULL, redeemed_at REAL NOT NULL,
          receipt_json TEXT NOT NULL, state_hmac TEXT NOT NULL,
          PRIMARY KEY(tenant_id,grant_id));
        CREATE INDEX IF NOT EXISTS idx_fabric_grants_device
          ON fabric_grants(tenant_id,device_id,state);
        CREATE TABLE IF NOT EXISTS fabric_enrolled_devices(
          tenant_id TEXT NOT NULL, device_id TEXT NOT NULL,
          device_public_key_sha256 TEXT NOT NULL, enrolled_at REAL NOT NULL,
          binding_hmac TEXT NOT NULL, device_public_key_ed25519 TEXT NOT NULL DEFAULT '',
          binding_generation INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(tenant_id,device_id));
        CREATE TABLE IF NOT EXISTS fabric_health(
          tenant_id TEXT NOT NULL, device_id TEXT NOT NULL, sample_id TEXT NOT NULL,
          observed_at REAL NOT NULL, evidence_json TEXT NOT NULL,
          PRIMARY KEY(tenant_id,device_id,sample_id));
        CREATE INDEX IF NOT EXISTS idx_fabric_health_tenant_time
          ON fabric_health(tenant_id,observed_at DESC,device_id,sample_id);
        CREATE TABLE IF NOT EXISTS fabric_rollouts(
          tenant_id TEXT NOT NULL, rollout_id TEXT NOT NULL, plan_json TEXT NOT NULL,
          state TEXT NOT NULL, version INTEGER NOT NULL, reason TEXT NOT NULL,
          updated_at REAL NOT NULL, record_hmac TEXT NOT NULL,
          evaluation_json TEXT NOT NULL DEFAULT '{}',
          canary_started_at REAL NOT NULL DEFAULT 0,
          canary_generation INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(tenant_id,rollout_id));
        CREATE INDEX IF NOT EXISTS idx_fabric_rollouts_tenant_time
          ON fabric_rollouts(tenant_id,updated_at DESC,rollout_id);
        CREATE TABLE IF NOT EXISTS fabric_stats(
          tenant_id TEXT PRIMARY KEY, grant_retention_drops INTEGER NOT NULL DEFAULT 0,
          health_retention_drops INTEGER NOT NULL DEFAULT 0,
          rollout_retention_drops INTEGER NOT NULL DEFAULT 0,
          health_sequence_gaps INTEGER NOT NULL DEFAULT 0,
          stats_hmac TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS fabric_health_heads(
          tenant_id TEXT NOT NULL, device_id TEXT NOT NULL,
          binding_generation INTEGER NOT NULL, sequence INTEGER NOT NULL,
          evidence_digest TEXT NOT NULL, accepted_total INTEGER NOT NULL,
          dropped_total INTEGER NOT NULL, rejected_total INTEGER NOT NULL,
          head_hmac TEXT NOT NULL, PRIMARY KEY(tenant_id,device_id));
        CREATE TABLE IF NOT EXISTS fabric_rollout_history(
          tenant_id TEXT NOT NULL, rollout_id TEXT NOT NULL, version INTEGER NOT NULL,
          state TEXT NOT NULL, record_json TEXT NOT NULL,
          evaluation_digest TEXT NOT NULL, previous_history_digest TEXT NOT NULL,
          history_hmac TEXT NOT NULL,
          PRIMARY KEY(tenant_id,rollout_id,version));
        CREATE TABLE IF NOT EXISTS fabric_clock_floor(
          tenant_id TEXT PRIMARY KEY, last_seen REAL NOT NULL,
          clock_hmac TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS fabric_authority(
          tenant_id TEXT PRIMARY KEY, install_epoch TEXT NOT NULL,
          authority_hmac TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS fabric_prune_tombstones(
          tenant_id TEXT NOT NULL, sequence INTEGER NOT NULL,
          domain TEXT NOT NULL, subject_id TEXT NOT NULL,
          row_count INTEGER NOT NULL, projection_digest TEXT NOT NULL,
          pruned_at REAL NOT NULL, previous_digest TEXT NOT NULL,
          tombstone_hmac TEXT NOT NULL,
          PRIMARY KEY(tenant_id,sequence));
        CREATE TABLE IF NOT EXISTS fabric_custody(
          tenant_id TEXT PRIMARY KEY, generation INTEGER NOT NULL,
          manifest_json TEXT NOT NULL, manifest_hmac TEXT NOT NULL);
        """)
        grant_columns = {
            str(row[1]) for row in self._db.execute("PRAGMA table_info(fabric_grants)")
        }
        if "state_hmac" not in grant_columns:
            self._db.execute(
                "ALTER TABLE fabric_grants ADD COLUMN state_hmac TEXT NOT NULL DEFAULT ''"
            )
        rollout_columns = {
            str(row[1]) for row in self._db.execute("PRAGMA table_info(fabric_rollouts)")
        }
        if "evaluation_json" not in rollout_columns:
            self._db.execute(
                "ALTER TABLE fabric_rollouts ADD COLUMN evaluation_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "canary_started_at" not in rollout_columns:
            self._db.execute(
                "ALTER TABLE fabric_rollouts ADD COLUMN "
                "canary_started_at REAL NOT NULL DEFAULT 0"
            )
        if "canary_generation" not in rollout_columns:
            self._db.execute(
                "ALTER TABLE fabric_rollouts ADD COLUMN "
                "canary_generation INTEGER NOT NULL DEFAULT 0"
            )
        enrolled_columns = {
            str(row[1])
            for row in self._db.execute("PRAGMA table_info(fabric_enrolled_devices)")
        }
        if "device_public_key_ed25519" not in enrolled_columns:
            self._db.execute(
                "ALTER TABLE fabric_enrolled_devices ADD COLUMN "
                "device_public_key_ed25519 TEXT NOT NULL DEFAULT ''"
            )
        if "binding_generation" not in enrolled_columns:
            self._db.execute(
                "ALTER TABLE fabric_enrolled_devices ADD COLUMN "
                "binding_generation INTEGER NOT NULL DEFAULT 0"
            )
        stats_columns = {
            str(row[1]) for row in self._db.execute("PRAGMA table_info(fabric_stats)")
        }
        if "health_sequence_gaps" not in stats_columns:
            self._db.execute(
                "ALTER TABLE fabric_stats ADD COLUMN "
                "health_sequence_gaps INTEGER NOT NULL DEFAULT 0"
            )
        if "stats_hmac" not in stats_columns:
            self._db.execute(
                "ALTER TABLE fabric_stats ADD COLUMN stats_hmac TEXT NOT NULL DEFAULT ''"
            )
        for tenant_id in self._keys:
            domain_rows = self._tenant_domain_row_count_locked(tenant_id)
            established = self._db.execute(
                "SELECT 1 FROM fabric_authority WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone() is not None
            has_custody = self._db.execute(
                "SELECT 1 FROM fabric_custody WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone() is not None
            stats_row = self._db.execute(
                "SELECT stats_hmac FROM fabric_stats WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            if stats_row is None:
                if domain_rows or established or has_custody:
                    raise RuntimeError("fleet statistics row is unavailable")
                self._db.execute(
                    "INSERT INTO fabric_stats(tenant_id) VALUES (?)", (tenant_id,)
                )
            elif not str(stats_row[0]) and (domain_rows or established or has_custody):
                raise RuntimeError("legacy fleet statistics are not authenticated")
            self._initialize_stats_hmac_locked(tenant_id)
            clock_row = self._db.execute(
                "SELECT last_seen,clock_hmac FROM fabric_clock_floor WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            if clock_row is None:
                if domain_rows or established or has_custody:
                    raise RuntimeError("fleet fabric clock floor is unavailable")
                core = {"tenant_id": tenant_id, "last_seen": 0.0}
                self._db.execute(
                    "INSERT INTO fabric_clock_floor VALUES (?,?,?)",
                    (
                        tenant_id,
                        0.0,
                        _hmac(self._key(tenant_id), b"clock-floor", core),
                    ),
                )
            else:
                core = {"tenant_id": tenant_id, "last_seen": float(clock_row[0])}
                if not hmac.compare_digest(
                    str(clock_row[1]),
                    _hmac(self._key(tenant_id), b"clock-floor", core),
                ):
                    raise RuntimeError("fleet fabric clock floor integrity failed")
            authority_row = self._db.execute(
                "SELECT install_epoch,authority_hmac FROM fabric_authority "
                "WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            if authority_row is None:
                if has_custody:
                    raise RuntimeError("fleet custody authority is unavailable")
                epoch = secrets.token_hex(32)
                authority_core = {
                    "schema": CUSTODY_SCHEMA_ID,
                    "tenant_id": tenant_id,
                    "install_epoch": epoch,
                }
                self._db.execute(
                    "INSERT INTO fabric_authority VALUES (?,?,?)",
                    (
                        tenant_id,
                        epoch,
                        _hmac(self._key(tenant_id), b"fabric-authority", authority_core),
                    ),
                )
                self._write_custody_locked(tenant_id)
            else:
                self._verify_authority_locked(tenant_id)
                if not has_custody:
                    raise RuntimeError("fleet custody checkpoint is unavailable")
                self._verify_custody_locked(tenant_id)

            authenticated_floor = self._authenticated_timestamp_floor_locked(tenant_id)
            floor_row = self._db.execute(
                "SELECT last_seen FROM fabric_clock_floor WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            current_floor = float(floor_row[0]) if floor_row else 0.0
            if authenticated_floor > current_floor:
                floor_core = {
                    "tenant_id": tenant_id,
                    "last_seen": authenticated_floor,
                }
                self._db.execute(
                    "UPDATE fabric_clock_floor SET last_seen=?,clock_hmac=? "
                    "WHERE tenant_id=?",
                    (
                        authenticated_floor,
                        _hmac(self._key(tenant_id), b"clock-floor", floor_core),
                        tenant_id,
                    ),
                )
        self._db.commit()

    @property
    def tenant_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    @property
    def transport_readiness(self) -> TransportReadiness:
        return validate_transport_config(self._transport_config)

    def _key(self, tenant_id: str) -> bytes:
        tenant = _identifier(tenant_id, "tenant ID")
        try:
            return self._keys[tenant]
        except KeyError as exc:
            raise PermissionError("tenant is not authorized") from exc

    def _tenant_domain_row_count_locked(self, tenant_id: str) -> int:
        """Count durable tenant data without treating bootstrap rows as evidence."""
        total = 0
        for table in (
            "fabric_grants",
            "fabric_enrolled_devices",
            "fabric_health",
            "fabric_health_heads",
            "fabric_rollouts",
            "fabric_rollout_history",
            "fabric_prune_tombstones",
        ):
            total += int(self._db.execute(
                f"SELECT COUNT(*) FROM {table} WHERE tenant_id=?",  # nosec B608
                (tenant_id,),
            ).fetchone()[0])
        return total

    def _verify_authority_locked(self, tenant_id: str) -> str:
        row = self._db.execute(
            "SELECT install_epoch,authority_hmac FROM fabric_authority WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("fleet custody authority is unavailable")
        core = {
            "schema": CUSTODY_SCHEMA_ID,
            "tenant_id": tenant_id,
            "install_epoch": str(row[0]),
        }
        if (
            not re.fullmatch(r"[0-9a-f]{64}", core["install_epoch"])
            or not hmac.compare_digest(
                str(row[1]),
                _hmac(self._key(tenant_id), b"fabric-authority", core),
            )
        ):
            raise RuntimeError("fleet custody authority integrity verification failed")
        return core["install_epoch"]

    @staticmethod
    def _projection_digest(value: Any) -> str:
        return hashlib.sha256(_canonical(value)).hexdigest()

    def _verified_tombstone_state_locked(
        self, tenant_id: str
    ) -> tuple[int, str, float]:
        rows = self._db.execute(
            "SELECT sequence,domain,subject_id,row_count,projection_digest,pruned_at,"
            "previous_digest,tombstone_hmac FROM fabric_prune_tombstones "
            "WHERE tenant_id=? ORDER BY sequence",
            (tenant_id,),
        ).fetchall()
        previous = ZERO_DIGEST
        newest = 0.0
        for expected_sequence, row in enumerate(rows, start=1):
            core = {
                "schema": CUSTODY_SCHEMA_ID,
                "tenant_id": tenant_id,
                "sequence": int(row[0]),
                "domain": str(row[1]),
                "subject_id": str(row[2]),
                "row_count": int(row[3]),
                "projection_digest": str(row[4]),
                "pruned_at": float(row[5]),
                "previous_digest": str(row[6]),
            }
            try:
                _identifier(core["subject_id"], "prune subject ID")
                _digest(core["projection_digest"], "prune projection digest")
                _digest(core["previous_digest"], "previous prune digest")
                _timestamp(core["pruned_at"], "prune time")
            except ValueError as exc:
                raise RuntimeError("fleet prune tombstone integrity verification failed") from exc
            if (
                core["sequence"] != expected_sequence
                or core["domain"] not in {"enrollment-grant", "health-evidence", "rollout"}
                or core["row_count"] < 1
                or core["previous_digest"] != previous
                or not hmac.compare_digest(
                    str(row[7]),
                    _hmac(self._key(tenant_id), b"prune-tombstone", core),
                )
            ):
                raise RuntimeError("fleet prune tombstone integrity verification failed")
            previous = self._projection_digest(core)
            newest = max(newest, core["pruned_at"])
        return len(rows), previous, newest

    def _append_prune_tombstone_locked(
        self,
        tenant_id: str,
        *,
        domain: str,
        subject_id: str,
        row_count: int,
        projection: Any,
        pruned_at: float,
    ) -> str:
        count, previous, _newest = self._verified_tombstone_state_locked(tenant_id)
        subject = _identifier(subject_id, "prune subject ID")
        if domain not in {"enrollment-grant", "health-evidence", "rollout"}:
            raise ValueError("invalid prune tombstone domain")
        if type(row_count) is not int or row_count < 1:
            raise ValueError("invalid prune tombstone row count")
        core = {
            "schema": CUSTODY_SCHEMA_ID,
            "tenant_id": tenant_id,
            "sequence": count + 1,
            "domain": domain,
            "subject_id": subject,
            "row_count": row_count,
            "projection_digest": self._projection_digest(projection),
            "pruned_at": _timestamp(pruned_at, "prune time"),
            "previous_digest": previous,
        }
        self._db.execute(
            "INSERT INTO fabric_prune_tombstones VALUES (?,?,?,?,?,?,?,?,?)",
            (
                tenant_id,
                core["sequence"],
                domain,
                subject,
                row_count,
                core["projection_digest"],
                core["pruned_at"],
                previous,
                _hmac(self._key(tenant_id), b"prune-tombstone", core),
            ),
        )
        return self._projection_digest(core)

    def _retained_head_evidence_locked(
        self,
        tenant_id: str,
        device_id: str,
        head: Mapping[str, Any] | None = None,
        retained_rows: list[tuple[Any, ...]] | None = None,
    ) -> FleetHealthEvidence:
        verified_head = dict(head or self._health_head_locked(tenant_id, device_id) or {})
        if not verified_head:
            raise RuntimeError("health chain head is unavailable")
        rows = (
            retained_rows
            if retained_rows is not None
            else self._db.execute(
                "SELECT evidence_json,sample_id,observed_at FROM fabric_health "
                "WHERE tenant_id=? AND device_id=?",
                (tenant_id, device_id),
            ).fetchall()
        )
        matches = [
            row for row in rows
            if hashlib.sha256(str(row[0]).encode("utf-8")).hexdigest()
            == str(verified_head["evidence_digest"])
        ]
        if len(matches) != 1:
            raise RuntimeError("retained health evidence does not reach its authenticated head")
        row = matches[0]
        evidence = self._decode_health(
            str(row[0]),
            tenant_id,
            expected_device_id=device_id,
            expected_sample_id=str(row[1]),
            expected_observed_at=float(row[2]),
        )
        if (
            evidence.digest != verified_head["evidence_digest"]
            or evidence.binding_generation != int(verified_head["binding_generation"])
            or evidence.sequence != int(verified_head["sequence"])
            or evidence.sample.accepted_total != int(verified_head["accepted_total"])
            or evidence.sample.dropped_total != int(verified_head["dropped_total"])
            or evidence.sample.rejected_total != int(verified_head["rejected_total"])
        ):
            raise RuntimeError("retained health evidence head projection is inconsistent")
        return evidence

    def _custody_projection_locked(
        self,
        tenant_id: str,
        verified_health_heads: dict[str, FleetHealthEvidence] | None = None,
    ) -> dict[str, Any]:
        stats = self._verified_stats_locked(tenant_id)
        grant_rows = self._db.execute(
            "SELECT grant_json,state,redeemed_at,receipt_json,state_hmac,grant_id,device_id "
            "FROM fabric_grants WHERE tenant_id=? ORDER BY grant_id",
            (tenant_id,),
        ).fetchall()
        grant_projections = [
            self._verified_grant_row_locked(tenant_id, row)[1] for row in grant_rows
        ]

        binding_rows = self._db.execute(
            "SELECT device_id FROM fabric_enrolled_devices WHERE tenant_id=? "
            "ORDER BY device_id",
            (tenant_id,),
        ).fetchall()
        binding_projections = []
        for row in binding_rows:
            binding = self._local_device_binding_locked(tenant_id, str(row[0]))
            if binding is None:
                raise RuntimeError("enrolled device custody projection is unavailable")
            binding_projections.append(binding)

        head_rows = self._db.execute(
            "SELECT device_id FROM fabric_health_heads WHERE tenant_id=? ORDER BY device_id",
            (tenant_id,),
        ).fetchall()
        retained_rows = self._db.execute(
            "SELECT evidence_json,device_id,sample_id,observed_at FROM fabric_health "
            "WHERE tenant_id=? ORDER BY device_id,observed_at,sample_id",
            (tenant_id,),
        ).fetchall()
        retained_by_device: dict[str, list[tuple[Any, ...]]] = {}
        for encoded, device_id, sample_id, observed_at in retained_rows:
            retained_by_device.setdefault(str(device_id), []).append(
                (encoded, sample_id, observed_at)
            )
        health_projections = []
        for row in head_rows:
            device_id = str(row[0])
            head = self._health_head_locked(tenant_id, device_id)
            if head is None:
                raise RuntimeError("health chain custody projection is unavailable")
            device_rows = retained_by_device.get(device_id, [])
            evidence = self._retained_head_evidence_locked(
                tenant_id, device_id, head, device_rows
            )
            if verified_health_heads is not None:
                verified_health_heads[device_id] = evidence
            retained_count = len(device_rows)
            health_projections.append({
                "head": head,
                "retained_count": retained_count,
                "retained_head_sample_id": evidence.sample.sample_id,
            })

        rollout_rows = self._db.execute(
            "SELECT rollout_id FROM fabric_rollouts WHERE tenant_id=? ORDER BY rollout_id",
            (tenant_id,),
        ).fetchall()
        rollout_projections = []
        for row in rollout_rows:
            plan, record = self._load_rollout_locked(tenant_id, str(row[0]))
            rollout_projections.append({
                "rollout_id": plan.rollout_id,
                "plan_digest": plan.digest,
                "state": record["state"],
                "version": record["version"],
                "record_hmac": record["record_hmac"],
                "history_length": record["history_length"],
                "history_head_digest": record["history_head_digest"],
            })
        tombstone_count, tombstone_head, _newest = (
            self._verified_tombstone_state_locked(tenant_id)
        )
        counts = {
            "grants": len(grant_rows),
            "enrolled_devices": len(binding_rows),
            "health_evidence": len(retained_rows),
            "health_heads": len(head_rows),
            "rollouts": len(rollout_rows),
            "rollout_history": int(self._db.execute(
                "SELECT COUNT(*) FROM fabric_rollout_history WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()[0]),
            "prune_tombstones": tombstone_count,
        }
        return {
            "schema": CUSTODY_SCHEMA_ID,
            "tenant_id": tenant_id,
            "install_epoch": self._verify_authority_locked(tenant_id),
            "counts": counts,
            "stats": stats,
            "grant_lifecycle_digest": self._projection_digest(grant_projections),
            "device_bindings_digest": self._projection_digest(binding_projections),
            "health_heads_digest": self._projection_digest(health_projections),
            "rollout_history_heads_digest": self._projection_digest(rollout_projections),
            "prune_tombstone_head": tombstone_head,
        }

    def _verified_custody_manifest_locked(self, tenant_id: str) -> dict[str, Any]:
        row = self._db.execute(
            "SELECT generation,manifest_json,manifest_hmac FROM fabric_custody "
            "WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("fleet custody checkpoint is unavailable")
        try:
            manifest = json.loads(str(row[1]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("fleet custody checkpoint integrity verification failed") from exc
        if (
            not isinstance(manifest, dict)
            or int(row[0]) < 1
            or manifest.get("generation") != int(row[0])
            or manifest.get("schema") != CUSTODY_SCHEMA_ID
            or manifest.get("tenant_id") != tenant_id
            or _canonical(manifest).decode("utf-8") != str(row[1])
            or not hmac.compare_digest(
                str(row[2]),
                _hmac(self._key(tenant_id), b"fabric-custody", manifest),
            )
        ):
            raise RuntimeError("fleet custody checkpoint integrity verification failed")
        return manifest

    def _verify_custody_locked(
        self,
        tenant_id: str,
        verified_health_heads: dict[str, FleetHealthEvidence] | None = None,
    ) -> Mapping[str, Any]:
        manifest = self._verified_custody_manifest_locked(tenant_id)
        expected = {
            **self._custody_projection_locked(tenant_id, verified_health_heads),
            "generation": int(manifest["generation"]),
        }
        if manifest != expected:
            raise RuntimeError("fleet custody checkpoint does not match retained evidence")
        return manifest

    def _write_custody_locked(self, tenant_id: str) -> Mapping[str, Any]:
        row = self._db.execute(
            "SELECT generation FROM fabric_custody WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        if row is None:
            generation = 1
        else:
            current = self._verified_custody_manifest_locked(tenant_id)
            generation = int(current["generation"]) + 1
        manifest = {**self._custody_projection_locked(tenant_id), "generation": generation}
        encoded = _canonical(manifest).decode("utf-8")
        seal = _hmac(self._key(tenant_id), b"fabric-custody", manifest)
        self._db.execute(
            "INSERT INTO fabric_custody VALUES (?,?,?,?) "
            "ON CONFLICT(tenant_id) DO UPDATE SET generation=excluded.generation,"
            "manifest_json=excluded.manifest_json,manifest_hmac=excluded.manifest_hmac",
            (tenant_id, generation, encoded, seal),
        )
        return manifest

    def _authenticated_timestamp_floor_locked(self, tenant_id: str) -> float:
        """Derive a migration floor only from rows whose authenticators verify."""
        floor = 0.0
        grant_rows = self._db.execute(
            "SELECT grant_json,state,redeemed_at,receipt_json,state_hmac,grant_id,device_id "
            "FROM fabric_grants WHERE tenant_id=?",
            (tenant_id,),
        ).fetchall()
        for row in grant_rows:
            grant, projection = self._verified_grant_row_locked(tenant_id, row)
            floor = max(floor, grant.issued_at, float(projection["redeemed_at"]))
        binding_rows = self._db.execute(
            "SELECT device_id FROM fabric_enrolled_devices WHERE tenant_id=?",
            (tenant_id,),
        ).fetchall()
        for row in binding_rows:
            binding = self._local_device_binding_locked(tenant_id, str(row[0]))
            if binding is None:
                raise RuntimeError("enrolled device binding is unavailable")
            floor = max(floor, float(binding["enrolled_at"]))
        health_rows = self._db.execute(
            "SELECT evidence_json,device_id,sample_id,observed_at FROM fabric_health "
            "WHERE tenant_id=?",
            (tenant_id,),
        ).fetchall()
        for row in health_rows:
            evidence = self._decode_health(
                str(row[0]), tenant_id,
                expected_device_id=str(row[1]),
                expected_sample_id=str(row[2]),
                expected_observed_at=float(row[3]),
            )
            floor = max(floor, evidence.sample.observed_at, evidence.recorded_at)
        rollout_rows = self._db.execute(
            "SELECT rollout_id FROM fabric_rollouts WHERE tenant_id=?",
            (tenant_id,),
        ).fetchall()
        for row in rollout_rows:
            plan, record = self._load_rollout_locked(tenant_id, str(row[0]))
            floor = max(
                floor,
                plan.created_at,
                float(record["updated_at"]),
                float(record["canary_started_at"]),
                float(record.get("evaluation", {}).get("evaluated_at", 0.0)),
            )
        _count, _head, newest_prune = self._verified_tombstone_state_locked(tenant_id)
        return max(floor, newest_prune)

    def _now(self, tenant_id: str) -> float:
        with self._lock:
            tenant = _identifier(tenant_id, "tenant ID")
            key = self._key(tenant)
            stamp = _timestamp(self._clock(), "fleet fabric time")
            if self._last_clock is not None and stamp < self._last_clock:
                raise RuntimeError("fleet fabric clock moved backwards")
            row = self._db.execute(
                "SELECT last_seen,clock_hmac FROM fabric_clock_floor WHERE tenant_id=?",
                (tenant,),
            ).fetchone()
            if row is None:
                raise RuntimeError("fleet fabric clock floor is unavailable")
            floor = float(row[0])
            core = {"tenant_id": tenant, "last_seen": floor}
            if not hmac.compare_digest(
                str(row[1]), _hmac(key, b"clock-floor", core)
            ):
                raise RuntimeError("fleet fabric clock floor integrity failed")
            if stamp < floor:
                raise RuntimeError("fleet fabric clock moved backwards")
            replacement = {"tenant_id": tenant, "last_seen": stamp}
            self._db.execute(
                "UPDATE fabric_clock_floor SET last_seen=?,clock_hmac=? "
                "WHERE tenant_id=?",
                (stamp, _hmac(key, b"clock-floor", replacement), tenant),
            )
            self._db.commit()
            self._last_clock = stamp
            return stamp

    def _stats_core_locked(self, tenant_id: str) -> dict[str, Any]:
        row = self._db.execute(
            "SELECT grant_retention_drops,health_retention_drops,"
            "rollout_retention_drops,health_sequence_gaps "
            "FROM fabric_stats WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("fleet statistics row is unavailable")
        return {
            "tenant_id": tenant_id,
            "grant_retention_drops": int(row[0]),
            "health_retention_drops": int(row[1]),
            "rollout_retention_drops": int(row[2]),
            "health_sequence_gaps": int(row[3]),
        }

    def _initialize_stats_hmac_locked(self, tenant_id: str) -> None:
        row = self._db.execute(
            "SELECT stats_hmac FROM fabric_stats WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        if row is None:
            raise RuntimeError("fleet statistics row is unavailable")
        core = self._stats_core_locked(tenant_id)
        supplied = str(row[0])
        expected = _hmac(self._key(tenant_id), b"fabric-stats", core)
        if supplied:
            if not hmac.compare_digest(supplied, expected):
                raise RuntimeError("fleet statistics integrity verification failed")
            return
        if any(int(core[name]) for name in core if name != "tenant_id"):
            raise RuntimeError("legacy fleet statistics are not authenticated")
        self._db.execute(
            "UPDATE fabric_stats SET stats_hmac=? WHERE tenant_id=?",
            (expected, tenant_id),
        )

    def _verified_stats_locked(self, tenant_id: str) -> dict[str, Any]:
        core = self._stats_core_locked(tenant_id)
        supplied_row = self._db.execute(
            "SELECT stats_hmac FROM fabric_stats WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        supplied = str(supplied_row[0]) if supplied_row else ""
        expected = _hmac(self._key(tenant_id), b"fabric-stats", core)
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise RuntimeError("fleet statistics integrity verification failed")
        return core

    def _increment_stat_locked(self, tenant_id: str, field: str, amount: int) -> None:
        allowed = {
            "grant_retention_drops",
            "health_retention_drops",
            "rollout_retention_drops",
            "health_sequence_gaps",
        }
        if field not in allowed or type(amount) is not int or amount < 0:
            raise ValueError("invalid fleet statistic update")
        core = self._verified_stats_locked(tenant_id)
        core[field] += amount
        self._db.execute(
            f"UPDATE fabric_stats SET {field}=?,stats_hmac=? WHERE tenant_id=?",  # nosec B608
            (
                core[field],
                _hmac(self._key(tenant_id), b"fabric-stats", core),
                tenant_id,
            ),
        )

    def _local_device_binding_locked(
        self, tenant_id: str, device_id: str
    ) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT device_public_key_sha256,enrolled_at,binding_hmac,"
            "device_public_key_ed25519,binding_generation "
            "FROM fabric_enrolled_devices WHERE tenant_id=? AND device_id=?",
            (tenant_id, device_id),
        ).fetchone()
        if row is None:
            return None
        core = {
            "tenant_id": tenant_id,
            "device_id": device_id,
            "device_public_key_sha256": str(row[0]),
            "device_public_key_ed25519": str(row[3]),
            "binding_generation": int(row[4]),
            "enrolled_at": float(row[1]),
        }
        expected = _hmac(self._key(tenant_id), b"device-binding", core)
        if (
            not core["device_public_key_ed25519"]
            or core["binding_generation"] < 1
            or _public_key_digest(core["device_public_key_ed25519"])
            != _digest(core["device_public_key_sha256"], "enrolled device public-key digest")
            or not hmac.compare_digest(str(row[2]), expected)
        ):
            raise RuntimeError("enrolled device binding integrity verification failed")
        return core

    def _verified_control_plane_devices_locked(
        self, tenant_id: str
    ) -> dict[str, Any]:
        """Read only HMAC-bearing control-plane rows; legacy blank HMAC fails closed."""
        plane = self._control_plane
        if plane is None:
            return {}
        plane_lock = getattr(plane, "_lock", None)
        plane_db = getattr(plane, "_db", None)
        plane_key_method = getattr(plane, "_key", None)
        verifier = getattr(plane, "_verify_device_row", None)
        if plane_lock is None or plane_db is None or not callable(plane_key_method):
            raise RuntimeError("control-plane verified device boundary is unavailable")
        with plane_lock:
            plane_key = bytes(plane_key_method(tenant_id))
            if not hmac.compare_digest(plane_key, self._key(tenant_id)):
                raise RuntimeError("control-plane tenant trust key mismatch")
            rows = plane_db.execute(
                "SELECT tenant_id,device_id,public_key,hostname_token,platform,"
                "version,group_id,state,last_seen,record_hmac FROM fleet_devices "
                "WHERE tenant_id=? ORDER BY device_id",
                (tenant_id,),
            ).fetchall()
            devices: dict[str, Any] = {}
            for row in rows:
                if not str(row[9]):
                    raise RuntimeError(
                        "legacy control-plane device row is not authenticated"
                    )
                if not callable(verifier):
                    raise RuntimeError("control-plane device verifier is unavailable")
                device = verifier(plane_key, row)
                if device.tenant_id != tenant_id:
                    raise RuntimeError("control-plane tenant binding mismatch")
                devices[device.device_id] = device
            return devices

    def _active_device_binding_locked(
        self, tenant_id: str, device_id: str
    ) -> dict[str, Any] | None:
        binding = self._local_device_binding_locked(tenant_id, device_id)
        if self._control_plane is None:
            return binding
        devices = self._verified_control_plane_devices_locked(tenant_id)
        device = devices.get(device_id)
        if device is None or device.state != "active":
            return None
        if binding is None:
            return None
        if not hmac.compare_digest(
            str(binding["device_public_key_ed25519"]), str(device.public_key)
        ):
            raise RuntimeError("control-plane and Fleet Fabric device keys disagree")
        return binding

    def _active_device_roster_locked(self, tenant_id: str) -> tuple[str, ...]:
        local_rows = self._db.execute(
            "SELECT device_id FROM fabric_enrolled_devices WHERE tenant_id=? "
            "ORDER BY device_id",
            (tenant_id,),
        ).fetchall()
        local = {
            str(row[0]): self._local_device_binding_locked(tenant_id, str(row[0]))
            for row in local_rows
        }
        if self._control_plane is None:
            return tuple(sorted(local))
        devices = self._verified_control_plane_devices_locked(tenant_id)
        active: list[str] = []
        for device_id, device in devices.items():
            if device.state != "active":
                continue
            binding = local.get(device_id)
            if binding is not None and hmac.compare_digest(
                str(binding["device_public_key_ed25519"]), str(device.public_key)
            ):
                active.append(device_id)
        return tuple(sorted(active))

    def _device_known(self, tenant_id: str, device_id: str) -> bool:
        return self._active_device_binding_locked(tenant_id, device_id) is not None

    def issue_enrollment_grant(
        self,
        tenant_id: str,
        device_id: str,
        device_public_key_sha256: str,
        *,
        ttl_seconds: int = 300,
        grant_id: str | None = None,
    ) -> EnrollmentGrant:
        tenant = _identifier(tenant_id, "tenant ID")
        device = _identifier(device_id, "device ID")
        public_digest = _digest(device_public_key_sha256, "device public-key digest")
        key = self._key(tenant)
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_GRANT_TTL_SECONDS:
            raise ValueError("grant TTL must be from 1 through 900 seconds")
        stamp = self._now(tenant)
        identity = _identifier(grant_id or f"grant-{secrets.token_hex(16)}", "grant ID")
        core = {
            "tenant_id": tenant,
            "device_id": device,
            "grant_id": identity,
            "device_public_key_sha256": public_digest,
            "issued_at": stamp,
            "expires_at": stamp + ttl_seconds,
            "nonce": secrets.token_hex(16),
            "schema": SCHEMA_ID,
        }
        grant = EnrollmentGrant(
            **core, grant_hmac=_hmac(key, b"enrollment-grant", core)
        )
        encoded = _canonical(asdict(grant)).decode("utf-8")
        state_hmac = self._grant_state_hmac(grant, "issued", 0.0, "")
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_custody_locked(tenant)
                self._expire_grants_locked(tenant, stamp)
                self._make_grant_room_locked(tenant, stamp)
                self._db.execute(
                    "INSERT INTO fabric_grants(tenant_id,grant_id,device_id,grant_json,"
                    "state,redeemed_at,receipt_json,state_hmac) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        tenant, identity, device, encoded, "issued", 0.0, "",
                        state_hmac,
                    ),
                )
                self._write_custody_locked(tenant)
                self._db.commit()
            except sqlite3.IntegrityError as exc:
                self._db.rollback()
                raise ValueError("enrollment grant ID is already in use") from exc
            except Exception:
                self._db.rollback()
                raise
        return grant

    def _expire_grants_locked(self, tenant_id: str, now: float) -> None:
        rows = self._db.execute(
            "SELECT grant_json,state,redeemed_at,receipt_json,state_hmac,grant_id,device_id "
            "FROM fabric_grants "
            "WHERE tenant_id=? AND state='issued'",
            (tenant_id,),
        ).fetchall()
        for row in rows:
            grant, _projection = self._verified_grant_row_locked(tenant_id, row)
            if grant.expires_at <= now:
                self._db.execute(
                    "UPDATE fabric_grants SET state='expired',state_hmac=? "
                    "WHERE tenant_id=? AND grant_id=? AND state='issued'",
                    (
                        self._grant_state_hmac(grant, "expired", 0.0, ""),
                        tenant_id,
                        grant.grant_id,
                    ),
                )

    def _make_grant_room_locked(self, tenant_id: str, pruned_at: float) -> None:
        count = int(self._db.execute(
            "SELECT COUNT(*) FROM fabric_grants WHERE tenant_id=?", (tenant_id,)
        ).fetchone()[0])
        if count < self._max_grants:
            return
        candidates = self._db.execute(
            "SELECT grant_json,state,redeemed_at,receipt_json,state_hmac,grant_id,device_id "
            "FROM fabric_grants "
            "WHERE tenant_id=? AND state IN ('redeemed','expired') "
            "ORDER BY redeemed_at,grant_id",
            (tenant_id,),
        ).fetchall()
        if not candidates:
            raise OverflowError("enrollment grant store is full of live grants")
        verified = [
            self._verified_grant_row_locked(tenant_id, row) for row in candidates
        ]
        victim_grant, victim_projection = verified[0]
        self._append_prune_tombstone_locked(
            tenant_id,
            domain="enrollment-grant",
            subject_id=victim_grant.grant_id,
            row_count=1,
            projection=victim_projection,
            pruned_at=pruned_at,
        )
        self._db.execute(
            "DELETE FROM fabric_grants WHERE tenant_id=? AND grant_id=?",
            (tenant_id, victim_grant.grant_id),
        )
        self._increment_stat_locked(tenant_id, "grant_retention_drops", 1)

    def _verify_grant(self, grant: EnrollmentGrant) -> bool:
        if not isinstance(grant, EnrollmentGrant):
            return False
        try:
            expected = _hmac(
                self._key(grant.tenant_id), b"enrollment-grant", grant.unsigned()
            )
        except (PermissionError, ValueError):
            return False
        return hmac.compare_digest(expected, grant.grant_hmac)

    def _grant_state_hmac(
        self,
        grant: EnrollmentGrant,
        state: str,
        redeemed_at: float,
        receipt_json: str,
    ) -> str:
        if state not in {"issued", "redeemed", "expired"}:
            raise ValueError("invalid enrollment grant state")
        core = {
            "tenant_id": grant.tenant_id,
            "grant_id": grant.grant_id,
            "grant_digest": grant.digest,
            "state": state,
            "redeemed_at": float(redeemed_at),
            "receipt_digest": hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
            if receipt_json else "",
        }
        return _hmac(self._key(grant.tenant_id), b"grant-state", core)

    def _verified_grant_row_locked(
        self, tenant_id: str, row: tuple[Any, ...]
    ) -> tuple[EnrollmentGrant, dict[str, Any]]:
        if len(row) != 7:
            raise RuntimeError("enrollment grant lifecycle projection is invalid")
        encoded, state_value, redeemed_value, receipt_value, state_hmac, row_grant, row_device = row
        try:
            grant = EnrollmentGrant(**json.loads(str(encoded)))
            state = str(state_value)
            redeemed_at = float(redeemed_value)
            receipt_json = str(receipt_value)
            if (
                state not in {"issued", "redeemed", "expired"}
                or grant.tenant_id != tenant_id
                or grant.grant_id != str(row_grant)
                or grant.device_id != str(row_device)
                or _canonical(asdict(grant)).decode("utf-8") != str(encoded)
                or not self._verify_grant(grant)
                or not hmac.compare_digest(
                    str(state_hmac),
                    self._grant_state_hmac(grant, state, redeemed_at, receipt_json),
                )
            ):
                raise ValueError("grant row binding mismatch")
            if state == "redeemed":
                receipt = EnrollmentReceipt(**json.loads(receipt_json))
                if (
                    redeemed_at <= 0
                    or not self.verify_enrollment_receipt(receipt)
                    or receipt.tenant_id != tenant_id
                    or receipt.device_id != grant.device_id
                    or receipt.grant_id != grant.grant_id
                    or receipt.grant_digest != grant.digest
                    or receipt.enrolled_at != redeemed_at
                ):
                    raise ValueError("grant receipt binding mismatch")
            elif redeemed_at != 0.0 or receipt_json:
                raise ValueError("non-redeemed grant carries a receipt")
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise RuntimeError("enrollment grant lifecycle integrity verification failed") from exc
        projection = {
            "tenant_id": tenant_id,
            "grant_id": grant.grant_id,
            "device_id": grant.device_id,
            "grant_digest": grant.digest,
            "state": state,
            "redeemed_at": redeemed_at,
            "receipt_digest": (
                hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
                if receipt_json else ""
            ),
            "state_hmac": str(state_hmac),
        }
        return grant, projection

    def redeem_enrollment_grant(
        self,
        grant: EnrollmentGrant,
        proof: EnrollmentProof,
        *,
        tenant_id: str,
        device_id: str,
        device_public_key_sha256: str,
    ) -> EnrollmentReceipt:
        tenant = _identifier(tenant_id, "tenant ID")
        device = _identifier(device_id, "device ID")
        public_digest = _digest(device_public_key_sha256, "device public-key digest")
        stamp = self._now(tenant)
        if not isinstance(grant, EnrollmentGrant) or not self._verify_grant(grant):
            raise PermissionError("enrollment grant authentication failed")
        if (
            grant.tenant_id != tenant
            or grant.device_id != device
            or grant.device_public_key_sha256 != public_digest
        ):
            raise PermissionError("enrollment grant tenant/device binding mismatch")
        if stamp < grant.issued_at:
            raise PermissionError("enrollment grant is not yet valid")
        if not isinstance(proof, EnrollmentProof):
            raise PermissionError("Ed25519 device possession proof is required")
        if (
            proof.tenant_id != tenant
            or proof.device_id != device
            or proof.grant_id != grant.grant_id
            or proof.grant_digest != grant.digest
            or _public_key_digest(proof.public_key_ed25519) != public_digest
        ):
            raise PermissionError("enrollment possession proof binding mismatch")
        try:
            Ed25519PublicKey.from_public_bytes(
                _decode_b64(proof.public_key_ed25519, 32, "Ed25519 public key")
            ).verify(
                _decode_b64(proof.signature_ed25519, 64, "Ed25519 possession signature"),
                enrollment_possession_challenge(grant),
            )
        except (InvalidSignature, ValueError) as exc:
            raise PermissionError("enrollment device possession proof is invalid") from exc
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_custody_locked(tenant)
                row = self._db.execute(
                    "SELECT grant_json,state,redeemed_at,receipt_json,state_hmac,grant_id,device_id "
                    "FROM fabric_grants WHERE tenant_id=? AND grant_id=?",
                    (tenant, grant.grant_id),
                ).fetchone()
                if row is None:
                    raise PermissionError("enrollment grant is unknown")
                stored_grant, lifecycle = self._verified_grant_row_locked(tenant, row)
                if stored_grant != grant:
                    raise RuntimeError("enrollment grant integrity verification failed")
                if lifecycle["state"] != "issued":
                    raise PermissionError("enrollment grant is stale or already redeemed")
                if stamp >= grant.expires_at:
                    self._db.execute(
                        "UPDATE fabric_grants SET state='expired',state_hmac=? "
                        "WHERE tenant_id=? AND grant_id=? AND state='issued'",
                        (
                            self._grant_state_hmac(grant, "expired", 0.0, ""),
                            tenant,
                            grant.grant_id,
                        ),
                    )
                    self._write_custody_locked(tenant)
                    self._db.commit()
                    raise PermissionError("enrollment grant expired")
                enrolled = self._local_device_binding_locked(tenant, device)
                if enrolled is not None and (
                    not hmac.compare_digest(
                        str(enrolled["device_public_key_sha256"]), public_digest
                    )
                    or not hmac.compare_digest(
                        str(enrolled["device_public_key_ed25519"]),
                        proof.public_key_ed25519,
                    )
                ):
                    raise PermissionError(
                        "enrolled device identity is already bound to another public key"
                    )
                generation = (
                    int(enrolled["binding_generation"]) if enrolled is not None else 1
                )
                if generation < 1:
                    raise RuntimeError("legacy device binding lacks possession proof")
                core = {
                    "tenant_id": tenant,
                    "device_id": device,
                    "grant_id": grant.grant_id,
                    "grant_digest": grant.digest,
                    "enrolled_at": stamp,
                    "binding_generation": generation,
                    "device_authentication": "ed25519-possession-proof-v1",
                    "schema": SCHEMA_ID,
                }
                receipt = EnrollmentReceipt(
                    **core, receipt_hmac=_hmac(self._key(tenant), b"enrollment-receipt", core)
                )
                encoded = _canonical(asdict(receipt)).decode("utf-8")
                if enrolled is None:
                    enrolled_count = int(self._db.execute(
                        "SELECT COUNT(*) FROM fabric_enrolled_devices WHERE tenant_id=?",
                        (tenant,),
                    ).fetchone()[0])
                    if enrolled_count >= self._max_enrolled_devices:
                        raise OverflowError("enrolled device store is full")
                    binding_core = {
                        "tenant_id": tenant,
                        "device_id": device,
                        "device_public_key_sha256": public_digest,
                        "device_public_key_ed25519": proof.public_key_ed25519,
                        "binding_generation": generation,
                        "enrolled_at": stamp,
                    }
                    self._db.execute(
                        "INSERT INTO fabric_enrolled_devices(tenant_id,device_id,"
                        "device_public_key_sha256,enrolled_at,binding_hmac,"
                        "device_public_key_ed25519,binding_generation) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (
                            tenant,
                            device,
                            public_digest,
                            stamp,
                            _hmac(self._key(tenant), b"device-binding", binding_core),
                            proof.public_key_ed25519,
                            generation,
                        ),
                    )
                cursor = self._db.execute(
                    "UPDATE fabric_grants SET state='redeemed',redeemed_at=?,receipt_json=?,"
                    "state_hmac=? "
                    "WHERE tenant_id=? AND grant_id=? AND state='issued'",
                    (
                        stamp,
                        encoded,
                        self._grant_state_hmac(grant, "redeemed", stamp, encoded),
                        tenant,
                        grant.grant_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("enrollment grant changed concurrently")
                self._write_custody_locked(tenant)
                self._db.commit()
                return receipt
            except PermissionError:
                if self._db.in_transaction:
                    self._db.rollback()
                raise
            except Exception:
                self._db.rollback()
                raise

    def verify_enrollment_receipt(self, receipt: EnrollmentReceipt) -> bool:
        if not isinstance(receipt, EnrollmentReceipt) or receipt.schema != SCHEMA_ID:
            return False
        value = asdict(receipt)
        supplied = value.pop("receipt_hmac", "")
        try:
            expected = _hmac(
                self._key(receipt.tenant_id), b"enrollment-receipt", value
            )
        except (PermissionError, ValueError):
            return False
        return bool(_SHA256.fullmatch(str(supplied))) and hmac.compare_digest(
            str(supplied), expected
        )

    def health_submission_state(
        self, tenant_id: str, device_id: str
    ) -> Mapping[str, Any]:
        """Return an inert local signing cursor; it grants no transport authority."""
        tenant = _identifier(tenant_id, "tenant ID")
        device = _identifier(device_id, "device ID")
        self._key(tenant)
        with self._lock:
            self._verify_custody_locked(tenant)
            binding = self._active_device_binding_locked(tenant, device)
            if binding is None:
                raise PermissionError("device is not actively enrolled in this tenant")
            head = self._health_head_locked(tenant, device)
        return {
            "schema": SCHEMA_ID,
            "tenant_id": tenant,
            "device_id": device,
            "binding_generation": int(binding["binding_generation"]),
            "next_sequence": int(head["sequence"]) + 1 if head else 1,
            "previous_evidence_digest": (
                str(head["evidence_digest"]) if head else ZERO_DIGEST
            ),
            "device_authentication": "ed25519-health-envelope-v1",
            "transport_authorized": False,
            "response_authority": "none",
        }

    def _health_head_locked(
        self, tenant_id: str, device_id: str
    ) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT binding_generation,sequence,evidence_digest,accepted_total,"
            "dropped_total,rejected_total,head_hmac FROM fabric_health_heads "
            "WHERE tenant_id=? AND device_id=?",
            (tenant_id, device_id),
        ).fetchone()
        if row is None:
            return None
        core = {
            "tenant_id": tenant_id,
            "device_id": device_id,
            "binding_generation": int(row[0]),
            "sequence": int(row[1]),
            "evidence_digest": str(row[2]),
            "accepted_total": int(row[3]),
            "dropped_total": int(row[4]),
            "rejected_total": int(row[5]),
        }
        _digest(core["evidence_digest"], "health chain-head digest")
        expected = _hmac(self._key(tenant_id), b"health-chain-head", core)
        if not hmac.compare_digest(str(row[6]), expected):
            raise RuntimeError("health chain head integrity verification failed")
        return core

    def _write_health_head_locked(self, evidence: FleetHealthEvidence) -> None:
        sample = evidence.sample
        core = {
            "tenant_id": sample.tenant_id,
            "device_id": sample.device_id,
            "binding_generation": evidence.binding_generation,
            "sequence": evidence.sequence,
            "evidence_digest": evidence.digest,
            "accepted_total": sample.accepted_total,
            "dropped_total": sample.dropped_total,
            "rejected_total": sample.rejected_total,
        }
        self._db.execute(
            "INSERT INTO fabric_health_heads(tenant_id,device_id,binding_generation,"
            "sequence,evidence_digest,accepted_total,dropped_total,rejected_total,head_hmac) "
            "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,device_id) DO UPDATE SET "
            "binding_generation=excluded.binding_generation,sequence=excluded.sequence,"
            "evidence_digest=excluded.evidence_digest,accepted_total=excluded.accepted_total,"
            "dropped_total=excluded.dropped_total,rejected_total=excluded.rejected_total,"
            "head_hmac=excluded.head_hmac",
            (
                sample.tenant_id,
                sample.device_id,
                evidence.binding_generation,
                evidence.sequence,
                evidence.digest,
                sample.accepted_total,
                sample.dropped_total,
                sample.rejected_total,
                _hmac(self._key(sample.tenant_id), b"health-chain-head", core),
            ),
        )

    def record_health(
        self, envelope: SignedFleetHealthEnvelope
    ) -> FleetHealthEvidence:
        if not isinstance(envelope, SignedFleetHealthEnvelope):
            raise TypeError(
                "health intake requires a device-signed SignedFleetHealthEnvelope"
            )
        sample = envelope.sample
        key = self._key(sample.tenant_id)
        stamp = self._now(sample.tenant_id)
        if sample.observed_at > stamp:
            raise ValueError("health observation may not be in the future")
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_custody_locked(sample.tenant_id)
                binding = self._active_device_binding_locked(
                    sample.tenant_id, sample.device_id
                )
                if binding is None:
                    raise PermissionError(
                        "health sample device is not actively enrolled in this tenant"
                    )
                if (
                    not hmac.compare_digest(
                        str(binding["device_public_key_sha256"]),
                        sample.device_public_key_sha256,
                    )
                    or envelope.binding_generation != binding["binding_generation"]
                ):
                    raise PermissionError("health sample device binding mismatch")
                payload = health_possession_payload(
                    sample,
                    binding_generation=envelope.binding_generation,
                    sequence=envelope.sequence,
                    previous_evidence_digest=envelope.previous_evidence_digest,
                )
                try:
                    Ed25519PublicKey.from_public_bytes(
                        _decode_b64(
                            binding["device_public_key_ed25519"],
                            32,
                            "Ed25519 public key",
                        )
                    ).verify(
                        _decode_b64(
                            envelope.signature_ed25519,
                            64,
                            "Ed25519 health signature",
                        ),
                        payload,
                    )
                except (InvalidSignature, ValueError) as exc:
                    raise PermissionError(
                        "health envelope device signature is invalid"
                    ) from exc
                existing = self._db.execute(
                    "SELECT evidence_json FROM fabric_health "
                    "WHERE tenant_id=? AND device_id=? AND sample_id=?",
                    (sample.tenant_id, sample.device_id, sample.sample_id),
                ).fetchone()
                if existing is not None:
                    stored = self._decode_health(
                        str(existing[0]),
                        sample.tenant_id,
                        expected_device_id=sample.device_id,
                        expected_sample_id=sample.sample_id,
                        expected_observed_at=sample.observed_at,
                    )
                    if (
                        stored.sample == sample
                        and stored.binding_generation == envelope.binding_generation
                        and stored.sequence == envelope.sequence
                        and stored.previous_evidence_digest
                        == envelope.previous_evidence_digest
                        and stored.device_signature_ed25519
                        == envelope.signature_ed25519
                    ):
                        self._db.rollback()
                        return stored
                    raise ValueError("health sample ID conflicts with another observation")
                head = self._health_head_locked(sample.tenant_id, sample.device_id)
                if head is None:
                    if envelope.sequence != 1 or envelope.previous_evidence_digest != ZERO_DIGEST:
                        raise PermissionError("first health envelope must start a new chain")
                    if sample.dropped_since_previous != sample.dropped_total:
                        raise ValueError("first health loss delta must equal its cumulative loss")
                    sequence_gap = 0
                else:
                    if head["binding_generation"] != envelope.binding_generation:
                        raise PermissionError("health chain binding generation mismatch")
                    if envelope.sequence <= head["sequence"]:
                        raise PermissionError("health sequence is stale or replayed")
                    if not hmac.compare_digest(
                        envelope.previous_evidence_digest, head["evidence_digest"]
                    ):
                        raise PermissionError("health history chain predecessor mismatch")
                    for field in ("accepted_total", "dropped_total", "rejected_total"):
                        if getattr(sample, field) < int(head[field]):
                            raise ValueError(f"health {field} counter regressed")
                    if (
                        sample.dropped_since_previous
                        != sample.dropped_total - int(head["dropped_total"])
                    ):
                        raise ValueError("health loss delta does not match cumulative history")
                    sequence_gap = envelope.sequence - int(head["sequence"]) - 1
                core = {
                    "sample": asdict(sample),
                    "recorded_at": stamp,
                    "binding_generation": envelope.binding_generation,
                    "sequence": envelope.sequence,
                    "sequence_gap": sequence_gap,
                    "previous_evidence_digest": envelope.previous_evidence_digest,
                    "device_signature_ed25519": envelope.signature_ed25519,
                }
                evidence = FleetHealthEvidence(
                    sample=sample,
                    recorded_at=stamp,
                    binding_generation=envelope.binding_generation,
                    sequence=envelope.sequence,
                    sequence_gap=sequence_gap,
                    previous_evidence_digest=envelope.previous_evidence_digest,
                    device_signature_ed25519=envelope.signature_ed25519,
                    evidence_hmac=_hmac(key, b"health-evidence", core),
                )
                encoded = _canonical(asdict(evidence)).decode("utf-8")
                self._db.execute(
                    "INSERT INTO fabric_health VALUES (?,?,?,?,?)",
                    (
                        sample.tenant_id,
                        sample.device_id,
                        sample.sample_id,
                        sample.observed_at,
                        encoded,
                    ),
                )
                self._write_health_head_locked(evidence)
                if sequence_gap:
                    self._increment_stat_locked(
                        sample.tenant_id, "health_sequence_gaps", sequence_gap
                    )
                self._prune_health_locked(sample.tenant_id, stamp)
                self._write_custody_locked(sample.tenant_id)
                self._db.commit()
                return evidence
            except Exception:
                if self._db.in_transaction:
                    self._db.rollback()
                raise

    def _prune_health_locked(self, tenant_id: str, pruned_at: float) -> None:
        count = int(self._db.execute(
            "SELECT COUNT(*) FROM fabric_health WHERE tenant_id=?", (tenant_id,)
        ).fetchone()[0])
        excess = count - self._max_health
        if excess <= 0:
            return
        rows = self._db.execute(
            "SELECT evidence_json,device_id,sample_id,observed_at FROM fabric_health "
            "WHERE tenant_id=? ORDER BY observed_at,device_id,sample_id",
            (tenant_id,),
        ).fetchall()
        head_rows = self._db.execute(
            "SELECT device_id FROM fabric_health_heads WHERE tenant_id=?",
            (tenant_id,),
        ).fetchall()
        retained_heads = {
            str(head["evidence_digest"])
            for row in head_rows
            if (head := self._health_head_locked(tenant_id, str(row[0]))) is not None
        }
        candidates: list[tuple[tuple[str, str, str], Mapping[str, Any]]] = []
        for encoded, device_id, sample_id, observed_at in rows:
            evidence = self._decode_health(
                str(encoded),
                tenant_id,
                expected_device_id=str(device_id),
                expected_sample_id=str(sample_id),
                expected_observed_at=float(observed_at),
            )
            if evidence.digest in retained_heads:
                continue
            candidates.append((
                (tenant_id, str(device_id), str(sample_id)),
                {
                    "device_id": str(device_id),
                    "sample_id": str(sample_id),
                    "evidence_digest": evidence.digest,
                    "sequence": evidence.sequence,
                    "observed_at": evidence.sample.observed_at,
                    "recorded_at": evidence.recorded_at,
                },
            ))
        if len(candidates) < excess:
            raise OverflowError(
                "health evidence bound cannot discard authenticated device chain heads"
            )
        selected = candidates[:excess]
        projection = [item[1] for item in selected]
        batch_digest = self._projection_digest(projection)
        self._append_prune_tombstone_locked(
            tenant_id,
            domain="health-evidence",
            subject_id=f"health-{batch_digest[:32]}",
            row_count=len(selected),
            projection=projection,
            pruned_at=pruned_at,
        )
        self._db.executemany(
            "DELETE FROM fabric_health WHERE tenant_id=? AND device_id=? AND sample_id=?",
            [item[0] for item in selected],
        )
        self._increment_stat_locked(tenant_id, "health_retention_drops", len(selected))

    def _decode_health(
        self,
        encoded: str,
        tenant_id: str,
        *,
        expected_device_id: str | None = None,
        expected_sample_id: str | None = None,
        expected_observed_at: float | None = None,
    ) -> FleetHealthEvidence:
        try:
            value = json.loads(encoded)
            if not isinstance(value, dict) or set(value) != {
                "sample",
                "recorded_at",
                "binding_generation",
                "sequence",
                "sequence_gap",
                "previous_evidence_digest",
                "device_signature_ed25519",
                "evidence_hmac",
            }:
                raise ValueError("health schema mismatch")
            sample = FleetHealthSample(**value["sample"])
            evidence = FleetHealthEvidence(
                sample=sample,
                recorded_at=_timestamp(value["recorded_at"], "health record time"),
                binding_generation=int(value["binding_generation"]),
                sequence=int(value["sequence"]),
                sequence_gap=int(value["sequence_gap"]),
                previous_evidence_digest=str(value["previous_evidence_digest"]),
                device_signature_ed25519=str(value["device_signature_ed25519"]),
                evidence_hmac=str(value["evidence_hmac"]),
            )
            if sample.tenant_id != tenant_id:
                raise ValueError("health tenant binding mismatch")
            if expected_device_id is not None and sample.device_id != expected_device_id:
                raise ValueError("health device row binding mismatch")
            if expected_sample_id is not None and sample.sample_id != expected_sample_id:
                raise ValueError("health sample row binding mismatch")
            if (
                expected_observed_at is not None
                and sample.observed_at != float(expected_observed_at)
            ):
                raise ValueError("health observation row binding mismatch")
            core = asdict(evidence)
            core.pop("evidence_hmac")
            expected = _hmac(self._key(tenant_id), b"health-evidence", core)
            if not _SHA256.fullmatch(evidence.evidence_hmac) or not hmac.compare_digest(
                evidence.evidence_hmac, expected
            ):
                raise ValueError("health authenticator mismatch")
            binding = self._local_device_binding_locked(tenant_id, sample.device_id)
            if (
                binding is None
                or binding["binding_generation"] != evidence.binding_generation
                or not hmac.compare_digest(
                    str(binding["device_public_key_sha256"]),
                    sample.device_public_key_sha256,
                )
            ):
                raise ValueError("health device binding is unavailable")
            Ed25519PublicKey.from_public_bytes(
                _decode_b64(
                    binding["device_public_key_ed25519"], 32, "Ed25519 public key"
                )
            ).verify(
                _decode_b64(
                    evidence.device_signature_ed25519,
                    64,
                    "Ed25519 health signature",
                ),
                health_possession_payload(
                    sample,
                    binding_generation=evidence.binding_generation,
                    sequence=evidence.sequence,
                    previous_evidence_digest=evidence.previous_evidence_digest,
                ),
            )
            return evidence
        except (
            InvalidSignature,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise RuntimeError("fleet health evidence integrity verification failed") from exc

    def health_snapshot(self, tenant_id: str, *, limit: int = 200) -> HealthSnapshot:
        tenant = _identifier(tenant_id, "tenant ID")
        self._key(tenant)
        if type(limit) is not int or not 1 <= limit <= MAX_DASHBOARD_ROWS:
            raise ValueError("health snapshot limit must be from 1 through 500")
        stamp = self._now(tenant)
        with self._lock:
            verified_latest: dict[str, FleetHealthEvidence] = {}
            self._verify_custody_locked(tenant, verified_latest)
            roster = self._active_device_roster_locked(tenant)
            total = int(self._db.execute(
                "SELECT COUNT(*) FROM fabric_health WHERE tenant_id=?", (tenant,)
            ).fetchone()[0])
            rows = self._db.execute(
                "SELECT evidence_json,device_id,sample_id,observed_at "
                "FROM fabric_health WHERE tenant_id=? "
                "ORDER BY observed_at DESC,device_id,sample_id LIMIT ?",
                (tenant, limit),
            ).fetchall()
            stats = self._verified_stats_locked(tenant)
            evidence = tuple(self._decode_health(
                str(row[0]),
                tenant,
                expected_device_id=str(row[1]),
                expected_sample_id=str(row[2]),
                expected_observed_at=float(row[3]),
            )
            for row in rows
            )
            latest_evidence = verified_latest
        roster_set = set(roster)
        latest = {
            device_id: item
            for device_id, item in latest_evidence.items()
            if device_id in roster_set
        }
        missing_ids = tuple(sorted(roster_set - set(latest)))
        stale_ids = tuple(sorted(
            device_id
            for device_id, item in latest.items()
            if (
                item.sample.observed_at < stamp - self._health_freshness
                or item.recorded_at < stamp - self._health_freshness
                or item.recorded_at > stamp
            )
        ))
        fresh_ids = roster_set - set(missing_ids) - set(stale_ids)
        reported_drops = sum(
            item.sample.dropped_total for item in latest.values()
        )
        backpressure = sum(
            item.sample.queue_depth * 100 >= item.sample.queue_capacity * 80
            for item in latest.values()
        )
        unhealthy_ids = set(missing_ids) | set(stale_ids) | {
            device_id
            for device_id, item in latest.items()
            if item.sample.health_percent < 100
        }
        retention = int(stats["health_retention_drops"])
        sequence_gaps = int(stats["health_sequence_gaps"])
        chain_status = (
            "authenticated-local-chain-with-visible-history-gaps"
            if retention or sequence_gaps
            else "authenticated-local-chain-heads-contiguous"
        )
        return HealthSnapshot(
            tenant,
            evidence,
            total,
            total > len(evidence),
            retention,
            reported_drops,
            backpressure,
            len(unhealthy_ids),
            len(roster),
            len(latest),
            len(fresh_ids),
            len(missing_ids),
            len(stale_ids),
            missing_ids,
            stale_ids,
            self._health_freshness,
            sequence_gaps,
            True,
            chain_status,
        )

    def stage_rollout(self, plan: FleetRolloutPlan) -> Mapping[str, Any]:
        if not isinstance(plan, FleetRolloutPlan):
            raise TypeError("rollout must use FleetRolloutPlan")
        key = self._key(plan.tenant_id)
        stamp = self._now(plan.tenant_id)
        if plan.created_at > stamp:
            raise ValueError("rollout creation time may not be in the future")
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_custody_locked(plan.tenant_id)
                active = set(self._active_device_roster_locked(plan.tenant_id))
                missing = [
                    device_id for device_id in plan.target_device_ids
                    if device_id not in active
                ]
                if missing:
                    raise PermissionError(
                        f"rollout contains {len(missing)} device(s) not enrolled in this tenant"
                    )
                encoded_plan = _canonical(asdict(plan)).decode("utf-8")
                record = self._rollout_record(
                    plan, "staged", 1, "awaiting explicit canary start", stamp, key
                )
                if int(self._db.execute(
                    "SELECT COUNT(*) FROM fabric_rollouts WHERE tenant_id=?",
                    (plan.tenant_id,),
                ).fetchone()[0]) >= self._max_rollouts:
                    self._prune_rollout_locked(plan.tenant_id, stamp)
                self._db.execute(
                    "INSERT INTO fabric_rollouts(tenant_id,rollout_id,plan_json,state,"
                    "version,reason,updated_at,record_hmac,evaluation_json,"
                    "canary_started_at,canary_generation) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        plan.tenant_id,
                        plan.rollout_id,
                        encoded_plan,
                        "staged",
                        1,
                        record["reason"],
                        stamp,
                        record["record_hmac"],
                        "{}",
                        0.0,
                        0,
                    ),
                )
                self._append_rollout_history_locked(plan, record)
                self._write_custody_locked(plan.tenant_id)
                self._db.commit()
            except sqlite3.IntegrityError as exc:
                self._db.rollback()
                raise ValueError("rollout ID is already in use") from exc
            except Exception:
                self._db.rollback()
                raise
        return record

    def _prune_rollout_locked(self, tenant_id: str, pruned_at: float) -> None:
        candidates = self._db.execute(
            "SELECT rollout_id FROM fabric_rollouts "
            "WHERE tenant_id=? AND state IN ('completed','cancelled','halted') "
            "ORDER BY updated_at,rollout_id",
            (tenant_id,),
        ).fetchall()
        if not candidates:
            raise OverflowError("rollout store is full of active plans")
        verified = [
            self._load_rollout_locked(tenant_id, str(row[0])) for row in candidates
        ]
        plan, record = verified[0]
        projection = {
            "plan": asdict(plan),
            "record": record,
            "history_length": int(record["history_length"]),
            "history_head_digest": str(record["history_head_digest"]),
        }
        self._append_prune_tombstone_locked(
            tenant_id,
            domain="rollout",
            subject_id=plan.rollout_id,
            row_count=1 + int(record["history_length"]),
            projection=projection,
            pruned_at=pruned_at,
        )
        self._db.execute(
            "DELETE FROM fabric_rollouts WHERE tenant_id=? AND rollout_id=?",
            (tenant_id, plan.rollout_id),
        )
        self._db.execute(
            "DELETE FROM fabric_rollout_history WHERE tenant_id=? AND rollout_id=?",
            (tenant_id, plan.rollout_id),
        )
        self._increment_stat_locked(tenant_id, "rollout_retention_drops", 1)

    @staticmethod
    def _rollout_record(
        plan: FleetRolloutPlan,
        state: str,
        version: int,
        reason: str,
        updated_at: float,
        key: bytes,
        *,
        canary_started_at: float = 0.0,
        canary_generation: int = 0,
    ) -> dict[str, Any]:
        if state not in _ROLLOUT_STATES:
            raise ValueError("unknown rollout state")
        started = _timestamp(canary_started_at, "canary start time")
        if type(canary_generation) is not int or canary_generation < 0:
            raise ValueError("invalid canary generation")
        if state == "staged" and (started != 0 or canary_generation != 0):
            raise ValueError("staged rollout may not claim canary activation")
        if state != "staged" and (started <= 0 or canary_generation < 1):
            raise ValueError("activated rollout requires a canary generation")
        core = {
            "tenant_id": plan.tenant_id,
            "rollout_id": plan.rollout_id,
            "plan_digest": plan.digest,
            "state": state,
            "version": version,
            "reason": str(reason)[:2_048],
            "updated_at": float(updated_at),
            "canary_started_at": started,
            "canary_generation": canary_generation,
        }
        return {**core, "record_hmac": _hmac(key, b"rollout-record", core)}

    def _append_rollout_history_locked(
        self,
        plan: FleetRolloutPlan,
        record: Mapping[str, Any],
        evaluation_json: str = "",
    ) -> str:
        prior = self._db.execute(
            "SELECT version,record_json,evaluation_digest,previous_history_digest,"
            "history_hmac FROM fabric_rollout_history WHERE tenant_id=? AND rollout_id=? "
            "ORDER BY version DESC LIMIT 1",
            (plan.tenant_id, plan.rollout_id),
        ).fetchone()
        previous_digest = ZERO_DIGEST
        if prior is not None:
            previous_record = json.loads(str(prior[1]))
            prior_core = {
                "tenant_id": plan.tenant_id,
                "rollout_id": plan.rollout_id,
                "version": int(prior[0]),
                "record": previous_record,
                "evaluation_digest": str(prior[2]),
                "previous_history_digest": str(prior[3]),
            }
            expected = _hmac(
                self._key(plan.tenant_id), b"rollout-history", prior_core
            )
            if not hmac.compare_digest(str(prior[4]), expected):
                raise RuntimeError("rollout history integrity verification failed")
            previous_digest = hashlib.sha256(_canonical(prior_core)).hexdigest()
            if int(record["version"]) != int(prior[0]) + 1:
                raise RuntimeError("rollout history version gap detected")
        elif int(record["version"]) != 1:
            raise RuntimeError("rollout history is missing its authenticated origin")
        evaluation_digest = (
            hashlib.sha256(evaluation_json.encode("utf-8")).hexdigest()
            if evaluation_json else ""
        )
        core = {
            "tenant_id": plan.tenant_id,
            "rollout_id": plan.rollout_id,
            "version": int(record["version"]),
            "record": dict(record),
            "evaluation_digest": evaluation_digest,
            "previous_history_digest": previous_digest,
        }
        history_hmac = _hmac(
            self._key(plan.tenant_id), b"rollout-history", core
        )
        self._db.execute(
            "INSERT INTO fabric_rollout_history(tenant_id,rollout_id,version,state,"
            "record_json,evaluation_digest,previous_history_digest,history_hmac) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                plan.tenant_id,
                plan.rollout_id,
                int(record["version"]),
                str(record["state"]),
                _canonical(dict(record)).decode("utf-8"),
                evaluation_digest,
                previous_digest,
                history_hmac,
            ),
        )
        return hashlib.sha256(_canonical(core)).hexdigest()

    def _verify_rollout_history_locked(
        self, plan: FleetRolloutPlan, current: Mapping[str, Any]
    ) -> tuple[int, str]:
        rows = self._db.execute(
            "SELECT version,state,record_json,evaluation_digest,"
            "previous_history_digest,history_hmac FROM fabric_rollout_history "
            "WHERE tenant_id=? AND rollout_id=? ORDER BY version",
            (plan.tenant_id, plan.rollout_id),
        ).fetchall()
        previous_digest = ZERO_DIGEST
        last_record: Mapping[str, Any] | None = None
        for expected_version, row in enumerate(rows, start=1):
            record = json.loads(str(row[2]))
            core = {
                "tenant_id": plan.tenant_id,
                "rollout_id": plan.rollout_id,
                "version": int(row[0]),
                "record": record,
                "evaluation_digest": str(row[3]),
                "previous_history_digest": str(row[4]),
            }
            if (
                int(row[0]) != expected_version
                or str(row[1]) != str(record.get("state"))
                or str(row[4]) != previous_digest
                or not hmac.compare_digest(
                    str(row[5]),
                    _hmac(self._key(plan.tenant_id), b"rollout-history", core),
                )
            ):
                raise RuntimeError("rollout history integrity verification failed")
            previous_digest = hashlib.sha256(_canonical(core)).hexdigest()
            last_record = record
        current_record = (
            {key: current.get(key) for key in last_record}
            if last_record is not None else {}
        )
        if not rows or last_record != current_record:
            raise RuntimeError("rollout state is not bound to its authenticated history")
        return len(rows), previous_digest

    def _load_rollout_locked(
        self, tenant_id: str, rollout_id: str
    ) -> tuple[FleetRolloutPlan, dict[str, Any]]:
        row = self._db.execute(
            "SELECT plan_json,state,version,reason,updated_at,record_hmac,evaluation_json,"
            "canary_started_at,canary_generation "
            "FROM fabric_rollouts WHERE tenant_id=? AND rollout_id=?",
            (tenant_id, rollout_id),
        ).fetchone()
        if row is None:
            raise KeyError(rollout_id)
        try:
            raw = json.loads(row[0])
            raw["target_device_ids"] = tuple(raw["target_device_ids"])
            raw["canary_device_ids"] = tuple(raw["canary_device_ids"])
            plan = FleetRolloutPlan(**raw)
            if plan.tenant_id != tenant_id or plan.rollout_id != rollout_id:
                raise ValueError("rollout row identity mismatch")
            record = self._rollout_record(
                plan, str(row[1]), int(row[2]), str(row[3]), float(row[4]),
                self._key(tenant_id),
                canary_started_at=float(row[7]),
                canary_generation=int(row[8]),
            )
            if not hmac.compare_digest(record["record_hmac"], str(row[5])):
                raise ValueError("rollout authenticator mismatch")
            evaluation_raw = json.loads(str(row[6]))
            if evaluation_raw:
                finding_rows = evaluation_raw.get("findings")
                if not isinstance(finding_rows, list):
                    raise ValueError("rollout evaluation findings are invalid")
                evaluation_raw["findings"] = tuple(
                    CanaryFinding(**item) for item in finding_rows
                )
                evaluation = RolloutEvaluation(**evaluation_raw)
                if not self.verify_rollout_evaluation(evaluation):
                    raise ValueError("rollout evaluation authenticator mismatch")
                if (
                    evaluation.tenant_id != tenant_id
                    or evaluation.rollout_id != rollout_id
                    or evaluation.version != record["version"]
                    or evaluation.state != record["state"]
                    or evaluation.canary_started_at != record["canary_started_at"]
                    or evaluation.canary_generation != record["canary_generation"]
                ):
                    raise ValueError("rollout evaluation row binding mismatch")
                record["evaluation"] = asdict(evaluation)
            history_length, history_head = self._verify_rollout_history_locked(
                plan, record
            )
            record["history_length"] = history_length
            record["history_head_digest"] = history_head
            record["history_chain_status"] = "authenticated-contiguous-local-history"
            return plan, record
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("fleet rollout integrity verification failed") from exc

    def start_canary(
        self,
        tenant_id: str,
        rollout_id: str,
        *,
        expected_version: int,
        desired_policy_hash: str,
    ) -> Mapping[str, Any]:
        tenant = _identifier(tenant_id, "tenant ID")
        identity = _identifier(rollout_id, "rollout ID")
        desired = _digest(desired_policy_hash, "desired policy hash")
        stamp = self._now(tenant)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_custody_locked(tenant)
                plan, current = self._load_rollout_locked(tenant, identity)
                if current["version"] != expected_version:
                    raise RuntimeError("rollout version conflict")
                if current["state"] != "staged":
                    raise ValueError("rollout is not staged")
                if plan.desired_policy_hash != desired:
                    raise PermissionError("rollout desired policy binding mismatch")
                active = set(self._active_device_roster_locked(tenant))
                missing = set(plan.target_device_ids) - active
                if missing:
                    raise PermissionError(
                        f"rollout activation contains {len(missing)} inactive device(s)"
                    )
                generation = int(current["canary_generation"]) + 1
                record = self._rollout_record(
                    plan, "canary", expected_version + 1,
                    "canary observation in progress; no dispatch authority",
                    stamp, self._key(tenant),
                    canary_started_at=stamp,
                    canary_generation=generation,
                )
                self._cas_rollout_locked(tenant, identity, current, record)
                self._append_rollout_history_locked(plan, record)
                self._write_custody_locked(tenant)
                self._db.commit()
                return record
            except Exception:
                self._db.rollback()
                raise

    def _cas_rollout_locked(
        self,
        tenant_id: str,
        rollout_id: str,
        current: Mapping[str, Any],
        replacement: Mapping[str, Any],
    ) -> None:
        cursor = self._db.execute(
            "UPDATE fabric_rollouts SET state=?,version=?,reason=?,updated_at=?,record_hmac=?,"
            "canary_started_at=?,canary_generation=? "
            "WHERE tenant_id=? AND rollout_id=? AND version=? AND state=?",
            (
                replacement["state"],
                replacement["version"],
                replacement["reason"],
                replacement["updated_at"],
                replacement["record_hmac"],
                replacement["canary_started_at"],
                replacement["canary_generation"],
                tenant_id,
                rollout_id,
                current["version"],
                current["state"],
            ),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("rollout version conflict")

    def evaluate_canary(
        self,
        tenant_id: str,
        rollout_id: str,
        *,
        expected_version: int,
        desired_policy_hash: str,
    ) -> RolloutEvaluation:
        tenant = _identifier(tenant_id, "tenant ID")
        identity = _identifier(rollout_id, "rollout ID")
        desired = _digest(desired_policy_hash, "desired policy hash")
        stamp = self._now(tenant)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                verified_latest: dict[str, FleetHealthEvidence] = {}
                self._verify_custody_locked(tenant, verified_latest)
                plan, current = self._load_rollout_locked(tenant, identity)
                if current["version"] != expected_version:
                    raise RuntimeError("rollout version conflict")
                if current["state"] != "canary":
                    raise ValueError("rollout is not in canary observation")
                if plan.desired_policy_hash != desired:
                    raise PermissionError("rollout desired policy binding mismatch")
                if stamp < float(current["canary_started_at"]):
                    raise RuntimeError("fleet fabric clock predates canary activation")
                findings = self._canary_findings_locked(
                    plan, current, stamp, verified_latest
                )
                state = (
                    "general-ready"
                    if len(findings) <= plan.max_canary_failures
                    else "halted"
                )
                reason = (
                    "canary evidence meets the declared health gate; general rollout remains proposal-only"
                    if state == "general-ready"
                    else f"canary halted: {len(findings)} finding(s) exceed failure budget "
                    f"{plan.max_canary_failures}"
                )
                record = self._rollout_record(
                    plan,
                    state,
                    expected_version + 1,
                    reason,
                    stamp,
                    self._key(tenant),
                    canary_started_at=float(current["canary_started_at"]),
                    canary_generation=int(current["canary_generation"]),
                )
                self._cas_rollout_locked(tenant, identity, current, record)
                core = {
                    "tenant_id": tenant,
                    "rollout_id": identity,
                    "desired_policy_hash": desired,
                    "state": state,
                    "version": expected_version + 1,
                    "evaluated_at": stamp,
                    "canary_started_at": float(current["canary_started_at"]),
                    "canary_generation": int(current["canary_generation"]),
                    "findings": [asdict(item) for item in findings],
                }
                evaluation = RolloutEvaluation(
                    tenant,
                    identity,
                    desired,
                    state,
                    expected_version + 1,
                    stamp,
                    float(current["canary_started_at"]),
                    int(current["canary_generation"]),
                    findings,
                    _hmac(self._key(tenant), b"rollout-evaluation", core),
                )
                evaluation_json = _canonical(asdict(evaluation)).decode("utf-8")
                cursor = self._db.execute(
                    "UPDATE fabric_rollouts SET evaluation_json=? "
                    "WHERE tenant_id=? AND rollout_id=? AND version=? AND state=?",
                    (
                        evaluation_json,
                        tenant,
                        identity,
                        evaluation.version,
                        evaluation.state,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("rollout evaluation changed concurrently")
                self._append_rollout_history_locked(plan, record, evaluation_json)
                self._write_custody_locked(tenant)
                self._db.commit()
                return evaluation
            except Exception:
                self._db.rollback()
                raise

    def verify_rollout_evaluation(self, evaluation: RolloutEvaluation) -> bool:
        if not isinstance(evaluation, RolloutEvaluation):
            return False
        core = {
            "tenant_id": evaluation.tenant_id,
            "rollout_id": evaluation.rollout_id,
            "desired_policy_hash": evaluation.desired_policy_hash,
            "state": evaluation.state,
            "version": evaluation.version,
            "evaluated_at": evaluation.evaluated_at,
            "canary_started_at": evaluation.canary_started_at,
            "canary_generation": evaluation.canary_generation,
            "findings": [asdict(item) for item in evaluation.findings],
        }
        try:
            expected = _hmac(
                self._key(evaluation.tenant_id), b"rollout-evaluation", core
            )
        except (PermissionError, ValueError):
            return False
        return hmac.compare_digest(evaluation.evaluation_hmac, expected)

    def _canary_findings_locked(
        self,
        plan: FleetRolloutPlan,
        rollout_record: Mapping[str, Any],
        evaluated_at: float,
        verified_health_heads: Mapping[str, FleetHealthEvidence],
    ) -> tuple[CanaryFinding, ...]:
        started_at = float(rollout_record["canary_started_at"])
        generation = int(rollout_record["canary_generation"])
        active = set(self._active_device_roster_locked(plan.tenant_id))
        requested = tuple(plan.canary_device_ids)
        findings: list[CanaryFinding] = []
        freshness_floor = evaluated_at - self._health_freshness
        for device_id in requested:
            if device_id not in active:
                findings.append(CanaryFinding(
                    device_id,
                    "device is no longer active in the authoritative enrolled roster",
                ))
                continue
            evidence = verified_health_heads.get(device_id)
            if evidence is None:
                findings.append(CanaryFinding(
                    device_id, "no post-activation canary health evidence"
                ))
                continue
            sample = evidence.sample
            if sample.observed_at < started_at or evidence.recorded_at < started_at:
                findings.append(CanaryFinding(
                    device_id, "no post-activation canary health evidence"
                ))
                continue
            if (
                sample.observed_at > evaluated_at
                or evidence.recorded_at > evaluated_at
            ):
                findings.append(CanaryFinding(
                    device_id, "health evidence is outside the canary activation window"
                ))
                continue
            reasons: list[str] = []
            if (
                sample.observed_at < freshness_floor
                or evidence.recorded_at < freshness_floor
            ):
                reasons.append("canary health evidence exceeds the freshness SLA")
            if (
                sample.rollout_id != plan.rollout_id
                or sample.rollout_generation != generation
            ):
                reasons.append("health evidence canary generation binding mismatch")
            if sample.desired_policy_hash != plan.desired_policy_hash:
                reasons.append("health evidence desired-policy binding mismatch")
            if sample.effective_policy_hash != plan.desired_policy_hash:
                reasons.append("effective policy does not match desired policy")
            if sample.health_percent < plan.minimum_health_percent:
                reasons.append(
                    f"health {sample.health_percent}% is below {plan.minimum_health_percent}%"
                )
            if sample.dropped_since_previous:
                reasons.append(
                    f"{sample.dropped_since_previous} health event(s) were lost"
                )
            if evidence.sequence_gap:
                reasons.append(
                    f"health evidence sequence contains {evidence.sequence_gap} gap(s)"
                )
            if sample.queue_depth * 100 >= sample.queue_capacity * 80:
                reasons.append(
                    f"health queue backpressure is {sample.queue_depth}/{sample.queue_capacity}"
                )
            if reasons:
                findings.append(CanaryFinding(
                    device_id, "; ".join(reasons), sample.effective_policy_hash
                ))
        return tuple(findings)

    def rollback_plan(self, tenant_id: str, rollout_id: str) -> RollbackPlan:
        tenant = _identifier(tenant_id, "tenant ID")
        identity = _identifier(rollout_id, "rollout ID")
        with self._lock:
            self._verify_custody_locked(tenant)
            plan, record = self._load_rollout_locked(tenant, identity)
        if record["state"] != "halted":
            raise ValueError("rollback planning requires a halted canary")
        return RollbackPlan(
            tenant,
            identity,
            plan.desired_policy_hash,
            plan.previous_policy_hash,
            plan.target_device_ids,
            record["reason"],
        )

    def rollout_snapshot(
        self, tenant_id: str, *, limit: int = 200
    ) -> tuple[Mapping[str, Any], ...]:
        tenant = _identifier(tenant_id, "tenant ID")
        self._key(tenant)
        if type(limit) is not int or not 1 <= limit <= MAX_DASHBOARD_ROWS:
            raise ValueError("rollout snapshot limit must be from 1 through 500")
        with self._lock:
            self._verify_custody_locked(tenant)
            identities = self._db.execute(
                "SELECT rollout_id FROM fabric_rollouts WHERE tenant_id=? "
                "ORDER BY updated_at DESC,rollout_id LIMIT ?",
                (tenant, limit),
            ).fetchall()
            result = []
            for row in identities:
                plan, record = self._load_rollout_locked(tenant, str(row[0]))
                result.append({
                    **record,
                    "policy_bundle_id": plan.policy_bundle_id,
                    "group_id": plan.group_id,
                    "desired_policy_hash": plan.desired_policy_hash,
                    "previous_policy_hash": plan.previous_policy_hash,
                    "target_count": len(plan.target_device_ids),
                    "canary_count": len(plan.canary_device_ids),
                })
        return tuple(result)

    def enrollment_snapshot(
        self, tenant_id: str, *, limit: int = 200
    ) -> tuple[Mapping[str, Any], ...]:
        tenant = _identifier(tenant_id, "tenant ID")
        self._key(tenant)
        if type(limit) is not int or not 1 <= limit <= MAX_DASHBOARD_ROWS:
            raise ValueError("enrollment snapshot limit must be from 1 through 500")
        with self._lock:
            self._verify_custody_locked(tenant)
            rows = self._db.execute(
                "SELECT grant_json,state,redeemed_at,receipt_json,state_hmac,grant_id,device_id "
                "FROM fabric_grants "
                "WHERE tenant_id=? ORDER BY redeemed_at DESC,grant_id LIMIT ?",
                (tenant, limit),
            ).fetchall()
            result: list[Mapping[str, Any]] = []
            for row in rows:
                grant, lifecycle = self._verified_grant_row_locked(tenant, row)
                result.append({
                    "tenant_id": tenant,
                    "device_id": grant.device_id,
                    "grant_id": grant.grant_id,
                    "state": lifecycle["state"],
                    "issued_at": grant.issued_at,
                    "expires_at": grant.expires_at,
                    "redeemed_at": lifecycle["redeemed_at"],
                    "device_public_key_sha256": grant.device_public_key_sha256,
                    "grant_digest": grant.digest,
                })
        return tuple(result)

    def custody_snapshot(self, tenant_id: str) -> Mapping[str, Any]:
        tenant = _identifier(tenant_id, "tenant ID")
        self._key(tenant)
        with self._lock:
            return dict(self._verify_custody_locked(tenant))

    def dashboard_snapshot(self, tenant_id: str) -> Mapping[str, Any]:
        tenant = _identifier(tenant_id, "tenant ID")
        health = self.health_snapshot(tenant)
        with self._lock:
            stats = self._verified_stats_locked(tenant)
            # health_snapshot just proved the full database projection. Read the
            # same sealed manifest here; enrollment/rollout reads below perform
            # their own full custody verification before rendering.
            custody = dict(self._verified_custody_manifest_locked(tenant))
        return {
            "schema": SCHEMA_ID,
            "tenant_id": tenant,
            "transport": asdict(self.transport_readiness),
            "enrollments": self.enrollment_snapshot(tenant),
            "rollouts": self.rollout_snapshot(tenant),
            "health": health,
            "authenticated_local_stats": stats,
            "authenticated_custody_checkpoint": custody,
            "device_authentication": "ed25519-possession-proof-and-signed-health",
            "storage_integrity": (
                "tenant-keyed-hmac-custody-checkpoint-and-prune-tombstones"
            ),
            "response_authority": "observe-and-plan-only",
            "remote_shell_available": False,
            "arbitrary_command_available": False,
        }

    def close(self) -> None:
        with self._lock:
            self._db.close()


__all__ = [
    "CanaryFinding",
    "CoordinatorTransportConfig",
    "EnrollmentGrant",
    "EnrollmentProof",
    "EnrollmentReceipt",
    "FleetFabricStore",
    "FleetHealthEvidence",
    "FleetHealthSample",
    "FleetRolloutPlan",
    "HealthSnapshot",
    "RollbackPlan",
    "RolloutEvaluation",
    "SignedFleetHealthEnvelope",
    "TransportReadiness",
    "ZERO_DIGEST",
    "effective_policy_hash",
    "enrollment_possession_challenge",
    "health_possession_payload",
    "validate_transport_config",
]
