"""Authorization-gated, passive device connection security assessments.

This module deliberately is *not* a network scanner or exploitation framework.
It accepts privacy-reduced observations from this host or a previously enrolled
agent, evaluates deterministic posture rules, and returns remediation guidance.
There is no target-address field and no facility for executing a response.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature


FORMAT = "angerona-device-security-lab-v1"
STATE_FORMAT = "angerona-device-security-lab-state-v1"
MAX_STATE_BYTES = 512 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_ENROLLMENTS = 64
MAX_PENDING_CHALLENGES = 64
MAX_AUDIT_RECORDS = 512
MAX_OBSERVATIONS = 128
MAX_ATTRIBUTES = 16
MAX_LISTENING_PORTS = 128
MAX_LABEL_CHARS = 48
MAX_CHALLENGE_TTL_SECONDS = 300
DEFAULT_CHALLENGE_TTL_SECONDS = 120
MAX_EVIDENCE_AGE_SECONDS = 300
DEFAULT_EVIDENCE_AGE_SECONDS = 120
DEFAULT_FUTURE_SKEW_SECONDS = 15
MAX_COLLECTION_TIMEOUT_SECONDS = 5.0

_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$")
_SAFE_TOKEN = re.compile(r"^[a-z][a-z0-9-]{7,63}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_SOURCES = frozenset({"local", "enrolled_agent"})
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SENSITIVE_KEYS = frozenset(
    {
        "address", "bssid", "command", "command_line", "device_id", "hostname",
        "ip", "mac", "name", "path", "pid", "serial", "ssid", "target", "user",
        "username",
    }
)
_COMMON_ATTRIBUTES = frozenset(
    {"supported", "present", "software_version_status", "configuration_baseline"}
)
_ATTRIBUTE_FIELDS: dict[str, frozenset[str]] = {
    "usb": _COMMON_ATTRIBUTES
    | frozenset(
        {
            "connected_count", "device_control_policy", "autorun_enabled",
            "unsigned_driver_present",
        }
    ),
    "ethernet": _COMMON_ATTRIBUTES
    | frozenset(
        {
            "interface_count", "up_count", "firewall_enabled", "listening_ports",
            "network_profile", "ieee8021x_enabled",
        }
    ),
    "wifi": _COMMON_ATTRIBUTES
    | frozenset(
        {
            "interface_count", "up_count", "firewall_enabled", "security_protocol",
            "randomized_mac", "hotspot_enabled",
        }
    ),
    "bluetooth": _COMMON_ATTRIBUTES
    | frozenset({"enabled", "discoverable", "paired_count", "legacy_pairing_allowed"}),
    "display_hdmi": _COMMON_ATTRIBUTES
    | frozenset({"connected_count", "hdcp_status", "cec_enabled", "data_channel_enabled"}),
}


class DeviceLabError(ValueError):
    """A device-lab trust, privacy, schema, or lifecycle contract failed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ConnectionKind(str, Enum):
    USB = "usb"
    ETHERNET = "ethernet"
    WIFI = "wifi"
    BLUETOOTH = "bluetooth"
    DISPLAY_HDMI = "display_hdmi"


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DeviceLabError("schema", "value is not canonical JSON") from exc


def _authority(value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("device-lab authority must be bytes")
    result = bytes(value)
    if len(result) < 32:
        raise DeviceLabError("authority", "device-lab authority must be at least 32 bytes")
    return result


def _private_key(value: object):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if isinstance(value, Ed25519PrivateKey):
        return value
    if not isinstance(value, (bytes, bytearray, memoryview)) or len(value) != 32:
        raise DeviceLabError("private_key", "Ed25519 private key must be 32 raw bytes")
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes(value))
    except ValueError as exc:
        raise DeviceLabError("private_key", "Ed25519 private key is invalid") from exc


def _decode_exact_base64(value: str | bytes, size: int, code: str) -> bytes:
    try:
        if isinstance(value, str):
            encoded = value.encode("ascii")
        elif isinstance(value, bytes):
            if len(value) == size:
                return value
            encoded = value
        else:
            raise TypeError
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise DeviceLabError(code, f"{code.replace('_', ' ')} is invalid") from exc
    if len(decoded) != size:
        raise DeviceLabError(code, f"{code.replace('_', ' ')} has an invalid size")
    return decoded


def _public_key(value: str | bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw = _decode_exact_base64(value, 32, "public_key")
    try:
        return Ed25519PublicKey.from_public_bytes(raw), raw
    except ValueError as exc:
        raise DeviceLabError("public_key", "Ed25519 public key is invalid") from exc


def _signature(value: str | bytes) -> bytes:
    return _decode_exact_base64(value, 64, "signature")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _kind(value: ConnectionKind | str) -> ConnectionKind:
    try:
        return value if isinstance(value, ConnectionKind) else ConnectionKind(value)
    except (TypeError, ValueError) as exc:
        raise DeviceLabError("connection_kind", "unsupported connection kind") from exc


def _redacted_label_token(label: str) -> str:
    digest = hashlib.sha256(label.casefold().encode("utf-8")).hexdigest()[:16]
    return f"device-{digest}"


def _looks_sensitive(value: str) -> bool:
    if "\\" in value or "/" in value or "@" in value:
        return True
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        pass
    return bool(re.search(r"(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value))


def _validate_attributes(kind: ConnectionKind, raw: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(raw, Mapping) or len(raw) > MAX_ATTRIBUTES:
        raise DeviceLabError("cardinality", "observation attributes exceed their bound")
    keys = frozenset(raw)
    if keys - _ATTRIBUTE_FIELDS[kind.value] or keys & _SENSITIVE_KEYS:
        raise DeviceLabError("privacy", "observation includes an unsupported or identifying field")
    result: dict[str, object] = {}
    boolean_fields = {
        "supported", "present", "autorun_enabled", "unsigned_driver_present",
        "firewall_enabled", "ieee8021x_enabled", "randomized_mac", "hotspot_enabled",
        "enabled", "discoverable", "legacy_pairing_allowed", "cec_enabled",
        "data_channel_enabled",
    }
    count_fields = {"connected_count", "interface_count", "up_count", "paired_count"}
    enums = {
        "software_version_status": {"current", "outdated", "unknown"},
        "configuration_baseline": {"compliant", "noncompliant", "unknown"},
        "device_control_policy": {"blocked", "allowlisted", "unrestricted", "unknown"},
        "network_profile": {"public", "private", "domain", "unknown"},
        "security_protocol": {"open", "wep", "wpa", "wpa2", "wpa3", "unknown"},
        "hdcp_status": {"enabled", "disabled", "unsupported", "unknown"},
    }
    for key, value in raw.items():
        if key in boolean_fields:
            if not isinstance(value, bool):
                raise DeviceLabError("schema", f"{key} must be a boolean")
        elif key in count_fields:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 64:
                raise DeviceLabError("bounds", f"{key} is outside its bound")
        elif key == "listening_ports":
            if not isinstance(value, (list, tuple)) or len(value) > MAX_LISTENING_PORTS:
                raise DeviceLabError("cardinality", "listening_ports exceeds its bound")
            if any(
                isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
                for port in value
            ):
                raise DeviceLabError("bounds", "listening_ports contains an invalid port")
            value = sorted(set(value))
        elif key in enums:
            if not isinstance(value, str) or value not in enums[key]:
                raise DeviceLabError("schema", f"{key} is not recognized")
        else:
            raise DeviceLabError("schema", f"unsupported attribute: {key}")
        if isinstance(value, str) and _looks_sensitive(value):
            raise DeviceLabError("privacy", "identifying string is not allowed in observations")
        result[key] = value
    return dict(sorted(result.items()))


@dataclass(frozen=True)
class ConnectionObservation:
    connection: ConnectionKind | str
    source: str
    observed_at: int
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        connection = _kind(self.connection)
        if self.source not in _EVIDENCE_SOURCES:
            raise DeviceLabError("source", "observation source is not recognized")
        if isinstance(self.observed_at, bool) or not isinstance(self.observed_at, int):
            raise DeviceLabError("time", "observed_at must be an integer epoch")
        if self.observed_at < 0:
            raise DeviceLabError("time", "observed_at is outside its bound")
        attributes = _validate_attributes(connection, self.attributes)
        object.__setattr__(self, "connection", connection)
        object.__setattr__(self, "attributes", attributes)

    def to_dict(self) -> dict[str, object]:
        return {
            "connection": self.connection.value,
            "source": self.source,
            "observed_at": self.observed_at,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ConnectionObservation":
        if not isinstance(value, Mapping) or frozenset(value) != {
            "connection", "source", "observed_at", "attributes"
        }:
            raise DeviceLabError("schema", "observation fields do not match the v1 schema")
        return cls(
            connection=value["connection"],
            source=value["source"],
            observed_at=value["observed_at"],
            attributes=value["attributes"],
        )


@dataclass(frozen=True)
class EnrollmentChallenge:
    enrollment_id: str
    label_token: str
    nonce: str
    evidence_source: str
    allowed_connections: tuple[str, ...]
    issued_at: int
    expires_at: int

    def to_dict(self) -> dict[str, object]:
        return {
            "format": FORMAT,
            "purpose": "enrollment_challenge",
            "enrollment_id": self.enrollment_id,
            "label_token": self.label_token,
            "nonce": self.nonce,
            "evidence_source": self.evidence_source,
            "allowed_connections": list(self.allowed_connections),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class EnrollmentRecord:
    enrollment_id: str
    label: str
    label_token: str
    evidence_source: str
    allowed_connections: tuple[str, ...]
    owner_attested_at: int
    enrolled_at: Optional[int]
    status: str
    public_key_fingerprint: str = ""
    authenticator: str = ""
    last_sequence: int = -1

    def to_dict(self) -> dict[str, object]:
        return {
            "enrollment_id": self.enrollment_id,
            "label": self.label,
            "label_token": self.label_token,
            "evidence_source": self.evidence_source,
            "allowed_connections": list(self.allowed_connections),
            "owner_attested_at": self.owner_attested_at,
            "enrolled_at": self.enrolled_at,
            "status": self.status,
            "public_key_fingerprint": self.public_key_fingerprint,
            "authenticator": self.authenticator,
            "last_sequence": self.last_sequence,
        }


@dataclass(frozen=True)
class EvidenceEnvelope:
    enrollment_id: str
    sequence: int
    issued_at: int
    expires_at: int
    observations: tuple[ConnectionObservation, ...]
    signature_ed25519: str

    def payload_dict(self) -> dict[str, object]:
        return {
            "format": FORMAT,
            "purpose": "posture_evidence",
            "enrollment_id": self.enrollment_id,
            "sequence": self.sequence,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "observations": [item.to_dict() for item in self.observations],
        }

    def to_dict(self) -> dict[str, object]:
        return {"payload": self.payload_dict(), "signature_ed25519": self.signature_ed25519}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "EvidenceEnvelope":
        if not isinstance(value, Mapping) or frozenset(value) != {
            "payload", "signature_ed25519"
        }:
            raise DeviceLabError("schema", "evidence wrapper fields do not match the v1 schema")
        payload = value["payload"]
        if not isinstance(payload, Mapping) or frozenset(payload) != {
            "format", "purpose", "enrollment_id", "sequence", "issued_at", "expires_at",
            "observations",
        }:
            raise DeviceLabError("schema", "evidence payload fields do not match the v1 schema")
        if payload["format"] != FORMAT or payload["purpose"] != "posture_evidence":
            raise DeviceLabError("version", "unsupported evidence format")
        raw_observations = payload["observations"]
        if not isinstance(raw_observations, list) or len(raw_observations) > MAX_OBSERVATIONS:
            raise DeviceLabError("cardinality", "evidence observation count exceeds its bound")
        signature = value["signature_ed25519"]
        _signature(signature)
        return cls(
            enrollment_id=payload["enrollment_id"],
            sequence=payload["sequence"],
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            observations=tuple(ConnectionObservation.from_dict(item) for item in raw_observations),
            signature_ed25519=signature,
        )


@dataclass(frozen=True)
class SecurityFinding:
    finding_id: str
    severity: str
    connection: str
    title: str
    evidence: str
    remediation: str
    patch_guidance: str
    response_options: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "connection": self.connection,
            "title": self.title,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "patch_guidance": self.patch_guidance,
            "response_options": list(self.response_options),
        }


@dataclass(frozen=True)
class AssessmentReport:
    assessment_id: str
    enrollment_id: str
    target_token: str
    generated_at: int
    outcome: str
    findings: tuple[SecurityFinding, ...]
    observation_count: int
    unsupported_connections: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        counts = {severity: 0 for severity in _SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "assessment_id": self.assessment_id,
            "enrollment_id": self.enrollment_id,
            "target_token": self.target_token,
            "generated_at": self.generated_at,
            "outcome": self.outcome,
            "severity_counts": counts,
            "findings": [item.to_dict() for item in self.findings],
            "observation_count": self.observation_count,
            "unsupported_connections": list(self.unsupported_connections),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class AuditRecord:
    event_id: str
    occurred_at: int
    action: str
    status: str
    subject_token: str
    detail: str
    authenticator: str

    def to_dict(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "occurred_at": self.occurred_at,
            "action": self.action,
            "status": self.status,
            "subject_token": self.subject_token,
            "detail": self.detail,
            "authenticator": self.authenticator,
        }


@dataclass
class _PendingChallenge:
    challenge: EnrollmentChallenge
    label: str


class DeviceSecurityLab:
    """Bounded engine for passive assessments of authorized devices."""

    _STATE_FILENAME = "device_security_lab_state.json"
    _SECRET_NAME = "ANGERONA_INTERNAL_DEVICE_LAB_AUTHORITY"

    def __init__(
        self,
        root: Path,
        *,
        authority: bytes | None = None,
        clock: Callable[[], float] = time.time,
        nonce_factory: Callable[[], str] | None = None,
        challenge_ttl_s: int = DEFAULT_CHALLENGE_TTL_SECONDS,
        evidence_age_s: int = DEFAULT_EVIDENCE_AGE_SECONDS,
        future_skew_s: int = DEFAULT_FUTURE_SKEW_SECONDS,
    ) -> None:
        self.root = Path(root)
        self._clock = clock
        self._nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(24))
        if not 1 <= challenge_ttl_s <= MAX_CHALLENGE_TTL_SECONDS:
            raise DeviceLabError("bounds", "challenge TTL is outside its bound")
        if not 1 <= evidence_age_s <= MAX_EVIDENCE_AGE_SECONDS:
            raise DeviceLabError("bounds", "evidence age is outside its bound")
        if not 0 <= future_skew_s <= 60:
            raise DeviceLabError("bounds", "future clock skew is outside its bound")
        self._challenge_ttl_s = int(challenge_ttl_s)
        self._evidence_age_s = int(evidence_age_s)
        self._future_skew_s = int(future_skew_s)
        self._lock = threading.RLock()
        self._pending: dict[str, _PendingChallenge] = {}
        self._records: dict[str, EnrollmentRecord] = {}
        self._public_keys: dict[str, str] = {}
        self._audit: list[AuditRecord] = []
        self._authority = _authority(authority) if authority is not None else self._protected_authority()
        self._load_state()

    def _protected_authority(self) -> bytes:
        """Load/create the authority only through Angerona's OS-protected store."""
        from angerona.core.secure_store import read_secret_map, write_secret_map

        try:
            values = read_secret_map(self.root, strict=True)
            encoded = values.get(self._SECRET_NAME, "")
            if encoded:
                return _authority(base64.urlsafe_b64decode(encoded.encode("ascii")))
            candidate = secrets.token_bytes(32)
            write_secret_map(
                {self._SECRET_NAME: base64.urlsafe_b64encode(candidate).decode("ascii")}, self.root
            )
            verified = read_secret_map(self.root, strict=True).get(self._SECRET_NAME, "")
            if not verified or not hmac.compare_digest(
                base64.urlsafe_b64decode(verified.encode("ascii")), candidate
            ):
                raise RuntimeError("protected authority verification failed")
            return candidate
        except (OSError, ValueError, RuntimeError) as exc:
            raise DeviceLabError(
                "protected_store_unavailable",
                "an OS-protected credential store is required for persistent device enrollment",
            ) from exc

    @staticmethod
    def generate_device_identity() -> object:
        """Return an Ed25519 private identity for an agent to protect locally."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.generate()

    @staticmethod
    def build_enrollment_proof(challenge: EnrollmentChallenge, private_key: object) -> str:
        return _b64(_private_key(private_key).sign(_canonical(challenge.to_dict())))

    def _now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise DeviceLabError("clock", "clock returned an invalid value")
        if value < 0 or value != value or value in (float("inf"), float("-inf")):
            raise DeviceLabError("clock", "clock returned an invalid value")
        return int(value)

    def create_enrollment(
        self,
        label: str,
        owner_attested: bool,
        *,
        evidence_source: str = "enrolled_agent",
        allowed_connections: Iterable[ConnectionKind | str] | None = None,
    ) -> tuple[EnrollmentRecord, EnrollmentChallenge]:
        """Begin enrollment only after explicit ownership/authorization attestation."""
        if owner_attested is not True:
            raise DeviceLabError(
                "authorization_required",
                "the operator must attest ownership or explicit authorization",
            )
        if not isinstance(label, str) or not _SAFE_LABEL.fullmatch(label):
            raise DeviceLabError("privacy", "label must be short and must not contain identifiers")
        if _looks_sensitive(label):
            raise DeviceLabError("privacy", "label appears to contain a private identifier")
        if evidence_source not in _EVIDENCE_SOURCES:
            raise DeviceLabError("source", "evidence source is not recognized")
        values = (
            tuple(ConnectionKind)
            if allowed_connections is None
            else tuple(_kind(item) for item in allowed_connections)
        )
        kinds = tuple(sorted({item.value for item in values}))
        if not kinds or len(kinds) > len(ConnectionKind):
            raise DeviceLabError("cardinality", "at least one connection kind is required")
        now = self._now()
        with self._lock:
            self._purge_expired_pending(now)
            if len(self._records) >= MAX_ENROLLMENTS:
                raise DeviceLabError("cardinality", "enrollment limit reached")
            if len(self._pending) >= MAX_PENDING_CHALLENGES:
                raise DeviceLabError("cardinality", "pending challenge limit reached")
            enrollment_id = f"enroll-{secrets.token_hex(12)}"
            nonce = self._nonce_factory()
            if not isinstance(nonce, str) or not 24 <= len(nonce) <= 128 or _looks_sensitive(nonce):
                raise DeviceLabError("nonce", "nonce source returned an unsafe value")
            challenge = EnrollmentChallenge(
                enrollment_id=enrollment_id,
                label_token=_redacted_label_token(label),
                nonce=nonce,
                evidence_source=evidence_source,
                allowed_connections=kinds,
                issued_at=now,
                expires_at=now + self._challenge_ttl_s,
            )
            record = EnrollmentRecord(
                enrollment_id=enrollment_id,
                label=label,
                label_token=challenge.label_token,
                evidence_source=evidence_source,
                allowed_connections=kinds,
                owner_attested_at=now,
                enrolled_at=None,
                status="pending",
            )
            self._pending[enrollment_id] = _PendingChallenge(challenge, label)
            self._append_audit("enrollment_challenge", "accepted", record.label_token, "pending")
            return record, challenge

    def confirm_enrollment(
        self, enrollment_id: str, signature: str | bytes, public_key: str | bytes
    ) -> EnrollmentRecord:
        """Confirm an agent enrollment using Ed25519 proof of key possession."""
        verifier, public_raw = _public_key(public_key)
        proof = _signature(signature)
        now = self._now()
        with self._lock:
            pending = self._pending.pop(enrollment_id, None)
            if pending is None:
                raise DeviceLabError("challenge", "challenge is unknown, expired, or already used")
            challenge = pending.challenge
            if now >= challenge.expires_at or now + self._future_skew_s < challenge.issued_at:
                self._append_audit(
                    "enrollment_confirm", "rejected", challenge.label_token, "expired"
                )
                raise DeviceLabError("expired", "enrollment challenge has expired")
            if challenge.evidence_source != "enrolled_agent":
                raise DeviceLabError("source", "local enrollment uses confirm_local_enrollment")
            try:
                verifier.verify(proof, _canonical(challenge.to_dict()))
            except InvalidSignature as exc:
                self._append_audit(
                    "enrollment_confirm", "rejected", challenge.label_token, "proof_failed"
                )
                raise DeviceLabError("forgery", "enrollment proof did not authenticate") from exc
            public_encoded = _b64(public_raw)
            unsigned = {
                "enrollment_id": enrollment_id,
                "label": pending.label,
                "label_token": challenge.label_token,
                "evidence_source": challenge.evidence_source,
                "allowed_connections": list(challenge.allowed_connections),
                "owner_attested_at": challenge.issued_at,
                "enrolled_at": now,
                "status": "active",
                "public_key_fingerprint": hashlib.sha256(public_raw).hexdigest(),
                "last_sequence": -1,
            }
            authenticator = self._record_authenticator(unsigned, public_encoded)
            record = EnrollmentRecord(**unsigned, authenticator=authenticator)
            self._records[enrollment_id] = record
            self._public_keys[enrollment_id] = public_encoded
            self._append_audit(
                "enrollment_confirm", "accepted", challenge.label_token, "authenticated"
            )
            self._save_state()
            return record

    def confirm_local_enrollment(
        self, enrollment_id: str, *, owner_attested: bool
    ) -> EnrollmentRecord:
        """Activate a local-source enrollment without creating a companion key."""
        if owner_attested is not True:
            raise DeviceLabError("authorization_required", "local enrollment requires attestation")
        now = self._now()
        with self._lock:
            pending = self._pending.pop(enrollment_id, None)
            if pending is None:
                raise DeviceLabError("challenge", "challenge is unknown, expired, or already used")
            challenge = pending.challenge
            if challenge.evidence_source != "local":
                raise DeviceLabError("source", "agent enrollment requires Ed25519 confirmation")
            if now >= challenge.expires_at:
                raise DeviceLabError("expired", "enrollment challenge has expired")
            unsigned = {
                "enrollment_id": enrollment_id,
                "label": pending.label,
                "label_token": challenge.label_token,
                "evidence_source": "local",
                "allowed_connections": list(challenge.allowed_connections),
                "owner_attested_at": challenge.issued_at,
                "enrolled_at": now,
                "status": "active",
                "public_key_fingerprint": "",
                "last_sequence": -1,
            }
            authenticator = self._record_authenticator(unsigned, "")
            record = EnrollmentRecord(**unsigned, authenticator=authenticator)
            self._records[enrollment_id] = record
            self._public_keys[enrollment_id] = ""
            self._append_audit(
                "enrollment_confirm", "accepted", challenge.label_token, "local_authenticated"
            )
            self._save_state()
            return record

    def list_enrollments(self) -> tuple[EnrollmentRecord, ...]:
        with self._lock:
            return tuple(sorted(self._records.values(), key=lambda item: item.enrolled_at or 0))

    def audit_log(self) -> tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(self._audit)

    def sign_evidence(
        self,
        enrollment_id: str,
        observations: Sequence[ConnectionObservation],
        private_key: object,
        *,
        sequence: int,
        issued_at: int | None = None,
    ) -> EvidenceEnvelope:
        """Agent-side helper for a bounded, authenticated evidence document."""
        signer = _private_key(private_key)
        normalized = self._normalize_observations(observations)
        now = self._now() if issued_at is None else issued_at
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise DeviceLabError("time", "issued_at must be an integer epoch")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence < 2**63:
            raise DeviceLabError("sequence", "evidence sequence is outside its bound")
        unsigned = EvidenceEnvelope(
            enrollment_id=enrollment_id,
            sequence=sequence,
            issued_at=now,
            expires_at=now + self._evidence_age_s,
            observations=normalized,
            signature_ed25519=_b64(b"\0" * 64),
        )
        signature = _b64(signer.sign(_canonical(unsigned.payload_dict())))
        result = EvidenceEnvelope(**{**unsigned.__dict__, "signature_ed25519": signature})
        if len(_canonical(result.to_dict())) > MAX_EVIDENCE_BYTES:
            raise DeviceLabError("size", "evidence exceeds its byte bound")
        return result

    def assess(
        self,
        enrollment_id: str,
        observations: Sequence[ConnectionObservation],
        *,
        evidence: EvidenceEnvelope | Mapping[str, object] | None = None,
    ) -> AssessmentReport:
        normalized = self._normalize_observations(observations)
        now = self._now()
        with self._lock:
            record = self._active_record(enrollment_id)
            self._validate_scope_and_time(record, normalized, now)
            if record.evidence_source == "enrolled_agent":
                if evidence is None:
                    raise DeviceLabError("authentication_required", "signed agent evidence is required")
                envelope = (
                    evidence if isinstance(evidence, EvidenceEnvelope) else EvidenceEnvelope.from_dict(evidence)
                )
                self._verify_evidence(record, normalized, envelope, now)
                record = EnrollmentRecord(
                    **{**record.__dict__, "last_sequence": envelope.sequence, "authenticator": ""}
                )
                public_key = self._public_keys[enrollment_id]
                unsigned = self._record_unsigned(record)
                record = EnrollmentRecord(
                    **{**unsigned, "authenticator": self._record_authenticator(unsigned, public_key)}
                )
                self._records[enrollment_id] = record
            elif evidence is not None:
                raise DeviceLabError("source", "local evidence must not carry an agent envelope")

            findings, unsupported = self._evaluate(normalized)
            outcome = self._outcome(findings, unsupported)
            report = AssessmentReport(
                assessment_id=f"assessment-{secrets.token_hex(10)}",
                enrollment_id=enrollment_id,
                target_token=record.label_token,
                generated_at=now,
                outcome=outcome,
                findings=tuple(findings),
                observation_count=len(normalized),
                unsupported_connections=tuple(sorted(unsupported)),
                limitations=(
                    "Passive configuration evidence only; no exploitability claim is made.",
                    "No packets, credentials, commands, payloads, or response actions are sent.",
                    "Physical interfaces reported as unsupported require operator verification.",
                ),
            )
            self._append_audit("assessment", "accepted", record.label_token, outcome)
            self._save_state()
            return report

    def collect_local_observations(
        self, enrollment_id: str, *, owner_attested: bool
    ) -> tuple[ConnectionObservation, ...]:
        """Collect bounded local-only metadata without probing any peer or address."""
        if owner_attested is not True:
            raise DeviceLabError("authorization_required", "local inspection requires attestation")
        with self._lock:
            record = self._active_record(enrollment_id)
            if record.evidence_source != "local":
                raise DeviceLabError("source", "this enrollment is not scoped to local collection")

        completed = queue.Queue(maxsize=1)

        def collect() -> None:
            try:
                completed.put((True, self._local_snapshot()), block=False)
            except Exception as exc:  # defensive boundary: return partial/unsupported, never crash UI
                completed.put((False, exc), block=False)

        worker = threading.Thread(target=collect, name="angerona-device-lab-passive", daemon=True)
        worker.start()
        worker.join(MAX_COLLECTION_TIMEOUT_SECONDS)
        if worker.is_alive():
            raise DeviceLabError("timeout", "passive local collection exceeded its time bound")
        try:
            ok, value = completed.get_nowait()
        except queue.Empty as exc:
            raise DeviceLabError("collection", "passive local collection returned no result") from exc
        if not ok:
            raise DeviceLabError("collection", "passive local collection failed safely") from value
        observations = tuple(
            item for item in value if item.connection.value in record.allowed_connections
        )
        with self._lock:
            self._append_audit(
                "local_collection", "accepted", record.label_token, f"observations={len(observations)}"
            )
            self._save_state()
        return observations

    def _local_snapshot(self) -> tuple[ConnectionObservation, ...]:
        now = self._now()
        ethernet_count = ethernet_up = wifi_count = wifi_up = 0
        listening_ports: list[int] = []
        try:
            import psutil

            stats = psutil.net_if_stats()
            if len(stats) > 64:
                stats = dict(list(stats.items())[:64])
            for name, status in stats.items():
                wireless = bool(re.search(r"(?i)(wi-?fi|wlan|wireless|^wl)", name))
                if wireless:
                    wifi_count += 1
                    wifi_up += int(bool(status.isup))
                else:
                    ethernet_count += 1
                    ethernet_up += int(bool(status.isup))
            for connection in psutil.net_connections(kind="inet"):
                if str(connection.status).upper() != "LISTEN":
                    continue
                port = getattr(connection.laddr, "port", None)
                if isinstance(port, int) and 1 <= port <= 65535:
                    listening_ports.append(port)
                    if len(set(listening_ports)) >= MAX_LISTENING_PORTS:
                        break
        except (ImportError, OSError, RuntimeError):
            pass

        display_count: int | None = None
        if os.name == "nt":
            try:
                import ctypes

                display_count = max(0, min(64, int(ctypes.windll.user32.GetSystemMetrics(80))))
            except (AttributeError, OSError, ValueError):
                display_count = None

        common = {"software_version_status": "unknown", "configuration_baseline": "unknown"}
        return (
            ConnectionObservation(
                ConnectionKind.ETHERNET,
                "local",
                now,
                {
                    **common,
                    "supported": True,
                    "present": ethernet_count > 0,
                    "interface_count": ethernet_count,
                    "up_count": ethernet_up,
                    "listening_ports": sorted(set(listening_ports)),
                    "network_profile": "unknown",
                },
            ),
            ConnectionObservation(
                ConnectionKind.WIFI,
                "local",
                now,
                {
                    **common,
                    "supported": True,
                    "present": wifi_count > 0,
                    "interface_count": wifi_count,
                    "up_count": wifi_up,
                    "security_protocol": "unknown",
                },
            ),
            ConnectionObservation(
                ConnectionKind.USB,
                "local",
                now,
                {**common, "supported": False, "present": False},
            ),
            ConnectionObservation(
                ConnectionKind.BLUETOOTH,
                "local",
                now,
                {**common, "supported": False, "present": False},
            ),
            ConnectionObservation(
                ConnectionKind.DISPLAY_HDMI,
                "local",
                now,
                {
                    **common,
                    "supported": display_count is not None,
                    "present": bool(display_count),
                    **({"connected_count": display_count} if display_count is not None else {}),
                    "hdcp_status": "unknown",
                },
            ),
        )

    def _normalize_observations(
        self, observations: Sequence[ConnectionObservation]
    ) -> tuple[ConnectionObservation, ...]:
        if isinstance(observations, (str, bytes, bytearray)) or not isinstance(
            observations, Sequence
        ):
            raise DeviceLabError("schema", "observations must be a bounded sequence")
        if not observations or len(observations) > MAX_OBSERVATIONS:
            raise DeviceLabError("cardinality", "observation count exceeds its bound")
        result = tuple(
            item
            if isinstance(item, ConnectionObservation)
            else ConnectionObservation.from_dict(item)
            for item in observations
        )
        if len(_canonical([item.to_dict() for item in result])) > MAX_EVIDENCE_BYTES:
            raise DeviceLabError("size", "observations exceed their byte bound")
        return result

    def _active_record(self, enrollment_id: str) -> EnrollmentRecord:
        if not isinstance(enrollment_id, str) or not _SAFE_TOKEN.fullmatch(enrollment_id):
            raise DeviceLabError("enrollment", "enrollment identifier is invalid")
        record = self._records.get(enrollment_id)
        if record is None or record.status != "active":
            raise DeviceLabError("enrollment", "active enrollment is required")
        return record

    def _validate_scope_and_time(
        self, record: EnrollmentRecord, observations: tuple[ConnectionObservation, ...], now: int
    ) -> None:
        for item in observations:
            if item.connection.value not in record.allowed_connections:
                raise DeviceLabError("scope", "observation is outside the enrolled connection scope")
            if item.source != record.evidence_source:
                raise DeviceLabError("source", "observation source does not match enrollment")
            if item.observed_at > now + self._future_skew_s:
                raise DeviceLabError("future_clock", "observation timestamp is in the future")
            if now - item.observed_at > self._evidence_age_s:
                raise DeviceLabError("stale", "observation is outside the freshness window")

    def _verify_evidence(
        self,
        record: EnrollmentRecord,
        observations: tuple[ConnectionObservation, ...],
        envelope: EvidenceEnvelope,
        now: int,
    ) -> None:
        if len(_canonical(envelope.to_dict())) > MAX_EVIDENCE_BYTES:
            raise DeviceLabError("size", "evidence exceeds its byte bound")
        if envelope.enrollment_id != record.enrollment_id:
            raise DeviceLabError("scope", "evidence is for another enrollment")
        if envelope.observations != observations:
            raise DeviceLabError("forgery", "evidence observations do not match the assessment")
        if isinstance(envelope.sequence, bool) or not isinstance(envelope.sequence, int):
            raise DeviceLabError("sequence", "evidence sequence is invalid")
        if not 0 <= envelope.sequence < 2**63 or envelope.sequence <= record.last_sequence:
            raise DeviceLabError("replay", "evidence sequence was replayed or regressed")
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (envelope.issued_at, envelope.expires_at)
        ):
            raise DeviceLabError("time", "evidence timestamps are invalid")
        if envelope.expires_at <= envelope.issued_at:
            raise DeviceLabError("time", "evidence lifetime is invalid")
        if envelope.expires_at - envelope.issued_at > self._evidence_age_s:
            raise DeviceLabError("time", "evidence lifetime exceeds its bound")
        if envelope.issued_at > now + self._future_skew_s:
            raise DeviceLabError("future_clock", "evidence timestamp is in the future")
        if now >= envelope.expires_at or now - envelope.issued_at > self._evidence_age_s:
            raise DeviceLabError("stale", "evidence is stale")
        verifier, _ = _public_key(self._public_keys[record.enrollment_id])
        try:
            verifier.verify(
                _signature(envelope.signature_ed25519), _canonical(envelope.payload_dict())
            )
        except InvalidSignature as exc:
            raise DeviceLabError("forgery", "evidence did not authenticate") from exc

    def _evaluate(
        self, observations: tuple[ConnectionObservation, ...]
    ) -> tuple[list[SecurityFinding], set[str]]:
        findings: list[SecurityFinding] = []
        unsupported: set[str] = set()
        for item in observations:
            kind = item.connection.value
            attrs = item.attributes
            if attrs.get("supported") is False:
                unsupported.add(kind)
                continue
            if attrs.get("software_version_status") == "outdated":
                findings.append(self._finding(kind, "high", "outdated_software"))
            if attrs.get("configuration_baseline") == "noncompliant":
                findings.append(self._finding(kind, "medium", "baseline_drift"))
            if kind in {"ethernet", "wifi"} and attrs.get("firewall_enabled") is False:
                findings.append(self._finding(kind, "high", "firewall_disabled"))
            if kind == "ethernet":
                ports = set(attrs.get("listening_ports", []))
                if ports & {23, 135, 139, 445, 3389, 5900}:
                    findings.append(self._finding(kind, "medium", "sensitive_listener"))
                if len(ports) > 32:
                    findings.append(self._finding(kind, "low", "broad_listener_surface"))
                if attrs.get("ieee8021x_enabled") is False:
                    findings.append(self._finding(kind, "low", "no_port_access_control"))
            elif kind == "wifi":
                protocol = attrs.get("security_protocol")
                if protocol in {"open", "wep"}:
                    findings.append(self._finding(kind, "critical", "weak_wireless_security"))
                elif protocol == "wpa":
                    findings.append(self._finding(kind, "high", "legacy_wireless_security"))
                if attrs.get("randomized_mac") is False:
                    findings.append(self._finding(kind, "low", "mac_randomization_disabled"))
                if attrs.get("hotspot_enabled") is True:
                    findings.append(self._finding(kind, "medium", "hotspot_enabled"))
            elif kind == "bluetooth":
                if attrs.get("discoverable") is True:
                    findings.append(self._finding(kind, "high", "bluetooth_discoverable"))
                if attrs.get("legacy_pairing_allowed") is True:
                    findings.append(self._finding(kind, "medium", "legacy_pairing"))
            elif kind == "usb":
                if attrs.get("autorun_enabled") is True:
                    findings.append(self._finding(kind, "high", "usb_autorun"))
                if attrs.get("device_control_policy") == "unrestricted":
                    findings.append(self._finding(kind, "medium", "unrestricted_usb"))
                if attrs.get("unsigned_driver_present") is True:
                    findings.append(self._finding(kind, "high", "unsigned_usb_driver"))
            elif kind == "display_hdmi":
                if attrs.get("data_channel_enabled") is True:
                    findings.append(self._finding(kind, "low", "display_data_channel"))
                if attrs.get("cec_enabled") is True:
                    findings.append(self._finding(kind, "low", "cec_enabled"))
        findings.sort(key=lambda item: (_SEVERITIES.index(item.severity), item.finding_id))
        return findings, unsupported

    @staticmethod
    def _outcome(findings: Sequence[SecurityFinding], unsupported: set[str]) -> str:
        if any(item.severity in {"critical", "high"} for item in findings):
            return "needs_attention"
        if findings:
            return "review_recommended"
        if unsupported:
            return "incomplete"
        return "pass"

    @staticmethod
    def _finding(connection: str, severity: str, code: str) -> SecurityFinding:
        guidance = {
            "outdated_software": (
                "Outdated device or interface software",
                "The enrolled evidence reports an outdated software or firmware posture.",
                "Use the vendor's signed update channel during a maintenance window.",
                "Verify the package signature, install the supported release, reboot if required, and reassess.",
                ("Review vendor advisory", "Schedule signed update", "Reassess"),
            ),
            "baseline_drift": (
                "Configuration differs from the approved baseline",
                "The enrolled agent reports a noncompliant configuration baseline.",
                "Review the changed settings against the organization's approved baseline.",
                "Export the current configuration, apply the approved policy, then collect fresh evidence.",
                ("Review drift", "Apply approved policy", "Reassess"),
            ),
            "firewall_disabled": (
                "Host firewall is disabled",
                "The passive posture record reports that the firewall is not enabled.",
                "Enable the platform firewall with an explicit deny-by-default inbound policy.",
                "Apply a tested firewall policy through the operating system or device management console.",
                ("Disconnect untrusted link", "Enable firewall", "Validate required services"),
            ),
            "sensitive_listener": (
                "Administrative service is listening locally",
                "One or more commonly administrative ports are in the local listening configuration.",
                "Confirm business need and restrict the service to trusted management boundaries.",
                "Disable unused services or add a scoped firewall rule; do not expose management services publicly.",
                ("Review service ownership", "Restrict firewall scope", "Disable if unused"),
            ),
            "broad_listener_surface": (
                "Broad local listening surface",
                "More than 32 unique local ports are listening.",
                "Inventory required services and remove unnecessary listeners.",
                "Use service management and firewall policy to reduce exposure, then reassess.",
                ("Inventory listeners", "Reduce services", "Reassess"),
            ),
            "no_port_access_control": (
                "Wired port access control is not enabled",
                "The enrolled configuration reports that IEEE 802.1X is disabled.",
                "Consider authenticated network access for managed environments.",
                "Deploy 802.1X in a staged policy with recovery access and certificate lifecycle planning.",
                ("Assess 802.1X readiness", "Pilot policy", "Monitor"),
            ),
            "weak_wireless_security": (
                "Wireless encryption is unsafe",
                "The enrolled configuration reports an open or WEP-protected wireless link.",
                "Disconnect from the link and use WPA2-AES or WPA3 with a unique credential.",
                "Update access-point firmware and replace the wireless security policy through its authorized console.",
                ("Disconnect", "Use a trusted network", "Upgrade wireless policy"),
            ),
            "legacy_wireless_security": (
                "Legacy WPA configuration",
                "The enrolled configuration reports first-generation WPA.",
                "Migrate to WPA2-AES or WPA3 and retire legacy compatibility.",
                "Apply supported access-point firmware and rotate the wireless credential after migration.",
                ("Plan migration", "Update firmware", "Rotate credential"),
            ),
            "mac_randomization_disabled": (
                "Wireless privacy randomization is disabled",
                "The enrolled configuration reports a stable hardware address for wireless discovery.",
                "Enable per-network address randomization where device management permits it.",
                "Apply the platform privacy setting and verify required enterprise authentication still works.",
                ("Review privacy policy", "Enable randomization", "Validate connectivity"),
            ),
            "hotspot_enabled": (
                "Local wireless hotspot is enabled",
                "The enrolled configuration reports an active hotspot function.",
                "Disable hotspot sharing unless it is explicitly approved and managed.",
                "Turn off connection sharing through the platform settings and reassess.",
                ("Confirm authorization", "Disable sharing", "Monitor"),
            ),
            "bluetooth_discoverable": (
                "Bluetooth is discoverable",
                "The enrolled configuration reports discoverable mode.",
                "Disable discoverability except during an attended pairing window.",
                "Use platform Bluetooth settings, remove unknown pairings, and update device firmware.",
                ("Disable discoverability", "Review pairings", "Update firmware"),
            ),
            "legacy_pairing": (
                "Legacy Bluetooth pairing is allowed",
                "The enrolled configuration permits a legacy pairing mode.",
                "Require authenticated secure pairing and remove devices that cannot support it.",
                "Update host and peripheral firmware before enforcing the stronger pairing policy.",
                ("Review paired devices", "Update firmware", "Require secure pairing"),
            ),
            "usb_autorun": (
                "USB AutoRun is enabled",
                "The enrolled configuration allows automatic content handling for removable media.",
                "Disable AutoRun and require deliberate, scanned file access.",
                "Apply the operating-system removable-media policy and verify it with benign media.",
                ("Eject unknown media", "Disable AutoRun", "Scan approved media"),
            ),
            "unrestricted_usb": (
                "USB device control is unrestricted",
                "The enrolled configuration has no allowlist or block policy for USB devices.",
                "Adopt a least-privilege device policy appropriate to the user's workflow.",
                "Pilot an allowlist for approved device classes and maintain a recovery procedure.",
                ("Inventory approved devices", "Pilot allowlist", "Monitor exceptions"),
            ),
            "unsigned_usb_driver": (
                "Unsigned device driver reported",
                "The enrolled evidence reports an unsigned driver associated with a USB device.",
                "Disconnect the device until a signed, supported driver is available.",
                "Remove the unsupported driver and install only a signature-verified vendor package.",
                ("Disconnect device", "Remove driver", "Install signed package"),
            ),
            "display_data_channel": (
                "Display data channel is enabled",
                "The enrolled configuration reports an auxiliary data channel on the display link.",
                "Disable unused display-link data features in sensitive environments.",
                "Use the authorized device settings to disable the feature and verify display operation.",
                ("Review need", "Disable unused channel", "Reassess"),
            ),
            "cec_enabled": (
                "HDMI-CEC control is enabled",
                "The enrolled configuration reports cross-device HDMI control.",
                "Disable CEC where cross-device control is not required.",
                "Apply the display or source-device setting and verify expected power/input behavior.",
                ("Review need", "Disable CEC", "Validate display"),
            ),
        }
        title, evidence, remediation, patch, responses = guidance[code]
        return SecurityFinding(
            finding_id=f"dsl-{connection}-{code}",
            severity=severity,
            connection=connection,
            title=title,
            evidence=evidence,
            remediation=remediation,
            patch_guidance=patch,
            response_options=responses,
        )

    def _record_unsigned(self, record: EnrollmentRecord) -> dict[str, object]:
        value = record.to_dict()
        value.pop("authenticator")
        return value

    def _record_authenticator(self, unsigned: Mapping[str, object], public_key: str) -> str:
        return hmac.new(
            self._authority,
            _canonical({"record": dict(unsigned), "public_key_ed25519": public_key}),
            hashlib.sha256,
        ).hexdigest()

    def _append_audit(
        self, action: str, status: str, subject_token: str, detail: str
    ) -> None:
        unsigned = {
            "event_id": f"audit-{secrets.token_hex(10)}",
            "occurred_at": self._now(),
            "action": action,
            "status": status,
            "subject_token": subject_token,
            "detail": detail,
        }
        signature = hmac.new(self._authority, _canonical(unsigned), hashlib.sha256).hexdigest()
        self._audit.append(AuditRecord(**unsigned, authenticator=signature))
        if len(self._audit) > MAX_AUDIT_RECORDS:
            del self._audit[: len(self._audit) - MAX_AUDIT_RECORDS]

    def _purge_expired_pending(self, now: int) -> None:
        expired = [
            key for key, item in self._pending.items() if now >= item.challenge.expires_at
        ]
        for key in expired:
            del self._pending[key]

    @property
    def _state_path(self) -> Path:
        return self.root / self._STATE_FILENAME

    def _save_state(self) -> None:
        records = []
        for enrollment_id, record in sorted(self._records.items()):
            records.append(
                {"record": record.to_dict(), "public_key_ed25519": self._public_keys[enrollment_id]}
            )
        payload = {
            "format": STATE_FORMAT,
            "records": records,
            "audit": [item.to_dict() for item in self._audit],
        }
        encoded = _canonical(payload)
        if len(encoded) > MAX_STATE_BYTES:
            raise DeviceLabError("size", "device-lab state exceeds its byte bound")
        self.root.mkdir(parents=True, exist_ok=True)
        descriptor: int | None = None
        temporary: Path | None = None
        try:
            for _ in range(16):
                candidate = self._state_path.with_name(
                    f".{self._state_path.name}.{secrets.token_hex(8)}.tmp"
                )
                try:
                    descriptor = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                        0o600,
                    )
                    temporary = candidate
                    break
                except FileExistsError:
                    continue
            if descriptor is None or temporary is None:
                raise DeviceLabError("storage", "could not allocate a private state file")
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._state_path)
            try:
                os.chmod(self._state_path, 0o600)
            except OSError:
                pass
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    def _load_state(self) -> None:
        if not self._state_path.exists():
            return
        try:
            if self._state_path.stat().st_size > MAX_STATE_BYTES:
                raise DeviceLabError("size", "device-lab state exceeds its byte bound")
            raw = self._state_path.read_bytes()
            value = json.loads(raw.decode("utf-8"))
        except DeviceLabError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise DeviceLabError("storage", "device-lab state is unreadable") from exc
        if not isinstance(value, Mapping) or frozenset(value) != {"format", "records", "audit"}:
            raise DeviceLabError("schema", "device-lab state schema is invalid")
        if value["format"] != STATE_FORMAT:
            raise DeviceLabError("version", "unsupported device-lab state format")
        records = value["records"]
        audits = value["audit"]
        if not isinstance(records, list) or len(records) > MAX_ENROLLMENTS:
            raise DeviceLabError("cardinality", "stored enrollment count exceeds its bound")
        if not isinstance(audits, list) or len(audits) > MAX_AUDIT_RECORDS:
            raise DeviceLabError("cardinality", "stored audit count exceeds its bound")
        for wrapper in records:
            record, public_key = self._decode_record(wrapper)
            if record.enrollment_id in self._records:
                raise DeviceLabError("schema", "duplicate enrollment identifier")
            if record.evidence_source == "enrolled_agent":
                _, raw_public = _public_key(public_key)
                if hashlib.sha256(raw_public).hexdigest() != record.public_key_fingerprint:
                    raise DeviceLabError("forgery", "stored public-key fingerprint is invalid")
            elif public_key or record.public_key_fingerprint:
                raise DeviceLabError("schema", "local enrollment must not contain an agent key")
            self._records[record.enrollment_id] = record
            self._public_keys[record.enrollment_id] = public_key
        for raw_audit in audits:
            self._audit.append(self._decode_audit(raw_audit))

    def _decode_record(self, wrapper: object) -> tuple[EnrollmentRecord, str]:
        if not isinstance(wrapper, Mapping) or frozenset(wrapper) != {
            "record", "public_key_ed25519"
        }:
            raise DeviceLabError("schema", "stored enrollment wrapper is invalid")
        raw = wrapper["record"]
        public_key = wrapper["public_key_ed25519"]
        if not isinstance(raw, Mapping) or frozenset(raw) != {
            "enrollment_id", "label", "label_token", "evidence_source", "allowed_connections",
            "owner_attested_at", "enrolled_at", "status", "public_key_fingerprint",
            "authenticator", "last_sequence",
        }:
            raise DeviceLabError("schema", "stored enrollment record is invalid")
        if not isinstance(public_key, str):
            raise DeviceLabError("schema", "stored public key is invalid")
        try:
            allowed = tuple(raw["allowed_connections"])
            record = EnrollmentRecord(
                enrollment_id=raw["enrollment_id"],
                label=raw["label"],
                label_token=raw["label_token"],
                evidence_source=raw["evidence_source"],
                allowed_connections=allowed,
                owner_attested_at=raw["owner_attested_at"],
                enrolled_at=raw["enrolled_at"],
                status=raw["status"],
                public_key_fingerprint=raw["public_key_fingerprint"],
                authenticator=raw["authenticator"],
                last_sequence=raw["last_sequence"],
            )
        except (KeyError, TypeError) as exc:
            raise DeviceLabError("schema", "stored enrollment record is invalid") from exc
        self._validate_loaded_record(record)
        expected = self._record_authenticator(self._record_unsigned(record), public_key)
        if not hmac.compare_digest(expected, record.authenticator):
            raise DeviceLabError("forgery", "stored enrollment record did not authenticate")
        return record, public_key

    @staticmethod
    def _validate_loaded_record(record: EnrollmentRecord) -> None:
        if not _SAFE_TOKEN.fullmatch(record.enrollment_id):
            raise DeviceLabError("schema", "stored enrollment identifier is invalid")
        if not isinstance(record.label, str) or not _SAFE_LABEL.fullmatch(record.label):
            raise DeviceLabError("schema", "stored label is invalid")
        if record.label_token != _redacted_label_token(record.label):
            raise DeviceLabError("forgery", "stored label token is invalid")
        if record.evidence_source not in _EVIDENCE_SOURCES or record.status != "active":
            raise DeviceLabError("schema", "stored enrollment status is invalid")
        if not isinstance(record.public_key_fingerprint, str) or (
            record.public_key_fingerprint and not _HEX_64.fullmatch(record.public_key_fingerprint)
        ):
            raise DeviceLabError("schema", "stored public-key fingerprint is invalid")
        if not record.allowed_connections or any(
            value not in {item.value for item in ConnectionKind}
            for value in record.allowed_connections
        ):
            raise DeviceLabError("schema", "stored connection scope is invalid")
        if (
            isinstance(record.owner_attested_at, bool)
            or not isinstance(record.owner_attested_at, int)
            or isinstance(record.enrolled_at, bool)
            or not isinstance(record.enrolled_at, int)
            or isinstance(record.last_sequence, bool)
            or not isinstance(record.last_sequence, int)
            or record.last_sequence < -1
        ):
            raise DeviceLabError("schema", "stored enrollment counters are invalid")
        if not isinstance(record.authenticator, str) or not _HEX_64.fullmatch(record.authenticator):
            raise DeviceLabError("schema", "stored record authenticator is invalid")

    def _decode_audit(self, raw: object) -> AuditRecord:
        if not isinstance(raw, Mapping) or frozenset(raw) != {
            "event_id", "occurred_at", "action", "status", "subject_token", "detail",
            "authenticator",
        }:
            raise DeviceLabError("schema", "stored audit record is invalid")
        try:
            audit = AuditRecord(**raw)
            unsigned = audit.to_dict()
            signature = unsigned.pop("authenticator")
            expected = hmac.new(self._authority, _canonical(unsigned), hashlib.sha256).hexdigest()
            if not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
                raise DeviceLabError("forgery", "stored audit record did not authenticate")
            if not _SAFE_TOKEN.fullmatch(audit.event_id) or not _SAFE_TOKEN.fullmatch(
                audit.subject_token
            ):
                raise DeviceLabError("schema", "stored audit token is invalid")
            if len(audit.detail) > 64 or len(audit.action) > 32 or len(audit.status) > 16:
                raise DeviceLabError("bounds", "stored audit text exceeds its bound")
            return audit
        except TypeError as exc:
            raise DeviceLabError("schema", "stored audit record is invalid") from exc


__all__ = [
    "AssessmentReport",
    "AuditRecord",
    "ConnectionKind",
    "ConnectionObservation",
    "DeviceLabError",
    "DeviceSecurityLab",
    "EnrollmentChallenge",
    "EnrollmentRecord",
    "EvidenceEnvelope",
    "SecurityFinding",
]
