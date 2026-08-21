"""Bounded, privacy-minimal sensor visibility attestations.

The document defined here is a software HMAC assertion from a sensor that has
been provisioned with the same authority.  It reports only continuity metadata;
it carries no raw telemetry and is not proof that native code, a kernel sensor,
or hardware-backed identity is present.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Mapping, Optional


FORMAT = "angerona-visibility-attestation-v1"
MAX_DOCUMENT_BYTES = 8 * 1024
MAX_SENSOR_ID_CHARS = 64
MAX_CANARY_FAMILIES = 32
MAX_CANARY_FAMILY_CHARS = 48
MAX_COUNTER = (1 << 63) - 1
MAX_TTL_SECONDS = 600
DEFAULT_FUTURE_SKEW_SECONDS = 30

_PLATFORMS = frozenset({"windows", "macos", "linux", "unknown"})
_CLOCK_QUALITIES = frozenset({"synchronized", "estimated", "unknown", "unreliable"})
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SAFE_CANARY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")

_PAYLOAD_FIELDS = frozenset(
    {
        "format",
        "sensor_id",
        "platform",
        "build_sha256",
        "policy_sha256",
        "session_epoch",
        "sequence",
        "expected_canary_families",
        "observed_canary_families",
        "drop_count",
        "issued_at",
        "expires_at",
        "clock_quality",
    }
)
_WRAPPER_FIELDS = frozenset({"payload", "hmac_sha256"})


class VisibilityAttestationError(ValueError):
    """A visibility document failed its bounded trust contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class VisibilityAssessment:
    sensor_id: str
    classification: str
    accepted: bool
    reason: str
    platform: str = "unknown"
    build_sha256: str = ""
    policy_sha256: str = ""
    session_epoch: Optional[int] = None
    sequence: Optional[int] = None
    expected_canary_families: tuple[str, ...] = ()
    observed_canary_families: tuple[str, ...] = ()
    missing_canary_families: tuple[str, ...] = ()
    drop_count: Optional[int] = None
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None
    clock_quality: str = "unknown"
    received_at: Optional[float] = None


@dataclass
class _SensorState:
    assessment: VisibilityAssessment
    session_epoch: int
    sequence: int
    drop_count: int
    issued_at: int


def _canonical(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise VisibilityAttestationError("schema", "document is not canonical JSON") from exc


def _require_authority(authority: bytes) -> bytes:
    if not isinstance(authority, (bytes, bytearray, memoryview)):
        raise TypeError("HMAC authority must be bytes")
    value = bytes(authority)
    if len(value) < 32:
        raise ValueError("HMAC authority must contain at least 32 bytes")
    return value


def _bounded_integer(payload: Mapping[str, object], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise VisibilityAttestationError("schema", f"{field} must be an integer")
    if value < 0 or value > MAX_COUNTER:
        raise VisibilityAttestationError("bounds", f"{field} is outside its bound")
    return value


def _canary_families(payload: Mapping[str, object], field: str) -> tuple[str, ...]:
    raw = payload.get(field)
    if not isinstance(raw, list) or len(raw) > MAX_CANARY_FAMILIES:
        raise VisibilityAttestationError("cardinality", f"{field} exceeds its bound")
    if field == "expected_canary_families" and not raw:
        raise VisibilityAttestationError("cardinality", "at least one canary family is required")
    result: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not _SAFE_CANARY.fullmatch(item):
            raise VisibilityAttestationError("privacy", f"{field} contains an unsafe identifier")
        result.append(item)
    if len(set(result)) != len(result) or result != sorted(result):
        raise VisibilityAttestationError(
            "canonical", f"{field} must contain unique, sorted identifiers"
        )
    return tuple(result)


def validate_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Return a normalized payload or reject any extra/privacy-bearing field."""
    if not isinstance(payload, Mapping) or frozenset(payload) != _PAYLOAD_FIELDS:
        raise VisibilityAttestationError("schema", "payload fields do not match the v1 schema")
    if payload.get("format") != FORMAT:
        raise VisibilityAttestationError("version", "unsupported visibility attestation format")

    sensor_id = payload.get("sensor_id")
    if (
        not isinstance(sensor_id, str)
        or len(sensor_id) > MAX_SENSOR_ID_CHARS
        or not _SAFE_IDENTIFIER.fullmatch(sensor_id)
    ):
        raise VisibilityAttestationError("privacy", "sensor_id is not a safe identifier")
    platform = payload.get("platform")
    if platform not in _PLATFORMS:
        raise VisibilityAttestationError("schema", "platform is not recognized")
    build_sha256 = payload.get("build_sha256")
    policy_sha256 = payload.get("policy_sha256")
    if not isinstance(build_sha256, str) or not _SHA256.fullmatch(build_sha256):
        raise VisibilityAttestationError("schema", "build_sha256 must be lowercase SHA-256")
    if not isinstance(policy_sha256, str) or not _SHA256.fullmatch(policy_sha256):
        raise VisibilityAttestationError("schema", "policy_sha256 must be lowercase SHA-256")

    session_epoch = _bounded_integer(payload, "session_epoch")
    sequence = _bounded_integer(payload, "sequence")
    drop_count = _bounded_integer(payload, "drop_count")
    issued_at = _bounded_integer(payload, "issued_at")
    expires_at = _bounded_integer(payload, "expires_at")
    if expires_at <= issued_at or expires_at - issued_at > MAX_TTL_SECONDS:
        raise VisibilityAttestationError("time", "attestation lifetime is invalid")

    expected = _canary_families(payload, "expected_canary_families")
    observed = _canary_families(payload, "observed_canary_families")
    if not set(observed).issubset(expected):
        raise VisibilityAttestationError("schema", "observed canaries must be expected")
    clock_quality = payload.get("clock_quality")
    if clock_quality not in _CLOCK_QUALITIES:
        raise VisibilityAttestationError("schema", "clock_quality is not recognized")

    normalized = {
        "format": FORMAT,
        "sensor_id": sensor_id,
        "platform": platform,
        "build_sha256": build_sha256,
        "policy_sha256": policy_sha256,
        "session_epoch": session_epoch,
        "sequence": sequence,
        "expected_canary_families": list(expected),
        "observed_canary_families": list(observed),
        "drop_count": drop_count,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "clock_quality": clock_quality,
    }
    if len(_canonical(normalized)) > MAX_DOCUMENT_BYTES:
        raise VisibilityAttestationError("size", "payload exceeds its byte bound")
    return normalized


def sign_visibility_attestation(
    payload: Mapping[str, object], authority: bytes
) -> dict[str, object]:
    """Sign a canonical v1 payload with an explicitly supplied authority."""
    key = _require_authority(authority)
    normalized = validate_payload(payload)
    signature = hmac.new(key, _canonical(normalized), hashlib.sha256).hexdigest()
    document: dict[str, object] = {"payload": normalized, "hmac_sha256": signature}
    if len(_canonical(document)) > MAX_DOCUMENT_BYTES:
        raise VisibilityAttestationError("size", "attestation exceeds its byte bound")
    return document


def _decode_document(document: object) -> Mapping[str, object]:
    if isinstance(document, str):
        encoded = document.encode("utf-8")
    elif isinstance(document, (bytes, bytearray, memoryview)):
        encoded = bytes(document)
    elif isinstance(document, Mapping):
        encoded = _canonical(document)
        if len(encoded) > MAX_DOCUMENT_BYTES:
            raise VisibilityAttestationError("size", "attestation exceeds its byte bound")
        return document
    else:
        raise VisibilityAttestationError("schema", "attestation must be JSON or a mapping")
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise VisibilityAttestationError("size", "attestation exceeds its byte bound")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise VisibilityAttestationError("schema", "duplicate JSON field")
            result[key] = value
        return result

    try:
        value = json.loads(encoded.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VisibilityAttestationError("schema", "attestation is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise VisibilityAttestationError("schema", "attestation wrapper must be an object")
    return value


def _verified_payload(document: object, authority: bytes) -> dict[str, object]:
    wrapper = _decode_document(document)
    if frozenset(wrapper) != _WRAPPER_FIELDS:
        raise VisibilityAttestationError("schema", "wrapper fields do not match the v1 schema")
    payload = wrapper.get("payload")
    if not isinstance(payload, Mapping):
        raise VisibilityAttestationError("schema", "payload must be an object")
    normalized = validate_payload(payload)
    signature = wrapper.get("hmac_sha256")
    if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
        raise VisibilityAttestationError("forgery", "attestation HMAC is invalid")
    expected = hmac.new(authority, _canonical(normalized), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise VisibilityAttestationError("forgery", "attestation HMAC is invalid")
    return normalized


def _assessment(
    payload: Mapping[str, object],
    *,
    now: float,
    accepted: bool = True,
    forced_classification: Optional[str] = None,
    forced_reason: Optional[str] = None,
) -> VisibilityAssessment:
    expected = tuple(payload["expected_canary_families"])
    observed = tuple(payload["observed_canary_families"])
    missing = tuple(sorted(set(expected) - set(observed)))
    if forced_classification is not None:
        classification = forced_classification
        reason = forced_reason or "attestation rejected"
    elif now >= int(payload["expires_at"]):
        classification = "blind"
        reason = "authenticated visibility attestation is stale"
        accepted = False
    elif not observed:
        classification = "blind"
        reason = "no expected canary family was observed"
    elif missing:
        classification = "degraded"
        reason = "one or more expected canary families were not observed"
    elif int(payload["drop_count"]) > 0:
        classification = "degraded"
        reason = "sensor reports dropped telemetry"
    elif payload["clock_quality"] not in {"synchronized", "estimated"}:
        classification = "degraded"
        reason = "sensor clock quality is not reliable enough for healthy status"
    else:
        classification = "healthy"
        reason = "authenticated canary and continuity metadata is current"
    return VisibilityAssessment(
        sensor_id=str(payload["sensor_id"]),
        classification=classification,
        accepted=accepted,
        reason=reason,
        platform=str(payload["platform"]),
        build_sha256=str(payload["build_sha256"]),
        policy_sha256=str(payload["policy_sha256"]),
        session_epoch=int(payload["session_epoch"]),
        sequence=int(payload["sequence"]),
        expected_canary_families=expected,
        observed_canary_families=observed,
        missing_canary_families=missing,
        drop_count=int(payload["drop_count"]),
        issued_at=int(payload["issued_at"]),
        expires_at=int(payload["expires_at"]),
        clock_quality=str(payload["clock_quality"]),
        received_at=now,
    )


class VisibilityAttestationRegistry:
    """Verify and retain a bounded last-known visibility state per sensor."""

    def __init__(
        self,
        authority: bytes,
        *,
        max_sensors: int = 256,
        future_skew_s: int = DEFAULT_FUTURE_SKEW_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._authority = _require_authority(authority)
        if max_sensors < 1 or max_sensors > 4096:
            raise ValueError("max_sensors must be between 1 and 4096")
        if future_skew_s < 0 or future_skew_s > 300:
            raise ValueError("future_skew_s must be between 0 and 300")
        self._max_sensors = max_sensors
        self._future_skew_s = future_skew_s
        self._clock = clock
        self._states: "OrderedDict[str, _SensorState]" = OrderedDict()
        self._evicted_sensors = 0
        self._rejected_documents = 0
        self._lock = threading.Lock()

    @property
    def evicted_sensors(self) -> int:
        with self._lock:
            return self._evicted_sensors

    @property
    def rejected_documents(self) -> int:
        with self._lock:
            return self._rejected_documents

    def _untrusted(self, reason: str) -> VisibilityAssessment:
        with self._lock:
            self._rejected_documents += 1
        return VisibilityAssessment(
            sensor_id="",
            classification="untrusted",
            accepted=False,
            reason=reason,
            received_at=self._clock(),
        )

    def ingest(self, document: object) -> VisibilityAssessment:
        """Verify one document and classify it without executing any action."""
        try:
            payload = _verified_payload(document, self._authority)
        except VisibilityAttestationError as exc:
            return self._untrusted(exc.code)

        now = float(self._clock())
        sensor_id = str(payload["sensor_id"])
        issued_at = int(payload["issued_at"])
        if issued_at > now + self._future_skew_s:
            return self._untrusted("future_clock")

        with self._lock:
            prior_state = self._states.get(sensor_id)
            prior = prior_state.assessment if prior_state is not None else None
            forced_classification: Optional[str] = None
            forced_reason: Optional[str] = None
            if prior is not None:
                epoch = int(payload["session_epoch"])
                sequence = int(payload["sequence"])
                if epoch < prior_state.session_epoch:
                    forced_classification, forced_reason = "untrusted", "session epoch regression"
                elif epoch == prior_state.session_epoch:
                    if sequence == prior_state.sequence:
                        forced_classification, forced_reason = "untrusted", "replayed sequence"
                    elif sequence < prior_state.sequence:
                        forced_classification, forced_reason = "untrusted", "sequence regression"
                    elif int(payload["drop_count"]) < prior_state.drop_count:
                        forced_classification, forced_reason = "untrusted", "drop counter regression"
                if (
                    forced_classification is None
                    and issued_at + self._future_skew_s < prior_state.issued_at
                ):
                    forced_classification, forced_reason = "untrusted", "sensor clock regression"

            assessment = _assessment(
                payload,
                now=now,
                accepted=forced_classification is None,
                forced_classification=forced_classification,
                forced_reason=forced_reason,
            )
            if forced_classification is not None:
                self._rejected_documents += 1
                if prior_state is not None:
                    prior_state.assessment = assessment
                return assessment

            if prior_state is None and len(self._states) >= self._max_sensors:
                self._states.popitem(last=False)
                self._evicted_sensors += 1
            self._states[sensor_id] = _SensorState(
                assessment=assessment,
                session_epoch=int(payload["session_epoch"]),
                sequence=int(payload["sequence"]),
                drop_count=int(payload["drop_count"]),
                issued_at=issued_at,
            )
            self._states.move_to_end(sensor_id)
            return assessment

    def snapshot(self, *, now: Optional[float] = None) -> dict[str, VisibilityAssessment]:
        """Return current classifications, turning expired records blind."""
        current = float(self._clock() if now is None else now)
        with self._lock:
            items = [(sensor_id, state.assessment) for sensor_id, state in self._states.items()]
        result: dict[str, VisibilityAssessment] = {}
        for sensor_id, assessment in items:
            if (
                assessment.classification != "untrusted"
                and assessment.expires_at is not None
                and current >= assessment.expires_at
            ):
                assessment = VisibilityAssessment(
                    **{
                        **vars(assessment),
                        "classification": "blind",
                        "accepted": False,
                        "reason": "authenticated visibility attestation is stale",
                    }
                )
            result[sensor_id] = assessment
        return result


LIMITATION = (
    "Software-HMAC sensor assertions only; this snapshot does not prove hardware-backed "
    "identity, native sensor execution, complete telemetry collection, or response authority."
)
