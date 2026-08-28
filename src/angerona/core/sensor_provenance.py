"""Broker-assigned identities and authenticated envelopes for local sensors.

This module is deliberately transport-agnostic.  A sensor can receive a
credential from :class:`SensorProvenanceBroker`, but it cannot choose its
identity or key.  Every accepted event is bound to that assigned identity,
an exact sequence, a cumulative source-loss counter, and bounded canonical
JSON.  Sequence gaps are accepted as evidence, never hidden as healthy.

The in-memory authority is a privilege-separation building block, not hardware
attestation or durable key custody.  Production callers must deliver the
credential through a protected local channel and keep the broker authority in
the privileged service.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping


FORMAT = "angerona-sensor-envelope-v1"
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_EVENT_BYTES = 48 * 1024
MAX_SENSORS = 256
MAX_SEQUENCE = (1 << 64) - 1
MAX_EVENT_AGE_NS = 5 * 60 * 1_000_000_000
MAX_FUTURE_SKEW_NS = 1_000_000_000
MAX_EVENT_DEPTH = 8
MAX_EVENT_ITEMS = 512
MAX_TEXT_CHARS = 4096

_PAYLOAD_FIELDS = frozenset(
    {
        "format",
        "broker_instance",
        "sensor_id",
        "sequence",
        "reported_loss",
        "issued_monotonic_ns",
        "event_type",
        "event",
    }
)
_WRAPPER_FIELDS = frozenset({"payload", "hmac_sha256"})
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,63}$")
_SAFE_EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SAFE_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_SENSOR_ID = re.compile(r"^sensor-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_HMAC_DOMAIN = b"Angerona-Sensor-Provenance-v1\x00"


class SensorProvenanceError(ValueError):
    """A sensor-provenance invariant failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SensorCredential:
    """One broker-created sensor identity and its private signing key."""

    sensor_id: str
    broker_instance: str
    label: str
    key: bytes
    issued_monotonic_ns: int

    def __repr__(self) -> str:
        return (
            "SensorCredential("
            f"sensor_id={self.sensor_id!r}, broker_instance={self.broker_instance!r}, "
            f"label={self.label!r}, key=<redacted>, "
            f"issued_monotonic_ns={self.issued_monotonic_ns!r})"
        )


@dataclass(frozen=True)
class AuthenticatedSensorEvent:
    sensor_id: str
    label: str
    sequence: int
    sequence_gap: int
    observed_gap_total: int
    reported_loss: int
    issued_monotonic_ns: int
    event_type: str
    event: Mapping[str, object]
    coverage_state: str


@dataclass(frozen=True)
class SensorStatus:
    sensor_id: str
    label: str
    state: str
    last_sequence: int
    accepted_events: int
    observed_gap_total: int
    reported_loss: int
    reason: str


@dataclass(frozen=True)
class BrokerHealth:
    state: str
    reason: str
    enrolled_sensors: int
    degraded_sensors: int


@dataclass
class _SensorRecord:
    label: str
    key: bytes
    last_sequence: int = 0
    accepted_events: int = 0
    observed_gap_total: int = 0
    reported_loss: int = 0
    revoked: bool = False


def _authority(value: bytes | None) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("sensor broker authority must be bytes")
    normalized = bytes(value)
    if len(normalized) < 32:
        raise ValueError("sensor broker authority must contain at least 32 bytes")
    return normalized


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SensorProvenanceError("schema", "sensor envelope is not canonical JSON") from exc


def _bounded_json(value: object, *, depth: int = 0, count: list[int] | None = None) -> object:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_EVENT_ITEMS or depth > MAX_EVENT_DEPTH:
        raise SensorProvenanceError("bounds", "sensor event exceeds structural bounds")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not -MAX_SEQUENCE <= value <= MAX_SEQUENCE:
            raise SensorProvenanceError("bounds", "sensor event integer exceeds its bound")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SensorProvenanceError("schema", "sensor event number must be finite")
        return value
    if isinstance(value, str):
        if len(value) > MAX_TEXT_CHARS or any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
            raise SensorProvenanceError("bounds", "sensor event text is unsafe or too long")
        return value
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not _SAFE_KEY.fullmatch(key):
                raise SensorProvenanceError("schema", "sensor event field name is invalid")
            if key in result:
                raise SensorProvenanceError("schema", "sensor event field is duplicated")
            result[key] = _bounded_json(item, depth=depth + 1, count=count)
        return result
    if isinstance(value, (list, tuple)):
        return [_bounded_json(item, depth=depth + 1, count=count) for item in value]
    raise SensorProvenanceError("schema", "sensor event contains an unsupported value")


def _bounded_counter(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SensorProvenanceError("schema", f"{field} must be an integer")
    if not minimum <= value <= MAX_SEQUENCE:
        raise SensorProvenanceError("bounds", f"{field} is outside its bound")
    return value


def _decode(document: object) -> Mapping[str, object]:
    if isinstance(document, Mapping):
        if len(_canonical(document)) > MAX_ENVELOPE_BYTES:
            raise SensorProvenanceError("bounds", "sensor envelope exceeds its byte bound")
        return document
    if isinstance(document, str):
        raw = document.encode("utf-8")
    elif isinstance(document, (bytes, bytearray, memoryview)):
        raw = bytes(document)
    else:
        raise SensorProvenanceError("schema", "sensor envelope must be JSON or a mapping")
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise SensorProvenanceError("bounds", "sensor envelope exceeds its byte bound")

    def unique_object(pairs):
        output = {}
        for key, value in pairs:
            if key in output:
                raise SensorProvenanceError("schema", "sensor envelope has duplicate fields")
            output[key] = value
        return output

    try:
        decoded = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SensorProvenanceError("schema", "sensor envelope is not strict JSON") from exc
    if not isinstance(decoded, Mapping):
        raise SensorProvenanceError("schema", "sensor envelope wrapper must be an object")
    return decoded


def _normalized_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, Mapping) or frozenset(payload) != _PAYLOAD_FIELDS:
        raise SensorProvenanceError("schema", "sensor payload fields do not match v1")
    if payload.get("format") != FORMAT:
        raise SensorProvenanceError("version", "sensor envelope format is unsupported")
    sensor_id = payload.get("sensor_id")
    if not isinstance(sensor_id, str) or not _SENSOR_ID.fullmatch(sensor_id):
        raise SensorProvenanceError("identity", "sensor identity is invalid")
    broker_instance = payload.get("broker_instance")
    if not isinstance(broker_instance, str) or not _DIGEST.fullmatch(broker_instance):
        raise SensorProvenanceError("identity", "broker identity is invalid")
    event_type = payload.get("event_type")
    if not isinstance(event_type, str) or not _SAFE_EVENT_TYPE.fullmatch(event_type):
        raise SensorProvenanceError("schema", "sensor event type is invalid")
    sequence = _bounded_counter(payload.get("sequence"), "sequence", minimum=1)
    reported_loss = _bounded_counter(payload.get("reported_loss"), "reported_loss")
    issued = _bounded_counter(payload.get("issued_monotonic_ns"), "issued_monotonic_ns")
    event = _bounded_json(payload.get("event"))
    if not isinstance(event, dict):
        raise SensorProvenanceError("schema", "sensor event must be an object")
    normalized = {
        "format": FORMAT,
        "broker_instance": broker_instance,
        "sensor_id": sensor_id,
        "sequence": sequence,
        "reported_loss": reported_loss,
        "issued_monotonic_ns": issued,
        "event_type": event_type,
        "event": event,
    }
    if len(_canonical(normalized)) > MAX_EVENT_BYTES:
        raise SensorProvenanceError("bounds", "sensor payload exceeds its byte bound")
    return normalized


def sign_sensor_event(
    credential: SensorCredential,
    *,
    sequence: int,
    reported_loss: int,
    event_type: str,
    event: Mapping[str, object],
    issued_monotonic_ns: int | None = None,
) -> dict[str, object]:
    """Create an authenticated event using a credential assigned by the broker."""
    if not isinstance(credential, SensorCredential):
        raise TypeError("a broker-created SensorCredential is required")
    issued = time.monotonic_ns() if issued_monotonic_ns is None else issued_monotonic_ns
    payload = _normalized_payload(
        {
            "format": FORMAT,
            "broker_instance": credential.broker_instance,
            "sensor_id": credential.sensor_id,
            "sequence": sequence,
            "reported_loss": reported_loss,
            "issued_monotonic_ns": issued,
            "event_type": event_type,
            "event": event,
        }
    )
    signature = hmac.new(
        credential.key,
        _HMAC_DOMAIN + _canonical(payload),
        hashlib.sha256,
    ).hexdigest()
    wrapper: dict[str, object] = {"payload": payload, "hmac_sha256": signature}
    if len(_canonical(wrapper)) > MAX_ENVELOPE_BYTES:
        raise SensorProvenanceError("bounds", "sensor envelope exceeds its byte bound")
    return wrapper


class SensorProvenanceBroker:
    """Assign sensor authority and authenticate sequence/loss-bound events."""

    def __init__(
        self,
        authority: bytes | None = None,
        *,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        max_event_age_ns: int = MAX_EVENT_AGE_NS,
        future_skew_ns: int = MAX_FUTURE_SKEW_NS,
    ) -> None:
        self._authority = _authority(authority)
        if not callable(clock_ns):
            raise TypeError("sensor broker clock must be callable")
        if (
            isinstance(max_event_age_ns, bool)
            or not isinstance(max_event_age_ns, int)
            or not 1 <= max_event_age_ns <= MAX_EVENT_AGE_NS
            or isinstance(future_skew_ns, bool)
            or not isinstance(future_skew_ns, int)
            or not 0 <= future_skew_ns <= MAX_FUTURE_SKEW_NS
        ):
            raise ValueError("sensor broker time bounds are invalid")
        self._clock_ns = clock_ns
        self._max_event_age_ns = max_event_age_ns
        self._future_skew_ns = future_skew_ns
        self._lock = threading.RLock()
        self._sensors: dict[str, _SensorRecord] = {}
        self._broker_instance = (
            hmac.new(
                self._authority,
                b"Angerona-Sensor-Broker-Identity-v1",
                hashlib.sha256,
            ).hexdigest()
            if self._authority is not None
            else ""
        )

    @property
    def broker_instance(self) -> str:
        return self._broker_instance

    def provision(self, label: str) -> SensorCredential:
        """Create identity and key material; callers cannot supply either value."""
        if self._authority is None:
            raise SensorProvenanceError("unconfigured", "sensor broker has no authority")
        if not isinstance(label, str) or not _SAFE_LABEL.fullmatch(label):
            raise SensorProvenanceError("schema", "sensor label is invalid")
        now = self._now()
        with self._lock:
            if len(self._sensors) >= MAX_SENSORS:
                raise SensorProvenanceError("capacity", "sensor enrollment bound reached")
            for _attempt in range(8):
                nonce = secrets.token_bytes(16)
                sensor_id = f"sensor-{nonce.hex()}"
                if sensor_id not in self._sensors:
                    break
            else:
                raise SensorProvenanceError("entropy", "could not allocate a unique sensor ID")
            key = hmac.new(
                self._authority,
                b"Angerona-Sensor-Key-v1\x00" + nonce + sensor_id.encode("ascii"),
                hashlib.sha256,
            ).digest()
            self._sensors[sensor_id] = _SensorRecord(label=label, key=key)
            return SensorCredential(
                sensor_id=sensor_id,
                broker_instance=self._broker_instance,
                label=label,
                key=key,
                issued_monotonic_ns=now,
            )

    def revoke(self, sensor_id: str) -> None:
        with self._lock:
            record = self._sensors.get(sensor_id)
            if record is None:
                raise SensorProvenanceError("identity", "sensor identity is unknown")
            record.revoked = True

    def ingest(
        self,
        document: object,
        *,
        expected_label: str | None = None,
        expected_event_type: str | None = None,
        event_validator: Callable[[Mapping[str, object]], bool] | None = None,
    ) -> AuthenticatedSensorEvent:
        """Authenticate one event and atomically advance its high-water mark.

        Consumer constraints are evaluated after HMAC authentication but before
        any sequence/loss state is mutated.  This prevents an authenticated
        envelope for the wrong schema from silently consuming continuity that a
        fixed-schema consumer never observed.
        """
        if self._authority is None:
            raise SensorProvenanceError("unconfigured", "sensor broker has no authority")
        if expected_label is not None and (
            not isinstance(expected_label, str) or not _SAFE_LABEL.fullmatch(expected_label)
        ):
            raise SensorProvenanceError("schema", "expected sensor label is invalid")
        if expected_event_type is not None and (
            not isinstance(expected_event_type, str)
            or not _SAFE_EVENT_TYPE.fullmatch(expected_event_type)
        ):
            raise SensorProvenanceError("schema", "expected sensor event type is invalid")
        if event_validator is not None and not callable(event_validator):
            raise SensorProvenanceError("schema", "sensor event validator is invalid")
        wrapper = _decode(document)
        if frozenset(wrapper) != _WRAPPER_FIELDS:
            raise SensorProvenanceError("schema", "sensor wrapper fields do not match v1")
        payload = _normalized_payload(wrapper.get("payload"))
        signature = wrapper.get("hmac_sha256")
        if not isinstance(signature, str) or not _DIGEST.fullmatch(signature):
            raise SensorProvenanceError("authentication", "sensor HMAC is invalid")
        sensor_id = str(payload["sensor_id"])
        with self._lock:
            record = self._sensors.get(sensor_id)
            if record is None:
                raise SensorProvenanceError("identity", "sensor identity is not broker-assigned")
            if record.revoked:
                raise SensorProvenanceError("revoked", "sensor identity has been revoked")
            if payload["broker_instance"] != self._broker_instance:
                raise SensorProvenanceError("identity", "sensor belongs to another broker")
            expected = hmac.new(
                record.key,
                _HMAC_DOMAIN + _canonical(payload),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise SensorProvenanceError("authentication", "sensor HMAC verification failed")
            if expected_label is not None and record.label != expected_label:
                raise SensorProvenanceError(
                    "consumer-schema", "sensor label is not admitted by this consumer"
                )
            if (
                expected_event_type is not None
                and payload["event_type"] != expected_event_type
            ):
                raise SensorProvenanceError(
                    "consumer-schema", "sensor event type is not admitted by this consumer"
                )
            if event_validator is not None:
                try:
                    admitted = event_validator(dict(payload["event"]))
                except Exception as exc:
                    raise SensorProvenanceError(
                        "consumer-schema", "sensor event failed its consumer schema"
                    ) from exc
                if admitted is not True:
                    raise SensorProvenanceError(
                        "consumer-schema", "sensor event failed its consumer schema"
                    )

            now = self._now()
            issued = int(payload["issued_monotonic_ns"])
            if issued > now + self._future_skew_ns:
                raise SensorProvenanceError("future", "sensor event is from the future")
            if now - issued > self._max_event_age_ns:
                raise SensorProvenanceError("expired", "sensor event is too old")
            sequence = int(payload["sequence"])
            if sequence <= record.last_sequence:
                raise SensorProvenanceError("replay", "sensor sequence was replayed or regressed")
            reported_loss = int(payload["reported_loss"])
            if reported_loss < record.reported_loss:
                raise SensorProvenanceError("loss-regression", "sensor loss counter regressed")
            gap = sequence - record.last_sequence - 1
            record.last_sequence = sequence
            record.accepted_events += 1
            record.observed_gap_total += gap
            record.reported_loss = reported_loss
            degraded = record.observed_gap_total > 0 or reported_loss > 0
            return AuthenticatedSensorEvent(
                sensor_id=sensor_id,
                label=record.label,
                sequence=sequence,
                sequence_gap=gap,
                observed_gap_total=record.observed_gap_total,
                reported_loss=reported_loss,
                issued_monotonic_ns=issued,
                event_type=str(payload["event_type"]),
                event=dict(payload["event"]),
                coverage_state="degraded" if degraded else "ready",
            )

    def status(self, sensor_id: str) -> SensorStatus:
        with self._lock:
            record = self._sensors.get(sensor_id)
            if record is None:
                raise SensorProvenanceError("identity", "sensor identity is unknown")
            if record.revoked:
                state, reason = "degraded", "sensor-revoked"
            elif record.observed_gap_total or record.reported_loss:
                state, reason = "degraded", "telemetry-loss-observed"
            elif not record.accepted_events:
                state, reason = "unconfigured", "awaiting-first-authenticated-event"
            else:
                state, reason = "ready", "authenticated-continuity-present"
            return SensorStatus(
                sensor_id=sensor_id,
                label=record.label,
                state=state,
                last_sequence=record.last_sequence,
                accepted_events=record.accepted_events,
                observed_gap_total=record.observed_gap_total,
                reported_loss=record.reported_loss,
                reason=reason,
            )

    def health(self) -> BrokerHealth:
        with self._lock:
            if self._authority is None:
                return BrokerHealth("unconfigured", "authority-not-provisioned", 0, 0)
            if not self._sensors:
                return BrokerHealth("unconfigured", "no-sensors-enrolled", 0, 0)
            statuses = [self.status(sensor_id) for sensor_id in self._sensors]
            degraded = sum(status.state != "ready" for status in statuses)
            if degraded:
                return BrokerHealth(
                    "degraded",
                    "one-or-more-sensors-lack-verified-continuity",
                    len(statuses),
                    degraded,
                )
            return BrokerHealth("ready", "all-sensors-authenticated", len(statuses), 0)

    def _now(self) -> int:
        value = self._clock_ns()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise SensorProvenanceError("clock", "sensor broker clock is invalid")
        return value
