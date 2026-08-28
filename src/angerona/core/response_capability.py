"""Single-use, action-scoped capabilities for privileged response operations.

Only code that already owns the authority may mint a capability.  The token is
HMAC-bound to one closed opcode, one resource, one canonical parameter digest,
one service epoch, one monotonic lifetime, and one strictly increasing
sequence.  Production readiness requires an authenticated durable state file
and an OS-exclusive lease.  Every restart rotates the epoch, so outstanding
tokens from an earlier process are rejected even after local-state rollback.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping

from angerona.core.atomic_io import replace_with_retry
from angerona.core.file_lease import ExclusiveFileLease, ExclusiveFileLeaseError


FORMAT = "angerona-response-capability-v2"
STATE_FORMAT = "angerona-response-capability-state-v1"
MAX_CAPABILITY_BYTES = 16 * 1024
MAX_PARAMETERS_BYTES = 8 * 1024
MAX_PARAMETER_ITEMS = 128
MAX_PARAMETER_DEPTH = 6
MAX_TEXT_CHARS = 2048
MAX_SEQUENCE = (1 << 64) - 1
MAX_TTL_NS = 60 * 1_000_000_000

_PAYLOAD_FIELDS = frozenset(
    {
        "format",
        "authority_id",
        "service_epoch",
        "capability_id",
        "sequence",
        "opcode",
        "resource",
        "parameters_sha256",
        "issued_monotonic_ns",
        "expires_monotonic_ns",
    }
)
_WRAPPER_FIELDS = frozenset({"payload", "hmac_sha256"})
_STATE_FIELDS = frozenset(
    {
        "format",
        "authority_id",
        "service_epoch",
        "issued_sequence",
        "consumed_sequence",
        "hmac_sha256",
    }
)
_CAPABILITY_ID = re.compile(r"^[0-9a-f]{32}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RESOURCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/\\-]{0,159}$")
_PARAMETER_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_HMAC_DOMAIN = b"Angerona-Response-Capability-v2\x00"
_STATE_HMAC_DOMAIN = b"Angerona-Response-Capability-State-v1\x00"
_ANCHOR_HMAC_DOMAIN = b"Angerona-Response-Capability-Anchor-v1\x00"


class PrivilegedOpcode(str, Enum):
    """Closed catalog; intentionally contains no shell or arbitrary command."""

    EVENT_LOG_EXPORT = "event-log.export"
    NETWORK_ISOLATE = "network.isolate"
    NETWORK_RESTORE = "network.restore"
    BOOT_ATTEST = "boot.attest"
    AUDIT_APPEND = "audit.append"
    DRIVER_QUARANTINE = "driver.quarantine"


class CapabilityError(ValueError):
    """A privileged capability failed its trust contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CapabilityHealth:
    state: str
    reason: str
    issued_sequence: int
    consumed_sequence: int


@dataclass(frozen=True)
class VerifiedCapability:
    capability_id: str
    sequence: int
    opcode: PrivilegedOpcode
    resource: str
    parameters_sha256: str
    issued_monotonic_ns: int
    expires_monotonic_ns: int


def _authority(value: bytes | None) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("capability authority must be bytes")
    result = bytes(value)
    if len(result) < 32:
        raise ValueError("capability authority must contain at least 32 bytes")
    return result


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
        raise CapabilityError("schema", "capability value is not canonical JSON") from exc


def _bounded_value(value: object, *, depth: int, count: list[int]) -> object:
    count[0] += 1
    if count[0] > MAX_PARAMETER_ITEMS or depth > MAX_PARAMETER_DEPTH:
        raise CapabilityError("bounds", "capability parameters exceed structural bounds")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not -MAX_SEQUENCE <= value <= MAX_SEQUENCE:
            raise CapabilityError("bounds", "capability parameter integer is out of range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CapabilityError("schema", "capability parameter number must be finite")
        return value
    if isinstance(value, str):
        if len(value) > MAX_TEXT_CHARS or any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
            raise CapabilityError("bounds", "capability parameter text is unsafe or too long")
        return value
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not _PARAMETER_KEY.fullmatch(key):
                raise CapabilityError("schema", "capability parameter field is invalid")
            output[key] = _bounded_value(item, depth=depth + 1, count=count)
        return output
    if isinstance(value, (list, tuple)):
        return [_bounded_value(item, depth=depth + 1, count=count) for item in value]
    raise CapabilityError("schema", "capability parameter type is unsupported")


def canonicalize_parameters(parameters: Mapping[str, object]) -> tuple[dict[str, object], bytes]:
    """Return a detached, bounded mapping and its canonical representation."""
    if not isinstance(parameters, Mapping):
        raise CapabilityError("schema", "capability parameters must be an object")
    normalized = _bounded_value(parameters, depth=0, count=[0])
    if not isinstance(normalized, dict):
        raise CapabilityError("schema", "capability parameters must be an object")
    encoded = _canonical(normalized)
    if len(encoded) > MAX_PARAMETERS_BYTES:
        raise CapabilityError("bounds", "capability parameters exceed their byte bound")
    return normalized, encoded


def _opcode(value: PrivilegedOpcode | str) -> PrivilegedOpcode:
    if isinstance(value, PrivilegedOpcode):
        return value
    if not isinstance(value, str):
        raise CapabilityError("opcode", "privileged opcode is invalid")
    try:
        return PrivilegedOpcode(value)
    except ValueError as exc:
        raise CapabilityError("opcode", "privileged opcode is not in the closed catalog") from exc


def _resource(value: object) -> str:
    if not isinstance(value, str) or not _RESOURCE.fullmatch(value):
        raise CapabilityError("resource", "privileged resource is invalid")
    normalized = value.replace("\\", "/")
    if "//" in normalized or any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise CapabilityError("resource", "privileged resource is not canonical")
    return value


def _counter(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CapabilityError("schema", f"{field} must be an integer")
    if not minimum <= value <= MAX_SEQUENCE:
        raise CapabilityError("bounds", f"{field} is outside its bound")
    return value


def _decode(document: object) -> Mapping[str, object]:
    if isinstance(document, Mapping):
        if len(_canonical(document)) > MAX_CAPABILITY_BYTES:
            raise CapabilityError("bounds", "capability exceeds its byte bound")
        return document
    if isinstance(document, str):
        raw = document.encode("utf-8")
    elif isinstance(document, (bytes, bytearray, memoryview)):
        raw = bytes(document)
    else:
        raise CapabilityError("schema", "capability must be JSON or a mapping")
    if len(raw) > MAX_CAPABILITY_BYTES:
        raise CapabilityError("bounds", "capability exceeds its byte bound")

    def unique_object(pairs):
        output = {}
        for key, value in pairs:
            if key in output:
                raise CapabilityError("schema", "capability contains duplicate fields")
            output[key] = value
        return output

    try:
        result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CapabilityError("schema", "capability is not strict JSON") from exc
    if not isinstance(result, Mapping):
        raise CapabilityError("schema", "capability wrapper must be an object")
    return result


def _normalized_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, Mapping) or frozenset(payload) != _PAYLOAD_FIELDS:
        raise CapabilityError("schema", "capability payload fields do not match v2")
    if payload.get("format") != FORMAT:
        raise CapabilityError("version", "capability format is unsupported")
    authority_id = payload.get("authority_id")
    service_epoch = payload.get("service_epoch")
    capability_id = payload.get("capability_id")
    digest = payload.get("parameters_sha256")
    if not isinstance(authority_id, str) or not _DIGEST.fullmatch(authority_id):
        raise CapabilityError("authority", "capability authority identity is invalid")
    if not isinstance(service_epoch, str) or not _CAPABILITY_ID.fullmatch(service_epoch):
        raise CapabilityError("epoch", "capability service epoch is invalid")
    if not isinstance(capability_id, str) or not _CAPABILITY_ID.fullmatch(capability_id):
        raise CapabilityError("identity", "capability identity is invalid")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise CapabilityError("schema", "capability parameter digest is invalid")
    issued = _counter(payload.get("issued_monotonic_ns"), "issued_monotonic_ns")
    expires = _counter(payload.get("expires_monotonic_ns"), "expires_monotonic_ns")
    if expires <= issued or expires - issued > MAX_TTL_NS:
        raise CapabilityError("expiry", "capability lifetime is invalid")
    return {
        "format": FORMAT,
        "authority_id": authority_id,
        "service_epoch": service_epoch,
        "capability_id": capability_id,
        "sequence": _counter(payload.get("sequence"), "sequence", minimum=1),
        "opcode": _opcode(payload.get("opcode")).value,
        "resource": _resource(payload.get("resource")),
        "parameters_sha256": digest,
        "issued_monotonic_ns": issued,
        "expires_monotonic_ns": expires,
    }


class ResponseCapabilityAuthority:
    """Mint and atomically consume narrowly scoped response capabilities."""

    def __init__(
        self,
        authority: bytes | None = None,
        *,
        state_path: str | Path | None = None,
        test_only: bool = False,
        clock_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self._authority = _authority(authority)
        if not callable(clock_ns):
            raise TypeError("capability clock must be callable")
        if test_only is not True and state_path is None and self._authority is not None:
            self._durable_state_required = True
        else:
            self._durable_state_required = False
        if test_only is True and state_path is not None:
            raise ValueError("test-only capability mode cannot use production durable state")
        self._clock_ns = clock_ns
        self._lock = threading.RLock()
        self._state_path = Path(state_path) if state_path is not None else None
        self._anchor_path = (
            self._state_path.with_name(f"{self._state_path.name}.anchor")
            if self._state_path is not None
            else None
        )
        self._state_lease: ExclusiveFileLease | None = None
        self._state_initialized = False
        self._test_only = test_only is True
        self._issued_sequence = 0
        self._consumed_sequence = 0
        self._service_epoch = secrets.token_hex(16) if self._authority is not None else ""
        self._last_clock_ns: int | None = None
        self._degraded_reason = ""
        self._authority_id = (
            hmac.new(
                self._authority,
                b"Angerona-Capability-Authority-Identity-v1",
                hashlib.sha256,
            ).hexdigest()
            if self._authority is not None
            else ""
        )
        if self._authority is not None and self._state_path is not None:
            try:
                lease_path = self._state_path.with_name(f"{self._state_path.name}.lock")
                self._state_lease = ExclusiveFileLease(lease_path)
                self._initialize_anchor()
                self._state_initialized = self._state_path.exists()
                previous = self._load_state()
                self._issued_sequence = int(previous["issued_sequence"])
                self._consumed_sequence = int(previous["consumed_sequence"])
                # A new unpredictable epoch invalidates every outstanding token
                # from a predecessor, including one restored from an old state
                # snapshot.  Sequence high-water remains monotonic as well.
                self._service_epoch = secrets.token_hex(16)
                self._save_state()
            except Exception:
                if self._state_lease is not None:
                    self._state_lease.close()
                    self._state_lease = None
                raise

    @property
    def authority_id(self) -> str:
        return self._authority_id

    def health(self) -> CapabilityHealth:
        with self._lock:
            if self._authority is None:
                return CapabilityHealth("unconfigured", "authority-not-provisioned", 0, 0)
            if self._durable_state_required:
                return CapabilityHealth(
                    "unconfigured",
                    "durable-state-not-provisioned",
                    self._issued_sequence,
                    self._consumed_sequence,
                )
            if self._degraded_reason:
                return CapabilityHealth(
                    "degraded",
                    self._degraded_reason,
                    self._issued_sequence,
                    self._consumed_sequence,
                )
            return CapabilityHealth(
                "ready",
                (
                    "test-only-memory-authority"
                    if self._test_only
                    else "durable-epoch-bound-authority-ready"
                ),
                self._issued_sequence,
                self._consumed_sequence,
            )

    def close(self) -> None:
        """Release the production singleton lease; the authority cannot be reused."""
        with self._lock:
            if self._state_lease is not None:
                self._state_lease.close()
                self._state_lease = None
            self._degraded_reason = "authority-closed"

    def __enter__(self) -> "ResponseCapabilityAuthority":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def _reject_state_alias(self) -> None:
        assert self._state_path is not None
        if self._state_path.is_symlink() or self._state_path.parent.is_symlink():
            raise CapabilityError("state", "capability state path is an alias")
        if os.name == "nt":
            try:
                from angerona.core.data_paths import _is_reparse_point

                if _is_reparse_point(self._state_path) or _is_reparse_point(
                    self._state_path.parent
                ):
                    raise CapabilityError("state", "capability state is reparse-backed")
            except CapabilityError:
                raise
            except Exception as exc:
                raise CapabilityError(
                    "state", "capability state reparse status is unavailable"
                ) from exc

    def _load_state(self) -> dict[str, object]:
        assert self._state_path is not None
        self._reject_state_alias()
        if not self._state_path.exists():
            if self._state_initialized:
                raise CapabilityError("state", "capability state disappeared")
            return {
                "issued_sequence": 0,
                "consumed_sequence": 0,
            }
        try:
            size = self._state_path.stat().st_size
            if not 1 <= size <= 16 * 1024:
                raise CapabilityError("state", "capability state size is invalid")
            raw = self._state_path.read_bytes()

            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise CapabilityError("state", "capability state has duplicate fields")
                    result[key] = value
                return result

            document = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique_object)
        except CapabilityError:
            raise
        except Exception as exc:
            raise CapabilityError("state", "capability state is unreadable") from exc
        if not isinstance(document, Mapping) or frozenset(document) != _STATE_FIELDS:
            raise CapabilityError("state", "capability state schema is invalid")
        if (
            document.get("format") != STATE_FORMAT
            or document.get("authority_id") != self._authority_id
            or not isinstance(document.get("service_epoch"), str)
            or not _CAPABILITY_ID.fullmatch(str(document["service_epoch"]))
        ):
            raise CapabilityError("state", "capability state identity is invalid")
        issued = _counter(document.get("issued_sequence"), "issued_sequence")
        consumed = _counter(document.get("consumed_sequence"), "consumed_sequence")
        if consumed > issued:
            raise CapabilityError("state", "capability state high-water is inconsistent")
        signature = document.get("hmac_sha256")
        if not isinstance(signature, str) or not _DIGEST.fullmatch(signature):
            raise CapabilityError("state", "capability state signature is invalid")
        body = {key: value for key, value in document.items() if key != "hmac_sha256"}
        expected = hmac.new(
            self._authority,
            _STATE_HMAC_DOMAIN + _canonical(body),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise CapabilityError("state", "capability state authentication failed")
        return {"issued_sequence": issued, "consumed_sequence": consumed}

    def _initialize_anchor(self) -> None:
        """Create/verify a separate first-enrollment marker.

        This detects ordinary deletion of the durable state across restart. It
        remains same-host evidence: deletion/restoration of both files still
        needs an external TPM counter or witness to detect authoritatively.
        """
        assert self._state_path is not None and self._anchor_path is not None
        body = {
            "format": "angerona-response-capability-anchor-v1",
            "authority_id": self._authority_id,
        }
        expected = hmac.new(
            self._authority,
            _ANCHOR_HMAC_DOMAIN + _canonical(body),
            hashlib.sha256,
        ).hexdigest()
        payload = _canonical({**body, "hmac_sha256": expected}) + b"\n"
        if self._anchor_path.exists():
            if self._anchor_path.is_symlink() or self._anchor_path.parent.is_symlink():
                raise CapabilityError("state", "capability enrollment anchor is an alias")
            try:
                document = json.loads(self._anchor_path.read_bytes().decode("utf-8", "strict"))
            except Exception as exc:
                raise CapabilityError("state", "capability enrollment anchor is unreadable") from exc
            if (
                not isinstance(document, dict)
                or document.get("format") != body["format"]
                or document.get("authority_id") != self._authority_id
                or frozenset(document) != {"format", "authority_id", "hmac_sha256"}
                or not isinstance(document.get("hmac_sha256"), str)
                or not hmac.compare_digest(document["hmac_sha256"], expected)
            ):
                raise CapabilityError("state", "capability enrollment anchor is invalid")
            if not self._state_path.exists():
                raise CapabilityError("state", "capability state is missing after enrollment")
            return
        if self._state_path.exists():
            raise CapabilityError("state", "capability enrollment anchor is missing")
        descriptor = os.open(
            os.fspath(self._anchor_path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())

    def _save_state(self) -> None:
        if self._state_path is None:
            return
        if self._state_lease is None or not self._state_lease.held:
            raise CapabilityError("state", "capability state lease is unavailable")
        self._reject_state_alias()
        body: dict[str, object] = {
            "format": STATE_FORMAT,
            "authority_id": self._authority_id,
            "service_epoch": self._service_epoch,
            "issued_sequence": self._issued_sequence,
            "consumed_sequence": self._consumed_sequence,
        }
        signed = {
            **body,
            "hmac_sha256": hmac.new(
                self._authority,
                _STATE_HMAC_DOMAIN + _canonical(body),
                hashlib.sha256,
            ).hexdigest(),
        }
        payload = _canonical(signed) + b"\n"
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._state_path.with_name(
            f".{self._state_path.name}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
        )
        try:
            descriptor = os.open(
                os.fspath(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            replace_with_retry(temporary, self._state_path)
            info = self._state_path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise CapabilityError("state", "capability state is not a regular file")
            if os.name != "nt":
                os.chmod(self._state_path, stat.S_IRUSR | stat.S_IWUSR)
            self._state_initialized = True
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def issue(
        self,
        opcode: PrivilegedOpcode | str,
        resource: str,
        parameters: Mapping[str, object],
        *,
        ttl_ns: int = 5_000_000_000,
    ) -> dict[str, object]:
        """Mint one action-bound token; keep this method behind approval policy."""
        self._require_ready()
        operation = _opcode(opcode)
        target = _resource(resource)
        _normalized, encoded_parameters = canonicalize_parameters(parameters)
        if isinstance(ttl_ns, bool) or not isinstance(ttl_ns, int) or not 1 <= ttl_ns <= MAX_TTL_NS:
            raise CapabilityError("bounds", "capability TTL is outside its bound")
        with self._lock:
            now = self._observe_clock()
            if self._issued_sequence >= MAX_SEQUENCE:
                self._degraded_reason = "capability-sequence-exhausted"
                raise CapabilityError("capacity", "capability sequence is exhausted")
            self._issued_sequence += 1
            payload = {
                "format": FORMAT,
                "authority_id": self._authority_id,
                "service_epoch": self._service_epoch,
                "capability_id": secrets.token_hex(16),
                "sequence": self._issued_sequence,
                "opcode": operation.value,
                "resource": target,
                "parameters_sha256": hashlib.sha256(encoded_parameters).hexdigest(),
                "issued_monotonic_ns": now,
                "expires_monotonic_ns": now + ttl_ns,
            }
            signature = hmac.new(
                self._authority,
                _HMAC_DOMAIN + _canonical(payload),
                hashlib.sha256,
            ).hexdigest()
            wrapper: dict[str, object] = {"payload": payload, "hmac_sha256": signature}
            if len(_canonical(wrapper)) > MAX_CAPABILITY_BYTES:
                self._degraded_reason = "capability-serialization-bound-exceeded"
                raise CapabilityError("bounds", "capability exceeds its byte bound")
            # Persist issuance before the token can leave this authority. A
            # failed durable write produces no usable token.
            self._save_state()
            return wrapper

    def consume(
        self,
        document: object,
        *,
        opcode: PrivilegedOpcode | str,
        resource: str,
        parameters: Mapping[str, object],
    ) -> VerifiedCapability:
        """Verify scope and atomically burn the token before execution begins."""
        self._require_ready()
        expected_opcode = _opcode(opcode)
        expected_resource = _resource(resource)
        _normalized, encoded_parameters = canonicalize_parameters(parameters)
        expected_digest = hashlib.sha256(encoded_parameters).hexdigest()
        wrapper = _decode(document)
        if frozenset(wrapper) != _WRAPPER_FIELDS:
            raise CapabilityError("schema", "capability wrapper fields do not match v1")
        payload = _normalized_payload(wrapper.get("payload"))
        signature = wrapper.get("hmac_sha256")
        if not isinstance(signature, str) or not _DIGEST.fullmatch(signature):
            raise CapabilityError("authentication", "capability HMAC is invalid")
        expected_signature = hmac.new(
            self._authority,
            _HMAC_DOMAIN + _canonical(payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            raise CapabilityError("authentication", "capability HMAC verification failed")
        if payload["authority_id"] != self._authority_id:
            raise CapabilityError("authority", "capability belongs to another authority")
        if payload["service_epoch"] != self._service_epoch:
            raise CapabilityError("epoch", "capability belongs to an earlier service epoch")
        if payload["opcode"] != expected_opcode.value:
            raise CapabilityError("scope", "capability opcode does not match the request")
        if payload["resource"] != expected_resource:
            raise CapabilityError("scope", "capability resource does not match the request")
        if not hmac.compare_digest(str(payload["parameters_sha256"]), expected_digest):
            raise CapabilityError("scope", "capability parameters do not match the request")

        with self._lock:
            now = self._observe_clock()
            issued = int(payload["issued_monotonic_ns"])
            expires = int(payload["expires_monotonic_ns"])
            if issued > now:
                raise CapabilityError("future", "capability was issued in the future")
            if now >= expires:
                raise CapabilityError("expired", "capability has expired")
            sequence = int(payload["sequence"])
            if sequence <= self._consumed_sequence:
                raise CapabilityError("replay", "capability was replayed or consumed out of order")
            # Strict high-water semantics intentionally invalidate any older
            # outstanding token when a newer token is consumed first.
            self._consumed_sequence = sequence
            # Burn durably before the caller can execute the privileged action.
            self._save_state()
            return VerifiedCapability(
                capability_id=str(payload["capability_id"]),
                sequence=sequence,
                opcode=expected_opcode,
                resource=expected_resource,
                parameters_sha256=expected_digest,
                issued_monotonic_ns=issued,
                expires_monotonic_ns=expires,
            )

    def _require_ready(self) -> None:
        health = self.health()
        if health.state != "ready":
            raise CapabilityError(health.state, health.reason)

    def _observe_clock(self) -> int:
        value = self._clock_ns()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            self._degraded_reason = "monotonic-clock-invalid"
            raise CapabilityError("clock", "capability clock is invalid")
        if self._last_clock_ns is not None and value < self._last_clock_ns:
            self._degraded_reason = "monotonic-clock-rollback"
            raise CapabilityError("clock-rollback", "capability clock moved backwards")
        self._last_clock_ns = value
        return value
