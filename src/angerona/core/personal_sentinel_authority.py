"""Independent Personal Sentinel witness and monotonic-state authority.

The authority is deliberately narrow.  It stores authenticated high-water
heads and issues signed time receipts; it cannot discover devices, administer
a router, change a firewall, or execute a host action.  Production transport is
direct HTTPS to one explicitly enrolled private endpoint.  The in-process
transport is marked test-only and must be opted into by the client.

An installation identifier names the protected Angerona installation.  A
separate client-instance identifier is enrolled at the authority.  Requests
from a clone carrying a different instance identifier are rejected, while two
copies carrying the same identifiers cannot create divergent state because
every transition is an exact compare-and-swap against the current signed head.
"""
from __future__ import annotations

import base64
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
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol

from angerona.core.atomic_io import replace_with_retry
from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.independent_high_water import (
    AUDIT_DOMAIN,
    NETWORK_DOMAIN,
    PLATFORM_DOMAIN,
    SCHEMA as HIGH_WATER_SCHEMA,
    ZERO_DIGEST,
    HighWaterHead,
    HighWaterRejected,
    HighWaterTransition,
    HighWaterUnavailable,
    validate_head,
    validate_installation_id,
)
from angerona.core.personal_sentinel_gateway import (
    GatewayEnrollment,
    GatewayTransport,
    GatewayTransportRequest,
    GatewayTransportResponse,
    StandardHttpsGatewayTransport,
)


REQUEST_SCHEMA = "angerona.personal-sentinel-authority-request.v1"
RESPONSE_SCHEMA = "angerona.personal-sentinel-authority-response.v1"
STATE_SCHEMA = "angerona.personal-sentinel-authority-state.v1"
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 32 * 1024
MAX_NONCES = 4096
MAX_DOMAINS = 16
MAX_SIGNATURE_CHARS = 1024
DEFAULT_ALLOWED_DOMAINS = frozenset({AUDIT_DOMAIN, NETWORK_DOMAIN, PLATFORM_DOMAIN})
TRANSPORT_RESPONSE_FLOOR_NAMESPACE = "angerona.sentinel.transport-response.v1"
TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE = (
    "angerona.sentinel.trusted-time-appraisal.v1"
)

_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_REQUEST_KEYS = frozenset(
    {
        "schema",
        "operation",
        "installation_id",
        "client_instance_id",
        "nonce",
        "issued_at",
        "key_id",
        "payload",
        "signature",
    }
)
_RESPONSE_KEYS = frozenset(
    {
        "schema",
        "operation",
        "request_nonce",
        "sequence",
        "received_at",
        "expires_at",
        "status",
        "payload",
        "key_id",
        "signature",
    }
)
_STATE_KEYS = frozenset(
    {
        "schema",
        "installation_id",
        "client_instance_id",
        "generation",
        "sequence",
        "last_authority_time",
        "heads",
        "nonce_hashes",
        "state_signature",
    }
)
_HEAD_KEYS = frozenset(
    {
        "schema",
        "installation_id",
        "domain",
        "revision",
        "state_digest",
        "previous_head",
        "head",
    }
)
_TRANSITION_KEYS = frozenset(
    {
        "schema",
        "installation_id",
        "domain",
        "previous_revision",
        "previous_state_digest",
        "previous_head",
        "revision",
        "state_digest",
    }
)


class SentinelAuthorityError(RuntimeError):
    """Base error for an authority or its authenticated transport."""


class SentinelRequestRejected(SentinelAuthorityError):
    """A malformed, unauthenticated, replayed, stale, or conflicting request."""


class SentinelStateIntegrityError(SentinelAuthorityError):
    """The durable authority state was missing, ambiguous, or unauthentic."""


class SentinelAuthenticator(Protocol):
    """Injected signing contract suitable for HMAC or asymmetric backends."""

    @property
    def key_id(self) -> str: ...

    def sign(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, signature: str) -> bool: ...


class SentinelVerifier(Protocol):
    """Public-side verification contract; it need not hold signing material."""

    @property
    def key_id(self) -> str: ...

    def verify(self, payload: bytes, signature: str) -> bool: ...


class SentinelSigner(Protocol):
    """Private-side signing contract used for requests or authority receipts."""

    @property
    def key_id(self) -> str: ...

    def sign(self, payload: bytes) -> str: ...


class SentinelResponseFloor(Protocol):
    """Durable client-side sequence/time continuity contract.

    Production implementations must atomically reject duplicate/regressed
    sequence or witness time and keep the floor outside a restorable monitored-
    host snapshot (for example in TPM NV or a second witness).  The exact
    ``namespace`` is part of the durable identity alongside installation and
    client-instance IDs; implementations must never collapse namespaces.
    """

    def compare_and_advance(
        self,
        *,
        namespace: str,
        installation_id: str,
        client_instance_id: str,
        sequence: int,
        received_at: float,
    ) -> bool: ...


class SentinelGenerationFloor(Protocol):
    """Pluggable monotonic authority-state anchor.

    A state-level deployment should implement this with TPM NV, WORM storage,
    or a second independently administered witness. A same-disk implementation
    can detect partial rollback but cannot defeat a full appliance snapshot.
    """

    def read_generation(
        self, *, installation_id: str, client_instance_id: str
    ) -> int | None: ...

    def compare_and_advance(
        self,
        *,
        installation_id: str,
        client_instance_id: str,
        previous_generation: int,
        generation: int,
        state_sha256: str,
    ) -> bool: ...


class HmacSha256Authenticator:
    """Small reference authenticator; production can inject an HSM-backed one."""

    def __init__(self, key: bytes, *, key_id: str = "sentinel-hmac-v1") -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("Personal Sentinel HMAC key must contain at least 32 bytes")
        if not isinstance(key_id, str) or not _TOKEN.fullmatch(key_id):
            raise ValueError("Personal Sentinel key identifier is invalid")
        self._key = bytes(key)
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: bytes) -> str:
        if not isinstance(payload, bytes):
            raise TypeError("signed payload must be bytes")
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        if not isinstance(signature, str) or not _HEX_64.fullmatch(signature):
            return False
        return hmac.compare_digest(self.sign(payload), signature)


class Ed25519PrivateSigner:
    """Asymmetric signer suitable for separating host and authority custody."""

    def __init__(self, private_key, *, key_id: str) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Personal Sentinel private key must be Ed25519")
        if not isinstance(key_id, str) or not _TOKEN.fullmatch(key_id):
            raise ValueError("Personal Sentinel key identifier is invalid")
        self._private_key = private_key
        self._key_id = key_id

    @classmethod
    def from_pem(cls, pem: bytes, *, key_id: str, password: bytes | None = None):
        from cryptography.hazmat.primitives import serialization

        if not isinstance(pem, bytes) or not pem or len(pem) > 64 * 1024:
            raise ValueError("Personal Sentinel private-key PEM size is invalid")
        key = serialization.load_pem_private_key(pem, password=password)
        return cls(key, key_id=key_id)

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: bytes) -> str:
        if not isinstance(payload, bytes):
            raise TypeError("signed payload must be bytes")
        return base64.urlsafe_b64encode(self._private_key.sign(payload)).rstrip(b"=").decode("ascii")

    def public_verifier(self) -> "Ed25519PublicVerifier":
        return Ed25519PublicVerifier(self._private_key.public_key(), key_id=self.key_id)


class Ed25519PublicVerifier:
    """Verify-only authority or client identity; contains no private key."""

    def __init__(self, public_key, *, key_id: str) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Personal Sentinel public key must be Ed25519")
        if not isinstance(key_id, str) or not _TOKEN.fullmatch(key_id):
            raise ValueError("Personal Sentinel key identifier is invalid")
        self._public_key = public_key
        self._key_id = key_id

    @classmethod
    def from_pem(cls, pem: bytes, *, key_id: str):
        from cryptography.hazmat.primitives import serialization

        if not isinstance(pem, bytes) or not pem or len(pem) > 64 * 1024:
            raise ValueError("Personal Sentinel public-key PEM size is invalid")
        key = serialization.load_pem_public_key(pem)
        return cls(key, key_id=key_id)

    @property
    def key_id(self) -> str:
        return self._key_id

    def verify(self, payload: bytes, signature: str) -> bool:
        if not isinstance(payload, bytes) or not isinstance(signature, str):
            return False
        try:
            encoded = signature.encode("ascii")
            padding = b"=" * (-len(encoded) % 4)
            raw = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
            if len(raw) != 64:
                return False
            self._public_key.verify(raw, payload)
            return True
        except Exception:
            return False


class _DuplicateJsonKey(ValueError):
    pass


def _canonical(document: object) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _strict_json(body: bytes, *, maximum: int, exact_keys: frozenset[str]) -> dict:
    if not isinstance(body, bytes) or not body or len(body) > maximum:
        raise SentinelRequestRejected("JSON document size is invalid")
    try:
        text = body.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SentinelRequestRejected("JSON document is not strict UTF-8") from exc

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if not isinstance(key, str) or key in result:
                raise _DuplicateJsonKey("duplicate or non-text JSON key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("non-finite JSON number")

    try:
        document = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError, _DuplicateJsonKey, ValueError) as exc:
        raise SentinelRequestRejected("JSON document is invalid or ambiguous") from exc
    if not isinstance(document, dict) or set(document) != exact_keys:
        raise SentinelRequestRejected("JSON document schema is invalid")
    return document


def _finite_time(value: object, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 32_503_680_000.0
    ):
        raise SentinelRequestRejected(f"{label} is invalid")
    return float(value)


def _client_instance_id(value: object) -> str:
    if not isinstance(value, str) or not _HEX_32.fullmatch(value):
        raise SentinelRequestRejected("client instance identity is invalid")
    return value


def _signature(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_SIGNATURE_CHARS
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value)
    ):
        raise SentinelRequestRejected("signature encoding is invalid")
    return value


def _sign(authenticator: SentinelSigner, payload: bytes) -> str:
    try:
        return _signature(authenticator.sign(payload))
    except SentinelRequestRejected:
        raise
    except Exception as exc:
        raise SentinelRequestRejected("signing authority failed") from exc


def _validate_domain(value: object, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise SentinelRequestRejected("high-water domain is not enrolled")
    return value


def _head_document(head: HighWaterHead) -> dict:
    return asdict(head)


def _parse_head(value: object, *, installation_id: str, domain: str) -> HighWaterHead:
    if not isinstance(value, dict) or set(value) != _HEAD_KEYS:
        raise SentinelRequestRejected("authority head schema is invalid")
    try:
        head = HighWaterHead(**value)
        return validate_head(head, installation_id=installation_id, domain=domain)
    except Exception as exc:
        raise SentinelRequestRejected("authority head is invalid") from exc


def _parse_transition(
    value: object,
    *,
    installation_id: str,
    allowed_domains: frozenset[str],
) -> HighWaterTransition:
    if not isinstance(value, dict) or set(value) != _TRANSITION_KEYS:
        raise SentinelRequestRejected("transition schema is invalid")
    if value.get("schema") != HIGH_WATER_SCHEMA:
        raise SentinelRequestRejected("transition schema version is invalid")
    if value.get("installation_id") != installation_id:
        raise SentinelRequestRejected("transition installation identity changed")
    domain = _validate_domain(value.get("domain"), allowed_domains)
    previous_revision = value.get("previous_revision")
    revision = value.get("revision")
    if (
        type(previous_revision) is not int
        or type(revision) is not int
        or not 0 <= previous_revision <= 2**63 - 2
        or revision != previous_revision + 1
    ):
        raise SentinelRequestRejected("transition revision is not monotonic")
    digests: dict[str, str] = {}
    for key in ("previous_state_digest", "previous_head", "state_digest"):
        candidate = value.get(key)
        if not isinstance(candidate, str) or not _HEX_64.fullmatch(candidate):
            raise SentinelRequestRejected(f"transition {key} is invalid")
        digests[key] = candidate
    if digests["state_digest"] == ZERO_DIGEST:
        raise SentinelRequestRejected("transition state digest is empty")
    if previous_revision == 0:
        if (
            digests["previous_state_digest"] != ZERO_DIGEST
            or digests["previous_head"] != ZERO_DIGEST
        ):
            raise SentinelRequestRejected("first transition has an unexpected predecessor")
    elif (
        digests["previous_state_digest"] == ZERO_DIGEST
        or digests["previous_head"] == ZERO_DIGEST
    ):
        raise SentinelRequestRejected("transition predecessor is incomplete")
    return HighWaterTransition(
        HIGH_WATER_SCHEMA,
        installation_id,
        domain,
        previous_revision,
        digests["previous_state_digest"],
        digests["previous_head"],
        revision,
        digests["state_digest"],
    )


@dataclass(frozen=True)
class SignedTimeReceipt:
    """One nonce-bound signed authority-time statement."""

    operation: str
    request_nonce: str
    sequence: int
    received_at: float
    expires_at: float
    installation_id: str
    client_instance_id: str
    key_id: str
    signature: str

    def signed_document(self) -> dict:
        return {
            "schema": RESPONSE_SCHEMA,
            "operation": self.operation,
            "request_nonce": self.request_nonce,
            "sequence": self.sequence,
            "received_at": self.received_at,
            "expires_at": self.expires_at,
            "status": "ok",
            "payload": {
                "installation_id": self.installation_id,
                "client_instance_id": self.client_instance_id,
                "authority_time": self.received_at,
            },
            "key_id": self.key_id,
        }

    def verify(self, verifier: SentinelVerifier) -> bool:
        try:
            return (
                verifier.key_id == self.key_id
                and verifier.verify(_canonical(self.signed_document()), self.signature) is True
            )
        except Exception:
            return False


class PersonalSentinelAuthority:
    """Durable, signed, bounded CAS authority intended for a separate host."""

    def __init__(
        self,
        state_path: str | Path,
        *,
        installation_id: str,
        client_instance_id: str,
        authenticator: SentinelAuthenticator | None = None,
        request_verifier: SentinelVerifier | None = None,
        response_signer: SentinelSigner | None = None,
        response_verifier: SentinelVerifier | None = None,
        generation_floor: SentinelGenerationFloor | None = None,
        allowed_domains: frozenset[str] = DEFAULT_ALLOWED_DOMAINS,
        clock: Callable[[], float] = time.time,
        max_request_age: float = 30.0,
        receipt_lifetime: float = 30.0,
        clock_rollback_tolerance: float = 1.0,
        max_nonces: int = MAX_NONCES,
    ) -> None:
        self.state_path = Path(state_path)
        self.installation_id = validate_installation_id(installation_id)
        self.client_instance_id = _client_instance_id(client_instance_id)
        request_verifier = request_verifier or authenticator
        response_signer = response_signer or authenticator
        response_verifier = response_verifier or authenticator
        if request_verifier is None or response_signer is None or response_verifier is None:
            raise TypeError("Personal Sentinel signing contracts are incomplete")
        for value, members, label in (
            (request_verifier, ("key_id", "verify"), "request verifier"),
            (response_signer, ("key_id", "sign"), "response signer"),
            (response_verifier, ("key_id", "verify"), "state verifier"),
        ):
            if any(not hasattr(value, member) for member in members):
                raise TypeError(f"Personal Sentinel {label} contract is incomplete")
            if not isinstance(value.key_id, str) or not _TOKEN.fullmatch(value.key_id):
                raise ValueError(f"Personal Sentinel {label} key identifier is invalid")
        if response_signer.key_id != response_verifier.key_id:
            raise ValueError("Personal Sentinel response signer and state verifier disagree")
        if (
            not isinstance(allowed_domains, frozenset)
            or not allowed_domains
            or len(allowed_domains) > MAX_DOMAINS
            or any(
                not isinstance(item, str)
                or not item
                or len(item) > 64
                or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in item)
                for item in allowed_domains
            )
        ):
            raise ValueError("Personal Sentinel domain enrollment is invalid")
        if (
            not isinstance(max_request_age, (int, float))
            or isinstance(max_request_age, bool)
            or not 1.0 <= float(max_request_age) <= 300.0
        ):
            raise ValueError("Personal Sentinel request freshness bound is invalid")
        if (
            not isinstance(receipt_lifetime, (int, float))
            or isinstance(receipt_lifetime, bool)
            or not 1.0 <= float(receipt_lifetime) <= 300.0
        ):
            raise ValueError("Personal Sentinel receipt lifetime is invalid")
        if (
            not isinstance(clock_rollback_tolerance, (int, float))
            or isinstance(clock_rollback_tolerance, bool)
            or not 0.0 <= float(clock_rollback_tolerance) <= 5.0
        ):
            raise ValueError("Personal Sentinel clock rollback tolerance is invalid")
        if type(max_nonces) is not int or not 64 <= max_nonces <= MAX_NONCES:
            raise ValueError("Personal Sentinel nonce-history bound is invalid")
        self.request_verifier = request_verifier
        self.response_signer = response_signer
        self.response_verifier = response_verifier
        self.generation_floor = generation_floor
        self.allowed_domains = allowed_domains
        self._clock = clock
        self._max_request_age = float(max_request_age)
        self._receipt_lifetime = float(receipt_lifetime)
        self._clock_rollback_tolerance = float(clock_rollback_tolerance)
        self._max_nonces = max_nonces
        self._lock = threading.RLock()
        self._closed = False
        self._lease: ExclusiveFileLease | None = None
        lease_path = self.state_path.with_name(f"{self.state_path.name}.lock")
        self._lease = ExclusiveFileLease(lease_path)
        self._initialized = self.state_path.exists()

    def _require_live_lease(self) -> None:
        lease = self._lease
        if self._closed or lease is None or lease.held is not True:
            raise SentinelStateIntegrityError(
                "authority is closed or its singleton lease is not held"
            )

    def _initial_state(self) -> dict:
        return {
            "schema": STATE_SCHEMA,
            "installation_id": self.installation_id,
            "client_instance_id": self.client_instance_id,
            "generation": 0,
            "sequence": 0,
            "last_authority_time": 0.0,
            "heads": [],
            "nonce_hashes": [],
        }

    def _state_signature(self, state: Mapping[str, object]) -> str:
        body = {key: value for key, value in state.items() if key != "state_signature"}
        return self._state_signature_for_canonical(_canonical(body))

    def _state_signature_for_canonical(self, payload: bytes) -> str:
        """Sign one already-canonical state without serializing it again."""

        try:
            return _sign(self.response_signer, payload)
        except SentinelRequestRejected as exc:
            raise SentinelStateIntegrityError("authority state signer failed") from exc

    def _load_state(self) -> dict:
        self._require_live_lease()
        if self.state_path.is_symlink() or self.state_path.parent.is_symlink():
            raise SentinelStateIntegrityError("authority state path is an alias")
        if not self.state_path.exists():
            if self._initialized:
                raise SentinelStateIntegrityError("authority state disappeared after initialization")
            return self._initial_state()
        try:
            size = self.state_path.stat().st_size
            if not 1 <= size <= 512 * 1024:
                raise SentinelStateIntegrityError("authority state size is invalid")
            raw = self.state_path.read_bytes()
            document = _strict_json(raw, maximum=512 * 1024, exact_keys=_STATE_KEYS)
        except SentinelStateIntegrityError:
            raise
        except Exception as exc:
            raise SentinelStateIntegrityError("authority state is unreadable") from exc
        if (
            document.get("schema") != STATE_SCHEMA
            or document.get("installation_id") != self.installation_id
            or document.get("client_instance_id") != self.client_instance_id
            or type(document.get("generation")) is not int
            or not 0 <= document["generation"] <= 2**63 - 1
            or type(document.get("sequence")) is not int
            or not 0 <= document["sequence"] <= 2**63 - 1
            or not isinstance(document.get("last_authority_time"), (int, float))
            or isinstance(document.get("last_authority_time"), bool)
            or not math.isfinite(float(document["last_authority_time"]))
            or not 0.0 <= float(document["last_authority_time"]) <= 32_503_680_000.0
            or not isinstance(document.get("heads"), list)
            or len(document["heads"]) > len(self.allowed_domains)
            or not isinstance(document.get("nonce_hashes"), list)
            or len(document["nonce_hashes"]) > self._max_nonces
        ):
            raise SentinelStateIntegrityError("authority state identity or bounds are invalid")
        signature = document.get("state_signature")
        try:
            authentic = (
                isinstance(signature, str)
                and self.response_verifier.verify(
                    _canonical(
                        {key: value for key, value in document.items() if key != "state_signature"}
                    ),
                    signature,
                )
                is True
            )
        except Exception as exc:
            raise SentinelStateIntegrityError("authority state verification failed") from exc
        if not authentic:
            raise SentinelStateIntegrityError("authority state signature does not match")
        domains: set[str] = set()
        for item in document["heads"]:
            if not isinstance(item, dict):
                raise SentinelStateIntegrityError("authority head list is invalid")
            domain = item.get("domain")
            if domain in domains:
                raise SentinelStateIntegrityError("authority state contains duplicate domains")
            try:
                _validate_domain(domain, self.allowed_domains)
                _parse_head(item, installation_id=self.installation_id, domain=domain)
            except SentinelRequestRejected as exc:
                raise SentinelStateIntegrityError("authority state contains an invalid head") from exc
            domains.add(domain)
        if any(not isinstance(item, str) or not _HEX_64.fullmatch(item) for item in document["nonce_hashes"]):
            raise SentinelStateIntegrityError("authority nonce history is invalid")
        if len(set(document["nonce_hashes"])) != len(document["nonce_hashes"]):
            raise SentinelStateIntegrityError("authority nonce history is ambiguous")
        state = {key: value for key, value in document.items() if key != "state_signature"}
        if self.generation_floor is not None:
            try:
                anchored = self.generation_floor.read_generation(
                    installation_id=self.installation_id,
                    client_instance_id=self.client_instance_id,
                )
            except Exception as exc:
                raise SentinelStateIntegrityError(
                    "external generation floor is unavailable"
                ) from exc
            if anchored != state["generation"]:
                raise SentinelStateIntegrityError(
                    "authority state generation conflicts with external floor"
                )
        return state

    def _save_state(self, state: dict) -> None:
        self._require_live_lease()
        previous_generation = state.get("generation")
        if type(previous_generation) is not int or not 0 <= previous_generation < 2**63 - 1:
            raise SentinelStateIntegrityError("authority state generation is exhausted")
        state["generation"] = previous_generation + 1
        # This state can approach the 512 KiB admission bound as the replay
        # window fills.  Canonicalize it once, then reuse those exact bytes for
        # both the optional external-floor digest and the state signature.  The
        # final signed document still goes through the normal canonical encoder.
        canonical_state = _canonical(state)
        if self.generation_floor is not None:
            unsigned_digest = hashlib.sha256(canonical_state).hexdigest()
            try:
                advanced = self.generation_floor.compare_and_advance(
                    installation_id=self.installation_id,
                    client_instance_id=self.client_instance_id,
                    previous_generation=previous_generation,
                    generation=state["generation"],
                    state_sha256=unsigned_digest,
                )
            except Exception as exc:
                raise SentinelStateIntegrityError(
                    "external generation floor advance failed"
                ) from exc
            if advanced is not True:
                raise SentinelStateIntegrityError(
                    "external generation floor rejected state transition"
                )
        signed = {
            **state,
            "state_signature": self._state_signature_for_canonical(canonical_state),
        }
        payload = _canonical(signed) + b"\n"
        if len(payload) > 512 * 1024:
            raise SentinelStateIntegrityError("authority state exceeded its byte bound")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(self.state_path.parent, stat.S_IRWXU)
        temp = self.state_path.with_name(
            f".{self.state_path.name}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
        )
        try:
            descriptor = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            replace_with_retry(temp, self.state_path)
            if os.name != "nt":
                os.chmod(self.state_path, stat.S_IRUSR | stat.S_IWUSR)
            self._initialized = True
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    @property
    def rollback_assurance(self) -> str:
        return (
            "external-generation-floor"
            if self.generation_floor is not None
            else "local-signed-state-only"
        )

    def close(self) -> None:
        """Irreversibly stop this authority and release its singleton lease."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            lease = self._lease
            self._lease = None
            if lease is not None:
                lease.close()

    def __enter__(self) -> "PersonalSentinelAuthority":
        with self._lock:
            self._require_live_lease()
            return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _validate_request(self, request_body: bytes, now: float) -> dict:
        request = _strict_json(
            request_body,
            maximum=MAX_REQUEST_BYTES,
            exact_keys=_REQUEST_KEYS,
        )
        if request.get("schema") != REQUEST_SCHEMA:
            raise SentinelRequestRejected("request schema version is invalid")
        operation = request.get("operation")
        if operation not in {"read-head", "compare-and-advance", "time-receipt"}:
            raise SentinelRequestRejected("authority operation is invalid")
        if request.get("installation_id") != self.installation_id:
            raise SentinelRequestRejected("installation identity is not enrolled")
        if request.get("client_instance_id") != self.client_instance_id:
            raise SentinelRequestRejected("client clone or identity mismatch rejected")
        nonce = request.get("nonce")
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            raise SentinelRequestRejected("request nonce is invalid")
        issued_at = _finite_time(request.get("issued_at"), "request time")
        if issued_at > now + self._max_request_age or now - issued_at > self._max_request_age:
            raise SentinelRequestRejected("request is stale or future-dated")
        if request.get("key_id") != self.request_verifier.key_id:
            raise SentinelRequestRejected("request signing key is not enrolled")
        signature = _signature(request.get("signature"))
        body = {key: value for key, value in request.items() if key != "signature"}
        try:
            verified = self.request_verifier.verify(_canonical(body), signature) is True
        except Exception as exc:
            raise SentinelRequestRejected("request signature verification failed") from exc
        if not verified:
            raise SentinelRequestRejected("request signature does not match")
        if not isinstance(request.get("payload"), dict):
            raise SentinelRequestRejected("request payload must be an object")
        return request

    def _advance(self, state: dict, transition: HighWaterTransition) -> HighWaterHead:
        current_document = next(
            (row for row in state["heads"] if row.get("domain") == transition.domain),
            None,
        )
        if current_document is None:
            current_revision = 0
            current_state_digest = ZERO_DIGEST
            current_head = ZERO_DIGEST
        else:
            current = _parse_head(
                current_document,
                installation_id=self.installation_id,
                domain=transition.domain,
            )
            current_revision = current.revision
            current_state_digest = current.state_digest
            current_head = current.head
        if (
            transition.previous_revision != current_revision
            or not hmac.compare_digest(transition.previous_state_digest, current_state_digest)
            or not hmac.compare_digest(transition.previous_head, current_head)
        ):
            raise SentinelRequestRejected("compare-and-swap rejected a duplicate or fork")
        body = {
            "schema": HIGH_WATER_SCHEMA,
            "installation_id": self.installation_id,
            "domain": transition.domain,
            "revision": transition.revision,
            "state_digest": transition.state_digest,
            "previous_head": current_head,
        }
        head = HighWaterHead(**body, head=hashlib.sha256(_canonical(body)).hexdigest())
        state["heads"] = sorted(
            [row for row in state["heads"] if row.get("domain") != transition.domain]
            + [_head_document(head)],
            key=lambda row: row["domain"],
        )
        return head

    def process(self, request_body: bytes, *, now: float | None = None) -> bytes:
        """Authenticate and atomically process one strict request body."""
        with self._lock:
            # Hold the same lock used by close() for the complete transaction,
            # including request validation and response signing.  Shutdown can
            # therefore either precede a request (which is rejected) or follow
            # its complete signed response; it can never release the lease in
            # the middle of state access.
            self._require_live_lease()
            observed = _finite_time(
                self._clock() if now is None else now, "authority time"
            )
            request = self._validate_request(request_body, observed)
            operation = request["operation"]
            nonce = request["nonce"]
            nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            state = self._load_state()
            last_authority_time = float(state["last_authority_time"])
            if observed < last_authority_time - self._clock_rollback_tolerance:
                raise SentinelStateIntegrityError("authority wall clock rolled backward")
            authority_time = max(observed, last_authority_time)
            state["last_authority_time"] = authority_time
            if nonce_hash in state["nonce_hashes"]:
                raise SentinelRequestRejected("request nonce replay was rejected")
            # Consume every authenticated fresh nonce, including one that later
            # loses a CAS race.  A rejected transition can never be replayed.
            state["nonce_hashes"] = [
                *state["nonce_hashes"][-(self._max_nonces - 1) :],
                nonce_hash,
            ]
            state["sequence"] += 1
            try:
                if operation == "read-head":
                    payload = request["payload"]
                    if set(payload) != {"domain"}:
                        raise SentinelRequestRejected("read-head payload schema is invalid")
                    domain = _validate_domain(payload.get("domain"), self.allowed_domains)
                    head = next(
                        (row for row in state["heads"] if row.get("domain") == domain),
                        None,
                    )
                    response_payload = {"head": head}
                elif operation == "compare-and-advance":
                    payload = request["payload"]
                    if set(payload) != {"transition"}:
                        raise SentinelRequestRejected("advance payload schema is invalid")
                    transition = _parse_transition(
                        payload.get("transition"),
                        installation_id=self.installation_id,
                        allowed_domains=self.allowed_domains,
                    )
                    response_payload = {"head": _head_document(self._advance(state, transition))}
                else:
                    if request["payload"]:
                        raise SentinelRequestRejected("time-receipt payload must be empty")
                    response_payload = {
                        "installation_id": self.installation_id,
                        "client_instance_id": self.client_instance_id,
                        "authority_time": authority_time,
                    }
            except Exception:
                self._save_state(state)
                raise
            self._save_state(state)
            response = {
                "schema": RESPONSE_SCHEMA,
                "operation": operation,
                "request_nonce": nonce,
                "sequence": state["sequence"],
                "received_at": authority_time,
                "expires_at": authority_time + self._receipt_lifetime,
                "status": "ok",
                "payload": response_payload,
                "key_id": self.response_signer.key_id,
            }
            response["signature"] = _sign(self.response_signer, _canonical(response))
            encoded = _canonical(response)
            if len(encoded) > MAX_RESPONSE_BYTES:
                raise SentinelAuthorityError("authority response exceeded its byte bound")
            return encoded


@dataclass(frozen=True)
class SentinelTransportResult:
    body: bytes
    tls_verified: bool
    test_only: bool = False


class SentinelTransport(Protocol):
    def exchange(self, body: bytes) -> SentinelTransportResult: ...


class InProcessSentinelTransport:
    """Explicitly test-only transport; production code must not opt into it."""

    def __init__(self, authority: PersonalSentinelAuthority, *, test_only: bool = False) -> None:
        if test_only is not True:
            raise ValueError("in-process Sentinel transport requires explicit test_only=True")
        self._authority = authority

    def exchange(self, body: bytes) -> SentinelTransportResult:
        return SentinelTransportResult(self._authority.process(body), False, True)


class PinnedHttpsSentinelTransport:
    """Direct private HTTPS transport with normal PKI plus a certificate pin."""

    def __init__(
        self,
        endpoint_url: str,
        certificate_sha256: str,
        *,
        transport: GatewayTransport | None = None,
        client_certificate_path: str = "",
        client_key_path: str = "",
        ca_bundle_path: str = "",
        connect_timeout: float = 2.0,
        read_timeout: float = 3.0,
    ) -> None:
        if not isinstance(endpoint_url, str) or not endpoint_url.endswith("/v1/authority"):
            raise ValueError("Sentinel authority endpoint must end with /v1/authority")
        self._enrollment = GatewayEnrollment(
            endpoint_url,
            certificate_sha256,
            ZERO_DIGEST,
            client_certificate_path=client_certificate_path,
            client_key_path=client_key_path,
            ca_bundle_path=ca_bundle_path,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            max_response_bytes=MAX_RESPONSE_BYTES,
        )
        self._transport = transport or StandardHttpsGatewayTransport()

    def _peer_matches(self, peer_ip: str) -> bool:
        import ipaddress

        try:
            peer = ipaddress.ip_address(str(peer_ip).split("%", 1)[0])
        except ValueError:
            return False
        host = self._enrollment._canonical_host
        if host == "localhost":
            return peer.is_loopback
        try:
            return peer == ipaddress.ip_address(host)
        except ValueError:
            return False

    def exchange(self, body: bytes) -> SentinelTransportResult:
        if not isinstance(body, bytes) or not body or len(body) > MAX_REQUEST_BYTES:
            raise HighWaterUnavailable("Sentinel request size is invalid")
        request = GatewayTransportRequest(
            endpoint_url=self._enrollment.endpoint_url,
            body=body,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
                "User-Agent": "Angerona-Personal-Sentinel-Authority/1",
            },
            connect_timeout=self._enrollment.connect_timeout,
            read_timeout=self._enrollment.read_timeout,
            max_response_bytes=MAX_RESPONSE_BYTES,
            client_certificate_path=self._enrollment.client_certificate_path,
            client_key_path=self._enrollment.client_key_path,
            ca_bundle_path=self._enrollment.ca_bundle_path,
            require_tls_validation=True,
        )
        try:
            response = self._transport.send(request)
        except Exception as exc:
            raise HighWaterUnavailable("Sentinel HTTPS authority is unavailable") from exc
        if not isinstance(response, GatewayTransportResponse):
            raise HighWaterRejected("Sentinel transport contract is invalid")
        if response.tls_verified is not True or not self._peer_matches(response.peer_ip):
            raise HighWaterRejected("Sentinel TLS peer is not the enrolled private authority")
        if (
            not isinstance(response.peer_certificate_der, bytes)
            or not response.peer_certificate_der
            or not hmac.compare_digest(
                hashlib.sha256(response.peer_certificate_der).hexdigest(),
                self._enrollment.certificate_sha256,
            )
        ):
            raise HighWaterRejected("Sentinel certificate pin does not match")
        if response.status_code != 200:
            raise HighWaterRejected("Sentinel authority rejected the request")
        if not isinstance(response.headers, Mapping) or len(response.headers) > 64:
            raise HighWaterRejected("Sentinel response headers are invalid")
        content_types = [
            value
            for name, value in response.headers.items()
            if isinstance(name, str) and name.casefold() == "content-type"
        ]
        if (
            len(content_types) != 1
            or not isinstance(content_types[0], str)
            or content_types[0].casefold().split(";", 1)[0].strip() != "application/json"
        ):
            raise HighWaterRejected("Sentinel response content type is invalid")
        if not isinstance(response.body, bytes) or not response.body:
            raise HighWaterRejected("Sentinel response body is invalid")
        return SentinelTransportResult(response.body, True, False)


class PersonalSentinelAuthorityClient:
    """Authenticated client implementing :class:`IndependentHighWater`."""

    def __init__(
        self,
        *,
        installation_id: str,
        client_instance_id: str,
        authenticator: SentinelAuthenticator | None = None,
        request_signer: SentinelSigner | None = None,
        response_verifier: SentinelVerifier | None = None,
        response_floor: SentinelResponseFloor | None = None,
        transport: SentinelTransport,
        clock: Callable[[], float] = time.time,
        nonce_factory: Callable[[], str] | None = None,
        max_response_age: float = 60.0,
        allow_test_transport: bool = False,
    ) -> None:
        self._installation_id = validate_installation_id(installation_id)
        self.client_instance_id = _client_instance_id(client_instance_id)
        self.request_signer = request_signer or authenticator
        self.response_verifier = response_verifier or authenticator
        if self.request_signer is None or self.response_verifier is None:
            raise TypeError("Sentinel client signing contracts are incomplete")
        if not hasattr(self.request_signer, "sign") or not hasattr(
            self.response_verifier, "verify"
        ):
            raise TypeError("Sentinel client signing contract is invalid")
        self.transport = transport
        self.response_floor = response_floor
        self._clock = clock
        self._nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(32))
        if not 1.0 <= float(max_response_age) <= 300.0:
            raise ValueError("Sentinel response freshness bound is invalid")
        self._max_response_age = float(max_response_age)
        self._allow_test_transport = bool(allow_test_transport)
        self._last_sequence = 0
        self._lock = threading.RLock()

    @property
    def installation_id(self) -> str:
        return self._installation_id

    def _request(self, operation: str, payload: dict) -> tuple[dict, str]:
        try:
            now = _finite_time(self._clock(), "client time")
            nonce = self._nonce_factory()
        except Exception as exc:
            raise HighWaterUnavailable("Sentinel client clock or nonce source is unavailable") from exc
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            raise HighWaterRejected("Sentinel client nonce is invalid")
        request = {
            "schema": REQUEST_SCHEMA,
            "operation": operation,
            "installation_id": self.installation_id,
            "client_instance_id": self.client_instance_id,
            "nonce": nonce,
            "issued_at": now,
            "key_id": self.request_signer.key_id,
            "payload": payload,
        }
        try:
            request["signature"] = _sign(self.request_signer, _canonical(request))
        except SentinelRequestRejected as exc:
            raise HighWaterUnavailable("Sentinel client signer is unavailable") from exc
        try:
            exchange = self.transport.exchange(_canonical(request))
        except SentinelRequestRejected as exc:
            raise HighWaterRejected("Sentinel authority rejected the request") from exc
        except (HighWaterRejected, HighWaterUnavailable):
            raise
        except Exception as exc:
            raise HighWaterUnavailable("Sentinel authority transport failed") from exc
        if not isinstance(exchange, SentinelTransportResult):
            raise HighWaterRejected("Sentinel transport result is invalid")
        if exchange.test_only:
            if not self._allow_test_transport or exchange.tls_verified:
                raise HighWaterRejected("Sentinel test transport was not explicitly authorized")
        elif exchange.tls_verified is not True:
            raise HighWaterRejected("Sentinel production transport did not verify TLS")
        response = _strict_json(
            exchange.body,
            maximum=MAX_RESPONSE_BYTES,
            exact_keys=_RESPONSE_KEYS,
        )
        if (
            response.get("schema") != RESPONSE_SCHEMA
            or response.get("operation") != operation
            or response.get("request_nonce") != nonce
            or response.get("status") != "ok"
            or response.get("key_id") != self.response_verifier.key_id
            or not isinstance(response.get("payload"), dict)
        ):
            raise HighWaterRejected("Sentinel response identity or schema is invalid")
        signature = _signature(response.get("signature"))
        signed = {key: value for key, value in response.items() if key != "signature"}
        if self.response_verifier.verify(_canonical(signed), signature) is not True:
            raise HighWaterRejected("Sentinel response signature does not match")
        received = _finite_time(response.get("received_at"), "receipt time")
        expires = _finite_time(response.get("expires_at"), "receipt expiry")
        if received > now + self._max_response_age or now - received > self._max_response_age:
            raise HighWaterRejected("Sentinel response is stale or future-dated")
        if expires <= received or expires < now or expires - received > 300.0:
            raise HighWaterRejected("Sentinel response lifetime is invalid")
        sequence = response.get("sequence")
        if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
            raise HighWaterRejected("Sentinel authority sequence is invalid")
        with self._lock:
            if sequence <= self._last_sequence:
                raise HighWaterRejected("Sentinel response sequence replay or rollback detected")
            if self.response_floor is None:
                if not exchange.test_only:
                    raise HighWaterRejected(
                        "Sentinel production client has no durable response floor"
                    )
            else:
                try:
                    advanced = self.response_floor.compare_and_advance(
                        namespace=TRANSPORT_RESPONSE_FLOOR_NAMESPACE,
                        installation_id=self.installation_id,
                        client_instance_id=self.client_instance_id,
                        sequence=sequence,
                        received_at=received,
                    )
                except Exception as exc:
                    raise HighWaterRejected(
                        "Sentinel durable response floor is unavailable"
                    ) from exc
                if advanced is not True:
                    raise HighWaterRejected(
                        "Sentinel durable response floor rejected replay or rollback"
                    )
            self._last_sequence = sequence
        return response, signature

    def read_head(self, domain: str) -> HighWaterHead | None:
        response, _signature_value = self._request("read-head", {"domain": domain})
        payload = response["payload"]
        if set(payload) != {"head"}:
            raise HighWaterRejected("Sentinel read response payload is invalid")
        if payload["head"] is None:
            return None
        return _parse_head(
            payload["head"], installation_id=self.installation_id, domain=domain
        )

    def compare_and_advance(self, transition: HighWaterTransition) -> HighWaterHead:
        if not isinstance(transition, HighWaterTransition):
            raise HighWaterRejected("Sentinel transition contract is invalid")
        response, _signature_value = self._request(
            "compare-and-advance",
            {"transition": asdict(transition)},
        )
        payload = response["payload"]
        if set(payload) != {"head"}:
            raise HighWaterRejected("Sentinel advance response payload is invalid")
        return _parse_head(
            payload["head"],
            installation_id=self.installation_id,
            domain=transition.domain,
        )

    def get_time_receipt(self) -> SignedTimeReceipt:
        response, signature = self._request("time-receipt", {})
        payload = response["payload"]
        if set(payload) != {"installation_id", "client_instance_id", "authority_time"}:
            raise HighWaterRejected("Sentinel time response payload is invalid")
        if (
            payload["installation_id"] != self.installation_id
            or payload["client_instance_id"] != self.client_instance_id
            or float(payload["authority_time"]) != float(response["received_at"])
        ):
            raise HighWaterRejected("Sentinel time response identity is invalid")
        return SignedTimeReceipt(
            operation="time-receipt",
            request_nonce=response["request_nonce"],
            sequence=response["sequence"],
            received_at=float(response["received_at"]),
            expires_at=float(response["expires_at"]),
            installation_id=self.installation_id,
            client_instance_id=self.client_instance_id,
            key_id=response["key_id"],
            signature=signature,
        )


def self_test() -> tuple[bool, str]:
    """Exercise the full signed CAS/time path without opening a socket."""

    import tempfile

    key = b"angerona-personal-sentinel-authority-self-test-key"
    auth = HmacSha256Authenticator(key)
    now = 1_800_000_000.0
    installation = "a" * 32
    instance = "b" * 32
    nonces = iter(("c" * 43, "d" * 43, "e" * 43))
    try:
        with tempfile.TemporaryDirectory(prefix="angerona-sentinel-authority-") as root:
            with PersonalSentinelAuthority(
                Path(root) / "state.json",
                installation_id=installation,
                client_instance_id=instance,
                authenticator=auth,
                clock=lambda: now,
                max_nonces=64,
            ) as authority:
                client = PersonalSentinelAuthorityClient(
                    installation_id=installation,
                    client_instance_id=instance,
                    authenticator=auth,
                    transport=InProcessSentinelTransport(authority, test_only=True),
                    clock=lambda: now,
                    nonce_factory=lambda: next(nonces),
                    allow_test_transport=True,
                )
                if client.read_head(AUDIT_DOMAIN) is not None:
                    return False, "new authority unexpectedly returned a head"
                transition = HighWaterTransition(
                    HIGH_WATER_SCHEMA,
                    installation,
                    AUDIT_DOMAIN,
                    0,
                    ZERO_DIGEST,
                    ZERO_DIGEST,
                    1,
                    "1" * 64,
                )
                head = client.compare_and_advance(transition)
                receipt = client.get_time_receipt()
                if head.revision != 1 or not receipt.verify(auth):
                    return False, "signed head or time receipt did not verify"
    except Exception as exc:
        return False, f"Personal Sentinel authority self-test failed: {exc}"
    return True, "signed private CAS authority and nonce-bound time receipt verified offline"


__all__ = [
    "DEFAULT_ALLOWED_DOMAINS",
    "Ed25519PrivateSigner",
    "Ed25519PublicVerifier",
    "HmacSha256Authenticator",
    "InProcessSentinelTransport",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "PersonalSentinelAuthority",
    "PersonalSentinelAuthorityClient",
    "PinnedHttpsSentinelTransport",
    "REQUEST_SCHEMA",
    "RESPONSE_SCHEMA",
    "STATE_SCHEMA",
    "SentinelAuthenticator",
    "SentinelAuthorityError",
    "SentinelRequestRejected",
    "SentinelStateIntegrityError",
    "SentinelSigner",
    "SentinelResponseFloor",
    "SentinelGenerationFloor",
    "SentinelTransport",
    "SentinelTransportResult",
    "SentinelVerifier",
    "SignedTimeReceipt",
    "TRANSPORT_RESPONSE_FLOOR_NAMESPACE",
    "TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE",
    "self_test",
]
