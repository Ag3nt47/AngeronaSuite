"""Bounded in-memory credentials for the local fleet service boundary.

The registry deliberately owns no persistence or operating-system key custody.
It is an immutable runtime view that a transport authenticator may use to look
up one active credential and, only after proving the request signature, create
a secret-free :class:`AuthenticatedFleetContext`.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

MAX_FLEET_CREDENTIALS = 10_000
MAX_FLEET_PERMISSIONS = 256
MAX_FLEET_SECRET_BYTES = 4096
MAX_LOCAL_FLEET_BUNDLE_BYTES = 32 * 1024
MAX_LOCAL_FLEET_CREDENTIALS = 8

INTERNAL_FLEET_CREDENTIALS_KEY = "ANGERONA_INTERNAL_FLEET_CREDENTIALS_V1"
LEGACY_FLEET_SERVICE_KEY = "ANGERONA_FLEET_SERVICE_KEY"
LOCAL_FLEET_CREDENTIAL_SCHEMA = "angerona.local-fleet-credentials/v1"
LOCAL_FLEET_OPERATOR_CREDENTIAL_ID = "local-operator"
LOCAL_FLEET_DEVICE_CREDENTIAL_ID = "local-device"

_LOCAL_OPERATOR_PERMISSIONS = (
    "fleet.capabilities.read",
    "fleet.contract.read",
    "fleet.device.read",
    "fleet.device.register",
    "fleet.event.read",
    "fleet.health.read",
)
_LOCAL_DEVICE_PERMISSIONS = (
    "fleet.capabilities.read",
    "fleet.event.ingest",
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_PERMISSION_SEGMENT = re.compile(r"[a-z][a-z0-9_-]*|\*")


class FleetCredentialKind(str, Enum):
    """The identity boundary to which a fleet credential is pinned."""

    TENANT = "tenant"
    DEVICE = "device"


def _validate_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _validate_timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be finite and non-negative")
    try:
        stamp = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError(
            f"{label} must be finite and non-negative"
        ) from exc
    if not math.isfinite(stamp) or stamp < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return stamp


def _validate_permission(permission: object) -> str:
    if not isinstance(permission, str):
        raise ValueError("invalid fleet permission")
    parts = permission.split(".")
    if not 2 <= len(parts) <= 5 or any(
        not _PERMISSION_SEGMENT.fullmatch(part) for part in parts
    ):
        raise ValueError("invalid fleet permission")
    if "*" in parts[:-1]:
        raise ValueError("fleet permission wildcard is allowed only at the end")
    return permission


def _validate_permissions(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        raise ValueError("fleet permissions must be a non-empty tuple")
    if len(value) > MAX_FLEET_PERMISSIONS:
        raise ValueError("fleet permission bound exceeded")
    permissions = tuple(_validate_permission(item) for item in value)
    if len(set(permissions)) != len(permissions):
        raise ValueError("duplicate fleet permission")
    return tuple(sorted(permissions))


def _matches_permission(rule: str, requested: str) -> bool:
    return rule == requested or (
        rule.endswith(".*") and requested.startswith(rule[:-1])
    )


@dataclass(frozen=True)
class FleetCredential:
    """One immutable HMAC credential bound to one tenant or one device."""

    credential_id: str
    tenant_id: str
    kind: FleetCredentialKind
    secret: bytes = field(repr=False)
    permissions: tuple[str, ...]
    device_id: str = ""
    not_before: float = 0
    expires_at: float = 0
    revoked_at: float = 0

    def __post_init__(self) -> None:
        _validate_identifier(self.credential_id, "fleet credential ID")
        _validate_identifier(self.tenant_id, "fleet credential tenant ID")
        if not isinstance(self.kind, FleetCredentialKind):
            raise ValueError("invalid fleet credential kind")
        if not isinstance(self.secret, bytes):
            raise ValueError("fleet credential secret must be immutable bytes")
        if not 32 <= len(self.secret) <= MAX_FLEET_SECRET_BYTES:
            raise ValueError("fleet credential secret has an invalid bounded size")
        object.__setattr__(self, "secret", bytes(self.secret))
        object.__setattr__(
            self, "permissions", _validate_permissions(self.permissions)
        )

        if self.kind is FleetCredentialKind.DEVICE:
            _validate_identifier(self.device_id, "fleet credential device ID")
        elif self.device_id:
            raise ValueError("tenant credentials must not bind a device ID")

        not_before = _validate_timestamp(self.not_before, "credential not-before")
        expires_at = _validate_timestamp(self.expires_at, "credential expiry")
        revoked_at = _validate_timestamp(self.revoked_at, "credential revocation")
        if expires_at and expires_at <= not_before:
            raise ValueError("credential expiry must follow its not-before time")
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "revoked_at", revoked_at)

    def is_active(self, now: float) -> bool:
        """Return whether this immutable credential is valid at ``now``."""
        stamp = _validate_timestamp(now, "credential resolution time")
        return (
            stamp >= self.not_before
            and (not self.expires_at or stamp < self.expires_at)
            and (not self.revoked_at or stamp < self.revoked_at)
        )

    def authenticated_context(self, authenticated_at: float) -> AuthenticatedFleetContext:
        """Create the secret-free context after a caller verifies authentication."""
        stamp = _validate_timestamp(authenticated_at, "authentication time")
        if not self.is_active(stamp):
            raise ValueError("fleet credential is not active")
        return AuthenticatedFleetContext(
            credential_id=self.credential_id,
            tenant_id=self.tenant_id,
            kind=self.kind,
            permissions=self.permissions,
            device_id=self.device_id,
            authenticated_at=stamp,
        )


@dataclass(frozen=True)
class AuthenticatedFleetContext:
    """Secret-free identity and authority resulting from fleet authentication."""

    credential_id: str
    tenant_id: str
    kind: FleetCredentialKind
    permissions: tuple[str, ...]
    device_id: str = ""
    authenticated_at: float = 0

    def __post_init__(self) -> None:
        _validate_identifier(self.credential_id, "fleet credential ID")
        _validate_identifier(self.tenant_id, "fleet credential tenant ID")
        if not isinstance(self.kind, FleetCredentialKind):
            raise ValueError("invalid fleet credential kind")
        object.__setattr__(
            self, "permissions", _validate_permissions(self.permissions)
        )
        if self.kind is FleetCredentialKind.DEVICE:
            _validate_identifier(self.device_id, "fleet credential device ID")
        elif self.device_id:
            raise ValueError("tenant contexts must not bind a device ID")
        object.__setattr__(
            self,
            "authenticated_at",
            _validate_timestamp(self.authenticated_at, "authentication time"),
        )

    @property
    def principal_id(self) -> str:
        """Return a canonical service-principal ID for authorization/audit use."""
        return f"fleet-credential:{self.credential_id}"

    @property
    def scope(self) -> str:
        """Return the narrowest authorization scope represented by the context."""
        scope = f"fleet/{self.tenant_id}"
        if self.device_id:
            return f"{scope}/device/{self.device_id}"
        return scope

    def allows(self, permission: str) -> bool:
        """Apply the same terminal-wildcard grammar as local authorization."""
        requested = _validate_permission(permission)
        return any(
            _matches_permission(rule, requested) for rule in self.permissions
        )


class FleetCredentialRegistry:
    """Immutable, bounded credential lookup used by a request authenticator."""

    def __init__(
        self,
        credentials: Sequence[FleetCredential],
        *,
        max_credentials: int = MAX_FLEET_CREDENTIALS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            isinstance(max_credentials, bool)
            or not isinstance(max_credentials, int)
            or not 1 <= max_credentials <= MAX_FLEET_CREDENTIALS
        ):
            raise ValueError("invalid fleet credential registry bound")
        if not isinstance(credentials, Sequence) or isinstance(
            credentials, (str, bytes, bytearray)
        ):
            raise TypeError("fleet credentials must be a bounded sequence")
        if len(credentials) > max_credentials:
            raise ValueError("fleet credential registry bound exceeded")
        if not callable(clock):
            raise TypeError("fleet credential registry clock must be callable")

        credential_map: dict[str, FleetCredential] = {}
        for credential in credentials:
            if not isinstance(credential, FleetCredential):
                raise TypeError("registry entries must be FleetCredential values")
            if credential.credential_id in credential_map:
                raise ValueError("duplicate fleet credential ID")
            credential_map[credential.credential_id] = credential
        self._credentials: Mapping[str, FleetCredential] = MappingProxyType(
            credential_map
        )
        self._max_credentials = max_credentials
        self._clock = clock

    def _time(self, now: float | None) -> float:
        try:
            value = self._clock() if now is None else now
        except Exception as exc:
            raise RuntimeError("fleet credential clock is unavailable") from exc
        try:
            return _validate_timestamp(value, "credential resolution time")
        except ValueError as exc:
            raise RuntimeError("fleet credential clock is unavailable") from exc

    def resolve(
        self, credential_id: object, *, now: float | None = None
    ) -> FleetCredential | None:
        """Resolve one active credential, using one generic miss result.

        Unknown, malformed, pending, expired, and revoked identifiers all yield
        ``None`` so an authentication boundary need not expose credential state.
        """
        stamp = self._time(now)
        if not isinstance(credential_id, str) or not _IDENTIFIER.fullmatch(
            credential_id
        ):
            return None
        credential = self._credentials.get(credential_id)
        if credential is None or not credential.is_active(stamp):
            return None
        return credential

    def public_snapshot(
        self, *, now: float | None = None
    ) -> Mapping[str, int | str]:
        """Return fixed-key aggregate health without secrets or identifiers."""
        stamp = self._time(now)
        counts = {
            "active": 0,
            "pending": 0,
            "expired": 0,
            "revoked": 0,
            "tenant": 0,
            "device": 0,
        }
        for credential in self._credentials.values():
            counts[credential.kind.value] += 1
            if credential.revoked_at and stamp >= credential.revoked_at:
                counts["revoked"] += 1
            elif credential.expires_at and stamp >= credential.expires_at:
                counts["expired"] += 1
            elif stamp < credential.not_before:
                counts["pending"] += 1
            else:
                counts["active"] += 1
        return MappingProxyType({
            "schema": "angerona.fleet-credential-registry/v1",
            "configured": len(self._credentials),
            "capacity": self._max_credentials,
            "active": counts["active"],
            "pending": counts["pending"],
            "expired": counts["expired"],
            "revoked": counts["revoked"],
            "tenant_credentials": counts["tenant"],
            "device_credentials": counts["device"],
        })


@dataclass(frozen=True)
class LocalFleetCredentialSet:
    """One protected single-tenant runtime bundle with separated key duties."""

    tenant_id: str
    device_id: str
    receipt_signing_key: bytes = field(repr=False)
    authorization_audit_key: bytes = field(repr=False)
    registry: FleetCredentialRegistry = field(repr=False)
    operator_credential: FleetCredential = field(repr=False)
    device_credential: FleetCredential = field(repr=False)

    def __post_init__(self) -> None:
        _validate_identifier(self.tenant_id, "local fleet tenant ID")
        _validate_identifier(self.device_id, "local fleet device ID")
        if not isinstance(self.registry, FleetCredentialRegistry):
            raise TypeError("local fleet registry is invalid")
        if not isinstance(self.operator_credential, FleetCredential) or not isinstance(
            self.device_credential, FleetCredential
        ):
            raise TypeError("local fleet credential access is invalid")
        for value, label in (
            (self.receipt_signing_key, "receipt signing key"),
            (self.authorization_audit_key, "authorization audit key"),
        ):
            if not isinstance(value, bytes) or len(value) != 32:
                raise ValueError(f"local fleet {label} must contain 32 bytes")
        object.__setattr__(
            self, "receipt_signing_key", bytes(self.receipt_signing_key)
        )
        object.__setattr__(
            self,
            "authorization_audit_key",
            bytes(self.authorization_audit_key),
        )
        operator = self.operator_credential
        device = self.device_credential
        if (
            operator.credential_id != LOCAL_FLEET_OPERATOR_CREDENTIAL_ID
            or operator.tenant_id != self.tenant_id
            or operator.kind is not FleetCredentialKind.TENANT
            or operator.device_id
            or operator.permissions != _LOCAL_OPERATOR_PERMISSIONS
        ):
            raise ValueError("local fleet operator credential binding is invalid")
        if (
            device.credential_id != LOCAL_FLEET_DEVICE_CREDENTIAL_ID
            or device.tenant_id != self.tenant_id
            or device.kind is not FleetCredentialKind.DEVICE
            or device.device_id != self.device_id
            or device.permissions != _LOCAL_DEVICE_PERMISSIONS
        ):
            raise ValueError("local fleet device credential binding is invalid")
        registered_operator = self.registry._credentials.get(  # noqa: SLF001
            LOCAL_FLEET_OPERATOR_CREDENTIAL_ID
        )
        registered_device = self.registry._credentials.get(  # noqa: SLF001
            LOCAL_FLEET_DEVICE_CREDENTIAL_ID
        )
        if registered_operator != operator or registered_device != device:
            raise ValueError("local fleet registry does not contain its credentials")
        keys = {
            operator.secret,
            device.secret,
            self.receipt_signing_key,
            self.authorization_audit_key,
        }
        if len(keys) != 4:
            raise ValueError("local fleet key duties must use distinct keys")

    @property
    def operator(self) -> FleetCredential:
        """Return the tenant-bound operator credential."""
        return self.operator_credential

    @property
    def device(self) -> FleetCredential:
        """Return the endpoint-bound ingestion credential."""
        return self.device_credential


_BUNDLE_FIELDS = frozenset({
    "schema",
    "tenant_id",
    "device_id",
    "receipt_signing_key",
    "authorization_audit_key",
    "credentials",
})
_CREDENTIAL_FIELDS = frozenset({
    "credential_id",
    "tenant_id",
    "kind",
    "secret",
    "permissions",
    "device_id",
    "not_before",
    "expires_at",
    "revoked_at",
})
_BASE64URL = re.compile(r"[A-Za-z0-9_-]{43}")


def _b64url_key(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_b64url_key(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value):
        raise ValueError(f"local fleet {label} is not canonical base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            f"local fleet {label} is not canonical base64url"
        ) from exc
    if len(raw) != 32 or _b64url_key(raw) != value:
        raise ValueError(f"local fleet {label} is not canonical base64url")
    return raw


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate local fleet bundle field: {key}")
        value[key] = item
    return value


def _require_fields(
    value: object, expected: frozenset[str], label: str
) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"local fleet {label} must be an object")
    typed = value
    if set(typed) != expected:
        raise ValueError(f"local fleet {label} has unknown or missing fields")
    return typed


def _serialize_local_bundle(
    tenant_id: str,
    device_id: str,
    receipt_signing_key: bytes,
    authorization_audit_key: bytes,
    credentials: Sequence[FleetCredential],
) -> str:
    value = {
        "schema": LOCAL_FLEET_CREDENTIAL_SCHEMA,
        "tenant_id": tenant_id,
        "device_id": device_id,
        "receipt_signing_key": _b64url_key(receipt_signing_key),
        "authorization_audit_key": _b64url_key(authorization_audit_key),
        "credentials": [
            {
                "credential_id": item.credential_id,
                "tenant_id": item.tenant_id,
                "kind": item.kind.value,
                "secret": _b64url_key(item.secret),
                "permissions": list(item.permissions),
                "device_id": item.device_id,
                "not_before": item.not_before,
                "expires_at": item.expires_at,
                "revoked_at": item.revoked_at,
            }
            for item in credentials
        ],
    }
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    if len(encoded.encode("utf-8")) > MAX_LOCAL_FLEET_BUNDLE_BYTES:
        raise ValueError("local fleet credential bundle exceeds its byte bound")
    return encoded


def _load_local_bundle(
    encoded: object,
    *,
    tenant_id: str,
    device_id: str,
    clock: Callable[[], float],
) -> LocalFleetCredentialSet:
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("protected local fleet credential bundle is invalid")
    try:
        raw = encoded.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(
            "protected local fleet credential bundle is not valid UTF-8"
        ) from exc
    if len(raw) > MAX_LOCAL_FLEET_BUNDLE_BYTES:
        raise ValueError("local fleet credential bundle exceeds its byte bound")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite local fleet value: {token}")
            ),
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ValueError("protected local fleet credential bundle is invalid") from exc
    bundle = _require_fields(value, _BUNDLE_FIELDS, "credential bundle")
    if bundle["schema"] != LOCAL_FLEET_CREDENTIAL_SCHEMA:
        raise ValueError("unsupported local fleet credential schema")
    if bundle["tenant_id"] != tenant_id or bundle["device_id"] != device_id:
        raise ValueError("local fleet credential tenant or device binding mismatch")
    _validate_identifier(bundle["tenant_id"], "local fleet tenant ID")
    _validate_identifier(bundle["device_id"], "local fleet device ID")

    rows = bundle["credentials"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_LOCAL_FLEET_CREDENTIALS:
        raise ValueError("local fleet credential count is invalid")
    credentials: list[FleetCredential] = []
    for row_value in rows:
        row = _require_fields(row_value, _CREDENTIAL_FIELDS, "credential")
        permissions = row["permissions"]
        if not isinstance(permissions, list):
            raise ValueError("local fleet credential permissions must be an array")
        try:
            kind = FleetCredentialKind(row["kind"])
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid local fleet credential kind") from exc
        credentials.append(FleetCredential(
            credential_id=row["credential_id"],
            tenant_id=row["tenant_id"],
            kind=kind,
            secret=_decode_b64url_key(row["secret"], "credential key"),
            permissions=tuple(permissions),
            device_id=row["device_id"],
            not_before=row["not_before"],
            expires_at=row["expires_at"],
            revoked_at=row["revoked_at"],
        ))
    credential_ids = {item.credential_id for item in credentials}
    expected_ids = {
        LOCAL_FLEET_OPERATOR_CREDENTIAL_ID,
        LOCAL_FLEET_DEVICE_CREDENTIAL_ID,
    }
    if len(credentials) != 2 or credential_ids != expected_ids:
        raise ValueError("local fleet bundle must contain its exact credential set")

    registry = FleetCredentialRegistry(
        tuple(credentials),
        max_credentials=MAX_LOCAL_FLEET_CREDENTIALS,
        clock=clock,
    )
    try:
        stamp = registry._time(None)  # noqa: SLF001
        operator = registry.resolve(
            LOCAL_FLEET_OPERATOR_CREDENTIAL_ID, now=stamp
        )
        device = registry.resolve(LOCAL_FLEET_DEVICE_CREDENTIAL_ID, now=stamp)
    except RuntimeError:
        raise
    if operator is None or device is None:
        raise RuntimeError("protected local fleet credential is inactive")
    return LocalFleetCredentialSet(
        tenant_id=tenant_id,
        device_id=device_id,
        receipt_signing_key=_decode_b64url_key(
            bundle["receipt_signing_key"], "receipt signing key"
        ),
        authorization_audit_key=_decode_b64url_key(
            bundle["authorization_audit_key"], "authorization audit key"
        ),
        registry=registry,
        operator_credential=operator,
        device_credential=device,
    )


def _random_distinct_key(excluded: set[bytes]) -> bytes:
    for _ in range(16):
        candidate = secrets.token_bytes(32)
        if len(candidate) == 32 and candidate not in excluded:
            return candidate
    raise RuntimeError("could not generate an independent local fleet key")


def _cleanup_legacy_fleet_key(secure_store: Any, data_root: Path) -> None:
    try:
        secure_store.write_secret_map({LEGACY_FLEET_SERVICE_KEY: ""}, data_root)
    except Exception:
        # The V1 bundle was verified before cleanup. Its presence makes retrying
        # this idempotent cleanup on the next load safe and deterministic.
        pass


def load_or_migrate_local_credentials(
    data_root: Path,
    tenant_id: str,
    device_id: str,
    legacy_secret: str = "",
    clock: Callable[[], float] = time.time,
) -> LocalFleetCredentialSet:
    """Load V1 protected credentials or atomically migrate the legacy secret.

    An existing V1 bundle always wins, including when it is corrupt: a legacy
    value must never silently replace protected credential state. Migration
    writes and byte-verifies V1 before separately requesting legacy cleanup.
    """
    from angerona.core import secure_store

    root = Path(data_root)
    tenant = _validate_identifier(tenant_id, "local fleet tenant ID")
    device = _validate_identifier(device_id, "local fleet device ID")
    if not callable(clock):
        raise TypeError("local fleet credential clock must be callable")
    values = secure_store.read_secret_map(root)
    if not isinstance(values, Mapping):
        raise RuntimeError("protected credential store returned an invalid map")

    existing = values.get(INTERNAL_FLEET_CREDENTIALS_KEY)
    if existing is not None:
        loaded = _load_local_bundle(
            existing, tenant_id=tenant, device_id=device, clock=clock
        )
        if LEGACY_FLEET_SERVICE_KEY in values:
            _cleanup_legacy_fleet_key(secure_store, root)
        return loaded

    protected_legacy = values.get(LEGACY_FLEET_SERVICE_KEY, "")
    source_secret = protected_legacy or legacy_secret
    if not isinstance(source_secret, str) or len(source_secret) < 32:
        raise RuntimeError("protected legacy fleet credential is unavailable")
    try:
        legacy_bytes = source_secret.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("legacy fleet credential is not valid UTF-8") from exc
    if len(legacy_bytes) > MAX_FLEET_SECRET_BYTES:
        raise ValueError("legacy fleet credential exceeds its byte bound")

    operator_key = hashlib.sha256(
        b"angerona-fleet-service-v1\0" + legacy_bytes
    ).digest()
    receipt_key = hmac.new(
        operator_key,
        b"angerona-fleet-tenant-v1\0" + tenant.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    used_keys = {operator_key, receipt_key}
    device_key = _random_distinct_key(used_keys)
    used_keys.add(device_key)
    audit_key = _random_distinct_key(used_keys)
    credentials = (
        FleetCredential(
            credential_id=LOCAL_FLEET_OPERATOR_CREDENTIAL_ID,
            tenant_id=tenant,
            kind=FleetCredentialKind.TENANT,
            secret=operator_key,
            permissions=_LOCAL_OPERATOR_PERMISSIONS,
        ),
        FleetCredential(
            credential_id=LOCAL_FLEET_DEVICE_CREDENTIAL_ID,
            tenant_id=tenant,
            kind=FleetCredentialKind.DEVICE,
            secret=device_key,
            permissions=_LOCAL_DEVICE_PERMISSIONS,
            device_id=device,
        ),
    )
    encoded = _serialize_local_bundle(
        tenant, device, receipt_key, audit_key, credentials
    )
    secure_store.write_secret_map(
        {INTERNAL_FLEET_CREDENTIALS_KEY: encoded}, root
    )
    verified_values = secure_store.read_secret_map(root)
    verified = verified_values.get(INTERNAL_FLEET_CREDENTIALS_KEY)
    if not isinstance(verified, str):
        raise RuntimeError("protected local fleet credential write did not verify")
    try:
        exact = hmac.compare_digest(
            verified.encode("utf-8"), encoded.encode("utf-8")
        )
    except UnicodeEncodeError as exc:
        raise RuntimeError(
            "protected local fleet credential write did not verify"
        ) from exc
    if not exact:
        raise RuntimeError("protected local fleet credential write did not verify")
    loaded = _load_local_bundle(
        verified, tenant_id=tenant, device_id=device, clock=clock
    )
    _cleanup_legacy_fleet_key(secure_store, root)
    return loaded
