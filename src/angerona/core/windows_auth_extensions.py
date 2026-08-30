"""Bounded, observation-only Windows authentication-extension integrity evidence.

The collector in this module reads a fixed registry catalogue.  It never loads a
registered DLL, executes a registry-derived command, searches ``PATH``, reads
credentials, or inspects LSASS memory.  Registry strings can identify files only
through an absolute local path, one of a small set of WinAPI-derived Windows
directory aliases, or a package basename resolved against WinAPI-derived
System32.

Persistent snapshots contain purpose-keyed tokens rather than raw local paths.
Raw paths are retained only in the bounded, immutable ``local_details`` member of
the in-memory collection returned to the local UI.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import stat
import sys
import threading
import time
from typing import Any, Callable, Final, Iterator, Mapping, Protocol, Sequence


AUTH_EXTENSION_SCHEMA: Final = "angerona.windows-auth-extension-snapshot.v1"
BASELINE_SCHEMA: Final = "angerona.windows-auth-extension-baseline.v2"
_TRUSTED_SLOT_SCHEMA: Final = "angerona.windows-auth-extension-trusted-slot.v1"
SURFACE_IDS: Final = (
    "lsa.authentication-packages",
    "lsa.notification-packages",
    "lsa.security-packages",
    "credential.providers",
    "credential.provider-filters",
    "network.providers",
)
MAX_BINDINGS: Final = 512
MAX_BINDINGS_PER_SURFACE: Final = 42
MAX_COMPONENTS: Final = 256
MAX_LOCAL_DETAILS: Final = 256
MAX_COMPONENT_BYTES: Final = 128 * 1024 * 1024
MAX_TOTAL_COMPONENT_BYTES: Final = 512 * 1024 * 1024
MAX_COLLECTION_SECONDS: Final = 45.0
MAX_BASELINE_BYTES: Final = 512 * 1024
MAX_BASELINE_JSON_DEPTH: Final = 12
MAX_BASELINE_JSON_NODES: Final = 32_768
MAX_BASELINE_OBJECT_FIELDS: Final = 32
MAX_BASELINE_STRING_BYTES: Final = 8 * 1024
_MAX_TRUSTED_SLOT_BYTES: Final = 2 * 1024
MAX_CHANGES: Final = 256
MAX_BASELINE_FRESHNESS_SECONDS: Final = 7 * 24 * 60 * 60
DEFAULT_BASELINE_FRESHNESS_SECONDS: Final = 24 * 60 * 60
_ENROLLMENT_LOCK_NAME: Final = ".angerona-windows-auth-extensions.enrollment.lock"
_TRUSTED_SLOT_NAME: Final = ".angerona-windows-auth-extensions.trusted-slot.json"
_BASELINE_RELATIVE_PARTS: Final = ("baselines", "windows_auth_extensions.json")
_WINDOWS_REPLACE_RETRY_ERROR: Final = 1175  # ERROR_UNABLE_TO_REMOVE_REPLACED
_WINDOWS_REPLACE_RETRY_DELAYS: Final = (0.005, 0.020, 0.050)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_-]{1,20}:v1:[0-9a-f]{32}$")
_CLSID = re.compile(r"^\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}$")
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SAFE_VERSION = re.compile(r"^[0-9A-Za-z .,_+()\[\]-]{1,160}$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

_LSA_ROOT = r"SYSTEM\CurrentControlSet\Control\Lsa"
_CREDENTIAL_ROOTS = {
    "credential.providers": (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
    ),
    "credential.provider-filters": (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters"
    ),
}
_NETWORK_ORDER = r"SYSTEM\CurrentControlSet\Control\NetworkProvider\Order"


class AuthExtensionError(ValueError):
    """Authentication-extension evidence violated its bounded contract."""


class BaselineIntegrityError(AuthExtensionError):
    """A persisted baseline is malformed, unauthenticated, or unsafe to access."""


class BaselineEnrollmentError(AuthExtensionError):
    """An operator enrollment request is incomplete or unsafe."""


def _bounded_text(value: object, label: str, *, maximum: int = 1000) -> str:
    if not isinstance(value, str):
        raise AuthExtensionError(f"{label} must be text")
    if value != value.strip() or not value or len(value) > maximum:
        raise AuthExtensionError(f"{label} is empty or oversized")
    if any(ord(character) < 32 for character in value):
        raise AuthExtensionError(f"{label} contains control characters")
    return value


def _optional_text(value: object, label: str, *, maximum: int = 1000) -> str:
    if value == "":
        return ""
    return _bounded_text(value, label, maximum=maximum)


def _path_free_reason(value: object, label: str, *, required: bool) -> str:
    text = (
        _bounded_text(value, label)
        if required
        else _optional_text(value, label)
    )
    if "\\" in text or "/" in text or re.search(r"(?i)\b[A-Z]:[\\/]", text):
        raise AuthExtensionError(f"{label} must not contain a local path")
    return text


def _bounded_int(value: object, label: str, *, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise AuthExtensionError(f"{label} is outside its allowed range")
    return value


def _token(key: bytes, namespace: bytes, value: str, prefix: str) -> str:
    digest = hmac.new(
        key,
        namespace + b"\0" + value.casefold().encode("utf-8", "surrogatepass"),
        hashlib.sha256,
    ).hexdigest()
    return f"{prefix}:v1:{digest[:32]}"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class AuthExtensionPurposeKeys:
    baseline_key: bytes
    privacy_key: bytes

    def __post_init__(self) -> None:
        if len(self.baseline_key) != 32 or len(self.privacy_key) != 32:
            raise AuthExtensionError("purpose keys must contain exactly 32 bytes")


def derive_auth_extension_keys(master_key: bytes) -> AuthExtensionPurposeKeys:
    """Derive non-interchangeable baseline and privacy keys."""
    if not isinstance(master_key, bytes) or len(master_key) != 32:
        raise AuthExtensionError("master key must contain exactly 32 bytes")
    return AuthExtensionPurposeKeys(
        hmac.new(
            master_key,
            b"angerona/windows-auth-extension-baseline/v1",
            hashlib.sha256,
        ).digest(),
        hmac.new(
            master_key,
            b"angerona/windows-auth-extension-privacy/v1",
            hashlib.sha256,
        ).digest(),
    )


def _read_install_key(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if path.is_symlink():
        raise OSError("installation key is link-backed")
    descriptor = os.open(path, flags | no_follow)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > 256
            or not _windows_handle_matches_path(descriptor, str(path))
        ):
            raise OSError("installation key is not a bounded regular file")
        encoded = os.read(descriptor, 257)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or len(encoded) > 256
        ):
            raise OSError("installation key changed during read")
    finally:
        os.close(descriptor)
    key = bytes.fromhex(encoded.decode("ascii", "strict").strip())
    if len(key) != 32:
        raise OSError("installation key has the wrong size")
    return key


def load_auth_extension_keys(
    data_root: Path | str,
    *,
    master_key: bytes | None = None,
) -> AuthExtensionPurposeKeys | None:
    """Load but never create or rotate the Angerona installation authority."""
    try:
        value = master_key if master_key is not None else _read_install_key(Path(data_root) / "bus.key")
        return derive_auth_extension_keys(value)
    except (AuthExtensionError, OSError, UnicodeError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class SurfaceCoverage:
    surface: str
    status: str
    reason: str
    enumerated_count: int
    admitted_count: int
    dropped_count: int = 0

    def __post_init__(self) -> None:
        if self.surface not in SURFACE_IDS:
            raise AuthExtensionError("surface coverage has an unsupported identifier")
        if self.status not in {"complete", "partial", "unknown"}:
            raise AuthExtensionError("surface coverage status is unsupported")
        if self.status != "complete":
            _path_free_reason(self.reason, "coverage reason", required=True)
        else:
            _path_free_reason(self.reason, "coverage reason", required=False)
        enumerated = _bounded_int(
            self.enumerated_count, "enumerated_count", maximum=MAX_BINDINGS_PER_SURFACE * 8
        )
        admitted = _bounded_int(
            self.admitted_count, "admitted_count", maximum=MAX_BINDINGS_PER_SURFACE
        )
        dropped = _bounded_int(
            self.dropped_count, "dropped_count", maximum=MAX_BINDINGS_PER_SURFACE * 8
        )
        if admitted > enumerated or dropped > enumerated:
            raise AuthExtensionError("surface coverage counts are inconsistent")


@dataclass(frozen=True, slots=True)
class ComponentEvidence:
    component_token: str
    path_token: str
    resolution_status: str
    resolution_reason: str
    sha256: str = ""
    size: int = 0
    file_identity: str = ""
    authenticode_state: str = "unknown"
    catalog_state: str = "unknown"
    signer_thumbprint: str = ""
    file_version: str = ""
    owner_token: str = ""
    acl_digest: str = ""
    evidence_status: str = "unknown"

    def __post_init__(self) -> None:
        if not _TOKEN.fullmatch(self.component_token) or not self.component_token.startswith(
            "component:"
        ):
            raise AuthExtensionError("component token is invalid")
        if self.path_token and (
            not _TOKEN.fullmatch(self.path_token) or not self.path_token.startswith("path:")
        ):
            raise AuthExtensionError("path token is invalid")
        if self.resolution_status not in {"resolved", "missing", "rejected", "unknown", "error"}:
            raise AuthExtensionError("component resolution status is unsupported")
        if self.resolution_status != "resolved":
            _path_free_reason(self.resolution_reason, "resolution reason", required=True)
        else:
            _path_free_reason(self.resolution_reason, "resolution reason", required=False)
        if self.sha256 and not _HEX_64.fullmatch(self.sha256):
            raise AuthExtensionError("component SHA256 is invalid")
        _bounded_int(self.size, "component size")
        if self.file_identity and (
            not _TOKEN.fullmatch(self.file_identity) or not self.file_identity.startswith("file:")
        ):
            raise AuthExtensionError("file identity token is invalid")
        if self.authenticode_state not in {
            "verified",
            "unsigned",
            "invalid",
            "unknown",
            "error",
        }:
            raise AuthExtensionError("Authenticode state is unsupported")
        if self.catalog_state not in {"verified", "not-found", "unknown", "error"}:
            raise AuthExtensionError("catalog state is unsupported")
        if self.signer_thumbprint and not _HEX_64.fullmatch(self.signer_thumbprint):
            raise AuthExtensionError("signer thumbprint must be a SHA256 token")
        if self.file_version and not _SAFE_VERSION.fullmatch(self.file_version):
            raise AuthExtensionError("file version is invalid")
        for label, value, prefix in (
            ("owner token", self.owner_token, "owner:"),
            ("ACL digest", self.acl_digest, "acl:"),
        ):
            if value and (not _TOKEN.fullmatch(value) or not value.startswith(prefix)):
                raise AuthExtensionError(f"{label} is invalid")
        if self.evidence_status not in {"complete", "partial", "unknown"}:
            raise AuthExtensionError("component evidence status is unsupported")


@dataclass(frozen=True, slots=True)
class AuthExtensionBinding:
    surface: str
    order: int
    binding_token: str
    registry_source: str
    registry_view: str
    registry_type: str
    component_token: str
    key_owner_token: str = ""
    key_acl_digest: str = ""
    key_security_state: str = "unknown"

    def __post_init__(self) -> None:
        if self.surface not in SURFACE_IDS:
            raise AuthExtensionError("binding surface is unsupported")
        _bounded_int(self.order, "binding order", maximum=MAX_BINDINGS)
        if not _TOKEN.fullmatch(self.binding_token) or not self.binding_token.startswith("binding:"):
            raise AuthExtensionError("binding token is invalid")
        _path_free_reason(self.registry_source, "registry source", required=True)
        if self.registry_view not in {"32", "64", "native"}:
            raise AuthExtensionError("registry view is unsupported")
        if self.registry_type not in {"REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ", "unknown"}:
            raise AuthExtensionError("registry type is unsupported")
        if not _TOKEN.fullmatch(self.component_token) or not self.component_token.startswith(
            "component:"
        ):
            raise AuthExtensionError("binding component token is invalid")
        for label, value, prefix in (
            ("key owner token", self.key_owner_token, "owner:"),
            ("key ACL digest", self.key_acl_digest, "acl:"),
        ):
            if value and (not _TOKEN.fullmatch(value) or not value.startswith(prefix)):
                raise AuthExtensionError(f"{label} is invalid")
        if self.key_security_state not in {"observed", "partial", "unknown"}:
            raise AuthExtensionError("registry key security state is unsupported")


@dataclass(frozen=True, slots=True)
class AuthExtensionSurface:
    coverage: SurfaceCoverage
    bindings: tuple[AuthExtensionBinding, ...]

    def __post_init__(self) -> None:
        if len(self.bindings) > MAX_BINDINGS_PER_SURFACE:
            raise AuthExtensionError("surface binding bound exceeded")
        if any(item.surface != self.coverage.surface for item in self.bindings):
            raise AuthExtensionError("surface contains a binding for another surface")
        if tuple(item.order for item in self.bindings) != tuple(range(len(self.bindings))):
            raise AuthExtensionError("surface bindings are not in a strict contiguous order")
        if self.coverage.admitted_count != len(self.bindings):
            raise AuthExtensionError("surface coverage does not match admitted bindings")


@dataclass(frozen=True, slots=True)
class AuthExtensionSnapshot:
    schema: str
    host_binding: str
    captured_at: float
    surfaces: tuple[AuthExtensionSurface, ...]
    components: tuple[ComponentEvidence, ...]
    collector_status: str
    collector_reason: str
    elapsed_ms: int

    def __post_init__(self) -> None:
        if self.schema != AUTH_EXTENSION_SCHEMA:
            raise AuthExtensionError("snapshot schema is unsupported")
        if not _TOKEN.fullmatch(self.host_binding) or not self.host_binding.startswith("host:"):
            raise AuthExtensionError("snapshot host binding is invalid")
        if (
            type(self.captured_at) not in (int, float)
            or (type(self.captured_at) is float and not math.isfinite(self.captured_at))
            or not 0 <= self.captured_at <= 10**15
        ):
            raise AuthExtensionError("snapshot capture time is invalid")
        if len(self.surfaces) != len(SURFACE_IDS):
            raise AuthExtensionError("snapshot must grade every fixed surface")
        if tuple(item.coverage.surface for item in self.surfaces) != SURFACE_IDS:
            raise AuthExtensionError("snapshot surfaces are missing or out of canonical order")
        if sum(len(item.bindings) for item in self.surfaces) > MAX_BINDINGS:
            raise AuthExtensionError("snapshot binding bound exceeded")
        if len(self.components) > MAX_COMPONENTS:
            raise AuthExtensionError("snapshot component bound exceeded")
        tokens = tuple(item.component_token for item in self.components)
        if len(tokens) != len(set(tokens)):
            raise AuthExtensionError("snapshot contains duplicate component tokens")
        known = set(tokens)
        if any(binding.component_token not in known for surface in self.surfaces for binding in surface.bindings):
            raise AuthExtensionError("binding refers to absent component evidence")
        if self.collector_status not in {"complete", "partial", "unknown"}:
            raise AuthExtensionError("collector status is unsupported")
        if self.collector_status != "complete":
            _path_free_reason(self.collector_reason, "collector reason", required=True)
        else:
            _path_free_reason(self.collector_reason, "collector reason", required=False)
        _bounded_int(self.elapsed_ms, "collector elapsed time", maximum=60_000)


@dataclass(frozen=True, slots=True)
class LocalComponentDetail:
    component_token: str
    path: str
    detail: str

    def __post_init__(self) -> None:
        if not _TOKEN.fullmatch(self.component_token) or not self.component_token.startswith(
            "component:"
        ):
            raise AuthExtensionError("local detail component token is invalid")
        _bounded_text(self.path, "local component path", maximum=1024)
        _bounded_text(self.detail, "local component detail", maximum=500)


@dataclass(frozen=True, slots=True)
class AuthExtensionCollection:
    snapshot: AuthExtensionSnapshot
    local_details: tuple[LocalComponentDetail, ...] = ()

    def __post_init__(self) -> None:
        if len(self.local_details) > MAX_LOCAL_DETAILS:
            raise AuthExtensionError("local detail bound exceeded")
        known = {item.component_token for item in self.snapshot.components}
        if any(item.component_token not in known for item in self.local_details):
            raise AuthExtensionError("local detail has no matching component")


@dataclass(frozen=True, slots=True)
class AuthExtensionChange:
    surface: str
    kind: str
    evidence_token: str
    before_digest: str
    after_digest: str

    def __post_init__(self) -> None:
        if self.surface not in {*SURFACE_IDS, "host"}:
            raise AuthExtensionError("change surface is unsupported")
        if self.kind not in {"added", "removed", "modified", "reordered", "coverage", "host"}:
            raise AuthExtensionError("change kind is unsupported")
        _bounded_text(self.evidence_token, "change evidence token", maximum=160)
        for value in (self.before_digest, self.after_digest):
            if value and not _HEX_64.fullmatch(value):
                raise AuthExtensionError("change digest is invalid")


@dataclass(frozen=True, slots=True)
class SnapshotComparison:
    status: str
    reason: str
    changes: tuple[AuthExtensionChange, ...]
    overflow: bool = False

    def __post_init__(self) -> None:
        if self.status not in {"stable", "drift", "unknown", "host-mismatch"}:
            raise AuthExtensionError("snapshot comparison status is unsupported")
        _bounded_text(self.reason, "comparison reason")
        if len(self.changes) > MAX_CHANGES:
            raise AuthExtensionError("change bound exceeded")


@dataclass(frozen=True, slots=True)
class SnapshotAssessment:
    health: int
    state: str
    reason: str
    baseline_eligible: bool

    def __post_init__(self) -> None:
        _bounded_int(self.health, "assessment health", maximum=75)
        if self.state not in {"complete-local", "partial", "unknown"}:
            raise AuthExtensionError("assessment state is unsupported")
        _bounded_text(self.reason, "assessment reason")


@dataclass(frozen=True, slots=True)
class BaselineComparison:
    status: str
    baseline_trusted: bool
    fresh: bool
    local_only: bool
    reason: str
    age_seconds: int
    changes: tuple[AuthExtensionChange, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {
            "provisional",
            "stable",
            "drift",
            "unknown",
            "tampered",
            "stale",
            "host-mismatch",
        }:
            raise AuthExtensionError("baseline comparison status is unsupported")
        if type(self.baseline_trusted) is not bool or type(self.fresh) is not bool:
            raise AuthExtensionError("baseline comparison flags must be booleans")
        if self.local_only is not True:
            raise AuthExtensionError("baseline comparison must disclose local-only trust")
        _bounded_text(self.reason, "baseline comparison reason")
        _bounded_int(self.age_seconds, "baseline age", maximum=2**31 - 1)
        if len(self.changes) > MAX_CHANGES:
            raise AuthExtensionError("baseline comparison change bound exceeded")


class AuthExtensionEvidenceProvider(Protocol):
    """Dependency seam used by the capability and safe non-Windows tests."""

    def collect(self) -> AuthExtensionCollection:
        """Return one bounded immutable observation."""


class UnavailableAuthExtensionEvidenceProvider:
    """Fail-closed provider used when a stable privacy authority is unavailable."""

    _UNKNOWN_HOST = "host:v1:" + "0" * 32

    def __init__(
        self,
        reason: str,
        *,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.reason = _bounded_text(reason, "unavailable provider reason", maximum=500)
        self.wall_clock = wall_clock

    def collect(self) -> AuthExtensionCollection:
        snapshot = AuthExtensionSnapshot(
            AUTH_EXTENSION_SCHEMA,
            self._UNKNOWN_HOST,
            float(self.wall_clock()),
            tuple(_unknown_surface(surface, self.reason) for surface in SURFACE_IDS),
            (),
            "unknown",
            self.reason,
            0,
        )
        return AuthExtensionCollection(snapshot)


def snapshot_to_dict(snapshot: AuthExtensionSnapshot) -> dict[str, object]:
    """Return the persistent, path-minimized representation only."""
    return asdict(snapshot)


def _strict_object(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    if len(pairs) > MAX_BASELINE_OBJECT_FIELDS:
        raise BaselineIntegrityError("baseline object cardinality exceeds its bound")
    result: dict[str, object] = {}
    for key, value in pairs:
        if not isinstance(key, str) or not key or len(key) > 128:
            raise BaselineIntegrityError("baseline object key is invalid")
        if key in result:
            raise BaselineIntegrityError("baseline contains duplicate JSON keys")
        result[key] = value
    return result


def _strict_json_integer(value: str) -> int:
    """Parse an unauthenticated JSON integer without permitting huge values."""
    if len(value) > 20:
        raise BaselineIntegrityError("baseline integer exceeds its bound")
    try:
        parsed = int(value, 10)
    except (TypeError, ValueError, OverflowError) as exc:
        raise BaselineIntegrityError("baseline integer is malformed") from exc
    if not -(2**63) <= parsed <= 2**63 - 1:
        raise BaselineIntegrityError("baseline integer exceeds its bound")
    return parsed


def _strict_json_float(value: str) -> float:
    """Parse an unauthenticated JSON float into a small finite domain."""
    if len(value) > 64:
        raise BaselineIntegrityError("baseline number exceeds its bound")
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise BaselineIntegrityError("baseline number is malformed") from exc
    if not math.isfinite(parsed) or abs(parsed) > 10**15:
        raise BaselineIntegrityError("baseline number exceeds its bound")
    return parsed


def _validate_untrusted_json_shape(value: object) -> None:
    """Bound depth, aggregate cardinality, and strings before authentication."""
    stack: list[tuple[object, int]] = [(value, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if visited > MAX_BASELINE_JSON_NODES:
            raise BaselineIntegrityError("baseline JSON cardinality exceeds its bound")
        if depth > MAX_BASELINE_JSON_DEPTH:
            raise BaselineIntegrityError("baseline JSON nesting exceeds its bound")
        if isinstance(current, dict):
            if len(current) > MAX_BASELINE_OBJECT_FIELDS:
                raise BaselineIntegrityError("baseline object cardinality exceeds its bound")
            stack.extend((item, depth + 1) for item in current.values())
            continue
        if isinstance(current, list):
            if len(current) > MAX_BASELINE_JSON_NODES:
                raise BaselineIntegrityError("baseline array cardinality exceeds its bound")
            stack.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, str):
            if len(current.encode("utf-8", "surrogatepass")) > MAX_BASELINE_STRING_BYTES:
                raise BaselineIntegrityError("baseline string exceeds its bound")
            continue
        if current is None or type(current) in (bool, int, float):
            continue
        raise BaselineIntegrityError("baseline JSON contains an unsupported value")


def _finite_baseline_number(value: object, *, maximum: float = 10**15) -> bool:
    """Check a parsed number without converting a hostile huge integer to float."""
    if type(value) is int:
        return 0 <= value <= maximum
    return type(value) is float and math.isfinite(value) and 0 <= value <= maximum


def snapshot_from_dict(value: object) -> AuthExtensionSnapshot:
    """Strictly reconstruct a snapshot from authenticated local state."""
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "host_binding",
        "captured_at",
        "surfaces",
        "components",
        "collector_status",
        "collector_reason",
        "elapsed_ms",
    }:
        raise BaselineIntegrityError("baseline snapshot fields are invalid")
    raw_surfaces = value["surfaces"]
    raw_components = value["components"]
    if not isinstance(raw_surfaces, (list, tuple)) or not isinstance(
        raw_components, (list, tuple)
    ):
        raise BaselineIntegrityError("baseline snapshot collections are invalid")
    if len(raw_surfaces) != len(SURFACE_IDS) or len(raw_components) > MAX_COMPONENTS:
        raise BaselineIntegrityError("baseline snapshot collection cardinality is invalid")
    surfaces: list[AuthExtensionSurface] = []
    for raw in raw_surfaces:
        if not isinstance(raw, Mapping) or set(raw) != {"coverage", "bindings"}:
            raise BaselineIntegrityError("baseline surface is invalid")
        coverage_raw = raw["coverage"]
        bindings_raw = raw["bindings"]
        if not isinstance(coverage_raw, Mapping) or not isinstance(
            bindings_raw, (list, tuple)
        ):
            raise BaselineIntegrityError("baseline surface evidence is invalid")
        if len(bindings_raw) > MAX_BINDINGS_PER_SURFACE:
            raise BaselineIntegrityError("baseline binding cardinality exceeds its bound")
        try:
            coverage = SurfaceCoverage(**dict(coverage_raw))
            bindings = tuple(AuthExtensionBinding(**dict(item)) for item in bindings_raw)
            surfaces.append(AuthExtensionSurface(coverage, bindings))
        except (AuthExtensionError, TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise BaselineIntegrityError("baseline surface failed validation") from exc
    try:
        components = tuple(ComponentEvidence(**dict(item)) for item in raw_components)
        return AuthExtensionSnapshot(
            schema=value["schema"],
            host_binding=value["host_binding"],
            captured_at=value["captured_at"],
            surfaces=tuple(surfaces),
            components=components,
            collector_status=value["collector_status"],
            collector_reason=value["collector_reason"],
            elapsed_ms=value["elapsed_ms"],
        )
    except (AuthExtensionError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise BaselineIntegrityError("baseline snapshot failed validation") from exc


def assess_auth_extension_snapshot(snapshot: AuthExtensionSnapshot) -> SnapshotAssessment:
    """Grade evidence without overstating local software assurance."""
    statuses = {surface.coverage.status for surface in snapshot.surfaces}
    if snapshot.collector_status == "unknown" or "unknown" in statuses:
        return SnapshotAssessment(
            25,
            "unknown",
            "One or more fixed authentication-extension surfaces could not be observed; "
            "absence is not evidence of safety.",
            False,
        )
    if snapshot.collector_status == "partial" or "partial" in statuses:
        return SnapshotAssessment(
            50,
            "partial",
            "Authentication-extension observation is partial; exact per-surface coverage "
            "reasons identify the missing evidence.",
            False,
        )
    unresolved = sum(
        component.resolution_status != "resolved" for component in snapshot.components
    )
    if unresolved:
        return SnapshotAssessment(
            65,
            "partial",
            f"All fixed registry surfaces were enumerated, but {unresolved} component "
            "binding(s) lack a safely resolved file identity.",
            False,
        )
    incomplete_components = 0
    for component in snapshot.components:
        signature_complete = component.authenticode_state == "verified" or (
            component.authenticode_state == "unsigned"
            and component.catalog_state == "verified"
        )
        if (
            component.evidence_status != "complete"
            or not component.path_token
            or not component.sha256
            or not component.file_identity
            or not component.owner_token
            or not component.acl_digest
            or not signature_complete
            or component.catalog_state in {"unknown", "error"}
            or component.authenticode_state in {"invalid", "unknown", "error"}
            or not component.signer_thumbprint
        ):
            incomplete_components += 1
    incomplete_bindings = sum(
        binding.key_security_state != "observed"
        or not binding.key_owner_token
        or not binding.key_acl_digest
        for surface in snapshot.surfaces
        for binding in surface.bindings
    )
    if incomplete_components or incomplete_bindings:
        return SnapshotAssessment(
            60,
            "partial",
            "Fixed surfaces were enumerated, but complete handle-bound signature, owner, "
            f"ACL, or registry custody is missing for {incomplete_components} component(s) "
            f"and {incomplete_bindings} binding(s); incomplete evidence cannot be enrolled.",
            False,
        )
    return SnapshotAssessment(
        75,
        "complete-local",
        "All fixed surfaces were observed; health is capped at 75% because HMAC, clock, "
        "signature, owner, and ACL evidence are local software assertions without an "
        "independent high-water or hardware-backed witness.",
        True,
    )


def _binding_rows(snapshot: AuthExtensionSnapshot) -> dict[str, tuple[AuthExtensionBinding, ...]]:
    return {surface.coverage.surface: surface.bindings for surface in snapshot.surfaces}


def _component_rows(snapshot: AuthExtensionSnapshot) -> dict[str, ComponentEvidence]:
    return {component.component_token: component for component in snapshot.components}


def compare_auth_extension_snapshots(
    baseline: AuthExtensionSnapshot,
    current: AuthExtensionSnapshot,
) -> SnapshotComparison:
    """Pure bounded drift comparison; it never mutates or promotes a baseline."""
    if baseline.host_binding != current.host_binding:
        return SnapshotComparison(
            "host-mismatch",
            "Current evidence is bound to a different host identity token.",
            (
                AuthExtensionChange(
                    "host",
                    "host",
                    current.host_binding,
                    _digest(baseline.host_binding),
                    _digest(current.host_binding),
                ),
            ),
        )
    changes: list[AuthExtensionChange] = []
    overflow = False

    def add(change: AuthExtensionChange) -> None:
        nonlocal overflow
        if len(changes) < MAX_CHANGES:
            changes.append(change)
        else:
            overflow = True

    old_surfaces = {surface.coverage.surface: surface for surface in baseline.surfaces}
    new_surfaces = {surface.coverage.surface: surface for surface in current.surfaces}
    for surface_id in SURFACE_IDS:
        before_surface = old_surfaces[surface_id]
        after_surface = new_surfaces[surface_id]
        if before_surface.coverage != after_surface.coverage:
            add(
                AuthExtensionChange(
                    surface_id,
                    "coverage",
                    f"coverage:{surface_id}",
                    _digest(asdict(before_surface.coverage)),
                    _digest(asdict(after_surface.coverage)),
                )
            )
        before = before_surface.bindings
        after = after_surface.bindings
        old_positions = {item.binding_token: index for index, item in enumerate(before)}
        new_positions = {item.binding_token: index for index, item in enumerate(after)}
        old_map = {item.binding_token: item for item in before}
        new_map = {item.binding_token: item for item in after}
        for token in sorted(set(new_map) - set(old_map)):
            add(AuthExtensionChange(surface_id, "added", token, "", _digest(asdict(new_map[token]))))
        for token in sorted(set(old_map) - set(new_map)):
            add(AuthExtensionChange(surface_id, "removed", token, _digest(asdict(old_map[token])), ""))
        for token in sorted(set(old_map) & set(new_map)):
            if old_positions[token] != new_positions[token]:
                add(
                    AuthExtensionChange(
                        surface_id,
                        "reordered",
                        token,
                        _digest(old_positions[token]),
                        _digest(new_positions[token]),
                    )
                )
            elif old_map[token] != new_map[token]:
                add(
                    AuthExtensionChange(
                        surface_id,
                        "modified",
                        token,
                        _digest(asdict(old_map[token])),
                        _digest(asdict(new_map[token])),
                    )
                )

    old_components = _component_rows(baseline)
    new_components = _component_rows(current)
    for token in sorted(set(old_components) & set(new_components)):
        if old_components[token] != new_components[token]:
            # Attribute component drift to every binding that names it, without
            # persisting or emitting its local path.
            surface_id = next(
                (
                    binding.surface
                    for bindings in _binding_rows(current).values()
                    for binding in bindings
                    if binding.component_token == token
                ),
                "lsa.authentication-packages",
            )
            add(
                AuthExtensionChange(
                    surface_id,
                    "modified",
                    token,
                    _digest(asdict(old_components[token])),
                    _digest(asdict(new_components[token])),
                )
            )
    if changes or overflow:
        suffix = " Change output reached its bound." if overflow else ""
        return SnapshotComparison(
            "drift",
            "Ordered authentication-extension binding, coverage, or component drift "
            f"was observed.{suffix}",
            tuple(changes),
            overflow,
        )
    if (
        baseline.collector_status != "complete"
        or current.collector_status != "complete"
        or any(surface.coverage.status != "complete" for surface in baseline.surfaces)
        or any(surface.coverage.status != "complete" for surface in current.surfaces)
    ):
        return SnapshotComparison(
            "unknown",
            "No difference was proven, but one or both snapshots have incomplete coverage.",
            (),
        )
    return SnapshotComparison("stable", "No bounded authentication-extension drift was observed.", ())


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.stat(follow_symlinks=False)
        return stat.S_ISLNK(info.st_mode) or bool(
            getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
        )
    except OSError:
        return True


def _same_filesystem_object(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _object_identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _require_fixed_local_path(path: Path) -> None:
    """Reject Windows network/removable baseline and rendezvous storage."""
    if os.name != "nt":
        return
    anchor = path.anchor
    if not anchor or anchor.startswith("\\\\"):
        raise OSError("authentication baseline storage must use a fixed local disk")
    try:
        import ctypes
        from ctypes import wintypes

        get_drive_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
        get_drive_type.argtypes = (wintypes.LPCWSTR,)
        get_drive_type.restype = wintypes.UINT
        drive_type = int(get_drive_type(anchor))
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise OSError("authentication baseline drive type could not be proven") from exc
    if drive_type != 3:  # DRIVE_FIXED
        raise OSError("authentication baseline storage must use a fixed local disk")


def _canonical_auth_path(path: Path, *, allow_missing: bool) -> Path:
    requested = Path(os.path.abspath(path.expanduser()))
    resolved = requested.resolve(strict=not allow_missing)
    if os.path.normcase(os.fspath(requested)) != os.path.normcase(os.fspath(resolved)):
        raise OSError("authentication baseline path traverses a link or reparse point")
    _require_fixed_local_path(resolved)
    return resolved


def _safe_directory_stat(path: Path) -> os.stat_result:
    info = os.lstat(path)
    attributes = int(getattr(info, "st_file_attributes", 0))
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or bool(attributes & _REPARSE_POINT)
    ):
        raise OSError("authentication baseline parent is not a protected directory")
    return info


def _safe_regular_stat(path: Path) -> os.stat_result:
    info = os.lstat(path)
    attributes = int(getattr(info, "st_file_attributes", 0))
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or int(info.st_nlink) != 1
        or bool(attributes & _REPARSE_POINT)
    ):
        raise OSError("authentication baseline object is not a unique regular file")
    return info


@dataclass(slots=True)
class _EnrollmentCustody:
    root_identity: tuple[int, int]
    parent_identity: tuple[int, int]
    lock_identity: tuple[int, int]
    lock_descriptor: int
    root_descriptor: int
    parent_descriptor: int
    baseline_identity: tuple[int, int] | None


def _open_windows_exclusive_lock(path: Path) -> int:
    """Open one crash-released Windows rendezvous handle with no sharing."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    generic_read_write = 0x80000000 | 0x40000000
    open_always = 4
    normal_attributes = 0x00000080
    open_reparse_point = 0x00200000
    invalid_handle = wintypes.HANDLE(-1).value
    handle = create_file(
        os.fspath(path),
        generic_read_write,
        0,  # No sharing: the kernel owns and releases enrollment authority.
        None,
        open_always,
        normal_attributes | open_reparse_point,
        None,
    )
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        raise OSError(error, "baseline enrollment lock is held or unavailable")
    try:
        return msvcrt.open_osfhandle(
            int(handle),
            os.O_RDWR | getattr(os, "O_BINARY", 0),
        )
    except Exception:
        close_handle(handle)
        raise


def _open_windows_directory_guard(path: Path) -> int:
    """Retain one no-delete-share directory handle for enrollment identity proof."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    file_read_attributes = 0x00000080
    share_read_write = 0x00000001 | 0x00000002
    open_existing = 3
    backup_semantics = 0x02000000
    open_reparse_point = 0x00200000
    invalid_handle = wintypes.HANDLE(-1).value
    handle = create_file(
        os.fspath(path),
        file_read_attributes,
        share_read_write,  # Deliberately omit FILE_SHARE_DELETE.
        None,
        open_existing,
        backup_semantics | open_reparse_point,
        None,
    )
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        raise OSError(error, "authentication baseline directory is unavailable")
    try:
        return msvcrt.open_osfhandle(int(handle), os.O_RDONLY)
    except Exception:
        close_handle(handle)
        raise


def _open_windows_promotion_guard(path: Path) -> int:
    """Retain the replaced object while permitting one atomic Windows promotion."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    generic_read = 0x80000000
    delete_access = 0x00010000
    share_read_write_delete = 0x00000001 | 0x00000002 | 0x00000004
    open_existing = 3
    normal_attributes = 0x00000080
    open_reparse_point = 0x00200000
    invalid_handle = wintypes.HANDLE(-1).value
    handle = create_file(
        os.fspath(path),
        generic_read | delete_access,
        share_read_write_delete,
        None,
        open_existing,
        normal_attributes | open_reparse_point,
        None,
    )
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        raise OSError(error, "provisional baseline promotion guard is unavailable")
    try:
        return msvcrt.open_osfhandle(
            int(handle),
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
    except Exception:
        close_handle(handle)
        raise


def _replace_baseline_file(
    temporary: Path,
    destination: Path,
    *,
    parent_descriptor: int,
) -> None:
    """Atomically replace one baseline while the old object remains identity-bound."""
    if os.name != "nt":
        os.replace(
            temporary.name,
            destination.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        return

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    replace_file = kernel32.ReplaceFileW
    replace_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
    )
    replace_file.restype = wintypes.BOOL
    if not replace_file(
        os.fspath(destination),
        os.fspath(temporary),
        None,
        0,
        None,
        None,
    ):
        error = ctypes.get_last_error()
        raise OSError(error, "atomic baseline promotion failed")


def _windows_error_code(error: OSError) -> int | None:
    """Return an unmapped Win32 code when one is available."""
    winerror = getattr(error, "winerror", None)
    if type(winerror) is int:
        return winerror
    return error.errno if type(error.errno) is int else None


def _exact_regular_file_bytes_match(
    path: Path,
    *,
    expected_identity: tuple[int, int],
    expected: bytes,
) -> bool:
    """Read one named object through its handle and prove exact bounded bytes."""
    if len(expected) > MAX_BASELINE_BYTES:
        return False
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        named_before = _safe_regular_stat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or int(before.st_nlink) != 1
            or bool(int(getattr(before, "st_file_attributes", 0)) & _REPARSE_POINT)
            or _object_identity(before) != expected_identity
            or _object_identity(named_before) != expected_identity
            or int(before.st_size) != len(expected)
            or not _windows_handle_matches_path(descriptor, str(path))
        ):
            return False
        chunks: list[bytes] = []
        remaining = len(expected) + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        named_after = _safe_regular_stat(path)
        return (
            _object_identity(after) == expected_identity
            and _object_identity(named_after) == expected_identity
            and int(after.st_nlink) == 1
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and hmac.compare_digest(b"".join(chunks), expected)
        )
    except (OSError, RuntimeError, ValueError):
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _exact_descriptor_bytes_match(
    descriptor: int,
    *,
    expected_identity: tuple[int, int],
    expected_link_count: int,
    expected: bytes,
) -> bool:
    """Prove exact bounded bytes through an already-retained file descriptor."""
    if len(expected) > MAX_BASELINE_BYTES:
        return False
    original_offset: int | None = None
    restored = True
    matched = False
    try:
        original_offset = os.lseek(descriptor, 0, os.SEEK_CUR)
        os.lseek(descriptor, 0, os.SEEK_SET)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or bool(int(getattr(before, "st_file_attributes", 0)) & _REPARSE_POINT)
            or _object_identity(before) != expected_identity
            or int(before.st_nlink) != expected_link_count
            or int(before.st_size) != len(expected)
        ):
            return False
        chunks: list[bytes] = []
        remaining = len(expected) + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        matched = (
            _object_identity(after) == expected_identity
            and int(after.st_nlink) == expected_link_count
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and hmac.compare_digest(b"".join(chunks), expected)
        )
    except (OSError, RuntimeError, ValueError):
        return False
    finally:
        if original_offset is not None:
            try:
                os.lseek(descriptor, original_offset, os.SEEK_SET)
            except OSError:
                restored = False
    return matched and restored


def _open_posix_directory(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


def _open_posix_lock(path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags, 0o600)


class AuthExtensionBaselineStore:
    """HMAC-authenticated, host-bound provisional/trusted local baseline.

    Trust enrollment is an explicit operator API.  ``observe`` never replaces
    any existing document, including after drift.  Each canonical data root has
    exactly one policy-selected slot, ``baselines/windows_auth_extensions.json``;
    callers cannot choose another filename.  Freshness is derived from the local
    software clock and HMAC only and is not an external anti-rollback witness.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        data_root: Path | str | None = None,
        master_key: bytes | None = None,
        clock: Callable[[], float] = time.time,
        freshness_cap_seconds: int = DEFAULT_BASELINE_FRESHNESS_SECONDS,
    ) -> None:
        requested_path = Path(path)
        if data_root is None:
            if (
                requested_path.name != _BASELINE_RELATIVE_PARTS[1]
                or requested_path.parent.name != _BASELINE_RELATIVE_PARTS[0]
            ):
                raise BaselineIntegrityError(
                    "authentication baseline must use the fixed "
                    "baselines/windows_auth_extensions.json slot"
                )
            requested_root = requested_path.parent.parent
        else:
            requested_root = Path(data_root)
        try:
            self.data_root = _canonical_auth_path(requested_root, allow_missing=True)
            self.path = _canonical_auth_path(requested_path, allow_missing=True)
            expected_path = _canonical_auth_path(
                self.data_root.joinpath(*_BASELINE_RELATIVE_PARTS),
                allow_missing=True,
            )
            if self.path != expected_path:
                raise ValueError("alternate authentication baseline slot")
        except (OSError, RuntimeError, ValueError) as exc:
            raise BaselineIntegrityError(
                "authentication baseline must use the canonical fixed-local "
                "baselines/windows_auth_extensions.json slot for its data root"
            ) from exc
        self._fixed_path = expected_path
        self._identity_lock = threading.Lock()
        self._transition_local = threading.local()
        self._root_identity: tuple[int, int] | None = None
        if os.path.lexists(self.data_root):
            try:
                self._root_identity = _object_identity(
                    _safe_directory_stat(self.data_root)
                )
            except OSError as exc:
                raise BaselineIntegrityError(
                    "baseline data root is not a protected directory"
                ) from exc
        self.keys = load_auth_extension_keys(self.data_root, master_key=master_key)
        self._logical_slot_token = (
            self._derive_logical_slot_token() if self.keys is not None else None
        )
        self.clock = clock
        cap = int(freshness_cap_seconds)
        if not 15 * 60 <= cap <= MAX_BASELINE_FRESHNESS_SECONDS:
            raise ValueError("baseline freshness cap must be between 15 minutes and 7 days")
        self.freshness_cap_seconds = cap

    @property
    def authentication_available(self) -> bool:
        return self.keys is not None

    def _sign(self, body: Mapping[str, object]) -> str:
        if self.keys is None:
            raise BaselineIntegrityError("baseline HMAC authority is unavailable")
        return hmac.new(self.keys.baseline_key, _canonical(body), hashlib.sha256).hexdigest()

    def _derive_logical_slot_token(self) -> str:
        """Bind authenticated bytes to one canonical root, relative name, and schema."""
        if self.keys is None:
            raise BaselineIntegrityError("baseline HMAC authority is unavailable")
        relative = self.path.relative_to(self.data_root)
        if os.name == "nt":
            root_text = ntpath.normcase(ntpath.abspath(os.fspath(self.data_root)))
            relative_text = ntpath.normcase(ntpath.normpath(os.fspath(relative))).replace(
                "\\", "/"
            )
        else:
            root_text = os.path.normpath(os.fspath(self.data_root))
            relative_text = relative.as_posix()
        material = _canonical(
            {
                "protected_root": root_text,
                "relative_name": relative_text,
                "baseline_schema": BASELINE_SCHEMA,
            }
        )
        digest = hmac.new(
            self.keys.baseline_key,
            b"angerona/windows-auth-extension-logical-slot/v1\0" + material,
            hashlib.sha256,
        ).hexdigest()
        return f"slot:v1:{digest[:32]}"

    def _registry_signature(self, body: Mapping[str, object]) -> str:
        if self.keys is None:
            raise BaselineIntegrityError("baseline HMAC authority is unavailable")
        return hmac.new(
            self.keys.baseline_key,
            b"angerona/windows-auth-extension-trusted-slot/v1\0" + _canonical(body),
            hashlib.sha256,
        ).hexdigest()

    def _load_trusted_slot(self) -> str | None:
        """Read the one authenticated trusted-baseline slot for this protected root."""
        registry_path = self.data_root / _TRUSTED_SLOT_NAME
        try:
            os.lstat(registry_path)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BaselineIntegrityError("trusted baseline slot could not be inspected") from exc
        if self.keys is None:
            raise BaselineIntegrityError("baseline HMAC authority is unavailable")
        if not self._path_safe(registry_path, allow_missing=False):
            raise BaselineIntegrityError("trusted baseline slot is link-backed or outside its root")
        root_before = self._assert_root_custody()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        custody = self._current_transition()
        if os.name != "nt" and custody is not None:
            descriptor = os.open(
                registry_path.name,
                flags | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=custody.root_descriptor,
            )
        else:
            descriptor = os.open(registry_path, flags | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or int(before.st_nlink) != 1
                or bool(int(getattr(before, "st_file_attributes", 0)) & _REPARSE_POINT)
                or before.st_size > _MAX_TRUSTED_SLOT_BYTES
                or not _windows_handle_matches_path(descriptor, str(registry_path))
            ):
                raise BaselineIntegrityError("trusted baseline slot is not a bounded unique file")
            chunks: list[bytes] = []
            remaining = _MAX_TRUSTED_SLOT_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(4096, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            named = _safe_regular_stat(registry_path)
            root_after = self._assert_root_custody()
            if (
                len(raw) > _MAX_TRUSTED_SLOT_BYTES
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or int(after.st_nlink) != 1
                or not _same_filesystem_object(after, named)
                or not _same_filesystem_object(root_before, root_after)
            ):
                raise BaselineIntegrityError("trusted baseline slot changed during read")
        finally:
            os.close(descriptor)
        try:
            wrapper = json.loads(
                raw.decode("utf-8", "strict"),
                object_pairs_hook=_strict_object,
                parse_int=_strict_json_integer,
                parse_float=_strict_json_float,
                parse_constant=lambda item: (_ for _ in ()).throw(
                    BaselineIntegrityError(f"invalid trusted slot constant: {item}")
                ),
            )
            _validate_untrusted_json_shape(wrapper)
        except (
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
            MemoryError,
        ) as exc:
            raise BaselineIntegrityError("trusted baseline slot JSON is malformed") from exc
        if not isinstance(wrapper, dict) or set(wrapper) != {"body", "hmac_sha256"}:
            raise BaselineIntegrityError("trusted baseline slot wrapper is invalid")
        body = wrapper["body"]
        signature = wrapper["hmac_sha256"]
        if (
            not isinstance(body, dict)
            or set(body) != {"schema", "logical_slot"}
            or body.get("schema") != _TRUSTED_SLOT_SCHEMA
            or not isinstance(body.get("logical_slot"), str)
            or not _TOKEN.fullmatch(body["logical_slot"])
            or not body["logical_slot"].startswith("slot:")
            or not isinstance(signature, str)
            or not _HEX_64.fullmatch(signature)
            or not hmac.compare_digest(signature, self._registry_signature(body))
        ):
            raise BaselineIntegrityError("trusted baseline slot authentication failed")
        return body["logical_slot"]

    def _create_trusted_slot(self) -> None:
        """Create the root-wide slot registration under retained enrollment custody."""
        custody = self._current_transition()
        if custody is None or self._logical_slot_token is None:
            raise BaselineEnrollmentError("trusted slot registration requires enrollment custody")
        self._assert_transition_custody(custody)
        registry_path = self.data_root / _TRUSTED_SLOT_NAME
        if not self._path_safe(registry_path, allow_missing=True):
            raise BaselineEnrollmentError("trusted baseline slot destination is unsafe")
        body = {"schema": _TRUSTED_SLOT_SCHEMA, "logical_slot": self._logical_slot_token}
        encoded = _canonical({"body": body, "hmac_sha256": self._registry_signature(body)})
        if len(encoded) > _MAX_TRUSTED_SLOT_BYTES:
            raise BaselineEnrollmentError("trusted baseline slot exceeds its storage bound")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if os.name != "nt":
            descriptor = os.open(
                registry_path.name,
                flags,
                0o600,
                dir_fd=custody.root_descriptor,
            )
        else:
            descriptor = os.open(registry_path, flags, 0o600)
        created_identity: tuple[int, int] | None = None
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or int(opened.st_nlink) != 1
                or bool(int(getattr(opened, "st_file_attributes", 0)) & _REPARSE_POINT)
                or not _windows_handle_matches_path(descriptor, str(registry_path))
            ):
                raise BaselineEnrollmentError("created trusted baseline slot is unsafe")
            created_identity = _object_identity(opened)
            view = memoryview(encoded)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError("trusted baseline slot write made no progress")
                written += count
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            named = _safe_regular_stat(registry_path)
            if (
                _object_identity(after) != created_identity
                or int(after.st_nlink) != 1
                or _object_identity(named) != created_identity
            ):
                raise BaselineEnrollmentError("trusted baseline slot changed during creation")
        except Exception:
            try:
                current = _safe_regular_stat(registry_path)
                if created_identity is not None and _object_identity(current) == created_identity:
                    if os.name != "nt":
                        os.unlink(registry_path.name, dir_fd=custody.root_descriptor)
                    else:
                        registry_path.unlink()
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)
        self._assert_transition_custody(custody)

    def _commit_trusted_slot(self) -> None:
        registered = self._load_trusted_slot()
        if registered is None:
            try:
                self._create_trusted_slot()
            except FileExistsError:
                pass
            registered = self._load_trusted_slot()
        if registered is None or registered != self._logical_slot_token:
            raise BaselineEnrollmentError(
                "another logical baseline slot already owns trusted enrollment"
            )

    def _assert_trusted_slot_unclaimed(self) -> None:
        if self._load_trusted_slot() is not None:
            raise BaselineEnrollmentError(
                "trusted baseline enrollment is already bound to a logical slot"
            )

    def _assert_root_custody(self) -> os.stat_result:
        try:
            current_path = _canonical_auth_path(self.path, allow_missing=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise BaselineIntegrityError(
                "authentication baseline fixed-slot path changed"
            ) from exc
        if current_path != self._fixed_path:
            raise BaselineIntegrityError(
                "authentication baseline fixed-slot path changed"
            )
        canonical = _canonical_auth_path(self.data_root, allow_missing=False)
        if canonical != self.data_root:
            raise BaselineIntegrityError("baseline data-root canonical path changed")
        current = _safe_directory_stat(self.data_root)
        identity = _object_identity(current)
        with self._identity_lock:
            if self._root_identity is None:
                self._root_identity = identity
            elif identity != self._root_identity:
                raise BaselineIntegrityError("baseline data-root identity changed")
        return current

    def _path_safe(self, path: Path, *, allow_missing: bool) -> bool:
        try:
            self._assert_root_custody()
            root = _canonical_auth_path(self.data_root, allow_missing=False)
            candidate = _canonical_auth_path(path, allow_missing=allow_missing)
            candidate.relative_to(root)
            current = candidate
            while True:
                if os.path.lexists(current):
                    info = os.lstat(current)
                    if stat.S_ISLNK(info.st_mode) or bool(
                        int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
                    ):
                        return False
                if current == root:
                    break
                parent = current.parent
                if parent == current:
                    return False
                current = parent
            return True
        except (OSError, RuntimeError, ValueError):
            return False

    def _load(
        self,
        *,
        require_trusted_slot: bool = True,
    ) -> tuple[dict[str, object], AuthExtensionSnapshot, str] | None:
        try:
            os.lstat(self.path)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BaselineIntegrityError("baseline path could not be inspected") from exc
        if self.keys is None:
            raise BaselineIntegrityError("baseline HMAC authority is unavailable")
        if not self._path_safe(self.path, allow_missing=False):
            raise BaselineIntegrityError("baseline path is outside its protected data root or link-backed")
        root_before = self._assert_root_custody()
        parent_before = _safe_directory_stat(self.path.parent)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        custody = getattr(self._transition_local, "custody", None)
        if os.name != "nt" and isinstance(custody, _EnrollmentCustody):
            descriptor = os.open(
                self.path.name,
                flags | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=custody.parent_descriptor,
            )
        else:
            descriptor = os.open(self.path, flags | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or int(before.st_nlink) != 1
                or bool(int(getattr(before, "st_file_attributes", 0)) & _REPARSE_POINT)
                or before.st_size > MAX_BASELINE_BYTES
                or not _windows_handle_matches_path(descriptor, str(self.path))
            ):
                raise BaselineIntegrityError(
                    "baseline is not a bounded, unique regular file"
                )
            raw = os.read(descriptor, MAX_BASELINE_BYTES + 1)
            after = os.fstat(descriptor)
            try:
                named = _safe_regular_stat(self.path)
                parent_after = _safe_directory_stat(self.path.parent)
                root_after = self._assert_root_custody()
            except OSError as exc:
                raise BaselineIntegrityError(
                    "baseline single-link namespace custody changed during read"
                ) from exc
            if (
                len(raw) > MAX_BASELINE_BYTES
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or int(after.st_nlink) != 1
                or not _same_filesystem_object(after, named)
                or not _same_filesystem_object(parent_before, parent_after)
                or not _same_filesystem_object(root_before, root_after)
            ):
                raise BaselineIntegrityError("baseline changed during read")
        finally:
            os.close(descriptor)
        try:
            wrapper = json.loads(
                raw.decode("utf-8", "strict"),
                object_pairs_hook=_strict_object,
                parse_int=_strict_json_integer,
                parse_float=_strict_json_float,
                parse_constant=lambda item: (_ for _ in ()).throw(
                    BaselineIntegrityError(f"invalid baseline constant: {item}")
                ),
            )
            _validate_untrusted_json_shape(wrapper)
        except (
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
            MemoryError,
        ) as exc:
            raise BaselineIntegrityError("baseline JSON is malformed") from exc
        if not isinstance(wrapper, dict) or set(wrapper) != {"body", "hmac_sha256"}:
            raise BaselineIntegrityError("baseline wrapper fields are invalid")
        body = wrapper["body"]
        signature = wrapper["hmac_sha256"]
        if not isinstance(body, dict) or set(body) != {
            "schema",
            "state",
            "captured_at",
            "host_binding",
            "freshness_cap_seconds",
            "freshness_authority",
            "logical_slot",
            "snapshot",
            "enrollment",
        }:
            raise BaselineIntegrityError("baseline body fields are invalid")
        if (
            body["schema"] != BASELINE_SCHEMA
            or body["state"] not in {"provisional", "trusted"}
            or type(body["captured_at"]) not in (int, float)
            or not _finite_baseline_number(body["captured_at"])
            or not isinstance(body.get("snapshot"), dict)
            or body["host_binding"] != body["snapshot"].get("host_binding")
            or body["freshness_cap_seconds"] != self.freshness_cap_seconds
            or body["freshness_authority"]
            != "local-software-clock-and-hmac-no-independent-high-water"
            or not isinstance(signature, str)
            or not _HEX_64.fullmatch(signature)
            or not hmac.compare_digest(signature, self._sign(body))
        ):
            raise BaselineIntegrityError("baseline failed schema, host, freshness, or HMAC validation")
        if (
            not isinstance(body["logical_slot"], str)
            or not _TOKEN.fullmatch(body["logical_slot"])
            or not body["logical_slot"].startswith("slot:")
            or body["logical_slot"] != self._logical_slot_token
        ):
            raise BaselineIntegrityError(
                "authenticated baseline logical slot does not match its canonical root and name"
            )
        enrollment = body["enrollment"]
        if body["state"] == "provisional":
            if enrollment is not None:
                raise BaselineIntegrityError("provisional baseline cannot claim enrollment")
        elif (
            not isinstance(enrollment, dict)
            or set(enrollment) != {"operator_token", "reason_digest", "approved_at"}
            or not isinstance(enrollment["operator_token"], str)
            or not _TOKEN.fullmatch(enrollment["operator_token"])
            or not enrollment["operator_token"].startswith("operator:")
            or not isinstance(enrollment["reason_digest"], str)
            or not _TOKEN.fullmatch(enrollment["reason_digest"])
            or not enrollment["reason_digest"].startswith("reason:")
            or type(enrollment["approved_at"]) not in (int, float)
            or not _finite_baseline_number(enrollment["approved_at"])
        ):
            raise BaselineIntegrityError("trusted baseline enrollment proof is invalid")
        if body["state"] == "trusted" and require_trusted_slot:
            registered = self._load_trusted_slot()
            if registered is None or registered != self._logical_slot_token:
                raise BaselineIntegrityError(
                    "trusted baseline is not bound to this root-wide logical slot"
                )
        snapshot = snapshot_from_dict(body["snapshot"])
        return body, snapshot, signature

    def _body(
        self,
        snapshot: AuthExtensionSnapshot,
        *,
        state: str,
        enrollment: Mapping[str, object] | None,
    ) -> dict[str, object]:
        now = float(self.clock())
        if not math.isfinite(now) or now < 0:
            raise BaselineIntegrityError("baseline clock is invalid")
        return {
            "schema": BASELINE_SCHEMA,
            "state": state,
            "captured_at": now,
            "host_binding": snapshot.host_binding,
            "freshness_cap_seconds": self.freshness_cap_seconds,
            "freshness_authority": "local-software-clock-and-hmac-no-independent-high-water",
            "logical_slot": self._logical_slot_token,
            "snapshot": snapshot_to_dict(snapshot),
            "enrollment": dict(enrollment) if enrollment is not None else None,
        }

    def _encoded(self, body: Mapping[str, object]) -> bytes:
        encoded = _canonical({"body": body, "hmac_sha256": self._sign(body)})
        if len(encoded) > MAX_BASELINE_BYTES:
            raise BaselineIntegrityError("baseline exceeds its storage bound")
        return encoded

    def _ensure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path_safe(self.path, allow_missing=True):
            raise BaselineIntegrityError("baseline destination is outside its data root or link-backed")
        _safe_directory_stat(self.path.parent)

    def _current_transition(self) -> _EnrollmentCustody | None:
        custody = getattr(self._transition_local, "custody", None)
        return custody if isinstance(custody, _EnrollmentCustody) else None

    def _opened_baseline_identity(
        self,
        parent_descriptor: int | None = None,
    ) -> tuple[int, int] | None:
        try:
            os.lstat(self.path)
        except FileNotFoundError:
            return None
        if not self._path_safe(self.path, allow_missing=False):
            raise BaselineIntegrityError("baseline path is link-backed or no longer canonical")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        if os.name != "nt" and parent_descriptor is not None:
            descriptor = os.open(
                self.path.name,
                flags | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
        else:
            descriptor = os.open(self.path, flags | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            named = _safe_regular_stat(self.path)
            if (
                not stat.S_ISREG(opened.st_mode)
                or int(opened.st_nlink) != 1
                or bool(int(getattr(opened, "st_file_attributes", 0)) & _REPARSE_POINT)
                or not _same_filesystem_object(opened, named)
                or not _windows_handle_matches_path(descriptor, str(self.path))
            ):
                raise BaselineIntegrityError(
                    "baseline object is not an exact single-link regular file"
                )
            return _object_identity(opened)
        finally:
            os.close(descriptor)

    def _verify_transition_namespace_custody(self, custody: _EnrollmentCustody) -> None:
        root_named = self._assert_root_custody()
        root_opened = os.fstat(custody.root_descriptor)
        parent_named = _safe_directory_stat(self.path.parent)
        parent_opened = os.fstat(custody.parent_descriptor)
        lock_path = self.data_root / _ENROLLMENT_LOCK_NAME
        lock_named = _safe_regular_stat(lock_path)
        lock_opened = os.fstat(custody.lock_descriptor)
        if (
            not stat.S_ISDIR(root_opened.st_mode)
            or not stat.S_ISDIR(parent_opened.st_mode)
            or _object_identity(root_opened) != custody.root_identity
            or _object_identity(root_named) != custody.root_identity
            or _object_identity(parent_opened) != custody.parent_identity
            or _object_identity(parent_named) != custody.parent_identity
            or not stat.S_ISREG(lock_opened.st_mode)
            or int(lock_opened.st_nlink) != 1
            or bool(int(getattr(lock_opened, "st_file_attributes", 0)) & _REPARSE_POINT)
            or _object_identity(lock_opened) != custody.lock_identity
            or _object_identity(lock_named) != custody.lock_identity
            or not _windows_handle_matches_path(custody.root_descriptor, str(self.data_root))
            or not _windows_handle_matches_path(custody.parent_descriptor, str(self.path.parent))
            or not _windows_handle_matches_path(custody.lock_descriptor, str(lock_path))
        ):
            raise BaselineEnrollmentError(
                "baseline enrollment root, parent, or lock identity changed"
            )

    def _verify_transition_custody(self, custody: _EnrollmentCustody) -> None:
        self._verify_transition_namespace_custody(custody)
        current_baseline = self._opened_baseline_identity(custody.parent_descriptor)
        if current_baseline != custody.baseline_identity:
            raise BaselineEnrollmentError(
                "baseline object identity changed during enrollment"
            )

    def _assert_transition_custody(self, custody: _EnrollmentCustody) -> None:
        try:
            self._verify_transition_custody(custody)
        except BaselineEnrollmentError:
            raise
        except (BaselineIntegrityError, OSError, RuntimeError, ValueError) as exc:
            raise BaselineEnrollmentError(
                "baseline enrollment namespace custody could not be proven"
            ) from exc

    def _create_exclusive(self, encoded: bytes) -> bool:
        self._ensure_parent()
        custody = self._current_transition()
        if custody is not None:
            self._assert_transition_custody(custody)
        root_before = self._assert_root_custody()
        parent_before = _safe_directory_stat(self.path.parent)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            if os.name != "nt" and custody is not None:
                descriptor = os.open(
                    self.path.name,
                    flags,
                    0o600,
                    dir_fd=custody.parent_descriptor,
                )
            else:
                descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            return False
        created_identity: tuple[int, int] | None = None
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or int(before.st_nlink) != 1
                or bool(int(getattr(before, "st_file_attributes", 0)) & _REPARSE_POINT)
                or not _windows_handle_matches_path(descriptor, str(self.path))
            ):
                raise BaselineIntegrityError("created baseline object is unsafe")
            created_identity = _object_identity(before)
            view = memoryview(encoded)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError("baseline write made no progress")
                written += count
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            named = _safe_regular_stat(self.path)
            if (
                _object_identity(after) != created_identity
                or int(after.st_nlink) != 1
                or _object_identity(named) != created_identity
                or not _same_filesystem_object(parent_before, _safe_directory_stat(self.path.parent))
                or not _same_filesystem_object(root_before, self._assert_root_custody())
            ):
                raise BaselineIntegrityError("created baseline changed during write")
            if custody is not None:
                custody.baseline_identity = created_identity
                self._assert_transition_custody(custody)
            try:
                os.fchmod(descriptor, 0o600)
            except (AttributeError, OSError):
                pass
        except Exception:
            try:
                current = _safe_regular_stat(self.path)
                if created_identity is not None and _object_identity(current) == created_identity:
                    if os.name != "nt" and custody is not None:
                        os.unlink(self.path.name, dir_fd=custody.parent_descriptor)
                    else:
                        self.path.unlink()
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)
        return True

    @contextmanager
    def _exclusive_transition(self) -> Iterator[None]:
        """Hold one crash-released enrollment authority for the protected root.

        The rendezvous name is constant for ``data_root`` and never derives
        from a caller-supplied baseline filename. Windows additionally retains
        no-delete directory handles. POSIX owns a nonblocking lock on the root
        directory inode itself, so unlinking/recreating the inert rendezvous
        file cannot split cooperating enrollers onto different lock objects.
        """
        self._ensure_parent()
        lock_path = self.data_root / _ENROLLMENT_LOCK_NAME
        if not self._path_safe(lock_path, allow_missing=True):
            raise BaselineEnrollmentError(
                "baseline enrollment lock is outside its protected root or link-backed"
            )
        root_before = self._assert_root_custody()
        parent_before = _safe_directory_stat(self.path.parent)
        root_descriptor = -1
        parent_descriptor = -1
        lock_descriptor = -1
        root_locked = False
        lock_locked = False
        try:
            root_descriptor = (
                _open_windows_directory_guard(self.data_root)
                if os.name == "nt"
                else _open_posix_directory(self.data_root)
            )
            parent_descriptor = (
                _open_windows_directory_guard(self.path.parent)
                if os.name == "nt"
                else _open_posix_directory(self.path.parent)
            )
            root_opened = os.fstat(root_descriptor)
            parent_opened = os.fstat(parent_descriptor)
            if (
                not stat.S_ISDIR(root_opened.st_mode)
                or not stat.S_ISDIR(parent_opened.st_mode)
                or not _same_filesystem_object(root_before, root_opened)
                or not _same_filesystem_object(parent_before, parent_opened)
                or not _windows_handle_matches_path(root_descriptor, str(self.data_root))
                or not _windows_handle_matches_path(parent_descriptor, str(self.path.parent))
            ):
                raise OSError("baseline enrollment directory identity changed")
            if os.name != "nt":
                import fcntl

                fcntl.flock(root_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                root_locked = True
            lock_descriptor = (
                _open_windows_exclusive_lock(lock_path)
                if os.name == "nt"
                else _open_posix_lock(lock_path)
            )
            if os.name != "nt":
                import fcntl

                fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_locked = True
        except (BlockingIOError, OSError, RuntimeError, ValueError) as exc:
            if lock_descriptor >= 0:
                os.close(lock_descriptor)
            if parent_descriptor >= 0:
                os.close(parent_descriptor)
            if root_descriptor >= 0:
                os.close(root_descriptor)
            raise BaselineEnrollmentError(
                "another baseline enrollment is active or its lock is unavailable"
            ) from exc
        try:
            lock_opened = os.fstat(lock_descriptor)
            try:
                lock_named = _safe_regular_stat(lock_path)
            except OSError as exc:
                raise BaselineEnrollmentError(
                    "baseline enrollment lock is not a unique regular file"
                ) from exc
            if (
                not stat.S_ISREG(lock_opened.st_mode)
                or int(lock_opened.st_nlink) != 1
                or bool(int(getattr(lock_opened, "st_file_attributes", 0)) & _REPARSE_POINT)
                or not _same_filesystem_object(lock_opened, lock_named)
                or not _windows_handle_matches_path(lock_descriptor, str(lock_path))
            ):
                raise BaselineEnrollmentError(
                    "baseline enrollment lock is not a unique regular file"
                )
            try:
                baseline_identity = self._opened_baseline_identity(parent_descriptor)
            except (BaselineIntegrityError, OSError) as exc:
                raise BaselineEnrollmentError(
                    "baseline object is not a unique, canonical regular file"
                ) from exc
            custody = _EnrollmentCustody(
                root_identity=_object_identity(root_opened),
                parent_identity=_object_identity(parent_opened),
                lock_identity=_object_identity(lock_opened),
                lock_descriptor=lock_descriptor,
                root_descriptor=root_descriptor,
                parent_descriptor=parent_descriptor,
                baseline_identity=baseline_identity,
            )
            self._transition_local.custody = custody
            self._assert_transition_custody(custody)
            os.ftruncate(lock_descriptor, 0)
            os.write(lock_descriptor, b"\x00")
            os.fsync(lock_descriptor)
            try:
                yield
            except BaseException:
                try:
                    self._assert_transition_custody(custody)
                except (BaselineEnrollmentError, BaselineIntegrityError, OSError) as custody_error:
                    raise BaselineEnrollmentError(
                        "baseline enrollment custody changed while the operation failed"
                    ) from custody_error
                raise
            self._assert_transition_custody(custody)
        finally:
            try:
                del self._transition_local.custody
            except AttributeError:
                pass
            try:
                if lock_locked:
                    import fcntl

                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                if root_locked:
                    import fcntl

                    fcntl.flock(root_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_descriptor)
            os.close(parent_descriptor)
            os.close(root_descriptor)

    def _reconcile_windows_promotion(
        self,
        *,
        custody: _EnrollmentCustody,
        provisional_descriptor: int,
        temporary: Path,
        temporary_identity: tuple[int, int],
        encoded: bytes,
        provisional_encoded: bytes,
    ) -> str:
        """Classify a failed ReplaceFileW call without trusting its error alone."""
        if os.name != "nt":
            return "ambiguous"
        try:
            retained = os.fstat(provisional_descriptor)
            destination_named = _safe_regular_stat(self.path)
            try:
                temporary_named = _safe_regular_stat(temporary)
            except FileNotFoundError:
                temporary_named = None
        except (OSError, RuntimeError, ValueError):
            return "ambiguous"
        if _object_identity(retained) != custody.baseline_identity:
            return "ambiguous"

        destination_identity = _object_identity(destination_named)
        if destination_identity == temporary_identity:
            if (
                temporary_named is not None
                or not _exact_descriptor_bytes_match(
                    provisional_descriptor,
                    expected_identity=custody.baseline_identity,
                    expected_link_count=0,
                    expected=provisional_encoded,
                )
            ):
                return "ambiguous"
            if not _exact_regular_file_bytes_match(
                self.path,
                expected_identity=temporary_identity,
                expected=encoded,
            ):
                return "ambiguous"
            return "promoted"

        if (
            destination_identity != custody.baseline_identity
            or temporary_named is None
            or _object_identity(temporary_named) != temporary_identity
            or not _windows_handle_matches_path(provisional_descriptor, str(self.path))
            or not _exact_descriptor_bytes_match(
                provisional_descriptor,
                expected_identity=custody.baseline_identity,
                expected_link_count=1,
                expected=provisional_encoded,
            )
            or not _exact_regular_file_bytes_match(
                temporary,
                expected_identity=temporary_identity,
                expected=encoded,
            )
        ):
            return "ambiguous"
        try:
            self._verify_transition_namespace_custody(custody)
        except (BaselineEnrollmentError, BaselineIntegrityError, OSError, RuntimeError, ValueError):
            return "ambiguous"
        return "unchanged"

    def _replace_provisional(self, body: Mapping[str, object], expected_signature: str) -> None:
        custody = self._current_transition()
        if custody is None or custody.baseline_identity is None:
            raise BaselineEnrollmentError(
                "baseline promotion requires retained enrollment custody"
            )
        self._assert_transition_custody(custody)
        encoded = self._encoded(body)
        loaded = self._load()
        if loaded is None or loaded[0]["state"] != "provisional" or loaded[2] != expected_signature:
            raise BaselineEnrollmentError("provisional baseline changed during enrollment")
        provisional_descriptor = -1
        temporary = self.path.with_name(
            f".{self.path.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
        )
        if not self._path_safe(temporary, allow_missing=True):
            raise BaselineEnrollmentError("baseline promotion temporary path is unsafe")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        temporary_identity: tuple[int, int] | None = None
        replaced = False
        try:
            if os.name != "nt":
                descriptor = os.open(
                    temporary.name,
                    flags,
                    0o600,
                    dir_fd=custody.parent_descriptor,
                )
            else:
                descriptor = os.open(temporary, flags, 0o600)
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or int(opened.st_nlink) != 1
                    or bool(int(getattr(opened, "st_file_attributes", 0)) & _REPARSE_POINT)
                    or not _windows_handle_matches_path(descriptor, str(temporary))
                ):
                    raise BaselineEnrollmentError(
                        "baseline promotion temporary object is unsafe"
                    )
                temporary_identity = _object_identity(opened)
                view = memoryview(encoded)
                written = 0
                while written < len(view):
                    count = os.write(descriptor, view[written:])
                    if count <= 0:
                        raise OSError("baseline promotion write made no progress")
                    written += count
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            temporary_named = _safe_regular_stat(temporary)
            if _object_identity(temporary_named) != temporary_identity:
                raise BaselineEnrollmentError(
                    "baseline promotion temporary object changed"
                )
            self._assert_transition_custody(custody)
            loaded = self._load()
            if loaded is None or loaded[2] != expected_signature:
                raise BaselineEnrollmentError("provisional baseline changed before promotion")
            provisional_encoded = self._encoded(loaded[0])
            self._assert_transition_custody(custody)
            read_flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            if os.name == "nt":
                provisional_descriptor = _open_windows_promotion_guard(self.path)
            else:
                provisional_descriptor = os.open(
                    self.path.name,
                    read_flags,
                    dir_fd=custody.parent_descriptor,
                )
            provisional_opened = os.fstat(provisional_descriptor)
            provisional_named = _safe_regular_stat(self.path)
            if (
                _object_identity(provisional_opened) != custody.baseline_identity
                or not _same_filesystem_object(provisional_opened, provisional_named)
                or int(provisional_opened.st_nlink) != 1
                or not _windows_handle_matches_path(provisional_descriptor, str(self.path))
            ):
                raise BaselineEnrollmentError(
                    "provisional baseline promotion identity is ambiguous"
                )
            retained_before = os.fstat(provisional_descriptor)
            named_before = _safe_regular_stat(self.path)
            if (
                _object_identity(retained_before) != custody.baseline_identity
                or int(retained_before.st_nlink) != 1
                or not _same_filesystem_object(retained_before, named_before)
            ):
                raise BaselineEnrollmentError("provisional baseline changed before promotion")
            retry_error: OSError | None = None
            for attempt in range(len(_WINDOWS_REPLACE_RETRY_DELAYS) + 1):
                if attempt:
                    time.sleep(_WINDOWS_REPLACE_RETRY_DELAYS[attempt - 1])
                    if self._reconcile_windows_promotion(
                        custody=custody,
                        provisional_descriptor=provisional_descriptor,
                        temporary=temporary,
                        temporary_identity=temporary_identity,
                        encoded=encoded,
                        provisional_encoded=provisional_encoded,
                    ) != "unchanged":
                        raise BaselineEnrollmentError(
                            "atomic baseline promotion changed before a verified retry"
                        ) from retry_error
                try:
                    _replace_baseline_file(
                        temporary,
                        self.path,
                        parent_descriptor=custody.parent_descriptor,
                    )
                except OSError as exc:
                    if (
                        os.name != "nt"
                        or _windows_error_code(exc) != _WINDOWS_REPLACE_RETRY_ERROR
                    ):
                        raise
                    retry_error = exc
                    state = self._reconcile_windows_promotion(
                        custody=custody,
                        provisional_descriptor=provisional_descriptor,
                        temporary=temporary,
                        temporary_identity=temporary_identity,
                        encoded=encoded,
                        provisional_encoded=provisional_encoded,
                    )
                    if state == "promoted":
                        replaced = True
                        break
                    if state != "unchanged":
                        raise BaselineEnrollmentError(
                            "atomic baseline promotion returned an ambiguous result"
                        ) from exc
                    if attempt == len(_WINDOWS_REPLACE_RETRY_DELAYS):
                        raise BaselineEnrollmentError(
                            "atomic baseline promotion remained unavailable after bounded retries"
                        ) from exc
                    continue
                replaced = True
                break
            promoted = os.lstat(self.path)
            retired = os.fstat(provisional_descriptor)
            if (
                not stat.S_ISREG(promoted.st_mode)
                or stat.S_ISLNK(promoted.st_mode)
                or bool(int(getattr(promoted, "st_file_attributes", 0)) & _REPARSE_POINT)
                or int(promoted.st_nlink) != 1
                or _object_identity(promoted) != temporary_identity
                or _object_identity(retired) != custody.baseline_identity
                or int(retired.st_nlink) != 0
            ):
                raise BaselineEnrollmentError(
                    "baseline promotion left an aliased or ambiguous object"
                )
            custody.baseline_identity = _object_identity(promoted)
            os.close(provisional_descriptor)
            provisional_descriptor = -1
            self._assert_transition_custody(custody)
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        except BaseException as operation_error:
            alias_removed = False
            if provisional_descriptor >= 0:
                try:
                    retained = os.fstat(provisional_descriptor)
                    current = os.lstat(self.path)
                    if (
                        stat.S_ISREG(current.st_mode)
                        and not stat.S_ISLNK(current.st_mode)
                        and not bool(
                            int(getattr(current, "st_file_attributes", 0))
                            & _REPARSE_POINT
                        )
                        and _object_identity(retained) == custody.baseline_identity
                        and _same_filesystem_object(retained, current)
                        and int(current.st_nlink) > 1
                    ):
                        if os.name != "nt":
                            os.unlink(
                                self.path.name,
                                dir_fd=custody.parent_descriptor,
                            )
                        else:
                            self.path.unlink()
                        try:
                            _safe_regular_stat(self.path)
                        except FileNotFoundError:
                            custody.baseline_identity = None
                            alias_removed = True
                except (BaselineIntegrityError, OSError):
                    pass
            if replaced and temporary_identity is not None:
                try:
                    current = os.lstat(self.path)
                    if _object_identity(current) == temporary_identity:
                        if os.name != "nt":
                            os.unlink(self.path.name, dir_fd=custody.parent_descriptor)
                        else:
                            self.path.unlink()
                        custody.baseline_identity = None
                except OSError:
                    pass
            if alias_removed:
                raise BaselineEnrollmentError(
                    "baseline promotion left an aliased or ambiguous object"
                ) from operation_error
            raise
        finally:
            try:
                current = _safe_regular_stat(temporary)
                if temporary_identity is not None and _object_identity(current) == temporary_identity:
                    if os.name != "nt":
                        os.unlink(temporary.name, dir_fd=custody.parent_descriptor)
                    else:
                        temporary.unlink()
            except OSError:
                pass
            if provisional_descriptor >= 0:
                os.close(provisional_descriptor)

    def observe(
        self,
        snapshot: AuthExtensionSnapshot,
        *,
        initialize_provisional: bool = True,
    ) -> BaselineComparison:
        assessment = assess_auth_extension_snapshot(snapshot)
        if self.keys is None:
            return BaselineComparison(
                "unknown",
                False,
                False,
                True,
                "Purpose-separated HMAC authority is unavailable; no baseline was trusted or written.",
                0,
            )
        try:
            loaded = self._load()
        except BaselineIntegrityError as exc:
            return BaselineComparison("tampered", False, False, True, str(exc), 0)
        except OSError:
            return BaselineComparison(
                "unknown",
                False,
                False,
                True,
                "Authenticated baseline could not be safely opened or read.",
                0,
            )
        if loaded is None:
            if not assessment.baseline_eligible:
                return BaselineComparison(
                    "unknown",
                    False,
                    False,
                    True,
                    "Incomplete evidence is not eligible for even provisional baseline creation.",
                    0,
                )
            if initialize_provisional:
                try:
                    created = self._create_exclusive(
                        self._encoded(self._body(snapshot, state="provisional", enrollment=None))
                    )
                    if not created:
                        loaded = self._load()
                except (BaselineIntegrityError, OSError):
                    return BaselineComparison(
                        "unknown",
                        False,
                        False,
                        True,
                        "Provisional baseline could not be created safely.",
                        0,
                    )
            if loaded is None:
                return BaselineComparison(
                    "provisional",
                    False,
                    True,
                    True,
                    "A complete first observation was recorded exclusively as provisional; "
                    "explicit reviewed operator enrollment is still required.",
                    0,
                )
        assert loaded is not None
        body, previous, _signature = loaded
        now = float(self.clock())
        captured_at = float(body["captured_at"])
        if not math.isfinite(now) or now < captured_at - 300:
            return BaselineComparison(
                "stale",
                bool(body["state"] == "trusted"),
                False,
                True,
                "Local clock moved behind the authenticated capture time; freshness cannot be proven.",
                0,
            )
        age = min(2**31 - 1, max(0, int(now - captured_at)))
        compared = compare_auth_extension_snapshots(previous, snapshot)
        trusted = body["state"] == "trusted"
        if compared.status == "host-mismatch":
            return BaselineComparison(
                "host-mismatch", False, False, True, compared.reason, age, compared.changes
            )
        if compared.status == "drift":
            return BaselineComparison(
                "drift", trusted, age <= self.freshness_cap_seconds, True, compared.reason, age, compared.changes
            )
        if age > self.freshness_cap_seconds:
            return BaselineComparison(
                "stale",
                trusted,
                False,
                True,
                "Authenticated local baseline exceeded its explicit freshness cap; no "
                "independent clock or high-water witness is available.",
                age,
            )
        if not trusted:
            return BaselineComparison(
                "provisional",
                False,
                True,
                True,
                "Authenticated baseline is stable but remains provisional and unreviewed.",
                age,
            )
        if compared.status == "unknown":
            return BaselineComparison(
                "unknown", True, True, True, compared.reason, age
            )
        return BaselineComparison(
            "stable",
            True,
            True,
            True,
            "Reviewed authenticated baseline is stable; assurance remains local-only without "
            "an independent high-water witness.",
            age,
        )

    def establish_trusted(
        self,
        snapshot: AuthExtensionSnapshot,
        *,
        operator: str,
        reason: str,
        approved: bool,
    ) -> None:
        """Enroll one reviewed snapshot; drift is never silently promoted."""
        if approved is not True:
            raise BaselineEnrollmentError("trusted enrollment requires approved=True")
        operator_ref = _bounded_text(operator, "operator", maximum=160)
        review_reason = _bounded_text(reason, "enrollment reason", maximum=512)
        if len(review_reason) < 12:
            raise BaselineEnrollmentError("enrollment reason must contain at least 12 characters")
        if self.keys is None:
            raise BaselineEnrollmentError("baseline HMAC authority is unavailable")
        assessment = assess_auth_extension_snapshot(snapshot)
        if not assessment.baseline_eligible:
            raise BaselineEnrollmentError("incomplete evidence cannot be enrolled as trusted")
        approved_at = float(self.clock())
        if not math.isfinite(approved_at) or approved_at < 0:
            raise BaselineEnrollmentError("enrollment clock is invalid")
        enrollment = {
            "operator_token": _token(
                self.keys.privacy_key, b"operator", operator_ref, "operator"
            ),
            "reason_digest": _token(
                self.keys.privacy_key, b"reason", review_reason, "reason"
            ),
            "approved_at": approved_at,
        }
        with self._exclusive_transition():
            try:
                loaded = self._load(require_trusted_slot=False)
            except (BaselineIntegrityError, OSError) as exc:
                raise BaselineEnrollmentError(
                    "existing baseline could not be authenticated for enrollment"
                ) from exc
            body = self._body(snapshot, state="trusted", enrollment=enrollment)
            if loaded is None:
                self._assert_trusted_slot_unclaimed()
                if not self._create_exclusive(self._encoded(body)):
                    raise BaselineEnrollmentError("baseline appeared during enrollment")
                self._commit_trusted_slot()
                if self._load() is None:
                    raise BaselineEnrollmentError("trusted baseline registration was not durable")
                return
            existing_body, previous, signature = loaded
            if existing_body["state"] == "trusted":
                registered = self._load_trusted_slot()
                if registered is None:
                    compared = compare_auth_extension_snapshots(previous, snapshot)
                    if compared.status != "stable":
                        raise BaselineEnrollmentError(
                            "unregistered trusted baseline differs from reviewed evidence"
                        )
                    self._commit_trusted_slot()
                    if self._load() is None:
                        raise BaselineEnrollmentError(
                            "trusted baseline registration recovery was not durable"
                        )
                    return
                raise BaselineEnrollmentError(
                    "trusted baseline replacement requires a separate explicit reset workflow"
                )
            self._assert_trusted_slot_unclaimed()
            compared = compare_auth_extension_snapshots(previous, snapshot)
            if compared.status != "stable":
                raise BaselineEnrollmentError(
                    "current evidence differs from the provisional observation; review cannot promote drift"
                )
            self._replace_provisional(body, signature)
            self._commit_trusted_slot()
            if self._load() is None:
                raise BaselineEnrollmentError("trusted baseline registration was not durable")


def _unknown_surface(surface: str, reason: str) -> AuthExtensionSurface:
    return AuthExtensionSurface(SurfaceCoverage(surface, "unknown", reason, 0, 0), ())


def _unknown_component(
    component_token: str,
    *,
    path_token: str = "",
    status: str = "unknown",
    reason: str,
) -> ComponentEvidence:
    return ComponentEvidence(
        component_token=component_token,
        path_token=path_token,
        resolution_status=status,
        resolution_reason=reason,
        evidence_status="unknown",
    )


@dataclass(slots=True)
class _CollectionBudget:
    started: float
    deadline: float
    total_bytes: int = 0
    components: int = 0


def _api_windows_directories() -> tuple[str | None, str | None]:
    if os.name != "nt":
        return None, None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_windows = kernel32.GetWindowsDirectoryW
        get_windows.argtypes = (wintypes.LPWSTR, wintypes.UINT)
        get_windows.restype = wintypes.UINT
        get_system = kernel32.GetSystemDirectoryW
        get_system.argtypes = (wintypes.LPWSTR, wintypes.UINT)
        get_system.restype = wintypes.UINT

        def read(function: Any) -> str | None:
            buffer = ctypes.create_unicode_buffer(32_768)
            count = function(buffer, len(buffer))
            if not count or count >= len(buffer):
                return None
            return buffer.value

        return read(get_windows), read(get_system)
    except (AttributeError, OSError, RuntimeError, ValueError):
        return None, None


def _windows_final_handle_path(descriptor: int) -> str | None:
    """Return the kernel-resolved path for an already-open Windows handle."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        function = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
        function.argtypes = (
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        function.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(1024)
        count = function(msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0)
        if not count:
            return None
        if count >= len(buffer):
            if count >= 32_768:
                return None
            buffer = ctypes.create_unicode_buffer(count + 1)
            count = function(msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0)
            if not count or count >= len(buffer):
                return None
        rendered = buffer.value
        if rendered.startswith("\\\\?\\UNC\\"):
            rendered = "\\\\" + rendered[8:]
        elif rendered.startswith("\\\\?\\"):
            rendered = rendered[4:]
        return rendered
    except (AttributeError, ImportError, OSError, RuntimeError, ValueError):
        return None


def _windows_handle_matches_path(descriptor: int, expected: str) -> bool:
    if os.name != "nt":
        return True
    final = _windows_final_handle_path(descriptor)
    if final is None:
        return False
    try:
        return ntpath.normcase(ntpath.abspath(final)) == ntpath.normcase(
            ntpath.abspath(expected)
        )
    except (OSError, ValueError):
        return False


def resolve_registered_component_path(
    configured: object,
    *,
    windows_directory: str | None,
    system_directory: str | None,
) -> tuple[str | None, str]:
    """Resolve one DLL path without commands, ``PATH`` search, or broad env expansion."""
    if not isinstance(configured, str):
        return None, "registered component path is not text"
    value = configured.strip()
    if not value or len(value) > 1024 or any(ord(character) < 32 for character in value):
        return None, "registered component path is empty, controlled, or oversized"
    if value.startswith('"') and value.endswith('"') and value.count('"') == 2:
        value = value[1:-1].strip()
    if any(character in value for character in ('"', "'", "|", ";", "\x00")):
        return None, "registered component path is command-like or ambiguous"
    lowered = value.casefold()
    substitutions: tuple[tuple[str, str | None], ...] = (
        ("%systemroot%", windows_directory),
        ("%windir%", windows_directory),
        ("%systemdirectory%", system_directory),
    )
    for marker, replacement in substitutions:
        if lowered.startswith(marker):
            if replacement is None:
                return None, f"WinAPI directory for {marker} is unavailable"
            value = replacement + value[len(marker) :]
            lowered = value.casefold()
            break
    if lowered.startswith("\\systemroot\\"):
        if windows_directory is None:
            return None, "WinAPI Windows directory is unavailable"
        value = windows_directory + value[len("\\systemroot") :]
    if "%" in value:
        return None, "unrecognized environment variable was not expanded"
    if any(part == ".." for part in PureWindowsPath(value).parts):
        return None, "parent traversal is not accepted in a registered component path"
    path = PureWindowsPath(value)
    if not path.is_absolute():
        if len(path.parts) != 1 or system_directory is None:
            return None, "relative component path is ambiguous"
        basename = path.name
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", basename):
            return None, "package basename contains unsupported characters"
        if "." not in basename:
            basename += ".dll"
        value = ntpath.join(system_directory, basename)
        path = PureWindowsPath(value)
    if path.drive.startswith("\\") or str(path).startswith("\\"):
        return None, "network component paths are not inspected"
    if not re.fullmatch(r"[A-Za-z]:", path.drive):
        return None, "component path is not on a local drive"
    normalized = ntpath.normpath(str(path))
    if len(normalized) > 1024:
        return None, "normalized component path exceeds its bound"
    return normalized, "resolved without PATH search or command execution"


def _registry_type_name(registry: Any, value_type: object) -> str:
    mapping = {
        getattr(registry, "REG_SZ", -1): "REG_SZ",
        getattr(registry, "REG_EXPAND_SZ", -2): "REG_EXPAND_SZ",
        getattr(registry, "REG_MULTI_SZ", -3): "REG_MULTI_SZ",
    }
    return mapping.get(value_type, "unknown")


def _file_security_from_handle(
    descriptor: int,
    privacy_key: bytes,
) -> tuple[str, str, str]:
    """Return purpose-keyed owner/ACL evidence when pywin32 can bind to the handle."""
    if os.name != "nt":
        return "", "", "unknown"
    try:
        import msvcrt
        import win32security  # type: ignore

        security = win32security.GetSecurityInfo(
            msvcrt.get_osfhandle(descriptor),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION,
        )
        owner = security.GetSecurityDescriptorOwner()
        owner_string = win32security.ConvertSidToStringSid(owner) if owner is not None else ""
        dacl = security.GetSecurityDescriptorDacl()
        ace_rows: list[tuple[object, ...]] = []
        if dacl is not None:
            for index in range(min(int(dacl.GetAceCount()), 4096)):
                ace = dacl.GetAce(index)
                header = ace[0]
                mask = ace[1]
                sid = ace[2]
                ace_rows.append(
                    (
                        int(header[0]),
                        int(header[1]),
                        int(mask),
                        win32security.ConvertSidToStringSid(sid),
                    )
                )
        owner_token = _token(privacy_key, b"file-owner", owner_string, "owner") if owner_string else ""
        acl_token = _token(privacy_key, b"file-acl", _canonical(ace_rows).decode("ascii"), "acl")
        return owner_token, acl_token, "observed"
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        return "", "", "unknown"


class WindowsAuthExtensionEvidenceProvider:
    """Fixed-catalog Windows collector with bounded handle-based file hashing."""

    def __init__(
        self,
        privacy_key: bytes,
        *,
        platform_name: str | None = None,
        registry_module: Any | None = None,
        windows_directory: str | None = None,
        system_directory: str | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        signature_probe: Callable[[str, int], Mapping[str, str]] | None = None,
    ) -> None:
        if not isinstance(privacy_key, bytes) or len(privacy_key) != 32:
            raise AuthExtensionError("provider privacy key must contain exactly 32 bytes")
        self.privacy_key = privacy_key
        self.platform_name = (platform_name or sys.platform).casefold()
        if registry_module is None and self.platform_name.startswith("win"):
            try:
                import winreg

                registry_module = winreg
            except ImportError:
                registry_module = None
        self.registry = registry_module
        api_windows, api_system = _api_windows_directories()
        self.windows_directory = windows_directory or api_windows
        self.system_directory = system_directory or api_system
        self.monotonic = monotonic
        self.wall_clock = wall_clock
        self.signature_probe = signature_probe

    def _host_binding(self) -> tuple[str, bool]:
        machine_ref = "windows-machine-identity-unavailable"
        observed = False
        registry = self.registry
        if registry is not None:
            try:
                access = getattr(registry, "KEY_READ", 0) | getattr(registry, "KEY_WOW64_64KEY", 0)
                with registry.OpenKey(
                    registry.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Cryptography",
                    0,
                    access,
                ) as key:
                    value, value_type = registry.QueryValueEx(key, "MachineGuid")
                if value_type == getattr(registry, "REG_SZ", object()) and isinstance(value, str):
                    rendered = value.strip()
                    if 1 <= len(rendered) <= 160 and not any(ord(char) < 32 for char in rendered):
                        machine_ref = rendered
                        observed = True
            except (OSError, TypeError, ValueError):
                pass
        return _token(self.privacy_key, b"host", machine_ref, "host"), observed

    def _registry_views(self) -> tuple[tuple[str, int], ...]:
        registry = self.registry
        if registry is None:
            return ()
        views = [("64", int(getattr(registry, "KEY_WOW64_64KEY", 0)))]
        flag32 = int(getattr(registry, "KEY_WOW64_32KEY", 0))
        if flag32 != views[0][1]:
            views.append(("32", flag32))
        return tuple(views)

    def _key_security(self, key: object) -> tuple[str, str, str]:
        if os.name != "nt":
            return "", "", "unknown"
        try:
            import win32security  # type: ignore

            handle = int(key)  # PyHKEY exposes the native HKEY integer.
            security = win32security.GetSecurityInfo(
                handle,
                win32security.SE_REGISTRY_KEY,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
            owner = security.GetSecurityDescriptorOwner()
            owner_string = win32security.ConvertSidToStringSid(owner) if owner is not None else ""
            dacl = security.GetSecurityDescriptorDacl()
            rows: list[tuple[object, ...]] = []
            if dacl is not None:
                for index in range(min(int(dacl.GetAceCount()), 4096)):
                    ace = dacl.GetAce(index)
                    rows.append(
                        (
                            int(ace[0][0]),
                            int(ace[0][1]),
                            int(ace[1]),
                            win32security.ConvertSidToStringSid(ace[2]),
                        )
                    )
            return (
                _token(self.privacy_key, b"registry-owner", owner_string, "owner")
                if owner_string
                else "",
                _token(
                    self.privacy_key,
                    b"registry-acl",
                    _canonical(rows).decode("ascii"),
                    "acl",
                ),
                "observed",
            )
        except (ImportError, OSError, RuntimeError, TypeError, ValueError):
            return "", "", "unknown"

    def _binding(
        self,
        *,
        surface: str,
        order: int,
        configured: str,
        binding_identity: str | None = None,
        registry_source: str,
        registry_view: str,
        registry_type: str,
        key_security: tuple[str, str, str],
    ) -> tuple[AuthExtensionBinding, str, str, str]:
        logical_identity = (binding_identity or configured).casefold()
        identity = "\x1f".join((surface, registry_source, registry_view, logical_identity))
        binding_token = _token(self.privacy_key, b"binding", identity, "binding")
        component_token = _token(
            self.privacy_key,
            b"component",
            f"{surface}\x1f{configured}",
            "component",
        )
        resolved, resolution_reason = resolve_registered_component_path(
            configured,
            windows_directory=self.windows_directory,
            system_directory=self.system_directory,
        )
        path_token = (
            _token(self.privacy_key, b"path", resolved, "path") if resolved is not None else ""
        )
        return (
            AuthExtensionBinding(
                surface,
                order,
                binding_token,
                registry_source,
                registry_view,
                registry_type,
                component_token,
                key_security[0],
                key_security[1],
                key_security[2],
            ),
            resolved or "",
            path_token,
            resolution_reason,
        )

    def _inspect_component(
        self,
        component_token: str,
        resolved_path: str,
        path_token: str,
        resolution_reason: str,
        budget: _CollectionBudget,
    ) -> tuple[ComponentEvidence, LocalComponentDetail | None]:
        if not resolved_path:
            return (
                _unknown_component(
                    component_token,
                    status="unknown",
                    reason=resolution_reason,
                ),
                None,
            )
        detail = LocalComponentDetail(component_token, resolved_path, resolution_reason)
        if budget.components >= MAX_COMPONENTS:
            return (
                _unknown_component(
                    component_token,
                    path_token=path_token,
                    status="rejected",
                    reason="component inventory bound reached",
                ),
                detail,
            )
        budget.components += 1
        if self.monotonic() > budget.deadline:
            return (
                _unknown_component(
                    component_token,
                    path_token=path_token,
                    status="rejected",
                    reason="collector time budget reached",
                ),
                detail,
            )
        path = Path(resolved_path)
        try:
            before_path = path.stat(follow_symlinks=False)
            if stat.S_ISLNK(before_path.st_mode) or getattr(
                before_path, "st_file_attributes", 0
            ) & _REPARSE_POINT:
                raise OSError("component path is link or reparse backed")
            if not stat.S_ISREG(before_path.st_mode):
                raise OSError("component path is not a regular file")
            if before_path.st_size > MAX_COMPONENT_BYTES:
                return (
                    _unknown_component(
                        component_token,
                        path_token=path_token,
                        status="rejected",
                        reason="component exceeds per-file hashing bound",
                    ),
                    detail,
                )
            if budget.total_bytes + before_path.st_size > MAX_TOTAL_COMPONENT_BYTES:
                return (
                    _unknown_component(
                        component_token,
                        path_token=path_token,
                        status="rejected",
                        reason="aggregate component hashing bound reached",
                    ),
                    detail,
                )
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_dev != before_path.st_dev
                    or before.st_ino != before_path.st_ino
                    or before.st_size != before_path.st_size
                    or not _windows_handle_matches_path(descriptor, resolved_path)
                ):
                    raise OSError("component identity changed before hashing")
                hasher = hashlib.sha256()
                remaining = before.st_size
                while remaining:
                    if self.monotonic() > budget.deadline:
                        raise TimeoutError("collector time budget reached while hashing")
                    chunk = os.read(descriptor, min(1024 * 1024, remaining))
                    if not chunk:
                        raise OSError("component ended before its handle-bound size")
                    hasher.update(chunk)
                    remaining -= len(chunk)
                after = os.fstat(descriptor)
                if (
                    before.st_dev != after.st_dev
                    or before.st_ino != after.st_ino
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                ):
                    raise OSError("component changed during hashing")
                owner_token, acl_digest, security_state = _file_security_from_handle(
                    descriptor, self.privacy_key
                )
                signature: Mapping[str, str] = {}
                if self.signature_probe is not None:
                    try:
                        candidate = self.signature_probe(resolved_path, descriptor)
                        signature = candidate if isinstance(candidate, Mapping) else {}
                    except Exception:
                        signature = {"authenticode_state": "error", "catalog_state": "error"}
                authenticode = str(signature.get("authenticode_state", "unknown"))
                catalog = str(signature.get("catalog_state", "unknown"))
                thumbprint = str(signature.get("signer_thumbprint", ""))
                version = str(signature.get("file_version", ""))
                if authenticode not in {"verified", "unsigned", "invalid", "unknown", "error"}:
                    authenticode = "error"
                if catalog not in {"verified", "not-found", "unknown", "error"}:
                    catalog = "error"
                if thumbprint and not _HEX_64.fullmatch(thumbprint):
                    thumbprint = ""
                if version and not _SAFE_VERSION.fullmatch(version):
                    version = ""
                final = os.fstat(descriptor)
                if (
                    before.st_dev != final.st_dev
                    or before.st_ino != final.st_ino
                    or before.st_size != final.st_size
                    or before.st_mtime_ns != final.st_mtime_ns
                    or not _windows_handle_matches_path(descriptor, resolved_path)
                ):
                    raise OSError("component changed during metadata assurance probes")
                if self.monotonic() > budget.deadline:
                    raise TimeoutError("collector time budget reached during assurance probes")
                signature_complete = authenticode == "verified" or (
                    authenticode == "unsigned" and catalog == "verified"
                )
                evidence_state = (
                    "complete"
                    if signature_complete
                    and catalog in {"verified", "not-found"}
                    and bool(thumbprint)
                    and security_state == "observed"
                    and bool(owner_token)
                    and bool(acl_digest)
                    else "partial"
                )
                identity = _token(
                    self.privacy_key,
                    b"file-identity",
                    f"{before.st_dev}:{before.st_ino}:{before.st_size}:{before.st_mtime_ns}",
                    "file",
                )
                budget.total_bytes += before.st_size
                return (
                    ComponentEvidence(
                        component_token,
                        path_token,
                        "resolved",
                        "",
                        hasher.hexdigest(),
                        before.st_size,
                        identity,
                        authenticode,
                        catalog,
                        thumbprint,
                        version,
                        owner_token,
                        acl_digest,
                        evidence_state,
                    ),
                    detail,
                )
            finally:
                os.close(descriptor)
        except FileNotFoundError:
            return (
                _unknown_component(
                    component_token,
                    path_token=path_token,
                    status="missing",
                    reason="registered component file is missing",
                ),
                detail,
            )
        except TimeoutError:
            return (
                _unknown_component(
                    component_token,
                    path_token=path_token,
                    status="rejected",
                    reason="collector time budget reached while hashing",
                ),
                detail,
            )
        except OSError:
            return (
                _unknown_component(
                    component_token,
                    path_token=path_token,
                    status="error",
                    reason="component file could not be safely opened and proven stable",
                ),
                detail,
            )

    def _lsa_surface(
        self,
        surface: str,
        value_name: str,
    ) -> tuple[AuthExtensionSurface, list[tuple[AuthExtensionBinding, str, str, str]]]:
        registry = self.registry
        assert registry is not None
        rows: list[tuple[AuthExtensionBinding, str, str, str]] = []
        errors: list[str] = []
        enumerated = 0
        paths = ((_LSA_ROOT, "lsa"), (_LSA_ROOT + r"\OSConfig", "lsa-osconfig"))
        for key_path, source in paths:
            try:
                access = getattr(registry, "KEY_READ", 0) | getattr(
                    registry, "KEY_WOW64_64KEY", 0
                )
                with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, key_path, 0, access) as key:
                    security = self._key_security(key)
                    try:
                        value, value_type = registry.QueryValueEx(key, value_name)
                    except FileNotFoundError:
                        value, value_type = [], getattr(registry, "REG_MULTI_SZ", -1)
                type_name = _registry_type_name(registry, value_type)
                if type_name == "REG_MULTI_SZ" and isinstance(value, (list, tuple)):
                    values = list(value)
                elif type_name in {"REG_SZ", "REG_EXPAND_SZ"} and isinstance(value, str):
                    values = [value]
                else:
                    errors.append(f"{source} returned an unsupported registry type")
                    continue
                if len(values) > MAX_BINDINGS_PER_SURFACE * 4:
                    errors.append(f"{source} exceeded the registry value bound")
                for configured in values[: MAX_BINDINGS_PER_SURFACE * 4]:
                    enumerated += 1
                    if len(rows) >= MAX_BINDINGS_PER_SURFACE:
                        continue
                    if not isinstance(configured, str) or not configured.strip() or len(configured) > 1024:
                        errors.append(f"{source} contained an invalid bounded package value")
                        continue
                    rows.append(
                        self._binding(
                            surface=surface,
                            order=len(rows),
                            configured=configured.strip(),
                            registry_source=source,
                            registry_view="64",
                            registry_type=type_name,
                            key_security=security,
                        )
                    )
            except FileNotFoundError:
                if source == "lsa":
                    errors.append("primary LSA key is unavailable")
            except OSError:
                errors.append(f"{source} could not be read")
        dropped = max(0, enumerated - len(rows))
        status = "partial" if errors or dropped else "complete"
        reason = "; ".join(dict.fromkeys(errors))[:1000] if errors else (
            "binding bound reached" if dropped else ""
        )
        coverage = SurfaceCoverage(surface, status, reason, enumerated, len(rows), dropped)
        return AuthExtensionSurface(coverage, tuple(item[0] for item in rows)), rows

    def _credential_surface(
        self,
        surface: str,
    ) -> tuple[AuthExtensionSurface, list[tuple[AuthExtensionBinding, str, str, str]]]:
        registry = self.registry
        assert registry is not None
        rows: list[tuple[AuthExtensionBinding, str, str, str]] = []
        errors: list[str] = []
        enumerated = 0
        for view_name, view_flag in self._registry_views():
            try:
                access = getattr(registry, "KEY_READ", 0) | view_flag
                with registry.OpenKey(
                    registry.HKEY_LOCAL_MACHINE, _CREDENTIAL_ROOTS[surface], 0, access
                ) as root:
                    security = self._key_security(root)
                    index = 0
                    clsids: list[str] = []
                    while index < MAX_BINDINGS_PER_SURFACE * 4:
                        try:
                            clsid = registry.EnumKey(root, index)
                        except OSError as exc:
                            if getattr(exc, "winerror", None) in {259, None}:
                                break
                            raise
                        index += 1
                        clsids.append(clsid)
                    if len(clsids) > MAX_BINDINGS_PER_SURFACE:
                        errors.append(f"{view_name}-bit credential registration bound reached")
                    for clsid in sorted(clsids, key=lambda item: str(item).casefold()):
                        enumerated += 1
                        if len(rows) >= MAX_BINDINGS_PER_SURFACE:
                            continue
                        if not isinstance(clsid, str) or _CLSID.fullmatch(clsid) is None:
                            errors.append(f"{view_name}-bit view contained an invalid CLSID")
                            continue
                        server_key = rf"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32"
                        try:
                            with registry.OpenKey(
                                registry.HKEY_LOCAL_MACHINE, server_key, 0, access
                            ) as server:
                                server_security = self._key_security(server)
                                configured, value_type = registry.QueryValueEx(server, "")
                            type_name = _registry_type_name(registry, value_type)
                        except (FileNotFoundError, OSError):
                            configured = ""
                            type_name = "unknown"
                            server_security = security
                            errors.append(f"{view_name}-bit CLSID has no readable InprocServer32")
                        if not isinstance(configured, str) or not configured.strip() or len(configured) > 1024:
                            configured_for_token = f"unresolved-clsid:{clsid}"
                        else:
                            configured_for_token = configured.strip()
                        rows.append(
                            self._binding(
                                surface=surface,
                                order=len(rows),
                                configured=configured_for_token,
                                binding_identity=clsid,
                                registry_source="credential-clsid-inprocserver32",
                                registry_view=view_name,
                                registry_type=type_name,
                                key_security=server_security,
                            )
                        )
            except FileNotFoundError:
                errors.append(f"{view_name}-bit credential registration root is unavailable")
            except OSError:
                errors.append(f"{view_name}-bit credential registration enumeration failed")
        dropped = max(0, enumerated - len(rows))
        status = "partial" if errors or dropped else "complete"
        reason = "; ".join(dict.fromkeys(errors))[:1000] if errors else (
            "binding bound reached" if dropped else ""
        )
        coverage = SurfaceCoverage(surface, status, reason, enumerated, len(rows), dropped)
        return AuthExtensionSurface(coverage, tuple(item[0] for item in rows)), rows

    def _network_surface(
        self,
    ) -> tuple[AuthExtensionSurface, list[tuple[AuthExtensionBinding, str, str, str]]]:
        surface = "network.providers"
        registry = self.registry
        assert registry is not None
        rows: list[tuple[AuthExtensionBinding, str, str, str]] = []
        errors: list[str] = []
        enumerated = 0
        try:
            access = getattr(registry, "KEY_READ", 0) | getattr(
                registry, "KEY_WOW64_64KEY", 0
            )
            with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, _NETWORK_ORDER, 0, access) as key:
                order_security = self._key_security(key)
                value, value_type = registry.QueryValueEx(key, "ProviderOrder")
            type_name = _registry_type_name(registry, value_type)
            if type_name not in {"REG_SZ", "REG_EXPAND_SZ"} or not isinstance(value, str):
                raise OSError("ProviderOrder has unsupported type")
            providers = [part.strip() for part in value.split(",") if part.strip()]
            for provider_name in providers[: MAX_BINDINGS_PER_SURFACE * 2]:
                enumerated += 1
                if len(rows) >= MAX_BINDINGS_PER_SURFACE:
                    continue
                if _SERVICE_NAME.fullmatch(provider_name) is None:
                    errors.append("ProviderOrder contained an unsafe service identifier")
                    continue
                provider_key = (
                    rf"SYSTEM\CurrentControlSet\Services\{provider_name}\NetworkProvider"
                )
                try:
                    with registry.OpenKey(
                        registry.HKEY_LOCAL_MACHINE, provider_key, 0, access
                    ) as key:
                        provider_security = self._key_security(key)
                        configured, provider_type = registry.QueryValueEx(key, "ProviderPath")
                    provider_type_name = _registry_type_name(registry, provider_type)
                except (FileNotFoundError, OSError):
                    configured = f"unresolved-provider:{provider_name}"
                    provider_type_name = "unknown"
                    provider_security = order_security
                    errors.append("an ordered network provider has no readable ProviderPath")
                if not isinstance(configured, str) or not configured.strip() or len(configured) > 1024:
                    configured = f"unresolved-provider:{provider_name}"
                    errors.append("a network ProviderPath is invalid or oversized")
                rows.append(
                    self._binding(
                        surface=surface,
                        order=len(rows),
                        configured=configured.strip(),
                        binding_identity=provider_name,
                        registry_source="network-provider-order-and-providerpath",
                        registry_view="64",
                        registry_type=provider_type_name,
                        key_security=provider_security,
                    )
                )
        except (FileNotFoundError, OSError):
            errors.append("NetworkProvider ProviderOrder could not be read")
        dropped = max(0, enumerated - len(rows))
        status = "unknown" if not rows and errors else ("partial" if errors or dropped else "complete")
        reason = "; ".join(dict.fromkeys(errors))[:1000] if errors else (
            "binding bound reached" if dropped else ""
        )
        coverage = SurfaceCoverage(surface, status, reason, enumerated, len(rows), dropped)
        return AuthExtensionSurface(coverage, tuple(item[0] for item in rows)), rows

    def collect(self) -> AuthExtensionCollection:
        started = self.monotonic()
        host_binding, host_binding_observed = self._host_binding()
        if not self.platform_name.startswith("win") or self.registry is None:
            reason = "Windows registry authentication-extension evidence is unavailable on this platform."
            snapshot = AuthExtensionSnapshot(
                AUTH_EXTENSION_SCHEMA,
                host_binding,
                float(self.wall_clock()),
                tuple(_unknown_surface(surface, reason) for surface in SURFACE_IDS),
                (),
                "unknown",
                reason,
                min(60_000, max(0, int((self.monotonic() - started) * 1000))),
            )
            return AuthExtensionCollection(snapshot)
        budget = _CollectionBudget(started, started + MAX_COLLECTION_SECONDS)
        built: list[tuple[AuthExtensionSurface, list[tuple[AuthExtensionBinding, str, str, str]]]] = []
        lsa_values = (
            ("lsa.authentication-packages", "Authentication Packages"),
            ("lsa.notification-packages", "Notification Packages"),
            ("lsa.security-packages", "Security Packages"),
        )
        for surface, value_name in lsa_values:
            built.append(self._lsa_surface(surface, value_name))
        built.append(self._credential_surface("credential.providers"))
        built.append(self._credential_surface("credential.provider-filters"))
        built.append(self._network_surface())

        components: dict[str, ComponentEvidence] = {}
        details: dict[str, LocalComponentDetail] = {}
        for _surface, rows in built:
            for binding, resolved, path_token, resolution_reason in rows:
                if binding.component_token in components:
                    continue
                evidence, detail = self._inspect_component(
                    binding.component_token,
                    resolved,
                    path_token,
                    resolution_reason,
                    budget,
                )
                components[binding.component_token] = evidence
                if detail is not None and len(details) < MAX_LOCAL_DETAILS:
                    details[binding.component_token] = detail
        surfaces = tuple(item[0] for item in built)
        statuses = {item.coverage.status for item in surfaces}
        if not host_binding_observed:
            collector_status = "partial"
            collector_reason = "Stable Windows machine identity could not be observed."
        elif "unknown" in statuses:
            collector_status = "unknown"
            collector_reason = "One or more fixed registry surfaces are unknown."
        elif "partial" in statuses:
            collector_status = "partial"
            collector_reason = "One or more fixed registry surfaces are partial."
        else:
            collector_status = "complete"
            collector_reason = ""
        elapsed_ms = min(60_000, max(0, int((self.monotonic() - started) * 1000)))
        snapshot = AuthExtensionSnapshot(
            AUTH_EXTENSION_SCHEMA,
            host_binding,
            float(self.wall_clock()),
            surfaces,
            tuple(sorted(components.values(), key=lambda item: item.component_token)),
            collector_status,
            collector_reason,
            elapsed_ms,
        )
        return AuthExtensionCollection(
            snapshot,
            tuple(sorted(details.values(), key=lambda item: item.component_token)),
        )


__all__ = [
    "AUTH_EXTENSION_SCHEMA",
    "BASELINE_SCHEMA",
    "SURFACE_IDS",
    "AuthExtensionBaselineStore",
    "AuthExtensionBinding",
    "AuthExtensionChange",
    "AuthExtensionCollection",
    "AuthExtensionError",
    "AuthExtensionEvidenceProvider",
    "AuthExtensionPurposeKeys",
    "AuthExtensionSnapshot",
    "AuthExtensionSurface",
    "BaselineComparison",
    "BaselineEnrollmentError",
    "BaselineIntegrityError",
    "ComponentEvidence",
    "LocalComponentDetail",
    "SnapshotAssessment",
    "SnapshotComparison",
    "SurfaceCoverage",
    "UnavailableAuthExtensionEvidenceProvider",
    "WindowsAuthExtensionEvidenceProvider",
    "assess_auth_extension_snapshot",
    "compare_auth_extension_snapshots",
    "derive_auth_extension_keys",
    "load_auth_extension_keys",
    "resolve_registered_component_path",
    "snapshot_from_dict",
    "snapshot_to_dict",
]
