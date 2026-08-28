"""Threshold-signed release authorization and authenticated rollback floors.

The verifier is deliberately independent of the network update checker.  A
version string or HTTPS response never authorizes installation: a bounded
statement must bind the exact artifact, SBOM, provenance, source revision,
builder, validity window, and a monotonic release sequence to a threshold of
pinned Ed25519 publisher keys.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from angerona.core.atomic_io import replace_with_retry

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _CRYPTO_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover
    Ed25519PublicKey = None  # type: ignore[assignment]
    _CRYPTO_ERROR = exc


SCHEMA = "angerona.release-authorization/v2"
FLOOR_SCHEMA = "angerona.release-floor/v1"
PAYLOAD_MANIFEST_SCHEMA = "angerona.release-payload/v1"
MAX_AUTHORIZATION_BYTES = 256 * 1024
MAX_PAYLOAD_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_PAYLOAD_FILES = 4096
MAX_SIGNATURES = 16
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{2,191}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40,64}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){2,3}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("release authorization contains a duplicate JSON key")
        result[key] = value
    return result


def _exact(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != keys:
        raise ValueError(f"{label} has an invalid schema")
    return value


def _version(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise ValueError("invalid release authorization version")
    return tuple(int(part) for part in value.split("."))


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", value):
        raise ValueError("release authorization signature encoding is invalid")
    try:
        raw = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError("release authorization signature encoding is invalid") from exc
    if len(raw) != 64:
        raise ValueError("release authorization signature length is invalid")
    return raw


@dataclass(frozen=True)
class ReleaseAuthorizationStatement:
    schema: str
    product: str
    version: str
    sequence: int
    platform: str
    artifact_sha256: str
    sbom_sha256: str
    payload_manifest_sha256: str
    payload_catalog_sha256: str
    provenance_sha256: str
    source_revision: str
    builder_id: str
    issued_at: float
    expires_at: float

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or self.product != "Angerona":
            raise ValueError("unsupported release authorization identity")
        _version(self.version)
        if type(self.sequence) is not int or not 1 <= self.sequence <= 2**63 - 1:
            raise ValueError("invalid release authorization sequence")
        if not _ID.fullmatch(self.platform) or not _ID.fullmatch(self.builder_id):
            raise ValueError("invalid release platform or builder identity")
        for digest in (
            self.artifact_sha256,
            self.sbom_sha256,
            self.payload_manifest_sha256,
            self.payload_catalog_sha256,
            self.provenance_sha256,
        ):
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise ValueError("invalid release authorization digest")
        if not isinstance(self.source_revision, str) or not _REVISION.fullmatch(
            self.source_revision
        ):
            raise ValueError("invalid release source revision")
        if any(
            type(value) not in (int, float) or not math.isfinite(float(value))
            or float(value) < 0
            for value in (self.issued_at, self.expires_at)
        ) or self.expires_at <= self.issued_at:
            raise ValueError("invalid release authorization validity window")

    def canonical(self) -> bytes:
        return _canonical(asdict(self))

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()


@dataclass(frozen=True)
class UpdateAuthorityPolicy:
    signature_threshold: int = 2
    allowed_builders: tuple[str, ...] = (
        "https://github.com/Ag3nt47/AngeronaSuite/.github/workflows/release.yml",
    )
    maximum_validity_seconds: int = 31 * 24 * 3600
    maximum_future_skew_seconds: int = 300

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_builders", tuple(self.allowed_builders))
        if (
            type(self.signature_threshold) is not int
            or not 1 <= self.signature_threshold <= MAX_SIGNATURES
        ):
            raise ValueError("invalid release signature threshold")
        if not self.allowed_builders or any(
            not isinstance(value, str) or not _ID.fullmatch(value)
            for value in self.allowed_builders
        ):
            raise ValueError("invalid authorized builder set")
        if (
            type(self.maximum_validity_seconds) is not int
            or not 60 <= self.maximum_validity_seconds <= 366 * 24 * 3600
        ):
            raise ValueError("invalid authorization validity policy")
        if (
            type(self.maximum_future_skew_seconds) is not int
            or not 0 <= self.maximum_future_skew_seconds <= 3600
        ):
            raise ValueError("invalid authorization clock-skew policy")


@dataclass(frozen=True)
class ReleaseAuthorizationResult:
    valid: bool
    errors: tuple[str, ...]
    statement: ReleaseAuthorizationStatement | None
    verified_signers: tuple[str, ...]
    statement_sha256: str


_STATEMENT_FIELDS = frozenset(ReleaseAuthorizationStatement.__dataclass_fields__)
_ENVELOPE_FIELDS = frozenset({"statement", "signatures"})
_SIGNATURE_FIELDS = frozenset({"signer_id", "signature"})


def verify_release_authorization(
    raw: bytes,
    trust_store: Mapping[str, bytes],
    policy: UpdateAuthorityPolicy,
    *,
    now: float,
    expected_platform: str,
    expected_artifact_sha256: str,
    expected_sbom_sha256: str,
    expected_payload_manifest_sha256: str,
    expected_payload_catalog_sha256: str,
    expected_provenance_sha256: str,
    installed_version: str,
    highest_sequence: int = 0,
    highest_version: str = "0.0.0",
    floor_statement_sha256: str = "",
) -> ReleaseAuthorizationResult:
    errors: list[str] = []
    statement: ReleaseAuthorizationStatement | None = None
    verified: list[str] = []
    statement_digest = ""
    try:
        if _CRYPTO_ERROR is not None:
            raise RuntimeError("Ed25519 support is required") from _CRYPTO_ERROR
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_AUTHORIZATION_BYTES:
            raise ValueError("release authorization exceeds its byte budget")
        if type(now) not in (int, float) or not math.isfinite(float(now)) or now < 0:
            raise ValueError("invalid authorization verification time")
        if not _ID.fullmatch(expected_platform):
            raise ValueError("invalid expected release platform")
        if any(
            not isinstance(value, str) or not _SHA256.fullmatch(value)
            for value in (
                expected_artifact_sha256,
                expected_sbom_sha256,
                expected_payload_manifest_sha256,
                expected_payload_catalog_sha256,
                expected_provenance_sha256,
            )
        ):
            raise ValueError("invalid expected release evidence digest")
        _version(installed_version)
        _version(highest_version)
        if type(highest_sequence) is not int or highest_sequence < 0:
            raise ValueError("invalid release rollback floor")
        if floor_statement_sha256 and not _SHA256.fullmatch(floor_statement_sha256):
            raise ValueError("invalid release floor statement digest")

        try:
            envelope = json.loads(raw, object_pairs_hook=_strict_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("release authorization is not valid UTF-8 JSON") from exc
        envelope = _exact(envelope, _ENVELOPE_FIELDS, "release authorization envelope")
        statement_raw = _exact(
            envelope["statement"], _STATEMENT_FIELDS, "release authorization statement",
        )
        try:
            statement = ReleaseAuthorizationStatement(**statement_raw)
        except TypeError as exc:
            raise ValueError("release authorization has invalid value types") from exc
        statement_digest = statement.sha256
        signatures = envelope["signatures"]
        if not isinstance(signatures, list) or not 1 <= len(signatures) <= MAX_SIGNATURES:
            raise ValueError("release authorization signatures are not a bounded list")
        seen: set[str] = set()
        verified_key_digests: set[str] = set()
        for entry in signatures:
            entry = _exact(entry, _SIGNATURE_FIELDS, "release signature")
            signer_id = entry["signer_id"]
            if not isinstance(signer_id, str) or not _ID.fullmatch(signer_id):
                raise ValueError("invalid release signer identity")
            folded = signer_id.casefold()
            if folded in seen:
                raise ValueError("duplicate release signer identity")
            seen.add(folded)
            public = trust_store.get(signer_id)
            if not isinstance(public, bytes) or len(public) != 32:
                continue
            try:
                Ed25519PublicKey.from_public_bytes(public).verify(
                    _decode_signature(entry["signature"]), statement.canonical(),
                )
            except Exception:
                continue
            key_digest = hashlib.sha256(public).hexdigest()
            if key_digest in verified_key_digests:
                # Different labels for one key are not independent authorities
                # and therefore never increase a threshold count.
                continue
            verified_key_digests.add(key_digest)
            verified.append(signer_id)
        if len(verified) < policy.signature_threshold:
            errors.append("publisher signature threshold is not met")
        if statement.builder_id not in policy.allowed_builders:
            errors.append("release builder identity is not authorized")
        if statement.platform != expected_platform:
            errors.append("release platform does not match the target")
        if statement.artifact_sha256 != expected_artifact_sha256:
            errors.append("release artifact digest does not match the target")
        if statement.sbom_sha256 != expected_sbom_sha256:
            errors.append("release SBOM digest does not match the packaged evidence")
        if statement.payload_manifest_sha256 != expected_payload_manifest_sha256:
            errors.append("release payload manifest digest does not match the packaged evidence")
        if statement.payload_catalog_sha256 != expected_payload_catalog_sha256:
            errors.append("release payload catalog digest does not match the packaged evidence")
        if statement.provenance_sha256 != expected_provenance_sha256:
            errors.append("release provenance digest does not match the packaged evidence")
        if statement.issued_at > now + policy.maximum_future_skew_seconds:
            errors.append("release authorization is not yet valid")
        if statement.expires_at <= now:
            errors.append("release authorization has expired")
        if statement.expires_at - statement.issued_at > policy.maximum_validity_seconds:
            errors.append("release authorization validity window is too long")
        if _version(statement.version) < _version(installed_version):
            errors.append("release authorization would downgrade the installed version")
        if statement.sequence < highest_sequence:
            errors.append("release authorization sequence is below the rollback floor")
        if _version(statement.version) < _version(highest_version):
            errors.append("release version is below the rollback floor")
        if statement.sequence == highest_sequence and highest_sequence > 0:
            if not floor_statement_sha256 or statement_digest != floor_statement_sha256:
                errors.append("release sequence was reused for different metadata")
    except Exception as exc:
        errors.append(str(exc) or type(exc).__name__)
    return ReleaseAuthorizationResult(
        valid=not errors,
        errors=tuple(errors),
        statement=statement,
        verified_signers=tuple(verified),
        statement_sha256=statement_digest,
    )


@dataclass(frozen=True)
class ReleaseFloor:
    highest_sequence: int
    highest_version: str
    statement_sha256: str

    def __post_init__(self) -> None:
        if type(self.highest_sequence) is not int or self.highest_sequence < 1:
            raise ValueError("invalid release floor sequence")
        _version(self.highest_version)
        if not _SHA256.fullmatch(self.statement_sha256):
            raise ValueError("invalid release floor digest")


class AuthenticatedReleaseFloor:
    """Local anti-rollback state; an external witness is still stronger."""

    def __init__(self, path: Path, authority_key: bytes) -> None:
        if not isinstance(authority_key, bytes) or len(authority_key) != 32:
            raise ValueError("release floor key must contain exactly 32 bytes")
        self._path = Path(path)
        self._key = bytes(authority_key)

    def _mac(self, core: Mapping[str, Any]) -> str:
        return hmac.new(self._key, _canonical(core), hashlib.sha256).hexdigest()

    def load(self) -> ReleaseFloor | None:
        if not self._path.exists():
            return None
        if self._path.is_symlink() or not self._path.is_file():
            raise ValueError("release floor is not a regular file")
        if self._path.stat().st_size > 16 * 1024:
            raise ValueError("release floor exceeds its byte budget")
        try:
            document = json.loads(
                self._path.read_bytes(), object_pairs_hook=_strict_object,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("release floor is not valid UTF-8 JSON") from exc
        fields = frozenset({
            "schema", "highest_sequence", "highest_version",
            "statement_sha256", "mac",
        })
        document = _exact(document, fields, "release floor")
        core = {key: document[key] for key in fields if key != "mac"}
        if document["schema"] != FLOOR_SCHEMA or not isinstance(document["mac"], str):
            raise ValueError("release floor schema is invalid")
        if not hmac.compare_digest(document["mac"], self._mac(core)):
            raise ValueError("release floor authentication failed")
        return ReleaseFloor(
            document["highest_sequence"], document["highest_version"],
            document["statement_sha256"],
        )

    def advance(self, result: ReleaseAuthorizationResult) -> ReleaseFloor:
        if not result.valid or result.statement is None:
            raise ValueError("only verified release metadata can advance the floor")
        candidate = ReleaseFloor(
            result.statement.sequence, result.statement.version,
            result.statement_sha256,
        )
        current = self.load()
        if current is not None:
            if candidate.highest_sequence < current.highest_sequence:
                raise ValueError("release sequence rollback refused")
            if _version(candidate.highest_version) < _version(current.highest_version):
                raise ValueError("release version rollback refused")
            if candidate.highest_sequence == current.highest_sequence:
                if candidate != current:
                    raise ValueError("release sequence equivocation refused")
                return current
        core = {
            "schema": FLOOR_SCHEMA,
            "highest_sequence": candidate.highest_sequence,
            "highest_version": candidate.highest_version,
            "statement_sha256": candidate.statement_sha256,
        }
        document = {**core, "mac": self._mac(core)}
        encoded = _canonical(document)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(self._path.suffix + f".{os.getpid()}.tmp")
        try:
            with open(temporary, "xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            replace_with_retry(temporary, self._path)
        finally:
            temporary.unlink(missing_ok=True)
        return candidate


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _payload_relative_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not 1 <= len(value) <= 240:
        raise ValueError("release payload path is invalid")
    if "\\" in value or "\x00" in value or ":" in value:
        raise ValueError("release payload path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("release payload path escapes its root")
    if path.as_posix() != value:
        raise ValueError("release payload path is not canonical")
    return path


def load_payload_manifest(raw: bytes) -> tuple[dict[str, Any], ...]:
    """Load a strict, bounded canonical payload manifest.

    The manifest is separately digest-bound by the threshold release statement.
    Entries are case-insensitively unique so a package cannot exploit Windows
    path aliasing while still appearing distinct to a case-sensitive builder.
    """
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_PAYLOAD_MANIFEST_BYTES:
        raise ValueError("release payload manifest exceeds its byte budget")
    try:
        document = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("release payload manifest is not valid UTF-8 JSON") from exc
    document = _exact(
        document, frozenset({"schema", "files"}), "release payload manifest",
    )
    if document["schema"] != PAYLOAD_MANIFEST_SCHEMA:
        raise ValueError("release payload manifest schema is invalid")
    files = document["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_PAYLOAD_FILES:
        raise ValueError("release payload manifest file list is not bounded")
    result: list[dict[str, Any]] = []
    previous = ""
    seen: set[str] = set()
    fields = frozenset({"path", "sha256", "size"})
    for entry in files:
        entry = _exact(entry, fields, "release payload manifest entry")
        path = _payload_relative_path(entry["path"]).as_posix()
        folded = path.casefold()
        if folded in seen or (previous and path <= previous):
            raise ValueError("release payload manifest paths are duplicate or unsorted")
        if not isinstance(entry["sha256"], str) or not _SHA256.fullmatch(
            entry["sha256"]
        ):
            raise ValueError("release payload manifest digest is invalid")
        if type(entry["size"]) is not int or not 0 <= entry["size"] <= 2**63 - 1:
            raise ValueError("release payload manifest size is invalid")
        seen.add(folded)
        previous = path
        result.append(dict(entry))
    return tuple(result)


def verify_payload_manifest(raw: bytes, root: Path) -> tuple[str, ...]:
    """Verify every manifest entry below one regular, non-reparse root."""
    errors: list[str] = []
    try:
        root = Path(root)
        if root.is_symlink() or not root.is_dir():
            raise ValueError("release payload root is not a regular directory")
        if getattr(os.path, "isjunction", lambda _path: False)(root):
            raise ValueError("release payload root is a junction")
        resolved_root = root.resolve(strict=True)
        for entry in load_payload_manifest(raw):
            relative = _payload_relative_path(entry["path"])
            candidate = root.joinpath(*relative.parts)
            current = root
            for part in relative.parts[:-1]:
                current = current / part
                if current.is_symlink() or getattr(
                    os.path, "isjunction", lambda _path: False
                )(current):
                    raise ValueError(f"release payload path is reparse-backed: {relative}")
            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError(f"release payload file is missing or linked: {relative}")
            if getattr(os.path, "isjunction", lambda _path: False)(candidate):
                raise ValueError(f"release payload file is reparse-backed: {relative}")
            metadata = candidate.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"release payload entry is not a regular file: {relative}")
            if metadata.st_size != entry["size"]:
                raise ValueError(f"release payload size mismatch: {relative}")
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(resolved_root)
            except ValueError as exc:
                raise ValueError(f"release payload path escapes its root: {relative}") from exc
            if file_sha256(candidate) != entry["sha256"]:
                raise ValueError(f"release payload digest mismatch: {relative}")
    except Exception as exc:
        errors.append(str(exc) or type(exc).__name__)
    return tuple(errors)
