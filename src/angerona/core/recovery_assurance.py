"""Externally signed, fail-closed recovery-copy assurance.

This module does not create, delete, mount, or restore backups.  It verifies
bounded statements from separately trusted recovery authorities and evaluates
whether the observed copies span the failure domains required by policy.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _CRYPTO_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - exercised only without dependency
    Ed25519PublicKey = None  # type: ignore[assignment]
    _CRYPTO_ERROR = exc


SCHEMA = "angerona.recovery-copy/v1"
MAX_EVIDENCE_FILES = 64
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_EVIDENCE_DIRECTORY_ENTRIES = 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40,64}$")
_MEDIA = frozenset({
    "external-drive", "network-vault", "object-lock", "offline-media",
    "personal-sentinel",
})


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("recovery evidence contains a duplicate JSON key")
        result[key] = value
    return result


def _bounded_stable_read(path: Path, maximum: int) -> bytes:
    """Read one evidence file through a bounded, identity-stable descriptor."""

    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
        raise ValueError("recovery evidence is not a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.fspath(path), flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ValueError("recovery evidence changed while opening")
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
    finally:
        os.close(descriptor)
    if len(payload) > maximum:
        raise ValueError("recovery evidence exceeds its byte bound")
    after = path.lstat()
    if (
        not stat.S_ISREG(after.st_mode)
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    ):
        raise ValueError("recovery evidence changed during read")
    return bytes(payload)


def _exact(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise ValueError(f"{label} has an invalid schema")
    return value


def _signature(value: Any) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", value):
        raise ValueError("recovery signature encoding is invalid")
    try:
        decoded = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError("recovery signature encoding is invalid") from exc
    if len(decoded) != 64:
        raise ValueError("recovery signature length is invalid")
    return decoded


@dataclass(frozen=True)
class RecoveryCopyStatement:
    schema: str
    copy_id: str
    failure_domain: str
    media_class: str
    source_revision: str
    archive_sha256: str
    manifest_sha256: str
    created_at: float
    verified_at: float
    restore_tested_at: float
    size_bytes: int
    online: bool
    writable: bool
    immutable: bool
    separate_identity: bool
    encrypted: bool
    offsite: bool
    air_gapped: bool

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("unsupported recovery evidence schema")
        if not _ID.fullmatch(self.copy_id) or not _ID.fullmatch(self.failure_domain):
            raise ValueError("invalid recovery copy identity")
        if self.media_class not in _MEDIA:
            raise ValueError("invalid recovery media class")
        if not _REVISION.fullmatch(self.source_revision):
            raise ValueError("invalid recovery source revision")
        if not _SHA256.fullmatch(self.archive_sha256) or not _SHA256.fullmatch(
            self.manifest_sha256
        ):
            raise ValueError("invalid recovery digest")
        times = (self.created_at, self.verified_at, self.restore_tested_at)
        if any(
            type(value) not in (int, float) or not math.isfinite(float(value))
            or float(value) < 0
            for value in times
        ):
            raise ValueError("invalid recovery evidence timestamp")
        if self.verified_at < self.created_at or self.restore_tested_at < self.created_at:
            raise ValueError("recovery evidence timestamps are inconsistent")
        if type(self.size_bytes) is not int or not 1 <= self.size_bytes <= 20 * 1024**3:
            raise ValueError("invalid recovery copy size")
        flags = (
            self.online, self.writable, self.immutable, self.separate_identity,
            self.encrypted, self.offsite, self.air_gapped,
        )
        if any(type(value) is not bool for value in flags):
            raise ValueError("recovery posture flags must be boolean")
        if self.air_gapped and self.online:
            raise ValueError("an air-gapped copy cannot be online")
        if self.immutable and self.writable:
            raise ValueError("an immutable copy cannot be writable")

    def canonical(self) -> bytes:
        return _canonical(asdict(self))


_STATEMENT_FIELDS = frozenset(RecoveryCopyStatement.__dataclass_fields__)
_ENVELOPE_FIELDS = frozenset({"signer_id", "statement", "signature"})


@dataclass(frozen=True)
class VerifiedRecoveryCopy:
    signer_id: str
    statement: RecoveryCopyStatement


def verify_recovery_envelope(
    raw: bytes,
    trust_store: Mapping[str, bytes],
) -> VerifiedRecoveryCopy:
    """Verify one exact-schema Ed25519 recovery statement.

    The caller supplies the trust store.  Public keys carried inside the same
    envelope are deliberately ignored because they would not establish trust.
    """
    if _CRYPTO_ERROR is not None:
        raise RuntimeError("Ed25519 support is required") from _CRYPTO_ERROR
    if not isinstance(raw, bytes) or len(raw) > MAX_EVIDENCE_BYTES:
        raise ValueError("recovery evidence exceeds its byte budget")
    try:
        envelope = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("recovery evidence is not valid UTF-8 JSON") from exc
    envelope = _exact(envelope, _ENVELOPE_FIELDS, "recovery envelope")
    signer_id = envelope["signer_id"]
    if not isinstance(signer_id, str) or not _ID.fullmatch(signer_id):
        raise ValueError("invalid recovery signer identity")
    statement_raw = _exact(
        envelope["statement"], _STATEMENT_FIELDS, "recovery statement",
    )
    try:
        statement = RecoveryCopyStatement(**statement_raw)
    except TypeError as exc:
        raise ValueError("recovery statement has invalid value types") from exc
    public = trust_store.get(signer_id)
    if not isinstance(public, bytes) or len(public) != 32:
        raise ValueError("recovery signer is not trusted")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            _signature(envelope["signature"]), statement.canonical(),
        )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("recovery signature verification failed") from exc
    return VerifiedRecoveryCopy(signer_id, statement)


@dataclass(frozen=True)
class RecoveryAssurancePolicy:
    minimum_verified_copies: int = 3
    minimum_failure_domains: int = 2
    minimum_signing_authorities: int = 2
    maximum_copy_age_seconds: int = 7 * 24 * 3600
    maximum_verification_age_seconds: int = 7 * 24 * 3600
    maximum_restore_test_age_seconds: int = 90 * 24 * 3600
    maximum_future_skew_seconds: int = 300
    require_encryption: bool = True
    require_separate_identity: bool = True
    require_immutable: bool = True
    require_offline: bool = True
    require_offsite: bool = True

    def __post_init__(self) -> None:
        if not 1 <= self.minimum_verified_copies <= 10:
            raise ValueError("invalid recovery copy minimum")
        if not 1 <= self.minimum_failure_domains <= self.minimum_verified_copies:
            raise ValueError("invalid recovery failure-domain minimum")
        if not 1 <= self.minimum_signing_authorities <= self.minimum_verified_copies:
            raise ValueError("invalid recovery signing-authority minimum")
        ages = (
            self.maximum_copy_age_seconds,
            self.maximum_verification_age_seconds,
            self.maximum_restore_test_age_seconds,
        )
        if any(type(value) is not int or not 60 <= value <= 366 * 24 * 3600 for value in ages):
            raise ValueError("invalid recovery evidence freshness policy")
        if (
            type(self.maximum_future_skew_seconds) is not int
            or not 0 <= self.maximum_future_skew_seconds <= 3600
        ):
            raise ValueError("invalid recovery evidence future-skew policy")


@dataclass(frozen=True)
class RecoveryAssuranceResult:
    healthy: bool
    health: int
    findings: tuple[str, ...]
    verified_copies: int
    failure_domains: int
    signing_authorities: int
    immutable_copies: int
    offline_copies: int
    offsite_copies: int
    source_revision_current: bool


def assess_recovery_assurance(
    copies: Sequence[VerifiedRecoveryCopy],
    policy: RecoveryAssurancePolicy,
    *,
    now: float,
    source_revision: str,
) -> RecoveryAssuranceResult:
    """Evaluate signed evidence without performing a recovery action."""
    if type(now) not in (int, float) or not math.isfinite(float(now)) or now < 0:
        raise ValueError("invalid recovery assessment time")
    if not _REVISION.fullmatch(source_revision):
        raise ValueError("invalid expected source revision")
    ordered = tuple(copies)
    copy_ids = [item.statement.copy_id.casefold() for item in ordered]
    if len(copy_ids) != len(set(copy_ids)):
        raise ValueError("duplicate recovery copy identity")

    findings: list[str] = []
    future = [
        item for item in ordered
        if any(
            stamp > now + policy.maximum_future_skew_seconds
            for stamp in (
                item.statement.created_at,
                item.statement.verified_at,
                item.statement.restore_tested_at,
            )
        )
    ]
    if future:
        findings.append("one or more recovery statements are dated in the future")
    current_candidates = [
        item for item in ordered
        if item not in future
        if now - item.statement.created_at <= policy.maximum_copy_age_seconds
        and now - item.statement.verified_at <= policy.maximum_verification_age_seconds
    ]

    # Redundant copies must describe one exact recovery cohort.  Three signed
    # statements for three different archives or manifests are not three copies
    # of a restorable backup.  Select the largest deterministic cohort for the
    # requested source revision and apply every policy count only to that set.
    cohorts: dict[tuple[str, str, str], list[VerifiedRecoveryCopy]] = {}
    for item in current_candidates:
        statement = item.statement
        if statement.source_revision != source_revision:
            continue
        key = (
            statement.source_revision,
            statement.archive_sha256,
            statement.manifest_sha256,
        )
        cohorts.setdefault(key, []).append(item)
    current = (
        min(cohorts.items(), key=lambda pair: (-len(pair[1]), pair[0]))[1]
        if cohorts
        else []
    )
    restore_current = [
        item for item in current
        if now - item.statement.restore_tested_at <= policy.maximum_restore_test_age_seconds
    ]
    if len(current) < policy.minimum_verified_copies:
        findings.append("minimum current, signature-verified recovery copies not met")
    if len(restore_current) < policy.minimum_verified_copies:
        findings.append("recent restore-test evidence is incomplete")
    domains = {item.statement.failure_domain.casefold() for item in current}
    if len(domains) < policy.minimum_failure_domains:
        findings.append("recovery copies do not span enough failure domains")
    authorities = {item.signer_id.casefold() for item in current}
    if len(authorities) < policy.minimum_signing_authorities:
        findings.append("recovery evidence does not span enough signing authorities")
    if policy.require_encryption and any(not item.statement.encrypted for item in current):
        findings.append("one or more current recovery copies are not encrypted")
    if policy.require_separate_identity and not any(
        item.statement.separate_identity for item in current
    ):
        findings.append("no current copy uses a separate administrative identity")
    immutable = [
        item for item in current
        if item.statement.immutable and not item.statement.writable
    ]
    offline = [
        item for item in current
        if item.statement.air_gapped and not item.statement.online
        and not item.statement.writable
    ]
    offsite = [item for item in current if item.statement.offsite]
    if policy.require_immutable and not immutable:
        findings.append("no current independently signed immutable copy exists")
    if policy.require_offline and not offline:
        findings.append("no current independently signed offline copy exists")
    if policy.require_offsite and not offsite:
        findings.append("no current independently signed offsite copy exists")
    revision_current = bool(current)
    if not revision_current:
        findings.append("no current recovery copy covers the expected source revision")

    # Do not let a collection of old or online-only mirrors produce a healthy
    # score.  The score is an operator signal, not a probability of recovery.
    health = max(0, 100 - 14 * len(findings))
    if not ordered:
        health = 15
    return RecoveryAssuranceResult(
        healthy=not findings,
        health=health,
        findings=tuple(findings),
        verified_copies=len(current),
        failure_domains=len(domains),
        signing_authorities=len(authorities),
        immutable_copies=len(immutable),
        offline_copies=len(offline),
        offsite_copies=len(offsite),
        source_revision_current=revision_current,
    )


def load_recovery_evidence_directory(
    root: Path,
    trust_store: Mapping[str, bytes],
) -> tuple[tuple[VerifiedRecoveryCopy, ...], tuple[str, ...]]:
    """Load a bounded non-recursive evidence directory without following links."""
    root = Path(root)
    if not root.exists():
        return (), ("recovery evidence directory is missing",)
    if root.is_symlink() or not root.is_dir():
        return (), ("recovery evidence directory is not a regular directory",)
    items: list[Path] = []
    try:
        with os.scandir(root) as directory:
            for visited, entry in enumerate(directory, start=1):
                if visited > MAX_EVIDENCE_DIRECTORY_ENTRIES:
                    return (), (
                        "recovery evidence directory entry count exceeds its bound",
                    )
                # Match the prior non-recursive ``*.json`` contract while
                # stopping as soon as the evidence-file budget is exceeded.
                if not Path(entry.name).match("*.json"):
                    continue
                items.append(root / entry.name)
                if len(items) > MAX_EVIDENCE_FILES:
                    return (), ("recovery evidence file count exceeds its bound",)
    except OSError:
        return (), ("recovery evidence directory is unreadable",)
    items.sort(key=lambda item: item.name.casefold())
    verified: list[VerifiedRecoveryCopy] = []
    errors: list[str] = []
    for item in items:
        try:
            if item.is_symlink() or not item.is_file():
                raise ValueError("evidence is not a regular file")
            verified.append(verify_recovery_envelope(
                _bounded_stable_read(item, MAX_EVIDENCE_BYTES), trust_store,
            ))
        except (OSError, ValueError, RuntimeError) as exc:
            # Paths and signature bytes are intentionally absent from the
            # diagnostic; only the bounded filename and reason category leave.
            reason = str(exc)[:180] or type(exc).__name__
            errors.append(f"{item.name[:100]}: {reason}")
    return tuple(verified), tuple(errors)


def evidence_set_digest(copies: Sequence[VerifiedRecoveryCopy]) -> str:
    return hashlib.sha256(_canonical([
        {"signer_id": item.signer_id, "statement": asdict(item.statement)}
        for item in sorted(copies, key=lambda value: value.statement.copy_id.casefold())
    ])).hexdigest()
