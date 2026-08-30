"""Content-addressed evidence for Angerona's fixed local release gate."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from angerona.core.atomic_io import replace_with_retry
from angerona.core.privacy import redact_text

REQUIRED_RELEASE_CHECKS = (
    "bytecode",
    "dependency-audit",
    "documentation-drift",
    "lint",
    "unit-tests",
)
_STATUS = {"pass", "fail", "unknown"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SUMMARY_SOURCE_LIMIT = 16_384
_SUMMARY_LIMIT = 2_000


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


@dataclass(frozen=True)
class QualityCheckEvidence:
    check_id: str
    status: str
    exit_code: int | None
    duration_seconds: float
    output_sha256: str
    summary: str
    command_fingerprint: str

    def __post_init__(self) -> None:
        if self.check_id not in REQUIRED_RELEASE_CHECKS:
            raise ValueError("release evidence uses an unregistered check")
        if self.status not in _STATUS:
            raise ValueError("invalid release check status")
        if self.status == "pass" and self.exit_code != 0:
            raise ValueError("passing release checks require exit code zero")
        if self.status == "fail" and (
            self.exit_code is None or self.exit_code == 0
        ):
            raise ValueError("failed release checks require a nonzero exit code")
        if (
            not math.isfinite(float(self.duration_seconds))
            or not 0 <= float(self.duration_seconds) <= 86_400
        ):
            raise ValueError("invalid release check duration")
        if not _SHA256.fullmatch(self.output_sha256):
            raise ValueError("invalid release check output digest")
        if not _SHA256.fullmatch(self.command_fingerprint):
            raise ValueError("invalid release check command fingerprint")
        # Release tools put the decisive result/footer at the end of their
        # output. Keep a bounded overlap before redaction so a sensitive token
        # cannot straddle the retained boundary, then preserve the terminal
        # status instead of silently truncating it away.
        source_tail = str(self.summary or "")[-_SUMMARY_SOURCE_LIMIT:]
        redacted_tail = redact_text(
            source_tail, limit=_SUMMARY_SOURCE_LIMIT * 2
        )
        object.__setattr__(self, "summary", redacted_tail[-_SUMMARY_LIMIT:])

    @classmethod
    def from_output(
        cls,
        check_id: str,
        *,
        command: Sequence[str],
        exit_code: int | None,
        duration_seconds: float,
        output: bytes,
        timed_out: bool = False,
    ) -> "QualityCheckEvidence":
        if timed_out:
            status = "fail"
            exit_code = 124
        elif exit_code is None:
            status = "unknown"
        else:
            status = "pass" if exit_code == 0 else "fail"
        tail = output[-_SUMMARY_SOURCE_LIMIT:].decode("utf-8", errors="replace")
        return cls(
            check_id=check_id,
            status=status,
            exit_code=exit_code,
            duration_seconds=round(float(duration_seconds), 3),
            output_sha256=hashlib.sha256(output).hexdigest(),
            summary=tail,
            command_fingerprint=hashlib.sha256(
                _canonical(tuple(str(item) for item in command))
            ).hexdigest(),
        )


@dataclass(frozen=True)
class ReleaseEvidenceManifest:
    product: str
    version: str
    commit_sha: str
    source_date_epoch: int
    checks: tuple[QualityCheckEvidence, ...]
    gate_status: str
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "checks", tuple(self.checks))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        if self.product != "Angerona" or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", self.version
        ):
            raise ValueError("invalid release evidence identity")
        if not _COMMIT.fullmatch(self.commit_sha):
            raise ValueError("release evidence requires a full commit SHA")
        if not 0 <= int(self.source_date_epoch) <= 4_102_444_800:
            raise ValueError("invalid source date epoch")
        ids = tuple(item.check_id for item in self.checks)
        if ids != REQUIRED_RELEASE_CHECKS:
            raise ValueError("release evidence checks are incomplete or unsorted")
        expected = "pass" if all(item.status == "pass" for item in self.checks) else "fail"
        if self.gate_status != expected:
            raise ValueError("release gate status does not match its evidence")
        if len(self.limitations) > 64 or any(
            not item or len(item) > 500 for item in self.limitations
        ):
            raise ValueError("release evidence limitations exceed their bound")

    def canonical(self) -> bytes:
        return _canonical(asdict(self))


@dataclass(frozen=True)
class ReleaseEvidencePack:
    schema: str
    manifest: ReleaseEvidenceManifest
    manifest_sha256: str
    publisher_signature_state: str = "external-required"

    def __post_init__(self) -> None:
        if self.schema != "angerona.release-evidence/v1":
            raise ValueError("unsupported release evidence schema")
        if not _SHA256.fullmatch(self.manifest_sha256):
            raise ValueError("invalid release evidence manifest digest")
        if self.publisher_signature_state not in {
            "external-required", "verified",
        }:
            raise ValueError("invalid publisher signature state")

    def canonical(self) -> bytes:
        return _canonical(asdict(self))


def build_evidence_pack(
    *,
    version: str,
    commit_sha: str,
    source_date_epoch: int,
    checks: Sequence[QualityCheckEvidence],
    limitations: Sequence[str] = (),
) -> ReleaseEvidencePack:
    ordered = tuple(sorted(checks, key=lambda item: item.check_id))
    manifest = ReleaseEvidenceManifest(
        product="Angerona",
        version=version,
        commit_sha=commit_sha,
        source_date_epoch=int(source_date_epoch),
        checks=ordered,
        gate_status=(
            "pass" if all(item.status == "pass" for item in ordered) else "fail"
        ),
        limitations=tuple(redact_text(item, limit=500) for item in limitations),
    )
    return ReleaseEvidencePack(
        schema="angerona.release-evidence/v1",
        manifest=manifest,
        manifest_sha256=hashlib.sha256(manifest.canonical()).hexdigest(),
    )


def verify_evidence_pack(pack: ReleaseEvidencePack) -> bool:
    return hashlib.sha256(pack.manifest.canonical()).hexdigest() == pack.manifest_sha256


def write_evidence_pack(path: Path, pack: ReleaseEvidencePack) -> None:
    """Write a bounded canonical pack atomically; signing remains external."""
    encoded = pack.canonical()
    if len(encoded) > 256 * 1024:
        raise ValueError("release evidence pack exceeds 256 KiB")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    try:
        with open(temporary, "xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        replace_with_retry(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
