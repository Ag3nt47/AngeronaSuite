"""Local HMAC-chained quality receipts for DetectionForge evaluations.

The quality ledger contains no replay event bodies.  Each append binds an
exact package, cohort, policy, signer, tuning profile, and resource-coverage
set to a verified evaluation digest. A broken, reordered, or substituted
record invalidates the ledger. The local chain proves the integrity of the
prefix that is present; deletion of a valid suffix requires an external anchor
and is deliberately not claimed here.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from angerona.core.detection_evaluation import (
    METRIC_REASON_CODES,
    SOURCE_KIND_CODES,
    DetectionComparison,
)

QUALITY_SCHEMA = "angerona.detection-quality-receipt.v3"
QUALITY_INPUT_SCHEMA = "angerona.detection-quality-input-attestation.v2"
MAX_QUALITY_RECEIPTS = 4096
MAX_LEDGER_BYTES = 16 * 1024 * 1024
_DIGEST_PREFIX = "sha256:"


class QualityStoreError(RuntimeError):
    """The quality ledger or requested receipt is not trustworthy."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise QualityStoreError("quality receipt contains non-canonical data") from exc


def _digest(value: object) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def _require_digest(value: object, field: str) -> str:
    rendered = str(value)
    if (
        len(rendered) != len(_DIGEST_PREFIX) + 64
        or not rendered.startswith(_DIGEST_PREFIX)
        or any(character not in "0123456789abcdef" for character in rendered[7:])
    ):
        raise QualityStoreError(f"{field} must be a lowercase SHA-256 digest")
    return rendered


def _require_text(value: object, field: str, maximum: int = 240) -> str:
    if not isinstance(value, str):
        raise QualityStoreError(f"{field} must be text")
    rendered = value.strip()
    if not rendered or len(rendered) > maximum or "\x00" in rendered:
        raise QualityStoreError(f"{field} is empty or oversized")
    return rendered


def _coverage(values: object) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    try:
        candidates = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise QualityStoreError("resource coverage must be a string collection") from exc
    if not 1 <= len(candidates) <= 64:
        raise QualityStoreError("resource coverage must contain 1-64 entries")
    result = tuple(sorted({_require_text(item, "resource coverage", 160) for item in candidates}))
    if not result:
        raise QualityStoreError("resource coverage cannot be empty")
    return result


@dataclass(frozen=True)
class QualityInputAttestation:
    """Short-lived authority over source, signer, tuning, and coverage inputs."""

    schema: str
    attestation_id: str
    package_id: str
    evaluation_digest: str
    cohort_digest: str
    source_digest: str
    evaluated_at: float
    signer: str
    policy_digest: str
    tuning_digest: str
    resource_coverage: tuple[str, ...]
    issued_at: float
    expires_at: float
    nonce: str
    attestation_hmac: str

    def __post_init__(self) -> None:
        if self.schema != QUALITY_INPUT_SCHEMA:
            raise QualityStoreError("unsupported quality-input attestation schema")
        _require_text(self.attestation_id, "attestation_id", 96)
        _require_text(self.package_id, "package_id", 128)
        for name in (
            "evaluation_digest",
            "cohort_digest",
            "source_digest",
            "policy_digest",
            "tuning_digest",
        ):
            _require_digest(getattr(self, name), name)
        _require_text(self.signer, "signer", 160)
        _coverage(self.resource_coverage)
        for name in ("evaluated_at", "issued_at", "expires_at"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) <= 0
            ):
                raise QualityStoreError(f"{name} must be a positive finite timestamp")
        if self.expires_at <= self.issued_at:
            raise QualityStoreError("quality-input attestation expiry is invalid")
        if self.evaluated_at > self.issued_at + 5.0:
            raise QualityStoreError("quality-input evaluation time is in the future")
        if len(self.nonce) != 32 or any(
            character not in "0123456789abcdef" for character in self.nonce
        ):
            raise QualityStoreError("quality-input attestation nonce is invalid")
        if len(self.attestation_hmac) != 64 or any(
            character not in "0123456789abcdef" for character in self.attestation_hmac
        ):
            raise QualityStoreError("quality-input attestation HMAC is invalid")

    def unsigned_dict(self) -> dict[str, object]:
        document = asdict(self)
        document["resource_coverage"] = list(self.resource_coverage)
        document.pop("attestation_hmac")
        return document


class QualityInputAuthority:
    """Purpose-separated HMAC authority injected by a trusted ingestion path."""

    def __init__(
        self,
        key: bytes,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("quality-input authority must contain exactly 32 bytes")
        self._key = hmac.new(
            key, b"angerona/detection-quality-input/v1", hashlib.sha256
        ).digest()
        self._clock = clock

    def _mac(self, attestation: QualityInputAttestation) -> str:
        unsigned = attestation.unsigned_dict()
        unsigned["attestation_id"] = ""
        return hmac.new(self._key, _canonical(unsigned), hashlib.sha256).hexdigest()

    def issue(
        self,
        comparison: DetectionComparison,
        *,
        package_id: str,
        signer: str,
        policy_digest: str,
        tuning_digest: str,
        resource_coverage: object,
        ttl_seconds: float = 5 * 60,
    ) -> QualityInputAttestation:
        comparison.assert_intact()
        stamp = float(self._clock())
        ttl = float(ttl_seconds)
        if not math.isfinite(stamp) or stamp <= 0 or not 5.0 <= ttl <= 3600.0:
            raise QualityStoreError("quality-input attestation time window is invalid")
        if comparison.evaluated_at > stamp + 5.0:
            raise QualityStoreError("quality-input evaluation time is in the future")
        values: dict[str, object] = {
            "schema": QUALITY_INPUT_SCHEMA,
            "attestation_id": "pending",
            "package_id": _require_text(package_id, "package_id", 128),
            "evaluation_digest": comparison.evaluation_digest,
            "cohort_digest": comparison.cohort_digest,
            "source_digest": comparison.source_digest,
            "evaluated_at": comparison.evaluated_at,
            "signer": _require_text(signer, "signer", 160),
            "policy_digest": _require_digest(policy_digest, "policy_digest"),
            "tuning_digest": _require_digest(tuning_digest, "tuning_digest"),
            "resource_coverage": _coverage(resource_coverage),
            "issued_at": stamp,
            "expires_at": stamp + ttl,
            "nonce": secrets.token_hex(16),
            "attestation_hmac": "0" * 64,
        }
        provisional = QualityInputAttestation(**values)  # type: ignore[arg-type]
        signature = self._mac(provisional)
        values["attestation_id"] = "quality-input-" + hashlib.sha256(
            _canonical(provisional.unsigned_dict()) + signature.encode("ascii")
        ).hexdigest()[:40]
        values["attestation_hmac"] = signature
        return QualityInputAttestation(**values)  # type: ignore[arg-type]

    def verify(self, attestation: QualityInputAttestation) -> None:
        if not isinstance(attestation, QualityInputAttestation):
            raise QualityStoreError("quality-input attestation type is invalid")
        expected = self._mac(attestation)
        if not hmac.compare_digest(attestation.attestation_hmac, expected):
            raise QualityStoreError("quality-input attestation HMAC verification failed")
        unsigned = attestation.unsigned_dict()
        unsigned["attestation_id"] = "pending"
        expected_id = "quality-input-" + hashlib.sha256(
            _canonical(unsigned) + expected.encode("ascii")
        ).hexdigest()[:40]
        if not hmac.compare_digest(attestation.attestation_id, expected_id):
            raise QualityStoreError("quality-input attestation identity verification failed")
        current = float(self._clock())
        if not math.isfinite(current):
            raise QualityStoreError("quality-input authority clock is invalid")
        if current < attestation.issued_at - 5.0:
            raise QualityStoreError("quality-input attestation was issued in the future")
        if current > attestation.expires_at:
            raise QualityStoreError("quality-input attestation is stale")


@dataclass(frozen=True)
class QualityReceipt:
    schema: str
    sequence: int
    receipt_id: str
    created_at: float
    package_id: str
    candidate_digest: str
    active_digests: tuple[str, ...]
    cohort_digest: str
    source_digest: str
    source_kind: str
    high_water: int
    row_count: int
    cohort_complete: bool
    evaluation_digest: str
    evaluated_at: float
    policy_digest: str
    signer: str
    tuning_digest: str
    resource_coverage: tuple[str, ...]
    input_trust: str
    input_attestation_id: str | None
    active_match_count: int
    candidate_match_count: int
    new_match_count: int
    lost_match_count: int
    shared_match_count: int
    precision: float | None
    recall: float | None
    metric_reason_code: str
    previous_hmac: str
    receipt_hmac: str

    def __post_init__(self) -> None:
        if self.schema != QUALITY_SCHEMA:
            raise QualityStoreError("unsupported quality receipt schema")
        if type(self.sequence) is not int or self.sequence < 1:
            raise QualityStoreError("quality receipt sequence is invalid")
        _require_text(self.receipt_id, "receipt_id", 96)
        if not math.isfinite(float(self.created_at)) or float(self.created_at) <= 0:
            raise QualityStoreError("created_at must be a positive timestamp")
        _require_text(self.package_id, "package_id", 128)
        _require_digest(self.candidate_digest, "candidate_digest")
        if len(self.active_digests) > 128:
            raise QualityStoreError("active digest set is oversized")
        for digest in self.active_digests:
            _require_digest(digest, "active_digest")
        for name in (
            "cohort_digest",
            "source_digest",
            "evaluation_digest",
            "policy_digest",
            "tuning_digest",
        ):
            _require_digest(getattr(self, name), name)
        if self.source_kind not in SOURCE_KIND_CODES:
            raise QualityStoreError("quality source kind is not a closed code")
        _require_text(self.signer, "signer", 160)
        if self.metric_reason_code not in METRIC_REASON_CODES:
            raise QualityStoreError("quality metric reason is not a closed code")
        _coverage(self.resource_coverage)
        if self.input_trust not in {"authenticated", "self-attested"}:
            raise QualityStoreError("quality input trust state is invalid")
        if self.input_trust == "authenticated":
            _require_text(self.input_attestation_id, "input_attestation_id", 96)
        elif self.input_attestation_id is not None:
            raise QualityStoreError("self-attested input cannot name an attestation")
        if type(self.cohort_complete) is not bool:
            raise QualityStoreError("cohort_complete must be boolean")
        if not math.isfinite(float(self.evaluated_at)) or float(self.evaluated_at) <= 0:
            raise QualityStoreError("evaluated_at must be a positive timestamp")
        if self.evaluated_at > self.created_at + 5.0:
            raise QualityStoreError("quality evaluation time is in the future")
        for name in (
            "high_water",
            "row_count",
            "active_match_count",
            "candidate_match_count",
            "new_match_count",
            "lost_match_count",
            "shared_match_count",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise QualityStoreError(f"{name} must be a non-negative integer")
        for name in ("precision", "recall"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not 0.0 <= float(value) <= 1.0
            ):
                raise QualityStoreError(f"{name} must be null or a finite ratio")
        for name in ("previous_hmac", "receipt_hmac"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise QualityStoreError(f"{name} must be a lowercase HMAC")

    def unsigned_dict(self) -> dict[str, object]:
        document = asdict(self)
        document["active_digests"] = list(self.active_digests)
        document["resource_coverage"] = list(self.resource_coverage)
        document.pop("receipt_hmac")
        return document

    def to_dict(self) -> dict[str, object]:
        document = self.unsigned_dict()
        document["receipt_hmac"] = self.receipt_hmac
        return document


class DetectionQualityStore:
    """Bounded, append-only HMAC chain for quality-gate evidence."""

    def __init__(
        self,
        path: str | Path,
        *,
        key: bytes,
        max_receipts: int = MAX_QUALITY_RECEIPTS,
        input_authority: QualityInputAuthority | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("quality-store authority must contain exactly 32 bytes")
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self._key = bytes(key)
        self._export_key = hmac.new(
            self._key, b"angerona/detection-quality-export/v1", hashlib.sha256
        ).digest()
        self._input_authority = input_authority
        self._clock = clock
        self.max_receipts = max(1, min(int(max_receipts), MAX_QUALITY_RECEIPTS))
        self._thread_lock = threading.RLock()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._thread_lock:
            self.lock_path.touch(exist_ok=True)
            stream = self.lock_path.open("r+b")
            acquired = False
            try:
                if os.name == "nt":
                    import msvcrt

                    stream.seek(0)
                    if stream.read(1) == b"":
                        stream.seek(0)
                        stream.write(b"\0")
                        stream.flush()
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                acquired = True
                yield
            finally:
                if acquired:
                    try:
                        if os.name == "nt":
                            import msvcrt

                            stream.seek(0)
                            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                        else:
                            import fcntl

                            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass
                stream.close()

    @staticmethod
    def _from_dict(document: Mapping[str, Any]) -> QualityReceipt:
        expected = {
            "schema", "sequence", "receipt_id", "created_at", "package_id",
            "candidate_digest", "active_digests", "cohort_digest", "source_digest",
            "source_kind", "high_water", "row_count", "cohort_complete",
            "evaluation_digest", "evaluated_at", "policy_digest", "signer", "tuning_digest",
            "resource_coverage", "input_trust", "input_attestation_id",
            "active_match_count", "candidate_match_count",
            "new_match_count", "lost_match_count", "shared_match_count", "precision",
            "recall", "metric_reason_code", "previous_hmac", "receipt_hmac",
        }
        if set(document) != expected:
            raise QualityStoreError("quality receipt fields are invalid")
        try:
            values = dict(document)
            values["active_digests"] = tuple(values["active_digests"])
            values["resource_coverage"] = tuple(values["resource_coverage"])
            return QualityReceipt(**values)
        except (TypeError, ValueError, QualityStoreError) as exc:
            if isinstance(exc, QualityStoreError):
                raise
            raise QualityStoreError("quality receipt values are invalid") from exc

    @staticmethod
    def _expected_id(unsigned: Mapping[str, object], receipt_hmac: str) -> str:
        body = dict(unsigned)
        body["receipt_id"] = ""
        return "quality-" + hashlib.sha256(_canonical(body) + receipt_hmac.encode("ascii")).hexdigest()[:40]

    def _read_locked(self) -> tuple[QualityReceipt, ...]:
        if not self.path.exists():
            return ()
        try:
            size = self.path.stat().st_size
            if size > MAX_LEDGER_BYTES:
                raise QualityStoreError("quality ledger exceeds 16 MiB")
            payload = self.path.read_bytes()
        except QualityStoreError:
            raise
        except OSError as exc:
            raise QualityStoreError("quality ledger could not be read") from exc
        if not payload:
            return ()
        if not payload.endswith(b"\n"):
            raise QualityStoreError("quality ledger ends with an incomplete record")
        lines = payload.splitlines()
        if len(lines) > self.max_receipts:
            raise QualityStoreError("quality ledger exceeds its receipt bound")
        receipts: list[QualityReceipt] = []
        previous = "0" * 64
        for index, line in enumerate(lines, start=1):
            if len(line) > 64 * 1024:
                raise QualityStoreError("quality ledger contains an oversized record")
            try:
                decoded = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise QualityStoreError("quality ledger contains malformed JSON") from exc
            if not isinstance(decoded, dict):
                raise QualityStoreError("quality ledger record must be an object")
            receipt = self._from_dict(decoded)
            if receipt.sequence != index:
                raise QualityStoreError("quality receipt sequence is discontinuous")
            if not hmac.compare_digest(receipt.previous_hmac, previous):
                raise QualityStoreError("quality receipt chain predecessor is invalid")
            expected_hmac = self._expected_hmac(receipt)
            if not hmac.compare_digest(receipt.receipt_hmac, expected_hmac):
                raise QualityStoreError("quality receipt HMAC verification failed")
            expected_id = self._expected_id(receipt.unsigned_dict(), receipt.receipt_hmac)
            if not hmac.compare_digest(receipt.receipt_id, expected_id):
                raise QualityStoreError("quality receipt identity verification failed")
            receipts.append(receipt)
            previous = receipt.receipt_hmac
        return tuple(receipts)

    def receipts(self) -> tuple[QualityReceipt, ...]:
        with self._locked():
            return self._read_locked()

    def append_evaluation(
        self,
        comparison: DetectionComparison,
        *,
        package_id: str,
        policy_digest: str,
        signer: str,
        tuning_digest: str,
        resource_coverage: object,
        input_attestation: QualityInputAttestation | None = None,
    ) -> QualityReceipt:
        """Append one complete evaluation as a chained local receipt."""
        comparison.assert_intact()
        if not comparison.complete:
            raise QualityStoreError("incomplete or budget-failed evaluation cannot be receipted")
        if len(comparison.candidate_digests) != 1:
            raise QualityStoreError("promotion quality receipts bind exactly one candidate")
        package_name = _require_text(package_id, "package_id", 128)
        policy = _require_digest(policy_digest, "policy_digest")
        tuning = _require_digest(tuning_digest, "tuning_digest")
        signer_name = _require_text(signer, "signer", 160)
        coverage = _coverage(resource_coverage)
        input_trust = "self-attested"
        attestation_id: str | None = None
        if input_attestation is not None:
            if self._input_authority is None:
                raise QualityStoreError("quality-input attestation authority is unavailable")
            self._input_authority.verify(input_attestation)
            bindings = {
                "package": (input_attestation.package_id, package_name),
                "evaluation": (
                    input_attestation.evaluation_digest,
                    comparison.evaluation_digest,
                ),
                "cohort": (input_attestation.cohort_digest, comparison.cohort_digest),
                "source": (input_attestation.source_digest, comparison.source_digest),
                "evaluation time": (
                    input_attestation.evaluated_at,
                    comparison.evaluated_at,
                ),
                "signer": (input_attestation.signer, signer_name),
                "policy": (input_attestation.policy_digest, policy),
                "tuning": (input_attestation.tuning_digest, tuning),
                "resource coverage": (input_attestation.resource_coverage, coverage),
            }
            for name, (provided, expected) in bindings.items():
                if provided != expected:
                    raise QualityStoreError(f"quality-input {name} substitution detected")
            input_trust = "authenticated"
            attestation_id = input_attestation.attestation_id
        stamp = float(self._clock())
        if not math.isfinite(stamp) or stamp <= 0:
            raise QualityStoreError("created_at must be a positive finite timestamp")
        if comparison.evaluated_at > stamp + 5.0:
            raise QualityStoreError("quality evaluation time is in the future")
        with self._locked():
            existing = self._read_locked()
            if len(existing) >= self.max_receipts:
                raise QualityStoreError("quality ledger is full; archive under operator control")
            if attestation_id is not None and any(
                receipt.input_attestation_id == attestation_id for receipt in existing
            ):
                raise QualityStoreError("quality-input attestation was already consumed")
            sequence = len(existing) + 1
            previous = existing[-1].receipt_hmac if existing else "0" * 64
            values: dict[str, object] = {
                "schema": QUALITY_SCHEMA,
                "sequence": sequence,
                "receipt_id": "pending",
                "created_at": stamp,
                "package_id": package_name,
                "candidate_digest": comparison.candidate_digests[0],
                "active_digests": tuple(comparison.active_digests),
                "cohort_digest": comparison.cohort_digest,
                "source_digest": comparison.source_digest,
                "source_kind": comparison.source_kind,
                "high_water": comparison.high_water,
                "row_count": comparison.row_count,
                "cohort_complete": comparison.loss.complete,
                "evaluation_digest": comparison.evaluation_digest,
                "evaluated_at": comparison.evaluated_at,
                "policy_digest": policy,
                "signer": signer_name,
                "tuning_digest": tuning,
                "resource_coverage": coverage,
                "input_trust": input_trust,
                "input_attestation_id": attestation_id,
                "active_match_count": len(comparison.active_event_ids),
                "candidate_match_count": len(comparison.candidate_event_ids),
                "new_match_count": len(comparison.new_event_ids),
                "lost_match_count": len(comparison.lost_event_ids),
                "shared_match_count": len(comparison.shared_event_ids),
                "precision": comparison.precision,
                "recall": comparison.recall,
                "metric_reason_code": comparison.metric_reason_code,
                "previous_hmac": previous,
                "receipt_hmac": "0" * 64,
            }
            provisional = QualityReceipt(**values)  # type: ignore[arg-type]
            # Receipt identity is derived from the final MAC. The MAC covers a
            # blank identity to avoid a circular signature dependency.
            unsigned = provisional.unsigned_dict()
            unsigned["receipt_id"] = ""
            receipt_hmac = hmac.new(
                self._key, _canonical(unsigned), hashlib.sha256
            ).hexdigest()
            receipt_id = self._expected_id(unsigned, receipt_hmac)
            values["receipt_id"] = receipt_id
            values["receipt_hmac"] = receipt_hmac
            receipt = QualityReceipt(**values)  # type: ignore[arg-type]
            # _expected_hmac normally includes receipt_id. For this ledger the
            # stable signature body explicitly blanks that derived identifier.
            line = _canonical(receipt.to_dict()) + b"\n"
            if (self.path.stat().st_size if self.path.exists() else 0) + len(line) > MAX_LEDGER_BYTES:
                raise QualityStoreError("quality ledger would exceed 16 MiB")
            try:
                with self.path.open("ab") as stream:
                    stream.write(line)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as exc:
                raise QualityStoreError("quality receipt append failed") from exc
            return receipt

    def _expected_hmac(self, receipt: QualityReceipt) -> str:
        unsigned = receipt.unsigned_dict()
        unsigned["receipt_id"] = ""
        return hmac.new(self._key, _canonical(unsigned), hashlib.sha256).hexdigest()

    def get(self, receipt_id: str) -> QualityReceipt:
        identifier = _require_text(receipt_id, "receipt_id", 96)
        with self._locked():
            matches = [
                receipt for receipt in self._read_locked()
                if hmac.compare_digest(receipt.receipt_id, identifier)
            ]
        if len(matches) != 1:
            raise QualityStoreError("quality receipt is missing or ambiguous")
        return matches[0]

    def verify(self, receipt: QualityReceipt) -> bool:
        """Verify exact ledger membership, not merely a caller-provided HMAC."""
        if not isinstance(receipt, QualityReceipt):
            return False
        try:
            stored = self.get(receipt.receipt_id)
            return hmac.compare_digest(_canonical(stored.to_dict()), _canonical(receipt.to_dict()))
        except QualityStoreError:
            return False

    def sanitized_export(self) -> tuple[dict[str, object], ...]:
        """Export a closed evidence schema without caller-controlled strings."""
        result: list[dict[str, object]] = []
        for receipt in self.receipts():
            signer_token = hmac.new(
                self._export_key,
                b"signer\x00" + receipt.signer.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()[:24]
            coverage_token = hmac.new(
                self._export_key,
                b"coverage\x00" + _canonical(list(receipt.resource_coverage)),
                hashlib.sha256,
            ).hexdigest()[:24]
            result.append({
                "schema": QUALITY_SCHEMA,
                "sequence": receipt.sequence,
                "receipt_id": receipt.receipt_id,
                "created_at": receipt.created_at,
                "candidate_digest": receipt.candidate_digest,
                "active_digests": list(receipt.active_digests),
                "cohort_digest": receipt.cohort_digest,
                "source_digest": receipt.source_digest,
                "source_kind_code": receipt.source_kind,
                "high_water": receipt.high_water,
                "row_count": receipt.row_count,
                "evaluation_digest": receipt.evaluation_digest,
                "evaluated_at": receipt.evaluated_at,
                "policy_digest": receipt.policy_digest,
                "signer_token": signer_token,
                "tuning_digest": receipt.tuning_digest,
                "resource_coverage_count": len(receipt.resource_coverage),
                "resource_coverage_token": coverage_token,
                "input_trust": receipt.input_trust,
                "active_match_count": receipt.active_match_count,
                "candidate_match_count": receipt.candidate_match_count,
                "new_match_count": receipt.new_match_count,
                "lost_match_count": receipt.lost_match_count,
                "shared_match_count": receipt.shared_match_count,
                "precision": receipt.precision,
                "recall": receipt.recall,
                "metric_reason_code": receipt.metric_reason_code,
                "integrity_scope": "authenticated-present-prefix",
                "external_suffix_anchor": False,
            })
        return tuple(result)


__all__ = [
    "QUALITY_SCHEMA",
    "DetectionQualityStore",
    "QualityInputAttestation",
    "QualityInputAuthority",
    "QualityReceipt",
    "QualityStoreError",
]
