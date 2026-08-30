"""Exact, fresh, one-use promotion authority for DetectionForge.

Fixture success never activates a detection.  Promotion requires a chained
quality receipt for an immutable replay cohort plus a separately HMAC-bound,
short-lived operator receipt.  The receipt names every value that could change
the decision: package, predecessor, cohort, policy, signer, tuning, resource
coverage, and quality receipt identity.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from angerona.core.detection_quality_store import (
    DetectionQualityStore,
    QualityReceipt,
)
from angerona.core.detection_registry import DetectionPackageRegistry

PROMOTION_SCHEMA = "angerona.detection-promotion-receipt.v1"
PROMOTION_STATE_SCHEMA = "angerona.detection-promotion-state.v2"
PROMOTION_CHECKPOINT_SCHEMA = "angerona.detection-promotion-checkpoint.v1"
PROMOTION_ANCHOR_SCHEMA = "angerona.detection-promotion-monotonic-anchor.v1"
_ACTIONS = frozenset({"promote", "rollback"})
_DIGEST_PREFIX = "sha256:"
_ZERO_DIGEST = _DIGEST_PREFIX + "0" * 64


class PromotionError(RuntimeError):
    """Promotion or rollback authority failed closed."""


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
        raise PromotionError("promotion authority contains non-canonical data") from exc


def _digest(value: object) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def digest_tuning(settings: Mapping[str, Any]) -> str:
    """Bind a strict JSON tuning profile without interpreting it as code."""
    if not isinstance(settings, Mapping):
        raise PromotionError("tuning settings must be an object")
    if len(settings) > 128 or len(_canonical(dict(settings))) > 64 * 1024:
        raise PromotionError("tuning settings exceed their structural budget")
    return _digest(dict(settings))


def _text(value: object, field: str, maximum: int = 240) -> str:
    if not isinstance(value, str):
        raise PromotionError(f"{field} must be text")
    rendered = value.strip()
    if not rendered or len(rendered) > maximum or "\x00" in rendered:
        raise PromotionError(f"{field} is empty or oversized")
    return rendered


def _digest_value(value: object, field: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    rendered = str(value)
    if (
        len(rendered) != 71
        or not rendered.startswith(_DIGEST_PREFIX)
        or any(character not in "0123456789abcdef" for character in rendered[7:])
    ):
        raise PromotionError(f"{field} must be a lowercase SHA-256 digest")
    return rendered


def _coverage(values: object) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    try:
        candidates = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise PromotionError("resource coverage must be a string collection") from exc
    if not 1 <= len(candidates) <= 64:
        raise PromotionError("resource coverage must contain 1-64 entries")
    return tuple(sorted({_text(value, "resource coverage", 160) for value in candidates}))


@dataclass(frozen=True)
class PromotionPolicy:
    policy_id: str = "angerona.enterprise-default"
    receipt_ttl_seconds: float = 15 * 60
    maximum_quality_age_seconds: float = 24 * 60 * 60
    minimum_rows: int = 2
    allowed_source_kinds: tuple[str, ...] = (
        "evidence-store",
        "curated-replay",
        "import",
    )
    require_complete_cohort: bool = True
    maximum_lost_matches: int = 0
    maximum_new_matches: int = 10_000
    minimum_precision: float | None = None
    minimum_recall: float | None = None
    required_resource_coverage: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.policy_id, "policy_id", 160)
        if (
            isinstance(self.receipt_ttl_seconds, bool)
            or not isinstance(self.receipt_ttl_seconds, (int, float))
            or not math.isfinite(float(self.receipt_ttl_seconds))
            or not 5.0 <= float(self.receipt_ttl_seconds) <= 86_400.0
        ):
            raise PromotionError("receipt TTL must be between 5 seconds and 24 hours")
        if (
            isinstance(self.maximum_quality_age_seconds, bool)
            or not isinstance(self.maximum_quality_age_seconds, (int, float))
            or not math.isfinite(float(self.maximum_quality_age_seconds))
            or not 5.0 <= float(self.maximum_quality_age_seconds) <= 30 * 24 * 60 * 60
        ):
            raise PromotionError("maximum quality age must be between 5 seconds and 30 days")
        for name in ("minimum_rows", "maximum_lost_matches", "maximum_new_matches"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise PromotionError(f"{name} must be a non-negative integer")
        if not self.allowed_source_kinds or len(self.allowed_source_kinds) > 16:
            raise PromotionError("allowed source kinds are invalid")
        for value in self.allowed_source_kinds:
            _text(value, "allowed source kind", 80)
        if type(self.require_complete_cohort) is not bool:
            raise PromotionError("require_complete_cohort must be boolean")
        for name in ("minimum_precision", "minimum_recall"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not 0.0 <= float(value) <= 1.0
            ):
                raise PromotionError(f"{name} must be null or a finite ratio")
        if len(self.required_resource_coverage) > 64:
            raise PromotionError("required resource coverage is oversized")
        for value in self.required_resource_coverage:
            _text(value, "required resource coverage", 160)

    @property
    def digest(self) -> str:
        document = asdict(self)
        document["allowed_source_kinds"] = list(self.allowed_source_kinds)
        document["required_resource_coverage"] = list(self.required_resource_coverage)
        return _digest(document)

    def quality_gates(self, receipt: QualityReceipt, *, now: float) -> tuple[str, ...]:
        failures: list[str] = []
        if receipt.policy_digest != self.digest:
            failures.append("quality receipt policy digest does not match current policy")
        if receipt.source_kind not in self.allowed_source_kinds:
            failures.append(
                "fixture-only, synthetic, or unapproved replay sources cannot authorize promotion"
            )
        if receipt.input_trust != "authenticated":
            failures.append(
                "self-attested source, signer, or coverage inputs cannot authorize promotion"
            )
        oldest_evidence = min(receipt.evaluated_at, receipt.created_at)
        if now < receipt.evaluated_at - 5.0 or now < receipt.created_at - 5.0:
            failures.append("quality evidence was created or evaluated in the future")
        elif now - oldest_evidence > self.maximum_quality_age_seconds:
            failures.append("quality receipt exceeds the maximum policy age")
        if receipt.row_count < self.minimum_rows:
            failures.append(f"cohort has {receipt.row_count} rows; {self.minimum_rows} required")
        if self.require_complete_cohort and not receipt.cohort_complete:
            failures.append("cohort reported loss or incomplete custody")
        if receipt.lost_match_count > self.maximum_lost_matches:
            failures.append(
                f"candidate loses {receipt.lost_match_count} matches; "
                f"maximum is {self.maximum_lost_matches}"
            )
        if receipt.new_match_count > self.maximum_new_matches:
            failures.append(
                f"candidate adds {receipt.new_match_count} matches; "
                f"maximum is {self.maximum_new_matches}"
            )
        if self.minimum_precision is not None:
            if receipt.precision is None:
                failures.append("precision gate requires a fully labelled cohort")
            elif receipt.precision < self.minimum_precision:
                failures.append("precision is below policy threshold")
        if self.minimum_recall is not None:
            if receipt.recall is None:
                failures.append("recall gate requires a fully labelled cohort")
            elif receipt.recall < self.minimum_recall:
                failures.append("recall is below policy threshold")
        missing = set(self.required_resource_coverage) - set(receipt.resource_coverage)
        if missing:
            failures.append(
                "required resource coverage is missing: " + ", ".join(sorted(missing))
            )
        return tuple(failures)


@dataclass(frozen=True)
class PromotionReceipt:
    schema: str
    receipt_id: str
    action: str
    package_id: str
    active_digest: str | None
    target_digest: str
    cohort_digest: str
    policy_digest: str
    quality_receipt_id: str
    signer: str
    tuning_digest: str
    resource_coverage: tuple[str, ...]
    issued_at: float
    expires_at: float
    nonce: str
    receipt_hmac: str

    def __post_init__(self) -> None:
        if self.schema != PROMOTION_SCHEMA:
            raise PromotionError("unsupported promotion receipt schema")
        _text(self.receipt_id, "receipt_id", 96)
        if self.action not in _ACTIONS:
            raise PromotionError("unsupported promotion action")
        _text(self.package_id, "package_id", 128)
        _digest_value(self.active_digest, "active_digest", optional=True)
        _digest_value(self.target_digest, "target_digest")
        _digest_value(self.cohort_digest, "cohort_digest")
        _digest_value(self.policy_digest, "policy_digest")
        _text(self.quality_receipt_id, "quality_receipt_id", 96)
        _text(self.signer, "signer", 160)
        _digest_value(self.tuning_digest, "tuning_digest")
        _coverage(self.resource_coverage)
        for name in ("issued_at", "expires_at"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) <= 0
            ):
                raise PromotionError(f"{name} must be a positive finite timestamp")
        if self.expires_at <= self.issued_at:
            raise PromotionError("promotion receipt expiry must follow issue time")
        if len(self.nonce) != 32 or any(
            character not in "0123456789abcdef" for character in self.nonce
        ):
            raise PromotionError("promotion nonce is invalid")
        if len(self.receipt_hmac) != 64 or any(
            character not in "0123456789abcdef" for character in self.receipt_hmac
        ):
            raise PromotionError("promotion receipt HMAC is invalid")

    def unsigned_dict(self) -> dict[str, object]:
        document = asdict(self)
        document["resource_coverage"] = list(self.resource_coverage)
        document.pop("receipt_hmac")
        return document

    def to_dict(self) -> dict[str, object]:
        document = self.unsigned_dict()
        document["receipt_hmac"] = self.receipt_hmac
        return document


class PromotionAuthority:
    """Purpose-separated HMAC authority for short-lived operator receipts."""

    def __init__(
        self,
        key: bytes,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("promotion authority must contain exactly 32 bytes")
        self._receipt_key = hmac.new(
            key, b"angerona/detection-promotion-receipt/v1", hashlib.sha256
        ).digest()
        self._state_key = hmac.new(
            key, b"angerona/detection-promotion-state/v2", hashlib.sha256
        ).digest()
        self._clock = clock

    def _mac(self, receipt: PromotionReceipt) -> str:
        unsigned = receipt.unsigned_dict()
        unsigned["receipt_id"] = ""
        return hmac.new(
            self._receipt_key, _canonical(unsigned), hashlib.sha256
        ).hexdigest()

    def current_time(self) -> float:
        current = float(self._clock())
        if not math.isfinite(current) or current <= 0:
            raise PromotionError("promotion authority clock is invalid")
        return current

    def state_mac(
        self,
        document: Mapping[str, object],
        *,
        checkpoint: bool = False,
        anchor: bool = False,
    ) -> str:
        if checkpoint and anchor:
            raise PromotionError("promotion MAC domain is ambiguous")
        domain = b"anchor\x00" if anchor else (b"checkpoint\x00" if checkpoint else b"state\x00")
        return hmac.new(
            self._state_key, domain + _canonical(document), hashlib.sha256
        ).hexdigest()

    def issue(
        self,
        *,
        action: str,
        package_id: str,
        active_digest: str | None,
        target_digest: str,
        cohort_digest: str,
        policy_digest: str,
        quality_receipt_id: str,
        signer: str,
        tuning_digest: str,
        resource_coverage: object,
        ttl_seconds: float = 15 * 60,
    ) -> PromotionReceipt:
        if action not in _ACTIONS:
            raise PromotionError("unsupported promotion action")
        stamp = self.current_time()
        ttl = float(ttl_seconds)
        if not math.isfinite(stamp) or stamp <= 0 or not 5.0 <= ttl <= 86_400.0:
            raise PromotionError("promotion receipt time window is invalid")
        values: dict[str, object] = {
            "schema": PROMOTION_SCHEMA,
            "receipt_id": "pending",
            "action": action,
            "package_id": _text(package_id, "package_id", 128),
            "active_digest": _digest_value(active_digest, "active_digest", optional=True),
            "target_digest": _digest_value(target_digest, "target_digest"),
            "cohort_digest": _digest_value(cohort_digest, "cohort_digest"),
            "policy_digest": _digest_value(policy_digest, "policy_digest"),
            "quality_receipt_id": _text(quality_receipt_id, "quality_receipt_id", 96),
            "signer": _text(signer, "signer", 160),
            "tuning_digest": _digest_value(tuning_digest, "tuning_digest"),
            "resource_coverage": _coverage(resource_coverage),
            "issued_at": stamp,
            "expires_at": stamp + ttl,
            "nonce": secrets.token_hex(16),
            "receipt_hmac": "0" * 64,
        }
        provisional = PromotionReceipt(**values)  # type: ignore[arg-type]
        receipt_hmac = self._mac(provisional)
        receipt_id = "promotion-" + hashlib.sha256(
            _canonical(provisional.unsigned_dict()) + receipt_hmac.encode("ascii")
        ).hexdigest()[:40]
        values["receipt_id"] = receipt_id
        values["receipt_hmac"] = receipt_hmac
        return PromotionReceipt(**values)  # type: ignore[arg-type]

    def verify(self, receipt: PromotionReceipt) -> None:
        if not isinstance(receipt, PromotionReceipt):
            raise PromotionError("promotion receipt type is invalid")
        expected = self._mac(receipt)
        if not hmac.compare_digest(receipt.receipt_hmac, expected):
            raise PromotionError("promotion receipt HMAC verification failed")
        unsigned = receipt.unsigned_dict()
        unsigned["receipt_id"] = "pending"
        expected_id = "promotion-" + hashlib.sha256(
            _canonical(unsigned) + receipt.receipt_hmac.encode("ascii")
        ).hexdigest()[:40]
        if not hmac.compare_digest(receipt.receipt_id, expected_id):
            raise PromotionError("promotion receipt identity verification failed")
        current = self.current_time()
        if current < receipt.issued_at - 5.0:
            raise PromotionError("promotion receipt was issued in the future")
        if current > receipt.expires_at:
            raise PromotionError("promotion receipt is stale")


@dataclass(frozen=True)
class PromotionResult:
    ok: bool
    action: str
    package_id: str
    target_digest: str
    previous_digest: str | None
    state: str
    activation_epoch: int = 0
    errors: tuple[str, ...] = ()


class DetectionPromotionCoordinator:
    """Serialize exact quality-gated registry transitions and one-use receipts."""

    def __init__(
        self,
        registry: DetectionPackageRegistry,
        quality_store: DetectionQualityStore,
        authority: PromotionAuthority,
        policy: PromotionPolicy | None = None,
        *,
        state_path: str | Path | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.registry = registry
        self.quality_store = quality_store
        self.authority = authority
        self.policy = policy or PromotionPolicy()
        self._clock = clock or authority.current_time
        self.state_path = Path(
            state_path or (registry.root / "promotion-state.json")
        ).resolve()
        self.checkpoint_path = self.state_path.with_suffix(
            self.state_path.suffix + ".checkpoint"
        )
        self.anchor_path = self.state_path.with_suffix(
            self.state_path.suffix + ".monotonic-anchor"
        )
        self.lock_path = self.state_path.with_suffix(".lock")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._thread_lock = threading.RLock()
        with self._locked():
            state_exists = self.state_path.exists()
            checkpoint_exists = self.checkpoint_path.exists()
            anchor_exists = self.anchor_path.exists()
            if len({state_exists, checkpoint_exists, anchor_exists}) != 1:
                raise PromotionError(
                    "promotion state/checkpoint pair is incomplete or its monotonic anchor "
                    "is missing; authority cannot be reinitialized"
                )
            if not state_exists:
                inventory = self.registry.inventory()
                has_active = any(
                    isinstance(record, Mapping) and record.get("state") == "active"
                    for versions in inventory.values()
                    if isinstance(versions, Mapping)
                    for record in versions.values()
                )
                if has_active or self.quality_store.receipts():
                    raise PromotionError(
                        "missing promotion state cannot be reinitialized over existing authority"
                    )
                self._write_state({
                    "schema": PROMOTION_STATE_SCHEMA,
                    "serial": 0,
                    "used_receipts": [],
                    "transitions": [],
                    "transition_head": "0" * 64,
                    "hmac": "",
                })
            else:
                self._read_state()

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

    def _state_mac(self, state: Mapping[str, object]) -> str:
        unsigned = dict(state)
        unsigned.pop("hmac", None)
        return self.authority.state_mac(unsigned)

    def _checkpoint_mac(self, checkpoint: Mapping[str, object]) -> str:
        unsigned = dict(checkpoint)
        unsigned.pop("hmac", None)
        return self.authority.state_mac(unsigned, checkpoint=True)

    def _anchor_mac(self, anchor: Mapping[str, object]) -> str:
        unsigned = dict(anchor)
        unsigned.pop("hmac", None)
        return self.authority.state_mac(unsigned, anchor=True)

    @staticmethod
    def _atomic_write(path: Path, payload: bytes, *, prefix: str) -> None:
        descriptor, temporary = tempfile.mkstemp(
            prefix=prefix, suffix=".tmp", dir=path.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            raise PromotionError("promotion state is missing after initialization")
        try:
            document = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PromotionError("promotion state is unreadable or malformed") from exc
        if not isinstance(document, dict) or set(document) != {
            "schema", "serial", "used_receipts", "transitions",
            "transition_head", "hmac"
        }:
            raise PromotionError("promotion state fields are invalid")
        if document["schema"] != PROMOTION_STATE_SCHEMA:
            raise PromotionError("promotion state schema is invalid")
        if type(document["serial"]) is not int or document["serial"] < 0:
            raise PromotionError("promotion state serial is invalid")
        if not isinstance(document["used_receipts"], list) or not isinstance(
            document["transitions"], list
        ):
            raise PromotionError("promotion state collections are invalid")
        if len(document["used_receipts"]) > 4096 or len(document["transitions"]) > 512:
            raise PromotionError("promotion state exceeds its bound")
        for item in document["used_receipts"]:
            if (
                not isinstance(item, dict)
                or set(item) != {"receipt_id", "expires_at"}
                or not isinstance(item["receipt_id"], str)
                or not item["receipt_id"]
                or isinstance(item["expires_at"], bool)
                or not isinstance(item["expires_at"], (int, float))
                or not math.isfinite(float(item["expires_at"]))
            ):
                raise PromotionError("promotion used-receipt checkpoint is invalid")
        head = document["transition_head"]
        if not isinstance(head, str) or len(head) != 64 or any(
            character not in "0123456789abcdef" for character in head
        ):
            raise PromotionError("promotion transition head is invalid")
        expected = self._state_mac(document)
        if not hmac.compare_digest(str(document["hmac"]), expected):
            raise PromotionError("promotion state HMAC verification failed")
        self._verify_checkpoint(document)
        self._verify_anchor(document)
        return document

    def _verify_checkpoint(self, state: Mapping[str, object]) -> None:
        if not self.checkpoint_path.exists():
            raise PromotionError("promotion checkpoint is missing")
        try:
            checkpoint = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PromotionError("promotion checkpoint is unreadable or malformed") from exc
        if not isinstance(checkpoint, dict) or set(checkpoint) != {
            "schema", "serial", "transition_head", "state_hmac", "hmac"
        }:
            raise PromotionError("promotion checkpoint fields are invalid")
        if checkpoint["schema"] != PROMOTION_CHECKPOINT_SCHEMA:
            raise PromotionError("promotion checkpoint schema is invalid")
        expected = self._checkpoint_mac(checkpoint)
        if not hmac.compare_digest(str(checkpoint["hmac"]), expected):
            raise PromotionError("promotion checkpoint HMAC verification failed")
        if (
            checkpoint["serial"] != state["serial"]
            or checkpoint["transition_head"] != state["transition_head"]
            or checkpoint["state_hmac"] != state["hmac"]
        ):
            raise PromotionError("promotion state/checkpoint divergence detected")

    def _read_anchor(self) -> dict[str, object]:
        if not self.anchor_path.exists():
            raise PromotionError("promotion monotonic anchor is missing")
        try:
            anchor = json.loads(self.anchor_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PromotionError("promotion monotonic anchor is unreadable or malformed") from exc
        if not isinstance(anchor, dict) or set(anchor) != {
            "schema", "serial", "transition_head", "state_hmac", "hmac"
        }:
            raise PromotionError("promotion monotonic anchor fields are invalid")
        if anchor["schema"] != PROMOTION_ANCHOR_SCHEMA:
            raise PromotionError("promotion monotonic anchor schema is invalid")
        if type(anchor["serial"]) is not int or anchor["serial"] < 0:
            raise PromotionError("promotion monotonic anchor serial is invalid")
        expected = self._anchor_mac(anchor)
        if not hmac.compare_digest(str(anchor["hmac"]), expected):
            raise PromotionError("promotion monotonic anchor HMAC verification failed")
        return anchor

    def _verify_anchor(self, state: Mapping[str, object]) -> None:
        anchor = self._read_anchor()
        if (
            anchor["serial"] != state["serial"]
            or anchor["transition_head"] != state["transition_head"]
            or anchor["state_hmac"] != state["hmac"]
        ):
            raise PromotionError("promotion monotonic rollback or divergence detected")

    def _write_state(self, state: dict[str, Any]) -> None:
        unsigned = dict(state)
        unsigned["hmac"] = self._state_mac(unsigned)
        checkpoint: dict[str, object] = {
            "schema": PROMOTION_CHECKPOINT_SCHEMA,
            "serial": unsigned["serial"],
            "transition_head": unsigned["transition_head"],
            "state_hmac": unsigned["hmac"],
            "hmac": "",
        }
        checkpoint["hmac"] = self._checkpoint_mac(checkpoint)
        anchor: dict[str, object] = {
            "schema": PROMOTION_ANCHOR_SCHEMA,
            "serial": unsigned["serial"],
            "transition_head": unsigned["transition_head"],
            "state_hmac": unsigned["hmac"],
            "hmac": "",
        }
        anchor["hmac"] = self._anchor_mac(anchor)
        if self.anchor_path.exists():
            prior = self._read_anchor()
            prior_serial = int(prior["serial"])
            proposed_serial = int(anchor["serial"])
            if proposed_serial < prior_serial:
                raise PromotionError("promotion monotonic anchor refuses serial rollback")
            if proposed_serial == prior_serial and prior != anchor:
                raise PromotionError("promotion monotonic anchor refuses same-serial substitution")
        self._atomic_write(
            self.state_path, _canonical(unsigned), prefix=".promotion-state-"
        )
        self._atomic_write(
            self.checkpoint_path,
            _canonical(checkpoint),
            prefix=".promotion-checkpoint-",
        )
        self._atomic_write(
            self.anchor_path,
            _canonical(anchor),
            prefix=".promotion-monotonic-anchor-",
        )

    @staticmethod
    def _current_active(
        inventory: Mapping[str, Any], package_id: str
    ) -> tuple[str | None, Mapping[str, Any] | None]:
        versions = inventory.get(package_id, {})
        if not isinstance(versions, Mapping):
            raise PromotionError("registry package inventory is invalid")
        active = [
            (digest, record) for digest, record in versions.items()
            if isinstance(record, Mapping) and record.get("state") == "active"
        ]
        if len(active) > 1:
            raise PromotionError("registry contains multiple active package digests")
        return active[0] if active else (None, None)

    def issue_promotion_receipt(
        self,
        quality_receipt: QualityReceipt,
        *,
        signer: str,
        tuning_digest: str,
        resource_coverage: object,
    ) -> PromotionReceipt:
        if not self.quality_store.verify(quality_receipt):
            raise PromotionError("quality receipt is not an exact member of the local ledger")
        if quality_receipt.policy_digest != self.policy.digest:
            raise PromotionError("quality receipt does not bind the current policy")
        active_digest, _record = self._current_active(
            self.registry.inventory(), quality_receipt.package_id
        )
        return self.authority.issue(
            action="promote",
            package_id=quality_receipt.package_id,
            active_digest=active_digest,
            target_digest=quality_receipt.candidate_digest,
            cohort_digest=quality_receipt.cohort_digest,
            policy_digest=self.policy.digest,
            quality_receipt_id=quality_receipt.receipt_id,
            signer=signer,
            tuning_digest=tuning_digest,
            resource_coverage=resource_coverage,
            ttl_seconds=self.policy.receipt_ttl_seconds,
        )

    def issue_rollback_receipt(
        self,
        *,
        package_id: str,
        signer: str,
        tuning_digest: str,
        resource_coverage: object,
    ) -> PromotionReceipt:
        active_digest, active_record = self._current_active(
            self.registry.inventory(), package_id
        )
        if active_digest is None or active_record is None:
            raise PromotionError("rollback requires an authoritative active package")
        target_digest = active_record.get("previous_digest")
        if not isinstance(target_digest, str):
            raise PromotionError("rollback target is not recorded by the registry")
        return self.authority.issue(
            action="rollback",
            package_id=package_id,
            active_digest=active_digest,
            target_digest=target_digest,
            cohort_digest=_ZERO_DIGEST,
            policy_digest=self.policy.digest,
            quality_receipt_id="rollback-operator-authority",
            signer=signer,
            tuning_digest=tuning_digest,
            resource_coverage=resource_coverage,
            ttl_seconds=self.policy.receipt_ttl_seconds,
        )

    @staticmethod
    def _same(value: object, expected: object, name: str) -> None:
        if value != expected:
            raise PromotionError(f"{name} substitution detected")

    def _verify_quality_binding(
        self, approval: PromotionReceipt, quality: QualityReceipt, *, now: float
    ) -> None:
        self._same(quality.package_id, approval.package_id, "package")
        self._same(quality.candidate_digest, approval.target_digest, "candidate digest")
        self._same(quality.cohort_digest, approval.cohort_digest, "cohort")
        self._same(quality.policy_digest, approval.policy_digest, "policy")
        self._same(quality.signer, approval.signer, "signer")
        self._same(quality.tuning_digest, approval.tuning_digest, "tuning")
        self._same(quality.resource_coverage, approval.resource_coverage, "resource coverage")
        expected_active = (approval.active_digest,) if approval.active_digest else ()
        self._same(quality.active_digests, expected_active, "active package")
        failures = self.policy.quality_gates(quality, now=now)
        if failures:
            raise PromotionError("; ".join(failures))

    def _record_transition(
        self,
        state: dict[str, Any],
        approval: PromotionReceipt,
        previous_digest: str | None,
        *,
        now: float,
    ) -> int:
        used = [
            item
            for item in state["used_receipts"]
            if float(item["expires_at"]) >= now
        ]
        if any(item["receipt_id"] == approval.receipt_id for item in used):
            raise PromotionError("promotion receipt was already consumed")
        if len(used) >= 4096:
            raise PromotionError(
                "promotion one-use checkpoint is full of unexpired receipts"
            )
        used.append({
            "receipt_id": approval.receipt_id,
            "expires_at": approval.expires_at,
        })
        transitions = list(state["transitions"])
        transition = {
            "serial": int(state["serial"]) + 1,
            "receipt_id": approval.receipt_id,
            "action": approval.action,
            "package_id": approval.package_id,
            "previous_digest": previous_digest,
            "target_digest": approval.target_digest,
            "authorized_at": now,
        }
        transitions.append(transition)
        state["serial"] = int(state["serial"]) + 1
        state["used_receipts"] = used
        state["transitions"] = transitions[-512:]
        state["transition_head"] = hashlib.sha256(
            str(state["transition_head"]).encode("ascii") + _canonical(transition)
        ).hexdigest()
        self._write_state(state)
        return int(state["serial"])

    def promote(self, approval: PromotionReceipt) -> PromotionResult:
        try:
            self.authority.verify(approval)
            current_time = float(self._clock())
            if not math.isfinite(current_time) or current_time <= 0:
                raise PromotionError("promotion coordinator clock is invalid")
            if approval.action != "promote":
                raise PromotionError("promotion requires a promote receipt")
            self._same(approval.policy_digest, self.policy.digest, "current policy")
            with self._locked():
                state = self._read_state()
                if any(
                    item["receipt_id"] == approval.receipt_id
                    for item in state["used_receipts"]
                ):
                    raise PromotionError("promotion receipt was already consumed")
                inventory = self.registry.inventory()
                active_digest, _record = self._current_active(inventory, approval.package_id)
                self._same(active_digest, approval.active_digest, "active package")
                versions = inventory.get(approval.package_id, {})
                target = versions.get(approval.target_digest) if isinstance(versions, Mapping) else None
                if not isinstance(target, Mapping) or target.get("state") not in {
                    "staged", "retired", "active"
                }:
                    raise PromotionError("candidate digest is not staged and retained")
                quality = self.quality_store.get(approval.quality_receipt_id)
                self._verify_quality_binding(approval, quality, now=current_time)
                # Persist one-use authority before touching the registry. If
                # the process crashes from this point onward, the exact receipt
                # remains consumed and can never be replayed against a later
                # package state. Registry activation itself is one atomic
                # manifest replacement and remains the completion authority.
                activation_epoch = self._record_transition(
                    state, approval, active_digest, now=current_time
                )
                report = self.registry.activate(approval.package_id, approval.target_digest)
                if not report.ok:
                    raise PromotionError("registry activation failed: " + "; ".join(report.errors))
                current, _current_record = self._current_active(
                    self.registry.inventory(), approval.package_id
                )
                if current != approval.target_digest:
                    raise PromotionError("registry did not commit the exact candidate digest")
                return PromotionResult(
                    ok=True,
                    action="promote",
                    package_id=approval.package_id,
                    target_digest=approval.target_digest,
                    previous_digest=active_digest,
                    state="active",
                    activation_epoch=activation_epoch,
                )
        except Exception as exc:
            return PromotionResult(
                ok=False,
                action="promote",
                package_id=getattr(approval, "package_id", ""),
                target_digest=getattr(approval, "target_digest", ""),
                previous_digest=getattr(approval, "active_digest", None),
                state="rejected",
                errors=(str(exc),),
            )

    def rollback(self, approval: PromotionReceipt) -> PromotionResult:
        try:
            self.authority.verify(approval)
            current_time = float(self._clock())
            if not math.isfinite(current_time) or current_time <= 0:
                raise PromotionError("promotion coordinator clock is invalid")
            if approval.action != "rollback":
                raise PromotionError("rollback requires a rollback receipt")
            self._same(approval.policy_digest, self.policy.digest, "current policy")
            with self._locked():
                state = self._read_state()
                if any(
                    item["receipt_id"] == approval.receipt_id
                    for item in state["used_receipts"]
                ):
                    raise PromotionError("rollback receipt was already consumed")
                inventory = self.registry.inventory()
                active_digest, active_record = self._current_active(
                    inventory, approval.package_id
                )
                self._same(active_digest, approval.active_digest, "active package")
                if active_record is None or active_record.get("previous_digest") != approval.target_digest:
                    raise PromotionError("rollback target is not the active package predecessor")
                activation_epoch = self._record_transition(
                    state, approval, active_digest, now=current_time
                )
                report = self.registry.rollback(approval.package_id)
                if not report.ok:
                    raise PromotionError("registry rollback failed: " + "; ".join(report.errors))
                current, _record = self._current_active(
                    self.registry.inventory(), approval.package_id
                )
                if current != approval.target_digest:
                    raise PromotionError("registry did not commit the exact rollback digest")
                return PromotionResult(
                    ok=True,
                    action="rollback",
                    package_id=approval.package_id,
                    target_digest=approval.target_digest,
                    previous_digest=active_digest,
                    state="active",
                    activation_epoch=activation_epoch,
                )
        except Exception as exc:
            return PromotionResult(
                ok=False,
                action="rollback",
                package_id=getattr(approval, "package_id", ""),
                target_digest=getattr(approval, "target_digest", ""),
                previous_digest=getattr(approval, "active_digest", None),
                state="rejected",
                errors=(str(exc),),
            )


__all__ = [
    "PROMOTION_SCHEMA",
    "DetectionPromotionCoordinator",
    "PromotionAuthority",
    "PromotionError",
    "PromotionPolicy",
    "PromotionReceipt",
    "PromotionResult",
    "digest_tuning",
]
