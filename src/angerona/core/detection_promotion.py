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
from copy import deepcopy
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
PROMOTION_STATE_SCHEMA = "angerona.detection-promotion-state.v3"
LEGACY_PROMOTION_STATE_SCHEMA = "angerona.detection-promotion-state.v2"
PROMOTION_CHECKPOINT_SCHEMA = "angerona.detection-promotion-checkpoint.v1"
PROMOTION_ANCHOR_SCHEMA = "angerona.detection-promotion-monotonic-anchor.v1"
PROMOTION_TRANSACTION_SCHEMA = "angerona.detection-promotion-transaction.v1"
_ACTIONS = frozenset({"promote", "rollback"})
_TRANSACTION_ACTIONS = _ACTIONS | frozenset({"quarantine"})
_DIGEST_PREFIX = "sha256:"
_ZERO_DIGEST = _DIGEST_PREFIX + "0" * 64
MAX_ACTIVE_BINDINGS = 128
_MAX_RECEIPT_TOMBSTONE_SECONDS = 86_400.0
_OWNER_LEASES: dict[str, dict[str, object]] = {}
_OWNER_LEASES_LOCK = threading.RLock()
_OWNER_LEASES_PID = os.getpid()


def _discard_inherited_owner_leases() -> None:
    """Drop fork-inherited descriptors without unlocking the parent's lease."""
    global _OWNER_LEASES, _OWNER_LEASES_LOCK, _OWNER_LEASES_PID
    current_pid = os.getpid()
    if current_pid == _OWNER_LEASES_PID:
        return
    inherited = tuple(_OWNER_LEASES.values())
    _OWNER_LEASES = {}
    _OWNER_LEASES_LOCK = threading.RLock()
    _OWNER_LEASES_PID = current_pid
    for entry in inherited:
        stream = entry.get("stream")
        close = getattr(stream, "close", None)
        if callable(close):
            try:
                # Closing the child's duplicate descriptor leaves the parent's
                # shared open-file-description lock intact. Never issue LOCK_UN.
                close()
            except OSError:
                pass


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_discard_inherited_owner_leases)


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
        transaction: bool = False,
    ) -> str:
        if sum((checkpoint, anchor, transaction)) > 1:
            raise PromotionError("promotion MAC domain is ambiguous")
        domain = (
            b"transaction\x00"
            if transaction
            else (b"anchor\x00" if anchor else (
                b"checkpoint\x00" if checkpoint else b"state\x00"
            ))
        )
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


@dataclass(frozen=True, eq=False)
class _CoordinatorAuthorityBinding:
    creator_pid: int
    registry_root: str
    registry_packages_path: str
    registry_quarantine_path: str
    registry_manifest_path: str
    registry_anchor_path: str
    registry_lock_path: str
    registry_trusted_keys_path: str | None
    registry_root_governed: bool
    registry_governance_required: bool
    registry_require_signed: bool
    state_path: str
    checkpoint_path: str
    anchor_path: str
    lock_path: str
    transaction_path: str
    owner_lease_path: str
    quality_path: str
    quality_lock_path: str
    quality_store: object
    authority: object
    policy: object
    clock_owner: object | None
    clock_callable: object
    transition_capability: object | None

    def matches(self, other: object) -> bool:
        if not isinstance(other, _CoordinatorAuthorityBinding):
            return False
        paths_and_configuration_match = (
            self.creator_pid == other.creator_pid
            and self.registry_root == other.registry_root
            and self.registry_packages_path == other.registry_packages_path
            and self.registry_quarantine_path == other.registry_quarantine_path
            and self.registry_manifest_path == other.registry_manifest_path
            and self.registry_anchor_path == other.registry_anchor_path
            and self.registry_lock_path == other.registry_lock_path
            and self.registry_trusted_keys_path
            == other.registry_trusted_keys_path
            and self.registry_root_governed == other.registry_root_governed
            and self.registry_governance_required
            == other.registry_governance_required
            and self.registry_require_signed == other.registry_require_signed
            and self.state_path == other.state_path
            and self.checkpoint_path == other.checkpoint_path
            and self.anchor_path == other.anchor_path
            and self.lock_path == other.lock_path
            and self.transaction_path == other.transaction_path
            and self.owner_lease_path == other.owner_lease_path
            and self.quality_path == other.quality_path
            and self.quality_lock_path == other.quality_lock_path
        )
        if not paths_and_configuration_match:
            return False
        if isinstance(self.transition_capability, bytes):
            capability_matches = isinstance(other.transition_capability, bytes) and (
                hmac.compare_digest(
                    self.transition_capability, other.transition_capability
                )
            )
        else:
            capability_matches = (
                self.transition_capability is other.transition_capability
            )
        return (
            capability_matches
            and self.quality_store is other.quality_store
            and self.authority is other.authority
            and self.policy is other.policy
            and self.clock_owner is other.clock_owner
            and self.clock_callable is other.clock_callable
        )


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
        transition_capability: object | None = None,
        runtime_module: object | None = None,
        runtime_manager: object | None = None,
        runtime_engine: object | None = None,
    ) -> None:
        self.registry = registry
        self.quality_store = quality_store
        self.authority = authority
        self.policy = policy or PromotionPolicy()
        registry.assert_transition_authority(transition_capability)
        self._transition_capability = transition_capability
        self._runtime_module = runtime_module
        self._runtime_manager = runtime_manager
        self._runtime_engine = runtime_engine
        self.__runtime_authority: object | None = None
        self.__runtime_authority_generation = -1
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
        self.transaction_path = self.state_path.with_suffix(
            self.state_path.suffix + ".pending"
        )
        self.owner_lease_path = self.registry.root / ".promotion-owner.lock"
        self._owner_lease_snapshot = self._owner_lease_binding()
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._thread_lock = threading.RLock()
        self._owner_lease_key: str | None = None
        self._closed = False
        self._acquire_owner_lease()
        try:
            self._initialize_authority_state()
            if (
                self._owner_lease_snapshot.registry_root_governed
                and self._runtime_engine is not None
            ):
                self._refresh_runtime_authority()
        except Exception:
            self.close()
            raise

    def _initialize_authority_state(self) -> None:
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
                    "authority_time_floor": self._authority_now(),
                    "active_bindings": {},
                    "used_receipts": [],
                    "transitions": [],
                    "transition_head": "0" * 64,
                    "hmac": "",
                })
                return
            try:
                raw_state = json.loads(self.state_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PromotionError(
                    "promotion state is unreadable or malformed"
                ) from exc
            if (
                isinstance(raw_state, Mapping)
                and raw_state.get("schema") == LEGACY_PROMOTION_STATE_SCHEMA
            ):
                self._migrate_v2_state(dict(raw_state))
            elif (
                isinstance(raw_state, Mapping)
                and raw_state.get("schema") == PROMOTION_STATE_SCHEMA
                and "authority_time_floor" not in raw_state
            ):
                self._migrate_v3_time_floor(dict(raw_state))
            else:
                self._read_state()

    @staticmethod
    def _canonical_owner_path(path: str | Path) -> str:
        return os.path.normcase(str(Path(path).resolve()))

    def _owner_lease_binding(self) -> _CoordinatorAuthorityBinding:
        """Describe the exact authority and durable paths owned by this instance."""
        registry = self.registry
        if not isinstance(registry, DetectionPackageRegistry):
            raise PromotionError("promotion registry identity is invalid")
        trusted_keys = registry.trusted_keys
        clock_owner = getattr(self._clock, "__self__", None)
        clock_callable = getattr(self._clock, "__func__", self._clock)
        return _CoordinatorAuthorityBinding(
            creator_pid=os.getpid(),
            registry_root=self._canonical_owner_path(registry.root),
            registry_packages_path=self._canonical_owner_path(registry.packages),
            registry_quarantine_path=self._canonical_owner_path(registry.quarantine),
            registry_manifest_path=self._canonical_owner_path(registry.manifest_path),
            registry_anchor_path=self._canonical_owner_path(
                registry.governance_anchor_path
            ),
            registry_lock_path=self._canonical_owner_path(registry.lock_path),
            registry_trusted_keys_path=(
                None
                if trusted_keys is None
                else self._canonical_owner_path(trusted_keys)
            ),
            registry_root_governed=bool(registry.root_governed),
            registry_governance_required=bool(registry.governance_required),
            registry_require_signed=bool(registry.require_signed),
            state_path=self._canonical_owner_path(self.state_path),
            checkpoint_path=self._canonical_owner_path(self.checkpoint_path),
            anchor_path=self._canonical_owner_path(self.anchor_path),
            lock_path=self._canonical_owner_path(self.lock_path),
            transaction_path=self._canonical_owner_path(self.transaction_path),
            owner_lease_path=self._canonical_owner_path(self.owner_lease_path),
            quality_path=self._canonical_owner_path(self.quality_store.path),
            quality_lock_path=self._canonical_owner_path(
                self.quality_store.lock_path
            ),
            quality_store=self.quality_store,
            authority=self.authority,
            policy=self.policy,
            clock_owner=clock_owner,
            clock_callable=clock_callable,
            transition_capability=self._transition_capability,
        )

    def _assert_owner_configuration(self) -> None:
        try:
            current = self._owner_lease_binding()
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            raise PromotionError(
                "promotion coordinator authority binding changed"
            ) from exc
        if not self._owner_lease_snapshot.matches(current):
            raise PromotionError("promotion coordinator authority binding changed")

    def _acquire_owner_lease(self) -> None:
        _discard_inherited_owner_leases()
        snapshot = self._owner_lease_snapshot
        if not snapshot.registry_root_governed:
            return
        if self._runtime_engine is None:
            raise PromotionError(
                "root-governed promotion requires an exact runtime owner"
            )
        if (self._runtime_module is None) != (self._runtime_manager is None):
            raise PromotionError("runtime owner identity is incomplete")
        key = snapshot.registry_root
        with _OWNER_LEASES_LOCK:
            existing = _OWNER_LEASES.get(key)
            if existing is not None:
                if not (
                    existing["manager"] is self._runtime_manager
                    and existing["module"] is self._runtime_module
                    and existing["engine"] is self._runtime_engine
                ):
                    raise PromotionError(
                        "promotion root is already owned by a foreign runtime"
                    )
                if not snapshot.matches(existing.get("binding")):
                    raise PromotionError(
                        "promotion root is already bound to a foreign authority"
                    )
                existing["references"] = int(existing["references"]) + 1
                self._owner_lease_key = key
                return
            self.owner_lease_path.touch(exist_ok=True)
            stream = self.owner_lease_path.open("r+b")
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
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(
                        stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                    )
                acquired = True
            except (BlockingIOError, OSError) as exc:
                raise PromotionError(
                    "promotion root owner lease is held by another process"
                ) from exc
            finally:
                if not acquired:
                    stream.close()
            _OWNER_LEASES[key] = {
                "manager": self._runtime_manager,
                "module": self._runtime_module,
                "engine": self._runtime_engine,
                "creator_pid": snapshot.creator_pid,
                "stream": stream,
                "references": 1,
                "binding": snapshot,
            }
            self._owner_lease_key = key

    def _assert_owner_lease(self) -> None:
        _discard_inherited_owner_leases()
        self._assert_owner_configuration()
        snapshot = self._owner_lease_snapshot
        if not snapshot.registry_root_governed:
            return
        key = self._owner_lease_key
        with _OWNER_LEASES_LOCK:
            entry = _OWNER_LEASES.get(key or "")
            if entry is None or not (
                entry["manager"] is self._runtime_manager
                and entry["module"] is self._runtime_module
                and entry["engine"] is self._runtime_engine
                and entry.get("creator_pid") == snapshot.creator_pid
                and snapshot.creator_pid == os.getpid()
                and snapshot.matches(entry.get("binding"))
            ):
                raise PromotionError("promotion root owner lease is unavailable")

    def close(self) -> None:
        """Release this coordinator's crash-released lifetime owner lease."""
        if self._owner_lease_snapshot.creator_pid != os.getpid():
            _discard_inherited_owner_leases()
            self._closed = True
            self._owner_lease_key = None
            return
        with self._thread_lock:
            if self._closed:
                return
            self._closed = True
            key = self._owner_lease_key
            self._owner_lease_key = None
        if key is None:
            return
        with _OWNER_LEASES_LOCK:
            entry = _OWNER_LEASES.get(key)
            if entry is None:
                return
            if entry.get("creator_pid") != os.getpid():
                stream = entry.get("stream")
                _OWNER_LEASES.pop(key, None)
                close = getattr(stream, "close", None)
                if callable(close):
                    try:
                        close()
                    except OSError:
                        pass
                return
            remaining = int(entry["references"]) - 1
            if remaining > 0:
                entry["references"] = remaining
                return
            stream = entry["stream"]
            try:
                if os.name == "nt":
                    import msvcrt

                    stream.seek(0)  # type: ignore[attr-defined]
                    msvcrt.locking(  # type: ignore[attr-defined]
                        stream.fileno(), msvcrt.LK_UNLCK, 1
                    )
                else:
                    import fcntl

                    fcntl.flock(  # type: ignore[attr-defined]
                        stream.fileno(), fcntl.LOCK_UN
                    )
            except OSError:
                pass
            finally:
                stream.close()  # type: ignore[attr-defined]
                _OWNER_LEASES.pop(key, None)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @property
    def runtime_managed(self) -> bool:
        return bool(
            self.registry.root_governed
            and self._runtime_engine is not None
        )

    def _refresh_runtime_authority(
        self, *, authority_generation: int | None = None
    ) -> object:
        engine = self._runtime_engine
        module = self._runtime_module
        if engine is None:
            raise PromotionError("manager-owned detection runtime is unavailable")
        seal = getattr(engine, "seal_active_authority", None)
        if not callable(seal):
            raise PromotionError("detection runtime authority sealing is unavailable")
        seal_kwargs: dict[str, object] = {
            "transition_capability": self._transition_capability,
        }
        if authority_generation is not None:
            seal_kwargs["authority_generation"] = authority_generation
        if self._runtime_manager is not None:
            seal_kwargs["manager"] = self._runtime_manager
        capability = seal(self.registry, module, **seal_kwargs)
        self.__runtime_authority = capability
        self.__runtime_authority_generation = int(
            getattr(module, "lifecycle_generation", 0)
            if authority_generation is None
            else authority_generation
        )
        return capability

    def assert_runtime_identity(self, engine: object) -> None:
        """Bind DetectionForge to the exact manager-owned active engine."""
        if self._runtime_engine is None:
            if self.registry.root_governed:
                raise PromotionError(
                    "root-governed promotion requires a manager-owned runtime"
                )
            return
        if engine is not self._runtime_engine:
            raise PromotionError("DetectionForge runtime engine substitution detected")

    def _assert_live_runtime(self, *, expected_generation: int | None = None) -> int:
        """Require the exact subscribed, running manager module at transition time."""
        module = self._runtime_module
        manager = self._runtime_manager
        engine = self._runtime_engine
        if module is None or manager is None or engine is None:
            if (
                self.registry.root_governed
                and engine is not None
                and module is None
                and manager is None
            ):
                try:
                    engine.assert_active_authority(
                        self.registry, self.__runtime_authority
                    )
                except Exception:
                    self._refresh_runtime_authority()
                return 0
            if self.registry.root_governed:
                raise PromotionError(
                    "root-governed transition requires the live registered runtime"
                )
            return -1
        modules = getattr(manager, "modules", None)
        module_name = getattr(module, "name", None)
        if not isinstance(modules, Mapping) or modules.get(module_name) is not module:
            raise PromotionError("registered detection runtime identity changed")
        if getattr(module, "engine", None) is not engine:
            raise PromotionError("registered detection runtime engine identity changed")
        manager_bus = getattr(manager, "bus", None)
        if manager_bus is None or getattr(module, "_bus", None) is not manager_bus:
            raise PromotionError("detection runtime is bound to the wrong EventBus")
        thread = getattr(module, "_thread", None)
        if (
            getattr(module, "status", None) != "running"
            or thread is None
            or not thread.is_alive()
            or not bool(getattr(module, "_subscribed", False))
            or bool(getattr(module, "stopping", True))
        ):
            raise PromotionError(
                "detection runtime must be subscribed and running before transition"
            )
        generation = getattr(module, "lifecycle_generation", None)
        if type(generation) is not int or generation < 1:
            raise PromotionError("detection runtime lifecycle generation is invalid")
        if expected_generation is not None and generation != expected_generation:
            raise PromotionError("detection runtime lifecycle changed during transition")
        if (
            self.__runtime_authority is None
            or self.__runtime_authority_generation != generation
        ):
            self._refresh_runtime_authority()
        else:
            try:
                engine.assert_active_authority(
                    self.registry, self.__runtime_authority
                )
            except Exception:
                self._refresh_runtime_authority()
        return generation

    def _assert_startup_runtime(self) -> None:
        """Require the exact fresh registered module before its first start."""
        module = self._runtime_module
        manager = self._runtime_manager
        engine = self._runtime_engine
        if module is None or manager is None or engine is None:
            raise PromotionError(
                "startup restoration requires the registered manager runtime"
            )
        modules = getattr(manager, "modules", None)
        module_name = getattr(module, "name", None)
        if not isinstance(modules, Mapping) or modules.get(module_name) is not module:
            raise PromotionError("registered detection runtime identity changed")
        if getattr(module, "engine", None) is not engine:
            raise PromotionError("registered detection runtime engine identity changed")
        manager_bus = getattr(manager, "bus", None)
        if manager_bus is None or getattr(module, "_bus", None) is not manager_bus:
            raise PromotionError("detection runtime is bound to the wrong EventBus")
        thread = getattr(module, "_thread", None)
        if (
            getattr(module, "lifecycle_generation", None) != 0
            or getattr(module, "status", None) != "stopped"
            or (thread is not None and thread.is_alive())
            or bool(getattr(module, "_subscribed", False))
            or bool(getattr(module, "stopping", True))
        ):
            raise PromotionError(
                "startup restoration is limited to a fresh pre-start runtime"
            )

    @contextmanager
    def _runtime_lifecycle_guard(self) -> Iterator[None]:
        """Hold manager and module lifecycle controls in manager order."""
        module = self._runtime_module
        manager = self._runtime_manager
        manager_lock = getattr(manager, "_module_control_lock", None)
        lifecycle_lock = getattr(module, "_lifecycle_lock", None)

        @contextmanager
        def held(lock: object | None) -> Iterator[None]:
            if lock is None:
                yield
            else:
                with lock:  # type: ignore[attr-defined]
                    yield

        with held(manager_lock):
            with held(lifecycle_lock):
                yield

    @contextmanager
    def _runtime_commit_guard(self, expected_generation: int) -> Iterator[None]:
        """Hold lifecycle controls across final proof, durable commit, and sync."""
        with self._runtime_lifecycle_guard():
            self._assert_live_runtime(expected_generation=expected_generation)
            yield

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if self._owner_lease_snapshot.creator_pid != os.getpid():
            _discard_inherited_owner_leases()
            raise PromotionError("promotion coordinator authority binding changed")
        with self._thread_lock:
            if self._closed:
                raise PromotionError("promotion coordinator is closed")
            self._assert_owner_lease()
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
                if self.transaction_path.exists():
                    self._recover_transaction()
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

    def _authority_now(self) -> float:
        now = float(self._clock())
        if not math.isfinite(now) or now <= 0:
            raise PromotionError("promotion coordinator clock is invalid")
        return now

    def _assert_authority_time(
        self, state: Mapping[str, object], *, now: float | None = None
    ) -> float:
        floor = state.get("authority_time_floor")
        if (
            isinstance(floor, bool)
            or not isinstance(floor, (int, float))
            or not math.isfinite(float(floor))
            or float(floor) <= 0
        ):
            raise PromotionError("promotion authority time floor is invalid")
        observed = self._authority_now() if now is None else float(now)
        if not math.isfinite(observed) or observed <= 0:
            raise PromotionError("promotion coordinator clock is invalid")
        if observed < float(floor):
            raise PromotionError("promotion authority clock rollback detected")
        return observed

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

    def _transaction_mac(self, transaction: Mapping[str, object]) -> str:
        unsigned = dict(transaction)
        unsigned.pop("hmac", None)
        return self.authority.state_mac(unsigned, transaction=True)

    def _write_transaction(
        self,
        *,
        action: str,
        package_id: str,
        target_digest: str,
        old_state: Mapping[str, object],
        new_state: Mapping[str, object],
        abort_state: Mapping[str, object],
        old_registry: Mapping[str, object],
        new_registry: Mapping[str, object],
    ) -> None:
        transaction: dict[str, object] = {
            "schema": PROMOTION_TRANSACTION_SCHEMA,
            "action": action,
            "package_id": package_id,
            "target_digest": target_digest,
            "old_state": dict(old_state),
            "new_state": dict(new_state),
            "abort_state": dict(abort_state),
            "old_registry": dict(old_registry),
            "new_registry": dict(new_registry),
            "hmac": "",
        }
        transaction["hmac"] = self._transaction_mac(transaction)
        payload = _canonical(transaction)
        if len(payload) > 8 * 1024 * 1024:
            raise PromotionError("promotion transaction exceeds its storage bound")
        self._atomic_write(
            self.transaction_path,
            payload,
            prefix=".promotion-transaction-",
        )

    def _read_transaction(self) -> dict[str, Any]:
        try:
            raw = self.transaction_path.read_bytes()
        except OSError as exc:
            raise PromotionError("promotion transaction journal is unreadable") from exc
        if len(raw) > 8 * 1024 * 1024:
            raise PromotionError("promotion transaction journal is oversized")
        try:
            transaction = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PromotionError("promotion transaction journal is malformed") from exc
        if not isinstance(transaction, dict) or set(transaction) != {
            "schema", "action", "package_id", "target_digest", "old_state",
            "new_state", "abort_state", "old_registry", "new_registry", "hmac",
        }:
            raise PromotionError("promotion transaction journal fields are invalid")
        if transaction["schema"] != PROMOTION_TRANSACTION_SCHEMA:
            raise PromotionError("promotion transaction journal schema is invalid")
        if transaction["action"] not in _TRANSACTION_ACTIONS:
            raise PromotionError("promotion transaction action is invalid")
        _text(transaction["package_id"], "transaction package_id", 128)
        _digest_value(transaction["target_digest"], "transaction target digest")
        for name in (
            "old_state", "new_state", "abort_state", "old_registry", "new_registry"
        ):
            if not isinstance(transaction[name], dict):
                raise PromotionError(f"promotion transaction {name} is invalid")
        if not hmac.compare_digest(
            str(transaction["hmac"]), self._transaction_mac(transaction)
        ):
            raise PromotionError("promotion transaction journal HMAC is invalid")
        old_state = transaction["old_state"]
        new_state = transaction["new_state"]
        abort_state = transaction["abort_state"]
        for transaction_state in (old_state, new_state, abort_state):
            self._assert_authority_time(transaction_state)
        if (
            old_state.get("schema") != PROMOTION_STATE_SCHEMA
            or new_state.get("schema") != PROMOTION_STATE_SCHEMA
            or type(old_state.get("serial")) is not int
            or type(new_state.get("serial")) is not int
            or int(new_state["serial"]) != int(old_state["serial"]) + 1
            or abort_state.get("schema") != PROMOTION_STATE_SCHEMA
            or type(abort_state.get("serial")) is not int
            or int(abort_state["serial"]) != int(new_state["serial"])
            or (
                transaction["action"] != "quarantine"
                and abort_state.get("active_bindings")
                != old_state.get("active_bindings")
            )
            or (
                transaction["action"] == "quarantine"
                and (
                    abort_state.get("active_bindings")
                    != new_state.get("active_bindings")
                )
            )
            or "authority_time_floor" not in old_state
            or "authority_time_floor" not in new_state
            or "authority_time_floor" not in abort_state
            or float(new_state["authority_time_floor"])
            < float(old_state["authority_time_floor"])
            or float(abort_state["authority_time_floor"])
            < float(old_state["authority_time_floor"])
            or not hmac.compare_digest(
                str(old_state.get("hmac", "")), self._state_mac(old_state)
            )
            or not hmac.compare_digest(
                str(new_state.get("hmac", "")), self._state_mac(new_state)
            )
            or not hmac.compare_digest(
                str(abort_state.get("hmac", "")), self._state_mac(abort_state)
            )
        ):
            raise PromotionError("promotion transaction state authority is invalid")
        self._assert_authority_time({
            "authority_time_floor": max(
                float(old_state["authority_time_floor"]),
                float(new_state["authority_time_floor"]),
                float(abort_state["authority_time_floor"]),
            )
        })
        return transaction

    @staticmethod
    def _candidate_quarantine_only(
        current: Mapping[str, object],
        expected: Mapping[str, object],
        package_id: str,
        target_digest: str,
    ) -> bool:
        candidate = deepcopy(dict(expected))
        try:
            candidate["packages"][package_id][target_digest]["state"] = "quarantined"
        except (KeyError, TypeError):
            return False
        return current == candidate

    def _clear_transaction(self) -> None:
        try:
            self.transaction_path.unlink()
        except FileNotFoundError:
            return
        try:
            descriptor = os.open(str(self.transaction_path.parent), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    def _authority_documents(
        self, state: Mapping[str, object]
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        signed = dict(state)
        signed["hmac"] = self._state_mac(signed)
        checkpoint: dict[str, object] = {
            "schema": PROMOTION_CHECKPOINT_SCHEMA,
            "serial": signed["serial"],
            "authority_time_floor": signed["authority_time_floor"],
            "transition_head": signed["transition_head"],
            "state_hmac": signed["hmac"],
            "hmac": "",
        }
        checkpoint["hmac"] = self._checkpoint_mac(checkpoint)
        anchor: dict[str, object] = {
            "schema": PROMOTION_ANCHOR_SCHEMA,
            "serial": signed["serial"],
            "authority_time_floor": signed["authority_time_floor"],
            "transition_head": signed["transition_head"],
            "state_hmac": signed["hmac"],
            "hmac": "",
        }
        anchor["hmac"] = self._anchor_mac(anchor)
        return signed, checkpoint, anchor

    def _transaction_authority_phase(
        self,
        transaction: Mapping[str, Any],
        current_registry: Mapping[str, object],
    ) -> frozenset[str]:
        """Accept only exact old/partial/new documents from this transaction."""
        variants = {
            label: self._authority_documents(transaction[f"{label}_state"])
            for label in ("old", "new", "abort")
        }
        labels: set[str] = set()
        for index, path in enumerate(
            (self.state_path, self.checkpoint_path, self.anchor_path)
        ):
            try:
                current = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PromotionError(
                    "promotion transaction authority phase is unreadable"
                ) from exc
            matches = {
                label for label, documents in variants.items()
                if current == documents[index]
            }
            if len(matches) != 1:
                raise PromotionError(
                    "promotion transaction is stale or authority phase diverged"
                )
            labels.update(matches)
        if labels == {"new"} and current_registry != transaction["new_registry"]:
            raise PromotionError(
                "completed promotion journal cannot roll back its registry"
            )
        if labels == {"abort"} and current_registry != transaction["old_registry"]:
            raise PromotionError(
                "completed abort journal cannot substitute its registry"
            )
        return frozenset(labels)

    def _recover_transaction(self) -> str:
        """Finish a valid registry commit or restore its authenticated predecessor."""
        transaction = self._read_transaction()
        old_registry = transaction["old_registry"]
        new_registry = transaction["new_registry"]
        abort_state = transaction["abort_state"]
        package_id = str(transaction["package_id"])
        target_digest = str(transaction["target_digest"])
        with self.registry._locked():
            current = self.registry._manifest()
            self._transaction_authority_phase(transaction, current)
            if transaction["action"] == "quarantine":
                if current not in (old_registry, new_registry):
                    raise PromotionError(
                        "quarantine transaction registry authority diverged"
                    )
                self._validate_registry_active_locked(
                    dict(new_registry),
                    dict(transaction["new_state"]["active_bindings"]),
                )
                if current != new_registry:
                    self.registry._write_manifest(dict(new_registry))
                self._write_state(
                    dict(transaction["new_state"]), recovering=True
                )
                outcome = "new"
            elif current == new_registry:
                valid = True
                bindings = dict(transaction["new_state"].get("active_bindings", {}))
                for active_package, active_digest in bindings.items():
                    if self.registry._trusted_active_locked(
                        current,
                        str(active_package),
                        str(active_digest),
                        quarantine_on_failure=False,
                    ) is None:
                        valid = False
                        break
                if valid:
                    self._write_state(
                        dict(transaction["new_state"]), recovering=True
                    )
                    outcome = "new"
                else:
                    self.registry._write_manifest(dict(old_registry))
                    self._write_state(
                        dict(abort_state), recovering=True
                    )
                    outcome = "old"
            elif current == old_registry or self._candidate_quarantine_only(
                current, new_registry, package_id, target_digest
            ):
                if current != old_registry:
                    self.registry._write_manifest(dict(old_registry))
                self._write_state(dict(abort_state), recovering=True)
                outcome = "old"
            else:
                raise PromotionError(
                    "promotion transaction registry diverged from both authenticated states"
                )
        self._clear_transaction()
        return outcome

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            raise PromotionError("promotion state is missing after initialization")
        try:
            document = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PromotionError("promotion state is unreadable or malformed") from exc
        if not isinstance(document, dict) or set(document) != {
            "schema", "serial", "authority_time_floor", "active_bindings",
            "used_receipts", "transitions", "transition_head", "hmac"
        }:
            raise PromotionError("promotion state fields are invalid")
        if document["schema"] != PROMOTION_STATE_SCHEMA:
            raise PromotionError("promotion state schema is invalid")
        if type(document["serial"]) is not int or document["serial"] < 0:
            raise PromotionError("promotion state serial is invalid")
        active_bindings = document["active_bindings"]
        if not isinstance(active_bindings, dict) or len(active_bindings) > MAX_ACTIVE_BINDINGS:
            raise PromotionError("promotion active binding set is invalid or oversized")
        normalized_bindings: dict[str, str] = {}
        for package_id, digest in active_bindings.items():
            normalized_package = _text(package_id, "active package_id", 128)
            normalized_digest = _digest_value(digest, "active package digest")
            if normalized_digest is None:  # pragma: no cover - optional=False above
                raise PromotionError("active package digest is unavailable")
            normalized_bindings[normalized_package] = normalized_digest
        if (
            active_bindings != normalized_bindings
            or list(active_bindings) != sorted(active_bindings)
        ):
            raise PromotionError("promotion active binding set is not canonical")
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
        self._assert_authority_time(document)
        return document

    def _prove_legacy_migration_history(
        self,
        transitions: list[object],
        *,
        serial: int,
        transition_head: str,
        used_receipts: list[object],
        now: float,
        allow_v3_actions: bool,
    ) -> tuple[dict[str, str], list[dict[str, object]]]:
        """Prove complete legacy history and rebuild bounded one-use tombstones."""
        if len(transitions) != serial:
            raise PromotionError(
                "legacy promotion history is incomplete or insufficient; "
                "explicit recovery is required"
            )
        derived_head = "0" * 64
        active_bindings: dict[str, str] = {}
        transition_receipts: list[tuple[str, float]] = []
        seen_transition_receipts: set[str] = set()
        prior_authorized_at = 0.0
        base_fields = {
            "serial", "receipt_id", "action", "package_id",
            "previous_digest", "target_digest", "authorized_at",
        }
        for expected_serial, item in enumerate(transitions, start=1):
            if not isinstance(item, dict):
                raise PromotionError("legacy promotion transition is invalid")
            action = item.get("action")
            if not isinstance(action, str):
                raise PromotionError("legacy promotion transition action is invalid")
            expected_fields = set(base_fields)
            if allow_v3_actions and action in {"abort-promote", "abort-rollback"}:
                expected_fields.add("disposition")
            elif allow_v3_actions and action == "quarantine":
                expected_fields.update({"disposition", "invalid_binding_count"})
            elif action not in _ACTIONS and not (
                allow_v3_actions and action == "migrate-active-bindings"
            ):
                raise PromotionError("legacy promotion transition action is invalid")
            if (
                set(item) != expected_fields
                or type(item.get("serial")) is not int
                or item.get("serial") != expected_serial
            ):
                raise PromotionError("legacy promotion transition fields are invalid")

            receipt_id = _text(item["receipt_id"], "legacy receipt_id", 96)
            if receipt_id in seen_transition_receipts:
                raise PromotionError("legacy promotion receipt history is not one-use")
            seen_transition_receipts.add(receipt_id)
            package_id = _text(item["package_id"], "legacy package_id", 128)
            previous_digest = _digest_value(
                item["previous_digest"], "legacy previous digest", optional=True
            )
            target_digest = _digest_value(
                item["target_digest"], "legacy target digest"
            )
            authorized_at = item["authorized_at"]
            if (
                isinstance(authorized_at, bool)
                or not isinstance(authorized_at, (int, float))
                or not math.isfinite(float(authorized_at))
                or float(authorized_at) <= 0
                or float(authorized_at) < prior_authorized_at
            ):
                raise PromotionError(
                    "legacy promotion transition timestamps are invalid or decreasing"
                )
            stamp = float(authorized_at)
            if now < stamp:
                raise PromotionError(
                    "promotion authority clock rollback predates legacy history"
                )
            prior_authorized_at = stamp

            if action in _ACTIONS:
                if previous_digest != active_bindings.get(package_id):
                    raise PromotionError(
                        "legacy promotion predecessor chain is incomplete"
                    )
                if target_digest is None:  # pragma: no cover - optional=False
                    raise PromotionError("legacy target digest is unavailable")
                active_bindings[package_id] = target_digest
            elif action in {"abort-promote", "abort-rollback"}:
                _text(item["disposition"], "legacy abort disposition", 160)
                if previous_digest != active_bindings.get(package_id):
                    raise PromotionError("legacy abort predecessor chain diverges")
            elif action == "quarantine":
                _text(item["disposition"], "legacy quarantine disposition", 160)
                invalid_count = item["invalid_binding_count"]
                if type(invalid_count) is not int or invalid_count != 1:
                    raise PromotionError(
                        "legacy multi-binding quarantine history requires explicit recovery"
                    )
                if previous_digest != target_digest:
                    raise PromotionError("legacy quarantine binding is invalid")
                if active_bindings.get(package_id) == target_digest:
                    active_bindings.pop(package_id)
            else:
                if previous_digest is not None or target_digest != _digest({
                    "active_bindings": dict(sorted(active_bindings.items()))
                }):
                    raise PromotionError(
                        "legacy active-binding migration proof is invalid"
                    )

            transition_receipts.append((receipt_id, stamp))
            derived_head = hashlib.sha256(
                derived_head.encode("ascii") + _canonical(item)
            ).hexdigest()
        if derived_head != transition_head:
            raise PromotionError("legacy promotion transition chain is invalid")

        tombstones: dict[str, float] = {}
        seen_used_receipts: set[str] = set()
        for item in used_receipts:
            if (
                not isinstance(item, dict)
                or set(item) != {"receipt_id", "expires_at"}
                or isinstance(item.get("expires_at"), bool)
                or not isinstance(item.get("expires_at"), (int, float))
                or not math.isfinite(float(item["expires_at"]))
                or float(item["expires_at"]) <= 0
            ):
                raise PromotionError("legacy used-receipt checkpoint is invalid")
            receipt_id = _text(item.get("receipt_id"), "legacy receipt_id", 96)
            if receipt_id in seen_used_receipts:
                raise PromotionError("legacy used-receipt checkpoint is duplicated")
            seen_used_receipts.add(receipt_id)
            expiry = float(item["expires_at"])
            if expiry >= now:
                tombstones[receipt_id] = expiry

        for receipt_id, authorized_at in transition_receipts:
            expiry = authorized_at + _MAX_RECEIPT_TOMBSTONE_SECONDS
            if expiry >= now:
                tombstones[receipt_id] = max(
                    expiry, tombstones.get(receipt_id, expiry)
                )
        if len(tombstones) > 4096:
            raise PromotionError(
                "legacy one-use receipt proof exceeds the bounded checkpoint"
            )
        return dict(sorted(active_bindings.items())), [
            {"receipt_id": receipt_id, "expires_at": expiry}
            for receipt_id, expiry in sorted(tombstones.items())
        ]

    def _migrate_v3_time_floor(self, document: dict[str, Any]) -> None:
        """Advance authenticated v3 authority onto a nondecreasing time floor."""
        if set(document) != {
            "schema", "serial", "active_bindings", "used_receipts", "transitions",
            "transition_head", "hmac",
        } or document.get("schema") != PROMOTION_STATE_SCHEMA:
            raise PromotionError("legacy v3 promotion state fields are invalid")
        serial = document.get("serial")
        bindings = document.get("active_bindings")
        used = document.get("used_receipts")
        transitions = document.get("transitions")
        head = document.get("transition_head")
        if type(serial) is not int or serial < 0:
            raise PromotionError("legacy v3 promotion serial is invalid")
        if (
            not isinstance(bindings, dict)
            or len(bindings) > MAX_ACTIVE_BINDINGS
            or list(bindings) != sorted(bindings)
            or not isinstance(used, list)
            or len(used) > 4096
            or not isinstance(transitions, list)
            or len(transitions) > 512
        ):
            raise PromotionError("legacy v3 promotion collections are invalid")
        for package_id, digest in bindings.items():
            _text(package_id, "legacy v3 active package_id", 128)
            _digest_value(digest, "legacy v3 active digest")
        if not isinstance(head, str) or len(head) != 64 or any(
            character not in "0123456789abcdef" for character in head
        ):
            raise PromotionError("legacy v3 transition head is invalid")
        if not hmac.compare_digest(
            str(document.get("hmac", "")), self._state_mac(document)
        ):
            raise PromotionError("legacy v3 promotion state HMAC verification failed")
        self._verify_checkpoint(document)
        self._verify_anchor(document)
        now = self._authority_now()
        derived_bindings, tombstones = self._prove_legacy_migration_history(
            transitions,
            serial=serial,
            transition_head=head,
            used_receipts=used,
            now=now,
            allow_v3_actions=True,
        )
        if derived_bindings != dict(bindings):
            raise PromotionError(
                "legacy v3 history cannot prove the active binding set"
            )
        migration = {
            "serial": serial + 1,
            "receipt_id": "authenticated-state-migration-authority-time-floor",
            "action": "migrate-authority-time-floor",
            "package_id": "angerona.detection-promotion-state",
            "previous_digest": None,
            "target_digest": _digest({"authority_time_floor": now}),
            "authorized_at": now,
        }
        if len(tombstones) >= 4096:
            raise PromotionError(
                "legacy one-use receipt proof cannot record its migration"
            )
        tombstones.append({
            "receipt_id": str(migration["receipt_id"]),
            "expires_at": now + _MAX_RECEIPT_TOMBSTONE_SECONDS,
        })
        tombstones.sort(key=lambda item: str(item["receipt_id"]))
        migrated_transitions = list(transitions)
        migrated_transitions.append(migration)
        migrated = {
            "schema": PROMOTION_STATE_SCHEMA,
            "serial": serial + 1,
            "authority_time_floor": now,
            "active_bindings": dict(bindings),
            "used_receipts": tombstones,
            "transitions": migrated_transitions[-512:],
            "transition_head": hashlib.sha256(
                head.encode("ascii") + _canonical(migration)
            ).hexdigest(),
            "hmac": "",
        }
        self._write_state(migrated)
        self._read_state()

    def _migrate_v2_state(self, document: dict[str, Any]) -> None:
        """Authentically advance a provable v2 state to the full-set v3 schema."""
        if set(document) != {
            "schema", "serial", "used_receipts", "transitions",
            "transition_head", "hmac",
        }:
            raise PromotionError("legacy promotion state fields are invalid")
        serial = document.get("serial")
        used_receipts = document.get("used_receipts")
        transitions = document.get("transitions")
        head = document.get("transition_head")
        if type(serial) is not int or serial < 0:
            raise PromotionError("legacy promotion state serial is invalid")
        if (
            not isinstance(used_receipts, list)
            or len(used_receipts) > 4096
            or not isinstance(transitions, list)
            or len(transitions) > 512
        ):
            raise PromotionError("legacy promotion state collections are invalid")
        if (
            not isinstance(head, str)
            or len(head) != 64
            or any(character not in "0123456789abcdef" for character in head)
        ):
            raise PromotionError("legacy promotion transition head is invalid")
        if not hmac.compare_digest(str(document.get("hmac", "")), self._state_mac(document)):
            raise PromotionError("legacy promotion state HMAC verification failed")
        self._verify_checkpoint(document)
        self._verify_anchor(document)
        now = self._authority_now()
        latest, tombstones = self._prove_legacy_migration_history(
            transitions,
            serial=serial,
            transition_head=head,
            used_receipts=used_receipts,
            now=now,
            allow_v3_actions=False,
        )

        registered = self._registry_active_bindings(self.registry.inventory())
        if registered != dict(sorted(latest.items())):
            raise PromotionError(
                "legacy promotion history cannot prove the full registry active set"
            )

        migration = {
            "serial": serial + 1,
            "receipt_id": "authenticated-state-migration-v2-to-v3",
            "action": "migrate-active-bindings",
            "package_id": "angerona.detection-promotion-state",
            "previous_digest": None,
            "target_digest": _digest({"active_bindings": registered}),
            "authorized_at": now,
        }
        if len(tombstones) >= 4096:
            raise PromotionError(
                "legacy one-use receipt proof cannot record its migration"
            )
        tombstones.append({
            "receipt_id": str(migration["receipt_id"]),
            "expires_at": now + _MAX_RECEIPT_TOMBSTONE_SECONDS,
        })
        tombstones.sort(key=lambda item: str(item["receipt_id"]))
        migrated_transitions = list(transitions)
        migrated_transitions.append(migration)
        migrated = {
            "schema": PROMOTION_STATE_SCHEMA,
            "serial": serial + 1,
            "authority_time_floor": now,
            "active_bindings": registered,
            "used_receipts": tombstones,
            "transitions": migrated_transitions[-512:],
            "transition_head": hashlib.sha256(
                head.encode("ascii") + _canonical(migration)
            ).hexdigest(),
            "hmac": "",
        }
        # Serial advancement lets the monotonic anchor distinguish this
        # authenticated schema migration from same-epoch state substitution.
        self._write_state(migrated)
        self._read_state()

    def _verify_checkpoint(self, state: Mapping[str, object]) -> None:
        if not self.checkpoint_path.exists():
            raise PromotionError("promotion checkpoint is missing")
        try:
            checkpoint = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PromotionError("promotion checkpoint is unreadable or malformed") from exc
        expected_fields = {
            "schema", "serial", "transition_head", "state_hmac", "hmac"
        }
        if "authority_time_floor" in state:
            expected_fields.add("authority_time_floor")
        if not isinstance(checkpoint, dict) or set(checkpoint) != expected_fields:
            raise PromotionError("promotion checkpoint fields are invalid")
        if checkpoint["schema"] != PROMOTION_CHECKPOINT_SCHEMA:
            raise PromotionError("promotion checkpoint schema is invalid")
        expected = self._checkpoint_mac(checkpoint)
        if not hmac.compare_digest(str(checkpoint["hmac"]), expected):
            raise PromotionError("promotion checkpoint HMAC verification failed")
        if (
            checkpoint["serial"] != state["serial"]
            or checkpoint.get("authority_time_floor")
            != state.get("authority_time_floor")
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
        if not isinstance(anchor, dict) or set(anchor) not in ({
            "schema", "serial", "transition_head", "state_hmac", "hmac"
        }, {
            "schema", "serial", "authority_time_floor", "transition_head",
            "state_hmac", "hmac",
        }):
            raise PromotionError("promotion monotonic anchor fields are invalid")
        if anchor["schema"] != PROMOTION_ANCHOR_SCHEMA:
            raise PromotionError("promotion monotonic anchor schema is invalid")
        if type(anchor["serial"]) is not int or anchor["serial"] < 0:
            raise PromotionError("promotion monotonic anchor serial is invalid")
        if "authority_time_floor" in anchor:
            floor = anchor["authority_time_floor"]
            if (
                isinstance(floor, bool)
                or not isinstance(floor, (int, float))
                or not math.isfinite(float(floor))
                or float(floor) <= 0
            ):
                raise PromotionError(
                    "promotion monotonic anchor time floor is invalid"
                )
        expected = self._anchor_mac(anchor)
        if not hmac.compare_digest(str(anchor["hmac"]), expected):
            raise PromotionError("promotion monotonic anchor HMAC verification failed")
        return anchor

    def _verify_anchor(self, state: Mapping[str, object]) -> None:
        anchor = self._read_anchor()
        if (
            anchor["serial"] != state["serial"]
            or anchor.get("authority_time_floor")
            != state.get("authority_time_floor")
            or anchor["transition_head"] != state["transition_head"]
            or anchor["state_hmac"] != state["hmac"]
        ):
            raise PromotionError("promotion monotonic rollback or divergence detected")

    def _write_state(
        self, state: dict[str, Any], *, recovering: bool = False
    ) -> None:
        unsigned, checkpoint, anchor = self._authority_documents(state)
        if self.anchor_path.exists():
            prior = self._read_anchor()
            prior_floor = prior.get("authority_time_floor")
            proposed_floor = anchor.get("authority_time_floor")
            if (
                prior_floor is not None
                and proposed_floor is not None
                and float(proposed_floor) < float(prior_floor)
            ):
                raise PromotionError(
                    "promotion monotonic anchor refuses authority clock rollback"
                )
            prior_serial = int(prior["serial"])
            proposed_serial = int(anchor["serial"])
            if not recovering and proposed_serial < prior_serial:
                raise PromotionError("promotion monotonic anchor refuses serial rollback")
            if not recovering and proposed_serial == prior_serial and prior != anchor:
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
        with self._locked():
            self._converge_invalid_active_locked()
            if not self.quality_store.verify(quality_receipt):
                raise PromotionError(
                    "quality receipt is not an exact member of the local ledger"
                )
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
        with self._locked():
            self._converge_invalid_active_locked()
            active_digest, active_record = self._current_active(
                self.registry.inventory(), package_id
            )
            if active_digest is None or active_record is None:
                raise PromotionError(
                    "rollback requires an authoritative active package"
                )
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

    @classmethod
    def _registry_active_bindings(
        cls, inventory: Mapping[str, Any]
    ) -> dict[str, str]:
        bindings: dict[str, str] = {}
        for raw_package_id in inventory:
            package_id = _text(raw_package_id, "registry package_id", 128)
            digest, _record = cls._current_active(inventory, package_id)
            if digest is not None:
                normalized = _digest_value(digest, "registry active digest")
                if normalized is None:  # pragma: no cover - optional=False above
                    raise PromotionError("registry active digest is unavailable")
                bindings[package_id] = normalized
        if len(bindings) > MAX_ACTIVE_BINDINGS:
            raise PromotionError("registry active binding set exceeds runtime capacity")
        return dict(sorted(bindings.items()))

    def authoritative_runtime_bindings(
        self,
    ) -> tuple[tuple[tuple[str, str], ...], int]:
        """Return the full exact governed active set and its activation epoch.

        The active map is HMAC-bound independently of the bounded transition
        history, so an old still-active package cannot age out of restoration.
        Any direct registry activation, retirement, or rollback diverges from
        this map and fails closed.
        """
        with self._locked():
            return self._authoritative_runtime_bindings_locked()

    def _authoritative_runtime_bindings_locked(
        self,
    ) -> tuple[tuple[tuple[str, str], ...], int]:
        state = self._converge_invalid_active_locked()
        serial = int(state["serial"])
        governed = dict(state["active_bindings"])
        registered = self._registry_active_bindings(self.registry.inventory())
        if registered != governed:
            raise PromotionError(
                "registry active set diverges from governed promotion bindings"
            )
        return tuple(sorted(governed.items())), serial

    def _fail_managed_runtime_locked(self, activation_epoch: int) -> None:
        engine = self._runtime_engine
        module = self._runtime_module
        if engine is None:
            return
        if (
            self.__runtime_authority is None
            or self.__runtime_authority_generation
            != getattr(module, "lifecycle_generation", 0)
        ):
            self._refresh_runtime_authority()
        else:
            try:
                engine.assert_active_authority(
                    self.registry, self.__runtime_authority
                )
            except Exception:
                self._refresh_runtime_authority()
        snapshot = engine.snapshot()
        engine.fail_closed_active(
            activation_epoch=max(1, activation_epoch),
            expected_current_epoch=snapshot.active_activation_epoch,
            expected_current_digests=snapshot.active_digests,
            runtime_authority=self.__runtime_authority,
        )

    def _reconcile_managed_runtime_locked(
        self, *, expected_generation: int
    ) -> tuple[tuple[tuple[str, str], ...], int]:
        bindings, activation_epoch = self._authoritative_runtime_bindings_locked()
        engine = self._runtime_engine
        if engine is None:
            raise PromotionError("manager-owned detection runtime is unavailable")
        try:
            self._assert_live_runtime(expected_generation=expected_generation)
            if activation_epoch == 0:
                if bindings or engine.snapshot().active_digests:
                    raise PromotionError(
                        "live detection runtime has content without promotion authority"
                    )
            else:
                engine.sync_active_set_from_registry(
                    self.registry,
                    expected_bindings=dict(bindings),
                    activation_epoch=activation_epoch,
                    runtime_authority=self.__runtime_authority,
                )
            self._assert_live_runtime(expected_generation=expected_generation)
            snapshot = engine.snapshot()
            if (
                snapshot.active_activation_epoch != activation_epoch
                or snapshot.active_digests != tuple(digest for _package, digest in bindings)
            ):
                raise PromotionError(
                    "live detection runtime did not accept the authoritative binding"
                )
            return bindings, activation_epoch
        except Exception:
            self._fail_managed_runtime_locked(activation_epoch)
            raise

    def reconcile_runtime(
        self,
    ) -> tuple[tuple[tuple[str, str], ...], int]:
        """Synchronize only the sealed exact live manager-owned engine."""
        if not self.runtime_managed:
            raise PromotionError("managed runtime reconciliation is unavailable")
        with self._locked():
            generation = self._assert_live_runtime()
            return self._reconcile_managed_runtime_locked(
                expected_generation=generation
            )

    def restore_runtime_for_startup(
        self,
    ) -> tuple[tuple[tuple[str, str], ...], int]:
        """Restore governed rules into the exact module before its first start."""
        if not self.runtime_managed:
            raise PromotionError("managed runtime restoration is unavailable")
        if self._runtime_module is None and self._runtime_manager is None:
            # Explicit root-governed standalone services have no deferred
            # lifecycle and use the normal exact reconciliation contract.
            return self.reconcile_runtime()
        engine = self._runtime_engine
        if engine is None:
            raise PromotionError("manager-owned detection runtime is unavailable")
        restore = getattr(engine, "restore_active_set_for_startup", None)
        if not callable(restore):
            raise PromotionError("detection runtime startup restoration is unavailable")
        with self._locked():
            with self._runtime_lifecycle_guard():
                self._assert_startup_runtime()
                bindings, activation_epoch = (
                    self._authoritative_runtime_bindings_locked()
                )
                if activation_epoch == 0:
                    if bindings or engine.snapshot().active_digests:
                        raise PromotionError(
                            "startup runtime has content without promotion authority"
                        )
                    return bindings, activation_epoch
                self._refresh_runtime_authority(authority_generation=1)
                restore(
                    self.registry,
                    expected_bindings=dict(bindings),
                    activation_epoch=activation_epoch,
                    runtime_authority=self.__runtime_authority,
                )
                self._assert_startup_runtime()
                snapshot = engine.snapshot()
                if (
                    snapshot.active_activation_epoch != activation_epoch
                    or snapshot.active_digests
                    != tuple(digest for _package, digest in bindings)
                ):
                    raise PromotionError(
                        "startup runtime did not accept the authoritative binding"
                    )
                return bindings, activation_epoch

    def fail_closed_runtime(
        self,
        *,
        activation_epoch: int,
        expected_current_epoch: int | None = None,
        expected_current_digests: tuple[str, ...] | None = None,
    ) -> bool:
        """Use the private seal to CAS-clear the exact managed runtime."""
        if not self.runtime_managed or self._runtime_engine is None:
            return False
        with self._locked():
            module = self._runtime_module
            if (
                self.__runtime_authority is None
                or self.__runtime_authority_generation
                != getattr(module, "lifecycle_generation", 0)
            ):
                self._refresh_runtime_authority()
            else:
                try:
                    self._runtime_engine.assert_active_authority(
                        self.registry, self.__runtime_authority
                    )
                except Exception:
                    self._refresh_runtime_authority()
            return bool(self._runtime_engine.fail_closed_active(
                activation_epoch=activation_epoch,
                expected_current_epoch=expected_current_epoch,
                expected_current_digests=expected_current_digests,
                runtime_authority=self.__runtime_authority,
            ))

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

    def _next_transition_state(
        self,
        state: dict[str, Any],
        approval: PromotionReceipt,
        previous_digest: str | None,
        *,
        now: float,
    ) -> tuple[dict[str, Any], int]:
        self._assert_authority_time(state, now=now)
        state = deepcopy(state)
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
        active_bindings = dict(state["active_bindings"])
        if (
            approval.package_id not in active_bindings
            and len(active_bindings) >= MAX_ACTIVE_BINDINGS
        ):
            raise PromotionError("promotion would exceed the 128-rule runtime capacity")
        active_bindings[approval.package_id] = approval.target_digest
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
        state["authority_time_floor"] = max(
            float(state["authority_time_floor"]), now
        )
        state["active_bindings"] = dict(sorted(active_bindings.items()))
        state["used_receipts"] = used
        state["transitions"] = transitions[-512:]
        state["transition_head"] = hashlib.sha256(
            str(state["transition_head"]).encode("ascii") + _canonical(transition)
        ).hexdigest()
        state["hmac"] = self._state_mac(state)
        return state, int(state["serial"])

    def _abort_transition_state(
        self,
        state: Mapping[str, Any],
        approval: PromotionReceipt,
        previous_digest: str | None,
        *,
        now: float,
    ) -> dict[str, Any]:
        """Burn interrupted authority without claiming the candidate active."""
        self._assert_authority_time(state, now=now)
        aborted = deepcopy(dict(state))
        used = [
            item for item in aborted["used_receipts"]
            if float(item["expires_at"]) >= now
        ]
        if not any(item["receipt_id"] == approval.receipt_id for item in used):
            if len(used) >= 4096:
                raise PromotionError(
                    "promotion one-use checkpoint is full of unexpired receipts"
                )
            used.append({
                "receipt_id": approval.receipt_id,
                "expires_at": approval.expires_at,
            })
        transition = {
            "serial": int(aborted["serial"]) + 1,
            "receipt_id": approval.receipt_id,
            "action": f"abort-{approval.action}",
            "package_id": approval.package_id,
            "previous_digest": previous_digest,
            "target_digest": approval.target_digest,
            "authorized_at": now,
            "disposition": "authenticated-predecessor-restored",
        }
        transitions = list(aborted["transitions"])
        transitions.append(transition)
        aborted["serial"] = int(aborted["serial"]) + 1
        aborted["authority_time_floor"] = max(
            float(aborted["authority_time_floor"]), now
        )
        aborted["used_receipts"] = used
        aborted["transitions"] = transitions[-512:]
        aborted["transition_head"] = hashlib.sha256(
            str(aborted["transition_head"]).encode("ascii")
            + _canonical(transition)
        ).hexdigest()
        aborted["hmac"] = self._state_mac(aborted)
        return aborted

    def _quarantine_transition_state(
        self,
        state: Mapping[str, Any],
        invalid_bindings: Mapping[str, str],
        *,
        now: float,
        approval: PromotionReceipt | None,
        disposition: str,
    ) -> dict[str, Any]:
        """Advance authority while removing currently invalid active bindings."""
        self._assert_authority_time(state, now=now)
        if not invalid_bindings:
            raise PromotionError("quarantine convergence requires an invalid binding")
        quarantined = deepcopy(dict(state))
        used = [
            item for item in quarantined["used_receipts"]
            if float(item["expires_at"]) >= now
        ]
        if approval is not None and not any(
            item["receipt_id"] == approval.receipt_id for item in used
        ):
            if len(used) >= 4096:
                raise PromotionError(
                    "promotion one-use checkpoint is full of unexpired receipts"
                )
            used.append({
                "receipt_id": approval.receipt_id,
                "expires_at": approval.expires_at,
            })
        active_bindings = dict(quarantined["active_bindings"])
        for package_id, digest in invalid_bindings.items():
            if active_bindings.get(package_id) == digest:
                active_bindings.pop(package_id)
        package_id, target_digest = next(iter(sorted(invalid_bindings.items())))
        next_serial = int(quarantined["serial"]) + 1
        receipt_id = (
            approval.receipt_id
            if approval is not None
            else f"authority-quarantine-{next_serial}-{target_digest[7:23]}"
        )
        transition = {
            "serial": next_serial,
            "receipt_id": receipt_id,
            "action": "quarantine",
            "package_id": package_id,
            "previous_digest": target_digest,
            "target_digest": target_digest,
            "authorized_at": now,
            "disposition": disposition,
            "invalid_binding_count": len(invalid_bindings),
        }
        transitions = list(quarantined["transitions"])
        transitions.append(transition)
        quarantined["serial"] = next_serial
        quarantined["authority_time_floor"] = max(
            float(quarantined["authority_time_floor"]), now
        )
        quarantined["active_bindings"] = dict(sorted(active_bindings.items()))
        quarantined["used_receipts"] = used
        quarantined["transitions"] = transitions[-512:]
        quarantined["transition_head"] = hashlib.sha256(
            str(quarantined["transition_head"]).encode("ascii")
            + _canonical(transition)
        ).hexdigest()
        quarantined["hmac"] = self._state_mac(quarantined)
        return quarantined

    def _publish_quarantine_locked(
        self,
        state: Mapping[str, Any],
        old_registry: Mapping[str, Any],
        new_registry: Mapping[str, Any],
        invalid_bindings: Mapping[str, str],
        *,
        now: float,
        approval: PromotionReceipt | None = None,
    ) -> dict[str, Any]:
        """Journal and roll forward one authenticated invalid-binding convergence."""
        new_state = self._quarantine_transition_state(
            state,
            invalid_bindings,
            now=now,
            approval=approval,
            disposition="invalid-binding-quarantined",
        )
        recovery_state = self._quarantine_transition_state(
            state,
            invalid_bindings,
            now=now,
            approval=approval,
            disposition="invalid-binding-recovery-completed",
        )
        package_id, target_digest = next(iter(sorted(invalid_bindings.items())))
        self._write_transaction(
            action="quarantine",
            package_id=package_id,
            target_digest=target_digest,
            old_state=state,
            new_state=new_state,
            abort_state=recovery_state,
            old_registry=old_registry,
            new_registry=new_registry,
        )
        self.registry._write_manifest(dict(new_registry))
        self._validate_registry_active_locked(
            dict(new_registry), new_state["active_bindings"]
        )
        self._write_state(new_state)
        self._clear_transaction()
        return new_state

    def _converge_invalid_active_locked(self) -> dict[str, Any]:
        """Remove invalid governed bindings through an authenticated transaction."""
        state = self._read_state()
        with self.registry._locked():
            manifest = self.registry._manifest()
            governed = dict(state["active_bindings"])
            registered = self._registry_active_bindings(manifest["packages"])
            unexpected = {
                package_id: digest for package_id, digest in registered.items()
                if governed.get(package_id) != digest
            }
            if unexpected:
                raise PromotionError(
                    "registry contains active content outside promotion authority"
                )
            invalid: dict[str, str] = {}
            for package_id, digest in governed.items():
                record = (
                    manifest["packages"].get(package_id, {}).get(digest)
                )
                if (
                    not isinstance(record, Mapping)
                    or record.get("state") != "active"
                    or self.registry._trusted_active_locked(
                        manifest,
                        package_id,
                        digest,
                        quarantine_on_failure=False,
                    ) is None
                ):
                    invalid[package_id] = digest
            if not invalid:
                if registered != governed:
                    raise PromotionError(
                        "registry active set diverges from promotion authority"
                    )
                return state
            new_registry = deepcopy(manifest)
            for package_id, digest in invalid.items():
                record = new_registry["packages"].get(package_id, {}).get(digest)
                if isinstance(record, dict):
                    record["state"] = "quarantined"
            return self._publish_quarantine_locked(
                state,
                manifest,
                new_registry,
                invalid,
                now=self._authority_now(),
            )

    def _validate_registry_active_locked(
        self,
        manifest: dict[str, Any],
        bindings: Mapping[str, str],
    ) -> None:
        registered = self._registry_active_bindings(manifest.get("packages", {}))
        if registered != dict(sorted(bindings.items())):
            raise PromotionError("prepared registry active set is not exact")
        for package_id, digest in bindings.items():
            if self.registry._trusted_active_locked(
                manifest,
                package_id,
                digest,
                quarantine_on_failure=False,
            ) is None:
                raise PromotionError(
                    "prepared registry active set failed current trust validation"
                )

    def _commit_transition(
        self,
        state: dict[str, Any],
        approval: PromotionReceipt,
        previous_digest: str | None,
        *,
        now: float,
        expected_runtime_generation: int | None = None,
    ) -> int:
        """Commit one registry/state transition behind an authenticated journal."""
        if expected_runtime_generation is not None:
            self._assert_live_runtime(
                expected_generation=expected_runtime_generation
            )
        next_state, activation_epoch = self._next_transition_state(
            state, approval, previous_digest, now=now
        )
        abort_state = self._abort_transition_state(
            state, approval, previous_digest, now=now
        )
        commit_error: Exception | None = None
        with self.registry._locked():
            if expected_runtime_generation is not None:
                self._assert_live_runtime(
                    expected_generation=expected_runtime_generation
                )
            old_registry = self.registry._manifest()
            new_registry, report = self.registry._prepare_activation_locked(
                old_registry, approval.package_id, approval.target_digest
            )
            if not report.ok:
                invalid = {
                    approval.package_id: approval.target_digest,
                }
                for package_id, digest in state["active_bindings"].items():
                    if self.registry._trusted_active_locked(
                        new_registry,
                        package_id,
                        digest,
                        quarantine_on_failure=False,
                    ) is None:
                        invalid[package_id] = digest
                        record = (
                            new_registry["packages"]
                            .get(package_id, {})
                            .get(digest)
                        )
                        if isinstance(record, dict):
                            record["state"] = "quarantined"
                self._publish_quarantine_locked(
                    state,
                    old_registry,
                    new_registry,
                    invalid,
                    now=now,
                    approval=approval,
                )
                raise PromotionError(
                    "registry activation failed: " + "; ".join(report.errors)
                )
            self._write_transaction(
                action=approval.action,
                package_id=approval.package_id,
                target_digest=approval.target_digest,
                old_state=state,
                new_state=next_state,
                abort_state=abort_state,
                old_registry=old_registry,
                new_registry=new_registry,
            )
            try:
                self.registry._write_manifest(new_registry)
                self._validate_registry_active_locked(
                    new_registry, next_state["active_bindings"]
                )
                self._write_state(next_state)
                self._clear_transaction()
                return activation_epoch
            except Exception as exc:
                commit_error = exc
        try:
            outcome = self._recover_transaction()
        except Exception as recovery_exc:
            raise PromotionError(
                f"promotion commit failed and recovery remains pending: {recovery_exc}"
            ) from commit_error
        if outcome == "new":
            return activation_epoch
        raise PromotionError(
            "promotion commit failed; authenticated predecessor was restored"
        ) from commit_error

    def promote(self, approval: PromotionReceipt) -> PromotionResult:
        activation_epoch = 0
        try:
            with self._locked():
                self._converge_invalid_active_locked()
            runtime_generation = self._assert_live_runtime()
            self.authority.verify(approval)
            current_time = self._authority_now()
            if approval.action != "promote":
                raise PromotionError("promotion requires a promote receipt")
            self._same(approval.policy_digest, self.policy.digest, "current policy")
            with self._locked():
                state = self._converge_invalid_active_locked()
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
                if self.runtime_managed:
                    with self._runtime_commit_guard(runtime_generation):
                        activation_epoch = self._commit_transition(
                            state,
                            approval,
                            active_digest,
                            now=current_time,
                            expected_runtime_generation=runtime_generation,
                        )
                        current, _current_record = self._current_active(
                            self.registry.inventory(), approval.package_id
                        )
                        if current != approval.target_digest:
                            raise PromotionError(
                                "registry did not commit the exact candidate digest"
                            )
                        self._reconcile_managed_runtime_locked(
                            expected_generation=runtime_generation
                        )
                else:
                    activation_epoch = self._commit_transition(
                        state, approval, active_digest, now=current_time
                    )
                    current, _current_record = self._current_active(
                        self.registry.inventory(), approval.package_id
                    )
                    if current != approval.target_digest:
                        raise PromotionError(
                            "registry did not commit the exact candidate digest"
                        )
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
                activation_epoch=activation_epoch,
            )

    def rollback(self, approval: PromotionReceipt) -> PromotionResult:
        activation_epoch = 0
        try:
            with self._locked():
                self._converge_invalid_active_locked()
            runtime_generation = self._assert_live_runtime()
            self.authority.verify(approval)
            current_time = self._authority_now()
            if approval.action != "rollback":
                raise PromotionError("rollback requires a rollback receipt")
            self._same(approval.policy_digest, self.policy.digest, "current policy")
            with self._locked():
                state = self._converge_invalid_active_locked()
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
                if self.runtime_managed:
                    with self._runtime_commit_guard(runtime_generation):
                        activation_epoch = self._commit_transition(
                            state,
                            approval,
                            active_digest,
                            now=current_time,
                            expected_runtime_generation=runtime_generation,
                        )
                        current, _record = self._current_active(
                            self.registry.inventory(), approval.package_id
                        )
                        if current != approval.target_digest:
                            raise PromotionError(
                                "registry did not commit the exact rollback digest"
                            )
                        self._reconcile_managed_runtime_locked(
                            expected_generation=runtime_generation
                        )
                else:
                    activation_epoch = self._commit_transition(
                        state, approval, active_digest, now=current_time
                    )
                    current, _record = self._current_active(
                        self.registry.inventory(), approval.package_id
                    )
                    if current != approval.target_digest:
                        raise PromotionError(
                            "registry did not commit the exact rollback digest"
                        )
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
                activation_epoch=activation_epoch,
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
