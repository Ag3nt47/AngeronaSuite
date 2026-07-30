"""Signed, versioned local policy bundles and deterministic dry-run resolution."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from typing import Any, Mapping, Sequence

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    _CRYPTO_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover
    Ed25519PublicKey = None  # type: ignore
    _CRYPTO_ERROR = exc

MAX_BUNDLE_BYTES = 256 * 1024
MAX_SETTINGS = 1000
SCHEMA_VERSION = 1
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")


class PolicyLayer(str, Enum):
    FLEET = "fleet"
    GROUP = "group"
    LOCAL = "local"


class RolloutState(str, Enum):
    STAGED = "staged"
    CANARY = "canary"
    GENERAL = "general"


@dataclass(frozen=True)
class PolicyApproval:
    approver_id: str
    signature: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.approver_id, str)
            or not _IDENTIFIER.fullmatch(self.approver_id)
            or not isinstance(self.signature, str)
            or not _SIGNATURE.fullmatch(self.signature)
        ):
            raise ValueError("policy approval identity or signature is invalid")


@dataclass(frozen=True)
class PolicyBundle:
    bundle_id: str
    version: int
    publisher_id: str
    channel: str
    layer: PolicyLayer
    settings: tuple[tuple[str, Any], ...]
    locked_keys: tuple[str, ...] = ()
    rollout: RolloutState = RolloutState.STAGED
    canary_percent: int = 0
    high_impact: bool = False
    expires_at: float = 0
    approvals: tuple[PolicyApproval, ...] = ()
    signature: str = ""
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "settings", tuple(self.settings))
        object.__setattr__(self, "locked_keys", tuple(self.locked_keys))
        object.__setattr__(self, "approvals", tuple(self.approvals))
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported policy schema")
        if not isinstance(self.layer, PolicyLayer) or not isinstance(self.rollout, RolloutState):
            raise ValueError("layer and rollout must use their typed enums")
        if (
            not isinstance(self.bundle_id, str)
            or not _IDENTIFIER.fullmatch(self.bundle_id)
            or type(self.version) is not int
            or self.version < 1
            or not isinstance(self.publisher_id, str)
            or not _IDENTIFIER.fullmatch(self.publisher_id)
        ):
            raise ValueError("invalid bundle identity/version")
        if not isinstance(self.channel, str) or self.channel not in {
            "configuration",
            "detection",
            "remediation",
        }:
            raise ValueError("unsupported content channel")
        if (
            type(self.high_impact) is not bool
            or type(self.expires_at) not in (int, float)
            or not math.isfinite(float(self.expires_at))
        ):
            raise ValueError("policy impact and expiry types are invalid")
        if len(self.settings) > MAX_SETTINGS or any(
            not isinstance(row, (tuple, list)) or len(row) != 2 for row in self.settings
        ):
            raise ValueError("too many settings")
        keys = [key for key, _ in self.settings]
        if any(not isinstance(key, str) or not key or len(key) > 200 for key in keys) or len(
            keys
        ) != len(set(keys)):
            raise ValueError("setting keys must be unique and bounded")
        if (
            any(not isinstance(key, str) for key in self.locked_keys)
            or len(self.locked_keys) != len(set(self.locked_keys))
            or not set(self.locked_keys) <= set(keys)
        ):
            raise ValueError("only supplied settings may be locked")
        if any(not isinstance(item, PolicyApproval) for item in self.approvals):
            raise ValueError("policy approvals must use the typed schema")
        if not isinstance(self.signature, str) or len(self.signature) > 128:
            raise ValueError("policy publisher signature is invalid")
        if self.rollout is RolloutState.CANARY:
            if type(self.canary_percent) is not int or not 1 <= self.canary_percent <= 99:
                raise ValueError("canary rollout requires 1-99 percent")
        elif type(self.canary_percent) is not int or self.canary_percent != 0:
            raise ValueError("canary percent is valid only for canary rollout")
        if len(self.canonical_signed()) > MAX_BUNDLE_BYTES:
            raise ValueError("policy bundle exceeds 256 KiB")

    def approval_body(self) -> bytes:
        value = asdict(self)
        value.pop("signature")
        value.pop("approvals")
        return _canonical(value)

    def canonical_signed(self) -> bytes:
        value = asdict(self)
        value.pop("signature")
        return _canonical(value)


@dataclass(frozen=True)
class PolicyDiff:
    key: str
    before: Any
    after: Any
    source_bundle: str
    blocked_by_lock: bool = False


@dataclass(frozen=True)
class EffectivePolicy:
    channel: str
    settings: tuple[tuple[str, Any], ...]
    sources: tuple[tuple[str, str], ...]
    locked_keys: tuple[str, ...]
    bundle_ids: tuple[str, ...]


@dataclass(frozen=True)
class PolicyAuditReceipt:
    bundle_id: str
    bundle_version: int
    accepted: bool
    reason: str
    publisher_id: str
    channel: str
    recorded_at: float
    bundle_hash: str
    effective_hash: str
    receipt_hash: str


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("policy must use finite JSON-safe values") from exc


def _unb64(value: str, expected_size: int) -> bytes:
    if not isinstance(value, str) or not _SIGNATURE.fullmatch(value):
        raise ValueError("policy signature encoding is invalid")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != expected_size or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise ValueError("policy signature size or encoding is invalid")
    return raw


def verify_bundle(
    bundle: PolicyBundle,
    trusted_publishers: Mapping[str, bytes],
    trusted_approvers: Mapping[str, bytes],
    *,
    now: float | None = None,
) -> tuple[bool, str]:
    if _CRYPTO_ERROR is not None:
        raise RuntimeError("Ed25519 cryptography support is required") from _CRYPTO_ERROR
    stamp = time.time() if now is None else float(now)
    if not math.isfinite(stamp):
        return False, "policy verification time is invalid"
    if bundle.expires_at <= stamp:
        return False, "bundle expired"
    publisher = trusted_publishers.get(bundle.publisher_id)
    if not isinstance(publisher, bytes) or len(publisher) != 32:
        return False, "publisher is not trusted"
    try:
        Ed25519PublicKey.from_public_bytes(publisher).verify(
            _unb64(bundle.signature, 64), bundle.canonical_signed()
        )
    except Exception:
        return False, "publisher signature invalid"
    if bundle.high_impact:
        identities = {approval.approver_id for approval in bundle.approvals}
        if len(identities) < 2:
            return False, "high-impact policy requires two distinct approvals"
        body = bundle.approval_body()
        valid: set[str] = set()
        for approval in bundle.approvals:
            public = trusted_approvers.get(approval.approver_id)
            if not isinstance(public, bytes) or len(public) != 32:
                continue
            try:
                Ed25519PublicKey.from_public_bytes(public).verify(
                    _unb64(approval.signature, 64), body
                )
                valid.add(approval.approver_id)
            except Exception:
                continue
        if len(valid) < 2:
            return False, "high-impact approvals are invalid or untrusted"
    return True, "verified"


def resolve_effective(
    bundles: Sequence[PolicyBundle], channel: str
) -> tuple[EffectivePolicy, tuple[PolicyDiff, ...]]:
    """Resolve fleet -> group -> local; a higher-authority lock blocks descendants."""
    selected = [bundle for bundle in bundles if bundle.channel == channel]
    by_layer: dict[PolicyLayer, PolicyBundle] = {}
    for bundle in selected:
        current = by_layer.get(bundle.layer)
        if current is None or (bundle.version, bundle.bundle_id) > (
            current.version,
            current.bundle_id,
        ):
            by_layer[bundle.layer] = bundle
    values: dict[str, Any] = {}
    sources: dict[str, str] = {}
    locked: set[str] = set()
    diffs: list[PolicyDiff] = []
    order = (PolicyLayer.FLEET, PolicyLayer.GROUP, PolicyLayer.LOCAL)
    used: list[str] = []
    for layer in order:
        bundle = by_layer.get(layer)
        if bundle is None:
            continue
        used.append(bundle.bundle_id)
        for key, value in sorted(bundle.settings):
            if key in locked:
                diffs.append(PolicyDiff(key, values.get(key), value, bundle.bundle_id, True))
                continue
            before = values.get(key)
            if before != value:
                diffs.append(PolicyDiff(key, before, value, bundle.bundle_id))
            values[key] = value
            sources[key] = bundle.bundle_id
        locked.update(bundle.locked_keys)
    return EffectivePolicy(
        channel,
        tuple(sorted(values.items())),
        tuple(sorted(sources.items())),
        tuple(sorted(locked)),
        tuple(used),
    ), tuple(diffs)


class PolicyManager:
    """Verification gate retaining last-known-good bundles in memory."""

    def __init__(
        self,
        trusted_publishers: Mapping[str, bytes],
        trusted_approvers: Mapping[str, bytes] | None = None,
    ) -> None:
        self.publishers = dict(trusted_publishers)
        self.approvers = dict(trusted_approvers or {})
        self._good: dict[tuple[str, PolicyLayer], PolicyBundle] = {}

    def submit(self, bundle: PolicyBundle, *, now: float | None = None) -> tuple[bool, str]:
        valid, reason = verify_bundle(bundle, self.publishers, self.approvers, now=now)
        if not valid:
            return False, reason
        key = (bundle.channel, bundle.layer)
        current = self._good.get(key)
        if current is not None and bundle.version <= current.version:
            return False, "bundle version is not newer"
        self._good[key] = bundle
        return True, "accepted"

    def effective(self, channel: str, *, now: float | None = None) -> EffectivePolicy:
        stamp = time.time() if now is None else float(now)
        active = [
            bundle
            for bundle in self._good.values()
            if bundle.channel == channel and bundle.expires_at > stamp
        ]
        # Expired new input never overwrites _good; if stored LKG later expires,
        # fail closed to no policy instead of continuing stale authorization.
        return resolve_effective(active, channel)[0]

    def simulate(
        self, bundle: PolicyBundle, *, now: float | None = None
    ) -> tuple[EffectivePolicy, tuple[PolicyDiff, ...]]:
        valid, reason = verify_bundle(bundle, self.publishers, self.approvers, now=now)
        if not valid:
            raise ValueError(reason)
        existing = [
            item
            for key, item in self._good.items()
            if key[0] == bundle.channel and key != (bundle.channel, bundle.layer)
        ]
        return resolve_effective([*existing, bundle], bundle.channel)

    def receipt(
        self,
        bundle: PolicyBundle,
        accepted: bool,
        reason: str,
        *,
        now: float | None = None,
    ) -> PolicyAuditReceipt:
        effective = self.effective(bundle.channel, now=now)
        stamp = time.time() if now is None else float(now)
        core = {
            "bundle_id": bundle.bundle_id,
            "bundle_version": bundle.version,
            "accepted": bool(accepted),
            "reason": reason,
            "publisher_id": bundle.publisher_id,
            "channel": bundle.channel,
            "recorded_at": stamp,
            "bundle_hash": hashlib.sha256(bundle.canonical_signed()).hexdigest(),
            "effective_hash": hashlib.sha256(_canonical(asdict(effective))).hexdigest(),
        }
        return PolicyAuditReceipt(**core, receipt_hash=hashlib.sha256(_canonical(core)).hexdigest())
