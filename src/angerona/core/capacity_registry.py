"""Bounded component-capacity declarations and observable pressure accounting."""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from dataclasses import asdict, dataclass
from typing import Iterable

_KINDS = {"queue", "cache", "history", "table", "worker"}


@dataclass(frozen=True)
class CapacitySpec:
    component: str
    kind: str
    capacity: int
    critical_reserve: int = 0

    def __post_init__(self) -> None:
        if not self.component or len(self.component) > 128:
            raise ValueError("invalid component")
        if self.kind not in _KINDS:
            raise ValueError("invalid capacity kind")
        if not 1 <= self.capacity <= 10_000_000:
            raise ValueError("invalid capacity")
        if not 0 <= self.critical_reserve < self.capacity:
            raise ValueError("invalid critical reserve")


@dataclass(frozen=True)
class CapacitySnapshot:
    component: str
    kind: str
    capacity: int
    critical_reserve: int
    current: int
    high_water: int
    accepted: int
    evicted: int
    dropped: int
    critical_dropped: int
    sampled_at: float


class CapacityRegistry:
    """One local source of truth for caps, pressure, drops, and evictions."""

    def __init__(self, specs: Iterable[CapacitySpec], audit_key: bytes) -> None:
        if len(audit_key) < 32:
            raise ValueError("audit key must contain at least 32 bytes")
        items = tuple(specs)
        self._specs = {item.component: item for item in items}
        if len(self._specs) != len(items):
            raise ValueError("duplicate component")
        self._key = bytes(audit_key)
        self._lock = threading.RLock()
        self._state = {
            name: {"current": 0, "high_water": 0, "accepted": 0,
                   "evicted": 0, "dropped": 0, "critical_dropped": 0}
            for name in self._specs
        }

    def observe(
        self, component: str, *, current: int, accepted: int = 0,
        evicted: int = 0, dropped: int = 0, critical_dropped: int = 0,
    ) -> None:
        spec = self._specs.get(component)
        if spec is None:
            raise KeyError(component)
        values = (current, accepted, evicted, dropped, critical_dropped)
        if any(not isinstance(value, int) or value < 0 for value in values):
            raise ValueError("capacity counters must be non-negative integers")
        if current > spec.capacity:
            raise ValueError("reported occupancy exceeds declared capacity")
        if critical_dropped > dropped:
            raise ValueError("critical drops cannot exceed total drops")
        with self._lock:
            state = self._state[component]
            state["current"] = current
            state["high_water"] = max(state["high_water"], current)
            for field, value in (
                ("accepted", accepted), ("evicted", evicted),
                ("dropped", dropped), ("critical_dropped", critical_dropped),
            ):
                state[field] += value

    def snapshots(self, *, now: float | None = None) -> tuple[CapacitySnapshot, ...]:
        stamp = time.time() if now is None else float(now)
        with self._lock:
            return tuple(
                CapacitySnapshot(
                    **asdict(self._specs[name]), **dict(self._state[name]),
                    sampled_at=stamp,
                )
                for name in sorted(self._specs)
            )

    def signed_report(self, *, now: float | None = None) -> bytes:
        payload = {
            "format": "angerona-capacity-report-v1",
            "components": [asdict(item) for item in self.snapshots(now=now)],
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        payload["hmac_sha256"] = hmac.new(
            self._key, canonical, hashlib.sha256
        ).hexdigest()
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def verify_report(self, report: bytes) -> bool:
        try:
            payload = json.loads(report)
            signature = payload.pop("hmac_sha256")
            canonical = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            return hmac.compare_digest(
                signature, hmac.new(self._key, canonical, hashlib.sha256).hexdigest()
            )
        except (TypeError, ValueError, KeyError, json.JSONDecodeError):
            return False
