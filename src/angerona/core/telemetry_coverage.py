"""Bounded, honest telemetry continuity accounting.

This module does not claim that a sensor observed everything.  It accounts only
for sequence numbers explicitly supplied by a sensor and reports missing or
stale sequence coverage as degraded.  Events without sequence metadata are
visible as ``unknown`` rather than being treated as healthy.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional

from angerona.core.eventbus import Event


@dataclass(frozen=True)
class SensorCoverage:
    sensor_id: str
    status: str
    first_sequence: Optional[int]
    last_sequence: Optional[int]
    accepted: int
    missing: int
    duplicates: int
    regressions: int
    unsequenced: int
    last_observed_at: Optional[float]
    reason: str


@dataclass
class _MutableCoverage:
    first_sequence: Optional[int] = None
    last_sequence: Optional[int] = None
    accepted: int = 0
    missing: int = 0
    duplicates: int = 0
    regressions: int = 0
    unsequenced: int = 0
    last_observed_at: Optional[float] = None


class TelemetryCoverageAccountant:
    """Track per-sensor sequence continuity with bounded memory.

    ``max_sensors`` is a cardinality/performance budget.  On overflow, the least
    recently observed sensor is evicted and the eviction counter is exposed.
    The class performs no I/O and subscriber handling is O(1).
    """

    def __init__(
        self,
        *,
        max_sensors: int = 256,
        stale_after_s: float = 300.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_sensors < 1:
            raise ValueError("max_sensors must be positive")
        if stale_after_s <= 0:
            raise ValueError("stale_after_s must be positive")
        self._max_sensors = max_sensors
        self._stale_after_s = stale_after_s
        self._clock = clock
        self._states: "OrderedDict[str, _MutableCoverage]" = OrderedDict()
        self._evicted_sensors = 0
        self._lock = threading.Lock()

    @property
    def evicted_sensors(self) -> int:
        with self._lock:
            return self._evicted_sensors

    def observe(
        self,
        sensor_id: str,
        sequence: Optional[int],
        *,
        observed_at: Optional[float] = None,
    ) -> None:
        sensor_id = str(sensor_id).strip()
        if not sensor_id:
            raise ValueError("sensor_id must not be empty")
        if sequence is not None and (isinstance(sequence, bool) or not isinstance(sequence, int)):
            raise TypeError("sequence must be an integer or None")
        if sequence is not None and sequence < 0:
            raise ValueError("sequence must be non-negative")
        now = self._clock() if observed_at is None else float(observed_at)

        with self._lock:
            state = self._states.get(sensor_id)
            if state is None:
                if len(self._states) >= self._max_sensors:
                    self._states.popitem(last=False)
                    self._evicted_sensors += 1
                state = _MutableCoverage()
                self._states[sensor_id] = state
            else:
                self._states.move_to_end(sensor_id)

            state.last_observed_at = now
            if sequence is None:
                state.unsequenced += 1
                return
            if state.last_sequence is None:
                state.first_sequence = state.last_sequence = sequence
                state.accepted += 1
            elif sequence == state.last_sequence:
                state.duplicates += 1
            elif sequence < state.last_sequence:
                state.regressions += 1
            else:
                state.missing += max(0, sequence - state.last_sequence - 1)
                state.last_sequence = sequence
                state.accepted += 1

    def observe_event(self, event: Event) -> None:
        """EventBus subscriber using ``sensor_id`` and ``sensor_sequence`` details."""
        details: Mapping[str, object] = event.details or {}
        sensor_id = details.get("sensor_id", event.module)
        raw_sequence = details.get("sensor_sequence")
        sequence: Optional[int]
        if raw_sequence is None:
            sequence = None
        elif (
            isinstance(raw_sequence, bool)
            or not isinstance(raw_sequence, int)
            or raw_sequence < 0
        ):
            sequence = None
        else:
            sequence = raw_sequence
        # Freshness is based on local receipt time. Sensor-provided/event time may
        # be skewed and must not make a live sensor falsely stale or future-fresh.
        self.observe(str(sensor_id), sequence)

    def snapshot(self, *, now: Optional[float] = None) -> dict[str, SensorCoverage]:
        current = self._clock() if now is None else float(now)
        result: dict[str, SensorCoverage] = {}
        with self._lock:
            items = list(self._states.items())
        for sensor_id, state in items:
            if state.last_sequence is None:
                status, reason = "unknown", "sensor has not supplied sequence metadata"
            elif state.missing or state.regressions:
                status, reason = "degraded", "sequence gaps or regressions observed"
            elif state.last_observed_at is None or current - state.last_observed_at > self._stale_after_s:
                status, reason = "degraded", "sensor telemetry is stale"
            else:
                status, reason = "healthy", "no sequence discontinuity observed"
            result[sensor_id] = SensorCoverage(
                sensor_id=sensor_id,
                status=status,
                first_sequence=state.first_sequence,
                last_sequence=state.last_sequence,
                accepted=state.accepted,
                missing=state.missing,
                duplicates=state.duplicates,
                regressions=state.regressions,
                unsequenced=state.unsequenced,
                last_observed_at=state.last_observed_at,
                reason=reason,
            )
        return result

    def save_checkpoint(self, path: Path, key: bytes) -> None:
        """Atomically persist authenticated sequence continuity across restart."""
        if len(key) < 32:
            raise ValueError("checkpoint key must contain at least 32 bytes")
        path = Path(path)
        with self._lock:
            payload = {
                "format": "angerona-telemetry-coverage-v1",
                "max_sensors": self._max_sensors,
                "stale_after_s": self._stale_after_s,
                "evicted_sensors": self._evicted_sensors,
                "states": [
                    {"sensor_id": sensor_id, **vars(state)}
                    for sensor_id, state in self._states.items()
                ],
            }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        wrapper = {
            "payload": payload,
            "hmac_sha256": hmac.new(key, canonical, hashlib.sha256).hexdigest(),
        }
        encoded = json.dumps(
            wrapper, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        with open(temporary, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    @classmethod
    def load_checkpoint(
        cls, path: Path, key: bytes, *, clock: Callable[[], float] = time.time
    ) -> "TelemetryCoverageAccountant":
        """Restore only a complete, authenticated, bounded checkpoint."""
        if len(key) < 32:
            raise ValueError("checkpoint key must contain at least 32 bytes")
        try:
            wrapper = json.loads(Path(path).read_bytes())
            payload = wrapper["payload"]
            canonical = json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(wrapper["hmac_sha256"], expected):
                raise ValueError("telemetry checkpoint authentication failed")
            if payload["format"] != "angerona-telemetry-coverage-v1":
                raise ValueError("unsupported telemetry checkpoint")
            result = cls(
                max_sensors=int(payload["max_sensors"]),
                stale_after_s=float(payload["stale_after_s"]),
                clock=clock,
            )
            states = payload["states"]
            if not isinstance(states, list) or len(states) > result._max_sensors:
                raise ValueError("telemetry checkpoint exceeds sensor bound")
            with result._lock:
                result._evicted_sensors = int(payload["evicted_sensors"])
                if result._evicted_sensors < 0:
                    raise ValueError("invalid checkpoint eviction count")
                for item in states:
                    sensor_id = str(item["sensor_id"]).strip()
                    if not sensor_id or sensor_id in result._states:
                        raise ValueError("invalid or duplicate checkpoint sensor")
                    values = {
                        field: item[field] for field in (
                            "first_sequence", "last_sequence", "accepted",
                            "missing", "duplicates", "regressions",
                            "unsequenced", "last_observed_at",
                        )
                    }
                    for field in (
                        "accepted", "missing", "duplicates", "regressions",
                        "unsequenced",
                    ):
                        if not isinstance(values[field], int) or values[field] < 0:
                            raise ValueError("invalid checkpoint counter")
                    for field in ("first_sequence", "last_sequence"):
                        value = values[field]
                        if value is not None and (
                            not isinstance(value, int) or value < 0
                        ):
                            raise ValueError("invalid checkpoint sequence")
                    result._states[sensor_id] = _MutableCoverage(**values)
            return result
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid or incomplete telemetry checkpoint") from exc
