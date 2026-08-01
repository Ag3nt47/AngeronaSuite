"""Bounded performance/soak evidence and low-cardinality health evaluation."""
from __future__ import annotations

import math
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Mapping

from angerona.core.atomic_io import replace_with_retry


@dataclass(frozen=True)
class PerformanceBudget:
    max_rss_growth_mb: float = 256.0
    max_thread_growth: int = 24
    max_handle_growth: int = 500
    max_p95_tick_ms: float = 250.0
    max_queue_utilization: float = 0.90
    max_dropped_events: int = 0

    def __post_init__(self) -> None:
        values = asdict(self)
        if any(not math.isfinite(float(value)) or float(value) < 0
               for value in values.values()):
            raise ValueError("performance budgets must be finite and non-negative")
        if self.max_queue_utilization > 1:
            raise ValueError("queue utilization is a ratio between 0 and 1")


@dataclass(frozen=True)
class RuntimeSample:
    timestamp: float
    rss_mb: float
    threads: int
    handles: int
    tick_ms: float
    queue_depth: int = 0
    queue_capacity: int = 1
    dropped_events: int = 0

    def __post_init__(self) -> None:
        if self.queue_capacity < 1 or self.queue_depth < 0:
            raise ValueError("invalid queue sample")
        if self.queue_depth > self.queue_capacity:
            raise ValueError("queue depth exceeds capacity")
        numeric = (
            self.timestamp, self.rss_mb, self.threads, self.handles,
            self.tick_ms, self.queue_depth, self.queue_capacity,
            self.dropped_events,
        )
        if any(not math.isfinite(float(value)) for value in numeric):
            raise ValueError("runtime measurements must be finite")
        if any(float(value) < 0 for value in numeric):
            raise ValueError("runtime measurements cannot be negative")


@dataclass(frozen=True)
class SLOResult:
    passed: bool
    duration_seconds: float
    sample_count: int
    indicators: Mapping[str, float]
    violations: tuple[str, ...]
    unknowns: tuple[str, ...] = ()


class SoakEvidence:
    """Fixed-memory sampler used by 8h/24h/7d external soak runners."""

    def __init__(
        self, budget: PerformanceBudget, *, max_samples: int = 20_160
    ) -> None:
        if not 2 <= int(max_samples) <= 100_000:
            raise ValueError("max_samples must be between 2 and 100000")
        self.budget = budget
        self.max_samples = int(max_samples)
        self._samples: list[RuntimeSample] = []
        self._evicted = 0

    def add(self, sample: RuntimeSample) -> None:
        if self._samples and sample.timestamp < self._samples[-1].timestamp:
            raise ValueError("sample timestamps must not regress")
        self._samples.append(sample)
        if len(self._samples) > self.max_samples:
            # Preserve baseline plus the newest window so growth remains
            # measurable while memory stays fixed.
            self._samples.pop(1)
            self._evicted += 1

    def evaluate(self) -> SLOResult:
        if len(self._samples) < 2:
            return SLOResult(
                False, 0.0, len(self._samples), {},
                (), ("at least two samples are required",),
            )
        first, last = self._samples[0], self._samples[-1]
        tick_values = sorted(item.tick_ms for item in self._samples)
        p95_index = max(0, math.ceil(len(tick_values) * 0.95) - 1)
        # Peak growth is intentional: a resource spike followed by a late drop
        # must not disappear from long-runtime evidence.
        indicators = {
            "rss_growth_mb": max(item.rss_mb for item in self._samples) - first.rss_mb,
            "thread_growth": float(
                max(item.threads for item in self._samples) - first.threads
            ),
            "handle_growth": float(
                max(item.handles for item in self._samples) - first.handles
            ),
            "p95_tick_ms": tick_values[p95_index],
            "max_queue_utilization": max(
                item.queue_depth / item.queue_capacity for item in self._samples
            ),
            "dropped_events_delta": float(sum(
                max(0, current.dropped_events - previous.dropped_events)
                for previous, current in zip(self._samples, self._samples[1:])
            )),
            "samples_evicted": float(self._evicted),
        }
        counter_resets = sum(
            current.dropped_events < previous.dropped_events
            for previous, current in zip(self._samples, self._samples[1:])
        )
        unknowns = (
            (f"dropped-event counter reset {counter_resets} time(s)",)
            if counter_resets else ()
        )
        checks = (
            ("rss_growth_mb", self.budget.max_rss_growth_mb),
            ("thread_growth", self.budget.max_thread_growth),
            ("handle_growth", self.budget.max_handle_growth),
            ("p95_tick_ms", self.budget.max_p95_tick_ms),
            ("max_queue_utilization", self.budget.max_queue_utilization),
            ("dropped_events_delta", self.budget.max_dropped_events),
        )
        violations = tuple(
            f"{name}={indicators[name]:.3f} exceeds {float(limit):.3f}"
            for name, limit in checks if indicators[name] > float(limit)
        )
        return SLOResult(
            not violations and not unknowns,
            max(0.0, last.timestamp - first.timestamp),
            len(self._samples), indicators, violations, unknowns,
        )


@dataclass(frozen=True)
class SoakProfile:
    """A named physical-host soak contract.

    The short ``smoke`` profile validates the runner and evidence plumbing. It
    is never represented as long-duration proof.
    """

    name: str
    duration_seconds: int
    sample_interval_seconds: float
    minimum_coverage_ratio: float = 0.95

    def __post_init__(self) -> None:
        if self.name not in {"smoke", "8h", "24h", "7d"}:
            raise ValueError("unsupported soak profile")
        if not 1 <= int(self.duration_seconds) <= 7 * 24 * 60 * 60:
            raise ValueError("invalid soak duration")
        if not 0.1 <= float(self.sample_interval_seconds) <= 300:
            raise ValueError("invalid soak sample interval")
        if not 0.5 <= float(self.minimum_coverage_ratio) <= 1:
            raise ValueError("invalid soak coverage ratio")


SOAK_PROFILES: Mapping[str, SoakProfile] = {
    "smoke": SoakProfile("smoke", 10, 1.0, 0.80),
    "8h": SoakProfile("8h", 8 * 60 * 60, 15.0),
    "24h": SoakProfile("24h", 24 * 60 * 60, 30.0),
    "7d": SoakProfile("7d", 7 * 24 * 60 * 60, 60.0),
}


def build_soak_report(
    *, profile: SoakProfile, result: SLOResult, completed: bool,
    interrupted: bool = False, clock: Callable[[], float] = time.time,
) -> dict[str, object]:
    """Build a bounded, host-identity-free evidence document."""
    coverage = min(1.0, result.duration_seconds / profile.duration_seconds)
    coverage_ok = coverage >= profile.minimum_coverage_ratio
    passed = bool(completed and coverage_ok and result.passed)
    return {
        "schema_version": 1,
        "profile": profile.name,
        "generated_at_epoch": int(clock()),
        "expected_duration_seconds": profile.duration_seconds,
        "observed_duration_seconds": round(result.duration_seconds, 3),
        "coverage_ratio": round(coverage, 6),
        "sample_count": result.sample_count,
        "completed": bool(completed),
        "interrupted": bool(interrupted),
        "gate_status": "pass" if passed else "fail",
        "indicators": {
            str(key)[:80]: round(float(value), 6)
            for key, value in sorted(result.indicators.items())
        },
        "violations": [str(item)[:512] for item in result.violations[:64]],
        "unknowns": [str(item)[:512] for item in result.unknowns[:64]],
        "limitations": [
            "The smoke profile validates plumbing only; it is not soak proof."
            if profile.name == "smoke" else
            "Evidence covers one local physical-host run and is not a fleet-wide claim.",
            "The report intentionally excludes PID, command line, username, hostname, and paths.",
        ],
    }


def write_soak_report(path: Path, report: Mapping[str, object]) -> None:
    """Atomically write bounded soak evidence on antivirus-inspected hosts."""
    import json

    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(
        report, sort_keys=True, indent=2, allow_nan=False,
    ).encode("utf-8") + b"\n"
    if len(encoded) > 256 * 1024:
        raise ValueError("soak report exceeds byte budget")
    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    )
    try:
        with temporary.open("wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        replace_with_retry(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def sample_current_process(
    *, tick_ms: float, queue_depth: int = 0, queue_capacity: int = 1,
    dropped_events: int = 0, clock: Callable[[], float] = time.time,
) -> RuntimeSample:
    """Capture one portable process sample; unavailable counters stay zero."""
    try:
        import psutil
        process = psutil.Process()
        rss = process.memory_info().rss / (1024 * 1024)
        threads = process.num_threads()
        handles = process.num_handles() if hasattr(process, "num_handles") else 0
    except Exception:
        rss = threads = handles = 0
    return RuntimeSample(
        clock(), float(rss), int(threads), int(handles), float(tick_ms),
        int(queue_depth), int(queue_capacity), int(dropped_events),
    )


def sample_process(
    process_id: int, *, tick_ms: float, queue_depth: int = 0,
    queue_capacity: int = 1, dropped_events: int = 0,
    clock: Callable[[], float] = time.time,
) -> RuntimeSample:
    """Capture one process without reading its identity, paths, or command line."""
    if not 1 <= int(process_id) <= 0xFFFFFFFF:
        raise ValueError("invalid process ID")
    try:
        import psutil

        process = psutil.Process(int(process_id))
        rss = process.memory_info().rss / (1024 * 1024)
        threads = process.num_threads()
        handles = process.num_handles() if hasattr(process, "num_handles") else 0
    except Exception as exc:
        raise RuntimeError("target process is unavailable") from exc
    return RuntimeSample(
        clock(), float(rss), int(threads), int(handles), float(tick_ms),
        int(queue_depth), int(queue_capacity), int(dropped_events),
    )


def structured_health(
    components: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    """Return bounded low-cardinality health; missing evidence is unknown."""
    if len(components) > 256:
        raise ValueError("component cardinality exceeds 256")
    statuses: dict[str, str] = {}
    degraded = unknown = 0
    for raw_name, evidence in components.items():
        name = str(raw_name)[:80]
        state = str(evidence.get("state", "unknown")).lower()
        fresh = evidence.get("fresh")
        if state not in {"healthy", "degraded", "failed", "unknown"}:
            state = "unknown"
        if fresh is False and state == "healthy":
            state = "degraded"
        statuses[name] = state
        degraded += state in {"degraded", "failed"}
        unknown += state == "unknown"
    overall = "unknown" if unknown else ("degraded" if degraded else "healthy")
    return {
        "schema_version": 1, "overall": overall,
        "component_count": len(statuses), "degraded_count": degraded,
        "unknown_count": unknown, "components": statuses,
    }
