"""Bounded performance/soak evidence and low-cardinality health evaluation."""
from __future__ import annotations

import math
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Mapping


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
        if any(float(value) < 0 for value in (
            self.rss_mb, self.threads, self.handles, self.tick_ms,
            self.dropped_events,
        )):
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
        indicators = {
            "rss_growth_mb": last.rss_mb - first.rss_mb,
            "thread_growth": float(last.threads - first.threads),
            "handle_growth": float(last.handles - first.handles),
            "p95_tick_ms": tick_values[p95_index],
            "max_queue_utilization": max(
                item.queue_depth / item.queue_capacity for item in self._samples
            ),
            "dropped_events_delta": float(
                last.dropped_events - first.dropped_events
            ),
            "samples_evicted": float(self._evicted),
        }
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
            not violations,
            max(0.0, last.timestamp - first.timestamp),
            len(self._samples), indicators, violations,
        )


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
