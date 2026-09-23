"""Bounded performance/soak evidence and low-cardinality health evaluation."""
from __future__ import annotations

import math
import os
import secrets
import time
from collections import OrderedDict
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
    max_p95_cpu_percent: float = 25.0
    max_write_mb_per_second: float = 10.0

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
    tick_ms: float | None
    queue_depth: int = 0
    queue_capacity: int = 1
    dropped_events: int = 0
    cpu_seconds: float | None = None
    read_bytes: int | None = None
    write_bytes: int | None = None
    process_count: int = 1
    logical_cpus: int = 1
    resource_unknowns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.queue_capacity < 1 or self.queue_depth < 0:
            raise ValueError("invalid queue sample")
        if self.queue_depth > self.queue_capacity:
            raise ValueError("queue depth exceeds capacity")
        numeric = (
            self.timestamp, self.rss_mb, self.threads, self.handles,
            self.queue_depth, self.queue_capacity,
            self.dropped_events,
            self.process_count, self.logical_cpus,
        )
        numeric += tuple(value for value in (
            self.tick_ms, self.cpu_seconds, self.read_bytes, self.write_bytes,
        ) if value is not None)
        if any(not math.isfinite(float(value)) for value in numeric):
            raise ValueError("runtime measurements must be finite")
        if any(float(value) < 0 for value in numeric):
            raise ValueError("runtime measurements cannot be negative")
        if self.logical_cpus < 1 or self.process_count < 1:
            raise ValueError("invalid process or CPU count")


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
        self._peaks: dict[str, float] = {}
        self._drops_delta = 0
        self._counter_resets = 0
        self._unknowns: set[str] = set()
        self._cpu_rates: list[float] = []
        self._max_write_rate = 0.0
        self._read_delta = self._write_delta = 0

    def add(self, sample: RuntimeSample) -> None:
        if self._samples and sample.timestamp < self._samples[-1].timestamp:
            raise ValueError("sample timestamps must not regress")
        for field in ("rss_mb", "threads", "handles", "process_count"):
            self._peaks[field] = max(self._peaks.get(field, 0), getattr(sample, field))
        self._peaks["queue"] = max(
            self._peaks.get("queue", 0), sample.queue_depth / sample.queue_capacity,
        )
        self._unknowns.update(str(item)[:120] for item in sample.resource_unknowns[:16])
        if self._samples:
            previous = self._samples[-1]
            self._drops_delta += max(0, sample.dropped_events - previous.dropped_events)
            self._counter_resets += sample.dropped_events < previous.dropped_events
            duration = sample.timestamp - previous.timestamp
            for field in ("cpu_seconds", "read_bytes", "write_bytes"):
                before, after = getattr(previous, field), getattr(sample, field)
                if before is None or after is None:
                    continue
                if after < before:
                    self._unknowns.add(f"{field} counter regressed")
                    continue
                delta = after - before
                if field == "cpu_seconds" and duration > 0:
                    self._cpu_rates.append(delta / duration / sample.logical_cpus * 100)
                    if len(self._cpu_rates) > self.max_samples:
                        self._cpu_rates.pop(0)
                elif field == "read_bytes":
                    self._read_delta += delta
                elif field == "write_bytes":
                    self._write_delta += delta
                    if duration > 0:
                        self._max_write_rate = max(
                            self._max_write_rate, delta / duration / (1024 * 1024),
                        )
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
        tick_values = sorted(item.tick_ms for item in self._samples if item.tick_ms is not None)
        p95_index = max(0, math.ceil(len(tick_values) * 0.95) - 1)
        # Peak growth is intentional: a resource spike followed by a late drop
        # must not disappear from long-runtime evidence.
        indicators = {
            "rss_growth_mb": self._peaks["rss_mb"] - first.rss_mb,
            "peak_rss_mb": self._peaks["rss_mb"],
            "thread_growth": self._peaks["threads"] - first.threads,
            "handle_growth": self._peaks["handles"] - first.handles,
            "peak_process_count": self._peaks["process_count"],
            "max_queue_utilization": self._peaks["queue"],
            "dropped_events_delta": float(self._drops_delta),
            "samples_evicted": float(self._evicted),
        }
        if tick_values:
            indicators["p95_tick_ms"] = tick_values[p95_index]
        if self._cpu_rates:
            rates = sorted(self._cpu_rates)
            indicators["p95_cpu_percent"] = rates[max(0, math.ceil(len(rates) * .95) - 1)]
        if any(item.write_bytes is not None for item in self._samples):
            indicators["max_write_mb_per_second"] = self._max_write_rate
            indicators["write_mb"] = self._write_delta / (1024 * 1024)
        if any(item.read_bytes is not None for item in self._samples):
            indicators["read_mb"] = self._read_delta / (1024 * 1024)
        unknowns = tuple(sorted(self._unknowns)) + (
            (f"dropped-event counter reset {self._counter_resets} time(s)",)
            if self._counter_resets else ()
        )
        checks = (
            ("rss_growth_mb", self.budget.max_rss_growth_mb),
            ("thread_growth", self.budget.max_thread_growth),
            ("handle_growth", self.budget.max_handle_growth),
            ("p95_tick_ms", self.budget.max_p95_tick_ms),
            ("max_queue_utilization", self.budget.max_queue_utilization),
            ("dropped_events_delta", self.budget.max_dropped_events),
            ("p95_cpu_percent", self.budget.max_p95_cpu_percent),
            ("max_write_mb_per_second", self.budget.max_write_mb_per_second),
        )
        violations = tuple(
            f"{name}={indicators[name]:.3f} exceeds {float(limit):.3f}"
            for name, limit in checks if name in indicators and indicators[name] > float(limit)
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


class ProcessTreeSampler:
    """On-demand process-tree counters bound to the original root generations.

    No background polling, process names, command lines, or paths are read.
    Explicit additional roots cover an independently started Ollama daemon or
    protection service. Trees are deduplicated. Departed children do not cause
    cumulative CPU/I/O counters to decrease. Processes which start and exit
    entirely between observations are outside this polling measurement.
    """

    MAX_PROCESSES = 4096

    def __init__(
        self, process_id: int, *, additional_pids: tuple[int, ...] = (),
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        import psutil

        ids = tuple(dict.fromkeys((process_id, *additional_pids)))
        if len(ids) > 32 or any(
            isinstance(pid, bool) or not isinstance(pid, int) or not 1 <= pid <= 0xFFFFFFFF
            for pid in ids
        ):
            raise ValueError("invalid process ID or more than 32 process roots")
        self._roots = tuple(psutil.Process(pid) for pid in ids)
        self._births = tuple(float(proc.create_time()) for proc in self._roots)
        if any(not math.isfinite(birth) or birth <= 0 for birth in self._births):
            raise RuntimeError("process root identity is unavailable")
        self._logical_cpus = max(1, int(psutil.cpu_count() or 1))
        self._clock = clock
        self._previous: OrderedDict[
            tuple[int, float], tuple[float | None, int | None, int | None]
        ] = OrderedDict()
        self._totals = [0.0, 0, 0]

    def sample(
        self, *, tick_ms: float = 0, queue_depth: int = 0,
        queue_capacity: int = 1, dropped_events: int = 0,
    ) -> RuntimeSample:
        processes = {}
        unknowns: set[str] = set()
        for root, birth in zip(self._roots, self._births):
            if not root.is_running() or float(root.create_time()) != birth:
                raise RuntimeError("original process root exited or was replaced")
            processes[root.pid] = root
            try:
                for child in root.children(recursive=True):
                    if len(processes) >= self.MAX_PROCESSES:
                        unknowns.add("process tree exceeds collection limit")
                        break
                    processes.setdefault(child.pid, child)
            except Exception:
                unknowns.add("process tree enumeration incomplete")
        rss = threads = handles = 0
        observed: dict[tuple[int, float], tuple[float | None, int | None, int | None]] = {}
        measured = [False, False, False]
        for process in processes.values():
            try:
                birth = float(process.create_time())
                if not math.isfinite(birth) or birth <= 0 or not process.is_running():
                    raise RuntimeError("process identity changed")
                identity = (process.pid, birth)
                with process.oneshot():
                    memory = int(process.memory_info().rss)
                    thread_count = int(process.num_threads())
                    handle_reader = getattr(process, "num_handles", None)
                    if handle_reader is None:
                        handle_reader = getattr(process, "num_fds", None)
                    handle_count = int(handle_reader()) if handle_reader else 0
                    if handle_reader is None:
                        unknowns.add("native handles/file descriptors unavailable")
                    cpu: float | None = None
                    read_bytes: int | None = None
                    write_bytes: int | None = None
                    try:
                        times = process.cpu_times()
                        cpu = float(times.user + times.system)
                    except Exception:
                        unknowns.add("process CPU counters incomplete")
                    try:
                        io = process.io_counters()
                        read_bytes, write_bytes = int(io.read_bytes), int(io.write_bytes)
                    except Exception:
                        unknowns.add("process disk I/O counters incomplete")
                # A PID reused during the reads cannot contribute another
                # process's counters under the previous generation's identity.
                if not process.is_running():
                    raise RuntimeError("process exited during sampling")
                rss += memory
                threads += thread_count
                handles += handle_count
                current = (cpu, read_bytes, write_bytes)
                previous = self._previous.get(identity, (0.0, 0, 0))
                for index, (before, after) in enumerate(zip(previous, current)):
                    if after is None:
                        continue
                    measured[index] = True
                    if before is None:
                        unknowns.add("process resource counter coverage resumed")
                    elif after < before:
                        unknowns.add("process resource counter regressed")
                    else:
                        self._totals[index] += after - before
                observed[identity] = current
            except Exception:
                unknowns.add("process resource collection incomplete")
        if not observed:
            raise RuntimeError("process tree resource counters unavailable")
        for identity, counters in observed.items():
            self._previous[identity] = counters
            self._previous.move_to_end(identity)
        while len(self._previous) > self.MAX_PROCESSES * 4:
            self._previous.popitem(last=False)
            unknowns.add("process counter history exceeded collection limit")
        return RuntimeSample(
            self._clock(), rss / (1024 * 1024), threads, handles, float(tick_ms),
            queue_depth, queue_capacity, dropped_events,
            float(self._totals[0]) if measured[0] else None,
            int(self._totals[1]) if measured[1] else None,
            int(self._totals[2]) if measured[2] else None,
            len(observed), self._logical_cpus, tuple(sorted(unknowns)),
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
