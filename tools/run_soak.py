"""Run a bounded local process soak and write privacy-minimized evidence."""
from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from angerona.core.operational_slo import (
    SOAK_PROFILES,
    PerformanceBudget,
    ProcessTreeSampler,
    RuntimeSample,
    SoakEvidence,
    SoakProfile,
    build_soak_report,
    sample_process,
    write_soak_report,
)
from angerona.core.runtime_metrics import validate_metrics

ROOT = Path(__file__).resolve().parents[1]
_MAX_METRICS_BYTES = 64 * 1024


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _read_runtime_metrics(path: Path | None) -> Mapping[str, Any]:
    if path is None:
        return {}
    from angerona.core.source_sandbox import _absolute, _hold_plain_directories, _validate_regular_file
    from angerona.core.executable_trust import _open_sealed
    from angerona.core.engine_transport import EngineError, decode
    target = _absolute(Path(path))
    with _hold_plain_directories(target.parent):
        _validate_regular_file(target)
        if target.stat().st_nlink != 1:
            raise ValueError("runtime metrics must not be linked")
        with _open_sealed(target) as handle:
            raw = handle.read(_MAX_METRICS_BYTES + 1)
    if len(raw) > _MAX_METRICS_BYTES:
        raise ValueError("runtime metrics exceed byte budget")
    try:
        value = decode(raw)
    except EngineError as exc:
        raise ValueError("runtime metrics must be strict JSON without duplicate or non-finite fields") from exc
    if not isinstance(value, dict):
        raise ValueError("runtime metrics must be a JSON object")
    return value


def _metric_number(
    metrics: Mapping[str, Any], name: str, default: float,
) -> float:
    value = metrics.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"runtime metric {name!r} must be numeric")
    return float(value)


def _metric_integer(
    metrics: Mapping[str, Any], name: str, default: int,
) -> int:
    value = metrics.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"runtime metric {name!r} must be an integer")
    return value


def _sample(
    process_id: int, metrics_path: Path | None,
    sampler: ProcessTreeSampler | None = None,
    *, engine_client=None, process_started_at: float | None = None,
) -> tuple[RuntimeSample, bool]:
    metrics = engine_client.metrics() if engine_client is not None else _read_runtime_metrics(metrics_path)
    requested = engine_client is not None or metrics_path is not None
    if requested:
        if process_started_at is None:
            import psutil
            process_started_at = psutil.Process(process_id).create_time()
        validate_metrics(metrics, pid=process_id, process_started_at=process_started_at)
    depth = metrics["queue_depth"] if requested else 0
    capacity = metrics["queue_capacity"] if requested else 1
    dropped = metrics["dropped_events"] if requested else 0
    arguments = dict(tick_ms=0, queue_depth=depth,
                     queue_capacity=capacity, dropped_events=dropped)
    observed = (
        sampler.sample(**arguments) if sampler is not None
        else sample_process(process_id, **arguments)
    )
    # Sampling the target process is not evidence of GUI responsiveness.
    # Headless/unsupplied timing stays absent and is omitted from SLO results.
    tick_ms = metrics["tick_ms"] if requested else None
    return replace(observed, tick_ms=tick_ms), requested


def _profile(name: str, duration_override: int | None) -> SoakProfile:
    selected = SOAK_PROFILES[name]
    if duration_override is None:
        return selected
    if name != "smoke":
        raise ValueError("duration override is allowed only for smoke runs")
    if not 1 <= duration_override <= 300:
        raise ValueError("smoke duration override must be between 1 and 300 seconds")
    return replace(selected, duration_seconds=duration_override)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Collect bounded process-tree CPU/I/O/memory and UI/queue evidence. Long profiles require "
            "an Angerona runtime metrics JSON file."
        ),
    )
    parser.add_argument("--profile", choices=tuple(SOAK_PROFILES), default="smoke")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--include-pid", type=int, action="append", default=[],
                        help="Additional known root, e.g. separately started Ollama; repeatable")
    parser.add_argument("--max-cpu-percent", type=float, default=25.0,
                        help="P95 CPU budget as percent of the host's logical CPU capacity")
    parser.add_argument("--max-write-mb-per-second", type=float, default=10.0)
    metrics_options = parser.add_mutually_exclusive_group()
    metrics_options.add_argument("--metrics-json", type=Path,
                                 help="Production diagnostics/runtime-metrics-PID.json; enable ANGERONA_RUNTIME_METRICS=1")
    metrics_options.add_argument("--engine-metrics", action="store_true",
                                 help="Read authenticated live metrics from the detached protection engine")
    parser.add_argument("--duration-seconds", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        profile = _profile(args.profile, args.duration_seconds)
    except ValueError as exc:
        parser.error(str(exc))
    if profile.name != "smoke" and args.pid is None:
        parser.error("--pid is required for long-duration profiles")
    if profile.name != "smoke" and args.metrics_json is None and not args.engine_metrics:
        parser.error("--metrics-json or --engine-metrics is required for long-duration profiles")

    process_id = os.getpid() if args.pid is None else args.pid
    output = (args.output or (
        ROOT / "analysis" / f"soak-evidence-local-{profile.name}.json"
    )).resolve()
    expected_samples = int(
        profile.duration_seconds / profile.sample_interval_seconds
    ) + 2
    try:
        budget = PerformanceBudget(
            max_p95_cpu_percent=args.max_cpu_percent,
            max_write_mb_per_second=args.max_write_mb_per_second,
        )
        sampler = ProcessTreeSampler(process_id, additional_pids=tuple(args.include_pid))
        process_started_at = sampler._births[0]
        if args.engine_metrics:
            from angerona.core.persistent_engine import EngineClient
            engine_client = EngineClient()
        else:
            engine_client = None
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    except Exception as exc:
        parser.error(f"process sampler initialization failed ({type(exc).__name__})")
    evidence = SoakEvidence(budget, max_samples=max(2, min(100_000, expected_samples)))
    start = time.monotonic()
    deadline = start
    completed = False
    interrupted = False
    metrics_observed = False
    gui_observed = False
    error = ""

    try:
        while True:
            sample, had_metrics = _sample(process_id, args.metrics_json, sampler,
                                          engine_client=engine_client, process_started_at=process_started_at)
            evidence.add(sample)
            metrics_observed = metrics_observed or had_metrics
            gui_observed = gui_observed or sample.tick_ms is not None
            elapsed = time.monotonic() - start
            if elapsed >= profile.duration_seconds:
                completed = True
                break
            deadline += profile.sample_interval_seconds
            time.sleep(max(0.0, deadline - time.monotonic()))
    except KeyboardInterrupt:
        interrupted = True
    except Exception as exc:  # evidence is still written for operator diagnosis
        error = f"{type(exc).__name__}: runtime sampling failed"

    result = evidence.evaluate()
    report = build_soak_report(
        profile=profile, result=result, completed=completed,
        interrupted=interrupted,
    )
    report["metric_coverage"] = {
        "process_resources": result.sample_count > 0,
        "process_tree": True,
        "explicit_additional_roots": len(args.include_pid),
        "queue_and_ui_runtime_file": metrics_observed,
        "runtime_metrics_source": "authenticated-engine" if args.engine_metrics else "file" if args.metrics_json else "none",
        "gui_latency": "measured" if gui_observed else "not-applicable-headless" if metrics_observed else "unavailable",
    }
    report["limitations"].extend([
        "Process-tree polling excludes processes born and exited between samples, "
        "and detached services unless their PID is supplied with --include-pid.",
        "CPU percentage is normalized to host logical CPU capacity; native handles "
        "on Windows and open file descriptors on Unix are not interchangeable.",
        "Read/write bytes are native process I/O counters, not a measurement of "
        "physical disk traffic; summed RSS can include shared pages more than once.",
        "P95 latency/CPU covers retained samples; peak growth, write rate and "
        "observed dropped-event deltas persist across sample eviction.",
    ])
    if metrics_observed and not gui_observed:
        report["limitations"].append("The measured engine is headless; GUI latency is not applicable and no GUI SLO was asserted.")
    if error:
        report["gate_status"] = "fail"
        report["runner_error"] = error
    if not metrics_observed:
        report["limitations"].append(
            "Queue depth, dropped-event count, and GUI tick latency were not supplied; "
            "smoke evidence covers runner plumbing and process counters only."
        )
    write_soak_report(output, report)
    print(f"{report['gate_status']}: {output}")
    return 0 if report["gate_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
