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
    RuntimeSample,
    SoakEvidence,
    SoakProfile,
    build_soak_report,
    sample_process,
    write_soak_report,
)

ROOT = Path(__file__).resolve().parents[1]
_MAX_METRICS_BYTES = 64 * 1024


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _read_runtime_metrics(path: Path | None) -> Mapping[str, Any]:
    if path is None:
        return {}
    source = Path(path)
    if source.is_symlink():
        raise ValueError("runtime metrics cannot be a symbolic link")
    target = source.resolve(strict=True)
    if not target.is_file():
        raise ValueError("runtime metrics must be a regular file")
    raw = target.read_bytes()
    if len(raw) > _MAX_METRICS_BYTES:
        raise ValueError("runtime metrics exceed byte budget")
    value = json.loads(
        raw.decode("utf-8", "strict"), parse_constant=_reject_constant,
    )
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
) -> tuple[RuntimeSample, bool]:
    started = time.perf_counter()
    metrics = _read_runtime_metrics(metrics_path)
    depth = _metric_integer(metrics, "queue_depth", 0)
    capacity = _metric_integer(metrics, "queue_capacity", 1)
    dropped = _metric_integer(metrics, "dropped_events", 0)
    observed = sample_process(
        process_id, tick_ms=0, queue_depth=depth,
        queue_capacity=capacity, dropped_events=dropped,
    )
    probe_ms = (time.perf_counter() - started) * 1000
    tick_ms = _metric_number(metrics, "tick_ms", probe_ms)
    return replace(observed, tick_ms=tick_ms), bool(metrics_path)


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
            "Collect bounded process/UI/queue evidence. Long profiles require "
            "an Angerona runtime metrics JSON file."
        ),
    )
    parser.add_argument("--profile", choices=tuple(SOAK_PROFILES), default="smoke")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--metrics-json", type=Path)
    parser.add_argument("--duration-seconds", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        profile = _profile(args.profile, args.duration_seconds)
    except ValueError as exc:
        parser.error(str(exc))
    if profile.name != "smoke" and args.pid is None:
        parser.error("--pid is required for long-duration profiles")
    if profile.name != "smoke" and args.metrics_json is None:
        parser.error("--metrics-json is required for long-duration profiles")

    process_id = os.getpid() if args.pid is None else args.pid
    output = (args.output or (
        ROOT / "analysis" / f"soak-evidence-local-{profile.name}.json"
    )).resolve()
    expected_samples = int(
        profile.duration_seconds / profile.sample_interval_seconds
    ) + 2
    evidence = SoakEvidence(
        PerformanceBudget(), max_samples=max(2, min(100_000, expected_samples)),
    )
    start = time.monotonic()
    deadline = start
    completed = False
    interrupted = False
    metrics_observed = False
    error = ""

    try:
        while True:
            sample, had_metrics = _sample(process_id, args.metrics_json)
            evidence.add(sample)
            metrics_observed = metrics_observed or had_metrics
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
        "process_resources": True,
        "queue_and_ui_runtime_file": metrics_observed,
    }
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
