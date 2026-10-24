"""Benchmark Process Monitor loop bookkeeping with inert process snapshots.

The measured region uses only supplied immutable process snapshots and guarded
entry points. Run reviewed source in a separate, single-purpose interpreter.
This guard is not a sandbox for arbitrary Python or a native-sensor benchmark.
The CLI reads source files and optionally runs Git before the measured region.
Historical comparisons require the same typed process_snapshot fixture seam.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
from contextlib import ExitStack, contextmanager
from types import MappingProxyType, ModuleType
from unittest.mock import patch


class InertBenchmarkViolation(RuntimeError):
    """A reviewed benchmark attempted a forbidden host-facing operation."""


@contextmanager
def _inert_access(processes: int):
    """Guard the measured fixture, including swallowed collector exceptions.

    This temporarily patches process-global entry points. Use a separate,
    single-purpose interpreter, never a running application. This is an
    accidental-access guard for reviewed source, not a Python sandbox.
    """
    from angerona.telemetry import sensors

    first_violation: list[str] = []

    def blocked(operation):
        def reject(*_args, **_kwargs):
            if not first_violation:
                first_violation.append(operation)
            raise InertBenchmarkViolation(f"inert benchmark blocked {operation}")
        return reject

    def check():
        if first_violation:
            raise InertBenchmarkViolation(
                f"inert benchmark blocked {first_violation[0]}"
            )

    fake_psutil = ModuleType("psutil")
    fake_psutil.pids = lambda: range(1, processes + 1)
    for name in ("Process", "process_iter", "net_connections", "_ppid_map"):
        setattr(fake_psutil, name, blocked(f"psutil.{name}"))

    def unavailable(name):
        if name.startswith("__"):
            raise AttributeError(name)
        return blocked(f"psutil.{name}")()

    fake_psutil.__getattr__ = unavailable
    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules, {"psutil": fake_psutil}))
        for name in (
            "process_snapshot", "list_processes",
            "connection_snapshot", "list_connections",
        ):
            stack.enter_context(patch.object(
                sensors, name, blocked(f"sensors.{name}"),
            ))
        # A captured original collector must not return unrelated cached host
        # rows if it is accidentally called instead of the guarded entry point.
        stack.enter_context(patch.object(sensors, "_proc_cache", (0.0, None)))
        stack.enter_context(patch.object(sensors, "_conn_cache", (0.0, None)))
        for owner, name, operation in (
            (subprocess, "Popen", "subprocess.Popen"),
            (threading.Thread, "start", "threading.Thread.start"),
            (socket, "socket", "socket.socket"),
            (socket, "create_connection", "socket.create_connection"),
            (os, "system", "os.system"),
            (os, "popen", "os.popen"),
        ):
            stack.enter_context(patch.object(owner, name, blocked(operation)))
        try:
            yield check
        finally:
            # A collector can legitimately catch Exception for coverage loss.
            # Its refusal must still fail this benchmark rather than time an
            # empty/incomplete inventory and report it as useful work.
            check()


def benchmark(source: str, *, processes: int, polls: int, arguments: int) -> dict:
    if (type(processes) is not int or processes <= 0
            or type(polls) is not int or polls <= 0
            or type(arguments) is not int or arguments < 0):
        raise ValueError("benchmark dimensions must be positive integers; arguments may be zero")

    from angerona.telemetry.sensors import ProcessSnapshot

    namespace = ModuleType("angerona.modules._poll_benchmark")
    rows = tuple(MappingProxyType({
        "pid": index + 1, "ppid": 0, "name": "fixture.exe",
        "exe": r"C:\Windows\fixture.exe", "create_time": 123.0,
        "cmdline": ("fixture.exe", *(
            f"--fixture-{n:03d}" for n in range(arguments)
        )),
    }) for index in range(processes))
    elapsed = []
    fixture_calls = []
    with _inert_access(processes) as check:
        exec(compile(source, "process_monitor_fixture.py", "exec"), namespace.__dict__)
        check()
        for _repeat in range(5):
            observed = 0

            def supplied_snapshot(*_args, **_kwargs):
                nonlocal observed
                observed += 1
                return ProcessSnapshot(rows, time.time(), True, len(rows), 0)

            # Bind the seam the current production loop actually uses. The
            # module-level real collector remains guarded throughout the run.
            namespace.process_snapshot = supplied_snapshot
            module = namespace.ProcessMonitorModule()
            count = 0

            def sleep(_seconds, **_kwargs):
                nonlocal count
                if count >= polls:
                    module.stop()
                count += 1

            module.sleep = sleep
            module.set_health = lambda *_args, **_kwargs: None
            module.mark_cycle_complete = lambda **_kwargs: None
            module.emit = lambda *_args, **_kwargs: None
            started = time.perf_counter()
            module.run()
            elapsed.append((time.perf_counter() - started) * 1000 / polls)
            check()
            if observed != polls or len(module._seen) != processes:
                raise InertBenchmarkViolation(
                    "inert benchmark did not inspect the complete supplied cohort"
                )
            fixture_calls.append(observed)
    return {
        "processes": processes, "polls": polls, "arguments": arguments,
        "median_ms_per_poll": round(statistics.median(elapsed), 6),
        "fixture_snapshot_calls": fixture_calls,
    }


def main() -> None:
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    relative = "src/angerona/modules/process_monitor.py"
    source = (root / relative).read_text(encoding="utf-8")
    sources = {"current": source}
    if args.baseline_ref:
        sources = {
            "before": subprocess.check_output(
                ["git", "show", f"{args.baseline_ref}:{relative}"],
                cwd=root, text=True, encoding="utf-8",
            ),
            "after": source,
        }
    print(json.dumps({
        label: [benchmark(body, processes=600, polls=100, arguments=count) for count in (16, 128)]
        for label, body in sources.items()
    }, indent=2))


if __name__ == "__main__":
    main()
