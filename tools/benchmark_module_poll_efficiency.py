"""Benchmark Process Monitor loop bookkeeping with inert process snapshots.

No sensors, threads, network, response actions or inference are started.
Use --baseline-ref to load a reviewed historical source directly from Git.
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from types import ModuleType, SimpleNamespace
from unittest.mock import patch


def benchmark(source: str, *, processes: int, polls: int, arguments: int) -> dict:
    namespace = ModuleType("angerona.modules._poll_benchmark")
    exec(compile(source, "process_monitor_fixture.py", "exec"), namespace.__dict__)
    rows = [{
        "pid": index + 1, "ppid": 0, "name": "fixture.exe",
        "exe": r"C:\Windows\fixture.exe", "create_time": 123.0,
        "cmdline": ["fixture.exe", *[f"--fixture-{n:03d}" for n in range(arguments)]],
    } for index in range(processes)]
    namespace.list_processes = lambda **_kwargs: rows
    elapsed = []
    for _repeat in range(5):
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
        with patch.dict(sys.modules, {"psutil": SimpleNamespace(pids=lambda: range(1, processes + 1))}):
            started = time.perf_counter()
            module.run()
            elapsed.append((time.perf_counter() - started) * 1000 / polls)
        assert len(module._seen) == processes
    return {
        "processes": processes, "polls": polls, "arguments": arguments,
        "median_ms_per_poll": round(statistics.median(elapsed), 6),
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
