"""Compare Black Box inspector overhead against an owned, inert process.

Reads only this benchmark process's native thread/memory/connection/file tables.
Runtime files use a private temporary directory; no suite sensors are started.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
from types import ModuleType

import psutil


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def measure(source: str, *, seconds: float, selected: str | None) -> dict:
    namespace = ModuleType("_blackbox_idle_benchmark")
    namespace.__file__ = str(ROOT / "blackbox_recorder.py")
    sys.modules[namespace.__name__] = namespace
    exec(compile(source, namespace.__file__, "exec"), namespace.__dict__)
    namespace.find_angerona_pid = os.getpid
    workers = [namespace.ThreadStateWorker(), namespace.MemoryProfilerWorker(),
               namespace.ConfigDriftWorker()]
    counts = {"threads": 0, "memory": 0, "resources": 0}
    for key, worker in zip(counts, workers):
        original = worker._collect

        def collect(original=original, key=key):
            counts[key] += 1
            return original()

        worker._collect = collect
        if hasattr(worker, "set_active"):
            worker.set_active(key == selected)
    started, cpu_started = time.perf_counter(), time.process_time()
    try:
        for worker in workers:
            worker.start()
        time.sleep(seconds)
    finally:
        for worker in workers:
            worker.stop()
        for worker in workers:
            if not worker.wait(15000):
                # Keep ownership until an in-flight native call returns.
                worker.wait()
                raise RuntimeError("native inspector exceeded the shutdown budget")
    return {"selected_tab": selected, "collections": counts,
            "wall_seconds": round(time.perf_counter() - started, 4),
            "process_cpu_seconds": round(time.process_time() - cpu_started, 6)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref")
    parser.add_argument("--seconds", type=float, default=6)
    args = parser.parse_args()
    if not 0.2 <= args.seconds <= 60:
        parser.error("--seconds must be between 0.2 and 60")
    source = (ROOT / "blackbox_recorder.py").read_text(encoding="utf-8")
    sources = {}
    if args.baseline_ref:
        sources["before_hidden"] = subprocess.check_output(
            ["git", "show", f"{args.baseline_ref}:blackbox_recorder.py"],
            cwd=ROOT, text=True, encoding="utf-8",
        )
    sources.update(after_hidden=source, after_memory_tab=source)
    (ROOT / ".tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / ".tmp", prefix="blackbox-idle-") as directory:
        os.environ["ANGERONA_DATA"] = directory
        os.environ["ANGERONA_DIAG_DIR"] = str(Path(directory) / "diagnostics")
        report = {key: measure(body, seconds=args.seconds,
                               selected="memory" if key == "after_memory_tab" else None)
                  for key, body in sources.items()}
    report["environment"] = {"platform": platform.system(), "python": platform.python_version(),
                             "logical_cpus": psutil.cpu_count(),
                             "ram_bytes": psutil.virtual_memory().total}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
