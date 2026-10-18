"""Compare inert entropy work with a reviewed Git baseline; no sensors/GPU run.

Run with the repository Python. The default baseline is a5cb7a3. Only the
stdlib entropy function, result type, worker and literal queue constants are
loaded from each source; optional accelerator imports are never executed.
Each idle worker runs in a disposable child with a finite parent timeout.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import queue
import statistics
import subprocess
import sys
import threading
import time
from types import ModuleType
from typing import Callable, List


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = "src/angerona/core/gpu_entropy.py"


def _load_inert(source: str, label: str) -> ModuleType:
    """Load the actual relevant implementations without optional/native imports."""
    module = ModuleType(label)
    sys.modules[label] = module
    module.__dict__.update({
        "queue": queue, "threading": threading, "time": time,
        "dataclass": dataclass, "Callable": Callable, "List": List,
        "_TORCH_OK": False, "_NP_OK": False,
    })
    selected = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "_entropy_python":
            selected.append(node)
        elif isinstance(node, ast.ClassDef) and node.name in {"EntropyResult", "EntropyWorker"}:
            selected.append(node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id in {"MAX_BATCH", "FLUSH_MS", "MAX_STR_LEN", "_QUEUE_CAP"}:
                module.__dict__[node.target.id] = ast.literal_eval(node.value)
    exec(compile(ast.Module(body=selected, type_ignores=[]), label, "exec"), module.__dict__)
    return module


def _idle_child() -> None:
    payload = json.load(sys.stdin)
    module = _load_inert(payload["source"], "entropy_idle_fixture")
    entered = threading.Event()
    observed = [0]

    class CountingQueue(queue.Queue):
        def get(self, block=True, timeout=None):
            observed[0] += 1
            entered.set()
            return super().get(block=block, timeout=timeout)

    worker = module.EntropyWorker()
    worker._queue = CountingQueue()
    worker._mode = "python"
    delivered = threading.Event()
    results = []

    def collect(result):
        results.append(result)
        delivered.set()

    worker.on_result(collect)
    worker.start()
    if not entered.wait(2):
        raise RuntimeError("idle fixture did not enter its queue wait")
    started = time.perf_counter()
    time.sleep(payload["idle_seconds"])
    elapsed = time.perf_counter() - started
    idle_calls = observed[0]
    worker.submit("inert-entropy-fixture")
    if not delivered.wait(2) or results[0].strings != ["inert-entropy-fixture"]:
        raise RuntimeError("idle fixture did not deliver its first inert arrival")
    # Worker is a daemon and owns only its private queue. Process exit cleans
    # it up; the parent kills/reaps this entire child if any step stops returning.
    print(json.dumps({"idle_get_calls": idle_calls,
                      "observed_seconds": round(elapsed, 4), "first_arrival_delivered": True}))


def _source_at(ref: str) -> tuple[str, str]:
    commit = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", ref + "^{commit}"],
        cwd=ROOT, capture_output=True, text=True, check=True, timeout=10,
    ).stdout.strip()
    source = subprocess.run(
        ["git", "show", commit + ":" + SOURCE_PATH], cwd=ROOT,
        capture_output=True, text=True, encoding="utf-8", check=True, timeout=10,
    ).stdout
    return commit, source


def _idle_measure(source: str, idle_seconds: float) -> dict:
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--_idle-child"], cwd=ROOT,
        input=json.dumps({"source": source, "idle_seconds": idle_seconds}),
        capture_output=True, text=True, encoding="utf-8", check=True, timeout=15,
    )
    return json.loads(completed.stdout)


def _cpu_measure(before, after, *, items: int, unique: int, samples: int) -> dict:
    values = [f"host-{index % unique:04d}.example-telemetry.test" for index in range(items)]
    old_result, new_result = before(values), after(values)
    if old_result != new_result:
        raise RuntimeError("optimized entropy differs from baseline output")
    old_times, new_times = [], []
    for sample in range(samples):
        pair = ((before, old_times), (after, new_times))
        # Alternate ordering to reduce warmup/order bias in wall-time samples.
        for callback, timings in (pair if sample % 2 == 0 else pair[::-1]):
            started = time.perf_counter()
            result = callback(values)
            timings.append((time.perf_counter() - started) * 1000)
            if result != old_result:
                raise RuntimeError("repeated entropy output differs from baseline")
    old, new = statistics.median(old_times), statistics.median(new_times)
    return {"items": items, "unique": unique, "samples": samples,
            "before_median_ms": round(old, 3), "after_median_ms": round(new, 3),
            "speedup": round(old / new, 3), "outputs_equal": True}


def main() -> None:
    if sys.argv[1:] == ["--_idle-child"]:
        _idle_child()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="a5cb7a3")
    parser.add_argument("--idle-seconds", type=float, default=0.3)
    parser.add_argument("--idle-runs", type=int, default=3)
    parser.add_argument("--samples", type=int, default=9)
    parser.add_argument("--items", type=int, default=4096)
    args = parser.parse_args()
    if (not 0.05 <= args.idle_seconds <= 2 or not 1 <= args.idle_runs <= 9
            or not 3 <= args.samples <= 31 or not 64 <= args.items <= 4096):
        parser.error("Require idle-seconds [0.05,2], idle-runs [1,9], samples [3,31], items [64,4096]")
    commit, baseline = _source_at(args.baseline)
    current = (ROOT / SOURCE_PATH).read_text(encoding="utf-8")
    old = _load_inert(baseline, "entropy_before_fixture")._entropy_python
    new = _load_inert(current, "entropy_after_fixture")._entropy_python
    report = {
        "method": "Actual Git/worktree implementations; inert stdlib-only work; local medians, not host throughput guarantees",
        "baseline_ref": args.baseline, "baseline_commit": commit,
        "current_source_sha256": hashlib.sha256(current.encode("utf-8")).hexdigest(),
        "idle_child_timeout_seconds": 15,
        "idle": {label: [_idle_measure(source, args.idle_seconds) for _ in range(args.idle_runs)]
                 for label, source in (("before", baseline), ("after", current))},
        "cpu": {"duplicate_batch_64_unique": _cpu_measure(
                    old, new, items=args.items, unique=64, samples=args.samples),
                "all_unique_batch": _cpu_measure(
                    old, new, items=args.items, unique=args.items, samples=args.samples)},
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
