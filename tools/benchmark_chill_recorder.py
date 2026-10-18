"""Measure real offline recorder idle queue calls against a reviewed Git baseline.

Each finite child AST-loads only the bounded queue and async recorder classes.
An inert memory sink replaces SQLite/DLQ I/O. Results measure this component's
queue waits and signed delivery, never whole-app CPU/RAM or detection coverage.
"""
from __future__ import annotations

import argparse
import ast
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = "src/angerona/core/storage.py"
sys.path.insert(0, str(ROOT / "src"))


def measure(source: str, idle_seconds: float) -> dict:
    from angerona.core.background_pacing import get_pacing_controller
    from angerona.core.eventbus import BusAuthority, Event, Severity
    from angerona.core.storage import AsyncRecorderMetrics, BatchRecordResult

    controller = get_pacing_controller()
    controller.set_chill_active(True)
    tree = ast.parse(source, filename=SOURCE_PATH)
    selected = [node for node in tree.body if (
        isinstance(node, ast.ClassDef) and node.name in {"_BoundedSimpleQueue", "AsyncFlightRecorder"}
    ) or (
        isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                                            and target.id == "_RECORDER_WAKE" for target in node.targets)
    )]
    assert sum(isinstance(node, ast.ClassDef) for node in selected) == 2
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    extracted = ast.fix_missing_locations(ast.Module(body=[future, *selected], type_ignores=[]))
    namespace = {"__name__": "angerona_recorder_benchmark", "threading": threading,
                 "time": time, "queue": queue, "dataclasses": dataclasses,
                 "Event": Event, "AsyncRecorderMetrics": AsyncRecorderMetrics,
                 "BatchRecordResult": BatchRecordResult}
    exec(compile(extracted, SOURCE_PATH, "exec"), namespace)

    class Sink:
        authority = BusAuthority(b"b" * 32)

        def __init__(self):
            self.events = []
            self.arrived = threading.Event()

        def record_batch_bus(self, events):
            self.events.extend(events)
            self.arrived.set()
            return BatchRecordResult(len(events), 0)

        def _route_batch_to_dlq(self, events):
            raise AssertionError("unexpected overflow in bounded delivery fixture")

        def _route_to_dlq(self, event):
            raise AssertionError("unexpected synchronous I/O fallback")

    sink = Sink()
    worker = namespace["AsyncFlightRecorder"](sink)
    counts = {"primary": 0, "overflow": 0}
    entries = {name: threading.Event() for name in counts}
    lock = threading.Lock()

    def observe(pending, name):
        original = pending.get

        def counted(*args, **kwargs):
            with lock:
                counts[name] += 1
            entries[name].set()
            return original(*args, **kwargs)
        pending.get = counted

    observe(worker._queue, "primary")
    observe(worker._overflow_queue, "overflow")
    try:
        assert worker.start()
        assert all(entered.wait(2.0) for entered in entries.values()), "worker did not enter queue wait"
        with lock:
            initial = dict(counts)
        began = time.perf_counter()
        threading.Event().wait(idle_seconds)
        elapsed = time.perf_counter() - began
        with lock:
            idle_calls = dict(counts)
        repeats = {name: idle_calls[name] - initial[name] for name in counts}
        first_published = time.perf_counter()
        for index in range(10):
            worker.submit(Event("benchmark", f"event-{index}", Severity.CRITICAL))
        assert sink.arrived.wait(2.0), "evidence did not wake the idle recorder promptly"
        arrival_ms = (time.perf_counter() - first_published) * 1000
        for index in range(10, 14):
            worker.submit(Event("benchmark", f"event-{index}", Severity.HIGH))
        stopping = time.perf_counter()
        assert worker.stop(2.0), "recorder did not drain within its finite stop budget"
        stop_ms = (time.perf_counter() - stopping) * 1000
        ordered = [event.message for event in sink.events] == [f"event-{i}" for i in range(14)]
        signed = all(sink.authority.verify(event) for event in sink.events)
        assert ordered and signed
        metrics = worker.metrics()
        assert metrics.accepted == metrics.persisted == 14
        assert metrics.queue_depth == metrics.overflow_queue_depth == metrics.dlq_failures == 0
        return {"idle_seconds_measured": elapsed,
                "queue_get_calls_including_initial_wait": idle_calls,
                "additional_empty_waits": repeats,
                "first_delivery_ms": arrival_ms, "stop_and_drain_ms": stop_ms,
                "ordered_events": len(sink.events), "order_verified": ordered,
                "hmac_verified": signed, "unfinished_workers": 0,
                "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest()}
    finally:
        assert worker.stop(2.0)
        controller.set_chill_active(False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="706a819")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--idle-seconds", type=float, default=0.35)
    parser.add_argument("--output", type=Path, default=ROOT / ".tmp" / "chill-recorder-benchmark.json")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        request = json.load(sys.stdin)
        print(json.dumps(measure(request["source"], request["idle_seconds"])))
        return 0
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", args.baseline):
        parser.error("baseline must be a reviewed Git commit hash")
    if not 1 <= args.samples <= 10 or not 0.1 <= args.idle_seconds <= 2.0:
        parser.error("samples must be 1..10 and idle-seconds 0.1..2.0")
    baseline = subprocess.run(["git", "show", f"{args.baseline}:{SOURCE_PATH}"],
                              cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                              check=True, timeout=10).stdout
    current = (ROOT / SOURCE_PATH).read_text(encoding="utf-8")
    rows = []
    for sample in range(args.samples):
        for label, source in (("baseline", baseline), ("current_chill", current)):
            environment = dict(os.environ)
            environment["ANGERONA_DATA"] = str(ROOT / ".tmp" / "chill-recorder-benchmark" / str(os.getpid()))
            child = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--child"],
                                   input=json.dumps({"source": source, "idle_seconds": args.idle_seconds}),
                                   capture_output=True, text=True, encoding="utf-8", check=True,
                                   timeout=10, cwd=ROOT, env=environment)
            rows.append({"sample": sample + 1, "version": label, **json.loads(child.stdout)})
    report = {"schema": 1, "baseline": args.baseline, "samples": args.samples,
              "idle_seconds_requested": args.idle_seconds,
              "scope": "Actual isolated async recorder + bounded queues, inert memory sink. No SQL, sensors, Ollama, CPU/RAM percentages or whole-app efficiency claims.",
              "results": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "trials": len(rows),
                      "idle_queue_get_totals": [sum(row["queue_get_calls_including_initial_wait"].values()) for row in rows],
                      "additional_empty_wait_totals": [sum(row["additional_empty_waits"].values()) for row in rows],
                      "signed_ordered_delivery": all(row["order_verified"] and row["hmac_verified"] for row in rows)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
