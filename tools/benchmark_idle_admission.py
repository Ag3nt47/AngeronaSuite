"""Inert Detection Runtime admission benchmarks and static Chill cadence audit.

Does not start any module worker, sensor, inference, native defense or GUI.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time
import tracemalloc
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]


def _load_runtime(source: str, label: str):
    name = f"angerona.modules._idle_benchmark_{label}"
    module = ModuleType(name)
    sys.modules[name] = module
    exec(compile(source, name, "exec"), module.__dict__)
    return module


def _measure(runtime):
    from angerona.core.eventbus import Event

    events = [Event("fixture", "observed process", ts=100.0, details={
        "event_id": f"fixture-{index}", "cmdline": "--fixture " * 100,
    }) for index in range(3000)]
    elapsed = []
    for _ in range(3):
        module = runtime.DetectionRuntimeModule()
        started = time.perf_counter()
        for event in events:
            module._on_event(event)
        elapsed.append((time.perf_counter() - started) * 1000)
    retained = len(module.engine._claimed_ids) + len(module.engine._source_cursors)
    normalization_elapsed = []
    for _ in range(3):
        started = time.perf_counter()
        for index, event in enumerate(events[:1000]):
            runtime.DetectionRuntimeEngine._queue_event(event, source_cursor=index)
        normalization_elapsed.append((time.perf_counter() - started) * 1000)
    payload = [["x" * 4096] * 32] * 32
    oversized = Event("fixture", "nested AI transcript", details={"nested": payload})
    times = []
    for _ in range(3):
        engine = runtime.DetectionRuntimeEngine()
        started = time.perf_counter()
        assert not engine.submit(oversized)
        times.append((time.perf_counter() - started) * 1000)
    tracemalloc.start()
    engine = runtime.DetectionRuntimeEngine()
    assert not engine.submit(oversized)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "unconfigured_3000_events_median_ms": round(statistics.median(elapsed), 3),
        "unconfigured_retained_identity_entries": retained,
        "configured_1000_normalizations_median_ms": round(statistics.median(normalization_elapsed), 3),
        "oversize_nested_median_ms": round(statistics.median(times), 3),
        "oversize_nested_peak_kib": round(peak / 1024, 1),
    }


def _health_measure(source: str | None):
    from angerona.core import module_base
    from angerona.core.process_egress_lease import EgressAuditBatch
    from angerona.modules.process_egress_guard import ProcessEgressGuardModule

    saved = module_base._health_callsite
    if source is not None:
        tree = ast.parse(source)
        declaration = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                           and node.name == "_health_callsite")
        globals_copy = dict(vars(module_base))
        exec(compile(ast.Module(body=[declaration], type_ignores=[]), "health_fixture", "exec"), globals_copy)
        module_base._health_callsite = globals_copy["_health_callsite"]
    try:
        module = ProcessEgressGuardModule()
        module.emit = lambda *_args, **_kwargs: None
        batch = EgressAuditBatch((), False, 0, "fixture missing provider")
        module._report_coverage(batch)  # warm source manifest
        assert module.health_evidence["source_provenance"] == "verified-loaded-implementation"
        elapsed = []
        for _ in range(3):
            started = time.perf_counter()
            for _index in range(200):
                module._report_coverage(batch)
            elapsed.append((time.perf_counter() - started) * 1000 / 200)
        return round(statistics.median(elapsed), 4)
    finally:
        module_base._health_callsite = saved


def cadence_audit():
    from angerona.core.chill_mode import CHILL_PAUSED_MODULES, CHILL_THROTTLE_FLOORS

    prior = json.loads((ROOT / "analysis/round-20260921/module-audit.json").read_text(encoding="utf-8"))
    rows = []
    for item in prior["modules"]:
        path = ROOT / item["source"]
        tree = ast.parse(path.read_text(encoding="utf-8"))
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == item["class"])
        constants = {}
        for node in [*tree.body, *cls.body]:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and node.value is not None:
                        try:
                            value = ast.literal_eval(node.value)
                        except (ValueError, TypeError, SyntaxError):
                            continue
                        if isinstance(value, (int, float)) and not isinstance(value, bool):
                            constants[target.id] = value
        calls = []
        for method in cls.body:
            if not isinstance(method, ast.FunctionDef) or method.name == "self_test":
                continue
            for call in ast.walk(method):
                if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                    continue
                if call.func.attr != "sleep" or not call.args or ast.unparse(call.func.value) != "self":
                    continue
                expr = ast.unparse(call.args[0])
                try:
                    seconds = ast.literal_eval(call.args[0])
                except (ValueError, TypeError, SyntaxError):
                    seconds = constants.get(expr.removeprefix("self."))
                calls.append({"method": method.name, "line": call.lineno, "expression": expr,
                              "literal_seconds": seconds})
        source = path.read_text(encoding="utf-8")
        markers = [name for name in ("process_iter", "net_connections", "list_processes",
                   "list_connections", "subprocess.run", "subprocess.Popen", "read_text",
                   "sqlite3.connect", ".subscribe(") if name in source]
        name = item["name"]
        rows.append({"name": name, "source": item["source"], "class": item["class"],
                     "default_enabled": item["default_enabled"],
                     "chill_policy": "parked" if name in CHILL_PAUSED_MODULES else "live",
                     "chill_floor": CHILL_THROTTLE_FLOORS.get(name, 1.0),
                     "sleep_calls": calls, "source_work_markers": markers})
    assert len(rows) == 84
    return {"scope": "Static declared policy; runtime settings/platform/usage gates still apply. "
                     "Literal sleeps exclude work duration; unresolved expressions remain explicit. "
                     "Source markers include helpers and do not prove work on every cycle.",
            "modules": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", default="7b7b264")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cadence-output", type=Path)
    args = parser.parse_args()
    rel = "src/angerona/modules/detection_runtime.py"
    before = subprocess.check_output(["git", "show", f"{args.baseline_ref}:{rel}"], cwd=ROOT,
                                     text=True, encoding="utf-8")
    health_before = subprocess.check_output(
        ["git", "show", f"{args.baseline_ref}:src/angerona/core/module_base.py"],
        cwd=ROOT, text=True, encoding="utf-8",
    )
    baseline = _load_runtime(before, "before")
    current = _load_runtime((ROOT / rel).read_text(encoding="utf-8"), "after")
    from angerona.core.eventbus import Event, Severity

    for index in range(128):
        event = Event("fixture", "unchanged normalized identity", Severity(index % 5), 100.0, {
            "event_id": f"event-{index}", "cmdline": "x" * (index * 79),
            "nested": [None, True, False, index, 1.25, {"snow": "\u2603"}],
        })
        previous = baseline.DetectionRuntimeEngine._queue_event(event, source_cursor=index)
        latest = current.DetectionRuntimeEngine._queue_event(event, source_cursor=index)
        assert vars(previous) == vars(latest)
    results = {"before": _measure(baseline), "after": _measure(current),
               "accepted_fixture_identities_equal": 128}
    results["before"]["degraded_health_median_ms"] = _health_measure(health_before)
    results["after"]["degraded_health_median_ms"] = _health_measure(None)
    print(json.dumps(results, indent=2))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    if args.cadence_output:
        args.cadence_output.parent.mkdir(parents=True, exist_ok=True)
        args.cadence_output.write_text(json.dumps(cadence_audit(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
