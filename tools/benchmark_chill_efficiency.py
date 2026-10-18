"""Compare actual Chill scheduling policies offline using a virtual clock.

No sensors, native services, model, or Qt windows start. This reports requested
work/rest budgets and scheduled callbacks, not measured CPU/RAM savings.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
PACING = "src/angerona/core/background_pacing.py"
DASHBOARD = "src/angerona/gui/main_window.py"
BASELINE = "706a819247af882fcc953f26290b0507ea854ca8"


def _baseline_source(ref: str, path: str) -> str:
    return subprocess.run(
        ["git", "show", f"{ref}:{path}"], cwd=ROOT, capture_output=True,
        text=True, encoding="utf-8", check=True, timeout=15,
    ).stdout


def _load(source: str, label: str, *, dashboard: bool = False) -> ModuleType:
    module = ModuleType(label)
    sys.modules[label] = module
    tree = ast.parse(source)
    if dashboard:
        # The pure timing function has no GUI imports or application state.
        tree = ast.Module(body=[node for node in tree.body
                               if isinstance(node, ast.FunctionDef)
                               and node.name == "_dashboard_refresh_plan"], type_ignores=[])
    exec(compile(tree, label, "exec"), module.__dict__)
    return module


def _work(module, *, chill: bool, item_ms: float, batch: int) -> dict:
    now = [0.0]
    controller = module.BackgroundPacingController(clock=lambda: now[0])
    setter = getattr(controller, "set_chill_active", None)
    if setter is not None:
        setter(chill)
    pacer = module.RoutineWorkPacer(controller, clock=lambda: now[0])
    rest = burst = longest = 0.0
    pauses = 0
    completed_items = []
    for completed in range(1, 65):
        now[0] += item_ms / 1000
        burst += item_ms
        completed_items.append(completed)
        delay = pacer.pause_seconds(completed, batch_size=batch)
        if delay:
            assert 0 < delay <= 0.05, "unbounded checkpoint pause"
            pauses += 1
            longest = max(longest, burst)
            burst = 0
            rest += delay
            now[0] += delay
            pacer.resume()
    assert completed_items == list(range(1, 65)), "work was dropped or reordered"
    return {"completed_items": len(completed_items), "item_ms": item_ms,
            "batch_size": batch, "pauses": pauses,
            "requested_rest_ms": round(rest * 1000, 3),
            "virtual_total_ms": round(now[0] * 1000, 3),
            "longest_work_burst_ms": round(max(longest, burst), 3),
            "resource_multiplier": controller.multiplier()}


def _dashboard(module) -> dict:
    rows = {}
    for mode, quiet in (("Full", False), ("Chill", True)):
        for state, visible, active in (("foreground", True, True),
                                       ("background", True, False),
                                       ("hidden", False, False)):
            plan = module._dashboard_refresh_plan(quiet, visible=visible, active=active)
            period, status, panels, posture, flow = plan
            rows[f"{mode}_{state}"] = {
                "dashboard_ms": period,
                "scheduled_dashboard_callbacks_per_hour": 3_600_000 / period,
                "status_ms": period * status, "panels_ms": period * panels,
                "posture_ms": period * posture, "flow_ms": period * flow,
            }
    return rows


def report() -> dict:
    sources = {name: {path: (_baseline_source(BASELINE, path) if name == "before"
                            else (ROOT / path).read_text(encoding="utf-8"))
                      for path in (PACING, DASHBOARD)} for name in ("before", "after")}
    modules = {name: _load(value[PACING], f"chill_benchmark_{name}")
               for name, value in sources.items()}
    work = []
    for item_ms in (0.5, 5.0, 20.0, 100.0):
        for batch in (8, 64):
            row = {name: {mode: _work(module, chill=quiet, item_ms=item_ms, batch=batch)
                          for mode, quiet in (("Full", False), ("Chill", True))}
                   for name, module in modules.items()}
            assert row["before"]["Full"] == row["after"]["Full"]
            assert row["after"]["Chill"]["requested_rest_ms"] > row["before"]["Chill"]["requested_rest_ms"]
            work.append(row)
    dashboard = {name: _dashboard(_load(value[DASHBOARD], f"chill_dashboard_{name}", dashboard=True))
                 for name, value in sources.items()}
    for state in ("foreground", "background", "hidden"):
        assert dashboard["before"][f"Full_{state}"] == dashboard["after"][f"Full_{state}"]
        assert dashboard["after"][f"Chill_{state}"]["dashboard_ms"] > dashboard["before"][f"Chill_{state}"]["dashboard_ms"]
    controller = modules["after"].BackgroundPacingController()
    controller.set_chill_active(True)
    normal_interval = controller.interval(3)
    assert normal_interval == 3, "live routine interval inherited optional Chill floor"
    optional_interval = controller.optional_interval(3)
    assert optional_interval == 24
    controller.set_enabled(False)
    assert controller.batch_delay() == 0.05, "adaptive opt-out overrode explicit Chill"
    controller.set_chill_active(False)
    assert controller.batch_delay() == 0 and controller.optional_interval(3) == 3
    return {
        "method": "Actual baseline/current scheduling code with virtual work costs; no physical CPU/RAM or detection efficacy claim.",
        "baseline_commit": BASELINE,
        "source_sha256_normalized": {name: {path: hashlib.sha256(text.encode()).hexdigest()
                                           for path, text in value.items()}
                                     for name, value in sources.items()},
        "dashboard": dashboard, "work_profiles": work,
        "verification": {"all_items_completed_in_order": True,
                         "full_scheduling_matches_baseline": True,
                         "live_interval_unchanged_by_chill": True,
                         "chill_survives_adaptive_opt_out": True,
                         "manual_full_restores_optional_budget": True},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(report(), indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    main()
