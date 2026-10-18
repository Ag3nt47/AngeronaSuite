"""Offline scheduling evidence and complete source inventory; no sensors start.

Resource profiles and work costs use virtual time. They demonstrate policy,
not physical hardware throughput or detection effectiveness.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from angerona.core.background_pacing import (  # noqa: E402
    BackgroundPacingController, RoutineWorkPacer,
)


def source_inventory() -> dict:
    modules, windows = [], []
    for area, rows in (("modules", modules), ("gui", windows)):
        for path in sorted((ROOT / "src/angerona" / area).glob("*.py")):
            # Git checkouts may translate newlines. Fingerprint normalized text
            # so public LF blobs and a Windows checkout have the same identity.
            source = path.read_text(encoding="utf-8").encode("utf-8")
            tree = ast.parse(source, filename=str(path))
            calls = [node.func.attr for node in ast.walk(tree)
                     if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
            constructors = [node.func.id for node in ast.walk(tree)
                            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
            row = {"source": path.relative_to(ROOT).as_posix(),
                   "sha256": hashlib.sha256(source).hexdigest()}
            if area == "modules":
                classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
                           and any((isinstance(base, ast.Name) and base.id == "BaseModule")
                                   or (isinstance(base, ast.Attribute) and base.attr == "BaseModule")
                                   for base in node.bases)]
                row.update({"module_classes": [node.name for node in classes],
                            "declared_self_tests": sum(
                                isinstance(item, ast.FunctionDef) and item.name == "self_test"
                                for node in classes for item in node.body),
                            "cooperative_checkpoints": calls.count("background_checkpoint"),
                            "routine_interval_calls": calls.count("background_interval"),
                            "sleep_calls": calls.count("sleep")})
            else:
                row.update({"presentation_timers": constructors.count("PresentationTimer"),
                            "qt_timers": constructors.count("QTimer"),
                            "single_shot_calls": calls.count("singleShot")})
            rows.append(row)
    return {"scope": "UTF-8 text hashes normalize newlines. Static call sites include helpers and inactive paths. "
            "Counts are coverage inventory, not proof of runtime cadence or an optimized module.",
            "module_source_files": len(modules),
            "module_classes": sum(len(row["module_classes"]) for row in modules),
            "gui_source_files": len(windows), "modules": modules, "gui": windows}


def simulate_profile(cpu: float, memory: float, available_mib: int, item_ms: float) -> dict:
    now = [0.0]
    controller = BackgroundPacingController(clock=lambda: now[0])
    for second in (0, 2, 4):
        now[0] = float(second)
        controller.report_host(cpu)
        controller.report_memory(memory, available_mib * 1024 * 1024)
    snapshot = controller.snapshot()
    pacer = RoutineWorkPacer(controller, clock=lambda: now[0])
    rest = burst = longest = 0.0
    pauses = 0
    for completed in range(1, 65):
        now[0] += item_ms / 1000
        burst += item_ms
        delay = pacer.pause_seconds(completed, batch_size=8)
        if delay:
            longest = max(longest, burst)
            burst = 0.0
            rest += delay
            pauses += 1
            now[0] += delay
            pacer.resume()
    # Feed healthy observations to exercise real hysteresis, rather than
    # assuming stale observations count as a recovered host.
    for _ in range(5):
        now[0] += controller.RECOVERY_SECONDS
        controller.report_host(10)
        controller.report_memory(40, 2048 * 1024 * 1024)
    assert controller.multiplier() == 1, "healthy resource samples did not restore pace"
    return {"pressure": snapshot, "items_completed": 64, "item_cost_ms": item_ms,
            "pause_count": pauses, "requested_rest_ms": round(rest * 1000, 3),
            "longest_work_burst_ms": round(max(longest, burst), 3),
            "recovered_multiplier": controller.multiplier()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inventory-output", type=Path)
    args = parser.parse_args()
    profiles = {"healthy": (10, 40, 2048), "low_available_ram": (10, 60, 384),
                "severe_ram_pressure": (10, 94, 192), "severe_cpu_pressure": (98, 40, 2048)}
    report = {"method": "Virtual clock and injected resource observations; "
              "no physical-host speed or detector efficacy estimate.",
              "profiles": {name: [simulate_profile(*values, item_ms)
                                  for item_ms in (0.5, 20.0)]
                           for name, values in profiles.items()}}
    payload = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    if args.inventory_output:
        args.inventory_output.parent.mkdir(parents=True, exist_ok=True)
        args.inventory_output.write_text(json.dumps(source_inventory(), indent=2) + "\n",
                                         encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    main()
