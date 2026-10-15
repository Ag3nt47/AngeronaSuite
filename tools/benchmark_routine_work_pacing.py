"""Simulate routine work pacing without burning CPU or starting sensors.

--item-ms represents one indivisible operation on a faster or slower host.
This measures scheduling policy in virtual time, not actual hardware speed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from angerona.core.background_pacing import RoutineWorkPacer  # noqa: E402


def simulate(*, multiplier: int, elapsed: bool, item_ms: float, items: int, batch: int) -> dict:
    clock = SimpleNamespace(value=0.0)
    requested = (multiplier - 1) * 0.05 / 7
    pacer = RoutineWorkPacer(SimpleNamespace(batch_delay=lambda: requested),
                             clock=lambda: clock.value)
    rest = burst = longest = 0.0
    for index in range(1, items + 1):
        clock.value += item_ms / 1000
        burst += item_ms
        delay = (pacer.pause_seconds(index, batch_size=batch) if elapsed else
                 requested if index % batch == 0 else 0.0)
        if delay:
            longest = max(longest, burst)
            burst = 0.0
            rest += delay
            clock.value += delay
            pacer.resume()
    return {"items_completed": items, "virtual_total_ms": round(clock.value * 1000, 3),
            "rest_ms": round(rest * 1000, 3), "longest_work_burst_ms": round(max(longest, burst), 3)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--item-ms", type=float, default=20)
    parser.add_argument("--items", type=int, default=32)
    parser.add_argument("--batch-size", type=int, default=8)
    args = parser.parse_args()
    if not 0 < args.item_ms <= 60_000 or not 1 <= args.items <= 100_000 or args.batch_size < 1:
        parser.error("Use item-ms in (0, 60000], items in [1, 100000], and batch-size >= 1")
    report = {}
    for multiplier in (1, 2, 4, 8):
        report[f"pace_{100 / multiplier:g}_percent"] = {
            label: simulate(multiplier=multiplier, elapsed=elapsed, item_ms=args.item_ms,
                            items=args.items, batch=args.batch_size)
            for label, elapsed in (("before_count_only", False), ("after_elapsed_work", True))
        }
    print(json.dumps({"method": "Virtual-time policy fixture; no hardware speed estimate",
                      "indivisible_item_ms": args.item_ms, "results": report}, indent=2))


if __name__ == "__main__":
    main()
