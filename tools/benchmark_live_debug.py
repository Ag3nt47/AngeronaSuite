"""Measure synthetic diagnostic overhead without starting sensors or responses.

Run on Windows with the repository interpreter. Every event is an inert
Self-Test record on a fresh, private in-memory EventBus. No operator data is
read. Results describe this workload and machine, not production capacity.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity  # noqa: E402
from angerona.core.live_debug import LiveDebugService  # noqa: E402


def percentile(values, fraction):
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * fraction))]


def measured_publish(bus, count, *, paced=False):
    durations = []
    started = time.perf_counter()
    for number in range(count):
        event = Event("Self-Test", "Inert live-debug performance fixture", Severity.INFO,
                      details={"event_id": number, "disposition": "observation"})
        before = time.perf_counter()
        bus.publish(event)
        durations.append((time.perf_counter() - before) * 1_000_000)
        if paced:
            time.sleep(0.002)
    return {"count": count, "wall_seconds": time.perf_counter() - started,
            "publish_us_p50": statistics.median(durations),
            "publish_us_p95": percentile(durations, .95),
            "publish_us_max": max(durations)}


def drain(service, timeout=10):
    deadline = time.monotonic() + timeout
    while service.status()["queued"] and time.monotonic() < deadline:
        time.sleep(.01)
    # Let the last dequeued event complete before taking a local snapshot.
    time.sleep(.1)
    if service.status()["queued"]:
        raise RuntimeError("Diagnostic worker did not drain within benchmark deadline")


def benchmark():
    import secrets
    bus = EventBus()
    bus.arm(BusAuthority(secrets.token_bytes(32)))
    result = {"schema": "angerona.live-debug-benchmark.v1", "synthetic": True,
              "python": sys.version.split()[0], "baseline": measured_publish(bus, 1000)}
    with tempfile.TemporaryDirectory(prefix="angerona-debug-benchmark-") as directory:
        service = LiveDebugService(bus, Path(directory), enabled=True, export_logs=False)
        if not service.start():
            raise RuntimeError(service.status()["error"])
        try:
            result["paced_500_per_second"] = measured_publish(bus, 1000, paced=True)
            drain(service)
            cursor, events = 0, []
            while True:
                view = service.recent(cursor, limit=1000)
                events.extend(row for row in view["records"] if row["kind"] == "event")
                cursor = view["cursor"]
                if cursor >= view["last_seq"] or not view["records"]:
                    break
            delays = [(row["ts"] - row["event_ts"]) * 1000 for row in events]
            result["paced_500_per_second"].update(
                exported=len(events), dropped=service.status()["queue_dropped"],
                export_ms_p50=statistics.median(delays), export_ms_p95=percentile(delays, .95),
                export_ms_max=max(delays),
            )
            # Isolate the pressure phase by reading its cumulative drop delta.
            before_drops = service.status()["queue_dropped"]
            result["burst"] = measured_publish(bus, 5000)
            drain(service)
            result["burst"].update(dropped=service.status()["queue_dropped"] - before_drops)
            pulls = []
            for _ in range(20):
                before = time.perf_counter()
                service.recent(0, limit=100)
                pulls.append((time.perf_counter() - before) * 1000)
            result["history_100_ms_p50"] = statistics.median(pulls)
            status = service.status()
            result["retained_records"] = status["cursor"] - status["first_seq"] + 1
        finally:
            started = time.perf_counter()
            service.stop(timeout=3)
            result["shutdown_ms"] = (time.perf_counter() - started) * 1000
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = benchmark()
    text = json.dumps(result, indent=2, allow_nan=False)
    print(text)
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(text + "\n")


if __name__ == "__main__":
    main()
