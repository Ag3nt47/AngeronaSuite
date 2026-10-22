"""Offline comparison of serial and bounded-parallel adaptation probes.

Every probe is an injected wait with fixed output. No host sensor, firewall,
model, or network call runs. Results measure scheduling overhead/overlap only;
they are not physical-host scan throughput or detector efficacy evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from angerona.core.host_adaptation import HostAdaptationService  # noqa: E402


def benchmark(delay_ms: float, repeats: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="angerona-adaptation-benchmark-") as directory:
        service = HostAdaptationService(directory)
        complete = service._quality(complete=True)

        def probe(value):
            def run():
                time.sleep(delay_ms / 1000)
                return value
            return run

        probes = {
            "_collect_services": ([], complete),
            "_collect_ports": ([], complete),
            "capture_context": {"collector": complete},
            "_firewall": {"supported": True, "complete": True},
            "_hardware": {"system": "injected-fixture"},
        }
        for name, value in probes.items():
            setattr(service, name, probe(value))
        samples = {"serial_ms": [], "parallel_ms": []}
        for _ in range(repeats):
            started = time.perf_counter()
            for name in probes:
                getattr(service, name)()
            samples["serial_ms"].append((time.perf_counter() - started) * 1000)
            started = time.perf_counter()
            snapshot = service.capture_snapshot()
            samples["parallel_ms"].append((time.perf_counter() - started) * 1000)
            assert all(row["complete"] for row in snapshot["collector_status"].values())
        medians = {key: round(statistics.median(values), 3) for key, values in samples.items()}
        return {
            "method": "Five injected I/O waits; serial legacy ordering vs fresh bounded-parallel capture. "
                      "No live probes; scheduling evidence only.",
            "delay_per_probe_ms": delay_ms,
            "repeats": repeats,
            "max_workers": 5,
            "median": medians,
            "median_ratio": round(medians["serial_ms"] / medians["parallel_ms"], 3),
            "samples": {key: [round(value, 3) for value in values] for key, values in samples.items()},
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delay-ms", type=float, default=20.0)
    parser.add_argument("--repeats", type=int, default=7)
    args = parser.parse_args()
    if not 0 < args.delay_ms <= 1000 or not 1 <= args.repeats <= 100:
        parser.error("delay must be in (0, 1000] ms and repeats in [1, 100]")
    print(json.dumps(benchmark(args.delay_ms, args.repeats), indent=2))


if __name__ == "__main__":
    main()
