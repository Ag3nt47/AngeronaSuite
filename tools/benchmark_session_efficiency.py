"""Offline DNS cooldown and growing-log workloads; no sensors or inference."""
from __future__ import annotations

import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from angerona.core import flow_metrics  # noqa: E402
from angerona.modules import network_protocol_decoder as dns  # noqa: E402


def main() -> None:
    timings = []
    retained = 0
    for _ in range(3):
        module = dns.NetworkProtocolDecoderModule()
        started = time.perf_counter()
        for index in range(10_000):
            assert module._should_emit(f"name-{index}.example.com")
        timings.append((time.perf_counter() - started) * 1000)
        retained = len(module._last_emit)
    (ROOT / ".tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / ".tmp") as directory:
        path = Path(directory) / "audit.log"
        line = b"x" * 255 + b"\n"
        path.write_bytes(line * 131_072)  # 32 MiB initial history
        assert flow_metrics._audit_line_count(path) == 131_072
        appends = []
        for index in range(20):
            with path.open("ab") as stream:
                stream.write(line)
            started = time.perf_counter()
            assert flow_metrics._audit_line_count(path) == 131_073 + index
            appends.append((time.perf_counter() - started) * 1000)
    print(json.dumps({
        "dns_10000_names_median_ms": round(statistics.median(timings), 3),
        "dns_retained_cooldowns": retained,
        "audit_32_mib_append_median_ms": round(statistics.median(appends), 3),
    }, indent=2))


if __name__ == "__main__":
    main()
