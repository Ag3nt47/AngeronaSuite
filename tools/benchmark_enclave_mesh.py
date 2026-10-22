"""Offline measured mesh seal/open latency; does not assert timing guarantees."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from angerona.core.enclave_mesh import MeshAuthority  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--messages", type=int, default=1000)
    parser.add_argument("--bytes", type=int, default=1024)
    args = parser.parse_args()
    if not 10 <= args.messages <= 100000 or not 0 <= args.bytes <= 262144:
        parser.error("messages must be10–100000; bytes0–262144")
    authority = MeshAuthority(verified=True)
    sender, receiver = authority.enroll("benchmark.sender"), authority.enroll("benchmark.receiver")
    payload = b"x" * args.bytes
    elapsed = []
    try:
        for _ in range(args.messages):
            start = time.perf_counter_ns()
            with authority.transaction():
                assert receiver.open(sender.seal(payload, receiver)) == payload
            elapsed.append((time.perf_counter_ns() - start) / 1e6)
    finally:
        authority.close()
    ordered = sorted(elapsed)
    print(json.dumps({"platform": platform.platform(), "python": platform.python_version(),
                      "messages": args.messages, "payload_bytes": args.bytes,
                      "operation": "local certificate verification + Ed25519 sign/verify + AES-GCM seal/open",
                      "median_ms": statistics.median(elapsed), "p95_ms": ordered[int(len(ordered) * .95)],
                      "mean_ms": statistics.mean(elapsed), "max_ms": max(elapsed)}, indent=2))


if __name__ == "__main__":
    main()
