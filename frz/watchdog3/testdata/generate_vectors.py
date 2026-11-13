"""Deterministic public fixtures from the existing Python wire authorities.

The keys are fixed test material, never an Angerona installation authority.
Run with PYTHONPATH=src from the repository root; --check changes nothing.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.resilience import control_authority, heartbeat, peer_alerts


def fixtures() -> dict:
    authority = bytes(range(32))
    seed = bytes(range(32, 64))
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    now = 1_700_000_000.125

    def signed(body: dict) -> str:
        document = dict(body, schema=1)
        document["sig"] = private.sign(control_authority._canonical(document)).hex()
        return json.dumps(document, separators=(",", ":"))

    epoch = signed({"kind": "epoch", "epoch": 7, "ts": 1_699_990_000.5})
    base = {"kind": "operator-stop", "epoch": 7, "ts": now - 1,
            "nonce": "0123456789abcdef" * 2, "reason": "Operator stop: café U0001f6a6"}
    operator = signed(base)
    maintenance = signed(dict(base, kind="maintenance", expires=now + 300))
    expired = signed(dict(base, kind="maintenance", expires=now - 0.125))
    stale = signed(dict(base, epoch=6))
    future = signed(dict(base, ts=now + 31))

    def legacy(reason: str, ts: float) -> str:
        nonce = "abcdef0123456789" * 2
        payload = f"{nonce}\x00{int(ts)}\x00{reason}".encode()
        return json.dumps({"nonce": nonce, "ts": ts, "reason": reason,
                           "sig": hmac.new(authority, payload, hashlib.sha256).hexdigest()},
                          separators=(",", ":"))

    heartbeats = []
    for name, timestamp, pid, counter, flags in (
        ("core", 1_700_000_000_125_000_000, 1234, 42, 0x80000001),
        ("watchdog", 1_700_000_001_125_000_000, 5678, 0xFFFFFFFF, 0x80000001),
        ("watchdog3", 1_700_000_002_125_000_000, 9012, 0, 0x80000000),
    ):
        proof = heartbeat.proof_for(heartbeat._component_key(name, authority),
                                    name, timestamp, pid, counter, flags)
        raw = struct.pack("<IQIQII", 0x41574447, timestamp, pid, proof, counter, flags)
        heartbeats.append({"name": name, "timestamp_ns": timestamp, "pid": pid,
                           "counter": counter, "flags": flags, "hex": raw.hex()})

    details = {"core_state": "dead", "watchdog_state": "suspended", "attempts": 2,
               "healthy": False, "wait_seconds": 1.0}
    first = {"id": "0123456789abcdef", "ts": now, "source": "watchdog3", "level": "HIGH",
             "msg": "Native watchdog peer state changed", "details": details, "prev": "0" * 64}
    first["mac"] = peer_alerts._mac(peer_alerts._derive(authority), first)
    second = dict(first, id="abcdef0123456789", prev=first["mac"], level="CRITICAL")
    second["mac"] = peer_alerts._mac(peer_alerts._derive(authority), second)
    integral = dict(first, ts=1_700_000_000.0)
    integral["mac"] = peer_alerts._mac(peer_alerts._derive(authority), integral)
    millisecond = dict(first, ts=1_700_000_000.001)
    millisecond["mac"] = peer_alerts._mac(peer_alerts._derive(authority), millisecond)
    line = lambda record: json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    return {
        "test_material_only": True, "authority_hex": authority.hex(),
        "ed25519_seed_hex": seed.hex(), "admin_public_hex": public.hex(), "now": now,
        "heartbeats": heartbeats,
        "stop": {"epoch": epoch, "operator": operator, "maintenance": maintenance,
                 "expired": expired, "stale_epoch": stale, "future": future,
                 "legacy_maintenance": legacy("maintenance", now - 1),
                 "legacy_operator": legacy("operator-stop: fixture operator", now - 7200),
                 "legacy_expired": legacy("maintenance", now - 7200)},
        "alerts": {"first": line(first), "second": line(second),
                   "integral": line(integral), "millisecond": line(millisecond)},
        "canonical_cases": [
            {"input": {"reason": "café U0001f6a6\x7f", "ts": 1.0},
             "expected": control_authority._canonical({"reason": "café U0001f6a6\x7f", "ts": 1.0}).decode()},
            {"input": {"a": 0.0001, "b": 1e-7, "c": 1e15, "d": 1e16, "e": -0.0},
             "expected": control_authority._canonical({"a": 0.0001, "b": 1e-7, "c": 1e15, "d": 1e16, "e": -0.0}).decode()},
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_name("protocol_vectors.json")
    raw = (json.dumps(fixtures(), sort_keys=True, indent=2) + "\n").encode()
    if args.check:
        if path.read_bytes() != raw:
            raise SystemExit("Watchdog3 protocol fixtures drifted from Python")
        print("Watchdog3 Python protocol vectors match")
    else:
        path.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
