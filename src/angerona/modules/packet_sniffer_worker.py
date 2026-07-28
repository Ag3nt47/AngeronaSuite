"""Crash-isolated Scapy/Npcap worker for :mod:`packet_sniffer`.

This module is a deliberately tiny subprocess boundary. It writes a bounded
JSON-lines protocol to stdout and never includes captured payload bytes.
"""
from __future__ import annotations

import argparse
import json
import string
from typing import Any

LEAK_TOKENS: tuple[tuple[str, str], ...] = (
    ("password", "password"),
    ("passwd", "password"),
    ("api_key", "API key"),
    ("apikey", "API key"),
    ("secret", "secret"),
    ("authorization", "authorization token"),
    ("token=", "token"),
    ("bearer ", "bearer token"),
    ("aws_secret", "AWS secret"),
    ("private_key", "private key"),
)
_PRINTABLE = set(string.printable.encode("ascii"))
_MAX_RECORDS = 256


def _is_text(payload: bytes) -> bool:
    if not payload:
        return False
    sample = payload[:4096]
    hits = sum(1 for byte in sample if byte in _PRINTABLE)
    return (hits / len(sample)) > 0.85


def _token_kind(payload: bytes) -> str:
    """Classify a likely cleartext secret without returning the secret value."""
    if not payload or not _is_text(payload):
        return ""
    text = payload[:4096].decode("ascii", errors="ignore").lower()
    for marker, label in LEAK_TOKENS:
        if marker in text:
            return label
    return ""


def _emit(record: dict[str, Any]) -> None:
    print(json.dumps(record, separators=(",", ":"), ensure_ascii=True), flush=True)


def capture(timeout: float) -> int:
    try:
        from scapy.all import IP, TCP, sniff
    except Exception as exc:
        _emit({"type": "error", "message": f"Scapy/Npcap unavailable: {exc}"})
        return 2

    emitted = 0

    def on_packet(packet: Any) -> None:
        nonlocal emitted
        if emitted >= _MAX_RECORDS:
            return
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(IP):
                return
            token_kind = _token_kind(bytes(packet[TCP].payload))
            if not token_kind:
                return
            emitted += 1
            _emit(
                {
                    "type": "detection",
                    "src": str(packet[IP].src)[:64],
                    "dst": str(packet[IP].dst)[:64],
                    "token_kind": token_kind,
                }
            )
        except Exception:
            # A malformed packet is discarded inside the already isolated
            # process. It never becomes a Core exception or a log disclosure.
            return

    try:
        sniff(
            prn=on_packet,
            store=False,
            timeout=max(1.0, min(300.0, float(timeout))),
        )
    except Exception as exc:
        _emit({"type": "error", "message": f"Capture failed: {exc}"})
        return 3
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args(argv)
    return capture(args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
