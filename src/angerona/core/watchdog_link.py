"""
core/watchdog_link.py — agent side of the circular-trust handshake with the
out-of-process resilience Watchdog (frz/angerona_watchdog.go, BL-01/BL-09).

The watchdog launches Angerona, passing a per-launch token (env
ANGERONA_WATCHDOG_TOKEN, hex) and the path to its own heartbeat region (env
ANGERONA_WATCHDOG_MMAP). It writes an authenticated heartbeat there every ~500 ms.
This module lets the agent verify the OTHER direction — that the watchdog is
genuinely alive AND knows the token (so a spoofed process can't impersonate it) —
completing the mutual handshake.

Watchdog heartbeat layout (little-endian, 32 bytes), written by the Go side:
    magic  uint32  @0   = 0x41574447 ("AWDG")
    ts_ns  uint64  @4   = wall-clock UnixNano of the beat (jittered)
    pid    uint32  @12  = watchdog pid
    proof  uint64  @16  = first 8 bytes of SHA-256(token_raw || counter_le)
    count  uint32  @24  = beat counter
    flags  uint32  @28  = 1 running
"""
from __future__ import annotations

import hashlib
import os
import struct
import time
from pathlib import Path

_MAGIC = 0x41574447
_FMT = "<IQIQII"                 # magic, ts_ns, pid, proof, counter, flags
_SIZE = struct.calcsize(_FMT)    # 32


def watchdog_proof(token_raw: bytes, counter: int) -> int:
    """The token proof the watchdog writes: first 8 bytes of
    SHA-256(token_raw || counter_le), as a little-endian uint64. Must match the
    Go tokenProof() byte-for-byte."""
    digest = hashlib.sha256(token_raw + struct.pack("<I", counter & 0xFFFFFFFF)).digest()
    return struct.unpack("<Q", digest[:8])[0]


def verify_watchdog(mmap_path: str | None = None, token_hex: str | None = None,
                    max_age_s: float = 5.0) -> tuple[bool, str]:
    """Verify the watchdog heartbeat: correct magic, fresh timestamp, and a token
    proof that only the genuine (token-holding) watchdog could produce. Returns
    (ok, detail). Absence of the env config means 'no watchdog' (not a failure)."""
    mmap_path = mmap_path or os.environ.get("ANGERONA_WATCHDOG_MMAP")
    token_hex = token_hex or os.environ.get("ANGERONA_WATCHDOG_TOKEN")
    if not mmap_path or not token_hex:
        return False, "no watchdog configured (env ANGERONA_WATCHDOG_* unset)"
    try:
        token_raw = bytes.fromhex(token_hex)
    except ValueError:
        return False, "malformed watchdog token"
    try:
        data = Path(mmap_path).read_bytes()
    except Exception as exc:
        return False, f"watchdog heartbeat unreadable: {exc}"
    if len(data) < _SIZE:
        return False, "watchdog heartbeat too short"
    magic, ts_ns, pid, proof, counter, flags = struct.unpack(_FMT, data[:_SIZE])
    if magic != _MAGIC:
        return False, f"bad magic {magic:#x}"
    age = time.time() - (ts_ns / 1e9)
    if age > max_age_s or age < -max_age_s:
        return False, f"stale heartbeat (age {age:.1f}s) — watchdog may be dead/hooked"
    if proof != watchdog_proof(token_raw, counter):
        return False, "token proof mismatch — heartbeat is spoofed, not the real watchdog"
    return True, f"watchdog alive & authenticated (pid {pid}, counter {counter})"
