"""
core/jitter.py — cryptographic timing jitter (anti-TOCTOU).

A sensor that fires on a fixed cadence (canary every 60 s, heartbeat every
500 ms) is easy for an automated adversary to map: it just runs its payload in
the dead space between sweeps and erases its tracks before the next one. Adding
UNPREDICTABLE jitter to every interval removes that dead space — the attacker
can no longer time a window that reliably avoids an overlapping check.

The randomness comes from ``os.urandom`` (the OS CSPRNG), not the ``random``
module, so an adversary who has predicted/seeded the Python PRNG still can't
predict the next interval.
"""
from __future__ import annotations

import os
import struct


def jitter_fraction() -> float:
    """A cryptographically-random float in [0.0, 1.0) from os.urandom."""
    return struct.unpack("<Q", os.urandom(8))[0] / 2.0 ** 64


def jittered(base: float, spread: float = 0.15) -> float:
    """Return ``base`` seconds perturbed by up to ±``spread`` fraction using
    OS entropy. e.g. jittered(60) -> ~51..69 s; jittered(0.5) -> ~0.425..0.575 s.
    Never returns a negative interval."""
    frac = (jitter_fraction() * 2.0 - 1.0) * spread     # uniform in [-spread, +spread]
    return max(0.0, base * (1.0 + frac))
