"""core/self_ioc.py — registry of Angerona's OWN synthetic indicators.

Angerona deliberately generates benign-but-suspicious-looking traffic and
artifacts to exercise its own detectors: CHAOS fires high-entropy DNS probes,
the Shark / Red-Team engines emit fake C2 domains, and the deception layer
stages decoy files. Those indicators must not be reported as *real* threats —
otherwise the suite detects itself, inflates the threat level, and (worst of
all) a detector that re-scores its own alert text can amplify into an alert
storm that freezes the GUI.

This is the shared allowlist the honeypot / probe side uses to tell the sensor
side: "this one is mine — treat it as a drill, not an intrusion." Entries are
TTL-bounded, so a synthetic indicator is only special-cased for a short window
around when it was generated; a genuinely malicious lookalike seen later is
scored normally.

Stdlib-only, thread-safe, bounded. Read-only to sensors; write-only to probes.
"""
from __future__ import annotations

import threading
import time

_DEFAULT_TTL_S = 300.0
_MAX_ENTRIES = 512

_lock = threading.Lock()
# normalized domain/host -> expiry (monotonic seconds)
_domains: "dict[str, float]" = {}


def _norm(host: str) -> str:
    return (host or "").strip().strip(".").lower()


def _prune_locked(now: float) -> None:
    for k in [k for k, e in _domains.items() if e <= now]:
        _domains.pop(k, None)


def register_domain(host: str, ttl: float = _DEFAULT_TTL_S) -> None:
    """Mark a domain/host as a self-generated indicator for ``ttl`` seconds."""
    h = _norm(host)
    if not h:
        return
    now = time.monotonic()
    with _lock:
        _prune_locked(now)
        if len(_domains) >= _MAX_ENTRIES:
            oldest = min(_domains, key=_domains.get)   # evict soonest-expiring
            _domains.pop(oldest, None)
        _domains[h] = now + max(0.001, float(ttl))


def is_self_ioc(host: str) -> bool:
    """True if ``host`` (or a parent domain of it) is a live self-indicator."""
    h = _norm(host)
    if not h:
        return False
    now = time.monotonic()
    with _lock:
        exp = _domains.get(h)
        if exp is not None:
            if exp > now:
                return True
            _domains.pop(h, None)
        # Suffix match: a registered base decoy (e.g. "example.net") covers its
        # subdomains too. Only live entries count.
        for d, e in _domains.items():
            if e > now and h.endswith("." + d):
                return True
    return False


def clear() -> None:
    with _lock:
        _domains.clear()


def self_test() -> "tuple[bool, str]":
    clear()
    register_domain("abc123xyz.example.net", ttl=5)
    exact = is_self_ioc("abc123xyz.example.net")
    negative = not is_self_ioc("evil-c2.example.org")
    register_domain("example.org", ttl=5)
    suffix = is_self_ioc("beacon.example.org")
    # expiry
    register_domain("shortlived.test", ttl=0.01)
    time.sleep(0.05)
    expired = not is_self_ioc("shortlived.test")
    clear()
    ok = exact and negative and suffix and expired
    return ok, (f"self-IOC registry OK (exact={exact}, neg={negative}, "
                f"suffix={suffix}, expiry={expired})" if ok else
                f"FAIL exact={exact} neg={negative} suffix={suffix} expiry={expired}")


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[self_ioc] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
