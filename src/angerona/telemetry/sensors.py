"""Cross-cutting sensors used by multiple modules.

Implementation note on "kernel access":
We deliberately source kernel-level facts (process creation, image loads,
network flows) through Microsoft-supported interfaces rather than a custom
driver:
  * psutil / WMI / CIM     -> processes, services, connections
  * ETW (Event Tracing)    -> high-fidelity kernel events  [extension point]
  * AMSI                    -> in-memory script scanning     [extension point]
  * WFP (Filtering Platform)-> network allow/deny            [extension point]

``KernelSensor`` is the abstract seam where a future *signed* driver could
attach. Nothing here loads an unsigned driver.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, Iterable, List

# ── Shared snapshot cache ─────────────────────────────────────────────────────
# A full process-table / connection-table enumeration is one of the most
# expensive things any sensor does on Windows (tens–hundreds of ms).  Many
# modules poll these helpers on independent 3–10 s cadences, so at any instant
# several sensor threads can be doing the SAME full scan within milliseconds of
# each other — pure duplicated work that shows up as the "so much loading in the
# background" the app feels.  A tiny time-boxed cache collapses those redundant
# scans into one: the first caller in each window pays for the enumeration and
# every other caller in that window reuses the identical snapshot.  The TTL is
# far shorter than any consumer's poll interval, so detection fidelity is
# unchanged.  ``ANGERONA_SENSOR_CACHE_TTL`` (env, seconds) tunes/disables it.
try:
    _CACHE_TTL = float(__import__("os").environ.get("ANGERONA_SENSOR_CACHE_TTL", "1.5"))
except Exception:
    _CACHE_TTL = 1.5

_proc_cache_lock = threading.Lock()
_conn_cache_lock = threading.Lock()
_proc_cache: tuple[float, List[Dict]] = (0.0, [])
_conn_cache: tuple[float, List[Dict]] = (0.0, [])


def list_processes(max_age: float | None = None) -> List[Dict]:
    """Snapshot of running processes (pid, name, exe, ppid, username).

    Cached for a short window (``ANGERONA_SENSOR_CACHE_TTL``, default 1.5 s) so
    concurrent sensor threads share one enumeration instead of each running
    their own.  Pass ``max_age=0`` to force a fresh scan.
    """
    global _proc_cache
    ttl = _CACHE_TTL if max_age is None else max_age
    # Serialize cache misses so simultaneous sensor ticks do not all perform the
    # same expensive OS enumeration before any of them has populated the cache.
    with _proc_cache_lock:
        now = time.time()
        if ttl > 0:
            ts, cached = _proc_cache
            # A successful enumeration can legitimately be empty (for example
            # in an isolated test/container).  Cache validity is represented
            # by its timestamp, not by the snapshot's truthiness.
            if ts > 0.0 and (now - ts) < ttl:
                return cached
        try:
            import psutil
        except Exception:
            return []
        out: List[Dict] = []
        for p in psutil.process_iter(["pid", "name", "exe", "ppid", "username"]):
            try:
                out.append(p.info)
            except Exception:
                continue
        _proc_cache = (now, out)
        return out


def list_connections(max_age: float | None = None) -> List[Dict]:
    """Active TCP/UDP connections with owning pid.

    Cached for a short window (see :func:`list_processes`); pass ``max_age=0``
    to force a fresh scan.
    """
    global _conn_cache
    ttl = _CACHE_TTL if max_age is None else max_age
    with _conn_cache_lock:
        now = time.time()
        if ttl > 0:
            ts, cached = _conn_cache
            if ts > 0.0 and (now - ts) < ttl:
                return cached
        try:
            import psutil
        except Exception:
            return []
        out: List[Dict] = []
        for c in psutil.net_connections(kind="inet"):
            try:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                out.append({"pid": c.pid, "status": c.status, "laddr": laddr, "raddr": raddr})
            except Exception:
                continue
        _conn_cache = (now, out)
        return out


class KernelSensor:
    """Abstract interface for a kernel-sourced event stream.

    A signed ETW session or minifilter driver would implement ``events()`` to
    yield real-time kernel events. Until then this stays unused; modules rely on
    the polling helpers above.
    """

    def events(self) -> Iterable[Dict]:  # pragma: no cover - interface only
        raise NotImplementedError
