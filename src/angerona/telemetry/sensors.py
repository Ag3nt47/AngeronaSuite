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
import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, Iterable, List, Mapping

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
# Cache lifetimes use monotonic time; evidence receipts retain wall-clock time.
# An NTP/manual clock correction must neither freeze a stale sensor snapshot
# nor cause every concurrent consumer to repeat an otherwise fresh scan.
_proc_cache: tuple[float, "ProcessSnapshot | None"] = (0.0, None)
_conn_cache: tuple[float, "ConnectionSnapshot | None"] = (0.0, None)


@dataclass(frozen=True)
class ConnectionSnapshot:
    """Bounded connection inventory plus explicit collection coverage."""

    connections: tuple[Dict, ...]
    collected_at: float
    complete: bool
    enumerated: int
    skipped: int
    error: str = ""


class ConnectionList(list[Dict]):
    """List-compatible snapshot carrying a typed completeness receipt."""

    def __init__(self, receipt: ConnectionSnapshot):
        super().__init__(dict(item) for item in receipt.connections)
        self.receipt = receipt

    @property
    def complete(self) -> bool:
        return self.receipt.complete

    @property
    def collected_at(self) -> float:
        return self.receipt.collected_at

    @property
    def skipped(self) -> int:
        return self.receipt.skipped

    @property
    def error(self) -> str:
        return self.receipt.error


@dataclass(frozen=True)
class ProcessSnapshot:
    """Shared, immutable process evidence with explicit collection loss.

    A missing command line or birth timestamp is retained as an unknown; it
    never becomes an empty, apparently successful inventory. Consumers must
    still revalidate process identity before taking action.
    """

    processes: tuple[Mapping[str, object], ...]
    collected_at: float
    complete: bool
    enumerated: int
    skipped: int
    unreadable: int = 0
    identity_incomplete: int = 0
    error: str = ""
    enumeration_complete: bool = True


def process_snapshot(max_age: float | None = None) -> ProcessSnapshot:
    """Snapshot rich process metadata, including PID birth and parent identity.

    Cached for a short window (``ANGERONA_SENSOR_CACHE_TTL``, default 1.5 s) so
    concurrent sensor threads share one enumeration instead of each running
    their own.  Pass ``max_age=0`` to force a fresh scan.
    """
    global _proc_cache
    ttl = _CACHE_TTL if max_age is None else max_age
    # Serialize cache misses so simultaneous sensor ticks do not all perform the
    # same expensive OS enumeration before any of them has populated the cache.
    with _proc_cache_lock:
        now = time.monotonic()
        if ttl > 0:
            ts, cached = _proc_cache
            # A successful enumeration can legitimately be empty (for example
            # in an isolated test/container).  Cache validity is represented
            # by its timestamp, not by the snapshot's truthiness.
            if ts > 0.0 and cached is not None and 0.0 <= (now - ts) < ttl:
                return cached
        out: list[Mapping[str, object]] = []
        enumerated = skipped = unreadable = identity_incomplete = 0
        error = ""
        enumeration_complete = True
        try:
            import psutil

            for p in psutil.process_iter([
                "pid", "name", "exe", "ppid", "username", "cmdline", "create_time",
            ]):
                enumerated += 1
                try:
                    info = dict(p.info)
                    # psutil caches Process objects between process_iter calls.
                    # Verify their birth identity after reading the metadata:
                    # otherwise a reused PID can mix an old birth timestamp
                    # with the replacement process's image or command line.
                    running = getattr(p, "is_running", None)
                    if running is not None and not running():
                        skipped += 1
                        continue
                    command = info.get("cmdline")
                    if not isinstance(command, (tuple, list)) or any(
                        not isinstance(value, str) for value in command
                    ):
                        command = None
                        unreadable += 1
                    else:
                        command = tuple(command)
                    info["cmdline"] = command
                    try:
                        birth = float(info.get("create_time"))
                        valid_identity = (
                            isinstance(info.get("pid"), int) and info["pid"] > 0
                            and math.isfinite(birth) and birth > 0
                        )
                    except (TypeError, ValueError, OverflowError):
                        valid_identity = False
                    identity_incomplete += int(not valid_identity)
                    out.append(MappingProxyType(info))
                except Exception:
                    skipped += 1
        except Exception as exc:
            enumeration_complete = False
            error = f"process enumeration failed: {exc}"[:500]
        if skipped and not error:
            error = f"{skipped} process row(s) could not be normalized"
        receipt = ProcessSnapshot(
            tuple(out), time.time(),
            enumeration_complete and not (skipped or unreadable or identity_incomplete),
            enumerated, skipped, unreadable, identity_incomplete, error,
            enumeration_complete and skipped == 0,
        )
        # The timestamp starts when collection begins: an expensive enumeration
        # must not silently extend the maximum evidence age by its own duration.
        _proc_cache = (now, receipt)
        return receipt


def list_processes(max_age: float | None = None) -> List[Dict]:
    """Return private, list-compatible rows from the shared rich snapshot.

    Consumers historically mutate dictionaries and command-line lists. Copies
    prevent one detector from changing evidence seen by other detectors.
    """
    return [
        {**row, "cmdline": list(row["cmdline"]) if row["cmdline"] is not None else None}
        for row in process_snapshot(max_age=max_age).processes
    ]


def connection_snapshot(max_age: float | None = None) -> ConnectionSnapshot:
    """Return active TCP/UDP connections and a fail-closed coverage receipt.

    Cached for a short window (see :func:`list_processes`); pass ``max_age=0``
    to force a fresh scan. Import/enumeration/per-row failures are represented
    in ``complete`` and ``error`` instead of being indistinguishable from a
    genuinely empty host connection table.
    """
    global _conn_cache
    ttl = _CACHE_TTL if max_age is None else max_age
    with _conn_cache_lock:
        now = time.monotonic()
        if ttl > 0:
            ts, cached = _conn_cache
            if ts > 0.0 and cached is not None and 0.0 <= (now - ts) < ttl:
                return cached
        try:
            import psutil
        except Exception as exc:
            receipt = ConnectionSnapshot(
                (), time.time(), False, 0, 0, f"psutil unavailable: {exc}"[:500]
            )
            _conn_cache = (now, receipt)
            return receipt
        out: List[Dict] = []
        skipped = 0
        try:
            rows = tuple(psutil.net_connections(kind="inet"))
        except Exception as exc:
            receipt = ConnectionSnapshot(
                (), time.time(), False, 0, 0, f"connection enumeration failed: {exc}"[:500]
            )
            _conn_cache = (now, receipt)
            return receipt
        enumerated = 0
        for c in rows:
            enumerated += 1
            try:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                out.append({"pid": c.pid, "status": c.status, "laddr": laddr, "raddr": raddr})
            except Exception:
                skipped += 1
                continue
        collected = time.time()
        receipt = ConnectionSnapshot(
            tuple(out),
            collected,
            skipped == 0,
            enumerated,
            skipped,
            f"{skipped} connection row(s) could not be normalized" if skipped else "",
        )
        _conn_cache = (time.monotonic(), receipt)
        return receipt


def list_connections(max_age: float | None = None) -> List[Dict]:
    """List-compatible connection snapshot with a ``receipt`` attribute."""
    return ConnectionList(connection_snapshot(max_age=max_age))


class KernelSensor:
    """Abstract interface for a kernel-sourced event stream.

    A signed ETW session or minifilter driver would implement ``events()`` to
    yield real-time kernel events. Until then this stays unused; modules rely on
    the polling helpers above.
    """

    def events(self) -> Iterable[Dict]:  # pragma: no cover - interface only
        raise NotImplementedError
