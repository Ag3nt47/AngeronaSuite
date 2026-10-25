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
import sys
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

# Bounds constrain our retained rows and adapter validation, not the duration of
# an individual native call. Missing/truncated evidence remains a coverage gap.
_MAX_PROCESS_ROWS = 65_536
_MAX_PARENT_MAP_ROWS = 65_536
_WINDOWS_PROCESS_MAP = sys.platform == "win32"


def _positive_birth(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return float(value) if math.isfinite(value) and value > 0 else None
    except (OverflowError, ValueError):
        return None


def _process_image(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _windows_parent_map(psutil) -> dict[int, int]:
    """Read one scan-local advisory map; never fall back to per-row scans.

    psutil 7.2.2's private adapter, also used by Process.children(), wraps one
    Toolhelp process snapshot. The supported project dependency is broader, so
    reject unavailable or changed adapter shapes as collection loss. This map
    has neither parent-birth nor executable custody and grants no authority.
    """
    reader = getattr(psutil, "_ppid_map", None)
    if not callable(reader):
        raise ValueError("unsupported Windows parent-map adapter")
    rows = reader()
    if type(rows) is not dict or len(rows) > _MAX_PARENT_MAP_ROWS:
        raise ValueError("invalid or oversized Windows parent map")
    for pid, parent in rows.items():
        if (type(pid) is not int or type(parent) is not int
                or not 0 <= pid <= 0xFFFFFFFF or not 0 <= parent <= 0xFFFFFFFF):
            raise ValueError("invalid Windows parent-map identity")
    return rows


@dataclass(frozen=True)
class ConnectionSnapshot:
    """Immutable connection inventory plus explicit collection coverage."""

    connections: tuple[Mapping[str, object], ...]
    collected_at: float
    complete: bool
    enumerated: int
    skipped: int
    error: str = ""

    def __post_init__(self) -> None:
        # Detach even caller-supplied mappings before sharing a receipt. Sensor
        # rows contain only scalar values; a consumer cannot poison another
        # detector's status/PID/endpoints through the cached dictionary.
        object.__setattr__(self, "connections", tuple(
            MappingProxyType(dict(row)) for row in self.connections
        ))

    def to_dict(self) -> dict[str, object]:
        """Return detached, JSON-compatible presentation data."""
        return {"connections": [dict(row) for row in self.connections],
                "collected_at": self.collected_at, "complete": self.complete,
                "enumerated": self.enumerated, "skipped": self.skipped, "error": self.error}


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

    Missing command lines and unconfirmed PID/birth/image observations remain
    unknown, never an apparently successful inventory. Parent PIDs are advisory
    observations, not parent-birth proof. Consumers must independently revalidate
    process identity and image custody before taking action.
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


_process_snapshot_provider = None
_process_snapshot_provider_generation = 0


def configure_process_snapshot_provider(provider) -> None:
    """Register an owned provider before production modules; never start it here.

    No cache lock or provider I/O: a lifecycle callback may call this on Qt.
    In-flight old-generation work cannot publish into the replacement cache.
    """
    global _process_snapshot_provider, _process_snapshot_provider_generation, _proc_cache
    _process_snapshot_provider = provider
    _process_snapshot_provider_generation += 1
    _proc_cache = (0.0, None)


def _process_snapshot_on_gui_thread() -> bool:
    qt = sys.modules.get("PySide6.QtCore")
    if qt is None:
        return False
    app = qt.QCoreApplication.instance()
    return app is not None and qt.QThread.currentThread() == app.thread()


def process_snapshot(max_age: float | None = None) -> ProcessSnapshot:
    """Snapshot rich metadata, birth observations and advisory parent PIDs.

    Cached for a short window (``ANGERONA_SENSOR_CACHE_TTL``, default 1.5 s) so
    concurrent sensor threads share one enumeration instead of each running
    their own. Pass ``max_age=0`` to force a fresh scan. The public PID table
    supplies IDs only: metadata comes from independent fresh Process objects.
    A second birth/image read brackets the scan-local Windows parent map. These
    are coherent observations, not an atomic snapshot or response authority.
    """
    global _proc_cache
    provider = _process_snapshot_provider
    generation = _process_snapshot_provider_generation
    if provider is not None and _process_snapshot_on_gui_thread():
        from angerona.telemetry.process_snapshot_worker import unavailable
        return unavailable("GUI-thread admission refused")
    ttl = _CACHE_TTL if max_age is None else max_age
    with _proc_cache_lock:
        now = time.monotonic()
        if ttl > 0:
            ts, cached = _proc_cache
            if ts > 0.0 and cached is not None and 0.0 <= (now - ts) < ttl:
                return cached
        if provider is None:
            # Direct offline callers and inert tests retain the local collector.
            # Production lifecycle registers its unstarted owner before modules.
            receipt = _collect_process_snapshot()
        else:
            from angerona.telemetry.process_snapshot_worker import unavailable
            try:
                receipt = provider.snapshot()
                if type(receipt) is not ProcessSnapshot:
                    raise TypeError("inventory provider receipt")
            except Exception as exc:
                receipt = unavailable(type(exc).__name__)
        if (provider is not _process_snapshot_provider
                or generation != _process_snapshot_provider_generation):
            from angerona.telemetry.process_snapshot_worker import unavailable
            return unavailable("provider lifecycle changed")
        # Anchor before dispatch; provider duration never extends evidence TTL.
        _proc_cache = (now, receipt)
        return receipt


def _collect_process_snapshot() -> ProcessSnapshot:
    """Existing rich collector, local only in its worker or offline fixtures."""
    out: list[Mapping[str, object]] = []
    enumerated = skipped = unreadable = identity_incomplete = 0
    error = ""
    enumeration_complete = True
    pending: list[tuple[int, dict[str, object]]] = []
    try:
        import psutil

        attrs = ["pid", "name", "exe", "username", "cmdline", "create_time"]
        if not _WINDOWS_PROCESS_MAP:
            attrs.append("ppid")
        # Enumerate IDs without creating psutil's lifetime-cached Process
        # objects; neither metadata pass may reuse those identity caches.
        for pid in psutil.pids():
            enumerated += 1
            if enumerated > _MAX_PROCESS_ROWS:
                enumeration_complete = False
                skipped += 1
                error = "process inventory exceeded the bounded row limit"
                break
            try:
                if type(pid) is not int or pid < 0:
                    raise ValueError("invalid enumerated PID")
                info = psutil.Process(pid).as_dict(attrs=attrs, ad_value=None)
                if type(info.get("pid")) is not int or info["pid"] != pid:
                    raise ValueError("process metadata PID changed")
                pending.append((pid, info))
            except Exception:
                skipped += 1
    except Exception as exc:
        enumeration_complete = False
        error = f"process enumeration failed: {exc}"[:500]

    # One whole-system map instead of one for each cold Process.ppid().
    # Preserve already visible metadata even when the map is unavailable.
    parents = None
    if _WINDOWS_PROCESS_MAP and pending:
        try:
            parents = _windows_parent_map(psutil)
        except Exception as exc:
            enumeration_complete = False
            error = error or f"Windows parent map unavailable: {type(exc).__name__}"
    for pid, info in pending:
        try:
            after = psutil.Process(pid).as_dict(
                attrs=["pid", "create_time", "exe"], ad_value=None,
            )
            if type(after.get("pid")) is not int or after["pid"] != pid:
                raise ValueError("process verification PID changed")
            before_birth = _positive_birth(info.get("create_time"))
            after_birth = _positive_birth(after.get("create_time"))
            before_image = _process_image(info.get("exe"))
            after_image = _process_image(after.get("exe"))
            # Different known observations are loss, not a stitched row.
            # Independent objects avoid the denied-fast-birth (PID,None)
            # identity comparison and the lifetime cached exe() result.
            if (before_birth is not None and after_birth is not None
                    and before_birth != after_birth):
                raise ValueError("process birth changed during collection")
            if (before_image is not None and after_image is not None
                    and before_image != after_image):
                raise ValueError("process image changed during collection")
            coherent = bool(pid > 0 and before_birth is not None
                            and after_birth is not None and before_image is not None
                            and after_image is not None)
            if before_birth is None or after_birth is None:
                info["create_time"] = None
            if before_image is None or after_image is None:
                info["exe"] = None
            if _WINDOWS_PROCESS_MAP:
                # Bind the PID-only parent map only between matching fresh
                # observations. Unreadable/protected identity stays unknown.
                info["ppid"] = parents.get(pid) if coherent and parents is not None else None
                coherent = coherent and info["ppid"] is not None
            elif not coherent:
                info["ppid"] = None
            identity_incomplete += int(not coherent)
            command = info.get("cmdline")
            if not isinstance(command, (tuple, list)) or any(
                not isinstance(value, str) for value in command
            ):
                command = None
                unreadable += 1
            else:
                command = tuple(command)
            info["cmdline"] = command
            out.append(MappingProxyType(info))
        except Exception:
            skipped += 1
    if skipped and not error:
        error = f"{skipped} process row(s) could not be normalized"
    receipt = ProcessSnapshot(
        tuple(out), time.time(),
        enumeration_complete and not (skipped or unreadable or identity_incomplete),
        enumerated, skipped, unreadable, identity_incomplete, error,
        enumeration_complete and skipped == 0,
    )
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
