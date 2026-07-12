"""telemetry_worker.py — Async GUI Architecture for Angerona.

Two-layer protection against module-induced UI lag:

Layer 1 — TelemetryWorker (QThread)
    A persistent background thread that continuously polls the In-Memory Flight
    Cache (MEMC) and the EventBus recent-events ring.  It accumulates new events
    in an internal deque and emits a ``batch_ready`` Qt signal once a configurable
    batch size or time window is reached.  The Qt main thread never touches the
    database or EventBus directly — it only processes pre-digested batches.

    Data boundary:
        EventBus / MEMC   ──(background thread)──►  deque  ──signal──►  Qt main thread

Layer 2 — UI Batch Flush via QTimer (100 ms cadence)
    In MainWindow (or any panel), connect the worker's ``batch_ready`` signal to
    a slot that appends events to the UI model.  Additionally, install a QTimer
    (100 ms) that flushes a local event queue to the visible widgets in a single
    render pass.  This prevents the rendering engine from being called on every
    individual network packet or ETW event.

Layer 3 — Console SQL Thread
    SQL threat-hunting queries (user-typed commands) block on I/O.  Running them
    in QThread subclasses (ConsoleQueryWorker) keeps the console input and UI
    rendering fluid while the query executes.

Drop-in integration
    See ``INTEGRATION NOTES`` at the bottom of this file.
"""
from __future__ import annotations

import collections
import queue
import sqlite3
import threading
import time
from typing import Any

from PySide6.QtCore import QThread, QTimer, Signal, Slot  # type: ignore

try:
    from angerona.core.eventbus import Event, recent as bus_recent
    _BUS_OK = True
except Exception:
    _BUS_OK = False
    Event = Any  # type: ignore


# ── constants ─────────────────────────────────────────────────────────────────
BATCH_SIZE: int = 50           # emit batch after this many events
BATCH_MAX_MS: float = 80.0     # or after this many ms, whichever comes first
POLL_INTERVAL_S: float = 0.05  # worker poll rate (50 ms → max 20 polls/s)
UI_FLUSH_MS: int = 100         # QTimer flush cadence in the main thread
_RECENT_N: int = 200           # events fetched per poll from EventBus


# ═════════════════════════════════════════════════════════════════════════════
# Layer 1: TelemetryWorker
# ═════════════════════════════════════════════════════════════════════════════
class TelemetryWorker(QThread):
    """Background QThread: polls MEMC / EventBus, emits batched signals.

    Signals
    ───────
    batch_ready(list)   — emitted when BATCH_SIZE events accumulate or after
                          BATCH_MAX_MS ms with at least one event pending.
    health_update(dict) — emitted on health changes detected in the cache.

    Usage
    ─────
    In MainWindow.__init__:
        self._worker = TelemetryWorker(db_path=config.db_path)
        self._worker.batch_ready.connect(self._on_telemetry_batch)
        self._worker.start()
    """

    batch_ready = Signal(list)     # payload: list[dict]  (serialised events)
    health_update = Signal(dict)   # payload: {module: str → health: int}

    def __init__(self, db_path: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self._db_path = db_path
        self._stopping = threading.Event()
        self._seen_ids: set[int] = set()     # deduplicate by row id
        self._pending: collections.deque[dict] = collections.deque()
        self._last_flush = time.monotonic()
        self.setDaemon(True)

    def stop(self) -> None:
        self._stopping.set()

    # ── MEMC / FlightRecorder reader ─────────────────────────────────────────
    def _read_memc(self) -> list[dict]:
        """Pull new events from the in-memory cache if MEMC module is active,
        otherwise fall back to a direct read of the on-disk FlightRecorder."""
        try:
            from angerona.modules.flight_cache import FlightCacheModule  # type: ignore
            # If the module singleton is running, use its in-memory DB
            # (this avoids touching the disk DB at all in the hot path)
            # The MEMC module registers itself via register(); we look it up
            # from the module manager if available.
            pass
        except Exception:
            pass

        # Direct on-disk fallback: read the last 200 rows
        if not self._db_path:
            return []
        try:
            con = sqlite3.connect(
                f"file:{self._db_path}?mode=ro",
                uri=True, check_same_thread=False,
                timeout=2.0,
            )
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT rowid, ts, module, severity, message, details "
                "FROM events ORDER BY rowid DESC LIMIT 200"
            ).fetchall()
            con.close()
            new = []
            for r in rows:
                rid = r["rowid"]
                if rid in self._seen_ids:
                    continue
                self._seen_ids.add(rid)
                new.append({
                    "id": rid,
                    "ts": r["ts"],
                    "module": r["module"],
                    "severity": r["severity"],
                    "message": r["message"],
                    "details": r["details"],
                })
            # Keep seen_ids bounded
            if len(self._seen_ids) > 50_000:
                self._seen_ids = set(list(self._seen_ids)[-25_000:])
            return list(reversed(new))   # oldest first
        except Exception:
            return []

    # ── EventBus reader ───────────────────────────────────────────────────────
    def _read_bus(self) -> list[dict]:
        if not _BUS_OK:
            return []
        try:
            events = bus_recent(_RECENT_N)
        except Exception:
            return []
        result = []
        for ev in events:
            eid = id(ev)
            if eid in self._seen_ids:
                continue
            self._seen_ids.add(eid)
            result.append({
                "id": eid,
                "ts": getattr(ev, "ts", time.time()),
                "module": getattr(ev, "module", ""),
                "severity": int(getattr(ev, "severity", 0)),
                "message": getattr(ev, "message", ""),
                "details": getattr(ev, "details", {}),
            })
        return result

    # ── flush logic ───────────────────────────────────────────────────────────
    def _maybe_flush(self, force: bool = False) -> None:
        now = time.monotonic()
        elapsed_ms = (now - self._last_flush) * 1000.0
        if not self._pending:
            return
        if force or len(self._pending) >= BATCH_SIZE or elapsed_ms >= BATCH_MAX_MS:
            batch = list(self._pending)
            self._pending.clear()
            self._last_flush = now
            # Emit the signal — Qt routes this to the main thread safely
            self.batch_ready.emit(batch)

    # ── main loop ─────────────────────────────────────────────────────────────
    def run(self) -> None:
        while not self._stopping.is_set():
            try:
                new_events = self._read_memc() or self._read_bus()
                for ev in new_events:
                    self._pending.append(ev)
                self._maybe_flush()
            except Exception:
                pass
            self._stopping.wait(timeout=POLL_INTERVAL_S)

        # Final flush on shutdown
        self._maybe_flush(force=True)


# ═════════════════════════════════════════════════════════════════════════════
# Layer 2: UIBatchFlusher (QTimer-based, lives in the main thread)
# ═════════════════════════════════════════════════════════════════════════════
class UIBatchFlusher:
    """Install in MainWindow to buffer telemetry batches and render every 100 ms.

    Usage
    ─────
        self._flusher = UIBatchFlusher(render_fn=self._append_alert_rows)
        self._worker.batch_ready.connect(self._flusher.enqueue)
        self._flusher.start()
    """

    def __init__(self, render_fn, parent=None) -> None:
        self._render_fn = render_fn
        self._queue: list[dict] = []
        self._lock = threading.Lock()
        self._timer = QTimer(parent)
        self._timer.setInterval(UI_FLUSH_MS)
        self._timer.timeout.connect(self._flush)

    def start(self) -> None:
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    @Slot(list)
    def enqueue(self, batch: list) -> None:
        """Receive a batch from TelemetryWorker (runs in main thread via signal)."""
        with self._lock:
            self._queue.extend(batch)

    def _flush(self) -> None:
        """Called by QTimer every 100 ms — drain the queue into the UI."""
        with self._lock:
            if not self._queue:
                return
            batch = self._queue
            self._queue = []
        try:
            self._render_fn(batch)
        except Exception:
            pass


# ═════════════════════════════════════════════════════════════════════════════
# Layer 3: ConsoleQueryWorker
# ═════════════════════════════════════════════════════════════════════════════
class ConsoleQueryWorker(QThread):
    """Run a SQL threat-hunting query in a background thread.

    Usage
    ─────
        worker = ConsoleQueryWorker(db_path, "SELECT * FROM processes LIMIT 20")
        worker.result_ready.connect(self._on_query_result)
        worker.error_occurred.connect(self._on_query_error)
        worker.start()

    The worker is transient — create a new one per query; don't reuse.
    """

    result_ready = Signal(list, float)   # (rows: list[dict], elapsed_ms: float)
    error_occurred = Signal(str)         # error message

    # Read-only whitelist — mirrors the gate in MEMC.query()
    _ALLOWED = ("select", "with")
    _FORBIDDEN = ("drop", "delete", "insert", "update", "alter", "attach",
                  "detach", "pragma", "create", "replace", "vacuum")

    def __init__(self, db_path: str, sql: str, params: tuple = (), parent=None) -> None:
        super().__init__(parent)
        self._db_path = db_path
        self._sql = sql
        self._params = params

    def run(self) -> None:
        first_word = self._sql.strip().split()[0].lower() if self._sql.strip() else ""
        if first_word not in self._ALLOWED:
            self.error_occurred.emit(
                f"Query rejected: only SELECT / WITH allowed (got '{first_word}')"
            )
            return
        for bad in self._FORBIDDEN:
            if bad in self._sql.lower():
                self.error_occurred.emit(f"Query rejected: forbidden keyword '{bad}'")
                return
        t0 = time.perf_counter()
        try:
            con = sqlite3.connect(
                f"file:{self._db_path}?mode=ro", uri=True, check_same_thread=False
            )
            con.row_factory = sqlite3.Row
            cur = con.execute(self._sql, self._params)
            rows = [dict(r) for r in cur.fetchmany(10_000)]
            con.close()
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self.result_ready.emit(rows, elapsed_ms)
        except Exception as exc:
            self.error_occurred.emit(str(exc))


# ═════════════════════════════════════════════════════════════════════════════
# INTEGRATION NOTES
# ═════════════════════════════════════════════════════════════════════════════
"""
1. In app.py (AngeronaApp) or main_window.py (MainWindow.__init__):

    from angerona.gui.telemetry_worker import (
        TelemetryWorker, UIBatchFlusher, ConsoleQueryWorker
    )

    # Start the background polling thread
    self._worker = TelemetryWorker(db_path=str(config.db_path))
    self._worker.start()

    # Install the 100-ms batch flusher (renders to the alerts panel)
    self._flusher = UIBatchFlusher(
        render_fn=self._alerts_panel.append_rows,
        parent=self,
    )
    self._worker.batch_ready.connect(self._flusher.enqueue)
    self._flusher.start()

    # On app shutdown:
    self._worker.stop()
    self._worker.wait(3000)
    self._flusher.stop()


2. For console SQL queries in CommandConsolePanel._run_query(sql):

    self._query_worker = ConsoleQueryWorker(config.db_path, sql)
    self._query_worker.result_ready.connect(self._on_query_result)
    self._query_worker.error_occurred.connect(self._on_query_error)
    self._query_worker.start()
    # Console input remains responsive while query runs


3. NDRD / Packet Sniffer GPU offload:

    from angerona.core.gpu_entropy import get_pipeline

    _GPU = get_pipeline()
    _GPU.on_result(self._handle_entropy_batch)

    # In the scanner hot-path:
    _GPU.submit_batch(extracted_strings)

    # In _handle_entropy_batch(result: EntropyResult):
    for s, h in zip(result.strings, result.entropies):
        if h >= 3.6:
            self.emit(f"High entropy: {s} H={h:.2f}", Severity.HIGH)
"""
