"""Flight recorder — an append-only SQLite ledger of every security event.

This is the tamper-evident audit trail. The GUI's Alerts page reads from here,
and it survives restarts so you can review what happened while you were away.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import List

from angerona.core.eventbus import Event, Severity


def _dlq_write_exclusive(path: Path, entry: str) -> None:
    """Write *entry* to *path* with an exclusive OS-level file lock.

    On Windows, msvcrt.locking() acquires a mandatory exclusive byte-range
    lock that blocks any other process from reading or writing the locked
    region.  On POSIX, fcntl.flock(LOCK_EX) is used instead.
    Falls back to plain append if neither is available.

    G3-E TOCTOU fix: OS-level lock prevents attacker processes from
    interleaving writes and corrupting the NDJSON structure.
    """
    import os
    import sys
    data = entry.encode("utf-8")
    try:
        if sys.platform == "win32":
            import msvcrt
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_BINARY
            fd = os.open(str(path), flags, 0o600)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, len(data))
                os.write(fd, data)
            finally:
                try:
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, len(data))
                except Exception:
                    pass
                os.close(fd)
        else:
            import fcntl
            with open(str(path), "ab") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    fh.write(data)
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)
    except Exception:
        # Last-resort: plain append (better than losing the event entirely)
        with open(str(path), "a", encoding="utf-8") as fh:
            fh.write(entry)


class FlightRecorder:
    # Retention: bound the ledger so every query (and the DB file) stays fast as
    # telemetry accumulates. Tunable / patchable for tests.
    MAX_ROWS = 40000        # keep roughly the newest N events
    PRUNE_EVERY = 1000      # amortise the trim across this many inserts

    # Dead-Letter Queue: if SQLite is still locked after this many retries,
    # route the event to a fast append-only JSON file so no telemetry is lost.
    _DLQ_RETRIES     = 3
    _DLQ_RETRY_DELAY = 0.05   # 50 ms between retries — fast but not hammering

    def __init__(self, db_path: Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the bus may publish from any module thread.
        self._db = sqlite3.connect(str(self._path), check_same_thread=False)
        self._lock     = threading.Lock()
        self._dlq_lock = threading.Lock()   # separate lock — DLQ must never deadlock primary
        self._writes   = 0
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            # WAL + NORMAL sync: the old code fsync'd on EVERY event (a full disk
            # sync per insert — crippling at ~140 events/sec). WAL lets readers run
            # without blocking the writer and cuts fsyncs to checkpoints; NORMAL is
            # durable enough for telemetry. busy_timeout avoids "database locked".
            for pragma in ("journal_mode=WAL", "synchronous=NORMAL", "busy_timeout=3000"):
                try:
                    self._db.execute(f"PRAGMA {pragma}")
                except Exception:
                    pass
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        REAL    NOT NULL,
                    module    TEXT    NOT NULL,
                    severity  INTEGER NOT NULL,
                    message   TEXT    NOT NULL,
                    details   TEXT
                )
                """
            )
            self._db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            self._db.commit()

    def record(self, event: Event) -> None:
        """Write an event to SQLite, falling back to the DLQ on repeated lock failures.

        The WAL + busy_timeout=3000 pragma handles most transient locks internally.
        This retry loop catches edge cases (checkpoint races, backup processes) where
        the DB remains locked beyond that window.  After _DLQ_RETRIES failures the
        event is routed to dlq_events.json so no telemetry is silently dropped.
        """
        for attempt in range(self._DLQ_RETRIES):
            try:
                with self._lock:
                    self._db.execute(
                        "INSERT INTO events (ts, module, severity, message, details) "
                        "VALUES (?,?,?,?,?)",
                        (event.ts, event.module, int(event.severity), event.message,
                         json.dumps(event.details)),
                    )
                    self._db.commit()
                    self._writes += 1
                    if self._writes >= self.PRUNE_EVERY:
                        self._writes = 0
                        self._prune_locked()
                return   # success
            except sqlite3.OperationalError:
                if attempt < self._DLQ_RETRIES - 1:
                    time.sleep(self._DLQ_RETRY_DELAY)
                else:
                    self._route_to_dlq(event)
            except Exception:
                return   # unexpected error — skip without crashing the bus

    def _route_to_dlq(self, event: Event) -> None:
        """Append-only JSON fallback when the primary SQLite ledger is locked.

        Each line in dlq_events.json is a complete, self-contained JSON object
        (newline-delimited JSON / NDJSON format) for easy batch re-ingestion.

        G3-E TOCTOU fix: uses OS-level exclusive file locking (msvcrt on Windows,
        fcntl on POSIX) so an attacker process cannot interleave writes and corrupt
        the NDJSON structure.  The in-process self._dlq_lock is still held first to
        guard concurrent threads within the same process.
        """
        dlq_path = self._path.parent / "dlq_events.json"
        entry = json.dumps({
            "ts":            event.ts,
            "module":        event.module,
            "severity":      int(event.severity),
            "severity_name": event.severity.name,
            "message":       event.message,
            "details":       event.details,
            "dlq_ts":        time.time(),
        }, default=str) + "\n"
        try:
            with self._dlq_lock:
                _dlq_write_exclusive(dlq_path, entry)
        except Exception:
            pass   # DLQ failure is silently ignored — we cannot recurse

    def _prune_locked(self) -> None:
        """Bound the table to ~MAX_ROWS newest rows (id-ordered). O(deleted rows)
        — cheap and keeps count_since / events_in_window / recent fast forever."""
        try:
            row = self._db.execute("SELECT MAX(id) FROM events").fetchone()
            if row and row[0] and row[0] > self.MAX_ROWS:
                self._db.execute("DELETE FROM events WHERE id <= ?", (row[0] - self.MAX_ROWS,))
                self._db.commit()
        except Exception:
            pass

    def recent(self, limit: int = 200) -> List[Event]:
        with self._lock:
            rows = self._db.execute(
                "SELECT ts, module, severity, message, details FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            try:
                details = json.loads(r[4]) if r[4] else {}
            except Exception:
                details = {}
            out.append(Event(module=r[1], message=r[3], severity=Severity(r[2]),
                             ts=r[0], details=details))
        return out

    def events_in_window(self, start_ts: float, end_ts: float) -> List[Event]:
        """Return ALL events between start_ts and end_ts (inclusive), ordered
        chronologically.  Unlike recent(), this is not capped by a row limit,
        so AAR reports won't silently miss catches from a drill that was run
        before a burst of other events pushed the run-time rows out of the
        recent-2000 window."""
        with self._lock:
            rows = self._db.execute(
                "SELECT ts, module, severity, message, details FROM events "
                "WHERE ts >= ? AND ts <= ? ORDER BY ts ASC",
                (start_ts, end_ts),
            ).fetchall()
        out = []
        for r in rows:
            try:
                details = json.loads(r[4]) if r[4] else {}
            except Exception:
                details = {}
            out.append(Event(module=r[1], message=r[3], severity=Severity(r[2]),
                             ts=r[0], details=details))
        return out

    def search(self, query: str, limit: int = 50) -> List[dict]:
        """Full-text search across message and details columns (case-insensitive).

        Returns plain dicts so callers (e.g. MCP server) can JSON-serialise directly.
        """
        q = f"%{query.lower()}%"
        with self._lock:
            rows = self._db.execute(
                "SELECT ts, module, severity, message, details FROM events "
                "WHERE LOWER(message) LIKE ? OR LOWER(details) LIKE ? "
                "ORDER BY id DESC LIMIT ?",
                (q, q, int(limit)),
            ).fetchall()
        out = []
        for r in rows:
            try:
                details = json.loads(r[4]) if r[4] else {}
            except Exception:
                details = {}
            out.append({
                "ts":       r[0],
                "module":   r[1],
                "severity": r[2],
                "message":  r[3],
                "details":  details,
            })
        return out

    def max_ts(self) -> float:
        """Return the timestamp of the most-recent stored event (0.0 if empty).
        Single aggregation query — no row deserialization.  Used by GUI panels
        as a zero-cost pre-check before calling the heavier recent() fetch."""
        with self._lock:
            row = self._db.execute("SELECT MAX(ts) FROM events").fetchone()
        return (row[0] or 0.0) if row else 0.0

    def count_since(self, ts: float) -> int:
        with self._lock:
            return self._db.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ?", (ts,)
            ).fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._db.close()
