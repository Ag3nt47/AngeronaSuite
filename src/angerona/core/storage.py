"""Flight recorder — an append-only SQLite ledger of every security event.

This is the tamper-evident audit trail. The GUI's Alerts page reads from here,
and it survives restarts so you can review what happened while you were away.
"""
from __future__ import annotations

import dataclasses
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import List

from angerona.core.eventbus import BusAuthority, Event, Severity


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
        self._authority = BusAuthority.load()
        self._lock     = threading.Lock()
        # GUI refreshes must never queue behind a busy SQLite writer. This
        # separately locked revision advances only after a committed insert
        # and any scheduled retention work have finished.
        self._revision_lock = threading.Lock()
        self._revision = 0
        self._dlq_lock = threading.Lock()   # separate lock — DLQ must never deadlock primary
        self._writes   = 0
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            # WAL + NORMAL sync: the old code fsync'd on EVERY event (a full disk
            # sync per insert — crippling at ~140 events/sec). WAL lets readers run
            # without blocking the writer and cuts fsyncs to checkpoints; NORMAL is
            # durable enough for telemetry. busy_timeout avoids "database locked".
            for pragma in (
                    "auto_vacuum=INCREMENTAL",
                    "journal_mode=WAL",
                    "synchronous=NORMAL",
                    "busy_timeout=3000",
                    "wal_autocheckpoint=1000",
                    "journal_size_limit=16777216"):
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
            columns = {
                row[1] for row in self._db.execute("PRAGMA table_info(events)").fetchall()
            }
            if "hmac_sig" not in columns:
                # Existing rows are retained as explicitly marked legacy records.
                self._db.execute(
                    "ALTER TABLE events ADD COLUMN hmac_sig TEXT NOT NULL DEFAULT ''"
                )
            self._db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_severity_id ON events(severity, id)"
            )
            self._db.commit()
            row = self._db.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
            self._revision = int(row[0] if row else 0)

    @property
    def authority(self) -> BusAuthority:
        """Signing authority shared with the live EventBus."""
        return self._authority

    @staticmethod
    def _details_json(details: dict) -> str:
        return json.dumps(
            details or {}, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, default=str,
        )

    def record(self, event: Event) -> None:
        """Write an event to SQLite, falling back to the DLQ on repeated lock failures.

        The WAL + busy_timeout=3000 pragma handles most transient locks internally.
        This retry loop catches edge cases (checkpoint races, backup processes) where
        the DB remains locked beyond that window.  After _DLQ_RETRIES failures the
        event is routed to dlq_events.json so no telemetry is silently dropped.
        """
        self._record(event, reuse_bus_signature=False)

    def record_bus(self, event: Event) -> None:
        """Persist an event delivered by an EventBus armed with ``authority``.

        The bus has already produced the authoritative signature, so the normal
        publish path can avoid repeating canonical JSON serialization and HMAC.
        Unsigned input is still signed defensively. Direct callers should use
        :meth:`record`, which preserves the independent-signing contract.
        """
        self._record(event, reuse_bus_signature=True)

    def _record(self, event: Event, reuse_bus_signature: bool) -> None:
        if not reuse_bus_signature or not event.hmac_sig:
            event = dataclasses.replace(event, hmac_sig=self._authority.sign(event))
        details_json = self._details_json(event.details)
        for attempt in range(self._DLQ_RETRIES):
            try:
                with self._lock:
                    cursor = self._db.execute(
                        "INSERT INTO events "
                        "(ts, module, severity, message, details, hmac_sig) "
                        "VALUES (?,?,?,?,?,?)",
                        (event.ts, event.module, int(event.severity), event.message,
                         details_json, event.hmac_sig),
                    )
                    self._db.commit()
                    self._writes += 1
                    if self._writes >= self.PRUNE_EVERY:
                        self._writes = 0
                        self._prune_locked()
                    with self._revision_lock:
                        self._revision = max(
                            self._revision, int(cursor.lastrowid or self._revision)
                        )
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
            "hmac_sig":      event.hmac_sig,
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
            row = self._db.execute("SELECT COUNT(*) FROM events").fetchone()
            excess = max(0, int(row[0] if row else 0) - int(self.MAX_ROWS))
            if excess:
                # Retire lower-severity chatter first so an INFO flood cannot
                # erase the entire HIGH/CRITICAL evidence window. If protected
                # evidence alone exceeds MAX_ROWS its oldest rows are retired,
                # preserving the hard disk bound.
                self._db.execute(
                    "DELETE FROM events WHERE id IN ("
                    "SELECT id FROM events ORDER BY "
                    "CASE WHEN severity >= ? THEN 1 ELSE 0 END ASC, id ASC LIMIT ?)",
                    (int(Severity.HIGH), excess),
                )
                self._db.commit()
                # DELETE alone leaves freed pages inside SQLite/WAL files, so
                # the old database kept occupying C: even though row retention
                # was active. Incremental vacuum plus a passive checkpoint
                # returns unused pages gradually without freezing writers.
                self._db.execute("PRAGMA incremental_vacuum(2000)")
                self._db.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except Exception:
            pass

    def recent(self, limit: int = 200) -> List[Event]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, ts, module, severity, message, details, hmac_sig "
                "FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._event_from_row(r) for r in rows]

    def revision(self) -> int:
        """Return the latest committed event id without touching SQLite.

        Dashboard timers use this as a change detector. Its independent lock
        is held only for an integer copy, so a retention checkpoint or burst of
        module writers cannot freeze the Qt thread.
        """
        with self._revision_lock:
            return self._revision

    def try_recent(self, limit: int = 200) -> List[Event] | None:
        """Return recent events only when the database is immediately free.

        ``None`` means a writer is busy and an interactive caller should keep
        its current view and retry on the next refresh. An empty list means the
        query completed and the ledger is empty.
        """
        if not self._lock.acquire(blocking=False):
            return None
        try:
            rows = self._db.execute(
                "SELECT id, ts, module, severity, message, details, hmac_sig "
                "FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        finally:
            self._lock.release()
        return [self._event_from_row(r) for r in rows]

    def events_in_window(self, start_ts: float, end_ts: float) -> List[Event]:
        """Return ALL events between start_ts and end_ts (inclusive), ordered
        chronologically.  Unlike recent(), this is not capped by a row limit,
        so AAR reports won't silently miss catches from a drill that was run
        before a burst of other events pushed the run-time rows out of the
        recent-2000 window."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, ts, module, severity, message, details, hmac_sig FROM events "
                "WHERE ts >= ? AND ts <= ? ORDER BY ts ASC",
                (start_ts, end_ts),
            ).fetchall()
        return [self._event_from_row(r) for r in rows]

    def recent_in_window(self, start_ts: float, end_ts: float,
                         min_severity: Severity = Severity.INFO,
                         limit: int = 500) -> List[Event]:
        """Return a bounded newest-first slice for interactive views."""
        limit = max(1, min(int(limit), 5000))
        with self._lock:
            rows = self._db.execute(
                "SELECT id, ts, module, severity, message, details, hmac_sig FROM events "
                "WHERE ts >= ? AND ts <= ? AND severity >= ? "
                "ORDER BY id DESC LIMIT ?",
                (start_ts, end_ts, int(min_severity), limit),
            ).fetchall()
        return [self._event_from_row(r) for r in rows]

    def search(self, query: str, limit: int = 50) -> List[dict]:
        """Full-text search across message and details columns (case-insensitive).

        Returns plain dicts so callers (e.g. MCP server) can JSON-serialise directly.
        """
        q = f"%{query.lower()}%"
        with self._lock:
            rows = self._db.execute(
                "SELECT id, ts, module, severity, message, details, hmac_sig FROM events "
                "WHERE LOWER(message) LIKE ? OR LOWER(details) LIKE ? "
                "ORDER BY id DESC LIMIT ?",
                (q, q, int(limit)),
            ).fetchall()
        out = []
        for r in rows:
            event = self._event_from_row(r)
            out.append({
                "ts": event.ts, "module": event.module,
                "severity": int(event.severity), "message": event.message,
                "details": event.details,
            })
        return out

    def _event_from_row(self, row) -> Event:
        """Decode and authenticate one ``id,ts,module,severity,message,details,sig`` row."""
        record_id, ts, module, severity, message, raw_details, sig = row
        try:
            details = json.loads(raw_details) if raw_details else {}
            if not isinstance(details, dict):
                raise ValueError("details is not an object")
            event = Event(
                module=str(module), message=str(message),
                severity=Severity(int(severity)), ts=float(ts),
                details=details, hmac_sig=str(sig or ""),
            )
        except Exception:
            return self._integrity_failure(record_id, ts, module, "malformed record")

        if not event.hmac_sig:
            marked = dict(event.details)
            marked["_ledger_integrity"] = "legacy-unsigned"
            return dataclasses.replace(
                event, details=marked,
                message=f"[UNSIGNED LEGACY] {event.message}",
            )
        if not self._authority.verify(event):
            return self._integrity_failure(record_id, ts, module, "invalid HMAC")
        return event

    @staticmethod
    def _integrity_failure(record_id, ts, module, reason: str) -> Event:
        try:
            event_ts = float(ts)
        except (TypeError, ValueError):
            event_ts = time.time()
        return Event(
            module="Flight Recorder",
            message=f"[INTEGRITY FAILURE] Stored event #{record_id} is not trusted ({reason}).",
            severity=Severity.CRITICAL,
            ts=event_ts,
            details={
                "_ledger_integrity": "invalid",
                "record_id": record_id,
                "stored_module": str(module),
                "reason": reason,
            },
        )

    def max_ts(self) -> float:
        """Return the timestamp of the most-recent stored event (0.0 if empty).
        Single aggregation query — no row deserialization.  Used by GUI panels
        as a zero-cost pre-check before calling the heavier recent() fetch."""
        with self._lock:
            row = self._db.execute("SELECT MAX(ts) FROM events").fetchone()
        return (row[0] or 0.0) if row else 0.0

    def max_ts_for_severity(self, min_severity: Severity) -> float:
        """Newest timestamp at or above a severity, without deserializing rows."""
        with self._lock:
            row = self._db.execute(
                "SELECT MAX(ts) FROM events WHERE severity >= ?",
                (int(min_severity),),
            ).fetchone()
        return (row[0] or 0.0) if row else 0.0

    def count_since(self, ts: float) -> int:
        with self._lock:
            return self._db.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ?", (ts,)
            ).fetchone()[0]

    def try_count_since(self, ts: float) -> int | None:
        """Return a count only if the writer lock is immediately available."""
        if not self._lock.acquire(blocking=False):
            return None
        try:
            row = self._db.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ?", (ts,)
            ).fetchone()
            return int(row[0] if row else 0)
        finally:
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            self._db.close()
