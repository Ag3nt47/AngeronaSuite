"""Flight recorder — an append-only SQLite ledger of every security event.

This is the tamper-evident audit trail. The GUI's Alerts page reads from here,
and it survives restarts so you can review what happened while you were away.
"""
from __future__ import annotations

import dataclasses
import json
import os
import queue
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable, List, NamedTuple

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
                os.lseek(fd, 0, os.SEEK_END)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, len(data))
                pending = memoryview(data)
                while pending:
                    written = os.write(fd, pending)
                    if written <= 0:
                        raise OSError("short DLQ write")
                    pending = pending[written:]
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
    # Authenticated spill spool. Active overflow is segmented so replay and
    # forensic tooling never need to load an unbounded file. The hard total
    # bound deliberately applies backpressure only after both in-memory lanes
    # and this local durable budget are exhausted; committed evidence is never
    # silently evicted to make room.
    DLQ_SEGMENT_BYTES = 2 * 1024 * 1024
    DLQ_MAX_SEGMENTS = 32
    DLQ_MAX_BYTES = 64 * 1024 * 1024
    DLQ_REPLAY_BATCH = 512

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
        self._dlq_capacity = threading.Condition(self._dlq_lock)
        # Capacity relief and periodic maintenance may request replay from
        # different workers.  Serialize the operation so a segment has exactly
        # one active reader/deleter even though receipt insertion is idempotent.
        self._dlq_replay_lock = threading.Lock()
        self._dlq_segment_serial = 0
        self._dlq_capacity_waits = 0
        self._dlq_capacity_wait_seconds = 0.0
        self._writes   = 0
        self._init_schema()
        # Interactive dashboard reads use their own read-only, zero-wait
        # connection. A non-blocking Python lock around the writer connection is
        # not sufficient: SQLite's busy handler can still sleep on an external
        # lock. WAL gives this connection the last committed snapshot while
        # timeout=0 guarantees the GUI skips a busy tick instead of freezing.
        self._ui_lock = threading.Lock()
        self._ui_db = sqlite3.connect(
            str(self._path), check_same_thread=False, timeout=0.0,
        )
        self._ui_db.execute("PRAGMA query_only=ON")
        self._ui_db.execute("PRAGMA busy_timeout=0")

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
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_hmac_sig ON events(hmac_sig)"
            )
            # A segment-scoped receipt closes the crash window between replay
            # commit and segment deletion. Receipts disappear only after the
            # corresponding segment is durably gone.
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS dlq_replay_receipts ("
                "hmac_sig TEXT PRIMARY KEY, segment TEXT NOT NULL, "
                "replayed_at REAL NOT NULL)"
            )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_dlq_receipt_segment "
                "ON dlq_replay_receipts(segment)"
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
                self._route_to_dlq(event)
                return

    def record_batch_bus(self, events: Iterable[Event]) -> "BatchRecordResult":
        """Persist bus-delivered events in one transaction.

        Unsigned input is signed defensively. If the transaction cannot be
        committed, every event is routed to the authenticated append-only DLQ.
        """
        prepared = [
            event if event.hmac_sig else dataclasses.replace(
                event, hmac_sig=self._authority.sign(event)
            )
            for event in events
        ]
        if not prepared:
            return BatchRecordResult(0, 0)
        rows = [
            (
                event.ts, event.module, int(event.severity), event.message,
                self._details_json(event.details), event.hmac_sig,
            )
            for event in prepared
        ]
        for attempt in range(self._DLQ_RETRIES):
            try:
                with self._lock:
                    self._db.executemany(
                        "INSERT INTO events "
                        "(ts, module, severity, message, details, hmac_sig) "
                        "VALUES (?,?,?,?,?,?)",
                        rows,
                    )
                    self._db.commit()
                    self._writes += len(rows)
                    if self._writes >= self.PRUNE_EVERY:
                        self._writes %= self.PRUNE_EVERY
                        self._prune_locked()
                    row = self._db.execute(
                        "SELECT COALESCE(MAX(id), 0) FROM events"
                    ).fetchone()
                    last_id = int(row[0] if row else 0)
                    with self._revision_lock:
                        self._revision = max(self._revision, last_id)
                return BatchRecordResult(len(prepared), 0)
            except sqlite3.OperationalError:
                try:
                    with self._lock:
                        self._db.rollback()
                except Exception:
                    pass
                if attempt < self._DLQ_RETRIES - 1:
                    time.sleep(self._DLQ_RETRY_DELAY)
                    continue
                break
            except Exception:
                try:
                    with self._lock:
                        self._db.rollback()
                except Exception:
                    pass
                break
        dlq = self._route_batch_to_dlq(prepared)
        return BatchRecordResult(0, dlq)

    def _route_to_dlq(self, event: Event) -> bool:
        """Append-only JSON fallback when the primary SQLite ledger is locked.

        Each line in dlq_events.json is a complete, self-contained JSON object
        (newline-delimited JSON / NDJSON format) for easy batch re-ingestion.

        G3-E TOCTOU fix: uses OS-level exclusive file locking (msvcrt on Windows,
        fcntl on POSIX) so an attacker process cannot interleave writes and corrupt
        the NDJSON structure.  The in-process self._dlq_lock is still held first to
        guard concurrent threads within the same process.
        """
        return self._route_batch_to_dlq((event,)) == 1

    @staticmethod
    def _dlq_entry(event: Event, dlq_ts: float) -> str:
        return json.dumps({
            "ts":            event.ts,
            "module":        event.module,
            "severity":      int(event.severity),
            "severity_name": event.severity.name,
            "message":       event.message,
            "details":       event.details,
            "hmac_sig":      event.hmac_sig,
            "dlq_ts":        dlq_ts,
        }, default=str) + "\n"

    def _route_batch_to_dlq(self, events: Iterable[Event]) -> int:
        """Append a batch under one file lock and one open/write cycle.

        The DLQ remains line-oriented and independently authenticated per event;
        batching changes only syscall and lock frequency. A failed aggregate
        append reports zero so callers can surface the durability failure rather
        than silently claiming partial success.
        """
        prepared = list(events)
        if not prepared:
            return 0
        dlq_ts = time.time()
        entries = [self._dlq_entry(event, dlq_ts) for event in prepared]
        written = 0
        chunk: list[str] = []
        chunk_bytes = 0
        for entry in entries:
            entry_bytes = len(entry.encode("utf-8"))
            if chunk and chunk_bytes + entry_bytes > self.DLQ_SEGMENT_BYTES:
                if not self._append_dlq_chunk("".join(chunk), chunk_bytes):
                    return written
                written += len(chunk)
                chunk = []
                chunk_bytes = 0
            chunk.append(entry)
            chunk_bytes += entry_bytes
        if chunk and self._append_dlq_chunk("".join(chunk), chunk_bytes):
            written += len(chunk)
        return written

    def _active_dlq_path(self) -> Path:
        return self._path.parent / "dlq_events.json"

    def _segment_paths_locked(self, *, include_quarantine: bool = True) -> list[Path]:
        patterns = ["dlq-*.ndjson"]
        if include_quarantine:
            patterns.append("dlq-quarantine-*.ndjson")
        paths: dict[str, Path] = {}
        for pattern in patterns:
            for path in self._path.parent.glob(pattern):
                paths[str(path)] = path
        active = self._active_dlq_path()
        if active.exists():
            paths[str(active)] = active
        return sorted(paths.values(), key=lambda path: path.name)

    @staticmethod
    def _paths_bytes(paths: Iterable[Path]) -> int:
        total = 0
        for path in paths:
            try:
                total += max(0, int(path.stat().st_size))
            except OSError:
                continue
        return total

    def _next_segment_path_locked(self) -> Path:
        while True:
            self._dlq_segment_serial += 1
            candidate = self._path.parent / (
                f"dlq-{time.time_ns()}-{os.getpid()}-"
                f"{self._dlq_segment_serial}.ndjson"
            )
            if not candidate.exists():
                return candidate

    def _rotate_active_dlq_locked(self) -> Path | None:
        active = self._active_dlq_path()
        try:
            if not active.exists() or active.stat().st_size <= 0:
                return None
            segment = self._next_segment_path_locked()
            os.replace(active, segment)
            return segment
        except OSError:
            return None

    def _append_dlq_chunk(self, entry: str, entry_bytes: int) -> bool:
        """Append one bounded chunk, waiting only at the catastrophic disk cap.

        Under normal floods callers enter this method only on the dedicated DLQ
        worker. If the hard spool budget is exhausted, the condition wait
        releases the file lock so the primary worker can replay and free a
        committed segment. This is the unavoidable fail-closed boundary: no
        evidence is discarded and disk use cannot grow without limit.
        """
        if entry_bytes <= 0 or entry_bytes > self.DLQ_MAX_BYTES:
            return False
        waited_at: float | None = None
        while True:
            needs_capacity = False
            try:
                with self._dlq_capacity:
                    active = self._active_dlq_path()
                    paths = self._segment_paths_locked()
                    total_bytes = self._paths_bytes(paths)
                    active_size = (
                        int(active.stat().st_size) if active.exists() else 0
                    )
                    rotate = bool(
                        active_size
                        and active_size + entry_bytes > self.DLQ_SEGMENT_BYTES
                    )
                    active_exists = active in paths
                    projected_count = len(paths)
                    if rotate:
                        projected_count += 1
                    elif not active_exists:
                        projected_count += 1
                    fits = (
                        projected_count <= self.DLQ_MAX_SEGMENTS
                        and total_bytes + entry_bytes <= self.DLQ_MAX_BYTES
                    )
                    if fits:
                        if waited_at is not None:
                            self._dlq_capacity_wait_seconds += (
                                time.monotonic() - waited_at
                            )
                        if rotate and self._rotate_active_dlq_locked() is None:
                            return False
                        _dlq_write_exclusive(active, entry)
                        if active.stat().st_size >= self.DLQ_SEGMENT_BYTES:
                            self._rotate_active_dlq_locked()
                        return True
                    if waited_at is None:
                        waited_at = time.monotonic()
                        self._dlq_capacity_waits += 1
                    needs_capacity = True
            except Exception:
                return False

            # Do not wait for the primary recorder to become idle: during a
            # sustained flood its idle-only maintenance path may never run, and
            # the overflow worker itself is marked busy.  Replaying one segment
            # here releases durable capacity without discarding signed evidence.
            if needs_capacity:
                try:
                    relieved = self.replay_dlq(max_segments=1)
                except Exception:
                    relieved = None
                if relieved is not None and relieved.segments_completed:
                    continue
                with self._dlq_capacity:
                    self._dlq_capacity.wait(timeout=0.25)

    def replay_dlq(self, *, max_segments: int = 1) -> "DLQReplayResult":
        """Serialize authenticated replay requested by maintenance or capacity."""
        with self._dlq_replay_lock:
            return self._replay_dlq_unlocked(max_segments=max_segments)

    def dlq_status(self) -> dict[str, int | float]:
        """Return an observable bounded-spool snapshot."""
        with self._dlq_lock:
            paths = self._segment_paths_locked()
            quarantine = [
                path for path in paths if path.name.startswith("dlq-quarantine-")
            ]
            return {
                "segments": len(paths),
                "bytes": self._paths_bytes(paths),
                "max_segments": int(self.DLQ_MAX_SEGMENTS),
                "max_bytes": int(self.DLQ_MAX_BYTES),
                "quarantine_segments": len(quarantine),
                "quarantine_bytes": self._paths_bytes(quarantine),
                "capacity_waits": int(self._dlq_capacity_waits),
                "capacity_wait_seconds": float(self._dlq_capacity_wait_seconds),
            }

    def _decode_dlq_event(self, raw: str) -> Event | None:
        """Decode and authenticate one spool line without trusting its metadata."""
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                return None
            details = payload.get("details") or {}
            if not isinstance(details, dict):
                return None
            event = Event(
                ts=float(payload["ts"]),
                module=str(payload["module"]),
                severity=Severity(int(payload["severity"])),
                message=str(payload["message"]),
                details=details,
                hmac_sig=str(payload.get("hmac_sig") or ""),
            )
            if not self._authority.verify(event):
                return None
            return event
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _insert_replay_batch(
        self, events: list[Event], segment: str,
    ) -> tuple[int, int] | None:
        """Idempotently commit one verified segment batch.

        Returns ``(new rows, already committed rows)``. No DLQ fallback occurs
        here: on failure the source segment remains authoritative and untouched.
        """
        if not events:
            return (0, 0)
        for attempt in range(self._DLQ_RETRIES):
            try:
                with self._lock:
                    # Deduplicate signatures inside this batch, then use one
                    # indexed membership query instead of two SELECTs per row.
                    # This keeps replay O(batch) in Python and a fixed number of
                    # SQLite statements per batch rather than an N+1 query loop.
                    unique = {event.hmac_sig: event for event in events}
                    signatures = list(unique)
                    placeholders = ",".join("?" for _ in signatures)
                    prior_receipts = {
                        str(row[0]) for row in self._db.execute(
                            f"SELECT hmac_sig FROM dlq_replay_receipts "
                            f"WHERE segment=? AND hmac_sig IN ({placeholders})",  # nosec B608
                            [segment, *signatures],
                        ).fetchall()
                    }
                    candidates = [
                        signature for signature in signatures
                        if signature not in prior_receipts
                    ]
                    stamp = time.time()
                    self._db.executemany(
                        "INSERT OR IGNORE INTO dlq_replay_receipts "
                        "(hmac_sig, segment, replayed_at) VALUES (?,?,?)",
                        ((signature, segment, stamp) for signature in signatures),
                    )
                    existing: set[str] = set()
                    if candidates:
                        candidate_placeholders = ",".join("?" for _ in candidates)
                        existing = {
                            str(row[0]) for row in self._db.execute(
                                f"SELECT hmac_sig FROM events WHERE hmac_sig IN "
                                f"({candidate_placeholders})",  # nosec B608
                                candidates,
                            ).fetchall()
                        }
                    missing = [
                        unique[signature]
                        for signature in candidates
                        if signature not in existing
                    ]
                    self._db.executemany(
                        "INSERT INTO events "
                        "(ts, module, severity, message, details, hmac_sig) "
                        "VALUES (?,?,?,?,?,?)",
                        (
                            (
                                event.ts, event.module, int(event.severity),
                                event.message, self._details_json(event.details),
                                event.hmac_sig,
                            )
                            for event in missing
                        ),
                    )
                    inserted = len(missing)
                    duplicates = len(events) - inserted
                    self._db.commit()
                    self._writes += inserted
                    if self._writes >= self.PRUNE_EVERY:
                        self._writes %= self.PRUNE_EVERY
                        self._prune_locked()
                    row = self._db.execute(
                        "SELECT COALESCE(MAX(id), 0) FROM events"
                    ).fetchone()
                    with self._revision_lock:
                        self._revision = max(
                            self._revision, int(row[0] if row else 0)
                        )
                return inserted, duplicates
            except sqlite3.OperationalError:
                try:
                    with self._lock:
                        self._db.rollback()
                except Exception:
                    pass
                if attempt < self._DLQ_RETRIES - 1:
                    time.sleep(self._DLQ_RETRY_DELAY)
            except Exception:
                try:
                    with self._lock:
                        self._db.rollback()
                except Exception:
                    pass
                return None
        return None

    def _remove_replay_receipts(self, segment: str) -> None:
        try:
            with self._lock:
                self._db.execute(
                    "DELETE FROM dlq_replay_receipts WHERE segment=?", (segment,)
                )
                self._db.commit()
        except Exception:
            pass

    @staticmethod
    def _write_private_text(path: Path, text: str) -> None:
        data = text.encode("utf-8")
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            pending = memoryview(data)
            while pending:
                written = os.write(fd, pending)
                if written <= 0:
                    raise OSError("short quarantine write")
                pending = pending[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def _replay_dlq_unlocked(self, *, max_segments: int = 1) -> "DLQReplayResult":
        """Authenticate and idempotently re-ingest bounded spill segments.

        The active file is first atomically rotated. Valid lines are streamed in
        fixed-size batches. Forged or malformed raw lines are retained in a
        quarantine segment and never rendered or executed. A source segment is
        deleted only after every valid line is committed/already present and
        every invalid line has been durably quarantined.
        """
        max_segments = max(1, min(int(max_segments), self.DLQ_MAX_SEGMENTS))
        with self._dlq_capacity:
            self._rotate_active_dlq_locked()
            segments = [
                path for path in self._segment_paths_locked(include_quarantine=False)
                if path.name.startswith("dlq-")
                and not path.name.startswith("dlq-quarantine-")
            ][:max_segments]

        processed = 0
        inserted = 0
        duplicates = 0
        quarantined = 0
        completed = 0
        failures = 0
        for segment in segments:
            invalid_lines: list[str] = []
            batch: list[Event] = []
            segment_ok = True
            try:
                with segment.open("r", encoding="utf-8", errors="replace") as stream:
                    for raw in stream:
                        processed += 1
                        event = self._decode_dlq_event(raw)
                        if event is None:
                            invalid_lines.append(
                                raw if raw.endswith("\n") else raw + "\n"
                            )
                            quarantined += 1
                            continue
                        batch.append(event)
                        if len(batch) >= self.DLQ_REPLAY_BATCH:
                            result = self._insert_replay_batch(batch, segment.name)
                            if result is None:
                                segment_ok = False
                                break
                            inserted += result[0]
                            duplicates += result[1]
                            batch.clear()
                if segment_ok and batch:
                    result = self._insert_replay_batch(batch, segment.name)
                    if result is None:
                        segment_ok = False
                    else:
                        inserted += result[0]
                        duplicates += result[1]
            except (OSError, UnicodeError):
                segment_ok = False

            if not segment_ok:
                failures += 1
                continue

            quarantine_path: Path | None = None
            if invalid_lines:
                suffix = segment.name.removeprefix("dlq-")
                quarantine_path = segment.with_name(
                    f"dlq-quarantine-{suffix}"
                )
                temp = quarantine_path.with_name(
                    quarantine_path.name + f".{os.getpid()}.tmp"
                )
                try:
                    try:
                        temp.unlink()
                    except FileNotFoundError:
                        pass
                    self._write_private_text(temp, "".join(invalid_lines))
                    os.replace(temp, quarantine_path)
                except OSError:
                    failures += 1
                    try:
                        temp.unlink()
                    except OSError:
                        pass
                    continue
            try:
                segment.unlink()
            except OSError:
                failures += 1
                continue
            self._remove_replay_receipts(segment.name)
            completed += 1
            with self._dlq_capacity:
                self._dlq_capacity.notify_all()

        return DLQReplayResult(
            processed=processed,
            inserted=inserted,
            duplicates=duplicates,
            quarantined=quarantined,
            segments_completed=completed,
            failures=failures,
        )

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
        # Preserve the established "writer busy -> skip this tick" contract.
        # The separate connection below additionally prevents SQLite's own busy
        # handler from sleeping after this cheap in-process check succeeds.
        if not self._lock.acquire(blocking=False):
            return None
        self._lock.release()
        if not self._ui_lock.acquire(blocking=False):
            return None
        try:
            rows = self._ui_db.execute(
                "SELECT id, ts, module, severity, message, details, hmac_sig "
                "FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        except sqlite3.OperationalError:
            return None
        finally:
            self._ui_lock.release()
        return [self._event_from_row(r) for r in rows]

    def try_recent_in_window(
        self,
        start_ts: float,
        end_ts: float,
        min_severity: Severity = Severity.INFO,
        limit: int = 500,
    ) -> List[Event] | None:
        """Return a bounded window only when the UI reader is immediately free.

        Interactive dialogs must never wait behind a telemetry burst, retention
        checkpoint, or another dashboard reader. ``None`` tells the caller to
        keep its current view (or use the in-memory bus) and retry later.
        """
        limit = max(1, min(int(limit), 5000))
        if not self._lock.acquire(blocking=False):
            return None
        self._lock.release()
        if not self._ui_lock.acquire(blocking=False):
            return None
        try:
            rows = self._ui_db.execute(
                "SELECT id, ts, module, severity, message, details, hmac_sig FROM events "
                "WHERE ts >= ? AND ts <= ? AND severity >= ? "
                "ORDER BY id DESC LIMIT ?",
                (start_ts, end_ts, int(min_severity), limit),
            ).fetchall()
        except sqlite3.OperationalError:
            return None
        finally:
            self._ui_lock.release()
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
        self._lock.release()
        if not self._ui_lock.acquire(blocking=False):
            return None
        try:
            row = self._ui_db.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ?", (ts,)
            ).fetchone()
            return int(row[0] if row else 0)
        except sqlite3.OperationalError:
            return None
        finally:
            self._ui_lock.release()

    def close(self) -> None:
        with self._ui_lock:
            self._ui_db.close()
        with self._lock:
            self._db.close()


class BatchRecordResult(NamedTuple):
    persisted: int
    dlq: int


class DLQReplayResult(NamedTuple):
    processed: int
    inserted: int
    duplicates: int
    quarantined: int
    segments_completed: int
    failures: int


@dataclasses.dataclass(frozen=True)
class AsyncRecorderMetrics:
    accepted: int
    persisted: int
    overflow_dlq: int
    storage_dlq: int
    dlq_failures: int
    queue_depth: int
    queue_capacity: int
    overflow_queue_depth: int
    overflow_queue_capacity: int
    overflow_queued: int
    overflow_synchronous: int
    replayed: int
    replay_duplicates: int
    replay_quarantined: int
    replay_failures: int
    spool_segments: int
    spool_bytes: int
    spool_max_segments: int
    spool_max_bytes: int
    spool_quarantine_segments: int
    spool_quarantine_bytes: int
    spool_capacity_waits: int
    spool_capacity_wait_seconds: float
    batches: int
    running: bool


class _BoundedSimpleQueue:
    """C-backed queue with an exact non-blocking capacity gate.

    ``queue.Queue`` uses a Python ``Condition`` around every put/get. Under a
    multi-publisher telemetry burst that lock convoy dominated the callback
    even though the overflow consumer was keeping up. ``SimpleQueue`` supplies
    the thread-safe C fast path while a bounded semaphore retains the same hard
    memory limit and ``queue.Full`` fallback contract.
    """

    def __init__(self, maxsize: int) -> None:
        self.maxsize = int(maxsize)
        self._slots = threading.BoundedSemaphore(self.maxsize)
        self._queue: queue.SimpleQueue[Event] = queue.SimpleQueue()

    def put_nowait(self, event: Event) -> None:
        if not self._slots.acquire(blocking=False):
            raise queue.Full
        try:
            self._queue.put(event)
        except Exception:
            # ``SimpleQueue.put`` is normally infallible apart from allocation
            # failure.  Preserve the exact capacity gate if an interpreter or
            # test double does raise so one failed handoff cannot leak a slot.
            self._slots.release()
            raise

    def get(self, timeout: float | None = None) -> Event:
        event = self._queue.get(timeout=timeout)
        self._slots.release()
        return event

    def get_nowait(self) -> Event:
        return self.get(timeout=0.0)

    def empty(self) -> bool:
        return self._queue.empty()

    def qsize(self) -> int:
        return self._queue.qsize()

    @staticmethod
    def task_done() -> None:
        # AsyncFlightRecorder owns drain completion through worker joins and
        # never calls Queue.join(); retain the narrow queue surface it uses.
        return None


class AsyncFlightRecorder:
    """Bounded worker-owned persistence adapter for EventBus subscribers.

    ``submit`` never touches SQLite. The normal path is a non-blocking queue
    operation. Primary-queue overflow enters a second bounded lane whose worker
    preserves signed events in append-only DLQ batches. Only exhaustion of both
    bounded lanes uses a synchronous DLQ append, preserving evidence without
    allowing an unbounded memory backlog. SQLite calls remain single-writer.
    """

    def __init__(
        self,
        recorder: FlightRecorder,
        *,
        queue_capacity: int = 4096,
        batch_size: int = 128,
        flush_interval: float = 0.10,
        overflow_queue_capacity: int = 8192,
        dlq_batch_size: int = 1024,
    ) -> None:
        if queue_capacity < 1:
            raise ValueError("queue_capacity must be positive")
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        if flush_interval <= 0:
            raise ValueError("flush_interval must be positive")
        if overflow_queue_capacity < 1:
            raise ValueError("overflow_queue_capacity must be positive")
        if dlq_batch_size < 1:
            raise ValueError("dlq_batch_size must be positive")
        self._recorder = recorder
        # The normal EventBus subscriber path is hotter than the overflow
        # lane.  It does not use Queue.join(), so retain the same exact bounded
        # capacity while avoiding queue.Queue's Condition convoy for every
        # producer handoff.  The worker still drains and persists identical
        # ordered Event objects, and saturation still falls through to the
        # authenticated overflow lane.
        self._queue = _BoundedSimpleQueue(queue_capacity)
        self._overflow_queue = _BoundedSimpleQueue(overflow_queue_capacity)
        self._batch_size = min(int(batch_size), int(queue_capacity))
        self._dlq_batch_size = min(
            int(dlq_batch_size), int(overflow_queue_capacity)
        )
        self._flush_interval = float(flush_interval)
        self._state_lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._stop = threading.Event()
        # Avoid raising ``queue.Full`` for every publisher while the primary
        # writer is known to be saturated. The recorder worker clears this as
        # soon as it consumes an item; overflow remains bounded and durable.
        self._primary_saturated = threading.Event()
        self._dlq_done = threading.Event()
        self._dlq_busy = threading.Event()
        self._thread: threading.Thread | None = None
        self._dlq_thread: threading.Thread | None = None
        self._accepted = 0
        self._persisted = 0
        self._overflow_dlq = 0
        self._storage_dlq = 0
        self._dlq_failures = 0
        self._overflow_queued = 0
        self._overflow_synchronous = 0
        self._replayed = 0
        self._replay_duplicates = 0
        self._replay_quarantined = 0
        self._replay_failures = 0
        self._last_replay_at = 0.0
        self._batches = 0

    def start(self) -> bool:
        """Start the worker once; return False if it is already running."""
        with self._state_lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop.clear()
            self._primary_saturated.clear()
            self._dlq_done.clear()
            self._dlq_busy.clear()
            self._dlq_thread = threading.Thread(
                target=self._run_dlq,
                name="angerona-flight-dlq",
                daemon=True,
            )
            self._thread = threading.Thread(
                target=self._run,
                name="angerona-flight-recorder",
                daemon=True,
            )
            self._dlq_thread.start()
            self._thread.start()
            return True

    def submit(self, event: Event) -> None:
        """Non-blocking subscriber callback. No SQLite operation occurs here."""
        if not event.hmac_sig:
            event = dataclasses.replace(
                event, hmac_sig=self._recorder.authority.sign(event)
            )
        # Lifecycle publishes these references while holding ``_state_lock``
        # and sets ``_stop`` before joining either worker. A snapshot avoids a
        # global lifecycle-lock convoy across independent EventBus publishers;
        # any concurrent stop falls through to the durable synchronous lane.
        thread = self._thread
        dlq_thread = self._dlq_thread
        running = thread is not None and thread.is_alive()
        dlq_running = dlq_thread is not None and dlq_thread.is_alive()
        if (
            running
            and not self._stop.is_set()
            and not self._primary_saturated.is_set()
        ):
            try:
                self._queue.put_nowait(event)
                with self._metrics_lock:
                    self._accepted += 1
                return
            except queue.Full:
                self._primary_saturated.set()
        if dlq_running and not self._stop.is_set():
            try:
                self._overflow_queue.put_nowait(event)
                with self._metrics_lock:
                    self._overflow_queued += 1
                return
            except queue.Full:
                # A full observation can race the C-backed consumer releasing
                # a slot. Yield once and make one bounded retry before taking
                # the much slower synchronous evidence path. A genuinely
                # exhausted lane still falls through without an unbounded wait.
                time.sleep(0)
                try:
                    self._overflow_queue.put_nowait(event)
                    with self._metrics_lock:
                        self._overflow_queued += 1
                    return
                except queue.Full:
                    pass
        written = self._recorder._route_to_dlq(event)
        with self._metrics_lock:
            if written:
                self._overflow_dlq += 1
                self._overflow_synchronous += 1
            else:
                self._dlq_failures += 1

    def stop(self, timeout: float = 5.0) -> bool:
        """Request a drain and wait a bounded time; safe to call repeatedly."""
        timeout = max(0.0, float(timeout))
        with self._state_lock:
            thread = self._thread
            dlq_thread = self._dlq_thread
            if thread is None and dlq_thread is None:
                return True
            self._stop.set()
        deadline = time.monotonic() + timeout
        current = threading.current_thread()
        for candidate in (thread, dlq_thread):
            if candidate is None or candidate is current:
                continue
            candidate.join(max(0.0, deadline - time.monotonic()))
        stopped = all(
            candidate is None or not candidate.is_alive()
            for candidate in (thread, dlq_thread)
        )
        if stopped:
            with self._state_lock:
                if self._thread is thread:
                    self._thread = None
                if self._dlq_thread is dlq_thread:
                    self._dlq_thread = None
        return stopped

    def metrics(self) -> AsyncRecorderMetrics:
        with self._state_lock:
            running = bool(
                self._thread is not None
                and self._thread.is_alive()
                and self._dlq_thread is not None
                and self._dlq_thread.is_alive()
            )
        status_reader = getattr(self._recorder, "dlq_status", None)
        try:
            spool = status_reader() if callable(status_reader) else {}
        except Exception:
            spool = {}
        with self._metrics_lock:
            return AsyncRecorderMetrics(
                accepted=self._accepted,
                persisted=self._persisted,
                overflow_dlq=self._overflow_dlq,
                storage_dlq=self._storage_dlq,
                dlq_failures=self._dlq_failures,
                queue_depth=self._queue.qsize(),
                queue_capacity=self._queue.maxsize,
                overflow_queue_depth=self._overflow_queue.qsize(),
                overflow_queue_capacity=self._overflow_queue.maxsize,
                overflow_queued=self._overflow_queued,
                overflow_synchronous=self._overflow_synchronous,
                replayed=self._replayed,
                replay_duplicates=self._replay_duplicates,
                replay_quarantined=self._replay_quarantined,
                replay_failures=self._replay_failures,
                spool_segments=int(spool.get("segments", 0)),
                spool_bytes=int(spool.get("bytes", 0)),
                spool_max_segments=int(spool.get("max_segments", 0)),
                spool_max_bytes=int(spool.get("max_bytes", 0)),
                spool_quarantine_segments=int(
                    spool.get("quarantine_segments", 0)
                ),
                spool_quarantine_bytes=int(spool.get("quarantine_bytes", 0)),
                spool_capacity_waits=int(spool.get("capacity_waits", 0)),
                spool_capacity_wait_seconds=float(
                    spool.get("capacity_wait_seconds", 0.0)
                ),
                batches=self._batches,
                running=running,
            )

    def _run(self) -> None:
        while (
            not self._stop.is_set()
            or not self._queue.empty()
            or not self._dlq_done.is_set()
        ):
            batch: list[Event] = []
            try:
                batch.append(self._queue.get(timeout=self._flush_interval))
                self._primary_saturated.clear()
            except queue.Empty:
                self._maybe_replay()
                continue
            deadline = time.monotonic() + self._flush_interval
            while len(batch) < self._batch_size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    batch.append(self._queue.get(timeout=remaining))
                except queue.Empty:
                    break
            result = self._recorder.record_batch_bus(batch)
            with self._metrics_lock:
                self._persisted += result.persisted
                self._storage_dlq += result.dlq
                self._dlq_failures += len(batch) - result.persisted - result.dlq
                self._batches += 1
            for _ in batch:
                self._queue.task_done()
            if self._queue.empty():
                self._maybe_replay()
        # One bounded final maintenance pass after the overflow writer drained.
        self._maybe_replay(force=True)

    def _maybe_replay(self, *, force: bool = False) -> None:
        replay = getattr(self._recorder, "replay_dlq", None)
        if not callable(replay):
            return
        now = time.monotonic()
        if not force and now - self._last_replay_at < 2.0:
            return
        if not force and (
            not self._queue.empty()
            or not self._overflow_queue.empty()
            or self._dlq_busy.is_set()
        ):
            return
        self._last_replay_at = now
        try:
            result = replay(max_segments=1)
        except Exception:
            with self._metrics_lock:
                self._replay_failures += 1
            return
        with self._metrics_lock:
            self._replayed += int(result.inserted)
            self._replay_duplicates += int(result.duplicates)
            self._replay_quarantined += int(result.quarantined)
            self._replay_failures += int(result.failures)

    def _run_dlq(self) -> None:
        """Drain overflow evidence in batches without blocking publishers."""
        try:
            while not self._stop.is_set() or not self._overflow_queue.empty():
                batch: list[Event] = []
                try:
                    batch.append(
                        self._overflow_queue.get(timeout=self._flush_interval)
                    )
                except queue.Empty:
                    continue
                self._dlq_busy.set()
                while len(batch) < self._dlq_batch_size:
                    try:
                        batch.append(self._overflow_queue.get_nowait())
                    except queue.Empty:
                        break
                batch_writer = getattr(self._recorder, "_route_batch_to_dlq", None)
                if callable(batch_writer):
                    written = int(batch_writer(batch))
                else:
                    written = sum(
                        1 for event in batch if self._recorder._route_to_dlq(event)
                    )
                with self._metrics_lock:
                    self._overflow_dlq += written
                    self._dlq_failures += len(batch) - written
                for _ in batch:
                    self._overflow_queue.task_done()
                self._dlq_busy.clear()
        finally:
            self._dlq_busy.clear()
            self._dlq_done.set()
