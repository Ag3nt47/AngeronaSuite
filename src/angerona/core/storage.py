"""Flight recorder — an append-only SQLite ledger of every security event.

This is the tamper-evident audit trail. The GUI's Alerts page reads from here,
and it survives restarts so you can review what happened while you were away.
"""
from __future__ import annotations

import dataclasses
from contextlib import contextmanager
import json
import os
import queue
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable, List, NamedTuple

from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.telemetry_storage_policy import (
    RecorderStorageHeld, StorageWriteProgress, STORAGE_UNIT_BYTES, TelemetryStorageBudget,
)


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


class RecorderInitializationPending(RuntimeError):
    """A failed constructor retains an ambiguously closed connection owner."""

    def __init__(self, owner):
        super().__init__("Recorder construction failed and connection retirement remains unproven")
        self.owner = owner
        self.recorder_retirement_pending = True


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
        self._storage_budget = TelemetryStorageBudget(self._path)
        self._storage_runtime_lock = threading.Lock()
        self._storage_runtime = None
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = self._ui_db = None
        self._failed_initialization_connections = ()
        try:
            self._open_connections()
        except BaseException as original:
            pending = []
            for name in ("_ui_db", "_db"):
                owned = getattr(self, name)
                setattr(self, name, None)
                if owned is not None:
                    try:
                        owned.close()
                    except BaseException:
                        # Retain the actual connection object; no constructor
                        # caller received ownership and no retry is inferred.
                        pending.append(owned)
            self._failed_initialization_connections = tuple(pending)
            if pending:
                raise RecorderInitializationPending(self) from original
            raise

    def _open_connections(self) -> None:
        # check_same_thread=False: the bus may publish from any module thread.
        self._db = sqlite3.connect(str(self._path), check_same_thread=False)
        self._authority = BusAuthority.load()
        self._lock     = threading.Lock()
        # GUI refreshes must never queue behind a busy SQLite writer. This
        # separately locked revision advances after a committed insert, before
        # optional retention work. It remains a committed-id high-water mark
        # even if retention immediately removes that event.
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

    def configure_storage_policy(self, *, blocked: bool, db_target_bytes: int,
                                 wal_target_bytes: int, min_free_bytes: int) -> dict:
        result = self._storage_budget.configure(blocked=blocked, db_target_bytes=db_target_bytes,
            wal_target_bytes=wal_target_bytes, min_free_bytes=min_free_bytes)
        runtime = self._storage_runtime
        if result["accepted"] and runtime is not None:
            runtime._storage_policy_changed()
        return result

    def storage_budget_snapshot(self) -> dict:
        return self._storage_budget.snapshot()

    def held_unit_review(self, lane: str) -> dict:
        runtime = self._storage_runtime
        if runtime is None:
            return {"schema": 1, "available": False, "reason_code": "worker_unavailable"}
        return runtime.held_unit_review(lane)

    def discard_held_unit(self, **request) -> dict:
        runtime = self._storage_runtime
        if runtime is None:
            return {"schema": 1, "accepted": False, "reason_code": "worker_unavailable", "discarded_events": 0}
        return runtime.discard_held_unit(**request)

    def _storage_unit_bytes(self, events) -> int:
        if not self._storage_budget.configured:
            return 0
        stamp = time.time()
        sql_bytes = 0
        dlq_bytes = 0
        for event in events:
            sql_bytes += 32 + sum(len(value.encode("utf-8")) for value in (
                event.module, event.message, self._details_json(event.details), event.hmac_sig))
            dlq_bytes += len(self._dlq_entry(event, stamp).encode("utf-8"))
        return max(sql_bytes, dlq_bytes)

    def _storage_refresh_on_worker(self):
        self._storage_budget.refresh_on_worker()
        runtime = self._storage_runtime
        if runtime is not None:
            runtime._storage_probe_published()

    @contextmanager
    def _storage_admission(self, unit_bytes: int, shared=None):
        lease = self._storage_budget.admit(unit_bytes) if shared is None else shared
        try:
            yield lease
        finally:
            if shared is None:
                self._storage_budget.release(lease, wrote=True)

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
        lease = None
        admitted = False
        persistence_unknown = False
        try:
            for attempt in range(self._DLQ_RETRIES):
                with self._lock:
                    if not admitted:
                        lease = self._storage_budget.admit(self._storage_unit_bytes((event,)))
                        admitted = True
                    try:
                        committing = False
                        cursor = self._db.execute(
                            "INSERT INTO events "
                            "(ts, module, severity, message, details, hmac_sig) "
                            "VALUES (?,?,?,?,?,?)",
                            (event.ts, event.module, int(event.severity), event.message,
                             details_json, event.hmac_sig),
                        )
                        last_id = int(cursor.lastrowid or 0)
                        committing = True
                        self._db.commit()
                    except sqlite3.OperationalError:
                        persistence_unknown = persistence_unknown or committing
                        self._rollback_locked()
                        retry = True
                    except RecorderStorageHeld:
                        self._rollback_locked()
                        raise
                    except Exception:
                        persistence_unknown = persistence_unknown or committing
                        self._rollback_locked()
                        retry = False
                    else:
                        self._after_insert_commit_locked(1, last_id)
                        return
                if retry and attempt < self._DLQ_RETRIES - 1:
                    time.sleep(self._DLQ_RETRY_DELAY)
                else:
                    break
            if lease is None:
                self._route_to_dlq(event)
            else:
                self._route_to_dlq(event, _storage_lease=lease)
        except RecorderStorageHeld as held:
            if persistence_unknown:
                raise RecorderStorageHeld(held.reason, held.policy_generation,
                    progress=dataclasses.replace(held.progress, persistence_unknown=True),
                    replay_progress=held.replay_progress, unit_bytes=held.unit_bytes) from None
            raise
        finally:
            self._storage_budget.release(lease, wrote=admitted)

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
        lease = None
        admitted = False
        persistence_unknown = False
        try:
            for attempt in range(self._DLQ_RETRIES):
                with self._lock:
                    if not admitted:
                        lease = self._storage_budget.admit(self._storage_unit_bytes(prepared))
                        admitted = True
                    try:
                        committing = False
                        self._db.executemany(
                            "INSERT INTO events "
                            "(ts, module, severity, message, details, hmac_sig) "
                            "VALUES (?,?,?,?,?,?)",
                            rows,
                        )
                        row = self._db.execute(
                            "SELECT COALESCE(MAX(id), 0) FROM events"
                        ).fetchone()
                        last_id = int(row[0] if row else 0)
                        committing = True
                        self._db.commit()
                    except sqlite3.OperationalError:
                        persistence_unknown = persistence_unknown or committing
                        self._rollback_locked()
                        retry = True
                    except RecorderStorageHeld:
                        self._rollback_locked()
                        raise
                    except Exception:
                        persistence_unknown = persistence_unknown or committing
                        self._rollback_locked()
                        retry = False
                    else:
                        self._after_insert_commit_locked(len(rows), last_id)
                        return BatchRecordResult(len(prepared), 0)
                if retry and attempt < self._DLQ_RETRIES - 1:
                    time.sleep(self._DLQ_RETRY_DELAY)
                else:
                    break
            dlq = (self._route_batch_to_dlq(prepared) if lease is None else
                   self._route_batch_to_dlq(prepared, _storage_lease=lease))
            return BatchRecordResult(0, dlq)
        except RecorderStorageHeld as held:
            if persistence_unknown:
                raise RecorderStorageHeld(held.reason, held.policy_generation,
                    progress=dataclasses.replace(held.progress, persistence_unknown=True),
                    replay_progress=held.replay_progress, unit_bytes=held.unit_bytes) from None
            raise
        finally:
            self._storage_budget.release(lease, wrote=admitted)

    def _rollback_locked(self) -> None:
        """Best-effort rollback of the current transaction under ``_lock``."""
        try:
            self._db.rollback()
        except Exception:
            pass

    def _after_insert_commit_locked(self, inserted: int, last_id: int) -> None:
        """Publish known committed progress; maintenance cannot retry its input.

        Only call after ``commit()`` returned successfully, while holding
        ``_lock``. A raised/ambiguous commit retains the existing retry policy;
        this boundary does not claim exactly-once delivery for that case.
        """
        try:
            with self._revision_lock:
                self._revision = max(self._revision, last_id)
        except Exception:
            # A failed cache publication may lag until the next write. It does
            # not turn a known committed event back into unpersisted input.
            pass
        try:
            self._writes += inserted
            if self._writes >= self.PRUNE_EVERY:
                self._writes %= self.PRUNE_EVERY
                self._prune_locked()
        except RecorderStorageHeld:
            self._storage_budget.note_deferred(maintenance=True)
        except Exception:
            # Retention is a separate transaction. Its rollback cannot undo
            # the earlier successful event/receipt commit.
            self._rollback_locked()

    def _route_to_dlq(self, event: Event, *, _storage_lease=None) -> bool:
        """Append-only JSON fallback when the primary SQLite ledger is locked.

        Each line in dlq_events.json is a complete, self-contained JSON object
        (newline-delimited JSON / NDJSON format) for easy batch re-ingestion.

        G3-E TOCTOU fix: uses OS-level exclusive file locking (msvcrt on Windows,
        fcntl on POSIX) so an attacker process cannot interleave writes and corrupt
        the NDJSON structure.  The in-process self._dlq_lock is still held first to
        guard concurrent threads within the same process.
        """
        return (self._route_batch_to_dlq((event,)) if _storage_lease is None else
                self._route_batch_to_dlq((event,), _storage_lease=_storage_lease)) == 1

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

    def _route_batch_to_dlq(self, events: Iterable[Event], *, _storage_lease=None) -> int:
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
        if self._storage_budget.configured and sum(len(entry.encode("utf-8")) for entry in entries) > STORAGE_UNIT_BYTES:
            raise RecorderStorageHeld("unit_too_large", self._storage_budget.snapshot()["policy_generation"])
        written = 0
        chunk: list[str] = []
        chunk_bytes = 0
        def append_chunk(text, size):
            try:
                if _storage_lease is None:
                    return self._append_dlq_chunk(text, size)
                return self._append_dlq_chunk(text, size, _storage_lease=_storage_lease)
            except RecorderStorageHeld as held:
                raise RecorderStorageHeld(held.reason, held.policy_generation,
                    progress=StorageWriteProgress(written, 0, written),
                    replay_progress=held.replay_progress, unit_bytes=held.unit_bytes) from None
        for entry in entries:
            entry_bytes = len(entry.encode("utf-8"))
            if chunk and chunk_bytes + entry_bytes > self.DLQ_SEGMENT_BYTES:
                if not append_chunk("".join(chunk), chunk_bytes):
                    return written
                written += len(chunk)
                chunk = []
                chunk_bytes = 0
            chunk.append(entry)
            chunk_bytes += entry_bytes
        if chunk and append_chunk("".join(chunk), chunk_bytes):
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

    def _append_dlq_chunk(self, entry: str, entry_bytes: int, *, _storage_lease=None) -> bool:
        """Append one bounded chunk, waiting only at the catastrophic disk cap.

        Under normal floods callers enter this method only on the dedicated DLQ
        worker. If the hard spool budget is exhausted, the condition wait
        releases the file lock so the primary worker can replay and free a
        committed segment. This is the unavoidable fail-closed boundary: no
        evidence is discarded and disk use cannot grow without limit.
        """
        with self._storage_admission(entry_bytes, shared=_storage_lease):
            if entry_bytes <= 0 or entry_bytes > self.DLQ_MAX_BYTES:
                return False
            waited_at: float | None = None
            while True:
                needs_capacity = False
                if self._storage_budget.configured:
                    policy = self._storage_budget.snapshot()
                    if policy["blocked"]:
                        raise RecorderStorageHeld("operator_blocked", policy["policy_generation"])
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
                            # Custody is accepted once append returned. Later
                            # rotation/stat failure cannot reclassify its bytes.
                            try:
                                if active.stat().st_size >= self.DLQ_SEGMENT_BYTES:
                                    self._rotate_active_dlq_locked()
                            except Exception:
                                pass
                            return True
                        if waited_at is None:
                            waited_at = time.monotonic()
                            self._dlq_capacity_waits += 1
                        needs_capacity = True
                except RecorderStorageHeld:
                    raise
                except Exception:
                    return False

                # Do not wait for the primary recorder to become idle: during a
                # sustained flood its idle-only maintenance path may never run, and
                # the overflow worker itself is marked busy.  Replaying one segment
                # here releases durable capacity without discarding signed evidence.
                if needs_capacity:
                    if self._storage_runtime is not None and self._storage_runtime._stop.is_set():
                        raise RecorderStorageHeld("worker_stopped", self._storage_budget.snapshot()["policy_generation"])
                    if self._storage_budget.configured:
                        # A configured worker parks this input, releases its
                        # lease, and requests separately-accounted replay.
                        # Never retain a lease in the legacy capacity loop.
                        raise RecorderStorageHeld("spool_capacity", self._storage_budget.snapshot()["policy_generation"])
                    try:
                        relieved = self.replay_dlq(max_segments=1)
                    except RecorderStorageHeld:
                        raise
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
        if (self._storage_budget.configured and self._storage_runtime is not None
                and self._storage_runtime._stop.is_set()):
            raise RecorderStorageHeld("worker_stopped", self._storage_budget.snapshot()["policy_generation"])
        with self._storage_admission(self._storage_unit_bytes(events)):
            for attempt in range(self._DLQ_RETRIES):
                with self._lock:
                    try:
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
                        row = self._db.execute(
                            "SELECT COALESCE(MAX(id), 0) FROM events"
                        ).fetchone()
                        last_id = int(row[0] if row else 0)
                        self._db.commit()
                    except sqlite3.OperationalError:
                        self._rollback_locked()
                        retry = True
                    except Exception:
                        self._rollback_locked()
                        retry = False
                    else:
                        self._after_insert_commit_locked(inserted, last_id)
                        return inserted, duplicates
                if retry and attempt < self._DLQ_RETRIES - 1:
                    time.sleep(self._DLQ_RETRY_DELAY)
                else:
                    break
            return None

    def _remove_replay_receipts(self, segment: str) -> None:
        try:
            with self._storage_admission(0), self._lock:
                self._db.execute(
                    "DELETE FROM dlq_replay_receipts WHERE segment=?", (segment,)
                )
                self._db.commit()
        except RecorderStorageHeld:
            self._storage_budget.note_deferred(maintenance=True)
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

    def _storage_replay_lines(self, stream):
        if not self._storage_budget.configured:
            yield from stream
            return
        while True:
            raw = stream.readline(STORAGE_UNIT_BYTES + 1)
            if not raw:
                return
            if len(raw) > STORAGE_UNIT_BYTES:
                # Drain only this physical line in finite chunks. It remains
                # untouched in the source; never parse/quarantine fragments.
                while raw and not raw.endswith(b"\n"):
                    if self._storage_runtime is not None and self._storage_runtime._stop.is_set():
                        raise RecorderStorageHeld("worker_stopped", self._storage_budget.snapshot()["policy_generation"])
                    raw = stream.readline(64 * 1024)
                yield None
            else:
                yield raw.decode("utf-8", errors="replace")

    def _replay_dlq_unlocked(self, *, max_segments: int = 1) -> "DLQReplayResult":
        """Authenticate and idempotently re-ingest bounded spill segments.

        The active file is first atomically rotated. Valid lines are streamed in
        fixed-size batches. Forged or malformed raw lines are retained in a
        quarantine segment and never rendered or executed. A source segment is
        deleted only after every valid line is committed/already present and
        every invalid line has been durably quarantined.
        """
        max_segments = max(1, min(int(max_segments), self.DLQ_MAX_SEGMENTS))
        lease = self._storage_budget.admit(0)
        self._storage_budget.release(lease)
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
            segment_deferred = False
            batch_bytes = 0
            try:
                opened = (segment.open("rb") if self._storage_budget.configured else
                          segment.open("r", encoding="utf-8", errors="replace"))
                with opened as stream:
                    for raw in self._storage_replay_lines(stream):
                        processed += 1
                        if raw is None:
                            segment_deferred = True
                            self._storage_budget.note_deferred(replay=True)
                            continue
                        event = self._decode_dlq_event(raw)
                        if event is None:
                            invalid_lines.append(
                                raw if raw.endswith("\n") else raw + "\n"
                            )
                            continue
                        size = self._storage_unit_bytes((event,))
                        if self._storage_budget.configured and size > STORAGE_UNIT_BYTES:
                            segment_deferred = True
                            self._storage_budget.note_deferred(replay=True)
                            continue
                        if batch and self._storage_budget.configured and batch_bytes + size + 64 > STORAGE_UNIT_BYTES:
                            result = self._insert_replay_batch(batch, segment.name)
                            if result is None:
                                segment_ok = False
                                break
                            inserted += result[0]
                            duplicates += result[1]
                            batch.clear()
                            batch_bytes = 0
                            # New units refresh facts only on this worker path.
                            self._storage_refresh_on_worker()
                        batch.append(event)
                        batch_bytes += size + 64
                        if len(batch) >= self.DLQ_REPLAY_BATCH:
                            result = self._insert_replay_batch(batch, segment.name)
                            if result is None:
                                segment_ok = False
                                break
                            inserted += result[0]
                            duplicates += result[1]
                            batch.clear()
                            batch_bytes = 0
                            if self._storage_budget.configured:
                                self._storage_refresh_on_worker()
                if segment_ok and batch:
                    result = self._insert_replay_batch(batch, segment.name)
                    if result is None:
                        segment_ok = False
                    else:
                        inserted += result[0]
                        duplicates += result[1]
                        if self._storage_budget.configured:
                            self._storage_refresh_on_worker()
            except RecorderStorageHeld as held:
                raise RecorderStorageHeld(held.reason, held.policy_generation,
                    replay_progress=DLQReplayResult(processed, inserted, duplicates, quarantined, completed, failures)) from None
            except (OSError, UnicodeError):
                segment_ok = False

            if not segment_ok:
                failures += 1
                continue

            if segment_deferred:
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
                    text = "".join(invalid_lines)
                    with self._storage_admission(len(text.encode("utf-8"))):
                        self._write_private_text(temp, text)
                    os.replace(temp, quarantine_path)
                    quarantined += len(invalid_lines)
                except RecorderStorageHeld as held:
                    raise RecorderStorageHeld(held.reason, held.policy_generation,
                        replay_progress=DLQReplayResult(processed, inserted, duplicates, quarantined, completed, failures)) from None
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
            if self._storage_budget.configured:
                self._storage_refresh_on_worker()
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
        with self._storage_admission(0):
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
                self._rollback_locked()

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

    def bounded_events_in_window(
        self,
        start_ts: float,
        end_ts: float,
        *,
        limit: int = 10_000,
    ) -> tuple[List[Event], int]:
        """Return oldest-first durable events plus the exact interval count.

        Reporting modules can therefore distinguish a complete interval from a
        bounded sample instead of silently describing the newest N rows as an
        entire day. The hard limit protects memory during event storms.
        """
        limit = max(1, min(int(limit), 10_000))
        with self._lock:
            total_row = self._db.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ? AND ts <= ?",
                (float(start_ts), float(end_ts)),
            ).fetchone()
            rows = self._db.execute(
                "SELECT id, ts, module, severity, message, details, hmac_sig "
                "FROM events WHERE ts >= ? AND ts <= ? ORDER BY id ASC LIMIT ?",
                (float(start_ts), float(end_ts), limit),
            ).fetchall()
        total = int(total_row[0] if total_row else 0)
        return [self._event_from_row(row) for row in rows], total

    def bounded_events_after_id(
        self,
        record_id: int,
        *,
        limit: int = 5_000,
    ) -> tuple[list[tuple[int, Event]], int, int]:
        """Return authenticated rows after a durable consumer cursor.

        ``total`` is the exact backlog and ``highwater`` is the database's
        current maximum id. Consumers advance only to the last returned id, so
        a burst larger than ``limit`` drains over multiple cycles without loss.
        """
        record_id = max(0, int(record_id))
        limit = max(1, min(int(limit), 10_000))
        with self._lock:
            total_row = self._db.execute(
                "SELECT COUNT(*) FROM events WHERE id > ?", (record_id,)
            ).fetchone()
            highwater_row = self._db.execute(
                "SELECT COALESCE(MAX(id), 0) FROM events"
            ).fetchone()
            rows = self._db.execute(
                "SELECT id, ts, module, severity, message, details, hmac_sig "
                "FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (record_id, limit),
            ).fetchall()
        decoded = [(int(row[0]), self._event_from_row(row)) for row in rows]
        return (
            decoded,
            int(total_row[0] if total_row else 0),
            int(highwater_row[0] if highwater_row else 0),
        )

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
    admission_rejected: int = 0
    rejection_saturated: int = 0
    rejection_stopping: int = 0
    rejection_unavailable: int = 0
    coverage_gap: bool = False
    rejection_storage_hold: int = 0
    storage_pending_events: int = 0
    storage_user_discarded: int = 0
    storage_held: bool = False
    storage_policy_generation: int = 0
    storage_reason: str = ""
    storage_write_failures: int = 0


class RecorderAdmissionRejected(RuntimeError):
    """This delivery was not admitted to the recorder's bounded memory lanes.

    Other EventBus subscribers may still receive the event. The reason and the
    recorder's cumulative rejection counters are process-local diagnostics, not
    durable evidence that a rejected delivery was recorded.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Recorder delivery rejected: {reason}")


_RECORDER_WAKE = object()


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

    ``submit`` performs only signing and bounded in-memory admission. Primary
    overflow enters a second bounded lane whose worker preserves signed events
    in append-only DLQ batches. Exhausted or unavailable lanes reject delivery
    explicitly, with process-lifetime, nondurable rejection accounting. Disk
    writes and capacity waits belong exclusively to the persistence workers.
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
        self._starting = False
        self._stop_callers = 0
        self._worker_generation = 0
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
        self._admission_rejected = 0
        self._rejection_saturated = 0
        self._rejection_stopping = 0
        self._rejection_unavailable = 0
        self._rejection_storage_hold = 0
        self._storage_user_discarded = 0
        self._storage_pending_events = 0
        self._storage_held = False
        self._storage_reason = ""
        self._storage_policy_generation = 0
        self._storage_tracking = False
        self._storage_slots = {"primary": None, "overflow": None}
        self._storage_pending_generation = 0
        self._storage_publication = 0
        self._storage_wake = threading.Event()
        budget = getattr(recorder, "_storage_budget", None)
        if budget is not None:
            with recorder._storage_runtime_lock:
                # One owner for this connection's lifetime. Restart this same
                # adapter; constructing another cannot erase retained input or
                # reset its publication/loss counters, even after a clean stop.
                if recorder._storage_runtime is not None:
                    raise RuntimeError("recorder already has a runtime owner; restart that owner")
                recorder._storage_runtime = self
            self._storage_policy_changed()

    def _storage_policy_changed(self):
        budget = getattr(self._recorder, "_storage_budget", None)
        if budget is None:
            return
        view = budget.snapshot()
        with self._metrics_lock:
            if view["configured"] and not self._storage_tracking:
                self._storage_pending_events = max(0, self._accepted + self._overflow_queued
                    - self._persisted - self._storage_dlq - self._overflow_dlq - self._dlq_failures)
                self._storage_tracking = True
            self._storage_policy_generation = max(self._storage_policy_generation, view["policy_generation"])
            oversized = any(slot and slot["oversized"] for slot in self._storage_slots.values())
            self._storage_held = view["state"] in {"held", "unavailable"} or oversized
            self._storage_reason = ("operator_blocked" if view["blocked"] else
                                    "unit_too_large" if oversized else
                                    view["reason_code"] if self._storage_held else "")
        self._storage_wake.set()
        if view["configured"]:
            if self._thread is not None and self._thread.is_alive():
                self._wake_idle(self._queue)
            if self._dlq_thread is not None and self._dlq_thread.is_alive():
                self._wake_idle(self._overflow_queue)
        self._publish_storage_runtime()

    def _publish_storage_runtime(self):
        budget = getattr(self._recorder, "_storage_budget", None)
        if budget is None:
            return
        with self._metrics_lock:
            self._storage_publication += 1
            revision = self._storage_publication
            values = {"storage_pending_events": self._storage_pending_events,
                "parked_primary_events": len(self._storage_slots["primary"]["events"])
                    if self._storage_slots["primary"] and not self._storage_slots["primary"]["in_flight"] else 0,
                "parked_overflow_events": len(self._storage_slots["overflow"]["events"])
                    if self._storage_slots["overflow"] and not self._storage_slots["overflow"]["in_flight"] else 0,
                "rejection_storage_hold": self._rejection_storage_hold,
                "storage_user_discarded": self._storage_user_discarded,
                "coverage_gap": bool(self._admission_rejected or self._storage_user_discarded or self._dlq_failures),
                "storage_write_failures": self._dlq_failures,
                "storage_held": self._storage_held,
                "storage_policy_generation": self._storage_policy_generation,
                "storage_reason": self._storage_reason}
        budget.publish_runtime(revision, values)

    def _storage_probe_published(self):
        view = self._recorder._storage_budget.snapshot()
        with self._metrics_lock:
            oversized = any(slot and slot["oversized"] for slot in self._storage_slots.values())
            self._storage_policy_generation = max(self._storage_policy_generation, view["policy_generation"])
            self._storage_held = oversized or view["state"] in {"held", "unavailable"}
            self._storage_reason = "unit_too_large" if oversized else view["reason_code"]
        self._publish_storage_runtime()

    def retirement_snapshot(self) -> dict:
        with self._state_lock:
            retired = not any(worker is not None and worker.is_alive()
                              for worker in (self._thread, self._dlq_thread))
            generation = self._worker_generation
            stopping = self._stop.is_set()
            with self._metrics_lock:
                pending = (self._storage_pending_events if self._storage_tracking else
                           max(0, self._accepted + self._overflow_queued - self._persisted
                               - self._storage_dlq - self._overflow_dlq - self._dlq_failures))
                parked = any(slot and slot["events"] for slot in self._storage_slots.values())
        return {"schema": 1, "worker_generation": generation, "workers_retired": retired,
                "drained": retired and pending == 0 and not parked,
                "pending_events": pending, "stopping": stopping}

    def held_unit_review(self, lane: str) -> dict:
        base = {"schema": 1, "available": False, "reason_code": "worker_unavailable"}
        if type(lane) is not str or lane not in {"primary", "overflow"}:
            return base
        generation = self._recorder._storage_budget.snapshot()["policy_generation"]
        with self._metrics_lock:
            slot = self._storage_slots[lane]
            if not slot or not slot["events"]:
                return base
            allowed = slot["reason"] == "unit_too_large" and slot["oversized"] and not slot["in_flight"]
            return {"schema": 1, "available": True, "reason_code": slot["reason"], "lane": lane,
                "token": slot["token"], "policy_generation": generation,
                "worker_generation": self._worker_generation,
                "pending_generation": slot["generation"], "event_count": 1,
                "serialized_bytes": slot["bytes"], "volatile": True,
                "in_flight": slot["in_flight"], "discard_allowed": allowed}

    def discard_held_unit(self, *, lane: str, token: str, policy_generation: int,
                          worker_generation: int, pending_generation: int) -> dict:
        def reply(accepted, reason):
            return {"schema": 1, "accepted": accepted, "reason_code": reason,
                    "discarded_events": int(accepted)}
        if (type(lane) is not str or lane not in {"primary", "overflow"}
                or type(token) is not str or len(token) != 32
                or any(type(value) is not int or value < 0 for value in (
                    policy_generation, worker_generation, pending_generation))):
            return reply(False, "invalid_request")
        budget = self._recorder._storage_budget
        with self._state_lock:
            if worker_generation != self._worker_generation:
                return reply(False, "stale_generation")
            with self._metrics_lock:
                # The policy lock remains short and memory-only through this
                # exact ownership decision. Neither worker holds it over I/O.
                with budget._lock:
                    if policy_generation != budget._generation:
                        return reply(False, "stale_generation")
                    slot = self._storage_slots[lane]
                    if (not slot or not slot["events"] or slot["token"] != token
                            or slot["generation"] != pending_generation):
                        return reply(False, "stale_generation")
                    if slot["in_flight"]:
                        return reply(False, "in_flight")
                    if slot["reason"] != "unit_too_large" or not slot["oversized"]:
                        return reply(False, "not_discardable")
                    # Only the first, oversized volatile event is discarded.
                    # The rest of its admitted suffix and every durable source
                    # remain owned. A repeated token cannot acknowledge twice.
                    slot["events"].pop(0)
                    self._storage_pending_events -= 1
                    self._storage_user_discarded += 1
                    self._storage_pending_generation += 1
                    slot.update(reason="", oversized=False, token="", bytes=None,
                                generation=self._storage_pending_generation)
                    if not slot["events"]:
                        self._storage_slots[lane] = None
                    self._storage_held = any(item and item["reason"] for item in self._storage_slots.values())
                    self._storage_reason = next((item["reason"] for item in self._storage_slots.values()
                                                 if item and item["reason"]), "")
                    pending_queue = self._queue if lane == "primary" else self._overflow_queue
                    pending_queue.task_done()
        budget.clear_local_unit_hold()
        self._storage_wake.set()
        self._publish_storage_runtime()
        return reply(True, "discarded")

    def _storage_slot(self, lane, events):
        with self._metrics_lock:
            if not self._storage_tracking:
                # Capacity STOP can park legacy input too. Ownership tracking
                # is independent of whether a byte policy was configured; it
                # must survive retirement and select the resuming lane loop.
                self._storage_pending_events = max(0, self._accepted + self._overflow_queued
                    - self._persisted - self._storage_dlq - self._overflow_dlq - self._dlq_failures)
                self._storage_tracking = True
            self._storage_pending_generation += 1
            self._storage_slots[lane] = {"events": list(events), "reason": "", "token": "",
                "generation": self._storage_pending_generation, "in_flight": False,
                "oversized": False, "bytes": None}

    def _storage_park(self, lane, held, *, oversized=False, size=None):
        token = secrets.token_hex(16)
        with self._metrics_lock:
            slot = self._storage_slots[lane]
            if slot and slot["events"]:
                self._storage_pending_generation += 1
                slot.update(reason=held.reason, in_flight=False, oversized=oversized,
                            bytes=size, token=token, generation=self._storage_pending_generation)
            self._storage_held = True
            self._storage_reason = held.reason
            self._storage_policy_generation = max(self._storage_policy_generation, held.policy_generation)
        self._publish_storage_runtime()

    def _storage_ack(self, lane, count):
        if not count:
            return
        pending_queue = self._queue if lane == "primary" else self._overflow_queue
        with self._metrics_lock:
            slot = self._storage_slots[lane]
            if slot is None or not 0 <= count <= len(slot["events"]):
                raise RuntimeError("invalid recorder prefix acknowledgement")
            del slot["events"][:count]
            self._storage_pending_events -= count
            slot.update(reason="", token="", in_flight=False, oversized=False, bytes=None)
            if not slot["events"]:
                self._storage_slots[lane] = None
            self._storage_held = any(item and item["reason"] for item in self._storage_slots.values())
            self._storage_reason = next((item["reason"] for item in self._storage_slots.values()
                                         if item and item["reason"]), "")
        for _ in range(count):
            pending_queue.task_done()
        self._publish_storage_runtime()

    def _run_storage_lane(self, lane):
        pending_queue = self._queue if lane == "primary" else self._overflow_queue
        capacity = self._batch_size if lane == "primary" else self._dlq_batch_size
        while True:
            with self._metrics_lock:
                slot = self._storage_slots[lane]
                oversized = any(item and item["oversized"] for item in self._storage_slots.values())
            if oversized:
                if self._stop.is_set():
                    break
                self._storage_wake.wait(1.0)
                self._storage_wake.clear()
                continue
            if not slot:
                if self._stop.is_set() and pending_queue.empty():
                    break
                try:
                    event = pending_queue.get(timeout=min(1.0, self._idle_wait_seconds()))
                except queue.Empty:
                    if lane == "primary":
                        self._recorder._storage_refresh_on_worker()
                        self._maybe_replay()
                    continue
                if lane == "primary":
                    with self._metrics_lock:
                        self._primary_saturated.clear()
                if event is _RECORDER_WAKE:
                    pending_queue.task_done()
                    if not self._stop.is_set():
                        self._recorder._storage_refresh_on_worker()
                    continue
                events = [event]
                while len(events) < capacity:
                    try:
                        event = pending_queue.get_nowait()
                    except queue.Empty:
                        break
                    if event is _RECORDER_WAKE:
                        pending_queue.task_done()
                    else:
                        events.append(event)
                self._storage_slot(lane, events)
            self._recorder._storage_refresh_on_worker()
            with self._metrics_lock:
                slot = self._storage_slots[lane]
                if not slot or not slot["events"]:
                    continue
                events = list(slot["events"])
            unit = []
            unit_bytes = 0
            first_size = self._recorder._storage_unit_bytes(events[:1])
            if first_size > STORAGE_UNIT_BYTES:
                try:
                    self._recorder._storage_budget.admit(first_size)
                except RecorderStorageHeld as held:
                    self._storage_park(lane, held, oversized=True, size=first_size)
                if self._stop.is_set():
                    break
                continue
            for event in events:
                size = self._recorder._storage_unit_bytes((event,))
                if unit and unit_bytes + size + 64 > STORAGE_UNIT_BYTES:
                    break
                unit.append(event)
                unit_bytes += size + 64
            with self._metrics_lock:
                slot = self._storage_slots[lane]
                if not slot:
                    continue
                slot["in_flight"] = True
            try:
                if lane == "primary":
                    result = self._recorder.record_batch_bus(unit)
                    persisted, spooled = result.persisted, result.dlq
                else:
                    persisted, spooled = 0, self._recorder._route_batch_to_dlq(unit)
            except RecorderStorageHeld as held:
                progress = held.progress
                with self._metrics_lock:
                    self._persisted += progress.persisted
                    if lane == "primary":
                        self._storage_dlq += progress.spooled
                    else:
                        self._overflow_dlq += progress.spooled
                    if held.replay_progress is not None:
                        self._replayed += held.replay_progress.inserted
                        self._replay_duplicates += held.replay_progress.duplicates
                        self._replay_quarantined += held.replay_progress.quarantined
                        self._replay_failures += held.replay_progress.failures
                self._storage_ack(lane, progress.completed)
                self._storage_park(lane, held, oversized=held.reason == "unit_too_large" and len(unit) == 1,
                                   size=held.unit_bytes if len(unit) == 1 else None)
                if self._stop.is_set():
                    break
                if held.reason == "spool_capacity":
                    self._recorder._storage_refresh_on_worker()
                    self._maybe_replay(force=True)
                self._storage_wake.wait(1.0)
                self._storage_wake.clear()
                continue
            with self._metrics_lock:
                self._persisted += persisted
                if lane == "primary":
                    self._storage_dlq += spooled
                    self._batches += 1
                else:
                    self._overflow_dlq += spooled
                self._dlq_failures += len(unit) - persisted - spooled
            self._storage_ack(lane, len(unit))
            if lane == "primary" and pending_queue.empty():
                self._maybe_replay()
        self._publish_storage_runtime()

    def start(self) -> bool:
        """Start missing workers, or explicitly restart after a completed stop."""
        if self._storage_tracking and self._recorder._storage_runtime is not self:
            return False
        with self._state_lock:
            if self._stop_callers:
                return False
            if self._stop.is_set():
                # A timed-out stop still owns both draining workers. Clearing
                # its signal would revive a live peer and invalidate the drain.
                if any(
                    worker is not None and worker.is_alive()
                    for worker in (self._thread, self._dlq_thread)
                ):
                    return False
                with self._metrics_lock:
                    self._stop.clear()
            return self._start_missing_workers_locked()

    def _start_missing_workers_locked(self) -> bool:
        """Preserve queues and live peers; caller holds ``_state_lock``."""
        if self._stop_callers:
            return False
        missing_dlq = self._dlq_thread is None or not self._dlq_thread.is_alive()
        missing_primary = self._thread is None or not self._thread.is_alive()
        if not missing_dlq and not missing_primary:
            return False
        # Publish the admission gate before starting either thread. Thread
        # creation can block; it must never hold the publishers' memory lock.
        with self._metrics_lock:
            self._starting = True
        try:
            if missing_dlq:
                self._dlq_done.clear()
                self._dlq_busy.clear()
                worker = threading.Thread(
                    target=self._run_dlq,
                    name="angerona-flight-dlq",
                    daemon=True,
                )
                try:
                    worker.start()
                except Exception:
                    # A live primary must not wait for a peer that never
                    # started. Do not publish an unstarted thread for join().
                    self._dlq_done.set()
                    raise
                self._dlq_thread = worker
                self._worker_generation += 1
            if missing_primary:
                self._primary_saturated.clear()
                worker = threading.Thread(
                    target=self._run,
                    name="angerona-flight-recorder",
                    daemon=True,
                )
                worker.start()
                self._thread = worker
                self._worker_generation += 1
            return True
        finally:
            with self._metrics_lock:
                self._starting = False

    def recover(self) -> bool:
        """Restore dead worker availability without overriding shutdown.

        Pending queues are retained. Restarting a worker cannot establish
        continuity for a batch it may have held when it failed.
        """
        with self._state_lock:
            if self._stop.is_set() or self._stop_callers:
                return False
            return self._start_missing_workers_locked()

    def recovery_snapshot(self) -> dict:
        """Read worker availability and cumulative failures without disk I/O."""
        with self._state_lock:
            stopping = self._stop.is_set()
            worker_alive = bool(self._thread and self._thread.is_alive())
            dlq_worker_alive = bool(
                self._dlq_thread and self._dlq_thread.is_alive()
            )
            with self._metrics_lock:
                return {
                    "healthy": worker_alive and dlq_worker_alive and not stopping,
                    "stopping": stopping,
                    "worker_alive": worker_alive,
                    "dlq_worker_alive": dlq_worker_alive,
                    "dlq_failures": self._dlq_failures,
                    "replay_failures": self._replay_failures,
                    "replay_quarantined": self._replay_quarantined,
                    "admission_rejected": self._admission_rejected,
                    "rejection_saturated": self._rejection_saturated,
                    "rejection_stopping": self._rejection_stopping,
                    "rejection_unavailable": self._rejection_unavailable,
                    "rejection_storage_hold": self._rejection_storage_hold,
                    "storage_pending_events": self._storage_pending_events,
                    "storage_user_discarded": self._storage_user_discarded,
                    "storage_held": self._storage_held,
                    "storage_policy_generation": self._storage_policy_generation,
                    "storage_reason": self._storage_reason,
                    "storage_write_failures": self._dlq_failures,
                    "coverage_gap": bool(self._admission_rejected or self._storage_user_discarded or self._dlq_failures),
                }

    def submit(self, event: Event) -> None:
        """Admit a delivery without disk I/O or waiting for queue capacity.

        Raise ``RecorderAdmissionRejected`` if no lane can accept this delivery.
        EventBus counts this subscriber failure and continues other callbacks.
        Counters remain cumulative across worker restarts, in memory only.
        """
        if not event.hmac_sig:
            event = dataclasses.replace(
                event, hmac_sig=self._recorder.authority.sign(event)
            )
        # Admission and stop's closure share only this short memory lock.
        # Signing, lifecycle thread starts/joins and every storage operation
        # happen outside it, so a blocked disk cannot hold publishers here.
        with self._metrics_lock:
            accepted = False
            storage_hold = False
            if self._storage_tracking:
                view = self._recorder._storage_budget.snapshot()
                self._storage_policy_generation = view["policy_generation"]
                storage_hold = (view["blocked"] or view["reason_code"] in {
                    "db_target", "wal_target", "free_floor", "probe_failed", "identity_changed",
                    "spool_capacity",
                } or any(slot and slot["oversized"] for slot in self._storage_slots.values()))
            if self._stop.is_set():
                reason = "stopping"
            elif self._starting:
                reason = "unavailable"
            elif storage_hold:
                reason = "storage_hold"
            else:
                thread = self._thread
                dlq_thread = self._dlq_thread
                running = thread is not None and thread.is_alive()
                dlq_running = dlq_thread is not None and dlq_thread.is_alive()
                if running and not self._primary_saturated.is_set():
                    try:
                        self._queue.put_nowait(event)
                    except queue.Full:
                        self._primary_saturated.set()
                    else:
                        self._accepted += 1
                        self._storage_pending_events += int(self._storage_tracking)
                        accepted = True
                if not accepted and dlq_running:
                    try:
                        self._overflow_queue.put_nowait(event)
                    except queue.Full:
                        pass
                    else:
                        self._overflow_queued += 1
                        self._storage_pending_events += int(self._storage_tracking)
                        accepted = True
                reason = "saturated" if running or dlq_running else "unavailable"
            if not accepted:
                self._admission_rejected += 1
                if reason == "saturated":
                    self._rejection_saturated += 1
                elif reason == "stopping":
                    self._rejection_stopping += 1
                elif reason == "storage_hold":
                    self._rejection_storage_hold += 1
                else:
                    self._rejection_unavailable += 1
        if self._storage_tracking:
            self._publish_storage_runtime()
        if accepted:
            return
        raise RecorderAdmissionRejected(reason)

    def stop(self, timeout: float = 5.0) -> bool:
        """Request a drain and wait a bounded time; safe to call repeatedly."""
        timeout = max(0.0, float(timeout))
        with self._state_lock:
            thread = self._thread
            dlq_thread = self._dlq_thread
            generation = self._worker_generation
            self._stop_callers += 1
            with self._metrics_lock:
                self._stop.set()
        try:
            self._storage_wake.set()
            # Wake only existing owners. A repeated stop after retirement must
            # not leave wake tokens in the preserved queues for a later start.
            if thread is not None and thread.is_alive():
                self._wake_idle(self._queue)
            if dlq_thread is not None and dlq_thread.is_alive():
                self._wake_idle(self._overflow_queue)
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
            with self._state_lock:
                # Concurrent stop callers may already have cleared these same
                # retired references. No caller may certify a new generation.
                same_generation = self._worker_generation == generation
                same_owners = (
                    (self._thread is thread or self._thread is None)
                    and (self._dlq_thread is dlq_thread or self._dlq_thread is None)
                )
                if (
                    stopped and same_generation and same_owners
                    and self._stop_callers == 1
                ):
                    # Earlier stop callers may have inserted a wake after its
                    # consumer retired. Only the last caller can now clean
                    # these tokens: all wake insertions finished, admission is
                    # closed, and lifecycle replacement remains fenced here.
                    primary_empty = self._discard_retired_wakes(self._queue)
                    overflow_empty = self._discard_retired_wakes(self._overflow_queue)
                    if self._thread is thread:
                        self._thread = None
                    if self._dlq_thread is dlq_thread:
                        self._dlq_thread = None
                    with self._metrics_lock:
                        pending = (self._storage_pending_events if self._storage_tracking else
                                   max(0, self._accepted + self._overflow_queued - self._persisted
                                       - self._storage_dlq - self._overflow_dlq - self._dlq_failures))
                        retained = pending > 0 or any(
                            slot and slot["events"] for slot in self._storage_slots.values())
                    return primary_empty and overflow_empty and not retained
                return False
        finally:
            # Keep replacement fenced until every caller has completed its
            # final generation check. Never hold lifecycle locks across joins.
            with self._state_lock:
                self._stop_callers -= 1

    @staticmethod
    def _discard_retired_wakes(pending) -> bool:
        """Discard only wake identities after all consumers/producers retire.

        The caller owns the lifecycle fence with admission closed. Preserve
        every original Event reference and its order within this bounded lane.
        A dead worker's pending originals prevent a successful drain receipt.
        """
        retained = []
        for _ in range(pending.maxsize):
            try:
                event = pending.get_nowait()
            except queue.Empty:
                break
            if event is not _RECORDER_WAKE:
                retained.append(event)
        for event in retained:
            pending.put_nowait(event)
        return not retained

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
                admission_rejected=self._admission_rejected,
                rejection_saturated=self._rejection_saturated,
                rejection_stopping=self._rejection_stopping,
                rejection_unavailable=self._rejection_unavailable,
                coverage_gap=bool(self._admission_rejected or self._storage_user_discarded or self._dlq_failures),
                rejection_storage_hold=self._rejection_storage_hold,
                storage_pending_events=self._storage_pending_events,
                storage_user_discarded=self._storage_user_discarded,
                storage_held=self._storage_held,
                storage_policy_generation=self._storage_policy_generation,
                storage_reason=self._storage_reason,
                storage_write_failures=self._dlq_failures,
            )

    @staticmethod
    def _wake_idle(pending) -> None:
        try:
            pending.put_nowait(_RECORDER_WAKE)
        except queue.Full:
            pass

    @staticmethod
    def _quiet_idle_policy() -> bool:
        from angerona.core.background_pacing import get_pacing_controller
        return get_pacing_controller().chill_active()

    def _idle_wait_seconds(self) -> float:
        # Queue arrival wakes immediately. Only an empty queue gets the longer
        # wait; the first real event still starts the original flush deadline.
        return 5.0 if self._quiet_idle_policy() else 1.0

    def _run(self) -> None:
        if self._storage_tracking:
            self._run_storage_lane("primary")
            return
        while (
            not self._stop.is_set()
            or not self._queue.empty()
            or not self._dlq_done.is_set()
        ):
            if self._storage_tracking:
                self._run_storage_lane("primary")
                return
            batch: list[Event] = []
            try:
                event = self._queue.get(timeout=self._idle_wait_seconds())
                # Pair relief with submit's full observation. Otherwise a
                # publisher could set a stale saturation flag after this clear
                # and bypass an available primary lane indefinitely.
                with self._metrics_lock:
                    self._primary_saturated.clear()
                if event is _RECORDER_WAKE:
                    if self._stop.is_set():
                        # stop() owns the bounded join. Retain this worker's
                        # draining lifetime until its peer has finished, with
                        # no periodic polling and no abandoned delivery.
                        self._dlq_done.wait()
                    continue
                batch.append(event)
            except queue.Empty:
                self._maybe_replay()
                continue
            deadline = time.monotonic() + self._flush_interval
            while len(batch) < self._batch_size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    event = self._queue.get(timeout=remaining)
                    if event is _RECORDER_WAKE:
                        break
                    batch.append(event)
                except queue.Empty:
                    break
            try:
                result = self._recorder.record_batch_bus(batch)
            except RecorderStorageHeld as held:
                self._storage_policy_changed()
                self._storage_slot("primary", batch)
                with self._metrics_lock:
                    self._persisted += held.progress.persisted
                    self._storage_dlq += held.progress.spooled
                self._storage_ack("primary", held.progress.completed)
                self._storage_park("primary", held)
                if not self._stop.is_set():
                    self._run_storage_lane("primary")
                return
            with self._metrics_lock:
                self._persisted += result.persisted
                self._storage_dlq += result.dlq
                self._dlq_failures += len(batch) - result.persisted - result.dlq
                self._batches += 1
                if self._storage_tracking:
                    self._storage_pending_events -= len(batch)
            for _ in batch:
                self._queue.task_done()
            if self._queue.empty():
                self._maybe_replay()
            if self._storage_tracking:
                self._run_storage_lane("primary")
                return
        # One bounded final maintenance pass after the overflow writer drained.
        self._maybe_replay(force=True)

    def _maybe_replay(self, *, force: bool = False) -> None:
        if self._storage_tracking and self._stop.is_set():
            return
        replay = getattr(self._recorder, "replay_dlq", None)
        if not callable(replay):
            return
        now = time.monotonic()
        replay_interval = 30.0 if self._quiet_idle_policy() else 2.0
        if not force and now - self._last_replay_at < replay_interval:
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
        except RecorderStorageHeld as held:
            self._recorder._storage_budget.note_deferred(replay=True)
            self._recorder._storage_budget.clear_local_unit_hold()
            result = held.replay_progress
            if result is None:
                return
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
            if self._storage_tracking:
                self._run_storage_lane("overflow")
                return
            while not self._stop.is_set() or not self._overflow_queue.empty():
                if self._storage_tracking:
                    self._run_storage_lane("overflow")
                    return
                batch: list[Event] = []
                try:
                    event = self._overflow_queue.get(timeout=self._idle_wait_seconds())
                    if event is _RECORDER_WAKE:
                        continue
                    batch.append(event)
                except queue.Empty:
                    continue
                self._dlq_busy.set()
                while len(batch) < self._dlq_batch_size:
                    try:
                        event = self._overflow_queue.get_nowait()
                        if event is not _RECORDER_WAKE:
                            batch.append(event)
                    except queue.Empty:
                        break
                batch_writer = getattr(self._recorder, "_route_batch_to_dlq", None)
                try:
                    if callable(batch_writer):
                        written = int(batch_writer(batch))
                    else:
                        written = sum(
                            1 for event in batch if self._recorder._route_to_dlq(event)
                        )
                except RecorderStorageHeld as held:
                    self._storage_policy_changed()
                    self._storage_slot("overflow", batch)
                    with self._metrics_lock:
                        self._overflow_dlq += held.progress.spooled
                    self._storage_ack("overflow", held.progress.completed)
                    self._storage_park("overflow", held)
                    if not self._stop.is_set():
                        self._run_storage_lane("overflow")
                    return
                with self._metrics_lock:
                    self._overflow_dlq += written
                    self._dlq_failures += len(batch) - written
                    if self._storage_tracking:
                        self._storage_pending_events -= len(batch)
                for _ in batch:
                    self._overflow_queue.task_done()
                self._dlq_busy.clear()
                if self._storage_tracking:
                    self._run_storage_lane("overflow")
                    return
        finally:
            self._dlq_busy.clear()
            # The primary may be waiting for this lane's final drain rather
            # than for an event. Wake it so an empty shutdown finishes now.
            self._wake_idle(self._queue)
            self._dlq_done.set()
