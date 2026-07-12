"""core/remediation_log.py — persistent, queryable audit ledger for every
remediation action Angerona takes or considers.

Stored in the same SQLite database as the FlightRecorder
(``flight-recorder.db``) under a separate ``remediation_log`` table so that
the full action history survives restarts and can be queried alongside events.

Schema (one row per action slot per call to apply_remediation):
  id           INTEGER PK AUTOINCREMENT
  ts           REAL     — Unix epoch of the decision
  trigger      TEXT     — module or context that triggered the call
                          (e.g. "PostureHardening", "console", "selftest")
  mitre        TEXT     — MITRE technique ID (T1003, etc.) or "-"
  action_key   TEXT     — e.g. "quarantine_file", "registry_hardening", or
                          "none" if no vetted action matched
  action_title TEXT     — human-readable title of the action
  outcome      TEXT     — one of: applied / skipped / dry_run / error / rolled_back
  verified     INTEGER  — 1 = post-apply verify passed, 0 = failed, -1 = not run
  host_level   INTEGER  — 1 if the action modifies OS state (registry/service/FW)
  record_json  TEXT     — full dict returned by action.apply() or the plan entry

Design notes
  * Written from any thread (remediation may run in a module daemon thread).
  * Read-only ``recent()`` / ``by_mitre()`` / ``stats()`` queries are safe to
    call from the GUI thread (short-lived lock).
  * Capped at MAX_ROWS (newest kept) — amortised trim every PRUNE_EVERY inserts,
    matching FlightRecorder discipline.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import List

MAX_ROWS = 10_000
PRUNE_EVERY = 500

_SINGLETON: "RemediationLog | None" = None
_INIT_LOCK = threading.Lock()


def init_log(db_path: Path) -> "RemediationLog":
    """Create (or return) the process-wide singleton, bound to *db_path*."""
    global _SINGLETON
    with _INIT_LOCK:
        if _SINGLETON is None:
            _SINGLETON = RemediationLog(db_path)
    return _SINGLETON


def get_log() -> "RemediationLog | None":
    """Return the singleton, or None if ``init_log`` has not been called yet."""
    return _SINGLETON


class RemediationLog:
    """SQLite-backed audit ledger for vetted remediation actions."""

    def __init__(self, db_path: Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self._path), check_same_thread=False)
        self._lock = threading.Lock()
        self._writes = 0
        self._init_schema()

    # ── schema ───────────────────────────────────────────────────────────────
    def _init_schema(self) -> None:
        with self._lock:
            for pragma in ("journal_mode=WAL", "synchronous=NORMAL", "busy_timeout=3000"):
                try:
                    self._db.execute(f"PRAGMA {pragma}")
                except Exception:
                    pass
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS remediation_log (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts           REAL    NOT NULL,
                    trigger      TEXT    NOT NULL DEFAULT '',
                    mitre        TEXT    NOT NULL DEFAULT '-',
                    action_key   TEXT    NOT NULL DEFAULT 'none',
                    action_title TEXT    NOT NULL DEFAULT '',
                    outcome      TEXT    NOT NULL DEFAULT 'dry_run',
                    verified     INTEGER NOT NULL DEFAULT -1,
                    host_level   INTEGER NOT NULL DEFAULT 0,
                    record_json  TEXT
                )
                """
            )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_remlog_ts    ON remediation_log(ts)"
            )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_remlog_mitre ON remediation_log(mitre)"
            )
            self._db.commit()

    # ── write ─────────────────────────────────────────────────────────────────
    def log(
        self,
        *,
        trigger: str = "",
        mitre: str = "-",
        action_key: str = "none",
        action_title: str = "",
        outcome: str = "dry_run",
        verified: int = -1,
        host_level: bool = False,
        record: dict | None = None,
    ) -> None:
        """Append one remediation-action entry.

        outcome values:
          ``applied``     — action ran and verify passed
          ``rolled_back`` — action ran but verify failed; was rolled back
          ``skipped``     — matched but not applied (host-level gate or apply=False)
          ``dry_run``     — plan-only call; no action attempted
          ``error``       — action raised an exception
        """
        with self._lock:
            self._db.execute(
                """
                INSERT INTO remediation_log
                  (ts, trigger, mitre, action_key, action_title,
                   outcome, verified, host_level, record_json)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    time.time(), trigger, mitre or "-", action_key,
                    action_title, outcome, int(verified), int(bool(host_level)),
                    json.dumps(record) if record is not None else None,
                ),
            )
            self._db.commit()
            self._writes += 1
            if self._writes >= PRUNE_EVERY:
                self._writes = 0
                self._prune_locked()

    def _prune_locked(self) -> None:
        try:
            row = self._db.execute(
                "SELECT MAX(id) FROM remediation_log"
            ).fetchone()
            if row and row[0] and row[0] > MAX_ROWS:
                self._db.execute(
                    "DELETE FROM remediation_log WHERE id <= ?",
                    (row[0] - MAX_ROWS,),
                )
                self._db.commit()
        except Exception:
            pass

    # ── read ──────────────────────────────────────────────────────────────────
    def recent(self, limit: int = 50) -> List[dict]:
        """Return the most recent *limit* entries, newest-first."""
        with self._lock:
            rows = self._db.execute(
                """
                SELECT ts, trigger, mitre, action_key, action_title,
                       outcome, verified, host_level, record_json
                FROM   remediation_log
                ORDER  BY id DESC
                LIMIT  ?
                """,
                (limit,),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def by_mitre(self, tid: str, limit: int = 50) -> List[dict]:
        """Return entries for a specific MITRE technique ID (case-insensitive)."""
        with self._lock:
            rows = self._db.execute(
                """
                SELECT ts, trigger, mitre, action_key, action_title,
                       outcome, verified, host_level, record_json
                FROM   remediation_log
                WHERE  lower(mitre) = lower(?)
                ORDER  BY id DESC
                LIMIT  ?
                """,
                (tid, limit),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def stats(self) -> dict:
        """Aggregate counts by outcome."""
        with self._lock:
            rows = self._db.execute(
                """
                SELECT outcome, COUNT(*) as n
                FROM   remediation_log
                GROUP  BY outcome
                """
            ).fetchall()
            total = self._db.execute(
                "SELECT COUNT(*) FROM remediation_log"
            ).fetchone()[0]
        counts = {r[0]: r[1] for r in rows}
        return {"total": total, **counts}


# ── helpers ───────────────────────────────────────────────────────────────────
def _row_to_dict(r) -> dict:
    ts, trigger, mitre, action_key, action_title, outcome, verified, host_level, rj = r
    return {
        "ts": ts,
        "trigger": trigger,
        "mitre": mitre,
        "action_key": action_key,
        "action_title": action_title,
        "outcome": outcome,
        "verified": None if verified == -1 else bool(verified),
        "host_level": bool(host_level),
        "record": json.loads(rj) if rj else None,
    }
