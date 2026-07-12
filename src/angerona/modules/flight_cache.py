"""flight_cache.py — In-Memory Ephemeral Flight Cache (Code: MEMC).

Purpose
    A fast, bounded read-cache tier that sits in front of the on-disk
    flight-recorder ledger. The GUI and threat-hunting console can query hot,
    recent events from an ``sqlite3`` ``:memory:`` mirror instead of hitting the
    persistent DB on every 1.5s refresh — cutting disk I/O and query latency.

Behaviour
    - Warms itself from the newest rows of ``flight-recorder.db`` on start.
    - Subscribes to the EventBus and appends live events into the in-memory
      mirror as they happen.
    - Bounded: keeps at most ``CAP`` rows, evicting the oldest (LRU by id) so
      memory stays flat. The on-disk ledger remains the durable source of truth;
      this tier is purely ephemeral and lost on exit (by design).

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time

from angerona.core.module_base import BaseModule, Severity

_READONLY_RE = re.compile(r"^\s*(select|with)\b", re.IGNORECASE)
_FORBIDDEN_RE = re.compile(r"\b(insert|update|delete|drop|alter|attach|pragma|create)\b",
                           re.IGNORECASE)


class FlightCache:
    """Thread-safe bounded in-memory mirror of the events ledger."""

    def __init__(self, cap: int = 5000) -> None:
        self.cap = cap
        self._lock = threading.Lock()
        self._db = sqlite3.connect(":memory:", check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._seq = 0
        self.hits = 0
        self.misses = 0
        with self._lock:
            self._db.execute(
                "CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL, module TEXT, "
                "severity INTEGER, message TEXT, details TEXT)")
            self._db.execute("CREATE INDEX idx_ts ON events(ts)")
            self._db.commit()

    def put(self, ts: float, module: str, severity: int, message: str,
            details: dict | str | None = None) -> None:
        det = details if isinstance(details, str) else json.dumps(details or {})
        with self._lock:
            self._seq += 1
            self._db.execute(
                "INSERT INTO events (id, ts, module, severity, message, details) "
                "VALUES (?,?,?,?,?,?)",
                (self._seq, ts, module, int(severity), message, det))
            # evict oldest beyond cap
            over = self._count_locked() - self.cap
            if over > 0:
                self._db.execute(
                    "DELETE FROM events WHERE id IN "
                    "(SELECT id FROM events ORDER BY id ASC LIMIT ?)", (over,))
            self._db.commit()

    def _count_locked(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def count(self) -> int:
        with self._lock:
            return self._count_locked()

    def recent(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        self.hits += 1
        return [dict(r) for r in rows]

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        """Read-only SQL served from the memory tier (SELECT/WITH only)."""
        if not _READONLY_RE.match(sql) or _FORBIDDEN_RE.search(sql):
            raise ValueError("flight cache is read-only (SELECT/WITH only)")
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        self.hits += 1
        return [dict(r) for r in rows]

    def warm(self, disk_db_path: str, limit: int = 2000) -> int:
        try:
            src = sqlite3.connect(f"file:{disk_db_path}?mode=ro", uri=True)
            rows = src.execute(
                "SELECT ts, module, severity, message, details FROM events "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            src.close()
        except Exception:
            return 0
        for ts, module, severity, message, details in reversed(rows):
            self.put(ts, module, severity, message, details)
        return len(rows)

    def close(self) -> None:
        with self._lock:
            self._db.close()


class FlightCacheModule(BaseModule):
    CODE = "MEMC"
    NAME = "In-Memory Flight Cache"
    name = "In-Memory Flight Cache"
    description = ("Bounded sqlite :memory: mirror of the flight recorder for fast, "
                   "low-I/O reads of hot recent events.")
    category = "Performance"
    version = "1.0.0"

    CAP = 5000

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self.cache = FlightCache(cap=self.CAP)

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # passthroughs
    def recent(self, limit: int = 100) -> list[dict]:
        return self.cache.recent(limit)

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        return self.cache.query(sql, params)

    def _on_event(self, event) -> None:
        try:
            self.cache.put(event.ts, event.module, int(event.severity),
                           event.message, event.details or {})
        except Exception:
            pass

    def run(self) -> None:
        from angerona.core.config import Config
        
        # FIX: Re-initialize the cache instance on start. 
        # If Angerona paused/stopped the sensor, the previous cache was closed.
        self.cache = FlightCache(cap=self.CAP)
        
        warmed = self.cache.warm(str(Config().db_path), limit=2000)
        
        if self._bus is not None:
            try:
                self._bus.subscribe(self._on_event)
            except Exception:
                pass
                
        self.emit(f"MEMC online — warmed {warmed} events into the in-memory tier.",
                  Severity.INFO)
                  
        while not self.stopping:
            n = self.cache.count()
            self.set_health(100, f"{n}/{self.CAP} cached rows")
            self.sleep(10.0)

    def stop(self) -> None:
        super().stop()
        self.cache.close()

    def self_test(self) -> tuple[bool, str]:
        """Verify insert, read-back, eviction cap, and read-only guard."""
        c = FlightCache(cap=10)
        for i in range(25):
            c.put(time.time(), "TEST", 0, f"msg{i}", {"i": i})
        count = c.count()
        newest = c.recent(1)[0]["message"]
        guarded = False
        try:
            c.query("DELETE FROM events")
        except ValueError:
            guarded = True
        sel = c.query("SELECT COUNT(*) AS n FROM events")[0]["n"]
        c.close()
        ok = count == 10 and newest == "msg24" and guarded and sel == 10
        return (ok, f"cache verified (cap-held={count}, newest={newest}, ro-guard={guarded})"
                if ok else f"cache broken (count={count}, newest={newest}, guard={guarded})")


def register() -> FlightCacheModule:
    return FlightCacheModule()
