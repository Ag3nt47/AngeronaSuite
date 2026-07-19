"""core/posture_history.py — append-only Angerona-Score trend store.

ARIA's posture-trend memory. Every time the Angerona Score is recomputed, a
caller appends one point here; the HUD reads the series back to draw the score
sparkline and ARIA answers "is our posture improving?" from it.

Design mirrors ``core/storage.py``: a single held SQLite connection guarded by
a lock, an append-only table, bounded reads. Stdlib-only, local-first, additive
— wired into nothing at import. Off by default in the sense that nothing calls
:meth:`record` until you opt in.

    HARD SCOPE: this is a *posture* trend (security-score history), never money
    or telemetry egress. Data stays in the local flight-recorder DB.
"""
from __future__ import annotations

import queue
import sqlite3
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Optional, TypeVar


_SCHEMA = """
CREATE TABLE IF NOT EXISTS posture_history (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts    REAL    NOT NULL,
    score INTEGER NOT NULL,
    band  TEXT    NOT NULL DEFAULT '',
    note  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_posture_ts ON posture_history(ts);
CREATE INDEX IF NOT EXISTS ix_posture_ts_score ON posture_history(ts, score);
"""


_T = TypeVar("_T")
_HUD_POINT_LIMIT = 100_000
_HUD_QUERY_BUDGET_S = 0.150
_HUD_CACHE_KEYS = 16


@dataclass(frozen=True)
class PosturePoint:
    ts: float
    score: int
    band: str = ""
    note: str = ""


def _band_for(score: int) -> str:
    """Coarse label for a 0–100 posture score (colour-coding on the HUD)."""
    if score >= 90:
        return "STRONG"
    if score >= 70:
        return "GUARDED"
    if score >= 50:
        return "ELEVATED"
    return "CRITICAL"


class PostureHistory:
    """Append-only Angerona-Score trend.

    Usage::

        hist = get_history(db_path)
        hist.record(score=82)                 # append one point
        pts = hist.series(limit=200)          # oldest→newest for the chart
        spark = hist.sparkline(width=32)      # tiny text sparkline for the HUD
        d = hist.trend(window_s=86400)        # +/- change over the last day
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        # check_same_thread=False: the GUI thread reads while a worker records.
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        # A posture write must not exclude a dashboard read. WAL keeps readers
        # on the last committed snapshot while the writer appends the next one.
        # These are the same low-contention settings used by FlightRecorder.
        for pragma in (
            "journal_mode=WAL",
            "synchronous=NORMAL",
            "busy_timeout=3000",
            "wal_autocheckpoint=1000",
        ):
            try:
                self._db.execute(f"PRAGMA {pragma}")
            except sqlite3.Error:
                pass
        self._db.executescript(_SCHEMA)
        self._db.commit()

        # The old HUD path used the writer connection and its Python lock. A
        # slow commit therefore parked Qt for 5-8 seconds in sparkline(). File
        # stores now get a dedicated zero-wait, read-only snapshot connection.
        # In-memory stores cannot be shared by a second connection, so tests and
        # standalone callers use the writer connection through a non-blocking
        # lock instead.
        self._ui_lock = threading.Lock()
        self._ui_db: Optional[sqlite3.Connection] = None
        if str(db_path) != ":memory:":
            self._ui_db = sqlite3.connect(
                db_path, check_same_thread=False, timeout=0.0,
            )
            self._ui_db.execute("PRAGMA query_only=ON")
            self._ui_db.execute("PRAGMA busy_timeout=0")

        self._cache_lock = threading.Lock()
        self._spark_cache: "OrderedDict[tuple[int, Optional[float]], str]" = OrderedDict()
        self._trend_cache: "OrderedDict[float, dict]" = OrderedDict()
        # Writes are drained on a dedicated daemon thread so the INSERT+commit
        # (which can block for SECONDS behind a WAL checkpoint or a busy
        # flight-recorder.db lock) never runs on the caller. The GUI refresh
        # timer records posture every tick and was freezing the Qt main thread
        # inside self._db.commit() — see diagnostics/not_responding.log
        # (_refresh_posture → posture_history.record → commit).
        self._wq: "queue.Queue[Optional[tuple]]" = queue.Queue()
        self._writer = threading.Thread(
            target=self._writer_loop, name="PostureHistoryWriter", daemon=True
        )
        self._writer.start()

    # ── Write (append-only, off the caller thread) ────────────────────────────
    def record(self, score: int, band: str = "", note: str = "",
               ts: Optional[float] = None) -> PosturePoint:
        """Append one posture point. Score is clamped to 0–100; band is derived
        if not supplied. Returns the stored point immediately; the DB write is
        performed asynchronously by the writer thread so the caller (typically
        the Qt GUI thread) never blocks on SQLite."""
        s = max(0, min(100, int(score)))
        b = band or _band_for(s)
        t = time.time() if ts is None else float(ts)
        self._wq.put((t, s, b, note))
        return PosturePoint(t, s, b, note)

    def _writer_loop(self) -> None:
        """Persist queued points one at a time, off the caller thread."""
        while True:
            item = self._wq.get()
            try:
                if item is None:            # shutdown sentinel
                    return
                with self._lock:
                    self._db.execute(
                        "INSERT INTO posture_history (ts, score, band, note) "
                        "VALUES (?,?,?,?)",
                        item,
                    )
                    self._db.commit()
            except Exception:
                pass                        # never let a write kill the thread
            finally:
                self._wq.task_done()

    def flush(self) -> None:
        """Block until all queued points are written (shutdown / tests)."""
        self._wq.join()

    # ── Reads (bounded) ───────────────────────────────────────────────────────
    def series(self, limit: int = 500, since: Optional[float] = None) -> list[PosturePoint]:
        """Return up to ``limit`` most-recent points, oldest→newest (chart order)."""
        q = "SELECT ts, score, band, note FROM posture_history"
        args: list = []
        if since is not None:
            q += " WHERE ts >= ?"
            args.append(float(since))
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(int(limit))
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [PosturePoint(r[0], r[1], r[2], r[3]) for r in reversed(rows)]

    def latest(self) -> Optional[PosturePoint]:
        with self._lock:
            row = self._db.execute(
                "SELECT ts, score, band, note FROM posture_history ORDER BY ts DESC LIMIT 1"
            ).fetchone()
        return PosturePoint(row[0], row[1], row[2], row[3]) if row else None

    def count(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM posture_history").fetchone()[0])

    def _try_ui_read(self, fn: Callable[[sqlite3.Connection], _T]) -> Optional[_T]:
        """Run a bounded interactive read, or return ``None`` immediately.

        A busy SQLite snapshot and a query that exceeds the short dashboard
        budget both mean "keep the last rendered value and retry next tick".
        This is intentionally separate from :meth:`series`, whose blocking,
        exact-read contract remains available to reports and tests.
        """
        if self._ui_db is None:
            if not self._lock.acquire(blocking=False):
                return None
            try:
                return fn(self._db)
            except sqlite3.Error:
                return None
            finally:
                self._lock.release()

        if not self._ui_lock.acquire(blocking=False):
            return None
        deadline = time.perf_counter() + _HUD_QUERY_BUDGET_S
        try:
            # timeout=0 handles database locks; the progress handler also puts
            # a hard bound on a very large local history scan.
            self._ui_db.set_progress_handler(
                lambda: 1 if time.perf_counter() >= deadline else 0, 1000,
            )
            return fn(self._ui_db)
        except sqlite3.Error:
            return None
        finally:
            try:
                self._ui_db.set_progress_handler(None, 0)
            except sqlite3.Error:
                pass
            self._ui_lock.release()

    @staticmethod
    def _remember(cache: OrderedDict, key, value) -> None:
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > _HUD_CACHE_KEYS:
            cache.popitem(last=False)

    def trend(self, window_s: float = 86400.0) -> dict:
        """Change in score over the last ``window_s`` seconds.

        Returns ``{"delta": int, "start": int|None, "current": int|None,
        "direction": "up"|"down"|"flat"|"n/a", "samples": int}``. ``delta`` is
        current minus the earliest point still inside the window."""
        window = float(window_s)

        def _read(db: sqlite3.Connection) -> dict:
            db.execute("BEGIN")
            try:
                row = db.execute(
                    "SELECT ts, score FROM posture_history ORDER BY ts DESC LIMIT 1"
                ).fetchone()
                if row is None:
                    return {"delta": 0, "start": None, "current": None,
                            "direction": "n/a", "samples": 0}
                current_ts, current = float(row[0]), int(row[1])
                cutoff = current_ts - window
                # OFFSET selects the oldest row only when the bounded window is
                # full; COUNT is performed inside SQLite, so no 100k-row Python
                # allocation is needed merely to calculate trend metadata.
                start_row, samples = db.execute(
                    "SELECT "
                    "(SELECT score FROM posture_history WHERE ts >= ? "
                    " ORDER BY ts DESC LIMIT 1 OFFSET ?), "
                    "(SELECT COUNT(*) FROM "
                    " (SELECT 1 FROM posture_history WHERE ts >= ? "
                    "  ORDER BY ts DESC LIMIT ?))",
                    (cutoff, _HUD_POINT_LIMIT - 1, cutoff, _HUD_POINT_LIMIT),
                ).fetchone()
                if start_row is None:
                    first = db.execute(
                        "SELECT score FROM posture_history WHERE ts >= ? "
                        "ORDER BY ts ASC LIMIT 1", (cutoff,),
                    ).fetchone()
                    start = int(first[0]) if first else current
                else:
                    start = int(start_row)
            finally:
                db.execute("ROLLBACK")
            delta = current - start
            direction = "up" if delta > 0 else "down" if delta < 0 else "flat"
            return {"delta": delta, "start": start, "current": current,
                    "direction": direction, "samples": int(samples)}

        result = self._try_ui_read(_read)
        with self._cache_lock:
            if result is not None:
                self._remember(self._trend_cache, window, dict(result))
                return result
            cached = self._trend_cache.get(window)
            if cached is not None:
                return dict(cached)
        return {"delta": 0, "start": None, "current": None,
                "direction": "n/a", "samples": 0}

    def downsample(self, n: int = 60, since: Optional[float] = None) -> list[PosturePoint]:
        """Evenly pick ≤ ``n`` points across the series for a fixed-width chart."""
        pts = self.series(limit=100000, since=since)
        if len(pts) <= n:
            return pts
        step = len(pts) / float(n)
        picked = [pts[min(len(pts) - 1, int(i * step))] for i in range(n)]
        if picked[-1] is not pts[-1]:
            picked[-1] = pts[-1]   # always keep the freshest point
        return picked

    def sparkline(self, width: int = 32, since: Optional[float] = None) -> str:
        """A tiny unicode sparkline of recent scores for the HUD status line.

        The interactive path never waits for the writer connection. If the
        read snapshot is momentarily busy, the last completed sparkline is
        returned and refreshed on the next timer tick.
        """
        blocks = "▁▂▃▄▅▆▇█"
        n = int(width)
        if n <= 0:
            return ""
        since_value = None if since is None else float(since)
        key = (n, since_value)

        def _read(db: sqlite3.Connection) -> str:
            q = "SELECT score FROM posture_history"
            args: list[object] = []
            if since_value is not None:
                q += " WHERE ts >= ?"
                args.append(since_value)
            q += " ORDER BY ts DESC LIMIT ?"
            args.append(_HUD_POINT_LIMIT)
            rows = db.execute(q, args).fetchall()
            if not rows:
                return ""
            scores = [int(row[0]) for row in reversed(rows)]
            if len(scores) > n:
                step = len(scores) / float(n)
                sampled = [scores[min(len(scores) - 1, int(i * step))]
                           for i in range(n)]
                sampled[-1] = scores[-1]
                scores = sampled
            lo = min(scores)
            hi = max(scores)
            span = (hi - lo) or 1
            return "".join(blocks[min(7, (score - lo) * 7 // span)]
                           for score in scores)

        result = self._try_ui_read(_read)
        with self._cache_lock:
            if result is not None:
                self._remember(self._spark_cache, key, result)
                return result
            return self._spark_cache.get(key, "")

    def close(self) -> None:
        self._wq.put(None)                  # tell the writer to stop
        self._writer.join(timeout=2.0)
        if self._ui_db is not None:
            with self._ui_lock:
                self._ui_db.close()
        with self._lock:
            self._db.close()

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Prove ordering, trend math, band derivation, and downsampling on a
        throwaway in-memory store (does not touch the real DB)."""
        try:
            h = PostureHistory(":memory:")
            base = 1_000_000.0
            for i, s in enumerate([40, 55, 70, 85, 90]):
                h.record(s, ts=base + i * 3600)     # one per hour, rising
            h.flush()                               # wait for async writes
            assert h.count() == 5, "all points stored"

            ser = h.series()
            assert [p.score for p in ser] == [40, 55, 70, 85, 90], "oldest→newest order"
            assert ser[0].band == "CRITICAL" and ser[-1].band == "STRONG", "band derivation"

            last = h.latest()
            assert last is not None and last.score == 90, "latest is freshest"

            tr = h.trend(window_s=10 * 3600)        # whole window
            assert tr["delta"] == 50 and tr["direction"] == "up", "trend = 90-40 up"

            # narrow window catches only the last two points (85→90)
            tr2 = h.trend(window_s=3600 + 1)
            assert tr2["delta"] == 5 and tr2["samples"] == 2, "windowed trend"

            # downsample never exceeds n and preserves endpoints
            many = PostureHistory(":memory:")
            for i in range(500):
                many.record(i % 101, ts=base + i)
            many.flush()                            # wait for async writes
            ds = many.downsample(60)
            assert len(ds) <= 60, "downsample bound"
            assert ds[0].ts == base and ds[-1].ts == base + 499, "endpoints preserved"

            spark = many.sparkline(16)
            assert len(spark) == 16, "sparkline width"

            h.close(); many.close()
            return True, ("OK — 5-point series ordered oldest→newest; bands "
                          "CRITICAL..STRONG; full-window trend +50 up, 2-point "
                          "window +5; downsample≤60 with endpoints kept; sparkline width honoured.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Singleton factory (mirrors remediation_log.get_log / init_log) ─────────────
_HISTORY: Optional[PostureHistory] = None


def init_history(db_path: str) -> PostureHistory:
    """Create/replace the process-wide store, e.g. pointed at flight-recorder.db.
    Call once from ``app.py`` if you opt in; otherwise never invoked."""
    global _HISTORY
    _HISTORY = PostureHistory(db_path)
    return _HISTORY


def get_history(db_path: str = ":memory:") -> PostureHistory:
    """Return the shared store, lazily creating one so HUD reads are always safe."""
    global _HISTORY
    if _HISTORY is None:
        _HISTORY = PostureHistory(db_path)
    return _HISTORY


if __name__ == "__main__":
    ok, detail = PostureHistory().self_test()
    print(f"[posture_history] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
