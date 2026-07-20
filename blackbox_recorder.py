#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
blackbox_recorder.py  —  Project Angerona "Black Box" out-of-band diagnostic recorder
=====================================================================================

A COMPLETELY DECOUPLED, STRICTLY READ-ONLY flight recorder for the Angerona
security suite.  It survives a fatal deadlock of the main suite because it shares
*nothing* with it: no IPC socket, no EventBus subscription, no shared mutex.  It
only ever *reads* diagnostic files from disk and queries the OS via ``psutil``.

Design contract (do not violate)
--------------------------------
  • READ-ONLY.  Nothing here writes to, signals, or commands the Angerona process.
    The only files this program writes are its own exports under ``archive/`` and
    the diagnostic bundles it produces — never anything Angerona reads.
  • ZERO-INTERFERENCE.  No IPC (loopback :65432 is never touched).  No EventBus.
  • LOW OVERHEAD.  Every background worker polls on a relaxed 2–5 s cycle and only
    reads the *appended* bytes of log files (tail-style), never the whole file.
  • SAFE I/O.  Files are opened read-only, in binary, with errors ignored, and are
    closed immediately — we never hold a handle Angerona might need to write.
  • THREAD SAFETY.  All background→UI communication goes through Qt Signals/Slots
    (queued connections), so the GUI never blocks on a worker.

Launch
------
  python blackbox_recorder.py            # starts hidden in the system tray
  python blackbox_recorder.py --show     # starts with the window visible

Dependencies: PySide6 (incl. the bundled PySide6.QtCharts) and psutil — both are
already in Angerona's venv, so no new dependency is introduced.
"""
from __future__ import annotations

import ctypes
import datetime as _dt
import hashlib
import io
import json
import os
import re
import shutil
import sys
import time
import traceback
import zipfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Deque, Dict, List, Optional, Tuple

import psutil

# QtCharts ships in the SEPARATE PySide6-Addons package. On an Essentials-only
# PySide6 install it's missing, and importing it would crash the recorder on
# startup — which (under pythonw, no console) looks like "it just doesn't launch".
# Make it optional: the telemetry tab falls back to numeric bars without the graph.
try:
    from PySide6.QtCharts import (
        QChart,
        QChartView,
        QDateTimeAxis,
        QLineSeries,
        QValueAxis,
    )
    _HAS_CHARTS = True
except Exception:
    _HAS_CHARTS = False
from PySide6.QtCore import (
    QDateTime,
    QObject,
    QPointF,
    Qt,
    QThread,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QFont,
    QIcon,
    QPainter,
    QPen,
    QPixmap,
    QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QSizePolicy,
    QSystemTrayIcon,
    QTableWidget,
    QTextEdit,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# ─────────────────────────────────────────────────────────────────────────────
#  Paths & constants
# ─────────────────────────────────────────────────────────────────────────────
APP_NAME = "Angerona Black Box"
APP_DIR = (Path(sys.executable).resolve().parent if getattr(sys, "frozen", False)
           else Path(__file__).resolve().parent)
RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))


def _angerona_data_dir() -> Path:
    """Resolve the same protected runtime root used by the suite."""
    configured = os.environ.get("ANGERONA_DATA", "").strip()
    if configured:
        return Path(configured).expanduser()
    if getattr(sys, "frozen", False):
        return Path(os.environ.get("PROGRAMDATA", str(APP_DIR))) / "Angerona"
    return APP_DIR / "runtime-data"


DATA_DIR = _angerona_data_dir()
DIAG_DIR = Path(os.environ.get("ANGERONA_DIAG_DIR") or (DATA_DIR / "diagnostics"))
ARCHIVE_DIR = DATA_DIR / "archive"
DATA_DIAG = DIAG_DIR

# Repo-side (next to the suite source) — uiwatchdog, status.json, flow_metrics,
# runtime_alerts, and a mirror of crash.log are written here.
CRASH_SNAP_DIR = DIAG_DIR / "crash_snapshots"
DATA_CRASH_SNAP_DIR = DATA_DIAG / "crash_snapshots"      # module quarantine bundles
NOT_RESPONDING = DIAG_DIR / "not_responding.log"
SELFTEST_FAILURES = DIAG_DIR / "selftest_failures.json"
CRASH_LOG = DIAG_DIR / "crash.log"
DATA_CRASH_LOG = DATA_DIR / "logs" / "crash.log"         # crashlog.py primary target
RUNTIME_ALERTS = DIAG_DIR / "runtime_alerts.log"         # CRITICAL/stall feed from the suite
STATUS_JSON = DIAG_DIR / "status.json"
DATA_STATUS_JSON = DATA_DIAG / "status.json"
FLOW_METRICS = DIAG_DIR / "flow_metrics.json"
SETTINGS_JSON = DATA_DIR / "settings.json"
ENV_FILE = DATA_DIR / ".env"
RINGBUFFER = DATA_DIR / "telemetry_ringbuffer.mmap"
FLIGHT_RECORDER = DATA_DIR / "flight-recorder.db"        # real DB lives in the data dir
THREAD_DUMP = DIAG_DIR / "thread_dump.json"
TRACEMALLOC_SNAP = DIAG_DIR / "tracemalloc.json"

# Colour palette — spec-mandated cyber/slate identity.
BG = "#11141a"
PANEL = "#161b24"
PANEL2 = "#1b2230"
BORDER = "#232c3b"
TEXT = "#d6e2f0"
DIM = "#7c8aa0"
ACCENT = "#38bdf8"
RED = "#ef4444"       # critical exceptions
AMBER = "#fbbf24"     # quick hints
GREEN = "#22c55e"
ALT_ROW = "#ffffff08"
MONO = "'Fira Code','Consolas','Cascadia Mono',monospace"

# Relaxed polling intervals (seconds) → near-zero host footprint.
HOST_POLL_S = 2.0
TAIL_POLL_S = 2.0
HEALTH_POLL_S = 3.0
THREAD_POLL_S = 3.0
CONFIG_POLL_S = 4.0
MEM_POLL_S = 5.0


def _selftest_failures(data) -> List[Dict]:
    """Accept both historical self-test report schemas.

    Older reports are dictionaries containing ``failures``; newer runs may write
    the failure records as the top-level list. Black Box is a reader and must
    tolerate either shape rather than killing its worker threads.
    """
    if isinstance(data, dict):
        rows = data.get("failures", [])
    elif isinstance(data, list):
        rows = data
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def _acquire_single_instance():
    """Hold a process-lifetime Windows mutex; return ``None`` for a duplicate."""
    if not sys.platform.startswith("win"):
        return True
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create_mutex = kernel.CreateMutexW
    create_mutex.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    create_mutex.restype = ctypes.c_void_p
    handle = create_mutex(None, False, r"Local\AngeronaBlackBox")
    if not handle:
        return None
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        kernel.CloseHandle(handle)
        return None
    return handle

CHART_WINDOW = 120          # rolling samples kept on the telemetry graphs
FRESH_STATUS_S = 20.0       # status.json newer than this ⇒ event bus "moving"


# ─────────────────────────────────────────────────────────────────────────────
#  Known-error heuristics (Quick Hints)  — requirement #13
# ─────────────────────────────────────────────────────────────────────────────
# Each entry: compiled regex → hint string.  Matched against the RAW stack trace
# inside the tailing worker; the first match per block is surfaced.
HEURISTICS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"psutil\.AccessDenied"),
     "Execution context lacks elevation. Verify the suite was launched as Administrator."),
    (re.compile(r"database is locked", re.I),
     "SQLite is contended. A module likely holds a write txn on the flight recorder — "
     "check for an orphaned handle on flight-recorder.db (Tab 6)."),
    (re.compile(r"sqlite3\.OperationalError"),
     "SQLite operational error. DB may be locked, missing, or the schema drifted."),
    (re.compile(r"\bMemoryError\b"),
     "Process is out of memory. Inspect Tab 5 for a runaway object type (e.g. an "
     "overflowing EventBus array)."),
    (re.compile(r"ConnectionRefusedError|WinError 10061"),
     "A local endpoint refused the connection. Ollama (:11434) or the IPC gate "
     "(:65432) may be down."),
    (re.compile(r"(?:ReadTimeout|ConnectTimeout|timed out)", re.I),
     "A network/model call timed out. Ollama may be cold-loading llama3 into VRAM."),
    (re.compile(r"ModuleNotFoundError|ImportError"),
     "A dependency failed to import. The venv may be incomplete — re-run install.bat."),
    (re.compile(r"PermissionError|WinError 5\b"),
     "OS denied access to a resource. Elevation or a file lock is the usual cause."),
    (re.compile(r"deadlock|Thread.*blocked|acquire.*Lock", re.I),
     "Possible lock contention. Cross-check the thread state visualizer (Tab 4) for "
     "two threads blocked on the same lock."),
    (re.compile(r"json\.decoder\.JSONDecodeError"),
     "A diagnostic JSON was read mid-write. Usually transient; the writer will finish."),
    (re.compile(r"WinError 10048"),
     "Address already in use. A stale Angerona instance may still hold port :65432 — "
     "run kill-all-angerona.bat."),
]

CRITICAL_MARKERS = re.compile(
    r"Traceback \(most recent call last\)|CRITICAL|FATAL|\bError\b|Exception|"
    r"NOT RESPONDING|deadlock",
    re.I,
)

# ── Plain-English protocol (requirement) ─────────────────────────────────────
# Each entry: regex → a plain-English sentence explaining what that error means.
# Rendered in GREEN beneath the raw trace so a non-expert understands each line.
PLAIN_ENGLISH: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"ModuleNotFoundError|No module named"),
     "A Python package the code needs isn't installed. Re-run install.bat to rebuild the virtual environment."),
    (re.compile(r"ImportError"),
     "A file tried to import something that no longer exists or failed to load — usually a bad edit or a missing dependency."),
    (re.compile(r"AttributeError"),
     "The code called a method/property on an object that doesn't have it — often a typo or a value that was None."),
    (re.compile(r"\bNameError\b"),
     "The code used a variable/function name that was never defined (typo, or defined in a different scope)."),
    (re.compile(r"\bTypeError\b"),
     "A value of the wrong type was used — e.g. calling something that isn't a function, or wrong argument types."),
    (re.compile(r"\bKeyError\b"),
     "The code looked up a dictionary key that isn't present."),
    (re.compile(r"\bIndexError\b"),
     "The code asked for a list position that doesn't exist (list was shorter than expected)."),
    (re.compile(r"\bValueError\b"),
     "A function got a value of the right type but an unacceptable content (e.g. int('abc'))."),
    (re.compile(r"ZeroDivisionError"),
     "The code divided by zero."),
    (re.compile(r"\bSyntaxError\b|IndentationError|unterminated"),
     "The Python file itself is malformed — a recent edit broke the code's structure. It won't run until fixed."),
    (re.compile(r"RecursionError|maximum recursion"),
     "A function kept calling itself without stopping — an infinite loop of calls."),
    (re.compile(r"\bMemoryError\b"),
     "The process ran out of RAM. Something is using too much memory (see the Memory Profiler tab)."),
    (re.compile(r"PermissionError|WinError 5\b|Access is denied"),
     "Windows blocked access to a file or resource — you likely need to run as Administrator, or a file is locked."),
    (re.compile(r"FileNotFoundError|WinError 2\b|No such file"),
     "A file the code expected wasn't there (moved, deleted, or a wrong path)."),
    (re.compile(r"ConnectionRefusedError|WinError 10061"),
     "A local service refused the connection — Ollama (:11434) or the IPC gate (:65432) is probably not running."),
    (re.compile(r"(?:ReadTimeout|ConnectTimeout|timed out)", re.I),
     "A network/model call took too long. Local AI (Ollama) may be cold-loading the model — this can be slow."),
    (re.compile(r"database is locked|sqlite3\.OperationalError", re.I),
     "The local database is busy or contended — two things tried to write the flight recorder at once."),
    (re.compile(r"json\.decoder\.JSONDecodeError|Expecting value"),
     "A data file was read while it was half-written. Usually harmless and transient."),
    (re.compile(r"deadlock|Thread.*blocked|acquire.*Lock|NOT RESPONDING", re.I),
     "Two parts of the program are waiting on each other, or the UI thread is stuck — a freeze/deadlock."),
    (re.compile(r"QThread|Qt|PySide"),
     "A GUI (Qt/PySide6) error — often a widget touched from a background thread instead of the main thread."),
]


def plain_english_for(text: str) -> List[str]:
    out: List[str] = []
    for pat, msg in PLAIN_ENGLISH:
        if pat.search(text):
            out.append(msg)
    return out


# Matches a Python traceback frame:  File "C:\...\x.py", line 115 in func
_TRACE_LINE = re.compile(r'File "([^"]+)",\s*line\s+(\d+)')


def now_stamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:,.1f} {unit}"
        n /= 1024.0
    return f"{n:,.1f} PB"


def find_angerona_pid() -> Optional[int]:
    """Best-effort, read-only discovery of the primary Angerona python PID.

    Never raises: on any access error it simply skips the process.  Matches a
    python interpreter whose command line references the ``angerona`` package
    (``python -m angerona`` / ``pythonw -m angerona``) but is NOT this recorder.
    """
    me = os.getpid()
    best: Optional[int] = None
    best_rss = -1
    for proc in psutil.process_iter(["pid", "name", "cmdline", "memory_info"]):
        try:
            if proc.info["pid"] == me:
                continue
            name = (proc.info["name"] or "").lower()
            if "python" not in name and "angerona" not in name:
                continue
            cmd = " ".join(proc.info["cmdline"] or []).lower()
            if "blackbox_recorder" in cmd:
                continue
            if "angerona" not in cmd and "-m angerona" not in cmd:
                continue
            rss = (proc.info["memory_info"].rss if proc.info["memory_info"] else 0)
            # Prefer the largest resident python — the real suite, not a helper.
            if rss > best_rss:
                best_rss = rss
                best = proc.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return best


def safe_tail_bytes(path: Path, offset: int) -> Tuple[bytes, int]:
    """Read only bytes appended since ``offset``.  Returns (data, new_offset).

    Opens read-only + binary and closes immediately so we never hold a handle
    that would block Angerona's writer.  Handles truncation/rotation by resetting
    the offset when the file shrinks.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return b"", offset
    if size < offset:          # rotated or truncated → start over
        offset = 0
    if size == offset:
        return b"", offset
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(size - offset)
        return data, size
    except OSError:
        return b"", offset


def prime_offset(path: Path, tail_bytes: int = 8192) -> int:
    """Return an offset that skips all but the last ``tail_bytes`` of a file."""
    try:
        size = path.stat().st_size
    except OSError:
        return 0
    return max(0, size - tail_bytes)


# ─────────────────────────────────────────────────────────────────────────────
#  Background workers — each a QThread that only READS and emits via Signals
# ─────────────────────────────────────────────────────────────────────────────
class LogTailWorker(QThread):
    """Tab 1 engine: tails the crash/diagnostic files and classifies each block.

    Emits:
      block(raw_text:str, severity:str, hints:list[str])   for the console
      exception_at(ts_epoch:float)                          for the Tab-2 overlay
    """

    block = Signal(str, str, list)
    exception_at = Signal(float)

    def __init__(self) -> None:
        super().__init__()
        self._running = True
        # file → last byte offset already consumed
        self._offsets: Dict[Path, int] = {}
        self._seen_snaps: set = set()

    def stop(self) -> None:
        self._running = False

    # -- classification ------------------------------------------------------
    @staticmethod
    def _hints_for(text: str) -> List[str]:
        out: List[str] = []
        for pattern, hint in HEURISTICS:
            if pattern.search(text):
                out.append(hint)
        return out

    @staticmethod
    def _severity_for(text: str) -> str:
        return "critical" if CRITICAL_MARKERS.search(text) else "info"

    def _emit_text(self, source: str, text: str) -> None:
        text = text.strip("\n")
        if not text:
            return
        sev = self._severity_for(text)
        hints = self._hints_for(text)
        header = f"──[ {source} @ {_dt.datetime.now():%H:%M:%S} ]" + "─" * 24
        self.block.emit(header + "\n" + text, sev, hints)
        if sev == "critical":
            self.exception_at.emit(time.time())

    # All plain appended-text logs the recorder tails, across BOTH the repo-side
    # diagnostics dir and the per-user data dir (so no crash evidence is missed).
    _TAIL_FILES = (
        (NOT_RESPONDING, "not_responding.log"),
        (CRASH_LOG, "crash.log (repo)"),
        (DATA_CRASH_LOG, "crash.log (data)"),
        (RUNTIME_ALERTS, "runtime_alerts.log"),
    )
    _SNAP_DIRS = (CRASH_SNAP_DIR, DATA_CRASH_SNAP_DIR)

    def run(self) -> None:  # noqa: D401 — QThread entry point
        # Prime offsets so we start near the tail of pre-existing (huge) logs.
        for p, _label in self._TAIL_FILES:
            self._offsets[p] = prime_offset(p)
        self._offsets[SELFTEST_FAILURES] = 0  # small file, read fully once
        for snap_dir in self._SNAP_DIRS:
            if snap_dir.is_dir():
                self._seen_snaps |= {f.name for f in snap_dir.glob("*")}

        self.block.emit(
            f"[ Black Box recorder armed @ {_dt.datetime.now():%Y-%m-%d %H:%M:%S} ] "
            f"watching {DIAG_DIR}  +  {DATA_DIAG}", "info", [],
        )

        while self._running:
            # 1) plain appended-text logs (repo + data dir)
            for p, label in self._TAIL_FILES:
                data, self._offsets[p] = safe_tail_bytes(p, self._offsets.get(p, 0))
                if data:
                    self._emit_text(label, data.decode("utf-8", "replace"))

            # 2) selftest_failures.json — re-read on change, render failures
            try:
                cur = SELFTEST_FAILURES.stat().st_mtime if SELFTEST_FAILURES.exists() else 0
            except OSError:
                cur = 0
            if cur and cur != self._offsets.get("_selftest_mtime", 0):
                self._offsets["_selftest_mtime"] = cur
                self._emit_selftest()

            # 3) crash_snapshots/ (repo + data dir) — surface each new bundle in full
            for snap_dir in self._SNAP_DIRS:
                if not snap_dir.is_dir():
                    continue
                try:
                    for f in sorted(snap_dir.glob("*")):
                        if f.name not in self._seen_snaps and f.is_file():
                            self._seen_snaps.add(f.name)
                            try:
                                raw = f.read_text("utf-8", "replace")
                            except OSError:
                                continue
                            self._emit_text(f"crash_snapshots/{f.name}", raw)
                except OSError:
                    pass

            # relaxed cadence
            for _ in range(int(TAIL_POLL_S * 10)):
                if not self._running:
                    break
                self.msleep(100)

    def _emit_selftest(self) -> None:
        try:
            data = json.loads(SELFTEST_FAILURES.read_text("utf-8", "replace"))
        except (OSError, json.JSONDecodeError):
            return
        fails = _selftest_failures(data)
        if not fails:
            return
        meta = data if isinstance(data, dict) else {}
        lines = [f"selftest: {meta.get('failed', len(fails))} failed / "
                 f"{meta.get('passed', '?')} passed  (gen {meta.get('generated', '?')})"]
        for f in fails:
            lines.append(f"  ✗ {f.get('module', '?')}: {f.get('detail', '')}")
        self._emit_text("selftest_failures.json", "\n".join(lines))


class HostTelemetryWorker(QThread):
    """Tab 2 engine: host hardware metrics on a relaxed cycle."""

    metrics = Signal(dict)

    def __init__(self) -> None:
        super().__init__()
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        # Prime cpu_percent (first call always returns 0.0).
        psutil.cpu_percent(percpu=True)
        last_io = psutil.disk_io_counters()
        last_t = time.time()
        while self._running:
            time.sleep(HOST_POLL_S)
            if not self._running:
                break
            try:
                per_core = psutil.cpu_percent(percpu=True)
                total = sum(per_core) / len(per_core) if per_core else 0.0
                vm = psutil.virtual_memory()
                io = psutil.disk_io_counters()
                now = time.time()
                dt = max(1e-6, now - last_t)
                read_bps = (io.read_bytes - last_io.read_bytes) / dt if io and last_io else 0
                write_bps = (io.write_bytes - last_io.write_bytes) / dt if io and last_io else 0
                last_io, last_t = io, now
                self.metrics.emit({
                    "ts": now,
                    "cpu_total": total,
                    "per_core": per_core,
                    "ram_used": vm.used,
                    "ram_total": vm.total,
                    "ram_pct": vm.percent,
                    "read_bps": max(0.0, read_bps),
                    "write_bps": max(0.0, write_bps),
                })
            except Exception:  # never let telemetry kill the thread
                continue


class SuiteHealthWorker(QThread):
    """Tab 3 engine: is Angerona alive, and is the event bus moving data?"""

    health = Signal(dict)

    def __init__(self) -> None:
        super().__init__()
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        while self._running:
            info: Dict = {"pid": None, "state": "DEAD", "cpu": 0.0, "rss": 0,
                          "bus_ts": None, "bus_fresh": False, "failed": [],
                          "counts": {}}
            pid = find_angerona_pid()
            info["pid"] = pid
            if pid:
                try:
                    p = psutil.Process(pid)
                    with p.oneshot():
                        status = p.status()
                        info["cpu"] = p.cpu_percent(interval=0.0)
                        info["rss"] = p.memory_info().rss
                        info["create_time"] = p.create_time()
                    # A process pegged in 'disk-sleep'/'stopped' or not scheduling
                    # is a candidate freeze; refine with the bus freshness below.
                    info["state"] = "FROZEN" if status in (
                        psutil.STATUS_STOPPED, psutil.STATUS_DISK_SLEEP) else "RUNNING"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    info["state"] = "DEAD"

            # event-bus liveness via status.json / flow_metrics.json / ringbuffer
            bus_ts = self._latest_bus_ts()
            info["bus_ts"] = bus_ts
            if bus_ts is not None:
                info["bus_fresh"] = (time.time() - bus_ts) <= FRESH_STATUS_S
                # A live process whose bus is stale ⇒ likely deadlocked.
                if info["state"] == "RUNNING" and not info["bus_fresh"]:
                    info["state"] = "FROZEN"

            info["failed"] = self._failed_modules()
            info["counts"] = self._status_counts()
            self.health.emit(info)

            for _ in range(int(HEALTH_POLL_S * 10)):
                if not self._running:
                    break
                self.msleep(100)

    @staticmethod
    def _pick_status() -> Optional[Path]:
        """Return the freshest existing status.json across repo + data dir."""
        best: Optional[Path] = None
        best_ts = -1.0
        for p in (STATUS_JSON, DATA_STATUS_JSON):
            try:
                if p.exists():
                    ts = p.stat().st_mtime
                    if ts > best_ts:
                        best_ts, best = ts, p
            except OSError:
                continue
        return best

    @staticmethod
    def _latest_bus_ts() -> Optional[float]:
        candidates: List[float] = []
        for p in (STATUS_JSON, DATA_STATUS_JSON, FLOW_METRICS, RINGBUFFER, FLIGHT_RECORDER):
            try:
                if p.exists():
                    candidates.append(p.stat().st_mtime)
            except OSError:
                continue
        return max(candidates) if candidates else None

    @classmethod
    def _failed_modules(cls) -> List[Dict]:
        out: List[Dict] = []
        # selftest failures
        try:
            if SELFTEST_FAILURES.exists():
                d = json.loads(SELFTEST_FAILURES.read_text("utf-8", "replace"))
                for f in _selftest_failures(d):
                    out.append({"name": f.get("module", "?"),
                                "detail": f.get("detail", ""), "src": "selftest"})
        except (OSError, json.JSONDecodeError):
            pass
        # status.json modules with errors / stopped-but-enabled
        try:
            sp = cls._pick_status()
            if sp:
                d = json.loads(sp.read_text("utf-8", "replace"))
                modules = d.get("modules", []) if isinstance(d, dict) else []
                for m in modules:
                    if not isinstance(m, dict):
                        continue
                    err = m.get("last_error") or ""
                    bad_state = m.get("health_state") in ("error", "crit")
                    if err or bad_state:
                        out.append({"name": m.get("name", "?"),
                                    "detail": err or m.get("health_note", ""),
                                    "src": "status"})
        except (OSError, json.JSONDecodeError):
            pass
        return out

    @classmethod
    def _status_counts(cls) -> Dict:
        try:
            sp = cls._pick_status()
            if sp:
                d = json.loads(sp.read_text("utf-8", "replace"))
                return d.get("counts", {}) if isinstance(d, dict) else {}
        except (OSError, json.JSONDecodeError):
            pass
        return {}


class ThreadStateWorker(QThread):
    """Tab 4 engine: thread-state visualizer.

    Read-only.  Prefers a cooperative dump Angerona may drop at
    ``diagnostics/thread_dump.json`` (name/id/function/line).  If absent, falls
    back to per-thread OS data from psutil for the Angerona PID — we can still
    surface thread ids, CPU time and status to spot a wedged thread.
    """

    threads = Signal(list, str)   # rows, source-label

    def __init__(self) -> None:
        super().__init__()
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        while self._running:
            rows, src = self._collect()
            self.threads.emit(rows, src)
            for _ in range(int(THREAD_POLL_S * 10)):
                if not self._running:
                    break
                self.msleep(100)

    def _collect(self) -> Tuple[List[Dict], str]:
        # Preferred: cooperative JSON dump written by Angerona itself.
        if THREAD_DUMP.exists():
            try:
                d = json.loads(THREAD_DUMP.read_text("utf-8", "replace"))
                items = d.get("threads", d) if isinstance(d, dict) else d
                rows = []
                for t in items:
                    rows.append({
                        "name": str(t.get("name", "?")),
                        "id": str(t.get("id", t.get("tid", "?"))),
                        "where": f'{t.get("function", t.get("func", "?"))}'
                                 f':{t.get("lineno", t.get("line", "?"))}',
                        "state": str(t.get("state", t.get("status", ""))),
                    })
                if rows:
                    return rows, "cooperative dump (thread_dump.json)"
            except (OSError, json.JSONDecodeError):
                pass

        # Fallback: OS thread table for the Angerona PID.
        pid = find_angerona_pid()
        if not pid:
            return [], "no Angerona PID found"
        try:
            p = psutil.Process(pid)
            status = p.status()
            rows = []
            for th in p.threads():
                rows.append({
                    "name": f"tid-{th.id}",
                    "id": str(th.id),
                    "where": f"user={th.user_time:.2f}s sys={th.system_time:.2f}s",
                    "state": status,
                })
            return rows, f"OS thread table (pid {pid}) — no cooperative dump"
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            return [], f"psutil: {exc.__class__.__name__}"


class MemoryProfilerWorker(QThread):
    """Tab 5 engine: top memory consumers.

    Prefers an Angerona-generated ``tracemalloc.json`` (top object types).  If
    absent, uses psutil memory-map data for the Angerona PID to rank the largest
    resident mappings — a coarse but honest leak indicator.
    """

    rows = Signal(list, str)

    def __init__(self) -> None:
        super().__init__()
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        while self._running:
            rows, src = self._collect()
            self.rows.emit(rows, src)
            for _ in range(int(MEM_POLL_S * 10)):
                if not self._running:
                    break
                self.msleep(100)

    def _collect(self) -> Tuple[List[Dict], str]:
        if TRACEMALLOC_SNAP.exists():
            try:
                d = json.loads(TRACEMALLOC_SNAP.read_text("utf-8", "replace"))
                items = d.get("top", d) if isinstance(d, dict) else d
                rows = []
                for it in items[:50]:
                    rows.append({
                        "label": str(it.get("type", it.get("traceback", it.get("file", "?")))),
                        "size": int(it.get("size", it.get("size_bytes", 0))),
                        "count": int(it.get("count", 0)),
                    })
                rows.sort(key=lambda r: r["size"], reverse=True)
                if rows:
                    return rows[:10], "tracemalloc snapshot"
            except (OSError, json.JSONDecodeError, ValueError):
                pass

        pid = find_angerona_pid()
        if not pid:
            return [], "no Angerona PID found"
        try:
            p = psutil.Process(pid)
            agg: Dict[str, List[int]] = {}
            for m in p.memory_maps():
                path = m.path or "[anonymous]"
                rss = getattr(m, "rss", 0) or 0
                a = agg.setdefault(path, [0, 0])
                a[0] += rss
                a[1] += 1
            rows = [{"label": k, "size": v[0], "count": v[1]} for k, v in agg.items()]
            rows.sort(key=lambda r: r["size"], reverse=True)
            return rows[:10], f"psutil memory maps (pid {pid}) — no tracemalloc snapshot"
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            return [], f"psutil: {exc.__class__.__name__}"


class ConfigDriftWorker(QThread):
    """Tab 6 engine: config-drift + orphaned resource monitor."""

    drift = Signal(dict)

    def __init__(self) -> None:
        super().__init__()
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        while self._running:
            self.drift.emit(self._collect())
            for _ in range(int(CONFIG_POLL_S * 10)):
                if not self._running:
                    break
                self.msleep(100)

    def _collect(self) -> Dict:
        out: Dict = {"files": [], "sockets": [], "handles": [], "pid": None}
        for label, p in (("settings.json", SETTINGS_JSON), (".env", ENV_FILE),
                         ("flight-recorder.db", FLIGHT_RECORDER),
                         ("status.json", STATUS_JSON)):
            try:
                if p.exists():
                    st = p.stat()
                    out["files"].append({
                        "label": label,
                        "mtime": _dt.datetime.fromtimestamp(st.st_mtime)
                                   .strftime("%Y-%m-%d %H:%M:%S"),
                        "age_s": time.time() - st.st_mtime,
                        "size": st.st_size,
                    })
                else:
                    out["files"].append({"label": label, "mtime": "— missing —",
                                         "age_s": None, "size": 0})
            except OSError:
                out["files"].append({"label": label, "mtime": "— error —",
                                     "age_s": None, "size": 0})

        pid = find_angerona_pid()
        out["pid"] = pid
        if pid:
            try:
                p = psutil.Process(pid)
                try:
                    for c in p.net_connections(kind="inet"):
                        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                        out["sockets"].append({
                            "laddr": laddr, "raddr": raddr, "status": c.status,
                            "orphan": c.status == psutil.CONN_CLOSE_WAIT,
                        })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                try:
                    for h in p.open_files():
                        name = h.path
                        flag = any(tag in name.lower() for tag in
                                   ("flight-recorder.db", ".mmap", "agent_memory.db",
                                    "ude_telemetry.db"))
                        out["handles"].append({"path": name, "flag": flag})
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return out


# ─────────────────────────────────────────────────────────────────────────────
#  Small UI helpers
# ─────────────────────────────────────────────────────────────────────────────
def make_icon(color: str = ACCENT) -> QIcon:
    """Return the Black Box icon. Prefer the shipped blackbox.ico (black box on a
    blue background — matches the desktop shortcut); fall back to a runtime-drawn
    glyph if the asset is missing."""
    try:
        ico = RESOURCE_DIR / "assets" / "icons" / "blackbox.ico"
        if ico.exists():
            icon = QIcon(str(ico))
            if not icon.isNull():
                return icon
    except Exception:
        pass
    pix = QPixmap(64, 64)
    pix.fill(QColor("#00000000"))
    pnt = QPainter(pix)
    pnt.setRenderHint(QPainter.Antialiasing)
    pnt.setBrush(QColor(BG))
    pnt.setPen(QPen(QColor(color), 4))
    pnt.drawRoundedRect(8, 8, 48, 48, 8, 8)
    pnt.setPen(QPen(QColor(color), 5))
    pnt.setBrush(QColor(color))
    pnt.drawEllipse(24, 24, 16, 16)   # the "recording" dot
    pnt.end()
    return QIcon(pix)


def section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color:{ACCENT};font-weight:700;letter-spacing:1px;"
        f"padding:2px 0 6px 0;font-size:12px;")
    return lbl


def metric_bar(label: str) -> Tuple[QWidget, QProgressBar, QLabel]:
    box = QWidget()
    lay = QVBoxLayout(box)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(2)
    top = QHBoxLayout()
    name = QLabel(label)
    name.setStyleSheet(f"color:{DIM};font-size:11px;")
    val = QLabel("—")
    val.setStyleSheet(f"color:{TEXT};font-size:11px;font-weight:700;")
    val.setAlignment(Qt.AlignRight)
    top.addWidget(name)
    top.addWidget(val)
    bar = QProgressBar()
    bar.setRange(0, 100)
    bar.setTextVisible(False)
    bar.setFixedHeight(10)
    lay.addLayout(top)
    lay.addWidget(bar)
    return box, bar, val


# ─────────────────────────────────────────────────────────────────────────────
#  Tab 1 — Live crash & error logs
# ─────────────────────────────────────────────────────────────────────────────
def _consult_ai(prompt: str) -> dict:
    """Reach the shared online-AI consult (Claude first, per Settings order).
    Adds ./src to the path so the standalone recorder can import the package."""
    try:
        from angerona.engines.ai_consult import consult_ai
    except Exception:
        try:
            srcp = str(APP_DIR / "src")
            if srcp not in sys.path:
                sys.path.insert(0, srcp)
            from angerona.engines.ai_consult import consult_ai
        except Exception as exc:
            return {"text": "", "provider": None, "error": f"AI consult unavailable: {exc}"}
    try:
        return consult_ai(prompt)
    except Exception as exc:
        return {"text": "", "provider": None, "error": str(exc)}


class _AiFixWorker(QThread):
    done = Signal(dict)

    def __init__(self, prompt: str) -> None:
        super().__init__()
        self._prompt = prompt

    def run(self) -> None:
        self.done.emit(_consult_ai(self._prompt))


class CrashInspector(QWidget):
    """Right-side panel: paste a traceback line → open the file (elevating if
    needed) → show the exact failing line (in RED) with line numbers, and ask an
    AI how to fix it."""

    def __init__(self) -> None:
        super().__init__()
        self._file = None
        self._line = None
        self._worker = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.addWidget(section_label("INSPECTION  —  paste a trace line to see the failing code"))

        self.paste = QLineEdit()
        self.paste.setPlaceholderText('Paste e.g.  File "D:\\...\\ai_triage.py", line 115 in _ping_ollama')
        self.paste.returnPressed.connect(self.inspect)
        self.paste.textChanged.connect(self._on_paste_changed)
        lay.addWidget(self.paste)

        row = QHBoxLayout()
        b_ins = QPushButton("🔍 Inspect line")
        b_full = QPushButton("📄 Open full file")
        b_ai = QPushButton("🤖 Code Question (AI fix)")
        b_ins.clicked.connect(self.inspect)
        b_full.clicked.connect(lambda: self.inspect(full=True))
        b_ai.clicked.connect(self.code_question)
        for b in (b_ins, b_full, b_ai):
            row.addWidget(b)
        lay.addLayout(row)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet(f"color:{DIM}; font-size:11px;")
        lay.addWidget(self.status)

        self.code = QTextEdit()
        self.code.setReadOnly(True)
        f = QFont("Fira Code"); f.setStyleHint(QFont.Monospace); f.setPointSize(10)
        self.code.setFont(f)
        self.code.setStyleSheet(
            f"background:{BG};color:{TEXT};border:1px solid {BORDER};border-radius:8px;padding:6px;")
        lay.addWidget(self.code, 1)

        self.ai_out = QPlainTextEdit()
        self.ai_out.setReadOnly(True)
        self.ai_out.setPlaceholderText("AI fix appears here…")
        self.ai_out.setMaximumHeight(180)
        lay.addWidget(self.ai_out)

    # -- auto-inspect on paste ----------------------------------------------
    @Slot(str)
    def _on_paste_changed(self, text: str) -> None:
        """Fire inspect() automatically as soon as the pasted text contains
        a recognisable Python traceback line — no button click required."""
        if _TRACE_LINE.search(text):
            self.inspect()

    # -- parsing + reading --------------------------------------------------
    def _parse(self):
        m = _TRACE_LINE.search(self.paste.text())
        if not m:
            return None, None
        return m.group(1), int(m.group(2))

    def _read_lines(self, path: str):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read().splitlines(), None
        except PermissionError as exc:
            return None, f"PermissionError: {exc}"
        except Exception as exc:
            return None, str(exc)

    def inspect(self, full: bool = False) -> None:
        path, line = self._parse()
        if not path:
            self.status.setText("Couldn't find a 'File \"...\", line N' pattern in the pasted text.")
            return
        self._file, self._line = path, line
        lines, err = self._read_lines(path)
        if err:
            self.status.setText(f"⚠ {err}")
            if "Permission" in (err or ""):
                self._offer_elevation()
            return
        self.status.setText(f"{path} — line {line}  ({len(lines)} lines total)")
        lo = 0 if full else max(0, line - 13)
        hi = len(lines) if full else min(len(lines), line + 12)
        self._render(lines, lo, hi, line)

    def _render(self, lines, lo, hi, offending) -> None:
        self.code.clear()
        cur = self.code.textCursor()
        width = len(str(hi))
        for i in range(lo, hi):
            n = i + 1
            fmt = QTextCharFormat()
            is_bad = (n == offending)
            fmt.setForeground(QColor(RED if is_bad else TEXT))
            if is_bad:
                fmt.setFontWeight(QFont.Bold)
            prefix = f"{n:>{width}} {'▶' if is_bad else ' '} "
            cur.insertText(prefix + lines[i] + "\n", fmt)
        # snap the view to the offending line
        self.code.moveCursor(QTextCursor.Start)
        target = min(hi, offending) - lo
        for _ in range(max(0, target - 3)):
            self.code.moveCursor(QTextCursor.Down)
        self.code.ensureCursorVisible()

    def _offer_elevation(self) -> None:
        if QMessageBox.question(
            self, "Access denied",
            "Reading that file was blocked by Windows. Re-launch the Black Box as "
            "Administrator to read protected files?") != QMessageBox.Yes:
            return
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                f'"{os.path.abspath(__file__)}" --show', str(APP_DIR), 1)
        except Exception as exc:
            self.status.setText(f"Could not elevate: {exc}")

    def code_question(self) -> None:
        path, line = self._parse()
        if not path:
            self.status.setText("Paste a 'File \"...\", line N' trace line first.")
            return
        lines, err = self._read_lines(path)
        snippet = ""
        if lines:
            lo, hi = max(0, line - 25), min(len(lines), line + 25)
            snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))
        prompt = (
            "This Python file in a PySide6 security suite (Project Angerona) raised an "
            f"error at line {line} of {path}. Explain the likely cause and give a precise, "
            "minimal fix (show the corrected lines). If you need the whole file, say so.\n\n"
            f"Pasted trace line:\n{self.paste.text()}\n\n"
            f"Code around line {line} (line-numbered):\n{snippet or '(file unreadable: ' + str(err) + ')'}")
        self.ai_out.setPlainText("Asking AI (Claude first)…")
        self._worker = _AiFixWorker(prompt)
        self._worker.done.connect(self._ai_done)
        self._worker.start()

    @Slot(dict)
    def _ai_done(self, res: dict) -> None:
        if res.get("text"):
            self.ai_out.setPlainText(f"[{res.get('provider')}]\n\n{res['text']}")
        else:
            self.ai_out.setPlainText(f"No AI answer: {res.get('error')}\n\n"
                                     "Set ANTHROPIC_API_KEY (or another provider) in Angerona "
                                     "Settings ▸ API Keys, or ensure Ollama is running.")


class LogConsole(QWidget):
    def __init__(self) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.addWidget(section_label(
            "LIVE CRASH & ERROR STREAM  —  raw trace (amber = hint · green = plain English)"))

        split = QSplitter(Qt.Horizontal)
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(20000)   # bound memory, never truncate a trace
        self.console.setStyleSheet(
            f"QPlainTextEdit{{background:{BG};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:8px;padding:8px;font-family:{MONO};font-size:12px;}}")
        f = QFont("Fira Code")
        f.setStyleHint(QFont.Monospace)
        f.setPointSize(10)
        self.console.setFont(f)
        split.addWidget(self.console)

        self.inspector = CrashInspector()
        split.addWidget(self.inspector)
        split.setSizes([720, 460])
        lay.addWidget(split, 1)

    @Slot(str, str, list)
    def append_block(self, text: str, severity: str, hints: List[str]) -> None:
        cur = self.console.textCursor()
        cur.movePosition(QTextCursor.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(RED if severity == "critical" else TEXT))
        cur.insertText(text + "\n", fmt)
        # Quick-hint lines rendered in amber directly beneath the trace.
        for h in hints:
            hint_fmt = QTextCharFormat()
            hint_fmt.setForeground(QColor(RED))
            cur.insertText(f"    [💡 HINT: {h}]\n", hint_fmt)
        # Plain-English protocol — GREEN explanation of each recognised error.
        for pe in plain_english_for(text):
            pe_fmt = QTextCharFormat()
            pe_fmt.setForeground(QColor(GREEN))
            cur.insertText(f"    [✅ In plain English: {pe}]\n", pe_fmt)
        cur.insertText("\n", QTextCharFormat())
        self.console.setTextCursor(cur)
        self.console.ensureCursorVisible()

    def snapshot_text(self) -> str:
        return self.console.toPlainText()

    def clear_view(self) -> None:
        self.console.clear()


# ─────────────────────────────────────────────────────────────────────────────
#  Tab 2 — Host telemetry with time-series graphs + event overlay
# ─────────────────────────────────────────────────────────────────────────────
class TelemetryTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._t0 = time.time()
        self.latest: Dict = {}
        self._event_marks: List[float] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.addWidget(section_label(
            "HOST TELEMETRY  —  rolling time-series  ·  red marker = exception in log"))

        # --- bars row (quick read) ---
        bars = QHBoxLayout()
        self.cpu_box, self.cpu_bar, self.cpu_val = metric_bar("CPU TOTAL")
        self.ram_box, self.ram_bar, self.ram_val = metric_bar("RAM USED")
        self.rd_box, self.rd_bar, self.rd_val = metric_bar("DISK READ")
        self.wr_box, self.wr_bar, self.wr_val = metric_bar("DISK WRITE")
        for b in (self.cpu_box, self.ram_box, self.rd_box, self.wr_box):
            bars.addWidget(b)
        root.addLayout(bars)

        # --- per-core grid ---
        self.core_grid = QGridLayout()
        self.core_bars: List[QProgressBar] = []
        self.core_vals: List[QLabel] = []
        core_wrap = QWidget()
        core_wrap.setLayout(self.core_grid)
        root.addWidget(core_wrap)

        # --- CPU/RAM time-series chart (QtCharts — optional) ---
        self._cpu_hist: Deque = deque(maxlen=CHART_WINDOW)
        self._ram_hist: Deque = deque(maxlen=CHART_WINDOW)
        self._marker_series: List = []
        if _HAS_CHARTS:
            self.cpu_series = QLineSeries()
            self.cpu_series.setName("CPU %")
            self.cpu_series.setColor(QColor(ACCENT))
            self.ram_series = QLineSeries()
            self.ram_series.setName("RAM %")
            self.ram_series.setColor(QColor(GREEN))

            self.chart = QChart()
            self.chart.addSeries(self.cpu_series)
            self.chart.addSeries(self.ram_series)
            self.chart.setBackgroundBrush(QColor(BG))
            self.chart.setPlotAreaBackgroundBrush(QColor(PANEL))
            self.chart.setPlotAreaBackgroundVisible(True)
            self.chart.legend().setLabelColor(QColor(TEXT))
            self.chart.setTitle("CPU / RAM utilisation (%)")
            self.chart.setTitleBrush(QColor(DIM))

            self.axis_x = QValueAxis()
            self.axis_x.setTitleText("seconds")
            self.axis_x.setLabelsColor(QColor(DIM))
            self.axis_x.setTitleBrush(QColor(DIM))
            self.axis_x.setGridLineColor(QColor(BORDER))
            self.axis_y = QValueAxis()
            self.axis_y.setRange(0, 100)
            self.axis_y.setLabelsColor(QColor(DIM))
            self.axis_y.setGridLineColor(QColor(BORDER))
            self.chart.addAxis(self.axis_x, Qt.AlignBottom)
            self.chart.addAxis(self.axis_y, Qt.AlignLeft)
            for s in (self.cpu_series, self.ram_series):
                s.attachAxis(self.axis_x)
                s.attachAxis(self.axis_y)

            view = QChartView(self.chart)
            view.setRenderHint(QPainter.Antialiasing)
            view.setMinimumHeight(240)
            root.addWidget(view)
        else:
            note = QLabel("Time-series graph unavailable (PySide6-Addons / QtCharts "
                          "not installed). Numeric bars above remain live.")
            note.setWordWrap(True)
            note.setStyleSheet(f"color:{DIM};font-size:11px;padding:8px;")
            root.addWidget(note)

    @Slot(dict)
    def on_metrics(self, m: Dict) -> None:
        self.latest = m
        t = m["ts"] - self._t0

        self.cpu_bar.setValue(int(m["cpu_total"]))
        self.cpu_val.setText(f"{m['cpu_total']:.0f}%")
        self.ram_bar.setValue(int(m["ram_pct"]))
        self.ram_val.setText(f"{human_bytes(m['ram_used'])} / {human_bytes(m['ram_total'])}")
        # Disk speeds scaled against a 100 MB/s reference for the bar.
        ref = 100 * 1024 * 1024
        self.rd_bar.setValue(min(100, int(m["read_bps"] / ref * 100)))
        self.rd_val.setText(f"{human_bytes(m['read_bps'])}/s")
        self.wr_bar.setValue(min(100, int(m["write_bps"] / ref * 100)))
        self.wr_val.setText(f"{human_bytes(m['write_bps'])}/s")

        self._sync_cores(m["per_core"])

        if not _HAS_CHARTS:
            return
        self._cpu_hist.append(QPointF(t, m["cpu_total"]))
        self._ram_hist.append(QPointF(t, m["ram_pct"]))
        self.cpu_series.replace(list(self._cpu_hist))
        self.ram_series.replace(list(self._ram_hist))
        lo = self._cpu_hist[0].x() if self._cpu_hist else 0
        self.axis_x.setRange(lo, max(lo + 10, t))
        self._refresh_markers(lo, t)

    def _sync_cores(self, cores: List[float]) -> None:
        if len(self.core_bars) != len(cores):
            # rebuild grid once we know the core count
            while self.core_grid.count():
                item = self.core_grid.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            self.core_bars.clear()
            self.core_vals.clear()
            cols = 4
            for i in range(len(cores)):
                box, bar, val = metric_bar(f"CORE {i}")
                self.core_bars.append(bar)
                self.core_vals.append(val)
                self.core_grid.addWidget(box, i // cols, i % cols)
        for i, c in enumerate(cores):
            self.core_bars[i].setValue(int(c))
            self.core_vals[i].setText(f"{c:.0f}%")

    @Slot(float)
    def mark_event(self, ts_epoch: float) -> None:
        """Inject a vertical red marker at the exception's timestamp."""
        self._event_marks.append(ts_epoch - self._t0)
        # keep only markers inside the visible window
        self._event_marks = self._event_marks[-40:]

    def _refresh_markers(self, lo: float, hi: float) -> None:
        if not _HAS_CHARTS:
            return
        # Clear old marker series
        for s in self._marker_series:
            self.chart.removeSeries(s)
        self._marker_series.clear()
        for x in self._event_marks:
            if x < lo:
                continue
            s = QLineSeries()
            s.append(x, 0)
            s.append(x, 100)
            pen = QPen(QColor(RED))
            pen.setWidth(2)
            pen.setStyle(Qt.DashLine)
            s.setPen(pen)
            self.chart.addSeries(s)
            s.attachAxis(self.axis_x)
            s.attachAxis(self.axis_y)
            self.chart.legend().markers(s)[0].setVisible(False)
            self._marker_series.append(s)

    def snapshot_text(self) -> str:
        m = self.latest
        if not m:
            return "no telemetry sample captured yet"
        lines = [
            f"CPU total : {m['cpu_total']:.1f}%",
            "Per-core  : " + ", ".join(f"{c:.0f}%" for c in m["per_core"]),
            f"RAM       : {human_bytes(m['ram_used'])} / {human_bytes(m['ram_total'])} "
            f"({m['ram_pct']:.1f}%)",
            f"Disk read : {human_bytes(m['read_bps'])}/s",
            f"Disk write: {human_bytes(m['write_bps'])}/s",
        ]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  Tab 3 — Angerona suite health
# ─────────────────────────────────────────────────────────────────────────────
class HealthTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.latest: Dict = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.addWidget(section_label("ANGERONA SUITE HEALTH ANALYSIS"))

        self.pid_lbl = QLabel("PID: —")
        self.state_lbl = QLabel("STATE: —")
        self.state_lbl.setStyleSheet("font-size:22px;font-weight:800;")
        self.bus_lbl = QLabel("Event bus: —")
        self.res_lbl = QLabel("Resources: —")
        for w in (self.state_lbl, self.pid_lbl, self.bus_lbl, self.res_lbl):
            root.addWidget(w)

        root.addWidget(section_label("RECENTLY FAILED MODULES"))
        self.fail_table = QTableWidget(0, 3)
        self.fail_table.setHorizontalHeaderLabels(["Module", "Detail", "Source"])
        self.fail_table.setAlternatingRowColors(True)
        self.fail_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.fail_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.fail_table.setSortingEnabled(True)
        root.addWidget(self.fail_table)

    @Slot(dict)
    def on_health(self, h: Dict) -> None:
        self.latest = h
        self.pid_lbl.setText(f"PID: {h['pid'] if h['pid'] else '— not found —'}")
        state = h["state"]
        color = {"RUNNING": GREEN, "FROZEN": AMBER, "DEAD": RED}.get(state, DIM)
        self.state_lbl.setText(f"STATE: {state}")
        self.state_lbl.setStyleSheet(
            f"font-size:22px;font-weight:800;color:{color};")
        if h["pid"]:
            self.res_lbl.setText(
                f"Resources: CPU {h['cpu']:.0f}%   RSS {human_bytes(h['rss'])}")
        else:
            self.res_lbl.setText("Resources: —")

        if h["bus_ts"]:
            age = time.time() - h["bus_ts"]
            fresh = "MOVING" if h["bus_fresh"] else "STALE"
            fc = GREEN if h["bus_fresh"] else RED
            ts = _dt.datetime.fromtimestamp(h["bus_ts"]).strftime("%H:%M:%S")
            self.bus_lbl.setText(
                f"Event bus: <span style='color:{fc}'>{fresh}</span> "
                f"— last data {ts} ({age:.0f}s ago)")
            self.bus_lbl.setTextFormat(Qt.RichText)
        else:
            self.bus_lbl.setText("Event bus: no telemetry files found")

        fails = h.get("failed", [])
        self.fail_table.setRowCount(len(fails))
        for r, f in enumerate(fails):
            self.fail_table.setItem(r, 0, QTableWidgetItem(f["name"]))
            self.fail_table.setItem(r, 1, QTableWidgetItem(f["detail"]))
            self.fail_table.setItem(r, 2, QTableWidgetItem(f["src"]))

    def snapshot_text(self) -> str:
        h = self.latest
        if not h:
            return "no health sample yet"
        lines = [f"PID   : {h.get('pid')}", f"STATE : {h.get('state')}"]
        if h.get("bus_ts"):
            lines.append(f"Bus   : {'MOVING' if h.get('bus_fresh') else 'STALE'} "
                         f"(last {time.time()-h['bus_ts']:.0f}s ago)")
        for f in h.get("failed", []):
            lines.append(f"  ✗ {f['name']}: {f['detail']}  [{f['src']}]")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  Tab 4 — Thread state visualizer
# ─────────────────────────────────────────────────────────────────────────────
class ThreadTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.latest: List[Dict] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.addWidget(section_label("ACTIVE THREAD STATE  —  spot deadlocks & wedged threads"))
        self.src_lbl = QLabel("source: —")
        self.src_lbl.setStyleSheet(f"color:{DIM};font-size:11px;")
        root.addWidget(self.src_lbl)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Thread", "ID", "Executing / blocked on", "State"])
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        root.addWidget(self.table)

    @Slot(list, str)
    def on_threads(self, rows: List[Dict], src: str) -> None:
        self.latest = rows
        self.src_lbl.setText(f"source: {src}")
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for r, t in enumerate(rows):
            for c, key in enumerate(("name", "id", "where", "state")):
                item = QTableWidgetItem(str(t.get(key, "")))
                if t.get("state", "").lower() in ("stopped", "disk-sleep") or \
                        "block" in str(t.get("where", "")).lower():
                    item.setForeground(QColor(RED))
                self.table.setItem(r, c, item)
        self.table.setSortingEnabled(True)

    def snapshot_text(self) -> str:
        if not self.latest:
            return "no thread data captured"
        return "\n".join(
            f"{t['name']:<20} {t['id']:<10} {t['where']:<40} {t['state']}"
            for t in self.latest)


# ─────────────────────────────────────────────────────────────────────────────
#  Tab 5 — Memory allocation profiler
# ─────────────────────────────────────────────────────────────────────────────
class MemoryTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.latest: List[Dict] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.addWidget(section_label("MEMORY PROFILER  —  top 10 consumers (leak hunt)"))
        self.src_lbl = QLabel("source: —")
        self.src_lbl.setStyleSheet(f"color:{DIM};font-size:11px;")
        root.addWidget(self.src_lbl)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Type / Mapping", "Size", "Count"])
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        root.addWidget(self.table)

    @Slot(list, str)
    def on_rows(self, rows: List[Dict], src: str) -> None:
        self.latest = rows
        self.src_lbl.setText(f"source: {src}")
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for r, it in enumerate(rows):
            self.table.setItem(r, 0, QTableWidgetItem(str(it["label"])))
            size_item = QTableWidgetItem(human_bytes(it["size"]))
            size_item.setData(Qt.UserRole, it["size"])
            self.table.setItem(r, 1, size_item)
            self.table.setItem(r, 2, QTableWidgetItem(str(it["count"])))
        self.table.setSortingEnabled(True)

    def snapshot_text(self) -> str:
        if not self.latest:
            return "no memory data captured"
        return "\n".join(
            f"{human_bytes(it['size']):>12}  x{it['count']:<6}  {it['label']}"
            for it in self.latest)


# ─────────────────────────────────────────────────────────────────────────────
#  Tab 6 — Config drift & orphaned resources
# ─────────────────────────────────────────────────────────────────────────────
class ConfigTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.latest: Dict = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.addWidget(section_label("CONFIG DRIFT & ORPHANED RESOURCES"))

        root.addWidget(QLabel("Watched config files:"))
        self.files_table = QTableWidget(0, 4)
        self.files_table.setHorizontalHeaderLabels(
            ["File", "Last modified", "Age", "Size"])
        self.files_table.setAlternatingRowColors(True)
        self.files_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.files_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        root.addWidget(self.files_table)

        root.addWidget(QLabel("Open sockets (Angerona PID):"))
        self.sock_table = QTableWidget(0, 4)
        self.sock_table.setHorizontalHeaderLabels(
            ["Local", "Remote", "Status", "Flag"])
        self.sock_table.setAlternatingRowColors(True)
        self.sock_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.sock_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        root.addWidget(self.sock_table)

        root.addWidget(QLabel("Open file handles (locked / DB resources flagged):"))
        self.handle_table = QTableWidget(0, 2)
        self.handle_table.setHorizontalHeaderLabels(["Path", "Flag"])
        self.handle_table.setAlternatingRowColors(True)
        self.handle_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.handle_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        root.addWidget(self.handle_table)

    @Slot(dict)
    def on_drift(self, d: Dict) -> None:
        self.latest = d
        files = d.get("files", [])
        self.files_table.setRowCount(len(files))
        for r, f in enumerate(files):
            self.files_table.setItem(r, 0, QTableWidgetItem(f["label"]))
            self.files_table.setItem(r, 1, QTableWidgetItem(str(f["mtime"])))
            age = f["age_s"]
            age_txt = f"{age:.0f}s ago" if isinstance(age, (int, float)) else "—"
            age_item = QTableWidgetItem(age_txt)
            if isinstance(age, (int, float)) and age < 60:
                age_item.setForeground(QColor(RED))   # recently changed = drift
            self.files_table.setItem(r, 2, age_item)
            self.files_table.setItem(r, 3, QTableWidgetItem(human_bytes(f["size"])))

        socks = d.get("sockets", [])
        self.sock_table.setRowCount(len(socks))
        for r, s in enumerate(socks):
            self.sock_table.setItem(r, 0, QTableWidgetItem(s["laddr"]))
            self.sock_table.setItem(r, 1, QTableWidgetItem(s["raddr"]))
            self.sock_table.setItem(r, 2, QTableWidgetItem(s["status"]))
            flag = QTableWidgetItem("ORPHAN?" if s["orphan"] else "")
            if s["orphan"]:
                flag.setForeground(QColor(RED))
            self.sock_table.setItem(r, 3, flag)

        handles = d.get("handles", [])
        self.handle_table.setRowCount(len(handles))
        for r, h in enumerate(handles):
            self.handle_table.setItem(r, 0, QTableWidgetItem(h["path"]))
            flag = QTableWidgetItem("LOCKED DB/MMAP" if h["flag"] else "")
            if h["flag"]:
                flag.setForeground(QColor(RED))
            self.handle_table.setItem(r, 1, flag)

    def snapshot_text(self) -> str:
        d = self.latest
        if not d:
            return "no config data captured"
        lines = ["Config files:"]
        for f in d.get("files", []):
            lines.append(f"  {f['label']:<22} {f['mtime']}  ({human_bytes(f['size'])})")
        lines.append("Sockets:")
        for s in d.get("sockets", []):
            lines.append(f"  {s['laddr']} -> {s['raddr']} [{s['status']}]"
                         + ("  ORPHAN?" if s["orphan"] else ""))
        lines.append("Handles:")
        for h in d.get("handles", []):
            lines.append(f"  {h['path']}" + ("  [LOCKED]" if h["flag"] else ""))
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  Extra tabs: SOAR Events + Firewall Rules
# ─────────────────────────────────────────────────────────────────────────────
class SoarEventsTab(QWidget):
    """Reads shared_logs/soar_queue.json and shows SOAR-queued items."""

    def __init__(self) -> None:
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.addWidget(section_label("SOAR QUEUE  —  operator-blocked items awaiting review"))

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Time", "Module", "Severity", "Message"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSortingEnabled(True)
        root.addWidget(self.table)

        bar = QHBoxLayout()
        self.status = QLabel("")
        self.status.setStyleSheet(f"color:{DIM}; font-size:11px;")
        bar.addWidget(self.status, 1)
        refresh = QPushButton("↺ Refresh")
        refresh.clicked.connect(self.refresh)
        bar.addWidget(refresh)
        root.addLayout(bar)
        self.refresh()

    def refresh(self) -> None:
        # Walk every known data dir for soar_queue.json
        paths = []
        for candidate in [
            DATA_DIR / "shared_logs" / "soar_queue.json",
        ]:
            if candidate.exists():
                paths.append(candidate)

        records = []
        for p in paths:
            try:
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except Exception:
                            pass
            except Exception:
                pass

        # de-dup by ts+message
        seen, unique = set(), []
        for r in records:
            key = (r.get("ts", 0), r.get("message", "")[:60])
            if key not in seen:
                seen.add(key)
                unique.append(r)
        unique.sort(key=lambda r: r.get("ts", 0), reverse=True)

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for rec in unique[:200]:
            row = self.table.rowCount(); self.table.insertRow(row)
            import time as _time
            ts = _time.strftime("%m-%d %H:%M:%S",
                                _time.localtime(rec.get("ts", 0)))
            self.table.setItem(row, 0, QTableWidgetItem(ts))
            self.table.setItem(row, 1, QTableWidgetItem(rec.get("origin_module", "")))
            sev = QTableWidgetItem(rec.get("severity", ""))
            sev.setForeground(QColor(RED if "CRITICAL" in rec.get("severity", "")
                                    else RED if "HIGH" in rec.get("severity", "")
                                    else TEXT))
            self.table.setItem(row, 2, sev)
            self.table.setItem(row, 3, QTableWidgetItem(rec.get("message", "")[:200]))

        self.table.setSortingEnabled(True)
        self.status.setText(f"{len(unique)} SOAR event(s) on record.")

    def snapshot_text(self) -> str:
        rows = []
        for r in range(self.table.rowCount()):
            rows.append("  ".join(
                self.table.item(r, c).text() if self.table.item(r, c) else ""
                for c in range(self.table.columnCount())
            ))
        return "SOAR Queue:\n" + ("\n".join(rows) or "(empty)")


class _FwDetailWorker(QThread):
    """Fetch extended firewall-rule details off the UI thread."""
    done = Signal(dict)

    def __init__(self, rule_id: str, use_display: bool = False) -> None:
        super().__init__()
        self._rule_id = rule_id
        self._use_display = use_display

    def run(self) -> None:
        result: dict = {}
        if not self._rule_id:
            self.done.emit(result)
            return
        try:
            import subprocess as _sub
            safe = self._rule_id.replace("'", "''")
            flag = "-DisplayName" if self._use_display else "-Name"
            cmd = (
                f"$r = Get-NetFirewallRule {flag} '{safe}' -ErrorAction Stop | Select-Object -First 1; "
                f"$app  = $r | Get-NetFirewallApplicationFilter; "
                f"$port = $r | Get-NetFirewallPortFilter; "
                f"$addr = $r | Get-NetFirewallAddressFilter; "
                f"[PSCustomObject]@{{"
                f"  Description   = [string]$r.Description; "
                f"  Profile       = [string]$r.Profile; "
                f"  Program       = [string]$app.Program; "
                f"  Protocol      = [string]$port.Protocol; "
                f"  LocalPort     = ($port.LocalPort  -join ', '); "
                f"  RemotePort    = ($port.RemotePort -join ', '); "
                f"  LocalAddress  = ($addr.LocalAddress  -join ', '); "
                f"  RemoteAddress = ($addr.RemoteAddress -join ', ') "
                f"}} | ConvertTo-Json -Compress"
            )
            out = _sub.check_output(
                ["powershell", "-NoProfile", "-Command", cmd],
                timeout=10, stderr=_sub.DEVNULL, text=True,
            )
            d = json.loads(out)
            result = {
                "description":   str(d.get("Description")   or ""),
                "profile":       str(d.get("Profile")       or ""),
                "program":       str(d.get("Program")       or ""),
                "proto":         str(d.get("Protocol")      or ""),
                "local_port":    str(d.get("LocalPort")     or ""),
                "remote_port":   str(d.get("RemotePort")    or ""),
                "local_addr":    str(d.get("LocalAddress")  or ""),
                "remote_addr":   str(d.get("RemoteAddress") or ""),
            }
        except Exception:
            pass
        self.done.emit(result)


class FirewallRuleDetailDialog(QDialog):
    """Click a firewall rule row → rich detail panel with file-path actions."""

    def __init__(self, rule: dict, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Firewall Rule — {rule.get('name', '')}")
        self.setMinimumWidth(660)
        self.setStyleSheet(f"background:{BG}; color:{TEXT};")
        self._program = ""
        self._worker: Optional[_FwDetailWorker] = None

        lay = QVBoxLayout(self)
        lay.setSpacing(10)

        # Title
        title = QLabel(rule.get("name", "Unknown Rule"))
        title.setWordWrap(True)
        title.setStyleSheet(f"color:{ACCENT}; font-weight:800; font-size:14px;")
        lay.addWidget(title)

        # Form — populated immediately from what the list already knows
        self._form = QFormLayout()
        self._form.setLabelAlignment(Qt.AlignRight)
        self._form.setHorizontalSpacing(16)
        for label, key in [
            ("Direction", "direction"),
            ("Action",    "action"),
            ("Enabled",   "enabled"),
            ("Protocol",  "proto"),
            ("Port",      "port"),
        ]:
            val = rule.get(key, "")
            if val:
                self._add_row(label, val)
        lay.addLayout(self._form)

        # Loading indicator — replaced by detail rows once worker finishes
        self._loading = QLabel("⏳  Fetching extended details…")
        self._loading.setStyleSheet(f"color:{DIM}; font-size:11px;")
        lay.addWidget(self._loading)

        # Program path box (hidden until we know the value)
        self._prog_box = QLabel()
        self._prog_box.setWordWrap(True)
        self._prog_box.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._prog_box.setStyleSheet(
            f"color:{TEXT}; font-family:'Fira Code'; font-size:10px; "
            f"background:{PANEL}; border:1px solid {BORDER}; "
            f"border-radius:6px; padding:6px;"
        )
        self._prog_box.hide()
        lay.addWidget(self._prog_box)

        # Action buttons
        btn_row = QHBoxLayout()
        self.btn_copy = QPushButton("📋  Copy File Path")
        self.btn_open = QPushButton("📂  Open File Location")
        btn_close    = QPushButton("Close")
        self.btn_copy.setEnabled(False)
        self.btn_open.setEnabled(False)
        self.btn_copy.clicked.connect(self._copy_path)
        self.btn_open.clicked.connect(self._open_location)
        btn_close.clicked.connect(self.accept)
        for b in (self.btn_copy, self.btn_open):
            b.setStyleSheet(
                f"QPushButton{{background:{PANEL2};border:1px solid {BORDER};"
                f"border-radius:6px;padding:5px 12px;color:{TEXT};}}"
                f"QPushButton:disabled{{color:{DIM};}}"
            )
        btn_row.addWidget(self.btn_copy)
        btn_row.addWidget(self.btn_open)
        btn_row.addStretch(1)
        btn_row.addWidget(btn_close)
        lay.addLayout(btn_row)

        # Start background fetch
        rule_id      = rule.get("rule_id", "")
        use_display  = rule.get("use_display", False)
        if rule_id:
            self._worker = _FwDetailWorker(rule_id, use_display)
            self._worker.done.connect(self._on_details)
            self._worker.start()
        else:
            self._loading.setText("(Extended details unavailable — rule loaded via netsh fallback.)")

    def _add_row(self, label: str, value: str) -> None:
        lbl = QLabel(str(value))
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._form.addRow(QLabel(f"<b>{label}:</b>"), lbl)

    @Slot(dict)
    def _on_details(self, d: dict) -> None:
        self._loading.hide()
        _SKIP = {"", "Any", "None", "*", "NotConfigured"}
        for label, key in [
            ("Description",    "description"),
            ("Profile",        "profile"),
            ("Protocol",       "proto"),
            ("Local Port",     "local_port"),
            ("Remote Port",    "remote_port"),
            ("Local Address",  "local_addr"),
            ("Remote Address", "remote_addr"),
        ]:
            val = d.get(key, "")
            if val and val not in _SKIP:
                self._add_row(label, val)

        prog = d.get("program", "")
        if prog and prog not in _SKIP:
            self._program = prog
            self._prog_box.setText(f"Program Path:\n{prog}")
            self.btn_copy.setEnabled(True)
            self.btn_open.setEnabled(True)
        else:
            self._prog_box.setText("Program:  Any  (rule applies to all applications)")
        self._prog_box.show()
        self.adjustSize()

    @Slot()
    def _copy_path(self) -> None:
        if self._program:
            QApplication.clipboard().setText(self._program)

    @Slot()
    def _open_location(self) -> None:
        import subprocess as _sub
        from pathlib import Path as _Path
        try:
            _sub.Popen(["explorer", str(_Path(self._program).parent)])
        except Exception as exc:
            QMessageBox.warning(self, "Error", f"Could not open location:\n{exc}")

    def closeEvent(self, event) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.quit()
            self._worker.wait(1000)
        super().closeEvent(event)


class FirewallTab(QWidget):
    """Snapshot of Windows Firewall rules via PowerShell / netsh."""

    def __init__(self) -> None:
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.addWidget(section_label("WINDOWS FIREWALL RULES  —  read-only snapshot"))

        bar = QHBoxLayout()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter rules (keyword)…")
        self.filter_edit.textChanged.connect(self._apply_filter)
        bar.addWidget(self.filter_edit, 1)
        refresh = QPushButton("↺ Refresh")
        refresh.clicked.connect(self.refresh)
        bar.addWidget(refresh)
        root.addLayout(bar)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Name", "Direction", "Action", "Protocol", "Port/Program"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setCursor(Qt.PointingHandCursor)
        self.table.cellClicked.connect(self._on_rule_clicked)
        root.addWidget(self.table)

        self.status = QLabel("Click Refresh to load firewall rules.  Click any row for full details.")
        self.status.setStyleSheet(f"color:{DIM}; font-size:11px;")
        root.addWidget(self.status)

        self._all_rules: list = []
        self._visible_rules: list = []

    def refresh(self) -> None:
        self.status.setText("Loading firewall rules (PowerShell)…")
        self._all_rules = []
        try:
            import subprocess as _sub
            out = _sub.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetFirewallRule | Select-Object DisplayName,Name,Direction,"
                 "Action,Enabled | ConvertTo-Json -Compress -Depth 2"],
                timeout=12, stderr=_sub.DEVNULL, text=True
            )
            raw = json.loads(out)
            if isinstance(raw, dict):
                raw = [raw]
            for r in raw[:2000]:
                name     = r.get("DisplayName", "")
                rule_id  = r.get("Name", "")
                dirn     = r.get("Direction", {}).get("Value", str(r.get("Direction", "")))
                act      = r.get("Action",    {}).get("Value", str(r.get("Action",    "")))
                en       = r.get("Enabled",   {}).get("Value", "?")
                self._all_rules.append({
                    "name": name, "rule_id": rule_id, "use_display": False,
                    "direction": dirn, "action": act,
                    "enabled": str(en), "proto": "", "port": "",
                })
        except Exception as exc:
            # Fallback: netsh
            try:
                import subprocess as _sub
                out = _sub.check_output(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                    timeout=10, stderr=_sub.DEVNULL, text=True, encoding="utf-8",
                    errors="replace",
                )
                current: dict = {}
                for line in out.splitlines():
                    if line.startswith("Rule Name:"):
                        if current:
                            self._all_rules.append(current)
                        current = {"name": line.split(":", 1)[1].strip(),
                                   "rule_id": line.split(":", 1)[1].strip(),
                                   "use_display": True,
                                   "direction": "", "action": "",
                                   "enabled": "", "proto": "", "port": ""}
                    elif ":" in line and current:
                        k, v = line.split(":", 1)
                        k = k.strip().lower()
                        if "direction" in k:
                            current["direction"] = v.strip()
                        elif "action" in k:
                            current["action"] = v.strip()
                        elif "enabled" in k:
                            current["enabled"] = v.strip()
                        elif "protocol" in k:
                            current["proto"] = v.strip()
                        elif "localport" in k:
                            current["port"] = v.strip()
                if current:
                    self._all_rules.append(current)
            except Exception as exc2:
                self.status.setText(f"Could not read firewall rules: {exc2}")
                return

        self._apply_filter()
        self.status.setText(f"{len(self._all_rules)} firewall rule(s) loaded.")

    def _apply_filter(self) -> None:
        kw = self.filter_edit.text().lower()
        rules = [r for r in self._all_rules
                 if not kw or kw in r["name"].lower()
                 or kw in r["action"].lower()
                 or kw in r["direction"].lower()]
        self._visible_rules = rules[:500]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for r in self._visible_rules:
            row = self.table.rowCount(); self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(r["name"]))
            dirn = QTableWidgetItem(r["direction"])
            dirn.setForeground(QColor(RED if "In" in r["direction"] else TEXT))
            self.table.setItem(row, 1, dirn)
            act = QTableWidgetItem(r["action"])
            act.setForeground(QColor(RED if "Block" in r["action"] else GREEN))
            self.table.setItem(row, 2, act)
            self.table.setItem(row, 3, QTableWidgetItem(r.get("proto", "")))
            self.table.setItem(row, 4, QTableWidgetItem(r.get("port", "")))
        self.table.setSortingEnabled(True)

    @Slot(int, int)
    def _on_rule_clicked(self, row: int, col: int) -> None:
        if row < 0 or row >= len(self._visible_rules):
            return
        # Re-map row after sort: find rule whose Name matches col-0 text
        display_name = (self.table.item(row, 0) or QTableWidgetItem("")).text()
        rule = next(
            (r for r in self._visible_rules if r["name"] == display_name),
            self._visible_rules[row] if row < len(self._visible_rules) else None
        )
        if rule is None:
            return
        dlg = FirewallRuleDetailDialog(rule, self)
        dlg.exec()

    def snapshot_text(self) -> str:
        rows = [f"  {r['name']} | {r['direction']} | {r['action']}"
                for r in self._all_rules[:100]]
        return "Firewall Rules:\n" + ("\n".join(rows) or "(none loaded)")


# ─────────────────────────────────────────────────────────────────────────────
#  Main window
# ─────────────────────────────────────────────────────────────────────────────
class BlackBoxWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(make_icon())
        self.resize(1180, 820)

        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        # header
        header = QHBoxLayout()
        brand = QLabel("ANGERONA · BLACK BOX")
        brand.setStyleSheet(
            f"color:{ACCENT};font-weight:800;letter-spacing:4px;font-size:18px;")
        tag = QLabel("out-of-band flight recorder · strictly read-only")
        tag.setStyleSheet(f"color:{DIM};font-size:11px;")
        header.addWidget(brand)
        header.addSpacing(12)
        header.addWidget(tag)
        header.addStretch(1)
        self.status_chip = QLabel("● watching")
        self.status_chip.setStyleSheet(f"color:{GREEN};font-weight:700;")
        header.addWidget(self.status_chip)
        outer.addLayout(header)

        # tabs
        self.tabs = QTabWidget()
        self.tab_logs = LogConsole()
        self.tab_host = TelemetryTab()
        self.tab_health = HealthTab()
        self.tab_threads = ThreadTab()
        self.tab_mem = MemoryTab()
        self.tab_config = ConfigTab()
        self.tab_soar     = SoarEventsTab()
        self.tab_firewall = FirewallTab()
        self.tabs.addTab(self.tab_logs,     "1 · Crash & Errors")
        self.tabs.addTab(self.tab_host,     "2 · Host Telemetry")
        self.tabs.addTab(self.tab_health,   "3 · Suite Health")
        self.tabs.addTab(self.tab_threads,  "4 · Thread State")
        self.tabs.addTab(self.tab_mem,      "5 · Memory Profiler")
        self.tabs.addTab(self.tab_config,   "6 · Config Drift")
        self.tabs.addTab(self.tab_soar,     "7 · SOAR Events")
        self.tabs.addTab(self.tab_firewall, "8 · Firewall Rules")
        outer.addWidget(self.tabs, 1)

        # footer actions
        footer = QHBoxLayout()
        self.btn_export = QPushButton("Generate Diagnostic Bundle (.zip)")
        self.btn_export.setObjectName("Primary")
        self.btn_archive = QPushButton("Archive && Clear Logs")
        self.btn_sandbox = QPushButton("Launch Sandbox Editor")
        footer.addWidget(self.btn_export)
        footer.addWidget(self.btn_archive)
        footer.addStretch(1)
        footer.addWidget(self.btn_sandbox)
        outer.addLayout(footer)

        self.btn_export.clicked.connect(self.on_export_bundle)
        self.btn_archive.clicked.connect(self.on_archive_clear)
        self.btn_sandbox.clicked.connect(self.on_launch_sandbox)

        self._start_workers()

    # -- workers ------------------------------------------------------------
    def _start_workers(self) -> None:
        self.w_log = LogTailWorker()
        self.w_log.block.connect(self.tab_logs.append_block)
        self.w_log.exception_at.connect(self.tab_host.mark_event)

        self.w_host = HostTelemetryWorker()
        self.w_host.metrics.connect(self.tab_host.on_metrics)

        self.w_health = SuiteHealthWorker()
        self.w_health.health.connect(self.tab_health.on_health)

        self.w_thread = ThreadStateWorker()
        self.w_thread.threads.connect(self.tab_threads.on_threads)

        self.w_mem = MemoryProfilerWorker()
        self.w_mem.rows.connect(self.tab_mem.on_rows)

        self.w_config = ConfigDriftWorker()
        self.w_config.drift.connect(self.tab_config.on_drift)

        for w in (self.w_log, self.w_host, self.w_health,
                  self.w_thread, self.w_mem, self.w_config):
            w.start()

    def stop_workers(self) -> None:
        for w in (self.w_log, self.w_host, self.w_health,
                  self.w_thread, self.w_mem, self.w_config):
            try:
                w.stop()
                w.wait(2000)
            except Exception:
                pass

    # -- footer actions -----------------------------------------------------
    @Slot()
    def on_export_bundle(self) -> None:
        """Requirement #12 — comprehensive timestamped .zip diagnostic bundle."""
        default = str(ARCHIVE_DIR / f"Angerona_DiagBundle_{now_stamp()}.zip")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Diagnostic Bundle", default, "Zip archive (*.zip)")
        if not path:
            return
        try:
            self._build_bundle(Path(path))
        except Exception as exc:  # never crash the recorder on export
            QMessageBox.critical(self, "Export failed", f"{exc}\n\n{traceback.format_exc()}")
            return
        QMessageBox.information(self, "Bundle created", f"Saved:\n{path}")

    def _build_bundle(self, out: Path) -> None:
        manifest = {
            "app": APP_NAME,
            "generated": _dt.datetime.now().isoformat(timespec="seconds"),
            "angerona_pid": find_angerona_pid(),
        }
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            # 1) live thread dump
            z.writestr("thread_dump.txt", self.tab_threads.snapshot_text())
            # 2) raw crash / diagnostic files
            for p in (NOT_RESPONDING, SELFTEST_FAILURES, CRASH_LOG, STATUS_JSON,
                      FLOW_METRICS):
                if p.exists():
                    try:
                        # copy at most the last 4 MB of any huge log
                        size = p.stat().st_size
                        with open(p, "rb") as fh:
                            if size > 4 * 1024 * 1024:
                                fh.seek(size - 4 * 1024 * 1024)
                                z.writestr(f"diagnostics/{p.name}.tail", fh.read())
                            else:
                                z.writestr(f"diagnostics/{p.name}", fh.read())
                    except OSError:
                        pass
            if CRASH_SNAP_DIR.is_dir():
                for f in CRASH_SNAP_DIR.glob("*"):
                    if f.is_file():
                        try:
                            z.writestr(f"crash_snapshots/{f.name}", f.read_bytes())
                        except OSError:
                            pass
            # 3) .env hash (NEVER the secret contents) + settings.json state
            if ENV_FILE.exists():
                try:
                    digest = hashlib.sha256(ENV_FILE.read_bytes()).hexdigest()
                    manifest["env_sha256"] = digest
                    manifest["env_mtime"] = _dt.datetime.fromtimestamp(
                        ENV_FILE.stat().st_mtime).isoformat()
                except OSError:
                    pass
            if SETTINGS_JSON.exists():
                try:
                    z.writestr("settings.json", SETTINGS_JSON.read_bytes())
                except OSError:
                    pass
            # 4) point-in-time snapshots
            z.writestr("host_telemetry.txt",  self.tab_host.snapshot_text())
            z.writestr("suite_health.txt",    self.tab_health.snapshot_text())
            z.writestr("memory_profile.txt",  self.tab_mem.snapshot_text())
            z.writestr("config_drift.txt",    self.tab_config.snapshot_text())
            z.writestr("soar_events.txt",     self.tab_soar.snapshot_text())
            z.writestr("firewall_rules.txt",  self.tab_firewall.snapshot_text())
            z.writestr("console_tail.txt",    self.tab_logs.snapshot_text())
            z.writestr("manifest.json", json.dumps(manifest, indent=2))

    @Slot()
    def on_archive_clear(self) -> None:
        confirm = QMessageBox.question(
            self, "Archive & Clear",
            "Move crash files from diagnostics/ into archive/ and clear the console?\n"
            "(Only Black-Box-owned copies are moved; live files Angerona holds open "
            "are copied, not deleted.)",
            QMessageBox.Yes | QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        archive = ARCHIVE_DIR
        archive.mkdir(exist_ok=True)
        moved = 0
        for src in DIAG_DIR.glob("*"):
            if src.is_file() and src.suffix in (".log", ".json", ".txt"):
                try:
                    dst = archive / f"{now_stamp()}_{src.name}"
                    src.rename(dst)
                    moved += 1
                except OSError:
                    pass
        self.tab_logs.console.clear()
        QMessageBox.information(self, "Done", f"Archived {moved} file(s) to {archive}.")

    @Slot()
    def on_launch_sandbox(self) -> None:
        """Launch the Live-Fire Sandbox Editor as a detached subprocess."""
        import subprocess as _sub
        try:
            python = sys.executable
            _sub.Popen(
                [python, "-m", "angerona.gui.sandbox_editor"],
                cwd=str(APP_DIR),
                creationflags=getattr(_sub, "CREATE_NO_WINDOW", 0),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Sandbox", f"Could not launch Sandbox Editor:\n{exc}")


# ─────────────────────────────────────────────────────────────────────────────
#  Entry-point
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--show", action="store_true",
                   help="Show the window immediately (default: start minimised)")
    args = p.parse_args()

    # The app and resilience supervisor can notice an absent recorder at nearly
    # the same instant. The OS mutex makes that race harmless and guarantees one
    # Black Box process even when process-command-line inspection is restricted.
    _instance_guard = _acquire_single_instance()
    if _instance_guard is None:
        return

    # Keep silent pythonw/frozen startup failures inside protected runtime data.
    _crash_log = DIAG_DIR / "blackbox_startup.log"
    try:
        _crash_log.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        _crash_log = DATA_DIR / "blackbox_startup.log"

    try:
        app = QApplication(sys.argv)
        app.setApplicationName(APP_NAME)
        app.setQuitOnLastWindowClosed(True)

        # Diagnose this independent window independently. Starting before the
        # window constructor also captures an expensive tab/widget constructor,
        # not only stalls that occur after the event loop begins.
        from angerona.core.uiwatchdog import UiWatchdog
        ui_watchdog = UiWatchdog(
            DIAG_DIR / "blackbox_not_responding.log", stall_seconds=5.0
        )
        ui_watchdog.start()
        win = BlackBoxWindow()
        beat_timer = QTimer()
        beat_timer.timeout.connect(ui_watchdog.beat)
        beat_timer.start(1000)
        if args.show:
            win.show()
        else:
            win.showMinimized()

        exit_code = app.exec()
        ui_watchdog.stop()
        sys.exit(exit_code)
    except Exception:
        import datetime
        msg = f"[{datetime.datetime.now().isoformat()}] BLACKBOX STARTUP CRASH\n{traceback.format_exc()}\n"
        try:
            with open(_crash_log, "a", encoding="utf-8") as f:
                f.write(msg)
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
