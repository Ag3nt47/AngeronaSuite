#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
blackbox_recorder.py  —  Project Angerona "Black Box" out-of-band diagnostic recorder
=====================================================================================

A STRICTLY READ-ONLY flight recorder for the Angerona security suite. Its
independent log and OS readers survive a main-suite deadlock without sharing an
EventBus subscription, control socket, or mutex. The optional Live AI Review
pane can also receive a one-way diagnostic stream; losing that connection never
stops the independent recorder.

Design contract (do not violate)
--------------------------------
  • READ-ONLY.  Nothing here writes to, signals, or commands the Angerona process.
    The only files this program writes are its own exports under ``archive/`` and
    the diagnostic bundles it produces — never anything Angerona reads.
  • ZERO-INTERFERENCE. No control IPC (loopback :65432 is never touched). No
    EventBus. The optional Live AI Review client only receives an outbound
    diagnostic pipe; the independent flight recorder never depends on it.
  • LOW OVERHEAD.  Logs, host telemetry and health continue in the background.
    Detailed thread, memory and resource inspectors run only while their tab is
    visible. Log readers consume appended bytes rather than whole files.
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
import codecs
import datetime as _dt
import hashlib
import io
import json
import math
import os
import re
import shutil
import stat
import tempfile
import sys
import threading
import time
import traceback
import weakref
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
    QCoreApplication,
    QDateTime,
    QEvent,
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
    QCloseEvent,
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
    """Use the suite's path policy without creating or hardening suite files."""
    # A standalone source launch need not have the package installed. Import
    # only the path utility: it creates no bus, IPC client, or suite singleton.
    source_dir = str(APP_DIR / "src")
    if not getattr(sys, "frozen", False) and (APP_DIR / "src").is_dir():
        if source_dir not in sys.path:
            sys.path.insert(0, source_dir)
    from angerona.core.data_paths import data_dir

    return data_dir(create=False)


DATA_DIR = _angerona_data_dir()
DIAG_DIR = Path(os.environ.get("ANGERONA_DIAG_DIR") or (DATA_DIR / "diagnostics"))
ARCHIVE_DIR = DATA_DIR / "archive"
DATA_DIAG = DIAG_DIR

# Runtime diagnostics — shared path policy also covers source profile data.
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
MAX_LOG_READ_BYTES = 16 * 1024
MAX_LOG_PREVIEW_BYTES = 64 * 1024


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
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


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
STATUS_POLL_GRACE_S = 2 * HEALTH_POLL_S
MAX_STATUS_BYTES = 4 * 1024 * 1024
MAX_SELFTEST_BYTES = 4 * 1024 * 1024
MAX_DIAGNOSTIC_READ_BYTES = 64 * 1024


class _DiagnosticTooLarge(ValueError):
    """A complete diagnostic cannot be read within its independent byte cap."""


def _read_diagnostic_bytes(path: Path, max_bytes: int) -> bytearray:
    """Read through EOF in small requests, or reject cap-plus-one evidence.

    Never parse a prefix after a read failure or assume st_size describes a
    pseudo-file. The handle and any partial bytes stay local to this read.
    """
    raw = bytearray()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(min(MAX_DIAGNOSTIC_READ_BYTES, max_bytes + 1 - len(raw)))
            if not chunk:
                return raw
            raw.extend(chunk)
            if len(raw) > max_bytes:
                raise _DiagnosticTooLarge("Diagnostic exceeds its byte review limit")


def _read_selftest_report() -> Tuple[List[Dict], Dict, str]:
    """Read advisory history separately from current process health evidence."""
    try:
        raw = _read_diagnostic_bytes(SELFTEST_FAILURES, MAX_SELFTEST_BYTES)
        # Preserve the historical reader's UTF-8 replacement policy.
        data = json.loads(raw.decode("utf-8", "replace"))
    except FileNotFoundError:
        return [], {}, "Unavailable: historical report is missing; current module health is separate."
    except _DiagnosticTooLarge:
        return [], {}, (
            f"Unavailable: historical report exceeds the {MAX_SELFTEST_BYTES}-byte review limit; "
            "source evidence is retained."
        )
    except OSError:
        return [], {}, "Unavailable: historical report could not be read; current module health is separate."
    except (ValueError, RecursionError):
        return [], {}, "Unavailable: historical report is invalid or incomplete; current module health is separate."
    try:
        rows = data.get("failures") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            return [], {}, "Unavailable: historical report schema is unsupported; current module health is separate."
        failures = _selftest_failures(data)
        out = [{"name": str(row.get("module") or row.get("name") or "?")[:200],
                "detail": str(row.get("detail", ""))[:2000],
                "src": "selftest (historical)"} for row in failures[:500]]
    except (ValueError, RecursionError):
        return [], {}, "Unavailable: historical rows could not be rendered; current module health is separate."
    note = f"Loaded historical report: {len(failures)} failure record(s)"
    if len(failures) > 500:
        note += "; showing the first 500"
    if len(rows) != len(failures):
        note += f"; {len(rows) - len(failures)} malformed row(s) omitted (incomplete evidence)"
    note += ". Advisory history does not establish current module health."
    return out, data if isinstance(data, dict) else {}, note


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
    (re.compile(r"NOT RESPONDING", re.I),
     "The GUI heartbeat arrived late. A slow call, CPU contention, or system sleep may "
     "be responsible; the sampled stack does not prove a deadlock."),
    (re.compile(r"Thread.*blocked|acquire.*Lock|\bdeadlock\b", re.I),
     "A thread may be waiting for a lock. Compare multiple thread samples to determine "
     "whether the program is deadlocked."),
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


def _is_angerona_core(name: str, cmdline: List[str]) -> bool:
    """Match an actual core entry point, never a checkout name in arguments."""
    name = name.casefold()
    if name == "angerona.exe":
        return True
    if not re.fullmatch(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?", name):
        return False
    args = iter(cmdline[1:])
    for arg in args:
        if arg == "-m":
            return next(args, None) == "angerona"
        if arg in ("-W", "-X"):
            if next(args, None) is None:
                return False
        elif not arg.startswith("-") or arg in ("-", "--") or arg.startswith("-c"):
            return False
    return False


def find_angerona_pid() -> Optional[int]:
    """Discover one unambiguous core, excluding its venv launcher parent.

    Memory consumption cannot identify which data profile a core belongs to.
    Multiple independent cores therefore leave process inspection unavailable;
    the explicitly PID/birth-bound Live AI Review remains a separate reader.
    """
    candidates = {}
    try:
        # Command lines and memory counters are expensive on Windows. Query
        # them only for candidate interpreters, not every host process three
        # times per monitoring cycle.
        processes = psutil.process_iter(["pid", "name"])
        for proc in processes:
            try:
                info = proc.info
                name = (info.get("name") or "").casefold()
                if info["pid"] == os.getpid() or not (
                    name == "angerona.exe" or
                    re.fullmatch(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?", name)
                ):
                    continue
                command = info.get("cmdline")
                if command is None:
                    command = [] if name == "angerona.exe" else proc.cmdline()
                if not _is_angerona_core(name, command):
                    continue
                parent = info.get("ppid")
                if parent is None:
                    parent = proc.ppid()
                candidates[info["pid"]] = parent
            except (psutil.Error, OSError, TypeError, ValueError, AttributeError):
                continue
    except (psutil.Error, OSError):
        pass
    # Windows venv launchers repeat the exact command line in a child. Exclude
    # only parents with another matching core child, not unrelated helpers.
    parents = {parent for parent in candidates.values() if parent in candidates}
    cores = [pid for pid in candidates if pid not in parents]
    return cores[0] if len(cores) == 1 else None


def _finite_number(value) -> Optional[float]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            number = float(value)
            return number if math.isfinite(number) else None
        except (ValueError, OverflowError):
            pass
    return None


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
            data = fh.read(min(size - offset, MAX_LOG_READ_BYTES))
        # Drain a burst over several polls, without discarding the source log
        # or submitting a multi-megabyte document layout to the GUI at once.
        return data, offset + len(data)
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
        self._tail_decoders = {}
        self._tail_contexts: Dict[Path, str] = {}
        self._tail_identities = {}
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

    def _emit_text(self, source: str, text: str, *, context: str = "") -> None:
        text = text.strip("\n")
        if not text:
            return
        # Preserve classification when a bounded read splits an error marker.
        # Only bounded context is classified; displayed/source bytes are not
        # duplicated, and each file has an independent incremental decoder.
        classified = context + text
        sev = self._severity_for(classified)
        hints = self._hints_for(classified)
        header = f"──[ {source} @ {_dt.datetime.now():%H:%M:%S} ]" + "─" * 24
        self.block.emit(header + "\n" + text, sev, hints)
        if sev == "critical":
            self.exception_at.emit(time.time())

    def _consume_tail(self, path: Path, label: str) -> None:
        try:
            info = path.stat()
        except OSError:
            return
        identity = (info.st_dev, info.st_ino)
        previous_identity = self._tail_identities.get(path)
        offset = self._offsets.get(path, 0)
        reset = (previous_identity is not None and previous_identity != identity) or info.st_size < offset
        if reset:
            offset = 0
        self._tail_identities[path] = identity
        data, following = safe_tail_bytes(path, offset)
        if reset or following < offset or path not in self._tail_decoders:
            self._tail_decoders[path] = codecs.getincrementaldecoder("utf-8")("replace")
            self._tail_contexts[path] = ""
        self._offsets[path] = following
        if data:
            decoded = self._tail_decoders[path].decode(data)
            context = self._tail_contexts.get(path, "")
            self._emit_text(label, decoded, context=context)
            self._tail_contexts[path] = (context + decoded)[-512:]

    # All plain appended-text logs the recorder tails, across BOTH the repo-side
    # diagnostics dir and the per-user data dir (so no crash evidence is missed).
    _TAIL_FILES = (
        (NOT_RESPONDING, "not_responding.log"),
        (CRASH_LOG, "crash.log (repo)"),
        (DATA_CRASH_LOG, "crash.log (data)"),
        (RUNTIME_ALERTS, "runtime_alerts.log"),
        (DIAG_DIR / "resilience_scanner_crash.log", "resilience_scanner_crash.log"),
        (DIAG_DIR / "resilience_watchdog_crash.log", "resilience_watchdog_crash.log"),
        (DIAG_DIR / "blackbox_startup.log", "blackbox_startup.log"),
        (DATA_DIR / "blackbox_startup.log", "blackbox_startup.log (fallback)"),
        (DIAG_DIR / "blackbox_not_responding.log", "blackbox_not_responding.log"),
    )
    _SNAP_DIRS = tuple(dict.fromkeys((CRASH_SNAP_DIR, DATA_CRASH_SNAP_DIR)))

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
                self._consume_tail(p, label)

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
                                with f.open("rb") as stream:
                                    preview = stream.read(MAX_LOG_PREVIEW_BYTES + 1)
                                raw = preview[:MAX_LOG_PREVIEW_BYTES].decode("utf-8", "replace")
                                if len(preview) > MAX_LOG_PREVIEW_BYTES:
                                    raw += "\n[Preview limited; complete evidence remains in the source file.]"
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
        fails, meta, note = _read_selftest_report()
        if not fails:
            self._emit_text(
                "selftest_failures.json",
                "Historical self-test evidence (diagnostic only): " + note,
            )
            return
        failed = str(meta.get("failed", len(fails)))[:200]
        passed = str(meta.get("passed", "?"))[:200]
        generated = str(meta.get("generated", "?"))[:200]
        lines = [f"Historical selftest: {failed} failed / {passed} passed (gen {generated})", note]
        for row in fails:
            lines.append(f"  ✗ {row['name']}: {row['detail']}")
        self._emit_text("selftest_failures.json", "\n".join(lines))


class HostTelemetryWorker(QThread):
    """Tab 2 engine: host hardware metrics on a relaxed cycle."""

    metrics = Signal(dict)

    def __init__(self) -> None:
        super().__init__()
        self._running = True
        self._stopped = threading.Event()

    def stop(self) -> None:
        self._running = False
        self._stopped.set()

    def run(self) -> None:
        # Prime cpu_percent (first call always returns 0.0).
        psutil.cpu_percent(percpu=True)
        last_io = psutil.disk_io_counters()
        last_t = time.time()
        while self._running:
            if self._stopped.wait(HOST_POLL_S):
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
    """Keep OS process state separate from advisory, process-bound diagnostics."""

    health = Signal(dict)

    def __init__(self) -> None:
        super().__init__()
        self._running = True
        self._last_bus_sample = None
        self._last_bus_state = "OBSERVED"
        self._cpu_sample_process = None
        self._cpu_sample_identity = None

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        while self._running:
            self.health.emit(self._collect())
            for _ in range(int(HEALTH_POLL_S * 10)):
                if not self._running:
                    break
                self.msleep(100)

    def _collect(self) -> Dict:
        info: Dict = {"pid": find_angerona_pid(), "state": "UNKNOWN", "cpu": 0.0,
                      "rss": 0, "create_time": None}
        if info["pid"]:
            try:
                process = psutil.Process(info["pid"])
                with process.oneshot():
                    status = process.status()
                    info["rss"] = process.memory_info().rss
                    info["create_time"] = process.create_time()
                identity = (info["pid"], info["create_time"])
                if identity != self._cpu_sample_identity:
                    self._cpu_sample_process = process
                    self._cpu_sample_identity = identity
                # cpu_percent needs the previous sample from the same Process
                # instance; recreating it each poll always reported zero.
                info["cpu"] = self._cpu_sample_process.cpu_percent(interval=0.0)
                info["state"] = {
                    psutil.STATUS_STOPPED: "STOPPED", psutil.STATUS_DISK_SLEEP: "WAITING",
                    psutil.STATUS_ZOMBIE: "DEAD", psutil.STATUS_DEAD: "DEAD",
                }.get(status, "RUNNING")
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                info["state"] = "DEAD"
            except (psutil.AccessDenied, OSError):
                info["state"] = "UNKNOWN"
        snapshot = self._read_status()
        info.update(self._observe_bus(snapshot, info["pid"], info["create_time"], time.time()))
        # Historical reports may still help, but stale status from a previous
        # process must never be presented as a current module failure.
        current = snapshot if info["bus_fresh"] and info["state"] != "DEAD" else {}
        historical, _meta, history_note = _read_selftest_report()
        info["failed"] = historical + self._failed_modules(current)
        info["selftest_history_note"] = history_note
        counts = current.get("counts", {})
        info["counts"] = counts if isinstance(counts, dict) else {}
        info["recovery_note"] = self._recovery_note(current)
        return info

    @staticmethod
    def _recovery_note(snapshot: Dict) -> str:
        """Present only bounded, current diagnostics; never request a repair."""
        recovery = snapshot.get("runtime_healer")
        if not isinstance(recovery, dict):
            return "No current recovery report"
        if recovery.get("enabled") is False:
            return "Stopped"
        if recovery.get("worker_alive") is not True:
            return "Recovery worker unavailable"
        components = recovery.get("components")
        if not isinstance(components, dict):
            return "Recovery report incomplete"
        states = {
            "observing": "observing", "unknown": "health unknown",
            "stopped": "stopped", "healthy": "available",
            "stabilizing": "recovery observed; checking stability",
            "confirming": "confirming failure", "cooldown": "waiting to retry",
            "attention_required": "needs attention", "verifying": "verifying repair",
        }
        parts = []
        for name, label in (("status_reporter", "Status reporter"),
                            ("flight_recorder", "Event recorder")):
            row = components.get(name)
            if not isinstance(row, dict):
                return "Recovery report incomplete"
            state, attempts = row.get("state"), row.get("attempts")
            if (not isinstance(state, str) or state not in states or
                    type(attempts) is not int or not 0 <= attempts <= 3):
                return "Recovery report invalid"
            parts.append(f"{label}: {states[state]} (attempts {attempts}/3)")
        return "; ".join(parts)

    def _observe_bus(self, snapshot: Dict, pid: Optional[int], started: Optional[float],
                     now: float) -> Dict:
        result = {"bus_ts": None, "bus_fresh": False, "bus_state": "UNKNOWN",
                  "bus_note": "No current process-bound status snapshot", "bus_warnings": []}
        if not pid or not isinstance(snapshot, dict) or not snapshot:
            self._last_bus_sample = None
            return result
        reported_start = _finite_number(snapshot.get("process_started_at"))
        reported_pid = snapshot.get("pid")
        if (type(reported_pid) is not int or reported_pid != pid or
                reported_start is None or started is None or abs(reported_start - started) > 0.01):
            result["bus_note"] = "Status snapshot does not identify the current process"
            self._last_bus_sample = None
            return result
        generated = _finite_number(snapshot.get("generated_ts"))
        interval = _finite_number(snapshot.get("heartbeat_interval_s"))
        if generated is None or interval is None or interval <= 0:
            result["bus_note"] = "Status heartbeat metadata is missing or invalid"
            return result
        age = now - generated
        if generated < started - STATUS_POLL_GRACE_S or age < -STATUS_POLL_GRACE_S:
            result["bus_note"] = "Status snapshot timestamp is inconsistent with the current process"
            return result
        result["bus_ts"] = generated
        # Reporter heartbeats are at least 30s, or 60s in chill mode. Allow two
        # advertised periods plus polling grace before marking diagnostics stale.
        if age > max(30.0, interval) * 2 + STATUS_POLL_GRACE_S:
            result.update(bus_state="STALE", bus_note="Status heartbeat overdue; bus health unknown")
            self._last_bus_sample = None
            return result
        result["bus_fresh"] = True
        metrics = snapshot.get("event_bus")
        fields = ("revision", "subscriber_count", "deliveries", "failures", "budget_violations")
        if (not isinstance(metrics, dict) or metrics.get("delivery_mode") != "inline" or
                any(type(metrics.get(key)) is not int or metrics[key] < 0 for key in fields)):
            result["bus_note"] = "Current status available; event bus counters are missing or invalid"
            return result
        sample = (pid, started, generated, metrics["revision"], metrics["deliveries"])
        previous = self._last_bus_sample
        state = "OBSERVED"
        if previous and previous[:2] == sample[:2]:
            if generated == previous[2]:
                state = self._last_bus_state
            elif generated > previous[2] and sample[3] >= previous[3] and sample[4] >= previous[4]:
                state = "ACTIVE" if sample[3:] != previous[3:] else "QUIET"
        self._last_bus_sample = sample
        self._last_bus_state = state
        notes = {"OBSERVED": "Inline bus counters available; awaiting a comparison",
                 "ACTIVE": "Events or deliveries increased since the previous heartbeat",
                 "QUIET": "No counter change since the previous heartbeat"}
        warnings = []
        if metrics["failures"]:
            warnings.append(f"{metrics['failures']} subscriber failures recorded")
        if metrics["budget_violations"]:
            warnings.append(f"{metrics['budget_violations']} delivery budget overruns recorded")
        result.update(bus_state=state, bus_note=notes[state], bus_warnings=warnings)
        return result

    @staticmethod
    def _pick_status() -> Optional[Path]:
        """Return the newest status file from the configured diagnostic paths."""
        best: Optional[Path] = None
        best_ts = -1.0
        for p in dict.fromkeys((STATUS_JSON, DATA_STATUS_JSON)):
            try:
                ts = p.stat().st_mtime
                if ts > best_ts:
                    best_ts, best = ts, p
            except OSError:
                continue
        return best

    @classmethod
    def _read_status(cls) -> Dict:
        try:
            path = cls._pick_status()
            if path:
                raw = _read_diagnostic_bytes(path, MAX_STATUS_BYTES)
                data = json.loads(raw)
                return data if isinstance(data, dict) else {}
        except (OSError, ValueError, UnicodeError, RecursionError):
            pass
        return {}

    @staticmethod
    def _failed_modules(snapshot: Dict) -> List[Dict]:
        """Collect only current, process-bound module failures from the caller."""
        out: List[Dict] = []
        modules = snapshot.get("modules", [])
        if isinstance(modules, list):
            for module in modules[:500]:
                if not isinstance(module, dict):
                    continue
                error = module.get("last_error") or ""
                if error or module.get("health_state") in ("error", "crit"):
                    out.append({"name": str(module.get("name", "?"))[:200],
                                "detail": str(error or module.get("health_note", ""))[:2000],
                                "src": "status"})
        return out


class _VisibleInspectorWorker(QThread):
    """Sleep without polling while a detailed diagnostic view is unattended.

    Visibility never interrupts an in-flight native read. Selecting the tab
    wakes the existing worker immediately; stop wakes even an inactive worker.
    Logging and suite-health monitoring have independent, continuous workers.
    """

    def __init__(self) -> None:
        super().__init__()
        self._running = True
        self._active = threading.Event()
        self._wake = threading.Event()

    def set_active(self, active: bool) -> None:
        if active == self._active.is_set():
            return
        if active:
            self._active.set()
        else:
            self._active.clear()
        self._wake.set()

    def stop(self) -> None:
        self._running = False
        self._wake.set()

    def run(self) -> None:
        while self._running:
            self._wake.clear()
            if not self._running:
                break
            if self._active.is_set():
                self._poll()
                self._wake.wait(self._poll_seconds())
            else:
                self._wake.wait()


class ThreadStateWorker(_VisibleInspectorWorker):
    """Tab 4 engine: thread-state visualizer.

    Read-only.  Prefers a cooperative dump Angerona may drop at
    ``diagnostics/thread_dump.json`` (name/id/function/line).  If absent, falls
    back to per-thread OS data from psutil for the Angerona PID — we can still
    surface thread ids, CPU time and status to spot a wedged thread.
    """

    threads = Signal(list, str)   # rows, source-label

    def _poll_seconds(self) -> float:
        return THREAD_POLL_S

    def _poll(self) -> None:
        rows, src = self._collect()
        self.threads.emit(rows, src)

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
            return [], "Angerona PID unavailable or ambiguous"
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


class MemoryProfilerWorker(_VisibleInspectorWorker):
    """Tab 5 engine: top memory consumers.

    Prefers an Angerona-generated ``tracemalloc.json`` (top object types).  If
    absent, uses psutil memory-map data for the Angerona PID to rank the largest
    resident mappings — a coarse but honest leak indicator.
    """

    rows = Signal(list, str)

    def _poll_seconds(self) -> float:
        return MEM_POLL_S

    def _poll(self) -> None:
        rows, src = self._collect()
        self.rows.emit(rows, src)

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
            return [], "Angerona PID unavailable or ambiguous"
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


class ConfigDriftWorker(_VisibleInspectorWorker):
    """Tab 6 engine: config-drift + orphaned resource monitor."""

    drift = Signal(dict)

    def _poll_seconds(self) -> float:
        return CONFIG_POLL_S

    def _poll(self) -> None:
        self.drift.emit(self._collect())

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
        self.console.setLineWrapMode(QPlainTextEdit.NoWrap)
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
        self._visible_marker_key: tuple[float, ...] = ()
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
        # A hidden telemetry tab does not need to repaint its chart every two
        # seconds. Keep collecting the bounded history and draw the newest state
        # on the next visible sample.
        if not self.isVisible():
            return
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
        visible = tuple(x for x in self._event_marks if lo <= x <= hi)
        if visible == self._visible_marker_key:
            return
        self._visible_marker_key = visible
        # Clear old marker series
        for s in self._marker_series:
            self.chart.removeSeries(s)
        self._marker_series.clear()
        for x in visible:
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
        self.bus_lbl.setTextFormat(Qt.PlainText)
        self.bus_lbl.setWordWrap(True)
        self.bus_lbl.setToolTip(
            "Local status snapshots are advisory. Counters describe observed activity; "
            "quiet or stale diagnostics alone cannot establish a deadlock.")
        self.res_lbl = QLabel("Resources: —")
        self.history_lbl = QLabel("Self-test history: not yet observed")
        self.history_lbl.setTextFormat(Qt.PlainText)
        self.history_lbl.setWordWrap(True)
        self.recovery_lbl = QLabel("Self-healing: —")
        self.recovery_lbl.setTextFormat(Qt.PlainText)
        self.recovery_lbl.setWordWrap(True)
        for w in (self.state_lbl, self.pid_lbl, self.bus_lbl, self.history_lbl,
                  self.recovery_lbl, self.res_lbl):
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
        color = {"RUNNING": GREEN, "STOPPED": AMBER, "WAITING": AMBER,
                 "DEAD": RED}.get(state, DIM)
        self.state_lbl.setText(f"STATE: {state}")
        self.state_lbl.setStyleSheet(
            f"font-size:22px;font-weight:800;color:{color};")
        if h["pid"]:
            self.res_lbl.setText(
                f"Resources: CPU {h['cpu']:.0f}%   RSS {human_bytes(h['rss'])}")
        else:
            self.res_lbl.setText("Resources: —")

        bus_state = h.get("bus_state", "UNKNOWN")
        bus_text = f"Event bus: {bus_state} — {h.get('bus_note', 'No current status snapshot')}"
        if h.get("bus_ts") is not None:
            bus_text += f" (snapshot {max(0.0, time.time() - h['bus_ts']):.0f}s ago)"
        warnings = h.get("bus_warnings", [])
        if warnings:
            bus_text += "; " + "; ".join(warnings) + " (cumulative)"
        self.bus_lbl.setText(bus_text)
        bus_color = AMBER if warnings or bus_state == "STALE" else (
            GREEN if bus_state == "ACTIVE" else DIM)
        self.bus_lbl.setStyleSheet(f"color:{bus_color};")
        self.history_lbl.setText(
            f"Self-test history: {h.get('selftest_history_note', 'Not observed; evidence unavailable')}")
        self.recovery_lbl.setText(
            f"Self-healing: {h.get('recovery_note', 'No current recovery report')}")

        fails = h.get("failed", [])
        self.fail_table.setSortingEnabled(False)
        self.fail_table.setRowCount(len(fails))
        for r, f in enumerate(fails):
            self.fail_table.setItem(r, 0, QTableWidgetItem(f["name"]))
            self.fail_table.setItem(r, 1, QTableWidgetItem(f["detail"]))
            self.fail_table.setItem(r, 2, QTableWidgetItem(f["src"]))
        self.fail_table.setSortingEnabled(True)

    def snapshot_text(self) -> str:
        h = self.latest
        if not h:
            return "no health sample yet"
        lines = [f"PID   : {h.get('pid')}", f"STATE : {h.get('state')}"]
        lines.append(self.bus_lbl.text())
        lines.append(self.history_lbl.text())
        lines.append(self.recovery_lbl.text())
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
        self.src_lbl = QLabel("Open this tab to collect thread details.")
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
        self._captured_at = _dt.datetime.now().isoformat(timespec="seconds")
        self.src_lbl.setText(f"Last captured {self._captured_at} · source: {src}")
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
        return f"Last captured {self._captured_at} (updates while tab is visible)\n" + "\n".join(
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
        self.src_lbl = QLabel("Open this tab to collect memory details.")
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
        self._captured_at = _dt.datetime.now().isoformat(timespec="seconds")
        self.src_lbl.setText(f"Last captured {self._captured_at} · source: {src}")
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
        return f"Last captured {self._captured_at} (updates while tab is visible)\n" + "\n".join(
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
        self.src_lbl = QLabel("Open this tab to collect config and resource details.")
        root.addWidget(self.src_lbl)

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
        self._captured_at = _dt.datetime.now().isoformat(timespec="seconds")
        self.src_lbl.setText(f"Last captured {self._captured_at} · updates while tab is visible")
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
        lines = [f"Last captured {self._captured_at} (updates while tab is visible)", "Config files:"]
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
        from angerona.gui.async_snapshot import AsyncSnapshot
        self._reader = AsyncSnapshot(
            self, lambda: SoarEventsTab._read_records, self._apply_records,
            name="BlackBoxSoarReader",
            status=lambda state: self.status.setText(
                "Loading recent SOAR events…" if state == "updating" else
                "Could not refresh SOAR events; previous snapshot retained."
            ) if state != "current" else None,
        )
        self.refresh()

    def refresh(self) -> None:
        if not self._reader.busy:
            self._reader.request()

    @staticmethod
    def _read_records() -> list:
        path = DATA_DIR / "shared_logs" / "soar_queue.json"
        try:
            with path.open("rb") as stream:
                size = stream.seek(0, 2)
                offset = max(0, size - 1024 * 1024)
                stream.seek(offset)
                raw = stream.read(1024 * 1024)
            if offset:
                # The first partial record cannot be trusted as a whole row.
                raw = raw.partition(b"\n")[2]
        except FileNotFoundError:
            return []
        seen, unique = set(), []
        for line in reversed(raw.splitlines()):
            try:
                r = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if not isinstance(r, dict):
                continue
            stamp = _finite_number(r.get("ts"))
            if stamp is None:
                continue
            try:
                rendered_time = time.strftime("%m-%d %H:%M:%S", time.localtime(stamp))
            except (ValueError, OverflowError, OSError):
                continue
            r = {key: str(r.get(key, ""))[:2048]
                 for key in ("origin_module", "severity", "message")} | {
                     "ts": stamp, "display_time": rendered_time,
                 }
            key = (stamp, r["origin_module"], r["severity"], r["message"])
            if key not in seen:
                seen.add(key)
                unique.append(r)
                if len(unique) >= 200:
                    break
        unique.sort(key=lambda r: r.get("ts", 0), reverse=True)
        return unique

    def _apply_records(self, unique: list) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for rec in unique[:200]:
            row = self.table.rowCount(); self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(rec["display_time"]))
            self.table.setItem(row, 1, QTableWidgetItem(rec.get("origin_module", "")))
            sev = QTableWidgetItem(rec.get("severity", ""))
            sev.setForeground(QColor(RED if "CRITICAL" in rec.get("severity", "")
                                    else RED if "HIGH" in rec.get("severity", "")
                                    else TEXT))
            self.table.setItem(row, 2, sev)
            self.table.setItem(row, 3, QTableWidgetItem(rec.get("message", "")[:200]))

        self.table.setSortingEnabled(True)
        self.status.setText(f"{len(unique)} recent SOAR event(s); showing up to 200 from the latest 1 MiB.")

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
        self._pending_result: Optional[int] = None

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

    def _defer_close(self, event) -> bool:
        from angerona.gui.thread_lifecycle import defer_close_until_threads

        return defer_close_until_threads(self, event, (self._worker,))

    def exec(self) -> int:
        # Qt caches this flag before its modal loop and would otherwise delete
        # the hidden dialog while its detail query is still running.
        delete_on_close = self.testAttribute(Qt.WA_DeleteOnClose)
        if delete_on_close:
            self.setAttribute(Qt.WA_DeleteOnClose, False)
        try:
            return super().exec()
        finally:
            if delete_on_close:
                self.setAttribute(Qt.WA_DeleteOnClose, True)
                if self._pending_result is None:
                    self.deleteLater()

    def done(self, result: int) -> None:
        # accept(), reject() and Escape can bypass closeEvent. Keep their first
        # result across hide()/exec() return and finish only after native exit.
        if self._pending_result is None:
            self._pending_result = int(result)
        self.setResult(self._pending_result)
        if self._defer_close(QCloseEvent()):
            return
        result, self._pending_result = self._pending_result, None
        super().done(result)

    def accept(self) -> None:
        self.done(QDialog.Accepted)

    def reject(self) -> None:
        self.done(QDialog.Rejected)

    def closeEvent(self, event) -> None:
        pending = self._pending_result
        if pending is None and self.isVisible():
            self.setResult(QDialog.Rejected)
        if self._defer_close(event):
            if pending is None:
                self._pending_result = int(QDialog.Rejected)
            return
        if pending is not None:
            self._pending_result = None
            super().done(pending)
            event.accept()
            return
        super().closeEvent(event)


_MAX_FIREWALL_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_FIREWALL_RULES = 2000
_MAX_FIREWALL_VISIBLE_RULES = 500


def _read_firewall_command(command: list[str], *, timeout: float) -> str:
    """Collect a fixed read-only query without unbounded ``communicate`` output."""
    import subprocess
    import threading
    from angerona.resilience._selftest_environment import (
        _assign_windows_kill_job, _resume_windows_process, _stop_process_custody,
    )

    if not math.isfinite(timeout) or not 0 < timeout <= 15:
        raise ValueError("Firewall query needs a bounded deadline")
    captured = bytearray()
    done, overflow, failed = threading.Event(), threading.Event(), threading.Event()
    process = job = reader = None
    try:
        kwargs = dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                      stderr=subprocess.DEVNULL, close_fds=True, bufsize=0)
        if os.name == "nt":
            from angerona.core.privilege import (
                sanitized_child_environment, trusted_powershell_path,
                trusted_windows_directories,
            )
            command = list(command)
            if command[0] in {"powershell", "netsh"}:
                _windows, system = trusted_windows_directories()
                command[0] = str(trusted_powershell_path() if command[0] == "powershell"
                                 else system / "netsh.exe")
                kwargs["cwd"] = str(system)
                kwargs["env"] = sanitized_child_environment(source={})
            kwargs["creationflags"] = (
                subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS
                | subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004  # CREATE_SUSPENDED
            )
        else:
            kwargs["start_new_session"] = True
        process = subprocess.Popen(command, **kwargs)
        if os.name == "nt":
            job = _assign_windows_kill_job(process)
            _resume_windows_process(process)

        def read() -> None:
            try:
                while True:
                    remaining = _MAX_FIREWALL_OUTPUT_BYTES - len(captured)
                    chunk = process.stdout.read(min(16384, remaining + 1))
                    if not chunk:
                        return
                    captured.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow.set()
                        return
            except (OSError, ValueError):
                failed.set()
            finally:
                done.set()

        reader = threading.Thread(target=read, name="BlackBoxFirewallOutput", daemon=True)
        reader.start()
        deadline = time.monotonic() + timeout
        if not done.wait(timeout):
            raise TimeoutError("Firewall query exceeded its deadline")
        if overflow.is_set():
            raise ValueError("Firewall query exceeded the 4 MiB output limit")
        if failed.is_set():
            raise OSError("Firewall query output could not be read")
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
        if process.returncode:
            raise OSError(f"Firewall query failed with exit {process.returncode}")
        return captured.decode("utf-8", errors="replace")
    finally:
        _stop_process_custody(process, job)
        if reader is not None and reader.ident is not None:
            reader.join(timeout=2)
        if process is not None and process.stdout is not None:
            process.stdout.close()


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
        self._detail_dialog: Optional[FirewallRuleDetailDialog] = None
        # Keep a detached detail query visible to BlackBoxWindow.stop_workers.
        self._worker: Optional[_FwDetailWorker] = None
        from angerona.gui.async_snapshot import AsyncSnapshot
        self._reader = AsyncSnapshot(
            self, lambda: FirewallTab._read_rules, self._apply_rules,
            name="BlackBoxFirewallReader",
            status=lambda state: self.status.setText(
                "Loading firewall rules…" if state == "updating" else
                "Could not refresh firewall rules; previous snapshot retained."
            ) if state != "current" else None,
        )

    def refresh(self) -> None:
        if not self._reader.busy:
            self._reader.request()

    @staticmethod
    def _read_rules() -> list:
        rules = []
        try:
            out = _read_firewall_command(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); "
                 "Get-NetFirewallRule -ErrorAction Stop | Select-Object -First 2000 DisplayName,Name,"
                 "@{n='Direction';e={$_.Direction.ToString()}},"
                 "@{n='Action';e={$_.Action.ToString()}},"
                 "@{n='Enabled';e={$_.Enabled.ToString()}} | ConvertTo-Json -Compress -Depth 2"],
                timeout=12,
            )
            raw = json.loads(out)
            if isinstance(raw, dict):
                raw = [raw]
            if raw is None:
                raw = []
            if not isinstance(raw, list):
                raise ValueError("Unexpected firewall snapshot")
            for r in raw[:_MAX_FIREWALL_RULES]:
                if not isinstance(r, dict):
                    continue
                def value(key):
                    result = r.get(key, "")
                    if isinstance(result, dict):
                        result = result.get("Value", "")
                    return str(result or "")[:2048]
                name, rule_id = value("DisplayName"), value("Name")
                dirn, act, en = value("Direction"), value("Action"), value("Enabled")
                rules.append({
                    "name": name, "rule_id": rule_id, "use_display": False,
                    "direction": dirn, "action": act,
                    "enabled": str(en), "proto": "", "port": "",
                })
        except Exception:
            # Fallback: netsh
            rules = []
            try:
                out = _read_firewall_command(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                    timeout=10,
                )
                current: dict = {}
                for line in out.splitlines():
                    if line.startswith("Rule Name:"):
                        if current:
                            rules.append(current)
                            if len(rules) >= _MAX_FIREWALL_RULES:
                                current = {}
                                break
                        current = {"name": line.split(":", 1)[1].strip()[:2048],
                                   "rule_id": line.split(":", 1)[1].strip()[:2048],
                                   "use_display": True,
                                   "direction": "", "action": "",
                                   "enabled": "", "proto": "", "port": ""}
                    elif ":" in line and current:
                        k, v = line.split(":", 1)
                        k = k.strip().lower()
                        if "direction" in k:
                            current["direction"] = v.strip()[:2048]
                        elif "action" in k:
                            current["action"] = v.strip()[:2048]
                        elif "enabled" in k:
                            current["enabled"] = v.strip()[:2048]
                        elif "protocol" in k:
                            current["proto"] = v.strip()[:2048]
                        elif "localport" in k:
                            current["port"] = v.strip()[:2048]
                if current:
                    rules.append(current)
            except Exception as exc:
                raise RuntimeError("Could not read firewall rules") from exc
        return rules

    def _apply_rules(self, rules: list) -> None:
        self._all_rules = rules[:_MAX_FIREWALL_RULES]
        self._apply_filter()

    def _apply_filter(self) -> None:
        kw = self.filter_edit.text().lower()
        rules = [r for r in self._all_rules
                 if not kw or kw in r["name"].lower()
                 or kw in r["action"].lower()
                 or kw in r["direction"].lower()]
        self._visible_rules = rules[:_MAX_FIREWALL_VISIBLE_RULES]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for r in self._visible_rules:
            row = self.table.rowCount(); self.table.insertRow(row)
            item = QTableWidgetItem(r["name"])
            item.setData(Qt.UserRole, r)
            self.table.setItem(row, 0, item)
            dirn = QTableWidgetItem(r["direction"])
            dirn.setForeground(QColor(RED if "In" in r["direction"] else TEXT))
            self.table.setItem(row, 1, dirn)
            act = QTableWidgetItem(r["action"])
            act.setForeground(QColor(RED if "Block" in r["action"] else GREEN))
            self.table.setItem(row, 2, act)
            self.table.setItem(row, 3, QTableWidgetItem(r.get("proto", "")))
            self.table.setItem(row, 4, QTableWidgetItem(r.get("port", "")))
        self.table.setSortingEnabled(True)
        self.status.setText(
            f"Showing {len(self._visible_rules)} of {len(rules)} matching rules in a "
            f"{len(self._all_rules)}-rule snapshot. Snapshot limit: {_MAX_FIREWALL_RULES}; "
            f"table limit: {_MAX_FIREWALL_VISIBLE_RULES}. Filtering searches this snapshot only."
        )

    @Slot(int, int)
    def _on_rule_clicked(self, row: int, col: int) -> None:
        if row < 0 or row >= len(self._visible_rules):
            return
        # Display names are not unique. Retain the exact rule across sorting.
        item = self.table.item(row, 0)
        rule = item.data(Qt.UserRole) if item is not None else None
        if not isinstance(rule, dict):
            return
        from shiboken6 import isValid

        current = self._detail_dialog
        if current is not None:
            if isValid(current) and current.isVisible():
                current.raise_()
                current.activateWindow()
            else:
                self.status.setText("Previous detail query is finishing; try again shortly.")
            return

        dlg = FirewallRuleDetailDialog(rule, self)
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        self._detail_dialog = dlg
        self._worker = dlg._worker
        owner_ref, detail_id = weakref.ref(self), id(dlg)

        def release_detail(*_args) -> None:
            owner = owner_ref()
            if owner is None or not isValid(owner):
                return
            current = owner._detail_dialog
            if current is not None and id(current) == detail_id:
                owner._detail_dialog = None
                owner._worker = None

        dlg.destroyed.connect(release_detail)
        dlg.exec()

    def snapshot_text(self) -> str:
        rows = [f"  {r['name']} | {r['direction']} | {r['action']}"
                for r in self._all_rules[:100]]
        return "Firewall Rules:\n" + ("\n".join(rows) or "(none loaded)")


# ─────────────────────────────────────────────────────────────────────────────
#  Main window
# ─────────────────────────────────────────────────────────────────────────────

# Diagnostic exports are private copies, never evidence/response authority.
BUNDLE_CHUNK_BYTES = 64 * 1024
BUNDLE_FILE_BYTES = 4 * 1024 * 1024
BUNDLE_CRASH_BYTES = 512 * 1024
BUNDLE_SETTINGS_BYTES = 256 * 1024
BUNDLE_ENV_BYTES = 1024 * 1024
BUNDLE_TOTAL_BYTES = 16 * 1024 * 1024
BUNDLE_READ_BYTES = 18 * 1024 * 1024
BUNDLE_ARCHIVE_BYTES = 18 * 1024 * 1024
BUNDLE_MANIFEST_BYTES = 64 * 1024
BUNDLE_MEMBER_LIMIT = 32
BUNDLE_SCAN_ENTRIES = 64
BUNDLE_CRASH_FILES = 16
BUNDLE_GUI_CHARS = 32 * 1024
BUNDLE_GUI_NODES = 2048
BUNDLE_SECONDS = 60.0
_BUNDLE_SETTING_FLAGS = (
    "live_debug_enabled", "spyware_auto_contain", "spyware_network_enabled",
    "spyware_memory_enabled", "spyware_beacon_enabled", "spyware_beacon_channel",
    "spyware_beacon_signal",
)


class _BundleCancelled(Exception):
    pass


class _BundleDeadline(Exception):
    pass


class _BundleSourceChanged(Exception):
    pass


class _BundleCapture:
    """Copy existing GUI-owned values with bounds before formatting/encoding."""
    def __init__(self):
        self.chars = BUNDLE_GUI_CHARS
        self.nodes = BUNDLE_GUI_NODES
        self.omitted = 0

    def copy(self, value, depth=0):
        if self.nodes <= 0 or self.chars <= 0 or depth > 4:
            self.omitted += 1
            return None
        self.nodes -= 1
        if value is None or type(value) is bool:
            return value
        if type(value) is int:
            if value.bit_length() <= 64:
                return value
            self.omitted += 1
            return None
        if type(value) is float:
            if math.isfinite(value):
                return value
            self.omitted += 1
            return None
        if type(value) is str:
            cap = min(self.chars, 512)
            result = value[:cap]
            self.chars -= len(result)
            self.omitted += int(len(value) > len(result))
            return result
        if type(value) in (tuple, list):
            result = []
            for index, item in enumerate(value):
                if index >= 64 or self.nodes <= 0 or self.chars <= 0:
                    self.omitted += len(value) - index
                    break
                result.append(self.copy(item, depth + 1))
            return result
        if type(value) is dict:
            result = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= 32 or self.nodes <= 0 or self.chars <= 0:
                    self.omitted += len(value) - index
                    break
                if type(key) is not str or len(key) > 64:
                    self.omitted += 1
                    continue
                if len(key) > self.chars:
                    self.omitted += len(value) - index
                    break
                self.chars -= len(key)
                result[key] = self.copy(item, depth + 1)
            return result
        self.omitted += 1
        return None

    def document_tail(self, document):
        # QTextDocument positions are UTF-16 units. Select a bounded tail in
        # Qt before creating a Python string; never call full toPlainText().
        end = max(0, document.characterCount() - 1)
        count = min(self.chars, 16 * 1024, end)
        cursor = QTextCursor(document)
        cursor.setPosition(end - count)
        cursor.setPosition(end, QTextCursor.KeepAnchor)
        value = cursor.selectedText().replace("\u2029", "\n")
        self.chars -= len(value)
        self.omitted += int(end > count)
        return value


def _bundle_identity(info):
    return info.st_dev, info.st_ino


def _bundle_json(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


class _BundleBuilder:
    """Worker-only bounded source reads and ZIP construction, no widgets."""
    def __init__(self, cancelled):
        self.cancelled = cancelled
        self.deadline = time.monotonic() + BUNDLE_SECONDS
        self.read_left = BUNDLE_READ_BYTES
        self.write_left = BUNDLE_TOTAL_BYTES - BUNDLE_MANIFEST_BYTES
        self.members = 0
        self._cleanup_gap = False
        self.manifest = {
            "schema": "angerona.blackbox.private-bundle.v2", "app": APP_NAME,
            "generated": _dt.datetime.now().isoformat(timespec="seconds"),
            "advisory_only": True, "private_export": True,
            "privacy": "Raw diagnostics and UI copies can contain private data. "
                       "Settings export is exact-boolean allowlist only; .env is hash-only. "
                       "Review before sharing. Originals are unchanged.",
            "gaps": [], "omitted_gap_count": 0, "sources": [],
            "limits": {"read_bytes": BUNDLE_READ_BYTES, "zip_input_bytes": BUNDLE_TOTAL_BYTES,
                       "file_bytes": BUNDLE_FILE_BYTES, "chunk_bytes": BUNDLE_CHUNK_BYTES,
                       "crash_files": BUNDLE_CRASH_FILES, "scanned_entries": BUNDLE_SCAN_ENTRIES,
                       "members": BUNDLE_MEMBER_LIMIT, "cooperative_seconds": BUNDLE_SECONDS},
        }

    def checkpoint(self):
        if self.cancelled():
            raise _BundleCancelled()
        if time.monotonic() >= self.deadline:
            raise _BundleDeadline()

    def gap(self, source, reason):
        if source == "partial_archive":
            self._cleanup_gap = True
        row = {"source": source[:128], "reason": reason[:80]}
        # Repeated omissions must not crowd out distinct coverage gaps.
        for existing in self.manifest["gaps"]:
            if existing["source"] == row["source"] and existing["reason"] == row["reason"]:
                existing["count"] = existing.get("count", 1) + 1
                return
        if len(self.manifest["gaps"]) < 64:
            self.manifest["gaps"].append(row)
        else:
            self.manifest["omitted_gap_count"] += 1

    def read_source(self, path, label, limit, *, tail=False, complete=False):
        self.checkpoint()
        cap = min(limit, self.read_left)
        if cap <= 0:
            self.gap(label, "aggregate-read-limit")
            return None
        descriptor = None
        try:
            before_path = path.lstat()
            if (not stat.S_ISREG(before_path.st_mode)
                    or getattr(before_path, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                self.gap(label, "nonregular-or-reparse-source-omitted")
                return None
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = None
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or _bundle_identity(before) != _bundle_identity(before_path):
                    raise _BundleSourceChanged()
                if complete and before.st_size > cap:
                    self.gap(label, "complete-source-exceeds-limit")
                    return None
                offset = max(0, before.st_size - cap) if tail else 0
                stream.seek(offset)
                remaining = min(before.st_size - offset, cap)
                chunks = []
                while remaining:
                    self.checkpoint()
                    chunk = stream.read(min(remaining, BUNDLE_CHUNK_BYTES))
                    if not chunk:
                        self.gap(label, "short-read")
                        break
                    self.read_left -= len(chunk)
                    remaining -= len(chunk)
                    chunks.append(chunk)
                self.checkpoint()
                after = os.fstat(stream.fileno())
                after_path = path.lstat()
                if (_bundle_identity(before) != _bundle_identity(after)
                        or _bundle_identity(before) != _bundle_identity(after_path)
                        or not stat.S_ISREG(after_path.st_mode)):
                    raise _BundleSourceChanged()
                changed = (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
                data = b"".join(chunks)
                truncated = offset > 0 or len(data) < before.st_size
                if changed:
                    self.gap(label, "source-changed-during-read")
                if truncated:
                    self.gap(label, "source-byte-limit-or-short-read")
                if complete and (changed or truncated):
                    return None
                receipt = {"source": label[:128], "bytes": len(data), "offset": offset,
                           "size_at_open": before.st_size, "truncated": truncated,
                           "changed_during_read": changed}
                self.manifest["sources"].append(receipt)
                return data
        except FileNotFoundError:
            self.gap(label, "source-unavailable")
        except _BundleSourceChanged:
            self.gap(label, "source-identity-changed-omitted")
        except OSError as exc:
            self.gap(label, "source-read-failed-" + type(exc).__name__)
        finally:
            if descriptor is not None:
                os.close(descriptor)
        return None

    def write_member(self, archive, name, data):
        self.checkpoint()
        if self.members >= BUNDLE_MEMBER_LIMIT - 1 or len(data) > self.write_left:
            self.gap(name, "aggregate-zip-input-or-member-limit-omitted")
            return
        with archive.open(name, "w") as member:
            for offset in range(0, len(data), BUNDLE_CHUNK_BYTES):
                self.checkpoint()
                member.write(data[offset:offset + BUNDLE_CHUNK_BYTES])
        self.write_left -= len(data)
        self.members += 1

    def settings(self, archive):
        raw = self.read_source(SETTINGS_JSON, "settings", BUNDLE_SETTINGS_BYTES, complete=True)
        if raw is None:
            return
        def reject_duplicates(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result
        try:
            parsed = json.loads(raw, object_pairs_hook=reject_duplicates,
                                parse_int=lambda _value: None, parse_float=lambda _value: None)
            if type(parsed) is not dict:
                raise ValueError("not an object")
        except (ValueError, UnicodeError, RecursionError):
            self.gap("settings", "invalid-settings-omitted")
            return
        included = {key: parsed[key] for key in _BUNDLE_SETTING_FLAGS
                    if key in parsed and type(parsed[key]) is bool}
        invalid = sum(key in parsed and type(parsed[key]) is not bool for key in _BUNDLE_SETTING_FLAGS)
        if invalid:
            self.gap("settings", "nonboolean-allowlisted-values-omitted")
        self.write_member(archive, "settings.sanitized.json", _bundle_json({
            "policy": "fixed-exact-boolean-allowlist; every other key/value omitted",
            "flags": included, "omitted_top_level_fields": len(parsed) - len(included),
        }))

    def populate(self, archive, capture):
        raw = _bundle_json(capture)
        if len(raw) > 256 * 1024:
            raise ValueError("GUI snapshot exceeded byte limit")
        self.write_member(archive, "ui_snapshot.json", raw)
        if capture.get("omitted", 0):
            self.gap("ui_snapshot", "bounded-ui-snapshot-truncated")
        self.settings(archive)
        raw_env = self.read_source(ENV_FILE, "env", BUNDLE_ENV_BYTES, complete=True)
        if raw_env is not None:
            self.manifest["env_sha256"] = hashlib.sha256(raw_env).hexdigest()
        for path in (NOT_RESPONDING, SELFTEST_FAILURES, CRASH_LOG, STATUS_JSON, FLOW_METRICS):
            cap = min(BUNDLE_FILE_BYTES, self.write_left)
            data = self.read_source(path, path.name, cap, tail=True)
            if data is not None:
                self.write_member(archive, "diagnostics/" + path.name + ".snapshot", data)
        included = 0
        try:
            with os.scandir(CRASH_SNAP_DIR) as entries:
                for index in range(BUNDLE_SCAN_ENTRIES):
                    self.checkpoint()
                    if included >= BUNDLE_CRASH_FILES:
                        self.gap("crash_snapshots", "file-count-limit-remainder-unknown")
                        break
                    entry = next(entries, None)
                    if entry is None:
                        break
                    if not entry.is_file(follow_symlinks=False):
                        self.gap("crash_snapshots", "nonregular-entry-omitted")
                        continue
                    included += 1
                    if len(entry.name) > 96:
                        self.gap("crash_snapshots", "source-label-truncated")
                    # Controlled member names avoid path traversal and duplicate
                    # archive entries from untrusted diagnostic filenames.
                    name = f"crash_snapshots/{included:04d}.snapshot"
                    data = self.read_source(Path(entry.path), "crash:" + entry.name[:96],
                                            min(BUNDLE_CRASH_BYTES, self.write_left), tail=True)
                    if data is not None:
                        self.write_member(archive, name, data)
                else:
                    self.gap("crash_snapshots", "entry-scan-limit-remainder-unknown")
        except OSError as exc:
            self.gap("crash_snapshots", "enumeration-failed-" + type(exc).__name__)
        self.checkpoint()
        raw_manifest = _bundle_json(self.manifest)
        if len(raw_manifest) > BUNDLE_MANIFEST_BYTES:
            raise ValueError("Manifest exceeded byte limit")
        archive.writestr("manifest.json", raw_manifest)

    def build(self, out, capture):
        partial = None
        owned_identity = None
        published = False
        descriptor = None
        result = {"status": "failed", "published": False, "gap_count": 0}
        try:
            self.checkpoint()
            # mkstemp creates only a new private export in the chosen directory.
            # Source diagnostics, settings and environment are always read-only.
            descriptor, name = tempfile.mkstemp(prefix=".Angerona_bundle_", suffix=".zip.partial", dir=out.parent)
            partial = Path(name)
            owned_identity = _bundle_identity(os.fstat(descriptor))
            stream = os.fdopen(descriptor, "w+b")
            descriptor = None  # stream now owns this exact descriptor
            with stream:
                with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                    self.populate(archive, capture)
                self.checkpoint()
                if stream.tell() > BUNDLE_ARCHIVE_BYTES:
                    raise ValueError("Compressed archive exceeded byte limit")
                stream.flush()
                os.fsync(stream.fileno())
                if _bundle_identity(partial.lstat()) != owned_identity:
                    raise _BundleSourceChanged()
                self.checkpoint()
                # Atomic, no-replace publication. An existing destination or an
                # unsupported filesystem is a visible failure, never a fallback
                # overwrite or a silently partial final ZIP.
                os.link(partial, out, follow_symlinks=False)
                published = True
            result["status"] = "created-with-gaps" if self.manifest["gaps"] else "created"
        except _BundleCancelled:
            result["status"] = "cancelled"
        except _BundleDeadline:
            result["status"] = "deadline-exceeded"
        except Exception as exc:
            result["error_type"] = type(exc).__name__
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    self.gap("partial_archive", "descriptor-close-failed")
            if partial is not None and owned_identity is None:
                self.gap("partial_archive", "owned-identity-unavailable-cleanup-held")
            if partial is not None and owned_identity is not None:
                try:
                    info = partial.lstat()
                    if stat.S_ISREG(info.st_mode) and _bundle_identity(info) == owned_identity:
                        partial.unlink()
                    else:
                        self.gap("partial_archive", "owned-path-identity-changed-cleanup-held")
                except OSError as exc:
                    self.gap("partial_archive", "cleanup-failed-" + type(exc).__name__)
            result["published"] = published
            result["gap_count"] = (sum(row.get("count", 1) for row in self.manifest["gaps"])
                                   + self.manifest["omitted_gap_count"])
            result["cleanup_gap"] = self._cleanup_gap
            if published and result["gap_count"]:
                result["status"] = "created-with-gaps"
        return result


class _BundleExportWorker(QThread):
    def __init__(self, out, capture, parent=None):
        super().__init__(parent)
        self.out = out
        self.capture = capture
        self.result = None
        self._cancel = threading.Event()
        self.setObjectName("BlackBoxBundleExport")

    def stop(self):
        self._cancel.set()
        self.requestInterruption()

    def run(self):
        builder = _BundleBuilder(lambda: self._cancel.is_set() or self.isInterruptionRequested())
        self.result = builder.build(self.out, self.capture)

class BlackBoxWindow(QMainWindow):
    close_completed = Signal()
    def __init__(self) -> None:
        super().__init__()
        self._closing = False
        self._bundle_worker = None
        self._bundle_dialog_open = False
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(make_icon())
        self.resize(1180, 820)
        self._shutdown_threads = None
        self._shutdown_timer = QTimer(self)
        self._shutdown_timer.setInterval(50)
        self._shutdown_timer.timeout.connect(self._finish_close)

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
        from angerona.gui.live_debug_panel import LiveDebugPanel
        self.tab_live_debug = LiveDebugPanel(self)
        self.tabs.addTab(self.tab_live_debug, "9 · Live AI Review")
        outer.addWidget(self.tabs, 1)

        # footer actions
        footer = QHBoxLayout()
        self.btn_export = QPushButton("Generate Diagnostic Bundle (.zip)")
        self.btn_export.setObjectName("Primary")
        self.btn_archive = QPushButton("Archive && Clear Logs")
        self.btn_sandbox = QPushButton("Launch Sandbox Editor")
        self.btn_cancel_bundle = QPushButton("Cancel export")
        self.btn_cancel_bundle.setEnabled(False)
        footer.addWidget(self.btn_export)
        footer.addWidget(self.btn_cancel_bundle)
        footer.addWidget(self.btn_archive)
        footer.addStretch(1)
        footer.addWidget(self.btn_sandbox)
        outer.addLayout(footer)

        self.btn_export.clicked.connect(self.on_export_bundle)
        self.btn_cancel_bundle.clicked.connect(self.on_cancel_bundle)
        self.btn_archive.clicked.connect(self.on_archive_clear)
        self.btn_sandbox.clicked.connect(self.on_launch_sandbox)

        try:
            self._start_workers()
            self.tabs.currentChanged.connect(self._sync_inspectors)
            self._sync_inspectors()
        except BaseException:
            # A partial start must not drop a running QThread's Python owner.
            self.stop_workers(timeout_ms=None)
            raise

    def _sync_inspectors(self, *_args) -> None:
        visible = not self._closing and self.isVisible() and not self.isMinimized()
        for worker_name, tab_name in (("w_thread", "tab_threads"),
                                     ("w_mem", "tab_mem"),
                                     ("w_config", "tab_config")):
            worker = getattr(self, worker_name, None)
            if worker is not None:
                worker.set_active(visible and self.tabs.currentWidget() is getattr(self, tab_name))

    def showEvent(self, event) -> None:  # noqa: N802 - Qt signature
        super().showEvent(event)
        self._sync_inspectors()

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt signature
        super().hideEvent(event)
        self._sync_inspectors()

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        super().changeEvent(event)
        self._sync_inspectors()

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

    def stop_workers(self, timeout_ms: int | None = 2000) -> bool:
        """Stop every owner first, then join against one shared deadline.

        A zero timeout is a nonblocking progress check for normal window close.
        The entry point uses None after its event loop exits: native reads cannot
        be safely preempted, and their QThread wrappers must remain owned until
        completion. No worker is terminated or discarded on a timeout.
        """
        if self._shutdown_threads is None:
            self._closing = True
            threads = []
            for name in ("w_log", "w_host", "w_health", "w_thread", "w_mem", "w_config"):
                worker = getattr(self, name, None)
                if worker is not None:
                    worker.stop()
                    threads.append(worker)
            bundle_worker = self._bundle_worker
            if bundle_worker is not None:
                bundle_worker.stop()
                threads.append(bundle_worker)
            # Snapshot readers and optional detail/AI workers are owned by child
            # views, rather than the six always-present recorder attributes.
            from angerona.gui.async_snapshot import AsyncSnapshot
            for view in (self, *self.findChildren(QWidget)):
                reader = getattr(view, "_reader", None)
                if isinstance(reader, AsyncSnapshot):
                    reader.close()
                    if reader.thread is not None:
                        threads.append(reader.thread)
                worker = getattr(view, "_worker", None)
                if isinstance(worker, QThread):
                    worker.requestInterruption()
                    threads.append(worker)
            debug_panel = getattr(self, "tab_live_debug", None)
            if debug_panel is not None:
                debug_panel.stop_workers(timeout_ms=0)
                threads.extend(debug_panel._workers)
            # Preserve ownership even when a bounded caller needs to return.
            self._shutdown_threads = tuple(dict.fromkeys(threads))
            overlay = getattr(self, "_angerona_window_reveal", None)
            if overlay is not None:
                overlay.shutdown()
        deadline = None if timeout_ms is None else time.monotonic() + max(0, timeout_ms) / 1000
        stopped = True
        for worker in self._shutdown_threads:
            remaining = None if deadline is None else max(0, deadline - time.monotonic())
            if isinstance(worker, QThread):
                if remaining is None:
                    worker.wait()
                else:
                    worker.wait(max(0, int(remaining * 1000)))
                stopped = not worker.isRunning() and stopped
            else:
                worker.join(remaining)
                stopped = not worker.is_alive() and stopped
        return stopped

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        if not self.stop_workers(timeout_ms=0):
            # Keep the native widget/worker owners alive without blocking Qt.
            self.status_chip.setText("Stopping readers… waiting for active reads")
            self.centralWidget().setEnabled(False)
            self._shutdown_timer.start()
            event.ignore()
            return
        self._shutdown_timer.stop()
        super().closeEvent(event)
        if event.isAccepted() and not getattr(self, "_close_completed_emitted", False):
            self._close_completed_emitted = True
            self.close_completed.emit()

    def _finish_close(self) -> None:
        if self.stop_workers(timeout_ms=0):
            self._shutdown_timer.stop()
            self.close()

    # -- footer actions -----------------------------------------------------
    def _capture_bundle(self):
        """GUI-thread DTO only: bounded selection/caches, no source file I/O."""
        budget = _BundleCapture()
        capture = {"schema": "angerona.blackbox.bounded-ui.v1", "advisory_only": True}
        capture["console_tail"] = budget.document_tail(self.tab_logs.console.document())
        views = {}
        for name, value in (
            ("host_telemetry", self.tab_host.latest), ("suite_health", self.tab_health.latest),
            ("thread_state", self.tab_threads.latest), ("memory_profile", self.tab_mem.latest),
            ("config_drift", self.tab_config.latest), ("firewall_rules", self.tab_firewall._all_rules),
        ):
            views[name] = budget.copy(value)
        # SOAR cells already originate from capped 2,048-character fields.
        # Bound rows/columns before copying, rather than formatting the table.
        table = self.tab_soar.table
        rows = []
        for row in range(min(64, table.rowCount())):
            if budget.chars <= 0 or budget.nodes <= 0:
                break
            values = []
            for column in range(min(4, table.columnCount())):
                item = table.item(row, column)
                values.append(budget.copy(item.text() if item is not None else ""))
            rows.append(values)
        budget.omitted += max(0, table.rowCount() - len(rows))
        views["soar_events"] = rows
        panel = getattr(self, "tab_live_debug", None)
        if panel is not None:
            records = []
            for row in panel.model.rows[-20:]:
                if budget.nodes <= 0 or budget.chars <= 0:
                    break
                records.append(budget.copy({"original_view": row.record, "local_review": row.annotation}))
            views["live_ai_review"] = {
                "records": records, "omitted_visible_records": len(panel.model.rows) - len(records),
                "status": budget.copy(panel._status_text), "server_pid": panel._connected_pid,
                "client_gaps": budget.copy(panel._lost),
                "history_evicted": budget.copy(panel.model.evicted),
                "advisory_only": True,
            }
        capture["views"] = views
        capture["omitted"] = budget.omitted
        return capture

    @Slot()
    def on_export_bundle(self) -> None:
        """Admit one private export; source reads/compression run off the GUI."""
        if self._closing:
            return
        if self._bundle_worker is not None or self._bundle_dialog_open:
            self.status_chip.setText("Export already active; duplicate request held")
            return
        self._bundle_dialog_open = True
        self.btn_export.setEnabled(False)
        try:
            default = str(ARCHIVE_DIR / f"Angerona_DiagBundle_{now_stamp()}.zip")
            path, _ = QFileDialog.getSaveFileName(
                self, "Save private diagnostic bundle (choose a NEW filename)",
                default, "Zip archive (*.zip)")
            if not path or self._closing:
                self.btn_export.setEnabled(not self._closing)
                return
            capture = self._capture_bundle()
            worker = _BundleExportWorker(Path(path), capture, self)
            self._bundle_worker = worker
            worker.finished.connect(lambda: self._bundle_retired(worker))
            self.btn_cancel_bundle.setEnabled(True)
            self.status_chip.setText("Export running — private diagnostics; review before sharing")
            try:
                worker.start()
            except Exception as exc:
                worker.result = {"status": "failed", "published": False,
                                 "error_type": type(exc).__name__, "gap_count": 0}
                worker.stop()
                self._bundle_retired(worker)
        except Exception as exc:
            self.btn_export.setEnabled(not self._closing)
            self.status_chip.setText("Export setup failed: " + type(exc).__name__)
        finally:
            self._bundle_dialog_open = False

    @Slot()
    def on_cancel_bundle(self) -> None:
        worker = self._bundle_worker
        if worker is not None:
            worker.stop()
            self.btn_cancel_bundle.setEnabled(False)
            self.status_chip.setText("Cancelling export… waiting for active I/O")

    def _bundle_retired(self, worker) -> None:
        from shiboken6 import isValid

        if not isValid(self) or not isValid(worker) or self._bundle_worker is not worker:
            return
        # A result/finished signal alone is not proof of native thread exit.
        if not worker.wait(0):
            QTimer.singleShot(25, lambda: self._bundle_retired(worker))
            return
        if self._closing:
            # stop_workers owns this object until its shutdown tuple retires.
            # Parent deletion then releases this already-stopped QThread.
            return
        self._bundle_worker = None
        self.btn_export.setEnabled(True)
        self.btn_cancel_bundle.setEnabled(False)
        result = worker.result or {"status": "failed", "published": False, "gap_count": 0}
        destination = str(worker.out)[:1024]
        worker.deleteLater()
        self.status_chip.setText("Export: " + result["status"])
        if result.get("published"):
            QMessageBox.information(
                self, "Private bundle created", f"Saved:\n{destination}\n\n"
                f"Reported gaps: {result.get('gap_count', 0)}. Inspect manifest.json and "
                "settings.sanitized.json. This ZIP can contain private diagnostic data. "
                "Review before sharing. Existing destination files are never overwritten."
                + ("\nTemporary-file cleanup needs review." if result.get("cleanup_gap") else ""))
        elif result["status"] not in ("cancelled",):
            QMessageBox.warning(
                self, "Export incomplete", "No completed bundle was published. Status: "
                + result["status"] + "; " + result.get("error_type", "")
                + (". Temporary-file cleanup needs review." if result.get("cleanup_gap") else ""))

    @Slot()
    def on_archive_clear(self) -> None:
        confirm = QMessageBox.question(
            self, "Archive & Clear",
            "Copy diagnostic snapshots into archive/ and clear the recorder console?\n"
            "Live diagnostic files remain in place. Files larger than 4 MB are copied as tails.",
            QMessageBox.Yes | QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        archive = ARCHIVE_DIR
        try:
            archive.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(self, "Archive failed", str(exc))
            return
        copied = 0
        for src in DIAG_DIR.glob("*"):
            if src.is_file() and src.suffix in (".log", ".json", ".txt"):
                try:
                    size = src.stat().st_size
                    with src.open("rb") as handle:
                        handle.seek(max(0, size - MAX_STATUS_BYTES))
                        data = handle.read(MAX_STATUS_BYTES)
                    suffix = ".tail" if size > MAX_STATUS_BYTES else ""
                    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                    dst = archive / f"{stamp}_{src.name}{suffix}"
                    with dst.open("xb") as handle:
                        handle.write(data)
                    copied += 1
                except OSError:
                    pass
        self.tab_logs.console.clear()
        QMessageBox.information(self, "Done", f"Copied {copied} diagnostic snapshot(s) to {archive}.")

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

    app = win = ui_watchdog = beat_timer = component_beat = None
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
        # Reverse-close animations hide the window before its final close.
        # Closing an already hidden widget need not emit lastWindowClosed, so
        # quitOnLastWindowClosed alone can leave a fully drained recorder alive.
        # Only the standalone entry point owns exiting this application loop.
        win.close_completed.connect(lambda: app.exit(0))
        app.aboutToQuit.connect(lambda: win.stop_workers(timeout_ms=0))
        beat_timer = QTimer()
        beat_timer.timeout.connect(ui_watchdog.beat)
        # This independent recorder pulses only when its real Qt event loop
        # dispatches the timer. A separate thread must not mask a frozen window.
        from angerona.resilience.component_status import ProgressHeartbeat
        component_beat = ProgressHeartbeat("blackbox")
        beat_timer.timeout.connect(component_beat.beat)
        if component_beat.failure:
            try:
                with open(_crash_log, "a", encoding="utf-8") as stream:
                    stream.write("BLACKBOX HEARTBEAT UNAVAILABLE: " + component_beat.failure + "\n")
            except OSError:
                pass
        beat_timer.start(1000)
        try:
            from angerona.core.config import Config
            motion_config = Config.load()
        except Exception:
            motion_config = None
        if args.show:
            from angerona.gui.header_controls import show_with_window_reveal
            show_with_window_reveal(
                win,
                config=motion_config,
                color="#38bdf8",
            )
        else:
            from angerona.gui.header_controls import install_global_window_reveal
            install_global_window_reveal(win, config=motion_config)
            win.showMinimized()

        exit_code = app.exec()
    except Exception:
        import datetime
        msg = f"[{datetime.datetime.now().isoformat()}] BLACKBOX STARTUP CRASH\n{traceback.format_exc()}\n"
        try:
            with open(_crash_log, "a", encoding="utf-8") as f:
                f.write(msg)
        except Exception:
            pass
        raise
    finally:
        if beat_timer is not None:
            beat_timer.stop()
        if component_beat is not None:
            try:
                component_beat.close()
            except Exception:
                pass  # A stale/missing heartbeat remains explicitly unavailable.
        if ui_watchdog is not None:
            ui_watchdog.stop()
            if ui_watchdog._thread is not None:
                ui_watchdog._thread.join()
        if win is not None:
            # Direct app.quit(), startup exceptions and Ctrl+C can bypass the
            # normal asynchronous close path. Keep native owners until all
            # in-flight read-only work completes, then delete only those owners.
            win.stop_workers(timeout_ms=None)
            win.deleteLater()
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        if app is not None:
            app.shutdown()
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
