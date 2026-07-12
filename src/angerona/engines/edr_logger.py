"""
edr_logger.py — Structured logging for the Unified EDR Stack

Features:
  - JSON-lines format (one JSON object per line) — easy to parse or grep
  - Rotating log files (5 MB max, keeps last 3)
  - Severity levels: DEBUG / INFO / WARNING / ERROR / CRITICAL
  - Per-component tagging so you can filter by subsystem
  - Human-readable console output (coloured on Windows via ANSI)
  - Thread-safe
  - Call edr_logger.tail(n) to get the last n entries for the dashboard

FIX APPLIED:
  The original hardcoded LOG_DIR to D:\\local-security-ai\\logs and called
  RotatingFileHandler at module import time. If that drive or folder didn't
  exist yet when agent.py first imported edr_logger, Python threw a
  FileNotFoundError during import — before agent.py even reached main() —
  silently killing the process and preventing the socket from ever opening.

  Fix: LOG_DIR now defaults to a "logs" subfolder next to this script file,
  with an override via the EDR_LOG_DIR environment variable. The folder is
  created with exist_ok=True before the handler is attached, so it always
  works regardless of what drive or directory the project lives on.

Usage:
    from edr_logger import log, tail, LogLevel

    log("FIM", "INFO",  "Baseline built — 412 files tracked")
    log("GEMINI", "ERROR", "HTTP 429 rate-limit", data={"retry_after": 30})
    log("MEMORY", "CRITICAL", "PAGE_EXECUTE_READWRITE in explorer.exe PID 4821")
"""

import os
import json
import time
import threading
import traceback
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
import logging

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
# FIX: Derive the log directory relative to this file instead of hardcoding
# D:\local-security-ai\logs. If you set EDR_LOG_DIR in your .env, that wins.
_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
LOG_DIR      = os.getenv("EDR_LOG_DIR", os.path.join(_SCRIPT_DIR, "logs"))
LOG_FILE     = os.path.join(LOG_DIR, "edr.log")
MAX_BYTES    = 5 * 1024 * 1024   # 5 MB per file
BACKUP_COUNT = 3                  # keep edr.log, edr.log.1, edr.log.2, edr.log.3

# In-memory ring buffer for dashboard tail
_RING_SIZE   = 200
_ring: list  = []
_ring_lock   = threading.Lock()

# ─────────────────────────────────────────────
# LEVEL CONSTANTS
# ─────────────────────────────────────────────
class LogLevel:
    DEBUG    = "DEBUG"
    INFO     = "INFO"
    WARNING  = "WARNING"
    ERROR    = "ERROR"
    CRITICAL = "CRITICAL"

_LEVEL_ORDER = {
    "DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4
}

# ANSI colours for console (Windows 10+ supports these natively)
_COLOURS = {
    "DEBUG":    "\033[90m",   # dark grey
    "INFO":     "\033[36m",   # cyan
    "WARNING":  "\033[33m",   # yellow
    "ERROR":    "\033[31m",   # red
    "CRITICAL": "\033[1;31m", # bold red
}
_RESET = "\033[0m"

# ─────────────────────────────────────────────
# INTERNAL SETUP
# ─────────────────────────────────────────────
# FIX: makedirs is now guaranteed to run before the handler is constructed,
# so importing this module can never crash due to a missing directory.
os.makedirs(LOG_DIR, exist_ok=True)

# Raw file handler — writes JSON lines directly (bypass Python logging formatter)
_file_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=MAX_BYTES,
    backupCount=BACKUP_COUNT,
    encoding="utf-8",
)

# Minimal Python logger just for the file handler plumbing
_py_logger = logging.getLogger("edr_raw")
_py_logger.setLevel(logging.DEBUG)
_py_logger.addHandler(_file_handler)
_py_logger.propagate = False   # don't bubble up to root logger

_write_lock = threading.Lock()

# ─────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────

def log(
    component: str,
    level: str,
    message: str,
    data: dict | None = None,
    exc: BaseException | None = None,
):
    """
    Write a structured log entry.

    Args:
        component : subsystem name, e.g. "FIM", "GEMINI", "MEMORY", "LINEAGE"
        level     : one of LogLevel.* constants
        message   : human-readable description
        data      : optional dict of extra key-value context
        exc       : optional exception — traceback is captured automatically
    """
    level = level.upper()
    if level not in _LEVEL_ORDER:
        level = "INFO"

    entry = {
        "ts":        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "level":     level,
        "component": component.upper(),
        "msg":       message,
    }

    if data:
        # Flatten non-serialisable values to strings
        entry["data"] = {
            k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
            for k, v in data.items()
        }

    if exc is not None:
        entry["exception"] = {
            "type":      type(exc).__name__,
            "value":     str(exc),
            "traceback": traceback.format_exc(),
        }

    json_line = json.dumps(entry, ensure_ascii=False)

    # ── Write to rotating file ──
    with _write_lock:
        _py_logger.info(json_line)
        _file_handler.flush()

    # ── Store in ring buffer ──
    with _ring_lock:
        _ring.append(entry)
        if len(_ring) > _RING_SIZE:
            _ring.pop(0)

    # ── Console output ──
    colour   = _COLOURS.get(level, "")
    ts_short = entry["ts"][11:19]           # HH:MM:SS
    print(
        f"{colour}[{ts_short}] [{level:<8}] [{component.upper():<12}] {message}{_RESET}",
        flush=True,
    )


def tail(n: int = 20, min_level: str = "DEBUG", component: str | None = None) -> list[dict]:
    """
    Return last n log entries from the in-memory ring buffer.

    Args:
        n         : how many entries to return (newest last)
        min_level : filter — only return entries at this level or above
        component : if set, filter to only this component (case-insensitive)

    Returns list of entry dicts — same shape written to disk.
    """
    min_ord = _LEVEL_ORDER.get(min_level.upper(), 0)
    with _ring_lock:
        entries = list(_ring)

    if component:
        comp_upper = component.upper()
        entries = [e for e in entries if e.get("component") == comp_upper]

    entries = [e for e in entries if _LEVEL_ORDER.get(e.get("level", "INFO"), 1) >= min_ord]
    return entries[-n:]


def tail_formatted(n: int = 20, min_level: str = "WARNING") -> list[str]:
    """
    Returns last n entries as formatted one-line strings — suitable for the
    dashboard ENGINE PROCESS TRACE LOG panel.
    """
    lines = []
    for e in tail(n, min_level):
        ts   = e["ts"][11:19]
        comp = e["component"]
        lvl  = e["level"]
        msg  = e["msg"]
        extra = ""
        if "exception" in e:
            extra = f" | EXC: {e['exception']['type']}: {e['exception']['value']}"
        if "data" in e:
            extra += " | " + " ".join(f"{k}={v}" for k, v in e["data"].items())
        lines.append(f"[{ts}][{lvl}][{comp}] {msg}{extra}")
    return lines


def get_log_path() -> str:
    return LOG_FILE


# ─────────────────────────────────────────────
# CONVENIENCE SHORTCUTS
# ─────────────────────────────────────────────

def debug(component: str, message: str, data: dict | None = None):
    log(component, LogLevel.DEBUG, message, data)

def info(component: str, message: str, data: dict | None = None):
    log(component, LogLevel.INFO, message, data)

def warning(component: str, message: str, data: dict | None = None, exc: BaseException | None = None):
    log(component, LogLevel.WARNING, message, data, exc)

def error(component: str, message: str, data: dict | None = None, exc: BaseException | None = None):
    log(component, LogLevel.ERROR, message, data, exc)

def critical(component: str, message: str, data: dict | None = None, exc: BaseException | None = None):
    log(component, LogLevel.CRITICAL, message, data, exc)
