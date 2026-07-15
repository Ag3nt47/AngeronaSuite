"""Crash capture.

Under `pythonw` there is no console, so an unhandled exception or a native Qt
fault leaves no trace — the window just vanishes. install() wires up:
  * sys.excepthook            — unhandled exceptions on any thread's stack
  * threading.excepthook      — exceptions in background/module/shark threads
  * faulthandler              — hard native faults (segfault / Qt C++ abort)
  * qInstallMessageHandler    — Qt Critical/Fatal messages

Everything is appended (timestamped) to <data_dir>/logs/crash.log AND mirrored
into the repo's diagnostics/crash.log so it's easy to find and share.
"""
from __future__ import annotations

import datetime
import faulthandler
import os
import sys
import threading
import traceback
from pathlib import Path

_TARGETS: list[Path] = []
_FH_FILES: list = []


def _data_log() -> Path:
    from angerona.core.data_paths import data_dir
    d = data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d / "crash.log"


def _repo_log() -> Path | None:
    try:
        repo = Path(__file__).resolve().parents[3]   # core→angerona→src→<repo>
        d = repo / "diagnostics"
        d.mkdir(parents=True, exist_ok=True)
        return d / "crash.log"
    except Exception:
        return None


def _write(kind: str, text: str) -> None:
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    block = f"\n{'=' * 72}\n[{stamp}] {kind}\n{'-' * 72}\n{text}\n"
    for p in _TARGETS:
        try:
            with open(p, "a", encoding="utf-8") as f:
                f.write(block)
        except Exception:
            pass


def install() -> list[Path]:
    global _TARGETS
    _TARGETS = [p for p in (_data_log(), _repo_log()) if p]

    # native hard faults → dump the C/Python stack to every target file
    for p in _TARGETS:
        try:
            fh = open(p, "a", encoding="utf-8")
            _FH_FILES.append(fh)
            faulthandler.enable(file=fh, all_threads=True)
        except Exception:
            pass

    def _excepthook(exc_type, exc, tb):
        _write("UNHANDLED EXCEPTION (main)",
               "".join(traceback.format_exception(exc_type, exc, tb)))
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = _excepthook

    def _threadhook(args):
        _write(f"THREAD EXCEPTION ({getattr(args.thread, 'name', '?')})",
               "".join(traceback.format_exception(
                   args.exc_type, args.exc_value, args.exc_traceback)))

    try:
        threading.excepthook = _threadhook
    except Exception:
        pass

    try:
        from PySide6.QtCore import QtMsgType, qInstallMessageHandler

        def _qt_handler(mode, context, message):
            if mode in (QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
                _write(f"QT {mode.name if hasattr(mode, 'name') else mode}", str(message))

        qInstallMessageHandler(_qt_handler)
    except Exception:
        pass

    _write("STARTUP", "crash logging armed — this line proves the log is writable.")
    return _TARGETS
