"""Opt-in test/Qt execution journal; diagnostic observations never grade tests."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

_CLOCK = time.monotonic
_ENCODE = json.dumps
_install_handler = None
_stream = None
_lock = threading.RLock()
_current = ""
_previous_qt_handler = None
_installed = False


def _record(kind: str, **fields) -> None:
    with _lock:
        if _stream is None:
            return
        _stream.write(_ENCODE({"kind": kind, "monotonic": _CLOCK(), **fields}) + "\n")
        _stream.flush()  # survive process abort; no per-test durable fsync


def _qt_handler(mode, context, message):
    label = getattr(mode, "name", str(mode))
    if label in {"QtCriticalMsg", "QtFatalMsg"}:
        _record("qt-message", nodeid=_current, severity=label, message=str(message)[:2048])
    if _previous_qt_handler is not None:
        _previous_qt_handler(mode, context, message)
    else:
        sys.stderr.write(str(message) + "\n")
        sys.stderr.flush()


def _install_qt_handler() -> None:
    global _previous_qt_handler, _installed
    if _install_handler is None:
        return
    previous = _install_handler(_qt_handler)
    if previous is not _qt_handler:
        _previous_qt_handler = previous
    _installed = True


def pytest_configure(config):
    global _stream, _install_handler
    output = os.environ.get("ANGERONA_PYTEST_TRACE_PATH")
    if not output:
        return
    # The gate selects this explicit diagnostic output; existing evidence must
    # not be overwritten. Opening errors fail setup instead of hiding them.
    _stream = Path(output).open("x", encoding="utf-8", buffering=1)
    try:
        from PySide6.QtCore import qInstallMessageHandler
        _install_handler = qInstallMessageHandler
    except ImportError:
        pass
    _record("session-start")


def pytest_runtest_logstart(nodeid, location):
    global _current
    _current = str(nodeid)[:4096]
    _record("test-start", nodeid=_current)
    if _stream is not None:
        _install_qt_handler()


def pytest_runtest_logreport(report):
    _record(
        "test-report", nodeid=str(report.nodeid)[:4096], when=report.when,
        outcome=report.outcome, duration=report.duration,
        failure=str(report.longrepr)[-8192:] if report.failed else "",
    )


def pytest_unconfigure(config):
    global _stream, _installed
    if _installed:
        _install_handler(_previous_qt_handler)
        _installed = False
    with _lock:
        if _stream is not None:
            _record("session-end")
            _stream.close()
            _stream = None
