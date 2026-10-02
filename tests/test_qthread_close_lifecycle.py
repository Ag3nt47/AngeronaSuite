from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent, QThread, Qt, Signal
from PySide6.QtWidgets import QApplication, QDialog

from angerona.gui.thread_lifecycle import defer_close_until_threads


def test_parent_destruction_and_gc_cannot_destroy_deferred_worker(tmp_path):
    from angerona.core.privilege import sanitized_child_environment

    script = r'''
import gc, os, threading, time, weakref
if os.name == 'nt':
    import ctypes
    ctypes.windll.kernel32.SetErrorMode(0x8007)
import shiboken6
from PySide6.QtCore import QThread, Qt, QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QDialog, QWidget
from angerona.gui.thread_lifecycle import defer_close_until_threads, _DEFERRED_OWNERS
app = QApplication([])
ready, release = threading.Event(), threading.Event()
class Worker(QThread):
    def run(self):
        ready.set()
        release.wait(5)
class Dialog(QDialog):
    def closeEvent(self, event):
        if not defer_close_until_threads(self, event, (self.worker,)):
            super().closeEvent(event)
parent = QWidget()
dialog = Dialog(parent)
dialog.setAttribute(Qt.WA_DeleteOnClose, True)
dialog.worker = Worker(dialog)
worker = dialog.worker
worker.start()
assert ready.wait(3)
try:
    assert dialog.close() is False
    reference, key = weakref.ref(dialog), id(dialog)
    shiboken6.delete(parent)
    del parent, dialog
    gc.collect()
    assert reference() is not None and worker.isRunning()
    assert key in _DEFERRED_OWNERS
finally:
    release.set()
    assert worker.wait(3000)
deadline = time.monotonic() + 3
while key in _DEFERRED_OWNERS and time.monotonic() < deadline:
    app.processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
assert key not in _DEFERRED_OWNERS
assert reference() is None or not shiboken6.isValid(reference())
print('deferred native worker survived parent destruction and GC')
'''
    environment = sanitized_child_environment(source={})
    environment.update({"QT_QPA_PLATFORM": "offscreen", "TEMP": str(tmp_path), "TMP": str(tmp_path)})
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1],
        env=environment, capture_output=True, timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")[-2000:]
    assert b"survived parent destruction and GC" in result.stdout


class _BlockingWorker(QThread):
    def __init__(self, ready: threading.Event, release: threading.Event, parent=None) -> None:
        super().__init__(parent)
        self._ready = ready
        self._release = release

    def run(self) -> None:
        self._ready.set()
        self._release.wait(timeout=3.0)


class _PayloadWorker(_BlockingWorker):
    """Exercise compatibility with a third-party worker that shadows finished."""

    finished = Signal(dict)

    def __init__(
        self, ready: threading.Event, release: threading.Event,
        emit_allowed: threading.Event, parent=None,
    ) -> None:
        super().__init__(ready, release, parent)
        self._emit_allowed = emit_allowed

    def run(self) -> None:
        self._ready.set()
        self._emit_allowed.wait(timeout=3.0)
        self.finished.emit({"verdict": "benign"})
        self._release.wait(timeout=3.0)
class _WorkerDialog(QDialog):
    def __init__(self, ready: threading.Event, release: threading.Event) -> None:
        super().__init__()
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.worker = _BlockingWorker(ready, release, self)

    def closeEvent(self, event) -> None:  # noqa: N802
        if defer_close_until_threads(self, event, (self.worker,)):
            return
        super().closeEvent(event)


def test_close_is_nonblocking_and_defers_qthread_destruction() -> None:
    app = QApplication.instance() or QApplication([])
    ready = threading.Event()
    release = threading.Event()
    dialog = _WorkerDialog(ready, release)
    dialog.show()
    worker = dialog.worker
    worker.start()
    try:
        assert ready.wait(timeout=1.0)

        started = time.perf_counter()
        assert dialog.close() is False
        assert time.perf_counter() - started < 0.2
        assert not dialog.isVisible()
        assert dialog._angerona_deferred_close is True
        assert worker.isRunning()
    finally:
        release.set()
        worker.wait(3_000)

    assert not worker.isRunning()
    deadline = time.monotonic() + 1.0
    while shiboken6.isValid(dialog) and time.monotonic() < deadline:
        app.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    assert not shiboken6.isValid(dialog)


def test_alert_detail_defers_close_during_standalone_analysis() -> None:
    from angerona.core.eventbus import Event, Severity
    from angerona.gui.pages import AlertDetailDialog

    app = QApplication.instance() or QApplication([])
    ready = threading.Event()
    release = threading.Event()
    emit_allowed = threading.Event()
    result_seen = threading.Event()
    dialog = AlertDetailDialog(
        Event(module="Lifecycle Test", message="benign", severity=Severity.INFO)
    )
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    dialog._analyze_worker = _PayloadWorker(ready, release, emit_allowed, dialog)
    dialog.show()
    worker = dialog._analyze_worker
    worker.finished.connect(lambda _payload: result_seen.set())
    worker.start()
    try:
        assert ready.wait(timeout=1.0)

        assert dialog.close() is False
        assert dialog._angerona_deferred_close is True
        assert not dialog.isVisible()

        # Deliver the shadowed result signal while native run() is blocked.
        # The close helper must retry after this early callback.
        emit_allowed.set()
        deadline = time.monotonic() + 1.0
        while not result_seen.is_set() and time.monotonic() < deadline:
            app.processEvents()
        assert result_seen.is_set()
        assert worker.isRunning()
    finally:
        emit_allowed.set()
        release.set()
        worker.wait(3_000)

    assert not worker.isRunning()
    deadline = time.monotonic() + 1.0
    while shiboken6.isValid(dialog) and time.monotonic() < deadline:
        app.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    assert not shiboken6.isValid(dialog)


def test_analysis_result_precedes_native_thread_completion_without_shadowing() -> None:
    from angerona.core.analysis_worker import AnalysisWorker

    app = QApplication.instance() or QApplication([])
    assert "finished" not in AnalysisWorker.__dict__
    assert "result_ready" in AnalysisWorker.__dict__

    release = threading.Event()
    result_seen = threading.Event()
    native_finished = threading.Event()

    class OrderingWorker(AnalysisWorker):
        def run(self) -> None:
            self.result_ready.emit({"verdict": "benign"})
            release.wait(timeout=3.0)

    worker = OrderingWorker({"type": "lifecycle-test"})
    worker.result_ready.connect(lambda _result: result_seen.set())
    worker.finished.connect(native_finished.set)
    worker.start()
    try:
        deadline = time.monotonic() + 1.0
        while not result_seen.is_set() and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.005)
        assert result_seen.is_set()
        assert worker.isRunning()
        assert not native_finished.is_set()
    finally:
        release.set()
        worker.wait(3_000)

    assert not worker.isRunning()
    deadline = time.monotonic() + 1.0
    while not native_finished.is_set() and time.monotonic() < deadline:
        app.processEvents()
    assert native_finished.is_set()
