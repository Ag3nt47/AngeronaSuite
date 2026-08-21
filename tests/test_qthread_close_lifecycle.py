from __future__ import annotations

import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent, QThread, Qt, Signal
from PySide6.QtWidgets import QApplication, QDialog

from angerona.gui.thread_lifecycle import defer_close_until_threads


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

    def run(self) -> None:
        super().run()
        self.finished.emit({"verdict": "benign"})
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
    dialog.worker.start()
    assert ready.wait(timeout=1.0)

    started = time.perf_counter()
    assert dialog.close() is False
    assert time.perf_counter() - started < 0.2
    assert not dialog.isVisible()
    assert dialog._angerona_deferred_close is True
    assert dialog.worker.isRunning()

    release.set()
    assert dialog.worker.wait(1_000)
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
    dialog = AlertDetailDialog(
        Event(module="Lifecycle Test", message="benign", severity=Severity.INFO)
    )
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    dialog._analyze_worker = _PayloadWorker(ready, release, dialog)
    dialog.show()
    dialog._analyze_worker.start()
    assert ready.wait(timeout=1.0)

    assert dialog.close() is False
    assert dialog._angerona_deferred_close is True
    assert not dialog.isVisible()

    release.set()
    assert dialog._analyze_worker.wait(1_000)
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

    deadline = time.monotonic() + 1.0
    while not result_seen.is_set() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    assert result_seen.is_set()
    assert worker.isRunning()
    assert not native_finished.is_set()

    release.set()
    assert worker.wait(1_000)
    deadline = time.monotonic() + 1.0
    while not native_finished.is_set() and time.monotonic() < deadline:
        app.processEvents()
    assert native_finished.is_set()
