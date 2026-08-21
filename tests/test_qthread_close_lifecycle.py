from __future__ import annotations

import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent, QThread, Qt
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
