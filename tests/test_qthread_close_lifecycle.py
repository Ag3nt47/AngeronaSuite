from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent, QThread, Qt, Signal
from PySide6.QtWidgets import QApplication, QDialog

from angerona.gui import thread_lifecycle as lifecycle
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


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError])
def test_valid_unknown_worker_state_is_retained_until_wrapper_is_deleted(error_type):
    app = QApplication.instance() or QApplication([])

    class UnknownState(QThread):
        def isRunning(self):
            raise error_type("inert unavailable worker state")

    worker = UnknownState()
    try:
        assert app is not None and shiboken6.isValid(worker)
        assert lifecycle._is_running(worker)
    finally:
        shiboken6.delete(worker)
    assert not shiboken6.isValid(worker)
    assert not lifecycle._is_running(worker)


def test_inactive_and_deleted_worker_wrappers_do_not_defer_close():
    app = QApplication.instance() or QApplication([])
    worker = QThread()
    try:
        assert app is not None and shiboken6.isValid(worker)
        assert not lifecycle._is_running(None)
        assert not lifecycle._is_running(worker)
    finally:
        shiboken6.delete(worker)
    assert not lifecycle._is_running(worker)


def test_worker_deleted_during_failed_state_query_is_not_retained():
    app = QApplication.instance() or QApplication([])

    class DeletedDuringQuery(QThread):
        def isRunning(self):
            shiboken6.delete(self)
            raise RuntimeError("inert wrapper deleted during query")

    worker = DeletedDuringQuery()
    assert app is not None and shiboken6.isValid(worker)
    assert not lifecycle._is_running(worker)
    assert not shiboken6.isValid(worker)

@pytest.mark.parametrize("active_worker", [False, True])
def test_nonmodal_close_releases_retained_wrapper_after_native_destruction(active_worker):
    from angerona.gui import pages

    app = QApplication.instance() or QApplication([])
    ready, release = threading.Event(), threading.Event()
    dialog = _WorkerDialog(ready, release)
    worker = dialog.worker
    key = id(dialog)
    results = []
    dialog.finished.connect(results.append)
    try:
        pages._show_nonmodal(dialog)
        assert any(item is dialog for item in pages._OPEN_DIALOGS)
        if active_worker:
            worker.start()
            assert ready.wait(1.0)
        assert dialog.close() is (not active_worker)
        if active_worker:
            assert worker.isRunning() and key in lifecycle._DEFERRED_OWNERS
            assert shiboken6.isValid(dialog) and not dialog.isVisible()
        else:
            assert results == [QDialog.Rejected]
            assert all(item is not dialog for item in pages._OPEN_DIALOGS)
        release.set()
        assert worker.wait(3_000)
        deadline = time.monotonic() + 3.0
        while shiboken6.isValid(dialog) and time.monotonic() < deadline:
            app.processEvents()
            QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert not shiboken6.isValid(dialog)
        assert key not in lifecycle._DEFERRED_OWNERS
        assert all(item is not dialog for item in pages._OPEN_DIALOGS)
        # Retention cleanup must not invent an Accepted dialog choice. The
        # deferred hidden-close result-signal contract remains owner-specific.
        assert QDialog.Accepted not in results
    finally:
        release.set()
        if shiboken6.isValid(worker):
            assert worker.wait(3_000)
        if shiboken6.isValid(dialog):
            lifecycle._DEFERRED_OWNERS.pop(key, None)
            shiboken6.delete(dialog)
        pages._OPEN_DIALOGS[:] = [item for item in pages._OPEN_DIALOGS if item is not dialog]
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()


@pytest.mark.parametrize("veto", [False, True])
@pytest.mark.parametrize("completion_path", ["queued", "direct-before-queue", "queued-then-direct"])
def test_duplicate_deferred_callbacks_dispatch_one_real_close_without_show_or_choice(veto, completion_path):
    app = QApplication.instance() or QApplication([])
    ready, release = threading.Event(), threading.Event()

    class CountingDialog(QDialog):
        def __init__(self):
            super().__init__()
            self.worker = _BlockingWorker(ready, release, self)
            self.terminal_closes = 0
            self.shows = 0

        def showEvent(self, event):  # noqa: N802 - Qt virtual
            self.shows += 1
            super().showEvent(event)

        def closeEvent(self, event):  # noqa: N802 - Qt virtual
            if defer_close_until_threads(self, event, (self.worker,)):
                return
            self.terminal_closes += 1
            if veto:
                event.ignore()
            else:
                super().closeEvent(event)

    dialog = CountingDialog()
    worker, key, results = dialog.worker, id(dialog), []
    second_worker = second_release = None
    dialog.finished.connect(results.append)
    try:
        dialog.show()
        worker.start()
        assert ready.wait(1.0)
        assert dialog.close() is False
        assert key in lifecycle._DEFERRED_OWNERS and not dialog.isVisible()
        release.set()
        assert worker.wait(3_000)
        if completion_path != "queued":
            if completion_path == "queued-then-direct":
                lifecycle._retry_deferred_close(dialog)
                assert dialog.terminal_closes == 0  # Terminal timer is queued.
            # A real close before or after queuing terminal completion owns
            # disposition and must consume the pending generation exactly once.
            assert dialog.close() is (not veto)
            assert key not in lifecycle._DEFERRED_OWNERS
        # Competing native-finished/queued-retry deliveries must not queue a
        # second close after either direct or timer-owned terminal dispatch.
        lifecycle._retry_deferred_close(dialog)
        lifecycle._retry_deferred_close(dialog)
        assert dialog.terminal_closes == (0 if completion_path == "queued" else 1)
        deadline = time.monotonic() + 1.0
        while (key in lifecycle._DEFERRED_OWNERS or dialog.terminal_closes == 0) and time.monotonic() < deadline:
            app.processEvents()
        app.processEvents()
        assert dialog.terminal_closes == 1
        assert key not in lifecycle._DEFERRED_OWNERS
        assert shiboken6.isValid(dialog) and not dialog.isVisible()
        assert dialog.shows == 1  # No hidden dialog is automatically shown.
        assert QDialog.Accepted not in results
        if veto:
            assert results == []  # The real custom policy was not bypassed.
        assert dialog._angerona_close_wait_connected is False
        if completion_path != "queued":
            # Cached non-deleting windows can reopen with a fresh worker.
            # Old callbacks have settled; the new deferral must wire its own
            # completion and retire without manual retry assistance.
            second_ready, second_release = threading.Event(), threading.Event()
            second_worker = _BlockingWorker(second_ready, second_release, dialog)
            dialog.worker = second_worker
            dialog.show()
            second_worker.start()
            assert second_ready.wait(1.0)
            assert dialog.close() is False
            assert dialog._angerona_close_wait_connected is True
            assert key in lifecycle._DEFERRED_OWNERS
            second_release.set()
            assert second_worker.wait(3_000)
            deadline = time.monotonic() + 3.0
            while (key in lifecycle._DEFERRED_OWNERS or dialog.terminal_closes < 2) and time.monotonic() < deadline:
                app.processEvents()
            assert dialog.terminal_closes == 2
            assert key not in lifecycle._DEFERRED_OWNERS
            assert dialog._angerona_close_wait_connected is False
            assert shiboken6.isValid(dialog) and not dialog.isVisible()
            assert dialog.shows == 2  # Only explicit opening/reopening shows.
            assert QDialog.Accepted not in results
    finally:
        release.set()
        if second_release is not None:
            second_release.set()
        for owned_worker in (worker, second_worker):
            if owned_worker is not None and shiboken6.isValid(owned_worker):
                assert owned_worker.wait(3_000)
        if shiboken6.isValid(dialog):
            lifecycle._DEFERRED_OWNERS.pop(key, None)
            shiboken6.delete(dialog)
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()

@pytest.mark.parametrize("veto", [False, True])
def test_old_queued_close_keeps_new_live_deferral_owned(veto):
    app = QApplication.instance() or QApplication([])
    first_ready, first_release = threading.Event(), threading.Event()
    second_ready, second_release = threading.Event(), threading.Event()

    class ReusedDialog(QDialog):
        def __init__(self):
            super().__init__()
            self.worker = _BlockingWorker(first_ready, first_release, self)
            self.terminal_closes = 0

        def closeEvent(self, event):  # noqa: N802 - Qt virtual
            if defer_close_until_threads(self, event, (self.worker,)):
                return
            self.terminal_closes += 1
            if veto:
                event.ignore()
            else:
                super().closeEvent(event)

    dialog = ReusedDialog()
    first_worker, second_worker = dialog.worker, None
    key, results = id(dialog), []
    dialog.finished.connect(results.append)
    try:
        dialog.show()
        first_worker.start()
        assert first_ready.wait(1.0)
        assert dialog.close() is False
        first_release.set()
        assert first_worker.wait(3_000)
        # Queue the old generation's real terminal close without delivering it.
        lifecycle._retry_deferred_close(dialog)
        old_generation = getattr(dialog, "_angerona_close_deferral_generation", None)
        assert not dialog._angerona_deferred_close
        assert dialog.terminal_closes == 0
        # Reopen and start fresh native work before the old timer fires. The
        # old closeEvent must legitimately defer for it, not lose its root.
        second_worker = _BlockingWorker(second_ready, second_release, dialog)
        dialog.worker = second_worker
        dialog.show()
        second_worker.start()
        assert second_ready.wait(1.0)
        deadline = time.monotonic() + 1.0
        while not dialog._angerona_deferred_close and time.monotonic() < deadline:
            app.processEvents()
        assert second_worker.isRunning()
        assert dialog._angerona_deferred_close is True
        assert lifecycle._DEFERRED_OWNERS.get(key) is dialog
        assert getattr(dialog, "_angerona_close_deferral_generation", None) is not old_generation
        assert shiboken6.isValid(dialog) and not dialog.isVisible()
        assert dialog.terminal_closes == 0 and not results
        second_release.set()
        assert second_worker.wait(3_000)
        deadline = time.monotonic() + 3.0
        while (key in lifecycle._DEFERRED_OWNERS or dialog.terminal_closes == 0) and time.monotonic() < deadline:
            app.processEvents()
        assert dialog.terminal_closes == 1
        assert key not in lifecycle._DEFERRED_OWNERS
        assert shiboken6.isValid(dialog) and not dialog.isVisible()
        assert QDialog.Accepted not in results
        if veto:
            assert results == []
    finally:
        first_release.set()
        second_release.set()
        for owned_worker in (first_worker, second_worker):
            if owned_worker is not None and shiboken6.isValid(owned_worker):
                assert owned_worker.wait(3_000)
        if shiboken6.isValid(dialog):
            lifecycle._DEFERRED_OWNERS.pop(key, None)
            shiboken6.delete(dialog)
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()
