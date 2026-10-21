"""Inert report readers must retire their native bridges on the GUI thread."""
from __future__ import annotations

import gc
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QObject, QThreadPool, Qt, Slot
from PySide6.QtWidgets import QApplication, QDialog, QListWidget, QPlainTextEdit, QVBoxLayout
from shiboken6 import delete, isValid

from angerona.gui import red_team_console as history


def delete_posted():
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def bare_history_dialog(tmp_path, pool):
    """Exercise only the real history UI, with no action/editor initialization."""
    dialog = history.RedTeamConsole.__new__(history.RedTeamConsole)
    QDialog.__init__(dialog)
    dialog._parent = SimpleNamespace(config=SimpleNamespace(data_dir=tmp_path))
    dialog._history_pool = pool
    dialog._hist_accept_results = True
    dialog._hist_listing = False
    dialog._hist_refresh_pending = False
    dialog._hist_reading = False
    dialog._hist_pending_name = None
    dialog._hist_active_name = None
    dialog._hist_list = QListWidget(dialog)
    dialog._hist_view = QPlainTextEdit(dialog)
    dialog.finished.connect(dialog._stop_history_loads)
    return dialog


@pytest.mark.parametrize("operation", ["list", "text"])
@pytest.mark.parametrize("read_error", [False, True])
def test_history_carrier_outlives_deleted_dialog_and_retires_on_gui(
    monkeypatch, tmp_path, operation, read_error,
):
    app = QApplication.instance()
    gui_thread = threading.get_ident()
    entered, release = threading.Event(), threading.Event()
    destroyed, work_threads, received, deleted_dialog_results = [], [], [], []
    pool = QThreadPool()
    pool.setMaxThreadCount(1)
    result = history.HistoryListing([]) if operation == "list" else "Inert local text"

    def read(*_args):
        work_threads.append(threading.get_ident())
        entered.set()
        assert release.wait(3), "fixture failed to release its inert reader"
        if read_error:
            raise OSError("inert local read failure")
        return result

    class Receiver(QObject):
        @Slot(str, str, object)
        def receive(self, kind, name, payload):
            received.append((kind, name, payload, threading.get_ident()))

    class ClosedDialog(QDialog):
        @Slot(str, str, object)
        def receive(self, *_args):
            deleted_dialog_results.append(True)

    monkeypatch.setattr(history, "list_history", read)
    monkeypatch.setattr(history, "load_verified_history_text", read)
    receiver = Receiver(app)
    dialog = ClosedDialog()
    worker = history._HistoryWorker(operation, tmp_path, "inert.txt")
    assert worker.signals.parent() is app
    assert worker.signals.thread() == app.thread()
    worker.signals.destroyed.connect(
        lambda: destroyed.append(threading.get_ident()),
        Qt.ConnectionType.DirectConnection,
    )
    worker.signals.finished.connect(receiver.receive)
    worker.signals.finished.connect(dialog.receive)
    try:
        pool.start(worker)
        del worker
        assert entered.wait(1)
        dialog.deleteLater()
        delete_posted()
        assert not isValid(dialog)
        gc.collect()
        assert destroyed == []
        release.set()
        assert pool.waitForDone(3000)
        assert destroyed == [], "pool completion destroyed the GUI-affinity bridge"
        app.processEvents()
        assert len(received) == 1
        expected = {"error": "inert local read failure"} if read_error else result
        assert received == [(operation, "inert.txt", expected, gui_thread)]
        assert deleted_dialog_results == []
        delete_posted()
        assert destroyed == [gui_thread]
        assert len(work_threads) == 1 and work_threads[0] != gui_thread
    finally:
        release.set()
        assert pool.waitForDone(3000)
        for obj in (dialog, receiver):
            if isValid(obj):
                obj.deleteLater()
        delete_posted()


@pytest.mark.parametrize("operation", ["list", "text"])
def test_history_rejected_start_retires_bridge_without_running_reader(
    monkeypatch, tmp_path, operation,
):
    gui_thread = threading.get_ident()
    destroyed, read_calls = [], []
    original_worker = history._HistoryWorker

    class RefusingPool:
        def start(self, _worker):
            raise RuntimeError("inert pool start failure")

    def observe_worker(*args):
        worker = original_worker(*args)
        worker.signals.destroyed.connect(
            lambda: destroyed.append(threading.get_ident()),
            Qt.ConnectionType.DirectConnection,
        )
        return worker

    monkeypatch.setattr(history, "_HistoryWorker", observe_worker)
    monkeypatch.setattr(history, "list_history", lambda *_args: read_calls.append(True))
    monkeypatch.setattr(history, "load_verified_history_text", lambda *_args: read_calls.append(True))
    dialog = bare_history_dialog(tmp_path, RefusingPool())
    try:
        if operation == "list":
            dialog._load_history()
            assert not dialog._hist_listing
            assert "Could not load report history" in dialog._hist_view.toPlainText()
        else:
            dialog._start_history_read("inert.txt")
            assert not dialog._hist_reading
            assert "Could not verify report history" in dialog._hist_view.toPlainText()
        assert "inert pool start failure" in dialog._hist_view.toPlainText()
        assert read_calls == []
        assert destroyed == []
        delete_posted()
        assert destroyed == [gui_thread]
    finally:
        dialog.deleteLater()
        delete_posted()


@pytest.mark.parametrize("operation", ["list", "text"])
def test_history_reader_completion_after_bridge_destruction_is_harmless(
    monkeypatch, tmp_path, operation,
):
    monkeypatch.setattr(history, "list_history", lambda *_args: history.HistoryListing([]))
    monkeypatch.setattr(history, "load_verified_history_text", lambda *_args: "Inert text")
    worker = history._HistoryWorker(operation, tmp_path, "inert.txt")
    # Simulate application-owned bridge destruction without destroying the
    # session application or touching any other test's native objects.
    delete(worker.signals)
    errors = []

    def complete():
        try:
            worker.run()
        except BaseException as exc:
            errors.append(type(exc).__name__)

    thread = threading.Thread(target=complete)
    thread.start()
    thread.join(3)
    assert not thread.is_alive()
    assert errors == []


def test_history_tab_delivers_inert_list_and_text_after_worker_retirement(monkeypatch, tmp_path):
    app = QApplication.instance()
    calls = []
    pool = QThreadPool()
    pool.setMaxThreadCount(1)

    def listing(root):
        calls.append(("list", root))
        return history.HistoryListing([("inert.txt", 0.0, "redteam_aar")])

    def text(root, name):
        calls.append(("text", root, name))
        return "Inert local history text"

    monkeypatch.setattr(history, "list_history", listing)
    monkeypatch.setattr(history, "load_verified_history_text", text)
    dialog = bare_history_dialog(tmp_path, pool)
    try:
        QVBoxLayout(dialog).addWidget(dialog._build_history_tab())
        deadline = time.monotonic() + 3
        while dialog._hist_view.toPlainText() != "Inert local history text" and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.005)
        assert dialog._hist_view.toPlainText() == "Inert local history text"
        assert not dialog._hist_listing and not dialog._hist_reading
        assert dialog._hist_list.count() == 1
        assert dialog._hist_list.item(0).text().startswith("✓ ")
        assert calls == [
            ("list", tmp_path / "aar_history"),
            ("text", tmp_path / "aar_history", "inert.txt"),
        ]
        assert pool.waitForDone(3000)
    finally:
        assert pool.waitForDone(3000)
        dialog.deleteLater()
        delete_posted()
