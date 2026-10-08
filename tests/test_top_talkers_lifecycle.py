"""Qt signal carriers must retire on the GUI thread after worker completion."""
from __future__ import annotations

import gc
import threading

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QThreadPool, Qt
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QPushButton
from shiboken6 import isValid

from angerona.gui import top_talkers


def delete_posted():
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def observe_carrier(monkeypatch, kind, destroyed):
    worker_name = "_TopTalkersWorker" if kind == "collect" else "_AskAiWorker"
    original = getattr(top_talkers, worker_name)

    def create(*args):
        worker = original(*args)
        worker.signals.destroyed.connect(
            lambda: destroyed.append(threading.get_ident()),
            Qt.ConnectionType.DirectConnection,
        )
        return worker

    monkeypatch.setattr(top_talkers, worker_name, create)


def launch(monkeypatch, window, kind, work):
    if kind == "collect":
        monkeypatch.setattr(top_talkers, "psutil", object())
        monkeypatch.setattr(top_talkers, "_collect_top_talkers", work)
        window.refresh()
        return
    monkeypatch.setattr(window, "_ask_ai", work)
    action = QDialog(window)
    button, status = QPushButton(action), QLabel(action)
    window._start_ai_request("inert", 4242, "example.invalid", action, button, status)


@pytest.mark.parametrize("kind", ["collect", "ai"])
def test_blocked_worker_outlives_deleted_dialog_but_carrier_dies_on_gui(monkeypatch, kind):
    app = QApplication.instance()
    main_thread = threading.get_ident()
    pool = QThreadPool()
    pool.setMaxThreadCount(1)
    entered, release = threading.Event(), threading.Event()
    destroyed, work_threads = [], []
    monkeypatch.setattr(top_talkers, "_top_talkers_pool", lambda: pool)
    monkeypatch.setattr(top_talkers, "psutil", None)
    observe_carrier(monkeypatch, kind, destroyed)

    def work(*_args):
        work_threads.append(threading.get_ident())
        entered.set()
        assert release.wait(3), "fixture failed to release blocked reader"
        return {"rows": [], "process_count": 0, "total_ext": 0} if kind == "collect" else "inert result"

    def no_dialog(*_args):
        pytest.fail("late result targeted a closed dialog")

    monkeypatch.setattr(top_talkers.QMessageBox, "information", no_dialog)
    window = top_talkers.TopTalkersDialog()
    try:
        launch(monkeypatch, window, kind, work)
        assert entered.wait(1)
        window.close()
        delete_posted()
        assert not isValid(window)
        assert destroyed == [], "carrier died before its reader completed"
        gc.collect()
        release.set()
        assert pool.waitForDone(3000)
        # Worker completion may only post GUI disposal; it must never directly
        # dispose the carrier on the native pool thread.
        assert destroyed == []
        delete_posted()
        app.processEvents()
        assert destroyed == [main_thread]
        assert len(work_threads) == 1 and work_threads[0] != main_thread
    finally:
        release.set()
        assert pool.waitForDone(3000)
        if isValid(window):
            window.close()
        delete_posted()


@pytest.mark.parametrize("kind", ["collect", "ai"])
def test_failed_worker_start_retires_carrier_on_gui(monkeypatch, kind):
    destroyed = []
    main_thread = threading.get_ident()

    class RefusingPool:
        def start(self, *_args):
            raise RuntimeError("inert pool start failure")

    monkeypatch.setattr(top_talkers, "_top_talkers_pool", RefusingPool)
    monkeypatch.setattr(top_talkers, "psutil", None)
    observe_carrier(monkeypatch, kind, destroyed)
    window = top_talkers.TopTalkersDialog()
    try:
        launch(monkeypatch, window, kind, lambda *_args: pytest.fail("rejected worker ran"))
        assert not window._refresh_in_flight
        assert not window._ai_in_flight
        assert destroyed == []
        delete_posted()
        assert destroyed == [main_thread]
    finally:
        window.close()
        delete_posted()
