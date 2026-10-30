"""STOP revokes real Qt reveal ownership before runtime/window teardown."""
from __future__ import annotations

import os
import socket
import subprocess
import threading
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6 import QtWidgets
from PySide6.QtCore import QAbstractAnimation, QCoreApplication, QEvent, QRect, QThread, Qt
from PySide6.QtGui import QRegion
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox, QWidget
from shiboken6 import delete, isValid

from angerona.core import ollama_lifecycle
from angerona.gui import header_controls, main_window
from angerona.gui.header_controls import PanelRevealOverlay
from angerona.gui.main_window import MainWindow
from angerona.resilience import shutdown_token


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance()
    owns = application is None
    if owns:
        application = QApplication([])
    previous = application.quitOnLastWindowClosed()
    application.setQuitOnLastWindowClosed(False)
    try:
        yield application
    finally:
        if owns:
            application.shutdown()
            assert QApplication.instance() is None
        else:
            application.setQuitOnLastWindowClosed(previous)


@pytest.fixture
def scene(app, monkeypatch):
    """Real Qt components; all runtime authority and host work are forbidden."""
    calls, workers, worker_errors, dialogs, masks = [], [], [], [], []

    def forbidden(*_args, **_kwargs):
        raise AssertionError("This fixture grants no host, AI or STOP-token authority")

    monkeypatch.delenv("ANGERONA_REDUCE_MOTION", raising=False)
    monkeypatch.setattr(header_controls, "_windows_client_animations_enabled", lambda: True)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    for name in ("begin_ollama_shutdown", "shutdown_ollama"):
        monkeypatch.setattr(ollama_lifecycle, name, forbidden)
    for name in ("request_operator_stop", "request_standdown", "signal_external_watchdog_stop"):
        monkeypatch.setattr(shutdown_token, name, forbidden)
    monkeypatch.setattr(QtWidgets.QApplication, "quit", lambda *_args: calls.append("qt-quit"))
    monkeypatch.setattr(os, "_exit", lambda code: calls.append(("inert-exit", code)))

    owner = QWidget()
    owner.resize(640, 400)
    owner.show()
    overlay = PanelRevealOverlay(owner)
    overlay.enable_global_windows()
    owner._panel_reveal = overlay
    owner._termination_started = False
    owner._shutdown_prepare = lambda: calls.append("persist")
    owner._shutdown_callback = lambda: calls.append("inert-cleanup")
    owner._holographic_orb = SimpleNamespace(shutdown=lambda: None)
    owner.tray = SimpleNamespace(hide=lambda: None)
    owner.red_team_engine = owner.shark_engine = SimpleNamespace(stop_and_clean=lambda: None)
    owner._release_redteam_validation_lease = lambda: None

    def verify_revoked():
        assert QThread.currentThread() == app.thread() == owner.thread()
        assert calls[0] == "persist" and owner._termination_started
        assert overlay._shut_down and not overlay._global_windows
        assert overlay._target is None and overlay._frame is None
        assert not overlay._armed and not overlay._pending_windows
        if isValid(overlay):
            assert overlay._animation.state() == QAbstractAnimation.Stopped
            assert not overlay._reveal_start_timer.isActive()
            assert not overlay._pending_start_timer.isActive()
        for dialog, original in zip(dialogs, masks):
            assert isValid(dialog)
            assert dialog.mask() == original

    def create_thread(*, target, **kwargs):
        # The admission point executes on Qt before the actual inert worker.
        verify_revoked()
        calls.append("cleanup-thread-admitted")

        def run():
            try:
                target()
            except BaseException as error:
                worker_errors.append(error)

        worker = threading.Thread(target=run, **kwargs)
        workers.append(worker)
        return worker

    monkeypatch.setattr(main_window, "threading", SimpleNamespace(
        Event=threading.Event, Thread=create_thread))
    owner._close_flight_instructor = verify_revoked
    owner._close_spyware_guard_window = verify_revoked
    owner._close_github_tools_window = verify_revoked

    def close_owned():
        verify_revoked()
        calls.append("owned-window-close")
        for dialog in dialogs:
            assert dialog.close()
            assert not dialog.isVisible()

    owner._breach_view = SimpleNamespace(shutdown=close_owned)
    owner._terminate = lambda: MainWindow._terminate(owner)

    def destination():
        dialog = QDialog(owner)
        dialog.resize(320, 200)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        original = QRegion(QRect(4, 4, 260, 160))
        dialog.setMask(original)
        dialogs.append(dialog)
        masks.append(original)
        dialog.show()
        return dialog

    state = SimpleNamespace(owner=owner, overlay=overlay, calls=calls, dialogs=dialogs,
                            destination=destination, workers=workers, worker_errors=worker_errors)
    try:
        yield state
    finally:
        for worker in workers:
            if worker.ident is not None:
                worker.join(3)
            assert not worker.is_alive(), "Exact inert cleanup worker did not retire"
        assert worker_errors == []
        if isValid(overlay):
            overlay.shutdown()
        for dialog in dialogs:
            if isValid(dialog):
                setattr(dialog, "_angerona_close_bypass", True)
                dialog.close()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        if isValid(owner):
            delete(owner)
        app.processEvents()


def finish_opening(app, overlay):
    app.processEvents()
    overlay._animation.setCurrentTime(overlay._animation.duration())
    app.processEvents()
    assert overlay._target is None and overlay._mode == "idle"


@pytest.mark.parametrize("phase", ["opening", "open", "closing", "queued"])
def test_accepted_stop_retires_motion_before_threads_and_real_dialog_close(app, scene, phase):
    first = scene.destination()
    assert scene.overlay._target is first and not first.mask().isEmpty()
    if phase in ("open", "closing"):
        finish_opening(app, scene.overlay)
    if phase == "closing":
        first.close()
        assert first.isVisible() and scene.overlay._mode == "closing"
    elif phase == "queued":
        second = scene.destination()
        assert len(scene.overlay._pending_windows) == 1
        assert second.isVisible()

    MainWindow._terminate(scene.owner)

    for worker in scene.workers:
        worker.join(3)
        assert not worker.is_alive()
    assert scene.worker_errors == []
    assert scene.calls[0:2] == ["persist", "cleanup-thread-admitted"]
    assert scene.calls.count("inert-cleanup") == 1
    assert scene.calls[-2:] == ["qt-quit", ("inert-exit", 0)]
    assert not scene.overlay.reveal(scene.owner, lambda: pytest.fail("STOP re-admitted UI motion"))
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert all(not isValid(dialog) for dialog in scene.dialogs)


@pytest.mark.parametrize("rejection", ["no", "persist-error"])
def test_rejected_stop_preserves_real_reveal_and_reverse_close(app, scene, monkeypatch, rejection):
    dialog = scene.destination()
    if rejection == "no":
        monkeypatch.setattr(QMessageBox, "question", lambda *_args: QMessageBox.No)
        MainWindow._full_shutdown(scene.owner)
        assert scene.calls == []
    else:
        def fail_prepare():
            scene.calls.append("persist-failed")
            raise OSError("inert persistence failure")

        scene.owner._shutdown_prepare = fail_prepare
        monkeypatch.setattr(QMessageBox, "critical", lambda *_args: scene.calls.append("stop-error"))
        MainWindow._terminate(scene.owner)
        assert scene.calls == ["persist-failed", "stop-error"]
    assert not scene.owner._termination_started and not scene.workers
    assert not scene.overlay._shut_down and scene.overlay._global_windows
    finish_opening(app, scene.overlay)
    dialog.close()
    assert dialog.isVisible() and scene.overlay._mode == "closing"
    scene.overlay._animation.setCurrentTime(scene.overlay._animation.duration())
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert not isValid(dialog)


def test_deleted_native_overlay_does_not_hold_durable_stop(app, scene):
    scene.destination()
    finish_opening(app, scene.overlay)
    delete(scene.overlay)
    assert not isValid(scene.overlay)

    MainWindow._terminate(scene.owner)

    assert scene.owner._termination_started
    assert scene.calls[-2:] == ["qt-quit", ("inert-exit", 0)]
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert all(not isValid(dialog) for dialog in scene.dialogs)
