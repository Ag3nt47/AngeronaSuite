"""STOP revokes real Qt reveal ownership before runtime/window teardown."""
from __future__ import annotations

import os
import json
import socket
import subprocess
import threading
import time
from types import MethodType, SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6 import QtWidgets
from PySide6.QtCore import QAbstractAnimation, QCoreApplication, QEvent, QObject, QRect, QThread, QTimer, Qt
from PySide6.QtGui import QRegion
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox, QWidget
from shiboken6 import delete, isValid

from angerona.core import ollama_lifecycle, process_exit
from angerona.gui import action_worker, breach_display, header_controls, live_debug_panel
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
def scene(app, monkeypatch, tmp_path):
    """Real Qt components; all runtime authority and host work are forbidden."""
    calls, dialogs, masks = [], [], []
    critical_entered, release_critical, motion_verified = (threading.Event() for _ in range(3))
    # Exercise the real process-wide fences, restoring only their fixture scope.
    assert not action_worker.active_finite_actions()
    assert not breach_display.active_report_exports()
    assert not live_debug_panel.active_live_debug_streams()
    monkeypatch.setattr(action_worker, "_CLOSING", action_worker._CLOSING)
    monkeypatch.setattr(breach_display, "_REPORT_EXPORT_ADMISSION", breach_display._REPORT_EXPORT_ADMISSION)
    monkeypatch.setattr(live_debug_panel, "_STREAM_ADMISSION", live_debug_panel._STREAM_ADMISSION)

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
    monkeypatch.setattr(process_exit, "exit_after_operator_shutdown",
                        lambda: calls.append(("inert-exit", 0)))

    owner = QWidget()
    owner.resize(640, 400)
    owner.show()
    overlay = PanelRevealOverlay(owner)
    overlay.enable_global_windows()
    owner._panel_reveal = overlay
    owner._termination_started = False
    owner._shutdown_prepare = lambda: calls.append("persist")
    owner._shutdown_callback = lambda: calls.append("inert-cleanup")
    owner.config = SimpleNamespace(data_dir=tmp_path)
    owner.console = SimpleNamespace(_append=lambda message: None)
    owner._simulation_session = None
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

    def hold_owned_views():
        MainWindow._hold_shutdown_views(owner)
        verify_revoked()
        calls.append("views-fenced")
        motion_verified.set()

    owner._hold_shutdown_views = hold_owned_views
    for name in ("_shutdown_view_owners", "_retained_shutdown_workers",
                 "_retained_shutdown_custody", "_operator_stop_cleanup",
                 "_operator_stop_progress", "_operator_stop_finish"):
        setattr(owner, name, MethodType(getattr(MainWindow, name), owner))

    def critical_cleanup():
        assert motion_verified.is_set()
        calls.append("critical-cleanup")
        critical_entered.set()
        assert release_critical.wait(5), "Test did not release its exact critical owner"

    owner._shutdown_critical = critical_cleanup
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
                            destination=destination, critical_entered=critical_entered,
                            release_critical=release_critical)
    try:
        yield state
    finally:
        release_critical.set()
        retirement = getattr(owner, "_operator_stop_retirement", None)
        if retirement is not None:
            wait_for(app, lambda: retirement._done)
            exact_workers = [row.worker for row in retirement._retained.values()]
            exact_workers.append(retirement._diagnostic_thread)
            for worker in exact_workers:
                if worker is not None and worker.ident is not None:
                    worker.join(3)
                    assert not worker.is_alive(), "Exact inert cleanup worker did not retire"
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


def wait_for(app, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.005)
    assert predicate()


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

    assert scene.critical_entered.wait(1)
    assert scene.calls[0] == "persist"
    assert scene.calls.index("views-fenced") < scene.calls.index("critical-cleanup")
    assert "inert-cleanup" not in scene.calls  # Stores wait for the critical owner.
    assert not scene.owner._operator_stop_retirement._done
    scene.release_critical.set()
    wait_for(app, lambda: scene.owner._operator_stop_retirement._done)
    result = scene.owner._operator_stop_result
    assert result["state"] == "retired" and result["forced"] is False, json.dumps(result, sort_keys=True)
    assert result["diagnostic_persisted"] is True
    assert not result["pending_workers"] and not result["pending_custody"]
    assert scene.calls.count("inert-cleanup") == 1
    assert scene.calls[-2:] == ["qt-quit", ("inert-exit", 0)]
    assert not scene.overlay.reveal(scene.owner, lambda: pytest.fail("STOP re-admitted UI motion"))
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert all(not isValid(dialog) for dialog in scene.dialogs)


@pytest.mark.parametrize("rejection", ["no", "persist-error"])
def test_rejected_stop_preserves_real_reveal_and_reverse_close(app, scene, monkeypatch, rejection):
    dialog = scene.destination()
    if rejection == "no":
        monkeypatch.setattr(QMessageBox, "exec", lambda *_args: QMessageBox.No)
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
    assert not scene.owner._termination_started
    assert not hasattr(scene.owner, "_operator_stop_retirement")
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
    assert scene.critical_entered.wait(1)
    scene.release_critical.set()
    wait_for(app, lambda: scene.owner._operator_stop_retirement._done)
    assert scene.owner._operator_stop_result["state"] == "retired"
    assert scene.calls[-2:] == ["qt-quit", ("inert-exit", 0)]
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert all(not isValid(dialog) for dialog in scene.dialogs)


@pytest.mark.parametrize("answer", ["no", "escape", "yes"])
def test_busy_reveal_cannot_drop_or_mask_the_real_stop_confirmation(app, scene, answer):
    from PySide6.QtTest import QTest

    owner, overlay = scene.owner, scene.overlay
    owner._full_shutdown = MethodType(MainWindow._full_shutdown, owner)
    owner._reveal_window_from = MethodType(MainWindow._reveal_window_from, owner)
    stop = header_controls.HeaderActionButton("STOP", "stop", "Stop Angerona", "Inert STOP fixture")
    stop.setParent(owner)
    owner._stop_btn = stop
    stop.clicked.connect(lambda _checked=False: MainWindow._run_header_action(
        owner, stop, owner._full_shutdown, "#ef4444"))
    first = scene.destination()
    assert overlay._target is first and not first.mask().isEmpty()
    # Busy optional motion cannot consume either an ordinary action or STOP.
    normal = QWidget(owner)
    ordinary_calls = []
    MainWindow._run_header_action(owner, normal, lambda: ordinary_calls.append(True), "#38bdf8")
    assert ordinary_calls == [True]

    shown, checked, failures = [], [], []

    class PromptShowProbe(QObject):
        def eventFilter(self, watched, event):
            if (isinstance(watched, QMessageBox) and watched.parentWidget() is owner
                    and watched.objectName() == "OperatorStopConfirmation"
                    and event.type() == QEvent.Show):
                shown.append((watched, watched.property("_angerona_no_reveal"),
                              watched.property("_angerona_security_prompt"), watched.mask().isEmpty()))
            return False

    probe = PromptShowProbe(owner)
    app.installEventFilter(probe)
    timer, deadline = QTimer(owner), QTimer(owner)
    timer.setSingleShot(True)
    deadline.setSingleShot(True)

    def cancel_if_blocked():
        failures.append(AssertionError("Inert STOP question did not finish"))
        prompt = getattr(owner, "_stop_confirmation_dialog", None)
        if prompt is not None and isValid(prompt):
            prompt.reject()

    def inspect_and_answer():
        prompt = getattr(owner, "_stop_confirmation_dialog", None)
        try:
            assert isinstance(prompt, QMessageBox) and prompt.isVisible()
            assert prompt.windowTitle() == "Stop Angerona"
            assert prompt.windowModality() == Qt.ApplicationModal
            assert QApplication.activeModalWidget() is prompt
            assert prompt.standardButtons() == QMessageBox.Yes | QMessageBox.No
            assert prompt.defaultButton() is prompt.button(QMessageBox.No)
            assert prompt.escapeButton() is prompt.button(QMessageBox.No)
            assert prompt.textFormat() == Qt.PlainText
            assert "Stop protection, unload Angerona's local AI models" in prompt.text()
            assert "Continue?" in prompt.text()
            assert prompt.mask().isEmpty() and prompt not in overlay._captured_windows
            assert shown == [(prompt, True, True, True)]
            assert scene.calls == [] and not owner._termination_started
            # Reentrant delivery raises this exact question instead of nesting one.
            MainWindow._full_shutdown(owner)
            assert owner._stop_confirmation_dialog is prompt
            assert len([box for box in owner.findChildren(QMessageBox) if box.isVisible()]) == 1
            checked.append(True)
            if answer == "escape":
                QTest.keyClick(prompt, Qt.Key_Escape)
            else:
                prompt.button(QMessageBox.Yes if answer == "yes" else QMessageBox.No).click()
        except BaseException as error:
            failures.append(error)
            if prompt is not None and isValid(prompt):
                prompt.reject()

    timer.timeout.connect(inspect_and_answer)
    deadline.timeout.connect(cancel_if_blocked)
    timer.start(0)
    deadline.start(5000)
    try:
        stop.click()
        assert not failures, repr(failures)
        assert checked == [True] and owner._stop_confirmation_dialog is None
        if answer == "yes":
            assert scene.critical_entered.wait(1)
            assert scene.calls.count("persist") == 1
            assert scene.calls.index("persist") < scene.calls.index("views-fenced")
            assert scene.calls.index("views-fenced") < scene.calls.index("critical-cleanup")
            scene.release_critical.set()
            wait_for(app, lambda: owner._operator_stop_retirement._done)
            assert owner._operator_stop_result["state"] == "retired"
            assert scene.calls[-2:] == ["qt-quit", ("inert-exit", 0)]
        else:
            assert scene.calls == [] and not owner._termination_started
            assert not hasattr(owner, "_operator_stop_retirement")
            assert not overlay._shut_down and overlay._global_windows
    finally:
        timer.stop()
        deadline.stop()
        app.removeEventFilter(probe)
        for child in (timer, deadline, probe, stop, normal):
            if isValid(child):
                child.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()
