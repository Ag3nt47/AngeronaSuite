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
from PySide6.QtWidgets import QApplication, QDialog, QWidget
from shiboken6 import delete, isValid

from angerona.core import ollama_lifecycle, process_exit
from angerona.gui import action_worker, breach_display, header_controls, live_debug_panel
from angerona.gui.header_controls import PanelRevealOverlay
from angerona.gui.main_window import MainWindow
from angerona.gui.stop_controls import StopControlsDialog
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
    # This scene tests Qt motion/teardown ordering. Retain the real coordinator
    # and its actual diagnostic thread, with a bounded memory sink so unrelated
    # filesystem contention cannot turn this UI fixture into a disk-speed test.
    from angerona.gui import shutdown_retirement
    actual_retirement = shutdown_retirement.ShutdownRetirement
    diagnostics = []

    def diagnostic_writer(_root, payload):
        if len(diagnostics) >= 8:
            raise AssertionError("Inert diagnostic projection exceeded its fixture bound")
        diagnostics.append(payload)

    def retirement_factory(owner, **options):
        assert "diagnostic_writer" not in options
        return actual_retirement(owner, diagnostic_writer=diagnostic_writer, **options)

    monkeypatch.setattr(shutdown_retirement, "ShutdownRetirement", retirement_factory)
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
    owner._termination_preparing = False
    owner._operator_stop_locked = False
    owner._stop_confirmation_dialog = None
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
                 "_operator_stop_progress", "_operator_stop_finish", "_poll_stop_preparation",
                 "_complete_prepared_stop", "_full_shutdown", "_set_operator_stop_locked",
                 "_confirm_operator_stop", "_operator_stop_exit_after_retirement",
                 "_poll_stop_finalization"):
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
                            release_critical=release_critical, diagnostics=diagnostics)
    try:
        yield state
    finally:
        release_critical.set()
        preparation = getattr(owner, "_operator_stop_preparation", None)
        if preparation is not None:
            preparation.thread.join(3)
            assert not preparation.thread.is_alive(), "Exact inert preparation did not retire"
            if owner._termination_preparing:
                owner._poll_stop_preparation()
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

    wait_for(app, scene.critical_entered.is_set)
    assert scene.calls[0] == "persist"
    assert scene.calls.index("views-fenced") < scene.calls.index("critical-cleanup")
    assert "inert-cleanup" not in scene.calls  # Stores wait for the critical owner.
    assert not scene.owner._operator_stop_retirement._done
    scene.release_critical.set()
    wait_for(app, lambda: scene.owner._operator_stop_retirement._done)
    result = scene.owner._operator_stop_result
    assert result["state"] == "retired" and result["forced"] is False, json.dumps(result, sort_keys=True)
    assert result["diagnostic_persisted"] is True
    assert scene.diagnostics[-1]["state"] == result["state"]
    assert not result["pending_workers"] and not result["pending_custody"]
    assert scene.calls.count("inert-cleanup") == 1
    assert scene.calls[-2:] == ["qt-quit", ("inert-exit", 0)]
    assert not scene.overlay.reveal(scene.owner, lambda: pytest.fail("STOP re-admitted UI motion"))
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert all(not isValid(dialog) for dialog in scene.dialogs)


@pytest.mark.parametrize("rejection", ["no", "persist-error"])
def test_rejected_stop_preserves_real_reveal_and_reverse_close(app, scene, rejection):
    dialog = scene.destination()
    if rejection == "no":
        MainWindow._full_shutdown(scene.owner)
        scene.owner._stop_confirmation_dialog.cancel_button.click()
        assert scene.calls == []
    else:
        def fail_prepare():
            scene.calls.append("persist-failed")
            raise OSError("inert persistence failure")

        scene.owner._shutdown_prepare = fail_prepare
        MainWindow._terminate(scene.owner)
        wait_for(app, lambda: not scene.owner._termination_preparing)
        assert scene.calls == ["persist-failed"]
        assert "preparation failed" in scene.owner._stop_confirmation_dialog.message_label.text()
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

    wait_for(app, lambda: scene.owner._termination_started)
    wait_for(app, scene.critical_entered.is_set)
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
    owner._reveal_window_from = MethodType(MainWindow._reveal_window_from, owner)
    stop = header_controls.HeaderActionButton("STOP", "stop", "Stop Angerona", "Inert STOP fixture")
    stop.setParent(owner)
    owner._stop_btn = stop
    stop.clicked.connect(lambda _checked=False: MainWindow._run_header_action(
        owner, stop, owner._full_shutdown, "#ef4444"))
    first = scene.destination()
    assert overlay._target is first and not first.mask().isEmpty()
    normal = QWidget(owner)
    ordinary_calls = []
    MainWindow._run_header_action(owner, normal, lambda: ordinary_calls.append(True), "#38bdf8")
    assert ordinary_calls == [True]

    shown = []
    class PromptShowProbe(QObject):
        def eventFilter(self, watched, event):
            if (isinstance(watched, StopControlsDialog) and watched.parentWidget() is owner
                    and watched.objectName() == "OperatorStopConfirmation"
                    and event.type() == QEvent.Show):
                shown.append((watched, watched.property("_angerona_no_reveal"),
                              watched.property("_angerona_security_prompt"), watched.mask().isEmpty()))
            return False

    probe = PromptShowProbe(owner)
    app.installEventFilter(probe)
    try:
        stop.click()  # Returns immediately; there is no nested modal event loop.
        prompt = owner._stop_confirmation_dialog
        assert isinstance(prompt, StopControlsDialog) and prompt.isVisible()
        assert prompt.windowTitle() == "Stop Angerona"
        assert prompt.windowModality() == Qt.NonModal
        assert QApplication.activeModalWidget() is None
        assert "Stop protection, unload Angerona's local AI models" in prompt.detail_label.text()
        assert prompt.mask().isEmpty() and prompt not in overlay._captured_windows
        assert shown == [(prompt, True, True, True)]
        assert scene.calls == [] and not owner._termination_started
        MainWindow._full_shutdown(owner)
        assert owner._stop_confirmation_dialog is prompt
        assert len([box for box in owner.findChildren(StopControlsDialog) if box.isVisible()]) == 1
        if answer == "escape":
            QTest.keyClick(prompt, Qt.Key_Escape)
        elif answer == "yes":
            prompt.confirm_stop.setChecked(True)
            prompt.stop_button.click()
        else:
            prompt.cancel_button.click()
        if answer == "yes":
            wait_for(app, scene.critical_entered.is_set)
            assert scene.calls.count("persist") == 1
            assert scene.calls.index("persist") < scene.calls.index("views-fenced")
            assert scene.calls.index("views-fenced") < scene.calls.index("critical-cleanup")
            scene.release_critical.set()
            wait_for(app, lambda: owner._operator_stop_retirement._done)
            assert owner._operator_stop_result["state"] == "retired"
            assert scene.calls[-2:] == ["qt-quit", ("inert-exit", 0)]
        else:
            assert not prompt.isVisible()
            assert scene.calls == [] and not owner._termination_started
            assert not hasattr(owner, "_operator_stop_retirement")
            assert not overlay._shut_down and overlay._global_windows
    finally:
        app.removeEventFilter(probe)
        for child in (probe, stop, normal):
            if isValid(child):
                child.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()
