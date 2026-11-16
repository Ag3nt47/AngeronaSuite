"""Real Qt STOP controls: modeless consent, session lock and thread retirement."""
from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from types import MethodType

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QPushButton, QWidget
from shiboken6 import delete, isValid

from angerona.gui.main_window import MainWindow
from angerona.gui.stop_controls import StopControlsDialog, StopPreparation
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


def wait_for(app, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.005)
    assert predicate()


@pytest.fixture
def control(app, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("STOP UI fixture grants no host or shutdown authority")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    for name in ("request_operator_stop", "request_standdown", "signal_external_watchdog_stop"):
        monkeypatch.setattr(shutdown_token, name, forbidden)
    owner = QWidget()
    owner._operator_stop_locked = False
    owner._termination_started = False
    owner._termination_preparing = False
    owner._shutdown_prepare = lambda: None
    owner._stop_confirmation_dialog = None
    owner._prepared_calls = []
    owner._complete_prepared_stop = lambda: owner._prepared_calls.append("accepted")
    for name in ("_quit", "_full_shutdown", "_set_operator_stop_locked", "_confirm_operator_stop",
                 "_terminate", "_poll_stop_preparation"):
        setattr(owner, name, MethodType(getattr(MainWindow, name), owner))
    owner.resize(420, 200)
    unrelated = QPushButton("Other controls", owner)
    unrelated.resize(150, 35)
    owner.show()
    try:
        yield owner, unrelated
    finally:
        preparation = getattr(owner, "_operator_stop_preparation", None)
        if preparation is not None:
            preparation.thread.join(3)
            assert not preparation.thread.is_alive(), "Exact inert authorization worker did not retire"
        finalization = getattr(owner, "_operator_stop_finalize_job", None)
        if finalization is not None:
            finalization.thread.join(3)
            assert not finalization.thread.is_alive(), "Exact finalization worker did not retire"
        final_timer = getattr(owner, "_operator_stop_finalize_timer", None)
        if final_timer is not None:
            final_timer.stop()
        timer = getattr(owner, "_operator_stop_prepare_timer", None)
        if timer is not None:
            timer.stop()
        question = owner._stop_confirmation_dialog
        if question is not None and isValid(question):
            question._busy = False
            question.close()
        if isValid(owner):
            delete(owner)
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()


def test_header_and_tray_reuse_modeless_question_without_blocking_other_controls(app, control):
    owner, unrelated = control
    other_calls = []
    unrelated.clicked.connect(lambda: other_calls.append(True))
    owner._full_shutdown()
    question = owner._stop_confirmation_dialog
    assert isinstance(question, StopControlsDialog) and question.isVisible()
    assert question.windowModality() == Qt.NonModal
    assert QApplication.activeModalWidget() is None
    assert question.property("_angerona_no_reveal") is True
    assert question.property("_angerona_security_prompt") is True
    assert question.mask().isEmpty()
    assert "Unrelated Python" in question.detail_label.text()
    assert "same Windows user" in question.scope_label.text()
    assert "Unlocked" in question.state_label.text()
    assert not question.stop_button.isEnabled()
    unrelated.click()
    assert other_calls == [True]
    owner._quit()
    owner._full_shutdown()
    assert owner._stop_confirmation_dialog is question
    assert owner.findChildren(StopControlsDialog) == [question]
    assert owner._prepared_calls == []


@pytest.mark.parametrize("dismiss", ["cancel", "escape", "close"])
def test_dismiss_never_stops_and_reopening_requires_fresh_consent(app, control, dismiss):
    owner, _ = control
    owner._full_shutdown()
    question = owner._stop_confirmation_dialog
    question.confirm_stop.setChecked(True)
    if dismiss == "cancel":
        question.cancel_button.click()
    elif dismiss == "escape":
        QTest.keyClick(question, Qt.Key_Escape)
    else:
        question.close()
    assert not question.isVisible()
    assert owner._prepared_calls == [] and not owner._termination_preparing
    owner._quit()
    assert owner._stop_confirmation_dialog is question and question.isVisible()
    assert not question.confirm_stop.isChecked()
    assert not question.stop_button.isEnabled()


def test_lock_then_confirmed_unlock_never_implicitly_stops_and_stale_stop_is_rejected(app, control):
    owner, _ = control
    owner._full_shutdown()
    question = owner._stop_confirmation_dialog
    question.confirm_stop.setChecked(True)
    question.lock_button.click()
    assert owner._operator_stop_locked and "Locked" in question.state_label.text()
    assert not question.stop_button.isEnabled() and not question.confirm_stop.isChecked()
    question.unlock_button.click()  # Disabled: affirmative unlock was not given.
    assert owner._operator_stop_locked
    question.confirm_unlock.setChecked(True)
    question.unlock_button.click()
    assert not owner._operator_stop_locked
    assert not question.confirm_stop.isChecked() and not question.stop_button.isEnabled()
    assert owner._prepared_calls == []
    question.confirm_stop.setChecked(True)
    # Simulate a stale queued stop signal racing an owner's newer lock state.
    owner._operator_stop_locked = True
    question.stop_requested.emit()
    assert not owner._termination_preparing and owner._prepared_calls == []
    owner._set_operator_stop_locked(False)
    question.confirm_stop.setChecked(True)
    question.stop_button.click()
    wait_for(app, lambda: owner._prepared_calls == ["accepted"])


def test_authenticated_stop_bypasses_only_the_ui_lock(app, control):
    owner, _ = control
    owner._full_shutdown()
    owner._stop_confirmation_dialog.lock_button.click()
    assert owner._operator_stop_locked
    owner._terminate()  # Exact authenticated peer path never consults UI consent.
    wait_for(app, lambda: owner._prepared_calls == ["accepted"])
    assert owner._operator_stop_locked


def test_preparation_is_one_responsive_worker_and_success_waits_for_actual_thread_exit(app, control, monkeypatch):
    owner, unrelated = control
    result_ready, release_thread = threading.Event(), threading.Event()
    original = StopPreparation._run

    def result_before_exit(preparation):
        original(preparation)
        result_ready.set()
        assert release_thread.wait(5), "Fixture did not release its exact preparation thread"

    monkeypatch.setattr(StopPreparation, "_run", result_before_exit)
    calls = []
    owner._shutdown_prepare = lambda: calls.append("prepare")
    owner._full_shutdown()
    question = owner._stop_confirmation_dialog
    question.confirm_stop.setChecked(True)
    question.stop_button.click()
    try:
        assert result_ready.wait(1)
        worker = owner._operator_stop_preparation
        assert worker.succeeded and worker.thread.is_alive()
        owner._terminate()
        owner._quit()
        question.close()
        question.reject()
        assert question.isVisible() and not question.cancel_button.isEnabled()
        unrelated.clicked.connect(lambda: calls.append("other-control"))
        unrelated.click()
        pulses = []
        timer = QTimer(owner)
        timer.setInterval(5)
        timer.timeout.connect(lambda: pulses.append(True))
        timer.start()
        wait_for(app, lambda: len(pulses) >= 3)
        timer.stop()
        assert owner._operator_stop_preparation is worker
        assert calls == ["prepare", "other-control"]
        assert owner._prepared_calls == [] and owner._termination_preparing
    finally:
        release_thread.set()
    wait_for(app, lambda: owner._prepared_calls == ["accepted"])
    assert worker.retired() and not owner._termination_preparing


def test_authorization_failure_keeps_controls_open_and_dialog_can_retry(app, control):
    owner, unrelated = control
    class AdminApprovalRequired(RuntimeError):
        pass

    def held():
        raise AdminApprovalRequired("inert protected authority unavailable")

    owner._shutdown_prepare = held
    owner._full_shutdown()
    question = owner._stop_confirmation_dialog
    question.confirm_stop.setChecked(True)
    question.stop_button.click()
    wait_for(app, lambda: not owner._termination_preparing)
    assert not owner._termination_started and owner._prepared_calls == []
    assert owner.isEnabled() and unrelated.isEnabled()
    assert "authorization is held" in question.message_label.text()
    assert question.isVisible() and question.cancel_button.isEnabled()
    assert not question.confirm_stop.isChecked()
    question.lock_button.click()
    assert owner._operator_stop_locked
    question.confirm_unlock.setChecked(True)
    question.unlock_button.click()
    assert not owner._operator_stop_locked and owner._prepared_calls == []
    owner._shutdown_prepare = lambda: None
    question.confirm_stop.setChecked(True)
    question.stop_button.click()
    wait_for(app, lambda: owner._prepared_calls == ["accepted"])


@pytest.mark.parametrize("receipt_error", [False, True])
def test_source_receipt_finalization_waits_for_actual_worker_exit(app, control, monkeypatch, receipt_error):
    owner, _ = control
    result_ready, release = threading.Event(), threading.Event()
    original = StopPreparation._run
    exits = []
    def delayed_thread_exit(preparation):
        original(preparation)
        result_ready.set()
        assert release.wait(5)
    monkeypatch.setattr(StopPreparation, "_run", delayed_thread_exit)
    def finalize(result):
        assert result["state"] == "retired" and not result["pending_workers"]
        if receipt_error:
            raise OSError("inert epoch receipt unavailable")
    owner._shutdown_retired_callback = finalize
    owner._poll_stop_finalization = MethodType(MainWindow._poll_stop_finalization, owner)
    owner._operator_stop_exit_after_retirement = lambda result: exits.append(result)
    result = dict(state="retired", forced=False, pending_workers=[], pending_custody=[])
    MainWindow._operator_stop_finish(owner, result)
    try:
        assert result_ready.wait(1)
        assert owner._operator_stop_finalize_job.thread.is_alive()
        owner._poll_stop_finalization()
        assert exits == []
    finally:
        release.set()
    wait_for(app, lambda: len(exits) == 1)
    assert exits[0]["retirement_callback_completed"] is (not receipt_error)
    if receipt_error:
        assert exits[0]["retirement_callback_error_type"] == "OSError"
    assert owner._operator_stop_finalize_job.retired()


def test_pending_finalization_is_explicit_forced_incomplete(app, control):
    owner, _ = control
    entered, release = threading.Event(), threading.Event()
    exits = []
    def finalize(_result):
        entered.set()
        assert release.wait(5)
    owner._shutdown_retired_callback = finalize
    owner._poll_stop_finalization = MethodType(MainWindow._poll_stop_finalization, owner)
    owner._operator_stop_exit_after_retirement = lambda result: exits.append(result)
    result = dict(state="retired", forced=False, pending_workers=[], pending_custody=[])
    MainWindow._operator_stop_finish(owner, result)
    try:
        assert entered.wait(1)
        owner._operator_stop_finalize_deadline = 0.0
        owner._poll_stop_finalization()
        assert len(exits) == 1
        assert exits[0]["state"] == "forced-incomplete" and exits[0]["forced"] is True
        assert exits[0]["pending_workers"] == ["source-stop-finalization"]
        assert exits[0]["retirement_callback_completed"] is False
    finally:
        release.set()
