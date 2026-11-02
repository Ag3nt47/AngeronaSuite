"""Inert owner/continuation checks; no real MainWindow, provider or drill launch."""
from __future__ import annotations

import socket
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QWidget
from shiboken6 import isValid

from angerona.gui import main_window, pages, red_team_console
from angerona.gui.main_window import MainWindow
from angerona.gui.pages import AARDialog, _show_nonmodal


@pytest.fixture(autouse=True)
def no_host_dispatch(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Window integration attempted host or network work")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def settle_until(predicate):
    deadline = time.monotonic() + 3
    while not predicate() and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(.005)
    assert predicate()


class Owner(QWidget):
    _admit_aar_work = MainWindow._admit_aar_work
    _release_aar_work = MainWindow._release_aar_work
    _show_aar_dialog = MainWindow._show_aar_dialog
    _show_settings = MainWindow._show_settings
    _settings_finished = MainWindow._settings_finished
    _settings_retired = MainWindow._settings_retired

    def __init__(self, directory):
        super().__init__()
        self.config = SimpleNamespace(data_dir=directory)
        self.manager = SimpleNamespace(modules={})
        self.shark_engine = SimpleNamespace(run_id="shark-test", is_running=False)
        self.red_team_engine = SimpleNamespace(run_id="redteam-test", is_running=False)
        self.process_baseline = None
        self.actions = []
        self._update_controller = SimpleNamespace(preferences_changed=lambda: self.actions.append("updates"))
        self.console = SimpleNamespace(_append=lambda text: self.actions.append(text))

    def _qss(self): return ""
    def apply_theme(self, *_args): pass
    def _apply_voice_settings_live(self): self.actions.append("voice")
    def _apply_aria_control_settings_live(self): self.actions.append("aria")
    def _apply_dashboard_mode_live(self): self.actions.append("dashboard")


@pytest.mark.parametrize("kind", ["fix", "apply", "refresh"])
def test_aar_close_retains_exact_worker_until_result_and_no_duplicate_job(tmp_path, monkeypatch, kind):
    owner = Owner(tmp_path)
    entered, release = threading.Event(), threading.Event()
    work_threads, finished = [], []
    gui_thread = threading.get_ident()

    def work(*_args):
        work_threads.append(threading.get_ident())
        entered.set()
        assert release.wait(3)
        if kind == "refresh":
            return "Retained authenticated fixture", {}, ("shark-test", "", "", 0), False
        return "Retained inert action result"

    monkeypatch.setattr(pages, "_read_aar_review", work)
    dialog = AARDialog(tmp_path, owner, on_attempt_fix=work,
                       report_binding={"run_id": "shark-test"})
    _show_nonmodal(dialog)
    dialog.finished.connect(lambda _result: finished.append(not worker.is_alive()))
    try:
        if kind == "fix":
            dialog._attempt_fix()
        elif kind == "apply":
            assert dialog._start_work("apply", work)
        else:
            dialog.refresh()
        worker = dialog._work_thread
        assert entered.wait(1)
        assert not dialog.isModal() and not dialog.testAttribute(Qt.WA_DeleteOnClose)
        assert dialog.windowFlags() & Qt.WindowMinimizeButtonHint
        assert dialog.windowFlags() & Qt.WindowMaximizeButtonHint
        assert not dialog._start_work("fix", work)
        assert not dialog.close()
        assert isValid(dialog) and not dialog.isVisible() and finished == []
        assert dialog._angerona_work_window_retained
        assert owner._aar_work_owner is dialog
        ticks = []
        QTimer.singleShot(0, lambda: ticks.append(1))
        QApplication.processEvents()
        assert ticks == [1]
        release.set()
        settle_until(lambda: not dialog.has_active_work())
        assert finished == [True] and not worker.is_alive()
        assert owner._aar_work_owner is None
        assert len(work_threads) == 1 and work_threads[0] != gui_thread
        assert "Retained" in dialog.body.toPlainText()
    finally:
        release.set()
        if dialog._work_thread is not None:
            dialog._work_thread.join(3)
            dialog._poll_work()
        dialog.close()
        owner.deleteLater()


def test_explicit_apply_hold_never_opens_consent_or_dispatches_current_plan(tmp_path, monkeypatch):
    calls = []
    reason = "Exact reviewed remediation plan is unavailable; review current Posture actions"
    monkeypatch.setattr(pages.QMessageBox, "question", lambda *_: pytest.fail("Unbound plan requested consent"))
    dialog = AARDialog(tmp_path, on_apply=lambda: calls.append(True), apply_hold_reason=reason)
    try:
        dialog._show_fix_result("[VETTED PLAN READY] synthetic advisory")
        assert calls == [] and not dialog.has_active_work()
        assert reason in dialog.body.toPlainText()
    finally:
        dialog.deleteLater()


def test_other_exact_apply_callback_keeps_explicit_no_default(tmp_path, monkeypatch):
    questions, applied = [], []
    monkeypatch.setattr(pages.QMessageBox, "question", lambda *args: questions.append(args) or pages.QMessageBox.No)
    dialog = AARDialog(tmp_path, on_apply=lambda: applied.append(True))
    try:
        dialog._show_fix_result("[VETTED PLAN READY] inert test contract")
        assert len(questions) == 1 and questions[0][-1] == pages.QMessageBox.No
        assert applied == [] and not dialog.has_active_work()
    finally:
        dialog.deleteLater()


def test_settings_reuses_live_modeless_view_and_accepted_continuation_runs_once(tmp_path, monkeypatch):
    owner, built = Owner(tmp_path), []

    class Settings(QDialog):
        def __init__(self, _cfg, _updates, _theme, parent, **_kwargs):
            super().__init__(parent)
            self.selected = []
            built.append(self)
        def _select_tab(self, name): self.selected.append(name)

    monkeypatch.setattr(main_window, "SettingsDialog", Settings)
    monkeypatch.setattr(main_window, "reconcile_module_usage", lambda _manager: owner.actions.append("reconcile"))
    try:
        first = owner._show_settings()
        assert owner._show_settings("ARIA") is first
        assert built == [first] and first.selected == ["ARIA"]
        assert not first.isModal() and QApplication.activeModalWidget() is None
        assert first.windowFlags() & Qt.WindowMinimizeButtonHint
        first.reject()
        assert owner.actions == [] and owner._settings_dialog is None
        saved = owner._show_settings()
        saved.accept()
        saved.finished.emit(QDialog.DialogCode.Accepted)
        assert owner.actions == ["reconcile", "voice", "aria", "dashboard", "updates"]
        assert owner._settings_dialog is None
    finally:
        owner.deleteLater()


def test_console_reopen_resets_history_generation_and_ignores_old_carrier():
    dialog = red_team_console.RedTeamConsole.__new__(red_team_console.RedTeamConsole)
    QDialog.__init__(dialog)
    dialog._hist_accept_results = True
    dialog._hist_generation = 0
    dialog._hist_listing = dialog._hist_reading = True
    dialog._hist_refresh_pending = False
    dialog._hist_pending_name = dialog._hist_active_name = "old"
    dialog.finished.connect(dialog._stop_history_loads)
    seen = []
    dialog._on_history_result = lambda *args: seen.append(args)
    old = red_team_console._HistoryResultReceiver(dialog, 0)
    try:
        dialog.show()
        dialog.reject()
        dialog.show()
        assert dialog._hist_accept_results and dialog._hist_generation > 0
        assert not dialog._hist_listing and not dialog._hist_reading
        new = red_team_console._HistoryResultReceiver(dialog, dialog._hist_generation)
        old.receive("list", "", "old generation")
        new.receive("list", "", "current generation")
        assert seen == [("list", "", "current generation")]
    finally:
        dialog.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_aar_work_admission_cannot_release_another_dialog_or_accept_stale_shark_reload(tmp_path):
    owner = Owner(tmp_path)
    first = SimpleNamespace(_redteam=True)
    second = SimpleNamespace(_redteam=False, _expected_report_run_id="shark-older")
    assert owner._admit_aar_work(first, "fix")
    assert not owner._admit_aar_work(second, "fix")
    owner._release_aar_work(second)
    assert owner._aar_work_owner is first
    owner._release_aar_work(first)
    assert not owner._admit_aar_work(second, "refresh")
    owner.deleteLater()


def test_main_aar_reuses_only_authenticated_run_identity_and_holds_generic_apply(tmp_path, monkeypatch):
    from angerona.shark.aar_report import AARReportResult

    owner, built = Owner(tmp_path), []

    class Review(QDialog):
        def __init__(self, _directory, parent, **kwargs):
            super().__init__(parent)
            self.options = kwargs
            built.append(self)
        def set_text(self, text): self.text = text
        def has_active_work(self): return False

    def handoff(digest):
        return AARReportResult(
            text="Inert Shark report", run_id="shark-test", report_kind="shark",
            report_basename="shark_aar", report_sha256=digest, head_sha256="b" * 64,
            sequence=1, text_bytes=b"Inert Shark report", report_bytes=b"{}", head_bytes=b"{}",
            journal_record_sha256="c" * 64, journal_record_bytes=b"{}", report_directory=tmp_path,
        )

    monkeypatch.setattr(main_window, "AARDialog", Review)
    # This test owns the already-authenticated handoff seam, not cryptography.
    monkeypatch.setattr("angerona.shark.aar_report.verified_aar_handoff_text", lambda result: result.text)
    try:
        first_result = handoff("a" * 64)
        first = owner._show_aar_dialog(first_result)
        assert owner._show_aar_dialog(first_result) is first
        second = owner._show_aar_dialog(handoff("d" * 64))
        assert second is not first and built == [first, second]
        assert first.isVisible() and second.isVisible()
        assert QApplication.activeModalWidget() is None
        assert first.options["on_apply"] is None
        assert "Exact reviewed remediation plan is unavailable" in first.options["apply_hold_reason"]
        assert first.windowFlags() & Qt.WindowMinimizeButtonHint
        first.reject()
        assert len(owner._aar_dialogs) == 1
    finally:
        for dialog in built:
            if isValid(dialog):
                dialog.close()
        owner.deleteLater()
