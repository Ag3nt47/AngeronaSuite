"""Inert exact-worker retirement for one closed Settings generation."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication, QDialog
from shiboken6 import isValid

from angerona.gui import pages
from angerona.gui.pages import SettingsDialog
from test_work_window_integration import Owner


def bare_settings():
    dialog = SettingsDialog.__new__(SettingsDialog)
    QDialog.__init__(dialog)
    dialog._accept_async_results = True
    dialog._settings_owned_workers = {}
    dialog._settings_retirement_callback = None
    dialog._settings_retirement_timer = QTimer(dialog)
    dialog._settings_retirement_timer.setSingleShot(True)
    dialog._settings_retirement_timer.setInterval(40)
    dialog._settings_retirement_timer.timeout.connect(dialog._poll_settings_retirement)
    dialog._voice_model_loading_token = None
    dialog._aria_test_loading_tokens = []
    return dialog


def test_retirement_keeps_one_exact_worker_and_rejects_duplicate_installer():
    dialog = bare_settings()
    entered, release = threading.Event(), threading.Event()
    callbacks = []

    def work():
        entered.set()
        assert release.wait(3)

    try:
        assert dialog._start_settings_worker("VoiceModelInstall", work)
        worker = dialog._settings_owned_workers["VoiceModelInstall"]
        assert entered.wait(1)
        assert not dialog._start_settings_worker("VoiceModelInstall", work)
        dialog.retire_after_workers(lambda current: callbacks.append((current, worker.is_alive())))
        assert callbacks == [] and dialog._settings_retirement_timer.isActive()
        assert not dialog._settings_worker_available("AnotherJob")
        assert isValid(dialog)
        release.set()
        deadline = time.monotonic() + 3
        while not callbacks and time.monotonic() < deadline:
            QApplication.processEvents()
            time.sleep(.005)
        assert callbacks == [(dialog, False)]
        assert dialog._settings_owned_workers == {}
        assert not dialog._settings_retirement_timer.isActive()
    finally:
        release.set()
        for worker in dialog._settings_owned_workers.values():
            worker.join(3)
        dialog.deleteLater()


def test_closed_result_slots_never_access_retired_widgets_and_tokens_finish(monkeypatch):
    dialog = bare_settings()
    finished = []
    monkeypatch.setattr(pages, "finish_loading", finished.append)
    dialog._voice_model_loading_token = "model"
    dialog._aria_test_loading_tokens = ["voice", "email"]
    callbacks = []
    try:
        dialog.retire_after_workers(callbacks.append)
        assert finished == ["model", "voice", "email"]
        assert callbacks == [dialog]
        # No status widgets exist: a closed-generation callback must return
        # without reading/updating them or emitting another loading finish.
        dialog._voice_model_finished("late", True)
        dialog._aria_test_finished("late")
        dialog._process_baseline_action_finished("late", True)
        dialog._finish_settings_loading()
        assert finished == ["model", "voice", "email"]
    finally:
        dialog.deleteLater()


@pytest.mark.parametrize("reader_kind", ["update", "installed-startup"])
def test_inflight_settings_snapshot_reader_is_retained_without_gui_join(reader_kind):
    dialog = bare_settings()
    entered, release = threading.Event(), threading.Event()
    worker = threading.Thread(target=lambda: (entered.set(), release.wait(3)))
    worker.start()
    assert entered.wait(1)
    if reader_kind == "update":
        dialog._update_check_reader = SimpleNamespace(thread=worker)
    else:
        # Enrollment can already be in native code when Settings closes. The
        # exact detached backend reader must also prevent a replacement view.
        dialog._installed_startup_controls = SimpleNamespace(_reader=SimpleNamespace(thread=worker))
    callbacks = []
    try:
        dialog.retire_after_workers(callbacks.append)
        assert callbacks == []
        release.set()
        worker.join(3)
        dialog._poll_settings_retirement()
        assert callbacks == [dialog] and not dialog._settings_retirement_timer.isActive()
    finally:
        release.set()
        worker.join(3)
        dialog.deleteLater()


def test_one_retiring_settings_tree_blocks_reopen_then_next_open_uses_fresh_config(tmp_path, monkeypatch):
    from angerona.gui import main_window
    owner, built = Owner(tmp_path), []
    owner.config.fixture_value = "before"

    class Settings(QDialog):
        def __init__(self, config, _updates, _theme, parent, **_kwargs):
            super().__init__(parent)
            self.value = config.fixture_value
            built.append(self)
        def retire_after_workers(self, callback):
            self.retired = callback

    monkeypatch.setattr(main_window, "SettingsDialog", Settings)
    try:
        old = owner._show_settings()
        old.reject()
        assert owner._retiring_settings_dialog is old
        for _ in range(20):
            assert owner._show_settings() is None
        assert built == [old] and isValid(old)
        owner.config.fixture_value = "after"
        old.retired(old)
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert not isValid(old) and owner._retiring_settings_dialog is None
        fresh = owner._show_settings()
        assert fresh is not old and fresh.value == "after" and len(built) == 2
        fresh.reject()
        fresh.retired(fresh)
    finally:
        for dialog in built:
            if isValid(dialog):
                dialog.deleteLater()
        owner.deleteLater()
