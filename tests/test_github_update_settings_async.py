from __future__ import annotations

import threading

from PySide6.QtCore import QElapsedTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget
from shiboken6 import delete

from angerona.gui.async_snapshot import AsyncSnapshot
from angerona.gui.pages import SettingsDialog


def test_manual_settings_check_runs_off_qt_and_displays_the_returned_status() -> None:
    app = QApplication.instance()
    owns_app = app is None
    if owns_app:
        app = QApplication([])
    previous_quit = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)
    main_thread = threading.get_ident()
    workers = []

    def check():
        workers.append(threading.get_ident())
        return "Published status available; source identity remains unknown."

    class Owner(QWidget):
        _prepare_update_check = SettingsDialog._prepare_update_check
        _apply_update_check = SettingsDialog._apply_update_check
        _update_check_status = SettingsDialog._update_check_status
        _on_check_updates = SettingsDialog._on_check_updates

    owner = Owner()
    owner._check_updates = check
    owner._shared_update_controller = None
    owner._accept_async_results = True
    owner._btn_check = QPushButton(owner)
    owner._update_status = QLabel(owner)
    owner._update_status.setTextFormat(Qt.PlainText)
    owner._update_check_reader = AsyncSnapshot(owner, owner._prepare_update_check, owner._apply_update_check,
                                               name="Update check contract", status=owner._update_check_status)
    thread = None
    try:
        owner._on_check_updates()
        assert not owner._btn_check.isEnabled()
        clock = QElapsedTimer()
        clock.start()
        while owner._update_check_reader.busy and clock.elapsed() < 2000:
            QTest.qWait(10)
        assert "source identity remains unknown" in owner._update_status.text()
        assert owner._btn_check.isEnabled() and workers and workers[0] != main_thread
        assert owner._update_status.textFormat() == Qt.PlainText
        thread = owner._update_check_reader.thread
    finally:
        owner._update_check_reader.close()
        thread = thread or owner._update_check_reader.thread
        if thread is not None:
            thread.join(2)
            assert not thread.is_alive()
        delete(owner)
        if owns_app:
            app.shutdown()
            assert QApplication.instance() is None
        else:
            app.setQuitOnLastWindowClosed(previous_quit)
