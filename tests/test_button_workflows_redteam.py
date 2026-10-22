"""Bounded report readers and efficient, non-destructive discovery."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QRunnable, QThreadPool
from PySide6.QtWidgets import QApplication, QDialog, QListWidget, QPlainTextEdit, QTextEdit

from angerona.gui import red_team_console
from angerona.shark.red_team import RedTeamEngine


@pytest.mark.parametrize("fail", [False, True])
def test_discovery_uses_pid_snapshot_and_reports_read_failure(monkeypatch, tmp_path, fail):
    import psutil

    def snapshot():
        if fail:
            raise OSError("inert enumeration refusal")
        return [10, 20, 30]

    monkeypatch.setattr(psutil, "pids", snapshot)
    monkeypatch.setattr(psutil, "process_iter", lambda *_args: pytest.fail("unused names queried"))
    engine = RedTeamEngine(tmp_path)
    engine._step_recon((0, 0))
    step = engine.steps[0]
    assert step.ok is (not fail)
    assert step.artifact_paths == []
    if fail:
        assert "inert enumeration refusal" in step.detail
    else:
        assert "3 processes" in step.description


def test_saturated_history_pool_rejects_read_instead_of_queueing(monkeypatch, tmp_path):
    entered, release = threading.Event(), threading.Event()

    class Blocker(QRunnable):
        def run(self):
            entered.set()
            release.wait(3.0)

    pool = QThreadPool()
    pool.setMaxThreadCount(1)
    pool.start(Blocker())
    assert entered.wait(1)
    calls = []
    monkeypatch.setattr(red_team_console, "list_history", lambda *_args: calls.append(True))
    dialog = red_team_console.RedTeamConsole.__new__(red_team_console.RedTeamConsole)
    QDialog.__init__(dialog)
    dialog._parent = SimpleNamespace(config=SimpleNamespace(data_dir=tmp_path))
    dialog._history_pool = pool
    dialog._hist_accept_results = True
    dialog._hist_listing = False
    dialog._hist_list = QListWidget(dialog)
    dialog._hist_view = QPlainTextEdit(dialog)
    try:
        dialog._load_history()
        assert dialog._hist_listing is False
        assert "history readers are busy" in dialog._hist_view.toPlainText()
        release.set()
        assert pool.waitForDone(3000)
        QApplication.instance().processEvents()
        assert calls == []
    finally:
        release.set()
        assert pool.waitForDone(3000)
        dialog.deleteLater()


def test_narration_is_displayed_as_literal_text():
    dialog = red_team_console.RedTeamConsole.__new__(red_team_console.RedTeamConsole)
    QDialog.__init__(dialog)
    dialog.log = QTextEdit(dialog)
    payload = '<b>operator technique name</b> <img src="https://example.invalid/remote.png">'
    try:
        dialog._on_narration(payload)
        assert dialog.log.toPlainText() == payload
    finally:
        dialog.deleteLater()
