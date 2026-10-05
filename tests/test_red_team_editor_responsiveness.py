"""Protected editor I/O must never block Qt or mutate installed source."""
from __future__ import annotations

import threading
import time

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from angerona.core.source_sandbox import SourceSandboxWorkspace
from angerona.gui import red_team_console as console


class EditorHarness(console.RedTeamConsole):
    def __init__(self):
        QDialog.__init__(self)
        self._build_editor_tab().setParent(self)


def drain(predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(0.002)
    assert predicate()


@pytest.fixture
def editor():
    dialog = EditorHarness()
    yield dialog
    reader = dialog._editor_reader
    reader.close()
    if reader.thread is not None:
        reader.thread.join(2)
        assert not reader.thread.is_alive()
    dialog.close()
    dialog.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_construction_is_lazy_and_blocked_load_keeps_qt_responsive(monkeypatch):
    calls, entered, release = [], threading.Event(), threading.Event()

    class Workspace:
        def __init__(self, *_args):
            calls.append(threading.get_ident())

        def reload(self, _path):
            entered.set()
            assert release.wait(5)
            return "VALUE = 1\n"

        def changed(self, _path):
            return False

    monkeypatch.setattr(console, "SourceSandboxWorkspace", Workspace)
    dialog = EditorHarness()
    try:
        assert calls == []
        assert dialog._editor_reader.thread is None
        dialog._load_editor()
        drain(entered.is_set)
        ticks = []
        QTimer.singleShot(0, lambda: ticks.append(True))
        dialog._reload_editor()
        dialog._save_editor()
        drain(lambda: bool(ticks))
        assert dialog._editor_reader.busy
        assert len(calls) == 1 and calls[0] != threading.get_ident()
        release.set()
        drain(lambda: not dialog._editor_reader.busy)
        assert dialog.editor.toPlainText() == "VALUE = 1\n"
        assert dialog._editor_loaded
    finally:
        release.set()
        reader = dialog._editor_reader
        reader.close()
        if reader.thread is not None:
            reader.thread.join(2)
        dialog.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_real_save_syntax_gate_and_confirmed_rollback_keep_source_unchanged(editor, tmp_path, monkeypatch):
    source_root = tmp_path / "installed"
    installed = source_root / console._RED_TEAM_SOURCE
    installed.parent.mkdir(parents=True)
    installed.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setattr(console, "SourceSandboxWorkspace", lambda key, paths: SourceSandboxWorkspace(
        key, paths, source_root=source_root, sandbox_root=tmp_path / "sandbox"))
    editor._load_editor()
    drain(lambda: not editor._editor_reader.busy)
    assert editor._editor_loaded
    worker = editor._editor_reader.thread
    editor.editor.setPlainText("VALUE = 2\n")
    editor._save_editor()
    drain(lambda: not editor._editor_reader.busy)
    assert editor._editor_workspace.reload(console._RED_TEAM_SOURCE) == "VALUE = 2\n"
    editor.editor.setPlainText("VALUE = (\n")
    editor._save_editor()
    drain(lambda: not editor._editor_reader.busy)
    assert "syntax error" in editor.edit_status.text()
    assert editor.editor.toPlainText() == "VALUE = (\n"
    assert editor._editor_workspace.reload(console._RED_TEAM_SOURCE) == "VALUE = 2\n"
    monkeypatch.setattr(QMessageBox, "question", lambda *_args: QMessageBox.Yes)
    editor._rollback_editor()
    drain(lambda: not editor._editor_reader.busy)
    assert editor.editor.toPlainText() == "VALUE = 1\n"
    assert installed.read_text(encoding="utf-8") == "VALUE = 1\n"
    assert editor._editor_reader.thread is worker


def test_initial_load_failure_can_retry_without_losing_buffer(editor, monkeypatch):
    def unavailable(*_args):
        raise PermissionError("inert failure")

    monkeypatch.setattr(console, "SourceSandboxWorkspace", unavailable)
    editor.editor.setPlainText("retained")
    editor._load_editor()
    drain(lambda: not editor._editor_reader.busy)
    assert editor.editor.toPlainText() == "retained"
    assert editor._editor_reload.isEnabled()
    assert not editor._editor_save.isEnabled()

    class Workspace:
        def __init__(self, *_args):
            pass

        def reload(self, _path):
            return "VALUE = 3\n"

        def changed(self, _path):
            return True

    monkeypatch.setattr(console, "SourceSandboxWorkspace", Workspace)
    editor._reload_editor()
    drain(lambda: not editor._editor_reader.busy)
    assert editor._editor_save.isEnabled()
    assert editor._editor_save.toolTip() == ""
    assert "modified" in editor.edit_status.text()


def test_destroyed_owner_discards_late_result(monkeypatch):
    entered, release = threading.Event(), threading.Event()

    class Workspace:
        def __init__(self, *_args):
            pass

        def reload(self, _path):
            entered.set()
            assert release.wait(5)
            return "VALUE = 1\n"

        def changed(self, _path):
            return False

    monkeypatch.setattr(console, "SourceSandboxWorkspace", Workspace)
    dialog = EditorHarness()
    dialog._load_editor()
    drain(entered.is_set)
    reader = dialog._editor_reader
    worker = reader.thread
    try:
        dialog.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert reader._closed
        release.set()
        worker.join(2)
        assert not worker.is_alive()
        assert reader._results.empty()
    finally:
        release.set()
        worker.join(2)
