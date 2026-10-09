from __future__ import annotations

from pathlib import Path
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QThread
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from angerona.gui import sandbox_editor


def spin_until(predicate, timeout=5):
    app = QApplication.instance()
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        time.sleep(0.005)
    assert predicate()


@pytest.fixture
def editor(monkeypatch):
    modules = {name: SimpleNamespace(name=name) for name in ("A", "B")}
    window = sandbox_editor.SandboxEditor(SimpleNamespace(modules=modules), None)
    window._close_confirmed = True
    window._current = "A"
    window.editor.setPlainText("VALUE = 2\n")
    window.tree.setCurrentItem(window.tree.topLevelItem(1))
    saved, opened = [], []
    content = ["VALUE = 1\n"]

    def save(relative, text):
        saved.append((relative, text))
        content[0] = text

    workspace = SimpleNamespace(
        save=save, reload=lambda _relative: content[0],
        file=lambda _relative: SimpleNamespace(working_path=Path("inert-copy.py")),
    )

    def for_module(name, _module):
        opened.append(name)
        return workspace, "probe.py"

    monkeypatch.setattr(window, "_workspace_for_module", for_module)
    yield window, workspace, saved, opened
    if isValid(window):
        window.close()
        spin_until(lambda: not isValid(window))


def test_validation_uses_opened_buffer_and_can_be_repeated(editor, monkeypatch):
    window, _workspace, saved, opened = editor
    results = []
    monkeypatch.setattr(sandbox_editor, "run_isolated_self_test",
                        lambda *args: (results.append(args) or (True, "inert baseline")))
    for _ in range(2):
        window._run_test()
        spin_until(lambda: window._test_worker is None)
    assert len(results) == 2
    assert all(args[2] == "A" for args in results)
    assert opened == ["A", "A"]
    assert saved == [("probe.py", "VALUE = 2\n")] * 2


def test_disposed_worker_wrapper_cannot_block_next_validation(editor, monkeypatch):
    window, _workspace, _saved, _opened = editor
    old = QThread()
    old.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert not isValid(old)
    window._test_worker = old
    monkeypatch.setattr(sandbox_editor, "run_isolated_self_test", lambda *_args: (True, "inert"))
    window._run_test()
    spin_until(lambda: window._test_worker is None)


def test_close_with_blocked_selftest_defers_native_destruction(editor, monkeypatch):
    window, _workspace, _saved, _opened = editor
    entered, release = threading.Event(), threading.Event()

    def blocked(*_args):
        entered.set()
        assert release.wait(5)
        return True, "inert"

    monkeypatch.setattr(sandbox_editor, "run_isolated_self_test", blocked)
    try:
        window._run_test()
        assert entered.wait(2)
        window.close()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert isValid(window)
        assert not window.isVisible()
    finally:
        release.set()
    spin_until(lambda: not isValid(window))


def test_undo_budget_refuses_save_and_failed_revert_preserves_backup(editor, monkeypatch):
    window, workspace, saved, _opened = editor
    monkeypatch.setattr(sandbox_editor, "_MAX_SESSION_BACKUPS", 1)
    window._apply_changes()
    assert len(saved) == 1
    window.editor.setPlainText("VALUE = 3\n")
    window._apply_changes()
    assert len(saved) == 1
    assert window._backups["A"] == ["VALUE = 1\n"]

    def refused(*_args):
        raise ValueError("inert write refusal")

    monkeypatch.setattr(workspace, "save", refused)
    window._revert()
    assert window._backups["A"] == ["VALUE = 1\n"]
    for _ in range(sandbox_editor._MAX_HISTORY_ENTRIES + 5):
        window._record_history("A", "probe", 0, "inert")
    assert len(window._history["A"]) == sandbox_editor._MAX_HISTORY_ENTRIES
    assert window.console.document().maximumBlockCount() == 1000
