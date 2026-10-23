"""The diagnostic harness must retire readers before deleting their owners."""
from __future__ import annotations

import ast
from pathlib import Path
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QDialog
from shiboken6 import isValid

from angerona.gui.async_snapshot import AsyncSnapshot


def cleanup_function():
    path = Path(__file__).parents[1] / "tools" / "selfcheck.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_teardown_qt_owned")
    namespace = {"time": time}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[function.name]


def test_cleanup_stops_reader_and_due_timer_without_dispatching_normal_callbacks():
    app = QApplication.instance()
    dialog = QDialog()
    applied, fired = [], []
    dialog.snapshot = AsyncSnapshot(dialog, lambda: lambda: {"ok": True}, applied.append,
                                    name="SelfcheckCleanupFixture")
    dialog.snapshot.request()
    worker = dialog.snapshot.thread
    timer = QTimer(dialog)
    timer.timeout.connect(lambda: fired.append(True))
    timer.start(0)
    detail = cleanup_function()(app, [dialog])
    assert not worker.is_alive()
    assert not isValid(dialog)
    assert not applied and not fired
    app.processEvents()
    assert not applied and not fired
    assert "1 readers" in detail and "1 Python" in detail


def test_cleanup_failure_is_reported_before_widget_deletion(monkeypatch):
    app = QApplication.instance()
    dialog = QDialog()
    dialog.snapshot = AsyncSnapshot(dialog, lambda: lambda: {}, lambda _result: None,
                                    name="SelfcheckCleanupFailureFixture")
    original = dialog.snapshot.close

    def failed_close(*_args):
        raise RuntimeError("reader stop failed")

    monkeypatch.setattr(dialog.snapshot, "close", failed_close)
    try:
        with pytest.raises(RuntimeError, match="reader stop failed"):
            cleanup_function()(app, [dialog])
        assert isValid(dialog)
    finally:
        monkeypatch.setattr(dialog.snapshot, "close", original)
        cleanup_function()(app, [dialog])


def test_unfinished_reader_fails_without_deleting_its_owner():
    app = QApplication.instance()
    dialog = QDialog()
    dialog.snapshot = AsyncSnapshot(dialog, lambda: lambda: {}, lambda _result: None,
                                    name="SelfcheckStuckReaderFixture")
    alive = [True]
    dialog.snapshot.thread = SimpleNamespace(ident=1, name="Stuck fixture", join=lambda _timeout: None,
                                             is_alive=lambda: alive[0])
    try:
        with pytest.raises(AssertionError, match="GUI reader did not stop"):
            cleanup_function()(app, [dialog], timeout=0)
        assert isValid(dialog)
    finally:
        alive[0] = False
        cleanup_function()(app, [dialog])
