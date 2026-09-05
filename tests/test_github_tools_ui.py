from __future__ import annotations

import io
import threading
import time
import zipfile

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication

from angerona.core import github_tool_catalog as core
from angerona.gui import github_tools as ui
from angerona.gui.red_team_console import RedTeamConsole


def wait_until(predicate):
    deadline = time.monotonic() + 5
    app = QApplication.instance()
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert predicate()


def ready_panel(tmp_path):
    panel = ui.GitHubToolsPanel(root=tmp_path / "library")
    panel.resize(720, 500)
    panel.show()
    wait_until(lambda: not panel._busy)
    assert panel._catalog is not None, panel.status.text()
    return panel


def test_repository_prose_is_literal_and_review_never_enables_run(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "_require_unprivileged", lambda: None)
    panel = ready_panel(tmp_path)
    try:
        content = io.BytesIO()
        with zipfile.ZipFile(content, "w") as archive:
            archive.writestr("fixture/README.md", "<b>Repository content is data.</b>")
        selected = core.ImportPlan("example/fixture", "main", "a" * 40, "MIT")
        panel._catalog.store_source(selected, content.getvalue(), core.ImportOperation())
        panel._populate(panel._catalog.list_imports())
        panel.imports.setCurrentRow(0)
        wait_until(lambda: not panel._busy)
        assert panel.files.count() == 1
        panel.files.setCurrentRow(0)
        wait_until(lambda: not panel._busy)
        assert panel.preview.toPlainText() == "<b>Repository content is data.</b>"
        panel.review_button.click()
        wait_until(lambda: not panel._busy)
        assert panel._catalog.list_imports()[0]["state"] == "reviewed"
        assert not panel.run_button.isEnabled()
    finally:
        panel.close()


def test_revision_edit_invalidates_resolved_import(tmp_path, monkeypatch):
    selected = core.ImportPlan("example/fixture", "main", "a" * 40, "MIT")
    monkeypatch.setattr(ui, "resolve_import", lambda *_args: selected)
    panel = ready_panel(tmp_path)
    try:
        panel.repository.setText("https://github.com/example/fixture")
        panel.resolve_button.click()
        wait_until(lambda: not panel._busy)
        assert panel.import_button.isEnabled()
        assert selected.commit in panel.verification.toPlainText()
        panel.revision.setText("different-branch")
        assert panel._plan is None
        assert not panel.import_button.isEnabled()
    finally:
        panel.close()


def test_pending_work_keeps_gui_responsive_and_discards_cancelled_result(tmp_path):
    panel = ready_panel(tmp_path)
    release = threading.Event()
    ticks = []
    try:
        panel._start("preview", lambda _operation: (release.wait(4), "late text")[1], "Working")
        QTimer.singleShot(0, lambda: ticks.append(True))
        QApplication.instance().processEvents()
        assert ticks
        panel.cancel_button.click()
        assert "Cancelling" in panel.status.text()
        release.set()
        wait_until(lambda: not panel._busy)
        assert "cancelled" in panel.status.text().lower()
        assert "late text" not in panel.preview.toPlainText()
    finally:
        release.set()
        panel.close()


def test_destroying_panel_cancels_worker_without_qt_callback(tmp_path):
    panel = ready_panel(tmp_path)
    release = threading.Event()
    completed = threading.Event()
    lifetime = panel._lifetime

    def work(operation):
        release.wait(4)
        completed.set()
        return "late text"

    panel._start("preview", work, "Working")
    operation = panel._operation
    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert lifetime["closed"]
    assert operation.cancelled.is_set()
    release.set()
    assert completed.wait(2)


def test_red_team_includes_source_library_and_preserves_editor(tmp_path):
    dialog = RedTeamConsole(default_target=str(tmp_path))
    try:
        titles = [dialog._tabs.tabText(index) for index in range(dialog._tabs.count())]
        assert "GitHub Tools" in titles
        assert any("Sandbox Editor" in title for title in titles)
        assert not dialog.github_tools.run_button.isEnabled()
        assert dialog.github_tools._catalog is None  # Lazy; no GUI-thread disk work.
        dialog.github_tools.run_button.clicked.emit()
        assert "no verified disposable-VM" in dialog.github_tools.status.text()
        assert not dialog.github_tools.run_button.isEnabled()
    finally:
        dialog.close()
