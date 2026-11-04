"""Read-only explanation remains modeless and separate from mutation admission."""
import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from angerona.gui.pages import AARDialog


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def test_aar_explanations_open_without_triggering_patch_or_fix(app, tmp_path):
    opened, changed = [], []
    dialog = AARDialog(tmp_path, on_diagnostics=lambda: opened.append("read-only"),
        on_patch=lambda: changed.append("patch"), on_attempt_fix=lambda: changed.append("fix"))
    try:
        dialog._diagnostics_btn.click()
        assert opened == ["read-only"] and not changed
        assert dialog.windowModality() == Qt.NonModal
        assert dialog.windowFlags() & Qt.WindowMinimizeButtonHint
        assert dialog.windowFlags() & Qt.WindowMaximizeButtonHint
    finally:
        dialog.close()
        app.processEvents()


def test_readonly_explanation_does_not_wait_for_unrelated_mutation_worker(app, tmp_path):
    release = threading.Event()
    worker = threading.Thread(target=lambda: release.wait(3), daemon=True)
    worker.start()
    opened = []
    dialog = AARDialog(tmp_path, on_diagnostics=lambda: opened.append("read-only"))
    dialog._work_thread = worker
    try:
        dialog._diagnostics_btn.click()
        assert opened == ["read-only"] and worker.is_alive()
    finally:
        release.set()
        worker.join(3)
        assert not worker.is_alive()
        dialog._work_thread = None
        dialog.close()
        app.processEvents()


def test_failed_diagnostics_show_untrusted_text_as_plain_without_mutation(app, tmp_path):
    def error():
        raise ValueError("<a href='file:///untrusted'>untrusted log</a>")
    dialog = AARDialog(tmp_path, on_diagnostics=error)
    try:
        dialog._diagnostics_btn.click()
        assert "<a href='file:///untrusted'>" in dialog.body.toPlainText()
        assert not dialog.has_active_work()
    finally:
        dialog.close()
        app.processEvents()


def test_session_shark_refresh_button_describes_saved_report_read(app, tmp_path):
    dialog = AARDialog(tmp_path, report_binding={"session_owned": True})
    try:
        assert dialog._reload_btn.text() == "Reload verified report"
    finally:
        dialog.close()
        app.processEvents()
