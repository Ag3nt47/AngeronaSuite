"""Modeless review, genuine worker retirement and diagnostic action holds."""
from __future__ import annotations

import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from angerona.gui import patch_center
from angerona.gui.pages import AARDialog


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def _wait(app, predicate):
    end = time.monotonic() + 3
    while time.monotonic() < end:
        app.processEvents()
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError("Owned UI worker did not retire within the fixture deadline")


class InertReview:
    def __init__(self, *_args):
        pass

    def snapshot(self):
        return {"report_state": "diagnostic", "reason": "Authenticated incomplete fixture",
            "gaps": [], "authority": {"allowed": False, "reason": "Source Observe"},
            "memory": {"gaps": [], "attempts": [], "incidents": []}}


def test_patch_window_is_modeless_and_diagnostics_cannot_enable_host_actions(app, monkeypatch):
    monkeypatch.setattr(patch_center, "PatchReviewService", InertReview)
    dialog = patch_center.AngeronaPatchDialog(None, None)
    try:
        dialog.show()
        _wait(app, lambda: not dialog.has_active_work())
        assert dialog.windowModality() == Qt.WindowModality.NonModal
        assert dialog.windowFlags() & Qt.WindowType.WindowMinimizeButtonHint
        assert dialog.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint
        assert not dialog.plan_button.isEnabled() and not dialog.apply_button.isEnabled()
        assert not dialog.rollback_button.isEnabled() and not dialog.recover_button.isEnabled()
        assert "Host actions held" in dialog.status.text()
    finally:
        dialog.close()


def test_close_retains_actual_worker_and_finishes_only_its_exact_loading_token(app, monkeypatch):
    monkeypatch.setattr(patch_center, "PatchReviewService", InertReview)
    begun, finished = [], []
    monkeypatch.setattr(patch_center, "begin_loading", lambda label: begun.append(label) or "token-" + str(len(begun)))
    monkeypatch.setattr(patch_center, "finish_loading", lambda token: finished.append(token))
    dialog = patch_center.AngeronaPatchDialog(None, None)
    release = threading.Event()
    try:
        _wait(app, lambda: not dialog.has_active_work())
        finished.clear()
        assert dialog._start("retest", lambda: release.wait(2) and {"ok": True, "state": "fixture-complete"})
        worker, token = dialog._worker, dialog._loading_token
        dialog.close()
        app.processEvents()
        assert worker.is_alive() and dialog.has_active_work() and finished == []
        assert dialog._angerona_work_window_retained is True
        release.set()
        _wait(app, lambda: not dialog.has_active_work())
        assert not worker.is_alive() and finished == [token]
    finally:
        release.set()
        _wait(app, lambda: not dialog.has_active_work())
        dialog.close()


def test_selection_change_invalidates_reviewed_plan(app, monkeypatch):
    monkeypatch.setattr(patch_center, "PatchReviewService", InertReview)
    dialog = patch_center.AngeronaPatchDialog(None, None)
    try:
        _wait(app, lambda: not dialog.has_active_work())
        dialog._plan = {"plan_id": "inert-plan", "change_needed": True, "authority": {"allowed": True}}
        dialog._control_changed()
        assert dialog._plan is None and not dialog.apply_button.isEnabled()
    finally:
        dialog.close()


def test_aar_diagnostic_has_functional_read_only_patch_callback_and_no_practice_fix(app, tmp_path):
    opened = []
    binding = {"run_id": "diagnostic-fixture", "sha256": "a" * 64,
        "handoff_verified": True, "diagnostic_only": True, "coverage_score_eligible": False}
    dialog = AARDialog(tmp_path, redteam=True,
        report_binding=binding, on_patch=lambda: opened.append("opened"))
    try:
        assert dialog._patch_btn.isEnabled() and not dialog._fix_btn.isEnabled()
        assert not dialog._test_fix_btn.isEnabled()
        dialog._patch_btn.click()
        assert opened == ["opened"]
        assert "coverage" in dialog._report_status.text()
    finally:
        dialog.close()


def test_loading_start_failure_releases_mutation_admission_without_dispatch(app, monkeypatch):
    from PySide6.QtWidgets import QWidget
    class Owner(QWidget):
        def __init__(self):
            super().__init__()
            self.owned = None
        def _admit_aar_work(self, dialog, _kind):
            self.owned = dialog
            return True
        def _release_aar_work(self, dialog):
            assert self.owned is dialog
            self.owned = None
    monkeypatch.setattr(patch_center, "PatchReviewService", InertReview)
    owner = Owner()
    dialog = patch_center.AngeronaPatchDialog(None, None, owner)
    try:
        _wait(app, lambda: not dialog.has_active_work())
        def broken(_label):
            raise RuntimeError("inert progress ownership failure")
        monkeypatch.setattr(patch_center, "begin_loading", broken)
        assert dialog._start("apply", lambda: pytest.fail("No effect may be dispatched")) is False
        assert owner.owned is None and not dialog.has_active_work()
    finally:
        dialog.close()
        owner.close()
