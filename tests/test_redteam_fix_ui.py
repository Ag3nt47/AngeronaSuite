from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QWidget

from angerona.gui.pages import AARDialog


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_practice_fix_controls_unlock_only_after_green_verification(tmp_path) -> None:
    app = _app()
    dialog = AARDialog(
        tmp_path,
        redteam=True,
        on_attempt_fix=lambda _progress: "unused",
    )
    try:
        assert dialog._test_fix_btn.isHidden()
        assert dialog._source_btn.isHidden()

        dialog._on_fix_progress(63, "Testing detector response")
        assert dialog._fix_spinner._pct == 63
        assert "63%" in dialog._fix_spinner._label.text()

        dialog._show_fix_result("[PRACTICE FIX PARTIAL] 0/1 passed")
        assert dialog._test_fix_btn.isHidden()
        assert dialog._source_btn.isHidden()

        dialog._show_fix_result("[PRACTICE FIX VERIFIED] 1/1 passed")
        assert not dialog._test_fix_btn.isHidden()
        assert not dialog._source_btn.isHidden()
        assert dialog._fix_spinner._pct == 100
        assert dialog._fix_spinner._label.text().startswith("✓")
        assert not dialog._fix_spinner._ring._timer.isActive()

        dialog._show_fix_result("[PRACTICE FIX PARTIAL] retest failed")
        assert dialog._test_fix_btn.isHidden()
        assert dialog._source_btn.isHidden()
    finally:
        dialog.close()
        app.processEvents()


def test_green_practice_result_refreshes_score_before_showing_receipt(
    tmp_path, monkeypatch,
) -> None:
    app = _app()
    dialog = AARDialog(tmp_path, redteam=True, on_attempt_fix=lambda _progress: "unused")
    refreshed: list[bool] = []
    monkeypatch.setattr(dialog, "refresh", lambda: refreshed.append(True))
    try:
        dialog._show_fix_result("[PRACTICE FIX VERIFIED] 1/1 passed")
        assert refreshed == [True]
        assert "PRACTICE FIX VERIFIED" in dialog.body.toPlainText()
    finally:
        dialog.close()
        app.processEvents()


def test_verified_source_button_opens_exact_detector_in_sandbox(
    tmp_path, monkeypatch,
) -> None:
    app = _app()

    class Parent(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.manager = object()
            self.bus = object()

    parent = Parent()
    calls = []
    sentinel = object()
    from angerona.gui import sandbox_editor

    monkeypatch.setattr(
        sandbox_editor,
        "launch_sandbox_editor",
        lambda manager, bus, **kwargs: calls.append((manager, bus, kwargs)) or sentinel,
    )
    dialog = AARDialog(
        tmp_path,
        parent=parent,
        redteam=True,
        on_attempt_fix=lambda _progress: "unused",
    )
    try:
        dialog._show_fix_result("[PRACTICE FIX VERIFIED] 1/1 passed")
        dialog._open_fix_source()
        assert dialog._sandbox is sentinel
        assert calls == [(
            parent.manager,
            parent.bus,
            {"parent": parent, "preselect": "Purple Remediation Guard"},
        )]
    finally:
        dialog.close()
        parent.close()
        app.processEvents()
