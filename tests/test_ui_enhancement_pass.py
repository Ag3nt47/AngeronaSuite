"""Operator-facing readiness and report-integrity state transitions."""
from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QApplication, QMainWindow

from angerona.core import drill_readiness
from angerona.gui.pages import AARDialog
from angerona.gui.red_team_console import RedTeamConsole
from angerona.gui.response_status import ResponseStatusPanel


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


class _ConsoleParent(QMainWindow):
    _shark_narration = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.manager = object()

    def _qss(self) -> str:
        return ""


def test_red_team_readiness_preview_tracks_profile_and_detection_only(
    tmp_path, monkeypatch,
) -> None:
    app = _app()
    calls: list[bool] = []
    readiness = {
        "ready": True,
        "state": "ARMED",
        "reason": "Exact response policy is ready.",
    }

    def assess(_manager, *, require_process: bool):
        calls.append(require_process)
        return dict(readiness)

    monkeypatch.setattr(drill_readiness, "assess_drill_response", assess)
    parent = _ConsoleParent()
    dialog = RedTeamConsole(parent, default_target=str(tmp_path))
    try:
        assert calls[-1] is True
        assert "APT process checks" in dialog.response_readiness.text()
        assert "ARMED" in dialog.response_readiness.text()
        assert "signed report receipts decide" in dialog.response_readiness.text()
        assert dialog.response_readiness.textFormat() == Qt.PlainText

        dialog.cb_apt.setChecked(False)
        assert calls[-1] is False
        assert "Shark checks" in dialog.response_readiness.text()

        readiness.update(
            ready=False,
            state="POLICY RESTRICTED",
            reason="File quarantine is disabled.",
        )
        dialog.refresh_readiness_btn.click()
        assert "File quarantine is disabled" in dialog.response_readiness.text()
        assert "Settings > Adversary Combat" in dialog.response_readiness.text()

        checks_before_detection_only = len(calls)
        dialog.cb_remediate.setChecked(False)
        assert len(calls) == checks_before_detection_only
        assert "Detection-only run selected" in dialog.response_readiness.text()
        assert "will not assign a containment pass" in dialog.response_readiness.text()
    finally:
        dialog.close()
        parent.close()
        app.processEvents()


def test_combat_unavailable_clears_prior_green_readiness() -> None:
    app = _app()
    current = {"snapshot": {
        "state": "ARMED", "ready": True, "reason": "Ready",
        "queue_depth": 0, "queue_capacity": 5,
    }}
    module = SimpleNamespace(response_snapshot=lambda: current["snapshot"])
    panel = ResponseStatusPanel(lambda: module)
    try:
        assert "#4ade80" in panel.state_label.styleSheet()
        current["snapshot"] = None
        panel.refresh()
        assert panel.state_label.text() == "Response status unavailable"
        assert "#4ade80" not in panel.state_label.styleSheet()
    finally:
        panel.close()
        app.processEvents()


def test_combat_settings_guidance_matches_disabled_and_full_queue() -> None:
    app = _app()
    current = {"state": "DISABLED", "ready": False, "reason": "Off"}
    module = SimpleNamespace(response_snapshot=lambda: current)
    panel = ResponseStatusPanel(lambda: module)
    try:
        assert "wait for ARMED" in panel.guidance_label.text()
        current["state"] = "QUEUE FULL"
        panel.refresh()
        assert "verified action receipts" in panel.guidance_label.text()
        assert "#f87171" in panel.state_label.styleSheet()
    finally:
        panel.close()
        app.processEvents()


def test_red_team_aar_keeps_report_visible_when_binding_failed(tmp_path) -> None:
    app = _app()
    dialog = AARDialog(
        tmp_path,
        redteam=True,
        report_binding={"error": "signature mismatch"},
        on_attempt_fix=lambda _progress: "unused",
    )
    try:
        dialog.set_text("Report text remains available for review")
        assert "Red Team Attack" in dialog.windowTitle()
        assert "Report verification failed" in dialog._report_status.text()
        assert dialog._report_status.textFormat() == Qt.PlainText
        assert not dialog._fix_btn.isEnabled()
        assert "Report text remains available" in dialog.body.toPlainText()
    finally:
        dialog.close()
        app.processEvents()


def test_red_team_aar_reload_failure_disables_practice_fix(
    tmp_path, monkeypatch,
) -> None:
    app = _app()
    dialog = AARDialog(
        tmp_path,
        redteam=True,
        report_binding={},
        on_attempt_fix=lambda _progress: "unused",
    )
    try:
        assert "Report text delivered" in dialog._report_status.text()

        def refuse(*_args, **_kwargs):
            raise ValueError("signed pair changed")

        monkeypatch.setattr("angerona.gui.pages._load_verified_aar_text", refuse)
        dialog.refresh()
        assert "signed pair changed" in dialog.body.toPlainText()
        assert "Report verification failed" in dialog._report_status.text()
        assert not dialog._fix_btn.isEnabled()
    finally:
        dialog.close()
        app.processEvents()
