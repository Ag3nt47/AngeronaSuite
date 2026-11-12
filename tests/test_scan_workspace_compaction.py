"""Inert public controls retain scan evidence, warnings and keyboard access."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtCore import QPoint, QRect, Qt, Signal
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMainWindow, QScrollArea, QWidget

from angerona.gui import github_tools
from angerona.gui.aar_history import HistoryListing
from angerona.gui.curated_tools import SpywareScanControls
from angerona.gui.red_team_console import RedTeamConsole
from angerona.gui.spyware_guard_page import SpywareGuardPage
from angerona.gui.theme import build_qss
from test_spyware_scan_presentation import memory as memory, progress


def settle():
    for _ in range(8):
        QApplication.processEvents()


def inside(widget, owner):
    assert owner.rect().contains(QRect(widget.mapTo(owner, QPoint()), widget.size()))


def test_spyware_primary_sections_keep_warnings_and_actions_outside_setup(memory):
    controller, manager, _config, module = memory
    panel = SpywareScanControls(manager)
    panel.resize(760, 900)
    panel.show()
    try:
        settle()
        assert not panel.setup_toggle.isChecked()
        assert panel.explanation_group.isVisible() and panel.resource_group.isVisible()
        assert panel.progress_group.property("functionRole") == "monitor"
        assert panel.cancel_button.property("functionRole") == "response"
        assert panel.activity.parentWidget() is panel.explanation_group
        assert panel.current_file.parentWidget() is panel.explanation_group
        panel.setup_toggle.click()
        panel.setup_toggle.click()
        controller.publish(state="failed", busy=False, lifecycle="terminal", coverage_incomplete=True,
                           message="Fixture coverage incomplete", scan_progress=progress())
        settle()
        assert panel.setup_body.isHidden()
        assert panel.hits.isVisible() and panel.outcome.isVisible() and panel.stage_explanation.isVisible()
        assert "Fixture coverage incomplete" in panel.outcome.text()
        assert panel.privileges.isVisible() and panel.cancel_button.isVisible()
        assert not panel.cancel_button.isEnabled()
        panel.cancel_button.click()
        assert controller.cancels == 0
        controller.publish(state="running", busy=True, lifecycle="running", scan_progress=progress())
        settle()
        assert not panel.setup_toggle.isChecked() and panel.cancel_button.isEnabled()
        panel.cancel_button.click()
        assert controller.cancels == 1
        assert not controller.requests and not module.calls
    finally:
        panel.close()


@pytest.mark.parametrize("width,scale", [(360, 1.0), (640, 1.4)])
def test_spyware_counts_are_primary_and_news_prose_is_explicitly_expandable(memory, width, scale):
    controller, manager, config, module = memory
    page = SpywareGuardPage(manager, config, None)
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setWidget(page)
    area.setStyleSheet(build_qss(scale=scale))
    area.resize(width, 700)
    area.show()
    try:
        settle()
        page._timer.stop()
        page._news_rotation_timer.stop()
        page._news_scroll_timer.stop()
        assert page.stats.parentWidget() is page.priority_scan.progress_group
        assert "Recent native records" in page.stats.text()
        assert not page.news_feed_details.isChecked() and not page.news_summary.isVisible()
        page.news_feed_details.click()
        settle()
        assert page.news_summary.isVisible()
        page.news_feed_details.click()
        page.refresh()
        settle()
        assert not page.news_summary.isVisible()
        assert area.horizontalScrollBar().maximum() == 0
        inside(page.scan_button, page)
        assert "#b91c1c" in page.scan_button.styleSheet()
        page.scan_button.click()
        assert len(controller.requests) == 1
        assert controller.requests[0]["mode"] == "full"
        assert not module.calls
    finally:
        area.close()


class _Parent(QMainWindow):
    _shark_narration = Signal(str)

    def __init__(self):
        super().__init__()
        self.config = SimpleNamespace(ui_motion_enabled=False)
        self._red_team_remote_backend = SimpleNamespace(
            response_readiness=lambda _process: {
                "ready": False, "state": "HELD", "reason": "Fixture coverage incomplete.",
            },
            history=lambda _operation, _name: HistoryListing([]),
        )

    @staticmethod
    def _qss():
        return build_qss()


class _InertTools(QWidget):
    def cancel_pending(self):
        pass


@pytest.mark.parametrize("width,scale", [(700, 1.0), (1040, 1.25)])
def test_redteam_setup_is_keyboard_accessible_while_progress_target_and_warnings_stay_visible(
    memory, monkeypatch, tmp_path, width, scale,
):
    launches, stops = [], []
    monkeypatch.setattr(github_tools, "GitHubToolsPanel", _InertTools)
    monkeypatch.setattr(RedTeamConsole, "_launch", lambda self: launches.append(True))
    monkeypatch.setattr(RedTeamConsole, "_stop", lambda self: stops.append(True))
    parent = _Parent()
    target = str(tmp_path / "drill-sandbox")
    dialog = RedTeamConsole(parent, default_target=target)
    dialog.setStyleSheet(build_qss(scale=scale))
    dialog.resize(width, 800)
    dialog.show()
    try:
        settle()
        # First show fits the actual available workarea; requested width is
        # not a promise to extend beyond a smaller CI/offscreen screen.
        available = dialog.screen().availableGeometry()
        assert available.contains(dialog.frameGeometry())
        assert 0 < dialog.width() <= width
        assert not dialog.setup_disclosure.is_expanded()
        assert dialog.setup_disclosure.toggle.accessibleName() == "Simulation setup: expand details"
        assert not dialog.cb_shark.isVisible()
        for widget in (dialog.overall_progress, dialog.performance_badge, dialog.target_summary,
                       dialog.response_readiness, dialog.cb_remediate, dialog.launch_btn, dialog.stop_btn):
            assert widget.isVisible()
            inside(widget, dialog)
        assert target in dialog.target_summary.text()
        assert "HELD" in dialog.response_readiness.text()
        for label in (dialog.target_summary, dialog.response_readiness):
            assert label.height() >= label.heightForWidth(label.width())
        dialog.setup_disclosure.toggle.setFocus()
        QTest.keyClick(dialog.setup_disclosure.toggle, Qt.Key.Key_Space)
        settle()
        assert dialog.setup_disclosure.is_expanded() and dialog.cb_shark.isVisible()
        for widget in (dialog.target_summary, dialog.response_readiness,
                       dialog.launch_btn, dialog.stop_btn):
            assert widget.isVisible()
            inside(widget, dialog)
        assert dialog.response_readiness.height() >= dialog.response_readiness.heightForWidth(
            dialog.response_readiness.width(),
        )
        assert dialog.sld.minimum() == 0 and dialog.sld.maximum() == 3
        assert dialog.launch_btn.text() == "▶  Launch simulation"
        dialog.sld.setValue(0)
        dialog.loc_edit.setText(target + "-changed")
        assert "Low" in dialog.setup_disclosure._summary_text
        assert target + "-changed" in dialog.target_summary.text()
        dialog.setup_disclosure.toggle.click()
        dialog.set_launch_status({"status": "rejected", "reason": "Fixture source coverage held"})
        settle()
        assert not dialog.setup_disclosure.is_expanded()
        assert "Fixture source coverage held" in dialog.workflow_detail.text()
        assert dialog.response_readiness.isVisible()
        assert dialog.launch_btn.property("functionRole") == "response"
        assert "#b91c1c" in dialog.launch_btn.styleSheet()
        dialog.launch_btn.click()
        dialog.stop_btn.click()
        assert launches == [True] and stops == [True]
    finally:
        dialog.close()
        parent.close()
