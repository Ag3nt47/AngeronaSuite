"""Readability and disclosure behavior with inert adapters and Qt widgets."""
from types import SimpleNamespace
import os
import socket
import subprocess

import pytest
from PySide6.QtCore import QPoint, QRect, Qt
from PySide6.QtGui import QFontDatabase, QPalette
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QStyle, QStyleOptionButton, QVBoxLayout, QWidget

from angerona.gui.community_tools import CommunityToolsPanel
from angerona.gui.main_window import MainWindow
from angerona.gui.rules_playbooks import RulesPlaybooksPanel
from angerona.gui.theme import FUNCTION_ROLES, build_qss, set_function_role
from test_community_tools_ui import FakeLibrary, FakeTools, retire, wait_until

_APP = None


@pytest.fixture
def app():
    global _APP
    _APP = QApplication.instance() or QApplication([])
    return _APP


@pytest.fixture(autouse=True)
def forbid_host_actions(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Workspace layout tests cannot dispatch host actions")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)


def _inside(panel, widget):
    return panel.rect().contains(QRect(widget.mapTo(panel, QPoint()), widget.size()))


def _text_fits(button):
    option = QStyleOptionButton()
    option.initFrom(button)
    option.text = button.text()
    content = button.style().subElementRect(QStyle.SubElement.SE_PushButtonContents, option, button)
    return button.fontMetrics().horizontalAdvance(button.text()) <= content.width()


@pytest.mark.parametrize("width,scale", [(640, 1.0), (800, 1.0), (1000, 1.25), (1280, 1.0)])
def test_suggested_primary_controls_fit_and_technical_help_is_keyboard_accessible(app, tmp_path, width, scale):
    panel = CommunityToolsPanel(FakeTools(tmp_path))
    panel.setStyleSheet(build_qss(scale=scale))
    panel.resize(width, 700)
    panel.show()
    wait_until(lambda: not panel._operations)
    try:
        for button in (panel.install_button, panel.check_button, panel.uninstall_button, panel.cancel_button):
            assert button.isVisible() and _inside(panel, button)
            assert _text_fits(button)
        assert "not-installed" in panel.summary.text()
        assert "managed-scanner" in panel.summary.text()
        assert not panel.source_details.is_expanded()
        assert not panel.technical_details.is_expanded()
        panel.source_details.toggle.setFocus()
        QTest.keyClick(panel.source_details.toggle, Qt.Key_Return)
        assert panel.source_details.is_expanded() and panel.sandbox_button.isVisible()
        assert panel.source_details.toggle.accessibleName()
        panel.check_button.click()
        wait_until(lambda: not panel._operations)
        assert panel.technical_details.is_expanded()
        assert '"state": "passed"' in panel.detail.toPlainText()
        panel.technical_details.set_expanded(False)
        panel._poll()
        panel._paint()
        assert not panel.technical_details.is_expanded()  # Polls respect an operator's collapse.
    finally:
        retire(panel)


def test_explicit_adapter_failure_keeps_warning_visible_and_opens_exact_record(app, tmp_path):
    service = FakeTools(tmp_path)
    def fail(*_args, **_kwargs):
        raise RuntimeError("Fixture coverage unavailable; no clean result")
    service.self_check = fail
    panel = CommunityToolsPanel(service)
    panel.show()
    wait_until(lambda: not panel._operations)
    try:
        panel.check_button.click()
        wait_until(lambda: not panel._operations)
        assert "coverage unavailable" in panel.status.text()
        assert panel.status.isVisible() and panel.technical_details.is_expanded()
        assert "no clean result" in panel.detail.toPlainText()
    finally:
        retire(panel)


def test_nested_scanner_hold_and_storage_gap_are_visible_without_expanding_json(app, tmp_path):
    service = FakeTools(tmp_path)
    def held(tool):
        service._record("status", tool)
        return {"tool_id": tool, "state": "held", "sandboxes": [], "scanner": {
            "message": "Scanner disabled in saved settings.",
            "execution_hold_reason": "Previous scanner custody remains unresolved.",
            "storage_inventory_error": "Storage inventory unavailable; usage is unknown.",
        }}
    service.status = held
    panel = CommunityToolsPanel(service)
    panel.show()
    wait_until(lambda: not panel._operations)
    try:
        assert not panel.technical_details.is_expanded()
        assert "disabled in saved settings" in panel.summary.text()
        assert "custody remains unresolved" in panel.summary.text()
        assert "usage is unknown" in panel.summary.text()
        assert "Refresh to inspect" not in panel.summary.text()
    finally:
        retire(panel)


def test_tall_suggested_overview_keeps_primary_actions_at_top_and_expanded_record_uses_space(
    app, tmp_path, record_property,
):
    if os.name == "nt":
        from pathlib import Path
        for name in ("segoeui.ttf", "segoeuib.ttf"):
            font = Path("C:/Windows/Fonts") / name
            if font.is_file():
                assert QFontDatabase.addApplicationFont(str(font)) >= 0
    shell = QWidget()
    shell.setStyleSheet(build_qss())
    layout = QVBoxLayout(shell)
    layout.addWidget(QLabel("DEMO · Inert adapter layout · No host actions"))
    panel = CommunityToolsPanel(FakeTools(tmp_path), shell)
    layout.addWidget(panel, 1)
    shell.resize(1440, 960)
    shell.show()
    wait_until(lambda: not panel._operations)
    try:
        overview = panel.tabs.widget(0)
        assert not panel.technical_details.is_expanded()
        assert panel.summary.mapTo(overview, QPoint()).y() <= 24
        action_y = panel.install_button.mapTo(overview, QPoint()).y()
        assert action_y < 200
        assert panel.check_button.isVisible() and panel.uninstall_button.isVisible()
        folded = tmp_path / "suggested-tools-tall-folded-demo.png"
        assert shell.grab().save(str(folded))
        record_property("folded_demo", str(folded))
        panel.technical_details.set_expanded(True)
        app.processEvents()
        assert abs(panel.install_button.mapTo(overview, QPoint()).y() - action_y) <= 2
        assert panel.detail.height() > overview.height() * .5
        expanded = tmp_path / "suggested-tools-tall-expanded-demo.png"
        assert shell.grab().save(str(expanded))
        record_property("expanded_demo", str(expanded))
        panel.technical_details.set_expanded(False)
        app.processEvents()
        assert abs(panel.install_button.mapTo(overview, QPoint()).y() - action_y) <= 2
    finally:
        retire(panel)
        shell.close()
        shell.deleteLater()


@pytest.mark.parametrize("width,scale", [(640, 1.0), (800, 1.0), (1000, 1.25), (1280, 1.0)])
def test_rules_runtime_gaps_results_and_draft_actions_remain_visible(app, width, scale):
    panel = RulesPlaybooksPanel(FakeLibrary(), cfg=SimpleNamespace(
        community_rules_enabled=False, community_playbooks_enabled=False))
    panel.setStyleSheet(build_qss(scale=scale))
    panel.resize(width, 760)
    panel.show()
    wait_until(lambda: panel._operation is None and panel.items.count() == 1)
    try:
        assert panel.global_state.isVisible()
        assert "YARA: OFF" in panel.global_state.text() and "SOAR: OFF" in panel.global_state.text()
        assert panel.runtime_settings_button.isVisible() and _inside(panel, panel.runtime_settings_button)
        assert not panel.workflow_details.is_expanded()
        panel.tabs.setCurrentIndex(1)
        panel.items.setCurrentRow(0)
        wait_until(lambda: panel._operation is None and "condition: false" in panel.editor.toPlainText())
        for button in (panel.save_button, panel.validate_button, panel.test_button, panel.diff_button,
                       panel.activate_button, panel.disable_button, panel.rollback_button, panel.cancel_button):
            assert button.isVisible() and _inside(panel, button)
            assert _text_fits(button)
        panel.activate_button.click()
        wait_until(lambda: panel._operation is None)
        assert panel.tabs.currentWidget() is panel.result_page
        assert panel.test_table.isVisible() and panel.results.isVisible() and panel.status.isVisible()
        assert '"state": "held"' in panel.results.toPlainText()
        assert "stays inactive" in panel.status.text()
    finally:
        retire(panel)


def test_function_roles_preserve_enabled_state_status_color_and_navigation_authority(app):
    owner = QWidget()
    owner._stop_btn, owner._sim_btn, owner._settings_btn = QPushButton("STOP"), QPushButton("Red Team"), QPushButton("Settings")
    status = QLabel("Unavailable")
    status.setStyleSheet("color:#94a3b8")
    owner._stop_btn.setObjectName("Critical")
    owner._stop_btn.setEnabled(False)
    original = status.styleSheet()
    try:
        MainWindow._style_header_functions(owner)
        assert owner._stop_btn.property("functionRole") == "response"
        assert owner._settings_btn.property("functionRole") == "configure"
        assert not owner._stop_btn.isEnabled() and owner._stop_btn.objectName() == "Critical"
        assert status.styleSheet() == original and status.property("functionRole") is None
        assert owner._settings_btn.accessibleDescription().startswith("Function:")
        with pytest.raises(ValueError):
            set_function_role(owner._settings_btn, "trusted")
    finally:
        owner._stop_btn.deleteLater()
        owner._sim_btn.deleteLater()
        owner._settings_btn.deleteLater()
        status.deleteLater()
        owner.deleteLater()


def test_failed_rule_validation_opens_exact_results_without_changing_global_switches(app):
    library = FakeLibrary()
    def fail(*_args, **_kwargs):
        raise RuntimeError("Fixture validation unavailable; data was not activated")
    library.validate = fail
    cfg = SimpleNamespace(community_rules_enabled=False, community_playbooks_enabled=False)
    panel = RulesPlaybooksPanel(library, cfg=cfg)
    panel.show()
    wait_until(lambda: panel._operation is None and panel.items.count() == 1)
    try:
        panel.tabs.setCurrentIndex(1)
        panel.items.setCurrentRow(0)
        wait_until(lambda: panel._operation is None and "condition: false" in panel.editor.toPlainText())
        panel.validate_button.click()
        wait_until(lambda: panel._operation is None)
        assert panel.tabs.currentWidget() is panel.result_page
        assert panel.results.isVisible() and panel.status.isVisible()
        assert "data was not activated" in panel.results.toPlainText()
        assert not cfg.community_rules_enabled and not cfg.community_playbooks_enabled
    finally:
        retire(panel)


@pytest.mark.parametrize("name", ["SectionTitle", "sectionTitle", "PageTitle"])
def test_static_function_headings_have_visible_role_accent_under_actual_theme(app, name):
    label = QLabel("Analysis and research")
    label.setObjectName(name)
    label.setStyleSheet(build_qss())
    try:
        set_function_role(label, "analysis")
        label.ensurePolished()
        assert label.palette().color(QPalette.ColorRole.WindowText).name() == FUNCTION_ROLES["analysis"][0]
        assert label.text() == "Analysis and research"
    finally:
        label.deleteLater()
