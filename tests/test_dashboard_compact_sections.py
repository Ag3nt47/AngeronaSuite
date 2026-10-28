"""Compact evidence workspace geometry with inert Qt widgets only."""
from __future__ import annotations

from types import SimpleNamespace
import os
import socket
import subprocess

import pytest
from PySide6.QtCore import QPoint, QRect, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication, QFrame, QGridLayout, QHBoxLayout, QLabel, QLayout, QPushButton,
    QSizePolicy, QSplitter, QVBoxLayout, QWidget,
)

from angerona.gui.dashboard_sections import (
    DashboardDisclosure, DashboardPanelCollapse, DashboardPanelGroup,
)
from angerona.gui.live_defense_activity import LiveDefenseActivityCard
from angerona.gui.main_window import MainWindow
from angerona.gui.pages import CommandConsolePanel, StatCard
from angerona.gui import system_pulse
from test_dashboard_responsive_shell import _DashboardShell


@pytest.fixture(autouse=True)
def forbid_host_dispatch(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Compact layout tests cannot dispatch host work")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(system_pulse, "_SystemPulseCollector", lambda: lambda: {
        "cpu": 12.0, "ram": 42.0, "available": 4 * 1024**3,
        "wifi": 85, "down": 4096.0, "up": 2048.0,
    })


class _CompactShell(_DashboardShell):
    """Use production resize/disclosure behavior without any runtime owner."""

    def __init__(self, scale=1.0):
        super().__init__()
        self.config.ui_scale_fixed = scale
        layout = self._dashboard_content.layout()
        layout.setSizeConstraint(QLayout.SetNoConstraint)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(7)
        left, brand, right = self._header_groups
        # Represent the real action row's full-label and compact-icon budgets.
        left.setMinimumSize(620 if scale <= 1 else 190, 36)
        brand.setMinimumSize(220 if scale <= 1 else 260, 60)
        right.setMinimumSize(600 if scale <= 1 else 620, 36)
        cards = QWidget()
        card_layout = QGridLayout(cards)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(7)
        for index, (title, value) in enumerate((
            ("Modules running", "55/86"), ("Alerts (24h)", "21362"),
            ("Active critical (10m)", "0"), ("Threat level", "Secure"),
        )):
            card = StatCard(title)
            card.set(value)
            card_layout.addWidget(card, 0, index)
        layout.insertWidget(1, cards)
        for panel in (self.modules_panel, self._right_tabs):
            panel.setMinimumHeight(180)
        old_section = self._console_section
        old_section.setParent(None)
        old_section.deleteLater()
        self.console = CommandConsolePanel(SimpleNamespace(config=SimpleNamespace(aria_enabled=False)))
        self.console.out.setMinimumHeight(40)
        self.console.out.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Ignored)
        events = [SimpleNamespace(ts=1700000000 + index, module="Synthetic sensor", severity=0,
                                  message="Synthetic observable activity") for index in range(5)]
        bus = SimpleNamespace(revision=lambda: 1, recent=lambda _limit: events)
        self.live_defense_activity = LiveDefenseActivityCard(bus, SimpleNamespace(modules={}))
        self.system_pulse = system_pulse.SystemPulseCard()
        self._console_section = QSplitter(Qt.Horizontal)
        for panel in (self.console, self.live_defense_activity, self.system_pulse):
            self._console_section.addWidget(panel)
        self._dashboard_panel_controls = [
            DashboardPanelCollapse(self.console, "incident response console"),
            DashboardPanelCollapse(self.live_defense_activity, "live activity", scroll_body=True),
            DashboardPanelCollapse(self.system_pulse, "system pulse", scroll_body=True),
        ]
        for control in self._dashboard_panel_controls:
            control.collapsed_changed.connect(lambda _value: self._resize_timer.start())
        self._operations_disclosure = DashboardPanelGroup(self._console_section, self._dashboard_panel_controls)
        self._body_splitter.addWidget(self._console_section)
        self._body_splitter.setChildrenCollapsible(False)
        self._body_splitter.setStretchFactor(0, 3)
        self._body_splitter.setStretchFactor(1, 1)
        self._body_splitter.setSizes([520, 180])
        self._operations_disclosure.expanded_changed.connect(self._on_operations_expanded)
        ribbons = QWidget()
        row = QVBoxLayout(ribbons)
        row.setContentsMargins(0, 0, 0, 0)
        for text in ("Health chips", "Estimated activity chips"):
            label = QLabel(text)
            label.setMinimumHeight(60)
            row.addWidget(label)
        self._module_ribbons_disclosure = DashboardDisclosure(
            "Module health & activity", ribbons, "55/86 live")
        layout.insertWidget(layout.count() - 1, self._module_ribbons_disclosure)
        self._module_ribbons_disclosure.expanded_changed.connect(
            lambda _expanded: self._resize_timer.start())
        ai = QLabel("Local AI is off while Chill Mode is enabled")
        ai.setFixedHeight(24)
        self.footer.setFixedHeight(32)
        layout.insertWidget(layout.count() - 1, ai)


def settle(window):
    window._apply_dashboard_layout()
    QApplication.processEvents()
    window._resize_timer.stop()


@pytest.mark.parametrize("width,height,scale", [
    (1280, 720, 1.0), (1366, 768, 1.0), (1920, 1080, 1.0), (1280, 720, 1.25),
])
def test_all_panels_open_with_only_module_health_folded_and_fit_desktop_work_areas(width, height, scale):
    window = _CompactShell(scale)
    try:
        window.resize(width, height)
        window.show()
        settle(window)
        top, bottom = window._body_splitter.sizes()
        assert top >= 180
        assert top > bottom
        assert window._operations_disclosure.is_expanded()
        assert all(not control.is_collapsed() for control in window._dashboard_panel_controls)
        assert all(control.view.isVisible() for control in window._dashboard_panel_controls)
        assert not window._module_ribbons_disclosure.content.isVisible()
        scroll = window.centralWidget()
        scroll.ensureWidgetVisible(window.footer, 0, 0)
        QApplication.processEvents()
        footer = QRect(window.footer.mapTo(scroll.viewport(), QPoint()), window.footer.size())
        assert scroll.viewport().rect().contains(footer)
        assert scroll.verticalScrollBar().maximum() == 0
    finally:
        window.system_pulse.shutdown()
        assert window.system_pulse._sampler.retired.wait(2)
        window._resize_timer.stop()
        window.close()
        window.deleteLater()


def test_individual_minimize_buttons_preserve_records_and_restore_without_hiding_other_panels():
    window = _CompactShell()
    try:
        window.resize(1280, 720)
        window.show()
        settle(window)
        control = window._dashboard_panel_controls[0]
        original = window.console.out.toPlainText()
        control._minimize_button.setFocus()
        QTest.keyClick(control._minimize_button, Qt.Key_Return)
        settle(window)
        assert control.is_collapsed()
        assert not control.view.isVisible()
        assert window.live_defense_activity.isVisible() and window.system_pulse.isVisible()
        assert window.console.out.toPlainText() == original
        QTest.keyClick(control._minimize_button, Qt.Key_Space)
        settle(window)
        assert not control.is_collapsed()
        assert control.view.isVisible()
        assert window.centralWidget().verticalScrollBar().maximum() == 0
        assert window._top_splitter.height() >= 180
    finally:
        window.system_pulse.shutdown()
        assert window.system_pulse._sampler.retired.wait(2)
        window._resize_timer.stop()
        window.close()
        window.deleteLater()


def test_minimize_reuses_existing_heading_and_preserves_conditional_child_visibility():
    panel = QFrame()
    layout = QVBoxLayout(panel)
    title_row = QHBoxLayout()
    title = QPushButton("Details")
    opened = []
    title.clicked.connect(lambda: opened.append(True))
    title_row.addWidget(title)
    layout.addLayout(title_row)
    body_row = QHBoxLayout()
    active, conditional = QLabel("Existing record"), QLabel("Conditional record")
    conditional.hide()
    body_row.addWidget(active)
    body_row.addWidget(conditional)
    layout.addLayout(body_row)
    control = DashboardPanelCollapse(panel, "synthetic panel", scroll_body=True)
    try:
        assert layout.count() == 2
        assert control.header is title_row
        assert not active.isHidden()
        assert conditional.isHidden()
        control.set_collapsed(True)
        conditional.show()  # A producer may update its own presentation state.
        control.set_collapsed(False)
        assert not conditional.isHidden()
        assert active.text() == "Existing record"
        QTest.keyClick(title, Qt.Key_Space)
        assert opened == [True]
    finally:
        panel.close()
        panel.deleteLater()


def test_folded_coverage_summary_keeps_critical_and_degraded_states_visible():
    content = QLabel("Full module coverage")
    disclosure = DashboardDisclosure("Module health & activity", content)
    strip = SimpleNamespace(
        _summary=SimpleNamespace(text=lambda: "55/86 live"),
        _prev={"one": ("critical", "25%", "limited"), "two": ("failed", "0%", "unavailable"),
               "three": ("degraded", "70%", "partial"), "four": ("off", "OFF", "disabled")},
    )
    owner = SimpleNamespace(_module_ribbons_disclosure=disclosure, status_strip=strip)
    try:
        MainWindow._update_module_ribbon_summary(owner)
        assert "2 critical/failed" in disclosure._summary.toolTip()
        assert "1 degraded" in disclosure._summary.toolTip()
        assert "55/86 live" in disclosure._summary.toolTip()
        assert "#ef4444" in disclosure._summary.styleSheet()
        assert not disclosure.is_expanded()
    finally:
        disclosure.close()
        disclosure.deleteLater()


def test_disclosure_preserves_full_summary_for_accessibility_and_changes_presentation_only():
    content = QLabel("Original records remain")
    section = DashboardDisclosure("Operations", content, "A detailed summary " * 12)
    try:
        section.resize(440, 40)
        section.show()
        QApplication.processEvents()
        assert section._summary.toolTip() == "A detailed summary " * 12
        assert section._summary.accessibleName() == section._summary.toolTip()
        assert section._summary.text() != section._summary.toolTip()
        section.set_expanded(True)
        assert section.content is content
        assert content.text() == "Original records remain"
        section.set_expanded(False)
        assert content.text() == "Original records remain"
    finally:
        section.close()
        section.deleteLater()
