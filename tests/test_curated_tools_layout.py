"""Compact tool and header geometry using synthetic in-memory publications."""
from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path
import sys

import pytest
from PySide6.QtCore import QObject, QPoint, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import QApplication, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget

from angerona.gui.curated_tools import CuratedScannerWidget
from angerona.gui.header_controls import HeaderActionButton
from angerona.gui.theme import build_qss
from test_dashboard_responsive_shell import _DashboardShell


@pytest.fixture(scope="module", autouse=True)
def readable_offscreen_fonts():
    # Qt's Windows offscreen plugin need not discover the native font store.
    # Use existing system fonts so layout checks measure real text, not tofu.
    if sys.platform == "win32":
        for filename in ("segoeui.ttf", "segoeuib.ttf", "consola.ttf", "seguiemj.ttf"):
            path = Path("C:/Windows/Fonts") / filename
            if path.is_file():
                assert QFontDatabase.addApplicationFont(str(path)) >= 0


class MemoryController(QObject):
    status_changed = Signal(dict)
    credits_ready = Signal(object)
    settings_saved = Signal()

    def __init__(self):
        super().__init__()
        self.manager = SimpleNamespace(cfg=SimpleNamespace())
        self._closed = False

    def snapshot(self):
        return dict(state="ready", installed=True, verified=True, version="0.1.10", busy=False,
                    message="DEMO — synthetic scanner publication; no host scan.",
                    coverage={"checked": ["Synthetic process and browser records"], "not_checked": ["Encrypted phone backup"]})

    def prepare(self): pass
    def scan(self, **_kwargs): pass
    def priority_scan(self, **_kwargs): pass
    def cancel(self): pass
    def load_credits(self): pass
    def self_test(self): pass
    def open_tool(self): pass
    def revert(self): pass
    def save_options(self, _values): pass
    def clear_reports(self): pass


@pytest.mark.parametrize("width,height,scale", [(1280, 780, 1.0), (1366, 768, 1.0), (640, 520, 1.0), (640, 520, 1.35)])
def test_tool_controls_stay_inside_scrolling_viewport(width, height, scale):
    controller = MemoryController()
    widget = CuratedScannerWidget(controller.manager, controller=controller)
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setWidget(widget)
    area.setStyleSheet(build_qss(scale=scale))
    area.resize(width, height)
    area.show()
    for _ in range(4):
        QApplication.processEvents()
    try:
        assert area.horizontalScrollBar().maximum() == 0, {
            "widget": (widget.width(), widget.minimumSizeHint().width()),
            "primary": widget._primary_actions.minimumSize().width(),
            "secondary": widget._secondary_actions.minimumSize().width(),
            "children": sorted([(type(child).__name__, child.objectName(), child.minimumSizeHint().width(),
                                  child.text()[:40] if hasattr(child, "text") else "")
                                 for child in widget.findChildren(QWidget) if child.parentWidget() is widget and not child.isHidden()],
                                key=lambda row: row[2], reverse=True)[:5],
        }
        for button in (widget.install_button, widget.run_button, widget.priority_button, widget.cancel_button,
                       widget.credits_button, widget.settings_button, widget.analysis_button, widget.advanced_button):
            assert button.width() >= 32
            assert button.mapTo(widget, QPoint()).x() >= 0
            assert button.mapTo(widget, QPoint()).x() + button.width() <= widget.width()
        assert not widget.options.isVisible()
    finally:
        area.close()
        area.deleteLater()


class HeaderShell(_DashboardShell):
    def __init__(self, scale):
        super().__init__()
        self.config.ui_scale_fixed = scale
        self._ui_scale = scale
        for old in self._header_groups:
            old.deleteLater()
        left, brand, right = QWidget(), QWidget(), QWidget()
        first, last = QHBoxLayout(left), QHBoxLayout(right)
        for layout in (first, last):
            layout.setContentsMargins(0, 0, 0, 0)
        self._header_primary_buttons = []
        for label, kind in (("ADAPTATION", "adaptation"), ("SELF-TEST", "selftest"),
                            ("RED TEAM SIMULATION", "simulation"), ("CHILL MODE", "eco")):
            button = HeaderActionButton(label, kind, label, "Synthetic header")
            self._header_primary_buttons.append(button)
            first.addWidget(button)
        self._header_nav_buttons = []
        for label, kind in (("WORLD VIEW", "world"), ("ATT&CK MAP", "attack"), ("THREAT INTEL", "intel"),
                            ("SPYWAREGUARD", "spyware"), ("GITHUB TOOLS", "github"), ("FORENSICS", "forensics"),
                            ("LOCAL SOC", "operations"), ("CONSOLE", "console"), ("SETUP", "setup"),
                            ("HELP", "help"), ("SETTINGS", "settings")):
            button = HeaderActionButton(label, kind, label.title(), "Synthetic header")
            if kind == "spyware":
                self._spyware_guard_btn = button
            if kind == "github":
                self.github = button
            self._header_nav_buttons.append(button)
            last.addWidget(button)
        self._header_stop_button = HeaderActionButton("STOP", "stop", "Stop", "Synthetic header")
        last.addWidget(self._header_stop_button)
        center = QVBoxLayout(brand)
        center.setContentsMargins(0, 0, 0, 0)
        center.addWidget(QLabel("A N G E R O N A"))
        center.addWidget(QLabel("POSTURE 86 · Secure"))
        self._header_groups = (left, brand, right)
        self.setStyleSheet(build_qss(scale=scale))


@pytest.mark.parametrize("width,scale", [(1280, 1.0), (1366, 1.0), (1920, 1.0), (1280, 1.35)])
def test_added_github_navigation_remains_reachable_in_real_header_budget(width, scale):
    shell = HeaderShell(scale)
    shell.resize(width, 800)
    shell._apply_dashboard_layout()
    shell.show()
    for _ in range(3):
        QApplication.processEvents()
    try:
        buttons = shell._header_primary_buttons + shell._header_nav_buttons + [shell._header_stop_button]
        for button in buttons:
            origin = button.mapTo(shell, QPoint())
            assert origin.x() >= 0
            assert origin.x() + button.width() <= shell.width()
        assert shell.github.isVisible()
        assert shell.github.width() >= 32
    finally:
        shell._resize_timer.stop()
        shell.close()
        shell.deleteLater()
