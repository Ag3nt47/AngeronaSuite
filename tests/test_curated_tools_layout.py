"""Compact tool and header geometry using synthetic in-memory publications."""
from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path
import sys

import pytest
from PySide6.QtCore import QObject, QPoint, QRect, QTimer, Signal
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QApplication, QGridLayout, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget

from angerona.gui.animations import GlobalLoadingIndicator, HeaderActivityLane, RunSpinner
from angerona.gui.curated_tools import CuratedScannerWidget
from angerona.gui.header_controls import HeaderActionButton, NotificationHeaderButton
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
        first, last = QHBoxLayout(left), QGridLayout(right)
        for layout in (first, last):
            layout.setContentsMargins(0, 0, 0, 0)
        last.setColumnStretch(0, 1)
        self._header_primary_buttons = []
        for label, kind in (("ADAPTATION", "adaptation"), ("SELF-TEST", "selftest"),
                            ("RED TEAM SIMULATION", "simulation"), ("CHILL MODE", "eco")):
            button = HeaderActionButton(label, kind, label, "Synthetic header")
            self._header_primary_buttons.append(button)
            first.addWidget(button)
        first.addStretch(1)
        self._header_nav_buttons = []
        for label, kind in (("WORLD VIEW", "world"), ("ATT&CK MAP", "attack"), ("THREAT INTEL", "intel"),
                            ("SPYWAREGUARD", "spyware"), ("GITHUB TOOLS", "github"), ("FORENSICS", "forensics"),
                            ("LOCAL SOC", "operations"), ("CONSOLE", "console"), ("SETUP", "setup"),
                            ("HELP", "help"), ("NOTIFICATIONS", "mail"), ("SETTINGS", "settings")):
            button = (NotificationHeaderButton() if kind == "mail"
                      else HeaderActionButton(label, kind, label.title(), "Synthetic header"))
            if kind == "spyware":
                self._spyware_guard_btn = button
            if kind == "github":
                self.github = button
            self._header_nav_buttons.append(button)
        self._header_stop_button = HeaderActionButton("STOP", "stop", "Stop", "Synthetic header")
        self._header_nav_columns = len(self._header_nav_buttons) + 1
        for column, button in enumerate((*self._header_nav_buttons, self._header_stop_button), 1):
            last.addWidget(button, 0, column)
        center = QVBoxLayout(brand)
        center.setContentsMargins(0, 0, 0, 0)
        center.addWidget(QLabel("A N G E R O N A"))
        center.addWidget(QLabel("POSTURE 86 · Secure"))
        self._header_groups = (left, brand, right)
        self.run_spinner = RunSpinner(bounded_text=True)
        self.loading_indicator = GlobalLoadingIndicator()
        self._header_activity_box = HeaderActivityLane(self.run_spinner, self.loading_indicator)
        self._dashboard_content.layout().insertWidget(1, self._header_activity_box)
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


def _assert_header_geometry(shell):
    viewport = shell.centralWidget().viewport()
    buttons = shell._header_primary_buttons + shell._header_nav_buttons + [shell._header_stop_button]
    rectangles = []
    for button in buttons:
        group = button.parentWidget()
        assert group.rect().contains(button.geometry()), button.accessibleName()
        rectangle = QRect(button.mapTo(viewport, QPoint()), button.size())
        assert viewport.rect().left() <= rectangle.left() <= rectangle.right() <= viewport.rect().right()
        assert button.width() >= 32 and button.height() >= 32
        assert not any(rectangle.intersects(other) for other in rectangles)
        rectangles.append(rectangle)
    lane = shell._header_activity_box
    if lane.isVisible():
        lane_rect = QRect(lane.mapTo(viewport, QPoint()), lane.size())
        assert viewport.rect().left() <= lane_rect.left() <= lane_rect.right() <= viewport.rect().right()
        assert not any(lane_rect.intersects(QRect(group.mapTo(viewport, QPoint()), group.size()))
                       for group in shell._header_groups)
        indicators = [indicator for indicator in (shell.run_spinner, shell.loading_indicator)
                      if indicator.isVisible()]
        for index, indicator in enumerate(indicators):
            assert lane.rect().contains(indicator.geometry())
            assert not any(indicator.geometry().intersects(other.geometry())
                           for other in indicators[index + 1:])
            assert indicator.rect().contains(indicator._ring.geometry())
            label = indicator._label
            assert indicator.rect().contains(label.geometry())
            assert label.fontMetrics().horizontalAdvance(label.text()) <= label.contentsRect().width()


@pytest.mark.parametrize("width,scale", [(480, 1.0), (700, 1.0), (1599, 1.0), (1599, 1.35), (2560, 1.35)])
def test_live_header_activity_elides_after_show_without_overlapping_actions(width, scale):
    shell = HeaderShell(scale)
    shell.resize(width, 800)
    shell._apply_dashboard_layout()
    shell.show()
    for _ in range(4):
        QApplication.processEvents()
    shell._resize_timer.stop()
    root = shell._dashboard_content.layout()
    idle_minimum = root.minimumSize().height()
    timer_count = len(shell.findChildren(QTimer))
    try:
        assert shell._header_activity_box.isHidden()
        _assert_header_geometry(shell)
        shell.run_spinner.start("Starting")
        indicator = shell.loading_indicator
        indicator._on_started("first", "First pending activity", 1, 4)
        indicator._on_started("second", "Reading", 1, 4)
        indicator._reveal_if_active()
        # Change content at the same shown width, without a layout call or
        # resize. The former brand-owned full text enlarged the action grid.
        for text in ("Reading", "Bringing protection modules online; collecting local diagnostics " * 12, "Ready"):
            shell.run_spinner.set_text(text)
            indicator._on_updated("second", text, 1, 4)
            for _ in range(4):
                QApplication.processEvents()
            assert shell._header_activity_box.isVisible()
            assert shell.run_spinner.isVisible() and indicator.isVisible()
            assert indicator.active_count == 2
            assert shell.run_spinner.current_text == text + "  0%"
            assert indicator.current_text == text + "  1/4  (+1)"
            for activity in (shell.run_spinner, indicator):
                assert activity.toolTip() == activity.current_text
                assert activity.accessibleDescription() == activity.current_text
                assert activity._label.accessibleName() == activity.current_text
                if activity._label.fontMetrics().horizontalAdvance(activity.current_text) > activity._label.width():
                    assert activity._label.text() != activity.current_text
                    assert activity._label.text().endswith("…")
            assert len(shell.findChildren(QTimer)) == timer_count
            _assert_header_geometry(shell)
        indicator._on_finished("second")
        assert indicator.active_count == 1 and not indicator.isHidden()
        indicator._on_finished("first")
        assert not shell._header_activity_box.isHidden()
        shell.run_spinner.stop()
        for _ in range(4):
            QApplication.processEvents()
        assert shell._header_activity_box.isHidden()
        assert root.minimumSize().height() == idle_minimum
        _assert_header_geometry(shell)
    finally:
        for timer in shell.findChildren(QTimer):
            timer.stop()
        shell.close()
        shell.deleteLater()


def test_wide_header_rechecks_fresh_brand_minimum_after_font_change():
    shell = HeaderShell(1.0)
    # Keep the viewport fixed while its children ask for more space, as on a
    # screen-bounded desktop. Letting the shell grow would change the stimulus.
    shell.setFixedSize(1920, 800)
    shell._apply_dashboard_layout()
    shell.show()
    for _ in range(4):
        QApplication.processEvents()
    try:
        assert shell._header_layout_mode == "wide"
        brand_label = shell._header_groups[1].layout().itemAt(0).widget()
        original_text, original_font = brand_label.text(), brand_label.font()
        original_style = brand_label.styleSheet()
        large = QFont(original_font)
        large.setPixelSize(72)
        brand_label.setFont(large)
        # The theme has a universal font-size rule, which overrides setFont.
        # Apply a local style and prove the actual allocation changed.
        brand_label.setStyleSheet(original_style + ";font-size:72px;")
        brand_label.ensurePolished()
        assert brand_label.font().pixelSize() == 72
        enlarged_text = original_text
        available = shell.width() - 80
        spacing = max(0, shell._header_layout.horizontalSpacing()) * 2
        for _ in range(128):
            brand_label.setText(enlarged_text)
            shell._apply_dashboard_layout()
            for _ in range(4):
                QApplication.processEvents()
            minima = [max(group.minimumWidth(), group.minimumSizeHint().width(),
                          group.layout().minimumSize().width()) for group in shell._header_groups]
            # The side groups can compact as the title grows. A title wider
            # than its old allocation alone does not exhaust the wide budget.
            if sum(minima) + spacing > available:
                break
            enlarged_text += " A"
        else:
            pytest.fail("The fixture could not exceed the measured wide header budget")
        assert shell.width() == 1920
        assert sum(minima) + spacing > available
        assert minima[1] <= available
        assert minima[0] + minima[2] + spacing <= available
        assert shell._header_layout_mode == "two"
        _assert_header_geometry(shell)
        brand_label.setStyleSheet(original_style)
        brand_label.setFont(original_font)
        brand_label.setText(original_text)
        shell._apply_dashboard_layout()
        for _ in range(4):
            QApplication.processEvents()
        assert shell._header_layout_mode == "wide"
        _assert_header_geometry(shell)
    finally:
        shell._resize_timer.stop()
        shell.close()
        shell.deleteLater()
