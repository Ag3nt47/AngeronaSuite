"""Compact tool and header geometry using synthetic in-memory publications."""
from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path
import sys

import pytest
from PySide6.QtCore import QObject, QPoint, QPointF, QRect, QTimer, Qt, Signal
from PySide6.QtGui import QFontDatabase, QWheelEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QGridLayout, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget

from angerona.gui.animations import GlobalLoadingIndicator, HeaderActivityLane, RunSpinner
from angerona.gui.curated_tools import CuratedScannerWidget
from angerona.gui.header_controls import CurrentAssessmentBanner, HeaderActionButton, NotificationHeaderButton
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
            if kind == "simulation":
                button.setObjectName("Danger")
            self._header_primary_buttons.append(button)
            first.addWidget(button)
        first.addStretch(1)
        self._header_nav_buttons = []
        for label, kind in (("SUITE MAP · 3D", "world"), ("WORLD VIEW", "world"),
                            ("ATT&CK MAP", "attack"), ("THREAT INTEL", "intel"),
                            ("SPYWAREGUARD", "spyware"), ("LOCAL SOC", "operations"),
                            ("FORENSICS", "forensics"), ("RULES & PLAYBOOKS", "console"),
                            ("GITHUB TOOLS", "github"), ("CONSOLE", "console"),
                            ("NOTIFICATIONS", "mail"), ("SETUP", "setup"),
                            ("SETTINGS", "settings"), ("HELP", "help")):
            button = (NotificationHeaderButton() if kind == "mail"
                      else HeaderActionButton(label, kind, label.title(), "Synthetic header"))
            if kind == "spyware":
                self._spyware_guard_btn = button
                button.setObjectName("SpywareGuardShortcut")
                button.setStyleSheet(
                    "QPushButton { background:#e2e8f0; color:#000000; font-weight:800; "
                    "border:2px solid #94a3b8; border-radius:6px; padding:7px 12px; } "
                    "QPushButton:hover { background:#ffffff; border-color:#64748b; } "
                    "QPushButton:disabled { background:#94a3b8; color:#334155; }"
                )
            if kind == "github":
                self.github = button
            self._header_nav_buttons.append(button)
        self._header_stop_button = HeaderActionButton("STOP", "stop", "Stop", "Synthetic header")
        self._header_stop_button.setObjectName("Critical")
        self._header_nav_columns = len(self._header_nav_buttons) + 1
        self._place_header_navigation(
            last, (*self._header_nav_buttons, self._header_stop_button), self._header_nav_columns)
        center = QVBoxLayout(brand)
        center.setContentsMargins(0, 0, 0, 0)
        brand_label = QLabel("ANGERONA")
        brand_label.setObjectName("Brand")
        brand_label.setAlignment(Qt.AlignCenter)
        center.addWidget(brand_label)
        posture = QLabel("POSTURE 86 · Secure")
        posture.setObjectName("Tagline")
        posture.setAlignment(Qt.AlignCenter)
        center.addWidget(posture)
        center.addWidget(CurrentAssessmentBanner(brand))
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
            if button is not shell._header_stop_button:
                shell._header_action_strip.ensureWidgetVisible(button, 0, 0)
                QApplication.processEvents()
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
    strip = shell._header_action_strip
    content = strip.widget()
    controls = shell._header_primary_buttons + shell._header_nav_buttons
    rectangles = []
    for button in controls:
        assert button.parentWidget().rect().contains(button.geometry()), button.accessibleName()
        rectangle = QRect(button.mapTo(content, QPoint()), button.size())
        assert button.width() >= 32 and button.height() >= 32
        assert not any(rectangle.intersects(other) for other in rectangles)
        rectangles.append(rectangle)
    assert len({rectangle.top() for rectangle in rectangles}) == 1
    row = shell._header_control_row
    stop = shell._header_stop_button
    stop_rect = QRect(stop.mapTo(row, QPoint()), stop.size())
    strip_rect = QRect(strip.mapTo(row, QPoint()), strip.size())
    assert row.rect().contains(stop_rect) and row.rect().contains(strip_rect)
    assert not strip_rect.intersects(stop_rect)
    assert stop.text() == "STOP" and not stop.is_compact()
    assert shell._header_layout_mode == "single-row"
    brand = shell._header_groups[1]
    assert brand.mapTo(viewport, QPoint(0, brand.height())).y() <= row.mapTo(viewport, QPoint()).y()
    # Overflow stays clipped in this one row and can be revealed without moving STOP.
    for button in controls:
        strip.ensureWidgetVisible(button, 0, 0)
        QApplication.processEvents()
        rectangle = QRect(button.mapTo(strip.viewport(), QPoint()), button.size())
        assert strip.viewport().rect().contains(rectangle), repr({"button": button.accessibleName(),
            "button_rect": rectangle, "strip": strip.size(), "viewport": strip.viewport().size(),
            "content": content.size(), "row_minimum": strip._row.minimumSize(),
            "group_minima": [group.minimumSizeHint() for group in strip._groups],
            "group_rects": [group.geometry() for group in strip._groups],
            "content_rect": content.contentsRect(), "row_rect": strip._row.geometry(),
            "group_layout_rects": [group.layout().geometry() for group in strip._groups],
            "frame": strip.frameWidth(), "scroll_max": strip.horizontalScrollBar().maximum()})
        assert QRect(stop.mapTo(viewport, QPoint()), stop.size()).right() <= viewport.rect().right()
    lane = shell._header_activity_box
    if lane.isVisible():
        lane_rect = QRect(lane.mapTo(viewport, QPoint()), lane.size())
        assert viewport.rect().left() <= lane_rect.left() <= lane_rect.right() <= viewport.rect().right()
        assert not lane_rect.intersects(QRect(row.mapTo(viewport, QPoint()), row.size()))
        assert not lane_rect.intersects(QRect(brand.mapTo(viewport, QPoint()), brand.size()))
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


@pytest.mark.parametrize("width", [640, 800, 1280, 1920])
@pytest.mark.parametrize("scale", [0.75, 1.0, 1.35])
def test_grouped_header_keeps_all_controls_stop_and_keyboard_order_reachable(width, scale):
    shell = HeaderShell(scale)
    shell.resize(width, 800)
    shell._apply_dashboard_layout()
    shell.show()
    for _ in range(4):
        QApplication.processEvents()
    try:
        shell._resize_timer.stop()
        _assert_header_geometry(shell)
        buttons = shell._header_primary_buttons + shell._header_nav_buttons + [shell._header_stop_button]
        assert len(buttons) == len(set(buttons)) == 19
        layout = shell._header_groups[2].layout()
        assert layout.indexOf(shell._header_stop_button) == -1
        assert {layout.getItemPosition(layout.indexOf(button))[0]
                for button in shell._header_nav_buttons} == {0}
        assert shell._header_stop_button.parentWidget() is shell._header_control_row
        for first, second in zip(buttons, buttons[1:]):
            first.setFocus(Qt.OtherFocusReason)
            QTest.keyClick(first, Qt.Key_Tab)
            assert QApplication.focusWidget() is second
            QApplication.processEvents()
            if second is not shell._header_stop_button:
                strip = shell._header_action_strip
                rectangle = QRect(second.mapTo(strip.viewport(), QPoint()), second.size())
                assert strip.viewport().rect().contains(rectangle), second.accessibleName()
        clicked = []
        for index, button in enumerate(buttons):
            button.clicked.connect(lambda _checked=False, number=index: clicked.append(number))
            button.click()
        assert clicked == list(range(19))  # Inert signals only; no production actions.
    finally:
        shell._resize_timer.stop()
        shell.close()
        shell.deleteLater()


@pytest.mark.parametrize("width", [640, 800, 1280, 1366, 1600, 1920])
@pytest.mark.parametrize("scale", [0.75, 1.05, 1.35])
def test_polished_header_keeps_stop_and_fitting_semantic_labels_complete(width, scale):
    """The real Danger/Critical/Spyware styles must not shorten useful labels."""
    shell = HeaderShell(scale)
    shell.resize(width, 800)
    shell._apply_dashboard_layout()
    shell.show()
    for _ in range(4):
        QApplication.processEvents()
    try:
        shell._resize_timer.stop()
        _assert_header_geometry(shell)
        stop = shell._header_stop_button
        assert not stop.is_compact() and stop.text() == "STOP", {
            "width": stop.width(), "minimum": stop.minimumWidth(),
            "semantic": stop.full_label_width(), "text": stop.text(),
            "font": stop.font().toString(), "mode": shell._header_layout_mode,
        }
        assert shell._spyware_guard_btn.text() == "SPYWAREGUARD"
        viewport = shell.centralWidget().viewport()
        stop_right = stop.mapTo(viewport, QPoint(stop.width() - 1, 0)).x()
        assert 0 <= viewport.rect().right() - stop_right <= max(32, round(32 * scale))
        primary = shell._header_primary_buttons
        gap = max(3, min(10, round(width / 180)))
        complete_cost = sum(button.full_label_width() for button in primary) + gap * (len(primary) - 1)
        if complete_cost <= max(408, width - 80):
            assert [button.text() for button in primary] == [
                "ADAPTATION", "SELF-TEST", "RED TEAM SIMULATION", "CHILL MODE"]
        for button in (*primary, shell._spyware_guard_btn, stop):
            if not button.is_compact():
                assert button.text() == button._full_label
                assert button.fontMetrics().horizontalAdvance(button.text()) < button.width()
    finally:
        shell._resize_timer.stop()
        shell.close()
        shell.deleteLater()


def test_header_restores_full_labels_after_narrowing_and_runtime_label_change():
    shell = HeaderShell(1.05)
    shell.resize(640, 800)
    shell._apply_dashboard_layout()
    shell.show()
    for _ in range(4):
        QApplication.processEvents()
    try:
        shell._header_primary_buttons[-1].set_full_label("CHILL: ON")
        shell.resize(1600, 900)
        shell._apply_dashboard_layout()
        for _ in range(4):
            QApplication.processEvents()
        shell._resize_timer.stop()
        assert [button.text() for button in shell._header_primary_buttons] == [
            "ADAPTATION", "SELF-TEST", "RED TEAM SIMULATION", "CHILL: ON"]
        assert shell._spyware_guard_btn.text() == "SPYWAREGUARD"
        assert shell._header_stop_button.text() == "STOP"
        _assert_header_geometry(shell)
    finally:
        shell._resize_timer.stop()
        shell.close()
        shell.deleteLater()


@pytest.mark.parametrize("width", [1600, 1920])
@pytest.mark.parametrize("scale", [1.0, 1.05, 1.35])
def test_title_posture_assessment_stay_above_one_control_row(width, scale):
    shell = HeaderShell(scale)
    shell.resize(width, 800)
    shell._apply_dashboard_layout()
    shell.show()
    for _ in range(4):
        QApplication.processEvents()
    try:
        shell._resize_timer.stop()
        _assert_header_geometry(shell)
        assert shell._header_layout_mode == "single-row"
        viewport = shell.centralWidget().viewport()
        rectangles = [QRect(group.mapTo(viewport, QPoint()), group.size())
                      for group in (shell._header_groups[1], shell._header_control_row)]
        top, bottom = min(rect.top() for rect in rectangles), max(rect.bottom() for rect in rectangles)
        brand_height = shell._header_groups[1].height()
        button_height = shell._header_control_row.height()
        spacing = max(0, shell._header_layout.verticalSpacing())
        assert bottom - top + 1 <= brand_height + button_height + spacing + 8
        assert shell._body_splitter.mapTo(viewport, QPoint()).y() - top < shell.height() / 4
        assert all(button.text() == button._full_label for button in shell._header_primary_buttons)
    finally:
        shell._resize_timer.stop()
        shell.close()
        shell.deleteLater()


def test_label_and_style_changes_rebudget_without_operator_resize_and_stop_fences_work():
    shell = HeaderShell(1.05)
    shell.resize(1600, 900)
    shell._apply_dashboard_layout()
    shell.show()
    for _ in range(4):
        QApplication.processEvents()
    try:
        shell._resize_timer.stop()
        chill = shell._header_primary_buttons[-1]
        chill.set_full_label("CHILL: ALERT")
        chill.setStyleSheet("font-weight:800; padding:7px 16px;")
        assert shell._resize_timer.isActive()
        QTest.qWait(160)
        assert chill.text() == "CHILL: ALERT"
        assert shell._header_stop_button.text() == "STOP"
        _assert_header_geometry(shell)
        shell._resize_timer.stop()
        shell._termination_started = True
        chill.set_full_label("CHILL: ON")
        assert not shell._resize_timer.isActive()
    finally:
        shell._resize_timer.stop()
        shell.close()
        shell.deleteLater()


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


def test_brand_font_change_keeps_controls_in_one_row_and_stop_visible():
    shell = HeaderShell(1.0)
    shell.setFixedSize(1920, 800)
    shell._apply_dashboard_layout()
    shell.show()
    for _ in range(4):
        QApplication.processEvents()
    try:
        brand_label = shell._header_groups[1].layout().itemAt(0).widget()
        original_style = brand_label.styleSheet()
        brand_label.setStyleSheet(original_style + ";font-size:72px;")
        shell._apply_dashboard_layout()
        for _ in range(4):
            QApplication.processEvents()
        assert brand_label.font().pixelSize() == 72
        assert shell.width() == 1920
        _assert_header_geometry(shell)
        brand_label.setStyleSheet(original_style)
        shell._apply_dashboard_layout()
        for _ in range(4):
            QApplication.processEvents()
        _assert_header_geometry(shell)
    finally:
        shell._resize_timer.stop()
        shell.close()
        shell.deleteLater()


def test_header_overflow_scrolls_without_actions_and_stop_stays_pinned():
    shell = HeaderShell(1.35)
    shell.resize(640, 800)
    shell._apply_dashboard_layout()
    shell.show()
    for _ in range(4):
        QApplication.processEvents()
    try:
        shell._resize_timer.stop()
        strip = shell._header_action_strip
        bar = strip.horizontalScrollBar()
        assert bar.maximum() > 0
        stop = shell._header_stop_button
        stop_before = QRect(stop.mapTo(shell, QPoint()), stop.size())
        clicked = []
        for button in (*shell._header_primary_buttons, *shell._header_nav_buttons, stop):
            button.clicked.connect(lambda: clicked.append(True))
        for value in (0, bar.maximum(), 0):
            bar.setValue(value)
            QApplication.processEvents()
            assert QRect(stop.mapTo(shell, QPoint()), stop.size()) == stop_before
            assert stop.text() == "STOP"
        wheel = QWheelEvent(QPointF(10, 10), QPointF(10, 10), QPoint(), QPoint(0, -120),
                            Qt.NoButton, Qt.NoModifier, Qt.NoScrollPhase, False)
        QApplication.sendEvent(strip.viewport(), wheel)
        assert bar.value() > 0 and clicked == []
        last = shell._header_nav_buttons[-1]
        last.setFocus(Qt.TabFocusReason)
        QApplication.processEvents()
        assert bar.value() > 0
        assert strip.viewport().rect().contains(QRect(last.mapTo(strip.viewport(), QPoint()), last.size()))
        QTest.keyClick(last, Qt.Key_Tab)
        assert QApplication.focusWidget() is stop
        assert QRect(stop.mapTo(shell, QPoint()), stop.size()) == stop_before
        assert clicked == []
    finally:
        shell._resize_timer.stop()
        shell.close()
        shell.deleteLater()
