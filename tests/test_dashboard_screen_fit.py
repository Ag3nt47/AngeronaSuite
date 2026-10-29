"""The framed dashboard fits scaled work areas without folding its panels."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest
from PySide6.QtCore import QPoint, QRect, QSize
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import QApplication

from angerona.gui.component_heartbeat import ComponentHeartbeatStrip
from angerona.gui.dashboard_footer import DashboardFooter
from angerona.gui.main_window import MainWindow
from angerona.gui import system_pulse
from test_dashboard_compact_sections import _CompactShell


@pytest.fixture(autouse=True)
def inert_layout_only(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Screen-fit tests cannot dispatch host work")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(system_pulse, "_SystemPulseCollector", lambda: lambda: {
        "cpu": 12.0, "ram": 42.0, "available": 4 * 1024**3,
        "wifi": 85, "down": 4096.0, "up": 2048.0,
    })
    if sys.platform == "win32":
        for name in ("segoeui.ttf", "segoeuib.ttf", "consola.ttf", "seguiemj.ttf"):
            font = Path("C:/Windows/Fonts") / name
            if font.is_file():
                assert QFontDatabase.addApplicationFont(str(font)) >= 0


class _ScreenShell(_CompactShell):
    """Use production fit/reflow, disclosures and footer with inert records."""

    def __init__(self, work_area, scale=1.0):
        super().__init__(scale)
        self._test_work_area = QRect(work_area)
        self._screen_fit_enabled = True
        self.setMinimumSize(480, 340)
        self._screen_fit_minimum = self.minimumSize()
        # Include the real font-dependent status bar, absent from older compact
        # layout fixtures. These widgets consume memory publications only.
        self._dashboard_content.layout().removeWidget(self.footer)
        self.footer.hide()
        self.footer.deleteLater()
        self.footer = DashboardFooter()
        self.heartbeats = ComponentHeartbeatStrip(self)
        self.statusBar().setSizeGripEnabled(False)
        self.statusBar().addPermanentWidget(self.footer, 1)
        self.statusBar().addPermanentWidget(self.heartbeats)

    def _fit_dashboard_to_screen(self, available=None, *, center=False):
        return MainWindow._fit_dashboard_to_screen(
            self, self._test_work_area if available is None else available,
            center=center,
        )


def _settle(window):
    for _ in range(4):
        window._apply_dashboard_layout()
        QApplication.processEvents()
    window._resize_timer.stop()


def _dispose(window):
    window.heartbeats._poll_timer.stop()
    window.heartbeats._animation_timer.stop()
    window.system_pulse.shutdown()
    assert window.system_pulse._sampler.retired.wait(2)
    window._resize_timer.stop()
    window.close()
    window.deleteLater()


@pytest.mark.parametrize("physical_width,physical_height,dpr,ui_scale", [
    (1920, 1020, 1.25, 1.0),
    (1366, 728, 1.25, 1.0),
    (1024, 700, 1.25, 1.25),
    (640, 440, 1.25, 1.0),
])
def test_scaled_work_area_contains_frame_and_all_open_panels_remain_reachable(
    physical_width, physical_height, dpr, ui_scale,
):
    # Mixed-DPI monitor origins are not scaled around desktop (0,0). Model the
    # reported left-hand monitor using its own Qt and native origin anchors.
    work = QRect(-1920, 0, int(physical_width / dpr), int(physical_height / dpr))
    if os.environ.get("ANGERONA_EXPECTED_TEST_DPR"):
        assert QApplication.primaryScreen().devicePixelRatio() == pytest.approx(
            float(os.environ["ANGERONA_EXPECTED_TEST_DPR"])
        )
    window = _ScreenShell(work, ui_scale)
    try:
        window.resize(1514, 860)  # Bigger than the observed 125% work area.
        window.move(-1908, 1)
        window.show()
        _settle(window)
        frame = window.frameGeometry()
        assert work.contains(frame), (work, frame)
        native_left = -1920 + (frame.x() - work.x()) * dpr
        native_top = (frame.y() - work.y()) * dpr
        assert native_left >= -1920
        assert native_top >= 0
        assert native_left + frame.width() * dpr <= -1920 + physical_width
        assert native_top + frame.height() * dpr <= physical_height
        assert not window.isMinimized()
        assert window._operations_disclosure.is_expanded()
        assert all(not control.is_collapsed() for control in window._dashboard_panel_controls)
        assert not window._module_ribbons_disclosure.is_expanded()

        scroll = window.centralWidget()
        if physical_width <= 1024:
            assert scroll.verticalScrollBar().maximum() > 0
        for panel in (window.modules_panel, window._right_tabs, window.console,
                      window.live_defense_activity, window.system_pulse):
            scroll.ensureWidgetVisible(panel, 0, 0)
            QApplication.processEvents()
            rect = QRect(panel.mapTo(scroll.viewport(), QPoint()), panel.size())
            assert rect.intersects(scroll.viewport().rect())
            assert panel.isVisible() and panel.height() >= 40
        footer = QRect(window.footer.mapTo(window, QPoint()), window.footer.size())
        assert window.rect().contains(footer)

        # A later font/style/layout pass must not reintroduce the overflow.
        before = window.frameGeometry()
        _settle(window)
        assert window.frameGeometry() == before
        assert work.contains(window.frameGeometry())
        assert all(not control.is_collapsed() for control in window._dashboard_panel_controls)
    finally:
        _dispose(window)


def test_centering_reduces_client_for_title_bar_and_preserves_panel_state():
    work = QRect(-1920, 0, 1536, 816)
    window = _ScreenShell(work)
    try:
        window._screen_fit_enabled = False
        window.resize(1514, 860)
        window.show()
        QApplication.processEvents()
        before = window.size()
        assert not work.contains(window.frameGeometry())
        assert window._fit_dashboard_to_screen(center=True)
        assert window.height() < before.height()
        assert work.contains(window.frameGeometry())
        frame = window.frameGeometry()
        assert abs(frame.center().x() - work.center().x()) <= 1
        assert abs(frame.center().y() - work.center().y()) <= 1
        assert not window._fit_dashboard_to_screen(center=True)
        assert all(not control.is_collapsed() for control in window._dashboard_panel_controls)
        assert not window._module_ribbons_disclosure.is_expanded()
    finally:
        _dispose(window)


def test_native_decoration_budget_reduces_the_observed_880_dip_frame():
    class DecoratedWindow:
        # Headless Qt has tiny decorations. Model the measured 880-DIP outer
        # height separately so a real title bar cannot consume the client cap.
        def __init__(self):
            self._size = QSize(1500, 849)
            self._position = QPoint(-1908, 1)
            self._minimum = QSize(480, 340)

        def isVisible(self):  # noqa: N802 - Qt signature
            return True

        def isMinimized(self):  # noqa: N802 - Qt signature
            return False

        isMaximized = isMinimized
        isFullScreen = isMinimized

        def frameGeometry(self):  # noqa: N802 - Qt signature
            return QRect(self._position, self._size + QSize(14, 31))

        def size(self):
            return QSize(self._size)

        def width(self):
            return self._size.width()

        def height(self):
            return self._size.height()

        def minimumSize(self):  # noqa: N802 - Qt signature
            return QSize(self._minimum)

        def minimumWidth(self):  # noqa: N802 - Qt signature
            return self._minimum.width()

        def minimumHeight(self):  # noqa: N802 - Qt signature
            return self._minimum.height()

        def resize(self, width, height):
            self._size = QSize(width, height)

        def pos(self):
            return QPoint(self._position)

        def move(self, x, y):
            self._position = QPoint(x, y)

    window = DecoratedWindow()
    work = QRect(-1920, 0, 1536, 816)
    assert window.frameGeometry().height() * 1.25 == 1100
    assert MainWindow._fit_dashboard_to_screen(window, work)
    assert window.height() == 781  # 816 work - 4 inset - 31 decorations.
    assert window.frameGeometry().height() == 812
    assert work.contains(window.frameGeometry())


@pytest.mark.parametrize("state", ["hidden", "minimized", "maximized", "fullscreen"])
def test_fit_leaves_hidden_and_window_manager_states_unchanged(state):
    class InertState:
        def isVisible(self):  # noqa: N802 - Qt signature
            return state != "hidden"

        def isMinimized(self):  # noqa: N802 - Qt signature
            return state == "minimized"

        def isMaximized(self):  # noqa: N802 - Qt signature
            return state == "maximized"

        def isFullScreen(self):  # noqa: N802 - Qt signature
            return state == "fullscreen"

        def screen(self):
            raise AssertionError("An ineligible window must not query or change geometry")

    assert not MainWindow._fit_dashboard_to_screen(InertState())


def test_tiny_work_area_can_lower_drag_floor_without_unfolding_module_health():
    window = _ScreenShell(QRect(0, 0, 470, 330))
    try:
        window.resize(800, 600)
        window.show()
        _settle(window)
        assert window._test_work_area.contains(window.frameGeometry())
        assert window.minimumHeight() < 340
        assert window.minimumWidth() < 480
        assert window.centralWidget().verticalScrollBar().maximum() > 0
        assert all(not control.is_collapsed() for control in window._dashboard_panel_controls)
        assert not window._module_ribbons_disclosure.is_expanded()

        window._test_work_area = QRect(0, 0, 1536, 816)
        _settle(window)
        assert window.minimumWidth() == 480
        assert window.minimumHeight() == 340
        assert window._test_work_area.contains(window.frameGeometry())
        assert all(not control.is_collapsed() for control in window._dashboard_panel_controls)
        assert not window._module_ribbons_disclosure.is_expanded()
    finally:
        _dispose(window)
