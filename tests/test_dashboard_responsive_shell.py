"""Responsive dashboard contracts without starting services or sensor modules."""
from __future__ import annotations

from types import SimpleNamespace
import threading

import pytest
from PySide6.QtCore import QPoint, QRect, QSize, Qt, QTimer
from PySide6.QtGui import QFont, QResizeEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication, QGridLayout, QLabel, QMainWindow, QScrollArea, QSplitter,
    QVBoxLayout, QWidget,
)

from angerona.gui.main_window import MainWindow
from angerona.gui import main_window
from angerona.gui.system_pulse import SystemPulseCard
from angerona.gui.live_defense_activity import _ActivityRow


class _DashboardShell(MainWindow):
    """Borrow production layout/resize behavior with inert panel placeholders."""

    def __init__(self):
        QMainWindow.__init__(self)
        self.config = SimpleNamespace(
            ui_scale_mode="fixed", ui_scale_fixed=1.0, theme="cyber", accent=None,
        )
        self._ui_scale = 1.0
        self.applications = 0
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.setInterval(120)
        self._resize_timer.timeout.connect(self._apply_dashboard_layout)
        self._dashboard_content = QWidget()
        root = QVBoxLayout(self._dashboard_content)
        self._header_layout = QGridLayout()
        self._header_groups = tuple(QLabel(text) for text in ("Actions", "Brand", "Navigation"))
        self._header_layout_mode = None
        root.addLayout(self._header_layout)
        self._top_splitter = QSplitter(Qt.Horizontal)
        self.modules_panel = QLabel("Modules")
        self._right_tabs = QLabel("Evidence tabs")
        for widget in (self.modules_panel, self._right_tabs):
            widget.setMinimumHeight(90)
            self._top_splitter.addWidget(widget)
        self._console_section = QSplitter(Qt.Horizontal)
        self.console = QLabel("Console")
        self.live_defense_activity = QLabel("Activity")
        self.system_pulse = QLabel("System pulse")
        for widget in (self.console, self.live_defense_activity, self.system_pulse):
            widget.setMinimumHeight(90)
            self._console_section.addWidget(widget)
        self._body_splitter = QSplitter(Qt.Vertical)
        self._body_splitter.addWidget(self._top_splitter)
        self._body_splitter.addWidget(self._console_section)
        root.addWidget(self._body_splitter, 1)
        self.footer = QLabel("Module status and local AI readiness")
        self.footer.setFixedHeight(40)
        root.addWidget(self.footer)
        viewport = QScrollArea()
        viewport.setWidgetResizable(True)
        viewport.setWidget(self._dashboard_content)
        self.setCentralWidget(viewport)

    def _apply_dashboard_layout(self):
        self.applications += 1
        MainWindow._apply_dashboard_layout(self)

    # The real lifecycle manages workers, trays, and startup receipts. This
    # harness owns no runtime and deliberately exercises Qt lifecycle alone.
    showEvent = QMainWindow.showEvent
    hideEvent = QMainWindow.hideEvent
    changeEvent = QMainWindow.changeEvent
    closeEvent = QMainWindow.closeEvent


@pytest.fixture
def shell():
    window = _DashboardShell()
    yield window
    window._resize_timer.stop()
    window.close()
    window.deleteLater()


@pytest.mark.parametrize(
    "width, expected_header, expected_orientation",
    [
        (1920, "wide", Qt.Horizontal),
        (1650, "wide", Qt.Horizontal),
        (1649, "two", Qt.Horizontal),
        (1280, "two", Qt.Horizontal),
        (1000, "two", Qt.Horizontal),
        (999, "two", Qt.Vertical),
        (850, "two", Qt.Vertical),
        (849, "stack", Qt.Vertical),
        (480, "stack", Qt.Vertical),
    ],
)
def test_header_and_panels_reflow_at_readable_widths(shell, width, expected_header, expected_orientation):
    shell.resize(width, 800)
    shell._apply_dashboard_layout()
    assert shell._header_layout_mode == expected_header
    assert shell._top_splitter.orientation() == expected_orientation
    assert shell._console_section.orientation() == expected_orientation
    positions = [shell._header_layout.getItemPosition(shell._header_layout.indexOf(widget))
                 for widget in shell._header_groups]
    assert len({position[:2] for position in positions}) == 3
    assert all(shell._header_layout.indexOf(widget) >= 0 for widget in shell._header_groups)


@pytest.mark.parametrize("size, expected", [((480, 340), 0.9), ((1200, 780), 1.0), ((3840, 2160), 1.1)])
def test_auto_scaling_keeps_small_text_readable_without_inflating_large_desktops(size, expected):
    owner = SimpleNamespace(config=SimpleNamespace(ui_scale_mode="auto"),
                            width=lambda: size[0], height=lambda: size[1])
    assert MainWindow._compute_ui_scale(owner) == pytest.approx(expected)


@pytest.mark.parametrize("scale, expected", [(0.2, 0.75), (1.25, 1.25), (2.0, 1.35)])
def test_fixed_accessibility_scaling_remains_independent_of_window_size(scale, expected):
    owner = SimpleNamespace(
        config=SimpleNamespace(ui_scale_mode="fixed", ui_scale_fixed=scale),
        width=lambda: 480, height=lambda: 340,
    )
    assert MainWindow._compute_ui_scale(owner) == pytest.approx(expected)


def test_resize_burst_defers_expensive_layout_until_drag_settles(shell):
    # Native resize events enter the real MainWindow handler, but this burst
    # cannot race desktop animation timing or start any production services.
    for width in range(1200, 1220):
        event = QResizeEvent(QSize(width, 800), QSize(width - 1, 800))
        QApplication.sendEvent(shell, event)
    assert shell.applications == 0
    assert shell._resize_timer.isActive()
    QTest.qWait(220)
    assert shell.applications == 1
    assert not shell._resize_timer.isActive()


def test_settings_scale_change_reflows_panels_without_a_manual_window_resize(shell):
    shell.resize(1200, 800)
    shell.show()
    shell._apply_dashboard_layout()
    QApplication.processEvents()
    shell._resize_timer.stop()
    assert shell._top_splitter.orientation() == Qt.Horizontal
    shell.config.ui_scale_fixed = 1.35
    shell.apply_theme()
    QTest.qWait(220)
    assert shell._top_splitter.orientation() == Qt.Vertical
    assert shell._console_section.orientation() == Qt.Vertical


def test_small_window_can_scroll_to_every_panel_and_footer_then_restore_desktop_layout(shell):
    shell.resize(480, 340)
    shell.show()
    shell._apply_dashboard_layout()
    QApplication.processEvents()
    scroll = shell.centralWidget()
    assert scroll.verticalScrollBar().maximum() > 0
    for panel in (shell.modules_panel, shell._right_tabs, shell.console,
                  shell.live_defense_activity, shell.system_pulse, shell.footer):
        scroll.ensureWidgetVisible(panel, 0, 0)
        QApplication.processEvents()
        rect = QRect(panel.mapTo(scroll.viewport(), QPoint()), panel.size())
        assert rect.intersects(scroll.viewport().rect()), panel.text()
        assert panel.width() > 0 and panel.height() >= 40
    footer_rect = QRect(shell.footer.mapTo(scroll.viewport(), QPoint()), shell.footer.size())
    assert scroll.viewport().rect().contains(footer_rect)

    shell.resize(1920, 1040)
    shell._apply_dashboard_layout()
    QApplication.processEvents()
    assert shell._header_layout_mode == "wide"
    assert shell._top_splitter.orientation() == Qt.Horizontal
    assert shell._console_section.orientation() == Qt.Horizontal
    assert scroll.verticalScrollBar().maximum() == 0


def test_desktop_to_narrow_resize_releases_old_horizontal_panel_width_caps(shell):
    shell.resize(1920, 1040)
    shell.show()
    shell._apply_dashboard_layout()
    QApplication.processEvents()
    assert shell.system_pulse.maximumWidth() == 340
    shell.resize(800, 650)
    shell._apply_dashboard_layout()
    QApplication.processEvents()
    # QSplitter caches child maximum widths while changing orientation. A
    # former 340px System Pulse cap must not constrain the stacked entire row.
    assert shell._console_section.maximumWidth() > 800
    assert shell._console_section.width() == shell._top_splitter.width()


@pytest.mark.parametrize("selected", ["alerts", "soar", "scan", "orbital"])
def test_hidden_alert_tab_skips_work_while_soar_receipts_and_security_stay_live(monkeypatch, selected):
    calls = []

    def panel(name):
        return SimpleNamespace(refresh=lambda: calls.append(name))

    alerts, soar, scan = panel("alerts"), panel("soar"), panel("scan")
    active = {"alerts": alerts, "soar": soar, "scan": scan, "orbital": alerts}[selected]
    monkeypatch.setattr(main_window, "reconcile_module_usage", lambda _manager: None)
    owner = SimpleNamespace(
        manager=object(), _quiet_chill_active=lambda: False,
        _current_refresh_plan=lambda: (1000, 1, 1, 1, 1),
        timer=SimpleNamespace(interval=lambda: 1000), _tick_count=0,
        status_strip=panel("status"), resource_strip=panel("resources"),
        red_swords=SimpleNamespace(set_active=lambda _active: None),
        shark_engine=SimpleNamespace(is_running=False),
        red_team_engine=SimpleNamespace(is_running=False),
        _check_threat_animation=lambda: calls.append("security"),
        _refresh_posture=lambda: calls.append("posture"),
        modules_panel=panel("modules"), cards=panel("cards"),
        live_defense_activity=panel("activity"),
        _orbital_view_active=lambda: selected == "orbital",
        _orbital_dashboard=panel("orbital"),
        _right_tabs=SimpleNamespace(currentWidget=lambda: active),
        alerts_panel=alerts, soar_panel=soar,
        _write_flow_metrics_async=lambda: calls.append("flow"),
    )
    MainWindow._refresh_body(owner)
    assert "security" in calls
    assert "status" in calls
    assert calls.count("modules") == (0 if selected == "orbital" else 1)
    assert calls.count("orbital") == (1 if selected == "orbital" else 0)
    assert calls.count("soar") == 1
    assert calls.count("alerts") == (1 if selected == "alerts" else 0)
    assert "scan" not in calls


@pytest.mark.parametrize("selected", ["alerts", "soar"])
def test_selecting_evidence_tab_refreshes_it_immediately(selected):
    calls = []
    alerts = SimpleNamespace(refresh=lambda: calls.append("alerts"))
    soar = SimpleNamespace(refresh=lambda: calls.append("soar"))
    active = {"alerts": alerts, "soar": soar}[selected]
    owner = SimpleNamespace(
        alerts_panel=alerts, soar_panel=soar, scan_center=object(),
        _pre_scan_center_sizes=None,
        _right_tabs=SimpleNamespace(currentWidget=lambda: active, indexOf=lambda _widget: 2),
    )
    MainWindow._on_right_tab_changed(owner, 0 if selected == "alerts" else 1)
    assert calls == [selected]


def test_wrapped_captions_do_not_force_preferred_panel_height_past_viewport():
    class LargePanel(QWidget):
        def sizeHint(self):
            return QSize(400, 900)

        def minimumSizeHint(self):
            return QSize(100, 100)

    content = QWidget()
    content.setMinimumHeight(400)
    layout = main_window._DashboardLayout(content)
    caption = QLabel("A readable caption may wrap while the evidence panel scrolls internally.")
    caption.setWordWrap(True)
    layout.addWidget(caption)
    layout.addWidget(LargePanel(), 1)
    viewport = QScrollArea()
    viewport.setWidgetResizable(True)
    viewport.setWidget(content)
    viewport.resize(700, 600)
    try:
        viewport.show()
        QApplication.processEvents()
        assert content.height() == viewport.viewport().height()
        assert viewport.verticalScrollBar().maximum() == 0
    finally:
        viewport.close()
        viewport.deleteLater()


@pytest.mark.parametrize(
    "external, card_visible, window_visible, minimized, closed, busy, wake",
    [
        (True, False, True, False, False, False, True),
        (False, True, True, False, False, False, True),
        (False, False, True, False, False, False, False),
        (True, False, False, False, False, False, False),
        (True, False, True, True, False, False, False),
        (True, False, True, False, True, False, False),
        (True, False, True, False, False, True, False),
    ],
)
def test_footer_reuses_sampler_only_when_its_dashboard_is_visible(
    external, card_visible, window_visible, minimized, closed, busy, wake,
):
    # No SystemPulseCard constructor, worker, psutil calls, or host probes. These
    # event flags model the existing sampler admission boundary directly.
    owner = SimpleNamespace(
        _closed=threading.Event(), _busy=threading.Event(),
        _sample_requested=threading.Event(), _external_view_active=external,
        isVisible=lambda: card_visible,
        window=lambda: SimpleNamespace(isVisible=lambda: window_visible,
                                       isMinimized=lambda: minimized),
    )
    if closed:
        owner._closed.set()
    if busy:
        owner._busy.set()
    SystemPulseCard.request_sample(owner)
    assert owner._sample_requested.is_set() is wake
    assert owner._busy.is_set() is (busy or wake)


def test_two_line_activity_row_grows_after_inherited_font_changes():
    row = _ActivityRow(0)
    row.setText("12:00:00 INFO Detector — A bounded synthetic event summary")
    try:
        for point_size in (9, 22, 12):
            row.setFont(QFont("Arial", point_size))
            QApplication.processEvents()
            assert row.minimumHeight() >= row.fontMetrics().height() * 2 + 2
    finally:
        row.close()
        row.deleteLater()
