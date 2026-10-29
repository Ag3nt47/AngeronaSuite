"""Opted-in dialogs fit Qt work areas while their content stays reachable."""
from __future__ import annotations

import copy
import os
import socket
import subprocess
import threading
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QEvent, QObject, QPoint, QRect, QSize, Qt, Signal
from PySide6.QtGui import QMoveEvent, QResizeEvent
from PySide6.QtWidgets import (
    QApplication, QDialog, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from angerona.core.config import Config
from angerona.gui import window_fit
from angerona.gui.pages import SettingsDialog
from angerona.gui.window_fit import _fit_window_to_work_area, install_window_fit


@pytest.fixture(autouse=True)
def inert_dialog_sources(monkeypatch):
    """Exercise real widgets without host inspection, workers or saved policy."""
    from angerona.connectors import hand_controls, voice
    from angerona.core import (
        autostart, process_allowlist, provider_credentials, secure_store, sgx_guard, usb_policy,
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Dialog geometry tests cannot perform host actions")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(threading.Thread, "start", forbidden)
    monkeypatch.setattr(Config, "save", forbidden)
    monkeypatch.setattr(autostart, "is_enabled", lambda: False)
    monkeypatch.setattr(sgx_guard, "is_confidential_compute_active", lambda: False)
    monkeypatch.setattr(usb_policy, "usb_pin_configured", lambda: False)
    monkeypatch.setattr(process_allowlist, "entries", lambda *_args: [])
    monkeypatch.setattr(secure_store, "read_secret_values", lambda keys, *_args: {
        key: "" for key in keys
    })
    monkeypatch.setattr(voice.Voice, "list_input_devices", staticmethod(lambda: []))
    monkeypatch.setattr(voice, "offline_model_status", lambda: (False, "Inert model source"))
    monkeypatch.setattr(hand_controls.HandControls, "status", lambda _self: "Inert camera source")
    monkeypatch.setattr(provider_credentials, "provider_form_values", lambda: {
        provider.provider_id: ""
        for provider in provider_credentials.PROVIDER_CREDENTIALS
    })


def _settle():
    for _ in range(4):
        QApplication.processEvents()


def _dispose(dialog):
    dialog.close()
    dialog.deleteLater()


class _MeasuredWindow:
    """Measured native decorations, independent of the test Qt platform."""

    def __init__(self, position, size, minimum, decorations=QSize(14, 31)):
        self._position = QPoint(position)
        self._size = QSize(size)
        self._minimum = QSize(minimum)
        self._decorations = QSize(decorations)

    def frameGeometry(self):  # noqa: N802 - Qt signature
        return QRect(self._position, self._size + self._decorations)

    def size(self):
        return QSize(self._size)

    def width(self):
        return self._size.width()

    def height(self):
        return self._size.height()

    def minimumSize(self):  # noqa: N802 - Qt signature
        return QSize(self._minimum)

    def setMinimumSize(self, size):  # noqa: N802 - Qt signature
        self._minimum = QSize(size)
        self._size = self._size.expandedTo(size)

    def resize(self, size):
        self._size = QSize(size)

    def pos(self):
        return QPoint(self._position)

    def move(self, position):
        self._position = QPoint(position)


@pytest.mark.parametrize("work", [
    QRect(-1920, 0, 1536, 816),
    QRect(1920, -700, 1092, 582),
    QRect(-1280, -800, 640, 440),
])
def test_mixed_origin_work_areas_deduct_actual_decorations_and_are_idempotent(work):
    normal_minimum = QSize(720, 520)
    window = _MeasuredWindow(work.topLeft() - QPoint(30, 20), QSize(1500, 849),
                             normal_minimum)
    assert _fit_window_to_work_area(window, normal_minimum, work)
    inset = work.adjusted(2, 2, -2, -2)
    assert inset.contains(window.frameGeometry())
    assert window.width() == min(1500, inset.width() - 14)
    assert window.height() == inset.height() - 31
    assert not _fit_window_to_work_area(window, normal_minimum, work)


def test_the_125_percent_native_frame_uses_dips_and_restores_the_normal_floor():
    window = _MeasuredWindow(QPoint(-1908, 1), QSize(1500, 849), QSize(720, 520))
    normal_minimum = QSize(720, 520)
    assert window.frameGeometry().height() * 1.25 == 1100
    assert _fit_window_to_work_area(window, normal_minimum, QRect(-1920, 0, 1536, 816))
    assert window.height() == 781
    assert window.frameGeometry().height() == 812
    compact = QRect(-1920, 0, 470, 330)
    assert _fit_window_to_work_area(window, normal_minimum, compact)
    assert compact.contains(window.frameGeometry())
    assert window.minimumSize() == QSize(452, 295)
    larger = QRect(1920, -200, 1536, 816)
    assert _fit_window_to_work_area(window, normal_minimum, larger)
    assert window.minimumSize() == normal_minimum
    assert window.size() == normal_minimum
    assert larger.contains(window.frameGeometry())
    before = (window.frameGeometry(), window.minimumSize())
    assert not _fit_window_to_work_area(window, normal_minimum, QRect())
    assert before == (window.frameGeometry(), window.minimumSize())


@pytest.mark.parametrize("state", ["child", "hidden", "minimized", "maximized", "fullscreen"])
def test_ineligible_dialog_states_leave_geometry_and_minimum_unchanged(state):
    parent = QWidget() if state == "child" else None
    dialog = QDialog(parent)
    try:
        if parent is not None:
            dialog.setWindowFlags(Qt.Widget)
            parent.show()
        dialog.setMinimumSize(720, 520)
        controller = install_window_fit(dialog)
        if state != "hidden":
            {"minimized": dialog.showMinimized,
             "maximized": dialog.showMaximized,
             "fullscreen": dialog.showFullScreen}.get(state, dialog.show)()
        _settle()
        before = (dialog.geometry(), dialog.minimumSize())
        assert not controller.fit_now(QRect(-100, 0, 300, 200))
        assert before == (dialog.geometry(), dialog.minimumSize())
        assert not controller._timer.isActive()
    finally:
        _dispose(dialog)
        if parent is not None:
            parent.close()
            parent.deleteLater()


def test_dialog_events_coalesce_and_hide_or_close_pauses_the_owned_timer(monkeypatch):
    dialog = QDialog()
    other = QDialog()
    controller = install_window_fit(dialog)
    calls = []
    original = window_fit._fit_window_to_work_area

    def measured(*args):
        calls.append(args[2])
        return original(*args)

    monkeypatch.setattr(window_fit, "_fit_window_to_work_area", measured)
    try:
        dialog.show()
        _settle()
        calls.clear()
        QApplication.sendEvent(dialog, QMoveEvent(dialog.pos(), dialog.pos()))
        QApplication.sendEvent(dialog, QResizeEvent(dialog.size(), dialog.size()))
        for kind in (QEvent.LayoutRequest, QEvent.StyleChange, QEvent.FontChange):
            QApplication.sendEvent(dialog, QEvent(kind))
        for _ in range(6):
            controller.schedule()
        assert controller._timer.isActive()
        _settle()
        assert len(calls) == 1
        assert not controller._timer.isActive()
        calls.clear()
        other.show()
        other.resize(400, 300)
        _settle()
        assert not calls  # No application-wide event filter.
        controller.schedule()
        dialog.hide()
        assert not controller._timer.isActive()
        dialog.show()
        assert controller._timer.isActive()
        dialog.close()
        assert not controller._timer.isActive()
        assert controller.parent() is dialog
        assert controller._timer.parent() is controller
    finally:
        _dispose(other)
        _dispose(dialog)


def test_monitor_change_replaces_the_work_area_signal_connection(monkeypatch):
    class Screen(QObject):
        availableGeometryChanged = Signal(QRect)

    dialog = QDialog()
    controller = install_window_fit(dialog)
    first, second = Screen(), Screen()
    scheduled = []
    monkeypatch.setattr(controller, "schedule", lambda: scheduled.append(True))
    try:
        controller._screen_changed(first)
        first.availableGeometryChanged.emit(QRect(0, 0, 800, 600))
        controller._screen_changed(second)
        count = len(scheduled)
        first.availableGeometryChanged.emit(QRect(0, 0, 700, 500))
        assert len(scheduled) == count
        second.availableGeometryChanged.emit(QRect(-800, 0, 800, 600))
        assert len(scheduled) == count + 1
    finally:
        _dispose(dialog)


def test_opted_in_scroll_wrapper_transfers_layout_once_and_keeps_long_content_reachable(monkeypatch):
    dialog = QDialog()
    work = QRect(-800, -200, 640, 440)
    monkeypatch.setattr(dialog, "screen", lambda: SimpleNamespace(
        availableGeometry=lambda: QRect(work)))
    layout = QVBoxLayout(dialog)
    heading = QLabel("Long diagnostic page")
    long_page = QWidget()
    long_page.setMinimumSize(1000, 950)
    page_layout = QVBoxLayout(long_page)
    last = QPushButton("Last diagnostic control")
    page_layout.addStretch()
    page_layout.addWidget(last)
    layout.addWidget(heading)
    layout.addWidget(long_page)
    dialog.setMinimumSize(1040, 1000)
    controller = install_window_fit(dialog, scroll_content=True)
    try:
        assert install_window_fit(dialog, scroll_content=True) is controller
        scroll = controller.scroll_area
        assert isinstance(scroll, QScrollArea)
        assert scroll.widget().layout() is layout
        assert len(dialog.findChildren(QScrollArea)) == 1
        dialog.show()
        _settle()
        controller.fit_now(work)
        _settle()
        controller.fit_now(work)
        assert work.contains(dialog.frameGeometry())
        assert scroll.horizontalScrollBar().maximum() > 0
        assert scroll.verticalScrollBar().maximum() > 0
        scroll.ensureWidgetVisible(last, 0, 0)
        _settle()
        rectangle = QRect(last.mapTo(scroll.viewport(), QPoint()), last.size())
        assert rectangle.intersects(scroll.viewport().rect())
        assert last.isVisible() and heading.isVisible()
    finally:
        _dispose(dialog)


@pytest.mark.parametrize("work", [QRect(-1920, 0, 1092, 582), QRect(-1280, -200, 640, 440)])
def test_actual_settings_preserves_tabs_search_values_and_reachable_footer(tmp_path, work, monkeypatch):
    config = Config(data_dir=tmp_path)
    before = copy.deepcopy(vars(config))
    dialog = SettingsDialog(config, lambda: None, lambda _theme: None,
                            initial_tab="Adversary Combat")
    monkeypatch.setattr(dialog, "screen", lambda: SimpleNamespace(
        availableGeometry=lambda: QRect(work)))
    controller = dialog._window_fit_controller
    expected = ["Overview", "Information", "General", "System", "Adversary Combat",
                "Enterprise", "Integrations", "ARIA", "Trusted Processes",
                "Mobile Integration", "API Keys", "Info"]
    try:
        assert dialog.minimumWidth() >= 720
        assert [dialog.tabs.tabText(i) for i in range(dialog.tabs.count())] == expected
        assert all(isinstance(dialog.tabs.widget(i), QScrollArea) for i in range(11))
        assert dialog.tabs.tabText(dialog.tabs.currentIndex()) == "Adversary Combat"
        dialog.resize(1200, 950)
        dialog.show()
        _settle()
        controller.fit_now(work)
        _settle()
        controller.fit_now(work)
        assert work.contains(dialog.frameGeometry())
        assert dialog.tabs.tabText(dialog.tabs.currentIndex()) == "Adversary Combat"
        assert dialog.tabs.currentWidget().verticalScrollBar().maximum() > 0
        for index in range(dialog.tabs.count()):
            dialog.tabs.setCurrentIndex(index)
            _settle()
            controller.fit_now(work)
            assert dialog.tabs.currentIndex() == index
            for button in (dialog._privacy_btn, dialog._settings_sandbox_btn,
                           dialog._btn_save, dialog._btn_cancel):
                rectangle = QRect(button.mapTo(dialog, QPoint()), button.size())
                assert button.isVisible()
                assert dialog.rect().contains(rectangle), (button.text(), rectangle)
        assert dialog._privacy_btn.y() < dialog._settings_sandbox_btn.y()
        assert dialog._settings_sandbox_btn.y() < dialog._btn_save.y()
        assert dialog._btn_cancel.y() == dialog._btn_save.y()
        dialog._settings_search.setText("microphone")
        _settle()
        assert dialog.tabs.tabText(dialog.tabs.currentIndex()) == "ARIA"
        controller.fit_now(QRect(0, 0, 1536, 816))
        assert dialog.minimumWidth() == 720
        assert vars(config) == before
        assert not (tmp_path / "settings.json").exists()
        dialog._btn_cancel.click()
        assert not dialog.isVisible()
        assert not controller._timer.isActive()
    finally:
        _dispose(dialog)
