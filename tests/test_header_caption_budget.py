"""Inert header caption budgets; no Core or action dispatch is constructed."""
from __future__ import annotations

import os
from math import ceil
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Qt
from PySide6.QtGui import QFont, QFontMetricsF
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QHBoxLayout, QStyle, QStyleOptionButton, QVBoxLayout, QWidget
from shiboken6 import delete, isValid

from angerona.gui.header_controls import HeaderActionButton, HeaderActionStrip
from angerona.gui.main_window import MainWindow
from angerona.gui.theme import build_qss, set_function_role


@pytest.fixture
def roots():
    app = QApplication.instance() or QApplication([])
    owned = []
    yield app, owned
    for widget in reversed(owned):
        if isValid(widget):
            widget.close()
            delete(widget)
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def _events(app):
    for _ in range(6):
        app.processEvents()


def _stop(parent):
    button = HeaderActionButton(
        "STOP", "stop", "Stop Angerona", "Stops the suite through its normal shutdown action.", parent
    )
    button.setObjectName("Critical")
    set_function_role(button, "response")
    return button


def _allocate_stop(roots, theme="cyber", scale=1.0):
    app, owned = roots
    parent = QWidget()
    owned.append(parent)
    parent.setStyleSheet(build_qss(theme, scale=scale))
    button = _stop(parent)
    owner = SimpleNamespace(
        _ui_scale=scale,
        _header_primary_buttons=(),
        _header_nav_buttons=(),
        _header_stop_button=button,
        _header_groups=(),
        _queue_header_semantic_layout=lambda: None,
    )
    MainWindow._update_header_button_modes(owner)
    parent.resize(button.width() + 20, button.height() + 20)
    parent.show()
    _events(app)
    return button, owner


def _assert_full_caption_paints(button):
    assert button.text() == "STOP"
    assert button.accessibleName() == "Stop Angerona"
    option = QStyleOptionButton()
    button.initStyleOption(option)
    contents = button.style().subElementRect(QStyle.SE_PushButtonContents, option, button)
    # The style's actual paintable contents must fit the fractional glyph run,
    # icon and Qt's normal icon/text gap, independent of the sizing helper.
    required = ceil(QFontMetricsF(button.font(), button).horizontalAdvance("STOP"))
    required += button.iconSize().width() + 4
    assert contents.width() >= required


@pytest.mark.parametrize("theme", ["cyber", "slate", "crt"])
@pytest.mark.parametrize("scale", [0.75, 1.0, 1.35])
def test_actual_header_allocation_keeps_full_critical_caption(roots, theme, scale):
    button, _owner = _allocate_stop(roots, theme, scale)
    _assert_full_caption_paints(button)


def test_fractional_glyph_run_survives_its_complete_styled_budget(roots):
    button, owner = _allocate_stop(roots)
    # Use real font shaping with a bounded spacing search, rather than mocking
    # either metrics API. Select the rounded-down case that caused the defect.
    base = QFont(button.font())
    for step in range(1, 65):
        font = QFont(base)
        font.setLetterSpacing(QFont.AbsoluteSpacing, step / 64)
        button.setFont(font)
        button.ensurePolished()
        exact = QFontMetricsF(button.font(), button).horizontalAdvance("STOP")
        rounded = button.fontMetrics().horizontalAdvance("STOP")
        if rounded < exact < rounded + 0.5:
            break
    else:
        pytest.fail("real font engine did not provide the fractional regression precondition")
    MainWindow._update_header_button_modes(owner)
    _events(roots[0])
    _assert_full_caption_paints(button)


class _HeaderOnly(QWidget):
    _queue_header_semantic_layout = MainWindow._queue_header_semantic_layout

    def __init__(self, width):
        super().__init__()
        self._ui_scale = 1.0
        self._termination_started = False
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.setInterval(120)
        self._resize_timer.timeout.connect(self._allocate)
        self.layout_passes = 0
        left, brand, right = QWidget(self), QWidget(self), QWidget(self)
        left_layout, right_layout = QHBoxLayout(left), QHBoxLayout(right)
        for layout in (left_layout, right_layout):
            layout.setContentsMargins(0, 0, 0, 0)
        self._header_groups = (left, brand, right)
        self._header_primary_buttons = [
            HeaderActionButton(label, kind, label, "Inert navigation fixture.", left)
            for label, kind in (
                ("ADAPTATION", "adaptation"), ("SELF-TEST", "selftest"),
                ("RED TEAM SIMULATION", "simulation"), ("CHILL MODE", "eco"),
            )
        ]
        for button in self._header_primary_buttons:
            left_layout.addWidget(button)
        self._header_nav_buttons = [
            HeaderActionButton(label, kind, label, "Inert navigation fixture.", right)
            for label, kind in (
                ("WORLD", "world"), ("ATTACK", "attack"), ("INTEL", "intel"),
                ("SPYWAREGUARD", "spyware"), ("FORENSICS", "forensics"),
                ("CONSOLE", "console"), ("SETUP", "setup"), ("HELP", "help"),
                ("SETTINGS", "settings"),
            )
        ]
        for button in self._header_nav_buttons:
            right_layout.addWidget(button)
        self._spyware_guard_btn = self._header_nav_buttons[3]
        self._header_stop_button = _stop(self)
        row = QWidget(self)
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        self._header_action_strip = HeaderActionStrip((left, right), row)
        row_layout.addWidget(self._header_action_strip, 1, Qt.AlignTop)
        row_layout.addWidget(self._header_stop_button, 0, Qt.AlignTop)
        self._header_control_row = row
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(brand)
        layout.addWidget(row)
        layout.addStretch(1)
        self.setStyleSheet(build_qss("cyber"))
        self._allocate()
        self.resize(width, 180)

    def _allocate(self):
        self.layout_passes += 1
        MainWindow._update_header_button_modes(self)


def test_polished_font_transition_uses_existing_coalesced_header_layout(roots):
    app, owned = roots
    shell = _HeaderOnly(1216)
    owned.append(shell)
    shell.show()
    QTest.qWait(150)
    _events(app)
    prior_passes = shell.layout_passes
    prior_width = shell._header_stop_button.width()
    shell._ui_scale = 1.35
    shell.setStyleSheet(build_qss("cyber", scale=1.35))
    QTest.qWait(150)
    _events(app)
    assert shell.layout_passes > prior_passes
    assert not shell._resize_timer.isActive()
    assert shell._header_stop_button.width() > prior_width
    _assert_full_caption_paints(shell._header_stop_button)


def test_real_underallocation_still_elides_and_compact_mode_keeps_its_identity(roots):
    button, owner = _allocate_stop(roots)
    full_width = button.width()
    button.set_responsive_width(full_width - 8)
    _events(roots[0])
    assert button.text() and button.text() != "STOP"
    assert button.accessibleName() == "Stop Angerona"
    button.set_compact(True, 38)
    assert button.text() == "" and button.width() == 38
    MainWindow._update_header_button_modes(owner)
    _events(roots[0])
    _assert_full_caption_paints(button)


@pytest.mark.parametrize("width", [480, 1216, 1920])
def test_stop_stays_fully_labeled_outside_the_single_overflow_row(roots, width):
    app, owned = roots
    shell = _HeaderOnly(width)
    owned.append(shell)
    shell.show()
    QTest.qWait(150)
    _events(app)
    stop = shell._header_stop_button
    strip = shell._header_action_strip
    _assert_full_caption_paints(stop)
    assert stop.parentWidget() is shell._header_control_row
    assert shell.rect().contains(stop.geometry().translated(stop.parentWidget().pos()))
    assert strip.geometry().right() < stop.geometry().left()
    assert not stop.is_compact()
    if width == 480:
        assert strip.horizontalScrollBar().maximum() > 0
