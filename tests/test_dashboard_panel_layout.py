"""Responsive dashboard panels retain readable text and reachable controls."""
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontMetrics
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel

from angerona.gui.pages import AlertsPanel, CommandConsolePanel, ModulesPanel, StatCard
from angerona.gui.theme import build_qss


@pytest.mark.parametrize("width,scale", [(210, 1.35), (250, 1.0), (460, 0.75)])
def test_summary_value_fits_card_without_changing_its_meaning(width, scale):
    card = StatCard("Threat level")
    card.setStyleSheet(build_qss(scale=scale))
    card.set("Critical", "#ef4444")
    card.resize(width, 110)
    card.show()
    QApplication.instance().processEvents()
    try:
        font = card.value._display_font()
        assert QFontMetrics(font).horizontalAdvance("Critical") <= card.value.contentsRect().width()
        assert card.value.text() == card.value.toolTip() == "Critical"
        assert card.width() == width
    finally:
        card.close()


def test_module_search_has_own_readable_row_and_names_do_not_collapse():
    panel = ModulesPanel(SimpleNamespace(modules={}), SimpleNamespace())
    panel.setStyleSheet(build_qss())
    panel.resize(370, 350)
    panel.show()
    QApplication.instance().processEvents()
    try:
        assert panel._module_search.width() > 300
        assert panel._module_search.y() > panel._sort_combo.y()
        assert panel.table.columnWidth(1) >= 230
        assert panel.table.horizontalScrollBar().maximum() > 0
    finally:
        panel.close()


def test_condensed_panel_titles_retain_action_explanations_and_keyboard_access():
    panel = AlertsPanel(SimpleNamespace())
    console = CommandConsolePanel(SimpleNamespace(config=SimpleNamespace(aria_enabled=False)))
    opened = []
    panel._title.clicked.connect(lambda: opened.append(True))
    try:
        assert panel._title.text() == "Live Alerts   ›"
        assert "15-minute exact-rule suppression" in panel._title.toolTip()
        assert "verified process target" in panel._title.toolTip()
        assert console._title.text() == "Incident Response Console   ›"
        assert "currently off" in console._title.toolTip()
        QTest.keyClick(panel._title, Qt.Key_Return)
        assert opened == [True]
        assert panel.table.columnWidth(3) >= 380
        assert panel.table.columnWidth(4) >= 280
    finally:
        panel.close()
        console.close()


def test_card_caption_uses_available_width_before_wrapping():
    card = StatCard("Active critical (10m)")
    card.setStyleSheet(build_qss(scale=1.35))
    card.resize(460, 110)
    card.show()
    QApplication.instance().processEvents()
    try:
        caption = card.findChild(QLabel, "CardLabel")
        assert caption.width() >= caption.fontMetrics().horizontalAdvance(caption.text())
    finally:
        card.close()


@pytest.mark.parametrize("width,overflows", [(1260, False), (820, True)])
def test_alert_actions_fit_desktop_while_narrow_panels_keep_readable_evidence(width, overflows):
    panel = AlertsPanel(SimpleNamespace())
    panel.setStyleSheet(build_qss())
    panel.resize(width, 400)
    panel.show()
    QApplication.instance().processEvents()
    try:
        assert (panel.table.horizontalScrollBar().maximum() > 0) is overflows
        assert panel.table.columnWidth(3) >= 280
        assert panel.table.columnWidth(4) >= 180
        if not overflows:
            header = panel.table.horizontalHeader()
            assert header.sectionViewportPosition(7) + header.sectionSize(7) <= panel.table.viewport().width()
    finally:
        panel.close()
