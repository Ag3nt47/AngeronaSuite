"""Compact summaries keep full evidence available without host actions."""
from __future__ import annotations

import os
import socket
import subprocess
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontMetrics
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QHBoxLayout, QPushButton, QStyleOptionViewItem, QVBoxLayout, QWidget

from angerona.core.eventbus import Event, Severity
from angerona.gui.pages import AlertsPanel, ModulesPanel, StatCard
from angerona.gui.theme import build_qss


@pytest.fixture(autouse=True)
def no_host_dispatch(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Compact table tests cannot dispatch network or processes")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def app():
    return QApplication.instance() or QApplication([])


def close(widget):
    widget.close()
    widget.deleteLater()
    app().processEvents()


def events():
    return [Event(
        "Synthetic Network Observation",
        "<b>Synthetic evidence</b> with a complete message and no host action " + str(index),
        Severity.HIGH,
        ts=float(1000 - index),
        details={"artifact_path": r"C:\DEMO\Long Folder\synthetic-artifact.exe"},
    ) for index in range(40)]


@pytest.mark.parametrize("width,scale", [(540, 1.0), (820, 1.0), (1260, 1.0), (820, 1.35)])
def test_alert_summary_uses_message_space_without_horizontal_scrolling(width, scale):
    application = app()
    panel = AlertsPanel(SimpleNamespace())
    panel.setStyleSheet(build_qss(scale=scale))
    panel._rebuild_event_rows(events())
    panel.resize(width, 380)
    panel.show()
    application.processEvents()
    try:
        assert [not panel.table.isColumnHidden(column) for column in range(8)] == [True] * 4 + [False] * 4
        minimum = sum(panel.table.columnWidth(column) for column in (0, 1, 2)) + 140
        assert (panel.table.horizontalScrollBar().maximum() > 0) is (minimum > panel.table.viewport().width())
        assert panel.table.columnWidth(3) >= 140
        assert panel.table.verticalHeader().defaultSectionSize() >= panel.table.fontMetrics().height() + 8
        tooltip = panel.table.item(0, 3).toolTip()
        assert "&lt;b&gt;Synthetic evidence&lt;/b&gt;" in tooltip
        assert r"C:\DEMO\Long Folder\synthetic-artifact.exe" in tooltip
        assert panel.table.item(0, 4).text() == r"C:\DEMO\Long Folder\synthetic-artifact.exe"
    finally:
        close(panel)


def test_optional_alert_columns_and_preview_preserve_the_selected_evidence(monkeypatch):
    application = app()
    panel = AlertsPanel(SimpleNamespace())
    selected = events()[0]
    panel._rebuild_event_rows([selected])
    panel.resize(1260, 380)
    panel.show()
    application.processEvents()
    opened = []
    monkeypatch.setattr(panel, "_open_event_details", opened.append)
    try:
        panel.table.selectRow(0)
        panel._artifact_column_action.setChecked(True)
        panel._inline_actions_action.setChecked(True)
        assert not any(panel.table.isColumnHidden(column) for column in range(8))
        panel._details_button.setChecked(True)
        assert panel.table.isColumnHidden(4)
        assert panel._preview_event is selected
        panel._details_button.setChecked(False)
        assert not panel.table.isColumnHidden(4)
        panel.table.setFocus()
        QTest.keyClick(panel.table, Qt.Key_Return)
        assert opened == [selected]
        assert panel._selected_event() is selected
    finally:
        close(panel)


def test_module_filters_stay_visible_as_summary_state_and_contract_values_remain():
    application = app()
    panel = ModulesPanel(SimpleNamespace(modules={}), SimpleNamespace())
    panel.setStyleSheet(build_qss())
    panel._render_rows({"Synthetic module": (
        True, "Synthetic module with a complete descriptive name", "running 100%", "#22c55e",
        100, "Synthetic assurance", "Synthetic category", "observe", "1.14.0", "Synthetic state",
    )})
    panel.resize(620, 380)
    panel.show()
    application.processEvents()
    try:
        assert panel._filters_row.isHidden()
        assert panel.table.horizontalScrollBar().maximum() == 0
        assert panel.table.columnWidth(1) >= 100
        assert all(panel.table.isColumnHidden(column) for column in (4, 5, 6))
        assert "Synthetic category" in panel.table.item(0, 1).toolTip()
        panel._columns_button.setChecked(True)
        assert not any(panel.table.isColumnHidden(column) for column in range(7))
        assert panel.table.item(0, 4).text() == "Synthetic category"
        panel._filters_button.setChecked(True)
        panel._mode_combo.setCurrentText("observe")
        panel._filters_button.setChecked(False)
        assert panel._filters_row.isHidden()
        assert panel._filters_button.text() == "Filters: observe"
        assert "observe" in panel._filters_button.toolTip()
    finally:
        close(panel)


def test_empty_feedback_rows_take_no_space_but_errors_and_undo_remain_available():
    application = app()
    panel = AlertsPanel(SimpleNamespace())
    panel.resize(820, 380)
    panel.show()
    application.processEvents()
    try:
        assert panel._status.isHidden() and panel._undo_allow.isHidden()
        panel._status.setText("Synthetic operation was held; no action occurred.")
        assert not panel._status.isHidden()
        assert panel._status.textFormat() == Qt.PlainText
        panel._undo_allow.setEnabled(True)
        assert not panel._undo_allow.isHidden()
        panel._status.clear()
        panel._undo_allow.setEnabled(False)
        assert panel._status.isHidden() and panel._undo_allow.isHidden()
    finally:
        close(panel)


def test_enter_opens_only_the_focused_table_and_leaves_child_action_buttons_alone(monkeypatch):
    application = app()
    shell = QWidget()
    layout = QHBoxLayout(shell)
    modules = ModulesPanel(SimpleNamespace(modules={}), SimpleNamespace())
    alerts = AlertsPanel(SimpleNamespace())
    layout.addWidget(modules)
    layout.addWidget(alerts)
    modules._render_rows({"Synthetic": (
        True, "Synthetic", "running 100%", "#22c55e", 100, "Synthetic assurance",
        "Synthetic", "observe", "1.14.0", "Synthetic state",
    )})
    selected = events()[0]
    alerts._rebuild_event_rows([selected])
    opened = []
    monkeypatch.setattr(modules, "_on_click", lambda row, column: opened.append(("module", row, column)))
    monkeypatch.setattr(alerts, "_open_event_details", lambda event: opened.append(("alert", event)))
    shell.resize(1300, 420)
    shell.show()
    shell.activateWindow()
    application.processEvents()
    try:
        modules.table.selectRow(0)
        alerts.table.selectRow(0)
        alerts.table.setFocus()
        QTest.keyClick(alerts.table, Qt.Key_Return)
        assert opened == [("alert", selected)]
        modules.table.setFocus()
        QTest.keyClick(modules.table, Qt.Key_Return)
        assert opened == [("alert", selected), ("module", 0, 1)]
        alerts._inline_actions_action.setChecked(True)
        child = QPushButton("Synthetic guarded action")
        child.setAutoDefault(True)
        actions = []
        child.clicked.connect(lambda: actions.append("existing guarded route"))
        alerts.table.setCellWidget(0, 5, child)
        child.setFocus()
        QTest.keyClick(child, Qt.Key_Return)
        assert actions == ["existing guarded route"]
        assert opened == [("alert", selected), ("module", 0, 1)]
    finally:
        close(shell)


@pytest.mark.parametrize("scale", [1.0, 1.35])
def test_compact_card_keeps_scaled_text_and_keyboard_detail_access(scale):
    application = app()
    card = StatCard("Active critical (10m)")
    card.setStyleSheet(build_qss(scale=scale))
    card.set("12345", "#ef4444")
    card.resize(300, card.sizeHint().height())
    card.show()
    application.processEvents()
    opened = []
    card.clicked.connect(lambda: opened.append(True))
    try:
        assert card.height() <= (80 if scale == 1.0 else 105)
        assert card.value.height() >= QFontMetrics(card.value._display_font()).height()
        assert card.value.text() == card.value.toolTip() == "12345"
        QTest.keyClick(card, Qt.Key_Return)
        assert opened == [True]
    finally:
        close(card)


def styled_item_width(table, row, column):
    index = table.model().index(row, column)
    option = QStyleOptionViewItem()
    option.initFrom(table)
    option.widget = table
    option.font = table.font()
    option.fontMetrics = table.fontMetrics()
    return table.itemDelegateForIndex(index).sizeHint(option, index).width()


@pytest.mark.parametrize("scale", [1.0, 1.35])
def test_styled_summary_cells_and_complete_headers_fit_their_columns(scale):
    application = app()
    modules = ModulesPanel(SimpleNamespace(modules={}), SimpleNamespace())
    alerts = AlertsPanel(SimpleNamespace())
    modules._render_rows({"Synthetic": (
        True, "Synthetic module", "running 100%", "#22c55e", 100, "Synthetic assurance",
        "Synthetic", "observe", "1.14.0", "Synthetic state",
    )})
    alerts._rebuild_event_rows([Event("Synthetic", "Synthetic evidence", Severity.CRITICAL, ts=1000)])
    alerts.table.item(0, 0).setText("23:59:59")
    for panel in (modules, alerts):
        panel.setStyleSheet(build_qss(scale=scale))
        panel.resize(900, 380)
        panel.show()
    application.processEvents()
    try:
        modules.table.sortByColumn(3, Qt.DescendingOrder)
        for table, columns in ((modules.table, (0, 2, 3)), (alerts.table, (0, 2))):
            for column in columns:
                assert table.columnWidth(column) >= table.horizontalHeader().sectionSizeHint(column)
                assert table.columnWidth(column) >= styled_item_width(table, 0, column)
        assert modules.table.item(0, 2).text() == "running 100%"
        assert modules.table.horizontalHeaderItem(3).text() == "Assurance"
        assert alerts.table.item(0, 0).text() == "23:59:59"
    finally:
        close(modules)
        close(alerts)


@pytest.mark.parametrize("scale", [1.0, 1.35])
def test_panels_start_open_and_minimize_only_their_body_without_losing_state(scale):
    application = app()
    shell = QWidget()
    shell.setStyleSheet(build_qss(scale=scale))
    layout = QVBoxLayout(shell)
    modules = ModulesPanel(SimpleNamespace(modules={}), SimpleNamespace())
    alerts = AlertsPanel(SimpleNamespace())
    layout.addWidget(modules)
    layout.addWidget(alerts)
    modules._render_rows({"Synthetic": (
        True, "Synthetic", "running 100%", "#22c55e", 100, "Synthetic assurance",
        "Synthetic", "observe", "1.14.0", "Synthetic state",
    )})
    alerts._rebuild_event_rows(events())
    shell.resize(1100, 760)
    shell.show()
    application.processEvents()
    try:
        for panel in (modules, alerts):
            before_rows = panel.table.rowCount()
            before_height = panel.height()
            assert not panel.is_collapsed() and not panel._body.isHidden()
            panel._minimize_button.click()
            application.processEvents()
            assert panel.is_collapsed() and panel._body.isHidden()
            assert panel._title.isVisible() and panel._minimize_button.isVisible()
            assert panel.height() < before_height
            assert panel.table.rowCount() == before_rows
            assert panel._minimize_button.toolTip().startswith("Restore ")
            panel.set_collapsed(False)
            application.processEvents()
            assert not panel.is_collapsed() and not panel._body.isHidden()
            assert panel.table.rowCount() == before_rows
            assert panel.table.viewport().height() >= panel.table.verticalHeader().defaultSectionSize() * 3
    finally:
        close(shell)


@pytest.mark.parametrize("scale", [1.0, 1.35])
def test_each_card_minimizes_without_opening_details_and_keeps_the_current_value(scale):
    application = app()
    shell = QWidget()
    shell.setStyleSheet(build_qss(scale=scale))
    layout = QHBoxLayout(shell)
    cards = [StatCard(label) for label in ("Modules running", "Alerts (24h)", "Active critical (10m)", "Threat level")]
    opened = []
    for card, value in zip(cards, ("75/86", "12", "1", "High")):
        layout.addWidget(card)
        card.set(value, "#ef4444")
        card.clicked.connect(lambda label=card._label: opened.append(label))
    shell.resize(1360, 160)
    shell.show()
    application.processEvents()
    try:
        for card in cards:
            assert not card.is_collapsed()
            QTest.mouseClick(card._minimize_button, Qt.LeftButton)
            application.processEvents()
            assert card.is_collapsed() and card.value.isHidden()
            assert card.value.text() in card._caption.text()
            assert opened == []
            QTest.keyClick(card._minimize_button, Qt.Key_Return)
            application.processEvents()
            assert not card.is_collapsed() and not card.value.isHidden()
            assert opened == []
        cards[2].set_collapsed(True)
        cards[2].set("7", "#ef4444")
        application.processEvents()
        assert cards[2]._caption.text().endswith(": 7")
        assert cards[2].property("alert") is True
    finally:
        close(shell)
