"""Bounded alert fitting preserves evidence without repeating Qt measurements."""
from __future__ import annotations

import os
import socket
import subprocess
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QApplication, QHeaderView, QStyledItemDelegate, QTableWidget, QTableWidgetItem,
)

from angerona.gui.pages import _ResponsiveAlertsTable, _summary_column_width
from angerona.gui.theme import build_qss


def _drain(application):
    for _ in range(10):
        application.processEvents()


def _selected(table):
    items = table.selectedItems()
    return items[0].data(Qt.UserRole) if items else None


class _CountedAlertsTable(_ResponsiveAlertsTable):
    def __init__(self):
        self.counts = {}
        self.fit_depth = 0
        super().__init__(24, 8)

    def count(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1

    def _fit_evidence_columns(self):
        self.count("fits")
        self.fit_depth += 1
        try:
            return super()._fit_evidence_columns()
        finally:
            self.fit_depth -= 1

    def setColumnWidth(self, column, width):  # noqa: N802
        self.count("column_writes")
        return super().setColumnWidth(column, width)


class _CountingDelegate(QStyledItemDelegate):
    bonus = 0

    def sizeHint(self, option, index):  # noqa: N802
        table = self.parent()
        if table.fit_depth:
            table.count("delegate_hints")
            table.count("column_hints_" + str(index.column()))
        size = super().sizeHint(option, index)
        return QSize(size.width() + self.bonus, size.height())


@pytest.fixture
def alerts_fixture(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Alert fitting tests cannot dispatch host or network work")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    application = QApplication.instance() or QApplication([])
    table = _CountedAlertsTable()
    table.setStyleSheet(build_qss("cyber"))
    table.setHorizontalHeaderLabels([
        "Time", "Module", "Severity", "Message", "File / artifact path",
        "Allow", "Block", "Analyze",
    ])
    header = table.horizontalHeader()
    header.setMinimumSectionSize(36)
    for column in (1, 3, 4):
        header.setSectionResizeMode(column, QHeaderView.Interactive)
    for column in (5, 6, 7):
        header.setSectionResizeMode(column, QHeaderView.Fixed)
    table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
    table.verticalHeader().hide()
    table.setEditTriggers(QTableWidget.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectRows)
    table.setTextElideMode(Qt.ElideRight)
    table.setWordWrap(False)
    delegate = _CountingDelegate(table)
    table.setItemDelegate(delegate)
    for row in range(24):
        severity = ("Info" if row < 23 else
                    "Synthetic severity with a deliberately longer sampled display value")
        values = [
            f"00:00:{row:02d}", f"Synthetic module {row}", severity,
            "Literal synthetic evidence; no host action", f"D:/inert/{row}.bin",
            "Allow", "Block", "Analyze",
        ]
        for column, text in enumerate(values):
            item = QTableWidgetItem(text)
            item.setData(Qt.UserRole, "inert-case-" + str(row))
            table.setItem(row, column, item)
    for column in (4, 5, 6, 7):
        table.setColumnHidden(column, True)
    table.setSortingEnabled(True)
    table.sortItems(0, Qt.AscendingOrder)
    vertical = table.verticalHeader()
    set_row_size = vertical.setDefaultSectionSize

    def count_row_size(size):
        table.count("row_writes")
        return set_row_size(size)

    monkeypatch.setattr(vertical, "setDefaultSectionSize", count_row_size)
    table.resize(1100, 430)
    table.show()
    _drain(application)
    table.fit_evidence_columns()
    _drain(application)
    table.selectRow(3)
    _drain(application)
    table.counts.clear()
    try:
        yield SimpleNamespace(app=application, table=table, delegate=delegate)
    finally:
        table.close()
        table.deleteLater()
        application.processEvents()


def _assert_current_geometry(table):
    """Compare cached output with fresh styled delegate measurements."""
    header = table.horizontalHeader()

    def clamp(width):
        return min(header.maximumSectionSize(), max(header.minimumSectionSize(), width))

    expected = {}
    for column, sample, minimum, measure in (
        (0, "23:59:59", 72, True), (1, "Module", 110, False),
        (2, "Critical", 78, True), (5, "Allow", 62, True),
        (6, "Block", 62, True), (7, "Analyze", 76, True),
    ):
        if table.isColumnHidden(column):
            continue
        width = _summary_column_width(
            table, column, sample, minimum, measure_content=measure,
        )
        if column == 1:
            width = max(width, min(180, round(table.viewport().width() * 0.18)))
        expected[column] = clamp(width)
    fixed = sum(expected.values())
    if table.isColumnHidden(4):
        expected[3] = max(140, table.viewport().width() - fixed)
    else:
        available = max(360, table.viewport().width() - fixed)
        expected[3] = max(200, round(available * 0.6))
        expected[4] = max(160, available - expected[3])
    assert all(table.columnWidth(column) == clamp(width)
               for column, width in expected.items())
    assert _selected(table) == "inert-case-3"
    assert table.rowCount() == 24
    assert all(table.item(row, column) is not None
               for row in range(24) for column in range(8))


def test_unchanged_explicit_fits_do_not_measure_or_write_geometry(alerts_fixture):
    fixture = alerts_fixture
    for _ in range(100):
        fixture.table.fit_evidence_columns()
    _drain(fixture.app)
    assert fixture.table.counts == {"fits": 100}
    _assert_current_geometry(fixture.table)


def test_native_resize_burst_coalesces_and_eventually_fits(alerts_fixture):
    fixture = alerts_fixture
    table = fixture.table
    for index in range(16):
        table.resize(1100 + (index % 2) * 17, 430 + (index % 2) * 3)
    assert table.counts.get("fits", 0) == 0
    _drain(fixture.app)
    # One requested turn can cause a second viewport turn if scrollbar state
    # changes; neither turn needs to repeat intrinsic content measurements.
    assert 1 <= table.counts.get("fits", 0) <= 3
    assert table.counts.get("delegate_hints", 0) == 0
    _assert_current_geometry(table)


def test_sort_remeasures_a_previously_unsampled_row(alerts_fixture):
    fixture = alerts_fixture
    table = fixture.table
    before = table.columnWidth(2)
    assert table.item(0, 0).data(Qt.UserRole) == "inert-case-0"
    table.sortItems(0, Qt.DescendingOrder)
    _drain(fixture.app)
    assert table.item(0, 0).data(Qt.UserRole) == "inert-case-23"
    assert table.columnWidth(2) > before
    assert table.counts.get("delegate_hints", 0) > 0
    _assert_current_geometry(table)


def test_effective_appearance_header_optional_and_delegate_changes_refit(alerts_fixture):
    fixture = alerts_fixture
    table = fixture.table
    before_height = table.fontMetrics().height()
    before_row = table.verticalHeader().defaultSectionSize()
    qss = (build_qss("cyber")
           + "\nQTableWidget {font-size:22px;} QHeaderView::section {font-size:20px;}")
    table.setStyleSheet(qss)
    _drain(fixture.app)
    assert table.font().pixelSize() == 22
    assert table.fontMetrics().height() > before_height
    assert table.verticalHeader().defaultSectionSize() > before_row
    _assert_current_geometry(table)
    before_width = table.columnWidth(0)
    table.setStyleSheet(qss + "\nQTableWidget::item {padding-left:24px;padding-right:24px;}")
    _drain(fixture.app)
    assert table.columnWidth(0) > before_width
    _assert_current_geometry(table)
    table.horizontalHeaderItem(0).setText("Synthetic observation timestamp expanded header")
    table.fit_evidence_columns()
    _assert_current_geometry(table)
    table.counts.clear()
    for column in (4, 5, 6, 7):
        table.setColumnHidden(column, False)
    table.fit_evidence_columns()
    _drain(fixture.app)
    assert all(not table.isColumnHidden(column) for column in (4, 5, 6, 7))
    assert all(table.counts.get("column_hints_" + str(column), 0) == 8
               for column in (5, 6, 7))
    _assert_current_geometry(table)
    before_action = table.columnWidth(5)
    fixture.delegate.bonus = 70
    fixture.delegate.sizeHintChanged.emit(table.model().index(0, 5))
    _drain(fixture.app)
    assert table.columnWidth(5) > before_action
    _assert_current_geometry(table)
    for column in (4, 5, 6, 7):
        table.setColumnHidden(column, True)
    table.fit_evidence_columns()
    table.counts.clear()
    table.item(0, 5).setText("Synthetic changed hidden action label")
    table.fit_evidence_columns()
    _drain(fixture.app)
    assert table.counts.get("delegate_hints", 0) == 0
    table.setColumnHidden(5, False)
    table.fit_evidence_columns()
    _drain(fixture.app)
    _assert_current_geometry(table)


def test_explicit_fit_observes_sample_roles_and_consumes_pending_request(alerts_fixture):
    fixture = alerts_fixture
    table = fixture.table
    # Keep viewport geometry stable so this assertion isolates consuming a
    # queued data request, rather than a legitimate scrollbar resize turn.
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
    _drain(fixture.app)
    table.counts.clear()
    table.item(0, 2).setData(Qt.SizeHintRole, QSize(1300, 40))
    table.fit_evidence_columns()
    assert table.columnWidth(2) >= 1304
    assert table.counts.get("fits", 0) == 1
    assert table.counts.get("delegate_hints", 0) == 8
    _drain(fixture.app)
    assert table.counts.get("fits", 0) == 1
    _assert_current_geometry(table)
    table.counts.clear()
    table.item(0, 0).setCheckState(Qt.Checked)
    table.fit_evidence_columns()
    _drain(fixture.app)
    assert table.counts.get("delegate_hints", 0) == 8
    _assert_current_geometry(table)
