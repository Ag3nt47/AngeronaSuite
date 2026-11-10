"""Inert geometry/detail checks for the Adapt Host comparison table."""
from __future__ import annotations

import json

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QHeaderView, QStyle

from test_adaptation_responsive_candidate import _pump, _workbench


@pytest.mark.parametrize("width,scale", [(1600, 1.0), (1600, 1.35), (520, 1.35)])
def test_change_columns_share_space_preserve_full_details_and_operator_widths(monkeypatch, width, scale):
    dialog = _workbench(monkeypatch)
    font = QFont(dialog.font())
    font.setPointSizeF(font.pointSizeF() * scale)
    dialog.setFont(font)
    effect = {
        "profile": "Public", "changed": True,
        "before": {"enabled": True, "inbound": "Allow", "outbound": "Allow"},
        "after": {"enabled": True, "inbound": "Block", "outbound": "Block"},
        "reason": "Literal <evidence>, never markup. " * 80,
        "reversibility": "Restore the complete captured firewall policy.",
        "verification": "Projected only; no host action. " * 80,
    }
    try:
        dialog.resize(width, 780)
        dialog.show()
        dialog.tabs.setCurrentIndex(dialog.adapt_tab_index)
        dialog._display_effects([effect])
        _pump()
        table, header = dialog.change_table, dialog.change_table.horizontalHeader()
        assert dialog.width() == width
        assert not header.stretchLastSection()
        margin = 2 * max(8, header.style().pixelMetric(QStyle.PM_HeaderMargin))
        for column in range(table.columnCount()):
            assert header.sectionResizeMode(column) == QHeaderView.Interactive
            caption = table.horizontalHeaderItem(column).text()
            assert header.sectionSize(column) >= header.fontMetrics().horizontalAdvance(caption) + margin
        assert table.columnWidth(2) >= 200 and table.columnWidth(3) >= 200
        assert table.columnWidth(6) <= table.columnWidth(2) * 1.5
        assert table.viewport().width() <= dialog._workbench_scroll.viewport().width()
        if width < 600:
            assert table.horizontalScrollBar().maximum() > 0
        else:
            assert table.horizontalScrollBar().maximum() == 0
        table.selectRow(0)
        _pump(2)
        assert json.loads(dialog.change_details.toPlainText()) == effect
        assert dialog.change_details.isReadOnly()
        assert table.item(0, 2).data(Qt.UserRole) == effect
        assert "complete before/after" in table.accessibleDescription()

        # Rendering long records and resizing the window must not take back an
        # operator's interactive column adjustment or alter its exact payload.
        header.resizeSection(2, 337)
        dialog.resize(width - 20, 780)
        updated = {**effect, "verification": "Still projected; no approval or native action."}
        dialog._display_effects([updated])
        _pump()
        assert table.columnWidth(2) == 337
        assert json.loads(dialog.change_details.toPlainText()) == updated
        assert not dialog.apply_button.isEnabled()
        assert dialog.findings_table.horizontalHeader().stretchLastSection()
        assert dialog.sandbox_table.horizontalHeader().stretchLastSection()
    finally:
        dialog.close()
        _pump()
