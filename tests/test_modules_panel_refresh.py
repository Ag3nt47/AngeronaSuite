"""Offscreen regressions for the module table's discovery and refresh path."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtTest import QSignalSpy, QTest
from PySide6.QtWidgets import QApplication, QCheckBox, QTableWidget

from angerona.core.module_base import BaseModule
from angerona.gui import pages


class _ProbeModule(BaseModule):
    """A module with no worker, storage, platform probe, or scanning side effect."""

    def __init__(
        self, name: str, *, category: str = "General", mode: str = "detect",
        score: int = 70,
    ) -> None:
        super().__init__()
        self.name = name
        self.category = category
        self.ui_mode = mode
        self.assurance_score = score
        self.capability_id = f"test.{name.lower().replace(' ', '-')}"
        self.status = "running"

    def run(self) -> None:
        raise AssertionError("UI tests must never start a module worker")


class _Manager:
    platform = "windows"

    def __init__(self, modules) -> None:
        self.modules = {module.name: module for module in modules}
        self.enabled = {name: True for name in self.modules}
        self.enable_calls: list[tuple[str, bool]] = []
        self.denial = ""

    def is_enabled(self, name: str) -> bool:
        return self.enabled.get(name, True)

    def set_enabled(self, name: str, enabled: bool) -> None:
        self.enable_calls.append((name, enabled))
        if self.denial == "raise":
            raise PermissionError("synthetic policy denial")
        if self.denial != "ignore":
            self.enabled[name] = enabled


class _ItemOnlyTable(QTableWidget):
    """Guard the actual costly operations from the reported watchdog stack."""

    fail_next_item = False

    def setCellWidget(self, *args) -> None:
        raise AssertionError("module rows must use native checkable items")

    def insertRow(self, *args) -> None:
        raise AssertionError("module discovery must allocate rows in a batch")

    def setItem(self, row, column, item) -> None:
        if self.fail_next_item:
            self.fail_next_item = False
            raise RuntimeError("synthetic rendering failure")
        super().setItem(row, column, item)


@pytest.fixture
def panel_factory(monkeypatch):
    app = QApplication.instance() or QApplication([])
    panels = []
    monkeypatch.setattr(pages, "QTableWidget", _ItemOnlyTable)
    monkeypatch.setattr(
        pages, "_module_assurance",
        lambda manager, module, operational=None: SimpleNamespace(
            score=module.assurance_score, reasons=(), dimensions=(),
        ),
    )
    monkeypatch.setattr(
        pages, "_capability_summary",
        lambda module: {
            "capability_id": module.capability_id,
            "mode": module.ui_mode,
            "implementation_version": module.version,
        },
    )

    def create(modules):
        manager = _Manager(modules)
        panel = pages.ModulesPanel(manager, None)
        panels.append(panel)
        return panel, manager

    yield create
    for panel in panels:
        panel.close()
        panel.deleteLater()
    app.processEvents()


def _row(panel, name):
    for row in range(panel.table.rowCount()):
        item = panel.table.item(row, 1)
        if item is not None and item.data(Qt.UserRole) == name:
            return row
    raise AssertionError(f"module is missing from the table: {name}")


def _visible_names(panel):
    return [
        panel.table.item(row, 1).data(Qt.UserRole)
        for row in range(panel.table.rowCount())
        if not panel.table.isRowHidden(row)
    ]


def _items(panel, name):
    row = _row(panel, name)
    return tuple(panel.table.item(row, col) for col in range(7))


def _toggle_with_keyboard(panel, name):
    panel.resize(1000, 450)
    panel.show()
    panel.table.setCurrentCell(_row(panel, name), 0)
    panel.table.setFocus()
    QApplication.instance().processEvents()
    QTest.keyClick(panel.table, Qt.Key_Space)
    QApplication.instance().processEvents()


@pytest.mark.parametrize("module_count", [84, 200])
def test_discovery_additions_preserve_existing_items_and_selection(
    panel_factory, module_count,
):
    modules = [_ProbeModule(f"Module {index:03}") for index in range(module_count)]
    panel, manager = panel_factory(modules[:40])
    panel.table.sortItems(1, Qt.AscendingOrder)
    selected = modules[20].name
    panel.table.setCurrentCell(_row(panel, selected), 1)
    originals = {module.name: _items(panel, module.name) for module in modules[:40]}

    # Discovery completes across multiple status ticks during startup.
    for batch in (modules[40:60], modules[60:]):
        manager.modules.update((module.name, module) for module in batch)
        panel.refresh()
        for name, old_items in originals.items():
            assert all(old is new for old, new in zip(old_items, _items(panel, name)))
        assert panel.table.item(panel.table.currentRow(), 1).data(Qt.UserRole) == selected
        assert panel.table.item(_row(panel, selected), 1).isSelected()

    assert panel.table.rowCount() == module_count
    assert not panel.findChildren(QCheckBox)
    for name in manager.modules:
        row = _row(panel, name)
        assert panel.table.cellWidget(row, 0) is None
        assert panel.table.item(row, 0).flags() & Qt.ItemIsUserCheckable
    assert manager.enable_calls == []


def test_unchanged_refresh_preserves_every_item_without_policy_writes(panel_factory):
    panel, manager = panel_factory([_ProbeModule("Alpha"), _ProbeModule("Bravo")])
    original = {name: _items(panel, name) for name in manager.modules}
    changes = QSignalSpy(panel.table.itemChanged)
    for _ in range(4):
        panel.refresh()
    for name, old_items in original.items():
        assert all(old is new for old, new in zip(old_items, _items(panel, name)))
    assert manager.enable_calls == []
    assert changes.count() == 0


def test_programmatic_refresh_uses_authoritative_enabled_state(panel_factory):
    module = _ProbeModule("Alpha")
    panel, manager = panel_factory([module])
    manager.enabled[module.name] = False
    module.status = "stopped"
    panel.refresh()

    checkbox, _, status, *_ = _items(panel, module.name)
    assert checkbox.checkState() == Qt.Unchecked
    assert checkbox.text() == "Off"
    assert status.text() == "stopped"
    assert manager.enable_calls == []

    manager.enabled[module.name] = True
    module.status = "running"
    panel.refresh()
    assert _items(panel, module.name)[0].checkState() == Qt.Checked
    assert _items(panel, module.name)[0].text() == "On"
    assert manager.enable_calls == []


def test_keyboard_toggle_targets_module_after_sort_and_reorders_safely(panel_factory):
    panel, manager = panel_factory([
        _ProbeModule("Alpha", score=9), _ProbeModule("Zulu", score=100),
    ])
    panel.table.sortItems(3, Qt.DescendingOrder)
    assert _visible_names(panel)[0] == "Zulu"
    _toggle_with_keyboard(panel, "Zulu")

    assert manager.enable_calls == [("Zulu", False)]
    assert manager.enabled == {"Alpha": True, "Zulu": False}
    assert _items(panel, "Zulu")[0].checkState() == Qt.Unchecked
    assert _items(panel, "Zulu")[0].text() == "Off"
    assert _items(panel, "Alpha")[0].checkState() == Qt.Checked

    # Sorting on the edited column may move the row during the itemChanged slot.
    panel.table.sortItems(0, Qt.AscendingOrder)
    _toggle_with_keyboard(panel, "Zulu")
    assert manager.enable_calls == [("Zulu", False), ("Zulu", True)]
    assert _items(panel, "Zulu")[0].checkState() == Qt.Checked
    assert _items(panel, "Zulu")[0].text() == "On"


@pytest.mark.parametrize("denial", ["ignore", "raise"])
def test_denied_toggle_reverts_to_manager_state(panel_factory, denial):
    panel, manager = panel_factory([_ProbeModule("Protected")])
    manager.denial = denial
    _toggle_with_keyboard(panel, "Protected")

    assert manager.enable_calls == [("Protected", False)]
    assert manager.enabled["Protected"] is True
    assert _items(panel, "Protected")[0].checkState() == Qt.Checked
    assert _items(panel, "Protected")[0].text() == "On"
    assert not panel.table.signalsBlocked()
    assert panel.table.updatesEnabled()


def test_same_count_replacement_and_filter_changes_follow_current_modules(panel_factory):
    alpha = _ProbeModule("Alpha", category="Network", mode="detect")
    bravo = _ProbeModule("Bravo", category="Response", mode="respond")
    panel, manager = panel_factory([alpha, bravo])
    alpha_name_item = _items(panel, "Alpha")[1]
    manager.modules.pop("Bravo")
    charlie = _ProbeModule("Charlie", category="Response", mode="respond")
    manager.modules["Charlie"] = charlie
    panel.refresh()

    assert set(_visible_names(panel)) == {"Alpha", "Charlie"}
    assert _items(panel, "Alpha")[1] is alpha_name_item
    panel._module_search.setText("NETWORK")
    assert _visible_names(panel) == ["Alpha"]
    panel._mode_combo.setCurrentText("respond")
    assert _visible_names(panel) == []
    panel._module_search.clear()
    assert _visible_names(panel) == ["Charlie"]

    # A replacement under the same key must refresh metadata, too.
    replacement = _ProbeModule("Charlie", category="Integrity", mode="observe")
    replacement.version = "2.1.0"
    manager.modules["Charlie"] = replacement
    panel.refresh()
    assert _visible_names(panel) == []
    panel._mode_combo.setCurrentText("All modes")
    panel._module_search.setText(replacement.capability_id)
    assert _visible_names(panel) == ["Charlie"]
    assert [item.text() for item in _items(panel, "Charlie")[4:]] == [
        "Integrity", "observe", "2.1.0",
    ]
    assert manager.enable_calls == []


def test_assurance_sort_is_numeric_and_refresh_updates_sort_value(panel_factory):
    modules = [
        _ProbeModule("Nine", score=9), _ProbeModule("Hundred", score=100),
        _ProbeModule("Seventy", score=70),
    ]
    panel, manager = panel_factory(modules)
    panel.table.sortItems(3, Qt.AscendingOrder)
    assert _visible_names(panel) == ["Nine", "Seventy", "Hundred"]

    manager.modules["Nine"].assurance_score = 90
    panel.refresh()
    assert _visible_names(panel) == ["Seventy", "Nine", "Hundred"]
    assert _items(panel, "Nine")[3].text() == "90%"
    assert "90%" in _items(panel, "Nine")[3].toolTip()
    panel.table.sortItems(3, Qt.DescendingOrder)
    assert _visible_names(panel) == ["Hundred", "Nine", "Seventy"]


def test_sort_combo_orders_rows_and_refresh_preserves_manual_header_sort(panel_factory):
    modules = [
        _ProbeModule("Alpha", category="Network", score=100),
        _ProbeModule("Bravo", category="Integrity", score=9),
        _ProbeModule("Charlie", category="General", score=70),
    ]
    modules[1].status = "error"
    modules[2].status = "stopped"
    panel, manager = panel_factory(modules)
    manager.enabled["Bravo"] = False
    panel.refresh()

    for label, column, expected in (
        ("Status", 2, ["Bravo", "Alpha", "Charlie"]),
        ("Assurance", 3, ["Bravo", "Charlie", "Alpha"]),
        ("Category", 4, ["Charlie", "Bravo", "Alpha"]),
        ("Name", 1, ["Alpha", "Bravo", "Charlie"]),
    ):
        panel._sort_combo.setCurrentText(label)
        assert panel.table.horizontalHeader().sortIndicatorSection() == column
        assert _visible_names(panel) == expected
        panel.refresh()
        assert _visible_names(panel) == expected

    panel._sort_combo.setCurrentText("On/Off")
    assert set(_visible_names(panel)[:2]) == {"Alpha", "Charlie"}
    assert _visible_names(panel)[-1] == "Bravo"

    panel.table.sortItems(1, Qt.DescendingOrder)
    manager.modules["Alpha"].assurance_score = 40
    manager.modules["Delta"] = _ProbeModule("Delta")
    panel.refresh()
    assert _visible_names(panel) == ["Delta", "Charlie", "Bravo", "Alpha"]
    assert panel.table.horizontalHeader().sortIndicatorSection() == 1
    assert panel.table.horizontalHeader().sortIndicatorOrder() == Qt.DescendingOrder
    assert manager.enable_calls == []


@pytest.mark.parametrize("initially_blocked", [False, True])
def test_render_failure_restores_table_state_and_next_refresh_recovers(
    panel_factory, initially_blocked,
):
    panel, manager = panel_factory([_ProbeModule("Alpha")])
    panel.table.sortItems(3, Qt.AscendingOrder)
    panel.table.blockSignals(initially_blocked)
    manager.modules["Bravo"] = _ProbeModule("Bravo", score=9)
    panel.table.fail_next_item = True
    try:
        panel.refresh()
    except RuntimeError as exc:
        assert str(exc) == "synthetic rendering failure"

    assert panel.table.signalsBlocked() is initially_blocked
    assert panel.table.updatesEnabled()
    assert panel.table.isSortingEnabled()
    assert panel.table.horizontalHeader().sortIndicatorSection() == 3
    assert panel.table.horizontalHeader().sortIndicatorOrder() == Qt.AscendingOrder

    panel.refresh()
    assert _visible_names(panel) == ["Bravo", "Alpha"]
    assert all(item is not None for item in _items(panel, "Bravo"))
    assert panel.table.signalsBlocked() is initially_blocked
    assert manager.enable_calls == []
