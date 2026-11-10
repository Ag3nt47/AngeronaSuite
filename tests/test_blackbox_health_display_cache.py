"""Inert Qt evidence for Black Box's cached, read-only health display."""
from copy import deepcopy

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView

import blackbox_recorder as blackbox


@pytest.fixture
def app():
    return blackbox.QApplication.instance() or blackbox.QApplication([])


@pytest.fixture
def tab(app):
    view = blackbox.HealthTab()
    view.resize(680, 430)
    yield view
    view.close()
    view.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    app.processEvents()


def observation(rows, **changes):
    result = {
        "pid": 42, "state": "RUNNING", "cpu": 5.0, "rss": 4096,
        "bus_state": "OBSERVED", "bus_note": "inert cached observation", "bus_ts": None,
        "selftest_history_note": "Historical fixture; current health is separate.",
        "recovery_note": "Inert recovery observation", "failed": rows,
    }
    result.update(changes)
    return result


def rows(count):
    return [{"name": f"module-{index:04}", "detail": f"literal <b>issue {index}</b>",
             "src": "status"} for index in range(count)]


def show(tab, app):
    tab.show()
    app.processEvents()


def allocations(monkeypatch, tab):
    calls, sorts = [], []
    constructor, sorting = blackbox.QTableWidgetItem, tab.fail_table.setSortingEnabled

    def item(text):
        calls.append(text)
        return constructor(text)

    def sort(enabled):
        sorts.append(enabled)
        return sorting(enabled)

    monkeypatch.setattr(blackbox, "QTableWidgetItem", item)
    monkeypatch.setattr(tab.fail_table, "setSortingEnabled", sort)
    return calls, sorts


def source_index(table, row):
    return table.item(row, 0).data(Qt.UserRole)


def selected_key(tab, item):
    return tab._rendered_failure_keys[source_index(tab.fail_table, item.row())], item.column()


def test_repeated_1000_rows_skip_all_item_allocations_and_sorts_but_update_headings(
        monkeypatch, tab, app):
    show(tab, app)
    made, sorts = allocations(monkeypatch, tab)
    original = rows(1000)
    tab.on_health(observation(original))
    assert len(made) == 3000 and sorts == [False, True]
    first_item = tab.fail_table.item(0, 0)
    made.clear()
    sorts.clear()
    tab.on_health(observation(deepcopy(original), pid=43, cpu=19.0,
                              bus_state="STALE", bus_note="new stale observation",
                              selftest_history_note="new history availability",
                              recovery_note="new recovery availability"))
    assert not made and not sorts
    assert tab.fail_table.item(0, 0) is first_item
    assert tab.pid_lbl.text() == "PID: 43" and "CPU 19%" in tab.res_lbl.text()
    assert "STALE" in tab.bus_lbl.text() and "new stale observation" in tab.bus_lbl.text()
    assert "new history availability" in tab.history_lbl.text()
    assert "new recovery availability" in tab.recovery_lbl.text()
    assert tab.fail_table.rowCount() == 1000


def test_hidden_observations_have_no_table_work_and_show_latest_once(monkeypatch, tab, app):
    made, sorts = allocations(monkeypatch, tab)
    tab.on_health(observation(rows(1000)))
    latest = observation(rows(3), pid=77)
    tab.on_health(latest)
    assert not made and not sorts and tab.fail_table.rowCount() == 0
    assert tab.pid_lbl.text() == "PID: 77" and "issue 2" in tab.snapshot_text()
    show(tab, app)
    assert len(made) == 9 and sorts == [False, True]
    assert tab.fail_table.rowCount() == 3
    made.clear()
    sorts.clear()
    tab._render_pending_failure_rows()
    assert not made and not sorts
    tab.hide()
    app.processEvents()
    tab.on_health(observation(rows(4)))
    assert tab.fail_table.rowCount() == 3 and not made
    show(tab, app)
    assert tab.fail_table.rowCount() == 4 and len(made) == 12


def test_hidden_projection_is_immutable_even_if_sender_later_mutates_its_dictionary(tab, app):
    original = observation(rows(1))
    tab.on_health(original)
    original["failed"][0]["detail"] = "changed after observation"
    show(tab, app)
    assert tab.fail_table.item(0, 1).text() == "literal <b>issue 0</b>"
    assert "changed after observation" not in tab.snapshot_text()
    tab.on_health(original)
    assert tab.fail_table.item(0, 1).text() == "changed after observation"


def test_source_dates_and_duplicate_rows_are_not_deduplicated_or_hidden(monkeypatch, tab, app):
    show(tab, app)
    made, _sorts = allocations(monkeypatch, tab)
    historical = {"name": "same", "detail": "literal <img src=none>",
                  "src": "selftest (historical)", "recorded_scope": "run",
                  "recorded_at": "2026-11-01T10:00:00Z"}
    original = observation([dict(historical), dict(historical), *rows(1)])
    saved = deepcopy(original)
    tab.on_health(original)
    assert len(made) == 9 and tab.fail_table.rowCount() == 3
    assert tab._rendered_failure_keys[0] != tab._rendered_failure_keys[1]
    assert tab._rendered_failure_rows[0] == tab._rendered_failure_rows[1]
    assert "recorded run: 2026-11-01T10:00:00Z" in tab.snapshot_text()
    made.clear()
    changed = deepcopy(original)
    changed["failed"][1]["recorded_at"] = "2026-11-02T10:00:00Z"
    tab.on_health(changed)
    assert len(made) == 9 and tab.fail_table.rowCount() == 3
    assert "recorded run: 2026-11-02T10:00:00Z" in tab.snapshot_text()
    assert original == saved


@pytest.mark.parametrize("invalid", [
    None, {}, (), [None], [{"name": "missing-source", "detail": "x"}],
    [{"name": "bad-detail", "detail": 7, "src": "status"}],
    [{"name": "bad-date", "detail": "x", "src": "history", "recorded_at": 7,
      "recorded_scope": "run"}],
    [{"name": "bad-scope", "detail": "x", "src": "history", "recorded_at": "stamp",
      "recorded_scope": []}],
])
def test_malformed_snapshot_is_visible_without_clearing_last_valid_rows(
        monkeypatch, tab, app, invalid):
    show(tab, app)
    tab.on_health(observation(rows(1)))
    made, sorts = allocations(monkeypatch, tab)
    tab.on_health(observation(invalid, pid=88, bus_state="UNKNOWN"))
    assert tab.pid_lbl.text() == "PID: 88" and "UNKNOWN" in tab.bus_lbl.text()
    assert tab.fail_table.rowCount() == 1 and "issue 0" in tab.fail_table.item(0, 1).text()
    assert "snapshot unavailable" in tab._failure_heading.text()
    assert "Failure snapshot unavailable" in tab.snapshot_text()
    assert not made and not sorts
    tab.on_health(observation([]))
    assert tab.fail_table.rowCount() == 0
    assert tab._failure_heading.text() == "RECENTLY FAILED MODULES"


@pytest.mark.parametrize("pixel_scroll", [False, True])
def test_changed_rows_preserve_selection_current_and_visible_scroll_anchor(tab, app, pixel_scroll):
    show(tab, app)
    table = tab.fail_table
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    for column in range(3):
        table.setColumnWidth(column, 300)
    if pixel_scroll:
        table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.sortItems(0, Qt.AscendingOrder)
    original = rows(100)
    tab.on_health(observation(original))
    table.setCurrentCell(52, 1)
    table.item(53, 2).setSelected(True)
    table.verticalScrollBar().setValue(900 if pixel_scroll else 40)
    table.horizontalScrollBar().setValue(45)
    app.processEvents()
    before_current = selected_key(tab, table.currentItem())
    before_selected = {selected_key(tab, item) for item in table.selectedItems()}
    before_top = selected_key(tab, table.item(table.rowAt(0), 0))[0]
    before_horizontal = table.horizontalScrollBar().value()
    before_offset = table.visualItemRect(table.item(table.rowAt(0), 0)).top()
    changed = [{"name": "aaa-new", "detail": "new observation", "src": "status"},
               *deepcopy(original)]
    tab.on_health(observation(changed))
    assert selected_key(tab, table.currentItem()) == before_current
    assert {selected_key(tab, item) for item in table.selectedItems()} == before_selected
    assert selected_key(tab, table.item(table.rowAt(0), 0))[0] == before_top
    assert table.horizontalScrollBar().value() == before_horizontal
    if pixel_scroll:
        assert table.visualItemRect(table.item(table.rowAt(0), 0)).top() == before_offset
    assert table.verticalScrollBar().value() > 0
    assert table.isSortingEnabled() and table.updatesEnabled()


@pytest.mark.parametrize("sorting", [False, True])
def test_native_render_fault_restores_flags_does_not_commit_cache_and_retries(
        monkeypatch, tab, app, sorting):
    show(tab, app)
    table = tab.fail_table
    table.setSortingEnabled(sorting)
    original = table.setItem
    calls = []

    def fail_once(row, column, item):
        calls.append((row, column))
        if len(calls) == 2:
            raise RuntimeError("inert Qt insertion failure")
        return original(row, column, item)

    monkeypatch.setattr(table, "setItem", fail_once)
    health = observation(rows(3))
    with pytest.raises(RuntimeError, match="inert Qt insertion"):
        tab.on_health(health)
    assert table.isSortingEnabled() is sorting and table.updatesEnabled()
    assert tab._rendered_failure_rows is None and tab._failure_render_failed
    assert "may be incomplete" in tab._failure_heading.text()
    assert "Failure table refresh failed" in tab.snapshot_text()
    monkeypatch.setattr(table, "setItem", original)
    tab.on_health(health)
    assert table.rowCount() == 3 and tab._rendered_failure_rows is not None
    assert table.isSortingEnabled() is sorting and table.updatesEnabled()
    assert tab._failure_heading.text() == "RECENTLY FAILED MODULES"


def test_existing_disabled_updates_and_sorting_are_preserved(tab, app):
    show(tab, app)
    table = tab.fail_table
    table.setSortingEnabled(False)
    table.setUpdatesEnabled(False)
    tab.on_health(observation(rows(2)))
    assert not table.isSortingEnabled() and not table.updatesEnabled()
    assert table.rowCount() == 2
