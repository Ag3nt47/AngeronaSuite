"""Sustained refresh and closed-view regressions, using inert evidence only."""
from __future__ import annotations

import dataclasses
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtWidgets import QApplication, QDialog, QWidget

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.gui import pages, top_talkers


def _drain_until(predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(0.002)
    assert predicate()


@pytest.mark.parametrize("kind", ["count", "alerts"])
def test_dashboard_reuses_one_reader_and_recovers_from_busy_and_failure(kind):
    state = SimpleNamespace(revision=0, result=None, error=False)
    calls = []

    def read(_limit):
        calls.append(threading.get_ident())
        if state.error:
            raise OSError("inert read failure")
        return state.result

    storage = SimpleNamespace(revision=lambda: state.revision,
                              try_count_since=read, try_recent=read)
    panel = (pages.DashboardCards(EventBus(), storage, SimpleNamespace(modules={}))
             if kind == "count" else pages.AlertsPanel(storage))
    reader = panel._count_reader if kind == "count" else panel._events_reader
    try:
        panel.refresh()
        _drain_until(lambda: not reader.busy)
        worker = reader.thread
        assert panel._last_storage_revision == -1  # busy is not an empty ledger
        state.error = True
        panel.refresh()
        _drain_until(lambda: not reader.busy)
        assert panel._last_storage_revision == -1
        state.error = False
        for revision in range(30):
            state.revision = revision
            state.result = revision if kind == "count" else [Event("fixture", str(revision))]
            panel.refresh()
            _drain_until(lambda: not reader.busy)
            assert reader.thread is worker
            assert panel._last_storage_revision == revision
        assert len(set(calls)) == 1
        assert calls[0] != threading.get_ident()
        if kind == "count":
            assert panel._cached_count == 29
        else:
            assert panel._events[0].message == "29"
    finally:
        panel.close()
        if reader.thread is not None:
            reader.thread.join(2)
            assert not reader.thread.is_alive()
        panel.deleteLater()


def _records(size=500):
    return [dict(request_id=f"{i:032x}", ts=float(i), status="PENDING",
                 origin_module="fixture", severity="High", message=f"row {i}")
            for i in range(size)]


def test_soar_change_retains_items_selection_scroll_and_fresh_action_data(monkeypatch):
    panel = pages.SoarPanel(EventBus())
    rows = _records()
    try:
        panel._apply_queue_snapshot((rows, "initial"))
        panel.show()
        QApplication.instance().processEvents()
        panel.table.selectRow(200)
        selected = panel._selected_request_id()
        scroll = panel.table.verticalScrollBar()
        scroll.setValue(100)
        position = scroll.value()
        old_items = [[panel.table.item(r, c) for c in range(5)] for r in range(500)]
        insert = Mock(wraps=panel.table.insertRow)
        monkeypatch.setattr(panel.table, "insertRow", insert)
        rows = [dict(row) for row in rows]
        rows[-1].update(status="APPROVED", action={"pid": 123}, execution_result="fresh")
        panel._apply_queue_snapshot((rows, "changed"))
        assert insert.call_count == 0
        assert all(panel.table.item(r, c) is old_items[r][c]
                   for r in range(500) for c in range(5))
        assert panel.table.item(0, 4).text() == "APPROVED"
        assert panel._queue_records[rows[-1]["request_id"]]["action"] == {"pid": 123}
        assert panel._approved_requests == {}  # display updates grant no authority
        assert panel._selected_request_id() == selected
        assert scroll.value() == position
    finally:
        panel.close()
        panel.deleteLater()


def test_soar_reorders_adds_removes_and_preserves_duplicate_history_rows():
    panel = pages.SoarPanel(EventBus())
    rows = _records(5)
    try:
        panel._apply_queue_snapshot((rows, "initial"))
        held = panel.table.item(3, 0)  # request 1
        panel.table.selectRow(0)  # request 4 will be removed
        updated = [rows[1], rows[0], dict(rows[1], message="duplicate"), rows[3]]
        panel._apply_queue_snapshot((updated, "reordered"))
        assert panel.table.rowCount() == 4
        assert [panel.table.item(r, 3).text() for r in range(4)] == [
            "row 3", "duplicate", "row 0", "row 1"]
        assert held in [panel.table.item(r, 0) for r in range(4)]
        assert panel._selected_request_id() == ""
        panel._apply_queue_snapshot(([], "cleared"))
        assert panel.table.rowCount() == 0
        assert panel._queue_display_rows == {}
        assert panel._queue_records == {}
    finally:
        panel.close()
        panel.deleteLater()


def test_soar_render_failure_restores_ui_and_retries(monkeypatch):
    panel = pages.SoarPanel(EventBus())
    rows = _records(3)
    try:
        panel._apply_queue_snapshot((rows, "initial"))
        new = _records(4)
        original = panel.table.insertRow
        monkeypatch.setattr(panel.table, "insertRow", Mock(side_effect=RuntimeError("inert")))
        with pytest.raises(RuntimeError, match="inert"):
            panel._apply_queue_snapshot((new, "new"))
        assert panel.table.updatesEnabled()
        assert not panel.table.signalsBlocked()
        assert panel._queue_fingerprint == "initial"
        monkeypatch.setattr(panel.table, "insertRow", original)
        panel._apply_queue_snapshot((new, "new"))
        assert [panel.table.item(r, 3).text() for r in range(4)] == [
            "row 3", "row 2", "row 1", "row 0"]
    finally:
        panel.close()
        panel.deleteLater()


def _receipt(request_id, **updates):
    details = dict(queue_request_id=request_id, action_succeeded=True,
                   postcondition_verified=True, action_ids=["action"], actions=["suspend_process"])
    details.update(updates)
    return Event("Adversary Combat", "fixture receipt", Severity.HIGH, details=details)


def test_batch_receipts_read_once_and_preserve_authentication_and_first_valid(monkeypatch):
    bus = EventBus()
    bus.arm(BusAuthority(b"r" * 32))
    rows = _records()
    for row in rows:
        row.update(status="SUBMITTED", submitted_at=time.time())
    first, second = rows[0]["request_id"], rows[1]["request_id"]
    bus.publish(_receipt(first, postcondition_verified=False))
    bus.publish(_receipt(first))
    valid_first = bus.recent(1)[0]
    bus.publish(_receipt(first, action_succeeded=False, action_ids=[], actions=[]))
    bus.publish(_receipt(second, action_succeeded=False, action_ids=[], actions=[]))
    valid_second = bus.recent(1)[0]
    forged = dataclasses.replace(valid_first, details={**valid_first.details, "queue_request_id": rows[2]["request_id"]})
    # A malformed request identifier must not make the shared batch fail.
    malformed = _receipt(["not a string"])
    events = [forged, malformed, *bus.recent(500)]
    recent = Mock(return_value=events)
    monkeypatch.setattr(bus, "recent", recent)
    updates = []
    monkeypatch.setattr(pages, "_update_soar_queue_record", lambda key, **kw: updates.append((key, kw)) or True)
    assert pages._reconcile_soar_submission_receipts(rows, bus)
    assert recent.call_count == 1
    assert [(key, update["receipt_hmac"]) for key, update in updates] == [
        (first, valid_first.hmac_sig), (second, valid_second.hmac_sig)]
    updates.clear()
    recent.reset_mock()
    assert not pages._reconcile_soar_submission_receipts(_records(), bus)
    assert recent.call_count == 0


@pytest.mark.parametrize("kind", ["events", "alert", "talkers"])
def test_direct_detail_windows_release_parent_owned_trees_on_close(kind, monkeypatch):
    parent = QWidget()
    storage = SimpleNamespace(try_recent_in_window=lambda *_: [])
    monkeypatch.setattr(top_talkers, "_collect_top_talkers", lambda _: {"rows": []})
    try:
        for _ in range(15):
            if kind == "events":
                dialog = pages.EventsWindow("fixture", EventBus(), storage, parent=parent)
            elif kind == "alert":
                dialog = pages.AlertDetailDialog(Event("fixture", "fixture"), parent=parent)
            else:
                dialog = top_talkers.TopTalkersDialog(parent)
            dialog.show()
            dialog.close()
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
            assert not shiboken6.isValid(dialog)
            assert parent.findChildren(QDialog) == []
    finally:
        top_talkers._top_talkers_pool().waitForDone(2000)
        parent.close()
        parent.deleteLater()
