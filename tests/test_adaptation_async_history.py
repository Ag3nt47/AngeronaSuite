"""Inert signed-view routing checks; no host collector or broker is admitted."""
from __future__ import annotations

import copy
import os
import threading
import time
from collections import Counter

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QPlainTextEdit, QPushButton, QWidget

from angerona.core.host_adaptation import PROFILES
from angerona.gui.adaptation_workbench import AdaptationWorkbench


class _Service:
    """Only fixed Python values, bounded event gates, and recorded reads."""

    def __init__(self):
        self.gui_thread = threading.get_ident()
        self.lock = threading.Lock()
        self.calls = Counter()
        self.threads = set()
        self.active = self.peak = 0
        self.gates = {}
        self.failures = {}
        self.automation_writes = []
        self.values = {
            "baseline": {"captured_at": "audit-fixture"},
            "recovery": {"available": True, "supported": True, "captured_at": "recovery-fixture",
                         "baseline_id": "baseline-fixture", "firewall_sha256": "a" * 64},
            "breaker": {"locked": False, "events": []},
            "transactions": [{"transaction_id": "txn-fixture", "updated_at": "2026-11-01",
                              "kind": "apply", "status": "verified", "profile_id": "balanced",
                              "snapshot_id": "snapshot-one", "receipt_digest": "fixture"}],
            "state": {"automation_enabled": True, "adaptive_weights": {"ports": 1.25},
                      "triggers": [{"id": "rule-fixture", "kind": "ssid", "value": "fixture",
                                    "profile_id": "balanced", "created_at": "2026-11-01"}]},
            "exceptions": [{"id": "exception-fixture", "category": "ports", "key": "fixture",
                            "reason": "known fixture", "created_at": "2026-11-01"}],
            "snapshots": [{"snapshot_id": f"snapshot-{suffix}", "captured_at": "2026-11-01",
                           "plan": {"profile_id": "balanced"}, "status": "ready",
                           "firewall": {"rules": [{"private_fixture": "never queued"}]}}
                          for suffix in ("one", "two")],
            "activity": [{"at": f"2026-11-01T00:{index:02d}:00", "action": "fixture",
                          "result": "success", "detail": f"literal <fixture> {index}"}
                         for index in range(60)],
        }

    def profiles(self):
        return tuple(PROFILES.values())

    def gate(self, name, call=1):
        entered, release = threading.Event(), threading.Event()
        self.gates[name, call] = entered, release
        return entered, release

    def _read(self, name):
        assert threading.get_ident() != self.gui_thread, f"{name} read reached the GUI thread"
        with self.lock:
            self.calls[name] += 1
            self.threads.add(threading.current_thread())
            self.active += 1
            self.peak = max(self.peak, self.active)
            gate = self.gates.get((name, self.calls[name]))
            value = copy.deepcopy(self.values[name])
            failure = self.failures.get(name)
        try:
            if gate:
                gate[0].set()
                assert gate[1].wait(5), "test did not release its inert read gate"
            if failure:
                raise OSError(failure)
            return value
        finally:
            with self.lock:
                self.active -= 1

    def load_baseline(self):
        return self._read("baseline")

    def security_baseline_status(self):
        return self._read("recovery")

    def breaker_status(self):
        return self._read("breaker")

    def transactions(self):
        return self._read("transactions")

    def state(self):
        return self._read("state")

    def list_exceptions(self):
        return self._read("exceptions")

    def list_snapshots(self):
        return self._read("snapshots")

    def activity(self):
        return self._read("activity")

    def set_automation(self, enabled, auto_apply):
        self.automation_writes.append((enabled, auto_apply))


def _until(predicate, timeout=5):
    app = QApplication.instance()
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.001)
    assert predicate(), "inert GUI operation did not settle within its bounded wait"


def _idle(dialog):
    _until(lambda: not dialog._status_active and dialog._status_thread is None
           and dialog._task_thread is None and not dialog._pending_status_views
           and dialog._results.empty() and not dialog._result_timer.isActive())


@pytest.fixture
def workbench(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("angerona.gui.recovery_panel.RecoveryPanel", lambda *_args: QWidget())
    monkeypatch.setattr("angerona.gui.prevention_panel.PreventionPanel", lambda *_args: QWidget())
    owned = []

    def create(service):
        dialog = AdaptationWorkbench(service)
        owned.append((service, dialog))
        return dialog

    yield create
    for service, dialog in owned:
        for _entered, release in service.gates.values():
            release.set()
        dialog.close()
        _idle(dialog)
        app.processEvents()


def _button(dialog, caption):
    return next(button for button in dialog.findChildren(QPushButton)
                if button.text() == caption or button.accessibleName() == caption)


def test_manual_history_wheel_coalesces_while_automatic_reads_stay_quiet(workbench):
    service = _Service()
    entered, release = service.gate("snapshots")
    dialog = workbench(service)
    _until(entered.is_set)
    assert dialog._activities.snapshot() == {}  # Initial/automatic history is quiet.
    dialog._refresh_snapshots(user_requested=True)
    first = dialog._history_activity
    dialog._refresh_snapshots(user_requested=True)
    assert dialog._history_activity == first
    assert dialog.progress_view.ring.percent is None
    release.set()
    _idle(dialog)
    assert dialog._activities.snapshot() == {} and service.calls["snapshots"] == 2


def test_task_result_publication_does_not_finish_wheel_before_thread_exit(workbench, monkeypatch):
    service = _Service()
    dialog = workbench(service)
    _idle(dialog)
    original = threading.Thread
    published, release = threading.Event(), threading.Event()

    def held_thread(*, target, **kwargs):
        def run():
            target()
            published.set()
            assert release.wait(5)
        return original(target=run, **kwargs)

    monkeypatch.setattr("angerona.gui.adaptation_workbench.threading.Thread", held_thread)
    try:
        dialog._run_task("fixture", lambda: {"literal": "result"})
        assert published.wait(2)
        dialog._poll_results()
        assert dialog._task_thread.is_alive() and dialog._activities.snapshot()
        release.set()
        _idle(dialog)
        assert dialog._activities.snapshot() == {}
    finally:
        release.set()
        if dialog._task_thread is not None:
            dialog._task_thread.join(3)
            assert not dialog._task_thread.is_alive()


@pytest.mark.parametrize("blocked", ["state", "exceptions", "snapshots", "activity"])
def test_initial_history_reads_leave_qt_responsive(workbench, blocked):
    service = _Service()
    entered, release = service.gate(blocked)
    dialog = workbench(service)
    _until(entered.is_set)
    marker = []
    QTimer.singleShot(0, lambda: marker.append("Qt event ran"))
    _until(lambda: bool(marker))
    assert dialog._status_active and not release.is_set()
    assert service.active == 1
    release.set()
    _idle(dialog)
    assert all(thread.ident != service.gui_thread for thread in service.threads)
    assert dialog.automation_enabled.isChecked()
    assert service.automation_writes == []  # Initial checkbox render blocks its signal.
    assert dialog.snapshot_combo.count() == 2
    assert dialog.activity_table.rowCount() == 60
    assert dialog.exceptions_table.rowCount() == dialog.trigger_table.rowCount() == 1


def test_initial_state_publication_preserves_checkbox_edit_while_read_is_blocked(workbench):
    service = _Service()
    service.values["state"]["automation_enabled"] = False
    entered, release = service.gate("state")
    dialog = workbench(service)
    _until(entered.is_set)
    assert not dialog.automation_enabled.isChecked() and not dialog._automation_initialized
    dialog.automation_enabled.click()
    assert dialog.automation_enabled.isChecked()
    assert service.automation_writes == [(True, False)]
    release.set()
    _idle(dialog)
    # The first read captured False before the explicit edit. Its eventual
    # publication initializes the view without restoring that stale value.
    assert service.values["state"]["automation_enabled"] is False
    assert dialog._automation_initialized and dialog.automation_enabled.isChecked()
    assert service.automation_writes == [(True, False)]
    assert service.calls["state"] == 1
    assert all(not thread.is_alive() for thread in service.threads)


def test_repeated_requests_union_into_one_followup_reader(workbench):
    service = _Service()
    entered, release = service.gate("snapshots")
    dialog = workbench(service)
    _until(entered.is_set)
    first_worker = dialog._status_thread
    for _index in range(24):
        dialog._refresh_snapshots()
        dialog._refresh_activity()
        dialog._refresh_exceptions()
        dialog._refresh_triggers()
    assert dialog._status_thread is first_worker
    assert dialog._pending_status_views == {"snapshots", "activity", "transactions", "exceptions", "state"}
    assert dialog._results.maxsize == 2 and service.peak == 1
    release.set()
    _idle(dialog)
    assert len(service.threads) == 2 and all(not thread.is_alive() for thread in service.threads)
    assert service.peak == 1
    assert all(service.calls[name] == 2 for name in ("snapshots", "activity", "transactions", "exceptions", "state"))
    assert all(service.calls[name] == 1 for name in ("baseline", "recovery", "breaker"))


def test_buttons_update_requested_rows_without_resetting_operator_inputs(workbench):
    service = _Service()
    dialog = workbench(service)
    _idle(dialog)
    dialog.automation_enabled.setChecked(False)
    _idle(dialog)  # Settle the supported action's own core-status refresh.
    core_counts = {key: service.calls[key] for key in ("baseline", "recovery", "breaker")}
    dialog.trigger_kind.setCurrentIndex(dialog.trigger_kind.findData("ssid"))
    dialog.trigger_value.setText("unsaved <literal> SSID")
    dialog.trigger_profile.setCurrentIndex(dialog.trigger_profile.findData("public"))
    review_marker = object()
    dialog._latest_plan = review_marker
    generation = dialog._review_generation
    dialog._latest_review = {"generation": generation, "report": {}}
    dialog.apply_button.setEnabled(False)
    recovery_view = dict(dialog._recovery_view)
    service.values["exceptions"][0]["reason"] = "updated fixture"
    service.values["state"]["adaptive_weights"] = {"ports": 1.5}
    service.values["state"]["triggers"][0]["value"] = "new persisted SSID"
    _button(dialog, "Refresh exceptions").click()  # clicked(False) must never become state.
    _idle(dialog)
    assert dialog.exceptions_table.item(0, 2).text() == "updated fixture"
    assert "ports 1.50×" in dialog.weights_label.text()
    assert dialog.trigger_table.item(0, 1).text() == "new persisted SSID"
    assert dialog.automation_enabled.isChecked() is False
    assert dialog.trigger_value.text() == "unsaved <literal> SSID"
    assert dialog.trigger_kind.currentData() == "ssid" and dialog.trigger_profile.currentData() == "public"
    assert dialog._latest_plan is review_marker and dialog._review_generation == generation
    assert dialog._recovery_view == recovery_view and not dialog.apply_button.isEnabled()
    service.values["activity"][0]["detail"] = "fresh activity fixture"
    # Keep ID/time/status/digest unchanged; a changed visible field still updates.
    service.values["transactions"][0]["kind"] = "rollback"
    _button(dialog, "Refresh activity").click()
    _idle(dialog)
    assert any(dialog.activity_table.item(row, 3).text() == "fresh activity fixture"
               for row in range(dialog.activity_table.rowCount()))
    assert dialog.transaction_table.item(0, 1).text() == "rollback"
    assert {key: service.calls[key] for key in core_counts} == core_counts
    assert dialog._recovery_view == recovery_view and not dialog.apply_button.isEnabled()


def test_transaction_update_preserves_selected_identity_column_scroll_and_open_detail(workbench):
    service = _Service()
    template = service.values["transactions"][0]
    service.values["transactions"] = [
        {**template, "transaction_id": f"txn-{index:03d}", "updated_at": f"2026-11-01T00:{index:02d}:00"}
        for index in range(60)
    ]
    dialog = workbench(service)
    _idle(dialog)
    dialog.resize(640, 700)
    dialog.show()
    dialog.tabs.setCurrentIndex(6)
    table = dialog.transaction_table
    table.sortItems(0, Qt.AscendingOrder)
    for column in range(table.columnCount()):
        table.setColumnWidth(column, 180)
    try:
        _until(lambda: table.verticalScrollBar().maximum() > 10 and table.horizontalScrollBar().maximum() > 0)
    except AssertionError as exc:
        raise AssertionError(
            "Transaction scroll geometry did not settle within 5s: "
            f"vertical(mode={table.verticalScrollMode()}, maximum={table.verticalScrollBar().maximum()}), "
            f"horizontal(mode={table.horizontalScrollMode()}, maximum={table.horizontalScrollBar().maximum()})"
        ) from exc
    selected_id = "txn-030"
    selected_row = next(row for row in range(table.rowCount())
                        if table.item(row, 0).data(Qt.UserRole)["transaction_id"] == selected_id)
    table.selectRow(selected_row)
    table.setCurrentCell(selected_row, 3)
    table.verticalScrollBar().setValue(10)
    table.horizontalScrollBar().setValue(min(20, table.horizontalScrollBar().maximum()))
    vertical, horizontal = table.verticalScrollBar().value(), table.horizontalScrollBar().value()
    assert vertical > 0 and horizontal > 0
    dialog._show_table_detail(table, selected_row)
    detail = dialog._row_detail_dialog
    original_detail = detail.findChild(QPlainTextEdit).toPlainText()
    updated = next(row for row in service.values["transactions"] if row["transaction_id"] == selected_id)
    updated.update(updated_at="2026-11-03", kind="rollback", status="held", profile_id="public",
                   detail="updated literal <transaction> fixture")
    service.values["transactions"].reverse()
    service.values["transactions"].append({**template, "transaction_id": "txn-added", "updated_at": "2026-10-31"})
    try:
        _button(dialog, "Refresh activity").click()
        _idle(dialog)
        current_row = table.currentRow()
        assert current_row != selected_row
        assert table.item(current_row, 0).data(Qt.UserRole)["transaction_id"] == selected_id
        assert {item.data(Qt.UserRole)["transaction_id"] for item in table.selectedItems()} == {selected_id}
        assert table.currentColumn() == 3
        assert table.verticalScrollBar().value() == vertical
        assert table.horizontalScrollBar().value() == horizontal
        assert [table.item(current_row, column).text() for column in (1, 2, 3)] == ["rollback", "held", "public"]
        assert table.item(current_row, 0).data(Qt.UserRole)["detail"] == "updated literal <transaction> fixture"
        assert detail.findChild(QPlainTextEdit).toPlainText() == original_detail
    finally:
        detail.close()


def test_unchanged_full_refresh_preserves_items_selection_scroll_and_open_detail(workbench):
    service = _Service()
    dialog = workbench(service)
    _idle(dialog)
    dialog.show()
    dialog.tabs.setCurrentIndex(6)
    QApplication.instance().processEvents()
    tables = (dialog.activity_table, dialog.exceptions_table, dialog.trigger_table, dialog.transaction_table)
    saved = []
    for table in tables:
        table.sortItems(0, Qt.AscendingOrder)
        table.selectRow(min(20, table.rowCount() - 1))
        table.verticalScrollBar().setValue(min(10, table.verticalScrollBar().maximum()))
        saved.append((table.item(table.currentRow(), 0), table.currentRow(),
                      table.verticalScrollBar().value(), table.horizontalScrollBar().value()))
    dialog.snapshot_combo.setCurrentIndex(1)
    selected_snapshot = dialog.snapshot_combo.currentData()
    dialog._show_table_detail(dialog.activity_table, dialog.activity_table.currentRow())
    detail = dialog._row_detail_dialog
    body = detail.findChild(QPlainTextEdit)
    original_detail = body.toPlainText()
    try:
        dialog._load_persisted_views()
        _idle(dialog)
        for table, (item, row, vertical, horizontal) in zip(tables, saved):
            assert table.item(row, 0) is item and table.currentRow() == row
            assert table.verticalScrollBar().value() == vertical
            assert table.horizontalScrollBar().value() == horizontal
        assert dialog.snapshot_combo.currentData() == selected_snapshot
        assert body.toPlainText() == original_detail and body.isReadOnly()
    finally:
        detail.close()


def test_read_failures_remain_visible_and_retain_successful_rows(workbench):
    service = _Service()
    dialog = workbench(service)
    _idle(dialog)
    dialog.snapshot_combo.setCurrentIndex(1)
    snapshot = dialog.snapshot_combo.currentData()
    tables = (dialog.activity_table, dialog.exceptions_table, dialog.trigger_table, dialog.transaction_table)
    items = []
    for table in tables:
        table.selectRow(0)
        items.append(table.item(0, 0))
    service.failures.update({key: f"signed {key} fixture held" for key in service.values})
    dialog._load_persisted_views()
    _idle(dialog)
    assert dialog.snapshot_combo.currentData() == snapshot and dialog.snapshot_combo.count() == 2
    for table, item in zip(tables, items):
        assert table.item(0, 0) is item and table.currentRow() == 0
    for label in (dialog.snapshot_status, dialog.activity_status, dialog.transaction_status,
                  dialog.trigger_status, dialog.weights_label):
        assert "unavailable" in label.text() and "signed" in label.toolTip()
    assert "integrity held" in dialog.recovery_status.text()
    assert not dialog._recovery_view.get("available")
    recovery_calls = service.calls["recovery"]
    service.failures.clear()
    dialog._refresh_activity()
    _idle(dialog)
    assert "unavailable" not in dialog.activity_status.text()
    assert "unavailable" not in dialog.transaction_status.text()
    assert "unavailable" in dialog.snapshot_status.text()
    assert "unavailable" in dialog.weights_label.text()
    assert "integrity held" in dialog.recovery_status.text()
    assert service.calls["recovery"] == recovery_calls
    dialog._load_persisted_views()
    _idle(dialog)
    assert dialog._persisted_errors == {}
    assert "unavailable" not in dialog.snapshot_status.text()
    assert dialog.snapshot_combo.currentData() == snapshot
    for table, item in zip(tables, items):
        assert table.item(0, 0) is item


def test_reopen_rejects_previous_generation_and_rechecks_recovery(workbench, monkeypatch):
    service = _Service()
    entered, release = service.gate("snapshots")
    dialog = workbench(service)
    _until(entered.is_set)
    worker = dialog._status_thread
    rendered = []
    real_finished = dialog._on_status_finished

    def finished(values):
        rendered.append(values)
        real_finished(values)

    monkeypatch.setattr(dialog, "_on_status_finished", finished)
    dialog._latest_plan, dialog._latest_review = object(), {"generation": dialog._review_generation}
    dialog.close()
    assert dialog._latest_plan is None and dialog._latest_review is None and not dialog.apply_button.isEnabled()
    assert dialog._recovery_view.get("checking") and not dialog._recovery_view.get("available")
    service.values["snapshots"] = [{"snapshot_id": "new-generation", "captured_at": "fresh"}]
    service.values["recovery"]["captured_at"] = "fresh-generation"
    dialog.show()
    assert dialog._status_thread is worker and len(service.threads) == 1
    assert "fresh-generation" not in dialog.recovery_status.text()
    release.set()
    _idle(dialog)
    assert len(rendered) == 1 and rendered[0]["snapshots"]["value"][0][0] == "new-generation"
    assert dialog.snapshot_combo.currentData() == "new-generation"
    assert "fresh-generation" in dialog.recovery_status.text()
    assert dialog._latest_plan is None and not dialog.apply_button.isEnabled()
    assert len(service.threads) == 2 and all(not thread.is_alive() for thread in service.threads)


def test_closed_reader_retires_naturally_without_rendering_or_spawning(workbench, monkeypatch):
    service = _Service()
    entered, release = service.gate("snapshots")
    dialog = workbench(service)
    _until(entered.is_set)
    worker = dialog._status_thread
    rendered = []
    monkeypatch.setattr(dialog, "_on_status_finished", lambda values: rendered.append(values))
    dialog._refresh_activity()
    dialog.close()
    assert worker.is_alive()
    release.set()
    _idle(dialog)
    assert not worker.is_alive() and len(service.threads) == 1
    assert rendered == [] and dialog._pending_status_views == set()
