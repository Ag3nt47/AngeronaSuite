"""Operator actions stay bound to their session across nested evidence views."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent, QObject, Qt, Signal
from PySide6.QtWidgets import (
    QDialog, QLabel, QMessageBox, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.gui import pages, resolve_center
from angerona.gui.dashboard_details import ModuleResourceDialog
from angerona.gui.main_window import MainWindow


class _Window(QWidget):
    def _reveal_window_from(self, _source, callback, _color):
        return callback()


@pytest.fixture
def windows():
    owners = []

    def create():
        root = _Window()
        owners.append(root)
        root.bus = EventBus()
        root.bus.arm(BusAuthority(b"a" * 32))
        root.manager = SimpleNamespace(modules={})
        root.storage = SimpleNamespace(revision=lambda: 0, try_recent=lambda _limit: [])
        root.alerts_panel = pages.AlertsPanel(root.storage, bus=root.bus)
        QVBoxLayout(root).addWidget(root.alerts_panel)
        root.live_defense_activity = QWidget(root)
        root.alerts_panel.hide()
        return root

    yield create
    for root in owners:
        for dialog in reversed(root.findChildren(QDialog)):
            if shiboken6.isValid(dialog):
                dialog.close()
        root.alerts_panel.close()
        root.close()
        root.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _event(root, rule="startup-entry", *, ts=None):
    root.bus.publish(Event(
        "Persistence Sweep", f"Unreviewed startup entry: {rule}",
        Severity.CRITICAL, ts=time.time() if ts is None else ts,
        details={"rule_id": rule, "active_attack": True},
    ))
    return root.bus.recent(1)[0]


def _put_event(table, event):
    table.setRowCount(1)
    item = QTableWidgetItem("event")
    item.setData(Qt.UserRole, event)
    table.setItem(0, 0, item)


def _open_from(surface, root, event, monkeypatch):
    nested = QDialog(root)
    nested.bus = root.bus
    if surface == "dashboard-summary":
        MainWindow._open_live_defense_event(root, event)
    elif surface == "event-history":
        monkeypatch.setattr(pages.EventsWindow, "_refresh", lambda _self: None)
        view = pages.EventsWindow("Events", root.bus, root.storage, parent=nested)
        _put_event(view.table, event)
        view._open_detail(0, 0)
    elif surface == "module-feed":
        nested.feed = QTableWidget(0, 3, nested)
        _put_event(nested.feed, event)
        pages.ModuleInspector._on_feed_click(nested, 0, 0)
    elif surface == "module-history":
        nested._refresh_history = lambda: None
        tab = pages.ModuleInspector._history_tab(nested)
        QVBoxLayout(nested).addWidget(tab)
        _put_event(nested._hist_table, event)
        nested._hist_table.cellClicked.emit(0, 0)
    elif surface == "module-resources":
        view = ModuleResourceDialog(
            event.module, lambda _name: {"events": [event]}, nested,
        )
        view._open_event_detail(0, 0)
    elif surface == "resolve-detail":
        monkeypatch.setattr(resolve_center.ResolveCenter, "_refresh", lambda _self: None)
        view = resolve_center.ResolveCenter(root.bus, root.storage, root.manager, nested)
        view._detail(event)
    elif surface == "live-alert-row":
        table = root.alerts_panel.table
        row = next(index for index in range(table.rowCount())
                   if table.item(index, 0).data(Qt.UserRole) is event)
        root.alerts_panel._on_click(row, 0)
    else:
        raise AssertionError(surface)
    dialogs = root.findChildren(pages.AlertDetailDialog)
    assert len(dialogs) == 1
    assert dialogs[0]._event is event
    return dialogs[0]


@pytest.mark.parametrize("surface", [
    "dashboard-summary", "event-history", "module-feed", "module-history",
    "module-resources", "resolve-detail", "live-alert-row",
])
def test_allow_and_undo_work_from_every_evidence_surface(windows, monkeypatch, surface):
    root = windows()
    # Keep the target behind a newer row regardless of platform clock precision.
    target = _event(root, ts=time.time() - 2)
    sibling = _event(root, "other-rule")
    root.alerts_panel._apply_loaded_events(1, [target, sibling])
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.Yes)
    dialog = _open_from(surface, root, target, monkeypatch)
    assert not root.alerts_panel.isVisible()
    assert dialog._panel is root.alerts_panel
    assert "verified by the live EventBus" in dialog.findChild(
        QLabel, "alertEvidenceAuthenticity",
    ).text()

    dialog._b_allow.click()
    assert root.alerts_panel._is_suppressed(target)
    assert not root.alerts_panel._is_suppressed(sibling)
    assert root.alerts_panel.table.rowCount() == 1
    assert "Temporary suppression active" in dialog._action_status.text()
    assert dialog._b_undo_allow.isEnabled()

    dialog._b_undo_allow.click()
    assert not root.alerts_panel._is_suppressed(target)
    assert root.alerts_panel.table.rowCount() == 2
    assert not dialog._b_undo_allow.isEnabled()
    audits = [e.details["action"] for e in reversed(root.bus.recent(10))
              if e.module == "Operator Alert Suppression"]
    assert audits == ["created", "revoked"]


def test_nested_or_detached_view_never_uses_another_sessions_actions(windows):
    first, second = windows(), windows()
    child = QDialog(second)
    nested = QDialog(child)
    assert pages._alert_action_panel(nested) is second.alerts_panel
    detached = QDialog()
    detached.bus = second.bus
    try:
        assert pages._alert_action_panel(detached) is second.alerts_panel
        detached.bus = EventBus()
        assert pages._alert_action_panel(detached) is None
        assert pages._alert_action_panel(None) is None
        assert first.alerts_panel is not second.alerts_panel
    finally:
        detached.deleteLater()


def test_detail_undo_revokes_its_own_scope_and_keeps_later_allow(windows, monkeypatch):
    root = windows()
    first, second = _event(root, "first"), _event(root, "second")
    dialog = pages.AlertDetailDialog(first, QDialog(root))
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.Yes)
    dialog._b_allow.click()
    root.alerts_panel._allow_event(second)
    dialog._b_undo_allow.click()
    assert not root.alerts_panel._is_suppressed(first)
    assert root.alerts_panel._is_suppressed(second)
    assert root.alerts_panel._undo_allow.isEnabled()
    root.alerts_panel._undo_allow.click()
    assert not root.alerts_panel._suppressions


def test_detail_allow_cancellation_and_integrity_refusal_remain_visible(windows, monkeypatch):
    root = windows()
    target = _event(root)
    dialog = pages.AlertDetailDialog(target, QDialog(root))
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.No)
    dialog._b_allow.click()
    assert not root.alerts_panel._suppressions
    assert "No alert suppression" in dialog._action_status.text()
    integrity = pages.AlertDetailDialog(
        Event("Self Integrity Sentinel", "HMAC verification failed", Severity.CRITICAL), root,
    )
    monkeypatch.setattr(QMessageBox, "warning", lambda *_a, **_k: None)
    integrity._b_allow.click()
    assert not root.alerts_panel._suppressions
    assert "cannot be suppressed" in integrity._action_status.text()


class _AnalysisWorker(QObject):
    progress = Signal(str)
    result_ready = Signal(dict)
    error = Signal(str)
    finished = Signal()

    def __init__(self, alert, allow_cloud=False, parent=None):
        super().__init__(parent)
        self.alert, self.allow_cloud = alert, allow_cloud

    def start(self):
        pass


def test_analysis_progress_and_results_stay_with_exact_event_after_other_view_closes(
    windows, monkeypatch,
):
    from angerona.core import analysis_worker

    root = windows()
    monkeypatch.setattr(analysis_worker, "AnalysisWorker", _AnalysisWorker)
    monkeypatch.setattr(pages, "begin_loading", lambda _message: None)
    monkeypatch.setattr(pages, "finish_loading", lambda _token: None)
    target = _event(root)
    first = pages.AlertDetailDialog(target, QDialog(root))
    same = pages.AlertDetailDialog(target, QDialog(root))
    other = pages.AlertDetailDialog(_event(root, "other"), root)
    first._b_analyze.click()
    worker = root.alerts_panel._analyze_workers[0]
    assert worker.allow_cloud is False
    assert "Running" in first._action_status.text()
    assert "Running" in same._action_status.text()
    same._b_analyze.click()
    assert len(root.alerts_panel._analyze_workers) == 1
    assert "already running" in same._action_status.text()
    worker.progress.emit("Reading local evidence")
    assert same._action_status.text() == "Reading local evidence"
    assert other._action_status.text() == ""
    first.close()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not shiboken6.isValid(first)
    worker.result_ready.emit({
        "final_verdict": "BENIGN", "final_confidence": 95,
        "local": {"reasoning": "Known maintenance task"},
    })
    worker.finished.emit()
    assert "Known maintenance task" in same._action_status.text()
    assert other._action_status.text() == ""
    assert not root.alerts_panel._analyze_workers


def test_analysis_queue_feedback_and_errors_are_local_to_detail(windows, monkeypatch):
    root = windows()
    panel = root.alerts_panel
    panel._analyze_workers[:] = [object(), object()]
    dialog = pages.AlertDetailDialog(_event(root), QDialog(root))
    dialog._b_analyze.click()
    assert "Analyze queued" in dialog._action_status.text()
    panel._on_analyze_err("local model unavailable", dialog._b_analyze, dialog._action_identity)
    assert "local model unavailable" in dialog._action_status.text()
    for index in range(6):
        panel._analyze_event(_event(root, str(index)), None)
    refused = pages.AlertDetailDialog(_event(root, "queue-full"), root)
    refused._b_analyze.click()
    assert "queue is full" in refused._action_status.text()
    assert refused._b_analyze.isEnabled()


def test_resolve_allow_uses_same_scope_and_never_acknowledges_a_cancel(windows, monkeypatch):
    root = windows()
    monkeypatch.setattr(resolve_center.ResolveCenter, "_refresh", lambda _self: None)
    center = resolve_center.ResolveCenter(root.bus, root.storage, root.manager, QDialog(root))
    target = _event(root)
    # Process attribution must not change Allow into permanent process trust.
    target.details["name"] = "maintenance.exe"
    monkeypatch.setattr(resolve_center.alert_ack, "ack", lambda *_a: pytest.fail("unexpected ack"))
    from angerona.core import process_allowlist
    monkeypatch.setattr(process_allowlist, "add", lambda *_a, **_k: pytest.fail("unexpected trust"))
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.No)
    center._allow(target)
    assert not root.alerts_panel._suppressions
    assert "No alert suppression" in center._status.text()
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.Yes)
    center._allow(target)
    assert root.alerts_panel._is_suppressed(target)
    assert "Temporary suppression active" in center._status.text()


def test_block_in_detail_uses_shared_preflight_and_reports_refusal(windows, monkeypatch):
    root = windows()
    target = _event(root)
    dialog = pages.AlertDetailDialog(target, QDialog(root))
    checked = []

    def refuse(record, bus, manager):
        checked.append((bus, manager))
        raise PermissionError("the signed process instance is no longer live")

    monkeypatch.setattr(pages, "_soar_process_preflight", refuse)
    monkeypatch.setattr(QMessageBox, "warning", lambda *_a, **_k: None)
    monkeypatch.setattr(pages, "_persist_soar_queue", lambda *_a: pytest.fail("wrong standalone route"))
    dialog._act_block()
    assert checked == [(root.bus, root.manager)]
    assert "no longer live" in dialog._action_status.text()
    assert "completed" not in dialog._action_status.text()


def test_allow_expiry_disables_undo_in_all_open_details(windows, monkeypatch):
    root = windows()
    event = _event(root)
    first = pages.AlertDetailDialog(event, root)
    second = pages.AlertDetailDialog(event, QDialog(root))
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.Yes)
    first._b_allow.click()
    assert second._b_undo_allow.isEnabled()
    for scope in root.alerts_panel._suppressions:
        root.alerts_panel._suppressions[scope] = 0
    root.alerts_panel._events = []
    root.alerts_panel._last_storage_revision = 0
    root.alerts_panel.refresh()
    assert not first._b_undo_allow.isEnabled()
    assert not second._b_undo_allow.isEnabled()
