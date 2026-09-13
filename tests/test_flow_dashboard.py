from __future__ import annotations

import os
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from angerona.core.config import Config  # noqa: E402
from angerona.core.evidence_store import EvidenceStore  # noqa: E402
from angerona.core.operations_center import LocalOperationsCenter  # noqa: E402
from angerona.gui.operations_center import (  # noqa: E402
    OperationsCenterDialog,
    RadialMetricCard,
)


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _settle(dialog, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _app().processEvents()
        dialog._flow_reader._poll()
        dialog._case_reader._poll()
        if not dialog._flow_reader.busy and not dialog._case_reader.busy:
            return
        time.sleep(0.002)
    pytest.fail("Flow snapshot did not settle")


def _dispose(dialog):
    dialog.close()
    for reader in (dialog._flow_reader, dialog._case_reader):
        reader.close()
        if reader.thread is not None:
            reader.thread.join(5)
            assert not reader.thread.is_alive()
    dialog.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


@pytest.fixture
def flow_service(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.db")
    service = LocalOperationsCenter(
        tmp_path, evidence_store=evidence,
        config=SimpleNamespace(ui_motion_enabled=False), master_key=b"f" * 32,
    )
    try:
        yield service
    finally:
        service.close()
        evidence.close()


def test_flow_dashboard_exposes_all_local_operations_tabs(tmp_path: Path) -> None:
    app = _app()
    evidence = EvidenceStore(tmp_path / "evidence.db")
    service = LocalOperationsCenter(
        tmp_path,
        evidence_store=evidence,
        config=SimpleNamespace(ui_motion_enabled=False),
        master_key=b"f" * 32,
    )
    try:
        dialog = OperationsCenterDialog(service)
        labels = [dialog.tabs.tabText(index) for index in range(dialog.tabs.count())]
        assert labels == [
            "Overview", "Cases", "Hunt", "Assets", "Detection Content",
            "Fleet Center", "DetectionForge", "AegisPath",
            "Parity & Interop", "Audit", "Info",
        ]
        assert dialog.deck.cards.keys() == {
            "cases", "evidence", "audit", "assets", "detections"
        }
        assert "LOCAL ONLY" in dialog.boundary.text()
        assert dialog.fleet_center.fabric is service.fleet_fabric
        assert dialog.detection_forge.service.registry is service.detections
        assert "UNKNOWN" in dialog.aegis_path.status_label.text()
        _settle(dialog)
        _dispose(dialog)
        app.processEvents()
    finally:
        service.close()
        evidence.close()


def test_flow_audit_verification_is_off_qt_and_refreshes_coalesce(flow_service, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    calls = []
    original = flow_service.audit.health

    def health(*args, **kwargs):
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(flow_service.audit, "health", health)
    dialog = OperationsCenterDialog(flow_service)
    ticks = []
    heartbeat = QTimer(dialog)
    heartbeat.timeout.connect(lambda: ticks.append(1))
    heartbeat.start(10)
    try:
        assert entered.wait(2)
        for _ in range(100):
            dialog.refresh_all()
        QTest.qWait(160)
        assert len(ticks) >= 3
        assert len(calls) == 1
        assert "UPDATING" in dialog.audit_health.text()
        release.set()
        _settle(dialog)
        assert len(calls) == 2
        assert all(ident != threading.get_ident() for ident in calls)
        assert dialog.audit_health.text() == "Integrity: VERIFIED"
        # A fresh verification failure must replace PASS; no presentation cache
        # is allowed to stand in for the authoritative ledger health read.
        monkeypatch.setattr(flow_service.audit, "health", lambda *_: {"chain_verified": False})
        dialog.refresh_all()
        _settle(dialog)
        assert dialog.audit_health.text() == "Integrity: CHECK REQUIRED"
    finally:
        release.set()
        heartbeat.stop()
        _dispose(dialog)


def test_flow_close_reopen_keeps_one_worker_and_discards_hidden_generation(flow_service, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    calls, applied = [], []
    original = flow_service.summary

    def summary():
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return {**original(), "evidence_records": len(calls)}

    monkeypatch.setattr(flow_service, "summary", summary)
    dialog = OperationsCenterDialog(flow_service)
    apply = dialog._flow_reader._apply
    dialog._flow_reader._apply = lambda result: (applied.append(result["summary"]["evidence_records"]), apply(result))
    try:
        assert entered.wait(2)
        worker = dialog._flow_reader.thread
        for _ in range(15):
            dialog.show()
            dialog.close()
        assert not dialog._flow_reader._timer.isActive()
        assert not dialog._case_reader._timer.isActive()
        assert dialog._flow_reader.thread is worker
        assert len(calls) == 1
        release.set()
        QTest.qWait(100)
        assert applied == []
        dialog.show()
        _settle(dialog)
        assert applied == [2]
        assert dialog._flow_reader.thread is worker
    finally:
        release.set()
        _dispose(dialog)


def test_flow_failed_read_marks_evidence_unavailable_and_can_retry(flow_service, monkeypatch):
    dialog = OperationsCenterDialog(flow_service)
    try:
        _settle(dialog)
        original = flow_service.inventory_store.load
        monkeypatch.setattr(flow_service.inventory_store, "load", lambda: 1 / 0)
        dialog.refresh_all()
        _settle(dialog)
        assert "UNAVAILABLE" in dialog.boundary.text()
        assert dialog.audit_health.text() == "Integrity: UNAVAILABLE"
        monkeypatch.setattr(flow_service.inventory_store, "load", original)
        dialog.refresh_all()
        _settle(dialog)
        assert "LOCAL ONLY" in dialog.boundary.text()
        assert dialog.audit_health.text() == "Integrity: VERIFIED"
    finally:
        _dispose(dialog)


def test_flow_destroy_during_blocked_read_does_not_wait_or_apply(flow_service, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    applied = []
    original = flow_service.summary

    def summary():
        entered.set()
        assert release.wait(5)
        return original()

    monkeypatch.setattr(flow_service, "summary", summary)
    dialog = OperationsCenterDialog(flow_service)
    reader = dialog._flow_reader
    reader._apply = applied.append
    try:
        assert entered.wait(2)
        start = time.monotonic()
        dialog.close()
        dialog.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert time.monotonic() - start < 0.25
        release.set()
        reader.thread.join(5)
        assert not reader.thread.is_alive()
        assert reader._closed
        assert applied == []
    finally:
        release.set()
        reader.close()
        reader.thread.join(5)


def test_flow_case_selection_discards_old_custody_and_disables_stale_updates(flow_service, monkeypatch):
    first = flow_service.create_case("First synthetic case")
    second = flow_service.create_case("Second synthetic case")
    dialog = OperationsCenterDialog(flow_service)
    entered, release = threading.Event(), threading.Event()
    original = flow_service.cases.get_case
    seen = []

    def get_case(case_id):
        seen.append((case_id, threading.get_ident()))
        if len(seen) == 1:
            entered.set()
            assert release.wait(5)
        return original(case_id)

    try:
        _settle(dialog)
        monkeypatch.setattr(flow_service.cases, "get_case", get_case)
        rows = {dialog.case_table.item(row, 0).data(Qt.UserRole): row for row in range(dialog.case_table.rowCount())}
        dialog.case_table.clearSelection()
        dialog.case_table.selectRow(rows[first.case_id])
        dialog._show_case_detail()
        assert entered.wait(2)
        dialog.case_table.selectRow(rows[second.case_id])
        dialog._show_case_detail()
        assert not dialog.case_update_button.isEnabled()
        assert dialog._case_loaded_id == ""
        updates = []
        monkeypatch.setattr(flow_service, "update_case", lambda *args, **kwargs: updates.append(args))
        dialog._update_case()
        assert updates == []
        release.set()
        _settle(dialog)
        assert "Second synthetic case" in dialog.case_detail.toPlainText()
        assert "First synthetic case" not in dialog.case_detail.toPlainText()
        assert dialog._case_loaded_id == second.case_id
        assert dialog.case_update_button.isEnabled()
        assert all(ident != threading.get_ident() for _, ident in seen)
    finally:
        release.set()
        _dispose(dialog)


def test_flow_audit_reuses_equal_display_rows_but_paints_changed_evidence(flow_service):
    flow_service.create_case("Audit rendering fixture")
    dialog = OperationsCenterDialog(flow_service)
    try:
        _settle(dialog)
        records = flow_service.audit_records(limit=500)
        dialog.audit_table.sortItems(0, Qt.AscendingOrder)
        items = [dialog.audit_table.item(0, column) for column in range(7)]
        dialog._refresh_audit(records)
        assert [dialog.audit_table.item(0, column) for column in range(7)] == items
        # Equal sequence/record IDs alone are not a sufficient presentation key.
        # Even a changed displayed field must repaint; verification remains in
        # the worker and is not replaced by this rendering fixture.
        row = records[0]
        entry = SimpleNamespace(**{name: getattr(row.entry, name) for name in (
            "timestamp", "action", "target", "result", "actor_id", "record_id")})
        entry.result = "changed fixture result"
        dialog._refresh_audit((SimpleNamespace(sequence=row.sequence, entry=entry),))
        assert dialog.audit_table.item(0, 4).text() == "changed fixture result"
        assert dialog.audit_table.item(0, 4) is items[4]
    finally:
        _dispose(dialog)


def test_flow_replacement_requested_during_apply_is_not_marked_current(flow_service):
    dialog = OperationsCenterDialog(flow_service)
    try:
        _settle(dialog)
        statuses, applied = [], []
        original = dialog._flow_reader._apply
        dialog._flow_reader._status = statuses.append

        def apply(result):
            original(result)
            applied.append(1)
            if len(applied) == 1:
                dialog.refresh_all()

        dialog._flow_reader._apply = apply
        dialog.refresh_all()
        _settle(dialog)
        assert statuses == ["updating", "updating", "current"]
    finally:
        _dispose(dialog)


def test_radial_metric_hover_property_is_bounded() -> None:
    _app()
    card = RadialMetricCard(
        "cases", "CASE FLOW", "#38bdf8",
        SimpleNamespace(ui_motion_enabled=False),
    )
    card.set_metric("7", 1.7, "seven active cases")
    assert card.ratio == 1.0
    card.hoverAmount = 2.0
    assert card.hoverAmount == 1.0
    card.hoverAmount = -1.0
    assert card.hoverAmount == 0.0


def test_flow_dashboard_preference_is_persisted(tmp_path: Path) -> None:
    config = Config(data_dir=tmp_path)
    config.dashboard_mode = "flow"
    config.save()
    payload = json.loads(config.settings_path.read_text(encoding="utf-8"))
    assert payload["dashboard_mode"] == "flow"
