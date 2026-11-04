"""Near-limit plain DTO fixtures; no host report, scanner or response action."""
from __future__ import annotations

import json
import time

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QThread
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from angerona.gui import action_worker as actions
from angerona.gui import simulation_diagnostics as gui


def near_budget_dto():
    """Schema-valid 512-row DTO within the producer's real serialized budget.

    The explanatory text is synthetic; this does not claim a real authenticated
    AAR currently emits these long reasons or grant the fixture trust authority.
    """
    result = {"schema": "angerona.simulation-diagnostics.v1", "run_id": "budget-fixture",
        "report_kind": "shark", "report_sha256": "1" * 64, "head_sha256": "2" * 64,
        "sequence": 1, "report_state": "complete", "overall_status": "failing",
        "coverage_score_eligible": True, "omitted_rows": 0, "omitted_text_characters": 0,
        "rows": [{"index": number, "stage": "Inert budget fixture", "technique": "T1059",
            "category": "detection", "detection_status": "fail", "response_status": "unscored",
            "status": "fail", "reason_code": "fixture.reason", "reason": "",
            "evidence": ["Synthetic plain evidence; no authority."],
            "next_steps": ["Review the exact producer contract before proposing any change."],
            "source_areas": ["src/angerona/shark/aar_report.py"],
            "fix_kind": "source-review", "fix_status": "not-applied"}
            for number in range(1, 513)]}
    # ASCII fill has exactly one encoded byte per added character. Distribute
    # it across rows so each selected detail stays well below its view limit.
    base = len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode("ascii"))
    remaining = 4 * 1024 * 1024 - 8 - base
    amount, extra = divmod(remaining, len(result["rows"]))
    for number, row in enumerate(result["rows"]):
        row["reason"] = "r" * (amount + (number < extra))
    return result


def test_producer_valid_near_four_mib_dto_is_not_rejected_by_pretty_print_expansion():
    data = near_budget_dto()
    producer_text = json.dumps(data, ensure_ascii=True, allow_nan=False)
    assert len(producer_text.encode("ascii")) == 4 * 1024 * 1024 - 8
    assert len(json.dumps(data, ensure_ascii=True, allow_nan=False, indent=2).encode("ascii")) > 4 * 1024 * 1024
    snapshot = gui._prepare_snapshot(data)
    assert snapshot.json_text == producer_text
    assert snapshot.data == data and json.loads(snapshot.json_text) == data
    assert len(snapshot.data["rows"]) == 512


def test_actual_serialized_oversize_is_rejected_without_truncation_or_input_mutation():
    data = near_budget_dto()
    data["rows"][0]["reason"] += "x" * 16
    before = json.dumps(data, ensure_ascii=True, allow_nan=False)
    assert len(before.encode("ascii")) == 4 * 1024 * 1024 + 8
    with pytest.raises(ValueError, match="nothing was truncated"):
        gui._prepare_snapshot(data)
    assert json.dumps(data, ensure_ascii=True, allow_nan=False) == before


def until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.005)
    assert predicate()


def test_near_budget_copy_export_remain_complete_and_selected_detail_readable(tmp_path, monkeypatch):
    assert not actions.active_finite_actions()
    monkeypatch.setattr(actions, "_CLOSING", False)
    data = near_budget_dto()
    monkeypatch.setattr(gui, "_load_verified_diagnostics", lambda _source, _owner: gui._prepare_snapshot(data))
    target = tmp_path / "complete-budget-fixture.json"
    monkeypatch.setattr(gui.QFileDialog, "getSaveFileName", lambda *_args: (str(target), "JSON files (*.json)"))
    panel = gui.SimulationDiagnosticsPanel(handoff="inert-budget-fixture")
    try:
        until(lambda: panel._worker is None and panel._snapshot is not None)
        panel.table.selectRow(0)
        selected = panel.detail.toPlainText()
        assert "FACTS FROM THE VERIFIED REPORT" in selected
        assert "PROPOSED REVIEW AND VALIDATION" in selected
        assert "Review the exact producer contract" in selected
        assert "display bounded" not in selected
        assert panel.detail.isReadOnly()
        panel.filter.setCurrentIndex(1)  # Hide every fail row in the table.
        assert panel.model.rowCount() == 0
        assert panel.copy_json()
        assert QApplication.clipboard().text() == panel._snapshot.json_text
        assert json.loads(QApplication.clipboard().text()) == data
        assert panel.export_json()
        until(lambda: panel._worker is None)
        assert target.read_bytes() == panel._snapshot.json_text.encode("ascii")
        assert json.loads(target.read_bytes()) == data
        assert not panel._activities.snapshot() and not panel._jobs
    finally:
        panel.close()
        for worker in actions.active_finite_actions():
            worker.requestInterruption()
            assert QThread.wait(worker, 3000)
            actions.poll_finite_action_retirement(worker)
        until(lambda: not actions.active_finite_actions())
        if isValid(panel):
            panel.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
