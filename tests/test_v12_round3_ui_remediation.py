from __future__ import annotations

import inspect
import os
import threading
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QCheckBox, QDialog, QMessageBox

from angerona.core.eventbus import Event, Severity
from angerona.core.host_adaptation import HostAdaptationService
from angerona.gui.adaptation_workbench import AdaptationWorkbench
from angerona.gui.dashboard_details import ModuleResourceDialog
from angerona.gui.threat_intel_page import (
    ThreatIntelDashboard,
    _AnalysisReviewDialog,
)


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _pump_events(count: int = 8) -> None:
    app = _app()
    for _index in range(count):
        app.processEvents()


def _audit_report(findings: list[dict]) -> dict:
    return {
        "baseline_exists": True,
        "baseline_captured_at": "2026-08-27T00:00:00+00:00",
        "findings": findings,
        "active_findings": len(findings),
        "excluded_findings": 0,
        "risk_score": 50,
    }


def test_adaptation_findings_sort_by_typed_severity_and_numeric_risk(
    tmp_path: Path,
) -> None:
    _app()
    dialog = AdaptationWorkbench(HostAdaptationService(tmp_path))
    findings = [
        {"severity": "LOW", "category": "a", "change": "x", "key": "low", "score": 9},
        {"severity": "CRITICAL", "category": "a", "change": "x", "key": "critical", "score": 100},
        {"severity": "MEDIUM", "category": "a", "change": "x", "key": "medium", "score": 20},
        {"severity": "HIGH", "category": "a", "change": "x", "key": "high", "score": 2},
    ]
    try:
        dialog._display_audit(_audit_report(findings))
        dialog.findings_table.sortItems(0, Qt.SortOrder.DescendingOrder)
        assert [
            dialog.findings_table.item(row, 0).text()
            for row in range(dialog.findings_table.rowCount())
        ] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

        dialog.findings_table.sortItems(4, Qt.SortOrder.DescendingOrder)
        assert [
            dialog.findings_table.item(row, 4).text()
            for row in range(dialog.findings_table.rowCount())
        ] == ["100.0", "20.0", "9.0", "2.0"]
    finally:
        dialog.close()


def test_auto_adapt_discards_consent_if_task_starts_while_dialog_is_open(
    tmp_path: Path, monkeypatch,
) -> None:
    _app()
    dialog = AdaptationWorkbench(HostAdaptationService(tmp_path))
    launched: list[str] = []
    notices: list[str] = []

    def accept_after_race(_prompt: QDialog) -> int:
        dialog._busy_task = "audit"
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(QDialog, "exec", accept_after_race)
    monkeypatch.setattr(
        QMessageBox,
        "information",
        lambda _parent, _title, message: notices.append(message),
    )
    monkeypatch.setattr(
        dialog,
        "_run_task",
        lambda name, _operation: launched.append(name),
    )
    try:
        dialog._show_auto_adapt()
        assert launched == []
        assert any("request was discarded" in message for message in notices)
    finally:
        dialog._busy_task = ""
        dialog.close()


def test_auto_adapt_worker_uses_immutable_accepted_choices(
    tmp_path: Path, monkeypatch,
) -> None:
    _app()
    service = HostAdaptationService(tmp_path)
    dialog = AdaptationWorkbench(service)
    captured: dict[str, object] = {}
    baseline_captures: list[bool] = []

    def accept_with_apply(prompt: QDialog) -> int:
        for checkbox in prompt.findChildren(QCheckBox):
            checkbox.setChecked(True)
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(QDialog, "exec", accept_with_apply)
    monkeypatch.setattr(
        dialog,
        "_run_task",
        lambda name, operation: captured.update(name=name, operation=operation),
    )
    monkeypatch.setattr(service, "audit", lambda: {"current": {"firewall": {}}})
    monkeypatch.setattr(service, "build_plan", lambda profile, _current: profile)
    monkeypatch.setattr(
        service,
        "simulate_plan",
        lambda plan, _current: {"profile_id": plan, "changes": []},
    )
    monkeypatch.setattr(service, "_plan_relaxes_current", lambda *_args: False)
    monkeypatch.setattr(
        service,
        "security_baseline_status",
        lambda: {"available": bool(baseline_captures), "supported": True},
    )
    monkeypatch.setattr(
        service,
        "capture_security_baseline",
        lambda approved: (
            baseline_captures.append(approved)
            or {"available": True, "supported": True}
        ),
    )
    try:
        dialog._show_auto_adapt()
        assert captured["name"] == "auto_prepare"

        # These were the old mutable cross-dialog fields. Mutating them after
        # acceptance must not narrow or broaden the worker's consent snapshot.
        dialog._auto_apply_after_prepare = False
        dialog._auto_capture_recovery_baseline = False
        result = captured["operation"]()
        assert result["apply_requested"] is True
        assert result["recovery"]["available"] is True
        assert baseline_captures == [True]
    finally:
        dialog.close()


def test_safe_automatic_checkup_audits_once_and_simulates_every_profile(
    tmp_path: Path, monkeypatch,
) -> None:
    _app()
    service = HostAdaptationService(tmp_path)
    dialog = AdaptationWorkbench(service)
    captured: dict[str, object] = {}
    audit_calls: list[bool] = []
    simulated: list[tuple[str, dict]] = []
    profiles = tuple(service.profiles())
    current = {"firewall": {"Domain": True, "Private": True, "Public": True}}

    monkeypatch.setattr(
        dialog,
        "_run_task",
        lambda name, operation: captured.update(name=name, operation=operation),
    )
    monkeypatch.setattr(
        service,
        "audit",
        lambda: audit_calls.append(True) or {"current": current, "findings": []},
    )
    monkeypatch.setattr(
        service,
        "sandbox",
        lambda profile_id, snapshot: (
            simulated.append((profile_id, snapshot))
            or {"profile_id": profile_id, "changes": []}
        ),
    )
    monkeypatch.setattr(
        service,
        "apply_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("safe checkup attempted a host mutation")
        ),
    )
    try:
        dialog._run_safe_checkup()
        assert captured["name"] == "safe_checkup"
        result = captured["operation"]()
        assert audit_calls == [True]
        assert [item["profile_id"] for item in result["simulations"]] == [
            profile.profile_id for profile in profiles
        ]
        assert simulated == [(profile.profile_id, current) for profile in profiles]
    finally:
        dialog.close()


def test_module_event_refresh_identity_covers_details_and_hmac(monkeypatch) -> None:
    _app()
    current = [
        Event(
            "Process Monitor",
            "process created",
            Severity.HIGH,
            100.0,
            {"pid": 7, "path": "C:/one.exe"},
            "a" * 64,
        )
    ]

    def snapshot(_name: str) -> dict:
        return {"intensity": 1, "health": 100, "status": "running", "events": current}

    detail = ModuleResourceDialog("Process Monitor", snapshot)
    detail._timer.stop()
    rebuilds = 0
    original = detail.table.setRowCount

    def counted(rows: int) -> None:
        nonlocal rebuilds
        rebuilds += 1
        original(rows)

    monkeypatch.setattr(detail.table, "setRowCount", counted)
    try:
        current[0] = Event(
            "Process Monitor",
            "process created",
            Severity.HIGH,
            100.0,
            {"pid": 8, "path": "C:/two.exe"},
            "a" * 64,
        )
        detail._refresh()
        assert rebuilds == 1
        assert detail.table.item(0, 0).data(Qt.ItemDataRole.UserRole).details["pid"] == 8

        current[0] = Event(
            "Process Monitor",
            "process created",
            Severity.HIGH,
            100.0,
            {"pid": 8, "path": "C:/two.exe"},
            "b" * 64,
        )
        detail._refresh()
        assert rebuilds == 2
    finally:
        detail.close()


def test_per_row_cve_analysis_is_owned_nonblocking_and_close_safe(
    monkeypatch,
) -> None:
    _app()
    entered = threading.Event()
    release = threading.Event()
    analysis_threads: list[threading.Thread] = []
    results: list[dict] = []

    def blocking_analysis(rec: dict) -> dict:
        analysis_threads.append(threading.current_thread())
        entered.set()
        assert release.wait(5.0)
        return {
            "cve": rec["cve"],
            "fix_available": False,
            "reason": "bounded test result",
        }

    from angerona.core import cve_fix_advisor

    monkeypatch.setattr(cve_fix_advisor, "analyze", blocking_analysis)
    dashboard = ThreatIntelDashboard()
    dashboard._timer.stop()
    review = _AnalysisReviewDialog(dashboard)
    review.show()
    main_thread = threading.current_thread()
    worker = dashboard._start_detail_analysis(
        "CVE-2026-1234",
        {"cve": "CVE-2026-1234"},
        results.append,
    )
    assert worker is not None
    review._analysis_worker = worker
    assert worker.parent() is dashboard
    assert entered.wait(2.0)
    assert len(analysis_threads) == 1
    assert analysis_threads[0] is not main_thread

    # Both close paths hide immediately but retain the owned QThread until its
    # bounded advisor call returns; no GUI-thread wait or processEvents shim is used.
    review.close()
    dashboard.close()
    _pump_events()
    assert not review.isVisible()
    assert not dashboard.isVisible()

    release.set()
    assert worker.wait(5_000)
    _pump_events(12)
    assert results == [{
        "cve": "CVE-2026-1234",
        "fix_available": False,
        "reason": "bounded test result",
    }]
    assert "_start_detail_analysis" in inspect.getsource(
        ThreatIntelDashboard._stage_review
    )
    assert "processEvents" not in inspect.getsource(ThreatIntelDashboard._stage_review)
