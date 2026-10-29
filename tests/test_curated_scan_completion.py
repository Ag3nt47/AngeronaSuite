"""One shared after-action surface, only after actual owned scan work settles."""
from __future__ import annotations

import copy
import threading
import time

import pytest
from PySide6.QtWidgets import QApplication

from angerona.gui import curated_tools as ui
from test_curated_tools_ui import Focus, NativeScanner, ready, wait_until

pytest_plugins = ("test_curated_tools_ui",)


def report_visible(controller):
    dialog = controller._completion_dialog
    return dialog is not None and ui.isValid(dialog) and dialog.isVisible()


def test_two_views_get_one_nonmodal_completion_and_share_manual_review(controller):
    first, second = ui.CuratedScannerWidget(controller.manager), ui.CuratedScannerWidget(controller.manager)
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    try:
        ready(controller)
        assert controller.scan(mode="full")
        wait_until(lambda: report_visible(controller))
        dialog = controller._completion_dialog
        assert len(outcomes) == 1 and not dialog.isModal()
        assert dialog._report["state"] == "incomplete"
        assert "fixture gap" in dialog.text.toPlainText()
        assert dialog._confirmed is False
        assert all(not dialog.actions[action].isEnabled() for action in ("isolate", "kill", "patch", "lift_lockdown"))
        first._investigate()
        second._investigate(trace=True)
        assert first._after_action_dialog is second._after_action_dialog is dialog
        first.close()
        assert report_visible(controller)  # Closing a view does not own App's report.
        dialog.close()
        for _ in range(3):
            controller._drain()
        assert not dialog.isVisible() and len(outcomes) == 1
        assert controller.refresh()
        wait_until(lambda: not controller.snapshot()["busy"])
        assert not dialog.isVisible() and len(outcomes) == 1
        assert controller.scan(mode="full")
        wait_until(lambda: len(outcomes) == 2)
        assert controller._completion_dialog is dialog and dialog.isVisible()
    finally:
        first.close()
        second.close()


def test_completion_waits_for_native_request_and_backend_custody(controller):
    native, focus = NativeScanner(), Focus()
    controller.manager.modules["SpywareGuard"] = native
    controller.manager.priority_scan_focus = lambda **_kwargs: focus
    service = ready(controller)
    release = threading.Event()
    service.wait_for_shutdown = lambda _timeout: release.is_set()
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    try:
        assert controller.priority_scan(native_enabled=True, zero_breach_enabled=True)
        wait_until(lambda: bool(service.requests))
        assert focus.active and not outcomes and controller._completion_dialog is None
        native.finished.set()
        wait_until(lambda: controller.snapshot().get("lifecycle") == "draining")
        assert not outcomes and controller._completion_dialog is None
        assert controller.snapshot()["busy"] is True
        release.set()
        wait_until(lambda: report_visible(controller))
        assert len(outcomes) == 1 and not focus.active
        assert outcomes[0]["native"]["request_finished"] is True
        assert outcomes[0]["native"]["collector_finished"] is True
    finally:
        native.finished.set()
        release.set()


@pytest.mark.parametrize("expected", ["failed", "timed-out", "cancelled"])
def test_partial_failure_outcome_is_shown_once_with_literal_reason(controller, expected):
    service = ready(controller)
    entered, release = threading.Event(), threading.Event()
    progress_state = {}
    service.progress_snapshot = lambda: copy.deepcopy(progress_state)

    def scan(_request, operation, *, progress):
        progress_state.update(operation_id=operation.operation_id, state="running", current_file="D:/owned/History",
                              steps=[dict(id="history", completed=12, total=100, state="running")])
        entered.set()
        assert release.wait(3)
        if expected == "timed-out":
            operation.deadline = time.monotonic() - 1
        operation.check()
        raise ValueError("<b>Owned fixture reader failed</b>")

    service.scan = scan
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    try:
        assert controller.scan(mode="full") and entered.wait(2)
        wait_until(lambda: "toolkit" in controller.snapshot().get("scanner_progress", {}))
        if expected == "cancelled":
            controller.cancel()
        release.set()
        wait_until(lambda: report_visible(controller))
        assert len(outcomes) == 1 and outcomes[0]["state"] == expected
        assert outcomes[0]["scanner_progress"]["toolkit"]["steps"][0]["completed"] == 12
        assert controller._completion_dialog._confirmed is False
        if expected == "failed":
            assert "<b>Owned fixture reader failed</b>" in controller._completion_dialog.text.toPlainText()
        if expected == "timed-out":
            assert "budget reached" in controller._completion_dialog.text.toPlainText()
    finally:
        release.set()


def test_previous_scan_evidence_cannot_leak_into_early_failure_report(controller):
    service = ready(controller)
    service.scan = lambda *_args, **_kwargs: dict(
        state="findings", findings=[{"indicator": "old owned finding"}], report="D:/owned/old-report.json",
        native_retired=True, native_generations=[{"pid": 42, "native_retired": True}], job_id="a" * 32)
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    assert controller.scan(mode="full")
    wait_until(lambda: len(outcomes) == 1)

    def fail(*_args, **_kwargs):
        raise ValueError("Owned preflight refusal before any new native worker")

    service.scan = fail
    assert controller.scan(mode="full")
    wait_until(lambda: len(outcomes) == 2)
    latest = outcomes[-1]
    assert latest["state"] == "failed"
    assert latest["operation_id"] != outcomes[0]["operation_id"]
    assert all(key not in latest for key in ("findings", "report", "native_retired", "native_generations", "job_id"))
    assert "old owned finding" not in controller._completion_dialog.text.toPlainText()


def test_previous_tool_resource_sample_cannot_reenter_an_early_failure_review(controller):
    service = ready(controller)
    service.resource_snapshot = lambda: dict(operation_id="f" * 32, job_id="e" * 32,
                                             pid=987654, cpu_percent=99, process_alive=False)
    entered, release = threading.Event(), threading.Event()

    def fail(*_args, **_kwargs):
        entered.set()
        assert release.wait(2)
        raise ValueError("Owned early refusal")

    service.scan = fail
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    try:
        assert controller.scan(mode="full") and entered.wait(1)
        controller._drain()
        sample = controller.snapshot()["resource_usage"]
        assert sample["state"] == "unavailable" and "pid" not in sample
        release.set()
        wait_until(lambda: bool(outcomes))
        assert "987654" not in controller._completion_dialog.text.toPlainText()
        assert outcomes[-1]["resource_usage"]["state"] == "unavailable"
    finally:
        release.set()


def test_priority_preemption_defers_old_cancelled_prompt_until_new_scan_finishes(controller):
    native, focus = NativeScanner(), Focus()
    controller.manager.modules["SpywareGuard"] = native
    controller.manager.priority_scan_focus = lambda **_kwargs: focus
    service = ready(controller)
    entered = threading.Event()

    def scan(request, operation, *, progress):
        service.requests.append(request)
        if request.mode == "browser":
            entered.set()
            while True:
                operation.check()
                operation.cancelled.wait(.01)
        return dict(state="incomplete", coverage={"not_checked": ["new owned gap"]}, findings=[])

    service.scan = scan
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    try:
        assert controller.scan(mode="browser") and entered.wait(2)
        assert controller.priority_scan(native_enabled=True, zero_breach_enabled=True, mode="full")
        wait_until(lambda: native.state["state"] == "running")
        assert not outcomes and controller._completion_dialog is None
        assert controller._completion_deferred["state"] == "cancelled"
        assert controller.snapshot()["busy"] is True
        native.finished.set()
        wait_until(lambda: report_visible(controller))
        assert len(outcomes) == 1 and outcomes[0]["state"] == "incomplete"
        assert outcomes[0]["previous_attempt"]["state"] == "cancelled"
        assert "previous_attempt" not in outcomes[0]["previous_attempt"]
    finally:
        native.finished.set()


def test_shutdown_closes_shared_report_and_discards_late_terminal_frames(controller):
    ready(controller)
    assert controller.scan(mode="full")
    wait_until(lambda: report_visible(controller))
    dialog = controller._completion_dialog
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    thread = threading.Thread(target=controller.shutdown)
    thread.start()
    thread.join(2)
    assert not thread.is_alive() and controller._closed
    QApplication.processEvents()
    assert not ui.isValid(dialog) or not dialog.isVisible()
    controller._frame("result", ("scan", {"state": "completed", "findings": []}))
    controller._drain()
    QApplication.processEvents()
    assert controller._completion_dialog is None and not outcomes


def test_admitted_worker_start_failure_gets_review_but_invalid_budget_does_not(controller, monkeypatch):
    ready(controller)
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    assert not controller.scan(timeout_seconds=1)
    assert not outcomes and controller._completion_dialog is None

    def failed_start(_thread):
        raise RuntimeError("Owned thread-start fixture refusal")

    monkeypatch.setattr(ui.threading.Thread, "start", failed_start)
    assert not controller.scan(mode="full")
    assert len(outcomes) == 1 and outcomes[0]["state"] == "failed"
    assert "Owned thread-start fixture refusal" in controller._completion_dialog.text.toPlainText()
    assert controller.wait_for_shutdown(1)


def test_completion_listener_shutdown_fences_reentrant_new_operation(controller):
    ready(controller)
    # Stage a legitimately pending captured completion before its GUI turn.
    controller._completion_serial = 1
    controller._completion_pending = (1, {"state": "incomplete", "message": "Owned terminal record"})
    controller.scan_outcome_ready.connect(lambda _report: controller.shutdown())
    assert not controller.refresh()
    assert controller._closed and controller._completion_dialog is None
