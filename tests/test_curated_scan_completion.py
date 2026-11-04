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


def test_terminal_outcome_survives_progress_refill_between_queue_get_and_put(controller, monkeypatch):
    service = ready(controller)
    wait_until(lambda: not controller._worker.is_alive())
    entered, release = threading.Event(), threading.Event()

    def scan(*_args, **_kwargs):
        entered.set()
        assert release.wait(3)
        return {"state": "findings", "findings": [{"classification": "fixture"}]}

    service.scan = scan
    outcomes, refills = [], []
    controller.scan_outcome_ready.connect(outcomes.append)
    try:
        assert controller.scan(mode="full") and entered.wait(2)
        controller._timer.stop()
        frames = controller._frames
        for _ in range(frames.maxsize):
            controller._frame("progress", "Fixture progress backlog")
        assert frames.full()
        dequeue = frames.get_nowait

        def get_with_competing_refill():
            value = dequeue()
            if threading.current_thread() is controller._worker:
                frames.put_nowait(("progress", "Competing observation refilled the vacancy"))
                refills.append(True)
            return value

        monkeypatch.setattr(frames, "get_nowait", get_with_competing_refill)
        release.set()
        assert controller._done.wait(2)
        controller._worker.join(2)
        assert not controller._worker.is_alive() and refills
        controller._drain()
        assert report_visible(controller) and len(outcomes) == 1
        assert outcomes[0]["state"] == "findings" and controller.snapshot()["lifecycle"] == "terminal"
        assert "fixture" in controller._completion_dialog.text.toPlainText()
        controller._drain()
        assert len(outcomes) == 1
    finally:
        release.set()


def test_presentation_failure_has_visible_retained_retry_without_rescan(controller, monkeypatch):
    service = ready(controller)
    wait_until(lambda: not controller._worker.is_alive())
    panel = ui.SpywareScanControls(controller.manager, controller=controller)
    panel.show()
    QApplication.processEvents()
    original = controller.show_after_action
    attempts, outcomes = [], []
    controller.scan_outcome_ready.connect(outcomes.append)

    def show(report=None):
        attempts.append(report)
        if len(attempts) == 1:
            raise ValueError("Fixture automatic presentation failure")
        return original(report)

    monkeypatch.setattr(controller, "show_after_action", show)
    try:
        assert panel.review_button.isHidden() and controller.open_retained_scan_report() is None
        assert panel.start()
        wait_until(lambda: bool(outcomes))
        assert not report_visible(controller) and len(outcomes) == 1
        assert panel.review_button.isVisible() and panel.review_button.isEnabled()
        assert "could not open (ValueError)" in panel.review_notice.text()
        panel.review_button.click()
        assert report_visible(controller)
        assert len(service.requests) == 1 and len(outcomes) == 1 and len(attempts) == 2
        assert "ready for review" in panel.review_notice.text()
        assert controller._completion_dialog._report == outcomes[0]
        assert controller._completion_dialog._confirmed is False
    finally:
        panel.close()


def test_toolkit_findings_keep_independent_coverage_gap_in_combined_review(controller):
    service = ready(controller)
    wait_until(lambda: not controller._worker.is_alive())
    service.scan = lambda *_args, **_kwargs: dict(
        state="findings", findings=[{"classification": "unconfirmed fixture"}],
        coverage_incomplete=True, coverage={"not_checked": ["fixture collector unavailable"]})
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    assert controller.priority_scan(native_enabled=False, zero_breach_enabled=True, mode="full")
    wait_until(lambda: report_visible(controller))
    report, = outcomes
    assert report["state"] == "incomplete" and report["coverage_incomplete"] is True
    assert report["details"]["zero_breach"]["state"] == "findings"
    assert report["findings"] == [{"classification": "unconfirmed fixture"}]
    assert "fixture collector unavailable" in controller._completion_dialog.text.toPlainText()
    assert controller._completion_dialog._confirmed is False


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


def test_manual_request_queues_behind_an_automatic_scan(controller, monkeypatch):
    owner = controller
    owner._busy = True
    owner._snapshot.update(active_action="priority_scan", automatic=True)
    owner._next_report_count_limit = 9
    cancellations = []
    monkeypatch.setattr(owner, "_cancel_current", lambda: cancellations.append(True))
    try:
        assert owner.priority_scan(mode="browser")
        assert owner._pending_priority == {"mode": "browser"}
        assert cancellations == [True]
        assert owner._next_report_count_limit == 9
    finally:
        owner._busy = False
        owner._pending_priority = None


def test_schedule_probe_cannot_restore_a_revoked_one_run_allowance(controller):
    controller._automatic_probe_snapshot = {"state": "idle", "next_report_count_limit": 9}
    controller._next_report_count_limit = None
    controller._apply_automatic_probe("result", ("automatic_probe", {"state": "cooldown"}))
    assert "next_report_count_limit" not in controller.snapshot()
    assert controller.snapshot()["automatic_schedule"]["state"] == "cooldown"


def test_daily_scan_claim_uses_normal_priority_without_opening_a_report(controller, monkeypatch, tmp_path):
    from angerona.core.spyware_scan_schedule import AutomaticSpywareScanSchedule

    cfg = controller.manager.cfg
    cfg.data_dir = tmp_path
    cfg.spyware_scan_native_enabled = False
    cfg.spyware_scan_auto_enabled = True
    cfg.spyware_scan_auto_scope = "full"
    service = ready(controller)
    controller.manager.priority_scan_focus = lambda **_kwargs: pytest.fail("Daily scan throttled other defenses")
    controller._next_report_count_limit = 9
    controller._snapshot["next_report_count_limit"] = 9
    worker_threads = []
    check = AutomaticSpywareScanSchedule.check
    claim = AutomaticSpywareScanSchedule.claim

    def observed_check(schedule, **kwargs):
        worker_threads.append(threading.get_ident())
        return check(schedule, **kwargs)

    def observed_claim(schedule, **kwargs):
        worker_threads.append(threading.get_ident())
        return claim(schedule, **kwargs)

    monkeypatch.setattr(AutomaticSpywareScanSchedule, "check", observed_check)
    monkeypatch.setattr(AutomaticSpywareScanSchedule, "claim", observed_claim)
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    wait_until(lambda: not controller._worker.is_alive())
    controller._automatic_tick()
    wait_until(lambda: controller._automatic_due and not controller._worker.is_alive())
    controller._automatic_tick()
    wait_until(lambda: len(outcomes) == 1)

    request, = service.requests
    assert request.mode == "full" and request.priority == "normal" and request.max_cpu_percent == 25
    assert len(worker_threads) == 2 and threading.get_ident() not in worker_threads
    assert check(AutomaticSpywareScanSchedule(tmp_path)).status == "cooldown"
    assert outcomes[0]["automatic"] is True and not report_visible(controller)
    assert controller.retained_scan_attempt() == outcomes[0]["review_attempt"]
    assert controller.snapshot()["next_report_count_limit"] == controller._next_report_count_limit == 9
