"""Inert controller/Qt scenarios; no scanner child, host collectors or evidence."""
from __future__ import annotations

import copy
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

from angerona.core import curated_tools as tools
from angerona.gui import curated_tools as ui


def wait_until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.01)
    assert predicate()


class Native:
    def __init__(self):
        self.finished = threading.Event()
        self.entered = threading.Event()
        self.cancelled = []
        self.request = ""

    def request_priority_scan(self, request):
        self.request = request
        self.entered.set()
        return True

    def priority_scan_snapshot(self):
        done = self.finished.is_set()
        return dict(request_id=self.request, lifecycle_generation=7,
                    state="completed" if done else "running", request_finished=done, collector_finished=done,
                    progress=dict(state="completed" if done else "running", overall_percent=100 if done else None,
                                  current_task="Synthetic native check", current_file="fixture only", steps=[]))

    def cancel_priority_scan(self, request):
        self.cancelled.append(request)  # Cancellation is a request, not completion proof.


class Service:
    def __init__(self, *, cfg=None):
        self.progress = {}
        self.native = None
        self.scan_entered = threading.Event()

    def status(self):
        return dict(state="ready", installed=True, verified=True, version="fixture")

    def scan(self, _request, operation, *, progress):
        self.scan_entered.set()
        if self.native is not None and self.native.finish_before_hold:
            self.native.finished.set()
        self.progress = dict(operation_id=operation.operation_id, state="not-started", native_started=False,
                             owner_retired=True, current_task="Toolkit admission held by retained reports",
                             current_file="", remaining_s=None, remaining_budget_s=None,
                             overall_percent=None, steps=[])
        raise tools.ToolStorageHeld("Retained scanner jobs reached their limit; nothing was deleted.",
                                    kind="report-count", reports=8, used_bytes=1024, limit_bytes=64 * 1024**2)

    def progress_snapshot(self):
        return copy.deepcopy(self.progress)

    def review_reports(self, _operation, *, progress):
        return dict(state="storage-review", storage_reports=[], storage={"retained_reports": 8, "report_limit": 8},
                    message="Synthetic metadata review; nothing deleted")

    def wait_for_shutdown(self, _timeout=0):
        return True  # This inert service has no native children.

    def cancel_all(self):
        pass

    def close(self):
        pass


@pytest.fixture
def controller(monkeypatch):
    backend = SimpleNamespace(ToolOperation=tools.ToolOperation, ToolScanRequest=tools.ToolScanRequest,
                              ToolStorageHeld=tools.ToolStorageHeld, CuratedToolService=Service)
    monkeypatch.setattr(ui, "_backend", lambda: backend)
    manager = SimpleNamespace(cfg=SimpleNamespace(github_tools_enabled=True), modules={})
    result = ui.CuratedToolsController(manager)
    result._service = Service()
    delivered = []
    monkeypatch.setattr(result, "show_after_action", lambda report=None, **_kwargs: delivered.append(copy.deepcopy(report)) or object())
    result.delivered_fixture = delivered
    result._publish(**result._service.status())
    yield result
    if result._native_priority_module is not None:
        result._native_priority_module.finished.set()
    result.shutdown()
    assert result.wait_for_shutdown(4)
    result.deleteLater()


def test_quota_hold_returns_one_terminal_partial_report_with_native_completion(controller):
    native = Native()
    native.finish_before_hold = True
    controller._service.native = native
    controller.manager.modules["SpywareGuard"] = native
    assert controller.priority_scan(native_enabled=True, zero_breach_enabled=True)
    wait_until(lambda: not controller.snapshot()["busy"] and bool(controller.delivered_fixture))
    snapshot = controller.snapshot()
    assert snapshot["state"] == "held" and snapshot["lifecycle"] == "terminal"
    assert snapshot["verified"] is True  # Storage admission does not invalidate the installed engine.
    assert snapshot["native"]["state"] == "completed"
    assert snapshot["details"]["zero_breach"]["state"] == "not-started"
    assert snapshot["scan_progress"]["state"] == "held"
    assert snapshot["scan_progress"]["finished"] == 2 and snapshot["scan_progress"]["total"] == 4
    assert snapshot["scan_progress"]["finished_stages"] == ("native", "preflight")
    assert snapshot["scanner_progress"]["native"]["state"] == "completed"
    assert snapshot["scanner_progress"]["toolkit"]["state"] == "not-started"
    assert snapshot["scanner_progress"]["toolkit"]["remaining_s"] is None
    assert snapshot["coverage_incomplete"] is True and len(controller.delivered_fixture) == 1
    assert not native.cancelled
    controls = ui.SpywareScanControls(controller.manager, controller=controller)
    try:
        controls._apply(snapshot)
        assert controls.progress_ring.percent == 50 and controls.progress_ring.busy is False
        assert "held" in controls.progress_stage.text().lower()
        assert "Export alone does not free slots" in controls.stage_explanation.text()
        assert "workflow ended" in controls.stage_chips["toolkit"].accessibleName()
        assert "not-started" in controls.scanner_summaries["toolkit"].text()
        assert "Last observed task" in controls.activity.text()
    finally:
        controls.close()


def test_quota_hold_does_not_release_native_request_before_actual_completion(controller):
    native = Native()
    native.finish_before_hold = False
    controller._service.native = native
    controller.manager.modules["SpywareGuard"] = native
    assert controller.priority_scan(native_enabled=True, zero_breach_enabled=True)
    wait_until(lambda: bool(native.cancelled))
    assert controller.snapshot()["busy"] is True
    assert controller._worker.is_alive() and not controller.delivered_fixture
    native.finished.set()
    wait_until(lambda: not controller.snapshot()["busy"] and bool(controller.delivered_fixture))
    assert controller.snapshot()["native"]["collector_finished"] is True
    assert len(controller.delivered_fixture) == 1


def test_standalone_quota_hold_does_not_mark_installed_engine_unverified(controller):
    assert controller.scan()
    wait_until(lambda: not controller.snapshot()["busy"] and bool(controller.delivered_fixture))
    assert controller.snapshot()["state"] == "held" and controller.snapshot()["verified"] is True
    assert controller.snapshot()["scanner_progress"]["toolkit"]["state"] == "not-started"


def test_storage_review_preserves_last_scan_aar_and_clears_old_refresh_error(controller):
    assert controller.scan()
    wait_until(lambda: not controller.snapshot()["busy"] and bool(controller.delivered_fixture))
    saved = copy.deepcopy(controller._last_scan_report)
    controller._snapshot["storage_review_error"] = "old fixture failure"
    assert controller.review_reports()
    wait_until(lambda: not controller.snapshot()["busy"])
    assert "storage_review_error" not in controller.snapshot()
    assert controller._last_scan_report == saved
    assert len(controller.delivered_fixture) == 1


def test_manual_aar_after_storage_action_shows_last_scan_and_review_button(controller):
    assert controller.scan()
    wait_until(lambda: not controller.snapshot()["busy"] and bool(controller.delivered_fixture))
    assert controller.review_reports()
    wait_until(lambda: not controller.snapshot()["busy"])
    dialog = ui.CuratedToolsController.show_after_action(controller)
    assert "last completed attempt" in dialog.notice.text()
    assert "held" in dialog.notice.text() and not dialog.isModal()
    assert dialog.scanner_storage_button.text() == "Review scanner storage…"


class StorageController(QObject):
    status_changed = Signal(dict)

    def __init__(self):
        super().__init__()
        self.calls = []
        self.values = dict(busy=False, message="Fixture review",
            storage={"retained_reports": 1, "report_limit": 8, "page": 0, "page_count": 1},
            storage_reports=[dict(job_id="a" * 32, receipt_sha256="b" * 64, state="complete", bytes=1024,
                                  can_export=True, can_delete=True, preview="literal <b>report</b>", message="fixture")])

    def snapshot(self):
        return copy.deepcopy(self.values)

    def review_reports(self, *, page=0):
        self.calls.append(("review",) if page == 0 else ("review", page))

    def export_report(self, **options):
        self.calls.append(("export", options))

    def clear_reports(self, expected, *, page=0):
        self.calls.append(("delete", expected, page))


def test_storage_dialog_is_modeless_and_delete_requires_explicit_receipt_choice():
    controller = StorageController()
    dialog = ui.ScannerStorageDialog(controller)
    try:
        assert not dialog.isModal() and dialog.delete_button.isEnabled()
        assert dialog.table.rowCount() == 1 and "<b>report</b>" in dialog.preview.toPlainText()
        dialog._confirm_delete()
        assert dialog._delete_prompt.standardButton(dialog._delete_prompt.defaultButton()) == QMessageBox.StandardButton.No
        dialog._delete_prompt.done(QMessageBox.StandardButton.No)
        QApplication.instance().processEvents()
        assert controller.calls == []
        dialog._confirm_delete()
        dialog._delete_prompt.done(QMessageBox.StandardButton.Yes)
        QApplication.instance().processEvents()
        assert controller.calls == [("delete", {"a" * 32: "b" * 64}, 0)]
    finally:
        dialog.close()
        dialog.deleteLater()


def test_delete_confirmation_cannot_dispatch_after_its_page_was_invalidated():
    controller = StorageController()
    dialog = ui.ScannerStorageDialog(controller)
    try:
        dialog._confirm_delete()
        controller.values.pop("storage")
        controller.status_changed.emit(controller.snapshot())
        assert dialog.table.rowCount() == 0 and not dialog.delete_button.isEnabled()
        dialog._delete_prompt.done(QMessageBox.StandardButton.Yes)
        assert controller.calls == []
    finally:
        dialog.close()
        dialog.deleteLater()


def test_storage_close_keeps_evidence_and_export_requires_chosen_destination(monkeypatch):
    controller = StorageController()
    dialog = ui.ScannerStorageDialog(controller)
    try:
        monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *_args: "")
        dialog._export()
        assert controller.calls == []
        monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *_args: "X:/fixture-selected")
        dialog._export()
        assert controller.calls == [("export", dict(job_id="a" * 32, expected_receipt="b" * 64,
                                                    destination="X:/fixture-selected"))]
        controller.calls.clear()
        dialog._confirm_delete()
        dialog.close()
        QApplication.instance().processEvents()
        assert controller.calls == []
    finally:
        dialog.close()
        dialog.deleteLater()


def test_busy_storage_review_disables_actions_and_retains_selection():
    controller = StorageController()
    dialog = ui.ScannerStorageDialog(controller)
    try:
        controller.values["busy"] = True
        controller.status_changed.emit(controller.snapshot())
        assert not dialog.refresh_button.isEnabled()
        assert not dialog.export_button.isEnabled() and not dialog.delete_button.isEnabled()
        assert dialog._selected()["job_id"] == "a" * 32
    finally:
        dialog.close()
        dialog.deleteLater()


def reviewed_capacity(controller, count=8):
    controller._publish(storage={"retained_reports": count, "report_limit": 8,
        "finite_report_limit": 32, "unknown_entries": False, "omitted_reports": 0})


def test_storage_review_shows_ninth_report_and_uses_its_exact_selection(monkeypatch):
    controller = StorageController()
    template = controller.values["storage_reports"][0]
    controller.values["storage_reports"] = [dict(template, job_id=f"{index:032x}") for index in range(9)]
    controller.values["storage"].update(retained_reports=9, finite_report_limit=32,
                                        unknown_entries=False, omitted_reports=0)
    dialog = ui.ScannerStorageDialog(controller)
    try:
        assert dialog.table.rowCount() == 9
        dialog.table.selectRow(8)
        selected = copy.deepcopy(dialog._selected())
        monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *_args: "X:/fixture-selected")
        dialog._export()
        assert controller.calls == [("export", dict(job_id=selected["job_id"],
            expected_receipt=selected["receipt_sha256"], destination="X:/fixture-selected"))]
        dialog._confirm_delete()
        dialog._delete_prompt.done(QMessageBox.StandardButton.Yes)
        QApplication.instance().processEvents()
        assert controller.calls[-1] == ("delete", {selected["job_id"]: selected["receipt_sha256"]}, 0)
    finally:
        dialog.close()
        dialog.deleteLater()


def test_extra_report_choice_defaults_no_escape_and_close_do_not_arm(controller):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest

    reviewed_capacity(controller)
    dialog = ui.ScannerStorageDialog(controller)
    try:
        assert dialog.allow_report_button.isEnabled()
        dialog._confirm_extra_report()
        prompt = dialog._count_prompt
        assert prompt.standardButton(prompt.defaultButton()) == QMessageBox.StandardButton.No
        assert prompt.standardButton(prompt.escapeButton()) == QMessageBox.StandardButton.No
        QTest.keyClick(prompt, Qt.Key.Key_Escape)
        QApplication.instance().processEvents()
        assert controller._next_report_count_limit is None and not controller.snapshot()["busy"]
        dialog._confirm_extra_report()
        dialog.close()
        QApplication.instance().processEvents()
        assert controller._next_report_count_limit is None and not controller._service.scan_entered.is_set()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_explicit_extra_report_choice_does_not_save_or_start_scan(controller, monkeypatch):
    before = dict(vars(controller.manager.cfg))
    monkeypatch.setattr(controller.manager.cfg, "save", lambda: pytest.fail("One-run consent must not save"), raising=False)
    reviewed_capacity(controller, count=9)  # Earlier extra report already exceeds saved default.
    dialog = ui.ScannerStorageDialog(controller)
    try:
        dialog._confirm_extra_report()
        dialog._count_prompt.done(QMessageBox.StandardButton.Yes)
        QApplication.instance().processEvents()
        assert controller._next_report_count_limit == 10
        assert not dialog.allow_report_button.isEnabled()
        assert not controller.allow_next_report(retained_reports=9, accepted=True)
        assert controller.snapshot()["next_report_count_limit"] == 10
        assert not controller.snapshot()["busy"] and not controller._service.scan_entered.is_set()
        assert {key: value for key, value in vars(controller.manager.cfg).items() if key != "save"} == before
        assert "Settings and existing evidence are unchanged" in controller.snapshot()["message"]
    finally:
        dialog.close()
        dialog.deleteLater()


def test_one_run_allowance_reaches_combined_scan_once_then_returns_to_default(controller, monkeypatch):
    native = Native()
    native.finished.set()
    controller.manager.modules["SpywareGuard"] = native
    limits = []

    def scan(_request, operation, *, progress):
        limits.append(operation.report_count_limit)
        return dict(state="complete", native_retired=True, findings=[], coverage={})

    monkeypatch.setattr(controller._service, "scan", scan)
    reviewed_capacity(controller)
    assert controller.allow_next_report(retained_reports=8, accepted=True)
    assert not controller.snapshot()["busy"]
    assert controller.priority_scan(native_enabled=True, zero_breach_enabled=True)
    wait_until(lambda: not controller.snapshot()["busy"])
    assert limits == [9] and controller._next_report_count_limit is None
    assert "storage" not in controller.snapshot()  # A subsequent choice requires a fresh review.
    assert controller.snapshot()["native"]["collector_finished"] is True
    assert controller.scan()
    wait_until(lambda: not controller.snapshot()["busy"])
    assert limits == [9, None]


def test_extra_report_allowance_is_consumed_by_refused_scan_and_cancel_revokes_it(controller):
    reviewed_capacity(controller)
    assert controller.allow_next_report(retained_reports=8, accepted=True)
    controller.cancel()
    assert controller._next_report_count_limit is None and "next_report_count_limit" not in controller.snapshot()
    reviewed_capacity(controller)
    assert controller.allow_next_report(retained_reports=8, accepted=True)
    assert controller.scan()  # The real controller receives an inert storage-hold result.
    wait_until(lambda: not controller.snapshot()["busy"])
    assert controller.snapshot()["state"] == "held" and controller._next_report_count_limit is None
    assert "next_report_count_limit" not in controller.snapshot()


@pytest.mark.parametrize("change", ["count-race", "cap", "unknown", "omitted", "unlimited", "review-error", "busy", "declined"])
def test_extra_report_choice_rejects_stale_unknown_capped_or_unaccepted_facts(controller, change):
    reviewed_capacity(controller)
    expected, accepted = 8, True
    if change == "count-race":
        expected = 7
    elif change == "cap":
        controller._snapshot["storage"]["retained_reports"] = 32
    elif change == "unknown":
        controller._snapshot["storage"]["unknown_entries"] = True
    elif change == "omitted":
        controller._snapshot["storage"]["omitted_reports"] = 1
    elif change == "unlimited":
        controller._snapshot["storage"]["report_limit"] = "unlimited"
    elif change == "review-error":
        controller._snapshot["storage_review_error"] = "Fixture refresh failed"
    elif change == "busy":
        controller._busy = True
    else:
        accepted = False
    try:
        assert not controller.allow_next_report(retained_reports=expected, accepted=accepted)
        assert controller._next_report_count_limit is None and not controller._service.scan_entered.is_set()
    finally:
        if change == "busy":
            controller._busy = False


@pytest.mark.parametrize("armed,new_count", [(False, 32), (True, 1), (True, "unlimited")])
def test_new_saved_count_revokes_old_review_and_allowance(controller, monkeypatch, armed, new_count):
    saved, observed = [], []

    class CountConfig:
        github_tools_enabled = True
        github_tools_report_count = 8

        def save(self):
            saved.append((self.github_tools_report_count, threading.get_ident()))

    controller.manager.cfg = CountConfig()
    reviewed_capacity(controller)
    if armed:
        assert controller.allow_next_report(retained_reports=8, accepted=True)
        assert controller._next_report_count_limit == 9
    assert controller.save_options({"github_tools_report_count": new_count})
    wait_until(lambda: not controller.snapshot()["busy"])
    assert controller.manager.cfg.github_tools_report_count == new_count
    assert len(saved) == 1
    assert saved[0][0] == new_count and saved[0][1] != threading.get_ident()
    assert controller._next_report_count_limit is None
    assert "storage" not in controller.snapshot() and "next_report_count_limit" not in controller.snapshot()
    assert not controller.allow_next_report(retained_reports=8, accepted=True)

    def scan(_request, operation, *, progress):
        observed.append(operation.report_count_limit)
        return dict(state="complete", findings=[], coverage={})

    monkeypatch.setattr(controller._service, "scan", scan)
    assert controller.scan()
    wait_until(lambda: not controller.snapshot()["busy"])
    assert observed == [None]  # The backend must use the newly saved policy.


def test_failed_storage_page_review_cannot_arm_a_new_allowance_from_stale_facts(controller, monkeypatch):
    reviewed_capacity(controller)
    controller._snapshot["storage"].update(page=0, page_count=2)
    assert ui._extra_report_choice(controller.snapshot()) == (8, 9)

    def unreadable(_operation, *, progress, page):
        assert page == 1
        raise tools.ToolError("Fixture inventory could not be reviewed")

    monkeypatch.setattr(controller._service, "review_reports", unreadable)
    assert controller.review_reports(page=1)
    assert "storage" not in controller.snapshot()
    wait_until(lambda: not controller.snapshot()["busy"] and not controller._worker.is_alive())
    snapshot = controller.snapshot()
    assert snapshot["state"] == "failed"
    assert "Fixture inventory could not be reviewed" in snapshot["storage_review_error"]
    assert "storage" not in snapshot
    assert not controller.allow_next_report(retained_reports=8, accepted=True)
    assert controller._next_report_count_limit is None

    def reviewed(_operation, *, progress):
        return {"state": "storage-review", "storage_reports": [], "storage": {
            "retained_reports": 8, "report_limit": 8, "finite_report_limit": 32,
            "unknown_entries": False, "page": 0, "page_count": 1,
        }}

    monkeypatch.setattr(controller._service, "review_reports", reviewed)
    assert controller.review_reports()
    wait_until(lambda: not controller.snapshot()["busy"])
    assert "storage_review_error" not in controller.snapshot()
    assert controller.allow_next_report(retained_reports=8, accepted=True)


@pytest.mark.parametrize("refresh_fails", [False, True])
def test_selected_delete_invalidates_old_rows_and_refreshes_same_page(controller, monkeypatch, refresh_fails):
    controller._publish(storage={"retained_reports": 34, "report_limit": "unlimited", "page": 1, "page_count": 2},
        storage_reports=[{"job_id": "a" * 32, "receipt_sha256": "b" * 64, "state": "complete",
                          "can_export": True, "can_delete": True, "preview": "deleted report"}])
    calls = []

    def delete(_operation, *, progress, expected):
        calls.append(("delete", expected))
        return {"state": "complete", "removed_reports": 1}

    def review(_operation, *, progress, page):
        calls.append(("review", page))
        if refresh_fails:
            raise tools.ToolError("Fixture post-delete review failed")
        return {"storage": {"retained_reports": 33, "report_limit": "unlimited", "page": 1, "page_count": 2},
                "storage_reports": [{"job_id": "c" * 32, "receipt_sha256": "d" * 64, "state": "complete",
                                     "can_export": True, "can_delete": True, "preview": "remaining report"}]}

    monkeypatch.setattr(controller._service, "clear_reports", delete, raising=False)
    monkeypatch.setattr(controller._service, "review_reports", review)
    dialog = ui.ScannerStorageDialog(controller)
    try:
        assert dialog.delete_button.isEnabled()
        dialog._confirm_delete()
        dialog._delete_prompt.done(QMessageBox.StandardButton.Yes)
        assert dialog.table.rowCount() == 0 and not dialog.delete_button.isEnabled()
        wait_until(lambda: not controller.snapshot()["busy"] and not controller._worker.is_alive())
        assert calls == [("delete", {"a" * 32: "b" * 64}), ("review", 1)]
        assert controller.snapshot()["removed_reports"] == 1 and dialog._page == 1
        if refresh_fails:
            assert "Fixture post-delete review failed" in dialog.summary.text()
            assert dialog.table.rowCount() == 0 and not dialog.export_button.isEnabled()
            assert not dialog.delete_button.isEnabled() and not dialog.preview.toPlainText()
        else:
            assert "page 2/2" in dialog.summary.text()
            assert dialog._selected()["job_id"] == "c" * 32 and dialog.delete_button.isEnabled()
        assert "deleted report" not in dialog.preview.toPlainText()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_unlimited_storage_dialog_pages_without_arming_a_count_exception():
    controller = StorageController()
    storage = controller.values["storage"]
    storage.update(retained_reports=34, report_limit="unlimited", finite_report_limit=32,
                   unknown_entries=False, page=0, page_count=2)
    template = controller.values["storage_reports"][0]
    controller.values["storage_reports"] = [
        dict(template, job_id=f"{index:032x}") for index in range(32)
    ]
    dialog = ui.ScannerStorageDialog(controller)
    try:
        assert "Unlimited slots" in dialog.summary.text()
        assert "page 1/2" in dialog.summary.text() and dialog.table.rowCount() == 32
        assert dialog.next_page.isEnabled() and not dialog.previous_page.isEnabled()
        assert not dialog.allow_report_button.isEnabled()
        dialog.next_page.click()
        assert controller.calls == [("review", 1)]
        storage["page"] = 1
        controller.values["storage_reports"] = [
            dict(template, job_id=f"{index:032x}") for index in range(32, 34)
        ]
        dialog._apply(controller.snapshot())
        assert "page 2/2" in dialog.summary.text() and dialog.table.rowCount() == 2
        assert not dialog.next_page.isEnabled() and dialog.previous_page.isEnabled()
        assert dialog._selected()["job_id"] == f"{32:032x}"
        dialog.previous_page.click()
        assert controller.calls[-1] == ("review",)
    finally:
        dialog.close()
        dialog.deleteLater()


@pytest.mark.parametrize("initial,chosen,expected", [("unlimited", 12, 12), (8, 0, "unlimited")])
def test_scanner_options_show_and_save_exact_unlimited_or_finite_choice(controller, monkeypatch, initial, chosen, expected):
    controller.manager.cfg.github_tools_report_count = initial
    saved = []
    monkeypatch.setattr(controller, "save_options", lambda values: saved.append(values))
    panel = ui.CuratedToolsSettings(controller)
    try:
        assert panel.report_count.value() == (0 if initial == "unlimited" else initial)
        assert panel.report_count.specialValueText() == "Unlimited"
        assert not saved
        panel.report_count.setValue(chosen)
        panel.save_button.click()
        assert saved[0]["github_tools_report_count"] == expected
    finally:
        panel.close()
        panel.deleteLater()


def test_failed_count_save_still_revokes_stale_exception_without_changing_config(controller):
    class CountConfig:
        github_tools_enabled = True
        github_tools_report_count = 8

        def save(self):
            raise OSError("Inert settings persistence refusal")

    controller.manager.cfg = CountConfig()
    reviewed_capacity(controller)
    assert controller.allow_next_report(retained_reports=8, accepted=True)
    assert controller.save_options({"github_tools_report_count": 1})
    wait_until(lambda: not controller.snapshot()["busy"])
    assert controller.manager.cfg.github_tools_report_count == 8
    assert controller._next_report_count_limit is None
    assert "storage" not in controller.snapshot() and "next_report_count_limit" not in controller.snapshot()
    assert controller.snapshot()["state"] == "failed" and "OSError" in controller.snapshot()["error"]
    assert not controller.allow_next_report(retained_reports=8, accepted=True)
