"""Real Qt controls with a synthetic maintained-scanner service; no host scans."""
from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from angerona.gui import curated_tools as ui
from angerona.gui.header_controls import HeaderActionButton, navigation_icon


class Operation:
    def __init__(self):
        self.cancelled = threading.Event()

    def cancel(self):
        self.cancelled.set()

    def check(self):
        if self.cancelled.is_set():
            raise RuntimeError("cancelled")


@dataclass
class Request:
    mode: str = "default"
    targets: tuple = ()
    phone: bool = False
    ios_input: str = "backup"
    quick: bool = False
    preview: bool = False
    extended_windows: bool = False
    include_feeds: bool = False
    iocs: tuple = ()
    priority: str = "above-normal"
    max_cpu_percent: int = 70
    max_memory_mib: int = 512


class Config:
    github_tools_enabled = True
    github_tools_auto_prepare = True
    github_tools_allow_download = True
    saved_on = []

    def save(self):
        self.saved_on.append(threading.get_ident())


class Service:
    instances = []

    def __init__(self, *, cfg=None):
        self.cfg = cfg
        self.calls = []
        self.release = None
        self.operation = None
        self.requests = []
        self.fail = False
        self.instances.append(self)

    def status(self):
        self.calls.append(("status", threading.get_ident()))
        return dict(installed=True, verified=True, state="ready", message="Pinned fixture ready", version="0.1.10")

    def prepare(self, operation, *, progress, allow_download):
        self.calls.append(("prepare", threading.get_ident()))
        self.operation = operation
        progress("Synthetic preparation")
        if self.release is not None:
            while not self.release.wait(.01):
                operation.check()
        operation.check()
        if self.fail:
            raise ValueError("<b>external text</b>")
        return self.status()

    def scan(self, request, operation, *, progress):
        self.calls.append(("scan", threading.get_ident()))
        self.requests.append(request)
        return dict(state="incomplete", message="<b>Literal external message</b>",
                    coverage={"not_checked": ["fixture gap"]}, findings=[])

    def self_test(self, operation, *, progress):
        return dict(state="self_test", message="Synthetic adapter check")

    def revert(self, operation, *, progress):
        return dict(state="disabled", installed=False, verified=False)

    def open_tool(self, operation, *, progress):
        return dict(state="opened", message="Synthetic interactive owner")

    def resource_snapshot(self):
        return dict(cpu_percent=12.5, memory_mib=48, io_bytes=1024, admin={"verified": True, "elevated": False})

    def cancel_all(self):
        if self.operation:
            self.operation.cancel()


def wait_until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.01)
    assert predicate()


@pytest.fixture
def controller(monkeypatch):
    Service.instances.clear()
    Config.saved_on.clear()
    backend = SimpleNamespace(ToolOperation=Operation, ToolScanRequest=Request,
                              CuratedToolService=Service, credits=lambda: [])
    monkeypatch.setattr(ui, "_backend", lambda: backend)
    manager = SimpleNamespace(cfg=Config(), modules={})
    result = ui.get_curated_tools_controller(manager)
    yield result
    result.shutdown()
    assert result.wait_for_shutdown(4)
    result.deleteLater()


def ready(controller):
    assert controller.refresh()
    wait_until(lambda: not controller.snapshot()["busy"])
    return Service.instances[-1]


def test_two_views_share_single_worker_and_closing_one_does_not_cancel(controller):
    first = ui.CuratedScannerWidget(controller.manager)
    second = ui.CuratedScannerWidget(controller.manager)
    try:
        assert first.controller is second.controller is controller
        service = ready(controller)
        service.release = threading.Event()
        assert controller.prepare()
        wait_until(lambda: service.operation is not None)
        assert not second.controller.prepare()
        first.close()
        assert not service.operation.cancelled.is_set()
        ticks = []
        QTimer.singleShot(0, lambda: ticks.append(True))
        QApplication.instance().processEvents()
        assert ticks
        service.release.set()
        wait_until(lambda: not controller.snapshot()["busy"])
        assert len([item for item in service.calls if item[0] == "prepare"]) == 1
        assert all(thread != threading.get_ident() for _name, thread in service.calls)
    finally:
        if Service.instances and Service.instances[-1].release:
            Service.instances[-1].release.set()
        first.close()
        second.close()


def test_shutdown_cancels_owned_operation_and_discards_late_publication(controller):
    service = ready(controller)
    service.release = threading.Event()
    assert controller.prepare()
    wait_until(lambda: service.operation is not None)
    controller.shutdown()
    assert service.operation.cancelled.is_set()
    assert controller.wait_for_shutdown(3)
    before = controller.snapshot()
    controller._drain()
    assert controller.snapshot() == before


def test_failed_verification_discards_previous_verified_claim_and_stays_literal(controller):
    widget = ui.CuratedScannerWidget(controller.manager)
    try:
        service = ready(controller)
        assert widget.run_button.isEnabled()
        service.fail = True
        controller.prepare()
        wait_until(lambda: not controller.snapshot()["busy"])
        assert not widget.run_button.isEnabled()
        assert controller.snapshot()["verified"] is False
        assert "<b>external text</b>" in widget.status.text()
        assert widget.status.textFormat() == ui.Qt.TextFormat.PlainText
    finally:
        widget.close()


def test_selected_evidence_stays_typed_and_no_password_control_exists(controller):
    widget = ui.CuratedScannerWidget(controller.manager)
    try:
        service = ready(controller)
        widget.mode.setCurrentIndex(widget.mode.findData("targeted"))
        widget._scan()
        assert not service.requests
        assert "Choose the local evidence" in widget.status.text()
        widget.targets.setPlainText("C:/Evidence copy/folder\nD:/local/export.json")
        widget.iocs.setText("C:/Evidence copy/indicators.json")
        widget._scan()
        wait_until(lambda: not controller.snapshot()["busy"])
        request = service.requests[-1]
        assert request.mode == "targeted"
        assert request.targets == ("C:/Evidence copy/folder", "D:/local/export.json")
        assert request.iocs == ("C:/Evidence copy/indicators.json",)
        assert request.include_feeds is False
        assert "fixture gap" in widget.results.toPlainText()
        assert "<b>Literal external message</b>" in widget.status.text()
    finally:
        widget.close()


def test_settings_save_runs_off_qt_and_revert_disables_future_auto_prepare(controller):
    ready(controller)
    assert controller.save_options({"github_tools_allow_download": False, "github_tools_timeout_seconds": 45})
    wait_until(lambda: not controller.snapshot()["busy"])
    assert controller.manager.cfg.github_tools_allow_download is False
    assert controller.manager.cfg.github_tools_timeout_seconds == 45
    assert Config.saved_on and all(value != threading.get_ident() for value in Config.saved_on)
    assert controller.revert()
    wait_until(lambda: not controller.snapshot()["busy"])
    assert controller.manager.cfg.github_tools_enabled is False
    assert controller.manager.cfg.github_tools_auto_prepare is False
    assert not controller.auto_prepare()


def test_only_the_requesting_view_opens_credits(controller, monkeypatch):
    monkeypatch.setattr(controller, "_credits", lambda _backend: [dict(name="Zero-Breach Toolkit", url=ui._PROJECT,
                                                                      license="Apache-2.0", notice="Provider credits")])
    first = ui.CuratedScannerWidget(controller.manager)
    second = ui.CuratedScannerWidget(controller.manager)
    try:
        ready(controller)
        first.show()
        second.show()
        first._request_credits()
        wait_until(lambda: first._credits_dialog is not None)
        assert second._credits_dialog is None
        assert first._credits_dialog.findChild(ui.QPlainTextEdit).toPlainText().find("Provider credits") >= 0
    finally:
        if first._credits_dialog:
            first._credits_dialog.close()
        first.close()
        second.close()


def test_github_icon_remains_available_as_compact_header_button():
    button = HeaderActionButton("GITHUB TOOLS", "github", "GitHub Tools", "Maintained scanners and source review")
    try:
        button.set_compact(True)
        assert button.text() == ""
        assert button.accessibleName() == "GitHub Tools"
        assert not button.icon().isNull()
        assert navigation_icon("github").pixmap(22, 22).toImage() != navigation_icon("world").pixmap(22, 22).toImage()
    finally:
        button.close()


class NativeScanner:
    def __init__(self):
        self.state = dict(request_id="", state="idle")
        self.finished = threading.Event()
        self.queued_on = None
        self.cancelled = []
        self.admit = True

    def request_priority_scan(self, request_id):
        self.queued_on = threading.get_ident()
        if not self.admit:
            return False
        self.state = dict(request_id=request_id, state="running", coverage={"fixture": "running"})
        return True

    def priority_scan_snapshot(self):
        if self.finished.is_set():
            self.state = dict(self.state, state="completed")
        return dict(self.state)

    def cancel_priority_scan(self, request_id):
        self.cancelled.append(request_id)
        if self.state["request_id"] == request_id:
            self.state = dict(self.state, state="cancelled")


class Focus:
    def __init__(self):
        self.active = False
        self.renewed = 0
        self.finished = threading.Event()

    def __enter__(self):
        self.active = True
        return self

    def __exit__(self, *_args):
        self.active = False
        self.finished.set()

    def renew(self):
        self.renewed += 1
        return True


def test_priority_chain_holds_focus_until_native_and_tool_complete_and_exposes_copied_usage(controller):
    native, focus = NativeScanner(), Focus()
    controller.manager.modules["SpywareGuard"] = native
    controller.manager.priority_scan_focus = lambda **_kwargs: focus
    service = ready(controller)
    assert controller.priority_scan(native_enabled=True, zero_breach_enabled=True)
    wait_until(lambda: bool(service.requests))
    assert focus.active
    assert native.queued_on != threading.get_ident()
    controller._focus_renewed_at = time.monotonic() - 11
    controller._drain()
    assert focus.renewed == 1
    assert controller.snapshot()["resource_usage"]["cpu_percent"] == 12.5
    assert controller.snapshot()["resource_usage"]["native"]["state"] == "running"
    native.finished.set()
    wait_until(lambda: not controller.snapshot()["busy"])
    assert focus.finished.is_set() and not focus.active
    assert controller.snapshot()["coverage"]["native"]["state"] == "completed"
    assert not native.cancelled


def test_priority_cancel_restores_focus_and_cancels_only_its_native_request(controller):
    native, focus = NativeScanner(), Focus()
    controller.manager.modules["SpywareGuard"] = native
    controller.manager.priority_scan_focus = lambda **_kwargs: focus
    ready(controller)
    assert controller.priority_scan(native_enabled=True, zero_breach_enabled=False)
    wait_until(lambda: native.state["state"] == "running")
    request_id = native.state["request_id"]
    controller.cancel()
    wait_until(lambda: not controller.snapshot()["busy"])
    assert focus.finished.is_set() and not focus.active
    assert native.cancelled and set(native.cancelled) == {request_id}
    assert controller.snapshot()["state"] == "cancelled"


def test_native_admission_gap_does_not_prevent_selected_tool_checks(controller):
    native, focus = NativeScanner(), Focus()
    native.admit = False
    controller.manager.modules["SpywareGuard"] = native
    controller.manager.priority_scan_focus = lambda **_kwargs: focus
    service = ready(controller)
    controller.priority_scan(native_enabled=True, zero_breach_enabled=True)
    wait_until(lambda: not controller.snapshot()["busy"])
    assert service.requests
    assert controller.snapshot()["coverage"]["native"]["state"] == "held"
    assert controller.snapshot()["state"] == "incomplete"
    assert not focus.active


def test_priority_request_preempts_optional_work_only_after_its_worker_retires(controller):
    service = ready(controller)
    old_active, release_old = threading.Event(), threading.Event()
    native, focus = NativeScanner(), Focus()
    native.finished.set()
    controller.manager.modules["SpywareGuard"] = native
    controller.manager.priority_scan_focus = lambda **_kwargs: focus

    def retained_prepare(operation, *, progress, allow_download):
        service.operation = operation
        old_active.set()
        assert release_old.wait(3)
        old_active.clear()
        operation.check()
        return service.status()

    service.prepare = retained_prepare
    original_scan = service.scan

    def checked_scan(*args, **kwargs):
        assert not old_active.is_set()
        return original_scan(*args, **kwargs)

    service.scan = checked_scan
    assert controller.prepare()
    wait_until(old_active.is_set)
    assert controller.priority_scan(native_enabled=True, zero_breach_enabled=True)
    assert controller.priority_scan(native_enabled=True, zero_breach_enabled=True)
    assert service.operation.cancelled.is_set()
    QApplication.processEvents()
    assert not service.requests and native.queued_on is None
    release_old.set()
    wait_until(lambda: bool(service.requests))
    wait_until(lambda: not controller.snapshot()["busy"])
    assert len(service.requests) == 1
    assert controller._pending_priority is None
    assert not focus.active


def test_source_execution_hold_does_not_fake_tool_readiness_or_block_native_scan(controller):
    native, focus = NativeScanner(), Focus()
    native.finished.set()
    controller.manager.modules["SpywareGuard"] = native
    controller.manager.priority_scan_focus = lambda **_kwargs: focus
    service = ready(controller)
    service.status = lambda: dict(installed=True, verified=True, state="held", execution_available=False,
                                  execution_hold_reason="An ordinary-user toolkit runtime is required.",
                                  admin_state={"verified": True, "elevated": True})
    widget = ui.CuratedScannerWidget(controller.manager)
    try:
        controller.refresh()
        wait_until(lambda: not controller.snapshot()["busy"])
        assert not widget.run_button.isEnabled()
        assert widget.advanced_button.isEnabled()  # Read-only options/download links stay available.
        controller.priority_scan(native_enabled=True, zero_breach_enabled=True)
        wait_until(lambda: not controller.snapshot()["busy"])
        assert native.queued_on is not None
        assert not service.requests
        assert "ordinary-user" in str(controller.snapshot()["coverage"]["zero_breach"])
        assert controller.snapshot()["state"] == "incomplete"
    finally:
        widget.close()


def test_external_report_actions_offer_review_without_inventing_response_authority(controller):
    widget = ui.CuratedScannerWidget(controller.manager)
    try:
        widget._investigate()
        dialog = widget._after_action_dialog
        assert dialog.actions["investigate"].isEnabled()
        assert dialog.actions["trace"].isEnabled()
        for action in ("isolate", "patch", "kill", "lift_lockdown"):
            assert not dialog.actions[action].isEnabled()
            assert "validated target" in dialog.actions[action].toolTip()
        assert dialog.actions["lift_lockdown"].text() == "Lift Lockdown"
        dialog.actions["trace"].click()
        assert "does not contact a remote target" in dialog.text.toPlainText()
    finally:
        if widget._after_action_dialog:
            widget._after_action_dialog.close()
        widget.close()


@pytest.mark.parametrize("url", ["file:///C:/private.txt", "http://github.com/example/tool", "https://github.com:bad/path",
                                 "https://user:pass@github.com/tool/repo", "https://raw.githubusercontent.com.attacker.invalid/tool",
                                 "https://malpedia.caad.fkie.fraunhofer.de@attacker.invalid/tool"])
def test_credits_links_reject_active_local_or_credential_urls(url, monkeypatch):
    opened = []
    monkeypatch.setattr(ui.QDesktopServices, "openUrl", lambda value: opened.append(value))
    ui._open_link(url)
    assert not opened


def test_all_maintained_credit_links_open_without_network_or_host_dispatch(monkeypatch):
    from angerona.core.curated_tools import credits
    opened = []
    monkeypatch.setattr(ui.QDesktopServices, "openUrl", lambda url: opened.append(url.toString()) or True)
    urls = {row[key] for row in credits() for key in ("url", "license_url", "source_url", "notice_url")
            if type(row.get(key)) is str}
    assert any("raw.githubusercontent.com/" in url for url in urls)
    assert any("malpedia.caad.fkie.fraunhofer.de/" in url for url in urls)
    for url in sorted(urls):
        ui._open_link(url)
    assert opened == sorted(urls)
