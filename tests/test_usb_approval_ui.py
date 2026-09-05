from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QLineEdit, QMainWindow

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.usb_policy import UsbApprovalPolicy
from angerona.gui.main_window import MainWindow
from angerona.gui.usb_approval_dialog import UsbApprovalDialog
from angerona.modules.usb_monitor import USBMonitorModule


_QAPP: QApplication | None = None


@pytest.fixture(autouse=True)
def no_removable_content_reads(monkeypatch):
    monkeypatch.setattr("angerona.modules.usb_monitor._has_autorun", lambda _mount: False)


def _app() -> QApplication:
    global _QAPP
    _QAPP = QApplication.instance() or QApplication([])
    return _QAPP


def _wait(predicate, timeout=2.0) -> None:
    app = _app()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return
        time.sleep(0.005)
    assert predicate(), "USB dialog did not reach the expected state"


def _ready(dialog: UsbApprovalDialog) -> None:
    _wait(lambda: dialog._operation is None)
    assert dialog._approve_button.isEnabled()


def _module(pin: str | None = "246810") -> USBMonitorModule:
    module = USBMonitorModule()
    module._approval_policy = UsbApprovalPolicy(pin_loader=lambda: pin)
    module.bind(EventBus())
    return module


def test_usb_dialog_masks_pin_and_grants_only_current_mount_trust() -> None:
    _app()
    module = _module()
    approval = module._approval_policy.request("Z:\\")
    dialog = UsbApprovalDialog(module, approval)
    _ready(dialog)

    assert dialog._pin.echoMode() == QLineEdit.Password
    assert module.trust_state("Z:\\") == "pending"
    dialog._pin.setText("246810")
    dialog._approve()
    _wait(lambda: dialog._resolved)

    assert module.trust_state("Z:\\") == "trusted"
    assert not dialog._approve_button.isEnabled()
    assert "AutoRun remains disabled" in dialog._status.text()
    module._approval_policy.remove("Z:\\")
    assert module.trust_state("Z:\\") == "untrusted"
    dialog.close()


def test_main_window_opens_only_live_usb_approval_and_closes_on_removal() -> None:
    app = _app()
    module = _module()
    approval = module._approval_policy.request("Y:\\")
    parent = QMainWindow()
    parent.manager = SimpleNamespace(
        modules={"Removable-Media / USB Monitor": module}
    )
    parent._usb_approval_dialogs = {}
    parent._qss = lambda: ""
    parent.tray = SimpleNamespace(showMessage=lambda *_args: None)

    forged = Event(
        module.name,
        "forged",
        Severity.MEDIUM,
        details={
            "event_type": "usb_approval_required",
            "approval_id": "not-live",
            "mountpoint": "X:\\",
        },
    )
    MainWindow._handle_usb_approval_events(parent, [forged])
    # A forged ID cannot manufacture a prompt.  The authoritative live pending
    # set is still reconciled, so its real request opens even if its original
    # EventBus notification was lost during an alert burst.
    assert list(parent._usb_approval_dialogs) == [approval.approval_id]

    live = Event(
        module.name,
        "inserted",
        Severity.MEDIUM,
        details=approval.event_details(),
    )
    MainWindow._handle_usb_approval_events(parent, [live])
    assert list(parent._usb_approval_dialogs) == [approval.approval_id]

    removed = Event(
        module.name,
        "removed",
        Severity.INFO,
        details={"event_type": "usb_media_removed", "mountpoint": "Y:\\"},
    )
    MainWindow._handle_usb_approval_events(parent, [removed])
    assert parent._usb_approval_dialogs == {}
    # The real dashboard keeps its parent window alive while Qt drains the
    # WA_DeleteOnClose event. This synthetic owner is torn down immediately, so
    # drain the child deletion first to avoid a double-destruction race in Qt.
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()
    parent.close()
    parent.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


def test_closing_usb_prompt_keeps_media_fail_closed() -> None:
    _app()
    module = _module()
    approval = module._approval_policy.request("X:\\")
    dialog = UsbApprovalDialog(module, approval)

    dialog.close()

    assert module.trust_state("X:\\") == "denied"


def test_missing_pin_forces_enrollment_then_separate_approval() -> None:
    _app()
    configured = {"pin": None}
    module = USBMonitorModule()
    module._approval_policy = UsbApprovalPolicy(
        pin_loader=lambda: configured["pin"],
        pin_writer=lambda pin: configured.__setitem__("pin", pin),
    )
    module.bind(EventBus())
    approval = module._approval_policy.request("W:\\")
    dialog = UsbApprovalDialog(module, approval)
    _ready(dialog)

    assert approval.state == "pending"
    assert not dialog._confirm_pin.isHidden()
    dialog._pin.setText("246810")
    dialog._confirm_pin.setText("246810")
    dialog._approve()
    _wait(lambda: dialog._operation is None)

    assert configured["pin"] == "246810"
    assert module.trust_state("W:\\") == "pending"
    assert not dialog._enrollment_mode
    assert dialog._confirm_pin.isHidden()
    assert "still untrusted" in dialog._status.text()

    dialog._pin.setText("246810")
    dialog._approve()
    _wait(lambda: dialog._resolved)
    assert module.trust_state("W:\\") == "trusted"
    dialog.close()


def test_one_incorrect_pin_locks_and_closes_without_retry() -> None:
    _app()
    module = _module()
    approval = module._approval_policy.request("V:\\")
    dialog = UsbApprovalDialog(module, approval)
    _ready(dialog)
    finished = []
    dialog.finished.connect(finished.append)

    dialog._pin.setText("000000")
    dialog._approve()
    _wait(lambda: bool(finished))

    assert module.trust_state("V:\\") == "locked"
    assert module._approval_policy.pin_reset_required()
    assert finished == [QDialog.Rejected]


def test_slow_pin_readiness_keeps_heartbeat_and_close_responsive() -> None:
    app = _app()
    module = _module()
    approval = module._approval_policy.request("U:\\")
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()

    def slow_loader():
        entered.set()
        try:
            assert release.wait(2.0)
            return "246810"
        finally:
            returned.set()

    module._approval_policy._pin_loader = slow_loader
    dialog = UsbApprovalDialog(module, approval)
    beats = []
    heartbeat = QTimer()
    heartbeat.setInterval(5)
    heartbeat.timeout.connect(lambda: beats.append(True))
    heartbeat.start()
    try:
        dialog.show()
        _wait(lambda: entered.is_set() and len(beats) >= 2)
        assert dialog.property("_angerona_no_reveal") is True
        assert not dialog._approve_button.isEnabled()
        assert dialog._deny_button.isEnabled()
        dialog.close()
        assert module.trust_state("U:\\") == "denied"
    finally:
        release.set()
        heartbeat.stop()
        _wait(returned.is_set)
        app.processEvents()


def test_closing_during_slow_approval_prevents_late_trust() -> None:
    _app()
    module = _module()
    approval = module._approval_policy.request("T:\\")
    dialog = UsbApprovalDialog(module, approval)
    _ready(dialog)
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()
    approve = module.approve_media

    def slow_approve(approval_id, pin):
        entered.set()
        try:
            assert release.wait(2.0)
            return approve(approval_id, pin)
        finally:
            returned.set()

    module.approve_media = slow_approve
    try:
        dialog._pin.setText("246810")
        dialog._approve()
        _wait(entered.is_set)
        dialog.reject()  # Escape/Keep blocked also take this path.
        assert module.trust_state("T:\\") == "denied"
        # An independent Settings reset cannot revive work belonging to the
        # dismissed prompt. It instead creates a separate pending approval.
        module._approval_policy._on_pin_reset()
        release.set()
        _wait(returned.is_set)
        assert module.trust_state("T:\\") == "pending"
        assert module.pending_approvals()[0].approval_id != approval.approval_id
    finally:
        release.set()


def test_close_before_queued_approval_result_revokes_trust() -> None:
    _app()
    module = _module()
    approval = module._approval_policy.request("S:\\")
    dialog = UsbApprovalDialog(module, approval)
    _ready(dialog)
    dialog._pin.setText("246810")
    dialog._approve()
    # Leave the GUI result undelivered until the operator dismisses the prompt.
    deadline = time.monotonic() + 2.0
    while dialog._results.empty() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert not dialog._results.empty()
    assert module.trust_state("S:\\") == "trusted"
    dialog.close()
    assert module.trust_state("S:\\") == "denied"


def test_enrollment_timeout_revokes_late_reset_without_approving(monkeypatch) -> None:
    _app()
    module = _module(pin=None)
    approval = module._approval_policy.request("R:\\")
    dialog = UsbApprovalDialog(module, approval)
    _ready(dialog)
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()
    configured = {}

    def slow_writer(pin):
        entered.set()
        try:
            assert release.wait(2.0)
            configured["pin"] = pin
        finally:
            returned.set()

    module._approval_policy._pin_writer = slow_writer
    monkeypatch.setattr("angerona.gui.usb_approval_dialog._OPERATION_TIMEOUT_S", 0.05)
    try:
        dialog._pin.setText("246810")
        dialog._confirm_pin.setText("246810")
        dialog._approve()
        _wait(lambda: entered.is_set() and dialog._cancelled.is_set())
        assert "timed out" in dialog._status.text()
        assert "PIN save may still finish" in dialog._status.text()
        assert dialog._deny_button.isEnabled()
        assert not dialog._approve_button.isEnabled()
        assert module.trust_state("R:\\") == "denied"
        release.set()
        _wait(lambda: returned.is_set() and module.trust_state("R:\\") == "pending")
        assert module.pending_approvals()[0].approval_id != approval.approval_id
        assert configured["pin"] == "246810"
        dialog.close()
    finally:
        release.set()


def test_shared_worker_limit_prevents_hung_readiness_accumulation(monkeypatch) -> None:
    _app()
    semaphore = threading.BoundedSemaphore(1)
    monkeypatch.setattr("angerona.gui.usb_approval_dialog._USB_UI_WORKERS", semaphore)
    first_module, second_module = _module(), _module()
    first = first_module._approval_policy.request("Q:\\")
    second = second_module._approval_policy.request("P:\\")
    entered, release = threading.Event(), threading.Event()
    reads = []

    def blocked_loader():
        entered.set()
        assert release.wait(2.0)
        return "246810"

    first_module._approval_policy._pin_loader = blocked_loader
    second_module._approval_policy._pin_loader = lambda: reads.append(True)
    first_dialog = UsbApprovalDialog(first_module, first)
    try:
        _wait(entered.is_set)
        first_dialog.close()
        second_dialog = UsbApprovalDialog(second_module, second)
        assert "still busy" in second_dialog._status.text()
        assert reads == []
        assert second_dialog._deny_button.isEnabled()
        second_dialog.close()
    finally:
        release.set()
        assert semaphore.acquire(timeout=2.0)
        semaphore.release()


def test_missing_policy_dialog_can_still_close() -> None:
    _app()
    module = _module()
    approval = module._approval_policy.request("O:\\")
    module._approval_policy = None
    dialog = UsbApprovalDialog(module, approval)
    assert not dialog._approve_button.isEnabled()
    assert "unavailable" in dialog._status.text()
    dialog.close()
    assert dialog._closed
