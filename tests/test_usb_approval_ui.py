from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QDialog, QLineEdit, QMainWindow

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.usb_policy import UsbApprovalPolicy
from angerona.gui.main_window import MainWindow
from angerona.gui.usb_approval_dialog import UsbApprovalDialog
from angerona.modules.usb_monitor import USBMonitorModule


_QAPP: QApplication | None = None


def _app() -> QApplication:
    global _QAPP
    _QAPP = QApplication.instance() or QApplication([])
    return _QAPP


def _module(pin: str = "246810") -> USBMonitorModule:
    module = USBMonitorModule()
    module._approval_policy = UsbApprovalPolicy(pin_loader=lambda: pin)
    module.bind(EventBus())
    return module


def test_usb_dialog_masks_pin_and_grants_only_current_mount_trust() -> None:
    _app()
    module = _module()
    approval = module._approval_policy.request("Z:\\")
    dialog = UsbApprovalDialog(module, approval)

    assert dialog._pin.echoMode() == QLineEdit.Password
    assert module.trust_state("Z:\\") == "pending"
    dialog._pin.setText("246810")
    dialog._approve()

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

    assert approval.state == "pending"
    assert not dialog._confirm_pin.isHidden()
    dialog._pin.setText("246810")
    dialog._confirm_pin.setText("246810")
    dialog._approve()

    assert configured["pin"] == "246810"
    assert module.trust_state("W:\\") == "pending"
    assert not dialog._enrollment_mode
    assert dialog._confirm_pin.isHidden()
    assert "still untrusted" in dialog._status.text()

    dialog._pin.setText("246810")
    dialog._approve()
    assert module.trust_state("W:\\") == "trusted"
    dialog.close()


def test_one_incorrect_pin_locks_and_closes_without_retry() -> None:
    _app()
    module = _module()
    approval = module._approval_policy.request("V:\\")
    dialog = UsbApprovalDialog(module, approval)

    dialog._pin.setText("000000")
    dialog._approve()

    assert module.trust_state("V:\\") == "locked"
    assert module._approval_policy.pin_reset_required()
    assert dialog.result() == QDialog.Rejected
