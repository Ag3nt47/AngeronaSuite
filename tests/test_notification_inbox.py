"""Exercise the modeless inbox with inert prompt actions."""

from __future__ import annotations

from dataclasses import replace
from types import MethodType, SimpleNamespace
from unittest.mock import Mock

import pytest
from PySide6.QtCore import QEvent, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication, QDialog, QLabel, QLineEdit, QListWidget, QPlainTextEdit, QPushButton, QWidget,
)

from angerona.core.usb_policy import USB_PIN_SECRET, UsbApprovalPolicy, UsbApprovalView
from angerona.gui.main_window import MainWindow
from angerona.gui.notification_inbox import NotificationInbox
from angerona.gui.usb_approval_dialog import UsbApprovalDialog


@pytest.fixture
def workspace():
    app = QApplication.instance() or QApplication([])
    owner = QWidget()
    inbox = NotificationInbox(owner)
    try:
        yield owner, inbox
    finally:
        inbox.shutdown()
        owner.deleteLater()
        app.sendPostedEvents(owner, QEvent.DeferredDelete)


def button(dialog, text):
    return next(widget for widget in dialog.findChildren(QPushButton) if widget.text() == text)


def bind_main_window_methods(owner, *names):
    for name in names:
        setattr(owner, name, MethodType(getattr(MainWindow, name), owner))


def test_removable_result_review_uses_retained_plain_text_and_clears_stale_rows(workspace):
    from angerona.core.security_scan_center import ScanFinding
    from angerona.modules.usb_monitor import UsbMediaScanResult

    owner, inbox = workspace
    finding = ScanFinding("test.literal", "medium", "Metadata", "Synthetic item", ("<b>literal evidence</b>",))
    result = UsbMediaScanResult("approval-a", "Z:\\", "limited", "Bounded sample reviewed.", 3, 1, (finding,))
    retained = [(result,)]
    module = SimpleNamespace(pending_approvals=lambda: (), recent_media_scan_results=lambda: retained[0])
    owner.manager = SimpleNamespace(modules={"Removable-Media / USB Monitor": module})
    owner._notifications = inbox
    owner._usb_scan_rows = {}
    owner._dismissed_usb_scan_rows = {}
    owner._usb_scan_review = None
    bind_main_window_methods(owner, "_usb_approval_module", "_sync_usb_scan_notices",
                             "_open_usb_scan_review", "_dismiss_usb_scan_notice")

    owner._sync_usb_scan_notices(module)
    key, = inbox._entries
    notice = inbox._entries[key]
    assert owner._usb_scan_review is None and key.endswith(":approval-a")
    notice.review()
    dialog = owner._usb_scan_review
    text = dialog.findChild(QPlainTextEdit, "RemovableScanReview").toPlainText()
    assert dialog.isVisible() and not dialog.isModal()
    assert "<b>literal evidence</b>" in text
    assert "Action taken · none" in text and "Files checked · 3" in text

    notice.dismiss()
    retained[0] = (replace(result),)
    owner._sync_usb_scan_notices(module)
    assert inbox.count == 0
    retained[0] = (replace(result, approval_id="approval-b"),)
    owner._sync_usb_scan_notices(module)
    assert not dialog.isVisible() and inbox.count == 1
    notice.review()
    assert not dialog.isVisible()
    retained[0] = ()
    owner._sync_usb_scan_notices(module)
    assert inbox.count == 0


def test_automatic_scan_notice_routes_only_the_exact_retained_terminal_attempt(workspace):
    owner, inbox = workspace
    current = [4]
    opened = []
    controller = SimpleNamespace(
        retained_scan_attempt=lambda: current[0],
        open_retained_scan_report=lambda *, expected_attempt: opened.append(expected_attempt),
    )
    owner.manager = SimpleNamespace(_curated_tools_controller=controller)
    owner._notifications = inbox
    owner._termination_started = False
    owner._automatic_scan_notice = None
    owner._dismissed_automatic_scan_notice = None
    owner._AUTOMATIC_SCAN_NOTICE = MainWindow._AUTOMATIC_SCAN_NOTICE
    bind_main_window_methods(owner, "_queue_automatic_scan_notice", "_sync_automatic_scan_notice")
    report = dict(automatic=True, lifecycle="terminal", review_attempt=4, state="incomplete", coverage_incomplete=True)
    for change in (dict(automatic=False), dict(lifecycle="running"), dict(review_attempt=True),
                   dict(review_attempt=3), dict(state="schedule-held")):
        owner._queue_automatic_scan_notice(dict(report, **change))
        assert inbox.count == 0

    owner._queue_automatic_scan_notice(report)
    notice = inbox._entries[owner._AUTOMATIC_SCAN_NOTICE]
    assert "Coverage gaps" in notice.description and not opened
    notice.review()
    assert opened == [4]
    notice.dismiss()
    owner._queue_automatic_scan_notice(report)
    assert inbox.count == 0

    current[0] = 5
    owner._queue_automatic_scan_notice(dict(report, review_attempt=5))
    newer = inbox._entries[owner._AUTOMATIC_SCAN_NOTICE]
    notice.dismiss()
    assert inbox.count == 1
    current[0] = 6
    newer.review()
    assert opened == [4] and inbox.count == 0


def test_upsert_deduplicates_without_opening_or_repainting_the_selected_prompt(workspace):
    owner, inbox = workspace
    counts = []
    opened = []
    inbox.count_changed.connect(counts.append)
    key = "usb:one-request"
    inbox.upsert(key, "Removable media", "<b>Pending PIN</b>", lambda: opened.append("original"))
    inbox.upsert(key, "Removable media", "<b>Pending PIN</b>", lambda: opened.append("latest"))
    assert counts == [1]
    assert owner.findChildren(QDialog) == []
    assert opened == []

    dialog = inbox.show()
    listing = dialog.findChild(QListWidget)
    details = dialog.findChild(QPlainTextEdit)
    selected = listing.currentItem()
    assert listing.count() == 1
    assert details.toPlainText() == "<b>Pending PIN</b>"
    edits = []
    details.textChanged.connect(lambda: edits.append(details.toPlainText()))

    inbox.upsert(key, "Removable media", "<b>Pending PIN</b>", lambda: opened.append("updated"))
    inbox.upsert("setup", "Setup", "Finish setup", lambda: opened.append("setup"))
    assert counts == [1, 2]
    assert listing.currentItem() is selected
    assert edits == []
    assert listing.count() == 2
    summary = next(label for label in dialog.findChildren(QLabel)
                   if label.accessibleName() == "Notification count")
    assert summary.text() == "2 pending notifications"

    button(dialog, "Review").click()
    assert opened == ["updated"]
    assert inbox.count == 2
    inbox.remove("setup")
    inbox.remove("setup")
    assert counts == [1, 2, 1]
    assert listing.currentItem() is selected
    assert edits == []


def test_close_reuses_the_window_and_only_explicit_dismiss_is_offered(workspace):
    owner, inbox = workspace
    reviewed = []
    dismissed = []
    inbox.upsert("usb", "Removable media", "Review this pending device.",
                 lambda: reviewed.append("usb"))

    def dismiss_setup():
        dismissed.append("setup")
        inbox.remove("setup")

    inbox.upsert("setup", "Setup", "Review setup.", lambda: reviewed.append("setup"),
                 review_label="Open setup", dismiss=dismiss_setup)
    dialog = inbox.show()
    assert not dialog.isModal()
    assert dialog.windowFlags() & Qt.WindowMinimizeButtonHint
    assert dialog.windowFlags() & Qt.WindowMaximizeButtonHint
    assert button(dialog, "Dismiss").isHidden()

    listing = dialog.findChild(QListWidget)
    listing.setCurrentRow(1)
    selected = listing.currentItem()
    assert not button(dialog, "Dismiss").isHidden()
    button(dialog, "Close").click()
    assert dismissed == reviewed == []
    assert inbox.count == 2
    assert not dialog.isVisible()
    assert inbox.show() is dialog
    assert listing.currentItem() is selected
    assert owner.findChildren(QDialog) == [dialog]

    button(dialog, "Open setup").click()
    assert reviewed == ["setup"]
    assert inbox.count == 2
    button(dialog, "Dismiss").click()
    assert dismissed == ["setup"]
    assert inbox.count == listing.count() == 1
    listing.setCurrentRow(0)
    assert button(dialog, "Dismiss").isHidden()


def test_removing_last_prompt_disables_review_and_shutdown_blocks_reopening(workspace):
    _owner, inbox = workspace
    called = []
    inbox.upsert("storage", "Storage", "Review storage options.", lambda: called.append(True))
    dialog = inbox.show()
    inbox.remove("storage")
    assert dialog.findChild(QPlainTextEdit).toPlainText() == ""
    assert dialog.findChild(QListWidget).count() == 0
    assert not button(dialog, "Review").isEnabled()
    assert button(dialog, "Dismiss").isHidden()
    assert called == []

    inbox.shutdown()
    inbox.upsert("late", "Late delivery", "Shutdown has started.", lambda: called.append(True))
    assert inbox.show() is None
    assert inbox.count == 0

def test_click_opens_the_exact_prompt_while_hover_only_previews(workspace):
    _owner, inbox = workspace
    reviewed = []
    inbox.upsert("first", "Storage", "Review storage", lambda: reviewed.append("first"))
    description = "Review this device <b>literally</b>.\n" + "A" * 640 + " trailing text"
    inbox.upsert("second", "Removable media", description, lambda: reviewed.append("second"))
    dialog = inbox.show()
    listing = dialog.findChild(QListWidget)
    QApplication.processEvents()
    second = listing.item(1)
    target = listing.visualItemRect(second).center()
    assert "Review this device &lt;b&gt;literally&lt;/b&gt;.<br>" in second.toolTip()
    assert "Click to review this notification." in second.toolTip()
    assert "trailing text" not in second.toolTip() and "…" in second.toolTip()
    QTest.mouseMove(listing.viewport(), target)
    QApplication.processEvents()
    assert reviewed == []
    QTest.mouseClick(listing.viewport(), Qt.LeftButton, pos=target)
    assert reviewed == ["second"]
    assert inbox.count == 2


def test_removable_rows_open_their_own_live_controls_and_keep_other_requests_pending(workspace):
    owner, inbox = workspace
    first = UsbApprovalView("first-device", "Y:\\", 1, False, "pending", 1, 0, True)
    second = replace(first, approval_id="second-device", mountpoint="Z:\\", detected_at=2)
    pending = {view.approval_id: view for view in (first, second)}
    approved = []

    def cancel(approval_id):
        pending.pop(approval_id, None)

    module = SimpleNamespace(
        pending_approvals=lambda: tuple(pending.values()),
        _approval_policy=SimpleNamespace(pin_configured=lambda: True, cancel=cancel),
        approve_media=lambda *args: approved.append(args),
        deny_media=lambda _approval_id: None,
    )
    owner.manager = SimpleNamespace(modules={"Removable-Media / USB Monitor": module})
    owner._notifications = inbox
    owner._usb_notification_keys = set()
    owner._usb_approval_dialogs = {}
    bind_main_window_methods(owner, "_usb_approval_module", "_handle_usb_approval_events", "_open_usb_approval")
    owner._handle_usb_approval_events(())
    dialog = inbox.show()
    listing = dialog.findChild(QListWidget)
    QApplication.processEvents()

    def click_row(index):
        point = listing.visualItemRect(listing.item(index)).center()
        QTest.mouseClick(listing.viewport(), Qt.LeftButton, pos=point)

    try:
        click_row(0)
        first_dialog = owner._usb_approval_dialogs[first.approval_id]
        click_row(1)
        second_dialog = owner._usb_approval_dialogs[second.approval_id]
        assert first_dialog is not second_dialog
        for prompt, view in ((first_dialog, first), (second_dialog, second)):
            assert isinstance(prompt, UsbApprovalDialog)
            assert prompt.isVisible() and not prompt.isModal()
            assert prompt.approval_id == view.approval_id
            assert any(label.text() == f"Mounted at: {view.mountpoint}" for label in prompt.findChildren(QLabel))
            assert prompt.findChild(QLineEdit).echoMode() == QLineEdit.Password
            assert button(prompt, "Approve Angerona scan").isVisible()
            assert button(prompt, "Keep blocked").isVisible()

        click_row(1)
        assert owner._usb_approval_dialogs == {first.approval_id: first_dialog, second.approval_id: second_dialog}
        button(dialog, "Close").click()
        assert inbox.show() is dialog and inbox.count == 2
        assert tuple(pending.values()) == (first, second)
        assert approved == []

        button(second_dialog, "Keep blocked").click()
        assert tuple(pending.values()) == (first,)
        assert owner._usb_approval_dialogs == {first.approval_id: first_dialog}
        assert inbox.count == 1
        assert approved == []
    finally:
        for prompt in tuple(owner._usb_approval_dialogs.values()):
            prompt.close()
        QApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_stale_usb_enrollment_uses_the_existing_pin_without_rewriting(workspace):
    owner, _inbox = workspace
    stored = {"pin": None}
    writer = Mock(side_effect=lambda pin: stored.update(pin=pin))
    policy = UsbApprovalPolicy(pin_loader=lambda: stored["pin"], pin_writer=writer)
    module = SimpleNamespace(_approval_policy=policy, deny_media=lambda _approval_id: None)
    first = UsbApprovalDialog(module, policy.request("Y:\\"), owner)
    second = UsbApprovalDialog(module, policy.request("Z:\\"), owner)
    first.show()
    second.show()

    def wait_for_idle(prompt):
        for _ in range(200):
            if prompt._operation is None:
                return
            QTest.qWait(10)
        pytest.fail("USB dialog worker did not settle")

    try:
        for prompt in (first, second):
            wait_for_idle(prompt)
            assert prompt._enrollment_mode
        for prompt, candidate in ((first, "234567"), (second, "987654")):
            prompt._pin.setText(candidate)
            prompt._confirm_pin.setText(candidate)
            button(prompt, "Create protected PIN").click()
            wait_for_idle(prompt)
            assert not prompt._enrollment_mode
        writer.assert_called_once_with("234567")
        assert "already configured" in second._status.text()
        assert {view.state for view in policy.pending()} == {"pending"}
    finally:
        first.close()
        second.close()
        QApplication.sendPostedEvents(None, QEvent.DeferredDelete)


@pytest.mark.parametrize("existing,reason", [
    ("234567", "pin_already_configured"),
    ("invalid", "stored_pin_invalid"),
    (RuntimeError("read denied"), "protected_store_unavailable"),
])
def test_prompt_enrollment_preserves_existing_or_unreadable_protected_store(monkeypatch, existing, reason):
    def read_only(name, _factory):
        assert name == USB_PIN_SECRET
        if isinstance(existing, Exception):
            raise existing
        return existing

    store = Mock(side_effect=read_only)
    monkeypatch.setattr("angerona.core.secure_store.get_or_create_secret", store)
    result = UsbApprovalPolicy().enroll_pin("987654", "987654")
    assert result.reason == reason and not result.updated
    store.assert_called_once()


def test_initial_enrollment_does_not_clear_a_peer_lockout_or_revive_a_denied_request():
    stored = {"pin": None}

    def writer(pin):
        stored["pin"] = pin
        assert policy.verify(peer.approval_id, "987654").reason == "locked"

    policy = UsbApprovalPolicy(pin_loader=lambda: stored["pin"], pin_writer=writer)
    peer = policy.request("Y:\\")
    denied = policy.request("Z:\\")
    policy.cancel(denied.approval_id)

    assert policy.enroll_pin("234567", "234567").updated
    assert policy.pin_reset_required()
    assert policy.verify(peer.approval_id, "234567").reason == "locked"
    assert policy.verify(denied.approval_id, "234567").reason == "operator_denied"
