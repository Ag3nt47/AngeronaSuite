"""PIN enrollment and fail-closed removable-media approval dialog.

This is a standalone UI surface so the main dashboard can open it when it sees
``event_type=usb_approval_required``. Closing the window leaves the drive
untrusted; only ``USBMonitorModule.approve_media`` can grant Angerona workflow
trust for the current mount.
"""
from __future__ import annotations

import queue
import threading
import time

from PySide6.QtCore import QRegularExpression, QTimer, Qt
from PySide6.QtGui import QRegularExpressionValidator
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from angerona.core.usb_policy import (
    UsbApprovalView,
    configure_usb_pin,
)


# A hung OS credential/device query keeps its permit until it really returns.
# Closing and reopening prompts therefore cannot accumulate background workers.
_USB_UI_WORKERS = threading.BoundedSemaphore(2)
_USB_DENIAL_NOTICES = threading.BoundedSemaphore(1)
_OPERATION_TIMEOUT_S = 15.0


def _revoke_approval(policy, approval_id: str) -> None:
    """Revoke the exact request using only the policy's in-memory state."""
    cancel = getattr(policy, "cancel", None)
    if callable(cancel):
        cancel(approval_id)


class UsbApprovalDialog(QDialog):
    """Small fail-closed PIN prompt for one pending USB approval."""

    def __init__(
        self,
        usb_module,
        approval: UsbApprovalView,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._module = usb_module
        self._approval = approval
        self._resolved = False
        self._closed = False
        self._operation: str | None = None
        self._operation_started = 0.0
        self._cancelled = threading.Event()
        self._results: queue.Queue = queue.Queue(maxsize=1)
        self._policy = getattr(usb_module, "_approval_policy", None)
        self._enrollment_mode = approval.state == "enrollment_required"
        self._lifetime = {"resolved": False}
        self.setWindowTitle("Angerona — removable media approval")
        self.setModal(False)
        # Security prompts must not be masked or queued behind cosmetic reveals.
        self.setProperty("_angerona_no_reveal", True)
        self.setMinimumWidth(520)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

        # Parent destruction can bypass the normal Close/Escape path. This
        # callback deliberately holds no QWidget or bound Qt method.
        cancellation, lifetime = self._cancelled, self._lifetime
        policy, approval_id = self._policy, approval.approval_id

        def destroyed_cleanup(*_args):
            cancellation.set()
            if not lifetime["resolved"] and policy is not None:
                _revoke_approval(policy, approval_id)

        self.destroyed.connect(destroyed_cleanup)

        layout = QVBoxLayout(self)
        self._title = QLabel()
        title = self._title
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        mount = QLabel(f"Mounted at: {approval.mountpoint}")
        mount.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(mount)

        self._explanation = QLabel()
        explanation = self._explanation
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        self._pin = QLineEdit()
        self._pin.setEchoMode(QLineEdit.Password)
        self._pin.setMaxLength(12)
        self._pin.setValidator(
            QRegularExpressionValidator(QRegularExpression(r"[0-9]{0,12}"), self)
        )
        self._pin.returnPressed.connect(self._approve)
        layout.addWidget(self._pin)

        self._confirm_pin = QLineEdit()
        self._confirm_pin.setEchoMode(QLineEdit.Password)
        self._confirm_pin.setMaxLength(12)
        self._confirm_pin.setValidator(
            QRegularExpressionValidator(QRegularExpression(r"[0-9]{0,12}"), self)
        )
        self._confirm_pin.returnPressed.connect(self._approve)
        layout.addWidget(self._confirm_pin)

        self._status = QLabel()
        self._status.setWordWrap(True)
        layout.addWidget(self._status)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self._deny_button = QPushButton("Keep blocked")
        self._deny_button.clicked.connect(self._deny)
        buttons.addWidget(self._deny_button)
        self._approve_button = QPushButton()
        self._approve_button.setObjectName("primaryButton")
        self._approve_button.clicked.connect(self._approve)
        buttons.addWidget(self._approve_button)
        layout.addLayout(buttons)

        self._render_mode()
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(50)
        self._poll_timer.timeout.connect(self._poll_operation)
        if approval.state == "locked":
            self._show_reset_required()
        else:
            self._begin_operation(
                "readiness",
                lambda: bool(policy is not None and policy.pin_configured()),
                "Checking protected PIN storage… You can keep this media blocked.",
            )
        self._pin.setFocus(Qt.PopupFocusReason)

    @property
    def approval_id(self) -> str:
        return self._approval.approval_id

    def _approve(self) -> None:
        if self._closed or self._resolved or self._operation is not None:
            return
        if self._approval.state == "locked":
            self._show_reset_required()
            return
        if self._enrollment_mode:
            self._enroll()
            return
        candidate = self._pin.text()
        self._pin.clear()
        module, approval_id = self._module, self._approval.approval_id
        self._begin_operation(
            "approve", lambda: module.approve_media(approval_id, candidate),
            "Checking this media and its PIN… Keep blocked cancels this approval.",
        )

    def _approval_finished(self, decision) -> None:
        if decision.approved:
            self._resolved = True
            self._lifetime["resolved"] = True
            self._status.setText(
                "✓ Approved for Angerona scanning. AutoRun remains disabled."
            )
            self._approve_button.setEnabled(False)
            self._deny_button.setEnabled(False)
            QTimer.singleShot(600, self.accept)
            return
        if decision.reason == "pin_not_configured":
            self._enrollment_mode = True
            self._render_mode()
        elif decision.reason == "locked":
            self._approval = UsbApprovalView(
                approval_id=self._approval.approval_id,
                mountpoint=self._approval.mountpoint,
                detected_at=self._approval.detected_at,
                autorun_present=self._approval.autorun_present,
                state=decision.state,
                attempts_remaining=decision.attempts_remaining,
                locked_until=decision.locked_until,
                policy_enforced=self._approval.policy_enforced,
            )
            self._show_reset_required()
            # There is deliberately no retry surface. Keep the policy record in
            # its locked state (do not turn close into an ordinary denial).
            self._resolved = True
            self._lifetime["resolved"] = True
            self.reject()
        elif decision.reason == "invalid_pin":
            # Backward-compatible handling for a stale module implementation:
            # fail closed locally rather than presenting another attempt.
            self._status.setText(
                "PIN rejected. This approval is closed; reset the USB PIN in "
                "Settings before trying again."
            )
            self._resolved = True
            self._lifetime["resolved"] = True
            self.reject()
        else:
            self._status.setText("Approval is no longer valid; the drive remains untrusted.")

    def _enroll(self) -> None:
        pin = self._pin.text()
        confirmation = self._confirm_pin.text()
        self._pin.clear()
        self._confirm_pin.clear()
        policy = getattr(self._module, "_approval_policy", None)
        setter = getattr(policy, "configure_pin", None)
        self._begin_operation(
            "enroll",
            lambda: (
                setter(pin, confirmation)
                if callable(setter)
                else configure_usb_pin(pin, confirmation)
            ),
            "Saving the PIN in protected storage… Closing keeps this media "
            "blocked; an already-started PIN save may still finish.",
        )

    def _enrollment_finished(self, result) -> None:
        if not result.updated:
            message = {
                "invalid_format": "Create a PIN containing 4–12 digits.",
                "confirmation_mismatch": "The two PIN entries did not match.",
                "protected_store_unavailable": (
                    "The operating-system protected credential store could not "
                    "save the PIN. The drive remains untrusted."
                ),
            }.get(result.reason, "PIN enrollment failed; the drive remains untrusted.")
            self._status.setText(message)
            return

        # Enrollment/reset never approves attached media. Require a separate
        # proof with the newly created PIN before Angerona reads any content.
        self._approval = UsbApprovalView(
            approval_id=self._approval.approval_id,
            mountpoint=self._approval.mountpoint,
            detected_at=self._approval.detected_at,
            autorun_present=self._approval.autorun_present,
            state="pending",
            attempts_remaining=1,
            locked_until=0.0,
            policy_enforced=self._approval.policy_enforced,
        )
        self._enrollment_mode = False
        self._render_mode()
        self._status.setText(
            "PIN created in protected storage. This media is still untrusted; "
            "enter the new PIN once to approve Angerona's scan."
        )
        self._pin.setFocus(Qt.PopupFocusReason)

    def _deny(self) -> None:
        self._pin.clear()
        self._confirm_pin.clear()
        self.reject()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        """Treat the window close control as an explicit fail-closed denial."""
        self._finish_closed()
        super().closeEvent(event)

    def done(self, result: int) -> None:
        # QDialog Escape calls reject()/done() without a closeEvent.
        self._finish_closed()
        super().done(result)

    def _finish_closed(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._poll_timer.stop()
        self._cancelled.set()
        if not self._resolved:
            self._revoke()

    def _revoke(self) -> None:
        # Do not wait for a blocked store/identity call or event subscriber.
        # verify() checks this exact record under the same in-memory policy lock.
        _revoke_approval(self._policy, self._approval.approval_id)
        notices = _USB_DENIAL_NOTICES
        if not notices.acquire(blocking=False):
            return
        module, approval_id = self._module, self._approval.approval_id

        def notify():
            try:
                module.deny_media(approval_id)
            except Exception:
                pass
            finally:
                notices.release()

        try:
            threading.Thread(target=notify, name="UsbDenialNotice", daemon=True).start()
        except Exception:
            notices.release()

    def _begin_operation(self, operation: str, callback, message: str) -> None:
        if self._closed or self._operation is not None or self._cancelled.is_set():
            return
        if self._policy is None or not callable(getattr(self._policy, "cancel", None)):
            self._approve_button.setEnabled(False)
            self._status.setText("USB approval policy is unavailable; this media stays untrusted.")
            return
        self._set_inputs_enabled(False)
        workers = _USB_UI_WORKERS
        if not workers.acquire(blocking=False):
            self._status.setText(
                "USB checks are still busy. This media stays untrusted; close "
                "the prompt and review the USB module before trying again."
            )
            return
        self._operation = operation
        self._operation_started = time.monotonic()
        self._status.setText(message)
        results, cancelled = self._results, self._cancelled
        policy, approval_id = self._policy, self._approval.approval_id

        def work():
            try:
                if cancelled.is_set():
                    return
                try:
                    result = callback()
                    succeeded = True
                except Exception:
                    result, succeeded = None, False
                if cancelled.is_set():
                    # In particular, a late enrollment resets pending records;
                    # reinstate the operator's denial after its write finishes.
                    _revoke_approval(policy, approval_id)
                    return
                results.put_nowait((succeeded, result))
            finally:
                workers.release()

        try:
            threading.Thread(target=work, name=f"UsbApproval-{operation}", daemon=True).start()
        except Exception:
            workers.release()
            self._operation = None
            self._status.setText("USB check could not start; this media stays untrusted.")
            return
        self._poll_timer.start()

    def _poll_operation(self) -> None:
        if self._closed or self._operation is None:
            return
        # A result that arrives after the deadline cannot authorize a late UI
        # success just because the Qt loop was busy when the timer was due.
        if time.monotonic() - self._operation_started >= _OPERATION_TIMEOUT_S:
            operation = self._operation
            self._operation = None
            self._poll_timer.stop()
            self._cancelled.set()
            self._revoke()
            self._status.setText(
                "USB check timed out; this media stays blocked. Close this prompt "
                "and review the USB module."
                + (" An already-started PIN save may still finish." if operation == "enroll" else "")
            )
            return
        try:
            succeeded, result = self._results.get_nowait()
        except queue.Empty:
            return
        operation = self._operation
        self._operation = None
        self._poll_timer.stop()
        if not succeeded:
            self._cancelled.set()
            self._revoke()
            self._status.setText("USB check failed; this media stays blocked. Review the USB module.")
            return
        self._set_inputs_enabled(True)
        if operation == "readiness":
            self._enrollment_mode = self._approval.state == "enrollment_required" or not result
            self._render_mode()
        elif operation == "approve":
            self._approval_finished(result)
        elif operation == "enroll":
            self._enrollment_finished(result)

    def _set_inputs_enabled(self, enabled: bool) -> None:
        self._pin.setEnabled(enabled)
        self._confirm_pin.setEnabled(enabled)
        self._approve_button.setEnabled(enabled)

    def _render_mode(self) -> None:
        if self._enrollment_mode:
            self._title.setText("🔐  Create a removable-media approval PIN")
            self._explanation.setText(
                "No approval PIN is configured. Create and confirm one before any "
                "Angerona scan can be approved. It is saved only in the operating-"
                "system protected credential store. This user-mode gate does not "
                "block raw operating-system access."
            )
            self._pin.setPlaceholderText("Create 4–12 digit PIN")
            self._confirm_pin.setPlaceholderText("Confirm new PIN")
            self._confirm_pin.show()
            self._approve_button.setText("Create protected PIN")
            self._status.setText(
                "Creating a PIN does not approve this media. Closing is a denial."
            )
        else:
            self._title.setText("🔐  Removable media is waiting for approval")
            self._explanation.setText(
                "AutoRun and AutoPlay remain disabled. Enter the removable-media "
                "PIN to let Angerona inspect this drive. One incorrect PIN locks "
                "USB approval until you explicitly reset it in Settings. This "
                "user-mode gate does not block raw operating-system access."
            )
            self._pin.setPlaceholderText("4–12 digit removable-media PIN")
            self._confirm_pin.hide()
            self._approve_button.setText("Approve Angerona scan")
            self._status.setText(
                "The drive stays untrusted if this window is closed or approval fails."
            )

    def _show_reset_required(self) -> None:
        self._pin.clear()
        self._confirm_pin.clear()
        self._pin.setEnabled(False)
        self._confirm_pin.setEnabled(False)
        self._approve_button.setEnabled(False)
        self._status.setText(
            "USB approval is locked for this session. Use Settings → System → "
            "Removable media to confirm and create a new PIN. Removing or "
            "reinserting the device does not clear this lock."
        )
