"""PIN enrollment and fail-closed removable-media approval dialog.

This is a standalone UI surface so the main dashboard can open it when it sees
``event_type=usb_approval_required``. Closing the window leaves the drive
untrusted; only ``USBMonitorModule.approve_media`` can grant Angerona workflow
trust for the current mount.
"""
from __future__ import annotations

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
        policy = getattr(usb_module, "_approval_policy", None)
        pin_ready = False
        try:
            pin_ready = bool(policy is not None and policy.pin_configured())
        except Exception:
            pin_ready = False
        self._enrollment_mode = (
            approval.state == "enrollment_required" or not pin_ready
        )
        self.setWindowTitle("Angerona — removable media approval")
        self.setModal(False)
        self.setMinimumWidth(520)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

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
        if approval.state == "locked":
            self._show_reset_required()
        self._pin.setFocus(Qt.PopupFocusReason)

    @property
    def approval_id(self) -> str:
        return self._approval.approval_id

    def _approve(self) -> None:
        if self._approval.state == "locked":
            self._show_reset_required()
            return
        if self._enrollment_mode:
            self._enroll()
            return
        candidate = self._pin.text()
        self._pin.clear()
        decision = self._module.approve_media(self._approval.approval_id, candidate)
        if decision.approved:
            self._resolved = True
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
            self.reject()
        elif decision.reason == "invalid_pin":
            # Backward-compatible handling for a stale module implementation:
            # fail closed locally rather than presenting another attempt.
            self._status.setText(
                "PIN rejected. This approval is closed; reset the USB PIN in "
                "Settings before trying again."
            )
            self._resolved = True
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
        result = (
            setter(pin, confirmation)
            if callable(setter)
            else configure_usb_pin(pin, confirmation)
        )
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
        self._module.deny_media(self._approval.approval_id)
        self._resolved = True
        self.reject()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        """Treat the window close control as an explicit fail-closed denial."""
        if not self._resolved:
            try:
                self._module.deny_media(self._approval.approval_id)
            except Exception:
                pass
            self._resolved = True
        super().closeEvent(event)

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
