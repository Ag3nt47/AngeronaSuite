"""Modeless operator STOP controls and exact preparation-thread ownership.

The session lock prevents accidental use of dashboard/tray controls. It is not
an operating-system security boundary and grants no shutdown authority.
"""
from __future__ import annotations

import threading

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout,
)


class StopPreparation:
    """Retain one exact authorization worker until its thread actually exits."""

    def __init__(self, prepare, *, name="OperatorStopPreparation"):
        self._prepare = prepare
        self.succeeded = False
        self.error_name = ""
        self.authorization_held = False
        self.thread = threading.Thread(
            target=self._run, name=name, daemon=True)

    def _run(self):
        try:
            self._prepare()
        except BaseException as error:
            # A callback raising SystemExit is not an accepted STOP. Preserve a
            # bounded type, not an exception/traceback containing private state.
            self.error_name = type(error).__name__
            self.authorization_held = self.error_name == "AdminApprovalRequired"
        else:
            self.succeeded = True

    def start(self):
        try:
            self.thread.start()
        except Exception as error:
            self.error_name = type(error).__name__

    def retired(self):
        # A success flag or callback result is insufficient: its finally blocks
        # and the actual thread must have returned before UI teardown begins.
        return not self.thread.is_alive()


class StopControlsDialog(QDialog):
    """One retained, modeless question; unlock and STOP are distinct actions."""

    stop_requested = Signal()
    lock_changed = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("OperatorStopConfirmation")
        self.setWindowTitle("Stop Angerona")
        self.setWindowModality(Qt.NonModal)
        self.setModal(False)
        self.setProperty("_angerona_no_reveal", True)
        self.setProperty("_angerona_security_prompt", True)
        self._locked = False
        self._busy = False
        self.resize(570, 420)
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        self.state_label = QLabel()
        self.state_label.setTextFormat(Qt.PlainText)
        self.state_label.setWordWrap(True)
        layout.addWidget(self.state_label)
        self.scope_label = QLabel(
            "Current session only: this lock controls dashboard STOP and tray Quit. "
            "It does not protect source processes from the same Windows user or an "
            "administrator, and it does not block an authenticated supervisor STOP.")
        self.scope_label.setTextFormat(Qt.PlainText)
        self.scope_label.setWordWrap(True)
        layout.addWidget(self.scope_label)
        self.detail_label = QLabel(
            "Stop protection, unload Angerona's local AI models, stop its owned "
            "AI services, scanners and watchdogs, and exit. Automatic recovery stays "
            "stopped until you launch Angerona again.\n\n"
            "Unrelated Python applications and a shared Ollama server stay running. "
            "Unloading a shared model also releases its residency for other apps. "
            "Downloaded model files are kept.")
        self.detail_label.setTextFormat(Qt.PlainText)
        self.detail_label.setWordWrap(True)
        layout.addWidget(self.detail_label)
        self.pending_label = QLabel()
        self.pending_label.setTextFormat(Qt.PlainText)
        self.pending_label.setWordWrap(True)
        layout.addWidget(self.pending_label)
        self.message_label = QLabel()
        self.message_label.setTextFormat(Qt.PlainText)
        self.message_label.setWordWrap(True)
        self.message_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.message_label)
        self.confirm_unlock = QCheckBox(
            "I confirm unlocking the STOP controls for this session.")
        self.confirm_stop = QCheckBox(
            "I confirm stopping Angerona and its owned components.")
        layout.addWidget(self.confirm_unlock)
        layout.addWidget(self.confirm_stop)
        buttons = QHBoxLayout()
        self.lock_button = QPushButton("Lock STOP")
        self.unlock_button = QPushButton("Unlock STOP")
        self.stop_button = QPushButton("Stop Angerona")
        self.stop_button.setObjectName("Danger")
        self.stop_button.setStyleSheet("QPushButton#Danger:disabled { background: #352126; color: #b49aa0; border: 1px solid #70424c; }")
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setDefault(True)
        for button in (self.lock_button, self.unlock_button, self.stop_button, self.cancel_button):
            button.setAutoDefault(False)
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.confirm_unlock.toggled.connect(self._sync)
        self.confirm_stop.toggled.connect(self._sync)
        self.lock_button.clicked.connect(self._lock)
        self.unlock_button.clicked.connect(self._unlock)
        self.stop_button.clicked.connect(self._request_stop)
        self.cancel_button.clicked.connect(self.reject)
        self._sync()

    def _sync(self, *_args):
        self.state_label.setText(
            "STOP controls: Locked" if self._locked else "STOP controls: Unlocked")
        self.state_label.setStyleSheet(
            "color: #fbbf24; font-weight: bold;" if self._locked
            else "color: #38bdf8; font-weight: bold;")
        self.confirm_unlock.setVisible(self._locked)
        self.confirm_stop.setVisible(not self._locked)
        self.confirm_unlock.setEnabled(not self._busy)
        self.confirm_stop.setEnabled(not self._busy)
        self.lock_button.setEnabled(not self._busy and not self._locked)
        self.unlock_button.setEnabled(
            not self._busy and self._locked and self.confirm_unlock.isChecked())
        self.stop_button.setEnabled(self.stop_confirmed())
        self.stop_button.setToolTip(
            "STOP preparation is in progress." if self._busy else
            "Unlock STOP, then confirm stopping this session." if self._locked else
            "Stop Angerona and its owned components." if self.confirm_stop.isChecked() else
            "Select the confirmation checkbox to enable Stop Angerona.")
        self.cancel_button.setEnabled(not self._busy)

    def reset_confirmation(self):
        self.confirm_unlock.setChecked(False)
        self.confirm_stop.setChecked(False)
        self._sync()

    def set_locked(self, locked):
        if self._busy:
            return
        self._locked = bool(locked)
        self.reset_confirmation()

    def set_pending_text(self, text):
        self.pending_label.setText(text)
        self.pending_label.setVisible(bool(text))

    def _lock(self):
        if self._busy or self._locked:
            return
        self.lock_changed.emit(True)

    def _unlock(self):
        if self._busy or not self._locked or not self.confirm_unlock.isChecked():
            return
        self.lock_changed.emit(False)

    def stop_confirmed(self):
        return not self._busy and not self._locked and self.confirm_stop.isChecked()

    def _request_stop(self):
        if self.stop_confirmed():
            self.stop_requested.emit()

    def set_busy(self, message):
        self._busy = True
        self.message_label.setText(message)
        self._sync()

    def set_failure(self, message):
        self._busy = False
        self.message_label.setText(message)
        self.reset_confirmation()

    def reject(self):
        if self._busy:
            return
        self.reset_confirmation()
        super().reject()

    def closeEvent(self, event):  # noqa: N802 - Qt signature
        if self._busy:
            event.ignore()
            return
        self.reset_confirmation()
        super().closeEvent(event)
