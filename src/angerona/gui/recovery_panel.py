"""Cached recovery posture and operator requests to the existing guard worker."""
from __future__ import annotations

import json
from collections.abc import Mapping

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QVBoxLayout, QWidget,
)


def _label(text):
    label = QLabel(text)
    label.setWordWrap(True)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class RecoveryPanel(QWidget):
    def __init__(self, manager=None, parent=None):
        super().__init__(parent)
        self.manager = manager
        self._timer = QTimer(self)
        self._timer.setInterval(1500)
        self._timer.timeout.connect(self.refresh)
        root = QVBoxLayout(self)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.addWidget(_label("INDEPENDENT RECOVERY · signed backup evidence and measured isolated restores"))
        layout.addWidget(_label("Select an authorized local encrypted Angerona backup and its separately signed "
            "copy statement. Enroll the recovery authority's public key through an independent trusted route first. "
            "A real test restores only into a new private Angerona directory and rereads every extracted byte. "
            "It never overwrites live files, uploads a backup, deletes a backup, or creates signing/encryption keys."))
        self.status = _label("Deployment required · no independently signed backup has been tested.")
        layout.addWidget(self.status)
        self.latest = _label("Latest tested archive's signed revision: unknown · age: unknown · measured restore time: unknown")
        layout.addWidget(self.latest)
        enrollment = QFormLayout()
        self.signer_id = QLineEdit()
        self.signer_id.setMaxLength(128)
        self.signer_id.setPlaceholderText("Pinned separate recovery-authority identifier")
        enrollment.addRow("Authority ID:", self.signer_id)
        self.public_key = QLineEdit()
        self.public_key.setMaxLength(256)
        self.public_key.setPlaceholderText("Base64 of the enrolled 32-byte Ed25519 PUBLIC key")
        enrollment.addRow("Authority PUBLIC key:", self.public_key)
        layout.addLayout(enrollment)
        self.enroll_button = QPushButton("Enroll public recovery authority")
        self.enroll_button.clicked.connect(lambda: self._queue("queue_enroll_recovery_authority",
            self.signer_id.text().strip(), self.public_key.text().strip()))
        layout.addWidget(self.enroll_button)
        paths = QFormLayout()
        self.archive = self._path_row(paths, "Authorized encrypted backup:", "Encrypted backup (*.angerona)")
        self.evidence = self._path_row(paths, "Signed copy statement:", "Signed evidence (*.json)")
        layout.addLayout(paths)
        self.encryption_key = QLineEdit()
        self.audit_key = QLineEdit()
        keys = QFormLayout()
        for title, field in (("One-shot decryption key:", self.encryption_key), ("One-shot proof/audit key:", self.audit_key)):
            field.setEchoMode(QLineEdit.EchoMode.Password)
            field.setMaxLength(64)
            field.setPlaceholderText("Optional original 32-byte key as 64 hex characters; cleared when queued")
            keys.addRow(title, field)
        layout.addLayout(keys)
        layout.addWidget(_label("Leave both key fields empty to request this user's existing protected recovery-drill "
            "keys. Missing keys require a fresh unlock; no new keys are generated. One-shot keys are copied to a "
            "bounded worker request and wiped best effort. Python/Qt temporary strings cannot be fully erased."))
        actions = QHBoxLayout()
        self.import_button = QPushButton("Import signed evidence")
        self.import_button.clicked.connect(lambda: self._queue("queue_import_recovery_evidence", self.evidence.text().strip()))
        actions.addWidget(self.import_button)
        self.restore_button = QPushButton("Test isolated restore")
        self.restore_button.clicked.connect(self._restore)
        actions.addWidget(self.restore_button)
        self.recheck_button = QPushButton("Recheck actual restored bytes")
        self.recheck_button.clicked.connect(self._recheck)
        actions.addWidget(self.recheck_button)
        layout.addLayout(actions)
        schedule = QHBoxLayout()
        self.recurring = QCheckBox("Opt in to recurring tests while this guard runs")
        schedule.addWidget(self.recurring)
        self.interval = QSpinBox()
        self.interval.setRange(1, 720)
        self.interval.setValue(24)
        self.interval.setSuffix(" hours")
        schedule.addWidget(self.interval)
        self.schedule_button = QPushButton("Apply recurring-test choice")
        self.schedule_button.clicked.connect(lambda: self._queue("queue_recovery_schedule",
            self.recurring.isChecked(), self.interval.value()))
        schedule.addWidget(self.schedule_button)
        layout.addLayout(schedule)
        layout.addWidget(_label("Recurring tests require a previously verified, explicitly selected archive and original "
            "keys already available in protected storage. One-shot keys are never retained for scheduling. The existing "
            "module worker paces tests and pauses under UGCAP. Recurrence is disabled after restart. At most 16 private "
            "test directories are retained; reaching capacity requires operator review. Decrypted test copies remain "
            "private for fresh rechecks. Closing this panel leaves admitted work owned by the guard; stopping the guard "
            "cancels cooperatively. Native filesystem calls cannot be preempted."))
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Cached signed evidence, measured restore proof, gaps and schedule status.")
        layout.addWidget(self.details)
        layout.addWidget(_label("A signature authenticates an enrolled authority's statement. It does not physically prove "
            "that storage is offsite, air-gapped, immutable or independently administered. The measured test proves only "
            "the selected archive's isolated extraction and current byte reread. An unknown, stale or missing external "
            "copy stays a coverage gap; a local test does not create independent backup redundancy. The revision label "
            "is the enrolled signer's association with that archive; this test does not prove a full Git revision "
            "reconstruction or full system recovery."))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(body)
        root.addWidget(scroll)
        self._buttons = (self.enroll_button, self.import_button, self.restore_button,
                         self.recheck_button, self.schedule_button)
        self.refresh()

    def _path_row(self, form, title, pattern):
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        field = QLineEdit()
        field.setMaxLength(32768)
        layout.addWidget(field, 1)
        choose = QPushButton("Choose…")
        def select():
            path, _ = QFileDialog.getOpenFileName(self, title, field.text(), pattern)
            if path:
                field.setText(path)
        choose.clicked.connect(select)
        layout.addWidget(choose)
        form.addRow(title, row)
        return field

    def _module(self):
        modules = getattr(self.manager, "modules", {})
        return modules.get("Immutable Recovery Assurance Guard") if isinstance(modules, Mapping) else None

    def _queue(self, method, *args, **kwargs):
        action = getattr(self._module(), method, None)
        try:
            accepted = callable(action) and action(*args, **kwargs) is True
        except Exception:
            accepted = False
        self.status.setText("Operator recovery request queued to the existing guard worker." if accepted else
            "Recovery request was not queued. Check the running guard, workspace gate and selected inputs.")
        return accepted

    def _keys(self):
        first, second = self.encryption_key.text(), self.audit_key.text()
        self.encryption_key.clear()
        self.audit_key.clear()
        if not first and not second:
            return None
        return bytearray(first, "ascii", "replace"), bytearray(second, "ascii", "replace")

    def _restore(self):
        keys = self._keys()
        try:
            self._queue("queue_restore_recovery", self.archive.text().strip(), self.evidence.text().strip(), keys=keys)
        finally:
            for key in keys or ():
                key[:] = b"\0" * len(key)

    def _recheck(self):
        keys = self._keys()
        try:
            self._queue("queue_recheck_recovery", keys=keys)
        finally:
            for key in keys or ():
                key[:] = b"\0" * len(key)

    def refresh(self):
        module = self._module()
        available = module is not None and getattr(module, "status", "stopped") == "running"
        for button in self._buttons:
            button.setEnabled(available)
        if module is None:
            self.status.setText("Recovery guard unavailable · independent backup coverage is unknown.")
            return
        try:
            snapshot = module.dashboard_snapshot()
        except Exception:
            self.status.setText("Cached recovery status unavailable; no new proof is claimed.")
            return
        if not isinstance(snapshot, dict):
            return
        self.status.setText("Recovery: " + str(snapshot.get("status", "unknown"))[:200])
        age = snapshot.get("last_verified_age_seconds")
        duration = snapshot.get("latest_restore_seconds")
        self.latest.setText("Latest tested archive's signed revision: " + str(snapshot.get("latest_verified_revision") or "unknown")[:64]
            + " · checked age: " + (f"{age:.0f}s" if type(age) in (int, float) else "unknown")
            + " · measured restore: " + (f"{duration:.3f}s" if type(duration) in (int, float) else "unknown"))
        self.details.setPlainText(json.dumps(snapshot, indent=2, ensure_ascii=True, default=str)[:18000])

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        self.refresh()
        self._timer.start()

    def hideEvent(self, event):  # noqa: N802
        self._timer.stop()
        self.encryption_key.clear()
        self.audit_key.clear()
        super().hideEvent(event)

    def closeEvent(self, event):  # noqa: N802
        self._timer.stop()
        self.encryption_key.clear()
        self.audit_key.clear()
        super().closeEvent(event)
