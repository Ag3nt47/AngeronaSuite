"""Modeless settings for the optional third watchdog and signing review."""
from __future__ import annotations

import copy
import html
import json
from pathlib import Path
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QScrollArea, QVBoxLayout, QWidget, QCheckBox,
)

from angerona.core.watchdog_signing import (
    SigningInspection, export_signing_request, inspect_candidate,
    prepare_signing_update, signing_indicator,
)
from angerona.gui.async_snapshot import AsyncSnapshot


def _cached_status() -> dict:
    try:
        from angerona.resilience.native_watchdog import third_watchdog_status
        value = third_watchdog_status()
        return value if type(value) is dict else {}
    except Exception:
        return {}


class WatchdogSettingsPanel(QWidget):
    """The UI never treats a settings choice or signature as runtime authority."""

    def __init__(self, config, parent=None, *, status_supplier=None,
                 inspector=inspect_candidate, exporter=export_signing_request):
        super().__init__(parent)
        self.setObjectName("WatchdogSettingsPanel")
        self._status_supplier = status_supplier or _cached_status
        self._inspector = inspector
        self._exporter = exporter
        self._inspection: SigningInspection | None = None
        self._request: dict | None = None
        self._closed = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        title = QLabel("Third watchdog")
        title.setStyleSheet("font-size: 16px; font-weight: 700;")
        layout.addWidget(title)
        self.unsigned_enabled = QCheckBox(
            "Enable unsigned third watchdog · reduced protection (restart required)")
        self.unsigned_enabled.setObjectName("WatchdogUnsignedEnabled")
        self.unsigned_enabled.setChecked(
            getattr(config, "watchdog3_unsigned_enabled", False) is True)
        self.unsigned_enabled.setEnabled(sys.platform == "win32")
        layout.addWidget(self.unsigned_enabled)
        warning = QLabel(
            "Off by default. This optional ordinary-user monitor is easier to stop or "
            "tamper with. It has no privileged service, firewall or containment authority. "
            "Saved enablement does not prove that the separate helper started. "
            "Signed protection still requires explicit signing, enrollment and the "
            "existing engine and service checks.")
        warning.setTextFormat(Qt.PlainText)
        warning.setWordWrap(True)
        layout.addWidget(warning)

        status_group = QGroupBox("Current third watchdog")
        form = QFormLayout(status_group)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)
        self.status_label = self._value("Unavailable")
        self.signature_label = self._value("Signature unverified")
        self.signer_label = self._value("Unavailable")
        self.fingerprint_label = self._value("Unavailable")
        self.expiry_label = self._value("Unavailable")
        self.enrollment_label = self._value("Not enrolled")
        self.runtime_reason_label = self._value("Runtime and recovery evidence unavailable")
        for name, widget in (
            ("Mode and heartbeat", self.status_label),
            ("Signature", self.signature_label),
            ("Signer", self.signer_label),
            ("Certificate SHA-256", self.fingerprint_label),
            ("Certificate expiry", self.expiry_label),
            ("Enrollment", self.enrollment_label),
            ("Runtime and recovery", self.runtime_reason_label),
        ):
            form.addRow(name, widget)
        refresh = QPushButton("Refresh current status")
        refresh.clicked.connect(self.refresh_status)
        form.addRow(refresh)
        layout.addWidget(status_group)

        self.signing_group = QGroupBox("Signing and future updates")
        self.signing_group.setObjectName("WatchdogSigningSection")
        signing = QVBoxLayout(self.signing_group)
        explanation = QLabel(
            "Select a newly signed watchdog file, verify its signature and prepare "
            "an update request. The selected file is inspected as data and never run. "
            "A separately governed installer must reverify and apply enrollment; "
            "this settings page does not elevate, create certificates or alter trust.")
        explanation.setTextFormat(Qt.PlainText)
        explanation.setWordWrap(True)
        signing.addWidget(explanation)
        row = QHBoxLayout()
        self.candidate_path = QLineEdit()
        self.candidate_path.setObjectName("WatchdogSigningCandidate")
        self.candidate_path.setReadOnly(True)
        self.candidate_path.setPlaceholderText("Choose a signed watchdog3.exe")
        self.select_button = QPushButton("Select signed file…")
        self.select_button.clicked.connect(self._select_candidate)
        row.addWidget(self.candidate_path, 1)
        row.addWidget(self.select_button)
        signing.addLayout(row)
        actions = QHBoxLayout()
        self.inspect_button = QPushButton("Verify selected signature")
        self.inspect_button.setObjectName("WatchdogInspectSignature")
        self.inspect_button.setEnabled(False)
        self.inspect_button.clicked.connect(self._inspect_selected)
        self.prepare_button = QPushButton("Prepare signing update")
        self.prepare_button.setObjectName("WatchdogPrepareSigningUpdate")
        self.prepare_button.setEnabled(False)
        self.prepare_button.clicked.connect(self._prepare_update)
        actions.addWidget(self.inspect_button)
        actions.addWidget(self.prepare_button)
        actions.addStretch()
        signing.addLayout(actions)
        self.inspection_label = self._value(
            "No file inspected. Signature verification does not establish runtime compatibility.")
        self.inspection_label.setObjectName("WatchdogSigningResult")
        signing.addWidget(self.inspection_label)
        self.request_preview = QPlainTextEdit()
        self.request_preview.setObjectName("WatchdogSigningRequestPreview")
        self.request_preview.setReadOnly(True)
        self.request_preview.setMaximumHeight(180)
        self.request_preview.setPlaceholderText(
            "Prepared requests are UNTRUSTED planning data. Activation remains held.")
        signing.addWidget(self.request_preview)
        self.export_button = QPushButton("Export update request…")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_update)
        signing.addWidget(self.export_button, 0, Qt.AlignLeft)
        self.activation_label = self._value(
            "Activation held: this source session has no governed signing-enrollment "
            "installer. Preparing or exporting a request changes no signing, service "
            "registration, trust or protected configuration.")
        signing.addWidget(self.activation_label)
        self.guide_button = QPushButton("Open signing guide")
        self.guide_button.clicked.connect(self._open_guide)
        signing.addWidget(self.guide_button, 0, Qt.AlignLeft)
        layout.addWidget(self.signing_group)
        layout.addStretch()

        self._inspection_reader = AsyncSnapshot(
            self, self._prepare_inspection, self._apply_inspection,
            name="WatchdogSigningInspection", status=self._inspection_status)
        self._export_reader = AsyncSnapshot(
            self, self._prepare_export, self._apply_export,
            name="WatchdogSigningRequestExport", status=self._export_status)
        self._export_job = None
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self.refresh_status)
        self.refresh_status()

    @staticmethod
    def _value(text: str) -> QLabel:
        widget = QLabel(text)
        widget.setTextFormat(Qt.PlainText)
        widget.setWordWrap(True)
        widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
        return widget

    @property
    def reader_threads(self) -> tuple:
        return tuple(reader.thread for reader in
                     (self._inspection_reader, self._export_reader)
                     if reader.thread is not None)

    def refresh_status(self) -> None:
        if self._closed:
            return
        try:
            raw = self._status_supplier()
        except Exception:
            raw = {}
        raw = raw if type(raw) is dict else {}
        view = signing_indicator(raw)
        first = view.tooltip.splitlines()[0]
        self.status_label.setText(first.removeprefix("Third watchdog: "))
        self.signature_label.setText(view.label)
        self.signature_label.setStyleSheet(
            "color: #22c55e;" if view.verified else "color: #f87171;")
        # Only verified identity is displayed as a signer. Unverified strings
        # cannot manufacture a certificate or a green signature marker.
        self.signer_label.setText(raw.get("publisher", "") if view.verified else "Unavailable")
        self.fingerprint_label.setText(
            raw.get("certificate_sha256", "") if view.verified else "Unavailable")
        self.expiry_label.setText(raw.get("not_after", "") if view.verified else "Unavailable")
        self.enrollment_label.setText(
            "Enrolled; other service and policy checks still apply"
            if raw.get("activation_enrolled") is True else
            "Not enrolled; signature alone does not enable protection")
        self.signature_label.setToolTip("<p>" + html.escape(view.tooltip).replace("\n", "<br>") + "</p>")
        reasons = [raw.get("reason"), raw.get("recovery_reason")]
        self.runtime_reason_label.setText("\n".join(
            value[:512] for value in reasons if type(value) is str and value)
            or "Runtime and recovery evidence unavailable")

    def select_candidate(self, path: str) -> None:
        """Select data only; no signature process or chosen executable runs here."""
        if self._closed or self._inspection_reader.busy:
            return
        self._inspection = None
        self._request = None
        self.candidate_path.setText(str(path))
        self.prepare_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.request_preview.clear()
        self.inspect_button.setEnabled(bool(path))
        self.inspection_label.setText("Selected file has not been inspected.")

    def _select_candidate(self) -> None:
        path, _kind = QFileDialog.getOpenFileName(
            self, "Select newly signed third watchdog", "", "Third watchdog (watchdog3.exe)")
        if path:
            self.select_candidate(path)

    def _inspect_selected(self) -> None:
        if not self._closed and self.candidate_path.text():
            self._inspection_reader.request(invalidate=True)

    def _prepare_inspection(self):
        selected = self.candidate_path.text()
        inspect = self._inspector
        return lambda: inspect(selected)

    def _inspection_status(self, state: str) -> None:
        if self._closed:
            return
        busy = state == "updating"
        self.select_button.setEnabled(not busy)
        self.inspect_button.setEnabled(not busy and bool(self.candidate_path.text()))
        if busy:
            self._inspection = None
            self._request = None
            self.prepare_button.setEnabled(False)
            self.export_button.setEnabled(False)
            self.request_preview.clear()
            self.inspection_label.setText("Checking selected file; it is not being executed…")
        elif state == "unavailable":
            self.inspection_label.setText(
                "Signature inspection unavailable. No enrollment or activation was performed. "
                "A reviewed bundled inspector and a verifiable signature are required.")

    def _apply_inspection(self, value) -> None:
        if self._closed or type(value) is not SigningInspection or value.path != self.candidate_path.text():
            return
        self._inspection = value
        self.prepare_button.setEnabled(value.signature_valid is True)
        if value.signature_valid:
            self.inspection_label.setText(
                f"Signature verified. Signer: {value.publisher}\n"
                f"Certificate SHA-256: {value.certificate_sha256}\n"
                f"Expiry: {value.not_after}\n"
                "Runtime compatibility and enrollment remain unverified.")
        else:
            self.inspection_label.setText(
                "Signature not verified. " + (value.reason or "No valid signer evidence available."))

    def _prepare_update(self) -> None:
        try:
            self._request = prepare_signing_update(self._inspection)
        except Exception:
            self._request = None
            self.export_button.setEnabled(False)
            self.request_preview.clear()
            self.activation_label.setText("No verified signing update request is available.")
            return
        self.request_preview.setPlainText(json.dumps(self._request, indent=2, ensure_ascii=True))
        self.export_button.setEnabled(True)
        self.activation_label.setText(
            "UNTRUSTED update request prepared. Activation remains held until a "
            "separately governed installer revalidates and applies enrollment. "
            "No certificate, key, service or protected file was changed.")

    def _export_update(self) -> None:
        if self._request is None or self._export_reader.busy:
            return
        path, _kind = QFileDialog.getSaveFileName(
            self, "Export signing review request", "watchdog3-signing-review.json",
            "JSON report (*.json)")
        if path:
            self._export_job = (Path(path), copy.deepcopy(self._request))
            self._export_reader.request(invalidate=True)

    def _prepare_export(self):
        destination, request = self._export_job
        export = self._exporter
        return lambda: (export(destination, request), str(destination))[1]

    def _apply_export(self, destination) -> None:
        if not self._closed:
            self.activation_label.setText(
                f"Untrusted review request exported to {destination}. "
                "No signing enrollment or service activation was performed.")

    def _export_status(self, state: str) -> None:
        if not self._closed:
            self.export_button.setEnabled(state != "updating" and self._request is not None)
            if state == "unavailable":
                self.activation_label.setText(
                    "Request export failed or the selected filename already exists. "
                    "Choose a new report filename. No protected enrollment changed.")

    def _open_guide(self) -> None:
        # A fixed public documentation destination, never an imported URL.
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl(
            "https://github.com/Ag3nt47/AngeronaSuite/blob/main/"
            "docs/enterprise/WINDOWS_SERVICE_ONBOARDING.md"))

    def focus_signing(self) -> None:
        self.select_button.setFocus(Qt.OtherFocusReason)
        ancestor = self.parentWidget()
        while ancestor is not None:
            if isinstance(ancestor, QScrollArea):
                ancestor.ensureWidgetVisible(self.signing_group, 16, 16)
                break
            ancestor = ancestor.parentWidget()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.refresh_status()
        self._status_timer.start()

    def hideEvent(self, event) -> None:
        self._status_timer.stop()
        super().hideEvent(event)

    def shutdown(self) -> None:
        self._closed = True
        self._status_timer.stop()
        self._inspection_reader.close()
        self._export_reader.close()
