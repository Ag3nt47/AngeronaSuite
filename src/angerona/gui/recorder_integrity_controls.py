"""Public witness enrollment and cached recorder coverage, with worker-only keys."""
from __future__ import annotations

import secrets

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox, QFormLayout, QGroupBox, QLabel, QLineEdit, QPlainTextEdit,
    QPushButton, QSizePolicy, QSpinBox, QToolButton, QVBoxLayout, QWidget,
)

from angerona.core.recorder_integrity import (
    settings_from_config, validate_settings,
)


class _ClickSpinBox(QSpinBox):
    def wheelEvent(self, event):  # noqa: N802
        event.ignore()


class RecorderIntegrityControls(QGroupBox):
    def __init__(self, config, manager=None, parent=None):
        super().__init__("Independent recorder integrity", parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        self._config, self._manager = config, manager
        runtime = getattr(manager, "recorder_integrity_runtime", None)
        self._enrollment = getattr(runtime, "enrollment", None)
        self._identity_revision = -1
        self._detached = False
        self._fields = {}
        layout = QVBoxLayout(self)
        self.status = QLabel()
        self.status.setTextFormat(Qt.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self._enabled = QCheckBox("Witness committed recorder history on an independent machine")
        self._enabled.setChecked(getattr(config, "recorder_witness_enabled", False))
        layout.addWidget(self._enabled)
        note = QLabel("Optional signed receipts help detect changes to previously sealed records. "
            "They do not establish sensor truth or kernel health. Missing or pruned records remain "
            "visible coverage gaps. Storage or network failures pause witnessing while protection continues. "
            "Enrollment changes take effect after restart.")
        note.setWordWrap(True)
        layout.addWidget(note)
        toggle = QToolButton()
        toggle.setText("Remote witness enrollment and storage")
        toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        toggle.setCheckable(True)
        toggle.setArrowType(Qt.RightArrow)
        layout.addWidget(toggle)
        panel = QWidget()
        panel.setVisible(False)
        form = QFormLayout(panel)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self._independent = QCheckBox("Authority and its signing key are administered on another machine")
        self._independent.setChecked(getattr(config, "recorder_witness_independent_host", False))
        self._independent.setToolTip("This declaration is not physical custody attestation. Keep the witness outside host backups.")
        form.addRow(self._independent)
        labels = {
            "recorder_witness_endpoint": "Private HTTPS authority address",
            "recorder_witness_certificate_sha256": "TLS certificate SHA-256 pin",
            "recorder_witness_authority_public_key": "Authority Ed25519 public PEM",
            "recorder_witness_installation_id": "Installation ID (32 hex characters)",
            "recorder_witness_client_id": "Client ID (32 hex characters)",
            "recorder_witness_client_certificate_path": "Enrolled client certificate file",
            "recorder_witness_client_key_path": "Protected client TLS key file",
            "recorder_witness_ca_bundle_path": "Authority CA file (optional)",
        }
        values = settings_from_config(config)
        for name, label in labels.items():
            if name.endswith("public_key"):
                field = QPlainTextEdit()
                field.setMaximumHeight(90)
                field.setPlainText(values[name])
            else:
                field = QLineEdit(values[name])
                field.setMaxLength(4096 if name.endswith("path") else 512)
            self._fields[name] = field
            form.addRow(label, field)
        self._archive_mib = _ClickSpinBox()
        self._archive_mib.setRange(4, 64)
        self._archive_mib.setSuffix(" MiB")
        self._archive_mib.setValue(values["recorder_witness_archive_mib"])
        form.addRow("Receipt archive limit", self._archive_mib)
        budget = QLabel("Up to 128 sealed ranges within this limit, plus one bounded pending record. "
            "At a 60-second cadence, active recording may reach the range limit in about two hours. "
            "Existing receipts are preserved; a full archive pauses sealing and reports the gap. "
            "Service deployments require their own service-account credentials and enrollment.")
        budget.setWordWrap(True)
        form.addRow(budget)
        self._identity_button = QPushButton("Create or show this host's public enrollment key")
        self._identity_button.clicked.connect(self._request_identity)
        form.addRow(self._identity_button)
        self._public_identity = QPlainTextEdit()
        self._public_identity.setReadOnly(True)
        self._public_identity.setMaximumHeight(90)
        self._public_identity.setPlaceholderText("Only the public request key is shown. Enroll it on the independent authority.")
        form.addRow("Host public request key", self._public_identity)
        self._identity_status = QLabel("The private request key remains in this profile's OS credential store.")
        self._identity_status.setTextFormat(Qt.PlainText)
        self._identity_status.setWordWrap(True)
        form.addRow(self._identity_status)
        layout.addWidget(panel)
        def expand(opened):
            panel.setVisible(opened)
            toggle.setArrowType(Qt.DownArrow if opened else Qt.RightArrow)
        toggle.toggled.connect(expand)
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self.refresh_status)
        self._timer.start()
        self.refresh_status()

    def _request_identity(self):
        if self._enrollment is not None:
            try:
                self._enrollment.request()
            except Exception:
                pass  # The retained owner publishes its sticky failure state.
            self._refresh_identity()

    def _show_identity(self, public):
        if type(public) is not str or len(public) > 2048:
            return
        self._public_identity.setPlainText(public)
        for name in ("recorder_witness_installation_id", "recorder_witness_client_id"):
            if not self._fields[name].text():
                self._fields[name].setText(secrets.token_hex(16))

    def _refresh_identity(self):
        if self._enrollment is None:
            self._identity_button.setEnabled(False)
            self._identity_status.setText("Open these controls from the running dashboard to enroll its owned profile.")
            return
        snapshot = self._enrollment.latest_status()
        self._identity_button.setEnabled(snapshot.state not in {"running", "stopped", "retirement-held"})
        if snapshot.revision == self._identity_revision:
            return
        self._identity_revision = snapshot.revision
        if snapshot.state == "ready":
            self._show_identity(snapshot.public_key)
        self._identity_status.setText({"running": "Resolving protected host identity…",
            "ready": "Public request key ready. Enroll this key and the displayed IDs on the independent authority.",
            "unavailable": "Protected identity is unavailable. Existing credentials were not replaced; review credential-store availability.",
            "stopped": "Enrollment task stopped with the dashboard.",
            "retirement-held": "Enrollment task retirement is unproven; its owner is retained."
            }.get(snapshot.state, "The private request key remains in this profile's OS credential store."))

    def refresh_status(self):
        if self._detached:
            return
        self._refresh_identity()
        runtime = getattr(self._manager, "recorder_integrity_runtime", None)
        if runtime is None:
            self.status.setText("Independent witnessing is not running in this dashboard session.")
            return
        status = runtime.latest_status()
        self.status.setText(f"{status.state}: {status.reason}\n"
            f"Sealed epoch {status.last_sealed_epoch} · row {status.last_sealed_row} · "
            f"archive {status.archive_bytes / 1048576:.2f}/{status.archive_limit_bytes / 1048576:.0f} MiB · "
            f"pending commit: {'yes' if status.pending else 'no'}\n"
            f"History awaiting checks: {status.verification_backlog_epochs} ranges · "
            f"known unavailable rows: {status.known_missing_rows} · changed rows in latest check: {status.changed_rows}")

    def write_candidate(self, candidate):
        values = {"recorder_witness_enabled": self._enabled.isChecked(),
            "recorder_witness_independent_host": self._independent.isChecked(),
            "recorder_witness_archive_mib": self._archive_mib.value()}
        for name, field in self._fields.items():
            values[name] = (field.toPlainText() if isinstance(field, QPlainTextEdit) else field.text()).strip()
        for name, value in validate_settings(values).items():
            setattr(candidate, name, value)

    def shutdown_reader(self):
        self._detached = True
        self._timer.stop()
        # Detach presentation only. The runtime retains any credential task
        # through its final write and includes it in the suite STOP drain.
