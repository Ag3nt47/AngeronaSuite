"""Interactive, local-only malware and exposure scanning for Live Alerts."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)


class ScanCenterPanel(QFrame):
    """Run bounded scans off the GUI thread and render redacted findings."""

    result_ready = Signal(object)
    progress_ready = Signal(object)
    error_ready = Signal(str)

    def __init__(self, *, bus=None, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Panel")
        self.bus = bus
        self._busy = False
        self._cancellation = None
        self._result: dict[str, object] | None = None
        self.result_ready.connect(self._apply_result)
        self.progress_ready.connect(self._apply_progress)
        self.error_ready.connect(self._apply_error)

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 14)
        root.setSpacing(8)
        title = QLabel("🛡  Angerona Scan Center")
        title.setStyleSheet("font-size:15px; font-weight:800; color:#e0f2fe;")
        root.addWidget(title)
        scope = QLabel(
            "Scan this computer for malware indicators and risky exposure. Angerona "
            "uses bounded local checks and can ask Microsoft Defender to scan on Windows. "
            "It never scans arbitrary remote devices from this panel."
        )
        scope.setWordWrap(True)
        scope.setStyleSheet("color:#9fb3c8;")
        root.addWidget(scope)

        target = QFrame()
        target.setObjectName("Card")
        target_layout = QGridLayout(target)
        target_layout.addWidget(QLabel("Folder or drive"), 0, 0)
        self.path_edit = QLineEdit(str(Path.home() / "Downloads"))
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        target_layout.addWidget(self.path_edit, 0, 1)
        target_layout.addWidget(browse, 0, 2)
        self.include_defender = QCheckBox(
            "Also request a Microsoft Defender custom scan (Windows only)"
        )
        target_layout.addWidget(self.include_defender, 1, 1, 1, 2)
        root.addWidget(target)

        actions = QGridLayout()
        path_scan = QPushButton("📁  Scan selected folder / drive")
        path_scan.clicked.connect(self._scan_selected_path)
        quick = QPushButton("⚡  Microsoft Defender quick scan")
        quick.clicked.connect(self._defender_quick_scan)
        ports = QPushButton("🎐  Audit local listening ports")
        ports.clicked.connect(self._audit_ports)
        network = QPushButton("📡  Review local network posture")
        network.clicked.connect(self._audit_network)
        self.stop_button = QPushButton("■  Stop scan")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._cancel)
        actions.addWidget(path_scan, 0, 0)
        actions.addWidget(quick, 0, 1)
        actions.addWidget(ports, 1, 0)
        actions.addWidget(network, 1, 1)
        actions.addWidget(self.stop_button, 0, 2, 2, 1)
        root.addLayout(actions)

        status_row = QHBoxLayout()
        self.status = QLabel("Ready · no scan is running")
        self.status.setStyleSheet("color:#94a3b8;")
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        status_row.addWidget(self.status, 1)
        status_row.addWidget(self.progress, 1)
        root.addLayout(status_row)

        self.findings = QTableWidget(0, 5)
        self.findings.setHorizontalHeaderLabels(
            ["Severity", "Finding", "Redacted evidence", "Solution", "Patch guidance"]
        )
        self.findings.setEditTriggers(QTableWidget.NoEditTriggers)
        self.findings.setSelectionBehavior(QTableWidget.SelectRows)
        self.findings.setWordWrap(True)
        self.findings.horizontalHeader().setStretchLastSection(True)
        root.addWidget(self.findings, 1)

        footer = QHBoxLayout()
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.document().setMaximumBlockCount(1000)
        self.log.setMaximumHeight(110)
        footer.addWidget(self.log, 1)
        export = QPushButton("📤  Export report")
        export.clicked.connect(self._export)
        footer.addWidget(export)
        root.addLayout(footer)

    def _service(self):
        from angerona.core.security_scan_center import SecurityScanCenter

        return SecurityScanCenter()

    def _browse(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self, "Select a local folder or drive", self.path_edit.text()
        )
        if selected:
            self.path_edit.setText(selected)

    def _confirm_defender(self, target: str, *, custom: bool) -> bool:
        action_note = (
            "This custom scan disables automatic remediation; review findings before "
            "any separate containment action."
            if custom
            else "Microsoft Defender may apply the threat actions configured in Windows "
            "Security during a quick scan."
        )
        return QMessageBox.question(
            self,
            "Run Microsoft Defender",
            "Angerona will ask the installed Microsoft Defender engine to scan "
            f"{target}. {action_note} Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        ) == QMessageBox.Yes

    def _scan_selected_path(self) -> None:
        target = Path(self.path_edit.text().strip()).expanduser()
        if not target.exists():
            QMessageBox.information(self, "Scan Center", "Choose an existing local folder.")
            return
        use_defender = self.include_defender.isChecked()
        if use_defender and not self._confirm_defender(str(target), custom=True):
            return

        def run(service, cancellation, progress):
            local_result = service.scan_path(
                target, cancellation=cancellation, progress=progress
            )
            if use_defender:
                defender_result = service.run_microsoft_defender_scan(
                    target,
                    execute=True,
                    cancellation=cancellation,
                    progress=progress,
                )
                return self._merge_scan_results(local_result, defender_result)
            return local_result

        self._start("Scanning selected folder / drive", run)

    def _defender_quick_scan(self) -> None:
        if not self._confirm_defender("this computer (quick scan)", custom=False):
            return
        self._start(
            "Microsoft Defender quick scan",
            lambda service, cancellation, progress: service.run_microsoft_defender_scan(
                execute=True,
                quick=True,
                cancellation=cancellation,
                progress=progress,
            ),
        )

    def _audit_ports(self) -> None:
        self._start(
            "Auditing local listening ports",
            lambda service, cancellation, progress: service.audit_listening_exposure(
                cancellation=cancellation, progress=progress
            ),
        )

    def _audit_network(self) -> None:
        self._start(
            "Reviewing local network posture",
            lambda service, cancellation, progress: service.summarize_network_posture(
                cancellation=cancellation, progress=progress
            ),
        )

    @staticmethod
    def _merge_scan_results(first, second) -> dict[str, object]:
        left = first.to_dict() if hasattr(first, "to_dict") else dict(first)
        right = second.to_dict() if hasattr(second, "to_dict") else dict(second)
        findings = list(left.get("findings", [])) + list(right.get("findings", []))
        merged = dict(left)
        merged["findings"] = findings
        merged["components"] = [left, right]
        merged["summary"] = {
            "finding_count": len(findings),
            "scanners": [
                left.get("operation", "Angerona"),
                right.get("operation", "Defender"),
            ],
        }
        return merged

    def _start(self, label: str, operation: Callable) -> None:
        if self._busy:
            QMessageBox.information(self, "Scan Center", "A scan is already running.")
            return
        try:
            from angerona.core.security_scan_center import ScanCancellationToken

            cancellation = ScanCancellationToken()
        except Exception as exc:
            self._apply_error(str(exc))
            return
        self._busy = True
        self._cancellation = cancellation
        self.stop_button.setEnabled(True)
        self.status.setText(label + "…")
        self.progress.setRange(0, 0)
        self.log.setPlainText(label + " started.")

        def progress(payload) -> None:
            data = payload.to_dict() if hasattr(payload, "to_dict") else payload
            self.progress_ready.emit(data)

        def worker() -> None:
            try:
                result = operation(self._service(), cancellation, progress)
                data = result.to_dict() if hasattr(result, "to_dict") else result
                self.result_ready.emit(data)
            except Exception as exc:
                self.error_ready.emit(f"{type(exc).__name__}: {exc}")

        threading.Thread(target=worker, name="AngeronaScanCenter", daemon=True).start()

    def _cancel(self) -> None:
        cancellation = self._cancellation
        if cancellation is not None:
            cancellation.cancel()
            self.status.setText("Cancellation requested…")

    def _apply_progress(self, payload) -> None:
        data = payload if isinstance(payload, dict) else {}
        message = str(
            data.get("message")
            or data.get("detail")
            or data.get("phase")
            or "Scanning"
        )
        completed = int(data.get("completed", 0) or 0)
        total = int(data.get("total", data.get("total_limit", 0)) or 0)
        if total > 0:
            self.progress.setRange(0, total)
            self.progress.setValue(min(completed, total))
        self.status.setText(message)

    def _apply_result(self, payload) -> None:
        data = payload if isinstance(payload, dict) else {}
        self._result = data
        raw_findings = data.get("findings", [])
        findings = raw_findings if isinstance(raw_findings, list) else []
        self.findings.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            item = finding if isinstance(finding, dict) else {}
            values = (
                item.get("severity", "Info"),
                item.get("title", item.get("finding", "Posture observation")),
                item.get("evidence", "Details available in export"),
                item.get("remediation", item.get("solution", "Review configuration")),
                item.get("patch_guidance", item.get("patch", "Follow vendor guidance")),
            )
            for column, value in enumerate(values):
                text = json.dumps(value, sort_keys=True) if isinstance(
                    value, (dict, list)
                ) else str(value)
                self.findings.setItem(row, column, QTableWidgetItem(text))
        self.findings.resizeRowsToContents()
        self._busy = False
        self._cancellation = None
        self.stop_button.setEnabled(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.status.setText(f"Complete · {len(findings)} finding(s)")
        summary = data.get("summary", {})
        if isinstance(summary, str):
            self.log.setPlainText(summary)
        else:
            self.log.setPlainText(json.dumps(summary, indent=2, sort_keys=True))

    def _apply_error(self, message: str) -> None:
        self._busy = False
        self._cancellation = None
        self.stop_button.setEnabled(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.status.setText("Scan failed or was refused")
        self.log.setPlainText(message)

    def _export(self) -> None:
        if self._result is None:
            QMessageBox.information(self, "Scan Center", "Run a scan first.")
            return
        path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Scan Center report",
            str(Path.home() / "angerona-scan-report.json"),
            "JSON report (*.json)",
        )
        if not path:
            return
        try:
            Path(path).write_text(
                json.dumps(self._result, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            self.log.appendPlainText("Exported redacted scan report.")
        except Exception as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
