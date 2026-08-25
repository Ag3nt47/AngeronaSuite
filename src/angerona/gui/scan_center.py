"""Interactive, local-only malware and exposure scanning for Live Alerts."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from angerona.gui.animations import begin_loading, finish_loading, update_loading


def _emit_if_accepting(owner, signal_name: str, *args) -> bool:
    """Drop late Python-worker results after the owning Qt panel closes."""
    try:
        if not bool(getattr(owner, "_accept_async_results", False)):
            return False
        getattr(owner, signal_name).emit(*args)
        return True
    except RuntimeError:
        # Shiboken raises when the C++ QObject was already deleted. A completed
        # scan has no UI consumer at that point, so this is normal cancellation.
        return False


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
        self._last_progress_message = ""
        self._accept_async_results = True
        self._worker_thread: threading.Thread | None = None
        self._loading_token: str | None = None
        self.result_ready.connect(self._apply_result)
        self.progress_ready.connect(self._apply_progress)
        self.error_ready.connect(self._apply_error)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self._scroll = QScrollArea()
        self._scroll.setObjectName("ScanCenterScroll")
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._content = QWidget()
        self._content.setObjectName("ScanCenterContent")
        self._content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._scroll.setWidget(self._content)
        outer.addWidget(self._scroll)

        root = QVBoxLayout(self._content)
        root.setContentsMargins(14, 12, 14, 14)
        root.setSpacing(8)
        self._title = QLabel("🛡  Angerona Scan Center")
        self._title.setStyleSheet("font-size:15px; font-weight:800; color:#e0f2fe;")
        root.addWidget(self._title)
        self._scope = QLabel(
            "Scan this computer for malware indicators and risky exposure. Angerona "
            "uses bounded local checks and can ask Microsoft Defender to scan on Windows. "
            "It never scans arbitrary remote devices from this panel."
        )
        self._scope.setWordWrap(True)
        self._scope.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        self._scope.setStyleSheet("color:#9fb3c8;")
        root.addWidget(self._scope)

        target = QFrame()
        target.setObjectName("Card")
        self._target_layout = QGridLayout(target)
        self._target_layout.setHorizontalSpacing(8)
        self._target_layout.setVerticalSpacing(6)
        self._target_label = QLabel("Folder or drive")
        self.path_edit = QLineEdit(str(Path.home() / "Downloads"))
        self.path_edit.setMinimumHeight(36)
        self.path_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._browse_button = QPushButton("Browse…")
        self._browse_button.setMinimumHeight(36)
        self._browse_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._browse_button.clicked.connect(self._browse)
        self.include_defender = QCheckBox(
            "Also request a Microsoft Defender custom scan (Windows only)"
        )
        self.include_defender.setMinimumHeight(30)
        self.include_defender.setToolTip(
            "Optionally ask Microsoft Defender to scan the selected local folder or drive."
        )
        root.addWidget(target)

        self._actions_layout = QGridLayout()
        self._actions_layout.setHorizontalSpacing(8)
        self._actions_layout.setVerticalSpacing(7)
        self.path_scan_button = QPushButton("📁  Scan selected folder / drive")
        self.path_scan_button.clicked.connect(self._scan_selected_path)
        self.quick_scan_button = QPushButton("⚡  Microsoft Defender quick scan")
        self.quick_scan_button.clicked.connect(self._defender_quick_scan)
        self.ports_button = QPushButton("🎐  Audit local listening ports")
        self.ports_button.clicked.connect(self._audit_ports)
        self.network_button = QPushButton("📡  Review local network posture")
        self.network_button.clicked.connect(self._audit_network)
        self.stop_button = QPushButton("■  Stop scan")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._cancel)
        self._action_buttons = (
            self.path_scan_button,
            self.quick_scan_button,
            self.ports_button,
            self.network_button,
            self.stop_button,
        )
        self._full_button_text = (
            "📁  Scan selected folder / drive",
            "⚡  Microsoft Defender quick scan",
            "🎐  Audit local listening ports",
            "📡  Review local network posture",
            "■  Stop scan",
        )
        self._compact_button_text = (
            "📁  Scan folder / drive",
            "⚡  Defender quick scan",
            "🎐  Listening ports",
            "📡  Network posture",
            "■  Stop scan",
        )
        for button, full_text in zip(self._action_buttons, self._full_button_text):
            button.setMinimumHeight(40)
            button.setMinimumWidth(0)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.setToolTip(full_text)
        root.addLayout(self._actions_layout)

        self._status_layout = QGridLayout()
        self._status_layout.setHorizontalSpacing(10)
        self._status_layout.setVerticalSpacing(5)
        self.status = QLabel("Ready · no scan is running")
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(28)
        self.status.setStyleSheet("color:#94a3b8;")
        self.progress = QProgressBar()
        self.progress.setMinimumHeight(30)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat("Ready")
        root.addLayout(self._status_layout)

        self.findings = QTableWidget(0, 5)
        self.findings.setHorizontalHeaderLabels(
            ["Severity", "Finding", "Redacted evidence", "Solution", "Patch guidance"]
        )
        self.findings.setEditTriggers(QTableWidget.NoEditTriggers)
        self.findings.setSelectionBehavior(QTableWidget.SelectRows)
        self.findings.setWordWrap(True)
        self.findings.setMinimumHeight(150)
        self.findings.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        header = self.findings.horizontalHeader()
        header.setMinimumSectionSize(78)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        for column in range(1, 5):
            header.setSectionResizeMode(column, QHeaderView.Stretch)
        root.addWidget(self.findings, 1)

        self._footer_layout = QGridLayout()
        self._footer_layout.setHorizontalSpacing(8)
        self._footer_layout.setVerticalSpacing(6)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.document().setMaximumBlockCount(1000)
        self.log.setMinimumHeight(64)
        self.log.setMaximumHeight(110)
        self.export_button = QPushButton("📤  Export report")
        self.export_button.setMinimumHeight(40)
        self.export_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.export_button.clicked.connect(self._export)
        root.addLayout(self._footer_layout)

        self._responsive_mode: tuple[bool, str, bool, bool] | None = None
        self._apply_responsive_layout(self.width())

    @staticmethod
    def _remove_widgets(layout: QGridLayout, widgets: tuple[QWidget, ...]) -> None:
        for widget in widgets:
            layout.removeWidget(widget)

    def _apply_responsive_layout(self, width: int) -> None:
        """Reflow controls instead of compressing text below its useful size."""
        compact_text = width < 430
        action_mode = "wide" if width >= 1080 else "two" if width >= 620 else "one"
        status_inline = width >= 700
        footer_inline = width >= 650
        mode = (compact_text, action_mode, status_inline, footer_inline)
        if mode == self._responsive_mode:
            return
        self._responsive_mode = mode

        labels = self._compact_button_text if compact_text else self._full_button_text
        for button, label in zip(self._action_buttons, labels):
            button.setText(label)
        self.include_defender.setText(
            "Also run Microsoft Defender (Windows)"
            if compact_text
            else "Also request a Microsoft Defender custom scan (Windows only)"
        )

        target_widgets = (
            self._target_label,
            self.path_edit,
            self._browse_button,
            self.include_defender,
        )
        self._remove_widgets(self._target_layout, target_widgets)
        for column in range(3):
            self._target_layout.setColumnStretch(column, 0)
        if width >= 860:
            self._target_layout.addWidget(self._target_label, 0, 0)
            self._target_layout.addWidget(self.path_edit, 0, 1)
            self._target_layout.addWidget(self._browse_button, 0, 2)
            self._target_layout.addWidget(self.include_defender, 1, 1, 1, 2)
            self._target_layout.setColumnStretch(1, 1)
        elif width >= 520:
            self._target_layout.addWidget(self._target_label, 0, 0, 1, 2)
            self._target_layout.addWidget(self.path_edit, 1, 0)
            self._target_layout.addWidget(self._browse_button, 1, 1)
            self._target_layout.addWidget(self.include_defender, 2, 0, 1, 2)
            self._target_layout.setColumnStretch(0, 1)
        else:
            self._target_layout.addWidget(self._target_label, 0, 0)
            self._target_layout.addWidget(self.path_edit, 1, 0)
            self._target_layout.addWidget(self._browse_button, 2, 0)
            self._target_layout.addWidget(self.include_defender, 3, 0)
            self._target_layout.setColumnStretch(0, 1)

        self._remove_widgets(self._actions_layout, self._action_buttons)
        self.stop_button.setMinimumHeight(87 if action_mode == "wide" else 40)
        for column in range(3):
            self._actions_layout.setColumnStretch(column, 0)
        if action_mode == "wide":
            self._actions_layout.addWidget(self.path_scan_button, 0, 0)
            self._actions_layout.addWidget(self.quick_scan_button, 0, 1)
            self._actions_layout.addWidget(self.ports_button, 1, 0)
            self._actions_layout.addWidget(self.network_button, 1, 1)
            self._actions_layout.addWidget(self.stop_button, 0, 2, 2, 1)
            for column in range(3):
                self._actions_layout.setColumnStretch(column, 1)
        elif action_mode == "two":
            self._actions_layout.addWidget(self.path_scan_button, 0, 0)
            self._actions_layout.addWidget(self.quick_scan_button, 0, 1)
            self._actions_layout.addWidget(self.ports_button, 1, 0)
            self._actions_layout.addWidget(self.network_button, 1, 1)
            self._actions_layout.addWidget(self.stop_button, 2, 0, 1, 2)
            self._actions_layout.setColumnStretch(0, 1)
            self._actions_layout.setColumnStretch(1, 1)
        else:
            for row, button in enumerate(self._action_buttons):
                self._actions_layout.addWidget(button, row, 0)
            self._actions_layout.setColumnStretch(0, 1)

        self._remove_widgets(self._status_layout, (self.status, self.progress))
        if status_inline:
            self._status_layout.addWidget(self.status, 0, 0)
            self._status_layout.addWidget(self.progress, 0, 1)
            self._status_layout.setColumnStretch(0, 1)
            self._status_layout.setColumnStretch(1, 1)
        else:
            self._status_layout.addWidget(self.status, 0, 0)
            self._status_layout.addWidget(self.progress, 1, 0)
            self._status_layout.setColumnStretch(0, 1)
            self._status_layout.setColumnStretch(1, 0)

        self._remove_widgets(self._footer_layout, (self.log, self.export_button))
        if footer_inline:
            self._footer_layout.addWidget(self.log, 0, 0)
            self._footer_layout.addWidget(self.export_button, 0, 1)
            self._footer_layout.setColumnStretch(0, 1)
            self._footer_layout.setColumnStretch(1, 0)
        else:
            self._footer_layout.addWidget(self.log, 0, 0)
            self._footer_layout.addWidget(self.export_button, 1, 0)
            self._footer_layout.setColumnStretch(0, 1)
            self._footer_layout.setColumnStretch(1, 0)

        header = self.findings.horizontalHeader()
        if width >= 900:
            header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
            for column in range(1, 5):
                header.setSectionResizeMode(column, QHeaderView.Stretch)
        else:
            widths = (88, 190, 220, 210, 210)
            for column, column_width in enumerate(widths):
                header.setSectionResizeMode(column, QHeaderView.Interactive)
                self.findings.setColumnWidth(column, column_width)

        min_height = 540 if action_mode == "wide" else 660 if action_mode == "two" else 820
        self._content.setMinimumHeight(min_height)
        self._content.updateGeometry()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._apply_responsive_layout(event.size().width())

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
        self.progress.setFormat("Working…")
        self._last_progress_message = ""
        self.log.setPlainText(label + " started.")
        self._loading_token = begin_loading(label + "…")

        def progress(payload) -> None:
            data = payload.to_dict() if hasattr(payload, "to_dict") else payload
            _emit_if_accepting(self, "progress_ready", data)

        def worker() -> None:
            try:
                result = operation(self._service(), cancellation, progress)
                data = result.to_dict() if hasattr(result, "to_dict") else result
                _emit_if_accepting(self, "result_ready", data)
            except Exception as exc:
                _emit_if_accepting(
                    self, "error_ready", f"{type(exc).__name__}: {exc}"
                )

        self._worker_thread = threading.Thread(
            target=worker, name="AngeronaScanCenter", daemon=True
        )
        self._worker_thread.start()

    def _cancel(self) -> None:
        cancellation = self._cancellation
        if cancellation is not None:
            cancellation.cancel()
            self.status.setText("Cancellation requested…")

    def _apply_progress(self, payload) -> None:
        if not self._accept_async_results:
            return
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
            self.progress.setFormat("%p%")
        else:
            # Defender's command-line scanner does not expose an honest percent.
            # Keep the activity animation indeterminate and show elapsed liveness
            # messages rather than pinning a misleading bar at 0%.
            self.progress.setRange(0, 0)
            self.progress.setFormat("Active")
        self.status.setText(message)
        update_loading(
            self._loading_token or "",
            message,
            done=completed,
            total=total,
        )
        if message != self._last_progress_message:
            self._last_progress_message = message
            self.log.appendPlainText(message)

    def _apply_result(self, payload) -> None:
        if not self._accept_async_results:
            return
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
        finish_loading(self._loading_token)
        self._loading_token = None
        self._cancellation = None
        self.stop_button.setEnabled(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        result_status = str(data.get("status", "completed")).casefold()
        if result_status == "cancelled":
            self.status.setText("Cancelled · Defender process stopped")
            self.progress.setFormat("Cancelled")
        elif result_status in {"error", "limited", "rejected", "unsupported"}:
            self.status.setText(f"Finished with {result_status} status")
            self.progress.setFormat(result_status.title())
        else:
            self.status.setText(f"Complete · {len(findings)} finding(s)")
            self.progress.setFormat("Complete")
        summary = data.get("summary", {})
        if isinstance(summary, str):
            self.log.setPlainText(summary)
        else:
            self.log.setPlainText(json.dumps(summary, indent=2, sort_keys=True))

    def _apply_error(self, message: str) -> None:
        if not self._accept_async_results:
            return
        self._busy = False
        finish_loading(self._loading_token)
        self._loading_token = None
        self._cancellation = None
        self.stop_button.setEnabled(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat("Failed")
        self.status.setText("Scan failed or was refused")
        self.log.setPlainText(message)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        self._accept_async_results = False
        finish_loading(self._loading_token)
        self._loading_token = None
        cancellation = self._cancellation
        if cancellation is not None:
            try:
                cancellation.cancel()
            except Exception:
                pass
        super().closeEvent(event)

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
