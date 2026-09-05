"""Modeless self-test results with explicit, bounded recovery actions."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QHBoxLayout, QLabel,
    QPlainTextEdit, QPushButton, QTabWidget, QVBoxLayout,
)


def next_step(failure: dict) -> str:
    name = str(failure.get("module", ""))
    detail = str(failure.get("detail", "")).casefold()
    if name == "AI Triage (Ollama)":
        return ("Check that local Ollama is running and the configured model is installed. "
                "Review the AI model setting, then run the test again.")
    if name == "AV Telemetry Bridge" and "continuity" in detail:
        return ("Review Defender telemetry access and continuity evidence in module details. "
                "A restart cannot restore missing event records; the recorded gap remains visible.")
    if name == "Adversary Combat":
        return ("Review the module's recovery and journal status. Recovery requires operator "
                "review; this self-test does not arm response or clear its recovery hold.")
    if "timed out" in detail or "still running" in detail:
        return "The check has not returned. Review module details; repeated tests will not restart it."
    if failure.get("repairable") is True:
        return "An audited module restart is available below. Review and approve the listed restarts first."
    return "Review module details and the reported dependency or configuration, then run the test again."


class SelfTestResultsDialog(QDialog):
    retry_requested = Signal()
    restart_requested = Signal()
    module_requested = Signal(str)

    def __init__(self, report: str, failures: list[dict], repairable: list[dict],
                 module_names, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Self-test results")
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.setProperty("_angerona_no_reveal", True)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.resize(820, 560)
        self._restart_sent = False
        self._can_restart = bool(repairable)
        self._report = str(report)[:200_000]
        layout = QVBoxLayout(self)
        self.summary = QLabel(
            f"Completed — {len(failures)} item(s) need attention."
            if failures else "Completed — no failures reported.")
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        tabs = QTabWidget(self)
        attention = QPlainTextEdit(self)
        self.attention = attention
        attention.setReadOnly(True)
        entries = []
        for failure in failures[:128]:
            entries.append(
                f"{str(failure.get('module', 'Self-test'))[:200]}\n"
                f"{str(failure.get('detail', 'No detail supplied'))[:2000]}\n"
                f"Next step: {next_step(failure)}")
        attention.setPlainText("\n\n".join(entries) or "All reported checks passed or were expected skips.")
        tabs.addTab(attention, "Needs attention" if failures else "Summary")
        report_view = QPlainTextEdit(self)
        report_view.setReadOnly(True)
        report_view.setPlainText(self._report)
        tabs.addTab(report_view, "Full report")
        layout.addWidget(tabs, 1)
        details_row = QHBoxLayout()
        self.modules = QComboBox(self)
        available = set(module_names)
        self.modules.addItems(sorted({str(f.get("module")) for f in failures if f.get("module") in available}))
        self.details_button = QPushButton("Open module details", self)
        self.details_button.setEnabled(self.modules.count() > 0)
        self.details_button.clicked.connect(lambda: self.module_requested.emit(self.modules.currentText()))
        details_row.addWidget(self.modules, 1)
        details_row.addWidget(self.details_button)
        layout.addLayout(details_row)
        eligible_names = ", ".join(str(f.get("module", ""))[:120] for f in repairable[:128])
        if eligible_names:
            attention.appendPlainText("\nEligible for restart:\n" + eligible_names)
        self.approval = QCheckBox("I approve restarting the eligible modules listed in this report.", self)
        self.approval.setVisible(self._can_restart)
        self.approval.setToolTip(eligible_names)
        layout.addWidget(self.approval)
        actions = QHBoxLayout()
        self.copy_button = QPushButton("Copy report", self)
        self.copy_button.clicked.connect(lambda: QApplication.clipboard().setText(self._report))
        self.restart_button = QPushButton("Restart approved modules", self)
        self.restart_button.setVisible(self._can_restart)
        self.restart_button.setEnabled(False)
        self.approval.toggled.connect(lambda checked: self.restart_button.setEnabled(checked and not self._restart_sent))
        self.restart_button.clicked.connect(self._restart)
        self.retry_button = QPushButton("Run self-test again", self)
        self.retry_button.clicked.connect(self._retry)
        self.close_button = QPushButton("Close", self)
        self.close_button.clicked.connect(self.close)
        for button in (self.copy_button, self.restart_button, self.retry_button, self.close_button):
            button.setAutoDefault(False)
            actions.addWidget(button)
        self.close_button.setDefault(True)
        layout.addLayout(actions)

    def _retry(self):
        self.retry_button.setEnabled(False)
        self.retry_requested.emit()

    def _restart(self):
        if not self._can_restart or not self.approval.isChecked() or self._restart_sent:
            return
        self._restart_sent = True
        self.set_busy("Requesting approved restarts…")
        self.restart_requested.emit()

    def set_busy(self, message: str):
        self.summary.setText(message)
        self.retry_button.setEnabled(False)
        self.restart_button.setEnabled(False)
        self.approval.setEnabled(False)

    def recovery_finished(self, restarted, errors):
        message = f"Restart requested for {len(restarted)} module(s). Run self-test again to verify."
        if errors:
            message += "\n" + str(errors[0])[:180]
            self.attention.appendPlainText(
                "\nRecovery details:\n" + "\n".join(str(error)[:1000] for error in errors[:128]))
        self.summary.setText(message)
        self.retry_button.setEnabled(True)
