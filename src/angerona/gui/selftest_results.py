"""Modeless self-test results with explicit, bounded recovery actions."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QHBoxLayout, QLabel,
    QPlainTextEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget,
)
from angerona.gui.action_progress import ActionActivities, ActionProgressView


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
    if name == "SpywareGuard":
        return ("Open the SpywareGuard dashboard and inspect source coverage, settings and recent "
                "hits. Its offline sandbox checks detection policy; verified isolation requires "
                "separate response receipts from Adversary Combat.")
    if "the call finished after its deadline" in detail:
        return ("The check returned after its deadline and remains failed. "
                "Review module details and timing before retrying.")
    if "timed out" in detail or "still running" in detail:
        return "The check has not returned. Review module details; repeated tests will not restart it."
    if failure.get("repairable") is True:
        return "Approve recovery to restart the faulted worker and verify it with a fresh module check."
    if failure.get("guidance"):
        return str(failure["guidance"])[:1500]
    return "Review module details and the reported dependency or configuration, then run the test again."


class SelfTestResultsDialog(QDialog):
    retry_requested = Signal()
    module_retry_requested = Signal(str)
    restart_requested = Signal()
    module_restart_requested = Signal(str)
    module_requested = Signal(str)

    def __init__(self, report: str, failures: list[dict], repairable: list[dict],
                 module_names, parent=None, *, results=()):
        super().__init__(parent)
        self.setWindowTitle("Self-test results")
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.setProperty("_angerona_no_reveal", True)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.resize(820, 560)
        self._restart_sent = False
        self._can_restart = bool(repairable)
        self._repairable_names = {row["module"] for row in repairable}
        self._module_results = {row["module"]: row for row in results if row.get("kind") == "module"}
        self._module_results.update({row["module"]: row for row in failures
                                     if row["module"] not in self._module_results})
        self._report = str(report)[:200_000]
        layout = QVBoxLayout(self)
        self._activities = ActionActivities(self)
        self._activity_handle = None
        self.progress_view = ActionProgressView(self._activities, self)
        layout.addWidget(self.progress_view)
        deferred = sum(row.get("status") == "DEFERRED" for row in results)
        summary = (f"Completed — {len(failures)} item(s) need attention."
                   if failures else "Completed — no failures reported.")
        if deferred:
            summary = f"Incomplete — {deferred} check(s) deferred. {len(failures)} failure(s)."
        self.summary = QLabel(summary)
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        tabs = QTabWidget(self)
        attention = QPlainTextEdit(self)
        self.attention = attention
        attention.setReadOnly(True)
        entries = []
        for failure in failures[:128]:
            context = self._module_results.get(failure.get("module"), {})
            entries.append(
                f"{str(failure.get('module', 'Self-test'))[:200]}\n"
                f"{str(failure.get('detail', 'No detail supplied'))[:2000]}\n"
                f"Next step: {next_step({**context, **failure})}")
        entries.extend(f"{row['module']} — Deferred\n{row['detail']}" for row in results
                       if row.get("status") == "DEFERRED")
        attention.setPlainText("\n\n".join(entries) or "All reported checks passed or were expected skips.")
        tabs.addTab(attention, "Needs attention" if failures or deferred else "Summary")
        module_view = QWidget(self)
        module_layout = QVBoxLayout(module_view)
        details_row = QHBoxLayout()
        self.modules = QComboBox(self)
        available = set(module_names)
        for name in sorted(available & self._module_results.keys()):
            status = self._module_results[name].get("status", "FAIL")
            self.modules.addItem(f"{name} — {status}", name)
        self.details_button = QPushButton("Open module details", self)
        self.details_button.clicked.connect(lambda: self.module_requested.emit(self.modules.currentData()))
        self.module_retry_button = QPushButton("Test selected module", self)
        self.module_retry_button.clicked.connect(self._retry_module)
        self.module_restart_button = QPushButton("Recover selected worker", self)
        self.module_restart_button.clicked.connect(self._restart_module)
        details_row.addWidget(self.modules, 1)
        for button in (self.details_button, self.module_retry_button, self.module_restart_button):
            button.setAutoDefault(False)
            details_row.addWidget(button)
        module_layout.addLayout(details_row)
        self.module_detail = QPlainTextEdit(self)
        self.module_detail.setReadOnly(True)
        module_layout.addWidget(self.module_detail, 1)
        tabs.addTab(module_view, "Module checks")
        self.report_view = QPlainTextEdit(self)
        self.report_view.setReadOnly(True)
        self.report_view.setPlainText(self._report)
        tabs.addTab(self.report_view, "Full report")
        layout.addWidget(tabs, 1)
        eligible_names = ", ".join(str(f.get("module", ""))[:120] for f in repairable[:128])
        if eligible_names:
            attention.appendPlainText("\nEligible for restart:\n" + eligible_names)
        self.approval = QCheckBox("I approve recovery for the eligible workers listed in this report.", self)
        self.approval.setVisible(self._can_restart)
        self.approval.setToolTip(eligible_names)
        layout.addWidget(self.approval)
        actions = QHBoxLayout()
        self.copy_button = QPushButton("Copy report", self)
        self.copy_button.clicked.connect(lambda: QApplication.clipboard().setText(self._report))
        self.restart_button = QPushButton("Restart approved modules", self)
        self.restart_button.setVisible(self._can_restart)
        self.restart_button.setEnabled(False)
        self.approval.toggled.connect(self._update_module_controls)
        self.modules.currentIndexChanged.connect(self._show_module)
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
        self._show_module()

    def _update_module_controls(self):
        name = self.modules.currentData()
        idle = self._activity_handle is None
        allowed = idle and self.approval.isChecked() and not self._restart_sent
        self.details_button.setEnabled(bool(name))
        self.module_retry_button.setEnabled(idle and bool(name))
        self.module_restart_button.setVisible(self._can_restart)
        self.module_restart_button.setEnabled(allowed and name in self._repairable_names)
        self.restart_button.setEnabled(allowed and self._can_restart)

    def _show_module(self):
        name = self.modules.currentData()
        result = self._module_results.get(name, {})
        lines = [f"{name} — {result.get('status', 'FAIL')}", str(result.get("detail", ""))] if name else []
        runtime = result.get("runtime")
        if runtime:
            lines.extend(["", f"Worker {runtime['status']} · health {runtime['health']}% · "
                          f"generation {runtime['lifecycle_generation']} · {runtime['cycle_count']} completed cycles"])
            if runtime.get("health_note"):
                lines.append(str(runtime["health_note"]))
        elif result.get("scope"):
            lines.extend(["", "Worker status was unavailable for this check."])
        if result.get("scope"):
            lines.extend(["", f"Check scope — {result['scope']}"])
        if result.get("duration_ms", 0) > 0:
            lines.append(f"Elapsed — {result['duration_ms']:.1f} ms")
        if result.get("policy"):
            policy = result["policy"]
            lines.append(f"Module policy — {policy['state']} · {policy['reason']}")
        if result.get("requirements"):
            lines.append("Requirements — " + ", ".join(result["requirements"]))
        if result.get("guidance"):
            lines.extend(["", "Diagnostic and recovery guidance", str(result["guidance"])])
        if name in self._repairable_names:
            lines.append("Recovery is available for the recorded faulted worker. Approval is required.")
        if result.get("checks"):
            lines.extend(["", "Check evidence"])
            lines.extend(f"{check['status']} · {check['check']} — {check.get('detail', '')}"
                         for check in result["checks"])
        self.module_detail.setPlainText("\n".join(lines) or "No module check records are available.")
        self._update_module_controls()

    def _retry_module(self):
        if self.module_retry_button.isEnabled():
            self.module_retry_requested.emit(self.modules.currentData())

    def _restart_module(self):
        if self.module_restart_button.isEnabled():
            name = self.modules.currentData()
            self._restart_sent = True
            self.set_busy(f"Recovering {name}…")
            self.module_restart_requested.emit(name)

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
        self._activity_handle = self._activities.begin("selftest", message)
        self.summary.setText(message)
        self.retry_button.setEnabled(False)
        self.restart_button.setEnabled(False)
        self.approval.setEnabled(False)
        self._update_module_controls()

    def begin_auto_recovery(self, names):
        self._repairable_names.difference_update(names)
        self._can_restart = bool(self._repairable_names)
        self.restart_button.setVisible(self._can_restart)
        self.approval.setVisible(self._can_restart)
        self.set_busy("Recovering workers with saved auto-recovery approval…")

    def set_progress(self, done: int, total: int):
        if self._activity_handle is not None:
            self._activities.update(self._activity_handle, done=done, total=total)

    def finish_activity(self):
        self._activities.finish(self._activity_handle)
        self._activity_handle = None

    def recovery_finished(self, restarted, errors):
        self.finish_activity()
        message = f"Verified recovery for {len(restarted)} module(s)."
        if restarted:
            self.attention.appendPlainText("\nRestarted and verified:\n" + "\n".join(restarted))
        if errors:
            message += "\n" + str(errors[0])[:180]
            self.attention.appendPlainText(
                "\nRecovery details:\n" + "\n".join(str(error)[:1000] for error in errors[:128]))
        outcomes = [*restarted, *errors]
        if outcomes:
            recovery = "\n\nWorker recovery results\n" + "\n".join(outcomes)
            self._report = (self._report + recovery)[:200_000]
            self.report_view.appendPlainText(recovery)
        self.summary.setText(message)
        self.retry_button.setEnabled(True)
        self.approval.setEnabled(self._can_restart and not self._restart_sent)
        self._update_module_controls()
