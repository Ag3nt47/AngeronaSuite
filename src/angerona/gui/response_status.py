"""Memory-only response readiness; diagnostic display grants no authority."""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QFrame, QLabel, QPushButton, QVBoxLayout


_DECISIONS = {
    "waiting": "No response decision in this worker session.",
    "queued": "Evidence queued for validation.",
    "below_threshold": "Evidence is below the configured response severity.",
    "missing_contract": "The detector supplied no exact response authorization.",
    "integrity_failed": "Evidence authentication failed; no response authorized.",
    "queue_saturated": "The response queue could not accept another request.",
    "policy_disabled": "Automatic response is disabled in the saved policy.",
    "not_actionable": "Evidence describes health, exposure or information.",
    "invalid_contract": "The evidence did not bind a valid action and exact target.",
    "recovery_required": "Journal recovery or capacity prevents automatic action.",
    "executed": "A response action was recorded as applied.",
    "no_eligible_target": "No action completed: check policy, target and action receipts.",
}


class ResponseStatusPanel(QFrame):
    """Show why Combat can or cannot act without polling its action journal."""

    def __init__(self, module_provider, parent=None):
        super().__init__(parent)
        self._module_provider = module_provider
        self.setFrameShape(QFrame.StyledPanel)
        layout = QVBoxLayout(self)
        self.state_label = QLabel()
        self.state_label.setStyleSheet("font-size:16px; font-weight:700;")
        self.reason_label = QLabel()
        self.activity_label = QLabel()
        self.guidance_label = QLabel()
        for label in (
            self.state_label, self.reason_label, self.activity_label, self.guidance_label,
        ):
            label.setTextFormat(Qt.PlainText)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(label)
        self.refresh_button = QPushButton("Refresh response status")
        self.refresh_button.clicked.connect(self.refresh)
        layout.addWidget(self.refresh_button)
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.refresh)
        self.refresh()

    def refresh(self):
        try:
            module = self._module_provider()
            reader = getattr(module, "response_snapshot", None)
            snapshot = reader() if callable(reader) else None
        except Exception:
            snapshot = None
        if not isinstance(snapshot, dict):
            self.state_label.setText("Response status unavailable")
            self.reason_label.setText("Open Settings from the running dashboard to inspect Combat.")
            self.activity_label.clear()
            self.guidance_label.clear()
            return
        self.state_label.setText("Automatic response: " + str(snapshot.get("state", "UNKNOWN")))
        color = "#4ade80" if snapshot.get("ready") else "#fbbf24"
        if snapshot.get("state") in {"RECOVERY REQUIRED", "JOURNAL FULL", "QUEUE FULL"}:
            color = "#f87171"
        self.state_label.setStyleSheet(f"font-size:16px; font-weight:700; color:{color};")
        self.reason_label.setText(str(snapshot.get("reason", ""))[:500])
        counts = snapshot.get("counts", {})
        counts = counts if isinstance(counts, dict) else {}
        self.activity_label.setText(
            f"Queue: {snapshot.get('queue_depth', 0)}/{snapshot.get('queue_capacity', 0)}"
            f" · Applied events: {counts.get('executed', 0)}"
            f" · Queue drops: {snapshot.get('queue_drops', 0)}\n"
            + _DECISIONS.get(snapshot.get("last_decision"), _DECISIONS["waiting"])
        )
        if snapshot.get("state") in {"RECOVERY REQUIRED", "JOURNAL FULL"}:
            guidance = (
                "Automatic action is held. Review the recovery error and verified action "
                "history. Preserve the journal, protected anchor and witness together; "
                "use verified recovery before rearming. Restarting or changing response "
                "severity does not repair this hold."
            )
        else:
            guidance = (
                "Status reflects this worker session. A threat alert alone does not "
                "authorize containment: the detector must supply authenticated evidence "
                "bound to an exact action and target."
            )
        self.guidance_label.setText(guidance)

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        self.refresh()
        self._timer.start()

    def hideEvent(self, event):  # noqa: N802
        self._timer.stop()
        super().hideEvent(event)

    def closeEvent(self, event):  # noqa: N802
        self._timer.stop()
        super().closeEvent(event)
