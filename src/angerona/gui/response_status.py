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
    "startup_expired": "Startup evidence exceeded 30 seconds; a fresh detector observation is required.",
    "generation_discarded": "Pending work was discarded when this worker stopped or failed startup.",
}


def _rule_summary(policy) -> str:
    """Describe the effective standing policy without granting action authority."""
    if policy is None:
        return "Automatic rules unavailable; no policy could be read."
    minimum = getattr(getattr(policy, "min_severity", None), "name", "UNKNOWN")
    mode = getattr(policy, "mode", "unknown")
    process = ("suspend" if mode == "contain" else
               getattr(policy, "process_action", "unknown"))
    process = {"suspend": "Suspend", "terminate": "Terminate"}.get(process, "Unavailable")
    on = lambda name: getattr(policy, name, None) is True
    lines = [
        f"Effective automatic rules · {minimum}+ authenticated detector evidence",
        "Verified file → " + ("Quarantine with Undo" if on("quarantine_files") else "No automatic quarantine"),
        "Exact process instance → " + process + " (protected processes excluded)",
        "Named remote address/program → " + ("Block with Undo" if on("block_network") else "No automatic network block"),
    ]
    if on("isolate_host") and mode == "maximum":
        count = getattr(policy, "isolation_event_threshold", "?")
        seconds = getattr(policy, "isolation_window_seconds", "?")
        lines.append(f"Explicit local-host evidence → Isolate on CRITICAL or {count} distinct causes within {seconds}s")
    else:
        lines.append("Whole-host isolation → Off for this policy")
    lines.append("Deception → " + ("Keep honeypots active" if on("activate_honeypots") else "No automatic activation"))
    lines.append(
        "Rules run without per-alert approval when ARMED. Each action still needs "
        "an exact detector-authorized target; health, exposure and AI advice are not containment commands."
    )
    return "\n".join(lines)


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
        self.rules_label = QLabel()
        for label in (
            self.state_label, self.reason_label, self.activity_label, self.guidance_label,
            self.rules_label,
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
            self.state_label.setStyleSheet(
                "font-size:16px; font-weight:700; color:#9fb3c8;"
            )
            self.reason_label.setText("Open Settings from the running dashboard to inspect Combat.")
            self.activity_label.clear()
            self.guidance_label.clear()
            self.rules_label.clear()
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
                "use verified recovery before rearming. Startup can repair only a proven "
                "unapplied fixed simulation-marker checkpoint. Other holds need separate "
                "verified recovery; changing severity does not repair them."
            )
        elif snapshot.get("state") == "DISABLED":
            guidance = (
                "Automatic response is off. To run a containment test, enable "
                "Adversary Combat in Settings, save, and wait for ARMED status. "
                "Detection-only drills do not require Combat."
            )
        elif snapshot.get("state") == "QUEUE FULL":
            guidance = (
                "The response queue cannot accept more requests now. Check queue "
                "depth, drops, and verified action receipts; an alert does not "
                "mean its response was applied."
            )
        else:
            guidance = (
                "Status reflects this worker session. A threat alert alone does not "
                "authorize containment: the detector must supply authenticated evidence "
                "bound to an exact action and target."
            )
        self.guidance_label.setText(guidance)
        try:
            reader = getattr(module, "policy", None)
            policy = reader() if callable(reader) else None
        except Exception:
            policy = None
        rules = _rule_summary(policy)
        if self.rules_label.text() != rules:
            self.rules_label.setText(rules)

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
