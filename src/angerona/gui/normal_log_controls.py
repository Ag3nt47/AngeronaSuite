"""Cached normal crash-log controls; no log reads, deletion or native queries."""
from __future__ import annotations

from types import SimpleNamespace

from PySide6.QtCore import QObject, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QGridLayout, QGroupBox, QLabel, QMessageBox,
    QPushButton, QSpinBox, QVBoxLayout,
)

from angerona.core.crashlog import configure_normal_log_budget, normal_write_snapshot


MIB = 1024 * 1024
_HOLD_REASONS = frozenset(("file-limit", "process-limit", "io-uncertain"))


def apply_normal_log_policy(config, *, note_target=None) -> dict:
    """One nonblocking attempt; accepted policy is not proof of a healthy sink."""
    try:
        result = configure_normal_log_budget(
            limit_mib=config.normal_log_max_mib,
            message_kib=config.normal_log_message_kib,
            paused=config.normal_log_paused,
        )
    except Exception:
        result = {"accepted": False, "reason": "configuration-unavailable"}
    owner = config if note_target is None else note_target
    owner._normal_log_policy_pending = result.get("accepted") is not True
    owner._normal_log_apply_note = _apply_text(result) if owner._normal_log_policy_pending else ""
    return result


def _rows(snapshot):
    rows = snapshot.get("targets", ()) if type(snapshot) is dict else ()
    if type(rows) not in (tuple, list):
        return ()
    return tuple(row for row in rows[:2] if type(row) is dict
                 and row.get("role") in ("logs", "diagnostics"))


def _number(value):
    return value if type(value) is int and 0 <= value <= (1 << 63) - 1 else None


def normal_log_warning(snapshot) -> str:
    """Fixed per-run categories; changing counts do not generate popup storms."""
    if type(snapshot) is not dict or snapshot.get("paused") is True:
        return ""
    rows = _rows(snapshot)
    for reason in ("io-uncertain", "file-limit", "process-limit"):
        if any(row.get("reason") == reason for row in rows):
            return reason
    limit = _number(snapshot.get("limit_bytes"))
    if limit:
        for row in rows:
            sizes = (_number(row.get("checked_size_bytes")), _number(row.get("reserved_bytes")))
            if any(size is not None and size >= limit * .8 for size in sizes):
                return "near-limit"
    return ""


def normal_log_usage(snapshot) -> str:
    if type(snapshot) is not dict:
        return "Normal log status unavailable. Existing evidence is preserved."
    limit = _number(snapshot.get("limit_bytes"))
    limit_text = f"{limit / MIB:g} MiB" if limit is not None else "unknown"
    lines = [f"Active allowance: {limit_text} per target and per process. "
             + ("Normal writes are blocked." if snapshot.get("paused") is True else "Normal writes are allowed within limits.")]
    reasons = {
        "": "ready at last check", "not-installed": "not installed",
        "resume-check-required": "waiting for the next opened-file check",
        "policy-paused": "blocked by your policy", "file-limit": "file limit reached",
        "process-limit": "process allowance reached", "io-uncertain": "write outcome uncertain; held for this process",
    }
    for row in _rows(snapshot):
        used, checked = _number(row.get("reserved_bytes")), _number(row.get("checked_size_bytes"))
        suppressed = _number(row.get("suppressed_blocks"))
        used_text = f"{used / MIB:.2f} MiB" if used is not None else "unknown"
        checked_text = f"{checked / MIB:.2f} MiB" if checked is not None else "unknown"
        count_text = str(suppressed) if suppressed is not None else "unknown"
        if snapshot.get("suppression_counts_lower_bound") is True and suppressed is not None:
            count_text = "at least " + count_text
        state = reasons.get(row.get("reason"), "status unavailable")
        lines.append(f"{row['role'].capitalize()}: {state}; reserved {used_text}; last checked file {checked_text}; suppressed blocks {count_text}.")
    lines.append("Cached observations; file size can change after the check. Existing logs are preserved.")
    return "\n".join(lines)


def _apply_text(result) -> str:
    if type(result) is dict and result.get("accepted") is True:
        return ("Policy accepted for this run. Resumable targets require an opened-file check "
                "on the next append; uncertain writes remain held. Save Settings to keep this choice.")
    return "Live policy was not applied. The writer may be busy; retry Apply now. Existing active limits remain in force."


class NormalLogControls(QGroupBox):
    def __init__(self, config, parent=None):
        super().__init__("Python and Qt crash-log storage", parent)
        self._config = config
        layout = QVBoxLayout(self)
        note = QLabel(
            "Normal exception and Qt messages stop at both the file ceiling and this process's "
            "cumulative allowance, for each of two crash logs. Full messages over the message "
            "limit are suppressed. No log is deleted or truncated. Native fault output and "
            "other writers are outside this budget; this is not a drive quota.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.paused = QCheckBox("Block normal Python / Qt crash-log writes")
        self.paused.setChecked(config.normal_log_paused)
        layout.addWidget(self.paused)
        grid = QGridLayout()
        self.max_mib = QSpinBox()
        self.max_mib.setRange(1, 64)
        self.max_mib.setSuffix(" MiB")
        self.max_mib.setValue(config.normal_log_max_mib)
        self.message_kib = QSpinBox()
        self.message_kib.setRange(4, 256)
        self.message_kib.setSuffix(" KiB")
        self.message_kib.setValue(config.normal_log_message_kib)
        grid.addWidget(QLabel("Per-target file and process allowance:"), 0, 0)
        grid.addWidget(self.max_mib, 0, 1)
        grid.addWidget(QLabel("Complete message limit (including header):"), 1, 0)
        grid.addWidget(self.message_kib, 1, 1)
        layout.addLayout(grid)
        actions = QGridLayout()
        self.block_button = QPushButton("Block for this run")
        self.allow_button = QPushButton("Allow within limits")
        self.apply_button = QPushButton("Apply now / retry")
        self.block_button.clicked.connect(self._block)
        self.allow_button.clicked.connect(self._allow)
        self.apply_button.clicked.connect(self._apply)
        for index, button in enumerate((self.block_button, self.allow_button, self.apply_button)):
            actions.addWidget(button, 0, index)
        layout.addLayout(actions)
        self.result = QLabel()
        self.result.setWordWrap(True)
        self.result.setTextFormat(Qt.PlainText)
        pending_note = getattr(config, "_normal_log_apply_note", "")
        if type(pending_note) is str:
            self.result.setText(pending_note)
        layout.addWidget(self.result)
        self.usage = QLabel()
        self.usage.setWordWrap(True)
        self.usage.setTextFormat(Qt.PlainText)
        layout.addWidget(self.usage)
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    def refresh(self):
        self.usage.setText(normal_log_usage(normal_write_snapshot()))

    def write_candidate(self, candidate):
        candidate.normal_log_paused = self.paused.isChecked()
        candidate.normal_log_max_mib = self.max_mib.value()
        candidate.normal_log_message_kib = self.message_kib.value()
        candidate.validate_normal_log_settings()

    def _apply(self):
        policy = SimpleNamespace(normal_log_paused=self.paused.isChecked(),
                                 normal_log_max_mib=self.max_mib.value(),
                                 normal_log_message_kib=self.message_kib.value())
        result = apply_normal_log_policy(policy, note_target=self._config)
        text = _apply_text(result)
        self.result.setText(text)
        self.refresh()

    def _block(self):
        self.paused.setChecked(True)
        self._apply()

    def _allow(self):
        self.paused.setChecked(False)
        self._apply()

    def closeEvent(self, event):
        self._timer.stop()
        super().closeEvent(event)


class NormalLogWarningController(QObject):
    """One nonmodal warning per category per run, from cached values only."""
    def __init__(self, config, parent, open_settings):
        super().__init__(parent)
        self._config, self._open_settings = config, open_settings
        self._warning = None
        self._acknowledged = set()
        self._closed = False
        self._timer = QTimer(self)
        self._timer.setInterval(30_000)
        self._timer.timeout.connect(self.poll)
        self._timer.start()
        QApplication.instance().aboutToQuit.connect(self.close)

    def poll(self):
        if self._closed:
            return
        snapshot = normal_write_snapshot()
        pending = getattr(self._config, "_normal_log_policy_pending", False) is True
        category = "policy-not-applied" if pending else normal_log_warning(snapshot)
        if not category or category in self._acknowledged or self._warning is not None:
            return
        self._acknowledged.add(category)
        pending_text = ("Saved or requested normal log policy has not been applied to the live writer. "
                        "Active limits are shown below; your requested block or tighter limit may not be active.\n\n"
                        if pending else "")
        dialog = QMessageBox(QMessageBox.Warning, "Angerona normal log storage needs review",
            pending_text + normal_log_usage(snapshot) + "\n\nChoose Block for this run, or review Allow / change limits "
            "in Settings. Logging limits do not block startup or stop the security engines. "
            "Native fault output is separate and remains outside this normal-message budget.",
            parent=self.parent())
        block = dialog.addButton("Block for this run", QMessageBox.RejectRole)
        change = dialog.addButton("Allow / change limits…", QMessageBox.ActionRole)
        retry = dialog.addButton("Retry saved policy now", QMessageBox.ActionRole) if pending else None
        keep = dialog.addButton("Keep current limits", QMessageBox.AcceptRole)
        dialog.setDefaultButton(block)
        dialog.setEscapeButton(keep)
        dialog.setTextFormat(Qt.PlainText)
        dialog.setWindowModality(Qt.NonModal)
        self._warning = dialog

        def finished(_result):
            clicked = dialog.clickedButton()
            self._warning = None
            if self._closed:
                dialog.deleteLater()
                return
            if clicked is block:
                result = apply_normal_log_policy(SimpleNamespace(
                    normal_log_max_mib=self._config.normal_log_max_mib,
                    normal_log_message_kib=self._config.normal_log_message_kib,
                    normal_log_paused=True), note_target=self._config)
                if result.get("accepted") is not True:
                    self._open_settings("General")
            elif retry is not None and clicked is retry:
                result = apply_normal_log_policy(self._config)
                if result.get("accepted") is not True:
                    self._open_settings("General")
            elif clicked is change:
                self._open_settings("General")
            dialog.deleteLater()
        dialog.finished.connect(finished)
        dialog.show()

    def close(self, *_args):
        self._closed = True
        self._timer.stop()
        if self._warning is not None:
            self._warning.reject()
