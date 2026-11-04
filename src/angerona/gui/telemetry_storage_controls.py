"""Cached telemetry storage choices; no GUI filesystem or SQLite probes."""
from __future__ import annotations

from collections import deque
import re
from types import SimpleNamespace

from PySide6.QtCore import QObject, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFormLayout, QGroupBox, QHBoxLayout,
    QLabel, QMessageBox, QPushButton, QSpinBox, QToolButton, QVBoxLayout, QWidget,
)

from angerona.core.config import (
    TELEMETRY_STORAGE_RANGES,
    apply_telemetry_storage_policy, apply_telemetry_storage_values,
    telemetry_storage_policy_values,
)
from angerona.core.status_report import _telemetry_storage_snapshot

MIB = 1024 * 1024
_REASONS = {
    "": "Ready at the last worker check", "unconfigured": "Storage policy unavailable",
    "facts_unmeasured": "Waiting for worker capacity observations",
    "facts_stale": "Waiting for fresh worker observations", "probe_pending": "Worker check pending",
    "operator_blocked": "New telemetry storage blocked by your policy",
    "db_target": "Shared database reached the telemetry target",
    "wal_target": "Shared WAL reached the telemetry target",
    "free_floor": "Free space is below the telemetry allowance",
    "probe_failed": "Worker capacity check unavailable", "identity_changed": "Storage identity changed",
    "unit_too_large": "A pending event exceeds the bounded write unit",
    "worker_unavailable": "Recorder worker unavailable", "worker_stopped": "Recorder worker stopped",
    "spool_capacity": "Telemetry spill storage is at its allowance",
}


def _uint(value):
    return value if type(value) is int and 0 <= value <= (1 << 63) - 1 else None


def telemetry_storage_snapshot(recorder):
    """Validate and copy fixed cached fields; never fall back to disk or a clock."""
    snapshot = _telemetry_storage_snapshot(recorder)
    return snapshot if type(snapshot) is dict and "storage_pending_events" in snapshot else None


def telemetry_pending_text(snapshot) -> str:
    if type(snapshot) is not dict or _uint(snapshot.get("storage_pending_events")) is None:
        return "Pending telemetry status unavailable; unpersisted events can be lost when Angerona exits."
    count = snapshot["storage_pending_events"]
    return (f"Pending in memory at the last snapshot: {count}. "
            "Unpersisted events can be lost when Angerona exits; recorded history is preserved.")


def telemetry_storage_usage(snapshot) -> str:
    if snapshot is None:
        return "Telemetry storage status unavailable. No current capacity or recording readiness is established."
    reason = snapshot["reason_code"]
    if (not snapshot["blocked"] and (snapshot["facts_stale"]
            or snapshot["facts_generation"] != snapshot["policy_generation"])):
        reason = reason if reason in {"probe_failed", "identity_changed", "unit_too_large",
                                      "worker_unavailable", "worker_stopped", "spool_capacity"} else "facts_unmeasured"
    lines = [_REASONS[reason] + "."]
    def amount(value):
        return f"{value / MIB:.2f} MiB" if value is not None else "unmeasured"
    lines.append(f"Database {amount(snapshot['db_bytes'])} / target {amount(snapshot['db_target_bytes'])}; "
                 f"WAL {amount(snapshot['wal_bytes'])} / target {amount(snapshot['wal_target_bytes'])}.")
    lines.append(f"Free space {amount(snapshot['free_bytes'])}; minimum for telemetry {amount(snapshot['min_free_bytes'])}.")
    lines.append(f"Instance counters: rejected {snapshot['rejection_storage_hold']}; "
                 f"failed or unconfirmed writes {snapshot['storage_write_failures']}; "
                 f"discarded queued copies {snapshot['storage_user_discarded']}.")
    lines.append(f"Cumulative deferral attempts this instance: replay {snapshot['replay_deferred']}; "
                 f"maintenance {snapshot['maintenance_deferred']}.")
    lines.append("Deferral attempts do not establish a current durable backlog. Any retained oversized replay "
                 "line needs offline review; this view does not discard originals.")
    if snapshot["coverage_gap"]:
        lines.append("A telemetry coverage gap was reported. These counters are process-lifetime and not durable.")
    lines.append("Cached worker observations; file sizes can change after the check.")
    return "\n".join(lines)


def telemetry_storage_warning(snapshot) -> str:
    if snapshot is None:
        return "status_unavailable"
    if snapshot["blocked"]:
        return "pending" if snapshot["storage_pending_events"] else ""
    if snapshot["state"] in {"held", "unavailable"}:
        return snapshot["reason_code"] or "status_unavailable"
    if snapshot["state"] in {"unconfigured", "unmeasured"}:
        return ""
    if snapshot["facts_stale"] or snapshot["facts_generation"] != snapshot["policy_generation"]:
        return ""
    for measured, target in (("db_bytes", "db_target_bytes"), ("wal_bytes", "wal_target_bytes")):
        used, limit = snapshot[measured], snapshot[target]
        if used is not None and limit is not None and limit > 0 and used >= limit * .8:
            return "near_target"
    return ""


def _apply_text(result):
    if result.get("accepted") is True:
        return ("Policy accepted for this run. Allow waits for a fresh worker check and cannot bypass "
                "the targets or unavailable facts. An already admitted finite write may finish. Save Settings to keep this choice.")
    return ("Live policy application is unverified. Review the active cached status and retry Apply; "
            "no capacity probe runs in this window.")


class _ClickNumber(QSpinBox):
    def wheelEvent(self, event):  # noqa: N802
        event.ignore()


class _ClickChoice(QComboBox):
    def wheelEvent(self, event):  # noqa: N802
        event.ignore()


class TelemetryStorageControls(QGroupBox):
    def __init__(self, config, manager=None, parent=None):
        super().__init__("Telemetry event storage", parent)
        self._config, self._recorder = config, getattr(manager, "recorder", None)
        self._closed = False
        self._review_dialog = None
        layout = QVBoxLayout(self)
        explanation = QLabel("Targets hold this telemetry writer while the dashboard and sensors continue. "
                             "Existing recorded history is preserved; new events may remain unpersisted or be rejected.")
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        self.blocked = QCheckBox("Block new telemetry event storage")
        self.blocked.setChecked(config.telemetry_storage_blocked)
        layout.addWidget(self.blocked)
        toggle = QToolButton()
        toggle.setText("Targets and shared-database scope")
        toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        toggle.setCheckable(True)
        toggle.setArrowType(Qt.RightArrow)
        layout.addWidget(toggle)
        panel = QWidget()
        panel.setVisible(False)
        form = QFormLayout(panel)
        self.fields = {}
        labels = {"telemetry_db_target_mib": "Database target", "telemetry_wal_target_mib": "WAL target",
                  "telemetry_min_free_mib": "Minimum free space"}
        for key, low, high in TELEMETRY_STORAGE_RANGES:
            spin = _ClickNumber()
            spin.setRange(low, high)
            spin.setSuffix(" MiB")
            spin.setValue(getattr(config, key))
            self.fields[key] = spin
            form.addRow(labels[key], spin)
        scope = QLabel("The database is shared with the separate remediation journal. These are telemetry "
                       "admission targets, not an OS quota or guaranteed response reserve. No database, WAL, "
                       "recorded history or recovery copy is automatically deleted here.")
        scope.setWordWrap(True)
        form.addRow(scope)
        toggle.toggled.connect(panel.setVisible)
        toggle.toggled.connect(lambda enabled: toggle.setArrowType(Qt.DownArrow if enabled else Qt.RightArrow))
        layout.addWidget(panel)
        actions = QHBoxLayout()
        self.block_button = QPushButton("Block for this run")
        self.allow_button = QPushButton("Allow within targets")
        self.apply_button = QPushButton("Apply now / retry")
        for button, callback in ((self.block_button, self._block), (self.allow_button, self._allow),
                                 (self.apply_button, self._apply)):
            button.clicked.connect(callback)
            actions.addWidget(button)
        layout.addLayout(actions)
        note = getattr(config, "_telemetry_storage_apply_note", "")
        self.result = QLabel(note if type(note) is str and len(note) <= 512 else "")
        self.usage, self.pending = QLabel(), QLabel()
        for label in (self.result, self.usage, self.pending):
            label.setWordWrap(True)
            label.setTextFormat(Qt.PlainText)
            layout.addWidget(label)
        review_row = QHBoxLayout()
        self.lane = _ClickChoice()
        self.lane.addItem("Primary queue", "primary")
        self.lane.addItem("Overflow queue", "overflow")
        self.review_button = QPushButton("Review oversized pending event…")
        self.review_button.clicked.connect(self._review_unit)
        review_row.addWidget(self.lane)
        review_row.addWidget(self.review_button)
        layout.addLayout(review_row)
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    def refresh(self):
        snapshot = telemetry_storage_snapshot(self._recorder)
        self.usage.setText(telemetry_storage_usage(snapshot))
        self.pending.setText(telemetry_pending_text(snapshot))
        self.review_button.setEnabled(self._recorder is not None and self._review_dialog is None)

    def write_candidate(self, candidate):
        candidate.telemetry_storage_blocked = self.blocked.isChecked()
        for key, spin in self.fields.items():
            setattr(candidate, key, spin.value())
        candidate.validate_telemetry_storage_settings()

    def _apply(self):
        values = {key: spin.value() for key, spin in self.fields.items()}
        values["telemetry_storage_blocked"] = self.blocked.isChecked()
        result = apply_telemetry_storage_policy(SimpleNamespace(**values), self._recorder,
                                                note_target=self._config)
        self.result.setText(_apply_text(result))
        self.refresh()

    def _block(self):
        self.blocked.setChecked(True)
        self._apply()

    def _allow(self):
        self.blocked.setChecked(False)
        self._apply()

    def _review_unit(self):
        if self._closed or self._review_dialog is not None:
            return
        lane = self.lane.currentData()
        try:
            review = self._recorder.held_unit_review(lane)
            valid = (type(review) is dict and type(review.get("schema")) is int and review["schema"] == 1
                     and review.get("available") is True and review.get("discard_allowed") is True
                     and review.get("reason_code") == "unit_too_large"
                     and review.get("volatile") is True and review.get("in_flight") is False
                     and review.get("lane") == lane and type(review.get("event_count")) is int
                     and review["event_count"] == 1 and type(review.get("token")) is str
                     and re.fullmatch(r"[0-9a-f]{32}", review["token"]) is not None
                     and all(_uint(review.get(key)) is not None for key in
                             ("policy_generation", "worker_generation", "pending_generation"))
                     and (review.get("serialized_bytes") is None or _uint(review["serialized_bytes"]) is not None))
        except Exception:
            valid = False
        if not valid:
            self.result.setText("No discardable oversized event is currently available for this lane; review cached status.")
            return
        selected = {key: review[key] for key in
                    ("lane", "token", "policy_generation", "worker_generation", "pending_generation")}
        size = review.get("serialized_bytes")
        size_text = f"Last measured serialized size: {size} bytes. " if size is not None else "Serialized size unavailable. "
        dialog = QMessageBox(QMessageBox.Warning, "Discard one unpersisted telemetry event?",
            size_text + "This queued copy exceeds the bounded admission unit and is held in memory. "
            "Discarding removes this copy and can lose unrecorded evidence; another subscriber or an earlier "
            "uncertain write may already hold a copy. Recorded database history, remediation receipts, replay "
            "files and recovery copies are preserved. A changed or in-flight queued copy cannot be discarded.",
            QMessageBox.Yes | QMessageBox.No, self)
        dialog.setDefaultButton(QMessageBox.No)
        dialog.setEscapeButton(QMessageBox.No)
        dialog.setTextFormat(Qt.PlainText)
        dialog.setWindowModality(Qt.NonModal)
        dialog.setProperty("_angerona_no_reveal", True)
        self._review_dialog = dialog
        def finished(choice):
            self._review_dialog = None
            if not self._closed and choice == QMessageBox.Yes:
                try:
                    outcome = self._recorder.discard_held_unit(**selected)
                    accepted = (type(outcome) is dict and type(outcome.get("schema")) is int
                                and outcome["schema"] == 1 and outcome.get("accepted") is True
                                and type(outcome.get("discarded_events")) is int
                                and outcome["discarded_events"] == 1)
                except Exception:
                    accepted = False
                self.result.setText("The reviewed queued copy was discarded; its coverage gap remains visible."
                                    if accepted else "Discard was not verified; the reviewed event may have changed. Refresh and review again.")
            dialog.deleteLater()
            if not self._closed:
                self.refresh()
        dialog.finished.connect(finished)
        dialog.show()
        self.refresh()

    def closeEvent(self, event):
        self._closed = True
        self._timer.stop()
        if self._review_dialog is not None:
            self._review_dialog.reject()
        super().closeEvent(event)


class TelemetryStorageWarningController(QObject):
    """One nonmodal notice per reason/policy generation, from cached values only."""
    _NOTICE = "storage:telemetry"

    def __init__(self, config, manager, parent, open_settings, *, notifications=None):
        super().__init__(parent)
        self._config, self._recorder = config, getattr(manager, "recorder", None)
        self._open_settings = open_settings
        self._notifications = notifications
        self._warning = None
        self._warning_key = None
        self._acknowledged = deque(maxlen=64)
        self._closed = False
        self._timer = QTimer(self)
        self._timer.setInterval(30_000)
        self._timer.timeout.connect(self.poll)
        self._timer.start()
        QApplication.instance().aboutToQuit.connect(self.close)

    def _state(self):
        snapshot = telemetry_storage_snapshot(self._recorder)
        pending = getattr(self._config, "_telemetry_storage_policy_pending", False) is True
        category = "policy_unverified" if pending else telemetry_storage_warning(snapshot)
        generation = snapshot["policy_generation"] if snapshot is not None else -1
        key = (category, generation) if category else None
        if self._notifications is not None and key is not None:
            key += tuple(getattr(self._config, name, None) for name in (
                "telemetry_storage_blocked", "telemetry_db_target_mib",
                "telemetry_wal_target_mib", "telemetry_min_free_mib"))
        return snapshot, pending, key

    def poll(self):
        if self._closed:
            return
        snapshot, pending, key = self._state()
        if self._notifications is not None:
            if key is None or key in self._acknowledged:
                self._notifications.remove(self._NOTICE)
            else:
                self._notifications.upsert(
                    self._NOTICE, "Telemetry storage needs review",
                    self._review_text(snapshot, pending), lambda: self._review(key))
            return
        if key is not None and key not in self._acknowledged and self._warning is None:
            self._acknowledged.append(key)
            self._show_review(snapshot, pending, key)

    def _review(self, expected):
        if self._closed:
            return
        snapshot, pending, key = self._state()
        if key != expected or key in self._acknowledged:
            self.poll()
            return
        if self._warning is not None:
            if self._warning_key == key:
                if self._warning.isMinimized():
                    self._warning.showNormal()
                self._warning.raise_()
                self._warning.activateWindow()
                return
            self._warning.reject()
        self._show_review(snapshot, pending, key)

    def _review_text(self, snapshot, pending):
        note = getattr(self._config, "_telemetry_storage_apply_note", "") if pending else ""
        if type(note) is not str or len(note) > 512:
            note = "Live policy application is unverified."
        return (note + ("\n\n" if note else "") + telemetry_storage_usage(snapshot) + "\n\n"
            + telemetry_pending_text(snapshot) + "\n\nBlock or review Allow / change targets in System settings. "
            "Storage holds do not block the dashboard or STOP. The separate remediation writer shares the "
            "database; these targets are not an OS quota or guaranteed response reserve.")

    def _show_review(self, snapshot, pending, key):
        dialog = QMessageBox(QMessageBox.Warning, "Angerona telemetry storage needs review",
            self._review_text(snapshot, pending), parent=self.parent())
        block = dialog.addButton("Block for this run", QMessageBox.RejectRole)
        change = dialog.addButton("Allow / change targets…", QMessageBox.ActionRole)
        retry = dialog.addButton("Retry saved policy", QMessageBox.ActionRole) if pending else None
        keep = dialog.addButton("Keep current choice", QMessageBox.AcceptRole)
        dialog.setDefaultButton(block)
        dialog.setEscapeButton(keep)
        dialog.setTextFormat(Qt.PlainText)
        dialog.setWindowModality(Qt.NonModal)
        dialog.setProperty("_angerona_no_reveal", True)
        self._warning = dialog
        self._warning_key = key

        def finished(_result):
            clicked = dialog.clickedButton()
            self._warning = None
            self._warning_key = None
            dialog.deleteLater()
            if self._closed:
                return
            latest = None
            if self._notifications is not None:
                latest, _, current_key = self._state()
                if current_key != key:
                    self.poll()
                    return
                if clicked is not None and clicked is not change:
                    self._acknowledged.append(key)
                    self._notifications.remove(self._NOTICE)
            if clicked is block:
                if self._notifications is None:
                    latest = telemetry_storage_snapshot(self._recorder)
                if latest is not None and latest["configured"]:
                    policy = {"blocked": True, **{name: latest[name] for name in
                              ("db_target_bytes", "wal_target_bytes", "min_free_bytes")}}
                else:
                    try:
                        policy = telemetry_storage_policy_values(self._config)
                        policy["blocked"] = True
                    except (ValueError, TypeError):
                        policy = None
                result = apply_telemetry_storage_values(self._recorder, policy, note_target=self._config)
                if result["accepted"] is not True:
                    self._open_settings("System")
            elif retry is not None and clicked is retry:
                result = apply_telemetry_storage_policy(self._config, self._recorder)
                if result["accepted"] is not True:
                    self._open_settings("System")
            elif clicked is change:
                self._open_settings("System")
        dialog.finished.connect(finished)
        dialog.show()

    def close(self, *_args):
        self._closed = True
        self._timer.stop()
        if self._notifications is not None:
            self._notifications.remove(self._NOTICE)
        if self._warning is not None:
            self._warning.reject()
