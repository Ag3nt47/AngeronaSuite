"""UGCAP operator panel. Vault, TPM and filesystem work stays on its worker.

The password widget is cleared before each queued operation. The worker must
copy the mutable challenge before returning; this view then wipes its copy.
Python/Qt cannot promise erasure of every temporary string or OS buffer.
"""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFileDialog, QFormLayout, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QScrollArea,
    QSpinBox, QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)


_MAX_DIFF_ROWS = 500
_MAX_RESTORE_PATHS = 128
_BINARY_SUFFIXES = (".exe", ".dll", ".pyd", ".sys", ".so", ".dylib")
_LIMITS = (
    "UGCAP verifies the protected scopes reported by the engine against a baseline that you "
    "explicitly initialize. A new baseline records the current installation; it does not prove "
    "that the installation was clean. Review the baseline's origin before trusting it.\n\n"
    "Attach your secondary offline medium yourself, choose the vault file, and enter your "
    "passcode for each operation. Remove the medium after the operation finishes. Angerona "
    "does not mount, eject, or keep an offline copy attached for you. A mounted drive remains "
    "visible to a compromised kernel.\n\n"
    "Hardware protection requires the engine's real supported TPM provider. There is no "
    "software-key fallback. Hardware or BLAKE3 coverage that is unavailable must be resolved "
    "before treating verification as complete. An authenticated hash chain alone does not "
    "provide an independent external witness against rollback.\n\n"
    "Restore requires a complete drift report and explicit selection of missing or modified "
    "paths from that exact report. Added files and read errors are review-only. Binary recovery "
    "may be deferred to an offline recovery environment. A source replacement can require "
    "a restart; an already running process is not repaired by replacing its file.\n\n"
    "The passcode is not written to settings, status, or logs by this panel. Qt and Python "
    "memory erasure is best effort; temporary strings, OS buffers, privileged memory inspection, "
    "and a compromised runtime can defeat it. UGCAP does not guarantee rootkit prevention "
    "or protection from a hostile kernel, firmware, or hardware."
)


def _text(value, limit=1000) -> str:
    return str(value if value is not None else "").replace("\x00", "")[:limit]


def _label(text="") -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


def _pretty(value, limit=20_000) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)[:limit]


def _same_path(left, right) -> bool:
    if not isinstance(left, str) or not isinstance(right, str) or not left or not right:
        return False
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


class UGCAPPage(QWidget):
    lock_state_changed = Signal(bool)

    def __init__(self, manager, config, bus=None, parent=None):
        super().__init__(parent)
        self.manager, self.config, self.bus = manager, config, bus
        self._closed = False
        self._workspace_locked = bool(getattr(manager, "ugcap_paused", False))
        self._report: dict = {}
        self._report_key = None
        self._diff_rows: list[dict] = []
        self._awaiting_report: str | None = None
        self._settings_dirty = False
        self._pending_settings: dict | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(3_000)
        self._timer.timeout.connect(self.refresh)
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        title = _label("UGCAP · Hardware-backed integrity and offline recovery")
        title.setObjectName("SectionTitle")
        root.addWidget(title)
        self.gate_status = _label()
        root.addWidget(self.gate_status)
        self._update_gate_banner()
        self.status = _label("Open UGCAP to view the engine's cached verification state.")
        root.addWidget(self.status)
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self._build_vault_tab()
        self._build_settings_tab()
        self._build_readiness_tab()
        self._build_limits_tab()
        self._update_availability()

    def _module(self):
        modules = getattr(self.manager, "modules", {})
        return modules.get("UGCAP Integrity Guard") if isinstance(modules, Mapping) else None

    def _build_vault_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        note = _label("Attach your offline medium, choose its vault file, and enter the passcode. "
                      "Choosing a path does not create a baseline. Remove the medium after work completes.")
        layout.addWidget(note)
        paths = QHBoxLayout()
        self.vault_path = QLineEdit(_text(getattr(self.config, "ugcap_vault_path", ""), 4096))
        self.vault_path.setMaxLength(4096)
        self.vault_path.setPlaceholderText("Absolute vault FILE path on your attached secondary medium")
        self.vault_path.textChanged.connect(self._path_changed)
        paths.addWidget(self.vault_path, 1)
        self.open_vault_button = QPushButton("Open vault…")
        self.open_vault_button.clicked.connect(self._choose_existing_vault)
        paths.addWidget(self.open_vault_button)
        self.new_vault_button = QPushButton("New vault path…")
        self.new_vault_button.clicked.connect(self._choose_new_vault)
        paths.addWidget(self.new_vault_button)
        layout.addLayout(paths)
        challenge = QHBoxLayout()
        self.passcode = QLineEdit()
        self.passcode.setEchoMode(QLineEdit.EchoMode.Password)
        self.passcode.setMaxLength(1024)
        self.passcode.setPlaceholderText("Passcode · cleared when queued, hidden, or locked")
        self.passcode.setAccessibleName("UGCAP passcode")
        challenge.addWidget(self.passcode, 1)
        self.verify_button = QPushButton("Verify now")
        self.verify_button.clicked.connect(self._verify)
        challenge.addWidget(self.verify_button)
        self.initialize_button = QPushButton("Initialize baseline")
        self.initialize_button.setToolTip("Explicitly record the current protected scopes into a new vault; this is not a clean-install attestation.")
        self.initialize_button.clicked.connect(self._initialize)
        challenge.addWidget(self.initialize_button)
        self.lock_button = QPushButton("Lock workspace")
        self.lock_button.clicked.connect(self._lock)
        challenge.addWidget(self.lock_button)
        layout.addLayout(challenge)
        self.report_summary = _label("No reviewed verification report is available.")
        layout.addWidget(self.report_summary)
        self.diff_table = QTableWidget(0, 4)
        self.diff_table.setHorizontalHeaderLabels(("Restore", "Change", "Path", "Recovery / error"))
        self.diff_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.diff_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.diff_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.diff_table.verticalHeader().setVisible(False)
        self.diff_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.diff_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for column, width in enumerate((70, 100, 250, 220)):
            self.diff_table.setColumnWidth(column, width)
        self.diff_table.setWordWrap(False)
        self.diff_table.setMinimumWidth(0)
        self.diff_table.setMinimumHeight(100)
        self.diff_table.itemChanged.connect(self._selection_changed)
        layout.addWidget(self.diff_table, 1)
        actions = QHBoxLayout()
        self.restore_button = QPushButton("Restore selected reviewed paths")
        self.restore_button.setEnabled(False)
        self.restore_button.clicked.connect(self._restore)
        actions.addWidget(self.restore_button)
        self.selection_status = _label("Select individual missing or modified paths from a complete drift report.")
        actions.addWidget(self.selection_status, 1)
        layout.addLayout(actions)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(page)
        self.tabs.addTab(scroll, "Vault / Review")

    def _build_settings_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.enabled = QCheckBox("Enable UGCAP scheduled integrity challenges")
        self.enabled.setChecked(bool(getattr(self.config, "ugcap_enabled", False)))
        self.enabled.toggled.connect(self._mark_settings_dirty)
        layout.addWidget(self.enabled)
        form = QFormLayout()
        self.cadence = QSpinBox()
        self.cadence.setRange(1, 8760)
        self.cadence.setSuffix(" hours")
        self.cadence.setValue(int(getattr(self.config, "ugcap_cadence_hours", 168)))
        self.cadence.valueChanged.connect(self._mark_settings_dirty)
        form.addRow("Challenge interval:", self.cadence)
        self.key_name = QLineEdit(_text(getattr(self.config, "ugcap_key_name", "Angerona.UGCAP.v1"), 200))
        self.key_name.setMaxLength(200)
        self.key_name.textChanged.connect(self._mark_settings_dirty)
        form.addRow("TPM key name:", self.key_name)
        layout.addLayout(form)
        self.lockdown = QCheckBox("Request local-host isolation when integrity divergence is detected")
        self.lockdown.setChecked(bool(getattr(self.config, "ugcap_lockdown", True)))
        self.lockdown.toggled.connect(self._mark_settings_dirty)
        layout.addWidget(self.lockdown)
        layout.addWidget(_label("A scheduled check requires your challenge: attach the vault medium and "
                                "enter the passcode when prompted. Scheduling does not store a passcode "
                                "or silently unlock an offline vault."))
        self.apply_settings_button = QPushButton("Apply UGCAP settings")
        self.apply_settings_button.clicked.connect(self._save_settings)
        layout.addWidget(self.apply_settings_button)
        self.provision_button = QPushButton("Provision hardware TPM key")
        self.provision_button.setToolTip("Explicitly request provisioning of the named supported TPM key. No software fallback is available.")
        self.provision_button.clicked.connect(self._provision_hardware)
        layout.addWidget(self.provision_button)
        layout.addWidget(_label("TPM provisioning is separate from baseline initialization. "
                                "Readiness and failures are reported by the engine. No hardware "
                                "operation runs merely by opening this panel."))
        self.schedule_status = _label("Challenge schedule status has not been reported.")
        layout.addWidget(self.schedule_status)
        layout.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(page)
        self.tabs.addTab(scroll, "Schedule / Hardware")

    def _build_readiness_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.readiness_status = _label("TPM, BLAKE3, and OS coverage readiness must be reported by the engine.")
        layout.addWidget(self.readiness_status)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Coverage, hardware status, protected scopes, and recovery outcomes appear here.")
        layout.addWidget(self.details, 1)
        self.tabs.addTab(page, "Readiness / Results")

    def _build_limits_tab(self):
        details = QPlainTextEdit()
        details.setReadOnly(True)
        details.setPlainText(_LIMITS)
        self.tabs.addTab(details, "How it works / Limits")

    def _update_gate_banner(self):
        self.gate_status.setText(
            "Workspace locked · complete the authorized UGCAP challenge to review recovery. "
            "Settings and Stop remain accessible."
            if self._workspace_locked else
            "Workspace gate open · UGCAP actions require your attached vault and explicit challenge."
        )

    def _update_availability(self):
        available = self._module() is not None
        for button in (self.verify_button, self.initialize_button, self.lock_button,
                       self.provision_button, self.apply_settings_button):
            button.setEnabled(available)
        if not available:
            self.status.setText("UGCAP Integrity Guard is unavailable. Settings cannot activate a missing engine.")
        self._selection_changed()

    def _command(self, name, *args, **kwargs):
        action = getattr(self._module(), name, None)
        if not callable(action):
            return False
        try:
            return action(*args, **kwargs)
        except Exception:
            # Never interpolate a challenge-bearing exception into the GUI.
            return False

    def _valid_vault_path(self):
        value = self.vault_path.text().strip()
        if (not value or not Path(value).is_absolute() or value.startswith(("\\\\", "//"))
                or any(ord(ch) < 32 for ch in value)):
            self.status.setText("Choose an absolute vault file path on your attached medium.")
            return None
        return value

    def _queue_challenge(self, method, *args):
        value = self.passcode.text()
        self.passcode.clear()
        if not value:
            self.status.setText("Enter the vault passcode for this operation.")
            return False
        challenge = bytearray(value, "utf-8")
        del value
        try:
            # Queue methods synchronously copy this bytearray before returning.
            return self._command(method, *args[:1], challenge, *args[1:])
        finally:
            challenge[:] = b"\x00" * len(challenge)
            challenge.clear()

    def _verify(self):
        path = self._valid_vault_path()
        if path is None:
            self.passcode.clear()
            return
        if self._queue_challenge("queue_verify", path):
            self._awaiting_report = _text(self._report.get("report_id", ""))
            self.status.setText("Verification queued. The worker will report the hardware and full diff outcome.")
            self._selection_changed()
        else:
            self.status.setText("Verification was not queued. Re-enter the passcode and check engine readiness.")

    def _initialize(self):
        path = self._valid_vault_path()
        if path is None:
            self.passcode.clear()
            return
        if self._queue_challenge("queue_initialize", path):
            self._awaiting_report = _text(self._report.get("report_id", ""))
            self.status.setText("Baseline initialization queued for this explicit vault path. Review the worker result before trusting it.")
            self._selection_changed()
        else:
            self.status.setText("Initialization was not queued. Re-enter the passcode and check TPM, path, and engine readiness.")

    def _lock(self):
        self.passcode.clear()
        if self._command("queue_lock"):
            self._awaiting_report = _text(self._report.get("report_id", ""))
            self.status.setText("Workspace lock queued. Unlocked vault material will be discarded by the worker.")
            self._selection_changed()
        else:
            self.status.setText("Workspace lock was not queued. Check engine availability.")

    def _choose_existing_vault(self):
        selected, _ = QFileDialog.getOpenFileName(self, "Choose an existing UGCAP vault file",
                                                self.vault_path.text(), "UGCAP vault (*.ugcap);;All files (*)")
        if selected:
            self.vault_path.setText(selected)

    def _choose_new_vault(self):
        selected, _ = QFileDialog.getSaveFileName(self, "Choose a NEW UGCAP vault file path",
                                                self.vault_path.text() or "angerona.ugcap",
                                                "UGCAP vault (*.ugcap);;All files (*)",
                                                options=QFileDialog.Option.DontConfirmOverwrite)
        if selected:
            self.vault_path.setText(selected)
            self.status.setText("New vault path selected. Its directory must already exist; initialize explicitly to create a baseline.")

    def _path_changed(self, *_args):
        if hasattr(self, "passcode"):
            self.passcode.clear()
        self._mark_settings_dirty()
        if hasattr(self, "restore_button"):
            self._selection_changed()

    def _mark_settings_dirty(self, *_args):
        self._settings_dirty = True
        self._pending_settings = None

    def _save_settings(self):
        self.passcode.clear()
        settings = {"ugcap_enabled": self.enabled.isChecked(),
                    "ugcap_cadence_hours": self.cadence.value(),
                    "ugcap_vault_path": self.vault_path.text().strip(),
                    "ugcap_key_name": self.key_name.text().strip(),
                    "ugcap_lockdown": self.lockdown.isChecked()}
        result = self._command("configure_settings", **settings)
        queued = result.get("queued", False) if isinstance(result, dict) else bool(result)
        if queued:
            self._pending_settings = settings
            self.status.setText("UGCAP settings queued. No passcode is stored and no vault operation was requested.")
        else:
            self.status.setText("UGCAP settings were not queued. Check the engine and selected values.")

    def _provision_hardware(self):
        self.passcode.clear()
        name = self.key_name.text().strip()
        if not name:
            self.status.setText("Enter the hardware key name before requesting TPM provisioning.")
            return
        if self._command("queue_provision_hardware", name):
            self.status.setText("TPM key provisioning queued. Hardware readiness remains unverified until the worker reports success.")
        else:
            self.status.setText("TPM provisioning was not queued. Check engine readiness.")

    def _restorable_report(self):
        coverage = self._report.get("coverage") or {}
        return (self._module() is not None and self._awaiting_report is None
                and self._report.get("status") == "drift"
                and isinstance(coverage, dict) and coverage.get("complete") is True
                and bool(self._report.get("report_id")) and bool(self._report.get("generation"))
                and _same_path(self._report.get("vault_path"), self.vault_path.text().strip()))

    def _checked_paths(self):
        selected = []
        for index, row in enumerate(self._diff_rows):
            item = self.diff_table.item(index, 0)
            if row["restorable"] and item is not None and item.checkState() == Qt.CheckState.Checked:
                selected.append(row["path"])
        return list(dict.fromkeys(selected))

    def _selection_changed(self, *_args):
        count = len(self._checked_paths())
        valid = self._restorable_report()
        self.restore_button.setEnabled(valid and 0 < count <= _MAX_RESTORE_PATHS)
        if self._awaiting_report is not None:
            text = "Awaiting a new verification report; prior diff selections cannot authorize recovery."
        elif not valid:
            text = "Restore requires a complete drift report for this exact vault path."
        elif count > _MAX_RESTORE_PATHS:
            text = f"Select at most {_MAX_RESTORE_PATHS} paths for one reviewed recovery batch."
        else:
            text = f"{count} reviewed path(s) selected. Binary files may require offline recovery."
        self.selection_status.setText(text)

    def _restore(self):
        paths = self._checked_paths()
        if not self._restorable_report() or not 0 < len(paths) <= _MAX_RESTORE_PATHS:
            self.passcode.clear()
            self.status.setText("Review a complete current diff and check individual missing or modified paths before restore.")
            return
        report_id = self._report["report_id"]
        path = self.vault_path.text().strip()
        if self._queue_challenge("queue_restore", path, paths, report_id):
            self._awaiting_report = report_id
            self.status.setText("Selected-path recovery queued against this exact report. Verify again before another restore and review restart/offline requirements.")
            self._selection_changed()
        else:
            self.status.setText("Recovery was not queued. Re-enter the passcode and obtain a fresh complete diff if required.")

    def _apply_report(self, report):
        if not isinstance(report, dict):
            report = {}
        self._report = report
        changes = report.get("changes") or {}
        if not isinstance(changes, dict):
            changes = {}
        rows = []
        total = 0
        for kind in ("modified", "missing", "added", "read_errors"):
            values = changes.get(kind) or []
            if not isinstance(values, (list, tuple)):
                continue
            total += len(values)
            for value in values[:_MAX_DIFF_ROWS - len(rows)]:
                path = value.get("path", "") if isinstance(value, dict) else value
                if not isinstance(path, str) or not path:
                    continue
                error = value.get("error", "") if isinstance(value, dict) else ""
                binary = path.lower().endswith(_BINARY_SUFFIXES)
                note = ("Requires offline recovery" if binary and kind in {"modified", "missing"}
                        else "Review only; no automatic deletion" if kind == "added"
                        else _text(error, 500) if kind == "read_errors" else "Verify again after recovery")
                rows.append({"kind": kind, "path": path, "note": note,
                             "restorable": kind in {"modified", "missing"}})
        report_id = _text(report.get("report_id", ""), 200)
        if self._awaiting_report is not None and report_id and report_id != self._awaiting_report:
            self._awaiting_report = None
        key = (report_id, report.get("generation"), report.get("vault_path"), report.get("status"),
               tuple((row["kind"], row["path"], row["note"]) for row in rows))
        if key != self._report_key:
            self._report_key = key
            self._diff_rows = rows
            self.diff_table.blockSignals(True)
            try:
                self.diff_table.setRowCount(len(rows))
                for index, row in enumerate(rows):
                    check = QTableWidgetItem()
                    check.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
                                   | (Qt.ItemFlag.ItemIsUserCheckable if row["restorable"] else Qt.ItemFlag.NoItemFlags))
                    if row["restorable"]:
                        check.setCheckState(Qt.CheckState.Unchecked)
                    self.diff_table.setItem(index, 0, check)
                    for column, value in enumerate((row["kind"], row["path"], row["note"]), start=1):
                        item = QTableWidgetItem(_text(value, 4096))
                        item.setToolTip(_text(value, 4096))
                        self.diff_table.setItem(index, column, item)
            finally:
                self.diff_table.blockSignals(False)
        if report_id:
            coverage = report.get("coverage") or {}
            complete = coverage.get("complete") is True if isinstance(coverage, dict) else False
            self.report_summary.setText(
                f"Report: {report_id} · {_text(report.get('status', 'unknown'), 100)} · "
                f"Coverage {'complete' if complete else 'incomplete'} · {total} change record(s). "
                f"Showing {len(rows)} (limit {_MAX_DIFF_ROWS}); a new report clears checked paths."
            )
        else:
            self.report_summary.setText("No verification report. Initialize only a trusted baseline, then verify explicitly.")
        self._selection_changed()

    def refresh(self):
        if self._closed or not self.isVisible():
            return
        self._update_availability()
        module = self._module()
        if module is None:
            return
        try:
            snapshot = module.dashboard_snapshot()
        except Exception:
            self.status.setText("UGCAP cached status is unavailable. The previous report is retained.")
            return
        if not isinstance(snapshot, dict):
            return
        workspace_locked = snapshot.get("workspace_locked", self._workspace_locked) is True
        if workspace_locked != self._workspace_locked:
            self._workspace_locked = workspace_locked
            self.passcode.clear()
            self._update_gate_banner()
            self.lock_state_changed.emit(workspace_locked)
        report = snapshot.get("report", snapshot.get("last_report", {}))
        self._apply_report(report)
        settings = snapshot.get("settings")
        if isinstance(settings, dict):
            if self._pending_settings and all(settings.get(key) == value for key, value in self._pending_settings.items()):
                self._settings_dirty = False
                self._pending_settings = None
            if not self._settings_dirty:
                fields = (("ugcap_enabled", self.enabled, "setChecked"),
                          ("ugcap_cadence_hours", self.cadence, "setValue"),
                          ("ugcap_vault_path", self.vault_path, "setText"),
                          ("ugcap_key_name", self.key_name, "setText"),
                          ("ugcap_lockdown", self.lockdown, "setChecked"))
                for name, widget, setter in fields:
                    if name in settings:
                        if name == "ugcap_vault_path" and widget.text() != settings[name]:
                            self.passcode.clear()
                        previous = widget.blockSignals(True)
                        getattr(widget, setter)(settings[name])
                        widget.blockSignals(previous)
        self._selection_changed()
        hardware = snapshot.get("hardware") or {}
        coverage = snapshot.get("coverage") or {}
        readiness = {"hardware": hardware, "coverage": coverage}
        for name in ("recovery", "result", "error", "locked", "initialized", "limits",
                     "protected_scopes", "exclusions", "created_at", "restart_required"):
            if name in snapshot:
                readiness[name] = snapshot[name]
            elif isinstance(report, dict) and name in report:
                readiness[name] = report[name]
        self.details.setPlainText(_pretty(readiness))
        self.readiness_status.setText("Engine-reported TPM / BLAKE3 / OS coverage and recovery state. "
                                      "Unavailable or incomplete coverage does not certify integrity.")
        schedule = snapshot.get("schedule", snapshot.get("challenge", snapshot.get("recovery", {})))
        self.schedule_status.setText("Challenge / schedule: " + _text(schedule, 1500))
        state = _text(snapshot.get("status", getattr(module, "status", "available")), 300)
        error = _text(snapshot.get("error", ""), 300)
        self.status.setText(f"UGCAP: {state}." + (" Worker reports: " + error if error else ""))

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        if not self._closed:
            self.refresh()
            self._timer.start()

    def hideEvent(self, event):  # noqa: N802
        self._timer.stop()
        self.passcode.clear()
        super().hideEvent(event)

    def closeEvent(self, event):  # noqa: N802
        self._closed = True
        self._timer.stop()
        self.passcode.clear()
        super().closeEvent(event)
