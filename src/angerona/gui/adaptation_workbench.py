"""Operator workbench for safe, local host adaptation."""
from __future__ import annotations

import json
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenuBar,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from angerona.core.host_adaptation import (
    AdaptationPlan,
    HostAdaptationService,
    PROFILES,
)


_SEVERITY_COLORS = {
    "critical": "#f87171",
    "high": "#fb923c",
    "medium": "#facc15",
    "low": "#60a5fa",
}

_SEVERITY_SORT_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class _TypedSortItem(QTableWidgetItem):
    """Display human-readable text while sorting by a typed stable value."""

    def __init__(self, text: str, sort_value: object) -> None:
        super().__init__(text)
        self._sort_value = sort_value

    def __lt__(self, other: QTableWidgetItem) -> bool:
        if isinstance(other, _TypedSortItem):
            return self._sort_value < other._sort_value
        return super().__lt__(other)


class _InfoPanel(QFrame):
    def __init__(self, title: str, text: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("AdaptationInfoPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 11, 14, 11)
        heading = QLabel(title)
        heading.setStyleSheet("font-weight:700; color:#67e8f9;")
        body = QLabel(text)
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(heading)
        layout.addWidget(body)


class AdaptationWorkbench(QDialog):
    """Complete audit, profile, sandbox, and feedback surface.

    Potentially slow host inspection and every broker call runs off the GUI
    thread. Profile mutation and rollback cannot be dismissed while active.
    """

    _task_finished = Signal(str, object, object)

    def __init__(
        self,
        service: HostAdaptationService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self._latest_report: dict[str, Any] | None = None
        self._latest_plan: AdaptationPlan | None = None
        self._busy_task = ""
        # Persisted views can be refreshed by both operator actions and the
        # dashboard context monitor.  Retain small, bounded row signatures so
        # an unchanged poll does not discard and recreate hundreds of Qt items.
        self._view_signatures: dict[str, tuple[Any, ...]] = {}
        self.setWindowTitle("Adaptation — Adapt to Host")
        self.setMinimumSize(920, 650)
        self.resize(1160, 780)
        self.setSizeGripEnabled(True)

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 12)
        root.setSpacing(9)
        root.setMenuBar(self._build_menu())

        heading_row = QHBoxLayout()
        heading = QLabel("ADAPTATION")
        heading.setStyleSheet("font-size:22px; font-weight:800; color:#67e8f9;")
        subtitle = QLabel("Adapt to Host  ·  local, reversible, operator-controlled")
        subtitle.setStyleSheet("color:#94a3b8;")
        heading_row.addWidget(heading)
        heading_row.addWidget(subtitle)
        heading_row.addStretch(1)
        self.adapt_host_button = QPushButton("AUTO ADAPT…")
        self.adapt_host_button.setObjectName("Primary")
        self.adapt_host_button.setToolTip(
            "Choose a safe intent profile, preview it, test it, and adapt this host."
        )
        self.adapt_host_button.clicked.connect(self._show_auto_adapt)
        heading_row.addWidget(self.adapt_host_button)
        self.busy_label = QLabel("Ready")
        self.busy_label.setStyleSheet("color:#5eead4; font-weight:600;")
        heading_row.addWidget(self.busy_label)
        root.addLayout(heading_row)

        status = QHBoxLayout()
        self.baseline_status = QLabel("Baseline: checking…")
        self.recovery_status = QLabel("Recovery baseline: checking…")
        self.risk_status = QLabel("Drift risk: —")
        self.context_status = QLabel("Context: not sampled")
        self.breaker_status_label = QLabel("Circuit breaker: checking…")
        for label in (
            self.baseline_status, self.recovery_status, self.risk_status,
            self.context_status, self.breaker_status_label,
        ):
            label.setStyleSheet(
                "padding:6px 10px; border:1px solid #334155; border-radius:6px; "
                "background:#0f172a; color:#cbd5e1;"
            )
            status.addWidget(label, 1)
        root.addLayout(status)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._build_overview_tab(), "Overview")
        self.tabs.addTab(self._build_audit_tab(), "Audit + Drift")
        self.tabs.addTab(self._build_exceptions_tab(), "Exceptions + Feedback")
        self.adapt_tab_index = self.tabs.addTab(self._build_profiles_tab(), "Adapt Host")
        self.tabs.addTab(self._build_sandbox_tab(), "Sandbox")
        self.tabs.addTab(self._build_automation_tab(), "Automation")
        self.tabs.addTab(self._build_activity_tab(), "Activity")
        root.addWidget(self.tabs, 1)

        footer = QHBoxLayout()
        self.footer_detail = QLabel(
            "No host change occurs until an exact plan is previewed and confirmed."
        )
        self.footer_detail.setStyleSheet("color:#94a3b8;")
        self.footer_detail.setWordWrap(True)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        footer.addWidget(self.footer_detail, 1)
        footer.addWidget(close)
        root.addLayout(footer)

        self._task_finished.connect(self._on_task_finished)
        self._load_persisted_views()

    # ── Menus and overview ────────────────────────────────────────────────
    def _action(self, text: str, slot: Callable[[], None]) -> QAction:
        action = QAction(text, self)
        action.triggered.connect(slot)
        return action

    def _build_menu(self) -> QMenuBar:
        menu = QMenuBar(self)
        file_menu = menu.addMenu("File")
        file_menu.addAction(self._action("Export latest audit as JSON…", self._export_json))
        file_menu.addAction(self._action("Export latest audit as CSV…", self._export_csv))
        file_menu.addSeparator()
        file_menu.addAction(self._action("Close", self.close))

        audit_menu = menu.addMenu("Audit")
        audit_menu.addAction(self._action("Run deep audit", self._run_audit))
        audit_menu.addAction(self._action("Save current audit as golden baseline…", self._save_baseline))
        audit_menu.addAction(self._action("Pin selected drift exception…", self._pin_exception))

        profile_menu = menu.addMenu("Adapt")
        profile_menu.addAction(self._action("Guided Auto Adapt…", self._show_auto_adapt))
        profile_menu.addAction(self._action("Open manual Adapt Host", self._show_adapt_host))
        profile_menu.addSeparator()
        profile_menu.addAction(self._action("Preview selected profile", self._preview_profile))
        profile_menu.addAction(self._action("Simulate selected profile", self._run_sandbox))
        profile_menu.addAction(self._action("Apply selected preview…", self._apply_profile))
        profile_menu.addAction(self._action("Roll back selected snapshot…", self._rollback_selected))

        safety_menu = menu.addMenu("Safety")
        safety_menu.addAction(self._action("Evaluate context triggers", self._evaluate_context))
        safety_menu.addAction(self._action("Reset circuit breaker…", self._reset_breaker))
        safety_menu.addAction(self._action("Refresh snapshots and activity", self._load_persisted_views))

        help_menu = menu.addMenu("Help")
        help_menu.addAction(self._action("Safety model", self._show_safety_help))
        help_menu.addAction(self._action("What each phase does", self._show_phase_help))
        return menu

    def _show_auto_adapt(self) -> None:
        """Collect intent once, then automate audit, preview, and sandbox."""
        if self._busy_task:
            QMessageBox.information(
                self,
                "Adaptation busy",
                f"{self._busy_task.replace('_', ' ').title()} is still running. "
                "Finish it before opening a new Auto Adapt request.",
            )
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Auto Adapt — choose security intent")
        dialog.setMinimumWidth(620)
        layout = QVBoxLayout(dialog)
        layout.addWidget(_InfoPanel(
            "Guided, deterministic Auto Adapt",
            "Angerona runs a fresh deep audit, builds an immutable closed-catalog plan, "
            "and tests the projected change without writing. Preview-only is the safe "
            "default. If apply is selected, one final exact-plan approval is still required.",
        ))
        form = QFormLayout()
        profile = self._profile_combo()
        form.addRow("Security intent:", profile)
        apply_after = QCheckBox("Ask to apply after the automatic review")
        apply_after.setChecked(False)
        apply_after.setToolTip(
            "Never applies silently; the final dialog includes exact commands and rollback coverage."
        )
        form.addRow("Host change:", apply_after)
        try:
            recovery_before = self.service.security_baseline_status()
        except Exception:
            recovery_before = {"available": False, "supported": True}
        capture_recovery = QCheckBox(
            "Explicitly capture the immutable firewall recovery baseline if missing"
        )
        capture_recovery.setChecked(
            bool(recovery_before.get("supported", True))
            and not bool(recovery_before.get("available"))
        )
        capture_recovery.setEnabled(bool(recovery_before.get("supported", True)))
        capture_recovery.setToolTip(
            "This is a permanent, non-replaceable recovery enrollment. It is separate "
            "from the temporary snapshot created immediately before every apply."
        )
        form.addRow("Recovery enrollment:", capture_recovery)
        layout.addLayout(form)
        coverage = QLabel(
            "Automatic phases: deep audit → collector completeness gate → immutable plan → "
            "no-write sandbox → recommendation. Emergency Lockdown is never auto-applied "
            "without its separate warning."
        )
        coverage.setWordWrap(True)
        coverage.setTextFormat(Qt.PlainText)
        layout.addWidget(coverage)
        buttons = QHBoxLayout()
        cancel = QPushButton("Cancel")
        prepare = QPushButton("Prepare automatically")
        prepare.setObjectName("Primary")
        cancel.clicked.connect(dialog.reject)
        prepare.clicked.connect(dialog.accept)
        buttons.addStretch(1)
        buttons.addWidget(cancel)
        buttons.addWidget(prepare)
        layout.addLayout(buttons)
        if dialog.exec() != QDialog.Accepted:
            return
        # A timer or another modal action can begin work while this dialog is
        # open. Never let an earlier consent screen queue behind that work.
        if self._busy_task:
            dialog.reject()
            QMessageBox.information(
                self,
                "Adaptation busy",
                f"{self._busy_task.replace('_', ' ').title()} started while Auto Adapt "
                "was open. The request was discarded; review the host again when it finishes.",
            )
            return
        profile_id = str(profile.currentData())
        # Copy consent into immutable closure values before any worker starts.
        # Later UI changes or a second dialog can therefore never broaden the
        # accepted request while its audit is running.
        apply_requested = bool(apply_after.isChecked())
        capture_recovery_requested = bool(capture_recovery.isChecked())

        def operation(
            selected_profile_id: str = profile_id,
            accepted_apply: bool = apply_requested,
            accepted_capture: bool = capture_recovery_requested,
        ) -> dict[str, Any]:
            report = self.service.audit()
            current = report.get("current")
            if not isinstance(current, dict):
                raise RuntimeError("deep audit did not return a host snapshot")
            plan = self.service.build_plan(selected_profile_id, current)
            simulation = self.service.simulate_plan(plan, current)
            relaxes = self.service._plan_relaxes_current(
                plan, current.get("firewall") or {}
            )
            recovery = self.service.security_baseline_status()
            if (
                accepted_apply
                and accepted_capture
                and not recovery.get("available")
            ):
                recovery = self.service.capture_security_baseline(approved=True)
            return {
                "report": report,
                "plan": plan,
                "simulation": simulation,
                "recovery": recovery,
                "relaxes": relaxes,
                "apply_requested": accepted_apply,
            }

        self._run_task("auto_prepare", operation)

    def _build_overview_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        start = QGroupBox("Adapt this host")
        start_layout = QHBoxLayout(start)
        start_text = QLabel(
            "Choose a protection profile, inspect every planned command, run the no-write "
            "sandbox, then explicitly approve the adaptation."
        )
        start_text.setWordWrap(True)
        start_button = QPushButton("Choose an adaptation profile…")
        start_button.setObjectName("Primary")
        start_button.clicked.connect(self._show_adapt_host)
        auto_button = QPushButton("AUTO ADAPT…")
        auto_button.setObjectName("Primary")
        auto_button.clicked.connect(self._show_auto_adapt)
        checkup_button = QPushButton("Run safe automatic checkup")
        checkup_button.clicked.connect(self._run_safe_checkup)
        start_layout.addWidget(start_text, 1)
        start_layout.addWidget(auto_button)
        start_layout.addWidget(checkup_button)
        start_layout.addWidget(start_button)
        outer.addWidget(start)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.addWidget(_InfoPanel(
            "Phase 1 · Deep audit and golden baseline",
            "Capture hardware, installed service state, listening ports, network adapters, "
            "connection context, and firewall posture. Compare it with a locally stored, "
            "digest-verified golden baseline. Known-good drift can be pinned as an exact "
            "exception and audit evidence can be exported as JSON or CSV.",
        ))
        layout.addWidget(_InfoPanel(
            "Phase 2 · Intent profiles with recovery",
            "Preview the exact closed-catalog command stack, simulate its before/after effect "
            "in the sandbox, and apply only after confirmation. Every apply first exports a "
            "Windows Firewall recovery artifact plus network context. Rollback is always "
            "available and is not blocked by the adaptation circuit breaker.",
        ))
        layout.addWidget(_InfoPanel(
            "Phase 3 · Context feedback and circuit breakers",
            "Map exact SSIDs, an active VPN, or a Public network category to an intent profile. "
            "Context automation is proposal-only: it never mutates the firewall unattended. "
            "A proposed profile must pass a fresh audit, immutable preview, no-write simulation, "
            "and exact operator approval. Dismissing a false positive creates an exception and "
            "gently lowers only that local drift category's scoring multiplier.",
        ))
        layout.addWidget(_InfoPanel(
            "Hard safety boundary",
            "Adaptation never stops services, kills processes, edits routes, disables the firewall, "
            "or runs user-authored commands. Non-Windows systems retain the full audit, drift, "
            "exception, export, and context workflow; active profile mutation is refused until a "
            "native reversible broker exists.",
        ))
        layout.addStretch(1)
        scroll.setWidget(content)
        outer.addWidget(scroll)
        return page

    def _show_adapt_host(self) -> None:
        """Reveal the guarded adaptation workflow without applying anything."""
        if not hasattr(self, "tabs") or not hasattr(self, "profile_combo"):
            return
        self.tabs.setCurrentIndex(self.adapt_tab_index)
        self.profile_combo.setFocus(Qt.OtherFocusReason)
        self.footer_detail.setText(
            "Choose a profile, preview its exact commands, test it in the sandbox, then "
            "explicitly approve Adapt Host."
        )

    # ── Audit ──────────────────────────────────────────────────────────────
    def _table(self, columns: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setStretchLastSection(True)
        table.setSortingEnabled(True)
        table.setAccessibleDescription(
            "Click a column heading to sort. Double-click a row for bounded, read-only details."
        )
        table.cellDoubleClicked.connect(
            lambda row, _column, source=table: self._show_table_detail(source, row)
        )
        return table

    def _show_table_detail(self, table: QTableWidget, row: int) -> None:
        """Inspect the immutable row payload; double-click never performs an action."""
        if row < 0 or row >= table.rowCount():
            return
        visible: dict[str, str] = {}
        raw: object = None
        for column in range(table.columnCount()):
            header = table.horizontalHeaderItem(column)
            item = table.item(row, column)
            label = header.text() if header is not None else f"column_{column + 1}"
            visible[label] = item.text()[:8192] if item is not None else ""
            if raw is None and item is not None:
                candidate = item.data(Qt.UserRole)
                if candidate is not None:
                    raw = candidate
        document: dict[str, Any] = {"display": visible}
        if isinstance(raw, (dict, list, tuple, str, int, float, bool)) or raw is None:
            document["record"] = raw
        else:
            document["record_id"] = str(raw)[:1000]
        rendered = json.dumps(document, indent=2, ensure_ascii=False, default=str)
        if len(rendered) > 128 * 1024:
            rendered = rendered[: 128 * 1024] + "\n… detail truncated at 128 KiB"
        dialog = QDialog(self)
        dialog.setWindowTitle("Read-only row details")
        dialog.setMinimumSize(680, 460)
        layout = QVBoxLayout(dialog)
        note = QLabel(
            "This is a bounded, read-only explanation. Paths are shown literally and are "
            "never opened or executed from this view."
        )
        note.setWordWrap(True)
        note.setTextFormat(Qt.PlainText)
        layout.addWidget(note)
        body = QPlainTextEdit()
        body.setReadOnly(True)
        body.setPlainText(rendered)
        layout.addWidget(body, 1)
        controls = QHBoxLayout()
        copy = QPushButton("Copy details")
        copy.clicked.connect(
            lambda: QApplication.clipboard().setText(body.toPlainText())
        )
        close = QPushButton("Close")
        close.clicked.connect(dialog.close)
        controls.addStretch(1)
        controls.addWidget(copy)
        controls.addWidget(close)
        layout.addLayout(controls)
        dialog.show()
        self._row_detail_dialog = dialog

    def _build_audit_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_InfoPanel(
            "Configuration drift",
            "Run a fresh deep audit before trusting the score. Excluded findings remain visible "
            "for accountability but contribute zero risk. Saving a new golden baseline is an "
            "explicit replacement, not automatic learning.",
        ))
        buttons = QHBoxLayout()
        self.audit_button = QPushButton("Run deep audit")
        self.audit_button.setObjectName("Primary")
        self.audit_button.clicked.connect(self._run_audit)
        baseline = QPushButton("Save as golden baseline…")
        baseline.clicked.connect(self._save_baseline)
        export_json = QPushButton("Export JSON…")
        export_json.clicked.connect(self._export_json)
        export_csv = QPushButton("Export CSV…")
        export_csv.clicked.connect(self._export_csv)
        for button in (self.audit_button, baseline, export_json, export_csv):
            buttons.addWidget(button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        self.audit_summary = QLabel("No audit has run in this session.")
        self.audit_summary.setWordWrap(True)
        layout.addWidget(self.audit_summary)
        self.findings_table = self._table([
            "Severity", "Category", "Change", "Item", "Risk", "Status",
        ])
        layout.addWidget(self.findings_table, 1)
        feedback = QHBoxLayout()
        pin = QPushButton("Pin selected as known-good exception…")
        pin.clicked.connect(self._pin_exception)
        dismiss = QPushButton("Dismiss false positive + tune score…")
        dismiss.clicked.connect(self._dismiss_feedback)
        feedback.addWidget(pin)
        feedback.addWidget(dismiss)
        feedback.addStretch(1)
        layout.addLayout(feedback)
        return page

    def _build_exceptions_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_InfoPanel(
            "Exact exceptions, never broad exclusions",
            "An exception binds to one drift category and stable item key. It does not disable a "
            "sensor or hide the row; it only excludes the known-good item from drift scoring. "
            "Feedback tuning is bounded between 0.25× and 2× per category.",
        ))
        self.exceptions_table = self._table(["Category", "Item", "Reason", "Created", "ID"])
        layout.addWidget(self.exceptions_table, 1)
        row = QHBoxLayout()
        refresh = QPushButton("Refresh exceptions")
        refresh.clicked.connect(self._refresh_exceptions)
        remove = QPushButton("Remove selected exception")
        remove.clicked.connect(self._remove_exception)
        row.addWidget(refresh)
        row.addWidget(remove)
        row.addStretch(1)
        layout.addLayout(row)
        self.weights_label = QLabel("Adaptive scoring: default 1.0× in every category")
        self.weights_label.setWordWrap(True)
        layout.addWidget(self.weights_label)
        return page

    # ── Profiles and sandbox ───────────────────────────────────────────────
    def _profile_combo(self) -> QComboBox:
        combo = QComboBox()
        for profile in self.service.profiles():
            combo.addItem(f"{profile.name} — {profile.intent}", profile.profile_id)
        return combo

    def _build_profiles_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_InfoPanel(
            "Intent-driven profiles",
            "Preview is mandatory: it captures the current firewall precondition and produces an "
            "immutable plan that expires in ten minutes. Apply rechecks that precondition, creates "
            "a rollback snapshot, and refuses altered or stale plans.",
        ))
        top = QHBoxLayout()
        self.profile_combo = self._profile_combo()
        self.profile_combo.currentIndexChanged.connect(self._profile_changed)
        preview = QPushButton("1. Preview adaptation")
        preview.clicked.connect(self._preview_profile)
        sandbox = QPushButton("2. Test in sandbox")
        sandbox.clicked.connect(self._run_sandbox)
        top.addWidget(QLabel("Profile:"))
        top.addWidget(self.profile_combo, 1)
        top.addWidget(preview)
        top.addWidget(sandbox)
        layout.addLayout(top)
        self.profile_description = QLabel()
        self.profile_description.setWordWrap(True)
        layout.addWidget(self.profile_description)
        self.plan_text = QPlainTextEdit()
        self.plan_text.setReadOnly(True)
        self.plan_text.setPlaceholderText("Preview a profile to see its exact commands, plan ID, expiry, and warnings.")
        layout.addWidget(self.plan_text, 1)
        apply_row = QHBoxLayout()
        self.apply_button = QPushButton("3. ADAPT HOST with this preview…")
        self.apply_button.setObjectName("Danger")
        self.apply_button.setEnabled(False)
        self.apply_button.clicked.connect(self._apply_profile)
        apply_row.addWidget(self.apply_button)
        apply_row.addStretch(1)
        layout.addLayout(apply_row)

        rollback = QGroupBox("Recovery snapshots")
        rb_layout = QHBoxLayout(rollback)
        self.snapshot_combo = QComboBox()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_snapshots)
        rollback_button = QPushButton("Roll back selected snapshot…")
        rollback_button.clicked.connect(self._rollback_selected)
        capture_baseline = QPushButton("Capture immutable host baseline…")
        capture_baseline.clicked.connect(self._capture_security_baseline)
        restore_baseline = QPushButton("Restore host baseline…")
        restore_baseline.clicked.connect(self._restore_security_baseline)
        rb_layout.addWidget(self.snapshot_combo, 1)
        rb_layout.addWidget(refresh)
        rb_layout.addWidget(rollback_button)
        rb_layout.addWidget(capture_baseline)
        rb_layout.addWidget(restore_baseline)
        layout.addWidget(rollback)
        return page

    def _build_sandbox_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_InfoPanel(
            "No-write profile sandbox",
            "The sandbox applies the selected profile to an in-memory copy of the captured "
            "firewall state. It shows the projected delta and command stack. host_mutated is "
            "always false and no snapshot is needed because nothing is executed.",
        ))
        row = QHBoxLayout()
        self.sandbox_profile_combo = self._profile_combo()
        run = QPushButton("Run no-write simulation")
        run.setObjectName("Primary")
        run.clicked.connect(self._run_sandbox)
        row.addWidget(QLabel("Profile:"))
        row.addWidget(self.sandbox_profile_combo, 1)
        row.addWidget(run)
        layout.addLayout(row)
        splitter = QSplitter(Qt.Vertical)
        self.sandbox_table = self._table(["Firewall profile", "Before", "After"])
        self.sandbox_commands = QPlainTextEdit()
        self.sandbox_commands.setReadOnly(True)
        self.sandbox_commands.setPlaceholderText("Simulation commands and warnings appear here.")
        splitter.addWidget(self.sandbox_table)
        splitter.addWidget(self.sandbox_commands)
        splitter.setSizes([300, 180])
        layout.addWidget(splitter, 1)
        return page

    # ── Automation and activity ────────────────────────────────────────────
    def _build_automation_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_InfoPanel(
            "Trigger-based contexts",
            "Rules use an exact SSID, Windows Public category, or active VPN adapter. Exact SSID "
            "rules take priority. Rules are proposal-only: SSIDs and session hints are not "
            "authenticated liveness proof and cannot safely authorize unattended firewall "
            "changes. Use Guided Auto Adapt for the one-flow audited preview and exact approval.",
        ))
        state = self.service.state()
        controls = QHBoxLayout()
        self.automation_enabled = QCheckBox("Monitor configured contexts")
        self.automation_enabled.setChecked(bool(state.get("automation_enabled")))
        self.auto_apply = QCheckBox("Unattended apply (disabled — exact review required)")
        self.auto_apply.setChecked(False)
        self.auto_apply.setEnabled(False)
        self.auto_apply.setToolTip(
            "Context rules propose profiles only; they never mutate the host unattended."
        )
        self.automation_enabled.toggled.connect(self._automation_changed)
        self.auto_apply.toggled.connect(self._auto_apply_changed)
        evaluate = QPushButton("Evaluate current context now")
        evaluate.clicked.connect(self._evaluate_context)
        controls.addWidget(self.automation_enabled)
        controls.addWidget(self.auto_apply)
        controls.addStretch(1)
        controls.addWidget(evaluate)
        layout.addLayout(controls)

        rule_group = QGroupBox("Add a context rule")
        form = QFormLayout(rule_group)
        self.trigger_kind = QComboBox()
        self.trigger_kind.addItem("Windows Public network", "public_network")
        self.trigger_kind.addItem("VPN adapter active", "vpn_active")
        self.trigger_kind.addItem("Exact Wi-Fi SSID", "ssid")
        self.trigger_value = QLineEdit()
        self.trigger_value.setPlaceholderText("Required only for exact SSID")
        self.trigger_profile = self._profile_combo()
        add = QPushButton("Add trigger mapping")
        add.clicked.connect(self._add_trigger)
        self.trigger_kind.currentIndexChanged.connect(self._trigger_kind_changed)
        form.addRow("When:", self.trigger_kind)
        form.addRow("Exact value:", self.trigger_value)
        form.addRow("Use profile:", self.trigger_profile)
        form.addRow("", add)
        layout.addWidget(rule_group)

        self.trigger_table = self._table(["When", "Value", "Profile", "Created", "Rule ID"])
        layout.addWidget(self.trigger_table, 1)
        actions = QHBoxLayout()
        remove = QPushButton("Remove selected rule")
        remove.clicked.connect(self._remove_trigger)
        reset = QPushButton("Reset circuit breaker…")
        reset.clicked.connect(self._reset_breaker)
        actions.addWidget(remove)
        actions.addWidget(reset)
        actions.addStretch(1)
        layout.addLayout(actions)
        self.context_detail = QPlainTextEdit()
        self.context_detail.setReadOnly(True)
        self.context_detail.setMaximumHeight(130)
        self.context_detail.setPlaceholderText("Current SSID/category/VPN state and rule matches appear here.")
        layout.addWidget(self.context_detail)
        return page

    def _build_activity_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_InfoPanel(
            "Bounded local activity trail",
            "The latest 500 audit, exception, trigger, breaker, profile, and rollback events are "
            "stored in a digest-verified local record. This view intentionally has no clear "
            "button; retention is bounded automatically.",
        ))
        self.activity_table = self._table(["Time (UTC)", "Action", "Result", "Detail"])
        layout.addWidget(self.activity_table, 1)
        refresh = QPushButton("Refresh activity")
        refresh.clicked.connect(self._refresh_activity)
        layout.addWidget(refresh, 0, Qt.AlignLeft)
        return page

    # ── Background task routing ────────────────────────────────────────────
    def _run_task(self, name: str, operation: Callable[[], Any]) -> None:
        if self._busy_task:
            QMessageBox.information(
                self, "Adaptation busy", f"{self._busy_task.replace('_', ' ').title()} is still running."
            )
            return
        self._busy_task = name
        self.busy_label.setText(f"Working: {name.replace('_', ' ')}…")
        self.audit_button.setEnabled(False)

        def worker() -> None:
            try:
                result = operation()
                self._task_finished.emit(name, result, None)
            except Exception as exc:
                self._task_finished.emit(name, None, exc)

        task = threading.Thread(
            target=worker, name=f"HostAdaptation-{name}", daemon=True
        )
        try:
            task.start()
        except Exception as exc:
            self._busy_task = ""
            self.busy_label.setText("Worker unavailable")
            self.audit_button.setEnabled(True)
            self.footer_detail.setText(str(exc))
            QMessageBox.warning(self, "Adaptation", str(exc))

    def _on_task_finished(self, name: str, result: Any, error: Any) -> None:
        self._busy_task = ""
        self.audit_button.setEnabled(True)
        if error is not None:
            self.busy_label.setText("Safely refused / failed")
            self.footer_detail.setText(str(error))
            QMessageBox.warning(self, "Adaptation", str(error))
            self._refresh_status()
            return
        self.busy_label.setText("Ready")
        if name == "audit":
            self._display_audit(result)
        elif name == "preview":
            self._display_plan(result)
        elif name == "sandbox":
            self._display_sandbox(result)
        elif name == "apply":
            self.apply_button.setEnabled(False)
            self._latest_plan = None
            self.plan_text.appendPlainText(
                "\nAPPLIED\n" + json.dumps(asdict(result), indent=2, default=str)
            )
            self.footer_detail.setText(
                f"Profile applied. Recovery snapshot: {result.snapshot_id}"
            )
            self._refresh_snapshots()
            self._refresh_activity()
        elif name == "rollback":
            self.footer_detail.setText("Rollback completed and the active profile marker was cleared.")
            self._refresh_snapshots()
            self._refresh_activity()
        elif name == "auto_prepare":
            report = dict(result.get("report") or {})
            plan = result.get("plan")
            simulation = dict(result.get("simulation") or {})
            self._display_audit(report)
            self._display_sandbox(simulation)
            if isinstance(plan, AdaptationPlan):
                self._display_plan(plan)
            gaps = list(report.get("incomplete_collectors") or ())
            if result.get("apply_requested"):
                if gaps:
                    self.footer_detail.setText(
                        "Auto Adapt prepared a proposal only: incomplete collectors prevent apply ("
                        + ", ".join(str(item) for item in gaps)
                        + ")."
                    )
                elif not dict(result.get("recovery") or {}).get("available"):
                    self.footer_detail.setText(
                        "Auto Adapt prepared a proposal only: explicitly capture the immutable "
                        "firewall recovery baseline before applying."
                    )
                elif result.get("relaxes"):
                    self.footer_detail.setText(
                        "Auto Adapt prepared a proposal only: the selected profile would relax "
                        "the current firewall posture and requires manual review."
                    )
                elif isinstance(plan, AdaptationPlan):
                    QTimer.singleShot(0, self._apply_profile)
            else:
                self.footer_detail.setText(
                    "Auto Adapt completed audit, immutable preview, and no-write simulation; "
                    "host untouched."
                )
        elif name == "safe_checkup":
            report = dict(result.get("report") or {})
            self._display_audit(report)
            simulations = list(result.get("simulations") or ())
            changed = sum(len(item.get("changes") or ()) for item in simulations)
            self.footer_detail.setText(
                f"Safe automatic checkup complete: {len(simulations)} profiles simulated, "
                f"{changed} projected profile changes, host untouched."
            )
        elif name == "capture_security_baseline":
            self.footer_detail.setText(
                "Immutable host recovery baseline captured for Windows Firewall policy."
            )
            self._refresh_snapshots()
            self._refresh_activity()
        elif name == "restore_security_baseline":
            self.footer_detail.setText(
                "Host security baseline restored and verified. A pre-restore recovery "
                f"snapshot remains available: {result.get('pre_restore_snapshot_id', 'unknown')}."
            )
            self._refresh_snapshots()
            self._refresh_activity()
        elif name == "context":
            self._display_context(result)
        self._refresh_status()

    # ── Audit actions ──────────────────────────────────────────────────────
    def _run_audit(self) -> None:
        self._run_task("audit", self.service.audit)

    def _run_safe_checkup(self) -> None:
        """Run every non-writing adaptation check in one bounded workflow."""
        def operation() -> dict[str, Any]:
            report = self.service.audit()
            current = report.get("current")
            if not isinstance(current, dict):
                raise RuntimeError("deep audit did not return a host snapshot")
            simulations = [
                self.service.sandbox(profile.profile_id, current)
                for profile in self.service.profiles()
            ]
            return {"report": report, "simulations": simulations}

        self._run_task("safe_checkup", operation)

    def _display_audit(self, report: dict[str, Any]) -> None:
        self._latest_report = report
        findings = list(report.get("findings") or [])
        skipped = [
            str(name) for name in report.get("skipped_incomplete_collectors") or []
        ]
        incomplete = [str(name) for name in report.get("incomplete_collectors") or []]
        coverage_gaps = list(dict.fromkeys(skipped + incomplete))
        audit_header = self.findings_table.horizontalHeader()
        audit_sort_column = audit_header.sortIndicatorSection()
        audit_sort_order = audit_header.sortIndicatorOrder()
        self.findings_table.setUpdatesEnabled(False)
        self.findings_table.setSortingEnabled(False)
        try:
            self.findings_table.setRowCount(len(findings))
            for row, finding in enumerate(findings):
                values = [
                    finding.get("severity", ""), finding.get("category", ""),
                    finding.get("change", ""), finding.get("key", ""),
                    f"{float(finding.get('score', 0)):.1f}",
                    "EXCLUDED" if finding.get("excluded") else "ACTIVE",
                ]
                for column, value in enumerate(values):
                    if column == 0:
                        severity = str(value).strip().casefold()
                        item = _TypedSortItem(
                            str(value), _SEVERITY_SORT_RANK.get(severity, 0)
                        )
                    elif column == 4:
                        item = _TypedSortItem(
                            str(value), float(finding.get("score", 0) or 0)
                        )
                    else:
                        item = QTableWidgetItem(str(value))
                    item.setData(Qt.UserRole, finding)
                    if column == 0:
                        item.setForeground(
                            QColor(_SEVERITY_COLORS.get(severity, "#cbd5e1"))
                        )
                    if finding.get("excluded"):
                        item.setForeground(QColor("#64748b"))
                    self.findings_table.setItem(row, column, item)
        finally:
            self.findings_table.setSortingEnabled(True)
            self.findings_table.sortItems(audit_sort_column, audit_sort_order)
            self.findings_table.setUpdatesEnabled(True)
        if report.get("baseline_exists"):
            summary = (
                f"Baseline {report.get('baseline_captured_at', 'unknown')} · "
                f"{report.get('active_findings', 0)} active · "
                f"{report.get('excluded_findings', 0)} excluded · "
                + (
                    "risk unavailable (coverage incomplete)"
                    if coverage_gaps else
                    f"risk {float(report.get('risk_score', 0)):.1f}/100"
                )
            )
        else:
            summary = (
                "No golden baseline exists. Review this capture, then save it as the baseline; "
                "drift scoring begins on the next audit."
            )
        if coverage_gaps:
            summary += (
                " · PARTIAL AUDIT: coverage is incomplete for "
                f"collector{'s' if len(coverage_gaps) != 1 else ''}: "
                f"{', '.join(coverage_gaps)}. Missing coverage is never scored as healthy."
            )
        self.audit_summary.setText(summary)
        self.footer_detail.setText(summary)
        self._refresh_status()

    def _selected_finding(self) -> dict[str, Any] | None:
        row = self.findings_table.currentRow()
        item = self.findings_table.item(row, 0) if row >= 0 else None
        value = item.data(Qt.UserRole) if item else None
        return dict(value) if isinstance(value, dict) else None

    def _save_baseline(self) -> None:
        if not self._latest_report:
            QMessageBox.information(self, "Golden baseline", "Run and review a deep audit first.")
            return
        current = self._latest_report.get("current")
        if not isinstance(current, dict):
            return
        incomplete = self._latest_report.get("incomplete_collectors") or []
        if incomplete:
            QMessageBox.warning(
                self,
                "Golden baseline refused",
                "A trusted golden baseline requires complete collectors. Re-run after "
                "resolving: " + ", ".join(str(name) for name in incomplete),
            )
            return
        answer = QMessageBox.warning(
            self,
            "Replace golden baseline?",
            "This makes the current reviewed hardware, services, ports, adapters, and firewall "
            "posture the new golden baseline. Existing exceptions remain."
            "\n\nContinue?",
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            self.service.save_baseline(current)
            self.baseline_status.setText("Baseline: saved now")
            self.footer_detail.setText("Golden baseline saved. Run another audit to calculate drift.")
            self._refresh_activity()
        except Exception as exc:
            QMessageBox.warning(self, "Golden baseline", str(exc))

    def _exception_reason(self, title: str) -> str:
        reason, ok = QInputDialog.getText(
            self, title, "Reason / owner / ticket (required):"
        )
        return reason.strip() if ok else ""

    def _pin_exception(self) -> None:
        finding = self._selected_finding()
        if not finding:
            QMessageBox.information(self, "Exception", "Select a drift finding first.")
            return
        reason = self._exception_reason("Pin known-good exception")
        if not reason:
            return
        try:
            self.service.add_exception(finding, reason)
            self._refresh_exceptions()
            self._run_task("audit", self.service.audit)
        except Exception as exc:
            QMessageBox.warning(self, "Exception", str(exc))

    def _dismiss_feedback(self) -> None:
        finding = self._selected_finding()
        if not finding:
            QMessageBox.information(self, "Feedback", "Select a drift finding first.")
            return
        reason = self._exception_reason("Dismiss false positive and tune scoring")
        if not reason:
            return
        try:
            self.service.add_exception(finding, reason, tune_feedback=True)
            self._refresh_exceptions()
            self._run_task("audit", self.service.audit)
        except Exception as exc:
            QMessageBox.warning(self, "Feedback", str(exc))

    def _export(self, fmt: str) -> None:
        if not self._latest_report:
            QMessageBox.information(self, "Export audit", "Run a deep audit first.")
            return
        suffix = f"*.{fmt}"
        filename, _ = QFileDialog.getSaveFileName(
            self, f"Export audit as {fmt.upper()}",
            str(Path.home() / f"angerona-host-audit.{fmt}"),
            f"{fmt.upper()} files ({suffix})",
        )
        if not filename:
            return
        try:
            target = self.service.export_report(self._latest_report, filename, fmt)
            self.footer_detail.setText(f"Audit exported to {target}")
            self._refresh_activity()
        except Exception as exc:
            QMessageBox.warning(self, "Export audit", str(exc))

    def _export_json(self) -> None:
        self._export("json")

    def _export_csv(self) -> None:
        self._export("csv")

    # ── Profile actions ────────────────────────────────────────────────────
    def _selected_profile_id(self, sandbox: bool = False) -> str:
        combo = self.sandbox_profile_combo if sandbox else self.profile_combo
        return str(combo.currentData() or "balanced")

    def _profile_changed(self, *_args) -> None:
        self._latest_plan = None
        self.apply_button.setEnabled(False)
        profile = PROFILES[self._selected_profile_id()]
        warning = " ".join(profile.warnings)
        self.profile_description.setText(
            f"{profile.description}\nSafety notes: {warning or 'Standard rollback requirements apply.'}"
        )

    def _preview_profile(self) -> None:
        profile_id = self._selected_profile_id()
        self._run_task("preview", lambda: self.service.build_plan(profile_id))

    def _display_plan(self, plan: AdaptationPlan) -> None:
        self._latest_plan = plan
        lines = [
            f"PLAN ID: {plan.plan_id}",
            f"PROFILE: {PROFILES[plan.profile_id].name}",
            f"CREATED: {plan.created_at}",
            f"EXPIRES: {plan.expires_at}",
            f"PRECONDITION SHA-256: {plan.precondition_digest}",
            f"DRASTIC: {'YES' if plan.drastic else 'NO'}",
            "",
            "EXACT COMMAND STACK:",
        ]
        lines.extend(f"  {index}. {command}" for index, command in enumerate(
            self.service.command_stack(plan), start=1
        ))
        lines.extend(["", "WARNINGS:"])
        lines.extend(f"  - {warning}" for warning in plan.warnings)
        lines.append("  - A rollback snapshot is mandatory before command 1.")
        self.plan_text.setPlainText("\n".join(lines))
        try:
            recovery_ready = bool(
                self.service.security_baseline_status().get("available")
            )
        except Exception:
            recovery_ready = False
        self.apply_button.setEnabled(recovery_ready)
        self.apply_button.setToolTip(
            "Apply this exact plan."
            if recovery_ready else
            "Capture the immutable firewall recovery baseline before applying."
        )
        self.tabs.setCurrentIndex(3)
        self.footer_detail.setText(
            f"Preview ready: {plan.plan_id}. It expires in ten minutes and is bound to current firewall state."
        )

    def _apply_profile(self) -> None:
        plan = self._latest_plan
        if plan is None:
            QMessageBox.information(self, "Apply profile", "Preview the selected profile first.")
            return
        try:
            recovery = self.service.security_baseline_status()
        except Exception as exc:
            QMessageBox.warning(self, "Apply profile", str(exc))
            return
        if not recovery.get("available"):
            QMessageBox.information(
                self,
                "Recovery baseline required",
                "Explicitly capture the immutable Windows Firewall recovery baseline "
                "before applying a profile. This enrollment is never created as a side "
                "effect of Apply.",
            )
            return
        warning = "\n".join(f"• {item}" for item in plan.warnings)
        commands = "\n".join(self.service.command_stack(plan))
        answer = QMessageBox.warning(
            self,
            "Apply adaptation profile?",
            f"Plan: {plan.plan_id}\n\n{warning}\n\nCommands:\n{commands}\n\n"
            "The immutable recovery baseline is enrolled. A fresh temporary Windows "
            "Firewall rollback snapshot and a durable transaction receipt will be created "
            "before command 1. Apply this exact plan?",
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if answer != QMessageBox.Yes:
            return
        self._run_task(
            "apply",
            lambda: self.service.apply_plan(
                plan, approved=True, approved_plan_id=plan.plan_id,
                authorization="operator-confirmed-workbench",
            ),
        )

    def _run_sandbox(self) -> None:
        # Keep both selectors convenient: if the request originated from the
        # profile tab, mirror that selection into the dedicated sandbox tab.
        if self.sender() is not None and self.tabs.currentIndex() == 3:
            profile_id = self._selected_profile_id()
            index = self.sandbox_profile_combo.findData(profile_id)
            if index >= 0:
                self.sandbox_profile_combo.setCurrentIndex(index)
        profile_id = self._selected_profile_id(sandbox=True)
        self._run_task("sandbox", lambda: self.service.sandbox(profile_id))

    def _display_sandbox(self, result: dict[str, Any]) -> None:
        changes = list(result.get("changes") or [])
        header = self.sandbox_table.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self.sandbox_table.setUpdatesEnabled(False)
        self.sandbox_table.setSortingEnabled(False)
        try:
            self.sandbox_table.setRowCount(len(changes))
            for row, change in enumerate(changes):
                before = json.dumps(change.get("before"), sort_keys=True, default=str)
                after = json.dumps(change.get("after"), sort_keys=True, default=str)
                for column, value in enumerate((change.get("profile", ""), before, after)):
                    item = QTableWidgetItem(str(value))
                    item.setData(Qt.UserRole, change)
                    self.sandbox_table.setItem(row, column, item)
        finally:
            self.sandbox_table.setSortingEnabled(True)
            self.sandbox_table.sortItems(sort_column, sort_order)
            self.sandbox_table.setUpdatesEnabled(True)
        text = [
            f"PLAN: {result.get('plan_id')}",
            f"HOST MUTATED: {result.get('host_mutated')}",
            "",
            "COMMANDS THAT WOULD RUN:",
            *[f"  {command}" for command in result.get("commands", [])],
            "",
            "WARNINGS:",
            *[f"  - {warning}" for warning in result.get("warnings", [])],
        ]
        self.sandbox_commands.setPlainText("\n".join(text))
        self.tabs.setCurrentIndex(4)
        self.footer_detail.setText(
            f"Sandbox complete: {len(changes)} projected firewall profile change(s); host untouched."
        )

    def _rollback_selected(self) -> None:
        snapshot_id = self.snapshot_combo.currentData()
        if not snapshot_id:
            QMessageBox.information(self, "Rollback", "No recovery snapshot is available.")
            return
        answer = QMessageBox.warning(
            self,
            "Restore firewall snapshot?",
            f"Import snapshot {snapshot_id} and replace current Windows Firewall policy?\n\n"
            "This is a recovery operation and is not blocked by the adaptation circuit breaker.",
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if answer != QMessageBox.Yes:
            return
        self._run_task(
            "rollback",
            lambda: self.service.rollback(
                str(snapshot_id), approved=True,
                authorization="operator-confirmed-workbench",
            ),
        )

    def _capture_security_baseline(self) -> None:
        try:
            status = self.service.security_baseline_status()
        except Exception as exc:
            QMessageBox.warning(self, "Host security baseline", str(exc))
            return
        if status.get("available"):
            QMessageBox.information(
                self,
                "Host security baseline",
                "The immutable original Windows Firewall baseline already exists and is "
                "never silently replaced.",
            )
            return
        answer = QMessageBox.warning(
            self,
            "Capture immutable host security baseline?",
            "Capture the current complete Windows Firewall policy as Angerona's permanent "
            "recovery default for this host?\n\nHardware, services, ports, and network "
            "context remain observational only and will not be advertised as restorable.",
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if answer == QMessageBox.Yes:
            self._run_task(
                "capture_security_baseline",
                lambda: self.service.capture_security_baseline(approved=True),
            )

    def _restore_security_baseline(self) -> None:
        try:
            status = self.service.security_baseline_status()
        except Exception as exc:
            QMessageBox.warning(self, "Host security baseline", str(exc))
            return
        if not status.get("available"):
            QMessageBox.information(
                self, "Host security baseline", "No restorable host baseline exists yet."
            )
            return
        answer = QMessageBox.warning(
            self,
            "Restore host security baseline?",
            "Replace the complete current Windows Firewall policy with the immutable "
            f"baseline captured {status.get('captured_at', 'earlier')}?\n\nA fresh "
            "pre-restore recovery snapshot is captured first, and the restored posture "
            "must pass its postcondition check.",
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if answer == QMessageBox.Yes:
            self._run_task(
                "restore_security_baseline",
                lambda: self.service.restore_security_baseline(approved=True),
            )

    # ── Exception, automation, and persisted views ─────────────────────────
    def _refresh_exceptions(self, state: dict[str, Any] | None = None) -> None:
        try:
            entries = self.service.list_exceptions()
            rows = tuple(
                tuple(str(value) for value in (
                    item.get("category", ""), item.get("key", ""),
                    item.get("reason", ""), item.get("created_at", ""), item.get("id", ""),
                ))
                for item in entries
            )
            if rows != self._view_signatures.get("exceptions"):
                self.exceptions_table.setUpdatesEnabled(False)
                header = self.exceptions_table.horizontalHeader()
                sort_column = header.sortIndicatorSection()
                sort_order = header.sortIndicatorOrder()
                self.exceptions_table.setSortingEnabled(False)
                try:
                    self.exceptions_table.setRowCount(len(rows))
                    for row, values in enumerate(rows):
                        exception_id = values[4]
                        for column, value in enumerate(values):
                            cell = QTableWidgetItem(value)
                            cell.setData(Qt.UserRole, exception_id)
                            self.exceptions_table.setItem(row, column, cell)
                    self._view_signatures["exceptions"] = rows
                finally:
                    self.exceptions_table.setSortingEnabled(True)
                    self.exceptions_table.sortItems(sort_column, sort_order)
                    self.exceptions_table.setUpdatesEnabled(True)
            current_state = state if state is not None else self.service.state()
            weights = current_state.get("adaptive_weights", {})
            detail = ", ".join(
                f"{key} {float(value):.2f}×" for key, value in sorted(weights.items())
            ) or "default 1.0× in every category"
            self.weights_label.setText(f"Adaptive scoring: {detail}")
        except Exception as exc:
            self.weights_label.setText(f"Exceptions unavailable: {exc}")

    def _remove_exception(self) -> None:
        row = self.exceptions_table.currentRow()
        item = self.exceptions_table.item(row, 0) if row >= 0 else None
        exception_id = item.data(Qt.UserRole) if item else ""
        if not exception_id:
            QMessageBox.information(self, "Exception", "Select an exception first.")
            return
        if QMessageBox.question(
            self, "Remove exception?", "Return this item to active drift scoring?",
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel,
        ) != QMessageBox.Yes:
            return
        self.service.remove_exception(str(exception_id))
        self._refresh_exceptions()

    def _refresh_snapshots(self) -> None:
        try:
            rows = tuple(
                (
                    str(snapshot.get("snapshot_id") or ""),
                    f"{snapshot.get('captured_at', '')} · "
                    f"{snapshot.get('plan', {}).get('profile_id', 'unknown')} · "
                    f"{snapshot.get('status', 'ready')}",
                )
                for snapshot in self.service.list_snapshots()
            )
            if rows == self._view_signatures.get("snapshots"):
                return
            selected = self.snapshot_combo.currentData()
            self.snapshot_combo.setUpdatesEnabled(False)
            try:
                self.snapshot_combo.clear()
                for snapshot_id, label in rows:
                    self.snapshot_combo.addItem(label, snapshot_id)
                if selected:
                    index = self.snapshot_combo.findData(selected)
                    if index >= 0:
                        self.snapshot_combo.setCurrentIndex(index)
                self._view_signatures["snapshots"] = rows
            finally:
                self.snapshot_combo.setUpdatesEnabled(True)
        except Exception as exc:
            self.snapshot_combo.clear()
            self.snapshot_combo.addItem(f"Snapshots unavailable: {exc}", None)
            self._view_signatures.pop("snapshots", None)

    def _automation_changed(self, checked: bool) -> None:
        if not checked and self.auto_apply.isChecked():
            self.auto_apply.blockSignals(True)
            self.auto_apply.setChecked(False)
            self.auto_apply.blockSignals(False)
        self.service.set_automation(checked, self.auto_apply.isChecked())
        self._refresh_status()

    def _auto_apply_changed(self, checked: bool) -> None:
        if checked:
            QMessageBox.information(
                self, "Proposal-only automation",
                "Unattended firewall mutation is disabled. Context rules prepare a proposal; "
                "Guided Auto Adapt provides one audited flow and a final exact-plan approval.",
            )
        self.auto_apply.blockSignals(True)
        self.auto_apply.setChecked(False)
        self.auto_apply.blockSignals(False)
        self.service.set_automation(self.automation_enabled.isChecked(), False)
        self._refresh_status()

    def _trigger_kind_changed(self, *_args) -> None:
        exact = self.trigger_kind.currentData() == "ssid"
        self.trigger_value.setEnabled(exact)
        if not exact:
            self.trigger_value.clear()

    def _add_trigger(self) -> None:
        try:
            self.service.add_trigger(
                str(self.trigger_kind.currentData()), self.trigger_value.text(),
                str(self.trigger_profile.currentData()),
            )
            self.trigger_value.clear()
            self._refresh_triggers()
        except Exception as exc:
            QMessageBox.warning(self, "Context trigger", str(exc))

    def _refresh_triggers(self, state: dict[str, Any] | None = None) -> None:
        current_state = state if state is not None else self.service.state()
        rules = current_state.get("triggers", [])
        labels = {
            "public_network": "Windows Public network",
            "vpn_active": "VPN adapter active",
            "ssid": "Exact Wi-Fi SSID",
        }
        rows = tuple(
            tuple(str(value) for value in (
                labels.get(rule.get("kind"), rule.get("kind", "")),
                rule.get("value", ""),
                PROFILES.get(rule.get("profile_id"), PROFILES["balanced"]).name,
                rule.get("created_at", ""), rule.get("id", ""),
            ))
            for rule in rules
        )
        if rows == self._view_signatures.get("triggers"):
            return
        self.trigger_table.setUpdatesEnabled(False)
        header = self.trigger_table.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self.trigger_table.setSortingEnabled(False)
        try:
            self.trigger_table.setRowCount(len(rows))
            for row, values in enumerate(rows):
                rule_id = values[4]
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setData(Qt.UserRole, rule_id)
                    self.trigger_table.setItem(row, column, item)
            self._view_signatures["triggers"] = rows
        finally:
            self.trigger_table.setSortingEnabled(True)
            self.trigger_table.sortItems(sort_column, sort_order)
            self.trigger_table.setUpdatesEnabled(True)

    def _remove_trigger(self) -> None:
        row = self.trigger_table.currentRow()
        item = self.trigger_table.item(row, 0) if row >= 0 else None
        rule_id = item.data(Qt.UserRole) if item else ""
        if not rule_id:
            QMessageBox.information(self, "Context trigger", "Select a rule first.")
            return
        self.service.remove_trigger(str(rule_id))
        self._refresh_triggers()

    def _evaluate_context(self) -> None:
        self._run_task("context", self.service.evaluate_context)

    def _display_context(self, evaluation: dict[str, Any]) -> None:
        context = evaluation.get("context", {})
        matches = evaluation.get("matches", [])
        lines = [
            f"SSID: {context.get('ssid') or '(not connected / unavailable)'}",
            f"Network category: {context.get('network_category', 'Unknown')}",
            f"VPN active: {bool(context.get('vpn_active'))}",
            f"Matched rules: {len(matches)}",
        ]
        lines.extend(
            f"  {rule.get('id')} -> {rule.get('profile_id')}" for rule in matches
        )
        self.context_detail.setPlainText("\n".join(lines))
        self.context_status.setText(
            f"Context: {context.get('network_category', 'Unknown')} · "
            f"VPN {'on' if context.get('vpn_active') else 'off'}"
        )
        self.footer_detail.setText(
            f"Context evaluated; {len(matches)} matching rule(s)."
        )

    def _reset_breaker(self) -> None:
        if QMessageBox.warning(
            self, "Reset adaptation circuit breaker?",
            "Reset the cooldown history and unlock profile changes? Review Activity first.",
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel,
        ) != QMessageBox.Yes:
            return
        self.service.reset_breaker()
        self._refresh_status()
        self._refresh_activity()

    def _refresh_activity(self) -> None:
        try:
            entries = self.service.activity()
            rows = tuple(
                tuple(str(value) for value in (
                    entry.get("at", ""), entry.get("action", ""),
                    entry.get("result", ""), entry.get("detail", ""),
                ))
                for entry in entries
            )
            if rows == self._view_signatures.get("activity"):
                return
            self.activity_table.setUpdatesEnabled(False)
            header = self.activity_table.horizontalHeader()
            sort_column = header.sortIndicatorSection()
            sort_order = header.sortIndicatorOrder()
            self.activity_table.setSortingEnabled(False)
            try:
                self.activity_table.setRowCount(len(rows))
                for row, values in enumerate(rows):
                    for column, value in enumerate(values):
                        self.activity_table.setItem(row, column, QTableWidgetItem(value))
                self._view_signatures["activity"] = rows
            finally:
                self.activity_table.setSortingEnabled(True)
                self.activity_table.sortItems(sort_column, sort_order)
                self.activity_table.setUpdatesEnabled(True)
        except Exception as exc:
            self.activity_table.setRowCount(1)
            self.activity_table.setItem(0, 3, QTableWidgetItem(str(exc)))
            self._view_signatures.pop("activity", None)

    def _refresh_status(self) -> None:
        try:
            baseline = self.service.load_baseline()
            self.baseline_status.setText(
                f"Baseline: {baseline.get('captured_at', 'saved')}" if baseline else "Baseline: not set"
            )
        except Exception as exc:
            self.baseline_status.setText(f"Baseline: integrity warning ({exc})")
        try:
            recovery = self.service.security_baseline_status()
            if recovery.get("available"):
                self.recovery_status.setText(
                    "Recovery: Firewall · " + str(recovery.get("captured_at") or "captured")
                )
                self.recovery_status.setToolTip(
                    "Restorable: Windows Firewall policy. Observational only: hardware, "
                    "services, listening ports, and network context."
                )
            else:
                if recovery.get("supported") is False:
                    self.recovery_status.setText("Recovery: Windows Firewall unsupported")
                else:
                    self.recovery_status.setText("Recovery: Firewall baseline not captured")
                self.recovery_status.setToolTip(str(recovery.get("detail") or ""))
        except Exception as exc:
            self.recovery_status.setText(f"Recovery: integrity warning ({exc})")
        if self._latest_report:
            gaps = list(dict.fromkeys(
                list(self._latest_report.get("skipped_incomplete_collectors") or [])
                + list(self._latest_report.get("incomplete_collectors") or [])
            ))
            if gaps:
                self.risk_status.setText(
                    f"Drift risk: unavailable · coverage incomplete ({len(gaps)})"
                )
            else:
                self.risk_status.setText(
                    f"Drift risk: {float(self._latest_report.get('risk_score', 0)):.1f}/100"
                )
        try:
            breaker = self.service.breaker_status()
            if breaker.get("locked"):
                self.breaker_status_label.setText("Circuit breaker: LOCKED")
                self.breaker_status_label.setStyleSheet(
                    "padding:6px 10px; border:1px solid #ef4444; border-radius:6px; "
                    "background:#450a0a; color:#fecaca;"
                )
            else:
                self.breaker_status_label.setText(
                    f"Circuit breaker: ready · {len(breaker.get('events', []))} recent"
                )
        except Exception as exc:
            self.breaker_status_label.setText(f"Circuit breaker: unavailable ({exc})")

    def _load_persisted_views(self) -> None:
        self._profile_changed()
        self._trigger_kind_changed()
        # Exceptions/weights and triggers live in the same signed state store;
        # share one verified read instead of parsing it once per table.
        state = self.service.state()
        self._refresh_exceptions(state)
        self._refresh_snapshots()
        self._refresh_triggers(state)
        self._refresh_activity()
        self._refresh_status()

    def refresh_after_automatic_cycle(self, status: str) -> None:
        """Refresh only views an automatic cycle could have changed."""
        if status == "applied":
            self._refresh_snapshots()
            self._refresh_activity()
            self._refresh_status()
        elif status in {"proposed", "context-changed"}:
            self._refresh_activity()

    # ── Help and lifecycle ─────────────────────────────────────────────────
    def _show_safety_help(self) -> None:
        QMessageBox.information(
            self,
            "Adaptation safety model",
            "Observation, planning, sandboxing, execution, and rollback are separate stages.\n\n"
            "Plans are immutable, expire after ten minutes, and bind to the current firewall "
            "digest. Apply requires exact-plan approval, a rollback snapshot, a closed command "
            "catalog, an explicitly enrolled immutable recovery baseline, a durable transaction "
            "journal, and a closed circuit breaker. Context monitoring is proposal-only. "
            "Rollback verifies both manifest and firewall artifact digests.",
        )

    def _show_phase_help(self) -> None:
        QMessageBox.information(
            self,
            "Adaptation phases",
            "Phase 1: audit, baseline, drift, exact exceptions, JSON/CSV export.\n\n"
            "Phase 2: intent profiles, exact dry-run commands, no-write sandbox, automatic "
            "snapshot, explicit apply, and one-click rollback.\n\n"
            "Phase 3: SSID/VPN/Public triggers, proposal-only monitoring, bounded feedback "
            "tuning, cooldowns, and a persistent circuit breaker.",
        )

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        if self._busy_task in {
            "apply", "rollback", "restore_security_baseline",
            "capture_security_baseline",
        }:
            QMessageBox.information(
                self, "Adaptation operation active",
                "Keep this window open until the host-change or recovery operation finishes."
            )
            event.ignore()
            return
        super().closeEvent(event)
