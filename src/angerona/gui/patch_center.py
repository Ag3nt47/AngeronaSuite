"""Modeless exact-report review and typed host-control patch workspace."""
from __future__ import annotations

import json
import queue
import threading

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QGridLayout,
    QHeaderView, QLabel, QLayout, QPlainTextEdit, QPushButton, QSplitter,
    QTableWidget, QTableWidgetItem, QVBoxLayout)

from angerona.core.patch_center import PatchReviewService
from angerona.gui.animations import begin_loading, finish_loading
from angerona.gui.progress_ring import ProgressRing
from angerona.gui.window_controls import configure_work_window
from angerona.gui.window_fit import install_window_fit


class _ClickControl(QComboBox):
    def wheelEvent(self, event):  # noqa: N802
        event.ignore()


class AngeronaPatchDialog(QDialog):
    """Native writes stay on one owned worker and require a reviewed exact plan."""

    def __init__(self, posture, handoff, parent=None, *, open_source=None):
        super().__init__(parent)
        self.setWindowTitle("AngeronaPatch — Verified gaps and typed controls")
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.setMinimumSize(600, 450)
        self.resize(1020, 760)
        self._service = PatchReviewService(posture, handoff)
        self._snapshot = {}
        self._plan = None
        self._rollback_plan = None
        self._worker = None
        self._operation_generation = None
        self._loading_token = None
        self._mutation_admitted = False
        self._results = queue.Queue(maxsize=1)
        self._close_requested = False
        self._open_source = open_source
        self._angerona_preserve_on_close = True
        self._angerona_work_window_retained = False
        root = QVBoxLayout(self)
        root.setSizeConstraint(QLayout.SizeConstraint.SetNoConstraint)
        root.setContentsMargins(12, 12, 12, 12)
        self.status = QLabel("Loading exact report and patch history…")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setMinimumWidth(0)
        root.addWidget(self.status)
        self.last_result = QLabel("No host control has been applied from this review.")
        self.last_result.setTextFormat(Qt.TextFormat.PlainText)
        self.last_result.setWordWrap(True)
        root.addWidget(self.last_result)
        explanation = QLabel(
            "Review one reported gap and one fixed OS control. A registry setting and its "
            "signed receipt do not prove a Windows exploit was patched or detector coverage restored.")
        explanation.setWordWrap(True)
        explanation.setMinimumWidth(0)
        root.addWidget(explanation)
        self.progress = ProgressRing(getattr(parent, "config", None), diameter=44, scope="patch workflow")
        root.addWidget(self.progress, 0, Qt.AlignmentFlag.AlignLeft)
        self.gaps = QTableWidget(0, 5)
        self.gaps.setHorizontalHeaderLabels(["Technique", "Gap", "Occurrences", "Scope", "Reported finding"])
        self.gaps.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.gaps.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.gaps.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.gaps.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.gaps.itemSelectionChanged.connect(self._gap_selected)
        self.controls = _ClickControl()
        self.controls.setToolTip("Click to choose one fixed reviewed control; scrolling does not change selection")
        self.controls.currentIndexChanged.connect(self._control_changed)
        self.attempts = QTableWidget(0, 4)
        self.attempts.setHorizontalHeaderLabels(["Patch attempt", "Control", "Transaction", "Fresh native check"])
        self.attempts.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.attempts.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.attempts.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.attempts.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.attempts.itemSelectionChanged.connect(self._attempt_selected)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        splitter = QSplitter(Qt.Orientation.Vertical)
        for widget in (self.gaps, self.attempts, self.details):
            widget.setMinimumHeight(0)
            splitter.addWidget(widget)
        splitter.setSizes([190, 150, 180])
        root.addWidget(splitter, 1)
        root.addWidget(self.controls)
        actions = QGridLayout()
        self.refresh_button = QPushButton("Refresh report / history")
        self.plan_button = QPushButton("Review selected control")
        self.apply_button = QPushButton("Apply reviewed control")
        self.retest_button = QPushButton("Retest native state")
        self.rollback_button = QPushButton("Review rollback")
        self.recover_button = QPushButton("Recover transaction")
        self.source_button = QPushButton("Open source sandbox")
        close = QPushButton("Close")
        buttons = (self.refresh_button, self.plan_button, self.apply_button,
                   self.retest_button, self.rollback_button, self.recover_button,
                   self.source_button, close)
        for index, button in enumerate(buttons):
            actions.addWidget(button, index // 3, index % 3)
        root.addLayout(actions)
        self.history_status = QLabel()
        self.history_status.setWordWrap(True)
        root.addWidget(self.history_status)
        self.refresh_button.clicked.connect(self.refresh)
        self.plan_button.clicked.connect(self._build_plan)
        self.apply_button.clicked.connect(self._apply)
        self.retest_button.clicked.connect(lambda: self._attempt_action("retest"))
        self.rollback_button.clicked.connect(lambda: self._attempt_action("rollback"))
        self.recover_button.clicked.connect(lambda: self._attempt_action("recover"))
        self.source_button.clicked.connect(self._source)
        close.clicked.connect(self.close)
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._poll)
        configure_work_window(self)
        install_window_fit(self)
        self._availability()
        self.refresh()

    def has_active_work(self):
        return self._worker is not None

    def _selected(self, table):
        rows = table.selectionModel().selectedRows()
        item = table.item(rows[0].row(), 0) if rows else None
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _gap_selected(self):
        selected = self._selected(self.gaps)
        gap = next((row for row in self._snapshot.get("gaps", []) if row["gap_id"] == selected), None)
        self.controls.blockSignals(True)
        self.controls.clear()
        for control in gap.get("controls", []) if gap else []:
            self.controls.addItem(control["title"], control["control_id"])
        self.controls.blockSignals(False)
        self._plan = None
        if gap:
            self.details.setPlainText(json.dumps(gap, indent=2, ensure_ascii=False))
        self._availability()

    def _control_changed(self, *_unused):
        self._plan = None
        self.last_result.setText("Control selection changed; build and inspect a new exact plan before applying.")
        self._availability()

    def _attempt_selected(self):
        self._rollback_plan = None
        identity = self._selected(self.attempts)
        attempt = next((row for row in self._snapshot.get("memory", {}).get("attempts", [])
                        if row.get("attempt_id") == identity), None)
        if attempt:
            self.details.setPlainText(json.dumps(attempt, indent=2, ensure_ascii=False))
        self._availability()

    def _availability(self, *_unused):
        busy = self.has_active_work() or self._close_requested
        authority = self._snapshot.get("authority", {})
        allowed = authority.get("allowed") is True
        gap_selected = self._selected(self.gaps) if hasattr(self, "gaps") else None
        attempt_id = self._selected(self.attempts) if hasattr(self, "attempts") else None
        attempt = next((row for row in self._snapshot.get("memory", {}).get("attempts", [])
                        if row.get("attempt_id") == attempt_id), {})
        self.refresh_button.setEnabled(not busy)
        self.plan_button.setEnabled(not busy and self._snapshot.get("report_state") == "verified-practice"
                                    and bool(gap_selected and self.controls.currentData()))
        plan_authority = self._plan.get("authority", {}) if self._plan else {}
        self.apply_button.setEnabled(not busy and allowed and plan_authority.get("allowed") is True
                                     and bool(self._plan and self._plan.get("change_needed")))
        self.apply_button.setToolTip(plan_authority.get("reason") or authority.get("reason", "Review and select one exact plan first"))
        has_receipt = type(attempt.get("transaction_id")) is int and bool(attempt.get("receipt_hash"))
        self.retest_button.setEnabled(not busy and has_receipt)
        self.rollback_button.setEnabled(not busy and allowed and has_receipt
                                        and attempt.get("state") == "applied-verified")
        self.rollback_button.setText("Apply reviewed rollback" if self._rollback_plan
            and self._rollback_plan.get("attempt_id") == attempt_id else "Review rollback")
        self.rollback_button.setToolTip("Restore only this exact control's authenticated retained prior state; current native state must still match. "
                                       + str(authority.get("reason", "")))
        self.recover_button.setEnabled(not busy and allowed and bool(attempt.get("recovery_required") or attempt.get("rollback_recovery_required")))
        self.recover_button.setToolTip("Existing durable recovery only; this is not an applied-action rollback shortcut")
        self.source_button.setEnabled(not busy and callable(self._open_source))
        if not callable(self._open_source):
            self.source_button.setToolTip("No source sandbox callback is available in this workspace")

    def _start(self, operation, work):
        if self.has_active_work() or self._close_requested:
            return False
        owner = self.parent()
        admit = getattr(owner, "_admit_aar_work", None)
        self._mutation_admitted = False
        if operation in {"apply", "rollback", "recover"} and callable(admit):
            if not admit(self, "patch"):
                self.status.setText("Patch action held while another drill, report action or shutdown is active.")
                return False
            self._mutation_admitted = True
        generation = object()
        try:
            token = begin_loading("AngeronaPatch · " + operation)
        except Exception as exc:
            if self._mutation_admitted:
                release = getattr(owner, "_release_aar_work", None)
                if callable(release):
                    release(self)
                self._mutation_admitted = False
            self.status.setText("Progress ownership unavailable: " + str(exc)[:300])
            return False
        self._operation_generation, self._loading_token = generation, token
        results = self._results
        def run():
            try:
                value = work()
            except Exception as exc:
                value = {"ok": False, "state": "held-or-failed", "reason": str(exc)[:512]}
            results.put_nowait((generation, operation, value))
        worker = threading.Thread(target=run, name="AngeronaPatch-" + operation, daemon=True)
        self._worker = worker
        self._angerona_work_window_retained = True
        self.progress.set_state(None, None, True)
        self.status.setText(operation.capitalize() + " in progress…")
        try:
            worker.start()
        except Exception as exc:
            finish_loading(token)
            self._loading_token = None
            self._operation_generation = None
            if self._mutation_admitted:
                release = getattr(owner, "_release_aar_work", None)
                if callable(release):
                    release(self)
                self._mutation_admitted = False
            self._worker = None
            self._angerona_work_window_retained = False
            self.progress.set_state(None, None, False)
            self.status.setText("Worker start held: " + str(exc)[:300])
            self._availability()
            return False
        self._timer.start()
        self._availability()
        return True

    def refresh(self):
        return self._start("refresh", self._service.snapshot)

    def _build_plan(self):
        gap_id, control_id, service = self._selected(self.gaps), self.controls.currentData(), self._service
        return self._start("plan", lambda: service.build_plan(gap_id, control_id))

    def _apply(self):
        if not self._plan:
            return
        # This explicit button applies only the concrete displayed plan. No
        # all-findings loop, environment toggle, elevation request or AI code.
        plan_id, service = self._plan["plan_id"], self._service
        self._plan = None
        return self._start("apply", lambda: service.apply(plan_id, approved=True))

    def _attempt_action(self, operation):
        attempt_id, service = self._selected(self.attempts), self._service
        if not attempt_id:
            return
        if operation == "retest":
            return self._start(operation, lambda: service.retest(attempt_id))
        if operation == "rollback":
            if self._rollback_plan and self._rollback_plan.get("attempt_id") == attempt_id:
                plan_id = self._rollback_plan["rollback_plan_id"]
                self._rollback_plan = None
                return self._start(operation, lambda: service.rollback(attempt_id, approved=True, rollback_plan_id=plan_id))
            return self._start("rollback-review", lambda: service.review_rollback(attempt_id))
        if operation == "recover":
            return self._start(operation, lambda: service.recover(attempt_id, approved=True))

    def _source(self):
        if callable(self._open_source):
            self._open_source()

    def _render_snapshot(self, snapshot):
        selected_gap, selected_attempt = self._selected(self.gaps), self._selected(self.attempts)
        gap_scroll, attempt_scroll = self.gaps.verticalScrollBar().value(), self.attempts.verticalScrollBar().value()
        self._snapshot = snapshot
        authority = snapshot.get("authority", {})
        self.status.setText(
            f"Report: {snapshot.get('report_state', 'unverified')} · "
            + ("Installed host authority available. " if authority.get("allowed") else "Host actions held. ")
            + str(authority.get("reason") or snapshot.get("reason") or ""))
        self.gaps.blockSignals(True)
        self.gaps.setRowCount(len(snapshot.get("gaps", [])))
        for index, row in enumerate(snapshot.get("gaps", [])):
            values = (row["technique"], row["gap_kind"], row["occurrences_in_report"], row["evidence_scope"], row["name"])
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, row["gap_id"])
                self.gaps.setItem(index, column, item)
            if row["gap_id"] == selected_gap:
                self.gaps.selectRow(index)
        self.gaps.blockSignals(False)
        self.gaps.verticalScrollBar().setValue(gap_scroll)
        memory = snapshot.get("memory", {})
        attempts = memory.get("attempts", [])
        self.attempts.blockSignals(True)
        self.attempts.setRowCount(len(attempts))
        for index, row in enumerate(attempts):
            values = (row.get("state", "unknown"), row.get("control_id", ""), row.get("transaction_id", "—"), row.get("watch_state", "not rechecked"))
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, row["attempt_id"])
                self.attempts.setItem(index, column, item)
            if row["attempt_id"] == selected_attempt:
                self.attempts.selectRow(index)
        self.attempts.blockSignals(False)
        self.attempts.verticalScrollBar().setValue(attempt_scroll)
        self.history_status.setText(
            f"Historical gap classes shown: {len(memory.get('gaps', []))}/{memory.get('totals', {}).get('gaps', 'unknown')}; "
            f"attempts: {len(attempts)}/{memory.get('totals', {}).get('attempts', 'unknown')}; "
            f"unverified index rows: {memory.get('unverified_rows', 'unknown')}; "
            f"held history admissions: {memory.get('admission_held', 'unknown')}. "
            "Original evidence is retained separately; the local index is bounded.")

    def _poll(self):
        if self._worker is None or self._worker.is_alive():
            return
        try:
            generation, operation, value = self._results.get_nowait()
        except queue.Empty:
            generation, operation, value = self._operation_generation, "unknown", {"ok": False, "reason": "Owned worker returned without a result"}
        if generation is not self._operation_generation:
            return  # Never let an old result release the current token/owner.
        finish_loading(self._loading_token)
        self._loading_token = self._operation_generation = None
        if self._mutation_admitted:
            release = getattr(self.parent(), "_release_aar_work", None)
            if callable(release):
                release(self)
            self._mutation_admitted = False
        self._worker = None
        self._angerona_work_window_retained = False
        self._timer.stop()
        self.progress.set_state(1, 1, False) if value.get("ok") is not False else self.progress.set_state(None, None, False)
        if operation == "refresh" and type(value) is dict and "report_state" in value:
            self._render_snapshot(value)
        else:
            self.details.setPlainText(json.dumps(value, indent=2, ensure_ascii=False, default=str))
            if operation == "plan" and type(value) is dict and value.get("plan_id"):
                self._plan = value
            if operation == "rollback-review" and type(value) is dict and value.get("rollback_plan_id"):
                self._rollback_plan = value
            self.last_result.setText(
                operation.capitalize() + " · " + str(value.get("state") or "review ready")
                + (" · reported detector/response gap remains open" if value.get("gap_closed") is False else ""))
            self.status.setText(operation.capitalize() + " · " + str(value.get("state") or "review ready"))
        self._availability()
        if self._close_requested:
            self._close_requested = False
            self.close()
        elif operation in {"apply", "rollback", "recover", "retest"}:
            self.refresh()

    def showEvent(self, event):  # noqa: N802
        self._close_requested = False
        super().showEvent(event)

    def closeEvent(self, event):  # noqa: N802
        if self.has_active_work():
            self._close_requested = True
            self.hide()
            event.ignore()
            return
        self._timer.stop()
        self.progress.set_state(None, None, False)
        super().closeEvent(event)
