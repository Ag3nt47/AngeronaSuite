"""Operator workbench for safe, local host adaptation."""
from __future__ import annotations

import json
import queue
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QEvent, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractScrollArea,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenuBar,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStyle,
    QStyleOptionButton,
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
from angerona.gui.window_controls import configure_work_window


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

_STATUS_READS = (
    ("baseline", "load_baseline"),
    ("recovery", "security_baseline_status"),
    ("breaker", "breaker_status"),
    ("transactions", "transactions"),
    ("state", "state"),
    ("exceptions", "list_exceptions"),
    ("snapshots", "list_snapshots"),
    ("activity", "activity"),
)
_CORE_STATUS_VIEWS = ("baseline", "recovery", "breaker", "transactions")


def _wrap_label(label: QLabel) -> QLabel:
    """Keep literal content available when a page is narrower than its text."""
    label.setWordWrap(True)
    label.setTextFormat(Qt.PlainText)
    label.setMinimumWidth(0)
    policy = label.sizePolicy()
    policy.setHorizontalPolicy(QSizePolicy.Ignored)
    policy.setHeightForWidth(True)
    label.setSizePolicy(policy)
    return label


def _fit_dialog(dialog: QDialog, width: int, height: int) -> None:
    dialog.setMinimumSize(280, 280)
    screen = dialog.screen() or QApplication.primaryScreen()
    available = screen.availableGeometry() if screen is not None else None
    dialog.resize(
        min(width, max(280, available.width() - 32)) if available is not None else width,
        min(height, max(280, available.height() - 48)) if available is not None else height,
    )


class _AdaptiveRow(QWidget):
    """Reflow existing controls against the owning page and scroll viewport.

    An old child's minimum width must never become the next width budget.
    Full button captions remain in tooltips/accessibility when a compact
    caption is necessary; the existing signals and controls are retained.
    """

    _COMPACT = {
        "Choose an adaptation profile…": "Choose profile…",
        "Run safe automatic checkup": "Safe checkup",
        "Save as golden baseline…": "Save audit baseline…",
        "Pin selected as known-good exception…": "Pin known-good exception…",
        "Dismiss false positive + tune score…": "Dismiss false positive…",
        "3. ADAPT HOST with this preview…": "3. Apply exact preview…",
        "Roll back selected snapshot…": "Roll back snapshot…",
        "Capture immutable host baseline…": "Capture recovery baseline…",
        "Restore host baseline…": "Restore recovery baseline…",
        "Run no-write simulation": "Run simulation",
        "Evaluate current context now": "Evaluate context",
        "Approve exact operation": "Approve operation",
    }

    def __init__(self, name: str, widgets: tuple[QWidget, ...], *, columns: int = 5) -> None:
        super().__init__()
        self.setObjectName(name)
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self._widgets = widgets
        self._max_columns = columns
        self._columns: int | None = None
        self._watching: tuple[QWidget, ...] = ()
        self._reflowing = False
        self._captions: dict[QPushButton, str] = {}
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setHorizontalSpacing(8)
        self._grid.setVerticalSpacing(6)
        for widget in widgets:
            widget.setMinimumWidth(0)
            if isinstance(widget, QLabel):
                _wrap_label(widget)
            elif isinstance(widget, QPushButton):
                caption = widget.text()
                self._captions[widget] = caption
                widget.setAccessibleName(caption)
                if not widget.toolTip():
                    widget.setToolTip(caption)
                policy = widget.sizePolicy()
                policy.setHorizontalPolicy(QSizePolicy.Ignored)
                widget.setSizePolicy(policy)
        self._reflow()

    def _ancestors(self) -> tuple[QWidget, ...]:
        watched = []
        parent = self.parentWidget()
        if parent is not None:
            watched.append(parent)
        ancestor = parent
        while ancestor is not None:
            if isinstance(ancestor, QAbstractScrollArea):
                viewport = ancestor.viewport()
                if viewport not in watched:
                    watched.append(viewport)
                break
            ancestor = ancestor.parentWidget()
        return tuple(watched)

    def _budget(self) -> int:
        watched = self._ancestors()
        if watched != self._watching:
            for widget in self._watching:
                try:
                    widget.removeEventFilter(self)
                except RuntimeError:
                    pass
            self._watching = watched
            for widget in watched:
                widget.installEventFilter(self)
        width = min((widget.contentsRect().width() for widget in watched), default=self.contentsRect().width())
        parent = self.parentWidget()
        if parent is not None and parent.layout() is not None:
            margins = parent.layout().contentsMargins()
            width -= margins.left() + margins.right()
        return max(0, width)

    def _button_width(self, button: QPushButton, text: str) -> int:
        option = QStyleOptionButton()
        option.initFrom(button)
        option.text = text
        size = QSize(button.fontMetrics().horizontalAdvance(text), button.fontMetrics().height())
        return button.style().sizeFromContents(QStyle.CT_PushButton, option, size, button).width()

    def _reflow(self) -> None:
        if not hasattr(self, "_widgets") or self._reflowing:
            return
        self._reflowing = True
        try:
            available = self._budget()
            widths = []
            for widget in self._widgets:
                widget.ensurePolished()
                if isinstance(widget, QPushButton):
                    width = self._button_width(widget, self._captions[widget])
                else:
                    width = min(280, max(140, widget.sizeHint().width()))
                widths.append(width)
            gap = max(0, self._grid.horizontalSpacing())
            columns = 1
            for count in range(min(self._max_columns, len(widths)), 0, -1):
                required = sum(max(widths[column::count]) for column in range(count)) + gap * (count - 1)
                if required <= available:
                    columns = count
                    break
            if columns != self._columns:
                self._columns = columns
                for widget in self._widgets:
                    self._grid.removeWidget(widget)
                for column in range(self._grid.columnCount()):
                    self._grid.setColumnStretch(column, 0)
                for index, widget in enumerate(self._widgets):
                    self._grid.addWidget(widget, index // columns, index % columns)
                for column in range(columns):
                    self._grid.setColumnStretch(column, 1)
            cell_width = max(0, (available - gap * (columns - 1)) // columns)
            for button, full in self._captions.items():
                caption = full
                if self._button_width(button, full) > cell_width:
                    caption = self._COMPACT.get(full, full)
                if self._button_width(button, caption) > cell_width:
                    padding = max(16, self._button_width(button, "") + 4)
                    caption = button.fontMetrics().elidedText(caption, Qt.ElideRight, max(0, cell_width - padding))
                if button.text() != caption:
                    button.setText(caption)
        finally:
            self._reflowing = False

    def eventFilter(self, watched, event):  # noqa: N802 - Qt signature
        if watched in self._watching and event.type() in (QEvent.Resize, QEvent.LayoutRequest, QEvent.ParentChange):
            self._reflow()
        return False

    def event(self, event):
        result = super().event(event)
        if event.type() in (QEvent.ParentChange, QEvent.LayoutRequest, QEvent.FontChange, QEvent.StyleChange):
            self._reflow()
        return result

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        super().resizeEvent(event)
        self._reflow()


def _scroll_surface(content: QWidget, name: str) -> QScrollArea:
    surface = QScrollArea()
    surface.setObjectName(name)
    surface.setWidgetResizable(True)
    surface.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    surface.setFrameShape(QFrame.NoFrame)
    surface.setMinimumWidth(0)
    surface.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
    content.setMinimumWidth(0)
    content.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
    surface.setWidget(content)
    return surface


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
        heading = _wrap_label(QLabel(title))
        heading.setStyleSheet("font-weight:700; color:#67e8f9;")
        body = _wrap_label(QLabel(text))
        body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(heading)
        layout.addWidget(body)


class AdaptationWorkbench(QDialog):
    """Complete audit, profile, sandbox, and feedback surface.

    Potentially slow host inspection and every broker call runs off the GUI
    thread. Profile mutation and rollback cannot be dismissed while active.
    """

    _task_finished = Signal(str, object, object)
    _status_finished = Signal(object)

    def __init__(
        self,
        service: HostAdaptationService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose, False)
        self.service = service
        self._latest_report: dict[str, Any] | None = None
        self._latest_plan: AdaptationPlan | None = None
        self._latest_review: dict[str, Any] | None = None
        self._review_generation = 0
        self._baseline_consent_sequence = 0
        self._auto_intent_dialog: QDialog | None = None
        self._notice_dialogs: list[QDialog] = []
        self._confirmation_dialogs: list[QDialog] = []
        self._task_thread: threading.Thread | None = None
        self._status_thread: threading.Thread | None = None
        self._task_generation = -1
        self._status_generation = -1
        self._results: queue.Queue[tuple[str, int, str, Any, Any]] = queue.Queue(maxsize=2)
        self._view_retired = threading.Event()
        self._lifecycle_generation = 0
        self.destroyed.connect(lambda *_args, retired=self._view_retired: retired.set())
        self._result_timer = QTimer(self)
        self._result_timer.setInterval(50)
        self._result_timer.timeout.connect(self._poll_results)
        self._busy_task = ""
        self._status_active = False
        self._status_dirty = False
        self._pending_status_views: set[str] = set()
        self._requested_status_views: tuple[str, ...] | None = None
        self._reopen_refresh = False
        self._automation_initialized = False
        self._automation_edited = False
        self._persisted_errors: dict[str, str] = {}
        self._weights_text = "Adaptive scoring: default 1.0× in every category"
        self._recovery_view: dict[str, Any] = {"available": False, "checking": True}
        # Persisted views can be refreshed by both operator actions and the
        # dashboard context monitor.  Retain small, bounded row signatures so
        # an unchanged poll does not discard and recreate hundreds of Qt items.
        self._view_signatures: dict[str, tuple[Any, ...]] = {}
        self.setWindowTitle("Adaptation — Adapt to Host")
        _fit_dialog(self, 1160, 780)
        self.setSizeGripEnabled(True)
        configure_work_window(self)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        content = QWidget()
        self._workbench_scroll = _scroll_surface(content, "adaptation_workbench_scroll")
        outer.addWidget(self._workbench_scroll)
        root = QVBoxLayout(content)
        root.setContentsMargins(14, 10, 14, 12)
        root.setSpacing(9)
        outer.setMenuBar(self._build_menu())

        heading = QLabel("ADAPTATION")
        heading.setStyleSheet("font-size:22px; font-weight:800; color:#67e8f9;")
        subtitle = QLabel("Adapt to Host  ·  local, reversible, operator-controlled")
        subtitle.setStyleSheet("color:#94a3b8;")
        self.adapt_host_button = QPushButton("AUTO ADAPT…")
        self.adapt_host_button.setObjectName("Primary")
        self.adapt_host_button.setToolTip(
            "Choose a safe intent profile, preview it, test it, and adapt this host."
        )
        self.adapt_host_button.clicked.connect(self._show_auto_adapt)
        self.busy_label = QLabel("Ready")
        self.busy_label.setStyleSheet("color:#5eead4; font-weight:600;")
        root.addWidget(_AdaptiveRow(
            "adaptation_heading", (heading, subtitle, self.adapt_host_button, self.busy_label), columns=4,
        ))

        self.baseline_status = QLabel("Baseline: checking…")
        self.recovery_status = QLabel("Recovery baseline: checking…")
        self.risk_status = QLabel("Drift risk: —")
        self.context_status = QLabel("Context: not sampled")
        self.breaker_status_label = QLabel("Circuit breaker: checking…")
        for label in (
            self.baseline_status, self.recovery_status, self.risk_status,
            self.context_status, self.breaker_status_label,
        ):
            label.setTextFormat(Qt.PlainText)
            label.setStyleSheet(
                "padding:6px 10px; border:1px solid #334155; border-radius:6px; "
                "background:#0f172a; color:#cbd5e1;"
            )
        root.addWidget(_AdaptiveRow(
            "adaptation_status", (self.baseline_status, self.recovery_status, self.risk_status,
                                    self.context_status, self.breaker_status_label),
        ))

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setMinimumSize(0, 340)
        self.tabs.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        self.tabs.setUsesScrollButtons(True)
        self.tabs.tabBar().setExpanding(False)
        self.tabs.addTab(_scroll_surface(self._build_overview_tab(), "adaptation_overview_scroll"), "Overview")
        self.tabs.addTab(_scroll_surface(self._build_audit_tab(), "adaptation_audit_scroll"), "Audit + Drift")
        self.tabs.addTab(_scroll_surface(self._build_exceptions_tab(), "adaptation_exceptions_scroll"), "Exceptions + Feedback")
        self.adapt_tab_index = self.tabs.addTab(_scroll_surface(self._build_profiles_tab(), "adaptation_profiles_scroll"), "Adapt Host")
        self.tabs.addTab(_scroll_surface(self._build_sandbox_tab(), "adaptation_sandbox_scroll"), "Sandbox")
        self.tabs.addTab(_scroll_surface(self._build_automation_tab(), "adaptation_automation_scroll"), "Automation")
        self.tabs.addTab(_scroll_surface(self._build_activity_tab(), "adaptation_activity_scroll"), "Activity")
        for label in self.tabs.findChildren(QLabel):
            _wrap_label(label)
        from angerona.gui.recovery_panel import RecoveryPanel
        self.recovery_panel = RecoveryPanel(getattr(parent, "manager", None), self)
        self.tabs.addTab(self.recovery_panel, "Independent Recovery")
        from angerona.gui.prevention_panel import PreventionPanel
        self.prevention_panel = PreventionPanel(getattr(parent, "manager", None), self)
        self.tabs.addTab(self.prevention_panel, "Windows Prevention")
        root.addWidget(self.tabs, 1)

        self.footer_detail = QLabel(
            "No host change occurs until an exact plan is previewed and confirmed."
        )
        self.footer_detail.setStyleSheet("color:#94a3b8;")
        self.footer_detail.setWordWrap(True)
        self.footer_detail.setTextFormat(Qt.PlainText)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        root.addWidget(_AdaptiveRow(
            "adaptation_footer", (self.footer_detail, close), columns=2,
        ))

        self._task_finished.connect(self._on_task_finished)
        self._status_finished.connect(self._on_status_finished)
        self._profile_changed()
        self._trigger_kind_changed()
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
        if self._view_retired.is_set():
            return
        if self._busy_task:
            self._show_notice(
                "Adaptation busy",
                f"{self._busy_task.replace('_', ' ').title()} is still running. "
                "Finish it before opening a new Auto Adapt request.",
            )
            return
        if self._auto_intent_dialog is not None:
            if self._auto_intent_dialog.isMinimized():
                self._auto_intent_dialog.showNormal()
            else:
                self._auto_intent_dialog.show()
            self._auto_intent_dialog.raise_()
            self._auto_intent_dialog.activateWindow()
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Auto Adapt — choose security intent")
        _fit_dialog(dialog, 680, 540)
        outer = QVBoxLayout(dialog)
        content = QWidget()
        outer.addWidget(_scroll_surface(content, "adaptation_intent_scroll"))
        layout = QVBoxLayout(content)
        layout.addWidget(_InfoPanel(
            "Guided, deterministic Auto Adapt",
            "Angerona runs a fresh deep audit, builds an immutable closed-catalog plan, "
            "and tests the projected change without writing. Preview-only is the safe "
            "default. If apply is selected, one final exact-plan approval is still required.",
        ))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        profile = self._profile_combo()
        form.addRow("Security intent:", profile)
        apply_after = QCheckBox("Ask to apply")
        apply_after.setAccessibleName("Ask to apply after the automatic review")
        apply_after.setChecked(False)
        apply_after.setToolTip(
            "Never applies silently; the final dialog includes exact commands and rollback coverage."
        )
        form.addRow("Host change:", apply_after)
        recovery_before = self._recovery_view
        capture_recovery = QCheckBox("Enroll baseline")
        capture_recovery.setAccessibleName("Explicitly capture the immutable firewall recovery baseline if missing")
        capture_recovery.setChecked(
            bool(recovery_before.get("supported", True))
            and not bool(recovery_before.get("available"))
        )
        capture_recovery.setEnabled(bool(recovery_before.get("supported", True)))
        capture_recovery.setToolTip(
            "This is a permanent, non-replaceable recovery enrollment. It is separate "
            "from the temporary snapshot created immediately before every apply."
        )
        form.addRow("Recovery:", capture_recovery)
        for field in (profile, apply_after, capture_recovery):
            label = form.labelForField(field)
            if isinstance(label, QLabel):
                _wrap_label(label)
        layout.addLayout(form)
        coverage = QLabel(
            "Automatic phases: deep audit → collector completeness gate → immutable plan → "
            "no-write sandbox → recommendation. Emergency Lockdown is never auto-applied "
            "without its separate warning."
        )
        _wrap_label(coverage)
        coverage.setTextFormat(Qt.PlainText)
        layout.addWidget(coverage)
        cancel = QPushButton("Cancel")
        cancel.setDefault(True)
        prepare = QPushButton("Prepare automatically")
        prepare.setAutoDefault(False)
        prepare.setObjectName("Primary")
        cancel.clicked.connect(dialog.reject)
        prepare.clicked.connect(dialog.accept)
        layout.addWidget(_AdaptiveRow(
            "adaptation_intent_actions", (cancel, prepare), columns=2,
        ))
        intent_generation = self._lifecycle_generation

        def finished(answer: int) -> None:
            if self._auto_intent_dialog is dialog:
                self._auto_intent_dialog = None
            if (answer != QDialog.Accepted or self._view_retired.is_set()
                    or intent_generation != self._lifecycle_generation):
                return
            # A modeless consent screen cannot queue an earlier request behind
            # work that began while it was open. Copy choices before dispatch.
            if self._busy_task:
                self._show_notice("Adaptation busy", "The request was discarded because another operation started.")
                return
            choices = (str(profile.currentData()), bool(apply_after.isChecked()),
                       bool(capture_recovery.isChecked()))
            self._prepare_review(*choices, task="auto_prepare")

        dialog.finished.connect(finished)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        configure_work_window(dialog)
        self._auto_intent_dialog = dialog
        dialog.show()

    def _prepare_review(
        self, profile_id: str, apply_requested: bool = False,
        capture_recovery: bool = False, *, task: str = "preview",
    ) -> None:
        if self._view_retired.is_set():
            return
        if self._busy_task:
            self._show_notice("Adaptation busy", "Finish the active operation before rebuilding the preview.")
            return
        index = self.profile_combo.findData(profile_id)
        if index >= 0:
            self.profile_combo.setCurrentIndex(index)
        self._review_generation += 1
        generation = self._review_generation
        self._latest_plan = None
        self._latest_review = None
        self.apply_button.setEnabled(False)

        def operation(
            selected: str = profile_id, accepted_apply: bool = apply_requested,
            accepted_capture: bool = capture_recovery, request_generation: int = generation,
        ) -> dict[str, Any]:
            result = self.service.prepare_review(
                selected, capture_recovery=accepted_apply and accepted_capture,
            )
            return {**result, "apply_requested": accepted_apply, "generation": request_generation}

        self._run_task(task, operation)

    def _build_overview_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        start = QGroupBox("Adapt this host")
        start_layout = QVBoxLayout(start)
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
        start_layout.addWidget(_wrap_label(start_text))
        start_layout.addWidget(_AdaptiveRow(
            "adaptation_overview_actions", (auto_button, checkup_button, start_button), columns=3,
        ))
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
            "SpywareGuard and adaptation coverage",
            "Use the dedicated SpywareGuard dashboard for spyware evidence, research intake, "
            "containment status, and its opt-in emergency beacon. Adaptation audits general host "
            "configuration and proposes reversible firewall profiles. A clean drift report does "
            "not prove that spyware is absent; review SpywareGuard coverage gaps as well.",
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
        table.setMinimumSize(0, 145)
        table.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
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
        _fit_dialog(dialog, 760, 540)
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
        configure_work_window(dialog)
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
        self.audit_button = QPushButton("Run deep audit")
        self.audit_button.setObjectName("Primary")
        self.audit_button.clicked.connect(self._run_audit)
        baseline = QPushButton("Save as golden baseline…")
        baseline.clicked.connect(self._save_baseline)
        export_json = QPushButton("Export JSON…")
        export_json.clicked.connect(self._export_json)
        export_csv = QPushButton("Export CSV…")
        export_csv.clicked.connect(self._export_csv)
        layout.addWidget(_AdaptiveRow(
            "adaptation_audit_actions", (self.audit_button, baseline, export_json, export_csv), columns=4,
        ))
        self.audit_summary = QLabel("No audit has run in this session.")
        self.audit_summary.setWordWrap(True)
        layout.addWidget(self.audit_summary)
        self.findings_table = self._table([
            "Severity", "Category", "Change", "Item", "Risk", "Status",
        ])
        layout.addWidget(self.findings_table, 1)
        pin = QPushButton("Pin selected as known-good exception…")
        pin.clicked.connect(self._pin_exception)
        dismiss = QPushButton("Dismiss false positive + tune score…")
        dismiss.clicked.connect(self._dismiss_feedback)
        layout.addWidget(_AdaptiveRow(
            "adaptation_feedback_actions", (pin, dismiss), columns=2,
        ))
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
        refresh = QPushButton("Refresh exceptions")
        refresh.clicked.connect(self._refresh_exceptions)
        remove = QPushButton("Remove selected exception")
        remove.clicked.connect(self._remove_exception)
        layout.addWidget(_AdaptiveRow(
            "adaptation_exception_actions", (refresh, remove), columns=2,
        ))
        self.weights_label = QLabel("Adaptive scoring: default 1.0× in every category")
        self.weights_label.setWordWrap(True)
        layout.addWidget(self.weights_label)
        return page

    # ── Profiles and sandbox ───────────────────────────────────────────────
    def _profile_combo(self) -> QComboBox:
        combo = QComboBox()
        combo.setMinimumWidth(0)
        combo.setMinimumContentsLength(12)
        combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        combo.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        combo.currentTextChanged.connect(combo.setToolTip)
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
        self.profile_combo = self._profile_combo()
        self.profile_combo.currentIndexChanged.connect(self._profile_changed)
        preview = QPushButton("1. Preview adaptation")
        preview.clicked.connect(self._preview_profile)
        sandbox = QPushButton("2. Test in sandbox")
        sandbox.clicked.connect(self._run_sandbox)
        layout.addWidget(QLabel("Security intent — choose a preset to adjust the proposed changes:"))
        layout.addWidget(self.profile_combo)
        layout.addWidget(_AdaptiveRow(
            "adaptation_preview_actions", (preview, sandbox), columns=2,
        ))
        self.profile_description = QLabel()
        self.profile_description.setWordWrap(True)
        layout.addWidget(self.profile_description)
        self.plan_text = QPlainTextEdit()
        self.plan_text.setReadOnly(True)
        self.plan_text.setPlaceholderText("Preview a profile to see its exact commands, plan ID, expiry, and warnings.")
        layout.addWidget(self.plan_text, 1)
        self.review_summary = QLabel("Choose an intent and rebuild its exact preview before approving changes.")
        self.review_summary.setWordWrap(True)
        self.review_summary.setTextFormat(Qt.PlainText)
        layout.addWidget(self.review_summary)
        self.change_table = self._table([
            "Profile", "State", "Before", "After", "Reason", "Reversibility", "Verification",
        ])
        self.change_table.setMinimumHeight(145)
        layout.addWidget(self.change_table, 1)
        self.change_details = QPlainTextEdit()
        self.change_details.setReadOnly(True)
        self.change_details.setMinimumSize(0, 110)
        self.change_details.setMaximumHeight(220)
        self.change_details.setPlaceholderText("Select a change for its complete before/after values, reason and verification.")
        self.change_details.setAccessibleName("Complete selected adaptation change")
        self.change_table.itemSelectionChanged.connect(self._display_selected_change)
        layout.addWidget(self.change_details)
        adjustment = _wrap_label(QLabel(
            "Adjustments use Balanced, Public network, or Emergency lockdown presets. "
            "Changing the preset invalidates the exact plan and any pending approval; preview it again. "
            "Individual commands are read-only. Rollback restores the complete captured firewall policy."
        ))
        layout.addWidget(adjustment)
        copy_review = QPushButton("Copy complete review")
        copy_review.clicked.connect(lambda: QApplication.clipboard().setText(
            self.plan_text.toPlainText() + "\n\n" + json.dumps(
                (self._latest_review or {}).get("simulation") or {}, indent=2, default=str,
            )
        ))
        layout.addWidget(copy_review, 0, Qt.AlignLeft)
        self.apply_button = QPushButton("3. ADAPT HOST with this preview…")
        self.apply_button.setObjectName("Danger")
        self.apply_button.setEnabled(False)
        self.apply_button.clicked.connect(self._apply_profile)
        layout.addWidget(_AdaptiveRow(
            "adaptation_apply_actions", (self.apply_button,), columns=1,
        ))

        rollback = QGroupBox("Recovery")
        rollback.setAccessibleName("Recovery snapshots")
        rollback.setToolTip("Recovery snapshots")
        rb_layout = QVBoxLayout(rollback)
        self.snapshot_combo = QComboBox()
        self.snapshot_combo.setMinimumWidth(0)
        self.snapshot_combo.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.snapshot_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.snapshot_combo.setMinimumContentsLength(12)
        self.snapshot_combo.currentTextChanged.connect(self.snapshot_combo.setToolTip)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_snapshots)
        rollback_button = QPushButton("Roll back selected snapshot…")
        rollback_button.clicked.connect(self._rollback_selected)
        capture_baseline = QPushButton("Capture immutable host baseline…")
        capture_baseline.clicked.connect(self._capture_security_baseline)
        restore_baseline = QPushButton("Restore host baseline…")
        restore_baseline.clicked.connect(self._restore_security_baseline)
        rb_layout.addWidget(self.snapshot_combo)
        self.snapshot_status = _wrap_label(QLabel("Recovery snapshots: checking…"))
        rb_layout.addWidget(self.snapshot_status)
        rb_layout.addWidget(_AdaptiveRow(
            "adaptation_recovery_actions", (refresh, rollback_button, capture_baseline, restore_baseline), columns=4,
        ))
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
        self.sandbox_profile_combo = self._profile_combo()
        run = QPushButton("Run no-write simulation")
        run.setObjectName("Primary")
        run.clicked.connect(self._run_sandbox)
        layout.addWidget(QLabel("Profile:"))
        layout.addWidget(self.sandbox_profile_combo)
        layout.addWidget(_AdaptiveRow("adaptation_sandbox_actions", (run,), columns=1))
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
            "Rules use an exact SSID, Windows Public category, or active VPN adapter. The "
            "strongest matching profile wins; Public context wins ties on an active public "
            "network. Rules are proposal-only: SSIDs and session hints are not "
            "authenticated liveness proof and cannot safely authorize unattended firewall "
            "changes. Use Guided Auto Adapt for the one-flow audited preview and exact approval.",
        ))
        controls = QVBoxLayout()
        self.automation_enabled = QCheckBox("Monitor configured contexts")
        self.auto_apply = QCheckBox("Unattended apply (unavailable)")
        self.auto_apply.setAccessibleName("Unattended apply disabled — exact review required")
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
        controls.addWidget(_AdaptiveRow("adaptation_context_actions", (evaluate,), columns=1))
        layout.addLayout(controls)

        rule_group = QGroupBox("Context rule")
        rule_group.setAccessibleName("Add a context rule")
        rule_group.setToolTip("Add a context rule")
        form = QFormLayout(rule_group)
        form.setRowWrapPolicy(QFormLayout.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
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
        self.trigger_status = _wrap_label(QLabel("Context rules: checking…"))
        layout.addWidget(self.trigger_status)
        remove = QPushButton("Remove selected rule")
        remove.clicked.connect(self._remove_trigger)
        reset = QPushButton("Reset circuit breaker…")
        reset.clicked.connect(self._reset_breaker)
        layout.addWidget(_AdaptiveRow(
            "adaptation_trigger_actions", (remove, reset), columns=2,
        ))
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
        self.activity_status = _wrap_label(QLabel("Activity: checking…"))
        layout.addWidget(self.activity_status)
        layout.addWidget(QLabel("Authenticated change and recovery transactions — double-click for full details"))
        self.transaction_table = self._table(["Time", "Operation", "Status", "Profile", "Rollback snapshot"])
        layout.addWidget(self.transaction_table, 1)
        self.transaction_status = _wrap_label(QLabel("Transaction history: checking…"))
        layout.addWidget(self.transaction_status)
        refresh = QPushButton("Refresh activity")
        refresh.clicked.connect(self._refresh_activity)
        layout.addWidget(refresh, 0, Qt.AlignLeft)
        return page

    # ── Background task routing ────────────────────────────────────────────
    def _result_publisher(self, kind: str, name: str = "") -> Callable[[Any, Any], None]:
        """Capture Python-only delivery state; a worker never touches Qt."""
        mailbox, retired, generation = self._results, self._view_retired, self._lifecycle_generation

        def publish(result: Any, error: Any = None) -> None:
            if retired.is_set():
                return
            try:
                mailbox.put_nowait((kind, generation, name, result, error))
            except queue.Full:
                # One task and one status reader are admitted. Preserve a held
                # lifecycle instead of ever calling a deleted C++ signal.
                retired.set()

        return publish

    def _poll_results(self) -> None:
        for _index in range(2):
            try:
                kind, generation, name, result, error = self._results.get_nowait()
            except queue.Empty:
                break
            if generation != self._lifecycle_generation or self._view_retired.is_set():
                continue
            if kind == "task":
                self._on_task_finished(name, result, error)
            else:
                self._on_status_finished(result)
        task_alive = self._task_thread is not None and self._task_thread.is_alive()
        status_alive = self._status_thread is not None and self._status_thread.is_alive()
        if not task_alive:
            self._task_thread = None
            if self._view_retired.is_set() or self._task_generation != self._lifecycle_generation:
                self._busy_task = ""
                self.audit_button.setEnabled(True)
        if not status_alive:
            self._status_thread = None
            if self._view_retired.is_set() or self._status_generation != self._lifecycle_generation:
                self._status_active = False
                self._status_dirty = bool(self._pending_status_views) and not self._view_retired.is_set()
            elif self._pending_status_views:
                self._status_active = False
        if not task_alive and not status_alive and self._results.empty():
            self._result_timer.stop()
        if not status_alive and self._pending_status_views and not self._view_retired.is_set():
            self._request_persisted_views(*tuple(self._pending_status_views))

    @staticmethod
    def _concise_error(detail: str) -> str:
        lowered = detail.casefold()
        if any(word in lowered for word in ("accessdenied", "access denied", "permission denied", "unauthorized")):
            return "Collector access is unavailable in this session. Review is retained; host changes remain held."
        return (detail.splitlines()[0] if detail else "The operation was safely held.")[:240]

    def _show_notice(self, title: str, summary: str, details: str = "") -> QDialog:
        """Retain bounded, copyable failure evidence without a nested event loop."""
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        _fit_dialog(dialog, 760, 440)
        layout = QVBoxLayout(dialog)
        label = QLabel(self._concise_error(summary))
        label.setTextFormat(Qt.PlainText)
        label.setWordWrap(True)
        layout.addWidget(label)
        body = QPlainTextEdit()
        body.setReadOnly(True)
        body.setPlainText((details or summary)[:128 * 1024])
        layout.addWidget(body, 1)
        buttons = QHBoxLayout()
        copy = QPushButton("Copy details")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(body.toPlainText()))
        close = QPushButton("Close")
        close.setDefault(True)
        close.clicked.connect(dialog.close)
        buttons.addStretch(1)
        buttons.addWidget(copy)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        self._notice_dialogs.append(dialog)
        dialog.finished.connect(lambda _answer: self._notice_dialogs.remove(dialog)
                                if dialog in self._notice_dialogs else None)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        configure_work_window(dialog)
        dialog.show()
        return dialog

    def _confirm_operation(
        self, title: str, description: str, details: str, accepted: Callable[[], None],
    ) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        _fit_dialog(dialog, 800, 560)
        layout = QVBoxLayout(dialog)
        label = QLabel(description)
        label.setTextFormat(Qt.PlainText)
        label.setWordWrap(True)
        layout.addWidget(label)
        body = QPlainTextEdit()
        body.setReadOnly(True)
        body.setPlainText(details[:128 * 1024])
        layout.addWidget(body, 1)
        cancel, approve = QPushButton("Cancel"), QPushButton("Approve exact operation")
        cancel.setDefault(True)
        approve.setAutoDefault(False)
        approve.setObjectName("Danger")
        cancel.clicked.connect(dialog.reject)
        approve.clicked.connect(dialog.accept)
        layout.addWidget(_AdaptiveRow(
            "adaptation_approval_actions", (cancel, approve), columns=2,
        ))
        self._confirmation_dialogs.append(dialog)
        confirmation_generation = self._lifecycle_generation

        def finished(answer: int) -> None:
            if dialog in self._confirmation_dialogs:
                self._confirmation_dialogs.remove(dialog)
            if (answer == QDialog.Accepted and not self._view_retired.is_set()
                    and confirmation_generation == self._lifecycle_generation):
                if self._busy_task:
                    self._show_notice("Adaptation busy", "Approval was discarded because another operation started.")
                else:
                    accepted()

        dialog.finished.connect(finished)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        configure_work_window(dialog)
        dialog.show()

    def _run_task(self, name: str, operation: Callable[[], Any]) -> None:
        if self._view_retired.is_set():
            return
        if self._busy_task or (self._task_thread is not None and self._task_thread.is_alive()):
            self._show_notice(
                "Adaptation busy", f"{self._busy_task.replace('_', ' ').title()} is still running."
            )
            return
        self._busy_task = name
        self.busy_label.setText(f"Working: {name.replace('_', ' ')}…")
        self.audit_button.setEnabled(False)
        self.apply_button.setEnabled(False)
        publish = self._result_publisher("task", name)

        def worker() -> None:
            try:
                result = operation()
            except Exception as exc:
                publish(None, exc)
            else:
                publish(result)

        task = threading.Thread(
            target=worker, name=f"HostAdaptation-{name}", daemon=True
        )
        self._task_thread = task
        self._task_generation = self._lifecycle_generation
        try:
            self._result_timer.start()
            task.start()
        except Exception as exc:
            self._task_thread = None
            self._busy_task = ""
            self.busy_label.setText("Worker unavailable")
            self.audit_button.setEnabled(True)
            self.footer_detail.setText(self._concise_error(str(exc)))
            self._show_notice("Adaptation", str(exc))

    def _on_task_finished(self, name: str, result: Any, error: Any) -> None:
        self._busy_task = ""
        self.audit_button.setEnabled(True)
        if error is not None:
            if name in {"audit", "preview", "auto_prepare"}:
                self._latest_plan = None
                self._latest_review = None
                self.apply_button.setEnabled(False)
                self.audit_summary.setText("Current review failed. Any earlier audit is retained for reference only.")
            self.busy_label.setText("Safely refused / failed")
            self.footer_detail.setText(self._concise_error(str(error)))
            self._show_notice("Adaptation", str(error))
            self._refresh_status()
            return
        self.busy_label.setText("Ready")
        if name == "audit":
            self._display_audit(result)
        elif name == "preview":
            self._display_review(result)
        elif name == "sandbox":
            self._display_sandbox(result)
        elif name == "apply":
            receipt = result.get("receipt") if isinstance(result, dict) else result
            self.apply_button.setEnabled(False)
            self._latest_plan = None
            self.plan_text.appendPlainText(
                "\nAPPLIED AND VERIFIED\n" + json.dumps(asdict(receipt), indent=2, default=str)
            )
            self.footer_detail.setText(
                f"Profile applied and verified. Recovery snapshot: {receipt.snapshot_id}"
            )
            effects = list(result.get("effects") or []) if isinstance(result, dict) else []
            self._display_effects(effects, applied=True)
            self.review_summary.setText(
                f"Applied and verified; rollback snapshot {receipt.snapshot_id}. "
                "The table shows observed postconditions from the authenticated transaction."
                if effects else
                "Apply receipt committed; detailed observed changes are unavailable in this view. Review Activity."
            )
            self._refresh_snapshots()
            self._refresh_activity()
        elif name == "rollback":
            self._profile_changed()
            self.footer_detail.setText("Rollback completed and the active profile marker was cleared.")
            self._refresh_snapshots()
            self._refresh_activity()
        elif name == "auto_prepare":
            self._display_review(result)
        elif name == "safe_checkup":
            report = dict(result.get("report") or {})
            self._display_audit(report)
            simulations = list(result.get("simulations") or ())
            holds = list(result.get("holds") or ())
            changed = sum(len(item.get("changes") or ()) for item in simulations)
            complete = result.get("complete") is True
            self.footer_detail.setText(
                f"Safe checkup {'complete' if complete else 'incomplete'}: "
                f"{len(simulations)}/{result.get('requested_profiles', len(PROFILES))} profiles simulated, "
                f"{changed} projected profile changes, host untouched."
            )
            if not complete:
                literal = "\n\n".join(
                    f"{row.get('stage', 'review')}:\n{row.get('detail', '')}" for row in holds
                )
                self._show_notice(
                    "Safe checkup incomplete", self.footer_detail.text(),
                    literal or "Complete audit and simulation coverage was not established.",
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
            profiles = self.service.profiles()
            simulations, holds = [], []

            def hold(stage: str, detail: str) -> None:
                if len(detail) > 16 * 1024:
                    detail = detail[:16 * 1024] + "\n… details truncated at 16 KiB"
                holds.append({"stage": stage, "detail": detail})

            gaps = list(dict.fromkeys(str(name) for name in (
                list(report.get("incomplete_collectors") or ())
                + list(report.get("skipped_incomplete_collectors") or ())
            )))
            if gaps:
                hold("audit coverage", "Incomplete collectors: " + ", ".join(gaps))
            for field in ("baseline_error", "comparison_error"):
                if report.get(field):
                    hold(field, str(report[field]))
            if not isinstance(current, dict):
                hold("audit", "Deep audit did not return a host snapshot; simulations were not run.")
            else:
                for profile in profiles:
                    try:
                        simulations.append(self.service.sandbox(profile.profile_id, current))
                    except Exception as exc:
                        hold(profile.profile_id, str(exc))
            return {"report": report, "simulations": simulations, "holds": holds,
                    "requested_profiles": len(profiles), "complete": not holds}

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
        if report.get("baseline_error") or report.get("comparison_error"):
            summary = "Audit retained; baseline comparison is held. Drift risk is unavailable."
        elif report.get("baseline_exists"):
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
        snapshot = report.get("current") or {}
        collection = snapshot.get("collection") or {}
        if "elapsed_ms" in collection:
            summary += f" · Capture: {float(collection['elapsed_ms']):.0f} ms"
        collector_rows = snapshot.get("collector_status") or {}
        self.audit_summary.setToolTip("\n".join(
            f"{name}: {'complete' if row.get('complete') else 'INCOMPLETE'}"
            f" · {float(row.get('elapsed_ms', 0)):.1f} ms"
            + (f" · {row.get('error')}" if row.get("error") else "")
            for name, row in collector_rows.items() if isinstance(row, dict)
        ))
        if report.get("baseline_error") or report.get("comparison_error"):
            self.audit_summary.setToolTip(self.audit_summary.toolTip() + "\n" + str(
                report.get("baseline_error") or report.get("comparison_error")
            ))
        self.audit_summary.setTextFormat(Qt.PlainText)
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
        self._review_generation += 1
        self._latest_plan = None
        self._latest_review = None
        self.apply_button.setEnabled(False)
        self.plan_text.setPlainText("Intent changed. Rebuild the exact preview before approval.")
        self.change_table.setRowCount(0)
        self.change_details.clear()
        self.review_summary.setText("Preview invalidated. Adjust the intent profile above, then preview again.")
        profile = PROFILES[self._selected_profile_id()]
        warning = " ".join(profile.warnings)
        self.profile_description.setText(
            f"{profile.description}\nSafety notes: {warning or 'Standard rollback requirements apply.'}"
        )

    def _preview_profile(self) -> None:
        self._prepare_review(self._selected_profile_id())

    def _can_apply_review(self) -> bool:
        review = self._latest_review or {}
        report = review.get("report") or {}
        return bool(
            self._latest_plan is not None and not self._busy_task
            and review.get("generation") == self._review_generation
            and not review.get("holds") and not report.get("incomplete_collectors")
            and not report.get("baseline_error") and not report.get("comparison_error")
            and self._recovery_view.get("available")
            and not self._recovery_view.get("checking")
        )

    def _display_selected_change(self) -> None:
        items = self.change_table.selectedItems()
        effect = items[0].data(Qt.UserRole) if items else None
        if not isinstance(effect, dict):
            self.change_details.clear()
            return
        rendered = json.dumps(effect, indent=2, ensure_ascii=False, default=str)
        if len(rendered) > 128 * 1024:
            rendered = rendered[:128 * 1024] + "\n… details truncated at 128 KiB"
        if self.change_details.toPlainText() != rendered:
            self.change_details.setPlainText(rendered)

    def _display_effects(self, effects: list[dict[str, Any]], *, applied: bool = False) -> None:
        self.change_table.setSortingEnabled(False)
        try:
            self.change_table.setRowCount(len(effects))
            for row, effect in enumerate(effects):
                values = (
                    effect.get("profile", ""),
                    ("APPLIED" if applied else "PROPOSED") if effect.get("changed") else "UNCHANGED",
                    json.dumps(effect.get("before"), sort_keys=True, default=str),
                    json.dumps(effect.get("after"), sort_keys=True, default=str),
                    effect.get("reason", ""), effect.get("reversibility", ""),
                    effect.get("verification", ""),
                )
                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    item.setData(Qt.UserRole, effect)
                    self.change_table.setItem(row, column, item)
        finally:
            self.change_table.setSortingEnabled(True)
        self._display_selected_change()

    def _display_review(self, result: dict[str, Any]) -> None:
        report = dict(result.get("report") or {})
        self._display_audit(report)
        if result.get("generation") != self._review_generation:
            self.footer_detail.setText("Audit retained. The intent changed during preparation; rebuild the preview.")
            return
        self._latest_review = result
        self._recovery_view = dict(result.get("recovery") or {})
        plan = result.get("plan")
        simulation = dict(result.get("simulation") or {})
        if simulation:
            self._display_sandbox(simulation)
        self._display_effects(list(simulation.get("effects") or simulation.get("changes") or []))
        if isinstance(plan, AdaptationPlan):
            self._display_plan(plan)
        else:
            self._latest_plan = None
            self.plan_text.setPlainText("PREVIEW HELD — collected audit evidence is retained.\n\n"
                                        + json.dumps(result.get("holds") or [], indent=2, default=str))
        gaps = list(report.get("incomplete_collectors") or [])
        holds = list(result.get("holds") or [])
        reasons = [self._concise_error(str(row.get("detail") or "")) for row in holds]
        if gaps:
            reasons.append("Incomplete collectors: " + ", ".join(str(name) for name in gaps))
        if not self._recovery_view.get("available"):
            reasons.append("Immutable firewall recovery baseline is required before apply.")
        summary = " ".join(dict.fromkeys(reasons)) or "Exact preview and no-write simulation ready. Host untouched."
        self.review_summary.setText(summary)
        self.footer_detail.setText(summary)
        self.apply_button.setEnabled(self._can_apply_review())
        self.tabs.setCurrentIndex(self.adapt_tab_index)
        if holds:
            details = {"holds": holds, "collector_status": (report.get("current") or {}).get("collector_status", {})}
            literal = "\n\n".join(
                f"{str(row.get('stage') or 'review')}:\n{str(row.get('detail') or '')}"
                for row in holds
            )
            context = json.dumps(details, indent=2, default=str)
            if len(literal) > 64 * 1024:
                literal = literal[:64 * 1024] + "\n… literal details truncated at 64 KiB"
            if len(context) > 48 * 1024:
                context = context[:48 * 1024] + "\n… JSON context truncated at 48 KiB"
            self._show_notice(
                "Adaptation review held", summary,
                "DETAILS (literal text):\n" + literal + "\n\nCONTEXT (JSON):\n" + context,
            )
        if (result.get("apply_requested") and self._can_apply_review()
                and not result.get("relaxes") and isinstance(plan, AdaptationPlan)):
            generation = self._review_generation
            QTimer.singleShot(0, lambda captured=plan, token=generation:
                              self._apply_profile(expected_plan=captured, generation=token))

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
        recovery_ready = bool(self._recovery_view.get("available"))
        self.apply_button.setEnabled(recovery_ready and self._can_apply_review())
        self.apply_button.setToolTip(
            "Apply this exact plan."
            if recovery_ready else
            "Capture the immutable firewall recovery baseline before applying."
        )
        self.tabs.setCurrentIndex(3)
        self.footer_detail.setText(
            f"Preview ready: {plan.plan_id}. It expires in ten minutes and is bound to current firewall state."
        )

    def _apply_profile(
        self, *, expected_plan: AdaptationPlan | None = None, generation: int | None = None,
    ) -> None:
        plan = self._latest_plan
        if (expected_plan is not None and (plan is not expected_plan or generation != self._review_generation)):
            return
        if plan is None or not self._can_apply_review():
            self._show_notice("Apply profile", "Rebuild a complete exact preview and enroll recovery before applying.")
            return
        recovery = self._recovery_view
        if not recovery.get("available"):
            self._show_notice(
                "Recovery baseline required",
                "Explicitly capture the immutable Windows Firewall recovery baseline "
                "before applying a profile. This enrollment is never created as a side "
                "effect of Apply.",
            )
            return
        warning = "\n".join(f"• {item}" for item in plan.warnings)
        commands = "\n".join(self.service.command_stack(plan))
        token = self._review_generation

        def accepted(captured: AdaptationPlan = plan, approved_generation: int = token) -> None:
            if captured is not self._latest_plan or approved_generation != self._review_generation or not self._can_apply_review():
                self._show_notice("Preview changed", "Approval was discarded. Rebuild and review the exact current plan.")
                return

            def operation() -> dict[str, Any]:
                receipt = self.service.apply_plan(
                    captured, approved=True, approved_plan_id=captured.plan_id,
                    authorization="operator-confirmed-workbench",
                )
                effects, review_error = [], ""
                try:
                    transaction = next(row for row in reversed(self.service.transactions())
                                       if row.get("receipt_digest") == receipt.receipt_digest
                                       and row.get("plan_digest") == captured.digest)
                    effects = list(transaction.get("verified_effects") or [])
                except Exception as exc:
                    review_error = str(exc)
                return {"receipt": receipt, "effects": effects, "review_error": review_error}

            self._run_task("apply", operation)

        self._confirm_operation(
            "Apply exact adaptation plan?",
            "A fresh rollback snapshot and durable transaction are required before command 1. "
            "Changing the intent invalidates this approval. Cancel remains the default.",
            f"Plan: {plan.plan_id}\nExpires: {plan.expires_at}\n\n{warning}\n\nCommands:\n{commands}\n\n"
            + json.dumps((self._latest_review or {}).get("simulation") or {}, indent=2, default=str),
            accepted,
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
            self._show_notice("Rollback", "No recovery snapshot is available.")
            return
        captured_snapshot = str(snapshot_id)
        self._confirm_operation(
            "Restore exact firewall snapshot?",
            "Rollback replaces Windows Firewall policy with the exact authenticated snapshot. "
            "Fresh postconditions must verify the restore; the adaptation breaker does not block recovery.",
            f"Snapshot: {captured_snapshot}\n\nThe selected snapshot identity is fixed for this approval.",
            lambda selected=captured_snapshot: self._run_task(
                "rollback", lambda: self.service.rollback(
                    selected, approved=True, authorization="operator-confirmed-workbench",
                )
            ),
        )

    def _capture_security_baseline(self) -> None:
        if self._view_retired.is_set():
            return
        status = dict(self._recovery_view)
        if status.get("checking"):
            self._refresh_status()
            self.footer_detail.setText("Recovery integrity check is running; retry after it completes.")
            return
        if status.get("available"):
            self._show_notice(
                "Host security baseline",
                "The immutable original Windows Firewall baseline already exists and is "
                "never silently replaced.",
            )
            return
        self._baseline_consent_sequence += 1
        sequence, generation = self._baseline_consent_sequence, self._review_generation

        def accepted() -> None:
            if (self._view_retired.is_set() or sequence != self._baseline_consent_sequence
                    or generation != self._review_generation):
                self._show_notice("Recovery review changed", "Approval was discarded. Review the current recovery state again.")
                return
            self._baseline_consent_sequence += 1
            current = dict(self._recovery_view)
            if current.get("checking"):
                self._refresh_status()
                self.footer_detail.setText("Recovery integrity check is running; retry after it completes.")
                return
            if current.get("available"):
                self._show_notice(
                    "Host security baseline",
                    "The immutable original Windows Firewall baseline already exists and is "
                    "never silently replaced.",
                )
                return
            self._run_task(
                "capture_security_baseline",
                lambda: self.service.capture_security_baseline(approved=True),
            )

        self._confirm_operation(
            "Capture immutable host security baseline?",
            "Capture the current complete Windows Firewall policy as Angerona's permanent "
            "recovery default for this host? Hardware, services, ports, and network "
            "context remain observational only and will not be advertised as restorable.",
            "Scope: complete Windows Firewall policy.\n"
            "This is a permanent recovery enrollment. An existing baseline is never silently replaced.\n"
            "The worker captures and authenticates the current policy only after approval.\n"
            "Cancel leaves the recovery baseline unchanged.",
            accepted,
        )

    def _restore_security_baseline(self) -> None:
        if self._view_retired.is_set():
            return
        status = dict(self._recovery_view)
        if status.get("checking"):
            self._refresh_status()
            self.footer_detail.setText("Recovery integrity check is running; retry after it completes.")
            return
        if not status.get("available"):
            self._show_notice("Host security baseline", "No restorable host baseline exists yet.")
            return
        identity = tuple(str(status.get(key) or "")
                         for key in ("baseline_id", "captured_at", "firewall_sha256"))
        captured_at = str(status.get("captured_at") or "earlier")
        self._baseline_consent_sequence += 1
        sequence, generation = self._baseline_consent_sequence, self._review_generation

        def accepted() -> None:
            if (self._view_retired.is_set() or sequence != self._baseline_consent_sequence
                    or generation != self._review_generation):
                self._show_notice("Recovery review changed", "Approval was discarded. Review the current recovery state again.")
                return
            self._baseline_consent_sequence += 1
            current = dict(self._recovery_view)
            current_identity = tuple(str(current.get(key) or "")
                                     for key in ("baseline_id", "captured_at", "firewall_sha256"))
            if current.get("checking") or not current.get("available") or current_identity != identity:
                self._show_notice(
                    "Recovery review changed",
                    "The displayed recovery baseline changed or is not ready. Approval was discarded; review it again.",
                )
                return
            self._run_task(
                "restore_security_baseline",
                lambda: self.service.restore_security_baseline(approved=True),
            )

        self._confirm_operation(
            "Restore host security baseline?",
            "Replace the complete current Windows Firewall policy with the immutable "
            f"baseline captured {captured_at}? A fresh pre-restore recovery snapshot is "
            "captured first, and the restored posture must pass its postcondition check.",
            "Scope: complete Windows Firewall policy.\n"
            f"Baseline: {identity[0] or 'not supplied'}\nCaptured: {captured_at}\n"
            f"Firewall SHA-256: {identity[2] or 'not supplied'}\n\n"
            "This restores the whole captured policy, including its firewall rules.\n"
            "The backend re-authenticates the immutable baseline and verifies fresh postconditions.\n"
            "Cancel leaves the current policy unchanged.",
            accepted,
        )

    # ── Exception, automation, and persisted views ─────────────────────────
    def _render_persisted_table(
        self, name: str, table: QTableWidget, rows: tuple[tuple[str, ...], ...],
        records: tuple[Any, ...] = (),
    ) -> None:
        """Keep unchanged Qt items, selection, scroll, and open details intact."""
        signature = (rows, tuple(json.dumps(record, sort_keys=True, default=str) for record in records))
        if signature == self._view_signatures.get(name):
            return
        selected_row, selected_column = table.currentRow(), table.currentColumn()
        selected_item = table.item(selected_row, 0) if selected_row >= 0 else None
        selected_record = selected_item.data(Qt.UserRole) if selected_item is not None else None
        selected_transaction_id = (selected_record.get("transaction_id")
                                   if name == "transactions" and isinstance(selected_record, dict) else None)
        selected_text = tuple(
            table.item(selected_row, column).text() if table.item(selected_row, column) else ""
            for column in range(table.columnCount())
        ) if selected_row >= 0 else None
        vertical, horizontal = table.verticalScrollBar().value(), table.horizontalScrollBar().value()
        header = table.horizontalHeader()
        sort_column, sort_order = header.sortIndicatorSection(), header.sortIndicatorOrder()
        sorting = table.isSortingEnabled()
        blocked = table.blockSignals(True)
        table.setUpdatesEnabled(False)
        table.setSortingEnabled(False)
        try:
            table.setRowCount(len(rows))
            for row, values in enumerate(rows):
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if records:
                        item.setData(Qt.UserRole, records[row])
                    table.setItem(row, column, item)
            self._view_signatures[name] = signature
        finally:
            table.setSortingEnabled(sorting)
            if sorting:
                table.sortItems(sort_column, sort_order)
            table.clearSelection()
            table.setCurrentCell(-1, -1)
            for row in range(table.rowCount()):
                item = table.item(row, 0)
                matched = (item.data(Qt.UserRole) == selected_record if selected_record is not None else
                           tuple(table.item(row, column).text() for column in range(table.columnCount())) == selected_text)
                if selected_transaction_id:
                    record = item.data(Qt.UserRole)
                    matched = isinstance(record, dict) and record.get("transaction_id") == selected_transaction_id
                if matched:
                    table.setCurrentCell(row, max(0, selected_column))
                    table.selectRow(row)
                    if selected_transaction_id:
                        table.setCurrentCell(row, max(0, selected_column))
                    break
            table.verticalScrollBar().setValue(vertical)
            table.horizontalScrollBar().setValue(horizontal)
            table.blockSignals(blocked)
            table.setUpdatesEnabled(True)

    def _refresh_exceptions(self) -> None:
        self._request_persisted_views("exceptions", "state")

    def _render_exceptions(self, entries: list[dict[str, Any]]) -> None:
        rows = tuple(
            tuple(str(value) for value in (
                item.get("category", ""), item.get("key", ""),
                item.get("reason", ""), item.get("created_at", ""), item.get("id", ""),
            ))
            for item in entries
        )
        self._render_persisted_table("exceptions", self.exceptions_table, rows, tuple(row[4] for row in rows))

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
        self._request_persisted_views("snapshots")

    def _render_snapshots(self, rows: tuple[tuple[str, str], ...]) -> None:
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

    def _automation_changed(self, checked: bool) -> None:
        self._automation_edited = True
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

    def _refresh_triggers(self) -> None:
        self._request_persisted_views("state")

    def _render_state(self, state: dict[str, Any]) -> None:
        weights = state.get("adaptive_weights") or {}
        detail = ", ".join(
            f"{key} {float(value):.2f}×" for key, value in sorted(weights.items())
        ) or "default 1.0× in every category"
        self._weights_text = f"Adaptive scoring: {detail}"
        if not self._automation_initialized:
            if not self._automation_edited:
                blocked = self.automation_enabled.blockSignals(True)
                try:
                    self.automation_enabled.setChecked(bool(state.get("automation_enabled")))
                finally:
                    self.automation_enabled.blockSignals(blocked)
            self._automation_initialized = True
        rules = state.get("triggers") or []
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
        self._render_persisted_table("triggers", self.trigger_table, rows, tuple(row[4] for row in rows))

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
        self._request_persisted_views("activity", "transactions")

    def _render_activity(self, entries: list[dict[str, Any]]) -> None:
        rows = tuple(
            tuple(str(value) for value in (
                entry.get("at", ""), entry.get("action", ""),
                entry.get("result", ""), entry.get("detail", ""),
            ))
            for entry in entries
        )
        self._render_persisted_table("activity", self.activity_table, rows)

    def _render_transactions(self, entries: list[dict[str, Any]]) -> None:
        records = tuple(reversed(entries))
        rows = tuple(
            tuple(str(value or "") for value in (
                row.get("updated_at"), row.get("kind"), row.get("status"),
                row.get("profile_id"), row.get("snapshot_id"),
            ))
            for row in records
        )
        self._render_persisted_table("transactions", self.transaction_table, rows, records)

    def _render_persisted_results(self, values: dict[str, Any]) -> None:
        for name, renderer, empty in (
            ("state", self._render_state, {}),
            ("exceptions", self._render_exceptions, []),
            ("snapshots", self._render_snapshots, ()),
            ("activity", self._render_activity, []),
            ("transactions", self._render_transactions, []),
        ):
            if name not in values:
                continue
            result = values[name]
            try:
                if "error" in result:
                    raise ValueError(str(result["error"]))
                renderer(result.get("value") or empty)
            except Exception as exc:
                self._persisted_errors[name] = str(exc)[:8192]
            else:
                self._persisted_errors.pop(name, None)
        for name, label, title, count in (
            ("state", self.trigger_status, "Context rules", self.trigger_table.rowCount()),
            ("snapshots", self.snapshot_status, "Recovery snapshots", self.snapshot_combo.count()),
            ("activity", self.activity_status, "Activity", self.activity_table.rowCount()),
            ("transactions", self.transaction_status, "Transaction history", self.transaction_table.rowCount()),
        ):
            if name not in values:
                continue
            error = self._persisted_errors.get(name)
            retained = " · previous rows retained" if self._view_signatures.get("triggers" if name == "state" else name) else ""
            label.setText(f"{title}: unavailable{retained}" if error is not None else f"{title}: {count} listed")
            label.setToolTip(error or "")
        if "state" in values or "exceptions" in values:
            errors = [self._persisted_errors[name] for name in ("exceptions", "state") if name in self._persisted_errors]
            self.weights_label.setText("Exceptions / scoring: unavailable · previous rows retained" if errors else self._weights_text)
            self.weights_label.setToolTip("\n\n".join(errors))
            self.exceptions_table.setToolTip(self._persisted_errors.get("exceptions", ""))
            self.automation_enabled.setToolTip(self._persisted_errors.get("state", ""))

    def _request_persisted_views(self, *names: str) -> None:
        # Keep the zero-argument refresh hook used by the inert public demo
        # and read-only GUI fixtures. The temporary scope is GUI-thread only.
        previous = self._requested_status_views
        self._requested_status_views = names
        try:
            self._refresh_status()
        finally:
            self._requested_status_views = previous

    def _refresh_status(self) -> None:
        """Render local risk and coalesce expensive integrity reads off-thread."""
        if self._latest_report:
            gaps = list(dict.fromkeys(
                list(self._latest_report.get("skipped_incomplete_collectors") or [])
                + list(self._latest_report.get("incomplete_collectors") or [])
            ))
            if gaps:
                self.risk_status.setText(
                    f"Drift risk: unavailable · coverage incomplete ({len(gaps)})"
                )
            elif self._latest_report.get("baseline_error") or self._latest_report.get("comparison_error"):
                self.risk_status.setText("Drift risk: baseline comparison held")
            elif not self._latest_report.get("baseline_exists"):
                self.risk_status.setText("Drift risk: baseline required")
            else:
                self.risk_status.setText(
                    f"Drift risk: {float(self._latest_report.get('risk_score', 0)):.1f}/100"
                )
        if self._view_retired.is_set():
            return
        self._pending_status_views.update(self._requested_status_views or _CORE_STATUS_VIEWS)
        self._start_status_refresh()

    def _start_status_refresh(self) -> None:
        """Admit one reader and one bounded union of follow-up view requests."""
        if self._view_retired.is_set() or not self._pending_status_views:
            return
        if self._status_active or (self._status_thread is not None and self._status_thread.is_alive()):
            self._status_dirty = True
            return
        requested = tuple(name for name, _method in _STATUS_READS if name in self._pending_status_views)
        self._pending_status_views.clear()
        self._status_active = True
        self._status_dirty = False
        if "recovery" in requested:
            self._recovery_view = {**self._recovery_view, "checking": True}
            self.recovery_status.setText("Recovery: checking…")
            self.apply_button.setEnabled(False)
        service = self.service
        publish = self._result_publisher("status")

        def worker() -> None:
            values = {}
            for name, method in _STATUS_READS:
                if name not in requested:
                    continue
                try:
                    value = getattr(service, method)()
                    if name == "snapshots":
                        # Authenticated manifests include full firewall captures.
                        # Drop those bodies here; Qt only needs these small rows.
                        value = tuple((
                            str(snapshot.get("snapshot_id") or ""),
                            f"{snapshot.get('captured_at', '')} · "
                            f"{snapshot.get('plan', {}).get('profile_id', 'unknown')} · "
                            f"{snapshot.get('status', 'ready')}",
                        ) for snapshot in value)
                    elif name == "state":
                        value = {key: value.get(key) for key in (
                            "automation_enabled", "adaptive_weights", "triggers",
                        )}
                    values[name] = {"value": value}
                except Exception as exc:
                    values[name] = {"error": str(exc)}
            publish(values)

        try:
            self._status_thread = threading.Thread(target=worker, name="HostAdaptationStatus", daemon=True)
            self._status_generation = self._lifecycle_generation
            self._result_timer.start()
            self._status_thread.start()
        except Exception as exc:
            self._status_thread = None
            self._status_active = False
            self._on_status_finished({name: {"error": str(exc)} for name in requested})

    def _on_status_finished(self, values: dict[str, Any]) -> None:
        self._status_active = False
        if "baseline" in values:
            baseline_result = values["baseline"]
            baseline = baseline_result.get("value")
            if "error" in baseline_result:
                self.baseline_status.setText("Baseline: integrity held")
                self.baseline_status.setToolTip(str(baseline_result["error"])[:8192])
            else:
                self.baseline_status.setText(
                    f"Baseline: {baseline.get('captured_at', 'saved')}" if baseline else "Baseline: not set"
                )
                self.baseline_status.setToolTip("")
        if "recovery" in values:
            recovery_result = values["recovery"]
            self._recovery_view = dict(recovery_result.get("value") or {})
            if "error" in recovery_result:
                self.recovery_status.setText("Recovery: integrity held")
                self.recovery_status.setToolTip(str(recovery_result["error"])[:8192])
            elif self._recovery_view.get("available"):
                self.recovery_status.setText(
                    "Recovery: Firewall · " + str(self._recovery_view.get("captured_at") or "captured")
                )
                self.recovery_status.setToolTip(
                    "Restorable: Windows Firewall policy. Observational only: hardware, "
                    "services, listening ports, and network context. Integrity verified in the background."
                )
            else:
                self.recovery_status.setText(
                    "Recovery: Windows Firewall unsupported"
                    if self._recovery_view.get("supported") is False else
                    "Recovery: Firewall baseline not captured"
                )
                self.recovery_status.setToolTip(str(self._recovery_view.get("detail") or ""))
        # This is a presentation hint only. Apply/restore always re-authenticate
        # the artifact in the broker immediately before the host change.
        if "recovery" in values and self._latest_plan is not None and not self._busy_task:
            self.apply_button.setEnabled(self._can_apply_review())
        self._render_persisted_results(values)
        breaker_result = values.get("breaker")
        if breaker_result is not None and "error" in breaker_result:
            self.breaker_status_label.setText("Circuit breaker: unavailable")
            self.breaker_status_label.setToolTip(str(breaker_result["error"])[:8192])
        elif breaker_result is not None:
            breaker = breaker_result.get("value") or {}
            self.breaker_status_label.setToolTip("")
            if breaker.get("locked"):
                self.breaker_status_label.setText("Circuit breaker: LOCKED")
                self.breaker_status_label.setStyleSheet(
                    "padding:6px 10px; border:1px solid #ef4444; border-radius:6px; "
                    "background:#450a0a; color:#fecaca;"
                )
            else:
                self.breaker_status_label.setStyleSheet(
                    "padding:6px 10px; border:1px solid #334155; border-radius:6px; "
                    "background:#0f172a; color:#cbd5e1;"
                )
                self.breaker_status_label.setText(
                    f"Circuit breaker: ready · {len(breaker.get('events', []))} recent"
                )
        # Delivery may precede the reader's natural exit. Keep the queued
        # refresh busy until _poll_results observes that exact thread retire.
        self._status_active = bool(self._pending_status_views)

    def _load_persisted_views(self) -> None:
        # One verified state read supplies weights, rules, and initial settings.
        self._request_persisted_views(*(name for name, _method in _STATUS_READS))

    def refresh_after_automatic_cycle(self, status: str) -> None:
        """Refresh only views an automatic cycle could have changed."""
        if status == "applied":
            self._request_persisted_views(*_CORE_STATUS_VIEWS, "snapshots", "activity")
        elif status in {"proposed", "context-changed"}:
            self._refresh_activity()

    # ── Help and lifecycle ─────────────────────────────────────────────────
    def showEvent(self, event) -> None:  # noqa: N802 - Qt signature
        self._view_retired.clear()
        if self._reopen_refresh:
            self._reopen_refresh = False
            self._load_persisted_views()
        self._poll_results()
        super().showEvent(event)

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
            self._show_notice(
                "Adaptation operation active",
                "Keep this window open until the host-change or recovery operation finishes."
            )
            event.ignore()
            return
        self._view_retired.set()
        self._reopen_refresh = True
        self._pending_status_views.clear()
        self._status_dirty = False
        self._recovery_view = {"available": False, "checking": True}
        self.recovery_status.setText("Recovery: recheck required")
        self._lifecycle_generation += 1
        self._review_generation += 1
        self._latest_plan = None
        self._latest_review = None
        self.apply_button.setEnabled(False)
        if self._auto_intent_dialog is not None:
            self._auto_intent_dialog.reject()
        for dialog in list(self._confirmation_dialogs):
            dialog.reject()
        for dialog in list(self._notice_dialogs):
            dialog.close()
        self._poll_results()
        super().closeEvent(event)
