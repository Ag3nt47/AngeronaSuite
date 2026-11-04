"""red_team_console.py — modern Red Team Simulation console.

Replaces the old RedTeamSimulationDialog with a single, better-looking, better-
flowing window that combines configuration, a live ATT&CK kill-chain view, a
narration log, and an embedded sandbox editor for the red-team engine itself.

Highlights:
  • Intensity slider (Low → Extreme) that scales phases, jitter, noise, threat
    level and process bursts in one move.
  • Campaign mode — chain techniques in kill-chain order instead of shuffling.
  • Prominent marker-location picker (presets + Browse).
  • Auto-remediate ON by default; analogy coaching is reserved for a later UI.
  • Live kill-chain panel that tracks the current and completed drill stages.
  • Embedded editor tab for a syntax-checked working copy of shark/red_team.py.
    Save/reload/rollback never rewrite or execute the installed engine.

Integration: the console reads the running engines off its parent (MainWindow),
subscribes to the parent's `_shark_narration` signal for live updates, and calls
`parent._run_simulation(cfg)` to launch. cfg keys: run_shark, run_redteam,
intensity, campaign, target_dir, custom, auto_remediate, analogy.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import time
from html import escape
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QObject, QRunnable, QRectF, Qt, QThreadPool, Signal, Slot
from PySide6.QtGui import QColor, QPainter
from shiboken6 import isValid
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFrame,
    QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QSlider,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout,
    QWidget,
)

from angerona.core.data_paths import data_dir
from angerona.core.source_sandbox import SourceSandboxWorkspace
from angerona.gui.aar_history import HistoryListing, list_history, load_verified_history_text
from angerona.gui.animations import RunSpinner
from angerona.gui.async_snapshot import AsyncSnapshot
from angerona.gui.progress_ring import ProgressRing
from angerona.shark.run_manifest import RED_TEAM_COMPREHENSIVE_PLAN

# Canonical kill-chain stages → (stable key, readable label, narration aliases).
# Both simulation engines use the same panel but narrate a few equivalent stages
# differently (for example "Exfil Staging" and "Exfiltration").
_STAGES = [
    ("initial_access", "Initial Access", ("initial access",)),
    ("discovery", "Discovery", ("discovery",)),
    ("credential_access", "Credential Access", ("credential access",)),
    ("privilege_escalation", "Privilege Escalation", ("privilege escalation",)),
    ("defense_evasion", "Defense Evasion", ("defense evasion", "byovd")),
    ("persistence", "Persistence", ("persistence (simulated)",)),
    ("registry_run_key", "Registry Run Key", ("registry run key",)),
    ("scheduled_task", "Scheduled Task", ("scheduled task",)),
    ("wmi_persistence", "WMI Persistence", ("wmi persistence",)),
    ("lateral_movement", "Lateral Movement", ("lateral movement",)),
    ("command_control", "Command & Control", ("command & control",)),
    ("exfiltration", "Exfiltration", ("exfil staging", "exfiltration")),
    ("ransomware", "Ransomware Impact", ("ransomware impact",)),
    ("data_destruction", "Data Destruction", ("data destruction",)),
    ("benign_execution", "Benign Execution", ("benign execution",)),
    ("custom_noise", "Custom / Noise", ("noise injection", "custom")),
]
_STAGES.extend(
    (
        str(row["key"]),
        str(row["stage"]).removesuffix(" (simulated)"),
        (str(row["stage"]).removesuffix(" (simulated)").casefold(),),
    )
    for row in RED_TEAM_COMPREHENSIVE_PLAN
)
_STAGE_LABELS = {key: label for key, label, _aliases in _STAGES}
_STAGE_DETAILS = {
    str(row["key"]): {
        "technique": str(row["technique"]),
        "tactic": str(row.get("tactic") or "simulation"),
        "stage": str(row["stage"]),
    }
    for row in RED_TEAM_COMPREHENSIVE_PLAN
}
_INTENSITY = ["Low", "Medium", "High", "Extreme"]
_INTENSITY_DESC = {
    "Low": "1 phase · gentle timing · minimal noise — a quiet probe.",
    "Medium": "2 phases · moderate timing/noise — a realistic intrusion.",
    "High": "3 phases · fast, noisier, more process bursts — a busy operation.",
    "Extreme": "4 phases · rapid, high-noise, heavy process bursts — stress test.",
}


_RED_TEAM_SOURCE = "src/angerona/shark/red_team.py"
_MAX_HISTORY_RENDER_CHARS = 512 * 1024

_HISTORY_POOL: QThreadPool | None = None


@dataclass(frozen=True)
class SessionLifecycleProjection:
    """Cached owner facts for workflow display; never response authority."""
    session_id: str
    generation: int
    plans_by_run: tuple[tuple[str, str], ...]
    phase: str
    source_available: bool
    owner_finished: bool
    workers_retired: bool
    custody_released: bool


def _run_editor_job(operation, work):
    """Run one protected sandbox operation without retaining any Qt objects."""
    try:
        return operation, True, work()
    except Exception as exc:
        return operation, False, exc


def _history_pool() -> QThreadPool:
    """Keep bounded report I/O away from the Qt thread and dialog lifetime."""
    global _HISTORY_POOL
    if _HISTORY_POOL is None:
        pool = QThreadPool()
        pool.setMaxThreadCount(2)
        pool.setExpiryTimeout(10_000)
        _HISTORY_POOL = pool
    return _HISTORY_POOL


class _HistorySignals(QObject):
    finished = Signal(str, str, object)


class _HistoryWorker(QRunnable):
    def __init__(self, operation: str, root: Path, name: str = "") -> None:
        super().__init__()
        self.operation = operation
        self.root = root
        self.name = name
        # Auto-delete runnables are released on the pool thread. Keep this
        # GUI-affinity QObject application-owned until GUI deferred deletion.
        self.signals = _HistorySignals(QCoreApplication.instance())

    def _retire_signals(self) -> None:
        try:
            self.signals.deleteLater()
        except RuntimeError:
            # Application teardown may already have destroyed the bridge.
            pass

    @Slot()
    def run(self) -> None:
        try:
            try:
                result = (
                    list_history(self.root)
                    if self.operation == "list"
                    else load_verified_history_text(self.root, self.name)
                )
            except Exception as exc:
                result = {"error": str(exc)}
            try:
                self.signals.finished.emit(self.operation, self.name, result)
            except RuntimeError:
                pass  # No UI remains if application shutdown removed the bridge.
        finally:
            self._retire_signals()


class _HistoryResultReceiver(QObject):
    """Route one reader result only to its still-current console generation."""

    def __init__(self, owner, generation):
        super().__init__(owner)
        self._owner = owner
        self._generation = generation

    @Slot(str, str, object)
    def receive(self, operation, name, result):
        try:
            owner = self._owner
            if (isValid(owner) and owner._hist_accept_results
                    and self._generation == getattr(owner, "_hist_generation", 0)):
                owner._on_history_result(operation, name, result)
        finally:
            self.deleteLater()


class _StageChip(QLabel):
    """Keyboard-accessible stage surface with an exact stable stage key."""

    clicked = Signal(str)

    def __init__(self, key: str, label: str) -> None:
        super().__init__(label)
        self.stage_key = key
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAccessibleName(f"{label} simulation stage details")

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt signature
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.stage_key)
        super().mousePressEvent(event)

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt signature
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
            self.clicked.emit(self.stage_key)
            event.accept()
            return
        super().keyPressEvent(event)


class _CaughtMissedBar(QWidget):
    """Typed measured provisional or final counts; pending is never a miss."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._caught = self._missed = None
        self._provisional = False
        self._left_label, self._right_label = "Caught", "Missed"
        self._reason = "Awaiting authenticated detection evidence"
        self.set_counts(None, None, self._reason)

    def set_counts(self, caught, missed, reason="", *, provisional=False,
                   containment_required=False) -> None:
        valid = (type(caught) is int and type(missed) is int
                 and 0 <= caught <= 10_000 and 0 <= missed <= 10_000
                 and 0 < caught + missed <= 10_000)
        self._caught, self._missed = (caught, missed) if valid else (None, None)
        self._provisional = provisional is True
        self._left_label = "Caught + contained" if self._provisional and containment_required is True else "Caught"
        self._right_label = "Measured gaps" if self._provisional else "Missed"
        self._reason = str(reason)[:512]
        if valid:
            total = caught + missed
            text = (f"{self._left_label} {caught}/{total} ({caught * 100 / total:.0f}%) · "
                    f"{self._right_label} {missed}/{total} ({missed * 100 / total:.0f}%). ")
            text += (("LIVE PROVISIONAL selected-criteria outcomes; this denominator contains only "
                      "independently verified settled checks. These gaps are not final detection misses. "
                      + self._reason)
                     if self._provisional else
                     "Finalized expected-positive steps with authenticated matched analytic evidence; "
                     "includes explicitly labeled simulation validation, not only native analytics. "
                     "This is separate from verified containment and real-attack efficacy.")
        else:
            text = self._reason or "Detection comparison unavailable"
        self.setAccessibleName("Simulation caught versus missed: " + text)
        self.setToolTip(text)
        self.setMinimumHeight(self.fontMetrics().height() + 24)
        self.setMaximumHeight(self.fontMetrics().height() + 24)
        self.update()

    def changeEvent(self, event) -> None:  # noqa: N802
        super().changeEvent(event)
        self.setMinimumHeight(self.fontMetrics().height() + 24)
        self.setMaximumHeight(self.fontMetrics().height() + 24)

    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        metrics = painter.fontMetrics()
        line_height = metrics.height()
        track = QRectF(0, line_height + 5, self.width(), 12)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#334155"))
        painter.drawRoundedRect(track, 5, 5)
        if self._caught is None:
            painter.setPen(QColor("#94a3b8"))
            painter.drawText(self.rect().adjusted(0, 0, 0, -22), Qt.AlignmentFlag.AlignLeft,
                             metrics.elidedText(self._reason, Qt.TextElideMode.ElideRight, self.width()))
            return
        total = self._caught + self._missed
        left_width = self.width() * self._caught / total
        if self._caught:
            painter.setBrush(QColor("#15803d"))
            painter.drawRoundedRect(QRectF(0, track.y(), left_width, track.height()), 5, 5)
        if self._missed:
            painter.setBrush(QColor("#b91c1c"))
            painter.drawRoundedRect(QRectF(left_width, track.y(), self.width() - left_width, track.height()), 5, 5)
        left = f"{self._left_label} {self._caught} · {self._caught * 100 / total:.0f}%"
        right = f"{self._right_label} {self._missed} · {self._missed * 100 / total:.0f}%"
        half = max(0, self.width() // 2 - 4)
        painter.setPen(QColor("#4ade80"))
        painter.drawText(self.rect().adjusted(0, 0, -(self.width() // 2), -22), Qt.AlignmentFlag.AlignLeft,
                         metrics.elidedText(left, Qt.TextElideMode.ElideRight, half))
        painter.setPen(QColor("#f87171"))
        painter.drawText(self.rect().adjusted(self.width() // 2, 0, 0, -22), Qt.AlignmentFlag.AlignRight,
                         metrics.elidedText(right, Qt.TextElideMode.ElideLeft, half))


class RedTeamConsole(QDialog):
    def __init__(self, parent=None, default_target: str | None = None) -> None:
        super().__init__(parent)
        self._parent = parent
        self.setWindowTitle("🗡️  Red Team Simulation — Console")
        # Keep Launch reachable on scaled/small desktops. The Run tab scrolls
        # independently while its action footer stays fixed at the bottom.
        self.setMinimumSize(700, 520)
        self.setSizeGripEnabled(True)
        self.setWindowFlag(Qt.WindowMaximizeButtonHint, True)
        screen = self.screen() or QApplication.primaryScreen()
        if screen is not None:
            available = screen.availableGeometry()
            self.resize(
                max(700, min(1040, int(available.width() * 0.86))),
                max(520, min(800, int(available.height() * 0.86))),
            )
        else:
            self.resize(960, 720)
        try:
            if parent is not None:
                self.setStyleSheet(parent._qss())
        except Exception:
            pass
        self._stage_messages: dict[str, list[str]] = {}
        self._report_runs: dict[str, str] = {}
        self._report_results: dict[str, dict] = {}
        self._report_native_analytics: dict[str, tuple[int, int] | None] = {}
        self._report_native_opportunities: dict[str, int | None] = {}
        self._report_catch_counts: dict[str, tuple[int, int] | None] = {}
        self._execution_progress: dict[str, dict] = {}
        self._performance_session = None
        self._session_lifecycle = None
        self._live_performance = {}
        self._performance_launch_accepted = False
        self._containment_requested = True
        self._run_cancelled = False
        self._run_pending = False
        self._launch_queued = False
        self._launch_preparing = False
        self._history_pool = _history_pool()
        self._hist_accept_results = True
        self._hist_generation = 0
        self._hist_listing = False
        self._hist_refresh_pending = False
        self._hist_reading = False
        self._hist_pending_name: str | None = None
        self._hist_active_name: str | None = None
        self.finished.connect(self._stop_history_loads)
        self.finished.connect(self._cancel_preparing_launch)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        title = QLabel("🗡️  Red Team Simulation")
        title.setObjectName("PageTitle")
        title.setStyleSheet("font-size:18px; font-weight:800;")
        root.addWidget(title)
        sub = QLabel("Unannounced, non-destructive adversary simulation against THIS instance. "
                     "Every technique is a benign, reversible marker — no real exploit, secret, or "
                     "persistence mechanism is ever touched.")
        sub.setWordWrap(True); sub.setStyleSheet("color:#9fb3c8;")
        root.addWidget(sub)

        summary = QFrame()
        summary.setObjectName("RedTeamProgressSummary")
        summary_layout = QHBoxLayout(summary)
        summary_layout.setContentsMargins(8, 6, 8, 6)
        summary_layout.setSpacing(12)
        self.overall_progress = ProgressRing(getattr(parent, "config", None), diameter=56, scope="simulation workflow")
        self.overall_progress.set_state(None, None, False)
        summary_layout.addWidget(self.overall_progress)
        summary_text = QVBoxLayout()
        summary_text.setSpacing(3)
        self.workflow_status = QLabel("Overall workflow · ready")
        self.workflow_status.setTextFormat(Qt.TextFormat.PlainText)
        self.workflow_status.setWordWrap(True)
        self.workflow_status.setStyleSheet("font-weight:700; color:#e2e8f0;")
        self.workflow_detail = QLabel("Technique attempts, optional-noise decisions and authenticated report verification.")
        self.workflow_detail.setTextFormat(Qt.TextFormat.PlainText)
        self.workflow_detail.setWordWrap(True)
        self.workflow_detail.setStyleSheet("color:#94a3b8; font-size:11px;")
        self.catch_comparison = _CaughtMissedBar()
        score_heading = QHBoxLayout()
        score_heading.addWidget(QLabel("Measured detection results"))
        score_heading.addStretch(1)
        self.performance_badge = QLabel("Pending")
        self.performance_badge.setObjectName("SimulationPerformanceBadge")
        self.performance_badge.setTextFormat(Qt.TextFormat.PlainText)
        self.performance_badge.setWordWrap(True)
        self.performance_badge.setMinimumWidth(0)
        self.performance_badge.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._set_performance_badge("pending", "Pending", "Awaiting authenticated current-run detection and response evidence.")
        score_heading.addWidget(self.performance_badge)
        summary_text.addWidget(self.workflow_status)
        summary_text.addWidget(self.workflow_detail)
        summary_text.addLayout(score_heading)
        summary_text.addWidget(self.catch_comparison)
        summary_layout.addLayout(summary_text, 1)
        root.addWidget(summary)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_run_tab(default_target), "▶  Run")
        self._tabs.addTab(self._build_history_tab(), "🕑  History")
        self._tabs.addTab(self._build_device_lab_tab(), "🛰  Device Security Lab")
        self._tabs.addTab(self._build_editor_tab(), "🧪  Sandbox Editor")
        from angerona.gui.github_tools import GitHubToolsPanel
        self.github_tools = GitHubToolsPanel(self)
        self._tabs.addTab(self.github_tools, "GitHub Tools")
        self.finished.connect(lambda _result: self.github_tools.cancel_pending())
        self._tabs.currentChanged.connect(self._on_tab_changed)
        from angerona.gui.context_info import attach_context_info
        self._context_info = attach_context_info(self._tabs, "red-team")
        root.addWidget(self._tabs, 1)

        # Engine callbacks originate on worker threads. A queued connection is
        # explicit here so the log and stage cards are always updated by Qt's UI
        # thread. Flight-Instructor coaching remains available elsewhere but is
        # intentionally hidden from this focused run view for now.
        self._narration_connected = False
        if parent is not None:
            try:
                parent._shark_narration.connect(
                    self._on_narration,
                    Qt.ConnectionType.QueuedConnection,
                )
                self._narration_connected = True
            except (AttributeError, RuntimeError, TypeError):
                self.live_status.setText("Live event feed unavailable for this window.")
        from angerona.gui.window_controls import configure_work_window
        configure_work_window(self)

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        if not getattr(self, "_hist_accept_results", True):
            self._hist_generation = getattr(self, "_hist_generation", 0) + 1
            self._hist_accept_results = True
            self._hist_listing = self._hist_reading = self._hist_refresh_pending = False
            self._hist_pending_name = self._hist_active_name = None
            tabs = getattr(self, "_tabs", None)
            if tabs is not None and "History" in tabs.tabText(tabs.currentIndex()):
                self._load_history()

    # ── Run tab ──────────────────────────────────────────────────────────────
    def _build_run_tab(self, default_target: str | None) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(8)
        scroll = QScrollArea()
        scroll.setObjectName("RedTeamRunScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setMinimumHeight(130)
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(4, 4, 8, 4)
        lay.setSpacing(10)

        # attack types
        types = QFrame(); types.setObjectName("Card")
        tl = QVBoxLayout(types)
        tl.addWidget(self._h("Attack profile"))
        self.cb_shark = QCheckBox("Shark — noisy commodity-malware chain")
        self.cb_shark.setToolTip(
            "Lure → discovery → persistence → exfiltration markers"
        )
        self.cb_apt = QCheckBox("APT Red Team — quiet adversary campaign")
        self.cb_apt.setToolTip(
            "Credential access and fileless-persistence simulation"
        )
        # One click launches both complementary, inert profiles by default.
        self.cb_shark.setChecked(True)
        self.cb_apt.setChecked(True)
        tl.addWidget(self.cb_shark); tl.addWidget(self.cb_apt)
        self.cb_comprehensive = QCheckBox(
            "Comprehensive safe catalog — 37 authenticated detector contracts"
        )
        self.cb_comprehensive.setChecked(True)
        self.cb_comprehensive.setToolTip(
            "Adds 24 fixed local text markers across ATT&CK tactics. No exploit, "
            "credential access, persistence, remote connection, exfiltration, or "
            "host damage is performed."
        )
        tl.addWidget(self.cb_comprehensive)
        lay.addWidget(types)

        # intensity
        inten = QFrame(); inten.setObjectName("Card"); il = QVBoxLayout(inten)
        il.addWidget(self._h("Intensity"))
        row = QHBoxLayout()
        self.sld = QSlider(Qt.Orientation.Horizontal)
        self.sld.setMinimum(0); self.sld.setMaximum(3); self.sld.setValue(1)
        self.sld.setTickInterval(1); self.sld.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.sld.valueChanged.connect(self._on_intensity)
        self.sld_lbl = QLabel(); self.sld_lbl.setStyleSheet("font-weight:700; min-width:80px;")
        row.addWidget(self.sld, 1); row.addWidget(self.sld_lbl)
        il.addLayout(row)
        self.inten_desc = QLabel(); self.inten_desc.setWordWrap(True)
        self.inten_desc.setStyleSheet("color:#9fb3c8;")
        il.addWidget(self.inten_desc)
        self.cb_campaign = QCheckBox("Campaign mode — follow kill-chain order")
        self.cb_campaign.setToolTip(
            "Recon → access → persistence → C2 → exfiltration → impact"
        )
        self.cb_campaign.setChecked(True)
        il.addWidget(self.cb_campaign)
        lay.addWidget(inten)
        self._on_intensity(1)

        # marker location picker
        loc = QFrame(); loc.setObjectName("Card"); ll = QVBoxLayout(loc)
        ll.addWidget(self._h("Marker discovery location"))
        loc_help = QLabel(
            "Choose where benign marker files are written. A watched folder makes "
            "detections appear faster."
        )
        loc_help.setWordWrap(True)
        ll.addWidget(loc_help)
        prow = QGridLayout()
        self.loc_preset = QComboBox()
        home = Path(os.environ.get("USERPROFILE", str(Path.home())))
        sandbox = Path(default_target) if default_target else data_dir() / "drill-sandbox"
        self._presets = {
            "Angerona sandbox (D: default)": str(sandbox),
            "Documents": str(home / "Documents"),
            "Desktop": str(home / "Desktop"),
            "Downloads": str(home / "Downloads"),
            "Angerona runtime temp": str(data_dir() / "tmp"),
        }
        self.loc_preset.addItems(list(self._presets.keys()) + ["Custom…"])
        self.loc_preset.currentTextChanged.connect(self._on_preset)
        self.loc_edit = QLineEdit(str(sandbox))
        browse = QPushButton("Browse…"); browse.clicked.connect(self._browse)
        prow.addWidget(self.loc_preset, 0, 0, 1, 2)
        prow.addWidget(self.loc_edit, 1, 0)
        prow.addWidget(browse, 1, 1)
        prow.setColumnStretch(0, 1)
        ll.addLayout(prow)
        lay.addWidget(loc)

        # custom technique + toggles
        opt = QFrame(); opt.setObjectName("Card"); ol = QVBoxLayout(opt)
        ol.addWidget(self._h("Options"))
        ol.addWidget(QLabel("Custom technique name (optional)"))
        self.custom_name = QLineEdit(); self.custom_name.setPlaceholderText(
            "Example: my-detection-test")
        ol.addWidget(self.custom_name)
        ol.addWidget(QLabel("Custom inert marker text (optional)"))
        self.custom_payload = QLineEdit(); self.custom_payload.setPlaceholderText(
            "Written verbatim to a marker file; never executed")
        ol.addWidget(self.custom_payload)
        # Keep the control available for backward-compatible configuration, but
        # reserve the unfinished coaching experience for a later feature.
        self.cb_analogy = QCheckBox("Analogy coaching (Flight Instructor) — explain each step in "
                                    "plain English while it runs")
        self.cb_analogy.setChecked(False)
        self.cb_analogy.setVisible(False)
        self.cb_remediate = QCheckBox("Auto-contain detected markers during the run")
        self.cb_remediate.setChecked(True)
        self.cb_remediate.setToolTip(
            "Attempts containment through the current response policy. If Combat is "
            "unready, the selected simulation still runs with a warning. "
            "Uncheck for a detection-only run."
        )
        ol.addWidget(self.cb_remediate)
        remediation_help = QLabel(
            "The selected simulation can run even when Combat needs recovery. "
            "Response limits stay in effect, and containment requires verified results. "
            "Uncheck this option for a detection-only run."
        )
        remediation_help.setWordWrap(True)
        remediation_help.setStyleSheet("color:#9fb3c8; margin-left:24px;")
        ol.addWidget(remediation_help)
        self.response_readiness = QLabel()
        self.response_readiness.setObjectName("RedTeamResponseReadiness")
        self.response_readiness.setAccessibleName("Containment readiness preview")
        self.response_readiness.setTextFormat(Qt.PlainText)
        self.response_readiness.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.response_readiness.setWordWrap(True)
        ol.addWidget(self.response_readiness)
        self.refresh_readiness_btn = QPushButton("Refresh containment readiness")
        self.refresh_readiness_btn.clicked.connect(self._refresh_response_readiness)
        ol.addWidget(self.refresh_readiness_btn)
        for option in (self.cb_shark, self.cb_apt, self.cb_remediate):
            option.toggled.connect(self._refresh_response_readiness)
        self._refresh_response_readiness()
        lay.addWidget(opt)

        lay.addStretch(1)
        scroll.setWidget(body)

        # The live panel is not inside the configuration scroller. It remains
        # readable while settings above it grow, and operators can resize the
        # split to favor setup or telemetry.
        live = QFrame(); live.setObjectName("Card")
        live.setMinimumHeight(190)
        live_lay = QVBoxLayout(live)
        live_lay.setContentsMargins(10, 8, 10, 10)
        live_lay.setSpacing(6)
        live_lay.addWidget(self._h("Live kill-chain"))
        self.live_status = QLabel("Waiting to launch…")
        self.live_status.setTextFormat(Qt.TextFormat.PlainText)
        self.live_status.setWordWrap(True)
        self.live_status.setStyleSheet("color:#9fb3c8; font-size:11px;")
        live_lay.addWidget(self.live_status)
        self.launch_warning = QLabel()
        self.launch_warning.setObjectName("RedTeamLaunchWarning")
        self.launch_warning.setAccessibleName("Simulation response warning")
        self.launch_warning.setTextFormat(Qt.PlainText)
        self.launch_warning.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.launch_warning.setWordWrap(True)
        self.launch_warning.setStyleSheet("color:#fbbf24; font-size:11px;")
        self.launch_warning.hide()
        live_lay.addWidget(self.launch_warning)
        self._chip_wrap = QWidget(); self._chips: dict[str, _StageChip] = {}
        self._active_stage: str | None = None
        cl = QGridLayout(self._chip_wrap)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setHorizontalSpacing(6)
        cl.setVerticalSpacing(6)
        for column in range(4):
            cl.setColumnStretch(column, 1)
        for index, (key, label, _aliases) in enumerate(_STAGES):
            chip = _StageChip(key, label)
            chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip.setWordWrap(True)
            chip.setMinimumHeight(30)
            chip.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            chip.setToolTip(f"Open exact {label} stage details and artifact evidence")
            chip.clicked.connect(self._open_stage_detail)
            self._chips[key] = chip
            self._set_chip_state(key, "idle")
            cl.addWidget(chip, index // 4, index % 4)
        chip_scroll = QScrollArea()
        chip_scroll.setWidgetResizable(True)
        chip_scroll.setFrameShape(QFrame.Shape.NoFrame)
        chip_scroll.setMinimumHeight(116)
        chip_scroll.setMaximumHeight(260)
        chip_scroll.setWidget(self._chip_wrap)
        live_lay.addWidget(chip_scroll)
        self._chip_scroll = chip_scroll

        # live log
        self.log = QTextEdit(); self.log.setReadOnly(True)
        self.log.document().setMaximumBlockCount(4000)
        self.log.setStyleSheet("font-family:'Fira Code',monospace; font-size:11px; "
                               "background:#0b1220; border:1px solid #23324a; border-radius:6px;")
        self.log.setMinimumHeight(90)
        self.log.setPlaceholderText("Simulation events will appear here as they happen.")
        live_lay.addWidget(self.log, 1)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setObjectName("RedTeamRunSplitter")
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(7)
        splitter.addWidget(scroll)
        splitter.addWidget(live)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([360, 280])
        outer.addWidget(splitter, 1)

        # Sticky actions live outside the scrolling configuration body, keeping
        # Launch and Stop & clean reachable at every supported window size.
        act = QHBoxLayout()
        # Only an authenticated containment result may complete the wheel.
        self.run_spinner = RunSpinner()
        # The full state is shown above the stage grid; reserve only the ring
        # here so footer buttons cannot clip its label on a 700 px window.
        self.run_spinner.set_compact(True, extent=30)
        act.addWidget(self.run_spinner)
        self.launch_btn = QPushButton("▶  Launch simulation")
        self.launch_btn.setStyleSheet("background:#7f1d1d; color:#fecaca; border:1px solid #b91c1c;"
                                      "border-radius:6px; padding:7px 16px; font-weight:800;")
        self.launch_btn.clicked.connect(self._launch)
        self.stop_btn = QPushButton("■  Stop & clean")
        self.stop_btn.clicked.connect(self._stop)
        act.addStretch(); act.addWidget(self.stop_btn); act.addWidget(self.launch_btn)
        outer.addLayout(act)
        self._run_scroll = scroll
        self._run_splitter = splitter
        self._live_panel = live
        return w

    def _refresh_response_readiness(self, *_unused) -> None:
        """Show a current, read-only preview; launch performs its own check."""
        if not (self.cb_shark.isChecked() or self.cb_apt.isChecked()):
            message = "Select an attack profile to check containment readiness."
            color = "#fbbf24"
        elif not self.cb_remediate.isChecked():
            message = (
                "Detection-only run selected. Combat readiness is not required, "
                "and the report will not assign a containment pass."
            )
            color = "#9fb3c8"
        else:
            from angerona.core.drill_readiness import assess_drill_response

            assessment = assess_drill_response(
                getattr(self._parent, "manager", None),
                require_process=self.cb_apt.isChecked(),
            )
            state = str(assessment.get("state") or "UNKNOWN")
            reason = str(assessment.get("reason") or "No reason was supplied.")
            scope = "APT process checks" if self.cb_apt.isChecked() else "Shark checks"
            if assessment.get("ready") is True and state == "ARMED":
                message = (
                    f"Containment readiness now ({scope}): ARMED. {reason} "
                    "Launch checks again; signed report receipts decide the result."
                )
                color = "#4ade80"
            elif assessment.get("ready") is True and state == "CANARYONLY":
                message = (
                    f"Practice canaries ready ({scope}). {reason} "
                    "Ordinary host response remains held. Fresh issuer leases, "
                    "exact target checks and authenticated report receipts are "
                    "required; launch checks readiness again."
                )
                color = "#38bdf8"
            else:
                message = (
                    f"Containment readiness now ({scope}): {state}. {reason} "
                    "Launch will continue with a warning. Response permissions will "
                    "not be expanded; unavailable containment stays unverified. "
                    "Review Settings > Adversary Combat for response recovery."
                )
                color = "#fbbf24"
        self.response_readiness.setText(message)
        self.response_readiness.setStyleSheet(
            f"color:{color}; background:#172033; border:1px solid #334155; "
            "border-radius:6px; padding:8px;"
        )

    def finish_run(self) -> None:
        """Engine completion starts evidence review; it does not prove containment."""
        if self._active_stage is not None:
            self._set_chip_state(self._active_stage, "complete")
            self._active_stage = None
        self.live_status.setText(
            "Simulation stages complete — awaiting authenticated response evidence. "
            "Stage colors show execution only."
        )
        self.live_status.setStyleSheet("color:#fbbf24; font-size:11px;")
        self.run_spinner.start("Verifying response evidence")
        self._render_execution_progress()

    def set_launch_status(self, result: dict, cfg: dict | None = None) -> None:
        """Also receives the eventual launch result after a queued Chill wake-up."""
        status = str(result.get("status") or "rejected")
        reason = str(result.get("reason") or "Launch was not accepted.")
        keep_lifecycle = (status == "rejected" and result.get("busy") is True
                          and self._accepted_lifecycle_pending())
        if (status == "rejected" and ((self._run_pending
                and (not self._launch_queued or result.get("busy") is True)) or keep_lifecycle)):
            self.log.append(escape("Additional launch refused — " + reason))
            if keep_lifecycle:
                # Report/execution completion does not drop the still-owned
                # Session binding. A menu/quick-launch refusal cannot turn its
                # pending custody into the legacy unbound completion path.
                self.launch_btn.setEnabled(False)
                self._render_execution_progress()
            return
        self.run_spinner.stop()
        self._launch_preparing = status == "preparing"
        warning = str(result.get("response_warning") or "") if status == "accepted" else ""
        self.launch_warning.setText(warning)
        self.launch_warning.setVisible(bool(warning))
        if status == "accepted":
            self._performance_launch_accepted = True
            self.launch_btn.setEnabled(False)
            self._run_pending = True
            self._run_cancelled = False
            self._launch_queued = False
            self._report_runs = dict(result.get("runs") or {})
            self._report_results = {}
            self._report_native_analytics = {}
            self._report_native_opportunities = {}
            self._report_catch_counts = {}
            self._execution_progress = {}
            self._performance_session = None
            self._session_lifecycle = None
            self._live_performance = {}
            self.catch_comparison.set_counts(None, None, "Run in progress · detection results pending")
            self.overall_progress.set_state(None, None, True)
            self.workflow_status.setText("Overall workflow · starting")
            self.workflow_detail.setText("Waiting for this run's measured technique counts.")
            self._containment_requested = bool((cfg or {}).get("auto_remediate", True))
            self.live_status.setText(
                "Containment test running — results require verified evidence."
                if self._containment_requested else
                "Detection-only run — no containment pass will be assigned."
            )
            self.live_status.setStyleSheet("color:#9fb3c8; font-size:11px;")
            self.run_spinner.start("Simulation running")
        else:
            self._performance_launch_accepted = False
            self._performance_session = None
            self._session_lifecycle = None
            self._live_performance = {}
            self._launch_queued = status in {"queued", "preparing"}
            self._run_pending = self._launch_queued
            if self._launch_queued:
                # A delayed handoff from the previous run must not overwrite
                # preparation or re-enable Launch before this attempt settles.
                self._report_runs = {}
                self._report_results = {}
            self.launch_btn.setEnabled(not self._launch_queued)
            self.live_status.setText(
                ({"queued": "Launch queued — ", "preparing": "Preparing simulation — "}
                 .get(status, "Launch blocked — "))
                + reason
            )
            self.live_status.setStyleSheet("color:#fbbf24; font-size:11px;")
            if self._launch_preparing:
                self.run_spinner.start("Preparing simulation")
            self.overall_progress.set_state(None, None, self._launch_queued)
            self.workflow_status.setText(
                "Overall workflow · preparing" if self._launch_queued else "Overall workflow · launch not accepted")
            self.workflow_detail.setText(reason)
            self.catch_comparison.set_counts(None, None, "No finalized detection result for this launch")
        self.log.append(escape(self.live_status.text()))
        if warning:
            self.log.append(escape("Containment warning — " + warning))
        self._render_performance_badge()

    def _accepted_lifecycle_pending(self) -> bool:
        """Preserve only the already accepted exact binding, never result text."""
        binding = getattr(self, "_performance_session", None)
        if (getattr(self, "_performance_launch_accepted", False) is not True
                or type(binding) is not tuple or len(binding) != 3
                or type(binding[0]) is not str or not 1 <= len(binding[0]) <= 160
                or type(binding[1]) is not int or not 0 <= binding[1] <= 1_000_000
                or type(binding[2]) is not dict or not 1 <= len(binding[2]) <= 2
                or set(binding[2]) != set(self._report_runs.values())
                or any(type(run_id) is not str or not 1 <= len(run_id) <= 160
                       or type(digest) is not str or len(digest) != 64
                       or any(char not in "0123456789abcdef" for char in digest)
                       for run_id, digest in binding[2].items())):
            return False
        return self._workflow_owner_pending()

    def update_execution_progress(self, snapshots: dict) -> bool:
        """Accept only plain cached counts bound to the current accepted runs."""
        active = False
        for kind, run_id in self._report_runs.items():
            row = snapshots.get(kind) if type(snapshots) is dict else None
            valid = (type(row) is dict and type(row.get("schema")) is int and row.get("schema") == 1
                     and row.get("run_id") == run_id
                     and type(row.get("state")) is str
                     and row.get("state") in {"queued", "running", "stopping", "completed", "cancelled", "failed", "incomplete"}
                     and type(row.get("finished")) is int and type(row.get("total")) is int
                     and 0 < row["total"] <= 10_000 and 0 <= row["finished"] <= row["total"]
                     and type(row.get("failed_units")) is int and 0 <= row["failed_units"] <= row["finished"]
                     and type(row.get("current_task")) is str and len(row["current_task"]) <= 160)
            if not valid:
                self._execution_progress.pop(kind, None)
                continue
            self._execution_progress[kind] = dict(row)
            active |= row["state"] in {"queued", "running", "stopping"}
        self._render_execution_progress()
        return active

    def _render_execution_progress(self) -> None:
        expected = set(self._report_runs)
        rows = [self._execution_progress[kind] for kind in sorted(expected) if kind in self._execution_progress]
        missing = expected - set(self._execution_progress)
        active = any(row["state"] in {"queued", "running", "stopping"} for row in rows)
        pending = expected - set(self._report_results)
        errors = any(row.get("error") for row in self._report_results.values())
        owner_pending = self._workflow_owner_pending()
        if not expected:
            return
        if missing:
            self.overall_progress.set_state(None, None, bool(self._run_pending or active or owner_pending))
            self.workflow_status.setText("Overall workflow · measured progress unavailable")
            self.workflow_detail.setText("Waiting for current-run counts: " + ", ".join(sorted(missing)))
            return
        # Report verification contributes one unit per requested run. A failed
        # signature/read never completes that unit or paints a false green100.
        reports_done = sum(1 for kind in expected if kind in self._report_results
                           and not self._report_results[kind].get("error"))
        finished = sum(row["finished"] for row in rows) + reports_done
        total = sum(row["total"] + 1 for row in rows)
        busy = active or bool(pending and self._run_pending) or owner_pending
        self.overall_progress.set_state(finished, total, busy)
        if active:
            title = "Stopping" if any(row["state"] == "stopping" for row in rows) else "Running"
            detail = " · ".join(row["current_task"] for row in rows if row["state"] in {"queued", "running", "stopping"})
        elif pending:
            title, detail = "Reviewing evidence", "Awaiting authenticated reports: " + ", ".join(sorted(pending))
        elif errors:
            title, detail = "Report verification failed", "Preserved results need review; unavailable evidence is not a pass."
        elif self._run_cancelled or any(row["state"] == "cancelled" for row in rows):
            title, detail = "Cancelled", "Unexecuted technique units remain incomplete. Review the authenticated report."
        elif any(row.get("diagnostic_only") for row in self._report_results.values()):
            title, detail = "Diagnostic report authenticated; scoring held", "The incomplete run preserves its planned denominator; diagnostic authenticity grants no coverage, containment or repair credit."
        elif any(row["state"] in {"failed", "incomplete"} or row["failed_units"] for row in rows):
            title, detail = "Ended with execution errors", "Workflow completion is separate from detection and containment; review the report."
        elif any(row.get("coverage_held") for row in self._report_results.values()):
            title, detail = "Report authenticated; coverage held", "Authenticated diagnostics do not establish detection coverage, containment or verified repair."
        elif owner_pending:
            title, detail = "Finishing session lifecycle", "The report is available. Waiting for the exact owner Thread to return and its lease/reservation custody to be released."
        else:
            title, detail = "Complete", "Execution and report verification finished. The containment result remains separate below."
        if owner_pending and title != "Finishing session lifecycle":
            detail += " Exact Session worker retirement and custody release remain pending or unavailable."
        self.workflow_status.setText(f"Overall workflow · {title} · {finished}/{total} units")
        self.workflow_status.setStyleSheet(
            "font-weight:700; color:" + (
                "#f87171" if errors or any(row["state"] == "failed" for row in rows) else
                "#fbbf24" if self._run_cancelled or any(row.get("coverage_held") for row in self._report_results.values()) or any(row["state"] in {"cancelled", "incomplete"} or row["failed_units"] for row in rows) else
                "#7dd3fc" if busy else "#e2e8f0") + ";")
        self.workflow_detail.setText(detail)
        self._render_performance_badge()

    def _set_performance_badge(self, state, label, detail) -> None:
        colors = {"pending": "#94a3b8", "unverified": "#94a3b8", "inconclusive": "#94a3b8",
                  "partial": "#fbbf24", "passing": "#2fe38a", "failing": "#ff7373"}
        if state not in colors:
            state, label = "unverified", "Unverified"
        self.performance_badge.setProperty("performanceState", state)
        self.performance_badge.setText(str(label)[:80])
        self.performance_badge.setToolTip(str(detail)[:1024])
        self.performance_badge.setAccessibleName("Simulation performance: " + str(label)[:80])
        self.performance_badge.setAccessibleDescription(str(detail)[:1024])
        self.performance_badge.setStyleSheet("color:" + colors[state]
            + "; background:#172033; border:1px solid " + colors[state]
            + "; border-radius:7px; padding:4px 8px; font-weight:800;")

    @staticmethod
    def _performance_state(runs, results, counts, *, cancelled=False, containment_requested=True, running=False):
        """Classify only current accepted, authenticated scored report evidence.

        Counts are populated solely by record_verified_report from the parent's
        immutable verified handoff. Execution progress never supplies a score.
        """
        expected = set(runs) if type(runs) is dict else set()
        if cancelled:
            return "inconclusive", "Inconclusive · cancelled", "Cancelled execution cannot establish a complete performance result."
        accepted = []
        unverified = diagnostic = False
        for kind in expected:
            row = results.get(kind) if type(results) is dict else None
            metric = counts.get(kind) if type(counts) is dict else None
            if row is None:
                continue
            if type(row) is not dict:
                unverified = True
                continue
            if row.get("error"):
                unverified = True
                continue
            if row.get("diagnostic_only") or row.get("coverage_held") or row.get("outcome") == "inconclusive":
                diagnostic = True
                continue
            if (type(metric) is not tuple or len(metric) != 2
                    or any(type(value) is not int or value < 0 for value in metric)
                    or not 0 < sum(metric) <= 10_000
                    or type(row.get("count")) is not int or type(row.get("eligible")) is not int
                    or row["eligible"] != sum(metric) or not 0 <= row["count"] <= row["eligible"]
                    or row.get("outcome") not in {"verified", "partial", "failed"}
                    or (row["outcome"] == "verified" and row["count"] != row["eligible"])
                    or (row["outcome"] == "partial" and not 0 < row["count"] < row["eligible"])
                    or (row["outcome"] == "failed" and row["count"] != 0)):
                unverified = True
                continue
            accepted.append((row, metric))
        missed = sum(metric[1] for _row, metric in accepted)
        if missed:
            return "failing", f"Failing · {missed} measured miss{'es' if missed != 1 else ''}", (
                "Authenticated completed expected-positive checks include measured detection misses. "
                "Other profiles or coverage can still be pending; this does not identify a real breach.")
        if containment_requested and any(row["outcome"] == "failed" for row, _metric in accepted):
            return "failing", "Failing · response", (
                "The authenticated current-run report records a failed containment outcome. "
                "Detection matches alone do not establish successful response or real-attack efficacy.")
        if len(accepted) != len(expected) or not expected:
            if accepted:
                return "partial", "Partial · evidence pending", (
                    f"{len(accepted)}/{len(expected)} requested profiles have accepted scored evidence; no overall pass is assigned.")
            if unverified:
                return "unverified", "Unverified", "The current report or metric could not be authenticated or accepted; no score is inferred."
            if diagnostic:
                return "inconclusive", "Inconclusive", "Authenticated diagnostics preserve evidence but withhold detection coverage and containment scores."
            return "pending", "Running · evidence pending" if running else "Pending", (
                "Execution progress is measured separately. Waiting for authenticated settled detection evidence.")
        if containment_requested and any(row["outcome"] != "verified" for row, _metric in accepted):
            return "partial", "Partial · response", "Some tested targets remain unverified; completed workflow is not a containment pass."
        return "passing", "Passing" if containment_requested else "Passing · detection only", (
            "All requested authenticated expected-positive checks were caught and all requested containment outcomes verified. "
            "This is a completed simulation result, not proof against real attacks."
            if containment_requested else
            "All requested authenticated expected-positive checks were caught. Containment was not requested and no response pass is assigned.")

    def _render_performance_badge(self) -> None:
        if not self._performance_launch_accepted:
            self._set_performance_badge("pending", "Preparing · evidence pending" if self._launch_queued else "Pending",
                "A new accepted current-run plan and authenticated measured evidence are required.")
            return
        state = self._performance_state(self._report_runs, self._report_results, self._report_catch_counts,
            cancelled=self._run_cancelled, containment_requested=self._containment_requested, running=self._run_pending)
        pending = set(self._report_runs) - set(self._report_results)
        if state[0] in {"pending", "partial"} and pending and not self._run_cancelled:
            provisional = self._live_performance_state()
            if provisional is not None:
                state = provisional
        self._set_performance_badge(*state)

    def bind_performance_session(self, session_id, generation, plans_by_run) -> bool:
        """Bind only the exact SessionPlan accepted by the parent launch owner."""
        if (self._performance_launch_accepted is not True
                or type(session_id) is not str or not 1 <= len(session_id) <= 160
                or type(generation) is not int or not 0 <= generation <= 1_000_000
                or type(plans_by_run) is not dict or not 1 <= len(plans_by_run) <= 2
                or set(plans_by_run) != set(self._report_runs.values())
                or any(type(run_id) is not str or not 1 <= len(run_id) <= 160
                       or type(digest) is not str or len(digest) != 64
                       or any(char not in "0123456789abcdef" for char in digest)
                       for run_id, digest in plans_by_run.items())):
            return False
        self._performance_session = (session_id, generation, dict(plans_by_run))
        self._session_lifecycle = None
        self._live_performance = {}
        self._render_performance_badge()
        return True

    def record_session_lifecycle(self, projection) -> bool:
        """Accept only the current immutable owner/run generation projection."""
        binding = self._performance_session
        if (type(projection) is not SessionLifecycleProjection or binding is None
                or not self._performance_launch_accepted
                or type(projection.session_id) is not str or type(projection.generation) is not int
                or projection.session_id != binding[0] or projection.generation != binding[1]
                or type(projection.plans_by_run) is not tuple
                or projection.plans_by_run != tuple(sorted(binding[2].items()))
                or set(binding[2]) != set(self._report_runs.values())
                or type(projection.phase) is not str or len(projection.phase) > 80
                or any(type(value) is not bool for value in (projection.source_available,
                    projection.owner_finished, projection.workers_retired, projection.custody_released))):
            return False
        if getattr(self, "_session_lifecycle", None) == projection:
            return True
        self._session_lifecycle = projection
        self._render_execution_progress()
        return True

    def _workflow_owner_pending(self) -> bool:
        """A busy state caps a measured wheel at99 without adding work units."""
        binding = getattr(self, "_performance_session", None)
        if binding is None:
            return False  # Legacy detached runs retain their existing behavior.
        row = getattr(self, "_session_lifecycle", None)
        return not (type(row) is SessionLifecycleProjection and row.session_id == binding[0]
            and type(row.generation) is int and row.generation == binding[1]
            and row.plans_by_run == tuple(sorted(binding[2].items()))
            and row.source_available is True and row.owner_finished is True
            and row.workers_retired is True and row.custody_released is True)

    def record_performance_snapshot(self, snapshot) -> bool:
        """Read a cached immutable native-verifier result, never rescore on Qt."""
        try:
            from angerona.shark.simulation_session import RunPerformanceSnapshot
            if (type(snapshot) is not RunPerformanceSnapshot or self._performance_session is None
                    or self._performance_launch_accepted is not True):
                return False
            session_id, generation, plans = self._performance_session
            fields = (snapshot.eligible_planned, snapshot.evaluated_steps, snapshot.detection_verified_steps,
                      snapshot.native_verified_steps, snapshot.simulation_verified_steps,
                      snapshot.containment_verified_steps, snapshot.provisional_failures,
                      snapshot.unsettled_steps, snapshot.unavailable_steps)
            if (type(snapshot.session_id) is not str or type(snapshot.session_generation) is not int
                    or type(snapshot.run_id) is not str or type(snapshot.plan_sha256) is not str
                    or snapshot.session_id != session_id or snapshot.session_generation != generation
                    or plans.get(snapshot.run_id) != snapshot.plan_sha256
                    or snapshot.run_id not in self._report_runs.values()
                    or snapshot.state not in {"pending", "provisional", "unverified", "final"}
                    or any(type(value) is not int or not 0 <= value <= 10_000 for value in fields)
                    or not 0 < snapshot.eligible_planned
                    or any(value > snapshot.eligible_planned for value in fields[1:])
                    or snapshot.native_verified_steps > snapshot.evaluated_steps
                    or snapshot.detection_verified_steps > snapshot.evaluated_steps
                    or snapshot.simulation_verified_steps > snapshot.detection_verified_steps
                    or snapshot.native_verified_steps > snapshot.detection_verified_steps
                    or snapshot.containment_verified_steps > snapshot.evaluated_steps
                    or snapshot.provisional_failures > snapshot.evaluated_steps
                    or type(snapshot.containment_required) is not bool
                    or snapshot.containment_required is not self._containment_requested
                    or (snapshot.finalized_misses is not None and (snapshot.state != "final"
                        or type(snapshot.finalized_misses) is not int
                        or not 0 <= snapshot.finalized_misses <= snapshot.eligible_planned))):
                return False
            self._live_performance[snapshot.run_id] = snapshot
        except (ImportError, AttributeError, TypeError, ValueError):
            return False
        self._render_catch_comparison()
        return True

    def _live_performance_state(self):
        rows = list(self._live_performance.values())
        if not rows:
            return None
        if any(row.state == "unverified" for row in rows):
            return "unverified", "Unverified · live evidence", "The current session verifier reports unavailable evidence; historical progress does not establish current coverage."
        native = sum(row.native_verified_steps for row in rows)
        detected = sum(row.detection_verified_steps for row in rows)
        simulation = sum(row.simulation_verified_steps for row in rows)
        contained = sum(row.containment_verified_steps for row in rows)
        failures = sum(row.provisional_failures for row in rows)
        evaluated = sum(row.evaluated_steps for row in rows)
        planned = sum(row.eligible_planned for row in rows)
        unavailable = sum(row.unavailable_steps for row in rows)
        unsettled = sum(row.unsettled_steps for row in rows)
        detail = (f"Measured profiles {len(rows)}/{len(self._report_runs)} in the accepted session: "
            f"{detected}/{evaluated} evaluated checks caught; {native} original-native analytics verified; "
            f"{simulation} simulation validations verified; "
            f"{contained} durable containment postconditions verified; {evaluated}/{planned} checks evaluated; "
            f"{failures} measured provisional gaps; {unsettled} unsettled; {unavailable} unavailable. "
            "Only actually evaluated settled checks enter the live denominator; unrun stages do not. "
            "Native/simulation categories can overlap. No final pass or real-attack protection is inferred; the signed AAR remains authoritative.")
        detail += (" Selected criteria: detection and durable containment."
                   if self._containment_requested else " Selected criteria: detection only; no response pass is assigned.")
        if failures:
            return "failing", "Failing so far · measured gaps", detail
        if evaluated and detected == evaluated and (not self._containment_requested or contained == evaluated):
            return "partial", "Passing so far · provisional", detail
        return "pending", "Running · evidence pending", detail

    @staticmethod
    def _caught_metric(payload, run_id):
        """Interpret the parent's authenticated payload; never verify by label."""
        if (type(payload) is not dict or payload.get("run_id") != run_id
                or payload.get("diagnostic_only") is True
                or payload.get("coverage_score_eligible") is not True):
            return None
        taxonomy = payload.get("evidence_taxonomy")
        union = taxonomy.get("compatible_analytic_union") if type(taxonomy) is dict else None
        if type(union) is not dict:
            return None
        total, caught = taxonomy.get("denominator"), union.get("count")
        if (type(total) is not int or type(caught) is not int
                or not 0 <= caught <= total <= 10_000
                or type(payload.get("detection_steps")) is not int
                or type(payload.get("detection_caught")) is not int
                or payload.get("detection_steps") != total or payload.get("detection_caught") != caught):
            return None
        return caught, total - caught

    def _render_catch_comparison(self) -> None:
        self._render_performance_badge()
        expected = set(self._report_runs)
        pending = expected - set(self._report_results)
        if pending:
            live = self._live_comparison_counts()
            if live is not None:
                caught, gaps, detail = live
                self.catch_comparison.set_counts(caught, gaps, detail, provisional=True,
                    containment_required=self._containment_requested)
                return
            self.catch_comparison.set_counts(None, None, "Detection results pending · awaiting authenticated reports")
            return
        counts = [self._report_catch_counts.get(kind) for kind in expected]
        if not counts or any(row is None for row in counts):
            self.catch_comparison.set_counts(None, None, "Detection comparison unavailable · incomplete or unverified report")
            return
        caught, missed = sum(row[0] for row in counts), sum(row[1] for row in counts)
        self.catch_comparison.set_counts(caught, missed,
            "No expected-positive steps were eligible for this run" if caught + missed == 0 else "")

    def _live_comparison_counts(self):
        """Use only validated cached rows; no event replay, estimates or authority."""
        if self._run_cancelled or self._performance_session is None or not self._performance_launch_accepted:
            return None
        pending_runs = {run_id for kind, run_id in self._report_runs.items() if kind not in self._report_results}
        rows = [row for run_id, row in self._live_performance.items() if run_id in pending_runs]
        if not rows or any(row.state not in {"pending", "provisional"} for row in rows):
            return None
        evaluated = sum(row.evaluated_steps for row in rows)
        detected = sum(row.detection_verified_steps for row in rows)
        passed = (sum(row.containment_verified_steps for row in rows)
                  if self._containment_requested else detected)
        gaps = sum(row.provisional_failures for row in rows) if self._containment_requested else 0
        if not 0 < passed + gaps <= evaluated <= 10_000:
            return None
        pending_response = evaluated - passed - gaps if self._containment_requested else 0
        detail = (f"Live provisional profiles {len(rows)}/{len(pending_runs)} awaiting final reports; "
            f"{detected}/{evaluated} evaluated checks have verified analytic detection; "
            f"{sum(row.native_verified_steps for row in rows)} native and "
            f"{sum(row.simulation_verified_steps for row in rows)} simulation validations (may overlap). "
            f"{passed} selected criteria met; {gaps} measured response gaps; "
            f"{pending_response} response-pending; "
            f"{sum(row.unsettled_steps for row in rows)} unrun/unsettled; "
            f"{sum(row.unavailable_steps for row in rows)} unavailable. "
            "Pending/unavailable checks and prior finalized profiles are outside this live denominator. "
            "The signed final AAR remains authoritative; no real-attack protection is inferred.")
        return passed, gaps, detail

    @staticmethod
    def _native_analytic_metric(payload: object) -> tuple[int, int] | None:
        """Read a native score only from the verified AAR's exact count fields."""
        if not isinstance(payload, dict):
            return None
        taxonomy = payload.get("evidence_taxonomy")
        if not isinstance(taxonomy, dict):
            return None
        native = taxonomy.get("native_analytic_detection")
        denominator = taxonomy.get("denominator")
        if not isinstance(native, dict):
            return None
        count = native.get("count")
        if (type(count) is not int or type(denominator) is not int
                or denominator <= 0 or not 0 <= count <= denominator):
            return None
        return count, denominator

    @staticmethod
    def _native_file_opportunities(payload: object) -> int | None:
        """Show only a complete, internally consistent signed-plan breakdown."""
        if not isinstance(payload, dict):
            return None
        taxonomy = payload.get("evidence_taxonomy")
        if not isinstance(taxonomy, dict):
            return None
        opportunity = taxonomy.get("native_analytic_opportunity")
        if not isinstance(opportunity, dict):
            return None
        denominator = taxonomy.get("denominator")
        file_count = opportunity.get("file_marker_steps")
        process_count = opportunity.get("process_observation_only_steps")
        unknown_count = opportunity.get("unclassified_steps")
        total = opportunity.get("total_expected_positive_steps")
        if (any(type(value) is not int or value < 0 for value in (
                file_count, process_count, unknown_count, total, denominator,
        )) or total <= 0 or total != denominator
                or file_count + process_count + unknown_count != total):
            return None
        return file_count

    def record_verified_report(
        self, kind: str, run_id: str, payload: dict | None, *, error: str = "",
    ) -> None:
        """Receive only the parent's verified immutable handoff, bound to this run."""
        if not run_id or self._report_runs.get(kind) != run_id:
            return
        try:
            if error:
                raise ValueError(error)
            metrics = payload["epistemic_metrics"]["verified_containment"]
            count, eligible = metrics["count"], metrics["eligible"]
            outcome = str(payload["outcome"])
            if (type(count) is not int or type(eligible) is not int
                    or not 0 <= count <= eligible
                    or outcome not in {"verified", "partial", "failed", "inconclusive"}
                    or (outcome == "verified" and (eligible == 0 or count != eligible))
                    or (outcome == "partial" and not 0 < count < eligible)
                    or (outcome == "failed" and (count != 0 or eligible == 0))):
                raise ValueError("verified containment metrics are inconsistent")
            diagnostic = payload.get("diagnostic_only") is True
            if diagnostic and (
                payload.get("run_id") != run_id or payload.get("coverage_score_eligible") is not False
                or outcome != "inconclusive" or count != 0 or metrics.get("rate") is not None
                or payload.get("validation_status") != "not-currently-verified"
                or payload.get("diagnostic_history_authentication") != "verified"
                or payload.get("readiness_scope") != "historical-at-launch"
                or type(payload.get("planned_steps")) is not int or not 0 <= payload["planned_steps"] <= 10_000
                or type(payload.get("steps_run")) is not int or not 0 <= payload["steps_run"] <= 10_000
                or type(payload.get("detection_steps")) is not int
                or payload["detection_steps"] != eligible or not 0 <= eligible <= payload["planned_steps"]
            ):
                raise ValueError("diagnostic-only report metadata is inconsistent")
            result = {"count": count, "eligible": eligible, "outcome": outcome,
                      "coverage_held": payload.get("coverage_score_eligible") is False,
                      "diagnostic_only": diagnostic,
                      "planned_steps": payload.get("planned_steps") if diagnostic else None,
                      "steps_run": payload.get("steps_run") if diagnostic else None}
        except (KeyError, TypeError, ValueError) as exc:
            result = {"count": 0, "eligible": 0, "outcome": "inconclusive", "error": str(exc)}
        self._report_results[kind] = result
        self._report_catch_counts[kind] = (
            self._caught_metric(payload, run_id) if not error and not result.get("error") else None)
        self._render_catch_comparison()
        self._report_native_analytics[kind] = (
            self._native_analytic_metric(payload) if not error else None
        )
        self._report_native_opportunities[kind] = (
            self._native_file_opportunities(payload) if not error else None
        )
        pending = set(self._report_runs) - set(self._report_results)
        if pending:
            self.live_status.setText("Awaiting authenticated evidence for: " + ", ".join(sorted(pending)))
            self._render_execution_progress()
            return
        count = sum(row["count"] for row in self._report_results.values())
        eligible = sum(row["eligible"] for row in self._report_results.values())
        inconclusive = any(row["outcome"] == "inconclusive" for row in self._report_results.values())
        errors = "; ".join(row["error"] for row in self._report_results.values() if row.get("error"))
        native_metrics = list(self._report_native_analytics.values())
        native_status = (
            f"{sum(row[0] for row in native_metrics)}/"
            f"{sum(row[1] for row in native_metrics)}"
            if native_metrics and all(row is not None for row in native_metrics)
            else "unavailable"
        )
        opportunity_counts = list(self._report_native_opportunities.values())
        if opportunity_counts and all(row is not None for row in opportunity_counts):
            native_status += (
                f" overall; {sum(opportunity_counts)} file-marker opportunities"
            )
        elif native_status != "unavailable":
            native_status += " overall; file-marker opportunities unavailable"
        self.run_spinner.stop()
        self._run_pending = False
        self.launch_btn.setEnabled(True)
        if self._run_cancelled:
            message = "Containment inconclusive — run cancelled; marker cleanup does not prove response success."
            color = "#fbbf24"
        elif any(row.get("diagnostic_only") for row in self._report_results.values()):
            diagnostics = [row for row in self._report_results.values() if row.get("diagnostic_only")]
            message = (
                f"Authenticated diagnostic only — {sum(row['steps_run'] for row in diagnostics)} steps recorded; "
                f"{sum(row['planned_steps'] for row in diagnostics)} mandatory steps planned. "
                "Detection coverage, containment and repair credit remain withheld; review the report's liveness failure."
            )
            color = "#fbbf24"
        elif not self._containment_requested:
            message = f"Detection-only result — {count}/{eligible} verified responses observed; no containment pass assigned."
            color = "#9fb3c8"
        elif inconclusive or eligible == 0:
            message = f"Containment inconclusive — {count}/{eligible} verified. " + (errors or "Review the report for incomplete evidence.")
            color = "#fbbf24"
        elif count == eligible and all(row["outcome"] == "verified" for row in self._report_results.values()):
            message = (
                f"Verified simulation containment — {count}/{eligible} tested targets "
                f"contained; native analytics: {native_status}."
            )
            color = "#2fe38a"
            self.run_spinner.start("Containment verified")
            self.run_spinner.finish("Containment verified")
        elif count == 0 and self.launch_warning.text():
            message = (
                f"Containment unverified — 0/{eligible} verified; response was "
                "unavailable at launch. Review the report."
            )
            color = "#fbbf24"
        else:
            message = f"Containment {'partial' if count else 'failed'} — {count}/{eligible} verified; {eligible - count} remain unverified. Review the report."
            color = "#fbbf24" if count else "#ff7373"
        self.live_status.setText(message)
        self.live_status.setStyleSheet(f"color:{color}; font-size:11px;")
        self.log.append(escape(message))
        self._render_execution_progress()

    # ── History tab ──────────────────────────────────────────────────────────
    def _build_history_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(self._h("Past After-Action Reports"))
        lay.addWidget(QLabel("Previous drill reports, newest first. Text appears only after its signed metadata and digest verify."))
        body = QHBoxLayout()
        self._hist_list = QListWidget(); self._hist_list.setFixedWidth(320)
        self._hist_list.currentItemChanged.connect(self._on_hist_select)
        body.addWidget(self._hist_list)
        self._hist_view = QPlainTextEdit(); self._hist_view.setReadOnly(True)
        self._hist_view.setStyleSheet("font-family:'Fira Code',monospace; font-size:11px;")
        body.addWidget(self._hist_view, 1)
        lay.addLayout(body, 1)
        row = QHBoxLayout()
        refresh = QPushButton("↻ Refresh"); refresh.clicked.connect(self._load_history)
        openf = QPushButton("📂 Open folder"); openf.clicked.connect(self._open_history_folder)
        row.addWidget(refresh); row.addWidget(openf); row.addStretch()
        lay.addLayout(row)
        self._load_history()
        return w

    def _history_dir(self) -> Path:
        try:
            return Path(self._parent.config.data_dir) / "aar_history"
        except Exception:
            return data_dir() / "aar_history"

    def _load_history(self) -> None:
        if not self._hist_accept_results:
            return
        if self._hist_listing:
            self._hist_refresh_pending = True
            return
        self._hist_listing = True
        self._hist_active_name = None
        self._hist_pending_name = None
        self._hist_list.clear()
        self._hist_view.setPlainText("Loading report history…")
        worker = _HistoryWorker("list", self._history_dir())
        receiver = _HistoryResultReceiver(self, getattr(self, "_hist_generation", 0))
        worker.signals.finished.connect(receiver.receive)
        try:
            self._admit_history_worker(worker)
        except Exception as exc:
            worker._retire_signals()
            receiver.deleteLater()
            self._hist_listing = False
            self._hist_view.setPlainText(f"Could not load report history: {exc}")

    @Slot(str, str, object)
    def _on_history_result(self, operation: str, name: str, result: object) -> None:
        if not self._hist_accept_results:
            return
        if operation == "text":
            self._hist_reading = False
            pending = self._hist_pending_name
            self._hist_pending_name = None
            if pending is not None and pending != name:
                self._start_history_read(pending)
                return
            current = self._hist_list.currentItem()
            selected = current.data(Qt.ItemDataRole.UserRole) if current else None
            if selected != name or self._hist_active_name != name:
                return
            label = current.text()
            for prefix in ("◌ ", "✓ ", "⚠ "):
                label = label.removeprefix(prefix)
            if isinstance(result, str):
                current.setText("✓ " + label)
                if len(result) > _MAX_HISTORY_RENDER_CHARS:
                    self._hist_view.setPlainText(
                        result[:_MAX_HISTORY_RENDER_CHARS]
                        + "\n\n[Display shortened after full signature verification. Open the report folder to read the complete signed file.]"
                    )
                else:
                    self._hist_view.setPlainText(result)
            else:
                current.setText("⚠ " + label)
                reason = result.get("error", "unknown error") if isinstance(result, dict) else "unknown error"
                self._hist_view.setPlainText(f"Report authenticity could not be verified: {reason}")
            return

        self._hist_listing = False
        if self._hist_refresh_pending:
            self._hist_refresh_pending = False
            self._load_history()
            return
        if isinstance(result, dict) and "error" in result:
            self._hist_view.setPlainText(f"Could not load report history: {result['error']}")
            return
        listing = result if isinstance(result, HistoryListing) else HistoryListing([])
        files = listing.rows
        if not files:
            label = "(history scan limited; no verified reports found)" if listing.limited else "(no past reports yet — run a simulation)"
            it = QListWidgetItem(label)
            it.setData(Qt.ItemDataRole.UserRole, None)
            self._hist_list.addItem(it)
            self._hist_view.setPlainText("History scan reached its safety limit; no authenticated report was found." if listing.limited else "No authenticated report history is available.")
            return
        for name, modified, basename in files:
            kind = "RED TEAM" if basename == "redteam_aar" else "SHARK"
            try:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(modified))
            except Exception:
                ts = "?"
            it = QListWidgetItem(f"◌ {kind}  ·  {ts}")
            it.setData(Qt.ItemDataRole.UserRole, name)
            self._hist_list.addItem(it)
        if listing.limited:
            it = QListWidgetItem("(history scan limited; showing verified reports found)")
            it.setData(Qt.ItemDataRole.UserRole, None)
            self._hist_list.addItem(it)
        self._hist_list.setCurrentRow(0)

    def _on_hist_select(self, cur, _prev) -> None:
        if cur is None:
            return
        name = cur.data(Qt.ItemDataRole.UserRole)
        if not name:
            self._hist_view.setPlainText("")
            return
        self._hist_active_name = name
        self._hist_view.setPlainText("Verifying report signature and text…")
        if self._hist_reading:
            self._hist_pending_name = name
            return
        self._start_history_read(name)

    def _start_history_read(self, name: str) -> None:
        self._hist_reading = True
        worker = _HistoryWorker("text", self._history_dir(), name)
        receiver = _HistoryResultReceiver(self, getattr(self, "_hist_generation", 0))
        worker.signals.finished.connect(receiver.receive)
        try:
            self._admit_history_worker(worker)
        except Exception as exc:
            worker._retire_signals()
            receiver.deleteLater()
            self._hist_reading = False
            self._hist_view.setPlainText(f"Could not verify report history: {exc}")

    def _admit_history_worker(self, worker) -> None:
        # QThreadPool.start() queues without a bound. Reopened consoles must
        # not accumulate readers behind a stuck filesystem or signature read.
        # Reject promptly; the existing Refresh action is the explicit retry.
        attempt = getattr(self._history_pool, "tryStart", None)
        if callable(attempt):
            if not attempt(worker):
                raise RuntimeError("history readers are busy; select Refresh to retry")
        else:
            self._history_pool.start(worker)  # compatibility for external hosts

    def _stop_history_loads(self, _result: int) -> None:
        self._hist_accept_results = False
        self._hist_generation = getattr(self, "_hist_generation", 0) + 1
        self._hist_listing = self._hist_reading = self._hist_refresh_pending = False
        self._hist_pending_name = self._hist_active_name = None

    def _on_tab_changed(self, idx: int) -> None:
        try:
            if idx == 0:
                self._refresh_response_readiness()
            if "History" in self._tabs.tabText(idx):
                self._load_history()
            if "Sandbox Editor" in self._tabs.tabText(idx) and not self._editor_loaded:
                self._load_editor()
        except Exception:
            pass

    def _open_history_folder(self) -> None:
        import subprocess
        d = self._history_dir()
        try:
            d.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                os.startfile(str(d))   # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(d)])
        except Exception:
            pass

    # ── Device Security Lab ──────────────────────────────────────
    def _device_lab_root(self) -> Path:
        try:
            root = Path(self._parent.config.data_dir)
        except Exception:
            root = data_dir()
        return root / "device-security-lab"

    def _device_lab_service(self):
        service = getattr(self, "_device_lab", None)
        if service is None:
            from angerona.core.device_security_lab import DeviceSecurityLab

            service = DeviceSecurityLab(self._device_lab_root())
            self._device_lab = service
        return service

    def _build_device_lab_tab(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(4, 4, 4, 4)
        outer.setSpacing(8)

        safety = QLabel(
            "Owner-authorized posture assessment only. Angerona passively inspects "
            "this computer or verifies fresh signed evidence from an enrolled companion. "
            "It does not scan arbitrary targets, crack wireless security, inject packets, "
            "guess credentials, or execute exploits."
        )
        safety.setWordWrap(True)
        safety.setStyleSheet(
            "background:#10223a; color:#bfdbfe; border:1px solid #2563eb; "
            "border-radius:6px; padding:8px;"
        )
        outer.addWidget(safety)

        enrollment = QFrame()
        enrollment.setObjectName("Card")
        form = QGridLayout(enrollment)
        form.addWidget(self._h("Authenticated device enrollment"), 0, 0, 1, 4)
        self.device_label = QLineEdit()
        self.device_label.setPlaceholderText("Friendly name, e.g. Living-room Mac")
        self.device_source = QComboBox()
        self.device_source.addItem("This computer (passive inspection)", "local")
        self.device_source.addItem("Owned companion device (signed evidence)", "enrolled_agent")
        form.addWidget(QLabel("Device"), 1, 0)
        form.addWidget(self.device_label, 1, 1)
        form.addWidget(QLabel("Evidence source"), 1, 2)
        form.addWidget(self.device_source, 1, 3)

        self.device_owner_attested = QCheckBox(
            "I own this device or have explicit permission to assess it"
        )
        form.addWidget(self.device_owner_attested, 2, 0, 1, 4)
        form.addWidget(QLabel("Allowed connection evidence"), 3, 0, 1, 4)
        self._device_connection_checks: dict[str, QCheckBox] = {}
        connection_row = QHBoxLayout()
        for key, label in (
            ("usb", "USB"),
            ("ethernet", "Ethernet + local ports"),
            ("wifi", "Wi-Fi"),
            ("bluetooth", "Bluetooth"),
            ("display_hdmi", "Display / HDMI"),
        ):
            check = QCheckBox(label)
            check.setChecked(True)
            self._device_connection_checks[key] = check
            connection_row.addWidget(check)
        connection_row.addStretch()
        form.addLayout(connection_row, 4, 0, 1, 4)

        enroll_button = QPushButton("➕  Create enrollment")
        enroll_button.clicked.connect(self._create_device_enrollment)
        refresh_button = QPushButton("↻  Refresh")
        refresh_button.clicked.connect(self._refresh_device_enrollments)
        form.addWidget(enroll_button, 5, 2)
        form.addWidget(refresh_button, 5, 3)
        outer.addWidget(enrollment)

        pairing = QFrame()
        pairing.setObjectName("Card")
        pairing_layout = QGridLayout(pairing)
        pairing_layout.addWidget(self._h("Companion pairing response"), 0, 0, 1, 4)
        pairing_help = QLabel(
            "For a companion enrollment, transfer the displayed short-lived challenge "
            "to the owned device. Paste its Ed25519 signature and public key here. "
            "The private device key must never leave that device."
        )
        pairing_help.setWordWrap(True)
        pairing_layout.addWidget(pairing_help, 1, 0, 1, 4)
        self.device_pairing_proof = QLineEdit()
        self.device_pairing_proof.setPlaceholderText("Challenge signature (base64)")
        self.device_pairing_key = QLineEdit()
        self.device_pairing_key.setPlaceholderText("Ed25519 public key (base64)")
        confirm_button = QPushButton("🔐  Confirm companion")
        confirm_button.clicked.connect(self._confirm_device_enrollment)
        export_challenge = QPushButton("📤  Export challenge")
        export_challenge.clicked.connect(self._export_device_challenge)
        import_response = QPushButton("📥  Import response")
        import_response.clicked.connect(self._import_device_pairing_response)
        pairing_layout.addWidget(self.device_pairing_proof, 2, 0, 1, 2)
        pairing_layout.addWidget(self.device_pairing_key, 2, 2)
        pairing_layout.addWidget(confirm_button, 2, 3)
        pairing_layout.addWidget(export_challenge, 3, 2)
        pairing_layout.addWidget(import_response, 3, 3)
        outer.addWidget(pairing)

        body = QHBoxLayout()
        self.device_enrollments = QListWidget()
        self.device_enrollments.setMinimumWidth(260)
        body.addWidget(self.device_enrollments)
        self.device_findings = QTableWidget(0, 5)
        self.device_findings.setHorizontalHeaderLabels(
            ["Severity", "Weakness", "Evidence", "Solution", "Patch guidance"]
        )
        self.device_findings.setWordWrap(True)
        self.device_findings.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.device_findings.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.device_findings.setSortingEnabled(True)
        self.device_findings.cellDoubleClicked.connect(
            self._show_device_finding_detail
        )
        self.device_findings.horizontalHeader().setStretchLastSection(True)
        body.addWidget(self.device_findings, 1)
        outer.addLayout(body, 1)

        self.device_lab_log = QPlainTextEdit()
        self.device_lab_log.setReadOnly(True)
        self.device_lab_log.document().setMaximumBlockCount(1000)
        self.device_lab_log.setMaximumHeight(120)
        outer.addWidget(self.device_lab_log)

        actions = QHBoxLayout()
        inspect_button = QPushButton("🖥  Inspect this computer")
        inspect_button.clicked.connect(self._inspect_local_device)
        import_button = QPushButton("📥  Import signed device report")
        import_button.clicked.connect(self._import_device_evidence)
        export_button = QPushButton("📤  Export findings")
        export_button.clicked.connect(self._export_device_report)
        actions.addWidget(inspect_button)
        actions.addWidget(import_button)
        actions.addStretch()
        actions.addWidget(export_button)
        outer.addLayout(actions)
        self._device_pending_id = ""
        self._device_pending_challenge: dict[str, object] | None = None
        self._device_report: dict[str, object] | None = None
        self._refresh_device_enrollments()
        return w

    def _selected_device_enrollment(self) -> str:
        item = self.device_enrollments.currentItem()
        if item is None:
            return ""
        return str(item.data(Qt.ItemDataRole.UserRole) or "")

    def _allowed_device_connections(self) -> list[str]:
        return [
            key for key, check in self._device_connection_checks.items()
            if check.isChecked()
        ]

    def _create_device_enrollment(self) -> None:
        if not self.device_owner_attested.isChecked():
            QMessageBox.warning(
                self,
                "Authorization required",
                "Confirm that you own the device or have explicit permission.",
            )
            return
        label = self.device_label.text().strip()
        if not label:
            QMessageBox.information(self, "Device name", "Enter a friendly device name.")
            return
        source = str(self.device_source.currentData())
        try:
            service = self._device_lab_service()
            record, challenge = service.create_enrollment(
                label,
                True,
                evidence_source=source,
                allowed_connections=self._allowed_device_connections(),
            )
            record_data = record.to_dict()
            enrollment_id = str(record_data["enrollment_id"])
            if source == "local":
                self._device_pending_id = ""
                self._device_pending_challenge = None
                service.confirm_local_enrollment(enrollment_id, owner_attested=True)
                self.device_lab_log.setPlainText(
                    "Local enrollment confirmed. Select it, then press Inspect this computer."
                )
            else:
                self._device_pending_id = enrollment_id
                challenge_data = challenge.to_dict()
                self._device_pending_challenge = challenge_data
                self.device_lab_log.setPlainText(
                    "PAIRING CHALLENGE (safe to transfer to the owned device):\n"
                    + json.dumps(challenge_data, indent=2, sort_keys=True)
                )
            self._refresh_device_enrollments(enrollment_id)
        except Exception as exc:
            QMessageBox.warning(self, "Enrollment failed", str(exc))

    def _confirm_device_enrollment(self) -> None:
        enrollment_id = self._device_pending_id or self._selected_device_enrollment()
        if not enrollment_id:
            QMessageBox.information(
                self, "Companion pairing", "Create or select a pending companion enrollment."
            )
            return
        try:
            self._device_lab_service().confirm_enrollment(
                enrollment_id,
                self.device_pairing_proof.text().strip(),
                self.device_pairing_key.text().strip(),
            )
            self.device_pairing_key.clear()
            self.device_pairing_proof.clear()
            self._device_pending_id = ""
            self._device_pending_challenge = None
            self.device_lab_log.setPlainText(
                "Companion public identity confirmed. Import only its fresh signed "
                "evidence reports; its private key was never shared."
            )
            self._refresh_device_enrollments(enrollment_id)
        except Exception as exc:
            self.device_pairing_key.clear()
            QMessageBox.warning(self, "Pairing refused", str(exc))

    def _export_device_challenge(self) -> None:
        challenge = self._device_pending_challenge
        if challenge is None:
            QMessageBox.information(
                self, "Pairing challenge", "Create a companion enrollment first."
            )
            return
        path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export short-lived companion challenge",
            str(Path.home() / "angerona-device-challenge.json"),
            "JSON challenge (*.json)",
        )
        if not path:
            return
        try:
            Path(path).write_text(
                json.dumps(challenge, indent=2, sort_keys=True), encoding="utf-8"
            )
            self.device_lab_log.appendPlainText(
                "Challenge exported. It expires quickly and contains no private key."
            )
        except Exception as exc:
            QMessageBox.warning(self, "Export failed", str(exc))

    def _import_device_pairing_response(self) -> None:
        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Import companion pairing response",
            str(Path.home()),
            "JSON response (*.json)",
        )
        if not path:
            return
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("pairing response must contain a JSON object")
            enrollment_id = str(payload.get("enrollment_id", ""))
            if enrollment_id != self._device_pending_id:
                raise ValueError("pairing response does not match the pending enrollment")
            self.device_pairing_proof.setText(str(payload.get("signature_ed25519", "")))
            self.device_pairing_key.setText(str(payload.get("public_key_ed25519", "")))
            self._confirm_device_enrollment()
        except Exception as exc:
            QMessageBox.warning(self, "Pairing response refused", str(exc))

    def _refresh_device_enrollments(self, select_id: str = "") -> None:
        widget = getattr(self, "device_enrollments", None)
        if widget is None:
            return
        widget.clear()
        try:
            records = self._device_lab_service().list_enrollments()
        except Exception as exc:
            widget.addItem(f"Device Lab unavailable: {exc}")
            return
        for record in records:
            data = record.to_dict()
            enrollment_id = str(data.get("enrollment_id", ""))
            state = str(data.get("state", data.get("status", "pending")))
            source = str(data.get("evidence_source", "device"))
            item = QListWidgetItem(
                f"{data.get('label', 'Device')}  ·  {source}  ·  {state}"
            )
            item.setData(Qt.ItemDataRole.UserRole, enrollment_id)
            widget.addItem(item)
            if enrollment_id == select_id:
                widget.setCurrentItem(item)

    def _inspect_local_device(self) -> None:
        enrollment_id = self._selected_device_enrollment()
        if not enrollment_id:
            QMessageBox.information(
                self, "Device Security Lab", "Select a confirmed local enrollment first."
            )
            return
        if not self.device_owner_attested.isChecked():
            QMessageBox.warning(
                self,
                "Authorization required",
                "Reconfirm ownership or explicit permission for this assessment.",
            )
            return
        try:
            service = self._device_lab_service()
            observations = service.collect_local_observations(
                enrollment_id, owner_attested=True
            )
            report = service.assess(enrollment_id, observations)
            self._show_device_report(report.to_dict())
        except Exception as exc:
            QMessageBox.warning(self, "Assessment refused", str(exc))

    def _import_device_evidence(self) -> None:
        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Import signed Device Security Lab evidence",
            str(Path.home()),
            "JSON evidence (*.json)",
        )
        if not path:
            return
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("evidence file must contain a JSON object")
            if isinstance(payload.get("payload"), dict):
                envelope_payload = payload["payload"]
                enrollment_id = str(envelope_payload.get("enrollment_id", ""))
                observations = envelope_payload.get("observations", [])
                evidence = payload
            else:
                enrollment_id = str(payload.get("enrollment_id", ""))
                observations = payload.get("observations", [])
                evidence = payload.get("evidence")
            report = self._device_lab_service().assess(
                enrollment_id, observations, evidence=evidence
            )
            self._show_device_report(report.to_dict())
        except Exception as exc:
            QMessageBox.warning(self, "Evidence refused", str(exc))

    def _show_device_report(self, report: dict[str, object]) -> None:
        self._device_report = report
        findings = report.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        header = self.device_findings.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self.device_findings.setSortingEnabled(False)
        self.device_findings.setUpdatesEnabled(False)
        self.device_findings.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            data = finding if isinstance(finding, dict) else {}
            values = (
                data.get("severity", "Info"),
                data.get("title", data.get("weakness", "Posture observation")),
                data.get("evidence", "Redacted evidence available in export"),
                data.get("remediation", data.get("solution", "Review configuration")),
                data.get("patch_guidance", data.get("patch", "Follow vendor guidance")),
            )
            for column, value in enumerate(values):
                if isinstance(value, (dict, list)):
                    text = json.dumps(value, sort_keys=True)
                else:
                    text = str(value)
                cell = QTableWidgetItem(text)
                cell.setData(Qt.UserRole, data)
                self.device_findings.setItem(row, column, cell)
        self.device_findings.setSortingEnabled(True)
        if sort_column >= 0:
            self.device_findings.sortItems(sort_column, sort_order)
        self.device_findings.setUpdatesEnabled(True)
        self.device_findings.resizeRowsToContents()
        summary = report.get("summary")
        if not isinstance(summary, dict):
            summary = {
                "outcome": report.get("outcome", "complete"),
                "severity_counts": report.get("severity_counts", {}),
                "observation_count": report.get("observation_count", 0),
                "limitations": report.get("limitations", []),
            }
        self.device_lab_log.setPlainText(
            "ASSESSMENT COMPLETE\n" + json.dumps(summary, indent=2, sort_keys=True)
        )

    def _show_device_finding_detail(self, row: int, _column: int) -> None:
        cell = self.device_findings.item(row, 0)
        finding = cell.data(Qt.UserRole) if cell is not None else None
        if not isinstance(finding, dict):
            return
        detail = json.dumps(
            finding, indent=2, sort_keys=True, ensure_ascii=False, default=str
        )[:16_384]
        QMessageBox.information(
            self,
            str(finding.get("title") or finding.get("weakness") or "Finding details")[:200],
            detail,
        )

    def _export_device_report(self) -> None:
        if self._device_report is None:
            QMessageBox.information(
                self, "Export findings", "Run or import an assessment first."
            )
            return
        path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export redacted Device Security Lab findings",
            str(self._device_lab_root() / "device-security-findings.json"),
            "JSON report (*.json)",
        )
        if not path:
            return
        try:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(self._device_report, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            self.device_lab_log.appendPlainText(f"Exported redacted report: {target.name}")
        except Exception as exc:
            QMessageBox.warning(self, "Export failed", str(exc))

    def _build_editor_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(self._h("Sandbox editor — isolated red-team working copy"))
        help_text = QLabel(
            "Experiment with techniques, jitter, process spawns, or a new stage. "
            "Save writes only to Angerona's runtime code-sandbox after a Python "
            "syntax check. Reload discards unsaved editor text; Roll back restores "
            "the working copy from the installed engine. Sandbox code is never "
            "executed or copied over the live application."
        )
        help_text.setWordWrap(True)
        lay.addWidget(help_text)
        self._editor_workspace: SourceSandboxWorkspace | None = None
        self._editor_loaded = False
        self._editor_job = None
        self._editor_reader = AsyncSnapshot(
            self, self._prepare_editor_job, self._apply_editor_result,
            name="RedTeamEditorWorker",
        )
        self.editor = QPlainTextEdit()
        self.editor.setStyleSheet("font-family:'Fira Code',monospace; font-size:11px;")
        lay.addWidget(self.editor, 1)
        row = QHBoxLayout()
        self._editor_save = QPushButton("💾  Save working copy")
        self._editor_save.clicked.connect(self._save_editor)
        self._editor_reload = QPushButton("↻  Reload saved copy")
        self._editor_reload.clicked.connect(self._reload_editor)
        self._editor_rollback = QPushButton("↩  Roll back copy")
        self._editor_rollback.clicked.connect(self._rollback_editor)
        self.edit_status = QLabel(""); self.edit_status.setStyleSheet("color:#9fb3c8;")
        row.addWidget(self._editor_save)
        row.addWidget(self._editor_reload)
        row.addWidget(self._editor_rollback)
        row.addWidget(self.edit_status, 1)
        lay.addLayout(row)
        # Opening Run must not create/check a sandbox for an unvisited tab.
        self._set_editor_busy(True)
        self.edit_status.setText("Open this tab to load the isolated working copy.")
        return w

    # ── helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _h(text: str) -> QLabel:
        lbl = QLabel(text); lbl.setStyleSheet("font-weight:700; color:#dbeafe;")
        return lbl

    @staticmethod
    def _chip_css(state: str) -> str:
        base = (
            "border-radius:8px; padding:6px 8px; font-size:11px; "
            "font-weight:650;"
        )
        if state == "current":
            return (
                "background:#7f1d1d; color:#fff1f2; border:2px solid #fb7185;" + base
            )
        if state == "complete":
            return (
                "background:#064e3b; color:#d1fae5; border:1px solid #34d399;" + base
            )
        return (
            "background:#111c2e; color:#9fb3c8; border:1px solid #334155;" + base
        )

    @staticmethod
    def _stage_from_narration(text: str) -> str | None:
        """Return the stable stage key for an engine STAGE narration line."""
        lowered = str(text).lower()
        if "stage:" not in lowered:
            return None
        matches = [
            (len(alias), key)
            for key, _label, aliases in _STAGES
            for alias in aliases
            if alias in lowered
        ]
        return max(matches, default=(0, None))[1]

    def _set_chip_state(self, key: str, state: str) -> None:
        chip = self._chips.get(key)
        if chip is None:
            return
        chip.setProperty("stageState", state)
        chip.setStyleSheet(self._chip_css(state))

    def _on_intensity(self, val: int) -> None:
        name = _INTENSITY[val]
        self.sld_lbl.setText(name)
        self.inten_desc.setText(_INTENSITY_DESC[name])

    def _on_preset(self, text: str) -> None:
        if text in self._presets:
            self.loc_edit.setText(self._presets[text])

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose marker location", self.loc_edit.text())
        if d:
            self.loc_edit.setText(d)

    def _stage_detail_text(self, key: str) -> str:
        """Return exact, stage-specific evidence without reading unrelated rows."""
        label = _STAGE_LABELS.get(key, key.replace("_", " ").title())
        chip = self._chips.get(key)
        state = str(chip.property("stageState") or "idle") if chip else "unknown"
        meta = _STAGE_DETAILS.get(key, {})
        lines = [
            f"Stage: {label}",
            f"State: {state}",
            f"Tactic: {meta.get('tactic', 'simulation')}",
            f"Technique: {meta.get('technique', 'see authenticated run manifest')}",
            "Safety boundary: fixed inert marker/read-only probe only; no exploit, "
            "credential access, persistence, remote connection, outbound traffic, "
            "security-control bypass, collection, encryption, or deletion.",
        ]

        method_names = {
            "initial_access": "_step_initial_access",
            "discovery": "_step_recon",
            "credential_access": "_step_credential_access",
            "privilege_escalation": "_step_privilege_escalation",
            "defense_evasion": "_step_defense_evasion",
            "registry_run_key": "_step_registry_runkey",
            "scheduled_task": "_step_scheduled_task",
            "wmi_persistence": "_step_wmi_persistence",
            "lateral_movement": "_step_lateral_movement",
            "command_control": "_step_c2_beacon",
            "exfiltration": "_step_exfil_staging",
            "ransomware": "_step_ransomware_canary",
            "data_destruction": "_step_data_destruction",
            "benign_execution": "_step_random_processes",
        }
        method_name = method_names.get(key, f"_step_{key}")
        try:
            import inspect
            from angerona.shark.red_team import RedTeamEngine

            method = getattr(RedTeamEngine, method_name)
            _, line = inspect.getsourcelines(method)
            lines.append(f"Implementation: {Path(inspect.getsourcefile(method) or _RED_TEAM_SOURCE)}:{line}")
        except (AttributeError, OSError, TypeError):
            lines.append(f"Implementation: {_RED_TEAM_SOURCE}")

        evidence: list[str] = []
        for engine_name in ("red_team_engine", "shark_engine"):
            engine = getattr(self._parent, engine_name, None)
            for step in list(getattr(engine, "steps", ()) or ()):
                stage = str(getattr(step, "stage", ""))
                resolved = self._stage_from_narration(f"▶ STAGE: {stage}")
                if resolved != key:
                    continue
                evidence.append(
                    f"{engine_name}: {stage} · {getattr(step, 'technique', '')} · "
                    f"ok={bool(getattr(step, 'ok', False))}"
                )
                elapsed = getattr(step, "duration_ms", None)
                if isinstance(elapsed, (int, float)) and elapsed >= 0:
                    evidence.append(f"  elapsed: {elapsed:.1f} ms (includes configured jitter and validation)")
                for path in list(getattr(step, "artifact_paths", ()) or ()):
                    evidence.append(f"  artifact: {path}")
                for pid in list(getattr(step, "pids", ()) or ()):
                    evidence.append(f"  bounded drill PID: {pid}")
        lines.append("Evidence:")
        lines.extend(evidence or ["  No stage evidence has been recorded in this window yet."])
        messages = self._stage_messages.get(key, [])[-4:]
        if messages:
            lines.append("Recent stage narration:")
            lines.extend(f"  {message}" for message in messages)
        return "\n".join(lines)

    def _open_stage_detail(self, key: str) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(f"{_STAGE_LABELS.get(key, key)} — exact stage evidence")
        dialog.setMinimumSize(640, 420)
        layout = QVBoxLayout(dialog)
        detail = QPlainTextEdit(self._stage_detail_text(key))
        detail.setReadOnly(True)
        detail.setObjectName("RedTeamStageEvidence")
        layout.addWidget(detail, 1)
        close = QPushButton("Close")
        close.clicked.connect(dialog.close)
        row = QHBoxLayout(); row.addStretch(1); row.addWidget(close)
        layout.addLayout(row)
        self._stage_detail_dialog = dialog
        from angerona.gui.window_controls import configure_work_window
        configure_work_window(dialog)
        dialog.show()
        dialog.raise_()

    def _on_narration(self, text: str) -> None:
        message = str(text)
        self.log.append(escape(message))
        stage = self._stage_from_narration(message)
        if stage is None:
            return
        self._stage_messages.setdefault(stage, []).append(message)
        self._stage_messages[stage] = self._stage_messages[stage][-16:]
        if self._active_stage is not None and self._active_stage != stage:
            self._set_chip_state(self._active_stage, "complete")
        self._active_stage = stage
        self._set_chip_state(stage, "current")
        self.live_status.setText(f"Current stage: {_STAGE_LABELS[stage]}")

    def _reset_chips(self) -> None:
        self._active_stage = None
        for key in self._chips:
            self._set_chip_state(key, "idle")
        self.live_status.setText("Starting simulation…")

    # ── launch / stop ────────────────────────────────────────────────────────
    def _launch(self) -> None:
        if self._run_pending:
            return
        self._refresh_response_readiness()
        if not (self.cb_shark.isChecked() or self.cb_apt.isChecked()):
            QMessageBox.information(self, "Red Team", "Pick at least one attack profile.")
            return
        self._reset_chips()
        self.log.clear()
        cfg = {
            "run_shark": self.cb_shark.isChecked(),
            "run_redteam": self.cb_apt.isChecked(),
            "intensity": _INTENSITY[self.sld.value()],
            "campaign": self.cb_campaign.isChecked(),
            "comprehensive": self.cb_comprehensive.isChecked(),
            "target_dir": self.loc_edit.text().strip() or None,
            "custom": ({"name": self.custom_name.text().strip(),
                        "payload": self.custom_payload.text()}
                       if self.custom_name.text().strip() and self.custom_payload.text().strip()
                       else None),
            "auto_remediate": self.cb_remediate.isChecked(),
            # Coaching is intentionally reserved for a later Red Team UI.
            "analogy": False,
            # legacy: map intensity → phase count for back-compat consumers
            "complexity": self.sld.value() + 1,
        }
        try:
            result = self._parent._run_simulation(cfg)
            if not isinstance(result, dict):
                result = {"status": "rejected", "reason": "No launch acceptance was returned."}
            if not result.get("dispatched"):
                self.set_launch_status(result, cfg)
        except Exception as exc:
            self.set_launch_status({"status": "rejected", "reason": str(exc)}, cfg)
            QMessageBox.warning(self, "Launch failed", str(exc))

    def _stop(self) -> None:
        if self._parent is not None:
            self._parent._pending_simulation_cfg = None
        if self._run_pending and not self._launch_queued:
            self._run_cancelled = True
        if self._launch_queued and not self._launch_preparing:
            self._launch_queued = False
            self._run_pending = False
        stop = getattr(self._parent, "_stop_simulation", None)
        if callable(stop):
            stop()
        else:
            # Detached compatibility hosts also clean up outside Qt.
            import threading
            from angerona.gui.simulation_launch import stop_engines

            engines = tuple(getattr(self._parent, name, None) for name in (
                "red_team_engine", "shark_engine"))
            threading.Thread(target=stop_engines, args=(engines, threading.Event()),
                             name="simulation-stop", daemon=True).start()
        try:
            self.run_spinner.stop()
        except Exception:
            pass
        self.live_status.setText("Stop requested — cleaning simulation markers…")
        self.launch_btn.setEnabled(not self._run_pending)
        self.log.append("■ Stop requested — engines cleaning up their markers.")
        self._render_performance_badge()

    def _cancel_preparing_launch(self, *_unused) -> None:
        cancel = getattr(self._parent, "_cancel_simulation_launch", None)
        if callable(cancel):
            cancel()

    def record_cleanup_failure(self, message: str) -> None:
        self._run_cancelled = True
        self._render_performance_badge()
        self.live_status.setText(str(message) + " — retry Stop & clean. No cleanup success is claimed.")
        self.live_status.setStyleSheet("color:#fbbf24; font-size:11px;")
        self.log.append(escape(str(message)))

    # ── editor ───────────────────────────────────────────────────────────────
    def _set_editor_busy(self, busy: bool) -> None:
        ready = self._editor_loaded and not busy
        self.editor.setReadOnly(not ready)
        for button in (self._editor_save, self._editor_rollback):
            button.setEnabled(ready)
        self._editor_reload.setEnabled(not busy)

    def _prepare_editor_job(self):
        operation, work = self._editor_job
        self._editor_job = None
        return lambda: _run_editor_job(operation, work)

    def _start_editor_job(self, operation: str, work) -> None:
        if self._editor_reader.busy:
            return
        self._editor_job = operation, work
        self._set_editor_busy(True)
        self.edit_status.setToolTip("")
        self.edit_status.setText({
            "load": "Loading isolated working copy…",
            "save": "Saving isolated working copy…",
            "rollback": "Restoring isolated working copy…",
        }[operation])
        self._editor_reader.request()
        if not self._editor_reader.busy:
            self._editor_job = None
            self._apply_editor_result((operation, False, RuntimeError("Editor worker unavailable")))

    def _apply_editor_result(self, result) -> None:
        operation, success, value = result
        if success:
            for button in (self._editor_save, self._editor_reload, self._editor_rollback):
                button.setToolTip("")
            if operation in ("load", "rollback"):
                self._editor_workspace, source, modified = value
                self.editor.setPlainText(source)
                self._editor_loaded = True
                suffix = " (modified)" if modified else ""
                self.edit_status.setText(
                    "✅ working copy rolled back; live engine unchanged"
                    if operation == "rollback"
                    else f"Loaded isolated working copy{suffix}"
                )
            else:
                self.edit_status.setText("✅ isolated working copy saved (live engine unchanged)")
        else:
            self.edit_status.setToolTip(str(value))
            if operation == "load" and not self._editor_loaded:
                self.edit_status.setText(
                    "❌ sandbox unavailable; simulation controls remain usable"
                )
                for button in (self._editor_save, self._editor_reload, self._editor_rollback):
                    button.setToolTip(
                        "The protected working-copy directory is unavailable. "
                        "Simulation controls are unaffected."
                    )
            elif isinstance(value, SyntaxError):
                self.edit_status.setText(f"❌ syntax error line {value.lineno} — not saved")
            else:
                self.edit_status.setText(f"❌ working copy {operation} failed; editor text retained")
        self._set_editor_busy(False)

    def _load_editor(self) -> None:
        if self._editor_reader.busy:
            return
        workspace, factory = self._editor_workspace, SourceSandboxWorkspace

        def load():
            active = workspace if workspace is not None else factory(
                "red-team-console", (_RED_TEAM_SOURCE,)
            )
            source = active.reload(_RED_TEAM_SOURCE)
            return active, source, active.changed(_RED_TEAM_SOURCE)

        self._start_editor_job("load", load)

    def _reload_editor(self) -> None:
        """Discard unsaved buffer text and reload the saved sandbox copy."""
        self._load_editor()

    def _save_editor(self) -> None:
        if self._editor_reader.busy:
            return
        _editor_workspace = self._editor_workspace
        if _editor_workspace is None:
            self.edit_status.setText("❌ sandbox working copy unavailable")
            return
        src = self.editor.toPlainText()
        self._start_editor_job("save", lambda: _editor_workspace.save(_RED_TEAM_SOURCE, src))

    def _rollback_editor(self) -> None:
        """Restore only the runtime working copy from immutable installed source."""
        if self._editor_reader.busy:
            return
        if self._editor_workspace is None:
            self.edit_status.setText("❌ sandbox working copy unavailable")
            return
        answer = QMessageBox.question(
            self,
            "Roll back sandbox working copy?",
            "Discard every saved experiment in this editor and restore the "
            "installed red-team source into the isolated working copy? The live "
            "application will not be changed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            self.edit_status.setText("Rollback cancelled")
            return
        workspace = self._editor_workspace

        def rollback():
            workspace.rollback((_RED_TEAM_SOURCE,))
            return workspace, workspace.reload(_RED_TEAM_SOURCE), workspace.changed(_RED_TEAM_SOURCE)

        self._start_editor_job("rollback", rollback)
