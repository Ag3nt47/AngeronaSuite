"""Main window — single-screen dashboard.

Everything is visible at once (mirroring the original Angerona layout):
a header with brand + threat, a row of stat cards, and a split body with the
Modules panel on the left and the Live Alerts feed on the right. Settings open
in a dialog from the header button.
"""
from __future__ import annotations

import hashlib
import json
import queue
import threading
import time

from PySide6.QtCore import QEvent, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QIcon, QPixmap
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QMainWindow, QMenu, QMessageBox, QPushButton, QSplitter,
    QSystemTrayIcon, QTabWidget, QVBoxLayout, QWidget,
)

from angerona.academy.security_academy import FlightInstructor
from angerona.branding import icon_path
from angerona.core.commands import CommandConsole
from angerona.core.chill_mode import (
    CHILL_PAUSED_MODULES,
    CHILL_THROTTLE_FLOORS,
    ChillPolicy,
)
from angerona.core.eco_wakeup import EcoWakeupWorker
from angerona.core.eventbus import Severity
from angerona.gui.animations import RunSpinner
from angerona.gui.header_controls import (
    HeaderActionButton, PanelRevealOverlay, motion_allowed)
from angerona.gui.holographic_orb import HolographicOrbController
from angerona.gui.dashboard_details import (
    AriaDetailDialog,
    SystemPulseDetailDialog,
)
from angerona.gui.pages import (
    AARDialog, AlertsPanel, CommandConsolePanel, DashboardCards, ModuleInspector,
    ModulesPanel, ResourceStrip, SettingsDialog, SharkMonitorDialog, SoarPanel,
    StatusStrip,
)
from angerona.gui.sandbox_editor import launch_sandbox_editor
from angerona.gui.scan_center import ScanCenterPanel
from angerona.gui.upgrade_console import launch_upgrade_console
from angerona.gui.system_pulse import SystemPulseCard
from angerona.gui.theme import build_qss, clamp_scale
from angerona.gui.threat_intel_page import ThreatIntelDashboard
from angerona.shark.shark_attack import SharkAttackEngine
from angerona.shark.red_team import RedTeamEngine, REDTEAM_STAGE_CATEGORY
from angerona.updater.github_updater import check_for_updates

class _NoAnim:
    """No-op stand-in for the removed shark/sword animations. Absorbs any
    start()/stop()/set_active()/setGeometry()/etc. call so existing call sites
    keep working while nothing renders."""
    def __getattr__(self, _name):
        return lambda *_args, **_kwargs: None


def _dashboard_refresh_plan(
    quiet_chill: bool,
    *,
    visible: bool,
    active: bool,
) -> tuple[int, int, int, int, int]:
    """Return bounded dashboard timing for the current presentation state.

    The tuple is ``(timer_ms, status_ticks, panel_ticks, posture_ticks,
    flow_ticks)``.  Security events have their own event-driven wake path, so
    these periods govern presentation work only.  Expressing the old cadences
    in elapsed time (rather than assuming every tick is one second) avoids the
    accidental five-minute flow delay that a naively slowed Qt timer creates.
    """
    if not visible:
        return (15_000, 2, 4, 4, 4)       # 30 / 60 / 60 / 60 seconds
    if quiet_chill and not active:
        return (10_000, 1, 1, 2, 6)       # 10 / 10 / 20 / 60 seconds
    if quiet_chill:
        return (5_000, 2, 2, 4, 12)       # 10 / 10 / 20 / 60 seconds
    if not active:
        return (2_000, 1, 1, 2, 6)        # defer paint while another app is active
    return (1_000, 1, 2, 4, 12)           # original full-mode cadence


class MainWindow(QMainWindow):
    # Emitted from background threads; Qt signals are the safe way to hand
    # control back to the GUI thread to touch widgets.
    _aar_ready = Signal(str)
    _shark_narration = Signal(str)
    _selftest_done = Signal(str, object)   # report text, failures list
    _selftest_progress = Signal(int, int)  # (done, total) → live progress wheel
    _selftest_repair_done = Signal(object, object)  # restarted names, errors
    _mic_level = Signal(float)             # live mic input level (0..1) → HUD meter
    _voice_live_requested = Signal()       # bring voice up live (GUI thread) after install
    _fi_coaching = Signal(str)             # Flight Instructor line → right pane
    startup_eco_requested = Signal()       # emitted from the loader thread once modules are up
    chill_return_requested = Signal()      # AAR worker asks GUI thread to restore Chill
    chill_maintenance_done = Signal(str, bool)
    _security_event_wake = Signal()

    def __init__(
        self, bus, storage, manager, config, *,
        evidence_store=None, evidence_ingestion=None,
        flight_recorder_worker=None,
        process_baseline=None,
    ) -> None:
        super().__init__()
        self.bus, self.storage, self.manager, self.config = bus, storage, manager, config
        self.evidence_store = evidence_store
        self.process_baseline = process_baseline
        self._operations_service = None
        self._operations_dialog = None
        self._voice_loop_lock = threading.Lock()
        self._voice_loop_thread: threading.Thread | None = None
        self._selftest_active = threading.Event()

        self.setWindowTitle("Angerona — Security Suite")
        # Custom shield icon (assets/icons/angerona.ico) — falls back to the
        # old solid-blue placeholder if the asset is missing so a stripped
        # dev checkout still runs. Sets the titlebar/taskbar/alt-tab icon;
        # _build_tray() below reuses the same QIcon for the system tray.
        icon_file = icon_path()
        self._app_icon = QIcon(icon_file) if icon_file else self._fallback_icon()
        self.setWindowIcon(self._app_icon)
        self.resize(1200, 780)
        # Explicit floor: without this, Qt derives the OS-level drag-resize
        # minimum from the *natural* minimumSizeHint of every nested widget
        # (splitters, tables, cards) added up — which is why the window could
        # still only shrink so far even after the header's fixed widths were
        # removed. An explicit setMinimumSize() overrides that chain outright,
        # so the window itself stays freely resizable down to this floor;
        # content below its comfortable size just compresses/scrolls instead
        # of blocking the resize.
        # Lowered floor (was 640×420) so the whole window — ARIA orb, prompt bar
        # and alerts — can be dragged much smaller before content starts to
        # compress. The responsive UI-scale (see resizeEvent) keeps text legible
        # as the window shrinks toward this floor.
        self.setMinimumSize(480, 340)
        # Live UI-scale factor (1.0 == the 1200×780 design size). resizeEvent
        # recomputes it and re-applies the stylesheet so buttons and text grow
        # and shrink with the window while staying inside a readable band.
        self._ui_scale = 1.0
        self.setStyleSheet(self._qss())

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        # ── Header: routine actions left, admin actions right, title centered ─
        # Three equal-stretch (ratio 1:1:1) sections keep the brand centered
        # at ANY window size (stretch factors scale proportionally in both
        # directions instead of hitting a hard floor — see setMinimumSize()
        # below for why that matters for shrinking the window).
        #
        # Self-Test and Shark Attack are the two things you reach for while
        # actively USING the app, so they anchor the left edge, closest to
        # where you're already looking. Settings and Stop are lower-frequency/
        # more consequential actions, so they anchor the right edge — Stop
        # furthest out, since it's the most drastic of the four.
        header = QHBoxLayout()
        left = QWidget(); bl = QHBoxLayout(left)
        bl.setContentsMargins(0, 0, 0, 0); bl.setSpacing(8)
        test_btn = HeaderActionButton(
            "RUN SELF-TEST",
            "selftest",
            "Run Self-Test",
            "Checks every enabled defensive module and reports what passed, "
            "what failed, and what the operator can do next.",
        )
        # Self-test reports progress in the header and does not open a window,
        # so it uses the normal tactile button press without the window reveal.
        test_btn.clicked.connect(
            lambda _checked=False: self._run_self_test())
        # Unified Red Team Simulation — the Shark Attack and APT Red-Team drills
        # are now scenarios inside one configurable simulation (difficulty,
        # target, custom benign technique), launched from this single button.
        sim_btn = HeaderActionButton(
            "RUN RED TEAM SIMULATION",
            "simulation",
            "Red Team Simulation",
            "Configures a safe, reversible drill that tests detection and response "
            "end to end without deploying a real exploit or persistence mechanism.",
        )
        # Styled via QSS object name (#Danger) so it scales with the UI-scale
        # factor instead of being frozen at fixed inline pixels.
        sim_btn.setObjectName("Danger")
        sim_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                sim_btn, self._open_simulation, "#fb7185"))
        # Chill Mode — network-first, all-day monitoring. Event-driven endpoint
        # safeguards and response remain live; deep file/memory/AI work sleeps
        # until an operator action or genuine active threat wakes it.
        self._eco_on = False
        self._eco_paused: list[str] = []
        self._chill_policy = ChillPolicy(
            quiet_seconds=float(getattr(config, "chill_quiet_seconds", 600.0))
        )
        self._chill_auto_wake = False
        self._eco_wake_epoch = 0
        self._pending_chill_wake: bool | None = None
        self._wake_retry_worker = None
        self.eco_btn = HeaderActionButton(
            "CHILL MODE",
            "eco",
            "Chill Mode",
            "Network-first all-day protection. Deep scanners and background AI "
            "sleep at idle, wake sequentially for a real threat, then return to Chill.",
        )
        # Eco is an immediate state toggle, not a destination window.
        self.eco_btn.clicked.connect(
            lambda _checked=False: self._toggle_eco_mode())
        # Shark/sword animations removed per user request. No-op stubs keep the
        # existing start()/stop()/set_active() call sites harmless.
        self.red_swords = _NoAnim()
        self.shark_swim = _NoAnim()
        bl.addWidget(test_btn); bl.addWidget(sim_btn); bl.addWidget(self.eco_btn)
        # Live progress wheel: shows self-test / eco-wake activity with a colour-
        # coded percentage (red → amber → green) right beside the buttons.
        self.run_spinner = RunSpinner()
        bl.addWidget(self.run_spinner)
        bl.addStretch(1)

        brand = QLabel("ANGERONA")
        brand.setObjectName("Brand")
        brand.setAlignment(Qt.AlignCenter)
        self.brand = brand   # kept so the Sandbox can override the threat banner
        # Composite Threat Posture indicator under the brand (at-a-glance 0–100).
        self.posture_lbl = QLabel("POSTURE —")
        self.posture_lbl.setAlignment(Qt.AlignCenter)
        self.posture_lbl.setCursor(Qt.PointingHandCursor)
        self.posture_lbl.setToolTip("Composite security posture (0–100). Click for detail.")
        self.posture_lbl.mousePressEvent = lambda ev: self._show_posture_detail()
        brand_box = QWidget()
        _bl = QVBoxLayout(brand_box)
        _bl.setContentsMargins(0, 0, 0, 0)
        _bl.setSpacing(0)
        _bl.addWidget(brand)
        _bl.addWidget(self.posture_lbl)

        right = QWidget(); rl = QHBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0); rl.setSpacing(8)
        worldview_btn = HeaderActionButton(
            "WORLD VIEW",
            "world",
            "World View",
            "Shows Angerona's live system flow, host resources, blinding checks, "
            "sensor health, and local AI diagnostics.",
        )
        worldview_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                worldview_btn, self._open_worldview, "#38bdf8"))
        attack_heatmap_btn = HeaderActionButton(
            "ATT&CK MAP",
            "attack",
            "MITRE ATT&CK Map",
            "Maps observed activity and detection coverage across ATT&CK tactics "
            "and techniques using time-decaying hit intensity.",
        )
        attack_heatmap_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                attack_heatmap_btn, self._open_attack_heatmap, "#fb923c"))
        # Threat Intel button — pulses red/amber when INTL has host-applicable
        # KEV CVEs waiting for operator review.  Style toggles in _refresh().
        self.threat_intel_btn = HeaderActionButton(
            "THREAT INTEL",
            "intel",
            "Threat Intelligence",
            "Correlates known exploited vulnerabilities and trusted intelligence "
            "against this host, then highlights items awaiting operator review.",
        )
        self.threat_intel_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                self.threat_intel_btn, self._open_threat_intel, "#60a5fa"))
        self._threat_intel_dlg: ThreatIntelDashboard | None = None
        self._intl_alert_pulse = False   # toggled each tick when alert is pending
        forensics_btn = HeaderActionButton(
            "FORENSICS",
            "forensics",
            "Forensics",
            "Investigates incidents with evidence capture, process provenance, "
            "blast-radius context, and signed after-action material.",
        )
        forensics_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                forensics_btn, self._open_forensics_hub, "#c084fc"))
        operations_btn = HeaderActionButton(
            "LOCAL SOC",
            "operations",
            "Flow Dashboard · Local SOC",
            "Connects cases, bounded evidence hunts, local assets, trusted "
            "detection content, and tamper-evident audit history in one "
            "interactive operations workspace.",
        )
        operations_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                operations_btn, self._open_operations_center, "#22d3ee"))
        console_btn = HeaderActionButton(
            "CONSOLE",
            "console",
            "Advanced Console",
            "Opens diagnostics, integrations, mobile response, watchdog controls, "
            "and advanced management tools.",
        )
        console_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                console_btn, self._open_upgrade_console, "#2dd4bf"))
        setup_btn = HeaderActionButton(
            "SETUP",
            "setup",
            "Guided Setup",
            "Configures local AI, voice, notifications, trusted applications, "
            "startup behavior, and other first-run choices.",
        )
        setup_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                setup_btn, self._open_setup, "#f472b6"))
        self._help_btn = HeaderActionButton(
            "HELP",
            "help",
            "Help and Guided Tour",
            "Explains setup, testing, troubleshooting, privacy, ARIA, and "
            "integrations, with an interactive tour of the dashboard.",
        )
        self._help_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                self._help_btn, self._open_help, "#facc15"))
        settings_btn = HeaderActionButton(
            "SETTINGS",
            "settings",
            "Settings",
            "Changes appearance, performance, privacy, trusted processes, "
            "enterprise controls, ARIA, microphone, and integrations.",
        )
        settings_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                settings_btn, self._open_settings, "#cbd5e1"))
        stop_btn = HeaderActionButton(
            "STOP",
            "stop",
            "Stop Angerona",
            "Stops every module and helper, closes local AI owned by Angerona, "
            "and shuts the suite down cleanly.",
        )
        # Styled via QSS object name (#Critical) so it scales with the UI.
        stop_btn.setObjectName("Critical")
        stop_btn.clicked.connect(
            lambda _checked=False: self._run_header_action(
                stop_btn, self._full_shutdown, "#ef4444"))
        rl.addStretch(1)
        rl.addWidget(worldview_btn); rl.addWidget(attack_heatmap_btn)
        rl.addWidget(self.threat_intel_btn)
        rl.addWidget(forensics_btn)
        rl.addWidget(operations_btn)
        rl.addWidget(console_btn); rl.addWidget(setup_btn); rl.addWidget(self._help_btn)
        rl.addWidget(settings_btn); rl.addWidget(stop_btn)

        # Keep references so the guided tour can highlight each control by name.
        self._selftest_btn = test_btn
        self._sim_btn = sim_btn
        self._worldview_btn = worldview_btn
        self._attack_btn = attack_heatmap_btn
        self._forensics_btn = forensics_btn
        self._operations_btn = operations_btn
        self._console_btn = console_btn
        self._setup_btn = setup_btn
        self._settings_btn = settings_btn
        self._stop_btn = stop_btn
        self._header_primary_buttons = [test_btn, sim_btn, self.eco_btn]
        self._header_nav_buttons = [
            worldview_btn,
            attack_heatmap_btn,
            self.threat_intel_btn,
            forensics_btn,
            operations_btn,
            console_btn,
            setup_btn,
            self._help_btn,
            settings_btn,
        ]
        # The destructive Stop action keeps its label whenever the available
        # width permits; at very narrow widths it remains uniquely identifiable
        # by its red square icon and definition tooltip.
        self._header_stop_button = stop_btn

        header.addWidget(left, 1)
        header.addWidget(brand_box, 1)
        header.addWidget(right, 1)
        root.addLayout(header)
        QTimer.singleShot(0, self._update_header_button_modes)

        # ── Stat cards ───────────────────────────────────────────────────────
        self.cards = DashboardCards(bus, storage, manager)
        root.addWidget(self.cards)

        # ── Body: (Modules | Live Alerts) over Console ───────────────────────
        self.modules_panel = ModulesPanel(manager, bus)
        self.alerts_panel = AlertsPanel(
            storage,
            allow_cloud=getattr(config, "alert_analysis_cloud_fallback", False),
            bus=bus,
        )
        # Right side keeps live evidence, response review, and explicit local
        # scanning together without blocking the dashboard thread.
        self.soar_panel = SoarPanel(bus, manager)
        self.scan_center = ScanCenterPanel(bus=bus)
        self._right_tabs = QTabWidget()
        self._right_tabs.addTab(self.alerts_panel, "Live Alerts")
        self._right_tabs.addTab(self.soar_panel, "SOAR Queue")
        self._right_tabs.addTab(self.scan_center, "🛡 Scan Center")
        self.alerts_panel.scan_requested.connect(
            lambda: self._right_tabs.setCurrentWidget(self.scan_center)
        )
        top_split = QSplitter(Qt.Horizontal)
        top_split.addWidget(self.modules_panel)
        top_split.addWidget(self._right_tabs)
        top_split.setStretchFactor(0, 4)
        top_split.setStretchFactor(1, 6)
        top_split.setSizes([460, 700])

        self.console = CommandConsolePanel(CommandConsole(
            manager, bus, config,
            evidence_store=evidence_store,
            evidence_ingestion=evidence_ingestion,
            flight_recorder_worker=flight_recorder_worker,
        ))

        # ── ARIA (v1.8.0): HUD tab + local assistant. Fully guarded so any
        # ARIA import/build failure just skips it without touching the rest.
        self._wire_aria()

        # Bottom section = ARIA + Console + a compact live System Pulse. The
        # monitor samples in a background worker, so CPU/Wi-Fi queries cannot
        # stall the prompt or dashboard repaint path.
        self.system_pulse = SystemPulseCard()
        self.system_pulse.details_requested.connect(
            self._open_system_pulse_details
        )
        if getattr(self, "aria_hud", None) is not None:
            self.aria_hud.details_requested.connect(self._open_aria_details)
            self._console_section = QSplitter(Qt.Horizontal)
            # Lowered from 150 so the ARIA orb column can be squeezed right down
            # beside the prompt; raised the ceiling a little for wide displays.
            self.aria_hud.setMinimumWidth(88)
            self.aria_hud.setMaximumWidth(420)
            self._console_section.addWidget(self.aria_hud)
            self._console_section.addWidget(self.console)
            self._console_section.addWidget(self.system_pulse)
            self._console_section.setStretchFactor(0, 2)
            self._console_section.setStretchFactor(1, 7)
            self._console_section.setStretchFactor(2, 2)
            self._console_section.setSizes([210, 760, 250])
            self._console_section.setOpaqueResize(False)
            self._console_section.setChildrenCollapsible(False)
            self._console_section.setHandleWidth(7)
            bottom = self._console_section
        else:
            self._console_section = QSplitter(Qt.Horizontal)
            self._console_section.addWidget(self.console)
            self._console_section.addWidget(self.system_pulse)
            self._console_section.setStretchFactor(0, 8)
            self._console_section.setStretchFactor(1, 2)
            self._console_section.setSizes([900, 250])
            self._console_section.setOpaqueResize(False)
            self._console_section.setChildrenCollapsible(False)
            self._console_section.setHandleWidth(7)
            bottom = self._console_section

        body = QSplitter(Qt.Vertical)
        body.addWidget(top_split)
        body.addWidget(bottom)
        body.setStretchFactor(0, 3)
        body.setStretchFactor(1, 2)
        body.setSizes([500, 240])
        root.addWidget(body, 1)
        self._body_splitter = body
        self._pre_scan_center_sizes: list[int] | None = None
        self._right_tabs.currentChanged.connect(self._on_right_tab_changed)

        # ── Reliable splitter drag ───────────────────────────────────────────
        # The panels hold heavy tables that re-layout on every pixel; with the
        # default OPAQUE resize the drag stutters and feels unreliable. Non-opaque
        # resize (rubber-band line, apply on release) is smooth and predictable;
        # a wider handle is easier to grab and disabling collapse stops panels
        # from snapping shut when dragged to an edge. Min sizes give each panel a
        # sane floor so the handle can't be pushed "past" a widget.
        # Lowered floors (were 220 / 280 / 120): the Modules panel can now be
        # squeezed narrower, which lets you drag the Live Alerts panel much
        # wider, and the Console/prompt can shrink further vertically.
        self.modules_panel.setMinimumWidth(150)
        self._right_tabs.setMinimumWidth(190)
        self.console.setMinimumHeight(84)
        for _sp in (top_split, body):
            _sp.setOpaqueResize(False)
            _sp.setChildrenCollapsible(False)
            _sp.setHandleWidth(7)

        # ── Bottom status strip (every module's state) ───────────────────────
        # Chips are clickable → open that module's full window (details, live
        # alerts, self-test, edit code in the Sandbox).
        self.status_strip = StatusStrip(manager, on_chip_click=self._open_module_window)
        root.addWidget(self.status_strip)
        # Second row: per-module resource-intensity (0–100%, red=off→green→red).
        self.resource_strip = ResourceStrip(manager, self.bus)
        root.addWidget(self.resource_strip)

        self.setCentralWidget(central)
        self._panel_reveal = PanelRevealOverlay(central)
        # Enable after construction so every later top-level Angerona dialog,
        # including older call sites, receives the same reveal and reverse close.
        QTimer.singleShot(0, self._panel_reveal.enable_global_windows)

        # Shark-sweep overlay and full-width swimming-shark banner removed per
        # user request — stubbed so existing start()/stop() calls are harmless.
        self.threat_overlay = _NoAnim()
        self._last_threat_ts = time.time()
        try:
            self._last_bus_revision: int | None = self.bus.revision()
        except Exception:
            self._last_bus_revision = None
        # The presentation timer may sleep for 5-15 seconds in Chill/background
        # operation, but genuine HIGH/CRITICAL evidence must still wake policy
        # immediately.  Coalesce a burst into one queued GUI callback: the
        # callback drains the bus's authoritative revision delta, so no event is
        # lost and publisher threads never touch Qt widgets directly.
        self._security_wake_pending = threading.Event()
        self._security_event_wake.connect(
            self._handle_security_event_wake,
            Qt.QueuedConnection,
        )
        self._bus_wake_subscriber = self._queue_security_event_wake
        try:
            self.bus.subscribe(self._bus_wake_subscriber)
        except Exception:
            pass
        # One fail-closed prompt per currently mounted removable volume.  The
        # dialog map is bounded by the USB policy's mount bound and entries are
        # removed as soon as each window finishes.
        self._usb_approval_dialogs: dict[str, object] = {}
        self.shark_banner = _NoAnim()

        # Shark Attack Engine — the adversary-simulation test harness.
        self.shark_engine = SharkAttackEngine(
            self.config.data_dir, on_event=self._on_shark_narration)
        # Separate Red Team engine — a distinct credential-access / fileless-
        # persistence scenario (not the shark drill). Shares the narration path.
        self.red_team_engine = RedTeamEngine(
            self.config.data_dir, on_event=self._on_shark_narration)
        self.shark_monitor = SharkMonitorDialog(self)
        self._shark_prev_armed = None
        self._aar_ready.connect(self._show_aar_dialog)
        self._shark_narration.connect(self.shark_monitor.append)
        self._fi_coaching.connect(self.shark_monitor.append_instructor)
        self._selftest_done.connect(self._on_selftest_done)
        self._selftest_progress.connect(self.run_spinner.set_progress)
        self._selftest_repair_done.connect(self._on_selftest_repair_done)
        self._mic_level.connect(self._on_mic_level)
        self._voice_live_requested.connect(self._enable_voice_live)
        self.startup_eco_requested.connect(self.apply_startup_eco)
        self.chill_return_requested.connect(self._return_to_chill_after_drill)
        self.chill_maintenance_done.connect(
            lambda name, ok: self.console._append(
                f"[chill] Sparse maintenance: {name} "
                f"{'completed one cycle' if ok else 'did not complete before its bound'}."
            )
        )

        # Cyber Security Academy — Flight Instructor Mode. Instantiation is
        # cheap (just resolves host/model, no network call), so it's created
        # eagerly here rather than lazily, which avoids a check-then-set race
        # if two narration lines land on background threads close together.
        self.flight_instructor = FlightInstructor(self.config)
        self._fi_enabled = True            # analogy coaching ON by default
        # Serialize and bound local-model coaching. A thread per narration line
        # could create hundreds of concurrent Ollama calls during Extreme drills.
        self._fi_queue: queue.Queue[str] = queue.Queue(maxsize=8)
        self._fi_worker = threading.Thread(
            target=self._fi_worker_loop, name="FlightInstructorWorker", daemon=True)
        self._fi_worker.start()
        self._flow_write_busy = threading.Event()
        try:
            self.shark_monitor.fi_check.setChecked(True)
        except Exception:
            pass
        self.shark_monitor.fi_check.stateChanged.connect(self._on_fi_toggle)
        self.shark_monitor.fi_style.currentTextChanged.connect(self._on_fi_style_change)

        self._build_tray()
        self._holographic_orb = HolographicOrbController(self, self.config)

        # ── Two-tier refresh: fast strip (1 s) + full panels (2 s) ──────────
        # Splitting the timer lets the status strip and threat check stay snappy
        # (1 s) while the heavier panels (alerts table, module table, stat cards)
        # refresh at a calmer 2 s cadence — halving the number of DB reads and
        # widget updates per second vs the old single 1.5 s timer.
        self._tick_count = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._refresh)
        self.timer.start(1000)
        self._sync_idle_presentation()
        # One parked deep scanner gets one bounded cycle per hour. With the
        # six-module rotation below, each deep surface is revisited only every
        # several hours instead of walking disks continuously.
        self._chill_maintenance_busy = threading.Event()
        self._chill_maintenance_index = 0
        self._chill_maintenance_timer = QTimer(self)
        self._chill_maintenance_timer.timeout.connect(
            self._run_sparse_chill_maintenance
        )
        self._chill_maintenance_timer.start(60 * 60 * 1000)
        # Do NOT call self._refresh() here — modules haven't loaded yet
        # (discover/start run on a background thread after first paint).
        # The first timer tick at t=1s will populate the panels with live data.

        # UI responsiveness watchdog: a GUI-thread heartbeat every 1s; if the GUI
        # thread ever stalls (Not Responding), a background thread records the
        # GUI stack to diagnostics/not_responding.log so the blocking call is
        # identifiable without dumping every sleeping module. Best-effort only.
        try:
            from angerona.core.data_paths import data_dir
            from angerona.core.uiwatchdog import UiWatchdog
            _diag = data_dir() / "diagnostics"
            self._ui_watchdog = UiWatchdog(_diag / "not_responding.log", stall_seconds=5.0)
            self._ui_watchdog.start()
            self._beat_timer = QTimer(self)
            self._beat_timer.timeout.connect(self._ui_watchdog.beat)
            self._beat_timer.start(1000)
        except Exception:
            self._ui_watchdog = None

        # The selected dashboard is a startup preference, never a migration.
        # Classic stays available behind the Flow workspace and its data stores
        # are shared, so switching modes cannot orphan alerts or cases.
        if str(getattr(self.config, "dashboard_mode", "classic")).lower() == "flow":
            QTimer.singleShot(900, self._open_operations_center)

    # ── Theme ────────────────────────────────────────────────────────────────
    def _qss(self) -> str:
        return build_qss(self.config.theme, self.config.accent or None,
                         scale=getattr(self, "_ui_scale", 1.0))

    # ── Responsive UI scale ───────────────────────────────────────────────────
    def _compute_ui_scale(self) -> float:
        """Derive a UI-scale factor from the current window size.

        Both dimensions are compared against the 1200×780 design size and the
        smaller ratio wins, so text never overflows the shorter axis. The raw
        factor is clamped into a readable band by ``clamp_scale`` (0.75–1.35).

        When the operator has chosen a FIXED scale in Settings, that value is
        used verbatim (still clamped) and the window size is ignored — handy on
        very large or high-DPI displays where auto-scaling feels off."""
        try:
            if str(getattr(self.config, "ui_scale_mode", "auto")).lower() == "fixed":
                return clamp_scale(float(getattr(self.config, "ui_scale_fixed", 1.0)))
        except (TypeError, ValueError):
            pass
        try:
            w = max(1, self.width())
            h = max(1, self.height())
            raw = min(w / 1200.0, h / 780.0)
        except Exception:
            raw = 1.0
        return clamp_scale(raw)

    def _maybe_rescale_ui(self) -> None:
        """Recompute the scale and, if it moved enough to matter, re-apply the
        stylesheet. Quantised to 0.05 steps so a drag-resize doesn't rebuild the
        (fairly large) stylesheet on every single pixel."""
        new = round(self._compute_ui_scale() / 0.05) * 0.05
        if abs(new - getattr(self, "_ui_scale", 1.0)) >= 0.049:
            self._ui_scale = new
            try:
                self.setStyleSheet(self._qss())
            except Exception:
                pass

    def _update_header_button_modes(self) -> None:
        """Keep the top row readable at every practical window width.

        Navigation destinations become icon-only before Qt has any reason to
        crop their labels. Primary operational actions retain text on a normal
        desktop width and collapse only on smaller windows.
        """
        width = max(1, self.width())
        scale = max(0.75, min(1.35, getattr(self, "_ui_scale", 1.0)))
        icon_extent = round((40 if width >= 1900 else 34) * scale)
        # Eight destination buttons need roughly one third of a 4K surface
        # before their complete labels are genuinely comfortable. Everywhere
        # else the unique icon + definition tooltip is clearer than truncation.
        nav_compact = width < 3000
        primary_compact = width < 1900
        stop_compact = width < 1900
        for button in getattr(self, "_header_nav_buttons", ()):
            button.set_compact(nav_compact, icon_extent)
        for button in getattr(self, "_header_primary_buttons", ()):
            button.set_compact(primary_compact, icon_extent)
        stop = getattr(self, "_header_stop_button", None)
        if stop is not None:
            stop.set_compact(stop_compact, icon_extent)

    def resizeEvent(self, event) -> None:  # noqa: N802 (Qt signature)
        try:
            self._maybe_rescale_ui()
            self._update_header_button_modes()
        except Exception:
            pass
        super().resizeEvent(event)

    def apply_theme(self, theme: str | None = None) -> None:
        # SettingsDialog passes the newly-chosen theme here; callers that just
        # want a restyle (no change) pass nothing. Without this optional arg the
        # Settings "Save" handler raised TypeError on any theme change and the
        # dialog neither closed nor applied — the "settings button isn't working".
        if theme:
            self.config.theme = theme
        # Recompute the scale here too so a Settings change to UI-scale mode/value
        # (auto ↔ fixed) takes effect immediately, not only on the next resize.
        try:
            self._ui_scale = self._compute_ui_scale()
        except Exception:
            pass
        self.setStyleSheet(self._qss())
        try:
            self._holographic_orb.sync_config()
        except Exception:
            pass

    def _run_header_action(self, source: QWidget, callback, color: str) -> None:
        """Route a top-row action through the real destination reveal."""
        self._reveal_window_from(source, callback, color)

    def _reveal_window_from(
        self,
        source: QWidget,
        callback,
        color: str = "#38bdf8",
    ) -> None:
        """Reveal the actual window created by any clickable dashboard surface."""
        if not motion_allowed(self.config):
            callback()
            return
        overlay = getattr(self, "_panel_reveal", None)
        if overlay is None:
            callback()
            return
        # A second click while the destination reveal is active is deliberately
        # ignored so it cannot open duplicate modal windows.
        overlay.reveal(source, callback, color)

    def _open_system_pulse_details(self) -> None:
        def _show():
            dialog = SystemPulseDetailDialog(self.system_pulse, self)
            self._system_pulse_detail = dialog
            dialog.show()
            dialog.raise_()
            return dialog

        self._reveal_window_from(self.system_pulse, _show, "#38bdf8")

    def _open_aria_details(self) -> None:
        hud = getattr(self, "aria_hud", None)
        if hud is None:
            return

        def _show():
            dialog = AriaDetailDialog(self, self)
            self._aria_detail = dialog
            dialog.show()
            dialog.raise_()
            return dialog

        self._reveal_window_from(hud, _show, "#c084fc")

    # ── Refresh ──────────────────────────────────────────────────────────────
    def _refresh(self) -> None:
        self._tick_count += 1
        # The ENTIRE refresh is wrapped: a single panel raising (e.g. under a data
        # flood or a transient DB lock) must never propagate out of the QTimer
        # callback and take the app down. Worst case we skip one repaint tick.
        try:
            self._refresh_body()
        except Exception as exc:
            try:
                self._blackbox_feed(f"UI refresh error (non-fatal): {exc}")
            except Exception:
                pass

    def _quiet_chill_active(self) -> bool:
        return bool(
            self._eco_on
            and self._chill_policy.enabled
            and not self._chill_policy.escalated
        )

    def _current_refresh_plan(self) -> tuple[int, int, int, int, int]:
        visible = self.isVisible() and not self.isMinimized()
        return _dashboard_refresh_plan(
            self._quiet_chill_active(),
            visible=visible,
            active=bool(visible and self.isActiveWindow()),
        )

    def _sync_idle_presentation(self) -> None:
        """Gate cosmetic UI work without weakening the incident wake path."""
        timer = getattr(self, "timer", None)
        plan = self._current_refresh_plan()
        if timer is not None and timer.interval() != plan[0]:
            timer.setInterval(plan[0])
        hud = getattr(self, "aria_hud", None)
        if hud is not None and hasattr(hud, "set_idle_mode"):
            visible = self.isVisible() and not self.isMinimized()
            hud.set_idle_mode(
                self._quiet_chill_active()
                or not visible
                or not self.isActiveWindow()
            )

    def _queue_security_event_wake(self, event) -> None:
        """Bridge serious EventBus publications to Qt, once per pending burst."""
        try:
            serious = event.severity >= Severity.HIGH
        except Exception:
            serious = False
        if serious and not self._security_wake_pending.is_set():
            self._security_wake_pending.set()
            self._security_event_wake.emit()

    def _handle_security_event_wake(self) -> None:
        self._security_wake_pending.clear()
        try:
            self._check_threat_animation()
        except Exception as exc:
            try:
                self._blackbox_feed(f"Security UI wake error (non-fatal): {exc}")
            except Exception:
                pass

    def _refresh_body(self) -> None:
        quiet_chill = self._quiet_chill_active()
        timer_ms, status_period, panel_period, posture_period, flow_period = (
            self._current_refresh_plan()
        )
        if self.timer.interval() != timer_ms:
            self.timer.setInterval(timer_ms)

        # The EventBus signal keeps serious threat decisions immediate; this
        # timer now governs cosmetic tables and strips only.
        if self._tick_count % status_period == 0:
            self.status_strip.refresh()
        self.red_swords.set_active(self.shark_engine.is_running or self.red_team_engine.is_running)
        self._check_threat_animation()

        # Resource strip + posture are heavier (walk recent bus events / compute a
        # composite) — run them every 4th tick (~4 s), not every tick, so they
        # don't add steady overhead. This keeps the UI light even in Eco mode.
        if self._tick_count % posture_period == 0:
            try:
                self.resource_strip.refresh()
            except Exception:
                pass
            self._refresh_posture()

        if self._tick_count % panel_period == 0:
            # Heavier panels: every 2 s in Full, every 10 s in quiet Chill, and
            # once per minute while minimized.
            # skip the others (or blow up the whole tick).
            for _fn in (self.cards.refresh, self.modules_panel.refresh,
                        self.alerts_panel.refresh, self.soar_panel.refresh):
                try:
                    _fn()
                except Exception:
                    pass
            # The external canvas feed is a diagnostic heartbeat, not a reason
            # to dirty the disk continuously while the suite sits idle.
            if self._tick_count % flow_period == 0:
                try:
                    self._write_flow_metrics_async()
                except Exception:
                    pass

    def _write_flow_metrics_async(self) -> None:
        """Coalesce the optional canvas feed and keep disk I/O off Qt."""
        if self._flow_write_busy.is_set():
            return
        self._flow_write_busy.set()

        def _write() -> None:
            try:
                from angerona.core import flow_metrics
                flow_metrics.write(self.manager, self.bus, self.config)
            finally:
                self._flow_write_busy.clear()

        threading.Thread(target=_write, name="FlowMetricsWriter", daemon=True).start()

    def _check_threat_animation(self) -> None:
        # React only to NEW, unresolved active-hostile evidence. Practice,
        # passive exposure, suite health and response summaries retain their
        # evidence severity but cannot claim that the host is under attack.
        # Ask the bounded EventBus for the exact revision delta. A fixed
        # ``recent(N)`` window can miss the active event that preceded a burst
        # of harmless process telemetry inside one UI tick.
        events = []
        candidates = []
        if self._last_bus_revision is not None and hasattr(self.bus, "recent_since"):
            try:
                current, candidates, overflow = self.bus.recent_since(
                    self._last_bus_revision
                )
                self._last_bus_revision = current
                events = candidates
                if overflow:
                    self.console._append(
                        "[telemetry] Event burst exceeded the live UI ring; "
                        "retained security events were still evaluated."
                    )
            except Exception:
                # Compatibility/fault fallback: a broken delta reader must not
                # blind Chill auto-wake. Timestamp filtering is less exact
                # during a very large burst, but still evaluates retained
                # security evidence instead of silently evaluating nothing.
                self._last_bus_revision = None
                events = self.bus.recent(100)
                candidates = [
                    event for event in events
                    if event.ts > self._last_threat_ts
                ]
        else:
            events = self.bus.recent(100)
            if events:
                candidates = [e for e in events if e.ts > self._last_threat_ts]
        new_threats = []
        if events:
            self._last_threat_ts = max(
                self._last_threat_ts, max(e.ts for e in events)
            )
            if candidates:
                try:
                    from angerona.core.threat import active_threat_events
                    new_threats = active_threat_events(candidates, window=60.0)
                except Exception:
                    new_threats = []
        # Reconcile the authoritative pending set every UI cadence.  EventBus
        # overflow can discard a notification, but it must never strand an
        # attached drive without its PIN prompt.
        self._handle_usb_approval_events(candidates)
        # Red-flash + emoji shark-sweep overlay removed per user request — the
        # full-width swimming SharkSwimBanner across the top now signals a drill,
        # and it doesn't strobe the whole screen red (which also cost repaints).
        # Push a tray/toast notification on NEW CRITICAL detections so the operator
        # keeps situational awareness even when the window is minimized. Throttled.
        crits = [e for e in new_threats if e.severity >= Severity.CRITICAL]
        if crits:
            self._notify_critical(crits)
        transition = self._chill_policy.observe_active(new_threats)
        if transition is not None and transition.action == "escalate":
            self.console._append(
                f"[chill] Active threat evidence ({transition.active_count}) — "
                "waking deep verification sensors sequentially."
            )
            self._wake_chill_modules(auto=True)

        # A drill/AAR owns its explicit sensor lease. Real incident leases cool
        # only after the wake worker has finished and ten quiet minutes elapsed.
        drill_busy = (
            self.shark_engine.is_running
            or self.red_team_engine.is_running
            or int(getattr(self, "_sim_aar_pending", 0)) > 0
        )
        worker = getattr(self, "_eco_worker", None)
        worker_busy = False
        try:
            worker_busy = bool(worker is not None and worker.isRunning())
        except (RuntimeError, AttributeError):
            pass
        if not drill_busy and not worker_busy:
            cooldown = self._chill_policy.tick()
            if cooldown is not None and cooldown.action == "cooldown" and self._eco_on:
                self._enter_eco(auto_return=True)
        # Pulse the THREAT INTEL button when INTL has pending KEV alerts.
        self._update_threat_intel_pulse()

    def _handle_usb_approval_events(self, events) -> None:
        """Open one PIN gate for each exact USB approval event.

        The EventBus payload is used only to locate a secret-free approval ID.
        The dialog receives the live approval object from the USB module, so a
        forged event cannot manufacture trust state or obtain a PIN prompt.
        """
        relevant = []
        terminal_ids: set[str] = set()
        removed_mounts: set[str] = set()
        for event in events:
            details = getattr(event, "details", None)
            if not isinstance(details, dict):
                continue
            event_type = str(details.get("event_type") or "").strip().casefold()
            if not event_type.startswith("usb_"):
                continue
            approval_id = str(details.get("approval_id") or "").strip()
            mountpoint = str(details.get("mountpoint") or "").strip()
            if event_type == "usb_approval_required" and approval_id:
                relevant.append((approval_id, mountpoint))
            elif event_type in {"usb_approval_decision", "usb_approval_rejected"}:
                # Invalid attempts and temporary lockout intentionally keep the
                # same prompt alive so the operator can use the remaining
                # attempts. Only a real trust/deny terminal state closes it.
                state = str(details.get("approval_state") or "").casefold()
                if approval_id and state in {"trusted", "denied"}:
                    terminal_ids.add(approval_id)
            elif event_type == "usb_media_removed" and mountpoint:
                removed_mounts.add(mountpoint.casefold())

        # Close stale prompts first. A close never grants trust and never
        # re-enables Windows AutoRun/AutoPlay.
        for approval_id, dialog in tuple(self._usb_approval_dialogs.items()):
            dialog_mount = str(
                getattr(getattr(dialog, "_approval", None), "mountpoint", "")
            ).casefold()
            if approval_id in terminal_ids or dialog_mount in removed_mounts:
                try:
                    dialog.close()
                except RuntimeError:
                    pass
                self._usb_approval_dialogs.pop(approval_id, None)

        usb_module = self.manager.modules.get("Removable-Media / USB Monitor")
        if usb_module is None:
            usb_module = next(
                (
                    module for module in self.manager.modules.values()
                    if getattr(module, "CODE", "") == "USBW"
                ),
                None,
            )
        if usb_module is None or not hasattr(usb_module, "pending_approvals"):
            return
        try:
            pending = {
                approval.approval_id: approval
                for approval in usb_module.pending_approvals()
            }
        except Exception:
            return

        # Pending policy state is authoritative.  Include it even if its
        # informational EventBus notification was evicted by an alert burst.
        requested_ids = {approval_id for approval_id, _mountpoint in relevant}
        requested_ids.update(pending)
        if removed_mounts:
            requested_ids = {
                approval_id
                for approval_id in requested_ids
                if str(getattr(pending.get(approval_id), "mountpoint", "")).casefold()
                not in removed_mounts
            }

        from angerona.gui.usb_approval_dialog import UsbApprovalDialog

        for approval_id in requested_ids:
            if approval_id in self._usb_approval_dialogs:
                continue
            approval = pending.get(approval_id)
            if approval is None:
                continue
            dialog = UsbApprovalDialog(usb_module, approval, self)
            dialog.setStyleSheet(self._qss())
            dialog.finished.connect(
                lambda _result, token=approval_id: self._usb_approval_dialogs.pop(
                    token, None
                )
            )
            self._usb_approval_dialogs[approval_id] = dialog
            dialog.show()
            dialog.raise_()
            dialog.activateWindow()
            try:
                self.tray.showMessage(
                    "Angerona — removable media blocked",
                    "AutoRun is disabled. Enter the USB PIN to approve Angerona scanning.",
                    QSystemTrayIcon.Warning,
                    8000,
                )
            except Exception:
                pass

    def _notify_critical(self, crits) -> None:
        now = time.time()
        # Always mirror CRITICALs to the Black Box feed (even the ones the tray
        # throttle suppresses) so the out-of-band recorder has the full picture —
        # but batch them into ONE file write instead of open/append/close per event,
        # so a critical storm doesn't hammer the disk on the GUI thread every tick.
        if crits:
            self._blackbox_feed(
                "\n".join(f"CRITICAL [{e.module}] {e.message[:300]}" for e in crits))
        if now - getattr(self, "_last_notify_ts", 0.0) < 8.0:
            return   # throttle bursts so a storm can't spam the tray
        self._last_notify_ts = now
        e = crits[0]
        extra = f" (+{len(crits) - 1} more)" if len(crits) > 1 else ""
        try:
            self.tray.showMessage(
                f"⚠ Angerona — CRITICAL: {e.module}",
                f"{e.message[:180]}{extra}",
                QSystemTrayIcon.Critical, 6000)
        except Exception:
            pass

    def _blackbox_feed(self, text: str) -> None:
        """Append a timestamped line to diagnostics/runtime_alerts.log — an
        out-of-band file the Black Box recorder tails. Best-effort; never raises."""
        try:
            from angerona.core.data_paths import data_dir
            d = data_dir() / "diagnostics"
            d.mkdir(parents=True, exist_ok=True)
            with open(d / "runtime_alerts.log", "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {text}\n")
        except Exception:
            pass

    def _update_threat_intel_pulse(self) -> None:
        """Toggle the THREAT INTEL button style to create a pulse effect.

        How it works:
          - Every 1-second tick we check whether any registered INTL module
            has `alert_pending = True`.
          - If yes: toggle between two border colours (red/amber) to create a
            slow pulse without needing a separate timer.
          - If no: restore the normal button style.

        The toggle state is stored in `self._intl_alert_pulse` (bool) so each
        call flips it — giving a 2 s full-cycle pulse at the 1 s tick rate.
        """
        intl_pending = False
        for mod in self.manager.modules.values():
            if getattr(mod, "CODE", None) == "INTL":
                if getattr(mod, "alert_pending", False):
                    intl_pending = True
                    break

        if intl_pending:
            self._intl_alert_pulse = not self._intl_alert_pulse
            if self._intl_alert_pulse:
                style = (
                    "background:#7f1d1d; color:#fca5a5; font-weight:700;"
                    "border:2px solid #ef4444; border-radius:6px; padding:7px 14px;"
                )
            else:
                style = (
                    "background:#78350f; color:#fcd34d; font-weight:700;"
                    "border:2px solid #f59e0b; border-radius:6px; padding:7px 14px;"
                )
        else:
            self._intl_alert_pulse = False
            style = ""   # let the theme QSS handle it normally

        # Only re-apply when the string actually changes. setStyleSheet() forces a
        # full style re-polish/repaint of the button every call; in the common
        # (no INTL alert) case the style is a constant "" every 1 s tick, so this
        # guard skips a redundant re-polish each second. When pulsing, the string
        # alternates every tick and is always applied — pulse behaviour unchanged.
        if style != getattr(self, "_intl_btn_style", None):
            self._intl_btn_style = style
            self.threat_intel_btn.setStyleSheet(style)

    def _open_threat_intel(self) -> None:
        """Open (or raise) the Threat Intelligence Dashboard dialog."""
        # Find the INTL module instance so the dashboard can call confirm().
        intl_mod = None
        for mod in self.manager.modules.values():
            if getattr(mod, "CODE", None) == "INTL":
                intl_mod = mod
                break

        if self._threat_intel_dlg is None:
            self._threat_intel_dlg = ThreatIntelDashboard(
                parent=self, intl_module=intl_mod)
            self._threat_intel_dlg.setStyleSheet(self._qss())
        self._threat_intel_dlg.show()
        self._threat_intel_dlg.raise_()
        self._threat_intel_dlg.activateWindow()

    # ── Chill Mode (network-first, all-day low-impact monitoring) ────────────
    # Compatibility alias retained for the startup loader and older tests.
    _ECO_HEAVY_MODULES = CHILL_PAUSED_MODULES
    _CHILL_USER_ONLY_MODULES = {
        "Speculative Triage Pre-Warm",
        "Scheduled AI Security Briefing",
        "Smart Deception",
    }
    _CHILL_MAINTENANCE_MODULES = (
        "File Integrity Monitor",
        "YARA Scanner",
        "Memory Injection Scanner",
        "Persistence Sweep",
        "AI Model Integrity Guard",
        "Shadow Shield",
    )

    def apply_startup_eco(self) -> None:
        """Apply the saved all-day Chill preference after module discovery.

        Startup already defers deep modules, so this establishes their policy
        state, slows sentinel cadences, and releases any resident Ollama model.
        Safe to call once modules have been started by the manager."""
        if getattr(self.config, "eco_mode", True) and not self._eco_on:
            self._enter_eco(startup=True)

    def _set_chill_runtime(self, quiet: bool) -> None:
        """Publish transient mode state without rewriting saved settings."""
        import os
        setattr(self.config, "runtime_chill_active", bool(quiet))
        if quiet:
            os.environ["ANGERONA_CHILL_ACTIVE"] = "1"
        else:
            os.environ.pop("ANGERONA_CHILL_ACTIVE", None)
        try:
            self.system_pulse.set_chill_mode(quiet)
        except Exception:
            pass
        self._sync_idle_presentation()
        if quiet:
            host = getattr(self.config, "ollama_host", "http://localhost:11434")
            model = getattr(self.config, "ollama_model", "llama3")

            def _release_model() -> None:
                try:
                    from angerona.core.ollama_lifecycle import unload_angerona_models
                    unload_angerona_models(host, model)
                except Exception:
                    pass

            threading.Thread(
                target=_release_model,
                name="ChillOllamaRelease",
                daemon=True,
            ).start()

    def _apply_chill_throttles(self, enabled: bool) -> None:
        for name, floor in CHILL_THROTTLE_FLOORS.items():
            mod = self.manager.modules.get(name)
            if mod is None:
                continue
            try:
                mod.set_throttle_floor(floor if enabled else 1.0)
                mod.set_throttle(floor if enabled else 1.0)
            except Exception:
                pass

    def _run_sparse_chill_maintenance(self) -> None:
        if (
            not self._eco_on
            or not bool(getattr(self.config, "runtime_chill_active", False))
            or self._chill_policy.escalated
            or self._chill_maintenance_busy.is_set()
            or self.shark_engine.is_running
            or self.red_team_engine.is_running
        ):
            return
        names = self._CHILL_MAINTENANCE_MODULES
        if not names:
            return
        name = names[self._chill_maintenance_index % len(names)]
        self._chill_maintenance_index += 1
        mod = self.manager.modules.get(name)
        try:
            enabled = bool(self.manager.is_enabled(name))
        except Exception:
            enabled = False
        if (
            mod is None
            or not getattr(mod, "_chill_paused", False)
            or not enabled
        ):
            return
        self._chill_maintenance_busy.set()

        def _one_cycle() -> None:
            ok = False
            try:
                setattr(mod, "_chill_paused", False)
                mod.start()
                ok = bool(mod.wait_for_first_cycle(timeout=5 * 60.0))
            except Exception:
                ok = False
            finally:
                still_quiet = (
                    self._eco_on
                    and bool(getattr(self.config, "runtime_chill_active", False))
                    and not self._chill_policy.escalated
                )
                if still_quiet:
                    try:
                        mod.stop()
                    except Exception:
                        pass
                    setattr(mod, "_chill_paused", True)
                self._chill_maintenance_busy.clear()
                self.chill_maintenance_done.emit(name, ok)

        threading.Thread(
            target=_one_cycle,
            name=f"ChillMaintenance-{name}",
            daemon=True,
        ).start()

    def _enter_eco(self, startup: bool = False, auto_return: bool = False) -> None:
        # Pause each running heavy module, remembering which we touched so resume
        # restores exactly that set.
        # If a sequential wake is still in flight, cancel it first. The worker's
        # control lock guarantees it cannot start another module after cancel()
        # returns, so ECO: ON cannot race with a late scanner wake-up.
        worker = getattr(self, "_eco_worker", None)
        # A cancelled QThread still emits its queued completion signals. Make
        # every callback from the old Full-mode transition stale before we park
        # modules, and discard any pending retry from an earlier rapid toggle.
        self._eco_wake_epoch += 1
        self._pending_chill_wake = None
        if worker is not None:
            try:
                if worker.isRunning():
                    worker.cancel()
            except (RuntimeError, AttributeError):
                pass
        self._eco_paused = []
        self._apply_chill_throttles(True)
        for name in self._ECO_HEAVY_MODULES:
            mod = self.manager.modules.get(name)
            if mod is None:
                continue
            try:
                enabled = bool(self.manager.is_enabled(name))
            except Exception:
                enabled = False
            # Do not relabel a genuine crashed/quarantined module as an expected
            # Chill pause; operators still need to see that degradation.
            if not enabled or getattr(mod, "status", "") == "error":
                continue
            # Re-establish the policy invariant for *every* enabled deep
            # module, not only those whose transient status currently says
            # ``running``.  A rapid Full -> Chill click can cancel the
            # sequential wake worker while later modules are still stopped (or
            # one is briefly ``restarting``); leaving those entries unmarked
            # strands them offline on the next Full transition.  stop() is
            # idempotent and also cancels a deferred restart safely.
            try:
                mod.stop()
            except Exception:
                pass
            setattr(mod, "_chill_paused", True)
            self._eco_paused.append(name)
        self._eco_on = True
        if not self._chill_policy.enabled:
            self._chill_policy.enable()
        self._chill_auto_wake = False
        self._set_chill_runtime(True)
        self.eco_btn.set_full_label("CHILL: ON")
        self.eco_btn.setStyleSheet(
            "background:#166534; color:#dcfce7; font-weight:800; border:none;"
            "border-radius:6px; padding:7px 16px;")
        prefix = "[chill] Startup in Chill Mode — " if startup else "[chill] "
        if auto_return:
            prefix = "[chill] Quiet window complete — "
        verb = "Deferred" if startup else "Paused"
        self.console._append(
            f"{prefix}{verb} {len(self._eco_paused)} deep scanner/AI module(s); "
            "network, Defender/AMSI, USB, ETW/Sysmon, watchdog and response stay live."
        )

    def _toggle_eco_mode(self) -> None:
        if not self._eco_on:
            self._enter_eco(startup=False)
        else:
            self._chill_policy.disable()
            self._wake_chill_modules(auto=False)

    def _wake_chill_modules(self, *, auto: bool) -> bool:
        """Wake policy-paused modules sequentially; return True if queued."""
        self._apply_chill_throttles(False)
        self._set_chill_runtime(False)
        self._chill_auto_wake = bool(auto)
        if auto:
            self.eco_btn.set_full_label("CHILL: ALERT")
            self.eco_btn.setStyleSheet(
                "background:#9a3412; color:#fff7ed; font-weight:800; border:none;"
                "border-radius:6px; padding:7px 16px;"
            )
        else:
            self._eco_on = False
            self.eco_btn.set_full_label("CHILL MODE")
            self.eco_btn.setStyleSheet("")

        worker = getattr(self, "_eco_worker", None)
        try:
            if worker is not None and worker.isRunning():
                if bool(getattr(worker, "_abort", False)):
                    # The cancelled worker owns a QThread until its run method
                    # returns. Queue one non-blocking retry so a fast
                    # Chill -> Full click cannot strand the deep sensors.
                    self._pending_chill_wake = bool(auto)
                    if self._wake_retry_worker is not worker:
                        self._wake_retry_worker = worker
                        worker.finished.connect(self._resume_pending_chill_wake)
                return True
        except (RuntimeError, AttributeError):
            pass

        names = []
        for name in self._ECO_HEAVY_MODULES:
            if auto and name in self._CHILL_USER_ONLY_MODULES:
                continue
            mod = self.manager.modules.get(name)
            if mod is None or not getattr(mod, "_chill_paused", False):
                continue
            try:
                if self.manager.is_enabled(name):
                    names.append(name)
            except Exception:
                pass
        mods = [self.manager.modules[name] for name in names]
        if not mods:
            return False
        total = len(mods)
        reason = "active verification" if auto else "Full mode"
        self.console._append(
            f"[chill] {reason}: waking {total} module(s) one at a time; each "
            "reaches a work-cycle boundary before the next starts."
        )
        self._eco_wake_total = total
        self._eco_wake_done = 0
        self._eco_wake_epoch += 1
        epoch = self._eco_wake_epoch
        self.run_spinner.start("Waking sensors")
        self._eco_worker = EcoWakeupWorker(mods)
        self._eco_worker.module_waking.connect(
            lambda name: self.console._append(f"[chill]   waking {name}…")
        )
        self._eco_worker.module_ready.connect(
            lambda name, ok, generation=epoch: self._on_eco_module_ready(
                generation, name, ok
            )
        )
        self._eco_worker.module_cycle_timeout.connect(
            lambda name: self.console._append(
                f"[chill]   {name}: first cycle still running; left online."
            )
        )
        self._eco_worker.wakeup_complete.connect(
            lambda ok, failed, generation=epoch: self._on_eco_wakeup_complete(
                generation, ok, failed
            )
        )
        self._eco_worker.finished.connect(self._eco_worker.deleteLater)
        self._eco_worker.start()
        return True

    def _resume_pending_chill_wake(self) -> None:
        self._wake_retry_worker = None
        auto = self._pending_chill_wake
        self._pending_chill_wake = None
        if auto is not None:
            QTimer.singleShot(0, lambda: self._wake_chill_modules(auto=auto))

    def _on_eco_module_ready(self, generation: int, name: str, ok: bool) -> None:
        if generation != self._eco_wake_epoch:
            return
        mod = self.manager.modules.get(name)
        if mod is not None:
            # A failed module is a real degradation, not a policy pause. Either
            # way, it has left the queued Chill set and should be visible.
            setattr(mod, "_chill_paused", False)
        self._eco_paused = [item for item in self._eco_paused if item != name]
        self._eco_wake_done += 1
        self.run_spinner.set_progress(self._eco_wake_done, getattr(self, "_eco_wake_total", 1))
        self.console._append(
            f"[chill]   {name}: {'back online' if ok else 'could not wake'}")

    def _on_eco_wakeup_complete(
        self, generation: int, ok: int, failed: int
    ) -> None:
        if generation != self._eco_wake_epoch:
            return
        self.run_spinner.finish("Scanners online")
        self.console._append(
            f"[chill] Wake-up complete — {ok} online, {failed} failed."
        )
        pending = getattr(self, "_pending_simulation_cfg", None)
        if pending is not None:
            self._pending_simulation_cfg = None
            QTimer.singleShot(0, lambda cfg=pending: self._run_simulation(cfg))

    def _return_to_chill_after_drill(self) -> None:
        if self._eco_on and self._chill_policy.enabled:
            self._enter_eco(auto_return=True)

    # ── Shark Attack Engine ──────────────────────────────────────────────────
    # ── Unified Red Team Simulation (Shark + APT scenarios, configurable) ────
    def _open_simulation(self) -> None:
        """Open the modern Red Team console (config + live kill-chain + editor).
        The console calls back into _run_simulation(cfg) when the operator launches."""
        from angerona.gui.red_team_console import RedTeamConsole
        # Keep drill artifacts with Angerona's bounded runtime data by default.
        # User folders remain explicit presets for deliberate coverage tests.
        default_target = str(self.config.data_dir / "drill-sandbox")
        if getattr(self, "_rt_console", None) is None:
            self._rt_console = RedTeamConsole(self, default_target=default_target)
        self._rt_console.show()
        self._rt_console.raise_()
        self._rt_console.activateWindow()

    def _open_device_lab(self) -> None:
        """Open Red Team directly to the owner-authorized Device Security Lab."""
        self._open_simulation()
        console = getattr(self, "_rt_console", None)
        tabs = getattr(console, "_tabs", None)
        if tabs is None:
            return
        for index in range(tabs.count()):
            if "Device Security Lab" in tabs.tabText(index):
                tabs.setCurrentIndex(index)
                break

    def _open_scan_center(self) -> None:
        """Bring the main window forward and select its local-only Scan Center."""
        self.show()
        self.raise_()
        self.activateWindow()
        self._right_tabs.setCurrentWidget(self.scan_center)

    def _on_right_tab_changed(self, index: int) -> None:
        """Give the Scan Center working room, restoring the dashboard afterward."""
        scan_index = self._right_tabs.indexOf(self.scan_center)
        if index == scan_index:
            if self._pre_scan_center_sizes is None:
                sizes = self._body_splitter.sizes()
                if sum(sizes) > 0:
                    self._pre_scan_center_sizes = sizes
            QTimer.singleShot(0, self._expand_scan_center)
            return
        if self._pre_scan_center_sizes is not None:
            previous = self._pre_scan_center_sizes
            self._pre_scan_center_sizes = None
            self._body_splitter.setSizes(previous)

    def _expand_scan_center(self) -> None:
        if self._right_tabs.currentWidget() is not self.scan_center:
            return
        sizes = self._body_splitter.sizes()
        total = sum(sizes) or max(600, self._body_splitter.height())
        bottom = max(90, min(150, total // 5))
        self._body_splitter.setSizes([max(360, total - bottom), bottom])

    def _run_simulation(self, cfg) -> None:
        if (self.shark_engine.is_running or self.red_team_engine.is_running
                or int(getattr(self, "_sim_aar_pending", 0)) > 0):
            QMessageBox.information(
                self,
                "Red Team Simulation",
                "A drill or its evidence-preserving report is already running.",
            )
            return
        # A drill must test real detector/response paths, not sensors that Chill
        # intentionally parked. Wake them first and launch only after the staged
        # worker reaches its cycle barriers. This is a coverage lease, not a
        # hostile-threat classification.
        if self._eco_on and self._chill_policy.enabled:
            self._chill_policy.force_escalate(
                "operator-requested practice drill needs full detector coverage"
            )
            self._pending_simulation_cfg = dict(cfg)
            if self._wake_chill_modules(auto=True):
                self.console._append(
                    "[chill] Preparing full detector coverage before the drill starts."
                )
                return
            self._pending_simulation_cfg = None
        import os
        self._shark_prev_armed = os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK")
        self._shark_prev_minsev = os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY")
        self._shark_prev_scope = os.environ.get("ANGERONA_SOAR_RESPONSE_SCOPE")
        # Auto-remediation (ON by default): arm SOAR's kill+rollback tier and lower
        # the response threshold for the drill so it actually contains the benign
        # MEDIUM/HIGH marker detections (the self-kill guard means this only rolls
        # back the dropped artifacts). Restored to the user's default when done.
        self._sim_auto_remediate = bool(cfg.get("auto_remediate", True))
        if self._sim_auto_remediate:
            os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] = "1"
            os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY"] = "MEDIUM"
            scope_roots = [str(self.config.data_dir / "drill-sandbox")]
            selected_target = str(cfg.get("target_dir") or "").strip()
            if selected_target:
                scope_roots.append(selected_target)
            os.environ["ANGERONA_SOAR_RESPONSE_SCOPE"] = os.pathsep.join(
                dict.fromkeys(scope_roots)
            )
        # Analogy coaching (Flight Instructor) — ON by default for the drill.
        self._fi_enabled = bool(cfg.get("analogy", True))
        try:
            self.shark_monitor.fi_check.setChecked(self._fi_enabled)
        except Exception:
            pass
        self._sim_ran_shark = bool(cfg.get("run_shark"))
        self._sim_ran_redteam = bool(cfg.get("run_redteam"))
        self._sim_aar_pending = int(self._sim_ran_shark) + int(self._sim_ran_redteam)
        import threading
        self._sim_aar_lock = threading.Lock()
        # The new Red Team console (which launched this) shows the live events and
        # analogy coaching itself, so the legacy Live Offense Monitor is no longer
        # popped up. It's still reset + fed silently (narration flows via the
        # _shark_narration / _fi_coaching signals to the console too).
        self.shark_monitor.reset()
        self.shark_monitor.append(
            f"Launching Red Team Simulation — intensity={cfg.get('intensity', cfg.get('complexity'))}, "
            f"campaign={bool(cfg.get('campaign'))}, shark={self._sim_ran_shark}, "
            f"apt={self._sim_ran_redteam}, auto-remediate={self._sim_auto_remediate}"
            + (", +custom technique" if cfg.get('custom') else "") + "…")
        self.shark_swim.start(); self.shark_banner.start()
        _target = cfg.get("target_dir") or None
        _custom = cfg.get("custom") or None
        self._sim_runtime_watch = _target
        if _target:
            try:
                from angerona.modules.file_integrity import register_runtime_watch
                register_runtime_watch(_target)
            except Exception:
                pass
            try:
                from angerona.modules.purple_guard import register_runtime_target
                register_runtime_target(_target)
            except Exception:
                pass
        if self._sim_ran_redteam:
            self.red_team_engine.hold_evidence_for_aar()
            self.red_team_engine.start(intensity=cfg.get("intensity"),
                                       campaign=bool(cfg.get("campaign", False)),
                                       target_dir=_target, custom=_custom)
        if self._sim_ran_shark:
            # Shark engine keeps the legacy interface (complexity/target/custom).
            self.shark_engine.start(complexity=cfg.get("complexity", 1),
                                    target_dir=_target, custom=_custom)
        self._sim_poll = QTimer(self)
        self._sim_poll.timeout.connect(self._sim_check_done)
        self._sim_poll.start(500)

    def _sim_check_done(self) -> None:
        if self.shark_engine.is_running or self.red_team_engine.is_running:
            return
        self._sim_poll.stop()
        self.shark_swim.stop(); self.shark_banner.stop()
        # Complete the live progress wheel in the Red Team console (green 100%).
        rtc = getattr(self, "_rt_console", None)
        if rtc is not None:
            try:
                rtc.finish_run()
            except Exception:
                pass
        # Do not disarm response here: FIM and other pollers report during the
        # following 45-second settle window. The last AAR worker restores the
        # operator's prior policy after evaluation completes.
        import threading
        if getattr(self, "_sim_ran_redteam", False):
            self._sim_redteam_cleanup_scope = (
                self.red_team_engine.evidence_cleanup_scope()
            )
            threading.Thread(target=self._red_team_build_aar, daemon=True).start()
        if getattr(self, "_sim_ran_shark", False):
            threading.Thread(target=self._shark_build_aar, daemon=True).start()

    def _simulation_aar_finished(self) -> None:
        """Restore the pre-drill response policy after every requested AAR settles."""
        lock = getattr(self, "_sim_aar_lock", None)
        if lock is None:
            return
        with lock:
            pending = int(getattr(self, "_sim_aar_pending", 0))
            if pending <= 0:
                return
            pending -= 1
            self._sim_aar_pending = pending
            if pending:
                return
            import os
            for key, previous in (
                    ("ANGERONA_SOAR_KILL_AND_ROLLBACK", self._shark_prev_armed),
                    ("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY",
                     getattr(self, "_shark_prev_minsev", None)),
                    ("ANGERONA_SOAR_RESPONSE_SCOPE",
                     getattr(self, "_shark_prev_scope", None))):
                if previous is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = previous
            try:
                from angerona.modules.file_integrity import unregister_runtime_watch
                unregister_runtime_watch(getattr(self, "_sim_runtime_watch", None))
            except Exception:
                pass
            try:
                from angerona.modules.purple_guard import unregister_runtime_target
                unregister_runtime_target(getattr(self, "_sim_runtime_watch", None))
            except Exception:
                pass
            self._sim_runtime_watch = None
            if self._eco_on and self._chill_policy.enabled:
                self.chill_return_requested.emit()

    def _start_shark_attack(self) -> None:
        if self.shark_engine.is_running:
            QMessageBox.information(self, "Shark Attack", "A drill is already running.")
            return
        reply = QMessageBox.question(
            self, "Initiate Shark Attack",
            "This runs an unannounced, non-destructive adversary simulation against "
            "THIS Angerona instance to test autonomous detection + response, end to "
            "end. The running modules get no advance notice — that's the point — but "
            "every action is a real, narrowly-scoped, reversible test (an inert EICAR "
            "test file, read-only system enumeration, a benign outbound test "
            "connection). No data ever leaves this machine and no real persistence "
            "mechanism is ever touched.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply != QMessageBox.Yes:
            return

        # Arm the Active Response SOAR engine's kill+rollback tier for the
        # duration of this one run, then restore whatever the user had set.
        import os
        self._shark_prev_armed = os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK")
        os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] = "1"

        self.shark_monitor.reset()
        self.shark_monitor.append("Launching Shark Attack Engine…")
        self.shark_monitor.show()
        self.shark_monitor.raise_()
        self.shark_monitor.activateWindow()

        self.shark_swim.start()
        self.shark_banner.start()
        self.shark_engine.start()
        self._shark_poll = QTimer(self)
        self._shark_poll.timeout.connect(self._shark_check_done)
        self._shark_poll.start(500)

    def _open_red_team(self) -> None:
        """Open the Red Team console window (Live Offense Monitor)."""
        self.shark_monitor.show()
        self.shark_monitor.raise_()
        self.shark_monitor.activateWindow()

    # ── Red Team Attack (its own distinct drill) ─────────────────────────────
    def _start_red_team(self) -> None:
        if self.red_team_engine.is_running or self.shark_engine.is_running:
            QMessageBox.information(self, "Red Team Attack", "A drill is already running.")
            return
        reply = QMessageBox.question(
            self, "Red Team Attack",
            "Run the Red Team drill — a non-destructive, APT-style credential-access / "
            "fileless-persistence simulation against THIS instance (a DIFFERENT scenario "
            "from the Shark Attack drill). Every step is a benign, reversible marker: no "
            "real secret is read and no persistence mechanism is touched.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        import os
        self._shark_prev_armed = os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK")
        os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] = "1"
        self.shark_monitor.reset()
        self.shark_monitor.append("Launching Red Team Engine…")
        self.shark_monitor.show()
        self.shark_monitor.raise_()
        self.shark_monitor.activateWindow()
        self.shark_swim.start()
        self.shark_banner.start()
        self.red_team_engine.hold_evidence_for_aar()
        self.red_team_engine.start()
        self._rt_poll = QTimer(self)
        self._rt_poll.timeout.connect(self._red_team_check_done)
        self._rt_poll.start(500)

    def _red_team_check_done(self) -> None:
        if self.red_team_engine.is_running:
            return
        self._rt_poll.stop()
        self.shark_swim.stop()
        self.shark_banner.stop()
        import os
        if self._shark_prev_armed is None:
            os.environ.pop("ANGERONA_SOAR_KILL_AND_ROLLBACK", None)
        else:
            os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] = self._shark_prev_armed
        self._sim_redteam_cleanup_scope = (
            self.red_team_engine.evidence_cleanup_scope()
        )
        import threading
        threading.Thread(target=self._red_team_build_aar, daemon=True).start()

    def _red_team_build_aar(self) -> None:
        from angerona.shark.aar_report import generate_aar
        scope = getattr(self, "_sim_redteam_cleanup_scope", None)
        if scope is None:
            scope = self.red_team_engine.evidence_cleanup_scope()
        try:
            text = generate_aar(self.config.data_dir, settle_seconds=45,
                                 history_name="redteam_history.json",
                                 stage_category=REDTEAM_STAGE_CATEGORY,
                                 title="RED TEAM ATTACK", report_basename="redteam_aar")
        except Exception as exc:
            text = (
                "RED TEAM ATTACK — After-Action Report unavailable\n\n"
                f"Report persistence/evaluation failed: {type(exc).__name__}: {exc}"
            )
        finally:
            try:
                self.red_team_engine.release_evidence_after_aar(scope)
            except Exception as cleanup_exc:
                self._shark_narration.emit(
                    f"Red Team evidence cleanup needs review: {cleanup_exc}"
                )
            finally:
                self._sim_redteam_cleanup_scope = None
            self._simulation_aar_finished()
        try:
            print(text)
        except Exception:
            pass
        self._shark_narration.emit("\U0001F4CB Red Team settle window done — opening the "
                                   "After-Action Report.")
        self._aar_ready.emit(text)

    # ── Flight Instructor Mode (Cyber Security Academy) ─────────────────────
    def _on_fi_toggle(self, state: int) -> None:
        # Plain bool flag, not a widget read — this gets checked from the
        # Shark Attack Engine's background thread, and Qt widget state should
        # only ever be touched on the GUI thread.
        self._fi_enabled = bool(state)

    def _on_fi_style_change(self, text: str) -> None:
        try:
            self.flight_instructor.set_style(text)
        except ValueError:
            pass  # combo box only ever offers valid values

    def _fi_narrate_async(self, raw_line: str) -> None:
        """Process one coaching line on the single bounded worker."""
        try:
            coaching = self.flight_instructor.narrate_event(raw_line)
        except Exception as exc:
            coaching = f"\U0001F393 (Flight Instructor error) {exc}"
        if coaching:
            self._fi_coaching.emit(coaching)   # → right (Flight Instructor) pane

    def _fi_worker_loop(self) -> None:
        """Drain coaching requests with exactly one local-model worker."""
        while True:
            raw_line = self._fi_queue.get()
            try:
                self._fi_narrate_async(raw_line)
            finally:
                self._fi_queue.task_done()

    def _on_shark_narration(self, msg: str) -> None:
        """Called from the engine's background thread — never touch widgets
        here directly, only emit the signal that queues onto the GUI thread."""
        self._shark_narration.emit(msg)
        if self._fi_enabled:
            try:
                self._fi_queue.put_nowait(msg)
            except queue.Full:
                # Coaching is explanatory, so coalesce toward the newest stage.
                # Raw drill telemetry above is never dropped.
                try:
                    self._fi_queue.get_nowait()
                    self._fi_queue.task_done()
                except queue.Empty:
                    pass
                try:
                    self._fi_queue.put_nowait(msg)
                except queue.Full:
                    pass

    def _shark_check_done(self) -> None:
        if self.shark_engine.is_running:
            return
        self._shark_poll.stop()
        self.shark_swim.stop()
        self.shark_banner.stop()

        import os
        if self._shark_prev_armed is None:
            os.environ.pop("ANGERONA_SOAR_KILL_AND_ROLLBACK", None)
        else:
            os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] = self._shark_prev_armed

        import threading
        threading.Thread(target=self._shark_build_aar, daemon=True).start()

    def _shark_build_aar(self) -> None:
        """Runs on a background thread — never touch widgets here directly,
        only emit the signal that hands the result back to the GUI thread."""
        from angerona.shark.aar_report import generate_aar
        # Give fast-polling modules (FIM: nominally 30s) one full cycle plus
        # a safety margin to catch up before judging anything a miss. This
        # was 35s, which a real run showed was too tight: FIM's scan used to
        # re-hash every watched file every cycle (thousands of files),
        # pushing worst-case real-world detection latency past a single
        # cycle boundary to ~60-90s. file_integrity.py now caches by
        # mtime/size so only new/changed files get re-hashed — cycle time
        # should be back near the nominal 30s — but 45s keeps a comfortable
        # margin for scheduling jitter without a noticeably longer wait for
        # the AAR dialog to pop up.
        try:
            text = generate_aar(self.config.data_dir, settle_seconds=45)
        finally:
            self._simulation_aar_finished()
        try:
            print(text)  # surface on the terminal when launched with a console
        except Exception:
            pass         # pythonw has no stdout — never let this crash the drill
        self._shark_narration.emit("\U0001F4CB Settle window done — opening the "
                                   "After-Action Report. (Also available any time "
                                   "via the console's `aar` command.)")
        self._aar_ready.emit(text)

    def _show_aar_dialog(self, text: str) -> None:
        pm = self.manager.modules.get("Posture Hardening")
        is_redteam = "RED TEAM ATTACK" in text.upper()
        report_path = self.config.data_dir / ("redteam_aar.json" if is_redteam
                                              else "shark_aar.json")
        report_binding = {"run_id": "", "sha256": "", "error": ""}
        try:
            raw_report = report_path.read_bytes()
            payload = json.loads(raw_report.decode("utf-8"))
            report_binding.update({
                "run_id": str(payload.get("run_id") or ""),
                "sha256": hashlib.sha256(raw_report).hexdigest(),
            })
        except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
            report_binding["error"] = str(exc)

        def _attempt_fix(progress=None) -> str:
            if pm is None:
                return "[Attempt Fix] Posture Hardening module not available."
            if is_redteam:
                if report_binding.get("error"):
                    return (
                        "[Drill resolution] The displayed report could not be bound to its "
                        "signed JSON. Re-run the report and review it before applying a fix."
                    )
                cleaned = 0
                result = pm.resolve_redteam_report(
                    report_path,
                    cleanup_count=cleaned,
                    expected_run_id=report_binding.get("run_id", ""),
                    expected_report_sha256=report_binding.get("sha256", ""),
                )
                if not result.get("ok"):
                    return f"[Drill resolution] {result.get('error', 'failed')}"
                count = int(result.get("candidates", 0))
                unsupported = result.get("unsupported") or []
                if count <= 0:
                    return (
                        "[Practice fix] No missed detector candidates required. "
                        + (f"Unsupported: {', '.join(unsupported)}" if unsupported else "")
                    )
                verification = pm.verify_redteam_practice(result, progress=progress)
                verified = int(verification.get("verified", 0))
                total = int(verification.get("total", count))
                lines = [
                    "[PRACTICE TEST — no Windows vulnerability was exploited or patched]",
                    f"Applied {count} reviewed Purple Guard candidate(s) under signed "
                    f"contracts; cleaned {cleaned} inert prior-run marker(s).",
                ]
                for row in verification.get("results", []):
                    if row.get("status") == "PRACTICE_FIX_VERIFIED":
                        lines.append(
                            f"✓ {row.get('mitre')}: PRACTICE FIX VERIFIED — positive control "
                            "detected, benign negative control quiet, signed evidence persisted, "
                            f"SOAR response succeeded, postcondition passed; receipt "
                            f"{row.get('receipt_id') or '?'}"
                        )
                    else:
                        lines.append(
                            f"✗ {row.get('mitre')}: APPLIED, NOT VERIFIED — "
                            f"{row.get('error') or 'retest failed'}"
                        )
                if unsupported:
                    lines.append(
                        f"{len(unsupported)} unsupported technique(s) remain OPEN: "
                        + ", ".join(unsupported)
                    )
                if verified == total and total:
                    lines.append(
                        f"[PRACTICE FIX VERIFIED] {verified}/{total} detector/response "
                        "contract(s) passed all controls."
                    )
                else:
                    lines.append(
                        f"[PRACTICE FIX PARTIAL] {verified}/{total} passed; failures remain OPEN."
                    )
                return "\n".join(lines)
            vuln = pm.weaknesses("VULNERABLE")
            if not vuln:
                return "[Attempt Fix] No open weaknesses — posture is clean."
            out = []
            for w in vuln:
                res = pm.generate_remediation(w["mitre_id"])
                if res.get("ok"):
                    out.append(f"— {w['name']} ({w['mitre_id']}) → staged {res['path']}\n"
                               f"{res['script'][:800]}")
                else:
                    out.append(f"— {w['mitre_id']}: {res.get('error')}")
            return ("Local-AI remediation generated (review before applying):\n\n"
                    + "\n\n".join(out))

        def _apply() -> str:
            if pm is None:
                return "Posture Hardening module not available."
            res = []
            for w in pm.weaknesses("VULNERABLE"):
                r = pm.execute_remediation(w["mitre_id"], authorized=True)
                if r.get("ok"):
                    res.append(f"— {w['mitre_id']}: applied (rc={r.get('returncode')})")
                elif r.get("review_required"):
                    res.append(f"— {w['mitre_id']}: no staged script — run Attempt Fix first")
                else:
                    res.append(f"— {w['mitre_id']}: {r.get('error', 'failed')}")
            return "Apply results:\n" + "\n".join(res)

        def _clean_markers() -> int:
            """Erase every drill marker/persistence-marker file from both engines."""
            total = 0
            for eng in (getattr(self, "red_team_engine", None),
                        getattr(self, "shark_engine", None)):
                if eng is None:
                    continue
                try:
                    sweep = getattr(eng, "_sweep_markers", None)
                    if callable(sweep):
                        total += int(sweep() or 0)
                    else:
                        eng.stop_and_clean()
                except Exception:
                    pass
            return total

        dlg = AARDialog(self.config.data_dir, self,
                        on_attempt_fix=_attempt_fix, on_apply=_apply,
                        on_clean=_clean_markers, redteam=is_redteam,
                        report_binding=report_binding)
        dlg.setStyleSheet(self._qss())
        dlg.set_text(text)
        dlg.exec()

    # ── Threat Posture indicator ─────────────────────────────────────────────
    # ── ARIA (local, defensive-only assistant layer) ──────────────────────────
    def _wire_aria(self) -> None:
        """Instantiate the ARIA layer and add the HUD tab. Fully guarded — any
        failure just skips ARIA without affecting the rest of the UI."""
        self.aria_hud = None
        self.aria_voice = None
        self.aria_push = None
        self.aria_governor = None
        self.aria_inbox = None
        self._aria_crit_announced = False
        # Master toggle (Settings ▸ ARIA). Default on so the HUD is visible.
        if not getattr(self.config, "aria_enabled", True):
            return
        try:
            from pathlib import Path
            from angerona.core.posture_history import init_history
            from angerona.core.runbook_rag import RunbookRAG
            from angerona.core.assistant import Assistant, ToolKind
            from angerona.gui.aria_hud import AriaHud

            # Posture-Score trend store — its OWN small DB (not the hot
            # flight-recorder.db) so the HUD's occasional trend writes can never
            # lock-contend with the high-frequency event writer on the GUI thread.
            _hist_db = str(Path(self.config.data_dir) / "aria_posture_history.db")
            self.aria_history = init_history(_hist_db)
            self._aria_last_score = None

            # Runbook RAG over any local playbooks (best-effort; empty is fine).
            from angerona.core.data_paths import project_root
            root = project_root()
            self._aria_rag = RunbookRAG([str(root / "docs"),
                                         str(root / "playbooks"),
                                         str(Path(self.config.data_dir) / "runbooks")])
            try:
                self._aria_rag.build()
            except Exception:
                pass

            # The assistant (reads live; writes stay confirm-then-execute).
            self.aria = Assistant(enabled=True)
            self.aria.register("posture", ToolKind.READ,
                               lambda: getattr(self, "_last_posture", {}) or {},
                               "current Angerona posture")
            # Give ARIA a real, gated action layer by reusing the tested console
            # backend. READ tools run live; WRITE tools stage behind a confirm
            # token (assistant.py enforces the gate). This is what lets ARIA
            # "perform actions/functions" that weren't hard-wired into a button.
            try:
                _b = self.console.backend
                self.aria.register("modules", ToolKind.READ, lambda: _b._modules([]),
                                   "list modules and their status")
                self.aria.register("alerts", ToolKind.READ, lambda: _b._iocs([]),
                                   "recent HIGH/CRITICAL indicators")
                self.aria.register("threat", ToolKind.READ, lambda: _b._threat([]),
                                   "current threat level + counts")
                self.aria.register("processes", ToolKind.READ, lambda n=15: _b._ps([str(n)]),
                                   "top processes by memory")
                self.aria.register("connections", ToolKind.READ, lambda: _b._conns([]),
                                   "active network connections")
                self.aria.register("selftest", ToolKind.READ, lambda: _b._test([]),
                                   "run module self-tests (diagnostics)")
                self.aria.register("resources", ToolKind.READ, lambda: _b._resources([]),
                                   "per-module resource load")
                self.aria.register("incidents", ToolKind.READ, lambda: _b._incidents([]),
                                   "correlated incidents (kill-chains)")
                self.aria.register("coverage", ToolKind.READ, lambda: _b._coverage([]),
                                   "MITRE ATT&CK detect/simulate/remediate coverage")
                self.aria.register("threat_intel", ToolKind.READ, lambda: _b._threat_intel([]),
                                   "latest CISA KEV threat intel for this host")
                self.aria.register("search_events", ToolKind.READ,
                                   lambda term="": _b._search([str(term)]),
                                   "search recent events for a term")
                self.aria.register(
                    "trust_running", ToolKind.WRITE, lambda: _b._trust_running([]),
                    "trust the apps you're running now (exact path)",
                    preview=lambda: "Trust every currently-running non-system app by exact "
                                    "path so memory/behaviour modules stop flagging them.")
                self.aria.register(
                    "suspend", ToolKind.WRITE, lambda pid: _b._suspend([str(pid)]),
                    "freeze (contain) a process by PID",
                    preview=lambda pid: f"Suspend/contain PID {pid} (reversible with resume).")
                self.aria.register(
                    "resume", ToolKind.WRITE, lambda pid: _b._resume([str(pid)]),
                    "resume a suspended process",
                    preview=lambda pid: f"Resume PID {pid}.")
                self.aria.register(
                    "kill", ToolKind.WRITE, lambda pid: _b._kill([str(pid)]),
                    "terminate a process by PID",
                    preview=lambda pid: f"TERMINATE PID {pid} — this cannot be undone.")
                self.aria.register(
                    "set_module", ToolKind.WRITE,
                    lambda name, state: _b._module([name, state]),
                    "enable/disable/restart a module",
                    preview=lambda name, state: f"Set module '{name}' → {state}.")
                # ARIA installs its OWN optional capabilities (voice, teams, …) into
                # this environment — no terminal, no PATH problems. READ status /
                # WRITE (confirm-gated) install.
                from angerona.core import self_installer as _si
                self.aria.register("capabilities", ToolKind.READ, lambda: _si.summary(),
                                   "which optional capabilities are installed / missing")
                self.aria.register(
                    "install_capabilities", ToolKind.WRITE,
                    lambda caps="all": self._aria_install(caps),
                    "install ARIA's optional capability packages (voice/teams/all)",
                    preview=lambda caps="all": (
                        "Install the missing packages for "
                        f"'{caps}' into Angerona's own Python (pip, no admin): "
                        + (", ".join(_si._resolve(
                            [c.strip() for c in str(caps).replace(',', ' ').split()] or ['all']))
                           or "nothing — already installed") + "."))
            except Exception as exc:
                self.console._append(f"[aria] action tools skipped: {exc}")
            self._aria_pending_token = ""   # last staged WRITE awaiting confirmation

            # Compact HUD: orb + status + sparkline only. ARIA now lives entirely
            # in the bottom Console (the single prompt bar), so the orb sits beside
            # the Console rather than in its own tab. This frees the right-hand
            # tabs for Live Alerts + SOAR Queue — you watch alerts and talk to ARIA
            # at the same time. (No more "ARIA" tab stealing the alerts view.)
            self.aria_hud = AriaHud(
                score_fn=lambda: int((getattr(self, "_last_posture", {}) or {}).get("score", 100)),
                alerts_fn=lambda: int(((getattr(self, "_last_posture", {}) or {}).get("factors", {}) or {}).get("active_threats", 0)),
                sparkline_fn=lambda: self.aria_history.sparkline(32),
                trend_fn=lambda: int(self.aria_history.trend().get("delta", 0)),
                ask_fn=self._aria_ask,
                stream_fn=self._aria_ask_stream,
                compact=True,
            )
            self.aria_hud.microphone_requested.connect(
                lambda source: self._reveal_window_from(
                    source,
                    self._open_voice_settings,
                    "#38bdf8",
                )
            )
            self.aria_hud.set_microphone_state(
                bool(getattr(self.config, "aria_voice_enabled", False)))
            # NOTE: intentionally NOT added to self._right_tabs — ARIA is in the
            # Console section now (see _build_console_section in __init__).

            # Meld ARIA into the always-visible bottom Console: any free-form
            # question typed there now STREAMS through ARIA's brain (live typing),
            # while the IR commands (kill/ps/suspend/…) keep working as before.
            try:
                console = getattr(self, "console", None)
                backend = getattr(console, "backend", None)
                if backend is not None and hasattr(backend, "set_ask_handler"):
                    backend.set_ask_handler(self._aria_ask)         # non-stream fallback
                    if hasattr(console, "set_stream_ask"):
                        console.set_stream_ask(self._aria_ask_stream)  # live streaming
                    if console is not None:
                        console._append(
                            "[aria] ARIA lives here now — ask anything in plain language "
                            "(e.g. \"what's my posture?\"); replies stream in live. Type "
                            "'help' for IR commands.")
            except Exception as exc:
                self.console._append(f"[aria] console meld skipped: {exc}")

            # ── Opt-in connectors (each honours its own Settings toggle) ──────
            # Overdrive governor — read-only tuning authority, instantiated so
            # panels/callers can consult it; only active when enabled.
            try:
                from angerona.core.perf_governor import init_governor
                self.aria_governor = init_governor(
                    enabled=bool(getattr(self.config, "perf_governor_enabled", False)))
            except Exception:
                self.aria_governor = None
            # Voice I/O — off unless enabled; degrades silently without a backend.
            try:
                from angerona.connectors.voice import init_voice
                self.aria_voice = init_voice(
                    enabled=bool(getattr(self.config, "aria_voice_enabled", False)),
                    allow_cloud_tts=bool(getattr(self.config, "aria_voice_cloud_tts", False)))
                # Select the mic source (computer default, or an added device).
                try:
                    self.aria_voice.set_mic_device(getattr(self.config, "aria_mic_device", "") or None)
                except Exception:
                    pass
                # If voice is enabled, run the hands-free listen→ARIA→speak loop on
                # a daemon thread. It idles silently when no STT backend/mic exists.
                self._aria_voice_stop = False
                if getattr(self.aria_voice, "enabled", False):
                    self._ensure_voice_loop()
                    # Live mic-level meter so you can SEE ARIA is hearing you. Runs
                    # whenever a mic backend (sounddevice) is present — even before
                    # vosk is installed — so the bar proves the mic works.
                    self._start_mic_meter()
                    self.console._append(
                        "[aria] voice enabled — speaking replies; watch the mic bar to confirm "
                        "I can hear you. For listening, ask me to 'install voice', then say "
                        "'hey aria …'.")
            except Exception:
                self.aria_voice = None
            # Talk to ARIA over the Signal mobile bridge: route its non-command
            # (already sender-verified) messages to ARIA's conversational brain.
            try:
                mob = (self.manager.modules.get("Mobile Response Bridge")
                       if getattr(self, "manager", None) else None)
                if mob is not None and hasattr(mob, "set_aria_handler"):
                    mob.set_aria_handler(self._aria_converse)
            except Exception:
                pass
            # Two-way Teams bot — opt-in; talk to ARIA from Teams. Off unless
            # enabled AND an App ID + password (.env) are set. Chat/reads only.
            try:
                import os as _os
                from angerona.connectors.teams_bot import init_teams_bot
                _tb_enabled = bool(getattr(self.config, "teams_bot_enabled", False))
                _tb_pw = _os.environ.get("ANGERONA_TEAMS_APP_PASSWORD", "")
                _allowed = getattr(self.config, "teams_allowed_users", "") or ""
                if isinstance(_allowed, str):
                    _allowed = [u for u in _allowed.replace(";", ",").split(",") if u.strip()]
                self.aria_teams = init_teams_bot(
                    enabled=_tb_enabled,
                    app_id=str(getattr(self.config, "teams_app_id", "") or ""),
                    app_password=_tb_pw,
                    allowed_users=_allowed,
                    handler=self._aria_converse,
                    port=int(getattr(self.config, "teams_bot_port", 3978) or 3978),
                    skip_auth=bool(getattr(self.config, "teams_bot_skip_auth", False)))
                if _tb_enabled and self.aria_teams.start():
                    self.console._append(
                        "[aria] Teams bot listening — DM the bot in Teams to chat with ARIA.")
                elif _tb_enabled:
                    self.console._append(
                        f"[aria] Teams bot not started: {self.aria_teams.last_error or 'set App ID + ANGERONA_TEAMS_APP_PASSWORD'}.")
            except Exception:
                self.aria_teams = None
            # Channel auto-brief — only if enabled AND a URL is configured.
            try:
                url = str(getattr(self.config, "aria_push_url", "") or "").strip()
                if getattr(self.config, "aria_push_enabled", False) and url:
                    from angerona.connectors.channel_push import (
                        init_channel_push, Target, Level)
                    self.aria_push = init_channel_push(
                        enabled=True, min_level=Level.CRITICAL,
                        targets=[Target(str(getattr(self.config, "aria_push_kind", "slack")), url)])
                else:
                    self.aria_push = None
            except Exception:
                self.aria_push = None
            # Research egress preference (browser-surface by default).
            try:
                from angerona.connectors.research import init_research
                from angerona.connectors.research_fetchers import HttpFetcher
                _egress = bool(getattr(self.config, "aria_research_egress", False))
                init_research(enabled=_egress,
                              fetch=HttpFetcher(allow_egress=True) if _egress else None)
            except Exception:
                pass
            # Email scanning — background read-only IMAP poller → bus alerts.
            # Only starts when enabled AND fully configured (password from .env).
            try:
                import os as _os
                _ih = str(getattr(self.config, "aria_imap_host", "") or "").strip()
                _iu = str(getattr(self.config, "aria_imap_user", "") or "").strip()
                _ip = _os.environ.get("ARIA_IMAP_PASS", "")
                if getattr(self.config, "aria_inbox_enabled", False) and _ih and _iu and _ip:
                    from angerona.connectors.inbox_watcher import InboxWatcher
                    from angerona.core.eventbus import Event, Severity

                    def _inbox_emit(message, sev_name, **details):
                        sev = getattr(Severity, str(sev_name).upper(), Severity.HIGH)
                        try:
                            self.bus.publish(Event("ARIA Inbox", message, sev, time.time(), details))
                        except Exception:
                            pass
                    _mins = float(getattr(self.config, "aria_inbox_interval_min", 5) or 5)
                    self.aria_inbox = InboxWatcher(
                        host=_ih, user=_iu, password=_ip,
                        interval_s=_mins * 60.0, emit=_inbox_emit)
                    self.aria_inbox.start()
            except Exception:
                self.aria_inbox = None
        except Exception as exc:
            self.aria_hud = None
            try:
                self.console._append(f"[aria] wiring skipped: {exc}")
            except Exception:
                pass

    def _on_mic_level(self, level: float) -> None:
        """Feed a live mic level (0..1) to the HUD meter (GUI thread)."""
        hud = getattr(self, "aria_hud", None)
        meter = getattr(hud, "mic_meter", None) if hud is not None else None
        if meter is not None:
            meter.push_level(level)

    def _start_mic_meter(self) -> None:
        """Show the mic-level meter and drive it from a background audio thread.
        Best-effort: silently does nothing if there's no mic backend."""
        v = getattr(self, "aria_voice", None)
        hud = getattr(self, "aria_hud", None)
        meter = getattr(hud, "mic_meter", None) if hud is not None else None
        if v is None or meter is None:
            return
        # Only show the meter if a mic backend (sounddevice) is actually present;
        # otherwise there's nothing to read — the user installs it via 'install voice'.
        try:
            from angerona.connectors.voice import Voice
            if not Voice.list_input_devices():
                return
        except Exception:
            return
        meter.set_active(True)
        if getattr(self, "_mic_meter_running", False):
            return                     # a monitor thread is already feeding the meter
        self._mic_meter_running = True

        def _run():
            try:
                v.level_monitor(on_level=lambda lv: self._mic_level.emit(lv),
                                should_stop=lambda: getattr(self, "_aria_voice_stop", False))
            except Exception:
                pass
            self._mic_meter_running = False
            # Monitor ended (no backend / stopped) — hide the meter.
            try:
                self._mic_level.emit(0.0)
            except Exception:
                pass

        import threading as _th
        _th.Thread(target=_run, name="AriaMicMeter", daemon=True).start()

    def _aria_ask(self, text: str) -> str:
        """Public ARIA entry point: run the brain, then speak the reply if voice
        output is enabled. Kept thin so the HUD, the console, and the voice loop
        all share one path."""
        answer = self._aria_ask_core(text)
        try:
            self._aria_speak(answer)
        except Exception:
            pass
        return answer

    def _aria_ask_stream(self, text: str, on_token) -> str:
        """Streaming entry point for the HUD: quick intents return instantly (no
        tokens); a real conversation streams token-by-token via on_token. The full
        answer is still returned (and spoken if voice is on)."""
        answer = self._aria_ask_core(text, on_token=on_token)
        try:
            self._aria_speak(answer)
        except Exception:
            pass
        return answer

    def _aria_speak(self, text: str) -> None:
        """Speak a trimmed version of an answer when voice OUTPUT is enabled."""
        v = getattr(self, "aria_voice", None)
        if v is None or not getattr(v, "enabled", False) or not text:
            return
        spoken = str(text).strip()
        if "\n" in spoken:                       # speak the headline, not whole tables
            spoken = spoken.split("\n", 1)[0]
        spoken = spoken[:400]
        try:
            v.speak(spoken)
        except Exception:
            pass

    def _aria_voice_loop(self) -> None:
        """Background: listen for 'hey aria <command>', run it through the full
        ARIA brain (gated actions included), and speak the reply. Off unless voice
        is enabled and an STT backend is present; degrades to a silent idle."""
        import time as _t
        v = getattr(self, "aria_voice", None)
        if v is None:
            return
        # Only run the hands-free LISTEN loop if a real STT backend resolves.
        # Without one, listen() returns instantly and the loop busy-spins at 100%
        # CPU hammering importlib.find_spec (seen in the crash dump). TTS reply-
        # speaking still works via _aria_speak, so we just skip the listen loop.
        try:
            stt = v._resolve_stt()
        except Exception:
            stt = None
        if stt is None:
            self._aria_speak("Voice replies enabled. Ask me to 'install voice' so I can hear you.")
            return
        self._voice_loop_alive = True     # a real listen loop is now running
        self._aria_speak("ARIA voice online. Say 'hey aria' followed by a command.")
        try:
            while not getattr(self, "_aria_voice_stop", False):
                try:
                    heard = v.listen(5.0)
                except Exception:
                    heard = None
                if not heard or not v.is_wake(heard):
                    _t.sleep(0.3)          # guard against any tight-spin on empty listen
                    continue
                cmd = v.strip_wake(heard)
                if not cmd:
                    self._aria_speak("Yes?")
                    continue
                try:
                    self._aria_ask(cmd)          # reply is spoken inside _aria_ask
                except Exception:
                    pass
                _t.sleep(0.2)
        finally:
            self._voice_loop_alive = False       # loop exited → allow a fresh start

    def _voice_loop_in_flight(self) -> bool:
        with self._voice_loop_lock:
            return (
                self._voice_loop_thread is not None
                and self._voice_loop_thread.is_alive()
            )

    def _voice_loop_entry(self) -> None:
        try:
            self._aria_voice_loop()
        finally:
            current = threading.current_thread()
            with self._voice_loop_lock:
                if self._voice_loop_thread is current:
                    self._voice_loop_thread = None

    def _ensure_voice_loop(self) -> bool:
        """Start at most one resolver/listener across rapid settings clicks."""
        with self._voice_loop_lock:
            current = self._voice_loop_thread
            if current is not None and current.is_alive():
                return False
            self._aria_voice_stop = False
            worker = threading.Thread(
                target=self._voice_loop_entry,
                name="AriaVoice",
                daemon=True,
            )
            self._voice_loop_thread = worker
            try:
                worker.start()
            except Exception:
                self._voice_loop_thread = None
                raise
            return True

    def _enable_voice_live(self) -> None:
        """(Re)build the voice subsystem NOW with whatever backends are installed,
        enable it, and start the listen loop + mic meter — so 'install voice'
        makes ARIA hear you WITHOUT an app restart. Runs on the GUI thread (via a
        signal) because it touches the mic-meter widget."""
        from angerona.connectors.voice import init_voice
        try:
            self.config.aria_voice_enabled = True
            self.config.save()
        except Exception:
            pass
        # If a listen loop is already alive, voice is already hearing — just make
        # sure the meter is visible and stop here (no duplicate loop).
        if self._voice_loop_in_flight():
            try:
                self._start_mic_meter()
            except Exception:
                pass
            return
        try:
            self.aria_voice = init_voice(
                enabled=True,
                allow_cloud_tts=bool(getattr(self.config, "aria_voice_cloud_tts", False)))
            try:
                self.aria_voice.set_mic_device(getattr(self.config, "aria_mic_device", "") or None)
            except Exception:
                pass
            self._ensure_voice_loop()
            self._start_mic_meter()
        except Exception as exc:
            try:
                self.console._append(f"[aria] live voice start failed: {exc}")
            except Exception:
                pass

    def _aria_install(self, caps: str = "all") -> str:
        """Install a capability, then — for voice — bring listening up live so the
        mic meter appears and ARIA can hear you without a restart."""
        from angerona.core import self_installer as si
        names = [c.strip() for c in str(caps).replace(",", " ").split()] or ["all"]
        report = si.install(names)
        low = [n.lower() for n in names]
        if any(n in ("voice", "all", "windows-speech") for n in low) and "❌" not in report:
            try:
                self._voice_live_requested.emit()   # start on the GUI thread
                report += ("\n\nVoice is coming online now — watch the mic bar next to ARIA "
                           "and speak; when it moves, I can hear you. Then say 'hey aria …'.")
            except Exception:
                report += "\n\n(Installed — restart Angerona to start voice listening.)"
        return report

    def _aria_ask_core(self, text: str, on_token=None) -> str:
        """HUD chat handler. A few quick intents (posture / indicator research)
        are answered directly; everything else is a real conversation with the
        local model, grounded with runbook excerpts + live posture. Runs on a
        worker thread (the HUD offloads it), so the blocking model call is fine.
        ``on_token`` (if given) streams the conversational reply chunk-by-chunk."""
        t = (text or "").strip()
        if not t:
            return ""
        low = t.lower()
        try:
            if low in ("score", "posture", "status"):
                p = getattr(self, "_last_posture", {}) or {}
                return f"Angerona Score {p.get('score', '?')} — {p.get('label', '?')}."
            # Greetings / help — answer directly; NEVER fall through to a runbook
            # dump (a BM25 match for "hello" is what made ARIA look broken).
            greetings = {"hi", "hello", "hey", "yo", "hiya", "sup", "howdy",
                         "hey aria", "hello aria", "hi aria", "thanks", "thank you",
                         "ty", "gm", "good morning", "good afternoon", "good evening"}
            g = low.rstrip("!.? ")
            if g in greetings or g in ("help", "commands", "what can you do",
                                       "who are you", "what can you do"):
                return self._aria_help()
            # Instant help topic (no model needed): "guide voice", "info teams".
            if g in ("guide", "info") or low.startswith("guide ") or low.startswith("info "):
                try:
                    from angerona.gui.help_content import get
                    topic = t.split(None, 1)[1] if len(t.split(None, 1)) > 1 else "getting-started"
                    return get(topic)
                except Exception:
                    pass
            # "trust my running apps" → baseline current apps into the allowlist.
            if "trust" in low and any(k in low for k in (
                    "running", "my apps", "these apps", "current apps", "open apps",
                    "programs i", "programs im", "what i'm running", "what im running")):
                try:
                    return self.console.backend._trust_running([])
                except Exception as exc:
                    return f"Couldn't baseline running apps: {exc}"
            # Gated actions / live reads (suspend/kill/resume/module, confirm …).
            acted = self._aria_action(t)
            if acted is not None:
                return acted
            # Strategy / planning → a prioritized, grounded action plan.
            if any(k in low for k in ("what should i do", "strategi", "recommend",
                                      "next step", "prioriti", "action plan", "game plan",
                                      "what do you suggest", "harden")):
                plan_q = ("Given the current posture and live environment above, reply with a "
                          "SHORT, prioritized, numbered action plan (most important first). For "
                          "each item give the exact Angerona step/command/Setting to use. "
                          "Operator asked: " + t)
                return self._aria_converse(plan_q, on_token=on_token)
            # Indicator? Open vetted lookups (user-initiated, read-only recon).
            from angerona.connectors.research import classify, get_research
            if classify(t) != "unknown":
                task = get_research().run(t)
                from angerona.connectors.research_fetchers import open_sources
                opened = open_sources(task)
                srcs = ", ".join(n for n, _ in task.sources) or "none"
                return f"{t} → {task.kind}: opened {opened} vetted source(s) [{srcs}]."
            # Everything else → conversational answer from the local model.
            return self._aria_converse(t, on_token=on_token)
        except Exception as exc:
            return f"[aria error] {exc}"

    def _aria_action(self, text: str):
        """Map a natural-language request to a gated ARIA tool. READ tools answer
        live; WRITE tools stage behind a confirm token (assistant.py enforces the
        gate). Returns a string to show, or None if this wasn't an action request."""
        import re
        aria = getattr(self, "aria", None)
        if aria is None:
            return None
        low = text.lower().strip()

        # 1) Confirm / cancel a pending write.
        m = re.search(r"\bconfirm\s+([0-9a-f]{8,})\b", low)
        if m:
            return aria.confirm(m.group(1)).text
        if low in ("confirm", "yes", "do it", "go ahead", "proceed", "y") and self._aria_pending_token:
            tok, self._aria_pending_token = self._aria_pending_token, ""
            return aria.confirm(tok).text
        if low in ("cancel", "no", "abort", "stop", "nvm", "never mind") and self._aria_pending_token:
            aria.cancel(self._aria_pending_token); self._aria_pending_token = ""
            return "Cancelled the pending action."

        def _pid(s):
            mm = re.search(r"\bpid\s*(\d{2,7})\b", s) or re.search(r"\b(\d{2,7})\b", s)
            return int(mm.group(1)) if mm else None

        # 2) Read intents (answered live). Don't fire the modules LIST when the
        # user is actually asking to enable/disable/restart a specific module.
        _has_module_verb = re.search(
            r"\b(enable|disable|restart|turn on|turn off|stop|start)\b", low)
        if ((re.search(r"\b(list|show|which)\s+modules?\b", low)
             or low in ("modules", "module status", "list modules", "show modules"))
                and not _has_module_verb):
            return aria.invoke("modules").text
        if re.search(r"\b(recent )?(alerts|iocs|indicators|detections)\b", low):
            return aria.invoke("alerts").text
        if low in ("threat", "threat level", "what's the threat level", "whats the threat level"):
            return aria.invoke("threat").text
        if re.search(r"\b(top )?(processes|proc list|running processes)\b", low):
            return aria.invoke("processes").text
        if re.search(r"\b(connections|netstat|network connections)\b", low):
            return aria.invoke("connections").text
        if re.search(r"\b(self.?test|run tests?|diagnostics?)\b", low):
            return aria.invoke("selftest").text
        if re.search(r"\b(resources?|resource (load|usage)|resmon)\b", low):
            return aria.invoke("resources").text
        if re.search(r"\b(incidents?|kill.?chains?)\b", low):
            return aria.invoke("incidents").text
        if re.search(r"\b(att&?ck coverage|mitre coverage|detection coverage|coverage)\b", low):
            return aria.invoke("coverage").text
        if re.search(r"\b(threat intel|kev|cve|vulnerabilit)\b", low):
            return aria.invoke("threat_intel").text
        # Capability status (read).
        if (re.search(r"\b(capabilit|dependenc|what.*can you install|what.*missing)\b", low)
                and not re.search(r"\binstall\b", low)):
            return aria.invoke("capabilities").text

        # 3) Write intents (staged behind confirmation).
        res = None
        # Self-install optional capabilities. "install voice", "install your
        # dependencies", "set up teams", "install everything".
        _inst = re.search(r"\b(install|set ?up|add|enable)\b", low)
        if _inst and re.search(r"\b(capabilit|dependenc|packages?|voice|teams|scapy|"
                               r"speech|everything|all your|yourself|your (deps|dependencies))\b", low):
            if re.search(r"\b(voice|speech|mic|listen|speak|talk)\b", low):
                caps = "voice windows-speech"
            elif "teams" in low:
                caps = "teams"
            elif re.search(r"\b(arp|scapy|network)\b", low):
                caps = "network-arp"
            elif re.search(r"\b(etw|real.?time)\b", low):
                caps = "realtime-etw"
            else:
                caps = "all"
            res = aria.invoke("install_capabilities", caps)
        if re.search(r"\b(suspend|contain|freeze|isolate)\b", low) and _pid(low):
            res = aria.invoke("suspend", pid=_pid(low))
        elif re.search(r"\b(resume|unfreeze|unsuspend)\b", low) and _pid(low):
            res = aria.invoke("resume", pid=_pid(low))
        elif re.search(r"\b(kill|terminate)\b", low) and _pid(low):
            res = aria.invoke("kill", pid=_pid(low))
        else:
            mm = (re.search(r"\b(enable|disable|restart|turn on|turn off|stop|start)\b"
                            r"(?:\s+the)?\s+(.+?)\s+module\b", low)
                  or re.search(r"\bmodule\s+(.+?)\s+(on|off|restart)\b", low))
            if mm:
                if mm.re.pattern.startswith(r"\bmodule"):
                    name, verb = mm.group(1), mm.group(2)
                else:
                    verb, name = mm.group(1), mm.group(2)
                state = {"enable": "on", "turn on": "on", "start": "on",
                         "disable": "off", "turn off": "off", "stop": "off",
                         "on": "on", "off": "off",
                         "restart": "restart"}.get(verb.strip(), verb.strip())
                # NOTE: pass positionally — assistant.invoke()'s first param is
                # itself called `name` (the tool name), so a name= kwarg collides.
                res = aria.invoke("set_module", name.strip(), state)

        if res is None:
            return None
        if res.needs_confirmation:
            self._aria_pending_token = res.confirm_token
        return res.text

    def _aria_help(self) -> str:
        p = getattr(self, "_last_posture", {}) or {}
        return (
            "Hi — I'm ARIA, your local assistant inside Angerona.\n"
            f"Current posture: Angerona Score {p.get('score', '?')} "
            f"({p.get('label', '?')}).\n\n"
            "You can ask me to:\n"
            "• \"score\" / \"posture\" — the live security posture\n"
            "• a question about Angerona or security — I'll answer from the local "
            "model, grounded in your runbooks\n"
            "• an indicator (hash / IP / domain / URL / CVE) — I'll open vetted, "
            "read-only lookups\n\n"
            "Everything I do is local and defensive; any action stays behind a "
            "confirm-then-execute gate."
        )

    @staticmethod
    def _looks_like_lookup(q: str) -> bool:
        """True if the question is a substantive how-to/what-is query worth a
        runbook fallback — as opposed to a greeting or one-word aside."""
        ql = (q or "").lower()
        if "?" in ql:
            return True
        triggers = ("how ", "what ", "why ", "where ", "when ", "which ", "who ",
                    "explain", "list", "show ", "configure", "set up", "setup",
                    "enable", "disable", "runbook", "playbook", "steps",
                    "procedure", "fix", "troubleshoot", "how to")
        return any(tk in ql for tk in triggers) or len(ql.split()) >= 4

    # Concise, static primer so ARIA understands how the modules interrelate
    # (the "how it works together" the operator asked for). Kept short on purpose.
    _ARIA_ARCH = (
        "How Angerona works together: real-time SENSORS (ETW + Sysmon process events, "
        "network sniffer/protocol decoder, memory-injection scanner, file-integrity, "
        "YARA, AMSI/AV bridges) publish onto a signed EventBus. DETECTION modules "
        "(Sigma engine, deterministic fast-path IOCs, LSASS/ransomware/beacon/shadow-copy "
        "guards, live ATT&CK tracker) score those events, and the Evidence Lattice fuses "
        "weak signals across modules into one corroborated finding. AI TRIAGE (local "
        "llama3, optional cloud fallback) explains them. The SOAR engine requires >=2 "
        "independent module signals before any contain/kill/rollback and only acts on "
        "operator confirmation (System32 allowlist protects critical processes). A "
        "resilience layer (watchdog + supervisor + shared-memory heartbeats) keeps the "
        "core alive, while DRILL and CHAOS fire benign synthetic probes to prove the "
        "sensors aren't blinded. Everything is local-first and strictly defensive."
    )

    # Practical setup/testing/troubleshooting knowledge so ARIA can coach the
    # operator through real tasks with exact steps (not vague advice).
    _ARIA_COACH = (
        "Coaching cheat-sheet (use exact names/commands):\n"
        "SETUP: Trusted apps → type 'trust-running' (or say 'trust my running apps') so "
        "memory/behaviour modules stop flagging apps you use. Local AI → run Ollama "
        "(ollama serve · ollama pull llama3); online fallback → Settings ▸ API Keys. "
        "Voice → Settings ▸ enable voice (speaks via Windows SAPI); for listening you "
        "don't need a terminal — just ask me to 'install voice' and I'll add vosk + "
        "sounddevice myself, then say 'hey aria …'. (I can also 'install teams' or "
        "'install all'; type 'capabilities' to see what's missing.) Phone → Settings ▸ Mobile "
        "Response Bridge (signal-cli path + your number); then text ARIA over Signal. "
        "Autostart → Settings ▸ Start with Windows.\n"
        "TESTING: header 'RUN SELF-TEST' or console 'test [module]' checks a sensor's "
        "pipeline; 'RUN RED TEAM SIMULATION' fires a benign ATT&CK drill; 'aar' re-scores "
        "the last drill (re-run after FIM ~30s / YARA ~5min cycles). DRILL/CHAOS auto-"
        "verify sensors aren't blind.\n"
        "TROUBLESHOOT: console 'threat' (level+counts), 'modules' (status), 'resources' "
        "(per-module load), 'iocs' (recent HIGH/CRITICAL). A module stuck 'stopped' or "
        "'quarantined' → 'module <name> restart'. Threat level stuck High on your own "
        "apps → 'trust-running' or Resolve Center ▸ Ignore/Allow. Logs live in "
        "diagnostics/ (runtime_alerts.log, crash.log, not_responding.log). If ARIA's "
        "local model is unreachable it's usually Ollama not running."
    )

    def _aria_context(self) -> str:
        """A compact, LIVE snapshot of the running environment so ARIA answers with
        real awareness of what's actually happening, not generic knowledge."""
        from angerona.core.eventbus import Severity
        lines: list[str] = []
        try:
            mods = self.manager.modules
            running = sum(1 for m in mods.values() if getattr(m, "status", "") == "running")
            by_cat: dict[str, list] = {}
            for m in mods.values():
                by_cat.setdefault(getattr(m, "category", "?"), []).append(m)
            lines.append(f"Live modules: {running}/{len(mods)} running, by role:")
            for cat in sorted(by_cat):
                ms = by_cat[cat]
                up = sum(1 for m in ms if getattr(m, "status", "") == "running")
                names = ", ".join(sorted(getattr(m, "name", type(m).__name__) for m in ms)[:6])
                lines.append(f"  {cat}: {up}/{len(ms)} up — {names}")
        except Exception:
            pass
        try:
            from angerona.core.threat import active_threat_events
            evs = active_threat_events(self.bus.recent(200))
            if evs:
                lines.append(f"Recent HIGH/CRITICAL ({len(evs)} in window), newest first:")
                for e in sorted(evs, key=lambda e: e.ts, reverse=True)[:6]:
                    lines.append(f"  [{e.severity.label}] {e.module}: {(e.message or '')[:90]}")
            else:
                lines.append("No HIGH/CRITICAL alerts in the recent window.")
        except Exception:
            pass
        return "\n".join(lines)

    def _aria_converse(self, question: str, on_token=None) -> str:
        """Ask the local Ollama model, grounded with a LIVE environment snapshot +
        architecture primer + runbook context + posture. If the local model is
        unreachable, optionally consult an online AI (when a provider key is
        configured), then fall back to a relevant runbook or a clear note."""
        from angerona.core.eventbus import Severity   # local import: keep top clean
        # Grounding: top runbook chunks (if any) + current posture.
        context = ""
        try:
            rag = getattr(self, "_aria_rag", None)
            hits = rag.query(question, k=3) if rag is not None else []
            if hits:
                context = "\n\n".join(f"[{h.source} › {h.heading}]\n{h.excerpt}" for h in hits)
        except Exception:
            pass
        p = getattr(self, "_last_posture", {}) or {}
        posture_line = f"Current Angerona Score: {p.get('score', '?')} ({p.get('label', '?')})."
        env = self._aria_context()
        system = (
            "You are ARIA, the local assistant embedded inside Angerona, a defensive "
            "Windows security suite. You are also a hands-on COACH: help the operator "
            "set up, configure, TEST, and TROUBLESHOOT any part of Angerona or their "
            "Windows device. When they ask how to do something, give concrete, ordered "
            "steps — name the exact Settings toggle, console command, or button, and "
            "explain what a good result looks like and what to check if it fails. Use "
            "the LIVE environment snapshot so your guidance reflects what's actually "
            "running now (e.g. reference a module that's stopped or an alert that's "
            "firing). Answer conversationally, concisely, accurately. You are strictly "
            "defensive: never help with malware, exploits, or offensive tooling. You may "
            "use general knowledge, but don't invent Angerona features you're unsure of."
        )
        prompt = (f"{system}\n\n{self._ARIA_ARCH}\n\n{self._ARIA_COACH}\n\n"
                  f"{posture_line}\n\n[LIVE ENVIRONMENT]\n{env}")
        if context:
            prompt += "\n\nReference excerpts from the operator's runbooks:\n" + context
        prompt += f"\n\nUser: {question}\nARIA:"
        try:
            from angerona.engines import ollama_client
            model = getattr(self.config, "ollama_model", "llama3")
            host = getattr(self.config, "ollama_host", None)
            # Conversational speed: keep_alive pins the model in RAM so there's no
            # multi-second cold reload between messages; capped num_predict + a
            # lower temperature make replies land fast and stay concise.
            payload = {"model": model, "prompt": prompt,
                       "keep_alive": getattr(self.config, "ollama_keep_alive", "30m"),
                       "options": {"num_predict": 400, "temperature": 0.4, "top_p": 0.9}}
            if on_token is not None:
                # Stream the reply token-by-token for a live "typing" feel.
                res = ollama_client.call_stream(dict(payload, stream=True), on_token,
                                                "/api/generate", host=host, timeout=60)
            else:
                res = ollama_client.call(dict(payload, stream=False),
                                         "/api/generate", host=host, timeout=60)
            if isinstance(res, dict) and res.get("response"):
                return str(res["response"]).strip()
            err = res.get("error") if isinstance(res, dict) else "no response"
            # Local model down → optionally consult an ONLINE AI. This only does
            # anything if the operator configured a provider key (Settings ▸ API
            # Keys); consult_ai self-gates and returns an error otherwise, so no
            # egress happens by default. Full ARIA context is passed along.
            if getattr(self.config, "aria_cloud_fallback", False):
                try:
                    from angerona.core.privacy import cloud_assistant_prompt
                    from angerona.engines.ai_consult import consult_ai
                    online = consult_ai(cloud_assistant_prompt(
                        question, score=p.get("score", "?"), label=p.get("label", "?")))
                    if isinstance(online, dict) and online.get("text"):
                        return (f"[ARIA · online:{online.get('provider', '?')}]\n"
                                + str(online["text"]).strip())
                except Exception:
                    pass
            # Then a runbook — but ONLY for substantive how-to queries; an
            # irrelevant BM25 match is worse than an honest "AI is offline" note.
            fb = ""
            if self._looks_like_lookup(question):
                try:
                    fb = self._aria_rag.answer(question) if getattr(self, "_aria_rag", None) else ""
                except Exception:
                    fb = ""
            if fb and "No " not in fb[:4]:
                return "Local AI is offline, but here's a relevant runbook:\n\n" + fb
            return (f"Local AI unavailable ({err}). Is Ollama running with the "
                    f"'{model}' model?  (ollama serve · ollama pull {model})  "
                    "Or set an online provider key in Settings ▸ API Keys for a cloud fallback.")
        except Exception as exc:
            return f"(Local AI error: {exc})"

    def _refresh_posture(self) -> None:
        try:
            from angerona.core.posture import posture, posture_tooltip
            p = posture(self.bus, self.manager, self.config)
        except Exception:
            return
        self._last_posture = p
        self.posture_lbl.setText(f"POSTURE {p['score']} · {p['label']}")
        self.posture_lbl.setStyleSheet(
            f"color:{p['color']}; font-weight:800; font-size:11px; letter-spacing:1px;")
        try:
            self.posture_lbl.setToolTip(posture_tooltip(p))
        except Exception:
            pass
        # Feed the ARIA HUD: record the score trend (on change) and repaint.
        try:
            if getattr(self, "aria_hud", None) is not None:
                s = int(p.get("score", 0))
                if getattr(self, "_aria_last_score", None) != s:
                    self.aria_history.record(s, band=str(p.get("label", "")))
                    self._aria_last_score = s
                self.aria_hud.refresh()
                # Proactive: announce a NEW critical posture once (voice + channel).
                # Both are no-ops unless their Settings toggle is on. Re-arms only
                # after posture recovers above the critical threshold.
                active_level = str(
                    (p.get("factors") or {}).get("active_threat_level", "")
                ).casefold()
                if active_level == "critical" and not self._aria_crit_announced:
                    self._aria_crit_announced = True
                    msg = f"Angerona posture critical — score {s} ({p.get('label', '')})."
                    v, pu = getattr(self, "aria_voice", None), getattr(self, "aria_push", None)
                    if v is not None or pu is not None:
                        # TTS runAndWait and the urllib POST both block — never on
                        # the Qt thread. Fire-and-forget on a daemon thread.
                        def _announce(_v=v, _pu=pu, _m=msg):
                            for _fn in ((lambda: _v.speak(_m)) if _v else None,
                                        (lambda: _pu.push(_m, level="CRITICAL")) if _pu else None):
                                if _fn is None:
                                    continue
                                try:
                                    _fn()
                                except Exception:
                                    pass
                        threading.Thread(target=_announce, name="AriaAnnounce",
                                         daemon=True).start()
                elif active_level != "critical":
                    self._aria_crit_announced = False
        except Exception:
            pass

    def _show_posture_detail(self) -> None:
        p = getattr(self, "_last_posture", None)
        if not p:
            return
        f = p.get("factors", {})
        QMessageBox.information(
            self, "Threat Posture",
            f"Threat Posture: {p['score']}/100 — {p['label']}\n\n"
            f"Contributing factors (each lowers the score):\n"
            f"  • Active threats (last 10 min): {f.get('active_threats', 0)}\n"
            f"  • Degraded / stopped modules: {f.get('degraded_modules', 0)}\n"
            f"  • Host-applicable KEV CVEs: {f.get('kev_exposure', 0)}\n"
            f"  • Recent ATT&CK heat: {f.get('attack_heat', 0)}\n\n"
            "100 = fully secure & healthy. Open Threat Intel, Modules, and the "
            "ATT&CK map to drill into each factor.")

    def _open_top_talkers(self) -> None:
        try:
            from angerona.gui.top_talkers import TopTalkersDialog
            self._top_talkers = TopTalkersDialog(self)
            self._top_talkers.show()
        except Exception as exc:
            QMessageBox.warning(self, "Top Talkers", f"Could not open Top Talkers: {exc}")

    # ── Module window (opened from a bottom status chip) ─────────────────────
    def _open_module_window(self, name: str) -> None:
        mod = self.manager.modules.get(name)
        if mod is None:
            return
        try:
            from angerona.gui.pages import _show_nonmodal

            source = self.sender()
            if not isinstance(source, QWidget):
                source = self.status_strip

            def _show():
                return _show_nonmodal(
                    ModuleInspector(self.manager, self.bus, mod, self)
                )

            self._reveal_window_from(source, _show, "#22c55e")
        except Exception as exc:
            QMessageBox.warning(self, "Module", f"Could not open module window: {exc}")

    # ── Live-Fire Sandbox & Editor ───────────────────────────────────────────
    def _set_threat_override(self, text: str) -> None:
        """Sandbox uses this to flip the brand banner into DIAGNOSTIC OVERRIDE and
        back. Empty string restores the normal brand text."""
        try:
            self.brand.setText(text or "ANGERONA")
        except Exception:
            pass

    def _open_sandbox(self) -> None:
        try:
            self._sandbox = launch_sandbox_editor(
                self.manager, self.bus, self._set_threat_override, self)
        except Exception as exc:
            QMessageBox.warning(self, "Sandbox", f"Could not open the sandbox: {exc}")

    def _open_upgrade_console(self) -> None:
        try:
            self._upgrade_console = launch_upgrade_console(
                self.manager, self.config, self.bus, self)
        except Exception as exc:
            QMessageBox.warning(self, "Console", f"Could not open the console: {exc}")

    def _show_classic_dashboard(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _show_scan_center(self) -> None:
        self._show_classic_dashboard()
        self._right_tabs.setCurrentWidget(self.scan_center)

    def _open_operations_center(self) -> None:
        """Open the shared, local-only case/hunt/asset operations workspace."""
        try:
            from angerona.core.operations_center import LocalOperationsCenter
            from angerona.gui.operations_center import OperationsCenterDialog

            if self._operations_service is None:
                self._operations_service = LocalOperationsCenter(
                    self.config.data_dir,
                    evidence_store=self.evidence_store,
                    manager=self.manager,
                    config=self.config,
                )
            if self._operations_dialog is None:
                self._operations_dialog = OperationsCenterDialog(
                    self._operations_service,
                    callbacks={
                        "scan": self._show_scan_center,
                        "forensics": self._open_forensics_hub,
                        "simulation": self._open_simulation,
                        "classic": self._show_classic_dashboard,
                    },
                    parent=self,
                )
            self._operations_dialog.setStyleSheet(self._qss())
            self._operations_dialog.show()
            self._operations_dialog.raise_()
            self._operations_dialog.activateWindow()
            return self._operations_dialog
        except Exception as exc:
            try:
                self.console._append(f"[local-soc] failed to open: {exc}")
            except Exception:
                pass
            QMessageBox.warning(
                self, "Flow Dashboard",
                "The Local SOC workspace could not open. The Classic dashboard "
                f"is still available.\n\n{exc}")
            return None

    def _open_help(self) -> None:
        """End-user Help & Info — one tab per topic (ARIA, voice, Signal, Teams,
        trusted apps, testing, troubleshooting, …)."""
        try:
            from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
                                           QTextEdit, QPushButton, QLabel)
            from angerona.gui.help_content import TOPICS
            dlg = QDialog(self)
            dlg.setWindowTitle("Angerona — Help & Info")
            dlg.resize(700, 580)
            lay = QVBoxLayout(dlg)
            lay.addWidget(QLabel("Everything you can set up, test, and troubleshoot. "
                                 "You can also just ask ARIA, or type 'guide <topic>' "
                                 "in the console."))
            tabs = QTabWidget()
            for _key, (title, body) in TOPICS.items():
                view = QTextEdit()
                view.setReadOnly(True)
                view.setPlainText(body)
                tabs.addTab(view, title.split("—")[0].strip()[:20])
            lay.addWidget(tabs)
            brow = QHBoxLayout()
            tour_btn = QPushButton("▶  Take the interactive tour")
            tour_btn.clicked.connect(lambda: (dlg.accept(), self._start_tour()))
            close = QPushButton("Close")
            close.clicked.connect(dlg.close)
            brow.addWidget(tour_btn)
            brow.addStretch()
            brow.addWidget(close)
            lay.addLayout(brow)
            dlg.exec()
        except Exception as exc:
            try:
                QMessageBox.information(self, "Help", f"Help unavailable: {exc}")
            except Exception:
                pass

    def _open_setup(self) -> None:
        """Open the comprehensive, platform-aware end-user setup program."""
        try:
            from angerona.gui.setup_wizard import SetupWizard

            def _trust():
                try:
                    return self.console.backend._trust_running([])
                except Exception:
                    return "Trusted applications could not be updated."
            dlg = SetupWizard(self.config,
                              apply_theme_fn=getattr(self, "_apply_theme", None),
                              trust_running_fn=_trust, parent=self)
            dlg.exec()
        except Exception as exc:
            try:
                QMessageBox.warning(self, "Setup", f"Setup wizard unavailable: {exc}")
            except Exception:
                pass

    def _start_tour(self) -> None:
        """Launch the interactive coach-marks tour of the dashboard."""
        try:
            from angerona.gui.tour import CoachMarks, build_default_steps
            self._tour = CoachMarks(self, build_default_steps(self))
            self._tour.start()
        except Exception as exc:
            try:
                QMessageBox.information(self, "Tour", f"Tour unavailable: {exc}")
            except Exception:
                pass

    def _open_forensics_hub(self) -> None:
        """Forensics hub — each tool in its own highlighted, hover-lit card."""
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QGroupBox, QLabel, QPushButton
        dlg = QDialog(self); dlg.setWindowTitle("Forensics"); dlg.resize(540, 540)
        try:
            dlg.setStyleSheet(self._qss())
        except Exception:
            pass
        lay = QVBoxLayout(dlg)
        title = QLabel("Incident Forensics"); title.setObjectName("PageTitle")
        lay.addWidget(title)
        lay.addWidget(QLabel("Pick a forensic view — each opens in its own window."))

        options = [
            ("🦈  Shark vs Shield — collision view",
             "Per simulated attack technique, see whether a defensive ring caught it and which one. "
             "Double-click a row for detail + a MITRE ATT&CK link.",
             self._open_collision),
            ("💥  Blast radius by PID",
             "Given a process ID, map its provenance/impact tree — parents, children, and what it touched.",
             self._open_blast_prompt),
            ("🌐  Top Talkers — outbound network",
             "Live per-process outbound connections. Double-click a process to Allow / Block / Ask-AI.",
             self._open_top_talkers),
            ("⛓️  Incident Kill-Chain Timeline",
             "Related alerts grouped per process and laid out along the ATT&CK chain "
             "(Recon → … → Impact) — see how far an attack got. Double-click a technique for MITRE.",
             self._open_incident_timeline),
            ("🧪  Live-Fire Sandbox & Editor",
             "Run and inspect code safely, and edit module source with AI help.",
             self._open_sandbox),
            ("🧰  Collect IR Triage Bundle",
             "Create a bounded, redacted diagnostics ZIP after an explicit privacy review. "
             "Credentials, raw identities, paths, addresses and command lines are excluded.",
             self._open_ir_bundle),
        ]

        def _make(cb):
            def _run():
                dlg.accept()
                try:
                    cb()
                except Exception as exc:
                    QMessageBox.warning(self, "Forensics", f"Could not open: {exc}")
            return _run

        for name, desc, cb in options:
            box = QGroupBox(name)
            box.setStyleSheet(
                "QGroupBox{border:1px solid #33507a;border-radius:8px;margin-top:10px;"
                "padding:10px;background:#12233b;font-weight:bold;}"
                "QGroupBox:hover{border-color:#38bdf8;background:#16304f;}"
                "QGroupBox::title{subcontrol-origin:margin;left:10px;padding:0 4px;color:#38bdf8;}")
            bl = QVBoxLayout(box)
            d = QLabel(desc); d.setWordWrap(True)
            d.setStyleSheet("color:#9fb3c8; font-weight:normal;")
            bl.addWidget(d)
            openb = QPushButton("Open")
            openb.clicked.connect(_make(cb))
            bl.addWidget(openb)
            lay.addWidget(box)

        lay.addStretch()
        close = QPushButton("Close"); close.clicked.connect(dlg.close)
        lay.addWidget(close)
        dlg.exec()

    def _open_incident_timeline(self) -> None:
        from angerona.gui.incident_timeline_page import IncidentTimelineDialog
        bus = getattr(self, "bus", None) or getattr(self, "_bus", None)
        IncidentTimelineDialog(bus, self).exec()

    def _open_ir_bundle(self) -> None:
        """Collect a forensic triage ZIP and offer to open its folder."""
        import os
        import subprocess
        from angerona.core.ir_bundle import collect_triage_bundle
        answer = QMessageBox.warning(
            self, "Create privacy-sanitized IR bundle?",
            "Angerona will create a bounded diagnostic ZIP for incident response.\n\n"
            "It excludes credentials, encrypted secret stores, raw usernames, paths, "
            "IP addresses and command lines, but you should still review the manifest "
            "before sharing it.\n\nCreate the bundle now?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        try:
            path = collect_triage_bundle(bus=getattr(self, "bus", None), consent=True)
        except Exception as exc:
            QMessageBox.warning(self, "IR Triage Bundle",
                                f"Could not collect bundle: {exc}")
            return
        box = QMessageBox(self)
        box.setWindowTitle("IR Triage Bundle")
        box.setText(f"Triage bundle collected:\n{path}")
        open_btn = box.addButton("Open Folder", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Close", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is open_btn:
            try:
                if os.name == "nt":
                    explorer = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                            "explorer.exe")
                    subprocess.Popen([explorer, "/select,", str(path)])
                else:
                    subprocess.Popen(["xdg-open", str(path.parent)])
            except Exception:
                pass

    # ── Settings ─────────────────────────────────────────────────────────────
    def _open_settings(self) -> None:
        self._show_settings()

    def _open_voice_settings(self) -> None:
        self._show_settings("ARIA")

    def _show_settings(self, initial_tab: str | None = None) -> None:
        # Wrapped so a construction error surfaces to the user instead of being
        # swallowed by Qt's slot dispatch — which looks exactly like "the Settings
        # button does nothing". The traceback also lands in the console for triage.
        try:
            dlg = SettingsDialog(self.config,
                                 lambda: check_for_updates(self.config.github_repo),
                                 self.apply_theme, self,
                                 initial_tab=initial_tab,
                                 process_baseline=self.process_baseline)
            dlg.setStyleSheet(self._qss())
            if dlg.exec():
                self._apply_voice_settings_live()
                self._apply_dashboard_mode_live()
        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            try:
                self.console._append(f"[settings] failed to open: {exc}\n{tb}")
            except Exception:
                pass
            QMessageBox.critical(
                self, "Settings",
                f"The Settings window failed to open:\n\n{exc}\n\n"
                "The full traceback was written to the console panel.")

    def _apply_dashboard_mode_live(self) -> None:
        """Apply the Settings dashboard choice without requiring a restart."""
        mode = str(getattr(self.config, "dashboard_mode", "classic")).lower()
        if mode == "flow":
            self._open_operations_center()
            return
        dialog = getattr(self, "_operations_dialog", None)
        if dialog is not None:
            dialog.close()
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _apply_voice_settings_live(self) -> None:
        """Apply microphone/voice choices immediately after Settings is saved."""
        enabled = bool(getattr(self.config, "aria_voice_enabled", False))
        hud = getattr(self, "aria_hud", None)
        voice = getattr(self, "aria_voice", None)
        if not enabled:
            self._aria_voice_stop = True
            if voice is not None:
                voice.enabled = False
            meter = getattr(hud, "mic_meter", None) if hud is not None else None
            if meter is not None:
                meter.set_active(False)
            if hud is not None:
                hud.set_microphone_state(False)
            return

        started_now = voice is None
        if started_now:
            self._enable_voice_live()
            voice = getattr(self, "aria_voice", None)
        if voice is not None:
            voice.enabled = True
            voice.allow_cloud_tts = bool(
                getattr(self.config, "aria_voice_cloud_tts", False))
            try:
                voice.set_mic_device(getattr(self.config, "aria_mic_device", "") or None)
            except Exception:
                pass
            self._aria_voice_stop = False
            if not started_now:
                self._ensure_voice_loop()
            self._start_mic_meter()
        if hud is not None:
            hud.set_microphone_state(True, self._voice_loop_in_flight())

    # ── Self-test (off-thread) + fix prompt on failures ──────────────────────
    def _claim_self_test(self) -> bool:
        """Single-flight gate; button invocations occur on the GUI thread."""
        if self._selftest_active.is_set():
            return False
        self._selftest_active.set()
        return True

    def _run_self_test(self) -> bool:
        if not self._claim_self_test():
            self.console._append("[self-test] already running")
            return False
        self.console._append("ARIA# test all")
        self.console._start_busy()
        self.run_spinner.start("Running self-test")
        self._selftest_btn.setEnabled(False)
        try:
            threading.Thread(
                target=self._self_test_worker,
                name="AngeronaSelfTest",
                daemon=True,
            ).start()
        except Exception:
            self._selftest_active.clear()
            self._selftest_btn.setEnabled(True)
            self.console._end_busy()
            raise
        return True

    def _self_test_worker(self) -> None:
        from angerona.core.selftest import SelfTestRunner
        runner = SelfTestRunner(self.manager, self.bus)
        try:
            report = runner.run(
                progress_cb=lambda done, total: self._selftest_progress.emit(done, total))
            failures = list(runner.last_failures)
        except Exception as exc:
            report, failures = f"self-test error: {exc}", []
        self._selftest_done.emit(report, failures)

    def _on_selftest_done(self, report: str, failures) -> None:
        self._selftest_active.clear()
        self._selftest_btn.setEnabled(True)
        self.console._append(report)
        self.console._end_busy()
        # Snap the wheel to a green 100% so the run visibly completes, then fade.
        self.run_spinner.finish("Self-test complete")
        if failures:
            self._prompt_selftest_fix(failures)

    def _prompt_selftest_fix(self, failures) -> None:
        repairable = [
            f for f in failures
            if bool(f.get("repairable", True))
            and f.get("module") in self.manager.modules
        ]
        manual = [f for f in failures if f not in repairable]
        if not repairable:
            lst = "\n".join(
                f"  • {f.get('module')} — {f.get('detail')}" for f in manual
            )
            QMessageBox.information(
                self,
                "Self-test needs operator attention",
                f"Self-test reported {len(manual)} item(s) that cannot be "
                f"repaired by restarting an Angerona module:\n\n{lst}\n\n"
                "No automatic change was made. Review the listed dependency "
                "or configuration, then re-run the self-test.",
            )
            return
        lst = "\n".join(
            f"  • {f.get('module')} — {f.get('detail')}" for f in repairable
        )
        manual_note = ""
        if manual:
            manual_note = (
                f"\n\n{len(manual)} additional item(s) require manual attention "
                "and will not be changed automatically."
            )
        if QMessageBox.question(
                self, "Self-test found issues — fix now?",
                f"Self-test reported {len(repairable)} restartable issue(s):\n\n"
                f"{lst}{manual_note}\n\n"
                "Attempt automatic recovery? Angerona will request a clean restart "
                "of each listed module. Full details were saved to "
                "diagnostics/selftest_failures.json.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self._selftest_active.set()
        self._selftest_btn.setEnabled(False)
        self.run_spinner.start("Restarting modules")
        try:
            threading.Thread(
                target=self._selftest_repair_worker,
                args=(repairable,),
                name="AngeronaSelfTestRepair",
                daemon=True,
            ).start()
        except Exception:
            self._selftest_active.clear()
            self._selftest_btn.setEnabled(True)
            self.run_spinner.finish("Recovery could not start")
            raise

    def _selftest_repair_worker(self, failures) -> None:
        try:
            restarted, errors = self._attempt_selftest_repairs(failures)
        except Exception as exc:
            # Never strand the GUI in its "repair active" state if an
            # unexpected module implementation escapes the per-module guard.
            restarted, errors = [], [f"recovery worker failed safely: {exc}"]
        self._selftest_repair_done.emit(restarted, errors)

    def _on_selftest_repair_done(self, restarted, errors) -> None:
        self._selftest_active.clear()
        self._selftest_btn.setEnabled(True)
        self.run_spinner.finish("Recovery requested")
        self.console._append(
            f"[auto-fix] restart requested for {len(restarted)} module(s): "
            + (", ".join(restarted) if restarted else "none")
            + ". Re-run 'test all' after startup settles to verify recovery.")
        if errors:
            self.console._append(
                "[auto-fix] manual attention required: " + "; ".join(errors)
            )

    def _attempt_selftest_repairs(self, failures) -> tuple[list[str], list[str]]:
        """Sequentially restart audited failures without touching Qt/config."""
        restarted: list[str] = []
        errors: list[str] = []
        for f in failures:
            nm = f.get("module")
            mod = self.manager.modules.get(nm)
            if (
                mod is None
                or not bool(f.get("repairable", True))
            ):
                continue
            try:
                if getattr(mod, "status", "") in {"running", "restarting"}:
                    mod.stop()
                mod.start()
                restarted.append(str(nm))
                waiter = getattr(mod, "wait_for_first_cycle", None)
                if callable(waiter):
                    waiter(timeout=2.0)
            except Exception as exc:
                errors.append(f"{nm}: {exc}")
                continue
        return restarted, errors

    # ── Forensics: dashboard-level entry to the incident views ───────────────
    def _open_collision(self) -> None:
        from angerona.gui.pages import CollisionView
        dlg = CollisionView(self)
        dlg.setStyleSheet(self._qss())
        dlg.exec()

    def _open_blast_prompt(self) -> None:
        from PySide6.QtWidgets import QInputDialog
        from angerona.gui.pages import BlastRadiusDialog
        prov = next((m for m in self.manager.modules.values()
                     if hasattr(m, "ancestry") and hasattr(m, "subtree")), None)
        if prov is None:
            QMessageBox.information(self, "Blast radius",
                                    "Provenance Graph module is not available.")
            return
        pid, ok = QInputDialog.getInt(self, "Blast radius",
                                      "Process ID (PID) to map:", 0, 0)
        if not ok:
            return
        dlg = BlastRadiusDialog(prov, int(pid), self)
        dlg.setStyleSheet(self._qss())
        dlg.exec()

    def _open_worldview(self) -> None:
        # World View is now the live system-architecture flowchart (native Qt).
        # The old host-telemetry panel is still reachable from inside it
        # ("Host telemetry…").
        from angerona.gui.flow_window import FlowWindow
        dlg = FlowWindow(self.bus, self.storage, self.manager, self.config, self)
        dlg.setStyleSheet(self._qss())
        dlg.show()

    def _open_attack_heatmap(self) -> None:
        from angerona.gui.attack_heatmap import AttackHeatmapWindow
        dlg = AttackHeatmapWindow(self)
        dlg.setStyleSheet(self._qss())
        dlg.show()

    # ── Tray ─────────────────────────────────────────────────────────────────
    @staticmethod
    def _fallback_icon() -> QIcon:
        """Only used if assets/icons/angerona.ico is missing from the
        checkout — the original solid-blue placeholder square."""
        pm = QPixmap(64, 64); pm.fill("#2563eb")
        return QIcon(pm)

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(self._app_icon, self)
        self.tray.setToolTip("Angerona — running")
        menu = QMenu()
        show = QAction("Open Angerona", self)
        show.triggered.connect(self._restore_from_background)
        quit_ = QAction("Quit", self); quit_.triggered.connect(self._quit)
        menu.addAction(show); menu.addSeparator(); menu.addAction(quit_)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda r: (
                self._restore_from_background()
                if r == QSystemTrayIcon.Trigger
                else None
            )
        )
        self.tray.show()

    def _restore_from_background(self) -> None:
        controller = getattr(self, "_holographic_orb", None)
        if controller is not None:
            controller.restore_main()
            return
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def showEvent(self, event) -> None:
        # Center the window the first time it is shown. Qt otherwise drops it at a
        # default offset that can hang off a screen edge (esp. multi-monitor).
        # Only centered ONCE — reopening from the tray keeps wherever you moved it.
        super().showEvent(event)
        QTimer.singleShot(0, self._sync_idle_presentation)
        if not getattr(self, "_did_center", False):
            self._did_center = True
            self._center_on_screen()

    def hideEvent(self, event) -> None:  # noqa: N802 (Qt signature)
        super().hideEvent(event)
        QTimer.singleShot(0, self._sync_idle_presentation)

    def changeEvent(self, event) -> None:  # noqa: N802 (Qt signature)
        super().changeEvent(event)
        if event.type() in (QEvent.WindowStateChange, QEvent.ActivationChange):
            QTimer.singleShot(0, self._sync_idle_presentation)

    def _center_on_screen(self) -> None:
        """Center on the monitor under the cursor (falls back to primary), clamped
        fully inside that monitor's work area so the title bar is never off-screen."""
        try:
            from PySide6.QtGui import QCursor, QGuiApplication
            screen = QGuiApplication.screenAt(QCursor.pos()) or QGuiApplication.primaryScreen()
            if screen is None:
                return
            avail = screen.availableGeometry()
            fg = self.frameGeometry()           # includes title bar/borders now that we're shown
            fg.moveCenter(avail.center())
            x = max(avail.left(), min(fg.left(), avail.right() - fg.width()))
            y = max(avail.top(),  min(fg.top(),  avail.bottom() - fg.height()))
            self.move(x, y)
        except Exception:
            pass   # positioning must never break startup

    def closeEvent(self, event) -> None:
        event.ignore()
        controller = getattr(self, "_holographic_orb", None)
        if controller is not None and controller.enabled():
            controller.collapse_window(self)
        else:
            self.hide()
            self.tray.showMessage(
                "Angerona",
                "Still protecting in the background.",
                QSystemTrayIcon.Information,
                2500,
            )

    def _quit(self) -> None:
        """Tray → Quit. Must guarantee the process actually dies and releases
        the single-instance lock (core/singleton.py's loopback socket) —  a
        bare QApplication.quit() only *requests* the Qt event loop stop; if
        anything (a module thread blocked in a native call, the tray icon,
        whatever) keeps the interpreter from winding down afterward, the
        process lingers, the lock socket stays bound, and the NEXT launch
        shows 'Angerona already running' even though the user already quit.
        Always finish with a hard os._exit() so that can't happen."""
        self._terminate()

    def _terminate(self) -> None:
        """Best-effort graceful cleanup, then an unconditional hard exit."""
        try:
            if self._operations_service is not None:
                self._operations_service.close()
                self._operations_service = None
        except Exception:
            pass
        try:
            self.manager.stop_all()
        except Exception:
            pass
        # This path ends with os._exit(), so QApplication.aboutToQuit may not
        # get enough event-loop time to run AngeronaApp.shutdown(). Explicitly
        # release the resident local model here as well; this covers the red
        # STOP button and tray Quit, while kill-all-angerona.bat has its own
        # external fallback for a wedged runner.
        try:
            from angerona.core.ollama_lifecycle import unload_angerona_models
            unload_angerona_models(
                getattr(self.config, "ollama_host", "http://localhost:11434"),
                getattr(self.config, "ollama_model", "llama3"),
            )
        except Exception:
            pass
        try:
            self._holographic_orb.shutdown()
        except Exception:
            pass
        try:
            self.tray.hide()
        except Exception:
            pass
        try:
            from PySide6.QtWidgets import QApplication
            QApplication.instance().quit()
        except Exception:
            pass
        import os
        os._exit(0)  # guarantee this instance dies and releases the lock socket

    def _full_shutdown(self) -> None:
        """Red STOP button: confirm, then HARD-kill EVERY Angerona instance
        (this one plus any stacked copies) and exit. This works where a normal
        PowerShell fails, because the app runs elevated and can terminate its
        sibling elevated processes."""
        from PySide6.QtWidgets import QMessageBox
        reply = QMessageBox.question(
            self, "Stop Angerona — hard kill",
            "This force-stops ALL Angerona instances (including any stacked "
            "copies running in the background) and exits completely.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply != QMessageBox.Yes:
            return

        # Hard-kill sibling Angerona python processes first (we're elevated).
        import os
        me = os.getpid()
        try:
            import psutil
            # Command-line reads are expensive and may retry on protected Windows
            # processes. Query names for the whole process table, then request a
            # command line only for the small set of Python candidates.
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    if "python" not in (p.info.get("name") or "").lower():
                        continue
                    cmd = " ".join(p.cmdline() or []).lower()
                    if ("angerona" in cmd or "local-security-ai" in cmd) and p.pid != me:
                        p.kill()
                except Exception:
                    continue
        except Exception:
            pass

        self._terminate()
