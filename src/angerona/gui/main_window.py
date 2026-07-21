"""Main window — single-screen dashboard.

Everything is visible at once (mirroring the original Angerona layout):
a header with brand + threat, a row of stat cards, and a split body with the
Modules panel on the left and the Live Alerts feed on the right. Settings open
in a dialog from the header button.
"""
from __future__ import annotations

import queue
import threading
import time

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction, QIcon, QPixmap
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QMainWindow, QMenu, QMessageBox, QPushButton, QSplitter,
    QSystemTrayIcon, QTabWidget, QVBoxLayout, QWidget,
)

from angerona.academy.security_academy import FlightInstructor
from angerona.branding import icon_path
from angerona.core.commands import CommandConsole
from angerona.core.eco_wakeup import EcoWakeupWorker
from angerona.core.eventbus import Severity
from angerona.gui.animations import (
    ClashingSwords, RunSpinner, SharkSwimBanner, SharkSwimIndicator, ThreatOverlay)
from angerona.gui.pages import (
    AARDialog, AlertsPanel, CommandConsolePanel, DashboardCards, ModuleInspector,
    ModulesPanel, ResourceStrip, SettingsDialog, SharkMonitorDialog, SoarPanel,
    StatusStrip,
)
from angerona.gui.sandbox_editor import launch_sandbox_editor
from angerona.gui.upgrade_console import launch_upgrade_console
from angerona.gui.theme import build_qss, clamp_scale
from angerona.gui.threat_intel_page import ThreatIntelDashboard
from angerona.shark.shark_attack import SharkAttackEngine
from angerona.shark.red_team import RedTeamEngine, REDTEAM_STAGE_CATEGORY
from angerona.updater.github_updater import check_for_updates

_META_MODULES = {"Self-Test", "Status", "Console"}


class _NoAnim:
    """No-op stand-in for the removed shark/sword animations. Absorbs any
    start()/stop()/set_active()/setGeometry()/etc. call so existing call sites
    keep working while nothing renders."""
    def __getattr__(self, _name):
        return lambda *a, **k: None


class MainWindow(QMainWindow):
    # Emitted from background threads; Qt signals are the safe way to hand
    # control back to the GUI thread to touch widgets.
    _aar_ready = Signal(str)
    _shark_narration = Signal(str)
    _selftest_done = Signal(str, object)   # report text, failures list
    _selftest_progress = Signal(int, int)  # (done, total) → live progress wheel
    _mic_level = Signal(float)             # live mic input level (0..1) → HUD meter
    _voice_live_requested = Signal()       # bring voice up live (GUI thread) after install
    _fi_coaching = Signal(str)             # Flight Instructor line → right pane
    startup_eco_requested = Signal()       # emitted from the loader thread once modules are up

    def __init__(self, bus, storage, manager, config) -> None:
        super().__init__()
        self.bus, self.storage, self.manager, self.config = bus, storage, manager, config

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
        test_btn = QPushButton("▶  RUN SELF-TEST")
        test_btn.clicked.connect(self._run_self_test)
        # Unified Red Team Simulation — the Shark Attack and APT Red-Team drills
        # are now scenarios inside one configurable simulation (difficulty,
        # target, custom benign technique), launched from this single button.
        sim_btn = QPushButton("RUN RED TEAM SIMULATION")
        sim_btn.setToolTip(
            "Configure and run an unannounced, non-destructive adversary simulation "
            "(Shark and/or APT Red-Team scenarios) with a difficulty level, a target, "
            "and an optional custom benign technique — tests detect + respond end to end.")
        # Styled via QSS object name (#Danger) so it scales with the UI-scale
        # factor instead of being frozen at fixed inline pixels.
        sim_btn.setObjectName("Danger")
        sim_btn.clicked.connect(self._open_simulation)
        # Eco Mode — one tap to shed heavy background scan load. Pauses the
        # expensive pollers/scanners (process/mem/yara/net enumeration) while
        # leaving the safety-critical response path (SOAR, deception, watchdog,
        # heartbeat, IPC guard, AI triage) fully live. Instant relief when the
        # host feels bogged down; tap again to resume full monitoring.
        self._eco_on = False
        self._eco_paused: list[str] = []
        self.eco_btn = QPushButton("🌿  ECO MODE")
        self.eco_btn.setToolTip(
            "Pause the heavy background scanners to free up the machine. The core "
            "response path (SOAR, deception, watchdog, heartbeat) stays active. "
            "Tap again to resume full monitoring.")
        self.eco_btn.clicked.connect(self._toggle_eco_mode)
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
        worldview_btn = QPushButton("🌐  WORLD VIEW")
        worldview_btn.setToolTip("Deep-transparency host telemetry: suite-vs-host resources, "
                                 "blinding detector, and live Ollama diagnostics")
        worldview_btn.clicked.connect(self._open_worldview)
        attack_heatmap_btn = QPushButton("🔥  ATT&CK MAP")
        attack_heatmap_btn.setToolTip(
            "Live MITRE ATT&CK heatmap — 86 techniques across 14 tactics, "
            "coloured by time-decaying hit frequency")
        attack_heatmap_btn.clicked.connect(self._open_attack_heatmap)
        # Threat Intel button — pulses red/amber when INTL has host-applicable
        # KEV CVEs waiting for operator review.  Style toggles in _refresh().
        self.threat_intel_btn = QPushButton("🛡  THREAT INTEL")
        self.threat_intel_btn.setToolTip(
            "CISA Known Exploited Vulnerabilities correlated against this host.\n"
            "Pulses when host-applicable CVEs are waiting for operator review.")
        self.threat_intel_btn.clicked.connect(self._open_threat_intel)
        self._threat_intel_dlg: ThreatIntelDashboard | None = None
        self._intl_alert_pulse = False   # toggled each tick when alert is pending
        forensics_btn = QPushButton("🎯  FORENSICS")
        forensics_btn.setToolTip("Incident forensics: Shark-vs-Shield ring collision view "
                                 "and per-PID blast-radius provenance tree")
        forensics_btn.clicked.connect(self._open_forensics_hub)
        console_btn = QPushButton("🧰  CONSOLE")
        console_btn.clicked.connect(self._open_upgrade_console)
        setup_btn = QPushButton("🚀  SETUP")
        setup_btn.setToolTip("One-swoop setup: AI, voice, Signal, Teams, trusted apps, startup")
        setup_btn.clicked.connect(self._open_setup)
        self._help_btn = QPushButton("❔  HELP")
        self._help_btn.setToolTip("How to set up, test, and troubleshoot Angerona, ARIA, "
                                  "voice, Signal and Teams — plus an interactive tour")
        self._help_btn.clicked.connect(self._open_help)
        settings_btn = QPushButton("⚙  SETTINGS")
        settings_btn.clicked.connect(self._open_settings)
        stop_btn = QPushButton("⏹  STOP")
        stop_btn.setToolTip("Stop all modules and shut Angerona down completely")
        # Styled via QSS object name (#Critical) so it scales with the UI.
        stop_btn.setObjectName("Critical")
        stop_btn.clicked.connect(self._full_shutdown)
        rl.addStretch(1)
        rl.addWidget(worldview_btn); rl.addWidget(attack_heatmap_btn)
        rl.addWidget(self.threat_intel_btn)
        rl.addWidget(forensics_btn)
        rl.addWidget(console_btn); rl.addWidget(setup_btn); rl.addWidget(self._help_btn)
        rl.addWidget(settings_btn); rl.addWidget(stop_btn)

        # Keep references so the guided tour can highlight each control by name.
        self._selftest_btn = test_btn
        self._sim_btn = sim_btn
        self._worldview_btn = worldview_btn
        self._attack_btn = attack_heatmap_btn
        self._forensics_btn = forensics_btn
        self._console_btn = console_btn
        self._setup_btn = setup_btn
        self._settings_btn = settings_btn
        self._stop_btn = stop_btn

        header.addWidget(left, 1)
        header.addWidget(brand_box, 1)
        header.addWidget(right, 1)
        root.addLayout(header)

        # ── Stat cards ───────────────────────────────────────────────────────
        self.cards = DashboardCards(bus, storage, manager)
        root.addWidget(self.cards)

        # ── Body: (Modules | Live Alerts) over Console ───────────────────────
        self.modules_panel = ModulesPanel(manager, bus)
        self.alerts_panel = AlertsPanel(storage)
        # Right side is now tabbed: Live Alerts + the persistent SOAR Queue.
        self.soar_panel = SoarPanel(bus, manager)
        self._right_tabs = QTabWidget()
        self._right_tabs.addTab(self.alerts_panel, "Live Alerts")
        self._right_tabs.addTab(self.soar_panel, "SOAR Queue")
        top_split = QSplitter(Qt.Horizontal)
        top_split.addWidget(self.modules_panel)
        top_split.addWidget(self._right_tabs)
        top_split.setStretchFactor(0, 4)
        top_split.setStretchFactor(1, 6)
        top_split.setSizes([460, 700])

        self.console = CommandConsolePanel(CommandConsole(manager, bus, config))

        # ── ARIA (v1.8.0): HUD tab + local assistant. Fully guarded so any
        # ARIA import/build failure just skips it without touching the rest.
        self._wire_aria()

        # Bottom section = ARIA. The compact orb HUD (built in _wire_aria) sits to
        # the LEFT of the Console prompt bar; the Console is the single place you
        # type to ARIA (streaming) or run IR commands. If ARIA is disabled/failed
        # to build, the Console fills the space alone.
        if getattr(self, "aria_hud", None) is not None:
            self._console_section = QSplitter(Qt.Horizontal)
            # Lowered from 150 so the ARIA orb column can be squeezed right down
            # beside the prompt; raised the ceiling a little for wide displays.
            self.aria_hud.setMinimumWidth(88)
            self.aria_hud.setMaximumWidth(420)
            self._console_section.addWidget(self.aria_hud)
            self._console_section.addWidget(self.console)
            self._console_section.setStretchFactor(0, 2)
            self._console_section.setStretchFactor(1, 8)
            self._console_section.setSizes([230, 900])
            self._console_section.setOpaqueResize(False)
            self._console_section.setChildrenCollapsible(False)
            self._console_section.setHandleWidth(7)
            bottom = self._console_section
        else:
            bottom = self.console

        body = QSplitter(Qt.Vertical)
        body.addWidget(top_split)
        body.addWidget(bottom)
        body.setStretchFactor(0, 3)
        body.setStretchFactor(1, 2)
        body.setSizes([500, 240])
        root.addWidget(body, 1)

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

        # Shark-sweep overlay and full-width swimming-shark banner removed per
        # user request — stubbed so existing start()/stop() calls are harmless.
        self.threat_overlay = _NoAnim()
        self._last_threat_ts = time.time()
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
        self._mic_level.connect(self._on_mic_level)
        self._voice_live_requested.connect(self._enable_voice_live)
        self.startup_eco_requested.connect(self.apply_startup_eco)

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

        # ── Two-tier refresh: fast strip (1 s) + full panels (2 s) ──────────
        # Splitting the timer lets the status strip and threat check stay snappy
        # (1 s) while the heavier panels (alerts table, module table, stat cards)
        # refresh at a calmer 2 s cadence — halving the number of DB reads and
        # widget updates per second vs the old single 1.5 s timer.
        self._tick_count = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._refresh)
        self.timer.start(1000)
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

    def resizeEvent(self, event) -> None:  # noqa: N802 (Qt signature)
        try:
            self._maybe_rescale_ui()
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

    def _refresh_body(self) -> None:
        full = (self._tick_count % 2 == 0)   # full refresh every other tick (2 s)

        # StatusStrip and threat check: every tick (1 s) — cheap with change-detection
        self.status_strip.refresh()
        self.red_swords.set_active(self.shark_engine.is_running or self.red_team_engine.is_running)
        self._check_threat_animation()

        # Resource strip + posture are heavier (walk recent bus events / compute a
        # composite) — run them every 4th tick (~4 s), not every tick, so they
        # don't add steady overhead. This keeps the UI light even in Eco mode.
        if self._tick_count % 4 == 0:
            try:
                self.resource_strip.refresh()
            except Exception:
                pass
            self._refresh_posture()

        if full:
            # Heavier panels: every 2 s — each guarded so one bad panel can't
            # skip the others (or blow up the whole tick).
            for _fn in (self.cards.refresh, self.modules_panel.refresh,
                        self.alerts_panel.refresh, self.soar_panel.refresh):
                try:
                    _fn()
                except Exception:
                    pass
            # Flow-canvas JSON feed only needs ~4 s (the in-app flow window reads
            # metrics live in-process; this file is just for the external canvas).
            if self._tick_count % 4 == 0:
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
        # Fire the shark/attack animation on a NEW genuine threat (HIGH+).
        events = self.bus.recent(20)
        if not events:
            return
        new_threats = [
            e for e in events
            if e.ts > self._last_threat_ts and e.severity >= Severity.HIGH
            and e.module not in _META_MODULES
        ]
        self._last_threat_ts = max(self._last_threat_ts, max(e.ts for e in events))
        # Red-flash + emoji shark-sweep overlay removed per user request — the
        # full-width swimming SharkSwimBanner across the top now signals a drill,
        # and it doesn't strobe the whole screen red (which also cost repaints).
        # Push a tray/toast notification on NEW CRITICAL detections so the operator
        # keeps situational awareness even when the window is minimized. Throttled.
        crits = [e for e in new_threats if e.severity >= Severity.CRITICAL]
        if crits:
            self._notify_critical(crits)
        # Pulse the THREAT INTEL button when INTL has pending KEV alerts.
        self._update_threat_intel_pulse()

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

    # ── Eco Mode (shed heavy background scan load) ───────────────────────────
    # Heavy pollers/scanners that dominate idle CPU but are NOT part of the
    # safety-critical response path — safe to pause for instant relief.
    _ECO_HEAVY_MODULES = (
        "Process Monitor", "Network Monitor", "Memory Time-Machine",
        "Memory Injection Scanner", "YARA Scanner", "Packet Sniffer",
        "Ransomware Heuristics",
        "Upstream Threat Intel Sync", "API Patch / Anti-Blinding Detector",
        "Persistence Sweep", "WLAN Monitor", "ARP Watchdog",
        "Data Provenance Graph", "Hardware-Rooted Integrity",
    )

    def apply_startup_eco(self) -> None:
        """Called shortly after boot: if the user's saved preference is Eco Mode,
        pause the heavy scanners so the first-run experience is fast + responsive.
        Safe to call once modules have been started by the manager."""
        if getattr(self.config, "eco_mode", True) and not self._eco_on:
            self._enter_eco(startup=True)

    def _enter_eco(self, startup: bool = False) -> None:
        # Pause each running heavy module, remembering which we touched so resume
        # restores exactly that set.
        # If a sequential wake is still in flight, cancel it first. The worker's
        # control lock guarantees it cannot start another module after cancel()
        # returns, so ECO: ON cannot race with a late scanner wake-up.
        worker = getattr(self, "_eco_worker", None)
        if worker is not None:
            try:
                if worker.isRunning():
                    worker.cancel()
            except (RuntimeError, AttributeError):
                pass
        self._eco_paused = []
        for name in self._ECO_HEAVY_MODULES:
            mod = self.manager.modules.get(name)
            if mod is not None and getattr(mod, "status", "") == "running":
                try:
                    mod.stop()
                    self._eco_paused.append(name)
                except Exception:
                    pass
            elif startup and mod is not None:
                # Startup Eco defers these modules before they create a worker
                # thread. Remember enabled ones so ECO OFF can wake them later.
                try:
                    if self.manager.is_enabled(name):
                        self._eco_paused.append(name)
                except Exception:
                    pass
        self._eco_on = True
        self.eco_btn.setText("🌿  ECO: ON")
        self.eco_btn.setStyleSheet(
            "background:#166534; color:#dcfce7; font-weight:800; border:none;"
            "border-radius:6px; padding:7px 16px;")
        prefix = "[eco] Startup in Eco Mode — " if startup else "[eco] "
        verb = "Deferred" if startup else "Paused"
        self.console._append(
            f"{prefix}{verb} {len(self._eco_paused)} background scanner(s) — "
            "core response path stays live. Tap ECO again to resume.")

    def _toggle_eco_mode(self) -> None:
        if not self._eco_on:
            self._enter_eco(startup=False)
        else:
            # Resume: wake paused modules SEQUENTIALLY on a background thread so
            # heavy scanners don't all fire their first scan at once (the
            # "memory stampede" that froze the UI). EcoWakeupWorker waits for a
            # real work-cycle boundary before starting the next module.
            mods = [self.manager.modules[n] for n in self._eco_paused
                    if n in self.manager.modules]
            self._eco_on = False
            self.eco_btn.setText("🌿  ECO MODE")
            self.eco_btn.setStyleSheet("")
            if not mods:
                self._eco_paused = []
                return
            total = len(mods)
            self.console._append(
                f"[eco] Waking {total} scanner(s) one at a time — each finishes a "
                "full work cycle before the next begins, so the machine stays smooth.")
            # Live wake-up progress on the header wheel (red → amber → green).
            self._eco_wake_total = total
            self._eco_wake_done = 0
            self.run_spinner.start("Waking scanners")
            self._eco_worker = EcoWakeupWorker(mods)
            self._eco_worker.module_waking.connect(
                lambda name: self.console._append(f"[eco]   waking {name}…"))
            self._eco_worker.module_ready.connect(self._on_eco_module_ready)
            self._eco_worker.module_cycle_timeout.connect(
                lambda name: self.console._append(
                    f"[eco]   {name}: still finishing its first cycle — leaving it running."))
            self._eco_worker.wakeup_complete.connect(self._on_eco_wakeup_complete)
            self._eco_worker.finished.connect(self._eco_worker.deleteLater)
            self._eco_paused = []
            self._eco_worker.start()

    def _on_eco_module_ready(self, name: str, ok: bool) -> None:
        self._eco_wake_done += 1
        self.run_spinner.set_progress(self._eco_wake_done, getattr(self, "_eco_wake_total", 1))
        self.console._append(
            f"[eco]   {name}: {'back online' if ok else 'could not wake'}")

    def _on_eco_wakeup_complete(self, ok: int, failed: int) -> None:
        self.run_spinner.finish("Scanners online")
        self.console._append(f"[eco] Wake-up complete — {ok} online, {failed} failed.")

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

    def _run_simulation(self, cfg) -> None:
        if self.shark_engine.is_running or self.red_team_engine.is_running:
            QMessageBox.information(self, "Red Team Simulation", "A drill is already running.")
            return
        import os
        self._shark_prev_armed = os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK")
        self._shark_prev_minsev = os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY")
        # Auto-remediation (ON by default): arm SOAR's kill+rollback tier and lower
        # the response threshold for the drill so it actually contains the benign
        # MEDIUM/HIGH marker detections (the self-kill guard means this only rolls
        # back the dropped artifacts). Restored to the user's default when done.
        self._sim_auto_remediate = bool(cfg.get("auto_remediate", True))
        if self._sim_auto_remediate:
            os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] = "1"
            os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY"] = "MEDIUM"
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
        if self._sim_ran_redteam:
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
                     getattr(self, "_shark_prev_minsev", None))):
                if previous is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = previous
            try:
                from angerona.modules.file_integrity import unregister_runtime_watch
                unregister_runtime_watch(getattr(self, "_sim_runtime_watch", None))
            except Exception:
                pass
            self._sim_runtime_watch = None

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
        import threading
        threading.Thread(target=self._red_team_build_aar, daemon=True).start()

    def _red_team_build_aar(self) -> None:
        from angerona.shark.aar_report import generate_aar
        try:
            text = generate_aar(self.config.data_dir, settle_seconds=45,
                                 history_name="redteam_history.json",
                                 stage_category=REDTEAM_STAGE_CATEGORY,
                                 title="RED TEAM ATTACK", report_basename="redteam_aar")
        finally:
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

        def _attempt_fix() -> str:
            if pm is None:
                return "[Attempt Fix] Posture Hardening module not available."
            if is_redteam:
                cleaned = _clean_markers()
                result = pm.resolve_redteam_report(report_path)
                if not result.get("ok"):
                    return f"[Drill resolution] {result.get('error', 'failed')}"
                count = int(result.get("candidates", 0))
                unsupported = result.get("unsupported") or []
                extra = (f" {len(unsupported)} unsupported technique(s) still need a detector."
                         if unsupported else "")
                return (f"[Purple remediation] Installed {count} reviewed detector "
                        f"candidate(s) for run {result.get('run_id') or 'unknown'} and cleaned "
                        f"{cleaned} inert marker/file(s). The findings remain open until a fresh "
                        f"drill proves marker → detector → recorder → SOAR end to end.{extra} "
                        "Run the simulation again to certify the fixes.")
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
                        on_clean=_clean_markers, redteam=is_redteam)
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
            self.aria_hud.microphone_requested.connect(self._open_voice_settings)
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
                    import threading as _th
                    _th.Thread(target=self._aria_voice_loop, name="AriaVoice",
                               daemon=True).start()
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
        if getattr(self, "_voice_loop_alive", False):
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
            self._aria_voice_stop = False
            import threading as _th
            _th.Thread(target=self._aria_voice_loop, name="AriaVoice", daemon=True).start()
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
            evs = [e for e in self.bus.recent(200) if e.severity >= Severity.HIGH]
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
                if s < 50 and not self._aria_crit_announced:
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
                elif s >= 50:
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
            _show_nonmodal(ModuleInspector(self.manager, self.bus, mod, self))
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
            close.clicked.connect(dlg.accept)
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
        """One-swoop Setup Wizard — steps through AI, voice, Signal, Teams, trusted
        apps and startup with Next/Skip, saving config at the end."""
        try:
            from angerona.gui.setup_wizard import SetupWizard

            def _trust():
                try:
                    self.console.backend._trust_running([])
                except Exception:
                    pass
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
        close = QPushButton("Close"); close.clicked.connect(dlg.accept)
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
                                 self.apply_theme, self, initial_tab=initial_tab)
            dlg.setStyleSheet(self._qss())
            if dlg.exec():
                self._apply_voice_settings_live()
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
            if not started_now and not getattr(self, "_voice_loop_alive", False):
                threading.Thread(target=self._aria_voice_loop, name="AriaVoice",
                                 daemon=True).start()
            self._start_mic_meter()
        if hud is not None:
            hud.set_microphone_state(True, bool(getattr(self, "_voice_loop_alive", False)))

    # ── Self-test (off-thread) + fix prompt on failures ──────────────────────
    def _run_self_test(self) -> None:
        self.console._append("ARIA# test all")
        self.console._start_busy()
        self.run_spinner.start("Running self-test")
        import threading
        threading.Thread(target=self._self_test_worker, daemon=True).start()

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
        self.console._append(report)
        self.console._end_busy()
        # Snap the wheel to a green 100% so the run visibly completes, then fade.
        self.run_spinner.finish("Self-test complete")
        if failures:
            self._prompt_selftest_fix(failures)

    def _prompt_selftest_fix(self, failures) -> None:
        lst = "\n".join(f"  • {f.get('module')} — {f.get('detail')}" for f in failures)
        if QMessageBox.question(
                self, "Self-test found issues — fix now?",
                f"Self-test reported {len(failures)} issue(s):\n\n{lst}\n\n"
                "Attempt automatic fixes? Angerona will enable and (re)start each "
                "affected module. Full details were saved to "
                "diagnostics/selftest_failures.json.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes) != QMessageBox.Yes:
            return
        fixed = []
        for f in failures:
            nm = f.get("module")
            if nm in self.manager.modules:
                try:
                    self.manager.set_enabled(nm, True)
                    fixed.append(nm)
                except Exception:
                    pass
        self.console._append(
            f"[auto-fix] (re)started {len(fixed)} module(s): "
            + (", ".join(fixed) if fixed else "none")
            + ". Re-run 'test all' to confirm.")

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
        show = QAction("Open Angerona", self); show.triggered.connect(self.showNormal)
        quit_ = QAction("Quit", self); quit_.triggered.connect(self._quit)
        menu.addAction(show); menu.addSeparator(); menu.addAction(quit_)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda r: self.showNormal() if r == QSystemTrayIcon.Trigger else None)
        self.tray.show()

    def showEvent(self, event) -> None:
        # Center the window the first time it is shown. Qt otherwise drops it at a
        # default offset that can hang off a screen edge (esp. multi-monitor).
        # Only centered ONCE — reopening from the tray keeps wherever you moved it.
        super().showEvent(event)
        if not getattr(self, "_did_center", False):
            self._did_center = True
            self._center_on_screen()

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
        self.hide()
        self.tray.showMessage("Angerona", "Still protecting in the background.",
                              QSystemTrayIcon.Information, 2500)

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
