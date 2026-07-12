"""Main window — single-screen dashboard.

Everything is visible at once (mirroring the original Angerona layout):
a header with brand + threat, a row of stat cards, and a split body with the
Modules panel on the left and the Live Alerts feed on the right. Settings open
in a dialog from the header button.
"""
from __future__ import annotations

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
    ClashingSwords, SharkSwimBanner, SharkSwimIndicator, ThreatOverlay)
from angerona.gui.pages import (
    AARDialog, AlertsPanel, CommandConsolePanel, DashboardCards, ModuleInspector,
    ModulesPanel, ResourceStrip, SettingsDialog, SharkMonitorDialog, SoarPanel,
    StatusStrip,
)
from angerona.gui.sandbox_editor import launch_sandbox_editor
from angerona.gui.upgrade_console import launch_upgrade_console
from angerona.gui.theme import build_qss
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
        self.setMinimumSize(640, 420)
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
        sim_btn.setStyleSheet(
            "background:#dc2626; color:white; font-weight:800; border:none;"
            "border-radius:6px; padding:7px 16px;")
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
        settings_btn = QPushButton("⚙  SETTINGS")
        settings_btn.clicked.connect(self._open_settings)
        stop_btn = QPushButton("⏹  STOP")
        stop_btn.setToolTip("Stop all modules and shut Angerona down completely")
        stop_btn.setStyleSheet(
            "background:#ef4444; color:white; font-weight:800; border:none;"
            "border-radius:6px; padding:7px 16px;")
        stop_btn.clicked.connect(self._full_shutdown)
        rl.addStretch(1)
        rl.addWidget(worldview_btn); rl.addWidget(attack_heatmap_btn)
        rl.addWidget(self.threat_intel_btn)
        rl.addWidget(forensics_btn)
        rl.addWidget(console_btn); rl.addWidget(settings_btn); rl.addWidget(stop_btn)

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

        body = QSplitter(Qt.Vertical)
        body.addWidget(top_split)
        body.addWidget(self.console)
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
        self.modules_panel.setMinimumWidth(220)
        self._right_tabs.setMinimumWidth(280)
        self.console.setMinimumHeight(120)
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
        self.startup_eco_requested.connect(self.apply_startup_eco)

        # Cyber Security Academy — Flight Instructor Mode. Instantiation is
        # cheap (just resolves host/model, no network call), so it's created
        # eagerly here rather than lazily, which avoids a check-then-set race
        # if two narration lines land on background threads close together.
        self.flight_instructor = FlightInstructor(self.config)
        self._fi_enabled = False
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
        # thread ever stalls (Not Responding), a background thread dumps all
        # thread stacks to diagnostics/not_responding.log so the blocking call is
        # identifiable. Starts best-effort; never breaks startup.
        try:
            from pathlib import Path as _P
            from angerona.core.uiwatchdog import UiWatchdog
            _diag = _P(__file__).resolve().parents[3] / "diagnostics"
            self._ui_watchdog = UiWatchdog(_diag / "not_responding.log", stall_seconds=5.0)
            self._ui_watchdog.start()
            self._beat_timer = QTimer(self)
            self._beat_timer.timeout.connect(self._ui_watchdog.beat)
            self._beat_timer.start(1000)
        except Exception:
            self._ui_watchdog = None

    # ── Theme ────────────────────────────────────────────────────────────────
    def _qss(self) -> str:
        return build_qss(self.config.theme, self.config.accent or None)

    def apply_theme(self, theme: str | None = None) -> None:
        # SettingsDialog passes the newly-chosen theme here; callers that just
        # want a restyle (no change) pass nothing. Without this optional arg the
        # Settings "Save" handler raised TypeError on any theme change and the
        # dialog neither closed nor applied — the "settings button isn't working".
        if theme:
            self.config.theme = theme
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
                    from angerona.core import flow_metrics
                    flow_metrics.write(self.manager, self.bus, self.config)
                except Exception:
                    pass

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
        # throttle suppresses) so the out-of-band recorder has the full picture.
        for e in crits:
            self._blackbox_feed(f"CRITICAL [{e.module}] {e.message[:300]}")
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
            from pathlib import Path as _P
            d = _P(__file__).resolve().parents[3] / "diagnostics"
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
    _ECO_HEAVY_MODULES = {
        "Process Monitor", "Network Monitor", "Memory Time-Machine",
        "Memory Injection Scanner", "YARA Scanner", "Packet Sniffer",
        "Ransomware Heuristics", "Sysmon Event Bridge", "ETW Core Listener",
        "Upstream Threat Intel Sync", "API Patch / Anti-Blinding Detector",
        "Persistence Sweep", "Network Protocol Deep Decoder", "WLAN Monitor",
        "ARP Watchdog", "AMSI Bridge", "AV Telemetry Bridge",
        "Data Provenance Graph", "Hardware-Rooted Integrity",
    }

    def apply_startup_eco(self) -> None:
        """Called shortly after boot: if the user's saved preference is Eco Mode,
        pause the heavy scanners so the first-run experience is fast + responsive.
        Safe to call once modules have been started by the manager."""
        if getattr(self.config, "eco_mode", True) and not self._eco_on:
            self._enter_eco(startup=True)

    def _enter_eco(self, startup: bool = False) -> None:
        # Pause each running heavy module, remembering which we touched so resume
        # restores exactly that set.
        self._eco_paused = []
        for name in self._ECO_HEAVY_MODULES:
            mod = self.manager.modules.get(name)
            if mod is not None and getattr(mod, "status", "") == "running":
                try:
                    mod.stop()
                    self._eco_paused.append(name)
                except Exception:
                    pass
        self._eco_on = True
        self.eco_btn.setText("🌿  ECO: ON")
        self.eco_btn.setStyleSheet(
            "background:#166534; color:#dcfce7; font-weight:800; border:none;"
            "border-radius:6px; padding:7px 16px;")
        prefix = "[eco] Startup in Eco Mode — " if startup else "[eco] "
        self.console._append(
            f"{prefix}Paused {len(self._eco_paused)} background scanner(s) — "
            "core response path stays live. Tap ECO again to resume.")

    def _toggle_eco_mode(self) -> None:
        if not self._eco_on:
            self._enter_eco(startup=False)
        else:
            # Resume: wake paused modules SEQUENTIALLY on a background thread so
            # ~19 heavy scanners don't all fire their first scan at once (the
            # "memory stampede" that froze the UI). EcoWakeupWorker health-gates
            # each module before starting the next; the GUI stays responsive.
            mods = [self.manager.modules[n] for n in self._eco_paused
                    if n in self.manager.modules]
            self._eco_on = False
            self.eco_btn.setText("🌿  ECO MODE")
            self.eco_btn.setStyleSheet("")
            if not mods:
                self._eco_paused = []
                return
            self.console._append(
                f"[eco] Waking {len(mods)} scanner(s) one-by-one — UI stays live…")
            self._eco_worker = EcoWakeupWorker(mods)
            self._eco_worker.module_waking.connect(
                lambda name: self.console._append(f"[eco]   waking {name}…"))
            self._eco_worker.module_ready.connect(
                lambda name, ok: self.console._append(
                    f"[eco]   {name}: {'online' if ok else 'FAILED to wake'}"))
            self._eco_worker.wakeup_complete.connect(
                lambda ok, failed: self.console._append(
                    f"[eco] Wake-up complete — {ok} online, {failed} failed."))
            self._eco_worker.finished.connect(self._eco_worker.deleteLater)
            self._eco_paused = []
            self._eco_worker.start()

    # ── Shark Attack Engine ──────────────────────────────────────────────────
    # ── Unified Red Team Simulation (Shark + APT scenarios, configurable) ────
    def _open_simulation(self) -> None:
        import os
        from pathlib import Path
        from angerona.gui.pages import RedTeamSimulationDialog
        default_target = str(Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Documents")
        dlg = RedTeamSimulationDialog(self, default_target=default_target,
                                     store_path=self.config.data_dir / "custom_techniques.json")
        dlg.setStyleSheet(self._qss())
        if not dlg.exec():
            return
        cfg = dlg.result_config()
        if not (cfg["run_shark"] or cfg["run_redteam"]):
            QMessageBox.information(self, "Red Team Simulation",
                                    "Pick at least one scenario (Shark and/or APT Red-Team).")
            return
        self._run_simulation(cfg)

    def _run_simulation(self, cfg) -> None:
        if self.shark_engine.is_running or self.red_team_engine.is_running:
            QMessageBox.information(self, "Red Team Simulation", "A drill is already running.")
            return
        import os
        self._shark_prev_armed = os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK")
        self._shark_prev_minsev = os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY")
        os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] = "1"
        # Lower the response threshold for the duration of the drill so SOAR
        # actually remediates the benign MEDIUM/HIGH marker detections (with the
        # self-kill guard this only rolls back the dropped artifacts). Restored
        # to the user's real-world default when the drill finishes.
        os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY"] = "MEDIUM"
        self._sim_ran_shark = bool(cfg.get("run_shark"))
        self._sim_ran_redteam = bool(cfg.get("run_redteam"))
        self.shark_monitor.reset()
        self.shark_monitor.append(
            f"Launching Red Team Simulation — complexity={cfg.get('complexity')}, "
            f"shark={self._sim_ran_shark}, apt={self._sim_ran_redteam}"
            + (", +custom technique" if cfg.get('custom') else "") + "…")
        self.shark_monitor.show(); self.shark_monitor.raise_(); self.shark_monitor.activateWindow()
        self.shark_swim.start(); self.shark_banner.start()
        params = dict(complexity=cfg.get("complexity", 1),
                      target_dir=cfg.get("target_dir") or None,
                      custom=cfg.get("custom") or None)
        if self._sim_ran_redteam:
            self.red_team_engine.start(**params)
        if self._sim_ran_shark:
            self.shark_engine.start(**params)
        self._sim_poll = QTimer(self)
        self._sim_poll.timeout.connect(self._sim_check_done)
        self._sim_poll.start(500)

    def _sim_check_done(self) -> None:
        if self.shark_engine.is_running or self.red_team_engine.is_running:
            return
        self._sim_poll.stop()
        self.shark_swim.stop(); self.shark_banner.stop()
        import os
        for _k, _prev in (("ANGERONA_SOAR_KILL_AND_ROLLBACK", self._shark_prev_armed),
                          ("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY",
                           getattr(self, "_shark_prev_minsev", None))):
            if _prev is None:
                os.environ.pop(_k, None)
            else:
                os.environ[_k] = _prev
        import threading
        if getattr(self, "_sim_ran_redteam", False):
            threading.Thread(target=self._red_team_build_aar, daemon=True).start()
        if getattr(self, "_sim_ran_shark", False):
            threading.Thread(target=self._shark_build_aar, daemon=True).start()

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
        text = generate_aar(self.config.data_dir, settle_seconds=45,
                             history_name="redteam_history.json",
                             stage_category=REDTEAM_STAGE_CATEGORY,
                             title="RED TEAM ATTACK", report_basename="redteam_aar")
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
        """Runs on its own background thread (spawned per narration line) so
        a slow/offline Ollama call never delays the drill's own pacing —
        _on_shark_narration is called synchronously by the engine between
        stages. Emits back onto the GUI thread via the existing signal, so
        this reuses the exact same append() path as the raw narration."""
        try:
            coaching = self.flight_instructor.narrate_event(raw_line)
        except Exception as exc:
            coaching = f"\U0001F393 (Flight Instructor error) {exc}"
        if coaching:
            self._fi_coaching.emit(coaching)   # → right (Flight Instructor) pane

    def _on_shark_narration(self, msg: str) -> None:
        """Called from the engine's background thread — never touch widgets
        here directly, only emit the signal that queues onto the GUI thread."""
        self._shark_narration.emit(msg)
        if self._fi_enabled:
            import threading
            threading.Thread(target=self._fi_narrate_async, args=(msg,), daemon=True).start()

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
        text = generate_aar(self.config.data_dir, settle_seconds=45)
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

        def _attempt_fix() -> str:
            if pm is None:
                return "[Attempt Fix] Posture Hardening module not available."
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

        dlg = AARDialog(self.config.data_dir, self,
                        on_attempt_fix=_attempt_fix, on_apply=_apply)
        dlg.setStyleSheet(self._qss())
        dlg.set_text(text)
        dlg.exec()

    # ── Threat Posture indicator ─────────────────────────────────────────────
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
             "One click: snapshot processes, connections, users, recent alerts and incidents "
             "into a timestamped ZIP for incident response / after-action review.",
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
        try:
            path = collect_triage_bundle(bus=getattr(self, "bus", None))
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
                    subprocess.Popen(["explorer", "/select,", str(path)])
                else:
                    subprocess.Popen(["xdg-open", str(path.parent)])
            except Exception:
                pass

    # ── Settings ─────────────────────────────────────────────────────────────
    def _open_settings(self) -> None:
        # Wrapped so a construction error surfaces to the user instead of being
        # swallowed by Qt's slot dispatch — which looks exactly like "the Settings
        # button does nothing". The traceback also lands in the console for triage.
        try:
            dlg = SettingsDialog(self.config,
                                 lambda: check_for_updates(self.config.github_repo),
                                 self.apply_theme, self)
            dlg.setStyleSheet(self._qss())
            dlg.exec()
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

    # ── Self-test (off-thread) + fix prompt on failures ──────────────────────
    def _run_self_test(self) -> None:
        self.console._append("UDE# test all")
        self.console._start_busy()
        import threading
        threading.Thread(target=self._self_test_worker, daemon=True).start()

    def _self_test_worker(self) -> None:
        from angerona.core.selftest import SelfTestRunner
        runner = SelfTestRunner(self.manager, self.bus)
        try:
            report = runner.run()
            failures = list(runner.last_failures)
        except Exception as exc:
            report, failures = f"self-test error: {exc}", []
        self._selftest_done.emit(report, failures)

    def _on_selftest_done(self, report: str, failures) -> None:
        self.console._append(report)
        self.console._end_busy()
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
            for p in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    if "python" not in (p.info.get("name") or "").lower():
                        continue
                    cmd = " ".join(p.info.get("cmdline") or []).lower()
                    if ("angerona" in cmd or "local-security-ai" in cmd) and p.pid != me:
                        p.kill()
                except Exception:
                    continue
        except Exception:
            pass

        self._terminate()
