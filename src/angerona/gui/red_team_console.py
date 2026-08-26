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

import json
import os
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFrame,
    QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QSlider,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout,
    QWidget,
)

from angerona.core.data_paths import data_dir
from angerona.core.source_sandbox import SourceSandboxWorkspace
from angerona.gui.animations import RunSpinner

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
_STAGE_LABELS = {key: label for key, label, _aliases in _STAGES}
_INTENSITY = ["Low", "Medium", "High", "Extreme"]
_INTENSITY_DESC = {
    "Low": "1 phase · gentle timing · minimal noise — a quiet probe.",
    "Medium": "2 phases · moderate timing/noise — a realistic intrusion.",
    "High": "3 phases · fast, noisier, more process bursts — a busy operation.",
    "Extreme": "4 phases · rapid, high-noise, heavy process bursts — stress test.",
}


_RED_TEAM_SOURCE = "src/angerona/shark/red_team.py"


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

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_run_tab(default_target), "▶  Run")
        self._tabs.addTab(self._build_history_tab(), "🕑  History")
        self._tabs.addTab(self._build_device_lab_tab(), "🛰  Device Security Lab")
        self._tabs.addTab(self._build_editor_tab(), "🧪  Sandbox Editor")
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
        self.cb_apt.setChecked(True)
        tl.addWidget(self.cb_shark); tl.addWidget(self.cb_apt)
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
            "Missed detector gaps can use Apply Practice Fix → Test → signed verification."
        )
        ol.addWidget(self.cb_remediate)
        remediation_help = QLabel(
            "Missed detector gaps can use Apply Practice Fix → Test → signed "
            "verification after the run."
        )
        remediation_help.setWordWrap(True)
        remediation_help.setStyleSheet("color:#9fb3c8; margin-left:24px;")
        ol.addWidget(remediation_help)
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
        self.live_status.setWordWrap(True)
        self.live_status.setStyleSheet("color:#9fb3c8; font-size:11px;")
        live_lay.addWidget(self.live_status)
        self._chip_wrap = QWidget(); self._chips: dict[str, QLabel] = {}
        self._active_stage: str | None = None
        cl = QGridLayout(self._chip_wrap)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setHorizontalSpacing(6)
        cl.setVerticalSpacing(6)
        for column in range(4):
            cl.setColumnStretch(column, 1)
        for index, (key, label, _aliases) in enumerate(_STAGES):
            chip = QLabel(label); chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip.setMinimumHeight(30)
            chip.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            chip.setToolTip(label)
            self._chips[key] = chip
            self._set_chip_state(key, "idle")
            cl.addWidget(chip, index // 4, index % 4)
        live_lay.addWidget(self._chip_wrap)

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
        # Live progress wheel — colours from red → amber → green as the drill runs.
        self.run_spinner = RunSpinner()
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

    def finish_run(self) -> None:
        """Called by the parent when both engines have finished — completes the wheel."""
        if self._active_stage is not None:
            self._set_chip_state(self._active_stage, "complete")
            self._active_stage = None
        self.live_status.setText("Simulation complete — all received stages are shown in green.")
        try:
            self.run_spinner.finish("Simulation complete")
        except Exception:
            pass

    # ── History tab ──────────────────────────────────────────────────────────
    def _build_history_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(self._h("Past After-Action Reports"))
        lay.addWidget(QLabel("Previous drill reports, newest first — click one to view it."))
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
        self._hist_list.clear()
        try:
            files = sorted(self._history_dir().glob("*_aar_*.txt"),
                           key=lambda p: p.stat().st_mtime, reverse=True)
        except Exception:
            files = []
        if not files:
            it = QListWidgetItem("(no past reports yet — run a simulation)")
            it.setData(Qt.ItemDataRole.UserRole, None)
            self._hist_list.addItem(it)
            self._hist_view.setPlainText("")
            return
        for p in files:
            kind = "RED TEAM" if "redteam" in p.name.lower() else "SHARK"
            try:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime))
            except Exception:
                ts = "?"
            it = QListWidgetItem(f"{kind}  ·  {ts}")
            it.setData(Qt.ItemDataRole.UserRole, str(p))
            self._hist_list.addItem(it)
        self._hist_list.setCurrentRow(0)

    def _on_hist_select(self, cur, _prev) -> None:
        if cur is None:
            return
        path = cur.data(Qt.ItemDataRole.UserRole)
        if not path:
            self._hist_view.setPlainText("")
            return
        try:
            self._hist_view.setPlainText(Path(path).read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            self._hist_view.setPlainText(f"Could not read report: {exc}")

    def _on_tab_changed(self, idx: int) -> None:
        try:
            if "History" in self._tabs.tabText(idx):
                self._load_history()
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
                self.device_findings.setItem(row, column, QTableWidgetItem(text))
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
        # Load AFTER edit_status exists — _load_editor() writes to it, so calling
        # it earlier raised 'RedTeamConsole has no attribute edit_status'.
        try:
            self._editor_workspace = SourceSandboxWorkspace(
                "red-team-console", (_RED_TEAM_SOURCE,)
            )
            self._load_editor()
        except Exception as exc:
            self.editor.setPlainText(
                f"# sandbox editor unavailable in this session: {exc}"
            )
            self.editor.setReadOnly(True)
            for button in (
                self._editor_save,
                self._editor_reload,
                self._editor_rollback,
            ):
                button.setEnabled(False)
                button.setToolTip(
                    "The protected working-copy directory is unavailable. "
                    "Simulation controls are unaffected."
                )
            self.edit_status.setText(
                "❌ sandbox unavailable; simulation controls remain usable"
            )
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
        for key, _label, aliases in _STAGES:
            if any(alias in lowered for alias in aliases):
                return key
        return None

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

    def _on_narration(self, text: str) -> None:
        message = str(text)
        self.log.append(message)
        stage = self._stage_from_narration(message)
        if stage is None:
            return
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
            self._parent._run_simulation(cfg)
            # Estimated-duration wheel: scales with intensity (phases) and whether
            # both profiles run. finish_run() snaps it to green when the drill ends.
            phases = self.sld.value() + 1
            est = 14 + phases * 9 + (12 if (self.cb_shark.isChecked() and self.cb_apt.isChecked()) else 0)
            self.run_spinner.begin_estimated(est, "Simulation running")
        except Exception as exc:
            QMessageBox.warning(self, "Launch failed", str(exc))

    def _stop(self) -> None:
        for eng in ("red_team_engine", "shark_engine"):
            try:
                getattr(self._parent, eng).stop_and_clean()
            except Exception:
                pass
        try:
            self.run_spinner.stop()
        except Exception:
            pass
        self.live_status.setText("Stop requested — cleaning simulation markers…")
        self.log.append("■ Stop requested — engines cleaning up their markers.")

    # ── editor ───────────────────────────────────────────────────────────────
    def _load_editor(self) -> None:
        if self._editor_workspace is None:
            self.edit_status.setText(
                "❌ sandbox unavailable; simulation controls remain usable"
            )
            return
        try:
            source = self._editor_workspace.reload(_RED_TEAM_SOURCE)
            self.editor.setPlainText(source)
            suffix = " (modified)" if self._editor_workspace.changed(
                _RED_TEAM_SOURCE
            ) else ""
            self.edit_status.setText(f"Loaded isolated working copy{suffix}")
        except Exception as exc:
            self.editor.setPlainText(f"# could not load sandbox working copy: {exc}")
            self.edit_status.setText("❌ sandbox working copy unavailable")

    def _reload_editor(self) -> None:
        """Discard unsaved buffer text and reload the saved sandbox copy."""
        self._load_editor()

    def _save_editor(self) -> None:
        if self._editor_workspace is None:
            self.edit_status.setText("❌ sandbox working copy unavailable")
            return
        src = self.editor.toPlainText()
        try:
            self._editor_workspace.save(_RED_TEAM_SOURCE, src)
        except SyntaxError as exc:
            QMessageBox.warning(self, "Syntax error — not saved",
                                f"Line {exc.lineno}: {exc.msg}")
            self.edit_status.setText(f"❌ syntax error line {exc.lineno} — not saved")
            return
        except Exception as exc:
            QMessageBox.warning(self, "Save failed", str(exc))
            self.edit_status.setText("❌ working copy was not saved")
            return
        self.edit_status.setText("✅ isolated working copy saved (live engine unchanged)")

    def _rollback_editor(self) -> None:
        """Restore only the runtime working copy from immutable installed source."""
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
        try:
            self._editor_workspace.rollback((_RED_TEAM_SOURCE,))
            self._load_editor()
            self.edit_status.setText("✅ working copy rolled back; live engine unchanged")
        except Exception as exc:
            QMessageBox.warning(self, "Rollback failed", str(exc))
            self.edit_status.setText("❌ working copy rollback failed")
