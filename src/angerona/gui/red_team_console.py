"""red_team_console.py — modern Red Team Simulation console.

Replaces the old RedTeamSimulationDialog with a single, better-looking, better-
flowing window that combines configuration, a live ATT&CK kill-chain view, a
narration log, and an embedded sandbox editor for the red-team engine itself.

Highlights:
  • Intensity slider (Low → Extreme) that scales phases, jitter, noise, threat
    level and process bursts in one move.
  • Campaign mode — chain techniques in kill-chain order instead of shuffling.
  • Prominent marker-location picker (presets + Browse).
  • Analogy coaching (Flight Instructor) ON by default; auto-remediate ON by default.
  • Live kill-chain strip that lights each stage as the drill narrates it.
  • Embedded editor tab to view/adjust shark/red_team.py behind an AST syntax gate,
    with Save + Revert.

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
    QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from angerona.core.data_paths import data_dir
from angerona.gui.animations import RunSpinner

# Canonical kill-chain stages → (match-substring in narration, short chip label)
_STAGES = [
    ("Initial Access", "Initial Access"), ("Discovery", "Discovery"),
    ("Credential Access", "Cred Access"), ("Privilege Escalation", "Priv Esc"),
    ("Defense Evasion", "Defense Evasion"), ("Registry Run Key", "Run Key"),
    ("Scheduled Task", "Sched Task"), ("WMI Persistence", "WMI Persist"),
    ("Lateral Movement", "Lateral"), ("Command & Control", "C2"),
    ("Exfil Staging", "Exfil"), ("Ransomware", "Ransomware"),
    ("Data Destruction", "Wiper"), ("Benign Execution", "Processes"),
]
_INTENSITY = ["Low", "Medium", "High", "Extreme"]
_INTENSITY_DESC = {
    "Low": "1 phase · gentle timing · minimal noise — a quiet probe.",
    "Medium": "2 phases · moderate timing/noise — a realistic intrusion.",
    "High": "3 phases · fast, noisier, more process bursts — a busy operation.",
    "Extreme": "4 phases · rapid, high-noise, heavy process bursts — stress test.",
}


def _red_team_path() -> Path:
    # …/gui/red_team_console.py → …/shark/red_team.py
    return Path(__file__).resolve().parent.parent / "shark" / "red_team.py"


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
        root.addWidget(self._tabs, 1)

        # subscribe to live narration + analogy coaching from the parent (the
        # legacy Live Offense Monitor is gone, so both flow into this console).
        for sig_name in ("_shark_narration", "_fi_coaching"):
            try:
                getattr(parent, sig_name).connect(self._on_narration)
            except Exception:
                pass

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
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        body = QWidget()
        body.setMinimumWidth(650)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(4, 4, 8, 4)
        lay.setSpacing(10)

        # attack types
        types = QFrame(); types.setObjectName("Card")
        tl = QVBoxLayout(types)
        tl.addWidget(self._h("Attack profile"))
        self.cb_shark = QCheckBox("Shark — noisy commodity-malware chain (lure → discovery → "
                                  "persistence → exfil markers)")
        self.cb_apt = QCheckBox("APT Red-Team — quiet credential-access / fileless-persistence "
                                "campaign (distinct scenario)")
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
        self.cb_campaign = QCheckBox("Campaign mode — chain techniques in kill-chain order "
                                     "(recon → access → persist → C2 → exfil → impact)")
        self.cb_campaign.setChecked(True)
        il.addWidget(self.cb_campaign)
        lay.addWidget(inten)
        self._on_intensity(1)

        # marker location picker
        loc = QFrame(); loc.setObjectName("Card"); ll = QVBoxLayout(loc)
        ll.addWidget(self._h("Marker discovery location"))
        ll.addWidget(QLabel("Where the benign marker files are written (a File-Integrity-Monitor-"
                            "watched folder makes detections fire faster)."))
        prow = QHBoxLayout()
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
        prow.addWidget(self.loc_preset); prow.addWidget(self.loc_edit, 1); prow.addWidget(browse)
        ll.addLayout(prow)
        lay.addWidget(loc)

        # custom technique + toggles
        opt = QFrame(); opt.setObjectName("Card"); ol = QVBoxLayout(opt)
        ol.addWidget(self._h("Options"))
        self.custom_name = QLineEdit(); self.custom_name.setPlaceholderText(
            "Optional custom technique name (e.g. 'my-detection-test')")
        self.custom_payload = QLineEdit(); self.custom_payload.setPlaceholderText(
            "Optional custom marker text — written verbatim to an INERT file, NEVER executed")
        ol.addWidget(self.custom_name); ol.addWidget(self.custom_payload)
        self.cb_analogy = QCheckBox("Analogy coaching (Flight Instructor) — explain each step in "
                                    "plain English while it runs")
        self.cb_analogy.setChecked(True)
        self.cb_remediate = QCheckBox(
            "Auto-contain detected markers during the run — missed detector gaps use "
            "Apply Practice Fix → Test → signed verification afterward"
        )
        self.cb_remediate.setChecked(True)
        ol.addWidget(self.cb_analogy); ol.addWidget(self.cb_remediate)
        lay.addWidget(opt)

        # live kill-chain strip
        lay.addWidget(self._h("Live kill-chain"))
        self._chip_wrap = QWidget(); self._chips: dict[str, QLabel] = {}
        cl = QGridLayout(self._chip_wrap)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setHorizontalSpacing(4)
        cl.setVerticalSpacing(4)
        for index, (key, label) in enumerate(_STAGES):
            chip = QLabel(label); chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            chip.setStyleSheet(self._chip_css(False))
            self._chips[key] = chip
            cl.addWidget(chip, index // 7, index % 7)
        lay.addWidget(self._chip_wrap)

        # live log
        self.log = QTextEdit(); self.log.setReadOnly(True)
        self.log.document().setMaximumBlockCount(4000)
        self.log.setStyleSheet("font-family:'Fira Code',monospace; font-size:11px; "
                               "background:#0b1220; border:1px solid #23324a; border-radius:6px;")
        self.log.setMinimumHeight(150)
        lay.addWidget(self.log, 1)

        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

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
        return w

    def finish_run(self) -> None:
        """Called by the parent when both engines have finished — completes the wheel."""
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
        lay.addWidget(self._h("Sandbox editor — shark/red_team.py"))
        lay.addWidget(QLabel("Adjust techniques, jitter, process spawns, or add your own stage. "
                             "Save is gated by a Python syntax check; Revert restores the on-disk "
                             "version. Changes take effect the next time the app imports the engine."))
        self.editor = QPlainTextEdit()
        self.editor.setStyleSheet("font-family:'Fira Code',monospace; font-size:11px;")
        lay.addWidget(self.editor, 1)
        row = QHBoxLayout()
        save = QPushButton("💾  Save (syntax-checked)"); save.clicked.connect(self._save_editor)
        revert = QPushButton("↩  Revert"); revert.clicked.connect(self._load_editor)
        self.edit_status = QLabel(""); self.edit_status.setStyleSheet("color:#9fb3c8;")
        row.addWidget(save); row.addWidget(revert); row.addWidget(self.edit_status, 1)
        lay.addLayout(row)
        # Load AFTER edit_status exists — _load_editor() writes to it, so calling
        # it earlier raised 'RedTeamConsole has no attribute edit_status'.
        self._load_editor()
        return w

    # ── helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _h(text: str) -> QLabel:
        lbl = QLabel(text); lbl.setStyleSheet("font-weight:700; color:#dbeafe;")
        return lbl

    @staticmethod
    def _chip_css(active: bool) -> str:
        if active:
            return ("background:#7f1d1d; color:#fee2e2; border:1px solid #ef4444;"
                    "border-radius:10px; padding:3px 8px; font-size:10px; font-weight:700;")
        return ("background:#111c2e; color:#64748b; border:1px solid #23324a;"
                "border-radius:10px; padding:3px 8px; font-size:10px;")

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
        self.log.append(text)
        for key, chip in self._chips.items():
            if key.lower() in text.lower():
                chip.setStyleSheet(self._chip_css(True))

    def _reset_chips(self) -> None:
        for chip in self._chips.values():
            chip.setStyleSheet(self._chip_css(False))

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
            "analogy": self.cb_analogy.isChecked(),
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
        self.log.append("■ Stop requested — engines cleaning up their markers.")

    # ── editor ───────────────────────────────────────────────────────────────
    def _load_editor(self) -> None:
        try:
            self.editor.setPlainText(_red_team_path().read_text(encoding="utf-8"))
            self.edit_status.setText(f"Loaded {_red_team_path().name}")
        except Exception as exc:
            self.editor.setPlainText(f"# could not load red_team.py: {exc}")

    def _save_editor(self) -> None:
        src = self.editor.toPlainText()
        try:
            compile(src, str(_red_team_path()), "exec")   # AST/syntax gate
        except SyntaxError as exc:
            QMessageBox.warning(self, "Syntax error — not saved",
                                f"Line {exc.lineno}: {exc.msg}")
            self.edit_status.setText(f"❌ syntax error line {exc.lineno} — not saved")
            return
        try:
            _red_team_path().write_text(src, encoding="utf-8")
            self.edit_status.setText("✅ saved — restart or re-import to take effect")
        except Exception as exc:
            QMessageBox.warning(self, "Save failed", str(exc))
