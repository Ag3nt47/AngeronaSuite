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

import os
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFileDialog, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit,
    QPushButton, QSlider, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)

from angerona.core.data_paths import data_dir

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
        self.setMinimumSize(940, 720)
        self.resize(1040, 800)
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
        w = QWidget(); lay = QVBoxLayout(w); lay.setSpacing(10)

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
        self.cb_remediate = QCheckBox("Auto-remediate after the run — SOAR contains the markers and "
                                      "the After-Action Report addresses them")
        self.cb_remediate.setChecked(True)
        ol.addWidget(self.cb_analogy); ol.addWidget(self.cb_remediate)
        lay.addWidget(opt)

        # live kill-chain strip
        lay.addWidget(self._h("Live kill-chain"))
        self._chip_wrap = QWidget(); self._chips: dict[str, QLabel] = {}
        cl = QHBoxLayout(self._chip_wrap); cl.setContentsMargins(0, 0, 0, 0); cl.setSpacing(4)
        for key, label in _STAGES:
            chip = QLabel(label); chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip.setStyleSheet(self._chip_css(False))
            self._chips[key] = chip; cl.addWidget(chip)
        lay.addWidget(self._chip_wrap)

        # live log
        self.log = QTextEdit(); self.log.setReadOnly(True)
        self.log.setStyleSheet("font-family:'Fira Code',monospace; font-size:11px; "
                               "background:#0b1220; border:1px solid #23324a; border-radius:6px;")
        self.log.setMinimumHeight(150)
        lay.addWidget(self.log, 1)

        # actions
        act = QHBoxLayout()
        self.launch_btn = QPushButton("▶  Launch simulation")
        self.launch_btn.setStyleSheet("background:#7f1d1d; color:#fecaca; border:1px solid #b91c1c;"
                                      "border-radius:6px; padding:7px 16px; font-weight:800;")
        self.launch_btn.clicked.connect(self._launch)
        self.stop_btn = QPushButton("■  Stop & clean")
        self.stop_btn.clicked.connect(self._stop)
        act.addStretch(); act.addWidget(self.stop_btn); act.addWidget(self.launch_btn)
        lay.addLayout(act)
        return w

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

    def _build_editor_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(self._h("Sandbox editor — shark/red_team.py"))
        lay.addWidget(QLabel("Adjust techniques, jitter, process spawns, or add your own stage. "
                             "Save is gated by a Python syntax check; Revert restores the on-disk "
                             "version. Changes take effect the next time the app imports the engine."))
        self.editor = QPlainTextEdit()
        self.editor.setStyleSheet("font-family:'Fira Code',monospace; font-size:11px;")
        lay.addWidget(self.editor, 1)
        self._load_editor()
        row = QHBoxLayout()
        save = QPushButton("💾  Save (syntax-checked)"); save.clicked.connect(self._save_editor)
        revert = QPushButton("↩  Revert"); revert.clicked.connect(self._load_editor)
        self.edit_status = QLabel(""); self.edit_status.setStyleSheet("color:#9fb3c8;")
        row.addWidget(save); row.addWidget(revert); row.addWidget(self.edit_status, 1)
        lay.addLayout(row)
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
        except Exception as exc:
            QMessageBox.warning(self, "Launch failed", str(exc))

    def _stop(self) -> None:
        for eng in ("red_team_engine", "shark_engine"):
            try:
                getattr(self._parent, eng).stop_and_clean()
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
