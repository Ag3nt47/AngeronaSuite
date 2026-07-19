"""threat_intel_page.py — Threat Intelligence Dashboard (G4-B).

Displays the CISA Known Exploited Vulnerabilities (KEV) matches that the
INTL module writes to ``shared_logs/upstream_threats.json``.

Analyst controls (v1.7.1):
  - **Ignore / Revert** per CVE: some CVEs are too vague to action or have no
    fix. Ignoring flags the ID (kept in memory with a full per-ID history) and
    removes it from the THREAT LEVEL — so Angerona stops reporting HIGH/CRITICAL
    over things you can't fix. A Revert button undoes it any time. (core/cve_ignore.py)
  - **AI fix analysis** (local llama3): compares each CVE to this host's system
    info; if a specific scriptable fix exists it shows ❗ "Potential fix
    available" with an Apply (confirm-then-execute) button and a Revert-change
    button after implementation. If none, offers Flag & Ignore. (core/cve_fix_advisor.py)
  - **Mass Flag & Ignore**: analyze everything and bulk-ignore the CVEs with no
    available fix in one click.

Remediation is REVIEW-GATED — Apply always shows the exact commands and requires
explicit confirmation before running; a revert script is captured automatically.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QTimer, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QDialog, QFrame, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QPushButton, QSizePolicy, QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget,
)
from angerona.gui.cve_analysis_window import CveAnalysisWindow

# ── tunables ──────────────────────────────────────────────────────────────────
_AUTO_REFRESH_MS = 60_000   # re-read upstream_threats.json every 60 s
_MAX_REMEDIATION_CELL = 120 # truncate remediation text in the table cell


def _repo_root() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


def _threats_path() -> Path:
    return _repo_root() / "shared_logs" / "upstream_threats.json"


def _load_threats() -> dict:
    p = _threats_path()
    if not p.exists():
        return {"matches": [], "generated": "", "match_count": 0}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"matches": [], "generated": "parse error", "match_count": 0}


class _FixWorker(QThread):
    """Runs local-AI fix analysis over a list of (cve, rec) off the GUI thread."""
    result = Signal(str, dict)     # cve, analysis
    done = Signal(int, int)        # analyzed, fixes_found

    def __init__(self, items: list, parent=None) -> None:
        super().__init__(parent)
        self._items = items

    def run(self) -> None:
        from angerona.core import cve_fix_advisor
        fixes = 0
        for cve, rec in self._items:
            if self.isInterruptionRequested():
                break
            try:
                analysis = cve_fix_advisor.analyze(rec)
            except Exception as exc:
                analysis = {"cve": cve, "fix_available": False,
                            "reason": f"analysis error: {exc}"}
            if analysis.get("fix_available"):
                fixes += 1
            self.result.emit(cve, analysis)
        self.done.emit(len(self._items), fixes)


class ThreatIntelDashboard(QDialog):
    """Non-modal dialog showing CISA KEV matches for this host."""

    _C_CVE, _C_VENDOR, _C_PROD, _C_MITRE, _C_RANS, _C_DUE, _C_REM, _C_FIX, _C_ACT = range(9)
    _HEADERS = [
        "CVE ID", "Vendor", "Product", "MITRE", "Ransomware",
        "Due Date", "Required Remediation", "Fix", "Action",
    ]

    def __init__(self, parent: Optional[QWidget] = None, intl_module=None) -> None:
        super().__init__(parent)
        self._intl = intl_module
        self._cve_analysis_dlg: CveAnalysisWindow | None = None
        self._staged: list = []
        self._fix_cache: dict[str, dict] = {}    # cve → analysis result
        self._worker: _FixWorker | None = None
        self.setWindowTitle("🛡  Threat Intelligence — CISA KEV Matches")
        self.setMinimumSize(1040, 560)
        self.resize(1240, 660)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(10)

        # ── Header bar ───────────────────────────────────────────────────
        hdr = QHBoxLayout()
        title = QLabel("🛡  CISA Known Exploited Vulnerabilities — Host Correlation")
        title.setObjectName("SectionTitle")
        title.setStyleSheet("font-size:15px; font-weight:800;")
        hdr.addWidget(title, 1)

        self._ts_label = QLabel("Last sync: —")
        self._ts_label.setStyleSheet("color:#94a3b8; font-size:11px;")
        hdr.addWidget(self._ts_label)

        analyze_btn = QPushButton("🔎  Analyze Fixes (AI)")
        analyze_btn.setToolTip("Ask the LOCAL model (llama3) whether each host-applicable CVE "
                               "has a specific scriptable fix. Rows with a fix show ❗.")
        analyze_btn.setStyleSheet(
            "background:#134e2e; color:#6ee7b7; border:1px solid #10b981;"
            "border-radius:6px; padding:5px 12px; font-weight:700;")
        analyze_btn.clicked.connect(self._analyze_all)
        hdr.addWidget(analyze_btn)

        mass_btn = QPushButton("🚫  Mass Flag & Ignore")
        mass_btn.setToolTip("Analyze all applicable CVEs and bulk-ignore the ones with NO available "
                            "fix, so they stop affecting the threat level. Reversible per CVE.")
        mass_btn.setStyleSheet(
            "background:#4a1d1d; color:#fca5a5; border:1px solid #b91c1c;"
            "border-radius:6px; padding:5px 12px; font-weight:700;")
        mass_btn.clicked.connect(self._mass_flag_ignore)
        hdr.addWidget(mass_btn)

        deep_btn = QPushButton("🔍  Deep Analysis")
        deep_btn.setToolTip("CVE Deep Analysis window — cards + AI remediation plan (local Ollama).")
        deep_btn.setStyleSheet(
            "background:#4c1d95; color:#c4b5fd; border:1px solid #7c3aed;"
            "border-radius:6px; padding:5px 12px; font-weight:700;")
        deep_btn.clicked.connect(self._open_deep_analysis)
        hdr.addWidget(deep_btn)

        consult_btn = QPushButton("🌐  Consult AI")
        consult_btn.setToolTip("Reach an ONLINE AI (cloud) for a comprehensive fix — on demand only.")
        consult_btn.setStyleSheet(
            "background:#1e3a5f; color:#7dd3fc; border:1px solid #2563eb;"
            "border-radius:6px; padding:5px 12px; font-weight:700;")
        consult_btn.clicked.connect(self._open_consult_ai)
        hdr.addWidget(consult_btn)

        refresh_btn = QPushButton("↺  Refresh")
        refresh_btn.clicked.connect(self._load_and_render)
        hdr.addWidget(refresh_btn)

        staged_btn = QPushButton("📋  Staged")
        staged_btn.setToolTip("View items staged/confirmed for remediation review.")
        staged_btn.clicked.connect(self._show_staged)
        hdr.addWidget(staged_btn)
        lay.addLayout(hdr)

        # ── Info bar ─────────────────────────────────────────────────────
        self._info = QLabel(
            "⚠  Only inbound CISA data is used — no host data leaves the machine. "
            "Ignored CVEs stay listed but are removed from the threat level. Apply is "
            "confirm-then-execute with an auto-captured Revert."
        )
        self._info.setWordWrap(True)
        self._info.setStyleSheet(
            "background:#1e293b; color:#94a3b8; border:1px solid #334155;"
            "border-radius:6px; padding:6px 10px; font-size:11px;")
        lay.addWidget(self._info)

        # ── Table ────────────────────────────────────────────────────────
        self._table = QTableWidget()
        self._table.setObjectName("Panel")
        self._table.setColumnCount(len(self._HEADERS))
        self._table.setHorizontalHeaderLabels(self._HEADERS)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(
            self._C_REM, QHeaderView.ResizeMode.Stretch)
        for col in (self._C_CVE, self._C_VENDOR, self._C_PROD, self._C_MITRE,
                    self._C_RANS, self._C_DUE, self._C_FIX, self._C_ACT):
            self._table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setStyleSheet(
            "QTableWidget { font-size:12px; }"
            "QTableWidget::item { padding: 5px 8px; }")
        lay.addWidget(self._table, 1)
        self._table.cellDoubleClicked.connect(self._on_row_double)

        # ── Footer stats ─────────────────────────────────────────────────
        self._footer = QLabel("No KEV data loaded.")
        self._footer.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(self._footer)

        self._timer = QTimer(self)
        self._timer.setInterval(_AUTO_REFRESH_MS)
        self._timer.timeout.connect(self._load_and_render)
        self._timer.start()

        self._load_and_render()

    # ── Data loading & rendering ─────────────────────────────────────────
    def _load_and_render(self) -> None:
        from angerona.core import cve_ignore
        data = _load_threats()
        matches = data.get("matches", [])
        generated = data.get("generated", "")
        self._row_recs: dict = {}
        self._matches = matches
        ignore_data = cve_ignore.load()

        self._ts_label.setText(f"Last sync: {generated or '—'}")

        rans_hits = sum(1 for m in matches
                        if str(m.get("ransomware", "")).strip().lower() == "known")

        self._table.setUpdatesEnabled(False)
        self._table.setRowCount(len(matches))

        for row, rec in enumerate(matches):
            cve = rec.get("cve") or "—"
            ignored = cve_ignore.is_ignored(cve, ignore_data)
            self._row_recs[row] = (cve, rec)

            def _item(text, color=None, dim=False):
                it = QTableWidgetItem(str(text or "—"))
                it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                if dim:
                    it.setForeground(QColor("#64748b"))
                elif color:
                    it.setForeground(QColor(color))
                return it

            rans = str(rec.get("ransomware") or "—")
            rem  = str(rec.get("remediation") or "—")
            due  = str(rec.get("due_date") or "—")
            rans_color = "#ef4444" if rans.strip().lower() == "known" else None

            self._table.setItem(row, self._C_CVE,    _item(cve, "#38bdf8", ignored))
            self._table.setItem(row, self._C_VENDOR, _item(rec.get("vendor") or "", dim=ignored))
            self._table.setItem(row, self._C_PROD,   _item(rec.get("product") or "", dim=ignored))
            self._table.setItem(row, self._C_MITRE,  _item(rec.get("mitre") or "", dim=ignored))
            self._table.setItem(row, self._C_RANS,   _item(rans, rans_color, ignored))
            self._table.setItem(row, self._C_DUE,    _item(due, _due_color(due), ignored))
            self._table.setItem(row, self._C_REM,
                                _item(rem[:_MAX_REMEDIATION_CELL]
                                      + ("…" if len(rem) > _MAX_REMEDIATION_CELL else ""),
                                      dim=ignored))
            self._set_fix_cell(row, cve, rec, ignored)
            self._set_action_cell(row, cve, rec, ignored)

        self._table.setUpdatesEnabled(True)

        active, ignored_n = cve_ignore.counts(matches)
        if len(matches) == 0:
            self._footer.setText("✅  No host-applicable KEV CVEs found.")
            self._footer.setStyleSheet("color:#22c55e; font-size:11px;")
        elif active == 0:
            self._footer.setText(
                f"✅  {len(matches)} applicable CVE(s), all {ignored_n} IGNORED — "
                "none are affecting the threat level.")
            self._footer.setStyleSheet("color:#22c55e; font-size:11px;")
        else:
            rans_note = f"  |  {rans_hits} ransomware-linked" if rans_hits else ""
            ign_note = f"  |  {ignored_n} ignored (excluded from threat level)" if ignored_n else ""
            self._footer.setText(
                f"⚠  {active} active CVE(s) affecting threat level{ign_note}{rans_note}. "
                "Double-click a row for detail, AI fix, ignore/revert & history.")
            self._footer.setStyleSheet("color:#f59e0b; font-size:11px;")

    def _set_fix_cell(self, row: int, cve: str, rec: dict, ignored: bool) -> None:
        """Fix column: ❗ clickable Apply when a fix exists, else status text."""
        from angerona.core import cve_fix_advisor
        applied = cve_fix_advisor.applied_state(cve)
        analysis = self._fix_cache.get(cve)
        if applied and applied.get("applied") and not applied.get("reverted"):
            btn = self._mini_btn("↩ Revert fix", "#7c2d12", "#fdba74",
                                  lambda: self._revert_fix(cve))
            self._table.setCellWidget(row, self._C_FIX, self._wrap(btn)); return
        if ignored:
            self._table.removeCellWidget(row, self._C_FIX)
            it = QTableWidgetItem("🚫 ignored"); it.setForeground(QColor("#64748b"))
            it.setFlags(Qt.ItemFlag.ItemIsEnabled); self._table.setItem(row, self._C_FIX, it); return
        if analysis is None:
            self._table.removeCellWidget(row, self._C_FIX)
            it = QTableWidgetItem("—"); it.setForeground(QColor("#64748b"))
            it.setFlags(Qt.ItemFlag.ItemIsEnabled); self._table.setItem(row, self._C_FIX, it); return
        if analysis.get("fix_available"):
            btn = self._mini_btn("❗ Apply fix", "#14532d", "#86efac",
                                  lambda: self._apply_fix(cve, analysis))
            self._table.setCellWidget(row, self._C_FIX, self._wrap(btn))
        else:
            self._table.removeCellWidget(row, self._C_FIX)
            it = QTableWidgetItem("no fix"); it.setForeground(QColor("#94a3b8"))
            it.setFlags(Qt.ItemFlag.ItemIsEnabled); self._table.setItem(row, self._C_FIX, it)

    def _set_action_cell(self, row: int, cve: str, rec: dict, ignored: bool) -> None:
        detail = self._mini_btn("Detail", "#1e3a5f", "#38bdf8",
                                lambda: self._stage_review(cve, rec))
        if ignored:
            toggle = self._mini_btn("Revert ignore", "#334155", "#e2e8f0",
                                    lambda: self._toggle_ignore(cve, False))
        else:
            toggle = self._mini_btn("Ignore", "#3f3f46", "#d4d4d8",
                                    lambda: self._toggle_ignore(cve, True))
        cell = QWidget(); cl = QHBoxLayout(cell)
        cl.setContentsMargins(4, 1, 4, 1); cl.setSpacing(4)
        cl.addWidget(detail); cl.addWidget(toggle)
        self._table.setCellWidget(row, self._C_ACT, cell)

    @staticmethod
    def _mini_btn(text, bg, fg, slot) -> QPushButton:
        b = QPushButton(text); b.setFixedHeight(26)
        b.setStyleSheet(f"background:{bg}; color:{fg}; border:1px solid {fg}55;"
                        "border-radius:4px; font-size:11px; padding:0 8px;")
        b.clicked.connect(slot); return b

    @staticmethod
    def _wrap(w) -> QWidget:
        cell = QWidget(); l = QHBoxLayout(cell)
        l.setContentsMargins(4, 1, 4, 1); l.addWidget(w); return cell

    # ── Ignore / Revert / History ────────────────────────────────────────
    def _toggle_ignore(self, cve: str, ignore_it: bool) -> None:
        from angerona.core import cve_ignore
        if ignore_it:
            reason = "operator ignore (too vague / no fix / accepted risk)"
            cve_ignore.ignore(cve, reason)
        else:
            cve_ignore.revert(cve, "operator reverted ignore")
        self._load_and_render()

    def _show_history(self, cve: str) -> None:
        from angerona.core import cve_ignore
        hist = cve_ignore.history(cve)
        dlg = QDialog(self); dlg.setWindowTitle(f"Ignore history — {cve}"); dlg.resize(560, 360)
        v = QVBoxLayout(dlg)
        v.addWidget(QLabel(f"<b>{cve}</b> — flag/ignore audit trail "
                           f"(currently {'IGNORED' if cve_ignore.is_ignored(cve) else 'active'}):"))
        txt = QTextEdit(); txt.setReadOnly(True)
        if hist:
            txt.setPlainText("\n".join(
                f"[{h.get('iso','')}]  {h.get('action','').upper():7}  {h.get('reason','')}"
                for h in hist))
        else:
            txt.setPlainText("No ignore/revert history for this CVE yet.")
        v.addWidget(txt)
        b = QPushButton("Close"); b.clicked.connect(dlg.accept); v.addWidget(b)
        dlg.exec()

    # ── AI fix analysis (single + batch) ─────────────────────────────────
    def _analyze_all(self) -> None:
        from angerona.core import cve_fix_advisor, cve_ignore
        if not cve_fix_advisor.ollama_available():
            QMessageBox.information(
                self, "Local AI unavailable",
                "The local model (Ollama) isn't reachable, so per-CVE fix analysis can't run.\n\n"
                "Start Ollama (ollama serve) and pick a model, or use '🌐 Consult AI' for an "
                "online analysis on demand.")
            return
        active = [(m.get("cve"), m) for m in getattr(self, "_matches", [])
                  if m.get("cve") and not cve_ignore.is_ignored(m.get("cve"))]
        if not active:
            QMessageBox.information(self, "Nothing to analyze",
                                    "There are no active (non-ignored) CVEs to analyze.")
            return
        if self._worker and self._worker.isRunning():
            QMessageBox.information(self, "Busy", "Fix analysis is already running.")
            return
        self._footer.setText(f"🔎  Analyzing {len(active)} CVE(s) with local AI…")
        self._worker = _FixWorker(active, self)
        self._worker.result.connect(self._on_fix_result)
        self._worker.done.connect(self._on_fix_done)
        self._worker.start()

    def _on_fix_result(self, cve: str, analysis: dict) -> None:
        self._fix_cache[cve] = analysis
        # refresh just the affected row's Fix cell
        for row, (c, rec) in getattr(self, "_row_recs", {}).items():
            if c == cve:
                self._set_fix_cell(row, cve, rec, False)
                break

    def _on_fix_done(self, analyzed: int, fixes: int) -> None:
        self._footer.setText(
            f"✅  AI analysis complete: {analyzed} analyzed, {fixes} with a potential fix (❗). "
            "Click ❗ Apply fix, or use Mass Flag & Ignore for the no-fix ones.")
        self._footer.setStyleSheet("color:#22c55e; font-size:11px;")

    def _mass_flag_ignore(self) -> None:
        from angerona.core import cve_fix_advisor, cve_ignore
        active = [(m.get("cve"), m) for m in getattr(self, "_matches", [])
                  if m.get("cve") and not cve_ignore.is_ignored(m.get("cve"))]
        if not active:
            QMessageBox.information(self, "Nothing to ignore",
                                    "There are no active (non-ignored) CVEs.")
            return
        if cve_fix_advisor.ollama_available():
            msg = (f"Analyze all {len(active)} active CVE(s) with local AI and IGNORE the ones "
                   "with NO available fix?\n\nThey'll stay listed (with history) and can be "
                   "reverted, but will stop affecting the threat level.")
        else:
            msg = (f"Local AI is unavailable. Ignore ALL {len(active)} active CVE(s) shown?\n\n"
                   "They'll stay listed (with history) and can be reverted per CVE, but will "
                   "stop affecting the threat level.")
        if QMessageBox.question(self, "Mass Flag & Ignore", msg,
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                                ) != QMessageBox.StandardButton.Yes:
            return
        ignored = 0
        if cve_fix_advisor.ollama_available():
            for cve, rec in active:
                analysis = self._fix_cache.get(cve) or cve_fix_advisor.analyze(rec)
                self._fix_cache[cve] = analysis
                if not analysis.get("fix_available"):
                    cve_ignore.ignore(cve, f"mass-ignore: no fix ({analysis.get('reason','')[:80]})")
                    ignored += 1
        else:
            for cve, _rec in active:
                cve_ignore.ignore(cve, "mass-ignore (AI unavailable)")
                ignored += 1
        self._load_and_render()
        QMessageBox.information(self, "Mass Flag & Ignore",
                                f"Ignored {ignored} CVE(s) with no available fix. "
                                "Revert any of them from its row or the detail dialog.")

    # ── Apply / Revert an AI fix (confirm-then-execute) ──────────────────
    def _apply_fix(self, cve: str, analysis: dict) -> None:
        from angerona.core import cve_fix_advisor
        script = (analysis or {}).get("fix_script", "").strip()
        revert = (analysis or {}).get("revert_script", "").strip()
        if not script:
            QMessageBox.information(self, "No fix", "No fix script is available for this CVE.")
            return
        dlg = QDialog(self); dlg.setWindowTitle(f"Apply fix — {cve}"); dlg.resize(680, 560)
        v = QVBoxLayout(dlg)
        v.addWidget(QLabel(f"<b>❗ Potential fix for {cve}</b>"))
        if analysis.get("summary"):
            s = QLabel(analysis["summary"]); s.setWordWrap(True); v.addWidget(s)
        if analysis.get("instructions"):
            v.addWidget(QLabel("<b>What this does:</b>"))
            ins = QTextEdit(); ins.setReadOnly(True); ins.setPlainText(analysis["instructions"])
            ins.setMaximumHeight(90); v.addWidget(ins)
        v.addWidget(QLabel("<b>Commands that will run (PowerShell):</b>"))
        code = QTextEdit(); code.setReadOnly(True); code.setPlainText(script)
        code.setStyleSheet("font-family:'Fira Code',monospace; font-size:11px;"); v.addWidget(code)
        if revert:
            v.addWidget(QLabel("<b>Auto-captured revert (used by ↩ Revert change):</b>"))
            rc = QTextEdit(); rc.setReadOnly(True); rc.setPlainText(revert)
            rc.setMaximumHeight(80); rc.setStyleSheet("font-family:'Fira Code',monospace; font-size:11px;")
            v.addWidget(rc)
        warn = QLabel("⚠ This runs AI-generated commands on THIS machine. Review them above. "
                      "You can undo with the Revert change button afterward.")
        warn.setWordWrap(True); warn.setStyleSheet("color:#fbbf24;"); v.addWidget(warn)
        row = QHBoxLayout(); row.addStretch()
        run = QPushButton("⚙  Confirm & Run fix")
        run.setStyleSheet("background:#14532d;color:#86efac;border:1px solid #10b981;"
                          "border-radius:5px;padding:5px 12px;font-weight:700;")
        cancel = QPushButton("Cancel")
        row.addWidget(run); row.addWidget(cancel); v.addLayout(row)

        def _run():
            res = cve_fix_advisor.apply_fix(cve, analysis)
            if res.get("ok"):
                QMessageBox.information(self, "Fix applied",
                    f"{cve} fix ran successfully.\n\nOutput:\n{res.get('output','')[:1500] or '(none)'}\n\n"
                    "Use ↩ Revert fix (in the row) to undo.")
            else:
                QMessageBox.warning(self, "Fix failed",
                    f"{cve} fix did not complete cleanly.\n\nOutput:\n{res.get('output','')[:1500]}")
            dlg.accept(); self._load_and_render()
        run.clicked.connect(_run); cancel.clicked.connect(dlg.reject)
        dlg.exec()

    def _revert_fix(self, cve: str) -> None:
        from angerona.core import cve_fix_advisor
        if QMessageBox.question(
                self, "Revert change",
                f"Run the captured revert script to undo the {cve} fix?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                ) != QMessageBox.StandardButton.Yes:
            return
        res = cve_fix_advisor.revert_fix(cve)
        if res.get("ok"):
            QMessageBox.information(self, "Reverted",
                f"{cve} change reverted.\n\nOutput:\n{res.get('output','')[:1200] or '(none)'}")
        else:
            QMessageBox.warning(self, "Revert failed",
                f"Could not revert {cve}.\n\nOutput:\n{res.get('output','')[:1200]}")
        self._load_and_render()

    # ── Row detail dialog (adds Ignore/Revert, History, Analyze fix) ─────
    def _on_row_double(self, row: int, _col: int) -> None:
        entry = getattr(self, "_row_recs", {}).get(row)
        if entry:
            self._stage_review(entry[0], entry[1])

    def _stage_review(self, cve: str, rec: dict) -> None:
        import time as _time
        import webbrowser
        from urllib.parse import quote_plus
        from angerona.core import cve_ignore

        rem    = rec.get("remediation") or "No remediation text available."
        mitre  = rec.get("mitre") or "—"
        rans   = rec.get("ransomware") or "—"
        due    = rec.get("due_date") or "—"
        name   = rec.get("name") or cve
        vendor = rec.get("vendor") or ""
        prod   = rec.get("product") or ""

        dlg = QDialog(self); dlg.setWindowTitle(f"Threat detail — {cve}"); dlg.resize(700, 620)
        lay = QVBoxLayout(dlg)
        ignored = cve_ignore.is_ignored(cve)
        state_txt = "🚫 IGNORED (excluded from threat level)" if ignored else "active"
        head = QLabel(f"<b>{name}</b><br><b>CVE:</b> {cve} &nbsp; "
                      f"<b>Vendor:</b> {vendor} &nbsp; <b>Product:</b> {prod}<br>"
                      f"<b>MITRE:</b> {mitre} &nbsp; <b>Ransomware:</b> {rans} &nbsp; "
                      f"<b>Due:</b> {due} &nbsp; <b>State:</b> {state_txt}")
        head.setWordWrap(True); lay.addWidget(head)

        lay.addWidget(QLabel("<b>Required Remediation (CISA KEV):</b>"))
        rt = QTextEdit(); rt.setReadOnly(True); rt.setPlainText(rem); rt.setMaximumHeight(90)
        lay.addWidget(rt)

        # ── Ignore / Revert / History row ──
        ig_row = QHBoxLayout()
        ig_btn = QPushButton("🚫 Revert ignore" if ignored else "🚫 Ignore this CVE")
        ig_btn.setToolTip("Ignored CVEs stay listed with full history but don't affect the threat level.")
        def _toggle():
            self._toggle_ignore(cve, not ignored); dlg.accept()
        ig_btn.clicked.connect(_toggle)
        hist_btn = QPushButton("🕑 History")
        hist_btn.clicked.connect(lambda: self._show_history(cve))
        ig_row.addWidget(ig_btn); ig_row.addWidget(hist_btn); ig_row.addStretch()
        lay.addLayout(ig_row)

        # ── AI fix analysis area ──
        lay.addWidget(QLabel("<b>AI fix analysis (local llama3, compared to your system):</b>"))
        fix_box = QLabel("Not analyzed yet."); fix_box.setWordWrap(True)
        fix_box.setStyleSheet("background:#0f172a; border:1px solid #334155; border-radius:5px;"
                              "padding:6px 8px; color:#cbd5e1;")
        lay.addWidget(fix_box)
        fix_actions = QHBoxLayout()
        analyze1 = QPushButton("🔎 Analyze fix")
        apply1 = QPushButton("⚙ Apply fix"); apply1.setEnabled(False)
        revert1 = QPushButton("↩ Revert change")
        flag1 = QPushButton("🚫 Flag & Ignore (no fix)")
        for b in (analyze1, apply1, revert1, flag1):
            fix_actions.addWidget(b)
        lay.addLayout(fix_actions)

        from angerona.core import cve_fix_advisor
        applied = cve_fix_advisor.applied_state(cve)
        revert1.setEnabled(bool(applied and applied.get("applied") and not applied.get("reverted")))

        def _render_analysis(a: dict):
            self._fix_cache[cve] = a
            if a.get("fix_available"):
                fix_box.setText(f"❗ <b>Potential fix available</b> (confidence "
                                f"{a.get('confidence',0):.0%}). {a.get('summary','')}")
                fix_box.setStyleSheet("background:#052e1a; border:1px solid #10b981;"
                                      "border-radius:5px; padding:6px 8px; color:#86efac;")
                apply1.setEnabled(True)
            else:
                fix_box.setText(f"No scriptable fix available. {a.get('reason','')}")
                fix_box.setStyleSheet("background:#1e293b; border:1px solid #475569;"
                                      "border-radius:5px; padding:6px 8px; color:#cbd5e1;")
                apply1.setEnabled(False)

        if cve in self._fix_cache:
            _render_analysis(self._fix_cache[cve])

        def _do_analyze():
            if not cve_fix_advisor.ollama_available():
                fix_box.setText("Local AI (Ollama) unavailable. Use 🌐 Consult AI for an online "
                                "analysis, or Flag & Ignore if no fix is expected.")
                return
            fix_box.setText("🔎 Analyzing with local AI…")
            QApp = __import__("PySide6.QtWidgets", fromlist=["QApplication"]).QApplication
            QApp.processEvents()
            _render_analysis(cve_fix_advisor.analyze(rec))
        analyze1.clicked.connect(_do_analyze)
        apply1.clicked.connect(lambda: (self._apply_fix(cve, self._fix_cache.get(cve, {})),
                                        dlg.accept()))
        revert1.clicked.connect(lambda: (self._revert_fix(cve), dlg.accept()))
        flag1.clicked.connect(lambda: (self._toggle_ignore(cve, True), dlg.accept()))

        # ── Web research + stage ──
        lay.addWidget(QLabel("<b>Research the specific fix on the web:</b>"))
        web = QHBoxLayout()
        def _open(url):
            try: webbrowser.open(url)
            except Exception: pass
        b_nvd = QPushButton("NVD detail")
        b_nvd.clicked.connect(lambda: _open(f"https://nvd.nist.gov/vuln/detail/{quote_plus(cve)}"))
        b_kev = QPushButton("CISA KEV entry")
        b_kev.clicked.connect(lambda: _open(
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext="
            + quote_plus(cve)))
        b_adv = QPushButton("Vendor advisory")
        b_adv.clicked.connect(lambda: _open("https://www.google.com/search?q="
            + quote_plus(f"{cve} {vendor} {prod} security advisory patch")))
        for b in (b_nvd, b_kev, b_adv):
            web.addWidget(b)
        lay.addLayout(web)

        act = QHBoxLayout(); act.addStretch()
        b_confirm = QPushButton("Confirm & Stage")
        b_close = QPushButton("Close")
        act.addWidget(b_confirm); act.addWidget(b_close); lay.addLayout(act)

        def _confirm():
            result = {"remediation": rem, "note": "review-gated; not executed"}
            if self._intl is not None:
                try:
                    result = self._intl.confirm(cve, run_verification=False)
                except Exception as exc:
                    QMessageBox.warning(self, "Stage Error", str(exc)); return
            self._staged.append({
                "cve": cve, "name": name, "vendor": vendor, "product": prod,
                "remediation": result.get("remediation", rem),
                "note": result.get("note", ""), "when": _time.strftime("%Y-%m-%d %H:%M:%S")})
            QMessageBox.information(self, "Staged", f"{cve} staged for operator review.")
            dlg.accept()
        b_confirm.clicked.connect(_confirm); b_close.clicked.connect(dlg.reject)
        dlg.exec()

    def _show_staged(self) -> None:
        dlg = QDialog(self); dlg.setWindowTitle("Staged / Confirmed remediations"); dlg.resize(700, 480)
        lay = QVBoxLayout(dlg)
        txt = QTextEdit(); txt.setReadOnly(True)
        staged = getattr(self, "_staged", [])
        if not staged:
            txt.setPlainText("Nothing staged yet. Double-click a CVE row, review, and "
                             "'Confirm & Stage'.")
        else:
            lines = []
            for s in staged:
                lines.append(f"[{s['when']}]  {s['cve']}  —  {s['name']}")
                lines.append(f"    Vendor / Product : {s['vendor']} / {s['product']}")
                lines.append(f"    Remediation      : {s['remediation']}")
                if s.get("note"):
                    lines.append(f"    Note             : {s['note']}")
                lines.append("")
            txt.setPlainText("\n".join(lines))
        lay.addWidget(txt)
        b = QPushButton("Close"); b.clicked.connect(dlg.accept); lay.addWidget(b)
        dlg.exec()

    def _open_consult_ai(self) -> None:
        self._open_deep_analysis()
        try:
            self._cve_analysis_dlg._open_online_ai(local_ok=True)
        except Exception:
            pass

    def _open_deep_analysis(self) -> None:
        if self._cve_analysis_dlg is None:
            self._cve_analysis_dlg = CveAnalysisWindow(
                parent=self.parent(), intl_module=self._intl)
            parent_ss = self.styleSheet()
            if parent_ss:
                self._cve_analysis_dlg.setStyleSheet(parent_ss)
        self._cve_analysis_dlg.show()
        self._cve_analysis_dlg.raise_()
        self._cve_analysis_dlg.activateWindow()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._load_and_render()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _due_color(due_str: str) -> str | None:
    try:
        import datetime
        due = datetime.date.fromisoformat(due_str)
        today = datetime.date.today()
        if due < today:
            return "#ef4444"
        if (due - today).days <= 14:
            return "#f59e0b"
    except Exception:
        pass
    return None
