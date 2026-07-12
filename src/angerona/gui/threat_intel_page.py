"""threat_intel_page.py — Threat Intelligence Dashboard (G4-B).

Displays the CISA Known Exploited Vulnerabilities (KEV) matches that the
INTL module writes to ``shared_logs/upstream_threats.json``.

Why a separate window?
    The main dashboard already has Modules + Alerts + Status.  KEV data is
    analyst-facing, not operator-alert-facing — it needs space to show the
    full CVE table, remediation guidance, ransomware flag, and MITRE mapping
    without competing for real estate with live event feeds.

Design
    - Non-modal QDialog (can stay open while using the rest of the UI).
    - QTableWidget with alternating rows; columns sized to content.
    - Auto-refresh every 60 s; manual "Refresh" button.
    - "Stage for Review" per-row button opens a QMessageBox with the full
      remediation text (review-gated — no auto-apply ever).
    - Pulsing indicator in the title bar shows alert state.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog, QFrame, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QPushButton, QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)
from angerona.gui.cve_analysis_window import CveAnalysisWindow

# ── tunables ──────────────────────────────────────────────────────────────────
_AUTO_REFRESH_MS = 60_000   # re-read upstream_threats.json every 60 s
_MAX_REMEDIATION_CELL = 120 # truncate remediation text in the table cell


def _repo_root() -> Path:
    """Best-effort: walk up from this file until we find shared_logs/."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "shared_logs").exists():
            return parent
    # Fallback — current working dir
    return Path.cwd()


def _threats_path() -> Path:
    return _repo_root() / "shared_logs" / "upstream_threats.json"


def _load_threats() -> dict:
    """Read upstream_threats.json; return empty structure if missing/invalid."""
    p = _threats_path()
    if not p.exists():
        return {"matches": [], "generated": "", "match_count": 0}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"matches": [], "generated": "parse error", "match_count": 0}


class ThreatIntelDashboard(QDialog):
    """Non-modal dialog showing CISA KEV matches for this host.

    Instantiate once from MainWindow and call show() / raise_() on each open.
    """

    # Column indices
    _C_CVE    = 0
    _C_VENDOR = 1
    _C_PROD   = 2
    _C_MITRE  = 3
    _C_RANS   = 4
    _C_DUE    = 5
    _C_REM    = 6
    _C_ACT    = 7

    _HEADERS = [
        "CVE ID", "Vendor", "Product", "MITRE", "Ransomware",
        "Due Date", "Required Remediation", "Action",
    ]

    def __init__(self, parent: Optional[QWidget] = None,
                 intl_module=None) -> None:
        super().__init__(parent)
        # intl_module — if provided, call .confirm() on the selected CVE.
        self._intl = intl_module
        self._cve_analysis_dlg: CveAnalysisWindow | None = None
        self.setWindowTitle("🛡  Threat Intelligence — CISA KEV Matches")
        self.setMinimumSize(1000, 560)
        self.resize(1200, 640)
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

        deep_btn = QPushButton("🔍  Deep Analysis")
        deep_btn.setFixedWidth(140)
        deep_btn.setToolTip(
            "Open the CVE Deep Analysis window — scrollable CVE cards + "
            "AI-generated prioritised remediation plan (local Ollama).")
        deep_btn.setStyleSheet(
            "background:#4c1d95; color:#c4b5fd; border:1px solid #7c3aed;"
            "border-radius:6px; padding:5px 12px; font-weight:700;")
        deep_btn.clicked.connect(self._open_deep_analysis)
        hdr.addWidget(deep_btn)

        consult_btn = QPushButton("🌐  Consult AI")
        consult_btn.setFixedWidth(130)
        consult_btn.setToolTip(
            "Reach out to an ONLINE AI (Claude first, then fallbacks) to build a "
            "comprehensive fix/patch for the host-applicable CVEs, with save/download.")
        consult_btn.setStyleSheet(
            "background:#1e3a5f; color:#7dd3fc; border:1px solid #2563eb;"
            "border-radius:6px; padding:5px 12px; font-weight:700;")
        consult_btn.clicked.connect(self._open_consult_ai)
        hdr.addWidget(consult_btn)

        refresh_btn = QPushButton("↺  Refresh")
        refresh_btn.setFixedWidth(100)
        refresh_btn.clicked.connect(self._load_and_render)
        hdr.addWidget(refresh_btn)

        self._staged: list = []
        staged_btn = QPushButton("📋  Staged / Confirmed")
        staged_btn.setToolTip("View the items you've staged/confirmed for remediation review.")
        staged_btn.clicked.connect(self._show_staged)
        hdr.addWidget(staged_btn)
        lay.addLayout(hdr)

        # ── Info bar ─────────────────────────────────────────────────────
        self._info = QLabel(
            "⚠  Only inbound CISA data is used — no host data leaves the machine. "
            "Remediation is REVIEW-GATED; click 'Stage for Review' to inspect."
        )
        self._info.setWordWrap(True)
        self._info.setStyleSheet(
            "background:#1e293b; color:#94a3b8; border:1px solid #334155;"
            "border-radius:6px; padding:6px 10px; font-size:11px;"
        )
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
        for col in (self._C_CVE, self._C_VENDOR, self._C_PROD,
                    self._C_MITRE, self._C_RANS, self._C_DUE, self._C_ACT):
            self._table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setStyleSheet(
            "QTableWidget { font-size:12px; }"
            "QTableWidget::item { padding: 5px 8px; }"
        )
        lay.addWidget(self._table, 1)
        # Double-click a row (anywhere, not just the Stage button) → full detail.
        self._table.cellDoubleClicked.connect(self._on_row_double)

        # ── Footer stats ─────────────────────────────────────────────────
        self._footer = QLabel("No KEV data loaded.")
        self._footer.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(self._footer)

        # ── Auto-refresh timer ────────────────────────────────────────────
        self._timer = QTimer(self)
        self._timer.setInterval(_AUTO_REFRESH_MS)
        self._timer.timeout.connect(self._load_and_render)
        self._timer.start()

        # Initial load
        self._load_and_render()

    # ── Data loading & rendering ─────────────────────────────────────────
    def _load_and_render(self) -> None:
        data = _load_threats()
        matches = data.get("matches", [])
        generated = data.get("generated", "")
        self._row_recs: dict = {}   # row index → (cve, rec), for row double-click

        self._ts_label.setText(f"Last sync: {generated or '—'}")

        ransomware_count = sum(
            1 for m in matches
            if str(m.get("ransomware", "")).strip().lower() not in ("known", "")
            and m.get("ransomware")
        )
        # Known Ransomware Campaign Use = "Known" in the KEV catalog
        rans_hits = sum(
            1 for m in matches
            if str(m.get("ransomware", "")).strip().lower() == "known"
        )

        self._table.setUpdatesEnabled(False)
        self._table.setRowCount(len(matches))

        for row, rec in enumerate(matches):
            def _item(text: str, color: str | None = None) -> QTableWidgetItem:
                it = QTableWidgetItem(str(text or "—"))
                it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                if color:
                    it.setForeground(
                        __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(color))
                return it

            cve  = rec.get("cve") or "—"
            self._row_recs[row] = (cve, rec)
            rans = str(rec.get("ransomware") or "—")
            rem  = str(rec.get("remediation") or "—")
            due  = str(rec.get("due_date") or "—")

            rans_color = "#ef4444" if rans.strip().lower() == "known" else None
            due_color  = _due_color(due)

            self._table.setItem(row, self._C_CVE,    _item(cve, "#38bdf8"))
            self._table.setItem(row, self._C_VENDOR, _item(rec.get("vendor") or ""))
            self._table.setItem(row, self._C_PROD,   _item(rec.get("product") or ""))
            self._table.setItem(row, self._C_MITRE,  _item(rec.get("mitre") or ""))
            self._table.setItem(row, self._C_RANS,   _item(rans, rans_color))
            self._table.setItem(row, self._C_DUE,    _item(due, due_color))
            self._table.setItem(row, self._C_REM,
                                _item(rem[:_MAX_REMEDIATION_CELL] +
                                      ("…" if len(rem) > _MAX_REMEDIATION_CELL else "")))

            # "Stage for Review" button cell
            btn = QPushButton("Stage for Review")
            btn.setFixedHeight(26)
            btn.setStyleSheet(
                "background:#1e3a5f; color:#38bdf8; border:1px solid #38bdf855;"
                "border-radius:4px; font-size:11px; padding:0 8px;"
            )
            # Capture rec by value for the closure
            btn.clicked.connect(self._make_stage_handler(cve, rec))
            cell_widget = QWidget()
            cell_lay = QHBoxLayout(cell_widget)
            cell_lay.setContentsMargins(4, 1, 4, 1)
            cell_lay.addWidget(btn)
            self._table.setCellWidget(row, self._C_ACT, cell_widget)

        self._table.setUpdatesEnabled(True)

        count = len(matches)
        if count == 0:
            self._footer.setText("✅  No host-applicable KEV CVEs found.")
            self._footer.setStyleSheet("color:#22c55e; font-size:11px;")
        else:
            rans_note = f"  |  {rans_hits} with known ransomware campaign use" if rans_hits else ""
            self._footer.setText(
                f"⚠  {count} host-applicable CVE(s) found{rans_note}. "
                "Review each entry and stage remediation with operator approval."
            )
            self._footer.setStyleSheet("color:#f59e0b; font-size:11px;")

    def _make_stage_handler(self, cve: str, rec: dict):
        """Return a slot closure that opens the review dialog for *cve*."""
        def _handler():
            self._stage_review(cve, rec)
        return _handler

    def _on_row_double(self, row: int, _col: int) -> None:
        entry = getattr(self, "_row_recs", {}).get(row)
        if entry:
            self._stage_review(entry[0], entry[1])

    def _stage_review(self, cve: str, rec: dict) -> None:
        """Full detail dialog: remediation text, WEB-RESEARCH buttons (KEV usually
        only says 'apply per vendor instructions', so link out to the specific,
        authoritative sources), and a review-gated Confirm & Stage."""
        import time as _time
        import webbrowser
        from urllib.parse import quote_plus
        from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                                       QTextEdit, QPushButton)

        rem    = rec.get("remediation") or "No remediation text available."
        mitre  = rec.get("mitre") or "—"
        rans   = rec.get("ransomware") or "—"
        due    = rec.get("due_date") or "—"
        name   = rec.get("name") or cve
        vendor = rec.get("vendor") or ""
        prod   = rec.get("product") or ""

        dlg = QDialog(self); dlg.setWindowTitle(f"Threat detail — {cve}"); dlg.resize(660, 500)
        lay = QVBoxLayout(dlg)
        head = QLabel(f"<b>{name}</b><br><b>CVE:</b> {cve} &nbsp; "
                      f"<b>Vendor:</b> {vendor} &nbsp; <b>Product:</b> {prod}<br>"
                      f"<b>MITRE:</b> {mitre} &nbsp; <b>Ransomware:</b> {rans} &nbsp; "
                      f"<b>Due:</b> {due}")
        head.setWordWrap(True); lay.addWidget(head)

        lay.addWidget(QLabel("<b>Required Remediation (CISA KEV):</b>"))
        rt = QTextEdit(); rt.setReadOnly(True); rt.setPlainText(rem); rt.setMaximumHeight(120)
        lay.addWidget(rt)

        lay.addWidget(QLabel("<b>Research the specific fix on the web:</b>"))
        web = QHBoxLayout()
        def _open(url):
            try:
                webbrowser.open(url)
            except Exception:
                pass
        b_nvd = QPushButton("NVD detail")
        b_nvd.clicked.connect(lambda: _open(f"https://nvd.nist.gov/vuln/detail/{quote_plus(cve)}"))
        b_kev = QPushButton("CISA KEV entry")
        b_kev.clicked.connect(lambda: _open(
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext="
            + quote_plus(cve)))
        b_adv = QPushButton("Vendor advisory")
        b_adv.clicked.connect(lambda: _open(
            "https://www.google.com/search?q="
            + quote_plus(f"{cve} {vendor} {prod} security advisory patch")))
        b_fix = QPushButton("How-to-patch search")
        b_fix.clicked.connect(lambda: _open(
            "https://www.google.com/search?q=" + quote_plus(f"{cve} remediation how to patch steps")))
        for b in (b_nvd, b_kev, b_adv, b_fix):
            web.addWidget(b)
        lay.addLayout(web)

        act = QHBoxLayout(); act.addStretch()
        b_confirm = QPushButton("Confirm & Stage")
        b_close = QPushButton("Close")
        act.addWidget(b_confirm); act.addWidget(b_close)
        lay.addLayout(act)

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
                "note": result.get("note", ""), "when": _time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            QMessageBox.information(self, "Staged",
                                   f"{cve} staged for operator review.\n"
                                   "View it any time via the 'Staged / Confirmed' button.")
            dlg.accept()
        b_confirm.clicked.connect(_confirm)
        b_close.clicked.connect(dlg.reject)
        dlg.exec()

    def _show_staged(self) -> None:
        """A place to review everything staged/confirmed this session."""
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
        dlg = QDialog(self); dlg.setWindowTitle("Staged / Confirmed remediations"); dlg.resize(700, 480)
        lay = QVBoxLayout(dlg)
        txt = QTextEdit(); txt.setReadOnly(True)
        staged = getattr(self, "_staged", [])
        if not staged:
            txt.setPlainText("Nothing staged yet.\n\nDouble-click a CVE row (or use 'Stage for "
                             "Review'), review the detail, and click 'Confirm & Stage' — confirmed "
                             "items appear here with their remediation and timestamp.")
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
        """Open the online AI consult directly on the current CVE set."""
        self._open_deep_analysis()
        try:
            self._cve_analysis_dlg._open_online_ai(local_ok=True)
        except Exception:
            pass

    def _open_deep_analysis(self) -> None:
        """Open (or raise) the CVE Deep Analysis window."""
        if self._cve_analysis_dlg is None:
            self._cve_analysis_dlg = CveAnalysisWindow(
                parent=self.parent(), intl_module=self._intl)
            # Inherit the parent's stylesheet if available
            parent_ss = self.styleSheet()
            if parent_ss:
                self._cve_analysis_dlg.setStyleSheet(parent_ss)
        self._cve_analysis_dlg.show()
        self._cve_analysis_dlg.raise_()
        self._cve_analysis_dlg.activateWindow()

    def showEvent(self, event) -> None:
        """Refresh on each show so data is current when reopened."""
        super().showEvent(event)
        self._load_and_render()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _due_color(due_str: str) -> str | None:
    """Return a warning/danger colour if the due date is past or imminent."""
    try:
        import datetime
        due = datetime.date.fromisoformat(due_str)
        today = datetime.date.today()
        if due < today:
            return "#ef4444"   # overdue — red
        if (due - today).days <= 14:
            return "#f59e0b"   # due within 2 weeks — amber
    except Exception:
        pass
    return None
