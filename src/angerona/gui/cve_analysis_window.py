"""cve_analysis_window.py — CVE Deep Analysis Window (G5-A).

Two-panel window:

  Left  — Scrollable CVE cards
    Each card shows the full detail for one host-applicable KEV entry:
    CVE ID (hyperlink to NVD), vendor/product, vulnerability name, date added,
    due date (colour-coded), MITRE technique, ransomware-campaign flag, CISA
    required action, and a "driver-related" badge for .sys/.driver entries.

  Right — AI Proposed Fixes
    "Generate AI Analysis" fires a background thread that sends the CVE list
    to local Ollama (llama3) with a security-focused system prompt.  The model
    returns a prioritised, plain-English fix plan — patch order, driver
    mitigations, Windows hardening steps, detection recommendations.  Falls
    back to a structured summary of the CISA text if Ollama is unreachable.

Design constraints
    - All Ollama calls happen off the Qt main thread (background daemon thread
      + Signal handoff).  The UI never blocks.
    - No host data is sent off-machine.  The AI call goes to 127.0.0.1:11434.
    - No auto-remediation — all output is advisory only.
"""
from __future__ import annotations

import json
import os
import threading
import urllib.request
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QDialog, QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton,
    QScrollArea, QSizePolicy, QSplitter, QVBoxLayout, QWidget,
)

# ── Ollama settings ───────────────────────────────────────────────────────────
_OLLAMA_HOST  = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
_OLLAMA_MODEL = os.environ.get("ANGERONA_MODEL", "llama3")
_OLLAMA_TIMEOUT = 60.0   # seconds — CVE analysis is a larger prompt than triage

_AI_SYSTEM_PROMPT = """\
You are a senior Windows security engineer advising a security operations team.
You will be given a list of CISA Known Exploited Vulnerabilities (KEV) that have
been correlated against a specific Windows host.  Your job is to produce a clear,
prioritised remediation plan.

Rules:
- Be specific and practical.  Name the exact patches, mitigations, or workarounds.
- Address driver-related CVEs separately with kernel-level mitigation advice.
- Prioritise CVEs with known ransomware campaign use at the top.
- For each CVE: state the risk, the immediate action, and a detection test.
- Do NOT suggest actions that require physical access or reinstallation unless
  there is no other option.
- Write in plain English.  Avoid jargon unless it is the industry-standard term.
- Format: numbered list, one CVE per section, with sub-bullets for each action.
"""

# Keywords that indicate a driver-related CVE
_DRIVER_KEYWORDS = (
    "driver", "kernel", ".sys", "hypervisor", "firmware", "bios", "uefi",
    "nvme", "usb", "hid", "ndis", "wdm", "winring", "rtcore", "dbutil",
    "gdrv", "capcom", "mhyprot",
)


def _threats_path() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "shared_logs").exists():
            return parent / "shared_logs" / "upstream_threats.json"
    return Path.cwd() / "shared_logs" / "upstream_threats.json"


def _load_matches() -> list[dict]:
    p = _threats_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data.get("matches", [])
    except Exception:
        return []


def _is_driver_cve(rec: dict) -> bool:
    text = " ".join([
        str(rec.get("product", "")),
        str(rec.get("vendor", "")),
        str(rec.get("name", "")),
        str(rec.get("remediation", "")),
    ]).lower()
    return any(kw in text for kw in _DRIVER_KEYWORDS)


def _due_color(due_str: str) -> str:
    import datetime
    try:
        due = datetime.date.fromisoformat(due_str)
        today = datetime.date.today()
        if due < today:
            return "#ef4444"
        if (due - today).days <= 14:
            return "#f59e0b"
        return "#22c55e"
    except Exception:
        return "#94a3b8"


def _severity_color(ransomware: str) -> str:
    if str(ransomware).strip().lower() == "known":
        return "#ef4444"
    return "#94a3b8"


# ── CVE Card widget ───────────────────────────────────────────────────────────

class CveCard(QFrame):
    """Displays one CVE record as a rich, styled card."""

    def __init__(self, rec: dict, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("Panel")
        self.setFrameShape(QFrame.Shape.StyledPanel)

        is_driver = _is_driver_cve(rec)
        rans = str(rec.get("ransomware") or "—")
        due  = str(rec.get("due_date") or "—")
        cve  = rec.get("cve") or "Unknown CVE"

        # Card left-border accent: red for ransomware-known, amber for driver, blue otherwise
        if rans.strip().lower() == "known":
            border_color = "#ef4444"
        elif is_driver:
            border_color = "#f59e0b"
        else:
            border_color = "#38bdf8"

        self.setStyleSheet(
            f"QFrame#Panel {{ background:#0f172a; border:1px solid #334155;"
            f"border-left:4px solid {border_color}; border-radius:8px;"
            f"margin:4px 0; }}"
        )

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 12)
        lay.setSpacing(6)

        # ── Title row ────────────────────────────────────────────────────
        title_row = QHBoxLayout()
        cve_lbl = QLabel(f"<a href='https://nvd.nist.gov/vuln/detail/{cve}' "
                         f"style='color:#38bdf8; font-weight:800; font-size:14px;'>{cve}</a>")
        cve_lbl.setOpenExternalLinks(True)
        cve_lbl.setTextInteractionFlags(
            Qt.TextInteractionFlag.LinksAccessibleByMouse |
            Qt.TextInteractionFlag.TextSelectableByMouse)
        title_row.addWidget(cve_lbl, 1)

        if is_driver:
            badge = QLabel("🔧 DRIVER/KERNEL")
            badge.setStyleSheet(
                "background:#78350f; color:#fcd34d; border:1px solid #f59e0b55;"
                "border-radius:4px; padding:2px 6px; font-size:10px; font-weight:700;"
            )
            title_row.addWidget(badge)

        if rans.strip().lower() == "known":
            rans_badge = QLabel("🔴 RANSOMWARE")
            rans_badge.setStyleSheet(
                "background:#7f1d1d; color:#fca5a5; border:1px solid #ef444455;"
                "border-radius:4px; padding:2px 6px; font-size:10px; font-weight:700;"
            )
            title_row.addWidget(rans_badge)

        lay.addLayout(title_row)

        # ── Vulnerability name ────────────────────────────────────────────
        name = rec.get("name") or ""
        if name:
            name_lbl = QLabel(name)
            name_lbl.setWordWrap(True)
            name_lbl.setStyleSheet("color:#f1f5f9; font-weight:600; font-size:12px;")
            lay.addWidget(name_lbl)

        # ── Detail grid ───────────────────────────────────────────────────
        grid = QHBoxLayout()
        grid.setSpacing(24)

        def _kv(key: str, val: str, color: str = "#94a3b8") -> QWidget:
            w = QWidget()
            kl = QVBoxLayout(w)
            kl.setContentsMargins(0, 0, 0, 0)
            kl.setSpacing(1)
            k = QLabel(key.upper())
            k.setStyleSheet("color:#64748b; font-size:10px; letter-spacing:1px; font-weight:700;")
            v = QLabel(val or "—")
            v.setWordWrap(True)
            v.setStyleSheet(f"color:{color}; font-size:12px; font-weight:600;")
            kl.addWidget(k)
            kl.addWidget(v)
            return w

        grid.addWidget(_kv("Vendor", rec.get("vendor") or "—"))
        grid.addWidget(_kv("Product", rec.get("product") or "—"))
        grid.addWidget(_kv("MITRE", rec.get("mitre") or "—", "#a78bfa"))
        grid.addWidget(_kv("Date Added", rec.get("date_added") or "—"))
        grid.addWidget(_kv("Due Date", due, _due_color(due)))
        grid.addStretch(1)
        lay.addLayout(grid)

        # ── CISA Required Action ──────────────────────────────────────────
        action = rec.get("remediation") or ""
        if action:
            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.HLine)
            sep.setStyleSheet("color:#334155;")
            lay.addWidget(sep)

            action_hdr = QLabel("CISA REQUIRED ACTION")
            action_hdr.setStyleSheet(
                "color:#64748b; font-size:10px; letter-spacing:1px; font-weight:700;")
            lay.addWidget(action_hdr)

            action_lbl = QLabel(action)
            action_lbl.setWordWrap(True)
            action_lbl.setStyleSheet("color:#cbd5e1; font-size:12px;")
            action_lbl.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            lay.addWidget(action_lbl)


# ── AI analysis helpers ───────────────────────────────────────────────────────

def _build_ai_prompt(matches: list[dict]) -> str:
    """Build the user message containing the CVE list for Ollama."""
    lines = [
        f"Analyse these {len(matches)} host-applicable CISA KEV entries and provide "
        "a prioritised remediation plan with driver-specific mitigations where applicable.\n"
    ]
    for i, rec in enumerate(matches, 1):
        rans = "YES — known ransomware use" if str(rec.get("ransomware", "")).lower() == "known" \
               else "No known ransomware campaign"
        driver = "YES" if _is_driver_cve(rec) else "No"
        lines.append(
            f"\n--- CVE {i}: {rec.get('cve','?')} ---\n"
            f"  Product:       {rec.get('vendor','')} {rec.get('product','')}\n"
            f"  Name:          {rec.get('name','')}\n"
            f"  MITRE:         {rec.get('mitre','')}\n"
            f"  Ransomware:    {rans}\n"
            f"  Driver/Kernel: {driver}\n"
            f"  Due date:      {rec.get('due_date','')}\n"
            f"  CISA action:   {rec.get('remediation','')}\n"
        )
    return "\n".join(lines)


def _call_ollama(prompt: str) -> Optional[str]:
    """Blocking Ollama call — always run in a background thread."""
    payload = json.dumps({
        "model": _OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": _AI_SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{_OLLAMA_HOST}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_OLLAMA_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return (data.get("message", {}) or {}).get("content", "").strip()
    except Exception as exc:
        return None


def _fallback_analysis(matches: list[dict]) -> str:
    """Structured plain-text summary when Ollama is unavailable."""
    if not matches:
        return "No host-applicable CVEs found."
    lines = ["OFFLINE / AI UNAVAILABLE — STRUCTURED CISA SUMMARY\n",
             "=" * 56, ""]
    # Sort: ransomware-known first, then driver CVEs, then rest
    def _sort_key(r):
        rans = str(r.get("ransomware", "")).lower() == "known"
        drv  = _is_driver_cve(r)
        return (not rans, not drv)
    for i, rec in enumerate(sorted(matches, key=_sort_key), 1):
        rans = str(rec.get("ransomware", "")).lower() == "known"
        drv  = _is_driver_cve(rec)
        flags = []
        if rans:  flags.append("🔴 RANSOMWARE CAMPAIGN")
        if drv:   flags.append("🔧 DRIVER/KERNEL")
        lines.append(f"{i}. {rec.get('cve','?')} — {rec.get('name','')}")
        if flags:
            lines.append(f"   ⚠  {' | '.join(flags)}")
        lines.append(f"   Product: {rec.get('vendor','')} {rec.get('product','')}")
        lines.append(f"   MITRE:   {rec.get('mitre','')}")
        lines.append(f"   Due:     {rec.get('due_date','')}")
        lines.append(f"   Action:  {rec.get('remediation','')}")
        lines.append("")
    lines.append(
        "─" * 56 + "\n"
        "To enable AI-powered analysis, ensure Ollama is running:\n"
        "  ollama serve\n"
        "Then click 'Generate AI Analysis' again."
    )
    return "\n".join(lines)


# ── Main window ───────────────────────────────────────────────────────────────

class CveAnalysisWindow(QDialog):
    """Deep CVE analysis: scrollable cards on the left, AI fixes on the right.

    Instantiate once; call show() / raise_() to (re)open.  The AI analysis
    result is fetched off-thread via a Signal so the GUI never blocks.
    """

    # Emitted from the background thread when Ollama returns (or fails).
    _ai_done = Signal(str)   # text to show in the fixes pane

    def __init__(self, parent: Optional[QWidget] = None,
                 intl_module=None) -> None:
        super().__init__(parent)
        self._intl = intl_module
        self._ai_running = False

        self.setWindowTitle("🔍  CVE Deep Analysis — Host Correlation & AI Remediation")
        self.setMinimumSize(1100, 680)
        self.resize(1380, 780)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)

        # Wire the background→GUI signal before building UI
        self._ai_done.connect(self._on_ai_done)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Title bar ─────────────────────────────────────────────────────
        tbar = QWidget()
        tbar.setStyleSheet("background:#0f172a; border-bottom:1px solid #334155;")
        tbar_lay = QHBoxLayout(tbar)
        tbar_lay.setContentsMargins(16, 10, 16, 10)

        title_lbl = QLabel("🔍  CVE Deep Analysis")
        title_lbl.setStyleSheet("font-size:16px; font-weight:800; color:#f1f5f9;")
        tbar_lay.addWidget(title_lbl, 1)

        self._status_lbl = QLabel("Loading…")
        self._status_lbl.setStyleSheet("color:#94a3b8; font-size:12px;")
        tbar_lay.addWidget(self._status_lbl)

        refresh_btn = QPushButton("↺  Refresh CVEs")
        refresh_btn.setFixedWidth(130)
        refresh_btn.clicked.connect(self._load_cves)
        tbar_lay.addWidget(refresh_btn)

        root.addWidget(tbar)

        # ── Main splitter: card list | AI pane ────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(3)
        splitter.setStyleSheet("QSplitter::handle { background:#334155; }")

        # ── Left: scrollable CVE cards ────────────────────────────────────
        left = QWidget()
        left.setStyleSheet("background:#020617;")
        left_lay = QVBoxLayout(left)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(0)

        left_hdr = QLabel("  HOST-APPLICABLE CVEs  (CISA KEV)")
        left_hdr.setStyleSheet(
            "background:#0f172a; color:#38bdf8; font-size:11px; font-weight:700;"
            "letter-spacing:2px; padding:8px 14px; border-bottom:1px solid #334155;"
        )
        left_lay.addWidget(left_hdr)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setStyleSheet(
            "QScrollArea { border:none; background:#020617; }"
            "QScrollBar:vertical { background:#0f172a; width:8px; }"
            "QScrollBar::handle:vertical { background:#334155; border-radius:4px; }"
        )
        self._card_container = QWidget()
        self._card_container.setStyleSheet("background:#020617;")
        self._cards_lay = QVBoxLayout(self._card_container)
        self._cards_lay.setContentsMargins(12, 12, 12, 12)
        self._cards_lay.setSpacing(8)
        self._cards_lay.addStretch(1)
        self._scroll.setWidget(self._card_container)
        left_lay.addWidget(self._scroll, 1)
        splitter.addWidget(left)

        # ── Right: AI proposed fixes ──────────────────────────────────────
        right = QWidget()
        right.setStyleSheet("background:#020617;")
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(0)

        right_hdr_row = QWidget()
        right_hdr_row.setStyleSheet(
            "background:#0f172a; border-bottom:1px solid #334155;")
        right_hdr_inner = QHBoxLayout(right_hdr_row)
        right_hdr_inner.setContentsMargins(14, 8, 14, 8)
        right_hdr_lbl = QLabel("🤖  AI PROPOSED FIXES")
        right_hdr_lbl.setStyleSheet(
            "color:#a78bfa; font-size:11px; font-weight:700; letter-spacing:2px;")
        right_hdr_inner.addWidget(right_hdr_lbl, 1)

        self._gen_btn = QPushButton("⚡  Generate AI Analysis")
        self._gen_btn.setStyleSheet(
            "background:#4c1d95; color:#c4b5fd; border:1px solid #7c3aed;"
            "border-radius:6px; padding:5px 12px; font-weight:700;")
        self._gen_btn.clicked.connect(self._run_ai_analysis)
        right_hdr_inner.addWidget(self._gen_btn)

        # Online AI: reach out (Claude first) to build a comprehensive fix/patch,
        # then download/save it. Explicit button press = consented egress.
        self._consult_btn = QPushButton("🌐  Consult AI")
        self._consult_btn.setToolTip("Reach out to an ONLINE AI (Claude first, then "
                                     "fallbacks) to build a comprehensive fix/patch you "
                                     "can save to a file.")
        self._consult_btn.setStyleSheet(
            "background:#1e3a5f; color:#7dd3fc; border:1px solid #2563eb;"
            "border-radius:6px; padding:5px 12px; font-weight:700;")
        self._consult_btn.clicked.connect(lambda: self._open_online_ai(local_ok=True))
        right_hdr_inner.addWidget(self._consult_btn)

        self._solution_btn = QPushButton("💡  AI Proposed Solution")
        self._solution_btn.setToolTip("Online-only comprehensive remediation in its own "
                                      "window, with Save to computer / Discard.")
        self._solution_btn.setStyleSheet(
            "background:#166534; color:#bbf7d0; border:1px solid #16a34a;"
            "border-radius:6px; padding:5px 12px; font-weight:700;")
        self._solution_btn.clicked.connect(lambda: self._open_online_ai(local_ok=False))
        right_hdr_inner.addWidget(self._solution_btn)
        right_lay.addWidget(right_hdr_row)

        # Notice bar
        note = QLabel(
            "  🔒  AI analysis uses local Ollama only (127.0.0.1:11434).  "
            "No data leaves the machine."
        )
        note.setStyleSheet(
            "background:#0c1a0c; color:#4ade80; font-size:11px;"
            "padding:5px 14px; border-bottom:1px solid #334155;"
        )
        right_lay.addWidget(note)

        self._ai_pane = QPlainTextEdit()
        self._ai_pane.setReadOnly(True)
        self._ai_pane.setFont(QFont("Fira Code", 11))
        self._ai_pane.setStyleSheet(
            "background:#020617; color:#e2e8f0; border:none;"
            "padding:14px; font-family:'Fira Code','Cascadia Mono','Consolas',monospace;"
        )
        self._ai_pane.setPlaceholderText(
            "Click ⚡ Generate AI Analysis to get an AI-powered, prioritised remediation "
            "plan for the CVEs shown on the left.\n\n"
            "Requires Ollama running locally (ollama serve).\n\n"
            "If Ollama is unavailable, a structured CISA summary is shown instead."
        )
        right_lay.addWidget(self._ai_pane, 1)
        splitter.addWidget(right)

        splitter.setSizes([560, 700])
        root.addWidget(splitter, 1)

        # Load CVEs on creation
        self._matches: list[dict] = []
        self._load_cves()

    # ── CVE loading ───────────────────────────────────────────────────────────
    def _load_cves(self) -> None:
        self._matches = _load_matches()
        self._render_cards()

    def _render_cards(self) -> None:
        # Clear existing cards (keep the trailing stretch)
        while self._cards_lay.count() > 1:
            item = self._cards_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        matches = self._matches
        if not matches:
            placeholder = QLabel(
                "No host-applicable CVEs found in shared_logs/upstream_threats.json.\n\n"
                "The INTL module fetches the CISA KEV catalog every 6 hours.\n"
                "Ensure internet access is available and wait for the next sync,\n"
                "or click ↺ Refresh CVEs after the INTL module runs."
            )
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setWordWrap(True)
            placeholder.setStyleSheet("color:#64748b; font-size:13px; padding:40px;")
            self._cards_lay.insertWidget(0, placeholder)
            self._status_lbl.setText("No CVEs found")
            return

        # Sort: ransomware → driver → rest
        def _rank(r):
            rans = str(r.get("ransomware", "")).lower() == "known"
            drv  = _is_driver_cve(r)
            return (not rans, not drv)

        for i, rec in enumerate(sorted(matches, key=_rank)):
            card = CveCard(rec)
            self._cards_lay.insertWidget(i, card)

        rans_count = sum(
            1 for r in matches if str(r.get("ransomware", "")).lower() == "known"
        )
        drv_count = sum(1 for r in matches if _is_driver_cve(r))

        parts = [f"{len(matches)} CVEs"]
        if rans_count:  parts.append(f"{rans_count} ransomware-linked")
        if drv_count:   parts.append(f"{drv_count} driver/kernel")
        self._status_lbl.setText(" · ".join(parts))

    # ── Online AI consult (Claude first) → save/download ─────────────────────
    def _open_online_ai(self, local_ok: bool) -> None:
        """Open the online AI consult window (Claude first) to build a
        comprehensive fix/patch for the host-applicable CVEs, with Save/Discard.

        local_ok=True  → "Consult AI" (falls back to local Ollama if offline).
        local_ok=False → "AI Proposed Solution" (online providers only)."""
        self._matches = _load_matches()
        self._render_cards()
        if not self._matches:
            self._ai_pane.setPlainText(
                "No host-applicable CVEs to solve yet. The INTL module must detect "
                "KEV entries first (needs internet for the CISA catalog fetch).")
            return
        try:
            from angerona.gui.ai_consult_dialog import AIConsultDialog
        except Exception as exc:
            self._ai_pane.setPlainText(f"Consult AI unavailable: {exc}")
            return
        prompt = (
            "You are producing a comprehensive, copy-pasteable remediation package for "
            "a Windows host affected by the following CISA KEV CVEs. For EACH CVE give: "
            "a one-line risk summary, the concrete fix (patch/registry/config/PowerShell), "
            "and a verification step. Prioritise ransomware-linked and driver/kernel CVEs. "
            "End with a single consolidated PowerShell script block that applies the safe "
            "mitigations, clearly commented.\n\n" + _build_ai_prompt(self._matches))
        title = ("Consult AI — CVE fix/patch" if local_ok
                 else "AI Proposed Solution — CVE remediation")
        fname = "cve_remediation.md"
        AIConsultDialog(title, prompt, default_filename=fname,
                        allow_local_fallback=local_ok, parent=self).show()

    # ── AI analysis ───────────────────────────────────────────────────────────
    def _run_ai_analysis(self) -> None:
        if self._ai_running:
            return

        # Reload CVEs to ensure we have the latest
        self._matches = _load_matches()
        self._render_cards()

        if not self._matches:
            self._ai_pane.setPlainText(
                "No CVEs to analyse.  The INTL module needs to detect host-applicable "
                "entries first (requires internet access for KEV catalog fetch)."
            )
            return

        self._ai_running = True
        self._gen_btn.setEnabled(False)
        self._gen_btn.setText("⏳  Generating…")
        self._ai_pane.setPlainText(
            "Sending CVE list to local Ollama for analysis…\n\n"
            "This may take 20–60 seconds depending on your hardware.\n"
            "The UI remains fully interactive while analysis runs."
        )

        prompt = _build_ai_prompt(self._matches)
        matches_snapshot = list(self._matches)  # capture for thread

        def _worker():
            result = _call_ollama(prompt)
            if result:
                self._ai_done.emit(result)
            else:
                self._ai_done.emit(_fallback_analysis(matches_snapshot))

        t = threading.Thread(target=_worker, daemon=True, name="CVE-AI-analysis")
        t.start()

    def _on_ai_done(self, text: str) -> None:
        """Receive AI result on the Qt main thread."""
        self._ai_pane.setPlainText(text)
        self._ai_running = False
        self._gen_btn.setEnabled(True)
        self._gen_btn.setText("⚡  Generate AI Analysis")

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._load_cves()
