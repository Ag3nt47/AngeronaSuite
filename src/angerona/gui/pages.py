"""Composable panels for the single-screen dashboard.

Everything lives on one screen (mirroring the original Angerona dashboard):
  • DashboardCards  — summary stat cards + threat pill
  • ModulesPanel    — module list with enable toggles + live status (click to inspect)
  • ModuleInspector — per-module detail + live feed + controls
  • AlertsPanel     — live event/alert feed
  • StatusStrip     — bottom matrix of every module's status (like the original)
  • SettingsDialog  — settings, opened from the header button
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import threading
import time
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QFont, QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFileDialog, QGridLayout, QFrame, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMenu, QMessageBox, QPlainTextEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

HELP_TEXT_SHORT = (
    "Gemini & Groq offer free keys. Paste a key in the API Keys tab and Save — "
    "it's stored locally in .env and used only for opt-in cloud escalation."
)
HELP_TEXT_FULL = """ANGERONA — API KEY SETUP

Angerona runs fully local by default (Ollama). Cloud keys are OPTIONAL and only
used for the 'Cloud CTI Escalation' second-opinion on CRITICAL events. Keys are
stored locally in a .env file next to the app and are NEVER committed or sent
anywhere except the provider you choose.

WHERE TO GET KEYS
  • Gemini (free tier):   https://aistudio.google.com/app/apikey
  • Groq (free tier):     https://console.groq.com/keys
  • OpenAI:               https://platform.openai.com/api-keys
  • Anthropic (Claude):   https://console.anthropic.com/settings/keys
  • OpenRouter:           https://openrouter.ai/keys

HOW TO ADD THEM
  1. Open the provider link above and create an API key.
  2. Copy the key.
  3. In the 'API Keys' tab, paste it into the matching field.
     - Gemini supports a comma-separated POOL of keys for rotation, e.g.
       key1,key2,key3
  4. Click 'Save keys'. They're written to .env and loaded live.
  5. The Cloud CTI Escalation module picks them up within ~30 seconds — no
     restart needed. Its health/Overview tab will show it active.

SECURITY NOTES
  • .env is git-ignored; keys never leave your machine except to the provider.
  • Remove a key anytime by clearing its field and saving.
  • Without any key, Angerona stays 100% local — nothing is sent externally.
"""

from angerona import __version__
from angerona.core.eventbus import Severity
from angerona.core.threat import threat_label
from angerona.gui.theme import SEVERITY_COLOR, available_themes

THREAT = {
    Severity.INFO: ("Calm", "#22c55e"),
    Severity.LOW: ("Low", "#3b82f6"),
    Severity.MEDIUM: ("Elevated", "#f97316"),   # orange — was amber
    Severity.HIGH: ("High", "#ef4444"),          # red    — was orange
    Severity.CRITICAL: ("Critical", "#b91c1c"), # deep red
}

STATUS_COLOR = {"running": "#22c55e", "stopped": "#6b7280", "error": "#ef4444"}
HEALTH_COLOR = {"ok": "#22c55e", "degraded": "#f59e0b", "critical": "#ef4444",
                "failed": "#b91c1c", "off": "#6b7280"}

# Per-module avatar icons (by category).
CATEGORY_AVATAR = {
    "Integrity": "\U0001F9EC",   # 🧬
    "Processes": "⚙",        # ⚙
    "Network": "\U0001F310",     # 🌐
    "Signatures": "\U0001F9EA",  # 🧪
    "AI": "\U0001F916",          # 🤖
    "Deception": "\U0001FA9F",   # 🪟 (trap-like)
    "Forensics": "\U0001F52C",   # 🔬
    "Response": "\U0001F6E1",    # 🛡
    "General": "\U0001F4E1",     # 📡
}


def _avatar(category: str) -> str:
    return CATEGORY_AVATAR.get(category, CATEGORY_AVATAR["General"])


# Short codes for status-strip chips.  Modules that expose a .CODE class attr
# (all Phase-2c/2d/3 modules) use it directly; legacy modules use this table.
_FALLBACK_CODES: dict[str, str] = {
    "File Integrity Monitor": "FIM",
    "Process Monitor":        "PROC",
    "Network Monitor":        "NET",
    "Packet Sniffer":         "PCAP",
    "YARA Scanner":           "YARA",
    "AI Triage (Ollama)":     "AITR",
    "Cloud CTI Escalation":   "CTI",
    "Active Deception":       "DEC",
    "Forensics Capture":      "FOR",
    "SOAR Automation":        "SOAR",
    "Posture Hardening":      "HARD",
    "Watchdog Monitor":       "WDOG",
}


def _short_code(mod) -> str:
    """Return a 2-5 char code for a status-strip chip."""
    code = getattr(mod, "CODE", None)
    if code:
        return str(code)
    return _FALLBACK_CODES.get(
        mod.name,
        "".join(w[0] for w in mod.name.split() if w not in {"Monitor", "Module"})[:5].upper()
        or mod.name[:4].upper(),
    )


def _sev_item(sev: Severity) -> QTableWidgetItem:
    item = QTableWidgetItem(sev.label)
    item.setForeground(QColor(SEVERITY_COLOR.get(sev, "#e5e7eb")))
    return item


# Non-modal dialog registry: keep references so garbage-collection doesn't close
# windows the user left open, while letting them click back to the main window.
_OPEN_DIALOGS: list = []


def _show_nonmodal(dlg):
    """Show a dialog NON-modally (user can click out and return later)."""
    try:
        dlg.setModal(False)
    except Exception:
        pass
    _OPEN_DIALOGS.append(dlg)
    def _drop(*_):
        try:
            _OPEN_DIALOGS.remove(dlg)
        except ValueError:
            pass
    try:
        dlg.finished.connect(_drop)
    except Exception:
        pass
    dlg.show()
    dlg.raise_()
    try:
        dlg.activateWindow()
    except Exception:
        pass
    return dlg


def _copy_event_to_clipboard(event) -> None:
    """Copy a bus Event's full record to the clipboard as readable text."""
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(getattr(event, "ts", time.time())))
        sev = getattr(event, "severity", None)
        sev = sev.label if hasattr(sev, "label") else str(sev)
        rec = {
            "time": ts, "module": getattr(event, "module", ""), "severity": sev,
            "message": getattr(event, "message", ""), "details": getattr(event, "details", {}),
        }
        QGuiApplication.clipboard().setText(json.dumps(rec, indent=2, default=str))
    except Exception:
        pass


def _soar_queue_path():
    from pathlib import Path as _P
    d = _P(__file__).resolve().parents[3] / "shared_logs"
    d.mkdir(parents=True, exist_ok=True)
    return d / "soar_queue.json"


def _persist_soar_queue(event) -> None:
    """Append a Block→SOAR request to a persisted JSON-lines file (scrollback)."""
    try:
        rec = {
            "ts": time.time(),
            "origin_module": getattr(event, "module", ""),
            "severity": getattr(getattr(event, "severity", None), "label", ""),
            "message": getattr(event, "message", "")[:400],
            "details": getattr(event, "details", {}),
            "status": "QUEUED — review required",
        }
        with open(_soar_queue_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass


def _read_soar_queue(limit: int = 500) -> list:
    out = []
    try:
        p = _soar_queue_path()
        if not p.exists():
            return out
        for line in p.read_text(encoding="utf-8").splitlines()[-limit:]:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return out


def _section(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("SectionTitle")
    return lbl


# ── Stat cards ───────────────────────────────────────────────────────────────
# Modules whose events are internal chatter, excluded from alert/threat counts.
NOISE_MODULES = ("Self-Test", "Status", "Console")


def _sev_color(sev) -> str:
    """Colour for a Severity, reusing the dashboard THREAT palette."""
    return THREAT.get(sev, ("", "#e5e7eb"))[1]


def _mitre_of(ev) -> str:
    """Best-effort extract of a MITRE/technique id from an event's details, so a
    threat can be matched to a stage-able remediation. Empty string if none."""
    d = getattr(ev, "details", None) or {}
    for key in ("mitre_id", "mitre", "technique_id", "technique", "tid", "ttp"):
        val = d.get(key)
        if val:
            return str(val)
    return ""


class StatCard(QFrame):
    """A dashboard summary tile. Now clickable — emits `clicked` on left press."""

    clicked = Signal()

    def __init__(self, label: str) -> None:
        super().__init__()
        self.setObjectName("Card")
        self.setCursor(Qt.PointingHandCursor)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.value = QLabel("—")
        self.value.setObjectName("CardValue")
        lay.addWidget(self.value)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        cap = QLabel(label)
        cap.setObjectName("CardLabel")
        row.addWidget(cap)
        row.addStretch(1)
        chevron = QLabel("›")          # ›  affordance: this tile opens a view
        chevron.setStyleSheet("color:#6b7280; font-size:14px; font-weight:bold;")
        row.addWidget(chevron)
        lay.addLayout(row)

    def set(self, text: str, color: str = "#ffffff") -> None:
        self.value.setText(text)
        self.value.setStyleSheet(f"color: {color};")

    def mousePressEvent(self, e) -> None:       # noqa: N802 (Qt signature)
        if e.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(e)


class DashboardCards(QWidget):
    def __init__(self, bus, storage, manager) -> None:
        super().__init__()
        self.bus, self.storage, self.manager = bus, storage, manager
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)
        self.c_modules = StatCard("Modules running")
        self.c_alerts = StatCard("Alerts (24h)")
        self.c_crit = StatCard("Critical (24h)")
        self.c_threat = StatCard("Threat level")
        for c in (self.c_modules, self.c_alerts, self.c_crit, self.c_threat):
            lay.addWidget(c)
        # Each tile opens its own focused detail window.
        self.c_modules.clicked.connect(self._open_modules)
        self.c_alerts.clicked.connect(self._open_alerts)
        self.c_crit.clicked.connect(self._open_critical)
        self.c_threat.clicked.connect(self._open_threat)
        # Cache the last-seen storage max_ts so count_since() only runs when new
        # events actually arrive — avoids a SQLite COUNT query every 2 s.
        self._last_storage_ts: float = 0.0
        self._cached_count: int = 0

    def refresh(self) -> None:
        running = sum(1 for m in self.manager.modules.values() if m.status == "running")
        self.c_modules.set(f"{running}/{len(self.manager.modules)}")
        cur_ts = self.storage.max_ts()
        if cur_ts != self._last_storage_ts:
            self._cached_count = self.storage.count_since(time.time() - 86400)
            self._last_storage_ts = cur_ts
        self.c_alerts.set(str(self._cached_count))

        events = self.bus.recent(200)
        crit = sum(1 for e in events if e.severity == Severity.CRITICAL
                   and e.module not in NOISE_MODULES)
        self.c_crit.set(str(crit), "#ef4444" if crit else "#ffffff")

        label, color = threat_label(events)
        self.c_threat.set(label, color)

    # ── Drill-down windows ───────────────────────────────────────────────────
    def _open_modules(self) -> None:
        _show_nonmodal(ModulesStatusWindow(self.manager, self.bus, self))

    def _open_alerts(self) -> None:
        _show_nonmodal(EventsWindow("Alerts — last 24 hours", self.bus, self.storage,
                                    min_sev=Severity.LOW, parent=self))

    def _open_critical(self) -> None:
        _show_nonmodal(EventsWindow("Critical alerts — last 24 hours", self.bus, self.storage,
                                    min_sev=Severity.CRITICAL, parent=self))

    def _open_threat(self) -> None:
        # Resolve Center: list CRITICAL/HIGH alerts with Allow/Block/Research/Apply/
        # Ignore so the operator can clear false positives and get back to Secure.
        from angerona.gui.resolve_center import ResolveCenter
        _show_nonmodal(ResolveCenter(self.bus, self.storage, self.manager, self))


# ── Shared helper: fill a table with events ───────────────────────────────────
def _fill_event_table(table: QTableWidget, events: list) -> None:
    table.setRowCount(0)
    for ev in events:
        r = table.rowCount()
        table.insertRow(r)
        when = time.strftime("%m-%d %H:%M:%S", time.localtime(getattr(ev, "ts", time.time())))
        sev = getattr(ev, "severity", Severity.INFO)
        sev_item = QTableWidgetItem(sev.label if hasattr(sev, "label") else str(sev))
        sev_item.setForeground(QColor(_sev_color(sev)))
        table.setItem(r, 0, QTableWidgetItem(when))
        table.setItem(r, 1, sev_item)
        table.setItem(r, 2, QTableWidgetItem(getattr(ev, "module", "")))
        table.setItem(r, 3, QTableWidgetItem(getattr(ev, "message", "")))
        table.item(r, 0).setData(Qt.UserRole, ev)


# ── Alerts / Critical drill-down window ───────────────────────────────────────
class EventsWindow(QDialog):
    """A standalone window listing events at/above a severity over the last 24h.
    Used for both the Alerts tile (min_sev=LOW) and Critical tile (CRITICAL)."""

    def __init__(self, title, bus, storage, min_sev=Severity.LOW,
                 window_s=86400, parent=None) -> None:
        super().__init__(parent)
        self.bus, self.storage = bus, storage
        self.min_sev, self.window_s = min_sev, window_s
        self.setWindowTitle(title)
        self.setMinimumSize(760, 520)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        root = QVBoxLayout(self)
        head = QLabel(title)
        head.setObjectName("PageTitle")
        root.addWidget(head)
        self.count_lbl = QLabel("")
        self.count_lbl.setStyleSheet("color:#9aa4b2;")
        root.addWidget(self.count_lbl)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Time", "Severity", "Module", "Message"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        # Click a row → open the full Alert detail window (Allow/Block/Analyze/
        # Research), so the Alerts & Critical dashboard boxes expose the same
        # actions as the main Live Alerts feed.
        self.table.cellClicked.connect(self._open_detail)
        root.addWidget(self.table)

        hint = QLabel("Click a row for full detail + actions (Allow · Block · Analyze · Research)")
        hint.setStyleSheet("color:#6b7280; font-size:11px;")
        root.addWidget(hint)

        row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addStretch(1)
        row.addWidget(refresh)
        row.addWidget(close)
        root.addLayout(row)
        self._refresh()

    def _open_detail(self, row: int, _col: int) -> None:
        item = self.table.item(row, 0)
        if item is None:
            return
        ev = item.data(Qt.UserRole)
        if ev is not None:
            _show_nonmodal(AlertDetailDialog(ev, self.window()))

    def _events(self) -> list:
        now = time.time()
        try:
            evs = self.storage.events_in_window(now - self.window_s, now)
        except Exception:
            evs = self.bus.recent(500)
        out = [e for e in evs
               if getattr(e, "severity", Severity.INFO) >= self.min_sev
               and getattr(e, "module", "") not in NOISE_MODULES]
        out.sort(key=lambda e: getattr(e, "ts", 0), reverse=True)
        return out

    def _refresh(self) -> None:
        evs = self._events()
        _fill_event_table(self.table, evs)
        self.count_lbl.setText(f"{len(evs)} event(s) in the last "
                               f"{int(self.window_s // 3600)}h")


# ── Modules status drill-down window ──────────────────────────────────────────
class ModulesStatusWindow(QDialog):
    """Shows every module's live status and health at a glance."""

    def __init__(self, manager, bus, parent=None) -> None:
        super().__init__(parent)
        self.manager, self.bus = manager, bus
        self.setWindowTitle("Modules — status")
        self.setMinimumSize(680, 520)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        root = QVBoxLayout(self)
        head = QLabel("Modules — status")
        head.setObjectName("PageTitle")
        root.addWidget(head)
        self.summary = QLabel("")
        self.summary.setStyleSheet("color:#9aa4b2;")
        root.addWidget(self.summary)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Module", "Status", "Health", "Category"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        root.addWidget(self.table)

        row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addStretch(1)
        row.addWidget(refresh)
        row.addWidget(close)
        root.addLayout(row)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(1500)
        self._refresh()

    def _refresh(self) -> None:
        mods = sorted(self.manager.modules.items())
        self.table.setRowCount(0)
        running = 0
        for name, mod in mods:
            r = self.table.rowCount()
            self.table.insertRow(r)
            status = getattr(mod, "status", "?")
            running += (status == "running")
            self.table.setItem(r, 0, QTableWidgetItem(getattr(mod, "name", name)))
            st_item = QTableWidgetItem(status)
            st_item.setForeground(QColor(STATUS_COLOR.get(status, "#e5e7eb")))
            self.table.setItem(r, 1, st_item)
            health = f"{getattr(mod, 'health', 0)}%" if status == "running" else "—"
            h_item = QTableWidgetItem(health)
            h_item.setForeground(QColor(HEALTH_COLOR.get(getattr(mod, "health_state", "off"), "#e5e7eb")))
            self.table.setItem(r, 2, h_item)
            self.table.setItem(r, 3, QTableWidgetItem(getattr(mod, "category", "")))
        self.summary.setText(f"{running}/{len(mods)} modules running")


# ── Threat drill-down window (with fix / harden actions) ──────────────────────
class ThreatWindow(QDialog):
    """Lists the HIGH/CRITICAL events currently driving the threat level, with
    per-threat detail and two remediation actions wired to Posture Hardening:
      • Attempt fix  — stage a review-gated remediation for the selected threat.
      • Harden system — stage remediations for all open weaknesses.
    Nothing that changes the OS runs without an explicit confirmation."""

    _action_done = Signal(str)

    def __init__(self, bus, storage, manager, parent=None) -> None:
        super().__init__(parent)
        self.bus, self.storage, self.manager = bus, storage, manager
        self.setWindowTitle("Threat level — triggering threats")
        self.setMinimumSize(820, 640)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        root = QVBoxLayout(self)

        label, color = threat_label(self.bus.recent(200))
        head = QLabel(f"Threat level: {label}")
        head.setObjectName("PageTitle")
        head.setStyleSheet(f"color:{color};")
        root.addWidget(head)
        sub = QLabel("Only the HIGH / CRITICAL events driving this level are shown. "
                     "Select one to see details and stage a fix.")
        sub.setWordWrap(True)
        sub.setStyleSheet("color:#9aa4b2;")
        root.addWidget(sub)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Time", "Severity", "Module", "Message"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.cellClicked.connect(self._on_select)
        root.addWidget(self.table)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(180)
        self.detail.setPlaceholderText("Select a threat to inspect its details.")
        root.addWidget(self.detail)

        controls = QHBoxLayout()
        self.fix_btn = QPushButton("Attempt fix (stage)")
        self.fix_btn.clicked.connect(self._attempt_fix)
        self.apply_btn = QPushButton("Apply staged fix…")
        self.apply_btn.clicked.connect(self._apply_fix)
        self.apply_btn.setEnabled(False)
        self.harden_btn = QPushButton("Harden system")
        self.harden_btn.clicked.connect(self._harden)
        self.blast_btn = QPushButton("Blast radius")
        self.blast_btn.clicked.connect(self._open_blast)
        self.collision_btn = QPushButton("Shark vs Shield")
        self.collision_btn.clicked.connect(self._open_collision)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        controls.addWidget(self.fix_btn)
        controls.addWidget(self.apply_btn)
        controls.addWidget(self.harden_btn)
        controls.addWidget(self.blast_btn)
        controls.addWidget(self.collision_btn)
        controls.addStretch(1)
        controls.addWidget(refresh)
        root.addLayout(controls)

        self.status_lbl = QLabel("")
        self.status_lbl.setWordWrap(True)
        root.addWidget(self.status_lbl)

        self._action_done.connect(self._on_action_done)
        self._selected_mitre = ""
        self._busy = False
        self._refresh()

    # ── data ─────────────────────────────────────────────────────────────────
    def _threats(self) -> list:
        evs = [e for e in self.bus.recent(300)
               if getattr(e, "severity", Severity.INFO) >= Severity.HIGH
               and getattr(e, "module", "") not in NOISE_MODULES]
        evs.sort(key=lambda e: getattr(e, "ts", 0), reverse=True)
        return evs

    def _refresh(self) -> None:
        _fill_event_table(self.table, self._threats())
        if self.table.rowCount() == 0:
            self.detail.setPlainText("No active HIGH/CRITICAL threats. You're clear.")

    def _posture(self):
        """Find the Posture Hardening module by capability (name-independent)."""
        for m in self.manager.modules.values():
            if hasattr(m, "generate_remediation") and hasattr(m, "weaknesses"):
                return m
        return None

    def _selected_event(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        cell = self.table.item(row, 0)
        return cell.data(Qt.UserRole) if cell else None

    # ── interactions ─────────────────────────────────────────────────────────
    def _on_select(self, *_):
        ev = self._selected_event()
        if not ev:
            return
        self._selected_mitre = _mitre_of(ev)
        lines = [
            f"Module:    {getattr(ev, 'module', '')}",
            f"Severity:  {getattr(ev, 'severity', Severity.INFO).label}",
            f"Time:      {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(getattr(ev, 'ts', 0)))}",
            f"Technique: {self._selected_mitre or '(none detected)'}",
            "",
            getattr(ev, "message", ""),
        ]
        details = getattr(ev, "details", None)
        if details:
            try:
                lines += ["", "Details:", json.dumps(details, indent=2, default=str)]
            except Exception:
                lines += ["", f"Details: {details}"]
        self.detail.setPlainText("\n".join(lines))
        self.apply_btn.setEnabled(False)

    def _guard(self) -> bool:
        if self._busy:
            self.status_lbl.setText("Working… please wait for the current action to finish.")
            return False
        posture = self._posture()
        if posture is None:
            self.status_lbl.setText("[!] Posture Hardening module is not available.")
            return False
        return True

    def _run_async(self, fn) -> None:
        self._busy = True
        self.fix_btn.setEnabled(False)
        self.harden_btn.setEnabled(False)
        self.status_lbl.setText("Working…")

        def work():
            try:
                msg = fn()
            except Exception as exc:               # never let a worker crash the app
                msg = f"[!] Action failed: {exc}"
            self._action_done.emit(msg)

        threading.Thread(target=work, daemon=True).start()

    def _on_action_done(self, msg: str) -> None:
        self._busy = False
        self.fix_btn.setEnabled(True)
        self.harden_btn.setEnabled(True)
        self.status_lbl.setText(msg)

    def _attempt_fix(self) -> None:
        if not self._guard():
            return
        ev = self._selected_event()
        if not ev:
            self.status_lbl.setText("Select a threat first.")
            return
        mitre = _mitre_of(ev)
        posture = self._posture()
        if not mitre:
            self.status_lbl.setText(
                "This threat has no MITRE technique id, so it can't be auto-staged. "
                "Open the Posture Hardening module to review weaknesses manually.")
            return

        def do():
            res = posture.generate_remediation(mitre)
            if isinstance(res, dict) and res.get("ok", True) and not res.get("error"):
                self._selected_mitre = mitre
                return (f"[+] Staged a review-gated remediation for {mitre}. "
                        f"Inspect it, then click 'Apply staged fix…' to run it.")
            return f"[!] Could not stage a fix for {mitre}: {res}"

        self._run_async(do)
        # enable Apply once staging kicks off; execution still confirms first
        self.apply_btn.setEnabled(True)

    def _apply_fix(self) -> None:
        if not self._guard():
            return
        mitre = self._selected_mitre
        if not mitre:
            self.status_lbl.setText("Stage a fix first with 'Attempt fix'.")
            return
        from PySide6.QtWidgets import QMessageBox
        if QMessageBox.question(
                self, "Apply staged remediation?",
                f"This will EXECUTE the staged remediation script for {mitre} on this "
                f"machine (PowerShell, as Administrator).\n\nProceed?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        posture = self._posture()

        def do():
            res = posture.execute_remediation(mitre, authorized=True)
            if isinstance(res, dict) and res.get("returncode") == 0:
                v = res.get("verification", "")
                return f"[+] Remediation applied for {mitre}. Verification: {v or 'n/a'}"
            return f"[!] Remediation for {mitre} did not complete cleanly: {res}"

        self._run_async(do)

    def _harden(self) -> None:
        if not self._guard():
            return
        posture = self._posture()

        def do():
            try:
                weaknesses = posture.weaknesses(status="VULNERABLE")
            except Exception:
                weaknesses = posture.weaknesses()
            if not weaknesses:
                return "[+] No open weaknesses on record — nothing to harden."
            staged = 0
            for w in weaknesses:
                try:
                    posture.generate_remediation(w["mitre_id"])
                    staged += 1
                except Exception:
                    pass
            return (f"[+] Staged review-gated remediations for {staged}/{len(weaknesses)} "
                    f"open weakness(es). Review and apply them per-threat.")

        self._run_async(do)

    # ── blast radius + collision view ────────────────────────────────────────
    def _prov(self):
        """Find the Provenance Graph module by capability (name-independent)."""
        for m in self.manager.modules.values():
            if hasattr(m, "ancestry") and hasattr(m, "subtree"):
                return m
        return None

    def _open_blast(self) -> None:
        ev = self._selected_event()
        pid = None
        if ev is not None:
            d = getattr(ev, "details", None) or {}
            for k in ("pid", "process_id", "target_pid"):
                if d.get(k):
                    try:
                        pid = int(d[k])
                        break
                    except (TypeError, ValueError):
                        pass
        if pid is None:
            self.status_lbl.setText("Select a threat that carries a PID to map its blast radius.")
            return
        prov = self._prov()
        if prov is None:
            self.status_lbl.setText("[!] Provenance Graph module is not available.")
            return
        BlastRadiusDialog(prov, pid, self).exec()

    def _open_collision(self) -> None:
        CollisionView(self).exec()


# ── Blast-radius provenance tree ─────────────────────────────────────────────
def build_blast_tree(prov, target_pid: int) -> dict:
    """Core data logic for a PID blast radius (blueprint contract):
    {'origin': <ancestry, root-cause chain>, 'blast_radius': <subtree spawned>}.
    Both are lists of provenance node dicts ({id, kind, label, ts, meta})."""
    return {"origin": prov.ancestry(target_pid),
            "blast_radius": prov.subtree(target_pid)}


class BlastRadiusDialog(QDialog):
    """Renders build_blast_tree(pid) as a hierarchical tree: the upstream origin
    chain that led to the process, and the downstream blast radius it spawned
    (child processes, files written, network connections opened)."""

    def __init__(self, prov, pid: int, parent=None) -> None:
        super().__init__(parent)
        self.prov, self.pid = prov, pid
        self.setWindowTitle(f"Blast radius — PID {pid}")
        self.setMinimumSize(680, 560)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem
        self._QTreeWidgetItem = QTreeWidgetItem
        root = QVBoxLayout(self)
        head = QLabel(f"Blast radius — PID {pid}")
        head.setObjectName("PageTitle")
        root.addWidget(head)
        self.summary = QLabel("")
        self.summary.setStyleSheet("color:#9aa4b2;")
        root.addWidget(self.summary)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Node", "Kind", "Detail"])
        self.tree.setColumnWidth(0, 300)
        root.addWidget(self.tree)

        row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addStretch(1)
        row.addWidget(refresh)
        row.addWidget(close)
        root.addLayout(row)
        self._refresh()

    def _node_item(self, node: dict):
        label = node.get("label", node.get("id", "?"))
        kind = node.get("kind", "")
        meta = node.get("meta") or {}
        detail = ", ".join(f"{k}={v}" for k, v in meta.items()) if meta else node.get("id", "")
        it = self._QTreeWidgetItem([str(label), str(kind), str(detail)])
        colour = {"file": "#f59e0b", "net": "#38bdf8"}.get(str(kind).lower(), "#e5e7eb")
        it.setForeground(0, QColor(colour))
        return it

    def _refresh(self) -> None:
        tree = build_blast_tree(self.prov, self.pid)
        origin, blast = tree["origin"], tree["blast_radius"]
        self.tree.clear()
        Item = self._QTreeWidgetItem
        origin_root = Item([f"Origin — how PID {self.pid} came to exist", "", f"{len(origin)} node(s)"])
        for n in origin:
            origin_root.addChild(self._node_item(n))
        blast_root = Item([f"Blast radius — what PID {self.pid} spawned/touched", "",
                           f"{len(blast)} node(s)"])
        for n in blast:
            blast_root.addChild(self._node_item(n))
        self.tree.addTopLevelItem(origin_root)
        self.tree.addTopLevelItem(blast_root)
        origin_root.setExpanded(True)
        blast_root.setExpanded(True)
        self.summary.setText(f"{len(origin)} ancestor node(s) upstream, "
                             f"{len(blast)} node(s) in the downstream blast radius.")


# ── Shark-vs-Shield collision view ───────────────────────────────────────────
# Map the module that caught a footprint to its hardening ring.
_RING_OF_MODULE = {
    "file integrity monitor": "Ring 1 · Driver/File Shield",
    "process monitor": "Ring 1 · Driver/File Shield",
    "upstream threat intel sync": "Ring 1 · Driver-Intel",
    "api patch / anti-blinding detector": "Ring 2 · In-Memory Integrity",
    "indirect syscall bridge": "Ring 2 · In-Memory Integrity",
    "telemetry canary drill": "Ring 3 · Runtime Vitality",
    "etw core listener": "Ring 3 · Runtime Vitality",
    "anti-suspension heartbeat": "Ring 3 · Runtime Vitality",
    "posture hardening": "Ring 4 · Posture Evolution",
    "active response soar": "Ring 4 · Posture Evolution",
    "soar automation": "Ring 4 · Posture Evolution",
    "yara scanner": "Ring 1 · Driver/File Shield",
}


def _ring_for(module_name: str) -> str:
    return _RING_OF_MODULE.get(str(module_name or "").lower().strip(), "—")


class CollisionView(QDialog):
    """Shark-vs-Shield collision view: reads the latest red-team After-Action
    Report and shows, per simulated technique, whether a defensive ring caught
    it and which one — the 'which ring of the circle caught the footprint' view."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Shark vs Shield — collision view")
        self.setMinimumSize(880, 560)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        root = QVBoxLayout(self)
        head = QLabel("Shark vs Shield — collision view")
        head.setObjectName("PageTitle")
        root.addWidget(head)
        self.summary = QLabel("")
        self.summary.setStyleSheet("color:#9aa4b2;")
        self.summary.setWordWrap(True)
        root.addWidget(self.summary)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Technique / stage", "Caught?", "Ring", "Detected by", "Latency"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.cellDoubleClicked.connect(self._on_verdict)   # row → detail + actions
        self._row_verdicts: dict = {}
        root.addWidget(self.table)
        _hint = QLabel("Double-click a technique for full detail + a MITRE ATT&CK link.")
        _hint.setStyleSheet("color:#64748b; font-size:11px;")
        root.addWidget(_hint)

        row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addStretch(1)
        row.addWidget(refresh)
        row.addWidget(close)
        root.addLayout(row)
        self._refresh()

    @staticmethod
    def _aar_paths() -> list:
        try:
            repo = Path(__file__).resolve().parents[3]
        except Exception:
            repo = Path(".")
        return [repo / "diagnostics" / "redteam_aar.json",
                repo / "diagnostics" / "shark_aar.json"]

    def _load_verdicts(self) -> tuple:
        for p in self._aar_paths():
            try:
                if p.exists():
                    data = json.loads(p.read_text(encoding="utf-8"))
                    return data.get("verdicts", []), str(p)
            except Exception:
                continue
        return [], ""

    def _refresh(self) -> None:
        verdicts, src = self._load_verdicts()
        self.table.setRowCount(0)
        self._row_verdicts = {}
        caught = 0
        for v in verdicts:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self._row_verdicts[r] = v
            is_caught = bool(v.get("caught"))
            caught += is_caught
            by = v.get("detected_by") or ""
            lat = v.get("detect_latency_s")
            tech = f"{v.get('stage', '')} — {v.get('technique', '')}".strip(" —")
            self.table.setItem(r, 0, QTableWidgetItem(tech))
            c_item = QTableWidgetItem("BLOCKED" if is_caught else "MISSED")
            c_item.setForeground(QColor("#22c55e" if is_caught else "#ef4444"))
            self.table.setItem(r, 1, c_item)
            self.table.setItem(r, 2, QTableWidgetItem(_ring_for(by) if is_caught else "—"))
            self.table.setItem(r, 3, QTableWidgetItem(by))
            self.table.setItem(r, 4, QTableWidgetItem(
                f"{lat:.1f}s" if isinstance(lat, (int, float)) else "—"))
        n = len(verdicts)
        if not n:
            self.summary.setText("No red-team After-Action Report found yet. Run a Shark "
                                 "drill, then reopen this view to see the ring-by-ring collision.")
        else:
            self.summary.setText(f"{caught}/{n} simulated technique(s) intercepted by the shield. "
                                 f"Source: {src}")

    def _on_verdict(self, row: int, _col: int) -> None:
        v = getattr(self, "_row_verdicts", {}).get(row)
        if v:
            self._verdict_detail(v)

    def _verdict_detail(self, v: dict) -> None:
        import re
        import webbrowser
        import json as _json
        from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                                       QTextEdit, QPushButton, QApplication)
        tech = f"{v.get('stage', '')} — {v.get('technique', '')}".strip(" —")
        caught = bool(v.get("caught"))
        m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", _json.dumps(v))
        tid = m.group(0) if m else ""

        dlg = QDialog(self); dlg.setWindowTitle(f"Collision detail — {tech or 'technique'}")
        dlg.resize(640, 480)
        try:
            dlg.setStyleSheet(self.styleSheet())
        except Exception:
            pass
        lay = QVBoxLayout(dlg)
        colour = "#22c55e" if caught else "#ef4444"
        status = "BLOCKED by the shield" if caught else "MISSED — not intercepted"
        lay.addWidget(QLabel(f"<b>{tech or 'Technique'}</b><br>Result: "
                             f"<b style='color:{colour}'>{status}</b>"))
        det = QTextEdit(); det.setReadOnly(True)
        det.setPlainText("\n".join(f"{k}: {val}" for k, val in v.items()))
        lay.addWidget(det)

        rowb = QHBoxLayout()
        if tid:
            base = tid.split(".")[0]
            url = (f"https://attack.mitre.org/techniques/{base}/{tid.split('.')[1]}/"
                   if "." in tid else f"https://attack.mitre.org/techniques/{tid}/")
            b_mitre = QPushButton(f"MITRE ATT&CK ({tid})")
            b_mitre.clicked.connect(lambda: webbrowser.open(url))
            rowb.addWidget(b_mitre)
        b_copy = QPushButton("Copy details")
        b_copy.clicked.connect(lambda: QApplication.clipboard().setText(det.toPlainText()))
        rowb.addWidget(b_copy)
        b_close = QPushButton("Close"); b_close.clicked.connect(dlg.accept)
        rowb.addWidget(b_close)
        lay.addLayout(rowb)
        dlg.exec()


# ── Red Team Simulation config (unified Shark + APT, difficulty/target/custom) ─
class CustomTechniqueStore:
    """Tiny JSON-backed library of user-defined benign techniques (name + payload).
    Persisted so saved techniques survive restarts and can be re-used, edited, or
    deleted. Payload is only ever written as an inert marker at run time."""

    def __init__(self, path) -> None:
        self.path = Path(path)
        self._items = self._load()

    def _load(self) -> list:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [d for d in data if isinstance(d, dict) and d.get("name")]
        except Exception:
            return []

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._items, indent=2), encoding="utf-8")
        except Exception:
            pass

    def names(self) -> list:
        return [i["name"] for i in self._items]

    def get(self, name: str):
        return next((i for i in self._items if i["name"] == name), None)

    def upsert(self, name: str, payload: str) -> None:
        it = self.get(name)
        if it:
            it["payload"] = payload
        else:
            self._items.append({"name": name, "payload": payload})
        self.save()

    def delete(self, name: str) -> None:
        self._items = [i for i in self._items if i["name"] != name]
        self.save()


class RedTeamSimulationDialog(QDialog):
    """Configure one Red Team Simulation: which scenarios (Shark / APT Red-Team),
    difficulty (recursion depth), target directory, and an OPTIONAL custom benign
    technique. The custom text is written verbatim to an INERT marker file — it is
    never executed, interpreted, or run. This is detection testing, not a payload
    runner."""

    _COMPLEXITY = {"Low (1 phase)": 1, "Medium (2 phases)": 2, "High (3 phases)": 3}

    def __init__(self, parent=None, default_target: str = "", store_path=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Run Red Team Simulation")
        self.setMinimumSize(680, 760)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        self._cfg = None
        if store_path is None:
            store_path = Path(__file__).resolve().parents[3] / "custom_techniques.json"
        self.store = CustomTechniqueStore(store_path)
        root = QVBoxLayout(self)
        head = QLabel("Run Red Team Simulation")
        head.setObjectName("PageTitle")
        root.addWidget(head)
        intro = QLabel("Unannounced, non-destructive adversary simulation against THIS instance. "
                       "Every technique is a benign, reversible marker — no real exploit, secret, "
                       "driver, or persistence is ever executed or touched.")
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#9aa4b2;")
        root.addWidget(intro)

        root.addWidget(_section("Scenarios"))
        self.cb_shark = QCheckBox("Shark — lure drops, discovery, BYOVD driver-drop, exfil markers")
        self.cb_shark.setChecked(True)
        self.cb_apt = QCheckBox("APT Red-Team — credential-access, WMI persistence, defense-evasion markers")
        self.cb_apt.setChecked(True)
        root.addWidget(self.cb_shark)
        root.addWidget(self.cb_apt)

        root.addWidget(_section("Difficulty / depth"))
        drow = QHBoxLayout()
        drow.addWidget(QLabel("Complexity:"))
        self.complexity = QComboBox()
        self.complexity.addItems(list(self._COMPLEXITY.keys()))
        self.complexity.setCurrentText("Medium (2 phases)")
        drow.addWidget(self.complexity)
        drow.addStretch(1)
        root.addLayout(drow)
        hint = QLabel("Higher complexity runs more recursive phases (recon → escalate → persist), "
                      "each pass chaining deeper — a longer test that makes richer defense logs.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#6b7280; font-size:11px;")
        root.addWidget(hint)

        root.addWidget(_section("Target"))
        trow = QHBoxLayout()
        trow.addWidget(QLabel("Marker directory:"))
        self.target = QLineEdit(default_target)
        trow.addWidget(self.target)
        root.addLayout(trow)
        thint = QLabel("Where benign marker files are written. A File-Integrity-Monitor-watched "
                       "path makes the test most visible; leave as-is for the default.")
        thint.setWordWrap(True)
        thint.setStyleSheet("color:#6b7280; font-size:11px;")
        root.addWidget(thint)

        root.addWidget(_section("Custom techniques — your saved library (scroll · click to edit)"))
        from PySide6.QtWidgets import QListWidget
        clib = QHBoxLayout()
        self.custom_list = QListWidget()
        self.custom_list.setMaximumHeight(120)
        self.custom_list.itemClicked.connect(self._on_custom_select)
        clib.addWidget(self.custom_list, 1)
        libbtns = QVBoxLayout()
        b_new = QPushButton("New")
        b_new.clicked.connect(self._new_custom)
        b_save = QPushButton("Save / Update")
        b_save.clicked.connect(self._save_custom)
        b_del = QPushButton("Delete")
        b_del.clicked.connect(self._delete_custom)
        for b in (b_new, b_save, b_del):
            libbtns.addWidget(b)
        libbtns.addStretch(1)
        clib.addLayout(libbtns)
        root.addLayout(clib)

        self.custom_name = QLineEdit()
        self.custom_name.setPlaceholderText("Technique name, e.g. 'my-detection-test'")
        root.addWidget(self.custom_name)
        self.custom_payload = QPlainTextEdit()
        self.custom_payload.setPlaceholderText(
            "Paste the content / pattern / snippet you want the defense tested against. "
            "It is written verbatim to an INERT marker file and NEVER executed.")
        self.custom_payload.setMaximumHeight(110)
        root.addWidget(self.custom_payload)
        cwarn = QLabel("⚠ Safety: your text is only written to a file as detection bait — Angerona "
                       "never executes, interprets, or runs it. This tests detection; it is not a "
                       "payload runner. 'Save / Update' keeps it in your library above.")
        cwarn.setWordWrap(True)
        cwarn.setStyleSheet("color:#f59e0b; font-size:11px;")
        root.addWidget(cwarn)
        self._refresh_custom_list()

        brow = QHBoxLayout()
        brow.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        run = QPushButton("▶  Run simulation")
        run.clicked.connect(self._on_run)
        brow.addWidget(cancel)
        brow.addWidget(run)
        root.addLayout(brow)

    # ── custom-technique library CRUD ────────────────────────────────────────
    def _refresh_custom_list(self) -> None:
        self.custom_list.clear()
        for nm in self.store.names():
            self.custom_list.addItem(nm)

    def _on_custom_select(self, item) -> None:
        rec = self.store.get(item.text())
        if rec:
            self.custom_name.setText(rec.get("name", ""))
            self.custom_payload.setPlainText(rec.get("payload", ""))

    def _new_custom(self) -> None:
        self.custom_list.clearSelection()
        self.custom_name.clear()
        self.custom_payload.clear()
        self.custom_name.setFocus()

    def _save_custom(self) -> None:
        name = self.custom_name.text().strip()
        payload = self.custom_payload.toPlainText().strip()
        if not (name and payload):
            return
        self.store.upsert(name, payload)
        self._refresh_custom_list()

    def _delete_custom(self) -> None:
        items = self.custom_list.selectedItems()
        name = items[0].text() if items else self.custom_name.text().strip()
        if name:
            self.store.delete(name)
            self._new_custom()
            self._refresh_custom_list()

    def _on_run(self) -> None:
        name = self.custom_name.text().strip()
        payload = self.custom_payload.toPlainText().strip()
        custom = {"name": name, "payload": payload} if (name and payload) else None
        self._cfg = {
            "complexity": self._COMPLEXITY.get(self.complexity.currentText(), 2),
            "run_shark": self.cb_shark.isChecked(),
            "run_redteam": self.cb_apt.isChecked(),
            "target_dir": self.target.text().strip() or None,
            "custom": custom,
        }
        self.accept()

    def result_config(self) -> dict:
        return self._cfg or {"complexity": 1, "run_shark": False, "run_redteam": False,
                             "target_dir": None, "custom": None}


# ── Modules panel ────────────────────────────────────────────────────────────
class ModulesPanel(QFrame):
    def __init__(self, manager, bus) -> None:
        super().__init__()
        self.setObjectName("Panel")
        self.manager = manager
        self.bus = bus
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 14)
        lay.addWidget(_section("Modules"))
        hint = QLabel("Click a row to inspect. Toggle to enable/disable.")
        hint.setStyleSheet("color:#6b7280; font-size:11px;")
        lay.addWidget(hint)

        sort_row = QHBoxLayout()
        sort_row.addWidget(QLabel("Sort by:"))
        self._sort_combo = QComboBox()
        self._sort_combo.addItems(["Name", "On/Off", "Status", "Category"])
        self._sort_combo.currentIndexChanged.connect(lambda *_: self._build())
        sort_row.addWidget(self._sort_combo)
        sort_row.addStretch(1)
        lay.addLayout(sort_row)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["On", "Module", "Status", "Category"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.cellClicked.connect(self._on_click)
        lay.addWidget(self.table)
        self._built_count = -1
        self._build()

    def _sorted_items(self):
        items = list(self.manager.modules.items())
        mode = self._sort_combo.currentText() if hasattr(self, "_sort_combo") else "Name"
        if mode == "On/Off":
            # enabled first, then by name
            return sorted(items, key=lambda kv: (not self.manager.is_enabled(kv[0]), kv[0].lower()))
        if mode == "Status":
            return sorted(items, key=lambda kv: (getattr(kv[1], "status", ""), kv[0].lower()))
        if mode == "Category":
            return sorted(items, key=lambda kv: (getattr(kv[1], "category", ""), kv[0].lower()))
        return sorted(items, key=lambda kv: kv[0].lower())

    def _build(self) -> None:
        self.table.setRowCount(0)
        for name, mod in self._sorted_items():
            r = self.table.rowCount()
            self.table.insertRow(r)
            chk = QCheckBox()
            chk.setChecked(self.manager.is_enabled(name))
            chk.stateChanged.connect(lambda st, n=name: self.manager.set_enabled(n, bool(st)))
            wrap = QWidget(); wlay = QHBoxLayout(wrap)
            wlay.setAlignment(Qt.AlignCenter); wlay.setContentsMargins(0, 0, 0, 0)
            wlay.addWidget(chk)
            self.table.setCellWidget(r, 0, wrap)
            name_item = QTableWidgetItem(f"{_avatar(mod.category)}  {mod.name}")
            name_item.setData(Qt.UserRole, mod.name)
            self.table.setItem(r, 1, name_item)
            self.table.setItem(r, 2, QTableWidgetItem(mod.status))
            self.table.setItem(r, 3, QTableWidgetItem(mod.category))
        self.table.setColumnWidth(0, 36)
        self._built_count = len(self.manager.modules)

    def refresh(self) -> None:
        # Rebuild once discovery has populated modules (fixes the empty table).
        if self._built_count != len(self.manager.modules):
            self._build()
            return
        self.table.setUpdatesEnabled(False)
        for r in range(self.table.rowCount()):
            name_item = self.table.item(r, 1)
            if not name_item:
                continue
            mod = self.manager.modules.get(name_item.data(Qt.UserRole))
            if not mod:
                continue
            txt = (f"{mod.status} {mod.health}%"
                   if mod.status == "running" else mod.status)
            existing = self.table.item(r, 2)
            if existing and existing.text() == txt:
                continue                     # no change — avoid creating a new item
            item = QTableWidgetItem(txt)
            item.setForeground(QColor(HEALTH_COLOR.get(mod.health_state, "#e5e7eb")))
            self.table.setItem(r, 2, item)
        self.table.setUpdatesEnabled(True)

    def _on_click(self, row: int, col: int) -> None:
        if col == 0:                         # checkbox column — don't open inspector
            return
        name_item = self.table.item(row, 1)
        if not name_item:
            return
        mod = self.manager.modules.get(name_item.data(Qt.UserRole))
        if mod:
            _show_nonmodal(ModuleInspector(self.manager, self.bus, mod, self))


# ── Module inspector ─────────────────────────────────────────────────────────
class ModuleInspector(QDialog):
    _test_done = Signal(str)

    def __init__(self, manager, bus, module, parent=None) -> None:
        super().__init__(parent)
        self.manager, self.bus, self.module = manager, bus, module
        self.setWindowTitle(f"Module — {module.name}")
        self.setMinimumSize(660, 560)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        root = QVBoxLayout(self)

        title = QLabel(module.name); title.setObjectName("PageTitle")
        root.addWidget(title)
        meta = QLabel(f"{module.category} · v{module.version}")
        meta.setStyleSheet("color:#9aa4b2;")
        root.addWidget(meta)

        tabs = QTabWidget()
        tabs.addTab(self._overview_tab(),  "Overview")
        tabs.addTab(self._perf_tab(),      "⚡ Performance")
        tabs.addTab(self._history_tab(),   "📋 History")
        tabs.addTab(self._deps_tab(),      "🔗 Dependencies")
        if self._is_ai():
            tabs.addTab(self._api_keys_tab(), "API Keys")
            tabs.addTab(self._help_tab(), "Help")
        root.addWidget(tabs)
        self._test_done.connect(self.test_lbl.setText)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(2000)   # 2 s is sufficient; 1 s was unnecessary CPU churn
        self._refresh()

    def _is_ai(self) -> bool:
        m = self.module
        return m.category == "AI" or "AI" in m.name or "Cloud" in m.name

    # ── Tabs ─────────────────────────────────────────────────────────────────
    def _overview_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        desc = QLabel(self.module.description); desc.setWordWrap(True)
        desc.setStyleSheet("color:#cbd5e1;"); lay.addWidget(desc)
        self.status_lbl = QLabel(""); lay.addWidget(self.status_lbl)
        self.error_lbl = QLabel(""); self.error_lbl.setWordWrap(True)
        self.error_lbl.setStyleSheet("color:#ef4444;"); lay.addWidget(self.error_lbl)
        controls = QHBoxLayout()
        self.toggle_btn = QPushButton(); self.toggle_btn.clicked.connect(self._toggle)
        restart = QPushButton("Restart module"); restart.clicked.connect(self._restart)
        selftest = QPushButton("Run self-test"); selftest.clicked.connect(self._selftest)
        edit_btn = QPushButton("✎ Edit code (Sandbox)")
        edit_btn.setToolTip("Open this module's .py in the Live-Fire Sandbox to view/edit/"
                            "hot-reload it (AST-checked, revert + history, warns before apply).")
        edit_btn.clicked.connect(self._open_in_sandbox)
        controls.addWidget(self.toggle_btn); controls.addWidget(restart)
        controls.addWidget(selftest); controls.addWidget(edit_btn); controls.addStretch(1)
        lay.addLayout(controls)
        self.test_lbl = QLabel(""); self.test_lbl.setWordWrap(True); lay.addWidget(self.test_lbl)
        lay.addWidget(_section("This module's recent events  —  click a row for full detail + actions"))
        self.feed = QTableWidget(0, 3)
        self.feed.setHorizontalHeaderLabels(["Time", "Severity", "Message"])
        self.feed.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.feed.verticalHeader().setVisible(False)
        self.feed.setEditTriggers(QTableWidget.NoEditTriggers)
        self.feed.setSelectionBehavior(QTableWidget.SelectRows)
        self.feed.cellClicked.connect(self._on_feed_click)
        lay.addWidget(self.feed)
        return w

    # ── Extra tabs ────────────────────────────────────────────────────────────

    def _perf_tab(self) -> QWidget:
        """Real-time performance metrics: throttle, event rates, health trend."""
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(_section("Module performance (auto-refreshes every 2 s)"))

        grid = QGridLayout(); grid.setColumnStretch(1, 1)
        self._p_throttle = QLabel("—")
        self._p_rate5    = QLabel("—")
        self._p_rate60   = QLabel("—")
        self._p_health   = QLabel("—")
        self._p_thread   = QLabel("—")
        for i, (lbl, val) in enumerate([
            ("Throttle multiplier:", self._p_throttle),
            ("Events (last 5 min):", self._p_rate5),
            ("Events (last 60 min):", self._p_rate60),
            ("Health %:", self._p_health),
            ("Thread status:", self._p_thread),
        ]):
            grid.addWidget(QLabel(lbl), i, 0)
            grid.addWidget(val, i, 1)
        lay.addLayout(grid)

        lay.addWidget(_section("Health trend (last 20 readings)"))
        self._p_trend = QPlainTextEdit()
        self._p_trend.setReadOnly(True)
        self._p_trend.setFixedHeight(80)
        self._p_trend.setFont(QFont("Consolas", 9))
        lay.addWidget(self._p_trend)
        self._health_trend: list[int] = []

        lay.addStretch()
        return w

    def _history_tab(self) -> QWidget:
        """Full scrollable event log for this module (all severities)."""
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(_section("All events from this module (most recent first)"))

        filt_row = QHBoxLayout()
        filt_row.addWidget(QLabel("Filter:"))
        self._hist_filter = QLineEdit()
        self._hist_filter.setPlaceholderText("keyword (Enter to apply)")
        self._hist_filter.returnPressed.connect(self._refresh_history)
        filt_row.addWidget(self._hist_filter, 1)
        lay.addLayout(filt_row)

        self._hist_table = QTableWidget(0, 3)
        self._hist_table.setHorizontalHeaderLabels(["Time", "Severity", "Message"])
        self._hist_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._hist_table.verticalHeader().setVisible(False)
        self._hist_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._hist_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._hist_table.cellClicked.connect(
            lambda r, _: _show_nonmodal(AlertDetailDialog(
                self._hist_table.item(r, 0).data(Qt.UserRole), self.window()))
            if self._hist_table.item(r, 0) and
               self._hist_table.item(r, 0).data(Qt.UserRole) else None
        )
        lay.addWidget(self._hist_table)
        return w

    def _refresh_history(self) -> None:
        kw = self._hist_filter.text().lower()
        events = [e for e in self.bus.recent(1000) if e.module == self.module.name]
        if kw:
            events = [e for e in events if kw in e.message.lower()]
        self._hist_table.setRowCount(0)
        for e in events:
            r = self._hist_table.rowCount(); self._hist_table.insertRow(r)
            ts_item = QTableWidgetItem(e.time_str)
            ts_item.setData(Qt.UserRole, e)
            self._hist_table.setItem(r, 0, ts_item)
            self._hist_table.setItem(r, 1, _sev_item(e.severity))
            self._hist_table.setItem(r, 2, QTableWidgetItem(e.message))

    def _deps_tab(self) -> QWidget:
        """Source file path, Python imports, and config fields used."""
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(_section("Module source"))

        src_path = self._find_module_src()
        path_lbl = QLabel(src_path or "(source file not found)")
        path_lbl.setStyleSheet("color:#93c5fd; font-family:Consolas;")
        path_lbl.setWordWrap(True)
        lay.addWidget(path_lbl)

        if src_path:
            open_btn = QPushButton("✎ Open in Sandbox")
            open_btn.clicked.connect(self._open_in_sandbox)
            lay.addWidget(open_btn)

        lay.addWidget(_section("Imports & dependencies"))
        deps_box = QPlainTextEdit()
        deps_box.setReadOnly(True)
        deps_box.setFont(QFont("Consolas", 9))
        deps_box.setPlainText(self._parse_imports(src_path))
        lay.addWidget(deps_box, 1)

        lay.addWidget(_section("Module metadata"))
        meta_box = QPlainTextEdit()
        meta_box.setReadOnly(True)
        meta_box.setFont(QFont("Consolas", 9))
        m = self.module
        meta_lines = [
            f"name          = {m.name}",
            f"category      = {m.category}",
            f"version       = {m.version}",
            f"enabled_by_default = {getattr(m, 'enabled_by_default', '?')}",
            f"MITRE_tags    = {getattr(m, 'mitre_tags', '(none)')}",
            f"description   = {m.description}",
        ]
        meta_box.setPlainText("\n".join(meta_lines))
        meta_box.setFixedHeight(110)
        lay.addWidget(meta_box)
        return w

    def _find_module_src(self) -> str:
        """Locate the .py file for self.module (inspect.getfile fallback)."""
        try:
            import inspect
            return inspect.getfile(type(self.module))
        except Exception:
            pass
        try:
            mod_name = type(self.module).__module__.split(".")[-1]
            cands = list(Path(__file__).resolve().parents[1].rglob(f"{mod_name}.py"))
            if cands:
                return str(cands[0])
        except Exception:
            pass
        return ""

    def _parse_imports(self, src_path: str) -> str:
        if not src_path:
            return "(source unavailable)"
        try:
            import ast as _ast
            src = Path(src_path).read_text(encoding="utf-8", errors="replace")
            tree = _ast.parse(src)
            lines = []
            for node in _ast.walk(tree):
                if isinstance(node, _ast.Import):
                    for alias in node.names:
                        lines.append(f"import {alias.name}")
                elif isinstance(node, _ast.ImportFrom):
                    names = ", ".join(a.name for a in node.names)
                    lines.append(f"from {node.module or ''} import {names}")
            # De-dup, sort, highlight angerona-internal deps
            seen, out = set(), []
            for ln in sorted(set(lines)):
                if ln not in seen:
                    seen.add(ln)
                    prefix = "  [internal] " if "angerona" in ln else "  "
                    out.append(prefix + ln)
            return "\n".join(out) or "(no imports found)"
        except Exception as exc:
            return f"(parse error: {exc})"

    def _on_feed_click(self, row: int, _col: int) -> None:
        item = self.feed.item(row, 0)
        if item is None:
            return
        event = item.data(Qt.UserRole)
        if event is not None:
            # Module alerts now open the SAME detail window (with Allow/Block/
            # Analyze/Research) as the main Live Alerts feed.
            _show_nonmodal(AlertDetailDialog(event, self.window()))

    def _api_keys_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        info = QLabel("Enter your own cloud API keys (optional). Stored locally in "
                      ".env, never committed. Used only for opt-in cloud escalation.")
        info.setWordWrap(True); lay.addWidget(info)
        self._key_fields = {}
        grid = QGridLayout()
        rows = [("Gemini (comma-separated pool)", "GEMINI_API_KEYS"),
                ("Groq", "GROQ_API_KEY"), ("OpenAI", "OPENAI_API_KEY"),
                ("Anthropic (Claude)", "ANTHROPIC_API_KEY"), ("OpenRouter", "OPENROUTER_API_KEY")]
        for i, (label, env) in enumerate(rows):
            grid.addWidget(QLabel(label), i, 0)
            f = QLineEdit(os.environ.get(env, ""))
            f.setEchoMode(QLineEdit.Password); f.setPlaceholderText(env)
            self._key_fields[env] = f
            grid.addWidget(f, i, 1)
        lay.addLayout(grid)
        save = QPushButton("Save keys"); save.setObjectName("Primary")
        save.clicked.connect(self._save_keys); lay.addWidget(save)
        self._keys_status = QLabel(""); self._keys_status.setWordWrap(True)
        self._keys_status.setStyleSheet("color:#9aa4b2;"); lay.addWidget(self._keys_status)
        lay.addStretch(1)
        return w

    def _save_keys(self) -> None:
        from angerona.core.config import write_env_keys
        updates = {env: f.text().strip() for env, f in self._key_fields.items()}
        try:
            path = write_env_keys(updates)
            self._keys_status.setText(f"Saved to {path}. Cloud escalation picks up keys within ~30s.")
        except Exception as exc:
            self._keys_status.setText(f"Error saving: {exc}")

    def _help_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        intro = QLabel(HELP_TEXT_SHORT); intro.setWordWrap(True)
        intro.setStyleSheet("color:#cbd5e1;"); lay.addWidget(intro)
        btn = QPushButton("Open full instructions"); btn.setObjectName("Primary")
        btn.clicked.connect(self._open_help); lay.addWidget(btn)
        lay.addStretch(1)
        return w

    def _open_help(self) -> None:
        dlg = QDialog(self); dlg.setWindowTitle("Angerona — API Key Setup Help")
        dlg.setMinimumSize(580, 540); dlg.setStyleSheet(self.styleSheet())
        l = QVBoxLayout(dlg)
        body = QPlainTextEdit(); body.setReadOnly(True); body.setPlainText(HELP_TEXT_FULL)
        body.setFont(QFont("Consolas", 10)); l.addWidget(body)
        close = QPushButton("Close"); close.setObjectName("Primary")
        close.clicked.connect(dlg.accept); l.addWidget(close)
        dlg.exec()

    def _enabled(self) -> bool:
        return self.manager.is_enabled(self.module.name)

    def _toggle(self) -> None:
        self.manager.set_enabled(self.module.name, not self._enabled())
        self._refresh()

    def _restart(self) -> None:
        self.module.stop()
        self.module.start()
        self._refresh()

    def _open_in_sandbox(self) -> None:
        try:
            from angerona.gui.sandbox_editor import launch_sandbox_editor
            # Auto-open THIS module's .py so the operator lands straight on its code.
            self._sandbox = launch_sandbox_editor(
                self.manager, self.bus, parent=self.window(),
                preselect=getattr(self.module, "name", None))
        except Exception as exc:
            QMessageBox.warning(self, "Sandbox", f"Could not open the sandbox: {exc}")

    def _selftest(self) -> None:
        self.test_lbl.setText("Testing…")
        threading.Thread(target=self._run_test, daemon=True).start()

    def _run_test(self) -> None:
        try:
            ok, detail = self.module.self_test()
            color = "#22c55e" if ok else "#ef4444"
            self._test_done.emit(f"<span style='color:{color}'>"
                                 f"{'PASS' if ok else 'FAIL'} — {detail}</span>")
        except Exception as exc:
            self._test_done.emit(f"<span style='color:#ef4444'>FAIL — {exc}</span>")

    def _refresh(self) -> None:
        color = HEALTH_COLOR.get(self.module.health_state, "#e5e7eb")
        note = (f"<br><span style='color:#9aa4b2'>{self.module.health_note}</span>"
                if self.module.health_note else "")
        self.status_lbl.setText(
            f"Status: <b style='color:{color}'>{self.module.status}</b> · "
            f"health <b style='color:{color}'>{self.module.health}%</b> · "
            f"{'enabled' if self._enabled() else 'disabled'}" + note)
        self.error_lbl.setText(f"Last error: {self.module.last_error}" if self.module.last_error else "")
        self.toggle_btn.setText("Disable" if self._enabled() else "Enable")

        events = [e for e in self.bus.recent(300) if e.module == self.module.name][:80]
        self.feed.setRowCount(0)
        for e in events:
            r = self.feed.rowCount(); self.feed.insertRow(r)
            ts_item = QTableWidgetItem(e.time_str)
            ts_item.setData(Qt.UserRole, e)   # stash event so a click opens detail
            self.feed.setItem(r, 0, ts_item)
            self.feed.setItem(r, 1, _sev_item(e.severity))
            self.feed.setItem(r, 2, QTableWidgetItem(e.message))

        # ── Performance tab refresh ──────────────────────────────────────
        try:
            now = time.time()
            all_ev = self.bus.recent(1000)
            mod_ev = [e for e in all_ev if e.module == self.module.name]
            rate5  = sum(1 for e in mod_ev if now - e.ts < 300)
            rate60 = sum(1 for e in mod_ev if now - e.ts < 3600)
            throttle = getattr(self.module, "_throttle", 1.0)
            health   = self.module.health
            is_live  = getattr(self.module, "_thread", None)
            thread_s = "alive" if (is_live and is_live.is_alive()) else "stopped"
            self._p_throttle.setText(f"{throttle:.1f}×"
                                     f"{'  (eco-throttled)' if throttle > 1 else ''}")
            self._p_rate5.setText(str(rate5))
            self._p_rate60.setText(str(rate60))
            hcolor = "#22c55e" if health >= 70 else "#f59e0b" if health >= 40 else "#ef4444"
            self._p_health.setText(f"<span style='color:{hcolor}'>{health}%</span>")
            self._p_thread.setText(thread_s)
            self._health_trend.append(health)
            if len(self._health_trend) > 20:
                self._health_trend = self._health_trend[-20:]
            bar = "".join(
                "█" if h >= 80 else "▇" if h >= 60 else "▄" if h >= 40 else "▂"
                for h in self._health_trend
            )
            self._p_trend.setPlainText(
                f"[{bar}]\n"
                f"min={min(self._health_trend)}%  max={max(self._health_trend)}%  "
                f"avg={sum(self._health_trend)//len(self._health_trend)}%"
            )
        except Exception:
            pass

        # ── History tab refresh (light — only if tab visible) ────────────
        try:
            self._refresh_history()
        except Exception:
            pass


# ── Alerts panel ─────────────────────────────────────────────────────────────

class _TimestampItem(QTableWidgetItem):
    """Sorts by raw float timestamp so midnight-spanning rows stay correct."""
    def __init__(self, ts: float) -> None:
        super().__init__(time.strftime("%H:%M:%S", time.localtime(ts)))
        self._ts = ts

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        if isinstance(other, _TimestampItem):
            return self._ts < other._ts
        return super().__lt__(other)


class _SeverityItem(QTableWidgetItem):
    """Sorts by Severity int order (INFO < LOW < MEDIUM < HIGH < CRITICAL)."""
    def __init__(self, sev: Severity) -> None:
        super().__init__(sev.label)
        self.setForeground(QColor(SEVERITY_COLOR.get(sev, "#e5e7eb")))
        self._order = int(sev)

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        if isinstance(other, _SeverityItem):
            return self._order < other._order
        return super().__lt__(other)


class AlertDetailDialog(QDialog):
    """Full granular detail for one alert, incl. a SHA-256 fingerprint.

    `panel` (optional): the AlertsPanel this alert came from. When provided, the
    Allow / Block / Analyze buttons reuse the panel's handlers so behaviour is
    identical to the inline row buttons. Research always works (AI consult)."""
    def __init__(self, event, parent=None, panel=None) -> None:
        super().__init__(parent)
        self._event = event
        self._panel = panel
        self.setWindowTitle("Alert detail")
        self.setMinimumSize(580, 480)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        lay = QVBoxLayout(self)

        title = QLabel(f"{event.severity.label} · {event.module}")
        title.setObjectName("PageTitle")
        lay.addWidget(title)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.ts))
        lay.addWidget(QLabel(f"Time: {ts}"))
        # Long alert text slowly scrolls inside a fixed-height box so the whole
        # message stays readable without stretching the dialog (doc request:
        # "any long string of text in a box, have it slowly rotate down").
        try:
            from angerona.core.analysis_worker import MarqueeLabel
            msg = MarqueeLabel("")
            msg.setText(event.message)   # triggers the overflow/scroll check
        except Exception:
            msg = QLabel(event.message); msg.setWordWrap(True)
        msg.setStyleSheet("color:#cbd5e1;"); lay.addWidget(msg)

        canon = (f"{event.ts}|{event.module}|{int(event.severity)}|{event.message}|"
                 f"{json.dumps(event.details, sort_keys=True)}")
        digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        lay.addWidget(_section("Cryptographic fingerprint (SHA-256)"))
        hbox = QLineEdit(digest); hbox.setReadOnly(True); lay.addWidget(hbox)

        lay.addWidget(_section("Full event record"))
        body = QPlainTextEdit(); body.setReadOnly(True)
        record = {"time": ts, "module": event.module, "severity": event.severity.label,
                  "message": event.message, "details": event.details, "sha256": digest}
        body.setPlainText(json.dumps(record, indent=2))
        lay.addWidget(body)

        # ── Action bar: Allow · Block · Analyze · Research ────────────────────
        lay.addWidget(_section("Actions"))
        self._action_status = QLabel("")
        self._action_status.setWordWrap(True)
        self._action_status.setStyleSheet("color:#94a3b8; font-size:12px;")
        acts = QHBoxLayout()
        b_allow = QPushButton("Allow");   b_allow.clicked.connect(self._act_allow)
        b_block = QPushButton("Block");   b_block.clicked.connect(self._act_block)
        b_analyze = QPushButton("Analyze"); b_analyze.clicked.connect(self._act_analyze)
        b_research = QPushButton("🔎 Research"); b_research.clicked.connect(self._act_research)
        b_copy = QPushButton("📋 Copy"); b_copy.clicked.connect(self._act_copy)
        b_copy.setStyleSheet("background:#334155;color:#e2e8f0;")
        b_allow.setStyleSheet("background:#14532d;color:#86efac;")
        b_block.setStyleSheet("background:#7f1d1d;color:#fca5a5;")
        b_analyze.setStyleSheet("background:#1e3a5f;color:#7dd3fc;")
        b_research.setStyleSheet("background:#4c1d95;color:#e9d5ff;")
        self._b_analyze = b_analyze
        for b in (b_allow, b_block, b_analyze, b_research, b_copy):
            acts.addWidget(b)
        acts.addStretch()
        close = QPushButton("Close"); close.setObjectName("Primary")
        close.clicked.connect(self.accept)
        acts.addWidget(close)
        lay.addLayout(acts)
        lay.addWidget(self._action_status)

    # ── Action handlers (reuse the AlertsPanel logic when available) ──────────
    def _act_allow(self) -> None:
        if self._panel is not None:
            self._panel._allow_event(self._event)
            self._action_status.setText(f"✓ Allowed future events from '{self._event.module}'.")
        else:
            self._action_status.setText("Allow needs the live Alerts panel.")

    def _act_block(self) -> None:
        if self._panel is not None:
            self._panel._block_event(self._event)
            self._action_status.setText("Queued SOAR containment for review.")
            return
        # Standalone (opened from a module view): publish the same review-gated
        # SOAR containment request directly to the bus.
        e = self._event
        try:
            from angerona.core.eventbus import publish, Event as BusEvent, Severity as BusSev
            publish(BusEvent(ts=time.time(), module="OPERATOR", severity=BusSev.CRITICAL,
                             message=(f"[SOAR-QUEUE] Operator requested containment of source "
                                      f"'{e.module}' — alert: {e.message[:120]}"),
                             details={"origin_module": e.module, "origin_ts": e.ts,
                                      "soar_action": "containment_review"}))
            _persist_soar_queue(e)
            self._action_status.setText(f"✓ Containment request queued for '{e.module}'.")
        except Exception as exc:
            self._action_status.setText(f"Block failed: {exc}")

    def _act_analyze(self) -> None:
        if self._panel is not None:
            self._panel._analyze_event(self._event, self._b_analyze)
            self._action_status.setText("Running deep AI triage… (see Alerts panel status)")
            return
        # Standalone deep triage (module view): run the worker here.
        try:
            from angerona.core.analysis_worker import AnalysisWorker
        except Exception as exc:
            self._action_status.setText(f"Analyze unavailable: {exc}")
            return
        e = self._event
        d = e.details or {}
        alert = {"pid": d.get("pid"), "process_name": d.get("name") or e.module,
                 "ancestry": d.get("ancestry") or [], "connections": d.get("connections") or [],
                 "memory_strings": d.get("memory_strings") or [], "details": e.message,
                 "type": e.module}
        self._b_analyze.setEnabled(False); self._b_analyze.setText("Analyzing…")
        self._analyze_worker = AnalysisWorker(alert, allow_cloud=True, parent=self)
        self._analyze_worker.progress.connect(self._action_status.setText)
        self._analyze_worker.finished.connect(self._on_standalone_analyze)
        self._analyze_worker.error.connect(
            lambda m: (self._action_status.setText(f"⚠ {m}"),
                       self._b_analyze.setEnabled(True), self._b_analyze.setText("Analyze")))
        self._analyze_worker.start()

    def _on_standalone_analyze(self, res: dict) -> None:
        self._b_analyze.setEnabled(True); self._b_analyze.setText("Analyze")
        verdict = res.get("final_verdict", "UNKNOWN")
        conf = res.get("final_confidence", 0)
        detail = (res.get("cloud") or res.get("local") or {})
        reason = detail.get("reasoning") or detail.get("justification") or ""
        self._action_status.setText(f"🔍 [{verdict} · {conf}%] {reason}")

    def _act_copy(self) -> None:
        _copy_event_to_clipboard(self._event)
        self._action_status.setText("📋 Alert copied to clipboard.")

    def _act_research(self) -> None:
        """Consult an online AI (Claude first) for context + remediation on this alert."""
        try:
            from angerona.gui.ai_consult_dialog import AIConsultDialog
        except Exception as exc:
            self._action_status.setText(f"Research unavailable: {exc}")
            return
        e = self._event
        prompt = (
            "Research this endpoint security alert and give the operator: (1) what it "
            "most likely means, (2) how to confirm whether it is malicious, (3) concrete "
            "remediation/containment steps for Windows.\n\n"
            f"Module: {e.module}\nSeverity: {e.severity.label}\nMessage: {e.message}\n"
            f"Details: {json.dumps(e.details, default=str)[:1500]}")
        AIConsultDialog("Research — " + e.module, prompt,
                        default_filename="alert_research.md", parent=self.window()).show()


class AlertsPanel(QFrame):
    def __init__(self, storage) -> None:
        super().__init__()
        self.setObjectName("Panel")
        self.storage = storage
        self._events: list = []
        self._newest_ts: float = 0.0
        # Modules the operator has allowed — excluded from future rows.
        self._suppressed: set[str] = set()
        # Live "Analyze" deep-triage workers, kept alive across row rebuilds.
        self._analyze_workers: list = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 14)
        lay.addWidget(_section(
            "Live Alerts  —  click a header to sort · click a row for detail  "
            "· Allow = suppress future events from this module  "
            "· Block = queue SOAR containment for review  "
            "· Analyze = deep AI triage (local → cloud)"
        ))
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Module", "Severity", "Message", "Allow", "Block", "Analyze"]
        )
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(1, QHeaderView.Interactive)
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.Fixed)
        hdr.setSectionResizeMode(5, QHeaderView.Fixed)
        hdr.setSectionResizeMode(6, QHeaderView.Fixed)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(4, 68)
        self.table.setColumnWidth(5, 68)
        self.table.setColumnWidth(6, 78)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.cellClicked.connect(self._on_click)
        # Ctrl+C copies the selected alert row to the clipboard instantly.
        _sc = QShortcut(QKeySequence.Copy, self.table)
        _sc.activated.connect(self._copy_selected)
        # Enable click-to-sort on all column headers; default = newest first.
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.DescendingOrder)
        lay.addWidget(self.table)
        # Status line for Allow/Block feedback
        self._status = QLabel("")
        self._status.setStyleSheet("color:#94a3b8; font-size:12px; padding:2px 0;")
        lay.addWidget(self._status)

    def _copy_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 0)
        ev = item.data(Qt.UserRole) if item else None
        if ev is not None:
            _copy_event_to_clipboard(ev)
            self._status.setText("📋 Alert copied to clipboard.")

    def _on_click(self, row: int, col: int) -> None:
        # Col 4/5 handled by button widgets; cols 0-3 open detail dialog.
        if col >= 4:
            return
        item = self.table.item(row, 0)
        if item is not None:
            event = item.data(Qt.UserRole)
            if event is not None:
                _show_nonmodal(AlertDetailDialog(event, self.window(), panel=self))

    def _make_allow_btn(self, event) -> QPushButton:
        btn = QPushButton("Allow")
        btn.setFixedHeight(22)
        btn.setStyleSheet(
            "QPushButton{background:#14532d;color:#86efac;border:none;border-radius:3px;"
            "font-size:11px;padding:0 4px;}"
            "QPushButton:hover{background:#166534;}"
        )
        btn.clicked.connect(lambda: self._allow_event(event))
        return btn

    def _make_block_btn(self, event) -> QPushButton:
        btn = QPushButton("Block")
        btn.setFixedHeight(22)
        btn.setStyleSheet(
            "QPushButton{background:#7f1d1d;color:#fca5a5;border:none;border-radius:3px;"
            "font-size:11px;padding:0 4px;}"
            "QPushButton:hover{background:#991b1b;}"
        )
        btn.clicked.connect(lambda: self._block_event(event))
        return btn

    def _make_analyze_btn(self, event) -> QPushButton:
        btn = QPushButton("Analyze")
        btn.setFixedHeight(22)
        btn.setStyleSheet(
            "QPushButton{background:#1e3a5f;color:#7dd3fc;border:none;border-radius:3px;"
            "font-size:11px;padding:0 4px;}"
            "QPushButton:hover{background:#1d4ed8;}"
            "QPushButton:disabled{background:#334155;color:#94a3b8;}"
        )
        btn.clicked.connect(lambda: self._analyze_event(event, btn))
        return btn

    def _analyze_event(self, event, btn) -> None:
        """Run operator-triggered deep triage off the GUI thread (local Ollama →
        cloud fallback). The button disables while running so the local GPU queue
        can't be spammed; results land in the status line. Fail-open."""
        try:
            from angerona.core.analysis_worker import AnalysisWorker
        except Exception as exc:
            self._status.setText(f"Analyze unavailable: {exc}")
            return
        try:
            btn.setEnabled(False)
            btn.setText("Analyzing…")
        except RuntimeError:
            pass   # button may have been rebuilt by a refresh — harmless
        d = event.details or {}
        alert = {
            "pid":            d.get("pid"),
            "process_name":   d.get("name") or d.get("image") or event.module,
            "ancestry":       d.get("ancestry") or d.get("lineage") or [],
            "connections":    d.get("connections") or [],
            "memory_strings": d.get("memory_strings") or [],
            "details":        event.message,
            "type":           event.module,
        }
        worker = AnalysisWorker(alert, allow_cloud=True, parent=self)
        self._analyze_workers.append(worker)
        worker.progress.connect(self._status.setText)
        worker.finished.connect(lambda res, b=btn, w=worker: self._on_analyze_done(res, b, w))
        worker.error.connect(lambda msg, b=btn, w=worker: self._on_analyze_err(msg, b, w))
        worker.start()

    @staticmethod
    def _reset_analyze_btn(btn) -> None:
        try:
            btn.setEnabled(True)
            btn.setText("Analyze")
        except RuntimeError:
            pass   # row was rebuilt mid-analysis — the new button is already fresh

    def _reap_worker(self, worker) -> None:
        try:
            self._analyze_workers.remove(worker)
        except ValueError:
            pass
        worker.deleteLater()

    def _on_analyze_done(self, result: dict, btn, worker) -> None:
        self._reset_analyze_btn(btn)
        verdict = result.get("final_verdict", "UNKNOWN")
        conf = result.get("final_confidence", 0)
        src = "cloud" if result.get("cloud") else "local"
        detail = (result.get("cloud") or result.get("local") or {})
        reason = detail.get("reasoning") or detail.get("justification") or ""
        self._status.setText(f"🔍 [{verdict} · {conf}% · {src}] {reason}")
        self._reap_worker(worker)

    def _on_analyze_err(self, msg: str, btn, worker) -> None:
        self._reset_analyze_btn(btn)
        self._status.setText(f"⚠ Analyze failed: {msg}")
        self._reap_worker(worker)

    def _allow_event(self, event) -> None:
        """Suppress future events from this module in the live feed."""
        self._suppressed.add(event.module)
        self._status.setText(
            f"✓ '{event.module}' allowed — future events from this module are hidden. "
            "Restart or remove from allowlist in Settings to restore."
        )
        # Force refresh to remove suppressed rows immediately
        self._newest_ts = 0.0
        self._events = []
        self.refresh()

    def _block_event(self, event) -> None:
        """Queue a SOAR containment action for operator review (never auto-executes)."""
        ts_str = time.strftime("%H:%M:%S", time.localtime(event.ts))
        details = (f"Module: {event.module}\n"
                   f"Severity: {event.severity.label}\n"
                   f"Time: {ts_str}\n\n"
                   f"Message: {event.message}\n\n"
                   f"Confirming will stage a SOAR containment request for this source.\n"
                   f"No action will be taken automatically — you must review and\n"
                   f"approve in the SOAR / Posture Hardening panel.")
        dlg = QMessageBox(self.window())
        dlg.setWindowTitle("Queue SOAR Containment?")
        dlg.setText(f"Block source from module '{event.module}'?")
        dlg.setInformativeText(details)
        dlg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        dlg.setDefaultButton(QMessageBox.Cancel)
        dlg.setIcon(QMessageBox.Warning)
        if dlg.exec() != QMessageBox.Ok:
            return
        # Publish a SOAR containment request event to the bus (review-gated)
        try:
            from angerona.core.eventbus import publish, Event as BusEvent
            from angerona.core.eventbus import Severity as BusSeverity
            publish(BusEvent(
                ts=time.time(),
                module="OPERATOR",
                severity=BusSeverity.CRITICAL,
                message=(f"[SOAR-QUEUE] Operator requested containment of source "
                         f"'{event.module}' — alert: {event.message[:120]}"),
                details={"origin_module": event.module, "origin_ts": event.ts,
                         "origin_message": event.message, "soar_action": "containment_review"},
                mitre_tags=getattr(event, "mitre_tags", []),
            ))
            _persist_soar_queue(event)   # save so the SOAR tab keeps a scrollable history
            self._status.setText(
                f"✓ Containment request queued for '{event.module}' — "
                "review in the SOAR tab before any action is applied."
            )
        except Exception as exc:
            self._status.setText(f"Bus publish failed: {exc}")

    def _insert_row(self, pos: int, e) -> None:
        if e.module in self._suppressed:
            return
        self.table.insertRow(pos)
        ts_item = _TimestampItem(e.ts)
        ts_item.setData(Qt.UserRole, e)      # store event for click lookup
        self.table.setItem(pos, 0, ts_item)
        # node_origin: alerts forwarded by a remote sensor node (Remote Bridge)
        # are tagged so the operator can tell them apart from local telemetry.
        origin = (e.details or {}).get("node_origin")
        mod_item = QTableWidgetItem(f"{e.module}  ⇠{origin}" if origin else e.module)
        if origin:
            mod_item.setToolTip(f"Forwarded from remote node: {origin}")
        self.table.setItem(pos, 1, mod_item)
        self.table.setItem(pos, 2, _SeverityItem(e.severity))
        self.table.setItem(pos, 3, QTableWidgetItem(e.message))
        # Action buttons — must use setCellWidget, not setItem
        self.table.setCellWidget(pos, 4, self._make_allow_btn(e))
        self.table.setCellWidget(pos, 5, self._make_block_btn(e))
        self.table.setCellWidget(pos, 6, self._make_analyze_btn(e))

    def refresh(self) -> None:
        # Cheap pre-check: a single MAX(ts) aggregation avoids fetching and
        # deserializing 120 event rows when nothing has changed (the common case).
        if self.storage.max_ts() == self._newest_ts:
            return

        events = self.storage.recent(120)
        if not events:
            return
        newest_ts = events[0].ts          # storage.recent() returns newest-first

        # ── fast path: nothing new ──────────────────────────────────────────
        if newest_ts == self._newest_ts and len(events) == len(self._events):
            return

        # ── full rebuild — preserving the user's current sort column/order ──
        hdr = self.table.horizontalHeader()
        sort_col = hdr.sortIndicatorSection()
        sort_ord = hdr.sortIndicatorOrder()

        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        self.table.setRowCount(0)
        for e in events:
            self._insert_row(self.table.rowCount(), e)
        self.table.setUpdatesEnabled(True)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(sort_col, sort_ord)

        self._events = events
        self._newest_ts = newest_ts


# ── Bottom status strip ───────────────────────────────────────────────────────
# Each chip shows: CODE (acronym, 2-5 chars) on line 1, health-% on line 2.
# Chips share equal stretch so they fill the bar width automatically.
# Change-detection (_prev_states) skips stylesheet regeneration for chips that
# haven't changed, keeping repaint cost O(new_events) not O(all_modules).

_CHIP_FONT: QFont | None = None  # built lazily to avoid pre-QApplication issues


def _chip_font() -> QFont:
    global _CHIP_FONT
    if _CHIP_FONT is None:
        _CHIP_FONT = QFont("Consolas", 8)
        _CHIP_FONT.setBold(True)
    return _CHIP_FONT


class SoarPanel(QFrame):
    """SOAR queue: every 'Block → SOAR' request lands here (persisted, scrollable).

    Includes a smart 'Consult AI' button that sends the whole queue — enriched
    with per-item file info + VPN/interface status — to online AIs for an opinion.
    """
    def __init__(self, bus, manager=None) -> None:
        super().__init__()
        self.setObjectName("Panel")
        self.bus = bus
        self.manager = manager
        self._count = 0
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 14)
        lay.addWidget(_section(
            "SOAR Queue  —  operator-blocked sources awaiting review (persisted history)"))

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "Source module", "Severity", "Message", "Status"])
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        # Right-click → per-alert AI analysis
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._row_context_menu)
        lay.addWidget(self.table)

        row = QHBoxLayout()
        self._status = QLabel("")
        self._status.setStyleSheet("color:#94a3b8; font-size:12px;")
        row.addWidget(self._status, 1)
        self._btn_ai_sel = QPushButton("🤖 Ask AI (selected)")
        self._btn_ai_sel.setToolTip(
            "Deep-dive AI analysis of the selected alert — includes file hash, "
            "parent process, open connections, VPN status, and system health snapshot.")
        self._btn_ai_sel.setStyleSheet("background:#1e3a5f;color:#bfdbfe;font-weight:700;")
        self._btn_ai_sel.clicked.connect(self._consult_ai_selected)
        row.addWidget(self._btn_ai_sel)
        self._btn_ai = QPushButton("🤖 Consult AI on queue")
        self._btn_ai.setToolTip("Send every queued item — with file info + VPN/interface "
                                "status — to online AIs (Claude first) for triage.")
        self._btn_ai.setStyleSheet("background:#4c1d95;color:#e9d5ff;font-weight:700;")
        self._btn_ai.clicked.connect(self._consult_ai)
        row.addWidget(self._btn_ai)
        clear = QPushButton("Clear history")
        clear.clicked.connect(self._clear)
        row.addWidget(clear)
        lay.addLayout(row)

    def refresh(self) -> None:
        items = _read_soar_queue()
        if len(items) == self._count:
            return
        self._count = len(items)
        self.table.setRowCount(0)
        for rec in reversed(items):     # newest first
            r = self.table.rowCount()
            self.table.insertRow(r)
            ts = time.strftime("%m-%d %H:%M:%S", time.localtime(rec.get("ts", 0)))
            self.table.setItem(r, 0, QTableWidgetItem(ts))
            self.table.setItem(r, 1, QTableWidgetItem(str(rec.get("origin_module", ""))))
            self.table.setItem(r, 2, QTableWidgetItem(str(rec.get("severity", ""))))
            self.table.setItem(r, 3, QTableWidgetItem(str(rec.get("message", ""))))
            st = QTableWidgetItem(str(rec.get("status", "")))
            st.setForeground(QColor("#f59e0b"))
            self.table.setItem(r, 4, st)
        self._status.setText(f"{len(items)} item(s) in the SOAR queue.")

    def _clear(self) -> None:
        try:
            _soar_queue_path().write_text("", encoding="utf-8")
        except Exception:
            pass
        self._count = -1
        self.refresh()

    # ── System context ────────────────────────────────────────────────────────
    def _gather_system_context(self) -> str:
        """Snapshot of system health at query time — sent to AI with every prompt."""
        lines = []
        try:
            lines.append(f"host={platform.node()} os={platform.version()[:60]}")
        except Exception:
            pass
        try:
            import psutil
            vm = psutil.virtual_memory()
            lines.append(f"ram_used={vm.percent}% cpu={psutil.cpu_percent(interval=0.15):.0f}%")
            lines.append(f"proc_count={len(psutil.pids())} conn_count={len(psutil.net_connections(kind='inet'))}")
            boot = time.time() - psutil.boot_time()
            h, m = divmod(int(boot // 60), 60)
            lines.append(f"uptime={h}h{m}m")
        except Exception:
            pass
        try:
            from angerona.core.net_interfaces import classify_interfaces, VIRTUAL_VPN
            ifaces = classify_interfaces()
            vpn = {n: v for n, v in ifaces.items() if v == VIRTUAL_VPN}
            lines.append(f"vpn_tunnels={'none' if not vpn else ','.join(vpn.keys())}")
        except Exception:
            pass
        # Angerona module health summary
        if self.manager:
            try:
                statuses = []
                for m in self.manager.modules:
                    h = getattr(m, "_health", None)
                    if h and h.get("pct", 100) < 50:
                        statuses.append(f"{m.name}:{h.get('pct')}%")
                if statuses:
                    lines.append(f"unhealthy_modules={';'.join(statuses)}")
            except Exception:
                pass
        # Threat level from bus
        if self.bus:
            try:
                recent = self.bus.recent(5)
                crits = sum(1 for e in recent if e.severity.value >= 4)
                lines.append(f"recent_crits_5min={crits}")
            except Exception:
                pass
        return " | ".join(lines)

    def _enrich(self, rec: dict) -> str:
        """Deep-enrich one queued item: process tree, file hash, connections, VPN."""
        d = rec.get("details", {}) or {}
        bits = []
        pid = d.get("pid")
        path = d.get("path") or d.get("image") or d.get("exe")

        # ── Process info ───────────────────────────────────────────────────
        try:
            import psutil
            if pid:
                p = psutil.Process(int(pid))
                with p.oneshot():
                    path = path or p.exe()
                    bits.append(f"proc={p.name()}(pid={pid})")
                    try:
                        parent = p.parent()
                        bits.append(f"parent={parent.name()}(pid={parent.pid})")
                    except Exception:
                        pass
                    # All TCP connections for this PID
                    try:
                        conns = p.connections(kind="inet")
                        remote_set = {
                            f"{c.raddr.ip}:{c.raddr.port}"
                            for c in conns if c.raddr
                        }
                        if remote_set:
                            bits.append(f"open_connections={','.join(sorted(remote_set)[:6])}")
                    except Exception:
                        pass
        except Exception:
            if pid:
                bits.append(f"pid={pid}")

        # ── File attributes + hash ─────────────────────────────────────────
        if path and os.path.exists(path):
            try:
                stt = os.stat(path)
                bits.append(f"path={path}")
                bits.append(
                    f"size={stt.st_size}B "
                    f"created={time.strftime('%Y-%m-%d', time.localtime(stt.st_ctime))} "
                    f"modified={time.strftime('%Y-%m-%d', time.localtime(stt.st_mtime))}"
                )
                # SHA-256 (skip files > 64 MB to stay fast in GUI thread)
                if stt.st_size < 64 * 1024 * 1024:
                    sha = hashlib.sha256()
                    with open(path, "rb") as fh:
                        for chunk in iter(lambda: fh.read(65536), b""):
                            sha.update(chunk)
                    bits.append(f"sha256={sha.hexdigest()}")
            except Exception:
                bits.append(f"path={path}")
            # Windows Authenticode / digital signature quick check
            if os.name == "nt":
                try:
                    out = subprocess.check_output(
                        ["powershell", "-NoProfile", "-Command",
                         f"(Get-AuthenticodeSignature '{path}').Status"],
                        timeout=4, stderr=subprocess.DEVNULL, text=True
                    ).strip()
                    bits.append(f"signature={out}")
                except Exception:
                    pass

        # ── VPN / network ──────────────────────────────────────────────────
        try:
            from angerona.core.net_interfaces import classify_interfaces, VIRTUAL_VPN
            ifaces = classify_interfaces()
            vpn = [n for n, t in ifaces.items() if t == VIRTUAL_VPN]
            bits.append(f"vpn={'yes:' + ','.join(vpn) if vpn else 'no'}")
        except Exception:
            pass

        raddr = d.get("raddr") or d.get("remote_ip")
        if raddr:
            bits.append(f"remote={raddr}:{d.get('rport', '')}")

        return " | ".join(bits) if bits else "(no details)"

    # ── Right-click context menu ───────────────────────────────────────────────
    def _row_context_menu(self, pos) -> None:
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        menu = QMenu(self)
        act_ai   = QAction("🤖 Ask AI about this alert", self)
        act_copy = QAction("📋 Copy message", self)
        menu.addAction(act_ai)
        menu.addAction(act_copy)
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen == act_ai:
            self._consult_ai_single(row)
        elif chosen == act_copy:
            item = self.table.item(row, 3)
            if item:
                QGuiApplication.clipboard().setText(item.text())

    def _consult_ai_selected(self) -> None:
        rows = {idx.row() for idx in self.table.selectedIndexes()}
        if not rows:
            self._status.setText("Select a row first, then click Ask AI (selected).")
            return
        self._consult_ai_single(sorted(rows)[0])

    def _consult_ai_single(self, row: int) -> None:
        """Deep-dive AI analysis of one specific SOAR queue item."""
        items = _read_soar_queue()
        # items are displayed newest-first; row 0 = items[-1]
        idx = len(items) - 1 - row
        if idx < 0 or idx >= len(items):
            self._status.setText("Row out of range — refresh and try again.")
            return
        try:
            from angerona.gui.ai_consult_dialog import AIConsultDialog
        except Exception as exc:
            self._status.setText(f"Consult AI unavailable: {exc}")
            return
        rec = items[idx]
        sys_ctx = self._gather_system_context()
        enriched = self._enrich(rec)
        prompt = (
            "You are a Tier-3 SOC analyst reviewing a single operator-flagged SOAR alert.\n"
            "Provide:\n"
            "  1. Likely intent / threat classification\n"
            "  2. Confidence (Low / Medium / High) with reasoning\n"
            "  3. Recommended immediate action (kill / suspend / isolate / allow / investigate)\n"
            "  4. Suggested next forensic steps\n"
            "  5. Any indicators of compromise to hunt for\n\n"
            f"=== Alert ===\n"
            f"Severity : {rec.get('severity','')}\n"
            f"Module   : {rec.get('origin_module','')}\n"
            f"Message  : {rec.get('message','')}\n\n"
            f"=== Enrichment ===\n{enriched}\n\n"
            f"=== System state at query time ===\n{sys_ctx}"
        )
        dlg = AIConsultDialog(
            f"SOAR — AI deep-dive: {rec.get('origin_module','')} alert",
            prompt,
            default_filename="soar_single_alert_ai.md",
            parent=self.window(),
        )
        _show_nonmodal(dlg)

    def _consult_ai(self) -> None:
        items = _read_soar_queue()
        if not items:
            self._status.setText("SOAR queue is empty.")
            return
        try:
            from angerona.gui.ai_consult_dialog import AIConsultDialog
        except Exception as exc:
            self._status.setText(f"Consult AI unavailable: {exc}")
            return
        sys_ctx = self._gather_system_context()
        lines = [
            "You are a Tier-3 SOC analyst reviewing operator-blocked containment items.\n"
            "For EACH item give:\n"
            "  • likely intent & threat classification\n"
            "  • confidence (Low/Medium/High)\n"
            "  • recommended action (kill/suspend/isolate/allow/investigate) + one-line why\n"
            "  • if multiple items share a source IP, PID, or file — call out the pattern.\n\n"
            f"=== System snapshot ===\n{sys_ctx}\n",
        ]
        for i, rec in enumerate(items[-25:], 1):
            lines.append(
                f"[{i}] {rec.get('severity','')} | {rec.get('origin_module','')} | "
                f"{rec.get('message','')}\n     {self._enrich(rec)}"
            )
        prompt = "\n\n".join(lines)
        dlg = AIConsultDialog("SOAR — AI review of the containment queue", prompt,
                              default_filename="soar_ai_review.md", parent=self.window())
        _show_nonmodal(dlg)


class _ClickableChip(QLabel):
    """A status chip that emits its module name when clicked."""
    clicked = Signal(str)

    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name
        self.setCursor(Qt.PointingHandCursor)

    def mousePressEvent(self, ev) -> None:  # noqa: N802 (Qt signature)
        if ev.button() == Qt.LeftButton:
            self.clicked.emit(self._name)
        super().mousePressEvent(ev)


class StatusStrip(QFrame):
    def __init__(self, manager, on_chip_click=None) -> None:
        super().__init__()
        self.setObjectName("StatusStrip")
        self.manager = manager
        self._on_chip_click = on_chip_click   # callback(name) → open module window
        self.setFixedHeight(52)
        self._lay = QHBoxLayout(self)
        self._lay.setContentsMargins(8, 4, 8, 4)
        self._lay.setSpacing(4)
        self._chips: dict[str, QLabel] = {}
        # Cache last visual state per chip: (health_state, pct_text)
        self._prev: dict[str, tuple[str, str]] = {}
        self._built_count = -1
        self._build()

    def _build(self) -> None:
        while self._lay.count():
            item = self._lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._chips.clear()
        self._prev.clear()
        font = _chip_font()
        for name in sorted(self.manager.modules):
            chip = _ClickableChip(name)
            chip.setAlignment(Qt.AlignCenter)
            chip.setFont(font)
            chip.setMinimumWidth(0)
            if self._on_chip_click is not None:
                chip.clicked.connect(self._on_chip_click)
            self._chips[name] = chip
            self._lay.addWidget(chip, 1)
        self._built_count = len(self.manager.modules)

    def refresh(self) -> None:
        if self._built_count != len(self.manager.modules):
            self._build()
            return
        for name, chip in self._chips.items():
            mod = self.manager.modules.get(name)
            if not mod:
                continue
            state = mod.health_state
            pct_text = (f"{mod.health}%" if mod.status == "running"
                        else mod.status[:3].upper())
            key = (state, pct_text)
            if self._prev.get(name) == key:
                continue                     # nothing changed — skip repaint
            self._prev[name] = key
            color = HEALTH_COLOR.get(state, "#6b7280")
            code  = _short_code(mod)
            chip.setText(f"{code}\n{pct_text}")
            chip.setToolTip(
                f"{mod.name}  {pct_text}"
                + (f"  [{mod.health_note}]" if mod.health_note else "")
            )
            chip.setStyleSheet(
                f"background:{color}1a; color:{color};"
                f"border:1px solid {color}55; border-radius:8px;"
                f"padding:1px 3px; font-weight:700;"
            )


# ── Resource-intensity strip ──────────────────────────────────────────────────
# A second row of chips, aligned under the StatusStrip, showing how resource-hungry
# each module currently is (0–100%). 0 = not running (red); low = green/good; the
# busier a module is, the higher the % and the more amber→red it becomes. Since
# modules are threads inside one process (no per-thread RSS in Python), intensity
# is a heuristic: a static heaviness weight for known heavy scanners + a live bonus
# from how many events the module has emitted recently (real, changing activity).
_HEAVY_MODULES = {
    "Process Monitor", "Network Monitor", "Memory Time-Machine",
    "Memory Injection Scanner", "YARA Scanner", "Packet Sniffer",
    "Ransomware Heuristics", "Sysmon Event Bridge", "ETW Core Listener",
    "Upstream Threat Intel Sync", "API Patch / Anti-Blinding Detector",
    "Persistence Sweep", "Network Protocol Deep Decoder", "WLAN Monitor",
    "ARP Watchdog", "AMSI Bridge", "AV Telemetry Bridge",
    "Data Provenance Graph", "Hardware-Rooted Integrity",
}


def _intensity_color(pct: int, running: bool) -> str:
    if not running or pct <= 0:
        return "#ef4444"          # off → red
    if pct < 34:
        return "#22c55e"          # low → green/good
    if pct < 67:
        return "#f59e0b"          # medium → amber
    return "#f97316"              # heavy → orange-red


class ResourceStrip(QFrame):
    """Per-module resource-intensity chips (0–100%), aligned under the StatusStrip."""

    def __init__(self, manager, bus) -> None:
        super().__init__()
        self.setObjectName("ResourceStrip")
        self.manager = manager
        self.bus = bus
        self.setFixedHeight(46)
        self._lay = QHBoxLayout(self)
        self._lay.setContentsMargins(8, 2, 8, 4)
        self._lay.setSpacing(4)
        self._chips: dict[str, QLabel] = {}
        self._prev: dict[str, tuple[int, bool]] = {}
        self._built_count = -1
        self._build()

    def _build(self) -> None:
        while self._lay.count():
            item = self._lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._chips.clear()
        self._prev.clear()
        font = _chip_font()
        for name in sorted(self.manager.modules):
            chip = QLabel()
            chip.setAlignment(Qt.AlignCenter)
            chip.setFont(font)
            self._chips[name] = chip
            self._lay.addWidget(chip, 1)
        self._built_count = len(self.manager.modules)

    def _intensity(self, name: str, mod, activity: dict) -> int:
        if getattr(mod, "status", "") != "running":
            return 0
        base = 42 if name in _HEAVY_MODULES else 16
        bonus = min(52, activity.get(name, 0) * 8)
        return max(1, min(100, base + bonus))

    def refresh(self) -> None:
        if self._built_count != len(self.manager.modules):
            self._build()
            return
        # Live activity: count recent events per module (cheap, changes over time).
        activity: dict[str, int] = {}
        try:
            for e in self.bus.recent(120):
                activity[e.module] = activity.get(e.module, 0) + 1
        except Exception:
            pass
        for name, chip in self._chips.items():
            mod = self.manager.modules.get(name)
            if not mod:
                continue
            running = getattr(mod, "status", "") == "running"
            pct = self._intensity(name, mod, activity)
            key = (pct, running)
            if self._prev.get(name) == key:
                continue
            self._prev[name] = key
            color = _intensity_color(pct, running)
            chip.setText(f"{_short_code(mod)}\n{pct}%")
            chip.setToolTip(f"{mod.name} — resource intensity {pct}%"
                            + ("" if running else " (stopped)"))
            chip.setStyleSheet(
                f"background:{color}1a; color:{color};"
                f"border:1px solid {color}55; border-radius:8px;"
                f"padding:1px 3px; font-weight:700;")


# ── Command console (interactive prompt + AI) ────────────────────────────────
class CommandConsolePanel(QFrame):
    """Embedded console: type a command (try 'help') or ask the AI. Commands run
    on a background thread so AI calls never freeze the UI."""
    _result = Signal(str)

    def __init__(self, backend) -> None:
        super().__init__()
        self.setObjectName("Panel")
        self.backend = backend
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.addWidget(_section("Console  —  type 'help', or ask the AI"))

        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setFont(QFont("Fira Code", 10))
        self.out.setStyleSheet("background:#0b0d12; color:#cbd5e1; border:1px solid #232a36; border-radius:8px;")
        lay.addWidget(self.out)

        row = QHBoxLayout()
        self.spin = QLabel("")
        self.spin.setStyleSheet("color:#1f9cff; font-weight:800; font-size:14px; "
                                "letter-spacing:1px; min-width:150px;")
        row.addWidget(self.spin)
        prompt = QLabel("UDE#")
        prompt.setStyleSheet("color:#22c55e; font-weight:700; font-family:Consolas;")
        row.addWidget(prompt)
        self.inp = QLineEdit()
        self.inp.setPlaceholderText("kill 1234   ·   ps   ·   suspend 1234   ·   ask is pid 20300 safe?")
        self.inp.setStyleSheet("font-family:Consolas;")
        self.inp.returnPressed.connect(self._submit)
        row.addWidget(self.inp)
        lay.addLayout(row)

        # Spinner (braille dots) shown while a command / self-test runs.
        self._busy = 0
        self._frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self._frame = 0
        self._spin_timer = QTimer(self)
        self._spin_timer.timeout.connect(self._tick)

        self._result.connect(self._on_result)
        self._append("Angerona console ready. Type 'help' for commands.")

    def _submit(self) -> None:
        text = self.inp.text().strip()
        self.inp.clear()
        if not text:
            return
        if text.lower() == "clear":
            self.out.clear()
            return
        self._append(f"UDE# {text}")
        self._start_busy()
        threading.Thread(target=self._work, args=(text,), daemon=True).start()

    def run_command(self, text: str) -> None:
        """Run a command programmatically (e.g. from a toolbar button)."""
        self._append(f"UDE# {text}")
        self._start_busy()
        threading.Thread(target=self._work, args=(text,), daemon=True).start()

    def _work(self, text: str) -> None:
        try:
            result = self.backend.run(text)
        except Exception as exc:
            result = f"error: {exc}"
        self._result.emit(result)

    def _on_result(self, text: str) -> None:
        self._append(text)
        self._end_busy()

    # ── Spinner ──────────────────────────────────────────────────────────────
    def _start_busy(self) -> None:
        self._busy += 1
        if not self._spin_timer.isActive():
            self._spin_timer.start(90)

    def _end_busy(self) -> None:
        self._busy = max(0, self._busy - 1)
        if self._busy == 0:
            self._spin_timer.stop()
            self.spin.setText("")

    def _tick(self) -> None:
        self._frame = (self._frame + 1) % len(self._frames)
        self.spin.setText(f"{self._frames[self._frame]}  WORKING…")

    def _append(self, text: str) -> None:
        if text:
            self.out.appendPlainText(text)
        self.out.verticalScrollBar().setValue(self.out.verticalScrollBar().maximum())

    def refresh(self) -> None:
        pass  # console is event-driven; nothing to poll


# ── Shark Attack — live offense monitor (non-modal) ───────────────────────────
class SharkMonitorDialog(QDialog):
    """Live narration window for a running Shark Attack drill — what it's
    doing and where, as it happens. Deliberately non-modal: it's meant to sit
    next to the main dashboard so you can watch the OFFENSE narration here
    and the DEFENSE side (Alerts panel, Modules table, status strip) react
    live in the main window at the same time. Closing this window does not
    stop the drill — it only hides the narration; the AAR review window
    still opens automatically when the run finishes."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Live Offense Monitor")
        self.setMinimumSize(980, 520)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        # Non-modal + not auto-deleted on close, so MainWindow can keep
        # reusing/showing the same instance across multiple drills.
        self.setWindowModality(Qt.NonModal)
        self.setAttribute(Qt.WA_DeleteOnClose, False)
        lay = QVBoxLayout(self)

        title = QLabel("\U0001F988  OFFENSE — what the drill is doing, live")
        title.setObjectName("PageTitle")
        lay.addWidget(title)
        hint = QLabel("This window only narrates the simulated attack. Watch the main "
                     "dashboard's Alerts panel, Modules table, and status strip "
                     "alongside it to see the DEFENSE side react in real time.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#9aa4b2;")
        lay.addWidget(hint)

        # ── Flight Instructor Mode — Cyber Security Academy's live AI coach ──
        # Purely additive: when off, this dialog behaves exactly as before
        # (raw engine narration only). When on, MainWindow also streams a
        # short AI explanation of each stage into this same log, using the
        # same append() path — so it's one interleaved, timestamped feed.
        fi_row = QHBoxLayout()
        self.fi_check = QCheckBox("\U0001F393 Flight Instructor Mode — AI coaching narration")
        self.fi_style = QComboBox()
        self.fi_style.addItems(["analogy", "technical"])
        self.fi_style.setToolTip("Explanation register: plain-language analogy, or precise technical detail.")
        fi_row.addWidget(self.fi_check)
        fi_row.addWidget(self.fi_style)
        fi_row.addStretch(1)
        lay.addLayout(fi_row)

        panes = QHBoxLayout()
        # Left pane: the OFFENSE — the test running and its results.
        left = QVBoxLayout()
        lh = QLabel("\U0001F5E1️  OFFENSE — test run & results")
        lh.setStyleSheet("color:#f87171; font-weight:700;")
        left.addWidget(lh)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("Fira Code", 10))
        self.log.setStyleSheet(
            "background:#0b0d12; color:#7dd3fc; border:1px solid #232a36; border-radius:8px;")
        left.addWidget(self.log)
        panes.addLayout(left, 1)
        # Right pane: the FLIGHT INSTRUCTOR — analogy/technical coaching per step.
        right = QVBoxLayout()
        rh = QLabel("\U0001F393  FLIGHT INSTRUCTOR — what it's doing & why")
        rh.setStyleSheet("color:#a78bfa; font-weight:700;")
        right.addWidget(rh)
        self.instructor = QPlainTextEdit()
        self.instructor.setReadOnly(True)
        self.instructor.setFont(QFont("Fira Code", 10))
        self.instructor.setStyleSheet(
            "background:#0b0d12; color:#c4b5fd; border:1px solid #232a36; border-radius:8px;")
        self.instructor.setPlaceholderText(
            "Enable 'Flight Instructor Mode' above to stream a plain-language ANALOGY or a "
            "precise TECHNICAL explanation of each step here (pick the register in the dropdown).")
        right.addWidget(self.instructor)
        panes.addLayout(right, 1)
        lay.addLayout(panes)

        row = QHBoxLayout()
        row.addStretch(1)
        close = QPushButton("Close (drill keeps running)")
        close.clicked.connect(self.hide)
        row.addWidget(close)
        lay.addLayout(row)

    def reset(self) -> None:
        self.log.clear()
        self.instructor.clear()

    def append(self, line: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.log.appendPlainText(f"[{ts}] {line}")
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def append_instructor(self, line: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.instructor.appendPlainText(f"[{ts}] {line}")
        self.instructor.verticalScrollBar().setValue(self.instructor.verticalScrollBar().maximum())


# ── Shark Attack — After-Action Report (dialog) ───────────────────────────────
class AARDialog(QDialog):
    """Read-only review window for a completed Shark Attack drill. Shows the
    same formatted report that's printed to the terminal (see
    angerona.shark.aar_report), with a button to re-run the comparison —
    useful since slower-polling modules (YARA's 5-minute scan interval, for
    instance) may catch something a few minutes after the drill ends."""

    _fix_done = Signal(str)
    _apply_done = Signal(str)

    def __init__(self, data_dir, parent=None, on_attempt_fix=None, on_apply=None,
                 on_clean=None) -> None:
        super().__init__(parent)
        self.data_dir = data_dir
        self._on_attempt_fix = on_attempt_fix
        self._on_apply = on_apply
        self._on_clean = on_clean
        self._fix_done.connect(self._show_fix_result)
        self._apply_done.connect(lambda t: self.body.appendPlainText("\n" + t))
        self.setWindowTitle("Shark Attack — After-Action Report")
        self.setMinimumSize(760, 600)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        lay = QVBoxLayout(self)

        title = QLabel("\U0001F988  Shark Attack — After-Action Report")
        title.setObjectName("PageTitle")
        lay.addWidget(title)

        self.body = QPlainTextEdit()
        self.body.setReadOnly(True)
        self.body.setFont(QFont("Fira Code", 10))
        self.body.setStyleSheet(
            "background:#0b0d12; color:#cbd5e1; border:1px solid #232a36; border-radius:8px;")
        lay.addWidget(self.body)

        row = QHBoxLayout()
        refresh = QPushButton("Re-run report"); refresh.setObjectName("Primary")
        refresh.clicked.connect(self.refresh)
        row.addWidget(refresh)
        row.addStretch(1)
        self._fix_btn = QPushButton("\U0001F6E0  Attempt Fix")
        self._fix_btn.setObjectName("Primary")
        self._fix_btn.setToolTip("Ask the local AI to generate a remediation for each open "
                                 "weakness, then optionally apply it (with your confirmation).")
        self._fix_btn.clicked.connect(self._attempt_fix)
        row.addWidget(self._fix_btn)
        row.addStretch(1)
        close = QPushButton("\U0001F9F9  Clean & Close")
        close.setToolTip("Erase every benign drill marker / persistence-marker file used during "
                         "the simulation, then close this report.")
        close.clicked.connect(self._clean_and_close)
        row.addWidget(close)
        lay.addLayout(row)

    def _clean_and_close(self) -> None:
        """Sweep the drill's marker files, then close the report."""
        if self._on_clean:
            try:
                n = self._on_clean()
                if isinstance(n, int):
                    self.body.appendPlainText(
                        f"\n\U0001F9F9  Cleaned {n} drill marker/file(s). Closing.")
            except Exception:
                pass
        self.accept()

    @staticmethod
    def _safe(fn):
        try:
            return fn()
        except Exception as exc:
            return f"[error] {exc}"

    def _attempt_fix(self) -> None:
        if not self._on_attempt_fix:
            self.body.appendPlainText("\n[Attempt Fix] Posture Hardening module not available.")
            return
        self._fix_btn.setEnabled(False)
        self.body.appendPlainText("\n[Attempt Fix] Asking the local AI for a remediation "
                                  "(temperature 0) — this may take a few seconds…")
        import threading
        threading.Thread(target=lambda: self._fix_done.emit(self._safe(self._on_attempt_fix)),
                         daemon=True).start()

    def _show_fix_result(self, text: str) -> None:
        self.body.appendPlainText("\n" + text)
        self._fix_btn.setEnabled(True)
        # Only offer to apply when a remediation was actually generated. If the
        # posture is clean (no open weaknesses), there is nothing to run.
        if not self._on_apply or "staged" not in text.lower():
            return
        from PySide6.QtWidgets import QMessageBox
        if QMessageBox.question(
                self, "Apply remediation",
                "Apply the generated remediation now? This runs an elevated PowerShell "
                "script on THIS machine. Review the text above first.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            self.body.appendPlainText("\n[Apply] Running remediation…")
            import threading
            threading.Thread(target=lambda: self._apply_done.emit(self._safe(self._on_apply)),
                             daemon=True).start()

    def set_text(self, text: str) -> None:
        self.body.setPlainText(text)

    def refresh(self) -> None:
        from angerona.shark.aar_report import generate_aar
        self.body.setPlainText("Re-evaluating against the flight-recorder ledger…")
        try:
            text = generate_aar(self.data_dir, settle_seconds=0)
        except Exception as exc:
            text = f"Could not generate report: {exc}"
        self.body.setPlainText(text)



# ── Settings dialog ───────────────────────────────────────────────────────────

class SettingsDialog(QDialog):
    """Settings dialog — opened from the header gear button.

    Tabs
    ----
    General   : Ollama host / model, GitHub repo, theme picker
    System    : Launch on boot (Scheduled Task), MCP server toggle
    API Keys  : Optional cloud-escalation keys (Gemini, Groq, OpenAI, etc.)
    """

    def __init__(self, config, check_updates_fn, apply_theme_fn, parent=None):
        super().__init__(parent)
        self._cfg            = config
        self._check_updates  = check_updates_fn
        self._apply_theme    = apply_theme_fn

        self.setWindowTitle("Angerona — Settings")
        self.setMinimumWidth(560)
        self.setModal(True)

        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(16, 16, 16, 16)

        tabs = QTabWidget()
        root.addWidget(tabs)

        tabs.addTab(self._tab_general(), "General")
        tabs.addTab(self._tab_system(),  "System")
        # Mobile Integration is consolidated into the Advanced Management Console so
        # there is only ONE place to configure it. Show a short redirect here.
        _mob = QWidget(); _mv = QVBoxLayout(_mob)
        _lbl = QLabel(
            "Mobile Integration has moved to the Advanced Management Console.\n\n"
            "Open the main window's  \U0001F9F0 CONSOLE  button, then the "
            "'Mobile Integration' tab — configure the transport (Signal / ntfy / "
            "Pushover / SMS), save the settings, and send a live test alert there.")
        _lbl.setWordWrap(True); _mv.addWidget(_lbl); _mv.addStretch()
        tabs.addTab(_mob, "Mobile Integration")
        tabs.addTab(self._tab_apikeys(), "API Keys")

        # ── button row ──
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._btn_save   = QPushButton("Save")
        self._btn_cancel = QPushButton("Cancel")
        self._btn_save.setFixedWidth(90)
        self._btn_cancel.setFixedWidth(90)
        self._btn_save.setDefault(True)
        btn_row.addWidget(self._btn_cancel)
        btn_row.addWidget(self._btn_save)
        root.addLayout(btn_row)

        self._btn_save.clicked.connect(self._save)
        self._btn_cancel.clicked.connect(self.reject)

    # ── Tab builders ──────────────────────────────────────────────────────────

    def _tab_general(self) -> QWidget:
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        lay.addWidget(self._section("Ollama (local AI)"))

        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        grid.addWidget(QLabel("Host:"), 0, 0)
        self._ollama_host = QLineEdit(self._cfg.ollama_host)
        grid.addWidget(self._ollama_host, 0, 1)
        grid.addWidget(QLabel("Model:"), 1, 0)
        self._ollama_model = QLineEdit(self._cfg.ollama_model)
        grid.addWidget(self._ollama_model, 1, 1)
        lay.addLayout(grid)

        lay.addWidget(self._section("Appearance"))
        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Theme:"))
        self._theme_combo = QComboBox()
        # available_themes() returns (key, label) tuples — add the label as the
        # visible text and stash the key as item data. addItem(tuple) is invalid
        # and was throwing during construction, which is why the Settings dialog
        # "did nothing" when the gear button was clicked.
        for t in available_themes():
            if isinstance(t, (tuple, list)):
                key = str(t[0])
                label = str(t[1]) if len(t) > 1 else key
            else:
                key = label = str(t)
            self._theme_combo.addItem(label, key)
        idx = self._theme_combo.findData(self._cfg.theme)
        if idx < 0:
            idx = self._theme_combo.findText(self._cfg.theme)
        if idx >= 0:
            self._theme_combo.setCurrentIndex(idx)
        theme_row.addWidget(self._theme_combo)
        theme_row.addStretch()
        lay.addLayout(theme_row)

        lay.addWidget(self._section("Updates"))
        repo_row = QHBoxLayout()
        repo_row.addWidget(QLabel("GitHub repo:"))
        self._github_repo = QLineEdit(self._cfg.github_repo)
        repo_row.addWidget(self._github_repo)
        self._btn_check = QPushButton("Check now")
        self._btn_check.clicked.connect(self._on_check_updates)
        repo_row.addWidget(self._btn_check)
        lay.addLayout(repo_row)

        lay.addStretch()
        return w

    def _tab_system(self) -> QWidget:
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        # ── Startup on boot ──
        lay.addWidget(self._section("Windows startup"))

        boot_box = QGroupBox()
        boot_box.setFlat(True)
        boot_lay = QVBoxLayout(boot_box)
        boot_lay.setContentsMargins(0, 0, 0, 0)

        from angerona.core.autostart import is_enabled as _autostart_is_enabled
        currently_enabled = _autostart_is_enabled()

        self._autostart_chk = QCheckBox("Launch Angerona automatically at Windows logon")
        self._autostart_chk.setChecked(
            currently_enabled if currently_enabled is not None
            else self._cfg.autostart_enabled
        )
        boot_lay.addWidget(self._autostart_chk)

        note = QLabel(
            "Uses a Windows Scheduled Task with highest-privilege runLevel — "
            "starts Angerona silently at logon without a UAC prompt."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        boot_lay.addWidget(note)

        self._autostart_status = QLabel()
        self._autostart_status.setStyleSheet("font-size: 11px;")
        self._refresh_autostart_status(currently_enabled)
        boot_lay.addWidget(self._autostart_status)

        lay.addWidget(boot_box)

        lay.addWidget(self._section("MCP Server (Claude Desktop integration)"))
        self._mcp_chk = QCheckBox("Enable local MCP server on port")
        self._mcp_chk.setChecked(self._cfg.mcp_enabled)
        self._mcp_port = QLineEdit(str(self._cfg.mcp_port))
        self._mcp_port.setFixedWidth(70)
        self._mcp_port.setEnabled(self._cfg.mcp_enabled)
        self._mcp_chk.toggled.connect(self._mcp_port.setEnabled)
        mcp_row = QHBoxLayout()
        mcp_row.addWidget(self._mcp_chk); mcp_row.addWidget(self._mcp_port); mcp_row.addStretch()
        lay.addLayout(mcp_row)
        mcp_note = QLabel("Loopback only (127.0.0.1). Restart required for changes to take effect.")
        mcp_note.setWordWrap(True); mcp_note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(mcp_note)

        lay.addWidget(self._section("Performance"))
        self._eco_chk = QCheckBox("Start in Eco Mode (heavy scanners paused) for a fast, responsive launch")
        self._eco_chk.setChecked(getattr(self._cfg, "eco_mode", True))
        lay.addWidget(self._eco_chk)
        eco_note = QLabel(
            "Recommended. The safety-critical response path (SOAR, deception, watchdog, "
            "heartbeat, IPC guard, AI triage) stays live; heavy pollers wake sequentially "
            "when you tap ECO off, so the UI never stampedes on startup."
        )
        eco_note.setWordWrap(True); eco_note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(eco_note)

        lay.addWidget(self._section("Black Box (out-of-band diagnostic recorder)"))
        self._blackbox_chk = QCheckBox("Launch the Black Box recorder automatically with Angerona")
        self._blackbox_chk.setChecked(getattr(self._cfg, "blackbox_enabled", True))
        lay.addWidget(self._blackbox_chk)
        bb_note = QLabel(
            "A separate, strictly read-only process that tails crash/diagnostic files, "
            "host telemetry, thread state and memory — it survives even if the main suite "
            "deadlocks. Runs quietly in the system tray; restart Angerona to apply a change."
        )
        bb_note.setWordWrap(True); bb_note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(bb_note)

        lay.addWidget(self._section("Linux eBPF sensor (headless Linux node)"))
        self._ebpf_chk = QCheckBox("Enable native eBPF kernel telemetry (Linux + BCC + root only)")
        self._ebpf_chk.setChecked(getattr(self._cfg, "ebpf_enabled", False))
        lay.addWidget(self._ebpf_chk)
        ebpf_note = QLabel(
            "Off by default. On a Linux sensor node with BCC and kernel headers, this "
            "hooks execve + tcp_sendmsg in-kernel and forwards events over the Remote Bridge. "
            "Inert on Windows / without BCC (degrades gracefully)."
        )
        ebpf_note.setWordWrap(True); ebpf_note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(ebpf_note)

        lay.addWidget(self._section("Confidential Compute (Intel SGX / Gramine)"))
        try:
            from angerona.core.sgx_guard import is_confidential_compute_active
            _sgx_on = is_confidential_compute_active()
        except Exception:
            _sgx_on = False
        sgx_lbl = QLabel(("ACTIVE — the flight cache runs inside an SGX enclave."
                          if _sgx_on else
                          "Not active — run under Gramine-SGX to hardware-encrypt the "
                          "in-memory cache (see angerona.manifest.template)."))
        sgx_lbl.setWordWrap(True)
        sgx_lbl.setStyleSheet(f"color: {'#22c55e' if _sgx_on else '#94a3b8'}; font-size: 11px;")
        lay.addWidget(sgx_lbl)

        lay.addStretch()
        return w

    def _tab_mobile(self) -> QWidget:
        """Mobile Response Bridge (Signal) config."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)
        lay.addWidget(self._section("Mobile Response Bridge (Signal / signal-cli)"))

        self._mob_chk = QCheckBox("Enable Mobile Response Bridge")
        self._mob_chk.setChecked(getattr(self._cfg, "mobile_enabled", False))
        lay.addWidget(self._mob_chk)

        warn = QLabel(
            "⚠  Requires signal-cli installed and a registered Signal phone number. "
            "Commands received are rate-limited and PIN-gated. The PIN is stored "
            "DPAPI-wrapped — never in plain text."
        )
        warn.setWordWrap(True)
        warn.setStyleSheet("color: #f59e0b; font-size: 11px;")
        lay.addWidget(warn)

        grid = QGridLayout(); grid.setColumnStretch(1, 1)
        grid.addWidget(QLabel("signal-cli path:"), 0, 0)
        self._mob_cli = QLineEdit(getattr(self._cfg, "mobile_signal_cli", ""))
        self._mob_cli.setPlaceholderText("/usr/local/bin/signal-cli")
        grid.addWidget(self._mob_cli, 0, 1)
        self._mob_browse = QPushButton("Browse…")
        self._mob_browse.clicked.connect(self._browse_signal_cli)
        grid.addWidget(self._mob_browse, 0, 2)

        grid.addWidget(QLabel("Host number (this machine):"), 1, 0)
        self._mob_host = QLineEdit(getattr(self._cfg, "mobile_host_number", ""))
        self._mob_host.setPlaceholderText("+15551234567")
        grid.addWidget(self._mob_host, 1, 1, 1, 2)

        grid.addWidget(QLabel("Operator destination #:"), 2, 0)
        self._mob_dest = QLineEdit(getattr(self._cfg, "mobile_dest_number", ""))
        self._mob_dest.setPlaceholderText("+15557654321")
        grid.addWidget(self._mob_dest, 2, 1, 1, 2)

        grid.addWidget(QLabel("Hardware PIN (4-digit):"), 3, 0)
        self._mob_pin = QLineEdit()
        self._mob_pin.setEchoMode(QLineEdit.Password)
        self._mob_pin.setMaxLength(4)
        self._mob_pin.setPlaceholderText("•••• (leave blank to keep existing)")
        try:
            from PySide6.QtGui import QIntValidator
            self._mob_pin.setValidator(QIntValidator(0, 9999, self._mob_pin))
        except Exception:
            pass
        grid.addWidget(self._mob_pin, 3, 1, 1, 2)
        lay.addLayout(grid)

        note = QLabel("The PIN is DPAPI-wrapped (user+machine bound) and stored in .env — "
                      "never in plain text. Type HELP from your phone for the command menu.")
        note.setWordWrap(True); note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(note)

        self._mob_fields = [self._mob_cli, self._mob_browse, self._mob_host,
                            self._mob_dest, self._mob_pin]
        def _lock(on: bool) -> None:
            for f in self._mob_fields:
                f.setEnabled(on)
        _lock(self._mob_chk.isChecked())
        self._mob_chk.toggled.connect(_lock)

        lay.addStretch()
        return w

    def _browse_signal_cli(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Locate signal-cli", "",
                                              "signal-cli (signal-cli*);;All files (*.*)")
        if path:
            self._mob_cli.setText(path)

    def _tab_apikeys(self) -> QWidget:
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(8)

        info = QLabel(HELP_TEXT_SHORT)
        info.setWordWrap(True)
        info.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(info)

        lay.addWidget(self._section("Cloud escalation API keys (optional)"))

        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        _KEYS = [
            ("GEMINI_API_KEY",     "Gemini:"),
            ("GROQ_API_KEY",       "Groq:"),
            ("OPENAI_API_KEY",     "OpenAI:"),
            ("ANTHROPIC_API_KEY",  "Anthropic:"),
            ("OPENROUTER_API_KEY", "OpenRouter:"),
        ]
        self._key_fields: dict[str, QLineEdit] = {}
        for _row, (env, label) in enumerate(_KEYS):
            grid.addWidget(QLabel(label), _row, 0)
            field = QLineEdit(os.environ.get(env, ""))
            field.setEchoMode(QLineEdit.Password)
            field.setPlaceholderText("(not set)")
            grid.addWidget(field, _row, 1)
            self._key_fields[env] = field
        lay.addLayout(grid)

        btn_keys = QPushButton("Save keys")
        btn_keys.setFixedWidth(110)
        btn_keys.clicked.connect(self._save_api_keys)
        lay.addWidget(btn_keys)

        lay.addWidget(self._section("Online AI consult order (first with a key wins)"))
        order_info = QLabel(
            "Use ▲ / ▼ to reorder. Consult AI, Sandbox Ask-AI, and SOAR AI review "
            "all try providers top-to-bottom; the first one with a key set above wins."
        )
        order_info.setWordWrap(True); order_info.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(order_info)

        _labels = {
            "anthropic":  "Anthropic (Claude)",
            "gemini":     "Google Gemini",
            "openai":     "OpenAI (ChatGPT)",
            "openrouter": "OpenRouter",
            "ollama":     "Local Ollama (offline fallback)",
        }
        self._ai_order_list = QListWidget()
        cur_order = list(
            getattr(self._cfg, "ai_provider_order", None)
            or ["anthropic", "gemini", "openai", "openrouter", "ollama"]
        )
        for key in cur_order:
            it = QListWidgetItem(_labels.get(key, key))
            it.setData(Qt.UserRole, key)
            self._ai_order_list.addItem(it)
        self._ai_order_list.setFixedHeight(135)

        order_row = QHBoxLayout()
        order_row.addWidget(self._ai_order_list, 1)
        order_col = QVBoxLayout()
        btn_up = QPushButton("▲  Up"); btn_dn = QPushButton("▼  Down")
        btn_up.clicked.connect(lambda: self._move_ai_order(-1))
        btn_dn.clicked.connect(lambda: self._move_ai_order(1))
        order_col.addWidget(btn_up); order_col.addWidget(btn_dn); order_col.addStretch()
        order_row.addLayout(order_col)
        lay.addLayout(order_row)

        lay.addStretch()
        return w

    # ── SettingsDialog helpers & save ─────────────────────────────────────────

    def _move_ai_order(self, delta: int) -> None:
        lw = self._ai_order_list
        r = lw.currentRow()
        if r < 0: return
        nr = r + delta
        if 0 <= nr < lw.count():
            it = lw.takeItem(r); lw.insertItem(nr, it); lw.setCurrentRow(nr)

    def _section(self, title: str) -> QLabel:
        lbl = QLabel(title)
        lbl.setStyleSheet(
            "font-weight: bold; font-size: 12px; color: #1F9CFF; "
            "border-bottom: 1px solid #334155; padding-bottom: 3px; margin-top: 6px;"
        )
        return lbl

    def _refresh_autostart_status(self, enabled) -> None:
        if enabled:
            self._autostart_status.setText("Status: scheduled task exists (AngeronaAutostart)")
            self._autostart_status.setStyleSheet("color: #22c55e; font-size: 11px;")
        elif enabled is False:
            self._autostart_status.setText("Status: no startup task found")
            self._autostart_status.setStyleSheet("color: #94a3b8; font-size: 11px;")
        else:
            self._autostart_status.setText("Status: could not detect (check Task Scheduler)")
            self._autostart_status.setStyleSheet("color: #f59e0b; font-size: 11px;")

    def _on_check_updates(self) -> None:
        if callable(self._check_updates):
            try:
                self._check_updates()
            except Exception as exc:
                QMessageBox.warning(self, "Update check failed", str(exc))

    def _save_api_keys(self) -> None:
        from angerona.core.config import write_env_keys
        updates = {env: field.text().strip() for env, field in self._key_fields.items()}
        try:
            write_env_keys(updates)
            QMessageBox.information(self, "Keys saved",
                                    "API keys written to .env. Active modules pick them up "
                                    "within ~30 s — no restart needed.")
        except Exception as exc:
            QMessageBox.warning(self, "Save failed", str(exc))

    def _save_mobile_pin(self) -> None:
        pin = self._mob_pin.text().strip()
        if not pin:
            return
        try:
            from angerona.engines.hardware_crypto import protect as _protect
            import base64
            blob = _protect(pin.encode("utf-8"), b"Angerona-MOBILE-PIN-v1")
            from angerona.core.config import write_env_keys
            write_env_keys({"ANGERONA_MOBILE_PIN_BLOB": base64.b64encode(blob).decode()})
        except Exception as exc:
            QMessageBox.warning(self, "PIN save failed",
                                f"Could not DPAPI-wrap the PIN: {exc}")

    def _save(self) -> None:
        from angerona.core.autostart import enable as _autostart_enable, \
            disable as _autostart_disable

        self._cfg.ollama_host  = self._ollama_host.text().strip()
        self._cfg.ollama_model = self._ollama_model.text().strip()
        self._cfg.github_repo  = self._github_repo.text().strip()
        theme_key = self._theme_combo.currentData() or self._theme_combo.currentText()
        self._cfg.theme = theme_key or self._cfg.theme
        if callable(self._apply_theme):
            try: self._apply_theme(self._cfg.theme)
            except Exception: pass

        want_autostart = self._autostart_chk.isChecked()
        self._cfg.autostart_enabled = want_autostart
        try:
            _autostart_enable() if want_autostart else _autostart_disable()
        except Exception:
            pass

        self._cfg.eco_mode         = self._eco_chk.isChecked()
        self._cfg.blackbox_enabled = self._blackbox_chk.isChecked()
        self._cfg.mcp_enabled      = self._mcp_chk.isChecked()
        try:
            self._cfg.mcp_port = int(self._mcp_port.text().strip() or "47923")
        except ValueError:
            pass
        self._cfg.ebpf_enabled = self._ebpf_chk.isChecked()

        self._cfg.mobile_enabled     = self._mob_chk.isChecked()
        self._cfg.mobile_signal_cli  = self._mob_cli.text().strip()
        self._cfg.mobile_host_number = self._mob_host.text().strip()
        self._cfg.mobile_dest_number = self._mob_dest.text().strip()
        self._save_mobile_pin()

        order = [self._ai_order_list.item(i).data(Qt.UserRole)
                 for i in range(self._ai_order_list.count())
                 if self._ai_order_list.item(i).data(Qt.UserRole)]
        if order:
            self._cfg.ai_provider_order = order
            os.environ["ANGERONA_AI_ORDER"] = ",".join(order)

        try:
            self._cfg.save()
        except Exception as exc:
            QMessageBox.warning(self, "Settings not saved", str(exc))
            return
        self.accept()
