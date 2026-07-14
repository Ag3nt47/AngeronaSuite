"""resolve_center.py — one place to clear the threat level back to Secure.

Opened from the dashboard Threat-level box. Lists the CRITICAL / HIGH alerts
currently driving the threat level and lets the operator address each one
directly:

  • Detail   — opens the full alert window (Allow · Block · Analyze · Research ·
    Apply fix), identical to the Live Alerts row actions.
  • Ignore   — acknowledges the alert (and future identical repeats) so it is
    EXCLUDED from the threat level — the way to clear false positives. Every
    ignore is revertable from the "Ignored" viewer.

When the list is empty the posture is Secure. Read side only; ignoring writes to
shared_logs/alert_acks.json via core.alert_ack.
"""
from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from angerona.core.eventbus import Severity
from angerona.core.threat import threat_label
from angerona.core import alert_ack

_SEV_COLOR = {"CRITICAL": "#f87171", "HIGH": "#fb923c", "MEDIUM": "#facc15"}


class ResolveCenter(QDialog):
    def __init__(self, bus, storage, manager, parent=None, window_s: int = 86400) -> None:
        super().__init__(parent)
        self.bus, self.storage, self.manager = bus, storage, manager
        self.window_s = window_s
        self.setWindowTitle("🛠  Resolve Center — clear the threat level")
        self.setMinimumSize(900, 600)
        if parent:
            self.setStyleSheet(parent.styleSheet())

        root = QVBoxLayout(self)
        self._head = QLabel("Resolve Center")
        self._head.setObjectName("PageTitle")
        root.addWidget(self._head)
        self._sub = QLabel("")
        self._sub.setWordWrap(True)
        self._sub.setStyleSheet("color:#9aa4b2;")
        root.addWidget(self._sub)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "Severity", "Module", "Message", "Actions"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("QTableWidget::item{padding:4px 6px;}")
        root.addWidget(self.table, 1)

        bar = QHBoxLayout()
        self._foot = QLabel("")
        self._foot.setStyleSheet("color:#9aa4b2;")
        bar.addWidget(self._foot, 1)
        ignored_btn = QPushButton("🔕  Ignored…")
        ignored_btn.setToolTip("View and revert previously-ignored alerts.")
        ignored_btn.clicked.connect(self._show_ignored)
        refresh = QPushButton("Refresh"); refresh.clicked.connect(self._refresh)
        close = QPushButton("Close"); close.clicked.connect(self.accept)
        for b in (ignored_btn, refresh, close):
            bar.addWidget(b)
        root.addLayout(bar)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(2000)
        self._refresh()

    # ── data ─────────────────────────────────────────────────────────────────
    _SCAN_CAP = 500   # bound the per-refresh signature work regardless of alert volume

    def _events(self) -> list:
        from angerona.gui.pages import NOISE_MODULES
        now = time.time()
        try:
            evs = self.storage.events_in_window(now - self.window_s, now)
        except Exception:
            evs = self.bus.recent(500)
        # Cheap filters + sort FIRST, then cap, THEN the expensive per-event ack
        # signature check — so a critical storm (thousands of HIGH+ events) can't
        # make this O(all events) in sha1 on every 2 s tick.
        out = [e for e in evs
               if getattr(e, "severity", Severity.INFO) >= Severity.HIGH
               and getattr(e, "module", "") not in NOISE_MODULES]
        out.sort(key=lambda e: getattr(e, "ts", 0), reverse=True)
        out = out[:self._SCAN_CAP]
        acked = alert_ack.acked_signatures()
        return [e for e in out if alert_ack.signature(e) not in acked]

    _MAX_ROWS = 200   # displayed-row cap — triaging the newest 200 is plenty

    def _free_action_widgets(self) -> None:
        """Delete the per-row Detail/Ignore cell widgets before a rebuild.
        setRowCount() does NOT free setCellWidget widgets — without this the
        Resolve Center leaks buttons on every 2 s refresh (badly, when critical)."""
        for r in range(self.table.rowCount()):
            w = self.table.cellWidget(r, 4)
            if w is not None:
                self.table.removeCellWidget(r, 4)
                w.deleteLater()

    def _refresh(self) -> None:
        # Change-detection: skip the whole (expensive) rebuild when nothing new has
        # arrived and no ack changed — otherwise this ran O(alerts) every 2 s.
        try:
            key = (self.storage.max_ts(), len(alert_ack.acked_signatures()))
        except Exception:
            key = None
        if key is not None and key == getattr(self, "_last_key", object()):
            return
        self._last_key = key

        evs = self._events()
        label, color = threat_label(self.bus.recent(200))
        self._head.setText(f"🛠  Resolve Center — threat level: {label}")
        self._head.setStyleSheet(f"color:{color};")
        if not evs:
            self._sub.setText("✅  Nothing left to resolve — the posture is Secure.")
        else:
            self._sub.setText(f"{len(evs)} unresolved CRITICAL/HIGH alert(s). Open Detail to "
                              "Allow / Block / Research / Apply fix, or Ignore a false positive "
                              "to remove it from the threat level.")
        n_ign = len(alert_ack.acked_records())
        self._foot.setText(f"{len(evs)} active · {n_ign} ignored. Clearing/ignoring all returns to Secure.")

        shown = evs[:self._MAX_ROWS]
        self.table.setUpdatesEnabled(False)
        self._free_action_widgets()          # free old buttons BEFORE resizing rows
        self.table.setRowCount(len(shown))
        for r, ev in enumerate(shown):
            when = time.strftime("%m-%d %H:%M:%S", time.localtime(getattr(ev, "ts", time.time())))
            sev = getattr(ev, "severity", Severity.INFO)
            sev_name = getattr(sev, "name", str(sev))
            self.table.setItem(r, 0, QTableWidgetItem(when))
            sev_it = QTableWidgetItem(sev_name)
            sev_it.setForeground(QColor(_SEV_COLOR.get(sev_name, "#e5e7eb")))
            self.table.setItem(r, 1, sev_it)
            self.table.setItem(r, 2, QTableWidgetItem(str(getattr(ev, "module", ""))))
            self.table.setItem(r, 3, QTableWidgetItem(str(getattr(ev, "message", ""))))
            self.table.setCellWidget(r, 4, self._actions_cell(ev))
        self.table.setUpdatesEnabled(True)
        self.table.resizeColumnToContents(4)

    def _actions_cell(self, ev) -> QWidget:
        w = QWidget(); h = QHBoxLayout(w)
        h.setContentsMargins(4, 1, 4, 1); h.setSpacing(4)
        detail = self._btn("Detail", "#1e3a5f", "#38bdf8", lambda: self._detail(ev))
        ignore = self._btn("Ignore", "#3f3f46", "#d4d4d8", lambda: self._ignore(ev))
        h.addWidget(detail); h.addWidget(ignore)
        return w

    @staticmethod
    def _btn(text, bg, fg, slot) -> QPushButton:
        b = QPushButton(text); b.setFixedHeight(26)
        b.setStyleSheet(f"background:{bg}; color:{fg}; border:1px solid {fg}55;"
                        "border-radius:4px; font-size:11px; padding:0 10px;")
        b.clicked.connect(slot); return b

    # ── actions ──────────────────────────────────────────────────────────────
    def _detail(self, ev) -> None:
        from angerona.gui.pages import AlertDetailDialog, _show_nonmodal
        _show_nonmodal(AlertDetailDialog(ev, self.window()))

    def _ignore(self, ev) -> None:
        alert_ack.ack(ev, "operator ignore (Resolve Center — false positive / handled)")
        self._refresh()

    def _show_ignored(self) -> None:
        recs = alert_ack.acked_records()
        dlg = QDialog(self); dlg.setWindowTitle("Ignored alerts"); dlg.resize(720, 420)
        if self.styleSheet():
            dlg.setStyleSheet(self.styleSheet())
        v = QVBoxLayout(dlg)
        v.addWidget(QLabel(f"{len(recs)} ignored alert signature(s). Un-ignore to let them "
                           "affect the threat level again."))
        tbl = QTableWidget(len(recs), 4)
        tbl.setHorizontalHeaderLabels(["Module", "Sample", "Reason", ""])
        tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        tbl.verticalHeader().setVisible(False)
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        for r, rec in enumerate(recs):
            tbl.setItem(r, 0, QTableWidgetItem(rec.get("module", "")))
            tbl.setItem(r, 1, QTableWidgetItem(rec.get("sample", "")))
            tbl.setItem(r, 2, QTableWidgetItem(rec.get("reason", "")))
            sig = rec.get("sig")
            btn = self._btn("Un-ignore", "#334155", "#e2e8f0",
                            lambda s=sig, d=dlg: (alert_ack.unack(s), d.accept(),
                                                  self._refresh(), self._show_ignored()))
            wrap = QWidget(); wl = QHBoxLayout(wrap); wl.setContentsMargins(4, 1, 4, 1)
            wl.addWidget(btn); tbl.setCellWidget(r, 3, wrap)
        v.addWidget(tbl, 1)
        b = QPushButton("Close"); b.clicked.connect(dlg.accept); v.addWidget(b)
        dlg.exec()
