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
    QApplication, QDialog, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from angerona.core.eventbus import Severity
from angerona.core.threat import threat_label
from angerona.core import alert_ack
from angerona.core import drill_resolution, process_allowlist

_SEV_COLOR = {"CRITICAL": "#f87171", "HIGH": "#fb923c", "MEDIUM": "#facc15"}


class ResolveCenter(QDialog):
    def __init__(self, bus, storage, manager, parent=None, window_s: int = 86400) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose, True)
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

        self._page = 0
        self._page_size = 25
        self._page_events: list = []
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Time", "Severity", "Module", "Message"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("QTableWidget::item{padding:4px 6px;}")
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._sync_action_state)
        self.table.cellDoubleClicked.connect(lambda *_: self._act_selected(self._detail))
        root.addWidget(self.table, 1)

        bar = QHBoxLayout()
        self._foot = QLabel("")
        self._foot.setStyleSheet("color:#9aa4b2;")
        bar.addWidget(self._foot, 1)
        self._previous_btn = QPushButton("‹ Previous")
        self._previous_btn.setShortcut("Alt+Left")
        self._previous_btn.setToolTip("Previous alert page (Alt+Left)")
        self._previous_btn.clicked.connect(lambda: self._change_page(-1))
        self._page_label = QLabel("Page 1 / 1")
        self._page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._page_label.setMinimumWidth(92)
        self._next_btn = QPushButton("Next ›")
        self._next_btn.setShortcut("Alt+Right")
        self._next_btn.setToolTip("Next alert page (Alt+Right)")
        self._next_btn.clicked.connect(lambda: self._change_page(1))
        self._detail_btn = QPushButton("Detail")
        self._detail_btn.clicked.connect(lambda: self._act_selected(self._detail))
        self._allow_btn = QPushButton("Allow")
        self._allow_btn.clicked.connect(lambda: self._act_selected(self._allow))
        self._block_btn = QPushButton("Block")
        self._block_btn.clicked.connect(lambda: self._act_selected(self._block))
        self._ignore_btn = QPushButton("Ignore")
        self._ignore_btn.clicked.connect(lambda: self._act_selected(self._ignore))
        ignore_all_btn = QPushButton("🔕  Ignore all active")
        ignore_all_btn.setToolTip("Ignore every active alert (by class) to clear the threat level "
                                  "back to Secure. Reversible; repeats of each class stay suppressed.")
        ignore_all_btn.setStyleSheet("background:#3f3f46; color:#e4e4e7; border:1px solid #52525b;"
                                     "border-radius:4px; padding:4px 10px;")
        ignore_all_btn.clicked.connect(self._ignore_all_shown)
        ignored_btn = QPushButton("Ignored…")
        ignored_btn.setToolTip("View and revert previously-ignored alerts.")
        ignored_btn.clicked.connect(self._show_ignored)
        refresh = QPushButton("Refresh"); refresh.clicked.connect(self._refresh)
        close = QPushButton("Close"); close.clicked.connect(self.close)
        for b in (self._previous_btn, self._page_label, self._next_btn,
                  self._detail_btn, self._allow_btn, self._block_btn, self._ignore_btn,
                  ignore_all_btn, ignored_btn, refresh, close):
            bar.addWidget(b)
        root.addLayout(bar)
        self._sync_action_state()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(4000)
        self._refresh()

    # ── data ─────────────────────────────────────────────────────────────────
    _SCAN_CAP = 5000  # bounded history; pagination makes rendering independent of this

    def _events(self) -> list:
        from angerona.core.threat import active_threat_events
        now = time.time()
        try:
            evs = self.storage.try_recent_in_window(
                now - self.window_s, now, Severity.HIGH, self._SCAN_CAP)
            if evs is None:
                evs = self.bus.recent(self._SCAN_CAP)
        except Exception:
            evs = self.bus.recent(self._SCAN_CAP)
        # The shared classifier excludes practice, passive exposure, health,
        # allowlisted and resolved evidence without changing the source record.
        out = [e for e in evs
               if now - self.window_s <= getattr(e, "ts", 0) <= now
               and getattr(e, "severity", Severity.INFO) >= Severity.HIGH]
        out.sort(key=lambda e: getattr(e, "ts", 0), reverse=True)
        out = out[:self._SCAN_CAP]
        return active_threat_events(out, window=self.window_s)

    def _refresh(self, *_args) -> None:
        # Change-detection: skip the whole (expensive) rebuild when nothing new has
        # arrived and no ack changed — otherwise this ran O(alerts) every 2 s.
        try:
            def _stamp(path):
                try:
                    return path.stat().st_mtime_ns
                except OSError:
                    return -1
            key = (self.storage.revision(),
                   len(alert_ack.acked_signatures()),
                   _stamp(process_allowlist.policy_path()),
                   _stamp(drill_resolution.state_path()))
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
        page_count = max(1, (len(evs) + self._page_size - 1) // self._page_size)
        self._page = min(self._page, page_count - 1)
        start = self._page * self._page_size
        shown = evs[start:start + self._page_size]
        self._page_events = shown
        first = start + 1 if shown else 0
        last = start + len(shown)
        self._foot.setText(
            f"{len(evs)} active · {n_ign} ignored · showing {first}–{last}. "
            "Double-click a row for detail.")
        self._page_label.setText(f"Page {self._page + 1} / {page_count}")
        self._previous_btn.setEnabled(self._page > 0)
        self._next_btn.setEnabled(self._page + 1 < page_count)

        header = self.table.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self.table.setUpdatesEnabled(False)
        self.table.setSortingEnabled(False)
        self.table.clearContents()
        self.table.setRowCount(len(shown))
        for r, ev in enumerate(shown):
            when = time.strftime("%m-%d %H:%M:%S", time.localtime(getattr(ev, "ts", time.time())))
            sev = getattr(ev, "severity", Severity.INFO)
            sev_name = getattr(sev, "name", str(sev))
            time_item = QTableWidgetItem(when)
            time_item.setData(Qt.UserRole, ev)
            self.table.setItem(r, 0, time_item)
            sev_it = QTableWidgetItem(sev_name)
            sev_it.setForeground(QColor(_SEV_COLOR.get(sev_name, "#e5e7eb")))
            self.table.setItem(r, 1, sev_it)
            self.table.setItem(r, 2, QTableWidgetItem(str(getattr(ev, "module", ""))))
            self.table.setItem(r, 3, QTableWidgetItem(str(getattr(ev, "message", ""))))
        self.table.setSortingEnabled(True)
        if sort_column >= 0:
            self.table.sortItems(sort_column, sort_order)
        self.table.setUpdatesEnabled(True)
        if shown:
            self.table.selectRow(0)
        self._sync_action_state()

    def _change_page(self, delta: int) -> None:
        new_page = max(0, self._page + delta)
        if new_page == self._page:
            return
        self._page = new_page
        self._last_key = None
        self._refresh()

    def _selected_event(self):
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        return item.data(Qt.UserRole) if item is not None else None

    def _sync_action_state(self) -> None:
        enabled = self._selected_event() is not None
        for button in (self._detail_btn, self._allow_btn, self._block_btn, self._ignore_btn):
            button.setEnabled(enabled)

    def _act_selected(self, action) -> None:
        ev = self._selected_event()
        if ev is not None:
            action(ev)

    def _alerts_panel(self):
        """Find the live AlertsPanel (on the MainWindow) so Allow/Block behave
        exactly like the Live Alerts feed — they share its suppression + SOAR queue."""
        try:
            for tlw in QApplication.topLevelWidgets():
                ap = getattr(tlw, "alerts_panel", None)
                if ap is not None:
                    return ap
        except Exception:
            pass
        return None

    @staticmethod
    def _btn(text, bg, fg, slot) -> QPushButton:
        b = QPushButton(text); b.setFixedHeight(26)
        b.setStyleSheet(f"background:{bg}; color:{fg}; border:1px solid {fg}55;"
                        "border-radius:4px; font-size:11px; padding:0 10px;")
        b.clicked.connect(slot); return b

    # ── actions ──────────────────────────────────────────────────────────────
    def _detail(self, ev) -> None:
        from angerona.gui.pages import AlertDetailDialog, _show_nonmodal
        # Pass the live AlertsPanel so the detail dialog's Allow/Block work here too.
        _show_nonmodal(AlertDetailDialog(ev, self.window(), panel=self._alerts_panel()))

    def _allow(self, ev) -> None:
        """Allow = suppress this module's future alerts in the live feed AND clear
        this one from the threat level."""
        proc_name, proc_path = process_allowlist.event_process(ev)
        if proc_name or proc_path:
            label = proc_path or proc_name
            if QMessageBox.question(
                    self, "Trust process",
                    f"Trust this exact process for process-attributed alerts?\n\n{label}\n\n"
                    "A trusted process is excluded from threat posture and automatic "
                    "response. Use this only when you recognize it.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                return
            try:
                process_allowlist.add(
                    proc_name,
                    proc_path,
                    source="resolve",
                )
            except Exception as exc:
                QMessageBox.warning(self, "Trust process", str(exc))
                return
            self._last_key = None
            self._refresh()
            return
        ap = self._alerts_panel()
        if ap is not None:
            try:
                ap._allow_event(ev)
            except Exception:
                pass
        alert_ack.ack(ev, "allowed via Resolve Center")
        self._last_key = None      # force a rebuild
        self._refresh()

    def _block(self, ev) -> None:
        """Block = queue a SOAR containment request for review (never auto-executes)."""
        ap = self._alerts_panel()
        if ap is not None:
            try:
                ap._block_event(ev)
            except Exception as exc:
                QMessageBox.warning(self, "Block", f"Could not queue containment: {exc}")
        else:
            QMessageBox.information(self, "Block",
                                    "The Live Alerts panel isn't available to queue containment.")
        self._last_key = None
        self._refresh()

    def _ignore(self, ev) -> None:
        alert_ack.ack(ev, "operator ignore (Resolve Center — false positive / handled)")
        self._last_key = None
        self._refresh()

    def _ignore_all_shown(self) -> None:
        evs = self._events()
        if not evs:
            return
        if QMessageBox.question(
                self, "Ignore all shown",
                f"Ignore all {len(evs)} active CRITICAL/HIGH alert(s)? They stay listed (with "
                "history) and can be reverted, but stop affecting the threat level. Repeats of "
                "each class are also suppressed.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                ) != QMessageBox.StandardButton.Yes:
            return
        seen = set()
        for ev in evs:
            sig = alert_ack.signature(ev)
            if sig in seen:
                continue
            seen.add(sig)
            alert_ack.ack(ev, "mass-ignore via Resolve Center")
        self._last_key = None
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
        b = QPushButton("Close"); b.clicked.connect(dlg.close); v.addWidget(b)
        dlg.exec()
