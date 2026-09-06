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

import hashlib
import json
import queue
import threading
import time
from dataclasses import dataclass

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication, QDialog, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from angerona.core.eventbus import Severity
from angerona.core.threat import active_threat_events, threat_label_from_active
from angerona.core import alert_ack
from angerona.core import process_allowlist

_SEV_COLOR = {"CRITICAL": "#f87171", "HIGH": "#fb923c", "MEDIUM": "#facc15"}
_READERS = threading.BoundedSemaphore(2)
_SCAN_CAP = 5000
_HISTORY_CACHE_SECONDS = 30.0


def _event_identity(event) -> str:
    """Presentation identity only; never a substitute for action authentication."""
    record = (
        getattr(event, "ts", 0), getattr(event, "module", ""),
        int(getattr(event, "severity", Severity.INFO)),
        getattr(event, "message", ""), getattr(event, "details", {}),
        getattr(event, "hmac_sig", ""),
    )
    encoded = json.dumps(record, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8", "replace")).hexdigest()


@dataclass(frozen=True)
class _AlertRow:
    event: object
    identity: str
    when: str
    severity: str
    module: str
    message: str


@dataclass(frozen=True)
class _ResolveSnapshot:
    rows: tuple[_AlertRow, ...]
    ignored: tuple[dict, ...]
    label: str
    color: str


class _SnapshotUnavailable(Exception):
    pass


class _SnapshotReader:
    """Worker-only reader. No QObject, widget, or callback into a dialog."""

    def __init__(self, bus, storage, window_s: int):
        self.bus, self.storage, self.window_s = bus, storage, window_s
        self._stored: tuple | None = None
        self._revision = None
        self._queried_at = 0.0

    def read(self, force: bool = False) -> _ResolveSnapshot:
        now = time.time()
        revision = self.storage.revision()
        if (force or self._stored is None or revision != self._revision
                or time.monotonic() - self._queried_at >= _HISTORY_CACHE_SECONDS):
            stored = self.storage.try_recent_in_window(
                now - self.window_s, now, Severity.HIGH, _SCAN_CAP)
            if stored is None:
                raise _SnapshotUnavailable("History reader is busy")
            self._stored = tuple(stored[:_SCAN_CAP])
            self._revision = revision
            self._queried_at = time.monotonic()

        # Include events not yet committed by the asynchronous storage writer.
        # Read the bus on every refresh, independently of the storage revision.
        events = {}
        for event in (*self._stored, *self.bus.recent(_SCAN_CAP)):
            if (now - self.window_s <= getattr(event, "ts", 0) <= now
                    and getattr(event, "severity", Severity.INFO) >= Severity.HIGH):
                events.setdefault(_event_identity(event), event)
        ordered = sorted(events.items(), key=lambda pair: pair[1].ts, reverse=True)[:_SCAN_CAP]
        # Reclassify even when history is cached: policy/ack changes (including
        # same-count replacements), drill resolution and expiry must take effect.
        active = active_threat_events([event for _, event in ordered], window=self.window_s)
        identities = {id(event): identity for identity, event in ordered}
        rows = []
        for event in active:
            severity = getattr(event, "severity", Severity.INFO)
            rows.append(_AlertRow(
                event, identities[id(event)],
                time.strftime("%m-%d %H:%M:%S", time.localtime(event.ts)),
                getattr(severity, "name", str(severity)),
                str(getattr(event, "module", ""))[:160],
                str(getattr(event, "message", ""))[:1600],
            ))
        # Resolve retains a day of actionable history; its header uses the same
        # ten-minute posture window as the dashboard without classifying twice.
        label, color = threat_label_from_active(
            [event for event in active if 0 <= now - event.ts <= 600.0])
        return _ResolveSnapshot(tuple(rows), tuple(alert_ack.acked_records()), label, color)


def _read_snapshot(reader, results, closed, generation, force) -> None:
    try:
        if closed.is_set():
            return
        try:
            snapshot, error = reader.read(force=force), ""
        except _SnapshotUnavailable:
            snapshot, error = None, "History reader is busy; keeping the previous view. Retrying…"
        except Exception:
            snapshot, error = None, "Could not refresh alerts; keeping the previous view. Retrying…"
        if not closed.is_set():
            results.put_nowait((generation, snapshot, error))
    finally:
        _READERS.release()


class ResolveCenter(QDialog):
    def __init__(self, bus, storage, manager, parent=None, window_s: int = 86400) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.bus, self.storage, self.manager = bus, storage, manager
        self.window_s = window_s
        self._reader = _SnapshotReader(bus, storage, window_s)
        self._snapshot: _ResolveSnapshot | None = None
        self._results: queue.Queue = queue.Queue(maxsize=1)
        self._closed = threading.Event()
        self._busy = False
        self._pending_refresh = False
        self._force_reload = False
        self._generation = 0
        self._render_key = None
        closed = self._closed
        self.destroyed.connect(lambda *_: closed.set())
        self.finished.connect(lambda *_: closed.set())
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
        self._status = QLabel("Loading alerts…")
        self._status.setStyleSheet("color:#9aa4b2;")
        root.addWidget(self._status)

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

        navigation = QHBoxLayout()
        self._foot = QLabel("")
        self._foot.setStyleSheet("color:#9aa4b2;")
        self._foot.setWordWrap(True)
        navigation.addWidget(self._foot, 1)
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
        refresh = QPushButton("Refresh"); refresh.clicked.connect(self._reload)
        close = QPushButton("Close"); close.clicked.connect(self.close)
        for b in (self._previous_btn, self._page_label, self._next_btn):
            navigation.addWidget(b)
        root.addLayout(navigation)
        bar = QHBoxLayout()
        for b in (self._detail_btn, self._allow_btn, self._block_btn, self._ignore_btn,
                  ignore_all_btn, ignored_btn, refresh, close):
            bar.addWidget(b)
        root.addLayout(bar)
        self._sync_action_state()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(4000)
        self._result_timer = QTimer(self)
        self._result_timer.timeout.connect(self._drain_results)
        self._refresh()

    # ── data ─────────────────────────────────────────────────────────────────
    _SCAN_CAP = _SCAN_CAP

    def _events(self) -> list:
        """Return the displayed snapshot without touching storage or policy files."""
        return [row.event for row in self._snapshot.rows] if self._snapshot else []

    def _refresh(self, *_args) -> None:
        if self._closed.is_set():
            return
        if self._busy:
            self._pending_refresh = True
            return
        if not _READERS.acquire(blocking=False):
            self._status.setText("Alert readers are busy; keeping the previous view. Retrying…")
            return
        self._busy = True
        self._pending_refresh = False
        self._status.setText("Refreshing alerts…" if self._snapshot else "Loading alerts…")
        force, self._force_reload = self._force_reload, False
        try:
            threading.Thread(
                target=_read_snapshot,
                args=(self._reader, self._results, self._closed, self._generation, force),
                name="Resolve snapshot", daemon=True,
            ).start()
            self._result_timer.start(50)
        except Exception:
            _READERS.release()
            self._busy = False
            self._status.setText("Could not start alert refresh; retrying…")

    def _reload(self, *_args) -> None:
        self._force_reload = True
        self._invalidate_snapshot()

    def _invalidate_snapshot(self) -> None:
        # Never apply a pre-action result after the operator has changed policy.
        self._generation += 1
        self._refresh()

    def _drain_results(self) -> None:
        if self._closed.is_set():
            self._timer.stop()
            self._result_timer.stop()
            return
        try:
            generation, snapshot, error = self._results.get_nowait()
        except queue.Empty:
            return
        self._result_timer.stop()
        self._busy = False
        if generation == self._generation:
            self._status.setText(error)
            if snapshot is not None:
                self._snapshot = snapshot
                self._render_page()
        if self._pending_refresh or generation != self._generation:
            self._refresh()

    def closeEvent(self, event) -> None:
        self._closed.set()
        self._timer.stop()
        self._result_timer.stop()
        super().closeEvent(event)

    def _render_page(self, *, reset_selection: bool = False) -> None:
        snapshot = self._snapshot
        if snapshot is None:
            return
        rows = snapshot.rows
        page_count = max(1, (len(rows) + self._page_size - 1) // self._page_size)
        self._page = min(self._page, page_count - 1)
        start = self._page * self._page_size
        shown = rows[start:start + self._page_size]
        key = (tuple(row.identity for row in shown), len(rows), len(snapshot.ignored),
               snapshot.label, snapshot.color, self._page)
        if key == self._render_key:
            return
        first_render = self._render_key is None
        selected = self.table.item(self.table.currentRow(), 0)
        selected_identity = selected.data(Qt.UserRole + 1) if selected is not None else None
        self._render_key = key
        self._head.setText(f"🛠  Resolve Center — threat level: {snapshot.label}")
        self._head.setStyleSheet(f"color:{snapshot.color};")
        if not rows:
            self._sub.setText("✅  Nothing left to resolve — the posture is Secure.")
        else:
            self._sub.setText(f"{len(rows)} unresolved CRITICAL/HIGH alert(s). Open Detail to "
                              "Allow / Block / Research / Apply fix, or Ignore a false positive "
                              "to remove it from the threat level.")
        self._page_events = [row.event for row in shown]
        first = start + 1 if shown else 0
        last = start + len(shown)
        self._foot.setText(
            f"{len(rows)} active · {len(snapshot.ignored)} ignored · showing {first}–{last}. "
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
        for r, row in enumerate(shown):
            time_item = QTableWidgetItem(row.when)
            time_item.setData(Qt.UserRole, row.event)
            time_item.setData(Qt.UserRole + 1, row.identity)
            self.table.setItem(r, 0, time_item)
            sev_it = QTableWidgetItem(row.severity)
            sev_it.setForeground(QColor(_SEV_COLOR.get(row.severity, "#e5e7eb")))
            self.table.setItem(r, 1, sev_it)
            self.table.setItem(r, 2, QTableWidgetItem(row.module))
            self.table.setItem(r, 3, QTableWidgetItem(row.message))
        self.table.setSortingEnabled(True)
        if sort_column >= 0:
            self.table.sortItems(sort_column, sort_order)
        self.table.setUpdatesEnabled(True)
        self.table.clearSelection()
        self.table.setCurrentCell(-1, -1)
        if shown and (first_render or reset_selection):
            self.table.selectRow(0)
        elif selected_identity is not None:
            for row in range(self.table.rowCount()):
                if self.table.item(row, 0).data(Qt.UserRole + 1) == selected_identity:
                    self.table.selectRow(row)
                    break
        self._sync_action_state()

    def _change_page(self, delta: int) -> None:
        new_page = max(0, self._page + delta)
        if new_page == self._page:
            return
        self._page = new_page
        self._render_page(reset_selection=True)

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
            self._invalidate_snapshot()
            return
        ap = self._alerts_panel()
        if ap is not None:
            try:
                ap._allow_event(ev)
            except Exception:
                pass
        alert_ack.ack(ev, "allowed via Resolve Center")
        self._invalidate_snapshot()

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
        self._invalidate_snapshot()

    def _ignore(self, ev) -> None:
        alert_ack.ack(ev, "operator ignore (Resolve Center — false positive / handled)")
        self._invalidate_snapshot()

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
        self._invalidate_snapshot()

    def _show_ignored(self) -> None:
        recs = self._snapshot.ignored if self._snapshot else ()
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
                                                  self._invalidate_snapshot()))
            wrap = QWidget(); wl = QHBoxLayout(wrap); wl.setContentsMargins(4, 1, 4, 1)
            wl.addWidget(btn); tbl.setCellWidget(r, 3, wrap)
        v.addWidget(tbl, 1)
        b = QPushButton("Close"); b.clicked.connect(dlg.close); v.addWidget(b)
        dlg.exec()
