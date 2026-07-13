"""
gui/attack_heatmap.py — Live MITRE ATT&CK heatmap dialog.

Three tabs:
  • Live Heat  — 14 tactic columns × N technique rows, coloured by heat score
    (0 = dark/inactive → blue → amber → red at 1.0). Click a cell for details:
    full technique info, recent event IDs (click to pivot), which Angerona
    module covers it, and a MITRE ATT&CK link.
  • Coverage   — the honest Detect / Simulate / Remediate matrix from
    core.attack_coverage, with blind spots highlighted and an overall %.
  • Top        — the currently hottest techniques, ranked.

Toolbar: threat-actor filter, technique search, active-only toggle, Explain
posture (local AI), Export to Navigator, Reset. Refresh every 5s via QTimer;
never blocks the Qt main thread. Local-first: reads AttackTracker.snapshot()
and attack_coverage; the only optional network call is loopback Ollama.
"""
from __future__ import annotations

import json
import threading
import time
import webbrowser
from typing import Callable

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import (
    QBrush, QColor, QFont, QPen, QPolygonF,
)
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFileDialog, QGraphicsItem, QGraphicsRectItem,
    QGraphicsScene, QGraphicsTextItem, QGraphicsView, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QPushButton, QSizePolicy, QTabWidget, QTableWidget,
    QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget,
)

from angerona.core.attack_tracker import (
    TACTIC_ORDER, THREAT_ACTOR_PLAYBOOKS, _TACTIC_TO_TECHNIQUES, _TID_TO_META,
    get_tracker,
)

# ── Layout constants ─────────────────────────────────────────────────────────
_CW    = 108   # cell width  px
_CH    = 34    # cell height px
_GAP   = 6     # horizontal gap between tactic columns
_HDR_H = 56    # tactic header band height
_PAD   = 12    # scene outer padding

# ── Tactic band colours ──────────────────────────────────────────────────────
_TACTIC_CLR: dict[str, str] = {
    "TA0043": "#374151", "TA0042": "#1e3a5f", "TA0001": "#7c2d12",
    "TA0002": "#581c87", "TA0003": "#14532d", "TA0004": "#713f12",
    "TA0005": "#1e1b4b", "TA0006": "#7f1d1d", "TA0007": "#164e63",
    "TA0008": "#1a1a2e", "TA0009": "#3b0764", "TA0011": "#0c4a6e",
    "TA0010": "#431407", "TA0040": "#450a0a",
}


def _heat_color(heat: float) -> QColor:
    if heat <= 0.0:
        return QColor("#0f172a")
    if heat < 0.15:
        return QColor("#1e3a5f")
    if heat < 0.35:
        return QColor("#1d4ed8")
    if heat < 0.55:
        return QColor("#d97706")
    if heat < 0.75:
        return QColor("#ea580c")
    return QColor("#dc2626")


def _heat_border(heat: float) -> QColor:
    if heat <= 0:
        return QColor("#1e293b")
    if heat < 0.35:
        return QColor("#3b82f6")
    if heat < 0.55:
        return QColor("#f59e0b")
    return QColor("#ef4444")


def _mitre_url(tid: str) -> str:
    base = tid.split(".")[0]
    sub = tid.split(".")[1] if "." in tid else None
    return f"https://attack.mitre.org/techniques/{base}/" + (f"{sub}/" if sub else "")


# ── Clickable technique cell ─────────────────────────────────────────────────
class _CellItem(QGraphicsRectItem):
    def __init__(self, tid: str, label: str, x: float, y: float,
                 on_click: Callable[[str], None]) -> None:
        super().__init__(x, y, _CW, _CH)
        self.tid      = tid
        self._on_click = on_click
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(1)

        self._lbl = QGraphicsTextItem(label, self)
        self._lbl.setDefaultTextColor(QColor("#e2e8f0"))
        self._lbl.setFont(QFont("Segoe UI", 8))
        self._lbl.setTextWidth(_CW - 4)
        self._lbl.setPos(x + 2, y + 2)
        self._lbl.setZValue(2)

        self._bar = QGraphicsRectItem(x, y + _CH - 3, _CW, 3, self)
        self._bar.setPen(QPen(Qt.NoPen))
        self._bar.setZValue(3)

        self.set_heat(0.0)

    def set_heat(self, heat: float, count: int = 0, dimmed: bool = False) -> None:
        self._heat   = heat
        self._dimmed = dimmed
        if dimmed:
            self.setBrush(QBrush(QColor("#0c111a")))
            self.setPen(QPen(QColor("#1a2234"), 0.5))
            self._bar.setBrush(QBrush(QColor("#0c111a")))
            self.setToolTip(f"{self.tid}  [filtered out]")
        else:
            clr    = _heat_color(heat)
            border = _heat_border(heat)
            self.setBrush(QBrush(clr.darker(110)))
            self.setPen(QPen(border, 0.8))
            self._bar.setBrush(QBrush(_heat_color(min(1.0, heat * 1.4))))
            self.setToolTip(f"{self.tid}  heat={heat:.2f}  hits={count}")

    def mousePressEvent(self, _event) -> None:  # type: ignore[override]
        self._on_click(self.tid)

    def hoverEnterEvent(self, _event) -> None:  # type: ignore[override]
        pen = self.pen(); pen.setWidth(2); self.setPen(pen)

    def hoverLeaveEvent(self, _event) -> None:  # type: ignore[override]
        self.set_heat(self._heat)


# ── Heatmap window ───────────────────────────────────────────────────────────
class AttackHeatmapWindow(QDialog):
    event_clicked = Signal(str)
    _posture_ready = Signal(str)
    _REFRESH_MS   = 5_000

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("🔥  MITRE ATT&CK Heatmap  — Live")
        self.setMinimumSize(1420, 720)
        self.resize(1540, 820)
        self.setAttribute(Qt.WA_DeleteOnClose, False)

        self._cells: dict[str, _CellItem] = {}
        self._scene = QGraphicsScene(self)
        self._view  = QGraphicsView(self._scene, self)
        self._view.setRenderHints(self._view.renderHints())
        self._view.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self._view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self._view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._view.setStyleSheet("background: #0d1117; border: none;")

        # ── Toolbar ───────────────────────────────────────────────────────────
        self._stats_lbl = QLabel("Initialising…")
        self._stats_lbl.setStyleSheet("color:#94a3b8; font:8pt 'Segoe UI'; padding:4px 8px;")
        self._stats_lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        self._actor: str = "— All —"
        self._actor_combo = QComboBox()
        self._actor_combo.addItems(["— All —"] + list(THREAT_ACTOR_PLAYBOOKS.keys()))
        self._actor_combo.setFixedWidth(180)
        self._actor_combo.setToolTip("Filter by threat actor: dims techniques outside their playbook.")
        self._actor_combo.setStyleSheet(
            "QComboBox{background:#1e293b;color:#cbd5e1;border:1px solid #334155;"
            "border-radius:4px;padding:2px 6px;font:8pt 'Segoe UI';}"
            "QComboBox::drop-down{border:none;}"
            "QComboBox QAbstractItemView{background:#1e293b;color:#cbd5e1;"
            "selection-background-color:#334155;border:1px solid #334155;}")
        self._actor_combo.currentTextChanged.connect(self._on_actor_changed)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search technique / id…")
        self._search.setFixedWidth(160)
        self._search.setStyleSheet(
            "QLineEdit{background:#1e293b;color:#cbd5e1;border:1px solid #334155;"
            "border-radius:4px;padding:2px 6px;font:8pt 'Segoe UI';}")
        self._search.textChanged.connect(lambda _t: self._refresh())

        self._active_only = QCheckBox("Active only")
        self._active_only.setStyleSheet("color:#cbd5e1;font:8pt 'Segoe UI';")
        self._active_only.stateChanged.connect(lambda _s: self._refresh())

        explain_btn = QPushButton("Explain posture")
        explain_btn.setFixedWidth(120)
        explain_btn.setToolTip("Plain-English summary of the current matrix (local AI, with a heuristic fallback).")
        explain_btn.clicked.connect(self._explain_posture)

        export_nav_btn = QPushButton("Export to Navigator")
        export_nav_btn.setFixedWidth(150)
        export_nav_btn.setToolTip("Save active techniques as a MITRE ATT&CK Navigator v4.9 layer JSON")
        export_nav_btn.clicked.connect(self._export_navigator)

        reset_btn = QPushButton("Reset counts")
        reset_btn.setFixedWidth(105)
        reset_btn.clicked.connect(self._reset)

        stats_row = QHBoxLayout()
        stats_row.addWidget(self._stats_lbl)
        stats_row.addStretch(1)
        for w in (self._search, self._active_only, self._actor_combo,
                  explain_btn, export_nav_btn, reset_btn):
            stats_row.addWidget(w)

        # ── Detail panel ──────────────────────────────────────────────────────
        self._detail_hdr = QLabel("Click a technique cell for details")
        self._detail_hdr.setStyleSheet("color:#f1f5f9; font:9pt 'Segoe UI' bold; padding:4px 8px;")
        self._detail_txt = QTextBrowser()
        self._detail_txt.setReadOnly(True)
        self._detail_txt.setOpenLinks(False)
        self._detail_txt.anchorClicked.connect(self._on_anchor)
        self._detail_txt.setFixedHeight(120)
        self._detail_txt.setStyleSheet(
            "background:#1e293b; color:#cbd5e1; font:8pt 'Consolas'; border:none; padding:4px;")
        self._detail_txt.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        detail_box = QVBoxLayout()
        detail_box.setContentsMargins(0, 0, 0, 0); detail_box.setSpacing(0)
        detail_box.addWidget(self._detail_hdr)
        detail_box.addWidget(self._detail_txt)

        # ── Tabs ──────────────────────────────────────────────────────────────
        heat_tab = QWidget()
        hl = QVBoxLayout(heat_tab); hl.setContentsMargins(0, 0, 0, 0); hl.setSpacing(0)
        hl.addWidget(self._view, 1); hl.addLayout(detail_box)

        self._tabs = QTabWidget()
        self._tabs.addTab(heat_tab, "🔥  Live Heat")
        self._tabs.addTab(self._build_coverage_tab(), "🛡  Coverage")
        self._tabs.addTab(self._build_top_tab(), "📊  Top Techniques")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
        root.addLayout(stats_row)
        root.addWidget(self._tabs, 1)

        self._build_scene()
        self._posture_ready.connect(self._show_posture)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(self._REFRESH_MS)
        self._refresh()

    # ── Coverage tab ─────────────────────────────────────────────────────────
    def _build_coverage_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        self._cov_hdr = QLabel("Coverage…")
        self._cov_hdr.setStyleSheet("color:#e2e8f0; font:9pt 'Segoe UI' bold; padding:4px 2px;")
        lay.addWidget(self._cov_hdr)
        lay.addWidget(QLabel("Honest Detect / Simulate / Remediate matrix — gaps are shown, not hidden. "
                             "The Remediate column is cross-checked against the real vetted-action allow-list."))
        self._cov_tbl = QTableWidget()
        self._cov_tbl.setColumnCount(6)
        self._cov_tbl.setHorizontalHeaderLabels(
            ["Technique", "Tactic", "Detect", "Simulate", "Remediate", "Status"])
        self._cov_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self._cov_tbl.setAlternatingRowColors(True)
        self._cov_tbl.verticalHeader().setVisible(False)
        self._cov_tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._cov_tbl.setStyleSheet("QTableWidget{font-size:11px;} QTableWidget::item{padding:3px 6px;}")
        lay.addWidget(self._cov_tbl, 1)
        return w

    def _refresh_coverage(self) -> None:
        try:
            from angerona.core import attack_coverage as cov
        except Exception:
            return
        s = cov.summary()
        self._cov_hdr.setText(
            f"Coverage: {s['covered']}/{s['techniques']} techniques covered "
            f"({s['coverage_pct']}%)   ·   Detect {s['detect']}   ·   "
            f"Simulate {s['simulate']}   ·   Remediate {s['remediate']}")
        valid = cov._valid_action_keys()
        rows = cov.COVERAGE
        self._cov_tbl.setRowCount(len(rows))
        for i, t in enumerate(rows):
            rem_ok = [k for k in t.remediate if k in valid]
            covered = bool(t.detect) or bool(rem_ok)
            cells = [
                f"{t.tid}  {t.name}", t.tactic,
                ", ".join(t.detect) or "·",
                ", ".join(t.simulate) or "·",
                ", ".join(rem_ok) or "·",
                "✓ covered" if covered else "✗ GAP",
            ]
            for c, txt in enumerate(cells):
                it = QTableWidgetItem(txt)
                if c == 5:
                    it.setForeground(QColor("#22c55e" if covered else "#ef4444"))
                elif c in (2, 3, 4) and txt == "·":
                    it.setForeground(QColor("#475569"))
                self._cov_tbl.setItem(i, c, it)

    # ── Top techniques tab ───────────────────────────────────────────────────
    def _build_top_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(QLabel("The currently hottest techniques (by decayed heat), most active first. "
                             "Double-click a row to open its MITRE ATT&CK page."))
        self._top_tbl = QTableWidget()
        self._top_tbl.setColumnCount(6)
        self._top_tbl.setHorizontalHeaderLabels(
            ["#", "Technique", "Tactic", "Hits", "Heat", "Last seen"])
        self._top_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self._top_tbl.setAlternatingRowColors(True)
        self._top_tbl.verticalHeader().setVisible(False)
        self._top_tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._top_tbl.setStyleSheet("QTableWidget{font-size:11px;} QTableWidget::item{padding:3px 6px;}")
        self._top_tbl.cellDoubleClicked.connect(self._on_top_double)
        lay.addWidget(self._top_tbl, 1)
        return w

    def _refresh_top(self, snap: dict) -> None:
        matrix = snap.get("matrix", {})
        active = [(tid, r) for tid, r in matrix.items() if r.get("count", 0) > 0]
        active.sort(key=lambda kv: kv[1].get("heat", 0), reverse=True)
        active = active[:25]
        self._top_tbl.setRowCount(len(active))
        for i, (tid, r) in enumerate(active):
            meta = _TID_TO_META.get(tid, (tid, "?", tid))
            vals = [str(i + 1), f"{tid}  {meta[0]}", meta[1],
                    str(r.get("count", 0)), f"{r.get('heat', 0):.3f}",
                    r.get("last_seen") or "—"]
            for c, txt in enumerate(vals):
                it = QTableWidgetItem(txt)
                if c == 0:
                    it.setData(Qt.UserRole, tid)
                if c == 4:
                    it.setForeground(_heat_border(r.get("heat", 0)))
                self._top_tbl.setItem(i, c, it)

    def _on_top_double(self, row: int, _col: int) -> None:
        it = self._top_tbl.item(row, 0)
        tid = it.data(Qt.UserRole) if it else None
        if tid:
            try:
                webbrowser.open(_mitre_url(tid))
            except Exception:
                pass

    # ── Scene construction ───────────────────────────────────────────────────
    def _build_scene(self) -> None:
        scene = self._scene
        max_techs = max(len(_TACTIC_TO_TECHNIQUES.get(tid, [])) for tid, _ in TACTIC_ORDER)
        scene_w = _PAD + len(TACTIC_ORDER) * (_CW + _GAP) + _PAD
        scene_h = _PAD + _HDR_H + max_techs * (_CH + 2) + _PAD
        scene.setSceneRect(0, 0, scene_w, scene_h)

        for col_idx, (tac_id, tac_name) in enumerate(TACTIC_ORDER):
            cx = _PAD + col_idx * (_CW + _GAP); cy = _PAD
            tac_clr = QColor(_TACTIC_CLR.get(tac_id, "#334155"))
            hdr = QGraphicsRectItem(cx, cy, _CW, _HDR_H)
            hdr.setBrush(QBrush(tac_clr)); hdr.setPen(QPen(tac_clr.lighter(130), 0.5))
            hdr.setZValue(1); scene.addItem(hdr)
            t = QGraphicsTextItem(f"{tac_id}\n{tac_name}")
            t.setDefaultTextColor(QColor("#f8fafc"))
            t.setFont(QFont("Segoe UI", 7, QFont.Bold))
            t.setTextWidth(_CW - 4); t.setPos(cx + 2, cy + 4); t.setZValue(2)
            scene.addItem(t)
            for row_idx, tid in enumerate(_TACTIC_TO_TECHNIQUES.get(tac_id, [])):
                ty = cy + _HDR_H + row_idx * (_CH + 2)
                lbl = _TID_TO_META[tid][0] if tid in _TID_TO_META else tid
                cell = _CellItem(tid, lbl, cx, ty, self._on_cell_clicked)
                scene.addItem(cell); scene.addItem(cell._lbl); scene.addItem(cell._bar)
                self._cells[tid] = cell

    # ── Refresh ──────────────────────────────────────────────────────────────
    def _refresh(self) -> None:
        tracker = get_tracker()
        if tracker is None:
            self._stats_lbl.setText("No tracker — start the application first")
            return
        snap   = tracker.snapshot()
        matrix = snap.get("matrix", {})
        summ   = snap.get("summary", {})

        actor = getattr(self, "_actor", "— All —")
        playbook: set[str] | None = None
        if actor != "— All —":
            playbook = set(THREAT_ACTOR_PLAYBOOKS.get(actor, []))
        query = (self._search.text() or "").strip().lower()
        active_only = self._active_only.isChecked()

        for tid, cell in self._cells.items():
            row   = matrix.get(tid, {})
            heat  = row.get("heat", 0.0)
            count = row.get("count", 0)
            dim = False
            if playbook is not None:
                in_pb = (tid in playbook or any(tid.startswith(p + ".") for p in playbook))
                dim = dim or not in_pb
            if active_only and count <= 0:
                dim = True
            if query:
                meta = _TID_TO_META.get(tid, (tid, "", tid))
                hay = f"{tid} {meta[0]} {meta[2]}".lower()
                if query not in hay:
                    dim = True
            cell.set_heat(heat, count, dimmed=dim)

        n_active = summ.get("techniques_active", 0)
        n_tacs   = summ.get("tactics_active", 0)
        top_tid  = summ.get("highest_heat_tid") or "—"
        top_lbl  = summ.get("highest_heat_label") or "—"
        actor_sfx = f"  |  Actor: {actor}" if actor != "— All —" else ""
        self._stats_lbl.setText(
            f"Active techniques: {n_active}  |  Active tactics: {n_tacs}  |  "
            f"Hottest: {top_tid} ({top_lbl})  |  Updated: {snap.get('generated', '—')}{actor_sfx}")

        self._refresh_top(snap)
        self._refresh_coverage()

    # ── Cell click detail ────────────────────────────────────────────────────
    def _on_cell_clicked(self, tid: str) -> None:
        tracker = get_tracker()
        if tracker is None:
            return
        snap = tracker.snapshot()
        row  = snap.get("matrix", {}).get(tid)
        if row is None:
            return
        meta = _TID_TO_META.get(tid, (tid, "?", tid))
        last = row.get("last_seen") or "never"
        ids  = row.get("event_ids", [])

        self._detail_hdr.setText(
            f"  {tid}  ·  {meta[2]}  ·  heat={row['heat']:.3f}  hits={row['count']}  last={last}")

        # coverage lookup by base technique id
        cov_line = "<span style='color:#475569'>not in coverage map</span>"
        try:
            from angerona.core import attack_coverage as cov
            base = tid.split(".")[0]
            match = next((t for t in cov.COVERAGE if t.tid == tid or t.tid == base), None)
            if match:
                valid = cov._valid_action_keys()
                d = ", ".join(match.detect) or "·"
                s = ", ".join(match.simulate) or "·"
                r = ", ".join(k for k in match.remediate if k in valid) or "·"
                cov_line = (f"<span style='color:#a7f3d0'>Detect:</span> {d} &nbsp; "
                            f"<span style='color:#93c5fd'>Simulate:</span> {s} &nbsp; "
                            f"<span style='color:#fca5a5'>Remediate:</span> {r}")
        except Exception:
            pass

        id_links = "".join(
            f'&nbsp;&nbsp;<a href="evt:{eid}" style="color:#38bdf8;text-decoration:none;">{eid}</a><br>'
            for eid in ids
        ) or "&nbsp;&nbsp;<span style='color:#475569'>(none recorded)</span>"

        self._detail_txt.setHtml(
            "<span style='color:#cbd5e1;font-family:Consolas;font-size:8pt;'>"
            f"<b>Technique&nbsp;:</b> {tid} &nbsp; "
            f"<a href='{_mitre_url(tid)}' style='color:#38bdf8;'>[MITRE ATT&CK ↗]</a><br>"
            f"<b>Full name&nbsp;:</b> {meta[2]} &nbsp; <b>Tactic:</b> {meta[1]}<br>"
            f"<b>Hits&nbsp;:</b> {row['count']} &nbsp; <b>Heat:</b> {row['heat']:.4f} &nbsp; "
            f"<b>Last seen:</b> {last}<br>"
            f"<b>Coverage&nbsp;:</b> {cov_line}<br>"
            f"<b>Event IDs</b> (click to pivot):<br>{id_links}</span>")

    def _on_anchor(self, url) -> None:
        s = url.toString()
        if s.startswith("http"):
            try:
                webbrowser.open(s)
            except Exception:
                pass
        elif s.startswith("evt:"):
            self.event_clicked.emit(s[4:])
        else:
            self.event_clicked.emit(s)

    # ── Threat Actor filter ───────────────────────────────────────────────────
    def _on_actor_changed(self, actor: str) -> None:
        self._actor = actor
        self._refresh()

    # ── Explain posture (local AI, heuristic fallback) ───────────────────────
    def _explain_posture(self) -> None:
        tracker = get_tracker()
        snap = tracker.snapshot() if tracker else {"matrix": {}, "summary": {}}
        self._show_posture("⏳ Analyzing current ATT&CK posture…")
        threading.Thread(target=self._posture_worker, args=(snap,), daemon=True).start()

    def _posture_worker(self, snap: dict) -> None:
        text = self._heuristic_posture(snap)
        ai = self._ollama_posture(snap)
        if ai:
            text = ai + "\n\n— — —\n(heuristic) " + text
        self._posture_ready.emit(text)

    def _heuristic_posture(self, snap: dict) -> str:
        matrix = snap.get("matrix", {}); summ = snap.get("summary", {})
        active = sorted(((t, r) for t, r in matrix.items() if r.get("count", 0) > 0),
                        key=lambda kv: kv[1].get("heat", 0), reverse=True)
        try:
            from angerona.core import attack_coverage as cov
            cs = cov.summary(); cov_pct = cs["coverage_pct"]
        except Exception:
            cov_pct = None
        lines = []
        if not active:
            lines.append("Posture: quiet — no techniques have fired in the current window.")
        else:
            top = ", ".join(f"{t} ({_TID_TO_META.get(t,(t,'',''))[0]})" for t, _ in active[:5])
            lines.append(f"Posture: {summ.get('techniques_active',0)} active technique(s) across "
                         f"{summ.get('tactics_active',0)} tactic(s). Hottest: {top}.")
        if cov_pct is not None:
            lines.append(f"Detection coverage sits at {cov_pct}% of the mapped techniques "
                         "(see the Coverage tab for the exact gaps).")
        return " ".join(lines)

    def _ollama_posture(self, snap: dict) -> str | None:
        import os, urllib.request
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        model = os.environ.get("ANGERONA_MODEL", "llama3")
        matrix = snap.get("matrix", {})
        active = sorted(((t, r) for t, r in matrix.items() if r.get("count", 0) > 0),
                        key=lambda kv: kv[1].get("heat", 0), reverse=True)[:10]
        facts = json.dumps({"active_techniques": [
            {"tid": t, "name": _TID_TO_META.get(t, (t, "", ""))[0],
             "hits": r.get("count"), "heat": round(r.get("heat", 0), 3)} for t, r in active]})
        payload = json.dumps({
            "model": model, "stream": False, "keep_alive": "30m",
            "options": {"temperature": 0},
            "messages": [
                {"role": "system", "content": "You are a SOC analyst. In 3-5 calm sentences, "
                 "summarise this host's MITRE ATT&CK activity and what to watch. No markdown headers."},
                {"role": "user", "content": facts}]}).encode()
        try:
            req = urllib.request.Request(f"{host}/api/chat", data=payload,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            return ((data.get("message", {}) or {}).get("content", "") or "").strip() or None
        except Exception:
            return None

    def _show_posture(self, text: str) -> None:
        if getattr(self, "_posture_dlg", None) is None:
            self._posture_dlg = QDialog(self)
            self._posture_dlg.setWindowTitle("ATT&CK posture")
            self._posture_dlg.resize(560, 320)
            v = QVBoxLayout(self._posture_dlg)
            self._posture_body = QTextBrowser()
            v.addWidget(self._posture_body)
            b = QPushButton("Close"); b.clicked.connect(self._posture_dlg.accept)
            v.addWidget(b)
        self._posture_body.setPlainText(text)
        self._posture_dlg.show(); self._posture_dlg.raise_(); self._posture_dlg.activateWindow()

    # ── ATT&CK Navigator export ───────────────────────────────────────────────
    def _export_navigator(self) -> None:
        tracker = get_tracker()
        if tracker is None:
            return
        snap   = tracker.snapshot()
        matrix = snap.get("matrix", {})
        techniques = []
        for tid, row in matrix.items():
            if row["count"] == 0:
                continue
            techniques.append({
                "techniqueID": tid, "score": int(round(row["heat"] * 100)), "color": "",
                "comment": f"hits={row['count']} last={row.get('last_seen') or 'never'}",
                "enabled": True, "metadata": [], "showSubtechniques": False,
            })
        layer = {
            "name": "Angerona Live Heatmap",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Exported {time.strftime('%Y-%m-%dT%H:%M:%S')} from Angerona live ATT&CK heat tracker",
            "filters": {"platforms": ["Windows"]}, "sorting": 3,
            "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
            "hideDisabled": False, "techniques": techniques,
            "gradient": {"colors": ["#0f172a", "#1d4ed8", "#d97706", "#dc2626"], "minValue": 0, "maxValue": 100},
            "legendItems": [], "metadata": [], "showTacticRowBackground": True,
            "tacticRowBackground": "#15202b", "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False, "links": [],
        }
        default_name = f"angerona_navigator_{time.strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export ATT&CK Navigator Layer", default_name, "JSON files (*.json)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(layer, fh, indent=2)
            except Exception:
                pass

    # ── Reset ─────────────────────────────────────────────────────────────────
    def _reset(self) -> None:
        tracker = get_tracker()
        if tracker:
            tracker.reset()
        for cell in self._cells.values():
            cell.set_heat(0.0)
        self._detail_hdr.setText("Counts reset")
        self._detail_txt.clear()
