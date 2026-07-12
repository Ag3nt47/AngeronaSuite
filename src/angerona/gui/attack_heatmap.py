"""
gui/attack_heatmap.py — Live MITRE ATT&CK heatmap dialog.

14 tactic columns × N technique rows.  Each cell is coloured by heat score
(0 = dark/inactive → blue → amber → red at 1.0).  A click-to-detail panel
below the matrix shows full technique info + recent event IDs.

Refresh is every 5 seconds via QTimer; never blocks the Qt main thread.
Local-first: reads only from AttackTracker.snapshot() — no network calls.
"""
from __future__ import annotations

import json
import time
from typing import Callable

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import (
    QBrush, QColor, QFont, QPen, QPolygonF,
)
from PySide6.QtWidgets import (
    QComboBox, QDialog, QFileDialog, QGraphicsItem, QGraphicsRectItem,
    QGraphicsScene, QGraphicsTextItem, QGraphicsView, QHBoxLayout, QLabel,
    QPushButton, QSizePolicy, QTextBrowser, QVBoxLayout, QWidget,
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
    "TA0043": "#374151",  # Recon         – slate
    "TA0042": "#1e3a5f",  # Resource Dev  – navy-blue
    "TA0001": "#7c2d12",  # Initial Access– burnt-orange
    "TA0002": "#581c87",  # Execution     – purple
    "TA0003": "#14532d",  # Persistence   – forest-green
    "TA0004": "#713f12",  # Priv Esc      – amber-dark
    "TA0005": "#1e1b4b",  # Def Evasion   – indigo
    "TA0006": "#7f1d1d",  # Cred Access   – crimson
    "TA0007": "#164e63",  # Discovery     – teal
    "TA0008": "#1a1a2e",  # Lateral Move  – deep-navy
    "TA0009": "#3b0764",  # Collection    – violet
    "TA0011": "#0c4a6e",  # C2            – ocean-blue
    "TA0010": "#431407",  # Exfiltration  – dark-rust
    "TA0040": "#450a0a",  # Impact        – deep-red
}


def _heat_color(heat: float) -> QColor:
    """Map 0.0–1.0 heat to a QColor on a dark→blue→amber→red ramp."""
    if heat <= 0.0:
        return QColor("#0f172a")   # inactive – near-black
    if heat < 0.15:
        return QColor("#1e3a5f")   # faint blue
    if heat < 0.35:
        return QColor("#1d4ed8")   # blue
    if heat < 0.55:
        return QColor("#d97706")   # amber
    if heat < 0.75:
        return QColor("#ea580c")   # orange
    return QColor("#dc2626")       # red – hot


def _heat_border(heat: float) -> QColor:
    if heat <= 0:
        return QColor("#1e293b")
    if heat < 0.35:
        return QColor("#3b82f6")
    if heat < 0.55:
        return QColor("#f59e0b")
    return QColor("#ef4444")


# ── Clickable technique cell ─────────────────────────────────────────────────
class _CellItem(QGraphicsRectItem):
    def __init__(
        self,
        tid: str,
        label: str,
        x: float,
        y: float,
        on_click: Callable[[str], None],
    ) -> None:
        super().__init__(x, y, _CW, _CH)
        self.tid      = tid
        self._on_click = on_click
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(1)

        # Label text — 8pt, truncated
        self._lbl = QGraphicsTextItem(label, self)
        self._lbl.setDefaultTextColor(QColor("#e2e8f0"))
        self._lbl.setFont(QFont("Segoe UI", 8))
        self._lbl.setTextWidth(_CW - 4)
        self._lbl.setPos(x + 2, y + 2)
        self._lbl.setZValue(2)

        # Heat bar at bottom (3px strip)
        self._bar = QGraphicsRectItem(x, y + _CH - 3, _CW, 3, self)
        self._bar.setPen(QPen(Qt.NoPen))
        self._bar.setZValue(3)

        self.set_heat(0.0)

    def set_heat(self, heat: float, count: int = 0, dimmed: bool = False) -> None:
        self._heat   = heat
        self._dimmed = dimmed
        if dimmed:
            # Not in the selected actor's playbook — mute to near-black
            self.setBrush(QBrush(QColor("#0c111a")))
            self.setPen(QPen(QColor("#1a2234"), 0.5))
            self._bar.setBrush(QBrush(QColor("#0c111a")))
            self.setToolTip(f"{self.tid}  [not in actor playbook]")
        else:
            clr    = _heat_color(heat)
            border = _heat_border(heat)
            self.setBrush(QBrush(clr.darker(110)))
            self.setPen(QPen(border, 0.8))
            bar_clr = _heat_color(min(1.0, heat * 1.4))
            self._bar.setBrush(QBrush(bar_clr))
            self.setToolTip(f"{self.tid}  heat={heat:.2f}  hits={count}")

    def mousePressEvent(self, _event) -> None:  # type: ignore[override]
        self._on_click(self.tid)

    def hoverEnterEvent(self, _event) -> None:  # type: ignore[override]
        pen = self.pen()
        pen.setWidth(2)
        self.setPen(pen)

    def hoverLeaveEvent(self, _event) -> None:  # type: ignore[override]
        self.set_heat(self._heat)   # re-apply normal border weight


# ── Heatmap window ───────────────────────────────────────────────────────────
class AttackHeatmapWindow(QDialog):
    """Non-modal dialog showing the live ATT&CK heatmap.

    Constructed with the same qss as the main window via:
        dlg.setStyleSheet(self._qss())
        dlg.show()

    Signals:
        event_clicked(str): emitted when the user clicks a hyperlinked event ID
                            in the detail panel — wire to AlertDetailDialog.
    """

    event_clicked = Signal(str)   # pivot: caller receives the raw event ID string
    _REFRESH_MS   = 5_000

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("🔥  MITRE ATT&CK Heatmap  — Live")
        self.setMinimumSize(1420, 720)
        self.resize(1540, 800)
        self.setAttribute(Qt.WA_DeleteOnClose, False)

        self._cells: dict[str, _CellItem] = {}   # tid → cell
        self._scene = QGraphicsScene(self)
        self._view  = QGraphicsView(self._scene, self)
        self._view.setRenderHints(self._view.renderHints())
        self._view.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self._view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self._view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._view.setStyleSheet("background: #0d1117; border: none;")

        # ── Stats bar ────────────────────────────────────────────────────────
        self._stats_lbl = QLabel("Initialising…")
        self._stats_lbl.setStyleSheet(
            "color:#94a3b8; font:8pt 'Segoe UI'; padding:4px 8px;")
        self._stats_lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        # Threat Actor filter — dims cells outside the selected actor's playbook
        self._actor: str = "— All —"
        self._actor_combo = QComboBox()
        self._actor_combo.addItems(["— All —"] + list(THREAT_ACTOR_PLAYBOOKS.keys()))
        self._actor_combo.setFixedWidth(195)
        self._actor_combo.setToolTip(
            "Filter by threat actor: dims techniques outside their known playbook "
            "and highlights the intersection with live heat data")
        self._actor_combo.setStyleSheet(
            "QComboBox{background:#1e293b;color:#cbd5e1;"
            "border:1px solid #334155;border-radius:4px;"
            "padding:2px 6px;font:8pt 'Segoe UI';}"
            "QComboBox::drop-down{border:none;}"
            "QComboBox QAbstractItemView{background:#1e293b;color:#cbd5e1;"
            "selection-background-color:#334155;border:1px solid #334155;}")
        # connect AFTER addItems so initial population does not fire _on_actor_changed
        self._actor_combo.currentTextChanged.connect(self._on_actor_changed)

        export_nav_btn = QPushButton("Export to Navigator")
        export_nav_btn.setFixedWidth(150)
        export_nav_btn.setToolTip(
            "Save active techniques as a MITRE ATT&CK Navigator v4.9 layer JSON")
        export_nav_btn.clicked.connect(self._export_navigator)

        reset_btn = QPushButton("Reset counts")
        reset_btn.setFixedWidth(110)
        reset_btn.clicked.connect(self._reset)

        stats_row = QHBoxLayout()
        stats_row.addWidget(self._stats_lbl)
        stats_row.addStretch(1)
        stats_row.addWidget(self._actor_combo)
        stats_row.addWidget(export_nav_btn)
        stats_row.addWidget(reset_btn)

        # ── Detail panel ─────────────────────────────────────────────────────
        self._detail_hdr = QLabel("Click a technique cell for details")
        self._detail_hdr.setStyleSheet(
            "color:#f1f5f9; font:9pt 'Segoe UI' bold; padding:4px 8px;")
        self._detail_txt = QTextBrowser()
        self._detail_txt.setReadOnly(True)
        self._detail_txt.setOpenLinks(False)
        # Clicking a hyperlinked event ID emits event_clicked(eid_str)
        self._detail_txt.anchorClicked.connect(
            lambda url: self.event_clicked.emit(url.toString()))
        self._detail_txt.setFixedHeight(110)
        self._detail_txt.setStyleSheet(
            "background:#1e293b; color:#cbd5e1; font:8pt 'Consolas';"
            "border:none; padding:4px;")
        self._detail_txt.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Fixed)

        detail_box = QVBoxLayout()
        detail_box.setContentsMargins(0, 0, 0, 0)
        detail_box.setSpacing(0)
        detail_box.addWidget(self._detail_hdr)
        detail_box.addWidget(self._detail_txt)

        # ── Root layout ──────────────────────────────────────────────────────
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addLayout(stats_row)
        root.addWidget(self._view, 1)
        root.addLayout(detail_box)

        # ── Build static scene skeleton ───────────────────────────────────────
        self._build_scene()

        # ── Refresh timer ─────────────────────────────────────────────────────
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(self._REFRESH_MS)
        self._refresh()   # immediate first paint

    # ── Scene construction ───────────────────────────────────────────────────
    def _build_scene(self) -> None:
        scene = self._scene

        # Figure out max column height
        max_techs = max(
            len(_TACTIC_TO_TECHNIQUES.get(tid, []))
            for tid, _ in TACTIC_ORDER
        )
        scene_w = _PAD + len(TACTIC_ORDER) * (_CW + _GAP) + _PAD
        scene_h = _PAD + _HDR_H + max_techs * (_CH + 2) + _PAD
        scene.setSceneRect(0, 0, scene_w, scene_h)

        for col_idx, (tac_id, tac_name) in enumerate(TACTIC_ORDER):
            cx = _PAD + col_idx * (_CW + _GAP)
            cy = _PAD

            # Tactic header band
            tac_clr = QColor(_TACTIC_CLR.get(tac_id, "#334155"))
            hdr = QGraphicsRectItem(cx, cy, _CW, _HDR_H)
            hdr.setBrush(QBrush(tac_clr))
            hdr.setPen(QPen(tac_clr.lighter(130), 0.5))
            hdr.setZValue(1)
            scene.addItem(hdr)

            # Tactic label (two-line: id + name)
            t = QGraphicsTextItem(f"{tac_id}\n{tac_name}")
            t.setDefaultTextColor(QColor("#f8fafc"))
            t.setFont(QFont("Segoe UI", 7, QFont.Bold))
            t.setTextWidth(_CW - 4)
            t.setPos(cx + 2, cy + 4)
            t.setZValue(2)
            scene.addItem(t)

            # Technique cells
            tids = _TACTIC_TO_TECHNIQUES.get(tac_id, [])
            for row_idx, tid in enumerate(tids):
                ty = cy + _HDR_H + row_idx * (_CH + 2)
                lbl = _TID_TO_META[tid][0] if tid in _TID_TO_META else tid
                cell = _CellItem(tid, lbl, cx, ty, self._on_cell_clicked)
                scene.addItem(cell)
                scene.addItem(cell._lbl)
                scene.addItem(cell._bar)
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

        # Build actor playbook set (None = no filter)
        actor = getattr(self, "_actor", "— All —")
        playbook: set[str] | None = None
        if actor != "— All —":
            playbook = set(THREAT_ACTOR_PLAYBOOKS.get(actor, []))

        for tid, cell in self._cells.items():
            row   = matrix.get(tid, {})
            heat  = row.get("heat", 0.0)
            count = row.get("count", 0)
            if playbook is not None:
                # Dim cells whose TID (or parent TID) is not in the actor's playbook
                in_pb = (tid in playbook or
                         any(tid.startswith(p + ".") for p in playbook))
                cell.set_heat(heat, count, dimmed=not in_pb)
            else:
                cell.set_heat(heat, count)

        # Stats bar
        n_active  = summ.get("techniques_active", 0)
        n_tacs    = summ.get("tactics_active", 0)
        top_tid   = summ.get("highest_heat_tid") or "—"
        top_lbl   = summ.get("highest_heat_label") or "—"
        actor_sfx = f"  |  Actor: {actor}" if actor != "— All —" else ""
        self._stats_lbl.setText(
            f"Active techniques: {n_active}  |  Active tactics: {n_tacs}  |  "
            f"Hottest: {top_tid} ({top_lbl})  |  "
            f"Updated: {snap.get('generated', '—')}{actor_sfx}"
        )

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
            f"  {tid}  ·  {meta[2]}  ·  "
            f"heat={row['heat']:.3f}  hits={row['count']}  last={last}"
        )

        # Render event IDs as clickable hyperlinks.
        # anchorClicked → event_clicked(str) so callers can open AlertDetailDialog.
        id_links = "".join(
            f'&nbsp;&nbsp;<a href="{eid}" style="color:#38bdf8;text-decoration:none;">'
            f'{eid}</a><br>'
            for eid in ids
        ) or "&nbsp;&nbsp;<span style='color:#475569'>(none recorded)</span>"

        self._detail_txt.setHtml(
            "<span style='color:#cbd5e1;font-family:Consolas;font-size:8pt;'>"
            f"<b>Technique&nbsp;:</b> {tid}<br>"
            f"<b>Full name&nbsp;:</b> {meta[2]}<br>"
            f"<b>Short lbl&nbsp;:</b> {meta[0]}<br>"
            f"<b>Tactic&nbsp;&nbsp;&nbsp;&nbsp;:</b> {meta[1]}<br>"
            f"<b>Hit count&nbsp;:</b> {row['count']}<br>"
            f"<b>Heat score:</b> {row['heat']:.4f}<br>"
            f"<b>Last seen&nbsp;:</b> {last}<br>"
            f"<b>Event IDs</b> (click to pivot):<br>"
            f"{id_links}</span>"
        )

    # ── Threat Actor filter ───────────────────────────────────────────────────
    def _on_actor_changed(self, actor: str) -> None:
        """Slot for the actor QComboBox — updates self._actor and repaints."""
        self._actor = actor
        self._refresh()

    # ── ATT&CK Navigator export ───────────────────────────────────────────────
    def _export_navigator(self) -> None:
        """Export current live heat scores as a MITRE ATT&CK Navigator v4.9 layer.

        Only techniques with at least one recorded hit are included; scores are
        mapped to 0–100 from the 0.0–1.0 heat value.  The gradient in the layer
        file matches Angerona's own dark→blue→amber→red ramp.
        """
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
                "techniqueID":       tid,
                "score":             int(round(row["heat"] * 100)),
                "color":             "",
                "comment":           (
                    f"hits={row['count']} "
                    f"last={row.get('last_seen') or 'never'}"
                ),
                "enabled":           True,
                "metadata":          [],
                "showSubtechniques": False,
            })

        layer = {
            "name":     "Angerona Live Heatmap",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain":   "enterprise-attack",
            "description": (
                f"Exported {time.strftime('%Y-%m-%dT%H:%M:%S')} "
                "from Angerona live ATT&CK heat tracker"
            ),
            "filters":      {"platforms": ["Windows"]},
            "sorting":      3,
            "layout": {
                "layout":            "side",
                "aggregateFunction": "average",
                "showID":            True,
                "showName":          True,
            },
            "hideDisabled": False,
            "techniques":   techniques,
            "gradient": {
                "colors":   ["#0f172a", "#1d4ed8", "#d97706", "#dc2626"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems":                   [],
            "metadata":                      [],
            "showTacticRowBackground":       True,
            "tacticRowBackground":           "#15202b",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
            "links":                         [],
        }

        default_name = f"angerona_navigator_{time.strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export ATT&CK Navigator Layer", default_name,
            "JSON files (*.json)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(layer, fh, indent=2)
            except Exception:
                pass   # silent — no blocking dialogs on export failure

    # ── Reset ─────────────────────────────────────────────────────────────────
    def _reset(self) -> None:
        tracker = get_tracker()
        if tracker:
            tracker.reset()
        for cell in self._cells.values():
            cell.set_heat(0.0)
        self._detail_hdr.setText("Counts reset")
        self._detail_txt.clear()
