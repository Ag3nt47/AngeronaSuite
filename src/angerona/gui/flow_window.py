"""
gui/flow_window.py — the World View, redesigned as a live system-architecture
flowchart rendered natively in Qt (no browser / Chromium).

Shows how the whole suite connects and operates over the host:
    Sensors → Telemetry Bus → Dynamic Patch Engine → GPU Offload →
    AI Guardrail → Ollama LLM → Self-Hardening Core → (back to the bus)

Nodes are fed live, in-process, from core.flow_metrics.build_metrics() — so there
is no file:// fetch, no local web server, and no CORS problem. A node turns RED
when it reports an error/stopped state; click a node to see its live metrics.
Pan by dragging, zoom with the mouse wheel.
"""
from __future__ import annotations

import math

from PySide6.QtCore import Qt, QTimer, QPointF, Signal, QThread
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPen, QPolygonF, QPainterPath
from PySide6.QtWidgets import (
    QDialog, QFrame, QGraphicsItem, QGraphicsPathItem, QGraphicsPolygonItem,
    QGraphicsRectItem, QGraphicsScene, QGraphicsTextItem, QGraphicsView, QGroupBox,
    QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

try:
    from angerona.telemetry.worldview import WorldViewEngine as _WorldViewEngine
except Exception:
    _WorldViewEngine = None  # type: ignore


class _OllamaWorker(QThread):
    """Runs ollama_diagnostics() off the GUI thread and emits the result."""
    result = Signal(dict)

    def __init__(self, engine):
        super().__init__()
        self._engine = engine

    def run(self):
        try:
            data = self._engine.ollama_diagnostics()
        except Exception as exc:
            data = {"available": False, "reason": str(exc)}
        self.result.emit(data)

# Six-step architecture loop  —  id, label, group, x, y, description
# Label format: "STEP · TITLE\nsubline"  (split on first \n in _NodeItem)
_NW, _NH = 240, 120

_NODES = [
    ("capture", "① CAPTURE\nETW · FIM · ProcMon · Sniffer · MTM",
     "capture", 0, 0,
     "ETW 4688 pulls process-creation and logon events from the Windows Security channel; "
     "sensors sample processes/connections; MTM strips duplicate strings (>80% token cut). "
     "All events are published to the EventBus."),
    ("detect", "② DETECT\nYARA · NDRD · APID · PROV · Deception",
     "detect", 270, 0,
     "Detection modules evaluate every event: File Integrity, Process, Network, DNS entropy "
     "(NDRD), YARA, Deception, and APID (sensor-hook check). Findings are written to the "
     "tamper-evident FlightRecorder (SQLite WAL), mirrored to MEMC and mapped into the "
     "PROV blast-radius graph."),
    ("triage", "③ AI TRIAGE\nSPEC pre-warm · Ollama LLM · scoring",
     "triage", 540, 0,
     "SPEC pre-warms the local model on high-risk early markers. Ollama AI (local loopback "
     "only, zero egress) explains and scores each event. Threat calibration keeps the level "
     "honest — only real detections raise the gauge."),
    ("respond", "④ RESPOND\nSOAR · AUTH · HMAC · Review-gate",
     "respond", 540, 195,
     "SOAR recommends or (opt-in) contains — always review-gated, never auto-executed. AUTH "
     "enforces zero-trust HMAC auth on the loopback control channel so nothing local can "
     "spoof the suite."),
    ("attack", "⑤ ATTACK\nAI red team · mutation · detection-score",
     "attack", 270, 195,
     "Press F9: a decoupled AI red team launches four randomised techniques, mutating stealthier "
     "variants when blocked. A detection bridge scores each round BLOCKED or SUCCESS and writes "
     "an honest after-action report."),
    ("harden", "⑥ SELF-HARDEN\nJudgment Gate · Evolution · Playbook · MTTR",
     "harden", 0, 195,
     "Posture Hardening logs the weakness; the Judgment gate re-attacks. On SUCCESS the Evolution "
     "Engine auto-writes a YARA rule and the Playbook Tuner arms a SOAR containment block, then "
     "re-verifies until CERTIFIED — BLOCKED. MTTR tracks how fast that happens. INTL feeds the "
     "same gate: a CISA-KEV match is promoted only after an operator confirms and interception "
     "is proven."),
]

_EDGES = [
    ("capture", "detect"),
    ("detect",  "triage"),
    ("triage",  "respond"),
    ("respond", "attack"),
    ("attack",  "harden"),
    ("harden",  "capture", True),   # loop-back: dashed — self-hardening feeds next cycle
]

_GROUP = {
    "capture": "#1d4ed8",   # blue-700    — defensive / capture
    "detect":  "#0e7490",   # teal-700    — defensive / detect
    "triage":  "#7c3aed",   # purple-700  — AI triage (local)
    "respond": "#1e40af",   # blue-800    — defensive / respond
    "attack":  "#991b1b",   # red-800     — adversarial red team
    "harden":  "#166534",   # green-800   — self-hardening
}

# Short annotation shown mid-edge
_EDGE_LABELS: dict[tuple[str, str], str] = {
    ("capture", "detect"):  "events",
    ("detect",  "triage"):  "alerts",
    ("triage",  "respond"): "score",
    ("respond", "attack"):  "gate",
    ("attack",  "harden"):  "weakness",
    ("harden",  "capture"): "fixed ↺",
}


class _NodeItem(QGraphicsRectItem):
    def __init__(self, nid, label, group, win):
        super().__init__(0, 0, _NW, _NH)
        self.nid, self.win, self.group = nid, win, group
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setZValue(2)

        # Coloured header band (top 40 px)
        self._band = QGraphicsRectItem(0, 0, _NW, 42, self)
        self._band.setPen(QPen(Qt.NoPen))

        # Split "① TITLE\nsubline"
        parts = label.split("\n", 1)
        title_text = parts[0]
        sub_text = parts[1] if len(parts) > 1 else ""

        # Title — step number + name, bold white
        t = QGraphicsTextItem(title_text, self)
        t.setDefaultTextColor(QColor("#ffffff"))
        t.setFont(QFont("Segoe UI", 12, QFont.Bold))
        t.setTextWidth(_NW - 10)
        t.setPos(5, 6)

        # Subtitle — module list, visible on body area
        if sub_text:
            s = QGraphicsTextItem(sub_text, self)
            s.setDefaultTextColor(QColor("#cbd5e1"))
            s.setFont(QFont("Segoe UI", 8))
            s.setTextWidth(_NW - 10)
            s.setPos(5, 52)

        # Live metric badge — bottom of node, updated each refresh
        self._metric = QGraphicsTextItem("", self)
        self._metric.setDefaultTextColor(QColor("#4ade80"))
        self._metric.setFont(QFont("Consolas", 8))
        self._metric.setTextWidth(_NW - 10)
        self._metric.setPos(5, 97)

        self.set_state("ok")

    def set_state(self, state: str) -> None:
        err = state == "err"
        base = QColor("#7f1d1d" if err else _GROUP.get(self.group, "#334155"))
        self.setBrush(QBrush(base.darker(135)))
        self.setPen(QPen(QColor("#ef4444" if err else "#475569"), 1.5))
        self._band.setBrush(QBrush(base))

    def set_metric(self, val: str, color: str = "#4ade80") -> None:
        self._metric.setPlainText(val)
        self._metric.setDefaultTextColor(QColor(color))

    def mousePressEvent(self, e):
        self.win._select(self.nid)
        super().mousePressEvent(e)


class _FlowView(QGraphicsView):
    def __init__(self, scene):
        super().__init__(scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setBackgroundBrush(QColor("#0b0e14"))

    def wheelEvent(self, e):
        f = 1.15 if e.angleDelta().y() > 0 else 1 / 1.15
        self.scale(f, f)


class FlowWindow(QDialog):
    """Live architecture flowchart (the redesigned World View)."""

    def __init__(self, bus, storage, manager, config, parent=None):
        super().__init__(parent)
        self.bus, self.storage, self.manager, self.config = bus, storage, manager, config
        self.setWindowTitle("World View — System Flow (live)")
        self.setMinimumSize(1040, 640)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        self._items: dict = {}
        self._meta = {n[0]: {"label": n[1], "desc": n[5]} for n in _NODES}
        self._selected = None

        root = QVBoxLayout(self)
        head = QLabel("World View — how Angerona connects & operates over the host (live)")
        head.setObjectName("PageTitle")
        root.addWidget(head)

        self.scene = QGraphicsScene(self)
        self._build_scene()
        self.view = _FlowView(self.scene)
        root.addWidget(self.view, 1)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(150)
        self.detail.setPlaceholderText("Click a node to see its live metrics. Drag to pan, wheel to zoom.")
        self.detail.setStyleSheet("background:#0b0d12; color:#cbd5e1; border:1px solid #232a36;")
        root.addWidget(self.detail)

        # ── inline host-telemetry panel (replaces the old popup) ────────────────
        self._tele_panel = self._build_tele_panel()
        root.addWidget(self._tele_panel)

        row = QHBoxLayout()
        self.status = QLabel("")
        self.status.setStyleSheet("color:#9aa4b2;")
        row.addWidget(self.status)
        row.addStretch(1)
        tele_toggle = QPushButton("Host telemetry ▲")
        tele_toggle.setCheckable(True)
        tele_toggle.setChecked(True)
        tele_toggle.toggled.connect(self._toggle_tele_panel)
        tele_toggle.toggled.connect(
            lambda on: tele_toggle.setText("Host telemetry ▲" if on else "Host telemetry ▼"))
        fit = QPushButton("Fit")
        fit.clicked.connect(lambda: self.view.fitInView(self.scene.itemsBoundingRect(), Qt.KeepAspectRatio))
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addWidget(tele_toggle); row.addWidget(fit); row.addWidget(close)
        root.addLayout(row)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(2000)
        self._refresh()
        QTimer.singleShot(0, lambda: self.view.fitInView(self.scene.itemsBoundingRect(), Qt.KeepAspectRatio))

    def _build_scene(self):
        pos = {n[0]: QPointF(float(n[3]), float(n[4])) for n in _NODES}

        # Scene header
        def _scene_text(txt, font_size, bold, color, x, y):
            item = QGraphicsTextItem(txt)
            item.setDefaultTextColor(QColor(color))
            item.setFont(QFont("Segoe UI", font_size,
                               QFont.Bold if bold else QFont.Normal))
            item.setPos(x, y)
            item.setZValue(3)
            self.scene.addItem(item)

        _scene_text("ANGERONA — SYSTEM FLOW",
                    13, True, "#f1f5f9", 0, -62)
        _scene_text("Run · Verify · Attack · Defend · Self-Harden  (live)",
                    8, False, "#64748b", 0, -38)

        # edges first (under nodes); store label items so _refresh() can update them
        self._edge_label_items: dict[tuple[str, str], QGraphicsTextItem | None] = {}
        for e in _EDGES:
            a, b = e[0], e[1]
            dashed = len(e) > 2 and e[2]
            lbl = _EDGE_LABELS.get((a, b), "")
            self._edge_label_items[(a, b)] = self._draw_edge(pos[a], pos[b], dashed, lbl)

        # ── Red "Dropped/Sampled" counter on the dashed loopback edge ────────
        # Placed in the vertical gap (y ≈ 120–195) between SELF-HARDEN and CAPTURE.
        # Both nodes sit at x=0, so the edge centre is at x = _NW/2, y = mid-gap.
        harden_cy  = pos["harden"].y()  + _NH / 2   # 195 + 60 = 255
        capture_cy = pos["capture"].y() + _NH / 2   #   0 + 60 =  60
        edge_cx    = pos["harden"].x()  + _NW / 2   # 0 + 120 = 120
        drop_my    = (harden_cy + capture_cy) / 2   # 157.5
        self._drop_label = QGraphicsTextItem("Dropped/Sampled: 0")
        self._drop_label.setDefaultTextColor(QColor("#ef4444"))
        self._drop_label.setFont(QFont("Segoe UI", 8))
        # Offset left of the edge line so it sits in the gap without overlapping
        self._drop_label.setPos(edge_cx - 65, drop_my + 8)
        self._drop_label.setZValue(3)
        self.scene.addItem(self._drop_label)

        # nodes on top
        for n in _NODES:
            it = _NodeItem(n[0], n[1], n[2], self)
            it.setPos(pos[n[0]])
            self.scene.addItem(it)
            self._items[n[0]] = it

        # Legend strip below the grid
        leg_y = _NH + 195 + 22
        legend = [
            ("● Blue — Defensive pipeline",    "#1d4ed8"),
            ("● Purple — AI Triage (local)",    "#7c3aed"),
            ("● Red — Adversarial red team",    "#991b1b"),
            ("● Green — Self-hardening",        "#166534"),
        ]
        for i, (txt, col) in enumerate(legend):
            lt = QGraphicsTextItem(txt)
            lt.setDefaultTextColor(QColor(col))
            lt.setFont(QFont("Segoe UI", 8))
            lt.setPos(i * 200, leg_y)
            lt.setZValue(3)
            self.scene.addItem(lt)

    def _draw_edge(
        self, a: QPointF, b: QPointF, dashed: bool,
        label: str = "", color: str = "#475569",
    ) -> QGraphicsTextItem | None:
        """Draw a bezier edge from node-centre a to node-centre b with an
        arrowhead at the target boundary and an optional mid-edge label.
        Returns the label QGraphicsTextItem so callers can update it live."""
        a0 = QPointF(a.x() + _NW / 2, a.y() + _NH / 2)
        b0 = QPointF(b.x() + _NW / 2, b.y() + _NH / 2)

        # Axis-aligned control points: straight lines for our 2×3 grid
        dx = b0.x() - a0.x()
        dy = b0.y() - a0.y()
        if abs(dy) > abs(dx):           # vertical-dominant
            mid = (a0.y() + b0.y()) / 2
            cp1, cp2 = QPointF(a0.x(), mid), QPointF(b0.x(), mid)
        else:                            # horizontal-dominant
            mid = (a0.x() + b0.x()) / 2
            cp1, cp2 = QPointF(mid, a0.y()), QPointF(mid, b0.y())

        path = QPainterPath(a0)
        path.cubicTo(cp1, cp2, b0)
        pen = QPen(QColor(color), 2.5)
        if dashed:
            pen.setStyle(Qt.DashLine)
        edge_item = QGraphicsPathItem(path)
        edge_item.setPen(pen)
        edge_item.setZValue(1)
        self.scene.addItem(edge_item)

        # ── arrowhead at the entry point of target node ───────────────────
        # Tangent direction at b0 = cp2 → b0
        tdx = b0.x() - cp2.x()
        tdy = b0.y() - cp2.y()
        tlen = math.hypot(tdx, tdy)
        if tlen > 1e-6:
            tdx /= tlen; tdy /= tlen
            # Clip to target node boundary
            hw, hh = _NW / 2 + 1, _NH / 2 + 1
            adx, ady = abs(tdx), abs(tdy)
            t = min((hw / adx) if adx > 1e-9 else 1e9,
                    (hh / ady) if ady > 1e-9 else 1e9)
            tip = QPointF(b0.x() - tdx * t, b0.y() - tdy * t)
            sz = 13
            bx = tip.x() - tdx * sz
            by = tip.y() - tdy * sz
            px, py = -tdy, tdx   # perpendicular
            poly = QPolygonF([
                tip,
                QPointF(bx + px * sz * 0.4, by + py * sz * 0.4),
                QPointF(bx - px * sz * 0.4, by - py * sz * 0.4),
            ])
            ah = QGraphicsPolygonItem(poly)
            ah.setBrush(QBrush(QColor(color)))
            ah.setPen(QPen(Qt.NoPen))
            ah.setZValue(1)
            self.scene.addItem(ah)

        # ── optional mid-edge label ───────────────────────────────────────
        lbl_item: QGraphicsTextItem | None = None
        if label:
            mx = (a0.x() + b0.x()) / 2
            my = (a0.y() + b0.y()) / 2
            lbl_item = QGraphicsTextItem(label)
            lbl_item.setDefaultTextColor(QColor("#94a3b8"))
            lbl_item.setFont(QFont("Segoe UI", 8))
            lbl_item.setPos(mx - 20, my - 10)
            lbl_item.setZValue(3)
            self.scene.addItem(lbl_item)
        return lbl_item

    # ── live update ──────────────────────────────────────────────────────────
    def _metrics(self) -> dict:
        try:
            from angerona.core import flow_metrics
            return flow_metrics.build_metrics(self.manager, self.bus, self.config)
        except Exception:
            return {"nodes": {}}

    def _refresh(self):
        data = self._metrics()
        nodes = data.get("nodes", {})
        errs = 0
        for nid, item in self._items.items():
            nd = nodes.get(nid, {})
            state = nd.get("state", "ok")
            errs += (state == "err")
            item.set_state(state)
            # Push the first metric value into the node's live badge
            metrics = nd.get("metrics") or {}
            if metrics:
                k, v = next(iter(metrics.items()))
                badge_col = "#ef4444" if state == "err" else "#4ade80"
                item.set_metric(f"{k}: {v}", badge_col)
        self._last = nodes
        self.status.setText(
            f"{len(self._items)} steps · {errs} in error · "
            f"updated {data.get('generated', '')}")
        if self._selected:
            self._render_detail(self._selected)

        # ── Live pipeline metrics on edges ───────────────────────────────────
        # pipeline key is added by flow_metrics.build_metrics(); absent on error.
        pipeline = data.get("pipeline", {})
        if pipeline and hasattr(self, "_edge_label_items"):
            cap_det = pipeline.get("cap_det", {})
            det_tri = pipeline.get("det_tri", {})
            lbl_cd  = self._edge_label_items.get(("capture", "detect"))
            lbl_dt  = self._edge_label_items.get(("detect",  "triage"))
            if lbl_cd is not None:
                q, ms = cap_det.get("queue", 0), cap_det.get("latency_ms", 0)
                lbl_cd.setPlainText(f"events  Q:{q}  {ms}ms")
            if lbl_dt is not None:
                q, ms = det_tri.get("queue", 0), det_tri.get("latency_ms", 0)
                lbl_dt.setPlainText(f"alerts  Q:{q}  {ms}ms")
        if hasattr(self, "_drop_label"):
            dropped = pipeline.get("dropped", 0) if pipeline else 0
            self._drop_label.setPlainText(f"Dropped/Sampled: {dropped:,}")

        self._refresh_tele_fast()

    def closeEvent(self, event):
        """Stop background threads before the dialog is destroyed."""
        self._timer.stop()
        if hasattr(self, "_ollama_timer"):
            self._ollama_timer.stop()
        if hasattr(self, "_ollama_worker") and self._ollama_worker is not None:
            self._ollama_worker.quit()
            self._ollama_worker.wait(1000)
        super().closeEvent(event)

    def _select(self, nid):
        self._selected = nid
        self._render_detail(nid)

    def _render_detail(self, nid):
        meta = self._meta.get(nid, {})
        nd = getattr(self, "_last", {}).get(nid, {})
        lines = [meta.get("label", nid).replace("\n", " — "), ""]
        lines.append(meta.get("desc", ""))
        lines.append("")
        lines.append("STATE: " + ("ERROR" if nd.get("state") == "err" else "ok"))
        for k, v in (nd.get("metrics") or {}).items():
            lines.append(f"  {k}: {v}")
        self.detail.setPlainText("\n".join(lines))

    # ── inline host-telemetry panel ──────────────────────────────────────────
    def _build_tele_panel(self) -> QGroupBox:
        """Build the always-inline host telemetry panel (no popup)."""
        box = QGroupBox("Host Telemetry")
        box.setStyleSheet(
            "QGroupBox{color:#f59e0b;font-weight:bold;border:1px solid #1e2a3a;"
            "border-radius:6px;margin-top:6px;background:#0a0e14;}"
            "QGroupBox::title{subcontrol-origin:margin;left:10px;padding:0 4px;}"
        )
        lay = QHBoxLayout(box)
        lay.setSpacing(8)

        def _mini_card(title: str) -> tuple[QFrame, QLabel]:
            f = QFrame()
            f.setStyleSheet("QFrame{background:#0f1720;border:1px solid #1e2a3a;border-radius:6px;}")
            v = QVBoxLayout(f)
            v.setContentsMargins(8, 6, 8, 6)
            v.setSpacing(2)
            hdr = QLabel(title)
            hdr.setStyleSheet("color:#f59e0b;font-size:10px;font-weight:bold;")
            lbl = QLabel("…")
            lbl.setWordWrap(True)
            lbl.setStyleSheet("color:#c8d3e0;font-family:Consolas;font-size:10px;")
            lbl.setTextFormat(Qt.RichText)
            v.addWidget(hdr); v.addWidget(lbl)
            return f, lbl

        mf, self._tele_matrix = _mini_card("1 · RESOURCE MATRIX")
        ef, self._tele_eps    = _mini_card("2 · TELEMETRY SALIENCY")
        of, self._tele_ollama = _mini_card("3 · LOCAL AI (Ollama)")
        lay.addWidget(mf, 2); lay.addWidget(ef, 2); lay.addWidget(of, 2)

        # Engine — created once; fast methods called on 2s timer; Ollama off-thread
        if _WorldViewEngine is not None:
            self._wv_engine = _WorldViewEngine()
            self._ollama_worker: _OllamaWorker | None = None
            self._ollama_timer = QTimer(self)
            self._ollama_timer.timeout.connect(self._kick_ollama)
            self._ollama_timer.start(8000)          # poll every 8 s
            QTimer.singleShot(500, self._kick_ollama)  # first fetch soon after open
        else:
            self._wv_engine = None

        return box

    def _toggle_tele_panel(self, visible: bool) -> None:
        self._tele_panel.setVisible(visible)

    def _refresh_tele_fast(self) -> None:
        """Update the fast (non-blocking) telemetry cards on the GUI thread."""
        if self._wv_engine is None:
            return
        # 1 · resource matrix
        try:
            m = self._wv_engine.host_vs_suite_matrix()
            if m.get("available"):
                h, s = m["host"], m["suite"]
                self._tele_matrix.setText(
                    f"<b>HOST</b> RAM {h['used_ram_pct']}% / {h['total_ram_gb']} GB · "
                    f"CPU {h['cpu_pct']}% · {h['processes']} procs<br>"
                    f"<b>SUITE</b> RSS {s['rss_mb']} MB · CPU {s['cpu_pct']}% · "
                    f"{s['threads']} threads")
            else:
                self._tele_matrix.setText(m.get("reason", "unavailable"))
        except Exception as exc:
            self._tele_matrix.setText(f"err: {exc}")
        # 2 · EPS / blinding
        try:
            evt_count = getattr(self.bus, "event_count", lambda: 0)()
            e = self._wv_engine.eps_gauge(evt_count)
            col = "#ef4444" if e.get("alarm") else (
                  "#f59e0b" if e.get("blinding_suspected") else "#22c55e")
            self._tele_eps.setText(
                f"<b style='color:{col}'>{e['internal_eps']:.1f} EPS</b> internal · "
                f"host ctx-switch {e['host_ctx_switch_rate']:.0f}/s · "
                f"host active: {e['host_active']}")
        except Exception as exc:
            self._tele_eps.setText(f"err: {exc}")

    def _kick_ollama(self) -> None:
        """Fire the Ollama worker if one isn't already running."""
        if self._wv_engine is None:
            return
        if self._ollama_worker is not None and self._ollama_worker.isRunning():
            return                          # still fetching — skip this cycle
        self._ollama_worker = _OllamaWorker(self._wv_engine)
        self._ollama_worker.result.connect(self._on_ollama_result)
        self._ollama_worker.start()

    def _on_ollama_result(self, data: dict) -> None:
        """Slot — receives Ollama data on the GUI thread via Signal."""
        if data.get("available"):
            self._tele_ollama.setText(
                f"model <b>{data.get('model','?')}</b> · "
                f"VRAM {data.get('vram_mb','?')} MB · "
                f"{data.get('tokens_per_sec','?')} tok/s · "
                f"queue {data.get('queue','?')}")
        else:
            self._tele_ollama.setText(
                f"<span style='color:#64748b'>Ollama offline — "
                f"{data.get('reason','not running')}</span>")
