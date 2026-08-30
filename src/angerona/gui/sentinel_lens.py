"""SentinelLens — clickable local-first threat-hunting graph workspace."""
from __future__ import annotations

import json
import ipaddress
import math
import os
import stat
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QPointF, QRectF, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QGraphicsItem,
    QGraphicsPathItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsTextItem,
    QGraphicsView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from angerona.core.sentinel_lens import (
    MAX_BUNDLE_BYTES,
    MAX_IMPORT_RECORDS,
    SentinelLensInputError,
    build_sentinel_snapshot,
    parse_log_bundle,
    render_narrative,
)

_MAX_IMPORT_FILE_BYTES = MAX_BUNDLE_BYTES
_MAX_GRAPH_EVENTS = 2_000
_MAX_VISIBLE_NODES = 260
_MAX_VISIBLE_EDGES = 700
_MAX_VISIBLE_ANOMALIES = 500
_NODE_W = 210
_NODE_H = 76
_KIND_ORDER = (
    "process", "event", "file", "network", "technique", "correlation", "proof"
)
_KIND_COLOR = {
    "process": "#1d4ed8",
    "event": "#475569",
    "file": "#b45309",
    "network": "#0e7490",
    "technique": "#7c3aed",
    "correlation": "#9f1239",
    "proof": "#166534",
}


def _loopback_ollama_url(value: object) -> str:
    rendered = str(value or "http://localhost:11434").strip()
    parsed = urlsplit(rendered)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.hostname is None
    ):
        raise SentinelLensInputError("local AI endpoint is not a plain loopback URL")
    hostname = parsed.hostname.casefold()
    try:
        loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        loopback = hostname == "localhost"
    if not loopback:
        raise SentinelLensInputError(
            "SentinelLens refuses non-loopback AI endpoints to prevent telemetry egress"
        )
    # Reuse the parsed URL only after its authority and path have been validated.
    return rendered.rstrip("/")


class _NarrativeWorker(QThread):
    result = Signal(str)

    def __init__(self, ask, prompt: str) -> None:
        super().__init__()
        self._ask = ask
        self._prompt = prompt

    def run(self) -> None:
        try:
            answer = self._ask(self._prompt)
        except Exception as exc:
            answer = f"Local AI narrative unavailable ({type(exc).__name__}: {exc})."
        self.result.emit(str(answer)[:12_000])


class _SnapshotWorker(QThread):
    result = Signal(dict)
    failed = Signal(str)

    def __init__(self, events: list) -> None:
        super().__init__()
        self._events = events

    def run(self) -> None:
        try:
            snapshot = build_sentinel_snapshot(
                self._events, max_events=_MAX_GRAPH_EVENTS
            )
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {str(exc)[:2_000]}")
            return
        self.result.emit(snapshot)


class _ImportWorker(QThread):
    result = Signal(object, str)
    failed = Signal(str)

    def __init__(self, path: Path, mode: str, loader, parser) -> None:
        super().__init__()
        self._path = path
        self._mode = mode
        self._loader = loader
        self._parser = parser

    def run(self) -> None:
        try:
            body = self._loader(self._path)
            records = self._parser(body, self._mode, self._path.suffix.casefold())
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {str(exc)[:240]}")
            return
        self.result.emit(records, self._path.name[:260])


class _LensNode(QGraphicsRectItem):
    def __init__(self, row: dict, owner) -> None:
        super().__init__(0, 0, _NODE_W, _NODE_H)
        self.row = row
        self.owner = owner
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setZValue(2)
        kind = str(row.get("kind") or "event").casefold()
        color = QColor(_KIND_COLOR.get(kind, "#475569"))
        self.setBrush(QBrush(color.darker(150)))
        self.setPen(QPen(color, 1.5))
        self._label = str(
            row.get("label")
            or row.get("message")
            or row.get("module")
            or row.get("id")
        )[:90]
        self._kind_label = kind.upper()
        self._severity = int(row.get("severity", 0) or 0)

    def paint(self, painter, option, widget=None) -> None:
        # Draw labels in the node's own paint pass. Some Qt viewport backends
        # can omit child text items after fitInView(), while direct bounded text
        # remains deterministic in both the live UI and public capture.
        super().paint(painter, option, widget)
        painter.setPen(QColor("#f8fafc"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
        painter.drawText(
            QRectF(6, 5, _NODE_W - 12, 46),
            Qt.TextWordWrap | Qt.AlignLeft | Qt.AlignTop,
            self._label,
        )
        painter.setPen(QColor("#cbd5e1"))
        painter.setFont(QFont("Consolas", 7))
        painter.drawText(
            QRectF(6, 54, _NODE_W - 12, 16),
            Qt.AlignLeft | Qt.AlignVCenter,
            f"{self._kind_label} · severity {self._severity}",
        )

    def mousePressEvent(self, event) -> None:
        self.owner.select_node(str(self.row.get("id") or ""))
        super().mousePressEvent(event)


class _LensView(QGraphicsView):
    def __init__(self, scene) -> None:
        super().__init__(scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setBackgroundBrush(QColor("#080b11"))

    def wheelEvent(self, event) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)


class SentinelLensDialog(QDialog):
    """Read-only graph explorer over live and explicitly imported evidence."""

    def __init__(
        self,
        bus,
        manager=None,
        parent=None,
        *,
        config=None,
        service=None,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.bus = bus
        self.manager = manager
        self.config = config
        self.service = service or getattr(
            manager, "sentinel_lens_service", None
        )
        self._snapshot: dict = {}
        self._nodes: dict[str, dict] = {}
        self._items: dict[str, _LensNode] = {}
        self._selected_node = ""
        self._imported = deque(maxlen=MAX_IMPORT_RECORDS)
        self._import_generation = 0
        self._worker: _NarrativeWorker | None = None
        self._snapshot_worker: _SnapshotWorker | None = None
        self._import_worker: _ImportWorker | None = None
        self._refresh_pending = False
        self._last_source_key: tuple[object, ...] | None = None
        self.setWindowTitle("SentinelLens — Autonomous Threat Hunting (local-first)")
        self.setMinimumSize(1220, 780)
        if parent is not None:
            self.setStyleSheet(parent.styleSheet())

        root = QVBoxLayout(self)
        title = QLabel("SentinelLens — Autonomous Threat Hunting & Log-Anomaly Graph")
        title.setObjectName("PageTitle")
        root.addWidget(title)
        subtitle = QLabel(
            "Live EventBus + explicit Syslog / Windows Event / NetFlow imports · "
            "deterministic anomaly reasons · governed local AI · proposal-only remediation"
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color:#94a3b8;")
        root.addWidget(subtitle)

        controls = QHBoxLayout()
        self.format_box = QComboBox()
        self.format_box.addItem("Auto-detect import", "auto")
        self.format_box.addItem("Syslog text", "syslog")
        self.format_box.addItem("Windows Event JSON/JSONL", "windows-event")
        self.format_box.addItem("NetFlow JSON/JSONL", "netflow")
        self.import_button = QPushButton("Import local logs…")
        self.import_button.clicked.connect(self._import_logs)
        refresh = QPushButton("Refresh graph")
        refresh.clicked.connect(lambda: self.refresh(force=True))
        fit = QPushButton("Fit graph")
        fit.clicked.connect(self._fit)
        self.kind_filter = QComboBox()
        self.kind_filter.addItem("All node types", "")
        for kind in _KIND_ORDER:
            self.kind_filter.addItem(kind.title(), kind)
        self.kind_filter.currentIndexChanged.connect(self._render_graph)
        controls.addWidget(self.format_box)
        controls.addWidget(self.import_button)
        controls.addWidget(refresh)
        controls.addWidget(fit)
        controls.addWidget(self.kind_filter)
        controls.addStretch(1)
        self.status = QLabel("")
        self.status.setStyleSheet("color:#94a3b8;")
        controls.addWidget(self.status)
        root.addLayout(controls)

        split = QSplitter(Qt.Horizontal)
        graph_host = QWidget()
        graph_layout = QVBoxLayout(graph_host)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        self.scene = QGraphicsScene(self)
        self.view = _LensView(self.scene)
        graph_layout.addWidget(self.view)
        split.addWidget(graph_host)

        detail_host = QWidget()
        detail_layout = QVBoxLayout(detail_host)
        detail_layout.setContentsMargins(8, 0, 0, 0)
        detail_layout.addWidget(QLabel("Selected evidence & attack-chain narrative"))
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText(
            "Click any graph node or anomaly row for exact evidence, relation basis, paths, and proposals."
        )
        detail_layout.addWidget(self.detail, 1)
        self.local_ai = QPushButton("Explain selection with strict loopback local AI")
        self.local_ai.clicked.connect(self._ask_local_ai)
        detail_layout.addWidget(self.local_ai)
        split.addWidget(detail_host)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([720, 480])
        root.addWidget(split, 4)

        self.anomaly_header = QLabel(
            "Anomalies — click a row to inspect why it scored below baseline"
        )
        self.anomaly_header.setStyleSheet("color:#f59e0b;font-weight:bold;")
        root.addWidget(self.anomaly_header)
        self.anomalies = QTableWidget(0, 5)
        self.anomalies.setHorizontalHeaderLabels(
            ["Score", "Rule", "Finding", "Exact reason", "Evidence node"]
        )
        self.anomalies.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )
        self.anomalies.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.anomalies.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeToContents
        )
        self.anomalies.setEditTriggers(QTableWidget.NoEditTriggers)
        self.anomalies.setSelectionBehavior(QTableWidget.SelectRows)
        self.anomalies.setSortingEnabled(True)
        self.anomalies.cellClicked.connect(self._select_anomaly)
        root.addWidget(self.anomalies, 2)

        footer = QHBoxLayout()
        privacy = QLabel(
            "LOCAL-FIRST: no telemetry leaves this host; imports are memory-only; "
            "no remediation command executes here."
        )
        privacy.setStyleSheet("color:#22c55e;")
        footer.addWidget(privacy)
        footer.addStretch(1)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        footer.addWidget(close)
        root.addLayout(footer)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self.refresh)
        self._refresh_timer.start(2_500)
        self._pending_refresh_timer = QTimer(self)
        self._pending_refresh_timer.setSingleShot(True)
        self._pending_refresh_timer.timeout.connect(self._run_pending_refresh)
        self.refresh()

    def _live_events(self) -> list:
        service = self.service
        if service is not None:
            try:
                live = list(service.recent_events(_MAX_GRAPH_EVENTS))
            except Exception:
                live = []
        else:
            live = []
        try:
            if service is None:
                live = (
                    list(self.bus.recent(_MAX_GRAPH_EVENTS))
                    if self.bus is not None else []
                )
        except Exception:
            live = []
        imported = [record.as_event() for record in reversed(self._imported)]
        if not live:
            return imported[:_MAX_GRAPH_EVENTS]
        if not imported:
            return live[:_MAX_GRAPH_EVENTS]
        # Preserve a fair lane for explicit analyst evidence. A full EventBus
        # ring must not silently starve the file the analyst just imported, and
        # a large import must not blind the live lane.
        lane = _MAX_GRAPH_EVENTS // 2
        live_take = min(len(live), lane)
        imported_take = min(len(imported), lane)
        remaining = _MAX_GRAPH_EVENTS - live_take - imported_take
        if remaining:
            extra_live = min(max(0, len(live) - live_take), remaining)
            live_take += extra_live
            remaining -= extra_live
        if remaining:
            imported_take += min(
                max(0, len(imported) - imported_take), remaining
            )
        return live[:live_take] + imported[:imported_take]

    def _source_key(self, events: list) -> tuple[object, ...]:
        revision_owner = self.service or self.bus
        revision = getattr(revision_owner, "revision", None)
        try:
            bus_revision = int(revision()) if callable(revision) else None
        except Exception:
            bus_revision = None
        newest = events[0] if events else None
        fingerprint = (
            str(getattr(newest, "hmac_sig", "") or "")[:128],
            float(getattr(newest, "ts", 0.0) or 0.0) if newest is not None else 0.0,
        )
        return bus_revision, len(events), fingerprint, self._import_generation

    def refresh(self, *, force: bool = False) -> None:
        if getattr(self, "_angerona_deferred_close", False):
            return
        active = self._snapshot_worker
        if active is not None and active.isRunning():
            self._refresh_pending = True
            return
        try:
            # With no private analyst import to merge, consume the app-owned
            # snapshot directly. Graph/anomaly computation already happened on
            # the service worker and never needs to occupy the GUI thread.
            if self.service is not None and not self._imported:
                snapshot = self.service.snapshot()
                health = snapshot.get("service_health", {})
                source_key = (
                    "service",
                    int(health.get("snapshot_revision", 0) or 0),
                )
                if (
                    not force
                    and self._snapshot
                    and source_key == self._last_source_key
                ):
                    return
                self._last_source_key = source_key
                self._apply_snapshot(snapshot)
                return
            events = self._live_events()
            source_key = self._source_key(events)
            if not force and self._snapshot and source_key == self._last_source_key:
                return
            self._last_source_key = source_key
            self.status.setText(
                f"Building bounded graph from {len(events)} local record(s)…"
            )
            worker = _SnapshotWorker(events)
            self._snapshot_worker = worker
            worker.result.connect(self._apply_snapshot)
            worker.failed.connect(self._snapshot_failed)
            worker.finished.connect(self._snapshot_finished)
            worker.start()
        except Exception as exc:
            self.status.setText(f"Snapshot unavailable: {type(exc).__name__}")
            self.detail.setPlainText(str(exc)[:2_000])

    def _apply_snapshot(self, snapshot: dict) -> None:
        if getattr(self, "_angerona_deferred_close", False):
            return
        self._snapshot = snapshot
        self._nodes = {
            str(row.get("id")): row for row in self._snapshot.get("nodes", ())
        }
        stats = self._snapshot.get("stats", {})
        health = self._snapshot.get("service_health")
        if not isinstance(health, dict) and self.service is not None:
            try:
                health = self.service.health()
            except Exception:
                health = {"state": "unavailable"}
        service_status = ""
        if isinstance(health, dict):
            service_status = (
                f" · hunt {health.get('state', 'unknown')}"
                f" q {health.get('queue_depth', 0)}/{health.get('queue_capacity', 0)}"
                f" · dropped {health.get('queue_dropped', 0)}"
                f" · parse rejected {health.get('analysis_rejections', 0)}"
            )
        self.status.setText(
            f"{stats.get('incidents', 0)} incident(s) · "
            f"{stats.get('nodes', 0)} nodes · "
            f"{len(self._snapshot.get('anomalies', ()))} anomaly lead(s) · "
            f"{len(self._imported)} imported · "
            f"{stats.get('rejected_records', 0)} rejected"
            + (" · source truncated" if stats.get("source_truncated") else "")
            + service_status
        )
        self._render_graph()
        self._render_anomalies()

    def _snapshot_failed(self, reason: str) -> None:
        self._last_source_key = None
        if not getattr(self, "_angerona_deferred_close", False):
            self.status.setText(f"Snapshot unavailable: {reason[:240]}")

    def _snapshot_finished(self) -> None:
        if (
            self._refresh_pending
            and not getattr(self, "_angerona_deferred_close", False)
        ):
            self._pending_refresh_timer.start(0)

    def _run_pending_refresh(self) -> None:
        if getattr(self, "_angerona_deferred_close", False):
            return
        self._refresh_pending = False
        self.refresh(force=True)

    def _visible_nodes(self) -> list[dict]:
        rows = list(self._snapshot.get("nodes", ()))
        requested = str(self.kind_filter.currentData() or "")
        if requested:
            rows = [row for row in rows if str(row.get("kind", "")).casefold() == requested]
        anomaly_nodes = {
            str(row.get("event_id") or "") for row in self._snapshot.get("anomalies", ())
        }
        rows.sort(key=lambda row: (
            str(row.get("id")) not in anomaly_nodes,
            -int(row.get("severity", 0) or 0),
            -float(row.get("last_ts", 0.0) or 0.0),
            str(row.get("id")),
        ))
        return rows[:_MAX_VISIBLE_NODES]

    def _render_graph(self) -> None:
        self.scene.clear()
        self._items.clear()
        rows = self._visible_nodes()
        visible = {str(row.get("id")) for row in rows}
        groups: dict[str, list[dict]] = {}
        for row in rows:
            groups.setdefault(str(row.get("kind") or "event").casefold(), []).append(row)
        positions: dict[str, QPointF] = {}
        ordered_kinds = list(_KIND_ORDER) + sorted(set(groups) - set(_KIND_ORDER))
        for column, kind in enumerate(ordered_kinds):
            bucket = groups.get(kind, ())
            if not bucket:
                continue
            header = QGraphicsTextItem(kind.upper())
            header.setDefaultTextColor(QColor(_KIND_COLOR.get(kind, "#94a3b8")))
            header.setFont(QFont("Segoe UI", 10, QFont.Bold))
            header.setPos(column * 250, -42)
            self.scene.addItem(header)
            for index, row in enumerate(bucket):
                node_id = str(row.get("id"))
                position = QPointF(column * 250, index * 96)
                item = _LensNode(row, self)
                item.setPos(position)
                self.scene.addItem(item)
                self._items[node_id] = item
                positions[node_id] = QPointF(
                    position.x() + _NODE_W / 2, position.y() + _NODE_H / 2
                )
        edges = [
            row for row in self._snapshot.get("edges", ())
            if row.get("source") in visible and row.get("target") in visible
        ][:_MAX_VISIBLE_EDGES]
        for row in edges:
            self._draw_edge(
                positions[str(row["source"])],
                positions[str(row["target"])],
                float(row.get("confidence", 0.0) or 0.0),
            )
        if not rows:
            empty = QGraphicsTextItem("No nodes match this filter.")
            empty.setDefaultTextColor(QColor("#94a3b8"))
            self.scene.addItem(empty)
        self._fit()

    def _draw_edge(self, source: QPointF, target: QPointF, confidence: float) -> None:
        path = QPainterPath(source)
        midpoint = (source.x() + target.x()) / 2
        path.cubicTo(
            QPointF(midpoint, source.y()),
            QPointF(midpoint, target.y()),
            target,
        )
        edge = QGraphicsPathItem(path)
        alpha = max(55, min(220, int(55 + confidence * 165)))
        color = QColor(100, 116, 139, alpha)
        edge.setPen(QPen(color, 1.0 + confidence))
        edge.setZValue(1)
        self.scene.addItem(edge)

    def _fit(self) -> None:
        bounds = self.scene.itemsBoundingRect()
        if bounds.isValid() and math.isfinite(bounds.width()):
            self.view.fitInView(bounds, Qt.KeepAspectRatio)

    def _render_anomalies(self) -> None:
        self.anomalies.setSortingEnabled(False)
        all_rows = list(self._snapshot.get("anomalies", ()))
        rows = all_rows[:_MAX_VISIBLE_ANOMALIES]
        self.anomaly_header.setText(
            "Anomalies — click a row for exact evidence and proposals"
            + (
                f" · showing highest {len(rows)} of {len(all_rows)} bounded leads"
                if len(all_rows) > len(rows) else ""
            )
        )
        self.anomalies.setRowCount(len(rows))
        for index, finding in enumerate(rows):
            score = QTableWidgetItem()
            score.setData(Qt.DisplayRole, int(finding.get("score", 0)))
            if int(finding.get("score", 0)) >= 80:
                score.setForeground(QColor("#ef4444"))
            self.anomalies.setItem(index, 0, score)
            self.anomalies.setItem(index, 1, QTableWidgetItem(str(finding.get("rule_id", ""))))
            self.anomalies.setItem(index, 2, QTableWidgetItem(str(finding.get("title", ""))))
            self.anomalies.setItem(index, 3, QTableWidgetItem(str(finding.get("reason", ""))))
            evidence = QTableWidgetItem(str(finding.get("event_id", "")))
            evidence.setData(Qt.UserRole, str(finding.get("finding_id", "")))
            self.anomalies.setItem(index, 4, evidence)
        self.anomalies.setSortingEnabled(True)
        self.anomalies.sortItems(0, Qt.DescendingOrder)

    def _select_anomaly(self, row: int, _column: int) -> None:
        item = self.anomalies.item(row, 4)
        if item is not None:
            self.select_node(item.text())

    def select_node(self, node_id: str) -> None:
        self._selected_node = str(node_id)
        for candidate, item in self._items.items():
            item.setSelected(candidate == self._selected_node)
        narrative = render_narrative(self._snapshot, self._selected_node)
        row = self._nodes.get(self._selected_node, {})
        findings = [
            finding for finding in self._snapshot.get("anomalies", ())
            if finding.get("event_id") in self._related_node_ids(self._selected_node)
        ]
        lines = [narrative, "", "EXACT NODE EVIDENCE", json.dumps(
            row, indent=2, sort_keys=True, ensure_ascii=False, default=str,
        )[:12_000]]
        for finding in findings:
            lines.extend((
                "",
                f"REMEDIATION PROPOSALS — {finding.get('finding_id')}",
                *[f"- {proposal}" for proposal in finding.get("remediation_proposals", ())],
            ))
        self.detail.setPlainText("\n".join(lines))

    def _related_node_ids(self, node_id: str) -> set[str]:
        related = {str(node_id)}
        for edge in self._snapshot.get("edges", ()):
            source = str(edge.get("source") or "")
            target = str(edge.get("target") or "")
            if source == node_id or target == node_id:
                related.update((source, target))
        return related

    def _ask_local_ai(self) -> None:
        if not self._selected_node:
            self.detail.appendPlainText("\nSelect a node before requesting a narrative.")
            return
        if self._worker is not None and self._worker.isRunning():
            return
        deterministic = render_narrative(self._snapshot, self._selected_node)
        self.local_ai.setEnabled(False)
        self.local_ai.setText("Local AI is reasoning…")
        self._worker = _NarrativeWorker(self._ask_loopback_ai, deterministic[:8_000])
        self._worker.result.connect(self._on_ai_result)
        self._worker.start()

    def _ask_loopback_ai(self, prompt: str) -> str:
        """Consult Ollama only when its configured URL is provably loopback."""
        config = self.config
        if config is None:
            owner = self.parent()
            while owner is not None and config is None:
                config = getattr(owner, "config", None)
                owner = owner.parent() if hasattr(owner, "parent") else None
        host = _loopback_ollama_url(getattr(config, "ollama_host", None))
        model = str(getattr(config, "ollama_model", "llama3") or "llama3")[:160]
        from angerona.engines import ollama_client

        result = ollama_client.call(
            {
                "model": model,
                "prompt": (
                    "You are the local-only SentinelLens analyst. Summarize the "
                    "separately delimited, untrusted defensive graph evidence. "
                    "Clearly separate evidence, inference, and unknowns. Do not "
                    "claim causation from time proximity. Recommend only review-gated "
                    "Angerona proposals and never output executable scripts."
                ),
                "stream": False,
                "keep_alive": str(
                    getattr(config, "ollama_keep_alive", "30m") or "30m"
                )[:32],
                "options": {"num_predict": 500, "temperature": 0.2, "top_p": 0.8},
            },
            "/api/generate",
            host=host,
            timeout=60,
            neutralized_telemetry=prompt[:8_000],
        )
        if not isinstance(result, dict) or not result.get("response"):
            reason = result.get("error") if isinstance(result, dict) else "no response"
            raise RuntimeError(f"loopback Ollama unavailable: {str(reason)[:240]}")
        return str(result["response"])[:12_000]

    def _on_ai_result(self, text: str) -> None:
        self.detail.appendPlainText("\n\nGOVERNED LOCAL-AI NARRATIVE\n" + text)
        self.local_ai.setEnabled(True)
        self.local_ai.setText("Explain selection with strict loopback local AI")

    @staticmethod
    def _is_link_or_reparse(info: os.stat_result) -> bool:
        attributes = int(getattr(info, "st_file_attributes", 0))
        return stat.S_ISLNK(info.st_mode) or bool(
            attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )

    @classmethod
    def _reject_reparse_components(cls, path: Path) -> None:
        components = list(reversed(path.parents)) + [path]
        for index, component in enumerate(components):
            info = component.lstat()
            if cls._is_link_or_reparse(info):
                raise SentinelLensInputError(
                    "selected import path contains a link or reparse point"
                )
            if index < len(components) - 1 and not stat.S_ISDIR(info.st_mode):
                raise SentinelLensInputError(
                    "selected import path contains a non-directory component"
                )

    @staticmethod
    def _identity(info: os.stat_result) -> tuple[object, ...]:
        return (
            info.st_dev,
            info.st_ino,
            stat.S_IFMT(info.st_mode),
            info.st_size,
            getattr(info, "st_mtime_ns", None),
        )

    @classmethod
    def _path_state(cls, info: os.stat_result) -> tuple[object, ...]:
        return (*cls._identity(info), getattr(info, "st_ctime_ns", None))

    @classmethod
    def _safe_import_bytes(cls, path: Path) -> bytes:
        # Keep the lexical path: resolving it first would hide that the analyst
        # selected a symlink/junction and defeat this admission check.
        path = Path(os.path.abspath(os.fspath(path)))
        cls._reject_reparse_components(path)
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or cls._is_link_or_reparse(info)
            or not 0 < info.st_size <= _MAX_IMPORT_FILE_BYTES
        ):
            raise SentinelLensInputError("selected import must be one bounded regular file")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(os.fspath(path), flags)
        except OSError as exc:
            raise SentinelLensInputError("selected import could not be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or cls._is_link_or_reparse(opened)
                or cls._identity(opened) != cls._identity(info)
            ):
                raise SentinelLensInputError("selected import changed while being opened")
            chunks: list[bytes] = []
            remaining = _MAX_IMPORT_FILE_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b"".join(chunks)
        except SentinelLensInputError:
            raise
        except OSError as exc:
            raise SentinelLensInputError("selected import could not be read safely") from exc
        finally:
            os.close(descriptor)
        if len(body) != info.st_size or len(body) > _MAX_IMPORT_FILE_BYTES:
            raise SentinelLensInputError("selected import changed or exceeded its byte bound")
        after = path.lstat()
        if cls._is_link_or_reparse(after) or cls._path_state(after) != cls._path_state(info):
            raise SentinelLensInputError("selected import changed while being read")
        cls._reject_reparse_components(path)
        return body

    def _import_logs(self) -> None:
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            "Import standardized security logs (local, memory-only)",
            "",
            "Security logs (*.log *.txt *.json *.jsonl *.ndjson);;All files (*)",
        )
        if not selected:
            return
        try:
            path = Path(os.path.abspath(selected))
            mode = str(self.format_box.currentData() or "auto")
            self.status.setText(
                f"Reading and validating {path.name[:260]} off the GUI thread…"
            )
            self.import_button.setEnabled(False)
            worker = _ImportWorker(
                path, mode, self._safe_import_bytes, self._parse_import
            )
            self._import_worker = worker
            worker.result.connect(self._import_complete)
            worker.failed.connect(self._import_failed)
            worker.finished.connect(lambda: self.import_button.setEnabled(True))
            worker.start()
        except Exception as exc:
            self.status.setText(f"Import rejected: {type(exc).__name__}: {str(exc)[:240]}")

    def _import_complete(self, records: list, name: str) -> None:
        if getattr(self, "_angerona_deferred_close", False):
            return
        for record in records:
            self._imported.append(record)
        self._import_generation += 1
        self.status.setText(
            f"Imported {len(records)} bounded record(s) from {name}; memory-only."
        )
        self.refresh(force=True)

    def _import_failed(self, reason: str) -> None:
        if not getattr(self, "_angerona_deferred_close", False):
            self.status.setText(f"Import rejected: {reason[:240]}")

    @staticmethod
    def _parse_import(body: bytes, mode: str, suffix: str) -> list:
        return list(parse_log_bundle(body, source_format=mode, suffix=suffix))

    def closeEvent(self, event) -> None:
        from angerona.gui.thread_lifecycle import defer_close_until_threads

        self._refresh_timer.stop()
        self._pending_refresh_timer.stop()
        if defer_close_until_threads(
            self,
            event,
            (self._worker, self._snapshot_worker, self._import_worker),
        ):
            return
        super().closeEvent(event)


__all__ = ["SentinelLensDialog"]
