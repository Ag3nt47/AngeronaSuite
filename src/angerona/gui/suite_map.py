"""Interactive software-rendered 3D suite topology; no OpenGL dependency."""
from __future__ import annotations

import math
from html import escape

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QPlainTextEdit, QPushButton, QSizePolicy,
    QSplitter, QVBoxLayout, QWidget,
)

from angerona.core.suite_topology import SuiteTopologyService, TopologySnapshot
from angerona.gui.header_controls import motion_allowed
from angerona.gui.window_controls import configure_work_window


class SuiteMapCanvas(QWidget):
    selected = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("SuiteMapCanvas")
        self.setAccessibleName("Interactive 3D Angerona Suite Map")
        self.setAccessibleDescription("Scroll to zoom. Drag to orbit. Shift-drag to pan. Click a shape for details and navigation.")
        self.setMouseTracking(True)
        self.setMinimumSize(320, 320)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.snapshot = TopologySnapshot()
        self.yaw, self.pitch, self.zoom = -.45, -.16, 1.0
        self.pan = QPointF()
        self._drag = self._pressed = None
        self._moved = False
        self._hits = []
        self._labels = []
        self._pending_labels = []
        self._hover = self._selected = ""
        self._phase = 0.0
        self.animate = True
        self.filter = "All components"
        self.query = ""
        self._timer = QTimer(self)
        self._timer.setInterval(83)  # maximum 12 FPS, visible view only.
        self._timer.timeout.connect(self._tick)

    def _tick(self):
        if self.animate:
            self._phase = (self._phase + .045) % 1
            self.update()

    def showEvent(self, event):
        super().showEvent(event)
        if self.animate:
            self._timer.start()

    def set_animation(self, enabled):
        self.animate = bool(enabled)
        if self.animate and self.isVisible():
            self._timer.start()
        else:
            self._timer.stop()
        self.update()

    def hideEvent(self, event):
        self._timer.stop()
        super().hideEvent(event)

    def reset_view(self):
        self.yaw, self.pitch, self.zoom, self.pan = -.45, -.16, 1.0, QPointF()
        extent = max((max(abs(value) for value in node.position) for node in self.snapshot.nodes), default=8)
        self.zoom = min(1.0, 8 / max(8, extent))
        self.update()

    def set_snapshot(self, snapshot):
        self.snapshot = snapshot
        self.update()

    def _project(self, position):
        x, y, z = position
        x, z = x * math.cos(self.yaw) + z * math.sin(self.yaw), -x * math.sin(self.yaw) + z * math.cos(self.yaw)
        y, z = y * math.cos(self.pitch) - z * math.sin(self.pitch), y * math.sin(self.pitch) + z * math.cos(self.pitch)
        perspective = 18 / max(5, 18 + z)
        scale = min(self.width(), self.height()) * .057 * self.zoom * perspective
        return QPointF(self.width() / 2 + self.pan.x() + x * scale,
                       self.height() / 2 + self.pan.y() - y * scale), z, scale

    def _visible(self, node):
        if self.query and self.query.casefold() not in (node.label + " " + node.kind).casefold():
            return False
        if self.filter == "Modules":
            return node.kind == "module" or node.id in {"host", "core", "bus"}
        if self.filter == "Drives & devices":
            return node.kind in {"host", "internal_drive", "external_drive", "volume", "accessory"}
        if self.filter == "Network ports":
            return node.kind in {"host", "port"}
        return True

    @staticmethod
    def _color(node):
        if node.kind == "module":
            if node.status in {"disabled", "not_configured", "not_installed", "unsupported", "paused"}:
                return QColor("#70859a")
            if node.status in {"error", "failed"} or node.health is not None and node.health <= 35:
                return QColor("#fb7185")
            if node.status != "running" or node.health is None or node.health < 80:
                return QColor("#fbbf24")
            return QColor("#34d399")
        return QColor({"bus": "#22d3ee", "core": "#60a5fa", "host": "#a78bfa", "port": "#fb923c",
            "internal_drive": "#93c5fd", "external_drive": "#c084fc", "volume": "#93c5fd", "accessory": "#f0abfc",
            "watchdog": "#2dd4bf", "scanner": "#f472b6", "storage": "#818cf8"}.get(node.kind, "#94a3b8"))

    def _shape(self, painter, node):
        center, depth, scale = self._project(node.position)
        size = .28 if node.kind == "module" else .52 if node.id in {"host", "core", "bus"} else .36
        x, y, z = node.position
        vertices = [self._project((x + dx * size, y + dy * size, z + dz * size))[0]
                    for dx, dy, dz in ((-1,-1,-1),(1,-1,-1),(1,1,-1),(-1,1,-1),(-1,-1,1),(1,-1,1),(1,1,1),(-1,1,1))]
        color = self._color(node)
        if node.kind in {"bus", "port", "accessory"}:
            vertices = [self._project((x + dx * size * 1.4, y + dy * size * 1.4, z + dz * size * 1.4))[0]
                        for dx,dy,dz in ((1,0,0),(0,1,0),(-1,0,0),(0,-1,0),(0,0,1),(0,0,-1))]
            faces = ((0,1,4),(1,2,4),(2,3,4),(3,0,4))
        else:
            faces = ((0,1,2,3),(1,5,6,2),(3,2,6,7))
        painter.setPen(QPen(color.lighter(145), 1.4 if node.id in {self._hover, self._selected} else .65))
        for index, face in enumerate(faces):
            fill = color.darker(180 - index * 22)
            fill.setAlpha(235)
            painter.setBrush(fill)
            painter.drawPolygon(QPolygonF([vertices[item] for item in face]))
        radius = max(8, size * scale * 1.7)
        box = QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2)
        self._hits.append((box, node))
        selected = node.id in {self._hover, self._selected}
        if selected or node.kind not in {"module", "port"} or self.zoom >= 1.7:
            self._pending_labels.append((node, center, radius, selected))

    def _draw_labels(self, painter):
        # Text is drawn after geometry so a nearer shape cannot paint through
        # an already positioned label. Selected labels reserve their space first.
        for node, center, radius, selected in sorted(self._pending_labels, key=lambda row: not row[3]):
            if not selected and len(self._labels) >= 40:
                continue
            painter.setPen(QColor("#e2e8f0"))
            text = painter.fontMetrics().elidedText(node.label, Qt.TextElideMode.ElideRight, 200)
            metrics = painter.fontMetrics()
            width, height = metrics.horizontalAdvance(text) + 8, metrics.height() + 5
            positions = ((center.x()+radius+3, center.y()-height/2),
                         (center.x()-radius-width-3, center.y()-height/2),
                         (center.x()-width/2, center.y()-radius-height-3),
                         (center.x()-width/2, center.y()+radius+3))
            for left, top in positions:
                left = max(8, min(self.width()-width-8, left))
                top = max(30, min(self.height()-height-30, top))
                label = QRectF(left, top, width, height)
                if any(label.adjusted(-2, -2, 2, 2).intersects(prior) for prior in self._labels):
                    continue
                painter.fillRect(label, QColor(8, 18, 30, 200))
                painter.drawText(label.adjusted(3, 0, -3, 0), Qt.AlignmentFlag.AlignVCenter, text)
                self._labels.append(label)
                break

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0, QColor("#06121f"))
        gradient.setColorAt(1, QColor("#101025"))
        painter.fillRect(self.rect(), gradient)
        painter.setPen(QPen(QColor("#152738"), 1))
        for step in range(-10, 11):
            a, _, _ = self._project((step, -6.7, -10))
            b, _, _ = self._project((step, -6.7, 10))
            painter.drawLine(a, b)
            a, _, _ = self._project((-10, -6.7, step))
            b, _, _ = self._project((10, -6.7, step))
            painter.drawLine(a, b)
        nodes = [node for node in self.snapshot.nodes if self._visible(node)]
        visible = {node.id: node for node in nodes}
        for index, edge in enumerate(self.snapshot.edges):
            if edge.source not in visible or edge.target not in visible:
                continue
            a, _, _ = self._project(visible[edge.source].position)
            b, _, _ = self._project(visible[edge.target].position)
            color = QColor("#19a7c6") if edge.observed else QColor("#254053")
            color.setAlpha(160 if edge.observed else 85)
            pen = QPen(color, 1.2 if edge.observed else .6)
            if not edge.observed:
                pen.setStyle(Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.drawLine(a, b)
            if edge.active and self.animate and index % 2 == 0:
                fraction = (self._phase + index * .07) % 1
                point = a * (1 - fraction) + b * fraction
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor("#67e8f9"))
                painter.drawEllipse(point, 2.5, 2.5)
        self._hits = []
        self._labels = []
        self._pending_labels = []
        for node in sorted(nodes, key=lambda value: self._project(value.position)[1], reverse=True):
            self._shape(painter, node)
        self._draw_labels(painter)
        painter.setPen(QColor("#8ca9c2"))
        painter.drawText(14, 24, "LOCAL SUITE MAP · 3D")
        painter.drawText(14, self.height() - 14, "Scroll: zoom   Drag: orbit   Shift-drag: pan   Click: inspect")

    def _hit(self, point):
        return next((node for box, node in reversed(self._hits) if box.contains(point)), None)

    def mousePressEvent(self, event):
        self._drag = self._pressed = event.position()
        self._moved = False

    def mouseMoveEvent(self, event):
        point = event.position()
        if self._drag is not None and event.buttons() & Qt.MouseButton.LeftButton:
            delta = point - self._drag
            self._moved |= (point - self._pressed).manhattanLength() > 5
            self._drag = point
            if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                self.pan += delta
            else:
                self.yaw += delta.x() * .008
                self.pitch = max(-1.35, min(1.35, self.pitch + delta.y() * .006))
            self.update()
            return
        node = self._hit(point)
        self._hover = node.id if node is not None else ""
        tooltip = node.label + "\n" + "\n".join(f"{key}: {value}" for key, value in node.info[:3]) if node else ""
        self.setToolTip("<qt>" + escape(tooltip).replace("\n", "<br>") + "</qt>" if tooltip else "")
        self.update()

    def mouseReleaseEvent(self, event):
        if not self._moved:
            node = self._hit(event.position())
            if node is not None:
                self._selected = node.id
                self.selected.emit(node)
        self._drag = self._pressed = None
        self.update()

    def wheelEvent(self, event):
        self.zoom = max(.3, min(4.5, self.zoom * math.exp(event.angleDelta().y() / 1200)))
        self.update()
        event.accept()


class SuiteMapDialog(QDialog):
    def __init__(self, manager, bus, parent=None, *, navigate=None, service=None, config=None):
        super().__init__(parent)
        self.config = config if config is not None else getattr(parent, "config", None)
        self.setWindowTitle("Angerona — Suite Map · 3D")
        self.setObjectName("SuiteMapDialog")
        self.resize(1240, 820)
        self.setMinimumSize(680, 480)
        self.service = service or SuiteTopologyService(manager, bus)
        self.navigate = navigate
        self._selection = None
        self._last_generation = -1
        self._listing_key = ()
        layout = QVBoxLayout(self)
        heading = QLabel("SUITE MAP · Follow the flow")
        heading.setStyleSheet("font-size:20px;font-weight:800;color:#67e8f9")
        layout.addWidget(heading)
        toolbar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Find a module, drive, device or port…")
        self.search.setObjectName("SuiteMapSearch")
        toolbar.addWidget(self.search, 1)
        self.filter = QComboBox()
        self.filter.addItems(["All components", "Modules", "Drives & devices", "Network ports"])
        toolbar.addWidget(self.filter)
        self.flows = QCheckBox("Animate observed flow")
        self.flows.setChecked(motion_allowed(self.config))
        toolbar.addWidget(self.flows)
        reset = QPushButton("Reset view")
        toolbar.addWidget(reset)
        layout.addLayout(toolbar)
        splitter = QSplitter()
        self.canvas = SuiteMapCanvas()
        splitter.addWidget(self.canvas)
        sidebar = QWidget()
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(6, 0, 0, 0)
        self.listing = QListWidget()
        self.listing.setObjectName("SuiteMapComponentList")
        side.addWidget(self.listing, 2)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setObjectName("SuiteMapSelectionDetails")
        self.details.setPlainText("Select a shape or list entry to inspect its purpose, status and coverage.")
        side.addWidget(self.details, 2)
        self.go = QPushButton("Take me there")
        self.go.setObjectName("SuiteMapNavigate")
        self.go.setEnabled(False)
        side.addWidget(self.go)
        splitter.addWidget(sidebar)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([900, 300])
        layout.addWidget(splitter, 1)
        self.status = QLabel("Starting cached topology…")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.legend = QLabel("Cyan solid: observed publications/endpoints · Dashed: architecture · Gray: off/paused · Colors reflect cached lifecycle, selection and health. Hidden intervals are not observed.")
        self.legend.setWordWrap(True)
        self.legend.setStyleSheet("color:#94a3b8")
        layout.addWidget(self.legend)
        self.search.textChanged.connect(self._filter)
        self.filter.currentTextChanged.connect(self._filter)
        self.flows.toggled.connect(self._animate)
        self._apply_motion_policy()
        reset.clicked.connect(self.canvas.reset_view)
        self.canvas.selected.connect(self._select)
        self.listing.currentItemChanged.connect(self._list_selected)
        self.go.clicked.connect(self._navigate)
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._refresh)
        configure_work_window(self)

    def _animate(self, enabled):
        self.canvas.set_animation(enabled and motion_allowed(self.config))

    def _apply_motion_policy(self):
        allowed = motion_allowed(self.config)
        self.flows.setEnabled(allowed)
        self.flows.setToolTip("Animate recent observed publications and endpoints." if allowed else
            "Animation is paused by the suite or operating system reduced-motion setting.")
        if not allowed:
            self.flows.setChecked(False)
        self._animate(self.flows.isChecked())

    def _filter(self, *_):
        self.canvas.query = self.search.text()
        self.canvas.filter = self.filter.currentText()
        self._listing_key = ()
        self._refresh()
        self.canvas.update()

    def _refresh(self):
        self._apply_motion_policy()
        if self.isVisible() and self.service.custody_released():
            self.service.start()
        snapshot = self.service.snapshot()
        self.canvas.set_snapshot(snapshot)
        key = tuple((node.id, node.label) for node in snapshot.nodes if self.canvas._visible(node))
        if key != self._listing_key:
            selected = self._selection.id if self._selection else ""
            scroll = self.listing.verticalScrollBar().value()
            self.listing.blockSignals(True)
            self.listing.clear()
            for node in snapshot.nodes:
                if self.canvas._visible(node):
                    item = QListWidgetItem(node.label)
                    item.setData(Qt.ItemDataRole.UserRole, node.id)
                    self.listing.addItem(item)
                    if node.id == selected:
                        self.listing.setCurrentItem(item)
            self.listing.verticalScrollBar().setValue(scroll)
            self.listing.blockSignals(False)
            self._listing_key = key
        if self._selection is not None:
            latest = next((node for node in snapshot.nodes if node.id == self._selection.id), None)
            if latest:
                self._select(latest)
            else:
                self._selection = None
                self.canvas._selected = ""
                self.details.setPlainText("The selected component is no longer present in the current snapshot.")
                self.go.setEnabled(False)
        self.status.setText(f"{snapshot.state.capitalize()} · {len(snapshot.nodes)} shapes · {len(snapshot.edges)} links · "
            f"{snapshot.events} observed events · {snapshot.dropped} queue losses · {snapshot.omitted} bounded omissions\n" + "\n".join(snapshot.coverage[:2]))

    def _list_selected(self, item, _previous):
        if item is not None:
            node = next((node for node in self.service.snapshot().nodes if node.id == item.data(Qt.ItemDataRole.UserRole)), None)
            if node:
                self.canvas._selected = node.id
                self._select(node)

    def _select(self, node):
        self._selection = node
        text = node.label + "\n\n" + "\n\n".join(f"{key}\n{value}" for key, value in node.info)
        if self.details.toPlainText() != text:
            scroll = self.details.verticalScrollBar().value()
            self.details.setPlainText(text)
            self.details.verticalScrollBar().setValue(scroll)
        self.go.setEnabled(bool(node.route and self.navigate))

    def _navigate(self):
        if self._selection is not None and self.navigate is not None:
            self.navigate(self._selection.route, self._selection.target)

    def showEvent(self, event):
        super().showEvent(event)
        self.service.start()
        self._timer.start()
        self._refresh()

    def hideEvent(self, event):
        self._timer.stop()
        self.service.request_shutdown()
        super().hideEvent(event)

    def request_shutdown(self):
        self._timer.stop()
        self.canvas._timer.stop()
        self.service.request_shutdown()

    def owned_workers(self):
        return self.service.owned_workers()

    def custody_released(self):
        return self.service.custody_released()
