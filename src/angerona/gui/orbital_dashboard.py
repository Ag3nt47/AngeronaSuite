"""An optional orbital presentation of existing, in-memory dashboard evidence.

Every satellite represents one discovered module. Rings are a visual inventory,
not inferred network links. No collectors, threads, or animation timers live here.
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass

from PySide6.QtCore import QPointF, QRectF, Qt, Signal, Slot
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient
from PySide6.QtWidgets import QSizePolicy, QWidget

from angerona.gui.dashboard_footer import _number, _rate


@dataclass(frozen=True)
class _Module:
    name: str
    code: str
    status: str
    health: int | None
    state: str
    note: str


_COLORS = {
    "ok": "#46e5bd", "degraded": "#f2bf6d", "critical": "#fb7185",
    "failed": "#fb7185", "off": "#617086", "unknown": "#8494aa",
}


def _plain(value, limit: int = 240) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


class OrbitalDashboard(QWidget):
    """Paint a lightweight live module constellation and selected-module detail.

    The owner calls refresh(), update_posture(dict), and update_sample(dict)
    from its existing refresh paths. Selecting a satellite never changes module
    policy. Enter/Space or clicking a satellite requests the ordinary inspector.
    """

    module_requested = Signal(str)
    alerts_requested = Signal()
    posture_requested = Signal()

    def __init__(self, bus, manager, config, parent=None) -> None:
        super().__init__(parent)
        self.bus, self.manager, self.config = bus, manager, config
        self.setObjectName("OrbitalDashboard")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMinimumSize(0, 390)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setMouseTracking(True)
        self.setAccessibleName("Orbital defense dashboard")
        self._modules: tuple[_Module, ...] = ()
        self._selected_name = ""
        self._hover_name = ""
        self._nodes: dict[str, QPointF] = {}
        self._core = QRectF()
        self._alerts_button = QRectF()
        self._module_button = QRectF()
        self._plot = QRectF()
        self._detail = QRectF()
        self._posture = (None, "Awaiting posture", "#7dd3fc")
        self._sample = (None, None, None, None)
        self._network_history: deque[tuple[float, float]] = deque(maxlen=60)
        self._idle = False
        self._accessible_summary = ""
        self.refresh()

    def refresh(self) -> bool:
        """Read only bounded module health fields; unchanged frames stay idle."""
        records = []
        for name, module in sorted(list(getattr(self.manager, "modules", {}).items())):
            try:
                summary = getattr(module, "health_summary", None)
                if callable(summary):
                    status, health, state = summary()
                else:
                    status = getattr(module, "status", "unknown")
                    health = getattr(module, "health", None)
                    state = getattr(module, "health_state", "unknown")
                numeric = _number(health, percentage=True)
                records.append(_Module(
                    name, _plain(getattr(module, "CODE", "") or
                                 "".join(word[0] for word in name.split()), 12),
                    _plain(status, 40), None if numeric is None else int(numeric),
                    _plain(state, 40), _plain(getattr(module, "health_note", "")),
                ))
            except Exception:
                records.append(_Module(name, "?", "unknown", None, "unknown",
                                       "Module health is unavailable."))
        snapshot = tuple(records)
        if snapshot == self._modules:
            return False
        self._modules = snapshot
        names = {module.name for module in snapshot}
        if self._selected_name not in names:
            self._selected_name = snapshot[0].name if snapshot else ""
        if self._hover_name not in names:
            self._hover_name = ""
        self._update_geometry()
        self._update_accessibility()
        self.update()
        return True

    @Slot(object)
    def update_posture(self, snapshot) -> None:
        data = snapshot if isinstance(snapshot, dict) else {}
        score = _number(data.get("score"), percentage=True)
        label = _plain(data.get("label") or "Awaiting posture", 96)
        raw_color = str(data.get("color") or "#7dd3fc")
        color = raw_color if QColor(raw_color).isValid() else "#7dd3fc"
        value = (score, label, color)
        if value == self._posture:
            return
        self._posture = value
        self._update_accessibility()
        self.update()

    @Slot(object)
    def update_sample(self, data) -> None:
        valid = isinstance(data, dict) and not data.get("error")
        sample = (
            _number(data.get("cpu"), percentage=True),
            _number(data.get("ram"), percentage=True),
            _number(data.get("down")), _number(data.get("up")),
        ) if valid else (None, None, None, None)
        history_changed = sample[2] is not None and sample[3] is not None
        if history_changed:
            self._network_history.append((sample[2], sample[3]))
        if sample == self._sample and not history_changed:
            return
        self._sample = sample
        self._update_accessibility()
        self.update()

    def set_idle_mode(self, quiet: bool) -> None:
        """Compatibility with the owner's quiet/hidden presentation policy.

        This view is deliberately static between fresh evidence or interaction;
        there is no animation worker to keep alive in either mode.
        """
        self._idle = bool(quiet)

    def _selected(self) -> _Module | None:
        wanted = self._hover_name or self._selected_name
        return next((module for module in self._modules if module.name == wanted), None)

    def _module_description(self, module: _Module) -> str:
        health = "unavailable" if module.health is None else f"{module.health}%"
        return (f"{module.name}. Status: {module.status}. Coverage health: {health}. "
                f"{module.note}").strip()

    def _update_accessibility(self) -> None:
        selected = next((module for module in self._modules
                         if module.name == self._selected_name), None)
        score, label, _color = self._posture
        posture = "Posture unavailable." if score is None else f"Posture {score:g}/100: {label}."
        description = (
            f"{len(self._modules)} module satellites. {posture} "
            + (self._module_description(selected) if selected else "No modules discovered.")
            + " Arrow keys select a module; Enter or Space opens its details. "
              "Press A for alerts or P for posture details."
        )
        if description != self._accessible_summary:
            self._accessible_summary = description
            self.setAccessibleDescription(description)
        cpu, ram, down, up = self._sample
        tooltip = (
            f"{description}\nCPU: {'unavailable' if cpu is None else f'{cpu:g}%'}. "
            f"RAM: {'unavailable' if ram is None else f'{ram:g}%'}. "
            f"Receive: {_rate(down)}. Send: {_rate(up)}.\n"
            "Satellites show module health. Orbital positions do not represent network connections."
        )
        if self.toolTip() != tooltip:
            self.setToolTip(tooltip)

    def _update_geometry(self) -> None:
        available = QRectF(self.rect()).adjusted(20, 70, -20, -20)
        if self.width() >= 780:
            detail_width = min(300.0, available.width() * 0.30)
            self._detail = QRectF(available.right() - detail_width, available.top(),
                                  detail_width, available.height())
            self._plot = QRectF(available.x(), available.y(),
                               max(0, available.width() - detail_width - 24), available.height())
        else:
            detail_height = min(160.0, max(115.0, available.height() * 0.33))
            self._detail = QRectF(available.x(), available.bottom() - detail_height,
                                  available.width(), detail_height)
            self._plot = QRectF(available.x(), available.y(), available.width(),
                               max(100, available.height() - detail_height - 8))
        center = self._plot.center()
        radius = max(26.0, min(self._plot.width(), self._plot.height()) * 0.45)
        core_radius = max(24.0, min(62.0, radius * 0.34))
        self._core = QRectF(center.x() - core_radius, center.y() - core_radius,
                            core_radius * 2, core_radius * 2)
        self._nodes = {}
        count = len(self._modules)
        rings = min(4, max(1, math.ceil(count / 24)))
        offset = 0
        for ring in range(rings):
            ring_count = math.ceil((count - offset) / (rings - ring))
            ring_radius = radius * (0.53 + (0.47 * ring / max(1, rings - 1)))
            for index in range(ring_count):
                angle = -math.pi / 2 + math.tau * index / max(1, ring_count) + ring * 0.16
                self._nodes[self._modules[offset + index].name] = QPointF(
                    center.x() + math.cos(angle) * ring_radius,
                    center.y() + math.sin(angle) * ring_radius,
                )
            offset += ring_count
        self._alerts_button = QRectF(max(20, self.width() - 136), 22, 116, 30)
        self._module_button = QRectF(self._detail.x() + 14, self._detail.bottom() - 42,
                                     max(0, self._detail.width() - 28), 28)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        if hasattr(self, "_modules"):
            self._update_geometry()

    def _hit_node(self, position: QPointF) -> str:
        closest, distance = "", 100.0
        for name, point in self._nodes.items():
            squared = (position.x() - point.x()) ** 2 + (position.y() - point.y()) ** 2
            if squared < distance:
                closest, distance = name, squared
        return closest

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        name = self._hit_node(event.position())
        if name != self._hover_name:
            self._hover_name = name
            if name:
                module = self._selected()
                if module is not None:
                    self.setToolTip(self._module_description(module))
            else:
                self._update_accessibility()
            self.update()
        clickable = (bool(name) or self._core.contains(event.position()) or
                     self._alerts_button.contains(event.position()) or
                     self._module_button.contains(event.position()))
        self.setCursor(Qt.PointingHandCursor if clickable else Qt.ArrowCursor)
        super().mouseMoveEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: N802
        if self._hover_name:
            self._hover_name = ""
            self._update_accessibility()
            self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            self.setFocus(Qt.MouseFocusReason)
            point = event.position()
            name = self._hit_node(point)
            if name:
                self._selected_name = name
                self._hover_name = ""
                self._update_accessibility()
                self.update()
                self.module_requested.emit(name)
            elif self._core.contains(point):
                self.posture_requested.emit()
            elif self._alerts_button.contains(point):
                self.alerts_requested.emit()
            elif self._module_button.contains(point) and self._selected_name:
                self.module_requested.emit(self._selected_name)
            event.accept()
            return
        super().mousePressEvent(event)

    def keyPressEvent(self, event) -> None:  # noqa: N802
        key = event.key()
        if key == Qt.Key_A:
            self.alerts_requested.emit()
        elif key == Qt.Key_P:
            self.posture_requested.emit()
        elif key in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space) and self._selected_name:
            self.module_requested.emit(self._selected_name)
        elif self._modules and key in (Qt.Key_Left, Qt.Key_Up, Qt.Key_Right, Qt.Key_Down,
                                      Qt.Key_Home, Qt.Key_End):
            names = [module.name for module in self._modules]
            index = names.index(self._selected_name) if self._selected_name in names else 0
            if key == Qt.Key_Home:
                index = 0
            elif key == Qt.Key_End:
                index = len(names) - 1
            else:
                index = (index + (-1 if key in (Qt.Key_Left, Qt.Key_Up) else 1)) % len(names)
            self._selected_name = names[index]
            self._hover_name = ""
            self._update_accessibility()
            self.update()
        else:
            super().keyPressEvent(event)
            return
        event.accept()

    def _text(self, painter, rect, text, size=12, color="#b8c9df", bold=False, align=Qt.AlignLeft):
        font = QFont(self.font())
        base = font.pixelSize() if font.pixelSize() > 0 else self.fontMetrics().height() * 0.8
        font.setPixelSize(max(10, round(size * base / 13)))
        font.setBold(bold)
        painter.setFont(font)
        painter.setPen(QColor(color))
        painter.drawText(rect, align | Qt.AlignVCenter,
                         painter.fontMetrics().elidedText(str(text), Qt.ElideRight, max(0, int(rect.width()))))

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        backdrop = QLinearGradient(0, 0, self.width(), self.height())
        backdrop.setColorAt(0, QColor("#07101e"))
        backdrop.setColorAt(0.6, QColor("#0b1326"))
        backdrop.setColorAt(1, QColor("#160e24"))
        painter.fillRect(self.rect(), backdrop)
        # Fixed decorative stars: no randomness, state churn or animation loop.
        painter.setPen(Qt.NoPen)
        for index in range(36):
            painter.setBrush(QColor(142, 173, 211, 30 + index % 4 * 10))
            painter.drawEllipse(QPointF((index * 193 + 29) % max(1, self.width()),
                                        (index * 97 + 71) % max(1, self.height())), 1, 1)
        self._text(painter, QRectF(20, 17, max(0, self.width() - 175), 23),
                   "ORBITAL DEFENSE", 16, "#d8eafe", True)
        running = sum(module.status == "running" for module in self._modules)
        attention = sum(module.status == "error" or (module.status == "running" and
                        (module.health is None or module.health < 90)) for module in self._modules)
        self._text(painter, QRectF(20, 42, max(0, self.width() - 175), 18),
                   f"{running}/{len(self._modules)} running  ·  {attention} need attention", 11, "#8ba4c1")
        self._paint_button(painter, self._alerts_button, "OPEN ALERTS")
        self._paint_orbits(painter)
        self._paint_detail(painter)
        if self.hasFocus():
            painter.setPen(QPen(QColor("#7dd3fc"), 1))
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(QRectF(self.rect()).adjusted(1, 1, -1, -1), 10, 10)

    def _paint_button(self, painter, rect, text):
        painter.setBrush(QColor("#122339"))
        painter.setPen(QPen(QColor("#2b526c"), 1))
        painter.drawRoundedRect(rect, 7, 7)
        self._text(painter, rect.adjusted(6, 0, -6, 0), text, 11, "#b8e7fb", True, Qt.AlignCenter)

    def _paint_orbits(self, painter):
        center = self._plot.center()
        radii = sorted({round(math.hypot(point.x() - center.x(), point.y() - center.y()), 1)
                        for point in self._nodes.values()})
        painter.setBrush(Qt.NoBrush)
        for radius in radii:
            painter.setPen(QPen(QColor("#263a58"), 1))
            painter.drawEllipse(center, radius, radius)
        selected = self._hover_name or self._selected_name
        for module in self._modules:
            point = self._nodes.get(module.name)
            if point is None:
                continue
            color = QColor(_COLORS.get(module.state, _COLORS["unknown"]))
            if module.status not in ("running", "error"):
                color = QColor(_COLORS["off"])
            radius = 5.0 if module.status == "running" else 4.0
            if module.name == selected:
                painter.setPen(QPen(QColor("#caedff"), 1.5))
                painter.setBrush(QColor(125, 211, 252, 25))
                painter.drawEllipse(point, 10, 10)
            if module.state in ("critical", "failed") and module.status in ("running", "error"):
                painter.setPen(QPen(color, 1))
                painter.setBrush(Qt.NoBrush)
                painter.drawEllipse(point, 8, 8)
            painter.setPen(Qt.NoPen)
            painter.setBrush(color)
            painter.drawEllipse(point, radius, radius)
        score, label, raw_color = self._posture
        color = QColor(raw_color)
        glow = QRadialGradient(center, self._core.width() * 0.85)
        glow.setColorAt(0, QColor(80, 155, 218, 75))
        glow.setColorAt(1, QColor(30, 67, 110, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(center, self._core.width() * 0.85, self._core.width() * 0.85)
        painter.setBrush(QColor("#0e1d31"))
        painter.setPen(QPen(color, 1.6))
        painter.drawEllipse(self._core)
        core = self._core
        self._text(painter, QRectF(core.x() + 8, center.y() - 24, core.width() - 16, 17),
                   "POSTURE", 10, "#a8bfd8", True, Qt.AlignCenter)
        self._text(painter, QRectF(core.x() + 5, center.y() - 9, core.width() - 10, 34),
                   "—" if score is None else f"{score:g}", 28, raw_color, True, Qt.AlignCenter)
        self._text(painter, QRectF(core.x() + 4, center.y() + 25, core.width() - 8, 16),
                   label if score is not None else "Pending", 10, "#a8bfd8", False, Qt.AlignCenter)
        if not self._modules:
            self._text(painter, QRectF(self._plot.x(), self._plot.bottom() - 26, self._plot.width(), 22),
                       "Waiting for module inventory", 12, "#8ba4c1", False, Qt.AlignCenter)

    def _paint_detail(self, painter):
        panel = self._detail
        painter.setPen(QPen(QColor("#24354e"), 1))
        painter.setBrush(QColor(10, 20, 36, 215))
        painter.drawRoundedRect(panel, 12, 12)
        area = panel.adjusted(14, 10, -14, -10)
        module = self._selected()
        self._text(painter, QRectF(area.x(), area.y(), area.width(), 17),
                   "SELECTED MODULE", 10, "#7895b8", True)
        self._text(painter, QRectF(area.x(), area.y() + 21, area.width(), 24),
                   module.name if module else "No module selected", 14, "#e0edff", True)
        if module:
            health = "unknown" if module.health is None else f"{module.health}%"
            self._text(painter, QRectF(area.x(), area.y() + 47, area.width(), 20),
                       f"{module.code}  ·  {module.status}  ·  health {health}", 12,
                       _COLORS.get(module.state, "#8494aa"))
            if panel.height() > 230:
                note = module.note or "No additional health note."
                self._text(painter, QRectF(area.x(), area.y() + 76, area.width(), 20), note, 11)
        if panel.height() > 285:
            cpu, ram, down, up = self._sample
            metrics_y = area.y() + 118
            cpu_text = "—" if cpu is None else f"{cpu:.0f}%"
            ram_text = "—" if ram is None else f"{ram:.0f}%"
            self._text(painter, QRectF(area.x(), metrics_y, area.width(), 22),
                       f"CPU {cpu_text}     RAM {ram_text}", 12, "#c5daee", True)
            self._text(painter, QRectF(area.x(), metrics_y + 26, area.width(), 22),
                       f"↓ {_rate(down)}     ↑ {_rate(up)}", 12, "#67dbe6")
            self._paint_network(painter, QRectF(area.x(), metrics_y + 60, area.width(),
                                                max(20, min(65, panel.height() - 255))))
        self._paint_button(painter, self._module_button, "OPEN MODULE DETAILS  ↗")

    def _paint_network(self, painter, rect):
        history = tuple(self._network_history)
        painter.setPen(QPen(QColor("#253950"), 1))
        painter.drawLine(rect.bottomLeft(), rect.bottomRight())
        if len(history) < 2:
            self._text(painter, rect, "Waiting for network samples", 10, "#7895b8")
            return
        peak = max(1.0, max(max(pair) for pair in history))
        for lane, color in ((0, "#67dbe6"), (1, "#bd9df2")):
            path = QPainterPath()
            for index, pair in enumerate(history):
                point = QPointF(rect.x() + rect.width() * index / (len(history) - 1),
                                rect.bottom() - rect.height() * pair[lane] / peak)
                if index:
                    path.lineTo(point)
                else:
                    path.moveTo(point)
            painter.setPen(QPen(QColor(color), 1.5))
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(path)
