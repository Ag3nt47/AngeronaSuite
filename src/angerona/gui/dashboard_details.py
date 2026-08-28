"""Futuristic, bounded detail windows for dashboard surfaces.

These views reuse data already held by the dashboard. They do not add polling
to the security hot path and never perform response actions automatically.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Callable

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QGuiApplication, QLinearGradient, QPainter, QPen
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from angerona.gui.header_controls import motion_allowed


def _event_content_fingerprint(event: object) -> str:
    """Return a canonical identity for every field shown or drilled into."""
    severity = getattr(event, "severity", 0)
    try:
        severity_value: object = int(severity)
    except (TypeError, ValueError, OverflowError):
        severity_value = str(severity)
    record = {
        "details": getattr(event, "details", {}) or {},
        "hmac_sig": str(getattr(event, "hmac_sig", "")),
        "message": str(getattr(event, "message", "")),
        "module": str(getattr(event, "module", "")),
        "severity": severity_value,
        "ts": getattr(event, "ts", 0.0),
    }
    try:
        canonical = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
            default=str,
        )
    except (TypeError, ValueError, RecursionError):
        # Malformed third-party detail values must still trigger a refresh and
        # must never crash the presentation loop.
        record["details"] = repr(record["details"])[:128 * 1024]
        canonical = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _motion_for(widget: QWidget) -> bool:
    current: QWidget | None = widget
    while current is not None:
        config = getattr(current, "config", None)
        if config is not None:
            return motion_allowed(config)
        current = current.parentWidget()
    return motion_allowed()


class FuturisticHeader(QFrame):
    """Low-cost scanning header that lives inside the destination window."""

    def __init__(
        self,
        title: str,
        subtitle: str,
        accent: str = "#38bdf8",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._accent = QColor(accent)
        self._phase = 0.0
        self.setMinimumHeight(76)
        self.setObjectName("FuturisticHeader")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 11, 16, 12)
        layout.setSpacing(3)
        row = QHBoxLayout()
        title_label = QLabel(title)
        title_label.setTextFormat(Qt.PlainText)
        title_label.setObjectName("PageTitle")
        self.badge = QLabel("● LIVE DETAIL")
        self.badge.setTextFormat(Qt.PlainText)
        self.badge.setStyleSheet(
            f"color:{accent}; font-size:10px; font-weight:800; letter-spacing:1px;"
        )
        row.addWidget(title_label)
        row.addStretch(1)
        row.addWidget(self.badge)
        layout.addLayout(row)
        subtitle_label = QLabel(subtitle)
        subtitle_label.setTextFormat(Qt.PlainText)
        subtitle_label.setWordWrap(True)
        subtitle_label.setStyleSheet("color:#94a3b8; font-size:11px;")
        layout.addWidget(subtitle_label)

        self._timer = QTimer(self)
        self._timer.setInterval(45)
        self._timer.timeout.connect(self._tick)

    def _tick(self) -> None:
        self._phase = (self._phase + 0.018) % 1.0
        self.update()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt signature
        super().showEvent(event)
        if _motion_for(self) and not self._timer.isActive():
            self._timer.start()

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt signature
        self._timer.stop()
        super().hideEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt signature
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(self.rect()).adjusted(1.0, 1.0, -1.0, -1.0)
        bg = QLinearGradient(rect.topLeft(), rect.bottomRight())
        dark = QColor("#0a111c")
        accent_fill = QColor(self._accent)
        accent_fill.setAlpha(28)
        bg.setColorAt(0.0, dark)
        bg.setColorAt(0.55, QColor("#0d1624"))
        bg.setColorAt(1.0, accent_fill)
        painter.setBrush(bg)
        border = QColor(self._accent)
        border.setAlpha(105)
        painter.setPen(QPen(border, 1.2))
        painter.drawRoundedRect(rect, 10.0, 10.0)

        x = rect.left() + rect.width() * self._phase
        beam = QLinearGradient(QPointF(x - 34.0, 0.0), QPointF(x + 34.0, 0.0))
        transparent = QColor(self._accent)
        transparent.setAlpha(0)
        bright = QColor(self._accent)
        bright.setAlpha(180)
        beam.setColorAt(0.0, transparent)
        beam.setColorAt(0.5, bright)
        beam.setColorAt(1.0, transparent)
        painter.setPen(QPen(beam, 2.2))
        painter.drawLine(
            QPointF(max(rect.left(), x - 34.0), rect.bottom() - 2.0),
            QPointF(min(rect.right(), x + 34.0), rect.bottom() - 2.0),
        )
        painter.end()


class MetricTile(QFrame):
    def __init__(self, label: str, value: str = "--", color: str = "#38bdf8") -> None:
        super().__init__()
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)
        caption = QLabel(label.upper())
        caption.setStyleSheet("color:#64748b; font-size:9px; font-weight:800;")
        self.value = QLabel(value)
        self.value.setStyleSheet(f"color:{color}; font-size:20px; font-weight:800;")
        self._rendered_value = str(value)
        self._rendered_color = str(color)
        layout.addWidget(caption)
        layout.addWidget(self.value)

    def set_value(self, value: object, color: str | None = None) -> None:
        text = str(value)
        if text != self._rendered_value:
            self._rendered_value = text
            self.value.setText(text)
        if color and str(color) != self._rendered_color:
            self._rendered_color = str(color)
            self.value.setStyleSheet(
                f"color:{color}; font-size:20px; font-weight:800;"
            )


class FuturisticDetailDialog(QDialog):
    """Shared chrome for dashboard drill-down views."""

    def __init__(
        self,
        title: str,
        subtitle: str,
        accent: str = "#38bdf8",
        parent: QWidget | None = None,
        minimum_size: tuple[int, int] = (760, 520),
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.accent = accent
        self.setWindowTitle(title)
        self.setMinimumSize(*minimum_size)
        if parent is not None:
            self.setStyleSheet(parent.styleSheet())

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 12)
        root.setSpacing(10)
        self.header = FuturisticHeader(title, subtitle, accent, self)
        root.addWidget(self.header)

        self.metrics = QHBoxLayout()
        self.metrics.setSpacing(8)
        root.addLayout(self.metrics)

        self.content_host = QFrame()
        self.content_host.setObjectName("Panel")
        self.content = QVBoxLayout(self.content_host)
        self.content.setContentsMargins(12, 10, 12, 10)
        self.content.setSpacing(8)
        root.addWidget(self.content_host, 1)

        footer = QHBoxLayout()
        self.footer_status = QLabel("Bounded local detail view · no automatic action")
        self.footer_status.setStyleSheet("color:#64748b; font-size:10px;")
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        footer.addWidget(self.footer_status)
        footer.addStretch(1)
        footer.addWidget(close)
        root.addLayout(footer)

    def add_metric(
        self, label: str, value: str = "--", color: str | None = None
    ) -> MetricTile:
        tile = MetricTile(label, value, color or self.accent)
        self.metrics.addWidget(tile, 1)
        return tile

    def copy_table_cell(self, table: QTableWidget, row: int, column: int) -> None:
        """Copy one literal display value without opening or executing it."""
        item = table.item(row, column)
        if item is None:
            return
        text = str(item.text())[:16_384]
        QGuiApplication.clipboard().setText(text)
        self.footer_status.setText(f"Copied exact table value: {text[:160]}")


class PulseHistoryGraph(QWidget):
    """Small zero-allocation line graph over System Pulse's retained samples."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._samples: list[dict] = []
        self.setMinimumHeight(150)

    def set_samples(self, samples: list[dict]) -> None:
        self._samples = list(samples[-90:])
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt signature
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(self.rect()).adjusted(36.0, 10.0, -12.0, -24.0)
        painter.fillRect(self.rect(), QColor("#080d15"))
        painter.setPen(QPen(QColor("#1e293b"), 1.0))
        for step in range(0, 101, 25):
            y = rect.bottom() - rect.height() * step / 100.0
            painter.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
            painter.drawText(QPointF(4.0, y + 4.0), str(step))
        if len(self._samples) >= 2:
            series = (
                ("cpu", QColor("#38bdf8")),
                ("ram", QColor("#c084fc")),
                ("wifi", QColor("#22c55e")),
            )
            for key, color in series:
                points: list[QPointF] = []
                for index, sample in enumerate(self._samples):
                    raw = sample.get(key)
                    if raw is None:
                        continue
                    x = rect.left() + rect.width() * index / max(
                        1, len(self._samples) - 1
                    )
                    value = max(0.0, min(100.0, float(raw)))
                    y = rect.bottom() - rect.height() * value / 100.0
                    points.append(QPointF(x, y))
                painter.setPen(QPen(color, 2.0))
                for left, right in zip(points, points[1:]):
                    painter.drawLine(left, right)
        painter.setPen(QColor("#64748b"))
        painter.drawText(
            QRectF(36.0, self.height() - 22.0, self.width() - 48.0, 18.0),
            Qt.AlignLeft,
            "CPU   RAM   WI-FI · newest sample at right",
        )
        painter.end()


class SystemPulseDetailDialog(FuturisticDetailDialog):
    def __init__(self, pulse_card, parent: QWidget | None = None) -> None:
        super().__init__(
            "System Pulse · Host Telemetry",
            "Live resource pressure and network movement from the existing "
            "background sampler. No extra host scan is started by this view.",
            "#38bdf8",
            parent,
            (820, 600),
        )
        self._pulse = pulse_card
        self.cpu = self.add_metric("CPU")
        self.ram = self.add_metric("RAM", color="#c084fc")
        self.wifi = self.add_metric("Wi-Fi", color="#22c55e")
        self.available = self.add_metric("Available memory", color="#facc15")
        self.graph = PulseHistoryGraph()
        self.content.addWidget(self.graph, 1)
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Telemetry", "Current value"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.cellDoubleClicked.connect(
            lambda row, column: self.copy_table_cell(self.table, row, column)
        )
        self.content.addWidget(self.table)
        self._last_sample_revision: int | None = None
        self._pulse_rows: dict[str, QTableWidgetItem] = {}
        for row, name in enumerate(
            ("Network receive", "Network send", "Sampling state", "Retained samples")
        ):
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(name))
            value = QTableWidgetItem("--")
            self.table.setItem(row, 1, value)
            self._pulse_rows[name] = value
        self.table.setSortingEnabled(True)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(900)
        self._refresh()

    def _refresh(self) -> None:
        revision_fn = getattr(self._pulse, "sample_revision", None)
        busy_fn = getattr(self._pulse, "sample_busy", None)
        revision = int(revision_fn()) if callable(revision_fn) else None
        busy = bool(busy_fn()) if callable(busy_fn) else False
        self._pulse_rows["Sampling state"].setText("Busy" if busy else "Ready")
        if revision is not None and revision == self._last_sample_revision:
            return
        snapshot = self._pulse.snapshot()
        self._last_sample_revision = revision
        latest = snapshot.get("latest") or {}
        self.cpu.set_value(f"{float(latest.get('cpu', 0.0)):.0f}%")
        self.ram.set_value(f"{float(latest.get('ram', 0.0)):.0f}%")
        wifi = latest.get("wifi")
        self.wifi.set_value("Offline" if wifi is None else f"{int(wifi)}%")
        available = float(latest.get("available", 0.0)) / (1024.0 ** 3)
        self.available.set_value(f"{available:.1f} GB")
        self.graph.set_samples(snapshot.get("history") or [])
        self._pulse_rows["Network receive"].setText(
            _rate(float(latest.get("down", 0.0)))
        )
        self._pulse_rows["Network send"].setText(
            _rate(float(latest.get("up", 0.0)))
        )
        self._pulse_rows["Sampling state"].setText(
            "Busy" if snapshot.get("busy") else "Ready"
        )
        self._pulse_rows["Retained samples"].setText(
            str(len(snapshot.get("history") or []))
        )


class ConsoleDetailDialog(FuturisticDetailDialog):
    def __init__(self, console_panel, parent: QWidget | None = None) -> None:
        super().__init__(
            "ARIA Console · Operations Deck",
            "Expanded transcript, command entry, and bounded operational context. "
            "Commands use the same guarded backend as the dashboard prompt.",
            "#2dd4bf",
            parent,
            (900, 620),
        )
        self._console = console_panel
        self.lines = self.add_metric("Transcript lines")
        self.busy = self.add_metric("Active jobs", color="#facc15")
        self.mode = self.add_metric("Input mode", "ARIA + commands", "#c084fc")
        self.transcript = QPlainTextEdit()
        self.transcript.setReadOnly(True)
        self.content.addWidget(self.transcript, 1)
        command_row = QHBoxLayout()
        self.command = QLineEdit()
        self.command.setPlaceholderText(
            "Ask ARIA, or run a command such as help, ps, resources, incidents…"
        )
        run = QPushButton("Run in dashboard console")
        run.clicked.connect(self._run)
        self.command.returnPressed.connect(self._run)
        command_row.addWidget(self.command, 1)
        command_row.addWidget(run)
        self.content.addLayout(command_row)
        help_text = QLabel(
            "READ examples: help · modules · resources · incidents · coverage · "
            "threat. State-changing commands retain their normal confirmation and "
            "policy gates."
        )
        help_text.setWordWrap(True)
        help_text.setStyleSheet("color:#94a3b8;")
        self.content.addWidget(help_text)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._console_revision: int | None = None
        self._timer.start(650)
        self._refresh()

    def _run(self) -> None:
        text = self.command.text().strip()
        if not text:
            return
        self.command.clear()
        self._console.run_command(text)
        self.footer_status.setText(f"Sent to guarded console: {text[:80]}")
        QTimer.singleShot(120, self._refresh)

    def _refresh(self) -> None:
        document = self._console.out.document()
        revision = int(document.revision())
        if revision != self._console_revision:
            text = self._console.out.toPlainText()
            bounded = text[-80_000:]
            self.transcript.setPlainText(bounded)
            self.transcript.verticalScrollBar().setValue(
                self.transcript.verticalScrollBar().maximum()
            )
            self.lines.set_value(str(text.count("\n") + (1 if text else 0)))
            self._console_revision = revision
        self.busy.set_value(str(int(getattr(self._console, "_busy", 0))))


class AriaDetailDialog(FuturisticDetailDialog):
    def __init__(self, owner, parent: QWidget | None = None) -> None:
        super().__init__(
            "ARIA · Local Intelligence Core",
            "Live posture reasoning, conversational access, and authority boundaries. "
            "ARIA recommends; deterministic policy and operator confirmation govern actions.",
            "#c084fc",
            parent,
            (850, 600),
        )
        self._owner = owner
        self.score = self.add_metric("Angerona score")
        self.alerts = self.add_metric("Active threats", color="#fb7185")
        self.voice = self.add_metric("Voice", color="#38bdf8")
        self.mode = self.add_metric("Inference", "Local-first", "#22c55e")

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("font-size:14px; font-weight:700;")
        self.content.addWidget(self.status)
        self.spark = QLabel("")
        self.spark.setStyleSheet(
            "font-family:'Fira Code',Consolas; color:#7dd3fc; font-size:16px;"
        )
        self.content.addWidget(self.spark)
        boundaries = QPlainTextEdit()
        boundaries.setReadOnly(True)
        boundaries.setPlainText(
            "ARIA CONTROL BOUNDARY\n\n"
            "• Reads live posture, modules, alerts, resources, incidents, coverage, "
            "connections, and threat intelligence.\n"
            "• Free-form analysis is local-first. Optional cloud paths remain "
            "separately consented and redacted.\n"
            "• Write operations are staged as immutable, expiring previews.\n"
            "• The model never receives approval authority, event-bus keys, or a "
            "generic execution channel.\n"
            "• Destructive actions still require deterministic policy checks and "
            "the normal operator confirmation path."
        )
        self.content.addWidget(boundaries, 1)
        prompt_row = QHBoxLayout()
        self.prompt = QLineEdit()
        self.prompt.setPlaceholderText("Ask ARIA through the dashboard console…")
        ask = QPushButton("Ask ARIA")
        ask.clicked.connect(self._ask)
        self.prompt.returnPressed.connect(self._ask)
        voice = QPushButton("Voice & microphone settings")
        voice.clicked.connect(lambda: self._open_from(voice, owner._open_voice_settings))
        prompt_row.addWidget(self.prompt, 1)
        prompt_row.addWidget(ask)
        prompt_row.addWidget(voice)
        self.content.addLayout(prompt_row)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(1000)
        self._refresh()

    def _open_from(self, source: QWidget, callback: Callable[[], object]) -> None:
        opener = getattr(self._owner, "_reveal_window_from", None)
        if callable(opener):
            opener(source, callback, "#38bdf8")
        else:
            callback()

    def _ask(self) -> None:
        text = self.prompt.text().strip()
        if not text:
            return
        self.prompt.clear()
        self._owner.console.run_command(text)
        self.footer_status.setText("Question sent to the live ARIA console")

    def _refresh(self) -> None:
        posture = getattr(self._owner, "_last_posture", {}) or {}
        factors = posture.get("factors", {}) or {}
        score = int(posture.get("score", 100))
        self.score.set_value(str(score))
        self.alerts.set_value(str(int(factors.get("active_threats", 0))))
        enabled = bool(getattr(self._owner.config, "aria_voice_enabled", False))
        self.voice.set_value("ON" if enabled else "OFF")
        hud = getattr(self._owner, "aria_hud", None)
        status = getattr(hud, "_status", None)
        spark = getattr(hud, "_spark", None)
        self.status.setText(
            status.text() if status is not None else "ARIA status unavailable"
        )
        self.spark.setText(spark.text() if spark is not None else "")


class ModuleResourceDialog(FuturisticDetailDialog):
    def __init__(
        self,
        module_name: str,
        snapshot_fn: Callable[[str], dict],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(
            f"{module_name} · Resource Telemetry",
            "Heuristic module intensity plus bounded recent activity. Python modules "
            "share one process, so this is scheduling/activity pressure—not per-thread RSS.",
            "#fb923c",
            parent,
            (820, 560),
        )
        self._name = module_name
        self._snapshot_fn = snapshot_fn
        self.intensity = self.add_metric("Intensity", color="#fb923c")
        self.health = self.add_metric("Health", color="#22c55e")
        self.status = self.add_metric("Status")
        self.events = self.add_metric("Recent events", color="#c084fc")
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Time", "Severity", "Message"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.cellDoubleClicked.connect(self._open_event_detail)
        self.content.addWidget(self.table, 1)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._events_fingerprint: tuple | None = None
        self._timer.start(1300)
        self._refresh()

    def _refresh(self) -> None:
        snapshot = self._snapshot_fn(self._name)
        self.intensity.set_value(f"{int(snapshot.get('intensity', 0))}%")
        self.health.set_value(f"{int(snapshot.get('health', 0))}%")
        self.status.set_value(str(snapshot.get("status", "unknown")))
        events = snapshot.get("events") or []
        self.events.set_value(str(len(events)))
        fingerprint = tuple(_event_content_fingerprint(event) for event in events)
        if fingerprint == self._events_fingerprint:
            return
        self._events_fingerprint = fingerprint
        header = self.table.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(events))
        for row, event in enumerate(events):
            time_item = QTableWidgetItem(
                time.strftime(
                    "%H:%M:%S",
                    time.localtime(float(getattr(event, "ts", time.time()))),
                )
            )
            time_item.setData(Qt.UserRole, event)
            self.table.setItem(
                row,
                0,
                time_item,
            )
            severity = getattr(getattr(event, "severity", None), "label", "")
            self.table.setItem(row, 1, QTableWidgetItem(str(severity)))
            self.table.setItem(
                row, 2, QTableWidgetItem(str(getattr(event, "message", "")))
            )
        self.table.setSortingEnabled(True)
        if sort_column >= 0:
            self.table.sortItems(sort_column, sort_order)

    def _open_event_detail(self, row: int, _column: int) -> None:
        item = self.table.item(row, 0)
        event = item.data(Qt.UserRole) if item is not None else None
        if event is None:
            return
        from angerona.gui.pages import AlertDetailDialog, _show_nonmodal

        _show_nonmodal(AlertDetailDialog(event, self))


def _rate(value: float) -> str:
    value = max(0.0, float(value))
    for suffix in ("B/s", "KB/s", "MB/s", "GB/s"):
        if value < 1024.0 or suffix == "GB/s":
            return f"{value:.0f} {suffix}" if value >= 10 else f"{value:.1f} {suffix}"
        value /= 1024.0
    return "0 B/s"
