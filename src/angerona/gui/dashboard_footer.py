"""Persistent dashboard summary, fed only by existing GUI snapshots."""
from __future__ import annotations

import math
import html

from PySide6.QtCore import QEvent, QRect, QSize, Qt, Signal, Slot
from PySide6.QtGui import QColor, QPainter, QPalette
from PySide6.QtWidgets import QAbstractButton, QSizePolicy, QStyle, QStyleOptionFocusRect


def _number(value, *, percentage: bool = False) -> float | None:
    try:
        value = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(value) or value < 0 or (percentage and value > 100):
        return None
    return value


def _rate(value: float | None) -> str:
    if value is None:
        return "—"
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if value < 1024 or unit == "GB/s":
            return f"{value:.0f} {unit}" if value >= 10 else f"{value:.1f} {unit}"
        value /= 1024
    return "—"


class DashboardFooter(QAbstractButton):
    """Compact, keyboard-accessible CPU/RAM/network/posture summary.

    This view never samples the host, reads files, or schedules refresh work.
    The main window forwards SystemPulseCard samples and posture dictionaries.
    Full text remains available to assistive technology when a cell is elided.
    """

    details_requested = Signal()
    heartbeat_painted = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("DashboardFooter")
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumWidth(0)
        self._metrics = ("CPU —", "RAM —", "↓ —   ↑ —")
        self._sample_description = "Host metrics have not been sampled yet."
        self._posture = "Posture —"
        self._posture_description = "Posture has not been evaluated yet."
        self._posture_color = QColor()
        self._response = "Auto —"
        self._response_description = "Automatic response status has not been checked yet."
        self._fps = "FPS —"
        self._fps_description = "Dashboard paint heartbeat has not been measured yet."
        self._pace = "Angerona pace 100%"
        self._pace_percent = 100.0
        self._heartbeat_requested = False
        self._rendered_accessibility = None
        self._rows = 1
        self.clicked.connect(self.details_requested.emit)
        self._sync_presentation()

    def heartbeat_rect(self) -> QRect:
        return QRect(3, max(0, (self.height() - 8) // 2), 8, 8)

    def request_heartbeat(self) -> None:
        """Invalidate only the small probe, leaving dashboard surfaces alone."""
        self._heartbeat_requested = True
        self.update(self.heartbeat_rect())

    @Slot(object)
    def update_responsiveness(self, sample) -> None:
        sample = sample if isinstance(sample, dict) else {}
        fps = _number(sample.get("fps"))
        percent = _number(sample.get("percent"), percentage=True)
        if not sample.get("active"):
            text = "FPS paused"
            state = "Measurement paused while the dashboard is hidden or minimized."
        elif not sample.get("ready") or fps is None or percent is None:
            text = "FPS measuring…"
            state = "Collecting the first second of visible paint deliveries."
        else:
            text = f"FPS {fps:.0f} ({percent:.0f}%)"
            lag = _number(sample.get("worst_lag_ms")) or 0.0
            state = f"Observed {fps:.1f} paints/s; worst scheduling/paint delay {lag:.0f} ms."
        pacing = sample.get("pacing") or {}
        multiplier = _number(pacing.get("multiplier")) or 1.0
        pace_percent = max(0.0, min(100.0, 100.0 / max(1.0, multiplier)))
        pace = f"Angerona pace {pace_percent:.0f}%"
        if pacing.get("enabled"):
            pacing_text = (
                f"Adaptive routine-scan pacing: {pacing.get('level', 'normal')}; "
                f"interval multiplier {multiplier:g}×. {pacing.get('reason', '')}"
            )
        else:
            pacing_text = "Adaptive routine-scan pacing is off."
        description = (
            "FPS is a small Qt footer paint heartbeat, targeting 30 paints/s "
            "(100%); it is a responsiveness proxy, not GPU or display frame rate. "
            f"{state} {pacing_text} Angerona pace is the configured routine-work "
            "pacing budget (100 divided by the interval multiplier), with bounded "
            "per-task waits. It is not a CPU quota, measured throughput, or security "
            "coverage percentage; CPU usage is shown separately."
        )
        if (text, description, pace) == (self._fps, self._fps_description, self._pace):
            return
        self._fps, self._fps_description = text, description
        self._pace, self._pace_percent = pace, pace_percent
        self._sync_presentation()

    @Slot(object)
    def update_sample(self, data) -> None:
        if not isinstance(data, dict) or data.get("error"):
            metrics = ("CPU —", "RAM —", "↓ —   ↑ —")
            description = "Host metrics unavailable; waiting for the next sample."
        else:
            cpu = _number(data.get("cpu"), percentage=True)
            ram = _number(data.get("ram"), percentage=True)
            down = _number(data.get("down"))
            up = _number(data.get("up"))
            metrics = (
                "CPU —" if cpu is None else f"CPU {cpu:.0f}%",
                "RAM —" if ram is None else f"RAM {ram:.0f}%",
                f"↓ {_rate(down)}   ↑ {_rate(up)}",
            )
            description = (
                f"CPU: {'unavailable' if cpu is None else f'{cpu:g}%'}. "
                f"RAM: {'unavailable' if ram is None else f'{ram:g}%'}. "
                f"Network receive: {'unavailable' if down is None else f'{down:g} bytes/s'}. "
                f"Network send: {'unavailable' if up is None else f'{up:g} bytes/s'}."
            )
        if (metrics, description) == (self._metrics, self._sample_description):
            return
        self._metrics, self._sample_description = metrics, description
        self._sync_presentation()

    @Slot(object)
    def update_posture(self, snapshot) -> None:
        snapshot = snapshot if isinstance(snapshot, dict) else {}
        score = _number(snapshot.get("score"), percentage=True)
        label = " ".join(str(snapshot.get("label") or "Unknown").split())[:96]
        text = "Posture —" if score is None else f"Posture {score:g} · {label}"
        description = ("Posture unavailable." if score is None else
                       f"Posture score: {score:g}/100. State: {label}.")
        color = QColor(str(snapshot.get("color") or ""))
        if (text, description, color) == (
            self._posture, self._posture_description, self._posture_color,
        ):
            return
        self._posture, self._posture_description, self._posture_color = text, description, color
        self._sync_presentation()

    def _sync_presentation(self) -> None:
        summary = (f"{self._sample_description} {self._posture_description} "
                   f"{self._response_description} {self._fps_description}")
        if summary != self._rendered_accessibility:
            self._rendered_accessibility = summary
            self.setAccessibleName(f"System pulse. {summary}")
            self.setAccessibleDescription("Open system pulse details. Press Enter or Space.")
            self.setToolTip(f"<p>{html.escape(summary)}</p><p>Open system pulse details.</p>")
        self._fit_rows()
        self.updateGeometry()
        self.update()

    def _preferred_widths(self) -> tuple[int, ...]:
        metrics = self.fontMetrics()
        return tuple(metrics.horizontalAdvance(text) + 16
                     for text in self._display_cells())

    def _display_cells(self) -> tuple[str, ...]:
        return self._metrics[:2] + (
            self._fps, self._pace, self._metrics[2], f"{self._response} · {self._posture}",
        )

    @Slot(object)
    def update_response(self, snapshot) -> None:
        """Expose standing-response holds using the existing memory snapshot."""
        snapshot = snapshot if isinstance(snapshot, dict) else {}
        state = snapshot.get("state")
        if not isinstance(state, str):
            state = None
        if state == "ARMED" and snapshot.get("ready") is True:
            text = "Auto ARMED"
        elif state == "DISABLED":
            text = "Auto OFF"
        elif state == "STARTING":
            text = "Auto STARTING"
        elif state in {"RECOVERY REQUIRED", "JOURNAL FULL", "QUEUE FULL"}:
            text = "Auto HELD"
        else:
            text = "Auto UNAVAILABLE"
        reason = " ".join(str(snapshot.get("reason") or "Status unavailable.").split())[:500]
        description = (
            f"Automatic response: {text.removeprefix('Auto ')}. {reason} "
            "View effective rules and action history in Settings > Adversary Combat."
        )
        if (text, description) == (self._response, self._response_description):
            return
        self._response, self._response_description = text, description
        self._sync_presentation()

    def _row_height(self) -> int:
        return self.fontMetrics().height() + 5

    def _fit_rows(self) -> None:
        self._rows = 3 if self.width() < sum(self._preferred_widths()) + 20 else 1
        height = self._row_height() * self._rows + 12
        if self.minimumHeight() != height or self.maximumHeight() != height:
            self.setFixedHeight(height)

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt signature
        if not hasattr(self, "_metrics"):
            return QSize(480, 28)
        return QSize(sum(self._preferred_widths()) + 20,
                     self._row_height() * self._rows + 12)

    def minimumSizeHint(self) -> QSize:  # noqa: N802 - Qt signature
        return QSize(0, self.sizeHint().height())

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        super().resizeEvent(event)
        if hasattr(self, "_metrics"):
            self._fit_rows()

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        super().changeEvent(event)
        if (event.type() in (QEvent.FontChange, QEvent.StyleChange)
                and hasattr(self, "_metrics")):
            self._fit_rows()
            self.updateGeometry()

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt signature
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            self.click()
            event.accept()
            return
        super().keyPressEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt signature
        painter = QPainter(self)
        heartbeat = self.heartbeat_rect()
        completed = self._heartbeat_requested and event.region().intersects(heartbeat)
        if event.region().intersects(heartbeat):
            painter.setPen(Qt.NoPen)
            painter.setBrush(self.palette().color(QPalette.Mid))
            painter.drawEllipse(heartbeat.adjusted(2, 2, -2, -2))
        # A heartbeat normally costs only this tiny paint. Qt's clip region
        # excludes every other footer cell and all dashboard panels.
        if heartbeat.contains(event.rect()):
            painter.end()
            if completed:
                self._heartbeat_requested = False
                self.heartbeat_painted.emit()
            return
        area = self.contentsRect().adjusted(16, 6, -4, -6)
        font_metrics = self.fontMetrics()
        preferred = self._preferred_widths()
        x = area.x()
        for index, text in enumerate(self._display_cells()):
            row = 0
            if self._rows > 1:
                row, column = divmod(index, 2)
                width = area.width() // 2
                x = area.x() + column * width
            elif index < 4:
                width = preferred[index]
            else:
                width = max(0, (area.width() - sum(preferred[:4])) // 2)
            rect = QRect(x, area.y() + row * self._row_height(),
                         max(0, width - 8), font_metrics.height())
            painter.setPen(self._posture_color if index == 5 and self._posture_color.isValid()
                           else self.palette().color(QPalette.WindowText))
            painter.drawText(rect, Qt.AlignLeft | Qt.AlignVCenter,
                             font_metrics.elidedText(text, Qt.ElideRight, rect.width()))
            if index == 3:
                bar = QRect(rect.left(), rect.bottom() + 2, rect.width(), 3)
                painter.fillRect(bar, self.palette().color(QPalette.Mid))
                fill = QRect(bar)
                fill.setWidth(round(bar.width() * self._pace_percent / 100.0))
                painter.fillRect(fill, self.palette().color(QPalette.Highlight))
            if self._rows == 1:
                x += width
        if self.hasFocus():
            option = QStyleOptionFocusRect()
            option.initFrom(self)
            option.rect = self.rect().adjusted(1, 1, -1, -1)
            self.style().drawPrimitive(QStyle.PE_FrameFocusRect, option, painter, self)
        painter.end()
        if completed:
            self._heartbeat_requested = False
            self.heartbeat_painted.emit()
