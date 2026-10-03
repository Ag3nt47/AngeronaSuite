"""Persistent dashboard summary, fed only by existing GUI snapshots."""
from __future__ import annotations

import math

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
        self._rendered_accessibility = None
        self._rows = 1
        self.clicked.connect(self.details_requested.emit)
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
        summary = f"{self._sample_description} {self._posture_description}"
        if summary != self._rendered_accessibility:
            self._rendered_accessibility = summary
            self.setAccessibleName(f"System pulse. {summary}")
            self.setAccessibleDescription("Open system pulse details. Press Enter or Space.")
            self.setToolTip(f"{summary}\nOpen system pulse details.")
        self._fit_rows()
        self.updateGeometry()
        self.update()

    def _preferred_widths(self) -> tuple[int, ...]:
        metrics = self.fontMetrics()
        return tuple(metrics.horizontalAdvance(text) + 16
                     for text in (*self._metrics, self._posture))

    def _fit_rows(self) -> None:
        self._rows = 2 if self.width() < sum(self._preferred_widths()) + 8 else 1
        height = self.fontMetrics().height() * self._rows + 12
        if self.minimumHeight() != height or self.maximumHeight() != height:
            self.setFixedHeight(height)

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt signature
        if not hasattr(self, "_metrics"):
            return QSize(480, 28)
        return QSize(sum(self._preferred_widths()) + 8,
                     self.fontMetrics().height() * self._rows + 12)

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
        area = self.contentsRect().adjusted(4, 6, -4, -6)
        font_metrics = self.fontMetrics()
        preferred = self._preferred_widths()
        columns = 2 if self._rows == 2 else 4
        x = area.x()
        for index, text in enumerate((*self._metrics, self._posture)):
            row, column = divmod(index, columns)
            if self._rows == 2:
                width = area.width() // 2
                x = area.x() + column * width
            elif index < 2:
                width = preferred[index]
            else:
                width = max(0, (area.width() - preferred[0] - preferred[1]) // 2)
            rect = QRect(x, area.y() + row * font_metrics.height(),
                         max(0, width - 8), font_metrics.height())
            painter.setPen(self._posture_color if index == 3 and self._posture_color.isValid()
                           else self.palette().color(QPalette.WindowText))
            painter.drawText(rect, Qt.AlignLeft | Qt.AlignVCenter,
                             font_metrics.elidedText(text, Qt.ElideRight, rect.width()))
            if self._rows == 1:
                x += width
        if self.hasFocus():
            option = QStyleOptionFocusRect()
            option.initFrom(self)
            option.rect = self.rect().adjusted(1, 1, -1, -1)
            self.style().drawPrimitive(QStyle.PE_FrameFocusRect, option, painter, self)
