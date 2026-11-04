"""Measured workflow completion, with cosmetic motion independent of work."""
from __future__ import annotations

import math

from PySide6.QtCore import QEvent, QRectF, Qt
from PySide6.QtGui import QColor, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import QWidget

from angerona.gui.presentation_timer import PresentationTimer


_C_RED = (255, 77, 77)
_C_YEL = (255, 176, 32)
_C_GRN = (47, 227, 138)


def _mix(a, b, t: float) -> QColor:
    t = max(0.0, min(1.0, t))
    return QColor(int(a[0] + (b[0] - a[0]) * t),
                  int(a[1] + (b[1] - a[1]) * t),
                  int(a[2] + (b[2] - a[2]) * t))


def color_for_pct(pct: float) -> QColor:
    """Red at zero, amber at halfway and green at measured completion."""
    p = max(0.0, min(100.0, float(pct))) / 100.0
    return (_mix(_C_RED, _C_YEL, p / 0.5) if p < 0.5 else
            _mix(_C_YEL, _C_GRN, (p - 0.5) / 0.5))


class ProgressRing(QWidget):
    """A centered count-derived percentage; unknown progress remains unknown.

    Rotation is cosmetic. It never advances a count or certifies a result.
    A running operation stays below 100 even when its producer has completed
    the measured units and is still settling. Consumers must present failures,
    cancellation and security outcomes separately from workflow completion.
    """

    def __init__(self, config=None, parent=None, *, diameter=68, scope="workflow"):
        super().__init__(parent)
        self.config = config
        self._diameter = max(26, min(256, int(diameter)))
        self._scope = str(scope or "workflow")[:80]
        self.percent = None
        self.busy = False
        self._angle = 0
        self._timer = PresentationTimer(
            self, pressure_sensitive=False, chill_sensitive=False, cosmetic=True)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._rotate)
        self._fit_font()
        self.set_state(None, None, False)

    @property
    def progress_color(self):
        return (color_for_pct(self.percent) if self.percent is not None
                else QColor("#38bdf8"))

    def set_diameter(self, diameter):
        """Use a compact fixed ring in a constrained action/header row."""
        self._diameter = max(26, min(256, int(diameter)))
        self._fit_font()
        self.update()

    def _fit_font(self):
        side = getattr(self, "_diameter", 68)
        if side >= 68:
            font = self.font()
            font.setBold(True)
            metrics = QFontMetrics(font)
            side = max(side, metrics.horizontalAdvance("100%") + 24,
                       metrics.height() + 24)
        if self.minimumWidth() != side or self.minimumHeight() != side:
            self.setFixedSize(side, side)

    def changeEvent(self, event):  # noqa: N802
        super().changeEvent(event)
        if event.type() in (QEvent.Type.FontChange, QEvent.Type.StyleChange):
            self._fit_font()

    def set_state(self, finished, total, busy):
        valid = (type(finished) is int and type(total) is int
                 and 0 < total <= 1_000_000 and 0 <= finished <= total)
        percent = min(99 if busy else 100, finished * 100 // total) if valid else None
        changed = (self.percent, self.busy) != (percent, bool(busy))
        self.percent, self.busy = percent, bool(busy)
        text = (f"{self.percent}% measured {self._scope}" if valid
                else f"{self._scope.capitalize()} progress count unavailable")
        if self.accessibleName() != text:
            self.setAccessibleName(text)
        tooltip = (text + ". Workflow completion does not establish successful "
                   "containment, files checked or protection coverage.")
        if self.toolTip() != tooltip:
            self.setToolTip(tooltip)
        if self.accessibleDescription() != tooltip:
            self.setAccessibleDescription(tooltip)
        self._sync_timer()
        if changed:
            self.update()

    def set_fraction(self, fraction, busy):
        if (type(fraction) not in (int, float) or not 0 <= fraction <= 1
                or not math.isfinite(fraction)):
            self.set_state(None, None, busy)
            return
        self.set_state(int(fraction * 1_000_000), 1_000_000, busy)

    def _sync_timer(self):
        from angerona.gui.header_controls import motion_allowed

        if self.busy and self.isVisible() and motion_allowed(self.config):
            self._timer.start()
        else:
            self._timer.stop()

    def _rotate(self):
        self._angle = (self._angle + 9) % 360
        self.update()

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        self._sync_timer()

    def hideEvent(self, event):  # noqa: N802
        self._timer.stop()
        super().hideEvent(event)

    def paintEvent(self, event):  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        small = min(self.width(), self.height()) < 48
        margin, stroke = (3, 2.4) if small else (5, 4)
        rect = QRectF(margin, margin, self.width() - 2 * margin,
                      self.height() - 2 * margin)
        painter.setPen(QPen(QColor("#334155"), stroke))
        painter.drawEllipse(rect)
        pen = QPen(self.progress_color, stroke)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        if self.busy:
            painter.drawArc(rect, -self._angle * 16, 100 * 16)
        elif self.percent is not None:
            painter.drawArc(rect, 90 * 16, -round(360 * self.percent / 100) * 16)
        painter.setPen(QColor("#f8fafc"))
        font = painter.font()
        font.setBold(True)
        if self._diameter < 68:
            # Compact header rings retain their reserved extent. Their full
            # percentage and scope are also available to accessibility/tooltip.
            font.setPixelSize(max(6, min(font.pixelSize() if font.pixelSize() > 0 else 16,
                                         round((self.width() - 12) / 2.6))))
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                         f"{self.percent}%" if self.percent is not None else "—")
