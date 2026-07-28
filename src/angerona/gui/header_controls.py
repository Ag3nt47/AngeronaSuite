"""Polished header controls and low-cost panel reveal animation.

The header intentionally uses vector icons drawn by Qt instead of emoji.  That
keeps every icon crisp, unique, theme-independent, and consistent on Windows
systems whose colour-emoji fonts differ.
"""
from __future__ import annotations

import ctypes
import os
import sys
from functools import lru_cache
from html import escape
from typing import Callable

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPoint,
    QPointF,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
)
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import QPushButton, QToolTip, QWidget


_ICON_COLORS = {
    "selftest": "#5eead4",
    "simulation": "#fb7185",
    "eco": "#4ade80",
    "world": "#38bdf8",
    "attack": "#fb923c",
    "intel": "#60a5fa",
    "forensics": "#c084fc",
    "console": "#2dd4bf",
    "setup": "#f472b6",
    "help": "#facc15",
    "settings": "#cbd5e1",
    "stop": "#ffffff",
}


def _icon_pixmap(kind: str, color: str, size: int = 22) -> QPixmap:
    """Draw one small, high-DPI vector icon."""
    px = QPixmap(size * 2, size * 2)
    px.setDevicePixelRatio(2.0)
    px.fill(Qt.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.Antialiasing)
    c = QColor(color)
    pen = QPen(c, 1.75)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    s = float(size)
    cx, cy = s / 2.0, s / 2.0

    if kind == "selftest":
        p.drawEllipse(QRectF(3.0, 3.0, s - 6.0, s - 6.0))
        p.drawLine(QPointF(7.0, 11.5), QPointF(10.0, 14.5))
        p.drawLine(QPointF(10.0, 14.5), QPointF(16.0, 8.0))
    elif kind == "simulation":
        p.drawEllipse(QRectF(3.0, 3.0, s - 6.0, s - 6.0))
        p.drawEllipse(QRectF(7.0, 7.0, s - 14.0, s - 14.0))
        p.drawLine(QPointF(cx, 1.5), QPointF(cx, 6.0))
        p.drawLine(QPointF(cx, s - 1.5), QPointF(cx, s - 6.0))
        p.drawLine(QPointF(1.5, cy), QPointF(6.0, cy))
        p.drawLine(QPointF(s - 1.5, cy), QPointF(s - 6.0, cy))
    elif kind == "eco":
        leaf = QPainterPath()
        leaf.moveTo(4.0, 17.5)
        leaf.cubicTo(4.5, 7.0, 11.0, 3.0, 18.5, 3.5)
        leaf.cubicTo(18.0, 12.0, 13.0, 18.0, 4.0, 17.5)
        p.drawPath(leaf)
        p.drawLine(QPointF(5.0, 17.0), QPointF(15.5, 7.0))
    elif kind == "world":
        p.drawEllipse(QRectF(2.5, 2.5, s - 5.0, s - 5.0))
        p.drawEllipse(QRectF(7.0, 2.5, s - 14.0, s - 5.0))
        p.drawLine(QPointF(3.5, 8.0), QPointF(s - 3.5, 8.0))
        p.drawLine(QPointF(3.5, 14.0), QPointF(s - 3.5, 14.0))
    elif kind == "attack":
        path = QPainterPath()
        path.moveTo(11.0, 2.5)
        path.cubicTo(14.5, 6.5, 17.8, 8.0, 17.0, 13.0)
        path.cubicTo(16.5, 17.2, 13.8, 19.5, 10.5, 19.5)
        path.cubicTo(6.5, 19.5, 4.5, 16.5, 5.0, 13.5)
        path.cubicTo(5.5, 10.5, 8.2, 9.0, 8.0, 5.0)
        path.cubicTo(9.5, 5.8, 10.4, 7.0, 11.2, 8.5)
        path.cubicTo(12.5, 6.0, 12.0, 4.2, 11.0, 2.5)
        p.drawPath(path)
    elif kind == "intel":
        shield = QPainterPath()
        shield.moveTo(cx, 2.5)
        shield.lineTo(18.0, 5.0)
        shield.lineTo(17.0, 13.0)
        shield.cubicTo(16.5, 16.5, 13.5, 19.0, cx, 20.0)
        shield.cubicTo(8.5, 19.0, 5.5, 16.5, 5.0, 13.0)
        shield.lineTo(4.0, 5.0)
        shield.closeSubpath()
        p.drawPath(shield)
        p.drawLine(QPointF(8.0, 11.0), QPointF(10.2, 13.2))
        p.drawLine(QPointF(10.2, 13.2), QPointF(14.5, 8.7))
    elif kind == "forensics":
        p.drawEllipse(QRectF(3.0, 3.0, 11.5, 11.5))
        p.drawLine(QPointF(13.0, 13.0), QPointF(19.0, 19.0))
        p.drawLine(QPointF(6.0, 8.0), QPointF(11.5, 8.0))
        p.drawLine(QPointF(8.75, 5.25), QPointF(8.75, 10.75))
    elif kind == "console":
        p.drawRoundedRect(QRectF(2.5, 4.0, s - 5.0, s - 8.0), 2.0, 2.0)
        p.drawLine(QPointF(6.0, 8.0), QPointF(9.0, 11.0))
        p.drawLine(QPointF(9.0, 11.0), QPointF(6.0, 14.0))
        p.drawLine(QPointF(11.5, 14.0), QPointF(16.0, 14.0))
    elif kind == "setup":
        p.drawLine(QPointF(5.0, 17.0), QPointF(16.5, 5.5))
        p.drawEllipse(QRectF(13.0, 2.0, 6.5, 6.5))
        p.drawLine(QPointF(4.0, 5.0), QPointF(4.0, 9.0))
        p.drawLine(QPointF(2.0, 7.0), QPointF(6.0, 7.0))
        p.drawLine(QPointF(14.0, 15.0), QPointF(14.0, 19.0))
        p.drawLine(QPointF(12.0, 17.0), QPointF(16.0, 17.0))
    elif kind == "help":
        p.drawEllipse(QRectF(3.0, 3.0, s - 6.0, s - 6.0))
        q = QPainterPath()
        q.moveTo(8.0, 8.2)
        q.cubicTo(8.8, 5.7, 14.8, 5.6, 14.8, 9.0)
        q.cubicTo(14.8, 11.6, 11.0, 11.3, 11.0, 14.0)
        p.drawPath(q)
        p.drawPoint(QPointF(11.0, 17.0))
    elif kind == "settings":
        p.drawEllipse(QRectF(8.0, 8.0, 6.0, 6.0))
        for i in range(8):
            import math
            angle = math.radians(i * 45.0)
            inner = QPointF(cx + 6.0 * math.cos(angle), cy + 6.0 * math.sin(angle))
            outer = QPointF(cx + 9.0 * math.cos(angle), cy + 9.0 * math.sin(angle))
            p.drawLine(inner, outer)
        p.drawEllipse(QRectF(4.5, 4.5, 13.0, 13.0))
    elif kind == "stop":
        p.setBrush(c)
        p.drawRoundedRect(QRectF(5.0, 5.0, s - 10.0, s - 10.0), 1.5, 1.5)
    else:
        p.drawEllipse(QRectF(4.0, 4.0, s - 8.0, s - 8.0))

    p.end()
    return px


@lru_cache(maxsize=64)
def navigation_icon(kind: str, color: str | None = None, size: int = 22) -> QIcon:
    """Return a cached vector icon for a named header destination."""
    tone = color or _ICON_COLORS.get(kind, "#e2e8f0")
    return QIcon(_icon_pixmap(kind, tone, size))


class HeaderActionButton(QPushButton):
    """Header button with a unique icon and an immediate definition card."""

    def __init__(
        self,
        label: str,
        icon_kind: str,
        title: str,
        definition: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(label, parent)
        self._hover_title = str(title)
        self._hover_definition = str(definition)
        self.setIcon(navigation_icon(icon_kind))
        self.setIconSize(QSize(20, 20))
        self.setCursor(Qt.PointingHandCursor)
        self.setAccessibleName(self._hover_title)
        self.setAccessibleDescription(self._hover_definition)
        self.setToolTip(
            "<div style='max-width:360px'>"
            f"<b style='font-size:13px'>{escape(self._hover_title)}</b><br>"
            f"<span>{escape(self._hover_definition)}</span>"
            "</div>"
        )

    def enterEvent(self, event) -> None:  # noqa: N802 - Qt signature
        QToolTip.showText(
            self.mapToGlobal(QPoint(self.width() // 2, self.height() + 6)),
            self.toolTip(),
            self,
        )
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: N802 - Qt signature
        QToolTip.hideText()
        super().leaveEvent(event)

    def focusInEvent(self, event) -> None:  # noqa: N802 - Qt signature
        QToolTip.showText(
            self.mapToGlobal(QPoint(self.width() // 2, self.height() + 6)),
            self.toolTip(),
            self,
        )
        super().focusInEvent(event)


def _windows_client_animations_enabled() -> bool:
    """Honor the Windows accessibility preference when it is available."""
    if sys.platform != "win32":
        return True
    try:
        # SPI_GETCLIENTAREAANIMATION
        enabled = ctypes.c_int(1)
        ok = ctypes.windll.user32.SystemParametersInfoW(
            0x1042, 0, ctypes.byref(enabled), 0
        )
        return bool(enabled.value) if ok else True
    except Exception:
        return True


def motion_allowed(config=None) -> bool:
    """Central motion gate used by the reveal animation."""
    if str(os.environ.get("ANGERONA_REDUCE_MOTION", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return False
    if config is not None and not bool(getattr(config, "ui_motion_enabled", True)):
        return False
    return _windows_client_animations_enabled()


class PanelRevealOverlay(QWidget):
    """A vertical accent line that grows into a translucent panel outline."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._progress = 0.0
        self._origin = QPointF()
        self._color = QColor("#38bdf8")
        self._after: Callable[[], None] | None = None
        self._animation = QPropertyAnimation(self, b"revealProgress", self)
        self._animation.setDuration(280)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self._animation.finished.connect(self._finish)
        self.hide()

    def reveal(
        self,
        source: QWidget,
        after: Callable[[], None],
        color: str | QColor | None = None,
    ) -> bool:
        """Play one reveal. Returns False when an animation is already active."""
        if self._animation.state() == QPropertyAnimation.Running:
            return False
        self.setGeometry(self.parentWidget().rect())
        source_center = source.mapToGlobal(source.rect().center())
        self._origin = QPointF(self.mapFromGlobal(source_center))
        self._color = QColor(color or "#38bdf8")
        self._after = after
        self._progress = 0.0
        self.show()
        self.raise_()
        self._animation.stop()
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(1.0)
        self._animation.start()
        return True

    def get_reveal_progress(self) -> float:
        return self._progress

    def set_reveal_progress(self, value: float) -> None:
        self._progress = max(0.0, min(1.0, float(value)))
        self.update()

    revealProgress = Property(
        float,
        get_reveal_progress,
        set_reveal_progress,
    )

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt signature
        if self._progress <= 0.0:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        margin_x = max(28.0, self.width() * 0.08)
        margin_y = max(24.0, self.height() * 0.08)
        target = QRectF(
            margin_x,
            margin_y,
            max(10.0, self.width() - margin_x * 2.0),
            max(10.0, self.height() - margin_y * 2.0),
        )

        # First grow a clean vertical line, then widen it into the panel.
        vertical = min(1.0, self._progress / 0.34)
        horizontal = max(0.0, min(1.0, (self._progress - 0.16) / 0.84))
        center_x = self._origin.x() + (target.center().x() - self._origin.x()) * horizontal
        center_y = self._origin.y() + (target.center().y() - self._origin.y()) * vertical
        width = 3.0 + (target.width() - 3.0) * horizontal
        height = 28.0 + (target.height() - 28.0) * vertical
        rect = QRectF(center_x - width / 2.0, center_y - height / 2.0, width, height)

        edge = QColor(self._color)
        edge.setAlpha(int(235 * (1.0 - max(0.0, self._progress - 0.82) / 0.18)))
        fill = QColor(self._color)
        fill.setAlpha(int(34 * horizontal))
        p.setBrush(fill)
        p.setPen(QPen(edge, 2.2))
        p.drawRoundedRect(rect, 10.0 * horizontal, 10.0 * horizontal)

        if horizontal < 0.12:
            glow = QColor(self._color)
            glow.setAlpha(70)
            p.setPen(QPen(glow, 7.0))
            p.drawLine(
                QPointF(center_x, rect.top()),
                QPointF(center_x, rect.bottom()),
            )
        p.end()

    def _finish(self) -> None:
        callback, self._after = self._after, None
        self.hide()
        self._progress = 0.0
        if callback is not None:
            callback()

