"""Dynamic threat animation overlay.

On a confirmed threat, a stylized shark sweeps across the window (mouth open)
over a red flash that fades — an unmistakable visual alarm. The same overlay
can run a different colour/glyph for other events (e.g. a scan sweep).
"""
from __future__ import annotations

from PySide6.QtCore import QPoint, QPropertyAnimation, Qt, QTimer
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QLabel, QWidget


class ThreatOverlay(QWidget):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._glyph = QLabel("\U0001F988", self)  # 🦈
        self._glyph.setStyleSheet("font-size:96px;")
        self._glyph.adjustSize()
        self._anim = QPropertyAnimation(self._glyph, b"pos", self)
        self._anim.finished.connect(self._maybe_hide)
        self._flash = 0.0
        self._color = QColor(255, 40, 40)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._fade)
        self.hide()

    def trigger(self, glyph: str = "\U0001F988", color=(255, 40, 40)) -> None:
        p = self.parentWidget()
        if p is None:
            return
        self.setGeometry(p.rect())
        self._color = QColor(*color)
        self._glyph.setText(glyph)
        self._glyph.adjustSize()
        y = self.height() // 2 - self._glyph.height() // 2
        start = QPoint(-self._glyph.width() - 40, y)
        end = QPoint(self.width() + 40, y)
        self._glyph.move(start)
        self.show()
        self.raise_()
        self._anim.stop()
        self._anim.setDuration(1500)
        self._anim.setStartValue(start)
        self._anim.setEndValue(end)
        self._anim.start()
        self._flash = 1.0
        self._timer.start(40)

    def _fade(self) -> None:
        self._flash = max(0.0, self._flash - 0.04)
        if self._flash <= 0:
            self._timer.stop()
            self._maybe_hide()
        self.update()

    def _maybe_hide(self) -> None:
        from PySide6.QtCore import QAbstractAnimation
        if self._flash <= 0 and self._anim.state() != QAbstractAnimation.Running:
            self.hide()

    def paintEvent(self, event) -> None:
        if self._flash <= 0:
            return
        painter = QPainter(self)
        c = QColor(self._color)
        c.setAlpha(int(self._flash * 110))
        painter.fillRect(self.rect(), c)


class SharkSwimIndicator(QWidget):
    """Small looping SWIM animation next to the "Initiate Shark Attack" button.

    A hand-drawn VECTOR shark (deliberately not the 🦈 emoji — colour-emoji
    glyphs don't render through a rotated/scaled QPainter, which is why the
    previous version only showed the bubbles). It swims across the strip, bobs,
    undulates its body, flicks its tail, turns to face its swim direction, and
    leaves a small bubble wake. Purely cosmetic — signals a drill is running."""

    _BODY_LEN = 26.0   # nose-to-tail span in px (used for edge margins)

    def __init__(self, parent: QWidget | None = None, width: int = 160, height: int = 34) -> None:
        super().__init__(parent)
        self.setFixedSize(width, height)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._x = self._BODY_LEN
        self._dir = 1
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.hide()

    def start(self) -> None:
        self._x = self._BODY_LEN
        self._dir = 1
        self._phase = 0.0
        self.show()
        self._timer.start(33)   # ~30 fps for a smooth swim

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def _tick(self) -> None:
        margin = self._BODY_LEN
        max_x = max(margin, self.width() - margin)
        self._x += self._dir * 1.8
        if self._x >= max_x:
            self._x, self._dir = max_x, -1
        elif self._x <= margin:
            self._x, self._dir = margin, 1
        self._phase += 1.0
        self.update()

    def paintEvent(self, event) -> None:
        import math
        from PySide6.QtCore import QPointF
        from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen

        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        phase = self._phase
        bob = math.sin(phase * 0.18) * 3.0
        undulate = math.sin(phase * 0.35) * 4.0     # whole-body sway (degrees)
        swish = math.sin(phase * 0.5)               # tail phase [-1, 1]
        cx = self._x
        cy = self.height() / 2.0 + bob

        # ── bubble wake, trailing behind the swim direction ──
        p.setPen(Qt.NoPen)
        for i in range(1, 4):
            bx = cx - self._dir * (self._BODY_LEN * 0.5 + i * 6.0)
            by = cy + math.sin(phase * 0.3 + i) * 1.5
            r = 2.2 - i * 0.5
            if r > 0 and 0 <= bx <= self.width():
                p.setBrush(QColor(140, 205, 255, 130 - i * 25))
                p.drawEllipse(QPointF(bx, by), r, r)

        # ── the shark (base drawing faces RIGHT; scale(dir,1) flips it) ──
        p.save()
        p.translate(cx, cy)
        p.scale(float(self._dir), 1.0)
        p.rotate(undulate)

        L, Hh = 13.0, 5.0
        p.setPen(QPen(QColor(205, 224, 240), 1.0))

        # tail fin (behind body, flicks with swish)
        tail = QPainterPath()
        tail.moveTo(-L + 2, 0)
        tail.lineTo(-L - 7, -5 + swish * 3)
        tail.lineTo(-L - 3, 0)
        tail.lineTo(-L - 7, 5 + swish * 3)
        tail.closeSubpath()
        p.setBrush(QColor(60, 92, 120))
        p.drawPath(tail)

        # body (teardrop: pointed nose at +L, rounded tail at -L)
        body = QPainterPath()
        body.moveTo(-L + 2, 0)
        body.cubicTo(-L * 0.2, -Hh, L * 0.55, -Hh, L, -0.5)
        body.cubicTo(L * 0.55, Hh, -L * 0.2, Hh, -L + 2, 0)
        p.setBrush(QColor(74, 112, 146))
        p.drawPath(body)

        # dorsal fin
        dorsal = QPainterPath()
        dorsal.moveTo(-1, -Hh + 0.5)
        dorsal.lineTo(3, -Hh - 6)
        dorsal.lineTo(5, -Hh + 0.5)
        dorsal.closeSubpath()
        p.setBrush(QColor(60, 92, 120))
        p.drawPath(dorsal)

        # pectoral fin (under belly, sweeps back)
        pect = QPainterPath()
        pect.moveTo(3, Hh - 1)
        pect.lineTo(0, Hh + 4)
        pect.lineTo(6, Hh - 0.5)
        pect.closeSubpath()
        p.drawPath(pect)

        # gill slits
        p.setPen(QPen(QColor(180, 205, 225), 0.8))
        p.drawLine(QPointF(L * 0.30, -2), QPointF(L * 0.30, 2))
        p.drawLine(QPointF(L * 0.30 + 2, -2), QPointF(L * 0.30 + 2, 2))

        # eye + highlight
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(15, 20, 28))
        p.drawEllipse(QPointF(L * 0.62, -1.2), 1.1, 1.1)
        p.setBrush(QColor(255, 255, 255, 200))
        p.drawEllipse(QPointF(L * 0.62 + 0.4, -1.6), 0.4, 0.4)

        p.restore()
        p.end()


class SharkSwimBanner(QWidget):
    """A big, full-width swimming shark that glides across the TOP of the window
    for the whole duration of a Shark Attack drill — the unmistakable "the shark
    is loose" banner. Vector-drawn (no emoji), transparent to mouse, and it
    re-spans the window on resize."""

    _SCALE = 2.1

    def __init__(self, parent: QWidget | None = None, height: int = 48) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._h = height
        self._x = 60.0
        self._dir = 1
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.hide()

    def start(self) -> None:
        par = self.parentWidget()
        if par is None:
            return
        self.setGeometry(0, 0, par.width(), self._h)
        self._x, self._dir, self._phase = 60.0, 1, 0.0
        self.show()
        self.raise_()
        self._timer.start(50)   # 20 fps — smooth enough, lighter on a busy drill

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def resizeEvent(self, event) -> None:
        par = self.parentWidget()
        if par is not None and self.isVisible():
            self.setGeometry(0, 0, par.width(), self._h)

    def _tick(self) -> None:
        margin = 40.0 * self._SCALE
        max_x = max(margin, self.width() - margin)
        self._x += self._dir * 4.0
        if self._x >= max_x:
            self._x, self._dir = max_x, -1
        elif self._x <= margin:
            self._x, self._dir = margin, 1
        self._phase += 1.0
        self.update()

    def paintEvent(self, event) -> None:
        import math
        from PySide6.QtCore import QPointF
        from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen

        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        s = self._SCALE
        phase = self._phase
        bob = math.sin(phase * 0.16) * 4.0
        undulate = math.sin(phase * 0.30) * 4.0
        swish = math.sin(phase * 0.50)
        cx = self._x
        cy = self.height() / 2.0 + bob

        # bubble wake
        p.setPen(Qt.NoPen)
        for i in range(1, 5):
            bx = cx - self._dir * (13 * s + i * 7 * s)
            by = cy + math.sin(phase * 0.3 + i) * 2.0
            r = 3.0 - i * 0.5
            if r > 0 and 0 <= bx <= self.width():
                p.setBrush(QColor(140, 205, 255, 120 - i * 20))
                p.drawEllipse(QPointF(bx, by), r, r)

        # shark (scaled)
        p.save()
        p.translate(cx, cy)
        p.scale(self._dir * s, s)
        p.rotate(undulate)
        L, Hh = 13.0, 5.0
        p.setPen(QPen(QColor(210, 228, 244), max(0.5, 1.0 / s)))

        tail = QPainterPath()
        tail.moveTo(-L + 2, 0)
        tail.lineTo(-L - 7, -5 + swish * 3)
        tail.lineTo(-L - 3, 0)
        tail.lineTo(-L - 7, 5 + swish * 3)
        tail.closeSubpath()
        p.setBrush(QColor(60, 92, 120))
        p.drawPath(tail)

        body = QPainterPath()
        body.moveTo(-L + 2, 0)
        body.cubicTo(-L * 0.2, -Hh, L * 0.55, -Hh, L, -0.5)
        body.cubicTo(L * 0.55, Hh, -L * 0.2, Hh, -L + 2, 0)
        p.setBrush(QColor(78, 116, 150))
        p.drawPath(body)

        dorsal = QPainterPath()
        dorsal.moveTo(-1, -Hh + 0.5)
        dorsal.lineTo(3, -Hh - 6)
        dorsal.lineTo(5, -Hh + 0.5)
        dorsal.closeSubpath()
        p.setBrush(QColor(60, 92, 120))
        p.drawPath(dorsal)

        pect = QPainterPath()
        pect.moveTo(3, Hh - 1)
        pect.lineTo(0, Hh + 4)
        pect.lineTo(6, Hh - 0.5)
        pect.closeSubpath()
        p.drawPath(pect)

        p.setPen(QPen(QColor(185, 208, 228), max(0.4, 0.8 / s)))
        p.drawLine(QPointF(L * 0.30, -2), QPointF(L * 0.30, 2))
        p.drawLine(QPointF(L * 0.30 + 2, -2), QPointF(L * 0.30 + 2, 2))

        p.setPen(Qt.NoPen)
        p.setBrush(QColor(15, 20, 28))
        p.drawEllipse(QPointF(L * 0.62, -1.2), 1.1, 1.1)
        p.setBrush(QColor(255, 255, 255, 200))
        p.drawEllipse(QPointF(L * 0.62 + 0.4, -1.6), 0.4, 0.4)
        p.restore()
        p.end()


class ClashingSwords(QWidget):
    """A small crossed-swords icon for the Red Team Attack button. Idle: two
    static crossed swords. Active (a drill running): the blades rapidly clash
    together with a spark flash. Vector-drawn, mouse-transparent."""

    def __init__(self, parent: QWidget | None = None, size: int = 30) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._active = False
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(40)

    def set_active(self, on: bool) -> None:
        self._active = bool(on)

    def _tick(self) -> None:
        # Only repaint while clashing (active); idle icon is static → no CPU cost.
        if self._active:
            self._phase += 1.0
            self.update()

    def paintEvent(self, event) -> None:
        import math
        from PySide6.QtCore import QPointF
        from PySide6.QtGui import QColor, QPainter, QPen

        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w / 2.0, h / 2.0
        clash = (math.sin(self._phase * 0.9) * 0.5 + 0.5) if self._active else 0.0
        gap = 3.2 * (1.0 - clash)          # blades meet as they clash

        blade = QPen(QColor(225, 230, 240), 2.2)
        guard = QPen(QColor(190, 150, 70), 2.0)

        # sword A: lower-left hilt → upper-right tip (shifted by -gap)
        p.setPen(blade)
        p.drawLine(QPointF(cx - 7 - gap, cy + 8), QPointF(cx + 7 - gap, cy - 8))
        # sword B: lower-right hilt → upper-left tip (shifted by +gap)
        p.drawLine(QPointF(cx + 7 + gap, cy + 8), QPointF(cx - 7 + gap, cy - 8))

        p.setPen(guard)
        p.drawLine(QPointF(cx - 10 - gap, cy + 6), QPointF(cx - 4 - gap, cy + 10))
        p.drawLine(QPointF(cx + 10 + gap, cy + 6), QPointF(cx + 4 + gap, cy + 10))

        # spark flash at the clash point
        if self._active and clash > 0.65:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(255, 232, 120, int(210 * clash)))
            r = 2.0 + clash * 2.5
            p.drawEllipse(QPointF(cx, cy - 2), r, r)
        p.end()
