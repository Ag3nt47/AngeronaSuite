"""Presentation refreshes sleep with their widgets and yield under host pressure."""
from __future__ import annotations

import time

from PySide6.QtCore import QEvent, QTimer
from PySide6.QtWidgets import QWidget

from angerona.core.background_pacing import get_pacing_controller


class PresentationTimer(QTimer):
    """A Qt timer for view refreshes, never for security or job completion.

    ``start`` records intent even before the widget is shown. Hiding a widget,
    switching away from its tab, or minimizing its window removes the native
    timer; showing it restores the requested cadence. Explicit ``stop`` also
    clears intent, so reopening cannot restart a completed job or animation.
    Existing pressure feedback paces visible refreshes without another sampler.
    """

    def __init__(self, owner: QWidget, *, pressure_sensitive: bool = True) -> None:
        super().__init__(owner)
        self._owner = owner
        self._window: QWidget | None = None
        self._requested = False
        self._base_interval_ms = 0
        self._pressure_sensitive = pressure_sensitive
        self._next_pressure_sample = 0.0
        self._paced_interval_ms = 0
        owner.installEventFilter(self)
        self.timeout.connect(self._on_timeout)

    def setInterval(self, msec: int) -> None:  # noqa: N802 - Qt signature
        self._base_interval_ms = max(1, int(msec))
        self._next_pressure_sample = 0.0
        super().setInterval(self._interval())

    def start(self, msec: int | None = None) -> None:
        if msec is not None:
            self.setInterval(msec)
        self._requested = True
        self._sync()

    def stop(self) -> None:
        self._requested = False
        super().stop()

    def _interval(self) -> int:
        now = time.monotonic()
        if now >= self._next_pressure_sample:
            base = max(1, self._base_interval_ms)
            self._paced_interval_ms = (
                max(base, round(get_pacing_controller().interval(base / 1000.0) * 1000))
                if self._pressure_sensitive else base
            )
            # Animation frames need no separate pressure poll on every repaint.
            self._next_pressure_sample = now + 1.0
        return self._paced_interval_ms

    def _watch_window(self) -> QWidget:
        window = self._owner.window()
        if window is not self._window:
            if self._window is not None and self._window is not self._owner:
                self._window.removeEventFilter(self)
            self._window = window
            if window is not self._owner:
                window.installEventFilter(self)
        return window

    def _sync(self) -> None:
        window = self._watch_window()
        if not self._requested or not self._owner.isVisible() or window.isMinimized():
            super().stop()
            return
        interval = self._interval()
        if not self.isActive() or self.interval() != interval:
            super().start(interval)

    def _on_timeout(self) -> None:
        if self.isSingleShot():
            self._requested = False
        else:
            self._sync()

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt signature
        kind = event.type()
        if kind == QEvent.Type.Hide:
            # Keep intent while suspending native wakeups, including tab changes.
            super().stop()
        elif kind in (QEvent.Type.Show, QEvent.Type.WindowStateChange,
                      QEvent.Type.ParentChange):
            self._sync()
        return False
