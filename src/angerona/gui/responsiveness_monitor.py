"""Measure a tiny Qt paint heartbeat without repainting the dashboard."""
from __future__ import annotations

from collections import deque
import math
import time

from PySide6.QtCore import QObject, Qt, QTimer, Signal


class FrameSampler:
    """A bounded two-second record of completed, requested paint events."""

    TARGET_FPS = 30.0
    WINDOW_SECONDS = 2.0

    def __init__(self) -> None:
        self._frames: deque[tuple[float, float]] = deque(maxlen=120)
        self._started_at = 0.0

    def reset(self, now: float) -> None:
        self._frames.clear()
        self._started_at = now

    def record(self, now: float, lag_ms: float) -> None:
        self._frames.append((now, max(0.0, lag_ms)))

    def snapshot(self, now: float) -> dict:
        cutoff = max(self._started_at, now - self.WINDOW_SECONDS)
        while self._frames and self._frames[0][0] <= cutoff:
            self._frames.popleft()
        elapsed = max(0.0, now - cutoff)
        ready = elapsed >= 1.0
        fps = len(self._frames) / elapsed if ready else None
        return {
            "active": True,
            "ready": ready,
            "fps": fps,
            "target_fps": self.TARGET_FPS,
            "percent": min(100.0, fps / self.TARGET_FPS * 100.0) if ready else None,
            "worst_lag_ms": max((lag for _, lag in self._frames), default=0.0),
        }


class ResponsivenessMonitor(QObject):
    """One visible-only heartbeat; the core controller owns pacing policy.

    FPS describes Qt deliveries for a small footer region, not GPU/display FPS.
    No host sampling, filesystem work, or whole-window update occurs here.
    """

    sample_ready = Signal(object)

    def __init__(self, footer, owner, *, controller=None, clock=time.monotonic) -> None:
        super().__init__(owner)
        if controller is None:
            from angerona.core.background_pacing import get_pacing_controller
            controller = get_pacing_controller()
        self._controller = controller
        self._footer = footer
        self._clock = clock
        self._sampler = FrameSampler()
        self._active = False
        self._pacing_enabled = True
        self._closed = False
        self._pending_at: float | None = None
        self._pending_lag = 0.0
        self._next_due = 0.0
        self._last_report = 0.0
        self._timer = QTimer(self)
        self._timer.setTimerType(Qt.PreciseTimer)
        self._timer.setInterval(round(1000 / FrameSampler.TARGET_FPS))
        self._timer.timeout.connect(self._tick)
        footer.heartbeat_painted.connect(self._painted)
        owner.destroyed.connect(self.close)

    def set_enabled(self, enabled: bool) -> None:
        """Switch routine-work pacing while retaining the visible FPS meter."""
        self._pacing_enabled = bool(enabled)
        self._controller.set_enabled(self._pacing_enabled)
        if not self._pacing_enabled:
            self._controller.report_ui(0.0, active=False)
        elif self._active:
            self._controller.begin_ui_monitoring()
        self._publish(self._clock())

    def set_active(self, active: bool) -> None:
        active = bool(active) and not self._closed
        if active == self._active:
            return
        self._active = active
        now = self._clock()
        self._sampler.reset(now)
        self._pending_at = None
        self._last_report = now
        if active:
            if self._pacing_enabled:
                self._controller.begin_ui_monitoring()
            self._next_due = now + self._timer.interval() / 1000.0
            self._timer.start()
        else:
            self._timer.stop()
            self._controller.report_ui(0.0, active=False)
        self._publish(now)

    def update_host_sample(self, sample) -> None:
        """Reuse System Pulse's existing CPU observation, including while hidden."""
        if self._closed or not isinstance(sample, dict) or sample.get("error"):
            return
        try:
            cpu = float(sample.get("cpu"))
        except (TypeError, ValueError, OverflowError):
            return
        if math.isfinite(cpu) and 0.0 <= cpu <= 100.0:
            self._controller.report_host(cpu)

    def _tick(self) -> None:
        if not self._active or self._closed:
            return
        if not self._footer.isVisible() or self._footer.window().isMinimized():
            self.set_active(False)
            return
        now = self._clock()
        timer_lag = max(0.0, (now - self._next_due) * 1000.0)
        self._next_due = now + self._timer.interval() / 1000.0
        if self._pending_at is None:
            self._pending_at = now
            self._pending_lag = timer_lag
            self._footer.request_heartbeat()
        else:
            self._pending_lag = max(self._pending_lag, timer_lag)
        if now - self._last_report >= 1.0:
            self._publish(now)
            self._last_report = now

    def _painted(self) -> None:
        if not self._active or self._pending_at is None or self._closed:
            return
        now = self._clock()
        lag = max(self._pending_lag, (now - self._pending_at) * 1000.0)
        self._pending_at = None
        self._sampler.record(now, lag)

    def _publish(self, now: float) -> None:
        sample = (self._sampler.snapshot(now) if self._active else
                  {"active": False, "ready": False, "fps": None,
                   "percent": None, "target_fps": FrameSampler.TARGET_FPS,
                   "worst_lag_ms": 0.0})
        if self._active and sample["ready"]:
            if self._pending_at is not None:
                sample["worst_lag_ms"] = max(
                    sample["worst_lag_ms"], self._pending_lag,
                    (now - self._pending_at) * 1000.0,
                )
            if self._pacing_enabled:
                self._controller.report_ui(
                    sample["fps"], target_fps=sample["target_fps"],
                    worst_lag_ms=sample["worst_lag_ms"], active=True,
                )
        sample["pacing"] = self._controller.snapshot()
        self.sample_ready.emit(sample)

    def close(self, *_args) -> None:
        if self._closed:
            return
        self.set_active(False)
        self._closed = True
        self._controller.report_ui(0.0, active=False)
