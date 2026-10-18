"""Bounded cooperative pacing for routine inventories, separate from UI cosmetics.

Existing GUI paint/host samples supply feedback. This module starts no sampler,
thread or timer, and never gates event delivery, response actions or watchdogs.
"""
from __future__ import annotations

import math
import threading
import time
from typing import Callable


class BackgroundPacingController:
    """Thread-safe hysteresis shared by explicitly opted-in background work."""

    SIGNAL_TTL = 12.0
    UI_STALE_SECONDS = 30.0
    STEP_SECONDS = 2.0
    RECOVERY_SECONDS = 8.0
    MAX_ADDED_INTERVAL = 30.0
    _FACTORS = (1, 2, 4, 8)

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._enabled = True
        self._step = 0
        self._changed_at = float("-inf")
        self._healthy_since: float | None = None
        self._ui: tuple[float, int] | None = None
        self._host: tuple[float, int] | None = None
        self._memory: tuple[float, int] | None = None
        self._reason = "No recent pressure"

    @staticmethod
    def _number(value: object) -> float | None:
        try:
            result = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if math.isfinite(result) else None

    def set_enabled(self, enabled: bool) -> None:
        with self._lock:
            self._enabled = bool(enabled)
            if not self._enabled:
                self._reset_locked()
                self._ui = self._host = None
                self._memory = None

    def _reset_locked(self) -> None:
        self._step = 0
        self._healthy_since = None
        self._changed_at = float("-inf")
        self._reason = "No recent pressure" if self._enabled else "Disabled"

    def begin_ui_monitoring(self) -> None:
        """Arm the visible heartbeat lease before its first measured frame.

        This is presence information, not a fabricated FPS sample. A GUI that
        freezes during warmup must still let background readers detect it.
        """
        with self._lock:
            if self._enabled and self._ui is None:
                self._ui = (self._clock(), 0)

    def report_ui(
        self, fps: float, target_fps: float = 30.0,
        worst_lag_ms: float = 0.0, active: bool = True,
    ) -> None:
        now = self._clock()
        measured, target, lag = map(self._number, (fps, target_fps, worst_lag_ms))
        with self._lock:
            if not active:
                self._ui = None
                self._evaluate_locked(now, reset_absent=True)
                return
            if (not self._enabled or measured is None or target is None
                    or lag is None or target <= 0 or measured < 0 or lag < 0):
                return
            ratio = measured / target
            severity = 2 if ratio < 0.5 or lag >= 250 else int(ratio < 0.8 or lag >= 80)
            self._ui = (now, severity)
            self._evaluate_locked(now)

    def report_host(self, cpu_percent: float) -> None:
        value = self._number(cpu_percent)
        if value is None or not 0 <= value <= 100:
            return
        now = self._clock()
        with self._lock:
            if not self._enabled:
                return
            self._host = (now, 2 if value >= 95 else int(value >= 85))
            self._evaluate_locked(now)

    def report_memory(self, percent: float, available_bytes: int | None = None) -> None:
        """Use existing RAM observations, including small hosts' absolute headroom.

        Invalid/unavailable observations do not overwrite a recent valid lease.
        This affects only opted-in routine work; it never drops evidence or
        changes event/response delivery. No sampler is started here.
        """
        used = self._number(percent)
        available = self._number(available_bytes) if available_bytes is not None else None
        if (used is None or not 0 <= used <= 100
                or (available_bytes is not None and (available is None or available < 0))):
            return
        severe = used >= 92 or (available is not None and available <= 256 * 1024 ** 2)
        busy = used >= 85 or (available is not None and available <= 512 * 1024 ** 2)
        now = self._clock()
        with self._lock:
            if not self._enabled:
                return
            self._memory = (now, 2 if severe else int(busy))
            self._evaluate_locked(now)

    def _evaluate_locked(self, now: float, *, reset_absent: bool = False) -> None:
        if not self._enabled:
            self._reset_locked()
            return
        ui = self._ui if self._ui and now >= self._ui[0] else None
        host = self._host if self._host and 0 <= now - self._host[0] <= self.SIGNAL_TTL else None
        memory = (self._memory if self._memory
                  and 0 <= now - self._memory[0] <= self.SIGNAL_TTL else None)
        if ui is None and host is None and memory is None:
            self._reset_locked()
            return
        # A visible heartbeat that cannot report is itself pressure. Hidden and
        # minimized/destroyed windows explicitly clear it. Prolonged missing
        # feedback falls back to conservative 2x rather than staying at 8x or
        # restoring full scans while the GUI may still be frozen.
        ui_pressure = max(ui[1], 2 if now - ui[0] >= 2.5 else 0) if ui else 0
        stale_ui = bool(ui and now - ui[0] > self.UI_STALE_SECONDS)
        if stale_ui:
            ui_pressure = 1
        pressure = max(ui_pressure, host[1] if host else 0, memory[1] if memory else 0)
        if pressure:
            self._healthy_since = None
            self._reason = ("UI responsiveness" if ui_pressure else
                            "Host CPU pressure" if host and host[1] else "Host memory pressure")
            ceiling = 3 if pressure >= 2 else 2
            if stale_ui and not ((host and host[1]) or (memory and memory[1])):
                ceiling = 1
                self._step = min(self._step, ceiling)
                self._reason = "UI feedback unavailable"
            if self._step < ceiling and now - self._changed_at >= self.STEP_SECONDS:
                self._step += 1
                self._changed_at = now
        elif reset_absent and ui is None and memory is None:
            self._reset_locked()
        else:
            if self._healthy_since is None:
                self._healthy_since = now
            if self._step and now - self._healthy_since >= self.RECOVERY_SECONDS:
                self._step -= 1
                self._healthy_since = now
                self._changed_at = now
            self._reason = "Recovering" if self._step else "Normal responsiveness"

    def multiplier(self) -> int:
        with self._lock:
            self._evaluate_locked(self._clock())
            return self._FACTORS[self._step]

    def interval(self, seconds: float) -> float:
        """Add at most 30 seconds to a routine interval; never shorten it."""
        base = max(0.0, float(seconds))
        return min(base * self.multiplier(), base + self.MAX_ADDED_INTERVAL)

    def batch_delay(self) -> float:
        """At most 50ms per cooperative batch; zero at normal load."""
        return (self.multiplier() - 1) * (0.05 / 7.0)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            self._evaluate_locked(self._clock())
            return {
                "enabled": self._enabled,
                "multiplier": self._FACTORS[self._step],
                # Requested pacing level, not measured CPU/scan throughput.
                "pace_percent": 100.0 / self._FACTORS[self._step],
                "level": "strained" if self._step >= 2 else "busy" if self._step else "normal",
                "reason": self._reason,
            }


_CONTROLLER = BackgroundPacingController()


def get_pacing_controller() -> BackgroundPacingController:
    return _CONTROLLER


class RoutineWorkPacer:
    """Per-worker elapsed-work budget, independent of CPU model or item cost.

    Count boundaries retain their existing pauses. Slow items also trigger a
    pause before the count boundary: at 8x, aim for roughly 7ms of work followed
    by up to 50ms of rest. A native call cannot be preempted. This is cooperative
    scheduling, not a process CPU quota or a guaranteed throughput percentage.
    Call resume after waits so idle time is never charged as active work.
    """

    MAX_WORK_SLICE = 0.05
    MAX_PAUSE = 0.05

    def __init__(self, controller=None, *, clock=time.monotonic) -> None:
        self._controller = controller if controller is not None else get_pacing_controller()
        self._clock = clock
        self._work_started = clock()
        self._work_budget = self.MAX_WORK_SLICE
        self._set_budget(self._controller.batch_delay())

    def _set_budget(self, delay: float) -> None:
        # batch_delay encodes (multiplier - 1) * 50ms / 7. Budget the work
        # that can precede one bounded pause at that requested pacing level.
        self._work_budget = (self.MAX_WORK_SLICE if delay <= 0 else
                             min(self.MAX_WORK_SLICE, self.MAX_PAUSE ** 2 / (7 * delay)))

    def pause_seconds(self, completed: int, *, batch_size: int) -> float:
        now = self._clock()
        elapsed = max(0.0, now - self._work_started)
        count_due = completed > 0 and completed % max(1, int(batch_size)) == 0
        if not count_due and elapsed < self._work_budget:
            return 0.0
        requested = min(self.MAX_PAUSE, max(0.0, self._controller.batch_delay()))
        self._set_budget(requested)
        self._work_started = now
        # A nested loop restarting its item counter must not reset elapsed
        # work. Only a serviced checkpoint (or explicit resume) does that.
        return min(self.MAX_PAUSE, max(requested, elapsed * 7 * requested / self.MAX_PAUSE))

    def resume(self) -> None:
        self._work_started = self._clock()
