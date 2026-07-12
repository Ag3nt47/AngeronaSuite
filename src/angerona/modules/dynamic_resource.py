"""Dynamic Resource Governor — G2-H.

Angerona runs many sensor threads simultaneously.  Under incident load (many
HIGH/CRITICAL events in a short window) we want the process to punch above its
default scheduling weight so evidence is captured before the attacker's payload
can finish.  In quiet periods we step back to normal priority so Angerona
doesn't steal CPU from the user's foreground work.

What this module does:
  1. Monitors the event bus rate (events per 10-second window).
  2. If the rate exceeds HIGH_EVENT_RATE, escalates the Angerona process to
     HIGH_PRIORITY_CLASS on Windows (psutil.HIGH_PRIORITY_CLASS = 0x80).
     This is *not* REALTIME_PRIORITY_CLASS — it will not starve the OS.
  3. After COOLDOWN_S seconds of calm (rate drops below LOW_EVENT_RATE),
     returns to NORMAL_PRIORITY_CLASS.
  4. Emits INFO events on each transition so operators can see when the
     governor fired.

Priority classes (Windows):
  IDLE_PRIORITY_CLASS      (0x40) — used for screen savers
  BELOW_NORMAL_PRIORITY    (0x4000)
  NORMAL_PRIORITY_CLASS    (0x20) — default for most apps
  ABOVE_NORMAL_PRIORITY    (0x8000)
  HIGH_PRIORITY_CLASS      (0x80) — what we escalate to under incident load
  REALTIME_PRIORITY_CLASS  (0x100) — NOT used; can starve the OS

Why not REALTIME?
  REALTIME can prevent the OS from servicing hardware interrupts, leading to
  system hangs.  HIGH is the highest safe level for a user-mode application.

Fallback:
  If psutil is unavailable the module idles and emits one INFO notice.
  If the priority change fails (permissions, non-Windows) it logs the error
  and continues monitoring — partial degradation, not a crash.
"""
from __future__ import annotations

import os
import time
from collections import deque
from typing import Deque

from angerona.core.module_base import BaseModule, Severity

# ── Tuning constants ──────────────────────────────────────────────────────────
POLL_INTERVAL    = 5.0     # seconds between rate checks
RATE_WINDOW_S    = 10.0    # sliding window for event-rate calculation
HIGH_EVENT_RATE  = 15      # events/window → escalate to HIGH priority
LOW_EVENT_RATE   = 5       # events/window → safe to de-escalate
COOLDOWN_S       = 60.0    # seconds of calm before de-escalation


class DynamicResourceModule(BaseModule):
    CODE = "DRES"
    NAME = "Dynamic Resource Governor"
    name = "Dynamic Resource Governor"
    description = (
        "Escalates process priority to HIGH_PRIORITY_CLASS under incident load "
        "and returns to NORMAL after COOLDOWN_S seconds of calm."
    )
    category = "System"

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def __init__(self) -> None:
        super().__init__()
        self._elevated        = False
        self._last_ts         = 0.0          # last bus event timestamp seen
        self._event_times: Deque[float] = deque()
        self._calm_since: float = 0.0        # when rate last dropped below LOW
        self._proc = None                    # psutil.Process handle

    def run(self) -> None:
        try:
            import psutil
            self._proc = psutil.Process(os.getpid())
        except ImportError:
            self.set_health(50, "psutil unavailable — priority control disabled")
            self.emit(
                "Dynamic Resource Governor: psutil not installed. "
                "Priority escalation disabled. pip install psutil to enable.",
                Severity.INFO,
            )
            while not self.stopping:
                self.sleep(60.0)
            return

        self.set_health(100, "")
        self.emit(
            f"Dynamic Resource Governor active — "
            f"escalation threshold={HIGH_EVENT_RATE} events/{RATE_WINDOW_S}s, "
            f"cooldown={COOLDOWN_S}s.",
            Severity.INFO,
        )

        self._calm_since = time.time()   # start calm

        while not self.stopping:
            self.sleep(POLL_INTERVAL)
            self._tick()

    def _tick(self) -> None:
        now = time.time()
        self._drain_bus(now)
        rate = self._current_rate(now)

        if not self._elevated and rate >= HIGH_EVENT_RATE:
            self._escalate()
            self._calm_since = 0.0   # reset calm timer
        elif self._elevated:
            if rate <= LOW_EVENT_RATE:
                if self._calm_since == 0.0:
                    self._calm_since = now
                elif now - self._calm_since >= COOLDOWN_S:
                    self._restore()
                    self._calm_since = now
            else:
                self._calm_since = 0.0   # still elevated — reset calm

    def _drain_bus(self, now: float) -> None:
        """Count new bus events into the sliding window."""
        if self._bus is None:
            return
        for ev in self._bus.recent(100):
            if ev.ts <= self._last_ts:
                continue
            self._last_ts = max(self._last_ts, ev.ts)
            self._event_times.append(ev.ts)

        # Evict events outside the window
        cutoff = now - RATE_WINDOW_S
        while self._event_times and self._event_times[0] < cutoff:
            self._event_times.popleft()

    def _current_rate(self, now: float) -> int:
        cutoff = now - RATE_WINDOW_S
        return sum(1 for t in self._event_times if t >= cutoff)

    def _escalate(self) -> None:
        """Raise process priority to HIGH_PRIORITY_CLASS."""
        try:
            import psutil
            self._proc.nice(psutil.HIGH_PRIORITY_CLASS)
            self._elevated = True
            self.emit(
                "Priority ESCALATED to HIGH_PRIORITY_CLASS — incident event rate exceeded "
                f"threshold ({HIGH_EVENT_RATE} events/{RATE_WINDOW_S}s).",
                Severity.INFO,
                priority_class="HIGH",
                rate_threshold=HIGH_EVENT_RATE,
            )
        except Exception as exc:
            # Non-fatal — log but keep monitoring
            self.emit(
                f"Priority escalation failed ({exc}) — continuing at normal priority.",
                Severity.LOW,
            )

    def _restore(self) -> None:
        """Return process priority to NORMAL_PRIORITY_CLASS."""
        try:
            import psutil
            self._proc.nice(psutil.NORMAL_PRIORITY_CLASS)
            self._elevated = False
            self.emit(
                f"Priority RESTORED to NORMAL_PRIORITY_CLASS after {COOLDOWN_S}s of calm.",
                Severity.INFO,
                priority_class="NORMAL",
                cooldown_s=COOLDOWN_S,
            )
        except Exception as exc:
            self.emit(
                f"Priority restore failed ({exc}) — still at elevated priority.",
                Severity.LOW,
            )

    def self_test(self) -> tuple[bool, str]:
        if self.status != "running":
            return super().self_test()   # not started yet — graceful "stopped" status
        if self._proc is None:
            return False, "psutil not initialised"
        try:
            import psutil
            current = self._proc.nice()
            label = (
                "HIGH"    if current == psutil.HIGH_PRIORITY_CLASS   else
                "NORMAL"  if current == psutil.NORMAL_PRIORITY_CLASS else
                f"other({current})"
            )
            return True, f"Process priority={label}, elevated={self._elevated}"
        except Exception as exc:
            return False, str(exc)

    def stop(self) -> None:
        # Always restore normal priority on clean shutdown
        if self._elevated:
            try:
                import psutil
                self._proc.nice(psutil.NORMAL_PRIORITY_CLASS)
            except Exception:
                pass
        super().stop()


def register() -> DynamicResourceModule:
    return DynamicResourceModule()
