"""Base class every Angerona module inherits from.

A module is a self-contained security capability. Subclass ``BaseModule``,
set the class attributes, and implement ``run()``. The ModuleManager handles
threading, lifecycle, and event routing — you only write detection logic and
call ``self.emit(...)`` when something interesting happens.
"""
from __future__ import annotations

import json
import os
import threading
import time
import traceback
from pathlib import Path
from typing import Optional

from angerona.core.eventbus import Event, EventBus, Severity


# ── Crash snapshot helpers ────────────────────────────────────────────────────

def _get_snapshot_dir() -> Path:
    """Return (and create) the crash-snapshot directory for this installation."""
    base = os.environ.get("ANGERONA_DATA") or os.path.join(
        os.environ.get("LOCALAPPDATA", str(Path.home())), "Angerona"
    )
    snap = Path(base) / "diagnostics" / "crash_snapshots"
    snap.mkdir(parents=True, exist_ok=True)
    return snap


_MAX_RESTARTS   = 3
_RESTART_DELAYS = (5, 30, 120)   # seconds to wait between successive restart attempts


class BaseModule:
    # ── Override these in your subclass ─────────────────────────────────────
    name: str = "Unnamed Module"
    description: str = ""
    category: str = "General"
    version: str = "1.0.0"
    enabled_by_default: bool = True

    def __init__(self) -> None:
        self._bus: Optional[EventBus] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.status: str = "stopped"
        self.last_error: str = ""
        self.health: int = 100        # 0-100; how well the module is actually working
        self.health_note: str = ""    # why it's degraded, if it is
        self._initial_delay: float = 0.0   # first-poll stagger (set by the manager at boot)
        self._throttle: float = 1.0   # loop-cadence multiplier (Adaptive Resource Governor)

    # ── Wiring (called by ModuleManager) ────────────────────────────────────
    def bind(self, bus: EventBus) -> None:
        self._bus = bus

    # ── Health ───────────────────────────────────────────────────────────────
    def set_health(self, pct: int, note: str = "") -> None:
        """Modules call this to report how well they're functioning."""
        self.health = max(0, min(100, int(pct)))
        self.health_note = note

    @property
    def health_state(self) -> str:
        """Coarse state used for colour coding."""
        if self.status == "stopped":
            return "off"
        if self.status == "error" or self.health <= 0:
            return "failed"
        if self.health >= 90:
            return "ok"
        if self.health >= 50:
            return "degraded"
        return "critical"

    def self_test(self) -> tuple[bool, str]:
        """Override to actively verify the module works. Default: readiness check.
        Returns (passed, detail)."""
        if self.status == "running" and self.health >= 50:
            return True, f"running, health {self.health}%"
        note = self.health_note or self.last_error
        return False, f"status={self.status}, health={self.health}%" + (f" — {note}" if note else "")

    def start(self, initial_delay: float = 0.0) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._initial_delay = max(0.0, float(initial_delay))
        self._stop.clear()
        self._thread = threading.Thread(target=self._wrapped_run, name=self.name, daemon=True)
        self._thread.start()
        self.status = "running"

    def stop(self) -> None:
        self._stop.set()
        self.status = "stopped"

    # ── Helpers available to subclasses ─────────────────────────────────────
    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def sleep(self, seconds: float) -> None:
        """Interruptible sleep — returns early if the module is stopping.

        The wait is scaled by ``self._throttle`` (default 1.0). The Adaptive
        Resource Governor raises this multiplier for heavy, non-security-critical
        modules when the host is under load, so their poll loops run less often
        (lower CPU) automatically — in both Eco and normal mode — and relaxes it
        back to 1.0 when things are idle. Modules that use ``self.sleep()`` for
        their loop cadence get this for free."""
        self._stop.wait(timeout=seconds * getattr(self, "_throttle", 1.0))

    def set_throttle(self, multiplier: float) -> None:
        """Set the loop-cadence multiplier (1.0 = normal, higher = slower/lighter).
        Clamped to [1.0, 8.0]. Called by the Adaptive Resource Governor."""
        try:
            self._throttle = max(1.0, min(8.0, float(multiplier)))
        except (TypeError, ValueError):
            self._throttle = 1.0

    def emit(self, message: str, severity: Severity = Severity.INFO, **details) -> None:
        if self._bus is not None:
            self._bus.publish(Event(self.name, message, severity, time.time(), details))

    # ── Implement this ──────────────────────────────────────────────────────
    def run(self) -> None:
        raise NotImplementedError

    # ── Internal ────────────────────────────────────────────────────────────
    def _wrapped_run(self) -> None:
        """Fault-isolated run wrapper with 3-try throttled restart and crash snapshot.

        On each unhandled exception:
          attempt 1 → emit HIGH, wait 5s, restart
          attempt 2 → emit HIGH, wait 30s, restart
          attempt 3 → write diagnostic bundle, emit CRITICAL, quarantine module

        The bus and all other modules keep running regardless.
        """
        # First-poll stagger: at boot the manager gives each module a small,
        # increasing delay so ~40 sensor threads don't all fire their first
        # (often full process/connection scan) at t=0 — that simultaneous burst
        # is what made the window unresponsive right after launch. Interruptible
        # so stop() during the delay still exits cleanly.
        if self._initial_delay:
            self._stop.wait(timeout=self._initial_delay)
            if self.stopping:
                return
        for attempt in range(_MAX_RESTARTS):
            try:
                self.run()
                return   # clean exit — no crash
            except Exception as exc:
                tb = traceback.format_exc()
                self.last_error = str(exc)

                if attempt < _MAX_RESTARTS - 1:
                    delay = _RESTART_DELAYS[attempt]
                    self.status = "restarting"
                    self.set_health(30, f"Crashed (attempt {attempt + 1}): {exc}")
                    self.emit(
                        f"Module crashed (attempt {attempt + 1}/{_MAX_RESTARTS}), "
                        f"restarting in {delay}s: {exc}",
                        Severity.HIGH,
                        traceback=tb[:500],
                    )
                    # Interruptible delay — respect stop() during the back-off period
                    self._stop.wait(timeout=delay)
                    if self.stopping:
                        break
                    self.status = "running"
                else:
                    # All retries exhausted — quarantine and snapshot
                    self.status = "error"
                    self.set_health(0, f"Quarantined after {_MAX_RESTARTS} crashes: {exc}")
                    self._write_crash_snapshot(exc, tb)
                    self.emit(
                        f"Module QUARANTINED after {_MAX_RESTARTS} crashes: {exc}. "
                        "Sensor blind — inspect crash snapshot in diagnostics/.",
                        Severity.CRITICAL,
                        traceback=tb[:500],
                    )

    def _write_crash_snapshot(self, exc: Exception, tb: str) -> None:
        """Write a diagnostic bundle to diagnostics/crash_snapshots/.

        Bundle contains:
          - exact error and full traceback
          - module process memory footprint (via psutil)
          - last 50 events from the EventBus ring (kill-chain context)
        """
        # Memory footprint
        try:
            import psutil
            mi  = psutil.Process().memory_info()
            mem = {
                "rss_mb":  round(mi.rss / 1024 / 1024, 2),
                "vms_mb":  round(mi.vms / 1024 / 1024, 2),
                "percent": round(psutil.Process().memory_percent(), 2),
            }
        except Exception:
            mem = {"note": "psutil unavailable"}

        # Last 50 bus events — gives kill-chain context around the crash
        recent: list = []
        if self._bus is not None:
            for ev in self._bus.recent(50):
                recent.append({
                    "ts":       ev.ts,
                    "module":   ev.module,
                    "severity": ev.severity.name,
                    "message":  ev.message,
                })

        bundle = {
            "module":         self.name,
            "crashed_at":     time.time(),
            "error":          str(exc),
            "traceback":      tb,
            "memory":         mem,
            "last_50_events": recent,
        }

        snap_dir = _get_snapshot_dir()
        ts_str   = time.strftime("%Y%m%d_%H%M%S")
        fname    = f"{self.name.replace(' ', '_')}_{ts_str}.json"
        try:
            (snap_dir / fname).write_text(
                json.dumps(bundle, default=str, indent=2), encoding="utf-8"
            )
        except Exception:
            pass   # snapshot failure must never mask the original crash
