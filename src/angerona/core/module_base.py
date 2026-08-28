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
    from angerona.core.data_paths import data_dir
    snap = data_dir() / "diagnostics" / "crash_snapshots"
    snap.mkdir(parents=True, exist_ok=True)
    return snap


_MAX_RESTARTS   = 3
_RESTART_DELAYS = (5, 30, 120)   # seconds to wait between successive restart attempts
_RESTART_JOIN_TIMEOUT = 0.25      # keep an operator restart responsive


class BaseModule:
    # ── Override these in your subclass ─────────────────────────────────────
    name: str = "Unnamed Module"
    description: str = ""
    category: str = "General"
    version: str = "1.0.0"
    enabled_by_default: bool = True
    # Existing modules predate the platform contract and are therefore treated
    # as Windows-only until they explicitly opt into another platform.  This is
    # a safety property: an unavailable sensor must not inflate protection.
    supported_platforms = frozenset({"windows"})
    capability_mode: str = "unknown"
    platform_requirements: tuple[str, ...] = ()
    # Automatic restart is opt-in for overridden self-tests. The central
    # runner separately recognizes this base class's own lifecycle/readiness
    # result as restartable; dependency/provisioning checks stay manual-only.
    selftest_auto_repair: bool = False
    _RESTART_JOIN_TIMEOUT: float = _RESTART_JOIN_TIMEOUT

    def __init__(self) -> None:
        self._bus: Optional[EventBus] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        # Lifecycle generations prevent a restarted module from clearing the
        # stop token underneath its exiting predecessor. ``stop()`` remains
        # non-blocking; ``start()`` performs only a short join and, when needed,
        # hands the restart to one daemon waiter.
        self._lifecycle_lock = threading.RLock()
        self._lifecycle_serial = 0
        self._lifecycle_generation = 0
        self._restart_request: Optional[tuple[int, float]] = None
        self._restart_waiter: Optional[threading.Thread] = None
        self._run_context = threading.local()
        self.status: str = "stopped"
        self.last_error: str = ""
        self.health: int = 100        # 0-100; how well the module is actually working
        self.health_note: str = ""    # why it's degraded, if it is
        self._initial_delay: float = 0.0   # first-poll stagger (set by the manager at boot)
        self._throttle: float = 1.0   # loop-cadence multiplier (Adaptive Resource Governor)
        self._throttle_floor: float = 1.0  # persistent Chill Mode cadence floor
        # Readiness barrier used by staged Eco Mode wake-up. A module's first
        # cadence boundary proves it has actually run, rather than merely
        # having a live thread and stale pre-Eco health.
        self._first_cycle_complete = threading.Event()
        self._cycle_count: int = 0
        self._last_cycle_completed_at: float = 0.0
        # EventBus polling uses monotonic publication revisions rather than
        # timestamps. The bus ring is newest-first and multiple events may
        # legitimately share a timestamp; timestamp watermarks therefore lose
        # evidence during bursts. Independent cursors let every module consume
        # an oldest-first, bounded delta without reimplementing that contract.
        self._bus_revision: int = 0
        self._bus_priority_revision: int = 0
        self._bus_cursor_enrolled: dict[bool, bool] = {False: False, True: False}
        self._bus_overflow_count: int = 0
        self._last_reported_overflow_revision: dict[bool, int] = {}
        self._generation_started_at: float = 0.0
        self._crash_count: int = 0
        self._last_crash_at: float = 0.0

    # ── Wiring (called by ModuleManager) ────────────────────────────────────
    def bind(self, bus: EventBus) -> None:
        if self._bus is not None and self._bus is not bus:
            # Revisions are scoped to one EventBus instance. Rebinding to a new
            # bus creates a new ordering domain and therefore requires a fresh
            # explicit enrollment decision by the consumer.
            self._bus_revision = 0
            self._bus_priority_revision = 0
            self._bus_cursor_enrolled = {False: False, True: False}
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

    def _spawn_generation_locked(self, initial_delay: float) -> None:
        """Start one generation. Caller must hold ``_lifecycle_lock``."""
        self._lifecycle_generation += 1
        generation = self._lifecycle_generation
        stop_event = threading.Event()
        self._stop = stop_event
        self._initial_delay = initial_delay
        self._first_cycle_complete.clear()
        self._cycle_count = 0
        self._last_cycle_completed_at = 0.0
        self._generation_started_at = time.monotonic()
        self._restart_request = None
        thread = threading.Thread(
            target=self._wrapped_run,
            args=(generation, stop_event, initial_delay),
            name=self.name,
            daemon=True,
        )
        self._thread = thread
        self.status = "running"
        thread.start()

    def _await_stopped_generation(self, old_thread: threading.Thread) -> None:
        """Complete a deferred restart after the prior generation exits."""
        old_thread.join()
        with self._lifecycle_lock:
            if self._restart_waiter is threading.current_thread():
                self._restart_waiter = None
            if self._thread is not old_thread:
                return
            request = self._restart_request
            if request is None or request[0] != self._lifecycle_serial:
                return
            self._spawn_generation_locked(request[1])

    def _ensure_restart_waiter_locked(self, old_thread: threading.Thread) -> None:
        waiter = self._restart_waiter
        if waiter is not None and waiter.is_alive():
            return
        waiter = threading.Thread(
            target=self._await_stopped_generation,
            args=(old_thread,),
            name=f"{self.name}-restart",
            daemon=True,
        )
        self._restart_waiter = waiter
        waiter.start()

    def start(self, initial_delay: float = 0.0) -> None:
        """Start the module, or safely restart an exiting generation.

        A normal duplicate ``start()`` is still a no-op. If ``stop()`` has
        already signalled a live generation, wait briefly for its interruptible
        loop to finish. A slow blocking operation never holds the caller beyond
        the bounded join: one daemon waiter starts the requested generation only
        after the old main thread (and its generation-owned helpers) has exited.
        """
        delay = max(0.0, float(initial_delay))
        with self._lifecycle_lock:
            old_thread = self._thread
            if old_thread is None or not old_thread.is_alive():
                self._lifecycle_serial += 1
                self._spawn_generation_locked(delay)
                return
            if not self._stop.is_set():
                return
            self._lifecycle_serial += 1
            request_serial = self._lifecycle_serial
            self._restart_request = (request_serial, delay)
            self.status = "restarting"

        # Never join ourselves. The deferred waiter is safe for the uncommon
        # case where a module requests its own restart.
        if old_thread is not threading.current_thread():
            old_thread.join(timeout=max(0.0, float(self._RESTART_JOIN_TIMEOUT)))

        with self._lifecycle_lock:
            if self._thread is not old_thread:
                return
            request = self._restart_request
            if request is None or request[0] != request_serial:
                return
            if not old_thread.is_alive():
                self._spawn_generation_locked(request[1])
                return
            self._ensure_restart_waiter_locked(old_thread)

    def stop(self) -> None:
        """Signal the active generation and return without waiting for it."""
        with self._lifecycle_lock:
            self._lifecycle_serial += 1
            self._restart_request = None
            self._stop.set()
            self.status = "stopped"

    # ── Helpers available to subclasses ─────────────────────────────────────
    @property
    def stopping(self) -> bool:
        return self.generation_stop_event().is_set()

    def generation_stop_event(self) -> threading.Event:
        """Return the immutable stop token for the calling run generation.

        The module's main thread receives a thread-local token. Helper threads
        should capture this value in ``run()`` and receive it explicitly; they
        must not consult the mutable ``self._stop`` after a restart.
        """
        return getattr(self._run_context, "stop_event", self._stop)

    @property
    def lifecycle_generation(self) -> int:
        """Monotonic generation identifier, useful for diagnostics/tests."""
        return self._lifecycle_generation

    def sleep(self, seconds: float, *, cycle_complete: bool = True) -> None:
        """Interruptible sleep — returns early if the module is stopping.

        The wait is scaled by ``self._throttle`` (default 1.0). The Adaptive
        Resource Governor raises this multiplier for heavy, non-security-critical
        modules when the host is under load, so their poll loops run less often
        (lower CPU) automatically — in both Eco and normal mode — and relaxes it
        back to 1.0 when things are idle. Modules that use ``self.sleep()`` for
        their loop cadence get this for free."""
        # Most legacy loops sleep after completing a poll/baseline. Sleep-first
        # loops must pass ``cycle_complete=False`` and explicitly publish the
        # boundary after their work; otherwise startup could attest readiness
        # before a sensor had observed anything.
        if cycle_complete:
            self.mark_cycle_complete()
        self.generation_stop_event().wait(
            timeout=seconds * getattr(self, "_throttle", 1.0)
        )

    def mark_cycle_complete(self) -> None:
        """Publish completion of one module work cycle."""
        self._cycle_count += 1
        self._last_cycle_completed_at = time.monotonic()
        self._first_cycle_complete.set()

    def wait_for_first_cycle(self, timeout: Optional[float] = None) -> bool:
        """Wait until this start has completed its first work cycle."""
        return self._first_cycle_complete.wait(timeout=timeout)

    @property
    def first_cycle_complete(self) -> bool:
        return self._first_cycle_complete.is_set()

    def set_throttle(self, multiplier: float) -> None:
        """Set the loop-cadence multiplier (1.0 = normal, higher = slower/lighter).
        Clamped to [1.0, 8.0]. Called by the Adaptive Resource Governor."""
        try:
            requested = max(1.0, min(8.0, float(multiplier)))
            self._throttle = max(self._throttle_floor, requested)
        except (TypeError, ValueError):
            self._throttle = self._throttle_floor

    def set_throttle_floor(self, multiplier: float) -> None:
        """Set a persistent minimum cadence multiplier for Chill Mode.

        The adaptive governor may ask for a faster cadence when CPU load falls;
        it must not undo an operator-selected all-day low-I/O profile.
        """
        try:
            floor = max(1.0, min(8.0, float(multiplier)))
        except (TypeError, ValueError):
            floor = 1.0
        self._throttle_floor = floor
        self._throttle = max(floor, self._throttle)

    def emit(self, message: str, severity: Severity = Severity.INFO, **details) -> None:
        if self._bus is not None:
            self._bus.publish(Event(self.name, message, severity, time.time(), details))

    def seed_bus_cursor(self, *, priority: bool = False) -> int:
        """Ignore existing history and begin at the bus's current revision.

        Most detectors intentionally inspect bounded retained history on first
        start. Exporters that must never replay history can call this once after
        binding. A revision is an ordering token only; it carries no trust or
        wall-clock meaning.
        """
        if self._bus is None:
            return 0
        if priority:
            revision = self._bus.priority_revision()
            self._bus_priority_revision = revision
        else:
            revision = self._bus.revision()
            self._bus_revision = revision
        self._bus_cursor_enrolled[priority] = True
        return revision

    def bus_cursor_enrolled(self, *, priority: bool = False) -> bool:
        """Whether this instance already chose/committed a cursor origin."""
        return bool(self._bus_cursor_enrolled.get(priority, False))

    def read_bus_events(
        self, *, priority: bool = False
    ) -> tuple[int, list[Event], bool]:
        """Read, but do not acknowledge, one bounded EventBus delta.

        Durable consumers commit their payloads to an outbox before calling
        :meth:`commit_bus_cursor`. A failed durable write therefore leaves the
        delta replayable. Ordinary detectors can use :meth:`poll_bus_events`,
        which preserves the original immediate-advance behavior.
        """
        if self._bus is None:
            return 0, [], False
        previous = self._bus_priority_revision if priority else self._bus_revision
        if priority:
            revision, newest_first, overflow = self._bus.priority_since(previous)
        else:
            revision, newest_first, overflow = self._bus.recent_since(previous)
        if overflow and self._last_reported_overflow_revision.get(priority) != revision:
            self._last_reported_overflow_revision[priority] = revision
            self._bus_overflow_count += 1
            note = (
                "EventBus retention overflow; one or more events were unavailable "
                "to this polling cycle."
            )
            if self.health > 60:
                self.set_health(60, note)
            elif note not in self.health_note:
                self.health_note = f"{self.health_note}; {note}".strip("; ")
            self.emit(
                "EventBus evidence gap detected; conclusions remain incomplete.",
                Severity.MEDIUM,
                finding_code="module.eventbus.retention_overflow",
                overflow_count=self._bus_overflow_count,
                priority_lane=priority,
                response_authorized=False,
            )
        return revision, list(reversed(newest_first)), overflow

    def commit_bus_cursor(self, revision: int, *, priority: bool = False) -> None:
        """Advance one cursor after a consumer reaches a durable disposition."""
        try:
            value = max(0, int(revision))
        except (TypeError, ValueError) as exc:
            raise ValueError("event revision must be an integer") from exc
        current = self._bus_priority_revision if priority else self._bus_revision
        if value < current:
            raise ValueError("event revision cannot move backwards")
        if priority:
            self._bus_priority_revision = value
        else:
            self._bus_revision = value
        self._bus_cursor_enrolled[priority] = True

    def poll_bus_events(self, *, priority: bool = False) -> tuple[list[Event], bool]:
        """Return and immediately acknowledge one bounded EventBus delta.

        EventBus delta APIs return newest-first for presentation compatibility.
        Stateful detectors must process the same delta oldest-first, so this
        helper reverses it and advances a monotonic cursor atomically.
        ``overflow`` stays explicit: retained events are returned, but absence
        of a match is no longer complete evidence.
        """
        revision, events, overflow = self.read_bus_events(priority=priority)
        self.commit_bus_cursor(revision, priority=priority)
        return events, overflow

    def operational_snapshot(self) -> dict[str, object]:
        """Return a bounded, JSON-safe live contract snapshot for UI and API.

        Every module gets the same lifecycle, freshness, throttle and evidence-
        loss vocabulary. Consumers can therefore distinguish a live thread from
        a capability that has actually completed work, and a healthy result from
        one produced after retained evidence was lost.
        """
        now = time.monotonic()
        thread = self._thread
        last_age = (
            max(0.0, now - self._last_cycle_completed_at)
            if self._last_cycle_completed_at > 0
            else None
        )
        uptime = (
            max(0.0, now - self._generation_started_at)
            if self._generation_started_at > 0 and thread is not None and thread.is_alive()
            else None
        )
        return {
            "schema": "angerona.module-operational.v12",
            "status": str(self.status),
            "health": int(self.health),
            "health_state": self.health_state,
            "health_note": str(self.health_note)[:1000],
            "thread_alive": bool(thread is not None and thread.is_alive()),
            "lifecycle_generation": int(self._lifecycle_generation),
            "generation_uptime_seconds": uptime,
            "first_cycle_complete": self.first_cycle_complete,
            "cycle_count": int(self._cycle_count),
            "last_cycle_age_seconds": last_age,
            "throttle_multiplier": float(self._throttle),
            "throttle_floor": float(self._throttle_floor),
            "event_revision": int(self._bus_revision),
            "priority_event_revision": int(self._bus_priority_revision),
            "event_overflow_count": int(self._bus_overflow_count),
            "crash_count": int(self._crash_count),
            "last_crash_age_seconds": (
                max(0.0, now - self._last_crash_at) if self._last_crash_at > 0 else None
            ),
        }

    # ── Implement this ──────────────────────────────────────────────────────
    def run(self) -> None:
        raise NotImplementedError

    # ── Internal ────────────────────────────────────────────────────────────
    def _wrapped_run(
        self,
        generation: int,
        stop_event: threading.Event,
        initial_delay: float,
    ) -> None:
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
        self._run_context.generation = generation
        self._run_context.stop_event = stop_event
        if initial_delay:
            stop_event.wait(timeout=initial_delay)
            if stop_event.is_set():
                return
        for attempt in range(_MAX_RESTARTS):
            try:
                self.run()
                if stop_event.is_set():
                    return
                self.status = "error"
                self.set_health(0, "Module worker returned before stop was requested")
                self.emit(
                    "Module worker exited unexpectedly; capability is no longer live.",
                    Severity.HIGH,
                    finding_code="module.lifecycle.unexpected_exit",
                    response_authorized=False,
                )
                return
            except Exception as exc:
                tb = traceback.format_exc()
                self.last_error = str(exc)
                self._crash_count += 1
                self._last_crash_at = time.monotonic()

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
                    stop_event.wait(timeout=delay)
                    if stop_event.is_set():
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
