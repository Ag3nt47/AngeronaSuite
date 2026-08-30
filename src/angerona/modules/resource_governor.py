"""resource_governor.py — Adaptive Resource Governor (CODE: GOV).

The suite runs ~40 module threads in one process. When the host gets busy, the
heavy background pollers/scanners can bog everything down. GOV samples the
process's CPU use and, when it's high, tells the **non-security-critical** heavy
modules to slow their poll loops (raising each module's ``_throttle`` multiplier,
which ``BaseModule.sleep()`` honours). When load drops, it relaxes them back to
full speed.

Key properties
--------------
- Works in BOTH Eco and normal mode (it governs whatever is still running).
- NEVER throttles the real-time response/protection path (SOAR, watchdog,
  heartbeat, IPC guard, AI triage, deception, ransomware/AMSI/fast-path, shadow
  shield) — those always run at full cadence so security is never reduced.
- Purely cooperative: it only changes a multiplier modules already consult; it
  never suspends threads or kills work. Fail-open (any error → no throttling).

Standard library + psutil only.
"""
from __future__ import annotations

SUPPORTED_PLATFORMS = ("windows", "macos", "linux")

import time
import threading
from typing import Optional

try:
    import psutil
except Exception:   # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity


# CPU thresholds as a percentage of ONE core (psutil normalises per process; we
# divide by core count so the numbers mean the same on any machine).
_HIGH_LOAD = 18.0     # above this (sustained) → tighten throttle a step
_LOW_LOAD  = 8.0      # below this → relax a step (and memory is comfortable)
_MAX_LEVEL = 8.0      # max slowdown multiplier applied to throttleable modules
_SAMPLE_S  = 4.0

# Memory pressure (system RAM %). Angerona was crashing under heavy data load, so
# the governor now also throttles on RAM — and hard-throttles before the machine
# starts thrashing/OOM-ing (which is what actually kills the process).
_HIGH_MEM  = 85.0
_CRIT_MEM  = 92.0


class ResourceGovernor(BaseModule):
    name = "Adaptive Resource Governor"
    CODE = "GOV"
    description = ("Watches process CPU and throttles heavy non-critical module "
                   "loops under load (Eco + normal); relaxes them when idle. "
                   "Never slows the real-time protection path.")
    category = "Performance"
    version = "1.13.0"
    supported_platforms = SUPPORTED_PLATFORMS
    capability_mode = "protect"

    def __init__(self) -> None:
        super().__init__()
        self._manager = None
        # Shared with authenticated ECO transactions so the governor cannot
        # publish a stale level between the transaction's module updates.
        self._level_lock = threading.RLock()
        self._level = 1.0          # current slowdown multiplier being applied
        self._proc = None
        self._ncpu = 1

    def bind_manager(self, manager) -> None:
        # ModuleManager hands us a handle so we can see/adjust our siblings.
        self._manager = manager

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _throttleable(self):
        """Yield release-trusted types which explicitly permit load shedding."""
        if self._manager is None:
            return
        for name, mod in self._manager.modules.items():
            if not isinstance(mod, BaseModule) or mod is self:
                continue
            if getattr(mod, "status", "") != "running":
                continue
            # Read the immutable declaration from the implementation type, not
            # a mutable instance/display-name field. External capabilities do
            # not inherit this privileged performance authority.
            if type(mod).__dict__.get("adaptive_throttle_allowed") is not True:
                continue
            trust = getattr(self._manager, "module_trust", {}).get(name, {})
            if trust and (
                trust.get("origin") != "builtin" or trust.get("trust") != "release"
            ):
                continue
            try:
                ceiling = float(type(mod).__dict__["adaptive_throttle_max"])
            except (KeyError, TypeError, ValueError, OverflowError):
                continue
            if not 1.0 <= ceiling <= 8.0:
                continue
            yield name, mod, ceiling

    def _apply(self, level: float) -> tuple[int, tuple[str, ...]]:
        applied = 0
        failed: list[str] = []
        for name, mod, ceiling in self._throttleable():
            try:
                requested = min(float(level), ceiling)
                # Bypass extension overrides: only BaseModule's bounded cadence
                # primitive may service this release-owned governor lease.
                BaseModule.set_throttle(mod, requested)
                expected = max(float(mod._throttle_floor), requested)
                if float(mod._throttle) != expected:
                    raise RuntimeError("throttle postcondition mismatch")
                applied += 1
            except Exception:
                failed.append(str(name)[:160])
        return applied, tuple(failed)

    def _load_pct(self) -> Optional[float]:
        if self._proc is None:
            return None
        try:
            raw = self._proc.cpu_percent(None)   # since last call, across all cores
        except Exception:
            return None
        return raw / max(1, self._ncpu)

    # ── Loop ──────────────────────────────────────────────────────────────────
    def run(self) -> None:
        if psutil is None:
            self.set_health(60, "psutil unavailable — governor inert")
            while not self.stopping:
                self.sleep(30)
            return
        self._proc = psutil.Process()
        self._ncpu = psutil.cpu_count() or 1
        self._proc.cpu_percent(None)   # prime the delta baseline
        self.emit("Adaptive Resource Governor online — will throttle heavy "
                  "non-critical modules under load.", Severity.INFO)

        try:
            while not self.stopping:
                self.sleep(_SAMPLE_S)
                load = self._load_pct()
                if load is None:
                    self.set_health(60, "CPU load collector unavailable")
                    continue
                memory_available = True
                try:
                    mem = float(psutil.virtual_memory().percent)
                except Exception:
                    mem = 0.0
                    memory_available = False

                # The level and all affected module multipliers form one cadence
                # policy transaction. Mobile ECO takes this same lock first and
                # then the per-module throttle locks, preserving one lock order.
                with self._level_lock:
                    prev = self._level
                    # Severe pressure (CPU pegged or RAM near OOM) → jump 2 steps so
                    # we shed load before the process thrashes or is killed.
                    severe = load > (_HIGH_LOAD * 2) or (
                        memory_available and mem >= _CRIT_MEM
                    )
                    if severe:
                        self._level = min(_MAX_LEVEL, self._level + 2.0)
                    elif load > _HIGH_LOAD or (
                        memory_available and mem >= _HIGH_MEM
                    ):
                        self._level = min(_MAX_LEVEL, self._level + 1.0)
                    elif load < _LOW_LOAD and (
                        not memory_available or mem < (_HIGH_MEM - 10)
                    ):
                        self._level = max(1.0, self._level - 1.0)
                    # else: hold steady in the comfortable band

                    changed = self._level != prev
                    # Reconcile every pass, including level 1. A restarted
                    # governor therefore cannot leave one of its opt-in leases
                    # stale at 8x while claiming a healthy 1x level.
                    count, failures = self._apply(self._level)
                    current_level = self._level

                if changed:
                    if current_level > 1.0:
                        self.emit(
                            f"Pressure (CPU {load:.0f}%/core, RAM {mem:.0f}%) — "
                            f"throttling {count} explicitly opt-in analytical "
                            f"module(s), capped per capability. Real-time sensors "
                            "and response paths remain at full cadence.",
                            Severity.MEDIUM if severe else Severity.INFO,
                            level=current_level,
                            load=round(load, 1),
                            mem=round(mem, 1) if memory_available else None,
                        )
                    else:
                        self.emit(
                            f"Load normalised (CPU {load:.0f}%/core) — restored "
                            "governor-owned analytical cadence leases.",
                            Severity.INFO,
                        )
                if failures:
                    self.set_health(
                        40,
                        "cadence lease application incomplete for: "
                        + ", ".join(failures[:16]),
                    )
                elif not memory_available:
                    self.set_health(
                        70,
                        f"CPU {load:.0f}%/core; memory pressure collector unavailable; "
                        f"throttle {current_level:.0f}x",
                    )
                else:
                    self.set_health(
                        100,
                        f"CPU {load:.0f}%/core · RAM {mem:.0f}% · "
                        f"throttle {current_level:.0f}x",
                    )
        finally:
            # A normal stop, crash, or watchdog restart always relinquishes the
            # governor's current cadence lease before the generation exits.
            with self._level_lock:
                self._level = 1.0
                _restored, failures = self._apply(1.0)
            if failures:
                self.set_health(
                    40,
                    "governor exit could not restore cadence for: "
                    + ", ".join(failures[:16]),
                )

    def self_test(self) -> tuple[bool, str]:
        if psutil is None:
            return False, "psutil not installed — governor cannot sample CPU"
        with self._level_lock:
            level = self._level
        return True, f"governor active; current throttle {level:.0f}x"


def register() -> BaseModule:
    return ResourceGovernor()
