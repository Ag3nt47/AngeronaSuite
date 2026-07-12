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

import time
from typing import Optional

try:
    import psutil
except Exception:   # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity


# Modules that must NEVER be slowed — the real-time protection/response path.
_CRITICAL_EXEMPT = {
    "Active Response SOAR", "SOAR Automation", "Watchdog Monitor",
    "Anti-Suspension Heartbeat", "Zero-Trust Local IPC Guard",
    "AI Triage (Ollama)", "Active Deception", "Ransomware Heuristics",
    "AMSI Bridge", "Deterministic Fast-Path Interceptor", "Shadow Shield",
    "Adaptive Resource Governor",   # never throttle ourselves
}

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
    version = "1.0.0"

    def __init__(self) -> None:
        super().__init__()
        self._manager = None
        self._level = 1.0          # current slowdown multiplier being applied
        self._proc = None
        self._ncpu = 1

    def bind_manager(self, manager) -> None:
        # ModuleManager hands us a handle so we can see/adjust our siblings.
        self._manager = manager

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _throttleable(self):
        """Yield running, non-critical sibling modules we may slow down."""
        if self._manager is None:
            return
        for name, mod in self._manager.modules.items():
            if name in _CRITICAL_EXEMPT:
                continue
            if getattr(mod, "category", "") == "Response":
                continue   # response modules stay fast
            if getattr(mod, "status", "") != "running":
                continue
            yield name, mod

    def _apply(self, level: float) -> int:
        n = 0
        for _name, mod in self._throttleable():
            try:
                mod.set_throttle(level)
                n += 1
            except Exception:
                pass
        return n

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

        while not self.stopping:
            self.sleep(_SAMPLE_S)
            load = self._load_pct()
            if load is None:
                continue
            try:
                mem = psutil.virtual_memory().percent
            except Exception:
                mem = 0.0

            prev = self._level
            # Severe pressure (CPU pegged or RAM near OOM) → jump 2 steps so we
            # shed load FAST before the process thrashes and the OS kills it.
            severe = load > (_HIGH_LOAD * 2) or mem >= _CRIT_MEM
            if severe:
                self._level = min(_MAX_LEVEL, self._level + 2.0)
            elif load > _HIGH_LOAD or mem >= _HIGH_MEM:
                self._level = min(_MAX_LEVEL, self._level + 1.0)
            elif load < _LOW_LOAD and mem < (_HIGH_MEM - 10):
                self._level = max(1.0, self._level - 1.0)
            # else: hold steady in the comfortable band

            if self._level != prev:
                count = self._apply(self._level)
                if self._level > 1.0:
                    self.emit(
                        f"Pressure (CPU {load:.0f}%/core, RAM {mem:.0f}%) — throttling "
                        f"{count} heavy non-critical module(s) to {self._level:.0f}x "
                        "slower to keep Angerona responsive. Protection path unaffected.",
                        Severity.MEDIUM if severe else Severity.INFO,
                        level=self._level, load=round(load, 1), mem=round(mem, 1))
                else:
                    self.emit(
                        f"Load normalised (CPU {load:.0f}%/core, RAM {mem:.0f}%) — "
                        "restored full cadence on all throttled modules.", Severity.INFO)
            # Keep newly-(re)started modules in sync with the current level even
            # when the level itself didn't change this tick.
            elif self._level > 1.0:
                self._apply(self._level)

            self.set_health(100, f"CPU {load:.0f}%/core · RAM {mem:.0f}% · throttle {self._level:.0f}x")

    def self_test(self) -> tuple[bool, str]:
        if psutil is None:
            return False, "psutil not installed — governor cannot sample CPU"
        return True, f"governor active; current throttle {self._level:.0f}x"


def register() -> BaseModule:
    return ResourceGovernor()
