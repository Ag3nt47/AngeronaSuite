"""profiler.py — Performance Profiler + Tuning Sandbox.

PerformanceProfiler is a thin, live psutil readout of Angerona's OWN process
(CPU % and RSS MB) — the point of the Academy is to make the security/
performance tradeoff visible, not to build a general system monitor.

TuningSandbox is deliberately NOT a set of invented knobs — every entry maps
to a real env var (or module toggle) that already changes real behavior
elsewhere in the app:

    ANGERONA_SOAR_AUTOCONTAIN                        modules/soar.py
    ANGERONA_SOAR_KILL_AND_ROLLBACK                  modules/soar_engine.py
    ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY     modules/soar_engine.py
    ANGERONA_NETMON_NOVELTY_WINDOW_MIN               modules/network_monitor.py

plus per-module enable/disable, via the same ModuleManager.set_enabled()
the console's `module <name> <on|off>` command already uses. Surfacing them
in one place (instead of "go read the source") is the entire value-add here.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


class PerformanceProfiler:
    """Live CPU/RAM overhead readout for Angerona's own process."""

    def __init__(self) -> None:
        self._proc = psutil.Process(os.getpid()) if psutil else None
        if self._proc:
            self._proc.cpu_percent(None)  # prime psutil's internal delta counter

    @property
    def available(self) -> bool:
        return self._proc is not None

    def sample(self) -> dict:
        if not self._proc:
            return {"cpu_percent": 0.0, "rss_mb": 0.0, "threads": 0, "ts": time.time(),
                    "error": "psutil not installed"}
        try:
            return {
                "cpu_percent": self._proc.cpu_percent(interval=0.2),
                "rss_mb": round(self._proc.memory_info().rss / (1024 * 1024), 1),
                "threads": self._proc.num_threads(),
                "ts": time.time(),
            }
        except Exception as exc:
            return {"cpu_percent": 0.0, "rss_mb": 0.0, "threads": 0, "ts": time.time(),
                    "error": str(exc)}

    def render_line(self, sample: Optional[dict] = None) -> str:
        s = sample or self.sample()
        if s.get("error"):
            return f"EDR overhead: unavailable ({s['error']})"
        return (f"EDR overhead: {s['cpu_percent']:5.1f}% CPU  ·  {s['rss_mb']:7.1f} MB RSS  "
               f"·  {s['threads']:>3} threads")


@dataclass
class TunableParam:
    key: str          # env var name — the single source of truth
    label: str
    kind: str          # "bool" | "severity" | "int"
    default: str
    description: str = ""

    @property
    def current(self) -> str:
        return os.environ.get(self.key, self.default)

    def set(self, value: str) -> None:
        if self.kind == "bool" and value not in ("0", "1"):
            raise ValueError(f"{self.key} expects '0' or '1', got {value!r}")
        if self.kind == "severity" and value.upper() not in (
            "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(f"{self.key} expects a severity name, got {value!r}")
        if self.kind == "int":
            int(value)  # raises ValueError with a clear message on bad input
        os.environ[self.key] = value

    def render_line(self) -> str:
        flag = "on " if (self.kind == "bool" and self.current == "1") else \
               ("off" if self.kind == "bool" else self.current)
        return f"  {self.key:<44} = {flag:<10} — {self.label}: {self.description}"


class TuningSandbox:
    """One place to see and adjust every real runtime knob Angerona exposes,
    without needing to grep the source for env var names."""

    PARAMS: List[TunableParam] = [
        TunableParam(
            "ANGERONA_SOAR_AUTOCONTAIN", "Auto-Suspend on CRITICAL", "bool", "0",
            description="SOAR Automation auto-suspends the offending process on a CRITICAL alert."),
        TunableParam(
            "ANGERONA_SOAR_KILL_AND_ROLLBACK", "Kill+Rollback Armed", "bool", "0",
            description="Active Response SOAR terminates + deletes the artifact on a matching alert."),
        TunableParam(
            "ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "Kill+Rollback Severity Floor",
            "severity", "CRITICAL",
            description="Minimum alert severity that triggers Active Response SOAR."),
        TunableParam(
            "ANGERONA_NETMON_NOVELTY_WINDOW_MIN", "Network Novelty Window (minutes)",
            "int", "60",
            description="How long before a previously-seen external host counts as 'new' again."),
    ]

    def snapshot(self) -> List[TunableParam]:
        return list(self.PARAMS)

    def get(self, key: str) -> TunableParam:
        for p in self.PARAMS:
            if p.key == key:
                return p
        raise KeyError(f"no such tunable: {key}")

    def set_value(self, key: str, value: str) -> None:
        self.get(key).set(value)

    def module_toggles(self, manager) -> Dict[str, bool]:
        """Current enabled/disabled state of every discovered module —
        read-only view; use manager.set_enabled(name, bool) to change one,
        exactly like the console's `module <name> <on|off>` command does."""
        return {name: manager.is_enabled(name) for name in sorted(manager.modules)}

    def render(self, manager=None) -> str:
        lines = ["\U0001F39B️  Tuning Sandbox — real runtime knobs", "-" * 78]
        for p in self.PARAMS:
            lines.append(p.render_line())
        if manager is not None:
            lines.append("")
            lines.append("  Modules:")
            for name, enabled in self.module_toggles(manager).items():
                lines.append(f"    [{'x' if enabled else ' '}] {name}")
        return "\n".join(lines)
