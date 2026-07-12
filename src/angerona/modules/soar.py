"""SOAR — Security Orchestration, Automation & Response.

Watches the event stream and runs response *playbooks* when serious events fire.
By default it operates in RECOMMEND mode (it suggests the containment action and
logs it). Set the env var ANGERONA_SOAR_AUTOCONTAIN=1 to let it ACT
automatically — e.g. auto-suspend the offending process on a CRITICAL event.

Auto-containment is opt-in on purpose: automatically freezing processes is
powerful and occasionally wrong, so you choose when to hand it the keys.
"""
from __future__ import annotations

import os
import time
from typing import List

from angerona.core.module_base import BaseModule, Severity

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


# ── G3-B: System32 allowlist ─────────────────────────────────────────────────
# Auto-containment (process suspend) is NEVER applied to processes whose exe
# basename is in this set.  Suspending these would destabilise Windows itself.
_SYSTEM32_NEVER_CONTAIN: frozenset[str] = frozenset({
    "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "svchost.exe",
    "ntoskrnl.exe", "system", "registry",
})

# G3-B: corroboration window — require 2 independent HIGH+ events for the same
# PID within this many seconds before triggering auto-containment.
_CORROBORATION_WINDOW_S = 30.0
_CORROBORATION_MIN      = 2   # signals from ≥2 distinct modules


class SOARModule(BaseModule):
    name = "SOAR Automation"
    description = (
        "Runs response playbooks on serious events (recommend, or opt-in auto-contain). "
        "G3-B: requires 2-signal corroboration and System32 allowlist before auto-act."
    )
    category = "Response"
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        self._last_ts = 0.0
        self._auto = os.environ.get("ANGERONA_SOAR_AUTOCONTAIN", "0") == "1"
        # G3-B corroboration state: pid → [(ts, module), ...]
        self._pending: dict[int, List[tuple[float, str]]] = {}

    def run(self) -> None:
        mode = "AUTO-CONTAIN" if self._auto else "RECOMMEND"
        self.emit(
            f"SOAR online — playbook mode: {mode} "
            "(2-signal corroboration required for auto-contain).",
            Severity.INFO,
        )
        while not self.stopping:
            self.sleep(5)
            if self._bus is None:
                continue
            # refresh the flag so the user can flip it without a restart
            self._auto = os.environ.get("ANGERONA_SOAR_AUTOCONTAIN", "0") == "1"
            for ev in self._bus.recent(25):
                if ev.ts <= self._last_ts or ev.severity < Severity.HIGH:
                    continue
                if ev.module in (self.name, "Console"):
                    continue
                self._last_ts = max(self._last_ts, ev.ts)
                self._run_playbook(ev)
            self._purge_stale_pending()

    # ── Playbooks ────────────────────────────────────────────────────────────
    def _run_playbook(self, ev) -> None:
        pid = ev.details.get("pid")

        # Playbook 1: CRITICAL event tied to a process → corroborate then contain.
        if ev.severity >= Severity.CRITICAL and isinstance(pid, int):
            # G3-B: System32 allowlist check
            if self._is_protected_process(pid):
                self.emit(
                    f"Playbook[contain]: SKIPPED — pid {pid} is a protected "
                    "system process (System32 allowlist). Manual review required.",
                    Severity.HIGH, pid=pid, trigger=ev.module,
                )
                return

            if self._auto:
                # G3-B: accumulate signal; only act when corroborated
                if self._add_signal(pid, ev):
                    self._contain(pid, ev)
                else:
                    self.emit(
                        f"Playbook[contain]: PENDING corroboration for pid {pid} "
                        f"({self._signal_count(pid)}/{_CORROBORATION_MIN} signals, "
                        f"window={_CORROBORATION_WINDOW_S}s). "
                        f"Trigger: {ev.module} — {ev.message[:60]}",
                        Severity.MEDIUM, pid=pid,
                    )
            else:
                self.emit(
                    f"Playbook[contain]: recommend SUSPEND pid {pid} "
                    f"(trigger: {ev.module} — {ev.message[:60]}). "
                    "Set ANGERONA_SOAR_AUTOCONTAIN=1 to auto-act.",
                    Severity.MEDIUM, pid=pid,
                )
            return

        # Playbook 2: any other HIGH+ event → correlate & log for the analyst.
        self.emit(
            f"Playbook[triage]: correlated {ev.severity.label} event from "
            f"{ev.module}. Review in Alerts.",
            Severity.INFO, trigger=ev.module,
        )

    # ── G3-B helpers ─────────────────────────────────────────────────────────
    def _is_protected_process(self, pid: int) -> bool:
        """True if the PID belongs to a never-contain system binary."""
        if psutil is None:
            return False
        try:
            name = psutil.Process(pid).name().lower()
            return name in _SYSTEM32_NEVER_CONTAIN
        except Exception:
            return False

    def _add_signal(self, pid: int, ev) -> bool:
        """Record a signal for *pid*.  Returns True when corroboration threshold
        is reached (≥ _CORROBORATION_MIN distinct modules in the window)."""
        now = time.time()
        if pid not in self._pending:
            self._pending[pid] = []
        self._pending[pid].append((now, ev.module))
        # Count distinct source modules within the window
        in_window = [
            (ts, mod) for ts, mod in self._pending[pid]
            if now - ts <= _CORROBORATION_WINDOW_S
        ]
        distinct_modules = {mod for _, mod in in_window}
        if len(distinct_modules) >= _CORROBORATION_MIN:
            del self._pending[pid]   # consumed — reset for next incident
            return True
        return False

    def _signal_count(self, pid: int) -> int:
        now = time.time()
        return len({
            mod for ts, mod in self._pending.get(pid, [])
            if now - ts <= _CORROBORATION_WINDOW_S
        })

    def _purge_stale_pending(self) -> None:
        now = time.time()
        for pid in list(self._pending):
            self._pending[pid] = [
                (ts, mod) for ts, mod in self._pending[pid]
                if now - ts <= _CORROBORATION_WINDOW_S
            ]
            if not self._pending[pid]:
                del self._pending[pid]

    def _contain(self, pid: int, ev) -> None:
        if psutil is None:
            self.emit("Playbook[contain]: psutil unavailable, cannot act.", Severity.MEDIUM)
            return
        try:
            p = psutil.Process(pid)
            name = p.name()
            p.suspend()
            self.emit(
                f"Playbook[contain]: AUTO-SUSPENDED {name} (pid {pid}) — "
                f"corroborated CRITICAL from {ev.module}. Investigate, then resume/kill.",
                Severity.HIGH, pid=pid,
            )
        except Exception as exc:
            self.emit(
                f"Playbook[contain]: could not suspend pid {pid}: {exc}",
                Severity.MEDIUM, pid=pid,
            )
