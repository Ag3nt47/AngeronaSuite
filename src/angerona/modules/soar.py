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
from angerona.core.process_allowlist import (
    is_event_allowed as _process_event_allowed,
    policy_snapshot as _process_policy_snapshot,
)

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

# ── Under-attack detection ────────────────────────────────────────────────────
# A burst of HIGH+ events across multiple processes in a short window means the
# host is being actively attacked. When that happens we engage ACTIVE DEFENSE:
# corroborated CRITICAL threats are contained automatically even if single-event
# auto-contain is off — the protected-process allowlist and 2-signal corroboration
# still apply, so we never freeze Windows itself.
_ATTACK_WINDOW_S       = 20.0
_ATTACK_MIN_EVENTS     = 4      # HIGH+ events in the window
_ATTACK_MIN_PIDS       = 2      # across at least this many distinct processes
_ACTIVE_DEFENSE_HOLD_S = 60.0   # stay in active-defense this long after a burst


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
        # Active defense: contain corroborated threats automatically WHEN under
        # attack. On by default (the whole point of an EDR); ANGERONA_ACTIVE_DEFENSE=0
        # to disable and stay recommend-only.
        self._active_defense = os.environ.get("ANGERONA_ACTIVE_DEFENSE", "1") != "0"
        # G3-B corroboration state: pid → [(ts, module), ...]
        self._pending: dict[int, List[tuple[float, str]]] = {}
        self._high_events: list = []        # (ts, pid, module) for attack detection
        self._under_attack_until = 0.0
        self._suspended_pids: set[int] = set()
        self._contained = 0                 # remediations actually taken
        self._attempts = 0

    def run(self) -> None:
        mode = ("AUTO-CONTAIN" if self._auto
                else "ACTIVE-DEFENSE" if self._active_defense else "RECOMMEND")
        self.emit(
            f"SOAR online — playbook mode: {mode}. Corroborated threats are contained "
            "automatically while under attack; 2-signal corroboration + protected-process "
            "allowlist are always enforced.",
            Severity.INFO,
        )
        while not self.stopping:
            self.sleep(5)
            if self._bus is None:
                continue
            # refresh the flags so the user can flip them without a restart
            self._auto = os.environ.get("ANGERONA_SOAR_AUTOCONTAIN", "0") == "1"
            self._active_defense = os.environ.get("ANGERONA_ACTIVE_DEFENSE", "1") != "0"
            process_policy = _process_policy_snapshot()
            for ev in self._bus.recent(25):
                if ev.ts <= self._last_ts or ev.severity < Severity.HIGH:
                    continue
                if ev.module in (self.name, "Console"):
                    continue
                self._last_ts = max(self._last_ts, ev.ts)
                if _process_event_allowed(ev, policy=process_policy):
                    continue
                self._track_attack(ev)
                self._run_playbook(ev)
            self._purge_stale_pending()
            self._write_stats()

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

            # Act automatically when explicitly enabled OR when we are under
            # active attack (a burst of corroborated threats). Otherwise recommend.
            act_now = self._auto or (self._active_defense and self._under_attack())
            if act_now:
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
                    "Active defense engages automatically under attack; set "
                    "ANGERONA_SOAR_AUTOCONTAIN=1 to always auto-act.",
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
        self._attempts += 1
        try:
            p = psutil.Process(pid)
            name = p.name()
            if pid in self._suspended_pids:
                # Already suspended once and still corroborating → escalate to KILL.
                p.kill()
                self._contained += 1
                self._suspended_pids.discard(pid)
                self.emit(
                    f"Playbook[contain]: TERMINATED {name} (pid {pid}) — repeat corroborated "
                    f"threat from {ev.module}. Active defense.",
                    Severity.HIGH, pid=pid, action="terminate", mitre="T1562",
                    trigger_ts=ev.ts, trigger_module=ev.module)
            else:
                p.suspend()
                self._suspended_pids.add(pid)
                self._contained += 1
                self._network_block(pid, name)   # isolate its outbound too
                self.emit(
                    f"Playbook[contain]: AUTO-SUSPENDED {name} (pid {pid}) — corroborated "
                    f"CRITICAL from {ev.module}. Investigate, then resume/kill.",
                    Severity.HIGH, pid=pid, action="suspend",
                    trigger_ts=ev.ts, trigger_module=ev.module)
        except Exception as exc:
            self.emit(
                f"Playbook[contain]: could not act on pid {pid}: {exc}",
                Severity.MEDIUM, pid=pid,
            )

    # ── under-attack detection + active-defense state ────────────────────────
    def _track_attack(self, ev) -> None:
        """Record a HIGH+ event and, on a multi-process burst, declare UNDER ATTACK
        so active defense engages automatically."""
        now = time.time()
        pid = ev.details.get("pid")
        self._high_events.append((now, pid, ev.module))
        self._high_events = [(t, p, m) for (t, p, m) in self._high_events
                             if now - t <= _ATTACK_WINDOW_S]
        pids = {p for (_t, p, _m) in self._high_events if isinstance(p, int)}
        if len(self._high_events) >= _ATTACK_MIN_EVENTS and len(pids) >= _ATTACK_MIN_PIDS:
            if now >= self._under_attack_until:      # newly entering attack state
                self.emit(
                    f"⚠ UNDER ATTACK — {len(self._high_events)} high-severity events across "
                    f"{len(pids)} process(es) in {int(_ATTACK_WINDOW_S)}s. Active defense engaged: "
                    "corroborated threats will be contained automatically.",
                    Severity.CRITICAL, under_attack=True, pids=sorted(pids))
            self._under_attack_until = now + _ACTIVE_DEFENSE_HOLD_S

    def _under_attack(self) -> bool:
        return time.time() < self._under_attack_until

    def _write_stats(self) -> None:
        """Persist remediation stats so the dashboard shows a non-zero figure and
        an operator can see what active defense has done."""
        try:
            import json
            from pathlib import Path
            from angerona.core.data_paths import data_dir
            root = data_dir() / "shared_logs"
            root.mkdir(parents=True, exist_ok=True)
            (root / "remediation_stats.json").write_text(json.dumps({
                "contained": self._contained,
                "attempts": self._attempts,
                "active_defense": self._active_defense,
                "under_attack": self._under_attack(),
                "ts": time.time(),
            }, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _network_block(self, pid: int, name: str) -> None:
        """Active isolation: block the offending program's OUTBOUND traffic via the
        Windows firewall so it can't reach its C2 even if it's later resumed. This
        is what turns a "suspend" into real containment. Best-effort, Windows-only,
        runs hidden. The rule name is tagged so it's easy to find/remove afterward."""
        if os.name != "nt" or psutil is None:
            return
        try:
            exe = psutil.Process(pid).exe()
        except Exception:
            exe = ""
        if not exe:
            return
        try:
            from angerona.core.win import run_hidden
            rule = f"Angerona-Isolate-{name}-{pid}"
            run_hidden([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule}", "dir=out", "action=block",
                f"program={exe}", "enable=yes",
            ], timeout=10)
            self.emit(
                f"Playbook[isolate]: OUTBOUND NETWORK BLOCKED for {name} (pid {pid}, {exe}). "
                "It can no longer reach a C2 server. Remove the firewall rule "
                f"'{rule}' after investigation.",
                Severity.HIGH, pid=pid, action="network_block", rule=rule)
        except Exception as exc:
            self.emit(
                f"Playbook[isolate]: could not block network for pid {pid}: {exc}",
                Severity.LOW, pid=pid)
