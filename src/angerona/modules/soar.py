"""SOAR — Security Orchestration, Automation & Response.

Watches the event stream and runs response *playbooks* when serious events fire.
By default it operates in RECOMMEND mode (it suggests the containment action and
logs it). Set the env var ANGERONA_SOAR_AUTOCONTAIN=1 to let it request an
automatic action from the hardened Adversary Combat response sink.

Auto-containment is opt-in on purpose: automatically freezing processes is
powerful and occasionally wrong, so you choose when to hand it the keys.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import List

from angerona.core.module_base import BaseModule, Severity
from angerona.core.eventbus import is_remote_observe_only
from angerona.core.threat import event_disposition
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
    version = "1.12.1"
    supported_platforms = ("windows",)
    capability_mode = "respond"
    capability_inputs = ("authenticated-high-severity-event", "operator-response-policy")
    capability_outputs = ("typed-process-suspension-request", "response-receipt")
    capability_permissions = ("process-inspection", "process-suspend")
    high_risk_permissions = ("process-suspend",)
    data_classes = ("process-identity", "security-finding", "response-decision")
    egress = "none"
    retention = "bounded-memory-correlation-and-local-receipts"
    response_authority = "typed-response"
    restart_policy = "bounded-three-attempt-backoff-quarantine"
    loss_behavior = "priority-revision-gap-degrades-and-never-authorizes"
    resource_budget = {
        "worker_model": "single-lifecycle-thread",
        "event_delivery": "bounded-priority-revision-best-effort",
        "startup_cycle_timeout_seconds": 30.0,
    }
    settings_schema = {
        "type": "object",
        "properties": {
            "auto_contain": {"type": "boolean", "default": False},
            "active_defense": {"type": "boolean", "default": False},
        },
        "additionalProperties": False,
    }
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        self._last_ts = 0.0
        self._seen_at_last_ts: set[str] = set()
        self._priority_cursor = 0
        self._priority_bus_id: int | None = None
        self._priority_overflow_count = 0
        self._auto = os.environ.get("ANGERONA_SOAR_AUTOCONTAIN", "0") == "1"
        # Active defense: contain corroborated threats automatically WHEN under
        # attack. On by default (the whole point of an EDR); ANGERONA_ACTIVE_DEFENSE=0
        # to disable and stay recommend-only.
        self._active_defense = os.environ.get("ANGERONA_ACTIVE_DEFENSE", "0") == "1"
        # G3-B corroboration state is bound to one exact process generation.
        # A PID alone is reusable and must never let signals for a dead process
        # authorize a response against a later process that inherited the PID.
        self._pending: dict[tuple[int, int, str], List[tuple[float, str]]] = {}
        self._high_events: list = []        # (ts, pid, module) for attack detection
        self._under_attack_until = 0.0
        self._contained = 0                 # remediations actually taken
        self._attempts = 0
        self._manager = None
        self._delivery_failures: dict[str, int] = {}
        self._dead_lettered = 0

    def bind_manager(self, manager) -> None:
        self._manager = manager

    def self_test(self) -> tuple[bool, str]:
        """Validate corroboration and cursor safety without executing a response."""
        class _Fixture:
            def __init__(self, module: str, ts: float = 100.0) -> None:
                self.module = module
                self.ts = ts
                self.hmac_sig = f"sig-{module}"

        original_pending = self._pending
        original_last = self._last_ts
        original_seen = self._seen_at_last_ts
        try:
            self._pending = {}
            sensor_a = _Fixture("sensor-a")
            sensor_b = _Fixture("sensor-b")
            for fixture in (sensor_a, sensor_b):
                fixture.details = {
                    "pid": 4242,
                    "process_create_time": 100.25,
                    "exe": os.path.abspath("self-test.exe"),
                }
            first = self._add_signal(4242, sensor_a)
            repeat = self._add_signal(4242, sensor_a)
            corroborated = self._add_signal(4242, sensor_b)
            event = _Fixture("cursor-source")
            unseen_before = self._is_unseen(event)
            self._advance_cursor(event)
            unseen_after = self._is_unseen(event)
            ok = (
                not first and not repeat and corroborated
                and unseen_before and not unseen_after
                and "lsass.exe" in _SYSTEM32_NEVER_CONTAIN
                and _CORROBORATION_MIN >= 2
            )
        finally:
            self._pending = original_pending
            self._last_ts = original_last
            self._seen_at_last_ts = original_seen
        return (
            ok,
            "offline distinct-source corroboration, cursor, and protected-process gates passed"
            if ok else "SOAR safety fixture failed",
        )

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
            self.sleep(5, cycle_complete=False)
            # refresh the flags so the user can flip them without a restart
            self._auto = os.environ.get("ANGERONA_SOAR_AUTOCONTAIN", "0") == "1"
            self._active_defense = os.environ.get("ANGERONA_ACTIVE_DEFENSE", "0") == "1"
            self.process_pending_once()
            self._purge_stale_pending()
            self._write_stats()
            self.mark_cycle_complete()

    @staticmethod
    def _cursor_key(ev) -> str:
        signature = str(getattr(ev, "hmac_sig", "") or "")
        return signature or f"memory:{id(ev)}"

    def _is_unseen(self, ev) -> bool:
        if ev.ts < self._last_ts:
            return False
        return not (
            ev.ts == self._last_ts
            and self._cursor_key(ev) in self._seen_at_last_ts
        )

    def _advance_cursor(self, ev) -> None:
        key = self._cursor_key(ev)
        if ev.ts > self._last_ts:
            self._last_ts = ev.ts
            self._seen_at_last_ts = {key}
        elif ev.ts == self._last_ts:
            self._seen_at_last_ts.add(key)

    @property
    def priority_overflow_count(self) -> int:
        return self._priority_overflow_count

    def _pending_security_events(self) -> tuple[list[tuple[int | None, object]], bool]:
        """Fetch serious events from the dedicated bounded revision lane.

        The boolean is true when the EventBus does not expose the priority API
        and the legacy timestamp cursor must be used.  An overflow emits suite
        health only: it never synthesizes evidence or authorizes containment.
        """
        bus = self._bus
        priority_records_since = getattr(bus, "priority_records_since", None)
        priority_since = getattr(bus, "priority_since", None)
        if bus is not None and callable(priority_records_since):
            bus_id = id(bus)
            if self._priority_bus_id != bus_id:
                self._priority_bus_id = bus_id
                self._priority_cursor = 0
            _current, newest_first, overflow = priority_records_since(
                self._priority_cursor
            )
            if overflow:
                self._priority_overflow_count += 1
                self.emit(
                    "SOAR priority event lane overflowed; retained signed "
                    "evidence will be reviewed, but overflow alone cannot "
                    "authorize containment.",
                    Severity.HIGH,
                    disposition="health",
                    event_type="security_lane_overflow",
                    response_authorized=False,
                )
            return list(reversed(newest_first)), False
        if bus is not None and callable(priority_since):
            _current, newest_first, overflow = priority_since(self._priority_cursor)
            if overflow:
                self._priority_overflow_count += 1
            return [(None, event) for event in reversed(newest_first)], True
        events = list(reversed(bus.recent(250))) if bus is not None else []
        events.sort(key=lambda event: event.ts)
        return [(None, event) for event in events], True

    def _process_one_event(self, ev, process_policy) -> bool:
        if ev.severity < Severity.HIGH:
            return False
        if ev.module in (self.name, "Console", "Active Response SOAR Request"):
            return False
        if is_remote_observe_only(ev):
            return False
        if _process_event_allowed(ev, policy=process_policy):
            return False
        disposition = event_disposition(ev)
        if disposition not in {"active", "practice"}:
            return False
        if disposition == "active":
            self._track_attack(ev)
        self._run_playbook(ev)
        return True

    def _commit_delivery(self, revision: int | None, ev, legacy_cursor: bool) -> None:
        if legacy_cursor or revision is None:
            self._advance_cursor(ev)
        else:
            self._priority_cursor = int(revision)

    def process_pending_once(self) -> int:
        """Evaluate the bounded alert batch oldest-first without dropping bursts."""
        if self._bus is None:
            return 0
        process_policy = _process_policy_snapshot()
        events, legacy_cursor = self._pending_security_events()
        handled = 0
        for revision, ev in events:
            if legacy_cursor and not self._is_unseen(ev):
                continue
            try:
                handled += int(self._process_one_event(ev, process_policy))
            except Exception as exc:
                key = self._cursor_key(ev)
                attempts = self._delivery_failures.get(key, 0) + 1
                self._delivery_failures[key] = attempts
                self.last_error = str(exc)
                if attempts < 3:
                    self.set_health(
                        45,
                        f"SOAR event delivery failed ({attempts}/3); cursor retained: {exc}",
                    )
                    break
                self._delivery_failures.pop(key, None)
                self._dead_lettered += 1
                self.set_health(
                    35,
                    f"{self._dead_lettered} SOAR event(s) dead-lettered after 3 failures",
                )
                self.emit(
                    "SOAR event moved to bounded dead-letter state after repeated "
                    "processing failure; later events remain eligible.",
                    Severity.HIGH,
                    event_type="soar_delivery_dead_letter",
                    failed_event_id=key,
                    response_authorized=False,
                )
                self._commit_delivery(revision, ev, legacy_cursor)
                continue
            self._delivery_failures.pop(self._cursor_key(ev), None)
            self._commit_delivery(revision, ev, legacy_cursor)
        return handled

    # ── Playbooks ────────────────────────────────────────────────────────────
    def _event_integrity_ok(self, ev) -> bool:
        """Re-verify authenticated evidence at the response action sink.

        ``Event`` is frozen, but its legacy ``details`` mapping is mutable. A
        buggy in-process subscriber can therefore invalidate a previously
        signed event after publication. Production buses are armed, so refuse
        automatic response when that final integrity check fails. Unarmed test
        and development buses retain their established behavior.
        """
        bus = self._bus
        if bus is None or not getattr(bus, "integrity_enabled", False):
            return True
        try:
            return bool(bus.verify(ev))
        except Exception:
            return False

    def _run_playbook(self, ev) -> None:
        if not self._event_integrity_ok(ev):
            self.emit(
                "Playbook refused: event integrity verification failed before response.",
                Severity.HIGH,
            )
            return
        if is_remote_observe_only(ev):
            self.emit(
                "Playbook[remote]: observe-only cross-host evidence; local process "
                "containment is forbidden.",
                Severity.INFO,
            )
            return
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
                if not self._exact_process_contract_ok(ev):
                    self.emit(
                        f"Playbook[contain]: REFUSED pid {pid} — automatic response "
                        "requires an exact PID/create-time/executable contract.",
                        Severity.HIGH,
                        pid=pid,
                        action_succeeded=False,
                        response_authorized=False,
                    )
                    return
                # G3-B: accumulate signal; only act when corroborated
                if self._add_signal(pid, ev):
                    self._contain(pid, ev)
                else:
                    self.emit(
                        f"Playbook[contain]: PENDING corroboration for pid {pid} "
                        f"({self._signal_count(pid, ev)}/{_CORROBORATION_MIN} signals, "
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

    @staticmethod
    def _signal_identity(pid: int, ev) -> tuple[int, int, str] | None:
        """Return a stable exact-process key from authenticated event evidence."""
        details = getattr(ev, "details", None)
        if not isinstance(details, dict) or details.get("pid") != pid:
            return None
        raw_exe = details.get("exe") or details.get("process_path") or details.get("image")
        try:
            created_us = int(round(float(details.get("process_create_time")) * 1_000_000))
        except (TypeError, ValueError, OverflowError):
            return None
        if pid <= 0 or created_us <= 0 or not isinstance(raw_exe, str) or not raw_exe:
            return None
        try:
            executable = os.path.normcase(str(Path(raw_exe).resolve(strict=False)))
        except (OSError, RuntimeError, ValueError):
            return None
        return pid, created_us, executable

    def _add_signal(self, pid: int, ev) -> bool:
        """Corroborate one exact process generation across distinct modules."""
        now = time.time()
        identity = self._signal_identity(pid, ev)
        if identity is None:
            return False
        if identity not in self._pending:
            self._pending[identity] = []
        self._pending[identity].append((now, ev.module))
        # Count distinct source modules within the window
        in_window = [
            (ts, mod) for ts, mod in self._pending[identity]
            if now - ts <= _CORROBORATION_WINDOW_S
        ]
        distinct_modules = {mod for _, mod in in_window}
        if len(distinct_modules) >= _CORROBORATION_MIN:
            del self._pending[identity]   # consumed — reset for this generation
            return True
        return False

    def _signal_count(self, pid: int, ev=None) -> int:
        now = time.time()
        identity = self._signal_identity(pid, ev) if ev is not None else None
        if identity is None:
            return 0
        return len({
            mod for ts, mod in self._pending.get(identity, [])
            if now - ts <= _CORROBORATION_WINDOW_S
        })

    def _purge_stale_pending(self) -> None:
        now = time.time()
        for identity in list(self._pending):
            self._pending[identity] = [
                (ts, mod) for ts, mod in self._pending[identity]
                if now - ts <= _CORROBORATION_WINDOW_S
            ]
            if not self._pending[identity]:
                del self._pending[identity]

    def _contain(self, pid: int, ev) -> None:
        """Delegate exact-target containment to the journaled Combat sink.

        This legacy module deliberately has no direct process/firewall mutation
        path.  Combat owns PID identity revalidation, intent/commit records,
        postconditions, recovery, and undo.
        """
        self._attempts += 1
        if not self._exact_process_contract_ok(ev):
            self.emit(
                f"Playbook[contain]: REFUSED pid {pid} — exact process "
                "identity changed before delegation.",
                Severity.HIGH,
                pid=pid,
                action_succeeded=False,
                response_authorized=False,
            )
            return
        combat = None
        try:
            combat = (
                getattr(self._manager, "modules", {}).get("Adversary Combat")
                if self._manager is not None
                else None
            )
        except Exception:
            combat = None
        if combat is None or getattr(combat, "status", "stopped") != "running":
            self.emit(
                f"Playbook[contain]: REFUSED pid {pid} — hardened Adversary "
                "Combat consumer is unavailable.",
                Severity.HIGH,
                pid=pid,
                action_succeeded=False,
                response_authorized=False,
            )
            return
        submit = getattr(combat, "_submit", None)
        if not callable(submit):
            self.emit(
                f"Playbook[contain]: REFUSED pid {pid} — response consumer "
                "does not expose the authenticated queue.",
                Severity.HIGH,
                pid=pid,
                action_succeeded=False,
                response_authorized=False,
            )
            return
        submit(ev)
        self.emit(
            f"Playbook[contain]: queued exact process instance pid {pid} for "
            "Adversary Combat; only Combat's signed completion receipt counts as success.",
            Severity.INFO,
            pid=pid,
            action="combat_delegate",
            trigger_ts=ev.ts,
            trigger_module=ev.module,
            action_succeeded=False,
            action_pending=True,
            response_authorized=False,
        )

    @staticmethod
    def _exact_process_contract_ok(ev) -> bool:
        """Require and locally preflight Combat's exact process contract."""
        try:
            from angerona.modules.adversary_combat import AdversaryCombat

            actions = AdversaryCombat._response_actions(ev)
        except Exception:
            return False
        if not actions or not actions.intersection(
            {"isolate_program", "suspend_process", "terminate_process"}
        ):
            return False
        details = ev.details if isinstance(ev.details, dict) else {}
        pid = details.get("pid")
        raw_exe = details.get("exe") or details.get("process_path") or details.get("image")
        if not isinstance(pid, int) or pid <= 0 or not isinstance(raw_exe, str) or not raw_exe:
            return False
        if psutil is None:
            return False
        try:
            expected_created = float(details.get("process_create_time"))
            process = psutil.Process(pid)
            actual_created = float(process.create_time())
            actual_exe = os.path.normcase(str(Path(process.exe()).resolve(strict=False)))
            expected_exe = os.path.normcase(str(Path(raw_exe).resolve(strict=False)))
        except (OSError, RuntimeError, TypeError, ValueError, OverflowError):
            return False
        return abs(actual_created - expected_created) <= 0.001 and actual_exe == expected_exe

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
