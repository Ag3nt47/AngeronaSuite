"""soar_engine.py — The Active Response SOAR Engine.

A stronger, opt-in-gated autonomous response tier sitting alongside the
existing "SOAR Automation" module (soar.py). Where that module recommends,
or (opt-in) *suspends*, a process on a CRITICAL event, this one performs a
full terminate-and-rollback: kill the offending process AND remove the
exact file artifact the triggering alert pointed at.

Origin-blind by design: this module only ever reacts to real EventBus
alerts that the OTHER detection modules already raised on their own. It
never reads shark_history.json, or anything else that would tell it "this
is a drill" — that's what keeps a Shark Attack run an honest end-to-end
test of the whole pipeline, not a rigged one. It is a normal, always-on
module exactly like every other capability in modules/; nothing about it is
specific to testing.

Disabled-by-default for the same reason the existing SOAR module's
auto-contain is opt-in: automatically killing processes is powerful and
occasionally wrong. Set ANGERONA_SOAR_KILL_AND_ROLLBACK=1 to arm it. The
Shark Attack "Initiate" button arms it for the duration of one test run and
restores your previous setting afterward (see gui/main_window.py).

Even armed, the response threshold defaults to CRITICAL only — a MEDIUM
"new file created" alert from File Integrity Monitor is a low-confidence
signal on its own (FIM has no way to know if a new file is malicious), so
auto-deleting on it by default would be trigger-happy. Set
ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY=HIGH (or MEDIUM) to lower the
bar — useful when you deliberately want to test a more aggressive policy
during a drill, without changing the real-world default.
"""
from __future__ import annotations

import os
import re
import sys
import time
import zipfile
from pathlib import Path

from angerona.core.archive_safety import read_bounded_member, validate_zip_members
from angerona.core.eventbus import is_remote_observe_only
from angerona.core.module_base import BaseModule, Severity
from angerona.core.threat import event_disposition
from angerona.core.process_allowlist import (
    is_event_allowed as _process_event_allowed,
    policy_snapshot as _process_policy_snapshot,
)

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


class ActiveResponseSOAR(BaseModule):
    name = "Active Response SOAR"
    description = "Opt-in: terminates the offending process and rolls back its file artifact on real CRITICAL alerts."
    category = "Response"
    enabled_by_default = True  # idles harmlessly unless armed — see _armed()

    def __init__(self) -> None:
        super().__init__()
        self._last_ts = 0.0
        self._seen_at_last_ts: set[str] = set()
        self._priority_cursor = 0
        self._priority_bus_id: int | None = None
        self._priority_overflow_count = 0
        self._general_cursor = 0
        self._manager = None

    def bind_manager(self, manager) -> None:
        self._manager = manager

    @staticmethod
    def _armed() -> bool:
        return os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK", "0") == "1"

    @staticmethod
    def _min_severity() -> Severity:
        name = os.environ.get(
            "ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "CRITICAL"
        ).strip().upper()
        try:
            return Severity[name]
        except KeyError:
            return Severity.CRITICAL  # unknown value — fail conservative, not permissive

    def self_test(self) -> tuple[bool, str]:
        armed = self._armed()
        ok = self.status == "running"
        state = f"ARMED (min severity {self._min_severity().label})" if armed else \
                "idle (set ANGERONA_SOAR_KILL_AND_ROLLBACK=1 to arm)"
        return ok, f"running, {state}"

    def run(self) -> None:
        self.set_health(100, "")
        self.emit("Active Response SOAR online (idle unless armed via "
                  "ANGERONA_SOAR_KILL_AND_ROLLBACK).", Severity.INFO)
        while not self.stopping:
            self.sleep(2)
            self.process_pending_once()

    @staticmethod
    def _cursor_key(ev) -> str:
        """Stable identity for events sharing a timestamp in the bounded ring."""
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

    def _pending_security_events(self) -> tuple[list, bool]:
        """Fetch response evidence without exposing HIGH+ to INFO eviction.

        Priority-lane overflow is reported as health degradation only.  It
        never creates a synthetic response event and therefore cannot grant
        kill/rollback authority. The general lane remains the data source so
        the operator's opt-in MEDIUM threshold continues to work.
        """
        bus = self._bus
        priority_since = getattr(bus, "priority_since", None)
        recent_since = getattr(bus, "recent_since", None)
        if bus is not None and callable(priority_since) and callable(recent_since):
            bus_id = id(bus)
            if self._priority_bus_id != bus_id:
                self._priority_bus_id = bus_id
                self._priority_cursor = 0
                self._general_cursor = 0
            # Active Response supports an explicit MEDIUM threshold. Consume
            # the general revision delta so that option keeps its historical
            # behavior; EventBus.recent_since transparently merges retained
            # HIGH/CRITICAL priority evidence after an INFO-ring overflow.
            general_current, newest_first, _general_overflow = recent_since(
                self._general_cursor
            )
            self._general_cursor = general_current
            priority_current, _priority_events, overflow = priority_since(
                self._priority_cursor
            )
            self._priority_cursor = priority_current
            if overflow:
                self._priority_overflow_count += 1
                self.emit(
                    "Active-response priority event lane overflowed; retained "
                    "signed evidence will be reviewed, but overflow alone "
                    "cannot authorize kill/rollback.",
                    Severity.HIGH,
                    disposition="health",
                    event_type="security_lane_overflow",
                    response_authorized=False,
                )
            return list(reversed(newest_first)), False
        events = list(reversed(bus.recent(250))) if bus is not None else []
        events.sort(key=lambda event: event.ts)
        return events, True

    def process_pending_once(self) -> int:
        """Evaluate one response batch in publication order.

        ``EventBus.recent`` is newest-first.  Advancing a timestamp watermark
        while iterating that order discarded every older alert in the same
        scanner burst.  Work oldest-first and advance only after each event has
        been evaluated, so an unrelated newest event cannot suppress the rest.
        """
        if self._bus is None or not self._armed():
            return 0
        floor = self._min_severity()
        process_policy = _process_policy_snapshot()
        events, legacy_cursor = self._pending_security_events()
        actions = 0
        for ev in events:
            if legacy_cursor and not self._is_unseen(ev):
                continue
            try:
                if ev.severity < floor:
                    continue
                if ev.module in (self.name, "Console", "SOAR Automation"):
                    continue
                if is_remote_observe_only(ev):
                    continue
                if _process_event_allowed(ev, policy=process_policy):
                    continue
                if event_disposition(ev) not in {"active", "practice"}:
                    continue
                if not self._event_in_response_scope(ev):
                    continue
                self._kill_and_rollback(ev)
                actions += 1
            finally:
                if legacy_cursor:
                    self._advance_cursor(ev)
        return actions

    # ── Response playbook ────────────────────────────────────────────────
    @staticmethod
    def _event_path(ev) -> str:
        details = getattr(ev, "details", {}) or {}
        for key in ("path", "artifact_path", "exe", "process_path", "image"):
            value = details.get(key)
            if value:
                return str(value)
        return ""

    @staticmethod
    def _scope_roots() -> tuple[Path, ...]:
        raw = os.environ.get("ANGERONA_SOAR_RESPONSE_SCOPE", "").strip()
        if not raw:
            return ()
        roots = []
        for value in raw.split(os.pathsep):
            try:
                roots.append(Path(value.strip()).expanduser().resolve(strict=False))
            except (OSError, RuntimeError, ValueError):
                continue
        return tuple(roots)

    @staticmethod
    def _inside(path: Path, roots: tuple[Path, ...]) -> bool:
        try:
            resolved = path.resolve(strict=False)
            return any(resolved == root or root in resolved.parents for root in roots)
        except (OSError, RuntimeError, ValueError):
            return False

    @staticmethod
    def _is_known_drill_artifact(path: Path) -> bool:
        """Prove a scoped file is one of Angerona's inert drill markers."""
        name = path.name.casefold()
        if name.startswith(("_redteam_", "_shark_")):
            return True
        try:
            if path.suffix.casefold() == ".zip":
                with zipfile.ZipFile(path) as archive:
                    members = validate_zip_members(
                        archive.infolist(),
                        max_files=20,
                        max_member_bytes=262_144,
                        max_total_bytes=5 * 1024 * 1024,
                        max_ratio=100,
                    )
                    for member in members:
                        sample = read_bounded_member(
                            archive,
                            member,
                            max_bytes=262_144,
                        )
                        if b"Angerona Shark Attack drill sample" in sample:
                            return True
                return False
            if path.stat().st_size > 262_144:
                return False
            sample = path.read_bytes()
        except (OSError, ValueError, zipfile.BadZipFile):
            return False
        return any(
            marker in sample
            for marker in (
                b"Angerona Shark Attack drill sample",
                b"simulated persistence artifact",
                b"ANGERONA custom drill marker",
                b"simulated BYOVD driver drop",
            )
        )

    def _event_in_response_scope(self, ev) -> bool:
        """Require Combat's exact contract and constrain temporary drill arming."""
        try:
            from angerona.modules.adversary_combat import AdversaryCombat

            if AdversaryCombat._response_actions(ev) is None:
                return False
        except Exception:
            return False
        roots = self._scope_roots()
        if not roots:
            # Permanent response is allowed only through an already-running
            # Combat consumer.  With no protected drill root there is no local
            # fallback and therefore no legacy kill/unlink capability.
            try:
                combat = getattr(self._manager, "modules", {}).get("Adversary Combat")
            except Exception:
                combat = None
            return combat is not None and getattr(combat, "status", "stopped") == "running"
        details = getattr(ev, "details", {}) or {}
        command = str(details.get("cmdline") or details.get("command_line") or "")
        if re.search(r"\bANGERONA_REDTEAM_[0-9a-f]{8}\b", command, re.I):
            return True
        raw_path = self._event_path(ev)
        if not raw_path:
            return False
        path = Path(raw_path)
        return self._inside(path, roots) and self._is_known_drill_artifact(path)

    def _event_integrity_ok(self, ev) -> bool:
        """Re-verify authenticated evidence immediately before host mutation."""
        bus = self._bus
        if bus is None or not getattr(bus, "integrity_enabled", False):
            return True
        try:
            return bool(bus.verify(ev))
        except Exception:
            return False

    def _kill_and_rollback(self, ev) -> None:
        if not self._event_integrity_ok(ev):
            self.emit(
                "Refusing kill/rollback: event integrity verification failed.",
                Severity.HIGH,
            )
            return
        if is_remote_observe_only(ev):
            self.emit(
                "Refusing local kill/rollback for observe-only cross-host evidence.",
                Severity.INFO,
            )
            return
        if not self._event_in_response_scope(ev):
            self.emit(
                "Refusing kill/rollback: event is outside the authorized response scope.",
                Severity.INFO,
            )
            return
        t0 = time.time()
        pid = ev.details.get("pid")
        path = self._event_path(ev) or None
        if not self._exact_process_binding_ok(ev):
            self.emit(
                "Refusing kill/rollback: process contract is not bound to the "
                "live PID/create-time/executable instance.",
                Severity.HIGH,
                pid=pid if isinstance(pid, int) else None,
            )
            return

        combat, synchronous = self._combat_consumer(ev)
        if combat is None:
            self.emit(
                "Refusing kill/rollback: hardened Adversary Combat consumer is unavailable.",
                Severity.HIGH,
                pid=pid if isinstance(pid, int) else None,
                path=path,
            )
            return

        before = self._matching_combat_receipts(combat, ev)
        try:
            if synchronous:
                combat._handle(ev)
            else:
                combat._submit(ev)
        except Exception as exc:
            self.emit(
                f"Combat delegation failed safely: {exc}",
                Severity.HIGH,
                pid=pid if isinstance(pid, int) else None,
                path=path,
            )
            return
        receipts = self._matching_combat_receipts(combat, ev)
        if not synchronous and len(receipts) <= len(before):
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                time.sleep(0.05)
                receipts = self._matching_combat_receipts(combat, ev)
                if len(receipts) > len(before):
                    break
        applied = receipts[len(before):] if len(receipts) > len(before) else receipts
        mitigated = bool(applied)

        elapsed = round(time.time() - t0, 3)
        self.emit(
            f"Exact response for {ev.module} {ev.severity.label} was delegated "
            f"to Combat: {len(applied)} signed action receipt(s), {elapsed}s.",
            Severity.HIGH if mitigated else Severity.MEDIUM,
            pid=pid,
            response_target_path=path,
            mitigated=mitigated,
            combat_action_ids=[str(row.get("action_id") or "") for row in applied],
            mitigation_seconds=elapsed, trigger_module=ev.module, trigger_ts=ev.ts,
        )

    @staticmethod
    def _exact_process_binding_ok(ev) -> bool:
        """Bind any process action to PID, creation time, and executable."""
        try:
            from angerona.modules.adversary_combat import AdversaryCombat

            actions = AdversaryCombat._response_actions(ev)
        except Exception:
            return False
        if not actions:
            return False
        process_actions = actions.intersection(
            {"isolate_program", "suspend_process", "terminate_process"}
        )
        if not process_actions:
            return True
        details = ev.details if isinstance(ev.details, dict) else {}
        pid = details.get("pid")
        raw_exe = details.get("exe") or details.get("process_path") or details.get("image")
        if (
            not raw_exe
            and os.environ.get("ANGERONA_SOAR_RESPONSE_SCOPE", "").strip()
        ):
            command = str(details.get("cmdline") or details.get("command_line") or "")
            if (
                re.search(r"\bANGERONA_REDTEAM_[0-9a-f]{8}\b", command, re.I)
                and command.startswith(f"{sys.executable} ")
            ):
                raw_exe = sys.executable
        if not isinstance(pid, int) or pid <= 0 or not isinstance(raw_exe, str) or not raw_exe:
            return False
        if pid in {os.getpid(), os.getppid()} or psutil is None:
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

    def _combat_consumer(self, ev):
        """Return the shared Combat sink, or an isolated practice-only sink."""
        try:
            combat = getattr(self._manager, "modules", {}).get("Adversary Combat")
        except Exception:
            combat = None
        if combat is not None and getattr(combat, "status", "stopped") == "running":
            return combat, False

        roots = self._scope_roots()
        # This fallback exists only while the explicit protected drill scope is
        # active. ``_event_in_response_scope`` has already proven the exact
        # marker or registered command token; no unscoped permanent mutation is
        # available through this legacy module.
        if len(roots) != 1:
            return None, False
        try:
            from angerona.modules.adversary_combat import AdversaryCombat

            combat = AdversaryCombat(roots[0].parent)
            combat.bind(self._bus)
            return combat, True
        except Exception:
            return None, False

    @staticmethod
    def _matching_combat_receipts(combat, ev) -> list[dict]:
        try:
            rows = combat.list_actions(limit=250)
        except Exception:
            return []
        matched = []
        for row in rows:
            try:
                same_ts = abs(float(row.get("trigger_ts")) - float(ev.ts)) < 0.000001
            except (TypeError, ValueError, OverflowError):
                same_ts = False
            if (
                same_ts
                and row.get("trigger_module") == ev.module
                and row.get("integrity_status") == "verified"
                and row.get("status") == "applied"
            ):
                matched.append(row)
        return matched
