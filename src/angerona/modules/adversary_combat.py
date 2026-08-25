"""Unattended adversary containment with durable, reversible action receipts.

``AdversaryCombat`` is the standing-authority response tier.  It consumes
authenticated local detector events and acts immediately; it never opens an
approval dialog.  The operator chooses the policy once in Settings and can
later change it or undo reversible actions.

Maximum mode intentionally accepts availability risk.  Evidence is still
bound to the exact process, file, executable, or remote address named by the
detector so a response cannot drift onto an unrelated target.
"""
from __future__ import annotations

import ipaddress
import json
import os
import queue
import shutil
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from angerona.core.data_paths import data_dir as canonical_data_dir
from angerona.core.eventbus import Event, Severity, is_remote_observe_only
from angerona.core.module_base import BaseModule
from angerona.core.threat import event_disposition

try:
    import psutil
except Exception:  # pragma: no cover - the module still blocks/quarantines
    psutil = None


_TRUE = frozenset({"1", "true", "yes", "on"})
_MODES = frozenset({"contain", "aggressive", "maximum"})
_PROCESS_ACTIONS = frozenset({"suspend", "terminate"})
_SELF_MODULES = frozenset({
    "Adversary Combat",
    "Active Response SOAR",
    "SOAR Automation",
    "Console",
})
_REMOTE_FIELDS = (
    "remote_ip", "destination_ip", "dest_ip", "dst_ip", "ip", "raddr",
)
_PATH_FIELDS = ("path", "artifact_path", "file_path", "exe", "process_path", "image")


def _bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().casefold() in _TRUE


def _severity(value: object, default: Severity = Severity.LOW) -> Severity:
    text = str(value or default.name).strip().upper()
    try:
        return Severity[text]
    except KeyError:
        return default


@dataclass(frozen=True)
class CombatPolicy:
    enabled: bool = True
    mode: str = "maximum"
    min_severity: Severity = Severity.LOW
    block_network: bool = True
    quarantine_files: bool = True
    process_action: str = "terminate"
    isolate_host: bool = True
    activate_honeypots: bool = True
    isolation_event_threshold: int = 3
    isolation_window_seconds: float = 30.0


@dataclass(frozen=True)
class CombatAction:
    action_id: str
    combat_id: str
    action: str
    applied_at: float
    reversible: bool
    target: str
    details: dict[str, Any]
    trigger_module: str
    trigger_ts: float
    status: str = "applied"


class AdversaryCombat(BaseModule):
    """Execute block/contain/isolate/deceive playbooks without incident prompts."""

    name = "Adversary Combat"
    description = (
        "Unattended maximum-response tier: blocks, contains, quarantines, "
        "isolates, and activates honeypots with undo receipts."
    )
    category = "Response"
    version = "1.0.0"
    enabled_by_default = True

    def __init__(self, data_root: Path | None = None) -> None:
        super().__init__()
        self._manager = None
        self._explicit_data_root = Path(data_root) if data_root is not None else None
        self._queue: queue.Queue[Event] = queue.Queue(maxsize=2048)
        self._receipt_lock = threading.RLock()
        self._seen_order: deque[str] = deque(maxlen=8192)
        self._seen: set[str] = set()
        self._active_events: deque[float] = deque(maxlen=256)
        self._host_isolated = False
        self._honeypot_started_by_combat = False
        self._dropped_events = 0
        self._blocked_ips: set[str] = set()
        self._blocked_programs: set[str] = set()

    def bind_manager(self, manager) -> None:
        self._manager = manager

    @property
    def data_root(self) -> Path:
        if self._explicit_data_root is not None:
            return self._explicit_data_root
        config = getattr(self._manager, "config", None)
        configured = getattr(config, "data_dir", None)
        return Path(configured) if configured is not None else canonical_data_dir()

    @property
    def quarantine_root(self) -> Path:
        return self.data_root / "combat-quarantine"

    @property
    def receipt_path(self) -> Path:
        return self.data_root / "shared_logs" / "adversary_combat_actions.jsonl"

    def policy(self) -> CombatPolicy:
        config = getattr(self._manager, "config", None)

        def setting(name: str, default: object) -> object:
            env_name = "ANGERONA_" + name.upper()
            if env_name in os.environ:
                return os.environ[env_name]
            return getattr(config, name.lower(), default) if config is not None else default

        mode = str(setting("ADVERSARY_COMBAT_MODE", "maximum")).strip().casefold()
        if mode not in _MODES:
            mode = "maximum"
        process_action = str(
            setting("ADVERSARY_COMBAT_PROCESS_ACTION", "terminate")
        ).strip().casefold()
        if process_action not in _PROCESS_ACTIONS:
            process_action = "terminate"
        try:
            threshold = max(1, min(100, int(
                setting("ADVERSARY_COMBAT_ISOLATION_THRESHOLD", 3)
            )))
        except (TypeError, ValueError, OverflowError):
            threshold = 3
        return CombatPolicy(
            enabled=_bool(setting("ADVERSARY_COMBAT_ENABLED", True), True),
            mode=mode,
            min_severity=_severity(setting("ADVERSARY_COMBAT_MIN_SEVERITY", "LOW")),
            block_network=_bool(
                setting("ADVERSARY_COMBAT_BLOCK_NETWORK", True), True
            ),
            quarantine_files=_bool(
                setting("ADVERSARY_COMBAT_QUARANTINE_FILES", True), True
            ),
            process_action=process_action,
            isolate_host=_bool(
                setting("ADVERSARY_COMBAT_ISOLATE_HOST", True), True
            ),
            activate_honeypots=_bool(
                setting("ADVERSARY_COMBAT_ACTIVATE_HONEYPOTS", True), True
            ),
            isolation_event_threshold=threshold,
        )

    def self_test(self) -> tuple[bool, str]:
        policy = self.policy()
        ok = self.status == "running" and policy.enabled
        detail = (
            f"{policy.mode.upper()} armed; {policy.min_severity.label}+; "
            f"process={policy.process_action}; queue drops={self._dropped_events}"
        )
        return ok, detail

    def run(self) -> None:
        if self._bus is None:
            self.set_health(0, "event bus unavailable")
            return
        self._bus.subscribe(self._submit)
        policy = self.policy()
        if policy.activate_honeypots:
            self._ensure_honeypots()
        self.set_health(100, "standing authority armed")
        self.emit(
            "Adversary Combat online — standing authority is ARMED. Detector evidence "
            "is acted on automatically without per-incident approval.",
            Severity.INFO,
            action_policy=policy.mode,
            minimum_severity=policy.min_severity.name,
        )
        self.mark_cycle_complete()
        stop = self.generation_stop_event()
        while not stop.is_set():
            try:
                event = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self._handle(event)
            finally:
                self._queue.task_done()

    def _submit(self, event: Event) -> None:
        if self.status != "running" or self.stopping:
            return
        policy = self.policy()
        if not policy.enabled or event.module in _SELF_MODULES:
            return
        if event.severity < policy.min_severity:
            return
        disposition = event_disposition(event)
        if disposition not in {"active", "practice"}:
            return
        signature = str(getattr(event, "hmac_sig", "") or "")
        identity = signature or (
            f"{event.module}\0{event.ts:.9f}\0{event.message}\0"
            f"{json.dumps(event.details or {}, sort_keys=True, default=str)}"
        )
        with self._receipt_lock:
            if identity in self._seen:
                return
            if len(self._seen_order) == self._seen_order.maxlen:
                self._seen.discard(self._seen_order[0])
            self._seen_order.append(identity)
            self._seen.add(identity)
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._dropped_events += 1
            self.set_health(30, "combat event queue saturated")

    def _integrity_ok(self, event: Event) -> bool:
        if self._bus is None or not getattr(self._bus, "integrity_enabled", False):
            return True
        try:
            return bool(self._bus.verify(event))
        except Exception:
            return False

    @staticmethod
    def _event_path(event: Event) -> str:
        details = event.details or {}
        for key in _PATH_FIELDS:
            value = details.get(key)
            if value:
                return str(value)
        return ""

    @staticmethod
    def _remote_ips(event: Event) -> tuple[str, ...]:
        details = event.details or {}
        found: list[str] = []
        for key in _REMOTE_FIELDS:
            raw = details.get(key)
            if not raw:
                continue
            value = str(raw).strip()
            try:
                address = str(ipaddress.ip_address(value.strip("[]")))
            except ValueError:
                # Sensor raddr values use host:port. IPv6 may be bracketed.
                candidate = value
                if value.startswith("[") and "]:" in value:
                    candidate = value[1:value.index("]:")]
                elif value.count(":") == 1:
                    candidate = value.rsplit(":", 1)[0]
                try:
                    address = str(ipaddress.ip_address(candidate))
                except ValueError:
                    continue
            if address not in found:
                found.append(address)
        return tuple(found)

    def _handle(self, event: Event) -> None:
        if not self._integrity_ok(event):
            self.emit(
                "Adversary Combat refused a tampered detector event.",
                Severity.HIGH,
                disposition="health",
                response_authorized=False,
            )
            return
        policy = self.policy()
        if not policy.enabled:
            return
        disposition = event_disposition(event)
        combat_id = f"combat-{uuid.uuid4().hex[:12]}"
        actions: list[CombatAction] = []
        path = self._event_path(event)
        details = event.details or {}
        pid = details.get("pid")

        if policy.block_network:
            for remote_ip in self._remote_ips(event):
                action = self._block_remote_ip(remote_ip, event, combat_id)
                if action is not None:
                    actions.append(action)

        # Cross-host evidence may block the named remote IOC, but it never gets
        # to redirect a local file/process mutation.
        if not is_remote_observe_only(event):
            process_action = self._act_on_process(pid, policy, event, combat_id)
            if process_action is not None:
                actions.extend(process_action)
            if policy.quarantine_files and path:
                action = self._quarantine_file(path, event, combat_id)
                if action is not None:
                    actions.append(action)

        if disposition == "active":
            now = time.time()
            self._active_events.append(now)
            while (
                self._active_events
                and now - self._active_events[0] > policy.isolation_window_seconds
            ):
                self._active_events.popleft()
            isolate_now = (
                policy.isolate_host
                and policy.mode == "maximum"
                and (
                    event.severity >= Severity.CRITICAL
                    or len(self._active_events) >= policy.isolation_event_threshold
                )
            )
            if isolate_now:
                action = self._isolate_host(event, combat_id)
                if action is not None:
                    actions.append(action)

        if policy.activate_honeypots:
            action = self._ensure_honeypots(event=event, combat_id=combat_id)
            if action is not None:
                actions.append(action)

        succeeded = [action for action in actions if action.status == "applied"]
        postcondition_verified = bool(succeeded) and all(
            action.details.get("postcondition_verified") is True
            for action in succeeded
        )
        summary = ", ".join(action.action for action in succeeded) or "no eligible target"
        self.emit(
            f"Adversary Combat executed {len(succeeded)} action(s) for "
            f"{event.module} {event.severity.label}: {summary}.",
            Severity.HIGH if succeeded else Severity.MEDIUM,
            combat_id=combat_id,
            actions=[action.action for action in succeeded],
            action_ids=[action.action_id for action in succeeded],
            action_succeeded=bool(succeeded),
            mitigated=bool(succeeded),
            postcondition_verified=postcondition_verified,
            reversible_actions=sum(1 for action in succeeded if action.reversible),
            trigger_module=event.module,
            trigger_ts=event.ts,
            path=path or None,
            pid=pid if isinstance(pid, int) else None,
            response_mode=policy.mode,
        )

    def _append_action(self, action: CombatAction) -> CombatAction:
        path = self.receipt_path
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(asdict(action), sort_keys=True, default=str)
        with self._receipt_lock:
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded + "\n")
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
        return action

    @staticmethod
    def _action(
        action: str,
        target: str,
        event: Event,
        combat_id: str,
        *,
        reversible: bool,
        details: dict[str, Any],
    ) -> CombatAction:
        return CombatAction(
            action_id=f"act-{uuid.uuid4().hex[:16]}",
            combat_id=combat_id,
            action=action,
            applied_at=time.time(),
            reversible=reversible,
            target=target,
            details=details,
            trigger_module=event.module,
            trigger_ts=event.ts,
        )

    def _quarantine_file(
        self, raw_path: str, event: Event, combat_id: str
    ) -> CombatAction | None:
        try:
            source = Path(raw_path).expanduser().resolve(strict=True)
            quarantine = self.quarantine_root.resolve(strict=False)
            if quarantine == source or quarantine in source.parents:
                return None
            if not source.is_file():
                return None
            destination_dir = quarantine / combat_id
            destination_dir.mkdir(parents=True, exist_ok=True)
            destination = destination_dir / source.name
            if destination.exists():
                destination = destination_dir / f"{uuid.uuid4().hex[:8]}-{source.name}"
            shutil.move(str(source), str(destination))
            verified = destination.is_file() and not source.exists()
            if not verified:
                return None
            action = self._action(
                "quarantine_file",
                str(source),
                event,
                combat_id,
                reversible=True,
                details={
                    "original": str(source),
                    "quarantine": str(destination),
                    "postcondition_verified": True,
                },
            )
            return self._append_action(action)
        except (OSError, RuntimeError, ValueError):
            return None

    def _act_on_process(
        self, pid: object, policy: CombatPolicy, event: Event, combat_id: str
    ) -> list[CombatAction] | None:
        if not isinstance(pid, int) or pid <= 0 or psutil is None:
            return None
        # Killing the response engine itself ends autonomous defense.  Parent
        # exclusion prevents a child detector from terminating its launcher.
        if pid in {os.getpid(), os.getppid()}:
            return None
        actions: list[CombatAction] = []
        try:
            process = psutil.Process(pid)
            created = float(process.create_time())
            name = process.name()
            exe = process.exe() or ""
        except Exception:
            return None
        if policy.block_network and exe:
            action = self._block_program(exe, pid, event, combat_id)
            if action is not None:
                actions.append(action)
        try:
            if policy.process_action == "suspend" or policy.mode == "contain":
                process.suspend()
                time.sleep(0.05)
                verified = process.status() == getattr(psutil, "STATUS_STOPPED", "stopped")
                if not verified:
                    return actions
                action = self._action(
                    "suspend_process",
                    f"{name} ({pid})",
                    event,
                    combat_id,
                    reversible=True,
                    details={
                        "pid": pid,
                        "create_time": created,
                        "name": name,
                        "postcondition_verified": True,
                    },
                )
            else:
                process.kill()
                try:
                    process.wait(timeout=3)
                except Exception:
                    pass
                verified = not process.is_running()
                if not verified:
                    return actions
                action = self._action(
                    "terminate_process",
                    f"{name} ({pid})",
                    event,
                    combat_id,
                    reversible=False,
                    details={
                        "pid": pid,
                        "create_time": created,
                        "name": name,
                        "postcondition_verified": True,
                    },
                )
            actions.append(self._append_action(action))
        except Exception:
            pass
        return actions

    def _run_firewall(self, arguments: list[str]) -> bool:
        if os.name != "nt":
            return False
        try:
            from angerona.core.win import run_hidden

            result = run_hidden(
                ["netsh", "advfirewall", "firewall", *arguments],
                capture_output=True,
                text=True,
                timeout=15,
            )
            return int(getattr(result, "returncode", 1)) == 0
        except Exception:
            return False

    def _block_remote_ip(
        self, remote_ip: str, event: Event, combat_id: str
    ) -> CombatAction | None:
        if remote_ip in self._blocked_ips:
            return None
        rule = f"Angerona-Combat-IP-{uuid.uuid4().hex[:12]}"
        applied: list[str] = []
        for direction in ("out", "in"):
            if self._run_firewall([
                "add", "rule", f"name={rule}-{direction}", f"dir={direction}",
                "action=block", f"remoteip={remote_ip}", "enable=yes",
            ]):
                applied.append(f"{rule}-{direction}")
        if len(applied) != 2:
            for partial in applied:
                self._run_firewall(["delete", "rule", f"name={partial}"])
            return None
        self._blocked_ips.add(remote_ip)
        action = self._action(
            "block_remote_ip",
            remote_ip,
            event,
            combat_id,
            reversible=True,
            details={
                "remote_ip": remote_ip,
                "rules": applied,
                "postcondition_verified": True,
            },
        )
        return self._append_action(action)

    def _block_program(
        self, exe: str, pid: int, event: Event, combat_id: str
    ) -> CombatAction | None:
        program_key = os.path.normcase(os.path.abspath(exe))
        if program_key in self._blocked_programs:
            return None
        rule = f"Angerona-Combat-Program-{pid}-{uuid.uuid4().hex[:8]}"
        if not self._run_firewall([
            "add", "rule", f"name={rule}", "dir=out", "action=block",
            f"program={exe}", "enable=yes",
        ]):
            return None
        self._blocked_programs.add(program_key)
        action = self._action(
            "isolate_program",
            exe,
            event,
            combat_id,
            reversible=True,
            details={
                "pid": pid,
                "exe": exe,
                "rules": [rule],
                "postcondition_verified": True,
            },
        )
        return self._append_action(action)

    def _isolate_host(self, event: Event, combat_id: str) -> CombatAction | None:
        if self._host_isolated:
            return None
        base = f"Angerona-Combat-Host-{uuid.uuid4().hex[:10]}"
        rules: list[str] = []
        for direction in ("out", "in"):
            name = f"{base}-{direction}"
            if self._run_firewall([
                "add", "rule", f"name={name}", f"dir={direction}",
                "action=block", "remoteip=any", "enable=yes",
            ]):
                rules.append(name)
        if len(rules) != 2:
            for partial in rules:
                self._run_firewall(["delete", "rule", f"name={partial}"])
            return None
        self._host_isolated = True
        action = self._action(
            "isolate_host",
            "all remote network traffic",
            event,
            combat_id,
            reversible=True,
            details={"rules": rules, "postcondition_verified": True},
        )
        return self._append_action(action)

    def _ensure_honeypots(
        self, event: Event | None = None, combat_id: str = "startup"
    ) -> CombatAction | None:
        manager = self._manager
        module = getattr(manager, "modules", {}).get("Smart Deception") if manager else None
        if module is None or module.status == "running":
            return None
        try:
            module.start()
            self._honeypot_started_by_combat = True
        except Exception:
            return None
        if event is None:
            return None
        action = self._action(
            "activate_honeypots",
            "Smart Deception",
            event,
            combat_id,
            reversible=True,
            details={
                "module": "Smart Deception",
                "postcondition_verified": module.status == "running",
            },
        )
        return self._append_action(action)

    def list_actions(self, limit: int = 100) -> list[dict[str, Any]]:
        path = self.receipt_path
        if not path.is_file():
            return []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        records: list[dict[str, Any]] = []
        for line in lines[-max(1, min(int(limit) * 4, 10_000)):]:
            try:
                value = json.loads(line)
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict):
                records.append(value)
        undone = {
            str(record.get("undo_of"))
            for record in records
            if record.get("record_type") == "undo" and record.get("status") == "undone"
        }
        actions = [
            {**record, "undone": str(record.get("action_id")) in undone}
            for record in records
            if record.get("action_id") and record.get("action")
        ]
        return actions[-max(1, int(limit)):][::-1]

    def undo_last(self) -> dict[str, Any]:
        for record in self.list_actions(limit=500):
            if record.get("reversible") is True and not record.get("undone"):
                return self.undo_action(str(record.get("action_id")))
        return {"ok": False, "error": "no reversible combat action is pending"}

    def undo_all(self) -> dict[str, Any]:
        """Undo every still-applied reversible action, newest first."""
        results = []
        for record in self.list_actions(limit=5000):
            if record.get("reversible") is not True or record.get("undone"):
                continue
            results.append(self.undo_action(str(record.get("action_id"))))
        failures = [result for result in results if not result.get("ok")]
        return {
            "ok": not failures,
            "attempted": len(results),
            "undone": len(results) - len(failures),
            "failures": failures,
        }

    def undo_action(self, action_id: str) -> dict[str, Any]:
        record = next(
            (item for item in self.list_actions(limit=5000)
             if item.get("action_id") == action_id),
            None,
        )
        if record is None:
            return {"ok": False, "error": "action not found"}
        if record.get("undone"):
            return {"ok": True, "already_undone": True, "action_id": action_id}
        if record.get("reversible") is not True:
            return {"ok": False, "error": "action is not reversible"}
        action = str(record.get("action") or "")
        details = record.get("details") if isinstance(record.get("details"), dict) else {}
        ok, error = False, "unsupported undo action"
        try:
            if action == "quarantine_file":
                source = Path(str(details["quarantine"]))
                destination = Path(str(details["original"]))
                if destination.exists():
                    error = "original path is occupied; quarantine was preserved"
                elif source.is_file():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(source), str(destination))
                    ok, error = True, ""
                else:
                    error = "quarantined file no longer exists"
            elif action == "suspend_process" and psutil is not None:
                process = psutil.Process(int(details["pid"]))
                if abs(float(process.create_time()) - float(details["create_time"])) > 0.001:
                    error = "PID was reused; process was not resumed"
                else:
                    process.resume()
                    ok, error = True, ""
            elif action in {"block_remote_ip", "isolate_program", "isolate_host"}:
                rules = [str(value) for value in details.get("rules", []) if value]
                results = [
                    self._run_firewall(["delete", "rule", f"name={rule}"])
                    for rule in rules
                ]
                ok = bool(results) and all(results)
                error = "" if ok else "one or more firewall rules could not be removed"
                if ok and action == "isolate_host":
                    self._host_isolated = False
                if ok and action == "block_remote_ip":
                    self._blocked_ips.discard(str(details.get("remote_ip") or ""))
                if ok and action == "isolate_program":
                    self._blocked_programs.discard(
                        os.path.normcase(os.path.abspath(str(details.get("exe") or "")))
                    )
            elif action == "activate_honeypots":
                manager = self._manager
                module = (
                    getattr(manager, "modules", {}).get("Smart Deception")
                    if manager else None
                )
                if module is not None:
                    module.stop()
                    self._honeypot_started_by_combat = False
                    ok, error = True, ""
                else:
                    error = "Smart Deception module is unavailable"
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

        undo_record = {
            "record_type": "undo",
            "undo_id": f"undo-{uuid.uuid4().hex[:16]}",
            "undo_of": action_id,
            "action": action,
            "undone_at": time.time(),
            "status": "undone" if ok else "undo_failed",
            "error": error,
        }
        path = self.receipt_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._receipt_lock:
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(undo_record, sort_keys=True) + "\n")
        if ok:
            self.emit(
                f"Adversary Combat undo completed: {action} ({action_id}).",
                Severity.INFO,
                action="undo",
                undo_of=action_id,
                action_succeeded=True,
            )
        return {"ok": ok, "action_id": action_id, "action": action, "error": error}


def register() -> AdversaryCombat:
    return AdversaryCombat()
