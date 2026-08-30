"""Process / parent-lineage monitor.

Watches for newly spawned processes and flags suspicious patterns (e.g. a shell
or script host spawned by an Office app, or execution from a temp/download
path). Ported from Angerona's lineage monitor.
"""
from __future__ import annotations

import os
import math
import threading
from typing import Dict, Set

from angerona.core.module_base import BaseModule, Severity
from angerona.telemetry.sensors import list_processes

SUSPICIOUS_CHILDREN = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
RISKY_PATH_TOKENS = ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\")


def _combat_enabled() -> bool:
    return os.environ.get(
        "ANGERONA_ADVERSARY_COMBAT_ENABLED", "0"
    ).strip().lower() in {"1", "true", "yes", "on"}


def _snapshot_max_age() -> float | None:
    """Make the shared process cache fresher than Combat's one-second loop."""
    return 0.5 if _combat_enabled() else None


def _process_identity(process: dict) -> tuple[tuple[int, str, str] | None, bool]:
    try:
        pid = int(process.get("pid"))
    except (TypeError, ValueError):
        return None, False
    if pid <= 0:
        return None, False
    executable = str(process.get("exe") or process.get("name") or "").casefold()
    try:
        birth = float(process.get("create_time"))
    except (TypeError, ValueError):
        birth = float("nan")
    complete = math.isfinite(birth) and birth > 0
    token = f"{birth:.6f}" if complete else f"unknown:{executable}"
    return (pid, token, executable), complete


class ProcessMonitorModule(BaseModule):
    name = "Process Monitor"
    description = "Flags suspicious process spawns and execution from risky locations."
    category = "Processes"
    version = "1.12.1"

    def __init__(self) -> None:
        super().__init__()
        self._seen: Set[tuple[int, str, str]] = set()
        self._names: Dict[int, str] = {}
        self._identity_gaps = 0
        self._redteam_receipt_capability: object | None = None
        self._redteam_receipt_lock = threading.RLock()
        self._redteam_receipted: Set[tuple[int, str, str]] = set()
        self._initial_pid_baseline: set[int] | None = None

    def bind_redteam_receipt_capability(
        self,
        capability: object | None,
        *,
        expected: object | None = None,
    ) -> None:
        """Bind/revoke one exact validation producer capability."""
        with self._redteam_receipt_lock:
            if expected is not None and self._redteam_receipt_capability is not expected:
                return
            self._redteam_receipt_capability = capability

    def observe_validation_process(self, pid: int) -> bool:
        """Perform one exact, read-only OS observation for an enrolled child."""
        if self.status != "running" or self.stopping:
            return False
        try:
            import psutil

            observed = psutil.Process(int(pid))
            process: dict[str, object] = {
                "pid": int(observed.pid),
                "ppid": int(observed.ppid()),
                "name": str(observed.name() or ""),
                "exe": str(observed.exe() or ""),
                "cmdline": [str(value) for value in observed.cmdline()],
                "create_time": float(observed.create_time()),
            }
            if not observed.is_running():
                return False
            with self._redteam_receipt_lock:
                capability = self._redteam_receipt_capability
            issue = getattr(capability, "issue_process_observation", None)
            receipt = issue(self, process=process) if callable(issue) else {}
            if not receipt:
                return False
            identity, _complete = _process_identity(process)
            if identity is not None:
                self._redteam_receipted.add(identity)
            command = " ".join(str(value) for value in process["cmdline"])
            self.emit(
                f"Process created: {process['name'] or '?'} (pid {pid})",
                Severity.INFO,
                event_type="process_creation",
                pid=int(pid),
                ppid=process["ppid"],
                exe=process["exe"],
                cmdline=command,
                process_create_time=process["create_time"],
                **receipt,
            )
            return True
        except (OSError, TypeError, ValueError):
            return False

    def self_test(self) -> tuple[bool, str]:
        """Exercise lineage and risky-path rules without enumerating processes."""
        emitted: list[tuple[str, Severity, dict]] = []
        original_emit = self.emit
        original_names = self._names
        try:
            self.emit = lambda message, severity=Severity.INFO, **details: emitted.append(
                (message, severity, details)
            )
            self._names = {10: "winword.exe"}
            self._evaluate(
                {
                    "pid": 11,
                    "ppid": 10,
                    "name": "powershell.exe",
                    "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "create_time": 123.0,
                },
                dict(self._names),
            )
            self._evaluate(
                {
                    "pid": 12,
                    "ppid": 10,
                    "name": "fixture.exe",
                    "exe": r"C:\Users\Test\Downloads\fixture.exe",
                    "create_time": 124.0,
                },
                dict(self._names),
            )
        finally:
            self.emit = original_emit
            self._names = original_names
        ok = bool(
            len(emitted) == 2
            and emitted[0][1] == Severity.CRITICAL
            and emitted[0][2].get("process_create_time") == 123.0
            and emitted[1][1] == Severity.MEDIUM
        )
        return (
            ok,
            "offline lineage and risky-path rules passed"
            if ok else "process rule fixture failed",
        )

    def run(self) -> None:
        # Establish the startup boundary from the OS PID table immediately.
        # Rich per-process fields are intentionally deferred to the first poll:
        # Windows can spend several seconds resolving command lines for hundreds
        # of protected processes. A child created after this exact PID boundary
        # remains new and cannot disappear into a slow startup enumeration.
        import psutil

        self._initial_pid_baseline = {
            int(pid) for pid in psutil.pids() if int(pid) > 0
        }
        self.set_health(
            70,
            "startup PID boundary captured; full birth/command identity enrichment pending",
        )
        self.mark_cycle_complete(interval_seconds=0.0)
        self.emit("Process monitor active.", Severity.INFO)

        while not self.stopping:
            combat = _combat_enabled()
            interval = 1.0 if combat else 3.0
            self.sleep(interval, cycle_complete=False)
            if self.stopping:
                break
            max_age = _snapshot_max_age()
            procs = (
                list_processes(max_age=max_age)
                if max_age is not None
                else list_processes()
            )
            live: Set[tuple[int, str, str]] = set()
            names: Dict[int, str] = {}
            identity_gaps = 0
            for p in procs:
                identity, complete = _process_identity(p)
                if identity is None:
                    identity_gaps += 1
                    continue
                pid = identity[0]
                live.add(identity)
                identity_gaps += int(not complete)
                names[pid] = (p.get("name") or "").lower()

            for p in procs:
                identity, _complete = _process_identity(p)
                if identity is None:
                    continue
                pid = identity[0]
                is_new = bool(
                    identity not in self._seen
                    and (
                        self._initial_pid_baseline is None
                        or pid not in self._initial_pid_baseline
                    )
                )
                # Publish complete process-creation telemetry for correlation.
                # INFO is not a malicious verdict; reviewed detectors such as
                # Purple Guard can promote exact tagged evidence independently.
                raw_command = p.get("cmdline") or []
                command = (
                    " ".join(str(part) for part in raw_command)
                    if isinstance(raw_command, (list, tuple))
                    else str(raw_command)
                )
                receipt: dict[str, object] = {}
                if identity not in self._redteam_receipted:
                    try:
                        with self._redteam_receipt_lock:
                            capability = self._redteam_receipt_capability
                        issue = getattr(capability, "issue_process_observation", None)
                        if callable(issue):
                            receipt = issue(self, process=dict(p))
                    except Exception:
                        receipt = {}
                if is_new or receipt:
                    self.emit(
                        f"Process created: {p.get('name') or '?'} (pid {pid})",
                        Severity.INFO,
                        event_type="process_creation",
                        pid=pid,
                        ppid=p.get("ppid"),
                        exe=p.get("exe"),
                        cmdline=command,
                        process_create_time=p.get("create_time"),
                        **receipt,
                    )
                if receipt:
                    self._redteam_receipted.add(identity)
                if is_new:
                    self._evaluate(p, names)

            self._seen = live
            self._initial_pid_baseline = None
            self._redteam_receipted.intersection_update(live)
            self._names = names
            self._identity_gaps = identity_gaps
            if identity_gaps:
                self.set_health(
                    70,
                    f"process identity incomplete for {identity_gaps}/{len(procs)} record(s)",
                )
            else:
                self.set_health(
                    100,
                    f"{len(live)} process generation(s) tracked by pid + birth identity",
                )
            self.mark_cycle_complete(interval_seconds=interval)

    def _evaluate(self, p: dict, names: Dict[int, str]) -> None:
        name = (p.get("name") or "").lower()
        exe = (p.get("exe") or "").lower()
        ppid = p.get("ppid")
        parent = self._names.get(ppid, names.get(ppid, "")).lower()

        if name in SUSPICIOUS_CHILDREN and parent in OFFICE_PARENTS:
            pid = p.get("pid")
            created = p.get("create_time")
            self.emit(
                f"Office app '{parent}' spawned '{name}' (pid {pid}) — possible macro abuse.",
                Severity.CRITICAL,
                pid=pid,
                parent=parent,
                exe=p.get("exe"),
                process_create_time=created,
            )
            return
        if exe and any(tok in exe for tok in RISKY_PATH_TOKENS):
            self.emit(f"Process running from a risky path: {p.get('exe')} (pid {p.get('pid')})",
                      Severity.MEDIUM, pid=p.get("pid"), exe=p.get("exe"),
                      process_create_time=p.get("create_time"))
