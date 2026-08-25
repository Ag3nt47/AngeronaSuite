"""Process / parent-lineage monitor.

Watches for newly spawned processes and flags suspicious patterns (e.g. a shell
or script host spawned by an Office app, or execution from a temp/download
path). Ported from Angerona's lineage monitor.
"""
from __future__ import annotations

import os
from typing import Dict, Set

from angerona.core.module_base import BaseModule, Severity
from angerona.telemetry.sensors import list_processes

SUSPICIOUS_CHILDREN = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
RISKY_PATH_TOKENS = ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\")


class ProcessMonitorModule(BaseModule):
    name = "Process Monitor"
    description = "Flags suspicious process spawns and execution from risky locations."
    category = "Processes"

    def __init__(self) -> None:
        super().__init__()
        self._seen: Set[int] = set()
        self._names: Dict[int, str] = {}

    def run(self) -> None:
        # Prime the set so we don't alert on everything already running.
        for p in list_processes():
            pid = p.get("pid")
            if pid is not None:
                self._seen.add(pid)
                self._names[pid] = (p.get("name") or "").lower()
        self.emit("Process monitor active.", Severity.INFO)

        while not self.stopping:
            combat = os.environ.get(
                "ANGERONA_ADVERSARY_COMBAT_ENABLED", "0"
            ).strip().lower() in {"1", "true", "yes", "on"}
            self.sleep(1.0 if combat else 3.0)
            procs = list_processes()
            live: Set[int] = set()
            names: Dict[int, str] = {}
            for p in procs:
                pid = p.get("pid")
                if pid is None:
                    continue
                live.add(pid)
                names[pid] = (p.get("name") or "").lower()

            for p in procs:
                pid = p.get("pid")
                if pid is None or pid in self._seen:
                    continue
                # Publish complete process-creation telemetry for correlation.
                # INFO is not a malicious verdict; reviewed detectors such as
                # Purple Guard can promote exact tagged evidence independently.
                raw_command = p.get("cmdline") or []
                command = (
                    " ".join(str(part) for part in raw_command)
                    if isinstance(raw_command, (list, tuple))
                    else str(raw_command)
                )
                self.emit(
                    f"Process created: {p.get('name') or '?'} (pid {pid})",
                    Severity.INFO,
                    event_type="process_creation",
                    pid=pid,
                    ppid=p.get("ppid"),
                    exe=p.get("exe"),
                    cmdline=command,
                )
                self._evaluate(p, names)

            self._seen = live
            self._names = names

    def _evaluate(self, p: dict, names: Dict[int, str]) -> None:
        name = (p.get("name") or "").lower()
        exe = (p.get("exe") or "").lower()
        ppid = p.get("ppid")
        parent = self._names.get(ppid, names.get(ppid, "")).lower()

        if name in SUSPICIOUS_CHILDREN and parent in OFFICE_PARENTS:
            self.emit(f"Office app '{parent}' spawned '{name}' (pid {p.get('pid')}) — possible macro abuse.",
                      Severity.CRITICAL, pid=p.get("pid"), parent=parent)
            return
        if exe and any(tok in exe for tok in RISKY_PATH_TOKENS):
            self.emit(f"Process running from a risky path: {p.get('exe')} (pid {p.get('pid')})",
                      Severity.MEDIUM, pid=p.get("pid"), exe=p.get("exe"))
