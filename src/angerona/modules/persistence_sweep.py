"""Persistence Sweep — autorun / persistence surface monitor (ATT&CK T1547, T1053,
T1543, T1546, T1037).

Most real-world malware survives reboot by writing to one of a small set of
well-known persistence surfaces. This module baselines those surfaces once, then
sweeps them on a timer and reports any *new* entry against the baseline — with a
pure classifier that raises severity when the new entry looks malicious (points
into a user-writable/temp path, launches a script host, uses encoded commands…).

Surfaces watched (all read-only enumeration — nothing is ever modified here):
  * Registry Run / RunOnce keys           (HKLM + HKCU)                  → T1547.001
  * Registry Winlogon Shell / Userinit    (HKLM)                        → T1547.004
  * Startup folders                        (per-user + common)          → T1547.001
  * Windows Services                       (image path, via psutil)     → T1543.003
  * Scheduled Tasks                        (schtasks, name-only)        → T1053.005
  * WMI permanent event consumers          (PowerShell CIM, name-only)  → T1546.003

SAFETY / PERF: enumeration only, never a write. The two subprocess-backed
surfaces (scheduled tasks, WMI consumers) are polled on a *slower* cadence than
the cheap in-process ones so the hot loop stays light. All collection is
best-effort and never raises into the module thread.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from angerona.core.module_base import BaseModule, Severity

try:
    import winreg  # type: ignore
except Exception:  # pragma: no cover — non-Windows (harness classifier still runs)
    winreg = None

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

# Registry autorun locations: (hive, subkey, label, mitre).
_RUN_KEYS = []
if winreg is not None:
    _RUN_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run", "T1547.001"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce", "T1547.001"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run", "T1547.001"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce", "T1547.001"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM\\Winlogon", "T1547.004"),
    ]

# Substrings that make an autorun entry suspicious wherever it points/runs.
_BAD_PATH_HINTS = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\public\\",
                   "\\programdata\\", "\\users\\public\\", "%temp%", "%appdata%")
_BAD_CMD_HINTS = ("powershell", "-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden",
                  "mshta", "rundll32", "regsvr32", "wscript", "cscript", "certutil",
                  "bitsadmin", "frombase64string", "iex", "invoke-expression", "curl ", "wget ")
# Winlogon Shell/Userinit exact known-good values (lowercased, trailing comma
# stripped by the classifier). Anything else in these values is a classic hijack.
_WINLOGON_DEFAULTS = {"explorer.exe", "userinit.exe", "c:\\windows\\system32\\userinit.exe"}

_SUBPROCESS_FLAGS = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW


class PersistenceSweepModule(BaseModule):
    name = "Persistence Sweep"
    description = ("Baselines and monitors autorun/persistence surfaces (Run keys, "
                  "services, scheduled tasks, WMI subscriptions, startup folders); "
                  "flags new and suspicious entries.")
    category = "Persistence"

    # Cheap in-process sweep every SWEEP_SECONDS; the two subprocess surfaces
    # every SLOW_EVERY sweeps (so ~5 min at defaults) to keep the loop light.
    SWEEP_SECONDS = 60
    SLOW_EVERY = 5

    def __init__(self) -> None:
        super().__init__()
        self._baseline: Dict[str, Set[str]] = {}
        self._values: Dict[str, str] = {}   # "surface\x00entry" -> command/value (for classify)

    # ── Pure classifier (unit-testable, no I/O) ──────────────────────────────
    def _classify(self, surface: str, entry: str, value: str, mitre: str) -> Tuple[Severity, str]:
        """Return (severity, reason) for a NEW persistence entry. Pure — used by
        self_test so the harness can verify logic without touching the host."""
        v = (value or "").lower()
        e = (entry or "").lower()
        if surface.endswith("Winlogon"):
            # Winlogon Shell/Userinit have exactly-known-good values; ANYTHING else
            # (including a legit value with a second binary appended) is a hijack.
            # Must be exact equality — 'explorer.exe,evil.exe'.startswith('explorer.exe')
            # would otherwise let an appended payload through.
            val = v.strip().rstrip(",")
            if val not in _WINLOGON_DEFAULTS:
                return (Severity.CRITICAL, f"Winlogon persistence hijack ({entry}={value}) [{mitre}]")
        hay = v + " " + e
        if any(h in hay for h in _BAD_CMD_HINTS):
            return (Severity.CRITICAL,
                    f"New persistence entry launches a script/LOLBin: {surface}\\{entry} → {value} [{mitre}]")
        if any(h in v for h in _BAD_PATH_HINTS):
            return (Severity.HIGH,
                    f"New persistence entry runs from a user-writable path: {surface}\\{entry} → {value} [{mitre}]")
        return (Severity.MEDIUM,
                f"New persistence entry: {surface}\\{entry} → {value or '(name-only)'} [{mitre}]")

    # ── Collectors (best-effort, read-only) ──────────────────────────────────
    def _collect_registry(self) -> None:
        if winreg is None:
            return
        for hive, subkey, label, mitre in _RUN_KEYS:
            names: Set[str] = set()
            try:
                with winreg.OpenKey(hive, subkey) as k:
                    i = 0
                    while True:
                        try:
                            n, val, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        names.add(n)
                        self._values[f"{label}\x00{n}"] = str(val)
                        self._values[f"{label}\x00{n}\x00mitre"] = mitre
            except FileNotFoundError:
                pass
            except Exception:
                continue
            self._pending[label] = names

    def _collect_startup(self) -> None:
        folders = []
        appdata = os.environ.get("APPDATA")
        programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        if appdata:
            folders.append(("Startup\\User", os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup")))
        folders.append(("Startup\\Common", os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\Startup")))
        for label, path in folders:
            names: Set[str] = set()
            try:
                for e in os.scandir(path):
                    if e.is_file():
                        names.add(e.name)
                        self._values[f"{label}\x00{e.name}"] = e.path
                        self._values[f"{label}\x00{e.name}\x00mitre"] = "T1547.001"
            except Exception:
                pass
            self._pending[label] = names

    def _collect_services(self) -> None:
        if psutil is None or not hasattr(psutil, "win_service_iter"):
            return
        names: Set[str] = set()
        try:
            for s in psutil.win_service_iter():
                try:
                    info = s.as_dict()
                    n = info.get("name") or s.name()
                    names.add(n)
                    self._values[f"Service\x00{n}"] = info.get("binpath") or ""
                    self._values[f"Service\x00{n}\x00mitre"] = "T1543.003"
                except Exception:
                    continue
        except Exception:
            return
        self._pending["Service"] = names

    def _collect_scheduled(self) -> None:
        out = self._run(["schtasks", "/query", "/fo", "csv", "/nh"])
        if out is None:
            return
        names: Set[str] = set()
        for line in out.splitlines():
            cell = line.split('","')[0].strip().strip('"')
            if cell and cell != "TaskName":
                names.add(cell)
                self._values[f"ScheduledTask\x00{cell}\x00mitre"] = "T1053.005"
        if names:
            self._pending["ScheduledTask"] = names

    def _collect_wmi(self) -> None:
        out = self._run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                         "Get-WmiObject -Namespace root\\subscription -Class __EventConsumer "
                         "| Select-Object -ExpandProperty Name"])
        if out is None:
            return
        names = {ln.strip() for ln in out.splitlines() if ln.strip()}
        for n in names:
            self._values[f"WMIConsumer\x00{n}\x00mitre"] = "T1546.003"
        self._pending["WMIConsumer"] = names

    def _run(self, cmd) -> Optional[str]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                               creationflags=_SUBPROCESS_FLAGS)
            return r.stdout or ""
        except Exception:
            return None

    def _sweep(self, include_slow: bool) -> Dict[str, Set[str]]:
        self._pending: Dict[str, Set[str]] = {}
        self._collect_registry()
        self._collect_startup()
        self._collect_services()
        if include_slow:
            self._collect_scheduled()
            self._collect_wmi()
        return self._pending

    def _mitre(self, surface: str, entry: str) -> str:
        return self._values.get(f"{surface}\x00{entry}\x00mitre", "T1547")

    def self_test(self) -> tuple[bool, str]:
        # Verify the classifier without touching the real host.
        a = self._classify("HKCU\\Run", "updater",
                            r"powershell -enc SQBFAFgA", "T1547.001")   # encoded PS → CRITICAL
        b = self._classify("HKLM\\Run", "tool",
                            r"C:\Users\me\AppData\Local\Temp\x.exe", "T1547.001")  # temp path → HIGH
        c = self._classify("HKLM\\Winlogon", "Shell", "explorer.exe", "T1547.004")  # default → not flagged high
        d = self._classify("HKLM\\Winlogon", "Shell", "explorer.exe,evil.exe", "T1547.004")  # hijack → CRITICAL
        ok = (a[0] == Severity.CRITICAL and b[0] == Severity.HIGH
              and c[0] == Severity.MEDIUM and d[0] == Severity.CRITICAL)
        return (ok, "persistence classifier verified (encoded-PS + Winlogon hijack CRITICAL, "
                    "temp-path HIGH, clean-default not escalated)"
                if ok else f"classifier failed: a={a} b={b} c={c} d={d}")

    def run(self) -> None:
        self.emit("Building persistence baseline…", Severity.INFO)
        self._baseline = self._sweep(include_slow=True)
        total = sum(len(v) for v in self._baseline.values())
        self.emit(f"Persistence baseline armed: {total} entries across "
                  f"{len(self._baseline)} surfaces.", Severity.INFO)
        self.set_health(100, "")

        cycle = 0
        while not self.stopping:
            self.sleep(self.SWEEP_SECONDS)
            if self.stopping:
                break
            cycle += 1
            include_slow = (cycle % self.SLOW_EVERY == 0)
            current = self._sweep(include_slow=include_slow)
            for surface, names in current.items():
                base = self._baseline.get(surface, set())
                for entry in names - base:
                    val = self._values.get(f"{surface}\x00{entry}", "")
                    sev, reason = self._classify(surface, entry, val, self._mitre(surface, entry))
                    self.emit(reason, sev, surface=surface, entry=entry,
                              value=val, mitre=self._mitre(surface, entry))
                # Persist newly-seen entries into the baseline so we alert once.
                self._baseline[surface] = base | names
