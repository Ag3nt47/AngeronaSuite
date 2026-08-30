"""Persistence Sweep — autorun / persistence surface monitor (ATT&CK T1547, T1053,
T1543, T1546, T1037).

Most real-world malware survives reboot by writing to one of a small set of
well-known persistence surfaces. This module takes an immutable startup
observation, then reports added, modified, and removed records without silently
promoting drift into that baseline. A pure classifier raises severity when a
new or changed entry looks malicious (for example, a user-writable path, script
host, or encoded command).

Surfaces watched (all read-only enumeration — nothing is ever modified here):
  * Registry Run / RunOnce keys           (HKLM + HKCU)                  → T1547.001
  * Registry Winlogon Shell / Userinit    (HKLM)                        → T1547.004
  * Startup folders                        (per-user + common)          → T1547.001
  * Windows Services                       (image path, via psutil)     → T1543.003
  * Scheduled Tasks (actions/triggers/principal/settings, CIM)         → T1053.005
  * WMI filters, consumers, and bindings (PowerShell CIM)              → T1546.003

SAFETY / PERF: enumeration only, never a write. The two subprocess-backed
surfaces (scheduled tasks, WMI subscriptions) are polled on a *slower* cadence than
the cheap in-process ones so the hot loop stays light. All collection is
explicitly completeness-graded; failed/partial sources remain UNKNOWN and are
never compared as an empty collection.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from collections import deque
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
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (32-bit)", "T1547.001"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce (32-bit)", "T1547.001"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM\\Winlogon", "T1547.004"),
    ]

# Substrings that make an autorun entry suspicious wherever it points/runs.
_BAD_PATH_HINTS = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\public\\",
                   "\\programdata\\", "\\users\\public\\", "%temp%", "%appdata%")
_BAD_CMD_HINTS = ("powershell", "-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden",
                  "mshta", "rundll32", "regsvr32", "wscript", "cscript", "certutil",
                  "bitsadmin", "frombase64string", "iex", "invoke-expression", "curl ", "wget ")
_SUBPROCESS_FLAGS = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
_MAX_STARTUP_HASH_BYTES = 512 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_MAX_REPORTED_CHANGES = 10_000
_MAX_COLLECTOR_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_COLLECTOR_RECORDS = 5_000
_MAX_RECORD_BYTES = 64 * 1024

_SCHEDULED_TASK_QUERY = r"""
$ErrorActionPreference='Stop'
$rows = @(Get-ScheduledTask | Select-Object -First 5001 | ForEach-Object {
  [pscustomobject]@{
    id = "$($_.TaskPath)$($_.TaskName)"
    state = [string]$_.State
    author = [string]$_.Author
    description = [string]$_.Description
    actions = @($_.Actions | Select-Object Execute,Arguments,WorkingDirectory,ClassId,Data)
    triggers = @($_.Triggers | Select-Object Enabled,StartBoundary,EndBoundary,ExecutionTimeLimit,UserId,Delay,RandomDelay)
    principal = $_.Principal | Select-Object UserId,LogonType,RunLevel,GroupId,DisplayName
    settings = $_.Settings | Select-Object Enabled,Hidden,AllowDemandStart,ExecutionTimeLimit,MultipleInstances,RestartCount,RestartInterval,RunOnlyIfIdle,RunOnlyIfNetworkAvailable,StartWhenAvailable,WakeToRun
  }
})
$json = ConvertTo-Json -InputObject $rows -Depth 7 -Compress
if ($json.Length -gt 8388608) { throw 'scheduled-task inventory exceeds bound' }
[Console]::Out.Write($json)
""".strip()

_WMI_QUERY = r"""
$ErrorActionPreference='Stop'
$filters = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Select-Object Name,Query,QueryLanguage,EventNamespace)
$consumers = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | Select-Object __CLASS,Name,CommandLineTemplate,ExecutablePath,ScriptText,ScriptingEngine,Destination,Filename)
$bindings = @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Select-Object Filter,Consumer)
$doc = [pscustomobject]@{ filters=$filters; consumers=$consumers; bindings=$bindings }
$json = ConvertTo-Json -InputObject $doc -Depth 6 -Compress
if ($json.Length -gt 8388608) { throw 'WMI subscription inventory exceeds bound' }
[Console]::Out.Write($json)
""".strip()


class PersistenceSweepModule(BaseModule):
    name = "Persistence Sweep"
    description = ("Baselines and monitors autorun/persistence surfaces (Run keys, "
                  "services, scheduled tasks, WMI subscriptions, startup folders); "
                  "flags new and suspicious entries.")
    category = "Persistence"
    version = "1.12.1"
    supported_platforms = ("windows",)
    capability_mode = "detect"
    capability_inputs = (
        "registry-autorun-record", "startup-file-record", "service-record",
        "scheduled-task-record", "wmi-consumer-record",
    )
    capability_outputs = ("persistence-added", "persistence-modified", "persistence-removed")
    capability_permissions = ("host-persistence-read",)
    data_classes = ("autorun-command", "service-configuration", "startup-file-hash")
    egress = "none"
    retention = "in-memory-approved-startup-baseline-and-bounded-change-dedup"
    response_authority = "none"
    restart_policy = "bounded-three-attempt-backoff-quarantine"
    loss_behavior = "collector-failure-is-degraded-not-clean"
    resource_budget = {
        "worker_model": "single-lifecycle-thread-with-bounded-subprocess-reads",
        "event_delivery": "snapshot-diff",
        "startup_cycle_timeout_seconds": 30.0,
    }
    settings_schema = {
        "type": "object",
        "properties": {
            "sweep_seconds": {"type": "integer", "minimum": 30, "maximum": 3600},
            "slow_every": {"type": "integer", "minimum": 1, "maximum": 60},
        },
        "additionalProperties": False,
    }

    # Cheap in-process sweep every SWEEP_SECONDS; the two subprocess surfaces
    # every SLOW_EVERY sweeps (so ~5 min at defaults) to keep the loop light.
    SWEEP_SECONDS = 60
    SLOW_EVERY = 5

    def __init__(self) -> None:
        super().__init__()
        self._baseline: Dict[str, Dict[str, str]] = {}
        self._values: Dict[str, str] = {}   # "surface\x00entry" -> command/value (for classify)
        self._reported_changes: set[str] = set()
        self._reported_change_order: deque[str] = deque()
        self._coverage: dict[str, dict[str, str]] = {}
        self._last_command_error = ""
        self._baseline_reviewed = False

    def _surface_complete(self, surface: str, names: Set[str]) -> None:
        self._pending[surface] = names
        self._coverage[surface] = {"status": "complete", "error": ""}

    def _surface_unknown(
        self, surface: str, error: object, *, partial: bool = False
    ) -> None:
        self._coverage[surface] = {
            "status": "partial" if partial else "unknown",
            "error": str(error)[:1000] or "collector failed",
        }

    def coverage_snapshot(self) -> dict[str, dict[str, str]]:
        """Return current per-surface evidence completeness for UI/diagnostics."""
        return {name: dict(value) for name, value in self._coverage.items()}

    def _remember_change(self, fingerprint: str) -> bool:
        """Return True once per recent change while keeping memory strictly bounded."""
        if fingerprint in self._reported_changes:
            return False
        if len(self._reported_change_order) >= _MAX_REPORTED_CHANGES:
            oldest = self._reported_change_order.popleft()
            self._reported_changes.discard(oldest)
        self._reported_change_order.append(fingerprint)
        self._reported_changes.add(fingerprint)
        return True

    # ── Pure classifier (unit-testable, no I/O) ──────────────────────────────
    def _classify(self, surface: str, entry: str, value: str, mitre: str) -> Tuple[Severity, str]:
        """Return (severity, reason) for a NEW persistence entry. Pure — used by
        self_test so the harness can verify logic without touching the host."""
        v = (value or "").lower()
        e = (entry or "").lower()
        typed_value = value or ""
        if v.lstrip().startswith("{"):
            try:
                decoded = json.loads(value)
                if isinstance(decoded, dict) and "value" in decoded:
                    typed_value = str(decoded.get("value") or "")
                    v = typed_value.lower()
            except (TypeError, ValueError):
                # Malformed typed evidence remains suspicious through the
                # generic classifier; it is never treated as a known default.
                pass
        if surface.endswith("Winlogon") and e in {"shell", "userinit"}:
            # Winlogon Shell/Userinit have exactly-known-good values; ANYTHING else
            # (including a legit value with a second binary appended) is a hijack.
            # Must be exact equality — 'explorer.exe,evil.exe'.startswith('explorer.exe')
            # would otherwise let an appended payload through.
            val = v.strip().rstrip(",")
            allowed = (
                {"explorer.exe"}
                if e == "shell"
                else {"userinit.exe", "c:\\windows\\system32\\userinit.exe"}
            )
            if val not in allowed:
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
                            n, val, value_type = winreg.EnumValue(k, i)
                        except OSError as exc:
                            if getattr(exc, "winerror", None) == 259:
                                break
                            raise
                        i += 1
                        names.add(n)
                        self._values[f"{label}\x00{n}"] = json.dumps(
                            {"value": str(val), "type": int(value_type)},
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        self._values[f"{label}\x00{n}\x00mitre"] = mitre
            except FileNotFoundError:
                pass
            except Exception as exc:
                self._surface_unknown(label, exc)
                continue
            self._surface_complete(label, names)

    def _collect_startup(self) -> None:
        hash_budget = _MAX_STARTUP_HASH_BYTES
        folders = []
        appdata = os.environ.get("APPDATA")
        programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        if appdata:
            folders.append(("Startup\\User", os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup")))
        folders.append(("Startup\\Common", os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\Startup")))
        for label, path in folders:
            names: Set[str] = set()
            partial_error = ""
            try:
                for e in os.scandir(path):
                    if e.is_file():
                        names.add(e.name)
                        try:
                            record, consumed, verified = self._startup_file_record(
                                e.path,
                                budget_bytes=hash_budget,
                            )
                            hash_budget -= consumed
                            self._values[f"{label}\x00{e.name}"] = json.dumps(
                                record, sort_keys=True, separators=(",", ":")
                            )
                            if not verified:
                                partial_error = (
                                    f"startup hash budget deferred {e.name!r} "
                                    f"({record.get('size', 'unknown')} bytes)"
                                )
                        except OSError as exc:
                            partial_error = str(exc) or "startup file metadata/hash changed"
                            self._values[f"{label}\x00{e.name}"] = e.path
                        self._values[f"{label}\x00{e.name}\x00mitre"] = "T1547.001"
            except FileNotFoundError:
                pass
            except Exception as exc:
                self._surface_unknown(label, exc)
                continue
            if partial_error:
                self._surface_unknown(label, partial_error, partial=True)
            else:
                self._surface_complete(label, names)

    @staticmethod
    def _startup_file_record(
        path: str,
        *,
        budget_bytes: int,
    ) -> tuple[dict[str, object], int, bool]:
        """Hash one no-follow, identity-held startup file within a sweep budget.

        Returning ``verified=False`` is never equivalent to a clean digest: the
        caller marks the whole surface PARTIAL so preserved size/mtime metadata
        cannot hide oversized content replacement behind health 100.
        """
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise OSError("startup entry is not a regular file")
            if bool(getattr(before, "st_file_attributes", 0) & 0x400):
                raise OSError("startup entry is a reparse point")
            identity = {
                "path": str(path),
                "size": int(before.st_size),
                "mtime_ns": int(before.st_mtime_ns),
                "device": int(before.st_dev),
                "inode": int(before.st_ino),
            }
            if before.st_size < 0 or before.st_size > max(0, int(budget_bytes)):
                return (
                    {
                        **identity,
                        "sha256": "",
                        "integrity_status": "pending-hash-budget",
                    },
                    0,
                    False,
                )
            hasher = hashlib.sha256()
            remaining = int(before.st_size)
            while remaining:
                chunk = os.read(descriptor, min(_HASH_CHUNK_BYTES, remaining))
                if not chunk:
                    raise OSError("startup file changed while hashing")
                hasher.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise OSError("startup file grew while hashing")
            after = os.fstat(descriptor)
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
            ):
                raise OSError("startup file identity changed while hashing")
            current = os.stat(path, follow_symlinks=False)
            if (
                current.st_dev != after.st_dev
                or current.st_ino != after.st_ino
                or current.st_size != after.st_size
                or current.st_mtime_ns != after.st_mtime_ns
                or bool(getattr(current, "st_file_attributes", 0) & 0x400)
            ):
                raise OSError("startup path changed after hashing")
            return (
                {
                    **identity,
                    "sha256": hasher.hexdigest(),
                    "integrity_status": "verified",
                },
                int(before.st_size),
                True,
            )
        finally:
            os.close(descriptor)

    def _collect_services(self) -> None:
        if psutil is None or not hasattr(psutil, "win_service_iter"):
            self._surface_unknown("Service", "Windows service API unavailable")
            return
        names: Set[str] = set()
        partial_error = ""
        try:
            for s in psutil.win_service_iter():
                try:
                    info = s.as_dict()
                    n = info.get("name") or s.name()
                    names.add(n)
                    self._values[f"Service\x00{n}"] = json.dumps(
                        {
                            "binpath": info.get("binpath") or "",
                            "start_type": info.get("start_type") or "",
                            "username": info.get("username") or "",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    self._values[f"Service\x00{n}\x00mitre"] = "T1543.003"
                except Exception as exc:
                    partial_error = str(exc) or "service record unavailable"
                    continue
        except Exception as exc:
            self._surface_unknown("Service", exc)
            return
        if partial_error:
            self._surface_unknown("Service", partial_error, partial=True)
        else:
            self._surface_complete("Service", names)

    def _collect_scheduled(self) -> None:
        out = self._run([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            _SCHEDULED_TASK_QUERY,
        ])
        if out is None:
            self._surface_unknown(
                "ScheduledTask", self._last_command_error or "scheduled-task query failed"
            )
            return
        try:
            decoded = json.loads(out or "[]")
            rows = decoded if isinstance(decoded, list) else [decoded]
            if len(rows) > _MAX_COLLECTOR_RECORDS:
                self._surface_unknown(
                    "ScheduledTask",
                    "scheduled-task inventory exceeded 5000 records and was truncated",
                    partial=True,
                )
                return
            names: Set[str] = set()
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError("scheduled-task record is not an object")
                task_id = str(row.get("id") or "").strip()
                if not task_id or len(task_id) > 512:
                    raise ValueError("scheduled-task identity is missing or oversized")
                canonical = json.dumps(row, sort_keys=True, separators=(",", ":"))
                if len(canonical.encode("utf-8")) > _MAX_RECORD_BYTES:
                    raise ValueError(f"scheduled-task record exceeds bound: {task_id[:80]}")
                names.add(task_id)
                self._values[f"ScheduledTask\x00{task_id}"] = canonical
                self._values[f"ScheduledTask\x00{task_id}\x00mitre"] = "T1053.005"
            self._surface_complete("ScheduledTask", names)
        except Exception as exc:
            self._surface_unknown("ScheduledTask", exc)

    def _collect_wmi(self) -> None:
        out = self._run([
            "powershell", "-NoProfile", "-NonInteractive", "-Command", _WMI_QUERY
        ])
        if out is None:
            self._surface_unknown(
                "WMISubscription", self._last_command_error or "WMI query failed"
            )
            return
        try:
            document = json.loads(out or "{}")
            if not isinstance(document, dict):
                raise ValueError("WMI inventory is not an object")
            names: Set[str] = set()
            total = 0
            for key, prefix in (
                ("filters", "Filter"),
                ("consumers", "Consumer"),
                ("bindings", "Binding"),
            ):
                raw_rows = document.get(key, [])
                rows = raw_rows if isinstance(raw_rows, list) else (
                    [] if raw_rows is None else [raw_rows]
                )
                total += len(rows)
                if total > _MAX_COLLECTOR_RECORDS:
                    raise ValueError("WMI subscription record count exceeds bound")
                for row in rows:
                    if not isinstance(row, dict):
                        raise ValueError("WMI subscription record is not an object")
                    canonical = json.dumps(row, sort_keys=True, separators=(",", ":"))
                    if len(canonical.encode("utf-8")) > _MAX_RECORD_BYTES:
                        raise ValueError("WMI subscription record exceeds bound")
                    if prefix == "Binding":
                        identity = f"{row.get('Filter', '')}|{row.get('Consumer', '')}"
                    else:
                        identity = str(row.get("Name") or "")
                    identity = identity.strip()
                    if not identity:
                        raise ValueError(f"WMI {prefix.lower()} identity is missing")
                    record_id = f"{prefix}:{identity[:1024]}"
                    names.add(record_id)
                    self._values[f"WMISubscription\x00{record_id}"] = canonical
                    self._values[f"WMISubscription\x00{record_id}\x00mitre"] = "T1546.003"
            self._surface_complete("WMISubscription", names)
        except Exception as exc:
            self._surface_unknown("WMISubscription", exc)

    def _run(self, cmd) -> Optional[str]:
        self._last_command_error = ""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                               creationflags=_SUBPROCESS_FLAGS)
            if r.returncode != 0:
                self._last_command_error = (
                    (r.stderr or "").strip()[:1000]
                    or f"collector exited with status {r.returncode}"
                )
                return None
            output = r.stdout or ""
            if len(output.encode("utf-8", "replace")) > _MAX_COLLECTOR_OUTPUT_BYTES:
                self._last_command_error = "collector output exceeds its 8 MiB bound"
                return None
            return output
        except Exception as exc:
            self._last_command_error = str(exc)[:1000]
            return None

    def _sweep(self, include_slow: bool) -> Dict[str, Dict[str, str]]:
        self._pending: Dict[str, Set[str]] = {}
        self._values = {}
        self._coverage = {}
        self._collect_registry()
        self._collect_startup()
        self._collect_services()
        if include_slow:
            self._collect_scheduled()
            self._collect_wmi()
        return {
            surface: {
                entry: self._values.get(f"{surface}\x00{entry}", "")
                for entry in sorted(entries)
            }
            for surface, entries in self._pending.items()
        }

    def _mitre(self, surface: str, entry: str) -> str:
        return self._values.get(f"{surface}\x00{entry}\x00mitre", "T1547")

    @staticmethod
    def _diff(
        baseline: Dict[str, str], current: Dict[str, str]
    ) -> tuple[set[str], set[str], set[str]]:
        before = set(baseline)
        after = set(current)
        modified = {
            name for name in before & after if baseline[name] != current[name]
        }
        return after - before, modified, before - after

    def self_test(self) -> tuple[bool, str]:
        # Verify the classifier without touching the real host.
        a = self._classify("HKCU\\Run", "updater",
                            r"powershell -enc SQBFAFgA", "T1547.001")   # encoded PS → CRITICAL
        b = self._classify("HKLM\\Run", "tool",
                            r"C:\Users\me\AppData\Local\Temp\x.exe", "T1547.001")  # temp path → HIGH
        c = self._classify("HKLM\\Winlogon", "Shell", "explorer.exe", "T1547.004")  # default → not flagged high
        d = self._classify("HKLM\\Winlogon", "Shell", "explorer.exe,evil.exe", "T1547.004")  # hijack → CRITICAL
        added, modified, removed = self._diff(
            {"same": "1", "changed": "old", "gone": "x"},
            {"same": "1", "changed": "new", "added": "y"},
        )
        ok = (a[0] == Severity.CRITICAL and b[0] == Severity.HIGH
              and c[0] == Severity.MEDIUM and d[0] == Severity.CRITICAL
              and added == {"added"} and modified == {"changed"}
              and removed == {"gone"})
        return (ok, "persistence classifier verified (encoded-PS + Winlogon hijack CRITICAL, "
                    "temp-path HIGH, clean-default not escalated)"
                if ok else f"classifier failed: a={a} b={b} c={c} d={d}")

    def run(self) -> None:
        self.emit("Building an unreviewed persistence startup reference…", Severity.INFO)
        self._baseline = self._sweep(include_slow=True)
        if not self._coverage:
            # Compatibility for injected/test collectors that return a typed
            # snapshot directly. Production collectors always populate this.
            self._coverage = {
                surface: {"status": "complete", "error": ""}
                for surface in self._baseline
            }
        total = sum(len(v) for v in self._baseline.values())
        incomplete = {
            name: value for name, value in self._coverage.items()
            if value.get("status") != "complete"
        }
        self.emit(
            f"Persistence startup reference enrolled: {total} entries across "
            f"{len(self._baseline)} complete surface(s); operator review is required.",
            Severity.MEDIUM,
            finding_code="persistence.baseline.unreviewed",
            baseline_trust="unreviewed",
            coverage=self.coverage_snapshot(),
            response_authorized=False,
        )
        # Pre-existing high-risk persistence must not disappear into first-run
        # enrollment. Emit suspicious records immediately while keeping all
        # baseline content explicitly unreviewed.
        for surface, records in self._baseline.items():
            for entry, value in records.items():
                severity, reason = self._classify(
                    surface, entry, value, self._mitre(surface, entry)
                )
                if severity < Severity.HIGH:
                    continue
                fingerprint = hashlib.sha256(
                    f"{surface}\0{entry}\0baseline\0{value}".encode(
                        "utf-8", "replace"
                    )
                ).hexdigest()
                if not self._remember_change(fingerprint):
                    continue
                self.emit(
                    reason.replace("New persistence entry", "Unreviewed startup entry", 1),
                    severity,
                    change="baseline_enrollment",
                    surface=surface,
                    entry=entry,
                    value=value[:8192],
                    mitre=self._mitre(surface, entry),
                    baseline_trust="unreviewed",
                    response_authorized=False,
                )
        if incomplete:
            self.set_health(
                50,
                f"{len(incomplete)} persistence collector(s) UNKNOWN/PARTIAL; "
                "startup reference unreviewed",
            )
        else:
            self.set_health(75, "startup reference is complete but unreviewed")

        cycle = 0
        while not self.stopping:
            self.sleep(self.SWEEP_SECONDS)
            if self.stopping:
                break
            cycle += 1
            include_slow = (cycle % self.SLOW_EVERY == 0)
            current = self._sweep(include_slow=include_slow)
            if not self._coverage:
                self._coverage = {
                    surface: {"status": "complete", "error": ""}
                    for surface in current
                }
            incomplete = {
                name: value for name, value in self._coverage.items()
                if value.get("status") != "complete"
            }
            if incomplete:
                fingerprint = hashlib.sha256(
                    json.dumps(incomplete, sort_keys=True).encode("utf-8")
                ).hexdigest()
                if self._remember_change(f"coverage:{fingerprint}"):
                    self.emit(
                        "Persistence collection is incomplete; missing surfaces are "
                        "UNKNOWN and were not compared as empty.",
                        Severity.HIGH,
                        finding_code="persistence.collector.incomplete",
                        coverage=self.coverage_snapshot(),
                        response_authorized=False,
                    )
                self.set_health(
                    50,
                    f"{len(incomplete)} persistence collector(s) UNKNOWN/PARTIAL",
                )
            else:
                self.set_health(75, "startup reference remains unreviewed")
            for surface, records in current.items():
                base = self._baseline.get(surface, {})
                added, modified, removed = self._diff(base, records)
                for change, entries in (("added", added), ("modified", modified)):
                    for entry in entries:
                        val = records.get(entry, "")
                        fingerprint = hashlib.sha256(
                            f"{surface}\0{entry}\0{change}\0{val}".encode(
                                "utf-8", "replace"
                            )
                        ).hexdigest()
                        if not self._remember_change(fingerprint):
                            continue
                        sev, reason = self._classify(
                            surface, entry, val, self._mitre(surface, entry)
                        )
                        if change == "modified":
                            reason = reason.replace(
                                "New persistence entry", "Modified persistence entry", 1
                            )
                        self.emit(
                            reason,
                            sev,
                            change=change,
                            surface=surface,
                            entry=entry,
                            previous_value=base.get(entry, "")[:8192],
                            value=val[:8192],
                            mitre=self._mitre(surface, entry),
                            response_authorized=False,
                        )
                for entry in removed:
                    fingerprint = hashlib.sha256(
                        f"{surface}\0{entry}\0removed\0{base.get(entry, '')}".encode(
                            "utf-8", "replace"
                        )
                    ).hexdigest()
                    if not self._remember_change(fingerprint):
                        continue
                    self.emit(
                        f"Persistence entry removed: {surface}\\{entry} "
                        f"[{self._mitre(surface, entry)}]",
                        Severity.MEDIUM,
                        change="removed",
                        surface=surface,
                        entry=entry,
                        previous_value=base.get(entry, "")[:8192],
                        mitre=self._mitre(surface, entry),
                        response_authorized=False,
                    )
