"""shadowcopy_guard.py — Shadow-Copy / Recovery Tamper Guard (Code: VSSG).

Almost every ransomware family deletes Volume Shadow Copies and disables Windows
recovery just before (or while) encrypting, so victims can't roll back. That
"inhibit system recovery" step (T1490) is one of the highest-signal ransomware
precursors. This module watches command lines for those exact destructive
recovery-tampering commands and raises a CRITICAL with the offending pid — so
SOAR active defense can contain the process BEFORE encryption spreads.

Read-only detection (command-line signatures). Never runs any of these commands.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import os
import threading

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity
from angerona.core.response_contract import process_response

# Destructive recovery-tampering command signatures (all parts must appear).
_TAMPER_SIGNATURES = (
    ("vssadmin", "delete", "shadows"),
    ("vssadmin", "resize", "shadowstorage"),      # shrink to purge shadows
    ("wmic", "shadowcopy", "delete"),
    ("wbadmin", "delete", "catalog"),
    ("wbadmin", "delete", "systemstatebackup"),
    ("bcdedit", "recoveryenabled", "no"),
    ("bcdedit", "bootstatuspolicy", "ignoreallfailures"),
    ("delete", "shadows", "/all"),
)
_TAMPER_TOKENS = (
    "disable-computerrestore", "set-mppreference -disablerealtimemonitoring",
)


def _looks_like_recovery_tamper(cmdline: str) -> str | None:
    cl = (cmdline or "").lower()
    if not cl:
        return None
    for tok in _TAMPER_TOKENS:
        if tok in cl:
            return f"recovery-tamper token: {tok}"
    for sig in _TAMPER_SIGNATURES:
        if all(part in cl for part in sig):
            return "recovery-tamper pattern: " + " ".join(sig)
    return None


def _argv(raw_cmdline: object) -> tuple[str, ...]:
    if not isinstance(raw_cmdline, (list, tuple)):
        return ()
    return tuple(
        str(value).strip().strip('"').casefold()
        for value in raw_cmdline
        if str(value).strip()
    )


def _trusted_system_utility(
    process_name: object,
    executable: object,
) -> str | None:
    if os.name != "nt":
        return None
    try:
        from angerona.core.privilege import (
            _authenticode_valid,
            trusted_powershell_path,
            trusted_windows_directories,
        )

        raw = str(executable or "")
        if not raw or not os.path.isabs(raw):
            return None
        name = os.path.basename(raw).casefold()
        if name != os.path.basename(str(process_name or "")).casefold():
            return None
        _windows, system32 = trusted_windows_directories()
        allowed = {
            utility: system32 / utility
            for utility in ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe")
        }
        allowed["powershell.exe"] = trusted_powershell_path()
        expected = allowed.get(name)
        if expected is None:
            return None
        if os.path.normcase(os.path.realpath(raw)) != os.path.normcase(
            os.path.realpath(str(expected))
        ):
            return None
        return name if _authenticode_valid(expected) else None
    except Exception:
        return None


def _recovery_argv_is_destructive(name: str, raw_cmdline: object) -> bool:
    args = _argv(raw_cmdline)
    if not args:
        return False
    command_args = args[1:] if os.path.basename(args[0]).casefold() == name else args

    def starts(*expected: str) -> bool:
        return command_args[:len(expected)] == expected

    if name == "vssadmin.exe":
        return starts("delete", "shadows") or starts("resize", "shadowstorage")
    if name == "wmic.exe":
        return starts("shadowcopy", "delete")
    if name == "wbadmin.exe":
        return starts("delete", "catalog") or starts("delete", "systemstatebackup")
    if name == "bcdedit.exe":
        if len(command_args) != 4 or command_args[0] != "/set":
            return False
        boot_entry = command_args[1]
        if (
            len(boot_entry) < 3
            or not boot_entry.startswith("{")
            or not boot_entry.endswith("}")
            or not all(
                value.isalnum() or value == "-" for value in boot_entry[1:-1]
            )
        ):
            return False
        return command_args[2:] in (
            ("recoveryenabled", "no"),
            ("bootstatuspolicy", "ignoreallfailures"),
        )
    # PowerShell's -Command grammar permits arbitrary expressions and nested
    # scripts. A token match is useful telemetry but is not host-outage
    # authority without script-block correlation from a stronger detector.
    return False


class ShadowCopyGuardModule(BaseModule):
    CODE = "VSSG"
    NAME = "Shadow-Copy / Recovery Tamper Guard"
    name = "Shadow-Copy / Recovery Tamper Guard"
    description = ("Detects shadow-copy deletion + recovery disabling (vssadmin/wmic/"
                   "wbadmin/bcdedit, T1490) — a ransomware precursor — and alerts with the pid.")
    category = "Detection"
    version = "1.13.0"

    _POLL = 2.0

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._alerted: set[tuple[int, str, str]] = set()
        self._detections = 0
        self._last_coverage = {
            "enumerated": 0,
            "readable": 0,
            "unreadable": 0,
            "identity_incomplete": 0,
        }

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        if psutil is None:
            self.set_health(50, "psutil unavailable")
            self.emit("VSSG unavailable — psutil not present.", Severity.LOW)
            while not self.stopping:
                self.sleep(self._POLL)
            return
        self.emit("VSSG online — watching for shadow-copy/recovery tampering.", Severity.INFO)
        while not self.stopping:
            try:
                live: set[tuple[int, str, str]] = set()
                enumerated = 0
                readable = 0
                unreadable = 0
                identity_incomplete = 0
                for p in psutil.process_iter([
                    "pid", "name", "exe", "cmdline", "create_time"
                ]):
                    enumerated += 1
                    info = p.info
                    pid = info.get("pid")
                    if not isinstance(pid, int) or pid <= 0:
                        identity_incomplete += 1
                        continue
                    created = info.get("create_time")
                    executable = str(info.get("exe") or "").strip().casefold()
                    if created is None or not executable:
                        identity_incomplete += 1
                    identity = (pid, str(created or "unknown"), executable)
                    live.add(identity)
                    raw_cmdline = info.get("cmdline")
                    if raw_cmdline is None:
                        unreadable += 1
                        continue
                    try:
                        cmd = " ".join(raw_cmdline or [])
                    except Exception:
                        unreadable += 1
                        continue
                    readable += 1
                    reason = _looks_like_recovery_tamper(cmd)
                    if reason and identity not in self._alerted:
                        self._alerted.add(identity)
                        self._detections += 1
                        # Attribute to the PARENT where possible — vssadmin is often a
                        # child of the real ransomware process; report both.
                        ppid = None
                        try:
                            ppid = psutil.Process(pid).ppid()
                        except Exception:
                            pass
                        response = {}
                        trusted_name = _trusted_system_utility(
                            info.get("name"), info.get("exe")
                        )
                        if trusted_name and _recovery_argv_is_destructive(
                            trusted_name, raw_cmdline
                        ):
                            response = process_response(
                                pid, created, escalate_host=True
                            )
                        self.emit(
                            f"⚠ RANSOMWARE PRECURSOR — {info.get('name','?')} "
                            f"(pid {pid}, parent {ppid}) is {reason}. This inhibits "
                            "recovery before encryption. Contain immediately.",
                            Severity.CRITICAL, pid=pid, ppid=ppid,
                            name=info.get("name"), exe=info.get("exe"),
                            process_create_time=created,
                            mitre="T1490", cmdline=cmd[:200], active_attack=True,
                            detector_policy=(
                                "exact-recovery-tool-command"
                                if response
                                else "semantic-indicator-alert-only"
                            ),
                            **response)
                self._alerted &= live
                self._last_coverage = {
                    "enumerated": enumerated,
                    "readable": readable,
                    "unreadable": unreadable,
                    "identity_incomplete": identity_incomplete,
                }
                if enumerated == 0:
                    self.set_health(60, "process enumeration returned no coverage")
                elif unreadable or identity_incomplete:
                    self.set_health(
                        70,
                        f"process coverage incomplete: {readable}/{enumerated} command "
                        f"lines readable, {identity_incomplete} identity gap(s)",
                    )
                else:
                    self.set_health(
                        100,
                        f"{readable}/{enumerated} process command lines readable; "
                        f"{self._detections} recovery-tamper attempt(s) seen",
                    )
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(60, f"scan error: {exc}")
            self.sleep(self._POLL)

    def self_test(self) -> tuple[bool, str]:
        a = _looks_like_recovery_tamper("vssadmin.exe delete shadows /all /quiet")
        b = _looks_like_recovery_tamper("bcdedit /set {default} recoveryenabled No")
        c = _looks_like_recovery_tamper("wmic shadowcopy delete")
        neg = _looks_like_recovery_tamper("vssadmin list shadows")   # read-only, benign
        ok = bool(a) and bool(b) and bool(c) and neg is None
        return ok, ("recovery-tamper signatures verified (vssadmin/bcdedit/wmic flagged, "
                    "'list shadows' ignored)" if ok else
                    f"failed: vss={a} bcd={b} wmic={c} benign={neg}")


def register() -> ShadowCopyGuardModule:
    return ShadowCopyGuardModule()
