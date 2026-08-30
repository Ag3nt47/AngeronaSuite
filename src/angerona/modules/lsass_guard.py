"""lsass_guard.py — LSASS Credential-Access Guard (Code: CREDG).

Detects credential-dumping activity against LSASS (T1003.001) — the classic
Mimikatz / procdump / comsvcs-MiniDump technique used to steal Windows
credentials. It watches running command lines and dropped artifacts for the
signatures of the common dumping tools and living-off-the-land methods, and
raises a CRITICAL (with the offending pid, so SOAR active defense can contain it).

Detection is behavioral/signature based on process command lines and file drops —
it never reads LSASS memory itself. Read-only, no host change.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import math
import os
import threading

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity
from angerona.core.response_contract import process_response

# Command-line signatures of common LSASS credential-dumping techniques.
_DUMP_SIGNATURES = (
    ("comsvcs", "minidump"),          # rundll32 comsvcs.dll, MiniDump <pid> lsass.dmp full
    ("procdump", "lsass"),            # procdump -ma lsass.exe
    ("-ma", "lsass"),
    ("rundll32", "minidump"),
    ("sqldumper", "lsass"),
    ("createdump", "lsass"),
)
_DUMP_TOKENS = (
    "sekurlsa", "mimikatz", "lsass.dmp", "nanodump", "dumpert", "lsassy",
    "pypykatz", "handlekatz", "safetykatz", "invoke-mimikatz",
)


def _process_generation(info: dict) -> tuple[tuple[int, str, str] | None, bool]:
    try:
        pid = int(info.get("pid"))
    except (TypeError, ValueError):
        return None, False
    if pid <= 0:
        return None, False
    executable = str(info.get("exe") or info.get("name") or "").casefold()
    try:
        birth = float(info.get("create_time"))
    except (TypeError, ValueError):
        birth = float("nan")
    complete = math.isfinite(birth) and birth > 0
    token = f"{birth:.6f}" if complete else f"unknown:{executable}"
    return (pid, token, executable), complete


def _looks_like_lsass_dump(cmdline: str) -> str | None:
    """Return a short reason if the command line looks like LSASS dumping, else None."""
    cl = (cmdline or "").lower()
    if not cl:
        return None
    for tok in _DUMP_TOKENS:
        if tok in cl:
            return f"credential-dump token: {tok}"
    for sig in _DUMP_SIGNATURES:
        if all(part in cl for part in sig):
            return "credential-dump pattern: " + " + ".join(sig)
    return None


def _argv(raw_cmdline: object) -> tuple[str, ...]:
    if not isinstance(raw_cmdline, (list, tuple)):
        return ()
    return tuple(
        str(value).strip().strip('"').casefold()
        for value in raw_cmdline
        if str(value).strip()
    )


def _exact_process_image(process_name: object, executable: object) -> str | None:
    raw = str(executable or "")
    if not raw or not os.path.isabs(raw):
        return None
    image_name = os.path.basename(raw).casefold()
    if image_name != os.path.basename(str(process_name or "")).casefold():
        return None
    return raw


def _trusted_system_image(executable: str, expected_name: str) -> bool:
    """Require the genuine signed System32 image before host escalation."""
    if os.name != "nt":
        return False
    try:
        from angerona.core.privilege import (
            _authenticode_valid,
            trusted_windows_directories,
        )

        _windows, system32 = trusted_windows_directories()
        image = os.path.realpath(executable)
        expected = os.path.realpath(str(system32 / expected_name))
        return os.path.normcase(image) == os.path.normcase(expected) and bool(
            _authenticode_valid(system32 / expected_name)
        )
    except Exception:
        return False


def _rundll32_targets_lsass(args: tuple[str, ...]) -> bool:
    if os.name != "nt" or len(args) < 2:
        return False
    try:
        from angerona.core.privilege import trusted_windows_directories

        _windows, system32 = trusted_windows_directories()
        canonical = os.path.normcase(os.path.realpath(str(system32 / "comsvcs.dll")))
        first = args[0].replace("/", "\\")
        combined_suffix = ",minidump"
        if first.endswith(combined_suffix):
            dll = first[:-len(combined_suffix)]
            pid_index = 1
        elif first.endswith(",") and args[1] == "minidump":
            dll = first[:-1]
            pid_index = 2
        else:
            return False
        if os.path.normcase(os.path.realpath(dll)) != canonical:
            return False
        target = args[pid_index]
    except (IndexError, OSError, RuntimeError, ValueError):
        return False
    if not target.isdecimal():
        return False
    try:
        return psutil is not None and psutil.Process(int(target)).name().casefold() == "lsass.exe"
    except Exception:
        return False


def _lsass_response_scope(
    process_name: object,
    executable: object,
    raw_cmdline: object,
) -> str | None:
    """Return ``process``/``host`` only for role-aware, unambiguous argv."""
    image = _exact_process_image(process_name, executable)
    args = _argv(raw_cmdline)
    if image is None or not args:
        return None
    name = os.path.basename(image).casefold()
    command_args = args[1:] if os.path.basename(args[0]).casefold() == name else args
    if name in {"procdump.exe", "procdump64.exe"}:
        try:
            target_index = command_args.index("-ma") + 1
            target = command_args[target_index].replace("/", "\\").rsplit("\\", 1)[-1]
        except (IndexError, ValueError):
            return None
        return "process" if target in {"lsass", "lsass.exe"} else None
    if name == "rundll32.exe" and _rundll32_targets_lsass(command_args):
        return (
            "host"
            if _trusted_system_image(image, "rundll32.exe")
            else "process"
        )
    if name in {"mimikatz.exe", "safetykatz.exe"} and any(
        value.startswith("sekurlsa::") for value in command_args
    ):
        return "process"
    return None


class LsassGuardModule(BaseModule):
    CODE = "CREDG"
    NAME = "LSASS Credential-Access Guard"
    name = "LSASS Credential-Access Guard"
    description = ("Detects LSASS credential-dumping (Mimikatz/procdump/comsvcs MiniDump, "
                   "T1003.001) by process command line + artifact signatures. Read-only.")
    category = "Detection"
    version = "1.12.1"

    _POLL = 3.0

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
            self.set_health(50, "psutil unavailable — cannot inspect processes")
            self.emit("CREDG unavailable — psutil not present.", Severity.LOW)
            while not self.stopping:
                self.sleep(self._POLL)
            return
        self.emit("CREDG online — watching for LSASS credential-dumping.", Severity.INFO)
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
                    identity, complete = _process_generation(info)
                    if identity is None:
                        identity_incomplete += 1
                        continue
                    live.add(identity)
                    identity_incomplete += int(not complete)
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
                    reason = _looks_like_lsass_dump(cmd)
                    if reason and identity not in self._alerted:
                        self._alerted.add(identity)
                        self._detections += 1
                        pid = identity[0]
                        created = info.get("create_time")
                        response = {}
                        scope = _lsass_response_scope(
                            info.get("name"),
                            info.get("exe"),
                            raw_cmdline,
                        )
                        if scope:
                            response = process_response(
                                pid, created, escalate_host=scope == "host"
                            )
                        self.emit(
                            f"⚠ LSASS credential-access attempt: {info.get('name','?')} "
                            f"(pid {pid}) — {reason}. Possible credential theft.",
                            Severity.CRITICAL, pid=pid, name=info.get("name"),
                            exe=info.get("exe"),
                            process_create_time=created, mitre="T1003.001",
                            cmdline=cmd[:200], active_attack=True,
                            detector_policy=(
                                "exact-tool-lsass-dump"
                                if response
                                else "semantic-indicator-alert-only"
                            ),
                            **response)
                # Evict exact generations that exited. A new birth at the same
                # PID remains distinct even if PID continuity spans snapshots.
                self._alerted &= live
                self._last_coverage = {
                    "enumerated": enumerated,
                    "readable": readable,
                    "unreadable": unreadable,
                    "identity_incomplete": identity_incomplete,
                }
                if enumerated == 0:
                    self.set_health(60, "process enumeration returned no LSASS coverage")
                elif unreadable or identity_incomplete:
                    self.set_health(
                        70,
                        f"LSASS coverage incomplete: {readable}/{enumerated} command "
                        f"lines readable, {identity_incomplete} identity gap(s)",
                    )
                else:
                    self.set_health(
                        100,
                        f"{readable}/{enumerated} process generations inspected; "
                        f"{self._detections} credential-dump attempt(s) seen",
                    )
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(60, f"scan error: {exc}")
            self.sleep(self._POLL)

    def self_test(self) -> tuple[bool, str]:
        pos = _looks_like_lsass_dump(
            r'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 640 C:\lsass.dmp full')
        pos2 = _looks_like_lsass_dump("procdump64.exe -ma lsass.exe out.dmp")
        neg = _looks_like_lsass_dump(r"C:\Windows\explorer.exe")
        ok = bool(pos) and bool(pos2) and neg is None
        return ok, ("LSASS-dump signature matcher verified (comsvcs+procdump flagged, "
                    "benign ignored)" if ok else
                    f"failed: comsvcs={pos} procdump={pos2} benign={neg}")


def register() -> LsassGuardModule:
    return LsassGuardModule()
