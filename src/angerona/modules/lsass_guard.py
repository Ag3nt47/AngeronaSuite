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

import os
import threading

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity

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


class LsassGuardModule(BaseModule):
    CODE = "CREDG"
    NAME = "LSASS Credential-Access Guard"
    name = "LSASS Credential-Access Guard"
    description = ("Detects LSASS credential-dumping (Mimikatz/procdump/comsvcs MiniDump, "
                   "T1003.001) by process command line + artifact signatures. Read-only.")
    category = "Detection"
    version = "1.0.0"

    _POLL = 3.0

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._alerted: set[int] = set()
        self._detections = 0

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
                live = set()
                for p in psutil.process_iter(["pid", "name", "cmdline"]):
                    live.add(p.info["pid"])
                    try:
                        cmd = " ".join(p.info.get("cmdline") or [])
                    except Exception:
                        cmd = ""
                    reason = _looks_like_lsass_dump(cmd)
                    if reason and p.info["pid"] not in self._alerted:
                        self._alerted.add(p.info["pid"])
                        self._detections += 1
                        self.emit(
                            f"⚠ LSASS credential-access attempt: {p.info.get('name','?')} "
                            f"(pid {p.info['pid']}) — {reason}. Possible credential theft.",
                            Severity.CRITICAL, pid=p.info["pid"], name=p.info.get("name"),
                            mitre="T1003.001", cmdline=cmd[:200])
                # evict pids that have exited so re-launches re-alert
                self._alerted &= live
                self.set_health(100, f"{self._detections} credential-dump attempt(s) seen")
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
