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

import threading

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity

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


class ShadowCopyGuardModule(BaseModule):
    CODE = "VSSG"
    NAME = "Shadow-Copy / Recovery Tamper Guard"
    name = "Shadow-Copy / Recovery Tamper Guard"
    description = ("Detects shadow-copy deletion + recovery disabling (vssadmin/wmic/"
                   "wbadmin/bcdedit, T1490) — a ransomware precursor — and alerts with the pid.")
    category = "Detection"
    version = "1.0.0"

    _POLL = 2.0

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
            self.set_health(50, "psutil unavailable")
            self.emit("VSSG unavailable — psutil not present.", Severity.LOW)
            while not self.stopping:
                self.sleep(self._POLL)
            return
        self.emit("VSSG online — watching for shadow-copy/recovery tampering.", Severity.INFO)
        while not self.stopping:
            try:
                live = set()
                for p in psutil.process_iter(["pid", "name", "cmdline"]):
                    live.add(p.info["pid"])
                    try:
                        cmd = " ".join(p.info.get("cmdline") or [])
                    except Exception:
                        cmd = ""
                    reason = _looks_like_recovery_tamper(cmd)
                    if reason and p.info["pid"] not in self._alerted:
                        self._alerted.add(p.info["pid"])
                        self._detections += 1
                        # Attribute to the PARENT where possible — vssadmin is often a
                        # child of the real ransomware process; report both.
                        ppid = None
                        try:
                            ppid = psutil.Process(p.info["pid"]).ppid()
                        except Exception:
                            pass
                        self.emit(
                            f"⚠ RANSOMWARE PRECURSOR — {p.info.get('name','?')} "
                            f"(pid {p.info['pid']}, parent {ppid}) is {reason}. This inhibits "
                            "recovery before encryption. Contain immediately.",
                            Severity.CRITICAL, pid=p.info["pid"], ppid=ppid,
                            name=p.info.get("name"), mitre="T1490", cmdline=cmd[:200])
                self._alerted &= live
                self.set_health(100, f"{self._detections} recovery-tamper attempt(s) seen")
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
