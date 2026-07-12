"""etw_listener.py — ETW Core Listener (Code: ETWG).

Purpose
    Capture process-creation and logon activity in-flight from Windows' own
    kernel-sourced telemetry (the ETW-backed Security channel) and republish it
    onto the AngeronaSuite EventBus so PROC/logon events feed triage, the
    provenance graph, and speculative pre-warming.

Sources (in priority order)
    1. Windows **Security** event log via ``win32evtlog`` — EID 4688 (process
       creation, with parent + command line when audit policy is on), 4624
       (successful logon), 4672 (special-privilege logon). This channel is ETW
       under the hood and is the supported user-mode capture path (no custom
       driver). Requires elevation, which the suite already runs with.
    2. Fallback: if that channel is unavailable (non-Windows, no pywin32, audit
       disabled, access denied) it degrades to psutil process-creation diffing so
       the pipeline still receives PROC events.

Safety
    Read-only consumption of local event telemetry. Nothing is written to the
    log, no policy is changed, nothing leaves the machine.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import os
import threading
import time

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity

_EID = {4688: "process_created", 4624: "logon", 4672: "privileged_logon"}


class EtwListenerModule(BaseModule):
    CODE = "ETWG"
    NAME = "ETW Core Listener"
    name = "ETW Core Listener"
    description = ("Captures process-creation (4688) + logon (4624/4672) telemetry "
                   "from the Windows Security channel; psutil fallback.")
    category = "Telemetry"
    version = "1.0.0"

    _POLL = 3.0

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._last_record = 0
        self._known_pids: set[int] = set()
        self._mode = "init"
        self.captured = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── ETW / Security channel ───────────────────────────────────────────────
    def _read_security_log(self) -> list[dict]:
        import win32evtlog  # type: ignore
        events: list[dict] = []
        h = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        try:
            highest = self._last_record
            batch = win32evtlog.ReadEventLog(h, flags, 0)
            for ev in batch or []:
                rec = int(getattr(ev, "RecordNumber", 0))
                highest = max(highest, rec)
                if rec <= self._last_record:
                    continue
                eid = int(ev.EventID) & 0xFFFF
                if eid not in _EID:
                    continue
                inserts = list(getattr(ev, "StringInserts", None) or [])
                events.append({"record": rec, "eid": eid, "kind": _EID[eid],
                               "inserts": inserts,
                               "ts": getattr(ev, "TimeGenerated", None)})
            if self._last_record == 0:      # first pass: set baseline, don't flood
                self._last_record = highest
                return []
            self._last_record = highest
        finally:
            win32evtlog.CloseEventLog(h)
        return list(reversed(events))       # oldest-first for causality

    @staticmethod
    def _describe(ev: dict) -> tuple[str, dict, Severity]:
        ins = ev["inserts"]
        if ev["eid"] == 4688:
            # 4688 inserts vary by OS; scan for the .exe token as the new image.
            new_img = next((s for s in ins if isinstance(s, str) and s.lower().endswith(".exe")), "")
            parent = next((s for s in reversed(ins)
                           if isinstance(s, str) and s.lower().endswith(".exe") and s != new_img), "")
            pid = next((s for s in ins if isinstance(s, str) and s.startswith("0x")), "")
            new_name = os.path.basename(new_img) if new_img else ""
            parent_name = os.path.basename(parent) if parent else ""
            details = {"name": new_name, "path": new_img, "parent_name": parent_name,
                       "pid_hex": pid, "eid": 4688, "raw": ins[:12]}
            suffix = f" (parent {parent_name})" if parent_name else ""
            return (f"Process created: {new_name or 'unknown'}{suffix}",
                    details, Severity.INFO)
        if ev["eid"] in (4624, 4672):
            user = next((s for s in ins if isinstance(s, str) and s and "\\" not in s
                         and s not in ("-",) and not s.startswith("0x")), "")
            details = {"eid": ev["eid"], "user": user, "kind": ev["kind"], "raw": ins[:12]}
            sev = Severity.LOW if ev["eid"] == 4672 else Severity.INFO
            return (f"Logon event ({ev['kind']}) user={user or 'n/a'}", details, sev)
        return (f"Security event {ev['eid']}", {"eid": ev["eid"], "raw": ins[:12]}, Severity.INFO)

    # ── psutil fallback ──────────────────────────────────────────────────────
    def _poll_psutil(self) -> list[dict]:
        if psutil is None:
            return []
        out = []
        current = {}
        for p in psutil.process_iter(["pid", "ppid", "name"]):
            current[p.info["pid"]] = p.info
        new_pids = set(current) - self._known_pids
        if self._known_pids:      # skip the first baseline sweep
            for pid in new_pids:
                info = current[pid]
                out.append({"eid": 4688, "kind": "process_created",
                            "inserts": [], "psutil": info})
        self._known_pids = set(current)
        return out

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        use_etw = os.name == "nt"
        if use_etw:
            try:
                import win32evtlog  # noqa: F401
            except Exception:
                use_etw = False
        self._mode = "security-channel" if use_etw else "psutil-fallback"
        self.emit(f"ETWG online — capturing process/logon telemetry ({self._mode}).",
                  Severity.INFO)
        while not self.stopping:
            try:
                if self._mode == "security-channel":
                    try:
                        events = self._read_security_log()
                    except Exception as exc:
                        self.last_error = str(exc)
                        self._mode = "psutil-fallback"   # e.g. access denied → degrade
                        self.set_health(70, f"Security channel unavailable ({exc}); psutil fallback")
                        events = []
                    for ev in events:
                        msg, details, sev = self._describe(ev)
                        details["source"] = "ETW:Security"
                        self.emit(msg, sev, **details)
                        self.captured += 1
                else:
                    for ev in self._poll_psutil():
                        info = ev.get("psutil", {})
                        self.emit(f"Process created: {info.get('name','?')} (psutil)",
                                  Severity.INFO, name=info.get("name"), pid=info.get("pid"),
                                  ppid=info.get("ppid"), eid=4688, source="psutil")
                        self.captured += 1
                if self.health < 90 and self._mode == "security-channel":
                    self.set_health(100, "Security channel live")
                elif self._mode == "psutil-fallback":
                    self.set_health(75, "psutil fallback (enable 4688 auditing for full fidelity)")
                else:
                    self.set_health(100, f"{self.captured} events captured")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(50, "capture error")
            self.sleep(self._POLL)

    def self_test(self) -> tuple[bool, str]:
        """Verify the 4688/4624 describers produce well-formed events."""
        msg, details, sev = self._describe(
            {"eid": 4688, "kind": "process_created",
             "inserts": ["S-1-5-18", "0x3e7", "0x1a4", r"C:\Windows\System32\cmd.exe",
                         "%%1936", r"C:\Windows\explorer.exe"]})
        ok = details.get("name") == "cmd.exe" and "cmd.exe" in msg
        if os.name == "nt":
            try:
                import win32evtlog  # noqa: F401
                mode = "Security channel available"
            except Exception:
                mode = "pywin32 missing → psutil fallback"
        else:
            mode = "non-Windows → psutil fallback"
        return (ok, f"4688 decode verified ({mode})" if ok
                else f"4688 decode failed: {details}")


def register() -> EtwListenerModule:
    return EtwListenerModule()
