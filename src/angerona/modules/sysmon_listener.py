"""Sysmon Event Bridge — G2-A.

Subscribes to the Microsoft-Windows-Sysmon/Operational event log and
translates EID 1/3/6/8/10/25 into Angerona bus events.

Why a separate module instead of folding into etw_listener?
  - etw_listener covers Windows native process/logon audit (EID 4688 etc.)
  - Sysmon provides *richer* telemetry (command-line hashes, parent spoofing
    detection, remote-thread targets) under a separate channel, and the
    signal-to-noise ratio depends on our own sysmon_config.xml allowlists.
    Keeping them separate means a Sysmon crash doesn't take down ETW coverage.

Fallback: if Sysmon/win32evtlog is unavailable the module falls back to a
psutil process-diff loop that catches EID-1-equivalent events (new processes).
The fallback is notably weaker — it misses network, driver, thread, and tamper
events — but keeps the sensor alive and the bus healthy.

Dependencies (optional Windows-only):
  pip install pywin32
"""
from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Optional

from angerona.core.module_base import BaseModule, Severity

# ── EID metadata ─────────────────────────────────────────────────────────────
# Maps Sysmon Event ID → (human label, MITRE tags, Severity)
_EID_MAP: dict[int, tuple[str, list[str], Severity]] = {
    1:  ("Process Created",          ["T1059", "T1106"],          Severity.INFO),
    3:  ("Network Connection",       ["T1071", "T1095"],          Severity.MEDIUM),
    6:  ("Driver Loaded",            ["T1014", "T1547.006"],      Severity.HIGH),
    8:  ("CreateRemoteThread",       ["T1055.003"],               Severity.CRITICAL),
    10: ("ProcessAccess",            ["T1003.001", "T1055"],      Severity.CRITICAL),
    25: ("ProcessTampering",         ["T1055.012"],               Severity.CRITICAL),
}

# win32evtlog constants (defined here so the module loads on non-Windows too)
_EVTLOG_SEQ_FWD = 0x0001 | 0x0004   # EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ
_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# XML namespace Sysmon uses in its event payloads
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _extract_field(root: ET.Element, name: str) -> str:
    """Pull a named EventData field from the Sysmon XML payload."""
    for node in root.iter(f"{{{_NS}}}Data"):
        if node.get("Name") == name:
            return (node.text or "").strip()
    return ""


def _build_message(eid: int, root: ET.Element) -> str:
    """Produce a concise human-readable description for each EID type."""
    get = lambda n: _extract_field(root, n)  # noqa: E731

    if eid == 1:
        image   = get("Image").split("\\")[-1]
        cmdline = get("CommandLine")[:200]
        parent  = get("ParentImage").split("\\")[-1]
        hsh     = get("Hashes").split(",")[0]  # first hash (SHA256=...)
        return (f"Process created: {image} | parent={parent} | "
                f"cmd={cmdline} | {hsh}")

    if eid == 3:
        image = get("Image").split("\\")[-1]
        dst   = get("DestinationIp")
        dport = get("DestinationPort")
        proto = get("Protocol")
        return f"Network connection: {image} → {dst}:{dport} ({proto})"

    if eid == 6:
        driver = get("ImageLoaded").split("\\")[-1]
        sig    = get("Signature")
        signed = get("Signed")
        hsh    = get("Hashes").split(",")[0]
        return (f"Driver loaded: {driver} | signed={signed} | "
                f"signer={sig} | {hsh}")

    if eid == 8:
        src    = get("SourceImage").split("\\")[-1]
        dst    = get("TargetImage").split("\\")[-1]
        spid   = get("SourceProcessId")
        tpid   = get("TargetProcessId")
        return f"RemoteThread injected: {src}(PID={spid}) → {dst}(PID={tpid})"

    if eid == 10:
        src    = get("SourceImage").split("\\")[-1]
        dst    = get("TargetImage").split("\\")[-1]
        access = get("GrantedAccess")
        return f"ProcessAccess: {src} → {dst} (GrantedAccess={access})"

    if eid == 25:
        image = get("Image").split("\\")[-1]
        ptype = get("Type")
        return f"ProcessTampering ({ptype}): {image}"

    return f"Sysmon EID {eid}"


def _build_details(eid: int, root: ET.Element, label: str, tags: list[str]) -> dict:
    """Collect all EventData fields into a details dict for the bus event."""
    get = lambda n: _extract_field(root, n)  # noqa: E731
    base: dict = {
        "eid":        eid,
        "label":      label,
        "mitre_tags": tags,
    }
    if eid == 1:
        base.update({
            "image":          get("Image"),
            "command_line":   get("CommandLine"),
            "parent_image":   get("ParentImage"),
            "parent_cmdline": get("ParentCommandLine"),
            "user":           get("User"),
            "hashes":         get("Hashes"),
            "pid":            get("ProcessId"),
            "parent_pid":     get("ParentProcessId"),
        })
    elif eid == 3:
        base.update({
            "image":          get("Image"),
            "dest_ip":        get("DestinationIp"),
            "dest_port":      get("DestinationPort"),
            "dest_hostname":  get("DestinationHostname"),
            "protocol":       get("Protocol"),
            "pid":            get("ProcessId"),
        })
    elif eid == 6:
        base.update({
            "image_loaded":   get("ImageLoaded"),
            "hashes":         get("Hashes"),
            "signed":         get("Signed"),
            "signature":      get("Signature"),
        })
    elif eid == 8:
        base.update({
            "source_image":   get("SourceImage"),
            "source_pid":     get("SourceProcessId"),
            "target_image":   get("TargetImage"),
            "target_pid":     get("TargetProcessId"),
            "start_address":  get("StartAddress"),
            "start_module":   get("StartModule"),
        })
    elif eid == 10:
        base.update({
            "source_image":   get("SourceImage"),
            "source_pid":     get("SourceProcessId"),
            "target_image":   get("TargetImage"),
            "target_pid":     get("TargetProcessId"),
            "granted_access": get("GrantedAccess"),
            "call_trace":     get("CallTrace")[:300],
        })
    elif eid == 25:
        base.update({
            "image":    get("Image"),
            "pid":      get("ProcessId"),
            "type":     get("Type"),
        })
    return base


# ── Module ────────────────────────────────────────────────────────────────────

class SysmonListenerModule(BaseModule):
    CODE = "SYSL"
    NAME = "Sysmon Event Bridge"
    name = "Sysmon Event Bridge"
    description = (
        "Reads Microsoft-Windows-Sysmon/Operational events (EID 1/3/6/8/10/25) "
        "and emits them onto the Angerona bus. Falls back to psutil process-diff "
        "when Sysmon or win32evtlog is unavailable."
    )
    category = "Endpoint"

    # Polling interval between event-log reads (seconds).  Short enough not to
    # miss a burst, long enough not to burn CPU.
    _POLL_INTERVAL = 2.0

    # How often to scan the process table in fallback mode (seconds).
    _FALLBACK_INTERVAL = 5.0

    def __init__(self) -> None:
        super().__init__()
        self._using_fallback = False
        self._evtlog_handle = None   # win32evtlog handle, if available
        self._seen_pids: set[int] = set()   # for psutil fallback dedup

    # ── Properties required by ModuleManager ────────────────────────────────
    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        if self._try_open_sysmon():
            self._run_sysmon_loop()
        else:
            self._run_fallback_loop()

    def _try_open_sysmon(self) -> bool:
        """Attempt to open the Sysmon event log channel.

        Returns True if successful; False if Sysmon is not installed or
        win32evtlog is not available (non-Windows or missing pywin32).
        """
        try:
            import win32evtlog  # type: ignore[import]
            self._evtlog_handle = win32evtlog.OpenEventLog(None, _SYSMON_CHANNEL)
            self._using_fallback = False
            self.set_health(100, "")
            self.emit(
                f"Sysmon channel opened: {_SYSMON_CHANNEL}",
                Severity.INFO,
                channel=_SYSMON_CHANNEL,
            )
            return True
        except Exception as exc:
            self._using_fallback = True
            self.set_health(
                50,
                f"Sysmon unavailable — running psutil fallback: {exc}",
            )
            self.emit(
                f"Sysmon/win32evtlog not available ({exc}). "
                "Running psutil process-diff fallback (EID-1 equivalent only). "
                "Install Sysmon64 + pywin32 for full coverage.",
                Severity.MEDIUM,
                fallback=True,
            )
            return False

    # ── Sysmon event log loop ─────────────────────────────────────────────────
    def _run_sysmon_loop(self) -> None:
        """Continuously poll the Sysmon event log and emit matching events."""
        import win32evtlog  # type: ignore[import]

        # Seek to end so we only see events that arrive after module start.
        # win32evtlog has no direct SEEK_END; read+discard the current backlog.
        try:
            while True:
                records = win32evtlog.ReadEventLog(
                    self._evtlog_handle,
                    _EVTLOG_SEQ_FWD,
                    0,
                )
                if not records:
                    break
        except Exception:
            pass   # empty log is fine

        while not self.stopping:
            try:
                records = win32evtlog.ReadEventLog(
                    self._evtlog_handle,
                    _EVTLOG_SEQ_FWD,
                    0,
                )
                if records:
                    for rec in records:
                        self._process_record(rec)
            except Exception as exc:
                self.set_health(60, f"Read error: {exc}")
                self.emit(
                    f"Sysmon log read error: {exc}",
                    Severity.MEDIUM,
                )
                # Try to reopen the channel once
                try:
                    self._evtlog_handle = win32evtlog.OpenEventLog(None, _SYSMON_CHANNEL)
                    self.set_health(100, "")
                except Exception:
                    pass
            self.sleep(self._POLL_INTERVAL)

    def _process_record(self, rec: object) -> None:
        """Parse a single win32evtlog record and emit onto the bus."""
        try:
            eid = int(rec.EventID & 0xFFFF)  # strip facility/severity bits
        except Exception:
            return
        if eid not in _EID_MAP:
            return

        label, tags, severity = _EID_MAP[eid]

        # Reconstruct the XML payload from the StringInserts field.
        # Sysmon stores the full event XML as the first StringInsert.
        xml_str: Optional[str] = None
        try:
            inserts = rec.StringInserts
            if inserts:
                xml_str = inserts[0] if isinstance(inserts[0], str) else None
        except Exception:
            pass

        if xml_str:
            try:
                root = ET.fromstring(xml_str)
                msg     = _build_message(eid, root)
                details = _build_details(eid, root, label, tags)
            except ET.ParseError:
                msg     = f"Sysmon EID {eid}: {label} (XML parse error)"
                details = {"eid": eid, "label": label, "mitre_tags": tags}
        else:
            msg     = f"Sysmon EID {eid}: {label}"
            details = {"eid": eid, "label": label, "mitre_tags": tags}

        self.emit(msg, severity, **details)

    # ── psutil fallback loop ──────────────────────────────────────────────────
    def _run_fallback_loop(self) -> None:
        """Psutil process-diff loop — EID-1-equivalent new-process detection.

        Much weaker than Sysmon (no network/driver/thread/tamper events), but
        keeps the module contributing useful signal on machines without Sysmon.
        """
        try:
            import psutil  # type: ignore[import]
        except ImportError:
            self.set_health(0, "psutil unavailable — sensor blind")
            self.emit(
                "psutil not installed; Sysmon fallback cannot run. "
                "pip install psutil to restore coverage.",
                Severity.HIGH,
            )
            # Park the thread so the module stays alive but idle
            while not self.stopping:
                self.sleep(30.0)
            return

        # Seed the seen-PID set with whatever is already running
        try:
            self._seen_pids = {p.pid for p in psutil.process_iter(["pid"])}
        except Exception:
            self._seen_pids = set()

        while not self.stopping:
            self.sleep(self._FALLBACK_INTERVAL)
            try:
                current: dict[int, psutil.Process] = {}
                for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
                    try:
                        current[proc.pid] = proc
                    except Exception:
                        pass

                new_pids = set(current.keys()) - self._seen_pids
                self._seen_pids = set(current.keys())

                for pid in new_pids:
                    proc = current.get(pid)
                    if proc is None:
                        continue
                    try:
                        info  = proc.as_dict(["name", "exe", "cmdline", "ppid"])
                        name  = info.get("name") or "unknown"
                        exe   = info.get("exe") or ""
                        cmd   = " ".join(info.get("cmdline") or [])[:200]
                        ppid  = info.get("ppid", 0)
                        pname = "unknown"
                        try:
                            pname = psutil.Process(ppid).name() if ppid else "unknown"
                        except Exception:
                            pass
                        self.emit(
                            f"[FALLBACK] Process created: {name} | parent={pname} | cmd={cmd}",
                            Severity.INFO,
                            eid=1,
                            label="Process Created (psutil fallback)",
                            mitre_tags=["T1059", "T1106"],
                            image=exe,
                            command_line=cmd,
                            pid=pid,
                            parent_pid=ppid,
                            parent_image=pname,
                            fallback=True,
                        )
                    except Exception:
                        pass
            except Exception as exc:
                self.set_health(40, f"Fallback loop error: {exc}")

    # ── Health check ─────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        if self.status != "running":
            return super().self_test()   # not started yet — graceful "stopped" status
        if self._using_fallback:
            return True, "Running psutil fallback (Sysmon not installed)"
        if self._evtlog_handle is not None:
            return True, f"Sysmon channel open: {_SYSMON_CHANNEL}"
        return False, "Not yet initialised"


def register() -> SysmonListenerModule:
    return SysmonListenerModule()
