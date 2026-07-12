"""AV Telemetry Bridge — G2-G (part 1).

Bridges Windows Defender operational events into the Angerona event bus.

Monitored Event IDs (Microsoft-Windows-Windows Defender/Operational channel):
  EID 1116 — Malware detected (threat name, file path, detection source)
  EID 1117 — Malware action taken (quarantine/remove/block)
  EID 5001 — Real-time protection disabled (CRITICAL — sensor gap)

Why this matters:
  Windows Defender is always on for home/SMB users.  When it detects something,
  we want that signal on our bus so SOAR / provenance_graph / AI-triage can
  correlate it with our own sensor output.  EID 5001 is especially important —
  an attacker who disables real-time protection opens a sensor gap that our
  bus should immediately surface.

Implementation:
  Uses win32evtlog on the Defender Operational channel (same pattern as
  etw_listener and sysmon_listener).  The Defender channel is readable by
  non-admin users — no elevation required.

Fallback:
  If win32evtlog is unavailable (non-Windows / no pywin32), the module
  falls back to polling `Get-MpThreatDetection` via PowerShell every 60s.
  The PowerShell path requires Windows Defender cmdlets (present by default
  on Windows 10/11).  If neither method works, the module idles.
"""
from __future__ import annotations

import json
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Optional

from angerona.core.module_base import BaseModule, Severity
from angerona.core.win import check_output_hidden

_DEFENDER_CHANNEL   = "Microsoft-Windows-Windows Defender/Operational"
_EVTLOG_SEQ_FWD     = 0x0001 | 0x0004   # SEQUENTIAL_READ | FORWARDS_READ
_POLL_INTERVAL      = 30.0              # seconds between log reads (was 10 — AV events don't need sub-30s latency)
_FALLBACK_INTERVAL  = 120.0            # seconds between PowerShell polls (was 60)

# Map Defender EID → (label, Severity, MITRE)
_EID_MAP = {
    1116: ("Malware Detected",              Severity.CRITICAL, ["T1204", "T1059"]),
    1117: ("Malware Action Taken",          Severity.HIGH,     ["T1204"]),
    5001: ("Real-Time Protection Disabled", Severity.CRITICAL, ["T1562.001"]),
}

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _extract(root: ET.Element, name: str) -> str:
    for node in root.iter(f"{{{_NS}}}Data"):
        if node.get("Name") == name:
            return (node.text or "").strip()
    return ""


def _parse_1116(root: ET.Element) -> tuple[str, dict]:
    threat    = _extract(root, "Threat Name")
    path      = _extract(root, "Path")
    severity  = _extract(root, "Severity Name")
    action    = _extract(root, "Action Name")
    proc      = _extract(root, "Process Name")
    msg = (
        f"Defender detected {threat!r} at {path!r} "
        f"(severity={severity}, action={action}, process={proc})"
    )
    details = {
        "threat_name":    threat,
        "path":           path,
        "av_severity":    severity,
        "action":         action,
        "process":        proc,
        "mitre_tags":     ["T1204", "T1059"],
    }
    return msg, details


def _parse_1117(root: ET.Element) -> tuple[str, dict]:
    threat  = _extract(root, "Threat Name")
    path    = _extract(root, "Path")
    action  = _extract(root, "Action Name")
    result  = _extract(root, "Action Status")
    msg = f"Defender remediated {threat!r} — {action} on {path!r} ({result})"
    details = {
        "threat_name":    threat,
        "path":           path,
        "action":         action,
        "result":         result,
        "mitre_tags":     ["T1204"],
    }
    return msg, details


def _parse_5001(root: ET.Element) -> tuple[str, dict]:
    reason = _extract(root, "Reason") or "unknown reason"
    msg    = (
        f"Windows Defender REAL-TIME PROTECTION DISABLED ({reason}) — "
        "sensor gap: threats may execute undetected (T1562.001)"
    )
    return msg, {"reason": reason, "mitre_tags": ["T1562.001"]}


_PARSERS = {1116: _parse_1116, 1117: _parse_1117, 5001: _parse_5001}


class AVTelemetryBridgeModule(BaseModule):
    CODE = "AVTB"
    NAME = "AV Telemetry Bridge"
    name = "AV Telemetry Bridge"
    description = (
        "Bridges Windows Defender detection events (EID 1116/1117/5001) into "
        "the Angerona bus for cross-sensor correlation."
    )
    category = "Endpoint"

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        if self._try_evtlog_mode():
            return
        if self._try_powershell_mode():
            return
        # Both unavailable
        self.set_health(0, "Defender channel and PowerShell cmdlets unavailable")
        self.emit(
            "AV Telemetry Bridge: no telemetry path available (non-Windows or no pywin32/MpCmdRun). "
            "Module idle.",
            Severity.MEDIUM,
        )
        while not self.stopping:
            self.sleep(120.0)

    # ── win32evtlog mode ──────────────────────────────────────────────────────
    def _try_evtlog_mode(self) -> bool:
        try:
            import win32evtlog  # type: ignore[import]
            handle = win32evtlog.OpenEventLog(None, _DEFENDER_CHANNEL)
        except Exception:
            return False

        self.emit(
            f"AV Telemetry Bridge active — monitoring {_DEFENDER_CHANNEL}",
            Severity.INFO,
            channel=_DEFENDER_CHANNEL,
        )
        self.set_health(100, "")

        # Drain backlog silently so we only see new events going forward
        try:
            while True:
                recs = win32evtlog.ReadEventLog(handle, _EVTLOG_SEQ_FWD, 0)
                if not recs:
                    break
        except Exception:
            pass

        while not self.stopping:
            try:
                recs = win32evtlog.ReadEventLog(handle, _EVTLOG_SEQ_FWD, 0)
                if recs:
                    for rec in recs:
                        self._process_record(rec)
            except Exception as exc:
                self.set_health(60, f"Read error: {exc}")
                try:
                    handle = win32evtlog.OpenEventLog(None, _DEFENDER_CHANNEL)
                    self.set_health(100, "")
                except Exception:
                    pass
            self.sleep(_POLL_INTERVAL)
        return True

    def _process_record(self, rec: object) -> None:
        try:
            eid = int(rec.EventID & 0xFFFF)
        except Exception:
            return
        if eid not in _EID_MAP:
            return
        _, severity, _ = _EID_MAP[eid]
        parser = _PARSERS.get(eid)

        xml_str: Optional[str] = None
        try:
            inserts = rec.StringInserts
            if inserts and isinstance(inserts[0], str):
                xml_str = inserts[0]
        except Exception:
            pass

        if xml_str and parser:
            try:
                root = ET.fromstring(xml_str)
                msg, details = parser(root)
            except ET.ParseError:
                msg     = f"Defender EID {eid} (XML parse error)"
                details = {}
        else:
            label   = _EID_MAP[eid][0]
            msg     = f"Defender: {label} (EID {eid})"
            details = {}

        self.emit(msg, severity, eid=eid, **details)

    # ── PowerShell fallback mode ──────────────────────────────────────────────
    def _try_powershell_mode(self) -> bool:
        """Use Get-MpThreatDetection if win32evtlog is unavailable."""
        try:
            out = check_output_hidden(
                ["powershell", "-NoProfile", "-Command",
                 "Get-MpThreatDetection | ConvertTo-Json -Depth 3"],
                timeout=30,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            _ = json.loads(out or "[]")
        except Exception:
            return False

        self.emit(
            "AV Telemetry Bridge: running PowerShell Get-MpThreatDetection fallback.",
            Severity.INFO,
            fallback=True,
        )
        self.set_health(80, "PowerShell fallback — no real-time EID monitoring")

        last_seen: set[str] = set()
        # Seed
        try:
            threats = self._poll_ps()
            for t in threats:
                last_seen.add(t.get("DetectionID", ""))
        except Exception:
            pass

        while not self.stopping:
            self.sleep(_FALLBACK_INTERVAL)
            try:
                threats = self._poll_ps()
                for t in threats:
                    tid = str(t.get("DetectionID", ""))
                    if tid in last_seen:
                        continue
                    last_seen.add(tid)
                    name     = t.get("ThreatName", "unknown")
                    path     = t.get("Resources", "unknown")
                    severity = Severity.HIGH
                    self.emit(
                        f"Defender [PS fallback] detected {name!r} at {path!r}",
                        severity,
                        threat_name=name,
                        path=str(path),
                        detection_id=tid,
                        fallback=True,
                        mitre_tags=["T1204"],
                    )
            except Exception:
                pass
        return True

    def _poll_ps(self) -> list[dict]:
        out = check_output_hidden(
            ["powershell", "-NoProfile", "-Command",
             "Get-MpThreatDetection | ConvertTo-Json -Depth 3"],
            timeout=30,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        data = json.loads(out or "[]")
        if isinstance(data, dict):
            data = [data]
        return data

    def self_test(self) -> tuple[bool, str]:
        if self.health >= 80:
            return True, f"health={self.health}%"
        return False, self.health_note


def register() -> AVTelemetryBridgeModule:
    return AVTelemetryBridgeModule()
