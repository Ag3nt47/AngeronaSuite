"""compliance_mapper.py — Automated Compliance Mapper (Code: CMAP).

Purpose
    Turns Angerona's live detection telemetry into formal compliance evidence.
    Every bus event that carries a MITRE ATT&CK technique id is cross-referenced
    against NIST SP 800-53 controls and DoD STIG baselines, and periodically
    compiled into a JSON posture artifact an auditor (or an eMASS/RMF workflow)
    can consume — proving which controls the running defenses actually enforce.

How it works
    CMAP subscribes to the EventBus (via ``recent()`` polling, the same
    consumer pattern AMSI Bridge uses), extracts a technique id from each event's
    ``details['mitre']`` / ``details['technique']`` (or the message text), maps
    it, and writes ``diagnostics/compliance_report.json``. It is read-only and
    performs no network I/O.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity


def _repo_root() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# MITRE ATT&CK technique → (NIST SP 800-53, DoD STIG) mapping. Base-technique
# keys (T1059) match their sub-techniques (T1059.001) via prefix fallback.
COMPLIANCE_MATRIX: dict[str, dict[str, str]] = {
    "T1059": {"NIST": "CM-5 (Access Restrictions for Change) / SI-4 (System Monitoring)",
              "STIG": "V-220717 (PowerShell Constrained Language Mode)"},
    "T1068": {"NIST": "AC-6 (Least Privilege) / SI-2 (Flaw Remediation)",
              "STIG": "V-220726 (Restrict local privilege escalation)"},
    "T1082": {"NIST": "AC-6 (Least Privilege)",
              "STIG": "V-220800 (Limit local admin reconnaissance)"},
    "T1190": {"NIST": "SI-2 (Flaw Remediation) / RA-5 (Vulnerability Monitoring)",
              "STIG": "V-222387 (Patch public-facing applications)"},
    "T1203": {"NIST": "SI-3 (Malicious Code Protection)",
              "STIG": "V-220708 (Client execution hardening)"},
    "T1210": {"NIST": "SC-7 (Boundary Protection) / SI-2 (Flaw Remediation)",
              "STIG": "V-220730 (Restrict remote service exploitation)"},
    "T1547": {"NIST": "CM-7 (Least Functionality)",
              "STIG": "V-220744 (Restrict autostart/persistence)"},
    "T1055": {"NIST": "SI-4 (System Monitoring) / SI-3 (Malicious Code Protection)",
              "STIG": "V-220706 (Process injection monitoring)"},
    "T1486": {"NIST": "CP-9 (System Backup) / SI-3 (Malicious Code Protection)",
              "STIG": "V-220709 (Ransomware/impact controls)"},
    "T1565": {"NIST": "SI-7 (Software, Firmware, and Information Integrity)",
              "STIG": "V-220712 (Data integrity verification)"},
}
_UNMAPPED = {"NIST": "Unmapped (review)", "STIG": "Unmapped (review)"}


def map_technique(mitre_id: str) -> dict[str, str]:
    """Map a MITRE id (technique or sub-technique) to NIST/STIG controls."""
    if not mitre_id:
        return dict(_UNMAPPED)
    m = _TECH_RE.search(mitre_id)
    tid = m.group(0) if m else mitre_id
    if tid in COMPLIANCE_MATRIX:
        return COMPLIANCE_MATRIX[tid]
    base = tid.split(".", 1)[0]
    return COMPLIANCE_MATRIX.get(base, dict(_UNMAPPED))


def generate_artifact(incident_log: list[dict], output_path: str | Path) -> dict:
    """Compile a formal report mapping incidents to compliance controls."""
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "frameworks": ["NIST SP 800-53 Rev5", "DoD STIG"],
        "mapped_incidents": [],
    }
    for incident in incident_log:
        mitre_id = incident.get("mitre_id") or incident.get("mitre") or ""
        mapping = map_technique(mitre_id)
        report["mapped_incidents"].append({
            "incident_time": incident.get("time"),
            "mitre_technique": _TECH_RE.search(mitre_id).group(0) if _TECH_RE.search(mitre_id or "") else mitre_id,
            "nist_control_enforced": mapping["NIST"],
            "stig_baseline_enforced": mapping["STIG"],
            "action_taken": incident.get("action"),
            "source_module": incident.get("module"),
            "severity": incident.get("severity"),
        })
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=4), "utf-8")
    return report


class ComplianceMapperModule(BaseModule):
    CODE = "CMAP"
    NAME = "Compliance Mapper"
    name = "Compliance Mapper"
    description = ("Maps live MITRE ATT&CK detections to NIST 800-53 + DoD STIG "
                   "controls and writes an auditable compliance posture artifact.")
    category = "Compliance"
    version = "1.0.0"

    _INTERVAL = 5 * 60.0      # regenerate artifact every 5 min

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._out = _repo_root() / "diagnostics" / "compliance_report.json"
        self._last_ts = 0.0
        self._incidents: list[dict] = []
        self._seen_techniques: set[str] = set()

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── bus consumption ──────────────────────────────────────────────────────
    @staticmethod
    def _extract_technique(ev) -> str:
        details = getattr(ev, "details", {}) or {}
        for key in ("mitre", "technique", "mitre_id", "mitre_tag"):
            val = details.get(key)
            if val and _TECH_RE.search(str(val)):
                return _TECH_RE.search(str(val)).group(0)
        # Fall back to scanning the message text.
        m = _TECH_RE.search(getattr(ev, "message", "") or "")
        return m.group(0) if m else ""

    def _drain_bus(self) -> None:
        if self._bus is None:
            return
        for ev in self._bus.recent(100):
            if ev.ts <= self._last_ts:
                continue
            self._last_ts = max(self._last_ts, ev.ts)
            tid = self._extract_technique(ev)
            if not tid:
                continue
            sev = getattr(ev, "severity", Severity.INFO)
            self._incidents.append({
                "time": getattr(ev, "time_str", None) or time.strftime("%H:%M:%S"),
                "mitre_id": tid,
                "module": getattr(ev, "module", ""),
                "action": (getattr(ev, "message", "") or "")[:200],
                "severity": int(sev) if isinstance(sev, int) else str(sev),
            })
            self._seen_techniques.add(tid)
        # Cap retained incidents so the artifact/memory stays bounded.
        if len(self._incidents) > 2000:
            self._incidents = self._incidents[-2000:]

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        self.emit("CMAP online — mapping detections to NIST 800-53 / DoD STIG.", Severity.INFO)
        while not self.stopping:
            try:
                self._drain_bus()
                report = generate_artifact(self._incidents, self._out)
                n = len(report["mapped_incidents"])
                mapped = sum(1 for i in report["mapped_incidents"]
                             if not i["nist_control_enforced"].startswith("Unmapped"))
                self.set_health(100, f"{n} incidents mapped ({len(self._seen_techniques)} techniques, "
                                     f"{n - mapped} unmapped)")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(60, f"artifact generation error: {exc}")
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        """Offline: verify technique mapping + sub-technique fallback."""
        sample = [
            {"mitre_id": "T1059.001", "time": "00:00:00", "action": "PowerShell encoded cmd"},
            {"mitre_id": "T1082", "time": "00:00:01", "action": "sysinfo discovery"},
            {"mitre_id": "T9999", "time": "00:00:02", "action": "unknown"},
        ]
        import tempfile, os as _os
        tmp = Path(tempfile.gettempdir()) / "cmap_selftest.json"
        try:
            report = generate_artifact(sample, tmp)
            inc = report["mapped_incidents"]
            ok = (inc[0]["nist_control_enforced"].startswith("CM-5")          # sub-tech → base map
                  and inc[1]["nist_control_enforced"].startswith("AC-6")
                  and inc[2]["nist_control_enforced"].startswith("Unmapped"))
            try:
                _os.unlink(tmp)
            except Exception:
                pass
            return ok, ("MITRE→NIST/STIG mapping + sub-technique fallback verified"
                        if ok else f"mapping failed: {inc}")
        except Exception as exc:
            return False, f"self-test error: {exc}"


def register() -> ComplianceMapperModule:
    return ComplianceMapperModule()
