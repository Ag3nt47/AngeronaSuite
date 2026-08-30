"""compliance_mapper.py — Automated Compliance Mapper (Code: CMAP).

Purpose
    Turns Angerona's live detection telemetry into control-relevance evidence.
    Every bus event that carries a MITRE ATT&CK technique id is cross-referenced
    against NIST SP 800-53 controls and DoD STIG baselines, and periodically
    compiled into a JSON posture artifact an auditor (or an eMASS/RMF workflow)
    can consume. A mapping never claims that a control is implemented/enforced;
    assessment and implementation evidence must be supplied separately.

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
import hashlib
import hmac
import os
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity
from angerona.core.atomic_io import replace_with_retry


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
_STATE_SCHEMA = 2
_STATE_HMAC = "hmac_sha256"
_STATE_DOMAIN = b"Angerona-Compliance-Mapper-v2"
_MAX_STATE_BYTES = 4 * 1024 * 1024
_MAX_DURABLE_BATCH = 5_000


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        replace_with_retry(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


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


def generate_artifact(
    incident_log: list[dict] | deque[dict],
    output_path: str | Path,
    *,
    coverage: dict | None = None,
    artifact_key: bytes | None = None,
) -> dict:
    """Compile a formal report mapping incidents to compliance controls."""
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "frameworks": ["NIST SP 800-53 Rev5", "DoD STIG"],
        "claim_semantics": (
            "Detection-to-control relevance mapping only; this artifact is not "
            "evidence that a control is implemented, enforced, or effective."
        ),
        "coverage": dict(coverage or {}),
        "mapped_incidents": [],
        "artifact_hmac_sha256": None,
    }
    for incident in incident_log:
        mitre_id = incident.get("mitre_id") or incident.get("mitre") or ""
        mapping = map_technique(mitre_id)
        report["mapped_incidents"].append({
            "incident_time": incident.get("time"),
            "mitre_technique": _TECH_RE.search(mitre_id).group(0) if _TECH_RE.search(mitre_id or "") else mitre_id,
            "nist_control_mapped": mapping["NIST"],
            "stig_baseline_mapped": mapping["STIG"],
            "claim_type": "control_relevance",
            "implementation_status": "not_assessed",
            "assessment_result": "not_assessed",
            "action_taken": incident.get("action"),
            "source_module": incident.get("module"),
            "severity": incident.get("severity"),
            "recorder_id": incident.get("recorder_id"),
        })
    if artifact_key is not None:
        unsigned = dict(report)
        unsigned["artifact_hmac_sha256"] = None
        report["artifact_hmac_sha256"] = hmac.new(
            artifact_key,
            json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    out = Path(output_path)
    _atomic_write(
        out,
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return report


class ComplianceMapperModule(BaseModule):
    CODE = "CMAP"
    NAME = "Compliance Mapper"
    name = "Compliance Mapper"
    description = ("Maps live MITRE ATT&CK detections to NIST 800-53 + DoD STIG "
                   "control relevance and writes an authenticated, coverage-aware artifact.")
    category = "Compliance"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 4.0
    version = "1.12.1"

    _INTERVAL = 5 * 60.0      # regenerate artifact every 5 min

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._out = _repo_root() / "diagnostics" / "compliance_report.json"
        # Keep exactly the newest 2,000 records with O(1) eviction. The former
        # list slice copied all retained references after every saturated drain.
        self._incidents: deque[dict] = deque(maxlen=2000)
        self._seen_techniques: set[str] = set()
        self._recorder = None
        self._cursor_id = 0
        self._state_status = "not-loaded"
        self._retention_drops = 0
        self._bus_overflows = 0
        self._state_path_override: Path | None = None
        self._state_key_override: bytes | None = None

    def bind_recorder(self, recorder) -> None:
        self._recorder = recorder

    @property
    def _state_path(self) -> Path:
        return self._state_path_override or self._out.with_name(
            "compliance_report.state.json"
        )

    def _state_key(self) -> bytes | None:
        key = self._state_key_override
        if key is None:
            try:
                from angerona.core.data_paths import data_dir

                key = bytes.fromhex(
                    (data_dir() / "bus.key").read_text(encoding="ascii").strip()
                )
            except (OSError, ValueError):
                return None
        if len(key) != 32:
            return None
        return hmac.new(key, _STATE_DOMAIN, hashlib.sha256).digest()

    @staticmethod
    def _state_body(value: dict) -> bytes:
        unsigned = {key: item for key, item in value.items() if key != _STATE_HMAC}
        return json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def _load_state(self) -> bool:
        key = self._state_key()
        if key is None:
            self._state_status = "key-unavailable"
            return False
        try:
            raw = self._state_path.read_bytes()
        except FileNotFoundError:
            self._state_status = "new"
            return True
        except OSError:
            self._state_status = "unreadable"
            return False
        try:
            if len(raw) > _MAX_STATE_BYTES:
                raise ValueError("state exceeds byte limit")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {
                "schema",
                "cursor_id",
                "retention_drops",
                "bus_overflows",
                "incidents",
                _STATE_HMAC,
            }:
                raise ValueError("state schema mismatch")
            incidents = value["incidents"]
            if (
                value["schema"] != _STATE_SCHEMA
                or not isinstance(incidents, list)
                or len(incidents) > 2000
            ):
                raise ValueError("state bounds invalid")
            cursor_id = int(value["cursor_id"])
            retention_drops = int(value["retention_drops"])
            bus_overflows = int(value["bus_overflows"])
            if min(cursor_id, retention_drops, bus_overflows) < 0:
                raise ValueError("negative state counter")
            clean: list[dict] = []
            for incident in incidents:
                if not isinstance(incident, dict) or set(incident) != {
                    "time",
                    "mitre_id",
                    "module",
                    "action",
                    "severity",
                    "recorder_id",
                }:
                    raise ValueError("incident schema invalid")
                if len(json.dumps(incident, default=str)) > 4096:
                    raise ValueError("incident exceeds bound")
                clean.append(dict(incident))
            supplied = str(value[_STATE_HMAC])
            expected = hmac.new(
                key, self._state_body(value), hashlib.sha256
            ).hexdigest()
            if len(supplied) != 64 or not hmac.compare_digest(supplied, expected):
                raise ValueError("state authentication failed")
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            self._state_status = "invalid"
            return False
        self._cursor_id = cursor_id
        self._retention_drops = retention_drops
        self._bus_overflows = bus_overflows
        self._incidents = deque(clean, maxlen=2000)
        self._seen_techniques = {
            str(item.get("mitre_id")) for item in clean if item.get("mitre_id")
        }
        self._state_status = "ok"
        return True

    def _save_state(self) -> None:
        if self._state_status not in {"new", "ok"}:
            raise RuntimeError(
                f"refusing to overwrite {self._state_status} compliance state"
            )
        key = self._state_key()
        if key is None:
            self._state_status = "key-unavailable"
            raise RuntimeError("compliance state key unavailable")
        document = {
            "schema": _STATE_SCHEMA,
            "cursor_id": self._cursor_id,
            "retention_drops": self._retention_drops,
            "bus_overflows": self._bus_overflows,
            "incidents": list(self._incidents),
        }
        document[_STATE_HMAC] = hmac.new(
            key, self._state_body(document), hashlib.sha256
        ).hexdigest()
        payload = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(payload) > _MAX_STATE_BYTES:
            raise RuntimeError("compliance state exceeds byte limit")
        _atomic_write(self._state_path, payload)
        self._state_status = "ok"

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

    def _append_event(self, ev, *, recorder_id: int | None) -> None:
        tid = self._extract_technique(ev)
        if not tid:
            return
        sev = getattr(ev, "severity", Severity.INFO)
        if len(self._incidents) == self._incidents.maxlen:
            self._retention_drops += 1
        self._incidents.append({
            "time": getattr(ev, "time_str", None) or time.strftime("%H:%M:%S"),
            "mitre_id": tid,
            "module": str(getattr(ev, "module", ""))[:200],
            "action": (getattr(ev, "message", "") or "")[:200],
            "severity": int(sev) if isinstance(sev, int) else str(sev)[:40],
            "recorder_id": recorder_id,
        })
        self._seen_techniques.add(tid)

    def _drain_events(self) -> dict:
        recorder = self._recorder
        if recorder is not None and hasattr(recorder, "bounded_events_after_id"):
            rows, backlog, highwater = recorder.bounded_events_after_id(
                self._cursor_id,
                limit=_MAX_DURABLE_BATCH,
            )
            for record_id, event in rows:
                self._append_event(event, recorder_id=int(record_id))
                self._cursor_id = int(record_id)
            remaining = max(0, int(backlog) - len(rows))
            return {
                "source": "flight-recorder",
                "complete": remaining == 0 and self._cursor_id >= int(highwater),
                "cursor_id": self._cursor_id,
                "highwater_id": int(highwater),
                "backlog_before": int(backlog),
                "backlog_remaining": remaining,
                "bus_overflows": self._bus_overflows,
                "retention_drops": self._retention_drops,
            }
        if self._bus is None:
            return {
                "source": "unavailable",
                "complete": False,
                "reason": "no recorder or EventBus",
                "bus_overflows": self._bus_overflows,
                "retention_drops": self._retention_drops,
            }
        events, overflow = self.poll_bus_events()
        if overflow:
            self._bus_overflows += 1
        for event in events:
            self._append_event(event, recorder_id=None)
        return {
            "source": "eventbus-fallback",
            "complete": False,
            "events_returned": len(events),
            "bus_overflows": self._bus_overflows,
            "retention_drops": self._retention_drops,
        }
    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        self.emit("CMAP online — mapping detections to NIST 800-53 / DoD STIG.", Severity.INFO)
        if not self._load_state():
            self.set_health(30, f"compliance state {self._state_status}")
            return
        while not self.stopping:
            try:
                coverage = self._drain_events()
                self._save_state()
                report = generate_artifact(
                    self._incidents,
                    self._out,
                    coverage=coverage,
                    artifact_key=self._state_key(),
                )
                n = len(report["mapped_incidents"])
                mapped = sum(1 for i in report["mapped_incidents"]
                             if not i["nist_control_mapped"].startswith("Unmapped"))
                if not coverage.get("complete"):
                    health = 65
                elif self._retention_drops or self._bus_overflows:
                    health = 75
                else:
                    health = 100
                self.set_health(
                    health,
                    f"{n} relevance mappings ({len(self._seen_techniques)} techniques, "
                    f"{n - mapped} unmapped); source={coverage.get('source')}; "
                    f"backlog={coverage.get('backlog_remaining', 'unknown')}; "
                    f"retention_drops={self._retention_drops}",
                )
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
            ok = (inc[0]["nist_control_mapped"].startswith("CM-5")          # sub-tech → base map
                  and inc[1]["nist_control_mapped"].startswith("AC-6")
                  and inc[2]["nist_control_mapped"].startswith("Unmapped")
                  and all(i["implementation_status"] == "not_assessed" for i in inc)
                  and "not evidence" in report["claim_semantics"])
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
