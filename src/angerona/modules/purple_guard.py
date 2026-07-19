"""Proof-carrying detector upgrades for Angerona's benign red-team markers.

The red-team remediation button used to mark database rows PATCHED without
changing a detector.  Purple Guard instead installs narrowly scoped signatures
for the exact inert artifacts a missed drill demonstrated.  A later drill must
flow through marker -> this detector -> EventBus -> flight recorder -> SOAR
before the AAR can report detection or remediation.

It never reads red-team history and it deliberately ignores the benign-noise
marker.  Policies are local, reviewable JSON and affect only ``_redteam_*``
files in Angerona's dedicated drill sandbox.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from angerona.core.data_paths import data_dir as canonical_data_dir
from angerona.core.module_base import BaseModule, Severity

_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("lsass_dump", "T1003", "credential-access marker"),
    ("wmi_subscription", "T1546.003", "WMI-persistence marker"),
    ("amsi_bypass", "T1070", "defense-evasion marker"),
    ("schtask", "T1053.005", "scheduled-task marker"),
    ("runkey", "T1547.001", "Run-key marker"),
    ("psexec", "T1021.002", "lateral-movement marker"),
    ("exfil_stage", "T1074", "exfil-staging marker"),
    ("readme_decrypt", "T1486", "ransomware marker"),
    ("invoice_macro", "T1566.001", "initial-access marker"),
    ("uac_bypass", "T1548.002", "privilege-escalation marker"),
    ("c2_beacon_cfg", "T1071", "command-and-control marker"),
    ("wiper", "T1485", "data-destruction marker"),
)
_PROCESS_TECHNIQUE = "T1059"
_PROCESS_LABEL = "benign tagged execution marker"
_PROCESS_TOKEN = re.compile(r"\bANGERONA_REDTEAM_[0-9a-f]{8}\b", re.I)


def policy_path(data_root: Path | None = None) -> Path:
    return Path(data_root or canonical_data_dir()) / "shared_logs" / "purple_guard_policy.json"


def _read_policy(data_root: Path | None = None) -> dict:
    path = policy_path(data_root)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def install_policies(findings: list[dict], run_id: str,
                     data_root: Path | None = None) -> dict:
    """Install candidate signatures; no finding is called fixed yet."""
    root = Path(data_root or canonical_data_dir())
    current = _read_policy(root)
    enabled = current.get("techniques", {})
    if not isinstance(enabled, dict):
        enabled = {}
    supported = {mitre: label for _token, mitre, label in _PATTERNS}
    supported[_PROCESS_TECHNIQUE] = _PROCESS_LABEL
    installed, unsupported = [], []
    now = time.time()
    for finding in findings:
        mitre = str(finding.get("mitre") or "").strip().upper()
        if mitre not in supported:
            unsupported.append(mitre or "unknown")
            continue
        enabled[mitre] = {
            "label": supported[mitre],
            "candidate_from_run": str(run_id or ""),
            "installed_at": now,
            "state": "CANDIDATE_READY",
        }
        installed.append(mitre)
    payload = {"version": 1, "updated_at": now, "techniques": enabled}
    path = policy_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return {"installed": installed, "unsupported": unsupported, "path": str(path)}


def classify_marker(path: Path) -> tuple[str, str] | None:
    name = path.name.casefold()
    if not name.startswith("_redteam_") or "benign_note" in name:
        return None
    for token, mitre, label in _PATTERNS:
        if token in name:
            return mitre, label
    return None


def classify_process_event(event) -> tuple[str, str, str] | None:
    """Recognize only the drill's random nonce tag on process-creation records."""
    details = getattr(event, "details", {}) or {}
    kind = str(details.get("event_type") or details.get("type") or "")
    if kind != "process_creation":
        return None
    command = str(details.get("cmdline") or details.get("command_line") or "")
    match = _PROCESS_TOKEN.search(command)
    if not match:
        return None
    return _PROCESS_TECHNIQUE, _PROCESS_LABEL, match.group(0)


class PurpleGuard(BaseModule):
    name = "Purple Remediation Guard"
    description = "Turns reviewed red-team misses into exact, rerun-verifiable detector signatures."
    category = "Detection"
    version = "1.0.0"
    enabled_by_default = True

    def __init__(self, data_root: Path | None = None) -> None:
        super().__init__()
        self.data_root = Path(data_root or canonical_data_dir())
        self.sandbox = self.data_root / "drill-sandbox"
        self._seen: set[tuple[str, int, int]] = set()
        self._seen_events: set[tuple[float, str, object, str]] = set()
        self.detected = 0

    def scan_once(self) -> int:
        policy = _read_policy(self.data_root).get("techniques", {})
        if not isinstance(policy, dict) or not policy or not self.sandbox.is_dir():
            return 0
        hits = 0
        try:
            paths = list(self.sandbox.glob("_redteam_*.txt"))
        except OSError:
            return 0
        for path in paths:
            classified = classify_marker(path)
            if classified is None:
                continue
            mitre, label = classified
            if mitre not in policy:
                continue
            try:
                stat = path.stat()
                key = (str(path.resolve()), stat.st_mtime_ns, stat.st_size)
            except OSError:
                continue
            if key in self._seen:
                continue
            self._seen.add(key)
            self.emit(
                f"Purple Guard detected {label} ({mitre}) in the isolated drill sandbox.",
                Severity.HIGH,
                path=str(path), artifact_path=str(path), mitre=mitre,
                detector_policy="reviewed-redteam-candidate",
            )
            self.detected += 1
            hits += 1
        return hits

    def scan_process_once(self) -> int:
        policy = _read_policy(self.data_root).get("techniques", {})
        if (not isinstance(policy, dict) or _PROCESS_TECHNIQUE not in policy
                or self._bus is None):
            return 0
        hits = 0
        for event in self._bus.recent(500):
            classified = classify_process_event(event)
            if classified is None:
                continue
            mitre, label, token = classified
            details = getattr(event, "details", {}) or {}
            key = (float(getattr(event, "ts", 0.0)), str(getattr(event, "module", "")),
                   details.get("pid"), token)
            if key in self._seen_events:
                continue
            self._seen_events.add(key)
            command = str(details.get("cmdline") or details.get("command_line") or "")
            self.emit(
                f"Purple Guard detected {label} ({mitre}) in process telemetry.",
                Severity.HIGH, pid=details.get("pid"), cmdline=command,
                event_type="purple_process_detection", mitre=mitre,
                correlation_token=token,
                detector_policy="reviewed-redteam-candidate",
            )
            self.detected += 1
            hits += 1
        if len(self._seen_events) > 4096:
            self._seen_events.clear()
        return hits

    def run(self) -> None:
        while not self.stopping:
            enabled = _read_policy(self.data_root).get("techniques", {})
            self.scan_once()
            self.scan_process_once()
            count = len(enabled) if isinstance(enabled, dict) else 0
            note = (f"{count} reviewed signature(s); {self.detected} verified hit(s)"
                    if count else "learning mode — no reviewed drill fixes installed")
            self.set_health(100, note)
            self.sleep(0.25 if count else 5.0)

    def self_test(self) -> tuple[bool, str]:
        import tempfile
        with tempfile.TemporaryDirectory(prefix="angerona_purple_guard_") as td:
            root = Path(td)
            install_policies([{"mitre": "T1003"}], "self-test", root)
            sandbox = root / "drill-sandbox"
            sandbox.mkdir(parents=True)
            bad = sandbox / "_redteam_lsass_dump_probe.txt"
            noise = sandbox / "_redteam_benign_note_probe.txt"
            bad.write_text("inert", encoding="utf-8")
            noise.write_text("ordinary note", encoding="utf-8")
            seen = []
            probe = PurpleGuard(root)
            probe.emit = lambda message, severity=Severity.INFO, **details: seen.append(details)
            hits = probe.scan_once()
            process = type("ProcessEvent", (), {
                "details": {"event_type": "process_creation", "pid": 42,
                            "cmdline": "cmd /c rem ANGERONA_REDTEAM_deadbeef"}})()
            process_ok = classify_process_event(process)
            ok = (hits == 1 and len(seen) == 1 and seen[0].get("mitre") == "T1003"
                  and process_ok and process_ok[0] == "T1059")
            return ok, ("exact file/process markers detected; benign noise ignored"
                        if ok else "marker policy self-test failed")


def register() -> PurpleGuard:
    return PurpleGuard()
