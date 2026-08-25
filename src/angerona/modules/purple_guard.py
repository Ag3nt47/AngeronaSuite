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
import threading
import time
from pathlib import Path
from typing import TypeAlias

from angerona.core.atomic_io import replace_with_retry
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
_PRACTICE_FILE_TOKEN = re.compile(
    r"_practice_(?P<id>[0-9a-f]{8,64})\.txt$",
    re.I,
)
_SAFE_LINEAGE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_POLICY_CACHE_UNSET = object()
_PathInput: TypeAlias = str | os.PathLike[str]
_RUNTIME_TARGETS: set[Path] = set()
_RUNTIME_TARGETS_LOCK = threading.RLock()


def _normalize_runtime_target(target: _PathInput, *, require_directory: bool) -> Path:
    """Return a stable local directory path suitable for the drill scanner."""
    try:
        raw = os.fspath(target)
    except TypeError as exc:
        raise ValueError("runtime drill target must be a filesystem path") from exc
    if not raw or not raw.strip() or "\x00" in raw:
        raise ValueError("runtime drill target must be a non-empty local path")
    if len(raw) > 1024:
        raise ValueError("runtime drill target path is too long")
    windows_form = raw.replace("/", "\\")
    if windows_form.startswith(("\\\\", "\\\\?\\", "\\\\.\\")):
        raise ValueError("network and device paths are not runtime drill targets")
    try:
        path = Path(os.path.expandvars(os.path.expanduser(raw))).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError("runtime drill target path is invalid") from exc
    if path == Path(path.anchor):
        raise ValueError("a filesystem root is not a runtime drill target")
    if path.exists() and not path.is_dir():
        raise ValueError("runtime drill target must be a directory path")
    if require_directory and not path.is_dir():
        raise ValueError("runtime drill target must be an existing directory")
    return path


def register_runtime_target(target: _PathInput) -> Path:
    """Pre-register one local drill directory for this process lifetime.

    Registration never widens marker matching: Purple Guard still inspects only
    direct children whose names match ``_redteam_*.txt``.  The bounded drill
    may create the directory immediately after this call, so absence is valid;
    roots, UNC/device paths, and non-directory values remain non-scannable.
    """
    path = _normalize_runtime_target(target, require_directory=False)
    with _RUNTIME_TARGETS_LOCK:
        _RUNTIME_TARGETS.add(path)
    return path


def unregister_runtime_target(target: _PathInput) -> bool:
    """Remove a runtime target, including one whose directory was deleted."""
    path = _normalize_runtime_target(target, require_directory=False)
    with _RUNTIME_TARGETS_LOCK:
        if path not in _RUNTIME_TARGETS:
            return False
        _RUNTIME_TARGETS.remove(path)
        return True


def _runtime_targets_snapshot() -> tuple[Path, ...]:
    with _RUNTIME_TARGETS_LOCK:
        return tuple(
            sorted(_RUNTIME_TARGETS, key=lambda path: os.path.normcase(str(path)))
        )


def _safe_lineage_details(details: dict) -> dict[str, str]:
    lineage: dict[str, str] = {}
    for key in ("practice_verification_id", "run_id", "step_id"):
        value = str(details.get(key) or "").strip()
        if value and _SAFE_LINEAGE_ID.fullmatch(value):
            lineage[key] = value
    return lineage


def _practice_id_from_marker(path: Path) -> str:
    match = _PRACTICE_FILE_TOKEN.search(path.name)
    return match.group("id").lower() if match else ""


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
    seen: set[str] = set()
    now = time.time()
    for finding in findings:
        mitre = str(finding.get("mitre") or "").strip().upper()
        if mitre in seen:
            continue
        seen.add(mitre)
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
        replace_with_retry(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return {"installed": installed, "unsupported": unsupported, "path": str(path)}


def ensure_redteam_validation_pack(data_root: Path | None = None) -> dict:
    """Activate every fixed, simulation-only Purple Guard signature.

    The Red Team console's Auto-contain option promises an end-to-end validation
    run, not a first-run learning exercise.  These signatures match only inert
    ``_redteam_*`` artifacts (or the nonce-tagged idle process) in explicitly
    registered drill targets.  Existing candidate metadata is preserved so an
    automatic validation run cannot overwrite prior signed remediation lineage.
    """
    root = Path(data_root or canonical_data_dir())
    current = _read_policy(root).get("techniques", {})
    enabled = current if isinstance(current, dict) else {}
    techniques = tuple(
        dict.fromkeys([mitre for _token, mitre, _label in _PATTERNS]
                      + [_PROCESS_TECHNIQUE])
    )
    missing = [mitre for mitre in techniques if mitre not in enabled]
    result = (
        install_policies(
            [{"mitre": mitre} for mitre in missing],
            "builtin-redteam-validation-v1",
            root,
        )
        if missing
        else {"installed": [], "unsupported": [], "path": str(policy_path(root))}
    )
    return {
        **result,
        "active": list(techniques),
        "already_active": [mitre for mitre in techniques if mitre in enabled],
        "simulation_only": True,
    }


def remove_policies(
    techniques: list[str],
    data_root: Path | None = None,
) -> dict:
    """Rollback exact Purple Guard techniques; unrelated policy is preserved."""
    root = Path(data_root or canonical_data_dir())
    current = _read_policy(root)
    enabled = current.get("techniques", {})
    if not isinstance(enabled, dict):
        enabled = {}
    requested = {str(value or "").strip().upper() for value in techniques if value}
    removed = []
    for technique in sorted(requested):
        if technique in enabled:
            enabled.pop(technique)
            removed.append(technique)
    payload = {
        "version": 1,
        "updated_at": time.time(),
        "techniques": enabled,
    }
    path = policy_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        replace_with_retry(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return {
        "removed": removed,
        "not_present": sorted(requested.difference(removed)),
        "path": str(path),
    }


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
        self._last_process_scan: tuple[int, tuple[str, ...]] | None = None
        self._policy_cache_key: object = _POLICY_CACHE_UNSET
        self._policy_cache: dict = {}
        self.detected = 0

    def _policy_snapshot(self) -> dict:
        """Return the policy, reparsing only after the file identity changes.

        An installed remediation policy is normally unchanged between drills,
        yet the active detector runs once per second.  A stat-based identity
        check avoids tens of thousands of identical JSON reads per day.  The
        key includes both change timestamps, size, and file identity so atomic
        replacement or an in-place rewrite invalidates the cache immediately.
        """
        path = policy_path(self.data_root)
        try:
            stat = path.stat()
            key: object = (
                int(getattr(stat, "st_dev", 0)),
                int(getattr(stat, "st_ino", 0)),
                int(stat.st_mtime_ns),
                int(stat.st_ctime_ns),
                int(stat.st_size),
            )
        except OSError:
            key = None
        if key == self._policy_cache_key:
            return self._policy_cache
        value = _read_policy(self.data_root).get("techniques", {})
        self._policy_cache = value if isinstance(value, dict) else {}
        self._policy_cache_key = key
        return self._policy_cache

    def scan_once(self, policy: dict | None = None) -> int:
        if policy is None:
            policy = _read_policy(self.data_root).get("techniques", {})
        if not isinstance(policy, dict) or not policy:
            return 0
        hits = 0
        targets = (self.sandbox.resolve(strict=False), *_runtime_targets_snapshot())
        visited: set[Path] = set()
        for target in targets:
            if target in visited or not target.is_dir():
                continue
            visited.add(target)
            try:
                # Direct children only. Broad file scanning or recursive walking
                # would turn this exact drill detector into a general-purpose
                # content scanner, which is intentionally outside its contract.
                paths = list(target.glob("_redteam_*.txt"))
            except OSError:
                continue
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
                practice_id = _practice_id_from_marker(path)
                practice_details = (
                    {"practice_verification_id": practice_id} if practice_id else {}
                )
                self.emit(
                    f"Purple Guard detected {label} ({mitre}) in a registered drill target.",
                    Severity.HIGH,
                    path=str(path), artifact_path=str(path), mitre=mitre,
                    drill_target=str(target),
                    detector_policy="reviewed-redteam-candidate",
                    response_authorized=True,
                    response_contract={
                        "version": 1,
                        "actions": ["quarantine_file"],
                        "targets": {"path": str(path)},
                    },
                    **practice_details,
                )
                self.detected += 1
                hits += 1
        return hits

    def scan_process_once(self, policy: dict | None = None) -> int:
        if policy is None:
            policy = _read_policy(self.data_root).get("techniques", {})
        if (not isinstance(policy, dict) or _PROCESS_TECHNIQUE not in policy
                or self._bus is None):
            return 0
        # The EventBus token changes for every publication. When neither it nor
        # the enabled technique set changed, rescanning the same newest 500
        # immutable Event objects cannot produce a new detection. Test doubles
        # without revision() retain the historical full scan.
        revision_fn = getattr(self._bus, "revision", None)
        scan_key = None
        if callable(revision_fn):
            try:
                scan_key = (
                    int(revision_fn()),
                    tuple(sorted(str(key) for key in policy)),
                )
            except (TypeError, ValueError):
                scan_key = None
        if scan_key is not None and scan_key == self._last_process_scan:
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
            pid = details.get("pid")
            raw_created = (
                details.get("process_create_time")
                or details.get("pid_create_time")
                or details.get("create_time")
                or details.get("process_start_time")
            )
            response = {}
            try:
                created = float(raw_created)
            except (TypeError, ValueError, OverflowError):
                created = 0.0
            if isinstance(pid, int) and pid > 0 and created > 0:
                response = {
                    "response_authorized": True,
                    "response_contract": {
                        "version": 1,
                        "actions": [
                            "isolate_program",
                            "suspend_process",
                            "terminate_process",
                        ],
                        "targets": {
                            "pid": pid,
                            "process_create_time": created,
                        },
                    },
                }
            self.emit(
                f"Purple Guard detected {label} ({mitre}) in process telemetry.",
                Severity.HIGH, pid=pid, cmdline=command,
                process_create_time=created or raw_created,
                event_type="purple_process_detection", mitre=mitre,
                correlation_token=token,
                detector_policy="reviewed-redteam-candidate",
                **response,
                **_safe_lineage_details(details),
            )
            self.detected += 1
            hits += 1
        if len(self._seen_events) > 4096:
            self._seen_events.clear()
        if scan_key is not None:
            self._last_process_scan = scan_key
        return hits

    def work_cycle(self) -> tuple[int, int, int]:
        """Run one detector cycle using one coherent policy snapshot.

        The old loop parsed ``purple_guard_policy.json`` three times per
        second (health, file markers, and process markers). A single parse is
        faster and makes every check in the cycle observe one policy version.
        """
        policy = self._policy_snapshot()
        file_hits = self.scan_once(policy)
        process_hits = self.scan_process_once(policy)
        return file_hits, process_hits, len(policy)

    def run(self) -> None:
        while not self.stopping:
            _file_hits, _process_hits, count = self.work_cycle()
            note = (f"{count} reviewed signature(s); {self.detected} verified hit(s)"
                    if count else "learning mode — no reviewed drill fixes installed")
            self.set_health(100, note)
            # File/process evidence persists long enough for a one-second cycle;
            # a 250 ms full sandbox + 500-event rescan wasted CPU without
            # improving detection coverage.
            self.sleep(1.0 if count else 5.0)

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
