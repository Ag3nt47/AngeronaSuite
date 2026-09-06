"""aar_report.py — Dynamic After-Action Report (AAR) generator.

Compares the Shark Attack Engine's own ground-truth log
(``shark_history.json``) against what Angerona's real detection modules —
and the Active Response SOAR Engine — actually recorded in the
flight-recorder ledger, which is this app's single existing source of
truth for everything that happened (core/storage.py). No separate
"remediation log" file is needed: SOAR's kill+rollback actions are just
ordinary ``self.emit()`` calls like every other module, so they're already
in the ledger under the "Active Response SOAR" module name.

This is intentionally a passive, read-only report generator. It never
re-triggers anything, and it never tells the shark engine or the defense
modules anything about each other — it only looks at what already happened,
after the fact.
"""
from __future__ import annotations

import copy
import base64
import hashlib
import json
import math
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from angerona.core.config import Config
from angerona.core.atomic_io import replace_with_retry
from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.shark.run_manifest import (
    DrillHistoryIntegrityError,
    MAX_ADMITTED_DRILL_SECONDS,
    load_verified_history,
)

WIDTH = 84


def _bounded_env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


# One report is kept as a text/JSON pair. These bounds prevent repeated drills
# from becoming a permanent archive while retaining useful comparison history.
_HISTORY_RUN_LIMIT = _bounded_env_int("ANGERONA_AAR_HISTORY_RUNS", 40)
_HISTORY_MAX_AGE_DAYS = _bounded_env_int("ANGERONA_AAR_HISTORY_DAYS", 30)

# How long after a drill step a detection may still be attributed to it. The
# real detectors that catch file-drop markers are interval pollers — FIM ~30s,
# YARA ~5min — so their catch lands well after the NEXT drill step has already
# begun. Bounding a step's catch window at the next step (as the raw ordering
# does) therefore drops every interval-scanner detection as "too late", scoring
# detection (and hence remediation) at ~0%. This budget extends the window past
# the next step so a late, artifact-specific catch can still attribute. Safe
# because _matches() requires the event to reference THIS step's marker and
# catches are de-duplicated, so a step can never steal another step's evidence.
_DETECTION_BUDGET_S = _bounded_env_int("ANGERONA_AAR_DETECTION_BUDGET_S", 360)
_HEAD_JOURNAL_MAX_BYTES = 64 * 1024 * 1024
_HEAD_JOURNAL_MAX_RECORDS = 8192
_REPORT_BUNDLE_MAX_BYTES = 16 * 1024 * 1024

# Not every Shark Attack stage is a "did a detector notice this" test. This
# mapping is what stops the report from mislabeling structurally-expected
# non-catches as failures right next to genuine detection gaps — a real run
# once showed "0/5 detected" and read as "everything is broken", when two of
# those five were never supposed to be caught in the first place:
#
#   detection   — a real detection gap/timing question. CAUGHT is good,
#                 MISSED means either a genuine gap or a module hasn't
#                 polled yet. (Initial Access, Persistence, Exfiltration.)
#   resilience  — a false-positive resilience check. NOT being caught IS
#                 the passing outcome; if something DOES fire on it, that's
#                 a false positive worth investigating. (Noise Injection.)
#   unmonitored — no detector exists for this by design (an explicit,
#                 already-made call — see angerona.academy's Discovery
#                 entry — not a bug to chase). Purely informational; never
#                 counted as a miss. (Discovery.)
STAGE_CATEGORY = {
    "Initial Access": "detection",
    "Discovery": "unmonitored",
    "Persistence (simulated)": "detection",
    "Noise Injection": "resilience",
    "Exfiltration": "detection",
}


@dataclass
class StepVerdict:
    stage: str
    technique: str
    description: str
    ts_start: float
    ok: bool
    category: str = "detection"
    # Evidence is intentionally split by epistemic strength. ``catch`` remains
    # the compatibility union of native analytic and simulation-validation
    # evidence; callers must use the explicit fields for honest coverage.
    observation: Optional[Event] = None
    observation_latency: Optional[float] = None
    native_catch: Optional[Event] = None
    native_latency: Optional[float] = None
    simulation_validation: Optional[Event] = None
    simulation_validation_latency: Optional[float] = None
    catch: Optional[Event] = None
    catch_latency: Optional[float] = None
    # Earliest detector evidence remains ``catch`` for latency. Purple Guard
    # proof is tracked independently so a faster FIM/telemetry event cannot
    # hide the reviewed detector candidate that arrived a moment later.
    verification_catch: Optional[Event] = None
    verification_latency: Optional[float] = None
    remediation: Optional[Event] = None
    remediation_latency: Optional[float] = None
    response_action_reported: bool = False
    response_action_applied: bool = False
    target_containment_verified: bool = False
    containment_latency: Optional[float] = None
    containment_reason: str = "No exact verified containment receipt was recorded."
    finding_resolved: bool = False
    technique_id: str = ""
    action_state: str = "OPEN"
    contract_id: Optional[str] = None
    contract_digest: Optional[str] = None
    action_applied: bool = False
    verification_expires_at: Optional[float] = None
    verification_mode: str = ""
    verification_run_id: str = ""
    verification_receipt_id: Optional[str] = None
    verification_error: str = ""


@dataclass(frozen=True)
class AARReportResult:
    """Immutable GUI handoff for one already-authenticated report pair."""

    text: str
    run_id: str
    report_kind: str
    report_basename: str
    report_sha256: str
    head_sha256: str
    sequence: int
    text_bytes: bytes
    report_bytes: bytes
    head_bytes: bytes
    journal_record_sha256: str
    journal_record_bytes: bytes
    report_directory: Path


def verified_aar_handoff_text(result: object) -> str:
    """Return display text only after verifying the exact signed byte bundle."""
    if type(result) is not AARReportResult:
        raise ValueError("AAR handoff has an unexpected type")
    if not all(
        isinstance(value, bytes) and 0 < len(value) <= _REPORT_BUNDLE_MAX_BYTES
        for value in (result.text_bytes, result.report_bytes, result.head_bytes)
    ):
        raise ValueError("AAR handoff byte bundle is missing or oversized")
    if (
        not isinstance(result.journal_record_bytes, bytes)
        or not 0 < len(result.journal_record_bytes) <= _REPORT_BUNDLE_MAX_BYTES * 4
        or not isinstance(result.report_directory, Path)
    ):
        raise ValueError("AAR handoff journal evidence is missing or oversized")
    try:
        text = result.text_bytes.decode("utf-8", errors="strict")
        report = json.loads(result.report_bytes.decode("utf-8", errors="strict"))
        head = json.loads(result.head_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise ValueError("AAR handoff byte bundle is malformed") from exc
    if text != result.text:
        raise ValueError("AAR handoff display text was mutated")
    report_sha256 = hashlib.sha256(result.report_bytes).hexdigest()
    text_sha256 = hashlib.sha256(result.text_bytes).hexdigest()
    head_sha256 = hashlib.sha256(result.head_bytes).hexdigest()
    try:
        from angerona.core import report_attest

        report_status = report_attest.verify(report)
        head_status = report_attest.verify(head)
    except Exception as exc:
        raise ValueError("AAR handoff authentication is unavailable") from exc
    if (
        not isinstance(report, dict)
        or not isinstance(head, dict)
        or head_status != "ok"
        or (result.report_kind == "red_team" and report_status != "ok")
        or result.report_sha256 != report_sha256
        or result.head_sha256 != head_sha256
        or report.get("report_text_sha256") != text_sha256
        or head.get("report_json_sha256") != report_sha256
        or head.get("report_text_sha256") != text_sha256
        or str(head.get("run_id") or "") != result.run_id
        or str(report.get("run_id") or "") != result.run_id
        or str(head.get("report_kind") or "") != result.report_kind
        or str(head.get("report_basename") or "") != result.report_basename
        or int(head.get("sequence", 0)) != result.sequence
        or re.fullmatch(r"[0-9a-f]{64}", result.journal_record_sha256) is None
    ):
        raise ValueError("AAR handoff signatures or digest bindings do not match")
    if (
        hashlib.sha256(result.journal_record_bytes).hexdigest()
        != result.journal_record_sha256
    ):
        raise ValueError("AAR handoff journal row digest does not match")

    root = result.report_directory.resolve(strict=False)
    if root != result.report_directory or root.is_symlink() or not root.is_dir():
        raise ValueError("AAR handoff report directory has an unsafe identity")
    lock_path = root / f"{result.report_basename}.writer.lock"
    journal_path = root / f"{result.report_basename}.heads.jsonl"
    with ExclusiveFileLease(lock_path):
        current_head, current_text, current_report, current_head_bytes = (
            _read_bound_report_bundle(root, result.report_basename)
        )
        journal = _load_head_journal(journal_path, result.report_basename)
        if not journal:
            raise ValueError("AAR handoff journal authority is missing")
        record, record_bytes, journal_text, journal_report, journal_head = journal[-1]
        if (
            record_bytes != result.journal_record_bytes
            or int(record.get("sequence", 0)) != result.sequence
            or str(record.get("head_sha256") or "") != result.head_sha256
            or current_text != result.text_bytes
            or current_report != result.report_bytes
            or current_head_bytes != result.head_bytes
            or journal_text != result.text_bytes
            or journal_report != result.report_bytes
            or journal_head != result.head_bytes
            or int(current_head.get("sequence", 0)) != result.sequence
        ):
            raise ValueError(
                "AAR handoff is stale, rolled back, or not the current journal head"
            )
    return text


_RESPONSE_MODULES = frozenset({
    "active response soar",
    "adversary combat",
    "soar automation",
})
_NON_DETECTOR_MODULES = frozenset({
    "console",
    "red team attack engine",
    "shark attack engine",
    "red team engine",
    "shark engine",
    "red team validation",
})
_NON_DETECTOR_EVIDENCE_TYPES = frozenset({
    "console",
    "ground_truth",
    "narration",
    "orchestration",
    "practice_announcement",
    "simulator_announcement",
})
_RAW_TELEMETRY_TYPES = frozenset({
    "process_creation",
    "raw_process_creation_telemetry",
    "raw_telemetry",
    "sensor_observation",
    "network_observation",
    "file_observation",
    "etw_observation",
})
_POSITIVE_VERDICTS = frozenset({
    "alert",
    "detected",
    "detection",
    "malicious",
    "match",
    "positive",
    "suspicious",
})


def _trusted_stored_event(
    ev: Event,
    *,
    required: bool,
    verifier: Callable[[Event], bool] | None = None,
) -> bool:
    """Require recorder-authenticated evidence in production AARs.

    ``FlightRecorder`` removes no valid signature and marks legacy/tampered
    rows with ``_ledger_integrity``. The optional compatibility mode is kept
    for pure unit tests that construct in-memory events directly.
    """
    if not required:
        return True
    if verifier is None or (ev.details or {}).get("_ledger_integrity"):
        return False
    try:
        return bool(verifier(ev))
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return False


def _is_response_source(ev: Event) -> bool:
    return str(ev.module or "").strip().casefold() in _RESPONSE_MODULES


def _is_non_detector_source(ev: Event) -> bool:
    module = str(ev.module or "").strip().casefold()
    details = ev.details or {}
    evidence_type = str(details.get("evidence_type") or "").strip().casefold()
    role = str(details.get("producer_role") or "").strip().casefold()
    return bool(
        module in _NON_DETECTOR_MODULES
        or module.endswith((" simulator", " orchestrator", " narrator"))
        or module.startswith("practice ")
        or _is_response_source(ev)
        or evidence_type in _NON_DETECTOR_EVIDENCE_TYPES
        or role in {"console", "ground-truth", "narrator", "orchestrator", "simulator"}
        or details.get("practice_announcement") is True
    )


def _step_attack_ids(step: dict) -> set[str]:
    values = step.get("attack_ids") or []
    ids = {str(value).upper() for value in values if value}
    ids.update(
        match.upper()
        for match in re.findall(
            r"\bT\d{4}(?:\.\d{3})?\b",
            f"{step.get('stage', '')} {step.get('technique', '')}",
            re.I,
        )
    )
    return ids


def _is_purple_validation(step: dict, ev: Event) -> bool:
    """Accept only an exact reviewed simulation-detector verdict."""
    if ev.module != "Purple Remediation Guard" or ev.severity < Severity.HIGH:
        return False
    details = ev.details or {}
    if details.get("detector_policy") != "reviewed-redteam-candidate":
        return False
    if (
        details.get("evidence_type") != "simulation_contract_validation"
        or str(details.get("detector_verdict") or "").casefold() != "positive"
    ):
        return False
    mitre = str(details.get("mitre") or "").strip().upper()
    return bool(mitre and mitre in _step_attack_ids(step))


def _is_native_analytic(ev: Event) -> bool:
    """Distinguish a detector alert from raw sensor observation."""
    if _is_non_detector_source(ev) or ev.module == "Purple Remediation Guard":
        return False
    if ev.severity < Severity.MEDIUM:
        return False
    details = ev.details or {}
    verdict = str(details.get("detector_verdict") or "").strip().casefold()
    evidence_type = str(details.get("evidence_type") or "").strip().casefold()
    event_type = str(details.get("event_type") or "").strip().casefold()
    if evidence_type in _RAW_TELEMETRY_TYPES or event_type in _RAW_TELEMETRY_TYPES:
        return False
    if verdict not in _POSITIVE_VERDICTS:
        return False
    if evidence_type != "native_analytic_detection":
        return False
    return True


def _custom_contract_category(step: dict) -> str | None:
    """Return a declared custom category only for a complete explicit contract."""
    contract = step.get("detector_contract")
    if not isinstance(contract, dict):
        return None
    producer = str(contract.get("producer_capability_id") or "").strip()
    evidence = str(contract.get("evidence_type") or "").strip()
    matcher = contract.get("matcher")
    if (
        contract.get("category") == "detection"
        and producer
        and evidence
        and isinstance(matcher, dict)
        and matcher
    ):
        return "detection"
    return None


def _category_for_step(step: dict, categories: dict) -> str:
    if str(step.get("stage") or "") == "Custom (simulated)":
        return _custom_contract_category(step) or "informational"
    return str(categories.get(step.get("stage"), "detection"))


def _load_history(path: Path) -> dict:
    return load_verified_history(path)


def _canonical_path(value: object) -> str:
    raw = os.path.expandvars(os.path.expanduser(str(value or "").strip().strip('"')))
    return os.path.normcase(os.path.normpath(raw)) if raw else ""


def _remote_endpoint(value: object) -> tuple[str, int | None]:
    """Normalize a sensor ``host:port`` value without fuzzy text matching."""
    raw = str(value or "").strip()
    if not raw:
        return "", None
    if raw.startswith("[") and "]:" in raw:
        host, port_text = raw[1:].split("]:", 1)
    elif raw.count(":") == 1:
        host, port_text = raw.rsplit(":", 1)
    else:
        host, port_text = raw.strip("[]"), ""
    try:
        port = int(port_text) if port_text else None
    except (TypeError, ValueError):
        port = None
    return host.casefold(), port


def _matches(step: dict, ev: Event) -> bool:
    """Match only deterministic drill evidence, never a basename or bare PID."""
    details = ev.details or {}
    step_id = str(step.get("step_id") or "")
    run_id = str(step.get("run_id") or "")
    event_step = str(details.get("step_id") or details.get("drill_step_id") or "")
    event_run = str(details.get("run_id") or details.get("drill_run_id") or "")
    if step_id and event_step and step_id == event_step and (not run_id or event_run == run_id):
        return True

    expected_paths = {_canonical_path(p) for p in step.get("artifact_paths", []) if p}
    observed_paths = {
        _canonical_path(details.get(key))
        for key in ("path", "artifact_path", "exe", "process_path", "image")
        if details.get(key)
    }
    if expected_paths.intersection(observed_paths):
        return True

    expected_ips = {str(value).strip().casefold()
                    for value in step.get("remote_ips", []) if value}
    expected_ports = {int(value) for value in step.get("remote_ports", [])
                      if isinstance(value, int)}
    observed_endpoints = [
        _remote_endpoint(details.get(key))
        for key in ("raddr", "remote", "remote_address", "destination")
        if details.get(key)
    ]
    observed_endpoints.extend(
        (_remote_endpoint(details.get(key))[0], details.get("remote_port"))
        for key in ("remote_ip", "destination_ip", "dest_ip", "dst_ip")
        if details.get(key)
    )
    expected_pid = step.get("pid")
    if (
        expected_ips
        and details.get("pid") == expected_pid
        and any(
            host in expected_ips and (not expected_ports or port in expected_ports)
            for host, port in observed_endpoints
        )
    ):
        return True

    expected_pids = {p for p in ([step.get("pid")] + list(step.get("pids") or []))
                     if isinstance(p, int)}
    tokens = [str(t) for t in step.get("correlation_tokens", []) if t]
    command = str(details.get("cmdline") or details.get("command_line") or "")
    if details.get("pid") in expected_pids and tokens and any(t in command for t in tokens):
        return True
    return False


def _response_trigger_identity(catch: Event, details: dict) -> tuple[object, object]:
    """Follow one authenticated delegation only through the exact detector HMAC."""
    module = details.get("trigger_module")
    timestamp = details.get("trigger_ts")
    if (module == "Active Response SOAR Request" and catch.hmac_sig
            and details.get("origin_event_digest") == catch.hmac_sig
            and details.get("origin_module") == catch.module):
        return details["origin_module"], details.get("origin_ts")
    return module, timestamp


def _matches_remediation(step: dict, catch: Event, ev: Event) -> bool:
    """Correlate an action without letting timestamp collisions imply identity."""
    details = ev.details or {}
    for expected_key, aliases in (
        ("run_id", ("run_id", "drill_run_id")),
        ("step_id", ("step_id", "drill_step_id")),
    ):
        expected = str(step.get(expected_key) or "")
        if expected and any(
            details.get(key) and str(details[key]) != expected for key in aliases
        ):
            return False
    trigger_module, trigger_time = _response_trigger_identity(catch, details)
    if trigger_module and trigger_module != catch.module:
        return False
    if "trigger_ts" in details:
        try:
            trigger_ts = float(trigger_time)
            if not math.isfinite(trigger_ts) or abs(trigger_ts - catch.ts) >= 0.000001:
                return False
        except (TypeError, ValueError, OverflowError):
            return False
    paths = {_canonical_path(path) for path in step.get("artifact_paths", []) if path}
    supplied = {_canonical_path(details[key]) for key in ("path", "artifact_path")
                if details.get(key)}
    if paths and supplied and not supplied.issubset(paths):
        return False
    pids = _step_pids(step)
    if pids and details.get("pid") is not None and details["pid"] not in pids:
        return False
    # A legacy full-path receipt can remain visible as an action report. It
    # cannot receive containment credit without the stronger proof below.
    if _matches(step, ev):
        return True
    if (trigger_module == catch.module and "trigger_ts" in details
            and pids and details.get("pid") in pids
            and details.get("pid") == (catch.details or {}).get("pid")):
        if step.get("remote_ips"):
            return True  # exact peer action identity is checked for containment
        created = _process_start(details)
        caught_created = _process_start(catch.details or {})
        return bool(created is not None and caught_created is not None
                    and abs(created - caught_created) <= 0.001)
    return False


def _is_remediation(ev: Event) -> bool:
    details = ev.details or {}
    if ev.module in {"Active Response SOAR", "Adversary Combat"}:
        # Absence is UNKNOWN, never success. Legacy recommendation/action rows
        # must not inflate a modern response score.
        return details.get("mitigated") is True
    if ev.module == "SOAR Automation":
        return details.get("action_succeeded") is True and str(
            details.get("action") or ""
        ).casefold() in {
            "suspend", "terminate", "isolate", "block",
        }
    return False


def _step_pids(step: dict) -> set[int]:
    return {pid for pid in [step.get("pid"), *(step.get("pids") or [])]
            if type(pid) is int and pid > 0}


def _expected_containment_targets(step: dict) -> set[tuple[str, object]]:
    """Every recorded artifact/child must be covered, including repeated spawns."""
    paths = {("path", _canonical_path(path))
             for path in step.get("artifact_paths", []) if path}
    peers = {("peer", str(peer).strip().casefold())
             for peer in step.get("remote_ips", []) if peer}
    # A network probe's PID identifies its connection; blocking every exact
    # peer is its postcondition, not terminating the enclosing test process.
    if peers:
        return paths | peers
    return paths | {("pid", pid) for pid in _step_pids(step)}


def _process_start(details: dict) -> float | None:
    for key in ("process_create_time", "pid_create_time", "create_time"):
        if key not in details:
            continue
        try:
            value = float(details[key])
            return value if math.isfinite(value) and value > 0 else None
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def _artifact_digests(step: dict, catches: list[Event]) -> dict[str, set[str]]:
    """Collect independent content identities already covered by evidence trust."""
    digests: dict[str, set[str]] = {}

    def include(path: str, value: object) -> None:
        if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value):
            digests.setdefault(path, set()).add(value.lower())

    paths = list(step.get("artifact_paths") or [])
    receipt = step.get("evidence_receipt") or {}
    receipts = receipt.get("artifact_receipts") if isinstance(receipt, dict) else None
    if isinstance(receipts, list):
        for path, row in zip(paths, receipts):
            if (isinstance(row, dict) and row.get("status") == "hashed"
                    and row.get("name") == Path(str(path)).name):
                include(_canonical_path(path), row.get("sha256"))
    expected = {_canonical_path(path) for path in paths}
    for catch in catches:
        details = catch.details or {}
        for key in ("path", "artifact_path"):
            path = _canonical_path(details.get(key))
            if path not in expected:
                continue
            for digest_key in ("sha256", "artifact_sha256", "observed_content_sha256"):
                include(path, details.get(digest_key))
    return digests


def _verified_containment_targets(
    step: dict, catch: Event, ev: Event,
    artifact_digests: dict[str, set[str]] | None = None,
) -> set[tuple[str, object]]:
    """Read exact committed action identities, never cleanup or wrapper claims."""
    details = ev.details or {}
    trigger_module, _trigger_time = _response_trigger_identity(catch, details)
    if not (
        ev.module == "Adversary Combat" and details.get("mitigated") is True
        and trigger_module == catch.module
        and "trigger_ts" in details and _matches_remediation(step, catch, ev)
    ):
        return set()
    rows = details.get("verified_actions")
    action_ids = details.get("action_ids")
    actions = details.get("actions")
    if not (isinstance(rows, list) and 0 < len(rows) <= 64
            and isinstance(action_ids, list) and isinstance(actions, list)):
        return set()
    expected = _expected_containment_targets(step)
    verified: set[tuple[str, object]] = set()
    used_ids: set[str] = set()
    catch_details = catch.details or {}
    if artifact_digests is None:
        artifact_digests = _artifact_digests(step, [catch])
    for row in rows:
        if not isinstance(row, dict) or row.get("postcondition_verified") is not True:
            continue
        action_id = row.get("action_id")
        action = row.get("action")
        identity = row.get("details")
        if not (isinstance(action_id, str) and 0 < len(action_id) <= 200
                and action_id in action_ids and action_id not in used_ids
                and isinstance(action, str) and action in actions and isinstance(identity, dict)):
            continue
        used_ids.add(action_id)
        if action == "quarantine_file":
            path = _canonical_path(identity.get("path"))
            caught_paths = {_canonical_path(catch_details.get(key))
                            for key in ("path", "artifact_path") if catch_details.get(key)}
            expected_digests = artifact_digests.get(path, set())
            digest = identity.get("sha256")
            if (path and path == _canonical_path(row.get("target"))
                    and path in caught_paths and ("path", path) in expected
                    and len(expected_digests) == 1 and isinstance(digest, str)
                    and digest.lower() in expected_digests):
                verified.add(("path", path))
        elif action in {"suspend_process", "terminate_process"}:
            pid = identity.get("pid")
            created = _process_start(identity)
            caught_created = _process_start(catch_details)
            target = row.get("target")
            if (type(pid) is int and ("pid", pid) in expected
                    and catch_details.get("pid") == pid
                    and isinstance(target, str) and len(target) <= 512
                    and target.endswith(f" ({pid})")
                    and created is not None and caught_created is not None
                    and abs(created - caught_created) <= 0.001):
                verified.add(("pid", pid))
        elif action == "block_remote_ip":
            peer = str(row.get("target") or "").strip().casefold()
            # The detector must independently bind this exact peer and PID.
            observed_peers = {
                _remote_endpoint(catch_details.get(key))[0]
                for key in ("raddr", "remote", "remote_address", "destination",
                            "remote_ip", "destination_ip", "dest_ip", "dst_ip")
                if catch_details.get(key)
            }
            if (("peer", peer) in expected and peer in observed_peers
                    and catch_details.get("pid") in _step_pids(step)):
                verified.add(("peer", peer))
        # Starting deception or changing unrelated host posture never proves
        # that this test's file/process/connection was contained.
    return verified


def evaluate(
    history: dict,
    events: List[Event],
    stage_category: Optional[dict] = None,
    *,
    require_authenticated: bool = False,
    event_verifier: Callable[[Event], bool] | None = None,
    native_verifier: Callable[[Event, dict], bool] | None = None,
    purple_verifier: Callable[[Event, dict], bool] | None = None,
) -> List[StepVerdict]:
    """Walk events in chronological order and, for each step, find the first
    real-module event that matches its artifact (the "catch"), then the first
    SOAR event that follows it (the "remediation"). `stage_category` overrides
    the default shark map so a different drill (e.g. Red Team) can classify its
    own stages."""
    cats = stage_category or STAGE_CATEGORY
    chrono = sorted(events, key=lambda e: e.ts)
    steps = list(history.get("steps", []))
    used_observations: set[int] = set()
    used_native: set[int] = set()
    used_verifications: set[int] = set()
    used_remediations: set[int] = set()
    verdicts: List[StepVerdict] = []
    for step_index, original_step in enumerate(steps):
        step = dict(original_step)
        step.setdefault("run_id", history.get("run_id", ""))
        next_start = (float(steps[step_index + 1]["ts_start"])
                      if step_index + 1 < len(steps)
                      else float(step.get("ts_end") or step["ts_start"]) + 30.0)
        # Extend the attribution window past the next step so interval-based
        # detectors (FIM ~30s, YARA ~5min) that fire late still count. _matches()
        # keeps this artifact-specific, so a widened window never mis-attributes.
        catch_deadline = max(next_start, float(step["ts_start"]) + _DETECTION_BUDGET_S)
        v = StepVerdict(stage=step["stage"], technique=step["technique"],
                        description=step["description"], ts_start=step["ts_start"],
                        ok=step.get("ok", True),
                        category=_category_for_step(step, cats))
        observation_index: Optional[int] = None
        native_index: Optional[int] = None
        verification_index: Optional[int] = None
        triggers: list[Event] = []
        native_indices: set[int] = set()
        verification_indices: set[int] = set()
        # Resolve detector evidence before response evidence.  Windows' wall
        # clock can assign the exact same ``time.time()`` value to a detector
        # publication and the immediately-following SOAR receipt.  Callers
        # commonly provide newest-first EventBus history, so a stable sort on
        # that timestamp alone can otherwise leave the receipt ahead of its
        # trigger and silently drop valid remediation proof.  The second pass
        # still requires a successful action, exact step/trigger correlation,
        # an unused receipt, and a non-negative response timestamp.
        for event_index, ev in enumerate(chrono):
            if (
                ev.ts < step["ts_start"] - 2
                or ev.ts > catch_deadline
                or not _trusted_stored_event(
                    ev,
                    required=require_authenticated,
                    verifier=event_verifier,
                )
            ):
                continue
            if _is_non_detector_source(ev):
                continue
            matches = _matches(step, ev)
            if not matches:
                continue
            if v.observation is None and event_index not in used_observations:
                v.observation = ev
                observation_index = event_index
                v.observation_latency = round(ev.ts - step["ts_start"], 3)

            purple = _is_purple_validation(step, ev)
            native = _is_native_analytic(ev)
            if require_authenticated:
                try:
                    purple = bool(
                        purple
                        and purple_verifier is not None
                        and purple_verifier(ev, step)
                    )
                    native = bool(
                        native
                        and native_verifier is not None
                        and native_verifier(ev, step)
                    )
                except (AttributeError, RuntimeError, TypeError, ValueError):
                    purple = False
                    native = False
            # Unauthenticated fixture mode changes storage trust only.  It
            # never changes evidence taxonomy: raw telemetry remains an
            # observation, and analytic credit still requires the explicit
            # native/Purple evidence type plus a positive detector verdict.
            if v.category == "informational":
                # Undeclared custom probes may be observed and displayed, but
                # cannot acquire analytic credit by accident.
                purple = False
                native = False
            native = native and event_index not in used_native
            purple = purple and event_index not in used_verifications
            if native:
                native_indices.add(event_index)
            if purple:
                verification_indices.add(event_index)
            if (native or purple) and all(ev is not item for item in triggers):
                triggers.append(ev)
            if (
                native
                and v.native_catch is None
                and event_index not in used_native
            ):
                v.native_catch = ev
                native_index = event_index
                v.native_latency = round(ev.ts - step["ts_start"], 3)
            if (
                purple
                and v.simulation_validation is None
                and event_index not in used_verifications
            ):
                v.simulation_validation = ev
                v.simulation_validation_latency = round(
                    ev.ts - step["ts_start"], 3
                )
                v.verification_catch = ev
                verification_index = event_index
                v.verification_latency = v.simulation_validation_latency

        analytic_candidates = [
            item for item in (v.native_catch, v.simulation_validation) if item
        ]
        if analytic_candidates:
            v.catch = min(analytic_candidates, key=lambda event: event.ts)
            v.catch_latency = round(v.catch.ts - step["ts_start"], 3)

        if triggers and v.catch is not None:
            remediation_candidates: list[tuple[int, Event]] = []
            contained: set[tuple[str, object]] = set()
            containment_events: list[Event] = []
            artifact_digests = _artifact_digests(step, triggers)
            for event_index, ev in enumerate(chrono):
                if (ev.ts < step["ts_start"] - 2
                        or ev.ts > catch_deadline
                        or event_index in used_remediations
                        or not _trusted_stored_event(
                            ev,
                            required=require_authenticated,
                            verifier=event_verifier,
                        )
                        or not _is_response_source(ev)):
                    continue
                matching_triggers = [item for item in triggers
                                     if ev.ts >= item.ts
                                     and _matches_remediation(step, item, ev)]
                if not matching_triggers:
                    continue
                v.response_action_reported = True
                if _is_remediation(ev):
                    remediation_candidates.append((event_index, ev))
                    v.response_action_applied = True
                proven: set[tuple[str, object]] = set()
                for trigger in matching_triggers:
                    proven.update(_verified_containment_targets(
                        step, trigger, ev, artifact_digests,
                    ))
                if proven:
                    contained.update(proven)
                    containment_events.append(ev)
                    used_remediations.add(event_index)
            expected = _expected_containment_targets(step)
            if v.ok and expected and expected.issubset(contained):
                v.target_containment_verified = True
                v.containment_latency = round(max(ev.ts for ev in containment_events)
                                              - step["ts_start"], 3)
                v.containment_reason = "Every recorded target has an exact verified containment action."
            elif contained:
                v.containment_reason = (
                    f"Only {len(contained & expected)}/{len(expected)} recorded targets "
                    "have exact verified containment actions."
                )
            elif v.response_action_applied:
                v.containment_reason = "Action reported applied; exact target containment is unverified."
            if remediation_candidates:
                # Active Response can publish a successful delegation wrapper
                # just before the exact Combat receipt becomes visible. Prefer
                # the receipt that proves the host postcondition, then fall back
                # to the earliest other successful response.
                event_index, ev = min(
                    remediation_candidates,
                    key=lambda item: (
                        0 if any(item[1] is ev for ev in containment_events) else 1,
                        item[1].ts,
                        item[0],
                    ),
                )
                trigger = min(
                    (
                        item for item in triggers
                        if ev.ts >= item.ts and _matches_remediation(step, item, ev)
                    ),
                    key=lambda item: item.ts,
                )
                v.remediation = ev
                v.remediation_latency = round(ev.ts - trigger.ts, 3)
                used_remediations.add(event_index)
        if observation_index is not None:
            used_observations.add(observation_index)
        if native_index is not None:
            used_native.add(native_index)
        if verification_index is not None:
            used_verifications.add(verification_index)
        used_native.update(native_indices)
        used_verifications.update(verification_indices)
        verdicts.append(v)
    return verdicts


def _bar(ch: str = "=") -> str:
    return ch * WIDTH


def _technique_id(value: object) -> str:
    match = re.search(
        r"\b(T\d{4}(?:\.\d{3})?|RT-[A-Z0-9_.-]+)\b",
        str(value or ""),
        re.I,
    )
    return match.group(1).upper() if match else str(value or "").strip()


def _closure_metrics(verdicts: List[StepVerdict]) -> dict:
    """Score unique actionable finding classes, never repeated drill steps."""
    classes: dict[str, list[StepVerdict]] = {}
    for verdict in verdicts:
        if verdict.category != "detection":
            continue
        technique = verdict.technique_id or _technique_id(verdict.technique)
        if technique:
            classes.setdefault(technique, []).append(verdict)
    applied = sum(
        1
        for rows in classes.values()
        if any(row.action_applied for row in rows)
    )

    verified = sum(
        1
        for rows in classes.values()
        if any(row.finding_resolved for row in rows)
    )
    return {
        "actionable_classes": len(classes),
        "actions_applied": applied,
        "verified_closures": verified,
    }


def _score_eligible(history: dict, verdicts: List[StepVerdict]) -> bool:
    campaign = history.get("campaign") or {}
    return bool(
        history.get("status", "completed") == "completed"
        and all(verdict.ok for verdict in verdicts)
        and (
            history.get("kind") != "red_team"
            or (isinstance(campaign, dict) and campaign.get("score_eligible") is True)
        )
    )


def _containment_metrics(history: dict, verdicts: List[StepVerdict]) -> dict:
    rows = [row for row in verdicts if row.category == "detection"]
    count = sum(1 for row in rows if row.target_containment_verified)
    eligible = len(rows)
    conclusive = _score_eligible(history, verdicts) and bool(eligible)
    return {
        "count": count,
        "eligible": eligible,
        "rate": count / eligible if conclusive else None,
        "outcome": ("inconclusive" if not conclusive else "verified"
                    if count == eligible else "partial" if count else "failed"),
    }


def render(history: dict, verdicts: List[StepVerdict], title: str = "SHARK ATTACK") -> str:
    lines = [_bar("="), f" ANGERONA — {title} AFTER-ACTION REPORT", _bar("=")]
    lines.append(f" Run ID     : {history.get('run_id', '?')}")
    lines.append(f" Generated  : {history.get('generated', '?')}")
    campaign = history.get("campaign") or {}
    score_eligible = _score_eligible(history, verdicts)
    containment = _containment_metrics(history, verdicts)
    lines.append(f" Containment outcome: {containment['outcome'].upper()}")
    if not score_eligible:
        expected = int(campaign.get("expected_steps", 0) or 0)
        missing = len(campaign.get("missing_plan_step_ids") or ())
        failed = len(campaign.get("failed_plan_step_ids") or ())
        unexpected = len(campaign.get("unexpected_plan_step_ids") or ())
        duplicates = len(campaign.get("duplicate_plan_step_ids") or ())
        lines.extend([
            " COVERAGE SCORE WITHHELD — mandatory campaign inventory is incomplete.",
            f" Expected mandatory steps: {expected}; missing={missing}; failed={failed}; "
            f"unexpected={unexpected}; duplicate={duplicates}.",
            " No retained subset is allowed to redefine the denominator or display 100%.",
        ])
    n = len(verdicts)
    caught = sum(1 for v in verdicts if v.catch)
    remediated = sum(1 for v in verdicts if v.remediation)
    lifecycle = _closure_metrics(verdicts)
    findings_resolved = lifecycle["verified_closures"]
    detection = [v for v in verdicts if v.category == "detection"]
    det_caught = sum(1 for v in detection if v.catch)
    observed = sum(1 for v in detection if v.observation)
    native_caught = sum(1 for v in detection if v.native_catch)
    simulation_validated = sum(1 for v in detection if v.simulation_validation)
    det_remediated = sum(1 for v in detection if v.remediation)
    verified_upgrades = sum(
        1 for v in detection if v.finding_resolved and v.verification_catch)
    lines.append(f" Steps run  : {n}     Compatible analytic catches: {caught}/{n}     "
                 f"Correlated SOAR actions: {remediated}/{caught}")
    readiness = history.get("validation_readiness")
    if isinstance(readiness, dict) and readiness:
        lines.append(
            " Simulation validation readiness: "
            f"{readiness.get('policy_count', '?')} contracts, "
            f"sensor health {readiness.get('sensor_health', '?')}%, "
            f"recorder authenticated="
            f"{bool((readiness.get('recorder') or {}).get('authenticated'))}."
        )
    lines.append(
        " Simulation-contract validation is a pipeline canary only; it is NOT "
        "real-attack, exploit, state-actor, or breach-prevention coverage."
    )
    lines.append(
        " Probe completion and test cleanup do not prove a response. Containment "
        "requires a committed action with a verified postcondition for every exact target."
    )
    lines.append(_bar("-"))
    lines.append(" TIMELINE")
    lines.append(_bar("-"))
    for v in verdicts:
        if v.category in {"unmonitored", "informational"}:
            status = "N/A    "
        elif v.category == "resilience":
            status = "FALSE-POS" if v.catch else "PASS   "
        else:
            status = "CAUGHT " if v.catch else "MISSED "
        lines.append(f" [{status}] {v.stage} — {v.technique}")
        lines.append(f"           {v.description}")

        if v.category == "informational":
            lines.append(
                "           informational only — this custom inert marker has no "
                "reviewed detector contract, so silence is not scored as a miss."
            )
        elif v.category == "unmonitored":
            lines.append("           no detector exists for this by design — read-only process/"
                         "connection enumeration is indistinguishable from ordinary admin-tool "
                         "activity without deeper behavioral correlation (see `academy explain "
                         f"\"{v.stage}\"` for the full reasoning). Informational only — not "
                         "counted in the detection coverage rate below.")
        elif v.category == "resilience":
            if v.catch:
                lines.append(f"           ⚠ {v.catch.module} fired on this — \"{v.catch.message}\" "
                             f"— but this step is a legitimate CPU/IO-heavy task with nothing "
                             "malicious about it. That's a FALSE POSITIVE worth investigating in "
                             f"{v.catch.module}'s trigger condition, not a successful catch.")
            else:
                lines.append("           correctly generated no alert — legitimate heavy CPU/IO "
                             "work should never be treated as malicious on its own. Silence here "
                             "is the passing outcome.")
        elif v.catch:
            if v.native_catch:
                lines.append(
                    f"           native analytic verdict by {v.native_catch.module} in "
                    f"{v.native_latency:.2f}s — \"{v.native_catch.message}\""
                )
            if v.simulation_validation:
                lines.append(
                    "           simulation-only Purple validation in "
                    f"{v.simulation_validation_latency:.2f}s — "
                    f"\"{v.simulation_validation.message}\""
                )
            if (
                v.observation
                and not v.native_catch
                and v.observation is not v.simulation_validation
            ):
                lines.append(
                    f"           raw sensor observation by {v.observation.module} in "
                    f"{v.observation_latency:.2f}s; observation alone is not a "
                    "native analytic verdict."
                )
            if v.finding_resolved:
                mode = ("PRACTICE FIX" if v.verification_mode == "practice-probe"
                        else "FULL-DRILL FIX")
                lines.append(f"           {mode} VERIFIED: fresh signed detector + response "
                             f"evidence is bound to action contract {v.contract_id}.")
            if v.remediation:
                lines.append(f"           action reported applied by {v.remediation.module} in "
                             f"{v.remediation_latency:.2f}s — \"{v.remediation.message}\"")
                if v.target_containment_verified:
                    lines.append(
                        "           TARGET CONTAINMENT VERIFIED: every exact recorded "
                        "target has a committed action and verified postcondition."
                    )
                else:
                    lines.append(f"           containment unverified: {v.containment_reason}")
            else:
                lines.append(f"           not remediated — the {v.catch.severity.label} "
                             "detection did not produce a correlated, successful SOAR action "
                             "inside this run's evidence window.")
        elif v.observation:
            lines.append(
                f"           observed by {v.observation.module} in "
                f"{v.observation_latency:.2f}s, but no positive analytic detector "
                "verdict was recorded in the bounded evidence window."
            )
        elif v.finding_resolved:
            mode = ("PRACTICE FIX" if v.verification_mode == "practice-probe"
                    else "LATER FULL-DRILL FIX")
            lines.append(f"           original run missed this marker; {mode} was subsequently "
                         f"verified by run {v.verification_run_id or '?'} under signed action "
                         f"contract {v.contract_id}. The original miss remains visible while "
                         "the detector/response gap is now closed.")
        elif v.action_applied:
            lines.append("           deterministic detector/cleanup action is APPLIED, not closed; "
                         "a fresh Purple Guard detector echo from a later run is still required.")
        elif v.stage == "Exfiltration":
            lines.append("           not yet detected — Network Monitor polls every 4s, so this "
                         "is rarely a timing issue. More likely: it deliberately doesn't re-alert "
                         "on a host it already saw within its novelty window (60 min by default), "
                         "so a repeat drill against the same test host within that window won't "
                         "generate a fresh alert even though the connection WAS observed (working "
                         "as designed — see `academy explain \"Exfiltration\"`). The engine "
                         "rotates between 3 test hosts per run to avoid this; if you've run several "
                         "drills back-to-back you may have cycled through all of them. Wait a few "
                         "minutes, or set ANGERONA_SHARK_EXFIL_HOST to a custom target, for a "
                         "guaranteed-fresh test.")
        else:
            lines.append("           not detected inside this report's bounded evidence window. "
                         "Slower scheduled scanners are not credited unless their exact "
                         "artifact-bound event was recorded before evidence cleanup; run a "
                         "fresh drill to test those scanners rather than treating a later "
                         "report refresh as new evidence.")
        if v.verification_error:
            lines.append(f"           verification pending/failed: {v.verification_error}")
        lines.append("")
    lines.append(_bar("-"))
    lines.append(" SCORECARD")
    lines.append(_bar("-"))
    if score_eligible:
        lines.append(f"   Sensor observation : {observed}/{len(detection)}  "
                     f"({(observed / len(detection) * 100 if detection else 0):.0f}%)")
        lines.append(f"   Native analytics   : {native_caught}/{len(detection)}  "
                     f"({(native_caught / len(detection) * 100 if detection else 0):.0f}%)")
        lines.append(f"   Simulation validate: {simulation_validated}/{len(detection)}  "
                     f"({(simulation_validated / len(detection) * 100 if detection else 0):.0f}%)  "
                     "— marker/process pipeline canary, not real-attack coverage")
        lines.append(f"   Detection coverage : {det_caught}/{len(detection)}  "
                     f"({(det_caught / len(detection) * 100 if detection else 0):.0f}%)   "
                     "— compatibility union; do not interpret as native efficacy")
    else:
        lines.append(
            f"   Sensor observation : WITHHELD ({observed}/{len(detection)} planned contracts)"
        )
        lines.append(
            f"   Native analytics   : WITHHELD ({native_caught}/{len(detection)} planned contracts)"
        )
        lines.append(
            "   Simulation validate: WITHHELD — incomplete mandatory run"
        )
        lines.append(
            "   Detection coverage : WITHHELD — incomplete mandatory run"
        )
    lines.append(f"   Actions reported   : {det_remediated}/{det_caught} analytic catches")
    if containment["rate"] is None:
        lines.append("   Response success   : WITHHELD — incomplete run or no eligible targets")
    else:
        lines.append(
            f"   Response success   : {containment['count']}/{containment['eligible']} "
            f"planned containment step(s) ({containment['rate'] * 100:.0f}%)"
        )
    actionable = lifecycle["actionable_classes"]
    applied = lifecycle["actions_applied"]
    verified = lifecycle["verified_closures"]
    lines.append(f"   Action contracts   : {applied}/{actionable} unique gap class(es) applied  "
                 f"({(applied / actionable * 100 if actionable else 0):.0f}%)")
    if score_eligible:
        lines.append(f"   Verified closure   : {verified}/{actionable} unique detector-fix class(es)  "
                     f"({(verified / actionable * 100 if actionable else 0):.0f}%)")
    else:
        lines.append("   Verified closure   : WITHHELD — incomplete run")
    if verified_upgrades:
        lines.append(f"   Detector fixes proven by rerun: {verified_upgrades}  "
                     "(signed Purple Guard evidence + contract verification)")
    if findings_resolved:
        lines.append(f"   Drill findings closed: {findings_resolved}  "
                     "(detector-fix contract and fresh rerun proof; "
                     "expiry/future misses reopen)")
    resilience = [v for v in verdicts if v.category == "resilience"]
    if resilience:
        fps = sum(1 for v in resilience if v.catch)
        lines.append(f"   Resilience check   : {'FAIL — false positive(s), see above' if fps else 'PASS — no false alert'}")
    unmon = [v for v in verdicts if v.category in {"unmonitored", "informational"}]
    if unmon:
        lines.append(f"   Unmonitored (info) : {', '.join(v.stage for v in unmon)} — no detector by design")
    times = [v.catch_latency for v in detection if v.catch_latency is not None]
    if times:
        lines.append(f"   Avg detect time    : {sum(times) / len(times):.2f}s   "
                     f"(fastest {min(times):.2f}s, slowest {max(times):.2f}s)")
    rtimes = [v.remediation_latency for v in verdicts if v.remediation_latency is not None]
    if rtimes:
        lines.append(f"   Avg mitigate time  : {sum(rtimes) / len(rtimes):.2f}s")
    lines.append(_bar("="))
    return "\n".join(lines)


def _report_dirs(data_dir: Path) -> List[Path]:
    """Keep AAR artifacts inside the configured runtime-data boundary."""
    return [Path(data_dir)]


def _prune_report_history(hist_dir: Path, basename: str) -> None:
    """Bound timestamped AAR text/JSON pairs by run count and age."""
    try:
        groups: dict[str, list[Path]] = {}
        for path in hist_dir.glob(f"{basename}_*.*"):
            if path.suffix.lower() not in {".txt", ".json"}:
                continue
            groups.setdefault(path.stem, []).append(path)
        ordered = sorted(
            groups.values(),
            key=lambda paths: max(p.stat().st_mtime for p in paths),
            reverse=True,
        )
        cutoff = time.time() - (_HISTORY_MAX_AGE_DAYS * 86400)
        for index, paths in enumerate(ordered):
            newest = max(p.stat().st_mtime for p in paths)
            if index < _HISTORY_RUN_LIMIT and newest >= cutoff:
                continue
            for path in paths:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
    except (OSError, ValueError):
        pass


def _atomic_write_text(path: Path, value: str) -> None:
    """Durably replace one report file without exposing a partial document."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_name(
        f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        replace_with_retry(tmp, destination)
    finally:
        tmp.unlink(missing_ok=True)


def _decode_journal_bundle(
    record: dict,
) -> tuple[bytes, bytes, bytes]:
    try:
        text_bytes = base64.b64decode(record["report_text_b64"], validate=True)
        report_bytes = base64.b64decode(record["report_json_b64"], validate=True)
        head_bytes = base64.b64decode(record["head_json_b64"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("AAR head journal bundle encoding is invalid") from exc
    if not all(
        0 < len(value) <= _REPORT_BUNDLE_MAX_BYTES
        for value in (text_bytes, report_bytes, head_bytes)
    ):
        raise ValueError("AAR head journal bundle is empty or oversized")
    return text_bytes, report_bytes, head_bytes


def _validate_journal_record(
    record: object,
    *,
    basename: str,
    previous_record_sha256: str,
    previous_head_sha256: str | None,
    expected_sequence: int,
) -> tuple[bytes, bytes, bytes]:
    if not isinstance(record, dict):
        raise ValueError("AAR head journal row is not an object")
    from angerona.core import report_attest

    if report_attest.verify(record) != "ok":
        raise ValueError("AAR head journal row HMAC is invalid")
    text_bytes, report_bytes, head_bytes = _decode_journal_bundle(record)
    try:
        report = json.loads(report_bytes.decode("utf-8", errors="strict"))
        head = json.loads(head_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise ValueError("AAR head journal signed bundle is malformed") from exc
    report_sha256 = hashlib.sha256(report_bytes).hexdigest()
    text_sha256 = hashlib.sha256(text_bytes).hexdigest()
    head_sha256 = hashlib.sha256(head_bytes).hexdigest()
    if (
        record.get("schema") != "angerona.aar-head-journal.v1"
        or record.get("report_basename") != basename
        or record.get("previous_record_sha256") != previous_record_sha256
        or record.get("head_sha256") != head_sha256
        or int(record.get("sequence", 0)) != expected_sequence
        or not isinstance(head, dict)
        or report_attest.verify(head) != "ok"
        or head.get("report_basename") != basename
        or int(head.get("sequence", 0)) != expected_sequence
        or (
            previous_head_sha256 is not None
            and head.get("previous_head_sha256") != previous_head_sha256
        )
        or (
            previous_head_sha256 is None
            and record.get("journal_anchor_previous_head_sha256")
            != head.get("previous_head_sha256")
        )
        or head.get("report_json_sha256") != report_sha256
        or head.get("report_text_sha256") != text_sha256
        or not isinstance(report, dict)
        or (
            str(head.get("report_kind") or "") == "red_team"
            and report_attest.verify(report) != "ok"
        )
        or report.get("report_text_sha256") != text_sha256
        or str(report.get("run_id") or "") != str(head.get("run_id") or "")
    ):
        raise ValueError("AAR head journal chain or bundle binding is invalid")
    return text_bytes, report_bytes, head_bytes


def _load_head_journal(
    path: Path,
    basename: str,
) -> list[tuple[dict, bytes, bytes, bytes, bytes]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise ValueError("AAR head journal has an unsafe identity")
    info = path.stat(follow_symlinks=False)
    if int(getattr(info, "st_nlink", 1)) != 1 or not 0 < info.st_size <= _HEAD_JOURNAL_MAX_BYTES:
        raise ValueError("AAR head journal size or link identity is invalid")
    raw = path.read_bytes()
    lines = [line for line in raw.splitlines() if line]
    if len(lines) > _HEAD_JOURNAL_MAX_RECORDS:
        raise ValueError("AAR head journal record bound was exceeded")
    rows: list[tuple[dict, bytes, bytes, bytes, bytes]] = []
    previous_record_sha256 = "0" * 64
    previous_head_sha256: str | None = None
    previous_sequence = 0
    for index, line in enumerate(lines, 1):
        if len(line) > _REPORT_BUNDLE_MAX_BYTES * 4:
            raise ValueError("AAR head journal row is oversized")
        try:
            record = json.loads(line.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, ValueError, TypeError) as exc:
            raise ValueError("AAR head journal row is malformed") from exc
        try:
            row_sequence = int(record.get("sequence", 0))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("AAR head journal sequence is invalid") from exc
        expected_sequence = (
            row_sequence if index == 1 else previous_sequence + 1
        )
        if row_sequence < 1:
            raise ValueError("AAR head journal sequence is invalid")
        text_bytes, report_bytes, head_bytes = _validate_journal_record(
            record,
            basename=basename,
            previous_record_sha256=previous_record_sha256,
            previous_head_sha256=previous_head_sha256,
            expected_sequence=expected_sequence,
        )
        rows.append((record, line, text_bytes, report_bytes, head_bytes))
        previous_record_sha256 = hashlib.sha256(line).hexdigest()
        previous_head_sha256 = hashlib.sha256(head_bytes).hexdigest()
        previous_sequence = row_sequence
    return rows


def _append_head_journal(path: Path, encoded_record: bytes) -> None:
    if not encoded_record or len(encoded_record) > _REPORT_BUNDLE_MAX_BYTES * 4:
        raise ValueError("AAR head journal append is empty or oversized")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if int(getattr(info, "st_nlink", 1)) != 1:
            raise ValueError("AAR head journal is linked")
        if info.st_size + len(encoded_record) + 1 > _HEAD_JOURNAL_MAX_BYTES:
            raise ValueError("AAR head journal capacity was exhausted")
        pending = encoded_record + b"\n"
        offset = 0
        while offset < len(pending):
            written = os.write(descriptor, pending[offset:])
            if written <= 0:
                raise OSError("AAR head journal append made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_bound_report_bundle(
    data_dir: Path,
    basename: str,
) -> tuple[dict, bytes, bytes, bytes]:
    text_path = data_dir / f"{basename}.txt"
    report_path = data_dir / f"{basename}.json"
    head_path = data_dir / f"{basename}.head.json"
    for path in (text_path, report_path, head_path):
        if path.is_symlink() or not path.is_file():
            raise ValueError("AAR fixed report bundle has an unsafe identity")
        info = path.stat(follow_symlinks=False)
        if (
            int(getattr(info, "st_nlink", 1)) != 1
            or not 0 < info.st_size <= _REPORT_BUNDLE_MAX_BYTES
        ):
            raise ValueError("AAR fixed report bundle size or links are invalid")
    text_bytes = text_path.read_bytes()
    report_bytes = report_path.read_bytes()
    head_bytes = head_path.read_bytes()
    try:
        report = json.loads(report_bytes.decode("utf-8", errors="strict"))
        head = json.loads(head_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise ValueError("AAR fixed report bundle is malformed") from exc
    from angerona.core import report_attest

    if (
        not isinstance(report, dict)
        or not isinstance(head, dict)
        or report_attest.verify(head) != "ok"
        or head.get("report_basename") != basename
        or head.get("report_json_sha256")
        != hashlib.sha256(report_bytes).hexdigest()
        or head.get("report_text_sha256")
        != hashlib.sha256(text_bytes).hexdigest()
        or report.get("report_text_sha256")
        != hashlib.sha256(text_bytes).hexdigest()
        or str(report.get("run_id") or "") != str(head.get("run_id") or "")
        or (
            str(head.get("report_kind") or "") == "red_team"
            and report_attest.verify(report) != "ok"
        )
    ):
        raise ValueError("AAR fixed report bundle binding is invalid")
    return head, text_bytes, report_bytes, head_bytes


def _publish_report_bundle(
    data_dir: Path,
    history: dict,
    *,
    basename: str,
    text: str,
    encoded_payload: str,
    report_sha256: str,
) -> AARReportResult:
    root = Path(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    journal_path = root / f"{basename}.heads.jsonl"
    head_path = root / f"{basename}.head.json"
    lock_path = root / f"{basename}.writer.lock"
    text_bytes = text.encode("utf-8")
    report_bytes = encoded_payload.encode("utf-8")
    if not all(
        0 < len(value) <= _REPORT_BUNDLE_MAX_BYTES
        for value in (text_bytes, report_bytes)
    ):
        raise ValueError("AAR report bundle is empty or oversized")

    with ExclusiveFileLease(lock_path):
        journal = _load_head_journal(journal_path, basename)
        prior_sequence = 0
        previous_head_sha256 = "0" * 64
        previous_record_sha256 = "0" * 64
        if journal:
            prior_record, prior_raw, prior_text, prior_report, prior_head = journal[-1]
            prior_sequence = int(prior_record["sequence"])
            previous_head_sha256 = hashlib.sha256(prior_head).hexdigest()
            previous_record_sha256 = hashlib.sha256(prior_raw).hexdigest()
            # Journal and fixed bundle are independent witnesses. A missing or
            # damaged fixed projection can be recovered from the journal, and
            # an authentic older fixed projection can be advanced. An authentic
            # fixed head newer than the journal is proof that the journal was
            # rolled back, so fail closed instead of creating a lower fork.
            try:
                fixed_head, _text, _report, fixed_head_bytes = (
                    _read_bound_report_bundle(
                    root, basename
                    )
                )
            except (OSError, UnicodeDecodeError, ValueError, TypeError):
                fixed_head = None
                fixed_head_bytes = b""
            repair_fixed = fixed_head is None
            if fixed_head is not None:
                try:
                    fixed_sequence = int(fixed_head.get("sequence", 0))
                except (AttributeError, TypeError, ValueError) as exc:
                    raise ValueError("AAR fixed-head sequence is invalid") from exc
                fixed_head_sha256 = hashlib.sha256(fixed_head_bytes).hexdigest()
                if fixed_head_sha256 == previous_head_sha256:
                    if fixed_sequence != prior_sequence:
                        raise ValueError("AAR fixed head sequence binding is invalid")
                elif fixed_sequence > prior_sequence:
                    raise ValueError(
                        "AAR journal rollback detected against newer fixed report evidence"
                    )
                elif fixed_sequence == prior_sequence:
                    raise ValueError(
                        "AAR same-sequence fixed/journal head fork detected"
                    )
                else:
                    exact_ancestor = any(
                        int(row[0].get("sequence", 0)) == fixed_sequence
                        and hashlib.sha256(row[4]).hexdigest() == fixed_head_sha256
                        for row in journal
                    )
                    if not exact_ancestor:
                        raise ValueError(
                            "AAR fixed report is not an authenticated journal ancestor"
                        )
                    repair_fixed = True
            if repair_fixed:
                _atomic_write_text(root / f"{basename}.txt", prior_text.decode("utf-8"))
                _atomic_write_text(root / f"{basename}.json", prior_report.decode("utf-8"))
                _atomic_write_text(root / f"{basename}.head.json", prior_head.decode("utf-8"))
        elif head_path.exists():
            # One-time migration: authenticate the exact legacy fixed bundle
            # and use it as the external predecessor of journal record one.
            prior_head, _prior_text, _prior_report, prior_head_bytes = (
                _read_bound_report_bundle(root, basename)
            )
            if (
                prior_head.get("continuity")
                == "os-serialized-authenticated-append-only-journal"
            ):
                raise ValueError(
                    "AAR journal deletion or rollback detected against fixed report evidence"
                )
            prior_sequence = int(prior_head.get("sequence", 0))
            if prior_sequence < 1:
                raise ValueError("AAR predecessor sequence is invalid")
            previous_head_sha256 = hashlib.sha256(prior_head_bytes).hexdigest()

        sequence = prior_sequence + 1
        head_body = {
            "schema": "angerona.aar-report-head.v2",
            "sequence": sequence,
            "previous_head_sha256": previous_head_sha256,
            "run_id": str(history.get("run_id") or ""),
            "report_kind": str(history.get("kind") or ""),
            "report_basename": basename,
            "report_json_sha256": report_sha256,
            "report_text_sha256": hashlib.sha256(text_bytes).hexdigest(),
            "published_at_ns": time.time_ns(),
            "continuity": "os-serialized-authenticated-append-only-journal",
        }
        from angerona.core import report_attest

        signed_head = report_attest.attest(head_body)
        if (
            history.get("kind") == "red_team"
            and report_attest.verify(signed_head) != "ok"
        ):
            raise ValueError("Red Team report head could not be authenticated")
        head_bytes = json.dumps(signed_head, indent=2).encode("utf-8")
        if len(head_bytes) > _REPORT_BUNDLE_MAX_BYTES:
            raise ValueError("AAR report head is oversized")
        head_sha256 = hashlib.sha256(head_bytes).hexdigest()
        record_body = {
            "schema": "angerona.aar-head-journal.v1",
            "sequence": sequence,
            "report_basename": basename,
            "previous_record_sha256": previous_record_sha256,
            "journal_anchor_previous_head_sha256": (
                previous_head_sha256 if not journal else ""
            ),
            "head_sha256": head_sha256,
            "report_text_b64": base64.b64encode(text_bytes).decode("ascii"),
            "report_json_b64": base64.b64encode(report_bytes).decode("ascii"),
            "head_json_b64": base64.b64encode(head_bytes).decode("ascii"),
        }
        signed_record = report_attest.attest(record_body)
        if report_attest.verify(signed_record) != "ok":
            raise ValueError("AAR head journal row could not be authenticated")
        encoded_record = json.dumps(
            signed_record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        _append_head_journal(journal_path, encoded_record)

        # The fsync-backed append above is authority. Fixed files are a
        # recoverable projection used by the GUI and remediation workflow.
        _atomic_write_text(root / f"{basename}.txt", text)
        _atomic_write_text(root / f"{basename}.json", encoded_payload)
        _atomic_write_text(root / f"{basename}.head.json", head_bytes.decode("utf-8"))

    try:
        hist_dir = root / "aar_history"
        hist_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        _atomic_write_text(hist_dir / f"{basename}_{stamp}.txt", text)
        _atomic_write_text(hist_dir / f"{basename}_{stamp}.json", encoded_payload)
        _prune_report_history(hist_dir, basename)
    except Exception:
        pass
    return AARReportResult(
        text=text,
        run_id=str(history.get("run_id") or ""),
        report_kind=str(history.get("kind") or ""),
        report_basename=basename,
        report_sha256=report_sha256,
        head_sha256=head_sha256,
        sequence=sequence,
        text_bytes=text_bytes,
        report_bytes=report_bytes,
        head_bytes=head_bytes,
        journal_record_sha256=hashlib.sha256(encoded_record).hexdigest(),
        journal_record_bytes=encoded_record,
        report_directory=root.resolve(strict=False),
    )


def _write_report(data_dir: Path, history: dict, verdicts: List[StepVerdict], text: str,
                  basename: str = "shark_aar") -> AARReportResult:
    """Persist both a human-readable .txt (identical to what's printed/shown
    in the GUI) and a structured .json (easy to parse programmatically) —
    always overwritten with the latest evaluation, so the files on disk
    never go stale relative to whatever `aar` or the review window last
    computed."""
    n = len(verdicts)
    caught = sum(1 for v in verdicts if v.catch)
    remediated = sum(1 for v in verdicts if v.remediation)
    lifecycle = _closure_metrics(verdicts)
    findings_resolved = lifecycle["verified_closures"]
    detection = [v for v in verdicts if v.category == "detection"]
    det_caught = sum(1 for v in detection if v.catch)
    observed = sum(1 for v in detection if v.observation)
    native_caught = sum(1 for v in detection if v.native_catch)
    simulation_validated = sum(1 for v in detection if v.simulation_validation)
    det_remediated = sum(1 for v in detection if v.remediation)
    verified_upgrades = sum(
        1 for v in detection if v.finding_resolved and v.verification_catch)
    campaign = history.get("campaign") or {}
    score_eligible = _score_eligible(history, verdicts)
    containment = _containment_metrics(history, verdicts)

    def _rate(numerator: int, denominator: int) -> float | None:
        if not score_eligible:
            return None
        return numerator / denominator if denominator else 0.0

    payload = {
        "run_id": history.get("run_id"),
        "report_basename": basename,
        "report_kind": history.get("kind"),
        "outcome": containment["outcome"],
        "report_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "steps_run": n,
        "detected": caught,               # raw count, all categories — kept for backward compat
        "remediated": sum(1 for v in verdicts if v.target_containment_verified),
        "response_actions_applied": remediated,
        "detection_response_actions_applied": det_remediated,
        "findings_resolved": findings_resolved,
        "actionable_finding_classes": lifecycle["actionable_classes"],
        "action_contracts_applied": lifecycle["actions_applied"],
        "verified_closures": lifecycle["verified_closures"],
        "verified_closure_rate": _rate(lifecycle["verified_closures"],
                                       lifecycle["actionable_classes"]),
        "detection_steps": len(detection),      # steps where a detector SHOULD fire
        "detection_caught": det_caught,
        "coverage_score_eligible": score_eligible,
        "campaign_completeness": copy.deepcopy(campaign) if isinstance(campaign, dict) else {},
        "coverage_interpretation": (
            "Simulation validation proves this inert marker/process pipeline, not "
            "real-attack, exploit, state-actor, or breach-prevention coverage."
        ),
        "receipt_trust_boundary": (
            "same-process-object-capability; a measured isolated producer/verifier "
            "is required to resist arbitrary native memory mutation"
        ),
        "validation_readiness": history.get("validation_readiness"),
        "epistemic_metrics": {
            "verified_containment": {
                "count": containment["count"],
                "eligible": containment["eligible"],
                "rate": containment["rate"],
            },
            "action_reported": {
                "count": sum(1 for v in detection if v.response_action_reported),
            },
            "action_applied": {
                "count": sum(1 for v in detection if v.response_action_applied),
            },
        },
        "evidence_taxonomy": {
            "denominator": len(detection),
            "sensor_observation": {
                "count": observed,
                "rate": _rate(observed, len(detection)),
            },
            "native_analytic_detection": {
                "count": native_caught,
                "rate": _rate(native_caught, len(detection)),
            },
            "simulation_contract_validation": {
                "count": simulation_validated,
                "rate": _rate(simulation_validated, len(detection)),
                "simulation_only": True,
            },
            "compatible_analytic_union": {
                "count": det_caught,
                "rate": _rate(det_caught, len(detection)),
            },
            "successful_response": {
                "count": containment["count"],
                "eligible": containment["eligible"],
                "rate": containment["rate"],
            },
        },
        "detection_remediated": containment["count"],
        "remediation_eligible": containment["eligible"],
        "response_success_rate": containment["rate"],
        "verified_detector_upgrades": verified_upgrades,
        "verdicts": [
            {
                "stage": v.stage,
                "technique": v.technique,
                "description": v.description,
                "ts_start": v.ts_start,
                "category": v.category,   # "detection" | "resilience" | "unmonitored"
                "caught": v.catch is not None,
                "detected_by": v.catch.module if v.catch else None,
                "detect_latency_s": v.catch_latency,
                "detect_message": v.catch.message if v.catch else None,
                "observed": v.observation is not None,
                "observed_by": v.observation.module if v.observation else None,
                "observation_latency_s": v.observation_latency,
                "native_analytic_detected": v.native_catch is not None,
                "native_analytic_detected_by": (
                    v.native_catch.module if v.native_catch else None
                ),
                "native_analytic_latency_s": v.native_latency,
                "simulation_validated": v.simulation_validation is not None,
                "simulation_validated_by": (
                    v.simulation_validation.module
                    if v.simulation_validation else None
                ),
                "simulation_validation_latency_s": (
                    v.simulation_validation_latency
                ),
                "verification_detected_by": (
                    v.verification_catch.module if v.verification_catch else None
                ),
                "verification_detect_latency_s": v.verification_latency,
                "remediated": v.target_containment_verified,
                "remediated_by": (v.remediation.module if v.remediation
                                  and v.target_containment_verified else None),
                "remediate_latency_s": v.containment_latency,
                "response_action_reported": v.response_action_reported,
                "response_action_applied": v.response_action_applied,
                "response_action_module": v.remediation.module if v.remediation else None,
                "response_action_message": v.remediation.message if v.remediation else None,
                "response_action_latency_s": v.remediation_latency,
                "target_containment_verified": v.target_containment_verified,
                "containment_reason": v.containment_reason,
                "finding_resolved": v.finding_resolved,
                "technique_id": v.technique_id or _technique_id(v.technique),
                "action_state": v.action_state,
                "action_applied": v.action_applied,
                "action_contract_id": v.contract_id,
                "action_contract_digest": v.contract_digest,
                "verification_expires_at": v.verification_expires_at,
                "verification_mode": v.verification_mode,
                "verification_run_id": v.verification_run_id,
                "verification_receipt_id": v.verification_receipt_id,
                "verification_error": v.verification_error,
            }
            for v in verdicts
        ],
    }
    # Attest the structured payload with the per-install HMAC key so the
    # self-hardening loop can prove this AAR wasn't forged or tampered with
    # before it learns weaknesses from it (see core/report_attest.py). Signing
    # is best-effort: if the key isn't available the payload is written unsigned
    # and the ingest side flags it — writing the report must never fail here.
    try:
        from angerona.core import report_attest
        signed_payload = report_attest.attest(payload)
    except Exception:
        signed_payload = payload

    encoded_payload = json.dumps(signed_payload, indent=2)
    encoded_payload_bytes = encoded_payload.encode("utf-8")
    report_sha256 = hashlib.sha256(encoded_payload_bytes).hexdigest()
    return _publish_report_bundle(
        Path(data_dir),
        history,
        basename=basename,
        text=text,
        encoded_payload=encoded_payload,
        report_sha256=report_sha256,
    )


def _incomplete_redteam_verdicts(history: dict) -> List[StepVerdict]:
    """Represent the authenticated planned denominator without scoring evidence."""
    campaign = history.get("campaign") or {}
    expected = campaign.get("expected_plan") if isinstance(campaign, dict) else []
    rows = expected if isinstance(expected, list) else []
    actual_steps = history.get("steps") if isinstance(history.get("steps"), list) else []
    actual_by_id = {
        str(row.get("plan_step_id") or ""): row
        for row in actual_steps
        if isinstance(row, dict) and row.get("plan_step_id")
    }
    fallback_ts = min(
        (
            float(row.get("ts_start", time.time()))
            for row in actual_steps
            if isinstance(row, dict)
        ),
        default=time.time(),
    )
    verdicts: List[StepVerdict] = []
    for planned in rows:
        if not isinstance(planned, dict):
            continue
        plan_step_id = str(planned.get("plan_step_id") or "")
        actual = actual_by_id.get(plan_step_id, {})
        ok = actual.get("ok") is True
        reason = (
            "Mandatory step completed, but the campaign is incomplete; all "
            "coverage credit is withheld."
            if ok
            else "Mandatory step was missing or failed; no coverage credit is permitted."
        )
        verdicts.append(StepVerdict(
            stage=str(planned.get("stage") or "Mandatory simulation step"),
            technique=str(planned.get("technique") or "unrecorded"),
            description=reason,
            ts_start=float(actual.get("ts_start", fallback_ts)),
            ok=False,
            category=str(planned.get("category") or "detection"),
            verification_error="campaign completeness gate withheld scoring",
        ))
    return verdicts


def generate_aar(data_dir: Optional[Path] = None, settle_seconds: float = 0.0,
                 window: float = 3600.0, history_name: str = "shark_history.json",
                 stage_category: Optional[dict] = None, title: str = "SHARK ATTACK",
                 report_basename: str = "shark_aar",
                 recorder: Optional[FlightRecorder] = None,
                 bus: object | None = None,
                 manager: object | None = None,
                 validation_lease: object | None = None,
                 return_result: bool = False) -> str | AARReportResult:
    """Build the report text, and persist it to shark_aar.txt / shark_aar.json
    (see _write_report) so it's readable straight off disk afterward.

    Call with ``settle_seconds`` > 0 right after a run completes to give
    fast-polling modules (e.g. File Integrity Monitor, 30s) one more cycle
    before judging a step a miss.  Only exact events already present in the
    bounded ledger window are credited.  A later refresh does not manufacture
    coverage after the originating run's artifacts have been cleaned; use a
    fresh drill when testing a slower scheduled detector.
    """
    if settle_seconds > 0:
        time.sleep(settle_seconds)
    # An explicit run root owns both ground truth and ledger evidence.  The old
    # implementation loaded an ambient Config and could score root A using the
    # recorder from unrelated root B.
    data_dir = Path(data_dir or Config.load().data_dir).resolve(strict=False)
    history_path = data_dir / history_name
    if not history_path.exists():
        return f"No {history_name} found — run a drill first."
    try:
        history = _load_history(history_path)
    except DrillHistoryIntegrityError as exc:
        return (
            "Drill history integrity check failed — "
            f"{exc}. AAR not generated."
        )
    red_team_history = str(history.get("kind") or "") == "red_team"
    if not history.get("steps") and not red_team_history:
        return "Last run recorded zero steps — nothing to report."

    active_recorder = recorder
    owns_recorder = active_recorder is None
    if active_recorder is None:
        active_recorder = FlightRecorder(data_dir / "flight-recorder.db")
    try:
        from angerona.modules.purple_guard import (
            RedTeamValidationError,
            RedTeamValidationLease,
            validate_redteam_recorder,
            validation_authority_matches,
            verify_validation_native_event,
            verify_validation_purple_event,
            verify_validation_run_history,
        )

        try:
            validate_redteam_recorder(active_recorder, data_dir, bus=bus)
        except RedTeamValidationError as exc:
            return (
                "AAR recorder integrity check failed — "
                f"{exc}. AAR not generated."
            )

        if red_team_history:
            if (
                type(validation_lease) is not RedTeamValidationLease
                or not validation_authority_matches(
                    validation_lease,
                    recorder=active_recorder,
                    bus=bus,
                    manager=manager,
                )
                or not verify_validation_run_history(validation_lease, history)
            ):
                return (
                    "Red Team validation integrity check failed — the signed run "
                    "history is not bound to the exact live, unreleased validation "
                    "lease, recorder, bus, manager, target, and sensor generation. "
                    "AAR not generated."
                )
            campaign = history.get("campaign") or {}
            if (
                history.get("status") != "completed"
                or not isinstance(campaign, dict)
                or campaign.get("score_eligible") is not True
            ):
                verdicts = _incomplete_redteam_verdicts(history)
                text = render(history, verdicts, title)
                result = _write_report(
                    data_dir, history, verdicts, text, report_basename
                )
                return result if return_result else text

        run_start = min(s["ts_start"] for s in history["steps"])
        evidence_window = float(window)
        if red_team_history:
            safety = history.get("safety_contract") or {}
            budget = safety.get("budget") if isinstance(safety, dict) else {}
            try:
                admitted_horizon = float(
                    budget.get("admitted_run_ttl_seconds")
                )
            except (AttributeError, TypeError, ValueError, OverflowError):
                admitted_horizon = 0.0
            if (
                not 60.0 <= admitted_horizon <= MAX_ADMITTED_DRILL_SECONDS
            ):
                return (
                    "Red Team evidence horizon is invalid — AAR not generated."
                )
            # Caller/default windows may widen ordinary reports, but can never
            # truncate an authenticated Red Team campaign. The absolute safety
            # contract remains the upper query bound.
            evidence_window = min(
                MAX_ADMITTED_DRILL_SECONDS,
                max(admitted_horizon, float(window)),
            )
        # events_in_window() queries by time range directly — no row-count cap,
        # so drills run long before the current session won't be silently empty
        # because newer events pushed them out of recent(2000).
        events = FlightRecorder.events_in_window(
            active_recorder,
            run_start - 5,
            run_start + evidence_window,
        )

        authority = active_recorder.authority

        def verify_stored_event(event: Event) -> bool:
            # Invoke the exact built-in implementations.  An instance-level
            # method replacement must not be able to turn arbitrary ledger
            # rows into authenticated detector evidence during a drill AAR.
            if not BusAuthority.verify(authority, event):
                return False
            if bus is not None and not EventBus.verify(bus, event):
                return False
            return True

        native_verifier = None
        purple_verifier = None
        if red_team_history:
            native_verifier = lambda event, step: verify_validation_native_event(
                validation_lease, event, manager, step
            )
            purple_verifier = lambda event, step: verify_validation_purple_event(
                validation_lease, event, step
            )
    finally:
        if owns_recorder:
            active_recorder.close()

    verdicts = evaluate(
        history,
        events,
        stage_category,
        require_authenticated=True,
        event_verifier=verify_stored_event,
        native_verifier=native_verifier,
        purple_verifier=purple_verifier,
    )
    # Reconcile proof, never invent or execute a fix: misses become
    # OPEN/REOPENED and only a fresh, exact Purple Guard echo can close an
    # already-applied deterministic action contract.
    try:
        from angerona.core import drill_resolution

        drill_resolution.reconcile_verdicts(
            verdicts,
            str(history.get("run_id") or ""),
            data_dir,
        )
    except Exception as exc:
        # The report stays available when lifecycle state is unavailable or
        # tampered, but no closure credit is granted.
        for verdict in verdicts:
            if verdict.category == "detection":
                verdict.verification_error = (
                    f"{type(exc).__name__}: lifecycle reconciliation unavailable"
                )
    text = render(history, verdicts, title)
    result = _write_report(data_dir, history, verdicts, text, report_basename)
    return result if return_result else text


if __name__ == "__main__":
    print(generate_aar())
