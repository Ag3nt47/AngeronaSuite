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

import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from angerona.core.config import Config
from angerona.core.atomic_io import replace_with_retry
from angerona.core.eventbus import Event
from angerona.core.storage import FlightRecorder
from angerona.shark.run_manifest import (
    DrillHistoryIntegrityError,
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
    catch: Optional[Event] = None
    catch_latency: Optional[float] = None
    # Earliest detector evidence remains ``catch`` for latency. Purple Guard
    # proof is tracked independently so a faster FIM/telemetry event cannot
    # hide the reviewed detector candidate that arrived a moment later.
    verification_catch: Optional[Event] = None
    verification_latency: Optional[float] = None
    remediation: Optional[Event] = None
    remediation_latency: Optional[float] = None
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


def _matches_remediation(step: dict, catch: Event, ev: Event) -> bool:
    details = ev.details or {}
    try:
        if abs(float(details.get("trigger_ts")) - float(catch.ts)) < 0.000001:
            return True
    except (TypeError, ValueError):
        pass
    return _matches(step, ev)


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


def evaluate(history: dict, events: List[Event],
             stage_category: Optional[dict] = None) -> List[StepVerdict]:
    """Walk events in chronological order and, for each step, find the first
    real-module event that matches its artifact (the "catch"), then the first
    SOAR event that follows it (the "remediation"). `stage_category` overrides
    the default shark map so a different drill (e.g. Red Team) can classify its
    own stages."""
    cats = stage_category or STAGE_CATEGORY
    chrono = sorted(events, key=lambda e: e.ts)
    steps = list(history.get("steps", []))
    used_catches: set[int] = set()
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
                        category=cats.get(step["stage"], "detection"))
        catch_index: Optional[int] = None
        verification_index: Optional[int] = None
        # Resolve detector evidence before response evidence.  Windows' wall
        # clock can assign the exact same ``time.time()`` value to a detector
        # publication and the immediately-following SOAR receipt.  Callers
        # commonly provide newest-first EventBus history, so a stable sort on
        # that timestamp alone can otherwise leave the receipt ahead of its
        # trigger and silently drop valid remediation proof.  The second pass
        # still requires a successful action, exact step/trigger correlation,
        # an unused receipt, and a non-negative response timestamp.
        for event_index, ev in enumerate(chrono):
            if ev.ts < step["ts_start"] - 2 or ev.ts > catch_deadline or ev.module == "Console":
                continue
            if _is_remediation(ev):
                continue
            matches = _matches(step, ev)
            if not matches:
                continue
            if v.catch is None and event_index not in used_catches:
                v.catch = ev
                catch_index = event_index
                v.catch_latency = round(ev.ts - step["ts_start"], 3)
            if (ev.module == "Purple Remediation Guard"
                    and v.verification_catch is None
                    and event_index not in used_verifications):
                v.verification_catch = ev
                verification_index = event_index
                v.verification_latency = round(ev.ts - step["ts_start"], 3)

        triggers = [item for item in (v.catch, v.verification_catch) if item]
        if triggers:
            for event_index, ev in enumerate(chrono):
                if (ev.ts < step["ts_start"] - 2
                        or ev.ts > catch_deadline
                        or event_index in used_remediations
                        or not _is_remediation(ev)):
                    continue
                trigger = next(
                    (
                        item
                        for item in triggers
                        if ev.ts >= item.ts
                        and _matches_remediation(step, item, ev)
                    ),
                    None,
                )
                if trigger is None:
                    continue
                v.remediation = ev
                v.remediation_latency = round(ev.ts - trigger.ts, 3)
                used_remediations.add(event_index)
                break
        if catch_index is not None:
            used_catches.add(catch_index)
        if verification_index is not None:
            used_verifications.add(verification_index)
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
        1 for rows in classes.values() if any(row.action_applied for row in rows)
    )
    def response_verified(row: StepVerdict) -> bool:
        return bool(
            row.remediation is not None
            and row.remediation.module == "Adversary Combat"
            and (row.remediation.details or {}).get("postcondition_verified") is True
        )

    verified = sum(
        1
        for rows in classes.values()
        if any(row.finding_resolved for row in rows)
        or (bool(rows) and all(response_verified(row) for row in rows))
    )
    return {
        "actionable_classes": len(classes),
        "actions_applied": applied,
        "verified_closures": verified,
    }


def render(history: dict, verdicts: List[StepVerdict], title: str = "SHARK ATTACK") -> str:
    lines = [_bar("="), f" ANGERONA — {title} AFTER-ACTION REPORT", _bar("=")]
    lines.append(f" Run ID     : {history.get('run_id', '?')}")
    lines.append(f" Generated  : {history.get('generated', '?')}")
    n = len(verdicts)
    caught = sum(1 for v in verdicts if v.catch)
    remediated = sum(1 for v in verdicts if v.remediation)
    lifecycle = _closure_metrics(verdicts)
    findings_resolved = lifecycle["verified_closures"]
    detection = [v for v in verdicts if v.category == "detection"]
    det_caught = sum(1 for v in detection if v.catch)
    det_remediated = sum(1 for v in detection if v.remediation)
    verified_upgrades = sum(
        1 for v in detection if v.finding_resolved and v.verification_catch)
    lines.append(f" Steps run  : {n}     Raw catches: {caught}/{n}     "
                 f"Correlated SOAR actions: {remediated}/{caught}")
    lines.append(f" (\"Raw catches\" includes every step regardless of what a pass looks like for "
                 "it — see the scorecard below for the number that actually matters: detection "
                 "coverage over the steps a detector is meant to catch.)")
    lines.append(_bar("-"))
    lines.append(" TIMELINE")
    lines.append(_bar("-"))
    for v in verdicts:
        if v.category == "unmonitored":
            status = "N/A    "
        elif v.category == "resilience":
            status = "FALSE-POS" if v.catch else "PASS   "
        else:
            status = "CAUGHT " if v.catch else "MISSED "
        lines.append(f" [{status}] {v.stage} — {v.technique}")
        lines.append(f"           {v.description}")

        if v.category == "unmonitored":
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
            lines.append(f"           detected by {v.catch.module} in "
                         f"{v.catch_latency:.2f}s — \"{v.catch.message}\"")
            if v.verification_catch and v.verification_catch is not v.catch:
                lines.append(
                    "           reviewed detector candidate also fired in "
                    f"{v.verification_latency:.2f}s — \"{v.verification_catch.message}\""
                )
            if v.finding_resolved:
                mode = ("PRACTICE FIX" if v.verification_mode == "practice-probe"
                        else "FULL-DRILL FIX")
                lines.append(f"           {mode} VERIFIED: fresh signed detector + response "
                             f"evidence is bound to action contract {v.contract_id}.")
            if v.remediation:
                lines.append(f"           remediated by {v.remediation.module} in "
                             f"{v.remediation_latency:.2f}s — \"{v.remediation.message}\"")
                if (v.remediation.module == "Adversary Combat"
                        and (v.remediation.details or {}).get(
                            "postcondition_verified"
                        ) is True):
                    lines.append(
                        "           COMBAT CLOSURE VERIFIED: the exact file/process/"
                        "network postcondition was checked after action."
                    )
            else:
                lines.append(f"           not remediated — the {v.catch.severity.label} "
                             "detection did not produce a correlated, successful SOAR action "
                             "inside this run's evidence window.")
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
    lines.append(f"   Detection coverage : {det_caught}/{len(detection)}  "
                 f"({(det_caught / len(detection) * 100 if detection else 0):.0f}%)   "
                 "— Initial Access / Persistence / Exfiltration-style steps only")
    lines.append(f"   Response success   : {det_remediated}/{det_caught} detected threat(s)  "
                 f"({(det_remediated / det_caught * 100 if det_caught else 0):.0f}%)")
    actionable = lifecycle["actionable_classes"]
    applied = lifecycle["actions_applied"]
    verified = lifecycle["verified_closures"]
    lines.append(f"   Action contracts   : {applied}/{actionable} unique gap class(es) applied  "
                 f"({(applied / actionable * 100 if actionable else 0):.0f}%)")
    lines.append(f"   Verified closure   : {verified}/{actionable} unique gap class(es)  "
                 f"({(verified / actionable * 100 if actionable else 0):.0f}%)")
    if verified_upgrades:
        lines.append(f"   Detector fixes proven by rerun: {verified_upgrades}  "
                     "(signed Purple Guard evidence + contract verification)")
    if findings_resolved:
        lines.append(f"   Drill findings closed: {findings_resolved}  "
                     "(authenticated action + verified postcondition or fresh rerun proof; "
                     "expiry/future misses reopen)")
    resilience = [v for v in verdicts if v.category == "resilience"]
    if resilience:
        fps = sum(1 for v in resilience if v.catch)
        lines.append(f"   Resilience check   : {'FAIL — false positive(s), see above' if fps else 'PASS — no false alert'}")
    unmon = [v for v in verdicts if v.category == "unmonitored"]
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


def _write_report(data_dir: Path, history: dict, verdicts: List[StepVerdict], text: str,
                  basename: str = "shark_aar") -> None:
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
    det_remediated = sum(1 for v in detection if v.remediation)
    verified_upgrades = sum(
        1 for v in detection if v.finding_resolved and v.verification_catch)
    payload = {
        "run_id": history.get("run_id"),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "steps_run": n,
        "detected": caught,               # raw count, all categories — kept for backward compat
        "remediated": remediated,
        "findings_resolved": findings_resolved,
        "actionable_finding_classes": lifecycle["actionable_classes"],
        "action_contracts_applied": lifecycle["actions_applied"],
        "verified_closures": lifecycle["verified_closures"],
        "verified_closure_rate": (
            lifecycle["verified_closures"] / lifecycle["actionable_classes"]
            if lifecycle["actionable_classes"] else 0.0
        ),
        "detection_steps": len(detection),      # steps where a detector SHOULD fire
        "detection_caught": det_caught,
        "detection_remediated": det_remediated,
        "remediation_eligible": det_caught,
        "response_success_rate": (det_remediated / det_caught if det_caught else 0.0),
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
                "verification_detected_by": (
                    v.verification_catch.module if v.verification_catch else None
                ),
                "verification_detect_latency_s": v.verification_latency,
                "remediated": v.remediation is not None,
                "remediated_by": v.remediation.module if v.remediation else None,
                "remediate_latency_s": v.remediation_latency,
                "remediate_message": v.remediation.message if v.remediation else None,
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
    for d in _report_dirs(data_dir):
        d.mkdir(parents=True, exist_ok=True)
        # These fixed files drive review and remediation authorization.  A
        # failed write must be visible to the caller; silently keeping a stale
        # prior run creates a dangerous display/action mismatch.
        _atomic_write_text(d / f"{basename}.txt", text)
        _atomic_write_text(d / f"{basename}.json", encoded_payload)

    # Keep a TIMESTAMPED archive so the Red Team console's History tab can list
    # previous reports (the fixed files above are overwritten every run).
    try:
        hist_dir = Path(data_dir) / "aar_history"
        hist_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        _atomic_write_text(hist_dir / f"{basename}_{stamp}.txt", text)
        _atomic_write_text(hist_dir / f"{basename}_{stamp}.json", encoded_payload)
        _prune_report_history(hist_dir, basename)
    except Exception:
        pass


def generate_aar(data_dir: Optional[Path] = None, settle_seconds: float = 0.0,
                 window: float = 3600.0, history_name: str = "shark_history.json",
                 stage_category: Optional[dict] = None, title: str = "SHARK ATTACK",
                 report_basename: str = "shark_aar") -> str:
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
    cfg = Config.load()
    data_dir = Path(data_dir or cfg.data_dir)
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
    if not history.get("steps"):
        return "Last run recorded zero steps — nothing to report."

    recorder = FlightRecorder(cfg.db_path)
    try:
        run_start = min(s["ts_start"] for s in history["steps"])
        # events_in_window() queries by time range directly — no row-count cap,
        # so drills run long before the current session won't be silently empty
        # because newer events pushed them out of recent(2000).
        events = recorder.events_in_window(run_start - 5, run_start + window)
    finally:
        recorder.close()

    verdicts = evaluate(history, events, stage_category)
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
    _write_report(data_dir, history, verdicts, text, report_basename)
    return text


if __name__ == "__main__":
    print(generate_aar())
