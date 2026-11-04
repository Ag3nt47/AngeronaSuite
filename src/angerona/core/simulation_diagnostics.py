"""Read-only, report-bound explanations of simulation evidence and repair leads.

The saved report remains authoritative. This projection grants no trust,
response, mutation, closure or execution authority, and never guesses a cause.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat


SCHEMA = "angerona.simulation-diagnostics.v1"
MAX_ROWS = 512
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_BASENAMES = {"red_team": "redteam_aar", "shark": "shark_aar"}
_PRODUCER_AREAS = {
    "YARA Scanner": "src/angerona/modules/yara_scanner.py",
    "Purple Remediation Guard": "src/angerona/modules/purple_guard.py",
    "Process Monitor": "src/angerona/modules/process_monitor.py",
    "File Integrity Monitor": "src/angerona/modules/file_integrity.py",
}
_REPAIRS = {
    "coverage.incomplete-run": (
        "The authenticated report withholds coverage credit for this run.", "coverage-review",
        ("Review the reported readiness/cancellation phase and collector coverage, then rerun the exact profile.",),
        ("src/angerona/shark/simulation_session.py", "src/angerona/shark/run_manifest.py")),
    "detection.observation-only": (
        "A sensor observation exists; this row has no credited native analytic or simulation validation.", "source-review",
        ("Compare the admitted technique contract with the originating detector's evidence and AAR mapping.",
         "Add or repair the specific detector/contract only after reproducing the gap; rerun to verify it."),
        ("src/angerona/shark/aar_report.py", "src/angerona/shark/simulation_session.py")),
    "detection.not-credited": (
        "This saved row contains no credited analytic detection.", "coverage-review",
        ("Inspect the originating collector and its retained coverage/loss records for this run.",
         "The false flag alone does not identify disabled policy, queue loss or a scanner timing defect."),
        ("src/angerona/shark/aar_report.py", "src/angerona/shark/simulation_session.py")),
    "detection.compatibility-only": (
        "Compatibility catch credit is present without a typed native or simulation analytic plane.", "source-review",
        ("Review the exact original event and migrate its producer/verifier mapping; do not invent native credit.",),
        ("src/angerona/shark/aar_report.py",)),
    "response.not-reported": (
        "Detection is credited, but this row reports no response action or verified containment.", "configuration-review",
        ("Check whether response was requested and currently authorized, then inspect admission/queue diagnostics.",
         "Do not enable broader policy merely to make a test pass."),
        ("src/angerona/modules/adversary_combat.py", "src/angerona/shark/simulation_session.py")),
    "response.not-applied": (
        "A response was reported, but application and exact containment were not verified.", "source-review",
        ("Inspect the exact action's retained admission/result and target identity; reproduce its reported refusal.",),
        ("src/angerona/modules/adversary_combat.py", "src/angerona/core/remediation_log.py")),
    "response.postcondition-unverified": (
        "An applied response is reported, but the exact target containment postcondition is unverified.", "source-review",
        ("Check the original trigger, exact target identity, committed action receipt and fresh postcondition.",
         "File disappearance or cleanup is not containment proof."),
        ("src/angerona/shark/aar_report.py", "src/angerona/modules/adversary_combat.py")),
    "evidence.inconsistent": (
        "The saved row's evidence flags are inconsistent; this view withholds a pass/fail conclusion.", "source-review",
        ("Preserve the original report and inspect its producer/verifier contract before rerunning.",),
        ("src/angerona/shark/aar_report.py",)),
    "verified.selected-evidence": (
        "This saved row credits analytic detection and exact containment; this is historical simulation evidence.", "none", (), ()),
    "category.unscored": (
        "This category is not a scored positive detection/response check.", "none", (), ()),
}


class SimulationDiagnosticsError(ValueError):
    """Missing, stale, unauthenticated or unsupported diagnostic evidence."""


def _text(value, limit, omitted):
    if type(value) is not str:
        return ""
    # Plain data only; the GUI must also use plain-text widgets.
    original_length = len(value)
    value = "".join(char for char in value if char in "\n\t" or ord(char) >= 32)
    omitted[0] += original_length - len(value)
    omitted[0] += max(0, len(value) - limit)
    return value[:limit]


def _check_expected(value, expected, label):
    if expected is not None and (type(value) is not type(expected) or value != expected):
        raise SimulationDiagnosticsError("Saved report does not match the expected " + label)


def _bounded_member(path, limit):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400
            or not 0 < info.st_size <= limit):
        raise SimulationDiagnosticsError("Diagnostic report member is redirected, nonordinary or outside its size bound")


def _active_profile_key(directory):
    """Read an existing key only from the selected active verification profile."""
    from angerona.core.data_paths import resolve_data_dir

    root = Path(directory).resolve(strict=True)
    active_root = resolve_data_dir().resolve(strict=True)
    if root != active_root or not root.is_dir():
        raise SimulationDiagnosticsError("Report directory differs from the active verification profile")
    for node in (*reversed(root.parents), root):
        info = node.lstat()
        if node.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise SimulationDiagnosticsError("Report profile has a redirected identity")
    key_path = root / "bus.key"
    _bounded_member(key_path, 128)
    descriptor = os.open(key_path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                         | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        held = os.fstat(descriptor)
        named = key_path.lstat()
        if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
                or getattr(held, "st_file_attributes", 0) & 0x400
                or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                or not 0 < held.st_size <= 128):
            raise SimulationDiagnosticsError("Verification key identity is unavailable")
        raw = os.read(descriptor, 129)
        after = os.fstat(descriptor)
        current = key_path.lstat()
        if (len(raw) != held.st_size or len(raw) > 128
                or (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)):
            raise SimulationDiagnosticsError("Verification key changed during the read")
    finally:
        os.close(descriptor)
    try:
        encoded = raw.decode("ascii").strip()
        if len(encoded) != 64 or re.fullmatch(r"[0-9a-fA-F]{64}", encoded) is None:
            raise ValueError("Unsupported key encoding")
        key = bytes.fromhex(encoded)
    except (UnicodeError, ValueError) as exc:
        raise SimulationDiagnosticsError("Existing verification key is malformed") from exc
    return root, key


def load_authenticated_handoff(data_dir, *, report_kind, expected_run_id=None,
                               expected_report_sha256=None, expected_head_sha256=None,
                               expected_sequence=None):
    """Load current signed bytes without rerunning sensors or a released lease.

    Uses the active profile's existing verification key. Arbitrary profile/key
    replacement is deliberately unavailable. The coordination lock is the only
    scratch admission; settings, evidence and policies are never rewritten.
    """
    from angerona.core import report_attest
    from angerona.shark import aar_report as aar

    if type(report_kind) is not str or report_kind not in _BASENAMES:
        raise SimulationDiagnosticsError("Unsupported report kind")
    for value in (expected_report_sha256, expected_head_sha256):
        if value is not None and (type(value) is not str or not _HASH.fullmatch(value)):
            raise SimulationDiagnosticsError("Expected report digest is invalid")
    if expected_run_id is not None and (type(expected_run_id) is not str or not 1 <= len(expected_run_id) <= 160):
        raise SimulationDiagnosticsError("Expected run identity is invalid")
    if expected_sequence is not None and (type(expected_sequence) is not int or expected_sequence < 1):
        raise SimulationDiagnosticsError("Expected report sequence is invalid")
    root, key = _active_profile_key(data_dir)
    basename = _BASENAMES[report_kind]
    with aar.ExclusiveFileLease(root / (basename + ".writer.lock"), existing_only=True):
        for suffix in (".txt", ".json", ".head.json"):
            _bounded_member(root / (basename + suffix), MAX_REPORT_BYTES)
        _bounded_member(root / (basename + ".heads.jsonl"), MAX_JOURNAL_BYTES)
        head, text_bytes, report_bytes, head_bytes = aar._read_bound_report_bundle(root, basename, verification_key=key)
        journal = aar._load_head_journal(root / (basename + ".heads.jsonl"), basename, verification_key=key)
        if not journal:
            raise SimulationDiagnosticsError("Authenticated report journal is missing")
        record, record_bytes, saved_text, saved_report, saved_head = journal[-1]
        if (saved_text, saved_report, saved_head) != (text_bytes, report_bytes, head_bytes):
            raise SimulationDiagnosticsError("Current report and journal head disagree")
        payload = json.loads(report_bytes.decode("utf-8"))
        if (type(payload) is not dict or report_attest.verify(payload, key=key) != "ok"
                or payload.get("report_kind") != report_kind
                or payload.get("report_basename") != basename
                or type(head.get("sequence")) is not int or head["sequence"] < 1
                or type(head.get("run_id")) is not str or not 1 <= len(head["run_id"]) <= 160):
            raise SimulationDiagnosticsError("Report kind or JSON authentication is unavailable")
        result = aar.AARReportResult(text=text_bytes.decode("utf-8"), run_id=head["run_id"],
            report_kind=report_kind, report_basename=basename,
            report_sha256=hashlib.sha256(report_bytes).hexdigest(),
            head_sha256=hashlib.sha256(head_bytes).hexdigest(), sequence=head["sequence"],
            text_bytes=text_bytes, report_bytes=report_bytes, head_bytes=head_bytes,
            journal_record_sha256=hashlib.sha256(record_bytes).hexdigest(),
            journal_record_bytes=record_bytes, report_directory=root)
    # The independent handoff check reacquires the writer lease; never nest it.
    aar.verified_aar_handoff_text(result, verification_key=key)
    _check_expected(result.run_id, expected_run_id, "run")
    _check_expected(result.report_sha256, expected_report_sha256, "report digest")
    _check_expected(result.head_sha256, expected_head_sha256, "head digest")
    _check_expected(result.sequence, expected_sequence, "sequence")
    return result


def _row(verdict, index, eligible, omitted):
    raw_category = verdict.get("category")
    category = _text(raw_category, 32, omitted)
    score_category = raw_category if type(raw_category) is str else None
    flags = ("observed", "native_analytic_detected", "simulation_validated", "caught",
             "response_action_reported", "response_action_applied", "target_containment_verified")
    valid = all(type(verdict.get(name)) is bool for name in flags)
    native = verdict.get("native_analytic_detected") is True
    simulation = verdict.get("simulation_validated") is True
    detected = native or simulation
    contained = verdict.get("target_containment_verified") is True
    reported = verdict.get("response_action_reported") is True
    applied = verdict.get("response_action_applied") is True
    detection, response, status = "inconclusive", "inconclusive", "inconclusive"
    if not eligible:
        code = "coverage.incomplete-run"
    elif score_category in {"resilience", "informational", "unmonitored"}:
        code, detection, response, status = "category.unscored", "unscored", "unscored", "unscored"
    elif (score_category != "detection" or not valid or (contained and (not detected or not reported or not applied))
            or (detected and verdict["caught"] is not True) or (applied and not reported)):
        code = "evidence.inconsistent"
    elif not detected:
        code = ("detection.compatibility-only" if verdict["caught"] else
                "detection.observation-only" if verdict["observed"] else "detection.not-credited")
        if code != "detection.compatibility-only":
            detection, status = "fail", "fail"
    else:
        detection = "pass"
        if contained:
            code, response, status = "verified.selected-evidence", "pass", "pass"
        else:
            code = ("response.postcondition-unverified" if applied else
                    "response.not-applied" if reported else "response.not-reported")
            response, status = "fail", "fail"
    reason, fix_kind, steps, areas = _REPAIRS[code]
    evidence = []
    for name in flags:
        value = verdict.get(name)
        evidence.append(name + ": " + (str(value).lower() if type(value) is bool else "unavailable"))
    for field in ("observed_by", "native_analytic_detected_by", "simulation_validated_by",
                  "containment_reason", "verification_error", "response_action_message"):
        value = _text(verdict.get(field), 1024, omitted)
        if value:
            evidence.append(field + ": " + value)
    source_areas = list(areas)
    if fix_kind != "none":
        for field in ("observed_by", "native_analytic_detected_by", "simulation_validated_by"):
            producer = verdict.get(field)
            area = _PRODUCER_AREAS.get(producer) if type(producer) is str else None
            if area is not None and area not in source_areas:
                source_areas.append(area)
    return {"index": index, "stage": _text(verdict.get("stage"), 240, omitted),
        "technique": _text(verdict.get("technique"), 240, omitted), "category": category,
        "detection_status": detection, "response_status": response, "status": status,
        "reason_code": code, "reason": reason, "evidence": evidence,
        "next_steps": list(steps), "source_areas": source_areas, "fix_kind": fix_kind,
        "fix_status": "none" if fix_kind == "none" else "not-applied",
        "identity_scope": "Report-bound verdict ordinal; saved row does not supply artifact/action identity"}


def diagnostics_for_handoff(handoff):
    """Project only exact authenticated current bytes; never accept an auth flag."""
    from angerona.core import report_attest
    from angerona.shark import aar_report as aar

    if (type(handoff) is not aar.AARReportResult or type(handoff.report_bytes) is not bytes
            or not 0 < len(handoff.report_bytes) <= MAX_REPORT_BYTES):
        raise SimulationDiagnosticsError("Unsupported or oversized immutable report handoff")
    if (type(handoff.run_id) is not str or not 1 <= len(handoff.run_id) <= 160
            or type(handoff.report_kind) is not str or handoff.report_kind not in _BASENAMES
            or type(handoff.report_basename) is not str
            or handoff.report_basename != _BASENAMES[handoff.report_kind]
            or type(handoff.sequence) is not int or handoff.sequence < 1
            or any(type(value) is not str or not _HASH.fullmatch(value) for value in (
                handoff.report_sha256, handoff.head_sha256, handoff.journal_record_sha256))):
        raise SimulationDiagnosticsError("Immutable report identity has malformed literal fields")
    _root, key = _active_profile_key(handoff.report_directory)
    aar.verified_aar_handoff_text(handoff, verification_key=key)
    report = json.loads(handoff.report_bytes.decode("utf-8"))
    head = json.loads(handoff.head_bytes.decode("utf-8"))
    if (type(report) is not dict or report_attest.verify(report, key=key) != "ok"
            or type(report.get("run_id")) is not str or report["run_id"] != handoff.run_id
            or report.get("report_kind") != handoff.report_kind
            or report.get("report_basename") != _BASENAMES[handoff.report_kind]
            or type(head) is not dict or type(head.get("sequence")) is not int
            or head["sequence"] != handoff.sequence):
        raise SimulationDiagnosticsError("Signed diagnostic report contract is unavailable")
    verdicts = report.get("verdicts")
    if type(verdicts) is not list or any(type(row) is not dict for row in verdicts[:MAX_ROWS]):
        raise SimulationDiagnosticsError("Saved verdict rows are unavailable")
    eligible = (report.get("coverage_score_eligible") is True
        and ("diagnostic_only" not in report or report["diagnostic_only"] is False))
    omitted = [0]
    rows = [_row(row, index + 1, eligible, omitted) for index, row in enumerate(verdicts[:MAX_ROWS])]
    counts = Counter(row["status"] for row in rows)
    outcome = "failing" if eligible and counts["fail"] else (
        "passing" if eligible and counts["pass"] and not counts["inconclusive"] and len(verdicts) <= MAX_ROWS
        and report.get("outcome") == "verified" else "inconclusive")
    result = {"schema": SCHEMA, "run_id": handoff.run_id, "report_kind": handoff.report_kind,
        "report_sha256": handoff.report_sha256, "head_sha256": handoff.head_sha256, "sequence": handoff.sequence,
        "authentication": "verified", "report_state": "complete" if eligible else "diagnostic",
        "coverage_score_eligible": eligible, "overall_status": outcome,
        "saved_outcome": _text(report.get("outcome"), 64, omitted),
        "scope": "Historical authenticated report projection; detection and response separate; no fresh host or policy proof",
        "counts": {key: counts[key] for key in ("pass", "fail", "inconclusive", "unscored")},
        "reasons": dict(Counter(row["reason_code"] for row in rows)), "rows": rows,
        "omitted_rows": max(0, len(verdicts) - MAX_ROWS), "omitted_text_characters": omitted[0],
        "fixes_applied_by_this_view": False, "response_authorized": False}
    if len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode("ascii")) > MAX_OUTPUT_BYTES:
        raise SimulationDiagnosticsError("Diagnostic projection exceeds its output budget")
    return result


def load_report_diagnostics(data_dir, **expected):
    return diagnostics_for_handoff(load_authenticated_handoff(data_dir, **expected))


def live_debug_summary(diagnostics):
    """Compact advisory admission for the existing opt-in read-only harness."""
    if type(diagnostics) is not dict or diagnostics.get("schema") != SCHEMA:
        raise SimulationDiagnosticsError("Unexpected diagnostic projection")
    result = {key: diagnostics[key] for key in ("schema", "run_id", "report_kind", "report_sha256",
        "head_sha256", "sequence", "overall_status", "coverage_score_eligible", "counts", "reasons", "omitted_rows")}
    result["advisory_only"] = True
    text = json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    if len(text) > 8192:
        raise SimulationDiagnosticsError("Live diagnostic summary exceeds the existing endpoint budget")
    return text
