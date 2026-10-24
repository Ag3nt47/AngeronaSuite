"""Offscreen operator clickthrough with real Red Team detector/response workers."""

from __future__ import annotations

import os
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import psutil
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox


_OS_WITNESS = r"""
import hashlib
import json
import os
import sys
from pathlib import Path

import psutil

request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
quarantine = Path(request["quarantine_root"])
verify_digest = bool(request.get("verify_digest", True))
markers = []
for expected in request["markers"]:
    source = Path(expected["source"])
    candidates = []
    matches = []
    read_errors = []
    for candidate in quarantine.rglob(source.name):
        if candidate.is_file() and not candidate.is_symlink():
            candidates.append(str(candidate))
            if verify_digest:
                try:
                    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
                except OSError as exc:
                    read_errors.append({"path": str(candidate), "error": str(exc)})
                else:
                    if digest == expected["sha256"]:
                        matches.append(str(candidate))
    markers.append({
        "source": str(source),
        "source_absent": not os.path.lexists(source),
        "sha256": expected["sha256"],
        "candidate_quarantines": sorted(candidates),
        "matching_quarantines": sorted(matches),
        "read_errors": read_errors,
    })

processes = []
for expected in request["processes"]:
    pid = int(expected["pid"])
    token = str(expected["token"])
    raw_birth = expected.get("birth")
    birth = float(raw_birth) if isinstance(raw_birth, (int, float)) else None
    original_alive = False
    status = "birth_unrecorded" if birth is None else "absent"
    current_birth = None
    if birth is not None:
        try:
            process = psutil.Process(pid)
            current_birth = float(process.create_time())
            same_birth = abs(current_birth - birth) <= 0.01
            original_alive = bool(process.is_running() and same_birth)
            status = "original_alive" if original_alive else "pid_reused_or_exited"
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            status = "access_denied"
    processes.append({"pid": pid, "token": token,
                      "expected_birth": birth, "observed_birth": current_birth,
                      "original_alive": original_alive, "status": status})

output = {
    "schema": "angerona.gui-live-os-witness.v1",
    "run_id": request["run_id"],
    "verify_digest": verify_digest,
    "markers": markers,
    "processes": processes,
}
Path(sys.argv[2]).write_text(json.dumps(output, indent=2), encoding="utf-8")
"""


@pytest.fixture
def isolated_root() -> Path:
    parent = Path(__file__).resolve().parents[1] / ".tmp"
    parent.mkdir(exist_ok=True)
    # Retain each isolated run for post-mortem review when an external witness
    # or authenticated report disagrees. The root is confined to ignored .tmp.
    yield Path(tempfile.mkdtemp(prefix="redteam_gui_live_", dir=parent))


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _os_witness_accepts(
    witness: dict, *, expected_markers: int, require_process: bool,
    require_digest: bool = True,
) -> bool:
    markers = witness.get("markers", [])
    processes = witness.get("processes", [])
    return bool(
        len(markers) == expected_markers
        and all(row["source_absent"] for row in markers)
        and all(row["candidate_quarantines"] for row in markers)
        and (
            not require_digest
            or (
                witness.get("verify_digest") is True
                and all(row["matching_quarantines"] for row in markers)
                and not any(row["read_errors"] for row in markers)
            )
        )
        and (not require_process or processes)
        and all(
            isinstance(row.get("expected_birth"), (int, float))
            and row["expected_birth"] > 0
            for row in processes
        )
        and all(row["status"] != "access_denied" for row in processes)
        and not any(row["original_alive"] for row in processes)
    )


def _witness_runtime_snapshot(combat, bus) -> dict:
    """Observe fixed policy fields and delivery counters without host I/O."""
    policy = combat.policy()
    snapshots = {
        "journal_error_present": bool(getattr(combat, "_journal_error", "")),
        "mutation_blocked": getattr(combat, "_mutation_blocked", False) is True,
        "journal_saturated": getattr(combat, "_journal_saturated", False) is True,
        "policy": {
            key: getattr(policy, key, None) if type(getattr(policy, key, None)) is bool else None
            for key in ("enabled", "block_network", "quarantine_files", "isolate_host", "activate_honeypots")
        },
        "submit_current": [],
    }
    for key, allowed in (
        ("mode", {"contain", "aggressive", "maximum"}),
        ("process_action", {"none", "suspend", "terminate"}),
    ):
        value = getattr(policy, key, None)
        snapshots["policy"][key] = value if value in allowed else "other"
    severity = getattr(getattr(policy, "min_severity", None), "name", "")
    snapshots["policy"]["min_severity"] = severity if severity in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"} else "other"
    for row in bus.subscriber_metrics():
        if row.name.endswith(".submit_current"):
            snapshots["submit_current"].append({
                key: value if type(value := getattr(row, key, None)) is int and value >= 0 else None
                for key in ("deliveries", "failures", "budget_violations")
            })
    snapshots["submit_current_count"] = len(snapshots["submit_current"])
    snapshots["submit_current"] = snapshots["submit_current"][:4]
    return snapshots


def _response_failure_diagnostic(combat, bus) -> dict:
    """Failure-only memory view; no host reads, authority or causal conclusion."""
    messages = {
        "combat journal custody is unavailable": "journal_custody_unavailable",
        "combat journal custody was lost during the transaction": "journal_custody_lost",
        "combat journal identity changed during the transaction": "journal_identity_changed",
        "combat journal object is unsafe": "journal_object_unsafe",
        "combat journal is unreadable": "journal_unreadable",
        "combat journal changed while being read": "journal_changed_during_read",
        "combat journal append failed": "journal_append_failed",
        "combat journal append was incomplete": "journal_append_incomplete",
        "combat journal changed during append": "journal_changed_during_append",
        "combat journal record schema is invalid": "journal_record_schema_invalid",
        "combat journal has an incomplete terminal line": "journal_terminal_incomplete",
        "combat journal interior checkpoint changed": "journal_interior_changed",
        "combat journal terminal checkpoint changed": "journal_terminal_changed",
        "combat journal transaction verification failed": "journal_transaction_verification_failed",
        "combat journal checkpoint is unavailable": "journal_checkpoint_unavailable",
        "combat journal terminal capacity reservation is unavailable": "journal_capacity_unavailable",
        "combat journal byte budget exceeded": "journal_byte_budget",
        "combat journal record budget exceeded": "journal_record_budget",
        "combat journal key custody failed": "journal_key_custody_failed",
        "combat journal key is unreadable": "journal_key_unreadable",
        "recovery rollback anchor is unavailable": "recovery_anchor_unavailable",
        "recovery rollback anchor did not advance": "recovery_anchor_not_advanced",
        "combat journal rollback or incomplete anchor transaction detected": "recovery_rollback_detected",
    }
    exception_types = {
        "JournalIntegrityError", "PermissionError", "FileNotFoundError", "FileExistsError",
        "OSError", "RuntimeError", "ValueError", "TypeError", "TimeoutError",
    }

    def safe_error(value):
        result = {"code": "unavailable", "exception_type": "unavailable"}
        if type(value) is not str:
            return result
        if not value:
            result["code"] = "none"
            return result
        if len(value) > 1024:
            result["code"] = "oversized_redacted"
            return result
        kind, separator, message = value.partition(": ")
        if separator and kind in exception_types:
            result["exception_type"] = kind
        else:
            message = value
        result["code"] = messages.get(message, "other_redacted")
        if message.startswith("commit failed: "):
            kind = message.removeprefix("commit failed: ")
            if kind in exception_types:
                result.update(code="commit_failed", exception_type=kind)
        for prefix, code in (
            ("journal schema failure at line ", "journal_schema_line"),
            ("journal integrity failure at line ", "journal_integrity_line"),
            ("broken journal record at line ", "journal_broken_record_line"),
            ("unsigned journal tail at line ", "journal_unsigned_tail_line"),
            ("journal resource/schema limit at line ", "journal_resource_line"),
        ):
            if message.startswith(prefix):
                line = message[len(prefix):]
                if line.isascii() and line.isdecimal() and len(line) <= 5 and 0 < int(line) <= 32768:
                    result.update(code=code, line=int(line))
        return result

    result = {
        "schema": "angerona.gui-live-response-failure-diagnostic.v1",
        "diagnostic_only": True, "cause_established": False,
        "current_store_error": safe_error(getattr(combat, "_journal_error", None)),
        "journal_cache": {"state": "busy_or_unavailable"},
        "retained_event_window": {"state": "unavailable", "limit": 128, "run_bound": False},
    }
    try:
        lock = getattr(combat, "_receipt_lock", None)
        acquired = lock is not None and lock.acquire(blocking=False)
        if acquired:
            try:
                records = getattr(combat, "_journal_cache_records", None)
                if type(records) is list:
                    rows = []
                    for record in records[-32:]:
                        if type(record) is not dict:
                            continue
                        def fixed(value, choices):
                            return value if type(value) is str and len(value) <= 64 and value in choices else "other"
                        rows.append({
                            "phase": fixed(record.get("record_type"), {"intent", "commit", "failure", "orphan", "undo_intent", "undo_commit", "undo_failure"}),
                            "action": fixed(record.get("action"), {"quarantine_file", "terminate_process", "suspend_process", "isolate_program", "block_remote_ip", "isolate_host", "activate_honeypots"}),
                            "error": safe_error(record.get("error")),
                        })
                    result["journal_cache"] = {
                        "state": "memory_view_unverified", "limit": 32,
                        "rows": rows, "older_rows_omitted": max(0, len(records) - 32),
                    }
                else:
                    result["journal_cache"] = {"state": "cache_unavailable"}
            finally:
                lock.release()
    except Exception:
        result["journal_cache"] = {"state": "snapshot_unavailable"}
    try:
        events = bus.recent(128)
        if type(events) is not list:
            raise TypeError("unsupported diagnostic event view")
        reasons = {"windows_sharing_conflict", "marker_custody_handoff_failed", "marker_mutation_or_terminal_failed"}
        counts = {}
        for event in events[:128]:
            if getattr(event, "module", None) != "Adversary Combat":
                continue
            details = getattr(event, "details", None)
            reason = details.get("response_failure_reason") if type(details) is dict else None
            if type(reason) is str and len(reason) <= 64 and reason in reasons:
                counts[reason] = counts.get(reason, 0) + 1
        result["retained_event_window"] = {
            "state": "memory_view_unverified", "limit": 128,
            "rows_sampled": min(128, len(events)), "limit_reached": len(events) >= 128,
            "failure_counts": counts, "run_bound": False,
        }
    except Exception:
        pass
    return result




def _os_witness_failure_summary(
    witness: dict, *, phase: str, run_index: int, expected_markers: int,
    require_process: bool, require_digest: bool, report: dict,
    settled: dict, combat: dict,
) -> str:
    """Bounded CI diagnostics; paths, tokens, report text and errors stay local."""
    markers = witness.get("markers", [])
    processes = witness.get("processes", [])
    failed_markers = []
    for row in markers:
        if (
            not row.get("source_absent") or not row.get("candidate_quarantines")
            or (require_digest and (
                not row.get("matching_quarantines") or row.get("read_errors")
            ))
        ):
            failed_markers.append({
                "basename": Path(str(row.get("source", ""))).name[:128],
                "source_absent": row.get("source_absent") is True,
                "candidate_count": len(row.get("candidate_quarantines", [])),
                "digest_match_count": len(row.get("matching_quarantines", [])),
                "read_error_count": len(row.get("read_errors", [])),
            })

    def count(value):
        return value if type(value) is int and value >= 0 else None

    states = {"absent", "pid_reused_or_exited", "original_alive", "birth_unrecorded", "access_denied"}
    process_rows = [{
        "index": index,
        "birth_recorded": isinstance(row.get("expected_birth"), (int, float)),
        "birth_positive": isinstance(row.get("expected_birth"), (int, float)) and row["expected_birth"] > 0,
        "original_alive": row.get("original_alive") is True,
        "status": row.get("status") if row.get("status") in states else "other",
    } for index, row in enumerate(processes[:16])]
    outcome = report.get("outcome")
    taxonomy = report.get("evidence_taxonomy", {})
    response = taxonomy.get("successful_response", {})
    combat_states = {"RECOVERY REQUIRED", "JOURNAL FULL", "DISABLED", "STARTING", "QUEUE FULL", "ARMED"}
    decision_codes = (
        "waiting", "generation_discarded", "startup_expired", "below_threshold",
        "missing_contract", "integrity_failed", "queue_saturated", "queued",
        "recovery_required", "policy_disabled", "not_actionable", "invalid_contract",
        "executed", "no_eligible_target", "file_content_changed",
    )
    decision_counts = combat.get("counts", {})
    summary = {
        "schema": "angerona.gui-live-witness-failure.v1",
        "phase": phase, "run_index": run_index,
        "expected_marker_count": expected_markers, "marker_count": len(markers),
        "require_process": require_process, "require_digest": require_digest,
        "digest_verified": witness.get("verify_digest") is True,
        "source_present_count": sum(not row.get("source_absent") for row in markers),
        "missing_candidate_count": sum(not row.get("candidate_quarantines") for row in markers),
        "missing_digest_count": sum(not row.get("matching_quarantines") for row in markers),
        "read_error_count": sum(len(row.get("read_errors", [])) for row in markers),
        "failed_markers": failed_markers[:64],
        "failed_markers_omitted": max(0, len(failed_markers) - 64),
        "process_count": len(processes), "processes": process_rows,
        "processes_omitted": max(0, len(processes) - 16),
        "aar": {
            "outcome": outcome if outcome in {"verified", "partial", "failed", "inconclusive", "detection_only"} else "other",
            **{key: count(report.get(key)) for key in (
                "steps_run", "detected", "remediated", "response_actions_applied",
                "detection_response_actions_applied", "verified_closures",
            )},
            "denominator": count(taxonomy.get("denominator")),
            "successful_response_count": count(response.get("count")),
        },
        "settlement": {
            "pending": count(settled.get("pending")),
            "timed_out": settled.get("timed_out") if type(settled.get("timed_out")) is bool else None,
            "combat_ready": combat.get("ready") if type(combat.get("ready")) is bool else None,
            "combat_state": combat.get("state") if combat.get("state") in combat_states else "other",
            **{key: count(combat.get(key)) for key in (
                "queue_depth", "queue_pending", "queue_capacity", "queue_drops",
            )},
            "decision_counts": {key: count(decision_counts[key]) for key in decision_codes if key in decision_counts},
            "last_decision": combat.get("last_decision") if combat.get("last_decision") in decision_codes else "other",
        },
    }
    return json.dumps(summary, sort_keys=True)


def test_os_witness_rejects_uncontained_marker(isolated_root: Path) -> None:
    """Independent OS check rejects an AAR-like success without containment."""
    marker = isolated_root / "_redteam_negative_control.txt"
    body = b"ANGERONA RED TEAM inert negative control\n"
    marker.write_bytes(body)
    quarantine = isolated_root / "combat-quarantine"
    quarantine.mkdir()
    request = isolated_root / "negative-witness-input.json"
    output = isolated_root / "negative-witness-output.json"
    request.write_text(json.dumps({
        "run_id": "negative-control",
        "quarantine_root": str(quarantine),
        "markers": [{"source": str(marker),
                     "sha256": hashlib.sha256(body).hexdigest()}],
        "processes": [],
    }), encoding="utf-8")
    subprocess.run(
        [sys.executable, "-c", _OS_WITNESS, str(request), str(output)],
        check=True, capture_output=True, text=True, timeout=15.0,
    )
    witness = json.loads(output.read_text(encoding="utf-8"))
    assert witness["markers"][0]["source_absent"] is False
    assert witness["markers"][0]["matching_quarantines"] == []
    assert not _os_witness_accepts(
        witness, expected_markers=1, require_process=False,
    )
    marker.rename(quarantine / marker.name)
    subprocess.run(
        [sys.executable, "-c", _OS_WITNESS, str(request), str(output)],
        check=True, capture_output=True, text=True, timeout=15.0,
    )
    contained = json.loads(output.read_text(encoding="utf-8"))
    assert _os_witness_accepts(
        contained, expected_markers=1, require_process=False,
    )


def test_witness_failure_summary_keeps_reasons_without_private_values() -> None:
    summary_text = _os_witness_failure_summary(
        {
            "verify_digest": False,
            "markers": [{
                "source": str(Path("private-parent") / "inert-marker.txt"),
                "source_absent": True, "candidate_quarantines": [],
                "matching_quarantines": [],
                "read_errors": [{"path": "private-quarantine", "error": "private-error"}],
            }],
            "processes": [{
                "pid": 76543, "token": "private-token", "expected_birth": None,
                "observed_birth": 123456.789, "original_alive": False,
                "status": "access_denied",
            }],
        },
        phase="pre", run_index=1, expected_markers=36, require_process=True,
        require_digest=False,
        report={"outcome": "partial", "response_actions_applied": 0,
                "verified_closures": 0, "body": "private-report",
                "evidence_taxonomy": {"denominator": 37, "successful_response": {"count": 0}}},
        settled={"pending": 0, "timed_out": False},
        combat={"ready": True, "state": "ARMED", "reason": "private-reason",
                "counts": {"no_eligible_target": 37, "private-code": 1},
                "last_decision": "no_eligible_target"},
    )
    summary = json.loads(summary_text)
    assert summary["missing_candidate_count"] == 1
    assert summary["failed_markers"] == [{
        "basename": "inert-marker.txt", "source_absent": True,
        "candidate_count": 0, "digest_match_count": 0, "read_error_count": 1,
    }]
    assert summary["processes"] == [{
        "index": 0, "birth_recorded": False, "birth_positive": False,
        "original_alive": False, "status": "access_denied",
    }]
    assert summary["aar"]["outcome"] == "partial"
    assert summary["aar"]["response_actions_applied"] == 0
    assert summary["aar"]["successful_response_count"] == 0
    assert summary["settlement"]["pending"] == 0
    assert summary["settlement"]["timed_out"] is False
    assert summary["settlement"]["decision_counts"] == {"no_eligible_target": 37}
    assert all(private not in summary_text for private in (
        "private-parent", "private-quarantine", "private-error", "private-token",
        "private-report", "private-reason", "private-code", "76543", "123456.789",
    ))


def test_response_failure_diagnostic_redacts_private_values_without_host_reads() -> None:
    from types import SimpleNamespace

    private = "private-path-key-token"
    io_calls = []
    def forbidden(*_args, **_kwargs):
        io_calls.append("journal_io")
        raise AssertionError("diagnostics attempted host or journal I/O")

    combat = SimpleNamespace(
        _journal_error="combat journal custody is unavailable",
        _receipt_lock=threading.Lock(),
        _journal_cache_records=[
            {"record_type": "failure", "action": "quarantine_file", "target": private,
             "error": "JournalIntegrityError: combat journal custody is unavailable"},
            {"record_type": private, "action": private, "error": "PermissionError: " + private},
        ],
        _read_journal=forbidden, list_actions=forbidden,
    )
    class Bus:
        def recent(self, limit):
            assert limit == 128
            return [
                SimpleNamespace(module="Adversary Combat", details={
                    "response_failure_reason": "marker_custody_handoff_failed", "path": private}),
                SimpleNamespace(module="Adversary Combat", details={
                    "response_failure_reason": private}),
            ]

    result = _response_failure_diagnostic(combat, Bus())
    assert io_calls == [], "swallowed exceptions must not hide attempted journal I/O"
    assert result["cause_established"] is False
    assert result["current_store_error"]["code"] == "journal_custody_unavailable"
    assert result["journal_cache"]["rows"][0] == {
        "phase": "failure", "action": "quarantine_file",
        "error": {"code": "journal_custody_unavailable", "exception_type": "JournalIntegrityError"},
    }
    assert result["journal_cache"]["rows"][1]["error"] == {
        "code": "other_redacted", "exception_type": "PermissionError",
    }
    assert result["retained_event_window"]["failure_counts"] == {"marker_custody_handoff_failed": 1}
    assert result["retained_event_window"]["run_bound"] is False
    assert private not in json.dumps(result)


def test_response_failure_diagnostic_bounds_cache_and_never_waits_for_receipt_lock() -> None:
    from types import SimpleNamespace

    class Bus:
        def recent(self, limit):
            assert limit == 128
            return []

    lock = threading.Lock()
    combat = SimpleNamespace(_journal_error="secret" * 1000, _receipt_lock=lock,
                             _journal_cache_records=[{}] * 100)
    with lock:
        result = _response_failure_diagnostic(combat, Bus())
    assert result["journal_cache"]["state"] == "busy_or_unavailable"
    assert result["current_store_error"]["code"] == "oversized_redacted"
    result = _response_failure_diagnostic(combat, Bus())
    assert len(result["journal_cache"]["rows"]) == 32
    assert result["journal_cache"]["older_rows_omitted"] == 68
    assert "secret" not in json.dumps(result)




@pytest.mark.skipif(os.name != "nt", reason="Windows response clickthrough")
def test_mainwindow_arm_launch_and_deliver_signed_aar_twice(
    isolated_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two UI clicks reach signed AAR and independent OS response evidence."""
    monkeypatch.setenv("ANGERONA_DATA", str(isolated_root))
    monkeypatch.setenv("ANGERONA_DIAG_DIR", str(isolated_root / "diagnostics"))
    monkeypatch.setenv("ANGERONA_SOAR_RESPONSE_SCOPE", str(isolated_root / "drill-sandbox"))

    from angerona.core import report_attest
    from angerona.core.config import Config
    from angerona.core.drill_readiness import assess_drill_response
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.module_contract import build_capability_contract
    from angerona.core.module_manager import ModuleManager
    from angerona.core.storage import FlightRecorder
    from angerona.gui.main_window import MainWindow
    from angerona.gui.pages import AARDialog, SettingsDialog
    from angerona.modules.adversary_combat import AdversaryCombat
    from angerona.modules.process_monitor import ProcessMonitorModule
    from angerona.modules import purple_guard as purple_module
    from angerona.modules.purple_guard import PurpleGuard
    from angerona.modules.purple_guard import RedTeamValidationError, RedTeamValidationLease
    from angerona.shark.aar_report import AARReportResult, verified_aar_handoff_text
    from angerona.shark.red_team import INTENSITY_LEVELS, RedTeamEngine

    # Each pytest case already owns a unique retained root. Keep every
    # trace, AAR alias and independent witness below that root as well.
    case_evidence = isolated_root / "diagnostics" / "gui-live"
    case_evidence.mkdir(parents=True, exist_ok=True)
    trace_path = case_evidence / "bug_audit_gui_trace.jsonl"

    def trace(phase: str, **details: object) -> None:
        with trace_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "wall_time": time.time(), "phase": phase, **details,
            }, default=str) + "\n")

    trace("fixture_start", isolated_root=str(isolated_root))

    # Observe the exact subcheck that fails at marker enrollment. All wrapped
    # functions call their originals and return/raise unchanged; no gate is
    # bypassed. Thread-local capture confines diagnostics to the engine thread.
    diagnostic_local = threading.local()
    original_stat = Path.stat

    def diagnostic_stat(path: Path, *args: object, **kwargs: object):
        try:
            return original_stat(path, *args, **kwargs)
        except OSError as exc:
            if getattr(diagnostic_local, "active", False):
                diagnostic_local.stat_errors.append({
                    "path": str(path), "error": f"{type(exc).__name__}: {exc}",
                    "errno": exc.errno,
                    "winerror": getattr(exc, "winerror", None),
                })
            raise

    monkeypatch.setattr(Path, "stat", diagnostic_stat)

    def wrap_lease_helper(name: str) -> None:
        original = getattr(purple_module, name)

        def observed(*args: object, **kwargs: object):
            try:
                result = original(*args, **kwargs)
            except Exception as exc:
                if getattr(diagnostic_local, "active", False):
                    diagnostic_local.probes[name] = {
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                raise
            if getattr(diagnostic_local, "active", False):
                if name in {"_policy_identity", "validate_redteam_recorder"}:
                    expected = (
                        diagnostic_local.expected_policy
                        if name == "_policy_identity"
                        else diagnostic_local.expected_recorder
                    )
                    detail = {"matched_readiness": result == expected}
                elif name == "_runtime_targets_snapshot":
                    detail = {"contains_target": diagnostic_local.target in result}
                elif name == "_marker_path_identity":
                    detail = {"identity_valid": bool(result[1]),
                              "path": str(args[0])}
                else:
                    detail = {"result": bool(result)}
                diagnostic_local.probes[name] = detail
            return result

        monkeypatch.setattr(purple_module, name, observed)

    for helper_name in (
        "_runtime_targets_snapshot", "_target_identity_matches",
        "_validation_target_markers_safe", "_marker_path_identity",
        "_policy_identity", "validate_redteam_recorder",
    ):
        wrap_lease_helper(helper_name)

    original_register = RedTeamValidationLease.register_artifact_handle

    def diagnosed_register(
        lease: RedTeamValidationLease, path: Path, *, run_id: str,
    ) -> dict[str, object]:
        state = purple_module._lease_authority(lease)
        diagnostic_local.active = True
        diagnostic_local.target = state.target
        diagnostic_local.expected_policy = state.readiness.get("policy")
        diagnostic_local.expected_recorder = state.readiness.get("recorder_identity")
        diagnostic_local.probes = {}
        diagnostic_local.stat_errors = []
        try:
            return original_register(lease, path, run_id=run_id)
        except RedTeamValidationError as exc:
            try:
                from angerona.core.module_base import BaseModule

                modules = getattr(state.manager, "modules", {})
                snapshot = {
                    "run_id": run_id,
                    "path": str(path),
                    "error": str(exc),
                    "released": bool(state.released),
                    "artifact_custody_failed": bool(state.artifact_custody_failed),
                    "consumed": bool(state.consumed),
                    "bound_run_matches": run_id == state.bound_run_id,
                    "run_deadline_expired": time.monotonic() > state.run_deadline_monotonic,
                    "process_epoch_matches": state.process_epoch == purple_module._LEASE_PROCESS_EPOCH,
                    "manager_graph_matches": bool(
                        getattr(state.manager, "bus", None) is state.bus
                        and modules.get(state.module.name) is state.module
                        and modules.get("Process Monitor") is state.process_module
                    ),
                    "purple": BaseModule.operational_snapshot(state.module),
                    "purple_cycle": PurpleGuard.validation_cycle_snapshot(state.module),
                    "process": BaseModule.operational_snapshot(state.process_module),
                    "readiness_sensor_generation": state.readiness.get("sensor_generation"),
                    "readiness_sensor_cycle": state.readiness.get("sensor_cycle_serial"),
                    "readiness_process": state.readiness.get("process_sensor"),
                    "handoff_paths": sorted(state.artifact_handoffs or set()),
                    "helper_results": diagnostic_local.probes,
                    "stat_errors": diagnostic_local.stat_errors,
                    "stat_error_post_state": [
                        {
                            "source": item["path"],
                            "source_exists": os.path.lexists(item["path"]),
                            "quarantine_names": [
                                str(candidate)
                                for candidate in combat.quarantine_root.rglob(
                                    Path(item["path"]).name
                                )
                            ],
                        }
                        for item in diagnostic_local.stat_errors
                    ],
                }
                diagnostic_path = case_evidence / f"bug_audit_gui_lease_failure_{run_id}.json"
                diagnostic_path.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
            except Exception as diagnostic_exc:
                (case_evidence / f"bug_audit_gui_lease_failure_{run_id}.txt").write_text(
                    f"Diagnostic capture failed: {diagnostic_exc}", encoding="utf-8",
                )
            raise
        finally:
            diagnostic_local.active = False

    monkeypatch.setattr(RedTeamValidationLease, "register_artifact_handle", diagnosed_register)

    key_path = isolated_root / "bus.key"
    key_path.write_text("42" * 32, encoding="ascii")
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    config = Config(
        data_dir=isolated_root,
        autostart_enabled=False,
        eco_mode=False,
        blackbox_enabled=False,
        adversary_combat_enabled=False,
        adversary_combat_block_network=False,
        adversary_combat_isolate_host=False,
        adversary_combat_activate_honeypots=False,
        adversary_combat_quarantine_files=True,
        adversary_combat_process_action="terminate",
        adversary_combat_min_severity="MEDIUM",
        module_states={
            "Purple Remediation Guard": True,
            "Process Monitor": True,
            "Adversary Combat": False,
        },
    )
    recorder = FlightRecorder(config.db_path)
    bus = EventBus(ring_size=4096)
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    manager = ModuleManager(bus, config, recorder=recorder)
    guard = PurpleGuard(isolated_root)
    process = ProcessMonitorModule()
    combat = AdversaryCombat(data_root=isolated_root)
    assert combat.quarantine_root.parent == isolated_root
    for module in (guard, process, combat):
        module.bind(bus)
        module._angerona_contract = build_capability_contract(
            module,
            capability_id=f"angerona.builtin.{type(module).__module__.rsplit('.', 1)[-1]}",
            origin="builtin", trust="release", publisher="Angerona",
        )
        manager.modules[module.name] = module
    combat.bind_manager(manager)

    # Reduce only the inert probe's pauses; actual GUI, sensors, response,
    # authenticated recorder and AAR remain unmodified and live.
    monkeypatch.setitem(INTENSITY_LEVELS["Low"], "jitter", (0.0, 0.0))
    monkeypatch.setitem(INTENSITY_LEVELS["Low"], "noise", 0.0)
    marker_digests: dict[str, dict[str, str]] = {}
    marker_lock = threading.Lock()
    spawn_births: dict[tuple[int, str], float | None] = {}
    original_popen = subprocess.Popen

    def record_tagged_spawn(*args: object, **kwargs: object) -> subprocess.Popen:
        proc = original_popen(*args, **kwargs)
        command = args[0] if args else kwargs.get("args")
        if (
            isinstance(command, (list, tuple))
            and len(command) == 4
            and command[0] == sys.executable
            and tuple(command[1:3]) == ("-c", "import time; time.sleep(30)")
            and isinstance(command[3], str)
            and command[3].startswith("ANGERONA_REDTEAM_")
        ):
            try:
                birth = float(psutil.Process(proc.pid).create_time())
            except (psutil.Error, OSError, ValueError):
                birth = None
            with marker_lock:
                spawn_births[(int(proc.pid), command[3])] = birth
        return proc

    monkeypatch.setattr(subprocess, "Popen", record_tagged_spawn)
    original_marker = RedTeamEngine._marker

    def record_created_marker(engine: RedTeamEngine, name: str, body: str) -> Path:
        path = original_marker(engine, name, body)
        with marker_lock:
            marker_digests.setdefault(engine.run_id, {})[str(path)] = hashlib.sha256(
                body.encode("utf-8")
            ).hexdigest()
        return path

    monkeypatch.setattr(RedTeamEngine, "_marker", record_created_marker)

    app = _app()
    window = MainWindow(bus, recorder, manager, config)
    pulse_worker = window.system_pulse._sample_worker
    trace("mainwindow_constructed")
    window.show()
    app.processEvents()
    window.timer.stop()
    if window._ui_watchdog is not None:
        window._ui_watchdog.stop()

    visited: list[str] = []
    delivered: list[object] = []
    shown_aar: list[str] = []
    modal_errors: list[str] = []
    activation_states: list[str] = []
    witness_paths: dict[str, tuple[Path, Path]] = {}
    settlement_evidence: dict[str, tuple[dict, dict]] = {}
    settlement_runtime: dict[str, dict] = {}
    window._aar_ready.connect(delivered.append)
    window._settings_combat_status.connect(
        lambda state, _message: activation_states.append(state)
    )

    def arm_from_modal() -> None:
        dialog = app.activeModalWidget()
        assert isinstance(dialog, SettingsDialog)
        visited.append("settings")
        dialog._combat_enabled_chk.setChecked(True)
        dialog._combat_mode_combo.setCurrentIndex(
            dialog._combat_mode_combo.findData("aggressive")
        )
        dialog._combat_severity_combo.setCurrentIndex(
            dialog._combat_severity_combo.findData("MEDIUM")
        )
        dialog._combat_process_combo.setCurrentIndex(
            dialog._combat_process_combo.findData("terminate")
        )
        dialog._combat_quarantine_chk.setChecked(True)
        dialog._combat_block_chk.setChecked(False)
        dialog._combat_host_isolation_chk.setChecked(False)
        dialog._combat_honeypot_chk.setChecked(False)
        dialog._autostart_chk.setChecked(False)
        QTest.mouseClick(dialog._btn_save, Qt.MouseButton.LeftButton)

    try:
        QTimer.singleShot(0, arm_from_modal)
        window._show_settings("Adversary Combat")
        deadline = time.monotonic() + 60.0
        while (
            (
                not combat.response_snapshot()["ready"]
                or bool(getattr(manager, "_settings_combat_activation_pending", False))
                or "ready" not in activation_states
            )
            and time.monotonic() < deadline
        ):
            app.processEvents()
            time.sleep(0.05)
        assert visited == ["settings"]
        assert "pending" in activation_states
        assert "ready" in activation_states, activation_states
        assert not getattr(manager, "_settings_combat_activation_pending", False)
        assert config.adversary_combat_enabled is True
        assert config.module_states["Adversary Combat"] is True
        assert manager.is_enabled(combat.name)
        assert combat.response_snapshot()["ready"]
        trace("settings_armed", combat=combat.response_snapshot())
        assert config.settings_path.is_file()
        saved = json.loads(config.settings_path.read_text(encoding="utf-8"))
        assert saved["adversary_combat_enabled"] is True
        assert saved["adversary_combat_quarantine_files"] is True
        assert saved["adversary_combat_block_network"] is False
        assert saved["adversary_combat_isolate_host"] is False

        process.start()
        deadline = time.monotonic() + 10.0
        process_ready = {}
        readiness_observed = False
        while time.monotonic() < deadline:
            process_ready = process.operational_snapshot()
            # The startup PID boundary is cycle 1 with enrichment pending.
            # Observe a real completed poll before asking the unchanged launch
            # authority to prove its own later fresh, loss-free cycle.
            if (
                process_ready["status"] == "running"
                and process_ready["thread_alive"] is True
                and process_ready["first_cycle_complete"] is True
                and process_ready["cycle_count"] > 1
                and process_ready["health"] >= 50
                and process_ready["event_overflow_count"] == 0
            ):
                readiness_observed = True
                break
            app.processEvents()
            time.sleep(0.05)
        if not readiness_observed:
            worker = getattr(process, "_thread", None)
            frame = sys._current_frames().get(worker.ident) if worker is not None else None
            frames = []
            for _ in range(8):
                if frame is None:
                    break
                frames.append({
                    "file": Path(frame.f_code.co_filename).name,
                    "function": frame.f_code.co_name, "line": frame.f_lineno,
                })
                frame = frame.f_back
            del frame
            diagnostic = {
                "schema": "angerona.gui-live-readiness-failure.v1",
                "worker_frames": frames,
                "process": {key: process_ready.get(key) for key in (
                    "cycle_count", "thread_alive", "health", "first_cycle_complete",
                    "last_cycle_age_seconds", "declared_cycle_interval_seconds",
                    "generation_uptime_seconds", "throttle_multiplier", "throttle_floor",
                    "event_overflow_count", "watchdog_deadline_remaining_seconds",
                )},
            }
            print("ANGERONA_GUI_READINESS_FAILURE " + json.dumps(diagnostic), flush=True)
            trace("readiness_failed", summary=diagnostic)
        assert process.operational_snapshot()["first_cycle_complete"]
        assert process_ready.get("cycle_count", 0) > 1, process_ready
        assert process_ready.get("status") == "running", process_ready
        assert process_ready.get("thread_alive") is True, process_ready
        assert process_ready.get("health", 0) >= 50, process_ready
        assert process_ready.get("event_overflow_count", -1) == 0, process_ready
        assert assess_drill_response(manager, require_process=True)["ready"]
        trace("readiness_passed", process=process.operational_snapshot())

        original_settlement = window._wait_for_redteam_response_settlement

        def settle_then_witness(*, started_at: float, **kwargs: object) -> dict:
            trace("settlement_start", steps=len(window.red_team_engine.steps),
                  combat=combat.response_snapshot())
            settled = original_settlement(started_at=started_at, **kwargs)
            combat_settled = combat.response_snapshot()
            runtime_settled = _witness_runtime_snapshot(combat, bus)
            trace("settlement_done", settled=settled,
                  combat=combat_settled, runtime=runtime_settled)
            engine = window.red_team_engine
            run_id = str(engine.run_id)
            settlement_evidence[run_id] = settled, combat_settled
            settlement_runtime[run_id] = runtime_settled
            with marker_lock:
                expected_markers = dict(marker_digests.get(run_id, {}))
            with marker_lock:
                expected_processes = [
                    {"pid": pid, "token": token,
                     "birth": spawn_births.get((pid, token))}
                    for step in engine.steps
                    for pid, token in zip(step.pids, step.correlation_tokens)
                ]
            witness_input = case_evidence / f"bug_audit_gui_os_witness_{run_id}.pre.input.json"
            witness_output = (
                case_evidence
                / f"bug_audit_gui_os_witness_{run_id}.pre.json"
            )
            witness_input.write_text(json.dumps({
                "run_id": run_id,
                "quarantine_root": str(combat.quarantine_root),
                "verify_digest": False,
                "markers": [
                    {"source": source, "sha256": digest}
                    for source, digest in expected_markers.items()
                ],
                "processes": expected_processes,
            }), encoding="utf-8")
            witness_process = subprocess.run(
                [sys.executable, "-c", _OS_WITNESS,
                 str(witness_input), str(witness_output)],
                check=False, capture_output=True, text=True, timeout=15.0,
            )
            (case_evidence / f"bug_audit_gui_os_witness_{run_id}.pre.stderr.txt").write_text(
                witness_process.stderr, encoding="utf-8",
            )
            if witness_process.returncode:
                trace("pre_witness_failed", returncode=witness_process.returncode,
                      stderr=witness_process.stderr[-2000:])
                raise AssertionError(
                    f"OS witness exited {witness_process.returncode}: "
                    f"{witness_process.stderr[-4000:]}"
                )
            witness_paths[run_id] = witness_input, witness_output
            trace("pre_witness_done", run_id=run_id,
                  markers=len(expected_markers), processes=len(expected_processes))
            return settled

        monkeypatch.setattr(
            window, "_wait_for_redteam_response_settlement", settle_then_witness,
        )

        def close_report_dialogs() -> None:
            for widget in app.topLevelWidgets():
                if isinstance(widget, AARDialog) and widget.isVisible():
                    shown_aar.append(widget.body.toPlainText())
                    widget.accept()
                elif isinstance(widget, QMessageBox) and widget.isVisible():
                    modal_errors.append(widget.text())
                    widget.accept()

        modal_timer = QTimer()
        modal_timer.timeout.connect(close_report_dialogs)
        modal_timer.start(100)
        window._open_simulation()
        console = window._rt_console
        assert console is not None
        console.cb_shark.setChecked(False)
        console.cb_apt.setChecked(True)
        console.cb_comprehensive.setChecked(True)
        console.cb_campaign.setChecked(True)
        console.cb_remediate.setChecked(True)
        console.sld.setValue(0)
        assert console.loc_edit.text() == str(isolated_root / "drill-sandbox")

        def capture_failed_launch_admission(run_index: int) -> None:
            """Record a bounded refused-launch view; grant no readiness proof."""
            try:
                status_limit, log_limit = 16_384, 4096
                status = console.live_status.text()
                status_truncated = len(status) > status_limit
                typed: dict[str, object] = {}
                parse_note = "typed diagnostic marker unavailable"
                if status_truncated:
                    parse_note = "console status exceeded diagnostic limit; no prefix was parsed"
                else:
                    _prefix, marker, encoded = status.partition("observation_diagnostic=")
                    if marker:
                        try:
                            decoded = json.loads(encoded)
                        except (ValueError, RecursionError):
                            parse_note = "typed diagnostic JSON invalid or incomplete"
                        else:
                            if (isinstance(decoded, dict) and decoded.get("schema") ==
                                    "angerona.process-fresh-observation-diagnostic.v1"):
                                typed = decoded
                                parse_note = "known fields copied from serialized refusal; diagnostic only"
                            else:
                                parse_note = "typed diagnostic schema unavailable or unsupported"

                def bounded_int(value: object) -> int | None:
                    return value if type(value) is int and 0 <= value <= 2**63 - 1 else None

                def bounded_seconds(value: object) -> float | None:
                    # This comparison also rejects NaN, infinities and negatives.
                    return float(value) if type(value) in (int, float) and 0 <= value <= 86400 else None

                def bounded_text(value: object, limit: int = 128) -> str | None:
                    return value[:limit] if isinstance(value, str) else None

                def bounded_token(value: object) -> list[int] | None:
                    if (isinstance(value, list) and len(value) == 2
                            and all(type(item) is int and 0 < item <= 2**63 - 1 for item in value)):
                        return list(value)
                    return None

                diagnostic: dict[str, object] = {
                    "schema": bounded_text(typed.get("schema")),
                    "parse_note": parse_note,
                    "generation": bounded_int(typed.get("generation")),
                }
                for key in ("diagnostic_only", "available", "waiting"):
                    value = typed.get(key)
                    diagnostic[key] = value if type(value) is bool else None
                for key in ("requested_token", "pending_token", "inflight_token",
                            "completed_token", "last_attempt_token", "last_coverage_token"):
                    diagnostic[key] = bounded_token(typed.get(key))
                for key in ("requested_age_seconds", "stage_age_seconds",
                            "last_attempt_age_seconds", "last_coverage_age_seconds",
                            "nominal_wait_seconds", "declared_wait_seconds", "wait_elapsed_seconds"):
                    diagnostic[key] = bounded_seconds(typed.get(key))
                for key in ("requested_stage", "worker_stage", "last_refusal_reason"):
                    diagnostic[key] = bounded_text(typed.get(key))
                for key in ("age_limit_seconds", "count_limit"):
                    diagnostic[key] = bounded_int(typed.get(key))
                coverage = typed.get("last_coverage")
                if isinstance(coverage, dict):
                    coverage_fields: dict[str, object] = {}
                    for key in ("complete", "enumeration_complete", "fresh", "counts_valid", "error_reported"):
                        value = coverage.get(key)
                        coverage_fields[key] = value if type(value) is bool else None
                    for key in ("enumerated", "skipped", "unreadable", "identity_incomplete",
                                "observed_identity_gaps"):
                        value = coverage.get(key)
                        coverage_fields[key] = (
                            value if type(value) is int and 0 <= value <= 2**31 - 1 else None
                        )
                    diagnostic["last_coverage"] = coverage_fields
                else:
                    diagnostic["last_coverage"] = None

                log_tail = None
                log_note = "console log unavailable"
                try:
                    from PySide6.QtGui import QTextCursor

                    document = console.log.document()
                    cursor = QTextCursor(document)
                    cursor.setPosition(max(0, document.characterCount() - 1 - log_limit))
                    cursor.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
                    log_tail = cursor.selectedText().replace("\u2029", "\n")[:log_limit]
                    log_note = "last at most 4096 UTF-16 document units; diagnostic text is untrusted"
                except Exception as exc:
                    log_note = "console log capture unavailable: " + type(exc).__name__[:80]

                print("ANGERONA_GUI_LAUNCH_ADMISSION_FAILURE " + json.dumps({
                    "diagnostic_only": True,
                    "run_index": run_index,
                    "console_preparing": console._launch_preparing,
                    "console_run_pending": console._run_pending,
                    "observation_diagnostic": diagnostic,
                }, sort_keys=True), flush=True)

                trace(
                    "launch_admission_failed", run_index=run_index,
                    diagnostic_only=True, observed_monotonic=time.monotonic(),
                    test_process_pid=os.getpid(),
                    console_status=status[:status_limit], console_status_truncated=status_truncated,
                    console_preparing=console._launch_preparing,
                    console_run_pending=console._run_pending,
                    observation_diagnostic=diagnostic,
                    console_log_tail=log_tail, console_log_note=log_note,
                )
            except Exception as exc:
                # Capture/formatting/IO failure must never replace the original
                # unchanged admission assertion or turn its refusal into a pass.
                try:
                    trace(
                        "launch_admission_diagnostic_unavailable", run_index=run_index,
                        diagnostic_only=True, capture_error_type=type(exc).__name__[:80],
                    )
                except Exception:
                    pass


        def await_real_process_preflight(run_index: int) -> None:
            """Synchronize fixture work; the launch still needs its own proof."""
            initial = process.operational_snapshot()
            expected_generation = initial.get("lifecycle_generation")
            baseline_cycle = initial.get("cycle_count")
            assert type(expected_generation) is int and expected_generation > 0, initial
            assert type(baseline_cycle) is int and baseline_cycle >= 1, initial
            request = ProcessMonitorModule.request_fresh_observation(
                process, expected_generation=expected_generation,
            )
            assert request is not None, initial
            # Reuse the startup fixture's ten-second allowance. Do not alter
            # launch preparation's budget, collection result or refusal gate.
            preflight_deadline = time.monotonic() + 10.0
            observed: dict[str, object] = {}
            ready = False
            while time.monotonic() < preflight_deadline:
                observed = process.operational_snapshot()
                ready = bool(
                    observed.get("status") == "running"
                    and observed.get("thread_alive") is True
                    and observed.get("first_cycle_complete") is True
                    and observed.get("lifecycle_generation") == expected_generation
                    and type(observed.get("cycle_count")) is int
                    and observed["cycle_count"] > baseline_cycle
                    and type(observed.get("health")) is int
                    and observed["health"] >= 50
                    and observed.get("event_overflow_count") == 0
                    and ProcessMonitorModule.fresh_observation_complete(process, request)
                )
                if ready:
                    break
                app.processEvents()
                time.sleep(0.05)
            summary = {
                "schema": "angerona.gui-live-prelaunch-observation.v1",
                "diagnostic_only": True,
                "run_index": run_index,
                "requested_token": list(request),
                "baseline_cycle": baseline_cycle,
                "process": {key: observed.get(key) for key in (
                    "status", "thread_alive", "first_cycle_complete",
                    "lifecycle_generation", "cycle_count", "health",
                    "event_overflow_count",
                )},
                "observation_diagnostic": ProcessMonitorModule.fresh_observation_diagnostic(
                    process, request,
                ),
            }
            if not ready:
                print("ANGERONA_GUI_PRELAUNCH_OBSERVATION_FAILURE " +
                      json.dumps(summary, sort_keys=True), flush=True)
                trace("prelaunch_observation_failed", summary=summary)
            assert ready, summary
            trace("prelaunch_observation_passed", summary=summary)

        try:
            for run_index in (1, 2):
                await_real_process_preflight(run_index)
                started = time.monotonic()
                previous_deliveries = len(delivered)
                QTest.mouseClick(console.launch_btn, Qt.MouseButton.LeftButton)
                trace("launch_clicked", run_index=run_index,
                      run_id=window.red_team_engine.run_id)
                assert console._run_pending
                # Preparation runs off Qt. Only its accepted GUI handoff may
                # publish the actual run ID; a pending click is not acceptance.
                deadline = time.monotonic() + 180.0
                acceptance_deadline = min(deadline, time.monotonic() + 30.0)
                while (
                    console._run_pending
                    and not console._report_runs.get("red_team")
                    and time.monotonic() < acceptance_deadline
                ):
                    app.processEvents()
                    time.sleep(0.05)
                if not console._report_runs.get("red_team"):
                    capture_failed_launch_admission(run_index)
                assert console._report_runs.get("red_team"), {
                    "console": console.live_status.text(),
                    "modal_errors": modal_errors,
                    "preparing": console._launch_preparing,
                }
                assert not console._launch_preparing
                assert console._report_runs["red_team"] == window.red_team_engine.run_id
                assert not console._report_runs.get("shark")
                trace("launch_accepted", run_index=run_index,
                      run_id=console._report_runs["red_team"])
                next_trace = time.monotonic() + 10.0
                while len(delivered) == previous_deliveries and time.monotonic() < deadline:
                    app.processEvents()
                    if time.monotonic() >= next_trace:
                        trace("waiting_for_aar", run_index=run_index,
                              steps=len(window.red_team_engine.steps),
                              engine_running=window.red_team_engine.is_running,
                              combat=combat.response_snapshot())
                        next_trace = time.monotonic() + 10.0
                    time.sleep(0.05)
                trace("aar_signal_observed", run_index=run_index,
                      deliveries=len(delivered), steps=len(window.red_team_engine.steps))
                assert len(delivered) == previous_deliveries + 1, {
                    "console": console.live_status.text(),
                    "modal_errors": modal_errors,
                    "steps": len(window.red_team_engine.steps),
                }
                handoff = delivered[-1]
                assert type(handoff) is AARReportResult, handoff
                assert "RED TEAM ATTACK" in verified_aar_handoff_text(handoff)
                report = json.loads(handoff.report_bytes.decode("utf-8"))
                trace("signed_aar", run_index=run_index, run_id=handoff.run_id,
                      outcome=report.get("outcome"))
                assert report["run_id"] == handoff.run_id
                shutil.copyfile(
                    isolated_root / "redteam_aar.json",
                    case_evidence / f"bug_audit_gui_aar_{run_index}.json",
                )

                witness_input, pre_output = witness_paths[handoff.run_id]
                pre_witness = json.loads(pre_output.read_text(encoding="utf-8"))
                assert pre_witness["run_id"] == handoff.run_id
                post_input = case_evidence / f"bug_audit_gui_os_witness_{handoff.run_id}.post.input.json"
                post_output = case_evidence / f"bug_audit_gui_os_witness_{handoff.run_id}.post.json"
                post_request = json.loads(witness_input.read_text(encoding="utf-8"))
                post_request["verify_digest"] = True
                post_input.write_text(json.dumps(post_request), encoding="utf-8")
                post_process = subprocess.run(
                    [sys.executable, "-c", _OS_WITNESS,
                     str(post_input), str(post_output)],
                    check=False, capture_output=True, text=True, timeout=15.0,
                )
                (case_evidence / f"bug_audit_gui_os_witness_{handoff.run_id}.post.stderr.txt").write_text(
                    post_process.stderr, encoding="utf-8",
                )
                assert post_process.returncode == 0, post_process.stderr
                trace("post_witness_done", run_index=run_index,
                      run_id=handoff.run_id)
                witness = json.loads(post_output.read_text(encoding="utf-8"))
                assert witness["run_id"] == handoff.run_id
                shutil.copyfile(
                    pre_output,
                    case_evidence / f"bug_audit_gui_os_witness_{run_index}.pre.json",
                )
                shutil.copyfile(
                    post_output,
                    case_evidence / f"bug_audit_gui_os_witness_{run_index}.post.json",
                )
                (case_evidence / f"bug_audit_gui_run_{run_index}.json").write_text(
                    json.dumps({
                        "run_id": handoff.run_id,
                        "duration_seconds": round(time.monotonic() - started, 3),
                        "engine_steps": len(window.red_team_engine.steps),
                        "aar_outcome": report.get("outcome"),
                        "aar_denominator": report["evidence_taxonomy"]["denominator"],
                        "aar_verified_containment": report["evidence_taxonomy"]["successful_response"]["count"],
                        "os_pre_markers": len(pre_witness["markers"]),
                        "os_pre_sources_absent": sum(row["source_absent"] for row in pre_witness["markers"]),
                        "os_pre_quarantine_names": sum(bool(row["candidate_quarantines"]) for row in pre_witness["markers"]),
                        "os_post_hash_matches": sum(bool(row["matching_quarantines"]) for row in witness["markers"]),
                        "os_witness_processes": len(witness["processes"]),
                        "console_status": console.live_status.text(),
                        "modal_errors": modal_errors,
                    }, indent=2), encoding="utf-8",
                )
                for phase, observed, require_digest in (
                    ("pre", pre_witness, False), ("post", witness, True),
                ):
                    accepted = _os_witness_accepts(
                        observed, expected_markers=36, require_process=True,
                        require_digest=require_digest,
                    )
                    diagnostic = ""
                    if not accepted:
                        settled, combat_settled = settlement_evidence.get(handoff.run_id, ({}, {}))
                        diagnostic = _os_witness_failure_summary(
                            observed, phase=phase, run_index=run_index,
                            expected_markers=36, require_process=True,
                            require_digest=require_digest, report=report,
                            settled=settled, combat=combat_settled,
                        )
                        detail = json.loads(diagnostic)
                        detail["runtime_at_settlement"] = settlement_runtime.get(handoff.run_id, {})
                        detail["runtime_at_assertion"] = _witness_runtime_snapshot(combat, bus)
                        try:
                            detail["response_failure_diagnostic"] = _response_failure_diagnostic(combat, bus)
                        except Exception:
                            detail["response_failure_diagnostic"] = {
                                "schema": "angerona.gui-live-response-failure-diagnostic.v1",
                                "available": False, "cause_established": False,
                            }
                        diagnostic = json.dumps(detail, sort_keys=True)
                        print("ANGERONA_GUI_OS_WITNESS_FAILURE " + diagnostic, flush=True)
                        trace("os_witness_rejected", summary=json.loads(diagnostic))
                    assert accepted, diagnostic
                assert report["coverage_score_eligible"] is True
                assert report["evidence_taxonomy"]["denominator"] == 37
                assert report["evidence_taxonomy"]["successful_response"]["count"] == 37
                assert report["outcome"] == "verified"
                assert console._report_results["red_team"] == {
                    "count": 37, "eligible": 37, "outcome": "verified",
                }
                assert "Verified simulation containment" in console.live_status.text()
                assert (
                    "native analytics: 0/37 overall; 36 file-marker opportunities"
                    in console.live_status.text()
                )
                assert shown_aar and "RED TEAM ATTACK" in shown_aar[-1]
                assert not modal_errors
        finally:
            modal_timer.stop()
    finally:
        trace("cleanup_start")
        cleanup_deadline = time.monotonic() + 30.0
        try:
            window.system_pulse.shutdown()
            # A failed assertion can leave preparation holding the manager and
            # recorder. Cancel and let that worker release its exact lease/watches
            # before their fixtures are stopped or closed.
            preparing = getattr(window, "_sim_launch_job", None)
            if preparing is not None:
                window._cancel_simulation_launch()
                while preparing.thread.is_alive() and time.monotonic() < cleanup_deadline:
                    app.processEvents()
                    preparing.thread.join(timeout=0.05)
                assert not preparing.thread.is_alive(), "Simulation preparation did not retire"
                window._poll_simulation_launch()
            if window.red_team_engine.is_running:
                window.red_team_engine.stop_and_clean()
            manager.stop_all()
        finally:
            # Retain and join the exact sampler created by this window. Reuse the
            # existing shared cleanup budget; shutdown itself must not block Qt.
            pulse_worker.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))
            assert not pulse_worker.is_alive(), "GUI-owned System Pulse sampler did not retire"
        for name in ("timer", "_chill_maintenance_timer", "_adaptation_timer", "_beat_timer"):
            timer = getattr(window, name, None)
            if timer is not None:
                timer.stop()
        window._flow_writer.close()
        window._posture_reader.close()
        window._panel_reveal.shutdown()
        window.tray.hide()
        window.hide()
        recorder.close()
        trace("cleanup_done")
