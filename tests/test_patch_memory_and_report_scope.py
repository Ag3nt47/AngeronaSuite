"""Real AAR writer/HMAC inputs; practice memory never grants host authority."""
from __future__ import annotations

import copy
import hashlib
import json
import sqlite3

import pytest

from angerona.core import patch_memory, report_attest
from angerona.core.eventbus import Event, Severity
from angerona.modules import remediation_actions
from angerona.modules.posture_hardening import PostureHardening
from angerona.shark import aar_report


@pytest.fixture
def context(tmp_path, monkeypatch):
    key = tmp_path / "bus.key"
    key.write_text((b"p" * 32).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    monkeypatch.setattr(PostureHardening, "_log_attempt", lambda *_a, **_kw: None)
    module = PostureHardening(data_dir=tmp_path)
    events = []
    monkeypatch.setattr(module, "emit", lambda message, *_a, **kw: events.append((message, kw)))
    def no_dispatch(*_a, **_kw):
        raise AssertionError("This test must not execute a host command or automatic remediation")
    monkeypatch.setattr(remediation_actions, "run_hidden", no_dispatch)
    return module, events


def _shark(root, run_id="shark-inert-1"):
    history = {"run_id": run_id, "kind": "shark", "status": "completed", "campaign": {}}
    rows = []
    for index in range(16):
        event = Event("Inert native detector", "Fixture analytic", Severity.HIGH, 101.0, {})
        rows.append(aar_report.StepVerdict(
            "Defense Evasion" if index < 12 else "Process Injection",
            "T1562.011 fixture" if index < 12 else "T1055 fixture",
            "No attack or host action is executed", 100.0, True,
            observation=event, observation_latency=event.ts - 100.0,
            native_catch=event if index < 12 else None,
            native_latency=event.ts - 100.0 if index < 12 else None,
            catch=event if index < 12 else None,
            catch_latency=event.ts - 100.0 if index < 12 else None,
            target_containment_verified=False))
    text = aar_report.render(history, rows, "SHARK ATTACK")
    result = aar_report._write_report(root, history, rows, text)
    assert aar_report.verified_aar_handoff_text(result) == text
    return result, json.loads(result.report_bytes)


def _diagnostic():
    return report_attest.attest({
        "run_id": "redteam-incomplete-13-of-80", "report_kind": "red_team",
        "diagnostic_only": True, "coverage_score_eligible": False,
        "outcome": "inconclusive", "validation_status": "not-currently-verified",
        "diagnostic_history_authentication": "verified", "readiness_scope": "historical-at-launch",
        "steps_run": 13, "planned_steps": 80, "detection_steps": 76,
        "epistemic_metrics": {"verified_containment": {"count": 0, "eligible": 76, "rate": None}},
        "verdicts": [{"stage": "Not an executed attack", "technique": "T1055 fixture",
                       "category": "detection", "caught": False, "remediated": False}
                     for _ in range(76)],
    })


def test_authenticated_diagnostic_preserves_incident_without_learning_action_or_closure(context, monkeypatch):
    module, events = context
    from angerona.core import drill_resolution
    def prohibited(*_a, **_kw):
        raise AssertionError("Incomplete history must never enter learning/policy/closure/action")
    monkeypatch.setattr(module, "apply_vetted_remediation", prohibited)
    monkeypatch.setattr(module, "mark_patched", prohibited)
    monkeypatch.setattr(drill_resolution, "record_findings", prohibited)
    monkeypatch.setattr(remediation_actions, "_auto_apply_enabled", lambda: True)
    report = _diagnostic()
    path = module.redteam_aar_path
    path.write_text(json.dumps(report), encoding="utf-8")
    assert report_attest.verify(report) == "ok"
    assert module.ingest_redteam_report(path) == []
    result = module.resolve_redteam_report(path, expected_run_id=report["run_id"],
        expected_report_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    assert result["ok"] is False and result["candidates"] == 0 and result["policy_changed"] is False
    verification = module.verify_redteam_practice({"ok": True, "run_id": report["run_id"],
        "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    assert verification["ok"] is False and verification["verified"] == 0
    assert module.weaknesses() == [] and module._trusted_evidence() is None
    memory = module.patch_memory_snapshot()
    assert memory["gaps"] == [] and memory["attempts"] == []
    assert memory["incidents"][0]["classification"] == "diagnostic"
    assert all(fields.get("response_authorized") is not True for _, fields in events)
    assert not (module.data_dir / "purple_guard_policy.json").exists()


def test_current_signed_shark_writer_learns_response_and_detection_gaps_separately(context):
    module, events = context
    _handoff, report = _shark(module.data_dir)
    assert report["detection_caught"] == 12 and report["remediated"] == 0
    found = module.ingest_report(module.data_dir / "shark_aar.json")
    assert {row["gap_kind"] for row in found} == {"response", "detection"}
    assert all(row["source"] == "shark-practice" for row in module.weaknesses())
    memory = module.patch_memory_snapshot()
    response = next(row for row in memory["gaps"] if row["gap_kind"] == "response")
    assert response["occurrences"] == response["sensor_observations"] == response["native_analytics"] == 12
    assert response["simulation_validations"] == response["verified_responses"] == 0
    assert response["evidence_scope"] == "practice" and response["status"] == "OPEN"
    assert all(fields.get("finding_kind") == "practice_gap" and fields.get("response_authorized") is False
               for _, fields in events)


def test_run_refresh_dedup_survives_new_posture_instance_and_new_run_reopens(context):
    module, _ = context
    _shark(module.data_dir)
    module.ingest_report(module.data_dir / "shark_aar.json")
    first = module.patch_memory_snapshot()
    response = next(row for row in first["gaps"] if row["gap_kind"] == "response")
    module._patch_memory.record_attempt({"attempt_id": "a" * 64, "gap_id": response["gap_id"],
                                        "state": "applied-verified", "gap_closed": False})
    restarted = PostureHardening(data_dir=module.data_dir)
    assert restarted.ingest_report(module.data_dir / "shark_aar.json") == []
    same = next(row for row in restarted.patch_memory_snapshot()["gaps"] if row["gap_kind"] == "response")
    assert same["occurrences"] == 12 and same["run_occurrences"] == 1
    _shark(module.data_dir, "shark-inert-2")
    restarted.ingest_report(module.data_dir / "shark_aar.json")
    recurring = next(row for row in restarted.patch_memory_snapshot()["gaps"] if row["gap_kind"] == "response")
    assert recurring["occurrences"] == 24 and recurring["run_occurrences"] == 2
    assert recurring["recurrences_after_patch"] == 12 and recurring["status"] == "OPEN"


def test_practice_mitre_collision_preserves_existing_host_row_and_context(context):
    module, _ = context
    module.record_weakness("T1562.011", "Actual host evidence", "Critical", source="host")
    module._ctx["T1562.011"] = {"source": "real-host"}
    _shark(module.data_dir)
    module.ingest_report(module.data_dir / "shark_aar.json")
    host = next(row for row in module.weaknesses() if row["mitre_id"] == "T1562.011")
    assert host["name"] == "Actual host evidence" and host["source"] == "host"
    assert module._ctx["T1562.011"] == {"source": "real-host"}
    assert any(row["technique"] == "T1562.011" for row in module.patch_memory_snapshot()["gaps"])


@pytest.mark.parametrize("flag", [None, False, 1, "true"])
def test_literal_eligibility_required_even_with_genuine_signature(context, flag):
    module, _ = context
    report = _diagnostic()
    report.pop(report_attest.SIG_FIELD)
    report.pop("diagnostic_only")
    if flag is None:
        report.pop("coverage_score_eligible")
    else:
        report["coverage_score_eligible"] = flag
    report = report_attest.attest(report)
    path = module.redteam_aar_path
    path.write_text(json.dumps(report), encoding="utf-8")
    assert report_attest.verify(report) == "ok"
    assert module.ingest_redteam_report(path) == [] and module.weaknesses() == []


def test_tampered_report_and_unsigned_index_row_are_explicitly_unverified(context):
    module, _ = context
    report = _diagnostic()
    report["steps_run"] = 80
    assert report_attest.verify(report) == "bad"
    module._remember_patch_report(report)
    assert module.patch_memory_snapshot()["incidents"][0]["classification"] == "unverified"
    with sqlite3.connect(module._patch_memory.path) as db:
        db.execute("UPDATE patch_reports SET body=?", (json.dumps({"classification": "verified-practice"}),))
    memory = module.patch_memory_snapshot()
    assert memory["incidents"] == [] and memory["unverified_rows"] == 1 and memory["gaps"] == []


def test_capacity_holds_new_admission_without_erasing_existing_evidence(context, monkeypatch):
    module, _ = context
    monkeypatch.setattr(patch_memory, "MAX_REPORTS", 1)
    first = _diagnostic()
    assert module._patch_memory.remember_report(first)["stored"] is True
    second = copy.deepcopy(first)
    second.pop(report_attest.SIG_FIELD)
    second["run_id"] = "second-authenticated-diagnostic"
    held = module._patch_memory.remember_report(report_attest.attest(second))
    assert held["stored"] is False and held["reason"] == "report-index-capacity"
    memory = module.patch_memory_snapshot()
    assert memory["admission_held"] == 1 and memory["totals"]["incidents"] == 1
    assert memory["incidents"][0]["run_id"] == first["run_id"]


def test_missing_signer_cannot_claim_attempt_was_durably_authenticated(context, monkeypatch):
    module, _ = context
    monkeypatch.setattr(report_attest, "_load_key", lambda: None)
    with pytest.raises(ValueError, match="signing"):
        module._patch_memory.record_attempt({"attempt_id": "b" * 64, "state": "prepared"})
    with sqlite3.connect(module._patch_memory.path) as db:
        assert db.execute("SELECT count(*) FROM patch_attempts").fetchone()[0] == 0


def test_oversized_report_is_held_before_json_parse_or_learning(context):
    module, _ = context
    path = module.redteam_aar_path
    path.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    assert module.ingest_redteam_report(path) == [] and module.weaknesses() == []
