"""Real signed history/plan checks; no sensor, scan or native process starts."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, EventBus
from angerona.core.storage import FlightRecorder
from angerona.shark import aar_report, simulation_session as sessions
from angerona.shark.run_manifest import (
    attest_run_history, build_run_history, verify_run_history, write_run_history,
)


def _prepare(root, monkeypatch, *, combined=False):
    monkeypatch.setattr(sessions.random, "random", lambda: 1.0)
    return sessions.prepare_session({"run_shark": True, "run_redteam": combined,
        "complexity": 1, "target_dir": str(root / "drill-sandbox"), "comprehensive": True},
        data_root=root, default_target=root / "drill-sandbox")


def test_plans_are_immutable_distinct_bounded_and_preserve_single_run_ids(tmp_path, monkeypatch):
    plan = _prepare(tmp_path, monkeypatch, combined=True)
    assert len(plan.runs) == 2
    assert [run.kind for run in plan.runs] == ["red_team", "shark"]
    assert len({run.run_id for run in plan.runs}) == 2
    for run in plan.runs:
        assert sessions.validate_prepared_run(run)
        assert run.session_id == plan.session_id
        assert run.admitted_ttl_seconds <= 4500
        with pytest.raises(FrozenInstanceError):
            run.run_id = "replacement"
    shark = plan.runs[-1]
    assert len(shark.steps) == 5
    assert len({step.planned_step_id for step in shark.steps}) == 5
    assert sum(len(step.control_kinds) for step in shark.steps) <= 4
    assert not sessions.validate_prepared_run(replace(shark, admitted_ttl_seconds=4501))
    assert not sessions.validate_prepared_run(replace(shark, plan_sha256="0" * 64))


def test_preflight_rejection_and_launch_diagnostic_do_not_invent_authenticated_runs(tmp_path, monkeypatch):
    with pytest.raises(sessions.SessionHeld):
        sessions.prepare_session({"run_shark": True, "complexity": 999},
            data_root=tmp_path, default_target=tmp_path / "sandbox")
    diagnostic = sessions.LaunchDiagnostic("session-test", "", "preflight", "rejected")
    assert not diagnostic.authenticated_run and not diagnostic.response_authorized
    with pytest.raises(TypeError):
        sessions.LaunchDiagnostic("session-test", "", "preflight", "rejected", authenticated_run=True)
    assert not (tmp_path / "shark_history.json").exists()


@pytest.fixture
def signed_shark(tmp_path, monkeypatch):
    root = tmp_path / "signed-shark"
    root.mkdir()
    key_path = root / "bus.key"
    key_path.write_text("42" * 32, encoding="ascii")
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    plan = _prepare(root, monkeypatch).runs[0]
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)

    def write(status="incomplete", count=0):
        now = time.time()
        rows = [{"stage": item.operation, "technique": item.variant,
            "description": "Authenticated interrupted ground-truth fixture; no behavior executed.",
            "ts_start": now + index / 100, "ts_end": now + (index + 1) / 100,
            "artifact_paths": [], "ok": False, "planned_step_id": item.planned_step_id}
            for index, item in enumerate(plan.steps[:count])]
        history = build_run_history(kind="shark", run_id=plan.run_id,
            generated=time.strftime("%Y-%m-%d %H:%M:%S"), steps=rows,
            preflight=json.loads(plan.preflight_json), status=status, prepared_run=plan.manifest())
        assert write_run_history(root / "shark_history.json", history)
        saved = json.loads((root / "shark_history.json").read_text(encoding="utf-8"))
        assert verify_run_history(saved, require_authenticity=True, allow_legacy=False).valid
        return saved

    try:
        yield SimpleNamespace(root=root, plan=plan, recorder=recorder, bus=bus, write=write)
    finally:
        recorder.close()


@pytest.mark.parametrize("status", ["incomplete", "cancelled"])
@pytest.mark.parametrize("count", [0, 2])
def test_zero_and_partial_signed_shark_runs_return_diagnostic_not_scored_results(
    signed_shark, monkeypatch, status, count,
):
    ctx = signed_shark
    ctx.write(status, count)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Diagnostic attempted detector scoring or action verification")

    monkeypatch.setattr(aar_report, "evaluate", forbidden)
    monkeypatch.setattr(aar_report, "_live_combat_action_verifier", forbidden)
    result = aar_report.generate_aar(ctx.root, recorder=ctx.recorder, bus=ctx.bus,
                                    manager=None, validation_lease=None, return_result=True)
    assert type(result) is aar_report.AARReportResult
    assert aar_report.verified_aar_handoff_text(result) == result.text
    payload = json.loads(result.report_bytes)
    assert report_attest.verify(payload) == "ok"
    assert payload["diagnostic_only"] is True and payload["coverage_score_eligible"] is False
    assert payload["outcome"] == "inconclusive"
    assert payload["steps_run"] == count and payload["planned_steps"] == 5
    assert payload["detection_steps"] == 4
    assert payload["epistemic_metrics"]["verified_containment"] == {"count": 0, "eligible": 4, "rate": None}
    for field in ("detected", "remediated", "response_actions_applied", "findings_resolved",
                  "action_contracts_applied", "verified_closures", "detection_caught"):
        assert payload[field] == 0
    assert payload["campaign_completeness"]["prepared_run"] == ctx.plan.manifest()


@pytest.mark.parametrize("tamper", ["signature", "payload", "valid-hmac-broken-plan"])
def test_corrupt_or_semantically_unbound_shark_history_cannot_receive_a_diagnostic(signed_shark, tamper):
    ctx = signed_shark
    history = ctx.write("incomplete", 2)
    if tamper == "signature":
        history.pop(report_attest.SIG_FIELD)
    elif tamper == "payload":
        history["steps"][0]["description"] = "corrupted after signing"
    else:
        history["campaign"]["prepared_run"]["plan_sha256"] = "0" * 64
        history = attest_run_history(history)
        assert report_attest.verify(history) == "ok"
    (ctx.root / "shark_history.json").write_text(json.dumps(history), encoding="utf-8")
    result = aar_report.generate_aar(ctx.root, recorder=ctx.recorder, bus=ctx.bus,
                                    manager=None, validation_lease=None, return_result=True)
    assert type(result) is str and "integrity check failed" in result
    assert not (ctx.root / "shark_aar.json").exists()


def test_signed_shark_history_cannot_borrow_another_open_recorder_root(signed_shark, tmp_path):
    ctx = signed_shark
    ctx.write("cancelled", 0)
    other = FlightRecorder(tmp_path / "other.db")
    try:
        result = aar_report.generate_aar(ctx.root, recorder=other, bus=ctx.bus, return_result=True)
        assert type(result) is str and "recorder integrity check failed" in result
        assert not (ctx.root / "shark_aar.json").exists()
    finally:
        other.close()


@pytest.mark.parametrize("scenario,expected_attempts", [
    ("stable-second-snapshot", 2),
    ("second-change", 2),
    ("other-refusal", 1),
    ("cancelled", 1),
    ("expired", 1),
    ("foreign-owner", 1),
])
def test_session_report_retries_only_one_changed_journal_while_owned(
    signed_shark, monkeypatch, scenario, expected_attempts,
):
    ctx = signed_shark
    ctx.write("completed", len(ctx.plan.steps))
    session = sessions.SimulationSession(manager=None, bus=ctx.bus, recorder=ctx.recorder,
        data_root=ctx.root, red_team_engine=None, shark_engine=None)
    session.thread = threading.Thread() if scenario == "foreign-owner" else threading.current_thread()
    session._run_deadline = time.monotonic() + 30
    original_verifier = aar_report._live_combat_action_verifier
    attempts = []
    reason = (aar_report.AARFailureReason.JOURNAL_BUSY if scenario == "other-refusal"
              else aar_report.AARFailureReason.JOURNAL_CHANGED)

    def final_snapshot_refused():
        if scenario == "cancelled":
            session.cancel()
        elif scenario == "expired":
            session._run_deadline = time.monotonic()
        return False

    def observe_verifier(*args, **kwargs):
        verifier = original_verifier(*args, **kwargs)
        assert kwargs["wait_for_report_worker"] is (scenario != "foreign-owner")
        # A refused generation must leave no report or partial publication.
        assert not list(ctx.root.glob("shark_aar*"))
        attempts.append(verifier)
        if len(attempts) == 1 or scenario == "second-change":
            verifier.journal_unchanged = final_snapshot_refused
            verifier.journal_failure_reason = lambda: reason
        return verifier

    monkeypatch.setattr(aar_report, "_live_combat_action_verifier", observe_verifier)
    if scenario == "stable-second-snapshot":
        report = session._build_report(ctx.plan)
        assert type(report) is aar_report.AARReportResult
        assert aar_report.verified_aar_handoff_text(report) == report.text
        payload = json.loads(report.report_bytes)
        assert report_attest.verify(payload) == "ok"
        assert payload["run_id"] == ctx.plan.run_id
        assert payload["steps_run"] == len(ctx.plan.steps)
        assert "diagnostic_only" not in payload
        assert payload["campaign_completeness"]["prepared_run"] == ctx.plan.manifest()
    else:
        with pytest.raises(sessions.SessionHeld) as held:
            session._build_report(ctx.plan)
        assert held.value.reason is reason
        assert not list(ctx.root.glob("shark_aar*"))
    assert len(set(attempts)) == len(attempts) == expected_attempts
