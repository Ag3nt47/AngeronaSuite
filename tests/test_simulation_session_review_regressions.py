"""Scheduling and signed-report projection only; no detector authority fixtures."""
from __future__ import annotations

import json
import os
import threading

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.shark import aar_report, simulation_session as sessions


class _SchedulingManager:
    pass


def _session(root):
    return sessions.SimulationSession(manager=_SchedulingManager(), bus=None, recorder=None,
        data_root=root, red_team_engine=None, shark_engine=None)


@pytest.mark.parametrize("requested", [True, False])
def test_requested_mode_is_detached_at_prepare_without_changing_response_policy(tmp_path, requested, monkeypatch):
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "unchanged-fixture")
    session = _session(tmp_path)
    cfg = {"run_shark": True, "auto_remediate": requested}
    plan = session.prepare(cfg, default_target=tmp_path / "sandbox")
    cfg["auto_remediate"] = not requested
    assert session.performance_snapshot(plan.runs[0].run_id).containment_required is requested
    assert session._cfg["auto_remediate"] is requested
    assert os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] == "unchanged-fixture"
    assert session.owned_workers() == () and session.completed_reports() == ()


@pytest.mark.parametrize("invalid", [None, 0, "false"])
def test_nonboolean_requested_mode_is_refused_before_plan_commit(tmp_path, invalid):
    session = _session(tmp_path)
    with pytest.raises(sessions.SessionHeld, match="boolean"):
        session.prepare({"run_shark": True, "auto_remediate": invalid}, default_target=tmp_path / "sandbox")
    assert session._prepared is None and session.owned_workers() == ()


def test_late_prepare_cannot_overwrite_a_session_started_during_planning(tmp_path, monkeypatch):
    session = _session(tmp_path)
    original_plan = session.prepare({"run_shark": True}, default_target=tmp_path / "sandbox")
    planning, resume_planning, retire = (threading.Event() for _ in range(3))
    real_prepare = sessions.prepare_session
    errors = []

    def paused_plan(*args, **kwargs):
        planning.set()
        assert resume_planning.wait(5)
        return real_prepare(*args, **kwargs)

    def prepare_late():
        try:
            session.prepare({"run_shark": True, "auto_remediate": False}, default_target=tmp_path / "other")
        except BaseException as error:
            errors.append(error)

    def scheduling_worker():
        try:
            assert retire.wait(5)
        finally:
            with sessions._SESSION_OWNERS_LOCK:
                session._reservation_active = False
            session.finished.set()

    monkeypatch.setattr(sessions, "prepare_session", paused_plan)
    monkeypatch.setattr(session, "_run", scheduling_worker)
    caller = threading.Thread(target=prepare_late, name="owned-late-plan")
    caller.start()
    try:
        assert planning.wait(2)
        assert session.start(original_plan)
        accepted_cache = session.snapshot()
        resume_planning.set()
        caller.join(timeout=5)
        assert not caller.is_alive()
        assert len(errors) == 1 and type(errors[0]) is sessions.SessionHeld
        assert "ownership changed" in str(errors[0])
        assert session._prepared is original_plan and session._plan_started
        assert session.snapshot() == accepted_cache
        assert session.performance_snapshot(original_plan.runs[0].run_id).containment_required is True
    finally:
        resume_planning.set()
        retire.set()
        caller.join(timeout=5)
        for worker in session.owned_workers():
            worker.join(timeout=5)
    assert not caller.is_alive() and all(not worker.is_alive() for worker in session.owned_workers())


def test_a_competing_prepare_cannot_replace_the_plan_committed_while_it_was_blocked(tmp_path, monkeypatch):
    session = _session(tmp_path)
    planning, resume = threading.Event(), threading.Event()
    real_prepare = sessions.prepare_session
    errors = []

    def paused_plan(*args, **kwargs):
        if threading.current_thread().name == "owned-first-prepare":
            planning.set()
            assert resume.wait(5)
        return real_prepare(*args, **kwargs)

    def prepare_first():
        try:
            session.prepare({"run_shark": True}, default_target=tmp_path / "first")
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(sessions, "prepare_session", paused_plan)
    caller = threading.Thread(target=prepare_first, name="owned-first-prepare")
    caller.start()
    try:
        assert planning.wait(2)
        accepted = session.prepare({"run_shark": True, "auto_remediate": False},
                                   default_target=tmp_path / "second")
        resume.set()
        caller.join(timeout=5)
        assert not caller.is_alive()
        assert len(errors) == 1 and type(errors[0]) is sessions.SessionHeld
        assert session._prepared is accepted
        assert session.performance_snapshot(accepted.runs[0].run_id).containment_required is False
    finally:
        resume.set()
        caller.join(timeout=5)
    assert not caller.is_alive() and session.owned_workers() == ()


@pytest.mark.parametrize("requested,misses", [(True, 4), (False, 0)])
def test_final_projection_uses_selected_criterion_from_actual_signed_report_bytes(
    tmp_path, monkeypatch, requested, misses,
):
    """Writer-shaped projection fixture, not a claim of native scan efficacy.

    Real native proof/response gates are exercised separately. This fixture
    deliberately supplies no detector, manager, process or mutation capability.
    """
    key = tmp_path / "report.key"
    key.write_text("68" * 32, encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key))
    session = _session(tmp_path)
    prepared = session.prepare({"run_shark": True, "auto_remediate": requested},
                               default_target=tmp_path / "sandbox").runs[0]
    event = Event("projection-only simulation output", "No native authority is represented", Severity.INFO)
    verdicts = [aar_report.StepVerdict("fixture", str(index), "projection only", 1.0, True,
        category="detection", catch=event, simulation_validation=event) for index in range(4)]
    history = {"run_id": prepared.run_id, "kind": "shark", "status": "completed", "steps": [], "campaign": {}}
    result = aar_report._write_report(tmp_path, history, verdicts,
                                    aar_report.render(history, verdicts), "projection_aar")
    assert type(result) is aar_report.AARReportResult
    aar_report.verified_aar_handoff_text(result)
    payload = json.loads(result.report_bytes)
    assert report_attest.verify(payload) == "ok"
    assert payload["epistemic_metrics"]["verified_containment"]["count"] == 0
    session._note_report_performance(prepared, result)
    snapshot = session.performance_snapshot(prepared.run_id)
    assert snapshot.state == "final" and snapshot.containment_required is requested
    assert snapshot.detection_verified_steps == snapshot.evaluated_steps == 4
    assert snapshot.containment_verified_steps == 0 and snapshot.finalized_misses == misses
    assert snapshot.final_report_sha256 == result.report_sha256
    assert session.owned_workers() == ()
