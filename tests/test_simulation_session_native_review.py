"""Actual native events and held durable commits; no readiness/proof shortcuts."""
from __future__ import annotations

import json
import socket
import threading

import pytest

from test_yara_automatic_response import controlled_runtime as controlled_runtime

from angerona.modules import purple_guard
from angerona.shark import aar_report, red_team, shark_attack, simulation_session as sessions
from angerona.shark.red_team import RedTeamEngine
from angerona.shark.shark_attack import SharkAttackEngine


@pytest.mark.parametrize("kind", ["shark", "red_team"])
@pytest.mark.parametrize("requested", [True, False])
def test_original_detection_survives_pending_commit_and_later_response_does_not_double_count(
    controlled_runtime, monkeypatch, kind, requested,
):
    ctx = controlled_runtime
    purple_guard.RedTeamValidationLease.release(ctx.lease)
    ctx.lease = None
    ctx.begin_scan()
    shark = SharkAttackEngine(ctx.root, documents_dir=ctx.target, downloads_dir=ctx.target)
    red = RedTeamEngine(ctx.root)
    monkeypatch.setattr(shark, "_jitter", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(red, "_jitter", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sessions.random, "choice", lambda choices: choices[0])
    monkeypatch.setattr(sessions.random, "random", lambda: 1.0)
    monkeypatch.setattr(sessions.random, "shuffle", lambda _rows: None)
    # A cancellation race must never create an external network request.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    monkeypatch.setenv("ANGERONA_SHARK_EXFIL_HOST", "127.0.0.1")
    monkeypatch.setattr(shark_attack, "EXFIL_TEST_PORT", listener.getsockname()[1])
    session = sessions.SimulationSession(manager=ctx.manager, bus=ctx.bus, recorder=ctx.recorder,
        data_root=ctx.root, red_team_engine=red, shark_engine=shark)
    commit_entered, release_commit = threading.Event(), threading.Event()
    detected, contained = threading.Event(), threading.Event()
    snapshots = []
    actual_commit = ctx.combat._commit_after_mutation

    def held_commit(action, **kwargs):
        commit_entered.set()
        assert release_commit.wait(10), "test did not release the genuine durable commit"
        return actual_commit(action, **kwargs)

    monkeypatch.setattr(ctx.combat, "_commit_after_mutation", held_commit)
    actual_shark_note = session._note_step_performance
    actual_red_note = session._note_redteam_performance

    def capture_snapshot(run_id):
        value = session.performance_snapshot(run_id)
        snapshots.append(value)
        if value.detection_verified_steps and not value.containment_verified_steps:
            detected.set()
            if not requested:
                session.cancel()
        if value.containment_verified_steps:
            contained.set()
            session.cancel()
        return value

    def note_shark(binding, planned, state, native_complete):
        actual_shark_note(binding, planned, state, native_complete)
        before = session.performance_snapshot(binding._prepared.run_id)
        actual_shark_note(binding, planned, state, native_complete)
        assert session.performance_snapshot(binding._prepared.run_id) == before
        capture_snapshot(binding._prepared.run_id)

    def note_red(observer, identifier, verdict, settled_negative):
        actual_red_note(observer, identifier, verdict, settled_negative)
        before = session.performance_snapshot(observer.prepared.run_id)
        actual_red_note(observer, identifier, verdict, settled_negative)
        assert session.performance_snapshot(observer.prepared.run_id) == before
        capture_snapshot(observer.prepared.run_id)

    monkeypatch.setattr(session, "_note_step_performance", note_shark)
    monkeypatch.setattr(session, "_note_redteam_performance", note_red)
    plan = session.prepare({"run_shark": kind == "shark", "run_redteam": kind == "red_team",
        "intensity": "Low", "comprehensive": False, "complexity": 1,
        "auto_remediate": requested, "target_dir": str(ctx.target)}, default_target=ctx.target)
    try:
        assert session.start(plan)
        assert commit_entered.wait(10), session.launch_diagnostics()
        assert detected.wait(8), (session.snapshot(), session.launch_diagnostics())
        pending = next(value for value in snapshots
                       if value.detection_verified_steps and not value.containment_verified_steps)
        assert pending.containment_required is requested
        assert pending.evaluated_steps == pending.detection_verified_steps
        assert pending.native_verified_steps or pending.simulation_verified_steps
        assert pending.provisional_failures == 0 and pending.finalized_misses is None
        assert ctx.combat.response_snapshot()["queue_pending"] > 0
        assert ctx.combat.response_snapshot()["host_authority_verified"] is False
        release_commit.set()
        if requested:
            assert contained.wait(15), (session.snapshot(), session.launch_diagnostics())
            later = next(value for value in snapshots if value.containment_verified_steps)
            assert later.detection_verified_steps >= later.containment_verified_steps
            assert later.evaluated_steps == later.detection_verified_steps
        assert session.finished.wait(60), session.snapshot()
        for worker in session.owned_workers():
            worker.join(timeout=5)
            assert not worker.is_alive()
        assert ctx.combat.response_snapshot()["host_authority_verified"] is False
        assert snapshots and all(value.containment_required is requested for value in snapshots)
    finally:
        release_commit.set()
        session.cancel()
        for worker in session.owned_workers():
            worker.join(timeout=5)
        listener.close()
    assert all(not worker.is_alive() for worker in session.owned_workers())


def test_cancelled_prepared_redteam_retains_exact_evidence_until_signed_diagnostic_and_release(
    controlled_runtime, monkeypatch,
):
    ctx = controlled_runtime
    purple_guard.RedTeamValidationLease.release(ctx.lease)
    ctx.lease = None
    ctx.begin_scan()
    engine = RedTeamEngine(ctx.root)
    monkeypatch.setattr(engine, "_jitter", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sessions.random, "shuffle", lambda _rows: None)
    monkeypatch.setattr(sessions.random, "random", lambda: 1.0)
    session = sessions.SimulationSession(manager=ctx.manager, bus=ctx.bus, recorder=ctx.recorder,
        data_root=ctx.root, red_team_engine=engine, shark_engine=SharkAttackEngine(ctx.root))
    recorded, reported, released = threading.Event(), threading.Event(), threading.Event()
    early_cleanup = []
    actual_record, actual_build = engine._record, session._build_report
    actual_sweep, actual_process_cleanup = engine._sweep_markers, engine._cleanup_probe_processes
    actual_unregister = red_team.unregister_run
    actual_release = purple_guard.RedTeamValidationLease.release

    def record_then_cancel(*args, **kwargs):
        row = actual_record(*args, **kwargs)
        if row.artifact_paths:
            recorded.set()
            session.cancel()
        return row

    def mark_early(operation):
        if recorded.is_set() and not released.is_set():
            early_cleanup.append(operation)

    def release(lease):
        owned = lease is session._active_lease
        if owned:
            assert reported.is_set() and not early_cleanup
            status = session.retirement_snapshot()
            assert status["lease_active"] and not status["custody_released"]
        result = actual_release(lease)
        if owned:
            released.set()  # Only the actual exact release's successful return.
        return result

    def sweep(*args, **kwargs):
        mark_early("markers")
        return actual_sweep(*args, **kwargs)

    def clean_processes():
        mark_early("processes")
        return actual_process_cleanup()

    def unregister(run_id):
        mark_early("run-registration")
        return actual_unregister(run_id)

    def build(prepared):
        assert recorded.is_set() and not early_cleanup
        assert engine._prepared_evidence_is_held()
        assert not session.retirement_snapshot()["custody_released"]
        assert engine._thread is not None and not engine._thread.is_alive()
        assert engine.cancel_evidence_hold() is False
        # An additional STOP hint must also preserve the same held evidence.
        engine.stop_and_clean()
        assert not early_cleanup
        result = actual_build(prepared)
        assert type(result) is aar_report.AARReportResult
        aar_report.verified_aar_handoff_text(result)
        payload = json.loads(result.report_bytes)
        assert payload["diagnostic_only"] is True and payload["coverage_score_eligible"] is False
        assert payload["epistemic_metrics"]["verified_containment"]["count"] == 0
        reported.set()
        return result

    monkeypatch.setattr(engine, "_record", record_then_cancel)
    monkeypatch.setattr(engine, "_sweep_markers", sweep)
    monkeypatch.setattr(engine, "_cleanup_probe_processes", clean_processes)
    monkeypatch.setattr(red_team, "unregister_run", unregister)
    monkeypatch.setattr(purple_guard.RedTeamValidationLease, "release", release)
    monkeypatch.setattr(session, "_build_report", build)
    plan = session.prepare({"run_shark": False, "run_redteam": True,
        "intensity": "Low", "comprehensive": False, "target_dir": str(ctx.target)},
        default_target=ctx.target)
    try:
        assert session.start(plan)
        assert session.finished.wait(60), session.snapshot()
        for worker in session.owned_workers():
            worker.join(timeout=5)
            assert not worker.is_alive()
        assert recorded.is_set() and reported.is_set() and released.is_set(), session.launch_diagnostics()
        assert not early_cleanup and len(session.completed_reports()) == 1
        assert session._active_lease is None and not engine._prepared_evidence_is_held()
        assert session.retirement_snapshot()["custody_released"] is True
        assert ctx.combat.response_snapshot()["host_authority_verified"] is False
    finally:
        session.cancel()
        for worker in session.owned_workers():
            worker.join(timeout=5)
    assert all(not worker.is_alive() for worker in session.owned_workers())
