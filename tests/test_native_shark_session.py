"""Actual native YARA/Combat effects; a local socket remains an explicit gap."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import threading

import pytest

from test_yara_automatic_response import controlled_runtime, _wait_for

from angerona.core import report_attest
from angerona.modules import purple_guard
from angerona.shark import aar_report, shark_attack, simulation_session as sessions
from angerona.shark.red_team import RedTeamEngine
from angerona.shark.shark_attack import SharkAttackEngine


@pytest.mark.parametrize("recipe,suffix", [("html", ".html"), ("pdf-text", ".pdf.txt")])
def test_fixed_new_lures_use_actual_native_scan_and_durable_quarantine(controlled_runtime, recipe, suffix):
    ctx = controlled_runtime
    declaration, path, original = ctx.create_control(recipe, step_id="new-fixed-lure")
    assert str(path).endswith(suffix)
    assert b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in original
    if recipe == "html":
        assert b"<script" not in original and original.startswith(b"<!doctype html>")
    ctx.begin_scan()
    catch = _wait_for(lambda: ctx.detection(path), description="actual native lure detection absent")
    response = _wait_for(lambda: ctx.response(catch), description="actual lure containment absent")
    assert ctx.detector.verify_control_detection_event(catch)
    assert not path.exists()
    assert response.details["postcondition_verified"] is True
    assert ctx.combat.response_snapshot()["host_authority_verified"] is False
    action = next(row for row in ctx.combat.list_actions() if row["target"] == str(path))
    assert action["status"] == "applied" and action["action"] == "quarantine_file"
    assert action["details"]["sha256"] == declaration["identity"]["sha256"]


def test_real_shark_session_reports_native_file_actions_and_preserves_network_gap(
    controlled_runtime, monkeypatch,
):
    ctx = controlled_runtime
    # Retire the unused fixture lease, then let the real session acquire and
    # consume its own exact plan/run lease. Actual producer workers stay live.
    purple_guard.RedTeamValidationLease.release(ctx.lease)
    ctx.lease = None
    ctx.begin_scan()
    engine = SharkAttackEngine(ctx.root, downloads_dir=ctx.target, documents_dir=ctx.target)
    red_team = RedTeamEngine(ctx.root)
    # Discretionary storytelling jitter is unrelated to proof/health/authority.
    monkeypatch.setattr(engine, "_jitter", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sessions.random, "choice", lambda choices: choices[0])
    monkeypatch.setattr(sessions.random, "random", lambda: 1.0)
    received, errors = [], []
    stop_server = threading.Event()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.1)
    monkeypatch.setenv("ANGERONA_SHARK_EXFIL_HOST", "127.0.0.1")
    monkeypatch.setattr(shark_attack, "EXFIL_TEST_PORT", listener.getsockname()[1])

    def serve():
        try:
            while not stop_server.is_set():
                try:
                    connection, _address = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(2)
                    received.append(connection.recv(4096))
                return
        except BaseException as error:
            errors.append(error)

    server = threading.Thread(target=serve, name="owned-local-shark-listener")
    server.start()
    session = sessions.SimulationSession(manager=ctx.manager, bus=ctx.bus, recorder=ctx.recorder,
        data_root=ctx.root, red_team_engine=red_team, shark_engine=engine)
    try:
        plan = session.prepare({"run_shark": True, "run_redteam": False,
            "complexity": 1, "target_dir": str(ctx.target)}, default_target=ctx.target)
        assert session.start(plan)
        assert session.finished.wait(60), session.snapshot()
        for worker in session.owned_workers():
            worker.join(timeout=5)
            assert not worker.is_alive()
        assert session.snapshot()["phase"] == "completed", session.launch_diagnostics()
        reports = session.completed_reports()
        assert len(reports) == 1 and type(reports[0]) is aar_report.AARReportResult
        result = reports[0]
        assert result.run_id == plan.runs[0].run_id == engine.run_id
        aar_report.verified_aar_handoff_text(result)
        payload = json.loads(result.report_bytes)
        assert report_attest.verify(payload) == "ok"
        assert payload["campaign_completeness"]["prepared_run"] == plan.runs[0].manifest()
        assert payload["epistemic_metrics"]["verified_containment"]["count"] == 3
        assert payload["epistemic_metrics"]["verified_containment"]["eligible"] == 4
        assert payload["outcome"] != "verified"
        performance = session.performance_snapshot(engine.run_id)
        assert type(performance) is sessions.RunPerformanceSnapshot
        assert performance.session_generation == plan.generation
        assert performance.plan_sha256 == plan.runs[0].plan_sha256
        assert performance.state == "final" and performance.finalized_misses == 1
        assert performance.final_report_sha256 == result.report_sha256
        network = next(row for row in payload["verdicts"] if row["stage"] == "Exfiltration")
        assert network["target_containment_verified"] is False
        assert received == [shark_attack.EXFIL_MARKER]
        assert ctx.combat.response_snapshot()["host_authority_verified"] is False
        actions = [row for row in ctx.combat.list_actions() if row["status"] == "applied"]
        assert len(actions) == 3 and all(row["action"] == "quarantine_file" for row in actions)
        # Cleanup is not containment evidence; every credited action already
        # has the exact native trigger and durable verified quarantine receipt.
        assert all(row.details.get("trigger_module") == "YARA Scanner"
                   for row in ctx.captured() if row.module == "Adversary Combat"
                   and row.details.get("postcondition_verified") is True)
    finally:
        session.cancel()
        for worker in session.owned_workers():
            worker.join(timeout=5)
        stop_server.set()
        server.join(timeout=5)
        listener.close()
    assert not server.is_alive() and not errors
    assert all(not worker.is_alive() for worker in session.owned_workers())


def test_real_redteam_live_step_evaluator_observes_actual_effects_before_final_report(
    controlled_runtime, monkeypatch,
):
    ctx = controlled_runtime
    purple_guard.RedTeamValidationLease.release(ctx.lease)
    ctx.lease = None
    ctx.begin_scan()
    engine = RedTeamEngine(ctx.root)
    monkeypatch.setattr(engine, "_jitter", lambda *_args, **_kwargs: None)
    session = sessions.SimulationSession(manager=ctx.manager, bus=ctx.bus, recorder=ctx.recorder,
        data_root=ctx.root, red_team_engine=engine, shark_engine=SharkAttackEngine(ctx.root))
    provisional = []
    original_note = session._note_redteam_performance

    def retain_actual_observation(observer, identifier, verdict, settled_negative):
        original_note(observer, identifier, verdict, settled_negative)
        provisional.append(session.performance_snapshot(observer.prepared.run_id))

    monkeypatch.setattr(session, "_note_redteam_performance", retain_actual_observation)
    plan = session.prepare({"run_shark": False, "run_redteam": True, "intensity": "Low",
        "comprehensive": False, "target_dir": str(ctx.target)}, default_target=ctx.target)
    try:
        assert session.start(plan)
        assert session.finished.wait(90), session.snapshot()
        for worker in session.owned_workers():
            worker.join(timeout=5)
            assert not worker.is_alive()
        measured = [item for item in provisional if item is not None and item.state == "provisional"]
        assert measured, session.launch_diagnostics()
        assert any(item.detection_verified_steps > 0 and item.containment_verified_steps > 0 for item in measured)
        for item in measured:
            assert item.session_id == plan.session_id and item.session_generation == plan.generation
            assert item.run_id == plan.runs[0].run_id and item.plan_sha256 == plan.runs[0].plan_sha256
            assert item.finalized_misses is None and item.final_report_sha256 is None
            assert item.evaluated_steps <= item.eligible_planned
            assert item.containment_verified_steps <= item.detection_verified_steps
            assert item.detection_verified_steps <= item.evaluated_steps
        assert ctx.combat.response_snapshot()["host_authority_verified"] is False
    finally:
        session.cancel()
        for worker in session.owned_workers():
            worker.join(timeout=5)
        engine.stop_and_clean()
    assert all(not worker.is_alive() for worker in session.owned_workers())
