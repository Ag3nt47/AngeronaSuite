"""Real Purple/FIM receipts with delayed delivery, never fabricated native proof."""
from __future__ import annotations

import json
import threading
import time
import uuid

import pytest

from test_yara_automatic_response import controlled_runtime as controlled_runtime, _wait_for

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.module_base import BaseModule
from angerona.core.module_contract import build_capability_contract
from angerona.modules import purple_guard
from angerona.modules.file_integrity import FileIntegrityModule
from angerona.shark import aar_report, simulation_session as sessions
from angerona.shark.red_team import RedTeamEngine
from angerona.shark.shark_attack import SharkAttackEngine


@pytest.mark.parametrize("order", ["raw-before-native", "simulation-before-native", "late-after-finalization"])
def test_genuine_native_upgrade_arrives_before_held_commit_without_losing_union(
    controlled_runtime, monkeypatch, order,
):
    ctx = controlled_runtime
    purple_guard.RedTeamValidationLease.release(ctx.lease)
    ctx.lease = None
    ctx.begin_scan()
    monkeypatch.setenv("ANGERONA_FIM_WATCH_ONLY", str(ctx.target))
    fim = FileIntegrityModule()
    fim.bind(ctx.bus)
    fim._angerona_origin = "builtin"
    fim._angerona_trust = "release"
    fim._angerona_contract = build_capability_contract(fim,
        capability_id="angerona.builtin.file_integrity", origin="builtin", trust="release", publisher="Angerona")
    ctx.manager.modules[fim.name] = fim
    binder = getattr(fim, "bind_manager", None)
    if callable(binder):
        binder(ctx.manager)
    binder = getattr(fim, "bind_recorder", None)
    if callable(binder):
        binder(ctx.recorder)
    engine = RedTeamEngine(ctx.root)
    monkeypatch.setattr(engine, "_jitter", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sessions.random, "shuffle", lambda _rows: None)
    monkeypatch.setattr(sessions.random, "random", lambda: 1.0)
    session = sessions.SimulationSession(manager=ctx.manager, bus=ctx.bus, recorder=ctx.recorder,
        data_root=ctx.root, red_team_engine=engine, shark_engine=SharkAttackEngine(ctx.root))
    before_effect, permit_effect, commit_entered, permit_commit = (threading.Event() for _ in range(4))
    step_submitted, permit_engine, raw_turn = (threading.Event() for _ in range(3))
    capture_lock = threading.Lock()
    held = {"simulation": [], "native": [], "row": None, "raw": None, "capture_error": ""}
    raw_nonce = uuid.uuid4().hex
    budget_lock, budget_deadline = threading.Lock(), [None]
    snapshots = []
    original_capture = sessions.RedTeamRunObserver._capture_event
    original_drain = sessions.RedTeamRunObserver.drain
    actual_quarantine, actual_commit = ctx.combat._quarantine_file, ctx.combat._commit_after_mutation
    actual_record, actual_note = engine._record, session._note_redteam_performance
    actual_finish_unit = engine._progress.finish_unit

    def remaining(cap=10):
        # The first owned gate starts the EXISTING ten-second finite budget.
        # Every following proof/effect/commit wait shares it; no serial wait
        # receives a fresh ten seconds while another real worker is held.
        with budget_lock:
            if budget_deadline[0] is None:
                budget_deadline[0] = time.monotonic() + 10
            value = budget_deadline[0] - time.monotonic()
        assert value > 0, ("shared event-order budget expired", session.snapshot())
        return min(cap, value)

    def wait_event(event, label, cap=10):
        assert event.wait(remaining(cap)), (label, session.snapshot(), session.launch_diagnostics())

    def wait_value(predicate, label):
        return _wait_for(predicate, description=label, timeout=remaining())

    def current_event(observer, event):
        details = event.details or {}
        return (observer.owner is session and details.get("run_id") == observer.prepared.run_id
                and details.get("lease_id") == observer._lease_id)

    def matching_receipt(category, observer, row):
        with capture_lock:
            assert not held["capture_error"], held["capture_error"]
            return next((event for event in held[category]
                if current_event(observer, event) and
                (event.details.get("path") or event.details.get("artifact_path")) in row.artifact_paths), None)

    def capture(observer, event):
        details = event.details or {}
        category = ("native" if event.module == fim.name and details.get("evidence_type") == "native_analytic_detection"
                    else "simulation" if event.module == ctx.guard.name
                    and details.get("evidence_type") == "simulation_contract_validation" else None)
        if category and current_event(observer, event):
            # Only delivery into this observer is delayed. These are original
            # events emitted by actual owner threads, with unmodified receipts;
            # the real recorder/Combat subscribers still receive them normally.
            with capture_lock:
                if len(held[category]) >= 8:
                    held["capture_error"] = "bounded current-run delayed-event capture overflow"
                else:
                    held[category].append(event)
            return
        with capture_lock:
            row = held["row"]
        if (row is not None and current_event(observer, event)
                and details.get("event_nonce") == raw_nonce
                and details.get("path") in row.artifact_paths
                and details.get("response_authorized") is False):
            # EventBus intentionally replaces/signs the caller's prototype.
            # Retain the actual sealed subscriber object, not that prototype.
            with capture_lock:
                held["raw"] = event
        original_capture(observer, event)

    def drain(observer, *, final=False):
        result = original_drain(observer, final=final)
        with capture_lock:
            raw = held["raw"]
        if raw is not None:
            with observer._lock:
                delivered = any(event is raw for event in observer._events)
            if delivered:
                assert threading.current_thread() is session.thread
                raw_turn.set()
        return result

    def record_one(*args, **kwargs):
        result = actual_record(*args, **kwargs)
        if result.artifact_paths:
            with capture_lock:
                held["row"] = result
        return result

    def finish_unit(*args, **kwargs):
        result = actual_finish_unit(*args, **kwargs)
        with capture_lock:
            row = held["row"]
        if row is None:
            return result  # The real optional-noise decision precedes the step.
        observer = session._active_redteam_observer
        assert observer is not None and threading.current_thread() is engine._thread
        with observer._lock:
            assert row.plan_step_id in observer._seen
        # The ORIGINAL engine called capture_completed_steps at its required
        # code site before this existing progress seam. Keep that engine alive
        # while the ORIGINAL Session loop continues to drain actual evidence.
        step_submitted.set()
        if not permit_engine.is_set():
            assert permit_engine.wait(remaining()), "test did not release the post-submission engine gate"
        return result

    def quarantine(raw_path, event, combat_id):
        observer = session._active_redteam_observer
        if observer is not None and current_event(observer, event):
            before_effect.set()
            if not permit_effect.is_set():
                assert permit_effect.wait(remaining()), "test did not release the genuine pre-effect gate"
        return actual_quarantine(raw_path, event, combat_id)

    def commit(action, **kwargs):
        with capture_lock:
            row = held["row"]
        if row is not None and action.target in row.artifact_paths:
            commit_entered.set()
            if not permit_commit.is_set():
                assert permit_commit.wait(remaining()), "test did not release the genuine durable commit"
        return actual_commit(action, **kwargs)

    def note(observer, identifier, verdict, settled_negative):
        actual_note(observer, identifier, verdict, settled_negative)
        snapshots.append(session.performance_snapshot(observer.prepared.run_id))

    monkeypatch.setattr(sessions.RedTeamRunObserver, "_capture_event", capture)
    monkeypatch.setattr(sessions.RedTeamRunObserver, "drain", drain)
    monkeypatch.setattr(engine, "_record", record_one)
    monkeypatch.setattr(engine._progress, "finish_unit", finish_unit)
    monkeypatch.setattr(ctx.combat, "_quarantine_file", quarantine)
    monkeypatch.setattr(ctx.combat, "_commit_after_mutation", commit)
    monkeypatch.setattr(session, "_note_redteam_performance", note)
    fim_thread = None
    try:
        fim.start()
        fim_thread = fim._thread
        _wait_for(lambda: BaseModule.operational_snapshot(fim)["first_cycle_complete"],
                  description="actual scoped FIM initial cycle did not complete")
        assert fim._last_scan_receipt["complete"] is True
        plan = session.prepare({"run_redteam": True, "run_shark": False, "intensity": "Low",
            "comprehensive": False, "auto_remediate": True, "target_dir": str(ctx.target)},
            default_target=ctx.target)
        assert session.start(plan)
        # Startup retains its existing ten-second bound. Once an owned gate
        # starts, every ordering/response assertion uses the shared deadline.
        assert step_submitted.wait(10), (session.snapshot(), session.launch_diagnostics())
        wait_event(before_effect, "actual current-run response did not reach its pre-effect gate")
        observer = session._active_redteam_observer
        assert observer is not None and session.thread.is_alive() and engine._thread.is_alive()
        with capture_lock:
            row = held["row"]
        assert row is not None
        with observer._lock:
            assert row.plan_step_id in observer._seen
        if order == "late-after-finalization":
            simulation = wait_value(lambda: matching_receipt("simulation", observer, row),
                "actual current-run Purple receipt absent")
            native = wait_value(lambda: matching_receipt("native", observer, row),
                "actual current-run scoped FIM receipt absent")
            assert EventBus.verify(ctx.bus, simulation) and EventBus.verify(ctx.bus, native)
            # Deliberately finalize the one-probe cancelled campaign without
            # delivering either original analytic event to the live observer.
            engine._cancel.set()
            permit_effect.set()
            permit_commit.set()
            permit_engine.set()
            assert session.finished.wait(60), session.snapshot()
            for worker in session.owned_workers():
                worker.join(timeout=5)
                assert not worker.is_alive()
            report, = session.completed_reports()
            aar_report.verified_aar_handoff_text(report)
            payload = json.loads(report.report_bytes)
            assert payload["diagnostic_only"] is True and payload["coverage_score_eligible"] is False
            before = session.performance_snapshot(plan.runs[0].run_id)
            assert before.state == "unverified" and before.finalized_misses is None
            assert before.detection_verified_steps == before.native_verified_steps == before.simulation_verified_steps == 0
            assert before.containment_verified_steps == 0
            # Model an already copied subscriber callback completing after
            # unsubscribe. No event is re-signed/re-published or invented.
            original_capture(observer, simulation)
            original_capture(observer, native)
            assert session.performance_snapshot(plan.runs[0].run_id) == before
            assert session.completed_reports()[0].report_sha256 == report.report_sha256
            assert session.retirement_snapshot()["custody_released"] is True
            return
        if order == "raw-before-native":
            prototype = Event("Test Raw Observation", "Observation without detector authority", Severity.INFO,
                details={"path": row.artifact_paths[0], "lease_id": observer._lease_id,
                         "run_id": observer.prepared.run_id, "event_nonce": raw_nonce,
                         "evidence_type": "sensor_observation", "detector_verdict": "observed",
                         "response_authorized": False})
            EventBus.publish(ctx.bus, prototype)
            wait_event(raw_turn, "sealed raw observation was not drained by the actual Session owner", cap=5)
            with capture_lock:
                raw = held["raw"]
            assert raw is not None and raw is not prototype
            assert not prototype.hmac_sig
            assert EventBus.verify(ctx.bus, raw)
            assert raw.details["event_nonce"] == raw_nonce and raw.details["run_id"] == observer.prepared.run_id
            assert raw.details["lease_id"] == observer._lease_id and raw.details["path"] in row.artifact_paths
            assert raw.details["response_authorized"] is False
            snapshot = session.performance_snapshot(plan.runs[0].run_id)
            assert snapshot.detection_verified_steps == snapshot.native_verified_steps == 0
        else:
            simulation = wait_value(lambda: matching_receipt("simulation", observer, row),
                "actual current-run Purple receipt absent")
            assert EventBus.verify(ctx.bus, simulation)
            original_capture(observer, simulation)
            first = wait_value(lambda: next((value for value in snapshots
                if value.simulation_verified_steps == 1 and value.native_verified_steps == 0), None),
                "actual simulation proof was not independently evaluated")
            assert first.detection_verified_steps == first.evaluated_steps == 1
            assert first.containment_verified_steps == 0
        native = wait_value(lambda: matching_receipt("native", observer, row),
            "actual current-run scoped FIM analytic receipt absent")
        assert EventBus.verify(ctx.bus, native)
        assert native.details["evidence_type"] == "native_analytic_detection"
        original_capture(observer, native)
        upgraded = wait_value(lambda: next((value for value in snapshots if value.native_verified_steps == 1), None),
            "new original native proof was blocked behind an earlier observation")
        assert upgraded.detection_verified_steps == upgraded.evaluated_steps == 1
        assert upgraded.containment_verified_steps == 0 and upgraded.finalized_misses is None
        assert upgraded.simulation_verified_steps == int(order == "simulation-before-native")
        if order == "raw-before-native":
            # The real response was triggered by Purple. Deliver that actual
            # original trigger only AFTER the raw->native ordering assertion,
            # so strict durable containment can be attributed without inventing
            # a response trigger or changing any verifier requirement.
            simulation = wait_value(lambda: matching_receipt("simulation", observer, row),
                "actual current-run Purple response trigger absent")
            assert EventBus.verify(ctx.bus, simulation)
            original_capture(observer, simulation)
        union = wait_value(lambda: next((value for value in snapshots
            if value.native_verified_steps == value.simulation_verified_steps == 1), None),
            "actual analytic planes did not preserve their one-step union")
        assert union.detection_verified_steps == union.evaluated_steps == 1
        permit_effect.set()
        wait_event(commit_entered, "actual durable commit was not reached")
        during_commit = session.performance_snapshot(plan.runs[0].run_id)
        assert during_commit.native_verified_steps == during_commit.detection_verified_steps == 1
        assert during_commit.containment_verified_steps == 0
        assert ctx.combat.response_snapshot()["queue_pending"] > 0
        assert ctx.combat.response_snapshot()["host_authority_verified"] is False
        permit_commit.set()
        contained = wait_value(lambda: next((value for value in snapshots
            if value.containment_verified_steps == 1), None),
            "actual original durable containment proof did not arrive")
        assert contained.native_verified_steps == contained.simulation_verified_steps == 1
        assert contained.detection_verified_steps == contained.evaluated_steps == 1
        assert contained.finalized_misses is None
        # No further probe starts until all ordered real-evidence assertions
        # have settled. Cancel this one-probe run, then release the owner seam.
        engine._cancel.set()
        permit_engine.set()
        assert session.finished.wait(60), session.snapshot()
        for worker in session.owned_workers():
            worker.join(timeout=5)
            assert not worker.is_alive()
        assert len(session.completed_reports()) == 1, session.launch_diagnostics()
        aar_report.verified_aar_handoff_text(session.completed_reports()[0])
        payload = json.loads(session.completed_reports()[0].report_bytes)
        assert payload["diagnostic_only"] is True and payload["coverage_score_eligible"] is False
        assert all(value.detection_verified_steps <= 1 and value.native_verified_steps <= 1 for value in snapshots)
        assert session.retirement_snapshot()["custody_released"] is True
    finally:
        permit_effect.set()
        permit_commit.set()
        permit_engine.set()
        session.cancel()
        for worker in session.owned_workers():
            worker.join(timeout=5)
        fim.stop()
        if fim_thread is not None:
            fim_thread.join(timeout=10)
            assert not fim_thread.is_alive()
    assert all(not worker.is_alive() for worker in session.owned_workers())
