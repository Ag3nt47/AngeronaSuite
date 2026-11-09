"""Final real producer work precedes response-queue settlement.

Scheduling-only cases use explicit inert seams. The Windows graph cases retain
the real issuer, producer, signed event and native file response boundaries.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import queue
import threading
import time
from types import SimpleNamespace

import pytest

from test_redteam_fix_pipeline import source_canary

from angerona.core.practice_verification import _write_registered_marker
from angerona.modules import adversary_combat, purple_guard
from angerona.shark import simulation_session as sessions


def _wait(predicate, *, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        threading.Event().wait(0.01)
    assert predicate(), "The exact owned scheduling boundary was not reached"


def _session(ctx):
    session = sessions.SimulationSession(manager=ctx.manager, bus=ctx.bus, recorder=ctx.recorder,
        data_root=ctx.root, red_team_engine=None, shark_engine=None)
    session._active_lease = ctx.lease
    # This direct scheduling fixture supplies no prepared-run/AAR verdict. Its
    # real lease, detector receipt and native response still verify normally.
    session._workflow_current_budget = replace(sessions._workflow_settlement_budget(), run_id=ctx.run_id)
    session._run_deadline = time.monotonic() + sessions._WORKFLOW_SETTLEMENT_FLOOR_SECONDS
    return session


def test_old_glob_and_queue_gap_cannot_end_final_producer_settlement(source_canary, monkeypatch):
    ctx = source_canary
    old_started, release_old = threading.Event(), threading.Event()
    fresh_started, release_fresh = threading.Event(), threading.Event()
    requested, completed = threading.Event(), threading.Event()
    response_entered, release_response = threading.Event(), threading.Event()
    target = ctx.marker.parent
    original_glob = Path.glob
    original_request = purple_guard.PurpleGuard.request_fresh_observation
    original_complete = purple_guard.PurpleGuard._complete_fresh_observation
    original_handle = ctx.combat._handle
    original_submit = adversary_combat.AdversaryCombat._submit.__get__(ctx.combat)
    snapshots = []
    tokens = []
    late = target / f"_redteam_lsass_dump_late_{ctx.run_id}.txt"

    def snapshot_then_pause(path, pattern, *args, **kwargs):
        result = list(original_glob(path, pattern, *args, **kwargs))
        if (threading.current_thread() is ctx.guard._thread and path == target
                and pattern == "_redteam_*.txt" and len(snapshots) < 2):
            snapshots.append(tuple(result))
            started, release = ((old_started, release_old) if len(snapshots) == 1
                                else (fresh_started, release_fresh))
            started.set()
            assert release.wait(10.0), "Fixture must release its actual producer scan"
        return iter(result)

    def observe_request(producer, lease, *, run_id):
        token = original_request(producer, lease, run_id=run_id)
        if producer is ctx.guard:
            tokens.append(token)
            requested.set()
        return token

    def observe_completion(producer, request, generation, lease):
        original_complete(producer, request, generation, lease)
        if producer is ctx.guard and request is not None:
            if purple_guard.PurpleGuard.fresh_observation_complete(
                    producer, request[0], lease, run_id=ctx.run_id):
                completed.set()

    def hold_actual_response(event):
        if event.details.get("path") == str(late):
            response_entered.set()
            assert release_response.wait(10.0), "Fixture must release its admitted response"
        return original_handle(event)

    monkeypatch.setattr(Path, "glob", snapshot_then_pause)
    monkeypatch.setattr(purple_guard.PurpleGuard, "request_fresh_observation", observe_request)
    monkeypatch.setattr(purple_guard.PurpleGuard, "_complete_fresh_observation", observe_completion)
    monkeypatch.setattr(ctx.combat, "_submit", original_submit)
    monkeypatch.setattr(ctx.combat, "_handle", hold_actual_response)
    ctx.guard._process_wake.set()
    result, errors = [], []
    session = _session(ctx)
    expiry = session._run_deadline

    def settle():
        try:
            result.append(session._settle_admitted_responses())
        except BaseException as error:
            errors.append(error)

    owner = threading.Thread(target=settle, name="owned-final-producer-settlement")
    try:
        assert old_started.wait(5.0)
        original_serial = ctx.guard.validation_cycle_snapshot()["serial"]
        _write_registered_marker(late, "ANGERONA inert late final control\n", ctx.run_id, lease=ctx.lease)
        assert late not in snapshots[0]
        # This is the original erroneous completion predicate: it is true even
        # though the real producer has not observed the final registered file.
        assert ctx.combat.response_snapshot()["queue_pending"] == 0 and late.exists()
        owner.start()
        assert requested.wait(5.0) and tokens[0] is not None
        assert owner.is_alive() and not result
        release_old.set()
        assert fresh_started.wait(5.0)
        assert late in snapshots[1]
        assert ctx.guard.validation_cycle_snapshot()["serial"] > original_serial
        # The older completed cycle must not acknowledge the newer request.
        assert purple_guard.PurpleGuard.fresh_observation_state(
            ctx.guard, tokens[0], ctx.lease, run_id=ctx.run_id) == "pending"
        assert owner.is_alive() and not result
        release_fresh.set()
        assert response_entered.wait(5.0) and completed.wait(5.0)
        assert ctx.combat.response_snapshot()["queue_pending"] > 0
        assert owner.is_alive() and not result
        release_response.set()
        owner.join(timeout=10.0)
        assert not owner.is_alive() and not errors and result == [True]
        assert not late.exists()
        assert ctx.combat.response_snapshot()["queue_pending"] == 0
        assert session._run_deadline == expiry
        record = session.workflow_settlement_snapshot(ctx.run_id)
        assert record["outcome"] == "drained" and record["producer_observation_state"] == "complete"
        detection = next(event for event in ctx.bus.recent(500)
                         if event.module == ctx.guard.name and event.details.get("path") == str(late))
        assert ctx.bus.verify(detection)
        response = next(event for event in ctx.bus.recent(500)
                        if event.module == ctx.combat.name
                        and event.details.get("trigger_event_digest") == detection.hmac_sig)
        assert ctx.bus.verify(response) and response.details["postcondition_verified"] is True
    finally:
        for signal in (release_old, release_fresh, release_response):
            signal.set()
        if owner.ident is not None:
            owner.join(timeout=10.0)
        assert not owner.is_alive()


def test_complete_ack_is_observed_before_response_queue_snapshot(tmp_path, monkeypatch):
    """A stale zero read before the final producer acknowledgment is unsafe."""
    work = queue.Queue()
    combat = object.__new__(adversary_combat.AdversaryCombat)
    combat._lifecycle_generation = 1
    session = sessions.SimulationSession(manager=SimpleNamespace(modules={"Adversary Combat": combat}),
        bus=None, recorder=None, data_root=tmp_path, red_team_engine=None, shark_engine=None)
    clock, calls = [100.0], []
    token = object()
    monkeypatch.setattr(session, "_begin_final_producer_observation", lambda _: token)

    def state(actual):
        assert actual is token
        if "producer" not in calls:
            work.put(object())
            work.get_nowait()
            calls.append("producer")
        return "complete"

    def snapshot(_):
        calls.append("queue")
        return {"queue_pending": work.unfinished_tasks}

    def sleep(seconds):
        assert 0 < seconds <= 0.1
        calls.append("wait")
        clock[0] += seconds
        if work.unfinished_tasks:
            work.task_done()

    monkeypatch.setattr(session, "_final_producer_observation_state", state)
    monkeypatch.setattr(adversary_combat.AdversaryCombat, "response_snapshot", snapshot)
    monkeypatch.setattr(sessions, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep))
    session._run_deadline = 101.0
    assert session._settle_admitted_responses() is True
    assert calls[:2] == ["producer", "queue"]
    assert "wait" in calls and work.unfinished_tasks == 0
    assert session._run_deadline == 101.0


def test_final_token_retries_same_generation_after_transient_scope_hold(source_canary, monkeypatch):
    ctx = source_canary
    original = purple_guard.RedTeamValidationLease._state_matches
    checks = []

    def transient(lease):
        if lease is ctx.lease and threading.current_thread() is ctx.guard._thread:
            checks.append(True)
            if len(checks) == 1:
                return False  # Explicit inert transient scope-check refusal.
        return original(lease)

    monkeypatch.setattr(purple_guard.RedTeamValidationLease, "_state_matches", transient)
    request = purple_guard.PurpleGuard.request_fresh_observation(ctx.guard, ctx.lease, run_id=ctx.run_id)
    assert request is not None
    _wait(lambda: purple_guard.PurpleGuard.fresh_observation_complete(
        ctx.guard, request, ctx.lease, run_id=ctx.run_id))
    assert len(checks) >= 2
    assert request[0] == ctx.guard.lifecycle_generation


def test_final_scope_check_serializes_with_actual_marker_handoff(source_canary, monkeypatch):
    ctx = source_canary
    state = purple_guard._lease_authority(ctx.lease)
    check = purple_guard.RedTeamValidationLease._state_matches
    probes, owners, failures = [], [], []
    probed, action_done = threading.Event(), threading.Event()

    def competing_handoff():
        try:
            acquired = state.lock.acquire(blocking=False)
            probes.append(acquired)
            if acquired:
                state.lock.release()
            probed.set()
            ctx.combat._handle(ctx.event)  # Original signed/native action.
        except BaseException as error:
            failures.append(error)
        finally:
            action_done.set()

    def check_with_competing_writer(lease):
        if lease is ctx.lease and threading.current_thread() is ctx.guard._thread and not owners:
            owner = threading.Thread(target=competing_handoff, name="owned-competing-marker-handoff")
            owners.append(owner)
            owner.start()
            assert probed.wait(3.0)
            # Deterministic nonblocking observation: the final checker already
            # owns the actual issuer lock, so the handoff cannot enter it yet.
            assert probes == [False]
            assert not action_done.is_set() and ctx.marker.exists()
        return check(lease)

    monkeypatch.setattr(purple_guard.RedTeamValidationLease, "_state_matches", check_with_competing_writer)
    request = purple_guard.PurpleGuard.request_fresh_observation(ctx.guard, ctx.lease, run_id=ctx.run_id)
    assert request is not None
    try:
        _wait(lambda: purple_guard.PurpleGuard.fresh_observation_complete(
            ctx.guard, request, ctx.lease, run_id=ctx.run_id))
        assert action_done.wait(5.0)
        assert not failures and probes == [False] and not ctx.marker.exists()
        response = next(event for event in ctx.bus.recent(500)
                        if event.module == ctx.combat.name
                        and event.details.get("trigger_event_digest") == ctx.event.hmac_sig)
        assert ctx.bus.verify(response) and response.details["postcondition_verified"] is True
    finally:
        for owner in owners:
            owner.join(timeout=10.0)
            assert not owner.is_alive()


def test_real_producer_cycle_exception_cannot_acknowledge_final_work(source_canary, monkeypatch):
    ctx = source_canary
    consumed, failed = threading.Event(), threading.Event()
    begin = purple_guard.PurpleGuard._begin_fresh_observation
    policy = ctx.guard._policy_snapshot

    def observe_begin(producer, generation, lease):
        request = begin(producer, generation, lease)
        if producer is ctx.guard and request is not None:
            consumed.set()
        return request

    def fail_requested_cycle():
        if threading.current_thread() is ctx.guard._thread and consumed.is_set():
            failed.set()
            raise RuntimeError("Inert requested producer-cycle failure")
        return policy()

    monkeypatch.setattr(purple_guard.PurpleGuard, "_begin_fresh_observation", observe_begin)
    monkeypatch.setattr(ctx.guard, "_policy_snapshot", fail_requested_cycle)
    request = purple_guard.PurpleGuard.request_fresh_observation(ctx.guard, ctx.lease, run_id=ctx.run_id)
    assert request is not None and failed.wait(5.0)
    try:
        _wait(lambda: ctx.guard.status == "restarting")
        assert purple_guard.PurpleGuard.fresh_observation_state(
            ctx.guard, request, ctx.lease, run_id=ctx.run_id) == "unavailable"
        assert not purple_guard.PurpleGuard.fresh_observation_complete(
            ctx.guard, request, ctx.lease, run_id=ctx.run_id)
        with ctx.guard._observation_request_lock:
            assert ctx.guard._pending_observation_request[0] == request
        session = _session(ctx)
        assert session._settle_admitted_responses() is False
        assert session.workflow_settlement_snapshot(ctx.run_id)["outcome"] == "unavailable"
    finally:
        # Retire before BaseModule's normal retry delay. The induced exception
        # neither changes its retry policy nor exhausts it into a crash dump.
        ctx.guard.stop()
        ctx.guard._thread.join(timeout=5.0)
        assert not ctx.guard._thread.is_alive()


def test_same_final_token_survives_real_worker_retry_without_deadline_renewal(source_canary, monkeypatch):
    ctx = source_canary
    begin = purple_guard.PurpleGuard._begin_fresh_observation
    policy = ctx.guard._policy_snapshot
    consumed, failed = threading.Event(), threading.Event()
    attempts = []

    def observe_begin(producer, generation, lease):
        request = begin(producer, generation, lease)
        if producer is ctx.guard and request is not None:
            consumed.set()
            attempts.append(request[0])
        return request

    def fail_once():
        if threading.current_thread() is ctx.guard._thread and consumed.is_set() and not failed.is_set():
            failed.set()
            raise RuntimeError("Inert one-time requested producer failure")
        return policy()

    original_expiry = purple_guard._lease_authority(ctx.lease).run_deadline_monotonic
    monkeypatch.setattr(purple_guard.PurpleGuard, "_begin_fresh_observation", observe_begin)
    monkeypatch.setattr(ctx.guard, "_policy_snapshot", fail_once)
    request = purple_guard.PurpleGuard.request_fresh_observation(ctx.guard, ctx.lease, run_id=ctx.run_id)
    assert request is not None and failed.wait(5.0)
    _wait(lambda: ctx.guard.status == "restarting")
    assert not purple_guard.PurpleGuard.fresh_observation_complete(
        ctx.guard, request, ctx.lease, run_id=ctx.run_id)
    _wait(lambda: purple_guard.PurpleGuard.fresh_observation_complete(
        ctx.guard, request, ctx.lease, run_id=ctx.run_id), timeout=10.0)
    assert len(attempts) >= 2 and all(token == request for token in attempts)
    assert purple_guard._lease_authority(ctx.lease).run_deadline_monotonic == original_expiry


def test_final_observation_rejects_fake_or_replaced_graph_and_generation(source_canary, monkeypatch):
    ctx = source_canary
    session = _session(ctx)
    observation = session._begin_final_producer_observation(ctx.run_id)
    assert observation is not None
    producer, token, lease, run_id = observation
    assert producer is ctx.guard and lease is ctx.lease and run_id == ctx.run_id
    for invalid in (None, (), (True, 1), (token[0], "1"), (-1, 1)):
        assert purple_guard.PurpleGuard.fresh_observation_state(
            producer, invalid, lease, run_id=run_id) == "unavailable"
    assert session._begin_final_producer_observation("wrong-run") is None
    with monkeypatch.context() as change:
        change.setitem(ctx.manager.modules, producer.name, SimpleNamespace())
        assert session._final_producer_observation_state(observation) == "unavailable"
        assert session._begin_final_producer_observation(run_id) is None
    with monkeypatch.context() as change:
        change.setattr(session, "_active_lease", object())
        assert session._final_producer_observation_state(observation) == "unavailable"
        assert session._begin_final_producer_observation(run_id) is None
    old_generation = token[0]
    worker = ctx.guard._thread
    ctx.guard.stop()
    worker.join(timeout=5.0)
    assert not worker.is_alive()
    ctx.guard.start()
    assert ctx.guard.lifecycle_generation > old_generation
    assert session._final_producer_observation_state(observation) == "unavailable"
    assert session._begin_final_producer_observation(run_id) is None


@pytest.mark.parametrize("mode", ["missing", "pending-expired", "faulted"])
def test_unavailable_or_unfinished_producer_never_fakes_empty_queue_success(tmp_path, monkeypatch, mode):
    combat = object.__new__(adversary_combat.AdversaryCombat)
    combat._lifecycle_generation = 1
    session = sessions.SimulationSession(manager=SimpleNamespace(modules={"Adversary Combat": combat}),
        bus=None, recorder=None, data_root=tmp_path, red_team_engine=None, shark_engine=None)
    clock = [100.0]
    monkeypatch.setattr(adversary_combat.AdversaryCombat, "response_snapshot", lambda _: {"queue_pending": 0})
    if mode != "missing":
        monkeypatch.setattr(session, "_begin_final_producer_observation", lambda _: object())
        if mode == "faulted":
            monkeypatch.setattr(session, "_final_producer_observation_state",
                                lambda _: (_ for _ in ()).throw(RuntimeError("inert worker fault")))
        else:
            monkeypatch.setattr(session, "_final_producer_observation_state", lambda _: "pending")
    monkeypatch.setattr(sessions, "time", SimpleNamespace(monotonic=lambda: clock[0],
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds)))
    session._run_deadline = 100.2
    assert session._settle_admitted_responses() is False
    record = session.workflow_settlement_snapshot("")
    assert record["outcome"] == ("expired" if mode == "pending-expired" else "unavailable")
    assert record["responses_drained"] is False and record["pending"] == 0
    assert session._run_deadline == 100.2


@pytest.mark.parametrize("change,boundary", [
    ("registry", "producer"), ("generation", "producer"),
    ("registry", "snapshot"), ("generation", "snapshot"),
])
def test_replaced_combat_cannot_supply_settlement_from_its_old_empty_queue(
    tmp_path, monkeypatch, change, boundary,
):
    combat = object.__new__(adversary_combat.AdversaryCombat)
    combat._lifecycle_generation = 1
    replacement = object.__new__(adversary_combat.AdversaryCombat)
    replacement._lifecycle_generation = 1
    manager = SimpleNamespace(modules={"Adversary Combat": combat})
    session = sessions.SimulationSession(manager=manager, bus=None, recorder=None,
        data_root=tmp_path, red_team_engine=None, shark_engine=None)
    session._run_deadline = time.monotonic() + 1.0
    original_deadline = session._run_deadline
    snapshots = []
    monkeypatch.setattr(session, "_begin_final_producer_observation", lambda _: object())

    def replace_owner():
        if change == "registry":
            manager.modules["Adversary Combat"] = replacement
        else:
            combat._lifecycle_generation = 2

    def producer(_):
        if boundary == "producer":
            replace_owner()
        return "complete"

    def snapshot(owner):
        snapshots.append(owner)
        if boundary == "snapshot":
            replace_owner()
        return {"queue_pending": 0}

    monkeypatch.setattr(session, "_final_producer_observation_state", producer)
    monkeypatch.setattr(adversary_combat.AdversaryCombat, "response_snapshot", snapshot)
    assert session._settle_admitted_responses() is False
    assert session.workflow_settlement_snapshot("")["outcome"] == "unavailable"
    assert snapshots == ([combat] if boundary == "snapshot" else [])
    assert session._run_deadline == original_deadline
