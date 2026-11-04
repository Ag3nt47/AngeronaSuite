"""Real issuer/worker/native file tests for queued re-observation, never TTL renewal."""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import threading
import time
from types import SimpleNamespace

import pytest

from test_redteam_fix_pipeline import source_canary

from angerona.core import module_base
from angerona.core.practice_verification import _publish_process_probe, _retire_process, _write_registered_marker
from angerona.core.response_proof import event_proof_digest
from angerona.modules import adversary_combat as combat, purple_guard as purple


class _PastWall:
    """Only the two initial producer wall clocks; no native/monotonic override."""
    def __init__(self, seconds):
        self.seconds = seconds

    def time(self):
        return time.time() - self.seconds

    def __getattr__(self, name):
        return getattr(time, name)


def _wait(predicate, message, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        threading.Event().wait(0.01)
    assert predicate(), message


@pytest.fixture
def queued_graph(request, monkeypatch):
    age = getattr(request, "param", 21)
    # Attestation's observed_at and BaseModule.emit's Event.ts are genuinely
    # minted/signed on the controlled old wall clock. Restore it before any
    # request or fresh producer observation; no receipt verifier is replaced.
    with monkeypatch.context() as clocks:
        clocks.setattr(purple, "time", _PastWall(min(age, 21)))
        clocks.setattr(module_base, "time", _PastWall(min(age, 21)))
        ctx = request.getfixturevalue("source_canary")
    assert ctx.bus.verify(ctx.event)
    assert ctx.event.details["redteam_detector_receipt_version"] == 2
    assert ctx.event.details["evidence_kind"] == "inert_file_marker"
    assert abs(ctx.event.ts - ctx.event.details["observed_at"]) < 1
    assert ctx.combat._thread.is_alive() and ctx.guard._thread.is_alive()
    producer_parked, producer_release = threading.Event(), threading.Event()
    actual_cycle = ctx.guard.work_cycle

    def parked_cycle():
        producer_parked.set()
        assert producer_release.wait(15), "Test must release its exact producer thread"
        return actual_cycle()  # Canonical work_cycle remains process()'s caller.

    monkeypatch.setattr(ctx.guard, "work_cycle", parked_cycle)
    ctx.guard._process_wake.set()
    if not producer_parked.wait(5):
        producer_release.set()
        pytest.fail("Actual producer did not enter its owned cycle barrier")
    # source_canary disables only queue intake to let older direct-boundary tests
    # choose their action. Restore the canonical actual intake for this graph.
    monkeypatch.setattr(ctx.combat, "_submit", combat.AdversaryCombat._submit.__get__(ctx.combat))
    request_clock, dequeued_ages = None, []
    if age == 31:
        # The 31-second case MUST first pass genuine admission while younger
        # than 30. Advance only delegated wall checks after the actual worker's
        # real queue.get returns that exact admitted object. Its caller returns
        # directly to canonical _run_response_generation, preserving custody.
        queue_ready = threading.Event()
        actual_get = ctx.combat._queue.get
        request_clock = _PastWall(0)
        monkeypatch.setattr(purple, "time", request_clock)
        monkeypatch.setattr(combat, "time", request_clock)

        def get_then_advance(*args, **kwargs):
            queue_ready.set()
            event = actual_get(*args, **kwargs)
            if event is ctx.event:
                request_clock.seconds = -10
                dequeued_ages.append(request_clock.time() - event.ts)
            return event

        monkeypatch.setattr(ctx.combat._queue, "get", get_then_advance)
        if not queue_ready.wait(3):
            producer_release.set()
            pytest.fail("Actual worker must enter the guarded queue before submission")
    authority = purple.RedTeamValidationLease._queued_file_reobservations(ctx.lease)
    graph = SimpleNamespace(ctx=ctx, authority=authority, release=producer_release,
                            cleanup_events=[], age=age, request_clock=request_clock,
                            dequeued_ages=dequeued_ages)
    try:
        yield graph
    finally:
        producer_release.set()
        for signal in graph.cleanup_events:
            signal.set()
        ctx.guard._process_wake.set()
        _wait(lambda: ctx.combat.response_snapshot()["queue_pending"] == 0,
              "Fixture must retire its actual response tasks/tickets before lease release", timeout=25)


def _children(ctx):
    return [event for event in ctx.bus.recent(4096)
            if event.module == ctx.guard.name
            and event.details.get("redteam_detector_receipt_version") == 3
            and event.details.get("evidence_kind") == "inert_file_marker"]


def _verify(graph, event, **kwargs):
    return purple.verify_queued_file_event(graph.ctx.lease, graph.ctx.combat, event, **kwargs)


def _reserve(graph, event=None):
    ctx = graph.ctx
    ctx.combat._submit(ctx.event if event is None else event)
    _wait(lambda: bool(ctx.combat._file_reobservations_pending), "Real worker did not reserve a refresh")
    _wait(lambda: ctx.combat._queue.unfinished_tasks == 0, "Original queue task did not retire")
    assert ctx.combat.response_snapshot()["queue_pending"] == 1
    if graph.request_clock is not None:
        assert graph.dequeued_ages and graph.dequeued_ages[0] >= 31
        # The old event genuinely reached the actual queue owner at logical
        # age31. Restore wall clocks BEFORE the new native read/attest/emit so
        # both new observed_at and Event.ts use the same ordinary current time.
        graph.request_clock.seconds = 0


def _gate_child_handler(graph, monkeypatch):
    ctx = graph.ctx
    entered, release = threading.Event(), threading.Event()
    graph.cleanup_events.append(release)
    actual_handle = ctx.combat._handle
    handled = []

    def handle(event):
        handled.append(event)
        assert event.hmac_sig != ctx.event.hmac_sig, "Consumed original reached its action handler"
        if event.details.get("redteam_detector_receipt_version") == 3:
            entered.set()
            assert release.wait(15), "Test must release its real child handler"
        return actual_handle(event)

    monkeypatch.setattr(ctx.combat, "_handle", handle)
    return entered, release, handled


@pytest.mark.parametrize("queued_graph", [21, 31], indirect=True)
def test_actual_queue_fresh_native_child_owns_its_action_and_historical_receipt(queued_graph, monkeypatch):
    graph, ctx = queued_graph, queued_graph.ctx
    entered, release, handled = _gate_child_handler(graph, monkeypatch)
    parent_bytes = ctx.marker.read_bytes()
    parent_hmac = ctx.event.hmac_sig
    _reserve(graph)
    assert ctx.marker.read_bytes() == parent_bytes and not _children(ctx)
    graph.release.set()
    assert entered.wait(10)
    child = _children(ctx)[0]
    assert ctx.bus.verify(child) and ctx.bus.verify(ctx.event)
    assert child.hmac_sig != parent_hmac and child.ts > ctx.event.ts
    assert -1 <= time.time() - child.ts < 10
    details = child.details
    assert details["reobservation_parent_hmac"] == parent_hmac
    assert details["reobservation_parent_sha256"] == event_proof_digest(ctx.event)
    assert details["reobservation_root_nonce"] == ctx.event.details["event_nonce"]
    assert details["event_nonce"] != details["reobservation_root_nonce"]
    assert details["reobservation_attempt"] == 1
    assert details["reobservation_combat_generation"] == ctx.combat.lifecycle_generation
    assert len(details["reobservation_request_id"]) == 32
    assert _verify(graph, child)
    assert not ctx.combat._file_reobservations_pending
    assert ctx.combat.response_snapshot()["queue_pending"] >= 1
    assert ctx.marker.read_bytes() == parent_bytes
    release.set()
    _wait(lambda: ctx.combat.response_snapshot()["queue_pending"] == 0,
          "Real child response did not retire", timeout=25)
    rows = ctx.combat.list_actions()
    actions = [row for row in rows if row.get("action") == "quarantine_file"
               and row.get("status") == "applied"]
    assert len(actions) == 1 and not ctx.marker.exists()
    assert actions[0]["details"]["aar_trigger_event_digest"] == child.hmac_sig
    assert actions[0]["details"]["sha256"] == hashlib.sha256(parent_bytes).hexdigest()
    assert not any(row.get("details", {}).get("aar_trigger_event_digest") == parent_hmac for row in actions)
    assert _verify(graph, child, historical=True)
    assert purple.verify_validation_purple_event(ctx.lease, child,
        {"attack_ids": [ctx.event.details["technique"]]})
    assert [event.hmac_sig for event in handled] == [child.hmac_sig]
    # Replay cannot mint another child, even after pending retirement/native move.
    ctx.combat._submit(ctx.event)
    threading.Event().wait(0.05)
    assert len(_children(ctx)) == 1 and ctx.combat.response_snapshot()["queue_pending"] == 0
    if graph.age == 31:
        assert graph.dequeued_ages[0] >= 31
        with pytest.raises(combat.HostMutationHeld, match="lineage.*consumed"):
            ctx.combat._require_current_response_event(ctx.event)


@pytest.mark.parametrize("release_reader", [True, False], ids=["transient", "held"])
def test_aged_root_waits_briefly_for_local_journal_reader(queued_graph, monkeypatch, release_reader):
    graph, ctx = queued_graph, queued_graph.ctx
    lock = ctx.combat._receipt_lock
    attempted, proceed = threading.Event(), threading.Event()
    graph.cleanup_events.append(proceed)
    options = {}

    class ObservedLock:
        __enter__ = lock.__enter__
        __exit__ = lock.__exit__
        release = lock.release

        def acquire(self, **kwargs):
            if threading.current_thread() is not ctx.combat._thread or attempted.is_set():
                return lock.acquire(**kwargs)
            options.update(kwargs)
            if not kwargs.get("timeout"):
                # Observe an actual immediate refusal before the test unlocks.
                acquired = lock.acquire(**kwargs)
                attempted.set()
                return acquired
            attempted.set()
            # Avoid racing the short real wait with test-thread scheduling.
            assert proceed.wait(5), "Fixture must release its acquisition barrier"
            return lock.acquire(**kwargs)

    monkeypatch.setattr(ctx.combat, "_receipt_lock", ObservedLock())
    try:
        with lock:
            ctx.combat._submit(ctx.event)
            assert attempted.wait(5), "Response worker did not reach the journal reader"
            assert options == {"timeout": combat._REOBSERVATION_JOURNAL_WAIT_S}
            assert 0 < options["timeout"] <= 0.25
            assert not _children(ctx) and ctx.marker.is_file()
            if not release_reader:
                proceed.set()
                _wait(lambda: ctx.combat._queue.unfinished_tasks == 0,
                      "Busy journal request did not finish within its bounded path")
    finally:
        proceed.set()

    if release_reader:
        _wait(lambda: bool(ctx.combat._file_reobservations_pending), "Aged root was not reserved")
        graph.release.set()
        _wait(lambda: ctx.combat.response_snapshot()["queue_pending"] == 0,
              "Fresh child did not retire", timeout=25)
        child, = _children(ctx)
        assert child.details["reobservation_parent_hmac"] == ctx.event.hmac_sig
        action, = ctx.combat.list_actions()
        assert action["details"]["aar_trigger_event_digest"] == child.hmac_sig
        assert action["status"] == "applied" and not ctx.marker.exists()
    else:
        assert ctx.combat.response_snapshot()["counts"]["file_reobservation_held"] == 1
        assert not ctx.combat._file_reobservations_pending
        ctx.combat._submit(ctx.event)
        graph.release.set()
        assert ctx.combat.response_snapshot()["queue_pending"] == 0
        assert not _children(ctx) and not ctx.combat.list_actions()
        assert ctx.marker.is_file()


def test_nonowner_calls_cannot_request_or_publish_from_a_valid_signed_parent(queued_graph):
    graph, ctx = queued_graph, queued_graph.ctx
    assert graph.authority.request(ctx.combat, ctx.event) is False
    assert ctx.combat._maybe_reobserve_queued_file(ctx.event) is False
    assert graph.authority.process(ctx.guard) == 0
    assert not ctx.combat._file_reobservations_pending and not _children(ctx)
    assert ctx.marker.is_file() and not ctx.combat.list_actions()


@pytest.mark.parametrize("change", ["content", "classification", "policy", "expiry"])
def test_fresh_producer_refuses_changed_native_target_or_revoked_scope(queued_graph, monkeypatch, change):
    graph, ctx = queued_graph, queued_graph.ctx
    _reserve(graph)
    before = ctx.marker.read_bytes()
    if change == "content":
        ctx.marker.write_bytes(before + b"changed")
    elif change == "classification":
        actual = purple.classify_marker
        monkeypatch.setattr(purple, "classify_marker",
            lambda path: None if path == ctx.marker else actual(path))
    elif change == "policy":
        policy = ctx.combat.policy()
        monkeypatch.setattr(ctx.combat, "policy", lambda: replace(policy, quarantine_files=False))
    else:
        purple._lease_authority(ctx.lease).run_deadline_monotonic = time.monotonic() - 1
    graph.release.set()
    _wait(lambda: not ctx.combat._file_reobservations_pending, "Producer did not terminally hold its own ticket")
    assert ctx.combat.response_snapshot()["queue_pending"] == 0
    assert not _children(ctx) and ctx.marker.is_file() and not ctx.combat.list_actions()


def test_actual_native_handoff_before_queue_admission_cannot_be_refreshed(queued_graph):
    graph, ctx = queued_graph, queued_graph.ctx
    before = ctx.marker.read_bytes()
    purple.RedTeamValidationLease.begin_marker_containment(ctx.lease, ctx.combat, ctx.event, ctx.marker)
    try:
        ctx.combat._submit(ctx.event)
        _wait(lambda: ctx.combat._queue.unfinished_tasks == 0, "Active-handoff root did not retire")
        assert not ctx.combat._file_reobservations_pending and not _children(ctx)
        assert ctx.marker.read_bytes() == before and not ctx.combat.list_actions()
    finally:
        purple.RedTeamValidationLease.abort_marker_containment(ctx.lease, ctx.combat, ctx.marker, recapture=True)


def test_real_strict_prior_intent_prevents_a_before_attempt_refresh(queued_graph):
    graph, ctx = queued_graph, queued_graph.ctx
    action = ctx.combat._action("quarantine_file", str(ctx.marker), ctx.event,
        "combat-909090909090", reversible=True, details={
            "original": str(ctx.marker), "sha256": hashlib.sha256(ctx.marker.read_bytes()).hexdigest()})
    ctx.combat._journal_intent(action)
    ctx.combat._submit(ctx.event)
    _wait(lambda: ctx.combat._queue.unfinished_tasks == 0, "Prior-intent request did not retire")
    assert not ctx.combat._file_reobservations_pending and not _children(ctx)
    records, legacy = ctx.combat._read_journal(strict=True)
    assert not legacy and any(row.get("record_type") == "intent" for row in records)
    assert ctx.marker.is_file()


@pytest.mark.parametrize("field,value", [
    ("detector_receipt_mac", "0" * 64), ("reobservation_attempt", 2),
    ("reobservation_parent_hmac", "0" * 64), ("reobservation_parent_sha256", "0" * 64),
    ("reobservation_root_nonce", "0" * 32), ("reobservation_request_id", "0" * 32),
    ("reobservation_combat_generation", 999), ("reobservation_combat_policy_sha256", "0" * 64),
])
def test_outer_bus_signature_cannot_forge_the_child_lineage_or_private_seal(
    queued_graph, monkeypatch, field, value,
):
    graph, ctx = queued_graph, queued_graph.ctx
    entered, release, _handled = _gate_child_handler(graph, monkeypatch)
    _reserve(graph)
    graph.release.set()
    assert entered.wait(10)
    child = _children(ctx)[0]
    details = copy.deepcopy(child.details)
    details[field] = value
    forged = replace(child, details=details, hmac_sig="")
    forged = replace(forged, hmac_sig=ctx.recorder.authority.sign(forged))
    assert ctx.bus.verify(forged), "Reach the issuer/lineage boundary, not outer authentication"
    assert not _verify(graph, forged)
    assert not _verify(graph, forged, historical=True)
    assert not purple.verify_validation_purple_event(ctx.lease, forged,
        {"attack_ids": [ctx.event.details["technique"]]})
    release.set()


def test_existing_nonce_tagged_process_still_uses_its_real_original_issuer_proof(source_canary):
    ctx = source_canary
    _binding, process = _publish_process_probe(ctx.bus, ctx.run_id, lease=ctx.lease)
    try:
        event = None
        deadline = time.monotonic() + 5
        while event is None and time.monotonic() < deadline:
            ctx.guard.scan_process_once(ctx.guard._policy_snapshot())
            event = next((row for row in ctx.bus.recent(4096)
                          if row.module == ctx.guard.name and row.details.get("pid") == process.pid
                          and row.details.get("evidence_kind") == "nonce_tagged_process"), None)
            if event is None:
                threading.Event().wait(0.01)
        assert event is not None and ctx.bus.verify(event)
        proof = ctx.combat._practice_mutation(event, "terminate_process")
        assert proof is not None and ctx.combat._canary_mutation_valid(proof)
        assert event.details["redteam_detector_receipt_version"] == 2
        assert "reobservation_parent_hmac" not in event.details and process.poll() is None
    finally:
        assert _retire_process(process)


def test_unregistered_exact_lease_is_held_through_real_combat_and_producer_cycle(source_canary, monkeypatch):
    ctx = source_canary
    foreign = object.__new__(purple.RedTeamValidationLease)
    producer, generation = ctx.guard._thread, ctx.guard.lifecycle_generation
    pins = []

    def forbidden_pin(_self, path, *_args, **_kwargs):
        pins.append(path)
        raise AssertionError("Missing issuer registry reached a native mutation pin")

    with monkeypatch.context() as broken:
        broken.setattr(ctx.guard, "_validation_lease", foreign)
        broken.setattr(combat._PinnedFileMove, "__init__", forbidden_pin)
        assert ctx.combat._queued_file_authority(ctx.event, create=True) is None
        ctx.combat._handle(ctx.event)
        before = ctx.guard._validation_cycle_serial
        ctx.guard._process_wake.set()
        _wait(lambda: ctx.guard._validation_cycle_serial > before,
              "The real producer did not complete a missing-registry cycle")
        assert ctx.guard._thread is producer and producer.is_alive()
        assert ctx.guard.lifecycle_generation == generation and not ctx.guard.last_error
        assert not pins and ctx.marker.is_file() and not ctx.combat.list_actions()
    assert ctx.guard._validation_lease is ctx.lease


def _extra_parent(ctx, monkeypatch, label):
    path = ctx.marker.with_name(f"_redteam_lsass_dump_{ctx.run_id}_{label}.txt")
    _write_registered_marker(path, "ANGERONA inert additional queued marker\n", ctx.run_id, lease=ctx.lease)
    with monkeypatch.context() as clocks:
        clocks.setattr(purple, "time", _PastWall(21))
        clocks.setattr(module_base, "time", _PastWall(21))
        # As in source_canary's initial observation, choose admission only
        # AFTER this genuine native detector/signature mint has returned and
        # its controlled wall clock is restored. The actual later queue path
        # is never replaced by a proof/admission-success stub.
        clocks.setattr(ctx.combat, "_submit", lambda _event: None)
        ctx.guard.scan_once(ctx.guard._policy_snapshot())
    event = next(event for event in ctx.bus.recent(4096)
                 if event.module == ctx.guard.name and event.details.get("path") == str(path)
                 and event.details.get("redteam_detector_receipt_version") == 2)
    assert ctx.bus.verify(event)
    return path, event


def test_completed_native_moved_witness_does_not_block_a_distinct_untouched_target(queued_graph, monkeypatch):
    graph, ctx = queued_graph, queued_graph.ctx
    prior = ctx.combat._quarantine_file(str(ctx.marker), ctx.event, "combat-717171717171")
    assert prior is not None and prior.status == "applied" and not ctx.marker.exists()
    path, parent = _extra_parent(ctx, monkeypatch, "aftercompleted")
    ctx.marker, ctx.event = path, parent
    entered, release, _handled = _gate_child_handler(graph, monkeypatch)
    _reserve(graph)
    graph.release.set()
    assert entered.wait(10)
    child = _children(ctx)[0]
    assert child.details["reobservation_parent_hmac"] == parent.hmac_sig and _verify(graph, child)
    release.set()
    _wait(lambda: ctx.combat.response_snapshot()["queue_pending"] == 0, "Distinct target did not retire", timeout=25)
    actions = [row for row in ctx.combat.list_actions() if row.get("status") == "applied"]
    assert len(actions) == 2 and not path.exists()
    assert any(row["details"]["aar_trigger_event_digest"] == child.hmac_sig for row in actions)


def test_pending_ticket_remains_until_the_real_stopped_producer_retires(queued_graph):
    graph, ctx = queued_graph, queued_graph.ctx
    _reserve(graph)
    owner = ctx.guard._thread
    ctx.guard.stop()
    assert owner.is_alive(), "The controlled producer is still parked in its own cycle"
    assert len(ctx.combat._file_reobservations_pending) == 1
    assert ctx.combat.response_snapshot()["queue_pending"] == 1
    graph.release.set()
    owner.join(timeout=5)
    assert not owner.is_alive()
    _wait(lambda: not ctx.combat._file_reobservations_pending, "Actual producer finally did not cancel its ticket")
    assert ctx.combat.response_snapshot()["queue_pending"] == 0
    assert ctx.marker.is_file() and not _children(ctx) and not ctx.combat.list_actions()


def test_pending_snapshot_keeps_admission_locked_through_the_real_queue_count(queued_graph):
    graph, ctx = queued_graph, queued_graph.ctx
    _reserve(graph)
    result, errors = [], []
    observer_started, terminal_started, terminal_done = (threading.Event() for _ in range(3))

    def observe():
        observer_started.set()
        try:
            result.append(ctx.combat.response_snapshot())
        except BaseException as error:
            errors.append(error)

    def terminal():
        terminal_started.set()
        try:
            graph.authority.revoke_queued()
        except BaseException as error:
            errors.append(error)
        finally:
            terminal_done.set()

    def admission_owned():
        acquired = ctx.combat._admission_lock.acquire(blocking=False)
        if acquired:
            ctx.combat._admission_lock.release()
        return not acquired

    observer, canceller = threading.Thread(target=observe), threading.Thread(target=terminal)
    # These are the actual Queue condition and actor lock. No snapshot, queue
    # or authority result is substituted. Old split reads would return early.
    with ctx.combat._queue.all_tasks_done:
        observer.start()
        assert observer_started.wait(2)
        _wait(admission_owned, "Snapshot released admission before its protected queue read", timeout=2)
        canceller.start()
        assert terminal_started.wait(2)
        assert not terminal_done.wait(0.05)
    observer.join(timeout=3)
    canceller.join(timeout=3)
    assert not observer.is_alive() and not canceller.is_alive() and not errors
    assert result[0]["queue_pending"] == 1
    assert terminal_done.is_set() and ctx.combat.response_snapshot()["queue_pending"] == 0
    assert ctx.marker.is_file() and not _children(ctx)


def test_real_child_queue_rejection_does_not_acknowledge_or_claim_completion(queued_graph, monkeypatch):
    import queue
    graph, ctx = queued_graph, queued_graph.ctx
    _reserve(graph)
    actual_put = ctx.combat._queue.put_nowait
    rejected = []

    def reject_child(event):
        if event.details.get("redteam_detector_receipt_version") == 3:
            # Called inside the canonical _submit admission lock, before any
            # real queue put/task count. Model only its actual Full exception.
            rejected.append((event, len(ctx.combat._file_reobservations_pending)))
            raise queue.Full
        return actual_put(event)

    monkeypatch.setattr(ctx.combat._queue, "put_nowait", reject_child)
    graph.release.set()
    _wait(lambda: bool(rejected) and not ctx.combat._file_reobservations_pending,
          "Rejected child did not terminally hold the exact pending ticket")
    child, pending_at_rejection = rejected[0]
    assert pending_at_rejection == 1 and ctx.bus.verify(child)
    assert not _verify(graph, child) and not _verify(graph, child, historical=True)
    assert ctx.combat.response_snapshot()["queue_pending"] == 0
    assert ctx.marker.is_file() and not ctx.combat.list_actions()


def test_pending_queue_eight_bound_uses_real_issuer_events_without_partial_admission(queued_graph, monkeypatch):
    graph, ctx = queued_graph, queued_graph.ctx
    parents = [ctx.event]
    paths = [ctx.marker]
    for index in range(8):
        path, event = _extra_parent(ctx, monkeypatch, f"bound{index}")
        parents.append(event)
        paths.append(path)
    assert len({event.details["event_nonce"] for event in parents}) == 9
    for event in parents:
        ctx.combat._submit(event)
    _wait(lambda: ctx.combat._queue.unfinished_tasks == 0, "Real bounded requests did not retire")
    assert len(ctx.combat._file_reobservations_pending) == 8
    assert ctx.combat.response_snapshot()["queue_pending"] == 8
    assert not _children(ctx) and all(path.is_file() for path in paths)
    graph.authority.revoke_queued()
    assert not ctx.combat._file_reobservations_pending
    assert ctx.combat.response_snapshot()["queue_pending"] == 0
    assert all(path.is_file() for path in paths) and not ctx.combat.list_actions()


def test_lifetime_ninety_six_root_budget_closes_unrecordable_replays(queued_graph, monkeypatch):
    graph, ctx = queued_graph, queued_graph.ctx
    _reserve(graph)
    nonces = {ctx.event.details["event_nonce"]}
    last = None
    # Genuine new native observations of the same enrolled file. Their separate
    # issuer nonces must consume the bounded lifetime ledger even though only
    # its first request can own pending work for this same file.
    for index in range(96):
        with monkeypatch.context() as clocks:
            clocks.setattr(purple, "time", _PastWall(21))
            clocks.setattr(module_base, "time", _PastWall(21))
            clocks.setattr(ctx.combat, "_submit", lambda _event: None)
            classified = purple.classify_marker(ctx.marker)
            assert classified is not None and classified[0] == ctx.event.details["technique"]
            receipt = purple.RedTeamValidationLease.attest_purple_detection(ctx.lease, ctx.guard,
                technique=classified[0], observed_target=str(ctx.marker), evidence_kind="inert_file_marker")
            assert receipt, "Each budget root must have genuine current native issuer proof"
            details = copy.deepcopy(ctx.event.details)
            details.update(receipt)
            ctx.guard.emit(f"Genuine repeated native observation {index}", purple.Severity.HIGH, **details)
            last = ctx.bus.recent(1)[0]
        assert ctx.bus.verify(last)
        nonces.add(last.details["event_nonce"])
        ctx.combat._submit(last)
        _wait(lambda: ctx.combat._queue.unfinished_tasks == 0, "Budget request did not retire")
    assert len(nonces) == 97
    assert len(ctx.combat._file_reobservations_pending) == 1
    # The last nonce cannot be stored in a 96-root ledger. The permanent
    # saturated fence must still deny it, never leave it reusable/admissible.
    assert not _verify(graph, last)
    assert ctx.combat.response_snapshot()["queue_pending"] == 1
    graph.authority.revoke_queued()
    assert ctx.combat.response_snapshot()["queue_pending"] == 0
    assert ctx.marker.is_file() and not _children(ctx) and not ctx.combat.list_actions()


def test_class_helper_redirects_cannot_grant_a_revoked_or_consumed_receipt(queued_graph, monkeypatch):
    graph, ctx = queued_graph, queued_graph.ctx
    entered, release, _handled = _gate_child_handler(graph, monkeypatch)
    _reserve(graph)
    graph.release.set()
    assert entered.wait(10)
    child = _children(ctx)[0]
    assert _verify(graph, child)
    actual_policy = ctx.combat.policy()
    with monkeypatch.context() as attack:
        # Deliberate attack fault injection, never a positive proof substitute:
        # the captured dispatch must ignore these reachable grant redirects.
        attack.setattr(type(graph.authority), "verify_event", lambda *_a, **_k: True)
        attack.setattr(type(graph.authority), "_original", lambda _a, event: event.details["event_nonce"])
        attack.setattr(type(graph.authority), "_current", lambda *_a, **_k: True)
        attack.setattr(ctx.combat, "policy", lambda: replace(actual_policy, quarantine_files=False))
        assert not _verify(graph, child)
        assert not _verify(graph, ctx.event)
    assert _verify(graph, child)
    release.set()


@pytest.mark.parametrize("clock", ["wall", "monotonic"])
def test_new_child_owns_a_separate_immutable_thirty_second_lease(queued_graph, monkeypatch, clock):
    graph, ctx = queued_graph, queued_graph.ctx
    entered, release, _handled = _gate_child_handler(graph, monkeypatch)
    _reserve(graph)
    graph.release.set()
    assert entered.wait(10)
    child = _children(ctx)[0]
    assert _verify(graph, child)
    signature, timestamp, details = child.hmac_sig, child.ts, copy.deepcopy(child.details)

    class AfterLease:
        def time(self):
            return child.ts + 31 if clock == "wall" else time.time()

        def monotonic(self):
            return time.monotonic() + 31 if clock == "monotonic" else time.monotonic()

        def __getattr__(self, name):
            return getattr(time, name)

    with monkeypatch.context() as clocks:
        clocks.setattr(purple, "time", AfterLease())
        assert not _verify(graph, child)
        assert _verify(graph, child, historical=True), "Historical authentication grants no live mutation authority"
    assert (child.hmac_sig, child.ts, child.details) == (signature, timestamp, details)
    assert _verify(graph, child)
    release.set()


def test_resigned_outer_replay_cannot_spend_the_same_issuer_nonce_twice(queued_graph):
    graph, ctx = queued_graph, queued_graph.ctx
    _reserve(graph)
    replay = replace(ctx.event, message=ctx.event.message + " copied outer envelope", hmac_sig="")
    replay = replace(replay, hmac_sig=ctx.recorder.authority.sign(replay))
    assert ctx.bus.verify(replay) and replay.hmac_sig != ctx.event.hmac_sig
    assert replay.details["event_nonce"] == ctx.event.details["event_nonce"]
    assert not _verify(graph, replay)
    ctx.combat._submit(replay)
    assert ctx.combat._queue.unfinished_tasks == 0
    assert len(ctx.combat._file_reobservations_pending) == 1
    assert ctx.combat.response_snapshot()["queue_pending"] == 1
    graph.authority.revoke_queued()
    assert ctx.combat.response_snapshot()["queue_pending"] == 0
    assert ctx.marker.is_file() and not _children(ctx) and not ctx.combat.list_actions()


def test_old_generation_terminal_removes_only_its_own_opaque_ticket(queued_graph, monkeypatch):
    graph, ctx = queued_graph, queued_graph.ctx
    old_emitting, new_emitting = threading.Event(), threading.Event()
    old_release, new_release = threading.Event(), threading.Event()
    graph.cleanup_events.extend((old_release, new_release))
    actual_emit = ctx.guard.emit

    def gate_fresh_emit(message, severity=purple.Severity.INFO, **details):
        if details.get("redteam_detector_receipt_version") == 3:
            parent = details["reobservation_parent_hmac"]
            signal, release = ((old_emitting, old_release) if parent == ctx.event.hmac_sig
                               else (new_emitting, new_release))
            signal.set()
            assert release.wait(15), "Test must release the actual producer publication"
        return actual_emit(message, severity, **details)

    monkeypatch.setattr(ctx.guard, "emit", gate_fresh_emit)
    _reserve(graph)
    old_tickets = set(ctx.combat._file_reobservations_pending)
    old_generation, old_worker = ctx.combat.lifecycle_generation, ctx.combat._thread
    graph.release.set()
    assert old_emitting.wait(10), "First native observation must precede the generation change"
    # AFTER native/read/classification and issuer locks, BEFORE publication.
    ctx.combat.stop()
    old_worker.join(timeout=5)
    assert not old_worker.is_alive()
    assert set(ctx.combat._file_reobservations_pending) == old_tickets
    ctx.combat.start()
    _wait(ctx.combat.response_ready, "Replacement real Combat generation did not become ready")
    assert ctx.combat.lifecycle_generation > old_generation and ctx.combat._thread is not old_worker
    later_path, later = _extra_parent(ctx, monkeypatch, "nextgeneration")
    ctx.combat._submit(later)
    _wait(lambda: len(ctx.combat._file_reobservations_pending) == 2,
          "New generation did not reserve its distinct native target")
    new_tickets = set(ctx.combat._file_reobservations_pending) - old_tickets
    assert len(new_tickets) == 1 and ctx.combat.response_snapshot()["queue_pending"] == 2
    old_release.set()
    assert new_emitting.wait(10)
    assert set(ctx.combat._file_reobservations_pending) == new_tickets
    assert ctx.combat.response_snapshot()["queue_pending"] == 1
    old_children = [event for event in _children(ctx)
                    if event.details["reobservation_parent_hmac"] == ctx.event.hmac_sig]
    assert len(old_children) == 1 and not _verify(graph, old_children[0])
    assert not _verify(graph, old_children[0], historical=True)
    assert ctx.marker.is_file() and later_path.is_file()
    new_release.set()
    _wait(lambda: ctx.combat.response_snapshot()["queue_pending"] == 0,
          "Current generation response did not retire", timeout=25)
    actions = [row for row in ctx.combat.list_actions() if row.get("status") == "applied"]
    assert len(actions) == 1 and ctx.marker.is_file() and not later_path.exists()
    current_child = next(event for event in _children(ctx)
                         if event.details["reobservation_parent_hmac"] == later.hmac_sig)
    assert actions[0]["details"]["aar_trigger_event_digest"] == current_child.hmac_sig
    assert _verify(graph, current_child, historical=True)
