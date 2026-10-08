"""Inert response lifecycle fixtures: startup may buffer, never bypass custody."""
from __future__ import annotations

import os
import threading
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.adversary_combat import AdversaryCombat, _ResponseEventQueue


_MISMATCH = "combat journal rollback or incomplete anchor transaction detected"


@pytest.fixture
def combat(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith("ANGERONA_ADVERSARY_COMBAT_"):
            monkeypatch.delenv(key)
    bus = EventBus()
    bus.arm(BusAuthority(b"s" * 32))
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    module.bind(bus)
    module.bind_manager(SimpleNamespace(config=SimpleNamespace(
        adversary_combat_enabled=True,
        adversary_combat_activate_honeypots=False,
    ), modules={}))
    return module, bus


def request(message="inert", **extra):
    return Event("Inert Detector", message, Severity.HIGH, details={
        "response_authorized": True,
        "response_contract": {
            "version": 1, "actions": ["activate_honeypots"],
            "targets": {"deception": "Smart Deception"},
        },
        **extra,
    })


def wait_for(predicate):
    deadline = time.monotonic() + 3
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.002)
    assert predicate()


def start_blocked(module, monkeypatch, *, succeeds=True):
    entered, release = threading.Event(), threading.Event()

    def reconcile():
        entered.set()
        assert release.wait(3), "fixture reconciliation was not released"
        if not succeeds:
            module._journal_error = "inert unsupported custody failure"
        return succeeds

    monkeypatch.setattr(module, "_reconcile_state", reconcile)
    module._stop.clear()
    module.status = "running"
    worker = threading.Thread(target=module.run, daemon=True)
    worker.start()
    assert entered.wait(1)
    return worker, release


def stop(module, worker, release):
    module._stop.set()
    release.set()
    worker.join(2)
    assert not worker.is_alive()


def test_current_startup_evidence_is_buffered_without_replaying_history(combat, monkeypatch):
    module, bus = combat
    bus.publish(request("historical"))
    handled = []

    def handle(event):
        assert module._response_initialized
        handled.append(event.message)

    monkeypatch.setattr(module, "_handle", handle)
    worker, release = start_blocked(module, monkeypatch)
    try:
        callback = bus._subs[0]
        callback(request("unsigned"))
        bus.publish(request("remote", node_origin="remote", response_scope="remote-observe-only"))
        bus.publish(request("during startup"))
        assert handled == []
        assert module._queue.qsize() == 1
        assert len(module._startup_admitted_at) == 1
        release.set()
        wait_for(lambda: handled == ["during startup"])
        bus.publish(request("after ready"))
        wait_for(lambda: len(handled) == 2)
        assert handled == ["during startup", "after ready"]
    finally:
        stop(module, worker, release)
    assert not bus._subs
    assert module._queue.unfinished_tasks == 0
    assert not module._startup_admitted_at


@pytest.mark.parametrize("expired_by", ["monotonic", "event_time"])
def test_old_startup_requests_expire_without_mutation(combat, monkeypatch, expired_by):
    module, bus = combat
    handled = []
    monkeypatch.setattr(module, "_handle", handled.append)
    worker, release = start_blocked(module, monkeypatch)
    try:
        event = request("expired")
        if expired_by == "event_time":
            event = replace(event, ts=event.ts - 60)
        bus.publish(event)
        if expired_by == "monotonic":
            for key in module._startup_admitted_at:
                module._startup_admitted_at[key] -= 60
        release.set()
        wait_for(lambda: module.response_snapshot()["counts"].get("startup_expired") == 1)
        assert not handled
        assert not module._startup_admitted_at
        diagnostics = [event for event in bus.recent(10)
                       if "discarded startup" in event.message]
        assert len(diagnostics) == 1
        assert diagnostics[0].details["response_authorized"] is False
        assert not module._seen
    finally:
        stop(module, worker, release)


def test_stop_drains_then_old_callback_cannot_enter_new_generation(combat, monkeypatch):
    module, bus = combat
    handled = []
    monkeypatch.setattr(module, "_handle", lambda event: handled.append(event.message))
    monkeypatch.setattr(module, "_ensure_honeypots", lambda: pytest.fail("stopped startup mutated host"))
    worker, release = start_blocked(module, monkeypatch)
    old_callback = bus._subs[0]
    event = request("retry after stop", queue_request_id="a" * 32)
    bus.publish(event)
    module._manager.config.adversary_combat_activate_honeypots = True
    stop(module, worker, release)
    assert not handled
    assert not bus._subs
    assert not module._seen
    assert module._queue.unfinished_tasks == 0
    assert module.response_snapshot()["counts"]["generation_discarded"] == 1

    module._manager.config.adversary_combat_activate_honeypots = False
    worker, release = start_blocked(module, monkeypatch)
    try:
        signed = next(item for item in bus.recent(10) if item.module == event.module)
        old_callback(signed)
        assert module._queue.empty()
        bus.publish(event)
        assert module._queue.qsize() == 1
        release.set()
        wait_for(lambda: handled == ["retry after stop"])
    finally:
        stop(module, worker, release)


def test_failed_reconciliation_detaches_and_discards_buffer(combat, monkeypatch):
    module, bus = combat
    monkeypatch.setattr(module, "_handle", lambda _event: pytest.fail("failed custody executed"))
    worker, release = start_blocked(module, monkeypatch, succeeds=False)
    try:
        bus.publish(request())
        release.set()
        wait_for(lambda: module._mutation_blocked and not bus._subs)
        assert not module._response_initialized
        assert module._queue.empty()
        assert not module._seen
        assert not module._startup_admitted_at
        assert module._queue.unfinished_tasks == 0
        bus.publish(request("still held"))
        assert module._queue.empty()
    finally:
        stop(module, worker, release)


def test_startup_overflow_diagnostic_cannot_deadlock_inline_delivery(combat, monkeypatch):
    module, bus = combat
    module._queue = _ResponseEventQueue(maxsize=1)
    monkeypatch.setattr(module, "_handle", lambda _event: None)
    worker, release = start_blocked(module, monkeypatch)
    try:
        bus.publish(request("first"))
        finished = threading.Event()
        publisher = threading.Thread(
            target=lambda: (bus.publish(request("overflow")), finished.set()), daemon=True,
        )
        publisher.start()
        assert finished.wait(1), "overflow health publication deadlocked admission"
        publisher.join(1)
        assert module._queue.qsize() == 1
        assert len(module._startup_admitted_at) == 1
        assert module._dropped_events == 1
        assert module.response_snapshot()["counts"]["queue_saturated"] == 1
    finally:
        stop(module, worker, release)


@pytest.mark.parametrize("retry_success", [True, False])
def test_checkpoint_repair_is_once_and_requires_normal_reconciliation(combat, monkeypatch, retry_success):
    from angerona.core import combat_checkpoint_recovery as recovery

    module, bus = combat
    calls = []

    def reconcile():
        calls.append("reconcile")
        module._journal_error = _MISMATCH
        return retry_success and calls.count("reconcile") == 2

    def repair(_module, *, before_commit):
        calls.append("repair")
        before_commit()
        return {"recovered": True, "rearmed": False}

    monkeypatch.setattr(module, "_reconcile_state", reconcile)
    monkeypatch.setattr(recovery, "recover_drill_checkpoint", repair)
    assert module._reconcile_startup_once() is retry_success
    assert calls == ["reconcile", "repair", "reconcile"]
    recovered = [event for event in bus.recent(10)
                 if event.details.get("event_type") == "combat_startup_checkpoint_recovered"]
    assert bool(recovered) is retry_success
    if recovered:
        assert recovered[0].details["response_authorized"] is False
        assert "action_succeeded" not in recovered[0].details


@pytest.mark.parametrize("refusal", ["disabled", "different_error", "stopped", "helper_failure",
                                     "helper_false", "disable_before_commit", "stop_before_commit"])
def test_repair_refusals_preserve_original_hold(combat, monkeypatch, refusal):
    from angerona.core import combat_checkpoint_recovery as recovery

    module, _bus = combat
    error = "another integrity error" if refusal == "different_error" else _MISMATCH
    calls = []

    def reconcile():
        calls.append("reconcile")
        module._journal_error = error
        return False

    def repair(_module, *, before_commit):
        calls.append("repair")
        if refusal == "helper_failure":
            raise RuntimeError("inert refusal")
        if refusal == "disable_before_commit":
            module._manager.config.adversary_combat_enabled = False
        if refusal == "stop_before_commit":
            module._stop.set()
        before_commit()
        return {"recovered": False}

    monkeypatch.setattr(module, "_reconcile_state", reconcile)
    monkeypatch.setattr(recovery, "recover_drill_checkpoint", repair)
    if refusal == "disabled":
        module._manager.config.adversary_combat_enabled = False
    if refusal == "stopped":
        module._stop.set()
    assert module._reconcile_startup_once() is False
    assert calls.count("reconcile") == 1
    assert calls.count("repair") == int(refusal not in {"disabled", "different_error", "stopped"})
    assert module._journal_error == error


def test_repair_window_accepts_only_buffered_evidence(combat, monkeypatch):
    from angerona.core import combat_checkpoint_recovery as recovery

    module, bus = combat
    entered, release = threading.Event(), threading.Event()
    handled, reconciliations = [], []

    def reconcile():
        reconciliations.append(True)
        module._mutation_blocked = len(reconciliations) == 1
        module._journal_error = _MISMATCH if module._mutation_blocked else ""
        return not module._mutation_blocked

    def repair(_module, *, before_commit):
        entered.set()
        assert release.wait(3)
        before_commit()
        return {"recovered": True}

    monkeypatch.setattr(module, "_reconcile_state", reconcile)
    monkeypatch.setattr(recovery, "recover_drill_checkpoint", repair)
    monkeypatch.setattr(module, "_handle", lambda event: handled.append(event.message))
    module.status = "running"
    worker = threading.Thread(target=module.run, daemon=True)
    worker.start()
    try:
        assert entered.wait(1)
        bus.publish(request("during strict repair"))
        assert module._queue.qsize() == 1
        assert not handled
        release.set()
        wait_for(lambda: handled == ["during strict repair"])
        assert len(reconciliations) == 2
    finally:
        stop(module, worker, release)


def test_eventbus_unsubscribe_accepts_equivalent_bound_method():
    bus = EventBus()

    class Receiver:
        def receive(self, _event):
            pytest.fail("unsubscribed callback delivered")

    receiver = Receiver()
    bus.subscribe(receiver.receive)
    bus.unsubscribe(receiver.receive)
    bus.unsubscribe(receiver.receive)
    bus.publish(request())
    assert bus.subscriber_metrics() == ()


def test_discard_releases_original_admitted_identity_not_mutated_details(combat, monkeypatch):
    module, bus = combat
    executed_identity = "soar:" + "e" * 32
    discarded_identity = "soar:" + "d" * 32
    module._seen.add(executed_identity)
    module._seen_order.append(executed_identity)
    worker, release = start_blocked(module, monkeypatch)
    event = request(queue_request_id="d" * 32)
    bus.publish(event)
    event.details["queue_request_id"] = "e" * 32
    stop(module, worker, release)
    assert executed_identity in module._seen
    assert discarded_identity not in module._seen
    assert not module._admitted_identities


def test_admission_bookkeeping_precedes_queue_visibility(combat, monkeypatch):
    module, bus = combat
    module.status = "running"
    bus.publish(request(queue_request_id="f" * 32))
    event = bus.recent(1)[0]
    original_put = module._queue.put_nowait

    def put(value):
        assert module._admitted_identities[id(value)] == "soar:" + "f" * 32
        original_put(value)

    monkeypatch.setattr(module._queue, "put_nowait", put)
    module._submit(event)
    assert module._queue.get_nowait() is event
    module._queue.task_done()
    module._forget_unhandled_submission(event)
    assert not module._admitted_identities
