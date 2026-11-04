from __future__ import annotations

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.soar import SOARModule
from angerona.modules.soar_engine import ActiveResponseSOAR


def _publish_pair(bus: EventBus) -> None:
    bus.publish(Event("sensor", "first", Severity.HIGH, 1.0, {}))
    bus.publish(Event("sensor", "second", Severity.HIGH, 2.0, {}))


def test_automation_self_test_never_replaces_live_delivery_state(monkeypatch) -> None:
    live = SOARModule()
    live._last_ts = 10_000.0
    live._seen_at_last_ts = {"live-signed-row"}
    live._priority_cursor = 90
    pending = live._pending
    seen = live._seen_at_last_ts
    real_add_signal = SOARModule._add_signal
    key = (31337, 1234, "inert live evidence")

    def signal(fixture, pid, event):
        assert fixture is not live and fixture._bus is None
        assert live._pending is pending and live._seen_at_last_ts is seen
        live._pending[key] = [(10_001.0, "live sensor")]
        live._last_ts = 10_001.0
        live._seen_at_last_ts.add("later live row")
        return real_add_signal(fixture, pid, event)

    monkeypatch.setattr(SOARModule, "_add_signal", signal)
    ok, detail = live.self_test()
    assert ok and "exact-process corroboration" in detail
    assert live._pending is pending and key in pending
    assert live._last_ts == 10_001.0 and live._seen_at_last_ts is seen
    assert seen == {"live-signed-row", "later live row"} and live._priority_cursor == 90


def test_active_self_test_reports_disarmed_worker_and_leaves_live_bus_untouched(monkeypatch) -> None:
    monkeypatch.delenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", raising=False)
    bus = EventBus()
    _publish_pair(bus)
    events = bus.recent(2)
    live = ActiveResponseSOAR()
    live.bind(bus)
    live._general_cursor, live._priority_cursor, live._last_ts = 10, 11, 12.0
    monkeypatch.setattr(live, "_kill_and_rollback", lambda *_a: pytest.fail("used live response sink"))
    ok, detail = live.self_test()
    assert ok and "Policy disarmed; worker stopped" in detail
    assert bus.recent(2) == events
    assert (live._general_cursor, live._priority_cursor, live._last_ts) == (10, 11, 12.0)


def test_active_self_test_reports_armed_missing_worker(monkeypatch) -> None:
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH")
    ok, detail = ActiveResponseSOAR().self_test()
    assert not ok and "Policy armed (minimum High); worker stopped" in detail


@pytest.mark.parametrize("method,detail", [
    ("_event_integrity_ok", "authenticated-event admission"),
    ("event_disposition", "advisory classification"),
    ("is_remote_observe_only", "remote observe-only evidence"),
])
def test_active_self_test_detects_refusal_gate_regressions(monkeypatch, method, detail) -> None:
    from angerona.modules import soar_engine

    if method == "_event_integrity_ok":
        monkeypatch.setattr(ActiveResponseSOAR, method, lambda *_args: True)
    elif method == "event_disposition":
        monkeypatch.setattr(soar_engine, method, lambda *_args: "active")
    else:
        monkeypatch.setattr(soar_engine, method, lambda *_args: False)
    ok, message = ActiveResponseSOAR().self_test()
    assert not ok and detail in message


def test_eventbus_exposes_exact_per_event_commit_revisions() -> None:
    bus = EventBus()
    _publish_pair(bus)

    current, records, overflow = bus.priority_records_since(0)
    general_current, general_records, general_overflow = bus.records_since(0)

    assert current == 2 and general_current == 2
    assert not overflow and not general_overflow
    assert [(revision, event.message) for revision, event in records] == [
        (2, "second"),
        (1, "first"),
    ]
    assert [(revision, event.message) for revision, event in general_records] == [
        (2, "second"),
        (1, "first"),
    ]


def test_soar_retries_failed_event_without_acknowledging_later_sibling(monkeypatch) -> None:
    bus = EventBus()
    _publish_pair(bus)
    module = SOARModule()
    module.bind(bus)
    processed: list[str] = []

    def fail_first_twice(event, _policy) -> bool:
        processed.append(event.message)
        if event.message == "first" and processed.count("first") <= 3:
            raise RuntimeError("injected processing failure")
        return event.message == "second"

    monkeypatch.setattr(module, "_process_one_event", fail_first_twice)

    assert module.process_pending_once() == 0
    assert module._priority_cursor == 0
    assert processed == ["first"]
    assert module.process_pending_once() == 0
    assert module._priority_cursor == 0
    assert processed == ["first", "first"]

    assert module.process_pending_once() == 1
    assert module._priority_cursor == 2
    assert processed == ["first", "first", "first", "second"]
    assert module._dead_lettered == 1
    assert module.health == 35


def test_soar_filtered_event_is_terminal_and_commits_revision(monkeypatch) -> None:
    bus = EventBus()
    _publish_pair(bus)
    module = SOARModule()
    module.bind(bus)
    monkeypatch.setattr(module, "_process_one_event", lambda _event, _policy: False)

    assert module.process_pending_once() == 0
    assert module._priority_cursor == 2
    assert module.process_pending_once() == 0


def test_active_soar_retains_general_cursor_until_failed_event_is_terminal(
    monkeypatch,
) -> None:
    bus = EventBus()
    _publish_pair(bus)
    module = ActiveResponseSOAR()
    module.bind(bus)
    monkeypatch.setattr(module, "_armed", lambda: True)
    processed: list[str] = []

    def fail_first_twice(event, _floor, _policy) -> bool:
        processed.append(event.message)
        if event.message == "first" and processed.count("first") <= 3:
            raise RuntimeError("injected active-response failure")
        return event.message == "second"

    monkeypatch.setattr(module, "_process_one_event", fail_first_twice)

    assert module.process_pending_once() == 0
    assert module._general_cursor == 0
    assert module._priority_cursor == 0
    assert module.process_pending_once() == 0
    assert module._general_cursor == 0

    assert module.process_pending_once() == 1
    assert module._general_cursor == 2
    assert module._priority_cursor == 2
    assert processed == ["first", "first", "first", "second"]
    assert module._dead_lettered == 1


class _CombatReceiptStub:
    status = "running"

    def __init__(self, bus: EventBus, *, publish_receipt: bool) -> None:
        self.bus = bus
        self.publish_receipt = publish_receipt
        self.submitted = []
        self.reads = 0
        self.rows = [{
            "action_id": "act-old",
            "trigger_module": "sensor",
            "trigger_ts": 10.0,
            "status": "applied",
            "integrity_status": "verified",
            "details": {"postcondition_verified": True},
        }]

    def _submit(self, request: Event) -> None:
        self.submitted.append(request)
        if not self.publish_receipt:
            return
        request_id = request.details["queue_request_id"]
        action_id = "act-fresh"
        self.rows.append({
            "action_id": action_id,
            "status": "applied",
            "integrity_status": "verified",
            "details": {"postcondition_verified": True},
        })
        self.bus.publish(Event(
            "Adversary Combat",
            "request completed",
            Severity.HIGH,
            details={
                "queue_request_id": request_id,
                "action_succeeded": True,
                "mitigated": True,
                "postcondition_verified": True,
                "action_ids": [action_id],
                "actions": ["suspend_process"],
            },
        ))

    def list_actions(self, limit: int = 500):
        self.reads += 1
        return self.rows[-limit:]


def _signed_response_event(bus: EventBus) -> Event:
    bus.publish(Event(
        "sensor",
        "exact process evidence",
        Severity.CRITICAL,
        ts=10.0,
        details={
            "pid": 999,
            "process_create_time": 5.0,
            "exe": "C:/sample.exe",
            "response_authorized": True,
            "response_contract": {
                "version": 1,
                "actions": ["suspend_process"],
                "targets": {"pid": 999, "process_create_time": 5.0},
            },
        },
    ))
    return bus.recent(1)[0]


def test_old_combat_action_can_never_credit_a_new_request(monkeypatch) -> None:
    bus = EventBus()
    bus.arm(BusAuthority(b"c" * 32))
    event = _signed_response_event(bus)
    combat = _CombatReceiptStub(bus, publish_receipt=False)
    module = ActiveResponseSOAR()
    module.bind(bus)
    monkeypatch.setattr(module, "_event_in_response_scope", lambda _event: True)

    def forbidden(*_args):
        raise AssertionError("Held synthetic delegation reached a target or Combat backend")

    monkeypatch.setattr(module, "_exact_process_binding_ok", forbidden)
    monkeypatch.setattr(module, "_combat_consumer", forbidden)
    # An unrelated, signed historical success cannot supply the missing exact
    # original producer-proof adapter for this event.
    bus.publish(Event("Adversary Combat", "unrelated old action", Severity.HIGH, ts=10.0,
                      details={"queue_request_id": "f" * 32, "mitigated": True,
                               "postcondition_verified": True, "action_ids": ["act-old"]}))

    module._kill_and_rollback(event)

    result = next(
        item for item in bus.recent(20)
        if item.module == module.name and item.details.get("receipt_status") == "held-original-proof-adapter"
    )
    assert result.details["mitigated"] is False
    assert result.details["response_authorized"] is False
    assert result.details.get("combat_action_ids", []) == []
    assert not result.details.get("queue_request_id")
    assert result.details["trigger_ts"] == event.ts
    assert result.details["response_withheld_reason"] == "original-producer-proof-adapter-unavailable"
    assert not [item for item in bus.recent(20) if item.module == "Active Response SOAR Request"]
    assert combat.submitted == [] and combat.reads == 0


def test_fresh_request_bound_signed_receipt_gets_mitigation_credit(monkeypatch) -> None:
    # Test only the retained receipt-verification seam. General SOAR envelopes
    # are held, so no synthetic event is dispatched to obtain this fixture.
    bus = EventBus()
    bus.arm(BusAuthority(b"d" * 32))
    combat = _CombatReceiptStub(bus, publish_receipt=True)
    module = ActiveResponseSOAR()
    module.bind(bus)
    request_id, request_ts = "e" * 32, 20.0
    assert module._verified_request_receipt(combat, request_id, request_ts) is None
    request = Event("Inert Receipt Fixture", "exact correlation", Severity.HIGH, ts=request_ts,
                    details={"queue_request_id": request_id})
    combat._submit(request)
    receipt = module._verified_request_receipt(combat, request_id, request_ts)
    assert receipt is not None and bus.verify(receipt)
    assert receipt.details["mitigated"] is True
    assert receipt.details["postcondition_verified"] is True
    assert receipt.details["action_ids"] == ["act-fresh"]
    assert receipt.details["queue_request_id"] == request_id
    assert module._verified_request_receipt(combat, "a" * 32, request_ts) is None
    assert module._verified_request_receipt(combat, request_id, receipt.ts + 1) is None
    receipt.details["mitigated"] = False
    assert not bus.verify(receipt)
    assert module._verified_request_receipt(combat, request_id, request_ts) is None
    receipt.details["mitigated"] = True
    assert bus.verify(receipt)
    combat.rows[-1]["details"]["postcondition_verified"] = False
    assert module._verified_request_receipt(combat, request_id, request_ts) is None
    assert not [item for item in bus.recent(20) if item.module == "Active Response SOAR Request"]
