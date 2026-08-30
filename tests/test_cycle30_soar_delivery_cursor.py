from __future__ import annotations

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.soar import SOARModule
from angerona.modules.soar_engine import ActiveResponseSOAR


def _publish_pair(bus: EventBus) -> None:
    bus.publish(Event("sensor", "first", Severity.HIGH, 1.0, {}))
    bus.publish(Event("sensor", "second", Severity.HIGH, 2.0, {}))


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
        self.rows = [{
            "action_id": "act-old",
            "trigger_module": "sensor",
            "trigger_ts": 10.0,
            "status": "applied",
            "integrity_status": "verified",
            "details": {"postcondition_verified": True},
        }]

    def _submit(self, request: Event) -> None:
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
    monkeypatch.setattr(module, "_exact_process_binding_ok", lambda _event: True)
    monkeypatch.setattr(module, "_combat_consumer", lambda _event: (combat, False))
    clock = [0.0]
    monkeypatch.setattr("angerona.modules.soar_engine.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "angerona.modules.soar_engine.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds + 1.0),
    )

    module._kill_and_rollback(event)

    result = next(
        item for item in bus.recent(20)
        if item.module == module.name and "was delegated" in item.message
    )
    assert result.details["mitigated"] is False
    assert result.details["combat_action_ids"] == []
    assert result.details["receipt_status"] == "pending-timeout"
    assert result.details["queue_request_id"]


def test_fresh_request_bound_signed_receipt_gets_mitigation_credit(monkeypatch) -> None:
    bus = EventBus()
    bus.arm(BusAuthority(b"d" * 32))
    event = _signed_response_event(bus)
    combat = _CombatReceiptStub(bus, publish_receipt=True)
    module = ActiveResponseSOAR()
    module.bind(bus)
    monkeypatch.setattr(module, "_event_in_response_scope", lambda _event: True)
    monkeypatch.setattr(module, "_exact_process_binding_ok", lambda _event: True)
    monkeypatch.setattr(module, "_combat_consumer", lambda _event: (combat, False))

    module._kill_and_rollback(event)

    result = next(
        item for item in bus.recent(20)
        if item.module == module.name and "was delegated" in item.message
    )
    assert result.details["mitigated"] is True
    assert result.details["combat_action_ids"] == ["act-fresh"]
    assert result.details["receipt_status"] == "verified-applied"
