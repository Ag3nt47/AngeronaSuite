from __future__ import annotations

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity


def test_info_flood_cannot_evict_priority_evidence_from_revision_consumers() -> None:
    bus = EventBus(ring_size=3, priority_ring_size=4)
    general_cursor = bus.revision()
    priority_cursor = bus.priority_revision()

    bus.publish(Event("Network Monitor", "active attack", Severity.CRITICAL))
    for index in range(20):
        bus.publish(Event("Telemetry", f"noise-{index}", Severity.INFO))

    priority_revision, priority_events, priority_overflow = bus.priority_since(
        priority_cursor
    )
    assert priority_revision == 1
    assert priority_overflow is False
    assert [event.message for event in priority_events] == ["active attack"]

    _revision, general_events, general_overflow = bus.recent_since(general_cursor)
    assert general_overflow is True
    assert "active attack" in {event.message for event in general_events}


def test_priority_lane_is_bounded_and_reports_its_own_overflow() -> None:
    bus = EventBus(ring_size=2, priority_ring_size=2)
    for index in range(3):
        bus.publish(Event("Detector", f"high-{index}", Severity.HIGH))

    revision, events, overflow = bus.priority_since(0)

    assert revision == 3
    assert overflow is True
    assert [event.message for event in events] == ["high-2", "high-1"]


def test_priority_lane_retains_the_signed_event_not_an_unsigned_copy() -> None:
    bus = EventBus(ring_size=1, priority_ring_size=2)
    bus.arm(BusAuthority(b"p" * 32))
    bus.publish(Event("Detector", "signed", Severity.HIGH, details={"pid": 9}))

    _revision, events, overflow = bus.priority_since(0)

    assert overflow is False
    assert len(events) == 1
    assert events[0].hmac_sig
    assert bus.verify(events[0]) is True

