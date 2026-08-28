from __future__ import annotations

import time

import pytest

from angerona.core.eventbus import Event, EventBus


def test_inline_subscriber_latency_and_failures_are_observable() -> None:
    bus = EventBus()

    def slow(_event: Event) -> None:
        time.sleep(0.003)

    def broken(_event: Event) -> None:
        raise RuntimeError("fixture")

    bus.subscribe(slow, delivery_budget_ms=1.0)
    bus.subscribe(broken, delivery_budget_ms=10.0)
    bus.publish(Event("test", "one"))

    rows = {row.name: row for row in bus.subscriber_metrics()}
    assert rows[slow.__qualname__].deliveries == 1
    assert rows[slow.__qualname__].budget_violations == 1
    assert rows[slow.__qualname__].max_delivery_ms >= 1.0
    assert rows[broken.__qualname__].failures == 1


def test_duplicate_subscription_does_not_duplicate_metrics_or_delivery() -> None:
    bus = EventBus()
    calls: list[str] = []

    def callback(event: Event) -> None:
        calls.append(event.message)

    bus.subscribe(callback)
    bus.subscribe(callback)
    bus.publish(Event("test", "once"))

    assert calls == ["once"]
    assert len(bus.subscriber_metrics()) == 1
    assert bus.subscriber_metrics()[0].deliveries == 1


@pytest.mark.parametrize("budget", [0, -1, 60_001, "bad"])
def test_subscriber_budget_is_bounded(budget) -> None:
    with pytest.raises(ValueError):
        EventBus().subscribe(lambda _event: None, delivery_budget_ms=budget)
