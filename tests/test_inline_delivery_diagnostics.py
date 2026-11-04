from __future__ import annotations

from dataclasses import replace
import threading

import pytest

from angerona.core.eventbus import (
    ActiveSubscriberDelivery, Event, EventBus, SubscriberActivity, SubscriberMetrics,
)
from angerona.core import subscriber_diagnostics as projection


def _metrics(**changes):
    row = SubscriberMetrics("fixture.callback", 25.0, 1, 0, 0, 1.0, 1.0, 1.0)
    return replace(row, **changes)


def _partition(section):
    assert section["total_rows"] == (
        section["retained_rows"] + section["unavailable_rows"] + section["omitted_rows"]
    )
    assert section["omitted_rows"] == (
        section["row_limit_omitted_rows"] + section["byte_budget_omitted_rows"]
        + section["producer_omitted_rows"]
    )
    assert section["retained_rows"] == len(section["rows"])


def test_real_blocked_subscriber_has_an_active_observation_before_completed_metrics(monkeypatch):
    bus = EventBus()
    entered, release = threading.Event(), threading.Event()
    errors = []

    def callback(_event):
        entered.set()
        assert release.wait(5)

    def publish():
        try:
            bus.publish(Event("fixture", "private event text must not enter timings"))
        except BaseException as error:
            errors.append(error)

    bus.subscribe(callback)
    thread = threading.Thread(target=publish, name="owned-inline-publication")
    thread.start()
    try:
        assert entered.wait(2)
        activity = bus.subscriber_activity()
        assert len(activity.rows) == 1 and activity.untracked_active == 0
        assert activity.rows[0].name == callback.__qualname__
        assert bus.subscriber_metrics()[0].deliveries == 0
        block = projection.project_subscribers(bus.subscriber_metrics(), activity)
        assert block["active"]["retained_rows"] == 1
        assert "private event text" not in str(block)
        with monkeypatch.context() as patch:
            patch.setattr("angerona.core.eventbus.time.perf_counter", lambda: pytest.fail("getter clock"))
            assert bus.subscriber_activity() == activity
        assert not release.is_set()
    finally:
        release.set()
        thread.join(timeout=5)
    assert not thread.is_alive() and not errors
    assert bus.subscriber_activity().rows == ()
    assert bus.subscriber_metrics()[0].deliveries == 1


def test_reentrant_publication_has_bounded_active_rows_and_explicit_omissions():
    bus = EventBus()
    observed = []

    def recursive(event):
        if event.details["depth"] == 70:
            observed.append(bus.subscriber_activity())
        else:
            bus.publish(Event("fixture", "nested", details={"depth": event.details["depth"] + 1}))

    bus.subscribe(recursive)
    bus.publish(Event("fixture", "nested", details={"depth": 1}))
    assert len(observed[0].rows) == 64 and observed[0].untracked_active == 6
    block = projection.project_subscribers(bus.subscriber_metrics(), observed[0])
    assert block["active"]["total_rows"] == 70
    assert block["active"]["producer_omitted_rows"] == 6
    assert sum(block[name]["inspected_rows"] for name in ("active", "completed")) == 64
    _partition(block["active"])
    _partition(block["completed"])
    assert bus.subscriber_activity() == SubscriberActivity((), 0)
    assert bus.subscriber_metrics()[0].deliveries == 70


def test_unsubscribe_during_actual_callback_preserves_only_its_inflight_observation():
    bus = EventBus()
    entered, release = threading.Event(), threading.Event()

    def callback(_event):
        entered.set()
        assert release.wait(5)

    bus.subscribe(callback)
    thread = threading.Thread(target=lambda: bus.publish(Event("fixture", "one")))
    thread.start()
    try:
        assert entered.wait(2)
        bus.unsubscribe(callback)
        assert bus.subscriber_metrics() == ()
        assert len(bus.subscriber_activity().rows) == 1
    finally:
        release.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert bus.subscriber_metrics() == ()
    assert bus.subscriber_activity() == SubscriberActivity((), 0)


def test_baseexception_does_not_leave_an_active_callback_or_change_propagation():
    bus = EventBus()

    def interrupted(_event):
        raise KeyboardInterrupt("inert fixture")

    bus.subscribe(interrupted)
    with pytest.raises(KeyboardInterrupt):
        bus.publish(Event("fixture", "one"))
    assert bus.subscriber_activity() == SubscriberActivity((), 0)


@pytest.mark.parametrize("changes", [
    {"deliveries": True}, {"deliveries": -1}, {"deliveries": 2**63},
    {"failures": 2}, {"budget_violations": 2}, {"last_delivery_ms": float("nan")},
    {"max_delivery_ms": float("inf")}, {"total_delivery_ms": -1.0},
    {"delivery_budget_ms": 0.0}, {"last_delivery_ms": 2.0},
    {"deliveries": 0}, {"name": "bad\ud800"}, {"name": "bad\nlabel"},
])
def test_invalid_metrics_are_unavailable_without_inventing_zero_counters(changes):
    block = projection.project_subscribers((_metrics(**changes),), SubscriberActivity((), 0))
    assert block["state"] == "partial"
    assert block["completed"]["unavailable_rows"] == 1
    assert block["completed"]["rows"] == []
    _partition(block["completed"])


def test_exact_collection_and_scalar_types_do_not_execute_custom_accessors():
    class Poison:
        def __iter__(self):
            pytest.fail("custom iterable inspected")

        def __float__(self):
            pytest.fail("custom converter called")

        def __str__(self):
            pytest.fail("custom string conversion called")

    block = projection.project_subscribers(Poison(), Poison())
    assert block["state"] == "unavailable"
    assert block["completed"]["total_rows"] is None
    invalid = projection.project_subscribers((_metrics(last_delivery_ms=Poison()),), None)
    assert invalid["completed"]["unavailable_rows"] == 1


def test_row_and_rendered_byte_limits_partition_loss_and_preserve_duplicate_labels():
    duplicate = projection.project_subscribers((_metrics(), _metrics()), SubscriberActivity((), 0))
    assert len(duplicate["completed"]["rows"]) == 2
    rows = tuple(_metrics(name="界" * 200) for _ in range(80))
    block = projection.project_subscribers(rows, SubscriberActivity((), 0))
    assert block["completed"]["inspected_rows"] == 64
    assert block["completed"]["row_limit_omitted_rows"] == 16
    assert block["completed"]["byte_budget_omitted_rows"] > 0
    assert all(row["name_truncated"] for row in block["completed"]["rows"])
    assert projection.encoded_projection_bytes(block) <= 16 * 1024
    _partition(block["completed"])


def test_no_tail_row_attributes_are_read_and_empty_real_bus_is_observed():
    class Poison:
        def __getattribute__(self, _name):
            pytest.fail("row-limit tail inspected")

    rows = tuple(_metrics() for _ in range(64)) + (Poison(),)
    block = projection.project_subscribers(rows, SubscriberActivity((), 0))
    assert block["completed"]["row_limit_omitted_rows"] == 1
    _partition(block["completed"])
    empty = EventBus()
    block = projection.project_subscribers(empty.subscriber_metrics(), empty.subscriber_activity())
    assert block["state"] == "observed"
    assert block["completed"]["total_rows"] == block["active"]["total_rows"] == 0


@pytest.mark.parametrize("activity", [
    SubscriberActivity((ActiveSubscriberDelivery("fixture.callback", float("nan")),), 0),
    SubscriberActivity((), True), SubscriberActivity((), -1),
])
def test_invalid_active_metadata_is_an_explicit_gap(activity):
    block = projection.project_subscribers((), activity)
    assert block["state"] == "partial"
    assert block["active"]["state"] in {"partial", "unavailable"}
    assert not block["active"]["rows"]
