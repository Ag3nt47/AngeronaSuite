"""Bounded in-process read-model lifecycle; no Qt, network or native children."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import sentinel_lens as lens
from angerona.core.eventbus import Event, EventBus


def wait_for(predicate):
    deadline = time.monotonic() + 3.0
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.001)
    assert predicate()


def test_transient_builder_failure_retries_without_another_event(monkeypatch):
    service = lens.SentinelLensService(analysis_interval=0.01)
    real_build = lens.build_sentinel_snapshot
    attempts = []
    def recover(events, **options):
        attempts.append(tuple(events))
        if len(attempts) == 1:
            raise ValueError("inert transient fixture")
        return real_build(events, **options)
    monkeypatch.setattr(lens, "build_sentinel_snapshot", recover)
    try:
        service.start()
        assert service.submit_event(Event("fixture", "one", ts=100))
        assert service.wait_for_revision(0, 3)
        health = service.health()
        assert health["analysis_failures"] == 1 and health["processed_records"] == 1
        assert health["analysis_pending"] is False and health["state"] == "running"
        assert len(attempts) == 2
    finally:
        assert service.stop(3)
        assert not service._thread.is_alive()


def test_failed_final_analysis_does_not_claim_clean_shutdown_or_replace_snapshot(monkeypatch):
    service = lens.SentinelLensService(analysis_interval=0.01)
    initial = service.snapshot()
    def unavailable(*_args, **_kwargs):
        raise ValueError("inert persistent fixture")
    monkeypatch.setattr(lens, "build_sentinel_snapshot", unavailable)
    try:
        service.start()
        assert service.submit_event(Event("fixture", "unpublished suffix", ts=100))
        wait_for(lambda: service.health()["analysis_failures"] > 0)
        assert service.stop(3)
        assert service.stop(3)  # Repeated stop cannot overwrite failed flush evidence.
        health = service.health()
        assert health["clean_shutdown"] is False and health["analysis_pending"] is True
        assert health["state"] == "stopped" and health["snapshot_revision"] == 0
        assert service.snapshot()["nodes"] == initial["nodes"]
    finally:
        assert service.stop(3)
        assert not service._thread.is_alive()


@pytest.mark.parametrize("stage", ["subscribe", "thread-start"])
def test_start_failure_closes_admission_and_detaches_partial_subscription(monkeypatch, stage):
    bus = EventBus()
    service = lens.SentinelLensService(bus, analysis_interval=0.01)
    real_subscribe = bus.subscribe
    real_start = threading.Thread.start
    with monkeypatch.context() as patch:
        if stage == "subscribe":
            def fail_subscribe(callback, **options):
                real_subscribe(callback, **options)
                raise RuntimeError("inert subscribe failure after registration")
            patch.setattr(bus, "subscribe", fail_subscribe)
        else:
            patch.setattr(threading.Thread, "start", lambda _thread: (_ for _ in ()).throw(RuntimeError("inert start failure")))
        with pytest.raises(RuntimeError, match="inert"):
            service.start()
        health = service.health()
        assert health["state"] == "created" and health["accepting"] is False
        assert health["subscribed"] is False and service._thread is None
        assert bus.subscriber_metrics() == ()
        assert service.submit_event(Event("fixture", "rejected")) is False
    assert threading.Thread.start is real_start
    try:
        assert service.start()
        bus.publish(Event("fixture", "retry accepted", ts=100))
        assert service.wait_for_revision(0, 3)
    finally:
        assert service.stop(3)


def test_stop_detaches_callback_and_no_accepted_enqueue_can_outlive_worker(monkeypatch):
    bus = EventBus()
    service = lens.SentinelLensService(bus, analysis_interval=0.01)
    entered, release, stop_done = threading.Event(), threading.Event(), threading.Event()
    accepted, stopped = [], []
    real_put = service._queue.put_nowait
    def delayed_put(item):
        entered.set()
        assert release.wait(3)
        return real_put(item)
    service.start()
    monkeypatch.setattr(service._queue, "put_nowait", delayed_put)
    sender = threading.Thread(target=lambda: accepted.append(service.submit_event(Event("fixture", "racing stop", ts=100))))
    def stop_service():
        stopped.append(service.stop(0.5))
        stop_done.set()
    stopper = threading.Thread(target=stop_service)
    try:
        sender.start()
        assert entered.wait(3)
        stopper.start()
        assert not stop_done.wait(0.15)  # Stop must serialize after this admission.
        release.set()
        sender.join(3)
        stopper.join(3)
        assert not sender.is_alive() and not stopper.is_alive()
        assert accepted == [True] and stopped == [True]
        health = service.health()
        assert health["accepted"] == health["processed_records"] == 1
        assert health["queue_depth"] == 0 and health["clean_shutdown"] is True
        assert health["subscribed"] is False and bus.subscriber_metrics() == ()
        submitted = health["submitted"]
        bus.publish(Event("fixture", "after detach"))
        assert service.health()["submitted"] == submitted
    finally:
        release.set()
        sender.join(3)
        if stopper.ident is not None:
            stopper.join(3)
        assert service.stop(3)


def test_malformed_record_does_not_kill_worker_and_overflow_scalars_are_normalized():
    class BrokenDetails:
        @property
        def details(self):
            raise RuntimeError("inert malformed event")
    service = lens.SentinelLensService(analysis_interval=0.01)
    try:
        service.start()
        assert service.submit_event(BrokenDetails())
        assert service.submit_event(SimpleNamespace(module="fixture", message="overflow", severity=float("inf"),
                                                   ts=10**1000, details={}, hmac_sig=""))
        assert service.wait_for_revision(0, 3)
        assert service.health()["analysis_rejections"] == 1
        assert service.health()["processed_records"] == 1
        row, = service.recent_events()
        assert row.severity == 0 and row.ts == 0
    finally:
        assert service.stop(3)
