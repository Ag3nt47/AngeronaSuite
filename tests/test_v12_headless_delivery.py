"""Exercise the bounded subscription and graph cleanup without starting sensors."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from angerona.core import alert_retention, headless, recorder_integrity
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import AsyncFlightRecorder, FlightRecorder


def test_headless_uses_real_bounded_recorder_subscription_and_drains_before_close(tmp_path, monkeypatch):
    class InertGraphBoundary(RuntimeError):
        pass

    calls, stores, writers, buses = [], [], [], []
    monkeypatch.setattr(headless, "_HEADLESS_RETIREMENT_HOLD", None)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: tmp_path / "bus.key"))
    config = headless.Config(data_dir=tmp_path)
    monkeypatch.setattr(headless.Config, "load", staticmethod(lambda: config))
    monkeypatch.setattr(recorder_integrity, "provider_from_config", lambda _config: None)
    real_graph = headless._run_headless_graph

    def graph(**kwargs):
        kwargs["resources"].manager = SimpleNamespace(
            modules={}, stop_all=lambda: calls.append("modules-stopped"))
        return real_graph(**kwargs)

    delivered = []

    def storage_factory(path):
        storage = FlightRecorder(path)
        native_close = storage.close
        closed = [False]

        def close():
            assert calls[-1] == "recorder-drained"
            rows = storage.recent(10)
            assert len(rows) == 1 and rows[0].message == "inert headless delivery"
            assert rows[0].hmac_sig == delivered[0].hmac_sig
            native_close()
            closed[0] = True
            calls.append("storage-closed")

        storage.close = close
        stores.append((storage, native_close, closed))
        return storage

    def writer_factory(storage):
        worker = AsyncFlightRecorder(storage, flush_interval=0.01)
        native_stop = worker.stop
        native_submit = worker.submit

        def submit(event):
            # Observe the exact authenticated copy sent to the sole writer,
            # then forward it through the real bounded handoff.
            delivered.append(event)
            return native_submit(event)

        def stop(*, timeout):
            assert "modules-stopped" in calls
            result = native_stop(timeout=timeout)
            assert result is True
            calls.append("recorder-drained")
            return result

        worker.stop = stop
        worker.submit = submit
        writers.append((worker, native_stop))
        return worker

    def bus_factory():
        bus = EventBus()
        buses.append(bus)
        return bus

    def graph_boundary(*_args, **_kwargs):
        bus, worker = buses[0], writers[0][0]
        assert bus._subs == [worker.submit]
        assert stores[0][0].record_bus not in bus._subs
        event = Event("Headless fixture", "inert headless delivery", Severity.INFO)
        assert event.hmac_sig == ""
        bus.publish(event)
        canonical, = delivered
        assert canonical is not event and event.hmac_sig == ""
        assert canonical.hmac_sig and stores[0][0].authority.verify(canonical)
        raise InertGraphBoundary("stop before any retention, manager, network or sensor starts")

    monkeypatch.setattr(headless, "_run_headless_graph", graph)
    monkeypatch.setattr(headless, "FlightRecorder", storage_factory)
    monkeypatch.setattr(headless, "AsyncFlightRecorder", writer_factory)
    monkeypatch.setattr(headless, "EventBus", bus_factory)
    monkeypatch.setattr(alert_retention, "AlertRetentionWorker", graph_boundary)
    try:
        with pytest.raises(InertGraphBoundary):
            headless.run_headless(stop_event=threading.Event())
        assert calls == ["modules-stopped", "recorder-drained", "storage-closed"]
        assert headless._HEADLESS_RETIREMENT_HOLD is None
    finally:
        for _worker, native_stop in writers:
            assert native_stop(timeout=3.0)
        for _storage, native_close, closed in stores:
            if not closed[0]:
                native_close()


def test_headless_writer_retirement_failure_retains_sqlite_and_graph(monkeypatch):
    monkeypatch.setattr(headless, "_HEADLESS_RETIREMENT_HOLD", None)
    calls = []
    control = SimpleNamespace()
    resource = headless._HeadlessResources(threading.Event(), None, control)
    resource.manager = SimpleNamespace(modules={}, stop_all=lambda: calls.append("modules-stopped"))
    resource.recorder = SimpleNamespace(stop=lambda **_kwargs: False)
    resource.storage = SimpleNamespace(close=lambda: calls.append("storage-closed"))
    with pytest.raises(headless.HeadlessRetirementPending):
        resource.close()
    assert calls == ["modules-stopped"]
    assert resource.stop.is_set() and control.graph_retirement_pending
    assert headless._HEADLESS_RETIREMENT_HOLD is resource
