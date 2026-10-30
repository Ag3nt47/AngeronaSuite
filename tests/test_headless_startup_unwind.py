"""Startup failures retain real local worker ownership and SQLite ordering."""
from __future__ import annotations

import os
import threading
from types import SimpleNamespace

import pytest

from angerona.core import headless
from angerona.core.eventbus import BusAuthority


@pytest.fixture
def graph(tmp_path, monkeypatch):
    from angerona.core import alert_retention, attack_tracker, incidents, ollama_lifecycle
    from angerona.core import remediation_log, runtime_metrics

    monkeypatch.setattr(headless, "_HEADLESS_RETIREMENT_HOLD", None)
    events, workers = [], []
    selected = SimpleNamespace(failure="", pending="", resources=None)
    config = SimpleNamespace(data_dir=tmp_path, db_path=tmp_path / "inert.sqlite", eco_mode=False,
        ollama_host="http://127.0.0.1:1", jarvis_control_enabled=False)
    monkeypatch.setattr(headless.Config, "load", lambda: config)
    monkeypatch.setenv("ANGERONA_RUNTIME_METRICS", "1")
    monkeypatch.delenv("ANGERONA_RESILIENCE", raising=False)
    monkeypatch.setattr(headless.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(incidents, "get_correlator", lambda: SimpleNamespace(on_event=lambda _event: None))
    monkeypatch.setattr(remediation_log, "init_log", lambda *_args: None)
    monkeypatch.setattr(attack_tracker, "init_tracker", lambda: SimpleNamespace(on_event=lambda _event: None))
    monkeypatch.setattr(ollama_lifecycle, "request_ollama_start", lambda *_args, **_kwargs: None)

    class Failure(RuntimeError):
        pass
    class Worker:
        def __init__(self, name):
            self.name = name
            self.stop_event = threading.Event()
            self._thread = None
            self.thread = None
            workers.append(self)
        def start(self):
            self._thread = self.thread = threading.Thread(target=self.stop_event.wait,
                                                          name="inert-unwind-" + self.name, daemon=False)
            self._thread.start()
            events.append(self.name + ":start")
            if selected.failure == self.name + "-start":
                raise Failure(self.name)
        def stop(self, **_kwargs):
            events.append(self.name + ":stop")
            if selected.pending == self.name:
                return False
            self.stop_event.set()
            if self._thread is not None:
                self._thread.join(2)
            return self._thread is None or not self._thread.is_alive()

    class Storage:
        authority = BusAuthority(b"s" * 32)
        def close(self):
            assert not any(worker._thread is not None and worker._thread.is_alive() for worker in workers)
            events.append("storage:close")
    monkeypatch.setattr(headless, "FlightRecorder", lambda _path: Storage())

    class Recorder(Worker):
        def __init__(self, _storage):
            super().__init__("recorder")
        def submit(self, _event):
            return True
    monkeypatch.setattr(headless, "AsyncFlightRecorder", Recorder)
    class Retention(Worker):
        def __init__(self, *_args):
            super().__init__("retention")
        def append(self, _line):
            return True
    monkeypatch.setattr(alert_retention, "AlertRetentionWorker", Retention)
    monkeypatch.setattr(alert_retention.RetentionPolicy, "from_config", lambda _config: object())
    monkeypatch.setattr(runtime_metrics, "RuntimeMetrics", lambda **_kwargs: object())
    monkeypatch.setattr(runtime_metrics, "MetricsPublisher", lambda *_args: Worker("metrics"))

    class Module(Worker):
        def __init__(self):
            super().__init__("module")
    class Manager:
        def __init__(self, *_args, **_kwargs):
            self.module = Module()
            self.modules = {"inert": self.module}
        def discover(self):
            if selected.failure == "discover":
                raise Failure("discover")
        def start_enabled(self):
            self.module.start()
            if selected.failure == "start-enabled":
                raise Failure("start-enabled")
        def stop_all(self):
            self.module.stop()
        def reconcile_usage(self):
            pass
    monkeypatch.setattr(headless, "ModuleManager", Manager)
    monkeypatch.setattr(headless, "StatusReporter", lambda *_args, **_kwargs: Worker("reporter"))
    control = SimpleNamespace(attach=lambda *_args: None, graph_retirement_pending=False)
    def ready():
        if selected.failure == "ready":
            raise Failure("ready")
    control.ready = ready
    selected.events, selected.workers, selected.control, selected.Failure = events, workers, control, Failure
    try:
        yield selected
    finally:
        for worker in workers:
            worker.stop_event.set()
            if worker._thread is not None:
                worker._thread.join(3)
                assert not worker._thread.is_alive()


@pytest.mark.parametrize("stage", ["recorder-start", "retention-start", "metrics-start", "discover",
                                   "start-enabled", "reporter-start", "ready"])
def test_failure_at_each_startup_stage_drains_started_workers_before_storage_close(graph, stage):
    graph.failure = stage
    with pytest.raises(graph.Failure):
        headless.run_headless(runtime_control=graph.control)
    assert graph.events[-1] == "storage:close"
    assert headless._HEADLESS_RETIREMENT_HOLD is None
    assert not graph.control.graph_retirement_pending
    assert not any(worker._thread is not None and worker._thread.is_alive() for worker in graph.workers)


@pytest.mark.parametrize("pending", ["recorder", "retention", "module"])
def test_pending_writer_or_producer_retains_graph_and_never_closes_sqlite(graph, pending):
    graph.failure, graph.pending = "ready", pending
    with pytest.raises(headless.HeadlessRetirementPending):
        headless.run_headless(runtime_control=graph.control)
    assert "storage:close" not in graph.events
    assert headless._HEADLESS_RETIREMENT_HOLD is not None and graph.control.graph_retirement_pending
    assert headless._HEADLESS_RETIREMENT_HOLD.storage is not None
    with pytest.raises(headless.HeadlessRetirementPending):
        headless.run_headless()


def test_service_composes_cached_owned_core_supplier_before_discovery(graph, monkeypatch):
    from angerona.core import engine_service_status, service_process_context, windows_engine_custody

    owner = SimpleNamespace(identity=SimpleNamespace(pid=os.getpid()), service_sid="S-1-5-80-1-2-3-4-5")
    monkeypatch.setattr(windows_engine_custody, "active_engine_custody", lambda: owner)
    monkeypatch.setattr(engine_service_status, "active_engine_custody", lambda: owner)
    control = engine_service_status.ServiceStatusControl(owner, _read_policy=lambda _owner: frozenset())
    created = []
    class Context:
        def __init__(self, admitted):
            assert admitted is owner
            created.append(self)
        def owned_process_identities(self):
            return ()  # Deliberately unavailable model, never invented coverage.
        def start(self):
            graph.events.append("context:start")
        def request_stop(self):
            graph.events.append("context:request-stop")
        def close(self):
            graph.events.append("context:close")
            return True
    monkeypatch.setattr(service_process_context, "ServiceProcessContext", Context)
    original_discover = headless.ModuleManager.discover
    def discover(manager):
        assert manager.owned_process_identities.__self__ is created[0]
        assert manager.owned_process_identities() == ()
        graph.events.append("discover:with-owned-context")
        original_discover(manager)
    monkeypatch.setattr(headless.ModuleManager, "discover", discover)
    stop = threading.Event()
    stop.set()
    assert headless.run_headless(stop_event=stop, runtime_control=control, service_custody=owner) == 0
    assert graph.events.index("context:start") < graph.events.index("discover:with-owned-context")
    assert graph.events.index("context:close") < graph.events.index("storage:close")
    assert graph.events[-1] == "storage:close"
