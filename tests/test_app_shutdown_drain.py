from types import SimpleNamespace

import pytest

from angerona.app import AngeronaApp


class _Stopper:
    def __init__(self, result=True):
        self.result = result
        self.called = False

    def stop(self, *args, **kwargs):
        self.called = True
        return self.result


class _Closer:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _app(recorder_drained, evidence_drained):
    app = AngeronaApp.__new__(AngeronaApp)
    app._resilience = None
    app.reporter = _Stopper()
    app._mcp = None
    app._fleet_service = None
    app._fleet_plane = None
    app.manager = SimpleNamespace(stop_all=lambda: None)
    app.flight_recorder_worker = _Stopper(recorder_drained)
    app.evidence_ingestion = _Stopper(evidence_drained)
    app.storage = _Closer()
    app.evidence_store = _Closer()
    app.config = SimpleNamespace(
        ollama_host="http://127.0.0.1:1", ollama_model="test",
    )
    return app


def test_shutdown_does_not_close_databases_under_live_workers(monkeypatch):
    monkeypatch.setattr(
        "angerona.core.ollama_lifecycle.unload_angerona_models",
        lambda *_args, **_kwargs: None,
    )
    app = _app(False, False)
    app.shutdown()
    assert not app.storage.closed
    assert not app.evidence_store.closed


def test_shutdown_closes_after_successful_drains(monkeypatch):
    monkeypatch.setattr(
        "angerona.core.ollama_lifecycle.unload_angerona_models",
        lambda *_args, **_kwargs: None,
    )
    app = _app(True, True)
    app.shutdown()
    assert app.storage.closed
    assert app.evidence_store.closed


def test_shutdown_keeps_stores_open_when_optional_native_retirement_is_unproven(monkeypatch):
    monkeypatch.setattr(
        "angerona.core.ollama_lifecycle.unload_angerona_models", lambda *_args, **_kwargs: None,
    )
    app = _app(True, True)
    app.manager._curated_tools_controller = SimpleNamespace(
        shutdown=lambda: None, wait_for_shutdown=lambda _timeout: False,
    )
    app.shutdown()
    assert app._optional_owned_drained is False
    assert app.flight_recorder_worker.called
    assert app.evidence_ingestion.called
    assert not app.storage.closed
    assert not app.evidence_store.closed


class _ParkedRecorder(_Stopper):
    def __init__(self, changes=None):
        super().__init__(False)
        self.changes = changes or {}

    def retirement_snapshot(self):
        if not self.called:
            return dict(schema=1, worker_generation=7, workers_retired=False,
                        stopping=False, drained=False, pending_events=2)
        return {**dict(schema=1, worker_generation=7, workers_retired=True,
                       stopping=True, drained=False, pending_events=2), **self.changes}


@pytest.mark.parametrize("changes,closed", [
    ({}, True), ({"workers_retired": False}, False), ({"stopping": False}, False),
    ({"worker_generation": 8}, False), ({"worker_generation": True}, False),
    ({"pending_events": True}, False), ({"schema": True}, False),
])
def test_retired_recorder_can_close_without_claiming_volatile_tail_drained(monkeypatch, changes, closed):
    from angerona.core import ollama_lifecycle
    monkeypatch.setattr(ollama_lifecycle, "unload_angerona_models", lambda *_a, **_k: None)
    app = _app(False, True)
    app.flight_recorder_worker = _ParkedRecorder(changes)
    app.shutdown()
    assert app.storage.closed is closed
    assert app._recorder_drained_at_shutdown is False
    if closed:
        assert app._recorder_pending_at_shutdown == 2


@pytest.mark.parametrize("changes,retired", [
    ({}, True), ({"workers_retired": False}, False), ({"stopping": False}, False),
    ({"worker_generation": 8}, False), ({"pending_events": -1}, False),
    ({"pending_events": True}, False),
])
def test_headless_retirement_distinguishes_worker_exit_from_memory_drain(changes, retired):
    from angerona.core.headless import _HeadlessResources
    resources = SimpleNamespace(recorder=_ParkedRecorder(changes))
    assert _HeadlessResources._stop_recorder(resources) is retired
    assert resources.recorder_drained is False
    if retired:
        assert resources.recorder_pending_at_shutdown == 2
