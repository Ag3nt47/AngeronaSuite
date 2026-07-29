from types import SimpleNamespace

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
