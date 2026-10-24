"""Opt-in native CPU correlation never becomes process/response authority."""
from types import SimpleNamespace
import threading

import pytest

from angerona.core.status_report import _worker_identity


def test_actual_worker_identity_and_retirement():
    ready, stop = threading.Event(), threading.Event()
    worker = threading.Thread(target=lambda: (ready.set(), stop.wait(5)), daemon=True)
    module = SimpleNamespace(_thread=worker, _lifecycle_generation=7)
    assert _worker_identity(module) == {}
    worker.start()
    try:
        assert ready.wait(2)
        assert _worker_identity(module) == {
            "native_id": str(worker.native_id), "lifecycle_generation": 7,
            "advisory_only": True,
        }
    finally:
        stop.set()
        worker.join(2)
    assert not worker.is_alive()
    assert _worker_identity(module) == {}


@pytest.mark.parametrize("change", ["generation", "thread"])
def test_racing_generation_is_not_attributed(change):
    module = SimpleNamespace(_lifecycle_generation=2)

    class RacingThread(threading.Thread):
        @property
        def native_id(self):
            return 123

        def is_alive(self):
            if change == "generation":
                module._lifecycle_generation += 1
            else:
                module._thread = None
            return True

    module._thread = RacingThread()
    assert _worker_identity(module) == {}


def test_opt_in_reporter_integration(tmp_path, monkeypatch):
    from angerona.core.eventbus import EventBus
    from angerona.core.status_report import StatusReporter

    module = SimpleNamespace(name="fixture", category="test", version="1", status="running",
        health=100, health_state="ok", health_note="", last_error="",
        _thread=threading.current_thread(), _lifecycle_generation=3)
    manager = SimpleNamespace(modules={"fixture": module}, is_enabled=lambda _: True)
    config = SimpleNamespace(data_dir=tmp_path, runtime_chill_active=False,
                             ollama_host="local", ollama_model="fixture")
    reporter = StatusReporter(EventBus(), SimpleNamespace(count_since=lambda _: 0), manager, config)
    monkeypatch.delenv("ANGERONA_RUNTIME_METRICS", raising=False)
    assert "worker" not in reporter._snapshot()["modules"][0]
    monkeypatch.setenv("ANGERONA_RUNTIME_METRICS", "1")
    row = reporter._snapshot()["modules"][0]
    assert row["worker"]["native_id"] == str(threading.get_native_id())
    assert row["worker"]["lifecycle_generation"] == 3
