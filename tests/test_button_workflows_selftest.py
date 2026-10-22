"""Offline button checks: real diagnostic bus, inert modules, no service startup."""
from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from angerona.core import selftest
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity


def _manager(*modules):
    return SimpleNamespace(platform="windows", modules={m.name: m for m in modules},
                           is_enabled=lambda _name: True)


def test_pipeline_receipt_survives_eviction_without_reading_history():
    class FloodBus(EventBus):
        def publish(self, event):
            super().publish(event)
            if event.module == "Self-Test":
                for index in range(200):
                    super().publish(Event("Noise", str(index), Severity.INFO))

        def recent(self, *_args):
            pytest.fail("normal diagnostic delivery must not poll history")

    bus = FloodBus(ring_size=8)
    bus.arm(BusAuthority(b"x" * 32))
    runner = selftest.SelfTestRunner(_manager(), bus)
    assert runner._pipeline_check() == (
        True, "synthetic event delivered to diagnostic subscriber")
    assert bus.subscriber_metrics() == ()


def test_pipeline_detaches_diagnostic_subscriber_after_publish_failure():
    class FailedBus(EventBus):
        def publish(self, _event):
            raise OSError("fixture publication failure")

    bus = FailedBus()
    runner = selftest.SelfTestRunner(_manager(), bus)
    with pytest.raises(OSError, match="fixture publication failure"):
        runner._pipeline_check()
    assert bus.subscriber_metrics() == ()


def test_pipeline_rejects_ring_only_delivery(monkeypatch):
    class RingOnlyBus(EventBus):
        def publish(self, event):
            # A broken adapter preserves the old ring-only appearance of health.
            with self._lock:
                self._ring.append(event)

    bus = RingOnlyBus()
    runner = selftest.SelfTestRunner(_manager(), bus)
    runner._PIPELINE_TIMEOUT = 0.03
    completed, _error, _result = selftest._bounded_call(
        runner._pipeline_check, selftest._EVENT_CALLS, 0.03, name="InertRingOnlyCanary")
    assert completed is False
    # The retained call must finish and detach; its process-wide slot remains
    # occupied throughout the bounded 2-second receipt wait.
    assert selftest._EVENT_CALLS.acquire(timeout=3.0)
    selftest._EVENT_CALLS.release()
    assert bus.subscriber_metrics() == ()


def test_module_stage_timings_and_slowest_summary_are_persisted(monkeypatch, tmp_path):
    path = tmp_path / "selftest.json"
    monkeypatch.setattr(selftest, "_failure_log_path", lambda: path)

    def active():
        time.sleep(0.01)
        return True, "inert timing fixture"

    module = SimpleNamespace(name="Timed fixture", self_test=active)
    runner = selftest.SelfTestRunner(_manager(module), EventBus())
    report = runner.run(timeout=1.0)
    record = next(row for row in runner.last_results if row["kind"] == "module")
    assert record["stage_ms"]["contract"] >= 0
    assert record["stage_ms"]["active_test"] >= 5
    assert record["duration_ms"] >= record["stage_ms"]["active_test"]
    assert "Slowest modules: Timed fixture" in report
    assert json.loads(path.read_text(encoding="utf-8"))["results"] == runner.last_results


def test_selftest_button_preserves_chill_and_never_prepares_model_service(monkeypatch, tmp_path):
    from angerona.core import ollama_lifecycle
    from angerona.gui.main_window import MainWindow

    monkeypatch.setenv("ANGERONA_CHILL_AI_BLOCKED", "1")
    monkeypatch.setenv("ANGERONA_CHILL_ACTIVE", "1")
    monkeypatch.setattr(selftest, "_failure_log_path", lambda: tmp_path / "selftest.json")

    def forbidden(*_args, **_kwargs):
        pytest.fail("the all-module Self-Test button attempted a model/service action")

    monkeypatch.setattr(ollama_lifecycle, "ensure_ollama_service", forbidden)
    ai = SimpleNamespace(name="AI Triage (Ollama)", self_test=forbidden)
    progress, finished = [], []
    host = SimpleNamespace(
        manager=_manager(ai), bus=EventBus(),
        config=SimpleNamespace(ollama_host="http://127.0.0.1:11434"),
        _selftest_progress=SimpleNamespace(emit=lambda *args: progress.append(args)),
        _selftest_done=SimpleNamespace(emit=lambda *args: finished.append(args)),
    )
    MainWindow._self_test_worker(host)
    assert progress[-1] == (2, 2)
    assert len(finished) == 1 and finished[0][1] == []
    assert "[SKIP] AI Triage (Ollama)" in finished[0][0]
    assert "1 passed, 0 failed, 1 skipped" in finished[0][0]


def test_default_selftest_includes_spyware_inert_scenarios_without_live_collectors(monkeypatch, tmp_path):
    from angerona.modules.spyware_guard import SpywareGuardModule

    monkeypatch.setattr(selftest, "_failure_log_path", lambda: tmp_path / "selftest.json")

    def forbidden(*_args, **_kwargs):
        pytest.fail("offline SpywareGuard self-test used a live collector")

    module = SpywareGuardModule(persistence_collector=forbidden, memory_collector=forbidden,
                               process_observer=forbidden, connection_observer=forbidden)
    runner = selftest.SelfTestRunner(_manager(module), EventBus())
    report = runner.run(timeout=2.0)
    assert "[PASS] SpywareGuard" in report
    assert runner.last_failures == []
    assert module.dashboard_snapshot()["stats"]["sandbox_runs"] == 0
    assert module.dashboard_snapshot()["containments"] == []
