from __future__ import annotations

import threading
from types import SimpleNamespace

from angerona.core import module_base
from angerona.core.module_base import BaseModule
from angerona.modules.evolution_engine import EvolutionEngine
from angerona.modules.watchdog_monitor import WatchdogMonitor


def _engine_without_io():
    engine = EvolutionEngine.__new__(EvolutionEngine)
    BaseModule.__init__(engine)
    engine.status = "running"
    engine._thread = SimpleNamespace(is_alive=lambda: True)
    return engine


def test_idle_cadence_remains_live_without_doing_model_or_file_work(monkeypatch):
    engine = _engine_without_io()
    now = [100.0]
    waits = []
    monkeypatch.setattr(module_base.time, "monotonic", lambda: now[0])

    class StopToken:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, timeout=None):
            waits.append(timeout)
            assert timeout == 60.0
            now[0] += timeout
            snapshot = engine.operational_snapshot()
            assert snapshot["watchdog_liveness_enabled"]
            assert not snapshot["watchdog_deadline_missed"]
            assert WatchdogMonitor._module_fault(snapshot) is None
            if len(waits) == 3:
                self.stopped = True
            return self.stopped

    token = StopToken()
    engine.generation_stop_event = lambda: token
    engine.run()
    assert waits == [60.0] * 3
    assert engine._cycle_count == 3
    assert engine._last_cycle_completed_at == 220.0

    # The declared cadence is still bounded if the worker stops progressing.
    now[0] = 311.0
    expired = engine.operational_snapshot()
    assert expired["watchdog_deadline_missed"]
    assert "deadline missed" in WatchdogMonitor._module_fault(expired)
    engine._thread = SimpleNamespace(is_alive=lambda: False)
    assert "no live worker thread" in WatchdogMonitor._module_fault(engine.operational_snapshot())


def test_already_stopped_engine_never_publishes_a_cycle():
    engine = _engine_without_io()
    engine.set_health(40, "prior proposal failure requires review")
    previous = engine.health, engine.health_note, engine.health_evidence
    stop = threading.Event()
    stop.set()
    engine.generation_stop_event = lambda: stop
    engine.run()
    assert not engine.first_cycle_complete
    assert engine._cycle_count == 0
    assert (engine.health, engine.health_note, engine.health_evidence) == previous


def test_idle_stop_uses_old_generation_token_and_publishes_no_late_cycle():
    engine = _engine_without_io()
    old_stop = threading.Event()
    engine._stop = old_stop
    engine._run_context.stop_event = old_stop
    waits = []

    def stop_during_wait(timeout=None):
        waits.append(timeout)
        old_stop.set()
        engine._stop = threading.Event()
        return True

    old_stop.wait = stop_during_wait
    engine.run()
    assert waits == [60.0]
    assert engine._cycle_count == 1
    assert not engine._stop.is_set()
