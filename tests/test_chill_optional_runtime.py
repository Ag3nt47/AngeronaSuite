"""Quiet optional work stays bounded; live cadence and operator intent survive."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.core.background_pacing import BackgroundPacingController, RoutineWorkPacer, get_pacing_controller
from angerona.core.chill_mode import CHILL_THROTTLE_FLOORS, chill_ai_blocked, set_chill_ai_blocked
from angerona.core.chill_runtime import ChillRuntimeController, CHILL_USER_ONLY_MODULES


def test_chill_optional_policy_is_independent_of_feedback_and_restores_full():
    controller = BackgroundPacingController(clock=lambda: 100.0)
    assert controller.optional_interval(3) == controller.interval(3) == 3
    assert controller.batch_delay() == 0
    controller.set_chill_active(True)
    controller.set_enabled(False)
    assert controller.snapshot()["chill_active"] is True
    assert controller.batch_delay() == pytest.approx(0.05)
    assert controller.optional_interval(3) == 24
    assert controller.optional_interval(60) == 360
    assert controller.optional_interval(0) == 0
    assert controller.interval(3) == 3  # existing live inventory path
    assert controller.multiplier() == 1
    controller.set_chill_active(False)
    assert controller.batch_delay() == 0
    assert controller.optional_interval(3) == 3


def test_chill_yields_all_optional_items_and_releases_policy_for_threat_wake():
    now = [100.0]
    controller = BackgroundPacingController(clock=lambda: now[0])
    controller.set_chill_active(True)
    worker = RoutineWorkPacer(controller, clock=lambda: now[0])
    completed, waits = [], []
    for index in range(1, 33):
        now[0] += 0.02
        completed.append(index)
        delay = worker.pause_seconds(index, batch_size=8)
        waits.append(delay)
        now[0] += delay
        worker.resume()
    assert completed == list(range(1, 33))
    assert sum(waits) == pytest.approx(1.6)
    assert max(waits) <= 0.05
    controller.set_chill_active(False)  # sensor escalation removes quiet policy
    now[0] += 0.02
    assert worker.pause_seconds(40, batch_size=8) == 0


def test_runtime_escalation_changes_pacing_without_unlocking_models(monkeypatch):
    config = SimpleNamespace()
    controller = ChillRuntimeController(SimpleNamespace(modules={}),
                                        SimpleNamespace(revision=lambda: 0), config)
    monkeypatch.setattr(controller, "_release_models_async", lambda: None)
    controller.prepare_runtime()
    assert get_pacing_controller().chill_active()
    assert chill_ai_blocked(config)
    controller._set_runtime_quiet(False)
    assert not get_pacing_controller().chill_active()
    assert chill_ai_blocked(config)
    assert "AI Triage (Ollama)" in CHILL_USER_ONLY_MODULES
    controller._set_runtime_quiet(True)
    assert chill_ai_blocked(config)
    set_chill_ai_blocked(config, False)  # explicit operator Full action
    controller._set_runtime_quiet(False)
    assert not chill_ai_blocked(config)


def test_heal_automatic_ai_work_waits_through_alert_until_manual_full(tmp_path, monkeypatch):
    from angerona.modules import self_healer

    pending = tmp_path / "pending.json"
    pending.write_bytes(b"inert retained diagnostic evidence")
    module = self_healer.SelfHealer()
    monkeypatch.setattr(self_healer, "_snapshot_dir", lambda: tmp_path)
    calls = []
    monkeypatch.setattr(module, "process_snapshots_once", lambda *args, **kwargs: calls.append(args))
    config = SimpleNamespace()
    set_chill_ai_blocked(config, True)
    sleeps = [0]

    def sleep(_seconds):
        sleeps[0] += 1
        if sleeps[0] == 1:
            monkeypatch.setenv("ANGERONA_CHILL_ACTIVE", "0")  # CHILL:ALERT
        elif sleeps[0] == 2:
            set_chill_ai_blocked(config, False)  # manual Full
        else:
            module._stop.set()

    monkeypatch.setattr(module, "sleep", sleep)
    module.run()
    assert sleeps[0] == 3 and len(calls) == 1
    assert pending.read_bytes() == b"inert retained diagnostic evidence"


def test_tune_learning_is_optional_but_live_protection_floors_stay_unchanged():
    assert CHILL_THROTTLE_FLOORS["TUNE"] == 8
    assert "Network Monitor" not in CHILL_THROTTLE_FLOORS
    assert CHILL_THROTTLE_FLOORS["Process Monitor"] == 2


def test_manual_full_recovers_retained_intent_without_a_live_controller():
    from angerona.core.engine_control import EngineControl

    config = SimpleNamespace(runtime_chill_active=True)
    set_chill_ai_blocked(config, True)
    get_pacing_controller().set_chill_active(True)
    EngineControl._set_chill(SimpleNamespace(chill=None, config=config), False)
    assert not chill_ai_blocked(config)
    assert config.runtime_chill_active is False
    assert not get_pacing_controller().chill_active()
