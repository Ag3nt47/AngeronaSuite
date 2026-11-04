from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from angerona.core import module_base
from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule
from angerona.core.module_manager import ModuleManager
from angerona.modules import watchdog_monitor
from angerona.modules.watchdog_monitor import WatchdogMonitor


class _AliveThread:
    @staticmethod
    def is_alive() -> bool:
        return True


class _CadenceProbe(BaseModule):
    name = "Cadence Probe"
    description = "Watchdog cadence contract probe."
    category = "Test"

    def run(self) -> None:
        return None


class _WaitingProbe(BaseModule):
    name = "Watchdog Worker Fixture"
    description = "Inert generation-bound worker."
    category = "Test"

    def run(self) -> None:
        self.sleep(60.0)


class _FaultProbe:
    def __init__(self, *, generation: int = 7) -> None:
        self.status = "running"
        self.health = 100
        self.generation = generation
        self.restart_calls: list[int] = []
        self.remain_faulted = False

    def operational_snapshot(self) -> dict[str, object]:
        return {
            "status": self.status,
            "health": self.health,
            "thread_alive": True,
            "lifecycle_generation": self.generation,
            "first_cycle_complete": True,
            "cycle_count": 1,
            "last_cycle_age_seconds": 91.0,
            "watchdog_deadline_missed": self.status != "healthy",
        }

    def restart_if_generation(self, generation: int) -> bool:
        self.restart_calls.append(generation)
        if generation != self.generation:
            return False
        if not self.remain_faulted:
            self.generation += 1
            self.status = "healthy"
        return True


class _Manager:
    def __init__(self, probe: _FaultProbe) -> None:
        self.modules = {"Fault Probe": probe}
        self.enabled = True

    def is_enabled(self, _name: str) -> bool:
        return self.enabled


def test_base_module_publishes_bounded_cadence_deadline(monkeypatch) -> None:
    now = [100.0]
    monkeypatch.setattr(module_base.time, "monotonic", lambda: now[0])
    module = _CadenceProbe()
    module._thread = _AliveThread()  # type: ignore[assignment]
    module._generation_started_at = now[0]
    module.status = "running"

    module.mark_cycle_complete(interval_seconds=12.0)
    snapshot = module.operational_snapshot()
    assert snapshot["declared_cycle_interval_seconds"] == 12.0
    assert snapshot["watchdog_deadline_remaining_seconds"] == 42.0
    assert snapshot["watchdog_deadline_missed"] is False

    now[0] = 142.001
    expired = module.operational_snapshot()
    assert expired["watchdog_deadline_missed"] is True
    assert float(expired["last_cycle_age_seconds"]) > 42.0


def test_watchdog_skips_half_started_worker_without_claiming_stability(monkeypatch) -> None:
    probe = _WaitingProbe()
    watchdog = WatchdogMonitor()
    watchdog.bind(EventBus())
    watchdog.bind_manager(SimpleNamespace(modules={probe.name: probe}))
    state = watchdog_monitor._RestartState(id(probe), attempts=1, stable_since=1.0)
    watchdog._restart_state[probe.name] = state
    published = threading.Event()
    release = threading.Event()
    real_start = threading.Thread.start

    def hold_worker_start(thread):
        if thread.name == probe.name:
            published.set()
            if not release.wait(5.0):
                raise TimeoutError("worker start barrier was not released")
        return real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", hold_worker_start)
    starter = threading.Thread(target=probe.start, name="Watchdog Fixture Starter")
    sweep = threading.Thread(target=watchdog._sweep, name="Watchdog Fixture Sweep")
    starter.start()
    try:
        assert published.wait(2.0)
        assert WatchdogMonitor._module_fault(probe.operational_snapshot()) == (
            "running lifecycle has no live worker thread"
        )
        sweep.start()
        sweep.join(1.0)
        assert not sweep.is_alive(), "sampling blocked on the worker lifecycle lock"
        assert state.attempts == 1 and state.stable_since == 0.0
        assert watchdog.health == 60
        assert "lifecycle sample(s) unavailable" in watchdog.health_note
        assert not watchdog._bus.recent(10)

        release.set()
        starter.join(2.0)
        assert not starter.is_alive()
        assert probe.wait_for_first_cycle(2.0)
        watchdog._sweep()
        assert probe.lifecycle_generation == 1
        assert state.attempts == 1 and state.stable_since > 0.0
        assert watchdog.health == 85
    finally:
        release.set()
        starter.join(2.0)
        if sweep.ident is not None:
            sweep.join(2.0)
        probe.stop()
        if probe._thread is not None and probe._thread.ident is not None:
            probe._thread.join(2.0)


@pytest.mark.parametrize("with_manager", [False, True])
def test_watchdog_rechecks_fault_before_stopping_live_worker(monkeypatch, with_manager) -> None:
    probe = _WaitingProbe()
    watchdog = WatchdogMonitor()
    bus = EventBus()
    watchdog.bind(bus)
    if with_manager:
        manager = ModuleManager(bus, SimpleNamespace(module_states={}), target_platform="windows")
        manager.modules = {probe.name: probe}
    else:
        manager = SimpleNamespace(modules={probe.name: probe})
    watchdog.bind_manager(manager)
    probe.start()
    try:
        assert probe.wait_for_first_cycle(2.0)
        generation = probe.lifecycle_generation
        stop = probe.generation_stop_event()
        with probe._cycle_lock:
            probe._watchdog_deadline_at = 1.0
        assert probe.try_watchdog_snapshot()["watchdog_deadline_missed"] is True

        # A competing operation may acquire lifecycle custody after the sweep.
        held = threading.Event()
        release = threading.Event()

        def hold_lifecycle():
            with probe._lifecycle_lock:
                held.set()
                release.wait(5.0)

        owner = threading.Thread(target=hold_lifecycle)
        decisions = []
        admit = threading.Thread(target=lambda: decisions.append(
            watchdog._restart_exact_generation(probe.name, probe, generation),
        ))
        owner.start()
        try:
            assert held.wait(2.0)
            admit.start()
            admit.join(1.0)
            assert not admit.is_alive(), "watchdog admission waited for lifecycle custody"
            assert decisions == [False] and not stop.is_set()
        finally:
            release.set()
            owner.join(2.0)
            if admit.ident is not None:
                admit.join(2.0)

        # Reproduce a real same-generation heartbeat between sweep and custody.
        restart = watchdog._restart_exact_generation

        def progress_then_restart(*args):
            probe.mark_cycle_complete(interval_seconds=60.0)
            return restart(*args)

        with monkeypatch.context() as patch:
            patch.setattr(watchdog, "_restart_exact_generation", progress_then_restart)
            watchdog._sweep()
        assert probe.lifecycle_generation == generation
        assert not stop.is_set()
        assert [event.details["finding_code"] for event in bus.recent(10)] == [
            "watchdog.restart.rejected",
        ]

        with probe._cycle_lock:
            probe._watchdog_deadline_at = 1.0
        assert watchdog._restart_exact_generation(probe.name, probe, generation)
        assert stop.is_set()
        assert probe.lifecycle_generation == generation + 1
        assert probe.wait_for_first_cycle(2.0)
        if with_manager:
            # Explicit authorized restarts do not require a watchdog fault.
            assert manager.restart_module_generation(probe.name, probe, generation + 1)
            assert probe.lifecycle_generation == generation + 2
    finally:
        probe.stop()
        probe._thread.join(2.0)


def test_watchdog_recovers_alive_but_stale_exact_generation() -> None:
    probe = _FaultProbe()
    watchdog = WatchdogMonitor()
    watchdog._mgr = _Manager(probe)

    watchdog._sweep()

    assert probe.restart_calls == [7]
    assert probe.generation == 8
    assert watchdog.health == 55
    assert "unresolved" in watchdog.health_note

    watchdog._sweep()
    assert probe.restart_calls == [7]
    assert watchdog.health == 85
    assert "stability window" in watchdog.health_note


def test_manager_authority_rejects_stale_generation_without_stop_start() -> None:
    probe = _FaultProbe()

    class _RacingManager(_Manager):
        def restart_module_generation(self, name, expected_module, generation):
            assert name == "Fault Probe"
            assert expected_module is probe
            probe.generation += 1
            return expected_module.restart_if_generation(generation)

    watchdog = WatchdogMonitor()
    watchdog._mgr = _RacingManager(probe)
    watchdog._sweep()

    assert probe.restart_calls == [7]
    assert probe.generation == 8
    assert probe.status == "running"
    assert watchdog.health == 45
    assert "unresolved" in watchdog.health_note


def test_disabled_module_is_never_restarted_and_incident_state_is_cleared() -> None:
    probe = _FaultProbe()
    manager = _Manager(probe)
    watchdog = WatchdogMonitor()
    watchdog._mgr = manager
    watchdog._restart_state["Fault Probe"] = watchdog_monitor._RestartState(id(probe))

    manager.enabled = False
    watchdog._sweep()

    assert probe.restart_calls == []
    assert "Fault Probe" not in watchdog._restart_state
    assert watchdog.health == 100


@pytest.mark.parametrize("health,state", [(20, "critical"), (50, "degraded"), (0, "failed")])
def test_watchdog_note_scopes_liveness_separately_from_detector_coverage(
    health: int, state: str,
) -> None:
    restart_calls = []
    probe = SimpleNamespace(
        health=health, health_state=state,
        operational_snapshot=lambda: {
            "status": "running", "health": health, "health_state": state,
            "thread_alive": True, "lifecycle_generation": 7,
            "first_cycle_complete": True, "watchdog_deadline_missed": False,
        },
        restart_if_generation=lambda generation: restart_calls.append(generation),
    )
    watchdog = WatchdogMonitor()
    watchdog._mgr = _Manager(probe)
    bus = EventBus()
    watchdog.bind(bus)

    watchdog._sweep()

    assert watchdog.health == 100
    assert watchdog.health_note == (
        "1 enabled sibling workers have no observed lifecycle/deadline faults; "
        "detector coverage is separate."
    )
    assert restart_calls == []
    assert (probe.health, probe.health_state) == (health, state)
    assert bus.recent(10) == []


def test_restart_exhaustion_is_bounded_and_terminal_alert_is_deduplicated(
    monkeypatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(watchdog_monitor.time, "monotonic", lambda: clock[0])
    probe = _FaultProbe()
    probe.remain_faulted = True
    watchdog = WatchdogMonitor()
    watchdog._mgr = _Manager(probe)
    bus = EventBus()
    watchdog.bind(bus)

    for instant in (0.0, 9.0, 40.0, 161.0, 240.0):
        clock[0] = instant
        watchdog._sweep()

    assert probe.restart_calls == [7, 7, 7]
    exhausted = [
        event for event in bus.recent(100)
        if event.details.get("finding_code") == "watchdog.restart.exhausted"
    ]
    assert len(exhausted) == 1
    assert watchdog.health == 20
    assert "exhausted restart recovery" in watchdog.health_note


def test_stable_worker_eventually_clears_restart_debt(monkeypatch) -> None:
    clock = [10.0]
    monkeypatch.setattr(watchdog_monitor.time, "monotonic", lambda: clock[0])
    probe = _FaultProbe()
    watchdog = WatchdogMonitor()
    watchdog._mgr = _Manager(probe)

    watchdog._sweep()
    clock[0] = 11.0
    watchdog._sweep()
    assert watchdog.health == 85

    clock[0] = 311.1
    watchdog._sweep()
    assert watchdog.health == 100
    assert watchdog._restart_state == {}
