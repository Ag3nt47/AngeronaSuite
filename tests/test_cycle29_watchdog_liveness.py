from __future__ import annotations

from types import SimpleNamespace

from angerona.core import module_base
from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule
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
