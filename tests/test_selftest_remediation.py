"""Exercise repair admission and verification through the real lifecycle."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.core import selftest
from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule
from angerona.core.module_manager import ModuleManager
from angerona.core.selftest_remediation import recover_module


class _Sensor(BaseModule):
    name = "Inert module recovery fixture"

    def __init__(self):
        super().__init__()
        self.attempts = 0
        self.fixture_ok = True

    def run(self):
        self.attempts += 1
        if self.attempts == 1:
            return
        self.set_health(100, "Fixture worker ready")
        while not self.stopping:
            self.sleep(0.01)

    def self_test(self):
        return self.fixture_ok, "isolated fixture check"


@pytest.fixture
def faulted(tmp_path, monkeypatch):
    monkeypatch.setattr(selftest, "_failure_log_path", lambda: tmp_path / "selftest.json")
    sensor = _Sensor()
    bus = EventBus()
    manager = ModuleManager(bus, SimpleNamespace(module_states={}, save=lambda: None), target_platform="windows")
    manager.modules[sensor.name] = sensor
    sensor.start()
    try:
        sensor._thread.join(3)
        assert sensor.status == "error"
        yield manager, sensor, selftest.SelfTestRunner(manager, bus)
    finally:
        manager.stop_all()
        if sensor._thread is not None:
            sensor._thread.join(3)
            assert not sensor._thread.is_alive()


def test_faulted_worker_can_be_recovered_and_retested(faulted):
    manager, sensor, runner = faulted
    runner.run(names=[sensor.name])
    result = next(row for row in runner.last_results if row["kind"] == "module")
    assert result["status"] == "FAIL"
    assert result["runtime"]["status"] == "error"
    assert result["repair"]["fault"] == "error"
    plan = runner.last_repairs[sensor.name]
    ok, detail = recover_module(manager, plan)
    assert ok, detail
    assert "passed its follow-up check" in detail
    assert sensor.attempts == 2
    assert sensor.operational_snapshot()["lifecycle_generation"] == plan.generation + 1
    assert not recover_module(manager, plan)[0]


@pytest.mark.parametrize("change", ["disabled", "chill", "replaced", "busy", "held"])
def test_recovery_holds_when_current_authority_or_generation_changes(faulted, change):
    manager, sensor, runner = faulted
    runner.run(names=[sensor.name])
    plan = runner.last_repairs[sensor.name]
    lock = selftest.module_selftest_lock(sensor)
    if change == "disabled":
        manager.config.module_states[sensor.name] = False
    elif change == "chill":
        sensor._chill_paused = True
    elif change == "replaced":
        manager.modules[sensor.name] = _Sensor()
    elif change == "held":
        manager._ugcap_paused = True
    else:
        assert lock.acquire(blocking=False)
    try:
        assert not recover_module(manager, plan)[0]
        assert sensor.attempts == 1
    finally:
        if change == "busy":
            lock.release()


def test_worker_restart_does_not_hide_failed_follow_up(faulted):
    manager, sensor, runner = faulted
    runner.run(names=[sensor.name])
    sensor.fixture_ok = False
    ok, detail = recover_module(manager, runner.last_repairs[sensor.name])
    assert not ok
    assert "follow-up check needs attention" in detail
    assert sensor.attempts == 2


def test_fixture_failure_with_working_worker_needs_module_guidance(faulted):
    manager, sensor, runner = faulted
    assert manager.restart_faulted_module_generation(sensor.name, sensor, 1)
    assert sensor.wait_for_first_cycle(3)
    sensor.fixture_ok = False
    runner.run(names=[sensor.name])
    assert not runner.last_repairs
    record = next(row for row in runner.last_results if row["kind"] == "module")
    assert record["status"] == "FAIL" and record["guidance"]
