"""Deterministic feedback, lifecycle and evidence checks without live sensors."""
from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from angerona.core import background_pacing as pacing
from angerona.core.eventbus import EventBus, Severity
from angerona.core.module_base import BaseModule


class Clock:
    value = 100.0

    def __call__(self):
        return self.value


def pressured_controller():
    clock = Clock()
    controller = pacing.BackgroundPacingController(clock=clock)
    for _ in range(3):
        controller.report_ui(8, worst_lag_ms=400)
        clock.value += 2
    assert controller.multiplier() == 8
    return controller, clock


def test_default_enabled_hysteresis_and_gradual_recovery():
    clock = Clock()
    controller = pacing.BackgroundPacingController(clock=clock)
    assert controller.snapshot()["enabled"] is True
    assert controller.multiplier() == 1
    observed = []
    for _ in range(3):
        controller.report_ui(8, worst_lag_ms=400)
        observed.append(controller.multiplier())
        for _ in range(50):  # more readers cannot accelerate the transition
            assert controller.multiplier() == observed[-1]
        clock.value += 2
    assert observed == [2, 4, 8]
    recovered = []
    for _ in range(25):
        controller.report_ui(30, worst_lag_ms=0)
        recovered.append(controller.multiplier())
        clock.value += 1
    assert recovered[0] == 8
    assert recovered[8] == 4
    assert recovered[16] == 2
    assert recovered[24] == 1


def test_missed_visible_heartbeat_paces_without_any_further_gui_callback():
    clock = Clock()
    controller = pacing.BackgroundPacingController(clock=clock)
    controller.report_ui(30)
    assert controller.multiplier() == 1
    clock.value += 3
    assert controller.multiplier() == 2
    clock.value += 2
    assert controller.multiplier() == 4
    clock.value += 2
    assert controller.multiplier() == 8
    clock.value += 30
    assert controller.multiplier() == 2  # prolonged unknown: bounded fallback
    assert controller.snapshot()["reason"] == "UI feedback unavailable"
    controller.report_ui(0, active=False)
    assert controller.multiplier() == 1


def test_warmup_lease_detects_freeze_before_first_measured_frame():
    clock = Clock()
    controller = pacing.BackgroundPacingController(clock=clock)
    controller.begin_ui_monitoring()
    assert controller.multiplier() == 1
    clock.value += 3
    controller.begin_ui_monitoring()  # repeated activation cannot mask a stall
    assert controller.multiplier() == 2
    controller.report_ui(0, active=False)
    clock.value += 10
    assert controller.multiplier() == 1
    controller.set_enabled(False)
    controller.begin_ui_monitoring()
    clock.value += 3
    assert controller.multiplier() == 1


def test_hidden_ui_host_pressure_expiry_and_disabled_reset():
    controller, clock = pressured_controller()
    controller.report_host(99)
    controller.report_ui(0, active=False)
    assert controller.multiplier() == 8
    clock.value += controller.SIGNAL_TTL + 1
    assert controller.multiplier() == 1
    controller.report_host(99)
    assert controller.multiplier() == 2
    controller.set_enabled(False)
    controller.report_ui(0, worst_lag_ms=1000)
    controller.report_host(100)
    assert controller.snapshot() == {
        "enabled": False, "multiplier": 1, "pace_percent": 100.0,
        "level": "normal", "reason": "Disabled",
    }
    controller.set_enabled(True)
    assert controller.multiplier() == 1


@pytest.mark.parametrize("value", [float("nan"), float("inf"), "invalid", None, -1])
def test_invalid_feedback_never_creates_pressure(value):
    controller = pacing.BackgroundPacingController(clock=Clock())
    controller.report_ui(value)
    controller.report_host(value)
    assert controller.multiplier() == 1


def test_interval_and_cooperative_delay_are_bounded():
    controller, _ = pressured_controller()
    assert controller.interval(3) == 24
    assert controller.interval(60) == 90
    assert controller.interval(0) == 0
    assert controller.interval(-1) == 0
    assert controller.batch_delay() == pytest.approx(0.05)


class InventoryModule(BaseModule):
    background_pacing_allowed = True


class CapturedStop:
    def __init__(self):
        self.waits = []
        self.stopped = False

    def is_set(self):
        return self.stopped

    def wait(self, timeout):
        self.waits.append(timeout)
        return self.stopped


def test_only_opted_in_worker_cadence_changes_and_governors_do_not_multiply(monkeypatch):
    controller, _ = pressured_controller()
    monkeypatch.setattr(pacing, "_CONTROLLER", controller)
    routine = InventoryModule()
    routine._stop = CapturedStop()
    routine._thread = threading.current_thread()
    routine.set_throttle(4)
    routine.sleep(3, cycle_complete=False)
    assert routine._stop.waits == [24]  # not 3 * 4 * 8
    assert routine._last_sleep_interval_seconds == 24
    assert not routine.first_cycle_complete

    critical = BaseModule()
    critical._thread = threading.current_thread()
    critical._stop = CapturedStop()
    critical.sleep(3)
    assert critical._stop.waits == [3]
    routine._thread = None  # direct self-test/action outside the worker
    routine.set_throttle(1)
    routine.sleep(3)
    assert routine._stop.waits[-1] == 3


def test_checkpoint_preserves_readiness_and_stop_and_skips_direct_selftests(monkeypatch):
    controller, _ = pressured_controller()
    monkeypatch.setattr(pacing, "_CONTROLLER", controller)
    module = InventoryModule()
    module._stop = CapturedStop()
    assert module.background_checkpoint(32)
    assert module._stop.waits == []
    module._thread = threading.current_thread()
    assert module.background_checkpoint(31)
    assert module.background_checkpoint(32)
    assert module._stop.waits == [pytest.approx(0.05)]
    assert module._cycle_count == 0
    assert not module.first_cycle_complete
    module._stop.stopped = True
    assert not module.background_checkpoint(33)
    assert len(module._stop.waits) == 1


def test_pressure_does_not_gate_critical_event_delivery(monkeypatch):
    controller, _ = pressured_controller()
    monkeypatch.setattr(pacing, "_CONTROLLER", controller)
    module = InventoryModule()
    module._thread = threading.current_thread()
    module._stop = CapturedStop()
    bus = EventBus()
    delivered = []
    bus.subscribe(delivered.append)
    module.bind(bus)
    module.emit("inert critical evidence", Severity.CRITICAL)
    assert delivered[-1].message == "inert critical evidence"
    assert module._stop.waits == []


def test_stop_interrupts_long_paced_wait_in_its_original_generation(monkeypatch):
    controller, _ = pressured_controller()
    monkeypatch.setattr(pacing, "_CONTROLLER", controller)
    entered = threading.Event()

    class ObservedStop(threading.Event):
        def wait(self, timeout=None):
            entered.set()
            return super().wait(timeout)

    module = InventoryModule()
    module._stop = ObservedStop()
    worker = threading.Thread(target=lambda: module.sleep(60, cycle_complete=False))
    module._thread = worker
    worker.start()
    try:
        assert entered.wait(2)
        assert module._last_sleep_interval_seconds == 90
        module._stop.set()
        worker.join(2)
        assert not worker.is_alive()
    finally:
        module._stop.set()
        worker.join(2)


def test_paced_inventory_still_admits_every_new_observation(monkeypatch):
    from angerona.modules import memory_timemachine as mtm

    controller, _ = pressured_controller()
    monkeypatch.setattr(pacing, "_CONTROLLER", controller)
    module = mtm.MemoryTimeMachineModule()
    module._thread = threading.current_thread()
    module._stop = CapturedStop()
    monkeypatch.setattr(mtm, "psutil", SimpleNamespace(
        net_connections=lambda **_: [],
        process_iter=lambda _attrs: iter(
            SimpleNamespace(info={"pid": pid}) for pid in range(1, 65)
        ),
    ))
    monkeypatch.setattr(module, "_process_strings", lambda *_: ["inert evidence"])
    monkeypatch.setattr(module, "set_health", lambda *_: None)
    module._sweep()
    assert module._forwarded == 64
    assert module.delta_queue.qsize() == 64
    assert len(module._stop.waits) == 7
    assert all(0 < wait <= 0.05 for wait in module._stop.waits)
    module._sweep()
    assert module._forwarded == 64


def test_concurrent_feedback_and_reads_keep_multiplier_in_bounded_steps():
    controller = pacing.BackgroundPacingController(clock=Clock())

    def exercise(index):
        controller.report_ui(10 if index % 2 else 30)
        controller.report_host(99 if index % 3 else 20)
        return controller.multiplier()

    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(exercise, range(400)))
    assert set(results) <= {1, 2, 4, 8}


@pytest.mark.parametrize("interrupt", [False, True])
def test_large_file_hash_yields_after_8_mib_without_partial_digest(tmp_path, monkeypatch, interrupt):
    from angerona.modules.file_integrity import FileIntegrityModule

    module = FileIntegrityModule()
    payload = b"inert-data" * (1024 * 1024)
    target = tmp_path / "large-inert.bin"
    target.write_bytes(payload)
    checkpoints = []

    def checkpoint(completed, *, batch_size):
        if completed and completed % batch_size == 0:
            checkpoints.append((completed, batch_size))
            if interrupt:
                module._stop.set()
                return False
        return True

    monkeypatch.setattr(module, "background_checkpoint", checkpoint)
    monkeypatch.setattr(module, "_handle_change_token", lambda _fd: 1)
    monkeypatch.setattr(module, "_handle_usn", lambda _fd: None)
    result = module._hash_once(str(target))
    assert checkpoints == [(128, 128)]
    assert result == ("" if interrupt else hashlib.sha256(payload).hexdigest())
