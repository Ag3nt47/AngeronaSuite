"""Low routine pace yields on actual work time, including slow hardware."""
import threading

import pytest

from angerona.core import background_pacing as pacing
from angerona.core.module_base import BaseModule


class Clock:
    value = 100.0

    def __call__(self):
        return self.value


def controller_at(multiplier, clock):
    controller = pacing.BackgroundPacingController(clock=clock)
    for index in range({1: 0, 2: 1, 4: 2, 8: 3}[multiplier]):
        if index:
            clock.value += 2
        controller.report_ui(8, worst_lag_ms=400)
    assert controller.multiplier() == multiplier
    return controller


@pytest.mark.parametrize("multiplier", [2, 4, 8])
def test_slow_item_yields_before_large_count_boundary(multiplier):
    clock = Clock()
    controller = controller_at(multiplier, clock)
    pacer = pacing.RoutineWorkPacer(controller, clock=clock)
    assert pacer.pause_seconds(0, batch_size=256) == 0
    clock.value += 0.06 / (multiplier - 1)
    assert pacer.pause_seconds(1, batch_size=256) == pytest.approx(0.05)
    pacer.resume()
    assert pacer.pause_seconds(2, batch_size=256) == 0


def test_nested_counter_resets_cannot_hide_elapsed_work():
    clock = Clock()
    controller = controller_at(8, clock)
    pacer = pacing.RoutineWorkPacer(controller, clock=clock)
    for _ in range(3):
        clock.value += 0.002
        assert pacer.pause_seconds(0, batch_size=256) == 0
    clock.value += 0.002
    assert pacer.pause_seconds(0, batch_size=256) == pytest.approx(0.05)


def test_normal_and_disabled_pacing_never_add_waits_and_pressure_is_rechecked():
    clock = Clock()
    controller = controller_at(1, clock)
    pacer = pacing.RoutineWorkPacer(controller, clock=clock)
    clock.value += 1
    assert pacer.pause_seconds(1, batch_size=256) == 0
    controller.report_ui(8, worst_lag_ms=400)
    clock.value += 0.06
    assert pacer.pause_seconds(2, batch_size=256) > 0
    controller.set_enabled(False)
    clock.value += 0.06
    assert pacer.pause_seconds(3, batch_size=256) == 0


def test_module_excludes_cadence_sleep_and_accounts_only_actual_wait(monkeypatch):
    clock = Clock()
    controller = controller_at(8, clock)
    pacer = pacing.RoutineWorkPacer(controller, clock=clock)
    module = BaseModule()
    module._thread = threading.current_thread()
    module._run_context.routine_pacer = pacer
    module._watchdog_deadline_at = 150
    monkeypatch.setattr("angerona.core.module_base.time.monotonic", clock)
    waits = []

    class Stop:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, timeout):
            waits.append(timeout)
            clock.value += timeout
            return self.stopped

    module._stop = Stop()
    module.sleep(10, cycle_complete=False)
    assert waits == [10]
    assert module.background_checkpoint(1, batch_size=256)
    assert waits == [10]  # the ordinary ten-second sleep is not scan work
    deadline = module._watchdog_deadline_at
    clock.value += 0.02
    assert module.background_checkpoint(2, batch_size=256)
    assert waits == [10, pytest.approx(0.05)]
    assert module._watchdog_deadline_at == pytest.approx(deadline + 0.05)
    assert module._cycle_count == 0 and not module.first_cycle_complete
    module._stop.stopped = True
    assert not module.background_checkpoint(3, batch_size=256)
    assert len(waits) == 2


def test_ordinary_self_test_does_not_create_a_worker_pacer():
    module = BaseModule()
    assert module.background_checkpoint(32)
    assert not hasattr(module._run_context, "routine_pacer")


def test_lower_pace_slows_same_work_and_breaks_slow_batches_into_shorter_bursts():
    def process(multiplier):
        clock = Clock()
        controller = controller_at(multiplier, clock)
        pacer = pacing.RoutineWorkPacer(controller, clock=clock)
        processed, pauses, bursts = [], [], []
        active_burst = 0.0
        for index in range(1, 33):
            processed.append(index)
            clock.value += 0.02  # one slow, indivisible 20-ms operation
            active_burst += 0.02
            delay = pacer.pause_seconds(index, batch_size=8)
            if delay:
                pauses.append(delay)
                bursts.append(active_burst)
                active_burst = 0.0
                clock.value += delay
                pacer.resume()
        return processed, sum(pauses), max(bursts, default=active_burst)

    normal, normal_rest, _ = process(1)
    paced, paced_rest, longest_burst = process(8)
    assert normal == paced == list(range(1, 33))
    assert normal_rest == 0
    assert paced_rest == pytest.approx(1.6)
    assert longest_burst == pytest.approx(0.02)  # count-only pacing waited 8*20=160ms
