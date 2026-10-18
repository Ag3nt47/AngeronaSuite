"""Bounded low-RAM scheduling and CPU-only worker regressions, using inert work."""
from __future__ import annotations

import math
import queue
import threading
from types import SimpleNamespace

import pytest

from angerona.core import background_pacing as pacing
from angerona.core import gpu_entropy, perf_governor
from angerona.core.eventbus import EventBus, Severity
from angerona.core.module_base import BaseModule
from angerona.modules import resource_governor as governor_module


@pytest.mark.parametrize("percent,available,expected", [
    (60, 2 * 1024 ** 3, 1),
    (60, 512 * 1024 ** 2, 4),
    (60, 256 * 1024 ** 2, 8),
    (85, None, 4),
    (92, None, 8),
    (100, 0, 8),
])
def test_memory_headroom_paces_routine_work_without_a_visible_gui(percent, available, expected):
    now = [100.0]
    controller = pacing.BackgroundPacingController(clock=lambda: now[0])
    for _ in range(3):
        controller.report_memory(percent, available)
        now[0] += 2
    assert controller.multiplier() == expected
    assert controller.interval(60) <= 90
    assert controller.batch_delay() <= 0.05
    if expected > 1:
        assert controller.snapshot()["reason"] == "Host memory pressure"
    now[0] += controller.SIGNAL_TTL + 1
    assert controller.multiplier() == 1


@pytest.mark.parametrize("percent,available", [
    (float("nan"), None), (float("inf"), 0), (-1, 0), (101, 0),
    (None, 0), (20, float("nan")), (20, -1), (20, "invalid"),
])
def test_invalid_memory_samples_never_erase_recent_pressure(percent, available):
    now = [100.0]
    controller = pacing.BackgroundPacingController(clock=lambda: now[0])
    controller.report_memory(95)
    assert controller.multiplier() == 2
    now[0] += 2
    controller.report_memory(percent, available)
    assert controller.multiplier() == 4
    assert controller.snapshot()["reason"] == "Host memory pressure"


def test_hidden_ui_does_not_cancel_memory_pressure_and_recovery_is_gradual():
    now = [100.0]
    controller = pacing.BackgroundPacingController(clock=lambda: now[0])
    for _ in range(3):
        controller.report_memory(95)
        now[0] += 2
    controller.report_ui(0, active=False)
    assert controller.multiplier() == 8
    for expected in (4, 2, 1):
        controller.report_memory(30, 2 * 1024 ** 3)
        now[0] += controller.RECOVERY_SECONDS
        controller.report_memory(30, 2 * 1024 ** 3)
        assert controller.multiplier() == expected
    controller.set_enabled(False)
    controller.report_memory(100, 0)
    assert controller.multiplier() == 1


def test_memory_pressure_never_delays_critical_event_delivery(monkeypatch):
    controller = pacing.BackgroundPacingController(clock=lambda: 100.0)
    controller.report_memory(100, 0)
    monkeypatch.setattr(pacing, "_CONTROLLER", controller)
    module = BaseModule()
    module._thread = threading.current_thread()
    bus = EventBus()
    events = []
    bus.subscribe(events.append)
    module.bind(bus)
    module.emit("inert critical fixture", Severity.CRITICAL)
    assert len(events) == 1
    assert events[0].severity == Severity.CRITICAL
    assert module._cycle_count == 0


def test_governor_reuses_samples_and_does_not_relax_on_missing_ram(monkeypatch):
    controller = pacing.BackgroundPacingController(clock=lambda: 100.0)
    monkeypatch.setattr(pacing, "_CONTROLLER", controller)
    samples = iter([
        SimpleNamespace(percent=95, available=128 * 1024 ** 2),
        SimpleNamespace(percent=float("nan"), available=0),
        SimpleNamespace(percent=30, available=2 * 1024 ** 3),
    ])
    process = SimpleNamespace(cpu_percent=lambda _interval: 0.0)
    monkeypatch.setattr(governor_module, "psutil", SimpleNamespace(
        Process=lambda: process, cpu_count=lambda: 2,
        virtual_memory=lambda: next(samples), cpu_percent=lambda **_: 20.0,
    ))
    governor = governor_module.ResourceGovernor()
    governor._level = 2
    levels = []
    real_apply = governor._apply

    def apply(level):
        levels.append(level)
        return real_apply(level)

    ticks = [0]

    def sleep(_seconds):
        ticks[0] += 1
        if ticks[0] == 4:
            governor.stop()

    monkeypatch.setattr(governor, "_apply", apply)
    monkeypatch.setattr(governor, "sleep", sleep)
    governor.run()
    assert levels == [4, 4, 3, 1]
    assert governor._level == 1
    assert controller.snapshot()["enabled"] is True


@pytest.mark.parametrize("raw", [float("nan"), float("inf"), -1, "invalid", None])
def test_governor_invalid_cpu_sample_stays_unavailable(raw):
    governor = governor_module.ResourceGovernor()
    governor._proc = SimpleNamespace(cpu_percent=lambda _interval: raw)
    assert governor._load_pct() is None


def test_governor_offline_selftest_proves_leases_without_host_changes(monkeypatch):
    monkeypatch.setattr(governor_module, "psutil", SimpleNamespace())
    governor = governor_module.ResourceGovernor()
    governor._level = 3
    assert governor.self_test()[0] is True
    assert governor._level == 3


def test_cosmetic_governor_retains_cpu_delta_baseline_and_recovers(monkeypatch):
    instances = []

    class Process:
        broken = False

        def __init__(self):
            self.samples = 0
            instances.append(self)

        def cpu_percent(self, interval=None):
            assert interval is None
            if self.broken:
                raise OSError("inert process collector failure")
            self.samples += 1
            return 0 if self.samples == 1 else 80

        def memory_info(self):
            return SimpleNamespace(rss=128 * 1024 ** 2)

    monkeypatch.setattr(perf_governor, "_HAVE_PSUTIL", True)
    monkeypatch.setattr(perf_governor, "psutil", SimpleNamespace(Process=Process))
    governor = perf_governor.PerfGovernor(enabled=True)
    assert governor._default_vitals().cpu_pct == 0
    assert governor._default_vitals().cpu_pct == 0.8
    assert len(instances) == 1
    instances[0].broken = True
    assert governor._default_vitals().raw is None
    assert governor._default_vitals().cpu_pct == 0
    assert len(instances) == 2


def test_entropy_worker_waits_for_first_item_instead_of_idle_polling(monkeypatch):
    monkeypatch.setattr(gpu_entropy, "_TORCH_OK", False)
    monkeypatch.setattr(gpu_entropy, "FLUSH_MS", 0)

    class ObservedQueue(queue.Queue):
        calls = []
        entered = threading.Event()

        def get(self, block=True, timeout=None):
            self.calls.append((block, timeout))
            self.entered.set()
            return super().get(block, timeout)

    worker = gpu_entropy.EntropyWorker()
    worker._queue = observed = ObservedQueue()
    batches = []
    collector = threading.Thread(target=lambda: batches.append(worker._collect_batch()))
    collector.start()
    try:
        assert observed.entered.wait(2)
        assert observed.calls == [(True, None)]
        worker.submit("inert arrival")
        collector.join(2)
        assert not collector.is_alive()
        assert batches == [["inert arrival"]]
        assert observed.calls == [(True, None)]
    finally:
        if collector.is_alive():
            worker.submit("cleanup")
            collector.join(2)


def test_entropy_batches_preserve_fifo_and_every_item_at_capacity(monkeypatch):
    monkeypatch.setattr(gpu_entropy, "_TORCH_OK", False)
    monkeypatch.setattr(gpu_entropy, "MAX_BATCH", 3)
    worker = gpu_entropy.EntropyWorker()
    assert worker.submit_batch(["one", "two", "three", "four", "five", "six"]) == 6
    assert worker._collect_batch() == ["one", "two", "three"]
    assert worker._collect_batch() == ["four", "five", "six"]
    assert worker._queue.empty()


def test_numpy_byte_histogram_matches_python_including_unicode_and_nuls():
    pytest.importorskip("numpy")
    strings = ["", "a", "abab", "\0x\0", "😀éλ", "\ud800", "abc123!" * 1000]
    numpy_values = gpu_entropy._entropy_numpy(strings)
    python_values = gpu_entropy._entropy_python(strings)
    assert numpy_values == pytest.approx(python_values, abs=1e-9)
    # The existing epsilon can produce a tiny negative result for constants.
    assert all(math.isfinite(value) and -1e-9 <= value <= 8 + 1e-9 for value in numpy_values)


def test_python_entropy_deduplicates_within_one_batch_and_keeps_every_output(monkeypatch):
    from collections import Counter
    import collections

    calls = []

    def counted(value):
        calls.append(value)
        return Counter(value)

    monkeypatch.setattr(collections, "Counter", counted)
    values = gpu_entropy._entropy_python(["ab", "ab", "aaaa", "aaaa", "", ""])
    assert values == [1, 1, 0, 0, 0, 0]
    assert calls == [b"ab", b"aaaa"]
    assert gpu_entropy._entropy_python(["ab"]) == [1]
    assert calls == [b"ab", b"aaaa", b"ab"]  # no retained evidence cache


def test_entropy_callbacks_can_register_without_deadlocking_worker(monkeypatch):
    monkeypatch.setattr(gpu_entropy, "_TORCH_OK", False)
    worker = gpu_entropy.EntropyWorker()
    worker._mode = "python"
    batches = iter([["one"], ["two"]])
    monkeypatch.setattr(worker, "_collect_batch", lambda: next(batches))
    events = []

    def late(result):
        events.append(("late", result.strings))

    def initial(result):
        events.append(("initial", result.strings))
        if result.strings == ["one"]:
            worker.on_result(late)

    worker.on_result(initial)
    failures = []

    def run_fixture():
        try:
            worker.run()
        except StopIteration:
            failures.append("fixture exhausted")

    runner = threading.Thread(target=run_fixture, daemon=True)
    runner.start()
    runner.join(2)
    assert not runner.is_alive(), "callback registration deadlocked entropy worker"
    assert failures == ["fixture exhausted"]
    assert events == [("initial", ["one"]), ("initial", ["two"]), ("late", ["two"])]
