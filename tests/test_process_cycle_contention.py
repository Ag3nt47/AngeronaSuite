"""Real owned threads and inert collectors; no host process enumeration."""
from __future__ import annotations

import threading
import time

import pytest

from angerona.core.eventbus import EventBus
from angerona.modules import process_monitor
from angerona.telemetry import sensors
from angerona.telemetry.process_snapshot_worker import unavailable


def _receipt():
    return sensors.ProcessSnapshot((), time.time(), True, 0, 0)


@pytest.fixture
def isolated_cache(monkeypatch):
    monkeypatch.setattr(sensors, "_proc_cache_lock", threading.Lock())
    monkeypatch.setattr(sensors, "_proc_cache", (0.0, None))
    monkeypatch.setattr(sensors, "_process_snapshot_provider", None)
    monkeypatch.setattr(sensors, "_process_snapshot_provider_generation", 0)
    monkeypatch.setattr(sensors, "_process_snapshot_on_gui_thread", lambda: False)


def _launch(target):
    errors = []

    def run():
        try:
            target()
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=run, name="owned-cycle-fixture")
    thread.start()
    return thread, errors


def _join(thread, errors):
    thread.join(timeout=5)
    assert not thread.is_alive(), "owned fixture thread did not retire"
    assert not errors


@pytest.mark.parametrize("remote", [False, True], ids=["local-collector", "owned-provider"])
def test_busy_collection_does_not_queue_a_second_collection(monkeypatch, isolated_cache, remote):
    entered, release, contender_done = threading.Event(), threading.Event(), threading.Event()
    calls, first, second = [], [], []

    def collect():
        calls.append(True)
        entered.set()
        assert release.wait(5)
        return _receipt()

    if remote:
        class Provider:
            snapshot = staticmethod(collect)
        sensors.configure_process_snapshot_provider(Provider())
        monkeypatch.setattr(sensors, "_collect_process_snapshot", lambda: pytest.fail("fallback collection"))
    else:
        monkeypatch.setattr(sensors, "_collect_process_snapshot", collect)
    owner, owner_errors = _launch(lambda: first.append(sensors.process_snapshot(max_age=0)))
    contender = None
    try:
        assert entered.wait(2)

        def contend():
            second.append(sensors.process_snapshot(max_age=0))
            contender_done.set()

        contender, contender_errors = _launch(contend)
        assert contender_done.wait(2), "contender inherited the blocked collector wait"
        assert not release.is_set() and owner.is_alive()
        assert calls == [True]
        assert type(second[0]) is sensors.ProcessSnapshot
        assert not second[0].complete and not second[0].enumeration_complete
        assert second[0].error.endswith("process cache admission deadline")
    finally:
        release.set()
        _join(owner, owner_errors)
        if contender is not None:
            _join(contender, contender_errors)
    assert first[0].complete and calls == [True]


def test_busy_fresh_request_cannot_reuse_a_snapshot_but_positive_age_can(monkeypatch, isolated_cache):
    entered, release = threading.Event(), threading.Event()
    cached = _receipt()
    calls = []

    class Provider:
        def snapshot(self):
            calls.append(True)
            entered.set()
            assert release.wait(5)
            return _receipt()

    sensors.configure_process_snapshot_provider(Provider())
    sensors._proc_cache = (time.monotonic(), cached)
    owner, errors = _launch(lambda: sensors.process_snapshot(max_age=0))
    try:
        assert entered.wait(2)
        assert sensors.process_snapshot(max_age=60) is cached
        refused = sensors.process_snapshot(max_age=0)
        assert refused is not cached and not refused.complete
        assert calls == [True]
    finally:
        release.set()
        _join(owner, errors)


def test_replacement_during_blocked_collection_never_reuses_or_caches_old_generation(monkeypatch, isolated_cache):
    entered, release = threading.Event(), threading.Event()
    old_results, new_calls = [], []

    class Old:
        def snapshot(self):
            entered.set()
            assert release.wait(5)
            return _receipt()

    class New:
        def snapshot(self):
            new_calls.append(True)
            return _receipt()

    sensors.configure_process_snapshot_provider(Old())
    sensors._proc_cache = (time.monotonic(), _receipt())
    owner, errors = _launch(lambda: old_results.append(sensors.process_snapshot(max_age=0)))
    try:
        assert entered.wait(2)
        sensors.configure_process_snapshot_provider(New())
        busy = sensors.process_snapshot(max_age=60)
        assert not busy.complete and not new_calls
        assert sensors._proc_cache == (0.0, None)
    finally:
        release.set()
        _join(owner, errors)
    assert old_results[0].error.endswith("provider lifecycle changed")
    assert sensors._proc_cache == (0.0, None)
    assert sensors.process_snapshot(max_age=0).complete
    assert new_calls == [True]


def test_normal_reuse_and_forced_fresh_keep_original_collection_count(isolated_cache):
    calls = []

    class Provider:
        def snapshot(self):
            calls.append(True)
            return _receipt()

    sensors.configure_process_snapshot_provider(Provider())
    first = sensors.process_snapshot(max_age=60)
    assert sensors.process_snapshot(max_age=60) is first
    assert sensors.process_snapshot(max_age=0) is not first
    assert calls == [True, True]


def test_busy_receipt_remains_unknown_in_the_actual_process_monitor_loop(monkeypatch):
    module = process_monitor.ProcessMonitorModule()
    module.bind(EventBus())
    polls = []
    monkeypatch.setattr("psutil.pids", lambda: [])

    def collect(**_kwargs):
        polls.append(True)
        return unavailable("process cache admission deadline")

    def sleep(*_args, **_kwargs):
        if polls:
            module.stop()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", sleep)
    thread, errors = _launch(module.run)
    _join(thread, errors)
    assert not module._last_coverage["complete"] and module.health < 90
    assert not module._last_coverage["enumeration_complete"]
    assert module.cycle_diagnostic_snapshot()["stage"] == "stopped"


def test_actual_worker_publication_stage_is_reviewable_until_callback_returns(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    module = process_monitor.ProcessMonitorModule()
    bus = EventBus()
    module.bind(bus)
    polls = []
    monkeypatch.setattr("psutil.pids", lambda: [])

    def collect(**_kwargs):
        polls.append(True)
        row = dict(pid=701, ppid=1, name="fixture.exe", exe="C:/Windows/fixture.exe",
                   create_time=123.0, cmdline=["fixture.exe"])
        return sensors.ProcessSnapshot((row,), time.time(), True, 1, 0)

    def sleep(*_args, **_kwargs):
        if polls:
            module.stop()

    def block_creation(event):
        if event.details.get("event_type") == "process_creation":
            entered.set()
            assert release.wait(5)

    bus.subscribe(block_creation)
    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", sleep)
    thread, errors = _launch(module.run)
    try:
        assert entered.wait(2)
        snapshot = module.cycle_diagnostic_snapshot()
        assert snapshot["stage"] == "publication" and snapshot["publication_active"]
        assert snapshot["rows_normalized"] == 1
        assert snapshot["creation_events_published"] == 0
        assert module.operational_snapshot()["cycle_count"] == 1  # startup only
        # Getters copy their cache and do not read clocks or re-enter callbacks.
        with monkeypatch.context() as patch:
            patch.setattr(process_monitor.time, "monotonic", lambda: pytest.fail("diagnostic clock read"))
            assert module.cycle_diagnostic_snapshot() == snapshot
        snapshot["stage_durations_ms"]["collection"] = -1
        assert module.cycle_diagnostic_snapshot()["stage_durations_ms"]["collection"] >= 0
    finally:
        release.set()
        _join(thread, errors)
    latest = module.cycle_diagnostic_snapshot()
    assert latest["stage"] == "stopped" and not latest["publication_active"]
    assert latest["creation_events_published"] == 0  # next cycle reset, then stop
    assert module.operational_snapshot()["cycle_count"] == 2


def test_cycle_diagnostic_lock_contention_is_explicit_and_never_changes_cycle_authority():
    module = process_monitor.ProcessMonitorModule()
    before = module.operational_snapshot()
    with module._cycle_diagnostic_lock:
        assert module.cycle_diagnostic_snapshot()["state"] == "unavailable"
        module._observe_cycle_stage("publication", module.lifecycle_generation)
    assert module.cycle_diagnostic_snapshot()["update_loss"] is True
    after = module.operational_snapshot()
    assert before["cycle_count"] == after["cycle_count"] == 0
    assert not after["first_cycle_complete"]
