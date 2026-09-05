"""Deadline regressions use inert fake modules and release every blocked call."""
from __future__ import annotations

import json
import threading
import time

import pytest

from angerona.core import selftest
from angerona.core.eventbus import EventBus


class _Module:
    supported_platforms = ("windows", "linux", "macos")
    selftest_auto_repair = True

    def __init__(self, name="Fake module", callback=None):
        self.name = name
        self.callback = callback
        self.calls = 0

    def self_test(self):
        self.calls += 1
        return self.callback() if self.callback else (True, "ready")


class _Manager:
    platform = "windows"

    def __init__(self, modules):
        self.modules = {module.name: module for module in modules}

    def is_enabled(self, _name):
        return True


@pytest.fixture
def runner_factory(monkeypatch, tmp_path):
    path = tmp_path / "selftest_failures.json"
    monkeypatch.setattr(selftest, "_failure_log_path", lambda: path)

    def create(modules=(), bus=None):
        runner = selftest.SelfTestRunner(_Manager(modules), bus or EventBus())
        runner._PIPELINE_TIMEOUT = 0.1
        runner._REPORT_TIMEOUT = 0.1
        return runner

    return create, path


def _wait_for_permits(permits, count):
    """Wait for fixtures to exit their actual worker finally blocks."""
    acquired = 0
    try:
        for _ in range(count):
            assert permits.acquire(timeout=3.0), "blocked test worker did not exit"
            acquired += 1
    finally:
        for _ in range(acquired):
            permits.release()


def test_blocked_pipeline_returns_diagnostics_and_does_not_spawn_on_rerun(
    runner_factory,
):
    create, path = runner_factory
    release = threading.Event()
    entered = threading.Event()

    class BlockingBus:
        calls = 0
        event = None

        def publish(self, event):
            self.calls += 1
            self.event = event
            entered.set()
            assert release.wait(5.0)

        def recent(self, _limit):
            return (self.event,)

    bus = BlockingBus()
    runners = [create(bus=bus) for _ in range(3)]
    try:
        started = time.monotonic()
        for runner in runners:
            report = runner.run(timeout=0.1)
            assert "[FAIL] Event pipeline" in report
            assert "[FAIL] Event reporting" in report
            assert all(not row["repairable"] for row in runner.last_failures)
        assert entered.is_set()
        assert bus.calls == 1
        assert time.monotonic() - started < 2.0
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["failed"] == 2
        assert payload["failures"] == runners[-1].last_failures
    finally:
        release.set()
        _wait_for_permits(selftest._EVENT_CALLS, 1)


def test_blocked_summary_cannot_prevent_failure_record(runner_factory):
    create, path = runner_factory
    release = threading.Event()
    entered = threading.Event()

    class SummaryBlockingBus(EventBus):
        def publish(self, event):
            if event.message.startswith("Drill complete:"):
                entered.set()
                assert release.wait(5.0)
            return super().publish(event)

    runner = create([_Module()], SummaryBlockingBus())
    try:
        report = runner.run(timeout=0.1)
        assert entered.is_set()
        assert "Result: 2 passed, 1 failed, 0 skipped." in report
        assert runner.last_failures[0]["module"] == "Event reporting"
        assert runner.last_failures[0]["repairable"] is False
        assert json.loads(path.read_text())["failed"] == 1
    finally:
        release.set()
        _wait_for_permits(selftest._EVENT_CALLS, 1)


def test_six_actual_module_checks_remain_capped_across_timeouts_and_reruns(
    runner_factory,
):
    create, _path = runner_factory
    release = threading.Event()
    counter_lock = threading.Lock()
    active = 0
    peak = 0

    def blocked():
        nonlocal active, peak
        with counter_lock:
            active += 1
            peak = max(active, peak)
        try:
            assert release.wait(5.0)
            return True, "released"
        finally:
            with counter_lock:
                active -= 1

    modules = [_Module(f"Module {index:02d}", blocked) for index in range(30)]
    try:
        runner = create(modules)
        started = time.monotonic()
        report = runner.run(timeout=0.1)
        assert "Result: 1 passed, 30 failed, 0 skipped." in report
        assert sum(module.calls for module in modules) == 6
        assert active == peak == 6
        assert all(not row["repairable"] for row in runner.last_failures)
        rerun = create(modules)
        rerun.run(timeout=0.1)
        assert sum(module.calls for module in modules) == 6
        assert all("test not started" in row["detail"] for row in rerun.last_failures)
        assert time.monotonic() - started < 3.0
    finally:
        release.set()
        _wait_for_permits(selftest._MODULE_CALLS, 6)
    assert active == 0
    # A timeout must not permanently consume slots once the original calls exit.
    assert "Result: 2 passed, 0 failed" in create([_Module()]).run(timeout=0.1)


def test_inspector_lock_prevents_duplicate_module_check(runner_factory):
    create, _path = runner_factory
    module = _Module()
    lock = selftest.module_selftest_lock(module)
    assert lock is selftest.module_selftest_lock(module)
    lock.acquire()
    try:
        runner = create([module])
        report = runner.run(timeout=0.1)
        assert "test already running for this capability" in report
        assert runner.last_failures[0]["repairable"] is False
        assert module.calls == 0
    finally:
        lock.release()


def test_public_inspector_helper_times_out_and_retains_single_flight_lock():
    release = threading.Event()
    entered = threading.Event()

    def blocked():
        entered.set()
        assert release.wait(5.0)
        return True, "released"

    module = _Module(callback=blocked)
    try:
        ok, detail = selftest.run_module_selftest(module, timeout=0.1)
        assert entered.is_set()
        assert not ok and detail.startswith("test timed out")
        assert selftest.module_selftest_lock(module).locked()
        ok, detail = selftest.run_module_selftest(module, timeout=0.1)
        assert not ok and detail == "test already running for this capability"
        assert module.calls == 1
    finally:
        release.set()
        _wait_for_permits(selftest._MODULE_CALLS, 6)
    assert not selftest.module_selftest_lock(module).locked()


def test_public_inspector_helper_preserves_raw_kernel_failure():
    module = _Module(callback=lambda: (False, "driver unavailable"))
    module.CODE = "KRNL"
    assert selftest.run_module_selftest(module, timeout=0.1) == (
        False, "driver unavailable",
    )
    # The existing all-module drill's optional-driver policy remains unchanged.
    assert selftest.SelfTestRunner._test_module(module, timeout=0.1) == (
        True, "Kernel Driver Not installed (driver unavailable)",
    )


def test_busy_kernel_check_cannot_be_masked_as_optional_driver_pass():
    module = _Module()
    module.CODE = "KRNL"
    lock = selftest.module_selftest_lock(module)
    lock.acquire()
    try:
        for check in (
            selftest.run_module_selftest, selftest.SelfTestRunner._test_module,
        ):
            ok, detail = check(module, timeout=0.1)
            assert not ok and detail == "test already running for this capability"
            assert not selftest.SelfTestRunner._is_repairable(module, detail)
        assert module.calls == 0
    finally:
        lock.release()


def test_blocked_progress_returns_results_and_rerun_has_no_second_dispatcher(
    runner_factory,
):
    create, path = runner_factory
    release = threading.Event()
    entered = threading.Event()
    calls = []

    def progress(done, total):
        calls.append((done, total))
        entered.set()
        assert release.wait(5.0)

    try:
        for _ in range(3):
            report = create([_Module()]).run(timeout=0.1, progress_cb=progress)
            assert "Result: 2 passed, 0 failed, 0 skipped." in report
            assert "Progress callback is still running" in report
        assert entered.is_set()
        assert len(calls) == 1
        assert json.loads(path.read_text())["passed"] == 2
    finally:
        release.set()
        _wait_for_permits(selftest._PROGRESS_CALLS, 1)


def test_healthy_delivery_keeps_critical_events_and_final_progress(runner_factory):
    create, _path = runner_factory
    bus = EventBus()
    runner = create([_Module(callback=lambda: (False, "failed readiness"))], bus)
    progress = []
    report = runner.run(
        timeout=0.1, progress_cb=lambda done, total: progress.append((done, total)),
    )
    assert "Result: 1 passed, 1 failed, 0 skipped." in report
    messages = [event.message for event in bus.recent(20)]
    assert any("CRITICAL FAILURE: Fake module" in message for message in messages)
    assert any("Drill complete: 1 passed, 1 failed" in message for message in messages)
    assert progress == sorted(progress)
    assert progress[-1] == (2, 2)


def test_bus_exceptions_are_reported_without_losing_module_failures(runner_factory):
    create, path = runner_factory

    class FailingBus:
        def publish(self, _event):
            raise RuntimeError("fake subscriber failed")

    runner = create([_Module(callback=lambda: (False, "worker unhealthy"))], FailingBus())
    report = runner.run(timeout=0.1)
    assert "Result: 0 passed, 3 failed, 0 skipped." in report
    assert {row["module"] for row in runner.last_failures} == {
        "Event pipeline", "Fake module", "Event reporting",
    }
    payload = json.loads(path.read_text())
    assert payload["failures"] == runner.last_failures
    assert "fake subscriber failed" in report


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_invalid_deadline_fails_before_dispatch(runner_factory, timeout):
    create, _path = runner_factory
    module = _Module()
    with pytest.raises(ValueError, match="positive and finite"):
        create([module]).run(timeout=timeout)
    assert module.calls == 0
