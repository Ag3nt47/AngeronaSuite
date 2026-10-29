"""Priority scans use inert collectors and retain lifecycle/policy boundaries."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import os
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import background_pacing, module_base
from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule
from angerona.core.module_manager import ModuleManager
from angerona.modules import spyware_guard
from angerona.modules.spyware_guard import SpywareGuardModule
from angerona.telemetry.sensors import ConnectionSnapshot, ProcessSnapshot


OWNER = "a" * 32
OTHER = "b" * 32
NOW = 1800000000.0


class Clock:
    def __init__(self):
        self.value = time.monotonic()

    def __call__(self):
        return self.value


class Background(BaseModule):
    name = "Inert reviewed analysis"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 8.0


class BoundedBackground(BaseModule):
    name = "Inert bounded analysis"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 2.0


class Critical(BaseModule):
    name = "Inert critical intake"


def manager_with_modules(monkeypatch):
    controller = background_pacing.BackgroundPacingController()
    monkeypatch.setattr(background_pacing, "_CONTROLLER", controller)
    manager = ModuleManager(EventBus(), SimpleNamespace(ugcap_enabled=False))
    modules = [Background(), BoundedBackground(), Critical(), SpywareGuardModule()]
    external = Background()
    external.name = "Inert extension"
    modules.append(external)
    manager.modules = {row.name: row for row in modules}
    manager.module_trust = {row.name: {"origin": "builtin", "trust": "release"} for row in modules}
    manager.module_trust[external.name] = {"origin": "external", "trust": "reviewed"}
    return manager, controller, modules


def test_focus_preserves_declared_caps_critical_intake_and_new_operator_preferences(monkeypatch):
    manager, controller, (routine, bounded, critical, native, external) = manager_with_modules(monkeypatch)
    routine.set_throttle(2)
    with manager.priority_scan_focus(owner=OWNER, background_percent=10) as focus:
        assert routine._priority_throttle == 8
        assert bounded._priority_throttle == 2
        assert critical._priority_throttle == native._priority_throttle == external._priority_throttle == 1
        assert focus.snapshot()["affected_modules"] == 2
        assert controller.work_multiplier() == 10
        routine.set_throttle_floor(3)
        routine.set_throttle(4)
        controller.set_chill_active(True)
        controller.report_host(99)
    assert routine._priority_throttle == bounded._priority_throttle == 1
    assert routine._throttle_floor == 3 and routine._throttle == 4
    assert controller.chill_active() and controller.work_multiplier() == 8
    assert manager.priority_scan_focus_snapshot() == {"active": False}


def test_focus_finally_stop_and_stale_close_cannot_clear_successor(monkeypatch):
    manager, controller, modules = manager_with_modules(monkeypatch)
    with pytest.raises(RuntimeError, match="inert failure"):
        with manager.priority_scan_focus(owner=OWNER):
            raise RuntimeError("inert failure")
    assert all(row._priority_throttle == 1 for row in modules)
    first = manager.priority_scan_focus(owner=OWNER)
    first.__enter__()
    manager.cancel_priority_scan_focus()
    with manager.priority_scan_focus(owner=OWNER) as successor:
        first.close()
        assert successor.snapshot()["active"] is True
        manager.stop_all()
        assert manager.priority_scan_focus_snapshot() == {"active": False}
    assert controller.work_multiplier() == 1
    assert all(row._priority_throttle == 1 for row in modules)
    with pytest.raises(RuntimeError, match="shutdown"):
        with manager.priority_scan_focus(owner=OTHER):
            pytest.fail("Stopped manager admitted a focus lease")


def test_focus_holds_workspace_policy_and_late_module_floor_is_retired(monkeypatch):
    manager, _controller, modules = manager_with_modules(monkeypatch)
    manager._ugcap_paused = True
    with pytest.raises(RuntimeError, match="workspace"):
        with manager.priority_scan_focus(owner=OWNER):
            pytest.fail("Workspace hold was bypassed")
    manager._ugcap_paused = False
    with manager.priority_scan_focus(owner=OWNER):
        with pytest.raises(RuntimeError, match="already active"):
            with manager.priority_scan_focus(owner=OTHER):
                pytest.fail("A second focus was admitted")
        replacement = Background()
        manager.modules[replacement.name] = replacement
        with manager._module_control_lock:
            assert manager._sync_priority_scan_module(replacement.name, replacement)
        assert replacement._priority_throttle == 8
    assert modules[0]._priority_throttle == replacement._priority_throttle == 1


def test_focus_renewal_does_not_block_the_app_thread(monkeypatch):
    manager, controller, _modules = manager_with_modules(monkeypatch)
    acquired, release = threading.Event(), threading.Event()

    def hold(lock):
        with lock:
            acquired.set()
            assert release.wait(5)

    with manager.priority_scan_focus(owner=OWNER) as focus:
        for lock in (manager._module_control_lock, controller._lock):
            acquired.clear()
            release.clear()
            thread = threading.Thread(target=hold, args=(lock,))
            try:
                thread.start()
                assert acquired.wait(2)
                started = time.monotonic()
                assert focus.renew() is False
                assert time.monotonic() - started < 0.5
            finally:
                release.set()
                thread.join(3)
            assert not thread.is_alive()
        assert focus.renew() is True


def test_focus_expiry_and_routine_work_limits_preserve_other_policies():
    clock = Clock()
    controller = background_pacing.BackgroundPacingController(clock=clock)
    controller.begin_priority_focus(OWNER, 10, seconds=60)
    assert controller.interval(5) == 35  # keep the existing 30-second inventory-age guard
    assert controller.batch_delay() == 0.05
    pacer = background_pacing.RoutineWorkPacer(controller, clock=clock)
    assert pacer._work_budget == pytest.approx(0.05 / 9)
    clock.value += 0.01
    assert 0 < pacer.pause_seconds(1, batch_size=1000) <= 0.05
    controller.set_chill_active(True)
    clock.value += 61
    assert "priority_focus" not in controller.snapshot()
    assert controller.work_multiplier() == 8
    controller.set_chill_active(False)
    assert controller.work_multiplier() == 1
    controller.begin_priority_focus(OTHER, 1)
    assert controller.work_multiplier() == 32
    assert controller.end_priority_focus(OWNER) is False
    assert controller.end_priority_focus(OTHER) is True


def test_stale_focus_renewal_and_close_preserve_a_new_routine_pacer_owner(monkeypatch):
    manager, controller, _modules = manager_with_modules(monkeypatch)
    with manager.priority_scan_focus(owner=OWNER) as focus:
        assert controller.end_priority_focus(focus.pacer_owner)
        controller.begin_priority_focus(OTHER, 20)
        assert focus.renew() is False
    assert controller.snapshot()["priority_focus"]["owner"] == OTHER
    assert controller.work_multiplier() == 5
    assert controller.end_priority_focus(OTHER)


def test_expired_temporary_floor_does_not_persist_into_later_sleeps(monkeypatch):
    module = BaseModule()
    expiry = time.monotonic() + 100
    module.set_throttle(3)
    module.set_priority_throttle(8, expiry)
    waits = []
    module._stop = SimpleNamespace(wait=lambda timeout: waits.append(timeout), is_set=lambda: False)
    monkeypatch.setattr(module_base, "time", SimpleNamespace(monotonic=lambda: expiry + 1))
    module.sleep(2, _background_pacing=False)
    assert waits == [6]
    assert module._priority_throttle == 1


def inert_module(monkeypatch, scan):
    module = SpywareGuardModule(clock=lambda: NOW,
        persistence_collector=lambda **_kw: {"findings": [], "coverage": {}},
        process_observer=lambda: ProcessSnapshot((), NOW, True, 0, 0),
        connection_observer=lambda: ConnectionSnapshot((), NOW, True, 0, 0))
    module._definitions_initialized = True
    module._scan_requested = False
    module._last_scan = NOW
    module.bind(EventBus())
    monkeypatch.setattr(module, "_ensure_report_worker", lambda: None)
    monkeypatch.setattr(module, "_ensure_beacon", lambda: None)
    monkeypatch.setattr(module, "_consume_events", lambda: None)
    monkeypatch.setattr(module, "_collect_responses", lambda: None)
    monkeypatch.setattr(module, "_scan_once", scan)
    return module


def retire(module):
    module.stop()
    if module._thread is not None:
        module._thread.join(5)
        assert not module._thread.is_alive()


def terminal(module, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = module.priority_scan_snapshot()
        if status["state"] not in {"queued", "running", "idle"}:
            return status
        time.sleep(0.01)
    pytest.fail("Inert native priority scan did not reach a terminal state")


def test_priority_scan_wakes_existing_worker_ahead_of_a_full_normal_queue(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    observed = []

    def scan(*, cancelled):
        observed.append(threading.current_thread())
        entered.set()
        assert release.wait(5)
        return not cancelled()

    module = inert_module(monkeypatch, scan)
    module.start(initial_delay=30)  # an explicit request also wakes the startup stagger
    try:
        for _ in range(32):
            assert module._enqueue("inert")
        assert module.request_priority_scan(OWNER)
        assert entered.wait(2)
        assert observed == [module._thread]
        assert module._commands.qsize() == 32
        assert not module.request_priority_scan(OTHER)
        release.set()
        result = terminal(module)
        assert result["state"] == "completed" and not result["error"]
        assert result["worker_thread_id"] == module._thread.native_id
        assert result["native_priority"]["thread_id"] == module._thread.native_id
        if os.name == "nt":
            assert result["native_priority"]["restored"] is True
        result["coverage"]["injected"] = "no mutation authority"
        assert "injected" not in module.priority_scan_snapshot()["coverage"]
    finally:
        release.set()
        retire(module)


def test_priority_cancel_is_request_bound_and_does_not_stop_the_module(monkeypatch):
    entered = threading.Event()

    def scan(*, cancelled):
        entered.set()
        deadline = time.monotonic() + 5
        while not cancelled() and time.monotonic() < deadline:
            time.sleep(0.01)
        return not cancelled()

    module = inert_module(monkeypatch, scan)
    module.start(initial_delay=30)
    try:
        assert not module.request_priority_scan("bad")
        assert module.request_priority_scan(OWNER)
        assert entered.wait(2)
        module.cancel_priority_scan(OTHER)
        assert module.priority_scan_snapshot()["state"] == "running"
        module.cancel_priority_scan(OWNER)
        assert terminal(module)["state"] == "cancelled"
        assert not module.stopping and module._thread.is_alive()
    finally:
        retire(module)
    assert not module.request_priority_scan(OTHER)


def test_queued_priority_cancellation_performs_no_scan(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    calls = []
    module = inert_module(monkeypatch, lambda **_kw: calls.append("unexpected scan"))
    original = module._tick

    def held_tick():
        entered.set()
        assert release.wait(5)
        original()

    monkeypatch.setattr(module, "_tick", held_tick)
    module.start()
    try:
        assert entered.wait(2)
        assert module.request_priority_scan(OWNER)
        module.cancel_priority_scan(OWNER)
        release.set()
        assert terminal(module)["state"] == "cancelled"
        assert not calls and not module.stopping
    finally:
        release.set()
        retire(module)


def test_restarted_native_generation_cannot_be_cancelled_by_an_old_request(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    calls = []

    def scan(*, cancelled):
        calls.append(threading.current_thread())
        entered.set()
        deadline = time.monotonic() + 5
        while not cancelled() and not release.is_set() and time.monotonic() < deadline:
            time.sleep(0.01)
        return not cancelled()

    module = inert_module(monkeypatch, scan)
    module.start(initial_delay=30)
    try:
        assert module.request_priority_scan(OWNER) and entered.wait(2)
        old_thread, old_generation, old_stop = module._thread, module.lifecycle_generation, module._stop
        module.stop()
        module.start()
        deadline = time.monotonic() + 3
        while module.lifecycle_generation == old_generation and time.monotonic() < deadline:
            time.sleep(0.01)
        old_thread.join(2)
        assert not old_thread.is_alive() and old_stop.is_set()
        assert module.lifecycle_generation > old_generation and not module.stopping
        entered.clear()
        assert module.request_priority_scan(OTHER) and entered.wait(2)
        module.cancel_priority_scan(OWNER)
        assert module.priority_scan_snapshot()["state"] == "running" and not module.stopping
        release.set()
        assert terminal(module)["state"] == "completed"
        assert calls == [old_thread, module._thread]
    finally:
        release.set()
        retire(module)
        if module._restart_waiter is not None:
            module._restart_waiter.join(3)
            assert not module._restart_waiter.is_alive()


def test_priority_failure_restores_thread_and_reports_error_without_restarting(monkeypatch):
    def scan(*, cancelled):
        raise RuntimeError("inert failure; untrusted exception text is not copied")

    module = inert_module(monkeypatch, scan)
    module.start(initial_delay=30)
    try:
        assert module.request_priority_scan(OWNER)
        result = terminal(module)
        assert result["state"] == "failed" and result["error"] == "RuntimeError"
        assert module._thread.is_alive() and not module.stopping
        if os.name == "nt":
            assert result["native_priority"]["restored"] is True
    finally:
        retire(module)


@pytest.mark.parametrize("setting", [{"untrusted": "value"}, ["high"], None])
def test_priority_request_normalizes_invalid_settings_and_is_idempotent(monkeypatch, setting):
    calls = []
    module = inert_module(monkeypatch, lambda **_kw: calls.append("scan") or True)
    module._config = SimpleNamespace(spyware_scan_priority=setting)
    module.start(initial_delay=30)
    try:
        assert module.request_priority_scan(OWNER)
        result = terminal(module)
        assert result["native_priority"]["requested"] == "above-normal"
        assert not module.request_priority_scan(OWNER)
        assert calls == ["scan"]
    finally:
        retire(module)


def test_failed_native_priority_restore_retires_only_that_inert_worker(monkeypatch):
    @contextmanager
    def failed_restore(_level):
        info = {"active": "above-normal", "restored": None}
        try:
            yield info
        finally:
            info["restored"] = False

    monkeypatch.setattr(spyware_guard, "_priority_worker_thread", failed_restore)
    module = inert_module(monkeypatch, lambda **_kw: True)
    module.start(initial_delay=30)
    try:
        assert module.request_priority_scan(OWNER)
        result = terminal(module)
        assert result["state"] == "failed"
        assert result["error"] == "native-thread-priority-restore-failed"
        module._thread.join(3)
        assert not module._thread.is_alive() and module.status == "error"
    finally:
        retire(module)


def test_cancelled_native_scan_stops_before_following_source_and_does_not_claim_completion():
    cancelled = threading.Event()
    calls = []

    def persistence(**_kw):
        calls.append("persistence")
        cancelled.set()
        return {"findings": [], "coverage": {"registry": "inert"}}

    module = SpywareGuardModule(persistence_collector=persistence,
        process_observer=lambda: pytest.fail("Cancelled priority scan reached next source"))
    assert module._scan_once(cancelled=cancelled.is_set) is False
    assert calls == ["persistence"] and module._last_scan is None


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows current-thread scheduling")
def test_actual_inert_thread_priority_restores_after_exception():
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentThread.restype = wintypes.HANDLE
    kernel.GetThreadPriority.argtypes = (wintypes.HANDLE,)
    kernel.GetThreadPriority.restype = ctypes.c_int
    records = []

    def worker():
        held = kernel.GetCurrentThread()
        before = kernel.GetThreadPriority(held)
        try:
            with spyware_guard._priority_worker_thread("high") as info:
                assert kernel.GetThreadPriority(held) == 2
                raise RuntimeError("inert unwind")
        except RuntimeError:
            records.append((before, kernel.GetThreadPriority(held), dict(info)))

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(5)
    assert not thread.is_alive() and len(records) == 1
    before, after, info = records[0]
    assert before == after and info["restored"] is True and info["active"] == "highest"
