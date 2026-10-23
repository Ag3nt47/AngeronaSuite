"""Supplied process receipts, real cadence, and exact owned-worker retirement."""
from __future__ import annotations

from contextlib import contextmanager
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import background_pacing as pacing
from angerona.core.module_base import BaseModule
from angerona.modules import process_monitor
from angerona.modules.process_monitor import ProcessMonitorModule
from angerona.telemetry.sensors import ProcessSnapshot


def _wait(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("owned fixture did not reach the expected causal boundary")


def _snapshot(**changes):
    fields = dict(
        processes=(), collected_at=time.time(), complete=True,
        enumerated=0, skipped=0, unreadable=0, identity_incomplete=0,
        error="", enumeration_complete=True,
    )
    fields.update(changes)
    return ProcessSnapshot(**fields)


@pytest.fixture(autouse=True)
def _inert_inventory(monkeypatch):
    import psutil

    monkeypatch.setattr(psutil, "pids", lambda: [])
    monkeypatch.setattr(process_monitor, "_combat_enabled", lambda: True)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("test attempted a native process inventory")

    monkeypatch.setattr(psutil, "process_iter", forbidden)
    monkeypatch.setattr(psutil, "Process", forbidden)
    monkeypatch.setattr(process_monitor, "process_snapshot", forbidden)


@pytest.fixture
def pressured_controller(monkeypatch):
    # Supply real controller samples rather than changing its factors or the
    # worker's clock. Only the controller's own input clock is deterministic.
    clock = [100.0]
    controller = pacing.BackgroundPacingController(clock=lambda: clock[0])
    for _ in range(3):
        controller.report_ui(8, worst_lag_ms=400)
        clock[0] += 2
    assert controller.multiplier() == 8 and controller.interval(1) == 8
    monkeypatch.setattr(pacing, "_CONTROLLER", controller)
    return controller


@contextmanager
def _run_owned(monkeypatch, module, work, *, release=()):
    entered = threading.Event()
    failures = []

    def guarded():
        entered.set()
        try:
            work()
        except BaseException as exc:
            failures.append(exc)
        finally:
            # Intentional test retirement must not become a crash/restart.
            module.generation_stop_event().set()

    monkeypatch.setattr(module, "run", guarded)
    owned = None
    try:
        module.start()
        owned = module._thread
        assert entered.wait(5.0)
        assert owned is not None and owned is module._thread
        yield module
    finally:
        module.stop()
        for event in release:
            event.set()
        if owned is not None and owned.ident is not None:
            owned.join(5.0)
            assert not owned.is_alive(), "exact owned process worker did not retire"
        assert module._thread is owned, "fixture unexpectedly replaced its worker"
        assert not failures, repr(failures)


@contextmanager
def _confined_lease_runtime(tmp_path, monkeypatch):
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.hardening import key_acl_required
    from angerona.core.module_contract import build_capability_contract
    from angerona.core.storage import FlightRecorder
    from angerona.modules import purple_guard

    assert not key_acl_required()
    assert purple_guard._runtime_targets_snapshot() == ()
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: tmp_path / "bus.key"))
    bus = EventBus(ring_size=128)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    guard = process = None
    try:
        bus.arm(recorder.authority)
        bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
        guard = purple_guard.PurpleGuard(tmp_path)
        guard.bind(bus)
        process = ProcessMonitorModule()
        process.bind(bus)
        process._angerona_contract = build_capability_contract(
            process, capability_id="angerona.builtin.process_monitor",
            origin="builtin", trust="release", publisher="Angerona",
        )
        manager = SimpleNamespace(modules={guard.name: guard, process.name: process}, bus=bus)
        yield purple_guard, manager, bus, recorder, guard, process
    finally:
        owned = tuple(getattr(module, "_thread", None) for module in (guard, process))
        for module in (guard, process):
            if module is not None:
                module.stop()
        for module, thread in zip((guard, process), owned):
            if thread is not None and thread.ident is not None:
                thread.join(5.0)
                assert not thread.is_alive(), "exact lease producer did not retire"
                assert module._thread is thread, "lease cleanup replaced its producer"
        recorder.close()


def test_real_eight_second_lease_admits_one_refused_receipt_under_eightfold_pacing(
    tmp_path, monkeypatch, pressured_controller,
):
    """Original source must fail the real admission deadline, not a new API call."""
    with _confined_lease_runtime(tmp_path, monkeypatch) as runtime:
        purple_guard, manager, bus, recorder, guard, module = runtime
        readiness_entered = threading.Event()
        rejected_seen = threading.Event()
        finished = threading.Event()
        calls, outcome = [], {}
        actual_snapshot = BaseModule.operational_snapshot

        def observe_snapshot(instance):
            snapshot = actual_snapshot(instance)
            if instance is module and threading.get_ident() == admission.ident:
                caller = sys._getframe(1)
                try:
                    # Observe the actual process-readiness loop after the real
                    # Purple cycle. Return its exact snapshot without edits.
                    if (
                        caller.f_code is purple_guard.acquire_redteam_validation_lease.__code__
                        and "process_deadline" in caller.f_locals
                    ):
                        readiness_entered.set()
                        if snapshot["health"] == 55 and snapshot["cycle_count"] >= 2:
                            rejected_seen.set()
                finally:
                    del caller
            return snapshot

        def collect(**kwargs):
            calls.append((kwargs, time.monotonic()))
            assert kwargs == {"max_age": 0.0}
            if len(calls) == 1:
                assert readiness_entered.wait(5.0)
                # Make the first real refusal causally later than loop entry.
                # An eight-second idle plus this positive work duration cannot
                # fit in the unchanged eight-second readiness allowance.
                assert not module.generation_stop_event().wait(0.25)
                return _snapshot(complete=False, enumeration_complete=False)
            assert len(calls) == 2, "unexpected extra process collection"
            return _snapshot()

        def acquire():
            try:
                # No timeout argument: exercise the existing real 8.0 default.
                outcome["lease"] = purple_guard.acquire_redteam_validation_lease(
                    manager, bus, recorder, tmp_path, tmp_path / "selected-target",
                )
            except BaseException as exc:
                outcome["error"] = exc
            finally:
                finished.set()

        admission = threading.Thread(target=acquire, name="inert-eight-second-lease-admission")
        monkeypatch.setattr(BaseModule, "operational_snapshot", observe_snapshot)
        monkeypatch.setattr(process_monitor, "process_snapshot", collect)
        assert module.run.__func__ is ProcessMonitorModule.run
        assert module.sleep.__func__ is BaseModule.sleep
        try:
            admission.start()
            assert finished.wait(12.0), "real eight-second lease did not finish"
            assert readiness_entered.is_set() and rejected_seen.is_set()
            assert "error" not in outcome, repr(outcome.get("error"))
            lease = outcome["lease"]
            assert len(calls) == 2
            assert lease.readiness["process_sensor"]["cycle_count"] >= 3
            assert lease.readiness["recorder"]["authenticated"] is True
            assert lease.readiness["recorder"]["persisted"] is True
            assert module.health == 100
            assert pressured_controller.multiplier() == 8
        finally:
            if not finished.is_set():
                module.stop()
                guard.stop()
            if admission.ident is not None:
                admission.join(5.0)
            assert not admission.is_alive(), "exact admission worker did not retire"
            lease = outcome.get("lease")
            if lease is not None:
                lease.release()


def test_new_request_wakes_an_already_entered_eightfold_idle(
    monkeypatch, pressured_controller,
):
    module = ProcessMonitorModule()
    actual_run, actual_sleep = module.run, module.sleep
    idle, collecting = threading.Event(), threading.Event()
    calls, sleeps = [], []

    def observe_sleep(seconds, **kwargs):
        sleeps.append(dict(kwargs))
        idle.set()
        actual_sleep(seconds, **kwargs)

    def collect(**kwargs):
        calls.append(kwargs)
        collecting.set()
        return _snapshot()

    monkeypatch.setattr(module, "sleep", observe_sleep)
    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, actual_run):
        assert idle.wait(5.0)
        _wait(lambda: module._last_sleep_interval_seconds == 8.0)
        assert not calls and not module._observation_request_event.is_set()
        token = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert token is not None
        # Real BaseModule.sleep checks the work hint at most every 0.25s;
        # allow scheduler headroom while proving it did not wait the 8s idle.
        assert collecting.wait(2.0)
        _wait(lambda: module.fresh_observation_complete(token))
        assert calls == [{"max_age": 0.0}]
        assert sleeps[0].get("_background_pacing", True) is True
        assert module._observation_retry_offered is None
        assert module._observation_retry_credit is None
        assert module.health == 100


@pytest.mark.parametrize("coalesce", [False, True])
def test_one_token_has_one_credit_even_with_persistent_refusal_or_coalescing(
    monkeypatch, pressured_controller, coalesce,
):
    module = ProcessMonitorModule()
    actual_run, actual_sleep = module.run, module.sleep
    start, retry_idle, retry_release, normal_idle = (threading.Event() for _ in range(4))
    calls, sleeps = [], []

    def collect(**kwargs):
        calls.append(kwargs)
        return []

    def observe_sleep(seconds, **kwargs):
        sleeps.append(dict(kwargs))
        if len(sleeps) == 2:
            retry_idle.set()
            assert retry_release.wait(5.0)
        elif len(sleeps) == 3:
            normal_idle.set()
        actual_sleep(seconds, **kwargs)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", observe_sleep)
    with _run_owned(monkeypatch, module, work, release=(start, retry_release)):
        token = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert token is not None
        start.set()
        assert retry_idle.wait(5.0)
        assert module._observation_retry_offered == token
        assert module._observation_retry_credit is None  # Consumed exactly once.
        assert not module._observation_request_event.is_set()
        if coalesce:
            for _ in range(20):
                assert module.request_fresh_observation(expected_generation=token[0]) == token
            # Existing caller-generated wakes remain supported. They do not
            # grant another pacing credit, nor does this patch bound them.
            assert module._observation_request_event.is_set()
            assert module._observation_retry_credit is None
        retry_release.set()
        assert normal_idle.wait(5.0)
        _wait(lambda: module._last_sleep_interval_seconds == 8.0)
        assert sleeps[0].get("_background_pacing", True) is True
        assert sleeps[1]["_background_pacing"] is False
        assert sleeps[2].get("_background_pacing", True) is True
        assert calls == [{"max_age": 0.0}, {"max_age": 0.0}]
        assert module._pending_observation_request == token
        assert module._observation_request_serial == token[1]
        assert module._observation_retry_offered == token
        assert module._observation_retry_credit is None
        assert not module._observation_request_event.is_set()
        assert not module.fresh_observation_complete(token) and module.health == 55
        assert not module.generation_stop_event().wait(0.3)
        assert len(calls) == 2, "persistent refusal created an immediate retry loop"


def test_superseding_token_revokes_old_credit_and_must_earn_its_own(
    monkeypatch, pressured_controller,
):
    module = ProcessMonitorModule()
    actual_run, actual_sleep = module.run, module.sleep
    start, collecting, release_first, second_retry, release_retry = (
        threading.Event() for _ in range(5)
    )
    calls, sleeps = [], []

    def collect(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            collecting.set()
            assert release_first.wait(5.0)
        return []

    def observe_sleep(seconds, **kwargs):
        sleeps.append(dict(kwargs))
        if len(sleeps) == 2:
            assert module._observation_retry_credit is None
            assert module._observation_retry_offered is None
        elif len(sleeps) == 3:
            second_retry.set()
            assert release_retry.wait(5.0)
        actual_sleep(seconds, **kwargs)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", observe_sleep)
    with _run_owned(monkeypatch, module, work, release=(start, release_first, release_retry)):
        first = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        start.set()
        assert collecting.wait(5.0)
        second = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert first is not None and second is not None and second[1] > first[1]
        release_first.set()
        assert second_retry.wait(5.0)
        assert sleeps[1].get("_background_pacing", True) is True
        assert sleeps[2]["_background_pacing"] is False
        assert module._observation_retry_offered == second
        assert module._observation_retry_credit is None
        assert module._pending_observation_request == second
        assert not module.fresh_observation_complete(first)
        assert not module.fresh_observation_complete(second)
        assert module.health == 55 and len(calls) == 2


def test_stop_revokes_unused_credit_and_restart_does_not_inherit_it(
    monkeypatch, pressured_controller,
):
    module = ProcessMonitorModule()
    actual_run = module.run
    actual_consume = module._consume_observation_retry_credit
    start, before_consume, release = (threading.Event() for _ in range(3))
    consumes, calls = [], []

    def collect(**kwargs):
        calls.append(kwargs)
        return [] if len(calls) == 1 else _snapshot()

    def observe_consume(generation):
        consumes.append(generation)
        if len(consumes) == 2:
            # This seam is outside the existing locks, immediately before the
            # first credit would be consumed. Stop can revoke it normally.
            before_consume.set()
            assert release.wait(5.0)
        return actual_consume(generation)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "_consume_observation_retry_credit", observe_consume)
    with _run_owned(monkeypatch, module, work, release=(start, release)):
        old = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert old is not None
        start.set()
        assert before_consume.wait(5.0)
        assert module._observation_retry_credit == old
        module.stop()
        assert module._observation_retry_credit is None
        assert module._observation_retry_offered is None
        assert module._pending_observation_request is None
        release.set()
    assert len(calls) == 1 and not module.fresh_observation_complete(old)
    with _run_owned(monkeypatch, module, actual_run):
        current = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert current is not None and current[0] > old[0]
        assert module._observation_retry_credit is None
        assert module._observation_retry_offered is None
        _wait(lambda: module.fresh_observation_complete(current))
        assert not module.fresh_observation_complete(old)
        assert module.health == 100 and len(calls) == 2


def test_foreign_or_stale_caller_preserves_valid_credit_and_owner_consumes_once(
    monkeypatch, pressured_controller,
):
    module = ProcessMonitorModule()
    actual_run = module.run
    actual_consume = module._consume_observation_retry_credit
    start, credited, foreign_checked, owner_checked = (threading.Event() for _ in range(4))
    calls, consumes = [], []

    def collect(**kwargs):
        calls.append(kwargs)
        return []

    def observe_consume(generation):
        consumes.append(generation)
        if len(consumes) != 2:
            return actual_consume(generation)
        token = module._observation_retry_credit
        assert token is not None
        credited.set()
        assert foreign_checked.wait(5.0)
        # The current real worker also cannot spend its credit using a stale
        # caller generation. The valid token must survive that refused call.
        assert actual_consume(generation - 1) is False
        assert module._observation_retry_credit == token
        assert actual_consume(generation) is True
        assert module._observation_retry_credit is None
        assert actual_consume(generation) is False
        # Fault injection: internally matching credit/pending/offered tokens
        # from another generation are stale independently of caller validity.
        stale = (generation + 1, token[1])
        with module._observation_request_lock:
            module._observation_retry_credit = stale
            module._pending_observation_request = stale
            module._observation_retry_offered = stale
        assert actual_consume(generation - 1) is False
        assert module._observation_retry_credit is None
        with module._observation_request_lock:
            module._pending_observation_request = token
            module._observation_retry_offered = token
        module.generation_stop_event().set()
        owner_checked.set()
        return False

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "_consume_observation_retry_credit", observe_consume)
    with _run_owned(monkeypatch, module, work, release=(start, foreign_checked)):
        token = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert token is not None
        start.set()
        assert credited.wait(5.0)
        assert module._observation_retry_credit == token
        assert actual_consume(token[0]) is False  # Foreign thread, valid generation.
        assert module._observation_retry_credit == token
        assert actual_consume(token[0] - 1) is False
        assert module._observation_retry_credit == token
        foreign_checked.set()
        assert owner_checked.wait(5.0)
        assert module._observation_retry_credit is None
        assert calls == [{"max_age": 0.0}]
        assert not module.fresh_observation_complete(token) and module.health == 55


def test_diagnostic_failure_does_not_prevent_or_replenish_retry_credit(
    monkeypatch, pressured_controller,
):
    module = ProcessMonitorModule()
    actual_run, actual_sleep = module.run, module.sleep
    start, normal_idle = threading.Event(), threading.Event()
    capture = module._capture_fresh_diagnostic
    calls, sleeps = [], []

    def faulted_capture(boundary, request, generation, interval):
        if boundary == "retry":
            raise RuntimeError("inert diagnostic capture failure")
        return capture(boundary, request, generation, interval)

    def collect(**kwargs):
        calls.append(kwargs)
        return []

    def observe_sleep(seconds, **kwargs):
        sleeps.append(dict(kwargs))
        if len(sleeps) == 3:
            normal_idle.set()
        actual_sleep(seconds, **kwargs)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(module, "_capture_fresh_diagnostic", faulted_capture)
    monkeypatch.setattr(module, "sleep", observe_sleep)
    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, work, release=(start,)):
        token = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        start.set()
        assert normal_idle.wait(5.0)
        _wait(lambda: module._last_sleep_interval_seconds == 8.0)
        assert sleeps[1]["_background_pacing"] is False
        assert sleeps[2].get("_background_pacing", True) is True
        assert module._observation_retry_offered == token
        assert module._observation_retry_credit is None
        assert module.fresh_observation_diagnostic(token)["available"] is False
        assert not module.fresh_observation_complete(token) and module.health == 55


@pytest.mark.parametrize("omit_pacing, expected", [(False, 8.0), (True, 4.0)])
def test_sleep_retry_option_preserves_chill_floor_watchdog_cycle_and_pacer(
    pressured_controller, omit_pacing, expected,
):
    class Inventory(BaseModule):
        background_pacing_allowed = True

    module = Inventory()
    waits, resumes = [], []
    module._thread = threading.current_thread()
    module._stop = SimpleNamespace(wait=lambda *, timeout: waits.append(timeout))
    module._run_context.routine_pacer = SimpleNamespace(resume=lambda: resumes.append(True))
    module.set_throttle_floor(4)
    module.set_throttle(1)
    module.mark_cycle_complete(interval_seconds=0)
    before_cycle = module._cycle_count
    before = time.monotonic()
    kwargs = {"_background_pacing": False} if omit_pacing else {}
    module.sleep(1, cycle_complete=False, **kwargs)
    assert waits == [expected] and resumes == [True]
    assert module._throttle == module._throttle_floor == 4.0
    assert module._last_sleep_interval_seconds == expected
    assert module._watchdog_deadline_at >= before + expected + module._watchdog_work_budget_seconds()
    assert module._cycle_count == before_cycle == 1
    assert module.first_cycle_complete


@pytest.mark.parametrize("signal", ["wake", "owned-stop"])
def test_retry_sleep_preserves_generation_owned_stop_and_existing_wake(signal):
    module = BaseModule()
    owned_stop, replacement_stop, wake = (threading.Event() for _ in range(3))
    entered, finished = threading.Event(), threading.Event()
    failures, resumes = [], []
    module._stop = replacement_stop

    def work():
        module._run_context.stop_event = owned_stop
        module._run_context.routine_pacer = SimpleNamespace(resume=lambda: resumes.append(True))
        entered.set()
        try:
            module.sleep(60, cycle_complete=False, _wake_event=wake, _background_pacing=False)
        except BaseException as exc:
            failures.append(exc)
        finally:
            finished.set()

    owned = threading.Thread(target=work, name="inert-retry-owned-wait")
    try:
        owned.start()
        assert entered.wait(5.0)
        replacement_stop.set()
        assert not finished.wait(0.1), "retry wait consulted a replacement generation"
        (wake if signal == "wake" else owned_stop).set()
        assert finished.wait(5.0)
        assert resumes == [True] and module._cycle_count == 0
    finally:
        owned_stop.set()
        wake.set()
        if owned.ident is not None:
            owned.join(5.0)
        assert not owned.is_alive() and not failures
