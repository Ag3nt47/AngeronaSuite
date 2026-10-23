"""Inert scheduling tests: supplied inventory only, with every owned thread retired."""
from contextlib import contextmanager
import threading
import time
from types import SimpleNamespace

import pytest

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
    raise AssertionError("owned inert worker did not reach the expected causal boundary")


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
            # A test-owned function returning is an intentional retirement,
            # never an unexpected-exit/crash diagnostic or a live watcher.
            module.generation_stop_event().set()

    monkeypatch.setattr(module, "run", guarded)
    try:
        module.start()
        assert entered.wait(5.0)
        yield module
    finally:
        module.stop()
        for event in release:
            event.set()
        thread = module._thread
        if thread is not None and thread.ident is not None:
            thread.join(5.0)
            assert not thread.is_alive(), "owned test worker did not retire"
        assert not failures, repr(failures)


@pytest.fixture(autouse=True)
def _inert_inventory(monkeypatch):
    import psutil

    monkeypatch.setattr(psutil, "pids", lambda: [])
    monkeypatch.setattr(process_monitor, "_combat_enabled", lambda: False)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("test attempted a native process inventory")

    monkeypatch.setattr(psutil, "process_iter", forbidden)
    monkeypatch.setattr(psutil, "Process", forbidden)
    monkeypatch.setattr(process_monitor, "process_snapshot", forbidden)


def _snapshot(**changes):
    fields = dict(processes=(), collected_at=time.time(), complete=True,
                  enumerated=0, skipped=0, unreadable=0, identity_incomplete=0,
                  error="", enumeration_complete=True)
    fields.update(changes)
    return ProcessSnapshot(**fields)


def _pause(module):
    module.generation_stop_event().wait(10.0)


def test_request_before_run_entry_survives_and_requires_real_completion(monkeypatch):
    module = ProcessMonitorModule()
    actual_run = module.run
    enter_run = threading.Event()
    collecting = threading.Event()
    finish_scan = threading.Event()
    calls = []

    def collect(**kwargs):
        calls.append(kwargs)
        collecting.set()
        assert finish_scan.wait(5.0)
        return _snapshot()

    def work():
        assert enter_run.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, work, release=(enter_run, finish_scan)):
        generation = module.lifecycle_generation
        before = module.operational_snapshot()
        request = module.request_fresh_observation(expected_generation=generation)
        assert request is not None
        after = module.operational_snapshot()
        assert after["cycle_count"] == before["cycle_count"] == 0
        assert after["health"] == before["health"]
        assert module._redteam_receipt_capability is None and module._bus is None
        assert not module.fresh_observation_complete(request)
        enter_run.set()
        assert collecting.wait(5.0)
        assert calls == [{"max_age": 0.0}]
        assert module.operational_snapshot()["cycle_count"] == 1
        assert not module.fresh_observation_complete(request)
        finish_scan.set()
        _wait(lambda: module.fresh_observation_complete(request))
        assert module.operational_snapshot()["cycle_count"] >= 2


def test_pending_requests_coalesce_without_publishing_health_or_cycle(monkeypatch):
    module = ProcessMonitorModule()
    with _run_owned(monkeypatch, module, lambda: _pause(module)):
        before = module.operational_snapshot()
        first = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert first is not None
        for _ in range(20):
            assert module.request_fresh_observation(expected_generation=module.lifecycle_generation) == first
        assert module._pending_observation_request == first
        assert module._observation_request_serial == first[1]
        assert module._observation_request_event.is_set()
        after = module.operational_snapshot()
        assert (after["cycle_count"], after["health"]) == (before["cycle_count"], before["health"])
        assert not module.fresh_observation_complete(first)


@pytest.mark.parametrize("bad", [True, False, 0, -1, "1", 1.0, None])
def test_invalid_generation_cannot_queue_observation(monkeypatch, bad):
    module = ProcessMonitorModule()
    with _run_owned(monkeypatch, module, lambda: _pause(module)):
        assert module.request_fresh_observation(expected_generation=bad) is None
        assert module._pending_observation_request is None
        assert not module._observation_request_event.is_set()


def test_stopped_and_stale_generation_requests_are_rejected(monkeypatch):
    module = ProcessMonitorModule()
    assert module.request_fresh_observation(expected_generation=1) is None
    with _run_owned(monkeypatch, module, lambda: _pause(module)):
        generation = module.lifecycle_generation
        assert module.request_fresh_observation(expected_generation=generation + 1) is None
        old_request = module.request_fresh_observation(expected_generation=generation)
        assert old_request is not None
    assert module.request_fresh_observation(expected_generation=generation) is None
    assert not module.fresh_observation_complete(old_request)
    with _run_owned(monkeypatch, module, lambda: _pause(module)):
        assert module.lifecycle_generation > generation
        assert module.request_fresh_observation(expected_generation=generation) is None
        assert not module.fresh_observation_complete(old_request)
        current = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert current is not None and current[0] != old_request[0]


@pytest.mark.parametrize("bad", [None, "1", [], (1,), (1, 1, 1), (True, 1), (1, True), (1, 0)])
def test_invalid_completion_token_is_never_proof(bad):
    module = ProcessMonitorModule()
    assert module.fresh_observation_complete(bad) is False


def test_unrelated_inflight_scan_cannot_acknowledge_new_request(monkeypatch):
    module = ProcessMonitorModule()
    actual_run = module.run
    first_entered = threading.Event()
    first_release = threading.Event()
    second_entered = threading.Event()
    second_release = threading.Event()
    calls = []

    # Eliminate the ordinary idle interval only in this inert race fixture.
    # Separate tests below exercise real BaseModule.sleep wake/stop semantics.
    monkeypatch.setattr(module, "sleep", lambda *_args, **_kwargs: None)

    def collect(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            first_entered.set()
            assert first_release.wait(5.0)
        elif len(calls) == 2:
            second_entered.set()
            assert second_release.wait(5.0)
        else:
            module.generation_stop_event().wait(5.0)
        return _snapshot()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, actual_run, release=(first_release, second_release)):
        assert first_entered.wait(5.0)
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        first_release.set()
        assert second_entered.wait(5.0)
        assert calls[:2] == [{}, {"max_age": 0.0}]
        assert module.operational_snapshot()["cycle_count"] == 2
        assert not module.fresh_observation_complete(request)
        second_release.set()
        _wait(lambda: module.fresh_observation_complete(request))


def test_new_request_during_requested_scan_stays_pending_for_next_scan(monkeypatch):
    module = ProcessMonitorModule()
    actual_run = module.run
    start = threading.Event()
    first_entered = threading.Event()
    first_release = threading.Event()
    second_entered = threading.Event()
    second_release = threading.Event()
    calls = []
    monkeypatch.setattr(module, "sleep", lambda *_args, **_kwargs: None)

    def collect(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            first_entered.set()
            assert first_release.wait(5.0)
        elif len(calls) == 2:
            second_entered.set()
            assert second_release.wait(5.0)
        else:
            module.generation_stop_event().wait(5.0)
        return _snapshot()

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, work, release=(start, first_release, second_release)):
        first = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        start.set()
        assert first_entered.wait(5.0)
        second = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert first is not None and second is not None and second[1] > first[1]
        first_release.set()
        assert second_entered.wait(5.0)
        assert module.fresh_observation_complete(first)
        assert not module.fresh_observation_complete(second)
        assert calls[:2] == [{"max_age": 0.0}, {"max_age": 0.0}]
        second_release.set()
        _wait(lambda: module.fresh_observation_complete(second))


@pytest.mark.parametrize("kind", [
    "invalid-type", "invalid-counts", "stale", "future", "error", "enumeration-incomplete",
])
def test_failed_collection_does_not_acknowledge_request(monkeypatch, kind):
    module = ProcessMonitorModule()
    actual_run = module.run
    start = threading.Event()

    def collect(**kwargs):
        assert kwargs == {"max_age": 0.0}
        if kind == "invalid-type":
            return []
        if kind == "invalid-counts":
            return _snapshot(enumerated=True)
        if kind == "stale":
            return _snapshot(collected_at=time.time() - 60)
        if kind == "future":
            return _snapshot(collected_at=time.time() + 60)
        if kind == "error":
            return _snapshot(complete=False, error="inert supplied collection failure")
        return _snapshot(complete=False, enumeration_complete=False)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, work, release=(start,)):
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        start.set()
        _wait(lambda: module.operational_snapshot()["cycle_count"] >= 2)
        assert not module.fresh_observation_complete(request)
        assert module.operational_snapshot()["health"] < 90


def test_fresh_partial_identity_can_complete_without_becoming_healthy(monkeypatch):
    module = ProcessMonitorModule()
    actual_run = module.run
    start = threading.Event()

    def collect(**kwargs):
        assert kwargs == {"max_age": 0.0}
        return _snapshot(
            processes=({"pid": 71, "name": "inert.exe", "exe": "C:/inert.exe",
                        "ppid": 0, "cmdline": (), "create_time": None},),
            complete=False, enumerated=1, identity_incomplete=1,
        )

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, work, release=(start,)):
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        start.set()
        _wait(lambda: module.fresh_observation_complete(request))
        assert module.operational_snapshot()["health"] == 70
        assert module._last_coverage["complete"] is False
        assert module._redteam_receipt_capability is None and module._bus is None


def test_default_sleep_retains_single_wait_and_one_pacer_resume():
    module = BaseModule()
    waits = []
    resumes = []
    module._stop = SimpleNamespace(wait=lambda *, timeout: waits.append(timeout))
    module._throttle = 2.0
    module._run_context.routine_pacer = SimpleNamespace(resume=lambda: resumes.append(True))
    module.sleep(0.75, cycle_complete=False)
    assert waits == [1.5] and resumes == [True]
    assert module._cycle_count == 0 and not module._first_cycle_complete.is_set()
    module.sleep(0.25)
    assert waits == [1.5, 0.5] and resumes == [True, True]
    assert module._cycle_count == 1 and module._first_cycle_complete.is_set()


def test_wake_only_shortens_idle_and_does_not_publish_cycle():
    module = BaseModule()
    wake = threading.Event()
    wake.set()
    resumes = []
    module._run_context.routine_pacer = SimpleNamespace(resume=lambda: resumes.append(True))
    module.sleep(60, cycle_complete=False, _wake_event=wake)
    assert module._cycle_count == 0 and not module._first_cycle_complete.is_set()
    assert resumes == [True]


@pytest.mark.parametrize("signal", ["wake", "owned-stop"])
def test_optional_wait_retains_thread_local_stop_ownership_and_retires(signal):
    module = BaseModule()
    owned_stop = threading.Event()
    other_generation_stop = threading.Event()
    wake = threading.Event()
    entered = threading.Event()
    finished = threading.Event()
    resumes = []
    failures = []
    module._stop = other_generation_stop

    def worker():
        module._run_context.stop_event = owned_stop
        module._run_context.routine_pacer = SimpleNamespace(resume=lambda: resumes.append(True))
        entered.set()
        try:
            module.sleep(60, cycle_complete=False, _wake_event=wake)
        except BaseException as exc:
            failures.append(exc)
        finally:
            finished.set()

    thread = threading.Thread(target=worker, name="inert-process-observation-wait")
    try:
        thread.start()
        assert entered.wait(5.0)
        other_generation_stop.set()
        assert not finished.wait(0.1), "wait consulted the mutable replacement stop token"
        (wake if signal == "wake" else owned_stop).set()
        assert finished.wait(5.0)
        assert resumes == [True] and module._cycle_count == 0
    finally:
        owned_stop.set()
        wake.set()
        if thread.ident is not None:
            thread.join(5.0)
        assert not thread.is_alive() and not failures


@contextmanager
def _confined_lease_runtime(tmp_path, monkeypatch):
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.hardening import key_acl_required
    from angerona.core.module_contract import build_capability_contract
    from angerona.core.storage import FlightRecorder
    from angerona.modules import purple_guard

    # This ordinary-source fixture may create only its own user-level test key.
    # Refuse a deployment requiring privileged key ACL provisioning instead of
    # invoking any host ACL tool or altering a trust/deployment requirement.
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
        for module in (guard, process):
            if module is not None:
                module.stop()
        for module in (guard, process):
            thread = getattr(module, "_thread", None)
            if thread is not None and thread.ident is not None:
                thread.join(5.0)
                assert not thread.is_alive(), "confined lease worker did not retire"
        recorder.close()


def test_real_lease_rebases_stopped_producer_old_cycle_count(tmp_path, monkeypatch):
    with _confined_lease_runtime(tmp_path, monkeypatch) as runtime:
        purple_guard, manager, bus, recorder, _guard, module = runtime
        actual_run, actual_sleep = module.run, module.sleep
        stop_prefill = threading.Event()
        prefill_blocked = threading.Event()
        phase = ["prefill"]
        counts = {"prefill": 0, "lease": 0}
        lease_calls = []

        def collect(**kwargs):
            current = phase[0]
            counts[current] += 1
            if current == "prefill" and counts[current] >= 11:
                # Ten rich cycles have completed; hold the next collection so
                # the parent can retire this exact generation causally.
                prefill_blocked.set()
                assert stop_prefill.wait(5.0)
            if current == "lease":
                lease_calls.append(kwargs)
            return _snapshot()

        monkeypatch.setattr(process_monitor, "process_snapshot", collect)
        monkeypatch.setattr(module, "sleep", lambda *_args, **_kwargs: None)
        with _run_owned(monkeypatch, module, actual_run, release=(stop_prefill,)):
            assert prefill_blocked.wait(5.0)
            assert module.operational_snapshot()["cycle_count"] >= 11
            old_generation = module.lifecycle_generation
        old_cycle = module.operational_snapshot()["cycle_count"]
        assert old_cycle >= 11
        # Restore real worker/cadence APIs for the actual gate restart.
        monkeypatch.setattr(module, "run", actual_run)
        monkeypatch.setattr(module, "sleep", actual_sleep)
        phase[0] = "lease"
        lease = None
        try:
            lease = purple_guard.acquire_redteam_validation_lease(
                manager, bus, recorder, tmp_path, tmp_path / "selected-target", timeout=3.0,
            )
            readiness = lease.readiness["process_sensor"]
            assert readiness["generation"] > old_generation
            assert 2 <= readiness["cycle_count"] < old_cycle
            assert lease_calls and lease_calls[0] == {"max_age": 0.0}
            assert lease.readiness["recorder"]["authenticated"] is True
            assert lease.readiness["recorder"]["persisted"] is True
        finally:
            if lease is not None:
                lease.release()


def test_real_lease_cannot_admit_startup_pid_boundary_before_rich_scan(tmp_path, monkeypatch):
    with _confined_lease_runtime(tmp_path, monkeypatch) as runtime:
        purple_guard, manager, bus, recorder, guard, module = runtime
        collecting = threading.Event()
        release_scan = threading.Event()
        finished = threading.Event()
        outcome = {}

        def collect(**kwargs):
            assert kwargs == {"max_age": 0.0}
            collecting.set()
            assert release_scan.wait(5.0)
            return _snapshot()

        def acquire():
            try:
                outcome["lease"] = purple_guard.acquire_redteam_validation_lease(
                    manager, bus, recorder, tmp_path, tmp_path / "selected-target", timeout=3.0,
                )
            except BaseException as exc:
                outcome["error"] = exc
            finally:
                finished.set()

        monkeypatch.setattr(process_monitor, "process_snapshot", collect)
        thread = threading.Thread(target=acquire, name="inert-confined-lease-admission")
        try:
            thread.start()
            assert collecting.wait(5.0)
            snapshot = module.operational_snapshot()
            assert snapshot["cycle_count"] == 1 and snapshot["health"] == 70
            assert not finished.wait(0.1), "startup-only boundary was admitted as rich observation"
            release_scan.set()
            assert finished.wait(8.0)
            assert "error" not in outcome, repr(outcome.get("error"))
            assert outcome["lease"].readiness["process_sensor"]["cycle_count"] >= 2
        finally:
            release_scan.set()
            # On assertion failure, stop only these exact fixture modules.
            # This prevents a still-pending gate from gaining admission later.
            if not finished.is_set():
                module.stop()
                guard.stop()
            if thread.ident is not None:
                thread.join(12.0)
            assert not thread.is_alive(), "owned admission thread did not retire"
            if "lease" in outcome:
                outcome["lease"].release()


def _retry_failure(kind):
    if kind == "invalid-type":
        return []
    if kind == "invalid-counts":
        return _snapshot(enumerated=True)
    if kind == "stale":
        return _snapshot(collected_at=time.time() - 60)
    if kind == "future":
        return _snapshot(collected_at=time.time() + 60)
    if kind == "error":
        return _snapshot(complete=False, error="inert transient collection failure")
    return _snapshot(complete=False, enumeration_complete=False)


@pytest.mark.parametrize("kind", [
    "invalid-type", "invalid-counts", "stale", "future", "error", "enumeration-incomplete",
])
def test_failed_request_retries_original_token_with_actual_fresh_work(monkeypatch, kind):
    module = ProcessMonitorModule()
    actual_run = module.run
    start, retry_idle, retry_release = (threading.Event() for _ in range(3))
    calls, sleeps = [], []

    def collect(**kwargs):
        calls.append(kwargs)
        return _retry_failure(kind) if len(calls) == 1 else _snapshot()

    def sleep(seconds, **kwargs):
        sleeps.append((seconds, kwargs))
        if len(sleeps) == 2:
            retry_idle.set()
            assert retry_release.wait(5.0)
        elif len(sleeps) > 2:
            module.generation_stop_event().wait(5.0)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", sleep)
    with _run_owned(monkeypatch, module, work, release=(start, retry_release)):
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        start.set()
        assert retry_idle.wait(5.0)
        assert calls == [{"max_age": 0.0}]
        assert module._pending_observation_request == request
        assert not module._observation_request_event.is_set()
        assert module._observation_request_serial == request[1]
        assert not module.fresh_observation_complete(request)
        assert module.health < 90
        assert sleeps[-1][0] == 3.0 and sleeps[-1][1]["cycle_complete"] is False
        assert sleeps[-1][1]["_wake_event"] is module._observation_request_event
        retry_release.set()
        _wait(lambda: module.fresh_observation_complete(request))
        assert calls == [{"max_age": 0.0}, {"max_age": 0.0}]
        assert module._completed_observation_request == request
        assert module._pending_observation_request is None
        assert module._observation_request_serial == request[1]
        assert module.health == 100
        assert module._redteam_receipt_capability is None and module._bus is None


def test_failed_inflight_request_never_clobbers_newer_pending_request(monkeypatch):
    module = ProcessMonitorModule()
    actual_run = module.run
    start, first_entered, first_release, retry_idle, retry_release = (
        threading.Event() for _ in range(5)
    )
    calls, sleeps = [], []

    def collect(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            first_entered.set()
            assert first_release.wait(5.0)
            return _retry_failure("error")
        return _snapshot()

    def sleep(_seconds, **_kwargs):
        sleeps.append(True)
        if len(sleeps) == 2:
            retry_idle.set()
            assert retry_release.wait(5.0)
        elif len(sleeps) > 2:
            module.generation_stop_event().wait(5.0)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", sleep)
    with _run_owned(monkeypatch, module, work, release=(start, first_release, retry_release)):
        first = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        start.set()
        assert first_entered.wait(5.0)
        second = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert first is not None and second is not None and second[1] > first[1]
        first_release.set()
        assert retry_idle.wait(5.0)
        assert module._pending_observation_request == second
        assert module._observation_request_event.is_set()
        assert not module.fresh_observation_complete(first)
        assert not module.fresh_observation_complete(second)
        retry_release.set()
        _wait(lambda: module.fresh_observation_complete(second))
        assert module.fresh_observation_complete(first)
        assert module._completed_observation_request == second
        assert calls == [{"max_age": 0.0}, {"max_age": 0.0}]


def test_persistent_failure_retains_one_hint_without_immediate_retry_wake(monkeypatch):
    module = ProcessMonitorModule()
    actual_run = module.run
    start, first_idle, first_retry, second_idle, second_retry = (
        threading.Event() for _ in range(5)
    )
    calls, sleeps = [], []

    def collect(**kwargs):
        calls.append(kwargs)
        return _retry_failure("enumeration-incomplete")

    def sleep(seconds, **kwargs):
        sleeps.append((seconds, kwargs["_wake_event"].is_set()))
        if len(sleeps) == 2:
            first_idle.set()
            assert first_retry.wait(5.0)
        elif len(sleeps) == 3:
            second_idle.set()
            assert second_retry.wait(5.0)
        elif len(sleeps) > 3:
            module.generation_stop_event().wait(5.0)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", sleep)
    with _run_owned(monkeypatch, module, work, release=(start, first_retry, second_retry)):
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        start.set()
        assert first_idle.wait(5.0)
        assert module._pending_observation_request == request
        assert not module.fresh_observation_complete(request)
        first_retry.set()
        assert second_idle.wait(5.0)
        assert module._pending_observation_request == request
        assert module._observation_request_serial == request[1]
        assert not module._observation_request_event.is_set()
        assert sleeps[1:] == [(3.0, False), (3.0, False)]
        assert calls == [{"max_age": 0.0}, {"max_age": 0.0}]
        assert not module.fresh_observation_complete(request)
        module.stop()
        assert module._pending_observation_request is None
        assert module._completed_observation_request is None
        assert not module._observation_request_event.is_set()
        second_retry.set()
    assert len(calls) == 2


def test_stop_during_failed_scan_revokes_retry_before_restart(monkeypatch):
    module = ProcessMonitorModule()
    actual_run = module.run
    start, entered, release = (threading.Event() for _ in range(3))
    calls = []

    def collect(**kwargs):
        calls.append(kwargs)
        entered.set()
        assert release.wait(5.0)
        return _retry_failure("error")

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", lambda *_args, **_kwargs: None)
    with _run_owned(monkeypatch, module, work, release=(start, release)):
        old = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        start.set()
        assert entered.wait(5.0)
        module.stop()
        release.set()
        _wait(lambda: not module._thread.is_alive())
        assert module._pending_observation_request is None
        assert module._completed_observation_request is None
        assert not module._observation_request_event.is_set()
        assert not module.fresh_observation_complete(old)
    with _run_owned(monkeypatch, module, lambda: _pause(module)):
        current = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert old is not None and current is not None and current[0] > old[0]
        module._complete_fresh_observation(old)
        assert module._pending_observation_request == current
        assert module._completed_observation_request is None
        assert not module.fresh_observation_complete(old)
    assert len(calls) == 1 and module._pending_observation_request is None


def test_fresh_diagnostic_is_a_detached_read_only_queued_hint(monkeypatch):
    module = ProcessMonitorModule()
    with _run_owned(monkeypatch, module, lambda: _pause(module)):
        before = module.operational_snapshot()
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        diagnostic = module.fresh_observation_diagnostic(request)
        assert diagnostic["schema"] == "angerona.process-fresh-observation-diagnostic.v1"
        assert diagnostic["diagnostic_only"] is True
        assert diagnostic["requested_stage"] == "queued"
        assert diagnostic["worker_stage"] == "unobserved"
        assert diagnostic["stage_age_seconds"] is None
        assert diagnostic["pending_token"] == list(request)
        assert diagnostic["inflight_token"] is None
        assert diagnostic["completed_token"] is None
        assert diagnostic["last_refusal_reason"] == "not-observed"
        assert diagnostic["last_coverage"] == {}
        assert 0 <= diagnostic["requested_age_seconds"] <= 86400
        diagnostic["pending_token"][1] = -1
        diagnostic["last_coverage"]["injected"] = "private supplied string"
        again = module.fresh_observation_diagnostic(request)
        assert again["pending_token"] == list(request)
        assert again["last_coverage"] == {}
        after = module.operational_snapshot()
        assert (after["cycle_count"], after["health"]) == (before["cycle_count"], before["health"])
        assert not module.fresh_observation_complete(request)
        assert module._redteam_receipt_capability is None and module._bus is None


def test_fresh_diagnostic_distinguishes_collection_processing_and_newer_queued_request(monkeypatch):
    module = ProcessMonitorModule()
    actual_run, actual_health = module.run, module._set_process_health
    start, collecting, finish_collection, processing, finish_processing = (
        threading.Event() for _ in range(5)
    )

    def collect(**kwargs):
        assert kwargs == {"max_age": 0.0}
        collecting.set()
        assert finish_collection.wait(5.0)
        return _snapshot()

    def health(*args):
        processing.set()
        assert finish_processing.wait(5.0)
        return actual_health(*args)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "_set_process_health", health)
    with _run_owned(monkeypatch, module, work, release=(start, finish_collection, finish_processing)):
        first = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert first is not None
        start.set()
        assert collecting.wait(5.0)
        second = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert second is not None and second[1] > first[1]
        active = module.fresh_observation_diagnostic(first)
        pending = module.fresh_observation_diagnostic(second)
        assert active["requested_stage"] == active["worker_stage"] == "collecting"
        assert active["inflight_token"] == list(first)
        assert active["last_coverage_token"] is None
        assert active["pending_token"] == list(second)
        assert pending["requested_stage"] == "queued"
        assert not module.fresh_observation_complete(first)
        finish_collection.set()
        assert processing.wait(5.0)
        active = module.fresh_observation_diagnostic(first)
        assert active["requested_stage"] == active["worker_stage"] == "processing"
        assert active["inflight_token"] == list(first)
        assert not module.fresh_observation_complete(first)
        finish_processing.set()
        _wait(lambda: module.fresh_observation_complete(second))
        finished = module.fresh_observation_diagnostic(second)
        assert finished["requested_stage"] == "completed"
        assert finished["completed_token"] == list(second)
        assert finished["last_refusal_reason"] == "acknowledgement-eligible"
        assert finished["last_coverage_token"] == list(second)


@pytest.mark.parametrize(("kind", "reason"), [
    ("invalid-type", "typed-receipt-unavailable"),
    ("invalid-counts", "invalid-coverage-counts"),
    ("stale", "collection-not-fresh"),
    ("future", "collection-not-fresh"),
    ("error", "collector-error-reported"),
    ("enumeration-incomplete", "enumeration-incomplete"),
])
def test_fresh_diagnostic_explains_refusal_without_copying_collector_text(monkeypatch, kind, reason):
    import json

    module = ProcessMonitorModule()
    actual_run = module.run
    start, retry_idle, retry_release = (threading.Event() for _ in range(3))
    sleeps, calls = [], []

    def collect(**kwargs):
        calls.append(kwargs)
        return _retry_failure(kind)

    def sleep(seconds, **kwargs):
        sleeps.append((seconds, kwargs["_wake_event"].is_set()))
        if len(sleeps) == 2:
            retry_idle.set()
            assert retry_release.wait(5.0)
        elif len(sleeps) > 2:
            module.generation_stop_event().wait(5.0)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    monkeypatch.setattr(module, "sleep", sleep)
    with _run_owned(monkeypatch, module, work, release=(start, retry_release)):
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        start.set()
        assert retry_idle.wait(5.0)
        before = module.operational_snapshot()
        diagnostic = module.fresh_observation_diagnostic(request)
        assert diagnostic["requested_stage"] == diagnostic["worker_stage"] == "retry"
        assert diagnostic["pending_token"] == list(request)
        assert diagnostic["inflight_token"] is None
        assert diagnostic["completed_token"] is None
        assert diagnostic["last_attempt_token"] == list(request)
        assert diagnostic["last_refusal_reason"] == reason
        assert diagnostic["last_coverage_token"] == list(request)
        assert diagnostic["waiting"] is True
        assert diagnostic["nominal_wait_seconds"] == 3.0
        # This fixture supplies sleep; its declared interval was published by
        # the real preceding cycle, not inferred from a pacing calculation.
        assert diagnostic["declared_wait_seconds"] == 3.0
        assert calls == [{"max_age": 0.0}]
        assert not module._observation_request_event.is_set()
        assert not module.fresh_observation_complete(request)
        assert "inert transient collection failure" not in json.dumps(diagnostic)
        assert len(json.dumps(diagnostic)) < 4096
        after = module.operational_snapshot()
        assert (after["health"], after["cycle_count"]) == (before["health"], before["cycle_count"])


def test_fresh_diagnostic_partial_identity_acknowledgement_keeps_degraded_health(monkeypatch):
    module = ProcessMonitorModule()
    actual_run = module.run
    start = threading.Event()

    def collect(**kwargs):
        assert kwargs == {"max_age": 0.0}
        return _snapshot(
            processes=({"pid": 71, "name": "inert.exe", "exe": "C:/private/inert.exe",
                        "ppid": 0, "cmdline": ("private supplied command",), "create_time": None},),
            complete=False, enumerated=1, identity_incomplete=1,
        )

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, work, release=(start,)):
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        start.set()
        _wait(lambda: module.fresh_observation_complete(request))
        diagnostic = module.fresh_observation_diagnostic(request)
        assert diagnostic["requested_stage"] == "completed"
        assert diagnostic["last_refusal_reason"] == "acknowledgement-eligible"
        assert diagnostic["last_coverage"]["complete"] is False
        assert diagnostic["last_coverage"]["observed_identity_gaps"] == 1
        assert module.health == 70
        assert "private" not in repr(diagnostic)
        assert "inert.exe" not in repr(diagnostic)


def test_fresh_diagnostic_stop_is_not_worker_retirement(monkeypatch):
    module = ProcessMonitorModule()
    actual_run = module.run
    start, collecting, finish = (threading.Event() for _ in range(3))

    def collect(**kwargs):
        assert kwargs == {"max_age": 0.0}
        collecting.set()
        assert finish.wait(5.0)
        return _snapshot()

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, work, release=(start, finish)):
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        start.set()
        assert collecting.wait(5.0)
        module.stop()
        diagnostic = module.fresh_observation_diagnostic(request)
        assert diagnostic["requested_stage"] == diagnostic["worker_stage"] == "stopping"
        assert diagnostic["inflight_token"] == list(request)
        assert diagnostic["pending_token"] is None and diagnostic["completed_token"] is None
        assert module._thread.is_alive(), "stop must not be reported as worker retirement"
        finish.set()
        _wait(lambda: not module._thread.is_alive())
        retired = module.fresh_observation_diagnostic(request)
        assert retired["requested_stage"] == "stopping"
        assert retired["inflight_token"] is None
        assert not module.fresh_observation_complete(request)


def test_typed_process_readiness_error_contains_only_detached_fixed_diagnostics():
    from angerona.modules.purple_guard import (
        RedTeamProcessObservationReadinessError, RedTeamValidationError,
        _process_observation_readiness_error,
    )

    module = ProcessMonitorModule()
    error = _process_observation_readiness_error(
        "existing readiness refusal", process_module=module, request=(1, 1),
    )
    assert isinstance(error, RedTeamValidationError)
    assert type(error) is RedTeamProcessObservationReadinessError
    assert "observation_diagnostic=" in str(error)
    evidence = error.failure_evidence()
    assert evidence["requested_stage"] == "unobserved"
    evidence["last_coverage"]["injected"] = "private text"
    assert error.failure_evidence()["last_coverage"] == {}
    assert "private text" not in str(error)


def _assert_diagnostic_unavailable(diagnostic):
    assert diagnostic == {
        "schema": "angerona.process-fresh-observation-diagnostic.v1",
        "diagnostic_only": True,
        "available": False,
        "reason": "diagnostic-unavailable",
    }


def test_diagnostic_clock_failure_after_queue_publication_preserves_request_and_wake(monkeypatch):
    module = ProcessMonitorModule()

    def failed_clock():
        raise RuntimeError("private diagnostic clock failure")

    with _run_owned(monkeypatch, module, lambda: _pause(module)):
        before = module.operational_snapshot()
        # Only the introduced diagnostic clock is faulted; the authoritative
        # engine and fixture keep their original clock functions.
        monkeypatch.setattr(module, "_fresh_observation_diagnostic_now", failed_clock)
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        assert module._pending_observation_request == request
        assert module._observation_request_event.is_set()
        assert not module.fresh_observation_complete(request)
        _assert_diagnostic_unavailable(module.fresh_observation_diagnostic(request))
        after = module.operational_snapshot()
        assert (after["health"], after["cycle_count"]) == (before["health"], before["cycle_count"])


@pytest.mark.parametrize("boundary", [
    "generation", "wait-begin", "wait-end", "begin", "processing", "coverage", "completed",
])
def test_diagnostic_capture_failure_cannot_interrupt_actual_observation(monkeypatch, boundary):
    module = ProcessMonitorModule()
    actual_run, capture = module.run, module._capture_fresh_diagnostic
    start, failed = threading.Event(), threading.Event()
    calls = []

    def faulted_capture(observed, request, generation, interval):
        if observed == boundary:
            failed.set()
            raise RuntimeError("private diagnostic capture failure")
        return capture(observed, request, generation, interval)

    def collect(**kwargs):
        calls.append(kwargs)
        return _snapshot()

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(module, "_capture_fresh_diagnostic", faulted_capture)
    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, work, release=(start,)):
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        assert module._observation_request_event.is_set()
        start.set()
        assert failed.wait(5.0)
        _wait(lambda: module.fresh_observation_complete(request))
        assert calls and calls[0] == {"max_age": 0.0}
        assert module.health == 100
        assert module.operational_snapshot()["cycle_count"] >= 2
        _assert_diagnostic_unavailable(module.fresh_observation_diagnostic(request))


def test_diagnostic_retry_capture_failure_preserves_original_retry_token_and_cadence(monkeypatch):
    module = ProcessMonitorModule()
    actual_run, capture = module.run, module._capture_fresh_diagnostic
    start, retry_idle, retry_release, failed = (threading.Event() for _ in range(4))
    calls, sleeps = [], []

    def faulted_capture(observed, request, generation, interval):
        if observed == "retry":
            failed.set()
            raise RuntimeError("private diagnostic retry failure")
        return capture(observed, request, generation, interval)

    def collect(**kwargs):
        calls.append(kwargs)
        return _retry_failure("error") if len(calls) == 1 else _snapshot()

    def sleep(seconds, **kwargs):
        sleeps.append((seconds, kwargs["_wake_event"].is_set()))
        if len(sleeps) == 2:
            retry_idle.set()
            assert retry_release.wait(5.0)
        elif len(sleeps) > 2:
            module.generation_stop_event().wait(5.0)

    def work():
        assert start.wait(5.0)
        actual_run()

    monkeypatch.setattr(module, "_capture_fresh_diagnostic", faulted_capture)
    monkeypatch.setattr(module, "sleep", sleep)
    monkeypatch.setattr(process_monitor, "process_snapshot", collect)
    with _run_owned(monkeypatch, module, work, release=(start, retry_release)):
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        start.set()
        assert retry_idle.wait(5.0) and failed.is_set()
        assert module._pending_observation_request == request
        assert module._completed_observation_request is None
        assert not module._observation_request_event.is_set()
        assert sleeps[-1] == (3.0, False)
        assert calls == [{"max_age": 0.0}]
        assert not module.fresh_observation_complete(request)
        _assert_diagnostic_unavailable(module.fresh_observation_diagnostic(request))
        retry_release.set()
        _wait(lambda: module.fresh_observation_complete(request))
        assert calls == [{"max_age": 0.0}, {"max_age": 0.0}]


def test_diagnostic_stop_capture_failure_cannot_prevent_revocation_or_retirement(monkeypatch):
    module = ProcessMonitorModule()
    capture = module._capture_fresh_diagnostic
    failed = threading.Event()

    def faulted_capture(observed, request, generation, interval):
        if observed == "stopping":
            failed.set()
            raise RuntimeError("private diagnostic stop failure")
        return capture(observed, request, generation, interval)

    monkeypatch.setattr(module, "_capture_fresh_diagnostic", faulted_capture)
    with _run_owned(monkeypatch, module, lambda: _pause(module)):
        request = module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        assert request is not None
        owned_thread = module._thread
        module.stop()
        assert failed.is_set()
        assert module._pending_observation_request is None
        assert module._completed_observation_request is None
        assert not module._observation_request_event.is_set()
        assert not module.fresh_observation_complete(request)
        _wait(lambda: not owned_thread.is_alive())
        _assert_diagnostic_unavailable(module.fresh_observation_diagnostic(request))


def test_diagnostic_initialization_failure_preserves_original_module_state(monkeypatch):
    def failed_capture(*_args, **_kwargs):
        raise RuntimeError("private diagnostic initialization failure")

    monkeypatch.setattr(ProcessMonitorModule, "_capture_fresh_diagnostic", failed_capture)
    module = ProcessMonitorModule()
    assert module._pending_observation_request is None
    assert module._completed_observation_request is None
    assert module._observation_request_serial == 0
    assert not module._observation_request_event.is_set()
    assert module.request_fresh_observation(expected_generation=1) is None
    _assert_diagnostic_unavailable(module.fresh_observation_diagnostic((1, 1)))


@pytest.mark.parametrize("seam", ["accessor", "encoder"])
def test_diagnostic_failure_preserves_original_readiness_error_type_and_exact_message(monkeypatch, seam):
    from angerona.modules import purple_guard

    def failed(*_args, **_kwargs):
        raise RuntimeError("private diagnostic refusal-formatting failure")

    module = ProcessMonitorModule()
    if seam == "accessor":
        monkeypatch.setattr(ProcessMonitorModule, "fresh_observation_diagnostic", failed)
    else:
        monkeypatch.setattr(purple_guard, "_encode_process_observation_diagnostic", failed)
    original_message = "existing refusal: status=running, health=55, generation=1, requested_observation_complete=False, error="
    error = purple_guard._process_observation_readiness_error(
        original_message, process_module=module, request=(1, 1),
    )
    assert type(error) is purple_guard.RedTeamValidationError
    assert str(error) == original_message
    assert "private" not in str(error)


def test_unavailable_diagnostic_preserves_original_readiness_error_type_and_exact_message(monkeypatch):
    from angerona.modules import purple_guard

    module = ProcessMonitorModule()
    monkeypatch.setattr(module, "_observation_diagnostic_unavailable", True)
    original_message = "existing refusal: requested_observation_complete=False, error="
    error = purple_guard._process_observation_readiness_error(
        original_message, process_module=module, request=(1, 1),
    )
    assert type(error) is purple_guard.RedTeamValidationError
    assert str(error) == original_message
    _assert_diagnostic_unavailable(module.fresh_observation_diagnostic((1, 1)))


def test_diagnostic_huge_exact_integer_interval_clamps_before_float_conversion(monkeypatch):
    module = ProcessMonitorModule()
    before = module.operational_snapshot()
    # Only introduced diagnostic storage is corrupted; engine cadence, clocks,
    # health and source collection state remain untouched.
    monkeypatch.setattr(module, "_observation_nominal_wait", 10**10000)
    diagnostic = module.fresh_observation_diagnostic((1, 1))
    assert diagnostic["available"] is True
    assert diagnostic["nominal_wait_seconds"] == 86400.0
    after = module.operational_snapshot()
    assert (after["health"], after["cycle_count"], after["declared_cycle_interval_seconds"]) == (
        before["health"], before["cycle_count"], before["declared_cycle_interval_seconds"],
    )


@pytest.mark.parametrize("stamp_kind", ["object", "text", "nan", "infinite", "huge-integer", "negative", "future"])
def test_diagnostic_invalid_stored_timestamp_returns_fixed_unavailable(monkeypatch, stamp_kind):
    module = ProcessMonitorModule()
    before = module.operational_snapshot()
    bad_stamp = {
        "object": lambda: object(), "text": lambda: "private invalid timestamp",
        "nan": lambda: float("nan"), "infinite": lambda: float("inf"),
        "huge-integer": lambda: 10**10000, "negative": lambda: -1,
        "future": lambda: module._fresh_observation_diagnostic_now() + 3600,
    }[stamp_kind]()
    monkeypatch.setattr(module, "_observation_waiting", True)
    monkeypatch.setattr(module, "_observation_wait_since", bad_stamp)
    _assert_diagnostic_unavailable(module.fresh_observation_diagnostic((1, 1)))
    after = module.operational_snapshot()
    assert (after["health"], after["cycle_count"]) == (before["health"], before["cycle_count"])


def test_diagnostic_future_wait_stamp_cannot_be_relabelled_zero_elapsed(monkeypatch):
    module = ProcessMonitorModule()
    before = module.operational_snapshot()
    module._observe_fresh_diagnostic("wait-begin", generation=module.lifecycle_generation, interval=3.0)
    monkeypatch.setattr(module, "_observation_wait_since", module._fresh_observation_diagnostic_now() + 3600)
    module._observe_fresh_diagnostic("wait-end", generation=module.lifecycle_generation, interval=3.0)
    _assert_diagnostic_unavailable(module.fresh_observation_diagnostic((1, 1)))
    after = module.operational_snapshot()
    assert (after["health"], after["cycle_count"]) == (before["health"], before["cycle_count"])


def test_operator_baseexception_is_not_swallowed_and_queue_publication_already_exists(monkeypatch):
    module = ProcessMonitorModule()

    def interrupted_clock():
        raise KeyboardInterrupt()

    with _run_owned(monkeypatch, module, lambda: _pause(module)):
        with monkeypatch.context() as scoped:
            scoped.setattr(module, "_fresh_observation_diagnostic_now", interrupted_clock)
            with pytest.raises(KeyboardInterrupt):
                module.request_fresh_observation(expected_generation=module.lifecycle_generation)
        request = module._pending_observation_request
        assert request is not None
        assert module._observation_request_event.is_set()
        assert not module.fresh_observation_complete(request)
