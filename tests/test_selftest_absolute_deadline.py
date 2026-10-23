"""Absolute self-test budgets retain completion timing and worker capacity."""
from __future__ import annotations

import ctypes
import json
import os
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import selftest


@pytest.fixture
def candidate():
    return selftest


class Clock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def scripted_runtime(monkeypatch, candidate, *, start, wait=None):
    clock = Clock()
    state = SimpleNamespace(worker=None, waits=[], event=None)

    class Event:
        def __init__(self):
            self.flag = False
            state.event = self

        def set(self):
            self.flag = True

        def is_set(self):
            return self.flag

        def wait(self, remaining):
            state.waits.append(remaining)
            return self.flag if wait is None else wait(clock, state, self, remaining)

    class Thread:
        def __init__(self, *, target, name, daemon):
            self.target = target
            assert name == 'inert-deadline'
            assert daemon is True
            state.worker = self

        def start(self):
            start(clock, state, self)

    monkeypatch.setattr(candidate, 'time', SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(candidate, 'threading', SimpleNamespace(Event=Event, Thread=Thread))
    return clock, state


def assert_one_permit_available(permits):
    assert permits.acquire(blocking=False)
    try:
        assert not permits.acquire(blocking=False)
    finally:
        permits.release()


def test_late_completed_callback_is_not_success_when_start_returns_late(candidate, monkeypatch):
    def start(clock, state, worker):
        worker.target()

    clock, state = scripted_runtime(monkeypatch, candidate, start=start)
    calls = []

    def callback():
        calls.append('once')
        clock.advance(0.5)
        return 'late-value'

    permits = threading.BoundedSemaphore(1)
    ok, error, value = candidate._bounded_call(callback, permits, 0.1, name='inert-deadline')
    assert not ok and value is None and calls == ['once']
    assert error == 'timed out after 0.1s; the call finished after its deadline'
    assert state.waits == [0.0]
    assert_one_permit_available(permits)


def test_on_time_completion_survives_late_coordinator_resume(candidate, monkeypatch):
    def start(clock, state, worker):
        worker.target()
        clock.advance(0.5)

    clock, state = scripted_runtime(monkeypatch, candidate, start=start)
    permits = threading.BoundedSemaphore(1)

    def callback():
        clock.advance(0.05)
        return 'on-time-value'

    assert candidate._bounded_call(callback, permits, 0.1, name='inert-deadline') == (True, '', 'on-time-value')
    assert state.waits == [0.0]
    assert_one_permit_available(permits)


def test_wait_receives_only_budget_remaining_after_start(candidate, monkeypatch):
    def start(clock, state, worker):
        clock.advance(0.04)

    def wait(clock, state, event, remaining):
        assert remaining == pytest.approx(0.06)
        clock.advance(0.02)
        state.worker.target()
        return event.flag

    scripted_runtime(monkeypatch, candidate, start=start, wait=wait)
    permits = threading.BoundedSemaphore(1)
    assert candidate._bounded_call(lambda: 'ready', permits, 0.1, name='inert-deadline') == (True, '', 'ready')
    assert_one_permit_available(permits)


def test_exact_completion_boundary_remains_eligible(candidate, monkeypatch):
    clock, _ = scripted_runtime(monkeypatch, candidate, start=lambda _c, _s, worker: worker.target())
    permits = threading.BoundedSemaphore(1)

    def callback():
        clock.advance(0.1)
        return 'at-boundary'

    assert candidate._bounded_call(callback, permits, 0.1, name='inert-deadline') == (True, '', 'at-boundary')
    assert_one_permit_available(permits)


def test_false_wait_rechecks_an_already_completed_event(candidate, monkeypatch):
    def wait(clock, state, event, remaining):
        clock.advance(0.05)
        state.worker.target()
        assert event.flag
        return False  # Completion won immediately after the condition wait.

    scripted_runtime(monkeypatch, candidate, start=lambda *_: None, wait=wait)
    permits = threading.BoundedSemaphore(1)
    assert candidate._bounded_call(lambda: 'race-complete', permits, 0.1, name='inert-deadline') == (True, '', 'race-complete')
    assert_one_permit_available(permits)


@pytest.mark.parametrize('late', [False, True])
def test_error_timing_preserves_original_type_and_message(candidate, monkeypatch, late):
    clock, _ = scripted_runtime(monkeypatch, candidate, start=lambda _c, _s, worker: worker.target())
    permits = threading.BoundedSemaphore(1)

    def callback():
        clock.advance(0.5 if late else 0.05)
        raise RuntimeError('inert original failure')

    ok, error, value = candidate._bounded_call(callback, permits, 0.1, name='inert-deadline')
    assert not ok and value is None
    if late:
        assert error == ('timed out after 0.1s; the call finished after its deadline; '
                         'original error: RuntimeError: inert original failure')
    else:
        assert error == 'RuntimeError: inert original failure'
    assert_one_permit_available(permits)


def test_completion_is_stamped_before_error_formatting(candidate, monkeypatch):
    clock, state = scripted_runtime(monkeypatch, candidate, start=lambda _c, _s, worker: worker.target())
    permits = threading.BoundedSemaphore(1)

    class SlowFormatError(Exception):
        def __str__(self):
            clock.advance(0.5)
            return 'inert-format'

    def callback():
        clock.advance(0.05)
        raise SlowFormatError()

    assert candidate._bounded_call(callback, permits, 0.1, name='inert-deadline') == (False, 'SlowFormatError: inert-format', None)
    assert state.waits == [0.0]
    assert_one_permit_available(permits)


def test_start_failure_returns_permit_and_preserves_exception(candidate, monkeypatch):
    failure = RuntimeError('inert start failure')

    def start(*_args):
        raise failure

    scripted_runtime(monkeypatch, candidate, start=start)
    permits = threading.BoundedSemaphore(1)
    calls = []
    with pytest.raises(RuntimeError) as error:
        candidate._bounded_call(lambda: calls.append('unexpected'), permits, 0.1, name='inert-deadline')
    assert error.value is failure and not calls
    assert_one_permit_available(permits)


def test_refused_capacity_starts_no_worker(candidate, monkeypatch):
    scripted_runtime(monkeypatch, candidate, start=lambda *_: pytest.fail('worker started without capacity'))
    permits = threading.BoundedSemaphore(1)
    assert permits.acquire(blocking=False)
    try:
        assert candidate._bounded_call(lambda: pytest.fail('callback invoked'), permits, 0.1, name='inert-deadline') == (False, 'a previous call is still running', None)
        assert not permits.acquire(blocking=False)
    finally:
        permits.release()
    assert_one_permit_available(permits)


def test_real_pending_worker_retains_both_permits_until_actual_retirement(candidate):
    entered, release = threading.Event(), threading.Event()
    process, hardware = threading.BoundedSemaphore(1), threading.BoundedSemaphore(1)
    lease = candidate._CapacityLease(hardware, process)
    owned = {}

    def callback():
        owned['worker'] = threading.current_thread()
        entered.set()
        assert release.wait(2.0), 'inert cleanup release missing'
        return 'completed-after-release'

    try:
        ok, error, value = candidate._bounded_call(callback, lease, 0.025, name='inert-owned-pending')
        assert entered.wait(1.0)
        assert not ok and value is None and 'the call is still running' in error
        assert not process.acquire(blocking=False)
        assert not hardware.acquire(blocking=False)
        assert candidate._bounded_call(lambda: pytest.fail('competing callback'), lease, 0.025, name='inert-refused') == (False, 'a previous call is still running', None)
    finally:
        release.set()
        worker = owned.get('worker')
        if worker is not None:
            worker.join(2.0)
            assert not worker.is_alive()
    assert_one_permit_available(process)
    assert_one_permit_available(hardware)


@pytest.mark.skipif(os.name != 'nt', reason='Native WinDLL/PyDLL GIL control requires Windows')
def test_native_sleep_pair_never_credits_after_deadline(candidate, monkeypatch):
    from ctypes import wintypes

    rows = []
    for label, factory in [('gil-released', ctypes.WinDLL), ('gil-held', ctypes.PyDLL)]:
        sleep = factory('kernel32.dll', winmode=0x800).Sleep
        sleep.argtypes = [wintypes.DWORD]
        sleep.restype = None
        permits = threading.BoundedSemaphore(1)
        owned = {}

        def thread_factory(**kwargs):
            worker = threading.Thread(**kwargs)
            owned['worker'] = worker
            return worker

        # Retain the worker before startup; a legitimate deadline can expire
        # before its callback receives a scheduling slice.
        monkeypatch.setattr(candidate, 'threading', SimpleNamespace(
            Event=threading.Event, Thread=thread_factory))

        def callback():
            before = time.monotonic()
            sleep(500)
            owned['native_seconds'] = time.monotonic() - before
            return 'completed-inert-native-wait'

        before = time.monotonic()
        result = candidate._bounded_call(callback, permits, 0.1, name='inert-native-deadline')
        elapsed = time.monotonic() - before
        worker = owned.get('worker')
        assert worker is not None, 'Owned native callback did not enter'
        worker.join(2.0)
        assert not worker.is_alive(), 'Owned native callback did not retire'
        assert_one_permit_available(permits)
        rows.append({'label': label, 'requested_seconds': 0.1, 'native_wait_ms': 500,
                     'completed': result[0], 'error': result[1], 'wall_seconds': elapsed,
                     'native_seconds': owned['native_seconds'], 'owned_thread_retired': True})
        assert result[0] is False and result[2] is None
        assert result[1].startswith('timed out after 0.1s;')
    print(json.dumps({'inert_native_deadline_pair': rows}, sort_keys=True))
