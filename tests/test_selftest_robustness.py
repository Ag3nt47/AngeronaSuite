"""Fail-closed outcomes and exact permit ownership; deterministic local fakes."""
from __future__ import annotations

import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from angerona.core import selftest as candidate


ROOT = Path(__file__).resolve().parents[1]
FALLBACK = "callback failed; exception message unavailable"


class Clock:
    now = 0.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def scripted_runtime(monkeypatch, *, event_failure=None, thread_failure=None, start_failure=None):
    clock = Clock()
    state = SimpleNamespace(event_attempts=0, thread_attempts=0, starts=0,
        worker_entries=0, uncaught_types=[], waits=[])

    class Event:
        def __init__(self):
            state.event_attempts += 1
            if event_failure is not None:
                raise event_failure
            self.flag = False

        def set(self):
            self.flag = True

        def is_set(self):
            return self.flag

        def wait(self, timeout):
            state.waits.append(timeout)
            return self.flag

    class Thread:
        def __init__(self, *, target, name, daemon):
            state.thread_attempts += 1
            if thread_failure is not None:
                raise thread_failure
            self.target = target

        def start(self):
            state.starts += 1
            if start_failure is not None:
                raise start_failure
            state.worker_entries += 1
            # A real Thread bootstrap handles escaping BaseExceptions instead
            # of rethrowing them from start(). Keep that boundary faithful so a
            # formatter failure cannot be confused with a start/double-release.
            try:
                self.target()
            except BaseException as exc:
                state.uncaught_types.append(type(exc).__name__)

    monkeypatch.setattr(candidate, "time", SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(candidate, "threading", SimpleNamespace(Event=Event, Thread=Thread))
    return clock, state


def owned_permits(use_lease):
    process = threading.BoundedSemaphore(1)
    if not use_lease:
        return process, (process,)
    capacity = threading.BoundedSemaphore(1)
    return candidate._CapacityLease(capacity, process), (capacity, process)


def assert_exactly_one_available(underlying):
    for permit in underlying:
        assert permit.acquire(blocking=False), "an acquired permit leaked"
        try:
            assert not permit.acquire(blocking=False), "permit capacity expanded"
        finally:
            permit.release()


def test_actual_source_is_selected_candidate():
    assert Path(candidate.__file__).resolve() == ROOT / "src/angerona/core/selftest.py"


@pytest.mark.parametrize("stage", ["event", "thread"])
@pytest.mark.parametrize("failure_kind", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("use_lease", [False, True])
def test_prestart_construction_failure_returns_exact_owned_capacity(monkeypatch, stage, failure_kind, use_lease):
    failure = failure_kind("inert construction failure")
    _clock, state = scripted_runtime(monkeypatch, **{stage + "_failure": failure})
    permits, underlying = owned_permits(use_lease)
    calls = []
    with pytest.raises(failure_kind) as caught:
        candidate._bounded_call(lambda: calls.append("unexpected"), permits, 1, name="inert-setup")
    assert caught.value is failure
    assert state.starts == state.worker_entries == 0 and calls == []
    assert state.thread_attempts == (1 if stage == "thread" else 0)
    assert_exactly_one_available(underlying)


@pytest.mark.parametrize("callback_base", [Exception, BaseException])
@pytest.mark.parametrize("formatter_failure", [RuntimeError, KeyboardInterrupt])
def test_unrenderable_callback_failure_cannot_become_success(monkeypatch, callback_base, formatter_failure):
    _clock, state = scripted_runtime(monkeypatch)
    permits, underlying = owned_permits(False)

    class Unrenderable(callback_base):
        def __str__(self):
            raise formatter_failure("PRIVATE-FORMATTER-TEXT-MUST-NOT-LEAK")

    def callback():
        raise Unrenderable()

    assert candidate._bounded_call(callback, permits, 1, name="inert-unrenderable") == (False, FALLBACK, None)
    assert state.worker_entries == 1 and state.uncaught_types == []
    assert_exactly_one_available(underlying)


@pytest.mark.parametrize("value", [None, 42, "normal callback value"])
def test_successful_callback_result_and_capacity_are_unchanged(monkeypatch, value):
    _clock, state = scripted_runtime(monkeypatch)
    permits, underlying = owned_permits(True)
    assert candidate._bounded_call(lambda: value, permits, 1, name="inert-normal") == (True, "", value)
    assert state.worker_entries == 1 and state.uncaught_types == []
    assert_exactly_one_available(underlying)


def test_renderable_error_keeps_original_type_message_and_capacity(monkeypatch):
    _clock, state = scripted_runtime(monkeypatch)
    permits, underlying = owned_permits(True)

    def callback():
        raise RuntimeError("original renderable message")

    assert candidate._bounded_call(callback, permits, 1, name="inert-original-error") == (False, "RuntimeError: original renderable message", None)
    assert state.uncaught_types == []
    assert_exactly_one_available(underlying)


@pytest.mark.parametrize("completion,late", [(0.25, False), (1.25, True)])
def test_completion_stamp_stays_before_failed_error_formatting(monkeypatch, completion, late):
    clock, state = scripted_runtime(monkeypatch)
    permits, underlying = owned_permits(True)

    class Unrenderable(Exception):
        def __str__(self):
            clock.advance(10)
            raise KeyboardInterrupt("inert formatter interruption")

    def callback():
        clock.advance(completion)
        raise Unrenderable()

    prefix = "timed out after 1s; the call finished after its deadline; original error: " if late else ""
    assert candidate._bounded_call(callback, permits, 1, name="inert-stamp") == (False, prefix + FALLBACK, None)
    assert state.waits == [0.0] and state.uncaught_types == []
    assert_exactly_one_available(underlying)


@pytest.mark.parametrize("use_lease", [False, True])
def test_original_prelaunch_start_failure_policy_and_identity_remain(monkeypatch, use_lease):
    failure = RuntimeError("inert original start failure")
    _clock, state = scripted_runtime(monkeypatch, start_failure=failure)
    permits, underlying = owned_permits(use_lease)
    with pytest.raises(RuntimeError) as caught:
        candidate._bounded_call(lambda: pytest.fail("callback started"), permits, 1, name="inert-start")
    assert caught.value is failure and state.starts == 1 and state.worker_entries == 0
    assert_exactly_one_available(underlying)


def test_unrenderable_notification_failure_is_reported_and_persisted(monkeypatch, tmp_path):
    owned_threads = []

    class OwnedThreading:
        def __getattr__(self, name):
            return getattr(threading, name)

        def Thread(self, *args, **kwargs):
            worker = threading.Thread(*args, **kwargs)
            owned_threads.append(worker)
            return worker

    class Unrenderable(Exception):
        def __str__(self):
            # Both the notification loop and worker attempt formatting. The
            # original failure survives both attempts without printable text.
            raise self

    class Bus:
        def publish(self, _event):
            raise Unrenderable()

    report_path = tmp_path / "owned-selftest-report.json"
    monkeypatch.setattr(candidate, "threading", OwnedThreading())
    monkeypatch.setattr(candidate, "_failure_log_path", lambda: report_path)
    manager = SimpleNamespace(platform="windows", modules={}, is_enabled=lambda _name: True)
    runner = candidate.SelfTestRunner(manager, Bus())
    runner._pipeline_check = lambda: (True, "inert synthetic pipeline")
    runner._worker_budget = lambda: (1, "inert fixture; no host inventory")
    try:
        report = runner.run(timeout=1)
        assert "[FAIL] Event reporting" in report
        failure = next(row for row in runner.last_failures if row["module"] == "Event reporting")
        assert FALLBACK in failure["detail"]
        saved = json.loads(report_path.read_text(encoding="utf-8"))
        assert any(row["module"] == "Event reporting" for row in saved["failures"])
    finally:
        for worker in owned_threads:
            if worker.ident is not None:
                worker.join(3)
            assert not worker.is_alive(), "owned reporting fixture did not retire"
