"""Exact-generation IO ownership controls; no vault, native child or response."""
import io
import os
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import ugcap_worker as worker
from ugcap_native_observer import empty_members


def _threaded_perform(owner, operation):
    results, errors = [], []

    def run():
        try:
            results.append(owner.perform(operation, time.monotonic() + 5))
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run, name="inert-startup-caller")
    return thread, results, errors


def _retire(owner, threads, release=()):
    owner.cancel()
    for event in release:
        event.set()
    for thread in threads:
        if thread.ident is not None:
            thread.join(5)
        assert not thread.is_alive()
    assert owner.join(2)


@pytest.mark.skipif(os.name != "nt", reason="native exact Windows thread handles")
def test_each_native_worker_handle_closes_once_after_retirement(monkeypatch):
    retain, close = worker._retain_startup_thread, worker._close_startup_thread
    retained, closed = [], []

    def capture():
        handle = retain()
        retained.append(handle)
        return handle

    def release(handle):
        if handle is not None:
            closed.append(handle)
        return close(handle)

    monkeypatch.setattr(worker, "_retain_startup_thread", capture)
    monkeypatch.setattr(worker, "_close_startup_thread", release)
    owner = worker._StartupIO()
    try:
        assert owner.perform(lambda: 41, time.monotonic() + 5) == 41
        assert owner.perform(lambda: 42, time.monotonic() + 5) == 42
        assert len(retained) == 2 and closed == retained
        owner.cancel()
        assert owner.join(0) and closed == retained
    finally:
        _retire(owner, [])


def test_cancellation_uses_retained_handle_without_thread_id_lookup(monkeypatch):
    held, finish = threading.Event(), threading.Event()
    cancelled, closed = [], []
    monkeypatch.setattr(worker, "_retain_startup_thread", lambda: 111)
    monkeypatch.setattr(worker, "_cancel_startup_thread", lambda handle: cancelled.append(handle))
    monkeypatch.setattr(worker, "_startup_thread_finished", lambda *_args: True)
    monkeypatch.setattr(worker, "_close_startup_thread", lambda handle: closed.append(handle) or True)

    def no_thread_id(_self):
        raise AssertionError("cancellation attempted a reusable thread-ID lookup")

    monkeypatch.setattr(threading.Thread, "native_id", property(no_thread_id))
    owner = worker._StartupIO()

    def operation():
        held.set()
        assert finish.wait(5)
        return "done"

    thread, results, errors = _threaded_perform(owner, operation)
    try:
        thread.start()
        assert held.wait(5)
        owner.cancel()
        assert cancelled and set(cancelled) == {111}
        finish.set()
        thread.join(5)
        assert not thread.is_alive() and not errors and results == ["done"]
        assert closed == [111]
    finally:
        _retire(owner, [thread], (finish,))


def test_cancel_before_handle_publication_never_runs_operation(monkeypatch):
    entering, publish = threading.Event(), threading.Event()
    operations, closed = [], []

    def retain():
        entering.set()
        assert publish.wait(5)
        return 222

    monkeypatch.setattr(worker, "_retain_startup_thread", retain)
    monkeypatch.setattr(worker, "_cancel_startup_thread", lambda _handle: None)
    monkeypatch.setattr(worker, "_startup_thread_finished", lambda *_args: True)
    monkeypatch.setattr(worker, "_close_startup_thread", lambda handle: closed.append(handle) or True)
    owner = worker._StartupIO()
    thread, _results, errors = _threaded_perform(owner, lambda: operations.append(True))
    try:
        thread.start()
        assert entering.wait(5)
        owner.cancel()
        publish.set()
        thread.join(5)
        assert not thread.is_alive() and len(errors) == 1 and isinstance(errors[0], OSError)
        assert not operations and closed == [222]
    finally:
        _retire(owner, [thread], (publish,))


def test_missing_thread_custody_never_performs_io_or_leaks_error(monkeypatch, capsys):
    operations, unhandled = [], []
    marker = "PRIVATE_DUPLICATE_FAILURE"

    def unavailable():
        raise OSError(marker)

    monkeypatch.setattr(worker, "_retain_startup_thread", unavailable)
    monkeypatch.setattr(threading, "excepthook", lambda value: unhandled.append(value))
    owner = worker._StartupIO()
    try:
        with pytest.raises(OSError) as failure:
            owner.perform(lambda: operations.append(True), time.monotonic() + 5)
        captured = capsys.readouterr()
        assert not operations and not unhandled
        assert marker not in str(failure.value) + captured.out + captured.err
    finally:
        _retire(owner, [])


def test_expired_deadline_refuses_before_thread_start(monkeypatch):
    starts = []

    def forbidden(_self):
        starts.append(True)
        raise AssertionError("expired startup issued a thread")

    monkeypatch.setattr(threading.Thread, "start", forbidden)
    owner = worker._StartupIO()
    with pytest.raises(TimeoutError):
        owner.perform(lambda: pytest.fail("expired operation"), time.monotonic() - 1)
    assert not starts and owner._workers == []
    assert owner.join(0)


def test_custom_baseexception_is_sanitized_without_thread_trace(monkeypatch, capsys):
    class PrivateFailure(BaseException):
        pass

    unhandled = []
    monkeypatch.setattr(threading, "excepthook", lambda value: unhandled.append(value))
    marker = "PRIVATE_BASEEXCEPTION_TEXT"

    def fail():
        raise PrivateFailure(marker)

    owner = worker._StartupIO()
    try:
        with pytest.raises(OSError) as failure:
            owner.perform(fail, time.monotonic() + 5)
        captured = capsys.readouterr()
        assert not unhandled and marker not in str(failure.value) + captured.out + captured.err
    finally:
        _retire(owner, [])


def test_io_retirement_retries_consume_job_close_authority_once(monkeypatch, tmp_path):
    from angerona.resilience import _selftest_environment
    closes, attempts = [], [False, False, True]

    def stop(_process, raw_job):
        if raw_job is not None:
            handle, close = raw_job
            close(handle)

    monkeypatch.setattr(_selftest_environment, "_stop_process_custody", stop)
    streams = [io.BytesIO(), io.BytesIO()]
    process = SimpleNamespace(stdin=streams[0], stdout=streams[1], poll=lambda: 0)
    job = worker._StartupJob(333, lambda _handle: True, lambda _handle: 0, lambda handle: closes.append(handle) or True, members=empty_members())
    owner = SimpleNamespace(cancel=lambda: None, join=lambda _timeout: attempts.pop(0))
    instance = worker.UGCAPDaemonClient(tmp_path)
    values = process, job, None, owner
    assert not instance._retire_owned(values)
    assert not instance._retire_owned(values)
    assert closes == [] and not any(stream.closed for stream in streams)
    assert instance.snapshot()["startup_cleanup_pending"]
    assert instance._retire_owned(values)
    assert closes == [333] and all(stream.closed for stream in streams)
    instance.close()
    assert closes == [333]


@pytest.mark.parametrize("failure", ["live", "unknown"])
def test_unproved_process_exit_retains_streams_and_refuses_reuse(monkeypatch, tmp_path, failure):
    from angerona.resilience import _selftest_environment
    monkeypatch.setattr(_selftest_environment, "_stop_process_custody", lambda *_args: None)
    exited = [False]

    def poll():
        if exited[0]:
            return 0
        if failure == "unknown":
            raise OSError("unavailable")
        return None

    streams = [io.BytesIO(), io.BytesIO()]
    process = SimpleNamespace(stdin=streams[0], stdout=streams[1], poll=poll)
    owner = SimpleNamespace(cancel=lambda: None, join=lambda _timeout: True)
    instance = worker.UGCAPDaemonClient(tmp_path, launch_factory=lambda *_a, **_kw: pytest.fail("new launch"))
    try:
        assert not instance._retire_owned((process, None, None, owner))
        assert instance.snapshot()["startup_cleanup_pending"]
        assert not any(stream.closed for stream in streams)
        with pytest.raises(worker.UGCAPWorkerUnavailable, match="cleanup is pending"):
            instance.execute("status", {})
    finally:
        exited[0] = True
        instance.close()
    assert not instance.snapshot()["startup_cleanup_pending"]
    assert all(stream.closed for stream in streams)


def test_python_thread_exit_without_native_completion_retains_handle(monkeypatch):
    native_done, closed = [False], []
    monkeypatch.setattr(worker, "_retain_startup_thread", lambda: 444)
    monkeypatch.setattr(worker, "_cancel_startup_thread", lambda _handle: None)
    monkeypatch.setattr(worker, "_startup_thread_finished", lambda *_args: native_done[0])
    monkeypatch.setattr(worker, "_close_startup_thread", lambda handle: closed.append(handle) or True)
    owner = worker._StartupIO()
    try:
        with pytest.raises(TimeoutError):
            owner.perform(lambda: "done", time.monotonic() + 5)
        assert not closed and not owner.join(0)
        native_done[0] = True
        assert owner.join(1) and closed == [444]
        assert owner.join(0) and closed == [444]
    finally:
        _retire(owner, [])


def test_cancellation_and_handle_close_cannot_race_reused_numeric_handle(monkeypatch):
    closing, finish_close, cancelled_done = threading.Event(), threading.Event(), threading.Event()
    cancellations, closes = [], []
    monkeypatch.setattr(worker, "_retain_startup_thread", lambda: 555)
    monkeypatch.setattr(worker, "_cancel_startup_thread", lambda handle: cancellations.append(handle))
    monkeypatch.setattr(worker, "_startup_thread_finished", lambda *_args: True)

    def close(handle):
        closes.append(handle)
        closing.set()
        assert finish_close.wait(5)
        return True

    monkeypatch.setattr(worker, "_close_startup_thread", close)
    owner = worker._StartupIO()
    thread, results, errors = _threaded_perform(owner, lambda: "done")

    def cancel():
        owner.cancel()
        cancelled_done.set()

    cancellation = threading.Thread(target=cancel, name="inert-startup-cancel")
    try:
        thread.start()
        assert closing.wait(5)
        cancellation.start()
        assert not cancelled_done.wait(.05)
        assert not cancellations
        finish_close.set()
        assert cancelled_done.wait(5)
        thread.join(5)
        assert not thread.is_alive() and not errors and results == ["done"]
        assert closes == [555] and not cancellations
    finally:
        finish_close.set()
        _retire(owner, [thread, cancellation])


@pytest.mark.parametrize("outcome", [False, None, "exception"])
def test_unknown_thread_close_consumes_numeric_handle_and_latches_pending(monkeypatch, outcome, capsys):
    closes, cancellations, unhandled = [], [], []
    monkeypatch.setattr(worker, "_retain_startup_thread", lambda: 777)
    monkeypatch.setattr(worker, "_startup_thread_finished", lambda *_args: True)
    monkeypatch.setattr(worker, "_cancel_startup_thread", lambda handle: cancellations.append(handle))
    monkeypatch.setattr(threading, "excepthook", lambda value: unhandled.append(value))

    def close(handle):
        closes.append(handle)
        if outcome == "exception":
            raise BaseException("PRIVATE_THREAD_CLOSE_EXCEPTION")
        return outcome

    monkeypatch.setattr(worker, "_close_startup_thread", close)
    owner = worker._StartupIO()
    try:
        with pytest.raises(TimeoutError) as failure:
            owner.perform(lambda: "inert result", time.monotonic() + 3)
        assert closes == [777] and owner._workers[0]["handle"] is None
        assert owner._workers[0]["close_outcome"] is False
        assert not owner.join(0) and not owner.join(.01)
        owner.cancel()
        assert not owner.join(.01) and closes == [777] and not cancellations
        assert not any(record["thread"].is_alive() for record in owner._workers)
        captured = capsys.readouterr()
        assert not unhandled
        assert "PRIVATE_THREAD_CLOSE_EXCEPTION" not in str(failure.value) + captured.out + captured.err
    finally:
        owner.cancel()
        for record in owner._workers:
            record["thread"].join(3)
            assert not record["thread"].is_alive()
        # The inert native-close outcome deliberately stays unknown. No second
        # close is issued merely to make this pending-state test green.
        assert not owner.join(0) and closes == [777]
