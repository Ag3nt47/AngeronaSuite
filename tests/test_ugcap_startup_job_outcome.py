"""Whole-job retirement evidence and ownership; fake APIs except one owned child."""
import io
import json
import os
import subprocess
import threading
from types import SimpleNamespace

import pytest

from angerona.core import ugcap_worker as worker
from ugcap_native_observer import ObserverPool, empty_members
from angerona.core.engine_transport import private_directory


def _process(poll=lambda: 0):
    return SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(), poll=poll)


def _job(*, handle=991, terminate=lambda _h: True, active=lambda _h: 0, close=lambda _h: True):
    return worker._StartupJob(handle, terminate, active, close, members=empty_members())


def test_poll_exception_keeps_custody_after_job_zero_and_close(tmp_path):
    closes, launches = [], []
    exited = [False]

    def poll():
        if not exited[0]:
            raise OSError("PRIVATE_POLL_EXCEPTION")
        return 0

    process = _process(poll)
    job = _job(close=lambda handle: closes.append(handle) or True)
    owner = SimpleNamespace(cancel=lambda: None, join=lambda _timeout: True)
    instance = worker.UGCAPDaemonClient(tmp_path, launch_factory=lambda *_a, **_kw: launches.append(True))
    try:
        assert not instance._retire_owned((process, job, None, owner))
        assert instance.snapshot()["startup_cleanup_pending"]
        assert not process.stdin.closed and not process.stdout.closed
        with pytest.raises(worker.UGCAPWorkerUnavailable, match="cleanup is pending"):
            instance.execute("status", {})
        assert closes == [] and not launches
    finally:
        exited[0] = True
        instance.close()
    assert not instance.snapshot()["startup_cleanup_pending"]
    assert process.stdin.closed and process.stdout.closed and closes == [991]


def test_async_job_members_remain_owned_until_observed_zero():
    queried, release = threading.Event(), threading.Event()
    order, results = [], []

    def active(handle):
        order.append(("query", handle))
        queried.set()
        return 0 if release.is_set() else 2

    job = _job(terminate=lambda h: order.append(("terminate", h)) or True,
               active=active, close=lambda h: order.append(("close", h)) or True)
    thread = threading.Thread(target=lambda: results.append(job.retire(3)), name="inert-job-retirement")
    try:
        thread.start()
        assert queried.wait(3)
        assert not job.confirmed_closed
        assert not any(kind == "close" for kind, _ in order)
        release.set()
        thread.join(3)
        assert not thread.is_alive() and results == [True] and not job.confirmed_closed
        assert not any(kind == 'close' for kind, _ in order)
        assert job.finalize(.1) and job.confirmed_closed
        assert order[0] == ("terminate", 991) and order[-1] == ("close", 991)
        assert sum(kind == "terminate" for kind, _ in order) == 1
        assert sum(kind == "close" for kind, _ in order) == 1
        assert job.retire(0) and order[-1] == ("close", 991)
    finally:
        release.set()
        if thread.ident is not None:
            thread.join(3)
        assert not thread.is_alive()


def test_active_job_timeout_retains_handle_and_refuses_new_launch(tmp_path):
    current, calls, launches = [1], [], []
    process = _process()
    job = _job(terminate=lambda h: calls.append(("terminate", h)) or True,
               active=lambda h: calls.append(("query", h)) or current[0],
               close=lambda h: calls.append(("close", h)) or True)
    owner = SimpleNamespace(cancel=lambda: None, join=lambda _timeout: True)
    instance = worker.UGCAPDaemonClient(tmp_path, launch_factory=lambda *_a, **_kw: launches.append(True))
    try:
        assert not job.retire(.02)
        assert job._handle == 991 and not job.confirmed_closed
        # An immediate timeout uses the actual client cleanup with no fake
        # process or OS cleanup callback substituted.
        original = job.retire
        job.retire = lambda _timeout: original(0)
        assert not instance._retire_owned((process, job, None, owner))
        assert instance.snapshot()["startup_cleanup_pending"]
        assert not any(kind == "close" for kind, _ in calls)
        with pytest.raises(worker.UGCAPWorkerUnavailable, match="cleanup is pending"):
            instance.execute("status", {})
        assert not launches and not process.stdin.closed
    finally:
        current[0] = 0
        job.retire = original
        instance.close()
    assert job.confirmed_closed and process.stdin.closed and process.stdout.closed
    assert sum(kind == "terminate" for kind, _ in calls) == 1
    assert sum(kind == "close" for kind, _ in calls) == 1


@pytest.mark.parametrize("outcome", [False, None, "exception"])
def test_terminate_failure_keeps_live_job_and_never_queries_or_closes(outcome):
    calls = []

    def terminate(handle):
        calls.append(("terminate", handle))
        if outcome == "exception":
            raise BaseException("PRIVATE_TERMINATE_EXCEPTION")
        return outcome

    job = _job(terminate=terminate,
               active=lambda h: calls.append(("query", h)) or 0,
               close=lambda h: calls.append(("close", h)) or True)
    assert not job.retire(.01) and not job.retire(.01)
    assert calls == [("terminate", 991)]
    assert not job.confirmed_closed and job._handle == 991


@pytest.mark.parametrize("outcome", [None, True, -1, "exception"])
def test_unknown_job_count_never_authorizes_close_and_can_be_requeried(outcome):
    state, calls = [outcome], []

    def active(handle):
        calls.append(("query", handle))
        if state[0] == "exception":
            raise OSError("PRIVATE_QUERY_EXCEPTION")
        return state[0]

    job = _job(terminate=lambda h: calls.append(("terminate", h)) or True,
               active=active, close=lambda h: calls.append(("close", h)) or True)
    assert not job.retire(.01)
    assert not job.confirmed_closed and job._handle == 991
    assert not any(kind == "close" for kind, _ in calls)
    state[0] = 0
    assert job.retire(.01) and not job.confirmed_closed
    assert job.finalize(.1) and job.confirmed_closed
    assert sum(kind == "terminate" for kind, _ in calls) == 1
    assert sum(kind == "close" for kind, _ in calls) == 1


@pytest.mark.parametrize("outcome", [False, None, "exception"])
def test_close_unknown_consumes_handle_once_and_remains_pending(tmp_path, outcome):
    calls, launches = [], []

    def close(handle):
        calls.append(("close", handle))
        if outcome == "exception":
            raise BaseException("PRIVATE_CLOSE_EXCEPTION")
        return outcome

    job = _job(terminate=lambda h: calls.append(("terminate", h)) or True,
               active=lambda h: calls.append(("query", h)) or 0, close=close)
    process = _process()
    instance = worker.UGCAPDaemonClient(tmp_path, launch_factory=lambda *_a, **_kw: launches.append(True))
    try:
        values = process, job, None, None
        assert not instance._retire_owned(values)
        before = list(calls)
        assert not instance._retire_owned(values) and calls == before
        assert job._zero_confirmed and job._close_attempted and job._handle is None
        assert not job.confirmed_closed and not process.stdin.closed
        with pytest.raises(worker.UGCAPWorkerUnavailable, match="cleanup is pending"):
            instance.execute("status", {})
        instance.close()
        assert calls == before and not launches and instance.snapshot()["startup_cleanup_pending"]
    finally:
        process.stdin.close()
        process.stdout.close()


def test_cleanup_callback_baseexception_is_sanitized_and_retained(tmp_path, monkeypatch, capsys):
    instance = worker.UGCAPDaemonClient(tmp_path)
    process = _process()
    values = process, None, None, None

    def fail(*_args):
        raise BaseException("PRIVATE_CLEANUP_EXCEPTION")

    monkeypatch.setattr(instance, "_stop_owned", fail)
    try:
        assert not instance._retire_owned(values)
        assert instance.snapshot()["startup_cleanup_pending"]
        instance.close()
        captured = capsys.readouterr()
        assert "PRIVATE_CLEANUP_EXCEPTION" not in captured.out + captured.err
        assert not process.stdin.closed and not process.stdout.closed
    finally:
        process.stdin.close()
        process.stdout.close()


def test_job_zero_cleanup_requires_no_guessed_executing_pid(tmp_path):
    class NoPid:
        stdin, stdout = io.BytesIO(), io.BytesIO()

        @property
        def pid(self):
            raise AssertionError("cleanup guessed an executing PID")

        def poll(self):
            return 0

    process, job = NoPid(), _job()
    instance = worker.UGCAPDaemonClient(tmp_path)
    try:
        assert instance._retire_owned((process, job, None, None))
        assert job.confirmed_closed and process.stdin.closed and process.stdout.closed
        assert not instance.snapshot()["startup_cleanup_pending"]
    finally:
        instance.close()


@pytest.mark.skipif(os.name != "nt", reason="actual owned suspended Windows child/job")
def test_native_early_cancel_before_resume_proves_zero_without_child_code(tmp_path, monkeypatch):
    from angerona.resilience import _selftest_environment

    processes, identities, jobs = [], [], []
    observers = ObserverPool()
    create = worker._create_worker_job

    def launch(command, **kwargs):
        process = subprocess.Popen(command, **kwargs)
        processes.append(process)
        identity = observers.pin_handle(int(process._handle))
        identities.append(dict(pid=identity[0], birth_raw=identity[1]))
        return process

    def capture():
        job = create()
        jobs.append(job)
        return job

    def refuse_resume(_process):
        raise OSError("inert cancellation before any Python child code")

    monkeypatch.setattr(worker, "_create_worker_job", capture)
    monkeypatch.setattr(_selftest_environment, "_resume_windows_process", refuse_resume)
    instance = worker.UGCAPDaemonClient(private_directory(tmp_path / "native-owned"), launch_factory=launch)
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable):
            instance.execute("status", {})
        assert len(processes) == len(jobs) == len(identities) == 1
        assert jobs[0].confirmed_closed and processes[0].poll() is not None
        assert not instance.snapshot()["startup_cleanup_pending"]
        identity = identities[0]
        observers.require_retired((identity['pid'], identity['birth_raw']))
        retired = True
        (tmp_path / "owned-early-cancel-proof.json").write_text(json.dumps({
            "identity_kind": "suspended-launcher", "identity": identity,
            "worker_code_executed": False, "job_active_zero_confirmed": jobs[0]._zero_confirmed,
            "job_closed_confirmed": jobs[0].confirmed_closed, "exact_retired": retired,
            "launcher_exit": processes[0].returncode,
        }, indent=2) + "\n")
    finally:
        instance.close()
        assert all(process.poll() is not None for process in processes)
        observers.close()


def test_auxiliary_close_failure_cannot_skip_job_termination_or_credit_cleanup(tmp_path):
    calls = []
    failed = [True]

    def close_pipe():
        if failed[0]:
            raise BaseException("PRIVATE_PIPE_CLOSE_FAILURE")

    process = _process()
    pipe = SimpleNamespace(close=close_pipe)
    job = _job(terminate=lambda h: calls.append(("terminate", h)) or True,
               active=lambda h: calls.append(("query", h)) or 0,
               close=lambda h: calls.append(("close", h)) or True)
    instance = worker.UGCAPDaemonClient(tmp_path)
    try:
        assert not instance._retire_owned((process, job, pipe, None))
        assert not job.confirmed_closed and calls == [('terminate', 991), ('query', 991)]
        assert instance.snapshot()["startup_cleanup_pending"] and not process.stdin.closed
        failed[0] = False
    finally:
        instance.close()
    assert not instance.snapshot()["startup_cleanup_pending"]
    assert process.stdin.closed and process.stdout.closed
    assert calls == [('terminate', 991), ('query', 991), ('query', 991), ('query', 991), ('close', 991)]


@pytest.mark.skipif(os.name != "nt", reason="Windows creation-before-assignment ownership path")
@pytest.mark.parametrize("outcome", [False, "exception"])
def test_assignment_failure_is_already_owned_and_never_resumes(tmp_path, monkeypatch, outcome):
    from angerona.resilience import _selftest_environment

    calls = []

    def attach(handle, process_handle):
        calls.append(("assign", handle, process_handle))
        if outcome == "exception":
            raise OSError("PRIVATE_ASSIGN_EXCEPTION")
        return False

    class LiveSuspendedProcess:
        _handle = 123

        def __init__(self):
            self.stdin, self.stdout = io.BytesIO(), io.BytesIO()
            self.exited = False

        @property
        def pid(self):
            raise AssertionError("unassigned cleanup resolved a PID")

        def poll(self):
            return 1 if self.exited else None

        def kill(self):
            calls.append(("kill", self._handle))
            self.exited = True

        def wait(self, timeout):
            calls.append(("wait", timeout))
            assert 0 <= timeout <= 2
            assert self.exited
            return 1

    process = LiveSuspendedProcess()
    job = worker._StartupJob(991, lambda h: calls.append(("terminate", h)) or True,
        lambda h: calls.append(("query", h)) or 0,
        lambda h: calls.append(('close', h)) or True, assign=attach, members=empty_members())
    monkeypatch.setattr(worker, "_create_worker_job", lambda: job)
    monkeypatch.setattr(_selftest_environment, "_resume_windows_process",
                        lambda _process: pytest.fail("unassigned child resumed"))
    instance = worker.UGCAPDaemonClient(private_directory(tmp_path / "inert-owned"),
                                       launch_factory=lambda *_a, **_kw: process)
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable) as error:
            instance.execute("status", {})
        assert "PRIVATE_ASSIGN_EXCEPTION" not in str(error.value)
        assert calls[:4] == [('assign', 991, 123), ('terminate', 991), ('query', 991), ('kill', 123)]
        assert len(calls) == 7 and calls[4][0] == 'wait'
        assert calls[-2:] == [('query', 991), ('close', 991)]
        assert job.confirmed_closed and not instance.snapshot()["startup_cleanup_pending"]
        assert process.stdin.closed and process.stdout.closed
    finally:
        instance.close()
    assert sum(call[0] == "kill" for call in calls) == 1
