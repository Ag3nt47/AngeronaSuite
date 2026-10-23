"""Exact retained-process retirement after empty-job failure; no PID discovery."""
import io
import json
import os
import subprocess
import time

import pytest

from angerona.core import ugcap_worker as worker
from ugcap_native_observer import ObserverPool, empty_members
from angerona.core.engine_transport import private_directory


class InertProcess:
    def __init__(self, failure=""):
        self.stdin, self.stdout = io.BytesIO(), io.BytesIO()
        self.failure = failure
        self.exited = False
        self.kills, self.polls, self.waits = 0, 0, []

    @property
    def pid(self):
        raise AssertionError("retirement must never resolve a PID")

    def poll(self):
        self.polls += 1
        if self.failure == "poll-initial" or (self.failure == "poll-final" and self.kills):
            raise OSError("PRIVATE_POLL_FAILURE")
        return 1 if self.exited else None

    def kill(self):
        self.kills += 1
        if self.failure == "kill-exception":
            raise OSError("PRIVATE_KILL_FAILURE")
        if self.failure == "kill-baseexception":
            raise BaseException("PRIVATE_KILL_FAILURE")
        self.exited = self.failure not in {"wait-timeout", "wait-exception", "wait-baseexception"}

    def wait(self, timeout):
        self.waits.append(timeout)
        assert 0 <= timeout <= 2
        if self.failure == "wait-exception":
            raise OSError("PRIVATE_WAIT_FAILURE")
        if self.failure == "wait-baseexception":
            raise BaseException("PRIVATE_WAIT_FAILURE")
        if not self.exited:
            raise subprocess.TimeoutExpired("owned-inert-process", timeout)
        return 1


def job(**kwargs):
    return worker._StartupJob(991, kwargs.get("terminate", lambda _h: True),
        kwargs.get("active", lambda _h: 0), kwargs.get('close', lambda _h: True), members=empty_members())


def test_empty_job_zero_cannot_replace_exact_live_process_retirement(tmp_path):
    process, owner = InertProcess(), job()
    instance = worker.UGCAPDaemonClient(tmp_path)
    try:
        assert instance._retire_owned((process, owner, None, None))
        assert owner.confirmed_closed and process.kills == 1 and len(process.waits) == 1
        assert process.exited and process.stdin.closed and process.stdout.closed
        assert not instance.snapshot()["startup_cleanup_pending"]
        instance.close()
        assert process.kills == 1
    finally:
        instance.close()


def test_process_wait_uses_remaining_job_cleanup_grace(tmp_path):
    def active(_handle):
        time.sleep(.03)
        return 0

    process, owner = InertProcess(), job(active=active)
    instance = worker.UGCAPDaemonClient(tmp_path)
    try:
        assert instance._retire_owned((process, owner, None, None))
        assert len(process.waits) == 1 and 0 <= process.waits[0] < 1.99
        assert process.kills == 1 and owner.confirmed_closed
    finally:
        instance.close()


@pytest.mark.parametrize("failure", ["kill-exception", "kill-baseexception", "wait-timeout",
    "wait-exception", "wait-baseexception", "poll-initial", "poll-final"])
def test_unproved_process_retirement_retains_streams_and_blocks_reuse(tmp_path, failure, capsys):
    process, owner, launches = InertProcess(failure), job(), []
    instance = worker.UGCAPDaemonClient(tmp_path, launch_factory=lambda *_a, **_kw: launches.append(True))
    try:
        values = process, owner, None, None
        assert not instance._retire_owned(values)
        assert not owner.confirmed_closed and instance.snapshot()['startup_cleanup_pending']
        assert not process.stdin.closed and not process.stdout.closed
        with pytest.raises(worker.UGCAPWorkerUnavailable, match="cleanup is pending"):
            instance.execute("status", {})
        instance.close()
        assert instance.snapshot()["startup_cleanup_pending"] and not launches
        assert process.kills == (0 if failure == "poll-initial" else 1)
        captured = capsys.readouterr()
        assert "PRIVATE_" not in captured.out + captured.err
    finally:
        # A fresh exact-handle exit observation can complete later cleanup;
        # merely retrying an unknown kill must not issue that kill again.
        process.failure, process.exited = "", True
        instance.close()
    assert not instance.snapshot()["startup_cleanup_pending"]
    assert process.stdin.closed and process.stdout.closed


def test_process_retirement_cannot_switch_to_another_object():
    first, other, owner = InertProcess(), InertProcess(), job()
    assert owner.retire_process(first, .1)
    assert not owner.retire_process(other, .1)
    assert first.kills == 1 and other.kills == other.polls == 0
    for process in (first, other):
        process.stdin.close()
        process.stdout.close()


def test_unknown_job_outcome_still_holds_even_after_owned_process_exit(tmp_path):
    process, owner = InertProcess(), job(terminate=lambda _h: False)
    instance = worker.UGCAPDaemonClient(tmp_path)
    try:
        assert not instance._retire_owned((process, owner, None, None))
        assert process.exited and process.kills == 1 and not owner.confirmed_closed
        assert instance.snapshot()["startup_cleanup_pending"] and not process.stdin.closed
        instance.close()
        assert process.kills == 1 and instance.snapshot()["startup_cleanup_pending"]
    finally:
        # Inert native-job failure stays unknown; never manufacture closure.
        process.stdin.close()
        process.stdout.close()


@pytest.mark.skipif(os.name != "nt", reason="owned CREATE_SUSPENDED Windows assignment refusal")
def test_native_empty_job_assignment_refusal_retires_unassigned_process(tmp_path, monkeypatch):
    from angerona.resilience import _selftest_environment

    processes, identities, owners = [], [], []
    observers = ObserverPool()
    create = worker._create_worker_job

    def launch(command, **kwargs):
        assert kwargs["creationflags"] & getattr(subprocess, "CREATE_SUSPENDED", 0x4)
        process = subprocess.Popen(command, **kwargs)
        processes.append(process)
        identity = observers.pin_handle(int(process._handle))
        identities.append(dict(pid=identity[0], birth_raw=identity[1]))
        return process

    def empty_job():
        owner = create()
        owner._assign = lambda _job, _process: False
        owners.append(owner)
        return owner

    monkeypatch.setattr(worker, "_create_worker_job", empty_job)
    monkeypatch.setattr(_selftest_environment, "_resume_windows_process",
                        lambda _p: pytest.fail("unassigned suspended child resumed"))
    instance = worker.UGCAPDaemonClient(private_directory(tmp_path / "native-unassigned"), launch_factory=launch)
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable):
            instance.execute("status", {})
        assert len(processes) == len(identities) == len(owners) == 1
        assert owners[0].confirmed_closed and owners[0]._process_kill_attempted
        assert processes[0].poll() is not None and not instance.snapshot()["startup_cleanup_pending"]
        identity = identities[0]
        observers.require_retired((identity['pid'], identity['birth_raw']))
        retired = True
        (tmp_path / "owned-unassigned-proof.json").write_text(json.dumps(dict(
            identity_kind="suspended-unassigned-launcher", identity=identity,
            worker_code_executed=False, job_active_zero_confirmed=owners[0]._zero_confirmed,
            job_closed_confirmed=owners[0].confirmed_closed, exact_retired=retired,
            launcher_exit=processes[0].returncode), indent=2) + "\n")
    finally:
        instance.close()
        assert all(process.poll() is not None for process in processes)
        observers.close()
