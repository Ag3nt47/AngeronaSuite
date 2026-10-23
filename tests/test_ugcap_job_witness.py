"""Inert native-contract counterexamples; no OS tool/process is invoked here."""
import io
from types import SimpleNamespace
import time

import pytest

from angerona.core import ugcap_job_witness as witness, ugcap_worker as worker


class API:
    def __init__(self, pids=(11, 12)):
        self.pids = pids
        self.count = len(pids)
        self.handles = {}
        self.opened, self.closed, self.waited = [], [], []
        self.signaled = True
        self.close_outcome = True
        self.member = True

    def snapshot(self, _job):
        return self.count, self.pids

    def total(self, _job):
        return self.count

    def open(self, pid):
        handle = 100 + len(self.opened)
        self.opened.append(handle)
        self.handles[handle] = (pid, pid * 1000)
        return handle

    def identity(self, handle):
        return self.handles[handle]

    def in_job(self, _handle, _job):
        return self.member

    def wait(self, handle, timeout):
        self.waited.append((handle, timeout))
        return self.signaled

    def close(self, handle):
        self.closed.append(handle)
        if isinstance(self.close_outcome, BaseException):
            raise self.close_outcome
        return self.close_outcome


def capture(api):
    proof = witness.JobMemberWitness(api)
    assert proof.capture(9, time.monotonic() + 1)
    return proof


def test_native_job_zero_does_not_replace_member_kernel_signal(tmp_path):
    api = API((11,))
    api.signaled = False
    proof, closes = capture(api), []
    job = worker._StartupJob(9, lambda _h: True, lambda _h: 0,
        lambda h: closes.append(h) or True, members=proof)
    process = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(), poll=lambda: 1)
    client = worker.UGCAPDaemonClient(tmp_path)
    try:
        assert not client._retire_owned((process, job, None, None))
        assert job._zero_confirmed and not job._members_ready and not job.confirmed_closed
        assert not closes and not process.stdin.closed
        assert client.snapshot()['startup_cleanup_pending']
        with pytest.raises(worker.UGCAPWorkerUnavailable, match='cleanup is pending'):
            client.execute('status', {})
        api.signaled = True
    finally:
        client.close()
    assert job.confirmed_closed and closes == [9] and process.stdin.closed
    assert all(record['signaled'] and record['closed'] for record in proof.records.values())


def test_terminal_history_survives_empty_current_list_and_duplicate_capture():
    api = API()
    proof = capture(api)
    assert proof.capture(9, time.monotonic() + 1)
    assert len(proof.records) == 2 and len(api.closed) == 2
    api.pids = ()
    assert proof.capture(9, time.monotonic() + 1)
    assert proof.wait_terminated(time.monotonic() + 1)
    assert len(set(api.closed)) == len(api.closed) == 4
    assert proof.check_total(9)
    before = list(api.closed)
    assert proof.wait_terminated(time.monotonic() + 1)
    assert api.closed == before


def test_spawn_after_capture_before_terminate_latches_unknown_and_keeps_job():
    api, closed = API((11,)), []
    proof = capture(api)

    def terminate(_h):
        api.count += 1
        return True

    job = worker._StartupJob(9, terminate, lambda _h: 0,
        lambda h: closed.append(h) or True, members=proof)
    assert not job.retire(.1) and not job.finalize(.1)
    assert proof.failure == 'member-history-uncovered' and not closed
    # A later empty active list cannot erase an unobserved generation.
    api.pids = ()
    assert not job.retire(.1) and not job.confirmed_closed


@pytest.mark.parametrize('change', ['during-capture', 'departed', 'failed-limit'])
def test_unobserved_lifetime_counter_is_never_credited(change):
    api = API((11,))
    if change == 'during-capture':
        original = api.snapshot
        calls = []

        def snapshot(job):
            calls.append(True)
            if len(calls) == 2:
                api.count = 2
            return original(job)
        api.snapshot = snapshot
    else:
        # TotalProcesses includes departed or failed-association generations;
        # it cannot establish their handle identity from a current PID list.
        api.count = 2
    proof = witness.JobMemberWitness(api)
    assert not proof.capture(9, time.monotonic() + 1)
    assert not proof.check_total(9)
    assert not proof.wait_terminated(time.monotonic() + 1)


@pytest.mark.parametrize('problem', ['vanished', 'access-denied', 'wrong-pid',
    'wrong-birth', 'not-member', 'identity-error', 'baseexception'])
def test_capture_unknown_retains_every_opened_handle(problem):
    api = API((11,))
    if problem in {'vanished', 'access-denied'}:
        def fail(_pid):
            raise OSError('PRIVATE_NATIVE_ERROR')
        api.open = fail
    elif problem == 'wrong-pid':
        api.identity = lambda _h: (12, 11000)
    elif problem == 'wrong-birth':
        api.identity = lambda _h: (11, True)
    elif problem == 'not-member':
        api.member = False
    else:
        def fail(_handle):
            if problem == 'baseexception':
                raise BaseException('PRIVATE_NATIVE_ERROR')
            raise OSError('PRIVATE_NATIVE_ERROR')
        api.identity = fail
    proof = witness.JobMemberWitness(api)
    if problem == 'baseexception':
        with pytest.raises(BaseException, match='PRIVATE_NATIVE_ERROR'):
            proof.capture(9, time.monotonic() + 1)
    else:
        assert not proof.capture(9, time.monotonic() + 1)
    assert not proof.wait_terminated(time.monotonic() + 1)
    assert api.closed == api.opened
    assert 'PRIVATE_' not in str(proof.proof())


@pytest.mark.parametrize('value', [(33, ()), (1, (11, 11)), (0, (11,)),
    (True, ()), (1, (True,)), (1, (0,)), (1, (2**32,)), (1, [11])])
def test_bounded_list_and_counter_rejected_before_open(value):
    api = API(())
    api.snapshot = lambda _j: value
    proof = witness.JobMemberWitness(api)
    assert not proof.capture(9, time.monotonic() + 1) and not api.opened


def test_counter_regression_cannot_restart_lifetime_accounting():
    api = API()
    proof = capture(api)
    api.count, api.pids = 1, (11,)
    assert not proof.capture(9, time.monotonic() + 1)
    assert proof.failure == 'member-counter-regressed'


def test_known_pid_reuse_keeps_both_raw_generations_in_lifetime_history():
    api = API((11,))
    proof = capture(api)
    original_open = api.open

    def open_new(pid):
        handle = original_open(pid)
        api.handles[handle] = (pid, 11001)
        return handle

    api.open, api.count = open_new, 2
    assert proof.capture(9, time.monotonic() + 1)
    assert set(proof.records) == {(11, 11000), (11, 11001)}
    assert proof.wait_terminated(time.monotonic() + 1)
    assert len(api.closed) == len(set(api.closed)) == 2


def test_native_open_requests_only_query_and_synchronize_noninherited():
    calls = []
    api = witness.NativeJobMemberAPI.__new__(witness.NativeJobMemberAPI)
    api.api = SimpleNamespace(OpenProcess=lambda *args: calls.append(args) or 99)
    assert api.open(11) == 99
    assert calls == [(0x00101000, False, 11)]


def test_wait_error_keeps_retained_member_and_sanitizes_failure():
    api = API((11,))
    proof = capture(api)

    def fail(_handle, _timeout):
        raise OSError('PRIVATE_WAIT_DETAIL')

    api.wait = fail
    assert not proof.wait_terminated(time.monotonic() + 1)
    assert not api.closed and proof.records[(11, 11000)]['handle'] == 100
    assert 'PRIVATE_' not in str(proof.proof())


@pytest.mark.parametrize('close', [False, None, BaseException('PRIVATE_CLOSE')])
def test_member_unknown_close_consumes_once_and_refuses_reuse(close):
    api = API((11,))
    proof = capture(api)
    api.close_outcome = close
    assert not proof.wait_terminated(time.monotonic() + 1)
    assert api.closed == [100] and proof.records[(11,11000)]['handle'] is None
    assert not proof.wait_terminated(time.monotonic() + 1) and api.closed == [100]
    assert not proof.capture(9, time.monotonic() + 1)


def test_retained_identity_change_blocks_signal_and_close():
    api = API((11,))
    proof = capture(api)
    api.handles[100] = (11, 11001)
    assert not proof.wait_terminated(time.monotonic() + 1)
    assert not api.waited and not api.closed


def test_shared_deadline_is_not_renewed_per_member(monkeypatch):
    api = API()
    proof = capture(api)
    now = [0.0]
    monkeypatch.setattr(witness, 'time', SimpleNamespace(monotonic=lambda: now[0]))

    def wait(handle, timeout):
        api.waited.append((handle, timeout))
        now[0] += .06
        return True

    api.wait = wait
    assert not proof.wait_terminated(.1)
    assert api.waited[0][1] == pytest.approx(.1)
    assert api.waited[1][1] == pytest.approx(.04)
    assert proof.wait_terminated(.2)


def test_expired_capture_never_opens_a_member(monkeypatch):
    api = API()
    proof = witness.JobMemberWitness(api)
    monkeypatch.setattr(witness, 'time', SimpleNamespace(monotonic=lambda: 5))
    assert not proof.capture(9, 5) and not api.opened


def test_missing_witness_is_held_instead_of_an_empty_job_fallback():
    closes = []
    job = worker._StartupJob(9, lambda _h: True, lambda _h: 0, lambda h: closes.append(h) or True)
    assert not job.retire(.1) and not job.finalize(.1) and not closes


def test_job_close_waits_for_exact_process_and_startup_io(tmp_path):
    api, closes, joined = API((11,)), [], [False]
    proof = capture(api)
    job = worker._StartupJob(9, lambda _h: True, lambda _h: 0,
        lambda h: closes.append(h) or True, members=proof)
    process = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(), poll=lambda: 1)
    io_owner = SimpleNamespace(cancel=lambda: None, join=lambda _t: joined[0])
    client = worker.UGCAPDaemonClient(tmp_path)
    try:
        assert not client._retire_owned((process, job, None, io_owner))
        assert job._members_ready and not closes and not job.confirmed_closed
        joined[0] = True
    finally:
        client.close()
    assert closes == [9] and job.confirmed_closed
