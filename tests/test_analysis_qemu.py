"""Supervision contracts use inert adapters; one Windows test exercises Win32."""
from __future__ import annotations

import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import analysis_qemu as qemu

JOB = 'a' * 32
READY = ('ANGERONA_READY:' + JOB + '\r\n').encode()
REPORT = b'ANGERONA_REPORT:{"fixture":true}\r\n'


class Operation:
    def __init__(self):
        self.calls = 0
        self.cancel_at = None

    def check(self):
        self.calls += 1
        if self.calls == self.cancel_at:
            raise InterruptedError('Fixture cancellation')


class FakeNative:
    def __init__(self, image):
        self.image = image
        self.parent = qemu._Identity('fixture-user', 2, 0x2000, False, True, False)
        self.child = self.parent
        self.chunks = [READY, REPORT]
        self.events = []
        self.closed = []
        self.reaped = []
        self.fail = None
        self.stopped = False
        self.actual_pid = 100

    def event(self, name):
        self.events.append(name)
        if self.fail == name:
            raise OSError('Fixture ' + name)

    def identity(self, process=None):
        self.event('parent' if process is None else 'child')
        return self.parent if process is None else self.child

    def system_directory(self):
        return self.image.parent / 'Windows/System32'

    def make_job(self):
        self.event('job')
        return 10

    def pipes(self):
        self.event('pipes')
        return 20, 21, 22, 23

    def create(self, arguments, directory, environment, child_input, child_output):
        self.event('create')
        self.environment = environment
        assert child_input == 20 and child_output == 21
        assert arguments[0] == str(self.image)
        assert directory == self.system_directory()
        return 30, 31, 100

    def assign(self, job, process):
        assert job == 10 and process == 30
        self.event('assign')

    def image_and_pid(self, process):
        assert process == 30
        self.event('image')
        return self.image, self.actual_pid

    def resume(self, thread):
        assert thread == 31
        self.event('resume')
        return 1

    def read(self, handle):
        assert handle == 23
        self.event('read')
        return self.chunks.pop(0) if self.chunks else b''

    def write(self, handle, data):
        assert handle == 22 and data == b'G'
        self.event('GO')

    def exited(self, process):
        assert process == 30
        return self.stopped

    def reap(self, process, job):
        self.reaped.append((process, job))
        self.event('reap')

    def close(self, handle):
        self.closed.append(handle)


@pytest.fixture
def native(tmp_path, monkeypatch):
    monkeypatch.setattr(qemu.time, 'sleep', lambda _seconds: None)
    return FakeNative(tmp_path / 'qemu-system-x86_64.exe')


def run(native, operation=None):
    root = native.image.parent
    argv = qemu.fixed_arguments(root, root / 'kernel', root / 'initrd', JOB)
    return qemu._supervise(native, argv, JOB, operation or Operation())


def assert_reaped(native):
    assert native.reaped == [(30, 10)]
    assert sorted(native.closed) == [10, 20, 21, 22, 23, 30, 31]


def test_fixed_profile_has_no_network_disks_monitor_or_external_options(tmp_path):
    argv = qemu.fixed_arguments(tmp_path, tmp_path / 'kernel', tmp_path / 'initrd', JOB)
    assert argv[0] == str(tmp_path / 'qemu-system-x86_64.exe')
    for key in ('-display', '-monitor', '-nic', '-parallel'):
        assert argv[argv.index(key) + 1] == 'none'
    assert argv[argv.index('-serial') + 1] == 'stdio'
    assert '-nodefaults' in argv and '-no-user-config' in argv
    assert argv[argv.index('-accel') + 1] == 'tcg,thread=single'
    assert argv[argv.index('-bios') + 1] == str(tmp_path / 'share/bios-256k.bin')
    assert not {'-drive', '-blockdev', '-netdev', '-virtfs', '-fsdev', '-readconfig', '-plugin'} & set(argv)


@pytest.mark.parametrize('identity', ['', 'A' * 32, '../x', 'a' * 31, 'a' * 33, None])
def test_invalid_job_identity_rejected(tmp_path, identity):
    with pytest.raises(ValueError, match='identity'):
        qemu.fixed_arguments(tmp_path, tmp_path / 'kernel', tmp_path / 'initrd', identity)


@pytest.mark.parametrize('path', ['relative', '../kernel', '//server/share', 'kernel\n'])
def test_nonlocal_or_relative_paths_rejected(tmp_path, path):
    with pytest.raises(ValueError, match='paths'):
        qemu.fixed_arguments(tmp_path, Path(path), tmp_path / 'initrd', JOB)


def test_limits_and_identity_are_established_before_resume_and_go(native, monkeypatch):
    monkeypatch.setenv('QEMU_MODULE_DIR', 'untrusted')
    monkeypatch.setenv('PATH', 'untrusted')
    assert run(native) == READY + REPORT
    assert native.events[:8] == ['parent', 'job', 'pipes', 'create', 'assign', 'child', 'image', 'resume']
    assert native.events.index('resume') < native.events.index('GO')
    assert native.environment == {
        'SystemRoot': str(native.system_directory().parent),
        'WINDIR': str(native.system_directory().parent),
        'PATH': str(native.system_directory()),
        'GNUTLS_SYSTEM_PRIORITY_FILE': 'NUL', 'OPENSSL_CONF': 'NUL',
        'OPENSSL_MODULES': str(native.image.parent / 'COPYING'),
        'OPENSSL_ENGINES': str(native.image.parent / 'COPYING'),
    }
    assert_reaped(native)


@pytest.mark.parametrize('change', [
    {'elevated': True}, {'integrity': 0x3000}, {'integrity': 0x2100},
    {'primary': False}, {'ui_access': True}, {'session': 0},
])
def test_elevated_or_wrong_parent_authority_never_creates_process(native, change):
    native.parent = replace(native.parent, **change)
    with pytest.raises(ValueError, match='normal'):
        run(native)
    assert native.events == ['parent'] and not native.closed and not native.reaped


@pytest.mark.parametrize('change', [
    {'sid': 'different-user'}, {'session': 1}, {'elevated': True},
    {'integrity': 0x3000}, {'primary': False}, {'ui_access': True},
])
def test_wrong_child_authority_terminated_before_resume(native, change):
    native.child = replace(native.child, **change)
    with pytest.raises(ValueError, match='trusted identity'):
        run(native)
    assert 'resume' not in native.events
    assert_reaped(native)


def test_wrong_pid_terminated_before_resume(native):
    native.actual_pid = 101
    with pytest.raises(ValueError, match='trusted identity'):
        run(native)
    assert 'resume' not in native.events
    assert_reaped(native)


def test_wrong_image_terminated_before_resume(native):
    native.image_and_pid = lambda _process: (native.image.parent / 'other.exe', 100)
    with pytest.raises(ValueError, match='trusted identity'):
        run(native)
    assert 'resume' not in native.events
    assert_reaped(native)


@pytest.mark.parametrize('failure', ['assign', 'child', 'image', 'resume', 'read', 'GO'])
def test_native_failures_always_reap_owned_child(native, failure):
    native.fail = failure
    with pytest.raises(OSError, match='Fixture'):
        run(native)
    assert_reaped(native)


def test_create_failure_releases_job_and_all_pipes(native):
    native.fail = 'create'
    with pytest.raises(OSError):
        run(native)
    assert not native.reaped
    assert sorted(native.closed) == [10, 20, 21, 22, 23]


@pytest.mark.parametrize('cancel_at', [1, 2, 3, 4, 5, 6, 7])
def test_cancellation_at_every_launch_and_handshake_boundary(native, cancel_at):
    operation = Operation()
    operation.cancel_at = cancel_at
    with pytest.raises(InterruptedError):
        run(native, operation)
    if 'create' in native.events:
        assert_reaped(native)
    else:
        assert not native.reaped


@pytest.mark.parametrize('chunks, message', [
    ([REPORT], 'before'), ([READY + REPORT], 'before'),
    ([READY, READY], 'repeated'),
    ([b'ANGERONA_READY:' + b'b' * 32 + b'\n'], 'different'),
    ([READY, b'ANGERONA_ANALYZER_FAILED\n'], 'analyzer failed'),
    ([b'x' * (qemu.MAX_OUTPUT + 1)], '2 MiB'),
])
def test_untrusted_serial_protocol_is_rejected(native, chunks, message):
    native.chunks = chunks
    with pytest.raises(ValueError, match=message):
        run(native)
    assert_reaped(native)


def test_partial_serial_chunks_and_crlf_are_supported(native):
    native.chunks = [READY[:7], READY[7:], REPORT[:11], REPORT[11:]]
    assert run(native) == READY + REPORT
    assert_reaped(native)


def test_startup_deadline_kills_owned_process(native, monkeypatch):
    native.chunks = []
    clock = iter([100, 100, 191])
    monkeypatch.setattr(qemu.time, 'monotonic', lambda: next(clock))
    with pytest.raises(ValueError, match='deadline'):
        run(native)
    assert_reaped(native)


def test_total_deadline_remains_enforced_after_ready(native, monkeypatch):
    native.chunks = [READY]
    clock = iter([100, 100, 401])
    monkeypatch.setattr(qemu.time, 'monotonic', lambda: next(clock))
    with pytest.raises(ValueError, match='deadline'):
        run(native)
    assert 'GO' in native.events
    assert_reaped(native)


def test_unexpected_exit_without_report_is_reaped(native):
    def read(_handle):
        native.stopped = True
        return b''
    native.read = read
    with pytest.raises(ValueError, match='stopped without'):
        run(native)
    assert_reaped(native)


def test_failed_reap_never_returns_a_report_and_still_closes_handles(native):
    native.fail = 'reap'
    with pytest.raises(OSError, match='Fixture reap'):
        run(native)
    assert_reaped(native)


def test_pending_job_termination_access_denied_waits_for_owned_handle():
    native = object.__new__(qemu._Native)
    waits = iter([258, 258, 0])
    terminated = []
    native.event = SimpleNamespace(WaitForSingleObject=lambda _handle, _wait: next(waits))
    native.job = SimpleNamespace(TerminateJobObject=lambda job, _code: terminated.append(job))

    def pending(_process, _code):
        raise PermissionError('Fixture asynchronous termination is pending')

    native.api = SimpleNamespace(TerminateProcess=pending)
    native.reap(30, 10)
    assert terminated == [10]


def test_unsignalled_owned_process_rejects_result_after_termination_attempts():
    native = object.__new__(qemu._Native)
    terminated = []
    native.event = SimpleNamespace(WaitForSingleObject=lambda _handle, _wait: 258)
    native.job = SimpleNamespace(TerminateJobObject=lambda job, _code: terminated.append(('job', job)))
    native.api = SimpleNamespace(TerminateProcess=lambda process, _code: terminated.append(('process', process)))
    with pytest.raises(OSError, match='did not stop'):
        native.reap(30, 10)
    assert terminated == [('job', 10), ('process', 30)]


@pytest.mark.skipif(os.name != 'nt', reason='Native Win32 process and pipe boundary')
def test_native_suspended_process_pipe_allowlist_job_and_reaping():
    native = qemu._Native()
    if not qemu._medium(native.identity()):
        pytest.skip('Requires a medium-integrity interactive Windows session')
    handles = []
    process = job = None
    try:
        job = native.make_job()
        handles.append(job)
        child_input, child_output, parent_input, parent_output = native.pipes()
        handles.extend((child_input, child_output, parent_input, parent_output))
        system = native.system_directory()
        environment = {'SystemRoot': str(system.parent), 'WINDIR': str(system.parent), 'PATH': str(system)}
        # An inert interpreter proves the Win32 contract without any VM, network,
        # privilege change, model load, or source-controlled executable script.
        # Windows venv python.exe is a redirector that spawns a second process;
        # the single-process job correctly forbids that. Use the base image.
        interpreter = Path(getattr(sys, '_base_executable', sys.executable))
        command = [str(interpreter), '-I', '-S', '-c',
                   "import sys; print('native pipe fixture', flush=True); sys.stdin.readline()"]
        process, thread, pid = native.create(command, system, environment, child_input, child_output)
        handles.extend((process, thread))
        native.assign(job, process)
        image, observed_pid = native.image_and_pid(process)
        assert observed_pid == pid and image == interpreter
        assert native.identity(process) == native.identity()
        assert native.process.GetPriorityClass(process) == 0x4000  # BELOW_NORMAL_PRIORITY_CLASS.
        assert native.read(parent_output) == b''  # Suspended child ran no code.
        assert native.resume(thread) == 1
        output = b''
        deadline = time.monotonic() + 5
        while not output and time.monotonic() < deadline:
            output = native.read(parent_output)
            time.sleep(.01)
        assert output.strip() == b'native pipe fixture'
        native.write(parent_input, b'G')
        native.reap(process, job)
        assert native.exited(process)
    finally:
        if process is not None:
            native.reap(process, job)
        for handle in reversed(handles):
            native.close(handle)
