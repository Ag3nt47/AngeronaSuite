"""Legacy VMX and current QEMU boot-input custody use only disposable fixtures."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sys
from types import SimpleNamespace

import pytest

from angerona.core import analysis_vmware as vmware, tool_analysis_jobs as jobs


def _profile(tmp_path):
    identity = 'a' * 32
    directory = tmp_path / identity
    directory.mkdir()
    path = directory / 'analysis.vmx'
    path.write_bytes(vmware.configuration(identity).encode())
    return directory, identity, path


@pytest.mark.parametrize('before,after', [
    ('ide0:0.fileName = "boot.iso"', 'ide0:0.fileName = "alternate.iso"'),
    ('ethernet0.present = "FALSE"', 'ethernet0.present = "TRUE"'),
    ('sharedFolder.maxNum = "0"', 'sharedFolder.maxNum = "1"'),
])
def test_changed_boot_or_device_profile_is_refused(tmp_path, before, after):
    directory, identity, path = _profile(tmp_path)
    path.write_text(path.read_text().replace(before, after), encoding='utf-8')
    with pytest.raises(ValueError, match='fixed reviewed profile'):
        with vmware.sealed_configuration(directory, identity):
            pytest.fail('mutable profile was admitted')


def test_existing_local_hardlink_alias_is_refused(tmp_path):
    directory, identity, path = _profile(tmp_path)
    os.link(path, tmp_path / 'alias.vmx')
    with pytest.raises(ValueError, match='identity or local alias'):
        with vmware.sealed_configuration(directory, identity):
            pytest.fail('aliased profile was admitted')


@pytest.mark.skipif(os.name != 'nt', reason='Windows deny-write/delete sharing')
def test_retained_windows_vmx_handle_blocks_overwrite_and_replacement(tmp_path):
    directory, identity, path = _profile(tmp_path)
    replacement = tmp_path / 'replacement.vmx'
    replacement.write_text('unreviewed configuration', encoding='utf-8')
    expected = path.read_bytes()
    with vmware.sealed_configuration(directory, identity) as verify:
        with pytest.raises(PermissionError):
            path.write_bytes(b'unreviewed configuration')
        with pytest.raises(PermissionError):
            os.replace(replacement, path)
        with pytest.raises(PermissionError):
            path.unlink()
        verify()
        assert path.read_bytes() == expected
    # The lease closes its handle after the lifecycle, including verification.
    path.write_bytes(expected)


@pytest.mark.parametrize('replace', [False, True])
def test_identity_and_bytes_are_rechecked_even_if_seal_is_defective(tmp_path, monkeypatch, replace):
    directory, identity, path = _profile(tmp_path)
    original = path.stat()
    real_fstat = os.fstat
    monkeypatch.setattr(vmware.os, 'fstat', lambda fd: original if fd == -471 else real_fstat(fd))

    @contextlib.contextmanager
    def deliberately_unsealed(candidate):
        # Model a broken custody primitive to exercise independent rechecks.
        # Preserve the initial identity without a real Windows sharing lock.

        class ReadAgain:
            def fileno(self):
                return -471

            def seek(self, *_args):
                pass

            def read(self, length):
                return candidate.read_bytes()[:length]

        yield ReadAgain()

    monkeypatch.setattr(vmware, '_open_sealed', deliberately_unsealed)
    with pytest.raises(ValueError, match='identity|fixed reviewed profile'):
        with vmware.sealed_configuration(directory, identity) as verify:
            if replace:
                replacement = tmp_path / 'other.vmx'
                replacement.write_bytes(path.read_bytes())
                os.replace(replacement, path)
            else:
                path.write_bytes(b'changed devices')
            verify()


def _fake_supervisor_environment(monkeypatch, identity, checks, *, fail_check=None):
    controls, writes, closed = [], [], []

    class NativeError(Exception):
        pass

    handle = lambda name: SimpleNamespace(Close=lambda: closed.append(name))
    monkeypatch.setitem(sys.modules, 'pywintypes', SimpleNamespace(
        SECURITY_ATTRIBUTES=lambda: SimpleNamespace(), error=NativeError,
    ))
    monkeypatch.setitem(sys.modules, 'win32api', SimpleNamespace(GetCurrentProcess=lambda: 1))
    chunks = iter([
        ('ANGERONA_READY:' + identity + '\n').encode(),
        b'ANGERONA_REPORT:{}\n',
    ])
    monkeypatch.setitem(sys.modules, 'win32file', SimpleNamespace(
        ReadFile=lambda *_a: (0, next(chunks)),
        WriteFile=lambda _pipe, value: writes.append(value),
    ))
    monkeypatch.setitem(sys.modules, 'win32pipe', SimpleNamespace(
        PIPE_ACCESS_DUPLEX=1, PIPE_TYPE_BYTE=0, PIPE_NOWAIT=1,
        CreateNamedPipe=lambda *_a: handle('pipe'), ConnectNamedPipe=lambda *_a: None,
    ))
    monkeypatch.setitem(sys.modules, 'win32security', SimpleNamespace(
        OpenProcessToken=lambda *_a: handle('token'),
        ConvertSidToStringSid=lambda *_a: 'S-1-5-21-fixture',
        GetTokenInformation=lambda *_a: ['sid'],
        ConvertStringSecurityDescriptorToSecurityDescriptor=lambda *_a: 'acl',
    ))
    monkeypatch.setattr(vmware, 'service_ready', lambda: None)
    monkeypatch.setattr(vmware, 'trusted_installation', lambda: contextlib.nullcontext('installation'))
    monkeypatch.setattr(vmware, '_control', lambda _d, verb, *_a, **_kw: controls.append(verb))
    monkeypatch.setattr(vmware, '_client_job', lambda *_a: handle('job'))
    monkeypatch.setattr(vmware.time, 'sleep', lambda *_a: None)
    active = []

    @contextlib.contextmanager
    def lease(*_args):
        active.append(True)

        def verify():
            assert active
            checks.append('verify')
            if len(checks) == fail_check:
                raise ValueError('configuration custody changed')

        try:
            yield verify
        finally:
            assert not controls or controls[-1] == 'stop'
            active.pop()

    monkeypatch.setattr(vmware, 'sealed_configuration', lease)
    return controls, writes, closed


@pytest.mark.parametrize('fail_check', [1, 2, 3])
def test_supervisor_rejects_failed_custody_before_start_go_or_report(tmp_path, monkeypatch, fail_check):
    identity = 'a' * 32
    checks = []
    controls, writes, closed = _fake_supervisor_environment(
        monkeypatch, identity, checks, fail_check=fail_check,
    )
    with pytest.raises(ValueError, match='custody changed'):
        vmware.supervise(tmp_path / identity, identity, SimpleNamespace(check=lambda: None))
    assert writes == ([] if fail_check < 3 else [b'G'])
    assert controls == ([] if fail_check == 1 else ['start', 'stop'])
    assert 'pipe' in closed
    if fail_check > 1:
        assert 'job' in closed


def test_supervisor_keeps_custody_through_stop_and_receipt(tmp_path, monkeypatch):
    identity = 'a' * 32
    checks = []
    controls, writes, closed = _fake_supervisor_environment(monkeypatch, identity, checks)
    result = vmware.supervise(tmp_path / identity, identity, SimpleNamespace(check=lambda: None))
    assert result.endswith(b'ANGERONA_REPORT:{}\n')
    assert len(checks) == 3
    assert controls == ['start', 'stop']
    assert len(writes) == 1
    assert closed.count('job') == 1


def _isolated_appliance(tmp_path, monkeypatch):
    root = tmp_path / 'lab'
    appliance = root / 'appliance'
    appliance.mkdir(parents=True)
    files = {'base.cpio.gz': b'inert appliance', 'kernel': b'inert kernel'}
    for name, raw in files.items():
        (appliance / name).write_bytes(raw)
    monkeypatch.setattr(jobs, 'OUTPUTS', {
        name: {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        for name, raw in files.items()
    })
    runtime = tmp_path / 'fixture-runtime'
    runtime.mkdir()
    # Never consult or launch the operator's real protected QEMU installation.
    monkeypatch.setattr(jobs.analysis_qemu_runtime, 'trusted_installation',
                        lambda: contextlib.nullcontext(runtime))
    return root, runtime


@pytest.mark.skipif(os.name != 'nt', reason='Windows deny-write/delete sharing')
def test_job_runner_pins_generated_initrd_until_report_is_parsed(tmp_path, monkeypatch):
    root, runtime = _isolated_appliance(tmp_path, monkeypatch)
    accepted = []

    def supervisor(actual_runtime, kernel, initrd, identity, _operation):
        assert actual_runtime == runtime
        assert kernel == root / 'appliance' / 'kernel'
        assert initrd == root / 'runs' / identity / 'initrd.cpio.gz'
        with pytest.raises(PermissionError):
            initrd.write_bytes(b'altered boot input')
        with pytest.raises(PermissionError):
            initrd.unlink()
        with pytest.raises(PermissionError):
            kernel.write_bytes(b'altered kernel')
        report = dict(schema=1, job=identity, tool='bandit', input_sha256='b' * 64,
                      catalog_sha256=jobs.CATALOG_DIGEST, errors=0, findings=[],
                      isolation={'network': ['lo'], 'block_devices': [], 'host_shares': False})
        return b'ANGERONA_REPORT:' + json.dumps(report).encode() + b'\n'

    original_parse = jobs.parse_report

    def parse(output, job):
        with pytest.raises(PermissionError):
            (root / 'runs' / job['job'] / 'initrd.cpio.gz').unlink()
        with pytest.raises(PermissionError):
            (root / 'appliance' / 'kernel').unlink()
        accepted.append(job['job'])
        return original_parse(output, job)

    monkeypatch.setattr(jobs.analysis_qemu, 'supervise', supervisor)
    monkeypatch.setattr(jobs, 'parse_report', parse)
    result = jobs._run(root, 'bandit', {}, {}, 'b' * 64, 0, jobs.AnalysisOperation())
    assert accepted == [result['job']]
    assert result['response_authority'] is False
    assert not list((root / 'runs').iterdir())


def test_job_runner_rejects_initrd_swapped_between_generation_and_sealing(tmp_path, monkeypatch):
    root, _runtime = _isolated_appliance(tmp_path, monkeypatch)
    original_write = jobs._atomic_bytes_write

    def race_after_generation(path, data, **kwargs):
        original_write(path, data, **kwargs)
        if path.name == 'initrd.cpio.gz':
            path.write_bytes(b'altered initrd before the readonly seal')

    monkeypatch.setattr(jobs, '_atomic_bytes_write', race_after_generation)
    monkeypatch.setattr(jobs.analysis_qemu, 'supervise', lambda *_a: pytest.fail('started altered guest'))
    monkeypatch.setattr(jobs, 'parse_report', lambda *_a: pytest.fail('accepted altered guest report'))
    with pytest.raises(ValueError, match='generated analysis input changed'):
        jobs._run(root, 'bandit', {}, {}, 'b' * 64, 0, jobs.AnalysisOperation())
