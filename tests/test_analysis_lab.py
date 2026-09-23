from __future__ import annotations

import copy
import hashlib
import io
import json
import stat
import tarfile
import threading
import time

import pytest

from angerona.core import analysis_image, analysis_vmware, tool_analysis_jobs as jobs
from angerona.core.analysis_guest import SOURCE


def job_and_report():
    job = {'job': 'a' * 32, 'tool': 'bandit', 'files': ['00000.py'],
           'input_sha256': 'b' * 64, 'catalog_sha256': jobs.CATALOG_DIGEST}
    report = {key: value for key, value in job.items() if key != 'files'}
    report.update(schema=1, findings=[{'file': '00000.py', 'rule': 'B101', 'line': 1, 'severity': 'LOW'}],
                  errors=0, isolation={'network': ['lo'], 'block_devices': ['sr0'], 'host_shares': False})
    return job, report


def encoded(report):
    return b'Boot diagnostics\r\nANGERONA_REPORT:' + json.dumps(report).encode() + b'\r\n'


def test_valid_report_has_only_locations_and_rule_ids():
    job, report = job_and_report()
    assert jobs.parse_report(encoded(report), job) == report
    assert set(report['findings'][0]) == {'file', 'rule', 'line', 'severity'}


@pytest.mark.parametrize('mutation', [
    lambda r: r.update(job='f' * 32),
    lambda r: r.update(catalog_sha256='0' * 64),
    lambda r: r.update(secret='must never export'),
    lambda r: r.update(errors=True),
    lambda r: r.update(schema=True),
    lambda r: r['findings'][0].update(Secret='must never export'),
    lambda r: r['findings'][0].update(file='../outside.py'),
    lambda r: r['findings'][0].update(line=True),
    lambda r: r['findings'][0].update(rule='source-text'),
    lambda r: r['findings'][0].update(severity='UNKNOWN'),
    lambda r: r['isolation'].update(network=['lo', 'eth0']),
    lambda r: r['isolation'].update(block_devices=['sr0', 'sda']),
    lambda r: r['isolation'].update(host_shares=True),
])
def test_forged_or_secret_bearing_reports_are_rejected(mutation):
    job, report = job_and_report()
    mutation(report)
    with pytest.raises(ValueError):
        jobs.parse_report(encoded(report), job)


def test_duplicate_and_oversized_reports_are_rejected():
    job, report = job_and_report()
    with pytest.raises(ValueError):
        jobs.parse_report(encoded(report) * 2, job)
    with pytest.raises(ValueError):
        jobs.parse_report(b'ANGERONA_REPORT:' + b'x' * (jobs.MAX_REPORT + 1), job)
    with pytest.raises(ValueError):
        jobs.parse_report(b'ANGERONA_REPORT:{"job":1,"job":2}', job)


def test_snapshot_copies_text_without_executing_project_or_using_config(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    body = b"raise RuntimeError('source must never execute')\n"
    (source / 'sample.py').write_bytes(body)
    (source / '.bandit').write_text('[bandit]\nskips=B101')
    (source / 'binary.py').write_bytes(b'\x00\xff')
    (source / 'venv').mkdir()
    (source / 'venv' / 'skip.py').write_text('assert True')
    values = jobs.snapshot(source, 'bandit', jobs.AnalysisOperation(), runtime_root=tmp_path/'runtime')
    files, mapping, digest, skipped = values
    assert files == {'00000.py': body}
    assert mapping == {'00000.py': 'sample.py'}
    assert skipped == 3
    assert len(digest) == 64
    assert values == jobs.snapshot(source, 'bandit', jobs.AnalysisOperation(), runtime_root=tmp_path/'runtime')
    assert (source / 'sample.py').read_bytes() == body


def test_snapshot_limits_and_unknown_adapter_fail_closed(tmp_path, monkeypatch):
    (tmp_path/'a.py').write_text('assert True')
    with pytest.raises(ValueError, match='reviewed analyzers'):
        jobs.snapshot(tmp_path, 'shell', jobs.AnalysisOperation(), runtime_root=tmp_path/'runtime')
    monkeypatch.setattr(jobs, 'MAX_INPUT', 2)
    with pytest.raises(ValueError, match='16 MiB'):
        jobs.snapshot(tmp_path, 'bandit', jobs.AnalysisOperation(), runtime_root=tmp_path/'runtime')


def test_snapshot_refuses_runtime_tree(tmp_path):
    with pytest.raises(ValueError, match='outside Angerona runtime'):
        jobs.snapshot(tmp_path, 'bandit', jobs.AnalysisOperation(), runtime_root=tmp_path)


def test_cancel_and_deadline_never_accept_late_work():
    operation = jobs.AnalysisOperation()
    operation.cancel()
    with pytest.raises(ValueError, match='cancelled'):
        operation.check()
    operation = jobs.AnalysisOperation()
    operation.deadline = time.monotonic() - 1
    with pytest.raises(ValueError, match='deadline'):
        operation.phase()


def test_vm_profile_has_only_readonly_boot_media_and_local_pipe():
    config = analysis_vmware.configuration('a'*32)
    assert 'ethernet0.present = "FALSE"' in config
    assert 'sharedFolder.maxNum = "0"' in config
    assert 'serial0.fileType = "pipe"' in config
    assert 'ide0:0.deviceType = "cdrom-image"' in config
    assert 'mainMem.useNamedFile = "FALSE"' in config
    assert '.vmdk' not in config
    assert 'D:\\Ubuntu' not in config
    with pytest.raises(ValueError):
        analysis_vmware.configuration('"\nmalformed')


def test_guest_entry_point_compiles_and_requires_supervisor_handshake():
    compile(SOURCE, '<reviewed guest>', 'exec')
    assert 'GO:' in SOURCE
    assert 'resource.RLIMIT_FSIZE' in SOURCE
    assert 'extra_groups=[]' in SOURCE
    assert 'user=65534' in SOURCE


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'a/../../b', 'a\\b', 'a\x00b'])
def test_guest_archive_paths_never_escape(name):
    with pytest.raises(ValueError):
        analysis_image.cpio({name: (stat.S_IFREG|0o644, b'text')})


def test_apk_style_concatenated_gzip_is_read_without_host_extraction(tmp_path):
    import gzip
    def archive(name, data):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tar:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
        return gzip.compress(buffer.getvalue())
    payload = archive('.PKGINFO', b'untrusted hook metadata') + archive('opt/data', b'harmless')
    image = analysis_image.GuestImage()
    image.tar(payload, jobs.AnalysisOperation())
    assert image.entries == {'opt/data': (stat.S_IFREG|0o644, b'harmless')}
    assert not list(tmp_path.iterdir())


def test_cached_runtime_tampering_is_detected(tmp_path):
    path = tmp_path/'artifact'
    path.write_bytes(b'valid')
    expected = {'size':5, 'sha256':hashlib.sha256(b'valid').hexdigest()}
    assert jobs._verified(path, expected, tmp_path) == b'valid'
    path.write_bytes(b'other')
    with pytest.raises(ValueError, match='integrity'):
        jobs._verified(path, expected, tmp_path)


def test_concurrent_jobs_fail_immediately(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, '_require_unprivileged', lambda: None)
    with jobs.transaction(tmp_path):
        with pytest.raises(ValueError, match='already active'):
            with jobs.transaction(tmp_path):
                pytest.fail('entered a concurrent transaction')


def test_history_cannot_assert_response_authority_or_include_extra_fields(tmp_path):
    job, report = job_and_report()
    report.update(origin='external_analysis', tool_version=jobs.TOOLS['bandit'], completed_at=1,
                  files={'00000.py':'example.py'}, skipped=0, file_count=1, response_authority=False)
    jobs.validate_receipt(report, job['job'])
    for extra in ({'response_authority':True}, {'secret':'never export'}, {'files':{'00000.py':'../outside'}}):
        modified = copy.deepcopy(report)
        modified.update(extra)
        with pytest.raises(ValueError):
            jobs.validate_receipt(modified, job['job'])


def test_dependency_catalog_is_exact_and_bounded():
    assert set(jobs.TOOLS) == {'bandit','gitleaks'}
    assert sum(item['size'] for item in jobs.PACKAGES) < 128 * 1024**2
    assert all(len(item['sha256']) == 64 and item['url'].startswith('https://') for item in jobs.PACKAGES)


def test_cleanup_cannot_leave_generated_job_boundary(tmp_path):
    root=tmp_path/'lab'
    own=root/'runs'/('a'*32)
    own.mkdir(parents=True)
    (own/'temporary.iso').write_bytes(b'inert copy')
    (own/'temporary.lck').mkdir()
    (own/'temporary.lck'/'lock').write_bytes(b'')
    outside=tmp_path/'original.py'
    outside.write_text('keep original')
    jobs.remove_job_directory(root,own)
    assert not own.exists()
    assert outside.read_text()=='keep original'
    with pytest.raises(ValueError,match='outside'):
        jobs.remove_job_directory(root,tmp_path)


def test_readiness_does_not_claim_a_missing_service_is_a_missing_hypervisor(tmp_path,monkeypatch):
    monkeypatch.setattr(jobs,'_require_unprivileged',lambda:None)
    monkeypatch.setattr(analysis_vmware,'installation',lambda:tmp_path)
    def stopped():raise ValueError('Start VMware Authorization Service in Windows Services.')
    monkeypatch.setattr(analysis_vmware,'service_ready',stopped)
    ready,reason=jobs.readiness(tmp_path)
    assert not ready
    assert 'Authorization Service' in reason


@pytest.mark.skipif(__import__('os').name!='nt',reason='Windows Job Object integration')
def test_real_windows_job_enforces_memory_and_kills_only_its_child(tmp_path,monkeypatch):
    import os
    import subprocess
    import sys
    import psutil
    import win32job
    process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)'],
                             creationflags=subprocess.CREATE_NO_WINDOW)
    actual=psutil.Process(process.pid)
    vmx=tmp_path/'analysis.vmx'
    job=None
    class Peer:
        def create_time(self):return actual.create_time()
        def exe(self):return str(tmp_path/'x64/vmware-vmx.exe')
        def cmdline(self):return [str(vmx)]
        def children(self):return []
    class Query:
        def __call__(self,_pipe,pointer):
            pointer._obj.value=process.pid
            return 1
    class Kernel:
        GetNamedPipeClientProcessId=Query()
    monkeypatch.setattr(analysis_vmware.ctypes,'WinDLL',lambda *_args,**_kwargs:Kernel())
    monkeypatch.setattr(psutil,'Process',lambda _pid:Peer())
    try:
        job=analysis_vmware._client_job(1,vmx,tmp_path)
        limits=win32job.QueryInformationJobObject(job,win32job.JobObjectExtendedLimitInformation)
        assert limits['ProcessMemoryLimit']==2*1024**3
        assert limits['BasicLimitInformation']['ActiveProcessLimit']==1
        assert process.poll() is None
        job.Close();job=None
        process.wait(timeout=5)
        assert process.poll() is not None
        assert os.getpid()!=process.pid
    finally:
        if job is not None:job.Close()
        if process.poll() is None:process.kill()
        process.wait(timeout=5)
