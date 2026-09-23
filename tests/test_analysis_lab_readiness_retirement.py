"""Current native check failures cannot inherit an earlier success receipt."""
import contextlib
import hashlib
import json
from types import SimpleNamespace

import pytest

from angerona.core import analysis_vmware as vmware, analysis_qemu_runtime as runtime, tool_analysis_jobs as jobs


def test_failed_native_recheck_retires_previous_success(tmp_path, monkeypatch):
    record = tmp_path / 'selfcheck.json'
    record.write_text(json.dumps({'catalog': jobs.CATALOG_DIGEST,
                                 'tools': sorted(jobs.TOOLS), 'passed': True}))
    monkeypatch.setattr(jobs, 'transaction', lambda _root: contextlib.nullcontext())
    def unavailable():
        raise ValueError('Protected runtime unavailable')

    monkeypatch.setattr(runtime, 'trusted_installation', unavailable)
    with pytest.raises(ValueError, match='Protected runtime unavailable'):
        jobs.check_runtime(tmp_path, jobs.AnalysisOperation())
    assert json.loads(record.read_text())['passed'] is False
    monkeypatch.setattr(runtime, 'trusted_installation', lambda: contextlib.nullcontext(tmp_path))
    monkeypatch.setattr(jobs, '_require_unprivileged', lambda: None)
    monkeypatch.setattr(jobs, '_verified', lambda *_a: b'')
    ready, reason = jobs.readiness(tmp_path)
    assert not ready and 'current appliance' in reason


def test_pre_custody_receipt_digest_is_retired():
    legacy = hashlib.sha256(json.dumps(
        [jobs.CATALOG_VERSION, jobs.TOOLS, jobs.PACKAGES, jobs.OUTPUTS], sort_keys=True,
    ).encode()).hexdigest()
    assert legacy != jobs.CATALOG_DIGEST


def test_vmware_file_access_failure_has_safe_specific_guidance(tmp_path, monkeypatch):
    monkeypatch.setattr(vmware.subprocess, 'CREATE_NO_WINDOW', 0, raising=False)
    monkeypatch.setattr(vmware.subprocess, 'run', lambda *_a, **_k: SimpleNamespace(
        returncode=1, stdout=b'A file access error occurred: untrusted path', stderr=b'',
    ))
    with pytest.raises(ValueError, match='protected analysis configuration') as caught:
        vmware._control(tmp_path, 'start', tmp_path / 'analysis.vmx')
    assert 'untrusted path' not in str(caught.value)
