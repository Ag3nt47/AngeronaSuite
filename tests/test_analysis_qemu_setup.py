"""Optional emulator setup never downloads, elevates, or installs in fixtures."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import analysis_qemu_setup as setup


class Operation:
    def __init__(self):
        self.cancelled = False
        self.phases = []

    def check(self):
        if self.cancelled:
            raise InterruptedError('fixture cancelled')

    def phase(self, seconds):
        self.check()
        self.phases.append(seconds)


def entry(content):
    return {'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}


@pytest.fixture
def catalog(monkeypatch):
    content = {'qemu-system-x86_64.exe': b'inert executable',
               'share/bios-256k.bin': b'inert firmware', 'COPYING': b'fixture license'}
    monkeypatch.setattr(setup, 'FILES', {name: entry(raw) for name, raw in content.items()})
    return content


@pytest.fixture
def source(tmp_path, catalog):
    directory = tmp_path / 'vendor'
    for name, content in catalog.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return directory


def test_bundle_contains_only_reviewed_files_and_retains_seal(source, tmp_path, catalog):
    (source / 'unrelated.dll').write_bytes(b'untrusted extra vendor file')
    with setup._bundle(source, tmp_path, Operation()) as (path, size, digest):
        assert path.stat().st_size == size
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        with zipfile.ZipFile(path) as archive:
            assert set(archive.namelist()) == set(catalog)
            assert {name: archive.read(name) for name in archive.namelist()} == catalog
        if os.name == 'nt':
            with pytest.raises(OSError):
                path.write_bytes(b'cannot replace held archive')
    assert not path.exists()


def test_same_size_modified_vendor_file_never_builds_bundle(source, tmp_path):
    path = source / 'qemu-system-x86_64.exe'
    path.write_bytes(b'x' * path.stat().st_size)
    with pytest.raises(ValueError, match='catalog checksum'):
        with setup._bundle(source, tmp_path, Operation()):
            pytest.fail('Unreviewed source bytes were accepted')
    assert not list(tmp_path.glob('qemu-runtime-*.zip'))


def make_zip(content):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, raw in content.items():
            archive.writestr(name, raw)
    stream.seek(0)
    return stream


@pytest.mark.parametrize('change', ['missing', 'extra', 'renamed', 'size', 'digest', 'duplicate'])
def test_sealed_archive_must_still_contain_exact_catalog_bytes(catalog, change):
    content = dict(catalog)
    if change == 'missing':
        content.pop('COPYING')
    elif change == 'extra':
        content['injected.dll'] = b'x'
    elif change == 'renamed':
        content['../escape.dll'] = content.pop('COPYING')
    elif change == 'size':
        content['COPYING'] += b'x'
    elif change == 'digest':
        content['COPYING'] = b'x' * len(content['COPYING'])
    stream = make_zip(content)
    if change == 'duplicate':
        with pytest.warns(UserWarning):
            with zipfile.ZipFile(stream, 'a') as archive:
                archive.writestr('COPYING', content['COPYING'])
    with pytest.raises(ValueError, match='archive'):
        setup._verify_bundle(stream, Operation())


def test_archive_swapped_before_readonly_seal_is_rejected(source, tmp_path, catalog, monkeypatch):
    original = setup._open_sealed
    content = dict(catalog)
    content['COPYING'] = b'x' * len(content['COPYING'])
    replacement = make_zip(content).getvalue()

    @contextlib.contextmanager
    def substitute(path):
        if path.suffix == '.zip':
            path.write_bytes(replacement)
        with original(path) as stream:
            yield stream

    monkeypatch.setattr(setup, '_open_sealed', substitute)
    with pytest.raises(ValueError, match='member checksum'):
        with setup._bundle(source, tmp_path, Operation()):
            pytest.fail('Pre-seal archive replacement reached the privileged copier')


@pytest.fixture
def download(monkeypatch):
    raw = b'reviewed inert installer fixture'
    expected = entry(raw)
    expected['sha512'] = hashlib.sha512(raw).hexdigest()
    expected['url'] = 'https://qemu.weilnetz.de/w64/fixture.exe'
    monkeypatch.setattr(setup, 'INSTALLER', expected)
    response = SimpleNamespace(status_code=200, headers={'Content-Length': str(len(raw))})
    response.iter_content = lambda _size: [raw[:5], raw[5:]]
    requests = []

    class Session:
        trust_env = True
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass
        def get(self, url, **kwargs):
            assert self.trust_env is False
            assert kwargs == {'timeout': (10, 10), 'stream': True, 'allow_redirects': False,
                              'headers': {'Accept-Encoding': 'identity'}}
            requests.append(url)
            return contextlib.nullcontext(response)

    monkeypatch.setitem(sys.modules, 'requests', SimpleNamespace(Session=Session))
    return raw, response, requests


def test_download_verifies_both_pins_and_reuses_cache(download, tmp_path):
    raw, _response, requests = download
    progress = []
    operation = Operation()
    path = setup._download(tmp_path, operation, progress.append)
    assert path.read_bytes() == raw
    assert setup._download(tmp_path, operation, progress.append) == path
    assert len(requests) == 1 and operation.phases == [900]
    assert progress[-1].endswith('100%')
    assert not list(tmp_path.glob('*.part'))


@pytest.mark.parametrize('case', ['wrong-hash', 'wrong-sha512', 'overrun', 'short', 'header', 'http'])
def test_unreviewed_or_incomplete_downloads_never_enter_cache(download, tmp_path, case):
    raw, response, _requests = download
    if case == 'wrong-hash':
        response.iter_content = lambda _size: [b'x' * len(raw)]
    elif case == 'wrong-sha512':
        setup.INSTALLER['sha512'] = '0' * 128
    elif case == 'overrun':
        response.iter_content = lambda _size: [raw + b'x']
    elif case == 'short':
        response.iter_content = lambda _size: [raw[:-1]]
    elif case == 'header':
        response.headers['Content-Length'] = str(len(raw) + 1)
    else:
        response.status_code = 404
    with pytest.raises(ValueError):
        setup._download(tmp_path, Operation(), lambda _message: None)
    assert not list(tmp_path.iterdir())


def test_cross_host_redirect_is_rejected_before_second_request(download, tmp_path):
    _raw, response, requests = download
    response.status_code = 302
    response.headers['Location'] = 'https://unapproved.invalid/installer.exe'
    with pytest.raises(ValueError, match='endpoint'):
        setup._download(tmp_path, Operation(), lambda _message: None)
    assert len(requests) == 1 and not list(tmp_path.iterdir())


def test_cancelled_download_removes_only_its_owned_partial(download, tmp_path):
    marker = tmp_path / 'operator-note.txt'
    marker.write_text('leave me')
    operation = Operation()
    with pytest.raises(InterruptedError):
        setup._download(tmp_path, operation, lambda _message: setattr(operation, 'cancelled', True))
    assert list(tmp_path.iterdir()) == [marker]


def test_powershell_literals_cannot_escape_into_code():
    assert setup._literal("D:\\path';throw 'escape\\installer.exe") == "'D:\\path'';throw ''escape\\installer.exe'"
    with pytest.raises(ValueError):
        setup._literal('bad\npath')


def test_privileged_copy_script_has_exact_bounds_and_fixed_destination(catalog, monkeypatch, tmp_path):
    scripts = []
    monkeypatch.setattr(setup, '_elevated', lambda script: scripts.append(script) or 0)
    setup._configure_bundle((tmp_path / "quote's.zip", 123, 'a' * 64), Operation(), lambda _message: None)
    script = scripts[0]
    assert "quote''s.zip" in script and '__SOURCE__' not in script
    assert 'Entries.Count -ne 3' in script
    assert 'New-ProtectedFile $target' in script and 'SetAccessRuleProtection($true, $false)' in script
    assert 'Microsoft.Win32.Win32Native' in script and '$directoryGuards.Add($guard)' in script
    assert 'qemu-system-x86_64.exe' not in script
    assert len(base64.b64encode(script.encode('utf-16-le'))) < 29000


def test_vendor_installer_staged_into_protected_namespace_before_execution(download, tmp_path, monkeypatch):
    raw, _response, _requests = download
    path = tmp_path / 'installer.exe'
    path.write_bytes(raw)
    scripts = []
    monkeypatch.setattr(setup, '_elevated', lambda script: scripts.append(script) or 0)
    setup._install_vendor(path, Operation(), lambda _message: None)
    script = scripts[0]
    assert script.index('Copy-VerifiedFile ' + setup._literal(path)) < script.index('Start-Process -FilePath $installer')
    assert 'AngeronaAnalysisInstaller-11.1.0-' in script
    assert '-WindowStyle Normal' in script and 'qemu-system-x86_64.exe' not in script
    assert '-Recurse' not in script


@pytest.mark.parametrize('code', [1, 1223, 3010, 1641])
def test_cancel_failure_or_restart_never_claims_configured(download, tmp_path, monkeypatch, code):
    raw, _response, _requests = download
    path = tmp_path / 'installer.exe'
    path.write_bytes(raw)
    monkeypatch.setattr(setup, '_elevated', lambda _script: code)
    with pytest.raises(ValueError):
        setup._install_vendor(path, Operation(), lambda _message: None)


@pytest.fixture
def workflow(tmp_path, monkeypatch, catalog):
    from angerona.core import privilege, tool_analysis_jobs
    program_files = tmp_path / 'Program Files'
    program_files.mkdir()
    root = tmp_path / 'lab'
    root.mkdir()
    monkeypatch.setattr(setup, 'os', SimpleNamespace(name='nt', fstat=os.fstat, fsync=os.fsync))
    monkeypatch.setattr(setup.platform, 'machine', lambda: 'AMD64')
    monkeypatch.setattr(setup, '_require_unprivileged', lambda: None)
    monkeypatch.setattr(privilege, '_windows_known_folder', lambda _kind: program_files)
    monkeypatch.setattr(tool_analysis_jobs, 'transaction', lambda _root: contextlib.nullcontext())
    monkeypatch.setattr(setup.analysis_qemu_runtime, 'trusted_installation', lambda: contextlib.nullcontext())
    calls = []
    monkeypatch.setattr(setup, '_configure_bundle', lambda *_args: calls.append('configure'))
    monkeypatch.setattr(setup, '_download', lambda *_args: calls.append('download') or root / 'installer.exe')

    def install(*_args):
        calls.append('install')
        for name, raw in catalog.items():
            path = program_files / 'qemu' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    monkeypatch.setattr(setup, '_install_vendor', install)
    return root, program_files, calls


def test_missing_vendor_install_downloads_then_configures(workflow):
    root, _program_files, calls = workflow
    assert 'configured' in setup.install_and_configure(root, Operation())
    assert calls == ['download', 'install', 'configure']


@pytest.mark.parametrize('machine', ['ARM64', 'aarch64', 'x86'])
def test_unsupported_machine_never_downloads_or_installs(workflow, monkeypatch, machine):
    root, _program_files, calls = workflow
    monkeypatch.setattr(setup.platform, 'machine', lambda: machine)
    with pytest.raises(ValueError, match='Intel or AMD'):
        setup.install_and_configure(root, Operation())
    assert calls == []
    assert not (root / 'downloads').exists()


def test_exact_existing_vendor_install_needs_no_download(workflow, catalog):
    root, program_files, calls = workflow
    for name, raw in catalog.items():
        path = program_files / 'qemu' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    setup.install_and_configure(root, Operation())
    assert calls == ['configure']


def test_existing_protected_target_is_verified_without_overwrite(workflow):
    root, program_files, calls = workflow
    target = program_files / setup.analysis_qemu_runtime.RUNTIME_DIRECTORY
    target.mkdir()
    marker = target / 'marker'
    marker.write_text('preserved')
    assert 'already verified' in setup.install_and_configure(root, Operation())
    assert not calls and marker.read_text() == 'preserved'


def test_cancel_after_native_installer_prevents_configuration(workflow, monkeypatch):
    root, _program_files, calls = workflow
    operation = Operation()
    monkeypatch.setattr(setup, '_install_vendor', lambda *_args: setattr(operation, 'cancelled', True))
    with pytest.raises(InterruptedError):
        setup.install_and_configure(root, operation)
    assert calls == ['download']


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell bootstrap boundary')
def test_native_readonly_bootstrap_pins_program_files_without_compiler_or_mutation():
    from angerona.core.privilege import (
        sanitized_child_environment, trusted_powershell_path, trusted_windows_directories,
    )
    powershell = trusted_powershell_path()
    _windows, system = trusted_windows_directories()
    script = setup._BOOTSTRAP + "\nif ($directoryGuards.Count -lt 2) { exit 2 }; exit 0\n"
    assert 'Add-Type' not in script and 'New-ProtectedDirectory $' not in script
    environment = sanitized_child_environment(source={})
    environment['PATH'] = str(system)
    result = subprocess.run(
        [str(powershell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
         base64.b64encode(script.encode('utf-16-le')).decode('ascii')],
        cwd=str(system), env=environment, capture_output=True, timeout=20,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    )
    assert result.returncode == 0, result.stderr.decode(errors='replace')
