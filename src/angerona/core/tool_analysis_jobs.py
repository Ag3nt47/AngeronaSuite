"""Bounded input copies, pinned appliance preparation and external-analysis receipts."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from angerona.core.analysis_catalog import CATALOG_VERSION, OUTPUTS, PACKAGES, TOOLS
from angerona.core.analysis_image import GuestImage, compress, cpio
from angerona.core import analysis_vmware
from angerona.core.data_paths import data_dir
from angerona.core.executable_trust import _open_sealed
from angerona.core.file_lease import ExclusiveFileLease, ExclusiveFileLeaseError
from angerona.core.github_tool_catalog import (
    ImportCancelled, ImportOperation, _bounded_read, _require_unprivileged, plain_text,
)
from angerona.core.source_sandbox import (
    _absolute, _atomic_bytes_write, _ensure_directory, _hold_plain_directories,
    _is_link_or_reparse, _validate_chain, _validate_regular_file,
)

MAX_INPUT = 16 * 1024**2
MAX_FILE = 1024**2
MAX_FILES = 2000
MAX_REPORT = 1024**2
_LOCK = threading.Lock()
_EXCLUDED = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', '.tmp', '.dev-tools',
             'runtime-data', 'dist', 'build', '.idea', '.vscode'}
_EXTENSIONS = {'.py', '.txt', '.md', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg',
               '.env', '.sh', '.ps1', '.js', '.ts', '.tsx', '.jsx', '.html', '.css',
               '.xml', '.conf', '.properties', '.sql', '.go', '.rs', '.c', '.h', '.cpp',
               '.java', '.cs', '.rb', '.php'}
CATALOG_DIGEST = hashlib.sha256(json.dumps(
    [CATALOG_VERSION, TOOLS, PACKAGES, OUTPUTS,
     analysis_vmware.SUPERVISOR_PROFILE, analysis_vmware.configuration('0' * 32)], sort_keys=True,
).encode()).hexdigest()


class AnalysisOperation(ImportOperation):
    def check(self):
        if self.cancelled.is_set():
            raise ImportCancelled('Analysis cancelled; no late result will be accepted.')
        if time.monotonic() >= self.deadline:
            raise ValueError('Analysis exceeded its phase deadline.')

    def phase(self, seconds=120):
        self.check()
        self.deadline = time.monotonic() + seconds


def default_root() -> Path:
    return data_dir() / 'analysis-lab'


@contextlib.contextmanager
def transaction(root: Path):
    _require_unprivileged()
    if not _LOCK.acquire(blocking=False):
        raise ValueError('An analysis or runtime preparation is already active.')
    try:
        _ensure_directory(root)
        with _hold_plain_directories(root):
            try:
                lease = ExclusiveFileLease(root / 'analysis.lock')
            except ExclusiveFileLeaseError:
                raise ValueError('Another Angerona session is using Analysis Lab.') from None
            with lease:
                yield
    finally:
        _LOCK.release()


def _verified(path, expected, root):
    raw = _bounded_read(path, root, expected['size'])
    if len(raw) != expected['size'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
        raise ValueError('Analysis runtime integrity failed. Prepare the reviewed runtime again.')
    return raw


def _fetch(item, operation):
    import requests
    url = item['url']
    operation.phase()
    with requests.Session() as session:
        session.trust_env = False
        for _attempt in range(4):
            parsed = urlsplit(url)
            if (parsed.scheme != 'https' or parsed.netloc not in {
                'dl-cdn.alpinelinux.org', 'files.pythonhosted.org', 'github.com',
                'release-assets.githubusercontent.com',
            } or parsed.fragment):
                raise ValueError('Unapproved analysis artifact endpoint.')
            operation.check()
            with session.get(url, timeout=10, stream=True, allow_redirects=False,
                             headers={'Accept-Encoding': 'identity'}) as response:
                if response.status_code in (301, 302, 307, 308):
                    url = response.headers.get('Location', '')
                    continue
                if response.status_code != 200:
                    raise ValueError(f'Runtime artifact download failed (HTTP {response.status_code}).')
                length = response.headers.get('Content-Length')
                if length is not None and (not length.isdecimal() or int(length) != item['size']):
                    raise ValueError('Runtime artifact size does not match the catalog.')
                raw = bytearray()
                for chunk in response.iter_content(64 * 1024):
                    operation.check()
                    raw.extend(chunk)
                    if len(raw) > item['size']:
                        raise ValueError('Runtime artifact exceeds its byte limit.')
                if len(raw) != item['size'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                    raise ValueError('Runtime artifact SHA-256 does not match the reviewed catalog.')
                return bytes(raw)
        raise ValueError('Runtime artifact redirected too many times.')


def prepare_runtime(root, operation, progress=lambda _message: None):
    root = _absolute(Path(root))
    with transaction(root):
        analysis_vmware.installation()  # Preparation does not require the service to be running.
        import pycdlib
        downloads, appliance = root / 'downloads', root / 'appliance'
        for path in (downloads, appliance):
            _ensure_directory(path)
        if shutil.disk_usage(root).free < 512 * 1024**2:
            raise ValueError('Runtime preparation requires at least 512 MiB of free disk space.')
        image = GuestImage()
        for index, item in enumerate(PACKAGES, 1):
            progress(f'Preparing verified runtime package {index} of {len(PACKAGES)}…')
            operation.phase()
            path = downloads / (item['sha256'] + '.pkg')
            try:
                raw = _verified(path, item, root)
            except FileNotFoundError:
                raw = _fetch(item, operation)
                _atomic_bytes_write(path, raw, root=root)
            operation.phase()
            if item['kind'] in {'rootfs', 'apk'}:
                image.tar(raw, operation)
            elif item['kind'] == 'wheel':
                image.wheel(raw, operation)
            elif item['kind'] == 'gitleaks':
                with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
                    member = archive.getmember('gitleaks')
                    if not member.isfile() or member.size > 32 * 1024**2:
                        raise ValueError('Unexpected Gitleaks executable entry.')
                    image.add('opt/gitleaks', archive.extractfile(member).read(), stat.S_IFREG | 0o755)
            elif item['kind'] == 'boot':
                iso = pycdlib.PyCdlib()
                try:
                    iso.open_fp(io.BytesIO(raw))
                    for name, entry in OUTPUTS.items():
                        if 'member' not in entry:
                            continue
                        buffer = io.BytesIO()
                        iso.get_file_from_iso_fp(buffer, rr_path='/' + entry['member'])
                        content = buffer.getvalue()
                        if (len(content) != entry['size']
                                or hashlib.sha256(content).hexdigest() != entry['sha256']):
                            raise ValueError('Guest boot component failed verification.')
                        _atomic_bytes_write(appliance / name, content, root=root)
                finally:
                    iso.close()
        operation.phase()
        content = image.finish()
        expected = OUTPUTS['base.cpio.gz']
        if len(content) != expected['size'] or hashlib.sha256(content).hexdigest() != expected['sha256']:
            raise ValueError('The assembled guest image does not match the reviewed build.')
        operation.check()
        _atomic_bytes_write(appliance / 'base.cpio.gz', content, root=root)
    return 'Reviewed runtime prepared. Check readiness to test both analyzers in VMware.'


def readiness(root) -> tuple[bool, str]:
    try:
        _require_unprivileged()
        analysis_vmware.installation()
        analysis_vmware.service_ready()
        root = _absolute(Path(root))
        for name, expected in OUTPUTS.items():
            _verified(root / 'appliance' / name, expected, root)
        record = json.loads(_bounded_read(root / 'selfcheck.json', root, 4096))
        if record != {'catalog': CATALOG_DIGEST, 'tools': sorted(TOOLS), 'passed': True}:
            raise ValueError('Check readiness to verify the current appliance with both analyzers.')
        return True, 'Ready: VMware · offline RAM-only guest · Bandit 1.9.4 / Gitleaks 8.30.1.'
    except (FileNotFoundError, ModuleNotFoundError):
        return False, 'Prepare the reviewed analysis runtime, then Check readiness.'
    except (ValueError, PermissionError) as exc:
        return False, plain_text(str(exc))
    except Exception:
        return False, 'VMware readiness could not be verified. Check the installation and Authorization Service.'


def snapshot(directory, tool, operation, *, runtime_root):
    if tool not in TOOLS:
        raise ValueError('Select one of the reviewed analyzers.')
    root = _absolute(Path(directory))
    _validate_chain(root)
    protected = (_absolute(runtime_root), _absolute(data_dir()))
    if any(root == path or root.is_relative_to(path) for path in protected):
        raise ValueError('Select project source outside Angerona runtime data.')
    files, mapping = {}, {}
    skipped, total, visited = 0, 0, 0
    pending = [root]
    while pending:
        operation.check()
        directory = pending.pop()
        with _hold_plain_directories(directory):
            with os.scandir(directory) as stream:
                candidates = []
                for entry in stream:
                    operation.check()
                    visited += 1
                    if visited > 20000:
                        raise ValueError('Input has too many entries; choose a smaller source directory.')
                    candidates.append(entry)
                for entry in sorted(candidates, key=lambda entry: entry.name.casefold()):
                    operation.check()
                    path = directory / entry.name
                    info = entry.stat(follow_symlinks=False)
                    if _is_link_or_reparse(info):
                        skipped += 1
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if entry.name.casefold() in _EXCLUDED or any(
                            path == protected_path or path.is_relative_to(protected_path)
                            for protected_path in protected
                        ):
                            skipped += 1
                        else:
                            pending.append(path)
                        continue
                    suffix = path.suffix.casefold()
                    if (not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE
                            or (tool == 'bandit' and suffix != '.py')
                            or (tool == 'gitleaks' and suffix not in _EXTENSIONS and path.name != '.env')):
                        skipped += 1
                        continue
                    raw = _bounded_read(path, root, MAX_FILE)
                    try:
                        text = raw.decode('utf-8-sig')
                    except UnicodeError:
                        skipped += 1
                        continue
                    if '\x00' in text:
                        skipped += 1
                        continue
                    total += len(raw)
                    if len(files) >= MAX_FILES or total > MAX_INPUT:
                        raise ValueError('Input exceeds 2,000 text files or 16 MiB; select a smaller directory.')
                    # Opaque names remove project configuration/plugin discovery
                    # and prevent filenames from becoming analyzer command options.
                    identity = f'{len(files):05d}' + ('.py' if suffix == '.py' else '.txt')
                    files[identity] = raw
                    mapping[identity] = plain_text(path.relative_to(root).as_posix())[:1000]
    if not files:
        raise ValueError('No eligible UTF-8 source files were found for this analyzer.')
    digest = hashlib.sha256()
    for name, content in sorted(files.items()):
        digest.update(mapping[name].encode() + b'\0' + hashlib.sha256(content).digest())
    return files, mapping, digest.hexdigest(), skipped


def make_iso(boot, initrd):
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge='1.09')
    content = dict(boot)
    content.pop('base.cpio.gz', None)
    content['initrd.gz'] = initrd
    content['isolinux.cfg'] = (b'DEFAULT analysis\nPROMPT 0\nTIMEOUT 1\nLABEL analysis\n'
                               b' KERNEL /kernel\n INITRD /initrd.gz\n'
                               b' APPEND console=ttyS0 quiet panic=1 rdinit=/init\n')
    try:
        for name, raw in content.items():
            iso.add_fp(io.BytesIO(raw), len(raw), iso_path='/' + name.upper() + ';1', rr_name=name)
        iso.add_eltorito('/ISOLINUX.BIN;1', boot_load_size=4, boot_info_table=True)
        buffer = io.BytesIO()
        iso.write_fp(buffer)
        return buffer.getvalue()
    finally:
        iso.close()


def parse_report(output, job):
    prefix = b'ANGERONA_REPORT:'
    lines = [line[len(prefix):] for line in output.splitlines() if line.startswith(prefix)]
    if len(lines) != 1 or len(lines[0]) > MAX_REPORT:
        raise ValueError('Missing, duplicate or oversized analyzer report.')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate analyzer report field.')
            result[key] = value
        return result
    report = json.loads(lines[0], object_pairs_hook=unique)
    if not isinstance(report, dict) or set(report) != {
        'schema', 'job', 'tool', 'input_sha256', 'catalog_sha256', 'findings', 'errors', 'isolation',
    }:
        raise ValueError('Unsupported analyzer report schema.')
    if type(report['schema']) is not int or report['schema'] != 1 or any(
        report[key] != job[key] for key in ('job', 'tool', 'input_sha256', 'catalog_sha256')
    ):
        raise ValueError('Analyzer report does not match this job.')
    isolation = report['isolation']
    if (not isinstance(isolation, dict)
            or set(isolation) != {'network', 'block_devices', 'host_shares'}
            or isolation['network'] != ['lo'] or isolation['block_devices'] not in ([], ['sr0'])
            or isolation['host_shares'] is not False):
        raise ValueError('Guest isolation check did not pass.')
    if type(report['errors']) is not int or not 0 <= report['errors'] <= MAX_FILES:
        raise ValueError('Invalid analyzer coverage count.')
    findings = report['findings']
    if not isinstance(findings, list) or len(findings) > MAX_FILES:
        raise ValueError('Too many analyzer findings.')
    for row in findings:
        if not isinstance(row, dict) or set(row) != {'file', 'rule', 'line', 'severity'}:
            raise ValueError('Unexpected analyzer finding fields.')
        if (not isinstance(row['file'], str) or row['file'] not in job['files']
                or not isinstance(row['rule'], str)
                or not re.fullmatch(r'B[0-9]{3}' if job['tool'] == 'bandit' else r'[a-z0-9-]{1,80}', row['rule'])
                or type(row['line']) is not int or not 1 <= row['line'] <= 1000000
                or not isinstance(row['severity'], str)
                or row['severity'] not in {'LOW', 'MEDIUM', 'HIGH'}):
            raise ValueError('Invalid analyzer finding location or rule.')
    return report


def _run(root, tool, files, mapping, digest, skipped, operation):
    operation.phase(300)
    if shutil.disk_usage(root).free < 128 * 1024**2:
        raise ValueError('Analysis needs at least 128 MiB of free space for its temporary boot image.')
    runs = root / 'runs'
    _ensure_directory(runs)
    if len(list(runs.iterdir())) >= 2:
        raise ValueError('Two interrupted analysis jobs need cleanup in the analysis runtime before another run.')
    identity = uuid.uuid4().hex
    job = {'job': identity, 'tool': tool, 'files': sorted(files), 'input_sha256': digest,
           'catalog_sha256': CATALOG_DIGEST}
    job_dir = runs / identity
    _ensure_directory(job_dir)
    with contextlib.ExitStack() as stack:
        stack.enter_context(_hold_plain_directories(root / 'appliance', job_dir))
        boot = {}
        for name, expected in OUTPUTS.items():
            path = root / 'appliance' / name
            _validate_regular_file(path)
            handle = stack.enter_context(_open_sealed(path))
            raw = handle.read(expected['size'] + 1)
            if len(raw) != expected['size'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
                raise ValueError('Analysis runtime changed; prepare the reviewed runtime again.')
            boot[name] = raw
        entries = {'input/' + name: (stat.S_IFREG | 0o444, raw) for name, raw in files.items()}
        entries['job.json'] = stat.S_IFREG | 0o444, json.dumps(job).encode()
        iso = make_iso(boot, boot['base.cpio.gz'] + compress(cpio(entries)))
        _atomic_bytes_write(job_dir / 'boot.iso', iso, root=root)
        _atomic_bytes_write(job_dir / 'analysis.vmx', analysis_vmware.configuration(identity).encode(), root=root)
        stack.enter_context(_open_sealed(job_dir / 'boot.iso'))
        verify_configuration = stack.enter_context(
            analysis_vmware.sealed_configuration(job_dir, identity)
        )
        operation.check()
        output = analysis_vmware.supervise(job_dir, identity, operation)
        operation.check()
        verify_configuration()
        report = parse_report(output, job)
    # Delete only files within this generated, reparse-checked job directory.
    # Keep a failed/interrupted job visible for operator cleanup, never follow aliases.
    remove_job_directory(root, job_dir)
    report.update(origin='external_analysis', tool_version=TOOLS[tool],
                  completed_at=int(time.time()), files=mapping, skipped=skipped,
                  file_count=len(files), response_authority=False)
    return report


def remove_job_directory(root, directory):
    """Delete only a generated job subtree, with every ancestor pinned against redirection."""
    root, directory = _absolute(Path(root)), _absolute(Path(directory))
    if directory.parent != root / 'runs' or not re.fullmatch('[0-9a-f]{32}', directory.name):
        raise ValueError('Refusing cleanup outside a generated analysis job.')
    remaining = [200]
    def remove(path, depth=0):
        if depth > 4:
            raise ValueError('Unexpected nested directory in analysis job.')
        with _hold_plain_directories(path):
            entries = list(path.iterdir())
            remaining[0] -= len(entries)
            if remaining[0] < 0:
                raise ValueError('Too many files in analysis job cleanup.')
            # Validate before removing any sibling; never follow links/reparse points.
            for item in entries:
                if _is_link_or_reparse(item.lstat()):
                    raise ValueError('Analysis job cleanup encountered a redirected path.')
            for item in entries:
                if item.is_dir():
                    remove(item, depth + 1)
                else:
                    _validate_regular_file(item)
                    item.unlink()
        path.rmdir()
    with _hold_plain_directories(root / 'runs'):
        remove(directory)


def clear_interrupted_jobs(root, operation):
    root = _absolute(Path(root))
    with transaction(root):
        runs = root / 'runs'
        if not runs.exists():
            return 'No interrupted jobs to clear.'
        with _hold_plain_directories(runs):
            directories = list(runs.iterdir())
            if len(directories) > 2:
                raise ValueError('Unexpected analysis job count; operator inspection is required.')
            with analysis_vmware.trusted_installation() as installation:
                for directory in directories:
                    operation.check()
                    if not re.fullmatch('[0-9a-f]{32}', directory.name):
                        raise ValueError('Unexpected directory in analysis jobs.')
                    _validate_chain(directory)
                    vmx = directory / 'analysis.vmx'
                    if vmx.exists():
                        _validate_regular_file(vmx)
                        analysis_vmware._control(installation, 'stop', vmx)
                    # Refuse to remove files still in use by a VM, regardless of control output.
                    import psutil
                    for process in psutil.process_iter(['name', 'cmdline']):
                        if process.info['name'] == 'vmware-vmx.exe' and any(
                            os.path.normcase(arg) == os.path.normcase(str(vmx))
                            for arg in (process.info['cmdline'] or [])
                        ):
                            raise ValueError('An analysis VM is still active; its files were retained.')
                    remove_job_directory(root, directory)
    return 'Interrupted analysis job copies cleared.'


def run_analysis(root, directory, tool, operation):
    root = _absolute(Path(root))
    with transaction(root):
        ready, reason = readiness(root)
        if not ready:
            raise ValueError(reason)
        reports = root / 'reports'
        _ensure_directory(reports)
        if len(list(reports.iterdir())) >= 100:
            raise ValueError('Analysis history is full. Export and remove older reports before another run.')
        files, mapping, digest, skipped = snapshot(directory, tool, operation, runtime_root=root)
        report = _run(root, tool, files, mapping, digest, skipped, operation)
        raw = json.dumps(report, ensure_ascii=True, sort_keys=True).encode()
        if len(raw) > MAX_REPORT:
            raise ValueError('Analysis receipt exceeds its byte limit.')
        operation.seal()
        _atomic_bytes_write(reports / (report['job'] + '.json'), raw, root=root)
        return report


def check_runtime(root, operation):
    root = _absolute(Path(root))
    with transaction(root):
        # A failed or cancelled explicit check must retire a previous success.
        # Readiness can only return after both current-profile fixtures pass.
        _atomic_bytes_write(root / 'selfcheck.json', json.dumps(
            {'catalog': CATALOG_DIGEST, 'tools': sorted(TOOLS), 'passed': False},
        ).encode(), root=root)
        analysis_vmware.installation()
        analysis_vmware.service_ready()
        # Inert fixtures exercise real analyzers; they cannot authorize response actions.
        fixtures = {'bandit': b'assert True\n',
                    'gitleaks': b'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";\n'}
        for tool, content in fixtures.items():
            name = '00000.py' if tool == 'bandit' else '00000.txt'
            digest = hashlib.sha256(content).hexdigest()
            report = _run(root, tool, {name: content}, {name: 'inert-selfcheck'}, digest, 0, operation)
            expected_rule = 'B101' if tool == 'bandit' else 'github-pat'
            if report['errors'] or not any(row['rule'] == expected_rule for row in report['findings']):
                raise ValueError('The appliance selfcheck did not produce its expected harmless finding.')
        operation.seal()
        _atomic_bytes_write(root / 'selfcheck.json', json.dumps(
            {'catalog': CATALOG_DIGEST, 'tools': sorted(TOOLS), 'passed': True},
        ).encode(), root=root)
    return readiness(root)


def history(root):
    root = _absolute(Path(root))
    directory = root / 'reports'
    if not directory.exists():
        return []
    rows = []
    with _hold_plain_directories(directory):
        paths = list(directory.iterdir())
        if len(paths) > 100:
            raise ValueError('Analysis history exceeds its entry limit.')
        for path in paths:
            if not re.fullmatch('[0-9a-f]{32}\\.json', path.name):
                raise ValueError('Unexpected file in analysis history.')
            row = json.loads(_bounded_read(path, root, MAX_REPORT))
            validate_receipt(row, path.stem)
            rows.append(row)
    return sorted(rows, key=lambda row: row['completed_at'], reverse=True)


def validate_receipt(row, identity):
    keys = {'schema', 'job', 'tool', 'input_sha256', 'catalog_sha256', 'findings', 'errors',
            'isolation', 'origin', 'tool_version', 'completed_at', 'files', 'skipped',
            'file_count', 'response_authority'}
    if (not isinstance(row, dict) or set(row) != keys or row['job'] != identity
            or not re.fullmatch('[0-9a-f]{32}', identity)
            or row['origin'] != 'external_analysis' or row['response_authority'] is not False
            or not isinstance(row['tool'], str) or row['tool'] not in TOOLS
            or row['tool_version'] != TOOLS[row['tool']]
            or not isinstance(row['files'], dict) or len(row['files']) > MAX_FILES
            or type(row['file_count']) is not int or row['file_count'] != len(row['files'])
            or type(row['skipped']) is not int or not 0 <= row['skipped'] <= 20000
            or type(row['completed_at']) is not int or not 0 <= row['completed_at'] < 2**40):
        raise ValueError('Invalid external-analysis receipt.')
    for field in ('input_sha256', 'catalog_sha256'):
        if not isinstance(row[field], str) or not re.fullmatch('[0-9a-f]{64}', row[field]):
            raise ValueError('Invalid analysis receipt identity.')
    for name, path in row['files'].items():
        if (not re.fullmatch('[0-9]{5}\\.(py|txt)', name) or not isinstance(path, str)
                or not 0 < len(path) <= 1000 or path != plain_text(path)
                or path.startswith(('/', '\\')) or '..' in path.split('/')):
            raise ValueError('Invalid analysis receipt file mapping.')
    guest = {key: row[key] for key in (
        'schema', 'job', 'tool', 'input_sha256', 'catalog_sha256', 'findings', 'errors', 'isolation',
    )}
    parse_report(b'ANGERONA_REPORT:' + json.dumps(guest).encode(), row)
