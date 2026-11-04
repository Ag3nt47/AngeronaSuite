"""Original stdlib-only source update publisher, snapshotted before STOP.

Only the closed immutable broker capsule may execute this module after source
publication begins. It imports no application, downloaded candidate or mutable
source-stage code. Source/user trust and parent-observed leases remain explicit.
"""
from __future__ import annotations
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from angerona.core import _source_tomli as tomllib
from typing import Mapping
from angerona.core.source_activation_file import (
    ActivationLock as ExclusiveFileLease, RetainedFile,
    directory_identity, plain_path, read_exact, write_new,
    private_owner_rights_directory,
)
from angerona.updater.source_git import read_source_git

MAX_METADATA = 16 * 1024**2
MAX_JOURNAL = 64 * 1024**2
MAX_FILES = 8192
MAX_FILE_BYTES = 16 * 1024**2
MAX_TREE_BYTES = 256 * 1024**2
MIN_FREE_BYTES = 2 * 1024**3
ORIGIN = 'https://github.com/Ag3nt47/AngeronaSuite.git'
_HEX32 = re.compile(r'[0-9a-f]{32}\Z')
_HEX40 = re.compile(r'[0-9a-f]{40}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_DECIMAL = re.compile(r'[0-9]{1,40}\Z')
_PLAN_SCHEMA = 'angerona.source-activation-plan/v1'
_REQUEST_SCHEMA = 'angerona.source-activation-request/v1'
_BASE_SCHEMA = 'angerona.source-applied-base/v1'
_CONTEXT_KEYS = frozenset(('schema', 'launch_id', 'source_root', 'state_root',
    'supervisor_pid', 'supervisor_birth', 'supervisor_image', 'token',
    'broker_pid', 'broker_birth', 'broker_image', 'core_pid', 'core_birth',
    'core_image', 'owner_state'))

_PLAN_KEYS = frozenset(('schema', 'source_root', 'state_root', 'root_identity', 'origin',
    'stage_id', 'manifest_sha256', 'resolution_sha256', 'target_revision', 'base_revision',
    'git', 'before', 'after', 'original_inventory_sha256', 'upstream', 'changed_paths',
    'preserved_changes', 'protected_data', 'runtime_contract', 'provenance', 'applied_base', 'broker_snapshot', 'plan_nonce', 'storage_reserve_bytes', 'source_reserve_bytes', 'activation_id'))

_GUARD_KEYS = frozenset(('schema', 'operation', 'guard_nonce', 'launch_id', 'activation_id',
    'plan_sha256', 'request_sha256', 'owner_sha256', 'source_root', 'state_root',
    'parent_pid', 'parent_birth', 'parent_image', 'parent_script_sha256',
    'root_identity', 'leases', 'retirement', 'snapshot_sha256'))
_REQUEST_KEYS = frozenset(('schema', 'activation_id', 'plan_sha256', 'approval_id',
    'source_root', 'state_root', 'launch_id', 'owner_sha256', 'core_pid', 'core_birth',
    'broker_pid', 'broker_birth', 'retirement_scope', 'accepted'))



_PENDING_SCHEMA = 'angerona.source-activation-pending/v1'
_TRANSACTION_SCHEMA = 'angerona.source-activation-transaction/v1'



class SourceActivationError(RuntimeError):
    """A source update remains unactivated; preserve originals and evidence."""

def _sha(raw):
    return hashlib.sha256(raw).hexdigest()

def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')

def _object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise SourceActivationError('Duplicate source activation metadata field')
        result[name] = value
    return result

def _json(raw):
    if not 0 < len(raw) <= MAX_METADATA:
        raise SourceActivationError('Source activation metadata exceeds its bound')
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_object,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise SourceActivationError('Source activation metadata is invalid') from error
    if type(value) is not dict:
        raise SourceActivationError('Source activation metadata must be an object')
    return value

def _read_json(path, *, absent=None):
    if not os.path.lexists(path):
        return absent
    return _json(read_exact(path, MAX_METADATA))

def _new_json(path, value):
    raw = _encoded(value)
    if len(raw) > MAX_METADATA:
        raise SourceActivationError('Source activation metadata exceeds its bound')
    write_new(path, raw)
    return _sha(raw)

def _root(value):
    return _stage_module()._physical_source_root(Path(value))

def _state(value, *, create=False):
    path = Path(os.path.abspath(value))
    from angerona.core.startup_recovery import private_directory
    if create and not os.path.lexists(path):
        plain_path(path.parent, directory=True)
        if not private_directory(path, create=True):
            raise SourceActivationError('Source update state could not be created privately')
    plain_path(path, directory=True)
    if not private_directory(path, create=False) and not private_owner_rights_directory(path):
        raise SourceActivationError('Source update state lacks private directory custody')
    return path

def _operation(state, activation_id, *, create=False):
    if type(activation_id) is not str or not _HEX32.fullmatch(activation_id):
        raise SourceActivationError('Source activation identity is invalid')
    parent = state / 'activations'
    path = parent / ('apply-' + activation_id)
    if create:
        _state(parent, create=True)
        if not os.path.lexists(path):
            count = 0
            with os.scandir(parent) as entries:
                for item in entries:
                    terminal = (_read_json(Path(item.path) / 'committed.json')
                                or _read_json(Path(item.path) / 'rolled-back.json'))
                    if terminal is None:
                        count += 1
                    if count >= 16:
                        raise SourceActivationError('Retained incomplete activation plan limit reached; review existing candidates')
                    if re.fullmatch(r'apply-[0-9a-f]{32}', item.name) is None:
                        raise SourceActivationError('Unknown activation state must be preserved')
                    plain_path(Path(item.path), directory=True)
        _state(path, create=True)
    else:
        _state(parent)
        _state(path)
    return path

def _tree_digest(files):
    # Same byte format as the original source-stage capture, not a new digest.
    return _sha(json.dumps({name: _sha(raw) for name, raw in files.items()},
                           sort_keys=True).encode())

def _manifest(files):
    return {name: {'sha256': _sha(raw), 'bytes': len(raw)}
            for name, raw in sorted(files.items())}

def _optional_file(path, maximum=MAX_METADATA):
    if not os.path.lexists(path):
        return {'present': False}
    with RetainedFile(path) as held:
        raw = held.read(maximum)
        return {'present': True, 'sha256': _sha(raw), 'bytes': len(raw),
                'identity': held.initial}

def _git_binding(root):
    stage = _stage_module()
    head = stage.local_source_revision(root)
    if not _HEX40.fullmatch(head):
        raise SourceActivationError('Exact canonical Git origin and HEAD are unavailable')
    raw = stage._git(root, ['rev-parse', '--git-path', 'index'])
    if len(raw) > 4096:
        raise SourceActivationError('Git index location exceeds its bound')
    try:
        index_name = raw.decode('utf-8', errors='strict').strip()
    except UnicodeError as error:
        raise SourceActivationError('Git index location is invalid') from error
    if not index_name or '\x00' in index_name or '\n' in index_name or '\r' in index_name:
        raise SourceActivationError('Git index location is ambiguous')
    index = Path(index_name)
    if not index.is_absolute():
        index = root / index
    index = Path(os.path.abspath(index))
    plain_path(index.parent, directory=True)
    head_file = index.parent / 'HEAD'
    captured_head = _optional_file(head_file, 4096)
    if not captured_head['present']:
        raise SourceActivationError('The actual Git-directory HEAD object is unavailable')
    return {'origin': ORIGIN, 'head': head, 'index_path': str(index),
            'index': _optional_file(index), 'head_path': str(head_file), 'head_file': captured_head}

def _protected_data(state):
    data = state.parent
    return {name: _optional_file(data / name) for name in ('settings.json', 'bus.key', 'shutdown.key')}

def _dependency_contract(files):
    selected = {}
    for name, raw in files.items():
        parts = Path(name).parts
        leaf = parts[-1].casefold()
        if (leaf.startswith(('requirements', 'constraints')) and leaf.endswith(('.txt', '.lock'))
                or name in {'uv.lock', 'poetry.lock', 'requirements.lock'}
                or name.startswith('release/locks/')):
            selected[name] = _sha(raw)
    raw = files.get('pyproject.toml')
    if raw is not None:
        try:
            document = tomllib.loads(raw.decode('utf-8', errors='strict'))
            project = document.get('project', {})
            if type(project) is not dict:
                raise ValueError
            selected['pyproject-runtime-contract'] = _sha(_encoded({
                'requires-python': project.get('requires-python'),
                'dependencies': project.get('dependencies'),
                'optional-dependencies': project.get('optional-dependencies'),
                'build-system': document.get('build-system'),
                'scripts': project.get('scripts'), 'gui-scripts': project.get('gui-scripts')}))
        except (UnicodeError, ValueError, TypeError, RecursionError) as error:
            raise SourceActivationError('The effective runtime dependency contract is invalid') from error
    return selected

def _digest_text(value, pattern=_HEX64):
    return type(value) is str and pattern.fullmatch(value) is not None

def _file_manifest(value):
    if type(value) is not dict or len(value) > MAX_FILES:
        raise SourceActivationError('Source activation inventory is invalid')
    total = 0
    for name, row in value.items():
        if (_stage_module().safe_relative(name) != name or type(row) is not dict
                or set(row) != {'sha256', 'bytes'} or not _digest_text(row['sha256'])
                or type(row['bytes']) is not int or not 0 <= row['bytes'] <= MAX_FILE_BYTES):
            raise SourceActivationError('Source activation file manifest is invalid')
        total += row['bytes']
    if total > MAX_TREE_BYTES:
        raise SourceActivationError('Source activation inventory exceeds its byte bound')
    _stage_module()._validate_tree({name: b'' for name in value})
    return value

def _load_plan(root, state, activation_id, plan_sha256):
    if not _digest_text(plan_sha256):
        raise SourceActivationError('Source activation plan digest is invalid')
    operation = _operation(state, activation_id)
    raw = read_exact(operation / 'plan.json', MAX_METADATA)
    plan = _json(raw)
    if (_sha(raw) != plan_sha256 or set(plan) != _PLAN_KEYS
            or plan['schema'] != _PLAN_SCHEMA or plan['activation_id'] != activation_id
            or not _digest_text(plan['plan_nonce'], _HEX32)
            or type(plan['storage_reserve_bytes']) is not int
            or type(plan['source_reserve_bytes']) is not int
            or not 0 < plan['source_reserve_bytes'] <= plan['storage_reserve_bytes']
            or not 0 < plan['storage_reserve_bytes'] <= 3 * MAX_TREE_BYTES + MAX_JOURNAL + 2 * MAX_METADATA + 4 * 1024**2
            or plan['source_root'] != str(root) or plan['state_root'] != str(state)
            or plan['root_identity'] != directory_identity(root) or plan['origin'] != ORIGIN
            or type(plan['stage_id']) is not str or re.fullmatch(r'source-[0-9a-f]{32}', plan['stage_id']) is None
            or not _digest_text(plan['target_revision'], _HEX40)
            or not _digest_text(plan['base_revision'], _HEX40)
            or not all(_digest_text(plan[key]) for key in (
                'manifest_sha256', 'resolution_sha256', 'original_inventory_sha256'))):
        raise SourceActivationError('Source activation plan identity changed')
    body = dict(plan)
    body.pop('activation_id')
    if _sha(_encoded(body))[:32] != activation_id:
        raise SourceActivationError('Source activation plan content identity changed')
    if (type(plan['git']) is not dict or set(plan['git']) != {
            'origin', 'head', 'index_path', 'index', 'head_path', 'head_file'}
            or plan['git']['origin'] != ORIGIN or not _digest_text(plan['git']['head'], _HEX40)
            or not all(type(plan['git'][key]) is str and Path(plan['git'][key]).is_absolute()
                       for key in ('index_path', 'head_path'))
            or Path(plan['git']['head_path']) != Path(plan['git']['index_path']).parent / 'HEAD'):
        raise SourceActivationError('Source activation Git binding is invalid')
    if (type(plan['broker_snapshot']) is not dict or set(plan['broker_snapshot']) != {'schema', 'files'}
            or plan['broker_snapshot']['schema'] != 'angerona.source-activation-broker-snapshot/v1'
            or set(plan['broker_snapshot']['files']) != set(BROKER_FILES)):
        raise SourceActivationError('Original source broker allowlist is invalid')
    before, after = _file_manifest(plan['before']), _file_manifest(plan['after'])
    expected = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
    if type(plan['changed_paths']) is not list or plan['changed_paths'] != expected or not expected:
        raise SourceActivationError('Source activation change set is inconsistent')
    if (type(plan['preserved_changes']) is not int or not 0 <= plan['preserved_changes'] <= MAX_FILES
            or type(plan['upstream']) is not dict or len(plan['upstream']) > MAX_FILES):
        raise SourceActivationError('Source activation lineage is invalid')
    for name in expected:
        if Path(name).parts[0].casefold() in {'.git', 'venv', '.venv', '.tmp', 'angeronadata'}:
            raise SourceActivationError('Source activation change escaped its code boundary')
    for name, digest in plan['upstream'].items():
        if _stage_module().safe_relative(name) != name or not _digest_text(digest):
            raise SourceActivationError('Source activation upstream inventory is invalid')
    return operation, plan

class _NativeProcess:
    """One query/synchronize handle; no process actions or numeric close retries."""
    _close_holds = []

    def __init__(self, pid, birth, image):
        if self._close_holds:
            raise SourceActivationError('Prior source-controller native retirement remains held')
        import ctypes
        from ctypes import wintypes as w
        if (os.name != 'nt' or type(pid) is not int or not 0 < pid <= 0xffffffff
                or type(birth) is not str or not _DECIMAL.fullmatch(birth)
                or type(image) is not str or not Path(image).is_absolute()):
            raise SourceActivationError('Exact native source-controller identity is unavailable')
        self.pid, self.birth, self.image = pid, birth, image
        self.handle, self.close_held = None, False
        self.api = api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.OpenProcess.argtypes, api.OpenProcess.restype = (w.DWORD, w.BOOL, w.DWORD), w.HANDLE
        api.GetProcessTimes.argtypes = (w.HANDLE, ctypes.POINTER(w.FILETIME),
            ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME))
        api.GetProcessTimes.restype = w.BOOL
        api.QueryFullProcessImageNameW.argtypes = (w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD))
        api.QueryFullProcessImageNameW.restype = w.BOOL
        api.WaitForSingleObject.argtypes, api.WaitForSingleObject.restype = (w.HANDLE, w.DWORD), w.DWORD
        api.CloseHandle.argtypes, api.CloseHandle.restype = (w.HANDLE,), w.BOOL
        self.handle = api.OpenProcess(0x00101000, False, pid)
        if not self.handle:
            raise SourceActivationError('Source controller native query handle is unavailable')
        try:
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        import ctypes
        from ctypes import wintypes as w
        if self.close_held or not self.handle or self.api.WaitForSingleObject(self.handle, 0) != 258:
            raise SourceActivationError('Source controller generation is not live')
        fields = [w.FILETIME() for _ in range(4)]
        if not self.api.GetProcessTimes(self.handle, *(ctypes.byref(x) for x in fields)):
            raise SourceActivationError('Source controller raw birth is unavailable')
        birth = str((fields[0].dwHighDateTime << 32) | fields[0].dwLowDateTime)
        length, buffer = w.DWORD(32768), ctypes.create_unicode_buffer(32768)
        if not self.api.QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(length)):
            raise SourceActivationError('Source controller native image is unavailable')
        if (birth != self.birth or os.path.normcase(os.path.normpath(buffer.value))
                != os.path.normcase(os.path.normpath(self.image))
                or self.api.WaitForSingleObject(self.handle, 0) != 258):
            raise SourceActivationError('Source controller native generation changed')

    def close(self):
        if self.close_held:
            raise SourceActivationError('Source controller native handle retirement is held')
        handle, self.handle = self.handle, None
        if handle:
            try:
                if not self.api.CloseHandle(handle):
                    raise SourceActivationError('Source controller native handle close failed')
            except BaseException:
                self.close_held = True
                self._close_holds.append((self, handle))
                raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

def _context(root, state, value, *, require_core=True, native_broker=True):
    if (type(value) is not dict or set(value) != _CONTEXT_KEYS
            or type(value['schema']) is not int or value['schema'] != 1
            or value['source_root'] != str(root) or value['state_root'] != str(state)
            or not _digest_text(value['launch_id'], _HEX32) or not _digest_text(value['token'])
            or value['owner_state'] != 'bound'):
        raise SourceActivationError('No bound canonical source-update controller is available')
    for prefix in ('supervisor', 'broker', 'core'):
        if (type(value[prefix + '_pid']) is not int or not 0 < value[prefix + '_pid'] <= 0xffffffff
                or type(value[prefix + '_birth']) is not str
                or not _DECIMAL.fullmatch(value[prefix + '_birth'])
                or type(value[prefix + '_image']) is not str
                or not Path(value[prefix + '_image']).is_absolute()):
            raise SourceActivationError('Source-update controller context is malformed')
    system_ps = 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
    if any(os.path.normcase(os.path.normpath(value[prefix + '_image']))
           != os.path.normcase(os.path.normpath(system_ps)) for prefix in ('supervisor', 'broker')):
        raise SourceActivationError('Source-update controller image is not the fixed system host')
    with (_NativeProcess(value['broker_pid'], value['broker_birth'], value['broker_image'])
          if native_broker else contextlib.nullcontext()):
        if require_core:
            if value['core_pid'] != os.getpid():
                raise SourceActivationError('Source-update consent is not from the bound dashboard')
            with _NativeProcess(value['core_pid'], value['core_birth'], value['core_image']):
                pass
    return value

def _request(root, state, activation_id, plan_sha256, request_sha256):
    path = state / 'activation-request.json'
    if not os.path.lexists(path):
        pending = _read_json(state / 'activation-pending.json')
        if (type(pending) is not dict or pending.get('activation_id') != activation_id
                or pending.get('request_sha256') != request_sha256):
            raise SourceActivationError('The approved source activation request is absent')
        path = _operation(state, activation_id) / 'requests' / (request_sha256 + '.json')
    raw = read_exact(path, MAX_METADATA)
    request = _json(raw)
    if (not _digest_text(request_sha256) or _sha(raw) != request_sha256
            or set(request) != _REQUEST_KEYS or request['schema'] != _REQUEST_SCHEMA
            or request['activation_id'] != activation_id or request['plan_sha256'] != plan_sha256
            or request['source_root'] != str(root) or request['state_root'] != str(state)
            or request['accepted'] is not True or not _digest_text(request['approval_id'], _HEX32)
            or not _digest_text(request['launch_id'], _HEX32) or not _digest_text(request['owner_sha256'])):
        raise SourceActivationError('The exact approved activation request is invalid')
    scope = request['retirement_scope']
    if type(scope) is not list or not 1 <= len(scope) <= 16:
        raise SourceActivationError('The approved retirement closure is invalid')
    seen = set()
    for row in scope:
        if (type(row) is not dict or set(row) != {'pid', 'birth', 'image', 'role'}
                or type(row['pid']) is not int or not 0 < row['pid'] <= 0xffffffff
                or row['pid'] in seen or type(row['birth']) is not str
                or not _DECIMAL.fullmatch(row['birth']) or type(row['image']) is not str
                or not Path(row['image']).is_absolute() or type(row['role']) is not str
                or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', row['role'])):
            raise SourceActivationError('An approved retirement generation is invalid')
        seen.add(row['pid'])
    if (request['broker_pid'] in seen or not any(row['role'] == 'core' and
            (row['pid'], row['birth']) == (request['core_pid'], request['core_birth']) for row in scope)):
        raise SourceActivationError('The approved retirement closure confuses Core and external controller')
    return request

class SourceActivationGuard:
    """Pinned real parent observation, not an independent attestation of leases.

    The canonical PS parent actually acquires the three leases and observes all
    approved generations retired. This child checks its exact native parent,
    current request/context and single-use private assertion before each effect.
    A compromised process under the same SID remains outside this custody model.
    """
    def __init__(self, root, state, activation_id, plan_sha256, request_sha256,
                 guard_file, guard_sha256, *, operation):
        self.root, self.state = root, state
        self.retained = self.parent = None
        self.progress = None
        self.progress_close_failure = None
        self.guard_path = plain_path(guard_file)
        if self.guard_path.parent != _operation(state, activation_id):
            raise SourceActivationError('Activation guard is outside its exact private operation')
        self.retained = RetainedFile(self.guard_path)
        try:
            raw = self.retained.read(MAX_METADATA)
            value = _json(raw)
            if (not _digest_text(guard_sha256) or _sha(raw) != guard_sha256
                    or set(value) != _GUARD_KEYS or type(value['schema']) is not int or value['schema'] != 1
                    or value['operation'] != operation or operation not in {'activate', 'reconcile'}
                    or not _digest_text(value['guard_nonce'], _HEX32)
                    or value['activation_id'] != activation_id or value['plan_sha256'] != plan_sha256
                    or value['request_sha256'] != request_sha256
                    or value['source_root'] != str(root) or value['state_root'] != str(state)
                    or value['root_identity'] != directory_identity(root)
                    or value['leases'] != {'runtime': True, 'source_helper': True, 'core': True,
                        'no_pending_repair': True, 'no_active_venv': True}
                    or any(type(x) is not bool for x in value['leases'].values())):
                raise SourceActivationError('The pinned source update guard is invalid')
            request = _request(root, state, activation_id, plan_sha256, request_sha256)
            owner_raw = read_exact(state / 'activation-owner.json', MAX_METADATA)
            owner = _context(root, state, _json(owner_raw), require_core=False, native_broker=operation == 'activate')
            retirement = value['retirement']
            if (value['owner_sha256'] != _sha(owner_raw) or value['owner_sha256'] != request['owner_sha256']
                    or value['launch_id'] != owner['launch_id'] or value['launch_id'] != request['launch_id']
                    or value['parent_pid'] != os.getppid()
                    or (operation == 'activate' and (value['parent_pid'], value['parent_birth'], value['parent_image'])
                        != (owner['broker_pid'], owner['broker_birth'], owner['broker_image']))
                    or request['broker_pid'] != owner['broker_pid'] or request['broker_birth'] != owner['broker_birth']
                    or type(retirement) is not dict or set(retirement) != {
                        'core_pid', 'core_birth', 'core_exit_code', 'complete', 'gaps', 'stop_receipt_sha256', 'core_retired_sha256'}
                    or {key: item for key, item in retirement.items() if key not in {'stop_receipt_sha256', 'core_retired_sha256'}} != {
                        'core_pid': request['core_pid'], 'core_birth': request['core_birth'],
                        'core_exit_code': 0, 'complete': True, 'gaps': []}
                    or not _digest_text(retirement['stop_receipt_sha256'])
                    or not _digest_text(retirement['core_retired_sha256'])
                    or type(retirement['core_exit_code']) is not int or type(retirement['complete']) is not bool):
                raise SourceActivationError('Exact canonical parent or actual retirement assertion changed')
            _, exact_plan = _load_plan(root, state, activation_id, plan_sha256)
            expected_ps = os.path.normcase(os.path.normpath(owner['broker_image']))
            if os.path.normcase(os.path.normpath(value['parent_image'])) != expected_ps:
                raise SourceActivationError('The activation parent is not the fixed system host')
            snapshot_raw = read_exact(_operation(state, activation_id) / 'broker' / 'snapshot.json', MAX_METADATA)
            if _sha(snapshot_raw) != value['snapshot_sha256'] or _json(snapshot_raw) != exact_plan['broker_snapshot']:
                raise SourceActivationError('The immutable original broker snapshot changed')
            if operation == 'reconcile':
                script_name = 'tools/Resume-AngeronaSourceActivation.ps1'
                script = read_exact(_operation(state, activation_id) / 'broker' / script_name, MAX_FILE_BYTES)
                allowed_scripts = {exact_plan['broker_snapshot']['files'][script_name]['sha256']}
            else:
                script_name = 'tools/Invoke-AngeronaSourceStartup.ps1'
                script = read_exact(root / script_name, MAX_FILE_BYTES)
                allowed_scripts = {row['sha256'] for manifest in (exact_plan['before'], exact_plan['after'])
                    if (row := manifest.get(script_name)) is not None}
            if _sha(script) != value['parent_script_sha256'] or value['parent_script_sha256'] not in allowed_scripts:
                raise SourceActivationError('The canonical activation parent script is not pinned')
            stop_raw = read_exact(state.parent / 'diagnostics' / 'operator-stop.json', MAX_METADATA)
            stop = _json(stop_raw)
            binding = {'launch_id': request['launch_id'], 'activation_id': activation_id,
                       'request_sha256': request_sha256, 'core_pid': request['core_pid'], 'core_birth': request['core_birth']}
            if (_sha(stop_raw) != retirement['stop_receipt_sha256']
                    or set(stop) != {'schema', 'state', 'operator_stop_recorded', 'pending_workers', 'pending_custody',
                        'before_cleanup_pending', 'tracked_workers', 'cleanup_error', 'discovery_error',
                        'scope', 'forced', 'epoch', 'source_activation'}
                    or type(stop['schema']) is not int or stop['schema'] != 1 or stop['state'] != 'retired'
                    or stop['operator_stop_recorded'] is not True or stop['forced'] is not False
                    or stop['pending_workers'] != [] or stop['pending_custody'] != []
                    or type(stop['before_cleanup_pending']) is not int or stop['before_cleanup_pending'] != 0
                    or stop['cleanup_error'] != '' or stop['discovery_error'] != ''
                    or stop['source_activation'] != binding):
                raise SourceActivationError('The exact managed STOP receipt is not clean and bound')
            retired_path = state / 'launches' / request['launch_id'] / 'core-retired.json'
            retired_raw = read_exact(retired_path, MAX_METADATA)
            retired = _json(retired_raw)
            if (_sha(retired_raw) != retirement['core_retired_sha256'] or set(retired) != {
                    'schema', 'launch_id', 'core_pid', 'core_birth', 'core_exit_code', 'native_wait0', 'owner_sha256'}
                    or retired != {'schema': 'angerona.source-activation-core-retired/v1',
                        'launch_id': request['launch_id'], 'core_pid': request['core_pid'], 'core_birth': request['core_birth'],
                        'core_exit_code': 0, 'native_wait0': True, 'owner_sha256': request['owner_sha256']}
                    or type(retired['core_exit_code']) is not int or type(retired['native_wait0']) is not bool):
                raise SourceActivationError('Original retained Core exit observation is unavailable')
            self.retired_raw, self.retired_path = retired_raw, retired_path
            self.stop_raw = stop_raw
            self.value, self.request, self.raw, self.owner_raw = value, request, raw, owner_raw
            self.parent = _NativeProcess(value['parent_pid'], value['parent_birth'], value['parent_image'])
        except BaseException:
            self.close()
            raise

    def claim(self):
        self.check()
        operation = _operation(self.state, self.value['activation_id'])
        _new_json(operation / ('guard-used-' + self.value['guard_nonce'] + '.json'), {
            'guard_sha256': _sha(self.raw), 'operation': self.value['operation']})

    def attach_progress(self):
        from angerona.resilience.heartbeat import OptionalHeartbeatWriter
        self.progress = OptionalHeartbeatWriter('activation_broker', self.state.parent,
            self.request['launch_id'], guard_nonce=self.value['guard_nonce'])
        launch = _state(self.state / 'launches' / self.request['launch_id'])
        image = _native_self_image()
        _new_json(launch / ('publisher-' + self.value['guard_nonce'] + '.json'), {
            'schema': 'angerona.source-activation-publisher/v1', 'launch_id': self.request['launch_id'],
            'activation_id': self.value['activation_id'], 'guard_nonce': self.value['guard_nonce'],
            'request_sha256': self.value['request_sha256'], 'pid': os.getpid(),
            'birth_ticks': self.progress.birth_ticks, 'image': image,
            'component': self.progress.component, 'slot': 'activation_broker.hb'})

    def progress_beat(self):
        if self.progress_close_failure is not None:
            raise SourceActivationError('Publisher progress observer cleanup remains held')
        if self.progress is not None:
            self.progress.beat()

    def finish_progress(self):
        if self.progress_close_failure is not None:
            raise SourceActivationError('Publisher progress observer cleanup remains held')
        writer, self.progress = self.progress, None
        if writer is not None:
            try:
                writer.close()
            except BaseException as error:
                self.progress_close_failure = error
                raise SourceActivationError('Publisher progress observer cleanup remains held') from error

    def check(self):
        self.progress_beat()
        self.retained.check()
        self.parent.check()
        if (directory_identity(self.root) != self.value['root_identity']
                or read_exact(self.state / 'activation-owner.json', MAX_METADATA) != self.owner_raw
                or read_exact(self.state.parent / 'diagnostics' / 'operator-stop.json', MAX_METADATA) != self.stop_raw
                or read_exact(self.retired_path, MAX_METADATA) != self.retired_raw
                or _request(self.root, self.state, self.value['activation_id'],
                    self.value['plan_sha256'], self.value['request_sha256']) != self.request):
            raise SourceActivationError('Source update parent/request/root changed during publication')

    def close(self):
        errors = []
        try:
            self.finish_progress()
        except BaseException as error:
            errors.append(error)
        for field in ('parent', 'retained'):
            obj = getattr(self, field, None)
            setattr(self, field, None)
            if obj is not None:
                try:
                    obj.close()
                except BaseException as error:
                    errors.append(error)
        if errors:
            raise SourceActivationError('Source update guard retirement remains held') from errors[0]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

def _journal_append(journal, row):
    tail = getattr(journal, '_activation_tail', None)
    if tail is None:
        previous = _journal_read(journal)
        tail = (len(previous), previous[-1]['sha256'] if previous else '')
    entry = {'sequence': tail[0] + 1, 'previous': tail[1], 'event': row}
    entry['sha256'] = _sha(_encoded(entry))
    journal.append(_encoded(entry) + b'\n', MAX_JOURNAL)
    journal._activation_tail = (entry['sequence'], entry['sha256'])
    return entry

def _journal_read(journal):
    raw = journal.read(MAX_JOURNAL)
    if raw and not raw.endswith(b'\n'):
        raise SourceActivationError('The source update journal is truncated')
    if raw.count(b'\n') > MAX_FILES * 12 + 64:
        raise SourceActivationError('The source update journal exceeds its record bound')
    result = []
    for line in raw.splitlines():
        value = _json(line)
        if (set(value) != {'sequence', 'previous', 'event', 'sha256'}
                or type(value['sequence']) is not int or value['sequence'] != len(result) + 1
                or value['previous'] != (result[-1]['sha256'] if result else '')
                or type(value['event']) is not dict):
            raise SourceActivationError('The source update journal continuity is invalid')
        digest = value.pop('sha256')
        if _sha(_encoded(value)) != digest:
            raise SourceActivationError('The source update journal digest is invalid')
        value['sha256'] = digest
        result.append(value)
    return result

def _same_object(path, stamp, digest=None):
    if stamp is None:
        return not os.path.lexists(path)
    if not os.path.lexists(path):
        return False
    with RetainedFile(path) as retained:
        return retained.initial == stamp and (digest is None or _sha(retained.read(MAX_FILE_BYTES)) == digest)

def _verify_tree(root, expected, *, retained=None, recovery_coherence=False):
    stage = _stage_module()
    paths = tuple(sorted(set(stage.source_inventory(root)) | set(expected)))
    if retained is None:
        actual = stage.snapshot_local(root, paths)
    else:
        by_path = {item.path: item for item in retained}
        actual = {}
        for name in paths:
            path = root / name
            if not os.path.lexists(path):
                continue
            item = by_path.get(path)
            if item is None:
                raise SourceActivationError('An unknown source object appeared during publication')
            actual[name] = item.read(MAX_FILE_BYTES)
    if _manifest(actual) != expected:
        raise SourceActivationError('Source activation whole-tree postcondition changed')
    if recovery_coherence:
        from angerona.core.startup_recovery import RecoveryCoherenceError, verify_recovery_coherence
        try:
            verify_recovery_coherence(actual)
        except RecoveryCoherenceError as error:
            raise SourceActivationError("Actual source recovery coherence is unverified; source remains held") from error

def _base_document(plan, plan_sha256, request_sha256, transaction_sha256, previous_sha256):
    return {'schema': _BASE_SCHEMA, 'activation_id': plan['activation_id'],
            'plan_sha256': plan_sha256, 'request_sha256': request_sha256,
            'source_root': plan['source_root'], 'root_identity': plan['root_identity'], 'origin': ORIGIN,
            'original_head': plan['git']['head'], 'target_revision': plan['target_revision'],
            'upstream': plan['upstream'], 'effective_paths': sorted(plan['after']), 'transaction_sha256': transaction_sha256,
            'previous_base_sha256': previous_sha256}

def _parents_for_changes(root, changes):
    existing, missing = {}, set()
    for name in changes:
        parent = (root / name).parent
        chain = []
        while parent != root:
            chain.append(parent)
            parent = parent.parent
        for directory in reversed(chain):
            relative = directory.relative_to(root).as_posix()
            if os.path.lexists(directory):
                existing[relative] = directory_identity(directory)
            else:
                missing.add(relative)
    return existing, sorted(missing, key=lambda name: (len(Path(name).parts), name))

def _directory_fences(root, transaction, made):
    if directory_identity(root) != transaction['root_identity']:
        raise SourceActivationError('Source root changed during publication')
    if directory_identity(root / transaction['workspace']['relative']) != transaction['workspace']['identity']:
        raise SourceActivationError('Source publication workspace changed native generation')
    for name, stamp in {**transaction['parents'], **made}.items():
        if directory_identity(root / name) != stamp:
            raise SourceActivationError('Source update parent directory changed')

def _retain_workspace(stack, workspace):
    from angerona.core.source_activation_storage import _OwnedDirectory, _stamp
    for path in (workspace.parent.parent, workspace.parent, workspace,
                 *(workspace / leaf for leaf in ('new', 'old', 'rolled-back'))):
        stack.enter_context(_OwnedDirectory(path, _stamp(path), delete_access=False))


def _prepare_transaction(root, state, operation, plan, original, candidate, guard, stack):
    from angerona.core.source_activation_workspace import create_workspace, validate_workspace
    descriptor = create_workspace(root, state, plan, _sha(_encoded(plan)))
    workspace, descriptor = validate_workspace(root, state, plan, _sha(_encoded(plan)), descriptor)
    _retain_workspace(stack, workspace)
    _state(operation / 'archive', create=True)
    held, before_ids = {}, {}
    for name in sorted(original):
        guard.check()
        item = stack.enter_context(RetainedFile(root / name, mutation=name in plan['changed_paths']))
        if item.read(MAX_FILE_BYTES) != original[name]:
            raise SourceActivationError('Source changed before retained transaction admission')
        held[name], before_ids[name] = item, item.initial
        archive = operation / 'archive' / _sha(original[name])
        if os.path.lexists(archive):
            if read_exact(archive, MAX_FILE_BYTES) != original[name]:
                raise SourceActivationError('A retained source backup changed')
        else:
            write_new(archive, original[name])
    head = stack.enter_context(RetainedFile(plan['git']['head_path']))
    if head.initial != plan['git']['head_file']['identity'] or _sha(head.read(4096)) != plan['git']['head_file']['sha256']:
        raise SourceActivationError('The retained Git HEAD object changed')
    if plan['git']['index']['present']:
        index = stack.enter_context(RetainedFile(plan['git']['index_path']))
        if (index.initial != plan['git']['index']['identity']
                or _sha(index.read(MAX_METADATA)) != plan['git']['index']['sha256']):
            raise SourceActivationError('The retained Git index changed')
    new_held, new_ids = {}, {}
    for number, name in enumerate(plan['changed_paths']):
        if name in candidate:
            path = workspace / 'new' / str(number)
            write_new(path, candidate[name])
            item = stack.enter_context(RetainedFile(path, mutation=True))
            if item.read(MAX_FILE_BYTES) != candidate[name]:
                raise SourceActivationError('The staged source update changed')
            new_held[name], new_ids[name] = item, item.initial
    parents, directories = _parents_for_changes(root, plan['changed_paths'])
    transaction = {'schema': _TRANSACTION_SCHEMA, 'activation_id': plan['activation_id'],
                   'source_root': str(root), 'state_root': str(state), 'root_identity': directory_identity(root),
                   'before_ids': before_ids, 'new_ids': new_ids, 'parents': parents, 'changed_paths': plan['changed_paths'],
                   'workspace': descriptor,
                   'planned_directories': directories, 'previous_base': plan['applied_base']}
    raw = _encoded(transaction)
    write_new(operation / 'transaction.json', raw)
    write_new(operation / 'journal.jsonl', b'')
    journal = stack.enter_context(RetainedFile(operation / 'journal.jsonl', writable=True))
    return transaction, _sha(raw), held, new_held, journal

def _pending(state, operation, activation_id, plan_sha256, request_sha256, transaction_sha256):
    value = {'schema': _PENDING_SCHEMA, 'activation_id': activation_id, 'plan_sha256': plan_sha256,
             'request_sha256': request_sha256, 'transaction_sha256': transaction_sha256,
             'source_root': str(_json(read_exact(operation / 'plan.json', MAX_METADATA))['source_root'])}
    path = state / 'activation-pending.json'
    _new_json(path, value)  # Immutable and continuously present across every source effect.
    return value

def _exact_pending(root, state, operation, activation_id, plan_sha256, request_sha256):
    value = _read_json(state / 'activation-pending.json')
    if (type(value) is not dict or set(value) != {'schema', 'activation_id', 'plan_sha256',
            'request_sha256', 'transaction_sha256', 'source_root'}
            or value['schema'] != _PENDING_SCHEMA or value['activation_id'] != activation_id
            or value['plan_sha256'] != plan_sha256 or value['request_sha256'] != request_sha256
            or value['source_root'] != str(root)):
        raise SourceActivationError('Source update pending identity is malformed or foreign')
    raw = read_exact(operation / 'transaction.json', MAX_METADATA)
    transaction = _json(raw)
    if _sha(raw) != value['transaction_sha256']:
        raise SourceActivationError('Source update transaction changed')
    if (set(transaction) != {'schema', 'activation_id', 'source_root', 'state_root', 'root_identity',
            'before_ids', 'new_ids', 'parents', 'changed_paths', 'planned_directories', 'previous_base', 'workspace'}
            or transaction['schema'] != _TRANSACTION_SCHEMA
            or transaction['activation_id'] != activation_id or transaction['source_root'] != str(root)
            or transaction['state_root'] != str(state) or transaction['root_identity'] != directory_identity(root)):
        raise SourceActivationError('Source update transaction custody is invalid')
    from angerona.core.source_activation_workspace import validate_workspace
    _, plan = _load_plan(root, state, activation_id, plan_sha256)
    validate_workspace(root, state, plan, plan_sha256, transaction['workspace'])
    return value, transaction

def _archive_request(state, operation, request, *, outcome):
    path = state / 'activation-request.json'
    archived = operation / (outcome + '-request-' + request['approval_id'] + '.json')
    if not os.path.lexists(path):
        if _read_json(archived) != request:
            raise SourceActivationError('The terminal request archive changed or disappeared')
        return
    with RetainedFile(path, mutation=True) as retained:
        if _json(retained.read(MAX_METADATA)) != request:
            raise SourceActivationError('Source update request changed before terminal retirement')
        retained.rename(operation / (outcome + '-request-' + request['approval_id'] + '.json'))
    proposal = state / 'activation-proposal.json'
    if os.path.lexists(proposal):
        with RetainedFile(proposal, mutation=True) as retained:
            value = _json(retained.read(MAX_METADATA))
            if (value.get('activation_id'), value.get('plan_sha256')) == (request['activation_id'], request['plan_sha256']):
                retained.rename(operation / (outcome + '-proposal.json'))

def _retire_pending(state, operation, pending, outcome):
    with RetainedFile(state / 'activation-pending.json', mutation=True) as retained:
        if _json(retained.read(MAX_METADATA)) != pending:
            raise SourceActivationError('Source update pending record changed before retirement')
        retained.rename(operation / (outcome + '-pending.json'))

def _publish_plan(root, state, operation, plan, plan_sha256, request_sha256, guard, checkpoint):
    original, candidate = _recheck_plan(root, state, plan)
    from angerona.core.source_activation_storage import require_source_update_storage
    require_source_update_storage(root, state, additional_bytes=plan['storage_reserve_bytes'], source_additional_bytes=plan['source_reserve_bytes'],
                                  new_completed_backup=True, progress=guard.progress_beat)
    stack = contextlib.ExitStack()
    pending = None
    try:
        transaction, transaction_sha, held, fresh, journal = _prepare_transaction(
            root, state, operation, plan, original, candidate, guard, stack)
        workspace = root / transaction['workspace']['relative']
        _verify_tree(root, plan['before'], retained=tuple(held.values()))
        stage_path = state / 'stages' / plan['stage_id']
        if _sha(read_exact(stage_path / 'manifest.json', MAX_METADATA)) != plan['manifest_sha256']:
            raise SourceActivationError('The approved stage manifest changed during backup')
        resolution = _read_json(stage_path / 'resolutions.json', absent={
            'schema': 'angerona.source-resolutions/v1', 'manifest_sha256': plan['manifest_sha256'], 'files': {}})
        if _sha(_encoded(resolution)) != plan['resolution_sha256']:
            raise SourceActivationError('The approved conflict choice changed during backup')
        if _git_binding(root) != plan['git'] or _protected_data(state) != plan['protected_data']:
            raise SourceActivationError('Git/preferences changed during source backup')
        guard.check()
        pending = _pending(state, operation, plan['activation_id'], plan_sha256, request_sha256, transaction_sha)
        _journal_append(journal, {'phase': 'prepared', 'transaction_sha256': transaction_sha})
        checkpoint('prepared', None)
        made = {}
        for name in transaction['planned_directories']:
            guard.check()
            _directory_fences(root, transaction, made)
            _journal_append(journal, {'phase': 'before-directory', 'path': name})
            checkpoint('before-directory', name)
            (root / name).mkdir(mode=0o700)
            made[name] = directory_identity(root / name)
            _journal_append(journal, {'phase': 'directory-created', 'path': name, 'identity': made[name]})
            checkpoint('directory-created', name)
        for number, name in enumerate(plan['changed_paths']):
            guard.check()
            _directory_fences(root, transaction, made)
            _journal_append(journal, {'phase': 'before-file', 'path': name})
            checkpoint('before-file', name)
            if name in held:
                held[name].rename(workspace / 'old' / str(number))
                _journal_append(journal, {'phase': 'old-preserved', 'path': name})
                checkpoint('old-preserved', name)
            elif os.path.lexists(root / name):
                raise SourceActivationError('An unknown file appeared at a source update destination')
            guard.check()
            _directory_fences(root, transaction, made)
            if name in fresh:
                fresh[name].rename(root / name)
                _journal_append(journal, {'phase': 'new-published', 'path': name})
                checkpoint('new-published', name)
            _journal_append(journal, {'phase': 'file-complete', 'path': name})
        guard.check()
        _directory_fences(root, transaction, made)
        _verify_tree(root, plan['after'], retained=tuple(held.values()) + tuple(fresh.values()), recovery_coherence=True)
        if _git_binding(root) != plan['git'] or _protected_data(state) != plan['protected_data']:
            raise SourceActivationError('Git or preferences changed during source activation')
        previous = plan['applied_base']
        base = _base_document(plan, plan_sha256, request_sha256, transaction_sha,
                              previous.get('sha256', '') if previous['present'] else '')
        base_stage = operation / 'applied-base.new.json'
        _new_json(base_stage, base)
        base_new = stack.enter_context(RetainedFile(base_stage, mutation=True))
        _journal_append(journal, {'phase': 'base-prepared', 'identity': base_new.initial,
                                  'sha256': _sha(_encoded(base))})
        checkpoint('base-prepared', None)
        guard.check()
        base_path = state / 'applied-base.json'
        if previous['present']:
            old = stack.enter_context(RetainedFile(base_path, mutation=True))
            if old.initial != previous['identity'] or _sha(old.read(MAX_METADATA)) != previous['sha256']:
                raise SourceActivationError('Applied source lineage changed during publication')
            old.rename(operation / 'applied-base.old.json')
            _journal_append(journal, {'phase': 'base-old-preserved'})
            checkpoint('base-old-preserved', None)
        elif os.path.lexists(base_path):
            raise SourceActivationError('Unknown applied source lineage appeared')
        base_new.rename(base_path)
        _journal_append(journal, {'phase': 'base-published'})
        checkpoint('base-published', None)
        guard.check()
        _verify_tree(root, plan['after'], retained=tuple(held.values()) + tuple(fresh.values()), recovery_coherence=True)
        _journal_append(journal, {'phase': 'verified-after'})
        # Unknown close custody must retain the pending barrier; success is not
        # recorded until every source/journal/index descriptor is retired.
        stack.close()
        guard.check()
        # Reopen/recheck after verified handle retirement, before terminal handoff.
        _verify_tree(root, plan['after'], recovery_coherence=True)
        result = {'status': 'committed', 'activation_id': plan['activation_id'],
                  'plan_sha256': plan_sha256, 'transaction_sha256': transaction_sha,
                  'applied_base_sha256': _sha(_encoded(base)), 'source_files': len(plan['after']),
                  'git_and_preferences_preserved': True, 'runtime_compatibility': 'unchanged-contract',
                  'scope': 'Source publication verified; fresh startup/protection acceptance remains separate'}
        _new_json(operation / 'committed.json', result)
        checkpoint('committed', None)
        guard.finish_progress()
        _archive_request(state, operation, guard.request, outcome='committed')
        _retire_pending(state, operation, pending, 'committed')
        return result
    except BaseException:
        stack.close()
        raise

def _journal_state(journal, transaction):
    rows = _journal_read(journal)
    made, base_new = {}, None
    seen = set()
    if not rows or rows[0]['event'].get('phase') != 'prepared':
        raise SourceActivationError('Source update journal has no original prepare receipt')
    allowed = {'prepared', 'before-directory', 'directory-created', 'before-file', 'old-preserved',
               'new-published', 'file-complete', 'base-prepared', 'base-old-preserved',
               'base-published', 'verified-after', 'before-rollback', 'rollback-file', 'rollback-base',
               'rollback-directory', 'verified-before'}
    for row in rows:
        event = row['event']
        if event.get('phase') not in allowed:
            raise SourceActivationError('Source update journal contains an unknown phase')
        phase = event['phase']
        fields = ({'phase', 'transaction_sha256'} if phase == 'prepared' else
                  {'phase', 'path', 'identity'} if phase == 'directory-created' else
                  {'phase', 'identity', 'sha256'} if phase == 'base-prepared' else
                  {'phase', 'path'} if phase in {'before-directory', 'before-file', 'old-preserved',
                      'new-published', 'file-complete', 'before-rollback', 'rollback-file', 'rollback-directory'} else
                  {'phase'})
        if set(event) != fields:
            raise SourceActivationError('Source update journal event fields are invalid')
        if phase == 'prepared' and event['transaction_sha256'] != _sha(_encoded(transaction)):
            raise SourceActivationError('Source update journal belongs to another transaction')
        if phase not in {'before-rollback', 'rollback-file', 'rollback-base', 'rollback-directory', 'verified-before'}:
            key = (phase, event.get('path'))
            if key in seen:
                raise SourceActivationError('Source update progress is duplicated')
            seen.add(key)
        if phase in {'before-file', 'old-preserved', 'new-published', 'file-complete', 'before-rollback', 'rollback-file'}:
            if event.get('path') not in transaction['changed_paths']:
                raise SourceActivationError('Source update progress names an unselected file')
        if event['phase'] == 'directory-created':
            name = event.get('path')
            if name not in transaction['planned_directories'] or name in made:
                raise SourceActivationError('Source update directory progress is duplicated or foreign')
            made[name] = event.get('identity')
        elif event['phase'] == 'base-prepared':
            if base_new is not None:
                raise SourceActivationError('Source base publication is duplicated')
            base_new = event
    return rows, made, base_new

def _restore_plan(root, state, operation, plan, plan_sha256, request_sha256, guard, checkpoint):
    pending, transaction = _exact_pending(root, state, operation, plan['activation_id'], plan_sha256, request_sha256)
    if (set(transaction['before_ids']) != set(plan['before'])
            or set(transaction['new_ids']) != set(plan['after']).intersection(plan['changed_paths'])
            or transaction['changed_paths'] != plan['changed_paths']
            or transaction['previous_base'] != plan['applied_base']):
        raise SourceActivationError('Source update rollback inventory changed')
    # Validate every complete backup before the first rollback effect.
    for name, row in plan['before'].items():
        raw = read_exact(operation / 'archive' / row['sha256'], MAX_FILE_BYTES)
        if len(raw) != row['bytes'] or _sha(raw) != row['sha256']:
            raise SourceActivationError('The complete original source archive changed')
    workspace = root / transaction['workspace']['relative']
    with contextlib.ExitStack() as workspace_stack, RetainedFile(operation / 'journal.jsonl', writable=True) as journal:
        _retain_workspace(workspace_stack, workspace)
        rows, made, base_new = _journal_state(journal, transaction)
        # Unchanged objects must still be their exact captured file generations.
        for name in set(plan['before']) - set(plan['changed_paths']):
            if not _same_object(root / name, transaction['before_ids'][name], plan['before'][name]['sha256']):
                raise SourceActivationError('An editor changed an unaffected source file; rollback is held')
        for name in transaction['planned_directories']:
            if os.path.lexists(root / name) and name not in made:
                raise SourceActivationError('A source directory appeared without an owned creation receipt')
        _directory_fences(root, transaction, {name: stamp for name, stamp in made.items() if os.path.lexists(root / name)})
        for number, name in reversed(list(enumerate(plan['changed_paths']))):
            guard.check()
            target, backup = root / name, workspace / 'old' / str(number)
            prior = transaction['before_ids'].get(name)
            fresh = transaction['new_ids'].get(name)
            before_hash = plan['before'].get(name, {}).get('sha256')
            after_hash = plan['after'].get(name, {}).get('sha256')
            _journal_append(journal, {'phase': 'before-rollback', 'path': name})
            checkpoint('before-rollback', name)
            if _same_object(target, prior, before_hash) and prior is not None:
                if os.path.lexists(backup):
                    raise SourceActivationError('Original source exists twice; rollback custody is ambiguous')
                continue
            if os.path.lexists(target):
                if fresh is None or not _same_object(target, fresh, after_hash):
                    raise SourceActivationError('An unknown replacement must not be overwritten by rollback')
                with RetainedFile(target, mutation=True) as owned:
                    owned.rename(workspace / 'rolled-back' / str(number))
            if prior is not None:
                if not _same_object(backup, prior, before_hash):
                    raise SourceActivationError('Original source backup native identity changed')
                with RetainedFile(backup, mutation=True) as owned:
                    owned.rename(target)
            elif os.path.lexists(backup):
                raise SourceActivationError('Unexpected original source backup')
            _journal_append(journal, {'phase': 'rollback-file', 'path': name})
            checkpoint('rollback-file', name)
        guard.check()
        previous, base_path, backup = transaction['previous_base'], state / 'applied-base.json', operation / 'applied-base.old.json'
        if previous['present'] and _same_object(base_path, previous['identity'], previous['sha256']):
            if os.path.lexists(backup):
                raise SourceActivationError('Previous source lineage exists twice')
        else:
            if os.path.lexists(base_path):
                if base_new is None or not _same_object(base_path, base_new['identity'], base_new['sha256']):
                    raise SourceActivationError('Unknown applied source lineage prevents rollback')
                with RetainedFile(base_path, mutation=True) as owned:
                    owned.rename(operation / 'applied-base.rolled-back.json')
            if previous['present']:
                if not _same_object(backup, previous['identity'], previous['sha256']):
                    raise SourceActivationError('Previous applied source base backup changed')
                with RetainedFile(backup, mutation=True) as owned:
                    owned.rename(base_path)
        _journal_append(journal, {'phase': 'rollback-base'})
        # Preserve created directories as evidence. Removing a pathname after
        # a check can race a replacement; no directory cleanup is authority.
        # Empty directories do not alter Git's source-file inventory.
        # Exact rollback bytes stay unchanged; incoherent original pins hold,
        # rather than authorizing a fresh bootstrap that could replace custom code.
        _verify_tree(root, plan['before'], recovery_coherence=True)
        if (_git_binding(root) != plan['git'] or _protected_data(state) != plan['protected_data']
                or _optional_file(base_path) != previous):
            raise SourceActivationError('Rollback source/Git/preferences/lineage verification remains held')
        _journal_append(journal, {'phase': 'verified-before'})
    guard.check()
    guard.finish_progress()
    result = {'status': 'rolled_back', 'activation_id': plan['activation_id'], 'plan_sha256': plan_sha256,
              'transaction_sha256': pending['transaction_sha256'], 'original_source_verified': True,
              'git_and_preferences_preserved': True}
    if not os.path.lexists(operation / 'rolled-back.json'):
        _new_json(operation / 'rolled-back.json', result)
    elif _read_json(operation / 'rolled-back.json') != result:
        raise SourceActivationError('Rollback terminal receipt changed')
    _archive_request(state, operation, guard.request, outcome='rolled-back')
    _retire_pending(state, operation, pending, 'rolled-back')
    return result

def run_source_activation(source_root, state_root, activation_id, plan_sha256, request_sha256,
                          guard_file, guard_sha256, *, reconcile=False, checkpoint=lambda phase, name: None):
    """Fixed broker entry. No caller boolean substitutes for the pinned parent."""
    root, state = _root(source_root), _state(state_root)
    with ExclusiveFileLease(state / 'activation.lock'):
        operation, plan = _load_plan(root, state, activation_id, plan_sha256)
        with SourceActivationGuard(root, state, activation_id, plan_sha256, request_sha256,
                                   guard_file, guard_sha256, operation='reconcile' if reconcile else 'activate') as guard:
            guard.claim()
            guard.attach_progress()
            if reconcile:
                return _restore_plan(root, state, operation, plan, plan_sha256, request_sha256, guard, checkpoint)
            if os.path.lexists(state / 'activation-pending.json'):
                raise SourceActivationError('Source activation cannot bypass an interrupted transaction')
            try:
                return _publish_plan(root, state, operation, plan, plan_sha256, request_sha256, guard, checkpoint)
            except Exception as error:
                if not os.path.lexists(state / 'activation-pending.json'):
                    raise
                if os.path.lexists(operation / 'committed.json'):
                    return {'status': 'held_unknown', 'activation_id': activation_id,
                            'publication_failure': type(error).__name__,
                            'reason': 'Verified source publication awaits terminal metadata/cleanup reconciliation; startup remains inhibited'}
                try:
                    result = _restore_plan(root, state, operation, plan, plan_sha256, request_sha256, guard, checkpoint)
                    return dict(result, publication_failure=type(error).__name__)
                except Exception as rollback_error:
                    return {'status': 'held_unknown', 'activation_id': activation_id,
                            'publication_failure': type(error).__name__, 'rollback_failure': type(rollback_error).__name__,
                            'reason': 'Source startup remains inhibited; preserve the pending marker and original archive'}

SourceStageError = SourceActivationError
MAX_PATH = 240
_RESERVED = re.compile(r'^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)', re.I)

def safe_relative(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_PATH:
        raise SourceStageError("invalid source path length")
    path = PurePosixPath(value)
    parts = value.split("/")
    if (path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} or part.casefold() == ".git" or part.endswith((".", " "))
        or _RESERVED.match(part) or any(ord(ch) < 32 or ch in '\\:*?"<>|' for ch in part)
        for part in parts
    )):
        raise SourceStageError("source path is unsafe or not portable")
    return value

def _validate_tree(tree: Mapping[str, bytes]) -> dict[str, bytes]:
    if len(tree) > MAX_FILES:
        raise SourceStageError("source file count exceeds limit")
    result = {}
    folded = set()
    prefixes = {}
    total = 0
    for path, data in tree.items():
        safe_relative(path)
        if path.casefold() in folded:
            raise SourceStageError("source contains case-colliding paths")
        folded.add(path.casefold())
        parts = PurePosixPath(path).parts
        for count in range(1, len(parts) + 1):
            prefix = "/".join(parts[:count])
            previous = prefixes.setdefault(prefix.casefold(), prefix)
            if previous != prefix:
                raise SourceStageError("source contains case-aliased parent paths")
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            raise SourceStageError("source file exceeds byte limit")
        total += len(data)
        if total > MAX_TREE_BYTES:
            raise SourceStageError("source tree exceeds byte limit")
        result[path] = data
    for path in result:
        if any(parent.as_posix().casefold() in folded for parent in PurePosixPath(path).parents if parent.as_posix() != "."):
            raise SourceStageError("source contains file/directory collisions")
    return result


def _broker_snapshot(root, paths):
    _validate_tree({safe_relative(name): b'' for name in paths})
    result, total = {}, 0
    for name in paths:
        path = root / name
        if not os.path.lexists(path):
            continue
        with RetainedFile(path) as retained:
            raw = retained.read(MAX_FILE_BYTES)
        total += len(raw)
        if total > MAX_TREE_BYTES:
            raise SourceActivationError('Source inventory exceeds its capture bound')
        result[name] = raw
    return result


class _BrokerStage:
    safe_relative = staticmethod(safe_relative)
    _validate_tree = staticmethod(_validate_tree)
    snapshot_local = staticmethod(_broker_snapshot)

    @staticmethod
    def _physical_source_root(value):
        root = plain_path(value, directory=True)
        before = directory_identity(root)
        final = root.resolve(strict=True)
        if directory_identity(final) != before:
            raise SourceActivationError('Source root alias changed native identity')
        return final

    @staticmethod
    def _git(root, arguments):
        return read_source_git(root, tuple(arguments))

    @staticmethod
    def local_source_revision(root):
        origin = read_source_git(root, ('remote', 'get-url', 'origin')).decode('ascii').strip()
        head = read_source_git(root, ('rev-parse', '--verify', 'HEAD')).decode('ascii').strip()
        return head if origin == ORIGIN and _digest_text(head, _HEX40) else ''

    @staticmethod
    def source_inventory(root):
        raw = read_source_git(root, ('ls-files', '-z', '--cached', '--others', '--exclude-standard'))
        values = raw.decode('utf-8', errors='strict').split('\0')
        if values[-1] != '':
            raise SourceActivationError('Source inventory is unterminated')
        names = tuple(sorted(set(safe_relative(name) for name in values[:-1])))
        if len(names) > MAX_FILES:
            raise SourceActivationError('Source inventory exceeds its path bound')
        return names


def _stage_module():
    return _BrokerStage



def _effective_recovery_candidate(candidate):
    from angerona.core.startup_recovery import (
        RecoveryCoherenceError, derive_recovery_coherent_tree, verify_recovery_coherence,
    )
    try:
        effective, _proof = derive_recovery_coherent_tree(candidate)
        verify_recovery_coherence(effective)
    except RecoveryCoherenceError as error:
        raise SourceActivationError("Supported merged recovery coherence could not be established") from error
    return effective


def _raw_stage_candidate(stage, manifest_raw, resolution, plan):
    """Bind original staged bytes before generated metadata can be normalized."""
    body = _json(manifest_raw)
    if (type(body) is not dict or body.get("schema") != "angerona.source-stage/v1"
            or body.get("status") not in {"prepared", "conflicts"}
            or type(body.get("files")) is not list or not 1 <= len(body["files"]) <= MAX_FILES
            or type(resolution) is not dict or resolution.get("schema") != "angerona.source-resolutions/v1"
            or resolution.get("manifest_sha256") != plan["manifest_sha256"]
            or type(resolution.get("files")) is not dict):
        raise SourceActivationError("Raw source stage or resolution metadata is invalid")
    expected = {}
    for row in body["files"]:
        if type(row) is not dict:
            raise SourceActivationError("Raw source stage row is invalid")
        name = _BrokerStage.safe_relative(row.get("path"))
        if name in expected:
            raise SourceActivationError("Raw source stage contains duplicate paths")
        digest = row.get("candidate")
        if row.get("action") == "conflict":
            choice = resolution["files"].get(name)
            if type(choice) is not dict or choice.get("choice") not in {"base", "user", "upstream", "delete"}:
                raise SourceActivationError("Raw source conflict is not resolved")
            digest = None if choice["choice"] == "delete" else row.get(choice["choice"])
            if choice.get("sha256") != digest:
                raise SourceActivationError("Raw source conflict choice changed")
        if digest is not None and not _digest_text(digest):
            raise SourceActivationError("Raw source candidate digest is invalid")
        expected[name] = digest
    _BrokerStage._validate_tree({name: b"" for name in expected})
    selected = {name: digest for name, digest in expected.items() if digest is not None}
    candidate_root = stage / "candidate"
    actual_names = set()
    directory_count = 0
    for current, directories, filenames in os.walk(candidate_root, followlinks=False):
        for name in directories:
            directory_count += 1
            if directory_count > MAX_FILES * 16:
                raise SourceActivationError("Raw source candidate directory bound exceeded")
            _BrokerStage._physical_source_root(Path(current) / name)
        for name in filenames:
            relative = (Path(current) / name).relative_to(candidate_root).as_posix()
            actual_names.add(_BrokerStage.safe_relative(relative))
            if len(actual_names) > MAX_FILES:
                raise SourceActivationError("Raw source candidate file bound exceeded")
    if actual_names != set(selected):
        raise SourceActivationError("Raw source candidate inventory changed before recovery derivation")
    candidate = _BrokerStage.snapshot_local(candidate_root, tuple(sorted(selected)))
    if {name: _sha(raw) for name, raw in candidate.items()} != selected:
        raise SourceActivationError("Raw source candidate bytes changed before recovery derivation")
    return candidate

def _recheck_plan(root, state, plan):
    stage = _state(state / 'stages' / plan['stage_id'])
    manifest_raw = read_exact(stage / 'manifest.json', MAX_METADATA)
    if _sha(manifest_raw) != plan['manifest_sha256']:
        raise SourceActivationError('The approved stage manifest changed')
    resolution = _read_json(stage / 'resolutions.json', absent={
        'schema': 'angerona.source-resolutions/v1', 'manifest_sha256': plan['manifest_sha256'], 'files': {}})
    if _sha(_encoded(resolution)) != plan['resolution_sha256']:
        raise SourceActivationError('The approved conflict resolutions changed')
    original = _BrokerStage.snapshot_local(root, tuple(sorted(set(_BrokerStage.source_inventory(root)) | set(plan['before']))))
    candidate = _raw_stage_candidate(stage, manifest_raw, resolution, plan)
    candidate = _effective_recovery_candidate(candidate)
    if (_manifest(original) != plan['before'] or _manifest(candidate) != plan['after']
            or _tree_digest(original) != plan['original_inventory_sha256']
            or _git_binding(root) != plan['git'] or _protected_data(state) != plan['protected_data']
            or _optional_file(state / 'applied-base.json') != plan['applied_base']
            or _dependency_contract(original) != plan['runtime_contract']
            or _dependency_contract(candidate) != plan['runtime_contract']):
        raise SourceActivationError('Source/candidate/Git/preferences/runtime changed after approval')
    return original, candidate


BROKER_FILES = (
    'tools/activate_source_update.py',
    'src/angerona/core/source_activation_broker.py',
    'src/angerona/core/source_activation_file.py',
    'src/angerona/core/startup_recovery.py',
    'src/angerona/updater/source_git.py',
    'tools/publication_transport.py',
    'tools/windows_publication_runtime.py',
    'tools/publication_git_runtime_profile.json',
    'tools/Resume-AngeronaSourceActivation.ps1',
    'tools/startup_repair_common.ps1',
    'src/angerona/core/source_activation_storage.py',
    'src/angerona/resilience/heartbeat.py',
    'src/angerona/core/_source_tomli/__init__.py',
    'src/angerona/core/_source_tomli/_parser.py',
    'src/angerona/core/_source_tomli/_re.py',
    'src/angerona/core/_source_tomli/_types.py',
    'src/angerona/core/_source_tomli/LICENSE',
    'src/angerona/core/source_activation_workspace.py',
)


def _native_self_image():
    import ctypes
    from ctypes import wintypes as w
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.GetCurrentProcess.argtypes, api.GetCurrentProcess.restype = (), w.HANDLE
    api.QueryFullProcessImageNameW.argtypes = (w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD))
    api.QueryFullProcessImageNameW.restype = w.BOOL
    length, buffer = w.DWORD(32768), ctypes.create_unicode_buffer(32768)
    if not api.QueryFullProcessImageNameW(api.GetCurrentProcess(), 0, buffer, ctypes.byref(length)):
        raise SourceActivationError('Publisher native self image is unavailable')
    return buffer.value
