"""Explicit compatible-runtime source activation, separate from installed trust.

The GUI prepares immutable plans and records exact consent. Only the fixed
external supervisor's bound broker may publish after real component retirement.
Parent lease assertions are not independent child attestations of those leases.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from angerona.core import _source_tomli as tomllib

from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.source_activation_file import (
    RetainedFile, directory_identity, plain_path,
    read_exact, write_new, private_owner_rights_directory,
)

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


def _cancelled(callback):
    if callback():
        raise SourceActivationError('Source activation was cancelled before publication')


def _stage_module():
    # Local import avoids a discovery/staging/activation import cycle. Nothing
    # from a downloaded candidate is imported or executed here.
    from angerona.updater import source_stage
    return source_stage


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

def _stage_data(source_root, state, stage_id, manifest_sha256):
    stage = _stage_module()
    if type(stage_id) is not str or not stage._STAGE_NAME.fullmatch(stage_id):
        raise SourceActivationError('Source stage identity is invalid')
    directory = _state(state / 'stages' / stage_id)
    body = stage._stage_manifest(directory, manifest_sha256)
    provenance = body.get('activation_provenance')
    if (type(provenance) is not dict or set(provenance) != {
            'schema', 'origin', 'source_root', 'root_identity',
            'base_archive_sha256', 'target_archive_sha256'}
            or provenance['schema'] != 1 or type(provenance['schema']) is not int
            or provenance['origin'] != ORIGIN or provenance['source_root'] != str(source_root)
            or provenance['root_identity'] != directory_identity(source_root)
            or not all(type(provenance[key]) is str and _HEX64.fullmatch(provenance[key])
                       for key in ('base_archive_sha256', 'target_archive_sha256'))):
        raise SourceActivationError('This stage has no exact activation provenance; prepare it again')
    resolution = stage._resolution_index(directory, manifest_sha256)
    resolution_sha = _sha(_encoded(resolution))
    expected, originals, upstream = {}, {}, {}
    for row in body['files']:
        if type(row) is not dict:
            raise SourceActivationError('Source stage row is invalid')
        name = stage.safe_relative(row.get('path'))
        if name in expected:
            raise SourceActivationError('Source stage has duplicate file names')
        digest = row.get('candidate')
        if row.get('action') == 'conflict':
            choice = resolution['files'].get(name)
            if (type(choice) is not dict or choice.get('choice') not in {'base', 'user', 'upstream', 'delete'}):
                raise SourceActivationError('Resolve every source conflict before activation')
            digest = None if choice['choice'] == 'delete' else row.get(choice['choice'])
            if choice.get('sha256') != digest:
                raise SourceActivationError('Source conflict choice changed')
        expected[name] = digest
        if row.get('user') is not None:
            originals[name] = stage._read_blob(directory, row['user'])
        if row.get('upstream') is not None:
            upstream[name] = row['upstream']
    validation = stage.validate_source_candidate(directory, manifest_sha256)
    if validation.get('static_checks') != 'passed':
        raise SourceActivationError('The exact resolved source candidate did not pass static validation')
    target_names = tuple(sorted(name for name, value in expected.items() if value is not None))
    candidate = stage.snapshot_local(directory / 'candidate', target_names)
    if {name: _sha(raw) for name, raw in candidate.items()} != {
            name: value for name, value in expected.items() if value is not None}:
        raise SourceActivationError('Source candidate bytes changed')
    # Raw hashes and explicit resolution choices are admitted BEFORE derivation.
    candidate = _effective_recovery_candidate(candidate)
    return body, resolution_sha, originals, candidate, upstream


def _preview(plan, plan_sha256):
    return {'schema': 1, 'status': 'ready', 'reason': '',
            'activation_id': plan['activation_id'], 'plan_sha256': plan_sha256,
            'stage_id': plan['stage_id'], 'manifest_sha256': plan['manifest_sha256'],
            'resolution_sha256': plan['resolution_sha256'],
            'original_inventory_sha256': plan['original_inventory_sha256'],
            'original_head': plan['git']['head'],
            'target_revision': plan['target_revision'], 'base_revision': plan['base_revision'],
            'changed_paths': list(plan['changed_paths']),
            'preserved_changes': plan['preserved_changes'], 'conflicts': 0,
            'dependencies_compatible': True, 'source_root': plan['source_root'],
            'scope': 'Explicit source-user activation; no installed or response authority'}


def prepare_source_activation(source_root, state_root, stage_id, manifest_sha256, *, cancelled=lambda: False):
    """Freeze an exact compatible-runtime plan off Qt, without changing source."""
    stage, root = _stage_module(), _root(source_root)
    state = _state(state_root, create=True)
    _cancelled(cancelled)
    from angerona.resilience.heartbeat import read_existing_optional_authority
    read_existing_optional_authority(state.parent)
    with ExclusiveFileLease(state / 'activation.lock'):
        if os.path.lexists(state / 'activation-pending.json'):
            raise SourceActivationError('An interrupted source update must be reconciled first')
        body, resolution_sha, original, target, upstream = _stage_data(
            root, state, stage_id, manifest_sha256)
        installed = applied_source_base(root, state)
        paths = set(stage.source_inventory(root)) | set(installed['effective_paths'] if installed is not None else ())
        current = stage.snapshot_local(root, tuple(sorted(paths)))
        if current != original or _tree_digest(current) != body.get('original_tree_sha256'):
            raise SourceActivationError('Original source changed after candidate preparation')
        binding = _git_binding(root)
        if binding['head'] != body.get('local_revision'):
            raise SourceActivationError('Git HEAD changed after candidate preparation')
        if _dependency_contract(current) != _dependency_contract(target):
            raise SourceActivationError('Dependency or Python ABI changes require separate verified runtime preparation')
        changes = sorted(name for name in set(current) | set(target) if current.get(name) != target.get(name))
        if not changes:
            raise SourceActivationError('This candidate has no source changes to activate')
        forbidden = {'.git', 'venv', '.venv', '.tmp', 'AngeronaData'}
        for name in changes:
            if Path(name).parts[0] in forbidden or root / name == state or state in (root / name).parents:
                raise SourceActivationError('Source activation escaped its code/data boundary')
            path = root / name
            plain_path(path.parent, directory=True) if path.parent.exists() else None
            if name not in current and os.path.lexists(path):
                raise SourceActivationError('A candidate addition collides with ignored or unknown local data')
        reserve = _activation_storage_reserve(current, target)
        from angerona.core.source_activation_storage import require_source_update_storage
        require_source_update_storage(root, state, additional_bytes=reserve,
            source_additional_bytes=_activation_workspace_reserve(current, target), new_completed_backup=True)
        plan = {'schema': _PLAN_SCHEMA, 'plan_nonce': secrets.token_hex(16), 'source_root': str(root), 'state_root': str(state),
                'root_identity': directory_identity(root), 'origin': ORIGIN,
                'stage_id': stage_id, 'manifest_sha256': manifest_sha256,
                'resolution_sha256': resolution_sha, 'target_revision': body['target_revision'],
                'base_revision': body['base_revision'], 'git': binding,
                'before': _manifest(current), 'after': _manifest(target),
                'original_inventory_sha256': _tree_digest(current),
                'upstream': upstream, 'changed_paths': changes,
                'preserved_changes': sum(row.get('base') != row.get('user') for row in body['files']),
                'protected_data': _protected_data(state), 'applied_base': _optional_file(state / 'applied-base.json'),
                'runtime_contract': _dependency_contract(current), 'storage_reserve_bytes': reserve,
                'source_reserve_bytes': _activation_workspace_reserve(current, target),
                'broker_snapshot': _snapshot_inputs(root),
                'provenance': body['activation_provenance']}
        plan['activation_id'] = _sha(_encoded(plan))[:32]
        raw = _encoded(plan)
        _cancelled(cancelled)
        operation = _operation(state, plan['activation_id'], create=True)
        path = operation / 'plan.json'
        if path.exists():
            if read_exact(path, MAX_METADATA) != raw:
                raise SourceActivationError('The existing activation plan changed')
        else:
            _new_json(path, plan)
        _write_snapshot(root, operation, plan['broker_snapshot'])
        return _preview(plan, _sha(raw))


_PLAN_KEYS = frozenset(('schema', 'source_root', 'state_root', 'root_identity', 'origin',
    'stage_id', 'manifest_sha256', 'resolution_sha256', 'target_revision', 'base_revision',
    'git', 'before', 'after', 'original_inventory_sha256', 'upstream', 'changed_paths',
    'preserved_changes', 'protected_data', 'runtime_contract', 'provenance', 'applied_base', 'broker_snapshot', 'plan_nonce', 'storage_reserve_bytes', 'source_reserve_bytes', 'activation_id'))


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


def _recheck_plan(root, state, plan):
    stage = _stage_module()
    body, resolution_sha, original, candidate, upstream = _stage_data(
        root, state, plan['stage_id'], plan['manifest_sha256'])
    if (resolution_sha != plan['resolution_sha256'] or _manifest(original) != plan['before']
            or _manifest(candidate) != plan['after'] or upstream != plan['upstream']
            or body['activation_provenance'] != plan['provenance']
            or body['base_revision'] != plan['base_revision']
            or body['target_revision'] != plan['target_revision']):
        raise SourceActivationError('The approved source candidate changed')
    current = stage.snapshot_local(root, tuple(sorted(set(stage.source_inventory(root)) | set(plan['before']))))
    if (_manifest(current) != plan['before'] or _tree_digest(current) != plan['original_inventory_sha256']
            or _git_binding(root) != plan['git'] or _protected_data(state) != plan['protected_data']
            or _optional_file(state / 'applied-base.json') != plan['applied_base']
            or _dependency_contract(current) != plan['runtime_contract']
            or _dependency_contract(candidate) != plan['runtime_contract']):
        raise SourceActivationError('Source, Git index, preferences or runtime changed after review')
    return original, candidate


class _NativeProcess:
    """One query/synchronize handle; no process actions or numeric close retries."""
    _close_holds = []

    def __init__(self, pid, birth, image, *, optional=False):
        if self._close_holds:
            raise SourceActivationError('Prior source-controller native retirement remains held')
        import ctypes
        from ctypes import wintypes as w
        if (os.name != 'nt' or type(pid) is not int or not 0 < pid <= 0xffffffff
                or type(birth) is not str or not _DECIMAL.fullmatch(birth)
                or type(image) is not str or not Path(image).is_absolute()):
            raise SourceActivationError('Exact native source-controller identity is unavailable')
        self.pid, self.birth, self.image = pid, birth, image
        self.optional, self.absent, self.live = optional, False, False
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
            if optional and ctypes.get_last_error() == 87:
                self.absent = True
                return
            raise SourceActivationError('Source controller native query handle is unavailable')
        try:
            self.live = self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        import ctypes
        from ctypes import wintypes as w
        if self.close_held:
            raise SourceActivationError('Source controller native retirement is held')
        if self.optional and self.absent:
            return False
        if not self.handle:
            raise SourceActivationError('Source controller generation is not live')
        waited = self.api.WaitForSingleObject(self.handle, 0)
        if self.optional and waited == 0:
            return False
        if waited != 258:
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
                ):
            if self.optional:
                return False
            raise SourceActivationError('Source controller native generation changed')
        waited = self.api.WaitForSingleObject(self.handle, 0)
        if self.optional and waited == 0:
            return False
        if waited != 258:
            raise SourceActivationError('Source controller native generation changed')
        return True

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


def current_source_activation_context(source_root, state_root):
    """Worker-only native read. Absence initializes no state and grants nothing."""
    root, state = _root(source_root), _state(state_root)
    path = state / 'activation-owner.json'
    value = _read_json(path)
    if value is None:
        return None
    _context(root, state, value)
    return value


def queue_source_activation_proposal(state_root, activation_id, plan_sha256, *, cancelled=lambda: False):
    state = _state(state_root)
    with ExclusiveFileLease(state / 'activation.lock'):
        raw = read_exact(_operation(state, activation_id) / 'plan.json', MAX_METADATA)
        plan = _json(raw)
        root = _root(plan.get('source_root', ''))
        _load_plan(root, state, activation_id, plan_sha256)
        _recheck_plan(root, state, plan)
        _cancelled(cancelled)
        proposal = {'schema': 'angerona.source-activation-proposal/v1', 'activation_id': activation_id,
                    'plan_sha256': plan_sha256, 'source_root': str(root), 'state_root': str(state)}
        path = state / 'activation-proposal.json'
        if os.path.lexists(path):
            if _read_json(path) != proposal:
                raise SourceActivationError('A different source update is already queued for reconfirmation')
        else:
            _new_json(path, proposal)
        _cancelled(cancelled)
        return {'status': 'queued-reconfirm', 'activation_id': activation_id,
                'plan_sha256': plan_sha256}


def approve_source_activation(state_root, activation_id, plan_sha256, launch_context,
                              *, accepted, approval_id=None, cancelled=lambda: False):
    if accepted is not True or type(accepted) is not bool:
        raise SourceActivationError('Source activation requires explicit current approval')
    if approval_id is None:
        approval_id = secrets.token_hex(16)
    if not _digest_text(approval_id, _HEX32):
        raise SourceActivationError('Source activation approval identity is invalid')
    state = _state(state_root)
    with ExclusiveFileLease(state / 'activation.lock'):
        plan_raw = read_exact(_operation(state, activation_id) / 'plan.json', MAX_METADATA)
        root = _root(_json(plan_raw).get('source_root', ''))
        operation, plan = _load_plan(root, state, activation_id, plan_sha256)
        if os.path.lexists(state / 'activation-pending.json'):
            raise SourceActivationError('An interrupted source update must be reconciled first')
        owner_raw = read_exact(state / 'activation-owner.json', MAX_METADATA)
        owner = _context(root, state, _json(owner_raw))
        if owner != launch_context:
            raise SourceActivationError('Source-update controller binding changed before approval')
        _recheck_plan(root, state, plan)
        from angerona.resilience.heartbeat import read_existing_optional_authority
        read_existing_optional_authority(state.parent)
        from angerona.core.source_activation_storage import require_source_update_storage
        require_source_update_storage(root, state, additional_bytes=plan['storage_reserve_bytes'], source_additional_bytes=plan['source_reserve_bytes'], new_completed_backup=True)
        _cancelled(cancelled)
        request = {'schema': _REQUEST_SCHEMA, 'activation_id': activation_id,
                   'plan_sha256': plan_sha256, 'approval_id': approval_id,
                   'source_root': str(root), 'state_root': str(state),
                   'launch_id': owner['launch_id'], 'owner_sha256': _sha(owner_raw),
                   'core_pid': owner['core_pid'], 'core_birth': owner['core_birth'],
                   'broker_pid': owner['broker_pid'], 'broker_birth': owner['broker_birth'],
                   'retirement_scope': capture_source_activation_retirement_scope(root, state, owner),
                   'accepted': True}
        request_path = state / 'activation-request.json'
        if os.path.lexists(request_path):
            raise SourceActivationError('A source activation request is already retained')
        request_sha = _sha(_encoded(request))
        request_archive = _state(operation / 'requests', create=True) / (request_sha + '.json')
        _new_json(request_archive, request)
        _new_json(request_path, request)
        # Preserve the exact consent in the immutable operation record too.
        _new_json(operation / ('approval-' + request['approval_id'] + '.json'), request)
        proposal_path = state / 'activation-proposal.json'
        if os.path.lexists(proposal_path):
            expected_proposal = {'schema': 'angerona.source-activation-proposal/v1',
                'activation_id': activation_id, 'plan_sha256': plan_sha256,
                'source_root': str(root), 'state_root': str(state)}
            with RetainedFile(proposal_path, mutation=True) as proposal:
                if _json(proposal.read(MAX_METADATA)) != expected_proposal:
                    raise SourceActivationError('A different queued proposal cannot be consumed by this consent')
                proposal.rename(operation / ('accepted-proposal-' + approval_id + '.json'))
        if cancelled():
            with RetainedFile(request_path, mutation=True) as retained:
                if retained.read(MAX_METADATA) != _encoded(request):
                    raise SourceActivationError('Cancellation found a changed source activation request')
                retained.rename(operation / ('cancelled-' + request['approval_id'] + '.json'))
            raise SourceActivationError('Source activation approval was cancelled before dashboard handoff')
        return {'status': 'requested', 'activation_id': activation_id, 'plan_sha256': plan_sha256,
                'request_sha256': request_sha}


def cancel_source_activation_request(state_root, activation_id, plan_sha256, request_sha256):
    state = _state(state_root)
    with ExclusiveFileLease(state / 'activation.lock'):
        path = state / 'activation-request.json'
        if not os.path.lexists(path):
            return {'status': 'absent'}
        raw = read_exact(path, MAX_METADATA)
        value = _json(raw)
        if (set(value) != _REQUEST_KEYS or value.get('schema') != _REQUEST_SCHEMA
                or _sha(raw) != request_sha256 or value.get('activation_id') != activation_id
                or value.get('plan_sha256') != plan_sha256
                or os.path.lexists(state / 'activation-pending.json')):
            return {'status': 'held', 'reason': 'The exact request is changed or already being applied'}
        operation = _operation(state, activation_id)
        with RetainedFile(path, mutation=True) as retained:
            if retained.read(MAX_METADATA) != raw:
                return {'status': 'held', 'reason': 'The exact request changed during cancellation'}
            retained.rename(operation / ('cancelled-' + value['approval_id'] + '.json'))
        return {'status': 'cancelled', 'activation_id': activation_id, 'plan_sha256': plan_sha256}


def inspect_source_activation(source_root, state_root):
    root = _root(source_root)
    if not os.path.lexists(state_root):
        return {'status': 'absent'}
    state = _state(state_root)
    if os.path.lexists(state / 'activation-pending.json'):
        return {'status': 'held', 'reason': 'An interrupted source update requires exact reconciliation'}
    request = _read_json(state / 'activation-request.json')
    proposal = _read_json(state / 'activation-proposal.json')
    selected = request if request is not None else proposal
    if selected is not None:
        expected = (_REQUEST_KEYS if request is not None else {'schema', 'activation_id', 'plan_sha256', 'source_root', 'state_root'})
        expected_schema = (_REQUEST_SCHEMA if request is not None else 'angerona.source-activation-proposal/v1')
        if set(selected) != expected or selected.get('schema') != expected_schema:
            raise SourceActivationError('The retained source activation record is malformed')
    if selected is None:
        return {'status': 'absent'}
    operation, plan = _load_plan(root, state, selected.get('activation_id'), selected.get('plan_sha256'))
    if (selected.get('source_root') != str(root) or selected.get('state_root') != str(state)):
        raise SourceActivationError('The retained activation belongs to another source scope')
    with ExclusiveFileLease(state / 'activation.lock'):
        current_path = state / ('activation-request.json' if request is not None else 'activation-proposal.json')
        if (_read_json(current_path) != selected or os.path.lexists(state / 'activation-pending.json')):
            raise SourceActivationError('The queued activation changed during inspection')
        _recheck_plan(root, state, plan)
        from angerona.core.source_activation_storage import require_source_update_storage
        require_source_update_storage(root, state, additional_bytes=plan['storage_reserve_bytes'], source_additional_bytes=plan['source_reserve_bytes'],
                                      new_completed_backup=True)
    result = _preview(plan, selected['plan_sha256'])
    result['status'] = 'requested' if request is not None else 'queued-reconfirm'
    return result


_RUNTIME = None


def register_source_activation_runtime(app):
    """Register the actual App supplier; no caller-supplied roster or authority."""
    import weakref
    from angerona.app import AngeronaApp
    if type(app) is not AngeronaApp:
        raise SourceActivationError('Source update retirement requires the actual application owner')
    global _RUNTIME
    _RUNTIME = (weakref.ref(app), AngeronaApp._owned_process_identities_for_response)


def capture_source_activation_retirement_scope(source_root, state_root, launch_context):
    from angerona.core.werfault_guard import read_owned_process_snapshot
    root, state = _root(source_root), _state(state_root)
    context = _context(root, state, launch_context)
    runtime = _RUNTIME
    app = runtime[0]() if runtime is not None else None
    if (app is None or Path(app.config.data_dir).absolute() / 'github-updates' != state
            or getattr(app, '_shutdown_requested', None) is None
            or app._shutdown_requested.is_set()):
        raise SourceActivationError('The real application retirement supplier is unavailable')
    started = time.monotonic()
    rows = read_owned_process_snapshot(lambda: runtime[1](app), not_before=started,
                                      clock=time.monotonic).rows
    current = {(row.pid, row.birth_ticks, row.image) for row in rows if row.role == 'core'}
    core = (context['core_pid'], context['core_birth'],
            os.path.normcase(os.path.normpath(context['core_image'])))
    if current != {core}:
        raise SourceActivationError('Current Core is missing from its complete native ownership closure')
    result = []
    broker = (context['broker_pid'], context['broker_birth'],
              os.path.normcase(os.path.normpath(context['broker_image'])))
    found_broker = False
    for row in rows:
        key = (row.pid, row.birth_ticks, row.image)
        if row.role == 'source-update-controller':
            if key != broker or found_broker:
                raise SourceActivationError('External source controller identity is contradictory')
            found_broker = True
            continue
        if row.role == 'source-update-supervisor':
            supervisor = (context['supervisor_pid'], context['supervisor_birth'],
                          os.path.normcase(os.path.normpath(context['supervisor_image'])))
            if key != supervisor:
                raise SourceActivationError('External source supervisor identity is contradictory')
            continue
        result.append({'pid': row.pid, 'birth': row.birth_ticks, 'image': row.image, 'role': row.role})
    if not found_broker or not result or len(result) > 16 or _RUNTIME is not runtime or app._shutdown_requested.is_set():
        raise SourceActivationError('The complete pre-stop resource closure is unavailable')
    return result


_GUARD_KEYS = frozenset(('schema', 'operation', 'guard_nonce', 'launch_id', 'activation_id',
    'plan_sha256', 'request_sha256', 'owner_sha256', 'source_root', 'state_root',
    'parent_pid', 'parent_birth', 'parent_image', 'parent_script_sha256',
    'root_identity', 'leases', 'retirement', 'snapshot_sha256'))
_REQUEST_KEYS = frozenset(('schema', 'activation_id', 'plan_sha256', 'approval_id',
    'source_root', 'state_root', 'launch_id', 'owner_sha256', 'core_pid', 'core_birth',
    'broker_pid', 'broker_birth', 'retirement_scope', 'accepted'))


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


def _base_document(plan, plan_sha256, request_sha256, transaction_sha256, previous_sha256):
    return {'schema': _BASE_SCHEMA, 'activation_id': plan['activation_id'],
            'plan_sha256': plan_sha256, 'request_sha256': request_sha256,
            'source_root': plan['source_root'], 'root_identity': plan['root_identity'], 'origin': ORIGIN,
            'original_head': plan['git']['head'], 'target_revision': plan['target_revision'],
            'upstream': plan['upstream'], 'effective_paths': sorted(plan['after']), 'transaction_sha256': transaction_sha256,
            'previous_base_sha256': previous_sha256}


def applied_source_base(source_root, state_root):
    """Read verified applied upstream lineage without changing Git or custom edits."""
    root = _root(source_root)
    if not os.path.lexists(Path(state_root) / 'applied-base.json') and not os.path.lexists(Path(state_root) / 'activation-pending.json'):
        return None
    state = _state(state_root)
    if os.path.lexists(state / 'activation-pending.json'):
        raise SourceActivationError('Interrupted source activation holds source currency')
    path = state / 'applied-base.json'
    if not os.path.lexists(path):
        return None
    raw = read_exact(path, MAX_METADATA)
    receipt = _json(raw)
    if set(receipt) != {'schema', 'activation_id', 'plan_sha256', 'request_sha256', 'source_root',
            'root_identity', 'origin', 'original_head', 'target_revision', 'upstream',
            'transaction_sha256', 'previous_base_sha256', 'effective_paths'} or receipt['schema'] != _BASE_SCHEMA:
        raise SourceActivationError('The applied source base receipt is invalid')
    operation, plan = _load_plan(root, state, receipt['activation_id'], receipt['plan_sha256'])
    transaction = read_exact(operation / 'transaction.json', MAX_METADATA)
    terminal = _read_json(operation / 'committed.json')
    if (terminal is None or terminal.get('status') != 'committed'
            or terminal.get('applied_base_sha256') != _sha(raw)
            or terminal.get('transaction_sha256') != _sha(transaction)
            or terminal.get('plan_sha256') != receipt['plan_sha256']
            or receipt != _base_document(plan, receipt['plan_sha256'], receipt['request_sha256'],
                                        _sha(transaction), receipt['previous_base_sha256'])
            or _stage_module().local_source_revision(root) != receipt['original_head']):
        raise SourceActivationError('The applied source lineage or preserved Git HEAD changed')
    return dict(receipt, receipt_sha256=_sha(raw))


_PENDING_SCHEMA = 'angerona.source-activation-pending/v1'
_TRANSACTION_SCHEMA = 'angerona.source-activation-transaction/v1'


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


def _snapshot_inputs(root):
    result, total = {}, 0
    for name in BROKER_FILES:
        raw = read_exact(root / name, MAX_FILE_BYTES)
        total += len(raw)
        if total > 4 * 1024**2:
            raise SourceActivationError('Original activation broker snapshot exceeds its bound')
        result[name] = {'sha256': _sha(raw), 'bytes': len(raw)}
    return {'schema': 'angerona.source-activation-broker-snapshot/v1', 'files': result}


def _write_snapshot(root, operation, snapshot):
    directory = _state(operation / 'broker', create=True)
    for name, row in snapshot['files'].items():
        target = directory / name
        current = directory
        for part in Path(name).parts[:-1]:
            current = _state(current / part, create=True)
        raw = read_exact(root / name, MAX_FILE_BYTES)
        if len(raw) != row['bytes'] or _sha(raw) != row['sha256']:
            raise SourceActivationError('The original broker changed while freezing its snapshot')
        if os.path.lexists(target):
            if read_exact(target, MAX_FILE_BYTES) != raw:
                raise SourceActivationError('The retained original broker snapshot changed')
        else:
            write_new(target, raw)
    target = directory / 'snapshot.json'
    if os.path.lexists(target):
        if _read_json(target) != snapshot:
            raise SourceActivationError('The retained broker snapshot manifest changed')
    else:
        _new_json(target, snapshot)


def cancel_source_activation_approval(state_root, activation_id, plan_sha256, approval_id):
    if not _digest_text(approval_id, _HEX32):
        raise SourceActivationError('Source approval cancellation identity is invalid')
    state = _state(state_root)
    with ExclusiveFileLease(state / 'activation.lock'):
        path = state / 'activation-request.json'
        if not os.path.lexists(path):
            return {'status': 'absent'}
        raw = read_exact(path, MAX_METADATA)
        value = _json(raw)
        if set(value) != _REQUEST_KEYS or value.get('schema') != _REQUEST_SCHEMA or (value.get('activation_id'), value.get('plan_sha256'), value.get('approval_id')) != (
                activation_id, plan_sha256, approval_id) or os.path.lexists(state / 'activation-pending.json'):
            return {'status': 'held', 'reason': 'This consent no longer owns a cancellable request'}
        operation = _operation(state, activation_id)
        with RetainedFile(path, mutation=True) as retained:
            if retained.read(MAX_METADATA) != raw:
                return {'status': 'held', 'reason': 'The consent request changed during cancellation'}
            retained.rename(operation / ('cancelled-' + approval_id + '.json'))
        return {'status': 'cancelled', 'activation_id': activation_id, 'plan_sha256': plan_sha256}


class SourceActivationController:
    """Separate external launch controller, never a Core child/STOP dependency."""
    def __init__(self, source_root, state_root, launch_id):
        import threading
        self.source_root = Path(source_root).absolute()
        self.state_root = Path(state_root).absolute()
        self.launch_id = launch_id
        self._lock = threading.Lock()
        self._owner_sha256 = None
        self._state = 'pending'
        self._observed_monotonic = self._expires_monotonic = None

    def cached_status(self):
        if not self._lock.acquire(blocking=False):
            return {'configured': True, 'state': 'busy', 'lifetime': 'post-Core external controller'}
        try:
            now = time.monotonic()
            native = ('unknown' if self._observed_monotonic is None else
                      'fresh' if self._observed_monotonic <= now < self._expires_monotonic else 'expired')
            return {'configured': True, 'state': self._state, 'native_observation': native,
                    'lifetime': 'post-Core external controller'}
        finally:
            self._lock.release()

    def observe(self, *, timeout=1.0):
        from angerona.telemetry.process_snapshot_worker import on_gui_thread
        from angerona.core.werfault_guard import OwnedProcessIdentity
        if on_gui_thread():
            raise SourceActivationError('Source controller native observation cannot run on Qt')
        if type(timeout) not in (int, float) or not 0 < timeout <= 1.0:
            raise SourceActivationError('Source controller observation budget is invalid')
        started = time.monotonic()
        if not _digest_text(self.launch_id, _HEX32):
            raise SourceActivationError('Inherited source controller launch identity is invalid')
        context = current_source_activation_context(self.source_root, self.state_root)
        if context is None or context['launch_id'] != self.launch_id:
            raise SourceActivationError('Expected external source controller is not bound')
        raw = read_exact(self.state_root / 'activation-owner.json', MAX_METADATA)
        if _json(raw) != context:
            raise SourceActivationError('Source controller context changed during observation')
        if not self._lock.acquire(timeout=max(0.0, min(timeout, started + timeout - time.monotonic()))):
            raise SourceActivationError('Source controller registration is busy')
        try:
            digest = _sha(raw)
            if self._owner_sha256 is not None and digest != self._owner_sha256:
                self._state = 'held'
                raise SourceActivationError('Source controller registration changed generation')
            self._owner_sha256, self._state = digest, 'native-bound'
        finally:
            self._lock.release()
        if not started <= time.monotonic() < started + timeout:
            raise SourceActivationError('Source controller native query exceeded its deadline')
        def row(prefix, role):
            return OwnedProcessIdentity(
                pid=context[prefix + '_pid'], birth_ticks=context[prefix + '_birth'],
                create_time=(int(context[prefix + '_birth']) - 116444736000000000) / 10_000_000,
                image=context[prefix + '_image'], role=role,
                observed_monotonic=started, expires_monotonic=started + 2.0)
        rows = [row('broker', 'source-update-controller')]
        supervisor = (context['supervisor_pid'], context['supervisor_birth'], context['supervisor_image'])
        broker = (context['broker_pid'], context['broker_birth'], context['broker_image'])
        if supervisor != broker:
            with _NativeProcess(*supervisor, optional=True) as observed:
                if observed.live:
                    rows.append(row('supervisor', 'source-update-supervisor'))
        if not started <= time.monotonic() < started + timeout:
            raise SourceActivationError('External source controller scope exceeded its deadline')
        if not self._lock.acquire(timeout=max(0.0, started + timeout - time.monotonic())):
            raise SourceActivationError('External source controller publication is busy')
        try:
            if not started <= time.monotonic() < started + timeout:
                raise SourceActivationError('External source controller publication exceeded its deadline')
            self._observed_monotonic, self._expires_monotonic = started, started + 2.0
        finally:
            self._lock.release()
        return tuple(rows)



def source_activation_controller_registration(source_root, state_root):
    """Inert constructor on Qt: an environment value is expectation only."""
    launch_id = os.environ.get('ANGERONA_SOURCE_ACTIVATION_LAUNCH_ID')
    return None if launch_id is None else SourceActivationController(source_root, state_root, launch_id)


def _activation_workspace_reserve(before, after):
    changed = {name for name in set(before) | set(after) if before.get(name) != after.get(name)}
    return sum(len(tree[name]) for tree in (before, after) for name in changed if name in tree) + 1024**2


def _activation_storage_reserve(before, after):
    # Unique complete archive + retained old changed objects + staged new ones,
    # bounded journal/metadata/capsule allowance; all under the SAME2GiB cap.
    unique = {_sha(raw): len(raw) for raw in before.values()}
    changed = {name for name in set(before) | set(after) if before.get(name) != after.get(name)}
    return (sum(unique.values()) + sum(len(before[name]) for name in changed if name in before)
            + sum(len(after[name]) for name in changed if name in after)
            + MAX_JOURNAL + 2 * MAX_METADATA + 4 * 1024**2)


def source_activation_resource_retirement_proven():
    """Memory-only STOP custody: unknown descriptor cleanup is never retried."""
    import sys
    from angerona.core import source_activation_file
    heartbeat = sys.modules.get('angerona.resilience.heartbeat')
    return (not source_activation_file._CLOSE_HOLDS and not _NativeProcess._close_holds
            and not (getattr(heartbeat, '_OPTIONAL_CLOSE_HOLDS', ()) if heartbeat is not None else ()))


def cancel_source_activation_proposal(state_root, activation_id, plan_sha256):
    state = _state(state_root)
    with ExclusiveFileLease(state / 'activation.lock'):
        path = state / 'activation-proposal.json'
        if not os.path.lexists(path):
            return {'status': 'absent'}
        value = _read_json(path)
        if (set(value) != {'schema', 'activation_id', 'plan_sha256', 'source_root', 'state_root'}
                or value.get('schema') != 'angerona.source-activation-proposal/v1'
                or value.get('activation_id') != activation_id or value.get('plan_sha256') != plan_sha256
                or os.path.lexists(state / 'activation-pending.json') or os.path.lexists(state / 'activation-request.json')):
            return {'status': 'held', 'reason': 'This proposal is changed or has active consent'}
        operation = _operation(state, activation_id)
        with RetainedFile(path, mutation=True) as retained:
            if _json(retained.read(MAX_METADATA)) != value:
                raise SourceActivationError('Proposal changed during decline')
            retained.rename(operation / ('proposal-cancelled-' + secrets.token_hex(16) + '.json'))
        return {'status': 'cancelled', 'activation_id': activation_id, 'plan_sha256': plan_sha256}


class _ControllerHeartbeatWitness:
    """Query-only exact externally bound native generation for progress display."""
    def __init__(self, controller, pid, expected):
        from angerona.core.windows_process_lease import ProcessObjectIdentity
        if (type(expected) is not tuple or len(expected) != 5 or expected[0] not in {'broker', 'supervisor'}
                or pid != int(expected[1]) or not _digest_text(expected[4])):
            raise SourceActivationError('Optional progress native profile is invalid')
        self.controller, self.expected = controller, expected
        self.native = _NativeProcess(pid, expected[2], expected[3])
        try:
            self.pid, self.birth_ticks = pid, int(expected[2])
            self.identity = ProcessObjectIdentity(pid, self.birth_ticks,
                os.path.normcase(os.path.normpath(expected[3])))
            self.generation_id = str(pid) + ':' + str(self.birth_ticks)
            if not self.validate():
                raise SourceActivationError('Optional progress owner binding changed')
        except BaseException:
            self.close()
            raise

    def validate(self):
        return (self.native is not None and self.native.check() is True
            and _sha(read_exact(self.controller.state_root / 'activation-owner.json', MAX_METADATA)) == self.expected[4])

    def close(self):
        native, self.native = self.native, None
        if native is not None:
            native.close()


def _controller_heartbeat_started(self, worker):
    import threading
    if type(worker) is not threading.Thread or worker is not threading.current_thread():
        raise SourceActivationError('Optional progress must use the actual existing observer thread')
    with self._lock:
        prior = getattr(self, '_observer_thread', None)
        if prior is not None and prior is not worker:
            raise SourceActivationError('Optional observer cannot replace an unretired generation')
        self._observer_thread = worker
        self._observer_closed = False


def _controller_heartbeat_sample(self):
    from angerona.resilience.component_status import ComponentHeartbeatCache
    from angerona.resilience.heartbeat import optional_component
    try:
        native_rows = self.observe(timeout=1.0)
        context = current_source_activation_context(self.source_root, self.state_root)
        owner_sha = _sha(read_exact(self.state_root / 'activation-owner.json', MAX_METADATA))
        if context is None or owner_sha != self._owner_sha256:
            raise SourceActivationError('Optional heartbeat context changed')
        selected = ('source_startup', 'source_update_owner')
        cache = getattr(self, '_heartbeat_cache', None)
        if cache is None:
            names = {'source_startup': optional_component('source_startup', self.launch_id, context['supervisor_birth']),
                     'source_update_owner': optional_component('source_update_owner', self.launch_id, context['broker_birth'])}
            expected = {role: (prefix, str(context[prefix + '_pid']), context[prefix + '_birth'],
                              context[prefix + '_image'], owner_sha)
                        for role, prefix in (('source_startup', 'supervisor'), ('source_update_owner', 'broker'))}
            cache = ComponentHeartbeatCache(expected, selected_roles=selected, component_names=names,
                heartbeat_directory=self.state_root.parent / 'heartbeats', owned_core_pid=None,
                identity_factory=lambda pid, profile: _ControllerHeartbeatWitness(self, pid, profile))
            self._heartbeat_cache = cache
        cache.sample()
        present = {(row.pid, row.birth_ticks) for row in native_rows}
        publication = list(cache.snapshot())
        for row in publication:
            if row['role'] == 'source_startup' and (context['supervisor_pid'], context['supervisor_birth']) not in present:
                row.update(pid=context['supervisor_pid'], generation_id=str(context['supervisor_pid']) + ':' + context['supervisor_birth'],
                    state='stopped', last_heartbeat_monotonic=None,
                    reason='The exact short supervisor generation is retired; no advancing heartbeat is fabricated for its completed lifetime.')
        publication.append({'role': 'activation_broker', 'generation_id': '', 'pid': None,
            'last_heartbeat_monotonic': None, 'deadline_seconds': 8.0, 'state': 'disabled',
            'reason': 'No Python publisher may run while this Core lives. Its own progress is visible only in the post-Core startup/update interface.'})
        with self._lock:
            if not getattr(self, '_observer_stopped', False):
                self._heartbeat_publication = tuple(dict(row) for row in publication)
    except Exception as error:
        with self._lock:
            if getattr(self, '_observer_stopped', False):
                return
            self._heartbeat_publication = tuple({'role': role, 'generation_id': '', 'pid': None,
                'last_heartbeat_monotonic': None, 'deadline_seconds': 10.0, 'state': 'held',
                'reason': 'Authenticated controller progress is unavailable (' + type(error).__name__ + ').'}
                for role in ('source_startup', 'source_update_owner', 'activation_broker'))


def _controller_heartbeat_snapshot(self):
    if not self._lock.acquire(blocking=False):
        return tuple({'role': role, 'generation_id': '', 'pid': None, 'last_heartbeat_monotonic': None,
            'deadline_seconds': 10.0, 'state': 'unavailable', 'reason': 'Controller progress publication is busy.'}
            for role in ('source_startup', 'source_update_owner', 'activation_broker'))
    try:
        return tuple(dict(row) for row in getattr(self, '_heartbeat_publication', ())) or tuple({
            'role': role, 'generation_id': '', 'pid': None, 'last_heartbeat_monotonic': None,
            'deadline_seconds': 10.0, 'state': 'starting', 'reason': 'Waiting for actual authenticated controller progress.'}
            for role in ('source_startup', 'source_update_owner', 'activation_broker'))
    finally:
        self._lock.release()


def _controller_heartbeat_stop(self):
    with self._lock:
        self._observer_stopped = True
        cache = getattr(self, '_heartbeat_cache', None)
        if cache is not None:
            cache.mark_stopped()
        self._heartbeat_publication = tuple({'role': role, 'generation_id': '', 'pid': None,
            'last_heartbeat_monotonic': None, 'deadline_seconds': 10.0, 'state': 'stopped',
            'reason': 'The Core stopped its local progress observer; external owner retirement follows Core exit.'}
            for role in ('source_startup', 'source_update_owner', 'activation_broker'))


def _controller_heartbeat_close(self):
    _controller_heartbeat_stop(self)
    cache = getattr(self, '_heartbeat_cache', None)
    try:
        if cache is not None:
            cache.close()
        with self._lock:
            self._observer_closed = True
    except BaseException:
        with self._lock:
            self._observer_close_failure = True
        raise


def _controller_heartbeat_retired(self, worker):
    return (worker is getattr(self, '_observer_thread', None) and not worker.is_alive()
            and getattr(self, '_observer_closed', False) is True
            and not getattr(self, '_observer_close_failure', False))


# Explicit fixed methods keep the controller's lifecycle integration narrow.
SourceActivationController.heartbeat_started = _controller_heartbeat_started
SourceActivationController.heartbeat_sample = _controller_heartbeat_sample
SourceActivationController.heartbeat_snapshot = _controller_heartbeat_snapshot
SourceActivationController.heartbeat_stop = _controller_heartbeat_stop
SourceActivationController.heartbeat_close = _controller_heartbeat_close
SourceActivationController.heartbeat_retired = _controller_heartbeat_retired
