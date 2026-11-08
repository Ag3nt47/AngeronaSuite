"""Bounded storage admission/review for explicit source-update evidence only.

No automatic deletion, quota increase, startup inhibition, cache cleanup or
source publication occurs here. Active/pending and current-lineage evidence
remain protected. A storage hold leaves the current dashboard running.
"""
from __future__ import annotations
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import secrets
import zipfile
import time

from angerona.core import source_activation_file as file_api

DEFAULT_COMPLETED_BACKUPS = 2
DEFAULT_MAX_BYTES = 2 * 1024**3
MIN_FREE_BYTES = 2 * 1024**3
MAX_ENTRIES = 100000
MAX_DEPTH = 128
SCAN_SECONDS = 10.0
MAX_METADATA = 16 * 1024**2
_ROOT_DIRECTORIES = frozenset(('stages', 'activations', 'launches', 'checkpoints', 'exports', 'retention'))
_ROOT_FILES = frozenset(('check.json', 'check.lock', 'activation.lock', 'activation-owner.json',
    'activation-request.json', 'activation-proposal.json', 'activation-pending.json',
    'applied-base.json', 'activation-storage-policy.json', 'activation-storage-policy-pending.json'))


class SourceActivationStorageHeld(RuntimeError):
    def __init__(self, reason, review=None):
        super().__init__('Source-update storage held: ' + reason +
            '. Keep the dashboard running; review/export retained updates, explicitly approve eligible deletion, or review a bounded storage allowance change. Nothing was deleted.')
        self.review = review


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SourceActivationStorageHeld('duplicate storage review metadata')
        result[key] = value
    return result


def _read(path, absent=None):
    if not os.path.lexists(path):
        return absent
    raw = file_api.read_exact(path, MAX_METADATA)
    value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if type(value) is not dict:
        raise SourceActivationStorageHeld('storage metadata is not an object')
    return value


def _info_stamp(info):
    if (stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            or stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
        raise SourceActivationStorageHeld('unknown/redirected storage object needs review')
    return (str(info.st_dev), str(info.st_ino), info.st_size, str(info.st_mtime_ns), stat.S_ISDIR(info.st_mode))


def _stamp(path):
    return _info_stamp(path.lstat())


def _custody_stamp(stamp, *, directory):
    # Ancestor children are outside this review's inventory. Creating one can
    # change its parent's size/mtime without changing the directory object.
    # Keep the full stamp for callers inventorying that directory's contents.
    return (stamp[0], stamp[1], stamp[-1]) if directory else stamp


def _native_custody(native, *, directory):
    return (native.volume, native.index, native.attributes) if directory else native


@contextlib.contextmanager
def _held_node(path, *, directory):
    file_api.plain_path(path, directory=directory)
    before = _stamp(path)
    if os.name == 'nt':
        # This original stdlib-only dependency is also in the broker capsule.
        from tools import windows_publication_runtime as runtime
        from ctypes import wintypes as w
        raw = runtime._open_handle(Path(path), directory=directory,
                                   share_write=True, share_delete=not directory)
        try:
            native = runtime._handle_identity(raw)
            if (bool(native.attributes & 0x10) != directory or native.attributes & 0x400
                    or _custody_stamp(_stamp(path), directory=directory) !=
                       _custody_stamp(before, directory=directory)):
                raise SourceActivationStorageHeld('storage native object changed while opening')
            yield before
            if (_custody_stamp(_stamp(path), directory=directory) !=
                    _custody_stamp(before, directory=directory)
                    or _native_custody(runtime._handle_identity(raw), directory=directory) !=
                       _native_custody(native, directory=directory)):
                raise SourceActivationStorageHeld('storage object changed during review')
        finally:
            kernel = runtime._kernel32()
            kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = (w.HANDLE,), w.BOOL
            try:
                if not kernel.CloseHandle(w.HANDLE(raw)):
                    raise SourceActivationStorageHeld('storage query handle retirement is unproven')
            except BaseException:
                file_api._CLOSE_HOLDS.append(('storage-review-node', runtime, raw, str(path)))
                raise
    else:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(path, flags)
        try:
            opened = _info_stamp(os.fstat(fd))
            if (opened[-1] != directory or
                    _custody_stamp(opened, directory=directory) !=
                    _custody_stamp(before, directory=directory) or
                    _custody_stamp(_stamp(path), directory=directory) !=
                    _custody_stamp(before, directory=directory)):
                raise SourceActivationStorageHeld('storage descriptor is not its named object')
            yield before
            if (_custody_stamp(_stamp(path), directory=directory) !=
                    _custody_stamp(before, directory=directory) or
                    _custody_stamp(_info_stamp(os.fstat(fd)), directory=directory) !=
                    _custody_stamp(opened, directory=directory)):
                raise SourceActivationStorageHeld('storage object changed during review')
        finally:
            try:
                os.close(fd)
            except BaseException as error:
                file_api._CLOSE_HOLDS.append(('storage-review-fd', fd, str(path)))
                raise SourceActivationStorageHeld('storage query descriptor retirement is unproven') from error


@contextlib.contextmanager
def _held_chain(directory):
    with contextlib.ExitStack() as stack:
        for item in (*reversed(Path(directory).parents), Path(directory)):
            stack.enter_context(_held_node(item, directory=True))
        yield


def _policy(state):
    value = _read(state / 'activation-storage-policy.json')
    if value is None:
        return {'completed_backups': DEFAULT_COMPLETED_BACKUPS, 'max_bytes': DEFAULT_MAX_BYTES}
    if (set(value) != {'schema', 'completed_backups', 'max_bytes', 'accepted'}
            or value['schema'] != 'angerona.source-activation-storage-policy/v1'
            or value['accepted'] is not True or type(value['completed_backups']) is not int
            or not 1 <= value['completed_backups'] <= 8 or type(value['max_bytes']) is not int
            or not 64 * 1024**2 <= value['max_bytes'] <= 4 * 1024**3):
        raise SourceActivationStorageHeld('storage allowance is not an explicit bounded policy')
    return {'completed_backups': value['completed_backups'], 'max_bytes': value['max_bytes']}


def _same_volume(left, right):
    return left.stat().st_dev == right.stat().st_dev


def review_source_update_storage(source_root, state_root, *, cancelled=lambda: False, progress=lambda: None):
    state = Path(os.path.abspath(state_root))
    root = file_api.plain_path(Path(os.path.abspath(source_root)), directory=True)
    file_api.plain_path(state, directory=True)
    started = time.monotonic()
    seen, totals, used = [], {}, 0
    total = 0
    last_progress = started

    def check():
        nonlocal last_progress
        if cancelled():
            raise SourceActivationStorageHeld('storage review was cancelled')
        now = time.monotonic()
        if now - last_progress >= 0.5:
            progress()
            last_progress = now
        if not started <= time.monotonic() < started + SCAN_SECONDS:
            raise SourceActivationStorageHeld('bounded storage inventory is incomplete')

    def walk(directory, depth=0, owner=None):
        nonlocal total, used
        check()
        if depth > MAX_DEPTH:
            raise SourceActivationStorageHeld('storage depth exceeds the review bound')
        with _held_node(directory, directory=True) as before:
            with os.scandir(directory) as entries:
                for entry in entries:
                    check()
                    used += 1
                    if used > MAX_ENTRIES:
                        raise SourceActivationStorageHeld('storage entry count exceeds the review bound')
                    path = directory / entry.name
                    if depth == 0 and owner is None and entry.name not in _ROOT_DIRECTORIES | _ROOT_FILES:
                        raise SourceActivationStorageHeld('unrecognized update state needs review')
                    stamp = _stamp(path)
                    if stamp[-1]:
                        walk(path, depth + 1, owner)
                    else:
                        with _held_node(path, directory=False) as held:
                            total += held[2]
                            parts = path.relative_to(state).parts if owner is None else ()
                            key = owner if owner is not None else '/'.join(parts[:2]) if len(parts) > 1 else parts[0]
                            totals[key] = totals.get(key, 0) + held[2]
                            seen.append((path, held))
            if _stamp(directory) != before:
                raise SourceActivationStorageHeld('storage directory changed during inventory')
            seen.append((directory, before))

    with _held_chain(state):
        walk(state)
        # Only exact nonce paths from closed hash-bound operation plans are
        # inspected on the source volume. No .tmp discovery is performed.
        parent = state / 'activations'
        if os.path.lexists(parent):
            from angerona.core.source_activation_workspace import workspace_path, validate_workspace
            for operation in sorted(parent.iterdir()):
                check()
                if re.fullmatch(r'apply-[0-9a-f]{32}', operation.name) is None:
                    raise SourceActivationStorageHeld('unknown update operation needs review')
                plan_path = operation / 'plan.json'
                plan = _read(plan_path)
                if plan is None:
                    continue
                raw = file_api.read_exact(plan_path, MAX_METADATA)
                _maintenance_plan(root, state, operation.name[6:], raw, plan)
                workspace = workspace_path(root, plan)
                if os.path.lexists(workspace):
                    workspace, _ = validate_workspace(root, state, plan, hashlib.sha256(raw).hexdigest())
                    walk(workspace, owner='activations/' + operation.name)
        directories = sorted(((path, stamp) for path, stamp in seen if stamp[-1]),
                             key=lambda item: len(item[0].parts))
        if len(directories) > 2048:
            raise SourceActivationStorageHeld('storage directory seals exceed their bounded handle allowance')
        with contextlib.ExitStack() as directory_seals:
            for path, expected in directories:
                check()
                current = directory_seals.enter_context(_held_node(path, directory=True))
                if current != expected:
                    raise SourceActivationStorageHeld('storage directory changed after inventory')
            for path, expected in seen:
                check()
                if _stamp(path) != expected:
                    raise SourceActivationStorageHeld('storage namespace changed after inventory')
        protected = set()
        protected_reasons = {}
        for name in ('activation-pending.json', 'activation-request.json', 'activation-proposal.json', 'applied-base.json'):
            value = _read(state / name)
            if value is not None:
                identifier = value.get('activation_id')
                if type(identifier) is not str or not re.fullmatch(r'[0-9a-f]{32}', identifier):
                    raise SourceActivationStorageHeld('protected source-update lineage is malformed')
                protected.add(identifier)
                protected_reasons.setdefault(identifier, {'activation-pending.json': 'pending', 'activation-request.json': 'active-request',
                    'activation-proposal.json': 'queued-reconfirmation', 'applied-base.json': 'current-lineage'}[name])
        operations = []
        parent = state / 'activations'
        if os.path.lexists(parent):
            for path in sorted(parent.iterdir()):
                check()
                if not re.fullmatch(r'apply-[0-9a-f]{32}', path.name) or not path.is_dir():
                    raise SourceActivationStorageHeld('unrecognized activation evidence needs review')
                identifier = path.name[6:]
                terminal = _read(path / 'committed.json') or _read(path / 'rolled-back.json')
                retired_payload = _read(path / 'backup-retired.json')
                retired_payload_ok = (type(retired_payload) is dict and retired_payload.get('schema') == 'angerona.source-activation-backup-retired/v1'
                                      and retired_payload.get('activation_id') == identifier)
                complete = terminal is not None and terminal.get('status') in {'committed', 'rolled_back'}
                inactive_candidate = (not complete and not os.path.lexists(path / 'transaction.json')
                    and os.path.lexists(path / 'plan.json') and identifier not in protected)
                deletable = (complete or inactive_candidate) and not retired_payload_ok and identifier not in protected
                operations.append({'activation_id': identifier, 'status': 'retired-payload' if retired_payload_ok else 'completed' if complete else 'inactive-candidate' if inactive_candidate else 'prepared-or-held',
                    'logical_bytes': totals.get('activations/' + path.name, 0),
                    'protected': identifier in protected,
                    'protected_reason': protected_reasons.get(identifier, 'retired-audit' if retired_payload_ok else '' if (complete or inactive_candidate) else 'unknown-custody'),
                    'export_allowed': deletable,
                    'delete_requires_confirmation': deletable})
        policy_pending = os.path.lexists(state / 'activation-storage-policy-pending.json')
        budget = ({'completed_backups': DEFAULT_COMPLETED_BACKUPS, 'max_bytes': DEFAULT_MAX_BYTES}
                  if policy_pending else _policy(state))
        available = shutil.disk_usage(state).free
        if type(available) is not int or available < 0:
            raise SourceActivationStorageHeld('native free-space observation is unavailable')
        same_volume = _same_volume(root, state)
        source_available = available if same_volume else shutil.disk_usage(root).free
        if type(source_available) is not int or source_available < 0:
            raise SourceActivationStorageHeld('source-volume free space is unavailable')
        result = {'schema': 'angerona.source-activation-storage-review/v1', 'source_root': str(root),
            'state_root': str(state), 'retained_bytes': total, 'completed_backups': sum(
                row['status'] == 'completed' for row in operations), 'entries': used,
            'protected_ids': sorted(protected), 'operations': operations, 'budget': budget,
            'policy_status': 'held-incomplete-policy' if policy_pending else 'ready',
            'free_bytes': available, 'source_free_bytes': source_available, 'same_volume': same_volume, 'free_reserve_bytes': MIN_FREE_BYTES,
            'inventory_sha256': hashlib.sha256(_encoded([(str(path.relative_to(state)) if state == path or state in path.parents else '@source/' + path.relative_to(root).as_posix(), stamp) for path, stamp in seen])).hexdigest(),
            'review_path': str(state), 'actions': ['review', 'export', 'delete-approved', 'allow-change'],
            'automatic_deletion': False, 'startup_inhibited': False}
        bound = {key: value for key, value in result.items() if key not in {'free_bytes', 'source_free_bytes'}}
        result['review_sha256'] = hashlib.sha256(_encoded(bound)).hexdigest()
        return result


def require_source_update_storage(source_root, state_root, *, additional_bytes=0,
                                  new_completed_backup=False, source_additional_bytes=0, cancelled=lambda: False, progress=lambda: None):
    if (type(additional_bytes) is not int or additional_bytes < 0 or type(new_completed_backup) is not bool
            or type(source_additional_bytes) is not int or not 0 <= source_additional_bytes <= additional_bytes):
        raise SourceActivationStorageHeld('storage admission request is invalid')
    review = review_source_update_storage(source_root, state_root, cancelled=cancelled, progress=progress)
    budget = review['budget']
    if review['policy_status'] != 'ready':
        raise SourceActivationStorageHeld('a prior policy change requires review; no default allowance is granted', review)
    if new_completed_backup and review['completed_backups'] >= budget['completed_backups']:
        raise SourceActivationStorageHeld('completed backup count is at its reviewed limit', review)
    if review['retained_bytes'] + additional_bytes > budget['max_bytes']:
        raise SourceActivationStorageHeld('combined stages/backups/capsules/journals exceed their reviewed byte limit', review)
    control_additional = additional_bytes if review['same_volume'] else additional_bytes - source_additional_bytes
    if (review['free_bytes'] < MIN_FREE_BYTES + control_additional
            or not review['same_volume'] and review['source_free_bytes'] < MIN_FREE_BYTES + source_additional_bytes):
        raise SourceActivationStorageHeld('the fixed free-space reserve is unavailable on a required volume', review)
    return review


_HEX32 = re.compile(r'[0-9a-f]{32}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def _private_directory(path):
    from angerona.core.startup_recovery import private_directory
    if not os.path.lexists(path) and not private_directory(path, create=True):
        raise SourceActivationStorageHeld('private maintenance directory could not be created')
    file_api.plain_path(path, directory=True)
    if not private_directory(path, create=False) and not file_api.private_owner_rights_directory(path):
        raise SourceActivationStorageHeld('maintenance directory lacks private custody')
    return path


def _write_record(path, value):
    raw = _encoded(value)
    if len(raw) > MAX_METADATA:
        raise SourceActivationStorageHeld('maintenance metadata exceeds its bounded allowance')
    file_api.write_new(path, raw)


def _scope_tree(path):
    files, directories = {}, {}
    started = time.monotonic()
    def walk(node, depth):
        if depth > MAX_DEPTH or time.monotonic() >= started + SCAN_SECONDS:
            raise SourceActivationStorageHeld('backup scope inventory is incomplete')
        with _held_node(node, directory=True) as stamp:
            directories[node.relative_to(path).as_posix()] = stamp
            with os.scandir(node) as entries:
                for entry in entries:
                    if len(files) + len(directories) >= MAX_ENTRIES:
                        raise SourceActivationStorageHeld('backup scope exceeds its entry bound')
                    child = node / entry.name
                    current = _stamp(child)
                    if current[-1]:
                        walk(child, depth + 1)
                    else:
                        with _held_node(child, directory=False) as held:
                            files[child.relative_to(path).as_posix()] = held
    with _held_chain(path.parent):
        walk(path, 0)
    return files, directories


def _safe_relative(name):
    from pathlib import PurePosixPath
    return (type(name) is str and 0 < len(name) <= 4096 and not name.startswith('/')
            and PurePosixPath(name).as_posix() == name
            and all(part not in {'', '.', '..'} and ':' not in part and '\\' not in part
                    for part in name.split('/')))



_CAPSULE_FILES = frozenset((
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
))


def _maintenance_plan(source_root, state, identifier, plan_raw, plan):
    if (type(plan) is not dict or plan.get('schema') != 'angerona.source-activation-plan/v1'
            or plan.get('activation_id') != identifier or plan.get('source_root') != str(source_root)
            or plan.get('state_root') != str(state) or type(plan.get('stage_id')) is not str
            or re.fullmatch(r'source-[0-9a-f]{32}', plan['stage_id']) is None
            or type(plan.get('manifest_sha256')) is not str or _HEX64.fullmatch(plan['manifest_sha256']) is None):
        raise SourceActivationStorageHeld('backup plan stage/scope binding is invalid')
    for key in ('before', 'after'):
        tree = plan.get(key)
        if type(tree) is not dict or len(tree) > 8192:
            raise SourceActivationStorageHeld('backup source manifest shape is invalid')
        for name, row in tree.items():
            if (not _safe_relative(name) or type(row) is not dict or set(row) != {'sha256', 'bytes'}
                    or type(row['sha256']) is not str or _HEX64.fullmatch(row['sha256']) is None
                    or type(row['bytes']) is not int or not 0 <= row['bytes'] <= 16 * 1024**2):
                raise SourceActivationStorageHeld('backup source manifest row is invalid')
    changes = plan.get('changed_paths')
    if (type(changes) is not list or not 1 <= len(changes) <= 8192
            or any(type(name) is not str for name in changes) or len(set(changes)) != len(changes)
            or any(not _safe_relative(name) or name not in set(plan['before']) | set(plan['after']) for name in changes)):
        raise SourceActivationStorageHeld('backup changed-path manifest is invalid')
    snapshot = plan.get('broker_snapshot')
    if (type(snapshot) is not dict or set(snapshot) != {'schema', 'files'}
            or snapshot['schema'] != 'angerona.source-activation-broker-snapshot/v1'
            or type(snapshot['files']) is not dict or set(snapshot['files']) != _CAPSULE_FILES):
        raise SourceActivationStorageHeld('backup capsule manifest shape is invalid')
    for row in snapshot['files'].values():
        if (type(row) is not dict or set(row) != {'sha256', 'bytes'}
                or type(row['sha256']) is not str or _HEX64.fullmatch(row['sha256']) is None
                or type(row['bytes']) is not int or not 0 <= row['bytes'] <= 4 * 1024**2):
            raise SourceActivationStorageHeld('backup capsule manifest row is invalid')
    body = dict(plan)
    body.pop('activation_id')
    if hashlib.sha256(_encoded(body)).hexdigest()[:32] != identifier:
        raise SourceActivationStorageHeld('backup plan content identity changed')
    stage_parent = file_api.plain_path(state / 'stages', directory=True)
    candidate = stage_parent / plan['stage_id']
    if candidate.parent != stage_parent:
        raise SourceActivationStorageHeld('backup stage is not its exact direct child')
    return candidate


_NATIVE_OUTPUT_LIMIT = 128
_NATIVE_LOG_LIMIT = 1024**2
_NATIVE_RECEIPT_LIMIT = 4096
_NATIVE_RECEIPT_KEYS = frozenset(('schema', 'activation_id', 'guard_nonce',
    'guard_sha256', 'plan_sha256', 'request_sha256', 'log_sha256', 'log_bytes',
    'child_job_retired', 'child_handles_closed', 'inherited_descendants_retired',
    'independent_attestation', 'observation_source'))
_NATIVE_GUARD_KEYS = frozenset(('schema', 'operation', 'guard_nonce', 'launch_id',
    'activation_id', 'plan_sha256', 'request_sha256', 'owner_sha256', 'source_root',
    'state_root', 'parent_pid', 'parent_birth', 'parent_image', 'parent_script_sha256',
    'root_identity', 'leases', 'retirement', 'snapshot_sha256'))
_NATIVE_OUTCOME_KEYS = frozenset(('schema', 'status', 'activation_id', 'plan_sha256',
    'request_sha256', 'guard_sha256', 'snapshot_sha256', 'source_root', 'state_root',
    'root_identity', 'pending_present', 'result'))


def _native_output_json(path, maximum):
    from angerona.core.startup_recovery import private_repair_file
    if not private_repair_file(path):
        raise SourceActivationStorageHeld('native output evidence is not private')
    raw = file_api.read_exact(path, maximum)
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise SourceActivationStorageHeld('native output evidence is malformed') from error
    if type(value) is not dict or not private_repair_file(path):
        raise SourceActivationStorageHeld('native output evidence custody changed')
    return raw, value


def _native_output_expectations(source_root, state, operation, plan, plan_raw, files, directories):
    # These closed receipts retain a PARENT ASSERTION, not independent native
    # attestation or an update/response authority grant. Unknown output stays.
    names = {name for name in files if name == 'native-output' or name.startswith('native-output/')}
    native_dirs = {name for name in directories if name == 'native-output' or name.startswith('native-output/')}
    if not names and not native_dirs:
        return {}
    groups = set()
    for name in names:
        parts = name.split('/')
        if (len(parts) != 3 or parts[0] != 'native-output' or not _HEX32.fullmatch(parts[1])
                or parts[2] not in {'activation.log', 'receipt.json'}):
            raise SourceActivationStorageHeld('unknown native output object must be preserved')
        groups.add(parts[1])
    if not 1 <= len(groups) <= _NATIVE_OUTPUT_LIMIT or native_dirs != {'native-output'} | {
            'native-output/' + nonce for nonce in groups}:
        raise SourceActivationStorageHeld('native output directories are incomplete or unknown')
    root_id = plan.get('root_identity')
    if (type(root_id) is not dict or set(root_id) != {'device', 'inode'}
            or any(type(value) is not str or re.fullmatch(r'[0-9]{1,40}', value) is None
                   for value in root_id.values())):
        raise SourceActivationStorageHeld('native output plan root identity is invalid')
    plan_sha = hashlib.sha256(plan_raw).hexdigest()
    snapshot_sha = hashlib.sha256(_encoded(plan['broker_snapshot'])).hexdigest()
    expected, started = {}, time.monotonic()
    for nonce in sorted(groups):
        if not started <= time.monotonic() < started + SCAN_SECONDS:
            raise SourceActivationStorageHeld('native output verification exceeded its bounded review')
        prefix = 'native-output/' + nonce + '/'
        members = {name for name in names if name.startswith(prefix)}
        if members != {prefix + 'activation.log', prefix + 'receipt.json'}:
            raise SourceActivationStorageHeld('native output log/receipt pair is incomplete')
        receipt_raw, receipt = _native_output_json(operation / (prefix + 'receipt.json'), _NATIVE_RECEIPT_LIMIT)
        if (set(receipt) != _NATIVE_RECEIPT_KEYS
                or receipt['schema'] != 'angerona.source-activation-native-output/v1'
                or receipt['activation_id'] != plan['activation_id'] or receipt['guard_nonce'] != nonce
                or any(type(receipt[key]) is not str or _HEX64.fullmatch(receipt[key]) is None
                       for key in ('guard_sha256', 'plan_sha256', 'request_sha256', 'log_sha256'))
                or receipt['plan_sha256'] != plan_sha
                or type(receipt['log_bytes']) is not int or not 0 <= receipt['log_bytes'] <= _NATIVE_LOG_LIMIT
                or receipt['child_job_retired'] is not True or receipt['child_handles_closed'] is not True
                or receipt['inherited_descendants_retired'] is not True
                or receipt['independent_attestation'] is not False
                or receipt['observation_source'] != 'parent-observed-owned-job'):
            raise SourceActivationStorageHeld('native output receipt scope or parent observation is invalid')
        guard_name, used_name, result_name = ('guard-' + nonce + '.json',
            'guard-used-' + nonce + '.json', 'result-' + nonce + '.json')
        if any(name not in files for name in (guard_name, used_name, result_name)):
            raise SourceActivationStorageHeld('native output guard/result evidence is incomplete')
        guard_raw, guard = _native_output_json(operation / guard_name, MAX_METADATA)
        used_raw, used = _native_output_json(operation / used_name, _NATIVE_RECEIPT_LIMIT)
        result_raw, result = _native_output_json(operation / result_name, MAX_METADATA)
        if (set(guard) != _NATIVE_GUARD_KEYS or type(guard['schema']) is not int or guard['schema'] != 1
                or type(guard['operation']) is not str or guard['operation'] not in {'activate', 'reconcile'} or guard['guard_nonce'] != nonce
                or guard['activation_id'] != plan['activation_id'] or guard['plan_sha256'] != plan_sha
                or guard['request_sha256'] != receipt['request_sha256']
                or guard['source_root'] != str(source_root) or guard['state_root'] != str(state)
                or guard['root_identity'] != root_id or guard['snapshot_sha256'] != snapshot_sha
                or hashlib.sha256(guard_raw).hexdigest() != receipt['guard_sha256']
                or set(used) != {'guard_sha256', 'operation'}
                or used != {'guard_sha256': receipt['guard_sha256'], 'operation': guard['operation']}):
            raise SourceActivationStorageHeld('native output original guard or one-use marker changed')
        if (set(result) != _NATIVE_OUTCOME_KEYS or result['schema'] != 'angerona.source-activation-outcome/v1'
                or type(result['status']) is not str or result['status'] not in {'committed', 'rolled_back'}
                or result['activation_id'] != plan['activation_id'] or result['plan_sha256'] != plan_sha
                or result['request_sha256'] != receipt['request_sha256']
                or result['guard_sha256'] != receipt['guard_sha256'] or result['snapshot_sha256'] != snapshot_sha
                or result['source_root'] != str(source_root) or result['state_root'] != str(state)
                or result['root_identity'] != root_id or result['pending_present'] is not False
                or type(result['result']) is not dict or result['result'].get('status') != result['status']):
            raise SourceActivationStorageHeld('native output result scope is not a terminal verified outcome')
        terminal_name = 'committed.json' if result['status'] == 'committed' else 'rolled-back.json'
        terminal = _read(operation / terminal_name)
        if (type(terminal) is not dict or terminal.get('status') != result['status']
                or terminal.get('plan_sha256') != plan_sha):
            raise SourceActivationStorageHeld('native output terminal evidence is absent or changed')
        from angerona.core.startup_recovery import private_repair_file
        log_path = operation / (prefix + 'activation.log')
        if not private_repair_file(log_path):
            raise SourceActivationStorageHeld('native output log lacks private custody')
        with file_api.RetainedFile(log_path) as log:
            digest, size = log.digest(_NATIVE_LOG_LIMIT)
        if (digest != receipt['log_sha256'] or size != receipt['log_bytes']
                or not private_repair_file(log_path)):
            raise SourceActivationStorageHeld('native output log bytes changed')
        expected.update({prefix + 'receipt.json': hashlib.sha256(receipt_raw).hexdigest(),
            prefix + 'activation.log': digest, guard_name: receipt['guard_sha256'],
            used_name: hashlib.sha256(used_raw).hexdigest(), result_name: hashlib.sha256(result_raw).hexdigest()})
    return expected



_HANDOFF_LIMIT = 32
_HANDOFF_RECEIPT_LIMIT = 8192
_HANDOFF_KEYS = frozenset(('schema', 'handoff_nonce', 'activation_id', 'plan_sha256',
    'request_sha256', 'gate_pid', 'gate_birth', 'cmd_pid', 'cmd_birth',
    'resume_pid', 'resume_birth', 'resume_image'))
_HANDOFF_REQUEST_KEYS = frozenset(('schema', 'activation_id', 'plan_sha256',
    'approval_id', 'source_root', 'state_root', 'launch_id', 'owner_sha256',
    'core_pid', 'core_birth', 'broker_pid', 'broker_birth', 'retirement_scope', 'accepted'))


def _handoff_expectations(source_root, state, operation, plan, plan_raw, files, directories):
    # A historical ready ACK is NOT proof that any launcher is now retired.
    # This verifier grants only a bounded old-backup storage scope.
    expected = {}
    if 'resume-owner.lock' in files:
        from angerona.core.startup_recovery import private_repair_file
        lock = operation / 'resume-owner.lock'
        if not private_repair_file(lock):
            raise SourceActivationStorageHeld('recovery owner lock is not private')
        raw = file_api.read_exact(lock, 1)
        if raw != b'\x00' or not private_repair_file(lock):
            raise SourceActivationStorageHeld('recovery owner lock has an unknown value')
        expected['resume-owner.lock'] = hashlib.sha256(raw).hexdigest()
    names = {name for name in files if name == 'handoffs' or name.startswith('handoffs/')}
    handoff_dirs = {name for name in directories if name == 'handoffs' or name.startswith('handoffs/')}
    if not names and not handoff_dirs:
        return expected
    groups = set()
    for name in names:
        parts = name.split('/')
        if (len(parts) != 3 or parts[0] != 'handoffs' or _HEX32.fullmatch(parts[1]) is None
                or parts[2] != 'ready.json'):
            raise SourceActivationStorageHeld('unknown recovery handoff must be preserved')
        groups.add(parts[1])
    if (not 1 <= len(groups) <= _HANDOFF_LIMIT or 'resume-owner.lock' not in expected
            or handoff_dirs != {'handoffs'} | {'handoffs/' + nonce for nonce in groups}):
        raise SourceActivationStorageHeld('recovery handoff directories or owner lock are incomplete')
    if os.name != 'nt':
        raise SourceActivationStorageHeld('native recovery handoff profile is unavailable on this platform')
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes, kernel.GetSystemDirectoryW.restype = (w.LPWSTR, w.UINT), w.UINT
    system = ctypes.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(system, len(system))
    if not 0 < length < len(system):
        raise SourceActivationStorageHeld('fixed native recovery image is unavailable')
    image = os.path.normcase(os.path.normpath(str(Path(system.value) / 'WindowsPowerShell/v1.0/powershell.exe')))
    plan_sha, started = hashlib.sha256(plan_raw).hexdigest(), time.monotonic()
    for nonce in sorted(groups):
        if not started <= time.monotonic() < started + SCAN_SECONDS:
            raise SourceActivationStorageHeld('recovery handoff review exceeded its bounded time')
        name = 'handoffs/' + nonce + '/ready.json'
        raw, ready = _native_output_json(operation / name, _HANDOFF_RECEIPT_LIMIT)
        if (set(ready) != _HANDOFF_KEYS or ready['schema'] != 'angerona.source-activation-resume-ready/v1'
                or ready['handoff_nonce'] != nonce or ready['activation_id'] != plan['activation_id']
                or ready['plan_sha256'] != plan_sha or type(ready['request_sha256']) is not str
                or _HEX64.fullmatch(ready['request_sha256']) is None
                or any(type(ready[key]) is not int or not 0 < ready[key] <= 0xffffffff
                       for key in ('gate_pid', 'cmd_pid', 'resume_pid'))
                or len({ready['gate_pid'], ready['cmd_pid'], ready['resume_pid']}) != 3
                or any(type(ready[key]) is not str or re.fullmatch(r'[1-9][0-9]{0,18}', ready[key]) is None
                       or int(ready[key]) > 0x7fffffffffffffff for key in ('gate_birth', 'cmd_birth', 'resume_birth'))
                or type(ready['resume_image']) is not str or not Path(ready['resume_image']).is_absolute()
                or os.path.normcase(os.path.normpath(ready['resume_image'])) != image):
            raise SourceActivationStorageHeld('recovery handoff ready metadata is outside its closed profile')
        request_name = 'requests/' + ready['request_sha256'] + '.json'
        if request_name not in files:
            raise SourceActivationStorageHeld('recovery handoff approved request evidence is absent')
        request_raw, request = _native_output_json(operation / request_name, MAX_METADATA)
        if (hashlib.sha256(request_raw).hexdigest() != ready['request_sha256']
                or set(request) != _HANDOFF_REQUEST_KEYS or request['schema'] != 'angerona.source-activation-request/v1'
                or request['activation_id'] != plan['activation_id'] or request['plan_sha256'] != plan_sha
                or request['source_root'] != str(source_root) or request['state_root'] != str(state)
                or request['accepted'] is not True):
            raise SourceActivationStorageHeld('recovery handoff request scope or original bytes changed')
        expected[name] = hashlib.sha256(raw).hexdigest()
        expected[request_name] = ready['request_sha256']
    return expected


def _backup_scope(source_root, state, identifier, review):
    if type(identifier) is not str or not _HEX32.fullmatch(identifier):
        raise SourceActivationStorageHeld('backup identity is invalid')
    selected = [row for row in review['operations'] if row['activation_id'] == identifier]
    if len(selected) != 1 or selected[0]['status'] not in {'completed', 'inactive-candidate'} or selected[0]['protected']:
        raise SourceActivationStorageHeld('current/active/interrupted/lineage backup is protected', review)
    operation = state / 'activations' / ('apply-' + identifier)
    plan_raw = file_api.read_exact(operation / 'plan.json', MAX_METADATA)
    plan = _read(operation / 'plan.json')
    terminal = _read(operation / 'committed.json') or _read(operation / 'rolled-back.json')
    if (type(plan) is not dict or plan.get('schema') != 'angerona.source-activation-plan/v1'
            or plan.get('activation_id') != identifier or plan.get('source_root') != str(source_root)
            or plan.get('state_root') != str(state)
            or (terminal is not None and terminal.get('plan_sha256') != hashlib.sha256(plan_raw).hexdigest())):
        raise SourceActivationStorageHeld('backup plan/terminal binding changed')
    candidate_stage = _maintenance_plan(source_root, state, identifier, plan_raw, plan)
    if terminal is None and os.path.lexists(operation / 'transaction.json'):
        raise SourceActivationStorageHeld('uncertain transaction must be preserved')
    files, directories = _scope_tree(operation)
    native_outputs = _native_output_expectations(source_root, state, operation, plan, plan_raw, files, directories)
    native_outputs.update(_handoff_expectations(source_root, state, operation, plan, plan_raw, files, directories))
    fixed = {'plan.json', 'transaction.json', 'journal.jsonl', 'committed.json', 'rolled-back.json',
             'applied-base.old.json', 'applied-base.new.json', 'applied-base.rolled-back.json',
             'committed-pending.json', 'rolled-back-pending.json', 'committed-proposal.json', 'rolled-back-proposal.json', 'backup-retired.json', 'resume-owner.lock'}
    metadata = re.compile(r'(?:approval|accepted-proposal|cancelled|guard|guard-used|result|committed-request|rolled-back-request|proposal-cancelled)-[0-9a-f]{32}\.json\Z')
    expected = {}
    for name, stamp in files.items():
        parts = name.split('/')
        digest = native_outputs.get(name)
        if len(parts) == 1 and (name in fixed or metadata.fullmatch(name)):
            pass
        elif len(parts) == 2 and parts[0] == 'archive' and _HEX64.fullmatch(parts[1]):
            if parts[1] not in {row['sha256'] for row in plan['before'].values()}:
                raise SourceActivationStorageHeld('unknown original backup object must be preserved')
            digest = parts[1]
        elif len(parts) == 2 and parts[0] in {'old', 'new', 'rolled-back'} and parts[1].isdecimal():
            number = int(parts[1])
            if not 0 <= number < len(plan['changed_paths']):
                raise SourceActivationStorageHeld('unknown numbered backup object must be preserved')
            key = plan['changed_paths'][number]
            digest = plan['before' if parts[0] == 'old' else 'after'].get(key, {}).get('sha256')
            if digest is None:
                raise SourceActivationStorageHeld('backup file has no original/candidate binding')
        elif len(parts) == 2 and parts[0] == 'requests' and parts[1].endswith('.json') and _HEX64.fullmatch(parts[1][:-5]):
            digest = parts[1][:-5]
        elif parts[0] == 'handoffs':
            if name not in native_outputs:
                raise SourceActivationStorageHeld('unknown recovery handoff must be preserved')
        elif parts[0] == 'native-output':
            if name not in native_outputs:
                raise SourceActivationStorageHeld('unknown native output must be preserved')
        elif parts[0] == 'broker':
            relative = '/'.join(parts[1:])
            if relative == 'snapshot.json':
                digest = hashlib.sha256(_encoded(plan['broker_snapshot'])).hexdigest()
            elif relative in plan['broker_snapshot']['files']:
                digest = plan['broker_snapshot']['files'][relative]['sha256']
            else:
                raise SourceActivationStorageHeld('unknown capsule object must be preserved')
        else:
            raise SourceActivationStorageHeld('unknown file added to backup must be preserved')
        expected[name] = {'stamp': stamp, 'sha256': digest}
    allowed_directories = {'.', 'archive', 'new', 'old', 'rolled-back', 'broker', 'requests'}
    for name in expected:
        parts = name.split('/')
        allowed_directories.update('/'.join(parts[:index]) for index in range(1, len(parts)))
    if set(directories) - allowed_directories:
        raise SourceActivationStorageHeld('unknown directory added to backup must be preserved')
    scopes = {'activation': {'path': operation, 'files': expected, 'directories': directories}}
    from angerona.core.source_activation_workspace import workspace_path, validate_workspace
    workspace = workspace_path(Path(source_root), plan)
    if os.path.lexists(workspace):
        workspace, descriptor = validate_workspace(Path(source_root), state, plan, hashlib.sha256(plan_raw).hexdigest())
        work_files, work_dirs = _scope_tree(workspace)
        if set(work_dirs) != {'.', 'old', 'new', 'rolled-back'}:
            raise SourceActivationStorageHeld('unknown workspace directory must be preserved')
        work_expected = {}
        for name, stamp in work_files.items():
            if name == 'workspace.json':
                digest = descriptor['marker_sha256']
            else:
                parts = name.split('/')
                if (len(parts) != 2 or parts[0] not in {'old', 'new', 'rolled-back'}
                        or not parts[1].isascii() or not parts[1].isdecimal()
                        or not 0 <= int(parts[1]) < len(plan['changed_paths'])):
                    raise SourceActivationStorageHeld('unknown workspace payload must be preserved')
                key = plan['changed_paths'][int(parts[1])]
                digest = plan['before' if parts[0] == 'old' else 'after'].get(key, {}).get('sha256')
                if digest is None:
                    raise SourceActivationStorageHeld('workspace payload lacks its source binding')
            work_expected[name] = {'stamp': stamp, 'sha256': digest}
        scopes['workspace'] = {'path': workspace, 'files': work_expected, 'directories': work_dirs}
    # Only an unreferenced completed stage can accompany its old restore point.
    stage_id = plan['stage_id']
    other_refs = False
    for row in review['operations']:
        if row['activation_id'] == identifier:
            continue
        other = _read(state / 'activations' / ('apply-' + row['activation_id']) / 'plan.json')
        if other is not None and other.get('stage_id') == stage_id:
            other_refs = True
    if not other_refs and os.path.lexists(candidate_stage):
        stage_raw = file_api.read_exact(candidate_stage / 'manifest.json', MAX_METADATA)
        if hashlib.sha256(stage_raw).hexdigest() != plan['manifest_sha256']:
            raise SourceActivationStorageHeld('the associated stage changed after activation')
        # Maintenance owns raw staged evidence, while plan.after binds the
        # separately derived effective publication. Reuse the ORIGINAL broker's
        # closed raw-manifest/resolution/candidate verifier, never stage code.
        from angerona.core import source_activation_broker as broker
        resolution_path = candidate_stage / 'resolutions.json'
        resolution_file_sha = None
        try:
            if os.path.lexists(resolution_path):
                resolution_raw = file_api.read_exact(resolution_path, MAX_METADATA)
                resolution = broker._json(resolution_raw)
                resolution_file_sha = hashlib.sha256(resolution_raw).hexdigest()
            else:
                resolution = {'schema': 'angerona.source-resolutions/v1',
                    'manifest_sha256': plan['manifest_sha256'], 'files': {}}
            if hashlib.sha256(_encoded(resolution)).hexdigest() != plan.get('resolution_sha256'):
                raise SourceActivationStorageHeld('the associated stage resolutions changed after activation')
            raw_candidate = broker._raw_stage_candidate(candidate_stage, stage_raw, resolution, plan)
            raw_candidate_manifest = broker._manifest(raw_candidate)
            # Keep the original exact-raw contract valid for historical restore
            # points. A differing effective plan must match trusted derivation.
            if raw_candidate_manifest != plan['after']:
                effective = broker._effective_recovery_candidate(raw_candidate)
                if broker._manifest(effective) != plan['after']:
                    raise SourceActivationStorageHeld('the associated effective candidate differs from its approved plan')
            stage_body = broker._json(stage_raw)
        except (broker.SourceActivationError, file_api.ActivationFileError,
                ValueError, TypeError, KeyError, OSError, RecursionError) as error:
            raise SourceActivationStorageHeld('the associated raw stage candidate or resolutions changed after activation') from error
        blob_hashes = {value for row in stage_body['files'] for side in ('base', 'user', 'upstream')
                       if (value := row.get(side)) is not None}
        stage_files, stage_dirs = _scope_tree(candidate_stage)
        if ("resolutions.json" in stage_files) != (resolution_file_sha is not None):
            raise SourceActivationStorageHeld("the associated resolution file presence changed")
        stage_expected = {}
        for name, stamp in stage_files.items():
            digest = None
            if name == 'manifest.json':
                digest = plan['manifest_sha256']
            elif name == 'resolutions.json':
                digest = resolution_file_sha
            elif name in {'intent.json', 'result.json', 'validation.json', 'resolution.lock'}:
                pass
            elif name.startswith('resolution-intents/') and len(name.split('/')) == 2:
                intent = _read(candidate_stage / name)
                known = {row['path'] for row in stage_body['files'] if row.get('action') == 'conflict'}
                if (type(intent) is not dict or intent.get('schema') != 'angerona.source-resolution-intent/v1'
                        or intent.get('manifest_sha256') != plan['manifest_sha256']
                        or intent.get('path') not in known
                        or name.split('/')[1] != hashlib.sha256(intent['path'].encode('utf-8')).hexdigest() + '.json'):
                    raise SourceActivationStorageHeld('unknown resolution intent must be preserved')
            elif name.startswith('preserved-blobs/') and name.split('/', 1)[1] in blob_hashes:
                digest = name.split('/', 1)[1]
            elif name.startswith('candidate/') and name[10:] in raw_candidate_manifest:
                digest = raw_candidate_manifest[name[10:]]['sha256']
            else:
                raise SourceActivationStorageHeld('unknown stage object must be preserved')
            stage_expected[name] = {'stamp': stamp, 'sha256': digest}
        stage_allowed_dirs = {'.', 'candidate', 'preserved-blobs', 'resolution-intents'}
        for name in stage_expected:
            parts = name.split('/')
            stage_allowed_dirs.update('/'.join(parts[:index]) for index in range(1, len(parts)))
        if set(stage_dirs) - stage_allowed_dirs:
            raise SourceActivationStorageHeld('unknown stage directory must be preserved')
        scopes['stage'] = {'path': candidate_stage, 'files': stage_expected, 'directories': stage_dirs}
    descriptor = {label: {'path': str(row['path']), 'files': row['files'], 'directories': row['directories']}
                  for label, row in scopes.items()}
    return scopes, hashlib.sha256(_encoded(descriptor)).hexdigest()


def _accepted_review(source_root, state_root, identifier, expected_sha):
    state = Path(os.path.abspath(state_root))
    review = review_source_update_storage(source_root, state)
    if type(expected_sha) is not str or not _HEX64.fullmatch(expected_sha) or review['review_sha256'] != expected_sha:
        raise SourceActivationStorageHeld('storage review scope changed; refresh before confirming', review)
    scopes, scope_sha = _backup_scope(source_root, state, identifier, review)
    return state, scopes, scope_sha


class _RetainedZipIO:
    """Seekable adapter; the exact RetainedFile alone owns its descriptor."""
    def __init__(self, held):
        self.held = held

    def tell(self):
        self.held.check()
        return os.lseek(self.held.fd, 0, os.SEEK_CUR)

    def seek(self, offset, whence=os.SEEK_SET):
        self.held.check()
        return os.lseek(self.held.fd, offset, whence)

    def seekable(self):
        return True

    def read(self, size=-1):
        self.held.check()
        remaining = max(0, self.held.initial['bytes'] - self.tell())
        size = remaining if size is None or size < 0 else min(size, remaining)
        parts = []
        while size:
            part = os.read(self.held.fd, min(size, 65536))
            if not part:
                raise SourceActivationStorageHeld('private export read was incomplete')
            parts.append(part)
            size -= len(part)
        self.held.check()
        return b''.join(parts)

    def write(self, raw):
        self.held.check()
        if self.tell() + len(raw) > DEFAULT_MAX_BYTES:
            raise SourceActivationStorageHeld('private export exceeds its bounded byte allowance')
        offset = 0
        while offset < len(raw):
            count = os.write(self.held.fd, raw[offset:offset + 65536])
            if count <= 0:
                raise SourceActivationStorageHeld('private export write was incomplete')
            offset += count
        self.held.initial = file_api.identity(os.fstat(self.held.fd))
        self.held.check()
        return offset

    def flush(self):
        self.held.check()
        os.fsync(self.held.fd)



def _external_export_target(destination, reserve):
    if (not isinstance(destination, (str, Path)) or not Path(destination).is_absolute()
            or '..' in Path(destination).parts or str(destination).startswith(('\\\\', '//'))):
        raise SourceActivationStorageHeld('external export requires the exact local SaveAs destination')
    target = Path(os.path.abspath(destination))
    if (not target.name.lower().endswith('.zip') or target.name.endswith(('.', ' '))
            or any(char in target.name for char in ':<>"|?*\0')
            or re.match(r'(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)', target.name)
            or len(str(target)) > 4096):
        raise SourceActivationStorageHeld('external ZIP destination spelling is unsupported')
    file_api.plain_path(target.parent, directory=True)
    if os.path.lexists(target):
        raise SourceActivationStorageHeld('external export never overwrites an existing destination')
    available = shutil.disk_usage(target.parent).free
    if (type(available) is not int or reserve > DEFAULT_MAX_BYTES
            or available < MIN_FREE_BYTES + reserve):
        raise SourceActivationStorageHeld('explicit external allocation cap/free reserve is unavailable')
    return target


@contextlib.contextmanager
def _maintenance_directory_fences(directory):
    with contextlib.ExitStack() as stack:
        for path in (*reversed(directory.parents), directory):
            stack.enter_context(_OwnedDirectory(path, _stamp(path), delete_access=False))
        yield

def export_source_update_backup(source_root, state_root, activation_id, review_sha256,
                                *, accepted=False, cancelled=lambda: False, destination=None):
    if accepted is not True or type(accepted) is not bool:
        return {'status': 'declined'}
    state = Path(os.path.abspath(state_root))
    with file_api.ActivationLock(state / 'activation.lock'):
        state, scopes, scope_sha = _accepted_review(source_root, state, activation_id, review_sha256)
        if cancelled():
            return {'status': 'declined'}
        payload = sum(row['stamp'][2] for scope in scopes.values() for row in scope['files'].values())
        members = sum(len(scope['files']) for scope in scopes.values())
        # Deflate overhead + exact member/manifest allowance belongs to the SAME
        # managed quota. Export never silently adds another multi-GiB budget.
        reserve = payload + payload // 1000 + members * 1024 + MAX_METADATA
        identifier = secrets.token_hex(16)
        external = destination is not None
        if external:
            target = _external_export_target(destination, reserve)
            root = Path(os.path.abspath(source_root))
            if target == state or state in target.parents or target == root or root in target.parents:
                raise SourceActivationStorageHeld('external export must stay outside managed state and installed source')
            exports = target.parent / ('.angerona-export-' + identifier)
            if os.path.lexists(exports):
                raise SourceActivationStorageHeld('external private staging destination already exists')
            from angerona.core.startup_recovery import private_directory
            if not private_directory(exports, create=True):
                raise SourceActivationStorageHeld('fresh external staging directory was not privately created')
            exports = _private_directory(exports)
            path = exports / 'payload.zip'
        else:
            require_source_update_storage(source_root, state, additional_bytes=reserve, cancelled=cancelled)
            exports = _private_directory(state / 'exports')
            path = exports / ('export-' + identifier + '.zip')
            target = path
        count = total = 0
        manifest = {}
        file_api.write_new(path, b'')
        # Creation, encode, verification, fsync and digest retain ONE exact
        # native file object. No named ZIP reopen can redirect a verified export.
        with _maintenance_directory_fences(exports), file_api.RetainedFile(path, writable=True, mutation=external) as output:
            stream = _RetainedZipIO(output)
            with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6,
                                 allowZip64=False) as archive:
                for label, scope in scopes.items():
                    with _held_chain(scope['path']):
                        for name, row in sorted(scope['files'].items()):
                            if cancelled():
                                raise SourceActivationStorageHeld('backup export cancelled; partial private ZIP preserved')
                            if not _safe_relative(name):
                                raise SourceActivationStorageHeld('export member path is unsafe')
                            with file_api.RetainedFile(scope['path'] / name) as held:
                                if _stamp(scope['path'] / name) != tuple(row['stamp']):
                                    raise SourceActivationStorageHeld('export native source identity changed')
                                raw = held.read(64 * 1024**2)
                            digest = hashlib.sha256(raw).hexdigest()
                            if row['sha256'] is not None and digest != row['sha256']:
                                raise SourceActivationStorageHeld('export source bytes are not the approved backup')
                            member = label + '/' + name
                            archive.writestr(member, raw)
                            manifest[member] = {'sha256': digest, 'bytes': len(raw)}
                            count += 1
                            total += len(raw)
                            if total > DEFAULT_MAX_BYTES:
                                raise SourceActivationStorageHeld('backup export exceeds its bounded byte allowance')
                manifest_bytes = _encoded({'source_scope_sha256': scope_sha, 'files': manifest})
                if len(manifest_bytes) > MAX_METADATA:
                    raise SourceActivationStorageHeld('export manifest exceeds its bounded allowance')
                archive.writestr('verified-manifest.json', manifest_bytes)
            stream.flush()
            stream.seek(0)
            with zipfile.ZipFile(stream, 'r') as archive:
                if set(archive.namelist()) != set(manifest) | {'verified-manifest.json'} or len(archive.namelist()) != len(manifest) + 1:
                    raise SourceActivationStorageHeld('private export membership is not exact')
                for member, row in manifest.items():
                    if cancelled():
                        raise SourceActivationStorageHeld('backup verification cancelled; private ZIP preserved')
                    raw = archive.read(member)
                    if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                        raise SourceActivationStorageHeld('private export member verification failed')
                if _read_zip_manifest(archive) != {'source_scope_sha256': scope_sha, 'files': manifest}:
                    raise SourceActivationStorageHeld('private export manifest changed')
            zip_digest, zip_bytes = output.digest(DEFAULT_MAX_BYTES)
            if external:
                if cancelled():
                    raise SourceActivationStorageHeld('external export cancelled before no-overwrite publication')
                output.rename(target)
                from angerona.core.startup_recovery import private_repair_file
                if not private_repair_file(target):
                    raise SourceActivationStorageHeld('published export private custody is unavailable')
        if external:
            with _OwnedDirectory(exports, _stamp(exports)) as empty:
                empty.delete_empty()
        result = {'schema': 'angerona.source-activation-export/v1', 'status': 'exported',
            'activation_id': activation_id, 'export_id': identifier, 'zip_sha256': zip_digest,
            'zip_bytes': zip_bytes, 'files': count, 'source_scope_sha256': scope_sha, 'path': str(target),
            'location': 'external' if external else 'managed', 'allocation_limit_bytes': DEFAULT_MAX_BYTES}
        if not external:
            _write_record(exports / ('export-' + identifier + '.json'), result)
        return result


def _read_zip_manifest(archive):
    raw = archive.read('verified-manifest.json')
    if len(raw) > MAX_METADATA:
        raise SourceActivationStorageHeld('export manifest exceeds its bound')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
    if type(value) is not dict:
        raise SourceActivationStorageHeld('export manifest is invalid')
    return value


class _OwnedDirectory:
    """Delete only this retained, verified empty directory object on Windows."""
    def __init__(self, path, stamp, *, delete_access=True):
        if os.name != 'nt':
            raise SourceActivationStorageHeld('native directory cleanup is unavailable on this platform')
        from tools import windows_publication_runtime as runtime
        self.runtime, self.path, self.handle = runtime, Path(path), None
        file_api.plain_path(self.path, directory=True)
        if _stamp(self.path) != tuple(stamp):
            raise SourceActivationStorageHeld('backup directory native identity changed')
        self.named_id = tuple(stamp)[:2]
        self.handle = runtime._open_handle(self.path, directory=True, delete_access=delete_access,
                                           share_write=not delete_access, share_delete=False)
        try:
            self.native = runtime._handle_identity(self.handle)
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        if self.handle is None:
            raise SourceActivationStorageHeld('backup directory custody is unavailable')
        current = self.runtime._handle_identity(self.handle)
        if (_stamp(self.path)[:2] != self.named_id or (current.volume, current.index)
                != (self.native.volume, self.native.index)
                or not current.attributes & 0x10 or current.attributes & 0x400):
            raise SourceActivationStorageHeld('backup directory object changed')

    def delete_empty(self):
        self.check()
        # The kernel's no-recursion empty-directory condition is authoritative;
        # a raced or unknown new child makes this native operation refuse.
        from ctypes import wintypes as w
        class Disposition(ctypes.Structure):
            _fields_ = [('flags', w.DWORD)]
        api = self.runtime._kernel32()
        api.SetFileInformationByHandle.argtypes = (w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD)
        api.SetFileInformationByHandle.restype = w.BOOL
        value = Disposition(0x11)
        if not api.SetFileInformationByHandle(w.HANDLE(self.handle), 21, ctypes.byref(value), ctypes.sizeof(value)):
            raise SourceActivationStorageHeld('known directory cleanup refused; remaining objects preserved')

    def close(self):
        raw, self.handle = self.handle, None
        if raw is not None:
            from ctypes import wintypes as w
            api = self.runtime._kernel32()
            api.CloseHandle.argtypes, api.CloseHandle.restype = (w.HANDLE,), w.BOOL
            try:
                if not api.CloseHandle(w.HANDLE(raw)):
                    raise SourceActivationStorageHeld('backup directory handle retirement remains held')
            except BaseException:
                file_api._CLOSE_HOLDS.append(('owned-cleanup-directory', self, raw))
                raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def delete_source_update_backup(source_root, state_root, activation_id, review_sha256,
                                *, accepted=False, permanent=False, cancelled=lambda: False):
    if accepted is not True or type(accepted) is not bool or permanent is not True or type(permanent) is not bool:
        return {'schema': 'angerona.source-activation-delete/v1', 'status': 'declined',
                'activation_id': activation_id, 'deleted_files': 0, 'deleted_bytes': 0,
                'receipt_id': '', 'reason': 'No exact permanent-deletion confirmation was accepted'}
    state = Path(os.path.abspath(state_root))
    count = total = 0
    receipt_id = secrets.token_hex(16)
    receipt = None
    with file_api.ActivationLock(state / 'activation.lock'):
        state, scopes, scope_sha = _accepted_review(source_root, state, activation_id, review_sha256)
        retention = _private_directory(state / 'retention')
        receipt = retention / ('delete-' + receipt_id + '.json')
        descriptor = {label: {'path': str(row['path']), 'files': row['files'], 'directories': row['directories']}
                      for label, row in scopes.items()}
        _write_record(receipt, {'schema': 'angerona.source-activation-delete-consent/v1',
            'activation_id': activation_id, 'review_sha256': review_sha256, 'source_scope_sha256': scope_sha,
            'accepted': True, 'permanent': True, 'export_recommended_not_required': True, 'scopes': descriptor})
        files, directories = {}, {}
        stack = contextlib.ExitStack()
        try:
            # All named objects are validated and retained before the first
            # irreversible operation. User-added or changed objects are held.
            for label, scope in scopes.items():
                stack.enter_context(_maintenance_directory_fences(scope['path'].parent))
                for name, stamp in sorted(scope['directories'].items(), key=lambda item: len(item[0].split('/'))):
                    path = scope['path'] if name == '.' else scope['path'] / name
                    directories[(label, name)] = stack.enter_context(_OwnedDirectory(path, stamp))
                for name, row in scope['files'].items():
                    path = scope['path'] / name
                    owned = stack.enter_context(file_api.RetainedFile(path, mutation=True))
                    if _stamp(path) != tuple(row['stamp']):
                        raise SourceActivationStorageHeld('backup file native generation changed')
                    digest, size = owned.digest(64 * 1024**2)
                    if row['sha256'] is not None and digest != row['sha256']:
                        raise SourceActivationStorageHeld('backup file content changed')
                    files[(label, name)] = (owned, size)
            for label, scope in scopes.items():
                actual_files = set()
                # Directory handles prevent namespace redirection. The exact
                # set check catches newly added children before any deletion.
                for (current_label, name), owned in directories.items():
                    if current_label != label:
                        continue
                    owned.check()
                    for entry in os.scandir(owned.path):
                        relative = (owned.path / entry.name).relative_to(scope['path']).as_posix()
                        if not entry.is_dir(follow_symlinks=False):
                            actual_files.add(relative)
                if actual_files != set(scope['files']):
                    raise SourceActivationStorageHeld('unknown object added after backup review')
            # Keep compact original plan/transaction/terminal metadata. It is
            # audit/lineage, not a completed payload backup after retirement.
            for (label, name), (owned, size) in files.items():
                if cancelled():
                    raise SourceActivationStorageHeld('approved cleanup was cancelled; remaining data preserved')
                if label == 'activation' and '/' not in name:
                    continue
                owned.delete()
                owned.close()
                count += 1
                total += size
            # The associated stage is unreferenced by any other update. Native
            # empty-only deletion never recursively removes unknown children.
            for (label, name), owned in sorted(directories.items(),
                    key=lambda item: 0 if item[0][1] == '.' else len(item[0][1].split('/')), reverse=True):
                if cancelled():
                    raise SourceActivationStorageHeld('approved cleanup was cancelled; remaining data preserved')
                if label == 'activation' and name == '.':
                    continue
                owned.delete_empty()
                owned.close()
            operation = state / 'activations' / ('apply-' + activation_id)
            expected_top = {name for name in scopes['activation']['files'] if '/' not in name}
            if {item.name for item in operation.iterdir()} != expected_top:
                raise SourceActivationStorageHeld('unknown object appeared during cleanup; it was preserved')
            stack.close()
            _write_record(operation / 'backup-retired.json', {
                'schema': 'angerona.source-activation-backup-retired/v1', 'activation_id': activation_id,
                'source_scope_sha256': scope_sha, 'consent_receipt': receipt_id,
                'deleted_files': count, 'deleted_bytes': total, 'compact_metadata_preserved': True})
            result = {'schema': 'angerona.source-activation-delete/v1', 'status': 'deleted',
                'activation_id': activation_id, 'deleted_files': count, 'deleted_bytes': total,
                'receipt_id': receipt_id, 'reason': 'Exact old backup payload and unreferenced stage deleted; current source and lineage preserved'}
            _write_record(retention / ('outcome-' + receipt_id + '.json'), result)
            return result
        except Exception as error:
            try:
                stack.close()
            except Exception:
                pass  # Sticky owners retain failed-close custody; no retry.
            result = {'schema': 'angerona.source-activation-delete/v1', 'status': 'held-partial',
                'activation_id': activation_id, 'deleted_files': count, 'deleted_bytes': total,
                'receipt_id': receipt_id, 'reason': type(error).__name__ + ': remaining and unknown objects preserved'}
            try:
                _write_record(retention / ('outcome-' + receipt_id + '.json'), result)
            except Exception:
                pass  # The original durable consent/scope remains authoritative evidence.
            return result
        finally:
            stack.close()


def set_source_update_storage_policy(source_root, state_root, review_sha256, *, accepted=False,
                                     completed_backups=DEFAULT_COMPLETED_BACKUPS,
                                     max_bytes=DEFAULT_MAX_BYTES, cancelled=lambda: False):
    if accepted is not True or type(accepted) is not bool:
        return {'status': 'declined', 'budget': None}
    if (type(completed_backups) is not int or not 1 <= completed_backups <= 8
            or type(max_bytes) is not int or not 64 * 1024**2 <= max_bytes <= 4 * 1024**3):
        raise SourceActivationStorageHeld('requested storage policy is outside its bounded choices')
    state = Path(os.path.abspath(state_root))
    with file_api.ActivationLock(state / 'activation.lock'):
        review = review_source_update_storage(source_root, state, cancelled=cancelled)
        if cancelled():
            return {'status': 'declined', 'budget': None}
        if review['review_sha256'] != review_sha256 or review['policy_status'] != 'ready':
            raise SourceActivationStorageHeld('storage review changed or prior policy transaction remains held', review)
        policy = {'schema': 'angerona.source-activation-storage-policy/v1', 'accepted': True,
                  'completed_backups': completed_backups, 'max_bytes': max_bytes}
        identifier = secrets.token_hex(16)
        retention = _private_directory(state / 'retention')
        staged = retention / ('policy-' + identifier + '.json')
        if cancelled():
            return {'status': 'declined', 'budget': None}
        _write_record(staged, policy)
        if cancelled():
            return {'status': 'declined', 'budget': None}
        # Once this durable marker exists, finish or retain an explicit policy
        # hold; view cancellation cannot turn a partial policy into a default.
        pending = state / 'activation-storage-policy-pending.json'
        _write_record(pending, {'schema': 'angerona.source-activation-policy-pending/v1',
            'policy_sha256': hashlib.sha256(_encoded(policy)).hexdigest(), 'policy_id': identifier,
            'old_budget': review['budget'], 'accepted': True})
        with file_api.RetainedFile(staged, mutation=True) as fresh:
            target = state / 'activation-storage-policy.json'
            if os.path.lexists(target):
                with file_api.RetainedFile(target, mutation=True) as old:
                    if _read_policy_from_held(old) != {'schema': 'angerona.source-activation-storage-policy/v1',
                            'accepted': True, **review['budget']}:
                        raise SourceActivationStorageHeld('storage policy changed during approval')
                    old.rename(retention / ('policy-old-' + identifier + '.json'))
            fresh.rename(target)
        with file_api.RetainedFile(pending, mutation=True) as marker:
            marker.rename(retention / ('policy-completed-' + identifier + '.json'))
        return {'status': 'changed', 'budget': {'completed_backups': completed_backups, 'max_bytes': max_bytes}}


def _read_policy_from_held(held):
    return json.loads(held.read(MAX_METADATA).decode('utf-8'), object_pairs_hook=_pairs)
