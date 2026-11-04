"""Fixed original-source activation entry; never imports the mutable source tree.

The canonical native-bound PS controller invokes its pre-stop immutable copy.
A hash-pinned parent assertion is not independent proof of the parent's leases.
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

MAX = 16 * 1024**2
HEX32 = re.compile(r'[0-9a-f]{32}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_DECIMAL = re.compile(r'[0-9]{1,40}\Z')
FILES = (
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


class BrokerBootstrapError(RuntimeError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BrokerBootstrapError('Duplicate broker metadata field')
        result[key] = value
    return result


def _json(raw):
    value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if type(value) is not dict:
        raise BrokerBootstrapError('Broker metadata must be an object')
    return value


def _plain(path):
    path = Path(os.path.abspath(path))
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise BrokerBootstrapError('Broker path is redirected')
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise BrokerBootstrapError('Broker ancestor is not a directory')
    return path


def _read(path, maximum=MAX):
    path = _plain(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise BrokerBootstrapError('Broker input is not bounded single-link regular data')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    try:
        opened = os.fstat(fd)
        stamp = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns)
        if stamp(opened) != stamp(before) or opened.st_nlink != 1:
            raise BrokerBootstrapError('Broker input changed while opening')
        parts, count = [], 0
        while True:
            raw = os.read(fd, min(65536, maximum + 1 - count))
            if not raw:
                break
            count += len(raw)
            if count > maximum:
                raise BrokerBootstrapError('Broker input grew beyond its bound')
            parts.append(raw)
        if count != before.st_size or stamp(os.fstat(fd)) != stamp(before) or stamp(path.lstat()) != stamp(before):
            raise BrokerBootstrapError('Broker input changed during capture')
        return b''.join(parts)
    finally:
        os.close(fd)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


class _NativeProcess:
    """One query/synchronize handle; no process actions or numeric close retries."""
    _close_holds = []

    def __init__(self, pid, birth, image):
        if self._close_holds:
            raise BrokerBootstrapError('Prior source-controller native retirement remains held')
        import ctypes
        from ctypes import wintypes as w
        if (os.name != 'nt' or type(pid) is not int or not 0 < pid <= 0xffffffff
                or type(birth) is not str or not _DECIMAL.fullmatch(birth)
                or type(image) is not str or not Path(image).is_absolute()):
            raise BrokerBootstrapError('Exact native source-controller identity is unavailable')
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
            raise BrokerBootstrapError('Source controller native query handle is unavailable')
        try:
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        import ctypes
        from ctypes import wintypes as w
        if self.close_held or not self.handle or self.api.WaitForSingleObject(self.handle, 0) != 258:
            raise BrokerBootstrapError('Source controller generation is not live')
        fields = [w.FILETIME() for _ in range(4)]
        if not self.api.GetProcessTimes(self.handle, *(ctypes.byref(x) for x in fields)):
            raise BrokerBootstrapError('Source controller raw birth is unavailable')
        birth = str((fields[0].dwHighDateTime << 32) | fields[0].dwLowDateTime)
        length, buffer = w.DWORD(32768), ctypes.create_unicode_buffer(32768)
        if not self.api.QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(length)):
            raise BrokerBootstrapError('Source controller native image is unavailable')
        if (birth != self.birth or os.path.normcase(os.path.normpath(buffer.value))
                != os.path.normcase(os.path.normpath(self.image))
                or self.api.WaitForSingleObject(self.handle, 0) != 258):
            raise BrokerBootstrapError('Source controller native generation changed')

    def close(self):
        if self.close_held:
            raise BrokerBootstrapError('Source controller native handle retirement is held')
        handle, self.handle = self.handle, None
        if handle:
            try:
                if not self.api.CloseHandle(handle):
                    raise BrokerBootstrapError('Source controller native handle close failed')
            except BaseException:
                self.close_held = True
                self._close_holds.append((self, handle))
                raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()



def _load_module(name, filename, raw):
    # Only exact hash-verified ORIGINAL capsule bytes enter compile/exec.
    module = types.ModuleType(name)
    module.__file__ = str(filename)
    module.__package__ = name if filename.name == '__init__.py' else name.rpartition('.')[0]
    if filename.name == '__init__.py':
        module.__path__ = []
    sys.modules[name] = module
    exec(compile(raw, str(filename), 'exec', dont_inherit=True), module.__dict__)
    return module


def run(options):
    if not HEX32.fullmatch(options.activation_id) or not all(HEX64.fullmatch(value) for value in (
            options.plan_sha256, options.request_sha256, options.guard_sha256)):
        raise BrokerBootstrapError('Broker input identity is invalid')
    root, state = _plain(options.root), _plain(options.state_root)
    operation = _plain(state / 'activations' / ('apply-' + options.activation_id))
    capsule = _plain(operation / 'broker')
    if Path(__file__).absolute() != capsule / 'tools' / 'activate_source_update.py':
        raise BrokerBootstrapError('Only the retained pre-stop broker snapshot can activate source')
    guard_path = _plain(options.guard_file)
    if guard_path.parent != operation:
        raise BrokerBootstrapError('Broker guard is outside its exact operation')
    guard_raw = _read(guard_path)
    if _sha(guard_raw) != options.guard_sha256:
        raise BrokerBootstrapError('Broker guard pin changed')
    guard = _json(guard_raw)
    if (guard.get('parent_pid') != os.getppid() or guard.get('operation') != ('reconcile' if options.reconcile else 'activate')
            or guard.get('activation_id') != options.activation_id or guard.get('plan_sha256') != options.plan_sha256
            or guard.get('request_sha256') != options.request_sha256 or guard.get('source_root') != str(root)
            or guard.get('state_root') != str(state) or guard.get('root_identity') != {
                'device': str(root.stat().st_dev), 'inode': str(root.stat().st_ino)}):
        raise BrokerBootstrapError('Broker guard identity is not exact')
    image = 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
    if os.path.normcase(os.path.normpath(guard.get('parent_image', ''))) != os.path.normcase(os.path.normpath(image)):
        raise BrokerBootstrapError('Broker parent is not the fixed system host')
    with _NativeProcess(guard['parent_pid'], guard['parent_birth'], guard['parent_image']):
        plan_raw = _read(operation / 'plan.json')
        if _sha(plan_raw) != options.plan_sha256:
            raise BrokerBootstrapError('Broker approved plan changed')
        plan = _json(plan_raw)
        snapshot_raw = _read(capsule / 'snapshot.json')
        if _sha(snapshot_raw) != guard.get('snapshot_sha256'):
            raise BrokerBootstrapError('Original broker snapshot pin changed')
        snapshot = _json(snapshot_raw)
        if (snapshot != plan.get('broker_snapshot') or set(snapshot) != {'schema', 'files'}
                or snapshot['schema'] != 'angerona.source-activation-broker-snapshot/v1'
                or type(snapshot['files']) is not dict or set(snapshot['files']) != set(FILES)):
            raise BrokerBootstrapError('Original broker capsule allowlist changed')
        sources, total = {}, 0
        for name in FILES:
            row = snapshot['files'][name]
            raw = _read(capsule / name, 4 * 1024**2)
            total += len(raw)
            if (type(row) is not dict or set(row) != {'sha256', 'bytes'}
                    or type(row['bytes']) is not int or type(row['sha256']) is not str
                    or not HEX64.fullmatch(row['sha256']) or len(raw) != row['bytes']
                    or _sha(raw) != row['sha256'] or total > 4 * 1024**2):
                raise BrokerBootstrapError('Original broker dependency pin changed')
            sources[name] = raw
        # Empty package namespaces prohibit loading any mixed-root/candidate
        # package initializer or unlisted sibling through Python's import path.
        for name in ('angerona', 'angerona.core', 'angerona.updater', 'angerona.resilience', 'angerona.core._source_tomli', 'tools'):
            package = types.ModuleType(name)
            package.__path__ = []
            sys.modules[name] = package
        modules = (
            ('angerona.core._source_tomli._types', 'src/angerona/core/_source_tomli/_types.py'),
            ('angerona.core._source_tomli._re', 'src/angerona/core/_source_tomli/_re.py'),
            ('angerona.core._source_tomli._parser', 'src/angerona/core/_source_tomli/_parser.py'),
            ('angerona.core._source_tomli', 'src/angerona/core/_source_tomli/__init__.py'),
            ('angerona.core.source_activation_file', 'src/angerona/core/source_activation_file.py'),
            ('angerona.core.startup_recovery', 'src/angerona/core/startup_recovery.py'),
            ('tools.windows_publication_runtime', 'tools/windows_publication_runtime.py'),
            ('tools.publication_transport', 'tools/publication_transport.py'),
            ('angerona.updater.source_git', 'src/angerona/updater/source_git.py'),
            ('angerona.core.source_activation_workspace', 'src/angerona/core/source_activation_workspace.py'),
            ('angerona.core.source_activation_storage', 'src/angerona/core/source_activation_storage.py'),
            ('angerona.resilience.heartbeat', 'src/angerona/resilience/heartbeat.py'),
            ('angerona.core.source_activation_broker', 'src/angerona/core/source_activation_broker.py'),
        )
        loaded = {}
        for name, path in modules:
            loaded[name] = _load_module(name, capsule / path, sources[path])
        file_api = loaded['angerona.core.source_activation_file']
        with contextlib.ExitStack() as retained:
            for name in FILES:
                item = retained.enter_context(file_api.RetainedFile(capsule / name))
                if item.read(4 * 1024**2) != sources[name]:
                    raise BrokerBootstrapError('Original broker snapshot changed before execution')
            result = loaded['angerona.core.source_activation_broker'].run_source_activation(
                root, state, options.activation_id, options.plan_sha256, options.request_sha256,
                guard_path, options.guard_sha256, reconcile=options.reconcile)
            pending_present = os.path.lexists(state / 'activation-pending.json')
            if result.get('status') in {'committed', 'rolled_back'} and pending_present:
                raise BrokerBootstrapError('A source transaction terminal result still has its startup barrier')
            outcome = {'schema': 'angerona.source-activation-outcome/v1', 'status': result['status'],
                'activation_id': options.activation_id, 'plan_sha256': options.plan_sha256,
                'request_sha256': options.request_sha256, 'guard_sha256': options.guard_sha256,
                'snapshot_sha256': guard['snapshot_sha256'], 'source_root': str(root), 'state_root': str(state),
                'root_identity': guard['root_identity'], 'pending_present': pending_present, 'result': result}
            raw = json.dumps(outcome, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
            file_api.write_new(operation / ('result-' + guard['guard_nonce'] + '.json'), raw)
            return {'schema': 'angerona.source-activation-output/v1', 'status': outcome['status'],
                    'activation_id': options.activation_id, 'receipt_sha256': _sha(raw)}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Apply only a bound approved source update from its original broker snapshot')
    for name in ('root', 'state-root', 'activation-id', 'plan-sha256', 'request-sha256', 'guard-file', 'guard-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--reconcile', action='store_true')
    options = parser.parse_args(argv)
    try:
        result = run(options)
    except Exception as error:
        print(json.dumps({'status': 'held_unknown', 'failure_type': type(error).__name__,
                          'reason': 'Source activation did not establish a terminal verified outcome'}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('status') in {'committed', 'rolled_back'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
