"""Explicit, bounded removal of Shadow Shield's disposable recovery copies.

The caller must quiesce its own cache writer, or independently establish that
the application has stopped. This helper grants no process-control authority.
It never reads source paths, follows links, or recursively deletes a pathname.
"""
from __future__ import annotations

import contextlib
import os
import re
import stat
import time
from pathlib import Path

from angerona.core.alert_retention import _Directory, _identity, _plain


MAX_ENTRIES = 100_000
MAX_SECONDS = 20.0
_KEY = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[0-9]{1,20}\.bak\Z")
_TEMPORARY = re.compile(r"\.[0-9]{1,20}\.[0-9a-f]{32}\.tmp\Z")


def _protected_directory(info):
    _plain(info, directory=True)
    if os.name != "nt" and (
        info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ValueError("cache directory must be owned by this account and not publicly writable")


class _CacheDirectory(_Directory):
    def __init__(self, path, descriptor, handle=None):
        super().__init__(path, descriptor)
        self.handle = handle
        self._guard_active = False
        self.identity = self.object_identity()

    def object_identity(self):
        info = (self.path.lstat() if self.descriptor is None else os.fstat(self.descriptor))
        _protected_directory(info)
        return info.st_dev, info.st_ino

    def remove_empty(self, parent, name, budget):
        info = parent.stat(name)
        _protected_directory(info)
        if (info.st_dev, info.st_ino) != self.identity or self.object_identity() != self.identity:
            raise ValueError("cache directory identity changed before removal")
        with self.entries() as entries:
            if next(entries, None) is not None:
                raise ValueError("cache directory is no longer empty")
        budget.check()
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            class Disposition(ctypes.Structure):
                _fields_ = [("delete", ctypes.c_ubyte)]

            setter = ctypes.WinDLL("kernel32", use_last_error=True).SetFileInformationByHandle
            setter.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
            setter.restype = wintypes.BOOL
            value = Disposition(1)
            # Native directory disposition itself refuses a concurrent new child.
            if not setter(self.handle, 4, ctypes.byref(value), ctypes.sizeof(value)):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.rmdir(name, dir_fd=parent.descriptor)


@contextlib.contextmanager
def _held_directory(path, parent=None):
    """Pin Windows ancestry; use anchored, no-follow POSIX directory handles."""
    path = Path(path)
    if parent is not None and (
        not isinstance(parent, _CacheDirectory) or not parent._guard_active
        or path.parent != parent.path
        or (parent.handle is None if os.name == "nt" else parent.descriptor is None)
    ):
        raise ValueError("cache child requires its matching active directory guard")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        from angerona.core.source_sandbox import _hold_plain_directories

        # Hold ancestors separately: a guard denying delete sharing on the final
        # directory would prevent our own exact-handle empty-directory removal.
        # A live matching parent already retains this complete ancestor chain.
        # Reopening it for every key adds redundant native I/O; the child's own
        # exclusive-write/delete guard and identity checks remain independent.
        ancestry = (contextlib.nullcontext() if parent is not None
                    else _hold_plain_directories(path.parent))
        with ancestry:
            before = path.lstat()
            _protected_directory(before)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            opener = kernel.CreateFileW
            opener.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                               wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
            opener.restype = wintypes.HANDLE
            closer = kernel.CloseHandle
            closer.argtypes = (wintypes.HANDLE,)
            closer.restype = wintypes.BOOL
            access = 0x80 | 1 | (0x10000 if parent is not None else 0)
            # Deny writable directory handles as well as renames: a compatible
            # writer could otherwise turn an emptied directory into a reparse
            # point while path-based child enumeration is still in progress.
            handle = opener(str(path), access, 1, None, 3,
                            0x02000000 | 0x00200000, None)
            if handle == wintypes.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            directory = None
            try:
                directory = _CacheDirectory(path, None, handle)
                if directory.identity != (before.st_dev, before.st_ino):
                    raise ValueError("cache directory changed while opening")
                directory._guard_active = True
                yield directory
            finally:
                if directory is not None:
                    directory._guard_active = False
                closer(handle)
        return
    descriptors = []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        if parent is not None:
            descriptor = os.open(path.name, flags, dir_fd=parent.descriptor)
            descriptors.append(descriptor)
        else:
            descriptor = os.open(path.anchor, flags)
            descriptors.append(descriptor)
            for component in path.parts[1:]:
                descriptor = os.open(component, flags, dir_fd=descriptor)
                descriptors.append(descriptor)
        _protected_directory(os.fstat(descriptor))
        directory = _CacheDirectory(path, descriptor)
        directory._guard_active = True
        try:
            yield directory
        finally:
            directory._guard_active = False
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


class _LimitReached(Exception):
    pass


class _Budget:
    def __init__(self, stopped):
        self.stopped = stopped
        self.deadline = time.monotonic() + MAX_SECONDS
        self.entries = 0

    def check(self):
        if self.stopped is not None and self.stopped.is_set():
            raise _LimitReached("cleanup cancelled; remaining copies preserved")
        if time.monotonic() >= self.deadline:
            raise _LimitReached("cleanup time bound reached; remaining copies preserved; run cleanup again")

    def inspect(self):
        self.check()
        if self.entries >= MAX_ENTRIES:
            raise _LimitReached("cleanup entry bound reached; remaining copies preserved; run cleanup again")
        self.entries += 1


def _remove(directory, name, expected, budget, result):
    budget.check()
    # _File opens the exact no-follow, single-link regular file. Windows denies
    # other writers/deleters until handle-based disposition completes; POSIX
    # uses flock plus unlink relative to the held protected directory.
    with directory.open(name) as held:
        if _identity(held.info()) != expected:
            raise ValueError("cache file changed after inspection")
        budget.check()
        held.delete(expected)
    result["removed_files"] += 1
    result["removed_bytes"] += expected[2]


def _clean_key(parent, name, before, budget, result):
    with _held_directory(parent.path / name, parent) as directory:
        current = parent.stat(name)
        _protected_directory(current)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("cache key directory changed after inspection")
        candidates = []
        metadata = None
        with directory.entries() as entries:
            for entry in entries:
                budget.inspect()
                if entry.name != "_source.txt" and not (
                    _VERSION.fullmatch(entry.name) or _TEMPORARY.fullmatch(entry.name)
                ):
                    raise ValueError("unrecognized cache entry preserved")
                info = directory.stat(entry.name)
                _plain(info)
                if directory.exists(entry.name + ".keep"):
                    raise ValueError("pinned cache entry preserved")
                item = (entry.name, _identity(info))
                if entry.name == "_source.txt":
                    metadata = item
                else:
                    candidates.append(item)
        # Preserve metadata until every inspected recovery copy is removed.
        for filename, identity in candidates:
            _remove(directory, filename, identity, budget, result)
        if metadata is not None:
            # An unexpected late entry must not lose its source mapping. The
            # caller owns writer quiescence; external mutations remain explicit.
            with directory.entries() as entries:
                for entry in entries:
                    budget.inspect()
                    if entry.name != "_source.txt":
                        raise ValueError("cache directory changed during cleanup; metadata preserved")
            _remove(directory, *metadata, budget, result)
        budget.check()
        directory.remove_empty(parent, name, budget)
    result["removed_directories"] += 1


def cleanup_cache(cache_dir, *, stopped=None) -> dict:
    """Remove only recognized cache artifacts; report incomplete work explicitly.

    Cancellation and cooperative work limits are checked before each deletion.
    Blocking filesystem calls cannot be preempted by the time budget. Only
    verified empty key directories are retired; unknown/unsafe data is preserved.
    """
    result = dict(complete=False, removed_files=0, removed_bytes=0,
                  removed_directories=0, reason="cleanup not completed")
    budget = _Budget(stopped)
    try:
        budget.check()
        supplied = Path(cache_dir)
        if not supplied.is_absolute() or ".." in supplied.parts:
            raise ValueError("cleanup requires an absolute lexical cache directory")
        path = Path(os.path.abspath(supplied))
        if path.name != "shadow_cache" or str(path).startswith(("\\\\", "//")):
            raise ValueError("cleanup requires a local shadow_cache directory")
        # Validate absence through a held, plain parent as well; a redirected
        # ancestor must not turn unavailable inspection into apparent success.
        with _held_directory(path.parent) as parent:
            if not parent.exists(path.name):
                result.update(complete=True, reason="cache directory absent")
                return result
        incomplete = False
        with _held_directory(path) as root:
            with root.entries() as entries:
                for entry in entries:
                    budget.inspect()
                    try:
                        if not _KEY.fullmatch(entry.name):
                            raise ValueError("unrecognized cache root entry preserved")
                        info = root.stat(entry.name)
                        _protected_directory(info)
                        _clean_key(root, entry.name, info, budget, result)
                    except (OSError, ValueError):
                        incomplete = True
        result.update(
            complete=not incomplete,
            reason=("unknown, pinned, unavailable or changed cache entries preserved"
                    if incomplete else "recognized recovery copies and empty key directories removed"),
        )
    except _LimitReached as exc:
        result["reason"] = str(exc)
    except (OSError, ValueError, TypeError):
        result["reason"] = "unsafe or unavailable cache directory; remaining entries preserved"
    return result
