"""Isolated working copies for operator-facing source-code exploration.

The menu Info tabs expose the implementation files behind a feature. Those
files must never be edited merely because an operator wants to experiment, so
this module copies an allow-listed set into Angerona's runtime data directory.
Only the copies are writable. Reset means "restore the copies from installed
source"; it never rewrites the installed application.

Every filesystem boundary is checked immediately before and after use.
Windows junctions and other reparse points are treated like symlinks and
rejected so a privileged process cannot be redirected out of its sandbox.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import os
import re
import secrets
import stat
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from angerona.core.atomic_io import replace_with_retry
from angerona.core.data_paths import data_dir, project_root, resource_root


_SAFE_KEY = re.compile(r"[^a-z0-9_-]+")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _slug(value: object) -> str:
    text = _SAFE_KEY.sub("-", str(value or "").strip().casefold()).strip("-")
    if not text:
        raise ValueError("sandbox key must contain a letter or number")
    return text[:80]


def _relative_source(value: object) -> str:
    """Normalize a catalog path without permitting traversal or absolutes."""
    raw = str(value or "").strip().replace("\\", "/")
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe sandbox source path: {value!r}")
    normalized = path.as_posix()
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _absolute(path: Path) -> Path:
    """Return an absolute *lexical* path without following links."""
    return Path(os.path.abspath(os.fspath(path)))


def _within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((os.fspath(path), os.fspath(root))) == os.fspath(root)
    except (OSError, ValueError):
        return False


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _chain(path: Path) -> tuple[Path, ...]:
    """Return path components from the filesystem anchor to ``path``."""
    absolute = _absolute(path)
    anchor = Path(absolute.anchor)
    relative = absolute.relative_to(anchor)
    current = anchor
    result: list[Path] = []
    for part in relative.parts:
        current = current / part
        result.append(current)
    return tuple(result)


def _validate_chain(path: Path, *, allow_missing_tail: bool = False) -> None:
    """Reject symlinks/reparse points and non-directory parent components."""
    components = _chain(path)
    for index, component in enumerate(components):
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            if allow_missing_tail:
                return
            raise ValueError(f"sandbox path component is missing: {component}") from None
        except OSError as exc:
            raise ValueError(f"cannot validate sandbox path component: {component}") from exc
        if _is_link_or_reparse(info):
            raise ValueError(f"sandbox path contains a symlink or reparse point: {component}")
        if index + 1 < len(components) and not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"sandbox parent component is not a directory: {component}")


def _ensure_directory(path: Path) -> None:
    """Create a directory one component at a time, rejecting redirection."""
    components = _chain(path)
    for component in components:
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            try:
                os.mkdir(component)
            except FileExistsError:
                pass
            info = os.lstat(component)
        if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"sandbox directory is not plain: {component}")
    _validate_chain(path)


def _validate_regular_file(path: Path) -> None:
    _validate_chain(path)
    info = os.lstat(path)
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"sandbox file is not a plain regular file: {path}")


@contextlib.contextmanager
def _hold_plain_directories(*paths: Path):
    """Keep validated Windows directory handles open for a bounded read.

    Mutating operations use the stronger delete-access handles in
    ``_windows_atomic_bytes_write``. This read guard still rejects every
    reparse component before opening a file and revalidates afterwards.
    """
    if os.name != "nt":
        for path in paths:
            _validate_chain(path)
        yield
        return

    import ctypes
    from ctypes import wintypes

    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = ctypes.windll.kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    invalid = wintypes.HANDLE(-1).value
    open_existing = 3
    read_attributes = 0x00000080
    share_read_write = 0x00000001 | 0x00000002
    backup_semantics = 0x02000000
    open_reparse = 0x00200000
    handles: list[int] = []
    components: list[Path] = []
    component_keys: set[str] = set()
    for path in paths:
        for component in _chain(path):
            key = os.path.normcase(os.fspath(component))
            if key in component_keys:
                continue
            component_keys.add(key)
            components.append(component)
    try:
        for component in components:
            # Components are ordered from the filesystem anchor downwards.
            # Every ancestor has therefore already been validated and is held
            # open without delete sharing.  Re-walking the full ancestor chain
            # for each child was quadratic in path depth and added several ms
            # to every sandbox read; a direct leaf check provides the same
            # pre-open reparse/directory gate while the pinned ancestors keep
            # the boundary stable.
            try:
                info = os.lstat(component)
            except OSError as exc:
                raise ValueError(
                    f"cannot validate sandbox path component: {component}"
                ) from exc
            if _is_link_or_reparse(info):
                raise ValueError(
                    f"sandbox path contains a symlink or reparse point: {component}"
                )
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError(
                    f"sandbox parent component is not a directory: {component}"
                )
            handle = create_file(
                os.fspath(component), read_attributes, share_read_write, None, open_existing,
                backup_semantics | open_reparse, None,
            )
            if handle == invalid:
                raise OSError(
                    ctypes.get_last_error(),
                    f"could not pin sandbox directory: {component}",
                )
            handles.append(handle)
            info = os.lstat(component)
            if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
                raise ValueError(f"sandbox directory is not plain: {component}")
        yield
    finally:
        for handle in reversed(handles):
            close_handle(handle)


def _read_bytes(path: Path, *, root: Path) -> bytes:
    path = _absolute(path)
    root = _absolute(root)
    if not _within(path, root):
        raise ValueError(f"sandbox read escaped its boundary: {path}")
    with _hold_plain_directories(root, path.parent):
        _validate_regular_file(path)
        flags = (
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"sandbox file is not regular: {path}")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                content = handle.read()
        finally:
            os.close(fd)
        _validate_regular_file(path)
    return content


def _atomic_bytes_write(path: Path, content: bytes, *, root: Path) -> None:
    """Durably replace one plain file underneath a validated sandbox root."""
    path = _absolute(path)
    root = _absolute(root)
    if not _within(path, root) or path == root:
        raise ValueError(f"sandbox write escaped its boundary: {path}")
    _ensure_directory(root)
    _ensure_directory(path.parent)
    if os.name == "nt":
        _windows_atomic_bytes_write(path, content, root=root)
        return
    with _hold_plain_directories(root, path.parent):
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        else:
            _validate_regular_file(path)

        fd, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=os.fspath(path.parent)
        )
        tmp = Path(temporary)
        try:
            _validate_regular_file(tmp)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            _validate_regular_file(tmp)
            try:
                os.lstat(path)
            except FileNotFoundError:
                pass
            else:
                _validate_regular_file(path)
            replace_with_retry(tmp, path)
            _validate_regular_file(path)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass


def _windows_atomic_bytes_write(path: Path, content: bytes, *, root: Path) -> None:
    """Write and rename through verified Windows handles.

    The temporary file's actual kernel path is checked against already-open
    root/parent handles before any bytes are written. Those handles request
    delete access without sharing delete, which makes Windows reject a parent
    rename while the final atomic rename is in flight.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    final_path = kernel32.GetFinalPathNameByHandleW
    final_path.argtypes = (
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
    )
    final_path.restype = wintypes.DWORD
    write_file = kernel32.WriteFile
    write_file.argtypes = (
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    )
    write_file.restype = wintypes.BOOL
    flush_file = kernel32.FlushFileBuffers
    flush_file.argtypes = (wintypes.HANDLE,)
    flush_file.restype = wintypes.BOOL
    set_info = kernel32.SetFileInformationByHandle
    set_info.argtypes = (
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
    )
    set_info.restype = wintypes.BOOL

    invalid = wintypes.HANDLE(-1).value
    read_attributes = 0x00000080
    generic_write = 0x40000000
    delete_access = 0x00010000
    share_read_write = 0x00000001 | 0x00000002
    share_read_write_delete = share_read_write | 0x00000004
    open_existing = 3
    create_new = 1
    backup_semantics = 0x02000000
    open_reparse = 0x00200000
    normal_attributes = 0x00000080

    def open_handle(target: Path, access: int, share: int, disposition: int, flags: int):
        handle = create_file(
            os.fspath(target), access, share, None, disposition, flags, None
        )
        if handle == invalid:
            error = ctypes.get_last_error()
            raise OSError(error, f"could not open sandbox boundary: {target}")
        return handle

    def actual_path(handle) -> Path:
        size = final_path(handle, None, 0, 0)
        if not size:
            raise OSError(ctypes.get_last_error(), "could not identify sandbox handle")
        buffer = ctypes.create_unicode_buffer(size + 1)
        if not final_path(handle, buffer, len(buffer), 0):
            raise OSError(ctypes.get_last_error(), "could not identify sandbox handle")
        value = buffer.value
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        return _absolute(Path(value))

    root_handle = parent_handle = temp_handle = None
    delete_temp = False
    try:
        root_handle = open_handle(
            root, read_attributes | delete_access, share_read_write, open_existing,
            backup_semantics | open_reparse,
        )
        if path.parent == root:
            parent_handle = root_handle
        else:
            parent_handle = open_handle(
                path.parent,
                read_attributes | delete_access,
                share_read_write,
                open_existing,
                backup_semantics | open_reparse,
            )
        actual_root = actual_path(root_handle)
        actual_parent = actual_path(parent_handle)
        if not _within(actual_parent, actual_root):
            raise ValueError("sandbox parent handle escaped its root")
        _validate_chain(root)
        _validate_chain(path.parent)
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        else:
            _validate_regular_file(path)

        for _ in range(16):
            temp_path = path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
            try:
                temp_handle = open_handle(
                    temp_path,
                    generic_write | delete_access,
                    share_read_write_delete,
                    create_new,
                    normal_attributes | open_reparse,
                )
                break
            except OSError as exc:
                if getattr(exc, "winerror", None) not in {80, 183} and exc.errno not in {80, 183}:
                    raise
        if temp_handle is None:
            raise OSError("could not allocate a unique sandbox temporary file")
        delete_temp = True
        actual_temp = actual_path(temp_handle)
        if os.path.normcase(os.fspath(actual_temp.parent)) != os.path.normcase(
            os.fspath(actual_parent)
        ):
            raise ValueError("sandbox temporary file was redirected outside its parent")

        offset = 0
        while offset < len(content):
            chunk = content[offset:offset + 1024 * 1024]
            buffer = ctypes.create_string_buffer(chunk)
            written = wintypes.DWORD()
            if not write_file(temp_handle, buffer, len(chunk), ctypes.byref(written), None):
                raise OSError(ctypes.get_last_error(), "sandbox write failed")
            if written.value <= 0:
                raise OSError("sandbox write made no progress")
            offset += written.value
        if not flush_file(temp_handle):
            raise OSError(ctypes.get_last_error(), "sandbox flush failed")

        filename = os.fspath(path)
        filename_type = wintypes.WCHAR * len(filename)

        class FileRenameInfo(ctypes.Structure):
            _fields_ = (
                ("ReplaceIfExists", ctypes.c_ubyte),
                ("RootDirectory", wintypes.HANDLE),
                ("FileNameLength", wintypes.DWORD),
                ("FileName", filename_type),
            )

        rename = FileRenameInfo()
        rename.ReplaceIfExists = True
        rename.RootDirectory = None
        rename.FileNameLength = len(filename.encode("utf-16-le"))
        rename.FileName = filename
        if not set_info(temp_handle, 3, ctypes.byref(rename), ctypes.sizeof(rename)):
            raise OSError(ctypes.get_last_error(), "secure sandbox replace failed")
        delete_temp = False
        expected = _absolute(actual_parent / path.name)
        if os.path.normcase(os.fspath(actual_path(temp_handle))) != os.path.normcase(
            os.fspath(expected)
        ):
            raise ValueError("sandbox replacement landed outside its verified parent")
    finally:
        if temp_handle is not None:
            if delete_temp:
                class FileDispositionInfo(ctypes.Structure):
                    _fields_ = (("DeleteFile", ctypes.c_ubyte),)

                disposition = FileDispositionInfo(True)
                set_info(temp_handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition))
            close_handle(temp_handle)
        if parent_handle is not None and parent_handle != root_handle:
            close_handle(parent_handle)
        if root_handle is not None:
            close_handle(root_handle)


def _atomic_text_write(path: Path, text: str, *, root: Path) -> None:
    _atomic_bytes_write(path, text.encode("utf-8"), root=root)


@dataclass(frozen=True)
class SandboxFile:
    """One immutable source and its operator-editable working copy."""

    relative_path: str
    source_path: Path
    working_path: Path


class SourceSandboxWorkspace:
    """Manage bounded working copies for one menu/topic."""

    def __init__(
        self,
        key: str,
        source_paths: Iterable[str],
        *,
        source_root: Path | None = None,
        sandbox_root: Path | None = None,
    ) -> None:
        self.key = _slug(key)
        preferred = _absolute(
            Path(source_root) if source_root is not None else resource_root()
        )
        roots: list[Path] = []
        candidates = (preferred, _absolute(project_root()), _absolute(resource_root()))
        for index, candidate in enumerate(candidates):
            if candidate in roots:
                continue
            try:
                _validate_chain(candidate)
                if not candidate.is_dir():
                    raise ValueError(f"source root is not a directory: {candidate}")
            except (OSError, ValueError):
                if index == 0 and source_root is not None:
                    raise ValueError(
                        f"sandbox source root is not a plain directory: {candidate}"
                    ) from None
                continue
            roots.append(candidate)
        self.source_roots = tuple(roots)

        base = _absolute(
            Path(sandbox_root)
            if sandbox_root is not None
            else data_dir() / "code-sandboxes"
        )
        self.root = _absolute(base / self.key)
        if not _within(self.root, base):
            raise ValueError("sandbox root escaped its data boundary")
        _validate_chain(base, allow_missing_tail=True)
        _ensure_directory(self.root)
        self._lock = threading.RLock()

        normalized: list[str] = []
        for raw in source_paths:
            item = _relative_source(raw)
            if item not in normalized:
                normalized.append(item)

        files: list[SandboxFile] = []
        for relative in normalized:
            source = self._find_source(relative)
            if source is None:
                continue
            working = _absolute(self.root / Path(relative))
            if not _within(working, self.root):
                raise ValueError(f"sandbox working path escaped boundary: {relative}")
            files.append(SandboxFile(relative, source, working))
        self.files = tuple(files)
        self._by_relative = {item.relative_path: item for item in self.files}

    def _find_source(self, relative: str) -> Path | None:
        for root in self.source_roots:
            candidate = _absolute(root / Path(relative))
            if not _within(candidate, root):
                continue
            try:
                _validate_chain(candidate)
                info = os.lstat(candidate)
                if stat.S_ISREG(info.st_mode) and not _is_link_or_reparse(info):
                    return candidate
            except (OSError, ValueError):
                continue
        return None

    @property
    def available(self) -> bool:
        return bool(self.files)

    def ensure(self) -> tuple[SandboxFile, ...]:
        """Create missing working copies while preserving existing experiments."""
        with self._lock:
            _validate_chain(self.root)
            for item in self.files:
                try:
                    os.lstat(item.working_path)
                except FileNotFoundError:
                    _atomic_bytes_write(
                        item.working_path,
                        _read_bytes(item.source_path, root=self._source_root(item)),
                        root=self.root,
                    )
                else:
                    _validate_regular_file(item.working_path)
            return self.files

    def _source_root(self, item: SandboxFile) -> Path:
        for root in self.source_roots:
            if _within(item.source_path, root):
                return root
        raise ValueError(f"source escaped configured roots: {item.relative_path}")

    def file(self, relative_path: str) -> SandboxFile:
        relative = _relative_source(relative_path)
        try:
            return self._by_relative[relative]
        except KeyError as exc:
            raise ValueError(f"source is not allow-listed for this sandbox: {relative}") from exc

    def read(self, relative_path: str) -> str:
        with self._lock:
            item = self.file(relative_path)
            self.ensure()
            text = _read_bytes(item.working_path, root=self.root).decode("utf-8")
            return text.replace("\r\n", "\n").replace("\r", "\n")

    def reload(self, relative_path: str) -> str:
        """Reload a saved working copy without touching installed source."""
        return self.read(relative_path)

    def save(self, relative_path: str, text: str) -> SandboxFile:
        """Save an experiment after a syntax gate; never touch ``source_path``."""
        with self._lock:
            item = self.file(relative_path)
            self.ensure()
            content = str(text)
            if item.working_path.suffix.casefold() == ".py":
                ast.parse(content, filename=item.relative_path)
            _atomic_text_write(item.working_path, content, root=self.root)
            return item

    def reset(self, relative_paths: Iterable[str] | None = None) -> tuple[SandboxFile, ...]:
        """Restore working copies from source without ever rewriting source."""
        with self._lock:
            selected = (
                tuple(self.file(path) for path in relative_paths)
                if relative_paths is not None
                else self.files
            )
            for item in selected:
                _atomic_bytes_write(
                    item.working_path,
                    _read_bytes(item.source_path, root=self._source_root(item)),
                    root=self.root,
                )
            return selected

    def rollback(
        self, relative_paths: Iterable[str] | None = None
    ) -> tuple[SandboxFile, ...]:
        """Roll back working copies to installed bytes; never rewrite source."""
        return self.reset(relative_paths)

    def changed(self, relative_path: str) -> bool:
        with self._lock:
            item = self.file(relative_path)
            try:
                original = hashlib.sha256(
                    _read_bytes(item.source_path, root=self._source_root(item))
                ).digest()
                working = hashlib.sha256(
                    _read_bytes(item.working_path, root=self.root)
                ).digest()
                return original != working
            except OSError:
                return False

    def changed_paths(self) -> tuple[str, ...]:
        return tuple(item.relative_path for item in self.files if self.changed(item.relative_path))
