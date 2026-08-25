"""Unattended adversary containment with durable, reversible action receipts.

``AdversaryCombat`` is the standing-authority response tier.  It consumes
authenticated local detector events and acts immediately; it never opens an
approval dialog.  The operator chooses the policy once in Settings and can
later change it or undo reversible actions.

Maximum mode intentionally accepts availability risk.  Evidence is still
bound to the exact process, file, executable, or remote address named by the
detector so a response cannot drift onto an unrelated target.
"""
from __future__ import annotations

import ipaddress
import hashlib
import hmac
import json
import math
import os
import queue
import re
import secrets
import stat
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from angerona.core.data_paths import data_dir as canonical_data_dir
from angerona.core.eventbus import Event, Severity, is_remote_observe_only
from angerona.core.module_base import BaseModule
from angerona.core.threat import event_disposition

try:
    # Keep the two autonomous response tiers on the same immutable Windows
    # never-contain policy.  This is deliberately not operator-configurable.
    from angerona.modules.soar import _SYSTEM32_NEVER_CONTAIN
except Exception:  # pragma: no cover - import failure must fail safe
    _SYSTEM32_NEVER_CONTAIN = frozenset({
        "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "svchost.exe", "ntoskrnl.exe", "system", "registry",
    })

try:
    import psutil
except Exception:  # pragma: no cover - the module still blocks/quarantines
    psutil = None


_TRUE = frozenset({"1", "true", "yes", "on"})
_MODES = frozenset({"contain", "aggressive", "maximum"})
_PROCESS_ACTIONS = frozenset({"suspend", "terminate"})
_SELF_MODULES = frozenset({
    "Adversary Combat",
    "Active Response SOAR",
    "SOAR Automation",
    "Console",
})
_REMOTE_FIELDS = (
    "remote_ip", "destination_ip", "dest_ip", "dst_ip", "ip", "raddr",
)
_PATH_FIELDS = ("path", "artifact_path", "file_path", "exe", "process_path", "image")
_CORRELATION_FIELDS = (
    "correlation_id", "incident_id", "event_id", "run_id", "probe_id",
    "drill_id", "correlation_token",
)
_CRITICAL_ROOT_FILES = frozenset({
    "bootmgr", "bootnxt", "hiberfil.sys", "pagefile.sys", "swapfile.sys",
})
_JOURNAL_VERSION = 1
_JOURNAL_GENESIS = "0" * 64
_JOURNAL_CONTEXT = b"angerona-adversary-combat-journal-v1"
_SIGNED_RECORD_TYPES = frozenset({
    "intent", "commit", "failure", "undo_intent", "undo_commit",
    "undo_failure", "orphan",
})
_CONTRACT_ACTIONS = frozenset({
    "block_remote_ip",
    "isolate_program",
    "suspend_process",
    "terminate_process",
    "quarantine_file",
    "isolate_host",
    "activate_honeypots",
})
_CONTRACT_TARGETS = frozenset({
    "path", "pid", "process_create_time", "remote_ips", "host", "deception",
})
_MANAGED_RULE_PATTERNS = {
    "block_remote_ip": re.compile(
        r"\AAngerona-Combat-IP-[0-9a-f]{12}-(?:in|out)\Z"
    ),
    "isolate_program": re.compile(
        r"\AAngerona-Combat-Program-[1-9][0-9]*-[0-9a-f]{8}\Z"
    ),
    "isolate_host": re.compile(
        r"\AAngerona-Combat-Host-[0-9a-f]{10}-(?:in|out)\Z"
    ),
}


class JournalIntegrityError(RuntimeError):
    """The combat journal cannot safely authorize another host mutation."""


def _absolute_path(path: Path) -> Path:
    """Return an absolute lexical path without following attacker-controlled links."""
    return Path(os.path.abspath(os.fspath(path)))


class _PinnedFileMove:
    """Pin one regular file and move that exact object without following links.

    Windows holds non-reparse handles for every parent and denies delete/write
    sharing on the source before hashing it.  The rename is then performed on
    the file handle with ``SetFileInformationByHandle``.  POSIX uses no-follow
    ``openat`` traversal, pins the inode, and uses ``renameat2(RENAME_NOREPLACE)``
    where available.  Unsupported platforms fail closed instead of falling
    back to a path-based copy/delete operation.
    """

    def __init__(self, path: Path) -> None:
        self.path = _absolute_path(path)
        self._closed = False
        if os.name == "nt":
            self._impl: Any = _WindowsPinnedFileMove(self.path)
        else:
            self._impl = _PosixPinnedFileMove(self.path)

    @property
    def identity(self) -> str:
        return self._impl.identity

    @property
    def move_strategy(self) -> str:
        return str(getattr(self._impl, "last_move_strategy", "rename"))

    def sha256(self) -> str:
        return self._impl.sha256()

    def rename_to(self, destination: Path) -> str:
        return str(self._impl.rename_to(_absolute_path(destination)))

    def crosses_volume(self, destination: Path) -> bool:
        checker = getattr(self._impl, "crosses_volume", None)
        return bool(checker and checker(_absolute_path(destination)))

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._impl.close()

    def __enter__(self) -> "_PinnedFileMove":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class _PosixPinnedFileMove:
    """No-follow dirfd implementation used on Linux and compatible POSIX hosts."""

    _RENAME_NOREPLACE = 1

    def __init__(self, path: Path) -> None:
        if not path.is_absolute() or not path.name:
            raise OSError("secure move requires an absolute file path")
        self.path = path
        self._parent_fd = self._open_dir(path.parent, create=False)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            self._fd = os.open(path.name, flags, dir_fd=self._parent_fd)
        except Exception:
            os.close(self._parent_fd)
            raise
        info = os.fstat(self._fd)
        if not stat.S_ISREG(info.st_mode):
            self.close()
            raise OSError("secure move source is not a regular file")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            self.close()
            raise OSError("secure move source has a different owner")
        self._dev_ino = (int(info.st_dev), int(info.st_ino))
        self.identity = f"posix:{info.st_dev}:{info.st_ino}"

    @staticmethod
    def _open_dir(path: Path, *, create: bool) -> int:
        absolute = _absolute_path(path)
        parts = absolute.parts
        if not parts:
            raise OSError("invalid secure directory")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        current = os.open(parts[0], flags)
        try:
            for component in parts[1:]:
                try:
                    child = os.open(component, flags, dir_fd=current)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(component, mode=0o700, dir_fd=current)
                    child = os.open(component, flags, dir_fd=current)
                os.close(current)
                current = child
            return current
        except Exception:
            os.close(current)
            raise

    def _source_name_matches(self) -> bool:
        try:
            info = os.stat(
                self.path.name,
                dir_fd=self._parent_fd,
                follow_symlinks=False,
            )
        except OSError:
            return False
        return (int(info.st_dev), int(info.st_ino)) == self._dev_ino

    @classmethod
    def _rename_noreplace(
        cls,
        source_fd: int,
        source_name: str,
        destination_fd: int,
        destination_name: str,
    ) -> None:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise OSError("renameat2(RENAME_NOREPLACE) is unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            source_fd,
            os.fsencode(source_name),
            destination_fd,
            os.fsencode(destination_name),
            cls._RENAME_NOREPLACE,
        )
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    def sha256(self) -> str:
        digest = hashlib.sha256()
        os.lseek(self._fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(self._fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        os.lseek(self._fd, 0, os.SEEK_SET)
        return digest.hexdigest()

    def rename_to(self, destination: Path) -> str:
        destination_fd = self._open_dir(destination.parent, create=True)
        try:
            if not self._source_name_matches():
                raise OSError("secure move source name no longer identifies pinned file")
            self._rename_noreplace(
                self._parent_fd,
                self.path.name,
                destination_fd,
                destination.name,
            )
            moved = os.stat(
                destination.name,
                dir_fd=destination_fd,
                follow_symlinks=False,
            )
            if (int(moved.st_dev), int(moved.st_ino)) != self._dev_ino:
                # A forced name swap won the narrow pre-rename race. Restore
                # that object to the source name and never authorize a commit.
                self._rename_noreplace(
                    destination_fd,
                    destination.name,
                    self._parent_fd,
                    self.path.name,
                )
                raise OSError("secure move destination is not the pinned file")
            self.last_move_strategy = "rename"
        finally:
            os.close(destination_fd)
        return self.identity

    def close(self) -> None:
        fd = getattr(self, "_fd", None)
        if fd is not None:
            os.close(fd)
            self._fd = None
        parent_fd = getattr(self, "_parent_fd", None)
        if parent_fd is not None:
            os.close(parent_fd)
            self._parent_fd = None


class _WindowsPinnedFileMove:
    """Windows handle-pinned rename implementation (no path-based move)."""

    def __init__(self, path: Path) -> None:
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._wintypes = wintypes
        self.path = path
        self._directory_handles = self._open_directory_chain(path.parent, create=False)
        self._handle = None
        try:
            self._handle = self._create_file(path)
            info = self._file_info(self._handle)
        except Exception:
            self.close()
            raise
        if info.dwFileAttributes & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
            self.close()
            raise OSError("secure move source is a reparse point")
        if info.dwFileAttributes & 0x10:  # FILE_ATTRIBUTE_DIRECTORY
            self.close()
            raise OSError("secure move source is not a regular file")
        index = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
        self._identity_tuple = (int(info.dwVolumeSerialNumber), index)
        self.identity = f"windows:{info.dwVolumeSerialNumber:08x}:{index:016x}"

    def _kernel32(self):
        kernel32 = self._ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            self._wintypes.LPCWSTR,
            self._wintypes.DWORD,
            self._wintypes.DWORD,
            self._wintypes.LPVOID,
            self._wintypes.DWORD,
            self._wintypes.DWORD,
            self._wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = self._wintypes.HANDLE
        kernel32.GetFileInformationByHandle.argtypes = [
            self._wintypes.HANDLE,
            self._wintypes.LPVOID,
        ]
        kernel32.GetFileInformationByHandle.restype = self._wintypes.BOOL
        kernel32.SetFilePointerEx.argtypes = [
            self._wintypes.HANDLE,
            self._ctypes.c_longlong,
            self._ctypes.POINTER(self._ctypes.c_longlong),
            self._wintypes.DWORD,
        ]
        kernel32.SetFilePointerEx.restype = self._wintypes.BOOL
        kernel32.ReadFile.argtypes = [
            self._wintypes.HANDLE,
            self._wintypes.LPVOID,
            self._wintypes.DWORD,
            self._ctypes.POINTER(self._wintypes.DWORD),
            self._wintypes.LPVOID,
        ]
        kernel32.ReadFile.restype = self._wintypes.BOOL
        kernel32.WriteFile.argtypes = [
            self._wintypes.HANDLE,
            self._wintypes.LPCVOID,
            self._wintypes.DWORD,
            self._ctypes.POINTER(self._wintypes.DWORD),
            self._wintypes.LPVOID,
        ]
        kernel32.WriteFile.restype = self._wintypes.BOOL
        kernel32.FlushFileBuffers.argtypes = [self._wintypes.HANDLE]
        kernel32.FlushFileBuffers.restype = self._wintypes.BOOL
        kernel32.SetFileInformationByHandle.argtypes = [
            self._wintypes.HANDLE,
            self._ctypes.c_int,
            self._wintypes.LPVOID,
            self._wintypes.DWORD,
        ]
        kernel32.SetFileInformationByHandle.restype = self._wintypes.BOOL
        kernel32.CloseHandle.argtypes = [self._wintypes.HANDLE]
        kernel32.CloseHandle.restype = self._wintypes.BOOL
        return kernel32

    def _open_directory_chain(self, path: Path, *, create: bool) -> list[int]:
        handles: list[int] = []
        current = Path(path.anchor)
        parts = path.parts[1:]
        try:
            handles.append(self._create_directory(current))
            for part in parts:
                current /= part
                if create:
                    try:
                        os.mkdir(current)
                    except FileExistsError:
                        pass
                handles.append(self._create_directory(current))
            return handles
        except Exception:
            self._close_handles(handles)
            raise

    def _create_directory(self, path: Path) -> int:
        kernel32 = self._kernel32()
        kernel32.CreateFileW.restype = self._wintypes.HANDLE
        handle = kernel32.CreateFileW(
            str(path),
            0x0001 | 0x0080,  # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
            0x0001 | 0x0002,  # share read/write, deliberately deny delete
            None,
            3,
            0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
            None,
        )
        if handle == self._wintypes.HANDLE(-1).value:
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        info = self._file_info(handle)
        if not (info.dwFileAttributes & 0x10) or info.dwFileAttributes & 0x400:
            kernel32.CloseHandle(handle)
            raise OSError(f"secure directory is missing or reparse-backed: {path}")
        return int(handle)

    def _create_file(self, path: Path) -> int:
        kernel32 = self._kernel32()
        kernel32.CreateFileW.restype = self._wintypes.HANDLE
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000 | 0x00010000 | 0x0080,  # READ | DELETE | READ_ATTRIBUTES
            0x0001,  # share read only: deny write/delete swaps while pinned
            None,
            3,
            0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
            None,
        )
        if handle == self._wintypes.HANDLE(-1).value:
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        return int(handle)

    def _open_verification_file(self, path: Path) -> int:
        kernel32 = self._kernel32()
        kernel32.CreateFileW.restype = self._wintypes.HANDLE
        handle = kernel32.CreateFileW(
            str(path),
            0x0080,  # FILE_READ_ATTRIBUTES
            0x0001,  # compatible with the pinned source's share-read policy
            None,
            3,
            0x00200000,
            None,
        )
        if handle == self._wintypes.HANDLE(-1).value:
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        return int(handle)

    def _create_destination_file(self, path: Path) -> int:
        """Atomically create one non-reparse destination with no replacement."""
        handle = self._kernel32().CreateFileW(
            str(path),
            0x80000000 | 0x40000000 | 0x00010000 | 0x0080,
            0x0001,  # readers only; deny write/delete swaps while copying
            None,
            1,  # CREATE_NEW
            0x00000080 | 0x08000000,  # NORMAL | SEQUENTIAL_SCAN
            None,
        )
        if handle == self._wintypes.HANDLE(-1).value:
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        return int(handle)

    def _file_info(self, handle: int):
        class ByHandleFileInformation(self._ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", self._wintypes.DWORD),
                ("ftCreationTime", self._wintypes.FILETIME),
                ("ftLastAccessTime", self._wintypes.FILETIME),
                ("ftLastWriteTime", self._wintypes.FILETIME),
                ("dwVolumeSerialNumber", self._wintypes.DWORD),
                ("nFileSizeHigh", self._wintypes.DWORD),
                ("nFileSizeLow", self._wintypes.DWORD),
                ("nNumberOfLinks", self._wintypes.DWORD),
                ("nFileIndexHigh", self._wintypes.DWORD),
                ("nFileIndexLow", self._wintypes.DWORD),
            ]

        info = ByHandleFileInformation()
        if not self._kernel32().GetFileInformationByHandle(handle, self._ctypes.byref(info)):
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        return info

    def _sha256_handle(self, handle: int) -> str:
        kernel32 = self._kernel32()
        position = self._ctypes.c_longlong(0)
        if not kernel32.SetFilePointerEx(handle, 0, self._ctypes.byref(position), 0):
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        digest = hashlib.sha256()
        buffer = self._ctypes.create_string_buffer(1024 * 1024)
        read = self._wintypes.DWORD()
        while True:
            if not kernel32.ReadFile(
                handle,
                buffer,
                len(buffer),
                self._ctypes.byref(read),
                None,
            ):
                raise self._ctypes.WinError(self._ctypes.get_last_error())
            if not read.value:
                break
            digest.update(buffer.raw[:read.value])
        if not kernel32.SetFilePointerEx(handle, 0, self._ctypes.byref(position), 0):
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        return digest.hexdigest()

    def sha256(self) -> str:
        digest = self._sha256_handle(self._handle)
        self._expected_digest = digest
        return digest

    @staticmethod
    def _identity_from_info(info: Any) -> tuple[tuple[int, int], str]:
        index = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
        serial = int(info.dwVolumeSerialNumber)
        return (serial, index), f"windows:{serial:08x}:{index:016x}"

    def crosses_volume(self, destination: Path) -> bool:
        anchor = self._create_directory(Path(destination.anchor))
        try:
            info = self._file_info(anchor)
            return int(info.dwVolumeSerialNumber) != self._identity_tuple[0]
        finally:
            self._kernel32().CloseHandle(anchor)

    def _rename_same_volume(
        self,
        destination: Path,
        destination_handles: list[int],
    ) -> str:
        del destination_handles  # handles remain live in the caller
        class FileRenameInfo(self._ctypes.Structure):
            _fields_ = [
                ("ReplaceIfExists", self._wintypes.BOOLEAN),
                ("RootDirectory", self._wintypes.HANDLE),
                ("FileNameLength", self._wintypes.DWORD),
                ("FileName", self._wintypes.WCHAR * 1),
            ]

        encoded = str(destination).encode("utf-16-le")
        size = FileRenameInfo.FileName.offset + len(encoded) + 2
        buffer = self._ctypes.create_string_buffer(size)
        info = self._ctypes.cast(
            buffer,
            self._ctypes.POINTER(FileRenameInfo),
        ).contents
        info.ReplaceIfExists = 0
        info.RootDirectory = None
        info.FileNameLength = len(encoded)
        self._ctypes.memmove(
            self._ctypes.addressof(buffer) + FileRenameInfo.FileName.offset,
            encoded,
            len(encoded),
        )
        if not self._kernel32().SetFileInformationByHandle(
            self._handle,
            3,  # FileRenameInfo
            buffer,
            size,
        ):
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        verification = self._open_verification_file(destination)
        try:
            moved = self._file_info(verification)
            identity, identity_text = self._identity_from_info(moved)
            if identity != self._identity_tuple:
                raise OSError("secure move destination is not the pinned file")
            self.last_move_strategy = "rename"
            return identity_text
        finally:
            self._kernel32().CloseHandle(verification)

    def _set_delete_pending(self, handle: int) -> None:
        class FileDispositionInfo(self._ctypes.Structure):
            _fields_ = [("DeleteFile", self._wintypes.BOOLEAN)]

        disposition = FileDispositionInfo(1)
        if not self._kernel32().SetFileInformationByHandle(
            handle,
            4,  # FileDispositionInfo
            self._ctypes.byref(disposition),
            self._ctypes.sizeof(disposition),
        ):
            raise self._ctypes.WinError(self._ctypes.get_last_error())

    def _copy_delete_cross_volume(self, destination: Path) -> str:
        """Copy from the pinned source into CREATE_NEW, then delete by handle."""
        destination_handle = self._create_destination_file(destination)
        source_deleted = False
        try:
            kernel32 = self._kernel32()
            expected_digest = getattr(self, "_expected_digest", None) or self.sha256()
            source_info = self._file_info(self._handle)
            expected_size = (
                (int(source_info.nFileSizeHigh) << 32)
                | int(source_info.nFileSizeLow)
            )
            position = self._ctypes.c_longlong(0)
            if not kernel32.SetFilePointerEx(
                self._handle, 0, self._ctypes.byref(position), 0
            ):
                raise self._ctypes.WinError(self._ctypes.get_last_error())
            if not kernel32.SetFilePointerEx(
                destination_handle, 0, self._ctypes.byref(position), 0
            ):
                raise self._ctypes.WinError(self._ctypes.get_last_error())

            digest = hashlib.sha256()
            buffer = self._ctypes.create_string_buffer(1024 * 1024)
            read = self._wintypes.DWORD()
            written = self._wintypes.DWORD()
            total = 0
            while True:
                if not kernel32.ReadFile(
                    self._handle,
                    buffer,
                    len(buffer),
                    self._ctypes.byref(read),
                    None,
                ):
                    raise self._ctypes.WinError(self._ctypes.get_last_error())
                if not read.value:
                    break
                if not kernel32.WriteFile(
                    destination_handle,
                    buffer,
                    read.value,
                    self._ctypes.byref(written),
                    None,
                ):
                    raise self._ctypes.WinError(self._ctypes.get_last_error())
                if written.value != read.value:
                    raise OSError("secure cross-volume copy was truncated")
                total += int(read.value)
                if total > expected_size:
                    raise OSError("secure cross-volume source size changed")
                digest.update(buffer.raw[:read.value])
            if total != expected_size or digest.hexdigest() != expected_digest:
                raise OSError("secure cross-volume source verification failed")
            if not kernel32.FlushFileBuffers(destination_handle):
                raise self._ctypes.WinError(self._ctypes.get_last_error())
            destination_info = self._file_info(destination_handle)
            destination_size = (
                (int(destination_info.nFileSizeHigh) << 32)
                | int(destination_info.nFileSizeLow)
            )
            if (
                destination_size != expected_size
                or self._sha256_handle(destination_handle) != expected_digest
            ):
                raise OSError("secure cross-volume destination verification failed")

            _identity, identity_text = self._identity_from_info(destination_info)
            # Source removal is performed against the still-pinned source
            # object, never by a path that could have been exchanged.
            self._set_delete_pending(self._handle)
            source_deleted = True
            self.last_move_strategy = "cross_volume_copy"
            return identity_text
        except Exception:
            if not source_deleted:
                try:
                    self._set_delete_pending(destination_handle)
                except Exception:
                    pass
            raise
        finally:
            self._kernel32().CloseHandle(destination_handle)

    def rename_to(self, destination: Path) -> str:
        destination_handles = self._open_directory_chain(
            destination.parent,
            create=True,
        )
        try:
            try:
                return self._rename_same_volume(destination, destination_handles)
            except OSError as exc:
                if int(getattr(exc, "winerror", 0) or 0) != 17:
                    raise
                return self._copy_delete_cross_volume(destination)
        finally:
            self._close_handles(destination_handles)

    def _close_handles(self, handles: list[int]) -> None:
        kernel32 = self._kernel32()
        for handle in reversed(handles):
            if handle:
                kernel32.CloseHandle(handle)

    def close(self) -> None:
        handle = getattr(self, "_handle", None)
        if handle:
            self._kernel32().CloseHandle(handle)
            self._handle = None
        handles = getattr(self, "_directory_handles", [])
        self._close_handles(handles)
        self._directory_handles = []


def _bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().casefold() in _TRUE


def _severity(value: object, default: Severity = Severity.LOW) -> Severity:
    text = str(value or default.name).strip().upper()
    try:
        return Severity[text]
    except KeyError:
        return default


@dataclass(frozen=True)
class CombatPolicy:
    enabled: bool = True
    mode: str = "maximum"
    min_severity: Severity = Severity.LOW
    block_network: bool = True
    quarantine_files: bool = True
    process_action: str = "terminate"
    isolate_host: bool = True
    activate_honeypots: bool = True
    isolation_event_threshold: int = 3
    isolation_window_seconds: float = 30.0


@dataclass(frozen=True)
class CombatAction:
    action_id: str
    combat_id: str
    action: str
    applied_at: float
    reversible: bool
    target: str
    details: dict[str, Any]
    trigger_module: str
    trigger_ts: float
    status: str = "applied"


class AdversaryCombat(BaseModule):
    """Execute block/contain/isolate/deceive playbooks without incident prompts."""

    name = "Adversary Combat"
    description = (
        "Unattended maximum-response tier: blocks, contains, quarantines, "
        "isolates, and activates honeypots with undo receipts."
    )
    category = "Response"
    version = "1.0.0"
    enabled_by_default = True

    def __init__(self, data_root: Path | None = None) -> None:
        super().__init__()
        self._manager = None
        self._explicit_data_root = Path(data_root) if data_root is not None else None
        self._queue: queue.Queue[Event] = queue.Queue(maxsize=2048)
        self._receipt_lock = threading.RLock()
        self._seen_order: deque[str] = deque(maxlen=8192)
        self._seen: set[str] = set()
        self._active_events: deque[tuple[float, str]] = deque(maxlen=256)
        self._host_isolated = False
        self._honeypot_started_by_combat = False
        self._dropped_events = 0
        self._blocked_ips: set[str] = set()
        self._blocked_programs: set[str] = set()
        self._journal_key_cache: bytes | None = None
        self._journal_error = ""
        # A response mutation may never continue after durable accounting or
        # exact rollback has failed.  This in-memory circuit is tripped at the
        # mutation boundary and is also rebuilt from the signed journal on
        # startup.  Read-only evidence collection continues while Combat is
        # disarmed for recovery.
        self._mutation_blocked = False
        self._recovery_required: dict[str, dict[str, Any]] = {}

    def bind_manager(self, manager) -> None:
        self._manager = manager

    @property
    def data_root(self) -> Path:
        if self._explicit_data_root is not None:
            return self._explicit_data_root
        config = getattr(self._manager, "config", None)
        configured = getattr(config, "data_dir", None)
        return Path(configured) if configured is not None else canonical_data_dir()

    @property
    def quarantine_root(self) -> Path:
        return self.data_root / "combat-quarantine"

    @property
    def receipt_path(self) -> Path:
        return self.data_root / "shared_logs" / "adversary_combat_actions.jsonl"

    @property
    def journal_key_path(self) -> Path:
        return self.data_root / "adversary_combat_journal.key"

    def policy(self) -> CombatPolicy:
        config = getattr(self._manager, "config", None)

        def setting(name: str, default: object) -> object:
            env_name = "ANGERONA_" + name.upper()
            if env_name in os.environ:
                return os.environ[env_name]
            return getattr(config, name.lower(), default) if config is not None else default

        mode = str(setting("ADVERSARY_COMBAT_MODE", "maximum")).strip().casefold()
        if mode not in _MODES:
            mode = "maximum"
        process_action = str(
            setting("ADVERSARY_COMBAT_PROCESS_ACTION", "terminate")
        ).strip().casefold()
        if process_action not in _PROCESS_ACTIONS:
            process_action = "terminate"
        try:
            threshold = max(1, min(100, int(
                setting("ADVERSARY_COMBAT_ISOLATION_THRESHOLD", 3)
            )))
        except (TypeError, ValueError, OverflowError):
            threshold = 3
        return CombatPolicy(
            enabled=_bool(setting("ADVERSARY_COMBAT_ENABLED", True), True),
            mode=mode,
            min_severity=_severity(setting("ADVERSARY_COMBAT_MIN_SEVERITY", "LOW")),
            block_network=_bool(
                setting("ADVERSARY_COMBAT_BLOCK_NETWORK", True), True
            ),
            quarantine_files=_bool(
                setting("ADVERSARY_COMBAT_QUARANTINE_FILES", True), True
            ),
            process_action=process_action,
            isolate_host=_bool(
                setting("ADVERSARY_COMBAT_ISOLATE_HOST", True), True
            ),
            activate_honeypots=_bool(
                setting("ADVERSARY_COMBAT_ACTIVATE_HONEYPOTS", True), True
            ),
            isolation_event_threshold=threshold,
        )

    def self_test(self) -> tuple[bool, str]:
        policy = self.policy()
        ok = (
            self.status == "running"
            and policy.enabled
            and not self._mutation_blocked
        )
        state = (
            "armed"
            if ok
            else "RECOVERY REQUIRED"
            if self._mutation_blocked
            else f"status={self.status}"
        )
        detail = (
            f"{policy.mode.upper()} {state}; {policy.min_severity.label}+; "
            f"process={policy.process_action}; queue drops={self._dropped_events}"
        )
        return ok, detail

    def response_ready(self) -> bool:
        """Return whether new host mutations may cross the Combat boundary."""
        return bool(
            self.status == "running"
            and self.policy().enabled
            and not self._mutation_blocked
        )

    def run(self) -> None:
        if self._bus is None:
            self.set_health(0, "event bus unavailable")
            return
        if not self._reconcile_state():
            self.emit(
                "Adversary Combat refused to arm: action journal integrity failed.",
                Severity.CRITICAL,
                disposition="health",
                response_authorized=False,
            )
            return
        self._bus.subscribe(self._submit)
        policy = self.policy()
        if policy.activate_honeypots:
            self._ensure_honeypots()
        self.set_health(100, "standing authority armed")
        self.emit(
            "Adversary Combat online — standing authority is ARMED. Detector evidence "
            "is acted on automatically without per-incident approval.",
            Severity.INFO,
            action_policy=policy.mode,
            minimum_severity=policy.min_severity.name,
        )
        self.mark_cycle_complete()
        stop = self.generation_stop_event()
        while not stop.is_set():
            try:
                event = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self._handle(event)
            finally:
                self._queue.task_done()

    def _submit(self, event: Event) -> None:
        if self.status != "running" or self.stopping or self._mutation_blocked:
            return
        policy = self.policy()
        if not policy.enabled or event.module in _SELF_MODULES:
            return
        # Cross-host evidence and explicitly non-response audit records have no
        # authority to mutate this endpoint or contribute to its isolation
        # threshold.  Enforce this before queue/dedup state is touched.
        if is_remote_observe_only(event) or not self._response_authorized(event):
            return
        if event.severity < policy.min_severity:
            return
        disposition = event_disposition(event)
        if disposition not in {"active", "practice"}:
            return
        signature = str(getattr(event, "hmac_sig", "") or "")
        details = event.details if isinstance(event.details, dict) else {}
        queue_request_id = str(details.get("queue_request_id") or "").casefold()
        identity = (
            f"soar:{queue_request_id}"
            if re.fullmatch(r"[0-9a-f]{32}", queue_request_id)
            else signature
        ) or (
            f"{event.module}\0{event.ts:.9f}\0{event.message}\0"
            f"{json.dumps(event.details or {}, sort_keys=True, default=str)}"
        )
        with self._receipt_lock:
            if identity in self._seen:
                return
            if len(self._seen_order) == self._seen_order.maxlen:
                self._seen.discard(self._seen_order[0])
            self._seen_order.append(identity)
            self._seen.add(identity)
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Admission failed, so the dedup claim must fail with it. Keeping
            # the identity would poison this exact request forever even after
            # capacity returns.
            with self._receipt_lock:
                self._seen.discard(identity)
                try:
                    self._seen_order.remove(identity)
                except ValueError:
                    pass
            self._dropped_events += 1
            self.set_health(30, "combat event queue saturated")
            self.emit(
                "Adversary Combat could not admit a response request because "
                "its bounded queue was saturated.",
                Severity.HIGH,
                disposition="health",
                response_authorized=False,
                action_succeeded=False,
                mitigated=False,
                postcondition_verified=False,
                actions=[],
                action_ids=[],
                queue_request_id=(
                    queue_request_id
                    if re.fullmatch(r"[0-9a-f]{32}", queue_request_id)
                    else None
                ),
                failure_reason="combat_queue_saturated",
            )

    def _integrity_ok(self, event: Event) -> bool:
        if self._bus is None or not getattr(self._bus, "integrity_enabled", False):
            return True
        try:
            return bool(self._bus.verify(event))
        except Exception:
            return False

    @classmethod
    def _response_actions(cls, event: Event) -> frozenset[str] | None:
        details = event.details if isinstance(event.details, dict) else {}
        # Severity is evidence priority, never response authority.  A producer
        # must deliberately opt into the local mutation contract; omission is
        # default-deny so a generic HIGH/CRITICAL health or bridge event cannot
        # cascade into host isolation.
        if details.get("response_authorized") is not True:
            return None
        contract = details.get("response_contract")
        if not isinstance(contract, dict) or set(contract) != {
            "version", "actions", "targets"
        }:
            return None
        if contract.get("version") != 1:
            return None
        raw_actions = contract.get("actions")
        targets = contract.get("targets")
        if (
            not isinstance(raw_actions, list)
            or not raw_actions
            or not all(isinstance(value, str) for value in raw_actions)
            or len(set(raw_actions)) != len(raw_actions)
            or not set(raw_actions).issubset(_CONTRACT_ACTIONS)
            or not isinstance(targets, dict)
            or not set(targets).issubset(_CONTRACT_TARGETS)
        ):
            return None
        actions = frozenset(raw_actions)

        if "quarantine_file" in actions:
            event_path = cls._event_path(event)
            contract_path = targets.get("path")
            if not event_path or not isinstance(contract_path, str):
                return None
            try:
                event_target = os.path.normcase(
                    str(Path(event_path).expanduser().resolve(strict=False))
                )
                contracted_target = os.path.normcase(
                    str(Path(contract_path).expanduser().resolve(strict=False))
                )
            except (OSError, RuntimeError, ValueError):
                return None
            if event_target != contracted_target:
                return None

        process_actions = actions.intersection({
            "isolate_program", "suspend_process", "terminate_process"
        })
        if process_actions:
            pid = details.get("pid")
            if not isinstance(pid, int) or pid <= 0 or targets.get("pid") != pid:
                return None
            supplied, event_start = cls._expected_process_start(details)
            try:
                contracted_start = float(targets.get("process_create_time"))
            except (TypeError, ValueError, OverflowError):
                return None
            if (
                not supplied
                or event_start is None
                or not math.isfinite(contracted_start)
                or abs(event_start - contracted_start) > 0.001
            ):
                return None

        if "block_remote_ip" in actions:
            event_ips = cls._remote_ips(event)
            raw_ips = targets.get("remote_ips")
            if not event_ips or not isinstance(raw_ips, list):
                return None
            try:
                contracted_ips = tuple(
                    dict.fromkeys(str(ipaddress.ip_address(str(value))) for value in raw_ips)
                )
            except ValueError:
                return None
            if contracted_ips != event_ips:
                return None

        if "isolate_host" in actions and targets.get("host") != "local":
            return None
        if (
            "activate_honeypots" in actions
            and targets.get("deception") != "Smart Deception"
        ):
            return None
        return actions

    @classmethod
    def _response_authorized(cls, event: Event) -> bool:
        return cls._response_actions(event) is not None

    @staticmethod
    def _causal_key(event: Event) -> str:
        details = event.details if isinstance(event.details, dict) else {}
        for key in _CORRELATION_FIELDS:
            value = details.get(key)
            if value not in (None, ""):
                return f"{key}:{str(value)[:256]}"
        signature = str(getattr(event, "hmac_sig", "") or "")
        if signature:
            return f"event:{signature}"
        return (
            f"event:{event.module}\0{event.ts:.9f}\0{event.message}\0"
            f"{json.dumps(details, sort_keys=True, default=str)}"
        )

    def _record_active_cause(
        self, event: Event, now: float, window_seconds: float
    ) -> int:
        while self._active_events and now - self._active_events[0][0] > window_seconds:
            self._active_events.popleft()
        cause = self._causal_key(event)
        if not any(existing == cause for _stamp, existing in self._active_events):
            self._active_events.append((now, cause))
        return len(self._active_events)

    @staticmethod
    def _event_path(event: Event) -> str:
        details = event.details or {}
        for key in _PATH_FIELDS:
            value = details.get(key)
            if value:
                return str(value)
        return ""

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            path_text = os.path.normcase(str(path.resolve(strict=False)))
            root_text = os.path.normcase(str(root.resolve(strict=False)))
            return os.path.commonpath((path_text, root_text)) == root_text
        except (OSError, RuntimeError, ValueError):
            return False

    @staticmethod
    def _system_root() -> Path | None:
        configured = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if configured:
            return Path(configured)
        if os.name == "nt":
            return Path(r"C:\Windows")
        return None

    @classmethod
    def _is_system_path(cls, path: Path) -> bool:
        system_root = cls._system_root()
        return system_root is not None and cls._is_within(path, system_root)

    @classmethod
    def _is_protected_file(cls, path: Path) -> bool:
        """Immutable deny boundary for host- and Angerona-critical files."""
        if cls._is_system_path(path):
            return True
        package_root = Path(__file__).resolve(strict=False).parents[1]
        if cls._is_within(path, package_root):
            return True
        try:
            if path.samefile(Path(sys.executable)):
                return True
        except (OSError, RuntimeError, ValueError):
            if os.path.normcase(str(path)) == os.path.normcase(str(Path(sys.executable))):
                return True
        try:
            at_volume_root = path.parent == Path(path.anchor)
        except (OSError, RuntimeError, ValueError):
            at_volume_root = False
        return at_volume_root and path.name.casefold() in _CRITICAL_ROOT_FILES

    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _valid_quarantine_binding(
        self, record: dict[str, Any]
    ) -> tuple[Path, Path] | None:
        details = record.get("details")
        if not isinstance(details, dict):
            return None
        try:
            source = _absolute_path(Path(str(details["quarantine"])))
            destination = _absolute_path(Path(str(details["original"])))
            combat_id = str(record["combat_id"])
            expected_dir = _absolute_path(self.quarantine_root / combat_id)
            target = _absolute_path(Path(str(record["target"])))
        except (KeyError, OSError, RuntimeError, ValueError):
            return None
        if (
            not re.fullmatch(r"combat-[0-9a-f]{12}|startup", combat_id)
            or source.parent != expected_dir
            or not self._is_within(source, self.quarantine_root)
            or destination != target
            or self._is_protected_file(destination)
        ):
            return None
        return source, destination

    @staticmethod
    def _expected_process_start(
        details: dict[str, Any],
    ) -> tuple[bool, float | None]:
        for key in (
            "process_create_time", "pid_create_time", "create_time",
            "process_start_time",
        ):
            value = details.get(key)
            if value in (None, ""):
                continue
            try:
                parsed = float(value)
            except (TypeError, ValueError, OverflowError):
                return True, None
            return True, parsed if math.isfinite(parsed) and parsed > 0 else None
        return False, None

    @staticmethod
    def _remote_ips(event: Event) -> tuple[str, ...]:
        details = event.details or {}
        found: list[str] = []
        for key in _REMOTE_FIELDS:
            raw = details.get(key)
            if not raw:
                continue
            value = str(raw).strip()
            try:
                address = str(ipaddress.ip_address(value.strip("[]")))
            except ValueError:
                # Sensor raddr values use host:port. IPv6 may be bracketed.
                candidate = value
                if value.startswith("[") and "]:" in value:
                    candidate = value[1:value.index("]:")]
                elif value.count(":") == 1:
                    candidate = value.rsplit(":", 1)[0]
                try:
                    address = str(ipaddress.ip_address(candidate))
                except ValueError:
                    continue
            if address not in found:
                found.append(address)
        return tuple(found)

    def _handle(self, event: Event) -> None:
        # Recheck at the execution boundary because tests and internal callers
        # may invoke _handle directly without passing through the queue.
        if self._mutation_blocked:
            return
        response_actions = self._response_actions(event)
        if is_remote_observe_only(event) or response_actions is None:
            return
        if not self._integrity_ok(event):
            self.emit(
                "Adversary Combat refused a tampered detector event.",
                Severity.HIGH,
                disposition="health",
                response_authorized=False,
            )
            return
        policy = self.policy()
        if not policy.enabled:
            return
        disposition = event_disposition(event)
        combat_id = f"combat-{uuid.uuid4().hex[:12]}"
        actions: list[CombatAction] = []
        path = self._event_path(event)
        details = event.details or {}
        pid = details.get("pid")

        if policy.block_network and "block_remote_ip" in response_actions:
            for remote_ip in self._remote_ips(event):
                action = self._block_remote_ip(remote_ip, event, combat_id)
                if action is not None:
                    actions.append(action)
                if self._mutation_blocked:
                    return

        process_action = self._act_on_process(
            pid, policy, event, combat_id, allowed_actions=response_actions
        )
        if process_action is not None:
            actions.extend(process_action)
        if self._mutation_blocked:
            return
        if (
            policy.quarantine_files
            and path
            and "quarantine_file" in response_actions
        ):
            action = self._quarantine_file(path, event, combat_id)
            if action is not None:
                actions.append(action)
        if self._mutation_blocked:
            return

        if disposition == "active":
            now = time.time()
            active_causes = self._record_active_cause(
                event, now, policy.isolation_window_seconds
            )
            isolate_now = (
                policy.isolate_host
                and "isolate_host" in response_actions
                and policy.mode == "maximum"
                and (
                    event.severity >= Severity.CRITICAL
                    or active_causes >= policy.isolation_event_threshold
                )
            )
            if isolate_now:
                action = self._isolate_host(event, combat_id)
                if action is not None:
                    actions.append(action)
        if self._mutation_blocked:
            return

        if policy.activate_honeypots and "activate_honeypots" in response_actions:
            action = self._ensure_honeypots(event=event, combat_id=combat_id)
            if action is not None:
                actions.append(action)
        if self._mutation_blocked:
            return

        succeeded = [action for action in actions if action.status == "applied"]
        postcondition_verified = bool(succeeded) and all(
            action.details.get("postcondition_verified") is True
            for action in succeeded
        )
        summary = ", ".join(action.action for action in succeeded) or "no eligible target"
        self.emit(
            f"Adversary Combat executed {len(succeeded)} action(s) for "
            f"{event.module} {event.severity.label}: {summary}.",
            Severity.HIGH if succeeded else Severity.MEDIUM,
            combat_id=combat_id,
            actions=[action.action for action in succeeded],
            action_ids=[action.action_id for action in succeeded],
            action_succeeded=bool(succeeded),
            mitigated=bool(succeeded),
            postcondition_verified=postcondition_verified,
            reversible_actions=sum(1 for action in succeeded if action.reversible),
            trigger_module=event.module,
            trigger_ts=event.ts,
            path=path or None,
            pid=pid if isinstance(pid, int) else None,
            response_mode=policy.mode,
            queue_request_id=(
                details.get("queue_request_id")
                if isinstance(details.get("queue_request_id"), str)
                else None
            ),
        )

    @staticmethod
    def _canonical_record(value: dict[str, Any]) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")

    def _journal_key(self) -> bytes:
        """Return stable protected journal authority for this data root."""
        if self._journal_key_cache is not None:
            return self._journal_key_cache
        # Production can derive a purpose-separated key from the already
        # protected per-install bus authority. Explicit roots (tests/portable
        # instances) get their own create-only protected key.
        authority = getattr(self._bus, "_authority", None)
        bus_key = getattr(authority, "_key", None)
        if self._explicit_data_root is None and isinstance(bus_key, bytes):
            if len(bus_key) < 32:
                raise JournalIntegrityError("event-bus authority is malformed")
            key = hmac.new(bus_key, _JOURNAL_CONTEXT, hashlib.sha256).digest()
            self._journal_key_cache = key
            return key

        path = self.journal_key_path
        from angerona.core.hardening import (
            ensure_sensitive_parent,
            key_acl_required,
            prepare_sensitive_key,
            secure_sensitive_file,
        )

        required = key_acl_required()
        path.parent.mkdir(parents=True, exist_ok=True)
        ensure_sensitive_parent(path, required=required)
        if path.exists() and not prepare_sensitive_key(path, required=required):
            raise JournalIntegrityError("combat journal key custody failed")
        if not path.exists():
            candidate = secrets.token_bytes(32)
            try:
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                try:
                    with os.fdopen(fd, "w", encoding="ascii") as handle:
                        handle.write(candidate.hex())
                        handle.flush()
                        os.fsync(handle.fileno())
                    secure_sensitive_file(path, required=required)
                except Exception:
                    try:
                        path.unlink()
                    except OSError:
                        pass
                    raise
        try:
            key = bytes.fromhex(path.read_text(encoding="ascii").strip())
        except (OSError, ValueError) as exc:
            raise JournalIntegrityError("combat journal key is unreadable") from exc
        if len(key) != 32:
            raise JournalIntegrityError("combat journal key has invalid length")
        secure_sensitive_file(path, required=required)
        self._journal_key_cache = key
        return key

    def _record_hmac(self, core: dict[str, Any]) -> str:
        return hmac.new(
            self._journal_key(), self._canonical_record(core), hashlib.sha256
        ).hexdigest()

    def _read_journal(
        self, *, strict: bool = False
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Return verified signed records and display-only legacy records."""
        path = self.receipt_path
        if not path.is_file():
            return [], []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            if strict:
                raise JournalIntegrityError("combat journal is unreadable") from exc
            self._journal_error = "combat journal is unreadable"
            return [], []
        signed: list[dict[str, Any]] = []
        legacy: list[dict[str, Any]] = []
        previous = _JOURNAL_GENESIS
        expected_sequence = 1
        signed_started = False
        for line_number, line in enumerate(lines, 1):
            try:
                value = json.loads(line)
            except (TypeError, ValueError):
                if signed_started:
                    self._journal_error = f"broken journal record at line {line_number}"
                    if strict:
                        raise JournalIntegrityError(self._journal_error)
                    break
                continue
            if not isinstance(value, dict):
                continue
            is_signed = (
                value.get("journal_version") == _JOURNAL_VERSION
                and value.get("record_type") in _SIGNED_RECORD_TYPES
            )
            if not is_signed:
                if signed_started:
                    self._journal_error = f"unsigned journal tail at line {line_number}"
                    if strict:
                        raise JournalIntegrityError(self._journal_error)
                    break
                legacy.append({**value, "integrity_status": "legacy-untrusted"})
                continue
            signed_started = True
            supplied = str(value.get("record_hmac") or "")
            core = {key: item for key, item in value.items() if key != "record_hmac"}
            valid = (
                value.get("sequence") == expected_sequence
                and value.get("previous_hmac") == previous
                and bool(re.fullmatch(r"[0-9a-f]{64}", supplied))
                and hmac.compare_digest(supplied, self._record_hmac(core))
            )
            if not valid:
                self._journal_error = f"journal integrity failure at line {line_number}"
                if strict:
                    raise JournalIntegrityError(self._journal_error)
                break
            signed.append(value)
            previous = supplied
            expected_sequence += 1
        if not self._journal_error:
            self._journal_error = ""
        return signed, legacy

    def _append_journal(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Append one authenticated, chained, fsynced journal phase."""
        path = self.receipt_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._receipt_lock:
            records, _legacy = self._read_journal(strict=True)
            previous = (
                str(records[-1]["record_hmac"]) if records else _JOURNAL_GENESIS
            )
            core = {
                **payload,
                "journal_version": _JOURNAL_VERSION,
                "sequence": len(records) + 1,
                "previous_hmac": previous,
            }
            record = {**core, "record_hmac": self._record_hmac(core)}
            encoded = json.dumps(record, sort_keys=True, default=str)
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return record

    def _journal_intent(self, action: CombatAction) -> None:
        self._append_journal({
            **asdict(action),
            "record_type": "intent",
            "status": "pending",
            "intent_at": time.time(),
        })

    def _journal_commit(self, action: CombatAction) -> CombatAction:
        committed = CombatAction(
            **{
                **asdict(action),
                "details": {**action.details, "postcondition_verified": True},
                "status": "applied",
            }
        )
        self._append_journal({
            **asdict(committed),
            "record_type": "commit",
            "committed_at": time.time(),
        })
        return committed

    def _commit_after_mutation(self, action: CombatAction) -> CombatAction | None:
        """Commit a mutation or immediately roll back an explicit orphan.

        The original durable intent remains recoverable if any follow-up write
        also fails.  A successful immediate rollback is closed with a terminal
        failure record; a failed rollback remains non-terminal so startup
        reconciliation will retry it.
        """
        try:
            return self._journal_commit(action)
        except Exception as exc:
            self._journal_error = f"commit failed: {type(exc).__name__}"
            orphan_payload = {
                **asdict(action),
                "record_type": "orphan",
                "status": "orphaned",
                "orphaned_at": time.time(),
                "error": self._journal_error,
                "rollback_state": "pending",
            }
            try:
                orphan_record = self._append_journal(orphan_payload)
            except Exception:
                orphan_record = orphan_payload

            if not action.reversible:
                self._trip_mutation_circuit(
                    orphan_record,
                    f"{self._journal_error}; non-reversible mutation requires review",
                )
                return None

            undo_id = f"undo-{uuid.uuid4().hex[:16]}"
            try:
                self._append_undo_phase(
                    "undo_intent", orphan_record, undo_id, recovery=True
                )
            except Exception:
                pass
            ok, rollback_error = self._undo_record(orphan_record)
            try:
                self._append_undo_phase(
                    "undo_commit" if ok else "undo_failure",
                    orphan_record,
                    undo_id,
                    error=rollback_error,
                    recovery=True,
                )
            except Exception:
                pass
            if ok:
                self._journal_failure(
                    action,
                    f"{self._journal_error}; immediate rollback completed",
                )
            else:
                try:
                    recovery_record = self._append_journal({
                        **orphan_payload,
                        "orphaned_at": time.time(),
                        "rollback_state": "retry_on_startup",
                        "rollback_error": str(rollback_error)[:1000],
                    })
                except Exception:
                    recovery_record = orphan_record
                self._trip_mutation_circuit(
                    recovery_record,
                    f"rollback failed: {rollback_error}",
                )
            return None

    def _trip_mutation_circuit(
        self, record: dict[str, Any], reason: str
    ) -> None:
        """Disarm all later mutation until this exact orphan is recovered."""
        action_id = str(record.get("action_id") or "")
        if action_id:
            self._recovery_required[action_id] = dict(record)
        self._mutation_blocked = True
        self._journal_error = str(reason)[:1000]
        self.set_health(0, "RECOVERY REQUIRED — Combat mutation circuit open")
        self.emit(
            "Adversary Combat disarmed itself after a mutation could not be "
            "durably committed or immediately rolled back. No later response "
            "mutation will run until exact recovery succeeds.",
            Severity.CRITICAL,
            disposition="health",
            response_authorized=False,
            recovery_required=True,
            action_id=action_id or None,
            recovery_error=self._journal_error,
        )

    def _journal_failure(self, action: CombatAction, error: str) -> None:
        try:
            self._append_journal({
                "record_type": "failure",
                "action_id": action.action_id,
                "combat_id": action.combat_id,
                "action": action.action,
                "failed_at": time.time(),
                "status": "failed",
                "error": str(error)[:1000],
            })
        except Exception:
            # The original journal exception remains the authoritative failure.
            pass

    @staticmethod
    def _action(
        action: str,
        target: str,
        event: Event,
        combat_id: str,
        *,
        reversible: bool,
        details: dict[str, Any],
    ) -> CombatAction:
        return CombatAction(
            action_id=f"act-{uuid.uuid4().hex[:16]}",
            combat_id=combat_id,
            action=action,
            applied_at=time.time(),
            reversible=reversible,
            target=target,
            details=details,
            trigger_module=event.module,
            trigger_ts=event.ts,
        )

    def _quarantine_file(
        self, raw_path: str, event: Event, combat_id: str
    ) -> CombatAction | None:
        action: CombatAction | None = None
        try:
            source = _absolute_path(Path(raw_path).expanduser())
            quarantine = _absolute_path(self.quarantine_root)
            if quarantine == source or quarantine in source.parents:
                return None
            if self._is_protected_file(source):
                return None
            destination_dir = quarantine / combat_id
            destination = destination_dir / source.name
            if destination.exists():
                destination = destination_dir / f"{uuid.uuid4().hex[:8]}-{source.name}"
            with _PinnedFileMove(source) as pinned:
                digest = pinned.sha256()
                planned_strategy = (
                    "cross_volume_copy"
                    if pinned.crosses_volume(destination)
                    else "rename"
                )
                action = self._action(
                    "quarantine_file",
                    str(source),
                    event,
                    combat_id,
                    reversible=True,
                    details={
                        "original": str(source),
                        "quarantine": str(destination),
                        "sha256": digest,
                        "file_identity": pinned.identity,
                        "source_identity": pinned.identity,
                        "move_strategy": planned_strategy,
                    },
                )
                self._journal_intent(action)
                destination_identity = pinned.rename_to(destination)
                if pinned.sha256() != digest:
                    self._journal_failure(action, "quarantine postcondition failed")
                    return None
                action = CombatAction(**{
                    **asdict(action),
                    "details": {
                        **action.details,
                        "file_identity": destination_identity,
                        "move_strategy": pinned.move_strategy,
                    },
                })
            return self._commit_after_mutation(action)
        except (OSError, RuntimeError, ValueError, JournalIntegrityError) as exc:
            if action is not None:
                self._journal_failure(action, f"{type(exc).__name__}: {exc}")
            return None

    def _act_on_process(
        self,
        pid: object,
        policy: CombatPolicy,
        event: Event,
        combat_id: str,
        *,
        allowed_actions: frozenset[str] | None = None,
    ) -> list[CombatAction] | None:
        if not isinstance(pid, int) or pid <= 0 or psutil is None:
            return None
        # Killing the response engine itself ends autonomous defense.  Parent
        # exclusion prevents a child detector from terminating its launcher.
        if pid in {os.getpid(), os.getppid()}:
            return None
        actions: list[CombatAction] = []
        try:
            process = psutil.Process(pid)
            created = float(process.create_time())
            name = process.name()
            exe = process.exe() or ""
        except Exception:
            return None
        details = event.details if isinstance(event.details, dict) else {}
        start_supplied, expected_start = self._expected_process_start(details)
        if start_supplied and expected_start is None:
            return None
        if expected_start is not None and abs(created - expected_start) > 0.001:
            return None
        if name.casefold() in _SYSTEM32_NEVER_CONTAIN:
            return None
        if exe and self._is_system_path(Path(exe)):
            return None
        # Close the check/use window as far as psutil permits. A reused PID must
        # never inherit a response intended for the prior process instance.
        try:
            if abs(float(process.create_time()) - created) > 0.001:
                return None
        except Exception:
            return None
        allowed = allowed_actions or _CONTRACT_ACTIONS
        if policy.block_network and exe and "isolate_program" in allowed:
            action = self._block_program(exe, pid, created, event, combat_id)
            if action is not None:
                actions.append(action)
        action: CombatAction | None = None
        try:
            exact_suspend_only = (
                "suspend_process" in allowed and "terminate_process" not in allowed
            )
            if (
                exact_suspend_only
                or policy.process_action == "suspend"
                or policy.mode == "contain"
            ):
                if "suspend_process" not in allowed:
                    return actions
                action = self._action(
                    "suspend_process",
                    f"{name} ({pid})",
                    event,
                    combat_id,
                    reversible=True,
                    details={
                        "pid": pid,
                        "create_time": created,
                        "name": name,
                    },
                )
                self._journal_intent(action)
                process.suspend()
                time.sleep(0.05)
                verified = process.status() == getattr(psutil, "STATUS_STOPPED", "stopped")
                if not verified:
                    self._journal_failure(action, "process suspend postcondition failed")
                    return actions
            else:
                if "terminate_process" not in allowed:
                    return actions
                action = self._action(
                    "terminate_process",
                    f"{name} ({pid})",
                    event,
                    combat_id,
                    reversible=False,
                    details={
                        "pid": pid,
                        "create_time": created,
                        "name": name,
                    },
                )
                self._journal_intent(action)
                process.kill()
                try:
                    process.wait(timeout=3)
                except Exception:
                    pass
                verified = not process.is_running()
                if not verified:
                    self._journal_failure(action, "process termination postcondition failed")
                    return actions
            committed = self._commit_after_mutation(action)
            if committed is not None:
                actions.append(committed)
        except Exception as exc:
            if action is not None:
                self._journal_failure(action, f"{type(exc).__name__}: {exc}")
        return actions

    def _run_firewall(self, arguments: list[str]) -> bool:
        if os.name != "nt":
            return False
        try:
            from angerona.core.win import run_hidden

            result = run_hidden(
                ["netsh", "advfirewall", "firewall", *arguments],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if int(getattr(result, "returncode", 1)) != 0:
                return False
            rule_name = next(
                (value[5:] for value in arguments if value.casefold().startswith("name=")),
                "",
            )
            if not rule_name:
                return True
            operation = tuple(value.casefold() for value in arguments[:2])
            if operation == ("add", "rule"):
                return self._firewall_rule_exists(rule_name)
            if operation == ("delete", "rule"):
                return not self._firewall_rule_exists(rule_name)
            return True
        except Exception:
            return False

    @staticmethod
    def _firewall_rule_exists(rule_name: str) -> bool:
        if os.name != "nt" or not rule_name:
            return False
        try:
            from angerona.core.win import run_hidden

            result = run_hidden(
                [
                    "netsh", "advfirewall", "firewall", "show", "rule",
                    f"name={rule_name}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            output = (
                str(getattr(result, "stdout", "") or "")
                + "\n"
                + str(getattr(result, "stderr", "") or "")
            ).casefold()
            return (
                int(getattr(result, "returncode", 1)) == 0
                and rule_name.casefold() in output
                and "no rules match" not in output
            )
        except Exception:
            return False

    @staticmethod
    def _managed_rule(action: str, rule: str) -> bool:
        pattern = _MANAGED_RULE_PATTERNS.get(action)
        return pattern is not None and pattern.fullmatch(rule) is not None

    @classmethod
    def _valid_rule_set(cls, action: str, rules: list[str]) -> bool:
        if not rules or len(set(rules)) != len(rules):
            return False
        if not all(cls._managed_rule(action, rule) for rule in rules):
            return False
        if action in {"block_remote_ip", "isolate_host"}:
            return (
                len(rules) == 2
                and {rule.rsplit("-", 1)[-1] for rule in rules} == {"in", "out"}
                and len({rule.rsplit("-", 1)[0] for rule in rules}) == 1
            )
        return action == "isolate_program" and len(rules) == 1

    @staticmethod
    def _combat_action_from_record(record: dict[str, Any]) -> CombatAction | None:
        fields = {
            "action_id", "combat_id", "action", "applied_at", "reversible",
            "target", "details", "trigger_module", "trigger_ts", "status",
        }
        try:
            return CombatAction(**{key: record[key] for key in fields})
        except (KeyError, TypeError, ValueError):
            return None

    def _intent_effect_present(self, record: dict[str, Any]) -> bool:
        action = str(record.get("action") or "")
        details = record.get("details") if isinstance(record.get("details"), dict) else {}
        try:
            if action == "quarantine_file":
                binding = self._valid_quarantine_binding(record)
                return binding is not None and binding[0].is_file()
            if action in {"block_remote_ip", "isolate_program", "isolate_host"}:
                rules = [str(value) for value in details.get("rules", []) if value]
                return self._valid_rule_set(action, rules) and any(
                    self._firewall_rule_exists(rule) for rule in rules
                )
            if action == "suspend_process" and psutil is not None:
                process = psutil.Process(int(details["pid"]))
                return (
                    abs(float(process.create_time()) - float(details["create_time"]))
                    <= 0.001
                    and process.status()
                    == getattr(psutil, "STATUS_STOPPED", "stopped")
                )
            if action == "activate_honeypots":
                module = (
                    getattr(self._manager, "modules", {}).get("Smart Deception")
                    if self._manager else None
                )
                return module is not None and module.status == "running"
        except Exception:
            return False
        return False

    def _recover_orphaned_journal(self) -> None:
        """Rollback crash-interrupted reversible work before accepting events."""
        records, _legacy = self._read_journal(strict=True)
        intents: dict[str, dict[str, Any]] = {}
        terminal: set[str] = set()
        commits: dict[str, dict[str, Any]] = {}
        undo_intents: dict[str, dict[str, Any]] = {}
        undo_terminal: set[str] = set()
        for record in records:
            record_type = record.get("record_type")
            action_id = str(record.get("action_id") or "")
            if record_type == "intent" and action_id:
                intents[action_id] = record
            elif record_type in {"commit", "failure"} and action_id:
                terminal.add(action_id)
                if record_type == "commit":
                    commits[action_id] = record
            elif record_type == "undo_intent":
                undo_intents[str(record.get("undo_id") or "")] = record
            elif record_type in {"undo_commit", "undo_failure"}:
                undo_terminal.add(str(record.get("undo_id") or ""))

        for action_id, record in intents.items():
            if action_id in terminal:
                continue
            action = self._combat_action_from_record(record)
            if action is None:
                raise JournalIntegrityError("signed intent schema is invalid")
            if action.reversible and self._intent_effect_present(record):
                undo_id = f"undo-{uuid.uuid4().hex[:16]}"
                self._append_undo_phase(
                    "undo_intent", record, undo_id, recovery=True
                )
                ok, error = self._undo_record(record)
                self._append_undo_phase(
                    "undo_commit" if ok else "undo_failure",
                    record,
                    undo_id,
                    error=error,
                    recovery=True,
                )
                if not ok:
                    self._trip_mutation_circuit(
                        record,
                        f"orphan recovery failed: {error}",
                    )
                    raise JournalIntegrityError(
                        f"recovery required for {action_id}: {error}"
                    )
                self._journal_failure(action, "orphaned intent safely rolled back")
            else:
                reason = (
                    "orphaned non-reversible intent requires manual verification"
                    if not action.reversible
                    else "orphaned intent had no observed postcondition"
                )
                self._journal_failure(action, reason)

        # Reload after action-intent recovery, then finish any crash-interrupted
        # undo whose mutation may already be complete. Execution is idempotent.
        records, _legacy = self._read_journal(strict=True)
        commits = {
            str(record.get("action_id")): record
            for record in records
            if record.get("record_type") == "commit"
        }
        undo_terminal = {
            str(record.get("undo_id") or "")
            for record in records
            if record.get("record_type") in {"undo_commit", "undo_failure"}
        }
        for undo in records:
            if undo.get("record_type") != "undo_intent":
                continue
            undo_id = str(undo.get("undo_id") or "")
            if not undo_id or undo_id in undo_terminal:
                continue
            record = commits.get(str(undo.get("undo_of") or ""))
            if record is None:
                # Recovery undo for an uncommitted action was already handled
                # above and closed by its action failure record.
                continue
            if undo.get("bound_record_hmac") != record.get("record_hmac"):
                raise JournalIntegrityError("undo intent binding is invalid")
            ok, error = self._undo_record(record)
            self._append_undo_phase(
                "undo_commit" if ok else "undo_failure",
                record,
                undo_id,
                error=error,
                recovery=True,
            )

    def _reconcile_state(self) -> bool:
        """Rebuild in-memory response state from still-applied verified receipts."""
        self._host_isolated = False
        self._blocked_ips.clear()
        self._blocked_programs.clear()
        self._mutation_blocked = False
        self._recovery_required.clear()
        try:
            self._recover_orphaned_journal()
        except JournalIntegrityError as exc:
            self._journal_error = str(exc)
            self.set_health(0, "combat journal integrity failure")
            return False
        for record in self.list_actions(limit=500):
            if (
                record.get("integrity_status") != "verified"
                or record.get("undone")
                or record.get("status") != "applied"
            ):
                continue
            action = str(record.get("action") or "")
            details = record.get("details")
            if not isinstance(details, dict):
                continue
            rules = [str(value) for value in details.get("rules", []) if value]
            if (
                not rules
                or not self._valid_rule_set(action, rules)
                or not all(self._firewall_rule_exists(rule) for rule in rules)
            ):
                continue
            if action == "isolate_host":
                self._host_isolated = True
            elif action == "block_remote_ip":
                remote_ip = str(details.get("remote_ip") or "")
                try:
                    self._blocked_ips.add(str(ipaddress.ip_address(remote_ip)))
                except ValueError:
                    continue
            elif action == "isolate_program":
                executable = str(details.get("exe") or "")
                if executable:
                    self._blocked_programs.add(
                        os.path.normcase(os.path.abspath(executable))
                    )
        return True

    def _pending_recovery_records(self) -> dict[str, dict[str, Any]]:
        """Return authenticated mutation intents that have no terminal phase."""
        signed, _legacy = self._read_journal(strict=True)
        pending: dict[str, dict[str, Any]] = {}
        terminal: set[str] = set()
        for record in signed:
            action_id = str(record.get("action_id") or "")
            if not action_id:
                continue
            record_type = str(record.get("record_type") or "")
            if record_type == "intent":
                pending[action_id] = record
            elif record_type == "orphan" and action_id in pending:
                pending[action_id] = record
            elif record_type in {"commit", "failure"}:
                terminal.add(action_id)
        return {
            action_id: record
            for action_id, record in pending.items()
            if action_id not in terminal
        }

    def _block_remote_ip(
        self, remote_ip: str, event: Event, combat_id: str
    ) -> CombatAction | None:
        if remote_ip in self._blocked_ips:
            return None
        rule = f"Angerona-Combat-IP-{uuid.uuid4().hex[:12]}"
        expected = [f"{rule}-out", f"{rule}-in"]
        action = self._action(
            "block_remote_ip",
            remote_ip,
            event,
            combat_id,
            reversible=True,
            details={"remote_ip": remote_ip, "rules": expected},
        )
        try:
            self._journal_intent(action)
        except JournalIntegrityError:
            return None
        applied: list[str] = []
        for direction in ("out", "in"):
            if self._run_firewall([
                "add", "rule", f"name={rule}-{direction}", f"dir={direction}",
                "action=block", f"remoteip={remote_ip}", "enable=yes",
            ]):
                applied.append(f"{rule}-{direction}")
        if len(applied) != 2:
            for partial in applied:
                self._run_firewall(["delete", "rule", f"name={partial}"])
            self._journal_failure(action, "firewall block was incomplete and rolled back")
            return None
        self._blocked_ips.add(remote_ip)
        return self._commit_after_mutation(action)

    def _block_program(
        self,
        exe: str,
        pid: int,
        create_time: float,
        event: Event,
        combat_id: str,
    ) -> CombatAction | None:
        program_key = os.path.normcase(os.path.abspath(exe))
        if program_key in self._blocked_programs:
            return None
        rule = f"Angerona-Combat-Program-{pid}-{uuid.uuid4().hex[:8]}"
        action = self._action(
            "isolate_program",
            exe,
            event,
            combat_id,
            reversible=True,
            details={
                "pid": pid,
                "create_time": create_time,
                "exe": exe,
                "rules": [rule],
            },
        )
        try:
            self._journal_intent(action)
        except JournalIntegrityError:
            return None
        if not self._run_firewall([
            "add", "rule", f"name={rule}", "dir=out", "action=block",
            f"program={exe}", "enable=yes",
        ]):
            self._journal_failure(action, "program firewall postcondition failed")
            return None
        identity_matches = False
        try:
            current = psutil.Process(pid) if psutil is not None else None
            current_exe = current.exe() if current is not None else ""
            identity_matches = bool(
                current is not None
                and abs(float(current.create_time()) - float(create_time)) <= 0.001
                and os.path.normcase(os.path.abspath(current_exe)) == program_key
            )
        except Exception:
            identity_matches = False
        if not identity_matches:
            rolled_back = self._run_firewall([
                "delete", "rule", f"name={rule}",
            ])
            self._journal_failure(
                action,
                "program identity changed after firewall mutation; rule "
                + ("rolled back" if rolled_back else "rollback failed"),
            )
            return None
        self._blocked_programs.add(program_key)
        return self._commit_after_mutation(action)

    def _isolate_host(self, event: Event, combat_id: str) -> CombatAction | None:
        if self._host_isolated:
            return None
        base = f"Angerona-Combat-Host-{uuid.uuid4().hex[:10]}"
        expected = [f"{base}-out", f"{base}-in"]
        action = self._action(
            "isolate_host",
            "all remote network traffic",
            event,
            combat_id,
            reversible=True,
            details={"rules": expected},
        )
        try:
            self._journal_intent(action)
        except JournalIntegrityError:
            return None
        rules: list[str] = []
        for direction in ("out", "in"):
            name = f"{base}-{direction}"
            if self._run_firewall([
                "add", "rule", f"name={name}", f"dir={direction}",
                "action=block", "remoteip=any", "enable=yes",
            ]):
                rules.append(name)
        if len(rules) != 2:
            for partial in rules:
                self._run_firewall(["delete", "rule", f"name={partial}"])
            self._journal_failure(action, "host isolation was incomplete and rolled back")
            return None
        self._host_isolated = True
        return self._commit_after_mutation(action)

    def _ensure_honeypots(
        self, event: Event | None = None, combat_id: str = "startup"
    ) -> CombatAction | None:
        manager = self._manager
        module = getattr(manager, "modules", {}).get("Smart Deception") if manager else None
        if module is None or module.status == "running":
            return None
        trigger = event or Event(
            self.name,
            "startup deception policy",
            Severity.INFO,
            time.time(),
            {"response_authorized": False},
        )
        action = self._action(
            "activate_honeypots",
            "Smart Deception",
            trigger,
            combat_id,
            reversible=True,
            details={"module": "Smart Deception"},
        )
        try:
            self._journal_intent(action)
            module.start()
            self._honeypot_started_by_combat = True
            if module.status != "running":
                self._journal_failure(action, "deception start postcondition failed")
                return None
        except Exception as exc:
            self._journal_failure(action, f"{type(exc).__name__}: {exc}")
            return None
        if event is None:
            # Startup actions are journalled too; callers do not need to count
            # them as a response to a detector event.
            self._commit_after_mutation(action)
            return None
        return self._commit_after_mutation(action)

    def list_actions(self, limit: int = 100) -> list[dict[str, Any]]:
        signed, legacy = self._read_journal()
        commits: dict[str, dict[str, Any]] = {}
        pending: dict[str, dict[str, Any]] = {}
        terminal: set[str] = set()
        undone: set[str] = set()
        for record in signed:
            record_type = record.get("record_type")
            action_id = str(record.get("action_id") or "")
            if record_type == "intent" and action_id:
                pending[action_id] = record
            elif record_type == "orphan" and action_id in pending:
                pending[action_id] = record
            elif record_type == "commit" and action_id:
                terminal.add(action_id)
                commits[action_id] = record
            elif record_type == "failure" and action_id:
                terminal.add(action_id)
            elif record_type == "undo_commit" and record.get("status") == "undone":
                undone.add(str(record.get("undo_of") or ""))
        trusted = [
            {
                **record,
                "undone": action_id in undone,
                "integrity_status": "verified",
            }
            for action_id, record in commits.items()
        ]
        recovery_actions = [
            {
                **record,
                "record_type": "recovery_required",
                "status": "recovery_required",
                "recovery_required": True,
                "undone": False,
                "integrity_status": "verified",
            }
            for action_id, record in pending.items()
            if action_id not in terminal
        ]
        # Historical unsigned lines remain visible for migration/forensics but
        # can never be selected by undo or startup reconciliation.
        legacy_actions = [
            {
                **record,
                "undone": False,
                "reversible": False,
                "integrity_status": "legacy-untrusted",
            }
            for record in legacy
            if record.get("action_id") and record.get("action")
        ]
        combined = trusted + recovery_actions + legacy_actions
        return combined[-max(1, int(limit)):][::-1]

    def _trusted_action(self, action_id: str) -> tuple[dict[str, Any] | None, bool]:
        signed, _legacy = self._read_journal(strict=True)
        record: dict[str, Any] | None = None
        undone = False
        for item in signed:
            if item.get("record_type") == "commit" and item.get("action_id") == action_id:
                record = item
            elif (
                item.get("record_type") == "undo_commit"
                and item.get("undo_of") == action_id
                and item.get("status") == "undone"
            ):
                undone = True
        return record, undone

    def _append_undo_phase(
        self,
        phase: str,
        record: dict[str, Any],
        undo_id: str,
        *,
        error: str = "",
        recovery: bool = False,
    ) -> None:
        status = {
            "undo_intent": "pending",
            "undo_commit": "undone",
            "undo_failure": "undo_failed",
        }[phase]
        self._append_journal({
            "record_type": phase,
            "undo_id": undo_id,
            "undo_of": str(record.get("action_id") or ""),
            "action": str(record.get("action") or ""),
            "phase_at": time.time(),
            "status": status,
            "error": str(error)[:1000],
            "recovery": bool(recovery),
            "bound_record_hmac": str(record.get("record_hmac") or ""),
        })

    def _undo_record(self, record: dict[str, Any]) -> tuple[bool, str]:
        """Execute one exact, revalidated reverse mutation idempotently."""
        action = str(record.get("action") or "")
        details = record.get("details") if isinstance(record.get("details"), dict) else {}
        try:
            if action == "quarantine_file":
                binding = self._valid_quarantine_binding(record)
                if binding is None:
                    return False, "quarantine binding failed validation"
                source, destination = binding
                expected_hash = str(details.get("sha256") or "")
                expected_identity = str(details.get("file_identity") or "")
                move_strategy = str(details.get("move_strategy") or "rename")
                if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                    return False, "quarantine digest is invalid"
                if not re.fullmatch(
                    r"(?:windows:[0-9a-f]{8}:[0-9a-f]{16}|posix:[0-9]+:[0-9]+)",
                    expected_identity,
                ):
                    return False, "quarantine identity is invalid"
                if source.exists():
                    # Pin the exact quarantined object before validating its
                    # receipt identity and content. The handle/dirfd remains
                    # authoritative through the non-replacing rename.
                    with _PinnedFileMove(source) as pinned:
                        pending_cross_volume = (
                            record.get("record_type") == "intent"
                            and move_strategy == "cross_volume_copy"
                        )
                        if (
                            pinned.identity != expected_identity
                            and not pending_cross_volume
                        ):
                            return False, "quarantined file identity no longer matches receipt"
                        if pinned.sha256() != expected_hash:
                            return False, "quarantined content no longer matches receipt"
                        if destination.exists() or self._is_protected_file(destination):
                            return False, "original target is occupied or protected"
                        restored_identity = pinned.rename_to(destination)
                        if pinned.sha256() != expected_hash:
                            return False, "quarantine restore postcondition failed"
                else:
                    restored_identity = expected_identity
                if source.exists():
                    return False, "quarantine restore left the receipt-bound source in place"
                try:
                    with _PinnedFileMove(destination) as restored:
                        if (
                            (
                                restored.identity == restored_identity
                                or move_strategy == "cross_volume_copy"
                            )
                            and restored.sha256() == expected_hash
                        ):
                            return True, ""
                except OSError:
                    pass
                return False, "quarantine restore postcondition failed"

            if action == "suspend_process" and psutil is not None:
                pid = int(details["pid"])
                created = float(details["create_time"])
                process = psutil.Process(pid)
                if abs(float(process.create_time()) - created) > 0.001:
                    return False, "PID was reused; process was not resumed"
                stopped = getattr(psutil, "STATUS_STOPPED", "stopped")
                if process.status() == stopped:
                    process.resume()
                if (
                    abs(float(process.create_time()) - created) <= 0.001
                    and process.status() != stopped
                ):
                    return True, ""
                return False, "process resume postcondition failed"

            if action in {"block_remote_ip", "isolate_program", "isolate_host"}:
                rules = [str(value) for value in details.get("rules", []) if value]
                if not self._valid_rule_set(action, rules):
                    return False, "receipt contains an invalid managed firewall rule set"
                if action == "block_remote_ip":
                    remote_ip = str(ipaddress.ip_address(str(details.get("remote_ip") or "")))
                    if remote_ip != str(record.get("target") or ""):
                        return False, "remote address binding does not match"
                if action == "isolate_program":
                    executable = os.path.normcase(os.path.abspath(str(details.get("exe") or "")))
                    if executable != os.path.normcase(
                        os.path.abspath(str(record.get("target") or ""))
                    ):
                        return False, "program binding does not match"
                for rule in rules:
                    if self._firewall_rule_exists(rule) and not self._run_firewall(
                        ["delete", "rule", f"name={rule}"]
                    ):
                        return False, f"managed firewall rule remains: {rule}"
                if any(self._firewall_rule_exists(rule) for rule in rules):
                    return False, "one or more managed firewall rules remain"
                if action == "isolate_host":
                    self._host_isolated = False
                elif action == "block_remote_ip":
                    self._blocked_ips.discard(str(details.get("remote_ip") or ""))
                else:
                    self._blocked_programs.discard(
                        os.path.normcase(os.path.abspath(str(details.get("exe") or "")))
                    )
                return True, ""

            if action == "activate_honeypots":
                if (
                    details.get("module") != "Smart Deception"
                    or record.get("target") != "Smart Deception"
                ):
                    return False, "deception module binding does not match"
                manager = self._manager
                module = (
                    getattr(manager, "modules", {}).get("Smart Deception")
                    if manager else None
                )
                if module is None:
                    return False, "Smart Deception module is unavailable"
                if module.status == "running":
                    module.stop()
                if module.status == "running":
                    return False, "Smart Deception stop postcondition failed"
                self._honeypot_started_by_combat = False
                return True, ""
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"
        return False, "unsupported undo action"

    def undo_last(self) -> dict[str, Any]:
        for record in self.list_actions(limit=500):
            if record.get("reversible") is True and not record.get("undone"):
                return self.undo_action(str(record.get("action_id")))
        return {"ok": False, "error": "no reversible combat action is pending"}

    def undo_all(self) -> dict[str, Any]:
        """Undo every still-applied reversible action, newest first."""
        results = []
        for record in self.list_actions(limit=5000):
            if record.get("reversible") is not True or record.get("undone"):
                continue
            results.append(self.undo_action(str(record.get("action_id"))))
        failures = [result for result in results if not result.get("ok")]
        return {
            "ok": not failures,
            "attempted": len(results),
            "undone": len(results) - len(failures),
            "failures": failures,
        }

    def undo_action(self, action_id: str) -> dict[str, Any]:
        try:
            record, undone = self._trusted_action(action_id)
        except JournalIntegrityError as exc:
            return {"ok": False, "error": str(exc)}
        recovery = False
        if record is None:
            try:
                record = self._pending_recovery_records().get(action_id)
            except JournalIntegrityError as exc:
                return {"ok": False, "error": str(exc)}
            if record is None:
                return {"ok": False, "error": "verified action not found"}
            recovery = True
        if undone:
            return {"ok": True, "already_undone": True, "action_id": action_id}
        if record.get("reversible") is not True:
            return {"ok": False, "error": "action is not reversible"}
        action = str(record.get("action") or "")
        undo_id = f"undo-{uuid.uuid4().hex[:16]}"
        try:
            self._append_undo_phase(
                "undo_intent", record, undo_id, recovery=recovery
            )
        except Exception as exc:
            return {"ok": False, "action_id": action_id, "error": str(exc)}
        ok, error = self._undo_record(record)
        try:
            self._append_undo_phase(
                "undo_commit" if ok else "undo_failure",
                record,
                undo_id,
                error=error,
                recovery=recovery,
            )
        except Exception as exc:
            # An orphan undo intent is deliberately left for restart recovery.
            return {
                "ok": False,
                "action_id": action_id,
                "action": action,
                "error": f"undo journal commit failed: {type(exc).__name__}",
            }
        if ok:
            if recovery:
                action_value = self._combat_action_from_record(record)
                if action_value is None:
                    return {
                        "ok": False,
                        "action_id": action_id,
                        "action": action,
                        "error": "recovery record schema is invalid",
                    }
                self._journal_failure(
                    action_value,
                    "recovery-required orphan manually rolled back",
                )
                self._recovery_required.pop(action_id, None)
                if not self._pending_recovery_records():
                    self._mutation_blocked = False
                    self._journal_error = ""
                    self.set_health(100, "standing authority armed")
            self.emit(
                f"Adversary Combat undo completed: {action} ({action_id}).",
                Severity.INFO,
                action="undo",
                undo_of=action_id,
                action_succeeded=True,
            )
        return {"ok": ok, "action_id": action_id, "action": action, "error": error}


def register() -> AdversaryCombat:
    return AdversaryCombat()
