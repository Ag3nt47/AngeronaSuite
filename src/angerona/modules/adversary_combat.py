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

import copy
import ipaddress
import hashlib
import hmac
import json
import math
import os
import platform
import queue
import re
import secrets
import stat
import sys
import threading
import time
import uuid
from collections import deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from angerona.core.authorization import AuthorizationDecision, AuthorizationPolicy
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
    "undo_failure", "orphan", "recovery_challenge", "operator_disposition",
})
_RECOVERY_AUTHORIZATION_SCOPE = "response/adversary-combat"
_RECOVERY_AUTHORIZATION_MAX_AGE_S = 300.0
_RECOVERY_DISPOSITIONS = frozenset({"confirmed_applied", "confirmed_not_applied"})
_MUTATION_GENERATION = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_RECOVERY_ANCHOR_SCHEMA = 2
_RECOVERY_ANCHOR_CONTEXT = b"angerona-adversary-combat-recovery-anchor-v1"
_RECOVERY_WITNESS_SCHEMA = 1
_RECOVERY_WITNESS_CONTEXT = b"angerona-adversary-combat-recovery-witness-v1"
_MAX_RECOVERY_ANCHOR_BYTES = 16 * 1024
_MAX_RECOVERY_WITNESS_BYTES = 16 * 1024
_MAX_JOURNAL_BYTES = 32 * 1024 * 1024
_MAX_JOURNAL_LINE_BYTES = 64 * 1024
_MAX_JOURNAL_RECORDS = 32_768
_MAX_JOURNAL_JSON_DEPTH = 16
# An intent may need a commit, orphan, undo intent/terminal, final failure and
# one recovery receipt. Reserve every one of those slots at the admission
# boundary so accounting cannot run out only after the host effect.
_JOURNAL_MUTATION_RESERVE_RECORDS = 8
_JOURNAL_UNDO_RESERVE_RECORDS = 3
_RECOVERY_CHALLENGE_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_RECOVERY_ANCHOR_FIELDS = frozenset({
    "schema", "host_binding", "install_epoch", "challenge_counter",
    "active_action_id", "active_challenge_sequence", "active_challenge_nonce",
    "last_journal_sequence", "last_journal_hmac", "consumed_terminal_sequence",
    "record_hmac",
})
_RECOVERY_WITNESS_FIELDS = frozenset({
    "schema", "host_binding", "authority_fingerprint", "install_epoch",
    "last_journal_sequence", "last_journal_hmac", "anchor_record_hmac",
    "record_hmac",
})
_RECOVERY_CHALLENGE_FIELDS = frozenset({
    "record_type", "action_id", "combat_id", "action", "status",
    "disposition", "reason_digest", "bound_record_hmac",
    "bound_record_sequence", "mutation_generation", "challenge_counter",
    "challenge_nonce", "install_epoch", "issued_at", "journal_version",
    "sequence", "previous_hmac", "record_hmac",
})
_OPERATOR_DISPOSITION_FIELDS = frozenset({
    "record_type", "action_id", "combat_id", "action", "status",
    "disposition", "reason", "reason_digest", "disposed_at",
    "operator_principal", "authorization_request_id",
    "authorization_request_digest", "authorization_policy_hash",
    "authorization_resource", "authorization_decision", "bound_record_hmac",
    "bound_record_sequence", "mutation_generation", "bound_challenge_hmac",
    "bound_challenge_sequence", "bound_challenge_counter",
    "bound_challenge_nonce", "install_epoch", "journal_version", "sequence",
    "previous_hmac", "record_hmac",
})
_JOURNAL_CHAIN_FIELDS = frozenset({
    "journal_version", "sequence", "previous_hmac", "record_hmac",
})
_ACTION_RECORD_FIELDS = frozenset({
    "action_id", "combat_id", "action", "applied_at", "reversible",
    "target", "details", "trigger_module", "trigger_ts", "status",
})
_JOURNAL_FIELDS_BY_TYPE: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "intent": (
        _JOURNAL_CHAIN_FIELDS | _ACTION_RECORD_FIELDS | {"record_type", "intent_at"},
        _JOURNAL_CHAIN_FIELDS | _ACTION_RECORD_FIELDS | {"record_type", "intent_at"},
    ),
    "commit": (
        _JOURNAL_CHAIN_FIELDS
        | _ACTION_RECORD_FIELDS
        | {"record_type", "committed_at"},
        _JOURNAL_CHAIN_FIELDS
        | _ACTION_RECORD_FIELDS
        | {"record_type", "committed_at"},
    ),
    "failure": (
        _JOURNAL_CHAIN_FIELDS
        | {
            "record_type", "action_id", "combat_id", "action", "failed_at",
            "status", "error",
        },
        _JOURNAL_CHAIN_FIELDS
        | {
            "record_type", "action_id", "combat_id", "action", "failed_at",
            "status", "error",
        },
    ),
    "orphan": (
        _JOURNAL_CHAIN_FIELDS
        | _ACTION_RECORD_FIELDS
        | {"record_type", "orphaned_at", "error", "rollback_state"},
        _JOURNAL_CHAIN_FIELDS
        | _ACTION_RECORD_FIELDS
        | {
            "record_type", "orphaned_at", "error", "rollback_state",
            "mutation_started", "rollback_error",
        },
    ),
    "recovery_challenge": (
        _RECOVERY_CHALLENGE_FIELDS,
        _RECOVERY_CHALLENGE_FIELDS,
    ),
    "operator_disposition": (
        _OPERATOR_DISPOSITION_FIELDS,
        _OPERATOR_DISPOSITION_FIELDS,
    ),
}
_UNDO_RECORD_FIELDS = (
    _JOURNAL_CHAIN_FIELDS
    | {
        "record_type", "undo_id", "undo_of", "action", "phase_at", "status",
        "error", "recovery", "bound_record_hmac",
    }
)
for _undo_record_type in ("undo_intent", "undo_commit", "undo_failure"):
    _JOURNAL_FIELDS_BY_TYPE[_undo_record_type] = (
        _UNDO_RECORD_FIELDS,
        _UNDO_RECORD_FIELDS,
    )
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

_COMBAT_WRITER_LEASES_GUARD = threading.Lock()
_COMBAT_WRITER_LEASES: dict[str, threading.RLock] = {}
_COMBAT_WRITER_LEASE_LOCAL = threading.local()


def _shared_combat_writer_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path.resolve(strict=False)))
    with _COMBAT_WRITER_LEASES_GUARD:
        return _COMBAT_WRITER_LEASES.setdefault(key, threading.RLock())


@contextmanager
def _exclusive_combat_writer_lease(path: Path) -> Iterator[None]:
    """Take one re-entrant process lock plus a non-blocking OS file lease."""
    key = os.path.normcase(str(path.resolve(strict=False)))
    lock = _shared_combat_writer_lock(path)
    if not lock.acquire(blocking=False):
        raise JournalIntegrityError("combat journal writer lease is already held")
    depths = getattr(_COMBAT_WRITER_LEASE_LOCAL, "depths", None)
    if depths is None:
        depths = {}
        _COMBAT_WRITER_LEASE_LOCAL.depths = depths
    depth = int(depths.get(key, 0))
    if depth:
        depths[key] = depth + 1
        try:
            yield
        finally:
            depths[key] -= 1
            lock.release()
        return

    descriptor: int | None = None
    windows_locked = False
    posix_locked = False
    try:
        from angerona.core.hardening import ensure_sensitive_parent, key_acl_required

        required = key_acl_required()
        path.parent.mkdir(parents=True, exist_ok=True)
        ensure_sensitive_parent(path, required=required)
        descriptor = os.open(
            path,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        info = os.fstat(descriptor)
        attributes = int(getattr(info, "st_file_attributes", 0))
        if (
            not stat.S_ISREG(info.st_mode)
            or int(getattr(info, "st_nlink", 1)) != 1
            or bool(attributes & 0x400)
            or info.st_size > 1
        ):
            raise JournalIntegrityError("combat journal writer lease object is unsafe")
        if info.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        current = os.lstat(path)
        current_attributes = int(getattr(current, "st_file_attributes", 0))
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or bool(current_attributes & 0x400)
            or int(getattr(current, "st_nlink", 1)) != 1
            or current.st_dev != info.st_dev
            or current.st_ino != info.st_ino
        ):
            raise JournalIntegrityError("combat journal writer lease identity changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            windows_locked = True
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            posix_locked = True
        depths[key] = 1
        yield
    except JournalIntegrityError:
        raise
    except (OSError, ValueError) as exc:
        raise JournalIntegrityError("combat journal writer lease is unavailable") from exc
    finally:
        depths.pop(key, None)
        if descriptor is not None:
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                if windows_locked:
                    import msvcrt

                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                elif posix_locked:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(descriptor)
            except OSError:
                pass
        lock.release()


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

    def require_single_link(self) -> int:
        """Prove that the retained object has no executable alias."""
        return int(self._impl.require_single_link())

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
        if int(getattr(info, "st_nlink", 0)) != 1:
            self.close()
            raise OSError("secure move source has one or more hard-link aliases")
        self._dev_ino = (int(info.st_dev), int(info.st_ino))
        self.identity = f"posix:{info.st_dev}:{info.st_ino}"
        self._destination_fd: int | None = None
        self._destination_name = ""

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

    def require_single_link(self) -> int:
        info = os.fstat(self._fd)
        if int(getattr(info, "st_nlink", 0)) != 1:
            raise OSError("secure move object has one or more hard-link aliases")
        if self._destination_fd is not None:
            try:
                named = os.stat(
                    self._destination_name,
                    dir_fd=self._destination_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise OSError("secure move destination name lost custody") from exc
            if (
                (int(named.st_dev), int(named.st_ino)) != self._dev_ino
                or int(getattr(named, "st_nlink", 0)) != 1
            ):
                raise OSError("secure move destination name changed identity")
        return 1

    def rename_to(self, destination: Path) -> str:
        destination_fd = self._open_dir(destination.parent, create=True)
        retained = False
        try:
            self.require_single_link()
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
            self.require_single_link()
            if int(getattr(moved, "st_nlink", 0)) != 1:
                raise OSError("secure move destination acquired a hard-link alias")
            self._destination_fd = destination_fd
            self._destination_name = destination.name
            retained = True
            self.last_move_strategy = "rename"
        finally:
            if not retained:
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
        destination_fd = getattr(self, "_destination_fd", None)
        if destination_fd is not None:
            os.close(destination_fd)
            self._destination_fd = None


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
        if int(info.nNumberOfLinks) != 1:
            self.close()
            raise OSError("secure move source has one or more hard-link aliases")
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
        kernel32.GetFinalPathNameByHandleW.argtypes = [
            self._wintypes.HANDLE,
            self._wintypes.LPWSTR,
            self._wintypes.DWORD,
            self._wintypes.DWORD,
        ]
        kernel32.GetFinalPathNameByHandleW.restype = self._wintypes.DWORD
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
            0,  # no sharing: Windows also denies hard-link creation while pinned
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
            0,  # no sharing: retain exclusive object/link custody while copying
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

    def _final_path(self, handle: int) -> Path:
        buffer = self._ctypes.create_unicode_buffer(32_768)
        count = self._kernel32().GetFinalPathNameByHandleW(
            handle, buffer, len(buffer), 0
        )
        if not count or count >= len(buffer):
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        value = str(buffer.value)
        if value.casefold().startswith("\\\\?\\unc\\"):
            value = "\\\\" + value[8:]
        elif value.casefold().startswith("\\\\?\\"):
            value = value[4:]
        return _absolute_path(Path(value))

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
        handle = getattr(self, "_moved_handle", None) or self._handle
        digest = self._sha256_handle(handle)
        self._expected_digest = digest
        return digest

    def require_single_link(self) -> int:
        handle = getattr(self, "_moved_handle", None) or self._handle
        info = self._file_info(handle)
        if int(info.nNumberOfLinks) != 1:
            raise OSError("secure move object has one or more hard-link aliases")
        return 1

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
        self.require_single_link()
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
        moved = self._file_info(self._handle)
        identity, identity_text = self._identity_from_info(moved)
        if (
            identity != self._identity_tuple
            or os.path.normcase(str(self._final_path(self._handle)))
            != os.path.normcase(str(destination))
        ):
            raise OSError("secure move destination is not the pinned file")
        if int(moved.nNumberOfLinks) != 1:
            raise OSError("secure move destination acquired a hard-link alias")
        self.require_single_link()
        self.path = destination
        self.last_move_strategy = "rename"
        return identity_text

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
        destination_handle: int | None = self._create_destination_file(destination)
        source_deleted = False
        try:
            kernel32 = self._kernel32()
            expected_digest = getattr(self, "_expected_digest", None) or self.sha256()
            source_info = self._file_info(self._handle)
            if int(source_info.nNumberOfLinks) != 1:
                raise OSError("secure cross-volume source has a hard-link alias")
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
                or int(destination_info.nNumberOfLinks) != 1
            ):
                raise OSError("secure cross-volume destination verification failed")

            _identity, identity_text = self._identity_from_info(destination_info)
            # Source removal is performed against the still-pinned source
            # object, never by a path that could have been exchanged.
            self._set_delete_pending(self._handle)
            source_deleted = True
            if int(self._file_info(destination_handle).nNumberOfLinks) != 1:
                raise OSError("secure destination acquired a hard-link alias")
            # Retain the exact copied destination object through the journal
            # terminal. ``sha256`` and ``require_single_link`` now operate on
            # this handle, while the source remains delete-pending by handle.
            self._moved_handle = destination_handle
            destination_handle = None
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
            if destination_handle:
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
        moved_handle = getattr(self, "_moved_handle", None)
        if moved_handle:
            self._kernel32().CloseHandle(moved_handle)
            self._moved_handle = None
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
    version = "1.13.0"
    enabled_by_default = True

    def __init__(
        self,
        data_root: Path | None = None,
        *,
        rollback_anchor: dict[str, str] | None = None,
    ) -> None:
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
        self._journal_session_local = threading.local()
        self._terminal_commit_local = threading.local()
        self._journal_cache_records: list[dict[str, Any]] | None = None
        self._journal_cache_legacy: tuple[dict[str, Any], ...] = ()
        self._journal_cache_fingerprint: tuple[int, ...] | None = None
        self._journal_cache_tail = b""
        self._journal_cache_authenticator: hmac.HMAC | None = None
        self._journal_cache_graph_authenticator: bytes | None = None
        self._journal_cache_commits: dict[str, dict[str, Any]] = {}
        self._journal_cache_undone: set[str] = set()
        self._journal_saturated = False
        self._rollback_anchor_override = rollback_anchor
        self._process_epoch = secrets.token_hex(16)
        self._recovery_challenges: dict[str, dict[str, Any]] = {}
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

    @property
    def recovery_witness_path(self) -> Path:
        """Signing-key-bound high-water kept apart from journal/anchor state."""
        return self.data_root / "adversary_combat_recovery_witness.json"

    @property
    def journal_writer_lease_path(self) -> Path:
        """State-root-scoped lease shared by every combat journal owner."""
        return self.data_root / "adversary_combat_journal.writer.lock"

    @contextmanager
    def _journal_writer_lease(self) -> Iterator[None]:
        with _exclusive_combat_writer_lease(self.journal_writer_lease_path):
            yield

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
        if not (
            self.status == "running"
            and self.policy().enabled
            and not self._mutation_blocked
            and not self._journal_saturated
        ):
            return False
        try:
            with self._receipt_lock:
                with self._journal_writer_lease():
                    with self._pinned_journal_session(create=True):
                        return self._journal_has_capacity(
                            _JOURNAL_MUTATION_RESERVE_RECORDS
                        )
        except (JournalIntegrityError, OSError, RuntimeError, ValueError):
            return False

    def run(self) -> None:
        if self._bus is None:
            self.set_health(0, "event bus unavailable")
            return
        if not self._reconcile_state():
            self._mutation_blocked = True
            self.set_health(0, f"RECOVERY REQUIRED — {self._journal_error or 'journal unavailable'}")
            self.emit(
                "Adversary Combat refused to arm: action journal integrity failed.",
                Severity.CRITICAL,
                disposition="health",
                response_authorized=False,
            )
            # A failed authority prerequisite is a blocked capability, not a
            # crashed worker. Keep the original diagnosis and wait interruptibly
            # for shutdown/operator repair instead of triggering restart storms.
            while not self.stopping:
                self.sleep(30.0)
            return
        self._bus.subscribe(self._submit)
        policy = self.policy()
        if policy.activate_honeypots and not self._mutation_blocked:
            self._ensure_honeypots()
        if self._mutation_blocked:
            # Keep evidence collection online, but never overwrite the recovery
            # circuit's red health state or imply mutation authority was restored.
            self.set_health(0, "RECOVERY REQUIRED — Combat mutation circuit open")
        else:
            self.set_health(100, "standing authority armed")
            self.emit(
                "Adversary Combat online — standing authority is ARMED. Detector "
                "evidence is acted on automatically without per-incident approval.",
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

    def _recovery_host_binding(self) -> str:
        material = {
            "node": platform.node(),
            "machine": platform.machine(),
            "system": platform.system(),
            "state_root": str(self.data_root.resolve(strict=False)),
        }
        return hashlib.sha256(self._canonical_record(material)).hexdigest()

    def _recovery_anchor_name(self) -> str:
        return f"ANGERONA_COMBAT_RECOVERY_{self._recovery_host_binding()[:32]}"

    def _recovery_anchor_key(self) -> bytes:
        return hmac.new(
            self._journal_key(),
            _RECOVERY_ANCHOR_CONTEXT
            + b"\0"
            + self._recovery_host_binding().encode("ascii"),
            hashlib.sha256,
        ).digest()

    def _read_recovery_anchor_value(self) -> str:
        name = self._recovery_anchor_name()
        try:
            if self._rollback_anchor_override is not None:
                return str(self._rollback_anchor_override.get(name, ""))
            from angerona.core.secure_store import read_secret_values

            return str(
                read_secret_values((name,), self.data_root, strict=True).get(name, "")
            )
        except JournalIntegrityError:
            raise
        except Exception as exc:
            raise JournalIntegrityError(
                "recovery rollback anchor is unavailable"
            ) from exc

    def _write_recovery_anchor_value(self, value: str) -> None:
        name = self._recovery_anchor_name()
        try:
            if self._rollback_anchor_override is not None:
                self._rollback_anchor_override[name] = value
            else:
                from angerona.core.secure_store import write_secret_map

                write_secret_map({name: value}, self.data_root)
            if not hmac.compare_digest(self._read_recovery_anchor_value(), value):
                raise JournalIntegrityError(
                    "recovery rollback anchor verification failed"
                )
        except JournalIntegrityError:
            raise
        except Exception as exc:
            raise JournalIntegrityError(
                "recovery rollback anchor could not be committed"
            ) from exc

    def _decode_recovery_anchor(self, raw: str) -> dict[str, Any]:
        value = self._bounded_authority_json(
            raw,
            label="recovery rollback anchor",
            max_bytes=_MAX_RECOVERY_ANCHOR_BYTES,
        )
        if not isinstance(value, dict) or set(value) != _RECOVERY_ANCHOR_FIELDS:
            raise JournalIntegrityError("recovery rollback anchor schema is invalid")
        try:
            supplied = str(value.pop("record_hmac"))
            expected = hmac.new(
                self._recovery_anchor_key(),
                self._canonical_record(value),
                hashlib.sha256,
            ).hexdigest()
            active_action = str(value.get("active_action_id") or "")
            active_nonce = str(value.get("active_challenge_nonce") or "")
            active_sequence = int(value.get("active_challenge_sequence") or 0)
            last_sequence = int(value.get("last_journal_sequence") or 0)
            last_hmac = str(value.get("last_journal_hmac") or "")
            consumed = int(value.get("consumed_terminal_sequence") or 0)
            challenge_counter = int(value.get("challenge_counter") or 0)
        except (TypeError, ValueError, OverflowError) as exc:
            raise JournalIntegrityError(
                "recovery rollback anchor values are invalid"
            ) from exc
        if (
            value.get("schema") not in (1, _RECOVERY_ANCHOR_SCHEMA)
            or value.get("host_binding") != self._recovery_host_binding()
            or not _RECOVERY_CHALLENGE_NONCE.fullmatch(
                str(value.get("install_epoch") or "")
            )
            or challenge_counter < 0
            or last_sequence < 0
            or consumed < 0
            or consumed > last_sequence
            or (
                last_hmac != _JOURNAL_GENESIS
                if last_sequence == 0
                else not bool(re.fullmatch(r"[0-9a-f]{64}", last_hmac))
            )
            or bool(active_action) != bool(active_sequence)
            or bool(active_action) != bool(active_nonce)
            or (active_action and not re.fullmatch(r"act-[0-9a-f]{16}", active_action))
            or (active_nonce and not _RECOVERY_CHALLENGE_NONCE.fullmatch(active_nonce))
            or active_sequence > last_sequence
            or not re.fullmatch(r"[0-9a-f]{64}", supplied)
            or not hmac.compare_digest(supplied, expected)
        ):
            raise JournalIntegrityError("recovery rollback anchor authentication failed")
        return {**value, "record_hmac": supplied}

    def _validated_recovery_anchor(self, raw: str) -> dict[str, Any]:
        """Decode authenticated bytes, then enforce non-coercible authority types."""
        value = self._decode_recovery_anchor(raw)
        integer_fields = (
            "schema",
            "challenge_counter",
            "active_challenge_sequence",
            "last_journal_sequence",
            "consumed_terminal_sequence",
        )
        if any(type(value.get(field)) is not int for field in integer_fields):
            raise JournalIntegrityError(
                "recovery rollback anchor values are invalid"
            )
        return value

    def _encode_recovery_anchor(self, core: dict[str, Any]) -> str:
        value = {
            **core,
            "record_hmac": hmac.new(
                self._recovery_anchor_key(),
                self._canonical_record(core),
                hashlib.sha256,
            ).hexdigest(),
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def _recovery_witness_key(self) -> bytes:
        return hmac.new(
            self._journal_key(),
            _RECOVERY_WITNESS_CONTEXT
            + b"\0"
            + self._recovery_host_binding().encode("ascii"),
            hashlib.sha256,
        ).digest()

    def _read_recovery_witness(self) -> dict[str, Any] | None:
        """Read one identity-pinned witness; missing is distinct from malformed."""
        path = self.recovery_witness_path
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise JournalIntegrityError("recovery high-water witness is unreadable") from exc
        try:
            before = os.fstat(descriptor)
            attributes = int(getattr(before, "st_file_attributes", 0))
            if (
                not stat.S_ISREG(before.st_mode)
                or int(getattr(before, "st_nlink", 1)) != 1
                or bool(attributes & 0x400)
                or before.st_size > _MAX_RECOVERY_WITNESS_BYTES
            ):
                raise JournalIntegrityError("recovery high-water witness is unsafe")
            chunks: list[bytes] = []
            remaining = _MAX_RECOVERY_WITNESS_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            current = os.lstat(path)
            if (
                len(raw) > _MAX_RECOVERY_WITNESS_BYTES
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or current.st_dev != after.st_dev
                or current.st_ino != after.st_ino
                or int(getattr(current, "st_nlink", 1)) != 1
            ):
                raise JournalIntegrityError(
                    "recovery high-water witness changed while being read"
                )
        except JournalIntegrityError:
            raise
        except OSError as exc:
            raise JournalIntegrityError("recovery high-water witness is unreadable") from exc
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        value = self._bounded_authority_json(
            raw,
            label="recovery high-water witness",
            max_bytes=_MAX_RECOVERY_WITNESS_BYTES,
        )
        if not isinstance(value, dict) or set(value) != _RECOVERY_WITNESS_FIELDS:
            raise JournalIntegrityError("recovery high-water witness schema is invalid")
        if type(value.get("schema")) is not int or type(
            value.get("last_journal_sequence")
        ) is not int:
            raise JournalIntegrityError(
                "recovery high-water witness values are invalid"
            )
        try:
            supplied = str(value.pop("record_hmac"))
            expected = hmac.new(
                self._recovery_witness_key(),
                self._canonical_record(value),
                hashlib.sha256,
            ).hexdigest()
            sequence = int(value.get("last_journal_sequence") or 0)
            journal_hmac = str(value.get("last_journal_hmac") or "")
        except (
            MemoryError,
            RecursionError,
            TypeError,
            ValueError,
            OverflowError,
        ) as exc:
            raise JournalIntegrityError(
                "recovery high-water witness values are invalid"
            ) from exc
        if (
            value.get("schema") != _RECOVERY_WITNESS_SCHEMA
            or value.get("host_binding") != self._recovery_host_binding()
            or value.get("authority_fingerprint")
            != hashlib.sha256(self._journal_key()).hexdigest()
            or not _RECOVERY_CHALLENGE_NONCE.fullmatch(
                str(value.get("install_epoch") or "")
            )
            or sequence < 0
            or (
                journal_hmac != _JOURNAL_GENESIS
                if sequence == 0
                else not bool(_HEX64.fullmatch(journal_hmac))
            )
            or not _HEX64.fullmatch(str(value.get("anchor_record_hmac") or ""))
            or not _HEX64.fullmatch(supplied)
            or not hmac.compare_digest(supplied, expected)
        ):
            raise JournalIntegrityError(
                "recovery high-water witness authentication failed"
            )
        return {**value, "record_hmac": supplied}

    def _write_recovery_witness(self, anchor: dict[str, Any]) -> None:
        path = self.recovery_witness_path
        core: dict[str, Any] = {
            "schema": _RECOVERY_WITNESS_SCHEMA,
            "host_binding": self._recovery_host_binding(),
            "authority_fingerprint": hashlib.sha256(self._journal_key()).hexdigest(),
            "install_epoch": str(anchor["install_epoch"]),
            "last_journal_sequence": int(anchor["last_journal_sequence"]),
            "last_journal_hmac": str(anchor["last_journal_hmac"]),
            "anchor_record_hmac": str(anchor["record_hmac"]),
        }
        value = {
            **core,
            "record_hmac": hmac.new(
                self._recovery_witness_key(),
                self._canonical_record(core),
                hashlib.sha256,
            ).hexdigest(),
        }
        candidate = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
        descriptor: int | None = None
        try:
            from angerona.core.atomic_io import replace_with_retry
            from angerona.core.hardening import (
                ensure_sensitive_parent,
                key_acl_required,
                secure_sensitive_file,
            )

            required = key_acl_required()
            path.parent.mkdir(parents=True, exist_ok=True)
            ensure_sensitive_parent(path, required=required)
            descriptor = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                descriptor = None
                stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            replace_with_retry(candidate, path)
            secure_sensitive_file(path, required=required)
            observed = self._read_recovery_witness()
            if observed is None or not hmac.compare_digest(
                str(observed["record_hmac"]), str(value["record_hmac"])
            ):
                raise JournalIntegrityError(
                    "recovery high-water witness verification failed"
                )
        except JournalIntegrityError:
            raise
        except Exception as exc:
            raise JournalIntegrityError(
                "recovery high-water witness could not be committed"
            ) from exc
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass

    def _verify_recovery_witness(self, anchor: dict[str, Any]) -> None:
        witness = self._read_recovery_witness()
        if witness is None:
            raise JournalIntegrityError(
                "recovery high-water witness is missing; mutation remains disarmed"
            )
        if (
            witness["install_epoch"] != anchor["install_epoch"]
            or int(witness["last_journal_sequence"])
            != int(anchor["last_journal_sequence"])
            or not hmac.compare_digest(
                str(witness["last_journal_hmac"]),
                str(anchor["last_journal_hmac"]),
            )
            or not hmac.compare_digest(
                str(witness["anchor_record_hmac"]),
                str(anchor["record_hmac"]),
            )
        ):
            raise JournalIntegrityError(
                "combat journal/anchor rollback violates the signing-key witness"
            )

    def _initial_recovery_anchor(self) -> dict[str, Any]:
        return {
            "schema": _RECOVERY_ANCHOR_SCHEMA,
            "host_binding": self._recovery_host_binding(),
            "install_epoch": secrets.token_hex(16),
            "challenge_counter": 0,
            "active_action_id": "",
            "active_challenge_sequence": 0,
            "active_challenge_nonce": "",
            "last_journal_sequence": 0,
            "last_journal_hmac": _JOURNAL_GENESIS,
            "consumed_terminal_sequence": 0,
        }

    def _recovery_anchor(
        self, *, allow_create: bool, journal_has_records: bool = False
    ) -> dict[str, Any]:
        raw = self._read_recovery_anchor_value()
        if not raw:
            if not allow_create or journal_has_records:
                raise JournalIntegrityError(
                    "recovery rollback anchor is missing; mutation remains disarmed"
                )
            with self._journal_writer_lease():
                # Recheck after acquiring the installation-wide lease. Two
                # startup owners must not enroll different install epochs.
                raw = self._read_recovery_anchor_value()
                if raw:
                    return self._validated_recovery_anchor(raw)
                if self._read_recovery_witness() is not None:
                    raise JournalIntegrityError(
                        "recovery rollback anchor is missing; signing-key witness "
                        "proves installation enrollment"
                    )
                core = self._initial_recovery_anchor()
                self._write_recovery_anchor_value(self._encode_recovery_anchor(core))
                raw = self._read_recovery_anchor_value()
                anchor = self._validated_recovery_anchor(raw)
                self._write_recovery_witness(anchor)
                return anchor
        return self._validated_recovery_anchor(raw)

    def _verify_recovery_anchor(self, records: list[dict[str, Any]]) -> None:
        anchor = self._recovery_anchor(
            allow_create=True, journal_has_records=bool(records)
        )
        sequence = len(records)
        record_hmac = str(records[-1]["record_hmac"]) if records else _JOURNAL_GENESIS
        if (
            int(anchor["last_journal_sequence"]) != sequence
            or not hmac.compare_digest(str(anchor["last_journal_hmac"]), record_hmac)
        ):
            raise JournalIntegrityError(
                "combat journal rollback or incomplete anchor transaction detected"
            )
        if int(anchor["schema"]) == 1:
            # Runtime state may never convert a legacy authority into current
            # mutation authority. Missing witness state is indistinguishable
            # from witness deletion after rollback. A separately audited,
            # explicit operator migration must establish schema 2 instead.
            raise JournalIntegrityError(
                "legacy recovery anchor is not runtime authority; explicit "
                "operator migration/recovery is required"
            )
        self._verify_recovery_witness(anchor)

    def _advance_recovery_anchor(self, record: dict[str, Any]) -> None:
        anchor = self._recovery_anchor(allow_create=False)
        self._verify_recovery_witness(anchor)
        sequence = int(record["sequence"])
        if (
            int(anchor["last_journal_sequence"]) != sequence - 1
            or anchor["last_journal_hmac"] != record["previous_hmac"]
        ):
            raise JournalIntegrityError("recovery rollback anchor did not advance")
        core = {key: value for key, value in anchor.items() if key != "record_hmac"}
        core["last_journal_sequence"] = sequence
        core["last_journal_hmac"] = str(record["record_hmac"])
        record_type = str(record.get("record_type") or "")
        if record_type == "recovery_challenge":
            counter = int(record.get("challenge_counter") or 0)
            if (
                counter != int(anchor["challenge_counter"]) + 1
                or record.get("install_epoch") != anchor["install_epoch"]
                or not _RECOVERY_CHALLENGE_NONCE.fullmatch(
                    str(record.get("challenge_nonce") or "")
                )
            ):
                raise JournalIntegrityError("recovery challenge sequence is invalid")
            core["challenge_counter"] = counter
            core["active_action_id"] = str(record["action_id"])
            core["active_challenge_sequence"] = sequence
            core["active_challenge_nonce"] = str(record["challenge_nonce"])
        elif record_type == "operator_disposition":
            if (
                str(record.get("action_id") or "") != anchor["active_action_id"]
                or int(record.get("bound_challenge_sequence") or 0)
                != int(anchor["active_challenge_sequence"])
                or int(record.get("bound_challenge_counter") or 0)
                != int(anchor["challenge_counter"])
                or str(record.get("bound_challenge_nonce") or "")
                != anchor["active_challenge_nonce"]
            ):
                raise JournalIntegrityError("recovery challenge consumption is invalid")
            core["active_action_id"] = ""
            core["active_challenge_sequence"] = 0
            core["active_challenge_nonce"] = ""
            core["consumed_terminal_sequence"] = sequence
        self._write_recovery_anchor_value(self._encode_recovery_anchor(core))
        advanced = self._validated_recovery_anchor(
            self._read_recovery_anchor_value()
        )
        self._write_recovery_witness(advanced)

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

    def _journal_topology(
        self, *, create_parent: bool
    ) -> tuple[os.stat_result, os.stat_result] | None:
        """Pin the state root and receipt parent without following link objects."""
        root = _absolute_path(self.data_root)
        parent = _absolute_path(self.receipt_path.parent)
        if parent.parent != root:
            raise JournalIntegrityError("combat journal parent escaped the state root")
        if create_parent:
            parent.mkdir(parents=True, exist_ok=True)
        try:
            root_info = os.lstat(root)
            parent_info = os.lstat(parent)
        except FileNotFoundError:
            if not create_parent:
                return None
            raise JournalIntegrityError("combat journal parent is unavailable") from None
        for label, info in (("state root", root_info), ("receipt parent", parent_info)):
            attributes = int(getattr(info, "st_file_attributes", 0))
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or bool(attributes & 0x400)
            ):
                raise JournalIntegrityError(f"combat journal {label} is unsafe")
        return root_info, parent_info

    @staticmethod
    def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
        return left.st_dev == right.st_dev and left.st_ino == right.st_ino

    def _active_journal_session(self) -> dict[str, Any] | None:
        session = getattr(self._journal_session_local, "session", None)
        return session if isinstance(session, dict) else None

    def _assert_journal_session(
        self, session: dict[str, Any]
    ) -> os.stat_result:
        """Prove that a pinned journal is still the one canonical path object."""
        descriptor = int(session["descriptor"])
        identity = session["identity"]
        topology = session["topology"]
        path = _absolute_path(self.receipt_path)
        try:
            current_descriptor = os.fstat(descriptor)
            current_path = os.lstat(path)
            current_topology = self._journal_topology(create_parent=False)
        except (FileNotFoundError, OSError) as exc:
            raise JournalIntegrityError(
                "combat journal custody was lost during the transaction"
            ) from exc
        attributes = int(getattr(current_descriptor, "st_file_attributes", 0))
        if current_descriptor.st_size > _MAX_JOURNAL_BYTES:
            raise JournalIntegrityError("combat journal byte budget exceeded")
        if current_topology is None or (
            not stat.S_ISREG(current_descriptor.st_mode)
            or bool(attributes & 0x400)
            or int(getattr(current_descriptor, "st_nlink", 1)) != 1
            or int(getattr(current_path, "st_nlink", 1)) != 1
            or not self._same_object(identity, current_descriptor)
            or not self._same_object(current_descriptor, current_path)
            or not self._same_object(topology[0], current_topology[0])
            or not self._same_object(topology[1], current_topology[1])
        ):
            raise JournalIntegrityError(
                "combat journal identity changed during the transaction"
            )
        return current_descriptor

    @contextmanager
    def _pinned_journal_session(self, *, create: bool) -> Iterator[None]:
        """Retain one identity-stable journal descriptor for a full transaction."""
        active = self._active_journal_session()
        if active is not None:
            self._assert_journal_session(active)
            try:
                yield
            finally:
                self._assert_journal_session(active)
            return

        path = _absolute_path(self.receipt_path)
        topology = self._journal_topology(create_parent=create)
        if topology is None:
            raise JournalIntegrityError("combat journal is missing")
        from angerona.core.hardening import ensure_sensitive_parent, key_acl_required

        required = key_acl_required()
        ensure_sensitive_parent(path, required=required)
        flags = (
            os.O_RDWR
            | os.O_APPEND
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(path, flags)
            except FileNotFoundError:
                if not create:
                    raise JournalIntegrityError("combat journal is missing") from None
                descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            identity = os.fstat(descriptor)
            attributes = int(getattr(identity, "st_file_attributes", 0))
            current = os.lstat(path)
            if identity.st_size > _MAX_JOURNAL_BYTES:
                raise JournalIntegrityError("combat journal byte budget exceeded")
            if (
                not stat.S_ISREG(identity.st_mode)
                or bool(attributes & 0x400)
                or int(getattr(identity, "st_nlink", 1)) != 1
                or int(getattr(current, "st_nlink", 1)) != 1
                or not self._same_object(identity, current)
            ):
                raise JournalIntegrityError("combat journal object is unsafe")
            session = {
                "descriptor": descriptor,
                "identity": identity,
                "topology": topology,
            }
            self._journal_session_local.session = session
            self._assert_journal_session(session)
            try:
                yield
            finally:
                self._assert_journal_session(session)
        except JournalIntegrityError:
            raise
        except OSError as exc:
            raise JournalIntegrityError("combat journal custody is unavailable") from exc
        finally:
            self._journal_session_local.session = None
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _read_active_journal_bytes(self, session: dict[str, Any]) -> bytes:
        descriptor = int(session["descriptor"])
        before = self._assert_journal_session(session)
        if before.st_size > _MAX_JOURNAL_BYTES:
            raise JournalIntegrityError("combat journal byte budget exceeded")
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = _MAX_JOURNAL_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        except (MemoryError, OSError) as exc:
            raise JournalIntegrityError("combat journal bounded read failed") from exc
        after = self._assert_journal_session(session)
        if (
            len(raw) > _MAX_JOURNAL_BYTES
            or before.st_size != after.st_size
            or len(raw) != after.st_size
        ):
            raise JournalIntegrityError("combat journal changed while being read")
        return raw

    @staticmethod
    def _json_depth_within_budget(raw: bytes) -> bool:
        depth = 0
        in_string = False
        escaped = False
        for value in raw:
            if in_string:
                if escaped:
                    escaped = False
                elif value == 0x5C:
                    escaped = True
                elif value == 0x22:
                    in_string = False
                continue
            if value == 0x22:
                in_string = True
            elif value in (0x7B, 0x5B):
                depth += 1
                if depth > _MAX_JOURNAL_JSON_DEPTH:
                    return False
            elif value in (0x7D, 0x5D):
                depth -= 1
                if depth < 0:
                    return False
        return depth == 0 and not in_string and not escaped

    @staticmethod
    def _strict_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON member")
            value[key] = item
        return value

    @classmethod
    def _bounded_authority_json(
        cls,
        raw: str | bytes,
        *,
        label: str,
        max_bytes: int,
    ) -> dict[str, Any]:
        """Decode one small authority object without recursive parser escape."""
        try:
            encoded = (
                raw.encode("utf-8", errors="strict")
                if isinstance(raw, str)
                else bytes(raw)
            )
            if (
                not encoded
                or len(encoded) > max_bytes
                or not cls._json_depth_within_budget(encoded)
            ):
                raise ValueError("authority JSON exceeds its structural budget")

            def reject_constant(token: str) -> None:
                raise ValueError(f"invalid JSON constant: {token}")

            value = json.loads(
                encoded.decode("utf-8", errors="strict"),
                object_pairs_hook=cls._strict_json_pairs,
                parse_constant=reject_constant,
            )
            if not isinstance(value, dict) or not cls._bounded_json_value(value):
                raise ValueError("authority JSON value budget is invalid")
            return value
        except JournalIntegrityError:
            raise
        except (
            MemoryError,
            RecursionError,
            UnicodeError,
            TypeError,
            ValueError,
            OverflowError,
        ) as exc:
            raise JournalIntegrityError(f"{label} is malformed") from exc

    @classmethod
    def _bounded_json_value(cls, value: Any, *, depth: int = 0) -> bool:
        if depth > _MAX_JOURNAL_JSON_DEPTH:
            return False
        if value is None or isinstance(value, (str, bool)):
            return True
        if isinstance(value, int):
            return not isinstance(value, bool) and -(2**63) <= value < 2**63
        if isinstance(value, float):
            return math.isfinite(value)
        if isinstance(value, (list, tuple)):
            return len(value) <= 256 and all(
                cls._bounded_json_value(item, depth=depth + 1) for item in value
            )
        if isinstance(value, dict):
            return len(value) <= 64 and all(
                isinstance(key, str)
                and len(key) <= 128
                and cls._bounded_json_value(item, depth=depth + 1)
                for key, item in value.items()
            )
        return False

    @classmethod
    def _signed_journal_schema_valid(cls, value: dict[str, Any]) -> bool:
        record_type = str(value.get("record_type") or "")
        field_contract = _JOURNAL_FIELDS_BY_TYPE.get(record_type)
        if field_contract is None:
            return False
        required, allowed = field_contract
        fields = frozenset(value)
        return bool(
            required <= fields <= allowed
            and value.get("journal_version") == _JOURNAL_VERSION
            and isinstance(value.get("sequence"), int)
            and not isinstance(value.get("sequence"), bool)
            and int(value["sequence"]) > 0
            and _HEX64.fullmatch(str(value.get("previous_hmac") or ""))
            and _HEX64.fullmatch(str(value.get("record_hmac") or ""))
            and cls._bounded_json_value(value)
        )

    def _read_pinned_journal_bytes(self) -> bytes | None:
        """Read the exact single-link journal object and prove stable topology."""
        active = self._active_journal_session()
        if active is not None:
            return self._read_active_journal_bytes(active)
        path = _absolute_path(self.receipt_path)
        topology = self._journal_topology(create_parent=False)
        if topology is None:
            return None
        descriptor: int | None = None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise JournalIntegrityError("combat journal is unreadable") from exc
        try:
            before = os.fstat(descriptor)
            attributes = int(getattr(before, "st_file_attributes", 0))
            current = os.lstat(path)
            if before.st_size > _MAX_JOURNAL_BYTES:
                raise JournalIntegrityError("combat journal byte budget exceeded")
            if (
                not stat.S_ISREG(before.st_mode)
                or int(getattr(before, "st_nlink", 1)) != 1
                or bool(attributes & 0x400)
                or not self._same_object(before, current)
                or int(getattr(current, "st_nlink", 1)) != 1
            ):
                raise JournalIntegrityError("combat journal object is unsafe")
            chunks: list[bytes] = []
            remaining = _MAX_JOURNAL_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            final = os.lstat(path)
            final_topology = self._journal_topology(create_parent=False)
            if final_topology is None or (
                len(raw) > _MAX_JOURNAL_BYTES
                or not self._same_object(before, after)
                or not self._same_object(after, final)
                or before.st_size != after.st_size
                or len(raw) != after.st_size
                or int(getattr(after, "st_nlink", 1)) != 1
                or int(getattr(final, "st_nlink", 1)) != 1
                or not self._same_object(topology[0], final_topology[0])
                or not self._same_object(topology[1], final_topology[1])
            ):
                raise JournalIntegrityError("combat journal changed while being read")
            return raw
        except JournalIntegrityError:
            raise
        except (MemoryError, OSError) as exc:
            raise JournalIntegrityError("combat journal is unreadable") from exc
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _append_pinned_journal_bytes(self, payload: bytes) -> None:
        """Append through one pinned regular object and recheck its topology."""
        active = self._active_journal_session()
        if active is not None:
            before = self._assert_journal_session(active)
            if (
                len(payload) > _MAX_JOURNAL_LINE_BYTES + 1
                or before.st_size + len(payload) > _MAX_JOURNAL_BYTES
            ):
                raise JournalIntegrityError("combat journal byte budget exceeded")
            descriptor = int(active["descriptor"])
            try:
                written = 0
                while written < len(payload):
                    count = os.write(descriptor, payload[written:])
                    if count <= 0:
                        raise JournalIntegrityError(
                            "combat journal append was incomplete"
                        )
                    written += count
                os.fsync(descriptor)
            except JournalIntegrityError:
                raise
            except OSError as exc:
                raise JournalIntegrityError("combat journal append failed") from exc
            after = self._assert_journal_session(active)
            if after.st_size != before.st_size + len(payload):
                raise JournalIntegrityError("combat journal append was incomplete")
            return
        path = _absolute_path(self.receipt_path)
        topology = self._journal_topology(create_parent=True)
        if topology is None:  # pragma: no cover - create_parent makes this impossible
            raise JournalIntegrityError("combat journal parent is unavailable")
        from angerona.core.hardening import ensure_sensitive_parent, key_acl_required

        required = key_acl_required()
        ensure_sensitive_parent(path, required=required)
        if len(payload) > _MAX_JOURNAL_LINE_BYTES + 1:
            raise JournalIntegrityError("combat journal line budget exceeded")
        descriptor: int | None = None
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            try:
                descriptor = os.open(path, flags)
            except FileNotFoundError:
                descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            before = os.fstat(descriptor)
            attributes = int(getattr(before, "st_file_attributes", 0))
            current = os.lstat(path)
            if (
                not stat.S_ISREG(before.st_mode)
                or int(getattr(before, "st_nlink", 1)) != 1
                or bool(attributes & 0x400)
                or before.st_size + len(payload) > _MAX_JOURNAL_BYTES
                or not self._same_object(before, current)
                or int(getattr(current, "st_nlink", 1)) != 1
            ):
                raise JournalIntegrityError("combat journal object is unsafe")
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    raise JournalIntegrityError("combat journal append was incomplete")
                written += count
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            final = os.lstat(path)
            final_topology = self._journal_topology(create_parent=False)
            if final_topology is None or (
                not self._same_object(before, after)
                or not self._same_object(after, final)
                or after.st_size != before.st_size + len(payload)
                or int(getattr(after, "st_nlink", 1)) != 1
                or int(getattr(final, "st_nlink", 1)) != 1
                or not self._same_object(topology[0], final_topology[0])
                or not self._same_object(topology[1], final_topology[1])
            ):
                raise JournalIntegrityError("combat journal changed during append")
        except JournalIntegrityError:
            raise
        except OSError as exc:
            raise JournalIntegrityError("combat journal append failed") from exc
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    @staticmethod
    def _journal_fingerprint(info: os.stat_result) -> tuple[int, ...]:
        return (
            int(getattr(info, "st_dev", 0)),
            int(getattr(info, "st_ino", 0)),
            int(info.st_size),
            int(getattr(info, "st_mtime_ns", 0)),
            int(getattr(info, "st_ctime_ns", 0)),
            int(getattr(info, "st_nlink", 1)),
        )

    def _invalidate_journal_cache(self) -> None:
        self._journal_cache_records = None
        self._journal_cache_legacy = ()
        self._journal_cache_fingerprint = None
        self._journal_cache_tail = b""
        self._journal_cache_authenticator = None
        self._journal_cache_graph_authenticator = None
        self._journal_cache_commits.clear()
        self._journal_cache_undone.clear()

    def _journal_cache_graph_digest(
        self, records: list[dict[str, Any]]
    ) -> bytes:
        """Authenticate every nested value retained as in-memory authority."""
        try:
            encoded = json.dumps(
                records,
                sort_keys=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8", errors="strict")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise JournalIntegrityError(
                "combat journal cache authority is not canonical"
            ) from exc
        return hmac.new(
            self._journal_key(),
            b"angerona/combat-journal-cache/v1\x00" + encoded,
            hashlib.sha256,
        ).digest()

    def _journal_cache_indexes_are_exact(
        self, records: list[dict[str, Any]]
    ) -> bool:
        """Require indexes to retain the exact authenticated record objects."""
        commits = {
            str(record.get("action_id")): record
            for record in records
            if record.get("record_type") == "commit" and record.get("action_id")
        }
        undone = {
            str(record.get("undo_of"))
            for record in records
            if record.get("record_type") == "undo_commit"
            and record.get("status") == "undone"
            and record.get("undo_of")
        }
        return bool(
            commits.keys() == self._journal_cache_commits.keys()
            and all(
                self._journal_cache_commits[action_id] is record
                for action_id, record in commits.items()
            )
            and undone == self._journal_cache_undone
        )

    def _active_journal_tail_bytes(self, session: dict[str, Any]) -> bytes:
        """Read only the terminal bounded line from the retained descriptor."""
        before = self._assert_journal_session(session)
        size = int(before.st_size)
        if size == 0:
            return b""
        descriptor = int(session["descriptor"])
        window = min(size, _MAX_JOURNAL_LINE_BYTES + 2)
        try:
            os.lseek(descriptor, size - window, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = window
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        except OSError as exc:
            raise JournalIntegrityError("combat journal tail is unreadable") from exc
        after = self._assert_journal_session(session)
        if int(after.st_size) != size or len(raw) != window or not raw.endswith(b"\n"):
            raise JournalIntegrityError("combat journal terminal line is incomplete")
        previous_newline = raw.rfind(b"\n", 0, len(raw) - 1)
        tail = raw[previous_newline + 1 :]
        if not tail or len(tail) > _MAX_JOURNAL_LINE_BYTES + 1:
            raise JournalIntegrityError("combat journal terminal line is oversized")
        return tail

    def _store_active_journal_cache(
        self,
        signed: list[dict[str, Any]],
        legacy: list[dict[str, Any]],
        raw: bytes,
    ) -> None:
        session = self._active_journal_session()
        if session is None:
            return
        info = self._assert_journal_session(session)
        # The parsed records are caller-visible from _read_journal().  Retain a
        # completely independent authority graph so no nested diagnostic value
        # can mutate the commit/undo indexes in memory.
        self._journal_cache_records = copy.deepcopy(signed)
        self._journal_cache_legacy = tuple(copy.deepcopy(legacy))
        self._journal_cache_fingerprint = self._journal_fingerprint(info)
        self._journal_cache_tail = (
            raw[raw.rfind(b"\n", 0, len(raw) - 1) + 1 :]
            if raw
            else b""
        )
        self._journal_cache_authenticator = hmac.new(
            self._journal_key(), raw, hashlib.sha256
        )
        self._journal_cache_commits = {
            str(record.get("action_id")): record
            for record in self._journal_cache_records
            if record.get("record_type") == "commit" and record.get("action_id")
        }
        self._journal_cache_undone = {
            str(record.get("undo_of"))
            for record in signed
            if record.get("record_type") == "undo_commit"
            and record.get("status") == "undone"
            and record.get("undo_of")
        }
        self._journal_cache_graph_authenticator = self._journal_cache_graph_digest(
            self._journal_cache_records
        )

    def _validated_active_journal_cache(self) -> list[dict[str, Any]] | None:
        session = self._active_journal_session()
        records = self._journal_cache_records
        if session is None or records is None:
            return None
        info = self._assert_journal_session(session)
        if self._journal_cache_fingerprint != self._journal_fingerprint(info):
            self._invalidate_journal_cache()
            return None
        authenticator = self._journal_cache_authenticator
        graph_authenticator = self._journal_cache_graph_authenticator
        if authenticator is None or graph_authenticator is None:
            self._invalidate_journal_cache()
            return None
        try:
            graph_valid = hmac.compare_digest(
                self._journal_cache_graph_digest(records), graph_authenticator
            ) and self._journal_cache_indexes_are_exact(records)
        except JournalIntegrityError:
            self._invalidate_journal_cache()
            raise
        if not graph_valid:
            self._invalidate_journal_cache()
            raise JournalIntegrityError(
                "combat journal in-memory authority graph changed"
            )
        # Metadata plus the terminal line cannot authenticate an interior
        # record. Re-HMAC the exact pinned bytes before authority is admitted;
        # the bounded journal makes this deterministic and fail-closed even if
        # an attacker restores mtime/change-time after a same-size edit.
        raw = self._read_active_journal_bytes(session)
        actual = hmac.new(self._journal_key(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(actual, authenticator.copy().digest()):
            self._invalidate_journal_cache()
            raise JournalIntegrityError("combat journal interior checkpoint changed")
        if not hmac.compare_digest(
            self._active_journal_tail_bytes(session), self._journal_cache_tail
        ):
            self._invalidate_journal_cache()
            raise JournalIntegrityError("combat journal terminal checkpoint changed")
        self._verify_recovery_anchor(records)
        return records

    def _cached_active_journal(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None:
        records = self._validated_active_journal_cache()
        if records is None:
            return None
        return (
            copy.deepcopy(records),
            copy.deepcopy(list(self._journal_cache_legacy)),
        )

    def _read_journal(
        self, *, strict: bool = False
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Return verified signed records and display-only legacy records."""
        if strict:
            cached = self._cached_active_journal()
            if cached is not None:
                return cached
        try:
            raw = self._read_pinned_journal_bytes()
        except JournalIntegrityError as exc:
            if strict:
                raise
            self._journal_error = str(exc)
            return [], []
        if raw is None:
            if strict:
                self._verify_recovery_anchor([])
            return [], []
        if len(raw) > _MAX_JOURNAL_BYTES:
            error = "combat journal byte budget exceeded"
            self._journal_error = error
            if strict:
                raise JournalIntegrityError(error)
            return [], []
        lines = raw.splitlines()
        if len(lines) > _MAX_JOURNAL_RECORDS:
            error = "combat journal record budget exceeded"
            self._journal_error = error
            if strict:
                raise JournalIntegrityError(error)
            return [], []
        if strict and raw and not raw.endswith(b"\n"):
            raise JournalIntegrityError("combat journal has an incomplete terminal line")
        signed: list[dict[str, Any]] = []
        legacy: list[dict[str, Any]] = []
        previous = _JOURNAL_GENESIS
        expected_sequence = 1
        signed_started = False
        for line_number, raw_line in enumerate(lines, 1):
            if (
                not raw_line
                or len(raw_line) > _MAX_JOURNAL_LINE_BYTES
                or not self._json_depth_within_budget(raw_line)
            ):
                self._journal_error = (
                    f"journal resource/schema limit at line {line_number}"
                )
                if strict:
                    raise JournalIntegrityError(self._journal_error)
                break
            try:
                line = raw_line.decode("utf-8", errors="strict")
                value = json.loads(
                    line,
                    object_pairs_hook=self._strict_json_pairs,
                    parse_constant=lambda token: (_ for _ in ()).throw(
                        ValueError(f"invalid JSON constant: {token}")
                    ),
                )
            except (MemoryError, RecursionError, TypeError, UnicodeError, ValueError):
                if signed_started:
                    self._journal_error = f"broken journal record at line {line_number}"
                    if strict:
                        raise JournalIntegrityError(self._journal_error)
                    break
                if strict:
                    raise JournalIntegrityError(
                        f"untrusted journal prefix at line {line_number}"
                    ) from None
                continue
            if not isinstance(value, dict) or not self._bounded_json_value(value):
                if strict:
                    raise JournalIntegrityError(
                        f"journal schema failure at line {line_number}"
                    )
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
                if strict:
                    raise JournalIntegrityError(
                        f"untrusted journal prefix at line {line_number}"
                    )
                legacy.append({**value, "integrity_status": "legacy-untrusted"})
                continue
            if not self._signed_journal_schema_valid(value):
                self._journal_error = f"journal schema failure at line {line_number}"
                if strict:
                    raise JournalIntegrityError(self._journal_error)
                break
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
        try:
            self._verify_recovery_anchor(signed)
        except JournalIntegrityError as exc:
            self._journal_error = str(exc)
            if strict:
                raise
        if strict:
            self._store_active_journal_cache(signed, legacy, raw)
        return signed, legacy

    def _append_journal(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Append one authenticated, chained, fsynced journal phase."""
        with self._receipt_lock:
            with self._journal_writer_lease():
                with self._pinned_journal_session(create=True):
                    try:
                        records = self._validated_active_journal_cache()
                        if records is None:
                            self._read_journal(strict=True)
                            records = self._validated_active_journal_cache()
                        if records is None:  # pragma: no cover - strict read stores it
                            raise JournalIntegrityError(
                                "combat journal checkpoint is unavailable"
                            )
                        if len(records) >= _MAX_JOURNAL_RECORDS:
                            raise JournalIntegrityError(
                                "combat journal record budget exhausted"
                            )
                        previous = (
                            str(records[-1]["record_hmac"])
                            if records
                            else _JOURNAL_GENESIS
                        )
                        retained_payload = copy.deepcopy(payload)
                        if retained_payload.get("record_type") == "commit":
                            validator = getattr(
                                self._terminal_commit_local, "validator", None
                            )
                            if callable(validator):
                                candidate = validator()
                                if (
                                    not isinstance(candidate, dict)
                                    or not self._bounded_json_value(candidate)
                                ):
                                    raise JournalIntegrityError(
                                        "mutation terminal object proof is malformed"
                                    )
                                details = retained_payload.get("details")
                                if not isinstance(details, dict):
                                    raise JournalIntegrityError(
                                        "mutation terminal details are malformed"
                                    )
                                retained_payload["details"] = {
                                    **details,
                                    **copy.deepcopy(candidate),
                                    "postcondition_verified": True,
                                }
                        core = {
                            **retained_payload,
                            "journal_version": _JOURNAL_VERSION,
                            "sequence": len(records) + 1,
                            "previous_hmac": previous,
                        }
                        record = {**core, "record_hmac": self._record_hmac(core)}
                        if not self._signed_journal_schema_valid(record):
                            raise JournalIntegrityError(
                                "combat journal record schema is invalid"
                            )
                        encoded = (
                            json.dumps(
                                record,
                                sort_keys=True,
                                allow_nan=False,
                                separators=(",", ":"),
                            )
                            + "\n"
                        ).encode("utf-8", errors="strict")
                        self._append_pinned_journal_bytes(encoded)
                        self._advance_recovery_anchor(record)
                        session = self._active_journal_session()
                        if session is None or not hmac.compare_digest(
                            self._active_journal_tail_bytes(session), encoded
                        ):
                            raise JournalIntegrityError(
                                "combat journal transaction verification failed"
                            )
                        authenticator = self._journal_cache_authenticator
                        if authenticator is None:
                            raise JournalIntegrityError(
                                "combat journal interior checkpoint is unavailable"
                            )
                        authenticator.update(encoded)
                        retained_record = copy.deepcopy(record)
                        records.append(retained_record)
                        info = self._assert_journal_session(session)
                        self._journal_cache_fingerprint = (
                            self._journal_fingerprint(info)
                        )
                        self._journal_cache_tail = encoded
                        record_type = str(record.get("record_type") or "")
                        action_id = str(record.get("action_id") or "")
                        if record_type == "commit" and action_id:
                            self._journal_cache_commits[action_id] = retained_record
                        elif (
                            record_type == "undo_commit"
                            and record.get("status") == "undone"
                            and record.get("undo_of")
                        ):
                            self._journal_cache_undone.add(
                                str(record["undo_of"])
                            )
                        self._journal_cache_graph_authenticator = (
                            self._journal_cache_graph_digest(records)
                        )
                    except Exception:
                        self._invalidate_journal_cache()
                        raise
        return record

    def _journal_has_capacity(self, required_records: int) -> bool:
        """Check worst-case record and byte capacity under journal custody."""
        records = self._validated_active_journal_cache()
        if records is None:
            self._read_journal(strict=True)
            records = self._validated_active_journal_cache()
        if records is None:  # pragma: no cover - strict read stores it
            raise JournalIntegrityError("combat journal checkpoint is unavailable")
        session = self._active_journal_session()
        if session is None:
            raise JournalIntegrityError("combat journal capacity lacks custody")
        info = self._assert_journal_session(session)
        required = max(1, int(required_records))
        required_bytes = required * (_MAX_JOURNAL_LINE_BYTES + 1)
        return bool(
            len(records) + required <= _MAX_JOURNAL_RECORDS
            and int(info.st_size) + required_bytes <= _MAX_JOURNAL_BYTES
        )

    def _reserve_journal_capacity(self, required_records: int) -> None:
        if self._journal_has_capacity(required_records):
            self._journal_saturated = False
            return
        self._journal_saturated = True
        self._journal_error = (
            "combat journal terminal capacity reservation is unavailable"
        )
        self.set_health(0, self._journal_error)
        raise JournalIntegrityError(self._journal_error)

    @contextmanager
    def _journaled_mutation(self, action: CombatAction) -> Iterator[None]:
        """Keep exact journal custody from intent through effect and terminal."""
        with self._receipt_lock:
            with self._journal_writer_lease():
                with self._pinned_journal_session(create=True):
                    self._reserve_journal_capacity(
                        _JOURNAL_MUTATION_RESERVE_RECORDS
                    )
                    self._journal_intent(action)
                    if self._validated_active_journal_cache() is None:
                        raise JournalIntegrityError(
                            "combat journal intent checkpoint is unavailable"
                        )
                    yield
                    if self._validated_active_journal_cache() is None:
                        raise JournalIntegrityError(
                            "combat journal terminal checkpoint is unavailable"
                        )

    def _journal_intent(self, action: CombatAction) -> None:
        self._append_journal({
            **asdict(action),
            "record_type": "intent",
            "status": "pending",
            "intent_at": time.time(),
        })

    @contextmanager
    def _terminal_commit_validator(
        self, validator: Callable[[], dict[str, Any]]
    ) -> Iterator[None]:
        """Bind an exact-object proof to the generic terminal writer.

        The validator is thread-local because the receipt lock serializes the
        transaction while nested helpers may still enter the journal writer.
        Calling it from the retained journal writer closes the former wrapper
        boundary where an alias could appear after the quarantine helper's
        final check but before the signed applied receipt.
        """
        previous = getattr(self._terminal_commit_local, "validator", None)
        self._terminal_commit_local.validator = validator
        try:
            yield
        finally:
            self._terminal_commit_local.validator = previous

    def _journal_commit(self, action: CombatAction) -> CombatAction:
        committed = CombatAction(
            **{
                **asdict(action),
                "details": {
                    **action.details,
                    "postcondition_verified": True,
                },
                "status": "applied",
            }
        )
        record = self._append_journal({
            **asdict(committed),
            "record_type": "commit",
            "committed_at": time.time(),
        })
        details = record.get("details")
        if not isinstance(details, dict):  # pragma: no cover - schema enforces this
            raise JournalIntegrityError("mutation terminal details are unavailable")
        return CombatAction(**{
            **asdict(committed),
            "details": copy.deepcopy(details),
        })

    def _commit_after_mutation(
        self,
        action: CombatAction,
        *,
        release_before_rollback: Callable[[], None] | None = None,
    ) -> CombatAction | None:
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

            # Some mutations retain an object handle that deliberately denies
            # a second delete/rename handle. Keep that custody through the
            # terminal commit attempt, then release it only if exact rollback
            # is required. The still-durable intent remains authoritative.
            if release_before_rollback is not None:
                try:
                    release_before_rollback()
                except Exception as release_exc:
                    self._trip_mutation_circuit(
                        orphan_record,
                        "mutation custody could not be released for rollback: "
                        f"{type(release_exc).__name__}",
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

    def _rollback_uncertain_reversible_mutation(
        self,
        action: CombatAction,
        reason: str,
        *,
        release_custody: Callable[[], None],
    ) -> None:
        """Durably orphan then reverse a mutation with an uncertain boundary."""
        orphan_payload = {
            **asdict(action),
            "record_type": "orphan",
            "status": "orphaned",
            "orphaned_at": time.time(),
            "error": str(reason)[:1000],
            "rollback_state": "pending",
        }
        try:
            orphan = self._append_journal(orphan_payload)
        except Exception:
            orphan = orphan_payload
        try:
            release_custody()
        except Exception as exc:
            self._trip_mutation_circuit(
                orphan,
                f"mutation custody release failed: {type(exc).__name__}",
            )
            return
        undo_id = f"undo-{uuid.uuid4().hex[:16]}"
        try:
            self._append_undo_phase(
                "undo_intent", orphan, undo_id, recovery=True
            )
        except Exception:
            self._trip_mutation_circuit(
                orphan, "uncertain mutation rollback intent was not durable"
            )
            return
        ok, rollback_error = self._undo_record(orphan)
        try:
            self._append_undo_phase(
                "undo_commit" if ok else "undo_failure",
                orphan,
                undo_id,
                error=rollback_error,
                recovery=True,
            )
        except Exception:
            ok = False
            rollback_error = "uncertain mutation rollback terminal was not durable"
        if ok:
            self._journal_failure(
                action, f"{reason}; uncertain mutation rolled back"
            )
            return
        self._trip_mutation_circuit(
            orphan, f"uncertain mutation rollback failed: {rollback_error}"
        )

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

    def _mark_nonreversible_uncertain(
        self, action: CombatAction, reason: str
    ) -> None:
        """Keep a possibly completed irreversible mutation non-terminal."""
        generation = str(action.details.get("mutation_generation") or "")
        if not _MUTATION_GENERATION.fullmatch(generation):
            generation = secrets.token_hex(16)
            action = CombatAction(**{
                **asdict(action),
                "details": {**action.details, "mutation_generation": generation},
            })
        orphan_payload = {
            **asdict(action),
            "record_type": "orphan",
            "status": "orphaned",
            "orphaned_at": time.time(),
            "error": str(reason)[:1000],
            "mutation_started": True,
            "rollback_state": "operator_disposition_required",
        }
        try:
            record = self._append_journal(orphan_payload)
        except Exception:
            # The fsynced intent remains the durable pending record. Current-run
            # authority still fails closed even if the richer orphan phase could
            # not be appended; restart reconstructs the circuit from the intent.
            record = orphan_payload
        self._trip_mutation_circuit(
            record,
            f"uncertain non-reversible mutation: {str(reason)[:900]}",
        )

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
        normalized_details = dict(details)
        if not reversible:
            normalized_details["mutation_generation"] = secrets.token_hex(16)
        return CombatAction(
            action_id=f"act-{uuid.uuid4().hex[:16]}",
            combat_id=combat_id,
            action=action,
            applied_at=time.time(),
            reversible=reversible,
            target=target,
            details=normalized_details,
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
                source_link_count = pinned.require_single_link()
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
                        "source_link_count": source_link_count,
                        "move_strategy": planned_strategy,
                    },
                )
                with self._journaled_mutation(action):
                    destination_identity = ""
                    try:
                        pinned.require_single_link()
                        destination_identity = pinned.rename_to(destination)
                        destination_link_count = pinned.require_single_link()
                        if pinned.sha256() != digest:
                            raise OSError("quarantine postcondition digest failed")
                        action = CombatAction(**{
                            **asdict(action),
                            "details": {
                                **action.details,
                                "file_identity": destination_identity,
                                "destination_link_count": destination_link_count,
                                "move_strategy": pinned.move_strategy,
                            },
                        })

                        def terminal_object_proof() -> dict[str, Any]:
                            link_count = pinned.require_single_link()
                            terminal_digest = pinned.sha256()
                            if terminal_digest != digest:
                                raise OSError(
                                    "quarantine terminal object digest drifted"
                                )
                            return {
                                "destination_link_count": link_count,
                                "terminal_object_sha256": terminal_digest,
                                "terminal_object_identity": pinned.identity,
                            }

                        # Retain exact object/directory custody and run the proof
                        # from inside the signed terminal writer. Any exception
                        # from the final check through the commit boundary is an
                        # orphaned moved object and follows exact rollback/recovery.
                        pinned.require_single_link()
                        if pinned.sha256() != digest:
                            raise OSError("quarantine pre-commit object drifted")
                        with self._terminal_commit_validator(terminal_object_proof):
                            return self._commit_after_mutation(
                                action,
                                release_before_rollback=pinned.close,
                            )
                    except Exception as exc:
                        if destination_identity:
                            action = CombatAction(**{
                                **asdict(action),
                                "details": {
                                    **action.details,
                                    "file_identity": destination_identity,
                                    "move_strategy": pinned.move_strategy,
                                },
                            })
                        self._rollback_uncertain_reversible_mutation(
                            action,
                            f"quarantine mutation boundary failed: "
                            f"{type(exc).__name__}",
                            release_custody=pinned.close,
                        )
                        return None
        except (OSError, RuntimeError, ValueError, JournalIntegrityError) as exc:
            if action is not None:
                self._journal_failure(action, f"{type(exc).__name__}: {exc}")
            return None

    def _terminate_process_transaction(
        self, process: Any, action: CombatAction
    ) -> CombatAction | None:
        """Serialize intent through commit/orphan for one irreversible kill.

        The same lock guards operator disposition.  A disposition therefore
        cannot observe or terminalize the bare in-flight intent while the host
        effect and its postcondition are still unresolved.
        """
        with self._receipt_lock:
            mutation_started = False
            try:
                with self._journaled_mutation(action):
                    try:
                        # Cross the uncertainty boundary before kill(): an
                        # exception from the call cannot prove that no effect
                        # occurred.
                        mutation_started = True
                        process.kill()
                        try:
                            process.wait(timeout=3)
                        except Exception:
                            pass
                        if process.is_running():
                            self._mark_nonreversible_uncertain(
                                action,
                                "process termination postcondition was not proven",
                            )
                            return None
                        return self._commit_after_mutation(action)
                    except Exception as exc:
                        if mutation_started:
                            self._mark_nonreversible_uncertain(
                                action, f"{type(exc).__name__}: {exc}"
                            )
                        else:
                            self._journal_failure(
                                action, f"{type(exc).__name__}: {exc}"
                            )
                        return None
            except Exception as exc:
                if mutation_started:
                    self._mark_nonreversible_uncertain(
                        action, f"{type(exc).__name__}: {exc}"
                    )
                else:
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
                with self._journaled_mutation(action):
                    process.suspend()
                    time.sleep(0.05)
                    verified = process.status() == getattr(
                        psutil, "STATUS_STOPPED", "stopped"
                    )
                    if not verified:
                        self._journal_failure(
                            action, "process suspend postcondition failed"
                        )
                        return actions
                    committed = self._commit_after_mutation(action)
                    if committed is not None:
                        actions.append(committed)
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
                committed = self._terminate_process_transaction(process, action)
                if committed is not None:
                    actions.append(committed)
                return actions
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

    @staticmethod
    def _mutation_generation_from_record(record: dict[str, Any]) -> str:
        details = record.get("details")
        if not isinstance(details, dict):
            return ""
        generation = str(details.get("mutation_generation") or "")
        return generation if _MUTATION_GENERATION.fullmatch(generation) else ""

    @classmethod
    def _valid_nonreversible_recovery_orphan(
        cls, record: dict[str, Any]
    ) -> bool:
        action = cls._combat_action_from_record(record)
        return bool(
            action is not None
            and not action.reversible
            and record.get("record_type") == "orphan"
            and record.get("status") == "orphaned"
            and record.get("mutation_started") is True
            and record.get("rollback_state") == "operator_disposition_required"
            and cls._mutation_generation_from_record(record)
            and isinstance(record.get("sequence"), int)
            and int(record["sequence"]) > 0
            and re.fullmatch(r"[0-9a-f]{64}", str(record.get("record_hmac") or ""))
        )

    @staticmethod
    def _normalized_recovery_reason(reason: object) -> str:
        return " ".join(str(reason).split())[:500]

    @classmethod
    def _valid_recovery_challenge(
        cls, challenge: dict[str, Any], orphan: dict[str, Any]
    ) -> bool:
        try:
            return bool(
                set(challenge) == _RECOVERY_CHALLENGE_FIELDS
                and cls._valid_nonreversible_recovery_orphan(orphan)
                and challenge.get("record_type") == "recovery_challenge"
                and challenge.get("action_id") == orphan.get("action_id")
                and challenge.get("combat_id") == orphan.get("combat_id")
                and challenge.get("action") == orphan.get("action")
                and challenge.get("status") == "authorization_pending"
                and challenge.get("disposition") in _RECOVERY_DISPOSITIONS
                and _HEX64.fullmatch(str(challenge.get("reason_digest") or ""))
                and challenge.get("bound_record_hmac") == orphan.get("record_hmac")
                and challenge.get("bound_record_sequence") == orphan.get("sequence")
                and challenge.get("mutation_generation")
                == cls._mutation_generation_from_record(orphan)
                and isinstance(challenge.get("challenge_counter"), int)
                and int(challenge["challenge_counter"]) > 0
                and _RECOVERY_CHALLENGE_NONCE.fullmatch(
                    str(challenge.get("challenge_nonce") or "")
                )
                and _RECOVERY_CHALLENGE_NONCE.fullmatch(
                    str(challenge.get("install_epoch") or "")
                )
                and isinstance(challenge.get("sequence"), int)
                and int(challenge["sequence"]) > int(orphan["sequence"])
                and math.isfinite(float(challenge.get("issued_at", -1)))
                and float(challenge["issued_at"]) >= 0
            )
        except (KeyError, TypeError, ValueError, OverflowError):
            return False

    @classmethod
    def _recovery_authorization_resource(
        cls,
        record: dict[str, Any],
        disposition: str,
        reason_digest: str,
        challenge: dict[str, Any],
    ) -> str:
        if (
            not cls._valid_recovery_challenge(challenge, record)
            or disposition not in _RECOVERY_DISPOSITIONS
            or not _HEX64.fullmatch(reason_digest)
            or challenge.get("disposition") != disposition
            or challenge.get("reason_digest") != reason_digest
        ):
            return ""
        state = {
            "contract": "angerona-combat-recovery-v2",
            "action_id": record["action_id"],
            "combat_id": record["combat_id"],
            "action": record["action"],
            "mutation_generation": cls._mutation_generation_from_record(record),
            "orphan_sequence": record["sequence"],
            "orphan_hmac": record["record_hmac"],
            "disposition": disposition,
            "reason_digest": reason_digest,
            "install_epoch": challenge["install_epoch"],
            "challenge_counter": challenge["challenge_counter"],
            "challenge_sequence": challenge["sequence"],
            "challenge_nonce": challenge["challenge_nonce"],
            "challenge_hmac": challenge["record_hmac"],
        }
        state_digest = hashlib.sha256(cls._canonical_record(state)).hexdigest()
        return (
            f"recovery:{record['action_id']}:{disposition}:"
            f"{reason_digest}:{state_digest[:24]}"
        )

    def _valid_operator_disposition(
        self,
        record: dict[str, Any],
        orphan: dict[str, Any],
        challenge: dict[str, Any] | None,
    ) -> bool:
        if (
            challenge is None
            or set(record) != _OPERATOR_DISPOSITION_FIELDS
            or not self._valid_recovery_challenge(challenge, orphan)
        ):
            return False
        disposition = str(record.get("disposition") or "")
        reason = self._normalized_recovery_reason(record.get("reason"))
        reason_digest = hashlib.sha256(reason.encode("utf-8", errors="strict")).hexdigest()
        expected_resource = self._recovery_authorization_resource(
            orphan, disposition, reason_digest, challenge
        )
        raw_decision = record.get("authorization_decision")
        if not isinstance(raw_decision, dict) or set(raw_decision) != set(
            AuthorizationDecision.__dataclass_fields__
        ):
            return False
        try:
            decision = AuthorizationDecision(
                **{
                    **raw_decision,
                    "matched_roles": tuple(raw_decision["matched_roles"]),
                }
            )
            disposed_at = float(record["disposed_at"])
        except (KeyError, TypeError, ValueError, OverflowError):
            return False
        policy = getattr(self._manager, "recovery_authorization_policy", None)
        try:
            verified = isinstance(policy, AuthorizationPolicy) and policy.verify_decision(
                decision
            )
        except Exception:
            verified = False
        return bool(
            record.get("record_type") == "operator_disposition"
            and record.get("action_id") == orphan.get("action_id")
            and record.get("combat_id") == orphan.get("combat_id")
            and record.get("action") == orphan.get("action")
            and record.get("status") == "operator_disposed"
            and disposition in _RECOVERY_DISPOSITIONS
            and len(reason) >= 12
            and record.get("reason") == reason
            and record.get("reason_digest") == reason_digest
            and math.isfinite(disposed_at)
            and disposed_at >= 0
            and record.get("bound_record_hmac") == orphan.get("record_hmac")
            and record.get("bound_record_sequence") == orphan.get("sequence")
            and record.get("mutation_generation")
            == self._mutation_generation_from_record(orphan)
            and record.get("bound_challenge_hmac") == challenge.get("record_hmac")
            and record.get("bound_challenge_sequence") == challenge.get("sequence")
            and record.get("bound_challenge_counter")
            == challenge.get("challenge_counter")
            and record.get("bound_challenge_nonce") == challenge.get("challenge_nonce")
            and record.get("install_epoch") == challenge.get("install_epoch")
            and record.get("authorization_resource") == expected_resource
            and verified
            and decision.allowed
            and decision.principal_kind == "human"
            and decision.permission == "response.execute"
            and decision.scope == _RECOVERY_AUTHORIZATION_SCOPE
            and decision.resource_id == expected_resource
            and record.get("operator_principal") == decision.principal_id
            and record.get("authorization_request_id") == decision.request_id
            and record.get("authorization_request_digest") == decision.request_digest
            and record.get("authorization_policy_hash") == decision.policy_hash
        )

    def _ordered_pending_phases(
        self, records: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """Replay each action in journal order and validate disposition binding."""
        pending: dict[str, dict[str, Any]] = {}
        challenges: dict[str, dict[str, Any]] = {}
        for record in records:
            action_id = str(record.get("action_id") or "")
            if not action_id:
                continue
            record_type = str(record.get("record_type") or "")
            if record_type in {"intent", "orphan"}:
                # A later orphan always reopens uncertainty, even if an invalid
                # earlier disposition was written by an older implementation.
                pending[action_id] = record
            elif record_type in {"commit", "failure"}:
                current = pending.get(action_id)
                if current is not None and self._valid_nonreversible_recovery_orphan(
                    current
                ):
                    # Once uncertainty is durable, only an exact operator
                    # disposition may close it; later generic terminal phases
                    # are semantically stale and cannot re-arm mutation.
                    self._journal_error = (
                        "automatic terminal phase followed recovery-required orphan"
                    )
                    continue
                pending.pop(action_id, None)
            elif record_type == "recovery_challenge":
                orphan = pending.get(action_id)
                if orphan is not None and self._valid_recovery_challenge(record, orphan):
                    challenges[action_id] = record
                else:
                    self._journal_error = (
                        "recovery challenge is not bound to the latest recovery orphan"
                    )
            elif record_type == "operator_disposition":
                orphan = pending.get(action_id)
                if orphan is None or not self._valid_operator_disposition(
                    record, orphan, challenges.get(action_id)
                ):
                    # The record can be HMAC-authentic yet semantically stale
                    # (for example, written by an older racing implementation).
                    # Reject its terminal effect and retain/reopen uncertainty.
                    self._journal_error = (
                        "operator disposition is not bound to the latest "
                        "recovery-required orphan"
                    )
                    continue
                pending.pop(action_id, None)
                challenges.pop(action_id, None)
        return pending

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
        pending_phases = self._ordered_pending_phases(records)
        commits: dict[str, dict[str, Any]] = {}
        undo_intents: dict[str, dict[str, Any]] = {}
        undo_terminal: set[str] = set()
        for record in records:
            record_type = record.get("record_type")
            action_id = str(record.get("action_id") or "")
            if record_type == "commit" and action_id:
                commits[action_id] = record
            elif record_type == "undo_intent":
                undo_intents[str(record.get("undo_id") or "")] = record
            elif record_type in {"undo_commit", "undo_failure"}:
                undo_terminal.add(str(record.get("undo_id") or ""))

        for action_id, record in pending_phases.items():
            action = self._combat_action_from_record(record)
            if action is None:
                raise JournalIntegrityError("signed intent schema is invalid")
            if not action.reversible:
                # A crash after a terminate intent cannot prove whether the
                # non-reversible host mutation happened. Keep the authenticated
                # intent pending until a human-authorized disposition is durable.
                reason = (
                    "orphaned non-reversible intent requires authenticated "
                    "operator disposition"
                )
                if self._valid_nonreversible_recovery_orphan(record):
                    self._trip_mutation_circuit(record, reason)
                else:
                    self._mark_nonreversible_uncertain(action, reason)
            elif self._intent_effect_present(record):
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
                self._journal_failure(
                    action, "orphaned intent had no observed postcondition"
                )

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
            with self._receipt_lock:
                with self._journal_writer_lease():
                    with self._pinned_journal_session(create=True):
                        # Restart compensation is itself a host mutation.  Keep
                        # the exact journal object pinned from intent recovery
                        # through every effect and its durable terminal.
                        self._recover_orphaned_journal()
                        self._journal_saturated = not self._journal_has_capacity(
                            _JOURNAL_MUTATION_RESERVE_RECORDS
                        )
        except (JournalIntegrityError, OSError, RuntimeError, ValueError) as exc:
            self._journal_error = str(exc)
            self._journal_saturated = True
            self._mutation_blocked = True
            self.set_health(0, "combat journal integrity failure")
            return False
        for record in self.list_actions(limit=None):
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
        if self._journal_saturated:
            self.set_health(
                0,
                "combat journal cannot reserve a complete mutation terminal; "
                "new response mutations are disarmed",
            )
            return False
        return True

    def _pending_recovery_records(self) -> dict[str, dict[str, Any]]:
        """Return authenticated mutation intents that have no terminal phase."""
        signed, _legacy = self._read_journal(strict=True)
        return self._ordered_pending_phases(signed)

    def recovery_authorization_resource(
        self,
        action_id: str,
        *,
        disposition: str,
        reason: str,
    ) -> str:
        """Issue one process-local, monotonic, orphan-bound approval challenge."""
        action_token = str(action_id)
        disposition_token = str(disposition).strip().casefold()
        reason_text = self._normalized_recovery_reason(reason)
        reason_digest = hashlib.sha256(
            reason_text.encode("utf-8", errors="strict")
        ).hexdigest()
        if (
            not re.fullmatch(r"act-[0-9a-f]{16}", action_token)
            or disposition_token not in _RECOVERY_DISPOSITIONS
            or len(reason_text) < 12
        ):
            return ""
        with self._receipt_lock:
            try:
                record = self._pending_recovery_records().get(action_token)
            except JournalIntegrityError:
                return ""
            current = self._recovery_required.get(action_token)
            if (
                not self._mutation_blocked
                or record is None
                or current is None
                or current.get("record_hmac") != record.get("record_hmac")
            ):
                return ""
            active = self._recovery_challenges.get(action_token)
            if (
                active is not None
                and active.get("orphan_hmac") == record.get("record_hmac")
                and active.get("disposition") == disposition_token
                and active.get("reason_digest") == reason_digest
                and active.get("process_epoch") == self._process_epoch
                and time.monotonic() - float(active.get("issued_monotonic", -1.0))
                <= _RECOVERY_AUTHORIZATION_MAX_AGE_S
            ):
                return str(active.get("resource") or "")
            try:
                anchor = self._recovery_anchor(allow_create=False)
                challenge = self._append_journal({
                    "record_type": "recovery_challenge",
                    "action_id": action_token,
                    "combat_id": record["combat_id"],
                    "action": record["action"],
                    "status": "authorization_pending",
                    "disposition": disposition_token,
                    "reason_digest": reason_digest,
                    "bound_record_hmac": record["record_hmac"],
                    "bound_record_sequence": record["sequence"],
                    "mutation_generation": self._mutation_generation_from_record(record),
                    "challenge_counter": int(anchor["challenge_counter"]) + 1,
                    "challenge_nonce": secrets.token_hex(16),
                    "install_epoch": anchor["install_epoch"],
                    "issued_at": time.time(),
                })
            except Exception as exc:
                self._trip_mutation_circuit(
                    record,
                    f"recovery challenge was not durable: {type(exc).__name__}",
                )
                return ""
            resource = self._recovery_authorization_resource(
                record, disposition_token, reason_digest, challenge
            )
            if not resource:
                self._trip_mutation_circuit(record, "recovery challenge schema rejected")
                return ""
            self._recovery_challenges[action_token] = {
                "record": challenge,
                "resource": resource,
                "orphan_hmac": record["record_hmac"],
                "disposition": disposition_token,
                "reason_digest": reason_digest,
                "issued_monotonic": time.monotonic(),
                "process_epoch": self._process_epoch,
            }
            return resource

    def resolve_nonreversible_recovery(
        self,
        action_id: str,
        *,
        disposition: str,
        reason: str,
        decision: AuthorizationDecision,
    ) -> dict[str, Any]:
        """Durably close one uncertain mutation with fresh human authority.

        There is intentionally no automatic disposition path. The RBAC receipt
        must be HMAC-valid, allowed for ``response.execute``, bound to this exact
        action, issued to a human principal, and fresh when it is consumed.
        """
        action_token = str(action_id)
        disposition_token = str(disposition).strip().casefold()
        reason_text = self._normalized_recovery_reason(reason)
        if (
            not re.fullmatch(r"act-[0-9a-f]{16}", action_token)
            or disposition_token not in _RECOVERY_DISPOSITIONS
            or len(reason_text) < 12
        ):
            return {"ok": False, "error": "invalid recovery disposition request"}
        authorization_policy = getattr(
            self._manager, "recovery_authorization_policy", None
        )
        if not isinstance(authorization_policy, AuthorizationPolicy) or not isinstance(
            decision, AuthorizationDecision
        ):
            return {"ok": False, "error": "authenticated operator receipt required"}
        with self._receipt_lock:
            stamp = time.time()
            try:
                record = self._pending_recovery_records().get(action_token)
            except JournalIntegrityError as exc:
                return {"ok": False, "error": str(exc)}
            action = self._combat_action_from_record(record or {})
            current = self._recovery_required.get(action_token)
            if (
                record is None
                or action is None
                or action.reversible
                or not self._mutation_blocked
                or current is None
                or current.get("record_hmac") != record.get("record_hmac")
                or not self._valid_nonreversible_recovery_orphan(record)
            ):
                return {
                    "ok": False,
                    "error": "exact recovery-required orphan is not available",
                }
            reason_digest = hashlib.sha256(
                reason_text.encode("utf-8", errors="strict")
            ).hexdigest()
            active = self._recovery_challenges.get(action_token)
            challenge = active.get("record") if isinstance(active, dict) else None
            if (
                not isinstance(challenge, dict)
                or active.get("process_epoch") != self._process_epoch
                or active.get("orphan_hmac") != record.get("record_hmac")
                or active.get("disposition") != disposition_token
                or active.get("reason_digest") != reason_digest
                or time.monotonic() - float(active.get("issued_monotonic", -1.0))
                > _RECOVERY_AUTHORIZATION_MAX_AGE_S
            ):
                return {"ok": False, "error": "recovery challenge is absent or expired"}
            expected_resource = self._recovery_authorization_resource(
                record, disposition_token, reason_digest, challenge
            )
            try:
                verified = authorization_policy.verify_decision(decision)
            except Exception:
                verified = False
            if not (
                expected_resource
                and verified
                and decision.allowed
                and decision.principal_kind == "human"
                and decision.permission == "response.execute"
                and decision.scope == _RECOVERY_AUTHORIZATION_SCOPE
                and decision.resource_id == expected_resource
            ):
                return {"ok": False, "error": "operator authorization receipt rejected"}
            try:
                anchor = self._recovery_anchor(allow_create=False)
            except JournalIntegrityError as exc:
                self._trip_mutation_circuit(record, str(exc))
                return {"ok": False, "error": str(exc)}
            if (
                anchor.get("active_action_id") != action_token
                or anchor.get("active_challenge_sequence") != challenge.get("sequence")
                or anchor.get("active_challenge_nonce") != challenge.get("challenge_nonce")
                or anchor.get("challenge_counter") != challenge.get("challenge_counter")
            ):
                return {"ok": False, "error": "recovery challenge was superseded"}
            generation = self._mutation_generation_from_record(record)
            try:
                receipt = self._append_journal({
                    "record_type": "operator_disposition",
                    "action_id": action_token,
                    "combat_id": action.combat_id,
                    "action": action.action,
                    "status": "operator_disposed",
                    "disposition": disposition_token,
                    "reason": reason_text,
                    "reason_digest": reason_digest,
                    "disposed_at": stamp,
                    "operator_principal": decision.principal_id,
                    "authorization_request_id": decision.request_id,
                    "authorization_request_digest": decision.request_digest,
                    "authorization_policy_hash": decision.policy_hash,
                    "authorization_resource": expected_resource,
                    "authorization_decision": asdict(decision),
                    "bound_record_hmac": str(record.get("record_hmac") or ""),
                    "bound_record_sequence": int(record["sequence"]),
                    "mutation_generation": generation,
                    "bound_challenge_hmac": challenge["record_hmac"],
                    "bound_challenge_sequence": challenge["sequence"],
                    "bound_challenge_counter": challenge["challenge_counter"],
                    "bound_challenge_nonce": challenge["challenge_nonce"],
                    "install_epoch": challenge["install_epoch"],
                })
            except Exception as exc:
                self._trip_mutation_circuit(
                    record, f"operator disposition journal failed: {type(exc).__name__}"
                )
                return {"ok": False, "error": "operator disposition was not durable"}

            self._recovery_challenges.pop(action_token, None)
            self._recovery_required.pop(action_token, None)
            try:
                pending = self._pending_recovery_records()
            except JournalIntegrityError as exc:
                self._trip_mutation_circuit(record, str(exc))
                return {"ok": False, "error": str(exc)}
            if not pending:
                self._mutation_blocked = False
                self._journal_error = ""
                self.set_health(100, "standing authority armed by operator disposition")
            self.emit(
                "Adversary Combat recovery disposition recorded by an authenticated "
                "operator.",
                Severity.INFO,
                disposition="health",
                response_authorized=False,
                recovery_required=bool(pending),
                action_id=action_token,
                recovery_disposition=disposition_token,
                operator_principal=decision.principal_id,
            )
            return {
                "ok": True,
                "action_id": action_token,
                "disposition": disposition_token,
                "recovery_required": bool(pending),
                "receipt_hmac": receipt["record_hmac"],
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
            with self._journaled_mutation(action):
                applied: list[str] = []
                for direction in ("out", "in"):
                    if self._run_firewall([
                        "add", "rule", f"name={rule}-{direction}",
                        f"dir={direction}", "action=block",
                        f"remoteip={remote_ip}", "enable=yes",
                    ]):
                        applied.append(f"{rule}-{direction}")
                if len(applied) != 2:
                    for partial in applied:
                        self._run_firewall(["delete", "rule", f"name={partial}"])
                    self._journal_failure(
                        action, "firewall block was incomplete and rolled back"
                    )
                    return None
                self._blocked_ips.add(remote_ip)
                return self._commit_after_mutation(action)
        except JournalIntegrityError:
            return None

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
            with self._journaled_mutation(action):
                if not self._run_firewall([
                    "add", "rule", f"name={rule}", "dir=out", "action=block",
                    f"program={exe}", "enable=yes",
                ]):
                    self._journal_failure(
                        action, "program firewall postcondition failed"
                    )
                    return None
                identity_matches = False
                try:
                    current = psutil.Process(pid) if psutil is not None else None
                    current_exe = current.exe() if current is not None else ""
                    identity_matches = bool(
                        current is not None
                        and abs(
                            float(current.create_time()) - float(create_time)
                        ) <= 0.001
                        and os.path.normcase(os.path.abspath(current_exe))
                        == program_key
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
        except JournalIntegrityError:
            return None

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
            with self._journaled_mutation(action):
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
                    self._journal_failure(
                        action,
                        "host isolation was incomplete and rolled back",
                    )
                    return None
                self._host_isolated = True
                return self._commit_after_mutation(action)
        except JournalIntegrityError:
            return None

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
            with self._journaled_mutation(action):
                module.start()
                self._honeypot_started_by_combat = True
                if module.status != "running":
                    self._journal_failure(
                        action, "deception start postcondition failed"
                    )
                    return None
                if event is None:
                    # Startup actions are journalled too; callers do not need to
                    # count them as a response to a detector event.
                    self._commit_after_mutation(action)
                    return None
                return self._commit_after_mutation(action)
        except Exception as exc:
            self._journal_failure(action, f"{type(exc).__name__}: {exc}")
            return None

    def list_actions(self, limit: int | None = 100) -> list[dict[str, Any]]:
        signed, legacy = self._read_journal()
        commits: dict[str, dict[str, Any]] = {}
        pending = self._ordered_pending_phases(signed)
        undone: set[str] = set()
        for record in signed:
            record_type = record.get("record_type")
            action_id = str(record.get("action_id") or "")
            if record_type == "commit" and action_id:
                commits[action_id] = record
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
        if limit is None:
            return combined[::-1]
        return combined[-max(1, int(limit)):][::-1]

    def _trusted_action(self, action_id: str) -> tuple[dict[str, Any] | None, bool]:
        records = self._validated_active_journal_cache()
        if records is None:
            self._read_journal(strict=True)
            records = self._validated_active_journal_cache()
        if records is not None:
            record = self._journal_cache_commits.get(action_id)
            return (
                copy.deepcopy(record) if record is not None else None,
                action_id in self._journal_cache_undone,
            )
        # Direct diagnostic callers outside retained journal custody keep the
        # historical behavior; mutation callers always use the O(1) index.
        signed, _legacy = self._read_journal(strict=True)
        record = next(
            (
                item
                for item in reversed(signed)
                if item.get("record_type") == "commit"
                and item.get("action_id") == action_id
            ),
            None,
        )
        undone = any(
            item.get("record_type") == "undo_commit"
            and item.get("undo_of") == action_id
            and item.get("status") == "undone"
            for item in signed
        )
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
        for record in self.list_actions(limit=None):
            if record.get("reversible") is True and not record.get("undone"):
                return self.undo_action(str(record.get("action_id")))
        return {"ok": False, "error": "no reversible combat action is pending"}

    def undo_all(self) -> dict[str, Any]:
        """Undo every still-applied reversible action, newest first."""
        results = []
        for record in self.list_actions(limit=None):
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
            with self._receipt_lock:
                with self._journal_writer_lease():
                    with self._pinned_journal_session(create=True):
                        self._reserve_journal_capacity(
                            _JOURNAL_UNDO_RESERVE_RECORDS
                        )
                        return self._undo_action_under_custody(action_id)
        except Exception as exc:
            return {
                "ok": False,
                "action_id": str(action_id),
                "error": str(exc),
            }

    def _undo_action_under_custody(self, action_id: str) -> dict[str, Any]:
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
            reason = f"undo journal commit failed: {type(exc).__name__}"
            self._trip_mutation_circuit(record, reason)
            return {
                "ok": False,
                "action_id": action_id,
                "action": action,
                "error": reason,
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
