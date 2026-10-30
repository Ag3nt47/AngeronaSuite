"""Small fail-fast OS file lease used by single-writer security authorities."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable


_PRIVATE_RETIREMENT_HOLDS: list[object] = []


class ExclusiveFileLeaseError(RuntimeError):
    """An exclusive authority lease could not be acquired safely."""


class PrivateLeaseRetirementHeld(ExclusiveFileLeaseError):
    """A private-opener lease retains an ambiguously retired descriptor."""

    def __init__(self, owner):
        super().__init__("Private authority lease descriptor retirement remains unproven")
        self.owner = owner


class ExclusiveFileLease:
    """Hold one byte-range/file lock until explicitly closed.

    The lock is intentionally non-blocking: a second authority process must
    fail visible instead of serving a fork while it waits for an ambiguous
    predecessor.  The lock file is retained after close; only the OS lock is
    authoritative.
    """

    def __init__(self, path: str | Path, *, opener: Callable | None = None) -> None:
        self.path = Path(path)
        self._private_opener = opener
        self._private_candidate = Path(os.path.abspath(self.path)) if opener is not None else None
        self._descriptor = -1
        self._closed = True
        self._ambiguous_descriptor = None
        self._cleanup_proven = True
        self._acquire()

    def _acquire(self) -> None:
        candidate = self.path if self._private_opener is None else self._private_candidate
        candidate.parent.mkdir(parents=True, exist_ok=True)
        if candidate.is_symlink() or candidate.parent.is_symlink():
            raise ExclusiveFileLeaseError("authority lease path is an alias")
        if os.name == "nt":
            try:
                from angerona.core.data_paths import _is_reparse_point

                if _is_reparse_point(candidate) or _is_reparse_point(candidate.parent):
                    raise ExclusiveFileLeaseError("authority lease path is reparse-backed")
            except ExclusiveFileLeaseError:
                raise
            except Exception as exc:
                raise ExclusiveFileLeaseError(
                    "authority lease reparse status is unavailable"
                ) from exc
        try:
            named = candidate.lstat()
        except FileNotFoundError:
            named = None
        except OSError as exc:
            raise ExclusiveFileLeaseError("authority lease identity is unavailable") from exc
        if named is not None and (
            not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
            or getattr(named, "st_file_attributes", 0) & 0x400
        ):
            raise ExclusiveFileLeaseError("authority lease is not a single-link regular file")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        # A supplied built-in private opener verifies/creates custody before
        # the first lease byte. Default callers keep their existing path.
        if self._private_opener is not None:
            held_owner = next((owner for owner in _PRIVATE_RETIREMENT_HOLDS
                               if owner._private_candidate == candidate), None)
            if held_owner is not None:
                raise PrivateLeaseRetirementHeld(held_owner)
            descriptor = self._private_opener(candidate, flags, 0o600)
        try:
            if self._private_opener is None:
                descriptor = os.open(os.fspath(candidate), flags, 0o600)
            info = os.fstat(descriptor)
            # Validate the actual descriptor and its named identity BEFORE the
            # first write. An empty hardlink must never receive the NUL byte.
            current = candidate.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                    or getattr(info, "st_file_attributes", 0) & 0x400
                    or getattr(current, "st_file_attributes", 0) & 0x400
                    or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
                raise ExclusiveFileLeaseError("authority lease is not the named single-link regular file")
            if info.st_size == 0:
                os.write(descriptor, b"\x00")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException as exc:
            if self._private_opener is not None:
                if "descriptor" in locals():
                    try:
                        os.close(descriptor)
                    except BaseException as close_exc:
                        self._hold_private_descriptor(descriptor)
                        raise PrivateLeaseRetirementHeld(self) from close_exc
                if isinstance(exc, (ExclusiveFileLeaseError, OSError)):
                    raise ExclusiveFileLeaseError("authority lease is already held or unavailable") from exc
                raise
            if isinstance(exc, ExclusiveFileLeaseError):
                if "descriptor" in locals():
                    os.close(descriptor)
                raise
            if not isinstance(exc, OSError):
                raise
            if "descriptor" in locals():
                os.close(descriptor)
            raise ExclusiveFileLeaseError("authority lease is already held or unavailable") from exc
        self._descriptor = descriptor
        self._closed = False

    def _hold_private_descriptor(self, descriptor):
        self._ambiguous_descriptor = descriptor
        self._cleanup_proven = False
        if not any(owner is self for owner in _PRIVATE_RETIREMENT_HOLDS):
            _PRIVATE_RETIREMENT_HOLDS.append(self)

    @property
    def held(self) -> bool:
        return not self._closed and self._descriptor >= 0

    def close(self) -> None:
        if self._closed:
            if self._private_opener is not None and not self._cleanup_proven:
                raise PrivateLeaseRetirementHeld(self)
            return
        descriptor = self._descriptor
        self._descriptor = -1
        self._closed = True
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            if self._private_opener is None:
                os.close(descriptor)
            else:
                try:
                    os.close(descriptor)
                except BaseException as exc:
                    self._hold_private_descriptor(descriptor)
                    raise PrivateLeaseRetirementHeld(self) from exc

    def __enter__(self) -> "ExclusiveFileLease":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


__all__ = ["ExclusiveFileLease", "ExclusiveFileLeaseError", "PrivateLeaseRetirementHeld"]
