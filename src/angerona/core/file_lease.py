"""Small fail-fast OS file lease used by single-writer security authorities."""
from __future__ import annotations

import os
import stat
from pathlib import Path


class ExclusiveFileLeaseError(RuntimeError):
    """An exclusive authority lease could not be acquired safely."""


class ExclusiveFileLease:
    """Hold one byte-range/file lock until explicitly closed.

    The lock is intentionally non-blocking: a second authority process must
    fail visible instead of serving a fork while it waits for an ambiguous
    predecessor.  The lock file is retained after close; only the OS lock is
    authoritative.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._descriptor = -1
        self._closed = True
        self._acquire()

    def _acquire(self) -> None:
        candidate = self.path
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
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(os.fspath(candidate), flags, 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ExclusiveFileLeaseError("authority lease is not a regular file")
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
        except ExclusiveFileLeaseError:
            if "descriptor" in locals():
                os.close(descriptor)
            raise
        except (OSError, BlockingIOError) as exc:
            if "descriptor" in locals():
                os.close(descriptor)
            raise ExclusiveFileLeaseError("authority lease is already held or unavailable") from exc
        self._descriptor = descriptor
        self._closed = False

    @property
    def held(self) -> bool:
        return not self._closed and self._descriptor >= 0

    def close(self) -> None:
        if self._closed:
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
            os.close(descriptor)

    def __enter__(self) -> "ExclusiveFileLease":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


__all__ = ["ExclusiveFileLease", "ExclusiveFileLeaseError"]
