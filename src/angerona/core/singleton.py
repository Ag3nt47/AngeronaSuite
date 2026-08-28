"""Authenticated, OS-backed single-instance lease.

The old implementation used a fixed loopback port. Any local process could
bind that port and make an elevated Angerona launch report that another copy
was running. The lease now lives directly in Angerona's protected data root
and uses the operating system's non-blocking file-lock primitive. A companion
record lets a later launch prove that the lock owner is a live instance of the
same executable before it yields.

The lock file is intentionally never deleted: unlinking a locked inode permits
two processes to lock different files at the same pathname. ``close()`` only
releases the kernel lease and closes its handle.
"""
from __future__ import annotations

import errno
import json
import os
import secrets
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Optional

import psutil

from angerona.core.atomic_io import replace_with_retry
from angerona.core.data_paths import data_dir
from angerona.core.hardening import key_acl_required, secure_sensitive_file

_LOCK_NAME = "angerona.instance.lock"
_RECORD_NAME = "angerona.instance.json"
_RECORD_SCHEMA = "angerona.instance-lease.v1"
_MAX_RECORD_BYTES = 4096
_RECORD_READ_ATTEMPTS = 4


class SingletonError(RuntimeError):
    """The singleton boundary could not establish trustworthy ownership."""


def _canonical_executable(path: str | os.PathLike[str]) -> str:
    resolved = os.path.realpath(os.path.abspath(os.fspath(path)))
    return os.path.normcase(resolved)


def _process_record() -> dict[str, object]:
    process = psutil.Process(os.getpid())
    executable = process.exe() or sys.executable
    return {
        "schema": _RECORD_SCHEMA,
        "pid": os.getpid(),
        "process_started_at": round(float(process.create_time()), 6),
        "executable": _canonical_executable(executable),
        "launcher": _canonical_executable(sys.executable),
        "lease_written_at": round(time.time(), 6),
    }


def _write_record(path: Path, record: dict[str, object]) -> None:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > _MAX_RECORD_BYTES:
        raise SingletonError("instance record exceeded its bounded size")
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    )
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            secure_sensitive_file(temporary, required=key_acl_required())
            replace_with_retry(temporary, path)
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _read_record(path: Path) -> dict[str, object]:
    last_error: Exception | None = None
    for attempt in range(_RECORD_READ_ATTEMPTS):
        try:
            with path.open("rb") as stream:
                payload = stream.read(_MAX_RECORD_BYTES + 1)
            if not payload or len(payload) > _MAX_RECORD_BYTES:
                raise SingletonError("instance ownership record is empty or oversized")
            decoded = json.loads(payload.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise SingletonError("instance ownership record is not an object")
            return decoded
        except (OSError, UnicodeError, json.JSONDecodeError, SingletonError) as exc:
            last_error = exc
            if attempt + 1 < _RECORD_READ_ATTEMPTS:
                time.sleep(0.02 * (attempt + 1))
    raise SingletonError("unable to read a trustworthy instance ownership record") from last_error


def _verified_incumbent(record: dict[str, object]) -> bool:
    if record.get("schema") != _RECORD_SCHEMA:
        return False
    try:
        pid = int(record["pid"])
        recorded_start = float(record["process_started_at"])
        recorded_executable = _canonical_executable(str(record["executable"]))
        recorded_launcher = _canonical_executable(str(record["launcher"]))
    except (KeyError, TypeError, ValueError, OSError):
        return False
    if pid <= 0 or not recorded_executable:
        return False
    try:
        process = psutil.Process(pid)
        actual_executable = _canonical_executable(process.exe())
        actual_start = float(process.create_time())
    except (psutil.Error, OSError, ValueError):
        return False
    return (
        actual_executable == recorded_executable
        and recorded_launcher == _canonical_executable(sys.executable)
        and abs(actual_start - recorded_start) <= 0.01
    )


def _try_lock(stream: BinaryIO) -> None:
    stream.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(stream: BinaryIO) -> None:
    stream.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _is_contention(exc: OSError) -> bool:
    return exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}


def _open_lock_file(path: Path) -> BinaryIO:
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SingletonError("instance lease target is not a regular file")
        stream = os.fdopen(descriptor, "r+b", buffering=0, closefd=True)
        descriptor = -1
        if info.st_size == 0:
            stream.write(b"\0")
            stream.flush()
            os.fsync(stream.fileno())
        secure_sensitive_file(path, required=key_acl_required())
        return stream
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        raise


@dataclass(slots=True)
class InstanceLease:
    """Held kernel lease returned to the application for its full lifetime."""

    path: Path
    _stream: BinaryIO = field(repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            _unlock(self._stream)
        except OSError:
            pass
        finally:
            self._stream.close()

    def __enter__(self) -> "InstanceLease":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - interpreter-shutdown guard
        try:
            self.close()
        except Exception:
            pass


def acquire_single_instance() -> Optional[InstanceLease]:
    """Acquire the protected process lease.

    ``None`` is returned only when the incumbent lock record proves a live
    process using this exact executable. Corrupt records, unsafe paths and
    unrelated lock owners raise :class:`SingletonError` so startup fails
    visibly instead of silently yielding to a squatter.
    """
    root = data_dir()
    lock_path = root / _LOCK_NAME
    record_path = root / _RECORD_NAME
    try:
        stream = _open_lock_file(lock_path)
    except Exception as exc:
        if isinstance(exc, SingletonError):
            raise
        raise SingletonError("unable to open the protected instance lease") from exc
    try:
        _try_lock(stream)
    except OSError as exc:
        stream.close()
        if not _is_contention(exc):
            raise SingletonError("operating-system instance lock failed") from exc
        record = _read_record(record_path)
        if _verified_incumbent(record):
            return None
        raise SingletonError(
            "instance lease is held but its owner is not a verified Angerona process"
        ) from exc
    try:
        _write_record(record_path, _process_record())
        return InstanceLease(path=lock_path, _stream=stream)
    except Exception:
        try:
            _unlock(stream)
        finally:
            stream.close()
        raise
