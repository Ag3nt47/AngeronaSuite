"""Bounded, optional retention for disposable runtime-alert diagnostics.

This deliberately does not prune the signed flight recorder, its pending spool,
case evidence, action receipts, recovery data, exports, or arbitrary directories.
Only this writer's closed ``runtime_alerts.<time_ns>.<uuid>.log`` segments are
eligible. Deletion is irreversible; a sibling ``.keep`` file pins a segment.
"""
from __future__ import annotations

import contextlib
import dataclasses
import heapq
import math
import os
import queue
import re
import stat
import threading
import time
import uuid
from pathlib import Path

ACTIVE_NAME = "runtime_alerts.log"
SEGMENT_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_ENTRIES = 1024
MAX_DELETIONS = 64
_ARCHIVE = re.compile(r"runtime_alerts\.[0-9]{1,20}\.[a-f0-9]{32}\.log\Z")
_LOCK_NAME = ".runtime-alert-retention.lock"


@dataclasses.dataclass(frozen=True)
class RetentionPolicy:
    enabled: bool = True
    days: int = 30
    max_mib: int = 256

    def __post_init__(self):
        if type(self.enabled) is not bool:
            raise ValueError("Alert retention enabled must be a boolean")
        if type(self.days) is not int or not 1 <= self.days <= 3650:
            raise ValueError("Alert retention days must be between 1 and 3650")
        if type(self.max_mib) is not int or not 8 <= self.max_mib <= 16384:
            raise ValueError("Alert archive size must be between 8 and 16384 MiB")

    @classmethod
    def from_config(cls, config):
        def read(name, default):
            if isinstance(config, dict):
                return config.get(name, default)
            return getattr(config, name, default)
        enabled = read("alert_retention_enabled", True)
        days = read("alert_retention_days", 30)
        mib = read("alert_retention_max_mib", 256)
        return cls(
            enabled if type(enabled) is bool else True,
            days if type(days) is int and 1 <= days <= 3650 else 30,
            mib if type(mib) is int and 8 <= mib <= 16384 else 256,
        )


def _plain(info, *, directory=False):
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Alert diagnostics refuse links and reparse points")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Alert diagnostics require a plain directory")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Alert diagnostics require a single-link regular file")


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


@contextlib.contextmanager
def _directory(root: Path, *, create: bool):
    """Hold the namespace; POSIX operations use the final directory descriptor."""
    root = Path(os.path.abspath(root))
    directory = root / "diagnostics"
    if os.name == "nt":
        from angerona.core.source_sandbox import _hold_plain_directories
        with _hold_plain_directories(root):
            if create:
                try:
                    directory.mkdir(mode=0o700)
                except FileExistsError:
                    pass
            if not os.path.lexists(directory):
                yield None
                return
            with _hold_plain_directories(directory):
                yield _Directory(directory, None)
        return
    descriptors = []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(root.anchor, flags)
        descriptors.append(descriptor)
        for component in root.parts[1:]:
            descriptor = os.open(component, flags, dir_fd=descriptor)
            descriptors.append(descriptor)
        if create:
            try:
                os.mkdir("diagnostics", mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
        try:
            descriptor = os.open("diagnostics", flags, dir_fd=descriptor)
        except FileNotFoundError:
            yield None
            return
        descriptors.append(descriptor)
        info = os.fstat(descriptor)
        _plain(info, directory=True)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError("Alert diagnostics must be owned by this account and not publicly writable")
        yield _Directory(directory, descriptor)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


class _Directory:
    def __init__(self, path, descriptor):
        self.path = path
        self.descriptor = descriptor

    def stat(self, name):
        if self.descriptor is None:
            return (self.path / name).lstat()
        return os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)

    def exists(self, name):
        try:
            self.stat(name)
            return True
        except FileNotFoundError:
            return False

    def entries(self):
        return os.scandir(self.path if self.descriptor is None else self.descriptor)

    def open(self, name, *, create=False, lease=False):
        if "/" in name or "\\" in name or name in {".", ".."}:
            raise ValueError("Invalid alert archive name")
        return _File(self, name, create=create, lease=lease)


class _File:
    def __init__(self, directory, name, *, create=False, lease=False):
        self.directory, self.name = directory, name
        self.descriptor = -1
        if os.name == "nt":
            import ctypes
            import msvcrt
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CreateFileW.argtypes = (
                wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
            )
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel.CloseHandle.restype = wintypes.BOOL
            access = 0xC0000000 | (0 if lease else 0x10000)
            handle = kernel.CreateFileW(
                str(directory.path / name), access, 3 if lease else 1, None,
                4 if create else 3, 0x00200000, None,
            )  # OPEN_REPARSE_POINT; never follow the leaf, deny other writers/deleters.
            if handle == wintypes.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                self.descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
            except BaseException:
                kernel.CloseHandle(handle)
                raise
        else:
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if create:
                flags |= os.O_CREAT
            self.descriptor = os.open(name, flags, 0o600, dir_fd=directory.descriptor)
        try:
            _plain(os.fstat(self.descriptor))
            # Validate the no-follow directory entry against the opened object,
            # including reparse attributes that CRT fstat can omit on Windows.
            entry = directory.stat(name)
            _plain(entry)
            if (entry.st_dev, entry.st_ino) != (
                os.fstat(self.descriptor).st_dev, os.fstat(self.descriptor).st_ino
            ):
                raise ValueError("Alert diagnostic handle changed identity")
            if os.name != "nt":
                import fcntl
                fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif lease:
                import msvcrt
                # Byte-range locks extend beyond EOF; no pre-lock write is needed.
                msvcrt.locking(self.descriptor, msvcrt.LK_NBLCK, 1)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def info(self):
        info = os.fstat(self.descriptor)
        _plain(info)
        return info

    def _set_information(self, kind, value):
        import ctypes
        import msvcrt
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        setter = kernel.SetFileInformationByHandle
        setter.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
        setter.restype = wintypes.BOOL
        if not setter(msvcrt.get_osfhandle(self.descriptor), kind,
                      ctypes.byref(value), ctypes.sizeof(value)):
            raise ctypes.WinError(ctypes.get_last_error())

    def rename(self, target):
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            encoded = str(self.directory.path / target).encode("utf-16-le")
            class Rename(ctypes.Structure):
                _fields_ = [("replace", wintypes.BOOLEAN), ("root", wintypes.HANDLE),
                            ("length", wintypes.DWORD), ("name", ctypes.c_byte * len(encoded))]
            value = Rename()
            value.length = len(encoded)
            value.name[:] = encoded
            self._set_information(3, value)  # exact held inode; ReplaceIfExists remains false
        else:
            current = self.directory.stat(self.name)
            if _identity(current) != _identity(self.info()):
                raise ValueError("Active alert log changed during rotation")
            if self.directory.exists(target):
                raise FileExistsError(target)
            os.rename(self.name, target, src_dir_fd=self.directory.descriptor,
                      dst_dir_fd=self.directory.descriptor)
            if _identity(self.directory.stat(target)) != _identity(self.info()):
                raise ValueError("Alert rotation identity changed")
        self.name = target

    def delete(self, expected):
        if _identity(self.info()) != expected or _identity(self.directory.stat(self.name)) != expected:
            raise ValueError("Alert archive changed during retention")
        if self.directory.exists(self.name + ".keep"):
            raise ValueError("Alert archive became pinned")
        if os.name == "nt":
            import ctypes
            class Disposition(ctypes.Structure):
                _fields_ = [("delete", ctypes.c_ubyte)]
            self._set_information(4, Disposition(1))
        else:
            # Anchored, non-recursive unlink cannot follow a replaced symlink or
            # remove content outside the held diagnostics directory. Our writer
            # and pin API share the authority lease, and this inode is flocked.
            os.unlink(self.name, dir_fd=self.directory.descriptor)


@contextlib.contextmanager
def _transaction(root, *, create):
    with _directory(Path(root), create=create) as directory:
        if directory is None:
            yield None
            return
        with directory.open(_LOCK_NAME, create=True, lease=True):
            yield directory


def _encoded_line(text):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    # Bound before encoding, including attacker-controlled multiline diagnostics.
    raw = f"[{stamp}] {str(text)[:MAX_LINE_BYTES]}\n".encode("utf-8", errors="replace")
    if len(raw) > MAX_LINE_BYTES:
        raw = raw[:MAX_LINE_BYTES - 18].decode("utf-8", errors="ignore").encode("utf-8") + b" [truncated]\n"
    return raw


def append_runtime_alert(root, text):
    """Synchronous worker-only append. Rotate oversized legacy files without reading."""
    _append_lines(root, [text])


def _append_lines(root, texts):
    """Amortize directory custody and the process lease over one bounded batch."""
    with _transaction(root, create=True) as directory:
        active = directory.open(ACTIVE_NAME, create=True)
        try:
            size = active.info().st_size
            os.lseek(active.descriptor, 0, os.SEEK_END)
            for text in texts:
                raw = _encoded_line(text)
                if size and size + len(raw) > SEGMENT_BYTES:
                    active.rename(f"runtime_alerts.{time.time_ns()}.{uuid.uuid4().hex}.log")
                    active.close()
                    active = directory.open(ACTIVE_NAME, create=True)
                    size = active.info().st_size
                pending = memoryview(raw)
                while pending:
                    written = os.write(active.descriptor, pending)
                    if written <= 0:
                        raise OSError("Alert diagnostic write made no progress")
                    pending = pending[written:]
                    size += written
        finally:
            active.close()


def pin_archive(root, name, pinned=True):
    """Serialize an investigation pin with cleanup; only our archive names qualify."""
    if not _ARCHIVE.fullmatch(name):
        raise ValueError("Select a closed runtime alert archive")
    with _transaction(root, create=False) as directory:
        if directory is None:
            raise FileNotFoundError(name)
        with directory.open(name):
            if pinned:
                with directory.open(name + ".keep", create=True):
                    pass
            else:
                try:
                    with directory.open(name + ".keep") as marker:
                        marker.delete(_identity(marker.info()))
                except FileNotFoundError:
                    pass


class RetentionScanCursor:
    """A bounded, resumable directory inventory owned by one maintenance worker."""
    def __init__(self):
        self.iterator = None
        self.identity = None
        self.candidates = []
        self.totals = {}
        self.omitted_candidates = False

    def close(self):
        if self.iterator is not None:
            self.iterator.close()
            self.iterator = None

    def prepare(self, directory):
        info = (os.fstat(directory.descriptor) if directory.descriptor is not None
                else directory.path.lstat())
        identity = (str(directory.path), info.st_dev, info.st_ino)
        if self.iterator is not None and identity != self.identity:
            self.close()
        if self.iterator is None:
            self.iterator = directory.entries()
            self.identity = identity
            self.candidates = []
            self.omitted_candidates = False
            self.totals = dict(managed_bytes=0, pinned_files=0, unsafe_files=0, archives=0)

    def candidate(self, stamp, name, identity):
        # Negative times make the heap root the newest retained candidate.
        item = (-stamp, name, identity)
        if len(self.candidates) < MAX_DELETIONS:
            heapq.heappush(self.candidates, item)
        else:
            self.omitted_candidates = True
            if item > self.candidates[0]:
                heapq.heapreplace(self.candidates, item)


def cleanup_alert_archives(root, policy=None, *, now=None, cursor=None):
    """One bounded maintenance pass; pressure remains explicit if custody prevents pruning."""
    policy = policy or RetentionPolicy()
    if not isinstance(policy, RetentionPolicy):
        raise TypeError("Expected RetentionPolicy")
    report = dict(status="disabled" if not policy.enabled else "clean", managed_bytes=0,
                  deleted_files=0, deleted_bytes=0, pinned_files=0, unsafe_files=0,
                  incomplete=False, quota_pressure=False, archives=0)
    if not policy.enabled:
        if cursor is not None:
            cursor.close()
        return report
    own_cursor = cursor is None
    cursor = RetentionScanCursor() if cursor is None else cursor
    now = time.time() if now is None else float(now)
    if not math.isfinite(now):
        raise ValueError("Retention time must be finite")
    try:
        with _transaction(root, create=False) as directory:
            if directory is None:
                cursor.close()
                return report
            cursor.prepare(directory)
            exhausted = False
            for _ in range(MAX_ENTRIES):
                try:
                    entry = next(cursor.iterator)
                except StopIteration:
                    exhausted = True
                    cursor.close()
                    break
                else:
                    if entry.name != ACTIVE_NAME and not _ARCHIVE.fullmatch(entry.name):
                        continue
                    try:
                        info = directory.stat(entry.name)
                        _plain(info)
                    except (OSError, ValueError):
                        cursor.totals["unsafe_files"] += 1
                        continue
                    cursor.totals["managed_bytes"] += info.st_size
                    if entry.name == ACTIVE_NAME:
                        continue
                    cursor.totals["archives"] += 1
                    if directory.exists(entry.name + ".keep"):
                        cursor.totals["pinned_files"] += 1
                        continue
                    # A permanently open/locked oldest prefix must not fill the
                    # bounded candidate heap and starve later deletable files.
                    try:
                        with directory.open(entry.name) as candidate:
                            if _identity(candidate.info()) != _identity(info):
                                raise ValueError("Alert archive changed during inventory")
                    except (OSError, ValueError):
                        cursor.totals["unsafe_files"] += 1
                        continue
                    cursor.candidate(info.st_mtime, entry.name, _identity(info))
            report.update(cursor.totals)
            report["incomplete"] = not exhausted
            limit = policy.max_mib * 1024 * 1024
            cutoff = now - policy.days * 86400
            for negative_stamp, name, identity in sorted(cursor.candidates, reverse=True):
                if -negative_stamp >= cutoff and (not exhausted or report["managed_bytes"] <= limit):
                    continue
                if report["deleted_files"] >= MAX_DELETIONS:
                    report["incomplete"] = True
                    break
                try:
                    with directory.open(name) as archive:
                        archive.delete(identity)
                except (OSError, ValueError):
                    report["unsafe_files"] += 1
                    continue
                report["deleted_files"] += 1
                report["deleted_bytes"] += identity[2]
                report["managed_bytes"] -= identity[2]
                report["archives"] -= 1
                cursor.candidates.remove((negative_stamp, name, identity))
                heapq.heapify(cursor.candidates)
            cursor.totals.update({key: report[key] for key in cursor.totals})
            if cursor.omitted_candidates and report["deleted_files"] >= MAX_DELETIONS:
                report["incomplete"] = True
            report["quota_pressure"] = report["managed_bytes"] > limit
            if report["quota_pressure"]:
                report["status"] = "quota-pressure"
            elif report["incomplete"] or report["unsafe_files"]:
                report["status"] = "incomplete"
    except (OSError, ValueError):
        cursor.close()
        report["status"] = "unavailable"
        report["incomplete"] = True
    finally:
        if own_cursor:
            cursor.close()
    return report


class AlertRetentionWorker:
    """No GUI I/O: bounded diagnostic queue plus infrequent archive maintenance."""
    def __init__(self, root, policy=None, *, startup_grace=60.0, interval=900.0):
        self.root = Path(root)
        self._policy = policy or RetentionPolicy()
        if not isinstance(self._policy, RetentionPolicy):
            raise TypeError("Expected RetentionPolicy")
        if not math.isfinite(float(startup_grace)) or not math.isfinite(float(interval)):
            raise ValueError("Alert maintenance intervals must be finite")
        self._grace = max(0.0, float(startup_grace))
        self._interval = max(1.0, float(interval))
        self._queue = queue.Queue(maxsize=256)
        self._wake, self._stop = threading.Event(), threading.Event()
        self._lock = threading.Lock()
        self._requested = False
        self._thread = None
        self._report = dict(status="waiting", managed_bytes=0, deleted_files=0,
                            deleted_bytes=0, pinned_files=0, unsafe_files=0,
                            incomplete=False, quota_pressure=False, archives=0)
        self._dropped = self._writer_errors = 0
        self._scan_cursor = RetentionScanCursor()

    def start(self):
        with self._lock:
            if self._thread is not None:
                return
            self._thread = threading.Thread(target=self._run, name="AlertRetention", daemon=True)
            self._thread.start()

    def append(self, text):
        if self._stop.is_set():
            return False
        try:
            self._queue.put_nowait(str(text)[:MAX_LINE_BYTES])
        except queue.Full:
            with self._lock:
                self._dropped += 1
            return False
        self._wake.set()
        return True

    def request_cleanup(self):
        with self._lock:
            self._requested = True
        self._wake.set()

    def update_policy(self, policy):
        if not isinstance(policy, RetentionPolicy):
            raise TypeError("Expected RetentionPolicy")
        with self._lock:
            self._policy = policy
            self._requested = True
        self._wake.set()

    def snapshot(self):
        with self._lock:
            result = dict(self._report)
            result.update(queued=self._queue.qsize(), dropped=self._dropped,
                          writer_errors=self._writer_errors, enabled=self._policy.enabled)
            return result

    def stop(self, timeout=2.0):
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(0.0, float(timeout)))
        return thread is None or not thread.is_alive()

    def _run(self):
        due = time.monotonic() + self._grace
        while True:
            self._wake.clear()
            # Bounded batch prevents a diagnostic flood from starving maintenance.
            batch = []
            for _ in range(64):
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            if batch:
                try:
                    _append_lines(self.root, batch)
                except Exception:
                    with self._lock:
                        self._writer_errors += len(batch)
                finally:
                    for _ in batch:
                        self._queue.task_done()
            if self._stop.is_set():
                if self._queue.empty():
                    self._scan_cursor.close()
                    return
                continue
            with self._lock:
                requested = self._requested
                self._requested = False
                policy = self._policy
            if requested or time.monotonic() >= due:
                report = cleanup_alert_archives(self.root, policy, cursor=self._scan_cursor)
                with self._lock:
                    self._report = report
                due = time.monotonic() + (min(5.0, self._interval)
                    if self._scan_cursor.iterator is not None else self._interval)
            if self._queue.empty():
                self._wake.wait(max(0.0, due - time.monotonic()))
