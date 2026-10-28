"""shadow_shield.py — Ransomware file shielding: VSS + delta cache (CODE: SHDW).

Active file protection with two recovery layers:

1. Delta version cache (fast, primary)
   A short-horizon version store. A polling loop copies recently-modified files
   from the protected directories into a hidden cache, keeping the last N
   versions of each. When RANS detects an active encryption event it calls
   ``trigger_rollback(before_ts=...)`` and we restore the newest cached version
   that predates the encryption burst — recovering the clean copy in place.

2. Volume Shadow Copy (heavier, fallback)
   Periodically requests a quiet VSS snapshot via WMI ``Win32_ShadowCopy.Create``
   (PowerShell fallback). This is the deeper safety net; full extraction from a
   shadow is surfaced to the operator/GUI rather than done automatically.

SAFETY: this module only *creates* snapshots and *restores* files. It never
deletes shadow copies — ``vssadmin delete shadows`` is a ransomware technique,
not a defensive one, and is intentionally absent here.

The delta cache is best-effort (polling can't intercept every write); VSS is the
stronger guarantee. Windows-only operations degrade gracefully (health note, no
crash) on non-Windows or non-elevated hosts.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from angerona.core.module_base import BaseModule, Severity


def _data_base() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


PROTECTED_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\Documents"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
]

POLL_S           = 15.0             # full Documents/Desktop stat-walk cadence; 15s
                                    # (was 5s) cuts steady CPU ~3x. The delta cache
                                    # is best-effort — VSS snapshots + the RANS
                                    # detector are the real ransomware net — so a
                                    # slightly wider window costs little protection.
RETAIN_VERSIONS  = 6                 # versions kept per file
MAX_FILE_BYTES   = 50 * 1024 * 1024  # don't cache files larger than 50 MB
VSS_INTERVAL_S   = 3600.0            # request a shadow at most hourly
VSS_TIMEOUT_S    = 90.0
CACHE_CHUNK_BYTES = 1024 * 1024
CACHE_SLICE_FILES = 128
CACHE_SLICE_BYTES = 16 * 1024 * 1024
CACHE_SLICE_SECONDS = 0.25
CACHE_YIELD_SECONDS = 0.25
MAX_PRUNE_ENTRIES = 128
# Aggregate admission never evicts recovery evidence. A held cache is rescanned
# after a module restart; low space and incomplete inventory remain coverage gaps.
MAX_CACHE_BYTES = 2 * 1024 * 1024 * 1024
MIN_FREE_BYTES = 2 * 1024 * 1024 * 1024
MAX_CACHE_ENTRIES = 20_000
MAX_CACHE_SOURCES = 4_096
CACHE_INVENTORY_SECONDS = 2.0
MAX_CLEANUP_PASSES = 256
MAX_CLEANUP_SECONDS = 30 * 60.0
SKIP_EXT         = {".tmp", ".part", ".crdownload"}


class ShadowShield(BaseModule):
    name = "Shadow Shield"
    CODE = "SHDW"
    description = "Ransomware file shielding via a delta version cache and VSS snapshots."
    category = "Response"
    version = "1.14.0"
    # A real bounded VSS request can take 90 seconds. Cache work publishes
    # completed slices with explicitly partial coverage, never timer heartbeats.
    startup_cycle_timeout = 120.0
    eco_cycle_timeout = 120.0
    watchdog_work_budget_seconds = 120.0

    def __init__(self) -> None:
        super().__init__()
        self._cache_dir = _data_base() / "shadow_cache"
        self._seen_mtime: dict[str, int] = {}
        self._last_vss = 0.0
        self._snapshots = 0
        self._rollbacks = 0
        self._vss_health: int | None = None
        self._vss_note = "VSS coverage not checked in this session"
        self._walk_errors = 0
        self._prune_errors = 0
        self._cache_bytes = 0
        self._cache_entries = 0
        self._cache_sources = 0
        self._cache_accounted = False
        self._cache_storage_hold = ""
        self._cache_directory_stamps: dict[Path, tuple[int, int, int, int]] = {}
        self._cache_populated_sources: set[Path] = set()
        self._cache_io_lock = threading.RLock()
        self._storage_command_lock = threading.RLock()
        self._storage_policy_pending: tuple[bool, bool, int, int, bool] | None = None
        self._storage_policy_applied: tuple[bool, bool, int, int, bool] | None = None
        self._cache_cleanup_pending = False
        self._cache_cleanup_running = False
        self._cache_cleanup_thread: threading.Thread | None = None
        self._cache_cleanup_cancel = threading.Event()
        self._cache_cleanup_report: dict | None = None
        self._storage_review_pending = False
        self._cache_enabled = True
        self._automatic_vss_enabled = False
        self._cache_limit_bytes: int | None = None
        self._free_reserve_bytes: int | None = None
        self._cache_free_bytes: int | None = None
        self._storage_status: dict = {}
        self._publish_storage_status()

    def bind_manager(self, manager) -> None:
        config = manager.config
        self.configure_storage_policy(
            cache_enabled=config.shadow_cache_enabled,
            vss_enabled=config.shadow_vss_enabled,
            max_mib=config.shadow_cache_max_mib,
            min_free_mib=config.shadow_min_free_mib,
        )

    def configure_storage_policy(self, *, cache_enabled: bool, vss_enabled: bool,
                                 max_mib: int, min_free_mib: int,
                                 review_pending: bool = False) -> None:
        """Queue operator settings; filesystem work belongs to this worker."""
        if (type(cache_enabled) is not bool or type(vss_enabled) is not bool or type(review_pending) is not bool
                or type(max_mib) is not int or not 64 <= max_mib <= 16_384
                or type(min_free_mib) is not int or not 512 <= min_free_mib <= 65_536):
            raise ValueError("invalid Shadow Shield storage policy")
        with self._storage_command_lock:
            self._storage_policy_pending = (cache_enabled, vss_enabled, max_mib, min_free_mib, review_pending)

    def request_cache_cleanup(self) -> bool:
        """Start retained maintenance work, including when the sensor is paused."""
        with self._storage_command_lock:
            if (self._cache_cleanup_pending or self._cache_cleanup_running
                    or self._cache_cleanup_thread is not None and self._cache_cleanup_thread.is_alive()):
                return False
            self._cache_cleanup_pending = True
            self._cache_cleanup_report = dict(complete=False, removed_files=0, removed_bytes=0,
                                             removed_directories=0, reason="cleanup requested")
            self._storage_status = {**self._storage_status, "cleanup_pending": True,
                                    "cleanup_report": dict(self._cache_cleanup_report)}
            cancel = self._cache_cleanup_cancel = threading.Event()
            worker = threading.Thread(target=self._cleanup_maintenance, args=(cancel,),
                                      name="ShadowShield-cache-maintenance", daemon=True)
            self._cache_cleanup_thread = worker
            try:
                worker.start()
            except RuntimeError:
                self._cache_cleanup_pending = False
                self._cache_cleanup_report["reason"] = "cache maintenance could not start"
                self._storage_status = {**self._storage_status, "cleanup_pending": False,
                                        "held": True, "reason": "cache maintenance could not start",
                                        "cleanup_report": dict(self._cache_cleanup_report)}
                return False
            return True

    def stop(self) -> None:
        with self._storage_command_lock:
            self._cache_cleanup_cancel.set()
        super().stop()

    def _cleanup_waiting(self) -> bool:
        with self._storage_command_lock:
            return self._cache_cleanup_pending or self._cache_cleanup_running

    def _cleanup_maintenance(self, cancel: threading.Event) -> None:
        # All generations share this lock, but only one bounded helper pass
        # holds it. Primary policy/observation turns can run between passes;
        # persistent maintenance flags exclude inventory/copy admission there.
        with self._storage_command_lock:
            self._cache_cleanup_pending = False
            self._cache_cleanup_running = True
        report = dict(complete=False, removed_files=0, removed_bytes=0,
                      removed_directories=0, reason="cleanup did not complete")
        started = time.monotonic()
        try:
            from angerona.core.shadow_cache_cleanup import cleanup_cache
            for _pass in range(MAX_CLEANUP_PASSES):
                if cancel.is_set():
                    report["reason"] = "cleanup cancelled; remaining copies preserved"
                    break
                if time.monotonic() - started >= MAX_CLEANUP_SECONDS:
                    report["reason"] = "cleanup overall time bound reached; remaining copies preserved"
                    break
                with self._cache_io_lock:
                    self._apply_storage_commands(cancel)
                    if cancel.is_set():
                        report["reason"] = "cleanup cancelled; remaining copies preserved"
                        break
                    result = cleanup_cache(self._cache_dir, stopped=cancel)
                    progress = 0
                    for field in ("removed_files", "removed_bytes", "removed_directories"):
                        value = result.get(field, 0)
                        if type(value) is not int or value < 0:
                            raise ValueError("invalid cleanup progress")
                        report[field] += value
                        if field != "removed_bytes":
                            progress += value
                    report["complete"] = result.get("complete") is True
                    report["reason"] = str(result.get("reason", "cleanup outcome unavailable"))[:300]
                    self._cache_accounted = False
                    self._cache_cleanup_report = dict(report)
                    self._publish_storage_status()
                if cancel.is_set() and not report["complete"]:
                    report["reason"] = "cleanup cancelled; remaining copies preserved"
                if report["complete"] or cancel.is_set() or not progress:
                    break
                # Only the helper's two explicit resumable bounds authorize
                # another pass. Unsafe, unknown and unavailable outcomes stop.
                if report["reason"] not in {
                    "cleanup time bound reached; remaining copies preserved; run cleanup again",
                    "cleanup entry bound reached; remaining copies preserved; run cleanup again",
                }:
                    break
                self._cleanup_pass_pause(cancel)
            else:
                report["reason"] = "cleanup overall pass bound reached; remaining copies preserved"
            with self._cache_io_lock:
                if report["complete"]:
                    self._cache_storage_hold = ""
                    self._storage_review_pending = False
                else:
                    self._cache_storage_hold = "requested cache cleanup incomplete: " + report["reason"][:200]
        except Exception:
            with self._cache_io_lock:
                self._cache_storage_hold = "requested cache cleanup unavailable; restart after review"
                report["complete"] = False
                report["reason"] = "cache cleanup unavailable; remaining copies preserved"
        finally:
            with self._cache_io_lock:
                self._cache_accounted = False
                self._cache_directory_stamps = {}
                self._cache_populated_sources = set()
                self._seen_mtime.clear()
                self._cache_cleanup_report = dict(report)
                with self._storage_command_lock:
                    self._cache_cleanup_running = False
                self._publish_storage_status()

    @staticmethod
    def _cleanup_pass_pause(cancel: threading.Event) -> None:
        # Yield outside I/O custody for a waiting primary policy turn. This is
        # cooperative scheduling, not a preemptible filesystem deadline.
        cancel.wait(0.01)

    def storage_status(self) -> dict:
        """Return cached advisory state; no directory walk or disk query."""
        with self._storage_command_lock:
            result = dict(self._storage_status)
            if result.get("cleanup_report") is not None:
                result["cleanup_report"] = dict(result["cleanup_report"])
            return result

    def _publish_storage_status(self) -> None:
        # Publish one advisory projection atomically. GUI readers never combine
        # a half-updated inventory with counters from a different worker turn.
        with self._storage_command_lock:
            self._storage_status = {
                "used_bytes": self._cache_bytes if self._cache_accounted else None,
                "limit_bytes": self._cache_limit_bytes or MAX_CACHE_BYTES,
                "free_bytes": self._cache_free_bytes,
                "reserve_bytes": self._free_reserve_bytes or MIN_FREE_BYTES,
                "held": bool(self._cache_storage_hold),
                "reason": self._cache_storage_hold or ("cache disabled by operator" if not self._cache_enabled else ""),
                "cleanup_pending": self._cache_cleanup_pending or self._cache_cleanup_running,
                "cleanup_report": (dict(self._cache_cleanup_report)
                                   if self._cache_cleanup_report is not None else None),
                "cache_enabled": self._cache_enabled,
                "inventory_complete": self._cache_accounted,
            }

    def _service_storage_commands(self, stopped: threading.Event) -> None:
        with self._storage_command_lock:
            pending = self._storage_policy_pending is not None
        if not pending:
            return
        with self._cache_io_lock:
            self._apply_storage_commands(stopped)

    def _apply_storage_commands(self, stopped: threading.Event) -> None:
        with self._storage_command_lock:
            policy = self._storage_policy_pending
            self._storage_policy_pending = None
        if policy is not None and policy != self._storage_policy_applied:
            self._storage_policy_applied = policy
            self._cache_enabled, self._automatic_vss_enabled, max_mib, min_free_mib, review_pending = policy
            self._cache_limit_bytes = max_mib * 1024 * 1024
            self._free_reserve_bytes = min_free_mib * 1024 * 1024
            self._cache_accounted = False
            self._cache_storage_hold = ""
            self._storage_review_pending = review_pending
            if review_pending:
                self._cache_storage_hold = "awaiting storage decision; open Storage settings to resume"
            if not self._automatic_vss_enabled:
                self._vss_health = 50
                self._vss_note = "automatic VSS disabled; delta cache only"
        self._publish_storage_status()

    def _storage_commands_waiting(self) -> bool:
        with self._storage_command_lock:
            return (self._storage_policy_pending is not None
                    or self._cache_cleanup_pending or self._cache_cleanup_running)

    # ── Cache helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def _key(path: str) -> str:
        return hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()

    def _keydir(self, path: str) -> Path:
        return self._cache_dir / self._key(path)

    @staticmethod
    def _plain(info, *, directory: bool) -> bool:
        return (
            not getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            and (stat.S_ISDIR(info.st_mode) if directory else
                 stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        )

    @staticmethod
    def _directory_stamp(info) -> tuple[int, int, int, int]:
        return info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns

    def _hold_storage(self, reason: str) -> bool:
        self._cache_storage_hold = reason
        self._publish_storage_status()
        self.set_health(50, f"delta cache coverage LIMITED: {reason}; existing recovery files preserved")
        return False

    def _prepare_cache_directory(self) -> bool:
        try:
            missing = []
            for ancestor in (self._cache_dir, *self._cache_dir.parents):
                try:
                    info = ancestor.lstat()
                except FileNotFoundError:
                    missing.append(ancestor)
                    continue
                if not self._plain(info, directory=True):
                    return self._hold_storage("cache directory ancestry is linked or unavailable")
            for directory in reversed(missing):
                directory.mkdir(exist_ok=True)
            if not self._plain(self._cache_dir.lstat(), directory=True):
                return self._hold_storage("cache root is linked or unavailable")
            return True
        except OSError:
            return self._hold_storage("cache directory unavailable; restart after review")

    def _inventory_cache(self) -> bool:
        if self._cleanup_waiting():
            return False
        with self._cache_io_lock:
            if self._cleanup_waiting():
                return False
            return self._inventory_cache_locked()

    def _inventory_cache_locked(self) -> bool:
        """Bound one startup/pass inventory; never traverse linked subtrees.

        Accounting assumes this module is the cache writer. Per-directory stamps
        reject observed concurrent changes; another pass refreshes retained bytes.
        These observations are admission checks, not a filesystem custody lease.
        """
        if self._cache_storage_hold:
            return False
        self._cache_accounted = False
        self._publish_storage_status()
        stopped = self.generation_stop_event()
        started = time.monotonic()
        total = entries = sources = 0
        stamps = {}
        populated = set()
        try:
            for ancestor in (self._cache_dir, *self._cache_dir.parents):
                if not self._plain(ancestor.lstat(), directory=True):
                    return self._hold_storage("cache directory ancestry is linked or unavailable")
            pending = [self._cache_dir]
            while pending:
                if stopped.is_set():
                    return False
                if time.monotonic() - started > CACHE_INVENTORY_SECONDS:
                    return self._hold_storage("cache inventory time limit reached; restart after review")
                current = pending.pop()
                before = current.lstat()
                if not self._plain(before, directory=True):
                    return self._hold_storage("cache inventory contains a linked directory")
                stamp = self._directory_stamp(before)
                with os.scandir(current) as children:
                    for child in children:
                        if stopped.is_set():
                            return False
                        entries += 1
                        if entries > MAX_CACHE_ENTRIES or time.monotonic() - started > CACHE_INVENTORY_SECONDS:
                            return self._hold_storage("cache inventory entry/time limit reached; restart after review")
                        info = child.stat(follow_symlinks=False)
                        candidate = Path(child.path)
                        if current != self._cache_dir and current not in populated:
                            populated.add(current)
                            sources += 1
                            if sources > MAX_CACHE_SOURCES:
                                return self._hold_storage("cache source limit reached; restart after review")
                        if self._plain(info, directory=True):
                            if current != self._cache_dir or not re.fullmatch(r"[0-9a-f]{64}", child.name):
                                return self._hold_storage("cache inventory contains an unexpected directory")
                            pending.append(candidate)
                        elif (stat.S_ISREG(info.st_mode)
                              and not getattr(info, "st_file_attributes", 0)
                              & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                            # Windows DirEntry caches can report st_nlink=0;
                            # a fresh lstat is required for the link-count gate.
                            info = candidate.lstat()
                            if not self._plain(info, directory=False):
                                return self._hold_storage("cache inventory contains a linked or nonregular object")
                            total += info.st_size
                            if total > (self._cache_limit_bytes or MAX_CACHE_BYTES):
                                return self._hold_storage("cache byte quota reached; restart after review")
                        else:
                            return self._hold_storage("cache inventory contains a linked or nonregular object")
                if self._directory_stamp(current.lstat()) != stamp:
                    return self._hold_storage("cache changed during inventory; restart after review")
                stamps[current] = stamp
            # A key discovered early must also remain unchanged while later
            # directories are counted; no partial inventory authorizes a copy.
            for path, stamp in stamps.items():
                if stopped.is_set():
                    return False
                if time.monotonic() - started > CACHE_INVENTORY_SECONDS:
                    return self._hold_storage("cache inventory time limit reached; restart after review")
                if self._directory_stamp(path.lstat()) != stamp:
                    return self._hold_storage("cache changed during inventory; restart after review")
            self._cache_bytes, self._cache_entries, self._cache_sources = total, entries, sources
            self._cache_directory_stamps = stamps
            self._cache_populated_sources = populated
            self._cache_accounted = True
            self._publish_storage_status()
            return True
        except (OSError, ValueError):
            return self._hold_storage("cache inventory unavailable; restart after review")

    def _space_available(self, path: Path, additional_bytes: int = 0, *, cache: bool = False) -> bool:
        try:
            free = shutil.disk_usage(path).free
            if cache:
                self._cache_free_bytes = free
                self._publish_storage_status()
            return free >= (self._free_reserve_bytes or MIN_FREE_BYTES) + additional_bytes
        except (OSError, ValueError):
            if cache:
                self._cache_free_bytes = None
                self._publish_storage_status()
            return False

    def _admit_cache(self, kd: Path, size: int, sidecar_bytes: int) -> bool:
        if self._cache_storage_hold:
            return False
        if not self._cache_accounted and not self._inventory_cache():
            return False
        try:
            for directory in (self._cache_dir, kd):
                expected = self._cache_directory_stamps.get(directory)
                if expected is not None and self._directory_stamp(directory.lstat()) != expected:
                    return self._hold_storage("cache changed outside the writer; restart after review")
                if expected is None and os.path.lexists(directory):
                    return self._hold_storage("cache has an unaccounted directory; restart after review")
            new_key = kd not in self._cache_directory_stamps
            new_source = kd not in self._cache_populated_sources
            # Reserve the full new version while prior versions still exist,
            # including its temporary name, sidecar and source directory.
            extra_entries = 1 + int(new_key) + int(sidecar_bytes > 0)
            if (self._cache_bytes + size + sidecar_bytes > (self._cache_limit_bytes or MAX_CACHE_BYTES)
                    or self._cache_entries + extra_entries > MAX_CACHE_ENTRIES
                    or self._cache_sources + int(new_source) > MAX_CACHE_SOURCES):
                return self._hold_storage("cache aggregate quota reached; restart after review")
            if not self._space_available(self._cache_dir, size + sidecar_bytes, cache=True):
                return self._hold_storage("cache free-space reserve unavailable; restart after review")
            return True
        except (OSError, ValueError):
            return self._hold_storage("cache admission accounting unavailable; restart after review")

    def _protected_files(self):
        stopped = self.generation_stop_event()
        for d in PROTECTED_DIRS:
            if stopped.is_set():
                return
            if not os.path.isdir(d):
                self._walk_errors += 1
                continue
            def walk_error(_error):
                self._walk_errors += 1
            for root, dirs, files in os.walk(d, onerror=walk_error):
                if stopped.is_set():
                    return
                for fn in files:
                    if stopped.is_set():
                        return
                    if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                        continue
                    yield os.path.join(root, fn)

    def _cache_version(self, path: str) -> tuple[str, int]:
        if self._cleanup_waiting():
            return "skipped", 0
        with self._cache_io_lock:
            if self._cleanup_waiting():
                return "skipped", 0
            return self._cache_version_locked(path)

    def _cache_version_locked(self, path: str) -> tuple[str, int]:
        """Copy the current bytes of `path` into the version cache, pruning old
        versions. Stores an index sidecar mapping cache filename → source path."""
        stopped = self.generation_stop_event()
        temporary: Path | None = None
        temporary_generation: tuple[int, int] | None = None
        kd: Path | None = None
        copied = 0
        try:
            if stopped.is_set():
                return "cancelled", 0
            if not self._cache_enabled:
                return "skipped", 0
            st = os.stat(path)
            if st.st_size > MAX_FILE_BYTES:
                return "skipped", 0
            mtime_ns = st.st_mtime_ns
            if self._seen_mtime.get(path) == mtime_ns:
                return "unchanged", 0
            kd = self._keydir(path)
            if self._cache_storage_hold:
                return "skipped", 0
            # Direct/test callers get the same inventory as the worker loop.
            if not self._prepare_cache_directory():
                return "skipped", 0
            if not self._cache_accounted and not self._inventory_cache():
                return "skipped", 0
            new_key = kd not in self._cache_directory_stamps
            new_source = kd not in self._cache_populated_sources
            idx = kd / "_source.txt"
            sidecar = path.encode("utf-8")
            sidecar_missing = not os.path.lexists(idx)
            sidecar_bytes = len(sidecar) if sidecar_missing else 0
            if not self._admit_cache(kd, st.st_size, sidecar_bytes):
                return "skipped", 0
            kd.mkdir(parents=True, exist_ok=True)
            # Record the true source path once (rollback needs it).
            if sidecar_missing:
                with idx.open("xb") as sidecar_file:
                    sidecar_file.write(sidecar)
                self._cache_bytes += sidecar_bytes
                self._cache_entries += 1
            if new_source:
                self._cache_sources += 1
                self._cache_populated_sources.add(kd)
            if new_key:
                self._cache_entries += 1
            self._cache_directory_stamps[self._cache_dir] = self._directory_stamp(self._cache_dir.lstat())
            self._cache_directory_stamps[kd] = self._directory_stamp(kd.lstat())
            dst = kd / f"{mtime_ns}.bak"
            if os.path.lexists(dst):
                return "unchanged", 0
            # A cancelled/changed source must never leave a partial .bak that
            # the existing exact-artifact recovery workflow could enumerate.
            temporary = kd / f".{mtime_ns}.{uuid.uuid4().hex}.tmp"
            with open(path, "rb") as source, temporary.open("xb") as target:
                created = os.fstat(target.fileno())
                temporary_generation = created.st_dev, created.st_ino
                opened = os.fstat(source.fileno())
                if (opened.st_size, opened.st_mtime_ns) != (st.st_size, mtime_ns):
                    return "failed", 0
                while True:
                    if stopped.is_set():
                        return "cancelled", copied
                    chunk = source.read(CACHE_CHUNK_BYTES)
                    if not chunk:
                        break
                    if stopped.is_set():
                        return "cancelled", copied
                    copied += len(chunk)
                    if copied > opened.st_size or copied > MAX_FILE_BYTES:
                        return "failed", copied
                    target.write(chunk)
                final = os.fstat(source.fileno())
                if (final.st_size, final.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
                    return "failed", copied
            shutil.copystat(path, temporary)
            with self._lifecycle_lock:
                if stopped.is_set() or stopped is not self._stop:
                    return "cancelled", copied
                os.replace(temporary, dst)
                temporary = None
                self._cache_bytes += copied
                self._cache_entries += 1
                self._seen_mtime[path] = mtime_ns
            self._prune(kd)
            # Keep a conservative upper bound after existing per-key retention;
            # the next bounded pass inventory reconciles bytes actually removed.
            return "cached", copied
        except Exception:
            self._hold_storage("cache copy/accounting unavailable; restart after review")
            return "failed", copied
        finally:
            if temporary is not None:
                try:
                    if os.path.lexists(temporary):
                        info = temporary.lstat()
                        if ((info.st_dev, info.st_ino) != temporary_generation
                                or not self._plain(info, directory=False)):
                            raise ValueError("staging file no longer belongs to this copy")
                        from angerona.core.shadow_cache_cleanup import delete_cache_file
                        # Retire this one owned staging file even when the
                        # module's generation stopped. copystat can have copied
                        # READONLY; exact-handle disposition needs no attr edit.
                        if not delete_cache_file(temporary, expected_identity=self._cache_file_identity(info)):
                            raise OSError("owned staging cleanup did not complete")
                except (OSError, ValueError):
                    self._hold_storage("partial cache cleanup unavailable; restart after review")
            if self._cache_accounted:
                try:
                    self._cache_directory_stamps[self._cache_dir] = self._directory_stamp(self._cache_dir.lstat())
                    if kd is not None and kd in self._cache_directory_stamps:
                        self._cache_directory_stamps[kd] = self._directory_stamp(kd.lstat())
                except OSError:
                    self._hold_storage("cache directory accounting unavailable; restart after review")
            self._publish_storage_status()

    @staticmethod
    def _cache_file_identity(info) -> tuple[int, int, int, int]:
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns

    def _prune(self, kd: Path) -> None:
        with self._cache_io_lock:
            self._prune_locked(kd)

    def _prune_locked(self, kd: Path) -> None:
        stopped = self.generation_stop_event()
        try:
            if kd.parent != self._cache_dir or re.fullmatch(r"[0-9a-f]{64}", kd.name) is None:
                raise ValueError("retention requires one bound cache key directory")
            versions = []
            with os.scandir(kd) as entries:
                for index, entry in enumerate(entries):
                    if stopped.is_set():
                        return
                    if index >= MAX_PRUNE_ENTRIES:
                        self._prune_errors += 1
                        self._hold_storage("cache retention inventory limit reached; restart after review")
                        return
                    if re.fullmatch(r"[0-9]{1,20}\.bak", entry.name):
                        candidate = Path(entry.path)
                        info = candidate.lstat()
                        if not self._plain(info, directory=False):
                            raise ValueError("cache retention artifact is not plain")
                        versions.append((info.st_mtime_ns, candidate, self._cache_file_identity(info)))
            versions.sort(key=lambda item: item[0])
            for _, old, expected in versions[:-RETAIN_VERSIONS]:
                if stopped.is_set():
                    return
                from angerona.core.shadow_cache_cleanup import delete_cache_file
                if not delete_cache_file(old, expected_identity=expected, stopped=stopped):
                    if not stopped.is_set():
                        raise OSError("cache retention deletion did not complete")
                    return
        except Exception:
            self._prune_errors += 1
            self._hold_storage("cache retention unavailable; restart after review")

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _canonical_protected_path(raw_path: str) -> Path | None:
        """Resolve one target and prove it remains under a protected root."""
        try:
            target = Path(raw_path).expanduser().resolve(strict=False)
            roots = tuple(
                Path(value).expanduser().resolve(strict=False)
                for value in PROTECTED_DIRS
            )
        except (OSError, RuntimeError, ValueError):
            return None
        if not any(target == root or root in target.parents for root in roots):
            return None
        return target

    def prepare_rollback_artifact(
        self, path: str, *, before_ts: float
    ) -> dict | None:
        """Bind one restore authorization to an exact cached file version.

        The returned descriptor is inert metadata.  ``restore_rollback_artifact``
        revalidates its path, cache key, version, size, and digest immediately
        before replacing the destination.
        """
        target = self._canonical_protected_path(path)
        if target is None:
            return None
        try:
            cutoff_ns = int(float(before_ts) * 1e9)
            key = self._key(str(target))
            keydir = (self._cache_dir / key).resolve(strict=True)
            if keydir.parent != self._cache_dir.resolve(strict=False):
                return None
            source = (keydir / "_source.txt").read_text(encoding="utf-8").strip()
            source_path = self._canonical_protected_path(source)
            if source_path != target:
                return None
            candidates = sorted(
                (
                    item
                    for item in keydir.glob("*.bak")
                    if item.is_file()
                    and not item.is_symlink()
                    and item.stem.isdigit()
                    and int(item.stem) < cutoff_ns
                ),
                key=lambda item: int(item.stem),
                reverse=True,
            )
            if not candidates:
                return None
            backup = candidates[0]
            digest = self._sha256(backup)
            size = int(backup.stat().st_size)
            version = backup.stem
        except (OSError, RuntimeError, TypeError, ValueError, OverflowError):
            return None
        artifact_id = hashlib.sha256(
            f"{target}\0{key}\0{version}\0{size}\0{digest}".encode("utf-8")
        ).hexdigest()
        return {
            "artifact_id": artifact_id,
            "source_path": str(target),
            "cache_key": key,
            "version_mtime_ns": version,
            "size": size,
            "sha256": digest,
        }

    def restore_rollback_artifact(self, artifact: dict) -> dict:
        """Restore exactly one previously bound cache artifact, or fail closed."""
        expected_keys = {
            "artifact_id", "source_path", "cache_key", "version_mtime_ns",
            "size", "sha256",
        }
        if not isinstance(artifact, dict) or set(artifact) != expected_keys:
            return {"restored": [], "failed": ["invalid artifact descriptor"]}
        target = self._canonical_protected_path(str(artifact.get("source_path") or ""))
        if target is None:
            return {"restored": [], "failed": ["target outside protected roots"]}
        key = str(artifact.get("cache_key") or "")
        version = str(artifact.get("version_mtime_ns") or "")
        digest = str(artifact.get("sha256") or "").casefold()
        try:
            size = int(artifact.get("size"))
        except (TypeError, ValueError, OverflowError):
            return {"restored": [], "failed": [str(target)]}
        expected_id = hashlib.sha256(
            f"{target}\0{key}\0{version}\0{size}\0{digest}".encode("utf-8")
        ).hexdigest()
        if (
            key != self._key(str(target))
            or not version.isdigit()
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or artifact.get("artifact_id") != expected_id
        ):
            return {"restored": [], "failed": [str(target)]}
        temporary: Path | None = None
        try:
            keydir = (self._cache_dir / key).resolve(strict=True)
            if keydir.parent != self._cache_dir.resolve(strict=False):
                raise ValueError("cache directory escaped")
            source = (keydir / "_source.txt").read_text(encoding="utf-8").strip()
            if self._canonical_protected_path(source) != target:
                raise ValueError("cache source changed")
            backup = (keydir / f"{version}.bak").resolve(strict=True)
            if backup.parent != keydir or backup.is_symlink() or not backup.is_file():
                raise ValueError("cache version is not a regular bound file")
            if backup.stat().st_size != size or self._sha256(backup) != digest:
                raise ValueError("cache version identity changed")
            target.parent.mkdir(parents=True, exist_ok=True)
            if self._canonical_protected_path(str(target.parent / target.name)) != target:
                raise ValueError("destination binding changed")
            temporary = target.parent / f".{target.name}.angerona-{uuid.uuid4().hex}.tmp"
            shutil.copy2(backup, temporary)
            if temporary.stat().st_size != size or self._sha256(temporary) != digest:
                raise ValueError("restore staging verification failed")
            os.replace(temporary, target)
            if target.stat().st_size != size or self._sha256(target) != digest:
                raise ValueError("restore postcondition failed")
        except (OSError, RuntimeError, TypeError, ValueError):
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            return {"restored": [], "failed": [str(target)]}
        self._rollbacks += 1
        self.emit(
            "Scoped rollback executed: one authorized file version restored.",
            Severity.HIGH,
            restored=[str(target)],
            failed=[],
            artifact_id=expected_id,
            version_mtime_ns=version,
        )
        return {"restored": [str(target)], "failed": [], "artifact_id": expected_id}

    # ── Rollback (called by RANS / SOAR) ─────────────────────────────────────
    def trigger_rollback(self, before_ts: Optional[float] = None,
                         paths: Optional[list[str]] = None) -> dict:
        """Retired unsafe bulk rollback entry point; never mutates host files.

        Cache pathnames and ``_source.txt`` metadata are not response authority.
        Callers must enumerate a reviewed artifact with ``list_artifacts`` and
        pass that exact signed/digested artifact to ``restore_artifact``.  This
        compatibility method remains so older integrations fail closed instead
        of silently regaining the former pathname-based mutation behavior.
        """
        requested = [str(path) for path in (paths or [])][:50]
        self.emit(
            "Legacy bulk rollback refused: select one exact cache artifact and "
            "use the scoped restore workflow.",
            Severity.HIGH,
            restored=[],
            failed=requested,
            before_ts=before_ts,
            response_authorized=False,
            proposal_only=True,
            remediation="Review list_artifacts() evidence and call restore_artifact().",
        )
        return {
            "restored": [],
            "failed": requested,
            "refused": True,
            "reason": "legacy pathname rollback retired; exact artifact required",
        }

    # ── VSS ───────────────────────────────────────────────────────────────────
    @staticmethod
    def _cancel_vss_process(process) -> None:
        """Stop only our child; cleanup cannot extend cancellation indefinitely."""
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.communicate(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            # Windows communicate() leaves its daemon readers owning the pipes
            # after a timeout. Closing here can wait forever on a reader's
            # stream lock; each reader already closes its own pipe after EOF.
            return

    def _set_vss_health(self, stopped: threading.Event, health: int, note: str) -> None:
        with self._lifecycle_lock:
            if stopped.is_set() or stopped is not self._stop:
                return
            self._vss_health = health
            self._vss_note = note
            self.set_health(health, note)

    def _take_vss_snapshot(self, drive: str = "C:\\") -> Optional[str]:
        """Request a ClientAccessible shadow via WMI (PowerShell). Best-effort;
        returns the ShadowID string on success. Requires elevation."""
        stopped = self.generation_stop_event()
        process = None
        try:
            ps = (f"(Get-WmiObject -List Win32_ShadowCopy)"
                  f".Create('{drive}','ClientAccessible') | "
                  f"Select-Object -ExpandProperty ShadowID")
            # Serialize launch with stop(): after stop returns no old generation
            # can issue another VSS request. Never hold this lock while waiting.
            with self._lifecycle_lock:
                if stopped.is_set() or stopped is not self._stop:
                    return None
                # Failed launches also consume the existing hourly attempt
                # interval; an unavailable host must not retry every cache poll.
                self._last_vss = time.time()
                cache_volume = self._cache_dir if self._cache_dir.exists() else self._cache_dir.parent
                if (not self._space_available(Path(drive))
                        or not self._space_available(cache_volume, cache=True)):
                    self._set_vss_health(stopped, 50, "VSS coverage LIMITED: free-space reserve unavailable; existing shadows preserved")
                    return None
                process = subprocess.Popen(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            deadline = time.monotonic() + VSS_TIMEOUT_S
            while True:
                if stopped.is_set():
                    self._cancel_vss_process(process)
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._cancel_vss_process(process)
                    self._set_vss_health(stopped, 70, "VSS snapshot timed out after 90 seconds.")
                    return None
                try:
                    stdout, stderr = process.communicate(timeout=min(0.25, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
            sid = (stdout or "").strip()
            with self._lifecycle_lock:
                if stopped.is_set() or stopped is not self._stop:
                    return None
                if process.returncode == 0 and sid:
                    self._snapshots += 1
                    self._set_vss_health(stopped, 100, "VSS snapshot confirmed")
                    self.emit(f"VSS snapshot created ({sid}).", Severity.INFO, shadow_id=sid)
                    return sid
            self._set_vss_health(stopped, 70, f"VSS create returned rc={process.returncode} "
                                f"(elevation required?): {(stderr or '').strip()[:120]}")
            return None
        except FileNotFoundError:
            self._set_vss_health(stopped, 60, "PowerShell/VSS unavailable on this host.")
            return None
        except Exception as exc:
            if process is not None:
                self._cancel_vss_process(process)
            self._set_vss_health(stopped, 70, f"VSS snapshot error: {exc}")
            return None

    def list_shadow_snapshots(self) -> list[dict]:
        """Enumerate existing shadows for operator-driven recovery in the GUI."""
        try:
            ps = ("Get-WmiObject Win32_ShadowCopy | "
                  "Select-Object ID, InstallDate, DeviceObject | ConvertTo-Json")
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=30,
            )
            import json
            data = json.loads(out.stdout or "[]")
            return data if isinstance(data, list) else [data]
        except Exception:
            return []

    # ── Loop ──────────────────────────────────────────────────────────────────
    def _cache_progress(self, counts: dict[str, int], *, complete: bool) -> None:
        health = self._vss_health if self._vss_health is not None else 50
        maintenance = self._cleanup_waiting()
        limited = bool(self._cache_storage_hold or not self._cache_enabled or maintenance)
        storage_note = ("cache maintenance in progress; copying held" if maintenance else
                        "LIMITED: " + self._cache_storage_hold if self._cache_storage_hold else
                        "admitted" if self._cache_enabled else "cache disabled by operator")
        if (not complete or self._walk_errors or self._prune_errors
                or counts["failed"] or counts["skipped"] or limited):
            health = min(health, 50)
        stopped = self.generation_stop_event()
        with self._lifecycle_lock:
            if stopped.is_set() or stopped is not self._stop:
                return
            self.set_health(
                health,
                f"delta cache {'coverage LIMITED' if limited else 'pass complete' if complete else 'coverage PARTIAL'}: "
                f"cached={counts['cached']}, unchanged={counts['unchanged']}, "
                f"skipped={counts['skipped']}, failed={counts['failed']}, "
                f"unavailable roots/walk errors={self._walk_errors}, "
                f"cache retention errors={self._prune_errors}; {self._vss_note}; "
                f"storage={storage_note}; "
                f"{self._snapshots} snapshots, {self._rollbacks} rollbacks",
            )

    def run(self) -> None:
        stopped = self.generation_stop_event()
        if stopped.is_set():
            return
        with self._cache_io_lock:
            self._cache_accounted = False
            self._cache_storage_hold = ("awaiting storage decision; open Storage settings to resume"
                                        if self._storage_review_pending else "")
            self._prepare_cache_directory()
        self.set_health(50, "Initializing delta cache; initial coverage is incomplete.")
        self.emit("Shadow Shield starting — checking delta cache and VSS coverage.", Severity.INFO)
        while not stopped.is_set():
            self._service_storage_commands(stopped)
            if stopped.is_set():
                return
            counts = dict.fromkeys(("cached", "unchanged", "skipped", "failed"), 0)
            self._walk_errors = 0
            self._prune_errors = 0
            slice_files = slice_bytes = 0
            slice_started = time.monotonic()
            admitted = self._cache_enabled and self._inventory_cache()
            interrupted_pass = False
            for path in self._protected_files() if admitted else ():
                if stopped.is_set():
                    return
                if self._storage_commands_waiting():
                    self._service_storage_commands(stopped)
                    interrupted_pass = True
                    break
                outcome, copied = self._cache_version(path)
                if stopped.is_set() or outcome == "cancelled":
                    return
                counts[outcome] += 1
                if self._cache_storage_hold:
                    break
                slice_files += 1
                slice_bytes += copied
                if (slice_files >= CACHE_SLICE_FILES or slice_bytes >= CACHE_SLICE_BYTES
                        or time.monotonic() - slice_started >= CACHE_SLICE_SECONDS):
                    # This is real completed cache work, with partial coverage
                    # explicitly retained until traversal finishes. Yielding
                    # avoids a full Documents/Desktop copy monopolizing IO.
                    self._cache_progress(counts, complete=False)
                    self.sleep(CACHE_YIELD_SECONDS)
                    if stopped.is_set():
                        return
                    slice_files = slice_bytes = 0
                    slice_started = time.monotonic()

            if stopped.is_set():
                return
            if self._storage_commands_waiting():
                self._service_storage_commands(stopped)
                interrupted_pass = True
            self._cache_progress(counts, complete=not interrupted_pass)
            self.mark_cycle_complete(interval_seconds=0.0)

            now = time.time()
            if (self._automatic_vss_enabled and not self._cleanup_waiting()
                    and now - self._last_vss >= VSS_INTERVAL_S):
                self._take_vss_snapshot()
            elif not self._automatic_vss_enabled and self._vss_health is None:
                self._vss_health = 50
                self._vss_note = "automatic VSS disabled; delta cache only"

            if stopped.is_set():
                return
            self._cache_progress(counts, complete=not interrupted_pass)
            self.sleep(POLL_S)

    def self_test(self) -> tuple[bool, str]:
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            return True, f"cache ready; {self._snapshots} VSS snapshots this session"
        except Exception as exc:
            return False, f"cache dir unavailable: {exc}"


def register() -> ShadowShield:
    return ShadowShield()
