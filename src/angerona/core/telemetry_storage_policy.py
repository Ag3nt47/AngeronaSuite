"""Cached telemetry admission policy; filesystem observations belong to workers.

Targets are observations of a shared database, not a quota or a response reserve.
The constructor, getter and policy setter never inspect the filesystem or clock.
"""
from __future__ import annotations

import dataclasses
import os
from pathlib import Path
import shutil
import stat
import threading
import time


MIB = 1024 * 1024
STORAGE_UNIT_BYTES = MIB
STORAGE_STATES = frozenset({"unconfigured", "unmeasured", "ready", "held", "unavailable"})
STORAGE_REASONS = frozenset({
    "", "unconfigured", "facts_unmeasured", "facts_stale", "probe_pending",
    "operator_blocked", "db_target", "wal_target", "free_floor", "probe_failed",
    "identity_changed", "unit_too_large", "worker_unavailable", "worker_stopped", "spool_capacity",
})


@dataclasses.dataclass(frozen=True)
class StorageWriteProgress:
    """Only acknowledged input prefixes; an ambiguous commit is not acknowledged."""
    completed: int = 0
    persisted: int = 0
    spooled: int = 0
    persistence_unknown: bool = False


class RecorderStorageHeld(RuntimeError):
    """The next unit is held, with earlier acknowledged progress preserved."""
    def __init__(self, reason: str, generation: int, *, progress=None, replay_progress=None, unit_bytes=None):
        if reason not in STORAGE_REASONS or not reason:
            raise ValueError("invalid storage hold reason")
        self.reason = reason
        self.policy_generation = generation
        self.progress = progress or StorageWriteProgress()
        self.replay_progress = replay_progress
        self.unit_bytes = unit_bytes
        super().__init__(f"Telemetry storage held: {reason}")


@dataclasses.dataclass(frozen=True)
class _Policy:
    blocked: bool
    db_target_bytes: int
    wal_target_bytes: int
    min_free_bytes: int


def _identity(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise ValueError("unsafe named storage object")
    return int(info.st_dev), int(info.st_ino)


def sample_storage_files(path: Path) -> dict:
    """Observe exactly DB/WAL/SHM and their volume; read no file contents."""
    path = Path(path).absolute()
    if str(path).startswith(("\\\\", "//")):
        raise ValueError("local storage path required")
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
            or getattr(parent, "st_file_attributes", 0) & 0x400):
        raise ValueError("unsafe storage parent")
    parent_id = int(parent.st_dev), int(parent.st_ino)
    values = {}
    identities = {}
    for name, suffix in (("db_bytes", ""), ("wal_bytes", "-wal"), ("shm_bytes", "-shm")):
        target = Path(str(path) + suffix)
        try:
            before = target.lstat()
        except FileNotFoundError:
            if not suffix:
                raise
            values[name] = 0
            identities[name] = None
            continue
        before_id = _identity(before)
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            after = target.lstat()
            if before_id != _identity(opened) or before_id != _identity(after):
                raise ValueError("named storage identity changed")
            values[name] = max(int(before.st_size), int(opened.st_size), int(after.st_size))
            identities[name] = before_id
            if before_id[0] != parent_id[0] or not all(before_id):
                raise ValueError("storage volume identity differs")
        finally:
            os.close(fd)
    after_parent = path.parent.lstat()
    if (not stat.S_ISDIR(after_parent.st_mode) or stat.S_ISLNK(after_parent.st_mode)
            or getattr(after_parent, "st_file_attributes", 0) & 0x400
            or not all(parent_id) or not all(identities["db_bytes"])
            or parent_id != (int(after_parent.st_dev), int(after_parent.st_ino))):
        raise ValueError("storage parent changed")
    usage = shutil.disk_usage(path.parent)
    final_parent = path.parent.lstat()
    if (not stat.S_ISDIR(final_parent.st_mode) or stat.S_ISLNK(final_parent.st_mode)
            or getattr(final_parent, "st_file_attributes", 0) & 0x400
            or parent_id != (int(final_parent.st_dev), int(final_parent.st_ino))):
        raise ValueError("storage parent changed")
    values.update(free_bytes=int(usage.free), parent_identity=parent_id,
                  db_identity=identities["db_bytes"])
    return values


class TelemetryStorageBudget:
    """One short memory lock, never held over SQL, filesystem I/O or waits."""
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._policy = None
        self._generation = 0
        self._facts_generation = 0
        self._facts = None
        self._observed = None
        self._age = None
        self._stale = True
        self._probing = False
        self._last_probe = None
        self._dirty = False
        self._identity = None
        self._reason = "unconfigured"
        self._state = "unconfigured"
        self._reserved = 0
        self._leases = {}
        self._serial = 0
        self._hold_attempts = 0
        self._replay_deferred = 0
        self._maintenance_deferred = 0
        self._runtime = {}
        self._runtime_revision = -1
        self.sampler = sample_storage_files
        self.clock = time.monotonic

    @property
    def configured(self):
        with self._lock:
            return self._policy is not None

    def configure(self, *, blocked, db_target_bytes, wal_target_bytes, min_free_bytes):
        values = ((db_target_bytes, 16 * MIB, 16384 * MIB),
                  (wal_target_bytes, 4 * MIB, 1024 * MIB),
                  (min_free_bytes, 512 * MIB, 65536 * MIB))
        valid = type(blocked) is bool and all(
            type(value) is int and low <= value <= high for value, low, high in values)
        with self._lock:
            if not valid:
                return {"schema": 1, "accepted": False, "policy_generation": self._generation,
                        "reason_code": "invalid_policy", "probe_pending": self._probing}
            self._policy = _Policy(blocked, db_target_bytes, wal_target_bytes, min_free_bytes)
            self._generation += 1
            self._stale = True
            self._state = "held" if blocked else "unmeasured"
            self._reason = "operator_blocked" if blocked else "facts_unmeasured"
            return {"schema": 1, "accepted": True, "policy_generation": self._generation,
                    "reason_code": self._reason, "probe_pending": True}

    def _reason_locked(self):
        policy = self._policy
        if policy is None:
            return "unconfigured"
        if policy.blocked:
            return "operator_blocked"
        if self._probing:
            return "probe_pending"
        if self._stale and self._reason in {"probe_failed", "identity_changed"}:
            return self._reason
        if self._facts_generation != self._generation or self._facts is None:
            return "facts_unmeasured"
        if self._stale:
            return self._reason if self._reason in {"probe_failed", "identity_changed"} else "facts_stale"
        facts = self._facts
        if facts["db_bytes"] >= policy.db_target_bytes:
            return "db_target"
        if facts["wal_bytes"] >= policy.wal_target_bytes:
            return "wal_target"
        if facts["free_bytes"] <= policy.min_free_bytes:
            return "free_floor"
        return ""

    def refresh_on_worker(self, *, force=False):
        now = self.clock()
        with self._lock:
            if self._policy is None:
                return
            if self._observed is not None:
                self._age = max(0.0, now - self._observed)
                self._stale = self._stale or self._age > 5.0
            if self._policy.blocked or self._probing:
                return
            if (not force and not self._dirty and not self._reason_locked()
                    and self._age is not None and self._age <= 5.0):
                return
            if (not force and not self._dirty and self._last_probe is not None
                    and now - self._last_probe < 1.0):
                return
            generation = self._generation
            self._probing = True
            self._last_probe = now
            self._dirty = False
        facts, reason = None, ""
        try:
            facts = self.sampler(self.path)
            if any(type(facts.get(key)) is not int or not 0 <= facts[key] < 2**63
                   for key in ("db_bytes", "wal_bytes", "shm_bytes", "free_bytes")):
                raise ValueError
            identity = (facts["parent_identity"], facts["db_identity"])
            if (any(type(item) is not tuple or len(item) != 2
                    or any(type(value) is not int or value <= 0 for value in item)
                    for item in identity) or identity[0][0] != identity[1][0]):
                raise ValueError
        except Exception:
            reason = "probe_failed"
        with self._lock:
            self._probing = False
            if generation != self._generation:
                return
            if not reason and self._identity is not None and identity != self._identity:
                reason = "identity_changed"
            if reason:
                self._stale = True
                self._state = "unavailable"
                self._reason = reason
                return
            self._identity = identity
            self._facts = {key: facts[key] for key in ("db_bytes", "wal_bytes", "shm_bytes", "free_bytes")}
            self._observed = now
            self._age = 0.0
            self._stale = self._dirty
            self._facts_generation = generation
            self._reason = self._reason_locked()
            self._state = "held" if self._reason else "ready"

    def admit(self, unit_bytes: int):
        now = self.clock()
        with self._lock:
            if self._policy is None:
                return None
            if self._observed is not None:
                self._age = max(0.0, now - self._observed)
                self._stale = self._stale or self._age > 5.0
            reason = "unit_too_large" if unit_bytes > STORAGE_UNIT_BYTES else self._reason_locked()
            if not reason:
                facts, policy = self._facts, self._policy
                projection = self._reserved + max(0, unit_bytes)
                if facts["db_bytes"] + projection > policy.db_target_bytes:
                    reason = "db_target"
                elif facts["wal_bytes"] + projection > policy.wal_target_bytes:
                    reason = "wal_target"
                elif facts["free_bytes"] - projection < policy.min_free_bytes:
                    reason = "free_floor"
            if reason:
                self._hold_attempts += 1
                self._reason = reason
                self._state = "held"
                raise RecorderStorageHeld(reason, self._generation, unit_bytes=unit_bytes)
            self._serial += 1
            self._state = "ready"
            self._reason = ""
            self._leases[self._serial] = max(0, unit_bytes)
            self._reserved += max(0, unit_bytes)
            return self._serial

    def release(self, lease, *, wrote=False):
        if lease is None:
            return
        with self._lock:
            self._reserved -= self._leases.pop(lease, 0)
            if wrote:
                self._stale = True
                self._dirty = True

    def note_deferred(self, *, replay=False, maintenance=False):
        with self._lock:
            self._replay_deferred += int(replay)
            self._maintenance_deferred += int(maintenance)

    def clear_local_unit_hold(self):
        with self._lock:
            if self._reason == "unit_too_large":
                self._reason = self._reason_locked()
                self._state = "held" if self._reason else "ready"

    def publish_runtime(self, revision: int, values: dict):
        with self._lock:
            if revision > self._runtime_revision:
                self._runtime_revision = revision
                names = ("storage_pending_events", "parked_primary_events", "parked_overflow_events",
                         "rejection_storage_hold", "storage_user_discarded", "coverage_gap",
                         "storage_held", "storage_policy_generation", "storage_reason", "storage_write_failures")
                self._runtime = {name: values[name] for name in names if name in values}

    def snapshot(self):
        with self._lock:
            policy = self._policy
            reason = self._reason_locked()
            if (not reason and self._state == "held" and self._reason in {
                    "unit_too_large", "db_target", "wal_target", "free_floor"}):
                reason = self._reason
            if policy is None:
                state = "unconfigured"
            elif reason in {"probe_failed", "identity_changed"}:
                state = "unavailable"
            elif reason in {"facts_unmeasured", "facts_stale", "probe_pending"}:
                state = "unmeasured"
            else:
                state = "held" if reason else "ready"
            result = {"schema": 1, "configured": policy is not None, "state": state,
                "reason_code": reason if reason else "", "policy_generation": self._generation,
                "facts_generation": self._facts_generation, "blocked": bool(policy and policy.blocked),
                "db_target_bytes": policy.db_target_bytes if policy else None,
                "wal_target_bytes": policy.wal_target_bytes if policy else None,
                "min_free_bytes": policy.min_free_bytes if policy else None,
                "unit_limit_bytes": STORAGE_UNIT_BYTES, "facts_observed_monotonic": self._observed,
                "facts_age_seconds": self._age, "facts_stale": self._stale,
                "probe_pending": self._probing, "storage_hold_attempts": self._hold_attempts,
                "replay_deferred": self._replay_deferred, "maintenance_deferred": self._maintenance_deferred,
                "scope": "telemetry-writer-only", "shared_database": True, "no_os_quota": True,
                "no_response_reserve": True, "durable": False}
            result.update(self._facts or {key: None for key in ("db_bytes", "wal_bytes", "shm_bytes", "free_bytes")})
            result.update({"storage_pending_events": 0, "parked_primary_events": 0,
                "parked_overflow_events": 0, "rejection_storage_hold": 0,
                "storage_user_discarded": 0, "coverage_gap": False})
            result["storage_write_failures"] = 0
            result.update(self._runtime)
            if (result.get("storage_held") and policy is not None and not policy.blocked
                    and result.get("storage_reason") in {"unit_too_large", "worker_stopped", "spool_capacity"}):
                result.update(state="held", reason_code=result["storage_reason"])
            if result["state"] == "ready" and (reason or self._stale or self._probing):
                result["state"] = "unmeasured"
            return result
