"""Retained Windows Job custody for explicitly launched child process trees.

Children are suspended until assigned. No process
table, process-name match, inherited handle, or PID lookup grants ownership.
"""
from __future__ import annotations

import math
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from angerona.core.werfault_guard import MAX_OWNED_PROCESSES, OwnedProcessIdentity


# Failed raw query closes are attempted once and never retried by numeric value.
# The global reference also retains custody if the original owner is collected.
_OWNED_OBSERVATION_CLOSE_HOLDS = []


def _on_gui_thread():
    qt = sys.modules.get("PySide6.QtCore")
    if qt is None:
        return False
    app = qt.QCoreApplication.instance()
    return app is not None and qt.QThread.currentThread() == app.thread()


class NativeOwnershipObservationError(OSError):
    """A query-only ownership observation or its native cleanup is unproven."""


class _OwnershipNative:
    """Fixed query-only Job operations using the existing process reader."""

    def __init__(self):
        from angerona.core.windows_process_lease import _Native

        self.processes = _Native()
        self.c, self.w, self.api = self.processes.ctypes, self.processes.wintypes, self.processes.api
        c, w = self.c, self.w
        for name, arguments, result in (
            ("GetCurrentProcess", [], w.HANDLE),
            ("DuplicateHandle", [w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE),
                                 w.DWORD, w.BOOL, w.DWORD], w.BOOL),
            ("QueryInformationJobObject", [w.HANDLE, c.c_int, w.LPVOID,
                                           w.DWORD, c.POINTER(w.DWORD)], w.BOOL),
            ("IsProcessInJob", [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)], w.BOOL),
        ):
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result

    def duplicate(self, handle, rights):
        current, result = self.api.GetCurrentProcess(), self.w.HANDLE()
        if not self.api.DuplicateHandle(current, int(handle), current, self.c.byref(result),
                                        rights, False, 0) or not result.value:
            raise NativeOwnershipObservationError("Retained child query duplication failed")
        return int(result.value)

    def members(self, job):
        c, w = self.c, self.w

        class Ids(c.Structure):
            _fields_ = [("assigned", w.DWORD), ("count", w.DWORD),
                        ("pids", c.c_size_t * MAX_OWNED_PROCESSES)]

        value = Ids()
        if not self.api.QueryInformationJobObject(job, 3, c.byref(value), c.sizeof(value), None):
            raise NativeOwnershipObservationError("Complete child Job membership is unavailable")
        if not 1 <= value.assigned == value.count <= MAX_OWNED_PROCESSES:
            raise NativeOwnershipObservationError("Complete child Job membership exceeds its bound")
        return tuple(int(pid) for pid in value.pids[:value.count])

    def contains(self, job, process):
        member = self.w.BOOL()
        if not self.api.IsProcessInJob(process, job, self.c.byref(member)):
            raise NativeOwnershipObservationError("Child Job membership query failed")
        return bool(member.value)

    def open(self, pid):
        return self.processes.open(pid, 0x101000, False)

    def identity(self, handle):
        return self.processes.identity(handle)

    def alive(self, handle):
        return self.processes.wait(handle, 0) is False

    def close(self, handle):
        self.processes.close(handle)

    def retirement_members(self, job):
        c, w = self.c, self.w

        class Ids(c.Structure):
            _fields_ = [("assigned", w.DWORD), ("count", w.DWORD),
                        ("pids", c.c_size_t * MAX_OWNED_PROCESSES)]

        value = Ids()
        if not self.api.QueryInformationJobObject(job, 3, c.byref(value), c.sizeof(value), None):
            raise NativeOwnershipObservationError("Retirement Job membership is unavailable")
        if not 0 <= value.assigned == value.count <= MAX_OWNED_PROCESSES:
            raise NativeOwnershipObservationError("Retirement Job membership exceeds its bound")
        return tuple(int(pid) for pid in value.pids[:value.count])

    def retirement_accounting(self, job):
        c, w = self.c, self.w

        class Accounting(c.Structure):
            _fields_ = [("user", c.c_longlong), ("kernel", c.c_longlong),
                        ("period_user", c.c_longlong), ("period_kernel", c.c_longlong),
                        ("faults", w.DWORD), ("total", w.DWORD),
                        ("active", w.DWORD), ("terminated", w.DWORD)]

        value = Accounting()
        if not self.api.QueryInformationJobObject(job, 1, c.byref(value), c.sizeof(value), None):
            raise NativeOwnershipObservationError("Retirement Job accounting is unavailable")
        return int(value.total), int(value.active)

    def object_identity(self, handle):
        return self.processes.object_identity(handle)

    def wait(self, handle, milliseconds):
        return self.processes.wait(handle, milliseconds)


# Pending retirement retains the original owner through every close acknowledgement.
_OWNED_TREE_RETIREMENTS = []


class _OwnedTreeRetirement:
    """Current associated-member cut, not a history of all Job generations."""

    def __init__(self, owner):
        self.owner = owner
        self.refs = (owner._process, owner._job, owner._job._handle, owner.pid)
        self.epoch = owner._owned_observation_epoch
        self.native = None
        self.handles, self.processes = [], []
        self.job = None
        self.roster = frozenset()
        self.total = None
        self.ready = self.dispatched = self.waited = False
        self.close_started = self.close_held = self.closed = False
        self.failure = ""
        self.deadline = None
        self.last_clock = 0.0
        _OWNED_TREE_RETIREMENTS.append(self)

    def clock(self):
        now = time.monotonic()
        if (type(now) not in (int, float) or not math.isfinite(now)
                or not 0 <= self.last_clock <= now):
            raise NativeOwnershipObservationError("Retirement clock is invalid")
        self.last_clock = now
        return now

    def current(self):
        owner = self.owner
        if (owner._process is not self.refs[0] or owner._job is not self.refs[1]
                or owner._job._handle is not self.refs[2] or owner.pid != self.refs[3]
                or owner._process is None or owner._job._handle is None
                or owner._owned_observation_epoch != self.epoch):
            raise NativeOwnershipObservationError("Retirement owner lifetime changed")

    def accounting(self):
        values = self.native.retirement_accounting(self.job)
        if (type(values) is not tuple or len(values) != 2
                or any(type(value) is not int for value in values)
                or not 1 <= values[0] <= 0xffffffff
                or not 0 <= values[1] <= min(values[0], MAX_OWNED_PROCESSES)):
            raise NativeOwnershipObservationError("Retirement accounting is invalid")
        return values

    def members(self):
        values = self.native.retirement_members(self.job)
        if (type(values) is not tuple or len(values) > MAX_OWNED_PROCESSES
                or any(type(pid) is not int or not 1 <= pid <= 0xffffffff for pid in values)
                or len(set(values)) != len(values)):
            raise NativeOwnershipObservationError("Retirement membership is incomplete")
        return frozenset(values)

    def identity(self, handle, pid):
        value = self.native.object_identity(handle)
        if (type(value) is not tuple or len(value) != 2
                or any(type(part) is not int for part in value)
                or value[0] != pid or not 0 < value[1] <= 0xffffffffffffffff):
            raise NativeOwnershipObservationError("Retirement process identity is invalid")
        return value

    def capture(self, remaining):
        self.clock()
        self.current()
        self.native = _OwnershipNative()
        remaining()
        self.job = self.native.duplicate(self.refs[2], 0x0004)
        self.handles.append(self.job)
        root = self.native.duplicate(self.refs[0], 0x101000)
        self.handles.append(root)
        self.processes.append((root, self.identity(root, self.refs[3])))
        total, active = self.accounting()
        roster = self.members()
        if active != len(roster) or len(roster | {self.refs[3]}) > MAX_OWNED_PROCESSES:
            raise NativeOwnershipObservationError("Retirement member count differs")
        if self.refs[3] not in roster and self.native.wait(root, 0) is not True:
            raise NativeOwnershipObservationError("Live retained root is absent from its Job")
        for pid in sorted(roster):
            remaining()
            handle = root if pid == self.refs[3] else self.native.open(pid)
            if pid != self.refs[3]:
                self.handles.append(handle)
                self.processes.append((handle, self.identity(handle, pid)))
            if self.native.contains(self.job, handle) is not True:
                raise NativeOwnershipObservationError("Retirement member belongs to another Job")
        if self.members() != roster or self.accounting() != (total, active):
            raise NativeOwnershipObservationError("Retirement cut changed during capture")
        for handle, identity in self.processes:
            remaining()
            if self.native.object_identity(handle) != identity:
                raise NativeOwnershipObservationError("Retirement process generation changed")
        self.current()
        self.total, self.roster, self.ready = total, roster, True

    def before_terminate(self):
        self.current()
        if self.close_started or self.close_held or self.closed:
            raise NativeOwnershipObservationError("Retirement close custody is held")
        self.waited = False
        if self.ready:
            try:
                roster = self.members()
                if (self.accounting() != (self.total, len(roster))
                        or not roster.issubset(self.roster)
                        or (not self.dispatched and roster != self.roster)):
                    raise NativeOwnershipObservationError("Retirement cut changed before termination")
            except Exception as error:
                self.failure = type(error).__name__
                self.ready = False
        # An incomplete cut still permits this exact owner's stop attempt.
        self.dispatched = False

    def verify_empty(self):
        self.current()
        for handle, identity in self.processes:
            if (self.native.object_identity(handle) != identity
                    or self.native.wait(handle, 0) is not True):
                raise NativeOwnershipObservationError("Retirement process signal is unproven")
        if self.accounting() != (self.total, 0) or self.members():
            raise NativeOwnershipObservationError("Retirement Job changed or is not empty")
        self.current()

    def wait_job_empty(self, timeout):
        while True:
            self.current()
            total, active = self.accounting()
            roster = self.members()
            if total != self.total or not roster.issubset(self.roster):
                raise NativeOwnershipObservationError("Retirement Job membership changed")
            if active == 0 and not roster:
                return
            remaining = self.deadline - self.clock()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("owned child tree", timeout)
            time.sleep(min(0.01, remaining))

    def wait(self, timeout, *, deadline):
        if not self.ready or not self.dispatched or self.failure or self.close_started:
            raise NativeOwnershipObservationError("Retirement cut is incomplete")
        self.current()
        last = self.clock()
        self.deadline = deadline
        if last > self.deadline:
            raise subprocess.TimeoutExpired("owned child tree", timeout)
        for handle, identity in self.processes:
            now = self.clock()
            if not math.isfinite(now) or not last <= now <= self.deadline:
                raise subprocess.TimeoutExpired("owned child tree", timeout)
            last = now
            milliseconds = max(0, int((self.deadline - now) * 1000))
            if self.native.wait(handle, milliseconds) is not True:
                raise subprocess.TimeoutExpired("owned child tree", timeout)
            if self.native.object_identity(handle) != identity:
                raise NativeOwnershipObservationError("Retirement process generation changed")
        if self.clock() > self.deadline:
            raise subprocess.TimeoutExpired("owned child tree", timeout)
        self.wait_job_empty(timeout)
        self.verify_empty()
        if self.clock() > self.deadline:
            raise subprocess.TimeoutExpired("owned child tree", timeout)
        self.waited = True

    def close_queries(self):
        if self.close_held or self.closed or self.close_started or not self.waited:
            raise NativeOwnershipObservationError("Retirement signal or close custody is unproven")
        if self.clock() > self.deadline:
            raise NativeOwnershipObservationError("Retirement close deadline expired")
        self.verify_empty()
        if self.clock() > self.deadline:
            raise NativeOwnershipObservationError("Retirement close deadline expired")
        self.close_started = True
        error = None
        while self.handles:
            handle = self.handles.pop()
            try:
                self.native.close(handle)
            except BaseException as failure:
                self.close_held = True
                _OWNED_OBSERVATION_CLOSE_HOLDS.append((self.owner, self.native, handle))
                error = error or failure
        if error is not None:
            raise NativeOwnershipObservationError("Retirement query close remains unproven") from error

    def finish_close(self):
        self.closed = True
        _OWNED_TREE_RETIREMENTS.remove(self)

    def snapshot(self):
        return {"scope": "Retained original root and current associated Job cut; historical exits not collected",
                "captured_processes": len(self.processes), "total_processes_at_cut": self.total,
                "cut_ready": self.ready, "dispatched": self.dispatched,
                "signals_proven": self.waited, "handles_closed": self.closed,
                "close_held": self.close_held, "error_type": self.failure}


class WindowsChildJob:
    def __init__(self, *, kill_on_close=True):
        import win32job

        self._api = win32job
        self._handle = None
        self._handle = win32job.CreateJobObject(None, "")
        try:
            info = win32job.QueryInformationJobObject(
                self._handle, win32job.JobObjectExtendedLimitInformation,
            )
            if kill_on_close:
                info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(
                self._handle, win32job.JobObjectExtendedLimitInformation, info,
            )
        except BaseException:
            self.close()
            raise

    def assign(self, process):
        self._api.AssignProcessToJobObject(self._handle, process)

    def terminate(self):
        if self._handle is not None:
            self._api.TerminateJobObject(self._handle, 1)

    def close(self):
        handle, self._handle = self._handle, None
        if handle is not None:
            handle.Close()

    def wait_empty(self, timeout=3.0):
        deadline = time.monotonic() + timeout
        while True:
            state = self._api.QueryInformationJobObject(
                self._handle, self._api.JobObjectBasicAccountingInformation,
            )
            if state["ActiveProcesses"] == 0:
                return
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("owned child tree", timeout)
            time.sleep(0.01)

    def __del__(self):
        self.close()


class OwnedWindowsChild:
    owns_descendants = True

    def __init__(self, process, pid, job):
        self._process, self.pid, self._job = process, pid, job
        self._handle_lock = threading.RLock()
        self._owned_observation_lock = threading.Lock()
        self._owned_observation_epoch = 0
        self._owned_observation_stopped = False
        self._owned_observation_close_holds = []
        self._tree_retirement = None

    def poll(self):
        import win32process

        with self._handle_lock:
            if self._process is None:
                raise OSError("Owned child custody is closed")
            code = win32process.GetExitCodeProcess(self._process)
        return None if code == 259 else code

    def contains_native_process(self, identity) -> bool:
        """Observe one exact live member of this retained Job, without mutation.

        This is background-only identity context. A redirector's PID is not
        substituted for its actual role child, and membership grants no response
        authority. Duplicate only JOB_OBJECT_QUERY while the owner is pinned;
        no borrowed numeric Job handle escapes the owner lock.
        """
        from angerona.core.windows_process_lease import ProcessObjectIdentity, _Native

        if type(identity) is not ProcessObjectIdentity:
            return False
        if not self._handle_lock.acquire(blocking=False):
            return False
        retained_job = None
        try:
            if self._process is None or self._job._handle is None:
                return False
            import win32api
            current = win32api.GetCurrentProcess()
            retained_job = win32api.DuplicateHandle(
                current, self._job._handle, current, 0x0004, False, 0,
            )
        except Exception:
            return False
        finally:
            self._handle_lock.release()
        process = None
        native = None
        try:
            import ctypes
            from ctypes import wintypes as w

            native = _Native()
            process = native.open(identity.pid, 0x101000, False)
            if native.wait(process, 0) or native.identity(process) != identity:
                return False
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.IsProcessInJob.argtypes = (w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL))
            kernel.IsProcessInJob.restype = w.BOOL
            member = w.BOOL()
            if not kernel.IsProcessInJob(process, int(retained_job), ctypes.byref(member)):
                return False
            return bool(member.value and not native.wait(process, 0)
                        and native.identity(process) == identity)
        except Exception:
            return False
        finally:
            cleanup_failure = False
            if process is not None:
                try:
                    native.close(process)
                except Exception:
                    cleanup_failure = True
            if retained_job is not None:
                try:
                    retained_job.Close()
                except Exception:
                    cleanup_failure = True
            if cleanup_failure:
                raise NativeOwnershipObservationError("Query-only native observation cleanup remains unproven")

    def observe_owned_process_identities(self, *, role: str = "suite-child",
                                         timeout: float = 1.0) -> tuple[OwnedProcessIdentity, ...]:
        """Observe the complete bounded live Job through retained query custody.

        Background-only, immutable two-second context, never response authority.
        The deadline bounds lock admission and acceptance, not an OS query
        already in progress. Any ambiguity withholds the entire observation.
        No process table, heartbeat PID, executable-name match or cached DTO
        substitutes for this actual retained root/Job relationship.
        """
        if _on_gui_thread() or os.name != "nt":
            raise NativeOwnershipObservationError("Child ownership requires a Windows background owner")
        if (type(role) is not str or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", role)
                or type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 1.0):
            raise NativeOwnershipObservationError("Invalid child ownership role or deadline")
        from angerona.core.windows_process_lease import ProcessObjectIdentity

        started = time.monotonic()
        if type(started) not in (int, float) or not math.isfinite(started) or started < 0:
            raise NativeOwnershipObservationError("Child ownership clock unavailable")
        deadline, last = started + timeout, started

        def remaining():
            nonlocal last
            now = time.monotonic()
            if (type(now) not in (int, float) or not math.isfinite(now)
                    or not last <= now < deadline):
                raise NativeOwnershipObservationError("Child ownership observation deadline")
            last = now
            return deadline - now

        def state_locked():
            if (type(self._job) is not WindowsChildJob or self._process is None
                    or self._job._handle is None or type(self.pid) is not int
                    or not 1 <= self.pid <= 0xFFFFFFFF
                    or type(self._owned_observation_epoch) is not int
                    or self._owned_observation_epoch < 0
                    or self._owned_observation_stopped is not False
                    or type(self._owned_observation_close_holds) is not list
                    or self._owned_observation_close_holds
                    or self._owned_observation_lock is not observation_lock):
                raise NativeOwnershipObservationError("Retained child ownership lifetime unavailable")
            if not 0 < int(self._process) < 0xFFFFFFFFFFFFFFFF or not 0 < int(self._job._handle) < 0xFFFFFFFFFFFFFFFF:
                raise NativeOwnershipObservationError("Retained child ownership handle is closed")
            return (self._process, self._job, self._job._handle, self.pid,
                    self._owned_observation_epoch, self._owned_observation_close_holds)

        def current_owner(expected):
            if not self._handle_lock.acquire(timeout=remaining()):
                raise NativeOwnershipObservationError("Child ownership state admission deadline")
            try:
                current = state_locked()
                if (any(current[index] is not expected[index] for index in (0, 1, 2, 5))
                        or current[3:5] != expected[3:5]):
                    raise NativeOwnershipObservationError("Retained child ownership lifetime changed")
            finally:
                self._handle_lock.release()

        try:
            observation_lock = self._owned_observation_lock
        except AttributeError as exc:
            raise NativeOwnershipObservationError("Child ownership was not initialized") from exc
        if not observation_lock.acquire(timeout=remaining()):
            raise NativeOwnershipObservationError("Child ownership observation admission deadline")
        handles, native, owner, rows = [], None, None, None
        error = close_error = None
        try:
            try:
                if not self._handle_lock.acquire(timeout=remaining()):
                    raise NativeOwnershipObservationError("Child ownership state admission deadline")
                try:
                    owner = state_locked()
                    native = _OwnershipNative()
                    job_query = native.duplicate(owner[2], 0x0004)
                    handles.append(job_query)
                    root_query = native.duplicate(owner[0], 0x101000)
                    handles.append(root_query)
                finally:
                    self._handle_lock.release()

                def members():
                    remaining()
                    values = native.members(job_query)
                    if (type(values) is not tuple or not 1 <= len(values) <= MAX_OWNED_PROCESSES
                            or any(type(pid) is not int or not 1 <= pid <= 0xFFFFFFFF for pid in values)
                            or len(set(values)) != len(values) or owner[3] not in values):
                        raise NativeOwnershipObservationError("Complete child Job membership unavailable")
                    return frozenset(values)

                initial = members()
                # Use the original native-query interval, never renew this
                # lease after the remaining queries, locks or cleanup.
                sampled = last
                identities = []
                for pid in sorted(initial):
                    remaining()
                    handle = root_query if pid == owner[3] else native.open(pid)
                    if pid != owner[3]:
                        handles.append(handle)
                    identity = native.identity(handle)
                    if (type(identity) is not ProcessObjectIdentity or identity.pid != pid
                            or native.alive(handle) is not True
                            or native.contains(job_query, handle) is not True):
                        raise NativeOwnershipObservationError("Native child identity or membership unavailable")
                    identities.append((handle, identity))
                if members() != initial:
                    raise NativeOwnershipObservationError("Child Job membership changed")
                for handle, identity in identities:
                    remaining()
                    if (native.identity(handle) != identity or native.alive(handle) is not True
                            or native.contains(job_query, handle) is not True):
                        raise NativeOwnershipObservationError("Native child member changed")
                if members() != initial:
                    raise NativeOwnershipObservationError("Child Job membership changed")
                current_owner(owner)
                remaining()
                rows = tuple(OwnedProcessIdentity(identity.pid, str(identity.birth_ticks),
                             identity.create_time, identity.image, role, sampled, sampled + 2.0)
                             for _handle, identity in identities)
            except BaseException as exc:
                error = exc
            finally:
                # Detach before close, never retry a possibly recycled number.
                while handles:
                    handle = handles.pop()
                    try:
                        native.close(handle)
                    except BaseException as exc:
                        # Also retain the original full-rights lifetime owner;
                        # a leaked query Job reference can defer kill-on-close.
                        hold = (self, native, handle)
                        _OWNED_OBSERVATION_CLOSE_HOLDS.append(hold)
                        owner[5].append(hold)
                        close_error = close_error or exc
            if close_error is not None:
                raise NativeOwnershipObservationError("Child ownership query close remains unproven") from close_error
            if error is not None:
                if isinstance(error, NativeOwnershipObservationError) or not isinstance(error, Exception):
                    raise error
                raise NativeOwnershipObservationError("Child ownership observation unavailable") from error
            current_owner(owner)
            remaining()
            return rows
        finally:
            observation_lock.release()

    def prepare_tree_retirement(self, *, timeout=3.0):
        """Opt in to signal-proven CURRENT-member shutdown, never history attestation."""
        if (os.name != "nt" or type(timeout) not in (int, float)
                or not math.isfinite(timeout) or not 0 <= timeout <= 3.0):
            raise NativeOwnershipObservationError("Invalid retirement platform or deadline")
        last = time.monotonic()
        if type(last) not in (int, float) or not math.isfinite(last) or last < 0:
            raise NativeOwnershipObservationError("Retirement clock unavailable")
        deadline = last + timeout

        def remaining():
            nonlocal last
            now = time.monotonic()
            if not math.isfinite(now) or not last <= now < deadline:
                raise subprocess.TimeoutExpired("owned child tree", timeout)
            last = now
            return deadline - now

        if not self._owned_observation_lock.acquire(timeout=remaining()):
            raise NativeOwnershipObservationError("Retirement observation is busy")
        try:
            if not self._handle_lock.acquire(timeout=remaining()):
                raise NativeOwnershipObservationError("Retirement owner is busy")
            try:
                retirement = getattr(self, "_tree_retirement", None)
                if retirement is not None:
                    retirement.current()
                    if retirement.failure or retirement.close_started or retirement.close_held:
                        raise NativeOwnershipObservationError("Existing retirement custody is held")
                    return
                if (type(self._job) is not WindowsChildJob or self._process is None
                        or self._job._handle is None or type(self.pid) is not int
                        or not 1 <= self.pid <= 0xffffffff
                        or self._owned_observation_close_holds):
                    raise NativeOwnershipObservationError("Retirement lifetime unavailable")
                retirement = self._tree_retirement = _OwnedTreeRetirement(self)
                try:
                    retirement.capture(remaining)
                    remaining()
                except BaseException as error:
                    retirement.failure = type(error).__name__
                    raise
            finally:
                self._handle_lock.release()
        finally:
            self._owned_observation_lock.release()

    def tree_retirement_snapshot(self):
        """Detached bounded memory only; no native query or response authority."""
        retirement = getattr(self, "_tree_retirement", None)
        return None if retirement is None else retirement.snapshot()

    def terminate(self):
        # Terminate the job even after its server exits: a runner can outlive it.
        with self._handle_lock:
            retirement = getattr(self, "_tree_retirement", None)
            if retirement is not None:
                retirement.before_terminate()
            self._owned_observation_epoch = getattr(self, "_owned_observation_epoch", 0) + 1
            self._owned_observation_stopped = True
            try:
                self._job.terminate()
            except BaseException:
                if retirement is not None:
                    retirement.epoch = self._owned_observation_epoch
                raise
            if retirement is not None:
                retirement.epoch = self._owned_observation_epoch
                retirement.dispatched = True

    kill = terminate

    def wait_tree(self, timeout=3.0):
        retirement = getattr(self, "_tree_retirement", None)
        if retirement is None:
            self._job.wait_empty(timeout)
            return
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or timeout < 0):
            raise NativeOwnershipObservationError("Invalid retirement wait deadline")
        deadline = retirement.clock() + timeout
        if not self._handle_lock.acquire(timeout=timeout):
            raise subprocess.TimeoutExpired("owned child tree", timeout)
        try:
            retirement.wait(timeout, deadline=deadline)
        finally:
            self._handle_lock.release()

    def wait(self, timeout=None):
        import win32api
        import win32con
        import win32event
        import win32process

        milliseconds = win32event.INFINITE if timeout is None else max(0, int(timeout * 1000))
        # The supervisor's waiter may still be unwinding when STOP closes its
        # owner. Each wait retains the same kernel object independently, so a
        # concurrent close cannot invalidate a pending native wait.
        with self._handle_lock:
            current = win32api.GetCurrentProcess()
            retained = win32api.DuplicateHandle(
                current, self._process, current, 0, False, win32con.DUPLICATE_SAME_ACCESS,
            )
        try:
            if win32event.WaitForSingleObject(retained, milliseconds) == win32event.WAIT_TIMEOUT:
                raise subprocess.TimeoutExpired("owned child", timeout)
            return win32process.GetExitCodeProcess(retained)
        finally:
            retained.Close()

    def close(self):
        with self._handle_lock:
            retirement = getattr(self, "_tree_retirement", None)
            if retirement is not None:
                if retirement.closed:
                    return
                retirement.current()
            self._owned_observation_epoch = getattr(self, "_owned_observation_epoch", 0) + 1
            self._owned_observation_stopped = True
            if retirement is not None:
                retirement.epoch = self._owned_observation_epoch
            observation_lock = getattr(self, "_owned_observation_lock", None)
            if observation_lock is not None and not observation_lock.acquire(blocking=False):
                raise NativeOwnershipObservationError("Child ownership query is still active; lifetime retained")
            try:
                if getattr(self, "_owned_observation_close_holds", ()):
                    raise NativeOwnershipObservationError("Child ownership query close remains unproven; lifetime retained")
                retirement = getattr(self, "_tree_retirement", None)
                if retirement is not None:
                    retirement.close_queries()
                try:
                    self._job.close()
                    handle, self._process = self._process, None
                    if handle is not None:
                        handle.Close()
                except BaseException:
                    if retirement is not None:
                        retirement.close_held = True
                    raise
                if retirement is not None:
                    retirement.finish_close()
            finally:
                if observation_lock is not None:
                    observation_lock.release()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def launch_windows_child(argv, environment, *, cwd=None, deadline=None,
                         check_cancelled=None, kill_on_close=True, window="hidden"):
    """Launch trusted fixed argv in a private job before its first instruction."""
    import win32api
    import win32con
    import win32process

    if not argv or not Path(argv[0]).is_absolute():
        raise ValueError("Owned child requires an absolute executable path")
    image = str(argv[0])
    if deadline is None:
        deadline = time.monotonic() + 10.0
    job = WindowsChildJob(kill_on_close=kill_on_close)
    process = thread = None
    try:
        startup = win32process.STARTUPINFO()
        startup.dwFlags = win32con.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0 if window == "hidden" else (7 if window == "minimized" else 1)
        visibility = (win32con.DETACHED_PROCESS | win32con.CREATE_NEW_PROCESS_GROUP | win32con.CREATE_NO_WINDOW
                      if window == "hidden" else win32con.CREATE_NEW_CONSOLE | win32con.CREATE_NEW_PROCESS_GROUP)
        process, thread, pid, _ = win32process.CreateProcess(
            image, subprocess.list2cmdline(list(argv)),
            None, None, False,
            win32con.CREATE_SUSPENDED | win32con.CREATE_UNICODE_ENVIRONMENT | visibility,
            environment, cwd, startup,
        )
        job.assign(process)
        if time.monotonic() >= deadline:
            raise TimeoutError
        if check_cancelled is not None:
            check_cancelled()
        if win32process.ResumeThread(thread) != 1:
            raise OSError("Owned Ollama thread could not resume")
        result = OwnedWindowsChild(process, pid, job)
        process = None
        job = None
        return result
    finally:
        try:
            if job is not None:
                try:
                    # Assignment failure leaves this exact process suspended.
                    if process is not None:
                        win32api.TerminateProcess(process, 1)
                finally:
                    job.close()
        finally:
            try:
                if process is not None:
                    process.Close()
            finally:
                if thread is not None:
                    thread.Close()
