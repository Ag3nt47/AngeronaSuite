"""Read-only native generation witnesses for one private UGCAP Windows job.

Unseen departed members and ambiguous coverage stay unknown. Native calls are
cooperative; deadlines do not preempt the kernel. No response authority exists
here, and observer handles never request process termination rights.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import time

MAX_MEMBERS = 32
_OBSERVER_RIGHTS = 0x00101000  # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION


class NativeJobMemberAPI:
    def __init__(self):
        if os.name != "nt":
            raise OSError("Native job member observation is unavailable")
        self.api = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
        signatures = {
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "GetProcessId": ([wintypes.HANDLE], wintypes.DWORD),
            "GetProcessTimes": ([wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4, wintypes.BOOL),
            "IsProcessInJob": ([wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
            "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "QueryInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result

    def total(self, job):
        class Accounting(ctypes.Structure):
            _fields_ = [("user", ctypes.c_int64), ("kernel", ctypes.c_int64),
                ("period_user", ctypes.c_int64), ("period_kernel", ctypes.c_int64),
                ("faults", wintypes.DWORD), ("total", wintypes.DWORD),
                ("active", wintypes.DWORD), ("terminated", wintypes.DWORD)]
        value = Accounting()
        if not self.api.QueryInformationJobObject(job, 1, ctypes.byref(value), ctypes.sizeof(value), None):
            raise OSError("Native job accounting is unavailable")
        return int(value.total)

    def snapshot(self, job):
        class ProcessList(ctypes.Structure):
            _fields_ = [("assigned", wintypes.DWORD), ("listed", wintypes.DWORD),
                        ("pids", ctypes.c_size_t * MAX_MEMBERS)]
        before = self.total(job)
        value = ProcessList()
        if not self.api.QueryInformationJobObject(job, 3, ctypes.byref(value), ctypes.sizeof(value), None):
            raise OSError("Native job member list is unavailable")
        after = self.total(job)
        if (before != after or value.assigned != value.listed or value.listed > MAX_MEMBERS):
            raise OSError("Native job member list is incomplete")
        return after, tuple(int(value.pids[index]) for index in range(value.listed))

    def open(self, pid):
        handle = self.api.OpenProcess(_OBSERVER_RIGHTS, False, pid)
        if not handle:
            raise OSError("Native job member handle is unavailable")
        return int(handle)

    def identity(self, handle):
        pid = int(self.api.GetProcessId(handle))
        values = [wintypes.FILETIME() for _ in range(4)]
        if not pid or not self.api.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
            raise OSError("Native job member identity is unavailable")
        return pid, (int(values[0].dwHighDateTime) << 32) | int(values[0].dwLowDateTime)

    def in_job(self, handle, job):
        value = wintypes.BOOL()
        if not self.api.IsProcessInJob(handle, job, ctypes.byref(value)):
            raise OSError("Native job membership is unavailable")
        return bool(value.value)

    def wait(self, handle, timeout):
        result = int(self.api.WaitForSingleObject(handle, min(2000, max(0, int(timeout * 1000)))))
        if result == 0:
            return True
        if result == 258:
            return False
        raise OSError("Native job member completion is unavailable")

    def close(self, handle):
        return bool(self.api.CloseHandle(handle))


class JobMemberWitness:
    """Bounded custody and lifetime coverage; injected APIs are inert test seams."""
    def __init__(self, api):
        self.api = api
        self.records = {}
        self.unbound = []
        self.covered_total = None
        self.failure = ""

    def _fail(self, reason):
        if not self.failure:
            self.failure = reason
        return False

    def _close(self, record):
        handle = record["handle"]
        if handle is None:
            return record["closed"] is True
        record["handle"], record["closed"] = None, False
        try:
            record["closed"] = self.api.close(handle) is True
        except BaseException:
            pass
        if not record["closed"]:
            self._fail("member-close-unknown")
        return record["closed"]

    @staticmethod
    def _snapshot(value):
        if not isinstance(value, tuple) or len(value) != 2:
            raise ValueError("invalid member snapshot")
        total, pids = value
        if (type(total) is not int or not 0 <= total <= MAX_MEMBERS
                or not isinstance(pids, tuple) or len(pids) > MAX_MEMBERS
                or len(set(pids)) != len(pids) or total < len(pids)
                or any(type(pid) is not int or not 0 < pid <= 0xFFFFFFFF for pid in pids)):
            raise ValueError("invalid member snapshot")
        return total, pids

    def capture(self, job, deadline):
        if self.failure:
            return False
        try:
            if time.monotonic() >= deadline:
                return self._fail("member-capture-deadline")
            total, pids = self._snapshot(self.api.snapshot(job))
            if self.covered_total is not None and total < self.covered_total:
                return self._fail("member-counter-regressed")
            for pid in pids:
                if time.monotonic() >= deadline:
                    return self._fail("member-capture-deadline")
                record = dict(handle=self.api.open(pid), closed=None, signaled=False)
                if type(record["handle"]) is not int or record["handle"] <= 0:
                    return self._fail("member-open-unavailable")
                # Retain before identity/membership calls can fail. Never drop
                # an opened handle in a local-list rollback.
                self.unbound.append(record)
                identity = self.api.identity(record["handle"])
                if (not isinstance(identity, tuple) or len(identity) != 2 or identity[0] != pid
                        or type(identity[0]) is not int or type(identity[1]) is not int or identity[1] <= 0
                        or self.api.in_job(record["handle"], job) is not True):
                    raise ValueError("member identity or membership differs")
                if identity in self.records:
                    if not self._close(record):
                        return False
                else:
                    if len(self.records) >= MAX_MEMBERS:
                        return self._fail("member-history-capacity")
                    self.records[identity] = record
                self.unbound.remove(record)
            after, current = self._snapshot(self.api.snapshot(job))
            if (after != total or after != len(self.records)
                    or not set(current).issubset({identity[0] for identity in self.records})):
                return self._fail("member-history-uncovered")
            if time.monotonic() >= deadline:
                return self._fail("member-capture-deadline")
            self.covered_total = after
            return True
        except BaseException as error:
            self._fail("member-capture-unavailable")
            if not isinstance(error, Exception):
                raise
            return False

    def check_total(self, job):
        try:
            total = self.api.total(job)
            if (self.failure or self.covered_total is None or type(total) is not int
                    or total != self.covered_total or total != len(self.records) or not 0 <= total <= MAX_MEMBERS):
                return self._fail("member-history-uncovered")
            return True
        except BaseException:
            return self._fail("member-accounting-unavailable")

    def wait_terminated(self, deadline):
        complete = True
        for identity, record in self.records.items():
            if not record["signaled"]:
                handle = record["handle"]
                if handle is None or time.monotonic() >= deadline:
                    complete = False
                    continue
                try:
                    if self.api.identity(handle) != identity:
                        self._fail("member-identity-changed")
                        complete = False
                        continue
                    signaled = self.api.wait(handle, max(0.0, deadline - time.monotonic()))
                    if signaled is not True:
                        complete = False
                        continue
                    record["signaled"] = True
                except BaseException:
                    self._fail("member-completion-unavailable")
                    complete = False
                    continue
            complete = self._close(record) and complete
        # Invalid/unbound observations grant no member coverage. They can be
        # closed once, but their missing generation permanently keeps pending.
        for record in self.unbound:
            complete = self._close(record) and complete
        return (complete and not self.failure and self.covered_total == len(self.records)
                and time.monotonic() < deadline)

    def proof(self):
        return dict(covered_total=self.covered_total, failure=self.failure,
            members=[dict(pid=key[0], birth_raw=key[1], signaled=value["signaled"],
                          close_confirmed=value["closed"] is True) for key, value in self.records.items()])
