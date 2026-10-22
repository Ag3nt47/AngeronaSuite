"""Bounded custody of one Windows process object for governed termination.

This binds a mutation to an opened kernel object, not a future PID lookup. It
does not attest loaded code, prevent process exit, or confer response authority.
"""
from __future__ import annotations

import math
import ntpath
import os
import time
from dataclasses import dataclass
from typing import Any, Callable


_RIGHTS = 0x1000 | 0x00100000 | 0x0001  # limited query, synchronize, terminate
_WINDOWS_EPOCH_TICKS = 116444736000000000
_MAX_LIFETIME = 60.0


class ProcessLeaseError(RuntimeError):
    """The exact process object, lifetime, or completion could not be proven."""


def _image_path(value: object) -> str:
    if (not isinstance(value, str) or not value or len(value) > 32767
            or any(ord(char) < 32 for char in value)):
        raise ProcessLeaseError("process image is unavailable")
    drive, tail = ntpath.splitdrive(value)
    if (len(drive) != 2 or drive[0] not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            or drive[1] != ":" or not tail.startswith(("\\", "/"))):
        raise ProcessLeaseError("process image must be a local absolute DOS path")
    return ntpath.normcase(ntpath.normpath(value))


@dataclass(frozen=True)
class ProcessObjectIdentity:
    pid: int
    birth_ticks: int
    image: str

    @property
    def create_time(self) -> float:
        return (self.birth_ticks - _WINDOWS_EPOCH_TICKS) / 10_000_000


class _Native:
    def __init__(self) -> None:
        if os.name != "nt":
            raise ProcessLeaseError("native Windows process custody is unavailable")
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "GetProcessId": ([wintypes.HANDLE], wintypes.DWORD),
            "GetProcessTimes": ([wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4,
                                wintypes.BOOL),
            "QueryFullProcessImageNameW": (
                [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                 ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
            "TerminateProcess": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "GetExitCodeProcess": ([wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)],
                                   wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes = arguments
            function.restype = result

    def _error(self, operation: str) -> ProcessLeaseError:
        return ProcessLeaseError(f"{operation} failed (Windows {self.ctypes.get_last_error()})")

    def open(self, pid: int, rights: int, inherit: bool) -> int:
        handle = self.api.OpenProcess(rights, inherit, pid)
        if not handle:
            raise self._error("OpenProcess")
        return int(handle)

    def object_identity(self, handle: int) -> tuple[int, int]:
        pid = int(self.api.GetProcessId(handle))
        if not pid:
            raise self._error("GetProcessId")
        times = [self.wintypes.FILETIME() for _ in range(4)]
        if not self.api.GetProcessTimes(handle, *(self.ctypes.byref(value) for value in times)):
            raise self._error("GetProcessTimes")
        birth = (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)
        return pid, birth

    def identity(self, handle: int) -> ProcessObjectIdentity:
        pid, birth = self.object_identity(handle)
        size = self.wintypes.DWORD(32768)
        buffer = self.ctypes.create_unicode_buffer(size.value)
        if not self.api.QueryFullProcessImageNameW(handle, 0, buffer, self.ctypes.byref(size)):
            raise self._error("QueryFullProcessImageNameW")
        if not 0 < size.value < len(buffer):
            raise ProcessLeaseError("native process image length is invalid")
        return ProcessObjectIdentity(pid, birth, _image_path(buffer[:size.value]))

    def wait(self, handle: int, milliseconds: int) -> bool:
        result = int(self.api.WaitForSingleObject(handle, milliseconds))
        if result == 0:
            return True
        if result == 258:
            return False
        raise self._error("WaitForSingleObject")

    def exit_code(self, handle: int) -> int:
        code = self.wintypes.DWORD()
        if not self.api.GetExitCodeProcess(handle, self.ctypes.byref(code)):
            raise self._error("GetExitCodeProcess")
        return int(code.value)

    def terminate(self, handle: int, code: int) -> None:
        if not self.api.TerminateProcess(handle, code):
            raise self._error("TerminateProcess")

    def close(self, handle: int) -> None:
        if not self.api.CloseHandle(handle):
            raise self._error("CloseHandle")


class WindowsProcessLease:
    """One non-inheritable, least-rights handle with a monotonic deadline.

    Injected native operations are a test seam, never a transport or policy
    interface. Callers must retain this object through intent and terminal
    persistence and enforce their protected-process policy on ``identity``.
    """

    def __init__(
        self, pid: int, create_time: float, image: str, *, lifetime: float = 60.0,
        _native: Any = None, _monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
            raise ProcessLeaseError("invalid process identifier")
        if (type(create_time) not in (int, float) or not math.isfinite(create_time)
                or create_time <= 0):
            raise ProcessLeaseError("invalid expected process birth")
        if (type(lifetime) not in (int, float) or not math.isfinite(lifetime)
                or not 0 < lifetime <= _MAX_LIFETIME):
            raise ProcessLeaseError("invalid process custody lifetime")
        expected_image = _image_path(image)
        self._clock = _monotonic
        self._last_now = float(self._clock())
        if not math.isfinite(self._last_now):
            raise ProcessLeaseError("invalid monotonic clock")
        self._deadline = self._last_now + lifetime
        self._native = _Native() if _native is None else _native
        self._handle: int | None = None
        self._dispatched = False
        self.identity: ProcessObjectIdentity
        try:
            self._handle = self._native.open(pid, _RIGHTS, False)
            observed = self._native.identity(self._handle)
            if (type(observed) is not ProcessObjectIdentity or observed.pid != pid
                    or type(observed.birth_ticks) is not int
                    or abs(observed.create_time - create_time) > 0.001
                    or _image_path(observed.image) != expected_image):
                raise ProcessLeaseError("native process identity differs from expected target")
            self.identity = observed
            self.validate(alive=True)
        except BaseException:
            self.close()
            raise

    def _remaining(self) -> float:
        now = float(self._clock())
        if not math.isfinite(now) or now < self._last_now or now >= self._deadline:
            raise ProcessLeaseError("process custody expired or monotonic clock regressed")
        self._last_now = now
        if self._handle is None:
            raise ProcessLeaseError("process custody is closed")
        return self._deadline - now

    def validate(self, *, alive: bool) -> None:
        self._remaining()
        if alive:
            if self._native.identity(self._handle) != self.identity:
                raise ProcessLeaseError("retained process identity changed")
        else:
            # Windows can discard the image pathname after exit (error 31).
            # The retained object cannot become a later process: prove its raw
            # birth/PID again and preserve the image checked before dispatch.
            if self._native.object_identity(self._handle) != (
                self.identity.pid, self.identity.birth_ticks,
            ):
                raise ProcessLeaseError("retained process identity changed")
        exited = self._native.wait(self._handle, 0)
        if type(exited) is not bool or exited == alive:
            raise ProcessLeaseError("retained process liveness does not match required state")
        self._remaining()

    def terminate(self) -> None:
        if self._dispatched:
            raise ProcessLeaseError("process termination was already dispatched")
        self.validate(alive=True)
        self._dispatched = True
        self._native.terminate(self._handle, 1)

    @property
    def dispatch_started(self) -> bool:
        """Whether the native call crossed the possible-effect boundary."""
        return self._dispatched

    def wait_terminated(self, timeout: float = 3.0) -> None:
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 3):
            raise ProcessLeaseError("invalid process completion wait")
        budget = min(float(timeout), self._remaining())
        milliseconds = min(3000, max(0, int(budget * 1000)))
        exited = self._native.wait(self._handle, milliseconds)
        if exited is not True:
            raise ProcessLeaseError("process termination completion was not proven")
        self.validate(alive=False)

    def terminal_proof(self) -> dict[str, Any]:
        self.validate(alive=False)
        code = self._native.exit_code(self._handle)
        if type(code) is not int or not 0 <= code <= 0xFFFFFFFF:
            raise ProcessLeaseError("process exit status is unavailable")
        self._remaining()
        return {
            "process_custody": "windows-retained-handle-v1",
            "native_pid": self.identity.pid,
            "native_birth_ticks": self.identity.birth_ticks,
            "native_image": self.identity.image,
            "native_image_observation": "before-termination",
            "native_exit_code": code,
            "native_wait_signaled": True,
        }

    def close(self) -> None:
        if self._handle is not None:
            handle, self._handle = self._handle, None
            # Do not retry a failed CloseHandle against a possibly reused value.
            self._native.close(handle)

    def __enter__(self) -> WindowsProcessLease:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
