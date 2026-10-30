"""Bounded Windows birth observations for advisory process inventory only.

Imports do not load DLLs or query the host. ``create_reader`` admits the exact
reviewed psutil seam and native AMD64 runtime when collection actually starts.
Each reader belongs to one scan; ``read`` always executes a new system query.
Nothing here establishes executable custody or grants response authority.

Layout reference (BSD-licensed psutil 7.2.2, copyright Jay Loden / Giampaolo
Rodola'):
https://github.com/giampaolo/psutil/blob/release-7.2.2/psutil/arch/windows/ntextapi.h
The same release's proc_info.c supplies fallback semantics and init.c supplies
the integer-first FILETIME conversion. Microsoft's public SPI declaration
reserves the CreateTime bytes, so this is a compatibility-gated adapter:
https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
"""
from __future__ import annotations

import ctypes
import functools
import math
import struct
import sys
from types import MappingProxyType
from typing import Mapping

_INITIAL_BUFFER = 256 * 1024
_MAX_BUFFER = 16 * 1024 * 1024
_MAX_ATTEMPTS = 4
_MAX_ROWS = 65_536
_EPOCH = 116444736000000000
_MAX_FILETIME = (1 << 63) - 1
_HEADER_SIZE = 256
_THREAD_SIZE = 80
_SYSTEM_PROCESS_INFORMATION = 5
_LENGTH_STATUSES = {0xC0000004, 0xC0000023}
_AMD64 = 0x8664
_SYSTEM32 = 0x00000800


@functools.lru_cache(maxsize=2)
def _system_library(name: str):
    # Retain only the two system-DLL bindings for this Python process. Repeated
    # reader construction must not repeatedly increment LoadLibrary's count.
    # No process observations, architecture result or self-witness are cached.
    return ctypes.WinDLL(name, use_last_error=True, winmode=_SYSTEM32)


class BirthObservationError(ValueError):
    """A fixed diagnostic code, never native error text or process metadata."""

    def __init__(self, code: str):
        if (type(code) is not str or not 0 < len(code) <= 80
                or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in code)):
            code = "adapter-error"
        self.code = code
        super().__init__(code)


def filetime_to_unix(ticks: int) -> float | None:
    """Match psutil 7.2.2's double conversion without accepting wraparound.

    Cast *after* the integer epoch subtraction, then divide as a double. The
    alternate ``ticks / 1e7 - epoch_seconds`` can change the resulting bits.
    Zero is an unavailable native birth, not a process identity.
    """
    if type(ticks) is not int or not 0 <= ticks <= _MAX_FILETIME:
        raise BirthObservationError("birth-range")
    if ticks == 0:
        return None
    if ticks <= _EPOCH:
        raise BirthObservationError("birth-epoch")
    return float(ticks - _EPOCH) / 10000000.0


def cached_fast_birth(process) -> float | None:
    """Read, never populate, the admitted public Process object's fast cache.

    Public Process construction already tried its independent fast birth
    query. Calling create_time() when this field is None would execute the
    expensive whole-system fallback we replace. No Process identity/cache is
    written, and no cached Process object survives the collector's scan.
    """
    fields = vars(process)
    if "_create_time" not in fields:
        raise BirthObservationError("fast-cache-shape")
    value = fields["_create_time"]
    if value is None:
        return None
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
    except (OverflowError, ValueError):
        valid = False
    if not valid:
        raise BirthObservationError("fast-cache-value")
    return float(value)


def bracket_births(pid: int, before_fast: float | None, after_fast: float | None,
                   before: Mapping[int, int] | None,
                   after: Mapping[int, int] | None) -> tuple[float | None, float | None]:
    """Keep all independently known births consistent, including raw bits."""
    first = before.get(pid) if before is not None else None
    second = after.get(pid) if after is not None else None
    first_birth = filetime_to_unix(first) if first is not None else None
    second_birth = filetime_to_unix(second) if second is not None else None
    if (before_fast is not None and after_fast is not None
            and before_fast > 0 and after_fast > 0 and before_fast != after_fast):
        raise BirthObservationError("fast-birth-changed")
    if first_birth is not None and second_birth is not None and first != second:
        # Distinct 100 ns timestamps can collapse to the same public float.
        raise BirthObservationError("raw-birth-changed")
    for fast in (before_fast, after_fast):
        if fast is not None and fast > 0:
            for observed in (first_birth, second_birth):
                if observed is not None and fast != observed:
                    raise BirthObservationError("fast-birth-mismatch")
    if first_birth is None or second_birth is None:
        return None, None
    # proc_info()'s denied fallback special-cases PID 0 and 4 to zero; do
    # not promote their raw kernel births when the public fast read failed.
    return (
        before_fast if before_fast is not None else (0.0 if pid in (0, 4) else first_birth),
        after_fast if after_fast is not None else (0.0 if pid in (0, 4) else second_birth),
    )


def _compatible_psutil(psutil) -> bool:
    """Reject replaced test factories/backends before any native admission."""
    process = getattr(psutil, "Process", None)
    platform = getattr(psutil, "_psplatform", None)
    backend = getattr(platform, "Process", None)
    native = getattr(platform, "cext", None)
    return bool(
        getattr(psutil, "__version__", None) == "7.2.2"
        and getattr(psutil, "WINDOWS", False) is True
        and isinstance(process, type) and process.__module__ == "psutil"
        and getattr(getattr(psutil, "pids", None), "__module__", None) == "psutil"
        and getattr(getattr(process, "as_dict", None), "__module__", None) == "psutil"
        and getattr(getattr(process, "_get_ident", None), "__module__", None) == "psutil"
        and getattr(platform, "__name__", None) == "psutil._pswindows"
        and isinstance(backend, type) and backend.__module__ == "psutil._pswindows"
        and getattr(getattr(backend, "create_time", None), "__module__", None) == "psutil._pswindows"
        and getattr(native, "version", None) == 722
        and getattr(getattr(native, "proc_times", None), "__module__", None) == "psutil_windows"
    )


def _native_amd64() -> bool:
    """Admit only a native AMD64 worker, using its own pseudo handle.

    No target process handle or per-PID architecture query is needed. WOW64,
    ARM64 and emulated AMD64 remain on the existing collector until reviewed.
    https://learn.microsoft.com/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2
    """
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        return False
    kernel = _system_library("kernel32.dll")
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.IsWow64Process2.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort),
    ]
    kernel.IsWow64Process2.restype = ctypes.c_int32
    process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
    if not kernel.IsWow64Process2(
        kernel.GetCurrentProcess(), ctypes.byref(process_machine), ctypes.byref(native_machine),
    ):
        return False
    return process_machine.value == 0 and native_machine.value == _AMD64


def create_reader(psutil):
    """Select compatibility before collection; never fall back after read()."""
    if sys.platform != "win32" or not _compatible_psutil(psutil):
        return None
    try:
        if not _native_amd64():
            return None
    except (OSError, AttributeError):
        # Missing architecture support is selected before PID enumeration or
        # the first birth query. Once admitted, even binding loss is explicit.
        return None
    try:
        return _WindowsBirthReader()
    except (OSError, AttributeError) as exc:
        raise BirthObservationError("native-binding") from exc


def parse_births(data, returned: int, base: int) -> Mapping[int, int]:
    """Parse only bounded AMD64 bytes; never dereference native pointers.

    The fixed SPI header is 256 bytes, its thread records are 80 bytes and its
    CreateTime is at offset 32 in the pinned layout. ImageName's length fields
    count UTF-16 bytes, not characters; its pointer is range-checked as an
    integer and is never dereferenced or decoded. ImageName is not exe evidence.
    https://learn.microsoft.com/windows/win32/api/ntdef/ns-ntdef-_unicode_string
    """
    if type(data) not in (bytes, bytearray, memoryview):
        raise BirthObservationError("buffer-type")
    try:
        view = memoryview(data).cast("B")
    except (TypeError, ValueError) as exc:
        raise BirthObservationError("buffer-shape") from exc
    if (type(returned) is not int or not _HEADER_SIZE <= returned <= _MAX_BUFFER
            or returned > len(view) or type(base) is not int
            or not 0 < base < (1 << 64) or base + returned > (1 << 64)):
        raise BirthObservationError("buffer-range")
    births: dict[int, int] = {}
    offset = 0
    while True:
        if len(births) >= _MAX_ROWS:
            raise BirthObservationError("row-limit")
        if offset > returned - _HEADER_SIZE:
            raise BirthObservationError("header-range")
        next_offset, threads = struct.unpack_from("<II", view, offset)
        if next_offset:
            if (next_offset % 8 or next_offset < _HEADER_SIZE
                    or next_offset > returned - offset):
                raise BirthObservationError("next-offset")
            end = offset + next_offset
            # A nonterminal entry must leave a complete next header.
            if end > returned - _HEADER_SIZE:
                raise BirthObservationError("next-header")
        else:
            end = returned
        if threads > (end - offset - _HEADER_SIZE) // _THREAD_SIZE:
            raise BirthObservationError("thread-range")
        pid, parent = struct.unpack_from("<QQ", view, offset + 80)
        if pid > 0xFFFFFFFF or parent > 0xFFFFFFFF:
            raise BirthObservationError("pid-range")
        if pid in births:
            raise BirthObservationError("duplicate-pid")
        ticks = struct.unpack_from("<q", view, offset + 32)[0]
        filetime_to_unix(ticks)  # validates raw ticks without discarding precision
        length, maximum = struct.unpack_from("<HH", view, offset + 56)
        pointer = struct.unpack_from("<Q", view, offset + 64)[0]
        if length % 2 or maximum % 2 or length > maximum:
            raise BirthObservationError("image-length")
        if maximum:
            relative = pointer - base
            if relative < 0 or relative > returned or maximum > returned - relative:
                raise BirthObservationError("image-range")
        births[pid] = ticks
        if not next_offset:
            return MappingProxyType(births)
        offset = end


class _WindowsBirthReader:
    """One scan's storage and runtime binding; no observed-map cache."""

    def __init__(self, query=None, *, witness=None):
        self._library = None
        if query is None:
            self._library = _system_library("ntdll.dll")
            query = self._library.NtQuerySystemInformation
            query.argtypes = [
                ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
            ]
            query.restype = ctypes.c_int32
            witness = _own_witness()
        elif witness is None:
            # Synthetic query injection must not accidentally query the host.
            raise BirthObservationError("witness-required")
        if (type(witness) is not tuple or len(witness) != 2
                or type(witness[0]) is not int or not 0 < witness[0] <= 0xFFFFFFFF
                or filetime_to_unix(witness[1]) is None):
            raise BirthObservationError("witness-shape")
        self._own_pid, self._own_birth = witness
        self._query = query
        self._buffer = None
        self._capacity = 0

    @property
    def own_pid(self) -> int:
        """Already witnessed worker PID, solely for inventory coverage checks."""
        return self._own_pid

    def read(self) -> Mapping[int, int]:
        for _attempt in range(_MAX_ATTEMPTS):
            if self._buffer is None:
                self._capacity = _INITIAL_BUFFER
                self._buffer = ctypes.create_string_buffer(self._capacity)
            returned = ctypes.c_uint32()
            status = self._query(
                _SYSTEM_PROCESS_INFORMATION, self._buffer, self._capacity,
                ctypes.byref(returned),
            )
            status = int(status) & 0xFFFFFFFF
            if status == 0:
                births = parse_births(
                    memoryview(self._buffer), returned.value, ctypes.addressof(self._buffer),
                )
                # Reserved-layout self-witness only: this is not process
                # custody or response authority. Compare all FILETIME bits.
                if births.get(self._own_pid) != self._own_birth:
                    raise BirthObservationError("self-witness-mismatch")
                return births
            if status not in _LENGTH_STATUSES:
                raise BirthObservationError(f"query-status-{status:08x}")
            capacity = max(returned.value, self._capacity * 2)
            if capacity > _MAX_BUFFER:
                raise BirthObservationError("buffer-limit")
            if _attempt + 1 == _MAX_ATTEMPTS:
                break
            self._buffer = ctypes.create_string_buffer(capacity)
            self._capacity = capacity
        raise BirthObservationError("query-attempt-limit")


class _Filetime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


def _own_witness() -> tuple[int, int]:
    """Read the worker's own exact birth; never close its pseudo handle.

    GetProcessTimes' FILETIME contains the raw count of 100 ns intervals since
    1601. It witnesses the private layout in each later independent bulk query.
    https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
    """
    kernel = _system_library("kernel32.dll")
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.GetCurrentProcessId.argtypes = []
    kernel.GetCurrentProcessId.restype = ctypes.c_uint32
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(_Filetime)] * 4
    kernel.GetProcessTimes.restype = ctypes.c_int32
    times = [_Filetime() for _ in range(4)]
    if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), *(ctypes.byref(t) for t in times)):
        raise BirthObservationError("self-witness-query")
    return kernel.GetCurrentProcessId(), (times[0].high << 32) | times[0].low
