"""Retain current Windows process/path objects during one firewall transaction.

This is identity custody, never response authority, loaded-image attestation or
PID-bound socket admission. Native filesystem calls obey a cooperative deadline;
they are not forcibly preempted. The physical handles remain held for exact-rule
compensation even when validation has expired.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import ntpath
import os
import re
import time
from typing import Any, Callable

from .windows_process_lease import ProcessObjectIdentity, _Native as _ProcessNative


_PROCESS_RIGHTS = 0x1000 | 0x00100000  # QUERY_LIMITED_INFORMATION | SYNCHRONIZE
_READ_ACCESS = 0x0001 | 0x0080  # READ_DATA / LIST_DIRECTORY | READ_ATTRIBUTES
_SHARE_READ = 0x0001
_MAX_ANCESTORS = 32
_MAX_LIFETIME = 60.0
_REPARSE = 0x0400
_DIRECTORY = 0x0010
_RESERVED = re.compile(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?\Z", re.I)


class ProgramFirewallLeaseError(RuntimeError):
    """Current process or executable path custody could not be established."""


def _path(value: object) -> str:
    if (type(value) is not str or not 3 <= len(value) <= 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ProgramFirewallLeaseError("program path is unavailable or oversized")
    value = value.replace("/", "\\")
    drive, tail = ntpath.splitdrive(value)
    if (len(drive) != 2 or drive[0] not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            or drive[1] != ":" or not tail.startswith("\\") or tail.startswith("\\\\")):
        raise ProgramFirewallLeaseError("program path must be an absolute local DOS path")
    parts = tail[1:].split("\\") if tail != "\\" else []
    if any(not part or part in {".", ".."} or part.endswith((" ", "."))
           or any(char in ':*?<>|"' for char in part) or _RESERVED.fullmatch(part)
           for part in parts):
        raise ProgramFirewallLeaseError("program path contains an alias or unsupported component")
    # Preserve spelling for every native open. NTFS directories can opt into
    # case-sensitive lookup; folding here could select a different sibling.
    return value


@dataclass(frozen=True)
class FileObjectIdentity:
    volume: int
    file_id: str
    attributes: int
    links: int
    size: int
    write_ticks: int
    name: str


class _Native:
    """Closed native API surface; no process mutation rights or operations."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise ProgramFirewallLeaseError("Windows program custody is unavailable")
        import ctypes as c
        from ctypes import wintypes as w

        self.c, self.w = c, w
        self.process = _ProcessNative()
        self.api = c.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "GetDriveTypeW": ([w.LPCWSTR], w.UINT),
            "CreateFileW": ([w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
            "GetFileType": ([w.HANDLE], w.DWORD),
            "GetFileInformationByHandle": ([w.HANDLE, w.LPVOID], w.BOOL),
            "GetFileInformationByHandleEx": ([w.HANDLE, c.c_int, w.LPVOID, w.DWORD], w.BOOL),
            "GetFinalPathNameByHandleW": ([w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD], w.DWORD),
            "QueryFullProcessImageNameW": ([w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result

    def _error(self, operation: str) -> ProgramFirewallLeaseError:
        return ProgramFirewallLeaseError(f"{operation} failed (Windows {self.c.get_last_error()})")

    def fixed_drive(self, root: str) -> bool:
        return self.api.GetDriveTypeW(root) == 3  # DRIVE_FIXED, before pathname I/O.

    def open_process(self, pid: int, rights: int, inherit: bool) -> int:
        return self.process.open(pid, rights, inherit)

    def process_identity(self, handle: int) -> ProcessObjectIdentity:
        # The termination lease intentionally has its own historical path
        # normalization. Do not reuse that image query for path custody.
        pid, birth = self.process.object_identity(handle)
        size = self.w.DWORD(32768)
        buffer = self.c.create_unicode_buffer(size.value)
        if not self.api.QueryFullProcessImageNameW(handle, 0, buffer, self.c.byref(size)):
            raise self._error("QueryFullProcessImageNameW")
        if not 0 < size.value < len(buffer):
            raise ProgramFirewallLeaseError("native process image length is invalid")
        return ProcessObjectIdentity(pid, birth, _path(buffer[:size.value]))

    def process_exited(self, handle: int) -> bool:
        return self.process.wait(handle, 0)

    def open_file(self, path: str, directory: bool) -> int:
        # A non-null security descriptor is unnecessary: these handles are not
        # inheritable. READ_ATTRIBUTES alone would not enforce sharing custody.
        handle = self.api.CreateFileW(path, _READ_ACCESS, _SHARE_READ, None, 3,
            0x00200000 | (0x02000000 if directory else 0), None)
        if handle == self.w.HANDLE(-1).value:
            raise self._error("CreateFileW")
        return int(handle)

    def file_identity(self, handle: int) -> FileObjectIdentity:
        c, w = self.c, self.w

        class Information(c.Structure):
            _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME),
                        ("accessed", w.FILETIME), ("written", w.FILETIME),
                        ("volume", w.DWORD), ("size_high", w.DWORD),
                        ("size_low", w.DWORD), ("links", w.DWORD),
                        ("index_high", w.DWORD), ("index_low", w.DWORD)]

        class FileId(c.Structure):
            _fields_ = [("volume", c.c_ulonglong), ("identifier", c.c_ubyte * 16)]

        info, identity = Information(), FileId()
        if self.api.GetFileType(handle) != 1:  # FILE_TYPE_DISK
            raise ProgramFirewallLeaseError("program custody object is not a disk object")
        if not self.api.GetFileInformationByHandle(handle, c.byref(info)):
            raise self._error("GetFileInformationByHandle")
        if not self.api.GetFileInformationByHandleEx(handle, 18, c.byref(identity), c.sizeof(identity)):
            raise self._error("GetFileInformationByHandleEx(FileIdInfo)")
        buffer = c.create_unicode_buffer(32768)
        length = self.api.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not 0 < length < len(buffer):
            raise self._error("GetFinalPathNameByHandleW")
        name = buffer[:length]
        if name.startswith("\\\\?\\"):
            name = name[4:]
        return FileObjectIdentity(int(identity.volume), bytes(identity.identifier).hex(),
            int(info.attributes), int(info.links), (int(info.size_high) << 32) | int(info.size_low),
            (int(info.written.dwHighDateTime) << 32) | int(info.written.dwLowDateTime), _path(name))

    def directory_case_flags(self, handle: int) -> int:
        # FILE_CASE_SENSITIVE_INFO / FILE_CASE_SENSITIVE_INFORMATION is one
        # ULONG Flags. Unsupported queries are uncertainty, never "disabled".
        flags = self.c.c_uint32()
        if not self.api.GetFileInformationByHandleEx(handle, 23, self.c.byref(flags), self.c.sizeof(flags)):
            raise self._error("GetFileInformationByHandleEx(FileCaseSensitiveInfo)")
        return int(flags.value)

    def close(self, handle: int) -> None:
        if not self.api.CloseHandle(handle):
            raise self._error("CloseHandle")


class ProgramFirewallLease:
    """One acquired current process/executable/ancestor set, maximum 60 seconds.

    Injected APIs/clocks are inert test seams. Expected birth is the existing
    detector contract's float; acquired raw FILETIME and file identity are new
    transaction evidence, not a detector-signed or originally mapped file ID.
    """

    def __init__(self, pid: int, create_time: float, image: str, *, lifetime: float = 60.0,
                 _native: Any = None, _monotonic: Callable[[], float] = time.monotonic) -> None:
        if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
            raise ProgramFirewallLeaseError("invalid process identifier")
        if (type(create_time) not in (int, float) or not 0 < create_time < 253402300800
                or not math.isfinite(create_time)):
            raise ProgramFirewallLeaseError("invalid expected process birth")
        if (type(lifetime) not in (int, float) or not 0 < lifetime <= _MAX_LIFETIME
                or not math.isfinite(lifetime)):
            raise ProgramFirewallLeaseError("invalid program custody lifetime")
        expected_path = _path(image)
        drive, tail = ntpath.splitdrive(expected_path)
        components = tail[1:].split("\\")
        if not components[-1] or len(components) > _MAX_ANCESTORS:
            raise ProgramFirewallLeaseError("program ancestry exceeds its bound")
        self._clock = _monotonic
        self._last_now = float(self._clock())
        if not math.isfinite(self._last_now):
            raise ProgramFirewallLeaseError("invalid monotonic clock")
        self._deadline = self._last_now + float(lifetime)
        self._native = _Native() if _native is None else _native
        self._process: int | None = None
        self._files: list[tuple[str, int, FileObjectIdentity, bool]] = []
        self._closed = False
        self._close_uncertain = False
        try:
            if self._native.fixed_drive(drive + "\\") is not True:
                raise ProgramFirewallLeaseError("program volume is not a fixed local drive")
            self._time_left()
            self._process = self._native.open_process(pid, _PROCESS_RIGHTS, False)
            self.identity = self._native.process_identity(self._process)
            if (type(self.identity) is not ProcessObjectIdentity or type(self.identity.pid) is not int
                    or self.identity.pid != pid
                    or type(self.identity.birth_ticks) is not int
                    or abs(self.identity.create_time - create_time) > .001
                    or ntpath.normcase(_path(self.identity.image)) != ntpath.normcase(expected_path)):
                raise ProgramFirewallLeaseError("retained process differs from expected target")
            # The caller's spelling is only an admission comparison. It never
            # supplies a pathname for any file open or the eventual firewall
            # command. Native spelling survives unchanged throughout custody.
            self._image_path = _path(self.identity.image)
            drive, tail = ntpath.splitdrive(self.path)
            components = tail[1:].split("\\")
            if not components[-1] or len(components) > _MAX_ANCESTORS:
                raise ProgramFirewallLeaseError("native program ancestry exceeds its bound")
            if self._native.fixed_drive(drive + "\\") is not True:
                raise ProgramFirewallLeaseError("native program volume is not a fixed local drive")
            self._check_process()
            parents = [drive + "\\"]
            parents.extend(drive + "\\" + "\\".join(components[:count])
                           for count in range(1, len(components)))
            for name, directory in [(name, True) for name in parents] + [(self.path, False)]:
                self._time_left()
                self._check_ancestry()
                handle = self._native.open_file(name, directory)
                # Register ownership before any metadata query can fail.
                self._files.append((name, handle, None, directory))
                if directory:
                    self._check_directory(handle)
                identity = self._native.file_identity(handle)
                self._check_file(identity, name, directory)
                self._files[-1] = (name, handle, identity, directory)
                self._validate_files()
                self._check_process()
            self.validate()
            # Positive case-insensitive admission follows proven insensitive
            # ancestors and exact held/named volume + file-ID comparisons.
            if ntpath.normcase(expected_path) != ntpath.normcase(self.path):
                raise ProgramFirewallLeaseError("expected program spelling is not equivalent")
        except BaseException as error:
            try:
                self.close()
            except Exception as close_error:
                raise ProgramFirewallLeaseError("partial custody cleanup is unproven") from close_error
            raise error

    def _time_left(self) -> None:
        now = float(self._clock())
        if self._closed or not math.isfinite(now) or now < self._last_now or now >= self._deadline:
            raise ProgramFirewallLeaseError("program custody expired, closed or clock regressed")
        self._last_now = now

    @property
    def path(self) -> str:
        return self._image_path

    def _check_file(self, value: object, path: str, directory: bool) -> None:
        self._check_ancestry()
        if (type(value) is not FileObjectIdentity or type(value.volume) is not int
                or not 0 < value.volume < 2**64 or type(value.file_id) is not str
                or not re.fullmatch(r"[0-9a-f]{32}", value.file_id)
                or value.file_id == "0" * 32 or ntpath.normcase(_path(value.name)) != ntpath.normcase(path)
                or type(value.attributes) is not int or not 0 <= value.attributes < 2**32
                or value.attributes & _REPARSE
                or bool(value.attributes & _DIRECTORY) != directory
                or type(value.links) is not int or value.links < 1
                or (not directory and value.links != 1)
                or type(value.size) is not int or not 0 <= value.size < 2**63
                or type(value.write_ticks) is not int or not 0 <= value.write_ticks < 2**64):
            raise ProgramFirewallLeaseError("program object is aliased, redirected or unavailable")

    @staticmethod
    def _same(left: FileObjectIdentity, right: FileObjectIdentity, directory: bool) -> bool:
        identity = (left.volume, left.file_id, left.attributes, left.links, ntpath.normcase(left.name))
        other = (right.volume, right.file_id, right.attributes, right.links, ntpath.normcase(right.name))
        return identity == other and (directory or (left.size, left.write_ticks) == (right.size, right.write_ticks))

    def _check_process(self) -> None:
        self._time_left()
        if (self._process is None or self._native.process_identity(self._process) != self.identity
                or self._native.process_exited(self._process) is not False):
            raise ProgramFirewallLeaseError("retained process identity or liveness changed")
        self._time_left()

    def _check_directory(self, handle: int) -> None:
        self._time_left()
        flags = self._native.directory_case_flags(handle)
        if type(flags) is not int or flags != 0:
            raise ProgramFirewallLeaseError("program ancestry is case-sensitive or case semantics are unknown")
        self._time_left()

    def _check_ancestry(self) -> None:
        # Read sharing does not freeze attribute/extended-attribute changes.
        # Re-query the retained directory objects at each validation barrier.
        for _name, handle, _identity, directory in self._files:
            if directory:
                self._check_directory(handle)

    def _validate_files(self) -> None:
        for name, handle, expected, directory in self._files:
            self._time_left()
            self._check_ancestry()
            held = self._native.file_identity(handle)
            self._check_file(held, name, directory)
            if expected is None or not self._same(expected, held, directory):
                raise ProgramFirewallLeaseError("retained program object changed")
            named_handle = self._native.open_file(name, directory)
            try:
                if directory:
                    self._check_directory(named_handle)
                named = self._native.file_identity(named_handle)
                self._check_file(named, name, directory)
                if not self._same(expected, named, directory):
                    raise ProgramFirewallLeaseError("named program object differs from retained object")
                if directory:
                    self._check_directory(named_handle)
            finally:
                try:
                    self._native.close(named_handle)
                except Exception:
                    self._close_uncertain = True
                    raise
            self._time_left()
        self._check_ancestry()

    def validate(self) -> None:
        self._check_process()
        self._validate_files()
        self._check_process()
        self._check_ancestry()

    def check_deadline(self) -> None:
        """Last nonblocking time check after the owner's dispatch authority check."""
        self._time_left()

    def proof(self) -> dict[str, Any]:
        self.validate()
        leaf = self._files[-1][2]
        ancestry = [(name, f"{identity.volume:016x}", identity.file_id)
                    for name, _handle, identity, directory in self._files if directory]
        return {"program_custody": "windows-program-firewall-lease-v1",
                "native_pid": self.identity.pid, "native_birth_ticks": str(self.identity.birth_ticks),
                "native_image": self.path, "program_file_volume": f"{leaf.volume:016x}",
                "program_file_id": leaf.file_id, "program_file_size": leaf.size,
                "program_file_write_ticks": str(leaf.write_ticks), "program_ancestor_count": len(ancestry),
                "program_ancestry_case": "queried-case-insensitive; metadata is not frozen",
                "program_ancestry_sha256": hashlib.sha256(json.dumps(ancestry,
                    separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest(),
                "program_custody_scope": "current-process/path objects; not mapped image or socket admission"}

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        handles = [handle for _name, handle, _identity, _directory in reversed(self._files)]
        self._files = []
        if self._process is not None:
            handles.append(self._process)
            self._process = None
        errors = self._close_uncertain
        for handle in handles:
            try:
                self._native.close(handle)
            except Exception:
                errors = True
        if errors:
            raise ProgramFirewallLeaseError("one or more program custody handles did not close provably")

    def __enter__(self) -> ProgramFirewallLease:
        return self

    def __exit__(self, *_error: object) -> None:
        self.close()
