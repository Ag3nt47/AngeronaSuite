"""Private recorder metadata creation, without changing existing file custody.

Windows chooses a new file's owner from TokenOwner, which can be the local
Administrators group even when TokenUser owns the private parent directory.
Supply TokenUser and the protected DACL atomically, before returning a writable
descriptor. This module does not enroll a service or grant response authority.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import threading


_RETIREMENT_HOLDS: list[object] = []
_HOLD_LOCK = threading.Lock()
_close_fd = os.close


def _windows_platform():
    return os.name == "nt"


class MetadataCreationUncertain(OSError):
    """The exact native creator is retained; replacement must remain fenced."""

    def __init__(self, owner):
        super().__init__("Recorder metadata creation cleanup remains unproven")
        self.owner = owner


def metadata_retirement_held() -> bool:
    with _HOLD_LOCK:
        return bool(_RETIREMENT_HOLDS)


def _plain_path(path: Path, *, parent=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if parent else stat.S_ISREG(info.st_mode))
            or not parent and info.st_nlink != 1):
        raise PermissionError("Recorder metadata requires an unredirected single-link file")
    return info


def _validate_path(path: Path):
    if not path.is_absolute() or ".." in path.parts or str(path).startswith(("\\\\", "//")):
        raise PermissionError("Recorder metadata requires an absolute local path")
    for item in (path.parent, *path.parent.parents):
        _plain_path(item, parent=True)


class _CreationOwner:
    """One native/CRT owner, retained before every potentially ambiguous call."""

    def __init__(self, api):
        if metadata_retirement_held():
            raise PermissionError("Recorder metadata native retirement is held")
        self.api = api
        self.raw_handle = None
        self.descriptor = None
        self.transfer_pending = False
        self.pending_native = None
        self.resources = []
        self.buffers = []
        self.uncertain = False
        self.retired = False
        self.ambiguous_numbers = []
        self._retire_lock = threading.Lock()

    def hold(self):
        self.uncertain = True
        with _HOLD_LOCK:
            if not any(owner is self for owner in _RETIREMENT_HOLDS):
                _RETIREMENT_HOLDS.append(self)

    def call(self, name, function, *arguments):
        self.pending_native = (name, function, arguments)
        try:
            result = function(*arguments)
        except BaseException:
            # An unknown Python/FFI failure cannot prove native admission did
            # not occur. Keep arguments, output slots and descriptor buffers.
            self.hold()
            raise
        self.pending_native = None
        return result

    def resource(self, value, closer):
        self.resources.append({"value": value, "closer": closer, "attempted": False})
        return value

    def retire_auxiliary(self):
        if not self._retire_lock.acquire(blocking=False):
            self.hold()
            return False
        try:
            return self._retire_auxiliary()
        finally:
            self._retire_lock.release()

    def _retire_auxiliary(self):
        if self.pending_native is not None:
            self.hold()
            return False
        for row in reversed(self.resources):
            if row["attempted"]:
                continue
            row["attempted"] = True
            value = row["value"]
            try:
                if not row["closer"](value):
                    raise OSError("Native recorder metadata resource close failed")
            except BaseException:
                self.ambiguous_numbers.append(value)
                self.hold()
        return not self.uncertain

    def retire(self):
        if not self._retire_lock.acquire(blocking=False):
            self.hold()
            return False
        try:
            return self._retire()
        finally:
            self._retire_lock.release()

    def _retire(self):
        if self.retired:
            return not self.uncertain
        if self.pending_native is not None or self.transfer_pending:
            self.hold()
            return False
        if self.descriptor is not None:
            value, self.descriptor = self.descriptor, None
            try:
                _close_fd(value)
            except BaseException:
                self.ambiguous_numbers.append(value)
                self.hold()
        elif self.raw_handle is not None:
            value, self.raw_handle = self.raw_handle, None
            try:
                if not self.api.close_handle(value):
                    raise OSError("Native recorder metadata file close failed")
            except BaseException:
                self.ambiguous_numbers.append(value)
                self.hold()
        self._retire_auxiliary()
        self.retired = True
        return not self.uncertain


class _WindowsApi:
    """Raw handles avoid a PyHANDLE/CRT double owner and a Detach race."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes as w

        self.c, self.w = ctypes, w
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        signatures = {
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "LocalFree": ([w.LPVOID], w.LPVOID),
            "CreateFileW": ([w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.kernel, name)
            function.argtypes, function.restype = args, result
        signatures = {
            "OpenProcessToken": ([w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL),
            "GetTokenInformation": ([w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL),
            "ConvertSidToStringSidW": ([w.LPVOID, ctypes.POINTER(w.LPWSTR)], w.BOOL),
            "ConvertStringSecurityDescriptorToSecurityDescriptorW": ([w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID], w.BOOL),
            "GetSecurityInfo": ([w.HANDLE, ctypes.c_int, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID)], w.DWORD),
            "EqualSid": ([w.LPVOID, w.LPVOID], w.BOOL),
            "GetSecurityDescriptorControl": ([w.LPVOID, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)], w.BOOL),
            "GetSecurityDescriptorDacl": ([w.LPVOID, ctypes.POINTER(w.BOOL), ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL)], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.adv, name)
            function.argtypes, function.restype = args, result

    def error(self, number=None):
        return self.c.WinError(self.c.get_last_error() if number is None else number)

    def close_handle(self, value):
        return bool(self.kernel.CloseHandle(value))

    def free(self, value):
        return not self.kernel.LocalFree(value)

    def attributes(self, owner):
        c, w = self.c, self.w
        token, size = w.HANDLE(), w.DWORD()
        owner.buffers.extend((token, size))
        if not owner.call("OpenProcessToken", self.adv.OpenProcessToken,
                          self.kernel.GetCurrentProcess(), 8, c.byref(token)):
            raise self.error()
        owner.resource(token.value, self.close_handle)
        owner.call("TokenUserSize", self.adv.GetTokenInformation, token, 1, None, 0, c.byref(size))
        if not 1 <= size.value <= 65536:
            raise PermissionError("Recorder metadata TokenUser exceeds its bound")
        user = c.create_string_buffer(size.value)
        owner.buffers.append(user)
        if not owner.call("TokenUser", self.adv.GetTokenInformation, token, 1, user, size, c.byref(size)):
            raise self.error()
        user_sid = c.cast(user, c.POINTER(w.LPVOID))[0]
        sid_text = w.LPWSTR()
        owner.buffers.append(sid_text)
        if not owner.call("ConvertSid", self.adv.ConvertSidToStringSidW, user_sid, c.byref(sid_text)):
            raise self.error()
        owner.resource(c.cast(sid_text, w.LPVOID).value, self.free)
        sid = sid_text.value
        if not sid or len(sid) > 184:
            raise PermissionError("Recorder metadata TokenUser SID is invalid")
        # Same owner/principal contract as engine_transport.create_private_file.
        sddl = f"O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
        descriptor = w.LPVOID()
        owner.buffers.append(descriptor)
        if not owner.call("ConvertDescriptor", self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW,
                          sddl, 1, c.byref(descriptor), None):
            raise self.error()
        owner.resource(descriptor.value, self.free)
        class Attributes(c.Structure):
            _fields_ = [("size", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]
        attributes = Attributes(c.sizeof(Attributes), descriptor, False)
        owner.buffers.append(attributes)
        return attributes, user_sid, descriptor

    def open_file(self, owner, path, access, create_new, attributes):
        # Share read/write so a second lease opener reaches the nonblocking
        # byte-range lock. Never share delete while validating file identity.
        value = owner.call("CreateFileW", self.kernel.CreateFileW, str(path), access | 0x20080,
                           3, self.c.byref(attributes) if create_new else None,
                           1 if create_new else 3, 0x00200000, None)
        if value in (None, self.w.HANDLE(-1).value):
            raise self.error()
        owner.raw_handle = value
        return value

    def verify(self, owner, handle, user_sid, expected, *, created):
        c, w = self.c, self.w
        actual, actual_owner, acl = w.LPVOID(), w.LPVOID(), w.LPVOID()
        owner.buffers.extend((actual, actual_owner, acl))
        code = owner.call("GetSecurityInfo", self.adv.GetSecurityInfo, handle, 1, 5,
                          c.byref(actual_owner), None, c.byref(acl), None, c.byref(actual))
        if code:
            raise self.error(code)
        owner.resource(actual.value, self.free)
        control, revision, present, defaulted, expected_acl = w.WORD(), w.DWORD(), w.BOOL(), w.BOOL(), w.LPVOID()
        if (not actual_owner or not acl
                or not owner.call("EqualSid", self.adv.EqualSid, actual_owner, user_sid)
                or not owner.call("DescriptorControl", self.adv.GetSecurityDescriptorControl,
                                  actual, c.byref(control), c.byref(revision))
                or created and not control.value & 0x1000
                or not owner.call("ExpectedDacl", self.adv.GetSecurityDescriptorDacl, expected,
                                  c.byref(present), c.byref(expected_acl), c.byref(defaulted))
                or not present or not expected_acl):
            raise PermissionError("Recorder metadata owner or protected DACL differs")
        def entries(pointer):
            count = c.cast(pointer.value + 4, c.POINTER(w.WORD))[0]
            size = c.cast(pointer.value + 2, c.POINTER(w.WORD))[0]
            if count > 16 or not 8 <= size <= 16384:
                raise PermissionError("Recorder metadata DACL exceeds its bound")
            offset, values = 8, []
            for _ in range(count):
                if offset + 4 > size:
                    raise PermissionError("Recorder metadata ACE is truncated")
                length = c.cast(pointer.value + offset + 2, c.POINTER(w.WORD))[0]
                if not 8 <= length <= 1024 or offset + length > size:
                    raise PermissionError("Recorder metadata ACE exceeds its bound")
                entry = c.string_at(pointer.value + offset, length)
                # Existing private leaves can inherit these same exact rights.
                values.append(entry[:1] + bytes([entry[1] & ~0x13]) + entry[2:])
                offset += length
            return sorted(values)
        if entries(acl) != entries(expected_acl):
            raise PermissionError("Recorder metadata grants unexpected rights")

    def to_fd(self, handle, flags):
        import msvcrt
        return msvcrt.open_osfhandle(handle, flags)


_windows_api = _WindowsApi


def open_private_metadata(path, flags, mode=0o600) -> int:
    """Open/create only private metadata; no truncate, ACL repair or deletion."""
    path = Path(path)
    if metadata_retirement_held():
        raise PermissionError("Recorder metadata native retirement is held")
    _validate_path(path)
    if mode != 0o600 or not flags & os.O_CREAT or flags & (os.O_TRUNC | os.O_APPEND):
        raise ValueError("Recorder metadata creation requires private exclusive/nontruncating controls")
    access_mode = flags & (os.O_WRONLY | os.O_RDWR)
    if access_mode not in (os.O_WRONLY, os.O_RDWR):
        raise ValueError("Recorder metadata requires a writable descriptor")
    from .startup_recovery import private_directory, private_repair_file
    if not private_directory(path.parent, create=False):
        raise PermissionError("Recorder metadata parent is not private")
    try:
        before = _plain_path(path)
    except FileNotFoundError:
        before = None
    if before is not None:
        if flags & os.O_EXCL:
            raise FileExistsError(path)
        if not private_repair_file(path):
            raise PermissionError("Existing recorder metadata is not private")
    if not _windows_platform():
        owner = _CreationOwner(None)
        try:
            owner.descriptor = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), mode)
            held, named = os.fstat(owner.descriptor), _plain_path(path)
            if ((held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                    or held.st_nlink != 1 or not private_repair_file(path)):
                raise PermissionError("Recorder metadata identity or custody differs")
        except BaseException as exc:
            if not owner.retire():
                raise MetadataCreationUncertain(owner) from exc
            raise
        descriptor, owner.descriptor = owner.descriptor, None
        owner.retired = True
        return descriptor
    owner = _CreationOwner(_windows_api())
    try:
        attributes, user_sid, expected = owner.api.attributes(owner)
        handle = owner.api.open_file(owner, path, 0xC0000000 if access_mode == os.O_RDWR else 0x40000000,
                                     before is None, attributes)
        owner.api.verify(owner, handle, user_sid, expected, created=before is None)
        owner.transfer_pending = True
        try:
            owner.descriptor = owner.api.to_fd(handle, access_mode | getattr(os, "O_BINARY", 0)
                                               | getattr(os, "O_NOINHERIT", 0))
        except BaseException:
            owner.hold()
            raise
        owner.raw_handle = None  # CRT now owns it; no native-close/Detach call.
        owner.transfer_pending = False
        held, named = os.fstat(owner.descriptor), _plain_path(path)
        if ((held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                or held.st_nlink != 1 or before is not None
                and (before.st_dev, before.st_ino) != (held.st_dev, held.st_ino)):
            raise PermissionError("Recorder metadata changed during native admission")
        if not owner.retire_auxiliary():
            raise MetadataCreationUncertain(owner)
        descriptor, owner.descriptor = owner.descriptor, None
        owner.retired = True
        return descriptor
    except BaseException as exc:
        if not owner.retire():
            raise MetadataCreationUncertain(owner) from exc
        raise
