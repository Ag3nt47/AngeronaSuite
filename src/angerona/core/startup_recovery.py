"""Closed startup outcomes and private, verified child scratch directories.

This module never repairs an interpreter or starts an application. The source
launch supervisor owns the one repair attempt, outside every venv process.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile
from typing import Callable


REPAIR_EXIT_CODES = {81: "Runtime", 82: "Dependencies", 83: "GuiRuntime"}
MINIMUM_FREE_BYTES = 128 * 1024 * 1024


def write_read_proof(directory: Path) -> None:
    """Flush and read back only a new, exclusively created disposable file."""
    expected = secrets.token_bytes(32)
    fd, name = tempfile.mkstemp(prefix="startup-check-", dir=directory)
    try:
        with os.fdopen(fd, "w+b") as stream:
            stream.write(expected)
            stream.flush()
            os.fsync(stream.fileno())
            stream.seek(0)
            if stream.read() != expected:
                raise OSError("Startup storage readback did not match the flushed bytes.")
    finally:
        Path(name).unlink(missing_ok=True)


def _windows_security(path: Path, *, create: bool, allow_inherited: bool = False) -> bool:
    """Atomically create, or independently verify, a current-user private dir."""
    from ctypes import wintypes as w

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    token = w.HANDLE()
    kernel.GetCurrentProcess.restype = w.HANDLE
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.OpenProcessToken.restype = w.BOOL
    advapi.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)]
    advapi.GetTokenInformation.restype = w.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [w.LPVOID, ctypes.POINTER(w.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = w.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.DWORD)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [w.LPVOID, ctypes.POINTER(w.BOOL), ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL)]
    advapi.GetSecurityDescriptorDacl.restype = w.BOOL
    advapi.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID)]
    advapi.GetNamedSecurityInfoW.restype = w.DWORD
    advapi.EqualSid.argtypes = [w.LPVOID, w.LPVOID]
    advapi.EqualSid.restype = w.BOOL
    advapi.GetSecurityDescriptorControl.argtypes = [w.LPVOID, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)]
    advapi.GetSecurityDescriptorControl.restype = w.BOOL
    kernel.LocalFree.argtypes = [w.LPVOID]
    kernel.LocalFree.restype = w.LPVOID
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    sid_text = w.LPWSTR()
    expected_sd = w.LPVOID()
    actual_sd = w.LPVOID()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        size = w.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        user = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, user, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        user_sid = ctypes.cast(user, ctypes.POINTER(w.LPVOID))[0]
        if not advapi.ConvertSidToStringSidW(user_sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = sid_text.value
        sddl = f"O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(expected_sd), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if create:
            class Attributes(ctypes.Structure):
                _fields_ = [("size", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]

            attrs = Attributes(ctypes.sizeof(Attributes), expected_sd, False)
            kernel.CreateDirectoryW.argtypes = [w.LPCWSTR, ctypes.POINTER(Attributes)]
            kernel.CreateDirectoryW.restype = w.BOOL
            if not kernel.CreateDirectoryW(str(path), ctypes.byref(attrs)):
                raise ctypes.WinError(ctypes.get_last_error())
        owner, actual_acl, expected_acl = w.LPVOID(), w.LPVOID(), w.LPVOID()
        if advapi.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(actual_acl), None, ctypes.byref(actual_sd)):
            return False
        present, defaulted = w.BOOL(), w.BOOL()
        control, revision = w.WORD(), w.DWORD()
        if not (
            owner and actual_acl and advapi.EqualSid(owner, user_sid)
            and advapi.GetSecurityDescriptorControl(actual_sd, ctypes.byref(control), ctypes.byref(revision))
            and (allow_inherited or control.value & 0x1000)
            and advapi.GetSecurityDescriptorDacl(expected_sd, ctypes.byref(present), ctypes.byref(expected_acl), ctypes.byref(defaulted))
            and present and expected_acl
        ):
            return False
        # Compare every complete ACE independently of the OS's canonical ACE
        # ordering. Extra/inherited rights and null DACLs remain rejected.
        def acl_entries(pointer):
            count = ctypes.cast(pointer.value + 4, ctypes.POINTER(w.WORD))[0]
            offset = 8
            entries = []
            for _ in range(count):
                length = ctypes.cast(pointer.value + offset + 2, ctypes.POINTER(w.WORD))[0]
                entry = ctypes.string_at(pointer.value + offset, length)
                if allow_inherited:
                    # Files inherit the same full-control principals from the
                    # private scratch parent; normalize only inheritance bits.
                    entry = entry[:1] + bytes([entry[1] & ~0x13]) + entry[2:]
                entries.append(entry)
                offset += length
            return sorted(entries)

        return acl_entries(actual_acl) == acl_entries(expected_acl)
    finally:
        for allocation in (sid_text, expected_sd, actual_sd):
            if allocation:
                kernel.LocalFree(allocation)
        if token:
            kernel.CloseHandle(token)


def private_directory(path: Path, *, create: bool) -> bool:
    if os.name == "nt":
        return _windows_security(path, create=create)
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    return (
        stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
    )


def private_repair_file(path: Path) -> bool:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return False
    if os.name == "nt":
        return _windows_security(path, create=False, allow_inherited=True)
    return info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o077


def select_temporary(storage: Path, installation: Path, *,
                     validate: Callable[[Path], None],
                     fixed: Callable[[Path], bool],
                     inherited: dict[str, str], critical_directory: Path | None = None) -> Path:
    """Select only owned scratch; never alter the caller's environment.

    The caller must first prove private persistent storage and actual I/O.
    Ordinary paths retain the free-space reserve. A kernel-validated critical
    workspace makes that recommendation advisory and keeps bounded admission.
    """
    bases = (storage / "tmp", installation / ".tmp")
    if critical_directory is not None:
        candidate = Path(critical_directory)
        if candidate.parent not in bases or candidate.name != "startup-temp.critical-preflight":
            raise OSError("Critical temporary storage is outside the fixed preflight workspaces.")
        validate(candidate)
        if not fixed(Path(candidate.anchor)) or not private_directory(candidate, create=False):
            raise OSError("Critical temporary storage lacks private fixed-drive custody.")
        count = 0
        total = 0
        for entry in candidate.iterdir():
            count += 1
            if count > 128:
                raise OSError("Critical temporary storage exceeds its bounded flat inventory.")
            validate(entry)
            info = entry.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
                raise OSError("Critical temporary storage contains an unknown or redirected entry.")
            total += info.st_size
            if total > 32 * 1024 * 1024:
                raise OSError("Critical temporary storage exceeds its 32 MiB working budget.")
        write_read_proof(candidate)
        return candidate
    # Reuse a supervisor's fresh private scratch only after all the same native
    # custody, fixed-volume, capacity and real I/O checks. No environment flag
    # is itself authority to skip a check.
    for name in ("TEMP", "TMP"):
        raw = inherited.get(name)
        if not raw:
            continue
        try:
            candidate = Path(raw)
            if candidate.parent not in bases or not candidate.name.startswith("startup-temp."):
                continue
            validate(candidate)
            if not fixed(Path(candidate.anchor)) or shutil.disk_usage(candidate).free < MINIMUM_FREE_BYTES:
                continue
            if private_directory(candidate, create=False):
                write_read_proof(candidate)
                return candidate
        except (OSError, ValueError, RuntimeError):
            continue
    for base in bases:
        try:
            validate(base)
            if not fixed(Path(base.anchor)):
                continue
            base.mkdir(parents=True, exist_ok=True)
            validate(base)
            if not base.is_dir() or shutil.disk_usage(base).free < MINIMUM_FREE_BYTES:
                continue
            candidate = base / f"startup-temp.{secrets.token_hex(16)}"
            validate(candidate)
            if not private_directory(candidate, create=True):
                continue
            validate(candidate)
            write_read_proof(candidate)
            return candidate
        except (OSError, ValueError, RuntimeError):
            continue
    raise OSError("No verified private startup temporary directory has 128 MB free. Free space on the local data or installation drive and retry; settings and evidence were preserved.")
