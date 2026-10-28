"""Bounded private startup observations; never changes startup admission policy."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import threading
import time
import traceback
from urllib.parse import urlsplit, urlunsplit

from angerona.core.alert_retention import _directory, _identity
from angerona.core.startup_recovery import private_repair_file

MAX_FILE_BYTES = 512 * 1024
MAX_FRAME_BYTES = 8 * 1024
MAX_RECORDS = 256
_NAME = "startup-diagnostics.jsonl"
_WRITE_LOCK = threading.Lock()
_SECRET = re.compile(r"(?i)(\b(?:api[_ -]?key|secret|password|passphrase|passwd|token|authorization|cookie|credential)\b[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)")
_BEARER = re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_\-.]+")
_KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9-]{12,})")
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
_FIELDS = frozenset({"reason", "exception_type", "traceback", "exit_code", "pid", "birth_filetime",
    "duration_ms", "expected", "actual", "package", "packages_checked", "mismatches", "output_tail",
    "next_steps", "strategy", "error_code", "preflight_log", "dashboard_log", "renderer_hint", "mismatches_total",
    "executable", "root", "log_error", "coverage", "attempt", "process_role", "bootstrap_pid"})


def safe_text(value: object, limit: int = 2048) -> str:
    text = str(value)[:8192]
    text = _CONTROL.sub("", text)
    if "-----BEGIN " in text and "PRIVATE KEY" in text:
        return "[private key material omitted]"
    text = _SECRET.sub(r"\1[redacted]", text)
    text = _BEARER.sub("[authorization redacted]", text)
    text = _KEY.sub("[credential redacted]", text)
    def url(match):
        try:
            parts = urlsplit(match.group())
            host = parts.hostname or ""
            if ":" in host:
                host = "[" + host + "]"
            if parts.port:
                host += ":" + str(parts.port)
            return urlunsplit((parts.scheme, host, parts.path, "", ""))
        except ValueError:
            return "[URL redacted]"
    return _URL.sub(url, text)[:limit]


def process_identity(process=None) -> dict:
    """Native birth is an exact decimal FILETIME, not a floating point value."""
    pid = os.getpid() if process is None else getattr(process, "pid", None)
    result = {"pid": pid} if type(pid) is int and pid > 0 else {}
    if os.name != "nt":
        return result
    try:
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        handle = getattr(process, "_handle", None) if process is not None else kernel.GetCurrentProcess()
        if handle is None:
            return result
        values = [wintypes.FILETIME() for _ in range(4)]
        getter = kernel.GetProcessTimes
        getter.argtypes = (wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4))
        getter.restype = wintypes.BOOL
        if getter(handle, *(ctypes.byref(value) for value in values)):
            result["birth_filetime"] = str((values[0].dwHighDateTime << 32) | values[0].dwLowDateTime)
    except (OSError, TypeError, ValueError, AttributeError):
        pass
    return result


def canonical_storage() -> Path:
    """Resolve the OS user folder without accepting environment path authority."""
    if os.name != "nt":
        raise OSError("Windows startup diagnostics require the Windows user folder")
    from ctypes import wintypes
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    getter = shell.SHGetFolderPathW
    getter.argtypes = (wintypes.HWND, ctypes.c_int, wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR)
    getter.restype = ctypes.c_long
    buffer = ctypes.create_unicode_buffer(32768)
    if getter(None, 0x1C, None, 0, buffer) != 0 or not buffer.value:
        raise OSError("Windows could not resolve Local AppData for startup diagnostics")
    return Path(buffer.value) / "Angerona" / ("Startup" if getattr(sys, "frozen", False) else "SourceData")


def _ensure_private_leaf(directory, name: str) -> None:
    """Atomically create our new Windows report with a protected private DACL.

    Existing leaves are never hardened or replaced here. The retained open and
    independent private-file check below still reject changed or unknown files.
    """
    if os.name != "nt" or directory.exists(name):
        return
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = (w.HANDLE,)
    kernel.CloseHandle.restype = w.BOOL
    kernel.LocalFree.argtypes = (w.LPVOID,)
    kernel.LocalFree.restype = w.LPVOID
    token, sid_text, descriptor = w.HANDLE(), w.LPWSTR(), w.LPVOID()
    try:
        advapi.OpenProcessToken.argtypes = (w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE))
        advapi.OpenProcessToken.restype = w.BOOL
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        advapi.GetTokenInformation.argtypes = (w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD))
        advapi.GetTokenInformation.restype = w.BOOL
        size = w.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        user = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, user, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(user, ctypes.POINTER(w.LPVOID))[0]
        advapi.ConvertSidToStringSidW.argtypes = (w.LPVOID, ctypes.POINTER(w.LPWSTR))
        advapi.ConvertSidToStringSidW.restype = w.BOOL
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        sddl = f"O:{sid_text.value}D:P(A;;FA;;;{sid_text.value})(A;;FA;;;SY)(A;;FA;;;BA)"
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID)
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        class Attributes(ctypes.Structure):
            _fields_ = [("size", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]
        attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
        opener = kernel.CreateFileW
        opener.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, ctypes.POINTER(Attributes), w.DWORD, w.DWORD, w.HANDLE)
        opener.restype = w.HANDLE
        handle = opener(str(directory.path / name), 0xC0000000, 1, ctypes.byref(attributes), 1, 0x00200000, None)
        if handle == w.HANDLE(-1).value:
            error = ctypes.get_last_error()
            if error not in (80, 183):
                raise ctypes.WinError(error)
        else:
            kernel.CloseHandle(handle)
    finally:
        for allocation in (sid_text, descriptor):
            if allocation:
                kernel.LocalFree(allocation)
        if token:
            kernel.CloseHandle(token)


def _validate_report(file) -> None:
    if file.info().st_size == 0:
        return
    os.lseek(file.descriptor, 0, os.SEEK_SET)
    header = os.read(file.descriptor, MAX_FRAME_BYTES + 1).split(b"\n", 1)[0]
    if len(header) > MAX_FRAME_BYTES:
        raise ValueError("startup diagnostic header is oversized")
    value = json.loads(header)
    if not isinstance(value, dict) or value.get("schema") != "angerona-startup-diagnostics-v1":
        raise ValueError("existing startup diagnostic file has an unknown format")


class StartupDiagnostics:
    def __init__(self, storage: Path):
        self.storage = Path(storage)
        self.path = self.storage / "diagnostics" / _NAME
        self.run_id = secrets.token_hex(16)
        self.records = 0
        self.last_error = ""

    def record(self, phase: str, status: str, **fields) -> bool:
        if self.records >= MAX_RECORDS:
            self.last_error = "startup diagnostic record budget reached"
            return False
        self.records += 1
        record = {"schema": "angerona-startup-diagnostics-v1", "run_id": self.run_id,
                  "time_ns": str(time.time_ns()), "phase": safe_text(phase, 64),
                  "status": safe_text(status, 32)}
        for name, value in fields.items():
            if name not in _FIELDS:
                continue
            if type(value) in (bool, int) or value is None:
                record[name] = value
            elif isinstance(value, (tuple, list)):
                record[name] = [safe_text(item, 256) for item in value[:24]]
            else:
                record[name] = safe_text(value, 4096 if name in {"traceback", "output_tail"} else 1024)
        encoded = json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
        if len(encoded) > MAX_FRAME_BYTES:
            # Keep the reason/identity; oversized free text is a visible omission.
            record.pop("traceback", None)
            record.pop("output_tail", None)
            record.pop("mismatches", None)
            record["coverage"] = "oversized optional startup detail omitted"
            encoded = json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
        try:
            if len(encoded) > MAX_FRAME_BYTES:
                raise ValueError("startup diagnostic frame exceeds its size limit")
            if (not self.storage.is_absolute() or ".." in self.storage.parts
                    or str(self.storage).startswith(("\\\\", "//"))):
                raise ValueError("startup diagnostics require canonical absolute storage")
            for ancestor in (*reversed(self.storage.parents), self.storage):
                if os.path.lexists(ancestor):
                    info = ancestor.lstat()
                    if (not stat.S_ISDIR(info.st_mode)
                            or getattr(info, "st_file_attributes", 0) & 0x400):
                        raise ValueError("startup diagnostics refuse redirected storage")
            self.storage.mkdir(parents=True, exist_ok=True, mode=0o700)
            with _WRITE_LOCK, _directory(self.storage, create=True) as directory:
                if directory is None:
                    raise OSError("startup diagnostics directory unavailable")
                _ensure_private_leaf(directory, _NAME)
                with directory.open(_NAME, create=True) as current:
                    if not private_repair_file(self.path):
                        raise ValueError("startup diagnostic file is not current-user private")
                    _validate_report(current)
                    if current.info().st_size + len(encoded) > MAX_FILE_BYTES:
                        oldest = _NAME + ".2"
                        if directory.exists(oldest):
                            with directory.open(oldest) as held:
                                _validate_report(held)
                                held.delete(_identity(held.info()))
                        previous = _NAME + ".1"
                        if directory.exists(previous):
                            with directory.open(previous) as held:
                                _validate_report(held)
                                held.rename(oldest)
                        current.rename(previous)
                _ensure_private_leaf(directory, _NAME)
                with directory.open(_NAME, create=True) as current:
                    if current.info().st_size + len(encoded) > MAX_FILE_BYTES:
                        raise OSError("startup diagnostic file changed during rotation")
                    os.lseek(current.descriptor, 0, os.SEEK_END)
                    view = memoryview(encoded)
                    while view:
                        written = os.write(current.descriptor, view)
                        if written <= 0:
                            raise OSError("startup diagnostic append made no progress")
                        view = view[written:]
                    os.fsync(current.descriptor)
            return True
        except (OSError, ValueError, TypeError) as exc:
            self.last_error = f"{type(exc).__name__}: {safe_text(exc, 512)}"
            return False

    def failure(self, phase: str, error: BaseException, *, exit_code: int = 1) -> str:
        hint = "software-renderer" if exit_code == 83 else "review-diagnostics"
        trace = "".join(traceback.format_exception(type(error), error, error.__traceback__, limit=8))
        persisted = self.record(phase, "failed", reason=str(error), exception_type=type(error).__name__,
            traceback=trace, exit_code=exit_code, renderer_hint=hint,
            process_role="startup-assistant",
            error_code=getattr(error, "winerror", None) or getattr(error, "errno", None),
            preflight_log=str(self.storage / "logs" / "startup-preflight.log"),
            dashboard_log=str(self.storage / "logs" / "startup-dashboard.log"),
            next_steps="Keep these private logs. Retry only through the verified source launcher; do not reset settings or evidence.",
            **process_identity())
        message = (f"Startup failed in {safe_text(phase, 64)}: {safe_text(error)}\n"
                   f"Startup diagnostics: {self.path}\n"
                   f"Dependency details: {self.storage / 'logs' / 'startup-preflight.log'}\n"
                   f"Dashboard details: {self.storage / 'logs' / 'startup-dashboard.log'}")
        if not persisted:
            message += "\nDiagnostic persistence unavailable: " + self.last_error
        return message
