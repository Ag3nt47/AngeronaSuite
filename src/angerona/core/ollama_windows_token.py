"""Start only Ollama with the current elevated user's linked medium token.

No alternate account, credentials, shell, UAC request or elevated fallback is
available. The caller retains sealed executable/directory custody throughout.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


_UNAVAILABLE = (
    "Start Ollama from a normal user session; its linked medium user token is unavailable."
)


@dataclass(frozen=True)
class _TokenIdentity:
    sid: str
    session: int
    elevated: bool
    integrity: int
    token_type: int
    elevation_type: int
    ui_access: bool


def _require_medium(parent: _TokenIdentity, token: _TokenIdentity, *, linked=False) -> None:
    if (token.sid != parent.sid or token.session != parent.session
            or token.session <= 0 or token.elevated or token.integrity != 0x2000
            or token.token_type not in ((1, 2) if linked else (1,))
            or token.elevation_type != 3 or token.ui_access):
        raise ValueError(_UNAVAILABLE)


class _Native:
    """Small Win32 boundary kept separate from token-policy tests."""

    def __init__(self):
        import win32api
        import win32process
        import win32security

        self.api = win32api
        self.process = win32process
        self.security = win32security

    def current_token(self):
        return self.security.OpenProcessToken(
            self.api.GetCurrentProcess(), self.security.TOKEN_QUERY,
        )

    def linked_token(self, token):
        return self.security.GetTokenInformation(token, self.security.TokenLinkedToken)

    def primary_token(self, token):
        """Convert only a token Windows already permits to become primary.

        An identification-only source cannot be converted: Windows returns
        ERROR_BAD_IMPERSONATION_LEVEL, which must fail closed. This operation
        neither raises the source impersonation level nor enables privileges.
        """
        from ctypes import wintypes

        duplicate = ctypes.WinDLL("advapi32", use_last_error=True).DuplicateTokenEx
        duplicate.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
                              ctypes.c_int, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
        duplicate.restype = wintypes.BOOL
        primary = wintypes.HANDLE()
        # Only QUERY | DUPLICATE | ASSIGN_PRIMARY. NULL attributes prohibit
        # handle inheritance. The source still needs SecurityImpersonation or
        # SecurityDelegation authority, regardless of this level argument.
        if not duplicate(int(token), 0x000B, None, 1, 1, ctypes.byref(primary)):
            raise OSError(ctypes.get_last_error(), "Linked medium token conversion failed.")
        return int(primary.value)

    def child_token(self, process):
        return self.security.OpenProcessToken(process, self.security.TOKEN_QUERY)

    def model_directory(self, token):
        import win32profile

        # Only this non-code setting is read from the linked user's block.
        # The entire block (which may contain credentials) is never forwarded.
        block = win32profile.CreateEnvironmentBlock(token, False)
        matches = [value for key, value in block.items()
                   if isinstance(key, str) and key.casefold() == "ollama_models"]
        if len(matches) > 1:
            raise ValueError(_UNAVAILABLE)
        return matches[0] if matches else None

    def identity(self, token):
        security = self.security

        def info(name):
            return security.GetTokenInformation(token, getattr(security, name))

        label = info("TokenIntegrityLevel")[0]
        return _TokenIdentity(
            security.ConvertSidToStringSid(info("TokenUser")[0]),
            int(info("TokenSessionId")), bool(info("TokenElevation")),
            int(label.GetSubAuthority(label.GetSubAuthorityCount() - 1)),
            int(info("TokenType")), int(info("TokenElevationType")),
            bool(info("TokenUIAccess")),
        )

    def create_suspended(self, token, image: Path, environment: dict[str, str]):
        from ctypes import wintypes

        class StartupInfo(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE),
            ]

        class ProcessInfo(ctypes.Structure):
            _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

        command = subprocess.list2cmdline([str(image), "serve"])
        if len(command) >= 1024:
            raise ValueError(_UNAVAILABLE)
        if any(not isinstance(key, str) or not isinstance(value, str)
               or not key or "=" in key or "\0" in key or "\0" in value
               for key, value in environment.items()):
            raise ValueError(_UNAVAILABLE)
        block = "\0".join(f"{key}={environment[key]}" for key in sorted(environment, key=str.casefold)) + "\0\0"
        if len(block) > 32767:
            raise ValueError(_UNAVAILABLE)
        environment_buffer = ctypes.create_unicode_buffer(block)
        command_buffer = ctypes.create_unicode_buffer(command)
        startup = StartupInfo()
        startup.cb = ctypes.sizeof(startup)
        startup.dwFlags = 1  # STARTF_USESHOWWINDOW; no inherited standard handles.
        startup.wShowWindow = 0  # SW_HIDE
        process = ProcessInfo()
        create = ctypes.WinDLL("advapi32", use_last_error=True).CreateProcessWithTokenW
        create.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR,
            wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
            ctypes.POINTER(StartupInfo), ctypes.POINTER(ProcessInfo),
        ]
        create.restype = wintypes.BOOL
        # This API does not inherit handles. The explicit application name
        # avoids Windows' unquoted executable path search/ambiguity.
        flags = 0x00000004 | 0x00000400 | 0x08000000
        if not create(int(token), 0, str(image), command_buffer, flags,
                      ctypes.cast(environment_buffer, wintypes.LPVOID),
                      str(image.parent), ctypes.byref(startup), ctypes.byref(process)):
            raise OSError("Linked-token Ollama launch failed.")
        return int(process.hProcess), int(process.hThread), int(process.dwProcessId)

    def image(self, process):
        from ctypes import wintypes

        query = ctypes.WinDLL("kernel32", use_last_error=True).QueryFullProcessImageNameW
        query.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                          ctypes.POINTER(wintypes.DWORD)]
        query.restype = wintypes.BOOL
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not query(process, 0, buffer, ctypes.byref(size)):
            raise OSError("Suspended Ollama image could not be checked.")
        return Path(buffer.value)

    def resume(self, thread):
        return self.process.ResumeThread(thread)

    def terminate(self, process):
        # Only the exact handle returned by our suspended creation is accepted.
        self.api.TerminateProcess(process, 1)

    def close(self, handle):
        if hasattr(handle, "Close"):
            handle.Close()
        else:
            self.api.CloseHandle(handle)

    def poll(self, process):
        code = self.process.GetExitCodeProcess(process)
        return None if code == 259 else code


class _MediumOllamaProcess:
    def __init__(self, native, handle, pid):
        self._native = native
        self._handle = handle
        self.pid = pid

    def poll(self):
        return self._native.poll(self._handle)

    def __del__(self):
        try:
            self._native.close(self._handle)
        except Exception:
            pass


def _launch(native, image, environment, deadline, *, check_cancelled=None):
    current = linked = primary = child_token = process = thread = None
    try:
        current = native.current_token()
        parent = native.identity(current)
        if (not parent.elevated or parent.elevation_type != 2 or parent.token_type != 1
                or not 0x3000 <= parent.integrity < 0x4000 or parent.session <= 0):
            raise ValueError(_UNAVAILABLE)
        linked = native.linked_token(current)
        linked_identity = native.identity(linked)
        _require_medium(parent, linked_identity, linked=True)
        launch_token = linked
        if linked_identity.token_type == 2:
            # Windows may expose the user's linked limited token as an
            # impersonation token. Validate its authority before conversion,
            # then independently revalidate the new primary token.
            primary = native.primary_token(linked)
            _require_medium(parent, native.identity(primary))
            launch_token = primary
        environment = dict(environment)
        models = native.model_directory(launch_token)
        if models is not None and models != "":
            if (not isinstance(models, str) or len(models) > 4096
                    or any(ord(character) < 32 for character in models)
                    or not Path(models).is_absolute()):
                raise ValueError(_UNAVAILABLE)
            environment["OLLAMA_MODELS"] = models
        if time.monotonic() >= deadline:
            raise TimeoutError
        if check_cancelled is not None:
            check_cancelled()
        process, thread, pid = native.create_suspended(launch_token, image, environment)
        child_token = native.child_token(process)
        _require_medium(parent, native.identity(child_token))
        if native.image(process).resolve(strict=True) != image.resolve(strict=True):
            raise ValueError(_UNAVAILABLE)
        if time.monotonic() >= deadline:
            raise TimeoutError
        if check_cancelled is not None:
            check_cancelled()
        if native.resume(thread) != 1:
            raise ValueError(_UNAVAILABLE)
        result = _MediumOllamaProcess(native, process, pid)
        process = None  # Ownership transfers only after the medium child resumes.
        return result
    except (TimeoutError, InterruptedError):
        raise
    except Exception as exc:
        raise ValueError(_UNAVAILABLE) from exc
    finally:
        cleanup_error = None
        if process is not None:
            try:
                native.terminate(process)
            except Exception as exc:
                cleanup_error = exc
        for handle in (process, child_token, thread, primary, linked, current):
            if handle is not None:
                try:
                    native.close(handle)
                except Exception as exc:
                    cleanup_error = exc
        if cleanup_error is not None:
            raise ValueError(_UNAVAILABLE) from cleanup_error


def launch_medium_ollama(image: Path, host: str, *, deadline: float, check_cancelled=None):
    """Launch fixed Ollama service under a proven same-user medium token.

    Retains image/parent custody in addition to lifecycle's existing guard.
    Recheck image trust and rebuild the environment here; no arbitrary process
    command, token, account or environment is accepted from the caller.
    """
    if sys.platform != "win32":
        raise ValueError(_UNAVAILABLE)
    from angerona.core.ollama_lifecycle import (
        _image_identity, _startup_environment, _startup_key, _trusted_ollama_image,
    )
    from angerona.core.executable_trust import _open_sealed
    from angerona.core.source_sandbox import _hold_plain_directories

    if not image.is_absolute():
        raise ValueError(_UNAVAILABLE)
    with _hold_plain_directories(image.parent), _open_sealed(image) as held:
        original = _image_identity(os.fstat(held.fileno()))
        if (not _trusted_ollama_image(image)
                or _image_identity(image.stat())[:4] != original[:4]
                or _image_identity(os.fstat(held.fileno())) != original):
            raise ValueError(_UNAVAILABLE)
        return _launch(_Native(), image, _startup_environment(_startup_key(host)), deadline,
                       check_cancelled=check_cancelled)
