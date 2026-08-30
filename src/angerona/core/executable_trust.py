"""Object-bound trust checks for privileged native sidecars.

An Authenticode ``Valid`` result is deliberately not sufficient. A sidecar
that inherits Angerona's token must match independently supplied SHA-256 and
publisher pins, live below a protected non-reparse path, and remain held open
with replacement denied until the child has been created. This module keeps
that custody object alive for callers supervising a long-running sidecar.
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import BinaryIO, Callable

_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ExecutableTrustError(RuntimeError):
    """A native executable failed an exact, fail-closed trust requirement."""


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(getattr(info, "st_dev", 0)),
        int(getattr(info, "st_ino", 0)),
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", 0)),
        int(getattr(info, "st_nlink", 1)),
    )


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
        return stat.S_ISLNK(info.st_mode) or bool(
            int(getattr(info, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
        )
    except OSError:
        return True


def _reject_reparse_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        if _is_link_or_reparse(current):
            raise ExecutableTrustError(
                f"native executable path is link/reparse-backed: {current}"
            )


def _hash_stream(stream: BinaryIO, size: int) -> str:
    if not 0 < int(size) <= _MAX_EXECUTABLE_BYTES:
        raise ExecutableTrustError("native executable size is outside its bound")
    stream.seek(0)
    digest = hashlib.sha256()
    remaining = int(size)
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            raise ExecutableTrustError("native executable read was incomplete")
        digest.update(chunk)
        remaining -= len(chunk)
    if stream.read(1):
        raise ExecutableTrustError("native executable grew during verification")
    return digest.hexdigest()


def _open_windows_sealed(path: Path) -> BinaryIO:
    """Open one file while denying write/delete sharing until the stream closes."""
    import msvcrt

    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    handle = create(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ only: deny write/delete replacement
        None,
        3,  # OPEN_EXISTING
        0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if not handle or int(handle) == invalid:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(
            int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
    except Exception:
        kernel.CloseHandle(handle)
        raise
    try:
        return os.fdopen(descriptor, "rb", buffering=0)
    except Exception:
        os.close(descriptor)
        raise


def _open_posix_sealed(path: Path) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        return os.fdopen(descriptor, "rb", buffering=0)
    except Exception:
        os.close(descriptor)
        raise


def _open_sealed(path: Path) -> BinaryIO:
    return _open_windows_sealed(path) if sys.platform == "win32" else _open_posix_sealed(path)


def _windows_acl_protected(path: Path) -> bool:
    """Require owner/write authority to be limited to SYSTEM/Administrators."""
    if sys.platform != "win32":
        try:
            return not bool(path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH))
        except OSError:
            return False
    try:
        from angerona.core.privilege import (
            sanitized_child_environment,
            trusted_powershell_path,
            trusted_windows_directories,
        )

        powershell = trusted_powershell_path()
        _windows, system = trusted_windows_directories()
        if not powershell.is_file():
            return False
        script = (
            "$a=Get-Acl -LiteralPath $env:ANGERONA_NATIVE_PATH -ErrorAction Stop;"
            "$o=(New-Object Security.Principal.NTAccount($a.Owner)).Translate("
            "[Security.Principal.SecurityIdentifier]).Value;"
            "$d=[Security.AccessControl.FileSystemRights]::WriteData -bor "
            "[Security.AccessControl.FileSystemRights]::AppendData -bor "
            "[Security.AccessControl.FileSystemRights]::WriteAttributes -bor "
            "[Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor "
            "[Security.AccessControl.FileSystemRights]::Delete -bor "
            "[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor "
            "[Security.AccessControl.FileSystemRights]::ChangePermissions -bor "
            "[Security.AccessControl.FileSystemRights]::TakeOwnership;"
            "$trusted=@('S-1-5-18','S-1-5-32-544',"
            "'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464');"
            "$bad=@($a.Access|Where-Object {$_.AccessControlType -eq 'Allow' -and "
            "$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value "
            "-notin $trusted -and "
            "(($_.FileSystemRights -band $d) -ne 0)});"
            "if($o -notin $trusted -or $bad.Count){exit 1};exit 0"
        )
        environment = sanitized_child_environment(source={})
        environment["ANGERONA_NATIVE_PATH"] = str(path)
        result = subprocess.run(
            [
                str(powershell),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            cwd=str(system),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def _protected_path(path: Path) -> bool:
    anchor = Path(path.anchor)
    for candidate in (path, *path.parents):
        if candidate == anchor:
            break
        if not _windows_acl_protected(candidate):
            return False
    return True


def _authenticode_identity(path: Path) -> tuple[str, str, str]:
    """Return bounded status, certificate subject, and thumbprint."""
    if sys.platform != "win32":
        return "Unsupported", "", ""
    try:
        from angerona.core.privilege import (
            sanitized_child_environment,
            trusted_powershell_path,
            trusted_windows_directories,
        )

        powershell = trusted_powershell_path()
        _windows, system = trusted_windows_directories()
        if not powershell.is_file():
            return "Unavailable", "", ""
        environment = sanitized_child_environment(source={})
        environment["ANGERONA_NATIVE_PATH"] = str(path)
        script = (
            "$s=Get-AuthenticodeSignature -LiteralPath $env:ANGERONA_NATIVE_PATH "
            "-ErrorAction Stop;"
            "$p=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''};"
            "$t=if($s.SignerCertificate){[string]$s.SignerCertificate.Thumbprint}else{''};"
            "[pscustomobject]@{status=[string]$s.Status;publisher=$p;thumbprint=$t}"
            "|ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            [
                str(powershell),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            cwd=str(system),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or len(result.stdout) > 4096:
            return "Unavailable", "", ""
        payload = json.loads(result.stdout.decode("utf-8", errors="strict"))
        if not isinstance(payload, dict):
            return "Unavailable", "", ""
        return (
            str(payload.get("status") or "")[:64],
            str(payload.get("publisher") or "")[:512],
            str(payload.get("thumbprint") or "")[:128],
        )
    except (
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        ValueError,
    ):
        return "Unavailable", "", ""


@dataclass
class TrustedExecutable:
    """A verified executable plus the file object that prevents replacement."""

    path: Path
    sha256: str
    publisher: str
    thumbprint: str
    object_identity: tuple[int, int, int, int, int]
    _stream: BinaryIO = field(repr=False)
    _path_guard: Callable[[Path], bool] = field(repr=False, default=_protected_path)

    @property
    def closed(self) -> bool:
        return self._stream.closed

    def close(self) -> None:
        self._stream.close()

    def still_valid(self, *, rehash: bool = False) -> bool:
        """Reprove the held object and canonical pathname before authorization."""
        try:
            if self.closed or _is_link_or_reparse(self.path):
                return False
            held = os.fstat(self._stream.fileno())
            current = self.path.stat()
            if (
                _identity(held) != self.object_identity
                or _identity(current) != self.object_identity
                or not stat.S_ISREG(held.st_mode)
                or int(getattr(held, "st_nlink", 1)) != 1
                or (rehash and not self._path_guard(self.path))
            ):
                return False
            return not rehash or hmac.compare_digest(
                _hash_stream(self._stream, held.st_size), self.sha256
            )
        except (OSError, ValueError, ExecutableTrustError):
            return False

    def __enter__(self) -> TrustedExecutable:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def acquire_pinned_executable(
    path: str | os.PathLike,
    *,
    expected_sha256: str,
    expected_publisher: str,
) -> TrustedExecutable:
    """Acquire exact sidecar custody or raise :class:`ExecutableTrustError`.

    Both independent pins are mandatory. The returned object must remain open
    through ``Popen`` (preferably for the child's supervised lifetime), so the
    verified pathname cannot be exchanged between verification and launch.
    """
    digest_pin = str(expected_sha256 or "").strip().casefold()
    publisher_pin = str(expected_publisher or "").strip()
    if not _SHA256.fullmatch(digest_pin):
        raise ExecutableTrustError("native executable SHA-256 pin is unavailable")
    if not publisher_pin or len(publisher_pin) > 512 or "\x00" in publisher_pin:
        raise ExecutableTrustError("native executable publisher pin is unavailable")

    candidate = Path(path)
    raw = str(candidate)
    if not raw or "\x00" in raw or len(raw) > 32767:
        raise ExecutableTrustError("native executable path is invalid")
    if sys.platform == "win32":
        pure = PureWindowsPath(raw)
        if (
            not pure.is_absolute()
            or not pure.drive
            or pure.suffix.casefold() != ".exe"
            or raw.startswith(("\\\\", "//", "\\\\?\\", "\\\\.\\"))
        ):
            raise ExecutableTrustError("native executable must be an absolute local .exe")
    try:
        absolute = candidate.absolute()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ExecutableTrustError("native executable is unavailable") from exc
    if os.path.normcase(os.path.normpath(str(absolute))) != os.path.normcase(
        os.path.normpath(str(resolved))
    ):
        raise ExecutableTrustError("native executable path does not resolve exactly")
    _reject_reparse_components(resolved)
    if not _protected_path(resolved):
        raise ExecutableTrustError("native executable path is not write-protected")

    try:
        stream = _open_sealed(resolved)
    except OSError as exc:
        raise ExecutableTrustError("native executable could not be sealed") from exc
    try:
        opened = os.fstat(stream.fileno())
        current = resolved.stat()
        object_identity = _identity(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(getattr(opened, "st_nlink", 1)) != 1
            or object_identity != _identity(current)
            or int(getattr(opened, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
        ):
            raise ExecutableTrustError("native executable is not one stable single-link file")
        actual_digest = _hash_stream(stream, opened.st_size)
        if not hmac.compare_digest(actual_digest, digest_pin):
            raise ExecutableTrustError("native executable SHA-256 does not match its pin")
        status, publisher, thumbprint = _authenticode_identity(resolved)
        if status.casefold() != "valid" or not hmac.compare_digest(
            publisher.casefold(), publisher_pin.casefold()
        ):
            raise ExecutableTrustError(
                "native executable Authenticode publisher does not match its pin"
            )
        receipt = TrustedExecutable(
            path=resolved,
            sha256=actual_digest,
            publisher=publisher,
            thumbprint=thumbprint,
            object_identity=object_identity,
            _stream=stream,
            _path_guard=_protected_path,
        )
        if not receipt.still_valid(rehash=True):
            raise ExecutableTrustError("native executable changed during trust verification")
        return receipt
    except Exception:
        stream.close()
        raise


def executable_is_trusted(
    path: str | os.PathLike,
    *,
    expected_sha256: str = "",
    expected_publisher: str = "",
) -> bool:
    """Compatibility predicate backed by the exact pinned custody check.

    Callers that launch the executable must use :func:`acquire_pinned_executable`
    and retain its result. Missing pins fail closed; the former generic-signer
    behavior is intentionally removed.
    """
    try:
        with acquire_pinned_executable(
            path,
            expected_sha256=expected_sha256,
            expected_publisher=expected_publisher,
        ):
            return True
    except (ExecutableTrustError, OSError, ValueError):
        return False


__all__ = [
    "ExecutableTrustError",
    "TrustedExecutable",
    "acquire_pinned_executable",
    "executable_is_trusted",
]
