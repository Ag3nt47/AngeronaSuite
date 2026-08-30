"""Pinned, handle-sealed Git for Windows runtime used only for publication.

The machine Git installation is discovery input, never execution authority.  A
reviewed profile pins every byte that can be selected from the staged Git/GCM/
HTTPS helper tree.  Source objects are opened without write/delete sharing,
copied into an atomically private directory, rehashed there, and retained behind
deny-write/delete handles until the publication boundary is closed.

Windows system DLLs loaded from the OS System32 directory remain an explicit
host trust boundary.  No file from the writable source installation, caller
PATH, caller current directory, or repository is executed as transport code.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator, Mapping


_LOADED_MODULE_PATH = Path(__file__).resolve(strict=True)
_REVIEWED_PROFILE_PATH = _LOADED_MODULE_PATH.with_name(
    "publication_git_runtime_profile.json"
)
PROFILE_PATH = _REVIEWED_PROFILE_PATH
PROFILE_SCHEMA = "angerona.publication-git-runtime/v1"
PROFILE_PLATFORM = "win32-x86_64"
# These values are reviewed code authority, deliberately independent of the
# mutable JSON document.  The profile is accepted only when its exact bytes and
# the security-relevant aggregate fields agree with this already-loaded module.
REVIEWED_PROFILE_SHA256 = (
    "3d77e4ffa00d2236836e2a90a292cdbf7b3884933771a4ad14176231a8efbfc0"
)
REVIEWED_PROFILE_SIZE = 54_008
REVIEWED_GIT_VERSION = "2.55.0.windows.4"
REVIEWED_GIT_BUILD_COMMIT = "a93524749d7806870fd2b4b00a3812da1d6e5f4a"
REVIEWED_FILE_COUNT = 312
REVIEWED_DIRECTORY_COUNT = 8
REVIEWED_TREE_BYTES = 191_289_767
REVIEWED_TREE_SHA256 = (
    "7151e168c3a919a5b63d42f432d38ebf51c1d05ee3eed821016e8c7349ce2356"
)
TREE_ROOTS = (
    "cmd",
    "mingw64/bin",
    "mingw64/libexec/git-core",
)
REQUIRED_SINGLE_FILES = (
    "usr/bin/msys-2.0.dll",
    "usr/bin/sh.exe",
)
_EXPECTED_PROFILE_KEYS = frozenset(
    {
        "schema",
        "platform",
        "git_version",
        "git_build_commit",
        "tree_roots",
        "required_single_files",
        "directories",
        "files",
        "file_count",
        "total_bytes",
        "tree_sha256",
        "system_dll_trust_boundary",
        "reviewed_at",
    }
)
_EXPECTED_FILE_KEYS = frozenset({"path", "size", "sha256"})
_MAX_PROFILE_BYTES = 512 * 1024
_MAX_FILES = 1024
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TREE_BYTES = 512 * 1024 * 1024
_COPY_CHUNK = 1024 * 1024
_WINDOWS_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class WindowsRuntimeError(RuntimeError):
    """Raised when the reviewed publication runtime cannot be proven exact."""


@dataclass(frozen=True)
class RuntimeFile:
    relative: str
    size: int
    sha256: str


@dataclass(frozen=True)
class RuntimeProfile:
    git_version: str
    git_build_commit: str
    directories: tuple[str, ...]
    files: tuple[RuntimeFile, ...]
    total_bytes: int
    tree_sha256: str


@dataclass(frozen=True)
class _HandleIdentity:
    volume: int
    index: int
    size: int
    links: int
    attributes: int


@dataclass
class _SealedSourceFileGroup:
    """One source object and every reviewed name for that exact file ID."""

    handle: int
    identity: _HandleIdentity
    records: list[RuntimeFile]
    aliases: tuple[str, ...] = ()


@dataclass
class _SealedRuntimeProfile:
    """One parsed profile retained behind its exact no-follow source handles."""

    profile: RuntimeProfile
    path: Path
    file_handle: int
    file_identity: _HandleIdentity
    parent_handle: int
    parent_identity: _HandleIdentity
    windows: bool
    closed: bool = False

    def revalidate(self) -> None:
        if self.closed:
            raise WindowsRuntimeError("reviewed publication profile seal is closed")
        file_identity = (
            _handle_identity(self.file_handle)
            if self.windows
            else _posix_handle_identity(self.file_handle)
        )
        parent_identity = (
            _handle_identity(self.parent_handle)
            if self.windows
            else _posix_handle_identity(self.parent_handle)
        )
        if (
            file_identity != self.file_identity
            or file_identity.links != 1
            or file_identity.attributes & _WINDOWS_REPARSE
        ):
            raise WindowsRuntimeError(
                "reviewed publication profile identity changed during staging"
            )
        if (
            parent_identity != self.parent_identity
            or parent_identity.attributes & _WINDOWS_REPARSE
        ):
            raise WindowsRuntimeError(
                "reviewed publication profile parent changed during staging"
            )
        if self.windows and str(_final_path_from_handle(self.file_handle)) != str(
            self.path
        ):
            raise WindowsRuntimeError(
                "reviewed publication profile canonical name changed during staging"
            )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.windows:
            _close_handle(self.file_handle)
            _close_handle(self.parent_handle)
        else:
            os.close(self.file_handle)
            os.close(self.parent_handle)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON numeric constant: {value}")


def _closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _safe_relative(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise WindowsRuntimeError(f"runtime profile {label} is not canonical text")
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or candidate.as_posix() != value
        or len(value) > 240
    ):
        raise WindowsRuntimeError(f"runtime profile {label} is not a safe path")
    return value


def _tree_digest(
    directories: Iterable[str],
    files: Iterable[RuntimeFile],
) -> str:
    digest = hashlib.sha256(b"angerona.publication-runtime-tree/v1\0")
    for relative in sorted(directories):
        digest.update(b"D\0")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
    for entry in sorted(files, key=lambda item: item.relative):
        digest.update(b"F\0")
        digest.update(entry.relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(entry.size).encode("ascii"))
        digest.update(b"\0")
        digest.update(entry.sha256.encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _parse_reviewed_profile(raw: bytes) -> RuntimeProfile:
    """Authenticate exact reviewed bytes before interpreting any JSON field."""

    if len(raw) != REVIEWED_PROFILE_SIZE or len(raw) > _MAX_PROFILE_BYTES:
        raise WindowsRuntimeError(
            "publication runtime profile does not match the compiled size"
        )
    if hashlib.sha256(raw).hexdigest() != REVIEWED_PROFILE_SHA256:
        raise WindowsRuntimeError(
            "publication runtime profile does not match the compiled SHA-256"
        )
    try:
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_closed_json_object,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise WindowsRuntimeError("publication runtime profile is invalid JSON") from exc
    if not isinstance(document, dict) or set(document) != _EXPECTED_PROFILE_KEYS:
        raise WindowsRuntimeError("publication runtime profile schema is not closed")
    if document["schema"] != PROFILE_SCHEMA or document["platform"] != PROFILE_PLATFORM:
        raise WindowsRuntimeError("publication runtime profile targets another platform")
    if (
        not isinstance(document["tree_roots"], list)
        or tuple(document["tree_roots"]) != TREE_ROOTS
    ):
        raise WindowsRuntimeError("publication runtime profile tree roots changed")
    if (
        not isinstance(document["required_single_files"], list)
        or tuple(document["required_single_files"]) != REQUIRED_SINGLE_FILES
    ):
        raise WindowsRuntimeError("publication runtime profile shell closure changed")
    version = document["git_version"]
    build = document["git_build_commit"]
    if (
        not isinstance(version, str)
        or not version
        or len(version) > 80
        or not isinstance(build, str)
        or len(build) != 40
        or any(character not in "0123456789abcdef" for character in build)
    ):
        raise WindowsRuntimeError("publication runtime version identity is invalid")
    raw_directories = document["directories"]
    raw_files = document["files"]
    if not isinstance(raw_directories, list) or not isinstance(raw_files, list):
        raise WindowsRuntimeError("publication runtime tree is not a list")
    directories = tuple(
        _safe_relative(item, label="directory") for item in raw_directories
    )
    if (
        directories != tuple(sorted(set(directories)))
        or len({item.casefold() for item in directories}) != len(directories)
    ):
        raise WindowsRuntimeError("publication runtime directories are not unique/sorted")
    files: list[RuntimeFile] = []
    for raw_entry in raw_files:
        if not isinstance(raw_entry, dict) or set(raw_entry) != _EXPECTED_FILE_KEYS:
            raise WindowsRuntimeError("publication runtime file record is not closed")
        relative = _safe_relative(raw_entry["path"], label="file")
        size = raw_entry["size"]
        sha256 = raw_entry["sha256"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= _MAX_FILE_BYTES
            or not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
        ):
            raise WindowsRuntimeError("publication runtime file identity is invalid")
        files.append(RuntimeFile(relative, size, sha256))
    file_tuple = tuple(files)
    file_names_casefold = {item.relative.casefold() for item in file_tuple}
    if (
        not file_tuple
        or len(file_tuple) > _MAX_FILES
        or tuple(item.relative for item in file_tuple)
        != tuple(sorted({item.relative for item in file_tuple}))
        or len(file_names_casefold) != len(file_tuple)
    ):
        raise WindowsRuntimeError("publication runtime files are not unique/sorted")
    file_names = {item.relative for item in file_tuple}
    if file_names_casefold & {item.casefold() for item in directories}:
        raise WindowsRuntimeError("publication runtime file/directory names collide")
    if not set(REQUIRED_SINGLE_FILES).issubset(file_names):
        raise WindowsRuntimeError("publication runtime shell files are missing")
    for root in TREE_ROOTS:
        if not any(name == root or name.startswith(root + "/") for name in directories):
            raise WindowsRuntimeError("publication runtime required directory is missing")
        if not any(name.startswith(root + "/") for name in file_names):
            raise WindowsRuntimeError("publication runtime required tree is empty")
    total = sum(item.size for item in file_tuple)
    if (
        document["file_count"] != len(file_tuple)
        or document["total_bytes"] != total
        or total > _MAX_TREE_BYTES
    ):
        raise WindowsRuntimeError("publication runtime aggregate identity is invalid")
    tree_sha256 = document["tree_sha256"]
    if tree_sha256 != _tree_digest(directories, file_tuple):
        raise WindowsRuntimeError("publication runtime tree digest is invalid")
    if (
        version != REVIEWED_GIT_VERSION
        or build != REVIEWED_GIT_BUILD_COMMIT
        or len(directories) != REVIEWED_DIRECTORY_COUNT
        or len(file_tuple) != REVIEWED_FILE_COUNT
        or total != REVIEWED_TREE_BYTES
        or tree_sha256 != REVIEWED_TREE_SHA256
    ):
        raise WindowsRuntimeError(
            "publication runtime profile does not match compiled tree authority"
        )
    trust = document["system_dll_trust_boundary"]
    reviewed_at = document["reviewed_at"]
    if (
        trust
        != "Windows System32 DLLs protected by the operating-system servicing boundary"
        or not isinstance(reviewed_at, str)
        or len(reviewed_at) != 10
    ):
        raise WindowsRuntimeError("publication runtime review metadata is invalid")
    return RuntimeProfile(
        git_version=version,
        git_build_commit=build,
        directories=directories,
        files=file_tuple,
        total_bytes=total,
        tree_sha256=tree_sha256,
    )


def load_runtime_profile(path: Path = _REVIEWED_PROFILE_PATH) -> RuntimeProfile:
    """Load the one compiled-path profile once through a retained exact handle."""

    sealed = _open_reviewed_profile(path)
    try:
        sealed.revalidate()
        return sealed.profile
    finally:
        sealed.close()


if os.name == "nt":
    from ctypes import wintypes

    _GENERIC_READ = 0x80000000
    _DELETE = 0x00010000
    _READ_CONTROL = 0x00020000
    _WRITE_DAC = 0x00040000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _ERROR_HANDLE_EOF = 38
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _SDDL_REVISION_1 = 1
    _SE_DACL_PROTECTED = 0x1000
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _FILE_DISPOSITION_INFO = 4

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]

    class _TOKEN_USER_RECORD(ctypes.Structure):
        _fields_ = [("User", _SID_AND_ATTRIBUTES)]

    class _ACL(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]

    class _ACCESS_ALLOWED_ACE(ctypes.Structure):
        _fields_ = [
            ("Header", _ACE_HEADER),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    class _FILE_DISPOSITION_INFO_RECORD(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    class _GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    # FOLDERID_LocalAppData.  This compiled identifier is resolved by the
    # shell for the current process token; it does not accept TEMP/TMP or a
    # caller-selected path as publication code authority.
    _FOLDERID_LOCAL_APP_DATA = _GUID(
        0xF1B32785,
        0x6FBA,
        0x4FCF,
        (ctypes.c_ubyte * 8)(0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91),
    )


def _kernel32():
    try:
        return ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError) as exc:
        raise WindowsRuntimeError("Windows kernel API is unavailable") from exc


def _advapi32():
    try:
        return ctypes.WinDLL("advapi32", use_last_error=True)
    except (AttributeError, OSError) as exc:
        raise WindowsRuntimeError("Windows security API is unavailable") from exc


def _close_handle(handle: int) -> None:
    if handle and handle != _INVALID_HANDLE_VALUE:
        kernel32 = _kernel32()
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def _open_handle(
    path: Path,
    *,
    directory: bool,
    delete_access: bool = False,
    share_write: bool = False,
    share_delete: bool = False,
    acl_control: bool = False,
) -> int:
    kernel32 = _kernel32()
    create = kernel32.CreateFileW
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
    access = (
        _GENERIC_READ
        | _READ_CONTROL
        | (_DELETE if delete_access else 0)
        | (_WRITE_DAC if acl_control else 0)
    )
    share = (
        _FILE_SHARE_READ
        | (_FILE_SHARE_WRITE if share_write else 0)
        | (_FILE_SHARE_DELETE if share_delete else 0)
    )
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    flags |= _FILE_FLAG_BACKUP_SEMANTICS if directory else _FILE_FLAG_SEQUENTIAL_SCAN
    handle = create(
        str(path),
        access,
        share,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    raw = ctypes.cast(handle, ctypes.c_void_p).value
    if raw == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise WindowsRuntimeError(
            f"publication runtime object could not be sealed ({error}): {path}"
        )
    return int(raw)


def _handle_identity(handle: int) -> _HandleIdentity:
    kernel32 = _kernel32()
    query = kernel32.GetFileInformationByHandle
    query.argtypes = [wintypes.HANDLE, ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION)]
    query.restype = wintypes.BOOL
    details = _BY_HANDLE_FILE_INFORMATION()
    if not query(wintypes.HANDLE(handle), ctypes.byref(details)):
        raise WindowsRuntimeError("publication runtime handle identity was lost")
    return _HandleIdentity(
        volume=int(details.dwVolumeSerialNumber),
        index=(int(details.nFileIndexHigh) << 32) | int(details.nFileIndexLow),
        size=(int(details.nFileSizeHigh) << 32) | int(details.nFileSizeLow),
        links=int(details.nNumberOfLinks),
        attributes=int(details.dwFileAttributes),
    )


def _read_handle(handle: int, expected_size: int) -> Iterator[bytes]:
    kernel32 = _kernel32()
    seek = kernel32.SetFilePointerEx
    seek.argtypes = [wintypes.HANDLE, ctypes.c_longlong, ctypes.c_void_p, wintypes.DWORD]
    seek.restype = wintypes.BOOL
    if not seek(wintypes.HANDLE(handle), 0, None, 0):
        raise WindowsRuntimeError("publication runtime source seek failed")
    read = kernel32.ReadFile
    read.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    read.restype = wintypes.BOOL
    remaining = expected_size
    buffer = ctypes.create_string_buffer(min(_COPY_CHUNK, max(1, expected_size)))
    while remaining:
        wanted = min(len(buffer), remaining)
        count = wintypes.DWORD()
        if not read(
            wintypes.HANDLE(handle),
            buffer,
            wanted,
            ctypes.byref(count),
            None,
        ):
            raise WindowsRuntimeError("publication runtime source read failed")
        actual = int(count.value)
        if actual <= 0 or actual > wanted:
            raise WindowsRuntimeError("publication runtime source was truncated")
        remaining -= actual
        yield buffer.raw[:actual]
    count = wintypes.DWORD()
    extra = ctypes.create_string_buffer(1)
    if not read(
        wintypes.HANDLE(handle),
        extra,
        1,
        ctypes.byref(count),
        None,
    ) or count.value:
        raise WindowsRuntimeError("publication runtime source size changed")


def _hash_handle(handle: int, expected_size: int) -> str:
    digest = hashlib.sha256()
    for chunk in _read_handle(handle, expected_size):
        digest.update(chunk)
    return digest.hexdigest()


def _posix_handle_identity(handle: int) -> _HandleIdentity:
    try:
        details = os.fstat(handle)
    except OSError as exc:
        raise WindowsRuntimeError(
            "reviewed publication profile handle identity was lost"
        ) from exc
    return _HandleIdentity(
        volume=int(details.st_dev),
        index=int(details.st_ino),
        size=int(details.st_size),
        links=int(details.st_nlink),
        attributes=0,
    )


def _read_posix_handle_once(handle: int, expected_size: int) -> bytes:
    try:
        os.lseek(handle, 0, os.SEEK_SET)
        payload = bytearray()
        while len(payload) < expected_size:
            chunk = os.read(handle, min(_COPY_CHUNK, expected_size - len(payload)))
            if not chunk:
                raise WindowsRuntimeError(
                    "reviewed publication profile was truncated during read"
                )
            payload.extend(chunk)
        if os.read(handle, 1):
            raise WindowsRuntimeError(
                "reviewed publication profile grew during read"
            )
    except OSError as exc:
        raise WindowsRuntimeError(
            "reviewed publication profile could not be read exactly"
        ) from exc
    return bytes(payload)


def _require_fixed_local_path(path: Path) -> None:
    if os.name != "nt":
        return
    kernel32 = _kernel32()
    volume_path = kernel32.GetVolumePathNameW
    volume_path.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    volume_path.restype = wintypes.BOOL
    buffer = ctypes.create_unicode_buffer(32768)
    if not volume_path(str(path), buffer, len(buffer)) or not buffer.value:
        raise WindowsRuntimeError(
            "reviewed publication profile volume could not be proven"
        )
    drive_type = kernel32.GetDriveTypeW
    drive_type.argtypes = [wintypes.LPCWSTR]
    drive_type.restype = wintypes.UINT
    if int(drive_type(buffer.value)) != 3:  # DRIVE_FIXED
        raise WindowsRuntimeError(
            "reviewed publication profile must reside on a fixed local volume"
        )


def _final_path_from_handle(handle: int) -> Path:
    if os.name != "nt":
        raise WindowsRuntimeError("canonical Windows handle path is unavailable")
    kernel32 = _kernel32()
    query = kernel32.GetFinalPathNameByHandleW
    query.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    query.restype = wintypes.DWORD
    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    length = int(query(wintypes.HANDLE(handle), buffer, size, 0))
    if length <= 0 or length >= size or not buffer.value:
        raise WindowsRuntimeError(
            "reviewed publication profile canonical name is unavailable"
        )
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _hardlink_paths_from_handle(handle: int) -> tuple[Path, ...]:
    """Enumerate the complete Windows hard-link namespace for one open file."""

    identity = _handle_identity(handle)
    if identity.links < 1 or identity.links > _MAX_FILES:
        raise WindowsRuntimeError(
            "publication runtime source hard-link count is outside policy"
        )
    canonical = _final_path_from_handle(handle)
    kernel32 = _kernel32()
    volume_path = kernel32.GetVolumePathNameW
    volume_path.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    volume_path.restype = wintypes.BOOL
    volume_buffer = ctypes.create_unicode_buffer(32768)
    if not volume_path(str(canonical), volume_buffer, len(volume_buffer)):
        raise WindowsRuntimeError(
            "publication runtime source volume namespace is unavailable"
        )
    volume_root = Path(volume_buffer.value)
    # Hard-link enumeration returns names relative to the volume.  A mounted
    # subvolume would require a second namespace translation; fail closed
    # instead of guessing how an enumerated name maps back to the source tree.
    if (
        not volume_buffer.value
        or not volume_root.is_absolute()
        or str(volume_root) != canonical.anchor
    ):
        raise WindowsRuntimeError(
            "publication runtime source volume namespace is not canonical"
        )

    first = kernel32.FindFirstFileNameW
    first.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
    ]
    first.restype = wintypes.HANDLE
    following = kernel32.FindNextFileNameW
    following.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
    ]
    following.restype = wintypes.BOOL
    close = kernel32.FindClose
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL

    name_buffer = ctypes.create_unicode_buffer(32768)
    length = wintypes.DWORD(len(name_buffer))
    finder = first(str(canonical), 0, ctypes.byref(length), name_buffer)
    finder_value = ctypes.cast(finder, ctypes.c_void_p).value
    if finder_value == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise WindowsRuntimeError(
            f"publication runtime hard-link enumeration failed ({error})"
        )
    names: list[str] = []
    try:
        names.append(name_buffer.value)
        while len(names) <= identity.links:
            length.value = len(name_buffer)
            ctypes.set_last_error(0)
            if following(finder, ctypes.byref(length), name_buffer):
                names.append(name_buffer.value)
                continue
            error = ctypes.get_last_error()
            if error == _ERROR_HANDLE_EOF:
                break
            raise WindowsRuntimeError(
                f"publication runtime hard-link enumeration changed ({error})"
            )
    finally:
        close(finder)
    if len(names) != identity.links:
        raise WindowsRuntimeError(
            "publication runtime hard-link enumeration is incomplete"
        )

    paths: list[Path] = []
    seen: set[str] = set()
    for name in names:
        if (
            not name.startswith("\\")
            or name.startswith("\\\\")
            or "/" in name
            or "\0" in name
        ):
            raise WindowsRuntimeError(
                "publication runtime hard-link name is not canonical"
            )
        parts = name[1:].split("\\")
        if any(
            not part or part in {".", ".."} or ":" in part
            for part in parts
        ):
            raise WindowsRuntimeError(
                "publication runtime hard-link name is not canonical"
            )
        candidate = volume_root / Path(*parts)
        folded = str(candidate).casefold()
        if folded in seen:
            raise WindowsRuntimeError(
                "publication runtime hard-link enumeration contains duplicates"
            )
        seen.add(folded)
        paths.append(candidate)
    return tuple(sorted(paths, key=lambda item: str(item).casefold()))


def _open_profile_at(path: Path, *, expected_path: Path) -> _SealedRuntimeProfile:
    """Open one exact candidate; ``expected_path`` exists for bounded fixtures."""

    if (
        not path.is_absolute()
        or str(path) != str(expected_path)
        or any("\0" in part or (":" in part and index > 0) for index, part in enumerate(path.parts))
    ):
        raise WindowsRuntimeError(
            "reviewed publication profile path is not the compiled canonical name"
        )
    _require_fixed_local_path(path)
    file_handle = 0
    parent_handle = 0
    windows = os.name == "nt"
    try:
        if windows:
            parent_handle = _open_handle(path.parent, directory=True)
            file_handle = _open_handle(path, directory=False)
            parent_identity = _handle_identity(parent_handle)
            file_identity = _handle_identity(file_handle)
            if str(_final_path_from_handle(file_handle)) != str(expected_path):
                raise WindowsRuntimeError(
                    "reviewed publication profile opened through a non-canonical name"
                )
        else:
            no_follow = getattr(os, "O_NOFOLLOW", 0)
            close_on_exec = getattr(os, "O_CLOEXEC", 0)
            directory = getattr(os, "O_DIRECTORY", 0)
            parent_handle = os.open(
                path.parent,
                os.O_RDONLY | directory | no_follow | close_on_exec,
            )
            file_handle = os.open(
                path,
                os.O_RDONLY | no_follow | close_on_exec,
            )
            parent_details = os.fstat(parent_handle)
            file_details = os.fstat(file_handle)
            if not stat.S_ISDIR(parent_details.st_mode) or not stat.S_ISREG(
                file_details.st_mode
            ):
                raise WindowsRuntimeError(
                    "reviewed publication profile is not a regular local file"
                )
            parent_identity = _posix_handle_identity(parent_handle)
            file_identity = _posix_handle_identity(file_handle)
        if (
            file_identity.size != REVIEWED_PROFILE_SIZE
            or file_identity.links != 1
            or file_identity.attributes & _WINDOWS_REPARSE
            or parent_identity.attributes & _WINDOWS_REPARSE
            or file_identity.volume != parent_identity.volume
        ):
            raise WindowsRuntimeError(
                "reviewed publication profile object identity is not trusted"
            )
        raw = (
            b"".join(_read_handle(file_handle, REVIEWED_PROFILE_SIZE))
            if windows
            else _read_posix_handle_once(file_handle, REVIEWED_PROFILE_SIZE)
        )
        profile = _parse_reviewed_profile(raw)
        sealed = _SealedRuntimeProfile(
            profile=profile,
            path=expected_path,
            file_handle=file_handle,
            file_identity=file_identity,
            parent_handle=parent_handle,
            parent_identity=parent_identity,
            windows=windows,
        )
        sealed.revalidate()
        file_handle = 0
        parent_handle = 0
        return sealed
    except OSError as exc:
        raise WindowsRuntimeError(
            "reviewed publication profile is unavailable"
        ) from exc
    finally:
        if file_handle:
            if windows:
                _close_handle(file_handle)
            else:
                os.close(file_handle)
        if parent_handle:
            if windows:
                _close_handle(parent_handle)
            else:
                os.close(parent_handle)


def _open_reviewed_profile(
    path: Path = _REVIEWED_PROFILE_PATH,
) -> _SealedRuntimeProfile:
    candidate = Path(path)
    if str(candidate) != str(_REVIEWED_PROFILE_PATH):
        raise WindowsRuntimeError(
            "publication runtime profile alternate paths are forbidden"
        )
    return _open_profile_at(candidate, expected_path=_REVIEWED_PROFILE_PATH)


def _current_user_sid() -> str:
    kernel32 = _kernel32()
    advapi32 = _advapi32()
    token = wintypes.HANDLE()
    open_token = advapi32.OpenProcessToken
    open_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_token.restype = wintypes.BOOL
    if not open_token(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise WindowsRuntimeError("publication runtime token could not be inspected")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
        if needed.value <= 0 or needed.value > 64 * 1024:
            raise WindowsRuntimeError("publication runtime token SID is unavailable")
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token,
            _TOKEN_USER,
            buffer,
            needed,
            ctypes.byref(needed),
        ):
            raise WindowsRuntimeError("publication runtime token SID is unavailable")
        record = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER_RECORD)).contents
        return _sid_text(record.User.Sid)
    finally:
        _close_handle(int(token.value))


def _sid_text(sid: int) -> str:
    advapi32 = _advapi32()
    kernel32 = _kernel32()
    converted = wintypes.LPWSTR()
    convert = advapi32.ConvertSidToStringSidW
    convert.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    convert.restype = wintypes.BOOL
    if not convert(sid, ctypes.byref(converted)):
        raise WindowsRuntimeError("publication runtime SID conversion failed")
    try:
        return str(converted.value)
    finally:
        kernel32.LocalFree(converted)


def _private_descriptor(current_sid: str, *, writable: bool) -> int:
    current_rights = "FA" if writable else "GRGX"
    descriptor_text = (
        f"O:{current_sid}G:{current_sid}D:P"
        "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        f"(A;OICI;{current_rights};;;{current_sid})"
    )
    advapi32 = _advapi32()
    descriptor = wintypes.LPVOID()
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.ULONG),
    ]
    convert.restype = wintypes.BOOL
    if not convert(
        descriptor_text,
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise WindowsRuntimeError("private publication DACL could not be built")
    return int(descriptor.value)


def _set_handle_private_acl(handle: int, current_sid: str, *, writable: bool) -> None:
    advapi32 = _advapi32()
    kernel32 = _kernel32()
    descriptor = _private_descriptor(current_sid, writable=writable)
    operation = advapi32.SetKernelObjectSecurity
    operation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]
    operation.restype = wintypes.BOOL
    try:
        if not operation(
            wintypes.HANDLE(handle),
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            wintypes.LPVOID(descriptor),
        ):
            error = ctypes.get_last_error()
            raise WindowsRuntimeError(
                f"private publication DACL could not be sealed ({error})"
            )
    finally:
        kernel32.LocalFree(wintypes.LPVOID(descriptor))


def _create_private_directory(parent: Path, *, prefix: str) -> tuple[Path, str]:
    if prefix not in {"angerona-publish-runtime-", "angerona-publish-state-"}:
        raise WindowsRuntimeError("private publication directory prefix is invalid")
    current_sid = _current_user_sid()
    kernel32 = _kernel32()
    descriptor = _private_descriptor(current_sid, writable=True)
    attributes = _SECURITY_ATTRIBUTES(
        ctypes.sizeof(_SECURITY_ATTRIBUTES), wintypes.LPVOID(descriptor), False
    )
    create = kernel32.CreateDirectoryW
    create.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SECURITY_ATTRIBUTES)]
    create.restype = wintypes.BOOL
    try:
        for _attempt in range(16):
            candidate = parent / f"{prefix}{secrets.token_hex(16)}"
            if create(str(candidate), ctypes.byref(attributes)):
                try:
                    _assert_private_directory_acl(
                        candidate,
                        current_sid,
                        writable=True,
                    )
                except Exception:
                    remove = kernel32.RemoveDirectoryW
                    remove.argtypes = [wintypes.LPCWSTR]
                    remove.restype = wintypes.BOOL
                    remove(str(candidate))
                    raise
                return candidate, current_sid
            error = ctypes.get_last_error()
            if error != 183:  # ERROR_ALREADY_EXISTS
                raise WindowsRuntimeError(
                    f"private publication directory creation failed ({error})"
                )
    finally:
        kernel32.LocalFree(wintypes.LPVOID(descriptor))
    raise WindowsRuntimeError("private publication directory name was exhausted")


def _assert_private_directory_acl(
    path: Path,
    current_sid: str,
    *,
    writable: bool = False,
) -> None:
    advapi32 = _advapi32()
    kernel32 = _kernel32()
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    query = advapi32.GetNamedSecurityInfoW
    query.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    query.restype = wintypes.DWORD
    error = query(
        str(path),
        1,  # SE_FILE_OBJECT
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if error:
        raise WindowsRuntimeError(f"private publication DACL query failed ({error})")
    try:
        if _sid_text(owner.value) != current_sid or not dacl.value:
            raise WindowsRuntimeError("private publication directory owner is wrong")
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        get_control = advapi32.GetSecurityDescriptorControl
        get_control.argtypes = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        get_control.restype = wintypes.BOOL
        if not get_control(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise WindowsRuntimeError("private publication DACL control is unavailable")
        if not int(control.value) & _SE_DACL_PROTECTED:
            raise WindowsRuntimeError("private publication DACL inherits authority")
        acl = ctypes.cast(dacl, ctypes.POINTER(_ACL)).contents
        if int(acl.AceCount) != 3:
            raise WindowsRuntimeError("private publication DACL has extra trustees")
        allowed = {current_sid, "S-1-5-18", "S-1-5-32-544"}
        observed: dict[str, int] = {}
        get_ace = advapi32.GetAce
        get_ace.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
        ]
        get_ace.restype = wintypes.BOOL
        for index in range(int(acl.AceCount)):
            ace_pointer = wintypes.LPVOID()
            if not get_ace(dacl, index, ctypes.byref(ace_pointer)):
                raise WindowsRuntimeError("private publication DACL ACE is unavailable")
            ace = ctypes.cast(
                ace_pointer, ctypes.POINTER(_ACCESS_ALLOWED_ACE)
            ).contents
            if int(ace.Header.AceType) != _ACCESS_ALLOWED_ACE_TYPE:
                raise WindowsRuntimeError("private publication DACL contains a deny/unknown ACE")
            sid_address = int(ace_pointer.value) + _ACCESS_ALLOWED_ACE.SidStart.offset
            observed[_sid_text(sid_address)] = int(ace.Mask)
        if set(observed) != allowed:
            raise WindowsRuntimeError("private publication DACL trustees are not exact")
        current_mask = observed[current_sid]
        dangerous = (
            0x40000000  # GENERIC_WRITE
            | 0x10000000  # GENERIC_ALL
            | _DELETE
            | _WRITE_DAC
            | 0x00080000  # WRITE_OWNER
            | 0x00000002  # FILE_WRITE_DATA / FILE_ADD_FILE
            | 0x00000004  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
            | 0x00000040  # FILE_DELETE_CHILD
        )
        if writable and not current_mask & dangerous:
            raise WindowsRuntimeError("private publication DACL is not writable for staging")
        if not writable and current_mask & dangerous:
            raise WindowsRuntimeError("private publication DACL retains write authority")
    finally:
        kernel32.LocalFree(descriptor)


def _trusted_temp_root() -> Path:
    """Resolve a token-owned staging parent without ambient path authority."""

    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        ole32 = ctypes.WinDLL("ole32", use_last_error=True)
        query = shell32.SHGetKnownFolderPath
        query.argtypes = [
            ctypes.POINTER(_GUID),
            wintypes.DWORD,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        query.restype = ctypes.c_long
        release = ole32.CoTaskMemFree
        release.argtypes = [wintypes.LPVOID]
        release.restype = None
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise WindowsRuntimeError(
            "Windows private staging parent query is unavailable"
        ) from exc

    allocated = wintypes.LPWSTR()
    try:
        result = int(
            query(
                ctypes.byref(_FOLDERID_LOCAL_APP_DATA),
                0,
                None,
                ctypes.byref(allocated),
            )
        )
        raw_parent = allocated.value or ""
    finally:
        if allocated:
            release(ctypes.cast(allocated, wintypes.LPVOID))
    if result != 0 or not raw_parent:
        raise WindowsRuntimeError("Windows private staging parent is unavailable")
    candidate = Path(raw_parent) / "Temp"
    try:
        resolved = candidate.resolve(strict=True)
        details = candidate.lstat()
    except OSError as exc:
        raise WindowsRuntimeError("Windows private staging parent is unavailable") from exc
    if (
        not resolved.is_absolute()
        or candidate != resolved
        or int(getattr(details, "st_file_attributes", 0)) & _WINDOWS_REPARSE
        or not resolved.is_dir()
    ):
        raise WindowsRuntimeError("Windows private staging parent is an alias")
    _require_fixed_local_path(resolved)
    return resolved


def _collect_scoped_tree(root: Path, profile: RuntimeProfile) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    for relative_root in TREE_ROOTS:
        start = root / Path(*PurePosixPath(relative_root).parts)
        stack = [start]
        while stack:
            current = stack.pop()
            try:
                details = current.lstat()
                resolved = current.resolve(strict=True)
            except OSError as exc:
                raise WindowsRuntimeError("publication runtime tree is unavailable") from exc
            if (
                current != resolved
                or int(getattr(details, "st_file_attributes", 0)) & _WINDOWS_REPARSE
                or not current.is_dir()
            ):
                raise WindowsRuntimeError("publication runtime tree contains an alias")
            relative = current.relative_to(root).as_posix()
            directories.add(relative)
            try:
                children = list(os.scandir(current))
            except OSError as exc:
                raise WindowsRuntimeError("publication runtime tree cannot be enumerated") from exc
            for child in children:
                child_path = Path(child.path)
                try:
                    child_details = child_path.lstat()
                except OSError as exc:
                    raise WindowsRuntimeError("publication runtime entry vanished") from exc
                if int(getattr(child_details, "st_file_attributes", 0)) & _WINDOWS_REPARSE:
                    raise WindowsRuntimeError("publication runtime tree contains a reparse point")
                child_relative = child_path.relative_to(root).as_posix()
                if child.is_dir(follow_symlinks=False):
                    stack.append(child_path)
                elif child.is_file(follow_symlinks=False):
                    files.add(child_relative)
                else:
                    raise WindowsRuntimeError("publication runtime tree has a special object")
    for required in REQUIRED_SINGLE_FILES:
        path = root / Path(*PurePosixPath(required).parts)
        try:
            details = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise WindowsRuntimeError("publication runtime shell closure is missing") from exc
        if (
            path != resolved
            or int(getattr(details, "st_file_attributes", 0)) & _WINDOWS_REPARSE
            or not path.is_file()
        ):
            raise WindowsRuntimeError("publication runtime shell closure is an alias")
        files.add(required)
    expected_files = {entry.relative for entry in profile.files}
    scoped_expected_directories = {
        item
        for item in profile.directories
        if any(item == root or item.startswith(root + "/") for root in TREE_ROOTS)
    }
    if files != expected_files:
        added = sorted(files - expected_files)[:3]
        removed = sorted(expected_files - files)[:3]
        detail = f" additions={added}" if added else ""
        detail += f" removals={removed}" if removed else ""
        raise WindowsRuntimeError("publication runtime file set changed" + detail)
    if directories != scoped_expected_directories:
        raise WindowsRuntimeError("publication runtime directory set changed")
    return files, directories


def _collect_staged_tree(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            children = list(os.scandir(current))
        except OSError as exc:
            raise WindowsRuntimeError("private publication runtime cannot be enumerated") from exc
        for child in children:
            path = Path(child.path)
            try:
                details = path.lstat()
            except OSError as exc:
                raise WindowsRuntimeError("private publication runtime entry vanished") from exc
            if int(getattr(details, "st_file_attributes", 0)) & _WINDOWS_REPARSE:
                raise WindowsRuntimeError("private publication runtime contains an alias")
            relative = path.relative_to(root).as_posix()
            if child.is_dir(follow_symlinks=False):
                directories.add(relative)
                stack.append(path)
            elif child.is_file(follow_symlinks=False):
                files.add(relative)
            else:
                raise WindowsRuntimeError("private publication runtime has a special object")
    return files, directories


def _required_source_directories(root: Path, profile: RuntimeProfile) -> list[Path]:
    relative_directories = set(profile.directories)
    for entry in profile.files:
        parent = PurePosixPath(entry.relative).parent
        while parent.parts:
            relative_directories.add(parent.as_posix())
            parent = parent.parent
    return [root, *(
        root / Path(*PurePosixPath(relative).parts)
        for relative in sorted(relative_directories, key=lambda item: (item.count("/"), item))
    )]


def _source_group_aliases(
    group: _SealedSourceFileGroup,
    source_root: Path,
    profile_files: Mapping[str, RuntimeFile],
) -> tuple[str, ...]:
    metadata = {(record.size, record.sha256) for record in group.records}
    if len(metadata) != 1 or next(iter(metadata))[0] != group.identity.size:
        raise WindowsRuntimeError(
            "publication runtime profiled hard-link aliases disagree"
        )
    expected_aliases = {record.relative for record in group.records}
    if group.identity.links == 1:
        # A stable link count of one plus the exact final handle name is the
        # complete namespace proof; reserve full FindFirstFileNameW traversal
        # for the exceptional reviewed multi-link groups.
        if len(expected_aliases) != 1:
            raise WindowsRuntimeError(
                "publication runtime hard-link topology differs from the profile"
            )
        relative = next(iter(expected_aliases))
        expected_path = source_root / Path(*PurePosixPath(relative).parts)
        record = profile_files.get(relative)
        if (
            record is None
            or str(_final_path_from_handle(group.handle)) != str(expected_path)
            or record.size != group.identity.size
            or record.sha256 != group.records[0].sha256
        ):
            raise WindowsRuntimeError(
                f"publication runtime source identity changed: {relative}"
            )
        return (relative,)
    observed_aliases: set[str] = set()
    for candidate in _hardlink_paths_from_handle(group.handle):
        try:
            if not candidate.is_relative_to(source_root):
                raise WindowsRuntimeError(
                    "publication runtime source has an outside hard-link alias"
                )
            relative = candidate.relative_to(source_root).as_posix()
        except (OSError, ValueError) as exc:
            raise WindowsRuntimeError(
                "publication runtime source hard-link namespace is invalid"
            ) from exc
        record = profile_files.get(relative)
        if record is None:
            raise WindowsRuntimeError(
                "publication runtime source has an unprofiled hard-link alias"
            )
        alias_handle = _open_handle(candidate, directory=False)
        try:
            alias_identity = _handle_identity(alias_handle)
            if (
                alias_identity != group.identity
                or alias_identity.attributes & _WINDOWS_REPARSE
                or str(_final_path_from_handle(alias_handle)) != str(candidate)
                or record.size != group.identity.size
                or record.sha256 != group.records[0].sha256
            ):
                raise WindowsRuntimeError(
                    f"publication runtime hard-link alias is not exact: {relative}"
                )
        finally:
            _close_handle(alias_handle)
        observed_aliases.add(relative)
    if observed_aliases != expected_aliases:
        raise WindowsRuntimeError(
            "publication runtime hard-link topology differs from the profile"
        )
    return tuple(sorted(observed_aliases))


def _revalidate_source_groups(
    groups: Mapping[tuple[int, int], _SealedSourceFileGroup],
    source_root: Path,
    profile_files: Mapping[str, RuntimeFile],
) -> None:
    for group in groups.values():
        actual = _handle_identity(group.handle)
        if actual != group.identity or actual.attributes & _WINDOWS_REPARSE:
            raise WindowsRuntimeError(
                "publication runtime source file identity changed"
            )
        aliases = _source_group_aliases(group, source_root, profile_files)
        if aliases != group.aliases:
            raise WindowsRuntimeError(
                "publication runtime source hard-link topology changed"
            )


def _copy_from_handle(handle: int, destination: Path, record: RuntimeFile) -> str:
    digest = hashlib.sha256()
    try:
        with destination.open("xb") as target:
            for chunk in _read_handle(handle, record.size):
                target.write(chunk)
                digest.update(chunk)
            target.flush()
            os.fsync(target.fileno())
    except OSError as exc:
        raise WindowsRuntimeError("private publication runtime copy failed") from exc
    return digest.hexdigest()


def _copy_hardlink_group_from_handle(
    handle: int,
    destinations: tuple[tuple[Path, RuntimeFile], ...],
) -> str:
    """Read one source identity once and materialize independent stage files."""

    if len(destinations) < 2:
        raise WindowsRuntimeError(
            "publication runtime hard-link copy group is not plural"
        )
    metadata = {(record.size, record.sha256) for _path, record in destinations}
    if len(metadata) != 1:
        raise WindowsRuntimeError(
            "publication runtime profiled hard-link aliases disagree"
        )
    expected_size, _expected_digest = next(iter(metadata))
    targets = []
    digest = hashlib.sha256()
    try:
        for destination, _record in destinations:
            targets.append(destination.open("xb"))
        for chunk in _read_handle(handle, expected_size):
            digest.update(chunk)
            for target in targets:
                if target.write(chunk) != len(chunk):
                    raise WindowsRuntimeError(
                        "private publication runtime copy was truncated"
                    )
        for target in targets:
            target.flush()
            os.fsync(target.fileno())
    except OSError as exc:
        raise WindowsRuntimeError("private publication runtime copy failed") from exc
    finally:
        for target in targets:
            target.close()
    return digest.hexdigest()


def _mark_delete(handle: int) -> None:
    kernel32 = _kernel32()
    operation = kernel32.SetFileInformationByHandle
    operation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    operation.restype = wintypes.BOOL
    info = _FILE_DISPOSITION_INFO_RECORD(True)
    if not operation(
        wintypes.HANDLE(handle),
        _FILE_DISPOSITION_INFO,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        error = ctypes.get_last_error()
        raise WindowsRuntimeError(
            f"private publication runtime cleanup could not be authorized ({error})"
        )


def _remove_private_scratch(root: Path) -> None:
    if not root.name.startswith("angerona-publish-state-"):
        raise WindowsRuntimeError("private publication scratch target is invalid")
    try:
        resolved = root.resolve(strict=True)
        details = root.lstat()
    except OSError as exc:
        raise WindowsRuntimeError("private publication scratch is unavailable") from exc
    if (
        resolved != root
        or int(getattr(details, "st_file_attributes", 0)) & _WINDOWS_REPARSE
        or not root.is_dir()
    ):
        raise WindowsRuntimeError("private publication scratch is an alias")
    files: list[Path] = []
    directories: list[Path] = []
    stack = [root]
    total_bytes = 0
    while stack:
        current = stack.pop()
        try:
            children = list(os.scandir(current))
        except OSError as exc:
            raise WindowsRuntimeError("private publication scratch cannot be read") from exc
        for child in children:
            path = Path(child.path)
            try:
                child_details = path.lstat()
            except OSError as exc:
                raise WindowsRuntimeError("private publication scratch entry vanished") from exc
            if (
                int(getattr(child_details, "st_file_attributes", 0)) & _WINDOWS_REPARSE
                or not path.is_relative_to(root)
            ):
                raise WindowsRuntimeError("private publication scratch contains an alias")
            if child.is_dir(follow_symlinks=False):
                directories.append(path)
                stack.append(path)
            elif child.is_file(follow_symlinks=False):
                total_bytes += int(child_details.st_size)
                files.append(path)
            else:
                raise WindowsRuntimeError("private publication scratch has a special object")
            if len(files) + len(directories) > 2048 or total_bytes > 16 * 1024 * 1024:
                raise WindowsRuntimeError("private publication scratch exceeds cleanup bounds")
    try:
        for path in files:
            path.unlink()
        for path in sorted(directories, key=lambda item: -len(item.parts)):
            path.rmdir()
        root.rmdir()
    except OSError as exc:
        raise WindowsRuntimeError("private publication scratch cleanup failed") from exc


class StagedWindowsRuntime:
    """Exact staged tree plus retained file/directory namespace seals."""

    def __init__(
        self,
        *,
        root: Path,
        scratch_root: Path,
        scratch_handle: int,
        scratch_identity: _HandleIdentity,
        parent_handle: int,
        file_handles: Mapping[str, tuple[int, _HandleIdentity]],
        directory_handles: Mapping[str, tuple[int, _HandleIdentity]],
        profile: RuntimeProfile,
        current_sid: str,
    ) -> None:
        self.root = root
        self.scratch_root = scratch_root
        self.executable = root / "cmd" / "git.exe"
        self.credential_helper = (
            root / "mingw64" / "bin" / "git-credential-manager.exe"
        )
        self.git_exec_path = root / "mingw64" / "libexec" / "git-core"
        self.shell_path = root / "usr" / "bin"
        self._parent_handle = parent_handle
        self._scratch_handle = scratch_handle
        self._scratch_identity = scratch_identity
        self._file_handles = dict(file_handles)
        self._directory_handles = dict(directory_handles)
        self._profile = profile
        self._current_sid = current_sid
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def git_version(self) -> str:
        return self._profile.git_version

    @property
    def git_build_commit(self) -> str:
        return self._profile.git_build_commit

    def revalidate(self) -> None:
        if self._closed:
            raise WindowsRuntimeError("private publication runtime is closed")
        for relative, (handle, expected) in self._file_handles.items():
            actual = _handle_identity(handle)
            if actual != expected or actual.links != 1 or actual.attributes & _WINDOWS_REPARSE:
                raise WindowsRuntimeError(
                    f"private publication runtime file changed: {relative}"
                )
        for relative, (handle, expected) in self._directory_handles.items():
            actual = _handle_identity(handle)
            if actual != expected or actual.attributes & _WINDOWS_REPARSE:
                raise WindowsRuntimeError(
                    f"private publication runtime directory changed: {relative}"
                )
        if (
            _handle_identity(self._scratch_handle) != self._scratch_identity
            or self._scratch_identity.attributes & _WINDOWS_REPARSE
        ):
            raise WindowsRuntimeError("private publication scratch directory changed")
        files, directories = _collect_staged_tree(self.root)
        expected_files = {item.relative for item in self._profile.files}
        if files != expected_files:
            raise WindowsRuntimeError("private publication runtime file set changed")
        if directories != set(self._profile.directories):
            raise WindowsRuntimeError("private publication runtime directory set changed")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        errors: list[Exception] = []
        for relative, (handle, _identity) in sorted(self._file_handles.items()):
            try:
                _set_handle_private_acl(
                    handle,
                    self._current_sid,
                    writable=True,
                )
                cleanup = _open_handle(
                    self.root / Path(*PurePosixPath(relative).parts),
                    directory=False,
                    delete_access=True,
                    share_delete=True,
                )
                try:
                    _mark_delete(cleanup)
                finally:
                    _close_handle(cleanup)
            except Exception as exc:  # Cleanup must still close every retained handle.
                errors.append(exc)
            finally:
                _close_handle(handle)
        for relative, (handle, _identity) in sorted(
            self._directory_handles.items(),
            key=lambda item: (
                -(item[0].count("/") if item[0] != "." else -1),
                item[0],
            ),
        ):
            try:
                _set_handle_private_acl(
                    handle,
                    self._current_sid,
                    writable=True,
                )
                path = self.root if relative == "." else (
                    self.root / Path(*PurePosixPath(relative).parts)
                )
                cleanup = _open_handle(
                    path,
                    directory=True,
                    delete_access=True,
                    share_delete=True,
                )
                try:
                    _mark_delete(cleanup)
                finally:
                    _close_handle(cleanup)
            except Exception as exc:
                errors.append(exc)
            finally:
                _close_handle(handle)
        _close_handle(self._scratch_handle)
        try:
            _remove_private_scratch(self.scratch_root)
        except Exception as exc:
            errors.append(exc)
        _close_handle(self._parent_handle)
        self._file_handles.clear()
        self._directory_handles.clear()
        if errors or self.root.exists() or self.scratch_root.exists():
            raise WindowsRuntimeError(
                "private publication runtime could not be removed exactly"
            ) from (errors[0] if errors else None)

    def __del__(self) -> None:
        if not getattr(self, "_closed", True):
            try:
                self.close()
            except Exception:
                pass


def stage_pinned_runtime(
    install_root: Path,
    *,
    profile: RuntimeProfile | None = None,
    staging_parent: Path | None = None,
) -> StagedWindowsRuntime:
    """Copy one exact reviewed runtime from sealed source handles."""

    if os.name != "nt":
        raise WindowsRuntimeError("pinned Git for Windows staging requires Windows")
    profile_seal: _SealedRuntimeProfile | None = None
    if profile is None:
        profile_seal = _open_reviewed_profile()
        active_profile = profile_seal.profile
        profile_seal.revalidate()
    else:
        # Explicit profiles are a fixture boundary for already trusted in-process
        # callers.  The publication path never supplies this argument.
        active_profile = profile
    try:
        source_root = install_root.resolve(strict=True)
        root_details = install_root.lstat()
    except OSError as exc:
        if profile_seal is not None:
            profile_seal.close()
        raise WindowsRuntimeError("machine Git installation root is unavailable") from exc
    if (
        not source_root.is_absolute()
        or source_root != install_root
        or int(getattr(root_details, "st_file_attributes", 0)) & _WINDOWS_REPARSE
        or not source_root.is_dir()
    ):
        if profile_seal is not None:
            profile_seal.close()
        raise WindowsRuntimeError("machine Git installation root is an alias")

    source_directories: dict[str, tuple[int, _HandleIdentity]] = {}
    source_groups: dict[tuple[int, int], _SealedSourceFileGroup] = {}
    profile_files = {record.relative: record for record in active_profile.files}
    if len(profile_files) != len(active_profile.files):
        if profile_seal is not None:
            profile_seal.close()
        raise WindowsRuntimeError("publication runtime profile paths are not unique")
    parent_handle = 0
    stage_root: Path | None = None
    scratch_root: Path | None = None
    scratch_handle = 0
    try:
        for directory in _required_source_directories(source_root, active_profile):
            relative = "." if directory == source_root else directory.relative_to(source_root).as_posix()
            handle = _open_handle(directory, directory=True)
            identity = _handle_identity(handle)
            if identity.attributes & _WINDOWS_REPARSE:
                _close_handle(handle)
                raise WindowsRuntimeError("machine Git tree contains a reparse directory")
            source_directories[relative] = (handle, identity)
        _collect_scoped_tree(source_root, active_profile)
        for record in active_profile.files:
            path = source_root / Path(*PurePosixPath(record.relative).parts)
            handle = _open_handle(path, directory=False)
            try:
                identity = _handle_identity(handle)
                if (
                    identity.attributes & _WINDOWS_REPARSE
                    or identity.size != record.size
                    or str(_final_path_from_handle(handle)) != str(path)
                ):
                    raise WindowsRuntimeError(
                        f"publication runtime source identity changed: {record.relative}"
                    )
                key = (identity.volume, identity.index)
                existing = source_groups.get(key)
                if existing is None:
                    source_groups[key] = _SealedSourceFileGroup(
                        handle=handle,
                        identity=identity,
                        records=[record],
                    )
                    handle = 0
                else:
                    if identity != existing.identity:
                        raise WindowsRuntimeError(
                            "publication runtime hard-link identity changed during acquisition"
                        )
                    existing.records.append(record)
            finally:
                if handle:
                    _close_handle(handle)
        for group in source_groups.values():
            group.aliases = _source_group_aliases(
                group,
                source_root,
                profile_files,
            )
        _collect_scoped_tree(source_root, active_profile)
        _revalidate_source_groups(source_groups, source_root, profile_files)
        if profile_seal is not None:
            profile_seal.revalidate()

        parent = (staging_parent or _trusted_temp_root()).resolve(strict=True)
        if not parent.is_dir():
            raise WindowsRuntimeError("private publication staging parent is invalid")
        parent_handle = _open_handle(
            parent,
            directory=True,
            share_write=True,
        )
        if (
            _handle_identity(parent_handle).attributes & _WINDOWS_REPARSE
            or str(_final_path_from_handle(parent_handle)) != str(parent)
        ):
            raise WindowsRuntimeError("private publication staging parent is an alias")
        stage_root, current_sid = _create_private_directory(
            parent,
            prefix="angerona-publish-runtime-",
        )
        scratch_root, scratch_sid = _create_private_directory(
            parent,
            prefix="angerona-publish-state-",
        )
        if scratch_sid != current_sid:
            raise WindowsRuntimeError("private publication scratch owner changed")
        scratch_handle = _open_handle(
            scratch_root,
            directory=True,
            share_write=True,
            acl_control=True,
        )
        scratch_identity = _handle_identity(scratch_handle)
        for relative in active_profile.directories:
            (stage_root / Path(*PurePosixPath(relative).parts)).mkdir(exist_ok=False)

        copied = hashlib.sha256(b"angerona.publication-runtime-copy/v1\0")
        for group in source_groups.values():
            records = tuple(sorted(group.records, key=lambda item: item.relative))
            if len(records) == 1:
                record = records[0]
                destination_digest = _copy_from_handle(
                    group.handle,
                    stage_root / Path(*PurePosixPath(record.relative).parts),
                    record,
                )
            else:
                destination_digest = _copy_hardlink_group_from_handle(
                    group.handle,
                    tuple(
                        (
                            stage_root / Path(*PurePosixPath(record.relative).parts),
                            record,
                        )
                        for record in records
                    ),
                )
            if destination_digest != records[0].sha256:
                raise WindowsRuntimeError(
                    "publication runtime source digest mismatch: "
                    + ", ".join(record.relative for record in records)
                )
            for record in records:
                copied.update(record.relative.encode("utf-8"))
                copied.update(b"\0")
                copied.update(destination_digest.encode("ascii"))
                copied.update(b"\0")

        stage_file_handles: dict[str, tuple[int, _HandleIdentity]] = {}
        stage_directory_handles: dict[str, tuple[int, _HandleIdentity]] = {}
        try:
            for record in active_profile.files:
                path = stage_root / Path(*PurePosixPath(record.relative).parts)
                handle = _open_handle(
                    path,
                    directory=False,
                    share_delete=True,
                    acl_control=True,
                )
                identity = _handle_identity(handle)
                if (
                    identity.size != record.size
                    or identity.links != 1
                    or identity.attributes & _WINDOWS_REPARSE
                    or _hash_handle(handle, record.size) != record.sha256
                ):
                    _close_handle(handle)
                    raise WindowsRuntimeError(
                        f"private publication runtime verification failed: {record.relative}"
                    )
                stage_file_handles[record.relative] = (handle, identity)
            all_directories = [".", *active_profile.directories]
            for relative in sorted(
                all_directories,
                key=lambda item: (-item.count("/"), item),
            ):
                path = stage_root if relative == "." else (
                    stage_root / Path(*PurePosixPath(relative).parts)
                )
                handle = _open_handle(
                    path,
                    directory=True,
                    share_delete=True,
                    acl_control=True,
                )
                identity = _handle_identity(handle)
                if identity.attributes & _WINDOWS_REPARSE:
                    _close_handle(handle)
                    raise WindowsRuntimeError(
                        f"private publication runtime directory is an alias: {relative}"
                    )
                stage_directory_handles[relative] = (handle, identity)
            for handle, _identity in stage_file_handles.values():
                _set_handle_private_acl(handle, current_sid, writable=False)
            for handle, _identity in stage_directory_handles.values():
                _set_handle_private_acl(handle, current_sid, writable=False)
            _assert_private_directory_acl(
                stage_root,
                current_sid,
                writable=False,
            )
            _revalidate_source_groups(source_groups, source_root, profile_files)
            for relative, (handle, expected) in source_directories.items():
                actual = _handle_identity(handle)
                if actual != expected or actual.attributes & _WINDOWS_REPARSE:
                    raise WindowsRuntimeError(
                        f"publication runtime source directory changed: {relative}"
                    )
            if profile_seal is not None:
                profile_seal.revalidate()
            runtime = StagedWindowsRuntime(
                root=stage_root,
                scratch_root=scratch_root,
                scratch_handle=scratch_handle,
                scratch_identity=scratch_identity,
                parent_handle=parent_handle,
                file_handles=stage_file_handles,
                directory_handles=stage_directory_handles,
                profile=active_profile,
                current_sid=current_sid,
            )
            parent_handle = 0
            scratch_handle = 0
            runtime.revalidate()
            stage_root = None
            scratch_root = None
            return runtime
        except Exception:
            for handle, _identity in stage_file_handles.values():
                try:
                    _set_handle_private_acl(handle, current_sid, writable=True)
                except WindowsRuntimeError:
                    pass
                _close_handle(handle)
            for handle, _identity in stage_directory_handles.values():
                try:
                    _set_handle_private_acl(handle, current_sid, writable=True)
                except WindowsRuntimeError:
                    pass
                _close_handle(handle)
            raise
    finally:
        for group in source_groups.values():
            _close_handle(group.handle)
        for handle, _identity in source_directories.values():
            _close_handle(handle)
        if profile_seal is not None:
            profile_seal.close()
        if parent_handle:
            _close_handle(parent_handle)
        if scratch_handle:
            _close_handle(scratch_handle)
        # Failure cleanup is deliberately pathname-bounded to the exact random
        # child created by this call.  Successful cleanup uses retained handles.
        if stage_root is not None and stage_root.exists():
            try:
                for path in sorted(
                    stage_root.rglob("*"),
                    key=lambda item: (-len(item.parts), str(item)),
                ):
                    if path.is_file() and not path.is_symlink():
                        path.unlink()
                    elif path.is_dir() and not path.is_symlink():
                        path.rmdir()
                stage_root.rmdir()
            except OSError:
                pass
        if scratch_root is not None and scratch_root.exists():
            try:
                _remove_private_scratch(scratch_root)
            except WindowsRuntimeError:
                pass
