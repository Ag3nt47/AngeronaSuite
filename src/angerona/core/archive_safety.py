"""Shared fail-closed validation for locally consumed ZIP archives."""
from __future__ import annotations

import stat
import unicodedata
import zipfile
from pathlib import PurePosixPath
from typing import Iterable

_WINDOWS_DEVICES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_WINDOWS_FORBIDDEN = set('<>:"|?*')
_SUPPORTED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


def safe_archive_path(name: str, *, allow_directory: bool = False) -> PurePosixPath:
    """Return a portable relative path or reject aliases and traversal."""
    if not isinstance(name, str) or not name or len(name) > 1024:
        raise ValueError("archive path must be a bounded string")
    if name != unicodedata.normalize("NFC", name):
        raise ValueError("archive path must use canonical Unicode")
    if "\\" in name or "\x00" in name:
        raise ValueError("unsafe archive path")
    directory = name.endswith("/")
    value = name[:-1] if directory else name
    if not value or (directory and not allow_directory):
        raise ValueError("unexpected archive directory")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or len(path.parts) > 32
        or path.as_posix() != value
    ):
        raise ValueError("unsafe archive path")
    for part in path.parts:
        if part in {"", ".", ".."} or part.endswith((" ", ".")):
            raise ValueError("unsafe archive path")
        if any(ord(char) < 32 or ord(char) == 127 for char in part):
            raise ValueError("unsafe archive path")
        if any(char in _WINDOWS_FORBIDDEN for char in part):
            raise ValueError("unsafe archive path")
        if part.split(".", 1)[0].upper() in _WINDOWS_DEVICES:
            raise ValueError("unsafe archive path")
    return path


def validate_zip_members(
    infos: Iterable[zipfile.ZipInfo],
    *,
    max_files: int,
    max_member_bytes: int,
    max_total_bytes: int,
    max_ratio: int,
    allow_directories: bool = False,
) -> tuple[zipfile.ZipInfo, ...]:
    """Validate ZIP metadata before any member is read or extracted."""
    accepted = tuple(infos)
    if len(accepted) > max_files:
        raise ValueError("archive has too many entries")
    identities: set[str] = set()
    total = 0
    for member in accepted:
        path = safe_archive_path(
            member.filename,
            allow_directory=allow_directories,
        )
        identity = path.as_posix().casefold()
        if identity in identities:
            raise ValueError("archive has duplicate or colliding entries")
        identities.add(identity)
        if member.flag_bits & 0x1:
            raise ValueError("encrypted archive members are unsupported")
        if member.compress_type not in _SUPPORTED_COMPRESSION:
            raise ValueError("unsupported archive compression")
        mode = (member.external_attr >> 16) & 0o170000
        expected_mode = stat.S_IFDIR if member.is_dir() else stat.S_IFREG
        if mode not in {0, expected_mode}:
            raise ValueError("archive contains a special file")
        if member.file_size < 0 or member.compress_size < 0:
            raise ValueError("invalid archive member size")
        if member.file_size > max_member_bytes:
            raise ValueError("archive member exceeds size bound")
        total += member.file_size
        if total > max_total_bytes:
            raise ValueError("archive exceeds total size bound")
        if member.file_size and member.compress_size == 0:
            raise ValueError("invalid compressed size")
        if (
            member.compress_size
            and member.file_size / member.compress_size > max_ratio
        ):
            raise ValueError("archive compression ratio exceeds bound")
    return accepted


def read_bounded_member(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    *,
    max_bytes: int,
) -> bytes:
    """Read one validated member while enforcing its real expanded size."""
    if member.file_size > max_bytes:
        raise ValueError("archive member exceeds size bound")
    chunks: list[bytes] = []
    total = 0
    with archive.open(member) as stream:
        while chunk := stream.read(min(1024 * 1024, max_bytes + 1 - total)):
            total += len(chunk)
            if total > max_bytes or total > member.file_size:
                raise ValueError("expanded archive member exceeds size bound")
            chunks.append(chunk)
    if total != member.file_size:
        raise ValueError("archive member size mismatch")
    return b"".join(chunks)
