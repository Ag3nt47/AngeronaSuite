"""Bounded Windows install-tree custody observation for an Ollama executable.

The image, DLLs, runners and other existing install-tree objects must be ordinary
objects owned and writable only by SYSTEM, Administrators or TrustedInstaller.
Ancestors use the existing protection-service replacement policy: unrelated
create slots on a drive root do not grant authority to replace its existing
protected child. No interactive-user SID is enrolled, including an administrator
running with a medium-integrity token.

This is a snapshot, not a software/signature identity, loaded-DLL lifetime lease,
or defense against another administrator. It changes no ACL or package file.
The deadline is checked between native/filesystem calls; it cannot interrupt a
blocked Windows provider. Call off the GUI thread under the caller's own timeout.
"""
from __future__ import annotations

import math
import os
import re
import stat
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from angerona.core.windows_engine_custody import _descriptor, check_descriptor

_TRUSTED = frozenset({
    "S-1-5-18",  # SYSTEM
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller
})
_WRITE = (0x53000000 | 0x000D0000 | 0x00000156)
_REPLACE = (0x53000000 | 0x000D0040)
_REPARSE = 0x400
_DIRECTORY = 0x10
_MAX_ENTRIES = 512
_MAX_DEPTH = 8
_MAX_ANCESTORS = 64
_SECONDS = 2.0
_NATIVE_LOCK = threading.Lock()
_RETIREMENT_HOLD = None


@dataclass(frozen=True, slots=True)
class PackageCustody:
    accepted: bool
    reason: str
    entries: int = 0


class _Held(Exception):
    pass


def _is_windows() -> bool:
    return sys.platform == "win32"


def _ordinary_name(name: str) -> bool:
    if (not name or name in {".", ".."} or name.endswith((".", " "))
            or any(char in '<>:"/\\|?*~' or ord(char) < 32 or ord(char) == 127 for char in name)):
        return False
    stem = name.split(".", 1)[0].upper()
    return not (stem in {"CON", "PRN", "AUX", "NUL"}
                or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem))


def _validate_image_path(image: Path) -> Path:
    """Pure lexical boundary; fake metadata tests replace it explicitly on POSIX."""
    value = os.fspath(image)
    if type(value) is not str or not value or len(value) > 32760:
        raise _Held("Ollama custody requires an explicit bounded local Windows image path")
    normalized = value.replace("/", "\\")
    parsed = PureWindowsPath(normalized)
    if (not parsed.is_absolute() or len(parsed.drive) != 2 or parsed.drive[1] != ":"
            or not parsed.drive[0].isascii() or not parsed.drive[0].isalpha()
            or not normalized.startswith(parsed.drive + "\\")
            or "\\\\" in normalized or ":" in normalized[2:]):
        raise _Held("Ollama custody refuses UNC, device, relative or aliased image paths")
    parts = normalized[3:].split("\\")
    if not parts or any(not _ordinary_name(part) for part in parts):
        raise _Held("Ollama custody refuses ambiguous or short-name image paths")
    if len(parsed.parents) > _MAX_ANCESTORS or parsed.parent == PureWindowsPath(parsed.anchor):
        raise _Held("Ollama custody requires a bounded dedicated installation directory")
    return Path(str(parsed))


def _fixed_local_drive(root: Path) -> bool:
    if not _is_windows():
        return False
    try:
        import win32file

        if win32file.GetDriveType(str(root)) != 3:  # DRIVE_FIXED
            return False
        mapping = win32file.QueryDosDevice(str(root)[:2])
        if type(mapping) is str:
            values = (mapping,)
        elif type(mapping) is tuple and 1 <= len(mapping) <= 16:
            values = mapping
        else:
            return False
        if any(type(item) is not str for item in values) or sum(map(len, values)) > 32768:
            return False
        devices = tuple(item for value in values for item in value.split("\0") if item)
        return (len(devices) == 1
                and re.fullmatch(r"\\Device\\HarddiskVolume[0-9]+", devices[0], re.IGNORECASE) is not None)
    except Exception:
        return False


def image_location_allowed(image: Path) -> bool:
    """Lexical/volume admission only, before any image/ancestor metadata query."""
    if not _is_windows():
        return False
    try:
        target = _validate_image_path(image)
        return _fixed_local_drive(Path(target.anchor)) is True
    except Exception:
        return False


def _handle_identity(info, directory: bool):
    if type(info) is not tuple or len(info) != 10:
        raise ValueError("Native package identity is unavailable")
    attributes, volume, links, high, low = info[0], info[4], info[7], info[8], info[9]
    if (any(type(value) is not int for value in (attributes, volume, links, high, low))
            or any(not 0 <= value <= 0xFFFFFFFF for value in (attributes, volume, high, low))
            or not (high or low)
            or attributes & _REPARSE or bool(attributes & _DIRECTORY) != directory
            or links < 1 or (not directory and links != 1)):
        raise ValueError("Native package object is redirected, linked or has the wrong type")
    return attributes, volume, links, high, low


def _native_custody(path: Path, directory: bool, *, ancestor: bool) -> bool:
    global _RETIREMENT_HOLD
    try:
        parsed = PureWindowsPath(os.fspath(path))
        if (not parsed.is_absolute() or len(parsed.drive) != 2 or parsed.drive[1] != ":"
                or not parsed.drive[0].isascii() or not parsed.drive[0].isalpha()
                or any(not _ordinary_name(part) for part in parsed.parts[1:])):
            return False
    except (TypeError, ValueError):
        return False
    if not _is_windows() or type(directory) is not bool or not _NATIVE_LOCK.acquire(blocking=False):
        return False
    try:
        if _RETIREMENT_HOLD is not None:
            return False
        handle = None
        accepted = False
        try:
            import win32file
            import win32security

            flags = 0x00200000 | (0x02000000 if directory else 0x80)
            handle = win32file.CreateFile(
                str(path), 0x00020080, 1, None, 3, flags, None,
            )  # READ_CONTROL | FILE_READ_ATTRIBUTES; share READ only; OPEN_EXISTING
            if win32file.GetFileType(handle) != 1:  # FILE_TYPE_DISK
                raise ValueError("Package object is not a disk file")
            identity = _handle_identity(win32file.GetFileInformationByHandle(handle), directory)
            descriptor = win32security.GetSecurityInfo(
                int(handle), win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
            )
            if not descriptor.GetSecurityDescriptorControl()[0] & 0x0004:  # SE_DACL_PRESENT
                raise ValueError("Package object has no explicit DACL observation")
            # The existing parser refuses NULL DACLs, unsupported ACEs and more
            # than 64 grants; the policy also refuses empty or untrusted owners.
            check_descriptor(
                _descriptor(descriptor), _TRUSTED,
                outside_allowed=0xFFFFFFFF ^ (_REPLACE if ancestor else _WRITE),
            )
            if _handle_identity(win32file.GetFileInformationByHandle(handle), directory) != identity:
                raise ValueError("Package object changed during its native observation")
            accepted = True
        except Exception:
            accepted = False
        finally:
            if handle is not None:
                try:
                    if handle.Close() is False:
                        raise OSError("Native package query retirement is unverified")
                except BaseException:
                    # Retain one exact owner, never retry a potentially reused
                    # numeric handle, and refuse further native allocations.
                    _RETIREMENT_HOLD = handle
                    accepted = False
        return accepted
    finally:
        _NATIVE_LOCK.release()


def _windows_object_custody(path: Path, directory: bool) -> bool:
    """Fakeable native seam: strict administrator-only writes on an install object."""
    return _native_custody(path, directory, ancestor=False)


def _windows_ancestor_custody(path: Path) -> bool:
    return _native_custody(path, True, ancestor=True)


def _metadata(path: Path, directory: bool, *, ancestor: bool = False) -> tuple:
    info = path.lstat()
    attributes = getattr(info, "st_file_attributes", 0)
    if (stat.S_ISLNK(info.st_mode) or attributes & _REPARSE
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        raise _Held("Ollama package contains a redirected, linked or unsupported object")
    # An unrelated create slot on an ancestor may legitimately change its size,
    # times or POSIX fixture link count. Bind that directory's identity/type,
    # while install-tree objects also retain the complete metadata observation.
    return (info.st_dev, info.st_ino, info.st_mode, 0 if ancestor else info.st_size,
            0 if ancestor else info.st_nlink, 0 if ancestor else info.st_mtime_ns,
            0 if ancestor else info.st_ctime_ns, attributes)


def assess_package(image: Path, *, deadline: float | None = None) -> PackageCustody:
    """Observe at most 512 unique objects, depth 8, with a two-second call budget.

    ``deadline`` is an absolute monotonic deadline and can shorten that budget.
    ``entries`` includes inspected ancestors, the install root and tree objects.
    No directory outside the image's installation tree is enumerated.
    """
    entries = 0
    try:
        if not _is_windows():
            raise _Held("Native Windows package custody is unavailable on this platform")
        started = time.monotonic()
        if not math.isfinite(started):
            raise _Held("Ollama package custody deadline is unavailable")
        if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)):
            raise _Held("Ollama package custody deadline is invalid")
        expires = min(started + _SECONDS, deadline) if deadline is not None else started + _SECONDS

        def budget():
            now = time.monotonic()
            if not math.isfinite(now) or now < started or now >= expires:
                raise _Held("Ollama package custody budget expired; snapshot is incomplete")

        budget()
        target = _validate_image_path(image)
        root = target.parent
        if not _fixed_local_drive(Path(target.anchor)):
            raise _Held("Ollama package custody requires an ordinary fixed local drive")
        budget()
        observations: dict[Path, tuple[tuple, bool]] = {}
        directories: dict[Path, frozenset[str]] = {}

        def observe(path: Path, directory: bool, *, ancestor: bool = False):
            nonlocal entries
            budget()
            if entries >= _MAX_ENTRIES:
                raise _Held("Ollama package custody entry limit reached; snapshot is incomplete")
            before = _metadata(path, directory, ancestor=ancestor)
            entries += 1
            trusted = (_windows_ancestor_custody(path) if ancestor
                       else _windows_object_custody(path, directory=directory))
            budget()
            if trusted is not True:
                raise _Held(
                    "Ollama package administrator-only write custody could not be verified; "
                    "use an administrator-owned installation instead of a writable per-user package"
                )
            if _metadata(path, directory, ancestor=ancestor) != before:
                raise _Held("Ollama package changed during custody observation")
            observations[path] = before, ancestor

        ancestors = tuple(root.parents)
        if len(ancestors) > _MAX_ANCESTORS:
            raise _Held("Ollama package ancestry exceeds the inspection limit")
        for parent in reversed(ancestors):
            observe(parent, True, ancestor=True)
        observe(root, True)
        observe(target, False)
        pending = [(root, 0)]
        found_image = False
        names_seen: set[str] = set()
        while pending:
            directory, depth = pending.pop()
            names = set()
            budget()
            with os.scandir(directory) as children:
                for child in children:
                    budget()
                    name = child.name
                    if not _ordinary_name(name) or name.casefold() in names:
                        raise _Held("Ollama package contains an ambiguous directory entry")
                    names.add(name.casefold())
                    path = directory / name
                    key = str(path).casefold()
                    if key in names_seen:
                        raise _Held("Ollama package directory topology is ambiguous")
                    names_seen.add(key)
                    if depth + 1 > _MAX_DEPTH:
                        raise _Held("Ollama package custody depth limit reached; snapshot is incomplete")
                    if path != target and entries >= _MAX_ENTRIES:
                        raise _Held("Ollama package custody entry limit reached; snapshot is incomplete")
                    info = path.lstat()
                    is_directory = stat.S_ISDIR(info.st_mode)
                    if path == target:
                        found_image = True
                        if _metadata(path, False) != observations[target][0]:
                            raise _Held("Ollama image changed during its package observation")
                    else:
                        observe(path, is_directory)
                    if is_directory:
                        pending.append((path, depth + 1))
            directories[directory] = frozenset(names)
        if not found_image:
            raise _Held("Ollama image was not present in the observed installation directory")
        # Recheck metadata and bounded names after enumeration; this is still a
        # snapshot and does not hold every object until a future DLL load.
        for path, (identity, ancestor) in observations.items():
            budget()
            if _metadata(path, stat.S_ISDIR(identity[2]), ancestor=ancestor) != identity:
                raise _Held("Ollama package changed before snapshot completion")
        for directory, expected in directories.items():
            seen = set()
            budget()
            with os.scandir(directory) as children:
                for child in children:
                    budget()
                    key = child.name.casefold()
                    if key not in expected or key in seen:
                        raise _Held("Ollama package directory changed before snapshot completion")
                    seen.add(key)
            if seen != expected:
                raise _Held("Ollama package directory changed before snapshot completion")
        budget()
        return PackageCustody(True, "Administrator-owned Ollama package snapshot verified", entries)
    except _Held as held:
        return PackageCustody(False, str(held), entries)
    except Exception:
        return PackageCustody(False, "Ollama package custody metadata or native provider is unavailable", entries)
