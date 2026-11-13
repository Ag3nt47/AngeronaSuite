"""Snapshot admission for Ollama's model-data directory; never create or rewrite it.

Windows admission requires an explicit fixed local drive and plain directory
ancestors. A missing suffix may be created later by the separately owned daemon.
These metadata observations are not a retained directory lease and cannot defeat
later same-user replacement. POSIX checks reject redirection and UNC-like names;
there is no portable fixed-mount/NFS attestation in this helper.
"""
from __future__ import annotations

import os
import re
import stat
import sys


class ModelDirectoryError(ValueError):
    """The requested model storage could not be admitted without a fallback."""


_MAX_PATH = 4096
_MAX_COMPONENTS = 128
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_RESERVED = {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}


def _direct_volume_mapping(targets: tuple[str, ...]) -> bool:
    return (len(targets) == 1 and type(targets[0]) is str
            and re.fullmatch(r"\\Device\\HarddiskVolume[0-9]+", targets[0], re.IGNORECASE) is not None)


def _windows_fixed_drive(anchor: str) -> bool:
    """Require a fixed drive and one direct volume mapping, excluding SUBST."""
    try:
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_type = kernel.GetDriveTypeW
        get_type.argtypes = [wintypes.LPCWSTR]
        get_type.restype = wintypes.UINT
        if int(get_type(anchor)) != 3:  # DRIVE_FIXED
            return False
        query = kernel.QueryDosDeviceW
        query.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        query.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(4096)
        count = int(query(anchor[:2], buffer, len(buffer)))
        if not 0 < count < len(buffer):
            return False
        targets = tuple(part for part in buffer[:count].split("\0") if part)
        return _direct_volume_mapping(targets)
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _lstat(path_text: str):
    return os.lstat(path_text)


def _windows_chain(value: str) -> list[str]:
    text = value.replace("/", "\\")
    if re.fullmatch(r"[A-Za-z]:\\[^<>:\"|?*]*", text) is None:
        raise ModelDirectoryError("OLLAMA_MODELS requires an ordinary absolute local-drive path.")
    anchor = text[:3]
    parts = text[3:].split("\\") if len(text) > 3 else []
    if len(parts) > _MAX_COMPONENTS:
        raise ModelDirectoryError("OLLAMA_MODELS has too many path components to verify.")
    for part in parts:
        stem = part.split(".", 1)[0].rstrip(" ").upper()
        if (not part or part in {".", ".."} or part != part.strip()
                or part.endswith(".") or stem in _RESERVED
                or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem)):
            raise ModelDirectoryError("OLLAMA_MODELS contains an ambiguous or reserved path component.")
    if not _windows_fixed_drive(anchor):
        raise ModelDirectoryError("OLLAMA_MODELS must be on a verified fixed local drive.")
    chain = [anchor]
    for part in parts:
        chain.append(chain[-1] + ("" if chain[-1].endswith("\\") else "\\") + part)
    return chain


def _posix_chain(value: str) -> list[str]:
    if not value.startswith("/") or value.startswith("//"):
        raise ModelDirectoryError("OLLAMA_MODELS requires an ordinary absolute local path.")
    parts = value[1:].split("/") if len(value) > 1 else []
    if len(parts) > _MAX_COMPONENTS:
        raise ModelDirectoryError("OLLAMA_MODELS has too many path components to verify.")
    if any(not part or part in {".", ".."} for part in parts):
        raise ModelDirectoryError("OLLAMA_MODELS contains noncanonical path components.")
    chain = ["/"]
    for part in parts:
        chain.append(chain[-1].rstrip("/") + "/" + part)
    return chain


def validate_model_directory(value: object) -> str:
    """Return the accepted spelling, or visibly reject the explicit setting.

    No directory is created, resolved through a link, substituted, persisted or
    taken from the ambient environment. Existing ancestors must all be ordinary
    directories. A missing suffix needs an already verified existing ancestor.
    """
    if (type(value) is not str or not 1 <= len(value) <= _MAX_PATH
            or value != value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ModelDirectoryError("OLLAMA_MODELS is empty, oversized or contains unsafe characters.")
    chain = _windows_chain(value) if sys.platform == "win32" else _posix_chain(value)
    existing = False
    for path_text in chain:
        try:
            info = _lstat(path_text)
        except FileNotFoundError:
            if not existing:
                raise ModelDirectoryError("OLLAMA_MODELS has no verified existing local ancestor.")
            # The full suffix is lexically checked, but remains unobserved. Do
            # not follow a concurrently created junction beneath a missing node.
            break
        except (OSError, TypeError, ValueError) as exc:
            raise ModelDirectoryError("OLLAMA_MODELS directory custody is unavailable; review the setting.") from exc
        try:
            unsafe = (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                      or bool(int(getattr(info, "st_file_attributes", 0)) & _REPARSE))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ModelDirectoryError("OLLAMA_MODELS directory metadata is unavailable.") from exc
        if unsafe:
            raise ModelDirectoryError("OLLAMA_MODELS traverses a link, reparse point or non-directory.")
        existing = True
    if not existing:
        raise ModelDirectoryError("OLLAMA_MODELS has no verified existing local ancestor.")
    return value


def default_model_directory(sanitized_environment: dict[str, str]) -> str:
    """Validate Ollama's conventional data path under an already sanitized home.

    The caller supplies trusted OS-derived environment values; this function
    neither reads HOME/USERPROFILE itself nor changes the saved preference.
    """
    if type(sanitized_environment) is not dict:
        raise ModelDirectoryError("The sanitized model-storage environment is unavailable.")
    windows = sys.platform == "win32"
    profile = sanitized_environment.get("USERPROFILE" if windows else "HOME")
    base = validate_model_directory(profile)
    separator = "\\" if windows else "/"
    target = base.rstrip("\\/" if windows else "/") + separator + ".ollama" + separator + "models"
    return validate_model_directory(target)
