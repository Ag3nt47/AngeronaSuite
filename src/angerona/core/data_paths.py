"""Canonical runtime locations for source and packaged Angerona installs."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import ctypes
import threading
from functools import lru_cache
from pathlib import Path


_hardened_roots: set[str] = set()
_ready_source_roots: set[str] = set()
_data_path_lock = threading.RLock()


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError:
        return False


def _fixed_volume_available(root: Path) -> bool:
    """True only for an existing, non-reparse Windows fixed-volume root."""
    if not sys.platform.startswith("win"):
        return False
    try:
        if not root.is_dir() or _is_reparse_point(root):
            return False
        get_drive_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        return get_drive_type(str(root)) == 3  # DRIVE_FIXED
    except (OSError, AttributeError):
        return False


def _frozen_default_data_root() -> Path:
    """Return the platform-native persistent state root for a frozen build."""
    if not sys.platform.startswith("win"):
        return _posix_default_data_root()
    drive = os.environ.get("ANGERONA_DATA_DRIVE", "D:").strip().upper()
    if len(drive) == 2 and drive[0].isalpha() and drive[1] == ":":
        preferred = Path(drive + "\\")
        if _fixed_volume_available(preferred):
            return preferred / "AngeronaData"
    program_data = Path(os.environ.get("PROGRAMDATA", str(project_root())))
    return program_data / "Angerona"


def _posix_default_data_root() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Angerona"
    configured = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(configured).expanduser() if configured else Path.home() / ".local" / "state"
    if not base.is_absolute():
        base = Path.home() / ".local" / "state"
    return base / "angerona"


def _harden_posix_data_root(path: Path) -> None:
    """Require a current-user-owned, non-symlink state directory with mode 0700."""
    if sys.platform.startswith("win"):
        return
    try:
        if path.is_symlink() or not path.is_dir():
            raise PermissionError(f"Refusing unsafe Angerona data directory: {path}")
        info = path.stat()
        getuid = getattr(os, "geteuid", None)
        if callable(getuid) and info.st_uid != getuid():
            raise PermissionError(
                f"Angerona data directory is owned by another account: {path}"
            )
        if stat.S_IMODE(info.st_mode) != 0o700:
            os.chmod(path, 0o700)
        if stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise PermissionError(f"Could not protect Angerona data directory: {path}")
    except OSError as exc:
        raise PermissionError(f"Could not verify Angerona data directory: {path}") from exc


def _create_admin_directory_atomic(path: Path) -> bool:
    """Create one Windows directory with an admin/SYSTEM-only DACL atomically."""
    if not sys.platform.startswith("win"):
        path.mkdir()
        return True

    from ctypes import wintypes

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD),
                    ("lpSecurityDescriptor", wintypes.LPVOID),
                    ("bInheritHandle", wintypes.BOOL)]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    descriptor = wintypes.LPVOID()
    # Owner/group = Administrators; protected DACL; full control to SYSTEM/admins.
    sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                        ctypes.POINTER(wintypes.LPVOID), wintypes.LPVOID]
    convert.restype = wintypes.BOOL
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attrs = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
        create = kernel.CreateDirectoryW
        create.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SECURITY_ATTRIBUTES)]
        create.restype = wintypes.BOOL
        if create(str(path), ctypes.byref(attrs)):
            return True
        error = ctypes.get_last_error()
        if error == 183:  # ERROR_ALREADY_EXISTS: caller must distrust then verify.
            return False
        raise ctypes.WinError(error)
    finally:
        kernel.LocalFree(descriptor)


def _admin_acl_valid(path: Path) -> bool:
    """Verify owner and every DACL identity without interpolating the path."""
    from angerona.core.privilege import (
        sanitized_child_environment,
        trusted_powershell_path,
    )

    try:
        powershell = trusted_powershell_path()
    except OSError:
        return False
    if not powershell.is_file():
        return False
    script = (
        "$a=Get-Acl -LiteralPath $env:ANGERONA_ACL_PATH; "
        "$o=(New-Object Security.Principal.NTAccount($a.Owner)).Translate("
        "[Security.Principal.SecurityIdentifier]).Value; "
        "$bad=@($a.Access|Where-Object {"
        "$_.AccessControlType -ne 'Allow' -or "
        "$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value "
        "-notin @('S-1-5-18','S-1-5-32-544')}); "
        "if ($o -notin @('S-1-5-18','S-1-5-32-544') -or $bad.Count -ne 0 "
        "-or $a.Access.Count -lt 2) {exit 1}; exit 0"
    )
    env = sanitized_child_environment({"ANGERONA_ACL_PATH": str(path)})
    result = subprocess.run([str(powershell), "-NoProfile", "-Command", script],
                            env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=20, check=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return result.returncode == 0


def _harden_frozen_data_root(path: Path, existed: bool) -> None:
    """Refuse a pre-created packaged data root and apply an admin-only ACL."""
    if not sys.platform.startswith("win"):
        return
    key = str(path).casefold()
    if key in _hardened_roots:
        return
    trusted = _admin_acl_valid(path)
    if existed and not trusted:
        raise PermissionError(
            f"Refusing untrusted pre-existing Angerona data directory: {path}. "
            "Rename it and relaunch so Angerona can create a private directory."
        )
    if not trusted or _is_reparse_point(path):
        raise PermissionError("Packaged data-directory trust verification failed")
    _hardened_roots.add(key)


def _elevated_source_runtime() -> bool:
    """Return whether this is an elevated, non-frozen Windows source runtime.

    This decision is made after elevation from the effective process token.  A
    launcher-supplied environment flag is not authority: the privileged
    bootstrap intentionally deletes every such inherited flag.
    """
    if not sys.platform.startswith("win") or getattr(sys, "frozen", False):
        return False
    try:
        from angerona.core.privilege import is_admin

        return bool(is_admin())
    except (ImportError, OSError):
        return False


def _canonical_source_data_root() -> Path:
    """Derive the source runtime root from this installed module, never env."""
    return Path(__file__).resolve().parents[3].parent / "AngeronaData"


def _verify_protected_source_data_root(path: Path) -> None:
    """Enforce post-elevation custody for an elevated source install.

    The source launcher protects ``AngeronaData`` before Python starts.  Keep
    that boundary fail-closed in the application too: bypassing the launcher
    while requesting elevated key custody must not silently downgrade the
    journal, cursor, and signing-key directory to an inherited user-writable
    ACL.
    """
    if not sys.platform.startswith("win"):
        return
    if not _elevated_source_runtime():
        return
    key = str(path).casefold()
    if key in _hardened_roots:
        return
    if _is_reparse_point(path) or not _admin_acl_valid(path):
        raise PermissionError(
            "Elevated source runtime storage is not protected by an "
            f"Administrators/SYSTEM-only ACL: {path}. Start Angerona through "
            "the guarded launcher so key custody can be established first."
        )
    _hardened_roots.add(key)


def project_root() -> Path:
    override = os.environ.get("ANGERONA_HOME", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[3]


def resource_root() -> Path:
    """Root containing read-only files bundled by the packager."""
    bundle = getattr(sys, "_MEIPASS", "")
    return Path(bundle).resolve() if bundle else project_root()


@lru_cache(maxsize=32)
def _canonical_data_path(
    configured: str,
    frozen: bool,
    _home: str,
    _data_drive: str,
    _program_data: str,
    _executable: str,
    _cwd: str,
    _xdg_state_home: str,
    _user_home: str,
) -> Path:
    """Resolve the runtime root once per effective environment.

    ``Path.resolve()`` calls the filesystem and was previously executed by every
    dashboard refresh and queue read. Under scanner I/O pressure a single call
    blocked the Qt thread for several seconds. The environment fields are part of
    the cache key so tests, portable installs, and operator overrides stay correct.
    """
    if configured:
        path = Path(configured).expanduser()
    elif frozen:
        path = _frozen_default_data_root()
    else:
        # Keep mutable state outside the Git checkout. Windows source installs
        # preserve the suite's D:-drive boundary; POSIX installs follow the XDG
        # state directory or macOS Application Support convention.
        path = (
            project_root().parent / "AngeronaData"
            if sys.platform.startswith("win")
            else _posix_default_data_root()
        )
    if frozen:
        return Path(os.path.abspath(path))
    return path.resolve()


def data_dir(create: bool = True) -> Path:
    """Return the sole persistent runtime root.

    Windows source installs use a sibling ``AngeronaData`` directory (D: in
    this workspace); frozen Windows releases prefer protected
    ``D:\\AngeronaData``. Linux follows ``XDG_STATE_HOME`` and macOS uses the
    current user's Application Support directory. ``ANGERONA_DATA`` remains an
    explicit override on every platform.
    """
    frozen = getattr(sys, "frozen", False)
    elevated_source = _elevated_source_runtime()
    # An elevated source process derives its key-custody root from the loaded
    # package location.  Neither ANGERONA_DATA nor ANGERONA_HOME may redirect
    # the privileged journal/signing-key root after bootstrap sanitization.
    configured = (
        str(_canonical_source_data_root())
        if elevated_source
        else os.environ.get("ANGERONA_DATA", "").strip()
    )
    path = _canonical_data_path(
        configured,
        frozen,
        os.environ.get("ANGERONA_HOME", ""),
        os.environ.get("ANGERONA_DATA_DRIVE", "D:"),
        os.environ.get("PROGRAMDATA", ""),
        sys.executable,
        os.getcwd(),
        os.environ.get("XDG_STATE_HOME", ""),
        str(Path.home()),
    )
    if frozen and str(path).casefold().startswith("d:\\"):
        # Relocate any legacy per-user C: spill into the canonical fixed data
        # drive on the Storage Hygiene module's first pass (collision-safe).
        os.environ.setdefault("ANGERONA_STORAGE_AUTOMIGRATE", "1")
    if frozen and sys.platform.startswith("win"):
        if not path.parent.is_dir() or _is_reparse_point(path.parent):
            raise PermissionError(f"Refusing unsafe Angerona data parent: {path.parent}")
        if create:
            created = _create_admin_directory_atomic(path)
            existed = not created
            if not path.is_dir() or _is_reparse_point(path):
                raise PermissionError(f"Refusing unsafe Angerona data directory: {path}")
            path = path.resolve(strict=True)
        else:
            existed = path.exists()
            if existed:
                if not path.is_dir() or _is_reparse_point(path):
                    raise PermissionError(f"Refusing unsafe Angerona data directory: {path}")
                path = path.resolve(strict=True)
    elif frozen:
        existed = path.exists()
        if create:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if path.is_symlink():
                raise PermissionError(f"Refusing unsafe Angerona data directory: {path}")
            path.mkdir(mode=0o700, exist_ok=True)
            path = path.resolve(strict=True)
        elif existed:
            if path.is_symlink() or not path.is_dir():
                raise PermissionError(f"Refusing unsafe Angerona data directory: {path}")
            path = path.resolve(strict=True)
    else:
        existed = False
    if elevated_source:
        os.environ["ANGERONA_DATA"] = str(path)
    else:
        os.environ.setdefault("ANGERONA_DATA", str(path))
    if create:
        if not frozen:
            key = str(path).casefold()
            if key not in _ready_source_roots:
                with _data_path_lock:
                    if key not in _ready_source_roots:
                        path.mkdir(parents=True, exist_ok=True)
                        if sys.platform.startswith("win"):
                            _verify_protected_source_data_root(path)
                        else:
                            _harden_posix_data_root(path)
                        _ready_source_roots.add(key)
        else:
            if sys.platform.startswith("win"):
                _harden_frozen_data_root(path, existed)
            else:
                _harden_posix_data_root(path)
    return path


def runtime_temp_dir(create: bool = True) -> Path:
    path = data_dir(create=create) / "tmp"
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not sys.platform.startswith("win"):
            os.chmod(path, 0o700)
    return path


def configure_runtime_environment() -> Path:
    """Pin app data, diagnostics, and inherited temp files to the canonical root."""
    root = data_dir()
    tmp = runtime_temp_dir()
    os.environ.setdefault("ANGERONA_DIAG_DIR", str(root / "diagnostics"))
    os.environ["TEMP"] = str(tmp)
    os.environ["TMP"] = str(tmp)
    return root
