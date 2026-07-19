"""Canonical runtime locations for source and packaged Angerona installs."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import ctypes
from pathlib import Path


_hardened_roots: set[str] = set()


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
    """Prefer the operator's fixed D: data volume, with a safe C: fallback."""
    drive = os.environ.get("ANGERONA_DATA_DRIVE", "D:").strip().upper()
    if len(drive) == 2 and drive[0].isalpha() and drive[1] == ":":
        preferred = Path(drive + "\\")
        if _fixed_volume_available(preferred):
            return preferred / "AngeronaData"
    program_data = Path(os.environ.get("PROGRAMDATA", str(project_root())))
    return program_data / "Angerona"


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
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
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
    env = os.environ.copy()
    env["ANGERONA_ACL_PATH"] = str(path)
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


def data_dir(create: bool = True) -> Path:
    """Return the sole persistent runtime root.

    Source installs use a sibling ``runtime-data`` directory (D: in this
    workspace). Frozen releases prefer protected ``D:\\AngeronaData`` on a
    fixed D: volume, with protected ProgramData as the no-D: fallback.
    ``ANGERONA_DATA`` remains an explicit override.
    """
    configured = os.environ.get("ANGERONA_DATA", "").strip()
    if configured:
        path = Path(configured).expanduser()
    elif getattr(sys, "frozen", False):
        # Packaged code may live under Program Files and must stay read-only.
        # Runtime state belongs on the fixed data drive where available; both
        # that root and the ProgramData fallback are created admin/SYSTEM-only.
        path = _frozen_default_data_root()
    else:
        path = project_root() / "runtime-data"
    frozen = getattr(sys, "frozen", False)
    if frozen and str(path).casefold().startswith("d:\\"):
        # Relocate any legacy per-user C: spill into the canonical fixed data
        # drive on the Storage Hygiene module's first pass (collision-safe).
        os.environ.setdefault("ANGERONA_STORAGE_AUTOMIGRATE", "1")
    if frozen:
        path = Path(os.path.abspath(path))
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
    else:
        path = path.resolve()
        existed = path.exists()
    os.environ.setdefault("ANGERONA_DATA", str(path))
    if create:
        if not frozen:
            path.mkdir(parents=True, exist_ok=True)
        else:
            _harden_frozen_data_root(path, existed)
    return path


def runtime_temp_dir(create: bool = True) -> Path:
    path = data_dir(create=create) / "tmp"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def configure_runtime_environment() -> Path:
    """Pin app data, diagnostics, and inherited temp files to the canonical root."""
    root = data_dir()
    tmp = runtime_temp_dir()
    os.environ.setdefault("ANGERONA_DIAG_DIR", str(root / "diagnostics"))
    os.environ["TEMP"] = str(tmp)
    os.environ["TMP"] = str(tmp)
    return root
