"""Integrity gates for executables launched by a frozen Angerona process."""
from __future__ import annotations

import hashlib
import hmac
import os
import stat
import subprocess
import sys
from pathlib import Path


def _is_reparse_point(path: Path) -> bool:
    try:
        attrs = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError:
        return True


def verify_blackbox_sidecar(path: Path, expected: str | None = None) -> bool:
    """Return true only for the exact Black Box executable embedded at build.

    A frozen elevated process must never execute a replaceable, merely
    same-named sidecar. The expected SHA-256 is compiled into the main one-file
    executable by the release workflow.
    """
    if expected is None:
        from angerona._release_integrity import BLACKBOX_SHA256
        expected = BLACKBOX_SHA256
    expected = expected.strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        return False
    try:
        if not path.is_file() or path.is_symlink() or _is_reparse_point(path):
            return False
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return hmac.compare_digest(digest.hexdigest(), expected)
    except OSError:
        return False


def _acl_blocks_unprivileged_writes(path: Path) -> bool:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    powershell = (system_root / "System32" / "WindowsPowerShell" /
                  "v1.0" / "powershell.exe")
    if not powershell.is_file():
        return False
    script = (
        "$a=Get-Acl -LiteralPath $env:ANGERONA_RELEASE_PATH; "
        "$o=(New-Object Security.Principal.NTAccount($a.Owner)).Translate("
        "[Security.Principal.SecurityIdentifier]).Value; "
        "$danger=[Security.AccessControl.FileSystemRights]::WriteData -bor "
        "[Security.AccessControl.FileSystemRights]::AppendData -bor "
        "[Security.AccessControl.FileSystemRights]::WriteAttributes -bor "
        "[Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor "
        "[Security.AccessControl.FileSystemRights]::Delete -bor "
        "[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor "
        "[Security.AccessControl.FileSystemRights]::ChangePermissions -bor "
        "[Security.AccessControl.FileSystemRights]::TakeOwnership; "
        "$bad=@($a.Access|Where-Object {$_.AccessControlType -eq 'Allow' -and "
        "$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value "
        "-notin @('S-1-5-18','S-1-5-32-544') -and "
        "(($_.FileSystemRights -band $danger) -ne 0)}); "
        "if ($o -notin @('S-1-5-18','S-1-5-32-544') -or $bad.Count) {exit 1}; exit 0"
    )
    env = os.environ.copy()
    env["ANGERONA_RELEASE_PATH"] = str(path)
    try:
        result = subprocess.run(
            [str(powershell), "-NoProfile", "-Command", script], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def verify_frozen_blackbox(path: Path) -> bool:
    """Verify protected location plus the build-embedded sidecar digest."""
    if not sys.platform.startswith("win") or not getattr(sys, "frozen", False):
        return False
    try:
        executable = Path(sys.executable).resolve(strict=True)
        sidecar = path.resolve(strict=True)
        root = executable.parent
        program_files = Path(os.environ["ProgramFiles"]).resolve(strict=True)
        if sidecar.parent != root or not root.is_relative_to(program_files):
            return False
        if any(_is_reparse_point(p) for p in (root, executable, sidecar)):
            return False
        if not (_acl_blocks_unprivileged_writes(root)
                and _acl_blocks_unprivileged_writes(executable)
                and _acl_blocks_unprivileged_writes(sidecar)):
            return False
    except (KeyError, OSError, RuntimeError):
        return False
    return verify_blackbox_sidecar(sidecar)
