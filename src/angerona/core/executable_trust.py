"""Trust checks for privileged native sidecars."""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


def executable_is_trusted(path: str | os.PathLike) -> bool:
    candidate = Path(path)
    try:
        if not candidate.is_file() or candidate.is_symlink():
            return False
    except OSError:
        return False
    if os.name != "nt":
        try:
            return not bool(candidate.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH))
        except OSError:
            return False

    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe")
    if not powershell.is_file():
        return False
    env = os.environ.copy()
    env["ANGERONA_NATIVE_PATH"] = str(candidate.resolve())
    try:
        result = subprocess.run(
            [str(powershell), "-NoProfile", "-NonInteractive", "-Command",
             "if ((Get-AuthenticodeSignature -LiteralPath "
             "$env:ANGERONA_NATIVE_PATH).Status -eq 'Valid') {exit 0}; exit 1"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


__all__ = ["executable_is_trusted"]
