"""Fail-closed Linux Secret Service adapter using libsecret's secret-tool.

No secret is passed on the command line.  ``secret-tool store`` receives the
bounded JSON value on stdin and the desktop's Secret Service decides where the
encrypted item lives.  Headless hosts without an unlocked Secret Service remain
supported through environment/systemd credentials, but the UI refuses to write
plaintext secrets to disk.
"""
from __future__ import annotations

import shutil
import subprocess


class SecretServiceError(RuntimeError):
    pass


def _tool() -> str:
    executable = shutil.which("secret-tool")
    if not executable:
        raise SecretServiceError(
            "Linux Secret Service is unavailable (install libsecret-tools and unlock a keyring)"
        )
    return executable


def read_blob(service: str, account: str) -> bytes | None:
    try:
        result = subprocess.run(
            [_tool(), "lookup", "service", service, "account", account],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecretServiceError(f"Linux Secret Service lookup failed: {exc}") from exc
    if result.returncode != 0:
        # libsecret returns a miss as a non-zero result with no value.  Backend
        # failures normally include stderr and must not be confused with empty.
        if result.stderr.strip():
            raise SecretServiceError("Linux Secret Service lookup was rejected")
        return None
    return result.stdout.rstrip(b"\r\n") or None


def write_blob(service: str, account: str, payload: bytes) -> None:
    if not isinstance(payload, bytes) or not payload or len(payload) > 256 * 1024:
        raise SecretServiceError("secret payload must contain 1..262144 bytes")
    try:
        result = subprocess.run(
            [
                _tool(), "store", "--label=Angerona runtime secrets",
                "service", service, "account", account,
            ],
            input=payload,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecretServiceError(f"Linux Secret Service write failed: {exc}") from exc
    if result.returncode != 0:
        raise SecretServiceError("Linux Secret Service rejected the credential write")

