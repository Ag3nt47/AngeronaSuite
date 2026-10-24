"""Fail-closed Linux Secret Service adapter using libsecret's secret-tool.

No secret is passed on the command line.  ``secret-tool store`` receives the
bounded JSON value on stdin and the desktop's Secret Service decides where the
encrypted item lives.  Headless hosts without an unlocked Secret Service remain
supported through environment/systemd credentials, but the UI refuses to write
plaintext secrets to disk.
"""
from __future__ import annotations

import os
import re
import selectors
import shutil
import subprocess
import time
from pathlib import Path


_METADATA_LIMIT = 2048
_METADATA_TIMEOUT_SECONDS = 5.0


class SecretServiceError(RuntimeError):
    pass


def _tool() -> str:
    executable = shutil.which("secret-tool")
    if not executable:
        raise SecretServiceError(
            "Linux Secret Service is unavailable (install libsecret-tools and unlock a keyring)"
        )
    return executable


def _metadata_probe(argv: list[str]) -> subprocess.CompletedProcess:
    """Bound both output streams and retire the exact owned metadata client."""
    process = None
    collected = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, close_fds=True)
        deadline = time.monotonic() + _METADATA_TIMEOUT_SECONDS
        for name in collected:
            selector.register(getattr(process, name), selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SecretServiceError("Linux Secret Service metadata lookup timed out")
            for key, _events in selector.select(remaining):
                target = collected[key.data]
                chunk = os.read(key.fd, _METADATA_LIMIT + 1 - len(target))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target.extend(chunk)
                if len(target) > _METADATA_LIMIT:
                    raise SecretServiceError("Linux Secret Service metadata output exceeded its bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SecretServiceError("Linux Secret Service metadata lookup timed out")
        code = process.wait(timeout=remaining)
        return subprocess.CompletedProcess(argv, code, bytes(collected["stdout"]), bytes(collected["stderr"]))
    finally:
        try:
            selector.close()
        finally:
            if process is not None:
                try:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=2)
                except (OSError, subprocess.SubprocessError) as exc:
                    raise SecretServiceError("Linux Secret Service metadata process retirement failed") from exc
                finally:
                    for name in collected:
                        stream = getattr(process, name)
                        if stream is not None:
                            stream.close()


def _native_service_backend() -> bool:
    # A direct session-bus search cannot speak for a portal/file/custom backend.
    return (os.environ.get("SECRET_BACKEND", "") in {"", "service"}
            and "SNAP_NAME" not in os.environ and not Path("/.flatpak-info").exists())


def _confirm_item_absent(service: str, account: str) -> None:
    """Search only item metadata; an empty lookup alone may mean locked."""
    if not _native_service_backend():
        raise SecretServiceError("Credential absence is unproven for this Linux backend")
    for value in (service, account):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value):
            raise SecretServiceError("Secret Service metadata identity is invalid")
    executable = shutil.which("gdbus")
    if not executable:
        raise SecretServiceError("Proving Linux credential absence requires gdbus (GLib tools)")
    attributes = "{'service': '" + service + "', 'account': '" + account + "'}"
    argv = [executable, "call", "--session", "--dest", "org.freedesktop.secrets",
            "--object-path", "/org/freedesktop/secrets", "--method",
            "org.freedesktop.Secret.Service.SearchItems", "--timeout", "3", attributes]
    try:
        result = _metadata_probe(argv)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecretServiceError("Linux Secret Service metadata lookup failed") from exc
    if (result.returncode != 0 or result.stderr != b""
            or result.stdout.strip() not in {b"(@ao [], @ao [])", b"([], [])"}):
        raise SecretServiceError("Linux credential absence is unproven; existing/locked items were not replaced")


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
        # The same empty result can describe an existing item that stayed
        # locked. Require a nonsecret metadata search proving both the locked
        # and unlocked result arrays are empty before permitting creation.
        if result.returncode == 1 and result.stdout == b"" and result.stderr == b"":
            _confirm_item_absent(service, account)
            return None
        raise SecretServiceError("Linux Secret Service lookup was rejected")
    value = result.stdout.rstrip(b"\r\n")
    if not value:
        raise SecretServiceError("Linux Secret Service lookup returned an empty success payload")
    return value


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

