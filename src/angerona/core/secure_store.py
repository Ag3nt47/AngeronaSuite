"""OS-protected storage for Angerona credentials.

The UI needs a small persistent key/value store for optional provider tokens,
mail credentials, and connector secrets.  Keeping those values in a project
``.env`` file made them readable to every account that inherited access to the
checkout. Windows stores one current-user DPAPI blob under Angerona's
canonical runtime-data directory and applies a private ACL as a second layer. macOS stores
the same logical map as one current-user Keychain item.

Windows uses a current-user DPAPI blob with a private ACL. macOS uses one
generic-password item in the current user's Keychain through Security.framework.
Linux uses the current desktop session's Secret Service through libsecret's
``secret-tool`` without ever putting the secret on a command line.
Legacy ``.env`` files are migrated only after a protected write/read verification
succeeds; the plaintext source is then removed. Unsupported platforms fail closed
instead of silently creating another plaintext credential file.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path
from typing import Mapping

_ENTROPY = b"Angerona-SecretStore-v1"
_FILENAME = "secrets.dpapi"
_MACOS_REFERENCE_FILENAME = "secrets.keychain-reference"
_MACOS_KEYCHAIN_SERVICE = "org.angerona.security-suite"
_MACOS_KEYCHAIN_ACCOUNT = "runtime-secrets-v1"
_LINUX_REFERENCE_FILENAME = "secrets.secret-service-reference"
_LINUX_SECRET_SERVICE = "org.angerona.security-suite"
_LINUX_SECRET_ACCOUNT = "runtime-secrets-v1"
_NON_ENVIRONMENT_SECRETS = frozenset({
    "ANGERONA_USB_PIN",
    # This token authorizes a loopback control plane in an elevated process.
    # Consumers must read it directly from the OS-protected store so a launcher,
    # parent process, or stale shell can never inject control authority.
    "ANGERONA_JARVIS_CONTROL_TOKEN",
})
_MAX_LEGACY_ENV_BYTES = 1024 * 1024


def _remove_environment_secrets(keys) -> None:
    """Ensure protected values never become process-global child inheritance."""
    for key in keys:
        if isinstance(key, str) and key:
            os.environ.pop(key, None)


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _path_traverses_reparse(path: Path) -> bool:
    """Inspect every existing component without resolving through it."""
    current = Path(os.path.abspath(path))
    while True:
        if os.path.lexists(current) and _is_link_or_reparse(current):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _legacy_source_identity(path: Path) -> tuple[int, int, int, int, int] | None:
    """Return a stable identity only for a small, ordinary plaintext file."""
    if _path_traverses_reparse(path):
        return None
    try:
        info = path.lstat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_size > _MAX_LEGACY_ENV_BYTES
        or getattr(info, "st_nlink", 1) != 1
    ):
        return None
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def secure_store_path(data_root: Path | None = None) -> Path:
    if data_root is None:
        from angerona.core.data_paths import data_dir
        data_root = data_dir()
    if sys.platform == "darwin":
        filename = _MACOS_REFERENCE_FILENAME
    elif sys.platform.startswith("linux"):
        filename = _LINUX_REFERENCE_FILENAME
    else:
        filename = _FILENAME
    return Path(data_root) / filename


def _protect_bytes(data: bytes) -> bytes | None:
    from angerona.modules.hardware_crypto import protect
    return protect(data, _ENTROPY)


def _unprotect_bytes(blob: bytes) -> bytes | None:
    from angerona.modules.hardware_crypto import unprotect
    return unprotect(blob, _ENTROPY)


def _private_acl(path: Path) -> None:
    """Best-effort owner/SYSTEM/admin-only ACL; DPAPI remains the hard boundary."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if not sys.platform.startswith("win"):
        return
    try:
        user = os.environ.get("USERNAME", "").strip()
        domain = os.environ.get("USERDOMAIN", "").strip()
        principal = f"{domain}\\{user}" if domain and user else user
        if not principal:
            return
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        icacls = (system_root / "System32" / "icacls.exe").resolve()
        if not icacls.is_file():
            return
        subprocess.run(
            [str(icacls), str(path), "/inheritance:r", "/grant:r",
             f"{principal}:(F)", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _read_macos_secret_map(*, strict: bool = False) -> dict[str, str]:
    try:
        from angerona.platforms.macos.keychain import read_blob
        raw = read_blob(_MACOS_KEYCHAIN_SERVICE, _MACOS_KEYCHAIN_ACCOUNT)
        if raw is None:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in value.items()
        ):
            raise ValueError("Keychain secret map has an invalid shape")
        return dict(value)
    except (OSError, UnicodeError, ValueError, TypeError, RuntimeError) as exc:
        if strict:
            raise RuntimeError(
                "macOS Keychain secrets are unreadable; refusing to overwrite them"
            ) from exc
        return {}


def _read_linux_secret_map(*, strict: bool = False) -> dict[str, str]:
    try:
        from angerona.platforms.linux.secret_service import read_blob
        raw = read_blob(_LINUX_SECRET_SERVICE, _LINUX_SECRET_ACCOUNT)
        if raw is None:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in value.items()
        ):
            raise ValueError("Linux Secret Service map has an invalid shape")
        return dict(value)
    except (OSError, UnicodeError, ValueError, TypeError, RuntimeError) as exc:
        if strict:
            raise RuntimeError(
                "Linux Secret Service secrets are unreadable; refusing to overwrite them"
            ) from exc
        return {}


def read_secret_map(
    data_root: Path | None = None, *, strict: bool = False,
) -> dict[str, str]:
    if sys.platform == "darwin":
        return _read_macos_secret_map(strict=strict)
    if sys.platform.startswith("linux"):
        return _read_linux_secret_map(strict=strict)
    path = secure_store_path(data_root)
    if not path.exists():
        return {}
    try:
        raw = _unprotect_bytes(path.read_bytes())
        if raw is None:
            raise ValueError("protected credential payload could not be decrypted")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in value.items()
        ):
            raise ValueError("protected credential map has an invalid shape")
        return {
            key: item
            for key, item in value.items()
        }
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        if strict:
            raise RuntimeError(
                "Protected credentials are unreadable; refusing to overwrite them"
            ) from exc
        return {}


def read_secret_values(
    names,
    data_root: Path | None = None,
    *,
    strict: bool = False,
) -> dict[str, str]:
    """Return only explicitly named values from protected storage.

    The encrypted payload is one OS-protected map, but callers do not need to
    receive unrelated fleet, connector, or provider authority in their local
    scope. Requests are bounded and duplicate-free.
    """
    if isinstance(names, str):
        requested = (names,)
    else:
        requested = tuple(names)
    if not 1 <= len(requested) <= 64 or any(
        not isinstance(name, str)
        or not name
        or len(name) > 256
        or any(ord(character) < 33 or ord(character) == 127 for character in name)
        for name in requested
    ):
        raise ValueError("protected credential name request is invalid")
    if len(set(requested)) != len(requested):
        raise ValueError("protected credential name request contains duplicates")
    values = (
        read_secret_map(data_root, strict=True)
        if strict
        else read_secret_map(data_root)
    )
    return {name: values[name] for name in requested if name in values}


def write_secret_map(updates: Mapping[str, object], data_root: Path | None = None) -> Path:
    # Clear an inherited plaintext PIN even when this particular update does
    # not contain the PIN. It must only ever be read from protected storage.
    _remove_environment_secrets((*_NON_ENVIRONMENT_SECRETS, *updates))
    path = secure_store_path(data_root)
    values = (
        _read_macos_secret_map(strict=True)
        if sys.platform == "darwin"
        else _read_linux_secret_map(strict=True)
        if sys.platform.startswith("linux")
        else read_secret_map(data_root, strict=True)
    )
    removed: set[str] = set()
    for key, value in updates.items():
        key = str(key).strip()
        if not key:
            continue
        if value in (None, ""):
            values.pop(key, None)
            removed.add(key)
        else:
            values[key] = str(value)
    payload = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if sys.platform == "darwin":
        from angerona.platforms.macos.keychain import write_blob
        write_blob(_MACOS_KEYCHAIN_SERVICE, _MACOS_KEYCHAIN_ACCOUNT, payload)
        if _read_macos_secret_map(strict=True) != values:
            raise RuntimeError(
                "macOS Keychain verification failed; credentials were not accepted"
            )
        _remove_environment_secrets((*values, *removed))
        # Kept as a stable API return value; no secret is written at this path.
        return path
    if sys.platform.startswith("linux"):
        from angerona.platforms.linux.secret_service import write_blob
        write_blob(_LINUX_SECRET_SERVICE, _LINUX_SECRET_ACCOUNT, payload)
        if _read_linux_secret_map(strict=True) != values:
            raise RuntimeError(
                "Linux Secret Service verification failed; credentials were not accepted"
            )
        _remove_environment_secrets((*values, *removed))
        return path
    blob = _protect_bytes(payload)
    if blob is None:
        raise RuntimeError(
            "No supported OS credential store is available; credentials were not written"
        )
    # Verify before replacing the previous store.  A DPAPI or account-context
    # problem must never destroy the only readable credential copy.
    if _unprotect_bytes(blob) != payload:
        raise RuntimeError("DPAPI verification failed; credentials were not written")
    if _path_traverses_reparse(path.parent) or (
        os.path.lexists(path) and _is_link_or_reparse(path)
    ):
        raise RuntimeError(
            "Protected credential path traverses a link or reparse point; refusing to write"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    if _path_traverses_reparse(path.parent):
        raise RuntimeError(
            "Protected credential directory became unsafe; refusing to write"
        )
    descriptor: int | None = None
    tmp: Path | None = None
    try:
        # Never use a predictable PID-only temporary name here. Angerona may be
        # elevated while its data directory is writable by the desktop user; an
        # attacker must not be able to pre-place a link and redirect a secret
        # store write into an arbitrary file.
        for _ in range(16):
            candidate = path.with_name(
                f".{path.name}.{secrets.token_hex(12)}.tmp"
            )
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_BINARY", 0),
                    0o600,
                )
                tmp = candidate
                break
            except FileExistsError:
                continue
        if descriptor is None or tmp is None:
            raise RuntimeError("could not allocate a private credential temp file")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        _private_acl(tmp)
        os.replace(tmp, path)
        _private_acl(path)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
        except OSError:
            pass
    _remove_environment_secrets((*values, *removed))
    return path


def parse_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return out
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            out[key] = value.strip()
    return out


def load_into_environment(data_root: Path | None = None) -> None:
    """Scrub protected names from the environment without publishing values.

    Historical callers retain this startup hook, but consumers now retrieve
    only the exact credential they need from the protected store.  This keeps
    optional provider and mail functionality while preventing generic child
    processes, crash handlers, or unrelated modules from inheriting secrets.
    """
    values = read_secret_map(data_root)
    _remove_environment_secrets((*_NON_ENVIRONMENT_SECRETS, *values))


def migrate_legacy_env(paths: list[Path], data_root: Path | None = None) -> list[Path]:
    """Explicitly migrate selected plaintext files after a verified DPAPI write.

    Callers must obtain operator approval for each path. Existing protected keys
    win, preventing a stale legacy file from replacing a credential silently.
    """
    merged: dict[str, str] = {}
    sources: list[tuple[Path, tuple[int, int, int, int, int]]] = []
    seen: set[str] = set()
    for candidate in paths:
        identity = _legacy_source_identity(candidate)
        if identity is None:
            continue
        canonical = os.path.normcase(os.path.abspath(candidate))
        if canonical in seen:
            continue
        seen.add(canonical)
        values = parse_env(candidate)
        # Reject a file that changed while it was being parsed. No protected
        # update or plaintext deletion is attempted for an unstable source.
        if values and _legacy_source_identity(candidate) == identity:
            merged.update(values)
            sources.append((candidate, identity))
    if not merged:
        return []
    existing = read_secret_map(data_root)
    write_secret_map({key: value for key, value in merged.items() if key not in existing},
                     data_root)
    stored = read_secret_map(data_root)
    expected = {**merged, **existing}
    if any(stored.get(key) != value for key, value in expected.items()):
        raise RuntimeError("legacy credential migration did not verify")
    removed: list[Path] = []
    for source, identity in sources:
        # Never delete a path that was swapped, linked, or changed after the
        # protected write/read verification. Leaving plaintext behind is safer
        # than deleting an object we did not inspect.
        if _legacy_source_identity(source) != identity:
            continue
        try:
            source.unlink()
            removed.append(source)
        except OSError:
            pass
    return removed
