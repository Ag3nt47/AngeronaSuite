"""DPAPI-protected storage for Angerona credentials.

The UI needs a small persistent key/value store for optional provider tokens,
mail credentials, and connector secrets.  Keeping those values in a project
``.env`` file made them readable to every account that inherited access to the
checkout.  This module stores the same values as one current-user DPAPI blob
under Angerona's runtime-data directory and applies a private Windows ACL as a
second layer of protection.

Legacy ``.env`` files remain readable for compatibility.  On Windows they are
migrated only after an encrypt/decrypt verification succeeds; the plaintext
source is then removed.  On platforms without DPAPI, writes fail closed instead
of silently creating another plaintext credential file.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Mapping

_ENTROPY = b"Angerona-SecretStore-v1"
_FILENAME = "secrets.dpapi"


def secure_store_path(data_root: Path | None = None) -> Path:
    if data_root is None:
        from angerona.core.data_paths import data_dir
        data_root = data_dir()
    return Path(data_root) / _FILENAME


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


def read_secret_map(data_root: Path | None = None) -> dict[str, str]:
    path = secure_store_path(data_root)
    if not path.exists():
        return {}
    try:
        raw = _unprotect_bytes(path.read_bytes())
        if raw is None:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            return {}
        return {
            str(key): str(item)
            for key, item in value.items()
            if isinstance(key, str) and isinstance(item, str)
        }
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}


def write_secret_map(updates: Mapping[str, object], data_root: Path | None = None) -> Path:
    path = secure_store_path(data_root)
    values = read_secret_map(data_root)
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
    blob = _protect_bytes(payload)
    if blob is None:
        raise RuntimeError("Windows DPAPI is unavailable; credentials were not written")
    # Verify before replacing the previous store.  A DPAPI or account-context
    # problem must never destroy the only readable credential copy.
    if _unprotect_bytes(blob) != payload:
        raise RuntimeError("DPAPI verification failed; credentials were not written")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_bytes(blob)
        _private_acl(tmp)
        os.replace(tmp, path)
        _private_acl(path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
    for key, value in values.items():
        os.environ[key] = value
    for key in removed:
        os.environ.pop(key, None)
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
    for key, value in read_secret_map(data_root).items():
        os.environ.setdefault(key, value)


def migrate_legacy_env(paths: list[Path], data_root: Path | None = None) -> list[Path]:
    """Explicitly migrate selected plaintext files after a verified DPAPI write.

    Callers must obtain operator approval for each path. Existing protected keys
    win, preventing a stale legacy file from replacing a credential silently.
    """
    merged: dict[str, str] = {}
    sources: list[Path] = []
    seen: set[str] = set()
    for candidate in paths:
        try:
            canonical = str(candidate.resolve())
        except OSError:
            canonical = str(candidate)
        if canonical in seen or not candidate.exists():
            continue
        seen.add(canonical)
        values = parse_env(candidate)
        if values:
            merged.update(values)
            sources.append(candidate)
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
    for source in sources:
        try:
            source.unlink()
            removed.append(source)
        except OSError:
            pass
    return removed
