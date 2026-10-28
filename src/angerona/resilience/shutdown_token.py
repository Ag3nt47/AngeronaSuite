"""shutdown_token.py — authenticated graceful stand-down for the ecosystem.

The mutual-restart loop is deliberately hard to kill — but an operator must still
be able to stop the whole suite for maintenance WITHOUT the survivors resurrecting
each other. This module provides that break: a nonce challenge-response signed with
the dedicated protected shutdown HMAC key, plus a
signed "stand-down" command file every component checks before respawning anything.

Security properties
    * Authenticated: a stand-down command is only honoured if its HMAC signature
      verifies against the local key. A stray/empty flag file does nothing.
    * Maintenance commands expire. Signed operator stops persist until a fresh
      explicit launch, so sleep or a long downtime cannot revive protection.
    * Native-parent stop uses a separate per-launch HMAC authority after proving
      that parent's signed image, heartbeat, process identity and session.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Optional

_OPERATOR_STOP_PREFIX = "operator-stop: "
# Source-recovery compatibility floor; this marker is not trust authority.
OPERATOR_STOP_CONTRACT_VERSION = 1


def _atomic_command(path: Path, command: dict) -> None:
    """Publish one bounded command durably without a shared temporary name."""
    raw = json.dumps(command, separators=(",", ":")).encode("utf-8")
    if len(raw) > 4096:
        raise ValueError("shutdown command exceeds its bound")
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _data_dir() -> Path:
    try:
        from angerona.core.config import _data_dir as core_data_dir
        return Path(core_data_dir())
    except Exception:
        from angerona.core.data_paths import data_dir
        return data_dir()


def _load_key() -> bytes:
    """Load the dedicated shutdown authority, creating it only when absent.

    Shutdown custody is intentionally separate from EventBus signing: a module
    that can authenticate telemetry must not thereby gain stand-down authority.
    Malformed/unreadable keys fail closed and are never silently rotated.
    """
    key_path = _data_dir() / "shutdown.key"
    from angerona.core.hardening import key_acl_required, prepare_sensitive_key
    required = key_acl_required()
    if key_path.exists() and not prepare_sensitive_key(
        key_path, required=required
    ):
        return _load_key()
    try:
        encoded = key_path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        from angerona.core.hardening import ensure_sensitive_parent
        ensure_sensitive_parent(key_path, required=required)
        try:
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return _load_key()
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(key.hex())
            fh.flush()
            os.fsync(fh.fileno())
        from angerona.core.hardening import secure_sensitive_file
        secure_sensitive_file(key_path, required=required)
        return key
    except Exception as exc:
        raise RuntimeError(f"shutdown authority is unreadable: {key_path}") from exc
    try:
        key = bytes.fromhex(encoded)
    except ValueError as exc:
        raise RuntimeError(f"shutdown authority is malformed: {key_path}") from exc
    if len(key) != 32:
        raise RuntimeError(
            f"shutdown authority has invalid length ({len(key)} bytes): {key_path}"
        )
    from angerona.core.hardening import secure_sensitive_file
    secure_sensitive_file(key_path, required=required)
    return key


def _standdown_path() -> Path:
    d = _data_dir() / "ipc"
    d.mkdir(parents=True, exist_ok=True)
    return d / "standdown.cmd"


# ── primitives (key-injectable for testing) ──────────────────────────────────
def make_challenge() -> str:
    """High-entropy nonce a challenger issues."""
    return secrets.token_hex(16)


def sign_challenge(nonce: str, key: Optional[bytes] = None) -> str:
    key = key if key is not None else _load_key()
    return hmac.new(key, nonce.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_response(nonce: str, sig: str, key: Optional[bytes] = None) -> bool:
    expected = sign_challenge(nonce, key)
    return hmac.compare_digest(expected, sig or "")


# ── stand-down command ───────────────────────────────────────────────────────
def request_standdown(reason: str = "maintenance", key: Optional[bytes] = None,
                      path: Optional[Path] = None) -> dict:
    """Write a signed stand-down command. Returns the command dict."""
    reason = str(reason).strip()
    if not reason or len(reason) > 256 or any(ord(char) < 32 for char in reason):
        raise ValueError("stand-down reason must be 1-256 printable characters")
    nonce = make_challenge()
    ts = time.time()
    payload = f"{nonce}\x00{int(ts)}\x00{reason}"
    sig = hmac.new(key if key is not None else _load_key(),
                   payload.encode("utf-8"), hashlib.sha256).hexdigest()
    cmd = {"nonce": nonce, "ts": ts, "reason": reason, "sig": sig}
    p = Path(path) if path else _standdown_path()
    _atomic_command(p, cmd)
    return cmd


def request_operator_stop(reason: str = "dashboard STOP", **kwargs) -> dict:
    """Persist an authenticated operator stop until an explicit user launch.

    The domain is part of the signed reason, so editing an unsigned expiry or
    mode field cannot turn a maintenance command into a persistent stop.
    """
    return request_standdown(_OPERATOR_STOP_PREFIX + reason, **kwargs)


def signal_external_watchdog_stop() -> bool:
    """Notify only the proven native parent using its per-launch authority."""
    from angerona.core.privilege import _validated_watchdog_context

    context = _validated_watchdog_context(os.environ)
    if not context:
        return False
    key = bytes.fromhex(context["ANGERONA_WATCHDOG_TOKEN"])
    nonce, ts = make_challenge(), int(time.time())
    payload = f"angerona-watchdog-stop-v1\x00{nonce}\x00{ts}"
    command = {"schema": 1, "nonce": nonce, "ts": ts,
               "sig": hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()}
    _atomic_command(Path(context["ANGERONA_WD_DATADIR"]) / "watchdog.stop", command)
    return True


def is_standdown_requested(max_age_s: float = 3600.0, key: Optional[bytes] = None,
                           path: Optional[Path] = None,
                           max_future_skew_s: float = 30.0) -> bool:
    """Verify maintenance freshness or a persistent, signed operator stop."""
    p = Path(path) if path else _standdown_path()
    try:
        with p.open("rb") as stream:
            raw = stream.read(4097)
    except OSError:
        return False
    return _verify_standdown_bytes(raw, max_age_s, key, max_future_skew_s)


def _verify_standdown_bytes(raw, max_age_s=3600.0, key=None, max_future_skew_s=30.0):
    try:
        if len(raw) > 4096:
            return False
        cmd = json.loads(raw)
        if not isinstance(cmd, dict):
            return False
    except Exception:
        return False
    try:
        nonce = str(cmd.get("nonce", ""))
        ts = float(cmd.get("ts", 0))
        reason = str(cmd.get("reason", ""))
        sig = str(cmd.get("sig", ""))
        max_age = float(max_age_s)
        max_future_skew = float(max_future_skew_s)
    except (TypeError, ValueError):
        return False
    if (
        not math.isfinite(ts)
        or not math.isfinite(max_age)
        or not math.isfinite(max_future_skew)
        or max_age < 0
        or max_future_skew < 0
        or not re.fullmatch(r"[0-9a-f]{32}", nonce)
        or not re.fullmatch(r"[0-9a-f]{64}", sig)
        or not reason
        or len(reason) > 256
        or any(ord(char) < 32 for char in reason)
    ):
        return False
    age = time.time() - ts
    persistent = reason.startswith(_OPERATOR_STOP_PREFIX)
    if age < -max_future_skew or ts <= 0 or (not persistent and age > max_age):
        return False
    payload = f"{nonce}\x00{int(ts)}\x00{reason}"
    expected = hmac.new(key if key is not None else _load_key(),
                        payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def standdown_active_for_storage(storage: Path) -> bool:
    """Read STOP from an already trusted startup storage plan, without writes.

    Absence does not create an IPC directory/key or repair/rotate authority.
    Runtime environment hints cannot redirect this independent launcher check.
    """
    root = Path(storage)
    if not root.is_absolute():
        raise ValueError("Startup stop storage must be absolute")
    command = root / "ipc" / "standdown.cmd"
    if not command.exists():
        return False
    key = _storage_shutdown_key(root)
    return is_standdown_requested(key=key, path=command)


def _storage_shutdown_key(root: Path) -> bytes:
    command = root / "ipc" / "standdown.cmd"
    authority = root / "shutdown.key"
    try:
        for path in (root / "ipc", command, authority):
            metadata = path.lstat()
            if (stat.S_ISLNK(metadata.st_mode)
                    or getattr(metadata, "st_file_attributes", 0) & 0x400
                    or (path != root / "ipc" and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1))):
                raise ValueError("Startup stop authority is redirected")
        with authority.open("rb") as stream:
            raw = stream.read(129)
        if len(raw) > 128:
            raise ValueError("Startup stop authority exceeds its bound")
        key = bytes.fromhex(raw.decode("ascii").strip())
        if len(key) != 32:
            raise ValueError("Startup stop authority is malformed")
    except (OSError, ValueError, UnicodeError) as error:
        raise RuntimeError("Startup stop authority is unavailable") from error
    return key


def clear_standdown_for_storage(storage: Path) -> None:
    """Explicit trusted-plan resume: authenticate and retire the exact command.

    Does not create or rotate a key, create IPC state, or accept another data
    root from the environment. Windows deletion targets the retained file
    handle while its namespace and contents are pinned against replacement.
    """
    root = Path(storage)
    if not root.is_absolute():
        raise ValueError("Startup stop storage must be absolute")
    command = root / "ipc" / "standdown.cmd"
    if not command.exists():
        return
    from angerona.core.alert_retention import _Directory, _identity
    from angerona.core.source_sandbox import _hold_plain_directories

    key = _storage_shutdown_key(root)
    descriptor = None
    try:
        with _hold_plain_directories(root / "ipc"):
            if os.name != "nt":
                descriptor = os.open(root / "ipc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            directory = _Directory(root / "ipc", descriptor)
            with directory.open("standdown.cmd") as held:
                raw = os.read(held.descriptor, 4097)
                # A manual resume may also retire expired maintenance commands,
                # but an unauthenticated or future command is never deleted.
                if not _verify_standdown_bytes(raw, max_age_s=1e300, key=key):
                    raise ValueError("The retained STOP command failed authentication")
                held.delete(_identity(held.info()))
        if command.exists():
            raise RuntimeError("The operator STOP remains present after resume")
    except (OSError, ValueError) as error:
        raise RuntimeError("The authenticated operator STOP could not be cleared") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def clear_standdown(path: Optional[Path] = None, *, strict: bool = False) -> None:
    p = Path(path) if path else _standdown_path()
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    except Exception:
        if strict:
            raise RuntimeError("The authenticated operator STOP could not be cleared.") from None


def self_test() -> tuple[bool, str]:
    """Offline: challenge/response sign+verify, tamper rejection, and a full
    signed stand-down request/detect/clear cycle — with an injected test key."""
    import tempfile
    key = secrets.token_bytes(32)
    d = Path(tempfile.mkdtemp(prefix="tok_selftest_"))
    try:
        nonce = make_challenge()
        sig = sign_challenge(nonce, key=key)
        sign_ok = verify_response(nonce, sig, key=key)
        tamper_ok = (not verify_response(nonce, sig[:-1] + ("0" if sig[-1] != "0" else "1"), key=key)
                     and not verify_response(nonce, sig, key=secrets.token_bytes(32)))

        p = d / "standdown.cmd"
        request_standdown("unit-test", key=key, path=p)
        detect_ok = is_standdown_requested(key=key, path=p)
        # Wrong key must NOT honour the command.
        wrongkey_ok = not is_standdown_requested(key=secrets.token_bytes(32), path=p)
        # Staleness: a 0s freshness window must reject.
        stale_ok = not is_standdown_requested(max_age_s=-1, key=key, path=p)
        clear_standdown(path=p)
        cleared_ok = not is_standdown_requested(key=key, path=p)

        ok = all([sign_ok, tamper_ok, detect_ok, wrongkey_ok, stale_ok, cleared_ok])
        return ok, ("challenge/response + tamper reject + signed stand-down "
                    "request/detect/clear verified" if ok else
                    f"failed: sign={sign_ok} tamper={tamper_ok} detect={detect_ok} "
                    f"wrongkey={wrongkey_ok} stale={stale_ok} cleared={cleared_ok}")
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    print(self_test())
