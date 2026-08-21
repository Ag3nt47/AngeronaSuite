"""shutdown_token.py — authenticated graceful stand-down for the ecosystem.

The mutual-restart loop is deliberately hard to kill — but an operator must still
be able to stop the whole suite for maintenance WITHOUT the survivors resurrecting
each other. This module provides that break: a nonce challenge-response signed with
the per-install HMAC key (the same ``bus.key`` the EventBus already uses), plus a
signed "stand-down" command file every component checks before respawning anything.

Security properties
    * Authenticated: a stand-down command is only honoured if its HMAC signature
      verifies against the local key. A stray/empty flag file does nothing.
    * Anti-replay: each command carries a fresh random nonce and a timestamp;
      components ignore commands older than ``max_age_s``.
    * Symmetric: any component can verify a challenge/response, so the Go watchdog
      (using the same key + HMAC-SHA256) interoperates.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time
from pathlib import Path
from typing import Optional


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
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(cmd), encoding="utf-8")
    os.replace(tmp, p)           # atomic
    return cmd


def is_standdown_requested(max_age_s: float = 3600.0, key: Optional[bytes] = None,
                           path: Optional[Path] = None,
                           max_future_skew_s: float = 30.0) -> bool:
    """True only if a fresh, correctly-signed stand-down command is present."""
    p = Path(path) if path else _standdown_path()
    try:
        cmd = json.loads(p.read_text(encoding="utf-8"))
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
    if age < -max_future_skew or age > max_age:
        return False
    payload = f"{nonce}\x00{int(ts)}\x00{reason}"
    expected = hmac.new(key if key is not None else _load_key(),
                        payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def clear_standdown(path: Optional[Path] = None) -> None:
    p = Path(path) if path else _standdown_path()
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    except Exception:
        pass


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
