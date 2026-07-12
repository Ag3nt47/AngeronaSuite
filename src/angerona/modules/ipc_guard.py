"""ipc_guard.py — Zero-Trust Local IPC Guard (Code: AUTH).

Purpose
    Enforce zero-trust on AngeronaSuite's local inter-process channel. Every peer
    that wants to talk to the suite over TCP loopback ``127.0.0.1:65432`` must
    prove possession of a per-install secret via an HMAC-SHA256
    challenge/response. Unsigned or wrongly-signed peers are denied by default and
    logged as a possible local-IPC spoofing / lateral-movement attempt.

Design
    - Per-install 256-bit secret generated with ``os.urandom`` and stored under
      the per-user data dir (never transmitted, never committed).
    - Server binds LOOPBACK ONLY (127.0.0.1) — never a routable interface — so the
      channel is unreachable from the network.
    - Challenge/response: server sends a random nonce; client returns
      ``HMAC(secret, nonce)``; the server verifies with constant-time
      ``hmac.compare_digest``. Default-deny.

Safety
    Loopback-only, local secret, read/verify only. This module authenticates
    callers; it never opens the machine to the network and stores no user
    passwords (the secret is a machine-generated key).

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import hashlib
import hmac
import os
import socket
import threading
import time
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity

_HOST = "127.0.0.1"
_PORT = 65432


def _load_or_create_key(path: Path) -> bytes:
    try:
        if path.exists():
            data = path.read_bytes()
            if len(data) >= 32:
                return data[:32]
        path.parent.mkdir(parents=True, exist_ok=True)
        key = os.urandom(32)
        path.write_bytes(key)
        try:
            os.chmod(path, 0o600)   # best-effort; NTFS ACLs differ but dir is per-user
        except Exception:
            pass
        return key
    except Exception:
        # last resort: ephemeral in-process key (still enforces zero-trust for this run)
        return os.urandom(32)


def sign(key: bytes, nonce: bytes) -> str:
    return hmac.new(key, nonce, hashlib.sha256).hexdigest()


def verify(key: bytes, nonce: bytes, sig_hex: str) -> bool:
    expected = sign(key, nonce)
    try:
        return hmac.compare_digest(expected, (sig_hex or "").strip())
    except Exception:
        return False


def authenticate(key: bytes, host: str = _HOST, port: int = _PORT,
                 timeout: float = 3.0) -> bool:
    """Client side: complete the challenge/response handshake with the guard."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        line = s.recv(256).decode("ascii", "ignore").strip()
        if not line.startswith("CHALLENGE "):
            return False
        nonce = line.split(" ", 1)[1].encode("ascii")
        s.sendall(f"AUTH {sign(key, nonce)}\n".encode("ascii"))
        resp = s.recv(64).decode("ascii", "ignore").strip()
        return resp == "OK"


class IpcGuardModule(BaseModule):
    CODE = "AUTH"
    NAME = "Zero-Trust Local IPC Guard"
    name = "Zero-Trust Local IPC Guard"
    description = ("HMAC-SHA256 challenge/response auth for the loopback IPC channel "
                   "(127.0.0.1:65432); default-deny, logs spoofing attempts.")
    category = "Integrity"
    version = "1.0.0"

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._key: bytes = b""
        self._srv: socket.socket | None = None
        self.accepted = 0
        self.denied = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── server ───────────────────────────────────────────────────────────────
    def _serve_conn(self, conn: socket.socket, addr) -> None:
        try:
            conn.settimeout(4.0)
            nonce = os.urandom(16).hex().encode("ascii")
            conn.sendall(b"CHALLENGE " + nonce + b"\n")
            data = conn.recv(256).decode("ascii", "ignore").strip()
            sig = data.split(" ", 1)[1] if data.startswith("AUTH ") else ""
            if verify(self._key, nonce, sig):
                conn.sendall(b"OK\n")
                with self.state_lock:
                    self.accepted += 1
            else:
                conn.sendall(b"DENY\n")
                with self.state_lock:
                    self.denied += 1
                self.emit(f"🚫 Zero-trust IPC DENY from {addr} — unsigned/invalid HMAC "
                          f"(possible local spoofing).", Severity.HIGH, peer=str(addr))
        except Exception as exc:
            self.last_error = str(exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _accept_loop(self) -> None:
        while not self.stopping and self._srv is not None:
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_conn, args=(conn, addr),
                             name="AUTH-conn", daemon=True).start()

    def run(self) -> None:
        from angerona.core.config import Config
        self._key = _load_or_create_key(Config().data_dir / "ipc_auth.key")
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((_HOST, _PORT))     # loopback only
            srv.listen(16)
            srv.settimeout(1.0)
            self._srv = srv
        except OSError as exc:
            self.last_error = str(exc)
            self.set_health(40, f"could not bind {_HOST}:{_PORT} ({exc}) — is a guard already up?")
            # keep module alive but idle; sign/verify helpers still usable
            while not self.stopping:
                self.sleep(5.0)
            return
        self.emit(f"AUTH online — zero-trust HMAC guard on {_HOST}:{_PORT} (default-deny).",
                  Severity.INFO)
        threading.Thread(target=self._accept_loop, name="AUTH-accept", daemon=True).start()
        while not self.stopping:
            with self.state_lock:
                a, d = self.accepted, self.denied
            self.set_health(100, f"{a} authorized, {d} denied")
            self.sleep(5.0)

    def stop(self) -> None:
        super().stop()
        if self._srv is not None:
            try:
                self._srv.close()
            except Exception:
                pass
            self._srv = None

    def self_test(self) -> tuple[bool, str]:
        """Prove HMAC verify (accept valid / reject tampered) AND a real loopback
        challenge/response round-trip on an ephemeral port (valid vs wrong key)."""
        key = os.urandom(32)
        nonce = os.urandom(16)
        if not verify(key, nonce, sign(key, nonce)):
            return False, "HMAC verify rejected a valid signature"
        if verify(key, nonce, sign(key, nonce)[:-1] + ("0" if sign(key, nonce)[-1] != "0" else "1")):
            return False, "HMAC verify accepted a tampered signature"

        # live loopback handshake on an ephemeral port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((_HOST, 0))
        srv.listen(4)
        srv.settimeout(3.0)
        port = srv.getsockname()[1]
        self._key = key
        results = {}

        def _once(tag: str):
            try:
                conn, addr = srv.accept()
                self._serve_conn(conn, addr)
            except Exception as exc:
                results[tag] = f"srv-err:{exc}"

        # valid client
        t = threading.Thread(target=_once, args=("v",), daemon=True); t.start()
        good = authenticate(key, _HOST, port)
        t.join(timeout=4.0)
        # wrong-key client
        t2 = threading.Thread(target=_once, args=("w",), daemon=True); t2.start()
        bad = authenticate(os.urandom(32), _HOST, port)
        t2.join(timeout=4.0)
        srv.close()

        if good and not bad:
            return True, "HMAC + loopback handshake verified (valid OK, wrong-key DENY)"
        return False, f"handshake failed (valid={good}, wrong-key={bad}, {results})"


def register() -> IpcGuardModule:
    return IpcGuardModule()
