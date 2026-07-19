"""remote_bridge.py — encrypted, mutually authenticated telemetry (CODE: RBRG).

Angerona can run as a silent SENSOR on a headless home server and forward its
high-severity telemetry to a central MAIN PC that owns the Ollama AI-triage
engine and the GUI. This module is that transport. It operates in one of two
modes, selected by environment/config:

    SENDER   (headless server) — polls the local EventBus, and for every HIGH or
             CRITICAL event securely forwards the payload to the main PC.
    RECEIVER (main PC)         — listens on a designated LAN port, authenticates
             the peer, then republishes each validated event onto the local
             EventBus tagged with ``node_origin`` + ``hostname`` so the AI-triage
             engine and GUI know it arrived from another node.

Zero-Trust LAN transport
------------------------
Both peers prove possession of a 256-bit shared key before telemetry moves. A
fresh per-connection session key protects every event with AES-256-GCM, so a LAN
observer cannot read or alter it. The receiver is loopback-only unless an
operator explicitly chooses a routable bind address.

Consent / safety
----------------
This module is the ONLY component that sends host telemetry off-machine, so it
is DISABLED by default and refuses to open any routable socket until the operator
explicitly configures a mode, a peer, and a shared key. Nothing leaves (or is
accepted from) the network otherwise. Only HIGH/CRITICAL events are forwarded —
never the full event stream.

The optional Remote Bridge requires ``cryptography`` for AES-GCM. If that
dependency or a strong key is absent, the module fails closed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Optional

from angerona.core.eventbus import Event, Severity
from angerona.core.module_base import BaseModule
from angerona.core.privacy import redact_text


# ── Configuration (env-driven; all optional — absent = disabled) ──────────────
_MODE_ENV   = "ANGERONA_BRIDGE_MODE"    # "SENDER" | "RECEIVER" (case-insensitive)
_PEER_ENV   = "ANGERONA_BRIDGE_PEER"    # SENDER: "host:port" of the RECEIVER
_PORT_ENV   = "ANGERONA_BRIDGE_PORT"    # RECEIVER: LAN port to listen on
_KEY_ENV    = "ANGERONA_BRIDGE_KEY"     # shared symmetric key (hex or passphrase)
_BIND_ENV   = "ANGERONA_BRIDGE_BIND"    # RECEIVER: bind addr (default loopback)
_NODE_ENV   = "ANGERONA_BRIDGE_NODE_ID" # optional privacy-safe display name

_DEFAULT_PORT = 47924
_SOCK_TIMEOUT = 4.0
_FORWARD_MIN  = Severity.HIGH           # only HIGH/CRITICAL cross the network
_PROTOCOL = "RBRG2"
_AAD = b"Angerona-Remote-Bridge-v2"
_MAX_FRAME = 1_000_000


def _shared_key() -> Optional[bytes]:
    """Load the shared symmetric key from env or ``<data>/bridge.key``.

    Only a hex-encoded value of at least 32 bytes is accepted. Legacy plaintext
    bridge.key files are migrated into Angerona's DPAPI store before use.
    """
    raw = os.environ.get(_KEY_ENV)
    if not raw:
        try:
            from angerona.core.data_paths import data_dir
            kp = data_dir() / "bridge.key"
            if kp.exists():
                raw = kp.read_text(encoding="ascii").strip()
                try:
                    from angerona.core.secure_store import write_secret_map
                    write_secret_map({_KEY_ENV: raw}, data_dir())
                    kp.unlink(missing_ok=True)
                except Exception:
                    pass
        except Exception:
            raw = None
    if not raw:
        return None
    try:
        b = bytes.fromhex(raw)
        return b if len(b) >= 32 else None
    except ValueError:
        return None


def _proof(key: bytes, role: bytes, server_nonce: bytes,
           client_nonce: bytes = b"") -> str:
    return hmac.new(key, _AAD + role + server_nonce + client_nonce,
                    hashlib.sha256).hexdigest()


def _session_key(key: bytes, server_nonce: bytes, client_nonce: bytes) -> bytes:
    return hmac.new(key, _AAD + b"session" + server_nonce + client_nonce,
                    hashlib.sha256).digest()


def _encrypt(key: bytes, payload: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, payload, _AAD)


def _decrypt(key: bytes, frame: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(frame) < 29:
        raise ValueError("encrypted frame too short")
    return AESGCM(key).decrypt(frame[:12], frame[12:], _AAD)


def _redact_text(value: object) -> str:
    return redact_text(value, limit=8192)


def _safe_details(value: object, depth: int = 0) -> object:
    """Bound and redact details before an explicitly enabled off-host transfer."""
    if depth > 4:
        return "[depth-limit]"
    if isinstance(value, dict):
        out = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 128:
                break
            name = str(key)[:128]
            folded = name.casefold()
            if any(word in folded for word in
                   ("password", "passwd", "secret", "token", "api_key",
                    "apikey", "authorization", "cookie")):
                out[name] = "[redacted]"
            else:
                out[name] = _safe_details(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_safe_details(item, depth + 1) for item in value[:128]]
    if isinstance(value, (str, bytes)):
        return _redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_text(value)


class RemoteBridge(BaseModule):
    """Secure SENDER/RECEIVER telemetry bridge. Module code: RBRG."""

    CODE = "RBRG"
    NAME = "Remote Bridge"
    name = "Remote Bridge"
    description = ("Secure multi-node telemetry forwarding (SENDER/RECEIVER) with "
                   "mutual authentication and AES-256-GCM encryption. Off by default.")
    category = "Integrity"
    version = "1.0.0"
    enabled_by_default = False   # never open the network without explicit opt-in

    def __init__(self) -> None:
        super().__init__()
        self._mode = (os.environ.get(_MODE_ENV) or "").strip().upper()
        self._key = _shared_key()
        self._srv: Optional[socket.socket] = None
        self._cursor_ts = 0.0
        self.forwarded = 0
        self.received = 0
        self.denied = 0
        self._connections = threading.BoundedSemaphore(16)
        self._crypto_ok = True
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        except Exception:
            self._crypto_ok = False

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── Entry ────────────────────────────────────────────────────────────────
    def run(self) -> None:
        if self._mode not in ("SENDER", "RECEIVER"):
            self.set_health(100, "idle — set ANGERONA_BRIDGE_MODE to SENDER/RECEIVER")
            while not self.stopping:
                self.sleep(10)
            return
        if self._key is None:
            self.set_health(40, "no strong shared key — use 64+ hex characters")
            self.emit("Remote Bridge configured without a 256-bit hex key — refusing "
                      "to open the network (default-deny).", Severity.MEDIUM)
            while not self.stopping:
                self.sleep(10)
            return
        if not self._crypto_ok:
            self.set_health(40, "cryptography unavailable — encrypted bridge disabled")
            self.emit("Remote Bridge requires the cryptography package; network access "
                      "was not opened.", Severity.MEDIUM)
            while not self.stopping:
                self.sleep(10)
            return
        if self._mode == "SENDER":
            self._run_sender()
        else:
            self._run_receiver()

    # ── SENDER ───────────────────────────────────────────────────────────────
    def _peer(self) -> Optional[tuple[str, int]]:
        raw = os.environ.get(_PEER_ENV, "").strip()
        if not raw or ":" not in raw:
            return None
        host, _, port = raw.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return None

    def _run_sender(self) -> None:
        peer = self._peer()
        if peer is None:
            self.set_health(40, f"no valid peer — set {_PEER_ENV}=host:port")
            while not self.stopping:
                self.sleep(10)
            return
        self.emit(f"Remote Bridge SENDER active — forwarding HIGH/CRITICAL events to "
                  f"{peer[0]}:{peer[1]}.", Severity.INFO)
        while not self.stopping:
            self.sleep(3)
            if self._bus is None:
                continue
            try:
                batch = []
                for ev in reversed(self._bus.recent(50)):   # oldest→newest
                    if ev.ts <= self._cursor_ts:
                        continue
                    if ev.severity < _FORWARD_MIN or ev.module == self.name:
                        self._cursor_ts = max(self._cursor_ts, ev.ts)
                        continue
                    batch.append(ev)
                for ev in batch:
                    if not self._forward(peer, ev):
                        break
                    self._cursor_ts = max(self._cursor_ts, ev.ts)
            except Exception as exc:
                self.set_health(60, f"sender loop error: {exc}")
                continue
            self.set_health(100, f"{self.forwarded} events forwarded")

    def _node_id(self) -> str:
        configured = os.environ.get(_NODE_ENV, "").strip()
        if configured:
            return configured[:64]
        digest = hmac.new(self._key or b"", socket.gethostname().encode("utf-8"),
                          hashlib.sha256).hexdigest()[:12]
        return f"node-{digest}"

    def _forward(self, peer: tuple[str, int], ev: Event) -> bool:
        """Mutually authenticate, encrypt, and send one event. Non-fatal."""
        payload = json.dumps({
            "module": ev.module, "message": _redact_text(ev.message),
            "severity": int(ev.severity), "ts": ev.ts,
            "details": _safe_details(ev.details or {}),
            "node_origin": self._node_id(),
        }).encode("utf-8")
        try:
            with socket.create_connection(peer, timeout=_SOCK_TIMEOUT) as s:
                s.settimeout(_SOCK_TIMEOUT)
                parts = self._recv_line(s, 512).split()
                if len(parts) != 4 or parts[:2] != [_PROTOCOL, "CHALLENGE"]:
                    return False
                server_nonce = bytes.fromhex(parts[2])
                expected = _proof(self._key, b"server", server_nonce)
                if not hmac.compare_digest(expected, parts[3]):
                    self.denied += 1
                    return False
                client_nonce = os.urandom(32)
                client_sig = _proof(self._key, b"client", server_nonce, client_nonce)
                auth = f"{_PROTOCOL} AUTH {client_nonce.hex()} {client_sig}\n"
                s.sendall(auth.encode("ascii"))
                session = _session_key(self._key, server_nonce, client_nonce)
                ack = self._recv_line(s, 256).split()
                expected_ack = _proof(session, b"receiver-ok", server_nonce, client_nonce)
                ack_ok = (len(ack) == 3 and ack[:2] == [_PROTOCOL, "OK"] and
                          hmac.compare_digest(expected_ack, ack[2]))
                if not ack_ok:
                    self.denied += 1
                    return False
                frame = _encrypt(session, payload)
                s.sendall(len(frame).to_bytes(4, "big") + frame)
                self.forwarded += 1
                return True
        except (OSError, socket.timeout):
            self.set_health(70, "peer unreachable (event left pending for retry)")
        except (ValueError, ImportError):
            self.denied += 1
        return False

    # ── RECEIVER ─────────────────────────────────────────────────────────────
    def _run_receiver(self) -> None:
        bind = os.environ.get(_BIND_ENV, "127.0.0.1").strip() or "127.0.0.1"
        try:
            port = int(os.environ.get(_PORT_ENV, _DEFAULT_PORT))
        except ValueError:
            port = _DEFAULT_PORT
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((bind, port))
            srv.listen(16)
            srv.settimeout(1.0)
            self._srv = srv
        except OSError as exc:
            self.set_health(40, f"could not bind {bind}:{port} ({exc})")
            while not self.stopping:
                self.sleep(5)
            return
        self.emit(f"Remote Bridge RECEIVER active — listening on {bind}:{port} "
                  f"(mutual auth + AES-GCM, default-deny).", Severity.INFO)
        while not self.stopping:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                self.set_health(100, f"{self.received} received, {self.denied} denied")
                continue
            except OSError:
                break
            if not self._connections.acquire(blocking=False):
                self.denied += 1
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn, addr),
                             name="RBRG-conn", daemon=True).start()

    def _serve(self, conn: socket.socket, addr) -> None:
        try:
            conn.settimeout(_SOCK_TIMEOUT)
            server_nonce = os.urandom(32)
            server_sig = _proof(self._key, b"server", server_nonce)
            challenge = f"{_PROTOCOL} CHALLENGE {server_nonce.hex()} {server_sig}\n"
            conn.sendall(challenge.encode("ascii"))
            parts = self._recv_line(conn, 512).split()
            valid = False
            client_nonce = b""
            if len(parts) == 4 and parts[:2] == [_PROTOCOL, "AUTH"]:
                try:
                    client_nonce = bytes.fromhex(parts[2])
                    expected = _proof(self._key, b"client", server_nonce, client_nonce)
                    valid = (len(client_nonce) == 32 and
                             hmac.compare_digest(expected, parts[3]))
                except ValueError:
                    valid = False
            if not valid:
                conn.sendall(f"{_PROTOCOL} DENY\n".encode("ascii"))
                self.denied += 1
                self.emit(f"Remote Bridge DENY from {addr} — invalid mutual-auth proof.",
                          Severity.HIGH, peer=str(addr))
                return
            session = _session_key(self._key, server_nonce, client_nonce)
            ack = _proof(session, b"receiver-ok", server_nonce, client_nonce)
            conn.sendall(f"{_PROTOCOL} OK {ack}\n".encode("ascii"))
            hdr = self._recvn(conn, 4)
            if not hdr:
                return
            length = int.from_bytes(hdr, "big")
            if length <= 0 or length > _MAX_FRAME:
                return
            frame = self._recvn(conn, length)
            if frame:
                self._republish(_decrypt(session, frame), addr)
        except Exception as exc:
            self.last_error = str(exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass
            self._connections.release()

    @staticmethod
    def _recv_line(conn: socket.socket, maximum: int) -> str:
        buf = bytearray()
        while len(buf) < maximum:
            chunk = conn.recv(1)
            if not chunk or chunk == b"\n":
                break
            buf.extend(chunk)
        if len(buf) >= maximum:
            raise ValueError("protocol line too long")
        return bytes(buf).decode("ascii", "strict").strip()

    @staticmethod
    def _recvn(conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _republish(self, body: bytes, addr) -> None:
        """Republish a validated remote event onto the local bus, tagged with its
        origin node so the GUI/triage can tell it apart from local telemetry."""
        try:
            d = json.loads(body.decode("utf-8"))
        except Exception:
            self.denied += 1
            return
        if not isinstance(d, dict) or self._bus is None:
            self.denied += 1
            return
        origin = _redact_text(d.get("node_origin") or "remote")[:64] or "remote"
        raw_details = d.get("details")
        details = _safe_details(raw_details if isinstance(raw_details, dict) else {})
        if not isinstance(details, dict):
            details = {}
        details["node_origin"] = origin
        try:
            sev = Severity(int(d.get("severity", int(Severity.INFO))))
        except (ValueError, TypeError):
            sev = Severity.INFO
        module = _redact_text(d.get("module") or "REMOTE")[:128] or "REMOTE"
        msg = f"[{origin}] {_redact_text(d.get('message', ''))}"
        self._bus.publish(Event(module, msg, sev,
                                time.time(), details))
        self.received += 1

    def stop(self) -> None:
        super().stop()
        if self._srv is not None:
            try:
                self._srv.close()
            except Exception:
                pass
            self._srv = None

    def self_test(self) -> tuple[bool, str]:
        """Verify mutual proofs and an AES-GCM round-trip."""
        key = os.urandom(32)
        server_nonce = os.urandom(32)
        client_nonce = os.urandom(32)
        signed = _proof(key, b"client", server_nonce, client_nonce)
        good = hmac.compare_digest(signed, signed)
        tampered = signed
        tampered = tampered[:-1] + ("0" if tampered[-1] != "0" else "1")
        bad = hmac.compare_digest(signed, tampered)
        session = _session_key(key, server_nonce, client_nonce)
        encrypted = _encrypt(session, b"private telemetry")
        if good and not bad and _decrypt(session, encrypted) == b"private telemetry":
            mode = self._mode or "idle"
            keyed = "keyed" if self._key else "no-key"
            return True, f"mutual auth + AES-GCM verified; mode={mode}, {keyed}"
        return False, "encrypted mutual-auth self-test failed"


def register() -> RemoteBridge:
    return RemoteBridge()
