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
Both peers prove possession of a 256-bit shared key and bind that proof to fresh
ephemeral X25519 public keys before telemetry moves. HKDF derives each AES-256-
GCM session key from the ephemeral shared secret and authenticated transcript,
so later compromise of the long-term PSK does not recover captured sessions.
The receiver is loopback-only unless an operator explicitly chooses a routable
bind address.

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

SUPPORTED_PLATFORMS = ("windows", "macos", "linux")

import hashlib
import hmac
import ipaddress
import json
import os
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from angerona.core.durable_outbox import (
    DurableOutbox,
    OutboxFull,
    load_or_create_outbox_key,
)
from angerona.core.eventbus import Event, REMOTE_OBSERVE_AUTHORITY, Severity
from angerona.core.module_base import BaseModule
from angerona.core.privacy import redact_text


# ── Configuration (env-driven; all optional — absent = disabled) ──────────────
_MODE_ENV   = "ANGERONA_BRIDGE_MODE"    # "SENDER" | "RECEIVER" (case-insensitive)
_PEER_ENV   = "ANGERONA_BRIDGE_PEER"    # SENDER: "host:port" of the RECEIVER
_PORT_ENV   = "ANGERONA_BRIDGE_PORT"    # RECEIVER: LAN port to listen on
_KEY_ENV    = "ANGERONA_BRIDGE_KEY"     # shared symmetric key (hex or passphrase)
_BIND_ENV   = "ANGERONA_BRIDGE_BIND"    # RECEIVER: bind addr (default loopback)
_NODE_ENV   = "ANGERONA_BRIDGE_NODE_ID" # optional privacy-safe display name
_ALLOW_NONLOOPBACK_ENV = "ANGERONA_BRIDGE_ALLOW_NONLOOPBACK"

_DEFAULT_PORT = 47924
_SOCK_TIMEOUT = 4.0
_FORWARD_MIN  = Severity.HIGH           # only HIGH/CRITICAL cross the network
_PROTOCOL = "RBRG3"
_AAD = b"Angerona-Remote-Bridge-v3"
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
            from angerona.core.secure_store import read_secret_values

            raw = read_secret_values(
                (_KEY_ENV,), data_dir(), strict=True
            ).get(_KEY_ENV)
        except Exception:
            raw = None
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


def _handshake_transcript(
    server_nonce: bytes,
    client_nonce: bytes,
    server_public: bytes,
    client_public: bytes,
) -> bytes:
    values = (server_nonce, client_nonce, server_public, client_public)
    if any(not isinstance(value, bytes) or len(value) > 64 for value in values):
        raise ValueError("remote bridge handshake field is invalid")
    return b"".join(len(value).to_bytes(2, "big") + value for value in values)


def _proof(
    key: bytes,
    role: bytes,
    server_nonce: bytes,
    client_nonce: bytes = b"",
    server_public: bytes = b"",
    client_public: bytes = b"",
) -> str:
    transcript = _handshake_transcript(
        server_nonce, client_nonce, server_public, client_public
    )
    return hmac.new(key, _AAD + role + transcript, hashlib.sha256).hexdigest()


def _ephemeral_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public


def _exchange_ephemeral(private, peer_public: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    if not isinstance(peer_public, bytes) or len(peer_public) != 32:
        raise ValueError("remote bridge ephemeral public key is invalid")
    shared = private.exchange(X25519PublicKey.from_public_bytes(peer_public))
    if len(shared) != 32 or hmac.compare_digest(shared, b"\0" * 32):
        raise ValueError("remote bridge ephemeral exchange was invalid")
    return shared


def _session_key(
    key: bytes,
    server_nonce: bytes,
    client_nonce: bytes,
    shared_secret: bytes,
    server_public: bytes,
    client_public: bytes,
) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if not isinstance(shared_secret, bytes) or len(shared_secret) != 32:
        raise ValueError("remote bridge shared secret is invalid")
    transcript = _handshake_transcript(
        server_nonce, client_nonce, server_public, client_public
    )
    salt = hmac.new(key, _AAD + b"hkdf-salt" + transcript, hashlib.sha256).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_AAD + b"ephemeral-session",
    ).derive(shared_secret)


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
    description = (
        "Secure multi-node telemetry forwarding with PSK-authenticated ephemeral "
        "X25519, HKDF, and AES-256-GCM. Off by default."
    )
    category = "Integrity"
    version = "1.13.0"
    supported_platforms = SUPPORTED_PLATFORMS
    capability_mode = "observe"
    capability_inputs = ("authenticated-high-severity-event", "mutually-authenticated-frame")
    capability_outputs = ("encrypted-telemetry-frame", "remote-observe-only-event")
    capability_permissions = ("configured-network-egress", "configured-network-listen")
    high_risk_permissions = ("configured-network-egress", "configured-network-listen")
    data_classes = ("redacted-security-finding", "source-node-pseudonym")
    egress = "optional"
    retention = "bounded-authenticated-receiver-idempotency-ledger"
    response_authority = "none"
    restart_policy = "bounded-three-attempt-backoff-quarantine"
    loss_behavior = (
        "bounded-priority-ingress-with-explicit-gap-receipt;"
        "durable-at-least-once-after-sender-enqueue"
    )
    resource_budget = {
        "worker_model": "bounded-16-connection-helper-pool",
        "event_delivery": "durable-sender-outbox-with-authenticated-receiver-stored-ack",
        "startup_cycle_timeout_seconds": 30.0,
    }
    settings_schema = {
        "type": "object",
        "properties": {
            "mode": {"type": "string", "enum": ["SENDER", "RECEIVER"]},
            "peer": {"type": "string", "maxLength": 320},
            "bind": {"type": "string", "maxLength": 253},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "node_id": {"type": "string", "maxLength": 64},
            "allow_nonloopback": {"type": "boolean", "default": False},
        },
        "additionalProperties": False,
    }
    enabled_by_default = False   # never open the network without explicit opt-in

    def __init__(self) -> None:
        super().__init__()
        self._mode = (os.environ.get(_MODE_ENV) or "").strip().upper()
        self._key = _shared_key()
        self._srv: Optional[socket.socket] = None
        self._inbox: DurableOutbox | None = None
        self._sender_outbox: DurableOutbox | None = None
        self._sender_owner = f"remote-bridge-{uuid.uuid4().hex}"
        self.forwarded = 0
        self.received = 0
        self.denied = 0
        self._denial_lock = threading.RLock()
        self._denial_last_emit = 0.0
        self._denial_suppressed = 0
        self._denial_emit_interval = 10.0
        self._clock = time.monotonic
        self._connections = threading.BoundedSemaphore(16)
        self._connection_lock = threading.RLock()
        self._connection_threads: set[threading.Thread] = set()
        self._active_connections: set[socket.socket] = set()
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
            parsed_port = int(port)
        except ValueError:
            return None
        if not host or not 1 <= parsed_port <= 65535:
            return None
        return host, parsed_port

    def _run_sender(self) -> None:
        peer = self._peer()
        if peer is None:
            self.set_health(40, f"no valid peer — set {_PEER_ENV}=host:port")
            while not self.stopping:
                self.sleep(10)
            return
        try:
            self._sender_outbox = self._open_sender_outbox()
        except Exception as exc:
            self.last_error = str(exc)
            self.set_health(30, f"durable sender outbox unavailable: {exc}")
            self.emit(
                "Remote Bridge refused sender mode without durable staging.",
                Severity.HIGH,
                response_authorized=False,
            )
            while not self.stopping:
                self.sleep(10)
            return
        self.emit(f"Remote Bridge SENDER active — durably staging HIGH/CRITICAL events for "
                  f"{peer[0]}:{peer[1]}.", Severity.INFO)
        self._enroll_sender_cursor_once()
        try:
            while not self.stopping:
                self.sleep(3, cycle_complete=False)
                if self._bus is None:
                    self.mark_cycle_complete()
                    continue
                try:
                    self._sender_delivery_cycle(peer)
                    stats = self._sender_outbox.stats()
                    if self._bus_overflow_count:
                        self.set_health(
                            45,
                            f"{self._bus_overflow_count} priority ingress gap(s); "
                            f"{stats.pending + stats.leased} queued",
                        )
                    elif stats.dead_letter:
                        self.set_health(
                            35,
                            f"{stats.dead_letter} dead-letter, "
                            f"{stats.pending + stats.leased} queued",
                        )
                    elif stats.pending or stats.leased:
                        self.set_health(
                            65,
                            f"{stats.pending + stats.leased} durably queued; "
                            f"{self.forwarded} receiver-acknowledged",
                        )
                    else:
                        self.set_health(
                            100, f"{self.forwarded} receiver-acknowledged from durable staging"
                        )
                except OutboxFull as exc:
                    self.last_error = str(exc)
                    self.set_health(20, str(exc))
                    self.emit(
                        "Remote Bridge sender outbox is full; ingress cursor was not advanced.",
                        Severity.HIGH,
                        finding_code="remote_bridge.outbox.capacity_exhausted",
                        response_authorized=False,
                    )
                    # Capacity pressure must never prevent recovery once the
                    # peer is reachable again. Cursor remains unchanged until
                    # the unstaged delta is durably committed on a later pass.
                    try:
                        self._drain_sender(peer)
                    except Exception as drain_exc:
                        self.last_error = f"{exc}; drain failed: {drain_exc}"
                except Exception as exc:
                    self.last_error = str(exc)
                    self.set_health(50, f"sender loop error: {exc}")
                self.mark_cycle_complete()
        finally:
            if self._sender_outbox is not None:
                self._sender_outbox.close()
                self._sender_outbox = None

    def _enroll_sender_cursor_once(self) -> int:
        """Seed only the first sender generation; restarts retain stopped-time events."""
        if self._bus is not None and not self.bus_cursor_enrolled(priority=True):
            return self.seed_bus_cursor(priority=True)
        return self._bus_priority_revision

    def _node_id(self) -> str:
        configured = os.environ.get(_NODE_ENV, "").strip()
        if configured:
            return configured[:64]
        digest = hmac.new(self._key or b"", socket.gethostname().encode("utf-8"),
                          hashlib.sha256).hexdigest()[:12]
        return f"node-{digest}"

    def _open_sender_outbox(self) -> DurableOutbox:
        from angerona.core.data_paths import data_dir
        root = data_dir() / "outbox"
        # Local queue integrity has a distinct protected key lifecycle from the
        # rotatable peer transport credential. Rotating a bridge key must not
        # strand pending rows or invalidate delivered tombstones.
        key = load_or_create_outbox_key(root / "remote-bridge-local.key")
        return DurableOutbox(
            root / "remote-bridge-sender.sqlite3",
            key,
            max_items=50_000,
            max_bytes=128 * 1024 * 1024,
            delivered_tombstones=50_000,
        )

    def _event_document(self, ev: Event) -> tuple[str, dict]:
        core = {
            "module": ev.module, "message": _redact_text(ev.message),
            "severity": int(ev.severity), "ts": ev.ts,
            "details": _safe_details(ev.details or {}),
            "node_origin": self._node_id(),
        }
        stable_source = str(getattr(ev, "hmac_sig", "") or "").encode("ascii", "ignore")
        if not stable_source:
            stable_source = json.dumps(
                core, sort_keys=True, separators=(",", ":"), default=str
            ).encode("utf-8")
        event_id = hashlib.sha256(stable_source).hexdigest()
        return event_id, {**core, "event_id": event_id}

    def _stage_sender_delta(self) -> tuple[int, bool]:
        if self._bus is None or self._sender_outbox is None:
            return 0, False
        revision, batch, overflow = self.read_bus_events(priority=True)
        staged = 0
        for ev in batch:
            if ev.severity < _FORWARD_MIN or ev.module == self.name:
                continue
            event_id, document = self._event_document(ev)
            staged += int(self._sender_outbox.enqueue(
                f"rbrg-{event_id}", {"event": document}, now=float(ev.ts)
            ))
        if overflow:
            gap = Event(
                "Remote Bridge Ingress",
                "Priority EventBus retention overflow; remote evidence is incomplete.",
                Severity.HIGH,
                details={
                    "finding_code": "remote_bridge.eventbus.capacity_gap",
                    "priority_revision": revision,
                    "response_authorized": False,
                },
            )
            gap_id, gap_document = self._event_document(gap)
            staged += int(self._sender_outbox.enqueue(
                f"rbrg-gap-{revision}-{gap_id[:24]}", {"event": gap_document}, now=gap.ts
            ))
        # Every retained event and any mandatory gap receipt are durable. An
        # enqueue failure exits before this cursor commit and replays the delta.
        self.commit_bus_cursor(revision, priority=True)
        return staged, overflow

    def _sender_delivery_cycle(self, peer: tuple[str, int]) -> tuple[int, bool]:
        """Free capacity, durably stage the delta, then send the new rows."""
        self._drain_sender(peer)
        staged, overflow = self._stage_sender_delta()
        self._drain_sender(peer)
        return staged, overflow

    def _drain_sender(self, peer: tuple[str, int]) -> None:
        if self._sender_outbox is None:
            return
        for item in self._sender_outbox.claim(
            self._sender_owner, limit=100, lease_seconds=30.0
        ):
            try:
                document = item.payload.get("event")
                if not isinstance(document, dict):
                    raise ValueError("durable bridge item has no event document")
                event_id = str(document.get("event_id") or "")
                if len(event_id) != 64:
                    raise ValueError("durable bridge item has an invalid event identity")
                payload = json.dumps(
                    document, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                if not self._forward_payload(peer, payload, event_id):
                    raise OSError("peer did not return an authenticated stored acknowledgment")
                self._sender_outbox.acknowledge(item.item_id, self._sender_owner)
            except Exception as exc:
                self.last_error = str(exc)
                self._sender_outbox.retry(
                    item.item_id, self._sender_owner, str(exc)
                )

    def _forward(self, peer: tuple[str, int], ev: Event) -> bool:
        """Mutually authenticate, encrypt, and send one event. Non-fatal."""
        event_id, document = self._event_document(ev)
        payload = json.dumps(
            document, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return self._forward_payload(peer, payload, event_id)

    def _forward_payload(
        self, peer: tuple[str, int], payload: bytes, event_id: str
    ) -> bool:
        """Send one durably identified payload and require final stored ACK."""
        try:
            with socket.create_connection(peer, timeout=_SOCK_TIMEOUT) as s:
                s.settimeout(_SOCK_TIMEOUT)
                parts = self._recv_line(s, 512).split()
                if len(parts) != 5 or parts[:2] != [_PROTOCOL, "CHALLENGE"]:
                    return False
                server_nonce = bytes.fromhex(parts[2])
                server_public = bytes.fromhex(parts[3])
                expected = _proof(
                    self._key,
                    b"server",
                    server_nonce,
                    server_public=server_public,
                )
                if (
                    len(server_nonce) != 32
                    or len(server_public) != 32
                    or not hmac.compare_digest(expected, parts[4])
                ):
                    self.denied += 1
                    return False
                client_nonce = os.urandom(32)
                client_private, client_public = _ephemeral_keypair()
                client_sig = _proof(
                    self._key,
                    b"client",
                    server_nonce,
                    client_nonce,
                    server_public,
                    client_public,
                )
                auth = (
                    f"{_PROTOCOL} AUTH {client_nonce.hex()} "
                    f"{client_public.hex()} {client_sig}\n"
                )
                s.sendall(auth.encode("ascii"))
                shared_secret = _exchange_ephemeral(client_private, server_public)
                session = _session_key(
                    self._key,
                    server_nonce,
                    client_nonce,
                    shared_secret,
                    server_public,
                    client_public,
                )
                del client_private, shared_secret
                ack = self._recv_line(s, 256).split()
                expected_ack = _proof(
                    session,
                    b"receiver-ok",
                    server_nonce,
                    client_nonce,
                    server_public,
                    client_public,
                )
                ack_ok = (len(ack) == 3 and ack[:2] == [_PROTOCOL, "OK"] and
                          hmac.compare_digest(expected_ack, ack[2]))
                if not ack_ok:
                    self.denied += 1
                    return False
                frame = _encrypt(session, payload)
                s.sendall(len(frame).to_bytes(4, "big") + frame)
                stored = self._recv_line(s, 512).split()
                expected_stored = _proof(
                    session,
                    b"stored:" + event_id.encode("ascii"),
                    server_nonce,
                    client_nonce,
                    server_public,
                    client_public,
                )
                if not (
                    len(stored) == 3
                    and stored[:2] == [_PROTOCOL, "STORED"]
                    and hmac.compare_digest(expected_stored, stored[2])
                ):
                    return False
                self.forwarded += 1
                return True
        except (OSError, socket.timeout):
            self.set_health(70, "peer unreachable (event left pending for retry)")
        except (ValueError, ImportError):
            self.denied += 1
        return False

    # ── RECEIVER ─────────────────────────────────────────────────────────────
    def _serve_tracked(self, conn: socket.socket, addr) -> None:
        """Own one admitted receiver socket until its helper fully exits."""
        try:
            self._serve(conn, addr)
        finally:
            with self._connection_lock:
                self._active_connections.discard(conn)
                self._connection_threads.discard(threading.current_thread())
            self._connections.release()

    def _start_connection_helper(self, conn: socket.socket, addr) -> None:
        """Start one bounded helper, restoring capacity if startup fails."""
        helper = threading.Thread(
            target=self._serve_tracked,
            args=(conn, addr),
            name="RBRG-conn",
            daemon=True,
        )
        with self._connection_lock:
            self._active_connections.add(conn)
            self._connection_threads.add(helper)
        try:
            helper.start()
        except Exception:
            with self._connection_lock:
                self._active_connections.discard(conn)
                self._connection_threads.discard(helper)
            try:
                conn.close()
            finally:
                self._connections.release()
            raise

    def _retire_receiver(self) -> None:
        """Close listener/sockets so bounded-time helpers leave their recv calls."""
        srv = self._srv
        self._srv = None
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        with self._connection_lock:
            connections = tuple(self._active_connections)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except (AttributeError, OSError):
                pass
            try:
                conn.close()
            except OSError:
                pass

    def _join_connection_helpers(self) -> None:
        """Wait off the caller thread before closing the shared inbox database."""
        current = threading.current_thread()
        while True:
            with self._connection_lock:
                helpers = tuple(
                    helper
                    for helper in self._connection_threads
                    if helper is not current
                )
            if not helpers:
                return
            for helper in helpers:
                helper.join()

    def _run_receiver(self) -> None:
        bind = os.environ.get(_BIND_ENV, "127.0.0.1").strip() or "127.0.0.1"
        try:
            port = int(os.environ.get(_PORT_ENV, _DEFAULT_PORT))
        except ValueError:
            port = _DEFAULT_PORT
        try:
            bind_address = ipaddress.ip_address(bind)
        except ValueError:
            self.set_health(40, "receiver bind must be a literal IP address")
            self.emit(
                "Remote Bridge refused an invalid receiver bind address.",
                Severity.MEDIUM,
                response_authorized=False,
            )
            while not self.stopping:
                self.sleep(10)
            return
        allow_nonloopback = os.environ.get(
            _ALLOW_NONLOOPBACK_ENV, ""
        ).strip().casefold() in {"1", "true", "yes"}
        if not bind_address.is_loopback and not allow_nonloopback:
            self.set_health(40, "non-loopback receive was not explicitly approved")
            self.emit(
                "Remote Bridge refused to open a routable receiver socket without "
                "explicit non-loopback approval.",
                Severity.MEDIUM,
                response_authorized=False,
            )
            while not self.stopping:
                self.sleep(10)
            return
        if not 1 <= port <= 65535:
            self.set_health(40, "receiver port must be between 1 and 65535")
            while not self.stopping:
                self.sleep(10)
            return
        srv: socket.socket | None = None
        try:
            self._inbox = self._open_receiver_inbox()
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((bind, port))
            srv.listen(16)
            srv.settimeout(1.0)
            self._srv = srv
        except OSError as exc:
            if srv is not None:
                try:
                    srv.close()
                except OSError:
                    pass
            self._retire_receiver()
            if self._inbox is not None:
                self._inbox.close()
                self._inbox = None
            self.set_health(40, f"could not bind {bind}:{port} ({exc})")
            while not self.stopping:
                self.sleep(5)
            return
        self.emit(
            f"Remote Bridge RECEIVER active — listening on {bind}:{port} "
            f"(PSK-authenticated ephemeral X25519 + AES-GCM, default-deny).",
            Severity.INFO,
        )
        try:
            while not self.stopping:
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    self.set_health(100, f"{self.received} received, {self.denied} denied")
                    continue
                except OSError:
                    break
                if self.stopping:
                    conn.close()
                    break
                if not self._connections.acquire(blocking=False):
                    self.denied += 1
                    conn.close()
                    continue
                try:
                    self._start_connection_helper(conn, addr)
                except Exception as exc:
                    self.last_error = str(exc)
                    self.set_health(40, f"receiver worker unavailable: {exc}")
                    break
        finally:
            self._retire_receiver()
            self._join_connection_helpers()
            if self._inbox is not None:
                self._inbox.close()
                self._inbox = None

    def _open_receiver_inbox(self) -> DurableOutbox:
        from angerona.core.data_paths import data_dir

        root = data_dir() / "outbox"
        local_key = load_or_create_outbox_key(root / "remote-bridge-local.key")
        return DurableOutbox(
            root / "remote-bridge-inbox.sqlite3",
            local_key,
            max_items=50_000,
            max_bytes=64 * 1024 * 1024,
            delivered_tombstones=50_000,
        )

    def _serve(self, conn: socket.socket, addr) -> None:
        try:
            conn.settimeout(_SOCK_TIMEOUT)
            server_nonce = os.urandom(32)
            server_private, server_public = _ephemeral_keypair()
            server_sig = _proof(
                self._key,
                b"server",
                server_nonce,
                server_public=server_public,
            )
            challenge = (
                f"{_PROTOCOL} CHALLENGE {server_nonce.hex()} "
                f"{server_public.hex()} {server_sig}\n"
            )
            conn.sendall(challenge.encode("ascii"))
            parts = self._recv_line(conn, 512).split()
            valid = False
            client_nonce = b""
            client_public = b""
            if len(parts) == 5 and parts[:2] == [_PROTOCOL, "AUTH"]:
                try:
                    client_nonce = bytes.fromhex(parts[2])
                    client_public = bytes.fromhex(parts[3])
                    expected = _proof(
                        self._key,
                        b"client",
                        server_nonce,
                        client_nonce,
                        server_public,
                        client_public,
                    )
                    valid = (
                        len(client_nonce) == 32
                        and len(client_public) == 32
                        and hmac.compare_digest(expected, parts[4])
                    )
                except ValueError:
                    valid = False
            if not valid:
                conn.sendall(f"{_PROTOCOL} DENY\n".encode("ascii"))
                self._record_auth_denial(addr, "invalid mutual-auth proof")
                return
            shared_secret = _exchange_ephemeral(server_private, client_public)
            session = _session_key(
                self._key,
                server_nonce,
                client_nonce,
                shared_secret,
                server_public,
                client_public,
            )
            del server_private, shared_secret
            ack = _proof(
                session,
                b"receiver-ok",
                server_nonce,
                client_nonce,
                server_public,
                client_public,
            )
            conn.sendall(f"{_PROTOCOL} OK {ack}\n".encode("ascii"))
            hdr = self._recvn(conn, 4)
            if not hdr:
                return
            length = int.from_bytes(hdr, "big")
            if length <= 0 or length > _MAX_FRAME:
                return
            frame = self._recvn(conn, length)
            if frame:
                event_id = self._republish(_decrypt(session, frame), addr)
                if event_id:
                    stored = _proof(
                        session,
                        b"stored:" + event_id.encode("ascii"),
                        server_nonce,
                        client_nonce,
                        server_public,
                        client_public,
                    )
                    conn.sendall(f"{_PROTOCOL} STORED {stored}\n".encode("ascii"))
        except Exception as exc:
            self.last_error = str(exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _record_auth_denial(self, peer, reason: str) -> None:
        """Count every denial while emitting only bounded aggregate evidence."""
        now = self._clock()
        emit_summary = False
        suppressed = 0
        with self._denial_lock:
            self.denied += 1
            if (
                self._denial_last_emit == 0.0
                or now - self._denial_last_emit >= self._denial_emit_interval
            ):
                emit_summary = True
                suppressed = self._denial_suppressed
                self._denial_suppressed = 0
                self._denial_last_emit = now
            else:
                self._denial_suppressed += 1
        if emit_summary:
            self.emit(
                "Remote Bridge denied an invalid mutual-auth attempt"
                + (f" ({suppressed} similar attempt(s) suppressed)." if suppressed else "."),
                Severity.HIGH,
                peer=_redact_text(str(peer))[:160],
                denial_reason=str(reason)[:160],
                denied_total=self.denied,
                suppressed_since_last=suppressed,
                response_authorized=False,
            )

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
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    def _republish(self, body: bytes, addr) -> str:
        """Republish a validated remote event onto the local bus, tagged with its
        origin node so the GUI/triage can tell it apart from local telemetry."""
        try:
            d = json.loads(body.decode("utf-8"))
        except Exception:
            self.denied += 1
            return ""
        if not isinstance(d, dict) or self._bus is None:
            self.denied += 1
            return ""
        event_id = str(d.get("event_id") or "").strip().casefold()
        # Deterministically upgrade authenticated v2 payloads created before
        # stable IDs were introduced. Receiver mode still has the durable
        # inbox open before it accepts a socket.
        if not event_id:
            event_id = hashlib.sha256(body).hexdigest()
        if len(event_id) != 64 or any(ch not in "0123456789abcdef" for ch in event_id):
            self.denied += 1
            return ""
        inbox_id = f"remote-{event_id}"
        if self._inbox is not None and self._inbox.is_delivered(inbox_id):
            return event_id
        if self._inbox is not None:
            self._inbox.enqueue(
                inbox_id,
                {"payload_sha256": hashlib.sha256(body).hexdigest()},
                now=float(d.get("ts") or time.time()),
            )
        origin = _redact_text(d.get("node_origin") or "remote")[:64] or "remote"
        raw_details = d.get("details")
        details = _safe_details(raw_details if isinstance(raw_details, dict) else {})
        if not isinstance(details, dict):
            details = {}
        # Cross-host identifiers have meaning only on the sender. Never expose
        # them under the local-action keys consumed by SOAR/rollback modules.
        # Preserve bounded copies for investigation under an explicit namespace.
        for key in (
            "pid", "ppid", "path", "artifact_path", "exe", "process_path", "image"
        ):
            if key in details:
                details[f"source_{key}"] = details.pop(key)
        source_module = _redact_text(d.get("module") or "REMOTE")[:128] or "REMOTE"
        details.update({
            "node_origin": origin,
            "source_module": source_module,
            "response_authority": REMOTE_OBSERVE_AUTHORITY,
            "remote_event_id": event_id,
        })
        try:
            sev = Severity(int(d.get("severity", int(Severity.INFO))))
        except (ValueError, TypeError):
            sev = Severity.INFO
        msg = f"[{origin}] {_redact_text(d.get('message', ''))}"
        # The transport owns the local module identity. A keyed peer must not be
        # able to impersonate two local detectors and satisfy corroboration.
        self._bus.publish(Event(self.name, msg, sev,
                                time.time(), details))
        if self._inbox is not None:
            self._inbox.complete_pending(inbox_id)
        self.received += 1
        return event_id

    def stop(self) -> None:
        super().stop()
        # The run thread joins admitted helpers before it closes their shared
        # inbox.  ``stop`` remains non-blocking while socket closure interrupts
        # bounded recv calls immediately.
        self._retire_receiver()

    def self_test(self) -> tuple[bool, str]:
        """Verify authenticated ephemeral agreement and an AES-GCM round-trip."""
        key = os.urandom(32)
        server_nonce = os.urandom(32)
        client_nonce = os.urandom(32)
        server_private, server_public = _ephemeral_keypair()
        client_private, client_public = _ephemeral_keypair()
        signed = _proof(
            key,
            b"client",
            server_nonce,
            client_nonce,
            server_public,
            client_public,
        )
        good = hmac.compare_digest(signed, signed)
        tampered = signed
        tampered = tampered[:-1] + ("0" if tampered[-1] != "0" else "1")
        bad = hmac.compare_digest(signed, tampered)
        server_shared = _exchange_ephemeral(server_private, client_public)
        client_shared = _exchange_ephemeral(client_private, server_public)
        session = _session_key(
            key,
            server_nonce,
            client_nonce,
            server_shared,
            server_public,
            client_public,
        )
        peer_session = _session_key(
            key,
            server_nonce,
            client_nonce,
            client_shared,
            server_public,
            client_public,
        )
        del server_private, client_private, server_shared, client_shared
        encrypted = _encrypt(session, b"private telemetry")
        if (
            good
            and not bad
            and hmac.compare_digest(session, peer_session)
            and _decrypt(session, encrypted) == b"private telemetry"
        ):
            mode = self._mode or "idle"
            keyed = "keyed" if self._key else "no-key"
            return True, (
                f"ephemeral X25519 + mutual PSK auth + AES-GCM verified; "
                f"mode={mode}, {keyed}"
            )
        return False, "encrypted mutual-auth self-test failed"


def register() -> RemoteBridge:
    return RemoteBridge()
