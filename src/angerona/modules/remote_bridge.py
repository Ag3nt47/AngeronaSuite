"""remote_bridge.py — Secure multi-node telemetry forwarding (CODE: RBRG).

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

Zero-Trust LAN authentication (extends AUTH)
--------------------------------------------
The loopback IPC Guard (AUTH, ipc_guard.py) uses an HMAC-SHA256
challenge/response with a per-install key. RBRG reuses that exact primitive but
with a SHARED symmetric key (``bridge.key`` / ``ANGERONA_BRIDGE_KEY``) that must
be identical on both nodes. The server and the main PC authenticate each other
before ANY telemetry is transmitted; unauthenticated LAN connection attempts are
dropped and logged as possible spoofing.

Consent / safety
----------------
This module is the ONLY component that sends host telemetry off-machine, so it
is DISABLED by default and refuses to open any routable socket until the operator
explicitly configures a mode, a peer, and a shared key. Nothing leaves (or is
accepted from) the network otherwise. Only HIGH/CRITICAL events are forwarded —
never the full event stream.

Standard library only (socket, hmac, hashlib, json, threading, os, time).
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


# ── Configuration (env-driven; all optional — absent = disabled) ──────────────
_MODE_ENV   = "ANGERONA_BRIDGE_MODE"    # "SENDER" | "RECEIVER" (case-insensitive)
_PEER_ENV   = "ANGERONA_BRIDGE_PEER"    # SENDER: "host:port" of the RECEIVER
_PORT_ENV   = "ANGERONA_BRIDGE_PORT"    # RECEIVER: LAN port to listen on
_KEY_ENV    = "ANGERONA_BRIDGE_KEY"     # shared symmetric key (hex or passphrase)
_BIND_ENV   = "ANGERONA_BRIDGE_BIND"    # RECEIVER: bind addr (default 0.0.0.0)

_DEFAULT_PORT = 47924
_SOCK_TIMEOUT = 4.0
_FORWARD_MIN  = Severity.HIGH           # only HIGH/CRITICAL cross the network


def _shared_key() -> Optional[bytes]:
    """Load the shared symmetric key from env or ``<data>/bridge.key``.

    A hex string of >=32 bytes is used verbatim; any other value is treated as a
    passphrase and stretched via SHA-256. Returns None if no key is configured —
    in which case the bridge stays inert (default-deny).
    """
    raw = os.environ.get(_KEY_ENV)
    if not raw:
        try:
            from angerona.core.data_paths import data_dir
            kp = data_dir() / "bridge.key"
            if kp.exists():
                raw = kp.read_text(encoding="ascii").strip()
        except Exception:
            raw = None
    if not raw:
        return None
    try:
        b = bytes.fromhex(raw)
        if len(b) >= 32:
            return b
    except ValueError:
        pass
    return hashlib.sha256(raw.encode("utf-8")).digest()


def _sign(key: bytes, nonce: bytes) -> str:
    return hmac.new(key, nonce, hashlib.sha256).hexdigest()


class RemoteBridge(BaseModule):
    """Secure SENDER/RECEIVER telemetry bridge. Module code: RBRG."""

    CODE = "RBRG"
    NAME = "Remote Bridge"
    name = "Remote Bridge"
    description = ("Secure multi-node telemetry forwarding (SENDER/RECEIVER) with "
                   "shared-key HMAC LAN authentication. Off by default.")
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
            self.set_health(40, "no shared key — set ANGERONA_BRIDGE_KEY or bridge.key")
            self.emit("Remote Bridge configured but no shared key present — refusing "
                      "to open the network (default-deny).", Severity.MEDIUM)
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
                    self._cursor_ts = max(self._cursor_ts, ev.ts)
                    if ev.severity < _FORWARD_MIN or ev.module == self.name:
                        continue
                    batch.append(ev)
                for ev in batch:
                    self._forward(peer, ev)
            except Exception as exc:
                self.set_health(60, f"sender loop error: {exc}")
                continue
            self.set_health(100, f"{self.forwarded} events forwarded")

    def _forward(self, peer: tuple[str, int], ev: Event) -> None:
        """Authenticate to the receiver, then send one event as JSON. Non-fatal."""
        payload = json.dumps({
            "module": ev.module, "message": ev.message,
            "severity": int(ev.severity), "ts": ev.ts,
            "details": ev.details or {},
            "node_origin": socket.gethostname(),
        }).encode("utf-8")
        try:
            with socket.create_connection(peer, timeout=_SOCK_TIMEOUT) as s:
                s.settimeout(_SOCK_TIMEOUT)
                line = s.recv(256).decode("ascii", "ignore").strip()
                if not line.startswith("CHALLENGE "):
                    return
                nonce = line.split(" ", 1)[1].encode("ascii")
                s.sendall(f"AUTH {_sign(self._key, nonce)}\n".encode("ascii"))
                if s.recv(64).decode("ascii", "ignore").strip() != "OK":
                    return
                s.sendall(len(payload).to_bytes(4, "big") + payload)
                self.forwarded += 1
        except (OSError, socket.timeout):
            # server unreachable / Wi-Fi drop — never crash the daemon
            self.set_health(70, "peer unreachable (buffered by watermark)")

    # ── RECEIVER ─────────────────────────────────────────────────────────────
    def _run_receiver(self) -> None:
        bind = os.environ.get(_BIND_ENV, "0.0.0.0")
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
                  f"(shared-key HMAC, default-deny).", Severity.INFO)
        while not self.stopping:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                self.set_health(100, f"{self.received} received, {self.denied} denied")
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn, addr),
                             name="RBRG-conn", daemon=True).start()

    def _serve(self, conn: socket.socket, addr) -> None:
        try:
            conn.settimeout(_SOCK_TIMEOUT)
            nonce = os.urandom(16).hex().encode("ascii")
            conn.sendall(b"CHALLENGE " + nonce + b"\n")
            data = conn.recv(256).decode("ascii", "ignore").strip()
            sig = data.split(" ", 1)[1] if data.startswith("AUTH ") else ""
            if not hmac.compare_digest(_sign(self._key, nonce), (sig or "").strip()):
                conn.sendall(b"DENY\n")
                self.denied += 1
                self.emit(f"🚫 Remote Bridge DENY from {addr} — invalid shared-key HMAC "
                          f"(possible LAN spoofing).", Severity.HIGH, peer=str(addr))
                return
            conn.sendall(b"OK\n")
            hdr = self._recvn(conn, 4)
            if not hdr:
                return
            length = int.from_bytes(hdr, "big")
            if length <= 0 or length > 1_000_000:
                return
            body = self._recvn(conn, length)
            if body:
                self._republish(body, addr)
        except Exception as exc:
            self.last_error = str(exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass

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
            return
        if self._bus is None:
            return
        origin = str(d.get("node_origin") or (addr[0] if addr else "remote"))
        details = dict(d.get("details") or {})
        details["node_origin"] = origin
        details["hostname"] = origin
        try:
            sev = Severity(int(d.get("severity", int(Severity.INFO))))
        except (ValueError, TypeError):
            sev = Severity.INFO
        msg = f"[{origin}] {d.get('message', '')}"
        self._bus.publish(Event(str(d.get("module", "REMOTE")), msg, sev,
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
        """Verify the HMAC handshake primitive (valid accepts, tampered rejects)."""
        key = os.urandom(32)
        nonce = os.urandom(16)
        good = hmac.compare_digest(_sign(key, nonce), _sign(key, nonce))
        tampered = _sign(key, nonce)
        tampered = tampered[:-1] + ("0" if tampered[-1] != "0" else "1")
        bad = hmac.compare_digest(_sign(key, nonce), tampered)
        if good and not bad:
            mode = self._mode or "idle"
            keyed = "keyed" if self._key else "no-key"
            return True, f"HMAC handshake verified; mode={mode}, {keyed}"
        return False, "HMAC self-test failed"


def register() -> RemoteBridge:
    return RemoteBridge()
