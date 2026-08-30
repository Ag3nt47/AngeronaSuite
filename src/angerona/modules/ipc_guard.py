"""ipc_guard.py — Zero-Trust Local IPC Guard (Code: AUTH).

Purpose
    Provide an authenticated loopback admission primitive and diagnostic probe.
    Every peer that connects to ``127.0.0.1:65432`` must
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
    Loopback-only, OS-protected local secret, read/verify only. The current
    server proves peer possession and then closes; no production command/data
    consumer is wired through this socket. It must therefore not be described as
    protecting unrelated Angerona IPC paths.

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
_MAX_CONNECTIONS = 16
_DENIAL_REPORT_INTERVAL = 30.0
_SECRET_NAME = "ANGERONA_IPC_AUTH_KEY"


def _load_or_create_key(path: Path) -> bytes:
    """Load/create the key in the OS store, migrating one exact legacy file."""
    from angerona.core.secure_store import read_secret_values, write_secret_map

    data_root = path.parent
    protected = read_secret_values((_SECRET_NAME,), data_root, strict=True)
    encoded = protected.get(_SECRET_NAME, "")
    if len(encoded) == 64:
        try:
            key = bytes.fromhex(encoded)
        except ValueError:
            pass
        else:
            # A prior migration may have committed protected storage but failed
            # to remove its plaintext source. Never listen until the residue is
            # either proven identical and removed or explicitly remediated.
            try:
                info = path.lstat()
            except FileNotFoundError:
                return key
            if (
                path.is_symlink()
                or not path.is_file()
                or info.st_size != 32
                or not hmac.compare_digest(path.read_bytes(), key)
            ):
                raise RuntimeError(
                    "plaintext IPC key residue is unsafe or differs from protected storage"
                )
            try:
                path.unlink()
            except OSError as exc:
                raise RuntimeError(
                    "plaintext IPC key residue could not be removed"
                ) from exc
            return key
    if encoded:
        raise RuntimeError("protected IPC authentication key has an invalid format")

    legacy: bytes | None = None
    try:
        info = path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_size != 32:
            raise RuntimeError("legacy IPC authentication key is not an exact regular file")
        legacy = path.read_bytes()
    except FileNotFoundError:
        pass
    key = legacy if legacy is not None else os.urandom(32)
    write_secret_map({_SECRET_NAME: key.hex()}, data_root)
    accepted = read_secret_values((_SECRET_NAME,), data_root, strict=True).get(
        _SECRET_NAME, ""
    )
    if not hmac.compare_digest(accepted, key.hex()):
        raise RuntimeError("OS credential store did not verify the IPC authentication key")
    if legacy is not None:
        try:
            path.unlink()
        except OSError as exc:
            raise RuntimeError(
                "protected IPC key was accepted but the plaintext legacy key could not be removed"
            ) from exc
    return key


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


class _IpcGeneration:
    """Socket and helper ownership for one module run generation."""

    def __init__(self, generation_stop: threading.Event) -> None:
        self.generation_stop = generation_stop
        self.helper_stop = threading.Event()
        self.lock = threading.RLock()
        self.srv: socket.socket | None = None
        self.accept_thread: threading.Thread | None = None
        self.connections: set[socket.socket] = set()
        self.helpers: set[threading.Thread] = set()
        self.connection_slots = threading.BoundedSemaphore(_MAX_CONNECTIONS)
        self.fatal_error = ""

    def stopping(self) -> bool:
        return self.generation_stop.is_set() or self.helper_stop.is_set()

    def retire(self) -> None:
        """Wake/close this generation without mutating a later generation."""
        self.helper_stop.set()
        with self.lock:
            srv = self.srv
            self.srv = None
            conns = list(self.connections)
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    def join_helpers(self) -> None:
        """Wait off the caller thread until every owned helper has exited."""
        current = threading.current_thread()
        accept_thread = self.accept_thread
        if accept_thread is not None and accept_thread is not current:
            accept_thread.join()
        while True:
            with self.lock:
                helpers = [thread for thread in self.helpers
                           if thread is not current]
            if not helpers:
                return
            for thread in helpers:
                thread.join()


class IpcGuardModule(BaseModule):
    CODE = "AUTH"
    NAME = "Zero-Trust Local IPC Guard"
    name = "Zero-Trust Local IPC Guard"
    description = ("Diagnostic HMAC-SHA256 admission probe on 127.0.0.1:65432; "
                   "authenticates and closes, with no production payload consumer.")
    category = "Integrity"
    version = "1.12.1"
    supported_platforms = ("windows", "macos", "linux")
    capability_mode = "observe"
    maturity_channel = "preview"
    capability_inputs = ("loopback-authentication-probe",)
    capability_outputs = ("diagnostic-peer-decision", "bounded-health-event")
    capability_permissions = ("loopback-listen", "local-secret-read-write")
    data_classes = ("local-peer-address", "authentication-result")
    egress = "none"
    retention = "bounded-counters-only"
    response_authority = "none"

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._key: bytes = b""
        self._srv: socket.socket | None = None
        self._server_lock = threading.RLock()
        self._server_generation: _IpcGeneration | None = None
        self.accepted = 0
        self.denied = 0
        self._last_denial_emit = 0.0
        self._suppressed_denials = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── server ───────────────────────────────────────────────────────────────
    def _record_denial(self, addr: object, *, reason: str) -> None:
        """Count every refusal while rate-limiting attacker-controlled events."""
        now = time.monotonic()
        with self.state_lock:
            self.denied += 1
            if (
                self._last_denial_emit > 0
                and now - self._last_denial_emit < _DENIAL_REPORT_INTERVAL
            ):
                self._suppressed_denials += 1
                return
            suppressed = self._suppressed_denials
            self._suppressed_denials = 0
            self._last_denial_emit = now
        self.emit(
            "Zero-trust IPC authentication refused a local peer.",
            Severity.HIGH,
            peer=str(addr)[:160],
            reason=str(reason)[:80],
            suppressed_since_last=suppressed,
            response_authorized=False,
        )

    def _serve_conn(
        self,
        conn: socket.socket,
        addr,
        *,
        key: bytes | None = None,
        emit_denial: bool = True,
        count_result: bool = True,
    ) -> None:
        try:
            conn.settimeout(4.0)
            nonce = os.urandom(16).hex().encode("ascii")
            conn.sendall(b"CHALLENGE " + nonce + b"\n")
            data = conn.recv(256).decode("ascii", "ignore").strip()
            sig = data.split(" ", 1)[1] if data.startswith("AUTH ") else ""
            auth_key = self._key if key is None else bytes(key)
            if verify(auth_key, nonce, sig):
                conn.sendall(b"OK\n")
                if count_result:
                    with self.state_lock:
                        self.accepted += 1
            else:
                conn.sendall(b"DENY\n")
                if emit_denial:
                    self._record_denial(addr, reason="invalid-hmac")
        except Exception as exc:
            self.last_error = str(exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _serve_generation_conn(
        self,
        generation: _IpcGeneration,
        conn: socket.socket,
        addr,
    ) -> None:
        try:
            if not generation.stopping():
                self._serve_conn(conn, addr)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with generation.lock:
                generation.connections.discard(conn)
                generation.helpers.discard(threading.current_thread())
            generation.connection_slots.release()

    def _accept_loop(self, generation: _IpcGeneration) -> None:
        srv = generation.srv
        if srv is None:
            return
        while not generation.stopping():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not generation.stopping():
                    generation.fatal_error = f"listener accept failed: {exc}"
                    generation.helper_stop.set()
                break
            if not generation.connection_slots.acquire(blocking=False):
                try:
                    conn.close()
                except OSError:
                    pass
                self._record_denial(addr, reason="connection-capacity")
                continue
            with generation.lock:
                if generation.stopping():
                    try:
                        conn.close()
                    except OSError:
                        pass
                    generation.connection_slots.release()
                    break
                helper = threading.Thread(
                    target=self._serve_generation_conn,
                    args=(generation, conn, addr),
                    name="AUTH-conn",
                    daemon=True,
                )
                generation.connections.add(conn)
                generation.helpers.add(helper)
                try:
                    helper.start()
                except Exception as exc:
                    generation.connections.discard(conn)
                    generation.helpers.discard(helper)
                    try:
                        conn.close()
                    except OSError:
                        pass
                    generation.connection_slots.release()
                    self.last_error = str(exc)
                    self.set_health(40, f"authentication worker unavailable: {exc}")
                    self._record_denial(addr, reason="worker-start-failure")
                    generation.fatal_error = f"authentication worker unavailable: {exc}"
                    generation.helper_stop.set()
                    break

    def run(self) -> None:
        generation = _IpcGeneration(self.generation_stop_event())
        with self._server_lock:
            self._server_generation = generation
        try:
            self._run_generation(generation)
        finally:
            generation.retire()
            generation.join_helpers()
            with self._server_lock:
                if self._server_generation is generation:
                    self._server_generation = None
                    self._srv = None

    def _run_generation(self, generation: _IpcGeneration) -> None:
        from angerona.core.config import Config
        try:
            self._key = _load_or_create_key(Config().data_dir / "ipc_auth.key")
        except Exception as exc:
            self.last_error = str(exc)
            self.set_health(0, f"protected authentication key unavailable: {exc}")
            self.emit(
                "AUTH diagnostic probe refused to listen without verified OS-protected key material.",
                Severity.HIGH,
                response_authorized=False,
            )
            while not generation.stopping():
                self.sleep(5.0)
            return
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((_HOST, _PORT))     # loopback only
            srv.listen(_MAX_CONNECTIONS)
            srv.settimeout(1.0)
            with generation.lock:
                generation.srv = srv
            with self._server_lock:
                if self._server_generation is generation:
                    self._srv = srv
        except OSError as exc:
            try:
                srv.close()
            except (OSError, UnboundLocalError):
                pass
            self.last_error = str(exc)
            self.set_health(40, f"could not bind {_HOST}:{_PORT} ({exc}) — is a guard already up?")
            # keep module alive but idle; sign/verify helpers still usable
            while not self.stopping:
                self.sleep(5.0)
            return
        self.emit(
            f"AUTH diagnostic admission probe online on {_HOST}:{_PORT}; authenticated "
            "connections carry no production payload.",
            Severity.INFO,
            production_consumer=False,
            response_authorized=False,
        )
        accept_thread = threading.Thread(
            target=self._accept_loop,
            args=(generation,),
            name="AUTH-accept",
            daemon=True,
        )
        generation.accept_thread = accept_thread
        try:
            accept_thread.start()
        except Exception as exc:
            generation.fatal_error = f"listener worker could not start: {exc}"
            self.set_health(20, generation.fatal_error)
            raise RuntimeError(generation.fatal_error) from exc
        try:
            bound_port = int(srv.getsockname()[1])
            live_probe = authenticate(self._key, _HOST, bound_port, timeout=2.0)
        except Exception as exc:
            live_probe = False
            generation.fatal_error = f"listener health probe failed: {exc}"
        if not live_probe:
            if not generation.fatal_error:
                generation.fatal_error = "listener health probe was not authenticated"
            generation.helper_stop.set()
            self.set_health(20, generation.fatal_error)
            raise RuntimeError(generation.fatal_error)
        while not generation.stopping():
            if generation.fatal_error:
                self.last_error = generation.fatal_error
                self.set_health(20, generation.fatal_error)
                raise RuntimeError(generation.fatal_error)
            if not accept_thread.is_alive():
                generation.fatal_error = "listener accept worker exited unexpectedly"
                self.last_error = generation.fatal_error
                self.set_health(20, generation.fatal_error)
                raise RuntimeError(generation.fatal_error)
            with self.state_lock:
                a, d = self.accepted, self.denied
            self.set_health(
                100,
                f"authenticated live listener; {a} authorized, {d} denied",
            )
            self.sleep(5.0)
        if generation.fatal_error and not generation.generation_stop.is_set():
            self.last_error = generation.fatal_error
            self.set_health(20, generation.fatal_error)
            raise RuntimeError(generation.fatal_error)

    def stop(self) -> None:
        super().stop()
        with self._server_lock:
            generation = self._server_generation
        if generation is not None:
            generation.retire()

    def self_test(self) -> tuple[bool, str]:
        """Prove HMAC verify (accept valid / reject tampered) AND a real loopback
        challenge/response round-trip on an ephemeral port (valid vs wrong key)."""
        production_key = self._key
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
        results = {}

        def _once(tag: str):
            try:
                conn, addr = srv.accept()
                self._serve_conn(
                    conn,
                    addr,
                    key=key,
                    emit_denial=False,
                    count_result=False,
                )
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

        if self._key != production_key:
            return False, "self-test changed the live authentication key"
        if good and not bad:
            return True, "isolated HMAC + loopback handshake verified (valid OK, wrong-key DENY)"
        return False, f"handshake failed (valid={good}, wrong-key={bad}, {results})"


def register() -> IpcGuardModule:
    return IpcGuardModule()
