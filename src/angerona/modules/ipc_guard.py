"""ipc_guard.py — Zero-Trust Local IPC Guard (Code: AUTH).

Purpose
    Provide an authenticated loopback admission primitive and diagnostic probe.
    An exclusive ephemeral loopback listener uses a per-install OS-protected
    secret, fresh client/server nonces and domain-separated mutual proofs.
    No client proof is emitted before the server proves possession for that
    client nonce. There is no v1/raw-nonce signing fallback.

Safety
    The listener authenticates and closes; no production command/data consumer
    is wired through it. Its private in-process self-check proves codec
    consistency, not live TCP routing or protection of other IPC channels.
    A failed self-check is visible degraded health with bounded retries; actual
    accept-worker death remains a lifecycle failure.

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
from angerona.core.engine_transport import (
    EngineError, canonical, decode, receive, send, _nonce, _verify, _wrap,
)

_HOST = "127.0.0.1"
_PORT = 0  # Diagnostic only: no production consumer requires a fixed port.
_AUTH_PROTOCOL = "angerona-diagnostic-auth-v2"
_AUTH_TIMEOUT = 1.0
_AUTH_FRAME = 1024
_PROBE_RETRY_SECONDS = 30.0
_SERVER_DOMAIN = b"diagnostic-auth-v2-server\0"
_CLIENT_DOMAIN = b"diagnostic-auth-v2-client\0"
_ACK_DOMAIN = b"diagnostic-auth-v2-ack\0"
_MAX_CONNECTIONS = 16
_DENIAL_REPORT_INTERVAL = 30.0
_SECRET_NAME = "ANGERONA_IPC_AUTH_KEY"


def _load_or_create_key(path: Path) -> bytes:
    """Load/create the key in the OS store, migrating one exact legacy file."""
    from angerona.core.secure_store import secret_transaction

    with secret_transaction(path.parent):
        return _load_or_create_key_locked(path)


def _load_or_create_key_locked(path: Path) -> bytes:
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
    if _SECRET_NAME in protected:
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


def _guard_key(key: bytes) -> None:
    if type(key) is not bytes or len(key) != 32:
        raise EngineError("Diagnostic authentication needs an exact private key")


def _server_proof(hello: dict, key: bytes) -> dict:
    _guard_key(key)
    if (set(hello) != {"protocol", "nonce"} or hello["protocol"] != _AUTH_PROTOCOL
            or not _nonce(hello["nonce"], 32)):
        raise EngineError("Invalid diagnostic client hello")
    return _wrap(dict(hello, challenge=os.urandom(32).hex()), key, _SERVER_DOMAIN)


def _client_proof(proof: dict, hello: dict, key: bytes) -> dict:
    _guard_key(key)
    body = _verify(proof, key, _SERVER_DOMAIN)
    if (set(body) != {"protocol", "nonce", "challenge"} or body["protocol"] != _AUTH_PROTOCOL
            or body["nonce"] != hello["nonce"] or not _nonce(body["challenge"], 64)):
        raise EngineError("Diagnostic server proof identity mismatch")
    # No client MAC is emitted until the server proves possession for this
    # fresh client nonce. Role-specific domains prohibit reflection/oracles.
    return _wrap(body, key, _CLIENT_DOMAIN)


def _server_accept(proof: dict, reply: dict, key: bytes) -> dict:
    expected = _verify(proof, key, _SERVER_DOMAIN)
    if _verify(reply, key, _CLIENT_DOMAIN) != expected:
        raise EngineError("Diagnostic client proof identity mismatch")
    return _wrap(dict(expected, accepted=True), key, _ACK_DOMAIN)


def _client_accept(ack: dict, proof: dict, key: bytes) -> bool:
    expected = dict(_verify(proof, key, _SERVER_DOMAIN), accepted=True)
    if _verify(ack, key, _ACK_DOMAIN) != expected:
        raise EngineError("Diagnostic acknowledgment identity mismatch")
    return True


def _authenticate_socket(conn, key: bytes, *, timeout: float = _AUTH_TIMEOUT) -> bool:
    _guard_key(key)
    deadline = time.monotonic() + timeout
    hello = {"protocol": _AUTH_PROTOCOL, "nonce": os.urandom(16).hex()}
    send(conn, hello, _AUTH_FRAME, deadline=deadline)
    proof = receive(conn, _AUTH_FRAME, deadline=deadline)
    reply = _client_proof(proof, hello, key)
    send(conn, reply, _AUTH_FRAME, deadline=deadline)
    return _client_accept(receive(conn, _AUTH_FRAME, deadline=deadline), proof, key)


def authenticate(key: bytes, host: str = _HOST, port: int = _PORT,
                 timeout: float = _AUTH_TIMEOUT) -> bool:
    """Mutually authenticate one explicit loopback diagnostic endpoint (v2 only)."""
    if host != _HOST or type(port) is not int or not 1 <= port <= 65535:
        return False
    if type(timeout) not in (int, float) or not 0 < timeout <= 3.0:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            return _authenticate_socket(conn, key, timeout=timeout)
    except (OSError, EngineError):
        return False


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
        self.probe_ok = False
        self.probe_error = "Authentication codec self-check has not run"

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
    description = ("Diagnostic mutual-HMAC admission probe on an exclusive ephemeral loopback port; "
                   "authenticates and closes, with no production payload consumer.")
    category = "Integrity"
    version = "1.14.0"
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
        deadline: float | None = None,
        close: bool = True,
    ) -> None:
        try:
            deadline = time.monotonic() + _AUTH_TIMEOUT if deadline is None else deadline
            auth_key = self._key if key is None else bytes(key)
            hello = receive(conn, _AUTH_FRAME, deadline=deadline)
            proof = _server_proof(hello, auth_key)
            send(conn, proof, _AUTH_FRAME, deadline=deadline)
            ack = _server_accept(proof, receive(conn, _AUTH_FRAME, deadline=deadline), auth_key)
            send(conn, ack, _AUTH_FRAME, deadline=deadline)
            if count_result:
                with self.state_lock:
                    self.accepted += 1
        except (OSError, EngineError):
            if emit_denial:
                self._record_denial(addr, reason="protocol-or-authentication")
        finally:
            if close:
                try:
                    conn.close()
                except OSError:
                    pass

    def _probe_exchange(self, client_key: bytes, server_key: bytes) -> bool:
        """Private codec/self-consistency check; this is not a TCP route probe."""
        def wire(message):
            raw = canonical(message)
            if len(raw) > _AUTH_FRAME:
                raise EngineError("Diagnostic self-check frame exceeds its bound")
            return decode(raw)
        try:
            hello = wire({"protocol": _AUTH_PROTOCOL, "nonce": os.urandom(16).hex()})
            proof = wire(_server_proof(hello, server_key))
            reply = wire(_client_proof(proof, hello, client_key))
            ack = wire(_server_accept(proof, reply, server_key))
            return _client_accept(ack, proof, client_key)
        except EngineError:
            return False

    def _check_codec(self, generation: _IpcGeneration) -> None:
        prior_error = generation.probe_error
        try:
            private_key = os.urandom(32)
            generation.probe_ok = self._probe_exchange(private_key, private_key)
            generation.probe_error = "" if generation.probe_ok else "In-process authentication codec self-check failed"
        except Exception:
            generation.probe_ok = False
            generation.probe_error = "In-process authentication codec self-check is unavailable"
        if generation.probe_ok and self.last_error == prior_error:
            self.last_error = ""
        if not generation.probe_ok:
            self.last_error = generation.probe_error
            self.set_health(20, generation.probe_error)
            self.emit(generation.probe_error + "; listener routing remains unverified and will be retried.",
                      Severity.HIGH, response_authorized=False, production_consumer=False,
                      finding_code="ipc.diagnostic.codec-unavailable")


    def _serve_generation_conn(
        self,
        generation: _IpcGeneration,
        conn: socket.socket,
        addr,
        deadline: float,
    ) -> None:
        try:
            if not generation.stopping():
                self._serve_conn(conn, addr, deadline=deadline, close=False)
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
            deadline = time.monotonic() + _AUTH_TIMEOUT
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
                helper = None
                try:
                    helper = threading.Thread(
                        target=self._serve_generation_conn,
                        args=(generation, conn, addr, deadline),
                        name="AUTH-conn",
                        daemon=True,
                    )
                    generation.connections.add(conn)
                    generation.helpers.add(helper)
                    helper.start()
                except Exception as exc:
                    generation.connections.discard(conn)
                    if helper is not None:
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
            if os.name == "nt":
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            srv.bind((_HOST, 0))     # Exclusive ephemeral diagnostic listener, loopback only
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
            self.set_health(40, f"could not establish an exclusive diagnostic listener ({exc})")
            # keep module alive but idle; sign/verify helpers still usable
            while not generation.stopping():
                self.sleep(5.0)
            return
        self.emit(
            f"AUTH diagnostic admission probe online on {_HOST}:{int(srv.getsockname()[1])}; authenticated "
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
        next_probe = 0.0
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
            now = time.monotonic()
            if now >= next_probe:
                self._check_codec(generation)
                next_probe = now + _PROBE_RETRY_SECONDS
            with self.state_lock:
                a, d = self.accepted, self.denied
            if generation.probe_ok:
                self.set_health(100, f"In-process mutual-auth codec verified; listener accepting; "
                                f"live TCP routing unverified; {a} authorized, {d} denied")
            else:
                self.set_health(20, generation.probe_error + "; listener routing unverified")
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
        """Prove isolated mutual-auth codec consistency; live TCP routing is unverified."""
        production_key = self._key
        key = os.urandom(32)
        nonce = os.urandom(16)
        if not verify(key, nonce, sign(key, nonce)):
            return False, "HMAC verify rejected a valid signature"
        if verify(key, nonce, sign(key, nonce)[:-1] + ("0" if sign(key, nonce)[-1] != "0" else "1")):
            return False, "HMAC verify accepted a tampered signature"

        # Pure codec proof uses only synthetic keys and bounded in-memory
        # messages. It neither contacts nor changes the production listener.
        good = self._probe_exchange(key, key)
        bad = self._probe_exchange(os.urandom(32), key)
        if self._key != production_key:
            return False, "self-test changed the live authentication key"
        if good and not bad:
            return True, "isolated HMAC + in-process mutual-auth codec verified; live TCP routing unverified"
        return False, f"in-process codec self-check failed (valid={good}, wrong-key={bad})"


def register() -> IpcGuardModule:
    return IpcGuardModule()
