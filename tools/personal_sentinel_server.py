#!/usr/bin/env python
"""Run the narrow Personal Sentinel CAS/time authority.

Production mode requires TLS.  Plain HTTP is available only on loopback when
both a conspicuous CLI switch and a test-only environment variable are set.
This server has no router discovery, router credentials, management endpoints,
firewall mutation, or arbitrary command surface.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from angerona.core.personal_sentinel_authority import (  # noqa: E402
    Ed25519PrivateSigner,
    Ed25519PublicVerifier,
    HmacSha256Authenticator,
    MAX_REQUEST_BYTES,
    PersonalSentinelAuthority,
    SentinelRequestRejected,
    SentinelStateIntegrityError,
)


def _private_bind(value: str) -> str:
    candidate = str(value or "").strip()
    if candidate.casefold() == "localhost":
        return candidate
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("bind must be localhost or a private IP literal") from exc
    if address.is_unspecified or address.is_multicast or address.is_link_local:
        raise argparse.ArgumentTypeError("wildcard, multicast, and link-local binds are forbidden")
    if not (address.is_loopback or address.is_private):
        raise argparse.ArgumentTypeError("public authority binds are forbidden")
    return str(address)


def _identity(value: str) -> str:
    candidate = str(value or "").strip().casefold()
    if len(candidate) != 32 or any(character not in "0123456789abcdef" for character in candidate):
        raise argparse.ArgumentTypeError("identity must be exactly 32 lowercase hexadecimal characters")
    return candidate


def _load_auth_key(path: Path) -> bytes:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file() or not 64 <= resolved.stat().st_size <= 257:
        raise ValueError("authority authentication key file size is invalid")
    text = resolved.read_text(encoding="ascii").strip()
    if len(text) % 2 or not 64 <= len(text) <= 256:
        raise ValueError("authority authentication key must be 32 to 128 bytes of hex")
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("authority authentication key is not hexadecimal") from exc
    if not 32 <= len(key) <= 128:
        raise ValueError("authority authentication key length is invalid")
    return key


def _load_pem(path: Path, *, private: bool, key_id: str):
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file() or not 64 <= resolved.stat().st_size <= 64 * 1024:
        raise ValueError("Sentinel Ed25519 key file size is invalid")
    before = resolved.stat()
    pem = resolved.read_bytes()
    after = resolved.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("Sentinel Ed25519 key changed during read")
    if private:
        return Ed25519PrivateSigner.from_pem(pem, key_id=key_id)
    return Ed25519PublicVerifier.from_pem(pem, key_id=key_id)


def _require_protected_production_path(path: Path, label: str, *, may_be_absent: bool = False) -> Path:
    """Reject links and weak custody before production reads or creates secrets."""

    candidate = path.expanduser()
    reparse = False
    if os.name == "nt":
        try:
            from angerona.core.data_paths import _is_reparse_point

            reparse = _is_reparse_point(candidate) or _is_reparse_point(candidate.parent)
        except Exception:
            reparse = True
    if candidate.is_symlink() or candidate.parent.is_symlink() or reparse:
        raise ValueError(f"{label} cannot be a symbolic link or reparse alias")
    if may_be_absent:
        parent = candidate.parent.resolve(strict=True)
        resolved = parent / candidate.name
    else:
        resolved = candidate.resolve(strict=True)
        parent = resolved.parent
    from angerona.core.hardening import sensitive_file_is_protected

    if not sensitive_file_is_protected(parent):
        raise ValueError(f"{label} parent is outside protected custody")
    if resolved.exists() and not sensitive_file_is_protected(resolved):
        raise ValueError(f"{label} is outside protected custody")
    return resolved


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    # Worker requests are bounded by socket timeouts and must be drained before
    # the authority lease is released.  ThreadingMixIn tracks and joins these
    # non-daemon workers from ``server_close``.
    daemon_threads = False
    block_on_close = True
    request_queue_size = 16

    def __init__(
        self,
        *args,
        tls_context: ssl.SSLContext | None = None,
        handshake_timeout: float = 3.0,
        **kwargs,
    ):
        if not 0.5 <= float(handshake_timeout) <= 10.0:
            raise ValueError("TLS handshake timeout is invalid")
        self._tls_context = tls_context
        self._handshake_timeout = float(handshake_timeout)
        self._preauth_slots = threading.BoundedSemaphore(16)
        self._worker_slots = threading.BoundedSemaphore(32)
        self._admission_lock = threading.RLock()
        self._preauth_threads: set[threading.Thread] = set()
        self._preauth_requests: dict[threading.Thread, object] = {}
        self._draining = False
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address) -> None:
        if self._tls_context is not None:
            with self._admission_lock:
                if self._draining or not self._preauth_slots.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                thread = threading.Thread(
                    target=self._handshake_and_dispatch,
                    args=(request, client_address),
                    daemon=False,
                    name="sentinel-preauth",
                )
                self._preauth_threads.add(thread)
                self._preauth_requests[thread] = request
                thread.start()
            return
        self._dispatch_authenticated(request, client_address)

    def _handshake_and_dispatch(self, request, client_address) -> None:
        secured = None
        try:
            request.settimeout(self._handshake_timeout)
            secured = self._tls_context.wrap_socket(
                request,
                server_side=True,
                do_handshake_on_connect=False,
            )
            secured.settimeout(self._handshake_timeout)
            secured.do_handshake()
            secured.settimeout(10.0)
        except Exception:
            self.shutdown_request(secured or request)
            return
        finally:
            self._preauth_slots.release()
            current = threading.current_thread()
            with self._admission_lock:
                self._preauth_threads.discard(current)
                self._preauth_requests.pop(current, None)
        self._dispatch_authenticated(secured, client_address)

    def _dispatch_authenticated(self, request, client_address) -> None:
        with self._admission_lock:
            if self._draining or not self._worker_slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except Exception:
                self._worker_slots.release()
                raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()

    def server_close(self) -> None:
        """Stop admission and drain bounded handshake/request workers."""

        with self._admission_lock:
            self._draining = True
            preauth = tuple(self._preauth_threads)
            requests = tuple(self._preauth_requests.values())
        # Close the listener and join all ThreadingMixIn request workers first.
        # No handshake can dispatch a new worker after ``_draining`` is set.
        super().server_close()
        for request in requests:
            self.shutdown_request(request)
        deadline = time.monotonic() + self._handshake_timeout + 1.0
        for thread in preauth:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the Personal Sentinel signed CAS/time authority",
    )
    parser.add_argument("--bind", type=_private_bind, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--installation-id", type=_identity, required=True)
    parser.add_argument("--client-instance-id", type=_identity, required=True)
    parser.add_argument(
        "--client-public-key-file",
        type=Path,
        help="production Ed25519 client request-verification public key",
    )
    parser.add_argument("--client-key-id", default="sentinel-client-ed25519-v1")
    parser.add_argument(
        "--authority-private-key-file",
        type=Path,
        help="production appliance-only Ed25519 receipt/state private key",
    )
    parser.add_argument("--authority-key-id", default="sentinel-authority-ed25519-v1")
    parser.add_argument(
        "--test-hmac-key-file",
        type=Path,
        help="symmetric key accepted only by explicit loopback test mode",
    )
    parser.add_argument("--test-hmac-key-id", default="sentinel-test-hmac-v1")
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    parser.add_argument(
        "--client-ca",
        type=Path,
        help="optional CA file that makes client certificates mandatory",
    )
    parser.add_argument(
        "--test-only-plaintext",
        action="store_true",
        help="loopback-only test transport; production always requires TLS",
    )
    return parser


def _handler(authority: PersonalSentinelAuthority):
    class AuthorityHandler(BaseHTTPRequestHandler):
        server_version = "PersonalSentinel/1"
        sys_version = ""

        def setup(self) -> None:
            self.request.settimeout(10.0)
            super().setup()

        def _reply(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            if self.path != "/v1/authority":
                self._reply(404, b'{"error":"not-found"}')
                return
            content_types = self.headers.get_all("Content-Type", failobj=[])
            if (
                len(content_types) != 1
                or self.headers.get_content_type().casefold() != "application/json"
            ):
                self._reply(415, b'{"error":"content-type-rejected"}')
                return
            if self.headers.get("Transfer-Encoding") is not None:
                self._reply(400, b'{"error":"transfer-encoding-rejected"}')
                return
            if self.headers.get("Content-Encoding") is not None:
                self._reply(415, b'{"error":"content-encoding-rejected"}')
                return
            lengths = self.headers.get_all("Content-Length", failobj=[])
            if len(lengths) != 1:
                self._reply(400, b'{"error":"content-length-required"}')
                return
            try:
                length = int(lengths[0])
            except (TypeError, ValueError):
                self._reply(400, b'{"error":"content-length-invalid"}')
                return
            if not 1 <= length <= MAX_REQUEST_BYTES:
                self._reply(413, b'{"error":"request-size-rejected"}')
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self._reply(400, b'{"error":"request-body-incomplete"}')
                return
            try:
                response = authority.process(body)
            except SentinelRequestRejected:
                self._reply(409, b'{"error":"authenticated-request-rejected"}')
                return
            except SentinelStateIntegrityError:
                self._reply(503, b'{"error":"authority-state-untrusted"}')
                return
            except Exception:
                self._reply(500, b'{"error":"authority-failed-closed"}')
                return
            self._reply(200, response)

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            self._reply(405, b'{"error":"method-not-allowed"}')

        def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
            self._reply(405, b'{"error":"method-not-allowed"}')

        def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
            self._reply(405, b'{"error":"method-not-allowed"}')

        def log_message(self, _format: str, *_args) -> None:
            # Do not echo client addresses, nonces, or malformed request text.
            return

    return AuthorityHandler


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    plaintext = bool(args.test_only_plaintext)
    if plaintext:
        try:
            address = ipaddress.ip_address("127.0.0.1" if args.bind == "localhost" else args.bind)
        except ValueError:
            parser.error("test-only plaintext bind must resolve to loopback")
        if not address.is_loopback or os.environ.get("ANGERONA_SENTINEL_TEST_ONLY") != "1":
            parser.error(
                "plaintext requires loopback plus ANGERONA_SENTINEL_TEST_ONLY=1"
            )
        if args.tls_cert or args.tls_key or args.client_ca:
            parser.error("test-only plaintext cannot accept TLS options")
        if args.test_hmac_key_file is None:
            parser.error("test-only plaintext requires --test-hmac-key-file")
        if args.client_public_key_file or args.authority_private_key_file:
            parser.error("test-only HMAC mode cannot accept production Ed25519 keys")
    else:
        if args.tls_cert is None or args.tls_key is None or args.client_ca is None:
            parser.error(
                "production mode requires --tls-cert, --tls-key, and --client-ca for mTLS"
            )
        if args.client_public_key_file is None or args.authority_private_key_file is None:
            parser.error(
                "production mode requires separate Ed25519 client-public and authority-private keys"
            )
        if args.test_hmac_key_file is not None:
            parser.error("production mode forbids symmetric HMAC authority credentials")
        try:
            args.client_public_key_file = _require_protected_production_path(
                args.client_public_key_file, "client request-verification public key"
            )
            args.tls_key = _require_protected_production_path(
                args.tls_key, "TLS private key"
            )
            args.authority_private_key_file = _require_protected_production_path(
                args.authority_private_key_file, "authority Ed25519 private key"
            )
            args.client_ca = _require_protected_production_path(
                args.client_ca, "mTLS client CA"
            )
            args.state = _require_protected_production_path(
                args.state, "authority state", may_be_absent=True
            )
        except Exception as exc:
            parser.error(f"production custody rejected: {exc}")
    try:
        if plaintext:
            test_authenticator = HmacSha256Authenticator(
                _load_auth_key(args.test_hmac_key_file),
                key_id=args.test_hmac_key_id,
            )
            request_verifier = test_authenticator
            response_signer = test_authenticator
            response_verifier = test_authenticator
        else:
            request_verifier = _load_pem(
                args.client_public_key_file,
                private=False,
                key_id=args.client_key_id,
            )
            response_signer = _load_pem(
                args.authority_private_key_file,
                private=True,
                key_id=args.authority_key_id,
            )
            response_verifier = response_signer.public_verifier()
        authority = PersonalSentinelAuthority(
            args.state.expanduser().resolve(),
            installation_id=args.installation_id,
            client_instance_id=args.client_instance_id,
            request_verifier=request_verifier,
            response_signer=response_signer,
            response_verifier=response_verifier,
        )
    except Exception as exc:
        parser.error(f"authority configuration rejected: {exc}")

    context = None
    if not plaintext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=str(args.tls_cert.expanduser().resolve(strict=True)),
            keyfile=str(args.tls_key.expanduser().resolve(strict=True)),
        )
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(args.client_ca.resolve(strict=True)))
        print(
            "Personal Sentinel: local signed state is active; full appliance snapshot "
            "rollback still requires an injected TPM or independent generation floor.",
            file=sys.stderr,
        )
    server = _BoundedThreadingHTTPServer(
        (args.bind, args.port),
        _handler(authority),
        tls_context=context,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        authority.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
