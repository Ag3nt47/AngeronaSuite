from __future__ import annotations

import argparse
import threading
import time

import pytest

from tools.personal_sentinel_server import (
    _BoundedThreadingHTTPServer,
    _handler,
    _load_auth_key,
    _load_pem,
    _private_bind,
    main,
)


def test_server_bind_accepts_only_private_or_loopback_literals():
    assert _private_bind("127.0.0.1") == "127.0.0.1"
    assert _private_bind("192.168.50.2") == "192.168.50.2"
    assert _private_bind("fd00::1") == "fd00::1"
    for value in ("0.0.0.0", "::", "8.8.8.8", "169.254.1.1", "sentinel.example"):
        with pytest.raises(argparse.ArgumentTypeError):
            _private_bind(value)


def test_server_auth_key_file_is_strict_hex_and_bounded(tmp_path):
    path = tmp_path / "authority.key"
    path.write_text("ab" * 32 + "\n", encoding="ascii")
    assert _load_auth_key(path) == bytes.fromhex("ab" * 32)
    path.write_text("not-hex\n", encoding="ascii")
    with pytest.raises(ValueError):
        _load_auth_key(path)


def test_production_ed25519_files_separate_signer_and_verify_only_roles(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "authority-private.pem"
    public_path = tmp_path / "client-public.pem"
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    signer = _load_pem(private_path, private=True, key_id="authority-ed25519-v1")
    verifier = _load_pem(public_path, private=False, key_id="authority-ed25519-v1")
    signature = signer.sign(b"receipt")
    assert verifier.verify(b"receipt", signature)
    assert not hasattr(verifier, "sign")


def test_production_server_refuses_to_start_without_tls(tmp_path):
    auth = tmp_path / "authority.key"
    auth.write_text("ab" * 32 + "\n", encoding="ascii")
    with pytest.raises(SystemExit):
        main(
            [
                "--state",
                str(tmp_path / "state.json"),
                "--installation-id",
                "a" * 32,
                "--client-instance-id",
                "b" * 32,
                "--test-hmac-key-file",
                str(auth),
            ]
        )


def test_plaintext_test_mode_requires_loopback_and_environment(tmp_path, monkeypatch):
    auth = tmp_path / "authority.key"
    auth.write_text("ab" * 32 + "\n", encoding="ascii")
    monkeypatch.delenv("ANGERONA_SENTINEL_TEST_ONLY", raising=False)
    with pytest.raises(SystemExit):
        main(
            [
                "--test-only-plaintext",
                "--state",
                str(tmp_path / "state.json"),
                "--installation-id",
                "a" * 32,
                "--client-instance-id",
                "b" * 32,
                "--test-hmac-key-file",
                str(auth),
            ]
        )


def test_production_server_requires_mutual_tls_client_ca(tmp_path):
    with pytest.raises(SystemExit):
        main(
            [
                "--state",
                str(tmp_path / "state.json"),
                "--installation-id",
                "a" * 32,
                "--client-instance-id",
                "b" * 32,
                "--tls-cert",
                str(tmp_path / "server.crt"),
                "--tls-key",
                str(tmp_path / "server.key"),
                "--client-public-key-file",
                str(tmp_path / "client.pub"),
                "--authority-private-key-file",
                str(tmp_path / "authority.key"),
            ]
        )


def test_tls_handshake_stall_does_not_block_dispatch_of_second_connection():
    release = threading.Event()
    dispatched = threading.Event()

    class FakeSocket:
        def __init__(self, stall=False):
            self.stall = stall

        def settimeout(self, _value):
            return None

        def do_handshake(self):
            if self.stall:
                release.wait(1.0)

        def shutdown(self, _how=None):
            return None

        def close(self):
            return None

    class Context:
        @staticmethod
        def wrap_socket(request, **_kwargs):
            return request

    server = _BoundedThreadingHTTPServer(
        ("127.0.0.1", 0),
        _handler(object()),
        tls_context=Context(),
        handshake_timeout=0.5,
    )
    server._dispatch_authenticated = lambda request, _address: (
        dispatched.set() if not request.stall else None
    )
    try:
        started = time.monotonic()
        server.process_request(FakeSocket(stall=True), ("127.0.0.1", 1))
        assert time.monotonic() - started < 0.2
        server.process_request(FakeSocket(stall=False), ("127.0.0.1", 2))
        assert dispatched.wait(0.4)
    finally:
        release.set()
        server.server_close()


def test_server_close_stops_admission_and_drains_preauth_threads():
    entered = threading.Event()
    released = threading.Event()
    dispatched = threading.Event()

    class FakeSocket:
        def settimeout(self, _value):
            return None

        def do_handshake(self):
            entered.set()
            released.wait(1.0)

        def shutdown(self, _how=None):
            released.set()

        def close(self):
            released.set()

    class Context:
        @staticmethod
        def wrap_socket(request, **_kwargs):
            return request

    server = _BoundedThreadingHTTPServer(
        ("127.0.0.1", 0),
        _handler(object()),
        tls_context=Context(),
        handshake_timeout=0.5,
    )
    server.finish_request = lambda _request, _address: dispatched.set()
    socket = FakeSocket()
    server.process_request(socket, ("127.0.0.1", 1))
    assert entered.wait(0.4)

    server.server_close()

    assert released.is_set()
    assert not dispatched.is_set()
    assert not server._preauth_threads
