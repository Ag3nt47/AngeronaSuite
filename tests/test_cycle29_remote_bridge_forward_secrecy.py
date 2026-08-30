from __future__ import annotations

import hashlib
import hmac
import os

import pytest

pytest.importorskip("cryptography")

from cryptography.exceptions import InvalidTag

from angerona.modules import remote_bridge


def _agreement(
    key: bytes,
    server_nonce: bytes,
    client_nonce: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    server_private, server_public = remote_bridge._ephemeral_keypair()
    client_private, client_public = remote_bridge._ephemeral_keypair()
    server_shared = remote_bridge._exchange_ephemeral(server_private, client_public)
    client_shared = remote_bridge._exchange_ephemeral(client_private, server_public)
    assert hmac.compare_digest(server_shared, client_shared)
    server_session = remote_bridge._session_key(
        key,
        server_nonce,
        client_nonce,
        server_shared,
        server_public,
        client_public,
    )
    client_session = remote_bridge._session_key(
        key,
        server_nonce,
        client_nonce,
        client_shared,
        server_public,
        client_public,
    )
    return server_session, client_session, server_public, client_public


def test_ephemeral_peers_agree_but_fresh_sessions_rotate_with_fixed_psk() -> None:
    key = b"r" * 32
    server_nonce = b"s" * 32
    client_nonce = b"c" * 32

    first, peer_first, first_server_public, first_client_public = _agreement(
        key, server_nonce, client_nonce
    )
    second, peer_second, second_server_public, second_client_public = _agreement(
        key, server_nonce, client_nonce
    )

    assert hmac.compare_digest(first, peer_first)
    assert hmac.compare_digest(second, peer_second)
    assert not hmac.compare_digest(first, second)
    assert first_server_public != second_server_public
    assert first_client_public != second_client_public


def test_captured_psk_and_transcript_cannot_decrypt_without_ephemeral_secret() -> None:
    key = os.urandom(32)
    server_nonce = os.urandom(32)
    client_nonce = os.urandom(32)
    session, peer_session, server_public, client_public = _agreement(
        key, server_nonce, client_nonce
    )
    assert hmac.compare_digest(session, peer_session)
    frame = remote_bridge._encrypt(session, b"private host telemetry")

    # This models a later PSK compromise plus a captured public transcript.  A
    # deterministic PSK/transcript construction is deliberately not the key:
    # the erased X25519 shared secret remains a required HKDF input.
    transcript = remote_bridge._handshake_transcript(
        server_nonce, client_nonce, server_public, client_public
    )
    psk_only_guess = hmac.new(
        key,
        remote_bridge._AAD + b"psk-only" + transcript,
        hashlib.sha256,
    ).digest()
    with pytest.raises(InvalidTag):
        remote_bridge._decrypt(psk_only_guess, frame)

    with pytest.raises(ValueError, match="shared secret"):
        remote_bridge._session_key(
            key,
            server_nonce,
            client_nonce,
            b"",
            server_public,
            client_public,
        )


def test_mutual_auth_proofs_bind_roles_nonces_and_both_ephemeral_keys() -> None:
    key = os.urandom(32)
    server_nonce = os.urandom(32)
    client_nonce = os.urandom(32)
    _server_private, server_public = remote_bridge._ephemeral_keypair()
    _client_private, client_public = remote_bridge._ephemeral_keypair()
    proof = remote_bridge._proof(
        key,
        b"client",
        server_nonce,
        client_nonce,
        server_public,
        client_public,
    )

    mutations = (
        (b"receiver-ok", server_nonce, client_nonce, server_public, client_public),
        (b"client", bytes([server_nonce[0] ^ 1]) + server_nonce[1:], client_nonce,
         server_public, client_public),
        (b"client", server_nonce, bytes([client_nonce[0] ^ 1]) + client_nonce[1:],
         server_public, client_public),
        (b"client", server_nonce, client_nonce,
         bytes([server_public[0] ^ 1]) + server_public[1:], client_public),
        (b"client", server_nonce, client_nonce, server_public,
         bytes([client_public[0] ^ 1]) + client_public[1:]),
    )
    for role, server_value, client_value, server_key, client_key in mutations:
        changed = remote_bridge._proof(
            key,
            role,
            server_value,
            client_value,
            server_key,
            client_key,
        )
        assert not hmac.compare_digest(proof, changed)


def test_invalid_or_low_order_ephemeral_inputs_fail_closed() -> None:
    private, _public = remote_bridge._ephemeral_keypair()
    with pytest.raises(ValueError, match="public key"):
        remote_bridge._exchange_ephemeral(private, b"short")
    with pytest.raises(ValueError):
        remote_bridge._exchange_ephemeral(private, b"\0" * 32)
    with pytest.raises(ValueError, match="handshake field"):
        remote_bridge._handshake_transcript(b"x" * 65, b"", b"", b"")


def test_protocol_three_rejects_legacy_aad_and_ciphertext() -> None:
    key = os.urandom(32)
    session, _peer, _server_public, _client_public = _agreement(
        key, os.urandom(32), os.urandom(32)
    )
    frame = remote_bridge._encrypt(session, b"telemetry")
    assert remote_bridge._PROTOCOL == "RBRG3"
    assert remote_bridge._AAD == b"Angerona-Remote-Bridge-v3"

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = frame[:12]
    legacy_frame = nonce + AESGCM(session).encrypt(
        nonce, b"telemetry", b"Angerona-Remote-Bridge-v2"
    )
    with pytest.raises(InvalidTag):
        remote_bridge._decrypt(session, legacy_frame)
