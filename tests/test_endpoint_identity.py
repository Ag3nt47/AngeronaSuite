import dataclasses
from concurrent.futures import ThreadPoolExecutor

import pytest

from angerona.core.endpoint_identity import (
    ConnectionVerifier, EndpointIdentity, ReplayLedger,
)


def test_identity_is_create_only_stable_and_fingerprinted(tmp_path):
    one = EndpointIdentity(tmp_path / "identity")
    two = EndpointIdentity(tmp_path / "identity")
    assert one.device_id == two.device_id
    assert one.public_key == two.public_key
    assert one.public_fingerprint.startswith("sha256:")


def test_enrollment_is_bound_signed_expiring_and_one_time(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    ledger = ReplayLedger(tmp_path / "replay.json")
    request = identity.enrollment_request(
        "hub.local:8443", nonce="A" * 24, expires_at=110, now=100
    )
    assert EndpointIdentity.verify_enrollment(request, ledger, now=101)
    assert not EndpointIdentity.verify_enrollment(request, ledger, now=101)
    tampered = dataclasses.replace(request, endpoint="evil.local:8443")
    assert not EndpointIdentity.verify_enrollment(
        tampered, ReplayLedger(tmp_path / "other.json"), now=101
    )


def test_enrollment_nonce_is_atomic_under_thread_contention(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    ledger = ReplayLedger(tmp_path / "replay.json")
    request = identity.enrollment_request(
        "hub.local:8443", nonce="B" * 24, expires_at=110, now=100,
    )
    with ThreadPoolExecutor(max_workers=16) as pool:
        accepted = list(pool.map(
            lambda _i: EndpointIdentity.verify_enrollment(
                request, ledger, now=101,
            ),
            range(32),
        ))
    assert accepted.count(True) == 1


def test_rotation_proves_old_and_new_key_continuity(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    device_id = identity.device_id
    old_public = identity.public_key
    proof = identity.rotate(now=100)
    assert proof.device_id == device_id
    assert old_public != identity.public_key
    assert EndpointIdentity.verify_rotation(proof)
    assert EndpointIdentity(tmp_path / "identity").public_key == identity.public_key


def test_revocation_and_quarantine_block_signing_and_persist(tmp_path):
    path = tmp_path / "identity"
    identity = EndpointIdentity(path)
    identity.set_access_state(quarantined=True)
    with pytest.raises(PermissionError):
        identity.sign_connection(1, "heartbeat", {})
    loaded = EndpointIdentity(path)
    assert loaded.quarantined
    loaded.set_access_state(quarantined=False, revoked=True)
    with pytest.raises(PermissionError):
        loaded.sign_connection(1, "heartbeat", {})


def test_connection_envelope_signature_sequence_and_clock_bounds(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    verifier = ConnectionVerifier(
        identity.device_id, identity.public_key,
        state_path=tmp_path / "connection-sequence.json",
        clock_skew_seconds=10,
    )
    envelope = identity.sign_connection(1, "heartbeat", {"health": 100}, sent_at=100)
    assert verifier.verify(envelope, now=105)
    assert not verifier.verify(envelope, now=105)
    future = identity.sign_connection(2, "heartbeat", {}, sent_at=200)
    assert not verifier.verify(future, now=100)
    tampered = dataclasses.replace(future, sent_at=100)
    assert not verifier.verify(tampered, now=100)
    restarted = ConnectionVerifier(
        identity.device_id, identity.public_key,
        state_path=tmp_path / "connection-sequence.json",
        clock_skew_seconds=10,
    )
    assert not restarted.verify(envelope, now=105)
    next_envelope = identity.sign_connection(
        2, "heartbeat", {}, sent_at=105,
    )
    assert restarted.verify(next_envelope, now=105)


def test_connection_payload_is_bounded(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    with pytest.raises(ValueError, match="64 KiB"):
        identity.sign_connection(1, "data", {"blob": "x" * 70000})
