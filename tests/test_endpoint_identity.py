import dataclasses
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from angerona.core import endpoint_identity as identity_module
from angerona.core.endpoint_identity import (
    ConnectionVerifier,
    EndpointIdentity,
    ReplayLedger,
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
    request = identity.enrollment_request("hub.local:8443", nonce="A" * 24, expires_at=110, now=100)
    assert EndpointIdentity.verify_enrollment(request, ledger, now=101)
    assert not EndpointIdentity.verify_enrollment(request, ledger, now=101)
    tampered = dataclasses.replace(request, endpoint="evil.local:8443")
    assert not EndpointIdentity.verify_enrollment(
        tampered, ReplayLedger(tmp_path / "other.json"), now=101
    )
    assert not EndpointIdentity.verify_enrollment(
        request, ReplayLedger(tmp_path / "expired.json"), now=110
    )


def test_enrollment_cannot_claim_another_key_derived_device_id(tmp_path):
    victim = EndpointIdentity(tmp_path / "victim")
    attacker = EndpointIdentity(tmp_path / "attacker")
    request = attacker.enrollment_request("hub.local:8443", nonce="C" * 24, expires_at=110, now=100)
    unsigned = {
        **request.unsigned(),
        "device_id": victim.device_id,
    }
    forged = dataclasses.replace(
        request,
        device_id=victim.device_id,
        signature=identity_module._b64(
            attacker._private.sign(identity_module._canonical(unsigned))
        ),
    )
    assert not EndpointIdentity.verify_enrollment(
        forged, ReplayLedger(tmp_path / "forged.json"), now=101
    )


def test_identity_state_and_connection_key_binding_fail_closed(tmp_path):
    path = tmp_path / "identity"
    identity = EndpointIdentity(path)
    state = json.loads(identity.state_path.read_text(encoding="utf-8"))
    state["device_id"] = "device-" + "0" * 32
    identity.state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(RuntimeError, match="identity state is invalid"):
        EndpointIdentity(path)

    other = EndpointIdentity(tmp_path / "other")
    verifier = ConnectionVerifier(
        identity.device_id,
        other.public_key,
        state_path=tmp_path / "sequence.json",
    )
    envelope = identity.sign_connection(1, "heartbeat", {}, sent_at=100)
    assert not verifier.verify(envelope, now=100)


def test_enrollment_nonce_is_atomic_under_thread_contention(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    ledger = ReplayLedger(tmp_path / "replay.json")
    request = identity.enrollment_request(
        "hub.local:8443",
        nonce="B" * 24,
        expires_at=110,
        now=100,
    )
    with ThreadPoolExecutor(max_workers=16) as pool:
        accepted = list(
            pool.map(
                lambda _i: EndpointIdentity.verify_enrollment(
                    request,
                    ledger,
                    now=101,
                ),
                range(32),
            )
        )
    assert accepted.count(True) == 1


def test_replay_ledger_rejects_coercion_duplicates_and_invalid_nonces(tmp_path):
    path = tmp_path / "replay.json"
    ledger = ReplayLedger(path)
    with pytest.raises(ValueError, match="nonce"):
        ledger.consume("not a valid nonce")

    path.write_text('{"version":1,"nonces":[123]}', encoding="utf-8")
    with pytest.raises(ValueError, match="ledger"):
        ledger.consume("D" * 24)

    path.write_text(
        '{"version":1,"version":1,"nonces":[]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate"):
        ledger.consume("D" * 24)


def test_rotation_proves_old_and_new_key_continuity(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    device_id = identity.device_id
    old_public = identity.public_key
    proof = identity.rotate(now=100)
    assert proof.device_id == device_id
    assert old_public != identity.public_key
    assert EndpointIdentity.verify_rotation(
        proof,
        expected_device_id=device_id,
        expected_old_public_key=old_public,
    )
    assert not EndpointIdentity.verify_rotation(
        proof,
        expected_device_id="device-" + "0" * 32,
        expected_old_public_key=old_public,
    )
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


def test_access_state_requires_exact_booleans(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    with pytest.raises(TypeError, match="boolean"):
        identity.set_access_state(revoked="false")
    with pytest.raises(TypeError, match="boolean"):
        identity.set_access_state(quarantined=1)
    assert not identity.revoked
    assert not identity.quarantined


def test_connection_envelope_signature_sequence_and_clock_bounds(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    verifier = ConnectionVerifier(
        identity.device_id,
        identity.public_key,
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
        identity.device_id,
        identity.public_key,
        state_path=tmp_path / "connection-sequence.json",
        clock_skew_seconds=10,
    )
    assert not restarted.verify(envelope, now=105)
    next_envelope = identity.sign_connection(
        2,
        "heartbeat",
        {},
        sent_at=105,
    )
    assert restarted.verify(next_envelope, now=105)


def test_connection_replay_state_and_clock_configuration_are_strict(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    state_path = tmp_path / "connection-sequence.json"
    envelope = identity.sign_connection(1, "heartbeat", {}, sent_at=100)

    with pytest.raises(ValueError, match="clock"):
        ConnectionVerifier(
            identity.device_id,
            identity.public_key,
            state_path=state_path,
            clock_skew_seconds=float("nan"),
        )

    verifier = ConnectionVerifier(
        identity.device_id,
        identity.public_key,
        state_path=state_path,
    )
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "device_id": identity.device_id,
                "last_sequence": False,
            }
        ),
        encoding="utf-8",
    )
    assert not verifier.verify(envelope, now=100)

    state_path.write_text(
        '{"version":1,"version":1,"device_id":"'
        + identity.device_id
        + '","last_sequence":0}',
        encoding="utf-8",
    )
    assert not verifier.verify(envelope, now=100)


def test_connection_payload_is_bounded(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    with pytest.raises(ValueError, match="64 KiB"):
        identity.sign_connection(1, "data", {"blob": "x" * 70000})
