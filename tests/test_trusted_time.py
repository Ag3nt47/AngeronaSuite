from __future__ import annotations

import dataclasses

from angerona.core.personal_sentinel_authority import (
    HmacSha256Authenticator,
    PersonalSentinelAuthority,
    PersonalSentinelAuthorityClient,
    SignedTimeReceipt,
    SentinelTransportResult,
    TRANSPORT_RESPONSE_FLOOR_NAMESPACE,
    TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE,
)
from angerona.core.trusted_time import LocalTimeSample, assess_trusted_time


INSTALLATION = "a" * 32
INSTANCE = "b" * 32


class Floor:
    def __init__(self) -> None:
        self.heads = {}

    def compare_and_advance(
        self,
        *,
        namespace,
        installation_id,
        client_instance_id,
        sequence,
        received_at,
    ):
        if installation_id != INSTALLATION or client_instance_id != INSTANCE:
            return False
        if namespace not in {
            TRANSPORT_RESPONSE_FLOOR_NAMESPACE,
            TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE,
        }:
            return False
        key = (namespace, installation_id, client_instance_id)
        previous_sequence, previous_time = self.heads.get(key, (0, 0.0))
        if sequence <= previous_sequence or received_at < previous_time:
            return False
        self.heads[key] = (sequence, received_at)
        return True


def _receipt(auth, received=1010.0):
    unsigned = SignedTimeReceipt(
        operation="time-receipt",
        request_nonce="n" * 43,
        sequence=7,
        received_at=received,
        expires_at=received + 30,
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        key_id=auth.key_id,
        signature="pending",
    )
    import json

    signature = auth.sign(
        json.dumps(
            unsigned.signed_document(), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )
    return dataclasses.replace(unsigned, signature=signature)


def test_same_boot_wall_and_monotonic_progression_is_local_only():
    previous = LocalTimeSample(1000, 100, "a" * 64)
    current = LocalTimeSample(1010, 110, "a" * 64)
    result = assess_trusted_time(current, previous=previous)
    assert result.state == "local-continuity-only"
    assert result.continuity_valid
    assert not result.independently_witnessed
    assert result.response_authorized is False


def test_wall_or_monotonic_rollback_is_untrusted_even_without_a_witness():
    previous = LocalTimeSample(1000, 100, "a" * 64)
    wall = assess_trusted_time(LocalTimeSample(900, 110, "a" * 64), previous=previous)
    monotonic = assess_trusted_time(LocalTimeSample(1010, 90, "a" * 64), previous=previous)
    assert wall.state == "untrusted-clock-discontinuity"
    assert monotonic.state == "untrusted-clock-discontinuity"


def test_valid_signed_witness_bridges_a_new_boot_without_claiming_response_authority():
    auth = HmacSha256Authenticator(b"k" * 32)
    previous = LocalTimeSample(1000, 100, "a" * 64)
    current = LocalTimeSample(1010, 5, "b" * 64)
    result = assess_trusted_time(
        current,
        previous=previous,
        witness=_receipt(auth),
        verifier=auth,
        expected_installation_id=INSTALLATION,
        expected_client_instance_id=INSTANCE,
        expected_witness_challenge="n" * 43,
        witness_floor=Floor(),
    )
    assert result.state == "externally-witnessed"
    assert result.independently_witnessed
    assert not result.continuity_valid
    assert result.response_authorized is False


def test_invalid_signature_identity_or_stale_witness_is_rejected():
    auth = HmacSha256Authenticator(b"k" * 32)
    current = LocalTimeSample(1010, 110, "a" * 64)
    bad_signature = dataclasses.replace(_receipt(auth), signature="0" * 64)
    for witness, installation in (
        (bad_signature, INSTALLATION),
        (_receipt(auth), "c" * 32),
        (_receipt(auth, received=900), INSTALLATION),
    ):
        result = assess_trusted_time(
            current,
            witness=witness,
            verifier=auth,
            expected_installation_id=installation,
            expected_client_instance_id=INSTANCE,
            expected_witness_challenge="n" * 43,
            witness_floor=Floor(),
        )
        assert result.state == "untrusted-witness"
        assert not result.independently_witnessed


def test_public_time_details_omit_raw_times_boot_and_identity():
    result = assess_trusted_time(LocalTimeSample(1010, 110, "a" * 64))
    details = result.event_details()
    text = repr(details)
    assert "1010" not in text
    assert "a" * 32 not in text
    assert details["response_authorized"] is False


def test_captured_or_sequence_regressed_receipt_is_not_independently_fresh():
    auth = HmacSha256Authenticator(b"k" * 32)
    current = LocalTimeSample(1010, 110, "a" * 64)
    receipt = _receipt(auth)

    detached = assess_trusted_time(
        current,
        witness=receipt,
        verifier=auth,
        expected_installation_id=INSTALLATION,
        expected_client_instance_id=INSTANCE,
    )
    assert detached.state == "historical-witness"
    assert not detached.independently_witnessed

    floor = Floor()
    first = assess_trusted_time(
        current,
        witness=receipt,
        verifier=auth,
        expected_installation_id=INSTALLATION,
        expected_client_instance_id=INSTANCE,
        expected_witness_challenge="n" * 43,
        witness_floor=floor,
    )
    replay = assess_trusted_time(
        current,
        witness=receipt,
        verifier=auth,
        expected_installation_id=INSTALLATION,
        expected_client_instance_id=INSTANCE,
        expected_witness_challenge="n" * 43,
        witness_floor=floor,
    )
    assert first.independently_witnessed
    assert replay.state == "untrusted-witness"
    assert not replay.independently_witnessed

    wrong_challenge = assess_trusted_time(
        current,
        witness=receipt,
        verifier=auth,
        expected_installation_id=INSTALLATION,
        expected_client_instance_id=INSTANCE,
        expected_witness_challenge="x" * 43,
        witness_floor=Floor(),
    )
    assert not wrong_challenge.independently_witnessed
    assert "external-time-witness-challenge-mismatch" in wrong_challenge.reasons


def test_production_transport_and_time_appraisal_use_independent_durable_namespaces(
    tmp_path,
):
    auth = HmacSha256Authenticator(b"p" * 32)
    authority = PersonalSentinelAuthority(
        tmp_path / "scoped-floor-authority.json",
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        clock=lambda: 1010.0,
        max_nonces=64,
    )

    class ProductionTransport:
        def exchange(self, body):
            return SentinelTransportResult(authority.process(body), True, False)

    floor = Floor()
    nonces = iter(("n" * 43, "m" * 43))
    client = PersonalSentinelAuthorityClient(
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        response_floor=floor,
        transport=ProductionTransport(),
        clock=lambda: 1010.0,
        nonce_factory=nonces.__next__,
    )
    current = LocalTimeSample(1010, 110, "a" * 64)
    try:
        receipt = client.get_time_receipt()
        first = assess_trusted_time(
            current,
            witness=receipt,
            verifier=auth,
            expected_installation_id=INSTALLATION,
            expected_client_instance_id=INSTANCE,
            expected_witness_challenge="n" * 43,
            witness_floor=floor,
        )
        replay = assess_trusted_time(
            current,
            witness=receipt,
            verifier=auth,
            expected_installation_id=INSTALLATION,
            expected_client_instance_id=INSTANCE,
            expected_witness_challenge="n" * 43,
            witness_floor=floor,
        )
        next_receipt = client.get_time_receipt()
        captured_for_new_challenge = assess_trusted_time(
            current,
            witness=receipt,
            verifier=auth,
            expected_installation_id=INSTALLATION,
            expected_client_instance_id=INSTANCE,
            expected_witness_challenge="m" * 43,
            witness_floor=floor,
        )
        second = assess_trusted_time(
            current,
            witness=next_receipt,
            verifier=auth,
            expected_installation_id=INSTALLATION,
            expected_client_instance_id=INSTANCE,
            expected_witness_challenge="m" * 43,
            witness_floor=floor,
        )
    finally:
        authority.close()

    assert first.independently_witnessed
    assert replay.state == "untrusted-witness"
    assert not replay.independently_witnessed
    assert "external-time-witness-challenge-mismatch" in captured_for_new_challenge.reasons
    assert not captured_for_new_challenge.independently_witnessed
    assert second.independently_witnessed
    assert set(floor.heads) == {
        (TRANSPORT_RESPONSE_FLOOR_NAMESPACE, INSTALLATION, INSTANCE),
        (TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE, INSTALLATION, INSTANCE),
    }
