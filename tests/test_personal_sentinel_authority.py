from __future__ import annotations

import dataclasses
import hashlib
import json
import threading

import pytest

from angerona.core.independent_high_water import (
    AUDIT_DOMAIN,
    SCHEMA,
    ZERO_DIGEST,
    HighWaterRejected,
    HighWaterTransition,
    HighWaterUnavailable,
)
from angerona.core.personal_sentinel_authority import (
    Ed25519PrivateSigner,
    HmacSha256Authenticator,
    InProcessSentinelTransport,
    PersonalSentinelAuthority,
    PersonalSentinelAuthorityClient,
    SentinelRequestRejected,
    SentinelStateIntegrityError,
    SentinelTransportResult,
    TRANSPORT_RESPONSE_FLOOR_NAMESPACE,
    self_test,
)


INSTALLATION = "a" * 32
INSTANCE = "b" * 32
NOW = 1_800_000_000.0


def _stack(tmp_path, nonces, *, instance=INSTANCE, allow_test=True):
    authenticator = HmacSha256Authenticator(b"k" * 32)
    authority = PersonalSentinelAuthority(
        tmp_path / "sentinel.json",
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=authenticator,
        clock=lambda: NOW,
        max_nonces=64,
    )
    client = PersonalSentinelAuthorityClient(
        installation_id=INSTALLATION,
        client_instance_id=instance,
        authenticator=authenticator,
        transport=InProcessSentinelTransport(authority, test_only=True),
        clock=lambda: NOW,
        nonce_factory=lambda: next(nonces),
        allow_test_transport=allow_test,
    )
    return authenticator, authority, client


def _transition(previous_revision=0, previous_digest=ZERO_DIGEST, previous_head=ZERO_DIGEST):
    return HighWaterTransition(
        SCHEMA,
        INSTALLATION,
        AUDIT_DOMAIN,
        previous_revision,
        previous_digest,
        previous_head,
        previous_revision + 1,
        f"{previous_revision + 1:064x}",
    )


def test_signed_cas_head_persists_and_time_receipt_verifies(tmp_path):
    auth, authority, client = _stack(tmp_path, iter(("c" * 43, "d" * 43, "e" * 43)))
    assert client.read_head(AUDIT_DOMAIN) is None
    head = client.compare_and_advance(_transition())
    receipt = client.get_time_receipt()
    assert head.revision == 1
    assert receipt.verify(auth)
    assert receipt.received_at == NOW

    authority.close()
    restarted = PersonalSentinelAuthority(
        authority.state_path,
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        clock=lambda: NOW,
        max_nonces=64,
    )
    restarted_client = PersonalSentinelAuthorityClient(
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        transport=InProcessSentinelTransport(restarted, test_only=True),
        clock=lambda: NOW,
        nonce_factory=lambda: "f" * 43,
        allow_test_transport=True,
    )
    try:
        assert restarted_client.read_head(AUDIT_DOMAIN) == head
    finally:
        restarted.close()


def test_duplicate_or_fork_transition_is_rejected_and_does_not_replace_head(tmp_path):
    _auth, _authority, client = _stack(
        tmp_path, iter(("c" * 43, "d" * 43, "e" * 43))
    )
    head = client.compare_and_advance(_transition())
    with pytest.raises(HighWaterRejected):
        client.compare_and_advance(_transition())
    assert client.read_head(AUDIT_DOMAIN) == head


def test_clone_identity_and_nonce_replay_fail_closed(tmp_path):
    _auth, _authority, clone = _stack(
        tmp_path, iter(("z" * 43,)), instance="c" * 32
    )
    with pytest.raises(HighWaterRejected):
        clone.read_head(AUDIT_DOMAIN)

    _auth, _authority, replaying = _stack(
        tmp_path / "other", iter(("r" * 43, "r" * 43))
    )
    assert replaying.read_head(AUDIT_DOMAIN) is None
    with pytest.raises(HighWaterRejected):
        replaying.read_head(AUDIT_DOMAIN)


def test_in_process_transport_requires_two_explicit_test_opt_ins(tmp_path):
    auth = HmacSha256Authenticator(b"k" * 32)
    authority = PersonalSentinelAuthority(
        tmp_path / "state.json",
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        clock=lambda: NOW,
        max_nonces=64,
    )
    with pytest.raises(ValueError):
        InProcessSentinelTransport(authority)
    _auth, _authority, client = _stack(
        tmp_path / "second", iter(("x" * 43,)), allow_test=False
    )
    with pytest.raises((HighWaterRejected, HighWaterUnavailable)):
        client.read_head(AUDIT_DOMAIN)


def test_state_tampering_and_post_initialization_deletion_are_not_first_run(tmp_path):
    _auth, authority, client = _stack(
        tmp_path, iter(("c" * 43, "d" * 43, "e" * 43))
    )
    assert client.read_head(AUDIT_DOMAIN) is None
    document = json.loads(authority.state_path.read_text(encoding="utf-8"))
    document["sequence"] += 1
    authority.state_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises((HighWaterRejected, HighWaterUnavailable)):
        client.read_head(AUDIT_DOMAIN)

    _auth, authority, client = _stack(
        tmp_path / "deleted", iter(("f" * 43, "g" * 43))
    )
    assert client.read_head(AUDIT_DOMAIN) is None
    authority.state_path.unlink()
    with pytest.raises((HighWaterRejected, HighWaterUnavailable)):
        client.read_head(AUDIT_DOMAIN)


def test_strict_json_rejects_duplicate_keys_and_stale_signed_requests(tmp_path):
    auth, authority, _client = _stack(tmp_path, iter(()))
    with pytest.raises(SentinelRequestRejected):
        authority.process(b'{"schema":"x","schema":"y"}', now=NOW)

    request = {
        "schema": "angerona.personal-sentinel-authority-request.v1",
        "operation": "time-receipt",
        "installation_id": INSTALLATION,
        "client_instance_id": INSTANCE,
        "nonce": "s" * 43,
        "issued_at": NOW - 31,
        "key_id": auth.key_id,
        "payload": {},
    }
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    request["signature"] = auth.sign(canonical)
    with pytest.raises(SentinelRequestRejected, match="stale"):
        authority.process(json.dumps(request, sort_keys=True, separators=(",", ":")).encode())


def test_time_receipt_signature_cannot_be_reused_after_mutation(tmp_path):
    auth, _authority, client = _stack(tmp_path, iter(("t" * 43,)))
    receipt = client.get_time_receipt()
    assert receipt.verify(auth)
    assert not dataclasses.replace(receipt, sequence=receipt.sequence + 1).verify(auth)


def test_authority_clock_rollback_after_a_signed_receipt_fails_closed(tmp_path):
    auth = HmacSha256Authenticator(b"k" * 32)
    clock = [NOW]
    authority = PersonalSentinelAuthority(
        tmp_path / "clock.json",
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        clock=lambda: clock[0],
        max_nonces=64,
    )
    nonces = iter(("u" * 43, "v" * 43))
    client = PersonalSentinelAuthorityClient(
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        transport=InProcessSentinelTransport(authority, test_only=True),
        clock=lambda: clock[0],
        nonce_factory=lambda: next(nonces),
        allow_test_transport=True,
    )
    assert client.get_time_receipt().received_at == NOW
    clock[0] = NOW - 10
    with pytest.raises(HighWaterUnavailable):
        client.get_time_receipt()


def test_asymmetric_client_and_authority_keys_have_separate_custody(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    client_signer = Ed25519PrivateSigner(
        Ed25519PrivateKey.generate(), key_id="client-ed25519-v1"
    )
    authority_signer = Ed25519PrivateSigner(
        Ed25519PrivateKey.generate(), key_id="authority-ed25519-v1"
    )
    authority = PersonalSentinelAuthority(
        tmp_path / "asymmetric.json",
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        request_verifier=client_signer.public_verifier(),
        response_signer=authority_signer,
        response_verifier=authority_signer.public_verifier(),
        clock=lambda: NOW,
        max_nonces=64,
    )
    client = PersonalSentinelAuthorityClient(
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        request_signer=client_signer,
        response_verifier=authority_signer.public_verifier(),
        transport=InProcessSentinelTransport(authority, test_only=True),
        clock=lambda: NOW,
        nonce_factory=lambda: "q" * 43,
        allow_test_transport=True,
    )
    receipt = client.get_time_receipt()
    assert receipt.verify(authority_signer.public_verifier())
    assert not receipt.verify(client_signer.public_verifier())


def test_authority_self_test_is_socket_free_and_passes():
    assert self_test()[0] is True


def test_authority_os_lease_rejects_a_second_live_instance(tmp_path):
    auth = HmacSha256Authenticator(b"k" * 32)
    first = PersonalSentinelAuthority(
        tmp_path / "singleton.json",
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        clock=lambda: NOW,
        max_nonces=64,
    )
    try:
        with pytest.raises(RuntimeError, match="lease"):
            PersonalSentinelAuthority(
                first.state_path,
                installation_id=INSTALLATION,
                client_instance_id=INSTANCE,
                authenticator=auth,
                clock=lambda: NOW,
                max_nonces=64,
            )
    finally:
        first.close()


def test_closed_authority_rejects_process_load_and_save_after_reopen(tmp_path):
    auth, authority, client = _stack(
        tmp_path, iter(("c" * 43, "d" * 43, "e" * 43))
    )
    assert client.get_time_receipt().sequence == 1
    authority.close()

    replacement = PersonalSentinelAuthority(
        authority.state_path,
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        clock=lambda: NOW,
        max_nonces=64,
    )
    try:
        with pytest.raises(HighWaterUnavailable, match="transport failed"):
            client.get_time_receipt()
        with pytest.raises(SentinelStateIntegrityError, match="closed"):
            authority._load_state()
        with pytest.raises(SentinelStateIntegrityError, match="closed"):
            authority._save_state(authority._initial_state())

        replacement_client = PersonalSentinelAuthorityClient(
            installation_id=INSTALLATION,
            client_instance_id=INSTANCE,
            authenticator=auth,
            transport=InProcessSentinelTransport(replacement, test_only=True),
            clock=lambda: NOW,
            nonce_factory=lambda: "f" * 43,
            allow_test_transport=True,
        )
        assert replacement_client.get_time_receipt().sequence == 2
    finally:
        replacement.close()


def test_close_serializes_with_inflight_transaction_before_reopen(tmp_path):
    auth, authority, client = _stack(
        tmp_path, iter(("g" * 43, "h" * 43, "i" * 43))
    )
    entered = threading.Event()
    release = threading.Event()
    close_finished = threading.Event()
    receipts = []
    failures = []
    original_validate = authority._validate_request

    def blocking_validate(body, observed):
        entered.set()
        if not release.wait(2.0):
            raise RuntimeError("test validation gate timed out")
        return original_validate(body, observed)

    authority._validate_request = blocking_validate

    def request_worker():
        try:
            receipts.append(client.get_time_receipt())
        except Exception as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    request_thread = threading.Thread(target=request_worker)
    close_thread = threading.Thread(
        target=lambda: (authority.close(), close_finished.set())
    )
    request_thread.start()
    assert entered.wait(1.0)
    close_thread.start()
    assert not close_finished.wait(0.1)
    release.set()
    request_thread.join(2.0)
    close_thread.join(2.0)

    assert not request_thread.is_alive()
    assert not close_thread.is_alive()
    assert not failures
    assert len(receipts) == 1
    assert close_finished.is_set()

    replacement = PersonalSentinelAuthority(
        authority.state_path,
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        clock=lambda: NOW,
        max_nonces=64,
    )
    try:
        with pytest.raises(HighWaterUnavailable):
            client.get_time_receipt()
    finally:
        replacement.close()


def test_external_generation_floor_detects_old_signed_snapshot(tmp_path):
    class Floor:
        generation = None
        state_sha256 = ""

        def read_generation(self, **_identity):
            return self.generation

        def compare_and_advance(
            self, *, previous_generation, generation, state_sha256, **_identity
        ):
            assert len(state_sha256) == 64
            self.state_sha256 = state_sha256
            current = 0 if self.generation is None else self.generation
            if previous_generation != current or generation != current + 1:
                return False
            self.generation = generation
            return True

    floor = Floor()
    auth = HmacSha256Authenticator(b"k" * 32)
    authority = PersonalSentinelAuthority(
        tmp_path / "floor.json",
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        generation_floor=floor,
        clock=lambda: NOW,
        max_nonces=64,
    )
    client = PersonalSentinelAuthorityClient(
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        transport=InProcessSentinelTransport(authority, test_only=True),
        clock=lambda: NOW,
        nonce_factory=iter(("x" * 43, "y" * 43)).__next__,
        allow_test_transport=True,
    )
    assert client.read_head(AUDIT_DOMAIN) is None
    saved = json.loads(authority.state_path.read_text(encoding="utf-8"))
    saved.pop("state_signature")
    canonical_unsigned = json.dumps(
        saved, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert floor.state_sha256 == hashlib.sha256(canonical_unsigned).hexdigest()
    old_snapshot = authority.state_path.read_bytes()
    assert client.get_time_receipt().sequence == 2
    authority.close()
    authority.state_path.write_bytes(old_snapshot)

    restarted = PersonalSentinelAuthority(
        authority.state_path,
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        generation_floor=floor,
        clock=lambda: NOW,
        max_nonces=64,
    )
    try:
        stale_client = PersonalSentinelAuthorityClient(
            installation_id=INSTALLATION,
            client_instance_id=INSTANCE,
            authenticator=auth,
            transport=InProcessSentinelTransport(restarted, test_only=True),
            clock=lambda: NOW,
            nonce_factory=lambda: "z" * 43,
            allow_test_transport=True,
        )
        with pytest.raises(HighWaterUnavailable):
            stale_client.read_head(AUDIT_DOMAIN)
    finally:
        restarted.close()


def test_production_client_requires_durable_response_floor(tmp_path):
    auth = HmacSha256Authenticator(b"k" * 32)
    authority = PersonalSentinelAuthority(
        tmp_path / "client-floor.json",
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        clock=lambda: NOW,
        max_nonces=64,
    )

    class ProductionTransport:
        def exchange(self, body):
            return SentinelTransportResult(authority.process(body), True, False)

    without_floor = PersonalSentinelAuthorityClient(
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        transport=ProductionTransport(),
        clock=lambda: NOW,
        nonce_factory=lambda: "m" * 43,
    )
    with pytest.raises(HighWaterRejected, match="durable response floor"):
        without_floor.get_time_receipt()

    class Floor:
        sequence = 0
        received_at = 0.0

        def compare_and_advance(
            self, *, namespace, sequence, received_at, **_identity
        ):
            assert namespace == TRANSPORT_RESPONSE_FLOOR_NAMESPACE
            if sequence <= self.sequence or received_at < self.received_at:
                return False
            self.sequence = sequence
            self.received_at = received_at
            return True

    with_floor = PersonalSentinelAuthorityClient(
        installation_id=INSTALLATION,
        client_instance_id=INSTANCE,
        authenticator=auth,
        response_floor=Floor(),
        transport=ProductionTransport(),
        clock=lambda: NOW,
        nonce_factory=lambda: "n" * 43,
    )
    try:
        assert with_floor.get_time_receipt().sequence == 2
    finally:
        authority.close()
