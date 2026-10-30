from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import asdict

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.independent_high_water import AUDIT_DOMAIN, HighWaterRejected, HighWaterUnavailable
from angerona.core.personal_sentinel_authority import (
    Ed25519PrivateSigner, HmacSha256Authenticator, InProcessSentinelTransport,
    PersonalSentinelAuthority, PersonalSentinelAuthorityClient, PinnedHttpsSentinelTransport,
    SentinelStateIntegrityError, SentinelTransportResult,
    TRANSPORT_RESPONSE_FLOOR_NAMESPACE, TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE, _canonical,
)
from angerona.core.personal_sentinel_gateway import GatewayTransportResponse
from angerona.core.recorder_epoch import EpochClaim, ZERO
from angerona.core.sentinel_remote_floor import RawSignedFloorClient

INSTALLATION, INSTANCE, NOW = "a" * 32, "b" * 32, 1_800_000_000.0


@pytest.fixture
def stack(tmp_path):
    request = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id="client-request")
    signer = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id="authority-receipt")
    authorities = []

    def authority(name="floor.json", **options):
        result = PersonalSentinelAuthority(tmp_path / name,
            installation_id=INSTALLATION, client_instance_id=INSTANCE,
            request_verifier=request.public_verifier(), response_signer=signer,
            response_verifier=signer.public_verifier(), clock=lambda: NOW, max_nonces=64,
            **options)
        authorities.append(result)
        return result

    def floor(server, *, transport=None, **options):
        counter = itertools.count(1)
        return RawSignedFloorClient(installation_id=INSTALLATION, client_instance_id=INSTANCE,
            request_signer=request, response_verifier=signer.public_verifier(),
            transport=transport or InProcessSentinelTransport(server, test_only=True),
            clock=lambda: NOW, nonce_factory=lambda: f"floor-{next(counter):038d}",
            allow_test_transport=True, **options)

    yield request, signer, authority, floor
    for item in reversed(authorities):
        item.close()


def _advance(client, sequence=1, received=NOW, namespace=TRANSPORT_RESPONSE_FLOOR_NAMESPACE):
    return client.compare_and_advance(namespace=namespace, installation_id=INSTALLATION,
        client_instance_id=INSTANCE, sequence=sequence, received_at=received)


def test_signed_floor_restart_strict_sequence_time_and_namespace_separation(stack):
    _request, _signer, authority, floor = stack
    server = authority(enable_client_response_floors=True)
    client = floor(server)
    assert _advance(client) is True
    assert _advance(client) is False  # A fresh request never blesses a duplicate.
    assert _advance(client, sequence=2, received=NOW - 1) is False
    assert _advance(client, sequence=2) is True  # Equal timestamps are permitted.
    assert _advance(client, namespace=TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE) is True
    saved = server.state_path.read_bytes()
    state = json.loads(saved)
    assert len(state["client_response_floors"]) == 2
    assert state["heads"] == []
    server.close()
    restarted = authority(enable_client_response_floors=True)
    restarted_client = floor(restarted)
    # A new client cannot reuse an earlier nonce either.
    with pytest.raises(HighWaterRejected):
        _advance(restarted_client, sequence=3)
    restarted_client._nonce_factory = lambda: "new-generation-" + "n" * 32
    assert _advance(restarted_client, sequence=2) is False
    restarted_client._nonce_factory = lambda: "new-generation-" + "m" * 32
    assert _advance(restarted_client, sequence=3) is True


def test_feature_off_holds_floor_state_without_rewriting(stack):
    _request, _signer, authority, floor = stack
    server = authority(enable_client_response_floors=True)
    assert _advance(floor(server))
    saved = server.state_path.read_bytes()
    server.close()
    disabled = authority()
    client = floor(disabled)
    with pytest.raises(HighWaterUnavailable):
        _advance(client, sequence=2)
    assert disabled.state_path.read_bytes() == saved


def test_disabled_new_operation_rejected_without_creating_floor(stack):
    _request, _signer, authority, floor = stack
    server = authority()
    with pytest.raises(HighWaterRejected):
        _advance(floor(server))
    assert "client_response_floors" not in json.loads(server.state_path.read_bytes())


def test_legacy_state_is_preserved_on_opt_in(stack):
    request, signer, authority, floor = stack
    old = authority()
    client = PersonalSentinelAuthorityClient(installation_id=INSTALLATION, client_instance_id=INSTANCE,
        request_signer=request, response_verifier=signer.public_verifier(),
        transport=InProcessSentinelTransport(old, test_only=True), allow_test_transport=True,
        clock=lambda: NOW)
    assert client.read_head(AUDIT_DOMAIN) is None
    previous = json.loads(old.state_path.read_bytes())
    old.close()
    server = authority(enable_client_response_floors=True)
    assert _advance(floor(server))
    state = json.loads(server.state_path.read_bytes())
    assert state["heads"] == previous["heads"]
    assert state["generation"] == previous["generation"] + 1
    assert set(previous["nonce_hashes"]).issubset(state["nonce_hashes"])


@pytest.mark.parametrize("floor_first", [False, True])
def test_both_extensions_survive_each_order_restart_and_feature_off(stack, floor_first):
    request, signer, authority, floor = stack
    server = authority(enable_client_response_floors=True, enable_recorder_epochs=True)
    client = PersonalSentinelAuthorityClient(installation_id=INSTALLATION, client_instance_id=INSTANCE,
        request_signer=request, response_verifier=signer.public_verifier(),
        transport=InProcessSentinelTransport(server, test_only=True), allow_test_transport=True,
        clock=lambda: NOW)
    if floor_first:
        assert _advance(floor(server))
    receipt = client.append_recorder_epoch(EpochClaim(1, 1, 1, 1, "c" * 64, ZERO))
    if not floor_first:
        assert _advance(floor(server))
    state = json.loads(server.state_path.read_bytes())
    assert state["recorder_epoch_head"] == asdict(receipt)
    assert len(state["client_response_floors"]) == 1
    server.close()
    restarted = authority(enable_client_response_floors=True, enable_recorder_epochs=True)
    assert restarted._load_state()["recorder_epoch_head"] == asdict(receipt)
    preserved = restarted.state_path.read_bytes()
    restarted.close()
    for flags in ({"enable_client_response_floors": True}, {"enable_recorder_epochs": True}):
        disabled = authority(**flags)
        with pytest.raises(SentinelStateIntegrityError, match="requires its enrolled authority feature"):
            disabled._load_state()
        assert disabled.state_path.read_bytes() == preserved
        disabled.close()


@pytest.mark.parametrize("which", ["namespace", "installation_id", "client_instance_id", "sequence", "received_at"])
def test_tuple_identity_and_bounds_rejected_before_transport(stack, which):
    _request, _signer, authority, floor = stack
    server = authority(enable_client_response_floors=True)
    client = floor(server)
    fields = dict(namespace=TRANSPORT_RESPONSE_FLOOR_NAMESPACE, installation_id=INSTALLATION,
                  client_instance_id=INSTANCE, sequence=1, received_at=NOW)
    fields[which] = {"namespace": "untrusted", "installation_id": "c" * 32,
                     "client_instance_id": "c" * 32, "sequence": True, "received_at": float("nan")}[which]
    with pytest.raises(HighWaterRejected):
        client.compare_and_advance(**fields)
    assert not server.state_path.exists()


@pytest.mark.parametrize("field,value", [
    ("request_nonce", "wrong-" + "x" * 38), ("operation", "time-receipt"),
    ("sequence", 0), ("received_at", NOW - 90), ("expires_at", NOW),
    ("status", "unknown"), ("key_id", "different-authority"),
    ("ack.namespace", TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE),
    ("ack.sequence", 2), ("ack.received_at", NOW + 1),
    ("ack.installation_id", "c" * 32), ("ack.client_instance_id", "d" * 32),
    ("ack.advanced", 1), ("ack.extra", "not-allowed"),
])
def test_even_signed_mismatched_or_stale_acknowledgements_rejected(stack, field, value):
    _request, signer, authority, floor = stack
    server = authority(enable_client_response_floors=True)

    class Mutated:
        def exchange(self, body):
            response = json.loads(server.process(body))
            if field.startswith("ack."):
                response["payload"][field[4:]] = value
            else:
                response[field] = value
            response.pop("signature")
            response["signature"] = signer.sign(_canonical(response))
            return SentinelTransportResult(_canonical(response), False, True)

    with pytest.raises(HighWaterRejected):
        _advance(floor(server, transport=Mutated()))


def test_nonce_bound_replay_rejected_without_recursive_parent_request(stack, monkeypatch):
    _request, _signer, authority, floor = stack
    server = authority(enable_client_response_floors=True)

    class Replay:
        response = None

        def exchange(self, body):
            if self.response is None:
                self.response = server.process(body)
            return SentinelTransportResult(self.response, False, True)

    monkeypatch.setattr(PersonalSentinelAuthorityClient, "_request",
        lambda *_args, **_kw: pytest.fail("Raw floor must never recurse through AuthorityClient"))
    client = floor(server, transport=Replay())
    assert _advance(client)
    with pytest.raises(HighWaterRejected):
        _advance(client, sequence=2)


def test_untrusted_response_signature_never_advances_client(stack):
    _request, _signer, authority, floor = stack
    server = authority(enable_client_response_floors=True)

    class Forged:
        def exchange(self, body):
            response = json.loads(server.process(body))
            response["signature"] = "A" * 86
            return SentinelTransportResult(_canonical(response), False, True)

    client = floor(server, transport=Forged())
    with pytest.raises(HighWaterRejected, match="signature"):
        _advance(client)
    assert client._last_sequence == 0


def test_request_reply_loss_consumes_floor_without_retrying_or_resetting(stack):
    _request, _signer, authority, floor = stack
    server = authority(enable_client_response_floors=True)

    class LostReply:
        def exchange(self, body):
            server.process(body)
            raise OSError("reply lost after durable remote advance")

    client = floor(server, transport=LostReply())
    with pytest.raises(HighWaterUnavailable):
        _advance(client)
    client.transport = InProcessSentinelTransport(server, test_only=True)
    assert _advance(client) is False
    assert _advance(client, sequence=2) is True


@pytest.mark.parametrize("regression", ["sequence", "time"])
def test_signed_raw_server_fork_or_time_regression_rejected(stack, regression):
    _request, signer, authority, floor = stack
    server = authority(enable_client_response_floors=True)

    class Fork:
        calls = 0

        def exchange(self, body):
            self.calls += 1
            response = json.loads(server.process(body))
            if self.calls == 2:
                response["sequence" if regression == "sequence" else "received_at"] = (
                    1 if regression == "sequence" else NOW - 1)
                response.pop("signature")
                response["signature"] = signer.sign(_canonical(response))
            return SentinelTransportResult(_canonical(response), False, True)

    client = floor(server, transport=Fork())
    assert _advance(client)
    with pytest.raises(HighWaterRejected):
        _advance(client, sequence=2)


def test_transport_outage_has_no_local_counter_or_fallback(stack):
    _request, _signer, authority, floor = stack
    server = authority(enable_client_response_floors=True)

    class Offline:
        def exchange(self, _body):
            raise OSError("offline")

    with pytest.raises(HighWaterUnavailable):
        _advance(floor(server, transport=Offline()))
    assert not server.state_path.exists()


def test_distinct_raw_keys_required_even_if_key_ids_differ(stack):
    _request, _signer, authority, floor = stack
    server = authority()
    key = Ed25519PrivateKey.generate()
    request = Ed25519PrivateSigner(key, key_id="client")
    authority_key = Ed25519PrivateSigner(key, key_id="different-name")
    with pytest.raises(ValueError, match="cryptographically distinct"):
        RawSignedFloorClient(installation_id=INSTALLATION, client_instance_id=INSTANCE,
            request_signer=request, response_verifier=authority_key.public_verifier(),
            transport=InProcessSentinelTransport(server, test_only=True), allow_test_transport=True)
    with pytest.raises(ValueError, match="cryptographically distinct"):
        PersonalSentinelAuthority(server.state_path.with_name("bad-key.json"),
            installation_id=INSTALLATION, client_instance_id=INSTANCE,
            request_verifier=request.public_verifier(), response_signer=authority_key,
            response_verifier=authority_key.public_verifier(), enable_client_response_floors=True)


def test_shared_mac_cannot_enroll_remote_floor(tmp_path):
    with pytest.raises(ValueError, match="independent Ed25519"):
        PersonalSentinelAuthority(tmp_path / "mac.json", installation_id=INSTALLATION,
            client_instance_id=INSTANCE, authenticator=HmacSha256Authenticator(b"x" * 32),
            enable_client_response_floors=True)


def test_production_requires_pinned_https_independent_enrollment_and_mode_proof(stack):
    request, signer, authority, _floor = stack
    server = authority(enable_client_response_floors=True)
    arguments = dict(installation_id=INSTALLATION, client_instance_id=INSTANCE,
        request_signer=request, response_verifier=signer.public_verifier(), clock=lambda: NOW)
    with pytest.raises(ValueError, match="pinned HTTPS"):
        RawSignedFloorClient(**arguments, transport=InProcessSentinelTransport(server, test_only=True),
            independently_administered=True)
    certificate = b"inert enrolled certificate fixture"

    class Gateway:
        def send(self, request):
            return GatewayTransportResponse(200, {"Content-Type": "application/json"},
                server.process(request.body), certificate, "127.0.0.1", True)

    pinned = PinnedHttpsSentinelTransport("https://127.0.0.1:9443/v1/authority",
        hashlib.sha256(certificate).hexdigest(), transport=Gateway())
    with pytest.raises(ValueError, match="independent administration"):
        RawSignedFloorClient(**arguments, transport=pinned)
    client = RawSignedFloorClient(**arguments, transport=pinned, independently_administered=True)
    assert _advance(client)
    # Explicit test mode never admits a claimed production response.
    test_client = RawSignedFloorClient(**arguments, transport=pinned, allow_test_transport=True)
    with pytest.raises(HighWaterRejected, match="transport mode"):
        _advance(test_client, sequence=2)


def test_primary_client_restart_rollback_rejected_by_remote_floor(stack):
    request, signer, authority, floor = stack
    remote = authority(enable_client_response_floors=True)
    primary = authority("primary.json")
    remote_floor = floor(remote)

    def parent(server):
        return PersonalSentinelAuthorityClient(installation_id=INSTALLATION, client_instance_id=INSTANCE,
            request_signer=request, response_verifier=signer.public_verifier(), response_floor=remote_floor,
            transport=InProcessSentinelTransport(server, test_only=True), allow_test_transport=True,
            clock=lambda: NOW)

    first = parent(primary)
    assert first.get_time_receipt().sequence == 1
    old_state = primary.state_path.read_bytes()
    assert first.get_time_receipt().sequence == 2
    primary.close()
    primary.state_path.write_bytes(old_state)  # Modeled host/primary snapshot replay, remote unchanged.
    rolled_back = authority("primary.json")
    with pytest.raises(HighWaterRejected, match="durable response floor rejected"):
        parent(rolled_back).get_time_receipt()


@pytest.mark.parametrize("kind", ["duplicate-namespace", "extra-namespace", "wrong-instance", "empty"])
def test_authenticated_malformed_floor_state_never_resets(stack, kind):
    _request, signer, authority, floor = stack
    server = authority(enable_client_response_floors=True)
    assert _advance(floor(server))
    document = json.loads(server.state_path.read_bytes())
    row = document["client_response_floors"][0]
    if kind == "duplicate-namespace":
        document["client_response_floors"] = [row, row]
    elif kind == "extra-namespace":
        row["namespace"] = "unknown"
    elif kind == "wrong-instance":
        row["client_instance_id"] = "d" * 32
    else:
        document["client_response_floors"] = []
    document.pop("state_signature")
    document["state_signature"] = signer.sign(_canonical(document))
    invalid = _canonical(document)
    server.state_path.write_bytes(invalid)
    with pytest.raises(HighWaterUnavailable):
        _advance(floor(server), sequence=2)
    assert server.state_path.read_bytes() == invalid
