import hashlib
import json

import pytest

from angerona.core.personal_sentinel_gateway import (
    GatewayConfigurationError,
    GatewayEnrollment,
    GatewayMonitorBinding,
    GatewayTransportResponse,
    PersonalSentinelGatewayClient,
    load_gateway_monitor_binding,
    self_test,
    witness_receipt_hash,
)


NOW = 2_000_000_000.0
CERTIFICATE = b"fake-der-certificate-for-transport-only"
PIN = hashlib.sha256(CERTIFICATE).hexdigest()
POLICY = hashlib.sha256(b"personal-sentinel-policy").hexdigest()
PRIVACY_KEY = b"personal-sentinel-test-privacy-key"
NONCE = "N" * 43


class FakeTransport:
    def __init__(
        self,
        *,
        mutate=None,
        status=200,
        headers=None,
        certificate=CERTIFICATE,
        peer_ip="192.168.50.1",
        tls_verified=True,
        raw_body=None,
        error=None,
    ):
        self.mutate = mutate
        self.status = status
        self.headers = headers or {"content-type": "application/json; charset=utf-8"}
        self.certificate = certificate
        self.peer_ip = peer_ip
        self.tls_verified = tls_verified
        self.raw_body = raw_body
        self.error = error
        self.requests = []

    def send(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        request_document = json.loads(request.body.decode("utf-8"))
        document = {
            "schema_version": 1,
            "nonce": request_document["nonce"],
            "attested_at": NOW - 1,
            "expires_at": NOW + 20,
            "policy_digest": POLICY,
            "path_status": "gateway-attested",
        }
        if self.mutate:
            self.mutate(document)
        body = self.raw_body
        if body is None:
            body = json.dumps(document, separators=(",", ":")).encode("utf-8")
        return GatewayTransportResponse(
            self.status,
            self.headers,
            body,
            self.certificate,
            self.peer_ip,
            self.tls_verified,
        )


def _enrollment(**overrides):
    values = {
        "endpoint_url": "https://192.168.50.1:9443/v1/attest",
        "certificate_sha256": PIN,
        "policy_digest": POLICY,
    }
    values.update(overrides)
    return GatewayEnrollment(**values)


def _client(transport, enrollment=None):
    return PersonalSentinelGatewayClient(
        enrollment or _enrollment(),
        PRIVACY_KEY,
        transport=transport,
        clock=lambda: NOW,
        nonce_factory=lambda: NONCE,
    )


def test_success_requires_pin_nonce_policy_and_freshness_but_grants_no_resource_trust():
    transport = FakeTransport()
    result = _client(transport).attest()
    assert result.success is True
    assert result.path_label == "gateway-attested"
    assert result.reason_code == "verified"
    assert result.endpoint_resources_trusted is False
    assert result.response_authorized is False
    assert result.endpoint_token.startswith("tok_")
    assert result.certificate_token.startswith("tok_")
    request = transport.requests[0]
    assert request.require_tls_validation is True
    assert request.endpoint_url == _enrollment().endpoint_url
    assert request.connect_timeout <= 10
    assert request.read_timeout <= 10
    assert "Authorization" not in request.headers


def test_optional_mutual_tls_paths_are_forwarded_without_reading_or_storing_credentials():
    transport = FakeTransport()
    enrollment = _enrollment(
        client_certificate_path="C:/sentinel/client.pem",
        client_key_path="C:/sentinel/client.key",
        ca_bundle_path="C:/sentinel/private-ca.pem",
    )
    assert _client(transport, enrollment).attest().success is True
    request = transport.requests[0]
    assert request.client_certificate_path.endswith("client.pem")
    assert request.client_key_path.endswith("client.key")
    assert request.ca_bundle_path.endswith("private-ca.pem")


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://192.168.50.1/attest",
        "https://8.8.8.8/attest",
        "https://169.254.169.254/latest/meta-data",
        "https://[fe80::1]/attest",
        "https://router.example/attest",
        "https://user:password@192.168.50.1/attest",
        "https://192.168.50.1/attest?target=10.0.0.1",
        "https://192.168.50.1/attest#fragment",
    ],
)
def test_enrollment_rejects_ssrf_public_metadata_credentials_and_ambiguous_urls(endpoint):
    with pytest.raises(GatewayConfigurationError):
        _enrollment(endpoint_url=endpoint)


def test_loopback_and_private_ipv6_are_explicitly_enrollable():
    assert _enrollment(endpoint_url="https://127.0.0.1/attest")
    assert _enrollment(endpoint_url="https://localhost/attest")
    assert _enrollment(endpoint_url="https://[fd00::1]/attest")


@pytest.mark.parametrize(
    ("transport", "reason"),
    [
        (FakeTransport(certificate=b"different-certificate"), "certificate-pin-mismatch"),
        (FakeTransport(tls_verified=False), "tls-unverified"),
        (FakeTransport(peer_ip="8.8.8.8"), "peer-address-rejected"),
        (FakeTransport(peer_ip="192.168.50.2"), "peer-address-rejected"),
        (FakeTransport(status=302), "redirect-rejected"),
        (FakeTransport(status=503), "http-status-rejected"),
        (FakeTransport(headers={"content-type": "text/html"}), "content-type-rejected"),
        (FakeTransport(error=RuntimeError("raw endpoint diagnostic")), "transport-failed"),
    ],
)
def test_transport_tls_pin_peer_redirect_and_content_fail_closed(transport, reason):
    result = _client(transport).attest()
    assert result.success is False
    assert result.path_label == "untrusted"
    assert result.reason_code == reason
    assert result.response_authorized is False


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda row: row.update(nonce="wrong" * 10), "nonce-mismatch"),
        (lambda row: row.update(policy_digest="0" * 64), "policy-digest-mismatch"),
        (lambda row: row.update(attested_at=NOW - 61), "attestation-stale"),
        (lambda row: row.update(attested_at=NOW + 6), "attestation-future-dated"),
        (lambda row: row.update(expires_at=NOW - 1), "attestation-expired"),
        (lambda row: row.update(expires_at=NOW + 120), "attestation-lifetime-rejected"),
        (lambda row: row.update(path_status="trusted"), "path-status-rejected"),
        (lambda row: row.update(extra="ambiguous"), "attestation-schema-rejected"),
    ],
)
def test_nonce_policy_freshness_status_and_schema_fail_closed(mutation, reason):
    result = _client(FakeTransport(mutate=mutation)).attest()
    assert result.success is False
    assert result.path_label == "untrusted"
    assert result.reason_code == reason


def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected_as_ambiguous():
    duplicate = (
        b'{"schema_version":1,"nonce":"' + NONCE.encode() +
        b'","nonce":"' + NONCE.encode() +
        b'","attested_at":1999999999,"expires_at":2000000020,'
        b'"policy_digest":"' + POLICY.encode() +
        b'","path_status":"gateway-attested"}'
    )
    duplicate_result = _client(FakeTransport(raw_body=duplicate)).attest()
    assert duplicate_result.reason_code == "attestation-schema-rejected"
    nonfinite = duplicate.replace(
        b'"nonce":"' + NONCE.encode() + b'","nonce":"' + NONCE.encode() + b'"',
        b'"nonce":"' + NONCE.encode() + b'"',
    ).replace(b"1999999999", b"NaN")
    nonfinite_result = _client(FakeTransport(raw_body=nonfinite)).attest()
    assert nonfinite_result.reason_code == "attestation-schema-rejected"


def test_response_body_and_header_bounds_are_rechecked_across_transport_boundary():
    enrollment = _enrollment(max_response_bytes=512)
    body_result = _client(
        FakeTransport(raw_body=b"{" + b"x" * 512 + b"}"), enrollment
    ).attest()
    assert body_result.reason_code == "response-size-rejected"
    headers = {f"x-{index}": "value" for index in range(65)}
    header_result = _client(FakeTransport(headers=headers)).attest()
    assert header_result.reason_code == "headers-invalid"


@pytest.mark.parametrize(
    "overrides",
    [
        {"connect_timeout": 0},
        {"read_timeout": 11},
        {"max_response_bytes": 511},
        {"max_response_bytes": 65537},
        {"max_attestation_age": 301},
        {"client_certificate_path": "client.pem"},
        {"certificate_sha256": "not-a-pin"},
        {"policy_digest": "not-a-digest"},
    ],
)
def test_enrollment_bounds_and_mtls_pairing_are_strict(overrides):
    with pytest.raises(GatewayConfigurationError):
        _enrollment(**overrides)


def test_event_details_are_tokenized_and_never_imply_authority():
    result = _client(FakeTransport()).attest()
    details = result.event_details()
    assert "192.168.50.1" not in repr(details)
    assert details["endpoint_resources_trusted"] is False
    assert details["response_authorized"] is False
    assert details["response_authority"] == "observe-only"


def test_gateway_self_test_is_offline_and_passes():
    assert self_test()[0] is True


def _write_gateway_config(path, document):
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)


def test_strict_fixed_file_loader_produces_explicit_interface_binding(tmp_path):
    path = tmp_path / "personal_sentinel_gateway.json"
    document = {
        "schema_version": 1,
        "interface_id": "Wi-Fi explicit binding",
        "endpoint_url": "https://192.168.50.1:9443/v1/attest",
        "certificate_sha256": PIN,
        "policy_digest": POLICY,
        "witness_endpoint_url": "https://192.168.50.1:9443/v1/witness",
        "connect_timeout": 1.5,
        "read_timeout": 2.0,
        "max_response_bytes": 4096,
    }
    _write_gateway_config(path, document)
    binding = load_gateway_monitor_binding(path)
    assert isinstance(binding, GatewayMonitorBinding)
    assert binding.interface_id == "Wi-Fi explicit binding"
    assert binding.enrollment.endpoint_url == document["endpoint_url"]
    assert binding.enrollment.witness_endpoint_url == document["witness_endpoint_url"]


def test_gateway_loader_absence_is_disabled_and_invalid_or_secret_fields_are_rejected(tmp_path):
    assert load_gateway_monitor_binding(tmp_path / "missing.json") is None
    base = {
        "schema_version": 1,
        "interface_id": "Ethernet",
        "endpoint_url": "https://192.168.50.1/v1/attest",
        "certificate_sha256": PIN,
        "policy_digest": POLICY,
    }
    unknown = tmp_path / "unknown.json"
    _write_gateway_config(unknown, {**base, "router_password": "forbidden"})
    with pytest.raises(GatewayConfigurationError):
        load_gateway_monitor_binding(unknown)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":1,"schema_version":1,"interface_id":"Ethernet",'
        f'"endpoint_url":"https://192.168.50.1/v1/attest",'
        f'"certificate_sha256":"{PIN}","policy_digest":"{POLICY}"}}',
        encoding="utf-8",
    )
    duplicate.chmod(0o600)
    with pytest.raises(GatewayConfigurationError):
        load_gateway_monitor_binding(duplicate)


def test_witness_endpoint_must_share_the_pinned_gateway_authority():
    with pytest.raises(GatewayConfigurationError):
        _enrollment(witness_endpoint_url="https://192.168.50.2:9443/v1/witness")
    with pytest.raises(GatewayConfigurationError):
        _enrollment(witness_endpoint_url="https://192.168.50.1:9444/v1/witness")


class WitnessTransport:
    def __init__(self, mutate=None):
        self.mutate = mutate
        self.requests = []

    def send(self, request):
        self.requests.append(request)
        sent = json.loads(request.body.decode("utf-8"))
        receipt = {
            "schema_version": 1,
            "nonce": sent["nonce"],
            "sequence": sent["sequence"],
            "previous_receipt_hash": sent["previous_receipt_hash"],
            "continuity_digest": sent["continuity_digest"],
            "event_count": sent["event_count"],
            "received_at": NOW - 0.5,
            "receipt_hash": witness_receipt_hash(
                sent["nonce"],
                sent["sequence"],
                sent["previous_receipt_hash"],
                sent["continuity_digest"],
                sent["event_count"],
            ),
            "status": "witnessed",
        }
        if self.mutate:
            self.mutate(receipt)
        return GatewayTransportResponse(
            200,
            {"content-type": "application/json"},
            json.dumps(receipt, separators=(",", ":")).encode("utf-8"),
            CERTIFICATE,
            "192.168.50.1",
            True,
        )


def _witness_client(transport, *, enrolled=True):
    enrollment = _enrollment(
        witness_endpoint_url=(
            "https://192.168.50.1:9443/v1/witness" if enrolled else ""
        )
    )
    return _client(transport, enrollment)


def test_compact_witness_is_explicit_nonce_chain_and_size_bound_with_no_raw_log_field():
    transport = WitnessTransport()
    digest = hashlib.sha256(b"compact-HMAC-or-hash-chain-head").hexdigest()
    receipt = _witness_client(transport).submit_witness(
        sequence=1,
        previous_receipt_hash="0" * 64,
        continuity_digest=digest,
        event_count=42,
    )
    assert receipt.success is True
    assert receipt.receipt_hash
    assert receipt.response_authorized is False
    sent = json.loads(transport.requests[0].body.decode("utf-8"))
    assert set(sent) == {
        "schema_version",
        "nonce",
        "issued_at",
        "sequence",
        "previous_receipt_hash",
        "continuity_digest",
        "event_count",
        "payload_kind",
    }
    assert sent["payload_kind"] == "log-continuity-digest"
    assert all("log" not in key or key == "payload_kind" for key in sent)
    assert receipt.event_details()["raw_logs_included"] is False


def test_witness_is_disabled_without_explicit_endpoint_and_rejects_bad_chain_inputs_preflight():
    transport = WitnessTransport()
    digest = hashlib.sha256(b"head").hexdigest()
    disabled = _witness_client(transport, enrolled=False).submit_witness(
        sequence=1,
        previous_receipt_hash="0" * 64,
        continuity_digest=digest,
        event_count=1,
    )
    assert disabled.reason_code == "witness-not-enrolled"
    bad_previous = _witness_client(transport).submit_witness(
        sequence=2,
        previous_receipt_hash="0" * 64,
        continuity_digest=digest,
        event_count=1,
    )
    assert bad_previous.reason_code == "previous-receipt-invalid"
    bad_size = _witness_client(transport).submit_witness(
        sequence=1,
        previous_receipt_hash="0" * 64,
        continuity_digest=digest,
        event_count=1_000_001,
    )
    assert bad_size.reason_code == "event-count-invalid"
    assert transport.requests == []


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda row: row.update(nonce="X" * 43), "witness-nonce-mismatch"),
        (lambda row: row.update(sequence=2), "witness-sequence-mismatch"),
        (lambda row: row.update(previous_receipt_hash="1" * 64), "witness-chain-echo-mismatch"),
        (lambda row: row.update(received_at=NOW - 61), "witness-freshness-rejected"),
        (lambda row: row.update(receipt_hash="f" * 64), "witness-receipt-hash-mismatch"),
        (lambda row: row.update(extra="ambiguous"), "witness-schema-rejected"),
    ],
)
def test_witness_receipt_nonce_sequence_chain_freshness_and_schema_fail_closed(mutation, reason):
    digest = hashlib.sha256(b"head").hexdigest()
    receipt = _witness_client(WitnessTransport(mutation)).submit_witness(
        sequence=1,
        previous_receipt_hash="0" * 64,
        continuity_digest=digest,
        event_count=5,
    )
    assert receipt.success is False
    assert receipt.reason_code == reason
    assert receipt.response_authorized is False
