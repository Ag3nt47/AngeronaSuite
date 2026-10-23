from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.engine_transport import canonical, private_directory
from angerona.core.personal_sentinel_authority import Ed25519PrivateSigner
from angerona.core.personal_sentinel_gateway import GatewayTransportResponse
from angerona.core.ugcap_witness import (
    AUTHORITY_KEY_ID, CLIENT_KEY_ID, MAX_BYTES, SCHEMA, WITNESS_DEFAULTS,
    WitnessAssessment, WitnessAuthority, WitnessClient, WitnessError,
    checkpoint, validate_settings,
)

NOW = 1_800_000_000.0
CERTIFICATE = b"inert-witness-tls-certificate"
PIN = hashlib.sha256(CERTIFICATE).hexdigest()


def observation(length=1, *, alternate=False):
    anchors = [{"length": n, "hash": hashlib.sha256(f"chain-{n}".encode()).hexdigest()}
               for n in range(1, length + 1)]
    if alternate:
        anchors[-1]["hash"] = "f" * 64
    return {"vault_id": "c" * 32, "baseline_id": "d" * 64,
            "chain_length": length, "chain_hash": anchors[-1]["hash"], "anchors": anchors[-128:]}


class Transport:
    def __init__(self, authority):
        self.authority, self.requests = authority, []
        self.mutate = lambda response: response

    def send(self, request):
        self.requests.append(request)
        return self.mutate(GatewayTransportResponse(200, {"Content-Type": "application/json"},
            self.authority.process(request.body), CERTIFICATE, "127.0.0.1", True))


@pytest.fixture
def witness(tmp_path):
    host = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id=CLIENT_KEY_ID)
    remote = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id=AUTHORITY_KEY_ID)
    folder = private_directory(tmp_path / "separate-witness")
    authority = WitnessAuthority(folder / "state.json", installation_id="a" * 32,
        client_id="b" * 32, vault_id="c" * 32, baseline_id="d" * 64,
        client_verifier=host.public_verifier(), signer=remote, clock=lambda: NOW, initialize=True)
    transport = Transport(authority)
    client = WitnessClient(endpoint="https://127.0.0.1:9444/v1/ugcap-witness",
        certificate_sha256=PIN, installation_id="a" * 32, client_id="b" * 32,
        signer=host, authority_verifier=remote.public_verifier(), transport=transport, clock=lambda: NOW)
    yield SimpleNamespace(host=host, remote=remote, authority=authority, transport=transport, client=client)
    authority.close()


def test_checkpoint_cas_heartbeat_and_old_valid_host_snapshot(witness):
    assert witness.client.exchange(observation()).status == "enrolled"
    assert witness.client.exchange(observation(2)).status == "advanced"
    assert witness.client.exchange(observation(2), heartbeat=True).status == "matched"
    # A replacement process restores the old valid local checkpoint/key, while
    # the separately retained witness remains unchanged. A fresh nonce prevents
    # receipt replay; the actual retained chain catches the old host snapshot.
    restored = WitnessClient(endpoint=witness.client.enrollment.endpoint_url, certificate_sha256=PIN,
        installation_id="a" * 32, client_id="b" * 32, signer=witness.host,
        authority_verifier=witness.remote.public_verifier(), transport=witness.transport, clock=lambda: NOW)
    rollback = restored.exchange(observation())
    assert rollback.status == "rollback" and not rollback.gate_allowed
    assert witness.client.exchange(observation(2), heartbeat=True).gate_allowed
    assert not rollback.snapshot()["whole_witness_snapshot_rollback_proof"]


def test_fork_and_gap_cannot_replace_or_enroll_via_heartbeat(witness):
    assert witness.client.exchange(observation(), heartbeat=True).status == "not-enrolled"
    witness.client.exchange(observation())
    assert witness.client.exchange(observation(2), heartbeat=True).status == "gap"
    assert witness.client.exchange(observation(1, alternate=True)).status == "conflict"
    assert witness.client.exchange(observation(), heartbeat=True).gate_allowed


def test_live_nonce_capacity_rejects_replay_until_expiry_even_after_restart(witness):
    for _ in range(256):
        assert witness.client.exchange(observation()).gate_allowed
    first = witness.transport.requests[0].body
    with pytest.raises(WitnessError, match="unreachable"):
        witness.client.exchange(observation())
    rejected = witness.transport.requests[-1].body
    with pytest.raises(WitnessError, match="nonce-capacity"):
        witness.authority.process(rejected)
    with pytest.raises(WitnessError, match="nonce-replay"):
        witness.authority.process(first)
    clock = [NOW]
    witness.authority.close()
    authority = WitnessAuthority(witness.authority.path, installation_id="a" * 32,
        client_id="b" * 32, vault_id="c" * 32, baseline_id="d" * 64,
        client_verifier=witness.host.public_verifier(), signer=witness.remote, clock=lambda: clock[0])
    witness.transport.authority = authority
    witness.client.clock = lambda: clock[0]
    try:
        with pytest.raises(WitnessError, match="nonce-replay"):
            authority.process(first)
        clock[0] = NOW + 30
        with pytest.raises(WitnessError, match="nonce-capacity"):
            authority.process(rejected)
        with pytest.raises(WitnessError, match="nonce-replay"):
            authority.process(first)
        clock[0] = NOW + 31
        assert witness.client.exchange(observation()).status == "matched"
        retained = authority._load()
        assert retained["sequence"] == 257 and len(retained["nonces"]) == 1
        assert authority.path.stat().st_size <= MAX_BYTES
        with pytest.raises(WitnessError, match="freshness"):
            authority.process(first)
    finally:
        authority.close()


def test_retained_server_state_authenticates_across_restart_and_rejects_loss(witness):
    witness.client.exchange(observation(2))
    witness.authority.close()
    old = witness.authority
    authority = WitnessAuthority(old.path, installation_id="a" * 32,
        client_id="b" * 32, vault_id="c" * 32, baseline_id="d" * 64,
        client_verifier=witness.host.public_verifier(), signer=witness.remote, clock=lambda: NOW)
    witness.transport.authority = authority
    witness.authority = authority
    try:
        assert witness.client.exchange(observation()).status == "rollback"
        authority.path.unlink()
        with pytest.raises(WitnessError, match="unreachable"):
            witness.client.exchange(observation())
    finally:
        authority.close()


def test_witness_restart_after_state_loss_never_implicitly_reenrolls(witness):
    witness.client.exchange(observation(2))
    authority = witness.authority
    authority.close()
    authority.path.unlink()
    arguments = dict(installation_id="a" * 32, client_id="b" * 32, vault_id="c" * 32,
        baseline_id="d" * 64, client_verifier=witness.host.public_verifier(),
        signer=witness.remote, clock=lambda: NOW)
    with pytest.raises(WitnessError, match="state-lost"):
        WitnessAuthority(authority.path, **arguments)
    with pytest.raises(WitnessError, match="may-not-overwrite"):
        WitnessAuthority(authority.path, initialize=True, **arguments)
    assert authority.marker.exists() and not authority.path.exists()


def test_no_implicit_initial_enrollment_or_marker_loss(tmp_path):
    host = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id=CLIENT_KEY_ID)
    remote = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id=AUTHORITY_KEY_ID)
    folder = private_directory(tmp_path / "separate")
    path = folder / "state.json"
    arguments = dict(installation_id="a" * 32, client_id="b" * 32, vault_id="c" * 32,
        baseline_id="d" * 64, client_verifier=host.public_verifier(), signer=remote)
    with pytest.raises(WitnessError, match="enrollment-required"):
        WitnessAuthority(path, **arguments)
    authority = WitnessAuthority(path, initialize=True, **arguments)
    authority.close()
    authority.marker.unlink()
    with pytest.raises(WitnessError, match="enrollment-required"):
        WitnessAuthority(path, **arguments)
    with pytest.raises(WitnessError, match="may-not-overwrite"):
        WitnessAuthority(path, initialize=True, **arguments)


def test_authority_close_retains_lease_until_admitted_cas_retires(witness, monkeypatch):
    import threading

    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    original = witness.authority._save
    def blocked(state):
        entered.set()
        assert release.wait(3)
        original(state)
    monkeypatch.setattr(witness.authority, "_save", blocked)
    errors = []
    def request():
        try:
            witness.client.exchange(observation())
        except Exception as exc:
            errors.append(exc)
    worker = threading.Thread(target=request)
    closer = threading.Thread(target=lambda: (witness.authority.close(), closed.set()))
    worker.start()
    try:
        assert entered.wait(2)
        closer.start()
        assert not closed.wait(.05)
        assert witness.authority._lease.held
    finally:
        release.set()
        worker.join(3)
        closer.join(3)
    assert not worker.is_alive() and not closer.is_alive() and closed.is_set() and not errors


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(installation_id="e" * 32),
    lambda value: value.update(client_id="e" * 32),
    lambda value: value.update(nonce="X" * 43),
    lambda value: value.update(operation="reset"),
    lambda value: value.update(received_at=NOW - 61),
    lambda value: value.update(sequence=True),
    lambda value: value.update(extra="ambiguous"),
])
def test_even_signed_ambiguous_stale_or_wrong_identity_receipts_fail(witness, mutation):
    def alter(response):
        value = json.loads(response.body)
        mutation(value)
        value.pop("signature")
        value["signature"] = witness.remote.sign(canonical(value))
        return GatewayTransportResponse(200, response.headers, canonical(value), CERTIFICATE, "127.0.0.1", True)
    witness.transport.mutate = alter
    with pytest.raises(WitnessError):
        witness.client.exchange(observation())


@pytest.mark.parametrize("change", [
    {"tls_verified": False}, {"peer_ip": "127.0.0.2"},
    {"peer_certificate_der": b"wrong"}, {"status_code": 302},
    {"headers": {"Content-Type": "text/plain"}}, {"body": b"x" * (MAX_BYTES + 1)},
])
def test_tls_pin_peer_redirect_and_size_boundaries(witness, change):
    witness.transport.mutate = lambda response: GatewayTransportResponse(**{**response.__dict__, **change})
    with pytest.raises(WitnessError):
        witness.client.exchange(observation())


def test_replayed_request_and_response_and_wrong_signer_fail(witness):
    witness.client.exchange(observation())
    first = witness.transport.requests[-1]
    with pytest.raises(WitnessError, match="nonce-replay"):
        witness.authority.process(first.body)
    original = witness.transport.mutate
    captured = []
    witness.transport.mutate = lambda response: captured.append(response) or original(response)
    witness.client.exchange(observation())
    witness.transport.mutate = lambda _response: captured[-1]
    with pytest.raises(WitnessError, match="nonce"):
        witness.client.exchange(observation())
    witness.transport.mutate = lambda response: response
    witness.client.verifier = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id="wrong").public_verifier()
    with pytest.raises(WitnessError, match="signature"):
        witness.client.exchange(observation())


def test_signed_protocol_accepts_only_fixed_bounded_hash_fields(witness):
    for raw in (b'{}', b'{"schema":1,"schema":2}', b'{"schema":NaN}', b"x" * (MAX_BYTES + 1)):
        with pytest.raises(WitnessError):
            witness.authority.process(raw)
    bad = observation()
    bad["source"] = "PRIVATE_SOURCE"
    with pytest.raises(WitnessError):
        witness.client.exchange(bad)
    witness.client.exchange(observation())
    wire = witness.transport.requests[-1].body
    assert all(s not in wire for s in (b"PRIVATE", b"vault_path", b"passcode", b"repository"))
    assert set(json.loads(wire)["checkpoint"]) == set(observation())


def test_concurrent_conflicting_cas_has_one_winner(witness):
    witness.client.exchange(observation())
    def advance(alternate):
        client = WitnessClient(endpoint=witness.client.enrollment.endpoint_url, certificate_sha256=PIN,
            installation_id="a" * 32, client_id="b" * 32, signer=witness.host,
            authority_verifier=witness.remote.public_verifier(), transport=witness.transport, clock=lambda: NOW)
        return client.exchange(observation(2, alternate=alternate)).status
    with ThreadPoolExecutor(2) as workers:
        assert sorted(workers.map(advance, (False, True))) == ["advanced", "conflict"]


def test_host_and_server_clock_rollback_fail_closed(witness):
    witness.client.exchange(observation())
    witness.client.clock = lambda: NOW - 1
    with pytest.raises(WitnessError, match="host-clock"):
        witness.client.exchange(observation())
    witness.client.clock = lambda: NOW
    witness.authority.clock = lambda: NOW - 1
    with pytest.raises(WitnessError, match="unreachable"):
        witness.client.exchange(observation())


def test_no_endpoint_or_new_vault_can_reset_server(witness):
    witness.client.exchange(observation(2))
    value = observation()
    value["vault_id"] = "e" * 32
    with pytest.raises(WitnessError):
        witness.client.exchange(value)
    assert witness.client.exchange(observation(2), heartbeat=True).gate_allowed


def test_optin_validation_private_pinned_identity_and_false_default(witness):
    assert validate_settings(dict(WITNESS_DEFAULTS))["ugcap_witness_enabled"] is False
    settings = {**WITNESS_DEFAULTS, "ugcap_witness_enabled": True,
        "ugcap_witness_endpoint": witness.client.enrollment.endpoint_url,
        "ugcap_witness_certificate_sha256": PIN,
        "ugcap_witness_installation_id": "a" * 32, "ugcap_witness_client_id": "b" * 32,
        "ugcap_witness_authority_public_key": witness.remote.public_verifier()._public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "ugcap_witness_client_certificate_path": str(witness.authority.path.parent / "client.pem"),
        "ugcap_witness_client_key_path": str(witness.authority.path.parent / "client-key.pem")}
    assert validate_settings(settings) == settings
    for change in ({"ugcap_witness_enabled": 1}, {"ugcap_witness_endpoint": "https://example.com/v1/ugcap-witness"},
                   {"ugcap_witness_endpoint": "http://127.0.0.1/v1/ugcap-witness"},
                   {"ugcap_witness_certificate_sha256": "bad"}, {"ugcap_witness_client_id": "wrong"},
                   {"ugcap_witness_client_key_path": ""}):
        with pytest.raises((WitnessError, ValueError)):
            validate_settings({**settings, **change})


def test_guard_witness_optin_holds_before_mesh_and_failure_reholds_without_response(witness):
    from angerona.core.eventbus import EventBus
    from angerona.modules.ugcap_guard import UGCAPGuardModule

    paused, activations = [], []
    config = SimpleNamespace(data_dir=witness.authority.path.parent, ugcap_enabled=True)
    manager = SimpleNamespace(config=config, ugcap_paused=True,
        pause_for_ugcap=lambda reason: paused.append(reason) or {"paused": True},
        freeze_enclave_mesh=lambda: None, activate_enclave_mesh=lambda report: activations.append(report) or True)
    guard = UGCAPGuardModule(witness_factory=lambda *_: witness.client)
    guard.bind(EventBus())
    guard.bind_manager(manager)
    guard._settings["ugcap_witness_enabled"] = True
    witness.client.exchange(observation(2))
    guard._accept_report({"status": "verified", "witness_checkpoint": observation()}, 0)
    assert guard.dashboard_snapshot()["status"] == "witness-held" and not activations
    assert guard.dashboard_snapshot()["witness"]["status"] == "rollback"
    manager.ugcap_paused = False
    witness.transport.send = lambda _request: (_ for _ in ()).throw(OSError("secret endpoint"))
    assert not guard._check_witness(observation(2), heartbeat=True)
    assert paused and "secret endpoint" not in json.dumps(guard.dashboard_snapshot())
    assert not guard.dashboard_snapshot()["witness"]["response_authorized"]


def test_checkpoint_is_detached_and_validates_anchor_sequence():
    value = observation(3)
    detached = checkpoint(value)
    detached["anchors"][0]["hash"] = "f" * 64
    assert value["anchors"][0]["hash"] != "f" * 64
    value["anchors"].reverse()
    with pytest.raises(WitnessError):
        checkpoint(value)


def test_actual_encrypted_vault_old_valid_snapshot_conflicts_with_retained_witness(tmp_path):
    import base64
    import shutil

    from angerona.core.ugcap import UGCAPVault

    class Hardware:
        def identity(self):
            return {"provider": "inert-test", "key_id": "fixture"}

        def seal(self, secret):
            return {"fixture": base64.b64encode(secret).decode()}

        def unseal(self, sealed, challenge):
            assert len(challenge) == 32
            return base64.b64decode(sealed["fixture"])

    repo, media = tmp_path / "repo", tmp_path / "media"
    repo.mkdir()
    media.mkdir()
    (repo / "main.py").write_text("PRISTINE_FIXTURE = True\n")
    vault = UGCAPVault(repo, media / "vault.ugcap", Hardware(),
        media_validator=lambda *_: {"volume_id": "fixture-secondary", "validated": True})
    vault.initialize("inert long fixture passphrase")
    first = vault.verify("inert long fixture passphrase")
    snapshot = tmp_path / "old-valid-snapshot"
    shutil.copytree(media, snapshot)
    host = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id=CLIENT_KEY_ID)
    remote = Ed25519PrivateSigner(Ed25519PrivateKey.generate(), key_id=AUTHORITY_KEY_ID)
    folder = private_directory(tmp_path / "independent-witness")
    point = first["witness_checkpoint"]
    authority = WitnessAuthority(folder / "state.json", installation_id="a" * 32, client_id="b" * 32,
        vault_id=point["vault_id"], baseline_id=point["baseline_id"],
        client_verifier=host.public_verifier(), signer=remote, initialize=True)
    client = WitnessClient(endpoint="https://127.0.0.1:9444/v1/ugcap-witness", certificate_sha256=PIN,
        installation_id="a" * 32, client_id="b" * 32, signer=host,
        authority_verifier=remote.public_verifier(), transport=Transport(authority))
    try:
        assert client.exchange(point).gate_allowed
        second = vault.verify("inert long fixture passphrase")
        assert client.exchange(second["witness_checkpoint"]).status == "advanced"
        for path in media.iterdir():
            path.unlink()
        for path in snapshot.iterdir():
            shutil.copyfile(path, media / path.name)
        restored = vault.verify("inert long fixture passphrase")
        assert restored["status"] == "verified"  # AES-GCM and local chain remain valid.
        result = client.exchange(restored["witness_checkpoint"])
        assert result.status == "conflict" and not result.gate_allowed
        assert restored["audit"]["rollback_proof"] is False
    finally:
        authority.close()


def test_actual_private_mtls_pin_before_request_and_native_shutdown(witness, monkeypatch):
    import datetime as dt
    import ipaddress
    import os
    import socket
    import ssl
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    from angerona.core.engine_transport import create_private_file
    from tools.ugcap_witness_server import WitnessHTTPServer, handler_for

    folder = witness.authority.path.parent
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Inert local witness CA")])
    now = dt.datetime.now(dt.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))

    def certificate(name, usage, *, ip=False):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name)])).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False))
        if ip:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        cert_path, key_path = folder / (name + ".pem"), folder / (name + "-key.pem")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        descriptor = create_private_file(key_path)
        import os
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        return cert, cert_path, key_path

    server_cert, server_path, server_key = certificate("server", ExtendedKeyUsageOID.SERVER_AUTH, ip=True)
    _client_cert, client_path, client_key = certificate("client", ExtendedKeyUsageOID.CLIENT_AUTH)
    ca_path = folder / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(server_path, server_key)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(ca_path))
    handler = handler_for(witness.authority, request_timeout=1.0)
    server = WitnessHTTPServer(("127.0.0.1", 0), handler, tls_context=context)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.05), name="InertWitnessTLS")
    thread.start()
    endpoint = f"https://127.0.0.1:{server.server_port}/v1/ugcap-witness"
    kwargs = dict(endpoint=endpoint, installation_id="a" * 32, client_id="b" * 32,
        signer=witness.host, authority_verifier=witness.remote.public_verifier(), clock=lambda: NOW,
        client_certificate_path=str(client_path), client_key_path=str(client_key), ca_bundle_path=str(ca_path))
    drip_thread = None
    stop_drip = threading.Event()
    try:
        bad_pin = WitnessClient(certificate_sha256="f" * 64, **kwargs)
        with pytest.raises(WitnessError, match="unreachable"):
            bad_pin.exchange(observation())
        assert witness.authority._load()["sequence"] == 0, "pin mismatch must send no signed request"
        client = WitnessClient(certificate_sha256=server_cert.fingerprint(hashes.SHA256()).hex(), **kwargs)
        assert client.exchange(observation()).gate_allowed
        assert client.exchange(observation(), heartbeat=True).status == "matched"
        # An authorized peer drips an unfinished request line faster than the
        # per-recv timeout. Shutdown still drains it at the total deadline.
        started = threading.Event()
        def drip():
            context = ssl.create_default_context(cafile=str(ca_path))
            context.load_cert_chain(str(client_path), str(client_key))
            try:
                with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as raw:
                    with context.wrap_socket(raw, server_hostname="127.0.0.1") as secured:
                        secured.sendall(b"P")
                        started.set()
                        while not stop_drip.wait(.05):
                            secured.sendall(b"x")
            except OSError:
                pass
        drip_thread = threading.Thread(target=drip, name="InertWitnessHeaderDrip")
        drip_thread.start()
        assert started.wait(3)
    finally:
        import time
        closing = time.monotonic()
        server.shutdown()
        server.server_close()
        thread.join(3)
        stop_drip.set()
        if drip_thread is not None:
            drip_thread.join(3)
        assert time.monotonic() - closing < 5
    assert not thread.is_alive()
    assert drip_thread is None or not drip_thread.is_alive()
    assert not server._preauth_threads
    # Also exercise the actual CLI's custody, asymmetric key loading, mandatory
    # mTLS context and final lease release. A bounded inert serve loop avoids
    # opening a second listener or leaving a daemon process behind.
    from tools import ugcap_witness_server as cli
    host_public = folder / "enrolled-host-public.pem"
    authority_private = folder / "authority-private.pem"
    host_public.write_bytes(witness.host.public_verifier()._public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    descriptor = create_private_file(authority_private)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(witness.remote._private_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    stopped = []
    class InertServer:
        def __init__(self, *args, tls_context):
            assert tls_context.verify_mode == ssl.CERT_REQUIRED

        def serve_forever(self, **kwargs):
            raise KeyboardInterrupt

        def server_close(self):
            stopped.append(True)
    monkeypatch.setattr(cli, "WitnessHTTPServer", InertServer)
    assert cli.main(["--state", str(folder / "cli-state.json"), "--initialize",
        "--installation-id", "a" * 32, "--client-id", "b" * 32,
        "--vault-id", "c" * 32, "--baseline-id", "d" * 64,
        "--client-public-key-file", str(host_public), "--authority-private-key-file", str(authority_private),
        "--tls-cert", str(server_path), "--tls-key", str(server_key), "--client-ca", str(ca_path)]) == 0
    assert stopped == [True]


def test_worker_witness_wait_cannot_outlive_operator_gate_revocation(tmp_path):
    import threading

    from angerona.core.eventbus import EventBus
    from angerona.modules.ugcap_guard import UGCAPGuardModule

    entered, release, activated = threading.Event(), threading.Event(), []
    class DelayedWitness:
        def exchange(self, *_args, **_kwargs):
            entered.set()
            assert release.wait(3)
            return WitnessAssessment("matched", "fresh-separate-witness-checkpoint", 1, NOW, True)

    manager = SimpleNamespace(config=SimpleNamespace(data_dir=tmp_path), ugcap_paused=True,
        pause_for_ugcap=lambda *_: {"paused": True}, freeze_enclave_mesh=lambda: None,
        activate_enclave_mesh=lambda report: activated.append(report) or True)
    guard = UGCAPGuardModule(witness_factory=lambda *_: DelayedWitness())
    guard.bind(EventBus())
    guard.bind_manager(manager)
    guard._settings["ugcap_witness_enabled"] = True
    worker = threading.Thread(target=lambda: guard._accept_report(
        {"status": "verified", "witness_checkpoint": observation()}, 0))
    worker.start()
    try:
        assert entered.wait(2)
        assert guard.queue_lock()
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive() and not activated


def test_stale_cached_receipt_never_displays_fresh_assurance(witness, monkeypatch):
    from angerona.core.eventbus import EventBus
    from angerona.modules import ugcap_guard

    guard = ugcap_guard.UGCAPGuardModule(witness_factory=lambda *_: witness.client)
    guard.bind(EventBus())
    guard._settings["ugcap_witness_enabled"] = True
    assert guard._check_witness(observation())
    at = guard._witness_succeeded_at
    monkeypatch.setattr(ugcap_guard.time, "monotonic", lambda: at + 91)
    snapshot = guard.dashboard_snapshot()["witness"]
    assert snapshot["status"] == "stale" and snapshot["gate_allowed"] is False


@pytest.mark.parametrize("change", [
    {"ugcap_witness_enabled": False},
    {"ugcap_witness_client_id": "e" * 32},
    {"ugcap_witness_certificate_sha256": "f" * 64},
])
def test_optout_or_enrollment_change_revokes_cached_witness_receipt(witness, monkeypatch, change):
    from angerona.core.eventbus import EventBus
    from angerona.modules import ugcap_guard

    guard = ugcap_guard.UGCAPGuardModule(witness_factory=lambda *_: witness.client)
    guard.bind(EventBus())
    guard._settings.update({**WITNESS_DEFAULTS, "ugcap_witness_enabled": True,
        "ugcap_witness_endpoint": witness.client.enrollment.endpoint_url,
        "ugcap_witness_certificate_sha256": PIN,
        "ugcap_witness_installation_id": "a" * 32, "ugcap_witness_client_id": "b" * 32,
        "ugcap_witness_authority_public_key": witness.remote.public_verifier()._public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "ugcap_witness_client_certificate_path": str(witness.authority.path.parent / "client.pem"),
        "ugcap_witness_client_key_path": str(witness.authority.path.parent / "client-key.pem")})
    assert guard._check_witness(observation())
    at = guard._witness_succeeded_at
    monkeypatch.setattr(ugcap_guard.time, "monotonic", lambda: at + 91)
    assert guard.dashboard_snapshot()["witness"]["status"] == "stale"
    assert guard.configure_settings(**change)["queued"]
    guard._process_one()
    snapshot = guard.dashboard_snapshot()["witness"]
    assert snapshot["gate_allowed"] is False
    assert snapshot["assurance"] != "fresh-separate-witness-checkpoint"
    assert guard._witness_succeeded_at is None and guard._witness_checkpoint is None
    expected = "verification-checkpoint-required" if guard._settings["ugcap_witness_enabled"] else "deployment-required"
    assert snapshot["status"] == expected


@pytest.mark.parametrize("provider_fails", [False, True])
def test_explicit_host_key_provision_revokes_prior_receipt_even_on_custody_failure(witness, monkeypatch, provider_fails):
    from angerona.core import ugcap_witness
    from angerona.core.eventbus import EventBus
    from angerona.modules.ugcap_guard import UGCAPGuardModule

    guard = UGCAPGuardModule(witness_factory=lambda *_: witness.client)
    guard.bind(EventBus())
    guard._settings["ugcap_witness_enabled"] = True
    assert guard._check_witness(observation())
    guard._witness_public_key = "previous-public-key"

    def provision(_root):
        snapshot = guard.dashboard_snapshot()["witness"]
        assert snapshot["gate_allowed"] is False and guard._witness_succeeded_at is None
        if provider_fails:
            raise OSError("inert unavailable key custody")
        return "replacement-public-key"

    monkeypatch.setattr(ugcap_witness, "provision_host_identity", provision)
    assert guard.queue_provision_witness_key()
    guard._process_one()
    snapshot = guard.dashboard_snapshot()
    assert snapshot["witness"]["gate_allowed"] is False
    assert snapshot["witness"]["assurance"] == "unverified-witness"
    assert guard._witness_succeeded_at is None and guard._witness_checkpoint is None
    assert snapshot["witness_host_public_key"] == ("" if provider_fails else "replacement-public-key")


def test_config_optin_roundtrip_and_invalid_enrollment_stays_required(tmp_path, monkeypatch):
    from angerona.core.config import Config

    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    config = Config(data_dir=tmp_path)
    assert not config.ugcap_witness_enabled
    config.save()
    assert not Config.load().ugcap_witness_enabled
    config.settings_path.write_text(json.dumps({"ugcap_witness_enabled": True,
        "ugcap_witness_endpoint": "https://public.example/v1/ugcap-witness"}))
    loaded = Config.load()
    assert loaded.ugcap_witness_enabled is True  # malformed opt-in cannot silently downgrade.
    assert loaded.ugcap_witness_endpoint == ""


def test_public_key_setting_rejects_private_pem_even_when_disabled():
    key = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    with pytest.raises(ValueError):
        validate_settings({**WITNESS_DEFAULTS, "ugcap_witness_authority_public_key": key})


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="real Windows current-user DPAPI boundary")
def test_explicit_host_key_is_dpapi_stored_never_ambient_or_replaced(tmp_path, monkeypatch):
    import os

    from angerona.core.secure_store import read_secret_values, secure_store_path
    from angerona.core.ugcap_witness import KEY_NAME, provision_host_identity

    monkeypatch.setenv(KEY_NAME, "ambient-attacker-value")
    public = provision_host_identity(tmp_path)
    assert "BEGIN PUBLIC KEY" in public and "PRIVATE" not in public
    assert KEY_NAME not in os.environ
    private = read_secret_values((KEY_NAME,), tmp_path, strict=True)[KEY_NAME]
    assert "BEGIN PRIVATE KEY" in private
    assert private.encode() not in secure_store_path(tmp_path).read_bytes()
    assert provision_host_identity(tmp_path) == public
