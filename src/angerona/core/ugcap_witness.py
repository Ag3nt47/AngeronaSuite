"""Scoped UGCAP witness checkpoints, never a signing or command service.

A separately administered witness retains the newest authenticated vault head.
Fresh nonce-bound receipts expose host snapshot rollback against that retained
head. Full witness-appliance rollback and a hostile signing host remain outside
this assurance; this does not implement IndependentHighWater's external floor.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
import hashlib
import hmac
import http.client
import ipaddress
import math
import os
from pathlib import Path
import re
import secrets
import ssl
import threading
import time

from angerona.core.engine_transport import (
    canonical, create_private_file, decode, private_directory, verify_private,
)
from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.personal_sentinel_authority import Ed25519PrivateSigner, Ed25519PublicVerifier
from angerona.core.personal_sentinel_gateway import (
    GatewayEnrollment, GatewayTransportRequest, GatewayTransportResponse,
)

SCHEMA = "angerona.ugcap-witness.v1"
MAX_BYTES = 32 * 1024
MAX_ANCHORS = 128
MAX_CHAIN = 2048
KEY_NAME = "ANGERONA_UGCAP_WITNESS_PRIVATE_KEY"
CLIENT_KEY_ID = "ugcap-witness-host-v1"
AUTHORITY_KEY_ID = "ugcap-witness-authority-v1"
WITNESS_DEFAULTS = {
    "ugcap_witness_enabled": False,
    "ugcap_witness_endpoint": "", "ugcap_witness_certificate_sha256": "",
    "ugcap_witness_authority_public_key": "", "ugcap_witness_installation_id": "",
    "ugcap_witness_client_id": "", "ugcap_witness_client_certificate_path": "",
    "ugcap_witness_client_key_path": "", "ugcap_witness_ca_bundle_path": "",
}
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_CHECKPOINT = frozenset({"vault_id", "baseline_id", "chain_length", "chain_hash", "anchors"})
_REQUEST = frozenset({"schema", "operation", "installation_id", "client_id", "nonce",
                      "issued_at", "checkpoint", "signature"})
_RESPONSE = frozenset({"schema", "operation", "installation_id", "client_id", "nonce",
                       "received_at", "sequence", "status", "head", "signature"})
_STATUSES = frozenset({"matched", "advanced", "enrolled", "rollback", "conflict", "gap", "not-enrolled"})


class WitnessError(RuntimeError):
    """Sanitized witness protocol, identity, or storage rejection."""


def validate_settings(values):
    """Validate only public enrollment settings; incomplete disabled setup is allowed."""
    if not isinstance(values, dict) or set(values) != set(WITNESS_DEFAULTS):
        raise WitnessError("witness-settings-schema-rejected")
    result = dict(values)
    if type(result["ugcap_witness_enabled"]) is not bool:
        raise WitnessError("witness-opt-in-must-be-boolean")
    for name, value in result.items():
        if name == "ugcap_witness_enabled":
            continue
        maximum = 2048 if name.endswith("public_key") else 1024 if name.endswith("path") else 512
        if (not isinstance(value, str) or len(value) > maximum
                or any(ord(c) < 32 and (not name.endswith("public_key") or c not in "\r\n")
                       or ord(c) == 127 for c in value)):
            raise WitnessError("witness-setting-text-rejected")
    endpoint = result["ugcap_witness_endpoint"]
    if endpoint:
        from angerona.core.personal_sentinel_gateway import _parse_enrolled_endpoint
        _parse_enrolled_endpoint(endpoint)
        if not endpoint.endswith("/v1/ugcap-witness"):
            raise WitnessError("witness-endpoint-path-rejected")
    for name in ("ugcap_witness_installation_id", "ugcap_witness_client_id"):
        if result[name]:
            _hex(result[name], 32)
    if result["ugcap_witness_certificate_sha256"]:
        _hex(result["ugcap_witness_certificate_sha256"], 64)
    if result["ugcap_witness_authority_public_key"]:
        Ed25519PublicVerifier.from_pem(result["ugcap_witness_authority_public_key"].encode("ascii"),
                                     key_id=AUTHORITY_KEY_ID)
    for name in ("ugcap_witness_client_certificate_path", "ugcap_witness_client_key_path",
                 "ugcap_witness_ca_bundle_path"):
        path = result[name]
        if path and (not Path(path).is_absolute() or path.startswith(("\\\\", "//"))
                     or ".." in Path(path).parts):
            raise WitnessError("witness-certificate-path-rejected")
    if result["ugcap_witness_enabled"]:
        if not result["ugcap_witness_authority_public_key"]:
            raise WitnessError("witness-authority-key-required")
        _hex(result["ugcap_witness_installation_id"], 32)
        _hex(result["ugcap_witness_client_id"], 32)
        GatewayEnrollment(endpoint, result["ugcap_witness_certificate_sha256"], "0" * 64,
            client_certificate_path=result["ugcap_witness_client_certificate_path"],
            client_key_path=result["ugcap_witness_client_key_path"],
            ca_bundle_path=result["ugcap_witness_ca_bundle_path"])
        if not result["ugcap_witness_client_certificate_path"]:
            raise WitnessError("witness-mtls-enrollment-required")
    return result


def provision_host_identity(data_root):
    """Explicit worker action: retain private key only in the OS credential store."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from angerona.core.secure_store import read_secret_values, write_secret_map

    existing = read_secret_values((KEY_NAME,), Path(data_root), strict=True).get(KEY_NAME)
    if existing:
        signer = Ed25519PrivateSigner.from_pem(existing.encode("ascii"), key_id=CLIENT_KEY_ID)
    else:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode("ascii")
        write_secret_map({KEY_NAME: pem}, Path(data_root))
        confirmed = read_secret_values((KEY_NAME,), Path(data_root), strict=True).get(KEY_NAME)
        if confirmed != pem:
            raise WitnessError("host-key-protected-storage-verification-failed")
        signer = Ed25519PrivateSigner.from_pem(confirmed.encode("ascii"), key_id=CLIENT_KEY_ID)
    return signer.public_verifier()._public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def client_from_settings(values, data_root):
    from angerona.core.secure_store import read_secret_values

    settings = validate_settings(values)
    if not settings["ugcap_witness_enabled"]:
        raise WitnessError("witness-disabled")
    pem = read_secret_values((KEY_NAME,), Path(data_root), strict=True).get(KEY_NAME)
    if not pem:
        raise WitnessError("host-key-not-provisioned")
    return WitnessClient(endpoint=settings["ugcap_witness_endpoint"],
        certificate_sha256=settings["ugcap_witness_certificate_sha256"],
        installation_id=settings["ugcap_witness_installation_id"],
        client_id=settings["ugcap_witness_client_id"],
        signer=Ed25519PrivateSigner.from_pem(pem.encode("ascii"), key_id=CLIENT_KEY_ID),
        authority_verifier=Ed25519PublicVerifier.from_pem(
            settings["ugcap_witness_authority_public_key"].encode("ascii"), key_id=AUTHORITY_KEY_ID),
        client_certificate_path=settings["ugcap_witness_client_certificate_path"],
        client_key_path=settings["ugcap_witness_client_key_path"],
        ca_bundle_path=settings["ugcap_witness_ca_bundle_path"])


def _hex(value, length):
    if not isinstance(value, str) or not (_HEX32 if length == 32 else _HEX64).fullmatch(value):
        raise WitnessError("invalid-identity-or-hash")
    return value


def _finite(value):
    if (type(value) not in (int, float) or not 0 <= value <= 32_503_680_000
            or not math.isfinite(value)):
        raise WitnessError("invalid-time")
    return float(value)


def _document(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BYTES:
        raise WitnessError("message-size-rejected")
    try:
        return decode(raw)
    except Exception as exc:
        raise WitnessError("message-schema-rejected") from exc


def checkpoint(value):
    """Validate a detached public hash-only checkpoint; no source data fields."""
    if not isinstance(value, dict) or set(value) != _CHECKPOINT:
        raise WitnessError("checkpoint-schema-rejected")
    _hex(value["vault_id"], 32)
    _hex(value["baseline_id"], 64)
    _hex(value["chain_hash"], 64)
    count = value["chain_length"]
    anchors = value["anchors"]
    if (type(count) is not int or not 1 <= count <= MAX_CHAIN
            or not isinstance(anchors, list) or not 1 <= len(anchors) <= MAX_ANCHORS):
        raise WitnessError("checkpoint-bounds-rejected")
    prior = 0
    for row in anchors:
        if (not isinstance(row, dict) or set(row) != {"length", "hash"}
                or type(row["length"]) is not int or not prior < row["length"] <= count):
            raise WitnessError("checkpoint-anchor-rejected")
        _hex(row["hash"], 64)
        prior = row["length"]
    if prior != count or anchors[-1]["hash"] != value["chain_hash"]:
        raise WitnessError("checkpoint-terminal-rejected")
    return {**value, "anchors": [dict(row) for row in anchors]}


def _head(value):
    if not isinstance(value, dict) or set(value) != _CHECKPOINT - {"anchors"}:
        raise WitnessError("head-schema-rejected")
    return {k: v for k, v in checkpoint({**value, "anchors": [
        {"length": value["chain_length"], "hash": value["chain_hash"]}
    ]}).items() if k != "anchors"}


def _signed(document, signer):
    return {**document, "signature": signer.sign(canonical(document))}


def _authentic(document, verifier):
    signature = document.get("signature")
    return (isinstance(signature, str) and len(signature) == 86
            and verifier.verify(canonical({k: v for k, v in document.items() if k != "signature"}),
                                signature) is True)


def _path_chain(path):
    current = Path(os.path.abspath(path))
    while True:
        if os.path.lexists(current):
            info = current.lstat()
            if current.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise WitnessError("state-path-alias-rejected")
        if current.parent == current:
            break
        current = current.parent


class WitnessAuthority:
    """Single enrolled identity/vault, durable signed CAS, no reset API.

    Enrollment is supplied by the separate administrator, never in a request.
    The host request key and witness receipt key are distinct Ed25519 roles.
    """

    def __init__(self, state_path, *, installation_id, client_id, vault_id, baseline_id,
                 client_verifier, signer, clock=time.time, initialize=False):
        if type(initialize) is not bool:
            raise WitnessError("explicit-initialization-must-be-boolean")
        if (not isinstance(client_verifier, Ed25519PublicVerifier)
                or not isinstance(signer, Ed25519PrivateSigner)):
            raise WitnessError("asymmetric-key-roles-required")
        self.installation_id, self.client_id = _hex(installation_id, 32), _hex(client_id, 32)
        self.vault_id, self.baseline_id = _hex(vault_id, 32), _hex(baseline_id, 64)
        self.verifier, self.signer, self.clock = client_verifier, signer, clock
        self.path = Path(state_path).absolute()
        self.marker = self.path.with_suffix(self.path.suffix + ".enrolled")
        _path_chain(self.path)
        private_directory(self.path.parent)
        self._lease = ExclusiveFileLease(self.path.with_suffix(self.path.suffix + ".lock"))
        self._lock = threading.Lock()
        try:
            if initialize is True:
                if os.path.lexists(self.path) or os.path.lexists(self.marker):
                    raise WitnessError("explicit-enrollment-may-not-overwrite-state")
                marker = {"schema": SCHEMA + ".enrollment", **{
                    k: getattr(self, k) for k in ("installation_id", "client_id", "vault_id", "baseline_id")}}
                descriptor = create_private_file(self.marker)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(canonical(_signed(marker, self.signer)))
                    stream.flush()
                    os.fsync(stream.fileno())
                self._save({"schema": SCHEMA, "installation_id": self.installation_id,
                    "client_id": self.client_id, "vault_id": self.vault_id,
                    "baseline_id": self.baseline_id, "sequence": 0, "last_time": 0,
                    "nonces": [], "head": None})
            self._load()  # Do not open a listener with missing/ambiguous enrollment.
        except BaseException:
            self._lease.close()
            raise

    def close(self):
        with self._lock:
            self._lease.close()

    def _load(self):
        if not self._lease.held:
            raise WitnessError("authority-closed")
        _path_chain(self.path)
        _path_chain(self.marker)
        verify_private(self.path.parent, directory=True)
        if not self.marker.exists():
            raise WitnessError("explicit-witness-enrollment-required")
        verify_private(self.marker)
        with self.marker.open("rb") as stream:
            marker = _document(stream.read(MAX_BYTES + 1))
        expected_marker = {"schema": SCHEMA + ".enrollment", **{
            k: getattr(self, k) for k in ("installation_id", "client_id", "vault_id", "baseline_id")}}
        if ({k: v for k, v in marker.items() if k != "signature"} != expected_marker
                or not _authentic(marker, self.signer.public_verifier())):
            raise WitnessError("witness-enrollment-marker-rejected")
        if not self.path.exists():
            raise WitnessError("witness-state-lost")
        verify_private(self.path)
        with self.path.open("rb") as stream:
            named, held = self.path.lstat(), os.fstat(stream.fileno())
            if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
                raise WitnessError("witness-state-changed")
            data = _document(stream.read(MAX_BYTES + 1))
        expected = {"schema", "installation_id", "client_id", "vault_id", "baseline_id",
                    "sequence", "last_time", "nonces", "head", "signature"}
        if (set(data) != expected or data["schema"] != SCHEMA
                or any(data[k] != getattr(self, k) for k in
                       ("installation_id", "client_id", "vault_id", "baseline_id"))
                or not _authentic(data, self.signer.public_verifier())
                or type(data["sequence"]) is not int or not 0 <= data["sequence"] < 2**63
                or not isinstance(data["nonces"], list) or not 0 <= len(data["nonces"]) <= 256):
            raise WitnessError("witness-state-rejected")
        _finite(data["last_time"])
        nonce_hashes = []
        for value in data["nonces"]:
            if not isinstance(value, dict) or set(value) != {"hash", "expires_at"}:
                raise WitnessError("witness-state-nonce-rejected")
            nonce_hashes.append(_hex(value["hash"], 64))
            if not data["last_time"] <= _finite(value["expires_at"]) <= data["last_time"] + 35:
                raise WitnessError("witness-state-nonce-expiry-rejected")
        if len(set(nonce_hashes)) != len(nonce_hashes):
            raise WitnessError("witness-state-nonce-ambiguity")
        if data["sequence"] == 0 and (data["head"] is not None or data["nonces"] or data["last_time"] != 0):
            raise WitnessError("witness-initial-state-rejected")
        if data["sequence"] > 0 and not data["nonces"]:
            raise WitnessError("witness-state-nonce-history-missing")
        if data["head"] is not None:
            head = _head(data["head"])
            if head["vault_id"] != self.vault_id or head["baseline_id"] != self.baseline_id:
                raise WitnessError("witness-state-enrollment-mismatch")
        return {k: v for k, v in data.items() if k != "signature"}

    def _save(self, state):
        if not self._lease.held:
            raise WitnessError("authority-closed")
        payload = canonical(_signed(state, self.signer))
        if len(payload) > MAX_BYTES:
            raise WitnessError("witness-state-capacity")
        _path_chain(self.path)
        staged = self.path.with_name(".witness-" + secrets.token_hex(16))
        descriptor = create_private_file(staged)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _path_chain(self.path)
            if self.path.exists():
                verify_private(self.path)
            os.replace(staged, self.path)
            verify_private(self.path)
            if os.name != "nt":
                directory = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            staged.unlink(missing_ok=True)

    def process(self, raw):
        request = _document(raw)
        if (set(request) != _REQUEST or request["schema"] != SCHEMA
                or type(request["operation"]) is not str
                or request["operation"] not in {"checkpoint", "heartbeat"}
                or request["installation_id"] != self.installation_id
                or request["client_id"] != self.client_id
                or not isinstance(request["nonce"], str) or not _NONCE.fullmatch(request["nonce"])
                or not _authentic(request, self.verifier)):
            raise WitnessError("request-identity-or-signature-rejected")
        proposed = checkpoint(request["checkpoint"])
        if proposed["vault_id"] != self.vault_id or proposed["baseline_id"] != self.baseline_id:
            raise WitnessError("vault-enrollment-mismatch")
        issued, now = _finite(request["issued_at"]), _finite(self.clock())
        if not -5 <= now - issued <= 30:
            raise WitnessError("request-freshness-rejected")
        nonce_hash = hashlib.sha256(request["nonce"].encode("ascii")).hexdigest()
        with self._lock:
            state = self._load()
            now = _finite(self.clock())
            if not -5 <= now - issued <= 30:
                raise WitnessError("request-freshness-rejected")
            if now < state["last_time"]:
                raise WitnessError("witness-clock-rollback")
            live_nonces = [row for row in state["nonces"] if now <= row["expires_at"]]
            if any(row["hash"] == nonce_hash for row in live_nonces):
                raise WitnessError("request-nonce-replay")
            if len(live_nonces) >= 256:
                # Never evict a still-fresh signed request merely to admit a new
                # one; a bounded busy window must reduce availability, not replay protection.
                raise WitnessError("request-nonce-capacity")
            head = state["head"]
            status = "not-enrolled"
            if head is None:
                if request["operation"] == "checkpoint":
                    head, status = _head({k: v for k, v in proposed.items() if k != "anchors"}), "enrolled"
            elif proposed["chain_length"] < head["chain_length"]:
                status = "rollback"
            elif proposed["chain_length"] == head["chain_length"]:
                status = "matched" if proposed["chain_hash"] == head["chain_hash"] else "conflict"
            elif request["operation"] == "heartbeat":
                status = "gap"
            elif not any(row == {"length": head["chain_length"], "hash": head["chain_hash"]}
                         for row in proposed["anchors"]):
                status = "conflict"
            else:
                head, status = _head({k: v for k, v in proposed.items() if k != "anchors"}), "advanced"
            state.update(sequence=state["sequence"] + 1, last_time=now, head=head,
                         nonces=live_nonces + [{"hash": nonce_hash, "expires_at": issued + 30}])
            if state["sequence"] >= 2**63:
                raise WitnessError("witness-sequence-exhausted")
            self._save(state)
            response = {"schema": SCHEMA, "operation": request["operation"],
                        "installation_id": self.installation_id, "client_id": self.client_id,
                        "nonce": request["nonce"], "received_at": now,
                        "sequence": state["sequence"], "status": status, "head": head}
            return canonical(_signed(response, self.signer))


@dataclass(frozen=True)
class WitnessAssessment:
    status: str
    assurance: str
    sequence: int = 0
    received_at: float | None = None
    gate_allowed: bool = False

    def snapshot(self):
        return {"status": self.status, "assurance": self.assurance, "sequence": self.sequence,
                "received_at": self.received_at, "gate_allowed": self.gate_allowed,
                "whole_witness_snapshot_rollback_proof": False, "response_authorized": False}


class PinnedWitnessTransport:
    """Private direct HTTPS; verify peer AND pin before sending a signed request."""

    def __init__(self, enrollment):
        self.enrollment = enrollment

    def send(self, request):
        from urllib.parse import urlsplit

        if request.endpoint_url != self.enrollment.endpoint_url or request.require_tls_validation is not True:
            raise WitnessError("transport-enrollment-mismatch")
        if any(os.environ.get(name) for name in ("SSL_CERT_FILE", "SSL_CERT_DIR")):
            raise WitnessError("ambient-tls-authority-rejected")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname, context.verify_mode = True, ssl.CERT_REQUIRED
        if request.ca_bundle_path:
            _path_chain(Path(request.ca_bundle_path))
            context.load_verify_locations(cafile=request.ca_bundle_path)
        else:
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        if request.client_certificate_path:
            _path_chain(Path(request.client_certificate_path))
            _path_chain(Path(request.client_key_path))
            verify_private(Path(request.client_key_path))
            context.load_cert_chain(request.client_certificate_path, request.client_key_path)
        parsed = urlsplit(request.endpoint_url)
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
            timeout=request.connect_timeout, context=context)
        deadline = time.monotonic() + request.connect_timeout + request.read_timeout + 1.0
        try:
            connection.connect()
            if connection.sock is None:
                raise WitnessError("tls-socket-missing")
            certificate = connection.sock.getpeercert(binary_form=True)
            peer_text = connection.sock.getpeername()[0]
            peer = ipaddress.ip_address(peer_text)
            host = self.enrollment._canonical_host
            matches = peer.is_loopback if host == "localhost" else peer == ipaddress.ip_address(host)
            if (not matches or not certificate or not hmac.compare_digest(
                    hashlib.sha256(certificate).hexdigest(), self.enrollment.certificate_sha256)):
                raise WitnessError("tls-peer-or-pin-rejected")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WitnessError("request-deadline")
            connection.sock.settimeout(min(request.read_timeout, remaining))
            connection.request("POST", parsed.path, body=request.body, headers=dict(request.headers))
            # A per-recv timeout alone permits an indefinite byte-drip. Parse
            # this one small Content-Length response against a total deadline.
            wire = bytearray()
            while b"\r\n\r\n" not in wire:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WitnessError("response-deadline")
                connection.sock.settimeout(min(request.read_timeout, remaining))
                chunk = connection.sock.recv(min(4096, 8193 - len(wire)))
                if not chunk:
                    raise WitnessError("response-truncated")
                wire.extend(chunk)
                split_at = wire.find(b"\r\n\r\n")
                if (split_at < 0 and len(wire) > 8192) or split_at > 8188:
                    raise WitnessError("response-headers-rejected")
            header, body_start = bytes(wire).split(b"\r\n\r\n", 1)
            lines = header.decode("ascii").split("\r\n")
            status_parts = lines[0].split(" ", 2)
            if (len(status_parts) < 2 or status_parts[0] not in {"HTTP/1.0", "HTTP/1.1"}
                    or len(status_parts[1]) != 3 or not status_parts[1].isdigit()):
                raise WitnessError("response-http-status-rejected")
            headers = {}
            if len(lines) > 65:
                raise WitnessError("response-headers-rejected")
            for line in lines[1:]:
                if ":" not in line or line[:1].isspace():
                    raise WitnessError("response-headers-rejected")
                name, value = line.split(":", 1)
                value = value.strip()
                lowered = name.casefold()
                if (not re.fullmatch(r"[A-Za-z0-9-]+", name) or lowered in headers
                        or len(name) > 1024 or len(value) > 1024
                        or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                    raise WitnessError("response-headers-rejected")
                headers[lowered] = value
            size_text = headers.get("content-length", "")
            if (headers.get("transfer-encoding") or headers.get("content-encoding")
                    or not size_text.isascii() or not size_text.isdigit() or len(size_text) > 6):
                raise WitnessError("response-framing-rejected")
            size = int(size_text)
            if not 1 <= size <= MAX_BYTES or len(body_start) > size:
                raise WitnessError("response-size-rejected")
            body = bytearray(body_start)
            while len(body) < size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WitnessError("response-deadline")
                connection.sock.settimeout(min(request.read_timeout, remaining))
                chunk = connection.sock.recv(size - len(body))
                if not chunk:
                    raise WitnessError("response-truncated")
                body.extend(chunk)
            return GatewayTransportResponse(int(status_parts[1]), headers, bytes(body), certificate, peer_text, True)
        finally:
            connection.close()


class WitnessClient:
    """Only typed checkpoints/heartbeats to one PKI+pin+Ed25519 enrollment."""

    def __init__(self, *, endpoint, certificate_sha256, installation_id, client_id,
                 signer, authority_verifier, client_certificate_path="", client_key_path="",
                 ca_bundle_path="", transport=None, clock=time.time, nonce_factory=None):
        if (not isinstance(signer, Ed25519PrivateSigner)
                or not isinstance(authority_verifier, Ed25519PublicVerifier)):
            raise WitnessError("asymmetric-key-roles-required")
        if not isinstance(endpoint, str) or not endpoint.endswith("/v1/ugcap-witness"):
            raise WitnessError("witness-endpoint-path-rejected")
        self.enrollment = GatewayEnrollment(endpoint, certificate_sha256, "0" * 64,
            client_certificate_path=client_certificate_path, client_key_path=client_key_path,
            ca_bundle_path=ca_bundle_path, max_response_bytes=MAX_BYTES,
            connect_timeout=2.0, read_timeout=3.0)
        self.installation_id, self.client_id = _hex(installation_id, 32), _hex(client_id, 32)
        self.signer, self.verifier = signer, authority_verifier
        self.transport = transport or PinnedWitnessTransport(self.enrollment)
        self.clock, self.nonce_factory = clock, nonce_factory or (lambda: secrets.token_urlsafe(32))
        self._sequence, self._last_time = 0, 0.0
        self._lock = threading.Lock()

    def exchange(self, observation, *, heartbeat=False):
        observation = checkpoint(observation)
        operation = "heartbeat" if heartbeat else "checkpoint"
        with self._lock:
            now, nonce = _finite(self.clock()), self.nonce_factory()
            if now < self._last_time:
                raise WitnessError("host-clock-rollback")
            if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
                raise WitnessError("host-nonce-invalid")
            request = {"schema": SCHEMA, "operation": operation, "installation_id": self.installation_id,
                       "client_id": self.client_id, "nonce": nonce, "issued_at": now,
                       "checkpoint": observation}
            body = canonical(_signed(request, self.signer))
            if len(body) > MAX_BYTES:
                raise WitnessError("request-size-rejected")
            request_args = GatewayTransportRequest(self.enrollment.endpoint_url, body,
                {"Accept": "application/json", "Content-Type": "application/json", "Cache-Control": "no-store"},
                self.enrollment.connect_timeout, self.enrollment.read_timeout, MAX_BYTES,
                self.enrollment.client_certificate_path, self.enrollment.client_key_path,
                self.enrollment.ca_bundle_path, True)
            try:
                response = self.transport.send(request_args)
            except Exception as exc:
                raise WitnessError("witness-unreachable") from exc
            if not isinstance(response, GatewayTransportResponse):
                raise WitnessError("transport-contract-rejected")
            try:
                peer = ipaddress.ip_address(response.peer_ip)
                host = self.enrollment._canonical_host
                peer_matches = peer.is_loopback if host == "localhost" else peer == ipaddress.ip_address(host)
            except (ValueError, TypeError):
                peer_matches = False
            if (response.tls_verified is not True or not peer_matches
                    or not isinstance(response.peer_certificate_der, bytes)
                    or not response.peer_certificate_der
                    or not hmac.compare_digest(hashlib.sha256(response.peer_certificate_der).hexdigest(),
                                               self.enrollment.certificate_sha256)):
                raise WitnessError("tls-peer-or-pin-rejected")
            if type(response.status_code) is not int or response.status_code != 200:
                raise WitnessError("http-status-rejected")
            content_types = [v for k, v in response.headers.items()
                             if isinstance(k, str) and k.casefold() == "content-type"] if isinstance(response.headers, Mapping) and len(response.headers) <= 64 else []
            if (len(content_types) != 1 or not isinstance(content_types[0], str)
                    or content_types[0].casefold().split(";", 1)[0].strip() != "application/json"):
                raise WitnessError("response-content-type-rejected")
            receipt = _document(response.body)
            if (set(receipt) != _RESPONSE or receipt["schema"] != SCHEMA
                    or receipt["operation"] != operation
                    or receipt["installation_id"] != self.installation_id
                    or receipt["client_id"] != self.client_id or receipt["nonce"] != nonce
                    or type(receipt["status"]) is not str or receipt["status"] not in _STATUSES
                    or not _authentic(receipt, self.verifier)):
                raise WitnessError("receipt-signature-identity-or-nonce-rejected")
            received = _finite(receipt["received_at"])
            sequence = receipt["sequence"]
            if (not -5 <= now - received <= 60 or received < self._last_time
                    or type(sequence) is not int or not self._sequence < sequence < 2**63):
                raise WitnessError("receipt-stale-or-regressed")
            head = _head(receipt["head"]) if receipt["head"] is not None else None
            accepted = receipt["status"] in {"matched", "advanced", "enrolled"}
            if accepted and head != {k: v for k, v in observation.items() if k != "anchors"}:
                raise WitnessError("receipt-checkpoint-mismatch")
            self._sequence, self._last_time = sequence, received
            return WitnessAssessment(receipt["status"],
                "fresh-separate-witness-checkpoint" if accepted else "witness-conflict-or-gap",
                sequence, received, accepted)


__all__ = ["WitnessAuthority", "WitnessClient", "WitnessAssessment", "WitnessError", "checkpoint"]
