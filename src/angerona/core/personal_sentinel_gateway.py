"""Fail-closed client for a vendor-neutral Personal Sentinel Gateway.

This is an attestation client, not a router-management client.  It performs no
discovery, stores no router credentials, and exposes no route/firewall mutation
API.  An operator explicitly enrolls one private or loopback HTTPS endpoint,
its expected policy digest, and a TLS certificate SHA-256 pin.  Normal platform
TLS validation remains mandatory; pinning is an additional identity check, not
a replacement for certificate-chain and hostname verification.

The transport boundary is injectable so tests and offline self-checks never
touch the network.  The standard transport does not use proxy settings and does
not follow redirects.

Monitor enrollment is intentionally file-based and explicit.  Create
``<AngeronaData>/config/personal_sentinel_gateway.json`` with mode 0600 on
POSIX systems (the protected Angerona data ACL is used on Windows)::

    {
      "schema_version": 1,
      "interface_id": "Wi-Fi",
      "endpoint_url": "https://192.168.1.1:9443/v1/attest",
      "certificate_sha256": "<64 lowercase hex characters>",
      "policy_digest": "<64 lowercase hex characters>"
    }

``interface_id`` must exactly match the local interface and the endpoint IP
must be that interface's observed default gateway.  Optional keys are listed in
:func:`load_gateway_monitor_binding`.  Missing or rejected configuration is
equivalent to disabled attestation and leaves the path untrusted.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
import secrets
import socket
import ssl
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol
from urllib.parse import SplitResult, urlsplit


SCHEMA_VERSION = 1
MAX_RESPONSE_BYTES = 64 * 1024
MAX_HEADERS = 64
MAX_HEADER_CHARS = 1024
MAX_ENDPOINT_CHARS = 512
MAX_NONCE_CHARS = 128
MAX_CONFIG_BYTES = 16 * 1024
GATEWAY_CONFIG_FILENAME = "personal_sentinel_gateway.json"
_ATTESTATION_KEYS = frozenset({
    "schema_version",
    "nonce",
    "attested_at",
    "expires_at",
    "policy_digest",
    "path_status",
})
_WITNESS_KEYS = frozenset({
    "schema_version",
    "nonce",
    "sequence",
    "previous_receipt_hash",
    "continuity_digest",
    "event_count",
    "received_at",
    "receipt_hash",
    "status",
})


class GatewayConfigurationError(ValueError):
    """The explicit gateway enrollment violates a security invariant."""


class GatewayTransportError(RuntimeError):
    """A bounded HTTPS exchange could not be completed safely."""


def _sha256_hex(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise GatewayConfigurationError(f"{field} must be text")
    normalized = value.strip().casefold().replace(":", "")
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise GatewayConfigurationError(f"{field} must be a SHA-256 hex digest")
    return normalized


def _is_enrollable_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Allow RFC1918, IPv6 ULA, and loopback; reject metadata/link-local space."""

    if address.is_loopback:
        return True
    if address.is_link_local or address.is_multicast or address.is_unspecified:
        return False
    if address.version == 4:
        private_ranges = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        return any(address in network for network in private_ranges)
    return address in ipaddress.ip_network("fc00::/7")


def _parse_enrolled_endpoint(endpoint_url: str) -> tuple[SplitResult, str]:
    if not isinstance(endpoint_url, str) or not endpoint_url or len(endpoint_url) > MAX_ENDPOINT_CHARS:
        raise GatewayConfigurationError("gateway endpoint is missing or too long")
    if any(ord(char) < 0x20 for char in endpoint_url):
        raise GatewayConfigurationError("gateway endpoint contains control characters")
    try:
        parsed = urlsplit(endpoint_url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise GatewayConfigurationError("gateway endpoint URL is invalid") from exc
    if parsed.scheme.casefold() != "https":
        raise GatewayConfigurationError("gateway endpoint must use HTTPS")
    if not parsed.netloc or not parsed.hostname:
        raise GatewayConfigurationError("gateway endpoint must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise GatewayConfigurationError("credentials are forbidden in gateway URLs")
    if parsed.query or parsed.fragment:
        raise GatewayConfigurationError("gateway endpoint queries and fragments are forbidden")
    if "\\" in parsed.path or not parsed.path.startswith("/"):
        raise GatewayConfigurationError("gateway endpoint path is invalid")
    if port is not None and not 1 <= port <= 65535:
        raise GatewayConfigurationError("gateway endpoint port is invalid")

    host = parsed.hostname.casefold().rstrip(".")
    if host == "localhost":
        return parsed, host
    # Requiring an IP literal avoids DNS rebinding and prevents the client from
    # becoming a generic SSRF primitive.  Private DNS names can be represented
    # by their explicitly enrolled private address and a certificate with an IP
    # SAN; no discovery or dynamic host resolution is performed.
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError as exc:
        raise GatewayConfigurationError(
            "gateway host must be localhost or an explicit private IP literal"
        ) from exc
    if not _is_enrollable_address(address):
        raise GatewayConfigurationError(
            "gateway host must be private or loopback; public and link-local hosts are forbidden"
        )
    return parsed, str(address)


@dataclass(frozen=True)
class GatewayEnrollment:
    endpoint_url: str
    certificate_sha256: str
    policy_digest: str
    witness_endpoint_url: str = ""
    client_certificate_path: str = ""
    client_key_path: str = ""
    ca_bundle_path: str = ""
    connect_timeout: float = 2.0
    read_timeout: float = 3.0
    max_response_bytes: int = 16 * 1024
    max_attestation_age: float = 60.0
    clock_skew_tolerance: float = 5.0

    def __post_init__(self) -> None:
        parsed, canonical_host = _parse_enrolled_endpoint(self.endpoint_url)
        witness_parsed = None
        witness_endpoint = str(self.witness_endpoint_url or "")
        if witness_endpoint:
            witness_parsed, witness_host = _parse_enrolled_endpoint(witness_endpoint)
            if (
                witness_host != canonical_host
                or (witness_parsed.port or 443) != (parsed.port or 443)
            ):
                raise GatewayConfigurationError(
                    "witness endpoint must use the explicitly pinned gateway authority"
                )
        certificate_pin = _sha256_hex(self.certificate_sha256, "certificate pin")
        policy_digest = _sha256_hex(self.policy_digest, "policy digest")
        cert_path = str(self.client_certificate_path or "")
        key_path = str(self.client_key_path or "")
        ca_path = str(self.ca_bundle_path or "")
        if bool(cert_path) != bool(key_path):
            raise GatewayConfigurationError(
                "client certificate and private-key paths must be provided together"
            )
        for label, value in (
            ("client certificate path", cert_path),
            ("client key path", key_path),
            ("CA bundle path", ca_path),
        ):
            if len(value) > 1024 or "\x00" in value:
                raise GatewayConfigurationError(f"{label} is invalid")
            if value and not Path(value).is_absolute():
                raise GatewayConfigurationError(f"{label} must be an absolute path")
        for label, value in (
            ("connect timeout", self.connect_timeout),
            ("read timeout", self.read_timeout),
        ):
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(float(value))
                or not 0.1 <= float(value) <= 10.0
            ):
                raise GatewayConfigurationError(f"{label} must be between 0.1 and 10 seconds")
        if (
            type(self.max_response_bytes) is not int
            or not 512 <= self.max_response_bytes <= MAX_RESPONSE_BYTES
        ):
            raise GatewayConfigurationError("response byte cap is invalid")
        if (
            not isinstance(self.max_attestation_age, (int, float))
            or isinstance(self.max_attestation_age, bool)
            or not 5.0 <= float(self.max_attestation_age) <= 300.0
        ):
            raise GatewayConfigurationError("attestation freshness bound is invalid")
        if (
            not isinstance(self.clock_skew_tolerance, (int, float))
            or isinstance(self.clock_skew_tolerance, bool)
            or not 0.0 <= float(self.clock_skew_tolerance) <= 30.0
        ):
            raise GatewayConfigurationError("clock-skew tolerance is invalid")
        object.__setattr__(self, "certificate_sha256", certificate_pin)
        object.__setattr__(self, "policy_digest", policy_digest)
        object.__setattr__(self, "witness_endpoint_url", witness_endpoint)
        object.__setattr__(self, "client_certificate_path", cert_path)
        object.__setattr__(self, "client_key_path", key_path)
        object.__setattr__(self, "ca_bundle_path", ca_path)
        object.__setattr__(self, "connect_timeout", float(self.connect_timeout))
        object.__setattr__(self, "read_timeout", float(self.read_timeout))
        object.__setattr__(self, "max_attestation_age", float(self.max_attestation_age))
        object.__setattr__(self, "clock_skew_tolerance", float(self.clock_skew_tolerance))
        # Cache only non-secret URL parsing facts.  Enrollment never accepts a
        # password, router admin credential, bearer token, or discovery hint.
        object.__setattr__(self, "_parsed", parsed)
        object.__setattr__(self, "_canonical_host", canonical_host)
        object.__setattr__(self, "_witness_parsed", witness_parsed)


@dataclass(frozen=True)
class GatewayMonitorBinding:
    """Explicit local-interface binding loaded from the strict config file."""

    interface_id: str
    enrollment: GatewayEnrollment

    def __post_init__(self) -> None:
        if (
            not isinstance(self.interface_id, str)
            or not self.interface_id
            or len(self.interface_id) > 512
            or "\x00" in self.interface_id
        ):
            raise GatewayConfigurationError("gateway interface binding is invalid")
        if not isinstance(self.enrollment, GatewayEnrollment):
            raise GatewayConfigurationError("gateway enrollment is invalid")


@dataclass(frozen=True)
class GatewayTransportRequest:
    endpoint_url: str
    body: bytes
    headers: Mapping[str, str]
    connect_timeout: float
    read_timeout: float
    max_response_bytes: int
    client_certificate_path: str = ""
    client_key_path: str = ""
    ca_bundle_path: str = ""
    require_tls_validation: bool = True


@dataclass(frozen=True)
class GatewayTransportResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    peer_certificate_der: bytes
    peer_ip: str
    tls_verified: bool


class GatewayTransport(Protocol):
    def send(self, request: GatewayTransportRequest) -> GatewayTransportResponse:
        """Perform one HTTPS POST without following redirects."""


class StandardHttpsGatewayTransport:
    """Direct, proxy-free HTTPS transport using the platform trust store."""

    def send(self, request: GatewayTransportRequest) -> GatewayTransportResponse:
        if request.require_tls_validation is not True:
            raise GatewayTransportError("TLS validation cannot be disabled")
        parsed, canonical_host = _parse_enrolled_endpoint(request.endpoint_url)
        if canonical_host == "localhost":
            try:
                candidates = socket.getaddrinfo(
                    parsed.hostname,
                    parsed.port or 443,
                    type=socket.SOCK_STREAM,
                )
                resolved = {
                    ipaddress.ip_address(row[4][0].split("%", 1)[0])
                    for row in candidates
                }
            except (OSError, ValueError) as exc:
                raise GatewayTransportError("loopback endpoint resolution failed") from exc
            if not resolved or any(not address.is_loopback for address in resolved):
                raise GatewayTransportError("loopback endpoint resolved outside loopback")
        context = ssl.create_default_context(
            cafile=request.ca_bundle_path or None,
        )
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if request.client_certificate_path:
            context.load_cert_chain(
                certfile=request.client_certificate_path,
                keyfile=request.client_key_path,
            )
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=request.connect_timeout,
            context=context,
        )
        path = parsed.path or "/"
        try:
            connection.connect()
            if connection.sock is None:
                raise GatewayTransportError("TLS socket was not established")
            certificate = connection.sock.getpeercert(binary_form=True)
            peer = connection.sock.getpeername()[0]
            try:
                peer_address = ipaddress.ip_address(str(peer).split("%", 1)[0])
            except ValueError as exc:
                raise GatewayTransportError("gateway peer address is invalid") from exc
            if not _is_enrollable_address(peer_address):
                raise GatewayTransportError("gateway peer is outside private or loopback space")
            if canonical_host == "localhost":
                if not peer_address.is_loopback:
                    raise GatewayTransportError("gateway peer escaped loopback")
            elif peer_address != ipaddress.ip_address(canonical_host):
                raise GatewayTransportError("gateway peer does not match enrollment")
            connection.sock.settimeout(request.read_timeout)
            connection.request("POST", path, body=request.body, headers=dict(request.headers))
            response = connection.getresponse()
            body = response.read(request.max_response_bytes + 1)
            if len(body) > request.max_response_bytes:
                raise GatewayTransportError("gateway response exceeded its byte cap")
            headers: dict[str, str] = {}
            for name, value in response.getheaders()[:MAX_HEADERS]:
                key = str(name).strip().casefold()[:MAX_HEADER_CHARS]
                if key and key not in headers:
                    headers[key] = str(value)[:MAX_HEADER_CHARS]
            return GatewayTransportResponse(
                status_code=int(response.status),
                headers=headers,
                body=body,
                peer_certificate_der=bytes(certificate or b""),
                peer_ip=str(peer),
                tls_verified=True,
            )
        except GatewayTransportError:
            raise
        except Exception as exc:
            # Do not place exception text into EventBus-facing results; TLS
            # libraries can include endpoint names and local certificate paths.
            raise GatewayTransportError("bounded HTTPS attestation failed") from exc
        finally:
            connection.close()


@dataclass(frozen=True)
class GatewayAttestation:
    success: bool
    path_label: str
    reason_code: str
    endpoint_token: str
    certificate_token: str = ""
    attested_at: float = 0.0
    expires_at: float = 0.0
    endpoint_resources_trusted: bool = False
    response_authorized: bool = False

    def event_details(self) -> dict:
        """Privacy-safe status suitable for a routine EventBus message."""

        return {
            "schema": "angerona.personal-sentinel-attestation.v1",
            "attestation_success": self.success,
            "path_label": self.path_label,
            "reason_code": self.reason_code,
            "endpoint_token": self.endpoint_token,
            "certificate_token": self.certificate_token,
            "attested_at": self.attested_at,
            "expires_at": self.expires_at,
            "endpoint_resources_trusted": False,
            "local_network_identifiers_omitted": True,
            "response_authorized": False,
            "response_authority": "observe-only",
        }


@dataclass(frozen=True)
class GatewayWitnessReceipt:
    """Compact receipt for a log-continuity digest; never contains raw logs."""

    success: bool
    reason_code: str
    endpoint_token: str
    sequence: int
    receipt_hash: str = ""
    received_at: float = 0.0
    response_authorized: bool = False

    def event_details(self) -> dict:
        return {
            "schema": "angerona.personal-sentinel-witness.v1",
            "witness_success": self.success,
            "reason_code": self.reason_code,
            "endpoint_token": self.endpoint_token,
            "sequence": self.sequence,
            "receipt_hash": self.receipt_hash,
            "received_at": self.received_at,
            "raw_logs_included": False,
            "endpoint_resources_trusted": False,
            "response_authorized": False,
            "response_authority": "observe-only",
        }


class _DuplicateJsonKey(ValueError):
    pass


def _strict_json_object(body: bytes, expected_keys: frozenset[str]) -> dict:
    try:
        text = body.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("response is not UTF-8 JSON") from exc

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if not isinstance(key, str) or key in result:
                raise _DuplicateJsonKey("duplicate or non-text JSON key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("non-finite JSON number")

    try:
        document = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, _DuplicateJsonKey, ValueError) as exc:
        raise ValueError("response JSON is invalid or ambiguous") from exc
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise ValueError("response schema is invalid")
    return document


def _strict_json_document(body: bytes) -> dict:
    return _strict_json_object(body, _ATTESTATION_KEYS)


def witness_receipt_hash(
    nonce: str,
    sequence: int,
    previous_receipt_hash: str,
    continuity_digest: str,
    event_count: int,
) -> str:
    """Canonical v1 receipt hash for a compact continuity witness."""

    document = {
        "continuity_digest": continuity_digest,
        "event_count": event_count,
        "nonce": nonce,
        "previous_receipt_hash": previous_receipt_hash,
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def default_gateway_config_path() -> Path:
    """Return the one documented enrollment path used by the monitor.

    The file is never created or populated automatically.  An operator must
    explicitly create ``<AngeronaData>/config/personal_sentinel_gateway.json``.
    File absence disables attestation and leaves every path untrusted.
    """

    from angerona.core.data_paths import data_dir

    return data_dir() / "config" / GATEWAY_CONFIG_FILENAME


def load_gateway_monitor_binding(path: str | Path | None = None) -> GatewayMonitorBinding | None:
    """Load one strict, credential-free gateway-to-interface enrollment.

    Required JSON keys are ``schema_version`` (1), ``interface_id``,
    ``endpoint_url``, ``certificate_sha256``, and ``policy_digest``.  Optional
    keys map exactly to :class:`GatewayEnrollment`, including mTLS *file paths*
    and ``witness_endpoint_url``.  Passwords, bearer tokens, router usernames,
    unknown fields, duplicate keys, symlinks/reparse points, oversized files,
    and loose POSIX permissions are rejected.  The file contains no router
    credential and is never discovered outside the fixed path.
    """

    candidate = Path(path) if path is not None else default_gateway_config_path()
    try:
        before = candidate.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise GatewayConfigurationError("gateway enrollment file is unavailable") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(before, "st_file_attributes", 0)
    if (
        not stat.S_ISREG(before.st_mode)
        or candidate.is_symlink()
        or bool(attributes & reparse_flag)
        or before.st_size > MAX_CONFIG_BYTES
    ):
        raise GatewayConfigurationError("gateway enrollment file is unsafe")
    if os.name == "posix":
        if before.st_mode & 0o077:
            raise GatewayConfigurationError("gateway enrollment file permissions are too broad")
        if hasattr(os, "getuid") and before.st_uid != os.getuid():
            raise GatewayConfigurationError("gateway enrollment file owner is invalid")
    try:
        with candidate.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise GatewayConfigurationError("gateway enrollment file changed while opening")
            raw = stream.read(MAX_CONFIG_BYTES + 1)
    except GatewayConfigurationError:
        raise
    except OSError as exc:
        raise GatewayConfigurationError("gateway enrollment file could not be read") from exc
    if not raw or len(raw) > MAX_CONFIG_BYTES:
        raise GatewayConfigurationError("gateway enrollment file is empty or oversized")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if not isinstance(key, str) or key in result:
                raise GatewayConfigurationError("gateway enrollment JSON is ambiguous")
            result[key] = value
        return result

    def reject_constant(_value):
        raise GatewayConfigurationError("gateway enrollment JSON number is invalid")

    try:
        document = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except GatewayConfigurationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise GatewayConfigurationError("gateway enrollment JSON is invalid") from exc
    required = {
        "schema_version",
        "interface_id",
        "endpoint_url",
        "certificate_sha256",
        "policy_digest",
    }
    optional = {
        "witness_endpoint_url",
        "client_certificate_path",
        "client_key_path",
        "ca_bundle_path",
        "connect_timeout",
        "read_timeout",
        "max_response_bytes",
        "max_attestation_age",
        "clock_skew_tolerance",
    }
    if (
        not isinstance(document, dict)
        or not required.issubset(document)
        or not set(document).issubset(required | optional)
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != SCHEMA_VERSION
    ):
        raise GatewayConfigurationError("gateway enrollment schema is invalid")
    interface_id = document.get("interface_id")
    text_fields = {
        "endpoint_url",
        "certificate_sha256",
        "policy_digest",
        "witness_endpoint_url",
        "client_certificate_path",
        "client_key_path",
        "ca_bundle_path",
    }
    if any(key in document and not isinstance(document[key], str) for key in text_fields):
        raise GatewayConfigurationError("gateway enrollment text field is invalid")
    enrollment_values = {
        key: value
        for key, value in document.items()
        if key not in {"schema_version", "interface_id"}
    }
    return GatewayMonitorBinding(
        interface_id,
        GatewayEnrollment(**enrollment_values),
    )


class PersonalSentinelGatewayClient:
    """Perform one explicit, nonce-bound, certificate-pinned attestation."""

    def __init__(
        self,
        enrollment: GatewayEnrollment,
        privacy_key: bytes,
        *,
        transport: GatewayTransport | None = None,
        clock=time.time,
        nonce_factory=None,
    ) -> None:
        if not isinstance(enrollment, GatewayEnrollment):
            raise GatewayConfigurationError("an explicit gateway enrollment is required")
        if not isinstance(privacy_key, bytes) or len(privacy_key) < 32:
            raise GatewayConfigurationError("privacy key must contain at least 32 bytes")
        self.enrollment = enrollment
        self._privacy_key = bytes(privacy_key)
        self._transport = transport or StandardHttpsGatewayTransport()
        self._clock = clock
        self._nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(32))
        self._endpoint_token = self._token(b"gateway-endpoint", enrollment.endpoint_url)
        self._witness_endpoint_token = (
            self._token(b"gateway-witness-endpoint", enrollment.witness_endpoint_url)
            if enrollment.witness_endpoint_url
            else ""
        )

    def _token(self, label: bytes, value: str) -> str:
        return "tok_" + hmac.new(
            self._privacy_key,
            label + b"\0" + value.casefold().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:24]

    def _failure(self, reason: str, certificate_token: str = "") -> GatewayAttestation:
        return GatewayAttestation(
            False,
            "untrusted",
            reason,
            self._endpoint_token,
            certificate_token=certificate_token,
        )

    def untrusted_status(self, reason_code: str) -> GatewayAttestation:
        """Build a privacy-safe fail-closed status without making a request."""

        allowed = {
            "configuration-absent",
            "configuration-invalid",
            "interface-binding-missing",
            "path-binding-rejected",
            "route-context-changed",
        }
        reason = reason_code if reason_code in allowed else "configuration-invalid"
        return self._failure(reason)

    def _validate_peer(self, peer_ip: str) -> bool:
        try:
            address = ipaddress.ip_address(str(peer_ip).split("%", 1)[0])
        except ValueError:
            return False
        if not _is_enrollable_address(address):
            return False
        host = self.enrollment._canonical_host
        if host == "localhost":
            return address.is_loopback
        try:
            return address == ipaddress.ip_address(host)
        except ValueError:
            return False

    def _witness_failure(self, reason: str, sequence: int) -> GatewayWitnessReceipt:
        return GatewayWitnessReceipt(
            False,
            reason,
            self._witness_endpoint_token,
            sequence if type(sequence) is int and sequence > 0 else 0,
        )

    def attest(self) -> GatewayAttestation:
        """Return ``gateway-attested`` only after all checks pass.

        Failures are represented by a privacy-safe status rather than leaking
        URLs, gateway addresses, TLS details, or local key paths.  No failure
        path changes host networking or response authority.
        """

        try:
            now = float(self._clock())
        except Exception:
            return self._failure("clock-unavailable")
        if not math.isfinite(now):
            return self._failure("clock-unavailable")
        try:
            nonce = self._nonce_factory()
        except Exception:
            return self._failure("nonce-unavailable")
        if (
            not isinstance(nonce, str)
            or not 32 <= len(nonce) <= MAX_NONCE_CHARS
            or any(ord(char) < 0x21 or ord(char) > 0x7e for char in nonce)
        ):
            return self._failure("nonce-invalid")

        request_document = {
            "schema_version": SCHEMA_VERSION,
            "nonce": nonce,
            "issued_at": now,
            "policy_digest": self.enrollment.policy_digest,
            "client": "angerona",
        }
        body = json.dumps(
            request_document, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        request = GatewayTransportRequest(
            endpoint_url=self.enrollment.endpoint_url,
            body=body,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
                "User-Agent": "Angerona-Personal-Sentinel/1",
            },
            connect_timeout=self.enrollment.connect_timeout,
            read_timeout=self.enrollment.read_timeout,
            max_response_bytes=self.enrollment.max_response_bytes,
            client_certificate_path=self.enrollment.client_certificate_path,
            client_key_path=self.enrollment.client_key_path,
            ca_bundle_path=self.enrollment.ca_bundle_path,
            require_tls_validation=True,
        )
        try:
            response = self._transport.send(request)
        except Exception:
            return self._failure("transport-failed")
        if not isinstance(response, GatewayTransportResponse):
            return self._failure("transport-contract-invalid")
        if response.tls_verified is not True:
            return self._failure("tls-unverified")
        if not self._validate_peer(response.peer_ip):
            return self._failure("peer-address-rejected")
        if (
            not isinstance(response.peer_certificate_der, bytes)
            or not response.peer_certificate_der
            or len(response.peer_certificate_der) > MAX_RESPONSE_BYTES
        ):
            return self._failure("peer-certificate-invalid")
        actual_pin = hashlib.sha256(response.peer_certificate_der).hexdigest()
        certificate_token = self._token(b"gateway-certificate", actual_pin)
        if not hmac.compare_digest(actual_pin, self.enrollment.certificate_sha256):
            return self._failure("certificate-pin-mismatch", certificate_token)
        if (
            type(response.status_code) is not int
            or not 100 <= response.status_code <= 599
        ):
            return self._failure("http-status-invalid", certificate_token)
        if 300 <= response.status_code <= 399:
            return self._failure("redirect-rejected", certificate_token)
        if response.status_code != 200:
            return self._failure("http-status-rejected", certificate_token)
        if not isinstance(response.headers, Mapping) or len(response.headers) > MAX_HEADERS:
            return self._failure("headers-invalid", certificate_token)
        headers: dict[str, str] = {}
        for name, value in response.headers.items():
            if (
                not isinstance(name, str)
                or not isinstance(value, str)
                or len(name) > MAX_HEADER_CHARS
                or len(value) > MAX_HEADER_CHARS
            ):
                return self._failure("headers-invalid", certificate_token)
            lowered = name.strip().casefold()
            if lowered in headers:
                return self._failure("headers-ambiguous", certificate_token)
            headers[lowered] = value.strip()
        content_type = headers.get("content-type", "").casefold().split(";", 1)[0].strip()
        if content_type != "application/json":
            return self._failure("content-type-rejected", certificate_token)
        if (
            not isinstance(response.body, bytes)
            or not response.body
            or len(response.body) > self.enrollment.max_response_bytes
        ):
            return self._failure("response-size-rejected", certificate_token)
        try:
            document = _strict_json_document(response.body)
        except ValueError:
            return self._failure("attestation-schema-rejected", certificate_token)

        if type(document.get("schema_version")) is not int or document["schema_version"] != SCHEMA_VERSION:
            return self._failure("schema-version-mismatch", certificate_token)
        echoed_nonce = document.get("nonce")
        if not isinstance(echoed_nonce, str) or not hmac.compare_digest(echoed_nonce, nonce):
            return self._failure("nonce-mismatch", certificate_token)
        digest = document.get("policy_digest")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or not hmac.compare_digest(digest.casefold(), self.enrollment.policy_digest)
        ):
            return self._failure("policy-digest-mismatch", certificate_token)
        if document.get("path_status") != "gateway-attested":
            return self._failure("path-status-rejected", certificate_token)
        attested_at = document.get("attested_at")
        expires_at = document.get("expires_at")
        if any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            for value in (attested_at, expires_at)
        ):
            return self._failure("freshness-invalid", certificate_token)
        attested = float(attested_at)
        expires = float(expires_at)
        if attested > now + self.enrollment.clock_skew_tolerance:
            return self._failure("attestation-future-dated", certificate_token)
        if now - attested > self.enrollment.max_attestation_age:
            return self._failure("attestation-stale", certificate_token)
        if expires < now or expires <= attested:
            return self._failure("attestation-expired", certificate_token)
        if expires - attested > self.enrollment.max_attestation_age:
            return self._failure("attestation-lifetime-rejected", certificate_token)

        return GatewayAttestation(
            True,
            "gateway-attested",
            "verified",
            self._endpoint_token,
            certificate_token=certificate_token,
            attested_at=attested,
            expires_at=expires,
        )

    def submit_witness(
        self,
        *,
        sequence: int,
        previous_receipt_hash: str,
        continuity_digest: str,
        event_count: int,
    ) -> GatewayWitnessReceipt:
        """Submit one compact hash-chain continuity witness.

        The API intentionally has no raw-event or arbitrary-payload argument.
        It is disabled until a separate witness URL is explicitly enrolled and
        uses the same TLS trust, mTLS option, private peer restriction, response
        cap, and certificate pin as gateway attestation.  It never mutates the
        gateway, router, host firewall, or route table.
        """

        if not self.enrollment.witness_endpoint_url:
            return self._witness_failure("witness-not-enrolled", sequence)
        if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
            return self._witness_failure("sequence-invalid", sequence)
        if type(event_count) is not int or not 0 <= event_count <= 1_000_000:
            return self._witness_failure("event-count-invalid", sequence)
        try:
            previous_hash = _sha256_hex(previous_receipt_hash, "previous receipt hash")
            digest = _sha256_hex(continuity_digest, "continuity digest")
        except GatewayConfigurationError:
            return self._witness_failure("continuity-input-invalid", sequence)
        zero_hash = "0" * 64
        if (sequence == 1 and previous_hash != zero_hash) or (
            sequence > 1 and previous_hash == zero_hash
        ):
            return self._witness_failure("previous-receipt-invalid", sequence)
        try:
            now = float(self._clock())
            nonce = self._nonce_factory()
        except Exception:
            return self._witness_failure("witness-runtime-unavailable", sequence)
        if not math.isfinite(now) or (
            not isinstance(nonce, str)
            or not 32 <= len(nonce) <= MAX_NONCE_CHARS
            or any(ord(char) < 0x21 or ord(char) > 0x7e for char in nonce)
        ):
            return self._witness_failure("witness-runtime-unavailable", sequence)

        document = {
            "schema_version": SCHEMA_VERSION,
            "nonce": nonce,
            "issued_at": now,
            "sequence": sequence,
            "previous_receipt_hash": previous_hash,
            "continuity_digest": digest,
            "event_count": event_count,
            "payload_kind": "log-continuity-digest",
        }
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(body) > 2048:
            return self._witness_failure("witness-request-too-large", sequence)
        request = GatewayTransportRequest(
            endpoint_url=self.enrollment.witness_endpoint_url,
            body=body,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
                "User-Agent": "Angerona-Personal-Sentinel/1",
            },
            connect_timeout=self.enrollment.connect_timeout,
            read_timeout=self.enrollment.read_timeout,
            max_response_bytes=self.enrollment.max_response_bytes,
            client_certificate_path=self.enrollment.client_certificate_path,
            client_key_path=self.enrollment.client_key_path,
            ca_bundle_path=self.enrollment.ca_bundle_path,
            require_tls_validation=True,
        )
        try:
            response = self._transport.send(request)
        except Exception:
            return self._witness_failure("witness-transport-failed", sequence)
        if not isinstance(response, GatewayTransportResponse):
            return self._witness_failure("witness-transport-contract-invalid", sequence)
        if response.tls_verified is not True:
            return self._witness_failure("witness-tls-unverified", sequence)
        if not self._validate_peer(response.peer_ip):
            return self._witness_failure("witness-peer-rejected", sequence)
        if (
            not isinstance(response.peer_certificate_der, bytes)
            or not response.peer_certificate_der
            or len(response.peer_certificate_der) > MAX_RESPONSE_BYTES
        ):
            return self._witness_failure("witness-certificate-invalid", sequence)
        actual_pin = hashlib.sha256(response.peer_certificate_der).hexdigest()
        if not hmac.compare_digest(actual_pin, self.enrollment.certificate_sha256):
            return self._witness_failure("witness-pin-mismatch", sequence)
        if type(response.status_code) is not int or not 100 <= response.status_code <= 599:
            return self._witness_failure("witness-http-status-invalid", sequence)
        if 300 <= response.status_code <= 399:
            return self._witness_failure("witness-redirect-rejected", sequence)
        if response.status_code != 200:
            return self._witness_failure("witness-http-status-rejected", sequence)
        if not isinstance(response.headers, Mapping) or len(response.headers) > MAX_HEADERS:
            return self._witness_failure("witness-headers-invalid", sequence)
        headers: dict[str, str] = {}
        for name, value in response.headers.items():
            if (
                not isinstance(name, str)
                or not isinstance(value, str)
                or len(name) > MAX_HEADER_CHARS
                or len(value) > MAX_HEADER_CHARS
            ):
                return self._witness_failure("witness-headers-invalid", sequence)
            lowered = name.strip().casefold()
            if lowered in headers:
                return self._witness_failure("witness-headers-ambiguous", sequence)
            headers[lowered] = value.strip()
        content_type = headers.get("content-type", "").casefold().split(";", 1)[0].strip()
        if content_type != "application/json":
            return self._witness_failure("witness-content-type-rejected", sequence)
        if (
            not isinstance(response.body, bytes)
            or not response.body
            or len(response.body) > self.enrollment.max_response_bytes
        ):
            return self._witness_failure("witness-response-size-rejected", sequence)
        try:
            receipt = _strict_json_object(response.body, _WITNESS_KEYS)
        except ValueError:
            return self._witness_failure("witness-schema-rejected", sequence)
        if type(receipt.get("schema_version")) is not int or receipt["schema_version"] != SCHEMA_VERSION:
            return self._witness_failure("witness-schema-version-mismatch", sequence)
        echoed_nonce = receipt.get("nonce")
        if not isinstance(echoed_nonce, str) or not hmac.compare_digest(echoed_nonce, nonce):
            return self._witness_failure("witness-nonce-mismatch", sequence)
        if type(receipt.get("sequence")) is not int or receipt["sequence"] != sequence:
            return self._witness_failure("witness-sequence-mismatch", sequence)
        if type(receipt.get("event_count")) is not int or receipt["event_count"] != event_count:
            return self._witness_failure("witness-event-count-mismatch", sequence)
        echoed_previous = receipt.get("previous_receipt_hash")
        echoed_digest = receipt.get("continuity_digest")
        if (
            not isinstance(echoed_previous, str)
            or not hmac.compare_digest(echoed_previous.casefold(), previous_hash)
            or not isinstance(echoed_digest, str)
            or not hmac.compare_digest(echoed_digest.casefold(), digest)
        ):
            return self._witness_failure("witness-chain-echo-mismatch", sequence)
        if receipt.get("status") != "witnessed":
            return self._witness_failure("witness-status-rejected", sequence)
        received_at = receipt.get("received_at")
        if (
            not isinstance(received_at, (int, float))
            or isinstance(received_at, bool)
            or not math.isfinite(float(received_at))
            or float(received_at) > now + self.enrollment.clock_skew_tolerance
            or now - float(received_at) > self.enrollment.max_attestation_age
        ):
            return self._witness_failure("witness-freshness-rejected", sequence)
        expected_receipt = witness_receipt_hash(
            nonce, sequence, previous_hash, digest, event_count
        )
        received_hash = receipt.get("receipt_hash")
        if (
            not isinstance(received_hash, str)
            or len(received_hash) != 64
            or not hmac.compare_digest(received_hash.casefold(), expected_receipt)
        ):
            return self._witness_failure("witness-receipt-hash-mismatch", sequence)
        return GatewayWitnessReceipt(
            True,
            "verified",
            self._witness_endpoint_token,
            sequence,
            receipt_hash=expected_receipt,
            received_at=float(received_at),
        )


def self_test() -> tuple[bool, str]:
    certificate = b"angerona-personal-sentinel-self-test-certificate"
    pin = hashlib.sha256(certificate).hexdigest()
    policy = hashlib.sha256(b"self-test-policy").hexdigest()
    now = 1_800_000_000.0

    class OfflineTransport:
        def send(self, request: GatewayTransportRequest) -> GatewayTransportResponse:
            request_body = json.loads(request.body.decode("utf-8"))
            response_body = json.dumps({
                "schema_version": 1,
                "nonce": request_body["nonce"],
                "attested_at": now - 1,
                "expires_at": now + 20,
                "policy_digest": policy,
                "path_status": "gateway-attested",
            }, separators=(",", ":")).encode("utf-8")
            return GatewayTransportResponse(
                200,
                {"content-type": "application/json"},
                response_body,
                certificate,
                "127.0.0.1",
                True,
            )

    enrollment = GatewayEnrollment(
        "https://127.0.0.1:9443/v1/attest",
        pin,
        policy,
    )
    result = PersonalSentinelGatewayClient(
        enrollment,
        b"personal-sentinel-self-test-key-01",
        transport=OfflineTransport(),
        clock=lambda: now,
        nonce_factory=lambda: "n" * 43,
    ).attest()
    if not result.success or result.path_label != "gateway-attested":
        return False, f"offline gateway attestation failed: {result.reason_code}"
    if result.endpoint_resources_trusted or result.response_authorized:
        return False, "gateway attestation granted forbidden implicit authority"
    if "127.0.0.1" in repr(result):
        return False, "raw endpoint escaped gateway result tokenization"
    return True, "pinned, nonce-bound, fail-closed gateway attestation verified offline"


__all__ = [
    "GatewayAttestation",
    "GatewayConfigurationError",
    "GatewayEnrollment",
    "GatewayMonitorBinding",
    "GatewayTransport",
    "GatewayTransportError",
    "GatewayTransportRequest",
    "GatewayTransportResponse",
    "GatewayWitnessReceipt",
    "GATEWAY_CONFIG_FILENAME",
    "MAX_RESPONSE_BYTES",
    "PersonalSentinelGatewayClient",
    "StandardHttpsGatewayTransport",
    "default_gateway_config_path",
    "load_gateway_monitor_binding",
    "self_test",
    "witness_receipt_hash",
]
