"""Authenticated loopback HTTP service for the local fleet control plane."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import threading
import time
import zlib
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlsplit

from angerona.core.authorization import AuthorizationPolicy, AuthorizationRequest
from angerona.core.fleet_credentials import (
    AuthenticatedFleetContext,
    FleetCredential,
    FleetCredentialKind,
    FleetCredentialRegistry,
)
from angerona.core.fleet_control_plane import (
    DEFAULT_DEVICE_BURST,
    DEFAULT_DEVICE_EVENTS_PER_SECOND,
    DEFAULT_TENANT_BURST,
    DEFAULT_TENANT_EVENTS_PER_SECOND,
    MAX_INGEST_BATCH,
    MAX_INGEST_BATCH_BYTES,
    MAX_QUERY_PAGE_EVENTS,
    MAX_QUERY_RESPONSE_BYTES,
    FleetControlPlane,
    FleetDevice,
    FleetRateLimitError,
)

MAX_BODY = 5 * 1024 * 1024
MAX_DECODED_BODY = 5 * 1024 * 1024
PREFERRED_COMPRESSION_THRESHOLD = 32 * 1024
MAX_SKEW_SECONDS = 60
MAX_AUTH_PATH = 8192
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
OPENAPI_VERSION = "3.1.0"
API_CONTRACT_VERSION = "2.0.0"
DEFAULT_FLEET_CREDENTIAL_ID = "local-preview"
FLEET_CREDENTIAL_HEADER = "X-Angerona-Credential-ID"
MAX_REPLAY_ENTRIES = 250_000
MAX_HANDLER_THREADS = 64

FLEET_CONTRACT_READ = "fleet.contract.read"
FLEET_CAPABILITIES_READ = "fleet.capabilities.read"
FLEET_DEVICE_READ = "fleet.device.read"
FLEET_DEVICE_REGISTER = "fleet.device.register"
FLEET_EVENT_READ = "fleet.event.read"
FLEET_EVENT_INGEST = "fleet.event.ingest"
FLEET_HEALTH_READ = "fleet.health.read"
FLEET_TENANT_PERMISSIONS = (
    FLEET_CONTRACT_READ,
    FLEET_CAPABILITIES_READ,
    FLEET_DEVICE_READ,
    FLEET_DEVICE_REGISTER,
    FLEET_EVENT_READ,
    FLEET_HEALTH_READ,
)
FLEET_DEVICE_PERMISSIONS = (
    FLEET_CAPABILITIES_READ,
    FLEET_EVENT_INGEST,
)
FLEET_LEGACY_PERMISSIONS = tuple(sorted({
    *FLEET_TENANT_PERMISSIONS, *FLEET_DEVICE_PERMISSIONS,
}))


class BodyTooLarge(ValueError):
    """The wire or decoded representation exceeded a fixed service budget."""


def ingestion_capabilities() -> dict[str, Any]:
    """Return bounded transport limits suitable for endpoint negotiation."""
    return {
        "schema": "angerona.fleet-ingestion-capabilities/v1",
        "encodings": ["identity", "gzip"],
        "preferred_encoding": "gzip",
        "preferred_compression_threshold_bytes": PREFERRED_COMPRESSION_THRESHOLD,
        "maximum_wire_bytes": MAX_BODY,
        "maximum_decoded_bytes": MAX_DECODED_BODY,
        "maximum_normalized_batch_bytes": MAX_INGEST_BATCH_BYTES,
        "maximum_batch_events": MAX_INGEST_BATCH,
        "default_rate_limits": {
            "tenant_events_per_second": DEFAULT_TENANT_EVENTS_PER_SECOND,
            "tenant_burst": DEFAULT_TENANT_BURST,
            "device_events_per_second": DEFAULT_DEVICE_EVENTS_PER_SECOND,
            "device_burst": DEFAULT_DEVICE_BURST,
        },
        "retry_after_ms": 0,
    }


def _decode_request_body(body: bytes, content_encoding: str) -> bytes:
    encoding = content_encoding.strip().casefold() or "identity"
    if encoding == "identity":
        if len(body) > MAX_DECODED_BODY:
            raise BodyTooLarge("decoded request exceeds byte budget")
        return body
    if encoding != "gzip":
        raise ValueError("content encoding must be identity or gzip")
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decoded = decoder.decompress(body, MAX_DECODED_BODY + 1)
        if len(decoded) > MAX_DECODED_BODY or decoder.unconsumed_tail:
            raise BodyTooLarge("decoded request exceeds byte budget")
        decoded += decoder.flush(MAX_DECODED_BODY + 1 - len(decoded))
    except BodyTooLarge:
        raise
    except zlib.error as exc:
        raise ValueError("gzip request body is invalid") from exc
    if len(decoded) > MAX_DECODED_BODY:
        raise BodyTooLarge("decoded request exceeds byte budget")
    if not decoder.eof or decoder.unused_data:
        raise ValueError("gzip request body must contain exactly one complete member")
    return decoded


def _strict_json(body: bytes) -> Any:
    """Decode exactly one strict UTF-8 JSON value with unique object keys."""
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("request JSON must be strict UTF-8") from exc

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("request JSON contains duplicate object keys")
            value[key] = item
        return value

    def reject_constant(_value: str) -> Any:
        raise ValueError("request JSON numbers must be finite")

    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON") from exc


def openapi_contract() -> dict[str, Any]:
    """Return the deterministic public contract for routes actually shipped."""
    auth = [{
        "AngeronaCredential": [],
        "AngeronaTimestamp": [],
        "AngeronaNonce": [],
        "AngeronaSignature": [],
    }]
    tenant_parameter = {
        "name": "tenant_id",
        "in": "path",
        "required": True,
        "schema": {
            "type": "string",
            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$",
        },
    }
    json_response = {
        "description": "Bounded JSON response",
        "content": {"application/json": {"schema": {"type": "object"}}},
    }
    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": "Angerona Local Fleet Preview API",
            "version": API_CONTRACT_VERSION,
            "description": (
                "Authenticated, loopback-only preview. This contract does not "
                "claim production mutual TLS, internet exposure, or multi-tenant "
                "high availability."
            ),
        },
        "servers": [{
            "url": "http://127.0.0.1:{port}",
            "variables": {
                "port": {"default": "47930", "description": "Local preview port"}
            },
        }],
        "security": auth,
        "paths": {
            "/health": {
                "get": {
                    "operationId": "fleetHealth",
                    "security": [],
                    "responses": {"200": json_response},
                }
            },
            "/v1/openapi": {
                "get": {
                    "operationId": "fleetOpenApiContract",
                    "responses": {
                        "200": json_response, "401": json_response,
                        "403": json_response,
                    },
                }
            },
            "/v1/ingestion-capabilities": {
                "get": {
                    "operationId": "fleetIngestionCapabilities",
                    "responses": {
                        "200": json_response, "401": json_response,
                        "403": json_response,
                    },
                }
            },
            "/v1/tenants/{tenant_id}/devices": {
                "parameters": [tenant_parameter],
                "get": {
                    "operationId": "listFleetDevices",
                    "responses": {
                        "200": json_response, "401": json_response,
                        "403": json_response,
                    },
                },
                "post": {
                    "operationId": "registerFleetDevice",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/FleetDevice"}
                            }
                        },
                    },
                    "responses": {
                        "200": json_response,
                        "400": json_response,
                        "401": json_response,
                        "403": json_response,
                        "413": json_response,
                    },
                },
            },
            "/v1/tenants/{tenant_id}/events": {
                "parameters": [tenant_parameter],
                "get": {
                    "operationId": "listFleetEvents",
                    "parameters": [{
                        "name": "device_id", "in": "query", "required": False,
                        "schema": {"type": "string"},
                    }, {
                        "name": "limit", "in": "query", "required": False,
                        "schema": {
                            "type": "integer", "minimum": 1,
                            "maximum": MAX_QUERY_PAGE_EVENTS, "default": 500,
                        },
                    }, {
                        "name": "cursor", "in": "query", "required": False,
                        "schema": {"type": "string", "maxLength": 1024},
                    }],
                    "responses": {
                        "200": json_response, "401": json_response,
                        "403": json_response,
                    },
                },
                "post": {
                    "operationId": "ingestFleetEvent",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IngestEvent"}
                            }
                        },
                    },
                    "responses": {
                        "200": json_response,
                        "400": json_response,
                        "401": json_response,
                        "403": json_response,
                        "413": json_response,
                        "429": json_response,
                    },
                },
            },
            "/v1/tenants/{tenant_id}/ingestion-health": {
                "parameters": [tenant_parameter],
                "get": {
                    "operationId": "getFleetIngestionHealth",
                    "responses": {
                        "200": json_response, "401": json_response,
                        "403": json_response,
                    },
                },
            },
            "/v1/tenants/{tenant_id}/event-batches": {
                "parameters": [tenant_parameter],
                "post": {
                    "operationId": "ingestFleetEventBatch",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/IngestBatch"
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": json_response,
                        "400": json_response,
                        "401": json_response,
                        "403": json_response,
                        "413": json_response,
                        "429": json_response,
                    },
                },
            },
        },
        "components": {
            "securitySchemes": {
                "AngeronaCredential": {
                    "type": "apiKey", "in": "header",
                    "name": FLEET_CREDENTIAL_HEADER,
                    "description": (
                        "Tenant- or device-bound local credential identifier. "
                        "The identifier is included in the signed transcript."
                    ),
                },
                "AngeronaTimestamp": {
                    "type": "apiKey", "in": "header",
                    "name": "X-Angerona-Timestamp",
                },
                "AngeronaNonce": {
                    "type": "apiKey", "in": "header",
                    "name": "X-Angerona-Nonce",
                },
                "AngeronaSignature": {
                    "type": "apiKey", "in": "header",
                    "name": "X-Angerona-Signature",
                    "description": (
                        "HMAC-SHA-256 over credential ID, method, complete path "
                        "and query, timestamp, nonce, and the SHA-256 "
                        "request-body digest."
                    ),
                },
            },
            "schemas": {
                "FleetDevice": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "device_id", "public_key", "hostname_token",
                        "platform", "version",
                    ],
                    "properties": {
                        "device_id": {"type": "string"},
                        "public_key": {"type": "string", "maxLength": 512},
                        "hostname_token": {
                            "type": "string", "pattern": "^tok_", "maxLength": 80,
                        },
                        "platform": {"type": "string", "maxLength": 40},
                        "version": {"type": "string", "maxLength": 80},
                        "group_id": {"type": "string", "default": "default"},
                    },
                },
                "IngestEvent": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["device_id", "event_id", "body"],
                    "properties": {
                        "device_id": {"type": "string"},
                        "event_id": {"type": "string"},
                        "body": {"type": "object"},
                        "observed_at": {
                            "type": "number", "exclusiveMinimum": 0,
                            "description": (
                                "Finite endpoint time. Clock quality and signed "
                                "server receipt time are returned separately."
                            ),
                        },
                    },
                },
                "IngestBatch": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["events"],
                    "properties": {
                        "events": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": MAX_INGEST_BATCH,
                            "items": {
                                "$ref": "#/components/schemas/IngestEvent"
                            },
                        },
                    },
                },
            },
        },
        "x-angerona-boundaries": {
            "transport": "loopback-only",
            "maximumRequestBytes": MAX_BODY,
            "maximumDecodedRequestBytes": MAX_DECODED_BODY,
            "maximumNormalizedBatchBytes": MAX_INGEST_BATCH_BYTES,
            "maximumBatchEvents": MAX_INGEST_BATCH,
            "requestEncodings": ["identity", "gzip"],
            "preferredCompressionThresholdBytes": (
                PREFERRED_COMPRESSION_THRESHOLD
            ),
            "maximumClockSkewSeconds": MAX_SKEW_SECONDS,
            "maximumEventPageBytes": MAX_QUERY_RESPONSE_BYTES,
            "maximumEventPageItems": MAX_QUERY_PAGE_EVENTS,
            "credentialBinding": "tenant-or-device",
            "arbitraryCommands": False,
            "productionMutualTls": False,
        },
    }


def openapi_contract_sha256() -> str:
    encoded = json.dumps(
        openapi_contract(), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_auth(
    credential_id: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    return "\n".join((
        credential_id, method.upper(), path, timestamp, nonce,
        hashlib.sha256(body).hexdigest(),
    )).encode("utf-8")


def sign_request(
    key: bytes, method: str, path: str, body: bytes = b"", *,
    timestamp: float | None = None, nonce: str | None = None,
    credential_id: str = DEFAULT_FLEET_CREDENTIAL_ID,
) -> dict[str, str]:
    if len(key) < 32:
        raise ValueError("fleet service key must contain at least 32 bytes")
    stamp = str(int(time.time() if timestamp is None else timestamp))
    token = nonce or secrets.token_urlsafe(24)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}", credential_id):
        raise ValueError("invalid fleet credential ID")
    signature = hmac.new(
        key,
        _canonical_auth(credential_id, method, path, stamp, token, body),
        hashlib.sha256,
    ).hexdigest()
    return {
        FLEET_CREDENTIAL_HEADER: credential_id,
        "X-Angerona-Timestamp": stamp,
        "X-Angerona-Nonce": token,
        "X-Angerona-Signature": signature,
    }


class FleetReplayWindow:
    """Indexed, freshness-window replay ledger that never evicts live nonces."""

    def __init__(self, path: Path, *, max_entries: int = MAX_REPLAY_ENTRIES) -> None:
        if type(max_entries) is not int or not 1 <= max_entries <= MAX_REPLAY_ENTRIES:
            raise ValueError("invalid fleet replay bound")
        supplied = Path(path)
        self.path = supplied.with_name(supplied.name + ".sqlite3")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._max_entries = max_entries
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=3000")
        self._db.execute("PRAGMA secure_delete=ON")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS fleet_replay(
          credential_id TEXT NOT NULL,
          nonce TEXT NOT NULL,
          expires_at REAL NOT NULL,
          PRIMARY KEY(credential_id,nonce));
        CREATE INDEX IF NOT EXISTS idx_fleet_replay_expiry
          ON fleet_replay(expires_at);
        """)

    def consume(
        self,
        credential_id: str,
        nonce: str,
        *,
        now: float,
        expires_at: float,
    ) -> bool:
        if not math.isfinite(now) or not math.isfinite(expires_at):
            raise ValueError("invalid replay time")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    "DELETE FROM fleet_replay WHERE expires_at<=?", (now,)
                )
                if self._db.execute(
                    "SELECT 1 FROM fleet_replay "
                    "WHERE credential_id=? AND nonce=?",
                    (credential_id, nonce),
                ).fetchone():
                    self._db.execute("COMMIT")
                    return False
                count = int(self._db.execute(
                    "SELECT COUNT(*) FROM fleet_replay"
                ).fetchone()[0])
                if count >= self._max_entries:
                    raise RuntimeError("fleet replay window is at capacity")
                self._db.execute(
                    "INSERT INTO fleet_replay VALUES(?,?,?)",
                    (credential_id, nonce, expires_at),
                )
                self._db.execute("COMMIT")
                return True
            except Exception:
                self._db.execute("ROLLBACK")
                raise


class RequestAuthenticator:
    def __init__(
        self,
        credentials: FleetCredentialRegistry | bytes,
        replay_path: Path,
        *,
        clock=time.time, max_skew: int = MAX_SKEW_SECONDS,
        legacy_tenant_id: str = "local",
    ) -> None:
        if isinstance(credentials, bytes):
            if len(credentials) < 32:
                raise ValueError("fleet service key must contain at least 32 bytes")
            credentials = FleetCredentialRegistry((FleetCredential(
                credential_id=DEFAULT_FLEET_CREDENTIAL_ID,
                tenant_id=legacy_tenant_id,
                kind=FleetCredentialKind.TENANT,
                secret=credentials,
                permissions=FLEET_LEGACY_PERMISSIONS,
            ),))
        if not isinstance(credentials, FleetCredentialRegistry):
            raise TypeError("fleet credential registry is required")
        self._credentials = credentials
        self._clock = clock
        self._max_skew = max(5, min(int(max_skew), 300))
        self._replay = FleetReplayWindow(replay_path)

    def authenticate(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[AuthenticatedFleetContext | None, str]:
        if (
            not isinstance(method, str) or not method
            or len(method) > 32
            or not isinstance(path, str) or not path
            or len(path) > MAX_AUTH_PATH
            or not isinstance(body, bytes) or len(body) > MAX_BODY
        ):
            return None, "request authentication failed"
        try:
            credential_id = headers[FLEET_CREDENTIAL_HEADER]
            stamp_text = headers["X-Angerona-Timestamp"]
            nonce = headers["X-Angerona-Nonce"]
            signature = headers["X-Angerona-Signature"]
            if not all(isinstance(value, str) for value in (
                credential_id, stamp_text, nonce, signature,
            )):
                return None, "request authentication failed"
            stamp = int(stamp_text)
            now = float(self._clock())
            if not math.isfinite(now):
                return None, "request authentication failed"
            credential = self._credentials.resolve(credential_id, now=now)
        except (KeyError, TypeError, ValueError, RuntimeError):
            return None, "request authentication failed"
        if credential is None:
            return None, "request authentication failed"
        if not _NONCE.fullmatch(nonce):
            return None, "request authentication failed"
        if not re.fullmatch(r"[0-9a-f]{64}", signature):
            return None, "request authentication failed"
        if abs(now - stamp) > self._max_skew:
            return None, "request authentication failed"
        expected = hmac.new(
            credential.secret,
            _canonical_auth(
                credential_id, method, path, stamp_text, nonce, body
            ),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None, "request authentication failed"
        try:
            if not self._replay.consume(
                credential_id,
                nonce,
                now=now,
                expires_at=float(stamp + self._max_skew + 1),
            ):
                return None, "request authentication failed"
            context = credential.authenticated_context(now)
        except Exception:
            return None, "request authentication failed"
        return context, "authenticated"

    def verify(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[bool, str]:
        context, reason = self.authenticate(method, path, headers, body)
        return context is not None, reason


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Thread-capped loopback server with observable bounded handler drain."""

    daemon_threads = True
    request_queue_size = MAX_HANDLER_THREADS

    def __init__(self, server_address, handler_class) -> None:
        self._slots = threading.BoundedSemaphore(MAX_HANDLER_THREADS)
        self._handler_condition = threading.Condition()
        self._active_handlers = 0
        super().__init__(server_address, handler_class)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        with self._handler_condition:
            self._active_handlers += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            self._handler_finished()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._handler_finished()

    def _handler_finished(self) -> None:
        self._slots.release()
        with self._handler_condition:
            self._active_handlers -= 1
            self._handler_condition.notify_all()

    def wait_for_handlers(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._handler_condition:
            while self._active_handlers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._handler_condition.wait(remaining)
            return True


class FleetLoopbackService:
    """Small bounded service; refuses every non-loopback bind."""

    def __init__(
        self,
        plane: FleetControlPlane,
        credentials: FleetCredentialRegistry | bytes,
        replay_path: Path,
        *,
        host: str = "127.0.0.1",
        port: int = 47930,
        authorization_policy: AuthorizationPolicy | None = None,
    ) -> None:
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("fleet service is loopback-only")
        if int(port) != 0 and not 1024 <= int(port) <= 65535:
            raise ValueError("invalid fleet service port")
        self.plane = plane
        self.host = host
        self.port = int(port)
        self.authorization_policy = authorization_policy
        if isinstance(credentials, bytes):
            if len(plane.tenant_ids) != 1:
                raise ValueError(
                    "legacy fleet keys are allowed only for one tenant"
                )
            self.auth = RequestAuthenticator(
                credentials,
                replay_path,
                legacy_tenant_id=plane.tenant_ids[0],
            )
        else:
            self.auth = RequestAuthenticator(credentials, replay_path)
        self._server: BoundedThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        if self._server is not None:
            return int(self._server.server_port)
        owner = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "AngeronaFleet/1"

            def version_string(self) -> str:
                return self.server_version

            def log_message(self, _format, *_args):
                return

            def setup(self):
                super().setup()
                self.connection.settimeout(5.0)

            def _json(
                self,
                status: int,
                value: Mapping[str, Any],
                *,
                extra_headers: Mapping[str, str] | None = None,
            ) -> None:
                data = json.dumps(
                    value, sort_keys=True, separators=(",", ":"), default=str
                ).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Pragma", "no-cache")
                self.send_header("X-Content-Type-Options", "nosniff")
                for name, header_value in (extra_headers or {}).items():
                    self.send_header(name, header_value)
                self.end_headers()
                self.wfile.write(data)

            def _body(self) -> bytes:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    raise ValueError("invalid content length")
                if length < 0 or length > MAX_BODY:
                    raise ValueError("request body exceeds byte budget")
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError("request body is incomplete")
                return body

            def _authenticate(
                self, body: bytes
            ) -> AuthenticatedFleetContext | None:
                context, reason = owner.auth.authenticate(
                    self.command, self.path, self.headers, body
                )
                if context is None:
                    self._json(401, {"ok": False, "error": reason})
                return context

            def _authorize(
                self,
                context: AuthenticatedFleetContext,
                tenant: str | None,
                permission: str,
                *,
                device_ids: set[str] | None = None,
            ) -> bool:
                structurally_allowed = True
                if tenant is not None:
                    structurally_allowed = context.tenant_id == tenant
                if context.kind is FleetCredentialKind.DEVICE:
                    if device_ids is not None:
                        structurally_allowed = (
                            structurally_allowed
                            and device_ids == {context.device_id}
                        )
                if owner.authorization_policy is not None:
                    if device_ids is not None:
                        candidate = (
                            next(iter(device_ids))
                            if len(device_ids) == 1 else ""
                        )
                        requested_device = (
                            candidate
                            if re.fullmatch(
                                r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}",
                                candidate,
                            )
                            else "invalid-device"
                        )
                        scope = (
                            f"fleet/{tenant or context.tenant_id}/device/"
                            f"{requested_device}"
                        )
                        resource_id = requested_device
                    elif context.kind is FleetCredentialKind.DEVICE:
                        scope = context.scope
                        resource_id = context.device_id
                    else:
                        scope = f"fleet/{tenant or context.tenant_id}"
                        resource_id = ""
                    request_seed = "\n".join((
                        context.credential_id,
                        self.command,
                        self.path,
                        permission,
                        self.headers.get("X-Angerona-Timestamp", ""),
                        self.headers.get("X-Angerona-Nonce", ""),
                    )).encode("utf-8")
                    request_id = "fleet:" + hashlib.sha256(request_seed).hexdigest()
                    try:
                        decision = owner.authorization_policy.decide(
                            AuthorizationRequest(
                                request_id=request_id,
                                principal_id=context.principal_id,
                                permission=permission,
                                scope=scope,
                                resource_id=resource_id,
                            ),
                            now=context.authenticated_at,
                        )
                        allowed = structurally_allowed and (
                            decision.allowed
                            and owner.authorization_policy.verify_decision(decision)
                        )
                    except Exception:
                        self._json(503, {
                            "ok": False,
                            "error": "authorization audit is unavailable",
                        })
                        return False
                else:
                    allowed = structurally_allowed and context.allows(permission)
                if not allowed:
                    self._json(403, {
                        "ok": False,
                        "error": "request is not authorized",
                    })
                return allowed

            def do_GET(self):  # noqa: N802
                parsed = urlsplit(self.path)
                if parsed.path == "/health":
                    self._json(200, {
                        "ok": True, "service": "angerona-fleet",
                        "transport": "loopback", "version": 1,
                        "api_contract_sha256": openapi_contract_sha256(),
                    })
                    return
                context = self._authenticate(b"")
                if context is None:
                    return
                if parsed.path == "/v1/openapi":
                    if not self._authorize(context, None, FLEET_CONTRACT_READ):
                        return
                    self._json(200, openapi_contract())
                    return
                if parsed.path == "/v1/ingestion-capabilities":
                    if not self._authorize(
                        context, None, FLEET_CAPABILITIES_READ
                    ):
                        return
                    self._json(200, ingestion_capabilities())
                    return
                parts = parsed.path.strip("/").split("/")
                if parts[:2] != ["v1", "tenants"] or len(parts) != 4:
                    self._json(404, {"ok": False, "error": "route not found"})
                    return
                tenant, resource = parts[2], parts[3]
                query = parse_qs(parsed.query)
                try:
                    if resource == "devices":
                        if not self._authorize(
                            context, tenant, FLEET_DEVICE_READ
                        ):
                            return
                        value = [asdict(item) for item in owner.plane.devices(tenant)]
                    elif resource == "events":
                        if not self._authorize(
                            context, tenant, FLEET_EVENT_READ
                        ):
                            return
                        page = owner.plane.event_page(
                            tenant,
                            device_id=query.get("device_id", [None])[0],
                            limit=int(query.get("limit", ["500"])[0]),
                            cursor=query.get("cursor", [""])[0],
                        )
                        self._json(200, {
                            "ok": True,
                            "items": list(page.items),
                            "next_cursor": page.next_cursor,
                            "truncated": page.truncated,
                            "encoded_bytes": page.encoded_bytes,
                        })
                        return
                    elif resource == "ingestion-health":
                        if not self._authorize(
                            context, tenant, FLEET_HEALTH_READ
                        ):
                            return
                        self._json(200, owner.plane.ingestion_health(tenant))
                        return
                    else:
                        raise KeyError(resource)
                    self._json(200, {"ok": True, "items": value})
                except (ValueError, PermissionError, KeyError) as exc:
                    self._json(403, {"ok": False, "error": str(exc)})

            def do_POST(self):  # noqa: N802
                try:
                    body = self._body()
                except (ValueError, TimeoutError, OSError) as exc:
                    self._json(413, {"ok": False, "error": str(exc)})
                    return
                context = self._authenticate(body)
                if context is None:
                    return
                try:
                    decoded_body = _decode_request_body(
                        body, self.headers.get("Content-Encoding", "identity")
                    )
                except BodyTooLarge as exc:
                    self._json(413, {"ok": False, "error": str(exc)})
                    return
                except ValueError as exc:
                    self._json(415, {"ok": False, "error": str(exc)})
                    return
                media_type = self.headers.get("Content-Type", "").split(";", 1)[0]
                if media_type.strip().casefold() != "application/json":
                    self._json(415, {
                        "ok": False, "error": "content type must be application/json"
                    })
                    return
                parts = urlsplit(self.path).path.strip("/").split("/")
                try:
                    if parts[:2] != ["v1", "tenants"] or len(parts) != 4:
                        raise KeyError("route not found")
                    tenant, resource = parts[2], parts[3]
                    if resource == "devices":
                        permission = FLEET_DEVICE_REGISTER
                    elif resource in {"events", "event-batches"}:
                        permission = FLEET_EVENT_INGEST
                    else:
                        raise KeyError("route not found")
                    if not self._authorize(context, tenant, permission):
                        return
                    value = _strict_json(decoded_body)
                    if resource == "devices":
                        if not isinstance(value, dict):
                            raise ValueError("device envelope must be an object")
                        allowed_fields = {
                            "device_id", "public_key", "hostname_token",
                            "platform", "version", "group_id",
                        }
                        if set(value) - allowed_fields:
                            raise ValueError("device envelope has unknown fields")
                        owner.plane.register_device(FleetDevice(
                            tenant_id=tenant,
                            device_id=value["device_id"],
                            public_key=value["public_key"],
                            hostname_token=value["hostname_token"],
                            platform=value["platform"],
                            version=value["version"],
                            group_id=value.get("group_id", "default"),
                        ))
                        result: Mapping[str, Any] = {"ok": True}
                    elif resource == "events":
                        if not isinstance(value, dict):
                            raise ValueError("event envelope must be an object")
                        if not self._authorize(
                            context,
                            tenant,
                            permission,
                            device_ids={str(value.get("device_id", ""))},
                        ):
                            return
                        result = {
                            "ok": True,
                            "receipt": asdict(
                                owner.plane.ingest_batch(tenant, (value,))[0]
                            ),
                        }
                    elif resource == "event-batches":
                        if not isinstance(value, dict) or set(value) != {"events"}:
                            raise ValueError(
                                "batch envelope must contain only events"
                            )
                        device_ids = {
                            str(event.get("device_id", ""))
                            for event in value["events"]
                            if isinstance(event, dict)
                        }
                        if not self._authorize(
                            context,
                            tenant,
                            permission,
                            device_ids=device_ids,
                        ):
                            return
                        result = {
                            "ok": True,
                            "receipts": [
                                asdict(receipt)
                                for receipt in owner.plane.ingest_batch(
                                    tenant, value["events"]
                                )
                            ],
                        }
                    else:
                        raise KeyError("route not found")
                    self._json(200, result)
                except json.JSONDecodeError:
                    self._json(400, {"ok": False, "error": "invalid JSON"})
                except FleetRateLimitError as exc:
                    self._json(
                        429,
                        {
                            "ok": False,
                            "error": str(exc),
                            "retry_after_ms": exc.retry_after_ms,
                        },
                        extra_headers={
                            "Retry-After": str(max(
                                1, math.ceil(exc.retry_after_ms / 1000)
                            ))
                        },
                    )
                except (TypeError, ValueError, PermissionError, KeyError) as exc:
                    self._json(400, {"ok": False, "error": str(exc)})

        self._server = BoundedThreadingHTTPServer(
            (self.host, self.port), Handler
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="AngeronaFleetLoopback",
            daemon=True,
        )
        self._thread.start()
        return int(self._server.server_port)

    def stop(self, timeout: float = 3.0) -> bool:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is None:
            return True
        started = time.monotonic()
        server.shutdown()
        if thread is not None:
            thread.join(max(0.1, min(float(timeout), 10.0)))
        elapsed = time.monotonic() - started
        drained = server.wait_for_handlers(max(0.0, float(timeout) - elapsed))
        server.server_close()
        return drained and (thread is None or not thread.is_alive())
