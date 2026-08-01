"""Authenticated loopback HTTP service for the local fleet control plane."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlsplit

from angerona.core.endpoint_identity import ReplayLedger
from angerona.core.fleet_control_plane import (
    MAX_INGEST_BATCH,
    FleetControlPlane,
    FleetDevice,
)

MAX_BODY = 256 * 1024
MAX_SKEW_SECONDS = 60
MAX_AUTH_PATH = 8192
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
OPENAPI_VERSION = "3.1.0"
API_CONTRACT_VERSION = "1.1.0"


def openapi_contract() -> dict[str, Any]:
    """Return the deterministic public contract for routes actually shipped."""
    auth = [{
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
                    "responses": {"200": json_response, "401": json_response},
                }
            },
            "/v1/tenants/{tenant_id}/devices": {
                "parameters": [tenant_parameter],
                "get": {
                    "operationId": "listFleetDevices",
                    "responses": {"200": json_response, "401": json_response},
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
                            "maximum": 5000, "default": 500,
                        },
                    }],
                    "responses": {"200": json_response, "401": json_response},
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
                        "413": json_response,
                    },
                },
            },
            "/v1/tenants/{tenant_id}/ingestion-health": {
                "parameters": [tenant_parameter],
                "get": {
                    "operationId": "getFleetIngestionHealth",
                    "responses": {"200": json_response, "401": json_response},
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
                        "413": json_response,
                    },
                },
            },
        },
        "components": {
            "securitySchemes": {
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
                        "HMAC-SHA-256 over method, complete path and query, "
                        "timestamp, nonce, and SHA-256 request-body digest."
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
                        "state": {
                            "type": "string",
                            "enum": ["active", "quarantined", "revoked", "retired"],
                            "default": "active",
                        },
                        "last_seen": {"type": "number", "minimum": 0},
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
            "maximumBatchEvents": MAX_INGEST_BATCH,
            "maximumClockSkewSeconds": MAX_SKEW_SECONDS,
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
    method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    return "\n".join((
        method.upper(), path, timestamp, nonce,
        hashlib.sha256(body).hexdigest(),
    )).encode("utf-8")


def sign_request(
    key: bytes, method: str, path: str, body: bytes = b"", *,
    timestamp: float | None = None, nonce: str | None = None,
) -> dict[str, str]:
    if len(key) < 32:
        raise ValueError("fleet service key must contain at least 32 bytes")
    stamp = str(int(time.time() if timestamp is None else timestamp))
    token = nonce or secrets.token_urlsafe(24)
    signature = hmac.new(
        key, _canonical_auth(method, path, stamp, token, body), hashlib.sha256
    ).hexdigest()
    return {
        "X-Angerona-Timestamp": stamp,
        "X-Angerona-Nonce": token,
        "X-Angerona-Signature": signature,
    }


class RequestAuthenticator:
    def __init__(
        self, key: bytes, replay_path: Path, *,
        clock=time.time, max_skew: int = MAX_SKEW_SECONDS,
    ) -> None:
        if len(key) < 32:
            raise ValueError("fleet service key must contain at least 32 bytes")
        self._key = bytes(key)
        self._clock = clock
        self._max_skew = max(5, min(int(max_skew), 300))
        self._replay = ReplayLedger(replay_path)

    def verify(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[bool, str]:
        if (
            not isinstance(method, str) or not method
            or len(method) > 32
            or not isinstance(path, str) or not path
            or len(path) > MAX_AUTH_PATH
            or not isinstance(body, bytes) or len(body) > MAX_BODY
        ):
            return False, "request components are invalid"
        try:
            stamp_text = headers["X-Angerona-Timestamp"]
            nonce = headers["X-Angerona-Nonce"]
            signature = headers["X-Angerona-Signature"]
            if not all(isinstance(value, str) for value in (
                stamp_text, nonce, signature,
            )):
                return False, "missing or invalid authentication headers"
            stamp = int(stamp_text)
        except (KeyError, TypeError, ValueError):
            return False, "missing or invalid authentication headers"
        if not _NONCE.fullmatch(nonce):
            return False, "request nonce is invalid"
        if not re.fullmatch(r"[0-9a-f]{64}", signature):
            return False, "request signature is invalid"
        if abs(float(self._clock()) - stamp) > self._max_skew:
            return False, "request timestamp is outside the freshness window"
        expected = hmac.new(
            self._key,
            _canonical_auth(method, path, stamp_text, nonce, body),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False, "request signature is invalid"
        try:
            if not self._replay.consume(nonce):
                return False, "request nonce was replayed"
        except Exception:
            return False, "replay ledger is unavailable"
        return True, "authenticated"


class FleetLoopbackService:
    """Small bounded service; refuses every non-loopback bind."""

    def __init__(
        self, plane: FleetControlPlane, key: bytes, replay_path: Path,
        *, host: str = "127.0.0.1", port: int = 47930,
    ) -> None:
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("fleet service is loopback-only")
        if int(port) != 0 and not 1024 <= int(port) <= 65535:
            raise ValueError("invalid fleet service port")
        self.plane = plane
        self.host = host
        self.port = int(port)
        self.auth = RequestAuthenticator(key, replay_path)
        self._server: ThreadingHTTPServer | None = None
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

            def _json(self, status: int, value: Mapping[str, Any]) -> None:
                data = json.dumps(
                    value, sort_keys=True, separators=(",", ":"), default=str
                ).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Pragma", "no-cache")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(data)

            def _body(self) -> bytes:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    raise ValueError("invalid content length")
                if length < 0 or length > MAX_BODY:
                    raise ValueError("request body exceeds byte budget")
                return self.rfile.read(length)

            def _authorize(self, body: bytes) -> bool:
                ok, reason = owner.auth.verify(
                    self.command, self.path, self.headers, body
                )
                if not ok:
                    self._json(401, {"ok": False, "error": reason})
                return ok

            def do_GET(self):  # noqa: N802
                parsed = urlsplit(self.path)
                if parsed.path == "/health":
                    self._json(200, {
                        "ok": True, "service": "angerona-fleet",
                        "transport": "loopback", "version": 1,
                        "api_contract_sha256": openapi_contract_sha256(),
                    })
                    return
                if not self._authorize(b""):
                    return
                if parsed.path == "/v1/openapi":
                    self._json(200, openapi_contract())
                    return
                parts = parsed.path.strip("/").split("/")
                if parts[:2] != ["v1", "tenants"] or len(parts) not in {3, 4}:
                    self._json(404, {"ok": False, "error": "route not found"})
                    return
                tenant = parts[2]
                query = parse_qs(parsed.query)
                resource = (
                    parts[3] if len(parts) == 4
                    else query.get("resource", ["devices"])[0]
                )
                try:
                    if resource == "devices":
                        value = [asdict(item) for item in owner.plane.devices(tenant)]
                    elif resource == "events":
                        value = list(owner.plane.events(
                            tenant,
                            device_id=query.get("device_id", [None])[0],
                            limit=int(query.get("limit", ["500"])[0]),
                        ))
                    elif resource == "ingestion-health":
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
                except ValueError as exc:
                    self._json(413, {"ok": False, "error": str(exc)})
                    return
                if not self._authorize(body):
                    return
                media_type = self.headers.get("Content-Type", "").split(";", 1)[0]
                if media_type.strip().casefold() != "application/json":
                    self._json(415, {
                        "ok": False, "error": "content type must be application/json"
                    })
                    return
                parts = urlsplit(self.path).path.strip("/").split("/")
                try:
                    value = json.loads(body)
                    if parts[:2] != ["v1", "tenants"] or len(parts) != 4:
                        raise KeyError("route not found")
                    tenant, resource = parts[2], parts[3]
                    if resource == "devices":
                        value["tenant_id"] = tenant
                        owner.plane.register_device(FleetDevice(**value))
                        result: Mapping[str, Any] = {"ok": True}
                    elif resource == "events":
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
                except (TypeError, ValueError, PermissionError, KeyError) as exc:
                    self._json(400, {"ok": False, "error": str(exc)})

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._server.daemon_threads = True
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
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(max(0.1, min(float(timeout), 10.0)))
            return not thread.is_alive()
        return True
