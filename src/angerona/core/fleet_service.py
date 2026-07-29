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
from angerona.core.fleet_control_plane import FleetControlPlane, FleetDevice

MAX_BODY = 256 * 1024
MAX_SKEW_SECONDS = 60
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")


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
        try:
            stamp_text = headers["X-Angerona-Timestamp"]
            nonce = headers["X-Angerona-Nonce"]
            signature = headers["X-Angerona-Signature"]
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
                    })
                    return
                if not self._authorize(b""):
                    return
                parts = parsed.path.strip("/").split("/")
                if len(parts) != 3 or parts[:2] != ["v1", "tenants"]:
                    self._json(404, {"ok": False, "error": "route not found"})
                    return
                tenant = parts[2]
                query = parse_qs(parsed.query)
                resource = query.get("resource", ["devices"])[0]
                try:
                    if resource == "devices":
                        value = [asdict(item) for item in owner.plane.devices(tenant)]
                    elif resource == "events":
                        value = list(owner.plane.events(
                            tenant,
                            device_id=query.get("device_id", [None])[0],
                            limit=int(query.get("limit", ["500"])[0]),
                        ))
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
                            "receipt": asdict(owner.plane.ingest(
                                tenant, value["device_id"], value["event_id"],
                                value["body"], observed_at=value.get("observed_at"),
                            )),
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
