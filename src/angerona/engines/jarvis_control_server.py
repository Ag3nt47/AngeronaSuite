"""Authenticated, bounded JARVIS control plane for Angerona.

The existing MCP server remains read-only.  This separate loopback service
exposes only a fixed catalog of local defensive scans.  Every scan must be
prepared and then confirmed with a short-lived, single-use ticket.  The
service accepts no command text, remote host, network target, or filesystem
path, and cancellation applies only to the job started by this service.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlparse

from angerona.core.security_scan_center import (
    ScanCancellationToken,
    ScanResult,
    SecurityScanCenter,
)


CONTROL_TOKEN_ENV = "ANGERONA_JARVIS_CONTROL_TOKEN"
MIN_CONTROL_TOKEN_BYTES = 32
DEFAULT_PORT = 47925
MAX_BODY_BYTES = 64 * 1024
CONFIRMATION_TTL_SECONDS = 90
_JOB_PATH = re.compile(r"^/v1/jobs/([a-zA-Z0-9_-]{16,80})/cancel$")


def _load_control_token(data_root: object) -> str:
    """Load JARVIS authority only from Angerona's OS-protected store.

    The process may be elevated, so an inherited environment variable is an
    untrusted launch input even if ``Config.load`` would normally publish other
    protected credentials into the environment. Scrub it before every read and
    fail closed if protected enrollment is absent or malformed.
    """
    os.environ.pop(CONTROL_TOKEN_ENV, None)
    from angerona.core.secure_store import read_secret_map

    credentials = read_secret_map(data_root, strict=True)
    token = str(credentials.get(CONTROL_TOKEN_ENV, "")).strip()
    if len(token.encode("utf-8")) < MIN_CONTROL_TOKEN_BYTES:
        raise ValueError(
            "the protected JARVIS control token is missing or shorter than "
            f"{MIN_CONTROL_TOKEN_BYTES} bytes"
        )
    return token


@dataclass(frozen=True)
class _Action:
    action_id: str
    name: str
    description: str
    risk: str
    consequence: str
    runner: str

    def public(self) -> dict[str, object]:
        return {
            "id": self.action_id,
            "name": self.name,
            "description": self.description,
            "risk": self.risk,
            "consequence": self.consequence,
            "requires_confirmation": True,
            "scope": "local_host_only",
        }


_ACTIONS = {
    item.action_id: item
    for item in (
        _Action(
            "listener_audit",
            "Audit listening exposure",
            "Passively inventories local listening sockets without sending packets.",
            "low",
            "Read-only local inspection; process names are filtered and addresses are not returned.",
            "audit_listening_exposure",
        ),
        _Action(
            "network_posture",
            "Summarize network posture",
            "Summarizes local interface posture without retaining network identifiers.",
            "low",
            "Read-only local inspection; SSIDs, MAC addresses, and IP addresses are not returned.",
            "summarize_network_posture",
        ),
        _Action(
            "defender_quick_scan",
            "Run Microsoft Defender quick scan",
            "Runs the trusted local Microsoft Defender quick-scan executable.",
            "guarded",
            "Windows Defender may apply the host's configured quarantine or remediation actions.",
            "run_microsoft_defender_scan",
        ),
    )
}


class JarvisControlPlane:
    """Owns confirmation tickets and at most one adapter-started scan job."""

    def __init__(
        self,
        manager: object,
        *,
        scan_center: SecurityScanCenter | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._manager = manager
        self._scan_center = scan_center or SecurityScanCenter()
        self._clock = clock
        self._lock = threading.RLock()
        self._pending: dict[str, tuple[str, float]] = {}
        self._job: dict[str, Any] | None = None
        self._cancel: ScanCancellationToken | None = None

    def action_catalog(self) -> list[dict[str, object]]:
        return [action.public() for action in _ACTIONS.values()]

    def prepare(self, action_id: str) -> dict[str, object]:
        action = _ACTIONS.get(str(action_id).strip())
        if action is None:
            raise ValueError("unsupported Angerona action")
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            if len(self._pending) >= 16:
                oldest = min(self._pending, key=lambda key: self._pending[key][1])
                self._pending.pop(oldest, None)
            ticket = secrets.token_urlsafe(32)
            self._pending[ticket] = (action.action_id, now + CONFIRMATION_TTL_SECONDS)
        return {
            "confirmation_id": ticket,
            "expires_at": now + CONFIRMATION_TTL_SECONDS,
            "action": action.public(),
            "preview": action.consequence,
        }

    def execute(self, confirmation_id: str) -> dict[str, object]:
        ticket = str(confirmation_id).strip()
        if not ticket:
            raise PermissionError("a confirmation ticket is required")
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            staged = self._pending.pop(ticket, None)
            if staged is None:
                raise PermissionError("confirmation ticket is invalid, expired, or already used")
            action_id, expires_at = staged
            if now > expires_at:
                raise PermissionError("confirmation ticket expired")
            if self._job is not None and self._job.get("state") in {"queued", "running", "cancelling"}:
                raise RuntimeError("another JARVIS-started Angerona job is already active")
            job_id = secrets.token_urlsafe(18)
            action = _ACTIONS[action_id]
            cancel = ScanCancellationToken()
            self._cancel = cancel
            self._job = {
                "id": job_id,
                "action_id": action_id,
                "action": action.name,
                "state": "queued",
                "started_at": now,
                "finished_at": None,
                "result": None,
                "error": None,
            }
            worker = threading.Thread(
                target=self._run,
                args=(job_id, action, cancel),
                name=f"JarvisAngerona-{action_id}",
                daemon=True,
            )
            worker.start()
            return dict(self._job)

    def cancel(self, job_id: str) -> dict[str, object]:
        with self._lock:
            if self._job is None or not hmac.compare_digest(str(self._job.get("id", "")), str(job_id)):
                raise KeyError("JARVIS-started Angerona job not found")
            if self._job.get("state") not in {"queued", "running", "cancelling"}:
                raise RuntimeError("the job is no longer active")
            if self._cancel is None:
                raise RuntimeError("the job cannot be cancelled")
            self._cancel.cancel()
            self._job["state"] = "cancelling"
            return dict(self._job)

    def status(self) -> dict[str, object]:
        with self._lock:
            job = dict(self._job) if self._job is not None else None
        modules = getattr(self._manager, "modules", {})
        try:
            values = tuple(modules.values())
            total = min(len(values), 10_000)
            running = min(sum(1 for module in values if getattr(module, "status", "") == "running"), total)
        except Exception:
            total = 0
            running = 0
        return {
            "status": "ready",
            "server": "angerona-jarvis-control",
            "transport": "loopback_authenticated",
            "authority": "bounded_defensive_scans",
            "modules": {"running": running, "total": total},
            "active_job": job,
            "prohibited_inputs": [
                "arbitrary_commands",
                "filesystem_paths",
                "remote_hosts",
                "network_targets",
                "protection_disable",
                "evidence_or_quarantine_delete",
            ],
        }

    def _run(self, job_id: str, action: _Action, cancel: ScanCancellationToken) -> None:
        with self._lock:
            if self._job is None or self._job.get("id") != job_id:
                return
            self._job["state"] = "running"
        try:
            method = getattr(self._scan_center, action.runner)
            if action.action_id == "defender_quick_scan":
                result: ScanResult = method(execute=True, quick=True, cancellation=cancel)
            else:
                result = method(cancellation=cancel)
            payload = result.to_dict()
            state = "cancelled" if result.status == "cancelled" else "completed"
            with self._lock:
                if self._job is not None and self._job.get("id") == job_id:
                    self._job.update(
                        state=state,
                        finished_at=self._clock(),
                        result=payload,
                    )
        except Exception as exc:
            with self._lock:
                if self._job is not None and self._job.get("id") == job_id:
                    self._job.update(
                        state="failed",
                        finished_at=self._clock(),
                        error={"type": type(exc).__name__, "message": "Angerona scan failed safely."},
                    )
        finally:
            with self._lock:
                if self._job is not None and self._job.get("id") == job_id:
                    self._cancel = None

    def _prune_locked(self, now: float) -> None:
        for ticket, (_, expires_at) in tuple(self._pending.items()):
            if expires_at < now:
                self._pending.pop(ticket, None)


class _ControlHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "_ControlHTTPServer"

    def log_message(self, *_: object) -> None:
        return

    def _guard(self) -> bool:
        if self.client_address[0] not in {"127.0.0.1", "::1"}:
            self._error(HTTPStatus.FORBIDDEN, "loopback clients only")
            return False
        host = (self.headers.get("Host") or "").split(":", 1)[0].strip().casefold()
        if host not in {"127.0.0.1", "localhost", ""}:
            self._error(HTTPStatus.FORBIDDEN, "forbidden host")
            return False
        auth = self.headers.get("Authorization", "")
        supplied = auth[7:].strip() if auth.startswith("Bearer ") else ""
        if not supplied or not hmac.compare_digest(supplied, self.server.token):
            self._error(HTTPStatus.UNAUTHORIZED, "unauthorized")
            return False
        return True

    def _headers(self, status: int, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.end_headers()

    def _json(self, status: int, value: object) -> None:
        body = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self._headers(status, len(body))
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"status": int(status), "error": message})

    def _body(self) -> dict[str, Any]:
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise ValueError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("JSON body is required and must be at most 64 KiB")
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def do_OPTIONS(self) -> None:
        # No CORS is intentionally granted; only the local JARVIS backend talks
        # to this service, never browser JavaScript.
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if not self._guard():
            return
        path = urlparse(self.path).path
        if path in {"/health", "/v1/status"}:
            return self._json(HTTPStatus.OK, self.server.plane.status())
        if path == "/v1/actions":
            return self._json(HTTPStatus.OK, {"actions": self.server.plane.action_catalog()})
        self._error(HTTPStatus.NOT_FOUND, "route not found")

    def do_POST(self) -> None:
        if not self._guard():
            return
        path = urlparse(self.path).path
        try:
            body = self._body()
            if path == "/v1/actions/prepare":
                return self._json(HTTPStatus.CREATED, self.server.plane.prepare(str(body.get("action_id", ""))))
            if path == "/v1/actions/execute":
                return self._json(HTTPStatus.ACCEPTED, self.server.plane.execute(str(body.get("confirmation_id", ""))))
            matched = _JOB_PATH.fullmatch(path)
            if matched:
                return self._json(HTTPStatus.ACCEPTED, self.server.plane.cancel(matched.group(1)))
            self._error(HTTPStatus.NOT_FOUND, "route not found")
        except KeyError as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc).strip("'"))
        except PermissionError as exc:
            self._error(HTTPStatus.FORBIDDEN, str(exc))
        except RuntimeError as exc:
            self._error(HTTPStatus.CONFLICT, str(exc))
        except (ValueError, json.JSONDecodeError, UnicodeError) as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal control-plane error")


class _ControlHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], plane: JarvisControlPlane, token: str) -> None:
        super().__init__(address, _ControlHandler)
        self.plane = plane
        self.token = token


class AngeronaJarvisControlServer:
    """Lifecycle wrapper used by :class:`angerona.app.AngeronaApp`."""

    def __init__(self, manager: object, config: object) -> None:
        token = _load_control_token(getattr(config, "data_dir", None))
        port = int(getattr(config, "jarvis_control_port", DEFAULT_PORT))
        if not 1024 <= port <= 65535:
            raise ValueError("the JARVIS control port must be between 1024 and 65535")
        self._port = port
        self._token = token
        self._plane = JarvisControlPlane(manager)
        self._server: _ControlHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._server is not None:
            return
        server = _ControlHTTPServer(("127.0.0.1", self._port), self._plane, self._token)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.25},
            name="AngeronaJarvisControl",
            daemon=True,
        )
        self._server = server
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=2.0)
