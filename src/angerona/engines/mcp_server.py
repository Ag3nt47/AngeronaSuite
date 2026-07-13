"""
engines/mcp_server.py — Angerona MCP (Model Context Protocol) server.

Exposes Angerona's live security data as read-only MCP tools so Claude
Desktop, Claude Code, and any MCP-compatible AI can query it locally.

Transport : HTTP + Server-Sent Events (SSE) on loopback 127.0.0.1
Protocol  : MCP 2024-11-05 (JSON-RPC 2.0)
Default   : localhost:47923  (separate from :47921 singleton guard, :8000 guardrail)
Security  : loopback-only, read-only tools, no data egress — local-first.

─────────────────────────────────────────────────────────────────────────────
Claude Desktop setup — edit (or create) this file on Windows:
  C:\\Users\\<you>\\AppData\\Roaming\\Claude\\claude_desktop_config.json

    {
      "mcpServers": {
        "angerona": {
          "url": "http://127.0.0.1:47923/sse"
        }
      }
    }

Then: tick Enable in Angerona Settings → Save → restart Angerona → restart
Claude Desktop.  The port field in Settings takes a number only (e.g. 47923).
─────────────────────────────────────────────────────────────────────────────
Available tools
───────────────
  get_recent_alerts     — last N events from the flight recorder
  get_module_status     — health/state for every loaded module
  get_attack_heatmap    — live ATT&CK technique heat snapshot
  get_incidents         — correlated scored incidents
  get_remediation_log   — recent remediation audit entries
  search_events         — free-text search across the flight recorder
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
import traceback
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable


# ── Tool registry entry ───────────────────────────────────────────────────────
class _Tool:
    __slots__ = ("schema", "fn")

    def __init__(self, schema: dict, fn: Callable) -> None:
        self.schema = schema   # MCP tool-description dict
        self.fn     = fn       # callable(**arguments) → JSON-serialisable object


# ── SSE request handler ───────────────────────────────────────────────────────
class _MCPHandler(BaseHTTPRequestHandler):
    """Handles the two MCP HTTP endpoints:
      GET  /sse               — opens an SSE stream for a new session
      POST /message?sessionId — receives JSON-RPC, queues response to SSE
    """

    # Class-level refs injected by AngeronaMCPServer.start()
    _sessions: dict[str, queue.Queue]   # session_id → response queue
    _tools:    dict[str, _Tool]         # tool name → _Tool
    _port:     int
    _token:    str | None = None        # optional bearer token (ANGERONA_MCP_TOKEN)

    # ── security guard (A-02): anti DNS-rebinding + optional bearer token ─────
    def _guard(self) -> bool:
        """Reject requests whose Host isn't loopback (defeats DNS-rebinding that
        points a public hostname at 127.0.0.1) and, if a token is configured,
        requests that don't present it. Returns True only when the request is
        allowed to proceed."""
        host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
        if host not in ("127.0.0.1", "localhost", ""):
            self.send_error(403, "Forbidden host")
            return False
        tok = type(self)._token
        if tok:
            supplied = None
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if q.get("token"):
                supplied = q["token"][0]
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                supplied = auth[7:].strip()
            if supplied != tok:
                self.send_error(401, "Unauthorized")
                return False
        return True

    # ── routing ──────────────────────────────────────────────────────────────
    def do_GET(self) -> None:
        if not self._guard():
            return
        p = urllib.parse.urlparse(self.path)
        if p.path == "/sse":
            self._handle_sse()
        elif p.path == "/health":
            self._send_json(200, {"status": "ok", "server": "angerona-mcp"})
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if not self._guard():
            return
        p = urllib.parse.urlparse(self.path)
        if p.path != "/message":
            self.send_error(404)
            return
        qs  = urllib.parse.parse_qs(p.query)
        sid = qs.get("sessionId", [None])[0]
        if sid not in self._sessions:
            self.send_error(400, "Unknown sessionId")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
        except Exception:
            self.send_error(400, "Bad JSON")
            return
        response = self._dispatch(body)
        if response is not None:
            self._sessions[sid].put(response)
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_OPTIONS(self) -> None:
        # No wildcard CORS: MCP clients are not browsers, so cross-origin reads
        # are intentionally NOT permitted (A-02). A browser preflight gets no
        # Access-Control-Allow-Origin and is therefore blocked from reading data.
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ── SSE stream ───────────────────────────────────────────────────────────
    def _handle_sse(self) -> None:
        session_id = str(uuid.uuid4())
        q: queue.Queue = queue.Queue()
        self._sessions[session_id] = q

        self.send_response(200)
        self.send_header("Content-Type",  "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection",    "keep-alive")
        self.end_headers()

        # First event: tell the client where to POST its messages
        endpoint_url = (
            f"http://127.0.0.1:{self._port}/message?sessionId={session_id}"
        )
        self._write_sse("endpoint", {"uri": endpoint_url})

        # Stream: block on queue, flush responses, send keepalives every 20 s
        try:
            while True:
                try:
                    msg = q.get(timeout=20)
                    if msg is None:       # shutdown signal
                        break
                    self._write_sse("message", msg)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self._sessions.pop(session_id, None)

    def _write_sse(self, event: str, data: Any) -> None:
        blob = f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
        self.wfile.write(blob.encode())
        self.wfile.flush()

    # ── JSON-RPC dispatcher ───────────────────────────────────────────────────
    def _dispatch(self, msg: dict) -> dict | None:
        method = msg.get("method", "")
        rpc_id  = msg.get("id")
        params  = msg.get("params") or {}

        # Notifications (no id) need no response
        if rpc_id is None and method.startswith("notifications/"):
            return None

        try:
            if method == "initialize":
                return self._ok(rpc_id, {
                    "protocolVersion": "2024-11-05",
                    "capabilities":    {"tools": {}},
                    "serverInfo":      {"name": "angerona", "version": "1.3.0"},
                })

            if method == "tools/list":
                return self._ok(rpc_id, {
                    "tools": [t.schema for t in self._tools.values()]
                })

            if method == "tools/call":
                name = params.get("name", "")
                args = params.get("arguments") or {}
                tool = self._tools.get(name)
                if tool is None:
                    return self._err(rpc_id, f"Unknown tool: {name}", -32601)
                result = tool.fn(**args)
                return self._ok(rpc_id, {
                    "content": [{
                        "type": "text",
                        "text": json.dumps(result, default=str, indent=2),
                    }],
                    "isError": False,
                })

            if method in ("ping", "notifications/initialized"):
                return self._ok(rpc_id, {}) if rpc_id is not None else None

            return self._err(rpc_id, f"Method not found: {method}", -32601)

        except Exception as exc:
            tb = traceback.format_exc()
            return self._err(rpc_id, f"{exc}\n{tb}")

    @staticmethod
    def _ok(id_: Any, result: Any) -> dict:
        return {"jsonrpc": "2.0", "id": id_, "result": result}

    @staticmethod
    def _err(id_: Any, msg: str, code: int = -32000) -> dict:
        return {"jsonrpc": "2.0", "id": id_,
                "error": {"code": code, "message": msg}}

    def log_message(self, *_) -> None:  # suppress default HTTP access log
        pass


# ── Tool implementations ──────────────────────────────────────────────────────
def _make_tools(storage, bus, manager, config) -> dict[str, _Tool]:
    """Build the tool registry, closing over the live service objects."""

    tools: dict[str, _Tool] = {}

    # ── helper ───────────────────────────────────────────────────────────────
    def register(
        name: str,
        description: str,
        properties: dict,
        required: list[str],
        fn: Callable,
    ) -> None:
        tools[name] = _Tool(
            schema={
                "name":        name,
                "description": description,
                "inputSchema": {
                    "type":       "object",
                    "properties": properties,
                    "required":   required,
                },
            },
            fn=fn,
        )

    # ── 1. get_recent_alerts ─────────────────────────────────────────────────
    def _get_recent_alerts(limit: int = 20) -> list[dict]:
        """Return the most recent security alerts from the EventBus ring buffer."""
        limit = max(1, min(int(limit), 200))
        events = bus.recent(limit)
        result = []
        for e in events[-limit:]:
            result.append({
                "id":        getattr(e, "id",         getattr(e, "uuid", str(id(e)))),
                "ts":        getattr(e, "ts",         None),
                "kind":      str(getattr(e, "kind",   getattr(e, "event_type", "?"))),
                "severity":  str(getattr(e, "severity", "?")),
                "message":   str(getattr(e, "message",  getattr(e, "msg", ""))),
                "data":      getattr(e, "data",       {}),
                "mitre_tags": getattr(e, "mitre_tags", []),
            })
        return result

    register(
        name="get_recent_alerts",
        description=(
            "Return the N most recent security events from Angerona's live EventBus. "
            "Includes severity, kind, MITRE tags, and raw event data."
        ),
        properties={
            "limit": {
                "type":        "integer",
                "description": "Number of alerts to return (1–200, default 20)",
                "default":     20,
            }
        },
        required=[],
        fn=_get_recent_alerts,
    )

    # ── 2. get_module_status ─────────────────────────────────────────────────
    def _get_module_status() -> list[dict]:
        """Return health/state for every loaded module."""
        rows = []
        for name, mod in manager.modules.items():
            rows.append({
                "name":         name,
                "status":       getattr(mod, "status",       "unknown"),
                "health_pct":   getattr(mod, "health_pct",   None),
                "health_state": getattr(mod, "health_state", None),
                "health_note":  getattr(mod, "health_note",  ""),
                "category":     getattr(mod, "category",     ""),
                "version":      getattr(mod, "version",      ""),
                "description":  getattr(mod, "description",  ""),
            })
        rows.sort(key=lambda r: r["name"])
        return rows

    register(
        name="get_module_status",
        description=(
            "Return health percentage, running state, and metadata for every "
            "Angerona module (sensors, detectors, SOAR, red-team, etc.)."
        ),
        properties={},
        required=[],
        fn=_get_module_status,
    )

    # ── 3. get_attack_heatmap ────────────────────────────────────────────────
    def _get_attack_heatmap(min_heat: float = 0.0) -> dict:
        """Return the live ATT&CK technique heat snapshot."""
        from angerona.core.attack_tracker import get_tracker
        tracker = get_tracker()
        if tracker is None:
            return {"error": "AttackTracker not initialised"}
        snap = tracker.snapshot()
        if min_heat > 0:
            snap["matrix"] = {
                tid: row for tid, row in snap["matrix"].items()
                if row["heat"] >= min_heat
            }
        return snap

    register(
        name="get_attack_heatmap",
        description=(
            "Return the live MITRE ATT&CK heatmap: 86 techniques across 14 tactics "
            "with time-decayed heat scores (0.0–1.0), hit counts, and last-seen timestamps. "
            "Optionally filter to only active techniques."
        ),
        properties={
            "min_heat": {
                "type":        "number",
                "description": "Only return techniques with heat >= this value (0.0 = all)",
                "default":     0.0,
            }
        },
        required=[],
        fn=_get_attack_heatmap,
    )

    # ── 4. get_incidents ─────────────────────────────────────────────────────
    def _get_incidents(limit: int = 10) -> list[dict]:
        """Return the most recent correlated incidents."""
        limit = max(1, min(int(limit), 100))
        try:
            from angerona.core.incidents import get_correlator
            correlator = get_correlator()
            incidents  = correlator.recent(limit)
            result = []
            for inc in incidents:
                result.append({
                    "id":          getattr(inc, "id",           "?"),
                    "risk_score":  getattr(inc, "risk_score",   0),
                    "opened":      getattr(inc, "opened_at",    None),
                    "closed":      getattr(inc, "closed_at",    None),
                    "event_count": getattr(inc, "event_count",  0),
                    "tactics":     getattr(inc, "tactics",      []),
                    "techniques":  getattr(inc, "techniques",   []),
                    "summary":     getattr(inc, "summary",      ""),
                })
            return result
        except Exception as exc:
            return [{"error": str(exc)}]

    register(
        name="get_incidents",
        description=(
            "Return the N most recent correlated security incidents. Each incident "
            "aggregates related alerts into a time-windowed, risk-scored event group "
            "with MITRE tactic/technique coverage."
        ),
        properties={
            "limit": {
                "type":        "integer",
                "description": "Number of incidents to return (1–100, default 10)",
                "default":     10,
            }
        },
        required=[],
        fn=_get_incidents,
    )

    # ── 5. get_remediation_log ───────────────────────────────────────────────
    def _get_remediation_log(limit: int = 20) -> list[dict]:
        """Return recent remediation audit entries."""
        limit = max(1, min(int(limit), 200))
        try:
            from angerona.core.remediation_log import get_log
            log = get_log()
            if log is None:
                return [{"error": "RemediationLog not initialised"}]
            return log.recent(limit)  # already returns list[dict]
        except Exception as exc:
            return [{"error": str(exc)}]

    register(
        name="get_remediation_log",
        description=(
            "Return the N most recent entries from the remediation audit log — "
            "every applied/skipped/dry-run/rolled-back action with its MITRE TID, "
            "caller, outcome, and verification result."
        ),
        properties={
            "limit": {
                "type":        "integer",
                "description": "Number of entries to return (1–200, default 20)",
                "default":     20,
            }
        },
        required=[],
        fn=_get_remediation_log,
    )

    # ── 6. search_events ─────────────────────────────────────────────────────
    def _search_events(query: str, limit: int = 50) -> list[dict]:
        """Full-text search across the flight recorder."""
        limit = max(1, min(int(limit), 500))
        query = str(query).strip()
        if not query:
            return [{"error": "query must not be empty"}]
        try:
            rows = storage.search(query, limit=limit)   # FlightRecorder.search()
            return rows if isinstance(rows, list) else list(rows)
        except AttributeError:
            # Fallback: scan bus.recent(400) if storage.search() not available
            recent = bus.recent(400)
            q_lo   = query.lower()
            hits   = []
            for e in recent:
                blob = json.dumps(
                    {
                        "kind":    str(getattr(e, "kind",    "")),
                        "message": str(getattr(e, "message", getattr(e, "msg", ""))),
                        "data":    getattr(e, "data", {}),
                    },
                    default=str,
                ).lower()
                if q_lo in blob:
                    hits.append({
                        "id":      getattr(e, "id",    str(id(e))),
                        "ts":      getattr(e, "ts",    None),
                        "kind":    str(getattr(e, "kind", "?")),
                        "message": str(getattr(e, "message", "")),
                    })
                    if len(hits) >= limit:
                        break
            return hits
        except Exception as exc:
            return [{"error": str(exc)}]

    register(
        name="search_events",
        description=(
            "Full-text search across the Angerona flight recorder database. "
            "Matches against kind, message, process name, and event data fields."
        ),
        properties={
            "query": {
                "type":        "string",
                "description": "Search term (plain text, case-insensitive)",
            },
            "limit": {
                "type":        "integer",
                "description": "Maximum results to return (1–500, default 50)",
                "default":     50,
            },
        },
        required=["query"],
        fn=_search_events,
    )

    return tools


# ── Server ────────────────────────────────────────────────────────────────────
class AngeronaMCPServer:
    """Loopback HTTP+SSE MCP server.

    Lifecycle mirrors StatusReporter — call start() at app boot and stop()
    in AngeronaApp.shutdown().  The HTTP server runs on a daemon thread so
    it cannot block app exit.
    """

    def __init__(self, storage, bus, manager, config) -> None:
        self._storage = storage
        self._bus     = bus
        self._manager = manager
        self._config  = config
        self._httpd:  HTTPServer | None     = None
        self._thread: threading.Thread | None = None
        self._sessions: dict[str, queue.Queue] = {}

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def start(self) -> int:
        """Start the server; returns the port it bound to."""
        port  = int(getattr(self._config, "mcp_port", 47923))
        tools = _make_tools(self._storage, self._bus, self._manager, self._config)

        sessions = self._sessions
        tools_ref = tools
        # Optional bearer token (A-02). Prefer config.mcp_token, else env; None = off.
        token = (getattr(self._config, "mcp_token", None)
                 or os.environ.get("ANGERONA_MCP_TOKEN") or None)

        class Handler(_MCPHandler):
            _sessions = sessions
            _tools    = tools_ref
            _port     = port
            _token    = token

        self._httpd = HTTPServer(("127.0.0.1", port), Handler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="AngeronaMCP",
            daemon=True,
        )
        self._thread.start()
        return port

    def stop(self) -> None:
        """Gracefully shut down the server and close all SSE sessions."""
        for q in list(self._sessions.values()):
            try:
                q.put_nowait(None)   # signal each SSE stream to close
            except Exception:
                pass
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd = None

    @property
    def is_running(self) -> bool:
        return self._httpd is not None and (
              self._thread is not None and self._thread.is_alive()
        )

    @property
    def url(self) -> str:
        port = int(getattr(self._config, "mcp_port", 47923))
        return f"http://127.0.0.1:{port}/sse"
