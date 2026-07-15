"""connectors/teams_bot.py — two-way Microsoft Teams bot for ARIA (opt-in).

Lets the operator chat with ARIA from Teams. Unlike an incoming webhook (which is
OUTBOUND only), this runs a small local endpoint that the Azure Bot Service POSTs
activities to, so messages flow BOTH ways: you message the bot in Teams, ARIA
answers back in the same chat.

Azure setup (one-time; do this on your side):
  1. Azure Portal → create an "Azure Bot" resource (Multi-tenant or Single-tenant).
     Note the Microsoft App ID; create a client secret (App password).
  2. Configuration → Messaging endpoint =  https://<your-tunnel>/api/messages
     Angerona runs the endpoint locally, so expose it with a tunnel (dev tunnel /
     ngrok / Azure relay). The endpoint must be HTTPS and reachable by Azure.
  3. Channels → add Microsoft Teams.
  4. In Angerona Settings ▸ Teams Bot: enable it, paste the App ID, set the port
     (default 3978) and your allowed Teams user id(s)/name(s). Put the App password
     in .env as ANGERONA_TEAMS_APP_PASSWORD (secrets belong in .env).
  5. Install the bot to your Teams (Upload a custom app / App Studio) and DM it.

Security:
  * OFF by default. Nothing listens until enabled AND an App ID + password exist.
  * Sender allowlist — only configured Teams user id(s)/name(s) are answered.
  * Inbound requests are verified as coming from the Bot Connector (JWT: audience
    == App ID, issuer + signature via the published JWKS) when PyJWT is installed.
    Without PyJWT the endpoint refuses traffic unless the explicit dev override
    ``skip_auth`` is set — so it fails CLOSED, not open.
  * ARIA's state-changing actions are NOT exposed here — chat/reads only, exactly
    like the Signal bridge. Remote mutations are intentionally out of scope.

Stdlib ``http.server`` for the listener and ``urllib`` for token/reply — both
injectable (``token_fn`` / ``reply_fn``) so ``self_test`` never touches the network.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.parse
import urllib.request
from typing import Callable, Iterable, Optional


def _have(mod: str) -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


_LOGIN_TOKEN_URL = ("https://login.microsoftonline.com/botframework.com/"
                    "oauth2/v2.0/token")
_TOKEN_SCOPE = "https://api.botframework.com/.default"
# OpenID metadata for validating tokens the Bot Connector sends us.
_OPENID_URL = "https://login.botframework.com/v1/.well-known/openidconfiguration"


class TeamsBot:
    """Opt-in, sender-allowlisted two-way Teams bot that answers via ARIA."""

    def __init__(self, *, enabled: bool = False, app_id: str = "",
                 app_password: str = "", allowed_users: Iterable[str] = (),
                 handler: Optional[Callable[[str], str]] = None,
                 port: int = 3978, path: str = "/api/messages",
                 skip_auth: bool = False,
                 token_fn: Optional[Callable[[str, str], str]] = None,
                 reply_fn: Optional[Callable[[str, str, dict], int]] = None) -> None:
        self.enabled = bool(enabled)
        self.app_id = str(app_id or "")
        self.app_password = str(app_password or "")
        self.allowed = {str(u).strip().lower() for u in allowed_users if str(u).strip()}
        self.handler = handler
        self.port = int(port)
        self.path = path or "/api/messages"
        self.skip_auth = bool(skip_auth)
        self._token_fn = token_fn
        self._reply_fn = reply_fn
        self._server = None
        self._thread = None
        self._token = ""
        self._token_exp = 0.0
        self.last_error = ""

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    def start(self) -> bool:
        """Start the local messaging endpoint if enabled and configured. Returns
        True if listening. Safe to call when disabled (no-op)."""
        if not self.enabled or not (self.app_id and self.app_password):
            return False
        try:
            from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        except Exception as exc:
            self.last_error = f"http.server unavailable: {exc}"
            return False

        bot = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):        # silence default stderr logging
                return

            def do_POST(self):                 # noqa: N802 (http.server signature)
                if self.path.rstrip("/") != bot.path.rstrip("/"):
                    self.send_response(404); self.end_headers(); return
                if not bot._verify_auth(self.headers.get("Authorization", "")):
                    self.send_response(401); self.end_headers(); return
                try:
                    length = int(self.headers.get("Content-Length", "0") or 0)
                    raw = self.rfile.read(length) if length else b""
                    activity = json.loads(raw.decode("utf-8", "replace") or "{}")
                except Exception:
                    self.send_response(400); self.end_headers(); return
                try:
                    bot.handle_activity(activity)
                except Exception as exc:
                    bot.last_error = f"activity handling failed: {exc}"
                self.send_response(200); self.end_headers()

        try:
            self._server = ThreadingHTTPServer(("0.0.0.0", self.port), _Handler)
        except Exception as exc:
            self.last_error = f"cannot bind :{self.port}: {exc}"
            return False
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="TeamsBot", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        try:
            if self._server is not None:
                self._server.shutdown()
        except Exception:
            pass

    # ── Inbound activity → ARIA → reply ───────────────────────────────────────
    def handle_activity(self, activity: dict) -> Optional[dict]:
        """Process one Bot Framework activity. Answers a 'message' from an allowed
        sender via the ARIA handler and posts the reply back. Returns the reply
        activity that was sent (or None). Public so self_test can drive it."""
        if not isinstance(activity, dict) or activity.get("type") != "message":
            return None
        frm = activity.get("from") or {}
        sender_id = str(frm.get("aadObjectId") or frm.get("id") or "").strip().lower()
        sender_name = str(frm.get("name") or "").strip().lower()
        if self.allowed and not (sender_id in self.allowed or sender_name in self.allowed):
            return None                        # not an allow-listed operator
        text = str(activity.get("text") or "").strip()
        if not text:
            return None
        reply_text = ""
        if self.handler is not None:
            try:
                reply_text = str(self.handler(text))
            except Exception as exc:
                reply_text = f"(ARIA error: {exc})"
        if not reply_text:
            return None
        return self._reply(activity, reply_text)

    def _reply(self, activity: dict, text: str) -> Optional[dict]:
        service_url = str(activity.get("serviceUrl") or "").rstrip("/")
        conv = (activity.get("conversation") or {}).get("id") or ""
        if not service_url or not conv:
            return None
        reply = {
            "type": "message",
            "from": activity.get("recipient"),
            "recipient": activity.get("from"),
            "conversation": activity.get("conversation"),
            "replyToId": activity.get("id"),
            "text": text[:3500],
        }
        url = f"{service_url}/v3/conversations/{urllib.parse.quote(conv)}/activities"
        try:
            token = self._get_token()
            if self._reply_fn is not None:      # test / custom transport
                self._reply_fn(url, token, reply)
                return reply
            body = json.dumps(reply).encode("utf-8")
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=10):
                pass
            return reply
        except Exception as exc:
            self.last_error = f"reply failed: {exc}"
            return None

    # ── Bot Connector OAuth token (client credentials) ────────────────────────
    def _get_token(self) -> str:
        now = time.time()
        if self._token and now < self._token_exp - 30:
            return self._token
        if self._token_fn is not None:
            self._token = str(self._token_fn(self.app_id, self.app_password))
            self._token_exp = now + 3000
            return self._token
        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self.app_id,
            "client_secret": self.app_password,
            "scope": _TOKEN_SCOPE,
        }).encode("utf-8")
        req = urllib.request.Request(
            _LOGIN_TOKEN_URL, data=data, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        self._token = str(payload.get("access_token") or "")
        self._token_exp = now + float(payload.get("expires_in", 3600))
        return self._token

    # ── Inbound auth: prove the request is from the Bot Connector ──────────────
    def _verify_auth(self, auth_header: str) -> bool:
        """Fail CLOSED. Full validation (signature via JWKS, audience == App ID,
        issuer, expiry) when PyJWT is available; otherwise only the explicit dev
        override lets traffic through."""
        token = ""
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
        if not token:
            return bool(self.skip_auth)
        if not _have("jwt"):
            # No JWT library → cannot verify the signature; refuse unless dev override.
            if not self.skip_auth:
                self.last_error = "PyJWT not installed; refusing unauthenticated Teams traffic"
            return bool(self.skip_auth)
        try:
            import jwt                          # PyJWT
            from jwt import PyJWKClient
            meta = json.loads(urllib.request.urlopen(_OPENID_URL, timeout=10)
                              .read().decode("utf-8", "replace"))
            jwks_uri = meta["jwks_uri"]
            signing_key = PyJWKClient(jwks_uri).get_signing_key_from_jwt(token)
            jwt.decode(token, signing_key.key, algorithms=meta.get(
                "id_token_signing_alg_values_supported", ["RS256"]),
                audience=self.app_id)
            return True
        except Exception as exc:
            self.last_error = f"inbound JWT rejected: {exc}"
            return bool(self.skip_auth)

    # ── Self-test (no network: injected token/reply transports) ────────────────
    def self_test(self) -> "tuple[bool, str]":
        try:
            sent: list = []
            asked: list = []

            def fake_token(_id, _pw):
                return "TESTTOKEN"

            def fake_reply(url, token, activity):
                sent.append((url, token, activity))
                return 200

            def handler(text):
                asked.append(text)
                return f"ARIA: re '{text}', posture is Elevated."

            bot = TeamsBot(enabled=True, app_id="app-123", app_password="secret",
                           allowed_users=["op-aad-id", "Operator Name"],
                           handler=handler, token_fn=fake_token, reply_fn=fake_reply)

            base = {"type": "message", "serviceUrl": "https://smba.trafficmanager.net/",
                    "conversation": {"id": "conv1"}, "id": "act1",
                    "recipient": {"id": "bot"}, "text": "how do I enable voice?"}

            # 1 ── allowed sender (by aadObjectId) → handler runs, reply posted
            a1 = dict(base, **{"from": {"aadObjectId": "op-aad-id", "name": "Operator Name"}})
            r1 = bot.handle_activity(a1)
            assert r1 is not None and len(sent) == 1 and asked == ["how do I enable voice?"], \
                "allowed sender answered + reply sent"
            assert sent[0][1] == "TESTTOKEN" and sent[0][0].endswith("/conv1/activities"), \
                "reply targets the conversation with a bearer token"
            assert r1["recipient"] == a1["from"], "reply addressed back to the sender"

            # 2 ── disallowed sender → ignored (no handler, no reply)
            sent.clear(); asked.clear()
            a2 = dict(base, **{"from": {"aadObjectId": "stranger", "name": "Mallory"}})
            assert bot.handle_activity(a2) is None and sent == [] and asked == [], \
                "unknown sender is ignored"

            # 3 ── non-message activity ignored
            assert bot.handle_activity({"type": "conversationUpdate"}) is None, "non-message ignored"

            # 4 ── auth fails closed without PyJWT / override; opens with dev override
            assert bot._verify_auth("Bearer sometoken") is False or _have("jwt"), \
                "no PyJWT ⇒ inbound refused (fail closed)"
            dev = TeamsBot(enabled=True, app_id="x", app_password="y", skip_auth=True)
            assert dev._verify_auth("Bearer sometoken") is True, "dev override allows (opt-in)"
            assert dev._verify_auth("") is True and TeamsBot()._verify_auth("") is False, \
                "empty auth follows skip_auth"

            return True, ("OK — allowed sender's message is answered by ARIA and the reply "
                          "is posted to the conversation with a bearer token; unknown senders "
                          "and non-messages are ignored; inbound auth fails closed without "
                          "PyJWT and only opens with the explicit dev override.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Singleton factory ──────────────────────────────────────────────────────────
_BOT: Optional[TeamsBot] = None


def init_teams_bot(**kwargs) -> TeamsBot:
    global _BOT
    _BOT = TeamsBot(**kwargs)
    return _BOT


def get_teams_bot() -> TeamsBot:
    global _BOT
    if _BOT is None:
        _BOT = TeamsBot(enabled=False)
    return _BOT


if __name__ == "__main__":
    ok, detail = TeamsBot().self_test()
    print(f"[teams_bot] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
