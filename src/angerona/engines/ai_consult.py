"""ai_consult.py — user-initiated online AI consultation (Anthropic-first).

Powers the operator-triggered "Consult AI", "AI Proposed Solution", and alert
"Research" actions. The GUI requires an exact sanitized-content and destination
review before each send. Direct explicit callers also pass through the same
bounded sanitizer. Model answers are advisory and grant no action authority.

Provider order (first with a key wins, each falls back to the next):
    1. Anthropic
    2. Google Gemini
    3. Groq
    4. OpenAI
    5. OpenRouter
    6. Local Ollama (always available offline) — last-resort fallback

Stdlib only (urllib) so importing this never fails on a missing SDK. Every call
is best-effort and returns a dict; it never raises.

    consult_ai(prompt, system="…") -> {
        "text": str,          # model output ("" on failure)
        "provider": str,      # which backend answered
        "error": str | None,  # populated only on total failure
    }
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from typing import Callable, Optional

from angerona.core.privacy import prepare_consultation_text

from angerona.core.provider_credentials import (
    configured_provider_ids,
    credential_value,
)
from angerona.core.url_policy import (
    OLLAMA_SERVICE_POLICY,
    host_policy,
    local_service_url,
    normalize_local_service_base,
    read_bounded,
    safe_urlopen,
)
from angerona.core.ollama_lifecycle import effective_keep_alive

# Environment-overridable model IDs. Credentials themselves are supplied only
# through the protected provider registry.
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
OPENAI_MODEL    = os.environ.get("OPENAI_MODEL", "gpt-4o")
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "anthropic/claude-3.5-sonnet")
GEMINI_MODEL    = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
GROQ_MODEL      = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
OLLAMA_MODEL    = os.environ.get("ANGERONA_MODEL", os.environ.get("OLLAMA_MODEL", "llama3"))
OLLAMA_HOST     = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")

_TIMEOUT = float(os.environ.get("ANGERONA_AI_CONSULT_TIMEOUT", "60"))
# Ephemeral, process-local account binding; never serialized as a credential.
_CONSULT_BINDING_KEY = secrets.token_bytes(32)

DEFAULT_SYSTEM = (
    "You are a senior Windows security engineer helping an operator of a local "
    "EDR/SOAR suite. Be precise, actionable, and concise. When asked for a fix or "
    "patch, provide concrete PowerShell / registry / config steps and explain the "
    "risk of each. Never invent CVE facts you are unsure of."
)


def _post(url: str, headers: dict, payload: dict, *, local: bool = False) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    if local:
        policy = OLLAMA_SERVICE_POLICY
    else:
        policy = host_policy(
            "configured AI provider",
            {
                "api.anthropic.com",
                "api.groq.com",
                "api.openai.com",
                "openrouter.ai",
                "generativelanguage.googleapis.com",
            },
        )
    with safe_urlopen(req, policy=policy, timeout=_TIMEOUT) as resp:
        return json.loads(read_bounded(resp).decode("utf-8"))


# ── Providers ─────────────────────────────────────────────────────────────────
def _anthropic(prompt: str, system: str, *,
              route: ConsultationDestination | None = None) -> Optional[str]:
    route = _adapter_route("anthropic", route)
    key = _adapter_key("anthropic", route)
    if not key:
        return None
    body = _post(
        route.endpoint,
        {"x-api-key": key, "anthropic-version": "2023-06-01",
         "content-type": "application/json"},
        {"model": route.model, "max_tokens": 1500, "system": system,
         "messages": [{"role": "user", "content": prompt}]},
    )
    parts = body.get("content") or []
    return "".join(p.get("text", "") for p in parts if isinstance(p, dict)).strip()


def _openai(prompt: str, system: str, *,
              route: ConsultationDestination | None = None) -> Optional[str]:
    route = _adapter_route("openai", route)
    key = _adapter_key("openai", route)
    if not key:
        return None
    body = _post(
        route.endpoint,
        {"Authorization": f"Bearer {key}", "content-type": "application/json"},
        {"model": route.model, "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}]},
    )
    return body["choices"][0]["message"]["content"].strip()


def _openrouter(prompt: str, system: str, *,
              route: ConsultationDestination | None = None) -> Optional[str]:
    route = _adapter_route("openrouter", route)
    key = _adapter_key("openrouter", route)
    if not key:
        return None
    body = _post(
        route.endpoint,
        {"Authorization": f"Bearer {key}", "content-type": "application/json"},
        {"model": route.model, "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}]},
    )
    return body["choices"][0]["message"]["content"].strip()


def _gemini(prompt: str, system: str, *,
              route: ConsultationDestination | None = None) -> Optional[str]:
    route = _adapter_route("gemini", route)
    key = _adapter_key("gemini", route)
    if not key:
        return None
    url = route.endpoint
    body = _post(url, {"content-type": "application/json", "x-goog-api-key": key},
                 {"system_instruction": {"parts": [{"text": system}]},
                  "contents": [{"parts": [{"text": prompt}]}]})
    cands = body.get("candidates") or []
    if not cands:
        return ""
    parts = cands[0].get("content", {}).get("parts", [])
    return "".join(p.get("text", "") for p in parts).strip()


def _groq(prompt: str, system: str, *,
              route: ConsultationDestination | None = None) -> Optional[str]:
    route = _adapter_route("groq", route)
    key = _adapter_key("groq", route)
    if not key:
        return None
    body = _post(
        route.endpoint,
        {"Authorization": f"Bearer {key}", "content-type": "application/json"},
        {"model": route.model, "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}]},
    )
    return body["choices"][0]["message"]["content"].strip()


def _ollama(prompt: str, system: str, *,
              route: ConsultationDestination | None = None) -> Optional[str]:
    route = _adapter_route("ollama", route)
    body = _post(
        local_service_url(route.endpoint[:-len("/api/chat")], "/api/chat"),
        {"content-type": "application/json"},
        {"model": route.model, "stream": False,
         "keep_alive": effective_keep_alive("30m"), "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}]},
        local=True,
    )
    return (body.get("message", {}) or {}).get("content", "").strip()


_PROVIDERS = [
    ("anthropic", _anthropic),
    ("gemini", _gemini),
    ("groq", _groq),
    ("openai", _openai),
    ("openrouter", _openrouter),
    ("ollama", _ollama),
]


def _ordered_providers():
    """Return _PROVIDERS reordered per ANGERONA_AI_ORDER (comma-separated provider
    keys the operator set in Settings). Unlisted providers keep default order."""
    order = [p.strip().lower() for p in os.environ.get("ANGERONA_AI_ORDER", "").split(",")
             if p.strip()]
    if not order:
        return list(_PROVIDERS)
    known = dict(_PROVIDERS)
    out, seen = [], set()
    for name in order:
        if name in known and name not in seen:
            out.append((name, known[name]))
            seen.add(name)
    for name, fn in _PROVIDERS:
        if name not in seen:
            out.append((name, fn))
            seen.add(name)
    return out


def available_providers() -> list[str]:
    """Names of providers that currently have a key configured (Ollama always)."""
    configured = set(configured_provider_ids())
    out = [name for name, _fn in _PROVIDERS if name in configured]
    out.append("ollama")
    return out



@dataclass(frozen=True)
class ConsultationDestination:
    provider_id: str
    endpoint: str
    model: str
    credential_binding: bytes = field(default=b"", repr=False)


@dataclass(frozen=True)
class ConsultationPreview:
    """Exact content and eligible fallback routes reviewed by the operator."""

    prompt: str
    system: str
    destinations: tuple[ConsultationDestination, ...]
    allow_local_fallback: bool

    def payload_json(self) -> str:
        return json.dumps({"system": self.system, "prompt": self.prompt},
                          ensure_ascii=False, indent=2)


def _validated_route(name: str, model: str, local_base: str = "") -> ConsultationDestination:
    # Validation is local-only: previewing does not perform DNS or HTTP.
    if (type(model) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,199}", model) is None
            or any(part in {".", ".."} for part in model.split("/"))):
        raise ValueError("provider model identity is invalid")
    endpoints = {
        "anthropic": "https://api.anthropic.com/v1/messages",
        "gemini": "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent",
        "groq": "https://api.groq.com/openai/v1/chat/completions",
        "openai": "https://api.openai.com/v1/chat/completions",
        "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    }
    if name == "ollama":
        if type(local_base) is not str or len(local_base) > 256:
            raise ValueError("local provider base is invalid")
        if any(ord(char) < 33 or ord(char) > 126 for char in local_base):
            raise ValueError("local provider base contains invalid characters")
        local_base = normalize_local_service_base(local_base)
        parsed = urlsplit(local_base)
        if (parsed.scheme not in {"http", "https"} or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"} or parsed.hostname is None):
            raise ValueError("local provider base is invalid")
        hostname = parsed.hostname.lower()
        if hostname != "localhost" and not ipaddress.ip_address(hostname).is_loopback:
            raise ValueError("local provider must use localhost or a loopback literal")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("local provider port is invalid")
        endpoint = local_base.rstrip("/") + "/api/chat"
    else:
        endpoint = endpoints[name]
    return ConsultationDestination(name, endpoint, model)


def _key_binding(name: str, key: str) -> bytes:
    if type(key) is not str or not key or len(key) > 8192:
        raise ValueError("provider credential unavailable or invalid")
    return hmac.new(_CONSULT_BINDING_KEY, name.encode("ascii") + b"\0" + key.encode("utf-8"),
                    hashlib.sha256).digest()


def _destination(name: str, *, bind_credential: bool = False) -> ConsultationDestination:
    models = {
        "anthropic": ANTHROPIC_MODEL, "gemini": GEMINI_MODEL, "groq": GROQ_MODEL,
        "openai": OPENAI_MODEL, "openrouter": OPENROUTER_MODEL, "ollama": OLLAMA_MODEL,
    }
    route = _validated_route(name, models[name], OLLAMA_HOST)
    if bind_credential and name != "ollama":
        return ConsultationDestination(name, route.endpoint, route.model,
                                       _key_binding(name, credential_value(name)))
    return route


def _adapter_route(name: str, route: ConsultationDestination | None) -> ConsultationDestination:
    if route is None:
        return _destination(name)
    if type(route) is not ConsultationDestination or route.provider_id != name:
        raise ValueError("provider route identity mismatch")
    suffix = "/api/chat"
    if name == "ollama" and not route.endpoint.endswith(suffix):
        raise ValueError("local provider route mismatch")
    base = route.endpoint[:-len(suffix)] if name == "ollama" else ""
    validated = _validated_route(name, route.model, base)
    if validated.endpoint != route.endpoint:
        raise ValueError("provider endpoint identity mismatch")
    return route


def _adapter_key(name: str, route: ConsultationDestination) -> str:
    # Bind the exact value placed in the authentication header, rather than a
    # prior lookup. Rotation/removal while a preview is pending requires review.
    key = credential_value(name)
    if route.credential_binding and not hmac.compare_digest(
            route.credential_binding, _key_binding(name, key)):
        raise ValueError("provider credential changed; review again")
    return key


def prepare_consultation(prompt: str, system: str = DEFAULT_SYSTEM,
                         allow_local_fallback: bool = True) -> ConsultationPreview:
    """Prepare an immutable review copy; no provider is contacted here.

    The destination list contains only currently configured cloud providers,
    plus the local fallback when allowed, in the operator's configured order.
    Routing or model changes between review and dispatch hold the request.
    """
    safe_prompt, safe_system = prepare_consultation_text(prompt, system)
    configured = set(configured_provider_ids())
    destinations = tuple(
        _destination(name, bind_credential=True) for name, _fn in _ordered_providers()
        if (name in configured or name == "ollama")
        and (name != "ollama" or allow_local_fallback)
    )
    return ConsultationPreview(safe_prompt, safe_system, destinations,
                               bool(allow_local_fallback))


def consult_ai(prompt: str, system: str = DEFAULT_SYSTEM,
               allow_local_fallback: bool = True, *,
               approved_preview: ConsultationPreview | None = None,
               cancelled: Callable[[], bool] | None = None) -> dict:
    """Try the configured order using sanitized content. Never send raw fallback.

    Explicit non-GUI callers retain their established provider-order behavior.
    GUI calls additionally bind dispatch to the exact reviewed content and
    configured destinations. These are privacy/admission checks, not a grant
    of host authority to any model reply.
    """
    try:
        admitted: set[str] | None = None
        providers = _ordered_providers()
        if approved_preview is not None:
            current = prepare_consultation(prompt, system, allow_local_fallback)
            if type(approved_preview) is not ConsultationPreview or current != approved_preview:
                return {"text": "", "provider": None,
                        "error": "Request held: content or destinations changed; review again."}
            safe_prompt, safe_system = current.prompt, current.system
            admitted = {route.provider_id for route in current.destinations}
            by_name = dict(providers)
            providers = [(route.provider_id, by_name[route.provider_id], route)
                         for route in current.destinations]
        else:
            providers = [(name, fn, None) for name, fn in providers]
            safe_prompt, safe_system = prepare_consultation_text(prompt, system)
    except Exception:
        return {"text": "", "provider": None,
                "error": "Request held: privacy preparation or routing validation failed."}

    errors: list[str] = []
    for name, fn, route in providers:
        try:
            if cancelled is not None and cancelled():
                return {"text": "", "provider": None, "error": "Consultation cancelled."}
        except Exception:
            return {"text": "", "provider": None, "error": "Cancellation check failed; request held."}
        if name == "ollama" and not allow_local_fallback:
            continue
        if admitted is not None and name not in admitted:
            continue
        if approved_preview is not None:
            try:
                if prepare_consultation(prompt, system, allow_local_fallback) != approved_preview:
                    raise ValueError("review configuration changed")
            except Exception:
                return {"text": "", "provider": None,
                        "error": "Request held: reviewed configuration changed before fallback."}
        try:
            text = (fn(safe_prompt, safe_system) if route is None
                    else fn(safe_prompt, safe_system, route=route))
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            errors.append(f"{name}: request failed ({type(exc).__name__[:80]})")
            continue
        except Exception as exc:
            errors.append(f"{name}: request failed ({type(exc).__name__[:80]})")
            continue
        if text is None:      # provider not configured — skip quietly
            continue
        if text:
            return {"text": text, "provider": name, "error": None}
        errors.append(f"{name}: empty response")
    return {"text": "", "provider": None,
            "error": "; ".join(errors) or "no AI provider available"}
