"""ai_consult.py — user-initiated online AI consultation (Anthropic-first).

Powers the operator-triggered "Consult AI", "AI Proposed Solution", and alert
"Research" actions. These are ALWAYS explicit button presses, so the outbound
call is consented (the local-first / no-silent-egress guardrail is about
*automatic* telemetry — a human clicking "Consult AI" is deliberate).

Provider order (first with a key wins, each falls back to the next):
    1. Anthropic  (ANTHROPIC_API_KEY)      — Claude, preferred
    2. OpenAI     (OPENAI_API_KEY)
    3. OpenRouter (OPENROUTER_API_KEY)
    4. Gemini     (GEMINI_API_KEY / GEMINI_API_KEYS)
    5. Local Ollama (always available offline) — last-resort fallback

Stdlib only (urllib) so importing this never fails on a missing SDK. Every call
is best-effort and returns a dict; it never raises.

    consult_ai(prompt, system="…") -> {
        "text": str,          # model output ("" on failure)
        "provider": str,      # which backend answered
        "error": str | None,  # populated only on total failure
    }
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Optional

# Env-overridable model ids (kept current-ish; the operator can override in .env).
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
OPENAI_MODEL    = os.environ.get("OPENAI_MODEL", "gpt-4o")
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "anthropic/claude-3.5-sonnet")
GEMINI_MODEL    = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
OLLAMA_MODEL    = os.environ.get("ANGERONA_MODEL", os.environ.get("OLLAMA_MODEL", "llama3"))
OLLAMA_HOST     = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")

_TIMEOUT = float(os.environ.get("ANGERONA_AI_CONSULT_TIMEOUT", "60"))

DEFAULT_SYSTEM = (
    "You are a senior Windows security engineer helping an operator of a local "
    "EDR/SOAR suite. Be precise, actionable, and concise. When asked for a fix or "
    "patch, provide concrete PowerShell / registry / config steps and explain the "
    "risk of each. Never invent CVE facts you are unsure of."
)


def _post(url: str, headers: dict, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ── Providers ─────────────────────────────────────────────────────────────────
def _anthropic(prompt: str, system: str) -> Optional[str]:
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key:
        return None
    body = _post(
        "https://api.anthropic.com/v1/messages",
        {"x-api-key": key, "anthropic-version": "2023-06-01",
         "content-type": "application/json"},
        {"model": ANTHROPIC_MODEL, "max_tokens": 1500, "system": system,
         "messages": [{"role": "user", "content": prompt}]},
    )
    parts = body.get("content") or []
    return "".join(p.get("text", "") for p in parts if isinstance(p, dict)).strip()


def _openai(prompt: str, system: str) -> Optional[str]:
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        return None
    body = _post(
        "https://api.openai.com/v1/chat/completions",
        {"Authorization": f"Bearer {key}", "content-type": "application/json"},
        {"model": OPENAI_MODEL, "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}]},
    )
    return body["choices"][0]["message"]["content"].strip()


def _openrouter(prompt: str, system: str) -> Optional[str]:
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        return None
    body = _post(
        "https://openrouter.ai/api/v1/chat/completions",
        {"Authorization": f"Bearer {key}", "content-type": "application/json"},
        {"model": OPENROUTER_MODEL, "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}]},
    )
    return body["choices"][0]["message"]["content"].strip()


def _gemini(prompt: str, system: str) -> Optional[str]:
    key = (os.environ.get("GEMINI_API_KEY", "").strip()
           or next((k.strip() for k in os.environ.get("GEMINI_API_KEYS", "").split(",")
                    if k.strip()), ""))
    if not key:
        return None
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{GEMINI_MODEL}:generateContent?key={key}")
    body = _post(url, {"content-type": "application/json"},
                 {"system_instruction": {"parts": [{"text": system}]},
                  "contents": [{"parts": [{"text": prompt}]}]})
    cands = body.get("candidates") or []
    if not cands:
        return ""
    parts = cands[0].get("content", {}).get("parts", [])
    return "".join(p.get("text", "") for p in parts).strip()


def _ollama(prompt: str, system: str) -> Optional[str]:
    body = _post(
        f"{OLLAMA_HOST}/api/chat",
        {"content-type": "application/json"},
        {"model": OLLAMA_MODEL, "stream": False, "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}]},
    )
    return (body.get("message", {}) or {}).get("content", "").strip()


_PROVIDERS = [
    ("anthropic", _anthropic),
    ("openai", _openai),
    ("openrouter", _openrouter),
    ("gemini", _gemini),
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
    out = []
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        out.append("anthropic")
    if os.environ.get("OPENAI_API_KEY", "").strip():
        out.append("openai")
    if os.environ.get("OPENROUTER_API_KEY", "").strip():
        out.append("openrouter")
    if (os.environ.get("GEMINI_API_KEY", "").strip()
            or os.environ.get("GEMINI_API_KEYS", "").strip()):
        out.append("gemini")
    out.append("ollama")
    return out


def consult_ai(prompt: str, system: str = DEFAULT_SYSTEM,
               allow_local_fallback: bool = True) -> dict:
    """Try each provider in order; return the first successful answer. Never raises."""
    errors: list[str] = []
    for name, fn in _PROVIDERS:
        if name == "ollama" and not allow_local_fallback:
            continue
        try:
            text = fn(prompt, system)
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            errors.append(f"{name}: {exc}")
            continue
        except Exception as exc:
            errors.append(f"{name}: {exc}")
            continue
        if text is None:      # provider not configured — skip quietly
            continue
        if text:
            return {"text": text, "provider": name, "error": None}
        errors.append(f"{name}: empty response")
    return {"text": "", "provider": None,
            "error": "; ".join(errors) or "no AI provider available"}
