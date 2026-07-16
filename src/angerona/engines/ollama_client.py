"""
engines/ollama_client.py — the single, guarded entry point for local-LLM calls.

Every model call in the suite should route through here (BL-02 single choke point,
BL-03 guardrail on every path). It applies the AI guardrail to input (injection
scan + DoS cap + immutable hardened system prompt), neutralizes untrusted
telemetry so embedded instructions are treated as data, forwards to Ollama with
the per-session guardrail token, redacts the response (PII / secrets / paths),
and audits — so no code path can reach the model unguarded.

Pure decision logic (guard_payload / analyze_telemetry) is unit-testable without
a running model; `call` lazily imports requests.
"""
from __future__ import annotations

import time

from angerona.engines import ai_guardrail as g


def guard_payload(payload: dict) -> dict:
    """Apply input guardrails to an Ollama payload. Returns
    {'allow','status','verdict','payload'} (payload has the system prompt wrapped
    and an over-long prompt truncated; blocked=injection => allow False)."""
    return g.process_request(dict(payload))


def analyze_telemetry(prompt_intro: str, telemetry: str, model: str,
                      path: str = "/api/generate") -> dict:
    """Build a guarded /api/generate payload whose telemetry is NEUTRALIZED
    (delimited + defused) before it reaches the model — the safe way to ask the
    model to reason over attacker-influenced strings."""
    payload = {"model": model, "stream": False,
               "prompt": prompt_intro.strip() + "\n\n" + g.neutralize_telemetry(telemetry)}
    return call(payload, path)


def call(payload: dict, path: str = "/api/generate", host: str | None = None,
         timeout: int = 120) -> dict:
    """Guarded round-trip to Ollama. Blocks injected/oversized prompts up front,
    forwards with the session token, and redacts the response. Best-effort; returns
    an {'error': ...} dict rather than raising."""
    t0 = time.time()
    plen = g._prompt_len_of(payload)
    decision = guard_payload(payload)
    if not decision["allow"]:
        g.audit("Input Blocked", decision["verdict"]["risk"], plen, time.time() - t0,
                {"reasons": decision["verdict"]["reasons"], "path": path})
        return {"error": "blocked by AI guardrail", "reasons": decision["verdict"]["reasons"]}
    host = host or g.OLLAMA_UPSTREAM
    try:
        import requests
        r = requests.post(f"{host}{path}", json=decision["payload"], timeout=timeout,
                          headers={g.TOKEN_HEADER: g.SESSION_TOKEN})
        raw = r.json()
    except Exception as exc:
        g.audit("Upstream Error", "Med", plen, time.time() - t0, {"error": str(exc)})
        return {"error": f"upstream: {exc}"}
    applied = []
    if "response" in raw:
        raw["response"], applied = g.redact_output(str(raw.get("response", "")))
    elif isinstance(raw.get("message"), dict):
        raw["message"]["content"], applied = g.redact_output(str(raw["message"].get("content", "")))
    g.audit("Output Redacted" if applied else "Clean", decision["verdict"]["risk"],
            plen, time.time() - t0, {"redactions": applied})
    return raw


def call_stream(payload: dict, on_token, path: str = "/api/generate",
                host: str | None = None, timeout: int = 120) -> dict:
    """Guarded STREAMING round-trip: same input guardrail as call(), but the model's
    reply is streamed. ``on_token(chunk)`` is invoked for each text chunk as it
    arrives (for a live typing effect); the full reply is redacted once at the end
    and returned as {'response': ...}. Best-effort; returns {'error': ...} on failure."""
    t0 = time.time()
    plen = g._prompt_len_of(payload)
    decision = guard_payload(payload)
    if not decision["allow"]:
        g.audit("Input Blocked", decision["verdict"]["risk"], plen, time.time() - t0,
                {"reasons": decision["verdict"]["reasons"], "path": path})
        return {"error": "blocked by AI guardrail", "reasons": decision["verdict"]["reasons"]}
    host = host or g.OLLAMA_UPSTREAM
    pay = dict(decision["payload"])
    pay["stream"] = True
    parts: list[str] = []
    try:
        import json as _json
        import requests
        with requests.post(f"{host}{path}", json=pay, timeout=timeout,
                           headers={g.TOKEN_HEADER: g.SESSION_TOKEN}, stream=True) as r:
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                try:
                    obj = _json.loads(line)
                except Exception:
                    continue
                chunk = obj.get("response")
                if chunk is None and isinstance(obj.get("message"), dict):
                    chunk = obj["message"].get("content")
                if chunk:
                    parts.append(chunk)
                    try:
                        on_token(chunk)
                    except Exception:
                        pass
                if obj.get("done"):
                    break
    except Exception as exc:
        g.audit("Upstream Error", "Med", plen, time.time() - t0, {"error": str(exc)})
        return {"error": f"upstream: {exc}"}
    text, applied = g.redact_output("".join(parts))
    g.audit("Output Redacted" if applied else "Clean", decision["verdict"]["risk"],
            plen, time.time() - t0, {"redactions": applied, "streamed": True})
    return {"response": text}
