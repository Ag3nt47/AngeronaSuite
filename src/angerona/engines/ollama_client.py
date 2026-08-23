"""
engines/ollama_client.py — the single, guarded entry point for local-LLM calls.

Every model call in the suite should route through here (BL-02 single choke point,
BL-03 guardrail on every path). It applies the AI guardrail to input (injection
scan + DoS cap + immutable hardened system prompt), neutralizes untrusted
telemetry so embedded instructions are treated as data, forwards to Ollama with
the per-session guardrail token, redacts the response (PII / secrets / paths),
and audits — so no code path can reach the model unguarded.

Pure decision logic (guard_payload / analyze_telemetry) is unit-testable without
a running model. Transport is loopback-only and bounded by the shared URL policy.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request

from angerona.core.url_policy import (
    LOCAL_SERVICE_POLICY,
    UrlPolicyError,
    local_json_request,
    local_service_url,
    safe_urlopen,
)
from angerona.engines import ai_guardrail as g
from angerona.core.ollama_lifecycle import effective_keep_alive


_GENERATION_PATHS = frozenset({"/api/generate", "/api/chat"})
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_STREAM_BYTES = 8 * 1024 * 1024
_MAX_STREAM_LINE = 64 * 1024
_METRICS_LOCK = threading.Lock()
_METRICS: dict[str, float | int] = {}


def _validated_path(path: str) -> str:
    if path not in _GENERATION_PATHS:
        raise UrlPolicyError("unsupported local model API path")
    return path


def _upstream_error(exc: Exception, *, path: str, started: float, plen: int) -> dict:
    """Return an operator-useful error without leaking paths or payload data."""
    kind = type(exc).__name__
    g.audit(
        "Upstream Error",
        "Med",
        plen,
        time.time() - started,
        {"error_type": kind, "path": path},
    )
    return {"error": "local model unavailable", "error_type": kind}


def _record_metrics(result: dict, wall_seconds: float) -> None:
    """Retain aggregate timing only; prompts and responses are never cached."""
    metrics: dict[str, float | int] = {
        "last_call_epoch": time.time(),
        "last_wall_ms": round(max(0.0, wall_seconds) * 1000, 1),
    }
    for key in ("eval_count", "eval_duration", "prompt_eval_count"):
        value = result.get(key)
        if isinstance(value, (int, float)) and value >= 0:
            metrics[key] = value
    count = metrics.get("eval_count")
    duration = metrics.get("eval_duration")
    if isinstance(count, (int, float)) and isinstance(duration, (int, float)) and duration:
        metrics["tokens_per_sec"] = round(float(count) / (float(duration) / 1e9), 1)
    with _METRICS_LOCK:
        _METRICS.clear()
        _METRICS.update(metrics)


def diagnostics_snapshot() -> dict[str, float | int]:
    """Return non-sensitive metrics from the last real inference, without probing."""
    with _METRICS_LOCK:
        return dict(_METRICS)


def guard_payload(payload: dict) -> dict:
    """Apply input guardrails to an Ollama payload. Returns
    {'allow','status','verdict','payload'} (payload has the system prompt wrapped
    and an over-long prompt truncated; blocked=injection => allow False)."""
    return g.process_request(dict(payload))


def analyze_telemetry(
    prompt_intro: str,
    telemetry: str,
    model: str,
    path: str = "/api/generate",
    *,
    system: str | None = None,
    host: str | None = None,
    timeout: int = 120,
    options: dict | None = None,
    keep_alive: str = "30m",
) -> dict:
    """Build a guarded /api/generate payload whose telemetry is NEUTRALIZED
    (delimited + defused) before it reaches the model — the safe way to ask the
    model to reason over attacker-influenced strings."""
    payload = {
        "model": model,
        "stream": False,
        "keep_alive": keep_alive,
        "prompt": prompt_intro.strip(),
    }
    if system:
        payload["system"] = system
    if options:
        payload["options"] = dict(options)
    return call(
        payload,
        path,
        host=host,
        timeout=timeout,
        neutralized_telemetry=telemetry,
    )


def call(
    payload: dict,
    path: str = "/api/generate",
    host: str | None = None,
    timeout: int = 120,
    *,
    neutralized_telemetry: str | None = None,
) -> dict:
    """Guarded round-trip to Ollama. Blocks injected/oversized prompts up front,
    forwards with the session token, and redacts the response. Best-effort; returns
    an {'error': ...} dict rather than raising."""
    t0 = time.time()
    # Chill keeps ARIA available on demand but never leaves the model pinned
    # after the response. Apply this at the shared transport choke point so
    # callers cannot accidentally defeat the all-day low-resource profile.
    payload = dict(payload)
    payload["keep_alive"] = effective_keep_alive(payload.get("keep_alive", "30m"))
    plen = g._prompt_len_of(payload)
    decision = guard_payload(payload)
    if not decision["allow"]:
        g.audit("Input Blocked", decision["verdict"]["risk"], plen, time.time() - t0,
                {"reasons": decision["verdict"]["reasons"], "path": path})
        return {"error": "blocked by AI guardrail", "reasons": decision["verdict"]["reasons"]}
    if neutralized_telemetry is not None:
        # Scan the trusted analysis instruction first, then append attacker-
        # influenced evidence in a bounded, unmistakable data envelope. This
        # preserves detection of prompt-injection text without executing it or
        # treating the mere presence of that text as a reason to skip triage.
        evidence = g.neutralize_telemetry(neutralized_telemetry)
        guarded = decision["payload"]
        if path == "/api/chat" and isinstance(guarded.get("messages"), list):
            guarded["messages"].append({"role": "user", "content": evidence})
        else:
            guarded["prompt"] = str(guarded.get("prompt", "")).rstrip() + "\n\n" + evidence
        plen += len(evidence)
    host = host or g.OLLAMA_UPSTREAM
    try:
        path = _validated_path(path)
        raw = local_json_request(
            host,
            path,
            payload=decision["payload"],
            headers={g.TOKEN_HEADER: g.SESSION_TOKEN},
            timeout=timeout,
            request_maximum=_MAX_REQUEST_BYTES,
        )
    except Exception as exc:
        return _upstream_error(exc, path=str(path), started=t0, plen=plen)
    applied = []
    if "response" in raw:
        raw["response"], applied = g.redact_output(str(raw.get("response", "")))
    elif isinstance(raw.get("message"), dict):
        raw["message"]["content"], applied = g.redact_output(str(raw["message"].get("content", "")))
    g.audit("Output Redacted" if applied else "Clean", decision["verdict"]["risk"],
            plen, time.time() - t0, {"redactions": applied})
    _record_metrics(raw, time.time() - t0)
    return raw


def call_stream(payload: dict, on_token, path: str = "/api/generate",
                host: str | None = None, timeout: int = 120) -> dict:
    """Guarded STREAMING round-trip: same input guardrail as call(), but the model's
    reply is read as bounded newline-delimited JSON. Output is fully assembled
    and redacted *before* ``on_token(chunk)`` receives it, preventing secrets
    split across network chunks from flashing in the UI. Best-effort; returns an
    error object on failure."""
    t0 = time.time()
    payload = dict(payload)
    payload["keep_alive"] = effective_keep_alive(payload.get("keep_alive", "30m"))
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
    final_meta: dict = {}
    try:
        path = _validated_path(path)
        body = json.dumps(
            pay,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(body) > _MAX_REQUEST_BYTES:
            raise UrlPolicyError("local model request exceeds its size bound")
        request = urllib.request.Request(
            local_service_url(host, path),
            data=body,
            headers={
                "Accept": "application/x-ndjson, application/json",
                "Content-Type": "application/json; charset=utf-8",
                g.TOKEN_HEADER: g.SESSION_TOKEN,
            },
            method="POST",
        )
        total = 0
        with safe_urlopen(
            request,
            policy=LOCAL_SERVICE_POLICY,
            timeout=float(timeout),
        ) as response:
            while True:
                line = response.readline(_MAX_STREAM_LINE + 1)
                if not line:
                    break
                total += len(line)
                if len(line) > _MAX_STREAM_LINE or total > _MAX_STREAM_BYTES:
                    raise UrlPolicyError("local model stream exceeds its size bound")
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(obj, dict):
                    continue
                final_meta = obj
                chunk = obj.get("response")
                if chunk is None and isinstance(obj.get("message"), dict):
                    chunk = obj["message"].get("content")
                if chunk:
                    parts.append(str(chunk))
                if obj.get("done"):
                    break
    except Exception as exc:
        return _upstream_error(exc, path=str(path), started=t0, plen=plen)
    clean_text, applied = g.redact_output("".join(parts))
    for offset in range(0, len(clean_text), 32):
        try:
            on_token(clean_text[offset:offset + 32])
        except Exception:
            break
    g.audit("Output Redacted" if applied else "Clean", decision["verdict"]["risk"],
            plen, time.time() - t0, {"redactions": applied, "streamed": True})
    _record_metrics(final_meta, time.time() - t0)
    return {"response": clean_text}
