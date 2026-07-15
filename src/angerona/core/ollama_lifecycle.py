"""Small, best-effort lifecycle helpers for Angerona's local Ollama models."""
from __future__ import annotations

import json
from urllib import request


def _json_request(url: str, payload: dict | None, timeout: float) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method="POST" if data is not None else "GET",
    )
    with request.urlopen(req, timeout=timeout) as response:
        raw = response.read()
    return json.loads(raw.decode("utf-8")) if raw else {}


def unload_angerona_models(
    host: str = "http://localhost:11434",
    configured_model: str = "llama3",
    timeout: float = 1.5,
) -> list[str]:
    """Immediately unload resident llama3/configured models from local Ollama.

    Only models reported by ``/api/ps`` are touched, so shutdown never loads a
    missing model merely to unload it.  Ollama itself stays available for other
    local applications; the CPU/GPU-heavy model runner is released.
    """
    base = host.rstrip("/")
    wanted = (configured_model or "llama3").split(":", 1)[0].casefold()
    try:
        running = _json_request(f"{base}/api/ps", None, timeout).get("models", [])
    except Exception:
        return []

    unloaded: list[str] = []
    for item in running:
        name = str(item.get("name") or item.get("model") or "").strip()
        family = name.split(":", 1)[0].casefold()
        if not name or (family != wanted and not family.startswith("llama3")):
            continue
        try:
            _json_request(
                f"{base}/api/generate",
                {"model": name, "prompt": "", "stream": False, "keep_alive": 0},
                timeout,
            )
            unloaded.append(name)
        except Exception:
            continue
    return unloaded
