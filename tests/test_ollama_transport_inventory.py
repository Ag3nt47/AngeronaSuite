from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).parents[1] / "src" / "angerona"
_OLLAMA_ROUTES = {
    "/api/chat",
    "/api/copy",
    "/api/create",
    "/api/delete",
    "/api/embed",
    "/api/embeddings",
    "/api/generate",
    "/api/ps",
    "/api/pull",
    "/api/push",
    "/api/show",
    "/api/tags",
    "/api/version",
}


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _policy_name(node: ast.Call) -> str:
    for keyword in node.keywords:
        if keyword.arg == "policy" and isinstance(keyword.value, ast.Name):
            return keyword.value.id
    return ""


def _uses_ollama_route(source: str) -> bool:
    return any(route in source for route in _OLLAMA_ROUTES) or (
        "/api/blobs/sha256:" in source
    )


def _is_raw_network_call(node: ast.Call) -> bool:
    """Identify transports that would skip the central URL policy entirely."""
    if isinstance(node.func, ast.Name):
        return node.func.id == "urlopen"
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr == "urlopen":
        return True
    return (
        isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"requests", "httpx", "urllib3", "aiohttp"}
        and node.func.attr
        in {"get", "post", "put", "delete", "patch", "request", "stream"}
    )


def test_every_local_ollama_transport_is_attested() -> None:
    failures: list[str] = []
    for path in _ROOT.rglob("*.py"):
        relative = path.relative_to(_ROOT).as_posix()
        source = path.read_text(encoding="utf-8-sig")
        tree = ast.parse(source, filename=str(path))
        uses_ollama_route = _uses_ollama_route(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = (
                    [alias.name for alias in node.names]
                    if isinstance(node, ast.Import)
                    else [str(node.module or "")]
                )
                if any(name == "ollama" or name.startswith("ollama.") for name in modules):
                    failures.append(f"{relative}:{node.lineno}: direct Ollama SDK import")
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "ollama"
                and name in {"chat", "generate", "Client"}
            ):
                failures.append(f"{relative}:{node.lineno}: direct Ollama SDK call")
            if relative == "core/url_policy.py":
                continue
            if uses_ollama_route and _is_raw_network_call(node):
                failures.append(
                    f"{relative}:{node.lineno}: raw Ollama network call bypasses policy"
                )
            if name == "local_json_request" and uses_ollama_route:
                if _policy_name(node) != "OLLAMA_SERVICE_POLICY":
                    failures.append(
                        f"{relative}:{node.lineno}: Ollama JSON request lacks attested policy"
                    )
            if name == "safe_urlopen" and uses_ollama_route:
                policy = _policy_name(node)
                if policy == "LOCAL_SERVICE_POLICY" or not policy:
                    failures.append(
                        f"{relative}:{node.lineno}: Ollama URL open lacks attested policy"
                    )
                if policy == "policy" and "policy = OLLAMA_SERVICE_POLICY" not in source:
                    failures.append(
                        f"{relative}:{node.lineno}: dynamic Ollama policy is not bound"
                    )

    assert failures == []


def test_generic_local_policy_is_not_used_as_an_ollama_bypass() -> None:
    offenders = []
    for path in _ROOT.rglob("*.py"):
        relative = path.relative_to(_ROOT).as_posix()
        if relative == "core/url_policy.py":
            continue
        source = path.read_text(encoding="utf-8-sig")
        if "LOCAL_SERVICE_POLICY" in source:
            offenders.append(relative)
    assert offenders == []
