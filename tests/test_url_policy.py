from __future__ import annotations

import socket
import urllib.request
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from angerona.core.url_policy import (
    LOCAL_SERVICE_POLICY,
    OLLAMA_SERVICE_POLICY,
    PUBLIC_HTTPS_POLICY,
    UrlPolicyError,
    host_policy,
    local_json_request,
    local_service_url,
    read_bounded,
    safe_urlopen,
    validate_url,
)


def _resolver(address: str):
    def resolve(_host, port, *, type):
        return [(2, type, 6, "", (address, port))]

    return resolve


@pytest.mark.parametrize(
    "url",
    [
        "file:///C:/Windows/win.ini",
        "http://127.0.0.1/admin",
        "https://10.0.0.5/metadata",
        "https://user:secret@example.com/x",
        "https://example.com/x#fragment",
        "https://example.com\\@evil.invalid/x",
    ],
)
def test_public_https_policy_rejects_local_and_ambiguous_destinations(url) -> None:
    with pytest.raises(UrlPolicyError):
        validate_url(url, PUBLIC_HTTPS_POLICY, resolver=_resolver("93.184.216.34"))


def test_public_https_policy_rejects_private_dns_resolution() -> None:
    with pytest.raises(UrlPolicyError, match="public Internet"):
        validate_url(
            "https://example.com/hook",
            PUBLIC_HTTPS_POLICY,
            resolver=_resolver("169.254.169.254"),
        )


def test_host_allowlist_and_loopback_service_are_strict() -> None:
    policy = host_policy("updates", {"api.github.com"})
    assert validate_url(
        "https://api.github.com/repos/a/b",
        policy,
        resolver=_resolver("140.82.112.6"),
    ) == "api.github.com"
    with pytest.raises(UrlPolicyError, match="not allowed"):
        validate_url(
            "https://api.github.com.evil.invalid/repos/a/b",
            policy,
            resolver=_resolver("93.184.216.34"),
        )
    assert local_service_url("http://127.0.0.1:11434", "/api/chat").endswith(
        "/api/chat"
    )
    with pytest.raises(UrlPolicyError, match="loopback"):
        validate_url(
            "http://ollama.internal:11434/api/chat",
            LOCAL_SERVICE_POLICY,
            resolver=_resolver("10.10.10.10"),
        )


def test_response_reader_enforces_declared_and_actual_bounds() -> None:
    response = SimpleNamespace(headers={}, read=lambda _amount: b"12345")
    with pytest.raises(UrlPolicyError, match="size bound"):
        read_bounded(response, 4)
    declared = SimpleNamespace(
        headers={"Content-Length": "999"},
        read=lambda _amount: b"",
    )
    with pytest.raises(UrlPolicyError, match="size bound"):
        read_bounded(declared, 10)


def test_local_json_request_uses_bounded_loopback_transport(monkeypatch) -> None:
    captured = {}

    class Response:
        headers = {"Content-Length": "11"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, amount):
            assert amount == 1025
            return b'{"ok":true}'

    def fake_open(request, *, policy, timeout):
        captured.update(request=request, policy=policy, timeout=timeout)
        return Response()

    monkeypatch.setattr("angerona.core.url_policy.safe_urlopen", fake_open)
    result = local_json_request(
        "http://127.0.0.1:11434",
        "/api/generate",
        payload={"prompt": "safe"},
        timeout=7,
        response_maximum=1024,
        policy=OLLAMA_SERVICE_POLICY,
    )

    assert result == {"ok": True}
    assert captured["request"].get_method() == "POST"
    assert b'"prompt":"safe"' in captured["request"].data
    assert captured["policy"] is OLLAMA_SERVICE_POLICY
    assert captured["timeout"] == 7


def test_local_json_request_rejects_oversized_or_non_object_payload() -> None:
    with pytest.raises(UrlPolicyError, match="size bound"):
        local_json_request(
            "http://127.0.0.1:11434",
            "/api/generate",
            payload={"prompt": "x" * 100},
            request_maximum=8,
        )
    with pytest.raises(TypeError, match="object"):
        local_json_request(  # type: ignore[arg-type]
            "http://127.0.0.1:11434",
            "/api/generate",
            payload=["not", "an", "object"],
        )


def test_local_json_request_supports_delete_with_bounded_json(monkeypatch) -> None:
    captured = {}

    class Response:
        headers = {"Content-Length": "11"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _amount):
            return b'{"ok":true}'

    def fake_open(request, *, policy, timeout):
        captured.update(request=request, policy=policy, timeout=timeout)
        return Response()

    monkeypatch.setattr("angerona.core.url_policy.safe_urlopen", fake_open)
    result = local_json_request(
        "http://127.0.0.1:11434",
        "/api/delete",
        method="DELETE",
        payload={"model": "angerona-test:v1"},
    )
    assert result == {"ok": True}
    assert captured["request"].get_method() == "DELETE"
    assert captured["request"].data == b'{"model":"angerona-test:v1"}'


def test_local_transport_pins_one_resolution_and_disables_inherited_proxy(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}
    resolutions = 0

    def resolve(_host, port, **kwargs):
        nonlocal resolutions
        resolutions += 1
        return [(socket.AF_INET, kwargs["type"], 6, "", ("127.0.0.1", port))]

    class Opener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return SimpleNamespace()

    def build_opener(*handlers):
        captured["handlers"] = handlers
        return Opener()

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")

    request = urllib.request.Request("http://localhost:11434/healthz")
    safe_urlopen(request, policy=LOCAL_SERVICE_POLICY, timeout=3)

    assert resolutions == 1
    opened = captured["request"]
    assert isinstance(opened, urllib.request.Request)
    assert urlsplit(opened.full_url).hostname == "127.0.0.1"
    proxies = [
        handler for handler in captured["handlers"]
        if isinstance(handler, urllib.request.ProxyHandler)
    ]
    assert len(proxies) == 1
    assert proxies[0].proxies == {}


def test_ollama_policy_attests_custom_port_but_unrelated_local_service_does_not(
    monkeypatch,
) -> None:
    from angerona.core import ollama_lifecycle

    attested: list[str] = []
    monkeypatch.setattr(
        ollama_lifecycle,
        "attest_ollama_service",
        lambda host: attested.append(host) or object(),
    )

    class Opener:
        def open(self, _request, timeout):
            assert timeout == 1
            return SimpleNamespace()

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_handlers: Opener())
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **kwargs: [
            (socket.AF_INET, kwargs["type"], 6, "", ("127.0.0.1", port))
        ],
    )

    safe_urlopen(
        "http://localhost:23145/api/chat",
        policy=LOCAL_SERVICE_POLICY,
        timeout=1,
    )
    safe_urlopen(
        "http://localhost:23146/healthz",
        policy=LOCAL_SERVICE_POLICY,
        timeout=1,
    )

    assert attested == ["http://localhost:23145"]


def test_ollama_policy_refuses_non_ollama_route_before_connection(monkeypatch) -> None:
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_handlers: (_ for _ in ()).throw(AssertionError("must not connect")),
    )
    with pytest.raises(UrlPolicyError, match="Ollama API path"):
        safe_urlopen(
            "http://127.0.0.1:11434/not-ollama",
            policy=OLLAMA_SERVICE_POLICY,
            timeout=1,
        )
