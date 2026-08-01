from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.core.url_policy import (
    LOCAL_SERVICE_POLICY,
    PUBLIC_HTTPS_POLICY,
    UrlPolicyError,
    host_policy,
    local_service_url,
    read_bounded,
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
