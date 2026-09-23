"""Inert regressions for attesting the exact local AI connection endpoint."""

from __future__ import annotations

import socket
import urllib.request
from types import SimpleNamespace
from urllib.parse import urlsplit

import psutil
import pytest

from angerona.core import ollama_lifecycle, url_policy


def _listener(address: str, pid: int, port: int = 11434) -> SimpleNamespace:
    return SimpleNamespace(status="LISTEN", laddr=(address, port), pid=pid)


@pytest.fixture
def endpoint_fixture(tmp_path, monkeypatch):
    """Replace all process/socket authority with fixed, local test records."""
    image = tmp_path / "ollama.exe"
    image.write_bytes(b"inert-test-image")
    processes = []

    def process(pid):
        processes.append(pid)
        return SimpleNamespace(
            create_time=lambda: 1234.5,
            exe=lambda: str(image),
            is_running=lambda: True,
        )

    monkeypatch.setattr(psutil, "Process", process)
    monkeypatch.setattr(
        ollama_lifecycle, "_trusted_ollama_image", lambda path: path == image
    )
    return processes


@pytest.mark.parametrize(
    ("host", "other_address"),
    (("http://127.0.0.1:11434", "::1"), ("http://[::1]:11434", "127.0.0.1")),
)
def test_opposite_family_listener_cannot_attest_requested_endpoint(
    monkeypatch, endpoint_fixture, host, other_address
):
    monkeypatch.setattr(
        ollama_lifecycle, "_ollama_tcp_listeners", lambda: [_listener(other_address, 101)]
    )

    with pytest.raises(ollama_lifecycle.OllamaAttestationError):
        ollama_lifecycle.attest_ollama_service(host)

    assert endpoint_fixture == []


@pytest.mark.parametrize(
    ("host", "trusted_address", "wildcard"),
    (
        ("http://127.0.0.1:11434", "::1", "0.0.0.0"),
        ("http://[::1]:11434", "127.0.0.1", "::"),
        ("http://127.0.0.1:11434", "127.0.0.1", "0.0.0.0"),
        ("http://[::1]:11434", "::1", "::"),
        # The socket table does not prove whether :: uses IPV6_V6ONLY.
        ("http://127.0.0.1:11434", "127.0.0.1", "::"),
    ),
)
def test_wildcard_affecting_endpoint_cannot_hide_behind_trusted_listener(
    monkeypatch, endpoint_fixture, host, trusted_address, wildcard
):
    monkeypatch.setattr(
        ollama_lifecycle,
        "_ollama_tcp_listeners",
        lambda: [_listener(trusted_address, 101), _listener(wildcard, 202)],
    )

    with pytest.raises(ollama_lifecycle.OllamaAttestationError):
        ollama_lifecycle.attest_ollama_service(host)

    assert endpoint_fixture == []


@pytest.mark.parametrize(
    ("host", "requested_address", "other_address"),
    (
        ("http://127.0.0.1:11434", "127.0.0.1", "::1"),
        ("http://[::1]:11434", "::1", "127.0.0.1"),
    ),
)
def test_trusted_exact_endpoint_is_allowed_with_unrelated_listeners(
    monkeypatch, endpoint_fixture, host, requested_address, other_address
):
    monkeypatch.setattr(
        ollama_lifecycle,
        "_ollama_tcp_listeners",
        lambda: [
            _listener(requested_address, 101),
            _listener(other_address, 202),
            _listener("::", 303, port=11435),
        ],
    )

    proof = ollama_lifecycle.attest_ollama_service(host)

    assert proof.pid == 101
    assert endpoint_fixture == [101]


@pytest.mark.parametrize("as_request", (False, True))
@pytest.mark.parametrize(
    "policy", (url_policy.OLLAMA_SERVICE_POLICY, url_policy.LOCAL_SERVICE_POLICY)
)
def test_transport_attests_same_pin_it_connects_to(monkeypatch, as_request, policy):
    resolutions = []
    attested = []
    opened = []
    result = object()

    def resolve(host, port, **kwargs):
        resolutions.append((host, port))
        # A second lookup deliberately selects another, still-loopback service.
        if len(resolutions) == 1:
            return [(socket.AF_INET, kwargs["type"], 6, "", ("127.0.0.1", port))]
        return [(socket.AF_INET6, kwargs["type"], 6, "", ("::1", port, 0, 0))]

    def attest(host):
        # Mirror attestation's URL canonicalization without inspecting any host
        # processes. A numeric connection target must not resolve localhost again.
        attested.append(url_policy.local_service_url(host))

    class Opener:
        def open(self, request, timeout):
            opened.append(request)
            assert timeout == 2
            return result

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(ollama_lifecycle, "attest_ollama_service", attest)
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_handlers: Opener())
    request = "http://localhost:11434/api/chat"
    if as_request:
        request = urllib.request.Request(
            request,
            data=b'{"model":"inert-fixture"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )

    assert url_policy.safe_urlopen(request, policy=policy, timeout=2) is result

    assert resolutions == [("localhost", 11434)]
    assert attested == ["http://127.0.0.1:11434"]
    transmitted = opened[0]
    target = transmitted.full_url if as_request else transmitted
    assert target == "http://127.0.0.1:11434/api/chat"
    assert urlsplit(target).netloc == urlsplit(attested[0]).netloc
    if as_request:
        assert transmitted.get_method() == "POST"
        assert transmitted.data == b'{"model":"inert-fixture"}'
        assert transmitted.get_header("Content-type") == "application/json"
