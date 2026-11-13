from __future__ import annotations

import http.client
import io
import ipaddress
import socket
import ssl
import urllib.request
from types import SimpleNamespace

import pytest

from angerona.core import url_policy


@pytest.fixture(autouse=True)
def inert_network(monkeypatch):
    def resolve(_host, port, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    def refused_socket(*_args, **_kwargs):
        raise AssertionError("A test attempted to open a real socket")

    validate = url_policy.validate_url
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", refused_socket)
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {})
    monkeypatch.setattr(url_policy, "validate_url", lambda value, policy, **kwargs:
        validate(value, policy, resolver=kwargs.get("resolver", resolve)))


@pytest.mark.parametrize("destination", [
    "https://other.example/end", "https://api.example:444/end",
])
def test_cross_origin_redirect_drops_known_and_custom_secrets(destination):
    request = urllib.request.Request("https://api.example/start", headers={
        "Authorization": "Bearer inert", "X-Api-Key": "inert",
        "X-Custom-Integration-Secret": "inert", "Cookie": "inert=1",
        "Host": "api.example", "Accept": "application/json", "User-Agent": "test",
    })
    handler = url_policy._PolicyRedirectHandler(url_policy.PUBLIC_HTTPS_POLICY)

    redirected = handler.redirect_request(request, None, 302, "Found", {}, destination)

    assert {key.lower(): value for key, value in redirected.header_items()} == {
        "accept": "application/json", "user-agent": "test",
    }
    assert request.get_header("Authorization") == "Bearer inert"


def test_same_origin_default_port_redirect_preserves_integration_headers():
    request = urllib.request.Request("https://api.example/start", headers={
        "Authorization": "Bearer inert", "X-Custom-Integration-Secret": "inert",
    })
    handler = url_policy._PolicyRedirectHandler(url_policy.PUBLIC_HTTPS_POLICY)

    redirected = handler.redirect_request(
        request, None, 302, "Found", {}, "https://API.EXAMPLE:443/end")

    assert redirected.get_header("Authorization") == "Bearer inert"
    assert redirected.get_header("X-custom-integration-secret") == "inert"


def test_every_redirect_rechecks_private_destination():
    handler = url_policy._PolicyRedirectHandler(url_policy.PUBLIC_HTTPS_POLICY)
    request = urllib.request.Request("https://api.example/start")
    redirected = handler.redirect_request(
        request, None, 302, "Found", {}, "https://other.example/end")

    with pytest.raises(url_policy.UrlPolicyError):
        handler.redirect_request(
            redirected, None, 302, "Found", {}, "https://127.0.0.1/private")


@pytest.mark.parametrize("url", ["https://224.0.0.1/", "https://[ff0e::1]/"])
def test_public_transport_refuses_multicast_before_connection(url):
    with pytest.raises(url_policy.UrlPolicyError):
        url_policy.safe_urlopen(url, policy=url_policy.PUBLIC_HTTPS_POLICY, timeout=3)


class _Socket:
    def __init__(self):
        self.peer = None
        self.closed = False

    def settimeout(self, value):
        assert 0 < value <= 3

    def connect(self, peer):
        self.peer = peer

    def getpeername(self):
        return self.peer

    def setsockopt(self, *_args):
        pass

    def close(self):
        self.closed = True


@pytest.mark.parametrize("address,family", [
    ("93.184.216.34", socket.AF_INET),
    ("2606:4700:4700::1111", socket.AF_INET6),
])
def test_public_connection_pins_numeric_peer_and_retains_tls_hostname(monkeypatch, address, family):
    resolutions = []
    sockets = []
    tls_names = []

    def resolve(host, port, **_kwargs):
        resolutions.append(host)
        if len(resolutions) != 1:
            raise AssertionError("The connection tried to resolve the hostname again")
        return [(family, socket.SOCK_STREAM, 6, "", (address, port))]

    def make_socket(selected_family, _kind):
        assert selected_family == family
        value = _Socket()
        sockets.append(value)
        return value

    def wrap(sock, *, server_hostname):
        tls_names.append(server_hostname)
        return sock

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", make_socket)
    request = urllib.request.Request("https://api.example:8443/private")
    factory = url_policy._public_connection_factory(
        request, url_policy.PUBLIC_HTTPS_POLICY, http.client.HTTPSConnection)
    connection = factory("api.example:8443", timeout=3, context=SimpleNamespace(wrap_socket=wrap))
    try:
        connection.connect()
        assert connection.host == "api.example"
        assert sockets[0].peer == (address, 8443)
        assert tls_names == ["api.example"]
        assert resolutions == ["api.example"]
    finally:
        connection.close()
    assert sockets[0].closed


def test_default_public_tls_context_keeps_certificate_and_hostname_checks():
    handler = url_policy._PublicHTTPSHandler(url_policy.PUBLIC_HTTPS_POLICY)
    assert handler._context.verify_mode == ssl.CERT_REQUIRED
    assert handler._context.check_hostname is True


def test_numeric_peer_mismatch_closes_socket(monkeypatch):
    sock = _Socket()
    sock.getpeername = lambda: ("127.0.0.1", 443)
    monkeypatch.setattr(socket, "socket", lambda *_args: sock)

    with pytest.raises(url_policy.UrlPolicyError, match="connected peer"):
        url_policy._public_socket((ipaddress.ip_address("93.184.216.34"),), 443, 3, None)

    assert sock.closed


def test_configured_proxy_is_explicitly_refused_before_socket_creation(monkeypatch):
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {
        "https": "http://proxy.example:3128",
    })
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda _host: False)

    with pytest.raises(url_policy.UrlPolicyError, match="configured proxy"):
        url_policy.safe_urlopen(
            "https://api.example/check", policy=url_policy.PUBLIC_HTTPS_POLICY, timeout=3)


def test_connection_handler_preserves_origin_host_header(monkeypatch):
    sent = []

    class Socket(_Socket):
        def sendall(self, data):
            sent.append(bytes(data))

        def makefile(self, _mode):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    monkeypatch.setattr(socket, "socket", lambda *_args: Socket())
    policy = url_policy.UrlPolicy("inert HTTP", frozenset({"http"}))

    with url_policy.safe_urlopen("http://api.example:8080/check", policy=policy, timeout=3) as response:
        assert response.status == 200

    assert b"Host: api.example:8080\r\n" in b"".join(sent)
    assert b"Host: 93.184.216.34" not in b"".join(sent)
