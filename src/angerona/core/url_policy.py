"""Central URL and response-size boundaries for optional network features.

Angerona is local-first. Local model calls must remain loopback-only, while an
explicitly enabled external integration may use public HTTPS but must not become
an SSRF path into localhost, private networks, link-local services, or files.
Every redirect is revalidated under the same policy.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlsplit


class UrlPolicyError(ValueError):
    """Raised when a destination violates its declared network boundary."""


Resolver = Callable[..., list[tuple]]


@dataclass(frozen=True)
class UrlPolicy:
    name: str
    schemes: frozenset[str]
    allowed_hosts: frozenset[str] = frozenset()
    allow_subdomains: bool = False
    loopback_only: bool = False
    resolve_addresses: bool = True
    max_url_chars: int = 4096


LOCAL_SERVICE_POLICY = UrlPolicy(
    name="local service",
    schemes=frozenset({"http", "https"}),
    loopback_only=True,
)

PUBLIC_HTTPS_POLICY = UrlPolicy(
    name="operator-approved public HTTPS",
    schemes=frozenset({"https"}),
)


def _normalized_host(host: str) -> str:
    try:
        return host.rstrip(".").encode("idna").decode("ascii").casefold()
    except (UnicodeError, ValueError) as exc:
        raise UrlPolicyError("destination hostname is invalid") from exc


def _host_allowed(host: str, policy: UrlPolicy) -> bool:
    if not policy.allowed_hosts:
        return True
    if host in policy.allowed_hosts:
        return True
    return policy.allow_subdomains and any(
        host.endswith("." + allowed) for allowed in policy.allowed_hosts
    )


def _resolved_addresses(
    host: str,
    port: int,
    resolver: Resolver,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        records = resolver(host, port, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror) as exc:
        raise UrlPolicyError("destination hostname could not be resolved") from exc
    addresses = []
    for record in records:
        try:
            addresses.append(ipaddress.ip_address(record[4][0]))
        except (IndexError, TypeError, ValueError):
            raise UrlPolicyError("destination resolution returned invalid data") from None
    if not addresses:
        raise UrlPolicyError("destination hostname resolved to no addresses")
    return tuple(dict.fromkeys(addresses))


def validate_url(
    url: str,
    policy: UrlPolicy,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> str:
    """Validate one absolute URL and return its normalized hostname."""
    if (
        not isinstance(url, str)
        or not 1 <= len(url) <= policy.max_url_chars
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in url)
        or "\\" in url
    ):
        raise UrlPolicyError("destination URL is malformed or oversized")
    parsed = urlsplit(url)
    scheme = parsed.scheme.casefold()
    if scheme not in policy.schemes:
        raise UrlPolicyError(
            f"{policy.name} allows only {', '.join(sorted(policy.schemes))} URLs"
        )
    if not parsed.netloc or parsed.hostname is None:
        raise UrlPolicyError("destination URL has no hostname")
    if parsed.username is not None or parsed.password is not None:
        raise UrlPolicyError("credentials are forbidden in destination URLs")
    if parsed.fragment:
        raise UrlPolicyError("destination URL fragments are not permitted")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UrlPolicyError("destination port is invalid") from exc
    host = _normalized_host(parsed.hostname)
    if not _host_allowed(host, policy):
        raise UrlPolicyError(f"destination host is not allowed by {policy.name}")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if policy.resolve_addresses:
        addresses = _resolved_addresses(host, port, resolver)
    elif literal is not None:
        addresses = (literal,)
    else:
        addresses = ()

    if policy.loopback_only:
        if not addresses or any(not address.is_loopback for address in addresses):
            raise UrlPolicyError("local service destination must resolve only to loopback")
    else:
        # is_global excludes loopback, private, link-local, multicast,
        # unspecified, documentation, and other special-purpose ranges.
        if addresses and any(not address.is_global for address in addresses):
            raise UrlPolicyError("external destination resolved outside the public Internet")
        if literal is not None and not literal.is_global:
            raise UrlPolicyError("external destination is not globally routable")
    return host


def local_service_url(base: str, path: str = "") -> str:
    """Join a loopback-only service base with one absolute API path."""
    validate_url(base, LOCAL_SERVICE_POLICY)
    parsed = urlsplit(base)
    if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise UrlPolicyError("local service base URL must not include a path or query")
    if not isinstance(path, str) or (path and not path.startswith("/")):
        raise UrlPolicyError("local service API path must start with '/'")
    if "?" in path or "#" in path or "\\" in path:
        raise UrlPolicyError("local service API path is invalid")
    return base.rstrip("/") + path


class _PolicyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, policy: UrlPolicy) -> None:
        super().__init__()
        self._policy = policy

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl, self._policy)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_urlopen(
    request_or_url,
    *,
    policy: UrlPolicy,
    timeout: float,
):
    """Open a validated URL and apply the same policy to every redirect."""
    url = (
        request_or_url.full_url
        if isinstance(request_or_url, urllib.request.Request)
        else str(request_or_url)
    )
    validate_url(url, policy)
    opener = urllib.request.build_opener(_PolicyRedirectHandler(policy))
    return opener.open(request_or_url, timeout=timeout)


def read_bounded(response, maximum: int = 4 * 1024 * 1024) -> bytes:
    """Read a network response with a strict in-memory size ceiling."""
    if not 1 <= int(maximum) <= 64 * 1024 * 1024:
        raise ValueError("response bound is invalid")
    declared = response.headers.get("Content-Length") if response.headers else None
    if declared:
        try:
            declared_size = int(declared)
        except ValueError as exc:
            raise UrlPolicyError("network response length is invalid") from exc
        if declared_size < 0:
            raise UrlPolicyError("network response length is invalid")
        if declared_size > maximum:
            raise UrlPolicyError("network response exceeds its size bound")
    data = response.read(int(maximum) + 1)
    if len(data) > maximum:
        raise UrlPolicyError("network response exceeds its size bound")
    return data


def host_policy(
    name: str,
    hosts: Iterable[str],
    *,
    allow_subdomains: bool = False,
) -> UrlPolicy:
    """Build a public-HTTPS allowlist policy from normalized hostnames."""
    normalized = frozenset(_normalized_host(str(host)) for host in hosts)
    if not normalized:
        raise ValueError("host policy requires at least one destination")
    return UrlPolicy(
        name=name,
        schemes=frozenset({"https"}),
        allowed_hosts=normalized,
        allow_subdomains=allow_subdomains,
    )


__all__ = [
    "LOCAL_SERVICE_POLICY",
    "PUBLIC_HTTPS_POLICY",
    "UrlPolicy",
    "UrlPolicyError",
    "host_policy",
    "local_service_url",
    "read_bounded",
    "safe_urlopen",
    "validate_url",
]
