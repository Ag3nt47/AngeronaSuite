"""Dependency-free Corelight Community-ID v1 flow correlation.

Community-ID is an interoperability identifier, not a security digest.  Version
1 deliberately specifies SHA-1; ``usedforsecurity=False`` makes that purpose
explicit to Python and static-analysis tooling.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import struct

_PROTOCOLS = {"tcp": 6, "udp": 17, "sctp": 132}
_PROTOCOL_NUMBERS = frozenset(_PROTOCOLS.values())
_MAX_IP_TEXT = 64


def _ip_bytes(value: object) -> bytes | None:
    if not isinstance(value, str) or not value or len(value) > _MAX_IP_TEXT:
        return None
    # Refuse ambiguous whitespace and IPv6 zone identifiers.  A Community-ID
    # represents an IP flow tuple, not an interface-scoped display string.
    if value != value.strip() or "%" in value:
        return None
    try:
        return ipaddress.ip_address(value).packed
    except ValueError:
        return None


def _port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not 0 <= value <= 65_535:
        return None
    return value


def _protocol_number(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value in _PROTOCOL_NUMBERS else None
    if isinstance(value, str) and 0 < len(value) <= 8:
        return _PROTOCOLS.get(value.casefold())
    return None


def community_id_v1(
    source_ip: object,
    destination_ip: object,
    source_port: object,
    destination_port: object,
    protocol: object,
    *,
    seed: int = 0,
) -> str:
    """Return a direction-invariant Community-ID v1, or ``""`` if invalid.

    The supported tuple families are TCP, UDP and SCTP over IPv4 or IPv6.  All
    components are validated before packing, and mixed address families,
    unsupported protocols, non-integral ports and out-of-range seeds fail
    closed with the empty identifier prescribed by the Community-ID spec.
    """
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 65_535:
        return ""
    source = _ip_bytes(source_ip)
    destination = _ip_bytes(destination_ip)
    sport = _port(source_port)
    dport = _port(destination_port)
    proto = _protocol_number(protocol)
    if (
        source is None
        or destination is None
        or len(source) != len(destination)
        or sport is None
        or dport is None
        or proto is None
    ):
        return ""

    if (source, sport) > (destination, dport):
        source, destination, sport, dport = destination, source, dport, sport
    payload = (
        struct.pack("!H", seed)
        + source
        + destination
        + struct.pack("!BBHH", proto, 0, sport, dport)
    )
    digest = hashlib.sha1(payload, usedforsecurity=False).digest()  # nosec B324
    return "1:" + base64.b64encode(digest).decode("ascii")


__all__ = ["community_id_v1"]
