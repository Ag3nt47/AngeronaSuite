"""Zero-trust evaluation for directly attached Wi-Fi and Ethernet paths.

The evaluator in this file is deliberately pure: it performs no discovery,
network I/O, firewall changes, or route changes.  Callers provide a bounded
snapshot and an optional prior tokenized baseline.  The result never retains
raw SSIDs, BSSIDs, interface names, gateways, DHCP servers, or DNS servers.

An operating-system "private" network category and a private IP range are
context, not authentication.  Every active non-loopback physical path is
therefore ``untrusted`` unless a separately verified Personal Sentinel Gateway
attestation labels only that path ``gateway-attested``.  Even then, resources
reachable through the gateway are not implicitly trusted.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import secrets
import stat
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence

from angerona.core.independent_high_water import (
    NETWORK_DOMAIN,
    ZERO_DIGEST,
    HighWaterAssessment,
    IndependentHighWater,
    advance_high_water,
    assess_high_water,
    state_pair_digest,
    validate_installation_id,
)


MAX_LINKS = 64
MAX_ROUTES_PER_LINK = 16
MAX_VALUES_PER_FIELD = 32
MAX_IDENTIFIER_CHARS = 512
MAX_BASELINE_BYTES = 128 * 1024

_LINK_KINDS = frozenset({"wifi", "ethernet", "other"})
_PROFILES = frozenset({"public", "private", "domain", "unknown"})
_FAMILIES = frozenset({"ipv4", "ipv6"})
_GATEWAY_LABELS = frozenset({"untrusted", "gateway-attested"})
COLLECTION_SOURCES = frozenset({
    "interfaces",
    "addresses",
    "dns",
    "dhcp",
    "routes-ipv4",
    "routes-ipv6",
    "neighbors",
    "profile",
    "wireless",
})
REQUIRED_GLOBAL_COLLECTION = frozenset({
    "interfaces", "addresses", "routes-ipv4", "routes-ipv6"
})
REQUIRED_LINK_COLLECTION = frozenset({
    "addresses", "dns", "dhcp", "routes-ipv4", "routes-ipv6", "neighbors", "profile"
})
_BASELINE_DOMAIN = b"angerona/network-trust-baseline/v1\x00"
_PRIVACY_DOMAIN = b"angerona/network-trust-privacy/v1\x00"
_ENROLLMENT_DOMAIN = b"angerona/network-trust-enrollment/v1\x00"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_HEX = frozenset("0123456789abcdef")

_WEAK_WIFI_MARKERS = (
    "open",
    "none",
    "wep",
    "wpa-personal",
    "wpa-psk",
    "tkip",
)
_STRONG_WIFI_MARKERS = (
    "wpa2",
    "wpa3",
    "sae",
    "owe",
    "802.1x",
    "enterprise",
    "ccmp",
    "aes",
)


def _bounded_text(value: object, field: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    if not allow_empty and not value:
        raise ValueError(f"{field} cannot be empty")
    if len(value) > MAX_IDENTIFIER_CHARS or "\x00" in value:
        raise ValueError(f"{field} exceeds its bound")
    return value


def _bounded_values(values: Sequence[str], field: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field} must be a sequence")
    result = tuple(_bounded_text(item, field, allow_empty=False) for item in values)
    if len(result) > MAX_VALUES_PER_FIELD:
        raise ValueError(f"{field} exceeds its item bound")
    return result


def _privacy_token(key: bytes, label: bytes, value: str) -> str:
    canonical = value.strip().casefold().encode("utf-8", "strict")
    return "tok_" + hmac.new(
        key, label + b"\0" + canonical, hashlib.sha256
    ).hexdigest()[:24]


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _path_unsafe(path: Path) -> bool:
    if not path.is_absolute():
        return True
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return True
        if _is_link_or_reparse(info):
            return True
    return False


def _safe_read(path: Path, maximum: int) -> bytes:
    if _path_unsafe(path):
        raise OSError("network state path is link/reparse-backed")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise OSError("network state is not an ordinary bounded file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            getattr(before, "st_dev", None), getattr(before, "st_ino", None), before.st_size
        ) != (
            getattr(opened, "st_dev", None), getattr(opened, "st_ino", None), opened.st_size
        ):
            raise OSError("network state identity changed while opening")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum:
            raise OSError("network state exceeds its read bound")
    finally:
        os.close(descriptor)
    after = path.lstat()
    if _is_link_or_reparse(after) or (
        getattr(before, "st_dev", None), getattr(before, "st_ino", None), before.st_size,
        getattr(before, "st_mtime_ns", None), getattr(before, "st_ctime_ns", None),
    ) != (
        getattr(after, "st_dev", None), getattr(after, "st_ino", None), after.st_size,
        getattr(after, "st_mtime_ns", None), getattr(after, "st_ctime_ns", None),
    ):
        raise OSError("network state changed during read")
    return payload


def _secure_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if _path_unsafe(path.parent) or (path.exists() and _path_unsafe(path)):
        raise OSError("network state destination is link/reparse-backed")
    temporary = path.with_name(
        f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
    )
    descriptor = os.open(
        str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        after = path.lstat()
        if not stat.S_ISREG(after.st_mode) or _is_link_or_reparse(after):
            raise OSError("network state destination changed file type")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def load_network_purpose_keys(
    data_root: Path | str,
    *,
    master_key: bytes | None = None,
) -> tuple[bytes, bytes, bytes] | None:
    """Derive stable, purpose-separated privacy/baseline/enrollment keys."""
    value = master_key
    if value is None:
        try:
            raw = _safe_read(Path(data_root) / "bus.key", 128)
            value = bytes.fromhex(raw.decode("ascii", "strict").strip())
        except (OSError, UnicodeError, ValueError):
            return None
    if not isinstance(value, bytes) or len(value) != 32:
        return None
    return (
        hmac.new(value, _PRIVACY_DOMAIN, hashlib.sha256).digest(),
        hmac.new(value, _BASELINE_DOMAIN, hashlib.sha256).digest(),
        hmac.new(value, _ENROLLMENT_DOMAIN, hashlib.sha256).digest(),
    )


@dataclass(frozen=True)
class DefaultRouteObservation:
    """One observed default route.  ``gateway`` remains raw only in the input."""

    gateway: str
    family: str = "ipv4"
    metric: int | None = None
    selected: bool = False
    attested: bool = False
    interface_index: int | None = None

    def __post_init__(self) -> None:
        gateway = _bounded_text(self.gateway, "route gateway", allow_empty=False)
        try:
            address = ipaddress.ip_address(gateway.split("%", 1)[0])
        except ValueError as exc:
            raise ValueError("route gateway must be an IP address") from exc
        family = self.family.strip().casefold() if isinstance(self.family, str) else ""
        if family not in _FAMILIES:
            raise ValueError("route family must be ipv4 or ipv6")
        if (family == "ipv4") != (address.version == 4):
            raise ValueError("route family does not match its gateway")
        if self.metric is not None and (
            type(self.metric) is not int or not 0 <= self.metric <= 2**31 - 1
        ):
            raise ValueError("route metric is invalid")
        if type(self.selected) is not bool or type(self.attested) is not bool:
            raise ValueError("route selection/attestation flags must be boolean")
        if self.attested and not self.selected:
            raise ValueError("only a selected default route can be attested")
        if self.interface_index is not None and (
            type(self.interface_index) is not int
            or not 0 <= self.interface_index <= 2**31 - 1
        ):
            raise ValueError("route interface index is invalid")
        object.__setattr__(self, "family", family)


@dataclass(frozen=True)
class NetworkLinkObservation:
    """Bounded raw input for one local interface.

    ``gateway_attestation`` must come from an explicit, independently verified
    attestation client.  It changes only the path label; it cannot grant trust
    to endpoints or response authority.
    """

    interface_id: str
    kind: str
    interface_index: int | None = None
    active: bool = True
    loopback: bool = False
    interface_epoch: str = ""
    ssid: str = ""
    bssid: str = ""
    wifi_security: str = "unknown"
    dns_servers: tuple[str, ...] = ()
    dhcp_server: str = ""
    default_routes: tuple[DefaultRouteObservation, ...] = ()
    gateway_identities: tuple[str, ...] = ()
    profile_category: str = "unknown"
    gateway_attestation: str = "untrusted"
    collection_complete: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _bounded_text(self.interface_id, "interface ID", allow_empty=False)
        kind = self.kind.strip().casefold() if isinstance(self.kind, str) else ""
        if kind not in _LINK_KINDS:
            raise ValueError("unsupported interface kind")
        if type(self.active) is not bool or type(self.loopback) is not bool:
            raise ValueError("interface activity flags must be boolean")
        if self.interface_index is not None and (
            type(self.interface_index) is not int
            or not 0 <= self.interface_index <= 2**31 - 1
        ):
            raise ValueError("interface index is invalid")
        _bounded_text(self.interface_epoch, "interface epoch")
        _bounded_text(self.ssid, "SSID")
        _bounded_text(self.bssid, "BSSID")
        _bounded_text(self.wifi_security, "Wi-Fi security", allow_empty=False)
        dns = _bounded_values(self.dns_servers, "DNS servers")
        dhcp = _bounded_text(self.dhcp_server, "DHCP server")
        routes = tuple(self.default_routes)
        if len(routes) > MAX_ROUTES_PER_LINK or any(
            not isinstance(route, DefaultRouteObservation) for route in routes
        ):
            raise ValueError("default routes exceed their bound")
        gateways = _bounded_values(self.gateway_identities, "gateway identities")
        profile = (
            self.profile_category.strip().casefold()
            if isinstance(self.profile_category, str)
            else ""
        )
        if profile not in _PROFILES:
            raise ValueError("unsupported network profile category")
        attestation = (
            self.gateway_attestation.strip().casefold()
            if isinstance(self.gateway_attestation, str)
            else ""
        )
        if attestation not in _GATEWAY_LABELS:
            raise ValueError("unsupported gateway attestation label")
        completeness = tuple(self.collection_complete)
        if (
            len(completeness) > len(COLLECTION_SOURCES)
            or len(set(completeness)) != len(completeness)
            or any(item not in COLLECTION_SOURCES for item in completeness)
        ):
            raise ValueError("network collection completeness is invalid")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "dns_servers", dns)
        object.__setattr__(self, "dhcp_server", dhcp)
        object.__setattr__(self, "default_routes", routes)
        object.__setattr__(self, "gateway_identities", gateways)
        object.__setattr__(self, "profile_category", profile)
        object.__setattr__(self, "gateway_attestation", attestation)
        object.__setattr__(self, "collection_complete", tuple(sorted(completeness)))


@dataclass(frozen=True)
class NetworkSnapshot:
    links: tuple[NetworkLinkObservation, ...]
    observed_at: float = 0.0
    collection_complete: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        links = tuple(self.links)
        if len(links) > MAX_LINKS:
            raise ValueError("network snapshot exceeds its interface bound")
        if any(not isinstance(link, NetworkLinkObservation) for link in links):
            raise ValueError("network snapshot contains an invalid interface")
        if not isinstance(self.observed_at, (int, float)) or isinstance(
            self.observed_at, bool
        ) or not math.isfinite(float(self.observed_at)):
            raise ValueError("network observation time is invalid")
        interface_ids = [link.interface_id for link in links]
        if len(set(interface_ids)) != len(interface_ids):
            raise ValueError("network snapshot contains duplicate interfaces")
        completeness = tuple(self.collection_complete)
        if (
            len(completeness) > len(COLLECTION_SOURCES)
            or len(set(completeness)) != len(completeness)
            or any(item not in COLLECTION_SOURCES for item in completeness)
        ):
            raise ValueError("snapshot collection completeness is invalid")
        object.__setattr__(self, "links", links)
        object.__setattr__(self, "observed_at", float(self.observed_at))
        object.__setattr__(self, "collection_complete", tuple(sorted(completeness)))


@dataclass(frozen=True)
class _PathFingerprint:
    path_token: str
    kind: str
    epoch_token: str
    network_token: str
    dns_tokens: tuple[str, ...]
    dhcp_token: str
    route_tokens: tuple[tuple[str, str, int | None, bool, bool], ...]
    gateway_tokens: tuple[str, ...]
    profile_category: str
    trust_label: str
    collection_complete: tuple[str, ...]


@dataclass(frozen=True)
class NetworkTrustBaseline:
    """Privacy-safe prior state accepted by :func:`evaluate_network_trust`."""

    paths: tuple[_PathFingerprint, ...] = ()
    pending_path_tokens: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        paths = tuple(self.paths)
        if len(paths) > MAX_LINKS or any(
            not isinstance(path, _PathFingerprint) for path in paths
        ):
            raise ValueError("network trust baseline exceeds its bound")
        tokens = [path.path_token for path in paths]
        if len(tokens) != len(set(tokens)):
            raise ValueError("network trust baseline contains duplicate paths")
        pending = tuple(self.pending_path_tokens)
        if (
            len(pending) > MAX_LINKS
            or any(not isinstance(token, str) for token in pending)
            or len(pending) != len(set(pending))
            or any(token not in tokens for token in pending)
        ):
            raise ValueError("network trust pending path set is invalid")
        object.__setattr__(self, "paths", paths)
        object.__setattr__(self, "pending_path_tokens", tuple(sorted(pending)))


@dataclass(frozen=True)
class PathTrust:
    path_token: str
    link_kind: str
    network_token: str
    trust_label: str
    profile_category: str
    attested_route_families: tuple[str, ...] = ()
    telemetry_quality: str = "incomplete"
    endpoint_resources_trusted: bool = False
    response_authorized: bool = False

    def event_details(self) -> dict:
        return {
            "schema": "angerona.network-path-trust.v1",
            "path_token": self.path_token,
            "link_kind": self.link_kind,
            "network_token": self.network_token,
            "trust_label": self.trust_label,
            "profile_category": self.profile_category,
            "attested_route_families": list(self.attested_route_families),
            "telemetry_quality": self.telemetry_quality,
            "endpoint_resources_trusted": False,
            "zero_trust_default": True,
            "local_network_identifiers_omitted": True,
            "response_authorized": False,
            "response_authority": "observe-only",
        }


@dataclass(frozen=True)
class NetworkTrustFinding:
    rule_id: str
    severity: str
    path_token: str
    link_kind: str
    trust_label: str
    reason: str
    evidence: tuple[tuple[str, object], ...] = ()
    recommendations: tuple[str, ...] = ()
    response_authorized: bool = False

    def event_details(self) -> dict:
        return {
            "schema": "angerona.network-trust-finding.v1",
            "finding_type": self.rule_id,
            "path_token": self.path_token,
            "link_kind": self.link_kind,
            "trust_label": self.trust_label,
            "evidence": dict(self.evidence),
            "recommendations": list(self.recommendations),
            "endpoint_resources_trusted": False,
            "local_network_identifiers_omitted": True,
            "response_authorized": False,
            "response_authority": "observe-only",
        }


@dataclass(frozen=True)
class NetworkTrustEvaluation:
    paths: tuple[PathTrust, ...]
    findings: tuple[NetworkTrustFinding, ...]
    baseline: NetworkTrustBaseline
    telemetry_complete: bool = False


def _wifi_security_state(value: str) -> str:
    normalized = "-".join(value.strip().casefold().replace("/", " ").split())
    if not normalized or normalized in {"unknown", "unavailable", "n/a"}:
        return "unknown"
    if any(marker in normalized for marker in _WEAK_WIFI_MARKERS):
        # WPA2/WPA3 strings sometimes contain a generic "WPA-Personal"
        # substring.  A strong generation marker wins unless TKIP is present.
        if "tkip" in normalized or not any(
            marker in normalized for marker in _STRONG_WIFI_MARKERS
        ):
            return "weak"
    if any(marker in normalized for marker in _STRONG_WIFI_MARKERS):
        return "strong"
    return "unknown"


def _fingerprint(link: NetworkLinkObservation, key: bytes) -> _PathFingerprint:
    path_token = _privacy_token(key, b"interface", link.interface_id)
    network_identity = "\0".join((link.ssid, link.bssid))
    network_token = (
        _privacy_token(key, b"wireless-network", network_identity)
        if network_identity.strip("\0")
        else ""
    )
    epoch_token = (
        _privacy_token(key, b"interface-epoch", link.interface_epoch)
        if link.interface_epoch
        else ""
    )
    dns_tokens = tuple(sorted({
        _privacy_token(key, b"dns", value) for value in link.dns_servers
    }))
    dhcp_token = (
        _privacy_token(key, b"dhcp", link.dhcp_server)
        if link.dhcp_server
        else ""
    )
    route_tokens = tuple(sorted({
        (
            route.family,
            _privacy_token(key, b"default-route", route.gateway),
            route.metric,
            route.selected,
            route.attested,
        )
        for route in link.default_routes
    }, key=lambda row: (
        row[0], row[1], -1 if row[2] is None else row[2], row[3], row[4]
    )))
    gateway_tokens = tuple(sorted({
        _privacy_token(key, b"gateway-identity", value)
        for value in link.gateway_identities
    }))
    return _PathFingerprint(
        path_token=path_token,
        kind=link.kind,
        epoch_token=epoch_token,
        network_token=network_token,
        dns_tokens=dns_tokens,
        dhcp_token=dhcp_token,
        route_tokens=route_tokens,
        gateway_tokens=gateway_tokens,
        profile_category=link.profile_category,
        trust_label=link.gateway_attestation,
        collection_complete=link.collection_complete,
    )


def _finding(
    rule_id: str,
    severity: str,
    path: _PathFingerprint,
    reason: str,
    *,
    evidence: Mapping[str, object] | None = None,
    recommendations: tuple[str, ...] = (),
) -> NetworkTrustFinding:
    return NetworkTrustFinding(
        rule_id=rule_id,
        severity=severity,
        path_token=path.path_token,
        link_kind=path.kind,
        trust_label=path.trust_label,
        reason=reason,
        evidence=tuple(sorted((evidence or {}).items())),
        recommendations=recommendations,
    )


def evaluate_network_trust(
    snapshot: NetworkSnapshot,
    privacy_key: bytes,
    previous: NetworkTrustBaseline | None = None,
) -> NetworkTrustEvaluation:
    """Return a deterministic, privacy-safe trust assessment.

    The function is bounded and side-effect free.  It neither consults network
    category/SSID allowlists nor mutates host networking.  Callers may retain
    the returned baseline for the next call; the baseline contains keyed tokens
    only.
    """

    if not isinstance(snapshot, NetworkSnapshot):
        raise ValueError("snapshot must be a NetworkSnapshot")
    if not isinstance(privacy_key, bytes) or len(privacy_key) < 32:
        raise ValueError("privacy key must contain at least 32 bytes")
    if previous is not None and not isinstance(previous, NetworkTrustBaseline):
        raise ValueError("previous state must be a NetworkTrustBaseline")

    active_links = tuple(
        link for link in snapshot.links
        if link.active and not link.loopback and link.kind in {"wifi", "ethernet"}
    )
    observed = tuple(_fingerprint(link, privacy_key) for link in active_links)
    source_by_token = {
        _privacy_token(privacy_key, b"interface", link.interface_id): link
        for link in active_links
    }
    global_complete = REQUIRED_GLOBAL_COLLECTION.issubset(
        snapshot.collection_complete
    )
    selected_by_family: dict[
        str, list[tuple[_PathFingerprint, tuple[str, str, int | None, bool, bool]]]
    ] = {"ipv4": [], "ipv6": []}
    routes_by_family: dict[
        str, list[tuple[_PathFingerprint, tuple[str, str, int | None, bool, bool]]]
    ] = {"ipv4": [], "ipv6": []}
    applicable_families: set[str] = set()
    for path in observed:
        for route in path.route_tokens:
            applicable_families.add(route[0])
            routes_by_family[route[0]].append((path, route))
            if route[3]:
                selected_by_family[route[0]].append((path, route))

    normalized: list[_PathFingerprint] = []
    for path in observed:
        source = source_by_token[path.path_token]
        required = set(REQUIRED_LINK_COLLECTION)
        if source.kind == "wifi":
            required.add("wireless")
        link_complete = required.issubset(path.collection_complete)
        full_route_attestation = bool(applicable_families)
        for family in applicable_families:
            selected = selected_by_family[family]
            raw_selected = [
                route for route in source.default_routes
                if route.family == family and route.selected
            ]
            if (
                len(routes_by_family[family]) != 1
                or
                len(selected) != 1
                or selected[0][0].path_token != path.path_token
                or selected[0][1][4] is not True
                or len(raw_selected) != 1
                or source.interface_index is None
                or raw_selected[0].interface_index != source.interface_index
            ):
                full_route_attestation = False
                break
        effective_label = (
            "gateway-attested"
            if (
                path.trust_label == "gateway-attested"
                and global_complete
                and link_complete
                and full_route_attestation
            )
            else "untrusted"
        )
        normalized.append(replace(path, trust_label=effective_label))
    current = tuple(normalized)
    telemetry_complete = global_complete and all(
        set(REQUIRED_LINK_COLLECTION).union(
            {"wireless"} if path.kind == "wifi" else set()
        ).issubset(path.collection_complete)
        for path in current
    )
    prior_by_path = {
        path.path_token: path for path in (previous.paths if previous else ())
    }
    added_path_count = sum(
        path.path_token not in prior_by_path for path in current
    ) if previous is not None else 0
    findings: list[NetworkTrustFinding] = []
    paths: list[PathTrust] = []

    all_routes: dict[str, list[_PathFingerprint]] = {"ipv4": [], "ipv6": []}
    for path in current:
        source = source_by_token[path.path_token]
        required = set(REQUIRED_LINK_COLLECTION)
        if path.kind == "wifi":
            required.add("wireless")
        missing_sources = tuple(sorted(required.difference(path.collection_complete)))
        attested_families = tuple(sorted({
            route[0] for route in path.route_tokens if route[3] and route[4]
        }))
        paths.append(PathTrust(
            path_token=path.path_token,
            link_kind=path.kind,
            network_token=path.network_token,
            trust_label=path.trust_label,
            profile_category=path.profile_category,
            attested_route_families=attested_families,
            telemetry_quality="complete" if not missing_sources and global_complete else "incomplete",
        ))
        if missing_sources or not global_complete:
            missing = set(missing_sources)
            missing.update(REQUIRED_GLOBAL_COLLECTION.difference(snapshot.collection_complete))
            findings.append(_finding(
                "network.telemetry_incomplete",
                "high",
                path,
                "required per-interface or address-family evidence is incomplete",
                evidence={"missing_sources": tuple(sorted(missing))},
                recommendations=(
                    "restore-network-inventory-sources",
                    "keep-path-untrusted",
                ),
            ))
        for family in _FAMILIES:
            count = sum(1 for route in path.route_tokens if route[0] == family)
            all_routes[family].extend([path] * count)
            if count > 1:
                findings.append(_finding(
                    "network.multiple_default_routes",
                    "high",
                    path,
                    "one interface has multiple default routes for the same address family",
                    evidence={"address_family": family, "route_count": count},
                    recommendations=(
                        "review-default-routes",
                        "consider-existing-host-lockdown",
                    ),
                ))

        if path.profile_category in {"private", "domain"} and path.trust_label == "untrusted":
            findings.append(_finding(
                "network.profile_trust_mismatch",
                "medium",
                path,
                "the operating-system profile is more permissive than the untrusted path label",
                evidence={"profile_category": path.profile_category},
                recommendations=(
                    "prefer-public-network-profile",
                    "consider-existing-host-firewall-lockdown",
                ),
            ))

        if path.kind == "wifi":
            security = _wifi_security_state(source.wifi_security)
            if security == "weak":
                findings.append(_finding(
                    "network.wifi_security_weak",
                    "high",
                    path,
                    "the active Wi-Fi path reports obsolete or unauthenticated link security",
                    evidence={"security_class": "weak"},
                    recommendations=(
                        "avoid-sensitive-traffic",
                        "consider-existing-host-lockdown",
                        "verify-personal-sentinel-gateway",
                    ),
                ))
            elif security == "unknown":
                findings.append(_finding(
                    "network.wifi_security_unknown",
                    "medium",
                    path,
                    "Wi-Fi link security could not be strongly classified",
                    evidence={"security_class": "unknown"},
                    recommendations=(
                        "verify-wifi-security-out-of-band",
                        "consider-existing-host-adaptation",
                    ),
                ))

        prior = prior_by_path.get(path.path_token)
        if prior is None:
            if previous is not None:
                findings.append(_finding(
                    "network.path_added",
                    "high",
                    path,
                    "a newly observed physical path is absent from the comparison baseline",
                    evidence={
                        "current_path_count": len(current),
                        "interface_set_changed": True,
                        "new_path_count": added_path_count,
                        "previous_path_count": len(prior_by_path),
                    },
                    recommendations=(
                        "verify-new-network-path",
                        "keep-path-untrusted",
                        "consider-existing-host-firewall-lockdown",
                    ),
                ))
            continue
        comparisons = (
            (
                "network.interface_epoch_changed",
                "high",
                prior.epoch_token,
                path.epoch_token,
                "the interface connection epoch changed",
            ),
            (
                "network.wireless_identity_drift",
                "high",
                prior.network_token,
                path.network_token,
                "the tokenized wireless network identity changed",
            ),
            (
                "network.dns_drift",
                "high",
                prior.dns_tokens,
                path.dns_tokens,
                "the DNS resolver set changed",
            ),
            (
                "network.dhcp_drift",
                "high",
                prior.dhcp_token,
                path.dhcp_token,
                "the DHCP server identity changed",
            ),
            (
                "network.default_route_drift",
                "high",
                prior.route_tokens,
                path.route_tokens,
                "the default route set changed",
            ),
            (
                "network.gateway_identity_drift",
                "critical",
                prior.gateway_tokens,
                path.gateway_tokens,
                "the observed gateway identity changed",
            ),
            (
                "network.profile_category_drift",
                "medium",
                prior.profile_category,
                path.profile_category,
                "the operating-system network profile category changed",
            ),
        )
        for rule_id, severity, before, after, reason in comparisons:
            # Missing telemetry on both samples is stable, not evidence.  A
            # present-to-missing transition remains drift and fails closed.
            if before != after and (before or after):
                findings.append(_finding(
                    rule_id,
                    severity,
                    path,
                    reason,
                    evidence={"changed": True},
                    recommendations=(
                        "verify-network-path",
                        "consider-existing-host-firewall-lockdown",
                    ),
                ))

    for family, route_paths in all_routes.items():
        unique_paths = {path.path_token: path for path in route_paths}
        if len(unique_paths) <= 1:
            continue
        for path in unique_paths.values():
            findings.append(_finding(
                "network.concurrent_default_paths",
                "high",
                path,
                "multiple active interfaces advertise a default route for one address family",
                evidence={
                    "address_family": family,
                    "active_default_path_count": len(unique_paths),
                },
                recommendations=(
                    "review-route-precedence",
                    "consider-existing-host-firewall-lockdown",
                ),
            ))

    # Stable ordering makes deduplication, testing, and evidence review simple.
    paths.sort(key=lambda item: item.path_token)
    findings.sort(key=lambda item: (item.path_token, item.rule_id, item.severity))
    # Retain tokenized state for recently absent interfaces so a down/up cycle
    # cannot erase the prior epoch just before reconnection.  Current paths win
    # the fixed-size bound; no raw identifier is retained.
    ordered_current = list(sorted(current, key=lambda item: item.path_token))
    current_tokens = {item.path_token for item in ordered_current}
    retained_absent = [
        item for item in sorted(
            previous.paths if previous else (), key=lambda row: row.path_token
        )
        if item.path_token not in current_tokens
    ]
    baseline_paths = tuple((ordered_current + retained_absent)[:MAX_LINKS])
    baseline_path_tokens = {path.path_token for path in baseline_paths}
    pending_path_tokens = tuple(
        token for token in (previous.pending_path_tokens if previous else ())
        if token in baseline_path_tokens
    )
    baseline = NetworkTrustBaseline(baseline_paths, pending_path_tokens)
    return NetworkTrustEvaluation(
        tuple(paths), tuple(findings), baseline, telemetry_complete
    )


class NetworkTrustEvaluator:
    """Small stateful adapter around the pure evaluator for polling modules."""

    def __init__(
        self,
        privacy_key: bytes,
        baseline: NetworkTrustBaseline | None = None,
    ) -> None:
        if not isinstance(privacy_key, bytes) or len(privacy_key) < 32:
            raise ValueError("privacy key must contain at least 32 bytes")
        self._privacy_key = bytes(privacy_key)
        if baseline is not None and not isinstance(baseline, NetworkTrustBaseline):
            raise ValueError("baseline must be NetworkTrustBaseline")
        self._baseline = baseline or NetworkTrustBaseline()
        self._comparison_established = baseline is not None

    @property
    def baseline(self) -> NetworkTrustBaseline:
        return self._baseline

    def evaluate(self, snapshot: NetworkSnapshot) -> NetworkTrustEvaluation:
        previous = self._baseline if self._comparison_established else None
        result = evaluate_network_trust(snapshot, self._privacy_key, previous)
        if result.telemetry_complete:
            self._baseline = result.baseline
            self._comparison_established = True
        return result

    def set_baseline(self, baseline: NetworkTrustBaseline) -> None:
        if not isinstance(baseline, NetworkTrustBaseline):
            raise ValueError("baseline must be NetworkTrustBaseline")
        self._baseline = baseline
        self._comparison_established = True


class NetworkTrustBaselineStore:
    """Strict HMAC baseline paired with a separately authenticated epoch."""

    def __init__(
        self,
        path: Path | str,
        *,
        baseline_key: bytes,
        enrollment_key: bytes,
        enrollment_path: Path | str | None = None,
        high_water: IndependentHighWater | None = None,
    ) -> None:
        if (
            not isinstance(baseline_key, bytes)
            or len(baseline_key) != 32
            or not isinstance(enrollment_key, bytes)
            or len(enrollment_key) != 32
        ):
            raise ValueError("network baseline keys must contain 32 bytes")
        self.path = Path(path)
        self.enrollment_path = Path(enrollment_path) if enrollment_path else (
            self.path.parent.parent / "continuity-epochs" / "network-trust.json"
        )
        self._baseline_key = bytes(baseline_key)
        self._enrollment_key = bytes(enrollment_key)
        self._high_water = high_water
        self._state = "unloaded"
        self._enrollment_id = ""
        self._revision = 0
        self._cursor_digest: str | None = None
        self._epoch_digest: str | None = None
        self._freshness = HighWaterAssessment(
            "unassessed", "state has not been loaded", False
        )

    @property
    def freshness_status(self) -> str:
        """Independent freshness, separate from local HMAC authenticity."""
        return self._freshness.state

    @property
    def independent_freshness_verified(self) -> bool:
        return self._freshness.independently_fresh

    @property
    def freshness_reason(self) -> str:
        return self._freshness.reason

    def _first_enrollment_freshness(self) -> HighWaterAssessment:
        if self._high_water is None:
            return assess_high_water(
                None,
                domain=NETWORK_DOMAIN,
                installation_id="0" * 32,
                revision=0,
                state_digest=ZERO_DIGEST,
            )
        try:
            installation_id = validate_installation_id(self._high_water.installation_id)
        except Exception:
            return HighWaterAssessment(
                "authority-rejected",
                "independent high-water installation identity is invalid",
                False,
            )
        self._enrollment_id = installation_id
        return assess_high_water(
            self._high_water,
            domain=NETWORK_DOMAIN,
            installation_id=installation_id,
            revision=0,
            state_digest=ZERO_DIGEST,
        )

    def _assess_loaded_freshness(
        self,
        cursor_payload: bytes,
        epoch_payload: bytes,
    ) -> HighWaterAssessment:
        digest = state_pair_digest(
            domain=NETWORK_DOMAIN,
            installation_id=self._enrollment_id,
            revision=self._revision,
            primary_payload=cursor_payload,
            epoch_payload=epoch_payload,
        )
        return assess_high_water(
            self._high_water,
            domain=NETWORK_DOMAIN,
            installation_id=self._enrollment_id,
            revision=self._revision,
            state_digest=digest,
        )

    @staticmethod
    def _json(payload: bytes) -> dict:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if not isinstance(key, str) or key in result:
                    raise ValueError("ambiguous network baseline JSON")
                result[key] = value
            return result

        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=unique,
            parse_constant=lambda _item: (_ for _ in ()).throw(
                ValueError("invalid network baseline number")
            ),
        )
        if not isinstance(value, dict):
            raise ValueError("network baseline is not an object")
        return value

    @staticmethod
    def _canonical(value: Mapping[str, object]) -> bytes:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    @staticmethod
    def _payload(path: Path) -> tuple[bytes | None, str | None]:
        try:
            payload = _safe_read(path, MAX_BASELINE_BYTES)
        except FileNotFoundError:
            return None, ""
        except OSError:
            return None, None
        return payload, hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _token(value: object, *, empty: bool = False) -> str:
        if value == "" and empty:
            return ""
        if (
            not isinstance(value, str)
            or len(value) != 28
            or not value.startswith("tok_")
            or any(char not in _HEX for char in value[4:])
        ):
            raise ValueError("network baseline token is invalid")
        return value

    @classmethod
    def _serialize_baseline(cls, baseline: NetworkTrustBaseline) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for path in baseline.paths:
            rows.append({
                "path_token": path.path_token,
                "kind": path.kind,
                "epoch_token": path.epoch_token,
                "network_token": path.network_token,
                "dns_tokens": list(path.dns_tokens),
                "dhcp_token": path.dhcp_token,
                "route_tokens": [list(route) for route in path.route_tokens],
                "gateway_tokens": list(path.gateway_tokens),
                "profile_category": path.profile_category,
                "trust_label": path.trust_label,
                "collection_complete": list(path.collection_complete),
            })
        return rows

    @classmethod
    def _parse_baseline(cls, value: object) -> NetworkTrustBaseline:
        if not isinstance(value, list) or len(value) > MAX_LINKS:
            raise ValueError("network baseline path set is invalid")
        paths: list[_PathFingerprint] = []
        expected = {
            "path_token", "kind", "epoch_token", "network_token", "dns_tokens",
            "dhcp_token", "route_tokens", "gateway_tokens", "profile_category",
            "trust_label", "collection_complete",
        }
        for row in value:
            if not isinstance(row, dict) or set(row) != expected:
                raise ValueError("network baseline path schema is invalid")
            dns = row["dns_tokens"]
            gateways = row["gateway_tokens"]
            routes = row["route_tokens"]
            completeness = row["collection_complete"]
            if (
                not isinstance(dns, list)
                or len(dns) > MAX_VALUES_PER_FIELD
                or not isinstance(gateways, list)
                or len(gateways) > MAX_VALUES_PER_FIELD
                or not isinstance(routes, list)
                or len(routes) > MAX_ROUTES_PER_LINK
                or not isinstance(completeness, list)
                or len(completeness) > len(COLLECTION_SOURCES)
            ):
                raise ValueError("network baseline collection exceeds its bound")
            route_tokens: list[tuple[str, str, int | None, bool, bool]] = []
            for route in routes:
                if (
                    not isinstance(route, list)
                    or len(route) != 5
                    or route[0] not in _FAMILIES
                    or (route[2] is not None and (
                        type(route[2]) is not int or not 0 <= route[2] <= 2**31 - 1
                    ))
                    or type(route[3]) is not bool
                    or type(route[4]) is not bool
                    or (route[4] and not route[3])
                ):
                    raise ValueError("network baseline route is invalid")
                route_tokens.append((
                    route[0], cls._token(route[1]), route[2], route[3], route[4]
                ))
            complete_tuple = tuple(completeness)
            if (
                len(set(complete_tuple)) != len(complete_tuple)
                or any(item not in COLLECTION_SOURCES for item in complete_tuple)
            ):
                raise ValueError("network baseline completeness is invalid")
            kind = row["kind"]
            profile = row["profile_category"]
            trust = row["trust_label"]
            if kind not in _LINK_KINDS or profile not in _PROFILES or trust not in _GATEWAY_LABELS:
                raise ValueError("network baseline classification is invalid")
            paths.append(_PathFingerprint(
                path_token=cls._token(row["path_token"]),
                kind=kind,
                epoch_token=cls._token(row["epoch_token"], empty=True),
                network_token=cls._token(row["network_token"], empty=True),
                dns_tokens=tuple(cls._token(item) for item in dns),
                dhcp_token=cls._token(row["dhcp_token"], empty=True),
                route_tokens=tuple(route_tokens),
                gateway_tokens=tuple(cls._token(item) for item in gateways),
                profile_category=profile,
                trust_label=trust,
                collection_complete=tuple(sorted(complete_tuple)),
            ))
        return NetworkTrustBaseline(tuple(paths))

    @staticmethod
    def _signed_body(document: Mapping[str, object]) -> bytes:
        return NetworkTrustBaselineStore._canonical({
            key: value for key, value in document.items() if key != "hmac_sha256"
        })

    @classmethod
    def _verify_signature(cls, document: Mapping[str, object], key: bytes) -> bool:
        signature = document.get("hmac_sha256")
        if not isinstance(signature, str) or len(signature) != 64:
            return False
        expected = hmac.new(key, cls._signed_body(document), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)

    def load(self) -> tuple[NetworkTrustBaseline | None, str]:
        cursor_payload, cursor_digest = self._payload(self.path)
        epoch_payload, epoch_digest = self._payload(self.enrollment_path)
        self._cursor_digest = cursor_digest
        self._epoch_digest = epoch_digest
        if cursor_digest is None or epoch_digest is None:
            self._state = "untrusted"
            self._freshness = HighWaterAssessment(
                "local-state-invalid", "local state could not be admitted", False
            )
            return None, "untrusted"
        if cursor_payload is None and epoch_payload is None:
            self._state = "missing"
            self._revision = 0
            self._freshness = self._first_enrollment_freshness()
            if self._freshness.state in {
                "local-behind", "fork-detected", "installation-mismatch",
                "authority-rejected",
            }:
                self._state = "untrusted"
                return None, "untrusted"
            return None, "missing"
        try:
            if cursor_payload is None or epoch_payload is None:
                raise ValueError("network baseline or enrollment epoch is missing")
            epoch = self._json(epoch_payload)
            cursor = self._json(cursor_payload)
            epoch_keys = {"schema", "enrollment_id", "revision", "hmac_sha256"}
            cursor_keys_v1 = {
                "schema", "enrollment_id", "revision", "trusted", "captured_at",
                "paths", "hmac_sha256",
            }
            cursor_keys_v2 = cursor_keys_v1 | {"pending_path_tokens"}
            cursor_schema = cursor.get("schema")
            if (
                set(epoch) != epoch_keys
                or epoch.get("schema") != 1
                or cursor_schema not in {1, 2}
                or set(cursor) != (
                    cursor_keys_v2 if cursor_schema == 2 else cursor_keys_v1
                )
                or not self._verify_signature(epoch, self._enrollment_key)
                or not self._verify_signature(cursor, self._baseline_key)
                or not isinstance(epoch.get("enrollment_id"), str)
                or len(epoch["enrollment_id"]) != 32
                or any(char not in _HEX for char in epoch["enrollment_id"])
                or cursor.get("enrollment_id") != epoch["enrollment_id"]
                or type(epoch.get("revision")) is not int
                or not 1 <= epoch["revision"] <= 2**63 - 1
                or cursor.get("revision") != epoch["revision"]
                or type(cursor.get("trusted")) is not bool
                or not isinstance(cursor.get("captured_at"), (int, float))
                or isinstance(cursor.get("captured_at"), bool)
                or not math.isfinite(float(cursor["captured_at"]))
            ):
                raise ValueError("network baseline authentication failed")
            baseline = self._parse_baseline(cursor["paths"])
            pending_value = cursor.get("pending_path_tokens")
            if pending_value is None:
                pending_value = (
                    [] if cursor["trusted"]
                    else [path.path_token for path in baseline.paths]
                )
            if (
                not isinstance(pending_value, list)
                or len(pending_value) > MAX_LINKS
                or len(pending_value) != len(set(pending_value))
                or (cursor["trusted"] and pending_value)
            ):
                raise ValueError("network pending path set is invalid")
            baseline = NetworkTrustBaseline(
                baseline.paths,
                tuple(self._token(token) for token in pending_value),
            )
            self._enrollment_id = epoch["enrollment_id"]
            self._revision = epoch["revision"]
            self._state = "trusted" if cursor["trusted"] else "provisional"
            self._freshness = self._assess_loaded_freshness(
                cursor_payload, epoch_payload
            )
            if self._freshness.state in {
                "local-behind", "fork-detected", "installation-mismatch",
                "authority-rejected",
            }:
                self._state = "untrusted"
                return None, "untrusted"
            return baseline, self._state
        except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError):
            self._state = "untrusted"
            self._freshness = HighWaterAssessment(
                "local-state-invalid", "local state authentication failed", False
            )
            return None, "untrusted"

    def _unchanged(self) -> bool:
        _cursor, cursor_digest = self._payload(self.path)
        _epoch, epoch_digest = self._payload(self.enrollment_path)
        return (
            cursor_digest is not None
            and epoch_digest is not None
            and cursor_digest == self._cursor_digest
            and epoch_digest == self._epoch_digest
        )

    def save(self, baseline: NetworkTrustBaseline, *, trusted: bool) -> bool:
        if (
            not isinstance(baseline, NetworkTrustBaseline)
            or type(trusted) is not bool
            or (trusted and bool(baseline.pending_path_tokens))
            or self._state not in {"missing", "provisional", "trusted"}
            or not self._unchanged()
        ):
            return False
        enrollment_id = self._enrollment_id or secrets.token_hex(16)
        revision = self._revision + 1
        cursor: dict[str, object] = {
            "schema": 2,
            "enrollment_id": enrollment_id,
            "revision": revision,
            "trusted": trusted,
            "captured_at": time.time(),
            "paths": self._serialize_baseline(baseline),
            "pending_path_tokens": list(baseline.pending_path_tokens),
        }
        cursor["hmac_sha256"] = hmac.new(
            self._baseline_key, self._signed_body(cursor), hashlib.sha256
        ).hexdigest()
        epoch: dict[str, object] = {
            "schema": 1,
            "enrollment_id": enrollment_id,
            "revision": revision,
        }
        epoch["hmac_sha256"] = hmac.new(
            self._enrollment_key, self._signed_body(epoch), hashlib.sha256
        ).hexdigest()
        cursor_payload = self._canonical(cursor)
        epoch_payload = self._canonical(epoch)
        if len(cursor_payload) > MAX_BASELINE_BYTES or len(epoch_payload) > MAX_BASELINE_BYTES:
            return False
        state_digest = state_pair_digest(
            domain=NETWORK_DOMAIN,
            installation_id=enrollment_id,
            revision=revision,
            primary_payload=cursor_payload,
            epoch_payload=epoch_payload,
        )
        if self._high_water is not None:
            if self._freshness.state not in {"ready-first-enrollment", "verified"}:
                return False
            previous_revision = self._revision
            previous_digest = (
                self._freshness.state_digest if previous_revision else ZERO_DIGEST
            )
            previous_head = self._freshness.head if previous_revision else ZERO_DIGEST
            advanced = advance_high_water(
                self._high_water,
                domain=NETWORK_DOMAIN,
                installation_id=enrollment_id,
                previous_revision=previous_revision,
                previous_state_digest=previous_digest,
                previous_head=previous_head,
                revision=revision,
                state_digest=state_digest,
            )
            self._freshness = advanced
            if not advanced.independently_fresh:
                return False
        try:
            _secure_write(self.path, cursor_payload)
            _secure_write(self.enrollment_path, epoch_payload)
        except OSError:
            if self._high_water is not None and self._freshness.independently_fresh:
                self._freshness = HighWaterAssessment(
                    "external-ahead-crash-recovery-required",
                    "independent head advanced before the local pair was durable",
                    False,
                    head=self._freshness.head,
                    state_digest=state_digest,
                )
            return False
        self._enrollment_id = enrollment_id
        self._revision = revision
        self._state = "trusted" if trusted else "provisional"
        self._cursor_digest = hashlib.sha256(cursor_payload).hexdigest()
        self._epoch_digest = hashlib.sha256(epoch_payload).hexdigest()
        if self._high_water is None:
            self._freshness = HighWaterAssessment(
                "local-authenticity-only",
                "local HMAC authenticity is verified without independent freshness",
                False,
                state_digest=state_digest,
            )
        return True


def self_test() -> tuple[bool, str]:
    key = b"network-trust-self-test-key-0001"
    first = NetworkSnapshot((NetworkLinkObservation(
        "self-test-wifi",
        "wifi",
        interface_epoch="one",
        ssid="sensitive-self-test-ssid",
        bssid="00:11:22:33:44:55",
        wifi_security="WPA3-SAE CCMP",
        dns_servers=("10.0.0.2",),
        dhcp_server="10.0.0.1",
        default_routes=(DefaultRouteObservation("10.0.0.1", selected=True),),
        gateway_identities=("10.0.0.1|00:aa:bb:cc:dd:ee",),
        profile_category="private",
        collection_complete=tuple(COLLECTION_SOURCES),
    ),), collection_complete=tuple(COLLECTION_SOURCES))
    initial = evaluate_network_trust(first, key)
    second = NetworkSnapshot((NetworkLinkObservation(
        "self-test-wifi",
        "wifi",
        interface_epoch="two",
        ssid="sensitive-self-test-ssid",
        bssid="00:11:22:33:44:55",
        wifi_security="WPA3-SAE CCMP",
        dns_servers=("10.0.0.9",),
        dhcp_server="10.0.0.8",
        default_routes=(DefaultRouteObservation("10.0.0.7", selected=True),),
        gateway_identities=("10.0.0.7|00:ff:ee:dd:cc:bb",),
        profile_category="public",
        collection_complete=tuple(COLLECTION_SOURCES),
    ),), collection_complete=tuple(COLLECTION_SOURCES))
    drift = evaluate_network_trust(second, key, initial.baseline)
    rules = {item.rule_id for item in drift.findings}
    required = {
        "network.interface_epoch_changed",
        "network.dns_drift",
        "network.dhcp_drift",
        "network.default_route_drift",
        "network.gateway_identity_drift",
    }
    representation = repr((initial, drift))
    if not required.issubset(rules):
        return False, "network drift rules did not fire"
    if any(raw in representation for raw in ("self-test-wifi", "10.0.0.", "00:11")):
        return False, "raw network identifiers escaped tokenization"
    if any(path.endpoint_resources_trusted for path in initial.paths):
        return False, "endpoint resources were implicitly trusted"
    return True, "zero-trust network evaluation and privacy boundaries verified"


__all__ = [
    "COLLECTION_SOURCES",
    "DefaultRouteObservation",
    "MAX_LINKS",
    "NetworkLinkObservation",
    "NetworkSnapshot",
    "NetworkTrustBaseline",
    "NetworkTrustBaselineStore",
    "NetworkTrustEvaluation",
    "NetworkTrustEvaluator",
    "NetworkTrustFinding",
    "PathTrust",
    "evaluate_network_trust",
    "load_network_purpose_keys",
    "self_test",
]
