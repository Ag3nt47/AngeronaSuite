"""Observe-only zero-trust monitor for active Wi-Fi and Ethernet paths.

Raw local network identifiers exist only inside a short-lived observation.
They are passed to :mod:`angerona.core.network_trust`, which returns keyed
tokens and typed findings.  This module never changes routes, firewall rules,
network profiles, or gateway configuration.
"""
from __future__ import annotations

import heapq
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

import psutil

from angerona.core.independent_high_water import IndependentHighWater
from angerona.core.module_base import BaseModule, Severity
from angerona.core.net_interfaces import LOOPBACK, VIRTUAL_VPN, classify_interfaces
from angerona.core.personal_sentinel_gateway import (
    GatewayAttestation,
    GatewayConfigurationError,
    GatewayMonitorBinding,
    GatewayTransport,
    PersonalSentinelGatewayClient,
    load_gateway_monitor_binding,
)
from angerona.core.network_trust import (
    COLLECTION_SOURCES,
    DefaultRouteObservation,
    MAX_LINKS,
    MAX_ROUTES_PER_LINK,
    NetworkLinkObservation,
    NetworkSnapshot,
    NetworkTrustBaseline,
    NetworkTrustEvaluation,
    NetworkTrustEvaluator,
    NetworkTrustBaselineStore,
    evaluate_network_trust,
    load_network_purpose_keys,
)
from angerona.core.win import popen_hidden


SUPPORTED_PLATFORMS = ("windows", "macos", "linux")
POLL_INTERVAL = 30.0
COMMAND_TIMEOUT = 4.0
MAX_COMMAND_OUTPUT = 256 * 1024
MAX_ROUTE_ROWS = 128
MAX_ROUTE_ROWS_PER_FAMILY = 64

_WIFI_NAME_HINTS = (
    "wi-fi",
    "wifi",
    "wireless",
    "wlan",
    "airport",
)


@dataclass(frozen=True)
class _CommandObservation:
    text: str
    complete: bool
    reason: str


def _run_observation_command_result(arguments: list[str]) -> _CommandObservation:
    """Drain a fixed inventory child through a hard in-flight memory cap."""

    try:
        process = popen_hidden(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return _CommandObservation("", False, "launch-failed")
    buffer = bytearray()
    overflow = threading.Event()

    def drain() -> None:
        stream = process.stdout
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                remaining = MAX_COMMAND_OUTPUT + 1 - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])
                if len(buffer) > MAX_COMMAND_OUTPUT or len(chunk) > remaining:
                    overflow.set()
                    try:
                        process.kill()
                    except OSError:
                        pass
                    break
        except OSError:
            return

    reader = threading.Thread(target=drain, name="AngeronaNetInventoryDrain", daemon=True)
    reader.start()
    reader.join(COMMAND_TIMEOUT)
    timed_out = reader.is_alive()
    if timed_out:
        try:
            process.kill()
        except OSError:
            pass
    reader.join(1.0)
    try:
        return_code = process.wait(timeout=1.0)
    except Exception:
        try:
            process.kill()
        except OSError:
            pass
        return _CommandObservation("", False, "termination-failed")
    finally:
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass
    if timed_out:
        return _CommandObservation("", False, "timeout")
    if overflow.is_set():
        return _CommandObservation("", False, "output-limit")
    if return_code != 0:
        return _CommandObservation("", False, "command-failed")
    return _CommandObservation(bytes(buffer).decode("utf-8", "replace"), True, "ok")


def _run_observation_command(arguments: list[str]) -> str:
    result = _run_observation_command_result(arguments)
    return result.text if result.complete else ""


def _valid_ip(value: str) -> str:
    candidate = str(value or "").strip().strip("[](),")
    try:
        return str(ipaddress.ip_address(candidate.split("%", 1)[0]))
    except ValueError:
        return ""


def _parse_windows_wlan(text: str) -> dict[str, dict[str, str]]:
    interfaces: dict[str, dict[str, str]] = {}
    current: dict[str, str] = {}

    def finish() -> None:
        name = current.get("name", "").strip()
        state = current.get("state", "").strip().casefold()
        if name and state == "connected":
            interfaces[name.casefold()] = {
                "ssid": current.get("ssid", "")[:512],
                "bssid": current.get("bssid", "")[:512],
                "security": " ".join(filter(None, (
                    current.get("authentication", ""),
                    current.get("cipher", ""),
                )))[:512] or "unknown",
            }

    for raw_line in text.splitlines():
        match = re.match(r"^\s*([^:]+?)\s*:\s*(.*)$", raw_line)
        if not match:
            continue
        key = match.group(1).strip().casefold()
        value = match.group(2).strip()
        if key == "name" and current:
            finish()
            current = {}
        if key in {"name", "state", "ssid", "bssid", "authentication", "cipher"}:
            current[key] = value
    if current:
        finish()
    return interfaces


def _windows_wlan() -> tuple[dict[str, dict[str, str]], bool]:
    if os.name != "nt":
        return {}, False
    result = _run_observation_command_result(
        ["netsh", "wlan", "show", "interfaces"]
    )
    return (_parse_windows_wlan(result.text), result.complete)


def _system_dns_servers() -> tuple[tuple[str, ...], bool]:
    values: set[str] = set()
    if os.name == "nt":
        observation = _run_observation_command_result(["ipconfig", "/all"])
        text = observation.text
        capture_continuation = False
        for line in text.splitlines():
            lower = line.casefold()
            if "dns servers" in lower and ":" in line:
                capture_continuation = True
                candidate = _valid_ip(line.rsplit(":", 1)[-1])
                if candidate:
                    values.add(candidate)
                continue
            if capture_continuation:
                candidate = _valid_ip(line.strip())
                if candidate:
                    values.add(candidate)
                    continue
                capture_continuation = False
    else:
        path = Path("/etc/resolv.conf")
        try:
            if path.is_file() and path.stat().st_size <= MAX_COMMAND_OUTPUT:
                text = path.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].casefold() == "nameserver":
                        candidate = _valid_ip(parts[1])
                        if candidate:
                            values.add(candidate)
        except OSError:
            return (), False
        observation = _CommandObservation("", True, "ok")
    return tuple(sorted(values))[:32], observation.complete


def _windows_dhcp_servers() -> tuple[tuple[str, ...], bool]:
    if os.name != "nt":
        return (), False
    values: set[str] = set()
    observation = _run_observation_command_result(["ipconfig", "/all"])
    text = observation.text
    for line in text.splitlines():
        if "dhcp server" not in line.casefold() or ":" not in line:
            continue
        candidate = _valid_ip(line.rsplit(":", 1)[-1])
        if candidate:
            values.add(candidate)
    return tuple(sorted(values))[:32], observation.complete


def _windows_profiles() -> tuple[dict[str, str], bool]:
    if os.name != "nt":
        return {}, False
    command = (
        "Get-NetConnectionProfile | "
        "Select-Object InterfaceAlias,NetworkCategory | ConvertTo-Json -Compress"
    )
    observation = _run_observation_command_result([
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-Command", command,
    ])
    text = observation.text
    if not text:
        return {}, observation.complete
    try:
        rows = json.loads(text)
    except (TypeError, ValueError):
        return {}, False
    if isinstance(rows, dict):
        rows = [rows]
    result: dict[str, str] = {}
    if not isinstance(rows, list) or len(rows) > 64:
        return result, False
    categories = {"public": "public", "private": "private", "domainauthenticated": "domain"}
    for row in rows:
        if not isinstance(row, dict):
            continue
        alias = str(row.get("InterfaceAlias", ""))[:512].casefold()
        category = categories.get(str(row.get("NetworkCategory", "")).casefold())
        if alias and category:
            result[alias] = category
    return result, observation.complete


def _json_rows(text: str, maximum: int = 256) -> list[dict]:
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return []
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list) or len(value) > maximum:
        return []
    return [row for row in value if isinstance(row, dict)]


def _windows_interface_settings() -> tuple[dict[str, tuple[tuple[str, ...], str]], bool]:
    """Return interface-bound DNS/DHCP evidence from fixed Windows providers."""
    if os.name != "nt":
        return {}, True
    dns_command = (
        "Get-DnsClientServerAddress | Select-Object InterfaceAlias,InterfaceIndex,"
        "ServerAddresses | ConvertTo-Json -Depth 3 -Compress"
    )
    dhcp_command = (
        "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | "
        "Select-Object InterfaceIndex,DHCPServer | ConvertTo-Json -Compress"
    )
    dns_result = _run_observation_command_result([
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-Command", dns_command,
    ])
    dhcp_result = _run_observation_command_result([
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-Command", dhcp_command,
    ])
    if not dns_result.complete or not dhcp_result.complete:
        return {}, False
    dhcp_by_index: dict[int, str] = {}
    for row in _json_rows(dhcp_result.text, 128):
        try:
            index = int(row.get("InterfaceIndex"))
        except (TypeError, ValueError):
            continue
        dhcp_by_index[index] = _valid_ip(str(row.get("DHCPServer") or ""))
    settings: dict[str, tuple[tuple[str, ...], str]] = {}
    dns_rows = _json_rows(dns_result.text, 256)
    if dns_result.text and not dns_rows:
        return {}, False
    for row in dns_rows:
        alias = str(row.get("InterfaceAlias") or "")[:512].casefold()
        try:
            index = int(row.get("InterfaceIndex"))
        except (TypeError, ValueError):
            continue
        raw_servers = row.get("ServerAddresses")
        if isinstance(raw_servers, str):
            raw_servers = [raw_servers]
        if not isinstance(raw_servers, list) or len(raw_servers) > 32:
            raw_servers = []
        dns = tuple(sorted(filter(None, (
            _valid_ip(str(value)) for value in raw_servers
        ))))[:32]
        if alias:
            existing = settings.get(alias, ((), ""))
            settings[alias] = (
                tuple(sorted(set(existing[0]).union(dns)))[:32],
                dhcp_by_index.get(index, existing[1]),
            )
    return settings, True


def _route_family(value: object) -> str:
    normalized = str(value or "").strip().casefold()
    if normalized in {"ipv4", "2"}:
        return "ipv4"
    if normalized in {"ipv6", "23"}:
        return "ipv6"
    return ""


def _route_integer(value: object, *, default: int | None = None) -> int:
    if value is None or value == "":
        if default is None:
            raise ValueError("route integer is missing")
        return default
    if isinstance(value, bool):
        raise ValueError("route integer cannot be boolean")
    return int(value)


def _append_bounded_route(
    routes: dict[str, list[DefaultRouteObservation]],
    interface: str,
    route: DefaultRouteObservation,
    complete_families: set[str],
) -> None:
    values = routes[interface]
    if len(values) >= MAX_ROUTES_PER_LINK:
        complete_families.discard(route.family)
        return
    values.append(route)


def _parse_windows_default_routes(
    text: str,
) -> tuple[dict[str, list[DefaultRouteObservation]], frozenset[str]]:
    """Parse bounded PowerShell route rows with per-family rejection state."""

    routes: dict[str, list[DefaultRouteObservation]] = defaultdict(list)
    complete_families = {"ipv4", "ipv6"}
    if not text.strip():
        return routes, frozenset(complete_families)
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return routes, frozenset()
    if isinstance(value, dict):
        rows: tuple[object, ...] = (value,)
    elif isinstance(value, list) and len(value) <= MAX_ROUTE_ROWS:
        rows = tuple(value)
    else:
        return routes, frozenset()
    for row in rows:
        if not isinstance(row, dict):
            complete_families.clear()
            continue
        family = _route_family(row.get("AddressFamily"))
        if not family:
            complete_families.clear()
            continue
        interface_value = row.get("InterfaceAlias")
        gateway_value = row.get("NextHop")
        if not isinstance(interface_value, str) or not isinstance(gateway_value, str):
            complete_families.discard(family)
            continue
        interface = interface_value.strip()
        gateway = _valid_ip(gateway_value)
        if not interface or len(interface) > 512 or not gateway:
            complete_families.discard(family)
            continue
        try:
            metric = _route_integer(row.get("RouteMetric"), default=0)
            metric += _route_integer(row.get("InterfaceMetric"), default=0)
            interface_index = _route_integer(row.get("InterfaceIndex"))
            route = DefaultRouteObservation(
                gateway, family, metric, interface_index=interface_index
            )
        except (TypeError, ValueError):
            complete_families.discard(family)
            continue
        _append_bounded_route(routes, interface, route, complete_families)
    return routes, frozenset(complete_families)


def _parse_linux_default_routes(
    text: str,
    family: str,
) -> tuple[dict[str, list[DefaultRouteObservation]], bool]:
    """Parse one bounded ``ip route`` family and expose every rejection."""

    routes: dict[str, list[DefaultRouteObservation]] = defaultdict(list)
    complete_families = {family}
    row_count = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        row_count += 1
        if row_count > MAX_ROUTE_ROWS_PER_FAMILY:
            complete_families.discard(family)
            break
        fields = line.split()
        if fields[0] != "default" or "dev" not in fields or "via" not in fields:
            complete_families.discard(family)
            continue
        try:
            interface = fields[fields.index("dev") + 1]
            gateway = _valid_ip(fields[fields.index("via") + 1])
            metric = (
                _route_integer(fields[fields.index("metric") + 1])
                if "metric" in fields else None
            )
            if not interface or len(interface) > 512 or not gateway:
                raise ValueError("route fields are invalid")
            route = DefaultRouteObservation(
                gateway,
                family,
                metric,
                interface_index=socket.if_nametoindex(interface),
            )
        except (IndexError, OSError, TypeError, ValueError):
            complete_families.discard(family)
            continue
        _append_bounded_route(routes, interface, route, complete_families)
    return routes, family in complete_families


def _merge_routes(
    destination: dict[str, list[DefaultRouteObservation]],
    incoming: dict[str, list[DefaultRouteObservation]],
    complete_families: set[str],
) -> None:
    for interface, values in incoming.items():
        for route in values:
            _append_bounded_route(destination, interface, route, complete_families)


def _default_routes(
    local_ip_to_interface: dict[str, str],
) -> tuple[dict[str, list[DefaultRouteObservation]], frozenset[str]]:
    del local_ip_to_interface  # reserved for route providers that report only source IP
    routes: dict[str, list[DefaultRouteObservation]] = defaultdict(list)
    complete_families: set[str] = set()
    if os.name == "nt":
        command = (
            "Get-NetRoute -PolicyStore ActiveStore | Where-Object { "
            "$_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' } | "
            "Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,NextHop,RouteMetric,InterfaceMetric | "
            "ConvertTo-Json -Compress"
        )
        observation = _run_observation_command_result([
            "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
            "-Command", command,
        ])
        if observation.complete:
            routes, parsed_complete = _parse_windows_default_routes(observation.text)
            complete_families.update(parsed_complete)
    elif platform.system().casefold() == "linux":
        for family, arguments in (
            ("ipv4", ["ip", "-o", "route", "show", "default"]),
            ("ipv6", ["ip", "-o", "-6", "route", "show", "default"]),
        ):
            observation = _run_observation_command_result(arguments)
            if not observation.complete:
                continue
            parsed, complete = _parse_linux_default_routes(observation.text, family)
            if complete:
                complete_families.add(family)
            _merge_routes(routes, parsed, complete_families)
    elif platform.system().casefold() == "darwin":
        for family, arguments in (
            ("ipv4", ["route", "-n", "get", "default"]),
            ("ipv6", ["route", "-n", "get", "-inet6", "default"]),
        ):
            observation = _run_observation_command_result(arguments)
            if not observation.complete:
                continue
            gateway = ""
            interface = ""
            for line in observation.text.splitlines():
                if line.strip().startswith("gateway:"):
                    gateway = _valid_ip(line.split(":", 1)[1])
                elif line.strip().startswith("interface:"):
                    interface = line.split(":", 1)[1].strip()
            if not gateway or not interface or len(interface) > 512:
                continue
            try:
                route = DefaultRouteObservation(
                    gateway,
                    family,
                    None,
                    interface_index=socket.if_nametoindex(interface),
                )
            except (OSError, ValueError):
                continue
            complete_families.add(family)
            _append_bounded_route(routes, interface, route, complete_families)

    candidates: list[tuple[str, int, DefaultRouteObservation]] = []
    for interface, values in routes.items():
        for index, route in enumerate(values):
            candidates.append((interface, index, route))
    for family in ("ipv4", "ipv6"):
        family_rows = [item for item in candidates if item[2].family == family]
        if len(family_rows) == 1:
            interface, index, route = family_rows[0]
            routes[interface][index] = replace(route, selected=True)
            continue
        known = [item for item in family_rows if item[2].metric is not None]
        if not known:
            continue
        minimum = min(int(item[2].metric) for item in known if item[2].metric is not None)
        winners = [item for item in known if item[2].metric == minimum]
        if len(winners) == 1:
            interface, index, route = winners[0]
            routes[interface][index] = replace(route, selected=True)
    return routes, frozenset(complete_families)


def _neighbor_identities() -> tuple[dict[str, str], bool]:
    if os.name == "nt":
        observation = _run_observation_command_result(["arp", "-a"])
    elif platform.system().casefold() == "linux":
        observation = _run_observation_command_result(["ip", "neigh", "show"])
    else:
        observation = _run_observation_command_result(["arp", "-an"])
    text = observation.text
    result: dict[str, str] = {}
    mac_pattern = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
    ip_pattern = re.compile(r"(?<![0-9a-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
    for line in text.splitlines()[:2048]:
        mac = mac_pattern.search(line)
        candidates = ip_pattern.findall(line)
        if not mac or not candidates:
            continue
        address = _valid_ip(candidates[0])
        if address:
            result[address] = mac.group(0).casefold().replace("-", ":")
    return result, observation.complete


def _bounded_owned_ips(rows: object) -> tuple[tuple[str, ...], bool]:
    """Return at most 32 interface addresses and expose rejected/overflow rows."""

    values: set[str] = set()
    complete = True
    try:
        iterator = iter(rows)
    except TypeError:
        return (), False
    for row in iterator:
        if getattr(row, "family", None) not in {socket.AF_INET, socket.AF_INET6}:
            continue
        candidate = _valid_ip(str(getattr(row, "address", "")))
        if not candidate:
            complete = False
            continue
        if candidate in values:
            continue
        if len(values) >= 32:
            complete = False
            continue
        values.add(candidate)
    return tuple(sorted(values)), complete


def observe_system_network() -> NetworkSnapshot:
    """Best-effort, bounded local inventory; never changes network state."""

    try:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception:
        return NetworkSnapshot((), time.time(), ())
    classification = classify_interfaces()
    wlan, wlan_complete = _windows_wlan()
    profiles, profiles_complete = _windows_profiles()
    if os.name == "nt":
        interface_settings, settings_complete = _windows_interface_settings()
        dns_servers: tuple[str, ...] = ()
        dhcp_servers: tuple[str, ...] = ()
        dns_complete = settings_complete
        dhcp_complete = settings_complete
    else:
        interface_settings = {}
        dns_servers, dns_complete = _system_dns_servers()
        dhcp_servers, dhcp_complete = _windows_dhcp_servers()
    interfaces_complete = len(addresses) <= MAX_LINKS
    for name in addresses:
        if not isinstance(name, str) or not name or len(name) > 512:
            interfaces_complete = False
            continue
        if stats.get(name) is None:
            interfaces_complete = False
    for name, stat in stats.items():
        if getattr(stat, "isup", False) and name not in addresses:
            interfaces_complete = False
    retained_names = tuple(heapq.nsmallest(
        MAX_LINKS,
        (
            name for name in addresses
            if isinstance(name, str) and name and len(name) <= 512
        ),
    ))
    owned_ips_by_name: dict[str, tuple[str, ...]] = {}
    eligible_names: list[str] = []
    addresses_complete = True
    for name in retained_names:
        owned_ips, row_complete = _bounded_owned_ips(addresses.get(name, ()))
        addresses_complete = addresses_complete and row_complete
        owned_ips_by_name[name] = owned_ips
        stat = stats.get(name)
        if stat is None or not stat.isup:
            continue
        adapter_class = classification.get(name, "Physical")
        if adapter_class in {LOOPBACK, VIRTUAL_VPN}:
            continue
        if owned_ips and all(
            ipaddress.ip_address(value).is_loopback for value in owned_ips
        ):
            continue
        eligible_names.append(name)
    local_ip_to_interface: dict[str, str] = {}
    for name, owned_ips in owned_ips_by_name.items():
        for candidate in owned_ips:
            local_ip_to_interface[candidate] = name
    routes, complete_route_families = _default_routes(local_ip_to_interface)
    eligible_name_set = set(eligible_names)
    complete_route_families = set(complete_route_families)
    for name, candidates in routes.items():
        if name in eligible_name_set:
            continue
        for route in candidates:
            complete_route_families.discard(route.family)
    neighbors, neighbors_complete = _neighbor_identities()
    complete_sources: set[str] = set()
    if interfaces_complete:
        complete_sources.add("interfaces")
    if addresses_complete:
        complete_sources.add("addresses")
    for name, complete in (
        ("dns", dns_complete),
        ("dhcp", dhcp_complete),
        ("routes-ipv4", "ipv4" in complete_route_families),
        ("routes-ipv6", "ipv6" in complete_route_families),
        ("neighbors", neighbors_complete),
        ("profile", profiles_complete),
        ("wireless", wlan_complete),
    ):
        if complete:
            complete_sources.add(name)
    links: list[NetworkLinkObservation] = []
    boot_epoch = str(int(psutil.boot_time()))

    for name in eligible_names:
        owned_ips = owned_ips_by_name[name]
        name_folded = name.casefold()
        wireless = wlan.get(name_folded)
        kind = "wifi" if wireless is not None or any(
            hint in name_folded for hint in _WIFI_NAME_HINTS
        ) or name_folded.startswith("wl") else "ethernet"
        link_routes = tuple(routes.get(name, ()))
        gateway_identities = tuple(
            f"{route.gateway}|{neighbors.get(route.gateway, 'unresolved')}"
            for route in link_routes
        )
        network = wireless or {}
        interface_dns, interface_dhcp = interface_settings.get(
            name_folded, (dns_servers, dhcp_servers[0] if len(dhcp_servers) == 1 else "")
        )
        epoch_material = "|".join((
            boot_epoch,
            ",".join(owned_ips),
            network.get("bssid", ""),
        ))[:512]
        try:
            interface_index = socket.if_nametoindex(name)
        except OSError:
            interface_index = None
        links.append(NetworkLinkObservation(
            interface_id=name[:512],
            kind=kind,
            interface_index=interface_index,
            active=True,
            loopback=False,
            interface_epoch=epoch_material,
            ssid=network.get("ssid", "")[:512],
            bssid=network.get("bssid", "")[:512],
            wifi_security=network.get("security", "unknown")[:512] or "unknown",
            dns_servers=interface_dns,
            dhcp_server=interface_dhcp,
            default_routes=link_routes,
            gateway_identities=gateway_identities,
            profile_category=profiles.get(name_folded, "unknown"),
            gateway_attestation="untrusted",
            collection_complete=tuple(sorted(complete_sources)),
        ))
    return NetworkSnapshot(
        tuple(links), time.time(), tuple(sorted(complete_sources))
    )


class NetworkTrustMonitorModule(BaseModule):
    CODE = "NZTR"
    NAME = "Zero-Trust Network Path Monitor"
    name = "Zero-Trust Network Path Monitor"
    description = (
        "Treats active Wi-Fi and Ethernet paths as untrusted by default and "
        "observes tokenized DNS, DHCP, route, gateway, profile, and epoch drift."
    )
    category = "Network"
    version = "1.12.1"
    supported_platforms = SUPPORTED_PLATFORMS
    capability_mode = "observe"

    def __init__(
        self,
        *,
        observer: Callable[[], NetworkSnapshot] | None = None,
        privacy_key: bytes | None = None,
        data_root: Path | None = None,
        gateway_loader: Callable[[], GatewayMonitorBinding | None] | None = None,
        gateway_transport: GatewayTransport | None = None,
        high_water: IndependentHighWater | None = None,
    ) -> None:
        super().__init__()
        self._observer = observer or observe_system_network
        if privacy_key is not None and (
            not isinstance(privacy_key, bytes) or len(privacy_key) < 32
        ):
            raise ValueError("network privacy key must contain at least 32 bytes")
        if data_root is None and privacy_key is None:
            from angerona.core.data_paths import data_dir

            root = data_dir()
        else:
            root = Path(data_root) if data_root is not None else None
        keys = load_network_purpose_keys(
            root, master_key=privacy_key[:32] if privacy_key is not None else None
        ) if root is not None else None
        self._privacy_key = bytes(privacy_key) if privacy_key is not None else (
            keys[0] if keys is not None else secrets.token_bytes(32)
        )
        self._baseline_store: NetworkTrustBaselineStore | None = None
        self._baseline_state = "unavailable"
        self._persisted_baseline = None
        if root is not None and keys is not None:
            self._baseline_store = NetworkTrustBaselineStore(
                root / "sensor-baselines" / "network-trust.json",
                baseline_key=keys[1],
                enrollment_key=keys[2],
                enrollment_path=root / "continuity-epochs" / "network-trust.json",
                high_water=high_water,
            )
            loaded, self._baseline_state = self._baseline_store.load()
            self._persisted_baseline = loaded
        self._evaluator = NetworkTrustEvaluator(
            self._privacy_key, self._persisted_baseline
        )
        self._gateway_loader = gateway_loader or load_gateway_monitor_binding
        self._gateway_transport = gateway_transport
        self._last_gateway_status: tuple[bool, str, str] | None = None
        self._first_observation = True
        self._last_path_states: dict[str, tuple[str, str]] = {}
        self._active_finding_keys: set[tuple[str, str, str]] = set()
        self._freshness_reported = ""

    def _report_baseline_freshness(self) -> None:
        store = self._baseline_store
        if store is None:
            return
        freshness = store.freshness_status
        if freshness == self._freshness_reported:
            return
        self._freshness_reported = freshness
        if store.independent_freshness_verified:
            return
        self.emit(
            "Network baseline local authenticity is separate from independent freshness",
            Severity.MEDIUM,
            schema="angerona.state-high-water.v1",
            state_domain="network-trust-baseline",
            freshness_status=freshness,
            independently_fresh=False,
            local_network_identifiers_omitted=True,
            response_authorized=False,
            response_authority="observe-only",
        )

    def _emit_gateway_status(self, status: GatewayAttestation) -> None:
        key = (status.success, status.reason_code, status.endpoint_token)
        if key == self._last_gateway_status:
            return
        self._last_gateway_status = key
        message = (
            "Personal Sentinel Gateway path attestation verified"
            if status.success
            else "Personal Sentinel Gateway attestation failed closed; path remains untrusted"
        )
        self.emit(
            message,
            Severity.INFO if status.success else Severity.MEDIUM,
            **status.event_details(),
        )

    def _apply_gateway_attestation(self, snapshot: NetworkSnapshot) -> NetworkSnapshot:
        """Attest only an explicitly configured interface/default-gateway pair."""

        # The live monitor accepts this label only from its own verifier.  A
        # collector, plugin, or restored snapshot cannot assert attestation.
        # Inspect every link/route on every tick, but avoid rebuilding an
        # already-clean immutable snapshot (the normal collector path).
        if any(
            link.gateway_attestation != "untrusted"
            or any(route.attested for route in link.default_routes)
            for link in snapshot.links
        ):
            snapshot = NetworkSnapshot(tuple(
                replace(
                    link,
                    gateway_attestation="untrusted",
                    default_routes=tuple(
                        replace(route, attested=False) if route.attested else route
                        for route in link.default_routes
                    ),
                )
                for link in snapshot.links
            ), snapshot.observed_at, snapshot.collection_complete)
        try:
            binding = self._gateway_loader()
        except Exception:
            if self._last_gateway_status != (False, "configuration-invalid", ""):
                self._last_gateway_status = (False, "configuration-invalid", "")
                self.emit(
                    "Personal Sentinel Gateway configuration was rejected; paths remain untrusted",
                    Severity.MEDIUM,
                    schema="angerona.personal-sentinel-attestation.v1",
                    attestation_success=False,
                    path_label="untrusted",
                    reason_code="configuration-invalid",
                    endpoint_token="",
                    certificate_token="",
                    endpoint_resources_trusted=False,
                    local_network_identifiers_omitted=True,
                    response_authorized=False,
                    response_authority="observe-only",
                )
            return snapshot
        if binding is None:
            # File absence is the secure default, not a discovery trigger.
            self._last_gateway_status = None
            return snapshot
        if not isinstance(binding, GatewayMonitorBinding):
            raise GatewayConfigurationError("gateway loader returned an invalid binding")
        client = PersonalSentinelGatewayClient(
            binding.enrollment,
            self._privacy_key,
            transport=self._gateway_transport,
        )
        target_index = next((
            index for index, link in enumerate(snapshot.links)
            if link.active
            and not link.loopback
            and link.kind in {"wifi", "ethernet"}
            and link.interface_id == binding.interface_id
        ), None)
        if target_index is None:
            self._emit_gateway_status(client.untrusted_status("interface-binding-missing"))
            return snapshot
        target = snapshot.links[target_index]
        endpoint_host = binding.enrollment._canonical_host
        route_context = self._selected_route_context(
            snapshot, binding.interface_id, endpoint_host
        )
        if route_context is None:
            self._emit_gateway_status(client.untrusted_status("path-binding-rejected"))
            return snapshot
        status = client.attest()
        if not status.success:
            self._emit_gateway_status(status)
            return snapshot
        try:
            post_snapshot = self._observer()
        except Exception:
            post_snapshot = None
        if (
            not isinstance(post_snapshot, NetworkSnapshot)
            or self._selected_route_context(
                post_snapshot, binding.interface_id, endpoint_host
            ) != route_context
        ):
            self._emit_gateway_status(client.untrusted_status("route-context-changed"))
            return snapshot
        self._emit_gateway_status(status)
        links = list(snapshot.links)
        links[target_index] = replace(
            target,
            gateway_attestation="gateway-attested",
            default_routes=tuple(
                replace(route, attested=True)
                if route.selected else route
                for route in target.default_routes
            ),
        )
        return NetworkSnapshot(
            tuple(links), snapshot.observed_at, snapshot.collection_complete
        )

    @staticmethod
    def _selected_route_context(
        snapshot: NetworkSnapshot,
        interface_id: str,
        endpoint_host: str,
    ) -> tuple[tuple[str, int, str, str, int | None], ...] | None:
        """Return a complete selected-route binding or fail closed."""
        required = {"interfaces", "addresses", "routes-ipv4", "routes-ipv6"}
        if not required.issubset(snapshot.collection_complete) or endpoint_host == "localhost":
            return None
        target = next((
            link for link in snapshot.links
            if link.active and not link.loopback and link.interface_id == interface_id
        ), None)
        if target is None or not required.issubset(target.collection_complete):
            return None
        routes_by_family: dict[
            str, list[tuple[NetworkLinkObservation, DefaultRouteObservation]]
        ] = defaultdict(list)
        for link in snapshot.links:
            if not link.active or link.loopback or link.kind not in {"wifi", "ethernet"}:
                continue
            for route in link.default_routes:
                routes_by_family[route.family].append((link, route))
        context: list[tuple[str, int, str, str, int | None]] = []
        for family, candidates in sorted(routes_by_family.items()):
            if not candidates:
                continue
            if len(candidates) != 1:
                return None
            selected = [item for item in candidates if item[1].selected]
            if len(selected) != 1:
                return None
            link, route = selected[0]
            if (
                link.interface_id != interface_id
                or link.interface_index is None
                or route.interface_index != link.interface_index
                or route.gateway.split("%", 1)[0] != endpoint_host
            ):
                return None
            context.append((
                link.interface_id,
                link.interface_index,
                link.interface_epoch,
                family,
                route.metric,
            ))
        return tuple(context) if context else None

    @staticmethod
    def _severity(value: str) -> Severity:
        return {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }.get(value.casefold(), Severity.MEDIUM)

    def _publish_evaluation(self, result: NetworkTrustEvaluation) -> None:
        current_states: dict[str, tuple[str, str]] = {}
        for path in result.paths:
            state = (path.trust_label, path.network_token)
            current_states[path.path_token] = state
            if self._first_observation or self._last_path_states.get(path.path_token) != state:
                message = (
                    "Active network path is gateway-attested; endpoint resources remain zero-trust"
                    if path.trust_label == "gateway-attested"
                    else "Active network path is untrusted by default"
                )
                self.emit(message, Severity.INFO, **path.event_details())

        finding_keys = {
            (finding.path_token, finding.rule_id, repr(finding.evidence))
            for finding in result.findings
        }
        for finding in result.findings:
            key = (finding.path_token, finding.rule_id, repr(finding.evidence))
            if key in self._active_finding_keys:
                continue
            self.emit(
                f"Zero-trust network finding: {finding.reason}",
                self._severity(finding.severity),
                **finding.event_details(),
            )
        if self._first_observation and not result.paths:
            self.emit(
                "No active non-loopback Wi-Fi or Ethernet path was observed",
                Severity.INFO,
                schema="angerona.network-path-trust.v1",
                active_path_count=0,
                zero_trust_default=True,
                local_network_identifiers_omitted=True,
                response_authorized=False,
                response_authority="observe-only",
            )
        self._active_finding_keys = finding_keys
        self._last_path_states = current_states
        self._first_observation = False

    def _tick(self) -> None:
        try:
            snapshot = self._observer()
            if not isinstance(snapshot, NetworkSnapshot):
                raise ValueError("observer contract violation")
            snapshot = self._apply_gateway_attestation(snapshot)
            result = self._evaluator.evaluate(snapshot)
        except Exception:
            self.set_health(50, "bounded network inventory unavailable")
            self.emit(
                "Zero-trust network inventory is temporarily unavailable; paths remain untrusted",
                Severity.MEDIUM,
                schema="angerona.network-path-trust.v1",
                telemetry_quality="unavailable",
                trust_label="untrusted",
                zero_trust_default=True,
                local_network_identifiers_omitted=True,
                response_authorized=False,
                response_authority="observe-only",
            )
            return
        drift_rules = {
            "network.path_added",
            "network.interface_epoch_changed",
            "network.wireless_identity_drift",
            "network.dns_drift",
            "network.dhcp_drift",
            "network.default_route_drift",
            "network.gateway_identity_drift",
            "network.profile_category_drift",
        }
        historical_drift = any(
            finding.rule_id in drift_rules for finding in result.findings
        )
        path_added = any(
            finding.rule_id == "network.path_added" for finding in result.findings
        )
        other_historical_drift = any(
            finding.rule_id in drift_rules
            and finding.rule_id != "network.path_added"
            for finding in result.findings
        )
        self._report_baseline_freshness()
        advance_allowed = (
            self._baseline_store is not None
            and self._baseline_store.freshness_status in {
                "local-authenticity-only", "ready-first-enrollment", "verified"
            }
        )
        if not result.telemetry_complete:
            if self._persisted_baseline is not None:
                self._evaluator.set_baseline(self._persisted_baseline)
            self.set_health(40, "network inventory is incomplete; baseline was not advanced")
        elif self._baseline_store is None:
            self.set_health(45, "stable network key custody is unavailable")
        elif self._baseline_state == "untrusted":
            self.set_health(25, "authenticated network baseline is missing or untrusted")
        elif self._baseline_state == "missing":
            if not advance_allowed:
                self.set_health(
                    30,
                    "network baseline enrollment awaits independent freshness recovery",
                )
            elif self._baseline_store.save(result.baseline, trusted=False):
                self._baseline_state = "provisional"
                self._persisted_baseline = result.baseline
                self.set_health(65, "complete network baseline recorded as provisional")
                self._report_baseline_freshness()
            else:
                self._baseline_state = "untrusted"
                self.set_health(25, "network baseline enrollment could not be authenticated")
        elif path_added:
            persisted_tokens = {
                path.path_token
                for path in (
                    self._persisted_baseline.paths
                    if self._persisted_baseline is not None
                    else ()
                )
            }
            candidate_tokens = {path.path_token for path in result.baseline.paths}
            addition_only = (
                not other_historical_drift
                and persisted_tokens.issubset(candidate_tokens)
            )
            if not addition_only:
                if self._persisted_baseline is not None:
                    self._evaluator.set_baseline(self._persisted_baseline)
                self.set_health(
                    30,
                    "new network path has additional drift; baseline was not advanced",
                )
            elif not advance_allowed:
                if self._persisted_baseline is not None:
                    self._evaluator.set_baseline(self._persisted_baseline)
                self.set_health(
                    30,
                    "new network path reconciliation awaits independent freshness recovery",
                )
            else:
                pending_tokens = tuple(sorted({
                    *result.baseline.pending_path_tokens,
                    *(
                        finding.path_token for finding in result.findings
                        if finding.rule_id == "network.path_added"
                    ),
                }))
                candidate = NetworkTrustBaseline(
                    result.baseline.paths, pending_tokens
                )
                if self._baseline_store.save(candidate, trusted=False):
                    self._baseline_state = "provisional"
                    self._persisted_baseline = candidate
                    self._evaluator.set_baseline(candidate)
                    self._report_baseline_freshness()
                    self.set_health(
                        55,
                        "new network path recorded as provisional; stability confirmation required",
                    )
                else:
                    if self._persisted_baseline is not None:
                        self._evaluator.set_baseline(self._persisted_baseline)
                    self._baseline_state = "untrusted"
                    self.set_health(25, "network path reconciliation failed closed")
        elif historical_drift:
            if self._persisted_baseline is not None:
                self._evaluator.set_baseline(self._persisted_baseline)
            self.set_health(35, "network path differs from the authenticated baseline")
        elif self._baseline_state == "provisional":
            active_tokens = {path.path_token for path in result.paths}
            pending_tokens = set(result.baseline.pending_path_tokens)
            if not pending_tokens.issubset(active_tokens):
                if self._persisted_baseline is not None:
                    self._evaluator.set_baseline(self._persisted_baseline)
                self.set_health(
                    40,
                    "provisional network path awaits an active stable confirmation",
                )
            elif not advance_allowed:
                self.set_health(
                    30,
                    "network baseline promotion awaits independent freshness recovery",
                )
            elif self._baseline_store.save(
                NetworkTrustBaseline(result.baseline.paths), trusted=True
            ):
                self._baseline_state = "trusted"
                self._persisted_baseline = NetworkTrustBaseline(result.baseline.paths)
                self._evaluator.set_baseline(self._persisted_baseline)
                self._report_baseline_freshness()
                self.set_health(
                    100
                    if self._baseline_store.independent_freshness_verified
                    else 75,
                    "authenticated network baseline is stable"
                    if self._baseline_store.independent_freshness_verified
                    else "network baseline is locally authentic; freshness is not independent",
                )
            else:
                self._baseline_state = "untrusted"
                self.set_health(25, "network baseline promotion failed closed")
        else:
            if self._persisted_baseline is not None:
                self._evaluator.set_baseline(self._persisted_baseline)
            self.set_health(
                100
                if self._baseline_store.independent_freshness_verified
                else 75,
                ""
                if self._baseline_store.independent_freshness_verified
                else "network baseline is locally authentic; freshness is not independent",
            )
        self._publish_evaluation(result)

    def run(self) -> None:
        while not self.stopping:
            self._tick()
            self.sleep(POLL_INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        key = b"network-monitor-self-test-key-0001"
        snapshot = NetworkSnapshot((NetworkLinkObservation(
            "raw-self-test-interface",
            "wifi",
            ssid="raw-self-test-ssid",
            bssid="00:11:22:33:44:55",
            wifi_security="open",
            profile_category="private",
        ),))
        result = evaluate_network_trust(snapshot, key)
        details = [path.event_details() for path in result.paths]
        details.extend(finding.event_details() for finding in result.findings)
        representation = repr(details)
        if not result.paths or result.paths[0].trust_label != "untrusted":
            return False, "active wireless link was not untrusted by default"
        if not {"network.wifi_security_weak", "network.profile_trust_mismatch"}.issubset(
            {finding.rule_id for finding in result.findings}
        ):
            return False, "wireless/profile defenses did not fire"
        if any(raw in representation for raw in (
            "raw-self-test-interface", "raw-self-test-ssid", "00:11:22:33:44:55"
        )):
            return False, "routine details exposed a raw network identifier"
        if any(item.get("response_authorized") is not False for item in details):
            return False, "observe-only response boundary is missing"
        return True, "untrusted-LAN/WLAN monitoring and privacy boundary verified"


def register() -> NetworkTrustMonitorModule:
    return NetworkTrustMonitorModule()


__all__ = [
    "NetworkTrustMonitorModule",
    "observe_system_network",
    "register",
]
