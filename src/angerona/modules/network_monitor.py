"""Network connection monitor.

Tracks new outbound connections and flags three independent signals:

  1. Connection to a hardcoded suspicious port (illustrative C2/tooling
     ports) — HIGH, unchanged from before.
  2. First contact with an external HOST not seen (by ANY process) in the
     novelty window — MEDIUM. This is what actually catches exfil-style
     traffic over ordinary ports like 443/80, which a port-only heuristic
     structurally cannot.
  3. First contact with an already-known HOST, but from a PROCESS that
     hasn't talked to it before — LOW. This closes a real gap signal #2
     alone can't see: on a real machine, a handful of IP ranges (Google,
     Cloudflare's shared anycast edge, etc.) are essentially always
     "already known" because a browser or background service touched them
     recently — so a newly-launched process reaching one of those same
     addresses would otherwise generate no signal at all, even though "a
     process that's never talked to this host before just did" is exactly
     the kind of thing worth a quiet note. (This is also what makes a
     Shark Attack Exfiltration drill reliably testable: the test domains
     resolve into Cloudflare's shared IP space, which is near-guaranteed to
     already be "known" on any machine with a browser — signal #2 alone
     would almost never fire on a repeat run, not because detection is
     broken, but because that specific IP just isn't a fresh destination
     for anyone. Signal #3 doesn't care who else has visited it.)

To avoid drowning the alert feed, everything else (a process repeating a
connection it's already made itself) is NOT alerted individually — it's
counted and rolled up into one quiet INFO line per minute. Loopback and
private/local addresses are ignored entirely.
"""
from __future__ import annotations

import ipaddress
import math
import os
import time
from typing import Dict, Mapping, Set, Tuple

from angerona.core.community_id import community_id_v1
from angerona.core.module_base import BaseModule, Severity
from angerona.core.net_interfaces import interface_type_for_local_ip
from angerona.modules.intel_sync import is_ip_flagged
from angerona.telemetry.sensors import list_connections

# Ports commonly abused by malware C2 / tooling (illustrative, tune as needed).
SUSPICIOUS_PORTS = {4444, 1337, 6660, 6667, 31337, 12345, 9001, 5555}

# Standard web ports. A first-contact to a novel host over ordinary HTTPS/HTTP is
# what normal browsing looks like — every new website hits one. Flagging those at
# MEDIUM turned routine web traffic into a threat-level-inflating alert storm, so
# novel hosts on these ports are downgraded to LOW (still recorded for exfil
# review, just not alarming). Novel hosts on NON-web ports stay MEDIUM — a fresh
# destination on an odd port is the more C2/beacon-like signal.
WEB_PORTS = {80, 443, 8080, 8443}

# A host counts as "novel" again if we haven't seen it in this many minutes —
# a fresh destination is a meaningfully different signal than a long-running
# peer, but "seen once, forever trusted" would quietly stop watching after
# the first day of uptime.
NOVELTY_WINDOW_S = float(os.environ.get("ANGERONA_NETMON_NOVELTY_WINDOW_MIN", "60")) * 60
_STATE_MAX = 10_000
_LOCAL_V4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_LOCAL_V6_NETWORKS = (ipaddress.ip_network("fc00::/7"),)


def _block_remote_contract(
    ip: str,
    *,
    corroborated: bool = False,
    classification: str = "",
) -> dict:
    """Bind firewall authority only to an explicitly corroborated IOC."""
    if not corroborated or classification != "threat-intel-ioc":
        return {}
    candidate = str(ip or "").strip().split("%", 1)[0]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return {}
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    # A remote-block action is meaningful only for one globally routable
    # unicast address. Poisoned intel must not authorize blocking loopback,
    # RFC1918/ULA, link-local, multicast, unspecified, or reserved peers.
    if not address.is_global or address.is_multicast:
        return {}
    normalized = str(address)
    return {
        "response_authorized": True,
        "response_classification": classification,
        "response_contract": {
            "version": 1,
            "actions": ["block_remote_ip"],
            "targets": {"remote_ips": [normalized]},
        },
    }


def _split_endpoint(value: object) -> tuple[str, int] | None:
    """Parse the bounded ``address:port`` form returned by local sensors."""
    if not isinstance(value, str) or not value or len(value) > 128:
        return None
    if value.startswith("["):
        close = value.find("]")
        if close < 2 or value[close + 1:close + 2] != ":":
            return None
        address, raw_port = value[1:close], value[close + 2:]
    else:
        address, separator, raw_port = value.rpartition(":")
        if not separator:
            return None
    if not raw_port.isascii() or not raw_port.isdecimal() or len(raw_port) > 5:
        return None
    port = int(raw_port)
    if not 0 <= port <= 65_535:
        return None
    return address, port


def _native_community_id(connection: Mapping[str, object]) -> str:
    local = _split_endpoint(connection.get("laddr"))
    remote = _split_endpoint(connection.get("raddr"))
    if local is None or remote is None:
        return ""
    # Established entries from psutil's inet snapshot are TCP.  A sensor that
    # supplies an explicit protocol may opt into UDP/SCTP correlation as well.
    protocol = connection.get("proto") or connection.get("protocol") or "tcp"
    return community_id_v1(local[0], remote[0], local[1], remote[1], protocol)


def _poll_interval() -> float:
    enabled = os.environ.get("ANGERONA_ADVERSARY_COMBAT_ENABLED", "0").strip().lower()
    mode = os.environ.get("ANGERONA_ADVERSARY_COMBAT_MODE", "").strip().lower()
    if enabled in {"1", "true", "yes", "on"} and mode == "maximum":
        return 0.75
    if enabled in {"1", "true", "yes", "on"}:
        return 2.0
    return 4.0


def _snapshot_max_age() -> float | None:
    """Keep Maximum/Combat sensor freshness below half its poll cadence."""
    enabled = os.environ.get("ANGERONA_ADVERSARY_COMBAT_ENABLED", "0").strip().lower()
    if enabled not in {"1", "true", "yes", "on"}:
        return None
    return max(0.05, _poll_interval() / 2.0)


def _is_local(ip: str) -> bool:
    if not ip:
        return True
    # Parse, canonicalize, and explicitly unwrap IPv4-mapped IPv6 before
    # classification. Prefix matching treated every ``::`` address as local,
    # including public ``::ffff:8.8.8.8`` destinations.
    candidate = str(ip).strip()
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        # Malformed sensor data cannot safely authorize an external-host claim.
        return True
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if isinstance(address, ipaddress.IPv4Address):
        return bool(
            address.is_loopback
            or address.is_link_local
            or address.is_unspecified
            or address.is_multicast
            or address.is_reserved
            or any(address in network for network in _LOCAL_V4_NETWORKS)
        )
    return bool(
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
        or any(address in network for network in _LOCAL_V6_NETWORKS)
    )


class NetworkMonitorModule(BaseModule):
    name = "Network Monitor"
    description = "Watches new outbound connections; alerts on suspicious ports and first-seen external hosts."
    category = "Network"
    version = "1.13.0"

    def __init__(self) -> None:
        super().__init__()
        self._seen: Set[Tuple] = set()
        self._known_hosts: Dict[str, float] = {}  # ip -> last-seen ts (any process)
        self._known_pid_hosts: Dict[Tuple[int, float, str], float] = {}

    @staticmethod
    def _process_birth(
        connection: Mapping[str, object],
        cache: Dict[int, float | None],
    ) -> float | None:
        """Resolve a PID-reuse-safe birth time once per process per poll."""
        raw = (
            connection.get("process_create_time")
            or connection.get("pid_create_time")
            or connection.get("create_time")
        )
        try:
            supplied = float(raw)
        except (TypeError, ValueError, OverflowError):
            supplied = 0.0
        if supplied > 0 and math.isfinite(supplied):
            return supplied
        pid = connection.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return None
        if pid in cache:
            return cache[pid]
        try:
            import psutil

            observed = float(psutil.Process(pid).create_time())
            value = observed if observed > 0 and math.isfinite(observed) else None
        except Exception:
            value = None
        cache[pid] = value
        return value

    @classmethod
    def _connection_key(
        cls,
        connection: Mapping[str, object],
        cache: Dict[int, float | None],
    ) -> tuple[object, float | None, object, object]:
        return (
            connection.get("pid"),
            cls._process_birth(connection, cache),
            connection.get("laddr"),
            connection.get("raddr"),
        )

    @staticmethod
    def _trim_recent(mapping: Dict, maximum: int = _STATE_MAX) -> Dict:
        """Keep the newest bounded entries without changing novelty semantics."""
        if len(mapping) <= maximum:
            return mapping
        newest = sorted(mapping.items(), key=lambda item: item[1], reverse=True)
        return dict(newest[:maximum])

    @staticmethod
    def _drop_older_than(mapping: Dict, cutoff: float) -> None:
        """Prune expired entries in place, allocating only for stale keys.

        Most polling cycles have no expiry at all. Rebuilding both 10,000-entry
        novelty maps every cycle imposed steady allocation/GC cost even though
        every retained identity and timestamp was unchanged.
        """
        stale = [key for key, seen_at in mapping.items() if seen_at < cutoff]
        for key in stale:
            del mapping[key]

    def _prune_state(self, active_connections: Set[Tuple], now: float) -> None:
        """Drop closed sockets and expired PID/host identities.

        This both bounds long-running state and lets a reused PID be assessed as
        a new process instead of inheriting an old process's network history.
        """
        self._seen.intersection_update(active_connections)
        pid_cutoff = now - NOVELTY_WINDOW_S
        host_cutoff = now - (NOVELTY_WINDOW_S * 2)
        self._drop_older_than(self._known_pid_hosts, pid_cutoff)
        self._drop_older_than(self._known_hosts, host_cutoff)
        self._known_pid_hosts = self._trim_recent(self._known_pid_hosts)
        self._known_hosts = self._trim_recent(self._known_hosts)

    def self_test(self) -> tuple[bool, str]:
        """Validate endpoint, identity and response gates without network I/O."""
        connection = {
            "pid": 7,
            "laddr": "[2001:db8::1]:53000",
            "raddr": "[2001:db8::2]:443",
            "status": "ESTABLISHED",
            "protocol": "tcp",
        }
        denied = _block_remote_contract(
            "8.8.8.8", corroborated=False, classification="threat-intel-ioc"
        )
        allowed = _block_remote_contract(
            "8.8.8.8", corroborated=True, classification="threat-intel-ioc"
        )
        values = {str(index): float(index) for index in range(12)}
        trimmed = self._trim_recent(values, maximum=5)
        ok = bool(
            _split_endpoint("203.0.113.9:443") == ("203.0.113.9", 443)
            and _split_endpoint("[2001:db8::2]:443") == ("2001:db8::2", 443)
            and _split_endpoint("203.0.113.9:99999") is None
            and _native_community_id(connection)
            and denied == {}
            and allowed.get("response_authorized") is True
            and allowed["response_contract"]["targets"]["remote_ips"] == ["8.8.8.8"]
            and len(trimmed) == 5
            and min(trimmed.values()) == 7.0
        )
        return (
            ok,
            "offline IPv4/IPv6, Community ID, bounds, and response gates passed"
            if ok else "network contract fixture failed",
        )

    def run(self) -> None:
        now0 = time.time()
        birth_cache: Dict[int, float | None] = {}
        for c in list_connections():
            key = self._connection_key(c, birth_cache)
            birth = key[1]
            self._seen.add(key)
            # Seed already-established peers as "known" so a pre-existing,
            # long-running connection doesn't get flagged as novel the
            # moment a second socket to the same host appears after startup.
            if c.get("raddr"):
                remote = _split_endpoint(c["raddr"])
                if remote is None:
                    continue
                ip, _port = remote
                if not _is_local(ip):
                    self._known_hosts[ip] = now0
                    if isinstance(c.get("pid"), int) and birth is not None:
                        self._known_pid_hosts[(c["pid"], birth, ip)] = now0
        self.set_health(100, "")
        self.emit("Network monitor active.", Severity.INFO)

        last_summary = time.time()
        new_external = 0
        while not self.stopping:
            self.sleep(_poll_interval())
            max_age = _snapshot_max_age()
            connections = (
                list_connections(max_age=max_age)
                if max_age is not None
                else list_connections()
            )
            active_connections: Set[Tuple] = set()
            birth_cache = {}
            for c in connections:
                if c["status"] != "ESTABLISHED" or not c["raddr"]:
                    continue
                remote = _split_endpoint(c["raddr"])
                if remote is None:
                    continue
                ip, rport = remote
                if _is_local(ip):
                    continue
                key = self._connection_key(c, birth_cache)
                birth = key[1]
                active_connections.add(key)
                if key in self._seen:
                    continue
                self._seen.add(key)
                new_external += 1
                community_id = _native_community_id(c)
                # Sensor snapshots are shared briefly between modules. Enrich a
                # private event copy so one consumer cannot mutate telemetry
                # another consumer is concurrently reading.
                event_details = dict(c)
                event_details["process_identity_complete"] = birth is not None
                if birth is not None:
                    event_details["process_create_time"] = birth
                # Raw socket snapshots are data, never an authority channel.
                # Only the trusted correlation branch below may add a response
                # contract to the emitted detector event.
                event_details.pop("response_authorized", None)
                event_details.pop("response_contract", None)
                event_details.pop("response_classification", None)
                if community_id:
                    event_details["community_id"] = community_id

                # VPN awareness: tag the owning interface (Physical / Virtual_VPN /
                # Loopback) so downstream (AI triage, split-tunnel rule) has context.
                _laddr = c.get("laddr") or ""
                event_details["interface_type"] = interface_type_for_local_ip(
                    _laddr.rsplit(":", 1)[0] if _laddr else "")

                now = time.time()
                last_seen = self._known_hosts.get(ip)
                is_novel_host = last_seen is None or (now - last_seen) > NOVELTY_WINDOW_S
                pid_host = (
                    (c["pid"], birth, ip)
                    if isinstance(c.get("pid"), int) and birth is not None
                    else None
                )
                last_pid_seen = self._known_pid_hosts.get(pid_host) if pid_host else None
                is_novel_for_pid = bool(
                    pid_host is None
                    or last_pid_seen is None
                    or (now - last_pid_seen) > NOVELTY_WINDOW_S
                )
                self._known_hosts[ip] = now
                if pid_host is not None:
                    self._known_pid_hosts[pid_host] = now

                if rport in SUSPICIOUS_PORTS:
                    corroborated = is_ip_flagged(ip)
                    self.emit(
                        f"Connection to suspicious port {rport}: {c['raddr']} "
                        f"(pid {c['pid']})",
                        Severity.HIGH,
                        **_block_remote_contract(
                            ip,
                            corroborated=corroborated,
                            classification="threat-intel-ioc" if corroborated else "",
                        ),
                        **event_details,
                    )
                elif is_novel_host:
                    mins = int(NOVELTY_WINDOW_S // 60)
                    # Novel host on a normal web port = ordinary browsing → LOW.
                    # Novel host on an unusual port = more C2/beacon-like → MEDIUM.
                    web = rport in WEB_PORTS
                    self.emit(f"First contact with external host {ip} in the last "
                              f"{mins}min (pid {c['pid']}, port {rport}) — novel-destination "
                              "signal." + (" (web port)" if web else ""),
                              Severity.LOW if web else Severity.MEDIUM, **event_details)
                elif is_novel_for_pid:
                    # The host itself is already known (some other process
                    # touched it recently — very common with shared-IP CDN
                    # ranges), but THIS process hasn't reached it before.
                    # Lower severity: much less alarming than a host nobody's
                    # ever seen, but still a real, distinct "new" signal.
                    self.emit(f"Process {c['pid']} made its first connection to already-known "
                              f"host {ip}:{rport} — new to this process, not to the machine.",
                              Severity.LOW, **event_details)

            self._prune_state(active_connections, time.time())

            # One quiet rollup per minute for everything else (repeat
            # connections to already-known hosts on ordinary ports).
            now = time.time()
            if now - last_summary >= 60:
                if new_external:
                    self.emit(f"{new_external} new external connection(s) in the last minute.",
                              Severity.INFO)
                new_external = 0
                last_summary = now
