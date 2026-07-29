"""Bounded, privacy-minimized Network Detection and Response analytics."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass

MAX_FLOWS = 50_000


def _token(key: bytes, label: bytes, value: str) -> str:
    return "tok_" + hmac.new(
        key, label + b"\0" + value.casefold().encode(),
        hashlib.sha256,
    ).hexdigest()[:24]


@dataclass(frozen=True)
class NetworkFlow:
    timestamp: float
    process_identity: str
    destination_ip: str
    destination_port: int
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0

    def __post_init__(self) -> None:
        if not self.process_identity or len(self.process_identity) > 512:
            raise ValueError("invalid process identity")
        ipaddress.ip_address(self.destination_ip)
        if not 1 <= int(self.destination_port) <= 65535:
            raise ValueError("invalid destination port")
        if self.protocol.casefold() not in {"tcp", "udp"}:
            raise ValueError("unsupported protocol")
        if self.bytes_sent < 0 or self.bytes_received < 0:
            raise ValueError("byte counters cannot be negative")


@dataclass(frozen=True)
class NetworkFinding:
    rule_id: str
    severity: str
    process_token: str
    destination_token: str
    evidence_count: int
    reason: str


class NetworkBehaviorAnalytics:
    """Fixed-memory flow analytics retaining tokens rather than raw endpoints."""

    def __init__(
        self, privacy_key: bytes, *, window_seconds: int = 600,
        max_flows: int = MAX_FLOWS, clock=time.time,
    ) -> None:
        if len(privacy_key) < 32:
            raise ValueError("privacy key must contain at least 32 bytes")
        if not 60 <= int(window_seconds) <= 3600:
            raise ValueError("window must be between 60 and 3600 seconds")
        self._key = bytes(privacy_key)
        self.window_seconds = int(window_seconds)
        self.max_flows = max(100, min(int(max_flows), MAX_FLOWS))
        self._clock = clock
        self._flows: deque[
            tuple[float, str, str, int, bool, int, int]
        ] = deque()

    def observe(self, flow: NetworkFlow) -> tuple[NetworkFinding, ...]:
        now = float(self._clock())
        if abs(now - float(flow.timestamp)) > 3600:
            raise ValueError("network flow is stale or future-dated")
        ip = ipaddress.ip_address(flow.destination_ip)
        private = bool(ip.is_private or ip.is_loopback or ip.is_link_local)
        process = _token(self._key, b"process", flow.process_identity)
        destination = _token(
            self._key, b"destination",
            f"{flow.destination_ip}:{flow.destination_port}/{flow.protocol.casefold()}",
        )
        self._flows.append((
            float(flow.timestamp), process, destination,
            int(flow.destination_port), private,
            int(flow.bytes_sent), int(flow.bytes_received),
        ))
        cutoff = now - self.window_seconds
        while self._flows and (
            self._flows[0][0] < cutoff or len(self._flows) > self.max_flows
        ):
            self._flows.popleft()

        findings: list[NetworkFinding] = []
        private_targets: dict[str, set[str]] = defaultdict(set)
        external_targets: dict[str, set[str]] = defaultdict(set)
        destination_times: dict[tuple[str, str], list[float]] = defaultdict(list)
        upload_totals: dict[tuple[str, str], int] = defaultdict(int)
        for stamp, proc, dest, _port, is_private, sent, _received in self._flows:
            (private_targets if is_private else external_targets)[proc].add(dest)
            destination_times[(proc, dest)].append(stamp)
            upload_totals[(proc, dest)] += sent

        if private and len(private_targets[process]) >= 10:
            findings.append(NetworkFinding(
                "network.lateral_fanout", "High", process, destination,
                len(private_targets[process]),
                "one process contacted ten or more private destinations",
            ))
        if not private and len(external_targets[process]) >= 20:
            findings.append(NetworkFinding(
                "network.external_fanout", "Medium", process, destination,
                len(external_targets[process]),
                "one process contacted twenty or more external destinations",
            ))
        stamps = destination_times[(process, destination)]
        if not private and len(stamps) >= 6:
            intervals = [
                later - earlier for earlier, later in zip(stamps, stamps[1:])
                if later > earlier
            ]
            if len(intervals) >= 5:
                mean = sum(intervals) / len(intervals)
                variance = sum((item - mean) ** 2 for item in intervals) / len(intervals)
                cv = math.sqrt(variance) / mean if mean else 1.0
                if mean >= 5 and cv <= 0.10:
                    findings.append(NetworkFinding(
                        "network.periodic_beacon", "High", process, destination,
                        len(stamps),
                        "six or more external connections have low-jitter periodic timing",
                    ))
        if (
            not private and upload_totals[(process, destination)] >= 50 * 1024 * 1024
            and flow.bytes_received * 20 < flow.bytes_sent
        ):
            findings.append(NetworkFinding(
                "network.asymmetric_upload", "High", process, destination,
                upload_totals[(process, destination)],
                "outbound transfer exceeded 50 MiB with strongly asymmetric traffic",
            ))
        return tuple(findings)

    @property
    def retained_flows(self) -> int:
        return len(self._flows)
