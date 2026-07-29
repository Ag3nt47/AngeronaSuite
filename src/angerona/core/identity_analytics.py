"""Bounded, privacy-minimized local identity threat analytics."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import time
from collections import defaultdict, deque
from dataclasses import dataclass

MAX_EVENTS = 20_000
MAX_WINDOW_SECONDS = 3600


def _token(key: bytes, namespace: bytes, value: str) -> str:
    return "tok_" + hmac.new(
        key, namespace + b"\0" + value.casefold().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:24]


@dataclass(frozen=True)
class AuthenticationEvent:
    timestamp: float
    account: str
    source: str
    success: bool
    interactive: bool = True
    privileged: bool = False
    service_account: bool = False
    device_id: str = "local-device"

    def __post_init__(self) -> None:
        if not self.account or len(self.account) > 320:
            raise ValueError("invalid account")
        if not self.source or len(self.source) > 253:
            raise ValueError("invalid authentication source")
        if not self.device_id or len(self.device_id) > 128:
            raise ValueError("invalid device ID")
        try:
            ipaddress.ip_address(self.source)
        except ValueError:
            if any(char not in "abcdefghijklmnopqrstuvwxyz0123456789.-_" for char in
                   self.source.casefold()):
                raise ValueError("invalid authentication source")


@dataclass(frozen=True)
class IdentityFinding:
    rule_id: str
    severity: str
    account_token: str
    source_token: str
    evidence_count: int
    window_seconds: int
    reason: str


class IdentityAnalytics:
    """Fixed-memory detector; raw account/source identities are never retained."""

    def __init__(
        self, privacy_key: bytes, *, window_seconds: int = 600,
        max_events: int = MAX_EVENTS, clock=time.time,
    ) -> None:
        if len(privacy_key) < 32:
            raise ValueError("privacy key must contain at least 32 bytes")
        if not 60 <= int(window_seconds) <= MAX_WINDOW_SECONDS:
            raise ValueError("window must be between 60 and 3600 seconds")
        self._key = bytes(privacy_key)
        self.window_seconds = int(window_seconds)
        self.max_events = max(100, min(int(max_events), MAX_EVENTS))
        self._clock = clock
        self._events: deque[tuple[float, str, str, bool, bool, bool, bool]] = deque()
        self._known_privileged_pairs: set[tuple[str, str]] = set()

    def observe(self, event: AuthenticationEvent) -> tuple[IdentityFinding, ...]:
        now = float(self._clock())
        if abs(now - float(event.timestamp)) > MAX_WINDOW_SECONDS:
            raise ValueError("authentication event is stale or future-dated")
        account = _token(self._key, b"account", event.account)
        source = _token(self._key, b"source", event.source)
        self._events.append((
            float(event.timestamp), account, source, bool(event.success),
            bool(event.interactive), bool(event.privileged),
            bool(event.service_account),
        ))
        cutoff = now - self.window_seconds
        while self._events and (
            self._events[0][0] < cutoff or len(self._events) > self.max_events
        ):
            self._events.popleft()

        findings: list[IdentityFinding] = []
        failures_by_source: dict[str, set[str]] = defaultdict(set)
        failures_by_account: dict[str, set[str]] = defaultdict(set)
        failure_counts: dict[tuple[str, str], int] = defaultdict(int)
        for _stamp, acct, src, success, *_flags in self._events:
            if success:
                continue
            failures_by_source[src].add(acct)
            failures_by_account[acct].add(src)
            failure_counts[(acct, src)] += 1

        if not event.success and len(failures_by_source[source]) >= 5:
            findings.append(IdentityFinding(
                "identity.password_spray", "High", account, source,
                len(failures_by_source[source]), self.window_seconds,
                "one source failed authentication across five or more accounts",
            ))
        if not event.success and len(failures_by_account[account]) >= 5:
            findings.append(IdentityFinding(
                "identity.distributed_account_attack", "High", account, source,
                len(failures_by_account[account]), self.window_seconds,
                "one account was targeted by five or more sources",
            ))
        if not event.success and failure_counts[(account, source)] >= 10:
            findings.append(IdentityFinding(
                "identity.repeated_failure", "Medium", account, source,
                failure_counts[(account, source)], self.window_seconds,
                "an account/source pair exceeded the failure threshold",
            ))
        if event.success and event.service_account and event.interactive:
            findings.append(IdentityFinding(
                "identity.service_account_interactive", "High", account, source,
                1, self.window_seconds,
                "a service account performed an interactive sign-in",
            ))
        pair = (account, source)
        if event.success and event.privileged:
            if self._known_privileged_pairs and pair not in self._known_privileged_pairs:
                findings.append(IdentityFinding(
                    "identity.privileged_new_source", "High", account, source,
                    1, self.window_seconds,
                    "a privileged account signed in from a new source",
                ))
            self._known_privileged_pairs.add(pair)
            if len(self._known_privileged_pairs) > 4096:
                self._known_privileged_pairs = {pair}
        return tuple(findings)

    @property
    def retained_events(self) -> int:
        return len(self._events)
