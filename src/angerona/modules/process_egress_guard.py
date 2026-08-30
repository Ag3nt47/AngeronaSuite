"""Observation-only monitor for process-bound egress lease decisions.

Actual connection admission must be performed by a separately privileged,
injected enforcement adapter.  This module consumes only the broker's bounded,
sanitized audit stream and never opens, closes, redirects, or filters sockets.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Callable

from angerona.core.module_base import BaseModule, Severity
from angerona.core.process_egress_lease import (
    EgressAttempt,
    EgressAuditBatch,
    GatewayPathIdentity,
    ProcessEgressLeaseBroker,
    ProcessIdentity,
)


POLL_INTERVAL = 5.0
MAX_SEEN_EVENTS = 1024
SUPPORTED_PLATFORMS = ("windows", "macos", "linux")
_HIGH_RISK_DENIALS = frozenset(
    {
        "clock-rollback",
        "connection-replay",
        "gateway-attestation-required",
        "lease-state-mismatch",
        "pid-reuse-detected",
        "process-executable-mismatch",
        "user-token-mismatch",
    }
)


def unavailable_audit_observer() -> EgressAuditBatch:
    return EgressAuditBatch((), False, 0, "broker-audit-not-connected")


class ProcessEgressGuardModule(BaseModule):
    CODE = "PELG"
    NAME = "Process Egress Lease Guard"
    name = NAME
    description = (
        "Observes HMAC-authenticated, process/start/user/destination/path-bound "
        "egress decisions and detects replay, PID reuse, DNS drift, budget use, "
        "and gateway-attestation loss."
    )
    category = "Network"
    version = "1.12.1"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    platform_requirements = (
        "A separately privileged connection-admission adapter",
        "Trusted process identity and first-hop path observers",
        "A shared ProcessEgressLeaseBroker audit stream",
    )

    def __init__(
        self,
        *,
        audit_observer: Callable[[], EgressAuditBatch] | None = None,
    ) -> None:
        super().__init__()
        self._audit_observer = audit_observer or unavailable_audit_observer
        self._seen_order: deque[str] = deque()
        self._seen: set[str] = set()
        self._last_coverage_state = ""

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def _remember(self, token: str) -> bool:
        if token in self._seen:
            return False
        while len(self._seen_order) >= MAX_SEEN_EVENTS:
            self._seen.discard(self._seen_order.popleft())
        self._seen.add(token)
        self._seen_order.append(token)
        return True

    def observe_once(self) -> EgressAuditBatch:
        batch = self._audit_observer()
        if not isinstance(batch, EgressAuditBatch):
            raise ValueError("egress audit observer contract violation")
        return batch

    def _report_coverage(self, batch: EgressAuditBatch) -> None:
        if batch.lost_records:
            health = 20
            state = f"loss:{batch.lost_records}"
            message = "Process egress audit records were lost; enforcement coverage is uncertain."
            severity = Severity.CRITICAL
        elif not batch.complete:
            health = 45
            state = f"incomplete:{batch.reason}"
            message = "Process egress enforcement audit coverage is incomplete."
            severity = Severity.HIGH
        else:
            health = 100
            state = "complete"
            message = "Process egress enforcement audit coverage is complete."
            severity = Severity.INFO
        self.set_health(health, "" if health == 100 else batch.reason or "audit coverage gap")
        if state != self._last_coverage_state:
            self._last_coverage_state = state
            self.emit(
                message,
                severity,
                schema="angerona.process-egress-guard-status.v1",
                audit_complete=batch.complete,
                lost_records=batch.lost_records,
                coverage_reason=batch.reason,
                observation_only=True,
                enforcement_performed=False,
                external_enforcer_required=True,
                response_authorized=False,
                response_authority="observe-only",
            )

    def _tick(self) -> None:
        try:
            batch = self.observe_once()
        except Exception as exc:
            batch = EgressAuditBatch(
                (), False, 0, f"observer-error-{type(exc).__name__}"[:160]
            )
        self._report_coverage(batch)
        for record in batch.records:
            if not self._remember(record.event_token):
                continue
            if record.allowed:
                severity = Severity.INFO
                message = "A bounded process egress reservation was admitted by the policy broker."
            else:
                severity = (
                    Severity.CRITICAL
                    if record.reason_code in _HIGH_RISK_DENIALS
                    else Severity.HIGH
                )
                message = "A process egress reservation failed zero-trust policy."
            self.emit(
                message,
                severity,
                schema=record.schema,
                event_token=record.event_token,
                lease_id=record.lease_id,
                purpose=record.purpose,
                broker_allowed=record.allowed,
                reason_code=record.reason_code,
                gateway_attested=record.gateway_attested,
                observed_at_ms=record.observed_at_ms,
                raw_process_user_dns_and_ip_omitted=True,
                observation_only=True,
                enforcement_performed=False,
                external_enforcer_required=True,
                response_authorized=False,
                response_authority="observe-only",
            )

    def run(self) -> None:
        while not self.stopping:
            self._tick()
            self.sleep(POLL_INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        now = [1_800_000_000.0]
        process = ProcessIdentity(4512, "a" * 64, "b" * 64, "c" * 64)
        path = GatewayPathIdentity("tok_" + "d" * 24, True)
        broker = ProcessEgressLeaseBroker(
            b"process-egress-self-test-key-000",
            process_observer=lambda pid: process if pid == process.pid else None,
            path_observer=lambda token: path if token == path.path_token else None,
            clock=lambda: now[0],
            nonce_factory=lambda: b"self-test-lease-nonce-0000000000",
        )
        try:
            lease = broker.issue(
                pid=process.pid,
                purpose="release-update",
                dns_name="updates.invalid",
                destination_ip="203.0.113.7",
                destination_port=443,
                protocol="tcp",
                path_token=path.path_token,
                max_connections=1,
                max_bytes=4096,
            )
            attempt = EgressAttempt(
                process.pid,
                "updates.invalid",
                "203.0.113.7",
                443,
                "tcp",
                path.path_token,
                "e" * 64,
                1024,
            )
            admitted = broker.authorize(lease, attempt)
            replay = broker.authorize(lease, attempt)
            audit = broker.drain_audit()
        except Exception as exc:
            return False, f"process egress self-test failed: {type(exc).__name__}"
        representation = repr(audit)
        if not admitted.allowed or replay.reason_code != "connection-replay":
            return False, "connection admission/replay boundary did not fail closed"
        if "updates.invalid" in representation or "203.0.113.7" in representation:
            return False, "egress audit retained raw DNS or IP data"
        if any(record.enforcement_performed for record in audit.records):
            return False, "observation layer claimed connection enforcement"
        return True, (
            "process/start/user/DNS/IP/path binding, one-use budget, replay denial, "
            "and sanitized observe-only audit verified"
        )


def register() -> ProcessEgressGuardModule:
    return ProcessEgressGuardModule()


__all__ = [
    "ProcessEgressGuardModule",
    "register",
    "unavailable_audit_observer",
]
