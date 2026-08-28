from __future__ import annotations

import json
from dataclasses import replace

import pytest

from angerona.core.eventbus import EventBus
from angerona.core.process_egress_lease import (
    EGRESS_PURPOSES,
    EgressAttempt,
    EgressAuditBatch,
    EgressLease,
    EgressLeaseRejected,
    GatewayPathIdentity,
    MAX_BYTE_BUDGET,
    MAX_CONNECTIONS,
    MAX_TTL_SECONDS,
    ProcessEgressLeaseBroker,
    ProcessIdentity,
    opaque_identity_token,
)
from angerona.modules.process_egress_guard import ProcessEgressGuardModule


KEY = b"process-egress-test-authority-01"
PATH = "tok_" + "d" * 24


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def identity(
    *,
    pid: int = 4100,
    executable: str = "a" * 64,
    start: str = "b" * 64,
    user: str = "c" * 64,
) -> ProcessIdentity:
    return ProcessIdentity(pid, executable, start, user)


def make_broker(*, gateway_attested: bool = True, clock: Clock | None = None):
    current = {"process": identity(), "path": GatewayPathIdentity(PATH, gateway_attested)}
    broker = ProcessEgressLeaseBroker(
        KEY,
        process_observer=lambda pid: (
            current["process"] if current["process"].pid == pid else None
        ),
        path_observer=lambda token: current["path"] if token == PATH else None,
        clock=clock or Clock(),
        nonce_factory=lambda: b"deterministic-test-nonce-00000000",
    )
    return broker, current


def issue(broker: ProcessEgressLeaseBroker, **overrides) -> EgressLease:
    values = {
        "pid": 4100,
        "purpose": "release-update",
        "dns_name": "updates.example.test",
        "destination_ip": "203.0.113.44",
        "destination_port": 443,
        "protocol": "tcp",
        "path_token": PATH,
        "ttl_seconds": 60,
        "max_connections": 2,
        "max_bytes": 4096,
    }
    values.update(overrides)
    return broker.issue(**values)


def attempt(**overrides) -> EgressAttempt:
    values = {
        "pid": 4100,
        "dns_name": "updates.example.test",
        "destination_ip": "203.0.113.44",
        "destination_port": 443,
        "protocol": "tcp",
        "path_token": PATH,
        "connection_nonce": "e" * 64,
        "requested_bytes": 1024,
    }
    values.update(overrides)
    return EgressAttempt(**values)


def test_lease_is_hmac_authenticated_canonical_and_omits_raw_identity_and_dns():
    broker, _ = make_broker()
    lease = issue(broker)
    payload = lease.to_json()

    assert EgressLease.from_json(payload) == lease
    assert payload == json.dumps(
        json.loads(payload), sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    assert b"updates.example.test" not in payload
    assert b"raw-user" not in payload
    assert lease.expires_at_ms - lease.issued_at_ms <= MAX_TTL_SECONDS * 1000

    with pytest.raises(EgressLeaseRejected):
        EgressLease.from_json(b" " + payload)
    document = lease.to_dict()
    document["unexpected"] = True
    with pytest.raises(EgressLeaseRejected):
        EgressLease.from_mapping(document)


def test_tampering_a_valid_field_breaks_the_mac_and_fails_closed():
    broker, _ = make_broker()
    lease = issue(broker)
    forged = replace(lease, executable_sha256="f" * 64)

    decision = broker.authorize(forged, attempt())

    assert decision.allowed is False
    assert decision.reason_code == "lease-invalid"
    assert decision.enforcement_performed is False


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"pid": 4200}, "process-id-mismatch"),
        ({"dns_name": "rebound.example.test"}, "dns-pin-mismatch"),
        ({"destination_ip": "203.0.113.45"}, "destination-ip-mismatch"),
        ({"destination_port": 8443}, "destination-port-mismatch"),
        ({"protocol": "udp"}, "protocol-mismatch"),
        ({"path_token": "tok_" + "f" * 24}, "path-token-mismatch"),
    ],
)
def test_every_connection_dimension_is_bound(override, reason):
    broker, _ = make_broker()
    lease = issue(broker)

    decision = broker.authorize(lease, attempt(**override))

    assert decision.allowed is False
    assert decision.reason_code == reason


@pytest.mark.parametrize(
    ("replacement", "reason"),
    [
        (identity(start="9" * 64), "pid-reuse-detected"),
        (identity(executable="8" * 64), "process-executable-mismatch"),
        (identity(user="7" * 64), "user-token-mismatch"),
    ],
)
def test_current_os_process_observation_detects_pid_reuse_and_identity_swap(
    replacement, reason
):
    broker, current = make_broker()
    lease = issue(broker)
    current["process"] = replacement

    decision = broker.authorize(lease, attempt())

    assert decision.allowed is False
    assert decision.reason_code == reason


def test_gateway_attestation_is_required_at_issue_and_rechecked_at_use():
    untrusted_broker, _ = make_broker(gateway_attested=False)
    with pytest.raises(EgressLeaseRejected, match="gateway-attested"):
        issue(untrusted_broker)

    broker, current = make_broker()
    lease = issue(broker)
    current["path"] = GatewayPathIdentity(PATH, False)
    decision = broker.authorize(lease, attempt())

    assert decision.allowed is False
    assert decision.reason_code == "gateway-attestation-required"


def test_connection_nonce_replay_and_connection_budget_are_atomic():
    broker, _ = make_broker()
    lease = issue(broker, max_connections=1)

    admitted = broker.authorize(lease, attempt())
    replay = broker.authorize(lease, attempt())
    exhausted = broker.authorize(
        lease, attempt(connection_nonce="f" * 64)
    )

    assert admitted.allowed is True
    assert admitted.remaining_connections == 0
    assert replay.reason_code == "connection-replay"
    assert exhausted.reason_code == "connection-budget-exhausted"


def test_byte_reservations_cannot_exceed_the_signed_budget():
    broker, _ = make_broker()
    lease = issue(broker, max_connections=2, max_bytes=100)

    first = broker.authorize(lease, attempt(requested_bytes=80))
    second = broker.authorize(
        lease,
        attempt(connection_nonce="f" * 64, requested_bytes=21),
    )

    assert first.allowed is True
    assert first.remaining_bytes == 20
    assert second.reason_code == "byte-budget-exhausted"


def test_expiry_and_clock_rollback_are_denied_and_rollback_is_sticky():
    clock = Clock(1_800_000_000.0)
    broker, _ = make_broker(clock=clock)
    lease = issue(broker, ttl_seconds=2)
    clock.value += 3
    assert broker.authorize(lease, attempt()).reason_code == "lease-expired"

    newer = issue(broker)
    clock.value -= 3
    rolled_back = broker.authorize(
        newer, attempt(connection_nonce="f" * 64)
    )
    clock.value += 20
    still_quarantined = broker.authorize(
        newer, attempt(connection_nonce="9" * 64)
    )
    assert rolled_back.reason_code == "clock-rollback"
    assert still_quarantined.reason_code == "clock-rollback"


def test_signed_lease_is_not_replayable_into_a_fresh_broker_state():
    broker, _ = make_broker()
    lease = issue(broker)
    replacement, _ = make_broker()

    decision = replacement.authorize(lease, attempt())

    assert decision.reason_code == "unknown-lease"


def test_closed_purpose_ttl_and_budget_catalogs_reject_ambient_authority():
    broker, _ = make_broker()
    assert "arbitrary-web" not in EGRESS_PURPOSES
    with pytest.raises(EgressLeaseRejected, match="closed catalog"):
        issue(broker, purpose="arbitrary-web")
    with pytest.raises(EgressLeaseRejected, match="TTL"):
        issue(broker, ttl_seconds=MAX_TTL_SECONDS + 1)
    with pytest.raises(EgressLeaseRejected, match="connection budget"):
        issue(broker, max_connections=MAX_CONNECTIONS + 1)
    with pytest.raises(EgressLeaseRejected, match="byte budget"):
        issue(broker, max_bytes=MAX_BYTE_BUDGET + 1)


def test_identity_token_helper_is_keyed_and_purpose_separated():
    first = opaque_identity_token(KEY, "process-start", "pid=4100;start=123")
    second = opaque_identity_token(KEY, "user", "pid=4100;start=123")
    assert first != second
    assert len(first) == len(second) == 64
    assert "4100" not in first


def test_observation_module_reports_sanitized_audit_without_claiming_enforcement():
    broker, _ = make_broker()
    lease = issue(broker, max_connections=1)
    broker.authorize(lease, attempt())
    broker.authorize(lease, attempt())
    module = ProcessEgressGuardModule(audit_observer=broker.drain_audit)
    bus = EventBus()
    module.bind(bus)

    module._tick()
    events = bus.recent()

    assert events
    assert module.health == 100
    assert any(event.details.get("reason_code") == "connection-replay" for event in events)
    assert all(event.details.get("enforcement_performed") is False for event in events)
    assert all(event.details.get("response_authorized") is False for event in events)
    assert "updates.example.test" not in repr(events)
    assert "203.0.113.44" not in repr(events)
    assert module.self_test()[0] is True


def test_unconnected_module_reports_incomplete_coverage_instead_of_health():
    module = ProcessEgressGuardModule()
    bus = EventBus()
    module.bind(bus)

    module._tick()

    assert module.health < 50
    assert bus.recent(1)[0].details["audit_complete"] is False


def test_audit_observer_contract_violation_fails_toward_unknown():
    module = ProcessEgressGuardModule(
        audit_observer=lambda: EgressAuditBatch((), False, 0, "test-gap")
    )
    module._tick()
    assert module.health == 45
