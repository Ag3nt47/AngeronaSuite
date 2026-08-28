from __future__ import annotations

import copy

import pytest

from angerona.core.response_capability import (
    MAX_TTL_NS,
    CapabilityError,
    PrivilegedOpcode,
    ResponseCapabilityAuthority,
)


class Clock:
    def __init__(self, value: int = 50_000_000_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


PARAMETERS = {"interface_id": "ethernet-1", "reason_code": "confirmed-c2"}


def _issue(authority: ResponseCapabilityAuthority):
    return authority.issue(
        PrivilegedOpcode.NETWORK_ISOLATE,
        "interface/ethernet-1",
        PARAMETERS,
        ttl_ns=1_000_000,
    )


def _consume(authority: ResponseCapabilityAuthority, document):
    return authority.consume(
        document,
        opcode=PrivilegedOpcode.NETWORK_ISOLATE,
        resource="interface/ethernet-1",
        parameters=PARAMETERS,
    )


def test_authority_is_unconfigured_without_an_explicit_secret() -> None:
    authority = ResponseCapabilityAuthority()

    assert authority.health().state == "unconfigured"
    with pytest.raises(CapabilityError) as caught:
        _issue(authority)
    assert caught.value.code == "unconfigured"
    with pytest.raises(ValueError):
        ResponseCapabilityAuthority(b"too-short")
    production_without_state = ResponseCapabilityAuthority(b"a" * 32)
    assert production_without_state.health().state == "unconfigured"
    assert production_without_state.health().reason == "durable-state-not-provisioned"


def test_capability_is_single_use_monotonic_and_exactly_action_scoped() -> None:
    clock = Clock()
    authority = ResponseCapabilityAuthority(b"a" * 32, clock_ns=clock, test_only=True)
    token = _issue(authority)

    verified = _consume(authority, token)

    assert verified.sequence == 1
    assert verified.opcode is PrivilegedOpcode.NETWORK_ISOLATE
    assert authority.health().consumed_sequence == 1
    with pytest.raises(CapabilityError) as caught:
        _consume(authority, token)
    assert caught.value.code == "replay"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("opcode", PrivilegedOpcode.NETWORK_RESTORE, "scope"),
        ("resource", "interface/ethernet-2", "scope"),
        ("parameters", {"interface_id": "ethernet-2"}, "scope"),
    ],
)
def test_capability_cannot_authorize_a_different_action(field, value, code) -> None:
    clock = Clock()
    authority = ResponseCapabilityAuthority(b"a" * 32, clock_ns=clock, test_only=True)
    token = _issue(authority)
    kwargs = {
        "opcode": PrivilegedOpcode.NETWORK_ISOLATE,
        "resource": "interface/ethernet-1",
        "parameters": PARAMETERS,
    }
    kwargs[field] = value

    with pytest.raises(CapabilityError) as caught:
        authority.consume(token, **kwargs)
    assert caught.value.code == code
    # A mismatched attempt does not burn the valid token.
    assert _consume(authority, token).sequence == 1


def test_tamper_unknown_opcode_expiry_and_ttl_bounds_are_rejected() -> None:
    clock = Clock()
    authority = ResponseCapabilityAuthority(b"a" * 32, clock_ns=clock, test_only=True)
    token = _issue(authority)
    tampered = copy.deepcopy(token)
    tampered["payload"]["resource"] = "interface/ethernet-2"
    with pytest.raises(CapabilityError) as caught:
        authority.consume(
            tampered,
            opcode=PrivilegedOpcode.NETWORK_ISOLATE,
            resource="interface/ethernet-2",
            parameters=PARAMETERS,
        )
    assert caught.value.code == "authentication"

    unknown = copy.deepcopy(token)
    unknown["payload"]["opcode"] = "shell.execute"
    with pytest.raises(CapabilityError) as caught:
        _consume(authority, unknown)
    assert caught.value.code == "opcode"

    clock.value += 1_000_000
    with pytest.raises(CapabilityError) as caught:
        _consume(authority, token)
    assert caught.value.code == "expired"

    with pytest.raises(CapabilityError) as caught:
        authority.issue(
            PrivilegedOpcode.AUDIT_APPEND,
            "audit/security",
            {},
            ttl_ns=MAX_TTL_NS + 1,
        )
    assert caught.value.code == "bounds"


def test_consuming_newer_sequence_invalidates_older_outstanding_token() -> None:
    clock = Clock()
    authority = ResponseCapabilityAuthority(b"a" * 32, clock_ns=clock, test_only=True)
    older = _issue(authority)
    newer = _issue(authority)

    assert _consume(authority, newer).sequence == 2
    with pytest.raises(CapabilityError) as caught:
        _consume(authority, older)
    assert caught.value.code == "replay"


def test_clock_rollback_degrades_authority_and_blocks_future_use() -> None:
    clock = Clock()
    authority = ResponseCapabilityAuthority(b"a" * 32, clock_ns=clock, test_only=True)
    token = _issue(authority)
    clock.value -= 1

    with pytest.raises(CapabilityError) as caught:
        _consume(authority, token)
    assert caught.value.code == "clock-rollback"
    assert authority.health().state == "degraded"


def test_parameter_and_resource_bounds_do_not_admit_generic_commands() -> None:
    authority = ResponseCapabilityAuthority(b"a" * 32, test_only=True)
    with pytest.raises(CapabilityError) as caught:
        authority.issue("shell.execute", "host/local", {})
    assert caught.value.code == "opcode"
    with pytest.raises(CapabilityError) as caught:
        authority.issue(PrivilegedOpcode.AUDIT_APPEND, "../audit", {})
    assert caught.value.code == "resource"
    with pytest.raises(CapabilityError) as caught:
        authority.issue(
            PrivilegedOpcode.AUDIT_APPEND,
            "audit/security",
            {"message": "x" * 3000},
        )
    assert caught.value.code == "bounds"


def test_durable_epoch_rejects_consumed_token_after_authority_restart(tmp_path) -> None:
    clock = Clock()
    state = tmp_path / "capability-state.json"
    first = ResponseCapabilityAuthority(b"a" * 32, state_path=state, clock_ns=clock)
    token = _issue(first)
    assert _consume(first, token).sequence == 1
    first.close()

    restarted = ResponseCapabilityAuthority(b"a" * 32, state_path=state, clock_ns=clock)
    try:
        assert restarted.health().reason == "durable-epoch-bound-authority-ready"
        with pytest.raises(CapabilityError) as caught:
            _consume(restarted, token)
        assert caught.value.code == "epoch"
        assert restarted.health().consumed_sequence == 1
    finally:
        restarted.close()


def test_durable_authority_lease_rejects_a_second_live_writer(tmp_path) -> None:
    state = tmp_path / "capability-state.json"
    first = ResponseCapabilityAuthority(b"a" * 32, state_path=state)
    try:
        with pytest.raises(Exception, match="lease"):
            ResponseCapabilityAuthority(b"a" * 32, state_path=state)
    finally:
        first.close()


def test_deleted_durable_state_is_not_treated_as_first_enrollment(tmp_path) -> None:
    state = tmp_path / "capability-state.json"
    first = ResponseCapabilityAuthority(b"a" * 32, state_path=state)
    first.close()
    state.unlink()

    with pytest.raises(CapabilityError, match="missing after enrollment"):
        ResponseCapabilityAuthority(b"a" * 32, state_path=state)
