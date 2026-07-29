from angerona.core.authorization import (
    AuthorizationPolicy, AuthorizationRequest, Principal, PrincipalKind, Role,
    RoleBinding,
)
import pytest


KEY = b"a" * 32


def policy():
    return AuthorizationPolicy(
        principals=(
            Principal("alice", PrincipalKind.HUMAN),
            Principal("sensor:one", PrincipalKind.SERVICE, expires_at=200),
        ),
        roles=(
            Role("analyst", ("case.read", "case.comment"), ("case.delete",)),
            Role("automation", ("evidence.append",)),
        ),
        bindings=(
            RoleBinding("alice", "analyst", "fleet/acme"),
            RoleBinding("sensor:one", "automation", "fleet/acme/host-1"),
        ),
        audit_key=KEY,
    )


def test_scope_and_permission_allow_with_authenticated_receipt():
    engine = policy()
    decision = engine.decide(
        AuthorizationRequest("r1", "alice", "case.read", "fleet/acme/group-a"),
        now=100,
    )
    assert decision.allowed
    assert decision.matched_roles == ("analyst",)
    assert engine.verify_decision(decision)


def test_explicit_deny_wins_and_scope_does_not_escape():
    engine = policy()
    denied = engine.decide(
        AuthorizationRequest("r1", "alice", "case.delete", "fleet/acme"), now=100
    )
    outside = engine.decide(
        AuthorizationRequest("r2", "alice", "case.read", "fleet/other"), now=100
    )
    assert not denied.allowed and denied.reason == "explicit deny"
    assert not outside.allowed


def test_service_account_requires_and_enforces_expiry():
    engine = policy()
    allowed = engine.decide(
        AuthorizationRequest(
            "r1", "sensor:one", "evidence.append", "fleet/acme/host-1"
        ), now=100,
    )
    expired = engine.decide(
        AuthorizationRequest(
            "r2", "sensor:one", "evidence.append", "fleet/acme/host-1"
        ), now=201,
    )
    assert allowed.allowed
    assert not expired.allowed and expired.reason == "principal expired"


def test_wildcard_is_bounded_and_receipt_tampering_detected():
    engine = AuthorizationPolicy(
        (Principal("admin", PrincipalKind.HUMAN),),
        (Role("viewer", ("inventory.*",)),),
        (RoleBinding("admin", "viewer", "fleet"),), KEY,
    )
    decision = engine.decide(
        AuthorizationRequest("r", "admin", "inventory.read", "fleet/host"), now=1
    )
    assert decision.allowed
    from dataclasses import replace
    assert not engine.verify_decision(replace(decision, allowed=False))
    assert not engine.verify_decision(replace(decision, scope="fleet/other"))


def test_receipt_binds_every_operation_field_and_request_id_is_idempotent():
    engine = policy()
    request = AuthorizationRequest(
        "bound", "alice", "case.read", "fleet/acme", "case-1"
    )
    first = engine.decide(request, now=10)
    assert engine.decide(request, now=999) == first
    assert first.principal_id == "alice"
    assert first.permission == "case.read"
    assert first.scope == "fleet/acme"
    assert first.resource_id == "case-1"
    with pytest.raises(ValueError, match="already bound"):
        engine.decide(
            AuthorizationRequest(
                "bound", "alice", "case.comment", "fleet/acme", "case-1"
            ),
            now=10,
        )


@pytest.mark.parametrize("scope", (
    "fleet/acme/../other", "fleet/acme//other", "fleet/acme/.",
    "/fleet/acme", "fleet/acme/",
))
def test_noncanonical_scopes_are_rejected(scope):
    with pytest.raises(ValueError, match="scope"):
        AuthorizationRequest("r", "alice", "case.read", scope)
