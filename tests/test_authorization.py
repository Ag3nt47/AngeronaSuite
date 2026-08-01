from angerona.core.authorization import (
    AuthorizationPolicy, AuthorizationRequest, Principal, PrincipalKind, Role,
    RoleBinding, STANDARD_ROLES, STANDARD_ROLES_BY_ID,
)
import math
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


@pytest.mark.parametrize("expiry", [math.nan, math.inf, -math.inf, True, 0])
def test_service_account_requires_finite_positive_expiry(expiry):
    with pytest.raises(ValueError, match="expiry|explicit expiry"):
        Principal("service:bad", PrincipalKind.SERVICE, expires_at=expiry)


def test_cached_service_allow_is_not_execution_authority_after_expiry():
    engine = policy()
    request = AuthorizationRequest(
        "expiring", "sensor:one", "evidence.append", "fleet/acme/host-1"
    )
    allowed = engine.decide(request, now=100)
    denied = engine.decide(request, now=201)
    assert allowed.allowed and allowed.valid_until == 200
    assert not denied.allowed and denied.reason == "principal expired"
    assert denied != allowed
    assert engine.verify_decision(allowed)
    assert engine.verify_decision(denied)


@pytest.mark.parametrize("now", [math.nan, math.inf, -math.inf, -1])
def test_authorization_rejects_invalid_decision_clock(now):
    with pytest.raises(ValueError, match="time"):
        policy().decide(
            AuthorizationRequest("bad-time", "alice", "case.read", "fleet/acme"),
            now=now,
        )


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


def test_policy_inputs_are_immutable_after_policy_hash_is_computed():
    engine = policy()
    original_hash = engine.policy_hash
    with pytest.raises(TypeError):
        engine.roles["backdoor"] = Role("backdoor", ("case.delete",))
    with pytest.raises(TypeError):
        engine.principals["mallory"] = Principal(
            "mallory", PrincipalKind.HUMAN
        )
    assert engine.policy_hash == original_hash
    assert not engine.decide(
        AuthorizationRequest("immutable", "alice", "case.delete", "fleet/acme"),
        now=100,
    ).allowed


@pytest.mark.parametrize("scope", (
    "fleet/acme/../other", "fleet/acme//other", "fleet/acme/.",
    "/fleet/acme", "fleet/acme/",
))
def test_noncanonical_scopes_are_rejected(scope):
    with pytest.raises(ValueError, match="scope"):
        AuthorizationRequest("r", "alice", "case.read", scope)


def test_standard_enterprise_roles_are_complete_and_default_deny():
    assert set(STANDARD_ROLES_BY_ID) == {
        "viewer", "analyst", "hunter", "responder", "detection-engineer",
        "fleet-operator", "tenant-administrator", "platform-administrator",
        "auditor",
    }
    engine = AuthorizationPolicy(
        (Principal("viewer-one", PrincipalKind.HUMAN),),
        STANDARD_ROLES,
        (RoleBinding("viewer-one", "viewer", "fleet/acme"),),
        KEY,
    )
    assert engine.decide(AuthorizationRequest(
        "view-1", "viewer-one", "inventory.read", "fleet/acme"
    ), now=1).allowed
    denied = engine.decide(AuthorizationRequest(
        "view-2", "viewer-one", "response.execute", "fleet/acme"
    ), now=1)
    assert not denied.allowed
    assert denied.reason == "no matching role permission"


def test_separation_of_duties_rejects_overlapping_privileged_bindings():
    principal = Principal("dual-role", PrincipalKind.HUMAN)
    with pytest.raises(ValueError, match="separation-of-duty"):
        AuthorizationPolicy(
            (principal,),
            STANDARD_ROLES,
            (
                RoleBinding("dual-role", "auditor", "fleet/acme"),
                RoleBinding(
                    "dual-role", "platform-administrator", "fleet/acme/group-a"
                ),
            ),
            KEY,
        )
    with pytest.raises(ValueError, match="separation-of-duty"):
        AuthorizationPolicy(
            (principal,),
            STANDARD_ROLES,
            (
                RoleBinding("dual-role", "detection-engineer", "fleet/acme"),
                RoleBinding("dual-role", "tenant-administrator", "fleet/acme"),
            ),
            KEY,
        )


def test_separation_of_duties_allows_distinct_nonoverlapping_scopes():
    principal = Principal("regional-role", PrincipalKind.HUMAN)
    engine = AuthorizationPolicy(
        (principal,),
        STANDARD_ROLES,
        (
            RoleBinding("regional-role", "auditor", "fleet/east"),
            RoleBinding("regional-role", "platform-administrator", "fleet/west"),
        ),
        KEY,
    )
    assert engine.decide(AuthorizationRequest(
        "audit-east", "regional-role", "audit.read", "fleet/east"
    ), now=1).allowed
    assert engine.decide(AuthorizationRequest(
        "configure-west", "regional-role", "platform.configure", "fleet/west"
    ), now=1).allowed
