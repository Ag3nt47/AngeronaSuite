from __future__ import annotations

import pytest

from angerona.core.authorization import (
    AuthorizationPolicy, AuthorizationRequest, Principal, PrincipalKind, Role, RoleBinding,
)


@pytest.mark.parametrize("identity", [None, 1, True, "", " ", "operator\n", "a" * 161])
def test_principal_id_rejects_noncanonical_configuration_without_type_errors(identity):
    with pytest.raises(ValueError, match="principal ID"):
        Principal(identity, PrincipalKind.HUMAN)


@pytest.mark.parametrize("kind", [None, 0, "human", "service", "unsupported"])
def test_principal_kind_requires_the_supported_enum(kind):
    with pytest.raises(ValueError, match="typed enum"):
        Principal("operator", kind)


@pytest.mark.parametrize("enabled", [None, 0, 1, "false", "true", [], {}])
def test_principal_enabled_never_coerces_trusted_configuration_values(enabled):
    with pytest.raises(ValueError, match="boolean"):
        Principal("operator", PrincipalKind.HUMAN, enabled=enabled)


@pytest.mark.parametrize("enabled", [False, True])
def test_canonical_enabled_boolean_preserves_actual_policy_admission(enabled):
    principal = Principal("operator", PrincipalKind.HUMAN, enabled=enabled)
    policy = AuthorizationPolicy([principal], [Role("reader", ("posture.read",))],
        [RoleBinding("operator", "reader", "tenant")], b"i" * 32)
    decision = policy.decide(AuthorizationRequest("request-1", "operator", "posture.read", "tenant"), now=100)
    assert decision.allowed is enabled
    assert decision.principal_kind == "human"
