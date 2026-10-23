import base64
from dataclasses import replace
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.approval_identity import ApprovalIdentityVerifier, PrincipalCredential, SignedPrincipalProof
from angerona.core.authorization import AuthorizationPolicy, AuthorizationRequest, Principal, PrincipalKind, Role, RoleBinding


def setup_identity(subject="user-1", seed="one", alias="credential-one"):
    private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())
    record = PrincipalCredential(alias, "fixture-issuer", subject,
        private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return record, private


def proof(record, private, digest):
    unsigned = SignedPrincipalProof.unsigned(record, digest, 100, 200, "1" * 32)
    return replace(unsigned, signature=base64.urlsafe_b64encode(private.sign(unsigned.signing_bytes())).decode().rstrip("="))


def test_authenticated_dispatch_requires_backend_binding_and_exact_credential_proof():
    record, private = setup_identity()
    verifier = ApprovalIdentityVerifier([record], clock=lambda: 110)
    inputs = dict(principals=[Principal("alice", PrincipalKind.HUMAN)],
                  roles=[Role("analyst", ("case.read",))],
                  bindings=[RoleBinding("alice", "analyst", "fleet/acme")], audit_key=b"a" * 32)
    policy = AuthorizationPolicy(**inputs)
    request = AuthorizationRequest("request-001", "alice", "case.read", "fleet/acme")
    assert policy.decide(request, now=110).allowed  # Policy inspection is not an operator login.
    with pytest.raises(PermissionError, match="binding unavailable"):
        policy.decide_authenticated(request, "alice", now=110)
    policy = AuthorizationPolicy(**inputs, identity_verifier=verifier,
                                 credential_bindings={"alice": record.credential_id})
    signed = proof(record, private, policy.authentication_digest(request))
    decision = policy.decide_authenticated(request, signed, now=110)
    assert decision.allowed and policy.verify_decision(decision)
    with pytest.raises(PermissionError):
        policy.decide_authenticated(replace(request, request_id="request-002"), signed, now=110)
    verifier.revoke(record.credential_id)
    with pytest.raises(PermissionError, match="revoked"):
        policy.decide_authenticated(request, signed, now=110)


@pytest.mark.parametrize("same_key,same_subject", [(True, False), (False, True)])
def test_separation_of_duties_applies_across_authenticated_aliases(same_key, same_subject):
    one, _ = setup_identity()
    two, _ = setup_identity(subject="user-1" if same_subject else "user-2",
                            seed="one" if same_key else "two", alias="credential-two")
    with pytest.raises(ValueError, match="separation-of-duty"):
        AuthorizationPolicy(
            [Principal("alias-one", PrincipalKind.HUMAN), Principal("alias-two", PrincipalKind.HUMAN)],
            [Role("auditor", ("audit.read",)), Role("responder", ("response.approve",))],
            [RoleBinding("alias-one", "auditor", "fleet/acme"),
             RoleBinding("alias-two", "responder", "fleet/acme")], b"a" * 32,
            identity_verifier=ApprovalIdentityVerifier([one, two]),
            credential_bindings={"alias-one": one.credential_id, "alias-two": two.credential_id})
