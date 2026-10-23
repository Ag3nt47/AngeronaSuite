import base64
from dataclasses import replace
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.approval_identity import (
    ApprovalIdentityVerifier, PrincipalCredential, SignedPrincipalProof,
    VerifiedPrincipal, bind_current_os_credential, current_os_identity,
    independent_principals,
)

DIGEST = "a" * 64


def key(seed):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


def credential(alias, subject, signing_key):
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return PrincipalCredential(alias, "fixture-issuer", subject, public)


def signed(record, signing_key, digest=DIGEST, issued=100, expires=200):
    unsigned = SignedPrincipalProof.unsigned(record, digest, issued, expires, "1" * 32)
    return replace(unsigned, signature=base64.urlsafe_b64encode(signing_key.sign(unsigned.signing_bytes())).decode().rstrip("="))


def test_signature_exact_digest_subject_key_and_lifetime_are_verified():
    private = key("first")
    record = credential("alice", "subject-1", private)
    verifier = ApprovalIdentityVerifier([record], clock=lambda: 110)
    proof = signed(record, private)
    verified = verifier.verify(proof, DIGEST)
    assert verified.principal_id == record.principal_id
    for changed in (replace(proof, purpose_digest="b" * 64), replace(proof, subject="other"),
                    replace(proof, signature="A" * 86), replace(proof, expires_at=109)):
        with pytest.raises(PermissionError):
            verifier.verify(changed, DIGEST)
    with pytest.raises(PermissionError):
        verifier.verify(proof, DIGEST, now=200)
    with pytest.raises(PermissionError, match="labels"):
        verifier.verify("alice", DIGEST)
    with pytest.raises(TypeError, match="trusted verifier"):
        VerifiedPrincipal(record, 200)


def test_aliases_key_rotation_and_real_os_sid_count_once(monkeypatch):
    first, rotated, other = key("first"), key("rotated"), key("other")
    native = current_os_identity()
    monkeypatch.setenv("USERNAME", "attacker-supplied-name")
    assert current_os_identity() == native
    records = [bind_current_os_credential("alias-one", credential("x", "x", first).public_key),
               bind_current_os_credential("alias-two", credential("y", "y", rotated).public_key)]
    assert records[0].principal_id == records[1].principal_id
    assert records[0].subject == native.subject
    verifier = ApprovalIdentityVerifier(records, clock=lambda: 110)
    verified = [verifier.verify(signed(record, signing), DIGEST) for record, signing in zip(records, [first, rotated])]
    assert len(independent_principals(verified)) == 1
    second_subject = credential("different-subject-same-key", "other-subject", first)
    independent = credential("independent", "third-subject", other)
    verifier = ApprovalIdentityVerifier([*records, second_subject, independent], clock=lambda: 110)
    one_key = [verifier.verify(signed(record, first), DIGEST) for record in [records[0], second_subject]]
    assert len(independent_principals(one_key)) == 1
    assert len(independent_principals([*one_key, verifier.verify(signed(independent, other), DIGEST)])) == 2


def test_revocation_covers_key_aliases_and_rebinding_invalidates_old_proof():
    private = key("first")
    one = credential("one", "user-1", private)
    two = credential("two", "user-1", private)
    verifier = ApprovalIdentityVerifier([one, two], clock=lambda: 110)
    verifier.revoke("one")
    with pytest.raises(PermissionError, match="revoked"):
        verifier.verify(signed(two, private), DIGEST)
    rebound = replace(one, subject="new-user")
    changed_policy = ApprovalIdentityVerifier([rebound], clock=lambda: 110)
    with pytest.raises(PermissionError):
        changed_policy.verify(signed(one, private), DIGEST)


def test_matching_does_not_lose_valid_independent_pair_during_rotation():
    first, second = key("first"), key("second")
    records = [credential("a", "user-1", first), credential("b", "user-1", second),
               credential("c", "user-2", first)]
    verifier = ApprovalIdentityVerifier(records, clock=lambda: 110)
    verified = [verifier.verify(signed(record, signing), DIGEST)
                for record, signing in zip(records, [first, second, first])]
    assert len(independent_principals(verified)) == 2


def test_sid_alternate_spelling_is_not_an_independent_principal():
    public = credential("one", "one", key("one")).public_key
    with pytest.raises(ValueError, match="canonical SID"):
        PrincipalCredential("one", "windows-token", "S-1-05-21-123", public)
