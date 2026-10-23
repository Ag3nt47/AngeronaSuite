import base64
import dataclasses
import hashlib
import math
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.policy_bundle import (
    PolicyApproval,
    PolicyBundle,
    PolicyLayer,
    PolicyManager,
    RolloutState,
)
from angerona.core.approval_identity import PrincipalCredential, SignedPrincipalProof


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def authenticated_approval(record, key, body, expires):
    unsigned = SignedPrincipalProof.unsigned(record, hashlib.sha256(body).hexdigest(),
        expires - 100, expires, hashlib.sha256(record.credential_id.encode()).hexdigest()[:32])
    proof = dataclasses.replace(unsigned, signature=b64(key.sign(unsigned.signing_bytes())))
    return PolicyApproval(record.credential_id, proof.signature, proof)


def signed(key, **changes):
    data = dict(
        bundle_id="b1",
        version=1,
        publisher_id="publisher",
        channel="configuration",
        layer=PolicyLayer.FLEET,
        settings=(("sensor.enabled", True),),
        locked_keys=(),
        rollout=RolloutState.STAGED,
        expires_at=time.time() + 100,
    )
    data.update(changes)
    unsigned = PolicyBundle(**data)
    return PolicyBundle(**data, signature=b64(key.sign(unsigned.canonical_signed())))


def test_signed_bundle_and_invalid_update_fall_back_to_lkg():
    publisher = Ed25519PrivateKey.generate()
    manager = PolicyManager({"publisher": public(publisher)})
    good = signed(publisher)
    assert manager.submit(good)[0]
    bad = signed(publisher, bundle_id="b2", version=2)
    bad = PolicyBundle(**{**bad.__dict__, "signature": "bad"})
    assert not manager.submit(bad)[0]
    assert manager.effective("configuration").bundle_ids == ("b1",)


def test_forged_changed_and_expired_policy_bundles_fail_closed():
    publisher = Ed25519PrivateKey.generate()
    manager = PolicyManager({"publisher": public(publisher)})
    original = signed(publisher, expires_at=200)
    forged = dataclasses.replace(
        original,
        settings=(("sensor.enabled", False),),
    )
    assert manager.submit(forged, now=100) == (
        False,
        "publisher signature invalid",
    )
    expired = signed(
        publisher,
        bundle_id="expired",
        version=2,
        expires_at=100,
    )
    assert manager.submit(expired, now=100) == (False, "bundle expired")
    assert manager.submit(original, now=math.nan) == (
        False,
        "policy verification time is invalid",
    )
    with pytest.raises(ValueError, match="expiry"):
        signed(publisher, expires_at=math.nan)


def test_precedence_locks_and_channel_separation():
    publisher = Ed25519PrivateKey.generate()
    manager = PolicyManager({"publisher": public(publisher)})
    fleet = signed(
        publisher,
        bundle_id="fleet",
        settings=(("x", 1),),
        locked_keys=("x",),
    )
    group = signed(
        publisher,
        bundle_id="group",
        layer=PolicyLayer.GROUP,
        settings=(("x", 2), ("y", 2)),
    )
    detection = signed(
        publisher,
        bundle_id="detect",
        channel="detection",
        settings=(("rule", "on"),),
    )
    for item in (fleet, group, detection):
        assert manager.submit(item)[0]
    effective = manager.effective("configuration")
    assert dict(effective.settings) == {"x": 1, "y": 2}
    assert dict(manager.effective("detection").settings) == {"rule": "on"}


def test_dry_run_does_not_mutate_and_reports_blocked_lock():
    publisher = Ed25519PrivateKey.generate()
    manager = PolicyManager({"publisher": public(publisher)})
    fleet = signed(
        publisher,
        bundle_id="fleet",
        settings=(("x", 1),),
        locked_keys=("x",),
    )
    manager.submit(fleet)
    group = signed(
        publisher,
        bundle_id="group",
        version=2,
        layer=PolicyLayer.GROUP,
        settings=(("x", 9),),
    )
    simulated, diff = manager.simulate(group)
    assert dict(simulated.settings)["x"] == 1
    assert any(item.blocked_by_lock for item in diff)
    assert manager.effective("configuration").bundle_ids == ("fleet",)


def test_high_impact_requires_two_distinct_signed_approvals():
    publisher = Ed25519PrivateKey.generate()
    first = Ed25519PrivateKey.generate()
    second = Ed25519PrivateKey.generate()
    expiry = time.time() + 100
    base = signed(publisher, high_impact=True, expires_at=expiry)
    body = base.approval_body()
    bindings = {"a1": PrincipalCredential("a1", "fixture-issuer", "operator-1", public(first)),
                "a2": PrincipalCredential("a2", "fixture-issuer", "operator-2", public(second))}
    approvals = (
        authenticated_approval(bindings["a1"], first, body, expiry),
        authenticated_approval(bindings["a2"], second, body, expiry),
    )
    approved = signed(publisher, high_impact=True, approvals=approvals, expires_at=expiry)
    manager = PolicyManager(
        {"publisher": public(publisher)},
        bindings,
    )
    assert manager.submit(approved)[0]
    one = signed(publisher, bundle_id="one", version=2, high_impact=True, approvals=(approvals[0],))
    assert not manager.submit(one)[0]


@pytest.mark.parametrize("same_key,same_subject", [(True, False), (False, True), (True, True)])
def test_high_impact_aliases_and_rotated_keys_never_count_as_two_operators(same_key, same_subject):
    publisher = Ed25519PrivateKey.generate()
    first = Ed25519PrivateKey.generate()
    second = first if same_key else Ed25519PrivateKey.generate()
    expiry = time.time() + 100
    body = signed(publisher, high_impact=True, expires_at=expiry).approval_body()
    bindings = {"alias-one": PrincipalCredential("alias-one", "fixture-issuer", "operator-1", public(first)),
                "alias-two": PrincipalCredential("alias-two", "fixture-issuer",
                    "operator-1" if same_subject else "operator-2", public(second))}
    approvals = (authenticated_approval(bindings["alias-one"], first, body, expiry),
                 authenticated_approval(bindings["alias-two"], second, body, expiry))
    bundle = signed(publisher, high_impact=True, approvals=approvals, expires_at=expiry)
    assert not PolicyManager({"publisher": public(publisher)}, bindings).submit(bundle)[0]


def test_legacy_key_labels_are_unavailable_and_revocation_rechecks_effective_policy():
    publisher, first, second = [Ed25519PrivateKey.generate() for _ in range(3)]
    expiry = time.time() + 100
    body = signed(publisher, high_impact=True, expires_at=expiry).approval_body()
    approvals = (PolicyApproval("one", b64(first.sign(body))), PolicyApproval("two", b64(second.sign(body))))
    bundle = signed(publisher, high_impact=True, approvals=approvals, expires_at=expiry)
    legacy = PolicyManager({"publisher": public(publisher)}, {"one": public(first), "two": public(second)})
    assert legacy.submit(bundle) == (False, "high-impact authenticated approver subject bindings unavailable")
    bindings = {alias: PrincipalCredential(alias, "fixture-issuer", alias, public(signing))
                for alias, signing in [("one", first), ("two", second)]}
    approvals = (authenticated_approval(bindings["one"], first, body, expiry),
                 authenticated_approval(bindings["two"], second, body, expiry))
    bundle = signed(publisher, high_impact=True, approvals=approvals, expires_at=expiry)
    manager = PolicyManager({"publisher": public(publisher)}, bindings)
    assert manager.submit(bundle)[0]
    manager.approvers["two"] = dataclasses.replace(bindings["two"], enabled=False)
    assert manager.effective("configuration").bundle_ids == ()


def test_old_approval_cannot_gain_another_subject_after_backend_alias_rebinding():
    publisher, first, second = [Ed25519PrivateKey.generate() for _ in range(3)]
    expiry = time.time() + 100
    body = signed(publisher, high_impact=True, expires_at=expiry).approval_body()
    bindings = {alias: PrincipalCredential(alias, "fixture-issuer", "same-operator", public(signing))
                for alias, signing in [("one", first), ("two", second)]}
    approvals = (authenticated_approval(bindings["one"], first, body, expiry),
                 authenticated_approval(bindings["two"], second, body, expiry))
    bundle = signed(publisher, high_impact=True, approvals=approvals, expires_at=expiry)
    bindings["two"] = dataclasses.replace(bindings["two"], subject="new-operator")
    assert not PolicyManager({"publisher": public(publisher)}, bindings).submit(bundle)[0]


def test_rollout_states_and_canonical_receipt():
    publisher = Ed25519PrivateKey.generate()
    manager = PolicyManager({"publisher": public(publisher)})
    canary = signed(publisher, rollout=RolloutState.CANARY, canary_percent=10)
    accepted, reason = manager.submit(canary)
    one = manager.receipt(canary, accepted, reason, now=10)
    two = manager.receipt(canary, accepted, reason, now=10)
    assert one == two
    assert len(one.receipt_hash) == 64
