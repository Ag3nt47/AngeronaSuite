import base64
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.policy_bundle import (
    PolicyApproval, PolicyBundle, PolicyLayer, PolicyManager, RolloutState,
)


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def signed(key, **changes):
    data = dict(
        bundle_id="b1", version=1, publisher_id="publisher",
        channel="configuration", layer=PolicyLayer.FLEET,
        settings=(("sensor.enabled", True),), locked_keys=(),
        rollout=RolloutState.STAGED, expires_at=time.time() + 100,
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


def test_precedence_locks_and_channel_separation():
    publisher = Ed25519PrivateKey.generate()
    manager = PolicyManager({"publisher": public(publisher)})
    fleet = signed(
        publisher, bundle_id="fleet", settings=(("x", 1),),
        locked_keys=("x",),
    )
    group = signed(
        publisher, bundle_id="group", layer=PolicyLayer.GROUP,
        settings=(("x", 2), ("y", 2)),
    )
    detection = signed(
        publisher, bundle_id="detect", channel="detection",
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
        publisher, bundle_id="fleet", settings=(("x", 1),),
        locked_keys=("x",),
    )
    manager.submit(fleet)
    group = signed(
        publisher, bundle_id="group", version=2, layer=PolicyLayer.GROUP,
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
    approvals = (
        PolicyApproval("a1", b64(first.sign(body))),
        PolicyApproval("a2", b64(second.sign(body))),
    )
    approved = signed(
        publisher, high_impact=True, approvals=approvals, expires_at=expiry
    )
    manager = PolicyManager(
        {"publisher": public(publisher)},
        {"a1": public(first), "a2": public(second)},
    )
    assert manager.submit(approved)[0]
    one = signed(publisher, bundle_id="one", version=2, high_impact=True,
                 approvals=(approvals[0],))
    assert not manager.submit(one)[0]


def test_rollout_states_and_canonical_receipt():
    publisher = Ed25519PrivateKey.generate()
    manager = PolicyManager({"publisher": public(publisher)})
    canary = signed(
        publisher, rollout=RolloutState.CANARY, canary_percent=10
    )
    accepted, reason = manager.submit(canary)
    one = manager.receipt(canary, accepted, reason, now=10)
    two = manager.receipt(canary, accepted, reason, now=10)
    assert one == two
    assert len(one.receipt_hash) == 64
