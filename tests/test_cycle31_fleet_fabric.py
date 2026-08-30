from __future__ import annotations

import base64
import hashlib
import sqlite3
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.fleet_control_plane import FleetControlPlane, FleetDevice
from angerona.core.fleet_fabric import (
    ZERO_DIGEST,
    EnrollmentGrant,
    EnrollmentProof,
    FleetFabricStore,
    FleetHealthSample,
    FleetRolloutPlan,
    SignedFleetHealthEnvelope,
    effective_policy_hash,
    enrollment_possession_challenge,
    health_possession_payload,
)
from angerona.core.policy_bundle import EffectivePolicy
from angerona.core import fleet_fabric as fleet_fabric_module

TENANT_KEYS = {"tenant-alpha": b"a" * 32, "tenant-bravo": b"b" * 32}
DESIRED = hashlib.sha256(b"desired-policy").hexdigest()
PREVIOUS = hashlib.sha256(b"previous-policy").hexdigest()
OTHER = hashlib.sha256(b"other-policy").hexdigest()


class _Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def set(self, value: float) -> None:
        self.value = value


def _private_key(device_id: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"fleet-test:{device_id}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_key(device_id: str) -> str:
    raw = _private_key(device_id).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")


def _public_digest(device_id: str) -> str:
    return hashlib.sha256(base64.b64decode(_public_key(device_id))).hexdigest()


def _proof(grant: EnrollmentGrant, device_id: str) -> EnrollmentProof:
    signature = _private_key(device_id).sign(enrollment_possession_challenge(grant))
    return EnrollmentProof(
        grant.tenant_id,
        grant.device_id,
        grant.grant_id,
        grant.digest,
        _public_key(device_id),
        base64.b64encode(signature).decode("ascii"),
    )


def _enroll(
    store: FleetFabricStore,
    clock: _Clock,
    tenant_id: str,
    device_id: str,
    *,
    at: float,
) -> None:
    clock.set(at)
    grant = store.issue_enrollment_grant(
        tenant_id,
        device_id,
        _public_digest(device_id),
        ttl_seconds=60,
        grant_id=f"grant-{tenant_id}-{device_id}",
    )
    clock.set(at + 1)
    receipt = store.redeem_enrollment_grant(
        grant,
        _proof(grant, device_id),
        tenant_id=tenant_id,
        device_id=device_id,
        device_public_key_sha256=_public_digest(device_id),
    )
    assert receipt.device_authentication == "ed25519-possession-proof-v1"
    assert store.verify_enrollment_receipt(receipt)


def _health(
    tenant_id: str,
    device_id: str,
    sample_id: str,
    *,
    observed_at: float,
    desired: str = DESIRED,
    effective: str = DESIRED,
    health: int = 100,
    reason: str = "",
    queue_depth: int = 1,
    accepted: int = 100,
    dropped: int = 0,
    dropped_delta: int = 0,
    rejected: int = 0,
    rollout_id: str = "",
    rollout_generation: int = 0,
) -> FleetHealthSample:
    return FleetHealthSample(
        tenant_id=tenant_id,
        device_id=device_id,
        sample_id=sample_id,
        device_public_key_sha256=_public_digest(device_id),
        observed_at=observed_at,
        desired_policy_hash=desired,
        effective_policy_hash=effective,
        health_percent=health,
        health_reason=reason,
        queue_capacity=100,
        queue_depth=queue_depth,
        accepted_total=accepted,
        dropped_total=dropped,
        dropped_since_previous=dropped_delta,
        rejected_total=rejected,
        rollout_id=rollout_id,
        rollout_generation=rollout_generation,
    )


def _envelope(
    sample: FleetHealthSample,
    *,
    sequence: int = 1,
    previous: str = ZERO_DIGEST,
    binding_generation: int = 1,
    signer_device_id: str | None = None,
) -> SignedFleetHealthEnvelope:
    payload = health_possession_payload(
        sample,
        binding_generation=binding_generation,
        sequence=sequence,
        previous_evidence_digest=previous,
    )
    signature = _private_key(signer_device_id or sample.device_id).sign(payload)
    return SignedFleetHealthEnvelope(
        sample,
        binding_generation,
        sequence,
        previous,
        base64.b64encode(signature).decode("ascii"),
    )


def _plan(
    rollout_id: str,
    *,
    tenant_id: str = "tenant-alpha",
    targets: tuple[str, ...] = ("device-alpha",),
    canaries: tuple[str, ...] = ("device-alpha",),
    created_at: float = 200.0,
) -> FleetRolloutPlan:
    return FleetRolloutPlan(
        tenant_id=tenant_id,
        rollout_id=rollout_id,
        policy_bundle_id=f"bundle-{rollout_id}",
        group_id="group-production",
        desired_policy_hash=DESIRED,
        previous_policy_hash=PREVIOUS,
        target_device_ids=targets,
        canary_device_ids=canaries,
        minimum_health_percent=90,
        max_canary_failures=0,
        created_at=created_at,
        change_context={"ticket": "CHG-3100", "summary": "detection policy preview"},
    )


def test_c31_rt_04_enrollment_requires_real_ed25519_possession_and_is_single_use(
    tmp_path,
) -> None:
    path = tmp_path / "fabric.db"
    clock = _Clock(100)
    store = FleetFabricStore(path, TENANT_KEYS, clock=clock)
    grant = store.issue_enrollment_grant(
        "tenant-alpha",
        "device-alpha",
        _public_digest("device-alpha"),
        ttl_seconds=10,
        grant_id="grant-single-use",
    )
    with pytest.raises(PermissionError, match="possession proof binding"):
        store.redeem_enrollment_grant(
            grant,
            _proof(grant, "device-substitute"),
            tenant_id="tenant-alpha",
            device_id="device-alpha",
            device_public_key_sha256=_public_digest("device-alpha"),
        )
    forged = replace(
        _proof(grant, "device-alpha"),
        signature_ed25519=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    with pytest.raises(PermissionError, match="possession proof is invalid"):
        store.redeem_enrollment_grant(
            grant,
            forged,
            tenant_id="tenant-alpha",
            device_id="device-alpha",
            device_public_key_sha256=_public_digest("device-alpha"),
        )
    clock.set(101)
    receipt = store.redeem_enrollment_grant(
        grant,
        _proof(grant, "device-alpha"),
        tenant_id="tenant-alpha",
        device_id="device-alpha",
        device_public_key_sha256=_public_digest("device-alpha"),
    )
    assert receipt.binding_generation == 1
    assert store.verify_enrollment_receipt(receipt)
    clock.set(102)
    with pytest.raises(PermissionError, match="already redeemed"):
        store.redeem_enrollment_grant(
            grant,
            _proof(grant, "device-alpha"),
            tenant_id="tenant-alpha",
            device_id="device-alpha",
            device_public_key_sha256=_public_digest("device-alpha"),
        )
    store.close()

    reopened = FleetFabricStore(path, TENANT_KEYS, clock=_Clock(103))
    with pytest.raises(PermissionError, match="already redeemed"):
        reopened.redeem_enrollment_grant(
            grant,
            _proof(grant, "device-alpha"),
            tenant_id="tenant-alpha",
            device_id="device-alpha",
            device_public_key_sha256=_public_digest("device-alpha"),
        )
    reopened.close()


def test_c31_rt_05_constructor_clock_only_expiry_and_backward_time_fail_closed(
    tmp_path,
) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(tmp_path / "fabric.db", TENANT_KEYS, clock=clock)
    grant = store.issue_enrollment_grant(
        "tenant-alpha",
        "device-alpha",
        _public_digest("device-alpha"),
        ttl_seconds=5,
        grant_id="grant-expiry",
    )
    with pytest.raises(TypeError):
        store.redeem_enrollment_grant(  # type: ignore[call-arg]
            grant,
            _proof(grant, "device-alpha"),
            tenant_id="tenant-alpha",
            device_id="device-alpha",
            device_public_key_sha256=_public_digest("device-alpha"),
            now=101,
        )
    clock.set(105)
    with pytest.raises(PermissionError, match="expired"):
        store.redeem_enrollment_grant(
            grant,
            _proof(grant, "device-alpha"),
            tenant_id="tenant-alpha",
            device_id="device-alpha",
            device_public_key_sha256=_public_digest("device-alpha"),
        )
    clock.set(104)
    with pytest.raises(RuntimeError, match="clock moved backwards"):
        store.issue_enrollment_grant(
            "tenant-alpha",
            "device-beta",
            _public_digest("device-beta"),
        )
    store.close()
    reopened = FleetFabricStore(
        tmp_path / "fabric.db", TENANT_KEYS, clock=_Clock(104)
    )
    with pytest.raises(RuntimeError, match="clock moved backwards"):
        reopened.issue_enrollment_grant(
            "tenant-alpha", "device-gamma", _public_digest("device-gamma")
        )
    reopened.close()


def test_c31_rt_06_quotas_and_pruning_are_per_tenant_and_batched(tmp_path) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(
        tmp_path / "fabric.db",
        TENANT_KEYS,
        max_grants=1,
        max_enrolled_devices=1,
        max_health_evidence=1,
        max_rollouts=1,
        clock=clock,
    )
    alpha = store.issue_enrollment_grant(
        "tenant-alpha", "device-alpha", _public_digest("device-alpha"),
        grant_id="grant-alpha",
    )
    bravo = store.issue_enrollment_grant(
        "tenant-bravo", "device-bravo", _public_digest("device-bravo"),
        grant_id="grant-bravo",
    )
    with pytest.raises(OverflowError, match="full of live grants"):
        store.issue_enrollment_grant(
            "tenant-alpha", "device-extra", _public_digest("device-extra"),
            grant_id="grant-extra",
        )
    clock.set(101)
    for grant, tenant, device in (
        (alpha, "tenant-alpha", "device-alpha"),
        (bravo, "tenant-bravo", "device-bravo"),
    ):
        store.redeem_enrollment_grant(
            grant,
            _proof(grant, device),
            tenant_id=tenant,
            device_id=device,
            device_public_key_sha256=_public_digest(device),
        )
    clock.set(110)
    alpha_one = store.record_health(_envelope(_health(
        "tenant-alpha", "device-alpha", "sample-alpha-one", observed_at=109,
    )))
    clock.set(111)
    store.record_health(_envelope(_health(
        "tenant-bravo", "device-bravo", "sample-bravo", observed_at=110,
    )))
    clock.set(112)
    store.record_health(_envelope(
        _health(
            "tenant-alpha", "device-alpha", "sample-alpha-two", observed_at=111,
            accepted=101,
        ),
        sequence=2,
        previous=alpha_one.digest,
    ))
    alpha_snapshot = store.health_snapshot("tenant-alpha")
    bravo_snapshot = store.health_snapshot("tenant-bravo")
    assert alpha_snapshot.total_rows == 1
    assert alpha_snapshot.retention_drops == 1
    assert bravo_snapshot.total_rows == 1
    assert bravo_snapshot.retention_drops == 0
    clock.set(200)
    store.stage_rollout(_plan("rollout-alpha", created_at=199))
    store.stage_rollout(_plan(
        "rollout-bravo",
        tenant_id="tenant-bravo",
        targets=("device-bravo",),
        canaries=("device-bravo",),
        created_at=199,
    ))
    assert len(store.rollout_snapshot("tenant-alpha")) == 1
    assert len(store.rollout_snapshot("tenant-bravo")) == 1
    store.close()


def test_c31_rt_04_and_08_signed_health_chain_rejects_substitution_and_exposes_gaps(
    tmp_path,
) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(tmp_path / "fabric.db", TENANT_KEYS, clock=clock)
    _enroll(store, clock, "tenant-alpha", "device-alpha", at=100)
    sample = _health(
        "tenant-alpha", "device-alpha", "sample-one", observed_at=109,
        dropped=2, dropped_delta=2,
    )
    cursor = store.health_submission_state("tenant-alpha", "device-alpha")
    assert cursor["next_sequence"] == 1
    assert cursor["previous_evidence_digest"] == ZERO_DIGEST
    assert cursor["transport_authorized"] is False
    clock.set(110)
    with pytest.raises(TypeError, match="device-signed"):
        store.record_health(sample)  # type: ignore[arg-type]
    with pytest.raises(PermissionError, match="signature is invalid"):
        store.record_health(_envelope(sample, signer_device_id="device-substitute"))
    first = store.record_health(_envelope(sample))
    cursor = store.health_submission_state("tenant-alpha", "device-alpha")
    assert cursor["next_sequence"] == 2
    assert cursor["previous_evidence_digest"] == first.digest
    clock.set(111)
    gap = store.record_health(_envelope(
        _health(
            "tenant-alpha", "device-alpha", "sample-three", observed_at=111,
            accepted=103, dropped=3, dropped_delta=1,
        ),
        sequence=3,
        previous=first.digest,
    ))
    assert gap.sequence_gap == 1
    snapshot = store.health_snapshot("tenant-alpha")
    assert snapshot.sequence_gaps == 1
    assert snapshot.stats_authenticated is True
    assert "visible-history-gaps" in snapshot.history_chain_status
    clock.set(112)
    with pytest.raises(ValueError, match="counter regressed"):
        store.record_health(_envelope(
            _health(
                "tenant-alpha", "device-alpha", "sample-four", observed_at=112,
                accepted=1, dropped=3,
            ),
            sequence=4,
            previous=gap.digest,
        ))
    store.close()


def test_c31_rt_02_snapshot_counts_silent_and_stale_enrolled_devices(tmp_path) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(
        tmp_path / "fabric.db", TENANT_KEYS, clock=clock,
        health_freshness_seconds=30,
    )
    _enroll(store, clock, "tenant-alpha", "device-alpha", at=100)
    _enroll(store, clock, "tenant-alpha", "device-beta", at=102)
    clock.set(110)
    store.record_health(_envelope(_health(
        "tenant-alpha", "device-alpha", "sample-alpha", observed_at=110,
    )))
    snapshot = store.health_snapshot("tenant-alpha")
    assert snapshot.enrolled_devices == 2
    assert snapshot.reporting_devices == 1
    assert snapshot.fresh_devices == 1
    assert snapshot.missing_device_ids == ("device-beta",)
    assert snapshot.unhealthy_devices == 1
    clock.set(141)
    stale = store.health_snapshot("tenant-alpha")
    assert stale.stale_device_ids == ("device-alpha",)
    assert stale.missing_devices == 1
    assert stale.unhealthy_devices == 2
    store.close()


def test_c31_rt_03_and_07_verified_control_plane_revocation_is_authoritative(
    tmp_path,
) -> None:
    plane = FleetControlPlane(
        tmp_path / "control.db", {"tenant-alpha": TENANT_KEYS["tenant-alpha"]},
        clock=_Clock(90),
    )
    plane.register_device(FleetDevice(
        "tenant-alpha", "device-alpha", _public_key("device-alpha"),
        "tok_device_alpha", "linux", "1.0",
    ))
    clock = _Clock(100)
    store = FleetFabricStore(
        tmp_path / "fabric.db",
        {"tenant-alpha": TENANT_KEYS["tenant-alpha"]},
        control_plane=plane,
        clock=clock,
    )
    _enroll(store, clock, "tenant-alpha", "device-alpha", at=100)
    clock.set(110)
    active = store.record_health(_envelope(_health(
        "tenant-alpha", "device-alpha", "sample-active", observed_at=110,
    )))
    plane.transition_device_state(
        "tenant-alpha", "device-alpha", "revoked", expected_state="active"
    )
    clock.set(111)
    with pytest.raises(PermissionError, match="not actively enrolled"):
        store.record_health(_envelope(
            _health(
                "tenant-alpha", "device-alpha", "sample-revoked", observed_at=111,
                accepted=101,
            ),
            sequence=2,
            previous=active.digest,
        ))
    with pytest.raises(PermissionError, match="not enrolled in this tenant"):
        store.stage_rollout(_plan("rollout-revoked", created_at=110))

    plane._db.execute(  # noqa: SLF001 - explicit legacy-integrity regression
        "UPDATE fleet_devices SET record_hmac='' WHERE tenant_id=? AND device_id=?",
        ("tenant-alpha", "device-alpha"),
    )
    with pytest.raises(RuntimeError, match="not authenticated"):
        store.health_snapshot("tenant-alpha")
    store.close()
    plane.close()


def test_c31_rt_01_canary_binds_activation_generation_and_freshness(tmp_path) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(
        tmp_path / "fabric.db", TENANT_KEYS, clock=clock,
        health_freshness_seconds=30,
    )
    _enroll(store, clock, "tenant-alpha", "device-alpha", at=100)
    clock.set(200)
    pre = store.record_health(_envelope(_health(
        "tenant-alpha", "device-alpha", "sample-pre", observed_at=200,
        rollout_id="rollout-bound", rollout_generation=1,
    )))
    plan = _plan("rollout-bound", created_at=199)
    store.stage_rollout(plan)
    clock.set(201)
    canary = store.start_canary(
        "tenant-alpha", plan.rollout_id, expected_version=1,
        desired_policy_hash=DESIRED,
    )
    assert canary["canary_started_at"] == 201
    assert canary["canary_generation"] == 1
    clock.set(202)
    wrong_generation = store.record_health(_envelope(
        _health(
            "tenant-alpha", "device-alpha", "sample-wrong-generation",
            observed_at=202, accepted=101,
            rollout_id=plan.rollout_id, rollout_generation=2,
        ),
        sequence=2,
        previous=pre.digest,
    ))
    clock.set(203)
    result = store.evaluate_canary(
        "tenant-alpha", plan.rollout_id, expected_version=2,
        desired_policy_hash=DESIRED,
    )
    assert result.state == "halted"
    assert result.canary_started_at == 201
    assert "generation binding mismatch" in result.findings[0].reason
    clock.set(204)
    with pytest.raises(ValueError, match="future"):
        store.record_health(_envelope(
            _health(
                "tenant-alpha", "device-alpha", "sample-future", observed_at=205,
                accepted=102, rollout_id=plan.rollout_id, rollout_generation=1,
            ),
            sequence=3,
            previous=wrong_generation.digest,
        ))
    store.close()


def test_c31_rt_01_pre_activation_and_stale_evidence_each_halt(tmp_path) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(
        tmp_path / "fabric.db", TENANT_KEYS, clock=clock,
        health_freshness_seconds=30,
    )
    _enroll(store, clock, "tenant-alpha", "device-alpha", at=100)
    clock.set(200)
    pre = store.record_health(_envelope(_health(
        "tenant-alpha", "device-alpha", "sample-pre-only", observed_at=200,
        rollout_id="rollout-pre-only", rollout_generation=1,
    )))
    pre_plan = _plan("rollout-pre-only", created_at=199)
    store.stage_rollout(pre_plan)
    clock.set(201)
    store.start_canary(
        "tenant-alpha", pre_plan.rollout_id, expected_version=1,
        desired_policy_hash=DESIRED,
    )
    clock.set(202)
    pre_result = store.evaluate_canary(
        "tenant-alpha", pre_plan.rollout_id, expected_version=2,
        desired_policy_hash=DESIRED,
    )
    assert pre_result.state == "halted"
    assert pre_result.findings[0].reason == "no post-activation canary health evidence"

    clock.set(300)
    stale_plan = _plan("rollout-stale", created_at=299)
    store.stage_rollout(stale_plan)
    clock.set(301)
    store.start_canary(
        "tenant-alpha", stale_plan.rollout_id, expected_version=1,
        desired_policy_hash=DESIRED,
    )
    clock.set(302)
    store.record_health(_envelope(
        _health(
            "tenant-alpha", "device-alpha", "sample-stale", observed_at=302,
            accepted=101, rollout_id=stale_plan.rollout_id, rollout_generation=1,
        ),
        sequence=2,
        previous=pre.digest,
    ))
    clock.set(333)
    stale_result = store.evaluate_canary(
        "tenant-alpha", stale_plan.rollout_id, expected_version=2,
        desired_policy_hash=DESIRED,
    )
    assert stale_result.state == "halted"
    assert "freshness SLA" in stale_result.findings[0].reason
    store.close()


def test_canary_healthy_path_is_proposal_only_and_history_is_contiguous(tmp_path) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(tmp_path / "fabric.db", TENANT_KEYS, clock=clock)
    _enroll(store, clock, "tenant-alpha", "device-alpha", at=100)
    clock.set(200)
    plan = _plan("rollout-healthy", created_at=199)
    staged = store.stage_rollout(plan)
    assert staged["state"] == "staged"
    clock.set(201)
    canary = store.start_canary(
        "tenant-alpha", plan.rollout_id, expected_version=1,
        desired_policy_hash=DESIRED,
    )
    clock.set(202)
    store.record_health(_envelope(_health(
        "tenant-alpha", "device-alpha", "sample-canary", observed_at=202,
        rollout_id=plan.rollout_id,
        rollout_generation=canary["canary_generation"],
    )))
    clock.set(203)
    evaluation = store.evaluate_canary(
        "tenant-alpha", plan.rollout_id, expected_version=2,
        desired_policy_hash=DESIRED,
    )
    assert evaluation.state == "general-ready"
    record = store.rollout_snapshot("tenant-alpha")[0]
    assert record["history_length"] == 3
    assert record["history_chain_status"] == "authenticated-contiguous-local-history"
    assert "command" not in record
    store._db.execute(  # noqa: SLF001 - authenticated-stat tamper regression
        "UPDATE fabric_stats SET health_sequence_gaps=9 WHERE tenant_id=?",
        ("tenant-alpha",),
    )
    with pytest.raises(RuntimeError, match="statistics integrity"):
        store.health_snapshot("tenant-alpha")
    store.close()


def test_c31_rt_08_rollout_history_deletion_is_detected(tmp_path) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(tmp_path / "fabric.db", TENANT_KEYS, clock=clock)
    _enroll(store, clock, "tenant-alpha", "device-alpha", at=100)
    clock.set(200)
    plan = _plan("rollout-history", created_at=199)
    store.stage_rollout(plan)
    clock.set(201)
    store.start_canary(
        "tenant-alpha", plan.rollout_id, expected_version=1,
        desired_policy_hash=DESIRED,
    )
    store._db.execute(  # noqa: SLF001 - authenticated-history gap regression
        "DELETE FROM fabric_rollout_history WHERE tenant_id=? AND rollout_id=? AND version=1",
        ("tenant-alpha", plan.rollout_id),
    )
    with pytest.raises(RuntimeError, match="history integrity"):
        store.rollout_snapshot("tenant-alpha")
    store.close()


def test_rollout_rejects_commands_cross_tenant_targets_and_policy_reimplementation(
    tmp_path,
) -> None:
    with pytest.raises(ValueError, match="forbidden"):
        replace(_plan("rollout-command"), change_context={
            "review": {"script": "Invoke-Expression payload"}
        })
    clock = _Clock(100)
    store = FleetFabricStore(tmp_path / "fabric.db", TENANT_KEYS, clock=clock)
    _enroll(store, clock, "tenant-bravo", "device-bravo", at=100)
    clock.set(200)
    with pytest.raises(PermissionError, match="not enrolled in this tenant"):
        store.stage_rollout(_plan(
            "rollout-cross-tenant", targets=("device-bravo",),
            canaries=("device-bravo",), created_at=199,
        ))
    policy = EffectivePolicy(
        "detection",
        (("rule.enabled", True),),
        (("rule.enabled", "bundle-existing"),),
        (),
        ("bundle-existing",),
    )
    assert effective_policy_hash(policy) == hashlib.sha256(
        b'{"bundle_ids":["bundle-existing"],"channel":"detection",'
        b'"locked_keys":[],"settings":[["rule.enabled",true]],'
        b'"sources":[["rule.enabled","bundle-existing"]]}'
    ).hexdigest()
    with pytest.raises(TypeError, match="EffectivePolicy"):
        effective_policy_hash({"settings": []})  # type: ignore[arg-type]
    store.close()


def test_enrollment_grant_constructor_rejects_unbounded_expiry() -> None:
    with pytest.raises(ValueError, match="fifteen minutes"):
        EnrollmentGrant(
            "tenant-alpha", "device-alpha", "grant-alpha",
            _public_digest("device-alpha"), 1, 902, "0" * 32, "0" * 64,
        )


def test_c31_new_01_missing_floor_with_records_fails_and_preissued_redeem_is_rejected(
    tmp_path,
) -> None:
    path = tmp_path / "fabric.db"
    clock = _Clock(100)
    store = FleetFabricStore(path, TENANT_KEYS, clock=clock)
    grant = store.issue_enrollment_grant(
        "tenant-alpha", "device-alpha", _public_digest("device-alpha"),
        grant_id="grant-floor-regression",
    )

    # Even a caller with the local test key cannot turn a rolled-back clock into
    # a not-yet-issued grant redemption while this process is live.
    floor_core = {"tenant_id": "tenant-alpha", "last_seen": 99.0}
    store._db.execute(  # noqa: SLF001 - exact authenticated rollback regression
        "UPDATE fabric_clock_floor SET last_seen=?,clock_hmac=? WHERE tenant_id=?",
        (
            99.0,
            fleet_fabric_module._hmac(  # noqa: SLF001 - exact sealed fixture
                TENANT_KEYS["tenant-alpha"], b"clock-floor", floor_core
            ),
            "tenant-alpha",
        ),
    )
    store._db.commit()  # noqa: SLF001 - exact durable rollback regression
    store._last_clock = None  # noqa: SLF001 - emulate a restarted clock observer
    clock.set(99)
    with pytest.raises(PermissionError, match="not yet valid"):
        store.redeem_enrollment_grant(
            grant,
            _proof(grant, "device-alpha"),
            tenant_id="tenant-alpha",
            device_id="device-alpha",
            device_public_key_sha256=_public_digest("device-alpha"),
        )
    store.close()

    with sqlite3.connect(path) as database:
        database.execute(
            "DELETE FROM fabric_clock_floor WHERE tenant_id=?", ("tenant-alpha",)
        )
    with pytest.raises(RuntimeError, match="clock floor is unavailable"):
        FleetFabricStore(path, TENANT_KEYS, clock=_Clock(101))


def test_c31_new_02_deleted_stats_and_newest_adverse_health_fail_closed(tmp_path) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(tmp_path / "stats.db", TENANT_KEYS, clock=clock)
    _enroll(store, clock, "tenant-alpha", "device-alpha", at=100)
    clock.set(110)
    store.record_health(_envelope(_health(
        "tenant-alpha", "device-alpha", "sample-adverse", observed_at=109,
        health=25, reason="sensor evidence is incomplete",
    )))
    store._db.execute(  # noqa: SLF001 - exact newest-row deletion regression
        "DELETE FROM fabric_health WHERE tenant_id=? AND sample_id=?",
        ("tenant-alpha", "sample-adverse"),
    )
    with pytest.raises(RuntimeError, match="custody|retained health"):
        store.health_snapshot("tenant-alpha")
    store.close()

    stats_store = FleetFabricStore(tmp_path / "stats-delete.db", TENANT_KEYS, clock=clock)
    stats_store._db.execute(  # noqa: SLF001 - exact statistics deletion regression
        "DELETE FROM fabric_stats WHERE tenant_id=?", ("tenant-alpha",)
    )
    with pytest.raises(RuntimeError, match="statistics row is unavailable"):
        stats_store.health_snapshot("tenant-alpha")
    stats_store.close()


def test_c31_new_02_deleted_newest_canary_evidence_cannot_become_ready(tmp_path) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(tmp_path / "canary-delete.db", TENANT_KEYS, clock=clock)
    _enroll(store, clock, "tenant-alpha", "device-alpha", at=100)
    clock.set(200)
    plan = _plan("rollout-deleted-adverse", created_at=199)
    store.stage_rollout(plan)
    clock.set(201)
    canary = store.start_canary(
        "tenant-alpha", plan.rollout_id, expected_version=1,
        desired_policy_hash=DESIRED,
    )
    clock.set(202)
    store.record_health(_envelope(_health(
        "tenant-alpha", "device-alpha", "sample-deleted-adverse", observed_at=202,
        health=10, reason="policy application failed", rollout_id=plan.rollout_id,
        rollout_generation=canary["canary_generation"],
    )))
    store._db.execute(  # noqa: SLF001 - exact canary evidence deletion regression
        "DELETE FROM fabric_health WHERE tenant_id=? AND sample_id=?",
        ("tenant-alpha", "sample-deleted-adverse"),
    )
    clock.set(203)
    with pytest.raises(RuntimeError, match="custody|retained health"):
        store.evaluate_canary(
            "tenant-alpha", plan.rollout_id, expected_version=2,
            desired_policy_hash=DESIRED,
        )
    store.close()


def test_c31_new_03_pruning_is_tombstoned_and_tampered_candidate_aborts(tmp_path) -> None:
    clock = _Clock(100)
    store = FleetFabricStore(
        tmp_path / "prune.db", TENANT_KEYS, clock=clock,
        max_grants=1, max_enrolled_devices=2,
    )
    first = store.issue_enrollment_grant(
        "tenant-alpha", "device-alpha", _public_digest("device-alpha"),
        grant_id="grant-prune-first",
    )
    clock.set(101)
    store.redeem_enrollment_grant(
        first, _proof(first, "device-alpha"), tenant_id="tenant-alpha",
        device_id="device-alpha", device_public_key_sha256=_public_digest("device-alpha"),
    )
    clock.set(102)
    store.issue_enrollment_grant(
        "tenant-alpha", "device-beta", _public_digest("device-beta"),
        grant_id="grant-prune-second",
    )
    custody = store.custody_snapshot("tenant-alpha")
    assert custody["counts"]["prune_tombstones"] == 1
    assert custody["stats"]["grant_retention_drops"] == 1
    store._db.execute(  # noqa: SLF001 - exact tombstone tamper regression
        "UPDATE fabric_prune_tombstones SET row_count=2 WHERE tenant_id=?",
        ("tenant-alpha",),
    )
    with pytest.raises(RuntimeError, match="tombstone integrity|custody"):
        store.custody_snapshot("tenant-alpha")
    store.close()

    tamper_store = FleetFabricStore(
        tmp_path / "candidate.db", TENANT_KEYS, clock=clock, max_grants=1
    )
    victim = tamper_store.issue_enrollment_grant(
        "tenant-alpha", "device-alpha", _public_digest("device-alpha"),
        grant_id="grant-tampered-candidate",
    )
    clock.set(103)
    tamper_store.redeem_enrollment_grant(
        victim, _proof(victim, "device-alpha"), tenant_id="tenant-alpha",
        device_id="device-alpha", device_public_key_sha256=_public_digest("device-alpha"),
    )
    tamper_store._db.execute(  # noqa: SLF001 - exact lifecycle tamper regression
        "UPDATE fabric_grants SET state='expired' WHERE tenant_id=? AND grant_id=?",
        ("tenant-alpha", victim.grant_id),
    )
    clock.set(104)
    with pytest.raises(RuntimeError, match="lifecycle integrity|custody"):
        tamper_store.issue_enrollment_grant(
            "tenant-alpha", "device-beta", _public_digest("device-beta"),
            grant_id="grant-must-not-prune",
        )
    assert tamper_store._db.execute(  # noqa: SLF001 - no forged prune receipt
        "SELECT COUNT(*) FROM fabric_prune_tombstones WHERE tenant_id=?",
        ("tenant-alpha",),
    ).fetchone()[0] == 0
    tamper_store.close()
