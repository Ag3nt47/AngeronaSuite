from __future__ import annotations

import base64
import hashlib
import sqlite3
import threading
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import angerona.core.fleet_fabric as fleet_fabric
from angerona.core.fleet_fabric import (
    CUSTODY_MANIFEST_SCHEMA_ID,
    ZERO_DIGEST,
    EnrollmentProof,
    FleetFabricStore,
    FleetHealthEvidence,
    FleetHealthSample,
    SignedFleetHealthEnvelope,
    _canonical,
    _hmac,
    enrollment_possession_challenge,
    health_possession_payload,
)


TENANT = "tenant-local"
DEVICE = "device-local"
KEYS = {TENANT: b"f" * 32}
DESIRED = hashlib.sha256(b"cycle34-followup-policy").hexdigest()


class _Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"cycle34-followup-device").digest()
    )


def _public() -> str:
    raw = _private().public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _public_digest() -> str:
    return hashlib.sha256(base64.b64decode(_public())).hexdigest()


def _enrolled_store(
    path: Path,
    *,
    max_health: int = 500,
) -> tuple[FleetFabricStore, _Clock]:
    clock = _Clock()
    store = FleetFabricStore(
        path,
        KEYS,
        max_health_evidence=max_health,
        clock=clock,
    )
    grant = store.issue_enrollment_grant(
        TENANT,
        DEVICE,
        _public_digest(),
        grant_id="grant-local",
        ttl_seconds=60,
    )
    proof = EnrollmentProof(
        TENANT,
        DEVICE,
        grant.grant_id,
        grant.digest,
        _public(),
        base64.b64encode(
            _private().sign(enrollment_possession_challenge(grant))
        ).decode("ascii"),
    )
    clock.value = 101.0
    store.redeem_enrollment_grant(
        grant,
        proof,
        tenant_id=TENANT,
        device_id=DEVICE,
        device_public_key_sha256=_public_digest(),
    )
    clock.value = 10_000.0
    return store, clock


def _record_rows(
    store: FleetFabricStore,
    count: int,
    *,
    observed: list[float] | None = None,
) -> None:
    previous = ZERO_DIGEST
    latest = None
    with store._lock:  # noqa: SLF001 - one authenticated batch fixture
        store._db.execute("BEGIN IMMEDIATE")  # noqa: SLF001
        for index in range(count):
            sample = FleetHealthSample(
                tenant_id=TENANT,
                device_id=DEVICE,
                sample_id=f"sample-{index:03d}",
                device_public_key_sha256=_public_digest(),
                observed_at=(
                    observed[index] if observed is not None else 200.0 + index
                ),
                desired_policy_hash=DESIRED,
                effective_policy_hash=DESIRED,
                health_percent=100,
                health_reason="",
                queue_capacity=100,
                queue_depth=1,
                accepted_total=100 + index,
                dropped_total=0,
                dropped_since_previous=0,
                rejected_total=0,
            )
            payload = health_possession_payload(
                sample,
                binding_generation=1,
                sequence=index + 1,
                previous_evidence_digest=previous,
            )
            signature = base64.b64encode(_private().sign(payload)).decode("ascii")
            core = {
                "sample": asdict(sample),
                "recorded_at": float(store._clock()),  # noqa: SLF001
                "binding_generation": 1,
                "sequence": index + 1,
                "sequence_gap": 0,
                "previous_evidence_digest": previous,
                "device_signature_ed25519": signature,
            }
            latest = FleetHealthEvidence(
                sample=sample,
                recorded_at=core["recorded_at"],
                binding_generation=1,
                sequence=index + 1,
                sequence_gap=0,
                previous_evidence_digest=previous,
                device_signature_ed25519=signature,
                evidence_hmac=_hmac(
                    store._key(TENANT), b"health-evidence", core  # noqa: SLF001
                ),
            )
            store._db.execute(  # noqa: SLF001
                "INSERT INTO fabric_health VALUES (?,?,?,?,?)",
                (
                    TENANT,
                    DEVICE,
                    sample.sample_id,
                    sample.observed_at,
                    _canonical(asdict(latest)).decode("utf-8"),
                ),
            )
            previous = latest.digest
        assert latest is not None
        store._write_health_head_locked(latest)  # noqa: SLF001
        store._prune_health_locked(TENANT, float(store._clock()))  # noqa: SLF001
        store._write_custody_locked(TENANT)  # noqa: SLF001
        store._db.commit()  # noqa: SLF001


def _next_health_envelope(
    store: FleetFabricStore,
    index: int,
) -> SignedFleetHealthEnvelope:
    with store._lock:  # noqa: SLF001 - exact authenticated signing cursor
        head = store._health_head_locked(TENANT, DEVICE)  # noqa: SLF001
    assert head is not None
    sample = FleetHealthSample(
        tenant_id=TENANT,
        device_id=DEVICE,
        sample_id=f"sample-{index:03d}",
        device_public_key_sha256=_public_digest(),
        observed_at=200.0 + index,
        desired_policy_hash=DESIRED,
        effective_policy_hash=DESIRED,
        health_percent=100,
        health_reason="",
        queue_capacity=100,
        queue_depth=1,
        accepted_total=100 + index,
        dropped_total=0,
        dropped_since_previous=0,
        rejected_total=0,
    )
    payload = health_possession_payload(
        sample,
        binding_generation=1,
        sequence=index + 1,
        previous_evidence_digest=str(head["evidence_digest"]),
    )
    return SignedFleetHealthEnvelope(
        sample,
        1,
        index + 1,
        str(head["evidence_digest"]),
        base64.b64encode(_private().sign(payload)).decode("ascii"),
    )


def _downgrade_to_authenticated_v1(store: FleetFabricStore) -> int:
    with store._lock:  # noqa: SLF001 - authenticated migration fixture
        manifest = dict(
            store._verified_custody_manifest_locked(TENANT)  # noqa: SLF001
        )
        assert manifest["schema"] == CUSTODY_MANIFEST_SCHEMA_ID
        generation = int(manifest["generation"])
        legacy = store._legacy_custody_projection(manifest)  # noqa: SLF001
        store._db.execute(  # noqa: SLF001
            "UPDATE fabric_custody SET manifest_json=?,manifest_hmac=? "
            "WHERE tenant_id=?",
            (
                _canonical(legacy).decode("utf-8"),
                _hmac(store._key(TENANT), b"fabric-custody", legacy),  # noqa: SLF001
                TENANT,
            ),
        )
        store._db.commit()  # noqa: SLF001
    return generation


def test_full_retained_health_projection_rejects_hidden_tamper_and_stays_bounded(
    tmp_path,
) -> None:
    store, _clock = _enrolled_store(tmp_path / "fleet.db")
    try:
        _record_rows(store, 201)
        originals = dict(store._db.execute(  # noqa: SLF001
            "SELECT sample_id,evidence_json FROM fabric_health WHERE tenant_id=?",
            (TENANT,),
        ).fetchall())
        for sample_id in ("sample-000", "sample-100", "sample-200"):
            store._db.execute(  # noqa: SLF001 - deliberate retained-row tamper
                "UPDATE fabric_health SET evidence_json='{}' "
                "WHERE tenant_id=? AND device_id=? AND sample_id=?",
                (TENANT, DEVICE, sample_id),
            )
            store._db.commit()  # noqa: SLF001
            with pytest.raises(RuntimeError, match="health evidence integrity"):
                store.dashboard_snapshot(TENANT)
            store._db.execute(  # noqa: SLF001
                "UPDATE fabric_health SET evidence_json=? "
                "WHERE tenant_id=? AND device_id=? AND sample_id=?",
                (originals[sample_id], TENANT, DEVICE, sample_id),
            )
            store._db.commit()  # noqa: SLF001

        store._db.execute(  # noqa: SLF001 - row-order binding tamper
            "UPDATE fabric_health SET observed_at=observed_at+0.5 "
            "WHERE tenant_id=? AND device_id=? AND sample_id='sample-100'",
            (TENANT, DEVICE),
        )
        store._db.commit()  # noqa: SLF001
        with pytest.raises(RuntimeError, match="health evidence integrity"):
            store.dashboard_snapshot(TENANT)
        store._db.execute(  # noqa: SLF001
            "UPDATE fabric_health SET observed_at=300.0 "
            "WHERE tenant_id=? AND device_id=? AND sample_id='sample-100'",
            (TENANT, DEVICE),
        )
        store._db.commit()  # noqa: SLF001

        statements: list[str] = []
        store._db.set_trace_callback(statements.append)  # noqa: SLF001
        snapshot = store.dashboard_snapshot(TENANT)
        store._db.set_trace_callback(None)  # noqa: SLF001
        selects = [
            item for item in statements if item.lstrip().upper().startswith("SELECT")
        ]
        assert snapshot["health"].total_rows == 201
        assert snapshot["health"].truncated is True
        assert len(selects) <= 17
        assert sum("FROM fabric_health WHERE" in item for item in selects) == 1
        assert "health_evidence_digest" in snapshot[
            "authenticated_custody_checkpoint"
        ]

        store._db.execute(  # noqa: SLF001 - deliberate retained truncation
            "DELETE FROM fabric_health WHERE tenant_id=? AND device_id=? "
            "AND sample_id='sample-000'",
            (TENANT, DEVICE),
        )
        store._db.commit()  # noqa: SLF001
        with pytest.raises(RuntimeError, match="health retained|custody checkpoint"):
            store.dashboard_snapshot(TENANT)
    finally:
        store.close()


def test_authenticated_v1_migration_verifies_rows_chain_and_prune_boundary(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "migrated.db"
    store, clock = _enrolled_store(path, max_health=3)
    _record_rows(store, 5, observed=[200.0, 500.0, 300.0, 400.0, 600.0])
    old_generation = _downgrade_to_authenticated_v1(store)
    store.close()

    signature_checks = 0
    original_public_key = fleet_fabric.Ed25519PublicKey

    class MigrationPublicKey:
        @staticmethod
        def from_public_bytes(raw: bytes):
            verifier = original_public_key.from_public_bytes(raw)

            class Verifier:
                @staticmethod
                def verify(signature: bytes, payload: bytes) -> None:
                    nonlocal signature_checks
                    signature_checks += 1
                    verifier.verify(signature, payload)

            return Verifier()

    monkeypatch.setattr(fleet_fabric, "Ed25519PublicKey", MigrationPublicKey)
    migrated = FleetFabricStore(
        path,
        KEYS,
        max_health_evidence=3,
        clock=clock,
    )
    try:
        assert signature_checks >= 3
        custody = migrated.custody_snapshot(TENANT)
        assert custody["schema"] == CUSTODY_MANIFEST_SCHEMA_ID
        assert custody["generation"] == old_generation + 1
        assert custody["counts"]["health_evidence"] == 3
        assert custody["stats"]["health_retention_drops"] == 2
        assert "health_evidence_digest" in custody
        assert migrated.dashboard_snapshot(TENANT)["health"].total_rows == 3
    finally:
        migrated.close()

    bad_path = tmp_path / "tampered-before-migration.db"
    bad, bad_clock = _enrolled_store(bad_path)
    _record_rows(bad, 3)
    _downgrade_to_authenticated_v1(bad)
    bad.close()
    with sqlite3.connect(str(bad_path)) as db:
        db.execute(
            "UPDATE fabric_health SET evidence_json='{}' "
            "WHERE tenant_id=? AND sample_id='sample-000'",
            (TENANT,),
        )
        db.commit()
    with pytest.raises(RuntimeError, match="health evidence integrity"):
        FleetFabricStore(bad_path, KEYS, clock=bad_clock)


def test_health_mutation_fast_path_is_incremental_and_signature_bounded(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "fast-health.db"
    store, clock = _enrolled_store(path, max_health=250)
    _record_rows(store, 250)
    store.close()

    # Startup performs the complete authenticated audit once and installs an
    # exact generation/change-counter guarded snapshot for steady-state intake.
    store = FleetFabricStore(path, KEYS, max_health_evidence=250, clock=clock)
    clock.value += 2_000.0
    envelope = _next_health_envelope(store, 250)
    counters = {"decode": 0, "signature": 0, "select": 0}
    original_decode = store._decode_health  # noqa: SLF001
    original_public_key = fleet_fabric.Ed25519PublicKey

    def counted_decode(*args, **kwargs):
        counters["decode"] += 1
        return original_decode(*args, **kwargs)

    class CountingPublicKey:
        @staticmethod
        def from_public_bytes(raw: bytes):
            verifier = original_public_key.from_public_bytes(raw)

            class Verifier:
                @staticmethod
                def verify(signature: bytes, payload: bytes) -> None:
                    counters["signature"] += 1
                    verifier.verify(signature, payload)

            return Verifier()

    monkeypatch.setattr(store, "_decode_health", counted_decode)
    monkeypatch.setattr(fleet_fabric, "Ed25519PublicKey", CountingPublicKey)

    def trace(statement: str) -> None:
        if statement.lstrip().upper().startswith("SELECT"):
            counters["select"] += 1

    store._db.set_trace_callback(trace)  # noqa: SLF001
    try:
        store.record_health(envelope)
    finally:
        store._db.set_trace_callback(None)  # noqa: SLF001
    assert counters["decode"] == 0
    assert counters["signature"] == 1
    assert counters["select"] <= 10
    assert store._db.execute(  # noqa: SLF001
        "SELECT COUNT(*) FROM fabric_health WHERE tenant_id=?", (TENANT,)
    ).fetchone()[0] == 250
    assert store._db.execute(  # noqa: SLF001
        "SELECT 1 FROM fabric_health WHERE tenant_id=? AND sample_id='sample-250'",
        (TENANT,),
    ).fetchone() == (1,)
    store.close()


def test_invalid_health_signature_cannot_force_retained_decode(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "invalid-admission.db"
    store, clock = _enrolled_store(path, max_health=50)
    _record_rows(store, 50)
    store.close()
    store = FleetFabricStore(path, KEYS, max_health_evidence=50, clock=clock)
    valid = _next_health_envelope(store, 50)
    invalid = SignedFleetHealthEnvelope(
        valid.sample,
        valid.binding_generation,
        valid.sequence,
        valid.previous_evidence_digest,
        base64.b64encode(b"x" * 64).decode("ascii"),
    )
    custody_before = store._verified_custody_manifest_locked(TENANT)  # noqa: SLF001
    clock_before = store._db.execute(  # noqa: SLF001
        "SELECT last_seen,clock_hmac FROM fabric_clock_floor WHERE tenant_id=?",
        (TENANT,),
    ).fetchone()
    changes_before = store._db.total_changes  # noqa: SLF001
    data_version_before = store._sqlite_data_version_locked()  # noqa: SLF001
    process_clock_before = store._last_clock  # noqa: SLF001
    cache_before = store._health_custody_cache[TENANT]  # noqa: SLF001
    limiter_before = store._health_rate_limiter.snapshot(TENANT)  # noqa: SLF001
    decodes = 0
    original_decode = store._decode_health  # noqa: SLF001

    def counted_decode(*args, **kwargs):
        nonlocal decodes
        decodes += 1
        return original_decode(*args, **kwargs)

    monkeypatch.setattr(store, "_decode_health", counted_decode)
    with pytest.raises(PermissionError, match="signature is invalid"):
        store.record_health(invalid)
    assert decodes == 0
    assert store._db.total_changes == changes_before  # noqa: SLF001
    assert store._sqlite_data_version_locked() == data_version_before  # noqa: SLF001
    assert store._last_clock == process_clock_before  # noqa: SLF001
    assert store._db.execute(  # noqa: SLF001
        "SELECT last_seen,clock_hmac FROM fabric_clock_floor WHERE tenant_id=?",
        (TENANT,),
    ).fetchone() == clock_before
    assert store._verified_custody_manifest_locked(TENANT) == custody_before  # noqa: SLF001
    assert store._health_custody_cache[TENANT] is cache_before  # noqa: SLF001
    assert store._health_rate_limiter.snapshot(TENANT) == limiter_before  # noqa: SLF001

    # The invalid envelope did not burn the authenticated cache.  Once the
    # historical fixture's conservative restart bucket has refilled, the next
    # fresh sample remains a zero-retained-decode fast-path mutation.
    clock.value += 1_000.0
    store.record_health(valid)
    assert decodes == 0
    store.close()


def test_valid_health_intake_has_bounded_per_device_burst(tmp_path) -> None:
    store, _clock = _enrolled_store(tmp_path / "rate-bounded.db", max_health=5)
    store._health_rate_limiter._clock = lambda: 0.0  # noqa: SLF001
    _record_rows(store, 1)
    envelope = _next_health_envelope(store, 1)
    try:
        first = store.record_health(envelope)
        changes_before = store._db.total_changes  # noqa: SLF001
        data_version_before = store._sqlite_data_version_locked()  # noqa: SLF001
        clock_before = store._db.execute(  # noqa: SLF001
            "SELECT last_seen,clock_hmac FROM fabric_clock_floor WHERE tenant_id=?",
            (TENANT,),
        ).fetchone()
        custody_before = store._verified_custody_manifest_locked(TENANT)  # noqa: SLF001
        cache_before = store._health_custody_cache[TENANT]  # noqa: SLF001
        process_clock_before = store._last_clock  # noqa: SLF001
        limiter_before = store._health_rate_limiter.snapshot(TENANT)  # noqa: SLF001
        for _ in range(10):
            assert store.record_health(envelope).sample.sample_id == "sample-001"
        assert first.sample.sample_id == "sample-001"
        assert store._db.total_changes == changes_before  # noqa: SLF001
        assert store._sqlite_data_version_locked() == data_version_before  # noqa: SLF001
        assert store._db.execute(  # noqa: SLF001
            "SELECT last_seen,clock_hmac FROM fabric_clock_floor WHERE tenant_id=?",
            (TENANT,),
        ).fetchone() == clock_before
        assert store._last_clock == process_clock_before  # noqa: SLF001
        assert store._verified_custody_manifest_locked(TENANT) == custody_before  # noqa: SLF001
        assert store._health_custody_cache[TENANT] is cache_before  # noqa: SLF001
        assert store._health_rate_limiter.snapshot(TENANT) == limiter_before  # noqa: SLF001

        # Captured exact replays neither charge quota nor starve a fresh sample.
        assert store.record_health(_next_health_envelope(store, 2)).sample.sample_id == (
            "sample-002"
        )
    finally:
        store.close()


def test_health_rate_state_survives_restart_without_unbounded_history(
    tmp_path,
) -> None:
    path = tmp_path / "rate-restart.db"
    store, clock = _enrolled_store(path, max_health=5)
    _record_rows(store, 4)
    store.close()

    store = FleetFabricStore(path, KEYS, max_health_evidence=5, clock=clock)
    store._health_rate_limiter._clock = lambda: 0.0  # noqa: SLF001
    envelope = _next_health_envelope(store, 4)
    changes_before = store._db.total_changes  # noqa: SLF001
    data_version_before = store._sqlite_data_version_locked()  # noqa: SLF001
    clock_before = store._db.execute(  # noqa: SLF001
        "SELECT last_seen,clock_hmac FROM fabric_clock_floor WHERE tenant_id=?",
        (TENANT,),
    ).fetchone()
    custody_before = store._verified_custody_manifest_locked(TENANT)  # noqa: SLF001
    cache_before = store._health_custody_cache[TENANT]  # noqa: SLF001
    process_clock_before = store._last_clock  # noqa: SLF001
    limiter_before = store._health_rate_limiter.snapshot(TENANT)  # noqa: SLF001
    try:
        with pytest.raises(RuntimeError, match="rate limit"):
            store.record_health(envelope)
        assert store._db.total_changes == changes_before  # noqa: SLF001
        assert store._sqlite_data_version_locked() == data_version_before  # noqa: SLF001
        assert store._db.execute(  # noqa: SLF001
            "SELECT last_seen,clock_hmac FROM fabric_clock_floor WHERE tenant_id=?",
            (TENANT,),
        ).fetchone() == clock_before
        assert store._last_clock == process_clock_before  # noqa: SLF001
        assert store._verified_custody_manifest_locked(TENANT) == custody_before  # noqa: SLF001
        assert store._health_custody_cache[TENANT] is cache_before  # noqa: SLF001
        assert store._health_rate_limiter.snapshot(TENANT) == limiter_before  # noqa: SLF001
        assert len(cache_before.rate_state.devices) <= 5

        # The authenticated bucket refills at the configured rate; the
        # restart guard is fail-safe rather than permanently fail-closed.
        clock.value += 5.0
        assert store.record_health(envelope).sample.sample_id == "sample-004"
    finally:
        store.close()


def test_failed_health_transaction_does_not_consume_volatile_quota(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "transactional-health-quota.db"
    store, clock = _enrolled_store(path, max_health=1)
    peer_device = "device-peer"
    peer_private = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"cycle34-followup-peer").digest()
    )
    peer_public = base64.b64encode(
        peer_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    peer_digest = hashlib.sha256(base64.b64decode(peer_public)).hexdigest()
    peer_grant = store.issue_enrollment_grant(
        TENANT,
        peer_device,
        peer_digest,
        grant_id="grant-peer",
        ttl_seconds=60,
    )
    peer_proof = EnrollmentProof(
        TENANT,
        peer_device,
        peer_grant.grant_id,
        peer_grant.digest,
        peer_public,
        base64.b64encode(
            peer_private.sign(enrollment_possession_challenge(peer_grant))
        ).decode("ascii"),
    )
    clock.value += 1.0
    store.redeem_enrollment_grant(
        peer_grant,
        peer_proof,
        tenant_id=TENANT,
        device_id=peer_device,
        device_public_key_sha256=peer_digest,
    )
    clock.value += 1.0
    _record_rows(store, 1)
    store.close()

    store = FleetFabricStore(path, KEYS, max_health_evidence=1, clock=clock)
    store._health_rate_limiter._clock = lambda: 0.0  # noqa: SLF001
    peer_sample = FleetHealthSample(
        tenant_id=TENANT,
        device_id=peer_device,
        sample_id="sample-peer-000",
        device_public_key_sha256=peer_digest,
        observed_at=300.0,
        desired_policy_hash=DESIRED,
        effective_policy_hash=DESIRED,
        health_percent=100,
        health_reason="",
        queue_capacity=100,
        queue_depth=1,
        accepted_total=1,
        dropped_total=0,
        dropped_since_previous=0,
        rejected_total=0,
    )
    peer_payload = health_possession_payload(
        peer_sample,
        binding_generation=1,
        sequence=1,
        previous_evidence_digest=ZERO_DIGEST,
    )
    peer_envelope = SignedFleetHealthEnvelope(
        peer_sample,
        1,
        1,
        ZERO_DIGEST,
        base64.b64encode(peer_private.sign(peer_payload)).decode("ascii"),
    )
    clock_before = store._db.execute(  # noqa: SLF001
        "SELECT last_seen,clock_hmac FROM fabric_clock_floor WHERE tenant_id=?",
        (TENANT,),
    ).fetchone()
    custody_before = store._verified_custody_manifest_locked(TENANT)  # noqa: SLF001
    cache_before = store._health_custody_cache[TENANT]  # noqa: SLF001
    process_clock_before = store._last_clock  # noqa: SLF001
    data_version_before = store._sqlite_data_version_locked()  # noqa: SLF001

    def limiter_state():
        limiter = store._health_rate_limiter  # noqa: SLF001
        with limiter._lock:  # noqa: SLF001
            return (
                tuple(limiter._buckets.items()),  # noqa: SLF001
                {tenant: tuple(stats) for tenant, stats in limiter._stats.items()},  # noqa: SLF001
            )

    limiter_before = limiter_state()

    def assert_rolled_back() -> None:
        assert not store._db.in_transaction  # noqa: SLF001
        assert store._sqlite_data_version_locked() == data_version_before  # noqa: SLF001
        assert store._db.execute(  # noqa: SLF001
            "SELECT last_seen,clock_hmac FROM fabric_clock_floor WHERE tenant_id=?",
            (TENANT,),
        ).fetchone() == clock_before
        assert store._last_clock == process_clock_before  # noqa: SLF001
        assert store._verified_custody_manifest_locked(TENANT) == custody_before  # noqa: SLF001
        assert store._health_custody_cache[TENANT] is cache_before  # noqa: SLF001
        assert limiter_state() == limiter_before
        assert store._db.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM fabric_health WHERE tenant_id=?",
            (TENANT,),
        ).fetchone() == (1,)
        assert store._db.execute(  # noqa: SLF001
            "SELECT 1 FROM fabric_health WHERE tenant_id=? AND device_id=?",
            (TENANT, peer_device),
        ).fetchone() is None

    try:
        # Two distinct device heads cannot fit under a one-row bound.  Repeated
        # post-validation prune failures must not burn the peer's burst quota.
        for _ in range(4):
            with pytest.raises(OverflowError, match="chain heads"):
                store.record_health(peer_envelope)
            assert_rolled_back()

        feasible = _next_health_envelope(store, 1)
        original_custody = store._write_incremental_health_custody_locked  # noqa: SLF001

        def fail_custody(*_args, **_kwargs):
            raise RuntimeError("injected custody write failure")

        monkeypatch.setattr(
            store,
            "_write_incremental_health_custody_locked",
            fail_custody,
        )
        with pytest.raises(RuntimeError, match="injected custody"):
            store.record_health(feasible)
        assert_rolled_back()
        monkeypatch.setattr(
            store,
            "_write_incremental_health_custody_locked",
            original_custody,
        )

        original_commit = store._commit_health_transaction_locked  # noqa: SLF001

        def fail_commit() -> None:
            acquired = store._health_rate_limiter._lock.acquire(  # noqa: SLF001
                blocking=False
            )
            if acquired:
                store._health_rate_limiter._lock.release()  # noqa: SLF001
            assert not acquired, "volatile quota reservation was not exclusive"
            raise sqlite3.OperationalError("injected health commit failure")

        monkeypatch.setattr(
            store,
            "_commit_health_transaction_locked",
            fail_commit,
        )
        with pytest.raises(sqlite3.OperationalError, match="injected health commit"):
            store.record_health(feasible)
        assert_rolled_back()
        monkeypatch.setattr(
            store,
            "_commit_health_transaction_locked",
            original_commit,
        )

        # The same store still has its full volatile allowance, and a feasible
        # same-device replacement commits successfully after every failure.
        assert store.record_health(feasible).sample.sample_id == "sample-001"
        assert store._health_rate_limiter.snapshot(TENANT)[  # noqa: SLF001
            "admitted_events"
        ] == 1
    finally:
        store.close()


@pytest.mark.parametrize("tamper", ["same-connection", "external", "delete-insert"])
def test_health_cache_guards_force_full_fail_closed_reverification(
    tmp_path,
    tamper,
) -> None:
    path = tmp_path / f"cache-guard-{tamper}.db"
    store, clock = _enrolled_store(path, max_health=5)
    _record_rows(store, 5)
    store.close()
    store = FleetFabricStore(path, KEYS, max_health_evidence=5, clock=clock)
    clock.value += 100.0
    envelope = _next_health_envelope(store, 5)
    if tamper == "same-connection":
        store._db.execute(  # noqa: SLF001
            "UPDATE fabric_health SET observed_at=observed_at+0.5 "
            "WHERE tenant_id=? AND sample_id='sample-002'",
            (TENANT,),
        )
        store._db.commit()  # noqa: SLF001
    elif tamper == "external":
        with sqlite3.connect(str(path)) as db:
            db.execute(
                "DELETE FROM fabric_health WHERE tenant_id=? "
                "AND sample_id='sample-002'",
                (TENANT,),
            )
            db.commit()
    else:
        replacement = store._db.execute(  # noqa: SLF001
            "SELECT evidence_json FROM fabric_health WHERE tenant_id=? "
            "AND sample_id='sample-003'",
            (TENANT,),
        ).fetchone()[0]
        store._db.execute(  # noqa: SLF001
            "DELETE FROM fabric_health WHERE tenant_id=? AND sample_id='sample-002'",
            (TENANT,),
        )
        store._db.execute(  # noqa: SLF001
            "INSERT INTO fabric_health VALUES (?,?,?,?,?)",
            (TENANT, DEVICE, "sample-002", 202.0, replacement),
        )
        store._db.commit()  # noqa: SLF001
    with pytest.raises(RuntimeError, match="health|custody"):
        store.record_health(envelope)
    assert store._db.execute(  # noqa: SLF001
        "SELECT 1 FROM fabric_health WHERE tenant_id=? AND sample_id='sample-005'",
        (TENANT,),
    ).fetchone() is None
    store.close()


def test_health_retention_bound_rejects_unserviceable_cache_sizes(tmp_path) -> None:
    with pytest.raises(ValueError, match="cadence budget"):
        FleetFabricStore(
            tmp_path / "oversized.db",
            KEYS,
            max_health_evidence=fleet_fabric.MAX_RETAINED_HEALTH_EVIDENCE + 1,
        )
    store = FleetFabricStore(tmp_path / "bounded.db", KEYS)
    try:
        assert store._max_health == 5_000  # noqa: SLF001
        assert (
            fleet_fabric._MAX_HEALTH_CACHE_ENCODED_BYTES  # noqa: SLF001
            == 5_000 * fleet_fabric.MAX_HEALTH_EVIDENCE_BYTES
        )
    finally:
        store.close()


def test_health_cache_total_changes_rejects_in_transaction_extra_write(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "cache-in-transaction.db"
    store, clock = _enrolled_store(path, max_health=5)
    _record_rows(store, 5)
    store.close()
    store = FleetFabricStore(path, KEYS, max_health_evidence=5, clock=clock)
    clock.value += 100.0
    envelope = _next_health_envelope(store, 5)
    original_prune = store._prune_health_locked  # noqa: SLF001

    def prune_then_tamper(*args, **kwargs):
        result = original_prune(*args, **kwargs)
        store._db.execute(  # noqa: SLF001 - simulated same-transaction corruption
            "UPDATE fabric_health SET evidence_json='{}' "
            "WHERE tenant_id=? AND sample_id='sample-002'",
            (TENANT,),
        )
        return result

    monkeypatch.setattr(store, "_prune_health_locked", prune_then_tamper)
    with pytest.raises(RuntimeError, match="changed unexpected rows"):
        store.record_health(envelope)
    assert store._db.execute(  # noqa: SLF001
        "SELECT evidence_json FROM fabric_health WHERE tenant_id=? "
        "AND sample_id='sample-002'",
        (TENANT,),
    ).fetchone()[0] != "{}"
    assert store._db.execute(  # noqa: SLF001
        "SELECT 1 FROM fabric_health WHERE tenant_id=? AND sample_id='sample-005'",
        (TENANT,),
    ).fetchone() is None
    store.close()


def _operations_window(tmp_path: Path) -> SimpleNamespace:
    from angerona.gui.main_window import MainWindow

    window = SimpleNamespace(
        config=SimpleNamespace(data_dir=tmp_path),
        evidence_store=None,
        manager=object(),
        _ECO_HEAVY_MODULES=(),
        startup_eco_requested=SimpleNamespace(emit=lambda: None),
        _operations_service=None,
        _operations_service_lock=threading.Lock(),
        _operations_service_shutdown=False,
        _operations_service_cancel=threading.Event(),
        _operations_service_state="waiting",
        _operations_service_build_token=None,
        _operations_service_completion=threading.Event(),
        _operations_service_error="",
        _operations_modules_discovered=threading.Event(),
        _operations_modules_ready=threading.Event(),
    )
    window._mark_operations_modules_discovered = lambda: (
        MainWindow._mark_operations_modules_discovered(window)
    )
    window._ensure_operations_service = lambda **kwargs: (
        MainWindow._ensure_operations_service(window, **kwargs)
    )
    window._begin_operations_shutdown = lambda: (
        MainWindow._begin_operations_shutdown(window)
    )
    window._close_operations_service = lambda: (
        MainWindow._close_operations_service(window)
    )
    return window


def _loader_app(window, trace: list[str]):
    from angerona.app import AngeronaApp

    class Manager:
        modules = {}

        @staticmethod
        def discover() -> None:
            trace.append("discover")

        @staticmethod
        def start_enabled(*, deferred_names) -> None:
            trace.append("modules-start")

    app = AngeronaApp.__new__(AngeronaApp)
    app._shutdown_requested = threading.Event()
    app._shutdown_gate = threading.Lock()
    app._startup_lifecycle_lock = threading.Lock()
    app.config = SimpleNamespace(eco_mode=False, blackbox_enabled=False)
    app.bus = object()
    app.manager = Manager()
    app.window = window
    window.manager = app.manager
    app.reporter = SimpleNamespace(start=lambda: trace.append("reporter-start"))
    app._mcp = None
    app._resilience = None
    app._record_startup_degradation = (
        lambda service, impact, exc, *_args: trace.append(
            f"degraded:{service}:{type(exc).__name__}"
        )
    )
    app._start_fleet_service = lambda: trace.append("fleet-start") or True
    return app


@pytest.mark.parametrize("reservation_owner", ["loader", "ui"])
def test_operations_readiness_reservation_blocks_modules_and_shutdown_orphans_once(
    tmp_path,
    monkeypatch,
    reservation_owner,
) -> None:
    from angerona.gui.main_window import MainWindow

    entered = threading.Event()
    release = threading.Event()
    discovery = threading.Event()
    let_loader_continue = threading.Event()
    created = []
    trace: list[str] = []

    class Service:
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    def factory(*_args, **_kwargs):
        entered.set()
        assert release.wait(timeout=5)
        service = Service()
        created.append(service)
        trace.append("factory-return")
        return service

    monkeypatch.setattr("angerona.core.operations_center.LocalOperationsCenter", factory)
    monkeypatch.setenv("ANGERONA_RESILIENCE", "0")
    window = _operations_window(tmp_path)
    if reservation_owner == "ui":
        def mark_and_pause() -> None:
            MainWindow._mark_operations_modules_discovered(window)
            discovery.set()
            assert let_loader_continue.wait(timeout=5)

        window._mark_operations_modules_discovered = mark_and_pause
    app = _loader_app(window, trace)
    loader = threading.Thread(target=app._load_modules, daemon=True)
    loader.start()

    if reservation_owner == "ui":
        assert discovery.wait(timeout=3)
        before = time.perf_counter()
        with pytest.raises(RuntimeError, match="in progress"):
            MainWindow._ensure_operations_service(window)
        assert time.perf_counter() - before < 0.25
        let_loader_continue.set()
    assert entered.wait(timeout=3)
    assert "modules-start" not in trace
    MainWindow._begin_operations_shutdown(window)
    assert window._operations_service_cancel.is_set()
    assert "modules-start" not in trace
    release.set()
    loader.join(timeout=3)
    assert not loader.is_alive()
    deadline = time.time() + 3
    while not created and time.time() < deadline:
        time.sleep(0.01)
    MainWindow._close_operations_service(window)
    assert len(created) == 1 and created[0].close_calls == 1
    assert window._operations_service is None
    assert not window._operations_modules_ready.is_set()


@pytest.mark.parametrize("reservation_owner", ["loader", "ui"])
def test_successful_operations_reservation_publishes_before_modules_start(
    tmp_path,
    monkeypatch,
    reservation_owner,
) -> None:
    from angerona.gui.main_window import MainWindow

    trace: list[str] = []
    discovery = threading.Event()
    let_loader_continue = threading.Event()

    class Service:
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    service = Service()

    def factory(*_args, **_kwargs):
        trace.append("service-ready")
        return service

    monkeypatch.setattr("angerona.core.operations_center.LocalOperationsCenter", factory)
    monkeypatch.setenv("ANGERONA_RESILIENCE", "0")
    window = _operations_window(tmp_path)
    if reservation_owner == "ui":
        def mark_and_pause() -> None:
            MainWindow._mark_operations_modules_discovered(window)
            discovery.set()
            assert let_loader_continue.wait(timeout=5)

        window._mark_operations_modules_discovered = mark_and_pause
    app = _loader_app(window, trace)
    loader = threading.Thread(target=app._load_modules, daemon=True)
    loader.start()
    if reservation_owner == "ui":
        assert discovery.wait(timeout=3)
        with pytest.raises(RuntimeError, match="in progress"):
            MainWindow._ensure_operations_service(window)
        let_loader_continue.set()
    loader.join(timeout=5)

    assert not loader.is_alive()
    assert window._operations_modules_ready.is_set()
    assert window._operations_service is service
    assert trace.index("service-ready") < trace.index("modules-start")
    MainWindow._close_operations_service(window)
    assert service.close_calls == 1


def test_operations_factory_failure_is_explicit_fail_closed_startup(
    tmp_path,
    monkeypatch,
) -> None:
    trace: list[str] = []

    def fail(*_args, **_kwargs):
        raise OSError("private path must not leak")

    monkeypatch.setattr("angerona.core.operations_center.LocalOperationsCenter", fail)
    monkeypatch.setenv("ANGERONA_RESILIENCE", "0")
    window = _operations_window(tmp_path)
    app = _loader_app(window, trace)
    app._load_modules()

    assert window._operations_service_state == "failed"
    assert window._operations_service_error == "OSError"
    assert not window._operations_modules_ready.is_set()
    assert "modules-start" not in trace
    assert any(item.startswith("degraded:Local SOC") for item in trace)
