from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

import pytest

from angerona.core.detection_packages import seal_package
from angerona.core.detection_registry import DetectionPackageRegistry
from angerona.core.fleet_fabric import (
    FleetFabricStore,
    FleetRolloutPlan,
    _canonical,
    _hmac,
)
from angerona.modules.detection_runtime import (
    DetectionRuntimeEngine,
    DetectionRuntimeError,
)


class _Clock:
    def __call__(self) -> float:
        return 1_000.0


def _seed_rollouts(store: FleetFabricStore, count: int) -> None:
    desired = hashlib.sha256(b"cycle34-desired").hexdigest()
    previous = hashlib.sha256(b"cycle34-previous").hexdigest()
    with store._lock:  # noqa: SLF001 - authenticated bounded performance fixture
        store._db.execute("BEGIN IMMEDIATE")  # noqa: SLF001
        for index in range(count):
            rollout_id = f"rollout-{index:03d}"
            plan = FleetRolloutPlan(
                tenant_id="tenant-local",
                rollout_id=rollout_id,
                policy_bundle_id=f"bundle-{index:03d}",
                group_id="group-local",
                desired_policy_hash=desired,
                previous_policy_hash=previous,
                target_device_ids=("device-local",),
                canary_device_ids=("device-local",),
                minimum_health_percent=90,
                max_canary_failures=0,
                created_at=900.0,
                change_context={"ticket": f"CHG-{index:04d}"},
            )
            record = store._rollout_record(  # noqa: SLF001
                plan,
                "staged",
                1,
                "awaiting explicit canary start",
                900.0 + index / 1_000,
                store._key("tenant-local"),  # noqa: SLF001
            )
            store._db.execute(  # noqa: SLF001
                "INSERT INTO fabric_rollouts(tenant_id,rollout_id,plan_json,state,"
                "version,reason,updated_at,record_hmac,evaluation_json,"
                "canary_started_at,canary_generation) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "tenant-local",
                    rollout_id,
                    _canonical(asdict(plan)).decode("utf-8"),
                    "staged",
                    1,
                    record["reason"],
                    record["updated_at"],
                    record["record_hmac"],
                    "{}",
                    0.0,
                    0,
                ),
            )
            store._append_rollout_history_locked(plan, record)  # noqa: SLF001
        store._write_custody_locked("tenant-local")  # noqa: SLF001
        store._db.commit()  # noqa: SLF001


def test_dashboard_uses_one_stable_custody_pass_and_batched_rollout_sql(
    tmp_path, monkeypatch,
) -> None:
    store = FleetFabricStore(
        tmp_path / "fleet.db", {"tenant-local": b"f" * 32}, clock=_Clock()
    )
    try:
        _seed_rollouts(store, 12)
        custody_calls = 0
        original_verify = store._verify_custody_locked  # noqa: SLF001

        def counted_verify(*args, **kwargs):
            nonlocal custody_calls
            custody_calls += 1
            return original_verify(*args, **kwargs)

        monkeypatch.setattr(store, "_verify_custody_locked", counted_verify)
        statements: list[str] = []
        store._db.set_trace_callback(statements.append)  # noqa: SLF001
        snapshot = store.dashboard_snapshot("tenant-local")
        store._db.set_trace_callback(None)  # noqa: SLF001

        selects = [
            statement
            for statement in statements
            if statement.lstrip().upper().startswith("SELECT")
        ]
        rollout_selects = [
            statement for statement in selects if "fabric_rollouts" in statement
        ]
        history_selects = [
            statement for statement in selects if "fabric_rollout_history" in statement
        ]
        assert custody_calls == 1
        assert len(rollout_selects) == 1
        assert len(history_selects) == 1
        assert len(selects) <= 15
        assert sum(statement == "BEGIN" for statement in statements) == 1
        assert sum(statement == "ROLLBACK" for statement in statements) == 1
        assert [row["rollout_id"] for row in snapshot["rollouts"]] == [
            f"rollout-{index:03d}" for index in reversed(range(12))
        ]
        assert snapshot["authenticated_custody_checkpoint"]["counts"][
            "rollout_history"
        ] == 12
    finally:
        store.close()


def test_batched_rollout_history_still_fails_closed_on_any_invalid_hmac(
    tmp_path,
) -> None:
    store = FleetFabricStore(
        tmp_path / "fleet.db", {"tenant-local": b"f" * 32}, clock=_Clock()
    )
    try:
        _seed_rollouts(store, 12)
        store._db.execute(  # noqa: SLF001 - deliberate retained-chain tamper
            "UPDATE fabric_rollout_history SET history_hmac=? "
            "WHERE tenant_id=? AND rollout_id=? AND version=1",
            ("0" * 64, "tenant-local", "rollout-006"),
        )
        store._db.commit()  # noqa: SLF001
        with pytest.raises(RuntimeError, match="rollout history integrity"):
            store.dashboard_snapshot("tenant-local")
    finally:
        store.close()


def test_batched_custody_rejects_authenticated_orphan_rollout_history(
    tmp_path,
) -> None:
    store = FleetFabricStore(
        tmp_path / "fleet.db", {"tenant-local": b"f" * 32}, clock=_Clock()
    )
    try:
        _seed_rollouts(store, 1)
        with store._lock:  # noqa: SLF001 - deliberate legacy/orphan fixture
            store._db.execute(  # noqa: SLF001
                "INSERT INTO fabric_rollout_history "
                "SELECT tenant_id,?,version,state,record_json,evaluation_digest,"
                "previous_history_digest,? FROM fabric_rollout_history "
                "WHERE tenant_id=? AND rollout_id=?",
                (
                    "orphan-rollout",
                    "0" * 64,
                    "tenant-local",
                    "rollout-000",
                ),
            )
            manifest = json.loads(_canonical(
                store._verified_custody_manifest_locked("tenant-local")  # noqa: SLF001
            ))
            manifest["counts"]["rollout_history"] += 1
            store._db.execute(  # noqa: SLF001
                "UPDATE fabric_custody SET manifest_json=?,manifest_hmac=? "
                "WHERE tenant_id=?",
                (
                    _canonical(manifest).decode("utf-8"),
                    _hmac(
                        store._key("tenant-local"),  # noqa: SLF001
                        b"fabric-custody",
                        manifest,
                    ),
                    "tenant-local",
                ),
            )
            store._db.commit()  # noqa: SLF001

        with pytest.raises(RuntimeError, match="without a retained rollout parent"):
            store.dashboard_snapshot("tenant-local")
    finally:
        store.close()


def _detection_document(index: int) -> dict[str, object]:
    marker = f"cycle34-marker-{index:03d}"
    return seal_package({
        "schema_version": 1,
        "id": f"org.angerona.round2-perf-{index:03d}",
        "version": "1.0.0",
        "owner": "Angerona performance regression",
        "description": "Bounded full-set runtime reconciliation fixture.",
        "telemetry": ["process.creation"],
        "attack": ["T1059.001"],
        "severity": "high",
        "confidence": 90,
        "logic": {"type": "sigma-subset", "detection": {
            "selection": {"cmdline|contains": marker},
            "condition": "selection",
        }},
        "fixtures": [{
            "name": "hit",
            "event": {"cmdline": marker},
            "expected_match": True,
        }],
        "performance": {"max_eval_ms": 50, "max_events_per_second": 1_000},
        "rollback": {"previous_digest": None, "instructions": "Restore predecessor."},
        "expires_at": "2099-01-01T00:00:00Z",
    })


def _active_detection_registry(tmp_path, count: int):
    registry = DetectionPackageRegistry(
        tmp_path / "registry", require_signed=False
    )
    bindings: dict[str, str] = {}
    for index in range(count):
        document = _detection_document(index)
        source = tmp_path / f"detection-{index:03d}.json"
        source.write_text(json.dumps(document), encoding="utf-8")
        staged = registry.stage(source)
        assert staged.ok
        assert registry.activate(staged.package_id, staged.digest).ok
        bindings[str(staged.package_id)] = str(staged.digest)
    return registry, bindings


def test_full_set_reconciliation_reads_registry_manifest_exactly_twice(
    tmp_path, monkeypatch,
) -> None:
    registry, bindings = _active_detection_registry(tmp_path, 8)
    manifest_reads = 0
    original_manifest = registry._manifest  # noqa: SLF001

    def counted_manifest():
        nonlocal manifest_reads
        manifest_reads += 1
        return original_manifest()

    monkeypatch.setattr(registry, "_manifest", counted_manifest)
    runtime = DetectionRuntimeEngine()
    active = runtime.sync_active_set_from_registry(
        registry,
        expected_bindings=bindings,
        activation_epoch=1,
    )
    assert manifest_reads == 2
    assert active == tuple(bindings[package_id] for package_id in sorted(bindings))


def test_full_set_reconciliation_detects_out_of_band_manifest_change(
    tmp_path, monkeypatch,
) -> None:
    registry, bindings = _active_detection_registry(tmp_path, 2)
    original_trusted_active = registry._trusted_active_locked  # noqa: SLF001
    changed = False

    def change_after_trust(*args, **kwargs):
        nonlocal changed
        package = original_trusted_active(*args, **kwargs)
        if not changed:
            changed = True
            document = json.loads(registry.manifest_path.read_text(encoding="utf-8"))
            document["packages"]["org.angerona.out-of-band"] = {}
            registry.manifest_path.write_text(json.dumps(document), encoding="utf-8")
        return package

    monkeypatch.setattr(registry, "_trusted_active_locked", change_after_trust)
    runtime = DetectionRuntimeEngine()
    with pytest.raises(DetectionRuntimeError, match="manifest changed"):
        runtime.sync_active_set_from_registry(
            registry,
            expected_bindings=bindings,
            activation_epoch=1,
        )
    assert runtime.snapshot().active_digests == ()
