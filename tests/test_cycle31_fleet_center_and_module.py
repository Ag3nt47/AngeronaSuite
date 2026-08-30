from __future__ import annotations

import base64
import hashlib
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from angerona.core.fleet_fabric import (
    ZERO_DIGEST,
    CoordinatorTransportConfig,
    EnrollmentProof,
    FleetFabricStore,
    FleetHealthSample,
    FleetRolloutPlan,
    SignedFleetHealthEnvelope,
    enrollment_possession_challenge,
    health_possession_payload,
    validate_transport_config,
)
from angerona.core.module_contract import build_capability_contract
from angerona.gui.fleet_center import FleetCenterDialog, FleetCenterWidget
from angerona.modules.fleet_health_monitor import FleetHealthMonitorModule

KEYS = {"tenant-local": b"l" * 32}
DESIRED = hashlib.sha256(b"desired").hexdigest()
PREVIOUS = hashlib.sha256(b"previous").hexdigest()
DRIFTED = hashlib.sha256(b"drifted").hexdigest()


class _Clock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def set(self, value: float) -> None:
        self.value = value


def _private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"device-key").digest())


def _public() -> str:
    raw = _private().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")


def _digest() -> str:
    return hashlib.sha256(base64.b64decode(_public())).hexdigest()


def _store(
    tmp_path, *, max_health_evidence: int = 100
) -> tuple[FleetFabricStore, _Clock]:
    clock = _Clock(100)
    store = FleetFabricStore(
        tmp_path / "fabric.db", KEYS, max_health_evidence=max_health_evidence,
        clock=clock,
    )
    grant = store.issue_enrollment_grant(
        "tenant-local", "device-local", _digest(),
        grant_id="grant-local", ttl_seconds=60,
    )
    proof = EnrollmentProof(
        grant.tenant_id,
        grant.device_id,
        grant.grant_id,
        grant.digest,
        _public(),
        base64.b64encode(_private().sign(
            enrollment_possession_challenge(grant)
        )).decode("ascii"),
    )
    clock.set(101)
    store.redeem_enrollment_grant(
        grant,
        proof,
        tenant_id="tenant-local",
        device_id="device-local",
        device_public_key_sha256=_digest(),
    )
    return store, clock


def _sample(
    sample_id: str,
    *,
    observed_at: float = 202,
    effective: str = DESIRED,
    health: int = 100,
    reason: str = "",
    queue_depth: int = 1,
    accepted: int = 100,
    dropped: int = 0,
    rollout_id: str = "",
    rollout_generation: int = 0,
) -> FleetHealthSample:
    return FleetHealthSample(
        "tenant-local",
        "device-local",
        sample_id,
        _digest(),
        observed_at,
        DESIRED,
        effective,
        health,
        reason,
        100,
        queue_depth,
        accepted,
        dropped,
        dropped,
        0,
        rollout_id,
        rollout_generation,
    )


def _signed(
    sample: FleetHealthSample, *, sequence: int = 1, previous: str = ZERO_DIGEST
) -> SignedFleetHealthEnvelope:
    payload = health_possession_payload(
        sample,
        binding_generation=1,
        sequence=sequence,
        previous_evidence_digest=previous,
    )
    return SignedFleetHealthEnvelope(
        sample,
        1,
        sequence,
        previous,
        base64.b64encode(_private().sign(payload)).decode("ascii"),
    )


def _halted_rollout(store: FleetFabricStore, clock: _Clock) -> None:
    plan = FleetRolloutPlan(
        "tenant-local",
        "rollout-local",
        "bundle-local",
        "group-local",
        DESIRED,
        PREVIOUS,
        ("device-local",),
        ("device-local",),
        90,
        0,
        200,
        {"ticket": "CHG-31"},
    )
    clock.set(200)
    store.stage_rollout(plan)
    clock.set(201)
    canary = store.start_canary(
        "tenant-local", "rollout-local", expected_version=1,
        desired_policy_hash=DESIRED,
    )
    clock.set(203)
    store.record_health(_signed(_sample(
        "sample-bad", observed_at=202, effective=DRIFTED, health=40,
        reason="effective hash drifted and queue is saturated", queue_depth=95,
        dropped=2, rollout_id="rollout-local",
        rollout_generation=canary["canary_generation"],
    )))
    clock.set(204)
    store.evaluate_canary(
        "tenant-local", "rollout-local", expected_version=2,
        desired_policy_hash=DESIRED,
    )


def test_coordinator_transport_is_disabled_loopback_and_incomplete_mtls_fails_closed(
    tmp_path,
) -> None:
    default = validate_transport_config(CoordinatorTransportConfig())
    assert default.enabled is False
    assert default.loopback_bind is True
    assert default.configuration_valid is True
    assert default.transport_available is False
    assert default.endpoint_scope == "loopback"
    assert default.reason == "disabled-by-default"

    incomplete = validate_transport_config(CoordinatorTransportConfig(
        enabled=True,
        endpoint="https://coordinator.example.test:9443",
        bind_host="127.0.0.1",
        server_name="coordinator.example.test",
        expected_peer_sha256="0" * 64,
    ))
    assert incomplete.mtls_complete is False
    assert incomplete.configuration_valid is False
    assert incomplete.transport_available is False
    assert "required" in incomplete.reason

    non_loopback_bind = validate_transport_config(CoordinatorTransportConfig(
        enabled=True,
        endpoint="https://coordinator.example.test:9443",
        bind_host="0.0.0.0",
        server_name="coordinator.example.test",
        expected_peer_sha256="0" * 64,
        ca_bundle=tmp_path / "missing-ca.pem",
        client_certificate=tmp_path / "missing-cert.pem",
        client_private_key=tmp_path / "missing-key.pem",
    ))
    assert non_loopback_bind.configuration_valid is False
    assert non_loopback_bind.transport_available is False
    assert "loopback" in non_loopback_bind.reason


def test_fleet_health_module_has_full_native_observe_only_contract() -> None:
    module = FleetHealthMonitorModule()
    contract = build_capability_contract(
        module, capability_id="angerona.fleet_health_monitor"
    )
    assert contract.metadata_level == "native"
    assert contract.metadata_gaps == ()
    assert contract.implementation_version == "1.13.0"
    assert contract.mode == "detect"
    assert contract.response_authority == "none"
    assert contract.egress == "none"
    assert set(contract.supported_platforms) == {"windows", "macos", "linux"}
    assert contract.self_test == "module-specific"
    assert module.self_test()[0]
    health, reason, details = module.observe_once()
    assert health == 35
    assert reason == "local Fleet Fabric store is not bound"
    assert details["transport_available"] is False


def test_module_reports_missing_roster_then_healthy_signed_evidence(tmp_path) -> None:
    store, clock = _store(tmp_path)
    module = FleetHealthMonitorModule()
    module.bind_fabric(store, "tenant-local")
    health, reason, details = module.observe_once()
    assert health == 40
    assert "device-local" in reason
    assert details["missing_devices"] == 1

    clock.set(203)
    store.record_health(_signed(_sample("sample-healthy", observed_at=202)))
    health, reason, details = module.observe_once()
    assert (health, reason) == (100, "")
    assert details["fresh_devices"] == 1
    assert details["stats_authenticated"] is True
    store.close()


def test_module_surfaces_retention_loss_before_endpoint_health(tmp_path) -> None:
    store, clock = _store(tmp_path, max_health_evidence=1)
    clock.set(202)
    old = store.record_health(_signed(_sample("sample-old", observed_at=201)))
    clock.set(204)
    store.record_health(_signed(
        _sample(
            "sample-new", observed_at=203, health=70,
            reason="sensor evidence is incomplete", accepted=101,
        ),
        sequence=2,
        previous=old.digest,
    ))
    module = FleetHealthMonitorModule()
    module.bind_fabric(store, "tenant-local")
    health, reason, details = module.observe_once()
    assert health == 50
    assert reason.startswith("local evidence retention discarded 1")
    assert details["unhealthy_devices"] == 1
    store.close()


def test_module_marks_deleted_custody_state_critical_with_exact_reason(tmp_path) -> None:
    store, _clock = _store(tmp_path)
    module = FleetHealthMonitorModule()
    module.bind_fabric(store, "tenant-local")
    store._db.execute(  # noqa: SLF001 - exact statistics deletion regression
        "DELETE FROM fabric_stats WHERE tenant_id=?", ("tenant-local",)
    )
    module._tick()  # noqa: SLF001 - one deterministic observe cycle
    assert module.health_pct == 25
    assert "fleet statistics row is unavailable" in module.health_note
    assert module.health_evidence is not None
    assert module.health_evidence["source_path"].endswith("fleet_health_monitor.py")
    store.close()


def test_embeddable_center_is_clickable_proposal_only_and_clears_atomically(
    tmp_path, monkeypatch,
) -> None:
    app = QApplication.instance() or QApplication([])
    store, clock = _store(tmp_path)
    _halted_rollout(store, clock)
    widget = FleetCenterWidget(store)
    try:
        assert widget.health_table.isSortingEnabled()
        assert widget.rollout_table.isSortingEnabled()
        assert widget.enrollment_table.isSortingEnabled()
        assert widget.health_table.rowCount() == 1
        assert widget.rollout_table.rowCount() == 1
        assert widget.enrollment_table.rowCount() == 1

        widget._health_clicked(0, 0)
        assert "DEVICE-SIGNED HEALTH" in widget.selected_evidence
        assert '"health_reason": "effective hash drifted' in widget.selected_evidence

        widget._rollout_clicked(0, 0)
        assert widget.rollback_button.isEnabled()
        widget._preview_rollback()
        detail = widget.selected_evidence
        assert "PROPOSAL-ONLY ROLLBACK PLAN" in detail
        assert '"execution_authorized": false' in detail
        assert '"response_authority": "proposal-only"' in detail
        assert '"command"' not in detail

        def unavailable(_tenant_id: str):
            raise RuntimeError("integrity unavailable")

        monkeypatch.setattr(store, "dashboard_snapshot", unavailable)
        widget.refresh()
        assert widget.health_table.rowCount() == 0
        assert widget.rollout_table.rowCount() == 0
        assert widget.enrollment_table.rowCount() == 0
        assert widget.selected_evidence == ""
        assert widget.rollback_button.isEnabled() is False
        assert "integrity unavailable" in widget.status.text()
    finally:
        widget.close()
        app.processEvents()
        store.close()


def test_dialog_is_only_a_wrapper_around_embeddable_center(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    store, _clock = _store(tmp_path)
    dialog = FleetCenterDialog(store)
    try:
        assert isinstance(dialog.center, FleetCenterWidget)
        assert dialog.center.fabric is store
        assert dialog.center.enrollment_table.rowCount() == 1
    finally:
        dialog.close()
        app.processEvents()
        store.close()
