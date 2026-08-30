"""Observe-only health monitor for the local Fleet Fabric evidence store."""
from __future__ import annotations

import hashlib
import time

from angerona.core.fleet_fabric import (
    FleetFabricStore,
    FleetHealthSample,
    FleetRolloutPlan,
)
from angerona.core.module_base import BaseModule, Severity

SUPPORTED_PLATFORMS = ("windows", "macos", "linux")
POLL_INTERVAL_SECONDS = 30.0


class FleetHealthMonitorModule(BaseModule):
    CODE = "FLTH"
    NAME = "Fleet Health Monitor"
    name = NAME
    description = (
        "Detects bounded Fleet Fabric evidence loss, queue backpressure, policy drift, "
        "custody deletion, unhealthy endpoints, and fail-closed coordinator readiness "
        "without mutating hosts."
    )
    category = "Fleet"
    version = "1.13.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "detect"
    maturity_channel = "preview"
    platform_requirements = (
        "An explicitly bound local FleetFabricStore for cross-device evidence",
        "Per-tenant key custody established by the existing fleet credential layer",
        "Ed25519 endpoint key custody for device possession and health signatures",
    )
    capability_permissions = ("fleet.fabric.read-local-evidence",)
    high_risk_permissions = ()
    capability_inputs = (
        "ed25519-device-signed-fleet-health-evidence",
        "tenant-hmac-custody-checkpoint-and-prune-tombstones",
        "coordinator-configuration-readiness",
    )
    capability_outputs = (
        "fleet-health-status-event",
        "fleet-loss-and-backpressure-finding",
        "policy-drift-finding",
    )
    data_classes = (
        "pseudonymous-device-identifiers",
        "policy-digests",
        "bounded-health-and-loss-counters",
    )
    egress = "none"
    retention = "bounded-hmac-custody-sealed-local-sqlite-with-prune-tombstones"
    response_authority = "none"
    capability_dependencies = (
        "angerona.core.fleet_fabric",
        "angerona.core.fleet_control_plane",
        "angerona.core.policy_bundle",
    )
    capability_conflicts = ()
    settings_schema = {
        "type": "object",
        "properties": {
            "poll_interval_seconds": {
                "type": "number", "minimum": 5, "maximum": 3600,
                "default": POLL_INTERVAL_SECONDS,
            },
            "tenant_id": {
                "type": "string", "minLength": 3, "maxLength": 128,
            },
        },
        "additionalProperties": False,
    }
    resource_budget = {
        "worker_model": "single-interruptible-observer",
        "throttle_min": 1.0,
        "throttle_max": 8.0,
        "startup_cycle_timeout_seconds": 10.0,
        "event_delivery": "deduplicated-best-effort-with-durable-source",
    }
    restart_policy = "supervised-bounded-backoff"
    loss_behavior = "degrade-health-with-exact-retention-and-agent-loss-counts"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 8.0

    def __init__(self) -> None:
        super().__init__()
        self._fabric: FleetFabricStore | None = None
        self._tenant_id = ""
        self._last_finding = ""

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def bind_fabric(self, fabric: FleetFabricStore, tenant_id: str) -> None:
        if not isinstance(fabric, FleetFabricStore):
            raise TypeError("Fleet Health Monitor requires FleetFabricStore")
        if tenant_id not in fabric.tenant_ids:
            raise PermissionError("Fleet Health Monitor tenant is not authorized")
        self._fabric = fabric
        self._tenant_id = tenant_id

    def observe_once(self) -> tuple[int, str, dict[str, object]]:
        fabric = self._fabric
        if fabric is None or not self._tenant_id:
            return 35, "local Fleet Fabric store is not bound", {
                "evidence_rows": 0,
                "retention_drops": 0,
                "reported_drops": 0,
                "backpressure_devices": 0,
                "unhealthy_devices": 0,
                "enrolled_devices": 0,
                "fresh_devices": 0,
                "missing_devices": 0,
                "stale_devices": 0,
                "transport_enabled": False,
                "transport_available": False,
            }
        snapshot = fabric.health_snapshot(self._tenant_id)
        transport = fabric.transport_readiness
        details: dict[str, object] = {
            "tenant_id": self._tenant_id,
            "evidence_rows": snapshot.total_rows,
            "snapshot_truncated": snapshot.truncated,
            "retention_drops": snapshot.retention_drops,
            "reported_drops": snapshot.reported_drops,
            "backpressure_devices": snapshot.backpressure_devices,
            "unhealthy_devices": snapshot.unhealthy_devices,
            "enrolled_devices": snapshot.enrolled_devices,
            "reporting_devices": snapshot.reporting_devices,
            "fresh_devices": snapshot.fresh_devices,
            "missing_devices": snapshot.missing_devices,
            "missing_device_ids": snapshot.missing_device_ids,
            "stale_devices": snapshot.stale_devices,
            "stale_device_ids": snapshot.stale_device_ids,
            "freshness_seconds": snapshot.freshness_seconds,
            "health_sequence_gaps": snapshot.sequence_gaps,
            "stats_authenticated": snapshot.stats_authenticated,
            "custody_authenticated": True,
            "history_chain_status": snapshot.history_chain_status,
            "transport_enabled": transport.enabled,
            "transport_configuration_valid": transport.configuration_valid,
            "transport_available": transport.transport_available,
            "transport_reason": transport.reason,
        }
        if transport.enabled and not transport.configuration_valid:
            return 30, f"requested coordinator configuration failed closed: {transport.reason}", details
        if snapshot.missing_devices:
            return 40, (
                f"{snapshot.missing_devices} actively enrolled device(s) have no signed health "
                f"evidence within the {snapshot.freshness_seconds}s SLA: "
                f"{', '.join(snapshot.missing_device_ids[:10])}"
            ), details
        if snapshot.stale_devices:
            return 45, (
                f"{snapshot.stale_devices} actively enrolled device(s) have stale signed health "
                f"evidence beyond the {snapshot.freshness_seconds}s SLA: "
                f"{', '.join(snapshot.stale_device_ids[:10])}"
            ), details
        if snapshot.retention_drops:
            return 50, (
                f"local evidence retention discarded {snapshot.retention_drops} oldest row(s); "
                "fleet continuity is incomplete"
            ), details
        if snapshot.reported_drops:
            return 55, (
                f"fleet agents report {snapshot.reported_drops} cumulative lost health event(s)"
            ), details
        if snapshot.sequence_gaps:
            return 55, (
                f"device-signed health history reports {snapshot.sequence_gaps} sequence gap(s)"
            ), details
        if snapshot.truncated:
            return 60, (
                f"bounded health view contains only {len(snapshot.items)} of "
                f"{snapshot.total_rows} evidence row(s); inspect the local Fleet Center"
            ), details
        if snapshot.backpressure_devices:
            return 65, (
                f"{snapshot.backpressure_devices} device health queue(s) are at or above 80% capacity"
            ), details
        if snapshot.unhealthy_devices:
            return 75, (
                f"{snapshot.unhealthy_devices} device(s) report health below 100%; inspect exact row reasons"
            ), details
        if not snapshot.enrolled_devices:
            return 70, "no possession-proved devices are enrolled in Fleet Fabric", details
        return 100, "", details

    def _tick(self) -> None:
        try:
            health, reason, details = self.observe_once()
        except Exception as exc:
            health = 25
            exact = str(exc).strip()[:512] or "integrity verification failed"
            reason = (
                f"Fleet Fabric evidence could not be authenticated: "
                f"{type(exc).__name__}: {exact}"
            )
            details = {
                "evidence_rows": 0,
                "retention_drops": 0,
                "reported_drops": 0,
                "backpressure_devices": 0,
                "unhealthy_devices": 0,
                "enrolled_devices": 0,
                "fresh_devices": 0,
                "missing_devices": 0,
                "stale_devices": 0,
                "stats_authenticated": False,
                "custody_authenticated": False,
                "integrity_failure": exact,
                "transport_enabled": False,
                "transport_available": False,
            }
        self.set_health(health, reason)
        finding = f"{health}:{reason}:{details}"
        if finding == self._last_finding:
            return
        self._last_finding = finding
        severity = (
            Severity.INFO if health == 100
            else Severity.LOW if health >= 70
            else Severity.MEDIUM if health >= 50
            else Severity.HIGH
        )
        self.emit(
            "Fleet Fabric health evidence is complete"
            if health == 100 else f"Fleet Fabric health is degraded: {reason}",
            severity,
            schema="angerona.fleet-health-status.v1",
            health_percent=health,
            exact_reason=reason,
            response_authorized=False,
            response_authority="observe-only",
            remote_shell_available=False,
            arbitrary_command_available=False,
            **details,
        )

    def run(self) -> None:
        while not self.stopping:
            self._tick()
            self.sleep(POLL_INTERVAL_SECONDS)

    def self_test(self) -> tuple[bool, str]:
        digest_a = hashlib.sha256(b"fleet-health-self-test-desired").hexdigest()
        digest_b = hashlib.sha256(b"fleet-health-self-test-previous").hexdigest()
        try:
            FleetHealthSample(
                "tenant-self-test",
                "device-self-test",
                "sample-self-test",
                hashlib.sha256(b"fleet-health-self-test-device").hexdigest(),
                time.time(),
                digest_a,
                digest_b,
                99,
                "effective policy differs from desired policy",
                64,
                1,
                10,
                0,
                0,
                0,
            )
            try:
                FleetRolloutPlan(
                    "tenant-self-test",
                    "rollout-self-test",
                    "bundle-self-test",
                    "group-self-test",
                    digest_a,
                    digest_b,
                    ("device-self-test",),
                    ("device-self-test",),
                    90,
                    0,
                    time.time(),
                    {"command": "whoami"},
                )
            except ValueError as exc:
                if "forbidden" not in str(exc):
                    return False, f"unexpected command-shape rejection: {exc}"
            else:
                return False, "command-shaped rollout context was accepted"
        except Exception as exc:
            return False, f"typed Fleet Fabric evidence contract failed: {exc}"
        return True, (
            "typed signed-health shape, exact degraded reason, and no-command rollout boundary verified"
        )


def register() -> FleetHealthMonitorModule:
    return FleetHealthMonitorModule()


__all__ = ["FleetHealthMonitorModule", "register"]
