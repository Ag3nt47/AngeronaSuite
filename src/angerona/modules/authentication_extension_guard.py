"""Observe-only Windows Authentication Extension Integrity Guard.

The capability inventories fixed Windows authentication extension surfaces and
compares path-minimized evidence with an authenticated local baseline.  It has
no response authority and never loads, invokes, disables, or rewrites a
registered component.
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import threading

from angerona.core.eventbus import Severity
from angerona.core.module_base import BaseModule
from angerona.core.windows_auth_extensions import (
    AUTH_EXTENSION_SCHEMA,
    SURFACE_IDS,
    AuthExtensionBaselineStore,
    AuthExtensionBinding,
    AuthExtensionCollection,
    AuthExtensionEvidenceProvider,
    AuthExtensionSnapshot,
    AuthExtensionSurface,
    BaselineIntegrityError,
    BaselineComparison,
    ComponentEvidence,
    SurfaceCoverage,
    UnavailableAuthExtensionEvidenceProvider,
    WindowsAuthExtensionEvidenceProvider,
    assess_auth_extension_snapshot,
    compare_auth_extension_snapshots,
    load_auth_extension_keys,
)


class AuthenticationExtensionIntegrityGuardModule(BaseModule):
    """Windows-only observer for LSA, credential, and network-provider bindings."""

    CODE = "AEIG"
    NAME = "Authentication Extension Integrity Guard"
    name = NAME
    description = (
        "Read-only fixed-catalog integrity observation for LSA authentication, notification, "
        "and security packages; credential providers and filters; and network providers."
    )
    category = "Identity"
    version = "1.13.0"
    supported_platforms = frozenset({"windows"})
    capability_mode = "observe"
    maturity_channel = "preview"
    platform_requirements = (
        "Windows registry read access to fixed authentication-extension keys",
        "Local component metadata read access when a binding resolves safely",
        "Angerona bus.key for path minimization and authenticated baseline state",
    )
    capability_inputs = (
        "windows-authentication-extension-registry-binding",
        "local-component-file-integrity-metadata",
    )
    capability_outputs = (
        "authentication-extension-coverage",
        "authentication-extension-drift",
        "authenticated-local-baseline-status",
    )
    capability_permissions = (
        "windows-fixed-registry-read",
        "registered-local-component-read",
        "local-baseline-state-write",
    )
    high_risk_permissions = ()
    data_classes = (
        "purpose-keyed-registry-binding",
        "purpose-keyed-local-path",
        "component-integrity-digest",
        "local-owner-and-acl-token",
    )
    egress = "none"
    retention = (
        "bounded-in-memory-raw-path-details-and-hmac-authenticated-path-minimized-local-baseline"
    )
    response_authority = "none"
    capability_dependencies = ()
    capability_conflicts = ()
    restart_policy = "bounded-three-attempt-backoff-quarantine"
    loss_behavior = "unknown-or-partial-coverage-never-means-clean-and-never-enrolls"
    settings_schema = {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }
    resource_budget = {
        "worker_model": "single-lifecycle-thread-fixed-fifteen-minute-cadence",
        "event_delivery": "bounded-tokenized-snapshot-diff",
        "startup_cycle_timeout_seconds": 45.0,
        "throttle_min": 1.0,
        "throttle_max": 8.0,
    }
    INTERVAL_SECONDS = 15 * 60

    def __init__(
        self,
        *,
        provider: AuthExtensionEvidenceProvider | None = None,
        baseline_store: AuthExtensionBaselineStore | None = None,
        data_root: Path | str | None = None,
        master_key: bytes | None = None,
    ) -> None:
        super().__init__()
        if master_key is not None and (
            not isinstance(master_key, bytes) or len(master_key) != 32
        ):
            raise ValueError("authentication-extension key override must contain 32 bytes")
        self._provider: AuthExtensionEvidenceProvider | None = provider
        self._baseline: AuthExtensionBaselineStore | None = baseline_store
        self._data_root_override = Path(data_root) if data_root is not None else None
        self._data_root = self._data_root_override
        self._master_key = master_key
        self._state_lock = threading.RLock()
        self._last_collection: AuthExtensionCollection | None = None
        self._last_baseline: BaselineComparison | None = None
        self._last_event_marker = ""

    def bind_manager(self, manager) -> None:
        if self._data_root_override is None:
            config = getattr(manager, "config", None)
            configured = getattr(config, "data_dir", None)
            if configured is not None:
                self._data_root = Path(configured)

    def _root(self) -> Path:
        if self._data_root is not None:
            return self._data_root
        from angerona.core.data_paths import data_dir

        self._data_root = data_dir()
        return self._data_root

    def _ensure_backends(self) -> tuple[AuthExtensionEvidenceProvider, AuthExtensionBaselineStore]:
        if self._provider is None:
            keys = load_auth_extension_keys(self._root(), master_key=self._master_key)
            if keys is None:
                self._provider = UnavailableAuthExtensionEvidenceProvider(
                    "Stable purpose-separated HMAC authority is unavailable; raw registry paths "
                    "will not be collected or retained."
                )
            else:
                self._provider = WindowsAuthExtensionEvidenceProvider(keys.privacy_key)
        if self._baseline is None:
            self._baseline = AuthExtensionBaselineStore(
                self._root() / "baselines" / "windows_auth_extensions.json",
                data_root=self._root(),
                master_key=self._master_key,
            )
        return self._provider, self._baseline

    @staticmethod
    def _event_details(**extra: object) -> dict[str, object]:
        details: dict[str, object] = {
            "read_only": True,
            "response_authorized": False,
            "response_authority": "observe-only",
            "attribution": "not-assessed",
            "capability_mode": "observe",
            "egress": "none",
            "raw_paths_omitted": True,
            "credentials_collected": False,
            "lsass_memory_accessed": False,
        }
        details.update(extra)
        return details

    def local_component_details(self) -> tuple[dict[str, str], ...]:
        """Return bounded raw paths to an explicitly local in-process details view."""
        with self._state_lock:
            collection = self._last_collection
            if collection is None:
                return ()
            return tuple(
                {
                    "component_token": detail.component_token,
                    "path": detail.path,
                    "detail": detail.detail,
                }
                for detail in collection.local_details
            )

    def evidence_snapshot(self) -> dict[str, object]:
        """Return path-safe evidence and baseline status for diagnostics/UI."""
        with self._state_lock:
            collection = self._last_collection
            comparison = self._last_baseline
            return {
                "available": collection is not None,
                "snapshot": asdict(collection.snapshot) if collection is not None else None,
                "baseline": asdict(comparison) if comparison is not None else None,
                "local_detail_count": len(collection.local_details) if collection is not None else 0,
                "read_only": True,
                "response_authorized": False,
                "response_authority": "observe-only",
                "attribution": "not-assessed",
            }

    def establish_trusted_baseline(
        self,
        *,
        operator: str,
        reason: str,
        approved: bool,
    ) -> dict[str, object]:
        """Explicitly enroll the currently displayed complete observation."""
        with self._state_lock:
            collection = self._last_collection
        if collection is None:
            raise RuntimeError("collect and review authentication-extension evidence first")
        _provider, baseline = self._ensure_backends()
        baseline.establish_trusted(
            collection.snapshot,
            operator=operator,
            reason=reason,
            approved=approved,
        )
        comparison = baseline.observe(collection.snapshot, initialize_provisional=False)
        with self._state_lock:
            self._last_baseline = comparison
        return {
            "baseline_status": comparison.status,
            "baseline_trusted": comparison.baseline_trusted,
            "baseline_fresh": comparison.fresh,
            "local_only": comparison.local_only,
            "response_authorized": False,
            "response_authority": "observe-only",
        }

    def _emit_state(
        self,
        collection: AuthExtensionCollection,
        comparison: BaselineComparison,
    ) -> None:
        snapshot = collection.snapshot
        coverage = {
            surface.coverage.surface: surface.coverage.status for surface in snapshot.surfaces
        }
        change_rows = tuple(asdict(change) for change in comparison.changes)
        marker = repr(
            (
                snapshot.collector_status,
                tuple(sorted(coverage.items())),
                comparison.status,
                comparison.baseline_trusted,
                comparison.fresh,
                change_rows,
            )
        )
        if marker == self._last_event_marker:
            return
        self._last_event_marker = marker
        if comparison.status == "tampered":
            severity = Severity.CRITICAL
            message = "Authentication-extension baseline failed local authentication."
            finding_code = "auth_extension.baseline.authentication_failed"
        elif comparison.status in {"drift", "host-mismatch"}:
            severity = Severity.HIGH
            message = "Authentication-extension binding or component drift was observed."
            finding_code = f"auth_extension.baseline.{comparison.status}"
        elif snapshot.collector_status != "complete" or comparison.status in {"unknown", "stale"}:
            severity = Severity.MEDIUM
            message = (
                "Authentication-extension evidence is incomplete or stale; no clean conclusion "
                "is available."
            )
            finding_code = f"auth_extension.coverage.{comparison.status}"
        else:
            severity = Severity.INFO
            message = "Authentication-extension local evidence state was updated."
            finding_code = f"auth_extension.baseline.{comparison.status}"
        self.emit(
            message,
            severity,
            **self._event_details(
                finding_code=finding_code,
                collector_status=snapshot.collector_status,
                surface_coverage=coverage,
                baseline_status=comparison.status,
                baseline_trusted=comparison.baseline_trusted,
                baseline_fresh=comparison.fresh,
                baseline_local_only=comparison.local_only,
                baseline_age_seconds=comparison.age_seconds,
                changes=change_rows,
                change_count=len(change_rows),
                local_detail_count=len(collection.local_details),
            ),
        )

    def observe_once(self) -> dict[str, object]:
        provider, baseline = self._ensure_backends()
        try:
            collection = provider.collect()
        except Exception as exc:
            self.set_health(
                15,
                "Authentication-extension collection failed closed; no host state was "
                "classified as clean.",
            )
            self.emit(
                "Authentication-extension collection failed closed.",
                Severity.HIGH,
                **self._event_details(
                    finding_code="auth_extension.collection.failed",
                    failure_type=type(exc).__name__,
                ),
            )
            return {
                "collector_status": "unknown",
                "baseline_status": "unknown",
                "health": self.health,
            }
        assessment = assess_auth_extension_snapshot(collection.snapshot)
        try:
            comparison = baseline.observe(collection.snapshot)
        except BaselineIntegrityError:
            comparison = BaselineComparison(
                "tampered",
                False,
                False,
                True,
                "Authentication-extension baseline failed bounded integrity validation.",
                0,
            )
        except (MemoryError, OSError, OverflowError, RecursionError, TypeError, ValueError):
            comparison = BaselineComparison(
                "unknown",
                False,
                False,
                True,
                "Authentication-extension baseline could not be evaluated safely.",
                0,
            )
        if comparison.status == "tampered":
            health = 15
            reason = "Authentication-extension baseline failed HMAC or schema authentication."
        elif comparison.status == "host-mismatch":
            health = 20
            reason = "Authentication-extension evidence is bound to a different host token."
        elif comparison.status == "drift":
            health = min(40, assessment.health)
            reason = "Authentication-extension drift is present and was not promoted into baseline."
        elif comparison.status == "stale":
            health = min(45, assessment.health)
            reason = (
                "Authentication-extension baseline exceeded its local freshness cap; no "
                "independent high-water exists."
            )
        elif comparison.status == "unknown":
            health = min(assessment.health, 35)
            reason = assessment.reason
        elif comparison.status == "provisional":
            health = min(assessment.health, 65)
            reason = (
                "Authentication-extension observation is provisional; an approved operator "
                "has not enrolled the complete host-bound snapshot."
            )
        else:
            health = assessment.health
            reason = assessment.reason
        self.set_health(health, reason)
        with self._state_lock:
            self._last_collection = collection
            self._last_baseline = comparison
        self._emit_state(collection, comparison)
        return {
            "collector_status": collection.snapshot.collector_status,
            "surface_coverage": {
                surface.coverage.surface: surface.coverage.status
                for surface in collection.snapshot.surfaces
            },
            "component_count": len(collection.snapshot.components),
            "local_detail_count": len(collection.local_details),
            "baseline_status": comparison.status,
            "baseline_trusted": comparison.baseline_trusted,
            "baseline_fresh": comparison.fresh,
            "health": health,
            "read_only": True,
            "response_authorized": False,
            "response_authority": "observe-only",
            "attribution": "not-assessed",
        }

    @staticmethod
    def _selftest_snapshot(sha256: str) -> AuthExtensionSnapshot:
        component = ComponentEvidence(
            "component:v1:" + "1" * 32,
            "path:v1:" + "2" * 32,
            "resolved",
            "",
            sha256,
            4096,
            "file:v1:" + "3" * 32,
            "verified",
            "not-found",
            "4" * 64,
            "1.0.0.0",
            "owner:v1:" + "5" * 32,
            "acl:v1:" + "6" * 32,
            "complete",
        )
        surfaces: list[AuthExtensionSurface] = []
        for index, surface_id in enumerate(SURFACE_IDS):
            bindings: tuple[AuthExtensionBinding, ...] = ()
            if index == 0:
                bindings = (
                    AuthExtensionBinding(
                        surface_id,
                        0,
                        "binding:v1:" + "7" * 32,
                        "lsa",
                        "64",
                        "REG_MULTI_SZ",
                        component.component_token,
                        "owner:v1:" + "9" * 32,
                        "acl:v1:" + "a" * 32,
                        "observed",
                    ),
                )
            surfaces.append(
                AuthExtensionSurface(
                    SurfaceCoverage(surface_id, "complete", "", len(bindings), len(bindings)),
                    bindings,
                )
            )
        return AuthExtensionSnapshot(
            AUTH_EXTENSION_SCHEMA,
            "host:v1:" + "8" * 32,
            1000.0,
            tuple(surfaces),
            (component,),
            "complete",
            "",
            1,
        )

    def self_test(self) -> tuple[bool, str]:
        try:
            before = self._selftest_snapshot("a" * 64)
            after = self._selftest_snapshot("b" * 64)
            comparison = compare_auth_extension_snapshots(before, after)
            assessment = assess_auth_extension_snapshot(before)
            if comparison.status != "drift" or not comparison.changes:
                return False, "pure component drift comparison did not detect change"
            if assessment.health != 75 or assessment.baseline_eligible is not True:
                return False, "local-only health cap or baseline eligibility failed"
            rendered = repr((before, comparison))
            if "C:\\" in rendered or "/Users/" in rendered:
                return False, "path-minimized evidence unexpectedly exposed a local path"
            details = self._event_details()
            if details != {
                "read_only": True,
                "response_authorized": False,
                "response_authority": "observe-only",
                "attribution": "not-assessed",
                "capability_mode": "observe",
                "egress": "none",
                "raw_paths_omitted": True,
                "credentials_collected": False,
                "lsass_memory_accessed": False,
            }:
                return False, "observe-only event contract failed"
        except Exception as exc:
            return False, f"authentication-extension bounded self-test failed: {exc}"
        return True, "bounded path-minimized drift and observe-only event contract verified"

    def run(self) -> None:
        self.set_health(20, "Authentication-extension fixed-surface observer is starting.")
        self.emit(
            "Authentication Extension Integrity Guard online in read-only mode.",
            Severity.INFO,
            **self._event_details(
                finding_code="auth_extension.guard.online",
                cadence_seconds=self.INTERVAL_SECONDS,
            ),
        )
        while not self.stopping:
            self.observe_once()
            self.sleep(self.INTERVAL_SECONDS)


def register() -> AuthenticationExtensionIntegrityGuardModule:
    return AuthenticationExtensionIntegrityGuardModule()


__all__ = ["AuthenticationExtensionIntegrityGuardModule", "register"]
