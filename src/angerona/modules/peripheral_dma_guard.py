"""Read-only peripheral, Kernel DMA, IOMMU, Thunderbolt, and USB4 guard."""
from __future__ import annotations

from typing import Callable

from angerona.core.module_base import BaseModule, Severity
from angerona.core.peripheral_posture import (
    POSTURE_SCHEMA,
    PeripheralPostureSnapshot,
    assess_peripheral_posture,
    observe_system_peripheral_posture,
)


POLL_INTERVAL = 300.0
SUPPORTED_PLATFORMS = ("windows", "macos", "linux")


class PeripheralDMAGuardModule(BaseModule):
    CODE = "PDMG"
    NAME = "Peripheral and DMA Posture Guard"
    name = NAME
    description = (
        "Observes Kernel DMA/IOMMU, Thunderbolt, USB4, removable-storage, and "
        "device-install control posture without changing device state."
    )
    category = "Hardware"
    version = "1.0.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    platform_requirements = (
        "Read access to OS device and DMA posture",
        "Independent hardware attestation for claims beyond the local kernel",
    )

    def __init__(
        self,
        *,
        observer: Callable[[], PeripheralPostureSnapshot] | None = None,
    ) -> None:
        super().__init__()
        self._observer = observer or observe_system_peripheral_posture
        self._last_state = ""

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def observe_once(self) -> tuple[PeripheralPostureSnapshot, object]:
        snapshot = self._observer()
        if not isinstance(snapshot, PeripheralPostureSnapshot):
            raise ValueError("peripheral posture observer contract violation")
        return snapshot, assess_peripheral_posture(snapshot)

    def _tick(self) -> None:
        try:
            snapshot, assessment = self.observe_once()
        except Exception as exc:
            self.set_health(10, "peripheral/DMA posture unavailable")
            state = f"observer-error:{type(exc).__name__}"
            if state != self._last_state:
                self._last_state = state
                self.emit(
                    "Peripheral and DMA posture could not be observed; controls remain unknown.",
                    Severity.CRITICAL,
                    schema=POSTURE_SCHEMA,
                    error_type=type(exc).__name__,
                    unknown_state=True,
                    raw_device_identifiers_omitted=True,
                    device_control_performed=False,
                    observation_only=True,
                    malicious_firmware_protection_claimed=False,
                    firmware_and_kernel_tampering_out_of_scope=True,
                    response_authorized=False,
                    response_authority="observe-only",
                )
            return
        self.set_health(assessment.health, assessment.state)
        state = (
            f"{assessment.state}:{','.join(assessment.risks)}:"
            f"{','.join(assessment.unknown)}"
        )
        if state == self._last_state:
            return
        self._last_state = state
        severity = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "info": Severity.INFO,
        }[assessment.severity]
        self.emit(
            "Peripheral/DMA risk detected."
            if assessment.risks
            else "Peripheral/DMA posture contains unknown coverage."
            if assessment.unknown
            else "Peripheral/DMA posture observed with no policy risk found.",
            severity,
            **assessment.event_details(snapshot),
        )

    def run(self) -> None:
        while not self.stopping:
            self._tick()
            self.sleep(POLL_INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        risky = PeripheralPostureSnapshot(
            POSTURE_SCHEMA,
            "windows",
            "disabled",
            "unknown",
            "present",
            "open",
            "present",
            "present",
            "allowed",
            "allowed",
            True,
            ("windows-deviceguard", "windows-pnp", "windows-removable-policy"),
            1_800_000_000.0,
        )
        unknown = PeripheralPostureSnapshot.unknown("macos", 1_800_000_000.0)
        try:
            risk_result = assess_peripheral_posture(risky)
            unknown_result = assess_peripheral_posture(unknown)
            details = risk_result.event_details(risky)
        except Exception as exc:
            return False, f"peripheral/DMA self-test failed: {type(exc).__name__}"
        if risk_result.severity != "critical" or not risk_result.risks:
            return False, "DMA/peripheral exposure did not produce a critical posture"
        if unknown_result.state != "peripheral-posture-unknown" or unknown_result.health >= 100:
            return False, "missing peripheral evidence was treated as healthy"
        if (
            details.get("device_control_performed") is not False
            or details.get("malicious_firmware_protection_claimed") is not False
            or details.get("response_authorized") is not False
        ):
            return False, "observe-only or firmware limitation boundary is missing"
        return True, (
            "Kernel DMA/IOMMU, Thunderbolt/USB4/removable control risks and honest "
            "UNKNOWN/firmware limitations verified without device changes"
        )


def register() -> PeripheralDMAGuardModule:
    return PeripheralDMAGuardModule()


__all__ = ["PeripheralDMAGuardModule", "register"]
