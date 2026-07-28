"""macOS Observe sensor module.

This is intentionally detect/observe-only.  It does not claim Endpoint Security
or Network Extension enforcement until an entitled, signed native component is
installed and reporting healthy status through the authenticated bridge.
"""
from __future__ import annotations

import os
import sys

from angerona.core.eventbus import Severity
from angerona.core.module_base import BaseModule
from angerona.platforms.macos.observe import MacOSObserveCollector

SUPPORTED_PLATFORMS = ("macos",)


class MacOSObserveModule(BaseModule):
    name = "macOS Observe Sensor"
    description = (
        "Privacy-minimized process and network observation for the macOS sensor "
        "preview; native Endpoint Security enforcement is reported separately."
    )
    category = "Endpoint"
    version = "0.1.0"
    supported_platforms = SUPPORTED_PLATFORMS
    capability_mode = "observe"
    platform_requirements = (
        "macOS 13 or later recommended",
        "signed native host required for Endpoint Security coverage",
    )

    def __init__(self, collector: MacOSObserveCollector | None = None) -> None:
        super().__init__()
        self._collector = collector or MacOSObserveCollector()
        try:
            raw = float(os.environ.get("ANGERONA_MACOS_OBSERVE_INTERVAL", "5"))
        except ValueError:
            raw = 5.0
        self._interval = max(2.0, min(60.0, raw))

    def self_test(self) -> tuple[bool, str]:
        if sys.platform != "darwin":
            return False, "macOS Observe is available only on macOS"
        try:
            self._collector.poll()
        except Exception as exc:
            return False, f"observe snapshot failed: {exc}"
        return True, (
            "observe snapshot succeeded; native Endpoint Security enforcement "
            "is not part of this preview"
        )

    def run(self) -> None:
        self.set_health(
            75,
            "Observe-only preview; native Endpoint Security coverage not installed.",
        )
        self.emit(
            "macOS Observe online (process/network snapshots, privacy-minimized). "
            "Native enforcement is not active.",
            Severity.INFO,
            capability_mode="observe",
            native_enforcement=False,
        )
        while not self.stopping:
            try:
                observations = self._collector.poll()
                degraded = getattr(self._collector, "degraded_reasons", ())
                if degraded:
                    self.set_health(40, "; ".join(degraded)[:800])
                else:
                    self.set_health(
                        75,
                        "Observe-only preview; native Endpoint Security "
                        "coverage not installed.",
                    )
                for observation in observations:
                    if self._bus is None:
                        break
                    message = (
                        f"macOS {observation.kind} {observation.action} observed"
                    )
                    self._bus.publish(
                        observation.to_event(self.name, Severity.INFO, message)
                    )
            except Exception as exc:
                self.set_health(35, f"Observe snapshot degraded: {exc}")
                self.emit(
                    f"macOS Observe snapshot degraded: {exc}",
                    Severity.MEDIUM,
                    capability_mode="observe",
                )
            self.sleep(self._interval)
