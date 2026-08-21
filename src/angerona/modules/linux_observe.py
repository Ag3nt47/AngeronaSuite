"""Rootless Linux Observe sensor module."""
from __future__ import annotations

import os
import sys

from angerona.core.eventbus import Severity
from angerona.core.module_base import BaseModule
from angerona.platforms.linux.observe import LinuxObserveCollector

SUPPORTED_PLATFORMS = ("linux",)


class LinuxObserveModule(BaseModule):
    name = "Linux Observe Sensor"
    description = (
        "Rootless, privacy-minimized process, established-flow, and kernel posture "
        "observation; optional eBPF adds privileged kernel telemetry separately."
    )
    category = "Endpoint"
    version = "1.0.0"
    supported_platforms = SUPPORTED_PLATFORMS
    capability_mode = "detect"
    platform_requirements = (
        "Linux with /proc",
        "psutil",
        "root is optional; required only by the separate eBPF sensor",
    )

    def __init__(self, collector: LinuxObserveCollector | None = None) -> None:
        super().__init__()
        self._collector = collector or LinuxObserveCollector()
        self._config = None
        try:
            raw = float(os.environ.get("ANGERONA_LINUX_OBSERVE_INTERVAL", "5"))
        except ValueError:
            raw = 5.0
        self._interval = max(2.0, min(60.0, raw))

    def bind_manager(self, manager) -> None:
        self._config = getattr(manager, "config", None)

    @staticmethod
    def classify(observation) -> tuple[Severity, str]:
        """Apply a small, explainable Linux fast path without shelling out."""
        if observation.kind == "security" and observation.action == "posture_change":
            security = observation.security
            if security.get("selinux_enforcing") is False:
                return Severity.HIGH, "SELinux enforcement changed to disabled"
            if security.get("apparmor_enabled") is False:
                return Severity.HIGH, "AppArmor changed to disabled"
            return Severity.MEDIUM, "kernel security posture changed"
        if observation.kind != "process":
            return Severity.INFO, "new local observation"
        process = observation.process
        executable = str(process.get("executable") or "")
        normalized = executable.removesuffix(" (deleted)").rstrip("/")
        uid = process.get("uid")
        if executable.endswith(" (deleted)"):
            return Severity.HIGH, "process is executing an unlinked executable"
        # These are detection signatures, never locations Angerona writes to.
        if normalized == "/dev/shm" or normalized.startswith("/dev/shm/"):  # nosec B108
            return (
                Severity.CRITICAL if uid == 0 else Severity.HIGH,
                "process started from shared memory",
            )
        if any(
            normalized == root or normalized.startswith(root + "/")
            for root in ("/tmp", "/var/tmp")  # nosec B108 - detection-only paths
        ):
            return (
                Severity.HIGH if uid == 0 else Severity.MEDIUM,
                "process started from a temporary directory",
            )
        return Severity.INFO, "new process start"

    def self_test(self) -> tuple[bool, str]:
        if not sys.platform.startswith("linux"):
            return False, "Linux Observe is available only on Linux"
        try:
            self._collector.poll()
        except Exception as exc:
            return False, f"observe snapshot failed: {exc}"
        return True, "rootless process/network/posture snapshot succeeded"

    def run(self) -> None:
        self.set_health(80, "Rootless Observe active; eBPF kernel coverage is optional.")
        self.emit(
            "Linux Observe online (process/network/posture snapshots, privacy-minimized).",
            Severity.INFO,
            capability_mode="observe",
            native_ebpf=bool(getattr(self._config, "ebpf_enabled", False)),
        )
        while not self.stopping:
            try:
                observations = self._collector.poll()
                degraded = self._collector.degraded_reasons
                if degraded:
                    self.set_health(55, "; ".join(degraded)[:800])
                else:
                    self.set_health(80, "Rootless Observe active; eBPF is optional.")
                for observation in observations:
                    if self._bus is None:
                        break
                    severity, reason = self.classify(observation)
                    self._bus.publish(observation.to_event(
                        self.name,
                        severity,
                        f"Linux {observation.kind} {observation.action}: {reason}",
                    ))
            except Exception as exc:
                self.set_health(35, f"Observe snapshot degraded: {exc}")
                self.emit(
                    f"Linux Observe snapshot degraded: {exc}",
                    Severity.MEDIUM,
                    capability_mode="observe",
                )
            self.sleep(self._interval)


def register() -> BaseModule:
    return LinuxObserveModule()
