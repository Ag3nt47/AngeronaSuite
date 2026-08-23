"""Adaptive low-impact monitoring policy for all-day unattended operation.

Chill Mode keeps event-driven and network-facing protection alive, pauses only
deep periodic scanners, and slows the remaining disk pollers.  A live hostile
HIGH/CRITICAL event temporarily wakes the deep scanners.  After a sustained
quiet period they can be returned to the low-impact profile.

This module is GUI-neutral: it owns policy/state only.  MainWindow performs the
actual sequential module lifecycle transitions on the Qt thread.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable


# Deep periodic work that is safe to defer while cheap live sensors, Windows
# telemetry, deception, response, and network behavior monitoring stay online.
CHILL_PAUSED_MODULES: tuple[str, ...] = (
    # Recursive/high-volume storage scanners. Lightweight Defender, AMSI,
    # Sysmon/ETW and removable-media event bridges remain live.
    "Shadow Shield",
    "File Integrity Monitor",
    "Memory Time-Machine",
    "Memory Injection Scanner",
    "YARA Scanner",
    "AI Model Integrity Guard",
    "Packet Sniffer",
    "API Patch / Anti-Blinding Detector",
    "Persistence Sweep",
    "Data Provenance Graph",
    "Hardware-Rooted Integrity",
    "Kernel-Boundary Posture Ledger",
    "Compliance Mapper",
    # Synthetic/AI background work is demand-driven in Chill. ARIA remains
    # available and loads the configured model only when the user asks it.
    "Telemetry Canary Drills",
    "CHAOS",
    "AI Triage (Ollama)",
    "Speculative Triage Pre-Warm",
    "Scheduled AI Security Briefing",
    "Smart Deception",
)


# Floors survive Adaptive Resource Governor updates. Network Monitor, Beacon
# Detector, WFP, Sysmon/ETW, AV telemetry, SOAR, deception, and watchdog paths
# intentionally do not appear: they retain their normal live cadence.
CHILL_THROTTLE_FLOORS: dict[str, float] = {
    # Quiet-mode support/maintenance work.  These modules do not establish
    # real-time hostile evidence: explicit drills and live hostile events leave
    # Chill before they need full cadence, while their idle bookkeeping can run
    # much less often during an unattended all-day session.
    "Posture Hardening": 8.0,
    "HEAL": 6.0,
    "In-Memory Flight Cache": 8.0,
    "Evidence Lattice Fusion": 8.0,
    "Storage Hygiene Enforcer": 8.0,
    # Local detection fallbacks remain available, but expensive periodic host
    # scans are slower while the event-driven ETW/Sysmon/AMSI/network path is
    # online.  Floors are removed immediately when Chill is escalated.
    "Ransomware Heuristics": 4.0,
    "Process Monitor": 2.0,
    "WLAN Monitor": 2.0,
    "ARP Watchdog": 2.0,
    "Network Protocol Deep Decoder": 2.0,
    "Self-Integrity Monitor": 4.0,
}


@dataclass(frozen=True)
class ChillTransition:
    action: str
    reason: str
    active_count: int = 0


class ChillPolicy:
    """Thread-safe escalation/cooldown state machine."""

    def __init__(
        self,
        *,
        quiet_seconds: float = 10.0 * 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        quiet = float(quiet_seconds)
        if not 1.0 <= quiet <= 24.0 * 60.0 * 60.0:
            raise ValueError("quiet_seconds must be between 1 second and 24 hours")
        self.quiet_seconds = quiet
        self._clock = clock
        self._lock = threading.Lock()
        self.enabled = False
        self.escalated = False
        self.awake_until = 0.0

    def enable(self) -> None:
        with self._lock:
            self.enabled = True
            self.escalated = False
            self.awake_until = 0.0

    def disable(self) -> None:
        with self._lock:
            self.enabled = False
            self.escalated = False
            self.awake_until = 0.0

    def observe_active(self, events: Iterable[object]) -> ChillTransition | None:
        """Extend the awake window for already-classified active threats."""
        active = tuple(events)
        if not active:
            return None
        with self._lock:
            if not self.enabled:
                return None
            self.awake_until = max(
                self.awake_until,
                self._clock() + self.quiet_seconds,
            )
            if self.escalated:
                return ChillTransition(
                    "extend",
                    "additional live hostile evidence extended the awake window",
                    len(active),
                )
            self.escalated = True
            return ChillTransition(
                "escalate",
                "live hostile evidence requires deep verification",
                len(active),
            )

    def force_escalate(self, reason: str) -> ChillTransition | None:
        """Wake coverage for an explicit operator action such as a drill.

        This does not classify the drill as hostile; it only makes sure the
        sensors being tested are actually online for the duration.
        """
        with self._lock:
            if not self.enabled:
                return None
            self.awake_until = max(
                self.awake_until,
                self._clock() + self.quiet_seconds,
            )
            if self.escalated:
                return ChillTransition("extend", reason)
            self.escalated = True
            return ChillTransition("escalate", reason)

    def tick(self) -> ChillTransition | None:
        with self._lock:
            if not self.enabled or not self.escalated:
                return None
            if self._clock() < self.awake_until:
                return None
            self.escalated = False
            self.awake_until = 0.0
            return ChillTransition(
                "cooldown",
                "quiet window completed with no new active threat",
            )

    def remaining_seconds(self) -> float:
        with self._lock:
            if not self.enabled or not self.escalated:
                return 0.0
            return max(0.0, self.awake_until - self._clock())
