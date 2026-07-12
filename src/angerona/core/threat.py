"""Threat-level calculation (calibrated to avoid false positives).

The dashboard threat level must reflect *actual threats*, not operational
chatter. Degradation notices ("Ollama offline", "YARA not configured"),
routine connection logs, and self-test/console output are NOT threats. Only
genuine HIGH/CRITICAL detections from security modules — within a recent time
window — raise the level. With nothing active, the state is SECURE.
"""
from __future__ import annotations

import time

from angerona.core.eventbus import Severity

# Modules whose output is meta/operational, never a threat signal.
_META_MODULES = {"Self-Test", "Status", "Console"}

# label, colour for each computed level
THREAT_LABEL = {
    Severity.INFO: ("Secure", "#22c55e"),
    Severity.HIGH: ("High", "#f97316"),
    Severity.CRITICAL: ("Critical", "#ef4444"),
}


def threat_level(events, window: float = 600.0) -> Severity:
    """Return INFO (secure), HIGH, or CRITICAL based on real detections in the
    last ``window`` seconds."""
    now = time.time()
    threats = [
        e for e in events
        if (now - e.ts) <= window
        and e.severity >= Severity.HIGH
        and e.module not in _META_MODULES
    ]
    if any(e.severity == Severity.CRITICAL for e in threats):
        return Severity.CRITICAL
    if threats:
        return Severity.HIGH
    return Severity.INFO


def threat_label(events, window: float = 600.0):
    """Convenience: returns (label, colour)."""
    return THREAT_LABEL[threat_level(events, window)]
