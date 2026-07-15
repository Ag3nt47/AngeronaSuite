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
    last ``window`` seconds. Operator-acknowledged (ignored) alerts are excluded
    so cleaning up false alerts in the Resolve Center returns the level to Secure."""
    now = time.time()
    try:
        from angerona.core.alert_ack import acked_signatures, signature
        acked = acked_signatures()
    except Exception:
        acked, signature = set(), None
    try:
        from angerona.core.process_allowlist import is_event_allowed, policy_snapshot
        process_policy = policy_snapshot()
    except Exception:
        is_event_allowed = lambda _event, **_kwargs: False
        process_policy = ()
    try:
        from angerona.core.drill_resolution import is_resolved_event, resolution_snapshot
        resolutions = resolution_snapshot()
    except Exception:
        is_resolved_event = lambda _event, **_kwargs: False
        resolutions = {}
    threats = [
        e for e in events
        if (now - e.ts) <= window
        and e.severity >= Severity.HIGH
        and e.module not in _META_MODULES
        and not (signature and signature(e) in acked)
        and not is_event_allowed(e, policy=process_policy)
        and not is_resolved_event(e, resolutions=resolutions)
    ]
    if any(e.severity == Severity.CRITICAL for e in threats):
        return Severity.CRITICAL
    if threats:
        return Severity.HIGH
    return Severity.INFO


def threat_label(events, window: float = 600.0):
    """Convenience: returns (label, colour)."""
    return THREAT_LABEL[threat_level(events, window)]
