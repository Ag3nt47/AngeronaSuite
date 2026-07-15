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

# Modules whose output is meta/operational, never an intrusion signal. These
# report the SUITE's OWN state — a module crashed, a watchdog restarted, a
# self-improvement pass needs work, a synthetic probe didn't echo. That is
# important health information, but it belongs to a resilience/health indicator,
# NOT the external-threat level. Counting it as CRITICAL is what makes the
# dashboard read "Critical" when nothing malicious is actually happening.
_META_MODULES = {
    "Self-Test", "Status", "Console",
    "Watchdog Monitor", "Resilience Supervisor", "Resilience Manager",
    "Evolution Engine", "CHAOS",
    # SOAR is a RESPONSE tier: its "UNDER ATTACK" is a summary of detections the
    # primary modules already emitted. Scoring it too double-counts and lets a
    # burst of upstream noise cascade the level to Critical. The underlying
    # detections still score on their own.
    "SOAR Automation", "Active Response SOAR",
}

# Message fingerprints of module-lifecycle / self-health events. These can be
# emitted under a real detector's own module name (e.g. a sensor announcing it
# has crashed), so they must be filtered by message, not just by module — that
# way a genuine detection from the same module still counts.
_HEALTH_MARKERS = (
    "quarantined after", "keeps crashing", "left down after", "sensor blind",
    "entered safe_mode", "pipeline regression", "could not catch",
    "manual signature work", "restarts; manual attention",
)


def _is_health_noise(event) -> bool:
    msg = (getattr(event, "message", "") or "").lower()
    return any(mk in msg for mk in _HEALTH_MARKERS)


def _is_self_or_drill(event) -> bool:
    """True for Angerona's own synthetic/drill activity (CHAOS probes, shark/
    red-team drills, self-IOC decoy traffic) so it never scores as a threat."""
    d = getattr(event, "details", None) or {}
    if d.get("drill") or d.get("synthetic") or d.get("self_probe"):
        return True
    try:
        from angerona.core.self_ioc import is_self_ioc
    except Exception:
        return False
    for key in ("qname", "domain", "host", "origin_message"):
        v = d.get(key)
        if isinstance(v, str) and is_self_ioc(v):
            return True
    return False

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
        and not _is_health_noise(e)
        and not _is_self_or_drill(e)
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
