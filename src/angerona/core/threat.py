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
    # Analysis, reporting, and self-repair layers describe evidence or the
    # suite's own state. Their HIGH result must not manufacture a second live
    # incident when the originating detector was practice/exposure/health.
    "AI Triage (Ollama)", "Speculative Triage Pre-Warm",
    "Scheduled AI Security Briefing", "Cloud CTI Escalation", "HEAL",
    # SOAR is a RESPONSE tier: its "UNDER ATTACK" is a summary of detections the
    # primary modules already emitted. Scoring it too double-counts and lets a
    # burst of upstream noise cascade the level to Critical. The underlying
    # detections still score on their own.
    "SOAR Automation", "Active Response SOAR", "Adversary Combat",
}

# Message fingerprints of module-lifecycle / self-health events. These can be
# emitted under a real detector's own module name (e.g. a sensor announcing it
# has crashed), so they must be filtered by message, not just by module — that
# way a genuine detection from the same module still counts.
_HEALTH_MARKERS = (
    "quarantined after", "keeps crashing", "left down after", "sensor blind",
    "entered safe_mode", "pipeline regression", "could not catch",
    "manual signature work", "restarts; manual attention",
    "module crashed (attempt", "module failed to start", "module unavailable",
)

_PRACTICE_MODULES = {
    "chaos",
    "red team",
    "red team simulation",
    "shark attack",
    "red team practice lab",
    "telemetry canary drills",
}
_EXPOSURE_MODULES = {
    "upstream threat intel sync",
    "vulnerability assessment",
    "vulnerability scanner",
    "cisa kev",
}
_EXPOSURE_KINDS = {
    "exposure",
    "passive_vulnerability",
    "vulnerability_assessment",
}
_EXPOSURE_EVENT_TYPES = {
    # Removable-media insertion and policy/approval state are local exposure
    # signals, not proof that hostile code is executing.  If a USB detector
    # later supplies explicit ``active_attack=True`` evidence, the active check
    # below deliberately wins before this classification is consulted.
    "usb_approval_required",
    "usb_approval_decision",
    "usb_approval_rejected",
    "usb_autorun_policy",
    "usb_media_removed",
    "usb_media_risk",
    "usb_pin_lockout",
}


def _is_health_noise(event) -> bool:
    msg = (getattr(event, "message", "") or "").lower()
    return any(mk in msg for mk in _HEALTH_MARKERS)


def _is_self_or_drill(event) -> bool:
    """True for Angerona's own synthetic/drill activity (CHAOS probes, shark/
    red-team drills, self-IOC decoy traffic) so it never scores as a threat."""
    d = getattr(event, "details", None) or {}
    if not isinstance(d, dict):
        d = {}
    # Practice is an authorization decision, not a string heuristic.  Only an
    # exact, live entry registered by Angerona's in-process drill may downgrade
    # detector evidence.  A malicious file named ``_redteam_*`` (or an event
    # claiming ``simulated=True``) remains an active alert.
    try:
        from angerona.core.practice_scope import is_practice_event
        if is_practice_event(event):
            return True
    except Exception:
        # Fail closed: registry failure must never suppress a detection.
        pass
    module = str(getattr(event, "module", "") or "").strip().casefold()
    if module in _PRACTICE_MODULES:
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


def event_disposition(event) -> str:
    """Classify an event without rewriting its evidentiary severity.

    ``severity`` records how important the observation is inside its own
    domain.  ``disposition`` answers the separate dashboard question: is this
    an active hostile incident, a practice result, a passive exposure, or suite
    health?  Keeping those concepts separate prevents a critical drill result
    or an applicable CVE from falsely claiming that the host is under attack.
    """
    if _is_self_or_drill(event):
        return "practice"
    if (
        getattr(event, "module", "") in _META_MODULES
        or _is_health_noise(event)
    ):
        return "health"
    details = getattr(event, "details", None)
    details = details if isinstance(details, dict) else {}
    if details.get("active_exploitation") is True or details.get("active_attack") is True:
        return "active"
    module = str(getattr(event, "module", "") or "").strip().casefold()
    finding_kind = str(details.get("finding_kind") or "").strip().casefold()
    disposition = str(details.get("disposition") or "").strip().casefold()
    source = str(details.get("source") or "").strip().casefold()
    event_type = str(details.get("event_type") or "").strip().casefold()
    # Posture Hardening emits practice-gap metadata only after authenticating a
    # signed Shark/Red-Team report.  Its AAR integrity errors intentionally do
    # not carry these fields, so "verification failed" stays an active alert.
    if (
        module == "posture hardening"
        and finding_kind == "practice_gap"
        and source in {"redteam", "shark"}
    ):
        return "practice"
    # Hardening gaps and Defender protection-state/action notifications are
    # important posture/response evidence, but do not prove that hostile code
    # is currently executing. A producer can still override this safely with
    # the explicit active_attack/active_exploitation flags handled above.
    if details.get("hardening") is True:
        return "exposure"
    if module == "av telemetry bridge":
        try:
            defender_eid = int(details.get("eid", 0))
        except (TypeError, ValueError):
            defender_eid = 0
        if defender_eid in {1117, 5001}:
            return "health"
    if (
        module in _EXPOSURE_MODULES
        or disposition in _EXPOSURE_KINDS
        or finding_kind in _EXPOSURE_KINDS
        or event_type in _EXPOSURE_EVENT_TYPES
        or source in {"cisa_kev", "cisa-kev", "vulnerability_assessment"}
    ):
        return "exposure"
    if getattr(event, "severity", Severity.INFO) >= Severity.HIGH:
        return "active"
    return "informational"


def is_active_threat(event) -> bool:
    """Return True only for HIGH/CRITICAL live-hostile evidence."""
    return (
        getattr(event, "severity", Severity.INFO) >= Severity.HIGH
        and event_disposition(event) == "active"
    )


def active_threat_events(events, window: float = 600.0) -> list:
    """Return unresolved, non-allowlisted active threats in the time window."""
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
    return [
        event for event in events
        if 0.0 <= now - getattr(event, "ts", 0.0) <= window
        and is_active_threat(event)
        and not (signature and signature(event) in acked)
        and not is_event_allowed(event, policy=process_policy)
        and not is_resolved_event(event, resolutions=resolutions)
    ]

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
    threats = active_threat_events(events, window)
    if any(e.severity == Severity.CRITICAL for e in threats):
        return Severity.CRITICAL
    if threats:
        return Severity.HIGH
    return Severity.INFO


def threat_label(events, window: float = 600.0):
    """Convenience: returns (label, colour)."""
    return THREAT_LABEL[threat_level(events, window)]
