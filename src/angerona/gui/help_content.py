"""Canonical, GUI-independent Help and capability content.

The capability portion is rendered from :mod:`angerona.core.capability_guide`.
Only genuinely supplementary operator topics live here, preventing Help,
Settings, the console and ARIA from drifting into different product claims.
"""
from __future__ import annotations

from angerona.core.capability_guide import (
    GUIDES,
    CapabilityGuide,
    DestinationActionability,
    DestinationAvailability,
    DestinationKind,
    search_guides,
)


def _getting_started_body() -> str:
    categories = ", ".join(sorted({guide.category for guide in GUIDES}))
    return (
        "Angerona is a local-first defensive security suite. It watches the host, "
        "explains evidence, and keeps cloud or messaging features off until the "
        "operator explicitly configures them.\n"
        "• The dashboard shows module health, alerts, posture, and current threat level.\n"
        "• The ARIA console accepts commands or plain-language questions.\n"
        "• Run Self-Test to verify local pipelines; use only inert Red Team drills for "
        "built-in validation.\n"
        f"• Help contains {len(GUIDES)} evidence-backed capabilities across: {categories}.\n"
        "• Type 'guide <capability or task>' or ask ARIA for a guided explanation."
    )


_SUPPLEMENTARY_TOPICS: dict[str, tuple[str, str]] = {
    "getting-started": ("Getting started", _getting_started_body()),
    "actions": (
        "ARIA actions (safe, confirm-first)",
        "ARIA can explain and stage defensive actions, but a model response is never "
        "host authority.\n"
        "• Reads such as module status, recent alerts, posture, and diagnostics may run "
        "without changing the host.\n"
        "• Changes are staged behind a short-lived confirmation token. Review the exact "
        "target and effect, then confirm or cancel.\n"
        "• High-impact enterprise actions also pass through typed authorization and "
        "approval controls. There is no generic remote shell.\n"
        "• Treat every recommendation as advice until the resulting evidence and receipt "
        "have been verified.",
    ),
    "troubleshooting": (
        "Troubleshooting",
        "• Threat level remains elevated: open Resolve Center and review each detection; "
        "allow only an exact, verified false positive.\n"
        "• A module is stopped or quarantined: inspect its detail and recovery evidence "
        "before restarting it.\n"
        "• ARIA is unavailable: verify the configured local model service and model. "
        "Optional provider credentials belong only in Settings > API Keys.\n"
        "• After sleep or resume: allow sensor freshness to recover, then run Self-Test.\n"
        "• For a crash or freeze: use Advanced Console diagnostics and inspect the local "
        "diagnostics directory. Do not paste unrestricted logs into a public issue.\n"
        "• Ask ARIA to explain posture or run diagnostics; do not authorize a change until "
        "the target and rollback are clear.",
    ),
    "threat-level": (
        "How the threat level works",
        "The threat level reflects unresolved security evidence, not merely the number of "
        "informational events. Self-health events and inert drills should not independently "
        "raise it. Review elevated findings in Resolve Center, verify the underlying event, "
        "and either remediate it or explicitly classify a proven false positive.",
    ),
    "privacy": (
        "Privacy and data boundaries",
        "Angerona is local-first. Detection, local ARIA answers, evidence correlation, and "
        "host metrics remain on the device. Optional online intelligence, provider-assisted "
        "AI, messaging, or interoperability can create egress only after explicit setup. "
        "Review each capability's privacy, limitations, and destination before enabling it. "
        "Credentials must be stored through the protected Settings workflow, never in a "
        "project file or diagnostic bundle.",
    ),
}


def render_capability_body(guide: CapabilityGuide) -> str:
    """Render one canonical capability as plain text for Help, ARIA or console."""

    steps = "\n".join(f"{index}. {step}" for index, step in enumerate(guide.steps, 1))
    evidence = "\n".join(f"• {reference}" for reference in guide.evidence)
    limitations = "\n".join(f"• {item}" for item in guide.limitations)
    availability = guide.destination_availability.value.replace("-", " ")
    actionability = guide.destination_actionability.value.replace("-", " ")
    if guide.destination_kind is DestinationKind.WINDOW:
        destination = "Main window > " + guide.name
    elif guide.destination_kind is DestinationKind.SETTINGS:
        destination = "Settings > " + guide.destination
    else:
        destination = "No in-product destination"
    if guide.destination_actionability is DestinationActionability.CONTEXTUAL:
        destination += " (opens the owning section; select this capability there)"
    if guide.destination_availability is not DestinationAvailability.AVAILABLE:
        destination += f" ({availability})"
    return (
        f"Maturity: {guide.maturity_label}\n"
        f"Category: {guide.category}\n\n"
        f"WHAT IT DOES\n{guide.definition}\n\n"
        f"HOW TO USE IT\n{steps}\n\n"
        f"VERIFY\n{guide.verify}\n\n"
        f"PRIVACY AND SAFETY\n{guide.privacy}\n\n"
        f"EVIDENCE\n{evidence}\n\n"
        f"KNOWN LIMITATIONS\n{limitations}\n\n"
        f"CANONICAL DESTINATION\n{destination}\n"
        f"Navigation: {actionability}; availability: {availability}."
    )


def capability_topics() -> dict[str, tuple[str, str]]:
    """Return capability Help topics in the canonical catalog order."""

    return {
        guide.key: (guide.name, render_capability_body(guide))
        for guide in GUIDES
    }


CAPABILITY_TOPIC_KEYS = tuple(guide.key for guide in GUIDES)
SUPPLEMENTARY_TOPIC_KEYS = tuple(_SUPPLEMENTARY_TOPICS)
TOPICS: dict[str, tuple[str, str]] = {
    **_SUPPLEMENTARY_TOPICS,
    **capability_topics(),
}

_ALIASES = {
    "start": "getting-started",
    "help": "getting-started",
    "overview": "getting-started",
    "action": "actions",
    "commands": "actions",
    "fix": "troubleshooting",
    "problem": "troubleshooting",
    "debug": "troubleshooting",
    "threat": "threat-level",
    "posture": "threat-level",
    "data": "privacy",
    "assistant": "local-ai",
    "aria": "local-ai",
    "voice": "local-ai",
    "stt": "local-ai",
    "tts": "local-ai",
    "mic": "local-ai",
    "friday": "local-ai",
    "ultron": "local-ai",
    "persona": "local-ai",
    "gesture": "local-ai",
    "hand-controls": "local-ai",
    "camera": "local-ai",
    "conversation": "local-ai",
    "awareness": "local-ai",
    "phone": "mobile",
    "signal": "mobile",
    "trusted": "trusted-processes",
    "trusted-apps": "trusted-processes",
    "test": "red-team",
    "testing": "red-team",
    "drill": "red-team",
}


def topics() -> list[str]:
    return list(TOPICS)


def _topic_key(value: str) -> str:
    return "-".join(str(value or "").strip().casefold().replace("_", " ").split())


def resolve(name: str) -> str | None:
    key = _topic_key(name)
    if key in TOPICS:
        return key
    alias = _ALIASES.get(key)
    if alias is not None:
        return alias
    matches = search_guides(name)
    return matches[0].key if matches else None


def get(name: str = "getting-started") -> str:
    """Return a rendered Help topic, or the canonical topic index if unknown."""

    key = resolve(name)
    if key is None:
        return (
            "Angerona guide - available topics:\n  "
            + " · ".join(topics())
            + "\nType 'guide <topic>' or ask ARIA."
        )
    title, body = TOPICS[key]
    return f"── {title} ──\n{body}"


def overview() -> str:
    return get("getting-started")
