"""Canonical ownership and routing for Angerona configuration surfaces."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SettingsArea:
    key: str
    title: str
    purpose: str
    keywords: tuple[str, ...]
    privacy: str
    restart: bool = False


AREAS = (
    SettingsArea(
        "general", "General",
        "Local model, appearance, motion, integrity and updates.",
        ("ollama", "model", "theme", "appearance", "animation", "motion",
         "orb", "update", "github", "integrity"),
        "Local configuration", False,
    ),
    SettingsArea(
        "system", "System",
        "Startup, local services, performance and platform sensors.",
        ("startup", "autostart", "eco", "performance", "black box", "mcp",
         "ebpf", "sgx", "service"),
        "Local configuration", True,
    ),
    SettingsArea(
        "enterprise", "Enterprise",
        "Readiness evidence, signed content, fleet and policy controls.",
        ("enterprise", "fleet", "policy", "rbac", "manifest", "signature",
         "receipt", "causal", "readiness"),
        "Local evidence", True,
    ),
    SettingsArea(
        "aria", "ARIA",
        "Assistant, microphone, voice, mailbox, Teams and optional egress.",
        ("aria", "microphone", "mic", "voice", "speech", "cloud", "mail",
         "teams", "research", "webhook", "notification"),
        "Optional egress; off by default", False,
    ),
    SettingsArea(
        "trusted", "Trusted Processes",
        "Exact-path process trust and supervised false-positive handling.",
        ("trusted", "allow", "process", "vpn", "false positive", "proton"),
        "Local executable metadata", False,
    ),
    SettingsArea(
        "mobile", "Mobile Integration",
        "Signal bridge, operator destination and protected command PIN.",
        ("mobile", "signal", "phone", "sms", "pin", "signal-cli"),
        "Optional egress; off by default", True,
    ),
    SettingsArea(
        "keys", "API Keys",
        "Encrypted credentials and provider preference for optional cloud use.",
        ("key", "api", "credential", "secret", "provider", "openai",
         "anthropic", "gemini", "groq"),
        "Secrets stored outside settings.json", False,
    ),
)


def validate_catalog(areas=AREAS) -> None:
    keys = [area.key for area in areas]
    titles = [area.title.casefold() for area in areas]
    if len(set(keys)) != len(keys) or len(set(titles)) != len(titles):
        raise ValueError("settings areas require unique keys and titles")
    owners: dict[str, str] = {}
    for area in areas:
        if not area.key or not area.title or not area.purpose:
            raise ValueError("settings area metadata is incomplete")
        for keyword in area.keywords:
            normalized = keyword.strip().casefold()
            if not normalized:
                raise ValueError("settings keyword must not be empty")
            previous = owners.setdefault(normalized, area.key)
            if previous != area.key:
                raise ValueError(
                    f"overlapping settings keyword {normalized!r}: "
                    f"{previous} and {area.key}"
                )


def resolve_area(query: str) -> SettingsArea | None:
    text = str(query or "").strip().casefold()
    if not text:
        return None
    exact = next(
        (area for area in AREAS if text in {area.key, area.title.casefold()}),
        None,
    )
    if exact is not None:
        return exact
    scored = [
        (max((len(word) for word in area.keywords if word in text), default=0), area)
        for area in AREAS
    ]
    score, area = max(scored, key=lambda item: item[0])
    return area if score else None


validate_catalog()
