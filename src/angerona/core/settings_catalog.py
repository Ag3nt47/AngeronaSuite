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
        ("ollama", "model", "theme", "appearance", "dashboard", "flow",
         "local soc", "animation", "motion",
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
        "Optional assistant, persona, conversation, hand, microphone, mailbox, Teams and egress controls.",
        ("aria", "microphone", "mic", "voice", "voice model", "speech",
         "friday", "ultron", "persona", "conversation", "awareness",
         "always listen", "follow up", "camera", "gesture", "hand controls",
         "privacy", "privacy defaults", "cloud", "mail", "teams",
         "research", "webhook", "notification"),
        "Assistant, sensors, listeners, and optional egress are off by default", False,
    ),
    SettingsArea(
        "trusted", "Trusted Processes",
        "Exact-path process trust and supervised false-positive handling.",
        ("trusted", "allow", "process", "vpn", "false positive", "proton",
         "baseline", "learning", "publisher", "authenticode"),
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
        ("key", "api", "api key", "api keys", "cloud api key",
         "cloud api keys", "credential", "secret", "provider", "openai",
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
    text, query_words = _normalize_search(query)
    if not text:
        return None
    exact = next(
        (
            area
            for area in AREAS
            if text
            in {
                _normalize_search(area.key)[0],
                _normalize_search(area.title)[0],
            }
        ),
        None,
    )
    if exact is not None:
        return exact

    candidates: list[tuple[tuple[int, int, int, int], SettingsArea]] = []
    for area in AREAS:
        matches: list[tuple[str, tuple[str, ...]]] = []
        for keyword in area.keywords:
            normalized, keyword_words = _normalize_search(keyword)
            if _contains_phrase(query_words, keyword_words):
                matches.append((normalized, keyword_words))
        if not matches:
            continue
        covered = {word for _keyword, words in matches for word in words}
        score = (
            max(len(words) for _keyword, words in matches),
            max(len(keyword) for keyword, _words in matches),
            len(covered),
            len(matches),
        )
        candidates.append((score, area))

    if not candidates:
        return None
    best_score = max(score for score, _area in candidates)
    winners = [area for score, area in candidates if score == best_score]
    # An unresolved semantic tie is safer than routing according to catalog order.
    return winners[0] if len(winners) == 1 else None


def _normalize_search(value: object) -> tuple[str, tuple[str, ...]]:
    """Return punctuation-insensitive text and its words for bounded matching."""
    folded = str(value or "").strip().casefold()
    normalized = " ".join(
        "".join(character if character.isalnum() else " " for character in folded)
        .split()
    )
    return normalized, tuple(normalized.split())


def _contains_phrase(
    words: tuple[str, ...], phrase: tuple[str, ...],
) -> bool:
    """Match whole words in order; substrings such as ``api`` in ``capital`` fail."""
    width = len(phrase)
    if not width or width > len(words):
        return False
    return any(
        words[index:index + width] == phrase
        for index in range(len(words) - width + 1)
    )


validate_catalog()
