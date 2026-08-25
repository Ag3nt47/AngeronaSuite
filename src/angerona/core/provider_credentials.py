"""Canonical metadata and access helpers for optional AI provider credentials.

Angerona keeps provider secrets in its operating-system protected credential
store. Runtime consumers use this module for scoped retrieval; credentials are
never republished into the process environment where unrelated child processes
could inherit them.

Legacy Gemini names are read for compatibility.  The next explicit Settings
save migrates them to ``GEMINI_API_KEYS`` and removes the aliases from protected
storage and the live environment.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


_MAX_CREDENTIAL_CHARS = 64 * 1024
_MAX_POOL_ITEMS = 32


@dataclass(frozen=True, slots=True)
class ProviderCredential:
    """Public provider metadata; this object never contains a secret value."""

    provider_id: str
    label: str
    environment_key: str
    legacy_aliases: tuple[str, ...] = ()
    supports_pool: bool = False


PROVIDER_CREDENTIALS = (
    ProviderCredential("anthropic", "Anthropic (Claude)", "ANTHROPIC_API_KEY"),
    ProviderCredential(
        "gemini",
        "Google Gemini",
        "GEMINI_API_KEYS",
        legacy_aliases=("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        supports_pool=True,
    ),
    ProviderCredential("groq", "Groq", "GROQ_API_KEY"),
    ProviderCredential("openai", "OpenAI", "OPENAI_API_KEY"),
    ProviderCredential("openrouter", "OpenRouter", "OPENROUTER_API_KEY"),
)

_BY_ID = MappingProxyType(
    {credential.provider_id: credential for credential in PROVIDER_CREDENTIALS}
)


def provider_credential(provider_id: str) -> ProviderCredential:
    """Return immutable metadata for *provider_id* or raise ``KeyError``."""

    return _BY_ID[str(provider_id).strip().casefold()]


def _bounded_value(value: object) -> str:
    text = "" if value is None else str(value).strip()
    if len(text) > _MAX_CREDENTIAL_CHARS:
        raise ValueError("provider credential exceeds the protected-store limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise ValueError("provider credential contains a control character")
    return text


def credential_values(
    provider_id: str,
    source: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Return configured values without logging, copying, or mutating storage.

    The canonical key wins.  Legacy aliases are consulted only when the
    canonical value is empty, preventing a stale alias from overriding a
    credential that the operator has already rotated.
    """

    spec = provider_credential(provider_id)
    if source is None:
        from angerona.core.secure_store import read_secret_values

        values = read_secret_values((spec.environment_key, *spec.legacy_aliases))
    else:
        values = source
    raw = _bounded_value(values.get(spec.environment_key, ""))
    if not raw:
        for alias in spec.legacy_aliases:
            raw = _bounded_value(values.get(alias, ""))
            if raw:
                break
    if not raw:
        return ()
    if not spec.supports_pool:
        return (raw,)
    items = tuple(part.strip() for part in raw.split(",") if part.strip())
    if len(items) > _MAX_POOL_ITEMS:
        raise ValueError("provider credential pool exceeds the supported item limit")
    return items


def credential_value(
    provider_id: str,
    source: Mapping[str, str] | None = None,
) -> str:
    """Return the first configured value for a provider, or an empty string."""

    values = credential_values(provider_id, source)
    return values[0] if values else ""


def provider_form_values(
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return provider-id keyed values suitable for the canonical Settings UI."""

    result: dict[str, str] = {}
    for spec in PROVIDER_CREDENTIALS:
        values = credential_values(spec.provider_id, source)
        result[spec.provider_id] = ",".join(values) if spec.supports_pool else (
            values[0] if values else ""
        )
    return result


def configured_provider_ids(
    source: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Return configured provider identifiers in canonical display order."""

    return tuple(
        spec.provider_id
        for spec in PROVIDER_CREDENTIALS
        if credential_values(spec.provider_id, source)
    )


def canonical_updates(values_by_provider: Mapping[str, object]) -> dict[str, str]:
    """Translate provider-id values into protected-store updates.

    Empty strings are intentional removals.  Aliases are cleared whenever a
    provider is included, making an explicit save a one-way compatibility
    migration without silently touching credentials at startup.
    """

    updates: dict[str, str] = {}
    for provider_id, value in values_by_provider.items():
        spec = provider_credential(provider_id)
        text = _bounded_value(value)
        if spec.supports_pool and text:
            items = tuple(part.strip() for part in text.split(",") if part.strip())
            if len(items) > _MAX_POOL_ITEMS:
                raise ValueError(
                    "provider credential pool exceeds the supported item limit"
                )
            text = ",".join(items)
        updates[spec.environment_key] = text
        updates.update({alias: "" for alias in spec.legacy_aliases})
    return updates


def save_provider_credentials(values_by_provider: Mapping[str, object]):
    """Persist an explicit provider update through the canonical secure store."""

    from angerona.core.config import write_env_keys

    return write_env_keys(canonical_updates(values_by_provider))
