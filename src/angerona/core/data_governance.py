"""Deterministic privacy classification, minimization, and egress previews.

Security telemetry is not assumed safe merely because it is local. This module
provides one bounded policy boundary for data leaving its original component.
It has no network or filesystem side effects.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping


class DataClass(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    SENSITIVE = 2
    RESTRICTED = 3


_RESTRICTED = frozenset({
    "api_key", "authorization", "cookie", "credential", "password", "secret",
    "token", "private_key",
})
_SENSITIVE = frozenset({
    "cmdline", "command_line", "email", "file_content", "hostname", "path",
    "process_path", "registry_data", "source_ip", "destination_ip", "username",
})
_INTERNAL = frozenset({
    "device_id", "event_id", "module", "rule_id", "technique_id",
})
_MAX_FIELDS = 256
_MAX_DEPTH = 6
_MAX_TEXT = 8192


def _field_class(name: str) -> DataClass:
    leaf = name.rsplit(".", 1)[-1].casefold()
    if leaf in _RESTRICTED:
        return DataClass.RESTRICTED
    if leaf in _SENSITIVE:
        return DataClass.SENSITIVE
    if leaf in _INTERNAL:
        return DataClass.INTERNAL
    return DataClass.PUBLIC


def _token(value: object, salt: bytes) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")
    return "tok_" + hashlib.sha256(salt + b"\0" + raw).hexdigest()[:20]


@dataclass(frozen=True)
class PrivacyField:
    path: str
    classification: DataClass
    action: str


@dataclass(frozen=True)
class PrivacyPreview:
    purpose: str
    destination: str
    permitted: bool
    highest_class: DataClass
    fields: tuple[PrivacyField, ...]
    minimized_payload: Mapping[str, Any]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class EgressPolicy:
    """Local policy for one explicit data transfer.

    ``maximum_class`` is the highest class allowed to remain verbatim.
    Restricted fields are always removed, regardless of this value.
    """

    maximum_class: DataClass = DataClass.INTERNAL
    allow_external: bool = False
    tokenize_sensitive: bool = True
    max_payload_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if not 1024 <= self.max_payload_bytes <= 1024 * 1024:
            raise ValueError("max_payload_bytes must be between 1 KiB and 1 MiB")

    def preview(
        self,
        payload: Mapping[str, Any],
        *,
        purpose: str,
        destination: str,
        salt: bytes,
        external: bool,
    ) -> PrivacyPreview:
        if not purpose.strip() or not destination.strip():
            raise ValueError("purpose and destination are required")
        if len(salt) < 16:
            raise ValueError("tokenization salt must contain at least 16 bytes")
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")

        records: list[PrivacyField] = []
        count = 0

        def visit(value: Any, path: str, depth: int) -> Any:
            nonlocal count
            if depth > _MAX_DEPTH:
                records.append(PrivacyField(path, DataClass.SENSITIVE, "removed-depth"))
                return None
            if isinstance(value, Mapping):
                out: dict[str, Any] = {}
                for key, item in value.items():
                    count += 1
                    if count > _MAX_FIELDS:
                        raise ValueError("payload exceeds field budget")
                    name = str(key)[:128]
                    child = f"{path}.{name}" if path else name
                    transformed = visit(item, child, depth + 1)
                    if transformed is not None:
                        out[name] = transformed
                return out
            if isinstance(value, (list, tuple)):
                return [visit(item, f"{path}[]", depth + 1) for item in value[:100]]

            classification = _field_class(path)
            if classification is DataClass.RESTRICTED:
                records.append(PrivacyField(path, classification, "removed"))
                return None
            if classification > self.maximum_class:
                action = "tokenized" if self.tokenize_sensitive else "removed"
                records.append(PrivacyField(path, classification, action))
                return _token(value, salt) if self.tokenize_sensitive else None
            records.append(PrivacyField(path, classification, "included"))
            if isinstance(value, str):
                return value[:_MAX_TEXT]
            if value is None or isinstance(value, (bool, int, float)):
                return value
            return str(value)[:_MAX_TEXT]

        minimized = visit(payload, "", 0)
        encoded = json.dumps(
            minimized, sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")
        reasons: list[str] = []
        permitted = True
        if external and not self.allow_external:
            permitted = False
            reasons.append("external egress is disabled")
        if len(encoded) > self.max_payload_bytes:
            permitted = False
            reasons.append("minimized payload exceeds byte budget")
        highest = max(
            (item.classification for item in records),
            default=DataClass.PUBLIC,
        )
        return PrivacyPreview(
            purpose=purpose.strip()[:256],
            destination=destination.strip()[:256],
            permitted=permitted,
            highest_class=highest,
            fields=tuple(records),
            minimized_payload=minimized,
            reasons=tuple(reasons),
        )


@dataclass(frozen=True)
class RetentionPolicy:
    days_by_class: Mapping[DataClass, int]

    def __post_init__(self) -> None:
        expected = set(DataClass)
        if set(self.days_by_class) != expected:
            raise ValueError("retention must define every data class")
        if any(not 1 <= int(days) <= 3650 for days in self.days_by_class.values()):
            raise ValueError("retention must be between 1 and 3650 days")

    def retain_days(self, classification: DataClass) -> int:
        return int(self.days_by_class[classification])


DEFAULT_RETENTION = RetentionPolicy({
    DataClass.PUBLIC: 365,
    DataClass.INTERNAL: 180,
    DataClass.SENSITIVE: 30,
    DataClass.RESTRICTED: 7,
})
