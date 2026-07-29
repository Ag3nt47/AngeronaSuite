"""Versioned, platform-neutral sensor event envelopes.

Platform collectors normalize their observations here before publishing them
onto Angerona's authenticated EventBus.  The schema intentionally separates
process, file, network, and extension metadata; consumers no longer need to
understand a Windows ETW payload or a macOS Endpoint Security message directly.
"""
from __future__ import annotations

import json
import math
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from angerona.core.eventbus import Event, Severity
from angerona.core.platforms import KNOWN_PLATFORMS, normalize_platform

SENSOR_EVENT_SCHEMA_VERSION = 1
MAX_EVENT_BYTES = 256 * 1024
MAX_TEXT = 4096
MAX_SECTION_ITEMS = 64
ALLOWED_KINDS = frozenset({
    "process",
    "file",
    "network",
    "authentication",
    "system",
    "security",
})


class SensorEventError(ValueError):
    """Raised when a platform sensor crosses the normalized-event boundary badly."""


def _text(value: object, field_name: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise SensorEventError(f"{field_name} must be a string")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum or "\x00" in cleaned:
        raise SensorEventError(f"{field_name} is empty or exceeds {maximum} characters")
    return cleaned


def _section(value: object, field_name: str) -> dict[str, Any]:
    if value in (None, {}):
        return {}
    if not isinstance(value, Mapping) or len(value) > MAX_SECTION_ITEMS:
        raise SensorEventError(
            f"{field_name} must be an object with at most {MAX_SECTION_ITEMS} fields"
        )
    result: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = _text(raw_key, f"{field_name}.key", 96)
        if isinstance(raw_value, str):
            result[key] = _text(raw_value, f"{field_name}.{key}")
        elif raw_value is None or isinstance(raw_value, (bool, int)):
            result[key] = raw_value
        elif isinstance(raw_value, float) and math.isfinite(raw_value):
            result[key] = raw_value
        elif isinstance(raw_value, (list, tuple)) and len(raw_value) <= 32:
            if any(not isinstance(item, str) for item in raw_value):
                raise SensorEventError(
                    f"{field_name}.{key} lists may contain only strings"
                )
            result[key] = [
                _text(item, f"{field_name}.{key}", 512)
                for item in raw_value
            ]
        else:
            raise SensorEventError(
                f"{field_name}.{key} contains an unsupported or unbounded value"
            )
    return result


@dataclass(frozen=True)
class SensorEvent:
    platform: str
    sensor: str
    kind: str
    action: str
    observed_at: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    process: Mapping[str, Any] = field(default_factory=dict)
    file: Mapping[str, Any] = field(default_factory=dict)
    network: Mapping[str, Any] = field(default_factory=dict)
    security: Mapping[str, Any] = field(default_factory=dict)
    privacy_classes: tuple[str, ...] = ()
    schema_version: int = SENSOR_EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        platform = normalize_platform(_text(self.platform, "platform", 64))
        if platform not in KNOWN_PLATFORMS:
            raise SensorEventError(f"unsupported platform: {self.platform!r}")
        if self.schema_version != SENSOR_EVENT_SCHEMA_VERSION:
            raise SensorEventError(
                f"schema_version must be {SENSOR_EVENT_SCHEMA_VERSION}"
            )
        if not isinstance(self.observed_at, (int, float)) or not math.isfinite(
            float(self.observed_at)
        ):
            raise SensorEventError("observed_at must be a finite timestamp")
        event_id = _text(self.event_id, "event_id", 96)
        sensor = _text(self.sensor, "sensor", 160)
        kind = _text(self.kind, "kind", 64).casefold()
        if kind not in ALLOWED_KINDS:
            raise SensorEventError(f"unsupported sensor event kind: {kind}")
        action = _text(self.action, "action", 160).casefold()
        privacy = tuple(dict.fromkeys(
            _text(item, "privacy_classes", 96).casefold()
            for item in self.privacy_classes
        ))
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "sensor", sensor)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "process", _section(self.process, "process"))
        object.__setattr__(self, "file", _section(self.file, "file"))
        object.__setattr__(self, "network", _section(self.network, "network"))
        object.__setattr__(self, "security", _section(self.security, "security"))
        object.__setattr__(self, "privacy_classes", privacy)
        encoded = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(encoded) > MAX_EVENT_BYTES:
            raise SensorEventError(
                f"normalized event exceeds {MAX_EVENT_BYTES} bytes"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "observed_at": float(self.observed_at),
            "platform": self.platform,
            "sensor": self.sensor,
            "kind": self.kind,
            "action": self.action,
            "process": dict(self.process),
            "file": dict(self.file),
            "network": dict(self.network),
            "security": dict(self.security),
            "privacy_classes": list(self.privacy_classes),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SensorEvent":
        if not isinstance(payload, Mapping):
            raise SensorEventError("sensor event must be an object")
        allowed = {
            "schema_version", "event_id", "observed_at", "platform", "sensor",
            "kind", "action", "process", "file", "network", "security",
            "privacy_classes",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise SensorEventError(
                f"sensor event contains {len(unknown)} unknown field(s)"
            )
        privacy = payload.get("privacy_classes", ())
        if not isinstance(privacy, (list, tuple)) or len(privacy) > 32:
            raise SensorEventError("privacy_classes must contain at most 32 values")
        return cls(
            schema_version=payload.get("schema_version", SENSOR_EVENT_SCHEMA_VERSION),
            event_id=payload.get("event_id", ""),
            observed_at=payload.get("observed_at", 0.0),
            platform=payload.get("platform", ""),
            sensor=payload.get("sensor", ""),
            kind=payload.get("kind", ""),
            action=payload.get("action", ""),
            process=payload.get("process", {}),
            file=payload.get("file", {}),
            network=payload.get("network", {}),
            security=payload.get("security", {}),
            privacy_classes=tuple(privacy),
        )

    def to_event(
        self,
        module: str,
        severity: Severity = Severity.INFO,
        message: str | None = None,
    ) -> Event:
        summary = message or (
            f"{self.platform} {self.kind}:{self.action} observed by {self.sensor}"
        )
        return Event(
            module=module,
            message=summary,
            severity=severity,
            ts=float(self.observed_at),
            details={"sensor_event": self.as_dict()},
        )
