"""Authenticated boundary for events produced by a native macOS host.

The entitled Endpoint Security / Network Extension processes must not publish
arbitrary Python objects directly.  The native host emits a bounded JSON frame,
authenticated with an installation-local bridge key.  This decoder validates
the signature, freshness, replay nonce, and normalized SensorEvent schema before
the shared core can put the observation on its EventBus.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from collections import deque
from typing import Mapping

from angerona.core.sensor_events import (
    MAX_EVENT_BYTES,
    SensorEvent,
    SensorEventError,
)

BRIDGE_SCHEMA_VERSION = 1
MAX_CLOCK_SKEW_SECONDS = 120.0
_NONCE = re.compile(r"^[0-9a-f]{32,64}$")


class NativeBridgeError(ValueError):
    pass


def _canonical_body(frame: Mapping[str, object]) -> bytes:
    body = {
        "schema_version": frame.get("schema_version"),
        "sent_at": frame.get("sent_at"),
        "nonce": frame.get("nonce"),
        "event": frame.get("event"),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuthenticatedNativeBridge:
    """Stateful decoder with a bounded replay cache."""

    def __init__(
        self,
        key: bytes,
        *,
        clock=time.time,
        max_replays: int = 4096,
    ) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise NativeBridgeError("native bridge key must contain at least 32 bytes")
        self._key = key
        self._clock = clock
        self._max_replays = max(128, min(65_536, int(max_replays)))
        self._nonce_order: deque[str] = deque()
        self._nonces: set[str] = set()

    def decode(self, packet: bytes) -> SensorEvent:
        if not isinstance(packet, bytes) or not packet or len(packet) > MAX_EVENT_BYTES:
            raise NativeBridgeError(
                f"native event frame must be 1..{MAX_EVENT_BYTES} bytes"
            )
        try:
            frame = json.loads(packet.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise NativeBridgeError("native event frame is not valid UTF-8 JSON") from exc
        if not isinstance(frame, dict):
            raise NativeBridgeError("native event frame must be an object")
        if set(frame) != {
            "schema_version", "sent_at", "nonce", "event", "hmac_sha256"
        }:
            raise NativeBridgeError("native event frame fields do not match schema")
        if frame["schema_version"] != BRIDGE_SCHEMA_VERSION:
            raise NativeBridgeError("unsupported native bridge schema")
        nonce = frame.get("nonce")
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            raise NativeBridgeError("native event nonce is malformed")
        if nonce in self._nonces:
            raise NativeBridgeError("native event replay detected")
        sent_at = frame.get("sent_at")
        if (
            not isinstance(sent_at, (int, float))
            or not math.isfinite(float(sent_at))
        ):
            raise NativeBridgeError("native event sent_at is invalid")
        if abs(float(self._clock()) - float(sent_at)) > MAX_CLOCK_SKEW_SECONDS:
            raise NativeBridgeError("native event is stale or too far in the future")
        supplied = frame.get("hmac_sha256")
        if not isinstance(supplied, str) or len(supplied) != 64:
            raise NativeBridgeError("native event signature is malformed")
        expected = hmac.new(
            self._key, _canonical_body(frame), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(supplied.casefold(), expected):
            raise NativeBridgeError("native event signature verification failed")
        event_raw = frame.get("event")
        if not isinstance(event_raw, Mapping):
            raise NativeBridgeError("native event payload must be an object")
        try:
            event = SensorEvent.from_dict(event_raw)
        except SensorEventError as exc:
            raise NativeBridgeError(f"native event payload rejected: {exc}") from exc
        if event.platform != "macos":
            raise NativeBridgeError("native bridge accepts macOS sensor events only")
        self._nonces.add(nonce)
        self._nonce_order.append(nonce)
        while len(self._nonce_order) > self._max_replays:
            self._nonces.discard(self._nonce_order.popleft())
        return event


def encode_for_test(event: SensorEvent, key: bytes, *, sent_at: float, nonce: str) -> bytes:
    """Create a canonical frame for native-bridge conformance tests."""
    frame: dict[str, object] = {
        "schema_version": BRIDGE_SCHEMA_VERSION,
        "sent_at": float(sent_at),
        "nonce": nonce,
        "event": event.as_dict(),
    }
    frame["hmac_sha256"] = hmac.new(
        key, _canonical_body(frame), hashlib.sha256
    ).hexdigest()
    return json.dumps(frame, sort_keys=True, separators=(",", ":")).encode("utf-8")
