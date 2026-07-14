"""A tiny thread-safe publish/subscribe bus plus the canonical Event type.

Modules run on their own threads and call ``EventBus.publish(...)``. Subscribers
(the flight-recorder and the GUI) receive every event. The bus also keeps a
bounded in-memory ring of recent events so the GUI can render instantly without
hitting the database on every refresh.

G3-A — HMAC-SHA256 bus authentication
--------------------------------------
Each event is optionally signed with HMAC-SHA256 before entering the ring.
A per-install 32-byte secret key is stored (or generated on first run) at
``LOCALAPPDATA/Angerona/bus.key``.

Why:
  A threat actor with filesystem access could tamper with the SQLite ledger
  and inject false events to manipulate the SOAR engine into acting (or not
  acting).  HMAC-signed events let SOAR verify that an event's module/severity/
  message/ts have not been changed since it was published by a legitimate module.

What HMAC does NOT protect:
  A compromised Python module that has already loaded the key can forge valid
  signatures.  HMAC hardens the STORED event path, not the in-process trust
  boundary (which is protected by the supervisor + process isolation layers).

Usage::
    auth = BusAuthority.load()      # or BusAuthority.generate() on first run
    bus.arm(auth)
    # From now on, every published event is signed; bus.verify(ev) → True.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, Deque, List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass(frozen=True)
class Event:
    module: str
    message: str
    severity: Severity = Severity.INFO
    ts: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)
    # G3-A: HMAC-SHA256 signature over canonical fields (empty = unsigned)
    hmac_sig: str = ""

    @property
    def time_str(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.ts))


Subscriber = Callable[[Event], None]


# ── G3-A: Bus authentication ──────────────────────────────────────────────────

class BusAuthority:
    """Loads or generates the per-install HMAC key for event signing.

    Key file: ``LOCALAPPDATA/Angerona/bus.key`` (32 random bytes, hex-encoded).
    On first run call ``BusAuthority.generate()`` to create a new key.
    On subsequent runs call ``BusAuthority.load()`` to read the existing key.
    """
    _KEY_BYTES = 32

    def __init__(self, key: bytes) -> None:
        self._key = key

    @staticmethod
    def _key_path() -> Path:
        base = os.environ.get("ANGERONA_DATA") or os.path.join(
            os.environ.get("LOCALAPPDATA", str(Path.home())), "Angerona"
        )
        return Path(base) / "bus.key"

    @classmethod
    def generate(cls) -> "BusAuthority":
        """Generate and atomically create the first-install key.

        This is deliberately create-only: a second process racing first start
        loads the winner's key rather than replacing it and splitting the
        ledger's signing authority.
        """
        key = secrets.token_bytes(cls._KEY_BYTES)
        p   = cls._key_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return cls.load()
        try:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(key.hex())
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            try:
                p.unlink()
            except Exception:
                pass
            raise
        return cls(key)

    @classmethod
    def load(cls) -> "BusAuthority":
        """Load the existing key; generate only when it is genuinely absent.

        A malformed or unreadable existing key is an integrity failure, not a
        first run. Silently rotating it would make every signed ledger row look
        corrupt and conceal key-file tampering.
        """
        p = cls._key_path()
        try:
            encoded = p.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            return cls.generate()
        except Exception as exc:
            raise RuntimeError(f"event signing key is unreadable: {p}") from exc
        try:
            key = bytes.fromhex(encoded)
        except ValueError as exc:
            raise RuntimeError(f"event signing key is malformed: {p}") from exc
        if len(key) != cls._KEY_BYTES:
            raise RuntimeError(
                f"event signing key has invalid length ({len(key)} bytes): {p}"
            )
        return cls(key)

    def sign(self, event: "Event") -> str:
        """Return hex HMAC-SHA256 over the event's canonical fields."""
        # Canonical JSON avoids separator ambiguity and includes the full details
        # payload used by triage, forensics, and response decisions.
        canonical = json.dumps(
            {
                "details": event.details or {},
                "message": event.message,
                "module": event.module,
                "severity": int(event.severity),
                "ts": event.ts,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        return hmac.new(self._key, canonical, hashlib.sha256).hexdigest()

    def verify(self, event: "Event") -> bool:
        """Return True if the event's hmac_sig matches the expected value."""
        if not event.hmac_sig:
            return False
        expected = self.sign(event)
        return hmac.compare_digest(event.hmac_sig, expected)


class EventBus:
    # G3-E: bounded recent-history ring; oldest entries roll off automatically.

    def __init__(self, ring_size: int = 500) -> None:
        self._subs:      List[Subscriber]          = []
        self._ring:      Deque[Event]              = deque(maxlen=ring_size)
        self._lock:      threading.RLock           = threading.RLock()
        self._authority: Optional[BusAuthority]    = None   # G3-A

    # G3-A: wire in the signing authority
    def arm(self, authority: BusAuthority) -> None:
        """Call once at startup to enable HMAC signing on all published events."""
        self._authority = authority

    def verify(self, event: Event) -> bool:
        """True if event carries a valid HMAC signature (requires arm() first)."""
        if self._authority is None:
            return True   # unarmed bus — all events pass
        return self._authority.verify(event)

    def subscribe(self, fn: Subscriber) -> None:
        with self._lock:
            self._subs.append(fn)

    def publish(self, event: Event) -> None:
        # G3-A: sign the event if an authority is registered
        if self._authority is not None:
            sig   = self._authority.sign(event)
            event = dataclasses.replace(event, hmac_sig=sig)

        # deque(maxlen=...) is the backpressure: it evicts old history while
        # every new event still reaches subscribers and persistent storage.
        with self._lock:
            self._ring.append(event)
            subs = list(self._subs)

        # Notify outside the lock so a slow subscriber can't block publishers.
        for fn in subs:
            try:
                fn(event)
            except Exception:
                # A misbehaving subscriber must never crash the producer.
                pass

    def recent(self, limit: int = 100) -> List[Event]:
        with self._lock:
            items = list(self._ring)
        return items[-limit:][::-1]  # newest first
