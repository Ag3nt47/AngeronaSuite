"""A tiny thread-safe publish/subscribe bus plus the canonical Event type.

Modules run on their own threads and call ``EventBus.publish(...)``. Subscribers
(the flight-recorder and the GUI) receive every event. The bus also keeps a
bounded in-memory ring of recent events so the GUI can render instantly without
hitting the database on every refresh.

G3-A — HMAC-SHA256 bus authentication
--------------------------------------
Each event is optionally signed with HMAC-SHA256 before entering the ring.
A per-install 32-byte secret key is stored (or generated on first run) at
``<ANGERONA_DATA>/bus.key``.

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
from itertools import islice
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


REMOTE_OBSERVE_AUTHORITY = "remote-observe-only"


def is_remote_observe_only(event: object) -> bool:
    """Return whether an event is cross-host evidence with no local authority.

    A mutually authenticated sensor peer is trusted to describe its own host,
    not to name a process or file that response engines may alter on this host.
    The legacy ``node_origin`` check keeps older forwarded events fail-safe.
    """
    details = getattr(event, "details", None)
    if not isinstance(details, dict):
        return False
    return (
        details.get("response_authority") == REMOTE_OBSERVE_AUTHORITY
        or bool(details.get("node_origin"))
    )


Subscriber = Callable[[Event], None]


@dataclass(frozen=True)
class SubscriberMetrics:
    name: str
    delivery_budget_ms: float
    deliveries: int
    failures: int
    budget_violations: int
    last_delivery_ms: float
    max_delivery_ms: float
    total_delivery_ms: float


# ── G3-A: Bus authentication ──────────────────────────────────────────────────

class BusAuthority:
    """Loads or generates the per-install HMAC key for event signing.

    Key file: ``<ANGERONA_DATA>/bus.key`` (32 random bytes, hex-encoded).
    On first run call ``BusAuthority.generate()`` to create a new key.
    On subsequent runs call ``BusAuthority.load()`` to read the existing key.
    """
    _KEY_BYTES = 32

    def __init__(self, key: bytes) -> None:
        self._key = key

    @staticmethod
    def _key_path() -> Path:
        from angerona.core.data_paths import data_dir
        return data_dir() / "bus.key"

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
        from angerona.core.hardening import ensure_sensitive_parent, key_acl_required
        required = key_acl_required()
        ensure_sensitive_parent(p, required=required)
        try:
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return cls.load()
        try:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(key.hex())
                fh.flush()
                os.fsync(fh.fileno())
            from angerona.core.hardening import secure_sensitive_file
            secure_sensitive_file(p, required=required)
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
        from angerona.core.hardening import key_acl_required, prepare_sensitive_key
        required = key_acl_required()
        if p.exists() and not prepare_sensitive_key(p, required=required):
            return cls.generate()
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
        from angerona.core.hardening import secure_sensitive_file
        secure_sensitive_file(p, required=required)
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

    def __init__(
        self,
        ring_size: int = 500,
        *,
        priority_ring_size: int | None = None,
    ) -> None:
        self._subs:      List[Subscriber]          = []
        self._ring:      Deque[Event]              = deque(maxlen=ring_size)
        # Security consumers must not lose a HIGH/CRITICAL event merely because
        # a chatty INFO producer filled the general presentation ring between
        # polls.  Keep a separately revisioned, still-bounded priority lane.
        # Entries also retain their global revision so ``recent_since`` can
        # recover priority evidence from a general-ring overflow transparently.
        if priority_ring_size is None:
            priority_ring_size = max(64, int(ring_size))
        self._priority_ring: Deque[tuple[int, int, Event]] = deque(
            maxlen=max(1, int(priority_ring_size))
        )
        self._lock:      threading.RLock           = threading.RLock()
        self._authority: Optional[BusAuthority]    = None   # G3-A
        # Monotonic in-process change token for polling consumers. Reading an
        # integer is much cheaper than repeatedly copying and scanning the ring
        # merely to discover that no event arrived since the previous cycle.
        self._revision: int = 0
        self._priority_revision: int = 0
        self._subscriber_stats: dict[int, dict[str, object]] = {}

    # G3-A: wire in the signing authority
    def arm(self, authority: BusAuthority) -> None:
        """Call once at startup to enable HMAC signing on all published events."""
        self._authority = authority

    def verify(self, event: Event) -> bool:
        """True if event carries a valid HMAC signature (requires arm() first)."""
        if self._authority is None:
            return True   # unarmed bus — all events pass
        return self._authority.verify(event)

    @property
    def integrity_enabled(self) -> bool:
        """Whether newly published events are HMAC authenticated."""
        return self._authority is not None

    def subscribe(self, fn: Subscriber, *, delivery_budget_ms: float = 25.0) -> None:
        """Register one deterministic, bounded inline callback.

        Callbacks execute in publication order. They must only update bounded
        memory or enqueue work; filesystem, network and database operations
        belong on a worker. Per-callback latency/failure counters make contract
        violations observable through :meth:`subscriber_metrics`.
        """
        try:
            budget = float(delivery_budget_ms)
        except (TypeError, ValueError) as exc:
            raise ValueError("delivery_budget_ms must be numeric") from exc
        if not 0.1 <= budget <= 60_000:
            raise ValueError("delivery_budget_ms must be between 0.1 and 60000")
        with self._lock:
            # Several modules subscribe from run(), so an operator stop/start or
            # Eco pause/resume used to append the same bound method repeatedly.
            # Every later event was then delivered N times, multiplying CPU and
            # state updates for the rest of the process lifetime.
            if fn not in self._subs:
                self._subs.append(fn)
                owner = getattr(fn, "__self__", None)
                owner_name = type(owner).__name__ if owner is not None else ""
                callback_name = getattr(fn, "__qualname__", getattr(fn, "__name__", "subscriber"))
                name = f"{owner_name}.{callback_name}" if owner_name else callback_name
                self._subscriber_stats[id(fn)] = {
                    "name": str(name)[:200],
                    "delivery_budget_ms": budget,
                    "deliveries": 0,
                    "failures": 0,
                    "budget_violations": 0,
                    "last_delivery_ms": 0.0,
                    "max_delivery_ms": 0.0,
                    "total_delivery_ms": 0.0,
                }

    def publish(self, event: Event) -> None:
        # G3-A: sign the event if an authority is registered
        if self._authority is not None:
            sig   = self._authority.sign(event)
            event = dataclasses.replace(event, hmac_sig=sig)

        # deque(maxlen=...) is the backpressure: it evicts old history while
        # every new event still reaches subscribers and persistent storage.
        with self._lock:
            self._ring.append(event)
            self._revision += 1
            if event.severity >= Severity.HIGH:
                self._priority_revision += 1
                self._priority_ring.append(
                    (self._revision, self._priority_revision, event)
                )
            subs = list(self._subs)

        # Notify outside the lock so callbacks cannot hold up ring readers or
        # other publishers waiting on the mutex. Delivery is intentionally
        # inline for deterministic response ordering, so every callback must be
        # an O(1), bounded memory/queue handoff; storage and other I/O use their
        # dedicated workers in both GUI and headless service graphs.
        for fn in subs:
            started = time.perf_counter()
            failed = False
            try:
                fn(event)
            except Exception:
                # A misbehaving subscriber must never crash the producer.
                failed = True
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            with self._lock:
                stats = self._subscriber_stats.get(id(fn))
                if stats is None:
                    continue
                stats["deliveries"] = int(stats["deliveries"]) + 1
                stats["failures"] = int(stats["failures"]) + int(failed)
                stats["last_delivery_ms"] = elapsed_ms
                stats["max_delivery_ms"] = max(float(stats["max_delivery_ms"]), elapsed_ms)
                stats["total_delivery_ms"] = float(stats["total_delivery_ms"]) + elapsed_ms
                if elapsed_ms > float(stats["delivery_budget_ms"]):
                    stats["budget_violations"] = int(stats["budget_violations"]) + 1

    def subscriber_metrics(self) -> tuple[SubscriberMetrics, ...]:
        """Return bounded inline-delivery SLO evidence for diagnostics/UI."""
        with self._lock:
            rows = [SubscriberMetrics(**dict(row)) for row in self._subscriber_stats.values()]
        return tuple(sorted(rows, key=lambda row: row.name.casefold()))

    def recent(self, limit: int = 100) -> List[Event]:
        with self._lock:
            if limit > 0:
                # Copy only what the caller requested. The old implementation
                # copied the whole ring on every poll and then sliced it.
                return list(islice(reversed(self._ring), limit))
            # Retain the historical zero/negative-limit semantics exactly.
            items = list(self._ring)
        return items[-limit:][::-1]  # newest first

    def revision(self) -> int:
        """Return a monotonic token that changes after every publication.

        The token is process-local and intentionally carries no security
        meaning. It is only a low-cost change detector; authoritative event
        content still comes from :meth:`recent` and retains the existing HMAC
        verification contract.
        """
        with self._lock:
            return self._revision

    def priority_revision(self) -> int:
        """Return the HIGH/CRITICAL lane's monotonic change token.

        INFO/LOW/MEDIUM publications intentionally do not advance this token,
        allowing incident consumers to sleep through telemetry noise without
        weakening their view of serious evidence.
        """
        with self._lock:
            return self._priority_revision

    def priority_since(self, revision: int) -> tuple[int, List[Event], bool]:
        """Atomically return HIGH/CRITICAL events after a priority revision.

        Results are newest-first. ``overflow`` means the requested priority
        delta exceeded this lane's own bounded capacity.  An overflow is a
        health/verification signal only; callers must never infer permission
        for a destructive response without a retained, verified event.
        """
        current, records, overflow = self.priority_records_since(revision)
        return current, [event for _item_revision, event in records], overflow

    def priority_records_since(
        self, revision: int
    ) -> tuple[int, List[tuple[int, Event]], bool]:
        """Return priority events with their exact per-lane commit revisions.

        Consumers which perform response work can advance only after each
        terminal disposition instead of acknowledging a whole batch up front.
        Results are newest-first, matching :meth:`priority_since`.
        """
        try:
            previous = int(revision)
        except (TypeError, ValueError):
            previous = -1
        with self._lock:
            current = self._priority_revision
            if previous == current:
                return current, [], False
            if previous < 0 or previous > current:
                return (
                    current,
                    [
                        (priority_revision, event)
                        for _global_revision, priority_revision, event
                        in reversed(self._priority_ring)
                    ],
                    True,
                )
            delta = current - previous
            retained = len(self._priority_ring)
            count = min(delta, retained)
            records = [
                (entry[1], entry[2])
                for entry in islice(reversed(self._priority_ring), count)
            ]
            return current, records, delta > retained

    def recent_since(self, revision: int) -> tuple[int, List[Event], bool]:
        """Atomically return events published after ``revision``.

        Results follow :meth:`recent` ordering (newest first). ``overflow`` is
        true when the requested delta exceeded the bounded ring, which tells a
        polling consumer that only the still-retained suffix is available.
        This prevents bursty INFO telemetry from hiding a security event simply
        because a UI poller guessed too small a fixed recent-event limit.
        """
        current, records, overflow = self.records_since(revision)
        return current, [event for _item_revision, event in records], overflow

    def records_since(
        self, revision: int
    ) -> tuple[int, List[tuple[int, Event]], bool]:
        """Return general events with exact global commit revisions."""
        try:
            previous = int(revision)
        except (TypeError, ValueError):
            previous = -1
        with self._lock:
            current = self._revision
            if previous == current:
                return current, [], False
            if previous < 0 or previous > current:
                events_by_revision = {
                    current - offset: event
                    for offset, event in enumerate(reversed(self._ring))
                }
                for global_revision, _priority_revision, event in self._priority_ring:
                    events_by_revision.setdefault(global_revision, event)
                records = [
                    (key, events_by_revision[key])
                    for key in sorted(events_by_revision, reverse=True)
                ]
                return current, records, True
            delta = current - previous
            retained = len(self._ring)
            count = min(delta, retained)
            records = [
                (current - offset, event)
                for offset, event in enumerate(
                    islice(reversed(self._ring), count)
                )
            ]
            overflow = delta > retained
            if not overflow:
                return current, records, False

            events_by_revision = {
                current - offset: event
                for offset, event in enumerate(reversed(self._ring))
                if current - offset > previous
            }
            for global_revision, _priority_revision, event in self._priority_ring:
                if global_revision > previous:
                    events_by_revision.setdefault(global_revision, event)
            records = [
                (key, events_by_revision[key])
                for key in sorted(events_by_revision, reverse=True)
            ]
            return current, records, True
