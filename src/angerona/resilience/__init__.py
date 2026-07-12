"""angerona.resilience — the decoupled multi-process resilience ecosystem.

Turns the watchdog and telemetry scanner into standalone, low-footprint OS
processes that mutually keep each other (and the Angerona core + BlackBox) alive,
while the scanner streams raw telemetry to the core over shared memory for the
core to decipher and act on.

Modules
    heartbeat        Shared-memory (mmap) per-process heartbeat — liveness AND
                     anti-suspension (frozen tick + live pid ⇒ suspended).
    ipc_ring         Bounded shared-memory ring buffer: sensors write raw framed
                     telemetry; the core reads asynchronously (backpressure-safe).
    shutdown_token   HMAC nonce challenge-response so maintenance can stand the
                     whole ecosystem down without triggering mutual respawns.
    supervisor       Detached-process spawn + respawn with exponential backoff and
                     a SAFE_MODE anti-thrash brake; honours the shutdown token.
    diagnostics      Atomic JSON writers (status/thread_dump/tracemalloc/selftest)
                     the read-only BlackBox surfaces without blocking.

Design principles
    * Low footprint: heartbeats/rings are fixed-size mmap; no per-tick allocation.
    * Honest naming: executables/processes use clear names (no stealth/ghosting).
    * The core is the brain: sensors forward RAW data; correlation/action stay in
      the Angerona core + operator-gated SOAR.
"""
from __future__ import annotations

# Canonical component identifiers used across heartbeats, diagnostics, and the ring.
COMPONENT_CORE = "core"
COMPONENT_WATCHDOG = "watchdog"
COMPONENT_SCANNER = "scanner"
COMPONENT_BLACKBOX = "blackbox"

ALL_COMPONENTS = (COMPONENT_CORE, COMPONENT_WATCHDOG, COMPONENT_SCANNER, COMPONENT_BLACKBOX)

__all__ = [
    "COMPONENT_CORE", "COMPONENT_WATCHDOG", "COMPONENT_SCANNER",
    "COMPONENT_BLACKBOX", "ALL_COMPONENTS",
]
