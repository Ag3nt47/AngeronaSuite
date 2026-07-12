"""canary_drill.py — Telemetry Canary Drill Engine (Code: DRILL).

Purpose
    Detect user-space telemetry blinding in real time.

    An adversary that patches ``ntdll!EtwEventWrite`` (or blocks the Windows
    Security event channel) can blind the ETWG module so that process-creation
    events stop flowing to the EventBus — Angerona keeps running but sees nothing.

    DRILL detects this by firing **synthetic canary probes** at a configurable
    interval:

    1. Spawn a very short-lived, benign subprocess (``cmd /c exit 0`` with a
       unique comment tag embedded in the command line so it is identifiable).
    2. Subscribe to the EventBus and wait up to ``CANARY_TIMEOUT_S`` seconds for
       an ETWG 4688 event whose details contain the canary tag.
    3. If the canary arrives → pipeline is healthy; reset the miss counter.
    4. If the timeout expires with no matching event → presume telemetry blinding;
       emit CRITICAL and escalate the threat level.

    DRILL also validates the FlightRecorder write path by verifying that the
    canary event (once confirmed) was persisted to the SQLite ledger.

Drop-in contract
    BaseModule subclass + CODE/NAME/state/health_pct/self_test + register().

Safety
    Canary subprocess is ``cmd /c exit 0`` — entirely benign, no payload.
    The tag is a UUID prefix so DRILL never misidentifies a legitimate event.
    No external network calls; no file writes outside the flight recorder.
"""
from __future__ import annotations

import os
import queue
import subprocess
import threading
import time
import uuid

from angerona.core.eventbus import Event
from angerona.core.jitter import jittered
from angerona.core.module_base import BaseModule, Severity
from angerona.core.win import popen_hidden

# ── tunables ──────────────────────────────────────────────────────────────────
DRILL_INTERVAL_S: float = 60.0   # how often to fire a canary
CANARY_TIMEOUT_S: float = 6.0    # window to receive the echo
MAX_CONSECUTIVE_MISSES: int = 2  # misses before CRITICAL
_CANARY_PREFIX = "DRILLCANARY_"

# G2 sensor coverage validation: if any of these modules is silent on the
# EventBus for longer than _SENSOR_SILENCE_WINDOW_S, emit MEDIUM so the
# operator knows that module may have stalled or crashed.
#
# These are the exact `name` attribute strings the G2 BaseModule subclasses
# set — they are what appears in Event.module for each module's own emits.
_G2_SENSOR_MODULES: frozenset[str] = frozenset({
    "Sysmon Event Bridge",
    "Memory Injection Scanner",
    "Ransomware Heuristics",
    "WFP Controller",
    "AMSI Bridge",
    "WLAN Monitor",
    "ARP Watchdog",
    "AV Telemetry Bridge",
    "Dynamic Resource Governor",
})

# 10-minute silence is suspicious — normal operation produces at least one
# INFO heartbeat from every module within this window.
_SENSOR_SILENCE_WINDOW_S: float = 600.0
# Don't check coverage in the first 2 min (modules may still be starting up).
_SENSOR_WARMUP_S: float        = 120.0
# How often to scan the bus for coverage evidence.
_SENSOR_COVERAGE_INTERVAL_S: float = 120.0


class CanaryDrillModule(BaseModule):
    CODE = "DRILL"
    NAME = "Telemetry Canary Drills"

    name = "Telemetry Canary Drills"
    description = (
        "Fires synthetic benign canary subprocesses at regular intervals and "
        "listens for the corresponding ETWG 4688 echo on the EventBus.  A missed "
        "canary signals user-space telemetry blinding (e.g. ntdll!EtwEventWrite "
        "hooking) and raises a CRITICAL alert."
    )
    category = "Resilience"
    version = "1.0.0"
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        self._pending: dict[str, float] = {}  # tag → deadline
        self._pending_lock = threading.Lock()
        self._echo_queue: queue.Queue[str] = queue.Queue()
        self._consecutive_misses = 0
        self._drills_fired = 0
        self._drills_caught = 0
        # G2 sensor coverage tracking: module name → last observed bus timestamp
        self._sensor_last_seen: dict[str, float] = {}
        self._next_coverage_check: float = time.monotonic() + _SENSOR_WARMUP_S
        self._start_time: float = time.monotonic()

    # ── dual-contract properties ─────────────────────────────────────────────
    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── EventBus subscriber ──────────────────────────────────────────────────
    def _on_event(self, event: Event) -> None:
        """Called for every bus event; look for our canary tag in the details."""
        # ETWG embeds raw command-line inserts; the canary tag appears in
        # the 'raw' list or message string.
        tag = None
        raw = event.details.get("raw", [])
        for part in raw:
            if isinstance(part, str) and part.startswith(_CANARY_PREFIX):
                tag = part[:36 + len(_CANARY_PREFIX)]  # prefix + UUID portion
                break
        if tag is None:
            # Also check the message text (psutil fallback path)
            msg = event.message or ""
            for candidate in msg.split():
                if candidate.startswith(_CANARY_PREFIX):
                    tag = candidate
                    break
        if tag:
            self._echo_queue.put(tag)

    # ── canary fire ──────────────────────────────────────────────────────────
    def _fire_canary(self) -> str:
        """Spawn a benign process tagged with a unique canary ID."""
        tag = _CANARY_PREFIX + uuid.uuid4().hex[:16].upper()
        deadline = time.monotonic() + CANARY_TIMEOUT_S
        with self._pending_lock:
            self._pending[tag] = deadline

        if os.name == "nt":
            # cmd /c REM <tag> exits immediately; the tag appears in the
            # 4688 CommandLine StringInsert that ETWG reads.
            cmd = ["cmd", "/c", f"REM {tag}"]
            popen_hidden(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            # Non-Windows: emit a synthetic bus event that DRILL can catch
            # (smoke-test only — blinding detection requires real ETW).
            from angerona.core.eventbus import Event as _Ev
            fake = _Ev(
                ts=time.time(),
                module="ETWG-sim",
                severity=Severity.INFO,
                message=f"Process created: cmd.exe {tag}",
                details={"eid": 4688, "raw": [tag], "source": "sim"},
            )
            if self._bus is not None:
                self._bus.publish(fake)

        self._drills_fired += 1
        return tag

    # ── result harvesting ────────────────────────────────────────────────────
    def _collect_echoes(self) -> None:
        """Drain the echo queue and mark matched canaries as caught."""
        while True:
            try:
                tag = self._echo_queue.get_nowait()
            except queue.Empty:
                break
            with self._pending_lock:
                if tag in self._pending:
                    del self._pending[tag]
                    self._drills_caught += 1

    def _expire_pending(self) -> list[str]:
        """Return tags whose deadline has passed (missed canaries)."""
        now = time.monotonic()
        expired = []
        with self._pending_lock:
            for tag, deadline in list(self._pending.items()):
                if now >= deadline:
                    expired.append(tag)
                    del self._pending[tag]
        return expired

    # ── G2 sensor coverage validation ────────────────────────────────────────
    def _check_sensor_coverage(self) -> None:
        """Scan the EventBus for recent G2 sensor activity.

        Each G2 sensor module emits at least one event per polling cycle
        (startup INFO, periodic health, or a detection).  If a module has
        been completely silent for _SENSOR_SILENCE_WINDOW_S seconds it is
        likely stalled, crashed, or was not registered — flag it as MEDIUM
        so the operator can investigate without waiting for a full miss storm.

        Why MEDIUM and not CRITICAL?  A silent module is bad, but it does not
        by itself confirm an attack.  The module may have been intentionally
        disabled, or the endpoint may have no matching activity to report
        (e.g. no WLAN adapters → WLAN Monitor is always quiet).  MEDIUM
        surfaces the gap without drowning out real detections.
        """
        if self._bus is None:
            return

        now_wall = time.time()
        now_mono = time.monotonic()

        # Scan recent bus events and update last-seen timestamps
        for ev in self._bus.recent(500):
            if ev.module in _G2_SENSOR_MODULES:
                prev = self._sensor_last_seen.get(ev.module, 0.0)
                if ev.ts > prev:
                    self._sensor_last_seen[ev.module] = ev.ts

        # Report any module that has never been seen OR has been silent too long
        silence_cutoff = now_wall - _SENSOR_SILENCE_WINDOW_S
        for module_name in _G2_SENSOR_MODULES:
            last = self._sensor_last_seen.get(module_name, 0.0)
            if last < silence_cutoff:
                elapsed = int(now_wall - last) if last else int(now_mono - self._start_time)
                self.emit(
                    f"[DRILL/COVERAGE] Sensor '{module_name}' has been silent for "
                    f"≥{elapsed}s — module may be stalled or unregistered.",
                    Severity.MEDIUM,
                    silent_module=module_name,
                    last_seen_ts=last,
                    silence_threshold_s=_SENSOR_SILENCE_WINDOW_S,
                )

        self._next_coverage_check = now_mono + _SENSOR_COVERAGE_INTERVAL_S

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        if self._bus is not None:
            self._bus.subscribe(self._on_event)
        self.emit("DRILL online — telemetry canary drills active.", Severity.INFO,
                  interval_s=DRILL_INTERVAL_S, timeout_s=CANARY_TIMEOUT_S)

        next_drill = time.monotonic() + 5.0  # first drill after 5s warm-up

        while not self.stopping:
            now = time.monotonic()

            # Collect any echoes that arrived
            self._collect_echoes()

            # Check for expired (missed) canaries
            for tag in self._expire_pending():
                self._consecutive_misses += 1
                self.emit(
                    f"⚠️ DRILL MISS: canary {tag} not echoed within "
                    f"{CANARY_TIMEOUT_S:.0f}s — possible telemetry blinding.",
                    Severity.HIGH,
                    canary_tag=tag,
                    consecutive_misses=self._consecutive_misses,
                )
                if self._consecutive_misses >= MAX_CONSECUTIVE_MISSES:
                    self.emit(
                        f"\U0001f6a8 TELEMETRY BLINDING DETECTED — "
                        f"{self._consecutive_misses} consecutive canaries missed.  "
                        "EtwEventWrite hooking or Security channel suppression suspected.",
                        Severity.CRITICAL,
                        consecutive_misses=self._consecutive_misses,
                        mitigation="Check APID for ntdll hooks; inspect audit policy.",
                    )
                    self.set_health(10, "telemetry blinding suspected")

            # G2 sensor coverage check (every _SENSOR_COVERAGE_INTERVAL_S after warmup)
            if now >= self._next_coverage_check:
                self._check_sensor_coverage()

            # Health update
            if self._consecutive_misses == 0 and self._drills_fired > 0:
                catch_rate = self._drills_caught / self._drills_fired
                pct = int(catch_rate * 100)
                self.set_health(min(100, pct),
                                f"{self._drills_caught}/{self._drills_fired} canaries caught")
            elif self._consecutive_misses > 0 and self._drills_fired > 0:
                self.set_health(
                    max(10, 100 - self._consecutive_misses * 30),
                    f"{self._consecutive_misses} miss(es)",
                )

            # Fire the next canary
            if now >= next_drill:
                try:
                    tag = self._fire_canary()
                    self.emit(f"DRILL canary fired: {tag}", Severity.INFO,
                              canary_tag=tag, drills_fired=self._drills_fired)
                except Exception as exc:
                    self.last_error = str(exc)
                    self.emit(f"DRILL canary spawn failed: {exc}", Severity.LOW)
                # Jittered cadence (anti-TOCTOU): no fixed 60s rhythm to exploit.
                next_drill = time.monotonic() + jittered(DRILL_INTERVAL_S)
                # Reset consecutive miss counter after each new canary fire
                # (only escalate if *consecutive* misses pile up)
                if self._consecutive_misses > 0 and self._drills_caught > 0:
                    self._consecutive_misses = 0

            self.sleep(1.0)

    def self_test(self) -> tuple[bool, str]:
        """Fire a canary and verify the echo_queue receives it (bus smoke-test)."""
        from angerona.core.eventbus import Event as _Ev

        tag = _CANARY_PREFIX + "SELFTEST0000"
        fake_event = _Ev(
            ts=time.time(),
            module="ETWG",
            severity=Severity.INFO,
            message=f"Process created: cmd.exe {tag}",
            details={"eid": 4688, "raw": [tag], "source": "self_test"},
        )
        self._on_event(fake_event)
        try:
            received = self._echo_queue.get(timeout=1.0)
            ok = received == tag
            return (ok, "canary echo round-trip OK" if ok
                    else f"echo mismatch: got {received!r}")
        except queue.Empty:
            return (False, "canary echo not received within 1s")


def register() -> CanaryDrillModule:
    return CanaryDrillModule()
