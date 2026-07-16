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
import time
import uuid

from angerona.core.eventbus import Event
from angerona.core.jitter import jittered
from angerona.core.module_base import BaseModule, Severity
from angerona.core.telemetry_contracts import (
    ExpectationContract,
    TelemetryExpectationEngine,
    self_test as contract_engine_self_test,
)
from angerona.core.win import popen_hidden

# ── tunables ──────────────────────────────────────────────────────────────────
DRILL_INTERVAL_S: float = 60.0   # how often to fire a canary
CANARY_TIMEOUT_S: float = 6.0    # window to receive the echo
MAX_CONSECUTIVE_MISSES: int = 2  # misses before CRITICAL
_CANARY_PREFIX = "DRILLCANARY_"
_CANARY_TAG_LEN = len(_CANARY_PREFIX) + 16
_PROCESS_ECHO = "sensor.process_create"
_PROCESS_CONTRACT = ExpectationContract(
    "benign_process_creation_echo",
    (_PROCESS_ECHO,),
    CANARY_TIMEOUT_S,
)
_TRUSTED_PROCESS_SENSORS: frozenset[str] = frozenset({
    "ETW Core Listener",
    "ETWG",
    "ETWG-sim",
    # Sysmon EID 1 always carries the full command line and the new-process PID,
    # so it catches the canary even when Windows 4688 command-line auditing is
    # off — the common reason DRILL never saw an echo and cried "blinding".
    "Sysmon Event Bridge",
    # The out-of-process psutil snapshot-diff scanner, bridged onto the bus by
    # the Resilience Manager as "Telemetry Scanner". On hosts with no elevation /
    # no Sysmon / no ETW, this is the ONLY process-creation sensor that actually
    # works — so DRILL must trust it or the echo path can never be verified and
    # DRILL cries "blinding" forever. It's a first-party Angerona component
    # (same trust tier as ETWG). Note: it validates the *polling* path, not ETW,
    # which is honest — if ETW is blinded but psutil still sees processes, that's
    # exactly what this reports.
    "Telemetry Scanner",
})
# Process-creation event IDs we accept from a trusted sensor: 4688 (Windows
# Security channel) and 1 (Sysmon process-create).
_PROCESS_ECHO_EIDS: frozenset[int] = frozenset({4688, 1})

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
    version = "1.1.0"
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        self._expectations = TelemetryExpectationEngine(max_pending=8)
        self._echo_queue: queue.Queue[tuple[str, float]] = queue.Queue()
        self._consecutive_misses = 0
        self._drills_fired = 0
        self._drills_caught = 0
        self._subscribed = False
        # canary process pid → tag, so an echo can be matched on PID even when
        # the 4688 event carries no command line (default Windows auditing, or
        # ETWG in psutil-fallback mode) and the tag is therefore invisible.
        self._pending_pids: dict[int, str] = {}
        # Have we EVER caught a canary this session? If not, misses mean the echo
        # path was never wired (no elevation / auditing off) — a config problem,
        # NOT adversary blinding. Gates the CRITICAL escalation below.
        self._ever_caught = False
        self._config_warned = False
        # G2 sensor coverage tracking: module name → last observed bus timestamp
        self._sensor_last_seen: dict[str, float] = {}
        self._coverage_alerted: set[str] = set()   # dedup: one alert per silence episode
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
        """Map a trusted ETWG 4688 event to the contract's named echo.

        The module's own ``DRILL canary fired`` event also contains the tag.
        Requiring both the ETWG source identity and EID 4688 prevents that
        announcement (or another module quoting the tag) from satisfying the
        telemetry contract.
        """
        if event.module not in _TRUSTED_PROCESS_SENSORS:
            return
        details = event.details or {}
        # Accept the echo if it's a process-creation record. Windows/Sysmon paths
        # carry an EID (4688 / 1); the psutil snapshot-diff scanner carries no EID
        # but tags the record type="process_creation" — that record still proves
        # a new process was observed, and it's PID-correlated below, so honour it.
        try:
            eid_ok = int(details.get("eid", 0)) in _PROCESS_ECHO_EIDS
        except (TypeError, ValueError):
            eid_ok = False
        type_ok = str(details.get("type") or details.get("event_type") or "") == "process_creation"
        if not (eid_ok or type_ok):
            return

        def tag_in(value: object) -> str | None:
            if not isinstance(value, str):
                return None
            start = value.find(_CANARY_PREFIX)
            if start < 0:
                return None
            candidate = value[start:start + _CANARY_TAG_LEN]
            suffix = candidate[len(_CANARY_PREFIX):]
            if (
                len(candidate) == _CANARY_TAG_LEN
                and all(ch in "0123456789ABCDEF" for ch in suffix.upper())
            ):
                return candidate
            return None

        raw = event.details.get("raw", [])
        if not isinstance(raw, (list, tuple)):
            raw = [raw]
        raw = list(raw)
        # Sysmon (and some ETW paths) carry the command line — where our canary
        # tag lives — in a structured field rather than in `raw`.
        for key in ("command_line", "cmdline", "CommandLine"):
            val = event.details.get(key)
            if isinstance(val, str):
                raw.append(val)
        tag = next(
            (found for part in raw if (found := tag_in(part)) is not None),
            None,
        )
        if tag is None:
            tag = tag_in(event.message or "")
        # Fallback: correlate on the canary's PID. A missing command line (4688
        # auditing off, or ETWG psutil-fallback which emits no cmdline at all)
        # means the tag is absent — but the new-process id still identifies our
        # own canary, so the pipeline is demonstrably NOT blind.
        if tag is None:
            pid = self._event_pid(event)
            if pid is not None:
                tag = self._pending_pids.get(pid)
        if tag:
            self._echo_queue.put((tag, time.monotonic()))

    @staticmethod
    def _event_pid(event: Event) -> int | None:
        """Extract the new-process id from an ETWG event (decimal ``pid`` from the
        psutil fallback, or ``pid_hex`` like ``0x1a2b`` from the Security channel)."""
        p = event.details.get("pid")
        if isinstance(p, int):
            return p
        if isinstance(p, str) and p.isdigit():
            return int(p)
        ph = event.details.get("pid_hex")
        if isinstance(ph, str) and ph.lower().startswith("0x"):
            try:
                return int(ph, 16)
            except ValueError:
                return None
        return None

    def _forget_tag(self, tag: str) -> None:
        """Drop any pending PID→tag mapping once a canary is resolved."""
        for pid in [p for p, t in self._pending_pids.items() if t == tag]:
            self._pending_pids.pop(pid, None)

    # ── canary fire ──────────────────────────────────────────────────────────
    def _fire_canary(self) -> str:
        """Spawn a benign process tagged with a unique canary ID."""
        tag = _CANARY_PREFIX + uuid.uuid4().hex[:16].upper()
        if not self._expectations.arm(tag, _PROCESS_CONTRACT, now=time.monotonic()):
            raise RuntimeError("telemetry expectation capacity exhausted")

        if os.name == "nt":
            # The tag appears in the 4688/Sysmon CommandLine StringInsert that ETW
            # reads (when command-line auditing is on); we also record the pid so
            # the echo can be matched by PID when the command line is unavailable.
            #
            # It must LINGER ~2s: the only sensor on an un-elevated host is the
            # 1 Hz psutil snapshot-diff scanner, which compares process sets each
            # poll. A fire-and-exit `REM` (sub-millisecond) never appears in any
            # snapshot, so the canary was structurally invisible — the real reason
            # the echo path never verified. `ping -n 3` keeps cmd.exe alive ~2s so
            # at least one poll snapshots it (well within the 6s echo window).
            cmd = ["cmd", "/c", f"REM {tag} & ping -n 3 127.0.0.1 >nul"]
            proc = popen_hidden(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if proc is not None and getattr(proc, "pid", None):
                if len(self._pending_pids) > 64:      # belt-and-suspenders bound
                    self._pending_pids.clear()
                self._pending_pids[proc.pid] = tag
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
    def _collect_echoes(self) -> list[str]:
        """Drain trusted echoes and return any contracts completed too late."""
        missed: list[str] = []
        while True:
            try:
                tag, observed_at = self._echo_queue.get_nowait()
            except queue.Empty:
                break
            outcome = self._expectations.observe(
                tag,
                _PROCESS_ECHO,
                now=observed_at,
            )
            if outcome is None:
                continue
            if outcome.status == "satisfied":
                self._drills_caught += 1
                self._consecutive_misses = 0
                # The echo path is proven live: real blinding (misses AFTER a
                # catch) can now legitimately escalate to CRITICAL again.
                self._ever_caught = True
                self._config_warned = False
                self._forget_tag(outcome.probe_id)
            else:
                missed.append(outcome.probe_id)
                self._forget_tag(outcome.probe_id)
        return missed

    def _expire_pending(self) -> list[str]:
        """Return tags whose deadline has passed (missed canaries)."""
        return [
            outcome.probe_id
            for outcome in self._expectations.expire(now=time.monotonic())
        ]

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
                    self._coverage_alerted.discard(ev.module)   # spoke again → re-arm

        # Flag ONLY a sensor that was ACTIVE before and then went silent — a real
        # stall. A never-seen module is almost always intentionally disabled or
        # Eco-paused (no activity to report), NOT stalled — flagging those produced
        # a MEDIUM alert storm in Eco Mode. Alert once per silence episode (dedup).
        silence_cutoff = now_wall - _SENSOR_SILENCE_WINDOW_S
        for module_name in _G2_SENSOR_MODULES:
            last = self._sensor_last_seen.get(module_name, 0.0)
            if last > 0.0 and last < silence_cutoff and module_name not in self._coverage_alerted:
                self._coverage_alerted.add(module_name)
                self.emit(
                    f"[DRILL/COVERAGE] Sensor '{module_name}' went silent for "
                    f"≥{int(now_wall - last)}s after being active — may have stalled.",
                    Severity.MEDIUM,
                    silent_module=module_name,
                    last_seen_ts=last,
                    silence_threshold_s=_SENSOR_SILENCE_WINDOW_S,
                )

        self._next_coverage_check = now_mono + _SENSOR_COVERAGE_INTERVAL_S

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        if self._bus is not None and not self._subscribed:
            self._bus.subscribe(self._on_event)
            self._subscribed = True
        self.emit("DRILL online — telemetry canary drills active.", Severity.INFO,
                  interval_s=DRILL_INTERVAL_S, timeout_s=CANARY_TIMEOUT_S)

        next_drill = time.monotonic() + 5.0  # first drill after 5s warm-up

        while not self.stopping:
            now = time.monotonic()

            # Collect any echoes that arrived
            late_misses = self._collect_echoes()

            # Check for expired (missed) canaries
            for tag in late_misses + self._expire_pending():
                self._consecutive_misses += 1
                self._forget_tag(tag)
                # A miss is only credible evidence of *blinding* once the echo
                # path has been proven to work at least once. Before that, a miss
                # just means the pipeline was never wired — report it as LOW noise,
                # not a HIGH "possible telemetry blinding" that inflates the threat
                # level on every host without process-creation auditing.
                self.emit(
                    f"⚠️ DRILL MISS: canary {tag} not echoed within "
                    f"{CANARY_TIMEOUT_S:.0f}s"
                    + (" — possible telemetry blinding." if self._ever_caught
                       else " (echo path not yet verified this session)."),
                    Severity.HIGH if self._ever_caught else Severity.LOW,
                    canary_tag=tag,
                    consecutive_misses=self._consecutive_misses,
                    echo_path_verified=self._ever_caught,
                )
                if self._consecutive_misses >= MAX_CONSECUTIVE_MISSES:
                    if self._ever_caught:
                        # Path worked earlier and has now gone dark → real signal.
                        self.emit(
                            f"\U0001f6a8 TELEMETRY BLINDING DETECTED — "
                            f"{self._consecutive_misses} consecutive canaries missed.  "
                            "EtwEventWrite hooking or Security channel suppression suspected.",
                            Severity.CRITICAL,
                            consecutive_misses=self._consecutive_misses,
                            mitigation="Check APID for ntdll hooks; inspect audit policy.",
                        )
                        self.set_health(10, "telemetry blinding suspected")
                    elif not self._config_warned:
                        # Never once caught a canary → misconfiguration, not attack.
                        # Warn ONCE, hold a degraded (not critical) health, and
                        # suppress the blinding CRITICAL until the path is verified.
                        self._config_warned = True
                        self.emit(
                            "DRILL cannot confirm the telemetry echo path — no canary "
                            "has ever been observed on the EventBus. This almost always "
                            "means process-creation auditing is unavailable (run elevated / "
                            "enable Audit Process Creation, or ensure ETWG isn't stuck in "
                            "psutil-fallback) rather than active blinding. Blinding alerts "
                            "are suppressed until one canary is confirmed.",
                            Severity.MEDIUM,
                            consecutive_misses=self._consecutive_misses,
                            remediation="Enable 4688 process-creation auditing or run Angerona elevated.",
                        )
                        self.set_health(40, "telemetry echo path unverified")

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
                if self._ever_caught:
                    self.set_health(
                        max(10, 100 - self._consecutive_misses * 30),
                        f"{self._consecutive_misses} miss(es)",
                    )
                else:
                    # Path never verified: degraded, not critical — the misses
                    # are a config gap, not confirmed blinding.
                    self.set_health(40, "telemetry echo path unverified")

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

            self.sleep(1.0)

    def self_test(self) -> tuple[bool, str]:
        """Verify contracts and reject self/untrusted echoes before ETWG smoke-test."""
        from angerona.core.eventbus import Event as _Ev

        tag = _CANARY_PREFIX + "ABCDEF0123456789"
        self_event = _Ev(
            ts=time.time(),
            module=self.name,
            severity=Severity.INFO,
            message=f"DRILL canary fired: {tag}",
            details={"canary_tag": tag},
        )
        self._on_event(self_event)
        self_echo_rejected = self._echo_queue.empty()

        fake_event = _Ev(
            ts=time.time(),
            module="ETWG",
            severity=Severity.INFO,
            message=f"Process created: cmd.exe {tag}",
            details={"eid": 4688, "raw": [tag], "source": "self_test"},
        )
        self._on_event(fake_event)
        try:
            received, _observed_at = self._echo_queue.get(timeout=1.0)
            echo_ok = received == tag
        except queue.Empty:
            echo_ok = False
        contracts_ok, contracts_detail = contract_engine_self_test()
        ok = self_echo_rejected and echo_ok and contracts_ok
        detail = (
            "strict ETWG echo + bounded telemetry contract controls passed"
            if ok else
            f"failed: reject_self={self_echo_rejected} echo={echo_ok} contracts={contracts_detail}"
        )
        return ok, detail


def register() -> CanaryDrillModule:
    return CanaryDrillModule()
