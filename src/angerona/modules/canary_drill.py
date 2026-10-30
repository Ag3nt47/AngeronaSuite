"""canary_drill.py — Telemetry Canary Drill Engine (Code: DRILL).

Purpose
    Validate canary coverage and report availability failures with unconfirmed cause.

    An adversary that patches ``ntdll!EtwEventWrite`` (or blocks the Windows
    Security event channel) can blind the ETWG module so that process-creation
    events stop flowing to the EventBus — Angerona keeps running but sees nothing.

    DRILL checks the echo path with **synthetic canary probes** at a configurable
    interval:

    1. Launch one isolated benign interpreter with an opaque command-line nonce,
       retained native identity and private Job custody; let it sleep two seconds.
    2. Subscribe to the EventBus and wait up to ``CANARY_TIMEOUT_S`` seconds for
       an ETWG 4688 event whose details contain the canary tag.
    3. If the canary arrives → pipeline is healthy; reset the miss counter.
    4. A missing echo is a coverage failure. Repeated misses on a previously
       verified path remain CRITICAL availability evidence; they do not prove
       ETW hooking, channel suppression or an active attack.

    DRILL also validates the FlightRecorder write path by verifying that the
    canary event (once confirmed) was persisted to the SQLite ledger.

Drop-in contract
    BaseModule subclass + CODE/NAME/state/health_pct/self_test + register().

Safety
    Canary subprocess executes only a fixed two-second sleep; no shell or payload.
    The tag is a UUID prefix so DRILL never misidentifies a legitimate event.
    No external network calls; no file writes outside the flight recorder.
"""
from __future__ import annotations

import os
import math
import queue
import re
import time
import uuid

from angerona.core.eventbus import Event
from angerona.core.jitter import jittered
from angerona.core.module_base import BaseModule, Severity
from angerona.core.kernel_telemetry_probe import (
    KernelEcho, KernelIdentityCandidate, KernelProbeTracker, OwnedCanaryProcess, PROVIDERS, ProviderReceipt,
)
from angerona.core.telemetry_contracts import (
    ExpectationContract,
    TelemetryExpectationEngine,
    self_test as contract_engine_self_test,
)

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
    "ETW Real-Time Process Sensor",
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
_ECHO_QUEUE_LIMIT: int = 64


class CanaryDrillModule(BaseModule):
    CODE = "DRILL"
    NAME = "Telemetry Canary Drills"

    name = "Telemetry Canary Drills"
    description = (
        "Fires synthetic benign canary subprocesses at regular intervals and "
        "listens for the corresponding ETWG 4688 echo on the EventBus.  A missed "
        "canary reports an availability gap with unconfirmed cause; repeated "
        "misses on a previously verified path retain CRITICAL priority."
    )
    category = "Resilience"
    version = "1.14.0"
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        self._expectations = TelemetryExpectationEngine(max_pending=8)
        self._echo_queue: queue.Queue[tuple[str, float, float, str]] = queue.Queue(
            maxsize=_ECHO_QUEUE_LIMIT
        )
        self._echo_queue_dropped = 0
        self._consecutive_misses = 0
        self._drills_fired = 0
        self._drills_caught = 0
        self._sensor_echoes = 0
        self._durable_misses = 0
        self._pending_durable: dict[str, tuple[float, float, str]] = {}
        self._recorder = None
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
        # Last time ANY trusted process-creation event was seen on the bus. Lets us
        # separate real blinding from our own telemetry source (scanner) being down.
        self._last_trusted_event = 0.0
        # G2 sensor coverage tracking: module name → last observed bus timestamp
        self._sensor_last_seen: dict[str, float] = {}
        self._coverage_alerted: set[str] = set()   # dedup: one alert per silence episode
        self._next_coverage_check: float = time.monotonic() + _SENSOR_WARMUP_S
        self._start_time: float = time.monotonic()
        self._manager = None
        self._kernel_tracker = KernelProbeTracker()
        self._kernel_echo_queue: queue.Queue[KernelEcho | KernelIdentityCandidate] = queue.Queue(maxsize=64)
        self._kernel_echo_dropped = 0
        self._native_receipt_cache: dict[str, ProviderReceipt] = {}
        self._owned_probes: dict[str, tuple[OwnedCanaryProcess, float]] = {}
        self._probe_retirement = ()
        self._generic_pending_tags: set[str] = set()
        self._generic_cancelled = 0
        self._kernel_probes_fired = 0
        self._last_kernel_only: bool | None = None

    def bind_manager(self, manager) -> None:
        self._manager = manager

    def _kernel_only(self) -> bool:
        return getattr(getattr(self._manager, "config", None), "runtime_chill_active", None) is True

    def _sync_loop_mode(self, kernel_only: bool, now: float) -> None:
        if kernel_only == self._last_kernel_only:
            return
        if kernel_only:
            # Cancel only transient expectations. Original events and historical
            # misses remain evidence; an intentionally deferred path is no miss.
            for tag in tuple(self._generic_pending_tags):
                self._expectations.cancel(tag)
                self._pending_durable.pop(tag, None)
                self._forget_tag(tag)
                self._generic_cancelled += 1
            while True:
                try:
                    self._echo_queue.get_nowait()
                except queue.Empty:
                    break
        elif self._last_kernel_only is True:
            # Generic sensors may have been intentionally paused. Start a new
            # coverage warmup instead of attributing their Chill silence.
            self._sensor_last_seen.clear()
            self._coverage_alerted.clear()
            self._next_coverage_check = now + _SENSOR_WARMUP_S
        self._last_kernel_only = kernel_only

    def _wait_control_tick(self) -> None:
        """Bound control checks without scaling the separate probe cadence."""
        self.mark_cycle_complete(interval_seconds=1.0)
        self.generation_stop_event().wait(timeout=1.0)

    def _native_receipts(self) -> tuple[ProviderReceipt, ...]:
        modules = getattr(self._manager, "modules", {})
        now, receipts = time.monotonic(), []
        expected = {"kernel-etw": ("angerona.modules.etw_realtime_sensor", "EtwRealtimeSensorModule"),
                    "sysmon-native": ("angerona.modules.sysmon_listener", "SysmonListenerModule")}
        for provider, name in PROVIDERS.items():
            module = modules.get(name)
            value = None
            if module is not None and (type(module).__module__, type(module).__name__) == expected[provider]:
                try:
                    value = module.collection_snapshot()  # Existing worker's cached result only.
                except Exception:
                    pass
            receipts.append(ProviderReceipt.from_snapshot(provider, value, now=now))
        result = tuple(receipts)
        self._native_receipt_cache = {receipt.provider: receipt for receipt in result}
        self._kernel_tracker.refresh_receipts(result)
        return result

    def kernel_coverage_snapshot(self) -> dict:
        return dict(scope="Per-provider nonce echo and authenticated persistence; no general kernel-integrity proof",
                    providers=tuple(outcome.event_details() for outcome in self._kernel_tracker.snapshot()),
                    cached_collectors=tuple(dict(provider=row.provider, generation=row.generation,
                                                 available=row.available, sampled_monotonic=row.sampled_monotonic,
                                                 reason=row.reason) for row in self._native_receipt_cache.values()),
                    generic_process_loop_caught=self._drills_caught,
                    generic_scope="May be satisfied by polling; never establishes a native kernel path",
                    mode="kernel-only" if self._kernel_only() else "full-generic-and-kernel",
                    generic_coverage="deferred in Chill" if self._kernel_only() else "enabled",
                    generic_attempts_cancelled=self._generic_cancelled,
                    kernel_probe_children_launched=self._kernel_probes_fired,
                    ingress_dropped=self._kernel_echo_dropped, retained_probe_children=len(self._owned_probes),
                    latest_probe_retirements=self._probe_retirement, response_authorized=False)

    def _capture_kernel_echo(self, event: Event) -> None:
        details = event.details if type(getattr(event, "details", None)) is dict else {}
        provider = None
        if (event.module == PROVIDERS["kernel-etw"] and details.get("source") == "ETW:Kernel-Process"
                and details.get("event_type") == "process_creation"):
            provider = "kernel-etw"
        elif (event.module == PROVIDERS["sysmon-native"] and details.get("sensor_source") == "sysmon-native"
              and type(details.get("eid")) is int and details["eid"] == 1):
            provider = "sysmon-native"
        if provider is None or self._bus is None or self.stopping:
            return
        receipt = self._native_receipt_cache.get(provider)
        generation, now = details.get("collection_generation"), time.monotonic()
        if (receipt is None or not receipt.available or generation != receipt.generation
                or not 0 <= now - receipt.sampled_monotonic <= 15):
            return
        values = (details.get("command_line"), details.get("cmdline"), details.get("CommandLine"))
        tag = None
        for value in values:
            if type(value) is str and len(value) <= 8192:
                match = re.search(r"(?<![A-Za-z0-9_])DRILLCANARY_[0-9A-F]{16}(?![A-Za-z0-9_])", value)
                if match:
                    tag = match.group()
                    break
        pid, stamp, signature = self._event_pid(event), getattr(event, "ts", None), getattr(event, "hmac_sig", None)
        birth = details.get("process_birth_ticks")
        exact_birth = (provider == "kernel-etw" and type(birth) is str and 1 <= len(birth) <= 20
                       and birth.isascii() and birth.isdecimal() and birth == str(int(birth))
                       and 116444736000000000 < int(birth) <= 0xFFFFFFFFFFFFFFFF)
        if ((tag is None and not exact_birth) or pid is None or type(stamp) not in (int, float)
                or not 0 < stamp <= 253402300799 or not math.isfinite(stamp)
                or type(signature) is not str or not re.fullmatch(r"[0-9a-f]{64}", signature)):
            return
        try:
            mode_before = self._bus.mesh_required
            if not self._bus.integrity_enabled or not self._bus.verify(event):
                return
            live = mode_before is True and self._bus.mesh_required is True
            captured = (KernelEcho(tag, provider, generation, pid, stamp, signature, now, live) if tag is not None else
                        KernelIdentityCandidate(provider, generation, pid, birth, stamp, signature, now, live))
            self._kernel_echo_queue.put_nowait(captured)
        except queue.Full:
            self._kernel_echo_dropped += 1
        except (ValueError, TypeError, AttributeError, OverflowError):
            return

    def _kernel_outcome(self, outcome) -> None:
        if outcome.state == "observed":
            severity = Severity.INFO
        elif outcome.prior_path_observed and outcome.state == "missed":
            severity = Severity.CRITICAL if outcome.consecutive_misses >= MAX_CONSECUTIVE_MISSES else Severity.HIGH
        else:
            severity = Severity.MEDIUM if outcome.prior_path_observed else Severity.LOW
        self.emit(f"Native telemetry loop {outcome.provider}: {outcome.state}; {outcome.reason}.",
                  severity, **outcome.event_details())

    def _check_kernel_echoes(self) -> None:
        while True:
            try:
                echo = self._kernel_echo_queue.get_nowait()
            except queue.Empty:
                break
            if type(echo) is KernelIdentityCandidate:
                match = next(((tag, owner) for tag, (owner, _deadline) in tuple(self._owned_probes.items())
                              if owner.identity.pid == echo.pid and str(owner.identity.birth_ticks) == echo.birth_ticks), None)
                if match is None:
                    continue
                tag, _owner = match
                echo = KernelEcho(tag, echo.provider, echo.generation, echo.pid, echo.event_ts, echo.hmac,
                                  echo.observed_monotonic, echo.live_enrolled_observed, "native-pid-birth")
            self._kernel_tracker.observe(echo)
        recorder = self._recorder
        for echo in self._kernel_tracker.awaiting_durable():
            if recorder is None or not hasattr(recorder, "bounded_events_in_window"):
                continue
            try:
                events, _total = recorder.bounded_events_in_window(echo.event_ts - 0.000001, echo.event_ts + 0.000001, limit=512)
                exact = any(row.hmac_sig == echo.hmac and row.module == PROVIDERS[echo.provider]
                            and (row.details or {}).get("collection_generation") == echo.generation
                            and (row.details or {}).get("_ledger_integrity") != "invalid"
                            and self._bus.integrity_enabled and self._bus.verify_archived(row) for row in events)
            except Exception:
                exact = False
            if exact:
                outcome = self._kernel_tracker.persisted(echo, now=time.monotonic())
                if outcome is not None:
                    self._kernel_outcome(outcome)
        for outcome in self._kernel_tracker.expire(now=time.monotonic()):
            self._kernel_outcome(outcome)

    def _retire_owned_probes(self, *, cancel=False) -> None:
        records = []
        for tag, (probe, deadline) in tuple(self._owned_probes.items()):
            try:
                receipt = probe.retire(cancel=cancel or time.monotonic() >= deadline)
                if receipt is not None:
                    records.append(receipt)
                    self._owned_probes.pop(tag, None)
            except Exception:
                self.last_error = "Owned canary retirement remains unverified"
                # Retain custody and refuse unbounded replacement probes.
        if records:
            self._probe_retirement = tuple(records[-8:])

    def bind_recorder(self, recorder) -> None:
        self._recorder = recorder

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
        self._capture_kernel_echo(event)
        if self.stopping or self._kernel_only() or event.module not in _TRUSTED_PROCESS_SENSORS:
            return
        details = event.details if isinstance(event.details, dict) else {}
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
        # Recent trusted activity distinguishes activity from a silent source.
        # It does not prove that the canary used the same provider or that a
        # missing echo was deliberately suppressed (polling can miss a probe).
        self._last_trusted_event = time.monotonic()

        def tag_in(value: object) -> str | None:
            if not isinstance(value, str):
                return None
            value = value[:8192]
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

        raw = details.get("raw", [])
        if not isinstance(raw, (list, tuple)):
            raw = [raw]
        raw = list(raw[:16])
        # Sysmon (and some ETW paths) carry the command line — where our canary
        # tag lives — in a structured field rather than in `raw`.
        for key in ("command_line", "cmdline", "CommandLine"):
            val = details.get(key)
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
        stamp = getattr(event, "ts", None)
        if (type(stamp) not in (int, float) or not 0 < stamp <= 253402300799 or not math.isfinite(stamp)):
            return
        if tag:
            echo = (
                tag,
                time.monotonic(),
                stamp,
                event.hmac_sig if type(getattr(event, "hmac_sig", None)) is str else "",
            )
            try:
                self._echo_queue.put_nowait(echo)
            except queue.Full:
                try:
                    self._echo_queue.get_nowait()
                except queue.Empty:
                    pass
                self._echo_queue_dropped += 1
                try:
                    self._echo_queue.put_nowait(echo)
                except queue.Full:
                    self._echo_queue_dropped += 1

    @staticmethod
    def _event_pid(event: Event) -> int | None:
        """Extract the new-process id from an ETWG event (decimal ``pid`` from the
        psutil fallback, or ``pid_hex`` like ``0x1a2b`` from the Security channel)."""
        p = event.details.get("pid")
        if type(p) is int and 1 <= p <= 0xFFFFFFFF:
            return p
        if type(p) is str and 1 <= len(p) <= 10 and p.isascii() and p.isdecimal() and 1 <= int(p) <= 0xFFFFFFFF:
            return int(p)
        ph = event.details.get("pid_hex")
        if type(ph) is str and re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", ph):
            try:
                value = int(ph, 16)
                return value if 1 <= value <= 0xFFFFFFFF else None
            except ValueError:
                return None
        return None

    def _forget_tag(self, tag: str) -> None:
        """Drop any pending PID→tag mapping once a canary is resolved."""
        for pid in [p for p, t in self._pending_pids.items() if t == tag]:
            self._pending_pids.pop(pid, None)
        if tag not in self._pending_durable:
            self._generic_pending_tags.discard(tag)

    # ── canary fire ──────────────────────────────────────────────────────────
    def _fire_canary(self, *, kernel_only: bool | None = None) -> str | None:
        """Spawn a benign process tagged with a unique canary ID."""
        if kernel_only is None:
            kernel_only = self._kernel_only()
        tag = _CANARY_PREFIX + uuid.uuid4().hex[:16].upper()
        receipts = self._native_receipts()
        if kernel_only and not any(row.available for row in receipts):
            for outcome in self._kernel_tracker.unavailable(tag, receipts, now=time.monotonic()):
                self._kernel_outcome(outcome)
            return None
        if not kernel_only:
            if not self._expectations.arm(tag, _PROCESS_CONTRACT, now=time.monotonic()):
                raise RuntimeError("telemetry expectation capacity exhausted")
            self._generic_pending_tags.add(tag)

        if os.name == "nt":
            self._retire_owned_probes()
            if len(self._owned_probes) >= 8:
                self._expectations.cancel(tag)
                self._forget_tag(tag)
                raise RuntimeError("Owned canary retirement capacity is held")
            started_wall, started = time.time(), time.monotonic()
            try:
                probe = OwnedCanaryProcess(tag)
            except Exception:
                self._expectations.cancel(tag)
                self._forget_tag(tag)
                raise
            self._owned_probes[tag] = (probe, started + CANARY_TIMEOUT_S)
            self._kernel_probes_fired += 1
            if not kernel_only:
                self._pending_pids[probe.identity.pid] = tag
            for outcome in self._kernel_tracker.arm(
                tag, pid=probe.identity.pid, birth_ticks=str(probe.identity.birth_ticks),
                started_wall=started_wall, now=started, receipts=receipts, timeout=CANARY_TIMEOUT_S,
            ):
                self._kernel_outcome(outcome)
        elif not kernel_only:
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

        if not kernel_only:
            self._drills_fired += 1
        return tag

    # ── result harvesting ────────────────────────────────────────────────────
    def _collect_echoes(self) -> list[str]:
        """Drain trusted echoes and return any contracts completed too late."""
        missed: list[str] = []
        while True:
            try:
                tag, observed_at, event_ts, event_hmac = self._echo_queue.get_nowait()
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
                self._sensor_echoes += 1
                # A bus echo proves the sensor leg only. The drill is not caught
                # until the exact signed Event is readable from FlightRecorder.
                if (
                    self._recorder is not None
                    and len(event_hmac) == 64
                    and event_ts > 0
                ):
                    self._pending_durable[outcome.probe_id] = (
                        event_ts,
                        observed_at + CANARY_TIMEOUT_S,
                        event_hmac,
                    )
                else:
                    self._durable_misses += 1
                self._forget_tag(outcome.probe_id)
            else:
                missed.append(outcome.probe_id)
                self._forget_tag(outcome.probe_id)
        return missed

    def _check_durable_receipts(self) -> list[str]:
        """Promote sensor echoes only after exact authenticated persistence."""
        missed: list[str] = []
        recorder = self._recorder
        now = time.monotonic()
        for tag, (event_ts, deadline, event_hmac) in list(
            self._pending_durable.items()
        ):
            found = False
            if recorder is not None and hasattr(recorder, "bounded_events_in_window"):
                try:
                    events, _total = recorder.bounded_events_in_window(
                        event_ts - 0.000001,
                        event_ts + 0.000001,
                        limit=512,
                    )
                    found = any(
                        getattr(event, "hmac_sig", "") == event_hmac
                        and event.module in _TRUSTED_PROCESS_SENSORS
                        and (event.details or {}).get("_ledger_integrity") != "invalid"
                        for event in events
                    )
                except Exception as exc:
                    self.last_error = str(exc)
            if found:
                self._pending_durable.pop(tag, None)
                self._forget_tag(tag)
                self._drills_caught += 1
                self._consecutive_misses = 0
                self._ever_caught = True
                self._config_warned = False
                self.emit(
                    f"DRILL full pipeline verified for {tag}: sensor echo + signed ledger.",
                    Severity.INFO,
                    canary_tag=tag,
                    sensor_echo=True,
                    recorder_persisted=True,
                )
            elif now >= deadline:
                self._pending_durable.pop(tag, None)
                self._forget_tag(tag)
                self._durable_misses += 1
                missed.append(tag)
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
        try:
            self._run_drills()
        finally:
            self._retire_owned_probes(cancel=True)
            if self._bus is not None and self._subscribed:
                self._bus.unsubscribe(self._on_event)
                self._subscribed = False

    def _run_drills(self) -> None:
        if self._bus is not None and not self._subscribed:
            self._bus.subscribe(self._on_event)
            self._subscribed = True
        self.emit("DRILL online — telemetry canary drills active.", Severity.INFO,
                  interval_s=DRILL_INTERVAL_S, timeout_s=CANARY_TIMEOUT_S)

        next_drill = time.monotonic() + 5.0  # first drill after 5s warm-up

        while not self.stopping:
            now = time.monotonic()
            kernel_only = self._kernel_only()
            self._sync_loop_mode(kernel_only, now)
            receipts = self._native_receipts()
            self._check_kernel_echoes()
            self._retire_owned_probes()

            if kernel_only:
                outcomes = self._kernel_tracker.snapshot()
                observed = sum(row.state == "observed" and any(
                    receipt.provider == row.provider and receipt.generation == row.generation and receipt.available
                    for receipt in receipts) for row in outcomes)
                prior_misses = [row for row in outcomes if row.state == "missed" and row.prior_path_observed]
                health = 10 if any(row.consecutive_misses >= MAX_CONSECUTIVE_MISSES for row in prior_misses) else (
                    40 if prior_misses or not observed else 100 if observed == len(PROVIDERS) else 60)
                self.set_health(health, f"Chill: {observed}/{len(PROVIDERS)} scoped native paths observed; "
                                "generic process/network/file/drill coverage deferred")
                if now >= next_drill:
                    try:
                        tag = self._fire_canary(kernel_only=True)
                        if tag is not None:
                            self.emit(f"DRILL native-path canary fired: {tag}; generic checks deferred in Chill.",
                                      Severity.INFO, canary_tag=tag, kernel_only=True,
                                      generic_coverage="deferred in Chill", disposition="health",
                                      response_authorized=False)
                    except Exception as exc:
                        self.last_error = str(exc)
                        self.emit(f"DRILL native-path canary spawn failed: {exc}", Severity.LOW,
                                  disposition="health", response_authorized=False)
                    next_drill = time.monotonic() + jittered(DRILL_INTERVAL_S)
                self._wait_control_tick()
                continue

            # Collect any echoes that arrived
            late_misses = self._collect_echoes()
            durable_misses = self._check_durable_receipts()
            for tag in durable_misses:
                self.emit(
                    f"DRILL recorder miss: signed sensor echo for {tag} was not "
                    "readable from FlightRecorder before deadline.",
                    Severity.MEDIUM,
                    canary_tag=tag,
                    sensor_echo=True,
                    recorder_persisted=False,
                    durable_misses=self._durable_misses,
                )

            # Check for expired (missed) canaries
            for tag in late_misses + self._expire_pending():
                self._consecutive_misses += 1
                self._forget_tag(tag)
                # Three cases for a miss:
                #   • echo path never verified  → LOW  (config gap, not blinding)
                #   • our telemetry SOURCE is silent (no trusted process events at
                #     all recently → scanner/ETW down, SAFE_MODE, or Eco-paused)
                #                               → MEDIUM operational, NOT blinding
                #   • other events flow but the canary echo is missing
                #                               → HIGH → CRITICAL availability;
                #                                 cause remains unconfirmed
                source_silent = self._ever_caught and (
                    time.monotonic() - self._last_trusted_event) > (CANARY_TIMEOUT_S * 3)
                if not self._ever_caught:
                    miss_msg = " (echo path not yet verified this session)."
                    miss_sev = Severity.LOW
                elif source_silent:
                    miss_msg = " — telemetry source is silent (a sensor may be down or paused)."
                    miss_sev = Severity.MEDIUM
                else:
                    miss_msg = " — canary coverage failure; cause unconfirmed."
                    miss_sev = Severity.HIGH
                self.emit(
                    f"⚠️ DRILL MISS: canary {tag} not echoed within "
                    f"{CANARY_TIMEOUT_S:.0f}s" + miss_msg,
                    miss_sev,
                    canary_tag=tag,
                    consecutive_misses=self._consecutive_misses,
                    echo_path_verified=self._ever_caught,
                    source_silent=source_silent,
                    disposition="health",
                    active_attack=False,
                    active_detection=False,
                    response_authorized=False,
                    cause_unconfirmed=True,
                    coverage_failure=True,
                )
                if self._consecutive_misses >= MAX_CONSECUTIVE_MISSES:
                    if self._ever_caught and not source_silent:
                        # Preserve critical availability priority without
                        # attributing a missing echo to hostile interference.
                        self.emit(
                            f"\U0001f6a8 CANARY COVERAGE FAILURE — "
                            f"{self._consecutive_misses} consecutive canaries missed.  "
                            "Cause unconfirmed; other process activity does not prove "
                            "ETW hooking or channel suppression.",
                            Severity.CRITICAL,
                            consecutive_misses=self._consecutive_misses,
                            canary_tag=tag,
                            echo_path_verified=self._ever_caught,
                            source_silent=source_silent,
                            disposition="health",
                            active_attack=False,
                            active_detection=False,
                            response_authorized=False,
                            cause_unconfirmed=True,
                            coverage_failure=True,
                            mitigation="Check provider coverage, polling cadence and echo delivery.",
                        )
                        self.set_health(10, "canary coverage failure; cause unconfirmed")
                    elif source_silent:
                        # Our OWN telemetry source stopped reporting — operational,
                        # not an attack. Warn once (reuse the throttle) at MEDIUM.
                        if not self._config_warned:
                            self._config_warned = True
                            self.emit(
                                "DRILL: telemetry source appears DOWN — no process-creation "
                                "events from any trusted sensor recently. The Telemetry Scanner "
                                "or ETW sensor is likely in SAFE_MODE, stopped, or Eco-paused. "
                                "This is an operational gap, NOT confirmed adversary blinding; "
                                "canaries resume verifying once it recovers.",
                                Severity.MEDIUM,
                                consecutive_misses=self._consecutive_misses,
                                remediation="Check the Telemetry Scanner is running (console: wd-restart scanner).",
                            )
                            self.set_health(40, "telemetry source down (operational)")
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
            completed_or_pending = self._drills_fired - self._generic_cancelled
            if self._consecutive_misses == 0 and completed_or_pending > 0:
                catch_rate = self._drills_caught / completed_or_pending
                pct = int(catch_rate * 100)
                if self._pending_durable:
                    pct = min(pct, 80)
                if self._durable_misses:
                    pct = min(pct, 60)
                self.set_health(
                    min(100, pct),
                    f"{self._drills_caught}/{completed_or_pending} full pipeline; "
                    f"sensor_echoes={self._sensor_echoes}; "
                    f"recorder_misses={self._durable_misses}; "
                    f"persistence_pending={len(self._pending_durable)}",
                )
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
                    tag = self._fire_canary(kernel_only=False)
                    if tag is not None:
                        self.emit(f"DRILL canary fired: {tag}", Severity.INFO,
                                  canary_tag=tag, drills_fired=self._drills_fired)
                except Exception as exc:
                    self.last_error = str(exc)
                    self.emit(f"DRILL canary spawn failed: {exc}", Severity.LOW)
                # Jittered cadence (anti-TOCTOU): no fixed 60s rhythm to exploit.
                next_drill = time.monotonic() + jittered(DRILL_INTERVAL_S)

            self._wait_control_tick()

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
        if self._kernel_only():
            contracts_ok, contracts_detail = contract_engine_self_test()
            ok = self_echo_rejected and self._echo_queue.empty() and contracts_ok
            return ok, ("Chill kernel-only mode: synthetic generic coverage explicitly deferred; "
                        f"contract controls: {contracts_detail}")
        try:
            received, _observed_at, _event_ts, _event_hmac = self._echo_queue.get(
                timeout=1.0
            )
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
