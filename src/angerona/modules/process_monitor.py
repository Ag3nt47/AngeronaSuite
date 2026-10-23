"""Process / parent-lineage monitor.

Watches for newly spawned processes and flags suspicious patterns (e.g. a shell
or script host spawned by an Office app, or execution from a temp/download
path). Ported from Angerona's lineage monitor.
"""
from __future__ import annotations

import os
import math
import threading
import time
from itertools import islice
from typing import Dict, Mapping, Set

from angerona.core.module_base import BaseModule, Severity
from angerona.telemetry.sensors import ProcessSnapshot, process_snapshot

SUSPICIOUS_CHILDREN = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
RISKY_PATH_TOKENS = ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\")
_MAX_PARTIAL_IDENTITIES = 16_384


def _combat_enabled() -> bool:
    return os.environ.get(
        "ANGERONA_ADVERSARY_COMBAT_ENABLED", "0"
    ).strip().lower() in {"1", "true", "yes", "on"}


def _snapshot_max_age() -> float | None:
    """Make the shared process cache fresher than Combat's one-second loop."""
    return 0.5 if _combat_enabled() else None


def _process_identity(process: dict) -> tuple[tuple[int, str, str] | None, bool]:
    try:
        pid = int(process.get("pid"))
    except (TypeError, ValueError):
        return None, False
    if pid <= 0:
        return None, False
    executable = str(process.get("exe") or process.get("name") or "").casefold()
    try:
        birth = float(process.get("create_time"))
    except (TypeError, ValueError):
        birth = float("nan")
    complete = math.isfinite(birth) and birth > 0
    token = f"{birth:.6f}" if complete else f"unknown:{executable}"
    return (pid, token, executable), complete


class ProcessMonitorModule(BaseModule):
    background_pacing_allowed = True
    name = "Process Monitor"
    description = "Flags suspicious process spawns and execution from risky locations."
    category = "Processes"
    version = "1.14.0"
    supported_platforms = ('windows',)
    capability_mode = 'detect'
    maturity_channel = 'preview'
    platform_requirements = ('psutil process PID, birth, executable, command and parent metadata; access-denied rows '
     'remain coverage gaps',
     'Windows executable-name/path rules; other platforms retain their existing unsupported '
     'status',
     'Optional exact Red Team lease issues simulation receipts; no containment authority is '
     'conferred')
    capability_inputs = ('read-only OS PID inventory',
     'shared typed ProcessSnapshot with birth identity, command, parent, account and coverage '
     'metadata',
     'optional exact enrolled-child observation capability',
     'shared Combat-enabled flag changes polling/cache cadence only')
    capability_outputs = ('process_creation EventBus telemetry with PID, PPID, executable, command and creation '
     'time',
     'Office-to-script-host and risky-Windows-path findings',
     'coverage/health/lifecycle state and optional challenge-bound native process-observation '
     'receipt')
    capability_permissions = ('process-metadata-read', 'process-command-line-read', 'event.emit')
    high_risk_permissions = ('process-command-line-read',)
    data_classes = ('process-identity',
     'parent-lineage',
     'executable-path',
     'process-command-line',
     'process-account-name',
     'collection-coverage',
     'simulation-correlation')
    egress = 'none'
    retention = ('OS inventory and name/identity/receipt dedup in memory; up to 16384 absent identities '
     'retained on partial polls; emitted events follow recorder policy')
    response_authority = 'none'
    capability_dependencies = ('psutil', 'shared typed process inventory', 'local EventBus')
    capability_conflicts = ()
    restart_policy = 'bounded-three-attempt-backoff-quarantine'
    loss_behavior = ('partial/denied/stale inventory lowers health; absence is not exit; bounded identity '
     'retention; emitted EventBus telemetry remains best effort')
    resource_budget = {'throttle_min': 1.0,
     'throttle_max': 8.0,
     'startup_cycle_timeout_seconds': 30.0,
     'worker_model': 'single-lifecycle-thread-with-shared-typed-process-inventory',
     'event_delivery': 'local-EventBus-best-effort-with-lifecycle-loss-accounting'}
    settings_schema = {'type': 'object',
     'properties': {},
     'additionalProperties': False,
     'description': 'No module-owned settings. Shared ANGERONA_ADVERSARY_COMBAT_ENABLED '
                    'changes nominal poll interval 3s to1s and cache max age to0.5s; global '
                    'sensor cache policy remains external.'}

    def __init__(self) -> None:
        super().__init__()
        self._seen: Set[tuple[int, str, str]] = set()
        self._names: Dict[int, str] = {}
        self._identity_gaps = 0
        self._redteam_receipt_capability: object | None = None
        self._redteam_receipt_lock = threading.RLock()
        self._redteam_receipted: Set[tuple[int, str, str]] = set()
        self._initial_pid_baseline: set[int] | None = None
        self._last_coverage: dict[str, object] = {}
        # One local read-only request may wait behind the single active scan.
        # These tuples schedule/acknowledge work; they are not trust receipts.
        self._observation_request_lock = threading.Lock()
        self._observation_request_event = threading.Event()
        self._pending_observation_request: tuple[int, int] | None = None
        self._completed_observation_request: tuple[int, int] | None = None
        self._observation_request_serial = 0
        # Scheduling credit only: each actually refused token may omit one
        # discretionary background delay, never the throttle/Chill floor.
        # Retaining the offered token after consumption prevents rearming it
        # on persistent refusal or coalesced requests. Diagnostics are not an
        # input to this state and the credit grants no observation proof.
        self._observation_retry_offered: tuple[int, int] | None = None
        self._observation_retry_credit: tuple[int, int] | None = None
        self._observe_fresh_diagnostic("initialize")

    def request_fresh_observation(
        self, *, expected_generation: int,
    ) -> tuple[int, int] | None:
        """Coalesce a bounded local work hint; grant no detection/response proof."""
        if type(expected_generation) is not int or expected_generation <= 0:
            return None
        with self._lifecycle_lock:
            thread = self._thread
            if (
                expected_generation != self._lifecycle_generation
                or self.status != "running" or self._stop.is_set()
                or thread is None or not thread.is_alive()
            ):
                return None
            with self._observation_request_lock:
                pending = self._pending_observation_request
                diagnostic_new_request = False
                if pending is None or pending[0] != expected_generation:
                    self._observation_request_serial += 1
                    pending = (expected_generation, self._observation_request_serial)
                    self._pending_observation_request = pending
                    self._observation_retry_offered = None
                    self._observation_retry_credit = None
                    diagnostic_new_request = True
                self._observation_request_event.set()
                if diagnostic_new_request:
                    self._observe_fresh_diagnostic("queued", request=pending,
                                                   generation=expected_generation, _lock_held=True)
                return pending

    def fresh_observation_complete(self, request: tuple[int, int]) -> bool:
        """Report only actual requested work in the same still-live generation."""
        if (
            type(request) is not tuple or len(request) != 2
            or any(type(value) is not int or value <= 0 for value in request)
        ):
            return False
        with self._lifecycle_lock:
            thread = self._thread
            if (
                request[0] != self._lifecycle_generation
                or self.status != "running" or self._stop.is_set()
                or thread is None or not thread.is_alive()
            ):
                return False
            with self._observation_request_lock:
                completed = self._completed_observation_request
                return bool(
                    completed is not None and completed[0] == request[0]
                    and completed[1] >= request[1]
                )

    @staticmethod
    def _fresh_observation_diagnostic_unavailable() -> dict[str, object]:
        return {
            "schema": "angerona.process-fresh-observation-diagnostic.v1",
            "diagnostic_only": True,
            "available": False,
            "reason": "diagnostic-unavailable",
        }

    @staticmethod
    def _fresh_observation_diagnostic_stamp(value: object) -> float:
        # Check an exact integer's range before any float conversion.
        if type(value) is int and 0 <= value <= 2**53:
            return float(value)
        if type(value) is float and math.isfinite(value) and value >= 0:
            return value
        raise ValueError("invalid diagnostic timestamp")

    def _fresh_observation_diagnostic_now(self) -> float:
        """A diagnostic-only fault seam; authoritative clocks never use it."""
        return self._fresh_observation_diagnostic_stamp(time.monotonic())

    def _observe_fresh_diagnostic(
        self, boundary: str, *, request: tuple[int, int] | None = None,
        generation: int | None = None, interval: float | None = None,
        _lock_held: bool = False,
    ) -> None:
        """Best-effort observability; normal failures cannot interrupt work.

        Existing token critical sections pass their held request lock. Other
        callers acquire it only for bounded capture, never across host work.
        A failed capture stays explicitly unavailable for this module instance
        rather than serving a possibly partial or stale diagnostic as current.
        Operator BaseExceptions deliberately propagate.
        """
        try:
            if _lock_held:
                try:
                    self._capture_fresh_diagnostic(boundary, request, generation, interval)
                except Exception:
                    self._observation_diagnostic_unavailable = True
            else:
                with self._observation_request_lock:
                    try:
                        self._capture_fresh_diagnostic(boundary, request, generation, interval)
                    except Exception:
                        # Mark partial capture unavailable before unlocking.
                        self._observation_diagnostic_unavailable = True
        except Exception:
            # Sticky loss flag only. Even failure to record diagnostic loss
            # must not replace the existing scheduling/stop/health outcome.
            try:
                self._observation_diagnostic_unavailable = True
            except Exception:
                pass

    def _capture_fresh_diagnostic(
        self, boundary: str, request: tuple[int, int] | None,
        generation: int | None, interval: float | None,
    ) -> None:
        """Called only by the best-effort wrapper with the request lock held."""
        if boundary == "initialize":
            self._observation_diagnostic_unavailable = False
            self._observation_pending_since: float | None = None
            self._observation_pending_stage = "unobserved"
            self._observation_inflight_request: tuple[int, int] | None = None
            self._observation_inflight_since: float | None = None
            self._observation_completed_since: float | None = None
            self._observation_stage = "unobserved"
            self._observation_stage_generation = 0
            self._observation_stage_since: float | None = None
            self._observation_last_attempt: tuple[int, int] | None = None
            self._observation_last_attempt_since: float | None = None
            self._observation_coverage: dict[str, object] = {}
            self._observation_coverage_request: tuple[int, int] | None = None
            self._observation_coverage_since: float | None = None
            self._observation_refusal = "not-observed"
            self._observation_waiting = False
            self._observation_wait_since: float | None = None
            self._observation_wait_elapsed: float | None = None
            self._observation_nominal_wait: float | None = None
            return
        if getattr(self, "_observation_diagnostic_unavailable", True) is not False:
            return
        if generation is not None and generation != self._lifecycle_generation:
            return
        now = self._fresh_observation_diagnostic_stamp(self._fresh_observation_diagnostic_now())
        stopping = (
            self._observation_stage == "stopping"
            and self._observation_stage_generation == self._lifecycle_generation
        )
        if boundary == "queued":
            self._observation_pending_since = now
            self._observation_pending_stage = "queued"
        elif boundary == "generation":
            pending = self._pending_observation_request
            if pending is None or pending[0] != generation:
                self._observation_pending_since = None
                self._observation_pending_stage = "unobserved"
            self._observation_inflight_request = None
            self._observation_inflight_since = None
            if not stopping:
                self._observation_stage = "unobserved"
                self._observation_stage_generation = self._lifecycle_generation
                self._observation_stage_since = now
            self._observation_last_attempt = None
            self._observation_last_attempt_since = None
            self._observation_coverage = {}
            self._observation_coverage_request = None
            self._observation_coverage_since = None
            self._observation_refusal = "not-observed"
            self._observation_waiting = False
            self._observation_wait_since = None
            self._observation_wait_elapsed = None
            self._observation_nominal_wait = None
            if self._completed_observation_request is None:
                self._observation_completed_since = None
        elif boundary == "begin":
            active = request if request is not None and request[0] == generation else None
            self._observation_inflight_request = active
            self._observation_inflight_since = self._observation_pending_since if active is not None else None
            self._observation_pending_since = None
            self._observation_pending_stage = "unobserved"
            if not stopping:
                self._observation_stage = "collecting"
                self._observation_stage_generation = self._lifecycle_generation
                self._observation_stage_since = now
            self._observation_last_attempt = active
            self._observation_last_attempt_since = now
        elif boundary == "processing" and not stopping:
            self._observation_stage = "processing"
            self._observation_stage_since = now
        elif boundary == "coverage" and not stopping:
            coverage = self._last_coverage
            observed: dict[str, object] = {}
            for name in ("complete", "enumeration_complete", "fresh", "counts_valid", "error_reported"):
                value = coverage.get(name)
                observed[name] = value if type(value) is bool else None
            for name in ("enumerated", "skipped", "unreadable", "identity_incomplete", "observed_identity_gaps"):
                value = coverage.get(name)
                observed[name] = min(value, 2**31 - 1) if type(value) is int and value >= 0 else None
            self._observation_coverage = observed
            self._observation_coverage_request = self._observation_inflight_request
            self._observation_coverage_since = now
            if coverage.get("reason") == "typed process collection receipt unavailable":
                reason = "typed-receipt-unavailable"
            elif coverage.get("error_reported") is True:
                reason = "collector-error-reported"
            elif coverage.get("counts_valid") is not True:
                reason = "invalid-coverage-counts"
            elif coverage.get("enumeration_complete") is not True:
                reason = "enumeration-incomplete"
            elif coverage.get("fresh") is not True:
                reason = "collection-not-fresh"
            else:
                reason = "acknowledgement-eligible"
            self._observation_refusal = reason
        elif boundary == "completed":
            if not stopping:
                if request is not None:
                    self._observation_completed_since = self._observation_inflight_since
                self._observation_stage = "completed"
                self._observation_stage_since = now
            self._observation_inflight_request = None
            self._observation_inflight_since = None
        elif boundary == "retry":
            if self._pending_observation_request == request:
                self._observation_pending_since = self._observation_inflight_since
                self._observation_pending_stage = "retry"
            if not stopping:
                self._observation_stage = "retry"
                self._observation_stage_since = now
            self._observation_inflight_request = None
            self._observation_inflight_since = None
        elif boundary == "revoked":
            if self._observation_inflight_request == request:
                self._observation_inflight_request = None
                self._observation_inflight_since = None
        elif boundary == "stopping":
            self._observation_pending_since = None
            self._observation_completed_since = None
            self._observation_pending_stage = "unobserved"
            self._observation_stage = "stopping"
            self._observation_stage_generation = self._lifecycle_generation
            self._observation_stage_since = now
        elif boundary == "wait-begin" and not stopping:
            self._observation_nominal_wait = interval
            self._observation_wait_since = now
            self._observation_waiting = True
        elif boundary == "wait-end" and not stopping:
            stamp = self._observation_wait_since
            finite_stamp = self._fresh_observation_diagnostic_stamp(stamp) if stamp is not None else None
            if finite_stamp is not None and finite_stamp > now:
                raise ValueError("future diagnostic timestamp")
            self._observation_wait_elapsed = (
                now - finite_stamp if finite_stamp is not None else None
            )
            self._observation_waiting = False

    def fresh_observation_diagnostic(self, request: tuple[int, int]) -> dict[str, object]:
        """Copy fixed bounded observations, or explicitly report unavailable.

        No native collection, pacing, health, readiness or work publication is
        performed. Normal diagnostic failures never become caller failures;
        operator BaseExceptions deliberately propagate. A returned diagnostic
        grants no detection, validation, trust or response authority.
        """
        try:
            return self._read_fresh_observation_diagnostic(request)
        except Exception:
            return self._fresh_observation_diagnostic_unavailable()

    def _read_fresh_observation_diagnostic(self, request: tuple[int, int]) -> dict[str, object]:
        def token(value: object) -> list[int] | None:
            if (type(value) is tuple and len(value) == 2
                    and all(type(item) is int and 0 < item <= (2**63 - 1) for item in value)):
                return list(value)
            return None

        def seconds(value: object) -> float | None:
            if type(value) is int:
                return float(min(86400, max(0, value)))
            if type(value) is float and math.isfinite(value):
                return round(min(86400.0, max(0.0, value)), 3)
            return None

        # Match existing lifecycle -> cycle order, release cycle before request.
        with self._lifecycle_lock:
            generation = self._lifecycle_generation
            with self._cycle_lock:
                declared_wait = self._last_sleep_interval_seconds
            with self._observation_request_lock:
                if getattr(self, "_observation_diagnostic_unavailable", True) is not False:
                    return self._fresh_observation_diagnostic_unavailable()
                now = self._fresh_observation_diagnostic_stamp(self._fresh_observation_diagnostic_now())

                def age(stamp: object) -> float | None:
                    if stamp is None:
                        return None
                    finite_stamp = self._fresh_observation_diagnostic_stamp(stamp)
                    if finite_stamp > now:
                        raise ValueError("future diagnostic timestamp")
                    return seconds(now - finite_stamp)

                pending = self._pending_observation_request
                inflight = self._observation_inflight_request
                completed = self._completed_observation_request
                stage = "unobserved"
                requested_since = None
                if token(request) is not None and request[0] == generation:
                    if (self._observation_stage == "stopping"
                            and self._observation_stage_generation == generation):
                        stage = "stopping"
                    elif request == inflight:
                        stage = self._observation_stage
                        requested_since = self._observation_inflight_since
                    elif request == pending:
                        stage = self._observation_pending_stage
                        requested_since = self._observation_pending_since
                    elif (completed is not None and completed[0] == request[0]
                          and completed[1] >= request[1]):
                        stage = "completed"
                        requested_since = self._observation_completed_since if request == completed else None
                waiting = self._observation_waiting
                return {
                    "schema": "angerona.process-fresh-observation-diagnostic.v1",
                    "diagnostic_only": True,
                    "available": True,
                    "generation": generation,
                    "requested_token": token(request),
                    "requested_stage": stage,
                    "requested_age_seconds": age(requested_since),
                    "worker_stage": (self._observation_stage if self._observation_stage_generation == generation
                                     else "unobserved"),
                    "stage_age_seconds": (age(self._observation_stage_since)
                                          if self._observation_stage_generation == generation else None),
                    "pending_token": token(pending),
                    "inflight_token": token(inflight),
                    "completed_token": token(completed),
                    "last_attempt_token": token(self._observation_last_attempt),
                    "last_attempt_age_seconds": age(self._observation_last_attempt_since),
                    "last_coverage": dict(self._observation_coverage),
                    "last_coverage_token": token(self._observation_coverage_request),
                    "last_coverage_age_seconds": age(self._observation_coverage_since),
                    "last_refusal_reason": self._observation_refusal,
                    "waiting": waiting,
                    "nominal_wait_seconds": seconds(self._observation_nominal_wait),
                    "declared_wait_seconds": seconds(declared_wait),
                    "wait_elapsed_seconds": (age(self._observation_wait_since) if waiting
                                             else seconds(self._observation_wait_elapsed)),
                    "age_limit_seconds": 86400,
                    "count_limit": 2**31 - 1,
                }

    def _begin_fresh_observation(self, generation: int) -> tuple[int, int] | None:
        with self._observation_request_lock:
            request = self._pending_observation_request
            self._pending_observation_request = None
            self._observation_request_event.clear()
            self._observe_fresh_diagnostic("begin", request=request, generation=generation, _lock_held=True)
            return request if request is not None and request[0] == generation else None

    def _complete_fresh_observation(self, request: tuple[int, int] | None) -> None:
        # Partial identity rows retain their existing explicit degraded health.
        # Failed/stale enumeration cannot acknowledge the requested observation.
        if request is None:
            self._observe_fresh_diagnostic("completed")
            return
        with self._lifecycle_lock:
            if (
                self.generation_stop_event().is_set() or self._stop.is_set()
                or request[0] != self._lifecycle_generation or self.status != "running"
            ):
                self._observe_fresh_diagnostic("revoked", request=request)
                return
            with self._observation_request_lock:
                if (
                    self._last_coverage.get("fresh") is True
                    and self._last_coverage.get("counts_valid") is True
                    and self._last_coverage.get("enumeration_complete") is True
                    and self._last_coverage.get("error_reported") is False
                ):
                    self._completed_observation_request = request
                    self._observe_fresh_diagnostic("completed", request=request, _lock_held=True)
                else:
                    pending = self._pending_observation_request
                    if pending is None or (
                        pending[0] == request[0] and pending[1] < request[1]
                    ):
                        # Retain one bounded hint, without waking a failed
                        # collector into a tight loop or replacing newer work.
                        self._pending_observation_request = request
                    if (
                        self._pending_observation_request == request
                        and self._observation_retry_offered != request
                    ):
                        self._observation_retry_offered = request
                        self._observation_retry_credit = request
                    self._observe_fresh_diagnostic("retry", request=request, _lock_held=True)

    def _consume_observation_retry_credit(self, generation: int) -> bool:
        """Omit one discretionary delay for the same live refused token."""
        with self._lifecycle_lock:
            with self._observation_request_lock:
                credit = self._observation_retry_credit
                if credit is None:
                    return False
                thread = self._thread
                if (
                    credit != self._pending_observation_request
                    or credit != self._observation_retry_offered
                    or credit[0] != self._lifecycle_generation
                    or thread is None or not thread.is_alive()
                    or self.status != "running" or self._stop.is_set()
                ):
                    self._observation_retry_credit = None
                    return False
                # A stale caller or another thread cannot spend or discard
                # credit which still belongs to the current live worker.
                if (
                    generation != self._lifecycle_generation
                    or thread is not threading.current_thread()
                ):
                    return False
                if self.generation_stop_event().is_set():
                    self._observation_retry_credit = None
                    return False
                self._observation_retry_credit = None
                return True

    def stop(self) -> None:
        # Serialize revocation with completion/requeue; a late collector cannot
        # republish a stopped generation's hint or acknowledgement.
        with self._lifecycle_lock:
            super().stop()
            with self._observation_request_lock:
                self._pending_observation_request = None
                self._completed_observation_request = None
                self._observation_retry_offered = None
                self._observation_retry_credit = None
                self._observation_request_event.clear()
                self._observe_fresh_diagnostic("stopping", _lock_held=True)

    def bind_redteam_receipt_capability(
        self,
        capability: object | None,
        *,
        expected: object | None = None,
    ) -> None:
        """Bind/revoke one exact validation producer capability."""
        with self._redteam_receipt_lock:
            if expected is not None and self._redteam_receipt_capability is not expected:
                return
            self._redteam_receipt_capability = capability

    def observe_validation_process(
        self,
        pid: int,
        *,
        _prepare_only: bool = False,
    ) -> bool | dict[str, object]:
        """Perform one exact, read-only OS observation for an enrolled child.

        ``_prepare_only`` is used only by the validation lease's two-phase
        binder: the native receipt is prepared without publishing while the
        challenge is pending, then published only after the lease atomically
        commits that exact receipt. Normal sensor polling retains the boolean
        API and publishes immediately.
        """
        if self.status != "running" or self.stopping:
            return False
        try:
            import psutil

            observed = psutil.Process(int(pid))
            process: dict[str, object] = {
                "pid": int(observed.pid),
                "ppid": int(observed.ppid()),
                "name": str(observed.name() or ""),
                "exe": str(observed.exe() or ""),
                "cmdline": [str(value) for value in observed.cmdline()],
                "create_time": float(observed.create_time()),
            }
            if not observed.is_running():
                return False
            with self._redteam_receipt_lock:
                capability = self._redteam_receipt_capability
            issue = getattr(capability, "issue_process_observation", None)
            receipt = issue(self, process=process) if callable(issue) else {}
            if not receipt:
                return False
            identity, _complete = _process_identity(process)
            if identity is not None:
                self._redteam_receipted.add(identity)
            command = " ".join(str(value) for value in process["cmdline"])
            prepared: dict[str, object] = {
                "message": (
                    f"Process created: {process['name'] or '?'} "
                    f"(pid {int(process['pid'])})"
                ),
                "details": {
                    "event_type": "process_creation",
                    "pid": int(process["pid"]),
                    "ppid": process["ppid"],
                    "exe": process["exe"],
                    "cmdline": command,
                    "process_create_time": process["create_time"],
                    **receipt,
                },
            }
            if _prepare_only:
                return prepared
            self.emit(
                str(prepared["message"]),
                Severity.INFO,
                **dict(prepared["details"]),
            )
            return True
        except (OSError, TypeError, ValueError):
            return False

    def self_test(self) -> tuple[bool, str]:
        """Exercise lineage and risky-path rules without enumerating processes."""
        emitted: list[tuple[str, Severity, dict]] = []
        original_emit = self.emit
        original_names = self._names
        try:
            self.emit = lambda message, severity=Severity.INFO, **details: emitted.append(
                (message, severity, details)
            )
            self._names = {10: "winword.exe"}
            self._evaluate(
                {
                    "pid": 11,
                    "ppid": 10,
                    "name": "powershell.exe",
                    "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "create_time": 123.0,
                },
                dict(self._names),
            )
            self._evaluate(
                {
                    "pid": 12,
                    "ppid": 10,
                    "name": "fixture.exe",
                    "exe": r"C:\Users\Test\Downloads\fixture.exe",
                    "create_time": 124.0,
                },
                dict(self._names),
            )
        finally:
            self.emit = original_emit
            self._names = original_names
        ok = bool(
            len(emitted) == 2
            and emitted[0][1] == Severity.CRITICAL
            and emitted[0][2].get("process_create_time") == 123.0
            and emitted[1][1] == Severity.MEDIUM
        )
        return (
            ok,
            "offline lineage and risky-path rules passed"
            if ok else "process rule fixture failed",
        )

    def run(self) -> None:
        # Establish the startup boundary from the OS PID table immediately.
        # Rich per-process fields are intentionally deferred to the first poll:
        # Windows can spend several seconds resolving command lines for hundreds
        # of protected processes. A child created after this exact PID boundary
        # remains new and cannot disappear into a slow startup enumeration.
        import psutil

        generation = int(getattr(self._run_context, "generation", self.lifecycle_generation))
        with self._observation_request_lock:
            # No collection has failed yet in this newly entered generation.
            self._observation_retry_offered = None
            self._observation_retry_credit = None
            pending = self._pending_observation_request
            # start() publishes a new worker before run() enters: retain a
            # request already accepted for this exact new generation.
            if pending is None or pending[0] != generation:
                self._pending_observation_request = None
                self._observation_request_event.clear()
            completed = self._completed_observation_request
            if completed is not None and completed[0] != generation:
                self._completed_observation_request = None
            self._observe_fresh_diagnostic("generation", generation=generation, _lock_held=True)

        self._initial_pid_baseline = {
            int(pid) for pid in psutil.pids() if int(pid) > 0
        }
        self.set_health(
            70,
            "startup PID boundary captured; full birth/command identity enrichment pending",
        )
        self.mark_cycle_complete(interval_seconds=0.0)
        self.emit("Process monitor active.", Severity.INFO)

        while not self.stopping:
            combat = _combat_enabled()
            interval = 1.0 if combat else 3.0
            self._observe_fresh_diagnostic("wait-begin", generation=generation, interval=interval)
            if self._consume_observation_retry_credit(generation):
                self.sleep(
                    interval, cycle_complete=False,
                    _wake_event=self._observation_request_event,
                    _background_pacing=False,
                )
            else:
                self.sleep(
                    interval, cycle_complete=False,
                    _wake_event=self._observation_request_event,
                )
            self._observe_fresh_diagnostic("wait-end", generation=generation, interval=interval)
            if self.stopping:
                break
            request = self._begin_fresh_observation(generation)
            max_age = 0.0 if request is not None else _snapshot_max_age()
            snapshot = (
                process_snapshot(max_age=max_age)
                if max_age is not None
                else process_snapshot()
            )
            self._observe_fresh_diagnostic("processing", generation=generation)
            if type(snapshot) is not ProcessSnapshot:
                self._last_coverage = {"complete": False, "reason": "typed process collection receipt unavailable"}
                self.set_health(55, "typed process collection receipt unavailable")
                self._observe_fresh_diagnostic("coverage", generation=generation)
                self.mark_cycle_complete(interval_seconds=interval)
                self._complete_fresh_observation(request)
                continue
            procs = snapshot.processes
            live: Set[tuple[int, str, str]] = set()
            names: Dict[int, str] = {}
            observations: list[tuple[Mapping, tuple[int, str, str]]] = []
            identity_gaps = 0
            for p in procs:
                identity, complete = _process_identity(p)
                if identity is None:
                    identity_gaps += 1
                    continue
                pid = identity[0]
                live.add(identity)
                identity_gaps += int(not complete)
                names[pid] = (p.get("name") or "").lower()
                observations.append((p, identity))

            # The complete name table is needed for parent-lineage rules, but
            # each immutable identity only needs normalizing once per snapshot.
            for p, identity in observations:
                pid = identity[0]
                is_new = bool(
                    identity not in self._seen
                    and (
                        self._initial_pid_baseline is None
                        or pid not in self._initial_pid_baseline
                    )
                )
                # Publish complete process-creation telemetry for correlation.
                # INFO is not a malicious verdict; reviewed detectors such as
                # Purple Guard can promote exact tagged evidence independently.
                receipt: dict[str, object] = {}
                if identity not in self._redteam_receipted:
                    try:
                        with self._redteam_receipt_lock:
                            capability = self._redteam_receipt_capability
                        issue = getattr(capability, "issue_process_observation", None)
                        if callable(issue):
                            receipt = issue(self, process=dict(p))
                    except Exception:
                        receipt = {}
                if is_new or receipt:
                    # Unchanged processes do not emit a creation event. Avoid
                    # rebuilding their potentially long command strings on
                    # every tick; validation still receives the full raw row.
                    raw_command = p.get("cmdline") or []
                    command = (
                        " ".join(str(part) for part in raw_command)
                        if isinstance(raw_command, (list, tuple))
                        else str(raw_command)
                    )
                    self.emit(
                        f"Process created: {p.get('name') or '?'} (pid {pid})",
                        Severity.INFO,
                        event_type="process_creation",
                        pid=pid,
                        ppid=p.get("ppid"),
                        exe=p.get("exe"),
                        cmdline=command,
                        process_create_time=p.get("create_time"),
                        **receipt,
                    )
                if receipt:
                    self._redteam_receipted.add(identity)
                if is_new:
                    self._evaluate(p, names)

            self._identity_gaps = identity_gaps
            complete = self._set_process_health(snapshot, identity_gaps, len(live))
            self._observe_fresh_diagnostic("coverage", generation=generation)
            if complete:
                self._seen = live
                self._initial_pid_baseline = None
                self._names = names
            else:
                # Absence from a partial inventory is not process exit. Retain
                # bounded prior identities/validation dedup until full coverage
                # returns; a denied poll must not turn old processes into new
                # spawns or reissue their validation receipt on the next tick.
                previous = islice(self._seen - live, max(0, _MAX_PARTIAL_IDENTITIES - len(live)))
                self._seen = live | set(previous)
                retained_pids = {identity[0] for identity in self._seen}
                self._names = {pid: name for pid, name in self._names.items() if pid in retained_pids}
                self._names.update(names)
            self._redteam_receipted.intersection_update(self._seen)
            self.mark_cycle_complete(interval_seconds=interval)
            self._complete_fresh_observation(request)

    def _set_process_health(self, snapshot: ProcessSnapshot, identity_gaps: int, tracked: int) -> bool:
        """Loss/freshness is part of collection, even when visible rows are valid."""
        counters = (snapshot.enumerated, snapshot.skipped, snapshot.unreadable, snapshot.identity_incomplete)
        valid_counts = all(type(value) is int and value >= 0 for value in counters)
        valid_counts = (valid_counts and snapshot.enumerated >= len(snapshot.processes)
                        and snapshot.skipped <= snapshot.enumerated
                        and snapshot.unreadable <= len(snapshot.processes)
                        and snapshot.identity_incomplete <= len(snapshot.processes))
        stamp = snapshot.collected_at
        age = time.time() - stamp if type(stamp) in (int, float) and math.isfinite(stamp) else float("inf")
        fresh = math.isfinite(age) and 0 <= age <= 30.0
        complete = (snapshot.complete is True and snapshot.enumeration_complete is True
                    and valid_counts and not any(counters[1:]) and not snapshot.error
                    and fresh and not identity_gaps)
        self._last_coverage = dict(complete=complete, enumeration_complete=snapshot.enumeration_complete is True,
            collected_at=stamp if type(stamp) in (int, float) and math.isfinite(stamp) else None,
            fresh=fresh, counts_valid=valid_counts, enumerated=snapshot.enumerated, skipped=snapshot.skipped,
            unreadable=snapshot.unreadable, identity_incomplete=snapshot.identity_incomplete,
            error_reported=bool(snapshot.error), observed_identity_gaps=identity_gaps)
        if complete:
            self.set_health(100, f"{tracked} process generation(s) tracked by pid + birth identity")
        elif identity_gaps:
            self.set_health(70, f"process identity incomplete for {identity_gaps}/{len(snapshot.processes)} record(s); collection coverage incomplete")
        else:
            gaps = []
            if snapshot.enumeration_complete is not True:
                gaps.append("process enumeration incomplete")
            if snapshot.error:
                gaps.append("collector error reported")
            if not valid_counts:
                gaps.append("invalid coverage counts")
            if not fresh:
                gaps.append("collection timestamp unavailable, stale or future")
            if valid_counts and any(counters[1:]):
                gaps.append(f"skipped={snapshot.skipped}, unreadable={snapshot.unreadable}, identity_incomplete={snapshot.identity_incomplete}")
            self.set_health(55, "process coverage incomplete: " + "; ".join(gaps or ["collector completeness not established"]))
        return complete

    def _evaluate(self, p: dict, names: Dict[int, str]) -> None:
        name = (p.get("name") or "").lower()
        exe = (p.get("exe") or "").lower()
        ppid = p.get("ppid")
        # A PID may have been reused since the previous inventory. Prefer the
        # parent observed alongside this child; cache only fills a missing row.
        parent = names.get(ppid, self._names.get(ppid, "")).lower()

        if name in SUSPICIOUS_CHILDREN and parent in OFFICE_PARENTS:
            pid = p.get("pid")
            created = p.get("create_time")
            self.emit(
                f"Office app '{parent}' spawned '{name}' (pid {pid}) — possible macro abuse.",
                Severity.CRITICAL,
                pid=pid,
                parent=parent,
                exe=p.get("exe"),
                process_create_time=created,
            )
            return
        if exe and any(tok in exe for tok in RISKY_PATH_TOKENS):
            self.emit(f"Process running from a risky path: {p.get('exe')} (pid {p.get('pid')})",
                      Severity.MEDIUM, pid=p.get("pid"), exe=p.get("exe"),
                      process_create_time=p.get("create_time"))
