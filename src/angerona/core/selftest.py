"""Self-test / stress harness.

Runs each module's ``self_test()`` (with a timeout so a hung test can't freeze
the app), plus an end-to-end pipeline check (publish a synthetic event and
confirm it flows through the bus). Produces a pass/fail/expected-skip report
and raises a failure notification only for actionable test failures.

Invoke from the console: ``test`` (all) or ``test <module>``.
"""
from __future__ import annotations

import json
import math
import os
import queue
import threading
import time
import uuid
from pathlib import Path
from typing import Callable, List, Optional

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.module_base import BaseModule, watchdog_fault_kind
from angerona.core.module_usage import ModuleUsage
from angerona.core.platforms import availability_for
from angerona.core.selftest_remediation import add_module_result_context, runtime_evidence
from angerona.core.selftest_verification import (
    module_contract_checks, verify_accounting, verify_harness,
)


# These permits belong to the process, not an individual drill. A timed-out
# Python call cannot safely be killed, and retains its permit until it exits.
_MODULE_CALLS = threading.BoundedSemaphore(6)
_EVENT_CALLS = threading.BoundedSemaphore(1)
_PROGRESS_CALLS = threading.BoundedSemaphore(1)
_MODULE_LOCK_CREATION = threading.Lock()
_DIAGNOSTIC_EVENT = {"response_authorized": False, "active_attack": False, "disposition": "health"}


class _CapacityLease:
    """Retain both hardware and process capacity until the actual call exits."""
    def __init__(self, capacity, process):
        self.capacity, self.process = capacity, process

    def acquire(self, blocking=False, timeout=None):
        deadline = time.monotonic() + timeout if timeout is not None else None
        if not self.capacity.acquire(blocking=blocking, timeout=timeout):
            return False
        remaining = max(0.0, deadline - time.monotonic()) if deadline is not None else None
        if not self.process.acquire(blocking=blocking, timeout=remaining):
            self.capacity.release()
            return False
        return True

    def release(self):
        self.process.release()
        self.capacity.release()


def module_selftest_lock(mod):
    """Use one lock when the inspector and a drill first test a module."""
    with _MODULE_LOCK_CREATION:
        lock = getattr(mod, "_angerona_selftest_lock", None)
        if lock is None:
            lock = threading.Lock()
            setattr(mod, "_angerona_selftest_lock", lock)
        return lock


def _deception_creation_hold_reason(mod, detail: str) -> Optional[str]:
    """Recognize only the bundled Windows diagnostic's exact capability hold."""
    if os.name != "nt":
        return None
    from angerona.modules.deception import DECEPTION_WINDOWS_CREATION_HELD, DeceptionModule
    if type(mod) is DeceptionModule and detail == DECEPTION_WINDOWS_CREATION_HELD:
        return detail
    return None


def run_module_selftest(mod, timeout: float = 15.0) -> tuple[bool, str]:
    """Run one inspector check under the drill's shared limits and lock."""
    timeout = float(timeout)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("self-test timeout must be positive and finite")
    if getattr(mod, "name", "") == "AI Triage (Ollama)":
        from angerona.core.ollama_lifecycle import ollama_blocked
        if ollama_blocked():
            return False, "SKIP: local AI is off in Chill Mode; switch Chill off manually for an active check"
    evidence: dict = {}
    ok, detail = SelfTestRunner._test_module(
        mod, timeout, optional_kernel_policy=False, evidence=evidence,
    )
    held = None if ok else _deception_creation_hold_reason(mod, detail)
    checks = evidence.get("checks", ())
    # Direct inspectors retain the same failure precedence as a complete drill.
    # An exact hold without completed result evidence is still no SKIP authority.
    if held and any(check.get("check") == "result_contract"
                    and check.get("status") == "PASS" for check in checks) and any(
        check.get("check") == "active_test" and check.get("status") == "FAIL"
        and check.get("detail") == held for check in checks
    ):
        defects = [check for check in checks
                   if check.get("status") == "FAIL" and check.get("check") != "active_test"]
        if defects:
            return False, "contract check failed: " + "; ".join(
                str(check["check"]) + " — " + str(check.get("detail", "")) for check in defects
            ) + "; native diagnostic held: " + held
        return False, "SKIP: " + held
    return ok, detail


def _bounded_call(callback, permits, timeout: float, *, name: str, admission_deadline=None, on_slow=None):
    """Account the absolute budget without abandoning unlimited callbacks.

    Native code holding the GIL can delay this coordinator; it cannot be
    preempted here. Completion after the deadline never becomes success merely
    because startup or the coordinator resumed late.
    """
    deadline = time.monotonic() + timeout
    if not permits.acquire(blocking=False):
        admit_until = admission_deadline() if admission_deadline else 0.0
        remaining = admit_until - time.monotonic()
        if remaining <= 0 or not permits.acquire(blocking=True, timeout=remaining):
            return False, "a previous call is still running", None
        now = time.monotonic()
        if now > admit_until:
            permits.release()
            return False, "a previous call is still running", None
        # Queue admission has its own budget. Time the admitted check from
        # before worker construction, without crediting a late callback.
        deadline = now + timeout
    try:
        completed = threading.Event()
        result: dict = {}

        def work():
            try:
                try:
                    result["value"] = callback()
                finally:
                    # Stamp callback completion before formatting a raised error.
                    result["finished_at"] = time.monotonic()
            except BaseException as exc:
                # A failed formatter must never erase the callback failure or
                # escape this worker with an apparently successful empty result.
                result["error"] = "callback failed; exception message unavailable"
                try:
                    result["error"] = f"{type(exc).__name__}: {exc}"
                except BaseException:
                    pass
            finally:
                permits.release()
                completed.set()

        worker = threading.Thread(target=work, name=name, daemon=True)
    except BaseException:
        # No start has been invoked: this path still owns the acquired lease.
        permits.release()
        raise
    try:
        worker.start()
    except Exception:
        permits.release()
        raise
    remaining = max(0.0, deadline - time.monotonic())
    if on_slow is not None and not completed.wait(min(5.0, timeout / 3, remaining)):
        on_slow()
        remaining = max(0.0, deadline - time.monotonic())
    if not completed.wait(remaining) and not completed.is_set():
        return False, f"timed out after {timeout:g}s; the call is still running", None
    if result["finished_at"] > deadline:
        error = f"timed out after {timeout:g}s; the call finished after its deadline"
        if "error" in result:
            error += f"; original error: {result['error']}"
        return False, error, None
    if "error" in result:
        return False, result["error"], None
    return True, "", result.get("value")


def _failure_log_path() -> Path:
    # Repo diagnostics/ dir (mounted / user-visible). Best-effort.
    from angerona.core.data_paths import data_dir
    return data_dir() / "diagnostics" / "selftest_failures.json"


class SelfTestRunner:
    _MAX_MODULE_WORKERS = 6
    _PIPELINE_TIMEOUT = 3.0
    _REPORT_TIMEOUT = 0.5
    _CAPACITY_GRACE = 1.0

    def __init__(self, manager, bus: EventBus) -> None:
        self.manager = manager
        self.bus = bus
        # Populated by run(): actionable failures from the last run.
        self.last_failures: List[dict] = []
        # Expected non-results are kept separate so the GUI never offers to
        # "repair" a sensor for another operating system, an operator-disabled
        # module, or a deep scanner intentionally parked by Chill Mode.
        self.last_skips: List[dict] = []
        self.last_deferred: List[dict] = []
        self.last_results: List[dict] = []
        self.last_repairs: dict = {}
        self.last_verification: dict = {}
        self.last_metrics: dict = {}

    def run(
        self,
        names: Optional[List[str]] = None,
        timeout: float = 15.0,
        progress_cb=None,
        expected_failure_cb: Callable[[str, str], Optional[str]] | None = None,
    ) -> str:
        """Run the pipeline and module checks.

        ``expected_failure_cb`` is reserved for controlled harnesses that
        intentionally do not start live sensors.  Returning a reason converts
        that specific result to a structured skip.  The default remains strict,
        and callback errors fail closed as ordinary test failures.
        """
        timeout = float(timeout)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("self-test timeout must be positive and finite")
        started = time.perf_counter()
        self.run_id = uuid.uuid4().hex
        self.last_results = []
        self.last_repairs = {}
        self.last_verification = {}
        self.last_metrics = {}
        lines = ["===== SELF-TEST / STRESS DRILL =====", ""]
        passed = failed = skipped = 0
        failures: List[dict] = []
        skips: List[dict] = []
        deferred: List[dict] = []
        notifications: list[Event] = []
        failed_modules: list[str] = []
        records: list[dict] = []

        target_names = [name for name in sorted(self.manager.modules) if not names or name in names]
        target_modules = [self.manager.modules[name] for name in target_names]
        targeted = bool(names)
        module_policies = {mod.name: self._module_policy(mod) for mod in target_modules}
        skip_reasons = {
            mod.name: reason
            for mod in target_modules
            if (
                reason := self._skip_reason(
                    mod,
                    respect_runtime_state=not targeted,
                    policy=module_policies[mod.name],
                )
            ) is not None
        }
        testable_modules = [
            mod for mod in target_modules if mod.name not in skip_reasons
        ]
        worker_limit, worker_reason, hardware_limit = self._worker_budget()
        worker_count = min(worker_limit, len(testable_modules))
        # Open one spare slot for the next queued check while a slow call
        # retains its original slot and still has time to finish.
        reserve = int(worker_count < min(hardware_limit, len(testable_modules)))
        run_capacity = threading.BoundedSemaphore(max(1, worker_count + reserve))
        spare_ready = threading.Event() if reserve else None
        deadline = time.monotonic() + max(
            self._PIPELINE_TIMEOUT,
            math.ceil(len(testable_modules) / max(1, worker_count)) * timeout,
        ) + self._CAPACITY_GRACE
        admission_lock = threading.Lock()
        admission_until = None

        def _admission_deadline():
            nonlocal admission_until
            with admission_lock:
                if admission_until is None:
                    # Share a single grace window across the run, rather than
                    # waiting again for every queued module behind a hung call.
                    admission_until = min(deadline, time.monotonic() + min(timeout, self._CAPACITY_GRACE))
                return admission_until

        lines.append(
            f"  Resource budget: {worker_count} module worker(s), {reserve} spare test slot(s); {worker_reason}"
        )
        lines.append("  Checks: identity, diagnostic contract, local health, bounded active test, timing, verification.")
        module_evidence: dict = {}
        pipeline_timing: dict = {}

        # Bound concurrent active checks. The old one-thread-per-module fanout
        # could briefly create 120+ threads and saturate an otherwise idle host.
        # A small daemon pool preserves parallelism without a scan stampede.
        pipeline_res: dict = {}
        mod_results: dict = {}
        result_lock = threading.Lock()
        dispatch_stopped = threading.Event()

        # Live progress: fire progress_cb(done, total) as each concurrent test
        # finishes, so the UI can show a real percentage climbing to 100%.
        total = len(target_modules) + 1          # +1 for the pipeline check
        _done = {"n": 0}
        _plock = threading.Lock()
        progress_queue: queue.Queue = queue.Queue(maxsize=total + 1)
        progress_stopped = threading.Event()

        def _bump():
            if progress_cb is None:
                return
            with _plock:
                _done["n"] += 1
                n = _done["n"]
                progress_queue.put_nowait((n, total))

        def _dispatch_progress() -> None:
            try:
                while not progress_stopped.is_set():
                    item = progress_queue.get()
                    if item is None:
                        return
                    try:
                        progress_cb(*item)
                    except Exception:
                        pass
            finally:
                _PROGRESS_CALLS.release()

        def _run_pipeline():
            began = time.perf_counter()
            completed, error, result = _bounded_call(
                self._pipeline_check,
                _EVENT_CALLS,
                self._PIPELINE_TIMEOUT,
                name="AngeronaSelfTestEventDelivery",
            )
            with result_lock:
                if not dispatch_stopped.is_set():
                    pipeline_res["res"] = (
                        result if completed else (False, f"pipeline check {error}")
                    )
                    pipeline_timing["duration_ms"] = (time.perf_counter() - began) * 1000
                    _bump()

        def _run_single(mod):
            began = time.perf_counter()
            evidence = {"checks": []}
            try:
                result = self._test_module(
                    mod, timeout, evidence=evidence, _capacity=run_capacity,
                    _admission_deadline=_admission_deadline,
                    _on_slow=spare_ready.set if spare_ready is not None else None,
                )
            except Exception as exc:
                result = (False, f"error: {exc}")
            evidence["duration_ms"] = (time.perf_counter() - began) * 1000
            with result_lock:
                if not dispatch_stopped.is_set():
                    mod_results[mod.name] = result
                    module_evidence[mod.name] = evidence
                    _bump()

        threads = []
        progress_thread = None
        progress_unavailable = False
        if progress_cb is not None and _PROGRESS_CALLS.acquire(blocking=False):
            progress_thread = threading.Thread(
                target=_dispatch_progress,
                name="AngeronaSelfTestProgress",
                daemon=True,
            )
            try:
                progress_thread.start()
            except Exception:
                _PROGRESS_CALLS.release()
                raise
        elif progress_cb is not None:
            progress_unavailable = True
        
        # Dispatch pipeline test
        p_thread = threading.Thread(
            target=_run_pipeline, name="AngeronaSelfTestPipeline", daemon=True,
        )
        p_thread.start()
        threads.append(p_thread)

        # Dispatch module tests through a bounded daemon worker pool.
        module_queue: queue.Queue = queue.Queue()
        for mod in testable_modules:
            module_queue.put(mod)

        def _module_worker() -> None:
            while not dispatch_stopped.is_set() and time.monotonic() < deadline:
                mod = module_queue.get()
                if mod is None:
                    return
                _run_single(mod)

        for _ in range(worker_count + reserve):
            module_queue.put(None)
        for index in range(worker_count):
            t = threading.Thread(
                target=_module_worker,
                name=f"AngeronaSelfTest-{index + 1}",
                daemon=True,
            )
            t.start()
            threads.append(t)
        spare_worker = None
        if spare_ready is not None:
            def _spare_worker():
                if spare_ready.wait(max(0.0, deadline - time.monotonic())):
                    _module_worker()

            spare_worker = threading.Thread(target=_spare_worker, name="AngeronaSelfTestSpare", daemon=True)
            spare_worker.start()

        # Expected skips count as completed work for the progress indicator,
        # but deliberately never execute the module's active test.
        for _mod in skip_reasons:
            _bump()

        # Only coordinator threads are joined here. Actual module and bus calls
        # keep process-wide permits after timeout, preventing repeated drills
        # from accumulating hung work. No callback receives an unbounded join.
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))
        if spare_worker is not None:
            # Release an unused spare once all regular coordinators retire.
            spare_ready.set()
            spare_worker.join(max(0.0, deadline - time.monotonic()))
        with result_lock:
            dispatch_stopped.set()
            for _ in range(len(testable_modules) - len(mod_results) + int("res" not in pipeline_res)):
                _bump()
        if progress_thread is not None:
            progress_queue.put_nowait(None)
            progress_thread.join(self._REPORT_TIMEOUT)
            progress_unavailable = progress_thread.is_alive()
            progress_stopped.set()

        # 1) Evaluate Pipeline check
        ok, detail = pipeline_res.get(
            "res", (False, "pipeline coordinator did not complete before its deadline"),
        )
        lines.append(f"  [{'PASS' if ok else 'FAIL'}] Event pipeline — {detail}")
        passed += ok
        failed += (not ok)
        records.append({"module": "Event pipeline", "kind": "pipeline",
                        "status": "PASS" if ok else "FAIL", "detail": detail,
                        "duration_ms": pipeline_timing.get("duration_ms", 0.0),
                        "checks": [{"check": "synthetic_delivery", "status": "PASS" if ok else "FAIL"}]})
        if not ok:
            failures.append({
                "module": "Event pipeline", "detail": detail, "repairable": False,
            })
            # Preserve critical core-bus diagnostics without calling a possibly
            # blocked subscriber from the result-collection thread.
            notifications.append(Event("Self-Test",
                                   f"CRITICAL FAILURE: Event pipeline — {detail}",
                                   Severity.CRITICAL, details={
                                       **_DIAGNOSTIC_EVENT, "finding_code": "selftest.event_pipeline",
                                   }))

        # 2) Evaluate Per-module tests
        for mod in target_modules:
            if mod.name in skip_reasons:
                skip_detail = skip_reasons[mod.name]
                checks = module_contract_checks(mod, include_health=False)
                contract_failures = [c for c in checks if c["status"] == "FAIL"]
                if contract_failures:
                    detail = "contract check failed: " + "; ".join(c["check"] for c in contract_failures)
                    lines.append(f"  [FAIL] {mod.name} — {detail}")
                    failed += 1
                    failed_modules.append(mod.name)
                    failures.append({"module": mod.name, "detail": detail, "repairable": False})
                    record = {"module": mod.name, "kind": "module", "status": "FAIL",
                              "detail": detail, "duration_ms": 0.0, "checks": checks,
                              "policy": module_policies[mod.name]}
                    add_module_result_context(mod, record, {})
                    records.append(record)
                    continue
                policy = module_policies[mod.name]
                if isinstance(mod, BaseModule) and policy["state"] in {
                    "disabled", "not_configured", "not_installed",
                }:
                    # One local liveness sample, with no host probe or lifecycle
                    # operation while the selected policy keeps the check off.
                    worker = mod._thread
                    if worker is not None and worker.is_alive():
                        skip_detail += ". A worker thread is still alive while this policy is off."
                        checks.append({"check": "policy_runtime", "status": "SKIP",
                                       "detail": "Worker observed alive while capability is off"})
                lines.append(f"  [SKIP] {mod.name} — {skip_detail}")
                skipped += 1
                skips.append({"module": mod.name, "detail": skip_detail})
                record = {"module": mod.name, "kind": "module", "status": "SKIP",
                          "detail": skip_detail, "duration_ms": 0.0,
                          "policy": module_policies[mod.name],
                          "checks": checks + [{"check": "active_test", "status": "SKIP", "detail": skip_detail}]}
                add_module_result_context(mod, record, {})
                records.append(record)
                continue
            t_ok, t_detail = mod_results.get(
                mod.name,
                (False, "the check did not report before the drill deadline; no module result was observed"),
            )
            evidence = module_evidence.get(mod.name, {
                "duration_ms": 0.0, "checks": [], "deferred": True,
            })
            record = {"module": mod.name, "kind": "module", "status": "PASS" if t_ok else "FAIL",
                      "detail": t_detail, "duration_ms": evidence["duration_ms"],
                      "policy": module_policies[mod.name],
                      "stage_ms": dict(evidence.get("stage_ms", {})),
                      "checks": list(evidence["checks"])}
            records.append(record)
            if t_ok:
                add_module_result_context(mod, record, evidence)
                lines.append(f"  [PASS] {mod.name} — {t_detail} ({record['duration_ms']:.1f} ms; {len(record['checks'])} checks)")
                passed += 1
            else:
                failed_other_check = any(
                    check["status"] == "FAIL" and check["check"] != "active_test"
                    for check in record["checks"]
                )
                if evidence.get("deferred") or (
                    not failed_other_check and self._attestation_pending(mod, t_detail)
                ):
                    record["status"] = "DEFERRED"
                    for check in record["checks"]:
                        if check["check"] == "active_test":
                            check["status"] = "DEFERRED"
                    add_module_result_context(mod, record, evidence)
                    deferred.append({"module": mod.name, "detail": t_detail})
                    lines.append(f"  [DEFERRED] {mod.name} — {t_detail}")
                    continue
                expected_reason = None if failed_other_check else self._optional_skip_reason(
                    mod, t_detail, module_policies[mod.name],
                )
                # Contract, crash and timeout failures can never be excused by
                # a caller-supplied readiness policy.
                eligible_skip = not failed_other_check and not t_detail.startswith(
                    ("error:", "test ", "contract check failed:")
                )
                if expected_failure_cb is not None and eligible_skip and expected_reason is None:
                    try:
                        expected_reason = expected_failure_cb(mod.name, t_detail)
                    except Exception:
                        expected_reason = None
                if expected_reason:
                    record["status"] = "SKIP"
                    record["detail"] = str(expected_reason)
                    for check in record["checks"]:
                        if check["check"] == "active_test":
                            check["status"] = "SKIP"
                            check["detail"] = str(expected_reason)
                    add_module_result_context(mod, record, evidence)
                    lines.append(
                        f"  [SKIP] {mod.name} — {expected_reason}"
                    )
                    skipped += 1
                    skips.append({
                        "module": mod.name,
                        "detail": str(expected_reason),
                    })
                    continue
                lines.append(f"  [FAIL] {mod.name} — {t_detail}")
                failed += 1
                failed_modules.append(mod.name)
                plan = add_module_result_context(mod, record, evidence)
                failure = {
                    "module": mod.name,
                    "detail": t_detail,
                    "repairable": plan is not None,
                }
                if plan is not None:
                    self.last_repairs[mod.name] = plan
                    failure["repair"] = record["repair"]
                failures.append(failure)

        if failed_modules:
            sample = [str(name)[:160] for name in failed_modules[:5]]
            if len(failed_modules) == 1:
                message = f"CRITICAL FAILURE: {sample[0]} — see Self-test results for details"
            else:
                message = f"CRITICAL FAILURE: {len(failed_modules)} module checks failed"
                message += f" ({', '.join(sample)}). See Self-test results for every failure."
            notifications.append(Event("Self-Test", message, Severity.CRITICAL, details={
                **_DIAGNOSTIC_EVENT, "finding_code": "selftest.module_failures",
                "failure_count": len(failed_modules), "sample_modules": sample,
            }))

        if progress_unavailable:
            lines.append(
                "  [NOTICE] Progress callback is still running; "
                "the completed results are shown below."
            )
        
        def _publish_notifications():
            errors = []
            for event in notifications:
                try:
                    self.bus.publish(event)
                except Exception as exc:
                    errors.append(f"{type(exc).__name__}: {exc}")
            return errors

        missing = sorted(set(names or ()) - set(self.manager.modules))
        if missing:
            detail = "unknown requested modules: " + ", ".join(map(str, missing))
            failed += 1
            lines.append(f"  [FAIL] Module selection — {detail}")
            failures.append({"module": "Module selection", "detail": detail, "repairable": False})
            records.append({"module": "Module selection", "kind": "selection", "status": "FAIL",
                            "detail": detail, "duration_ms": 0.0, "checks": []})
        verification_started = time.perf_counter()
        verified, verification_detail, verification_checks = verify_harness(type(self))
        reconciled, reconciliation_detail = verify_accounting(
            records, target_names, passed, failed, skipped, len(deferred),
        )
        verification_checks.append({"check": "report reconciliation",
                                    "status": "PASS" if reconciled else "FAIL",
                                    "detail": reconciliation_detail})
        verified = verified and reconciled
        self.last_verification = {"status": "PASS" if verified else "FAIL",
                                  "detail": verification_detail + "; " + reconciliation_detail,
                                  "duration_ms": (time.perf_counter() - verification_started) * 1000,
                                  "checks": verification_checks}
        lines.append(f"  [{'VERIFY' if verified else 'FAIL'}] Harness verification — {self.last_verification['detail']}")
        if not verified:
            failed += 1
            failures.append({"module": "Harness verification", "detail": self.last_verification["detail"],
                             "repairable": False})
            records.append({"module": "Harness verification", "kind": "verification", "status": "FAIL",
                            "detail": self.last_verification["detail"],
                            "duration_ms": self.last_verification["duration_ms"], "checks": verification_checks})
        self.last_results = records
        durations = sorted((r for r in records
                            if r["kind"] == "module" and r["status"] in {"PASS", "FAIL"}),
                           key=lambda r: r["duration_ms"], reverse=True)
        self.last_metrics = {"elapsed_ms": (time.perf_counter() - started) * 1000,
                             "timing_scope": "checks and verification; excludes report I/O and notifications",
                             "module_workers": worker_count, "worker_budget": worker_reason,
                             "module_recovery_slots": reserve,
                             "module_count": len(target_modules),
                             "slowest_modules": [{"module": r["module"], "duration_ms": r["duration_ms"]}
                                                 for r in durations[:10]]}
        lines.append(f"  Timing: {self.last_metrics['elapsed_ms']:.1f} ms for checks and verification; active checks bounded to {timeout:g}s each.")
        if durations:
            lines.append("  Slowest modules: " + "; ".join(
                f"{row['module']} {row['duration_ms']:.1f} ms" for row in durations[:5]
            ))
        self.last_failures = failures
        self.last_skips = skips
        self.last_deferred = deferred
        if self._write_failure_log(passed, failed, failures, skipped, skips) is False:
            failed += 1
            detail = "diagnostic report could not be written and independently read back"
            lines.append(f"  [FAIL] Report persistence — {detail}")
            failures.append({"module": "Report persistence", "detail": detail, "repairable": False})
            records.append({"module": "Report persistence", "kind": "persistence", "status": "FAIL",
                            "detail": detail, "duration_ms": 0.0, "checks": []})
        # Only now is a terminal summary truthful: selection, canaries,
        # reconciliation and report readback have all finished.
        counts = f"{passed} passed, {failed} failed, {skipped} skipped"
        if deferred:
            counts += f", {len(deferred)} deferred (no verdict)"
        # Actual module and pipeline faults already have distinct critical
        # diagnostics. The terminal report does not duplicate those alerts.
        summary_severity = Severity.MEDIUM if failed and not notifications else Severity.INFO
        notifications.append(Event("Self-Test", f"Drill complete: {counts}.",
                                   summary_severity, details=dict(_DIAGNOSTIC_EVENT)))
        reporting_started = time.perf_counter()
        delivered, error, delivery_errors = _bounded_call(
            _publish_notifications, _EVENT_CALLS, self._REPORT_TIMEOUT,
            name="AngeronaSelfTestEventDelivery",
        )
        if not delivered or delivery_errors:
            delivery_detail = error if not delivered else "; ".join(delivery_errors)
            delivery_detail = (f"event notifications {delivery_detail}; "
                               "review this report and diagnostics/selftest_failures.json")
            lines.append(f"  [FAIL] Event reporting — {delivery_detail}")
            failed += 1
            failures.append({"module": "Event reporting", "detail": delivery_detail, "repairable": False})
            records.append({"module": "Event reporting", "kind": "reporting", "status": "FAIL",
                            "detail": delivery_detail, "duration_ms": (time.perf_counter() - reporting_started) * 1000,
                            "checks": [{"check": "notification_delivery", "status": "FAIL"}]})
            # Preserve reporting failures even if a blocked bus can never
            # deliver a corrected notification. This path is still bounded.
            if not any(f["module"] == "Report persistence" for f in failures):
                if self._write_failure_log(passed, failed, failures, skipped, skips) is False:
                    failed += 1
                    detail = "updated event-reporting failure could not be persisted and read back"
                    lines.append(f"  [FAIL] Report persistence — {detail}")
                    failures.append({"module": "Report persistence", "detail": detail, "repairable": False})
                    records.append({"module": "Report persistence", "kind": "persistence", "status": "FAIL",
                                    "detail": detail, "duration_ms": 0.0, "checks": []})
        counts = f"{passed} passed, {failed} failed, {skipped} skipped"
        if deferred:
            counts += f", {len(deferred)} deferred (no verdict)"
        lines += ["", f"Result: {counts}."]
        
        return "\n".join(lines)

    def _write_failure_log(
        self,
        passed: int,
        failed: int,
        failures: List[dict],
        skipped: int = 0,
        skips: Optional[List[dict]] = None,
    ) -> bool:
        """Persist a readable record of the last self-test so failures can be
        reviewed after the fact (diagnostics/selftest_failures.json)."""
        try:
            path = _failure_log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            document = {
                "schema": 2, "run_id": getattr(self, "run_id", None),
                "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "passed": passed, "failed": failed, "skipped": skipped,
                "deferred": len(self.last_deferred), "deferred_modules": self.last_deferred,
                "failures": failures,
                "skips": list(skips or ()),
                "results": self.last_results,
                "verification": self.last_verification,
                "metrics": self.last_metrics,
            }
            # Replace atomically so readers never consume a partial JSON file.
            temporary = path.with_name(path.name + "." + str(os.getpid()) + "." + uuid.uuid4().hex + ".tmp")
            try:
                temporary.write_text(json.dumps(document, indent=2, allow_nan=False), encoding="utf-8")
                temporary.replace(path)
                return json.loads(path.read_text(encoding="utf-8")) == document
            finally:
                temporary.unlink(missing_ok=True)
        except Exception:
            return False

    # ── helpers ──────────────────────────────────────────────────────────────
    def _worker_budget(self) -> tuple[int, str, int]:
        """Use available capacity; no new sampler, timer or polling thread."""
        cores = os.cpu_count() or 2
        budget = min(self._MAX_MODULE_WORKERS, max(1, cores // 2))
        reasons = [f"{cores} logical CPUs"]
        try:
            import psutil
            memory = psutil.virtual_memory().available
            ram_limit = max(1, int(memory // (512 * 1024 * 1024)))
            budget = min(budget, ram_limit)
            reasons.append(f"{memory // (1024 * 1024)} MiB available RAM")
        except Exception:
            budget = min(budget, 2)
            reasons.append("RAM unavailable; conservative fallback")
        hardware_limit = budget
        try:
            from angerona.core.background_pacing import get_pacing_controller
            factor = max(1, get_pacing_controller().multiplier())
            budget = max(1, int(budget // factor))
            reasons.append(f"pacing {factor}x")
        except Exception:
            budget = min(budget, 2)
            hardware_limit = budget
        return budget, "; ".join(reasons), hardware_limit

    @staticmethod
    def _attestation_pending(mod, detail: str) -> bool:
        if mod.name != "AI Triage (Ollama)":
            return False
        from angerona.modules.ai_triage import AITRIAGE_ATTESTATION_DEFERRED, AITriageModule
        return type(mod) is AITriageModule and detail == AITRIAGE_ATTESTATION_DEFERRED

    @staticmethod
    def _optional_skip_reason(mod, detail: str, policy: dict) -> Optional[str]:
        held = _deception_creation_hold_reason(mod, detail)
        if held:
            return held
        # A known optional/disabled driver can report fixture success without
        # live coverage. A selected driver's missing handle is a real failure.
        if getattr(mod, "CODE", "") == "KRNL":
            from angerona.modules.kernel_bridge import KERNEL_BRIDGE_LIVE_UNAVAILABLE, KernelBridgeModule
            if (type(mod) is KernelBridgeModule and detail == KERNEL_BRIDGE_LIVE_UNAVAILABLE
                    and policy["state"] in {"disabled", "not_installed"}):
                return detail
        return None

    def _skip_reason(
        self,
        mod,
        *,
        respect_runtime_state: bool = True,
        policy: dict | None = None,
    ) -> Optional[str]:
        """Return an expected-skip reason without exercising the module.

        Platform availability and the manager's enabled-state contract are
        authoritative.  Chill's transient pause is checked separately because
        the module remains configured as enabled while its expensive worker is
        intentionally asleep.
        """
        if policy is None:
            policy = self._module_policy(mod)
        state = policy["state"]
        if state in {"unsupported", "chill_ai"}:
            return policy["reason"]
        if respect_runtime_state and state != "enabled":
            return "disabled by operator configuration" if state == "disabled" else policy["reason"]
        return None

    def _module_policy(self, mod) -> dict:
        """Snapshot the existing selection policy without starting a worker."""
        platform = getattr(self.manager, "platform", None)
        availability = availability_for(mod, platform)
        if not availability.available:
            return ModuleUsage(False, False, False, "unsupported", availability.reason).as_dict()
        usage = None
        try:
            usage = self.manager.module_usage(mod.name)
        except (AttributeError, KeyError, TypeError):
            pass
        if not isinstance(usage, ModuleUsage):
            try:
                enabled = bool(self.manager.is_enabled(mod.name))
            except (AttributeError, KeyError, TypeError):
                enabled = True
            usage = ModuleUsage(enabled, True, enabled, "enabled" if enabled else "disabled",
                                "Enabled for this machine." if enabled else "Off in module settings.")
        policy = usage.as_dict()
        if mod.name == "AI Triage (Ollama)":
            from angerona.core.ollama_lifecycle import ollama_blocked
            if ollama_blocked():
                policy.update(state="chill_ai", reason=(
                    "local AI is off in Chill Mode; switch Chill off manually for an active check"
                ))
                return policy
        if usage.enabled and bool(getattr(mod, "_chill_paused", False)):
            policy.update(state="chill_paused", reason="paused by Chill Mode; switch to Full Mode for an active check")
        elif usage.enabled:
            hold_reason = getattr(self.manager, "module_runtime_hold_reason", None)
            if callable(hold_reason) and (reason := hold_reason(mod)):
                policy.update(state="runtime_hold", reason=reason)
        return policy

    def _pipeline_check(self) -> tuple[bool, str]:
        marker = f"selftest-{uuid.uuid4().hex}"
        mesh_required = getattr(self.bus, "mesh_required", False) is True
        subscribe = getattr(self.bus, "subscribe", None)
        unsubscribe = getattr(self.bus, "unsubscribe", None)
        if callable(subscribe) and callable(unsubscribe):
            delivered = threading.Event()
            verify = getattr(self.bus, "verify", None)
            verify_archived = getattr(self.bus, "verify_archived", None)

            def receive(event):
                if event.message != marker:
                    return
                if mesh_required:
                    # This diagnostic has no enrollment authority. Verify the
                    # exact nonce on the bus's constrained, archival advisory
                    # route, never as a live authenticated mesh producer.
                    details = event.details
                    if (event.module != "Unattributed local producer"
                            or not isinstance(details, dict)
                            or details.get("unattributed_module") != "Self-Test"
                            or details.get("response_authority") != "unattributed-advisory"
                            or details.get("disposition") != "observation"
                            or details.get("response_authorized") is not False
                            or details.get("active_attack") is not False
                            or "response_contract" in details
                            or event.mesh_sig or event.mesh_peer or not event.hmac_sig
                            or not callable(verify_archived) or verify_archived(event) is not True):
                        return
                elif event.module != "Self-Test" or (callable(verify) and verify(event) is not True):
                    return
                delivered.set()

            subscribe(receive)
            try:
                self.bus.publish(Event("Self-Test", marker, Severity.HIGH, details=dict(_DIAGNOSTIC_EVENT)))
                if delivered.wait(2.0):
                    if mesh_required:
                        return True, (
                            "synthetic advisory delivered with verified archival HMAC; "
                            "authenticated mesh producer coverage is outside this check"
                        )
                    return True, "synthetic event delivered to diagnostic subscriber"
                if mesh_required:
                    return False, "no HMAC-verified synthetic advisory delivered to diagnostic subscriber"
                return False, "event not delivered to diagnostic subscriber"
            finally:
                unsubscribe(receive)
        if mesh_required:
            return False, "mesh advisory verification requires a diagnostic subscriber"
        # Compatibility for minimal external bus adapters without a subscriber
        # lifecycle. The normal bus uses one receipt, avoiding ring-flood false
        # failures and repeated history allocations during startup.
        self.bus.publish(Event("Self-Test", marker, Severity.HIGH, details=dict(_DIAGNOSTIC_EVENT)))
        for _ in range(20):
            if any(e.message == marker for e in self.bus.recent(50)):
                return True, "synthetic event retained by adapter"
            time.sleep(0.1)
        return False, "event not delivered"

    @staticmethod
    def _test_module(
        mod, timeout: float, *, optional_kernel_policy: bool = True,
        evidence: dict | None = None, _permits=None, _capacity=None, _admission_deadline=None, _on_slow=None,
    ) -> tuple[bool, str]:
        # ``optional_kernel_policy`` is retained for API compatibility. Optional
        # prerequisites are classified as skips by run(), never successes here.
        checks = []
        stages = {}
        runtime = {}
        deferred = False

        def work():
            nonlocal deferred
            # The inspector uses this same lock, so an active inspector check
            # and an all-module drill cannot exercise one module concurrently.
            lock = module_selftest_lock(mod)
            if not lock.acquire(blocking=False):
                deferred = True
                return False, "test already running for this capability"
            try:
                stage_started = time.perf_counter()
                checks.extend(module_contract_checks(mod))
                stages["contract"] = (time.perf_counter() - stage_started) * 1000
                defects = [c for c in checks if c["status"] == "FAIL"]
                if defects:
                    return False, "contract check failed: " + "; ".join(
                        c["check"] + " — " + c["detail"] for c in defects
                    )
                runtime["runtime_before"] = runtime_evidence(mod)
                stage_started = time.perf_counter()
                try:
                    result = mod.self_test()
                finally:
                    stages["active_test"] = (time.perf_counter() - stage_started) * 1000
                valid = (isinstance(result, (tuple, list)) and len(result) == 2
                         and type(result[0]) is bool and isinstance(result[1], str)
                         and bool(result[1].strip()) and len(result[1]) <= 32_768)
                checks.append({"check": "result_contract", "status": "PASS" if valid else "FAIL",
                               "detail": "expected (bool, nonempty bounded str)"})
                if not valid:
                    return False, "error: invalid self_test result; expected (bool, nonempty bounded str)"
                ok, detail = result
                checks.append({"check": "active_test", "status": "PASS" if ok else "FAIL", "detail": detail})
                snapshot = runtime["runtime_after"] = runtime_evidence(mod)
                fault = watchdog_fault_kind(snapshot) if snapshot is not None else None
                if fault:
                    checks.append({"check": "worker_lifecycle", "status": "FAIL", "detail": fault})
                    if ok:
                        return False, f"contract check failed: worker lifecycle fault ({fault}); module check passed: {detail}"
                # Functional fixture success is not evidence that a crashed
                # running sensor is healthy. Stopped modules may legitimately
                # exercise offline classifiers, so do not invent live coverage.
                summary = getattr(mod, "health_summary", None)
                if ok and callable(summary):
                    stage_started = time.perf_counter()
                    status, health, _state = summary()
                    stages["health_consistency"] = (time.perf_counter() - stage_started) * 1000
                    consistent = status != "error" and not (status == "running" and health <= 0)
                    checks.append({"check": "health_result_consistency",
                                   "status": "PASS" if consistent else "FAIL",
                                   "detail": f"status={status}, health={health}%"})
                    if not consistent:
                        return False, "contract check failed: active test passed but module lifecycle/health reports failure"
                return ok, detail
            finally:
                lock.release()

        permits = _MODULE_CALLS if _permits is None else _permits
        if _capacity is not None:
            permits = _CapacityLease(_capacity, permits)
        completed, error, result = _bounded_call(
            work, permits, timeout,
            name=f"AngeronaSelfTestModule-{mod.name}",
            admission_deadline=_admission_deadline,
            on_slow=_on_slow,
        )
        if evidence is not None:
            # Copy after completion/timeout: late workers cannot mutate the
            # evidence already returned to a report or GUI.
            evidence["checks"] = [dict(check) for check in checks]
            evidence["stage_ms"] = dict(stages)
            if completed:
                evidence.update(runtime)
            capacity_occupied = not completed and error == "a previous call is still running"
            if (completed and deferred) or capacity_occupied:
                evidence["deferred"] = True
            if not completed:
                evidence["checks"].append({
                    "check": "bounded_completion",
                    "status": "DEFERRED" if capacity_occupied else "FAIL",
                    "detail": error,
                })
        if not completed:
            if error.startswith("timed out"):
                return False, f"test {error}"
            if error == "a previous call is still running":
                return False, (
                    "test not started: hardware worker budget or process-wide six-call cap "
                    "is occupied by unfinished checks; retry after they finish"
                )
            return False, f"error: {error}"
        ok, detail = result
        return ok, detail
