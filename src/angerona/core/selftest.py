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
from angerona.core.module_base import BaseModule
from angerona.core.platforms import availability_for
from angerona.core.selftest_verification import (
    module_contract_checks, verify_accounting, verify_harness,
)


# These permits belong to the process, not an individual drill. A timed-out
# Python call cannot safely be killed, and retains its permit until it exits.
_MODULE_CALLS = threading.BoundedSemaphore(6)
_EVENT_CALLS = threading.BoundedSemaphore(1)
_PROGRESS_CALLS = threading.BoundedSemaphore(1)
_MODULE_LOCK_CREATION = threading.Lock()


class _CapacityLease:
    """Retain both hardware and process capacity until the actual call exits."""
    def __init__(self, capacity, process):
        self.capacity, self.process = capacity, process

    def acquire(self, blocking=False):
        if not self.capacity.acquire(blocking=blocking):
            return False
        if not self.process.acquire(blocking=blocking):
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


def run_module_selftest(mod, timeout: float = 15.0) -> tuple[bool, str]:
    """Run one inspector check under the drill's shared limits and lock."""
    timeout = float(timeout)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("self-test timeout must be positive and finite")
    return SelfTestRunner._test_module(mod, timeout, optional_kernel_policy=False)


def _bounded_call(callback, permits, timeout: float, *, name: str):
    """Return without abandoning an unlimited number of blocked callbacks."""
    if not permits.acquire(blocking=False):
        return False, "a previous call is still running", None
    completed = threading.Event()
    result: dict = {}

    def work():
        try:
            result["value"] = callback()
        except BaseException as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            permits.release()
            completed.set()

    worker = threading.Thread(target=work, name=name, daemon=True)
    try:
        worker.start()
    except Exception:
        permits.release()
        raise
    if not completed.wait(timeout):
        return False, f"timed out after {timeout:g}s; the call is still running", None
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

    def __init__(self, manager, bus: EventBus) -> None:
        self.manager = manager
        self.bus = bus
        # Populated by run(): actionable failures from the last run.
        self.last_failures: List[dict] = []
        # Expected non-results are kept separate so the GUI never offers to
        # "repair" a sensor for another operating system, an operator-disabled
        # module, or a deep scanner intentionally parked by Chill Mode.
        self.last_skips: List[dict] = []
        self.last_results: List[dict] = []
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
        started = time.monotonic()
        self.run_id = uuid.uuid4().hex
        self.last_results = []
        self.last_verification = {}
        self.last_metrics = {}
        lines = ["===== SELF-TEST / STRESS DRILL =====", ""]
        passed = failed = skipped = 0
        failures: List[dict] = []
        skips: List[dict] = []
        notifications: list[Event] = []
        records: list[dict] = []

        target_names = [name for name in sorted(self.manager.modules) if not names or name in names]
        target_modules = [self.manager.modules[name] for name in target_names]
        targeted = bool(names)
        skip_reasons = {
            mod.name: reason
            for mod in target_modules
            if (
                reason := self._skip_reason(
                    mod,
                    respect_runtime_state=not targeted,
                )
            ) is not None
        }
        testable_modules = [
            mod for mod in target_modules if mod.name not in skip_reasons
        ]
        worker_limit, worker_reason = self._worker_budget()
        worker_count = min(worker_limit, len(testable_modules))
        run_capacity = threading.BoundedSemaphore(max(1, worker_count))
        lines.append(f"  Resource budget: {worker_count} module worker(s); {worker_reason}")
        lines.append("  Checks: identity, diagnostic contract, local health, bounded active test, timing, verification.")
        module_evidence: dict = {}
        pipeline_timing: dict = {}

        # Bound concurrent active checks. The old one-thread-per-module fanout
        # could briefly create 120+ threads and saturate an otherwise idle host.
        # A small daemon pool preserves parallelism without a scan stampede.
        pipeline_res: dict = {}
        mod_results: dict = {}

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
            began = time.monotonic()
            completed, error, result = _bounded_call(
                self._pipeline_check,
                _EVENT_CALLS,
                self._PIPELINE_TIMEOUT,
                name="AngeronaSelfTestEventDelivery",
            )
            pipeline_res["res"] = (
                result if completed else (False, f"pipeline check {error}")
            )
            pipeline_timing["duration_ms"] = (time.monotonic() - began) * 1000
            _bump()

        def _run_single(mod):
            began = time.monotonic()
            evidence = {"checks": []}
            try:
                mod_results[mod.name] = self._test_module(
                    mod, timeout, evidence=evidence, _capacity=run_capacity,
                )
            except Exception as exc:
                mod_results[mod.name] = (False, f"error: {exc}")
            evidence["duration_ms"] = (time.monotonic() - began) * 1000
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
            while True:
                mod = module_queue.get()
                if mod is None:
                    return
                _run_single(mod)

        for index in range(worker_count):
            module_queue.put(None)
            t = threading.Thread(
                target=_module_worker,
                name=f"AngeronaSelfTest-{index + 1}",
                daemon=True,
            )
            t.start()
            threads.append(t)

        # Expected skips count as completed work for the progress indicator,
        # but deliberately never execute the module's active test.
        for _mod in skip_reasons:
            _bump()

        # Only coordinator threads are joined here. Actual module and bus calls
        # keep process-wide permits after timeout, preventing repeated drills
        # from accumulating hung work. No callback receives an unbounded join.
        deadline = time.monotonic() + max(
            self._PIPELINE_TIMEOUT,
            math.ceil(len(testable_modules) / max(1, worker_count)) * timeout,
        ) + 1.0
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))
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
                                   Severity.CRITICAL))

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
                    failures.append({"module": mod.name, "detail": detail, "repairable": False})
                    records.append({"module": mod.name, "kind": "module", "status": "FAIL",
                                    "detail": detail, "duration_ms": 0.0, "checks": checks})
                    continue
                lines.append(f"  [SKIP] {mod.name} — {skip_detail}")
                skipped += 1
                skips.append({"module": mod.name, "detail": skip_detail})
                records.append({"module": mod.name, "kind": "module", "status": "SKIP",
                                "detail": skip_detail, "duration_ms": 0.0,
                                "checks": checks + [{"check": "active_test", "status": "SKIP", "detail": skip_detail}]})
                continue
            t_ok, t_detail = mod_results.get(
                mod.name,
                (False, "test timed out waiting for its coordinator"),
            )
            evidence = module_evidence.get(mod.name, {"duration_ms": 0.0, "checks": []})
            record = {"module": mod.name, "kind": "module", "status": "PASS" if t_ok else "FAIL",
                      "detail": t_detail, "duration_ms": evidence["duration_ms"],
                      "checks": list(evidence["checks"])}
            records.append(record)
            if t_ok:
                lines.append(f"  [PASS] {mod.name} — {t_detail} ({record['duration_ms']:.1f} ms; {len(record['checks'])} checks)")
                passed += 1
            else:
                expected_reason = self._optional_skip_reason(mod, t_detail)
                # Contract, crash and timeout failures can never be excused by
                # a caller-supplied readiness policy.
                eligible_skip = not t_detail.startswith(("error:", "test ", "contract check failed:"))
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
                failures.append({
                    "module": mod.name,
                    "detail": t_detail,
                    "repairable": self._is_repairable(mod, t_detail),
                })
                # CRITICAL WHEN NEEDED: Elevate failed defense shields to maximum severity
                notifications.append(Event("Self-Test",
                                       f"CRITICAL FAILURE: {mod.name} — {t_detail}", 
                                       Severity.CRITICAL))

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
        verification_started = time.monotonic()
        verified, verification_detail, verification_checks = verify_harness(type(self))
        reconciled, reconciliation_detail = verify_accounting(
            records, target_names, passed, failed, skipped,
        )
        verification_checks.append({"check": "report reconciliation",
                                    "status": "PASS" if reconciled else "FAIL",
                                    "detail": reconciliation_detail})
        verified = verified and reconciled
        self.last_verification = {"status": "PASS" if verified else "FAIL",
                                  "detail": verification_detail + "; " + reconciliation_detail,
                                  "duration_ms": (time.monotonic() - verification_started) * 1000,
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
        durations = sorted((r for r in records if r["kind"] == "module"),
                           key=lambda r: r["duration_ms"], reverse=True)
        self.last_metrics = {"elapsed_ms": (time.monotonic() - started) * 1000,
                             "timing_scope": "checks and verification; excludes report I/O and notifications",
                             "module_workers": worker_count, "worker_budget": worker_reason,
                             "module_count": len(target_modules),
                             "slowest_modules": [{"module": r["module"], "duration_ms": r["duration_ms"]}
                                                 for r in durations[:10]]}
        lines.append(f"  Timing: {self.last_metrics['elapsed_ms']:.1f} ms for checks and verification; active checks bounded to {timeout:g}s each.")
        self.last_failures = failures
        self.last_skips = skips
        if self._write_failure_log(passed, failed, failures, skipped, skips) is False:
            failed += 1
            detail = "diagnostic report could not be written and independently read back"
            lines.append(f"  [FAIL] Report persistence — {detail}")
            failures.append({"module": "Report persistence", "detail": detail, "repairable": False})
            records.append({"module": "Report persistence", "kind": "persistence", "status": "FAIL",
                            "detail": detail, "duration_ms": 0.0, "checks": []})
        # Only now is a terminal summary truthful: selection, canaries,
        # reconciliation and report readback have all finished.
        notifications.append(Event("Self-Test",
                                   f"Drill complete: {passed} passed, {failed} failed, {skipped} skipped.",
                                   Severity.CRITICAL if failed else Severity.INFO))
        reporting_started = time.monotonic()
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
                            "detail": delivery_detail, "duration_ms": (time.monotonic() - reporting_started) * 1000,
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
        lines += ["", f"Result: {passed} passed, {failed} failed, {skipped} skipped."]
        
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
    def _worker_budget(self) -> tuple[int, str]:
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
        try:
            from angerona.core.background_pacing import get_pacing_controller
            factor = max(1, get_pacing_controller().multiplier())
            budget = max(1, int(budget // factor))
            reasons.append(f"pacing {factor}x")
        except Exception:
            budget = min(budget, 2)
        return budget, "; ".join(reasons)

    @staticmethod
    def _optional_skip_reason(mod, detail: str) -> Optional[str]:
        # Only the explicitly absent optional driver is an expected skip.
        # A handshake, integrity, exception or timeout failure remains visible.
        if getattr(mod, "CODE", "") == "KRNL" and detail == "AngeronaSensor.sys driver not loaded":
            return "optional kernel driver not loaded; kernel protection was not tested"
        return None

    def _skip_reason(
        self,
        mod,
        *,
        respect_runtime_state: bool = True,
    ) -> Optional[str]:
        """Return an expected-skip reason without exercising the module.

        Platform availability and the manager's enabled-state contract are
        authoritative.  Chill's transient pause is checked separately because
        the module remains configured as enabled while its expensive worker is
        intentionally asleep.
        """
        platform = getattr(self.manager, "platform", None)
        availability = availability_for(mod, platform)
        if not availability.available:
            return availability.reason

        if respect_runtime_state:
            try:
                enabled = bool(self.manager.is_enabled(mod.name))
            except (AttributeError, KeyError, TypeError):
                enabled = True
            if not enabled:
                return "disabled by operator configuration"
            if bool(getattr(mod, "_chill_paused", False)):
                return "paused by Chill Mode; switch to Full Mode for an active check"
        return None

    @staticmethod
    def _is_repairable(mod, detail: str) -> bool:
        """Allow automatic restart only for audited lifecycle failures."""
        if str(detail).casefold().startswith((
            "test timed out", "test not started", "test already running",
            "contract check failed:", "error: invalid self_test result",
        )):
            return False
        explicit = type(mod).__dict__.get("selftest_auto_repair")
        if explicit is not None:
            return bool(explicit)
        # The base readiness check reports worker lifecycle/health only. A
        # generation-safe restart can address that; arbitrary overridden tests
        # may represent missing drivers, models, ACLs, or other manual setup.
        return (
            getattr(type(mod), "self_test", None) is BaseModule.self_test
            and getattr(type(mod), "start", None) is BaseModule.start
            and getattr(type(mod), "stop", None) is BaseModule.stop
        )

    def _pipeline_check(self) -> tuple[bool, str]:
        marker = f"selftest-{time.time()}"
        # Use HIGH severity to bypass EventBus INFO backpressure dropping under load
        self.bus.publish(Event("Self-Test", marker, Severity.HIGH))
        
        # Poll for up to 2 seconds to allow async delivery, checking a wider
        # window (50) in case other modules are flooding the bus during startup.
        for _ in range(20):
            if any(e.message == marker for e in self.bus.recent(50)):
                return True, "synthetic event delivered"
            time.sleep(0.1)
            
        return False, "event not delivered"

    @staticmethod
    def _test_module(
        mod, timeout: float, *, optional_kernel_policy: bool = True,
        evidence: dict | None = None, _permits=None, _capacity=None,
    ) -> tuple[bool, str]:
        # ``optional_kernel_policy`` is retained for API compatibility. Optional
        # prerequisites are classified as skips by run(), never successes here.
        checks = []

        def work():
            # The inspector uses this same lock, so an active inspector check
            # and an all-module drill cannot exercise one module concurrently.
            lock = module_selftest_lock(mod)
            if not lock.acquire(blocking=False):
                return False, "test already running for this capability"
            try:
                checks.extend(module_contract_checks(mod))
                defects = [c for c in checks if c["status"] == "FAIL"]
                if defects:
                    return False, "contract check failed: " + "; ".join(
                        c["check"] + " — " + c["detail"] for c in defects
                    )
                result = mod.self_test()
                valid = (isinstance(result, (tuple, list)) and len(result) == 2
                         and type(result[0]) is bool and isinstance(result[1], str)
                         and bool(result[1].strip()) and len(result[1]) <= 32_768)
                checks.append({"check": "result_contract", "status": "PASS" if valid else "FAIL",
                               "detail": "expected (bool, nonempty bounded str)"})
                if not valid:
                    return False, "error: invalid self_test result; expected (bool, nonempty bounded str)"
                ok, detail = result
                checks.append({"check": "active_test", "status": "PASS" if ok else "FAIL", "detail": detail})
                # Functional fixture success is not evidence that a crashed
                # running sensor is healthy. Stopped modules may legitimately
                # exercise offline classifiers, so do not invent live coverage.
                summary = getattr(mod, "health_summary", None)
                if ok and callable(summary):
                    status, health, _state = summary()
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
        )
        if evidence is not None:
            # Copy after completion/timeout: late workers cannot mutate the
            # evidence already returned to a report or GUI.
            evidence["checks"] = [dict(check) for check in checks]
            if not completed:
                evidence["checks"].append({"check": "bounded_completion", "status": "FAIL", "detail": error})
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
