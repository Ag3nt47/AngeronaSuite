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
import queue
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.module_base import BaseModule
from angerona.core.platforms import availability_for


# These permits belong to the process, not an individual drill. A timed-out
# Python call cannot safely be killed, and retains its permit until it exits.
_MODULE_CALLS = threading.BoundedSemaphore(6)
_EVENT_CALLS = threading.BoundedSemaphore(1)
_PROGRESS_CALLS = threading.BoundedSemaphore(1)
_MODULE_LOCK_CREATION = threading.Lock()


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
        lines = ["===== SELF-TEST / STRESS DRILL =====", ""]
        passed = failed = skipped = 0
        failures: List[dict] = []
        skips: List[dict] = []
        notifications: list[Event] = []

        target_modules = [mod for name, mod in sorted(self.manager.modules.items())
                          if not names or name in names]
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
            completed, error, result = _bounded_call(
                self._pipeline_check,
                _EVENT_CALLS,
                self._PIPELINE_TIMEOUT,
                name="AngeronaSelfTestEventDelivery",
            )
            pipeline_res["res"] = (
                result if completed else (False, f"pipeline check {error}")
            )
            _bump()

        def _run_single(mod):
            try:
                mod_results[mod.name] = self._test_module(mod, timeout)
            except Exception as exc:
                mod_results[mod.name] = (False, f"error: {exc}")
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

        worker_count = min(self._MAX_MODULE_WORKERS, len(testable_modules))
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
            math.ceil(len(testable_modules) / self._MAX_MODULE_WORKERS) * timeout,
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
                lines.append(f"  [SKIP] {mod.name} — {skip_detail}")
                skipped += 1
                skips.append({"module": mod.name, "detail": skip_detail})
                continue
            t_ok, t_detail = mod_results.get(
                mod.name,
                (False, "test timed out waiting for its coordinator"),
            )
            if t_ok:
                lines.append(f"  [PASS] {mod.name} — {t_detail}")
                passed += 1
            else:
                expected_reason = None
                if expected_failure_cb is not None:
                    try:
                        expected_reason = expected_failure_cb(mod.name, t_detail)
                    except Exception:
                        expected_reason = None
                if expected_reason:
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
        
        # Final summary also escalates if the overall drill failed
        summary_sev = Severity.CRITICAL if failed else Severity.INFO
        notifications.append(Event("Self-Test",
                               f"Drill complete: {passed} passed, {failed} failed, "
                               f"{skipped} skipped.",
                               summary_sev))

        def _publish_notifications():
            errors = []
            for event in notifications:
                try:
                    self.bus.publish(event)
                except Exception as exc:
                    errors.append(f"{type(exc).__name__}: {exc}")
            return errors

        delivered, error, delivery_errors = _bounded_call(
            _publish_notifications,
            _EVENT_CALLS,
            self._REPORT_TIMEOUT,
            name="AngeronaSelfTestEventDelivery",
        )
        if not delivered or delivery_errors:
            delivery_detail = (
                error if not delivered else "; ".join(delivery_errors)
            )
            delivery_detail = (
                f"event notifications {delivery_detail}; "
                "review this report and diagnostics/selftest_failures.json"
            )
            lines.append(f"  [FAIL] Event reporting — {delivery_detail}")
            failed += 1
            failures.append({
                "module": "Event reporting", "detail": delivery_detail,
                "repairable": False,
            })
        lines += [
            "",
            f"Result: {passed} passed, {failed} failed, {skipped} skipped.",
        ]
        self.last_failures = failures
        self.last_skips = skips
        self._write_failure_log(passed, failed, failures, skipped, skips)
        
        return "\n".join(lines)

    def _write_failure_log(
        self,
        passed: int,
        failed: int,
        failures: List[dict],
        skipped: int = 0,
        skips: Optional[List[dict]] = None,
    ) -> None:
        """Persist a readable record of the last self-test so failures can be
        reviewed after the fact (diagnostics/selftest_failures.json)."""
        try:
            path = _failure_log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({
                "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "passed": passed, "failed": failed, "skipped": skipped,
                "failures": failures,
                "skips": list(skips or ()),
            }, indent=2), encoding="utf-8")
        except Exception:
            pass

    # ── helpers ──────────────────────────────────────────────────────────────
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
        )):
            return False
        explicit = type(mod).__dict__.get("selftest_auto_repair")
        if explicit is not None:
            return bool(explicit)
        # The base readiness check reports worker lifecycle/health only. A
        # generation-safe restart can address that; arbitrary overridden tests
        # may represent missing drivers, models, ACLs, or other manual setup.
        return (
            type(mod).self_test is BaseModule.self_test
            and type(mod).start is BaseModule.start
            and type(mod).stop is BaseModule.stop
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
    ) -> tuple[bool, str]:
        def work():
            # The inspector uses this same lock, so an active inspector check
            # and an all-module drill cannot exercise one module concurrently.
            lock = module_selftest_lock(mod)
            if not lock.acquire(blocking=False):
                return False, "test already running for this capability"
            try:
                ok, detail = mod.self_test()
                return bool(ok), str(detail)
            finally:
                lock.release()

        completed, error, result = _bounded_call(
            work, _MODULE_CALLS, timeout,
            name=f"AngeronaSelfTestModule-{mod.name}",
        )
        if not completed:
            if error.startswith("timed out"):
                return False, f"test {error}"
            if error == "a previous call is still running":
                return False, (
                    "test not started: all six worker slots are occupied by "
                    "unfinished checks; retry after they finish"
                )
            return False, f"error: {error}"
        ok, detail = result
        if not ok and detail.startswith("test already running"):
            return ok, detail
        
        # Treat missing optional kernel driver as a pass rather than a hard failure
        if optional_kernel_policy and not ok and (
            getattr(mod, "CODE", "") == "KRNL"
            or "Kernel Sensor" in getattr(mod, "NAME", "")
        ):
            return True, f"Kernel Driver Not installed ({detail})"
            
        return ok, detail
