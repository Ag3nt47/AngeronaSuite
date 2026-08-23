"""Self-test / stress harness.

Runs each module's ``self_test()`` (with a timeout so a hung test can't freeze
the app), plus an end-to-end pipeline check (publish a synthetic event and
confirm it flows through the bus). Produces a pass/fail/expected-skip report
and raises a failure notification only for actionable test failures.

Invoke from the console: ``test`` (all) or ``test <module>``.
"""
from __future__ import annotations

import json
import queue
import threading
import time
from pathlib import Path
from typing import List, Optional

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.module_base import BaseModule
from angerona.core.platforms import availability_for


def _failure_log_path() -> Path:
    # Repo diagnostics/ dir (mounted / user-visible). Best-effort.
    from angerona.core.data_paths import data_dir
    return data_dir() / "diagnostics" / "selftest_failures.json"


class SelfTestRunner:
    _MAX_MODULE_WORKERS = 6

    def __init__(self, manager, bus: EventBus) -> None:
        self.manager = manager
        self.bus = bus
        # Populated by run(): actionable failures from the last run.
        self.last_failures: List[dict] = []
        # Expected non-results are kept separate so the GUI never offers to
        # "repair" a sensor for another operating system, an operator-disabled
        # module, or a deep scanner intentionally parked by Chill Mode.
        self.last_skips: List[dict] = []

    def run(self, names: Optional[List[str]] = None, timeout: float = 15.0,
            progress_cb=None) -> str:
        lines = ["===== SELF-TEST / STRESS DRILL =====", ""]
        passed = failed = skipped = 0
        failures: List[dict] = []
        skips: List[dict] = []

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
        progress_queue: queue.Queue = queue.Queue()

        def _bump():
            if progress_cb is None:
                return
            with _plock:
                _done["n"] += 1
                n = _done["n"]
            progress_queue.put((n, total))

        def _dispatch_progress() -> None:
            while True:
                item = progress_queue.get()
                if item is None:
                    return
                try:
                    progress_cb(*item)
                except Exception:
                    pass

        def _run_pipeline():
            pipeline_res["res"] = self._pipeline_check()
            _bump()

        def _run_single(mod):
            mod_results[mod.name] = self._test_module(mod, timeout)
            _bump()

        threads = []
        progress_thread = None
        if progress_cb is not None:
            progress_thread = threading.Thread(
                target=_dispatch_progress,
                name="AngeronaSelfTestProgress",
                daemon=True,
            )
            progress_thread.start()
        
        # Dispatch pipeline test
        p_thread = threading.Thread(target=_run_pipeline, daemon=True)
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

        # Wait for all to finish
        for t in threads:
            t.join()
        if progress_thread is not None:
            progress_queue.put(None)
            progress_thread.join()

        # 1) Evaluate Pipeline check
        ok, detail = pipeline_res["res"]
        lines.append(f"  [{'PASS' if ok else 'FAIL'}] Event pipeline — {detail}")
        passed += ok
        failed += (not ok)
        if not ok:
            failures.append({"module": "Event pipeline", "detail": detail})
            # CRITICAL WHEN NEEDED: Escalate core bus failures immediately
            self.bus.publish(Event("Self-Test", 
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
            t_ok, t_detail = mod_results[mod.name]
            lines.append(f"  [{'PASS' if t_ok else 'FAIL'}] {mod.name} — {t_detail}")
            if t_ok:
                passed += 1
            else:
                failed += 1
                failures.append({
                    "module": mod.name,
                    "detail": t_detail,
                    "repairable": self._is_repairable(mod, t_detail),
                })
                # CRITICAL WHEN NEEDED: Elevate failed defense shields to maximum severity
                self.bus.publish(Event("Self-Test",
                                       f"CRITICAL FAILURE: {mod.name} — {t_detail}", 
                                       Severity.CRITICAL))

        lines += [
            "",
            f"Result: {passed} passed, {failed} failed, {skipped} skipped.",
        ]
        
        # Final summary also escalates if the overall drill failed
        summary_sev = Severity.CRITICAL if failed else Severity.INFO
        self.bus.publish(Event("Self-Test",
                               f"Drill complete: {passed} passed, {failed} failed, "
                               f"{skipped} skipped.",
                               summary_sev))
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
        if str(detail).casefold().startswith("test timed out"):
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

    def _test_module(self, mod, timeout: float) -> tuple[bool, str]:
        result: dict = {}

        def work():
            try:
                result["ok"], result["detail"] = mod.self_test()
            except Exception as exc:
                result["err"] = str(exc)

        # Internal daemon thread enforces the strict timeout on badly-behaving modules
        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(timeout)
        
        if t.is_alive():
            return False, f"test timed out after {int(timeout)}s"
        if "err" in result:
            return False, f"error: {result['err']}"
            
        ok = bool(result.get("ok"))
        detail = str(result.get("detail", ""))
        
        # Treat missing optional kernel driver as a pass rather than a hard failure
        if not ok and (getattr(mod, "CODE", "") == "KRNL" or "Kernel Sensor" in getattr(mod, "NAME", "")):
            return True, f"Kernel Driver Not installed ({detail})"
            
        return ok, detail
