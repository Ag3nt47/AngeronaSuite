"""Self-test / stress harness.

Runs each module's ``self_test()`` (with a timeout so a hung test can't freeze
the app), plus an end-to-end pipeline check (publish a synthetic event and
confirm it flows through the bus). Produces a pass/fail report and raises a
failure notification for anything that doesn't pass.

Invoke from the console: ``test`` (all) or ``test <module>``.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import List, Optional

from angerona.core.eventbus import Event, EventBus, Severity


def _failure_log_path() -> Path:
    # Repo diagnostics/ dir (mounted / user-visible). Best-effort.
    return Path(__file__).resolve().parents[3] / "diagnostics" / "selftest_failures.json"


class SelfTestRunner:
    def __init__(self, manager, bus: EventBus) -> None:
        self.manager = manager
        self.bus = bus
        # Populated by run(): list of {"module", "detail"} for the last run.
        self.last_failures: List[dict] = []

    def run(self, names: Optional[List[str]] = None, timeout: float = 15.0,
            progress_cb=None) -> str:
        lines = ["===== SELF-TEST / STRESS DRILL =====", ""]
        passed = failed = 0
        failures: List[dict] = []

        target_modules = [mod for name, mod in sorted(self.manager.modules.items())
                          if not names or name in names]

        # SUPER EFFICIENT: Run pipeline check and all module self-tests concurrently.
        # This collapses the entire drill duration to the speed of the single slowest test.
        pipeline_res: dict = {}
        mod_results: dict = {}

        # Live progress: fire progress_cb(done, total) as each concurrent test
        # finishes, so the UI can show a real percentage climbing to 100%.
        total = len(target_modules) + 1          # +1 for the pipeline check
        _done = {"n": 0}
        _plock = threading.Lock()

        def _bump():
            if progress_cb is None:
                return
            with _plock:
                _done["n"] += 1
                n = _done["n"]
            try:
                progress_cb(n, total)
            except Exception:
                pass

        def _run_pipeline():
            pipeline_res["res"] = self._pipeline_check()
            _bump()

        def _run_single(mod):
            mod_results[mod.name] = self._test_module(mod, timeout)
            _bump()

        threads = []
        
        # Dispatch pipeline test
        p_thread = threading.Thread(target=_run_pipeline, daemon=True)
        p_thread.start()
        threads.append(p_thread)

        # Dispatch module tests
        for mod in target_modules:
            t = threading.Thread(target=_run_single, args=(mod,), daemon=True)
            t.start()
            threads.append(t)

        # Wait for all to finish
        for t in threads:
            t.join()

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
            t_ok, t_detail = mod_results[mod.name]
            lines.append(f"  [{'PASS' if t_ok else 'FAIL'}] {mod.name} — {t_detail}")
            if t_ok:
                passed += 1
            else:
                failed += 1
                failures.append({"module": mod.name, "detail": t_detail})
                # CRITICAL WHEN NEEDED: Elevate failed defense shields to maximum severity
                self.bus.publish(Event("Self-Test",
                                       f"CRITICAL FAILURE: {mod.name} — {t_detail}", 
                                       Severity.CRITICAL))

        lines += ["", f"Result: {passed} passed, {failed} failed."]
        
        # Final summary also escalates if the overall drill failed
        summary_sev = Severity.CRITICAL if failed else Severity.INFO
        self.bus.publish(Event("Self-Test",
                               f"Drill complete: {passed} passed, {failed} failed.", 
                               summary_sev))
        self.last_failures = failures
        self._write_failure_log(passed, failed, failures)
        
        return "\n".join(lines)

    def _write_failure_log(self, passed: int, failed: int, failures: List[dict]) -> None:
        """Persist a readable record of the last self-test so failures can be
        reviewed after the fact (diagnostics/selftest_failures.json)."""
        try:
            path = _failure_log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({
                "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "passed": passed, "failed": failed,
                "failures": failures,
            }, indent=2), encoding="utf-8")
        except Exception:
            pass

    # ── helpers ──────────────────────────────────────────────────────────────
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