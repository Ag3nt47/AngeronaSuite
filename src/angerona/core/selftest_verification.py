"""Independent, offline evidence checks for the self-test harness.

These checks exercise the actual bounded module-call path with inert fixtures.
They prove failure detection and accounting, not real sensor coverage.
"""
from __future__ import annotations

import math
import threading
import time
from types import SimpleNamespace

from angerona.core.module_base import BaseModule
from angerona.core.platforms import KNOWN_PLATFORMS


def module_contract_checks(mod, *, include_health: bool = True) -> list[dict]:
    """Inspect cheap local contracts; never start a module or probe a service."""
    checks = []
    name = getattr(mod, "name", None)
    checks.append({
        "check": "identity", "status": "PASS" if (
            isinstance(name, str) and bool(name.strip()) and len(name) <= 256
        ) else "FAIL", "detail": "nonempty bounded module name required",
    })
    checks.append({
        "check": "self_test_callable",
        "status": "PASS" if callable(getattr(mod, "self_test", None)) else "FAIL",
        "detail": "callable module diagnostic required",
    })
    if isinstance(mod, BaseModule):
        declared = getattr(mod, "supported_platforms", ())
        valid_platforms = isinstance(declared, (tuple, list, set, frozenset)) and bool(declared)
        valid_platforms = valid_platforms and all(p in KNOWN_PLATFORMS for p in declared)
        valid_metadata = all(isinstance(getattr(mod, key, None), str)
                             and bool(getattr(mod, key).strip())
                             and len(getattr(mod, key)) <= 256 for key in ("version", "category"))
        checks.append({"check": "capability_metadata", "status": "PASS" if (
            valid_platforms and valid_metadata and callable(getattr(mod, "start", None))
            and callable(getattr(mod, "stop", None))
        ) else "FAIL", "detail": "version, category, declared platforms and lifecycle entry points"})
    # Fake/third-party modules may not implement BaseModule's health API.
    # A skip accurately distinguishes that from a checked health snapshot.
    summary = getattr(mod, "health_summary", None)
    if not include_health or not callable(summary):
        checks.append({"check": "health_contract", "status": "SKIP",
                       "detail": "active health probe skipped by availability policy" if not include_health
                       else "module does not expose the base health API"})
        return checks
    try:
        status, health, state = summary()
        valid = (
            isinstance(status, str) and bool(status.strip())
            and type(health) is int and 0 <= health <= 100
            and state in {"off", "failed", "ok", "degraded", "critical"}
        )
        if not valid:
            raise ValueError("invalid lifecycle/health snapshot")
        expected_state = ("off" if status == "stopped" else
                          "failed" if status == "error" or health <= 0 else
                          "ok" if health >= 90 else "degraded" if health >= 50 else "critical")
        if state != expected_state:
            raise ValueError(f"inconsistent health state: {state}; expected {expected_state}")
        checks.append({"check": "health_contract", "status": "PASS",
                       "detail": f"status={status}, health={health}%, state={state}"})
    except Exception as exc:
        checks.append({"check": "health_contract", "status": "FAIL",
                       "detail": f"{type(exc).__name__}: {exc}"[:1000]})
    return checks


def verify_accounting(results: list[dict], expected_modules: list[str],
                      passed: int, failed: int, skipped: int) -> tuple[bool, str]:
    """Reconcile independently assembled evidence against public counters."""
    if len(expected_modules) != len(set(expected_modules)):
        return False, "duplicate module identities in selection"
    modules = [row["module"] for row in results if row["kind"] == "module"]
    if sorted(modules) != sorted(expected_modules):
        return False, "module result coverage differs from requested inventory"
    observed = {status: sum(row["status"] == status for row in results)
                for status in ("PASS", "FAIL", "SKIP")}
    if (observed["PASS"], observed["FAIL"], observed["SKIP"]) != (passed, failed, skipped):
        return False, "result totals do not reconcile with individual evidence"
    if sum(observed.values()) != len(results):
        return False, "unknown result status"
    for row in results:
        elapsed = row.get("duration_ms")
        if not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0:
            return False, "missing or invalid timing evidence"
        checks = row.get("checks", ())
        if row["status"] in {"PASS", "SKIP"} and any(
            check.get("status") == "FAIL" for check in checks
        ):
            return False, "failed subcheck was hidden by a successful or skipped result"
    return True, f"{len(modules)}/{len(expected_modules)} modules accounted for; totals and subchecks reconcile"


def verify_harness(runner_type) -> tuple[bool, str, list[dict]]:
    """Inject deterministic defects through the production result validator.

    A private permit bounds canary calls without occupying the live module
    budget. The timeout fixture is always released and joined before return.
    """
    checks = []
    permits = threading.BoundedSemaphore(1)

    def probe(label, callback, expected, fragment=""):
        mod = SimpleNamespace(name=f"Verification {label}", self_test=callback)
        started = time.monotonic()
        ok, detail = runner_type._test_module(
            mod, 2.0, optional_kernel_policy=False, _permits=permits,
        )
        valid = ok is expected and fragment in detail
        checks.append({"check": label, "status": "PASS" if valid else "FAIL",
                       "detail": detail, "duration_ms": (time.monotonic() - started) * 1000})

    probe("success canary", lambda: (True, "canary ready"), True, "canary ready")
    probe("failure canary", lambda: (False, "canary defect"), False, "canary defect")

    def raises():
        raise RuntimeError("canary exception")

    probe("exception canary", raises, False, "canary exception")
    probe("malformed-result canary", lambda: ("False", "invalid truthy result"),
          False, "invalid self_test result")
    release, entered, exited = threading.Event(), threading.Event(), threading.Event()

    def blocked():
        entered.set()
        try:
            release.wait(2.0)
            return True, "released canary"
        finally:
            exited.set()

    mod = SimpleNamespace(name="Verification timeout", self_test=blocked)
    try:
        ok, detail = runner_type._test_module(
            mod, 0.02, optional_kernel_policy=False, _permits=permits,
        )
        valid = not ok and detail.startswith("test timed out")
        checks.append({"check": "timeout canary", "status": "PASS" if valid else "FAIL",
                       "detail": detail})
    finally:
        release.set()
        if not entered.wait(2.0) or not exited.wait(2.0):
            checks.append({"check": "timeout cleanup", "status": "FAIL",
                           "detail": "canary worker did not exit within its cleanup deadline"})
        elif permits.acquire(timeout=2.0):
            permits.release()
        else:
            checks.append({"check": "timeout permit cleanup", "status": "FAIL",
                           "detail": "canary retained its worker permit after returning"})

    stopped = SimpleNamespace(name="Verification disabled", supported_platforms=("windows",))
    manager = SimpleNamespace(platform="windows", modules={stopped.name: stopped},
                              is_enabled=lambda _name: False)
    policy = runner_type(manager, None)
    reason = policy._skip_reason(stopped)
    checks.append({"check": "disabled skip canary",
                   "status": "PASS" if reason == "disabled by operator configuration" else "FAIL",
                   "detail": str(reason)})
    stopped.supported_platforms = ("linux",)
    reason = policy._skip_reason(stopped, respect_runtime_state=False)
    checks.append({"check": "platform skip canary",
                   "status": "PASS" if reason and reason.startswith("Unavailable on windows") else "FAIL",
                   "detail": str(reason)})
    corrupted = [{"module": "canary", "kind": "module", "status": "PASS",
                  "duration_ms": 0.0, "checks": []}]
    rejected, _ = verify_accounting(corrupted, ["canary"], 0, 1, 0)
    checks.append({"check": "corrupt-accounting canary",
                   "status": "PASS" if not rejected else "FAIL",
                   "detail": "deliberately incorrect totals must be rejected"})
    ok = all(check["status"] == "PASS" for check in checks)
    return ok, f"{sum(c['status'] == 'PASS' for c in checks)}/{len(checks)} controlled verification checks passed", checks
