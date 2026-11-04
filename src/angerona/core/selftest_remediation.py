"""Module test evidence and generation-bound, operator-approved recovery."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

from angerona.core.module_base import BaseModule, watchdog_fault_kind
from angerona.core.platforms import availability_for


@dataclass(frozen=True)
class ModuleRecovery:
    name: str
    module: BaseModule
    generation: int
    fault: str


def runtime_evidence(module) -> dict | None:
    """Sample the exact worker and completed work without probing the host."""
    if not isinstance(module, BaseModule):
        return None
    snapshot = module.try_watchdog_snapshot()
    if snapshot is None:
        return None
    fields = (
        "status", "health", "health_state", "health_note", "thread_alive",
        "lifecycle_generation", "first_cycle_complete", "cycle_count",
        "last_cycle_age_seconds", "watchdog_deadline_missed", "event_overflow_count",
    )
    return {key: snapshot[key] for key in fields}


def _uses_managed_recovery(module) -> bool:
    cls = type(module)
    return (
        isinstance(module, BaseModule)
        and getattr(module, "_angerona_origin", "builtin") == "builtin"
        and getattr(module, "response_authority", "none") == "none"
        and not getattr(module, "high_risk_permissions", ())
        and cls.__dict__.get("selftest_auto_repair") is not False
        and cls.start is BaseModule.start and cls.stop is BaseModule.stop
        and cls.restart_faulted_generation is BaseModule.restart_faulted_generation
    )


def recovery_setting_key(module) -> str:
    """An opt-in binds to a reviewed bundled capability ID, never its label."""
    key = getattr(getattr(module, "_angerona_contract", None), "capability_id", "")
    if type(key) is str and re.fullmatch(r"angerona\.builtin\.[a-z0-9_]{1,80}", key) and _uses_managed_recovery(module):
        return key
    return ""


def auto_recovery_allowed(config, plan: ModuleRecovery) -> bool:
    choices = getattr(config, "selftest_auto_recover_modules", ())
    key = recovery_setting_key(plan.module)
    return bool(key and type(choices) is list and key in choices)


def add_module_result_context(module, record: dict, evidence: dict) -> ModuleRecovery | None:
    """Attach display data to any result and create a live plan for a proven fault."""
    from angerona.core.selftest_guidance import module_guidance

    if isinstance(module, BaseModule):
        record["guidance"] = module_guidance(module)
        record["scope"] = "readiness" if type(module).self_test is BaseModule.self_test else "module diagnostic"
        record["requirements"] = list(availability_for(module).requirements)
    before, after = evidence.get("runtime_before"), evidence.get("runtime_after")
    if after is None:
        return None
    record["runtime"] = after
    generation = after["lifecycle_generation"]
    fault = watchdog_fault_kind(after)
    if (record["status"] != "FAIL" or record.get("policy", {}).get("state", "enabled") != "enabled"
            or getattr(module, "_chill_paused", False) or not fault or generation < 1 or before is None
            or before["lifecycle_generation"] != generation or not _uses_managed_recovery(module)):
        return None
    record["repair"] = {"action": "restart_faulted_worker", "generation": generation, "fault": fault}
    return ModuleRecovery(module.name, module, generation, fault)


def _is_selected(manager, plan: ModuleRecovery) -> bool:
    hold_reason = getattr(manager, "module_runtime_hold_reason", None)
    return (manager.modules.get(plan.name) is plan.module
            and manager.is_enabled(plan.name)
            and not getattr(plan.module, "_chill_paused", False)
            and not getattr(manager, "ugcap_paused", False)
            and not (callable(hold_reason) and hold_reason(plan.module)))


def recover_module(manager, plan: ModuleRecovery, *, startup_timeout: float = 5.0) -> tuple[bool, str]:
    """Restart only a still-faulty generation, then verify its replacement."""
    from angerona.core.selftest import module_selftest_lock, run_module_selftest

    module = plan.module
    lock = module_selftest_lock(module)
    if not lock.acquire(blocking=False):
        return False, "A module diagnostic is still running. No restart requested."
    try:
        current = runtime_evidence(module)
        if (not _uses_managed_recovery(module) or not _is_selected(manager, plan)
                or current is None or current["lifecycle_generation"] != plan.generation
                or watchdog_fault_kind(current) != plan.fault):
            return False, "The worker, fault, or enablement changed. Run a fresh check."
        if not manager.restart_faulted_module_generation(plan.name, module, plan.generation):
            return False, "The manager held the restart. Review module policy and rerun its check."
    finally:
        lock.release()

    expected = plan.generation + 1
    deadline = time.monotonic() + startup_timeout
    while time.monotonic() < deadline:
        current = runtime_evidence(module)
        if not _is_selected(manager, plan) or (current and current["lifecycle_generation"] > expected):
            return False, "Restart was accepted, but the worker or enablement changed during verification."
        if current and current["lifecycle_generation"] == expected:
            if watchdog_fault_kind(current):
                return False, "The replacement worker reported a lifecycle fault."
            if current["first_cycle_complete"]:
                break
        time.sleep(0.05)
    else:
        return False, "Restart was accepted. The replacement has yet to complete its first cycle."

    config = getattr(manager, "config", None)
    ok, detail = run_module_selftest(module, timeout=getattr(config, "selftest_timeout_seconds", 30))
    current = runtime_evidence(module)
    if (current is None or current["lifecycle_generation"] != expected
            or current["status"] != "running" or watchdog_fault_kind(current)
            or not _is_selected(manager, plan)):
        return False, "Replacement worker changed or failed during its verification check."
    if not ok:
        return False, f"Replacement worker started. Its follow-up check needs attention: {detail}"
    if current["health"] < 50:
        return False, f"Replacement passed its diagnostic but worker health is still {current['health']}%."
    return True, (f"Replacement worker completed a cycle and passed its follow-up check "
                  f"at {current['health']}% worker health: {detail}")
