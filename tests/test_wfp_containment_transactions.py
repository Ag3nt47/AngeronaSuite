from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from angerona.modules.wfp_controller import (
    ContainmentTarget,
    WFPController,
)


NOW = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)


def test_plan_is_deterministic_scoped_and_recovery_safe(monkeypatch):
    monkeypatch.setattr(WFPController, "_try_init_wfp", lambda self: False)
    ctrl = WFPController()
    targets = [
        ContainmentTarget("process", "Suspect.EXE"),
        ContainmentTarget("ip", "203.0.113.8", "both"),
    ]
    first = ctrl.plan_containment(
        targets, ttl_seconds=300, recovery_exclusions=["management:443"], now=NOW
    )
    second = ctrl.plan_containment(
        reversed(targets), ttl_seconds=300, recovery_exclusions=["management:443"], now=NOW
    )

    assert first == second
    assert first.dry_run is True
    assert set(("loopback", "dns", "dhcp")).issubset(first.recovery_exclusions)
    assert first.targets[1].value == "suspect.exe"
    assert first.expires_at == (NOW + timedelta(seconds=300)).isoformat()


@pytest.mark.parametrize(
    "target",
    [
        ContainmentTarget("command", "anything"),
        ContainmentTarget("port", "0"),
        ContainmentTarget("process", r"C:\Windows\thing.exe"),
        ContainmentTarget("ip", "1.2.3.4; shutdown"),
    ],
)
def test_plan_rejects_unscoped_or_unsafe_targets(monkeypatch, target):
    monkeypatch.setattr(WFPController, "_try_init_wfp", lambda self: False)
    with pytest.raises((TypeError, ValueError)):
        WFPController().plan_containment([target], now=NOW)


def test_enforcement_is_opt_in_and_requires_a_rollback(monkeypatch):
    monkeypatch.setattr(WFPController, "_try_init_wfp", lambda self: False)
    ctrl = WFPController()
    preview = ctrl.plan_containment([ContainmentTarget("port", "4444")], now=NOW)
    with pytest.raises(PermissionError, match="dry-run"):
        ctrl.apply_containment(preview, approved=True, executor=lambda plan: ["undo"], now=NOW)

    plan = ctrl.plan_containment(
        [ContainmentTarget("port", "4444")], dry_run=False, now=NOW
    )
    with pytest.raises(PermissionError, match="human approval"):
        ctrl.apply_containment(plan, executor=lambda item: ["undo"], now=NOW)
    with pytest.raises(RuntimeError, match="executor"):
        ctrl.apply_containment(
            plan, approved=True, approved_plan_id=plan.plan_id, now=NOW
        )
    with pytest.raises(RuntimeError, match="rollback"):
        ctrl.apply_containment(
            plan,
            approved=True,
            approved_plan_id=plan.plan_id,
            executor=lambda item: [],
            now=NOW,
        )
    with pytest.raises(PermissionError, match="bound"):
        ctrl.apply_containment(
            plan,
            approved=True,
            approved_plan_id="wfp-a-different-plan",
            executor=lambda item: ["undo"],
            now=NOW,
        )


def test_receipt_is_tamper_evident_and_supports_independent_verification(monkeypatch):
    monkeypatch.setattr(WFPController, "_try_init_wfp", lambda self: False)
    ctrl = WFPController()
    plan = ctrl.plan_containment(
        [ContainmentTarget("cidr", "198.51.100.0/24")],
        dry_run=False,
        ttl_seconds=600,
        now=NOW,
    )
    receipt = ctrl.apply_containment(
        plan,
        approved=True,
        approved_plan_id=plan.plan_id,
        executor=lambda item: [f"remove rules for {item.plan_id}"],
        now=NOW,
    )

    assert ctrl.verify_rollback_receipt(receipt, plan)
    assert ctrl.verify_rollback_receipt(receipt, plan, verifier=lambda item: True)
    assert not ctrl.verify_rollback_receipt(receipt, plan, verifier=lambda item: False)
    assert not ctrl.verify_rollback_receipt(
        replace(receipt, rollback_actions=("different",)), plan
    )


def test_expired_plan_is_never_applied(monkeypatch):
    monkeypatch.setattr(WFPController, "_try_init_wfp", lambda self: False)
    ctrl = WFPController()
    plan = ctrl.plan_containment(
        [ContainmentTarget("port", "443")], dry_run=False, ttl_seconds=30, now=NOW
    )
    called = False

    def executor(_plan):
        nonlocal called
        called = True
        return ["undo"]

    with pytest.raises(ValueError, match="expired"):
        ctrl.apply_containment(
            plan,
            approved=True,
            approved_plan_id=plan.plan_id,
            executor=executor,
            now=NOW + timedelta(seconds=30),
        )
    assert called is False


def test_naive_timestamp_is_rejected(monkeypatch):
    monkeypatch.setattr(WFPController, "_try_init_wfp", lambda self: False)
    with pytest.raises(ValueError, match="timezone-aware"):
        WFPController().plan_containment(
            [ContainmentTarget("port", "443")], now=datetime(2026, 7, 29, 12, 0)
        )


def test_apply_rejects_directly_forged_plan_fields_before_executor(monkeypatch):
    monkeypatch.setattr(WFPController, "_try_init_wfp", lambda self: False)
    ctrl = WFPController()
    valid = ctrl.plan_containment(
        [ContainmentTarget("port", "443")], dry_run=False, now=NOW
    )
    forged = (
        replace(valid, plan_id="wfp-forged"),
        replace(valid, targets=(ContainmentTarget("port", "4444"),)),
        replace(valid, recovery_exclusions=("loopback",)),
        replace(valid, targets=(ContainmentTarget("process", r"C:\bad.exe"),)),
        replace(valid, targets=(ContainmentTarget("process", "bad.exe; calc"),)),
        replace(
            valid,
            expires_at=(NOW + timedelta(hours=25)).isoformat(),
        ),
    )
    executions = 0

    def executor(_plan):
        nonlocal executions
        executions += 1
        return ["undo"]

    for candidate in forged:
        with pytest.raises(ValueError):
            ctrl.apply_containment(
                candidate,
                approved=True,
                approved_plan_id=candidate.plan_id,
                executor=executor,
                now=NOW,
            )
    assert executions == 0
