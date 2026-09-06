from types import SimpleNamespace

import pytest

from angerona.core.drill_readiness import assess_drill_response
from angerona.core.eventbus import Severity


def _manager(*, snapshot=None, **changes):
    policy = SimpleNamespace(
        enabled=True, quarantine_files=True, process_action="terminate",
        min_severity=Severity.HIGH,
    )
    for key, value in changes.items():
        setattr(policy, key, value)
    status = snapshot if snapshot is not None else {
        "ready": True, "state": "ARMED", "reason": "Waiting for evidence.",
    }
    module = SimpleNamespace(response_snapshot=lambda: status, policy=lambda: policy)
    return SimpleNamespace(modules={"Adversary Combat": module}), module, policy


def test_ready_snapshot_is_memory_only_detached_and_non_secret(monkeypatch):
    manager, module, policy = _manager()
    policy.private_key = "not-for-display"
    forbidden = lambda: pytest.fail("Readiness must not inspect or mutate response authority")
    module.response_ready = forbidden
    module._read_journal = forbidden
    module._reconcile_state = forbidden
    monkeypatch.setattr("angerona.core.drill_readiness.time.time", lambda: 123.5)
    result = assess_drill_response(manager, require_process=True)
    assert result == {
        "ready": True, "state": "ARMED", "checked_at": 123.5,
        "reason": (
            "Combat is armed for the drill's containment checks. Each action still requires "
            "authenticated evidence and a verified postcondition."
        ),
        "policy": {
            "enabled": True, "quarantine_files": True,
            "process_action": "terminate", "min_severity": "HIGH",
        },
    }
    result["policy"]["enabled"] = False
    assert policy.enabled is True
    assert "not-for-display" not in str(result)


@pytest.mark.parametrize("manager", [None, SimpleNamespace(), SimpleNamespace(modules={})])
def test_missing_combat_is_not_ready(manager):
    result = assess_drill_response(manager)
    assert result["ready"] is False
    assert result["state"] == "UNAVAILABLE"
    assert result["policy"] == {}


@pytest.mark.parametrize("state, reason", [
    ("status=stopped", "The response worker is stopped or restarting."),
    ("RECOVERY REQUIRED", "combat journal rollback or incomplete anchor transaction detected"),
    ("JOURNAL FULL", "No complete receipt capacity remains."),
    ("QUEUE FULL", "Queue cannot accept new evidence."),
    ("STARTING", "Journal reconciliation has not finished."),
])
def test_worker_hold_reason_is_preserved_over_policy_restrictions(state, reason):
    manager, _module, _policy = _manager(
        snapshot={"ready": False, "state": state, "reason": reason},
        quarantine_files=False,
    )
    result = assess_drill_response(manager)
    assert result["ready"] is False
    assert result["state"] == state
    assert result["reason"] == reason


@pytest.mark.parametrize("changes, fragment", [
    ({"enabled": False}, "disabled"),
    ({"enabled": "true"}, "disabled"),
    ({"quarantine_files": False}, "quarantine"),
    ({"quarantine_files": "true"}, "quarantine"),
    ({"min_severity": Severity.CRITICAL}, "exceeds HIGH"),
    ({"min_severity": True}, "unknown"),
    ({"min_severity": -1}, "unknown"),
    ({"min_severity": "bad"}, "unknown"),
])
def test_inert_marker_policy_requirements(changes, fragment):
    manager, _module, _policy = _manager(**changes)
    result = assess_drill_response(manager)
    assert result["ready"] is False
    assert fragment in result["reason"]


@pytest.mark.parametrize("minimum", [Severity.INFO, Severity.LOW, Severity.MEDIUM, 3, "HIGH"])
def test_thresholds_up_to_high_can_attempt_containment(minimum):
    manager, _module, _policy = _manager(min_severity=minimum)
    assert assess_drill_response(manager)["ready"] is True


@pytest.mark.parametrize("action", ["none", "unknown", None, "observe"])
def test_process_policy_is_required_only_for_process_checks(action):
    manager, _module, _policy = _manager(process_action=action)
    assert assess_drill_response(manager)["ready"] is True
    result = assess_drill_response(manager, require_process=True)
    assert result["ready"] is False
    assert "suspension or termination" in result["reason"]


@pytest.mark.parametrize("action", ["suspend", "terminate"])
def test_supported_process_policies(action):
    manager, _module, _policy = _manager(process_action=action)
    assert assess_drill_response(manager, require_process=True)["ready"] is True


@pytest.mark.parametrize("reader", ["response_snapshot", "policy"])
def test_reader_errors_do_not_leak_exception_contents(reader):
    manager, module, _policy = _manager()

    def failed():
        raise RuntimeError("private diagnostic contents")

    setattr(module, reader, failed)
    result = assess_drill_response(manager)
    assert result["ready"] is False
    assert result["state"] == "ERROR"
    assert "private diagnostic contents" not in str(result)


@pytest.mark.parametrize("snapshot", [
    [], {}, {"ready": "true", "state": "ARMED"},
    {"ready": True, "state": "RECOVERY REQUIRED"},
])
def test_malformed_or_inconsistent_status_is_not_ready(snapshot):
    manager, _module, _policy = _manager(snapshot=snapshot)
    result = assess_drill_response(manager)
    assert result["ready"] is False
    assert result["state"] == "UNKNOWN"


def test_recovery_reason_remains_visible_when_policy_reader_fails():
    manager, module, _policy = _manager(snapshot={
        "ready": False, "state": "RECOVERY REQUIRED", "reason": "Checkpoint mismatch.",
    })

    def failed():
        raise RuntimeError("unavailable")

    module.policy = failed
    result = assess_drill_response(manager)
    assert result["state"] == "RECOVERY REQUIRED"
    assert result["reason"] == "Checkpoint mismatch."
    assert result["policy"] == {}
