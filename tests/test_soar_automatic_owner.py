from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.adversary_combat import AdversaryCombat, CombatPolicy
from angerona.modules.soar import SOARModule


class _Combat:
    def __init__(self, bus, *, policy=None, snapshot=None):
        self._bus = bus
        self._policy = policy if policy is not None else CombatPolicy()
        self._snapshot = snapshot if snapshot is not None else {
            "ready": True, "state": "ARMED", "reason": "Waiting for exact evidence.",
        }

    def policy(self):
        return self._policy

    def response_snapshot(self):
        return self._snapshot

    def response_ready(self):
        pytest.fail("Ownership reporting must not open the journal")

    def list_actions(self):
        pytest.fail("Ownership reporting must not read receipts")

    def _submit(self, _event):
        pytest.fail("Standing-rule ownership must not duplicate a response request")


def _module(monkeypatch, *, armed=True, policy=None, snapshot=None):
    bus = EventBus()
    if armed:
        bus.arm(BusAuthority(b"o" * 32))
    module = SOARModule()
    module._auto = module._active_defense = False
    module.bind(bus)
    combat = _Combat(bus, policy=policy, snapshot=snapshot)
    module.bind_manager(SimpleNamespace(modules={"Adversary Combat": combat}))
    # Legacy recommendation tests remain inert; owned events must bypass even
    # this mocked process inspection (asserted separately below).
    monkeypatch.setattr(module, "_is_protected_process", lambda _pid: False)
    return module, bus, combat


def _event(bus, actions=("suspend_process", "terminate_process"), **overrides):
    targets = {}
    details = {"response_authorized": True}
    if set(actions).intersection({"isolate_program", "suspend_process", "terminate_process"}):
        details.update(pid=4242, process_create_time=100.25, exe="C:/lab/exact.exe")
        targets.update(pid=4242, process_create_time=100.25)
    if "quarantine_file" in actions:
        details["path"] = "C:/lab/exact.txt"
        targets["path"] = details["path"]
    if "block_remote_ip" in actions:
        details["remote_ip"] = "203.0.113.42"
        targets["remote_ips"] = [details["remote_ip"]]
    if "isolate_host" in actions:
        targets["host"] = "local"
    if "activate_honeypots" in actions:
        targets["deception"] = "Smart Deception"
    details["response_contract"] = {
        "version": 1, "actions": list(actions), "targets": targets,
    }
    details.update(overrides.pop("details", {}))
    bus.publish(Event(
        overrides.pop("module", "Exact Detector"), "exact evidence",
        overrides.pop("severity", Severity.CRITICAL), details=details, **overrides,
    ))
    return bus.recent(1)[0]


def _output(module, bus):
    return [event for event in bus.recent(100) if event.module == module.name]


@pytest.mark.parametrize("actions,expected", [
    (("suspend_process", "terminate_process"), ["terminate_process"]),
    (("suspend_process",), ["suspend_process"]),
    (("isolate_program",), ["isolate_program"]),
    (("block_remote_ip",), ["block_remote_ip"]),
    (("quarantine_file",), ["quarantine_file"]),
    (("isolate_host",), ["isolate_host"]),
    (("activate_honeypots",), ["activate_honeypots"]),
])
def test_signed_standing_rule_reports_owner_without_duplicate_request_or_success(
    monkeypatch, actions, expected,
):
    module, bus, _combat = _module(monkeypatch)
    event = _event(bus, actions)
    monkeypatch.setattr(module, "_is_protected_process", lambda _pid: pytest.fail("PID probe"))
    monkeypatch.setattr(module, "_exact_process_contract_ok", lambda _ev: pytest.fail("PID preflight"))
    module._auto = True  # Even legacy opt-in cannot submit a duplicate here.

    module._run_playbook(event)

    [reported] = _output(module, bus)
    assert bus.verify(reported)
    assert reported.details["response_owner"] == "Adversary Combat"
    assert reported.details["policy_actions"] == expected
    assert reported.details["response_state"] == "automatic-review"
    for key in ("response_authorized", "action_succeeded", "admission_confirmed",
                "postcondition_verified", "mitigated"):
        assert reported.details[key] is False
    assert "action_pending" not in reported.details
    assert "automatic review" in reported.message
    assert "unconfirmed" in reported.message
    assert "recommend" not in reported.message
    assert "queued" not in reported.message
    assert module._attempts == module._contained == 0
    assert module._pending == {}


@pytest.mark.parametrize("state,reason", [
    ("RECOVERY REQUIRED", "An earlier response needs verified recovery."),
    ("JOURNAL FULL", "No complete receipt reservation is available."),
    ("STARTING", "Journal reconciliation is incomplete."),
    ("QUEUE FULL", "The bounded queue is full."),
    ("status=stopped", "The response worker is stopped."),
])
def test_exact_owned_alert_reports_current_hold_without_escalation(monkeypatch, state, reason):
    module, bus, _combat = _module(monkeypatch, snapshot={
        "ready": False, "state": state, "reason": reason,
    })
    module._auto = True

    module._run_playbook(_event(bus))

    [reported] = _output(module, bus)
    assert "HELD" in reported.message
    assert state in reported.message and reason in reported.message
    assert reported.details["response_state"] == "held"
    assert reported.details["admission_confirmed"] is False
    assert reported.details["action_succeeded"] is False
    assert module._attempts == 0


@pytest.mark.parametrize("policy,actions", [
    (CombatPolicy(enabled=False), ("terminate_process",)),
    (CombatPolicy(process_action="suspend"), ("terminate_process",)),
    (CombatPolicy(mode="contain"), ("terminate_process",)),
    (CombatPolicy(block_network=False), ("isolate_program",)),
    (CombatPolicy(block_network=False), ("block_remote_ip",)),
    (CombatPolicy(quarantine_files=False), ("quarantine_file",)),
    (CombatPolicy(isolate_host=False), ("isolate_host",)),
    (CombatPolicy(mode="aggressive"), ("isolate_host",)),
    (CombatPolicy(activate_honeypots=False), ("activate_honeypots",)),
    (SimpleNamespace(enabled=True), ("terminate_process",)),
    (CombatPolicy(mode="unknown"), ("terminate_process",)),
])
def test_uncovered_disabled_or_unknown_policy_keeps_legacy_reporting(monkeypatch, policy, actions):
    module, bus, _combat = _module(monkeypatch, policy=policy)

    module._run_playbook(_event(bus, actions))

    [reported] = _output(module, bus)
    assert "response_owner" not in reported.details
    assert "recommend SUSPEND" in reported.message or "Playbook[triage]" in reported.message


@pytest.mark.parametrize("policy,expected", [
    (CombatPolicy(process_action="suspend"), "suspend_process"),
    (CombatPolicy(mode="contain"), "suspend_process"),
    (CombatPolicy(mode="aggressive"), "terminate_process"),
])
def test_process_policy_reports_selected_alternative_only(monkeypatch, policy, expected):
    module, bus, _combat = _module(monkeypatch, policy=policy)
    module._run_playbook(_event(bus))
    assert _output(module, bus)[0].details["policy_actions"] == [expected]


def test_partial_policy_reports_only_covered_actions(monkeypatch):
    module, bus, _combat = _module(monkeypatch, policy=CombatPolicy(block_network=False))
    module._run_playbook(_event(bus, ("isolate_program", "terminate_process")))
    reported = _output(module, bus)[0]
    assert reported.details["policy_actions"] == ["terminate_process"]
    assert "isolate_program" not in reported.message


def test_real_combat_memory_snapshot_needs_no_worker_or_journal(monkeypatch):
    module, bus, _stub = _module(monkeypatch)
    combat = AdversaryCombat()
    combat.bind(bus)
    combat.status = "running"
    combat._response_initialized = True
    monkeypatch.setattr(combat, "policy", lambda: CombatPolicy())
    monkeypatch.setattr(combat, "response_ready", lambda: pytest.fail("journal capacity probe"))
    monkeypatch.setattr(combat, "list_actions", lambda: pytest.fail("receipt read"))
    monkeypatch.setattr(combat, "_submit", lambda _event: pytest.fail("duplicate submission"))
    module._manager.modules["Adversary Combat"] = combat

    module._run_playbook(_event(bus))

    assert _output(module, bus)[0].details["response_state"] == "automatic-review"
    assert combat._queue.empty()
    assert combat.response_snapshot()["counts"] == {}


@pytest.mark.parametrize("case", [
    "unsigned", "tampered", "missing-contract", "mismatched-target", "boolean-pid",
    "unknown-action", "wrong-bus", "no-combat", "unknown-readiness", "inconsistent-readiness",
    "unready-armed",
])
def test_unknown_or_invalid_authority_never_claims_automatic_ownership(monkeypatch, case):
    module, bus, combat = _module(monkeypatch, armed=case != "unsigned")
    event = _event(bus)
    if case == "tampered":
        event.details["pid"] = 9999
    elif case in {"missing-contract", "mismatched-target", "boolean-pid", "unknown-action"}:
        # Re-sign semantic errors to distinguish schema validation from HMAC.
        if case == "missing-contract":
            del event.details["response_contract"]
        elif case == "mismatched-target":
            event.details["response_contract"]["targets"]["pid"] = 9999
        elif case == "boolean-pid":
            event.details["pid"] = True
            event.details["response_contract"]["targets"]["pid"] = True
        else:
            event.details["response_contract"]["actions"].append("approve_everything")
        bus.publish(replace(event, hmac_sig=""))
        event = bus.recent(1)[0]
    elif case == "wrong-bus":
        combat._bus = EventBus()
    elif case == "no-combat":
        module._manager.modules.clear()
    elif case == "unknown-readiness":
        combat._snapshot = {"ready": "yes"}
    elif case == "inconsistent-readiness":
        combat._snapshot = {"ready": True, "state": "RECOVERY REQUIRED", "reason": "held"}
    elif case == "unready-armed":
        combat._snapshot = {"ready": False, "state": "ARMED", "reason": "inconsistent"}

    module._run_playbook(event)

    assert all("response_owner" not in item.details for item in _output(module, bus))
    assert module._attempts == module._contained == 0


@pytest.mark.parametrize("source,details", [
    ("Exact Detector", {"node_origin": "remote.example"}),
    ("Exact Detector", {"response_authority": "remote-observe-only"}),
    ("Watchdog Monitor", {}),
    ("Adversary Combat", {}),
    ("Exact Detector", {"disposition": "observation"}),
    ("Exact Detector", {"hardening": True}),
])
def test_remote_health_or_observation_never_enters_owner_reporting(monkeypatch, source, details):
    module, bus, _combat = _module(monkeypatch)
    event = _event(bus, module=source, details=details)
    assert module._report_combat_ownership(event) is False
    assert module._process_one_event(event, ()) is False
    assert _output(module, bus) == []


def test_explicit_generic_health_contract_does_not_claim_automatic_owner(monkeypatch):
    module, bus, _combat = _module(monkeypatch)
    event = _event(bus, details={"disposition": "health"})
    assert module._report_combat_ownership(event) is False
    assert _output(module, bus) == []


def test_below_policy_floor_and_unproven_isolation_threshold_keep_triage(monkeypatch):
    module, bus, combat = _module(monkeypatch, policy=CombatPolicy(min_severity=Severity.CRITICAL))
    module._run_playbook(_event(bus, severity=Severity.HIGH))
    assert "Playbook[triage]" in _output(module, bus)[0].message
    combat._policy = CombatPolicy()
    module._run_playbook(_event(bus, ("isolate_host",), severity=Severity.HIGH))
    assert all("response_owner" not in item.details for item in _output(module, bus))


def test_disabled_legacy_automation_never_claims_engagement(monkeypatch):
    module, bus, _combat = _module(monkeypatch, policy=CombatPolicy(enabled=False))
    module._stop.set()
    module.run()  # Startup message only, no polling or stats I/O.
    module._run_playbook(_event(bus))
    for pid in (4242, 4243, 4242, 4243):
        module._track_attack(Event("Detector", "burst", Severity.CRITICAL, details={"pid": pid}))

    text = " ".join(item.message for item in _output(module, bus))
    assert "UNDER ATTACK" in text
    assert "Legacy automatic requests and active defense are disabled" in text
    assert "Active defense engaged" not in text
    assert "contained automatically" not in text


@pytest.mark.parametrize("auto,active,phrase", [
    (True, False, "Legacy automatic requests are enabled"),
    (False, True, "Legacy active-defense requests are enabled during an attack burst"),
])
def test_enabled_legacy_mode_still_describes_guards(monkeypatch, auto, active, phrase):
    module, _bus, _combat = _module(monkeypatch)
    module._auto, module._active_defense = auto, active
    assert phrase in module._delegation_description()
    assert "safety checks" in module._delegation_description()
