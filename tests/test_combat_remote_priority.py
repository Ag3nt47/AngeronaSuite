"""Actual _handle scheduling with signed evidence and inert effect providers."""
from types import SimpleNamespace
import threading

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.response_contract import authorize_response
from angerona.modules import adversary_combat as combat


def fixture(monkeypatch, tmp_path, *, mode="maximum", process_action="terminate",
            actions=("terminate_process", "block_remote_ip"), block_network=True):
    module = combat.AdversaryCombat(tmp_path, rollback_anchor={})
    bus = EventBus()
    bus.arm(BusAuthority(b"r" * 32))
    module.bind(bus)
    module._mutation_blocked = False
    module._journal_saturated = False
    policy = combat.CombatPolicy(mode=mode, process_action=process_action,
        block_network=block_network, isolate_host=False, activate_honeypots=False,
        quarantine_files=False)
    monkeypatch.setattr(module, "policy", lambda: policy)
    details = dict(pid=45001, process_create_time=100.25, remote_ip="8.8.8.8",
        active_attack=True, **authorize_response(actions, pid=45001,
        process_create_time=100.25, remote_ips=("8.8.8.8",)))
    bus.publish(Event("Inert exact detector", "fixture", Severity.CRITICAL, details=details))
    event = bus.recent(1)[0]
    assert bus.verify(event) and module._response_actions(event) is not None
    calls = []
    def process(pid, selected_policy, source, combat_id, *, allowed_actions):
        assert pid == 45001 and source is event and selected_policy is policy
        assert allowed_actions == frozenset(actions)
        calls.append("process")
        return []
    def remote(ip, source, combat_id):
        assert ip == "8.8.8.8" and source is event
        calls.append("remote")
        return None
    monkeypatch.setattr(module, "_act_on_process", process)
    monkeypatch.setattr(module, "_block_remote_ip", remote)
    return module, bus, event, calls


def test_maximum_exact_termination_is_dispatched_before_remote_firewall(monkeypatch, tmp_path):
    module, bus, event, calls = fixture(monkeypatch, tmp_path)
    module._handle(event)
    assert calls == ["process", "remote"]
    output = bus.recent(1)[0]
    assert bus.verify(output) and output.details["action_succeeded"] is False


def test_held_remote_provider_does_not_delay_authorized_process_dispatch(monkeypatch, tmp_path):
    module, _, event, calls = fixture(monkeypatch, tmp_path)
    entered, release, process_done = threading.Event(), threading.Event(), threading.Event()
    original_process = module._act_on_process
    def process(*args, **kwargs):
        result = original_process(*args, **kwargs)
        process_done.set()
        return result
    def remote(*_args):
        calls.append("remote")
        entered.set()
        assert release.wait(3)
    monkeypatch.setattr(module, "_act_on_process", process)
    monkeypatch.setattr(module, "_block_remote_ip", remote)
    errors = []
    def handle():
        try:
            module._handle(event)
        except BaseException as exc:
            errors.append(exc)
    worker = threading.Thread(target=handle)
    worker.start()
    try:
        assert entered.wait(2)
        assert process_done.is_set(), "Remote firewall entered before process dispatch"
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive() and not errors


@pytest.mark.parametrize("mode,action,allowed,network,expected", [
    ("contain", "terminate", ("terminate_process", "suspend_process", "block_remote_ip"), True, ["remote", "process"]),
    ("maximum", "suspend", ("terminate_process", "suspend_process", "block_remote_ip"), True, ["remote", "process"]),
    ("maximum", "terminate", ("suspend_process", "block_remote_ip"), True, ["remote", "process"]),
    ("maximum", "terminate", ("block_remote_ip",), True, ["remote", "process"]),
    ("maximum", "terminate", ("terminate_process",), True, ["process"]),
    ("maximum", "terminate", ("terminate_process", "block_remote_ip"), False, ["process"]),
])
def test_mode_capability_and_network_policy_boundaries_preserve_existing_order(
    monkeypatch, tmp_path, mode, action, allowed, network, expected,
):
    module, _, event, calls = fixture(monkeypatch, tmp_path, mode=mode,
        process_action=action, actions=allowed, block_network=network)
    module._handle(event)
    assert calls == expected
    assert calls.count("process") == 1


def test_uncertain_process_outcome_holds_remote_and_later_effects(monkeypatch, tmp_path):
    module, _, event, calls = fixture(monkeypatch, tmp_path)
    def uncertain(*_args, **_kwargs):
        calls.append("process")
        module._mutation_blocked = True
        return []
    monkeypatch.setattr(module, "_act_on_process", uncertain)
    module._handle(event)
    assert calls == ["process"]


def test_nonpriority_uncertain_remote_still_holds_process(monkeypatch, tmp_path):
    module, _, event, calls = fixture(monkeypatch, tmp_path, mode="contain")
    def uncertain(*_args):
        calls.append("remote")
        module._mutation_blocked = True
    monkeypatch.setattr(module, "_block_remote_ip", uncertain)
    module._handle(event)
    assert calls == ["remote"]


@pytest.mark.parametrize("refusal", ["tampered", "missing-contract", "recovery-hold"])
def test_ordering_change_cannot_bypass_authenticity_or_admission_gates(monkeypatch, tmp_path, refusal):
    module, bus, event, calls = fixture(monkeypatch, tmp_path)
    if refusal == "tampered":
        event.details["active_attack"] = False
    elif refusal == "missing-contract":
        bus.publish(Event("Inert exact detector", "fixture", Severity.CRITICAL,
            details={"pid": 45001, "active_attack": True}))
        event = bus.recent(1)[0]
    else:
        module._mutation_blocked = True
    module._handle(event)
    assert calls == []
