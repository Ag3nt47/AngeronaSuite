"""Exercise response ordering with inert processes and firewall providers."""
from __future__ import annotations

from contextlib import contextmanager
import subprocess
import threading
from types import SimpleNamespace

import pytest

from angerona.core import module_base, win
from angerona.core.eventbus import Event, Severity
from angerona.modules import adversary_combat as combat


def _fixture(monkeypatch, tmp_path):
    module = combat.AdversaryCombat(tmp_path, rollback_anchor={})
    state = {"birth": 10.0, "exe": "C:/fixture/inert.exe", "alive": True}
    calls = []
    process = SimpleNamespace(
        create_time=lambda: state["birth"], name=lambda: "inert.exe",
        exe=lambda: state["exe"], is_running=lambda: state["alive"],
        suspend=lambda: calls.append("suspend"), status=lambda: "stopped",
    )
    monkeypatch.setattr(combat, "psutil", SimpleNamespace(
        Process=lambda _pid: process, STATUS_STOPPED="stopped"))
    monkeypatch.setattr(module, "_is_system_path", lambda _path: False)
    monkeypatch.setattr(combat.time, "sleep", lambda _seconds: None)

    def fence(exe, pid, birth, event, combat_id):
        calls.append("fence")
        return module._action("isolate_program", exe, event, combat_id,
                              reversible=True, details={"pid": pid, "create_time": birth})

    @contextmanager
    def journal(action):
        calls.append("intent:" + action.action)
        yield

    monkeypatch.setattr(module, "_block_program", fence)
    monkeypatch.setattr(module, "_journaled_mutation", journal)
    monkeypatch.setattr(module, "_commit_after_mutation", lambda action: action)
    monkeypatch.setattr(module, "_journal_failure", lambda *_args: calls.append("failure"))
    event = Event("Inert Detector", "fixture", Severity.CRITICAL,
                  details={"pid": 999999, "process_create_time": 10.0})
    return module, process, state, calls, event


def test_maximum_terminate_uses_existing_native_transaction_before_firewall(
    monkeypatch, tmp_path,
):
    module, _process, state, calls, event = _fixture(monkeypatch, tmp_path)

    class Lease:
        identity = SimpleNamespace(pid=999999, birth_ticks=116444736100000000,
                                   image="C:/fixture/inert.exe")
        dispatch_started = False

        def validate(self, *, alive):
            assert alive and state["alive"]
            calls.append("validate")

        def terminate(self):
            calls.append("terminate")
            self.dispatch_started = True
            state["alive"] = False

        def wait_terminated(self, *, timeout):
            assert timeout == 3.0 and not state["alive"]
            calls.append("wait")

        def terminal_proof(self):
            return {"native_wait_signaled": True}

        def close(self):
            calls.append("close")

    monkeypatch.setattr(combat, "_WINDOWS_PROCESS_CUSTODY", True)
    monkeypatch.setattr(module, "_acquire_termination_lease", lambda _action: Lease())
    result = module._act_on_process(
        999999, combat.CombatPolicy(mode="maximum", process_action="terminate"),
        event, "combat-aaaaaaaaaaaa",
        allowed_actions=frozenset({"terminate_process", "isolate_program"}),
    )
    assert [action.action for action in result] == ["terminate_process"]
    assert calls == ["intent:terminate_process", "validate", "terminate", "wait", "close"]
    assert result[0].details["process_custody"] == "windows-retained-handle-v1"
    assert "fence" not in calls


@pytest.mark.parametrize("failure", ["pre-effect", "uncertain", "reused", "image-changed", "exited", "unreadable",
                                     "stopping", "journal-full", "recovery-required"])
def test_failed_kill_falls_back_only_with_intact_authority_and_same_live_target(
    monkeypatch, tmp_path, failure,
):
    module, _process, state, calls, event = _fixture(monkeypatch, tmp_path)

    def failed_kill(_process, _action):
        calls.append("terminate-refused")
        if failure == "uncertain":
            module._mutation_blocked = True
        elif failure == "reused":
            state["birth"] += 1
        elif failure == "image-changed":
            state["exe"] = "C:/fixture/another.exe"
        elif failure == "exited":
            state["alive"] = False
        elif failure == "unreadable":
            _process.exe = lambda: (_ for _ in ()).throw(OSError("inert identity unavailable"))
        elif failure == "stopping":
            module._stop.set()
        elif failure == "journal-full":
            module._journal_saturated = True
        elif failure == "recovery-required":
            module._recovery_required = True
        return None

    monkeypatch.setattr(module, "_terminate_process_transaction", failed_kill)
    result = module._act_on_process(
        999999, combat.CombatPolicy(mode="maximum", process_action="terminate"),
        event, "combat-aaaaaaaaaaaa",
        allowed_actions=frozenset({"terminate_process", "isolate_program"}),
    )
    assert calls == (["terminate-refused", "fence"] if failure == "pre-effect"
                     else ["terminate-refused"])
    assert [action.action for action in result] == (
        ["isolate_program"] if failure == "pre-effect" else [])


def test_network_only_contract_does_not_inherit_terminate_permission(monkeypatch, tmp_path):
    module, _process, _state, calls, event = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "_terminate_process_transaction",
                        lambda *_args: pytest.fail("network-only contract cannot kill"))
    result = module._act_on_process(
        999999, combat.CombatPolicy(), event, "combat-aaaaaaaaaaaa",
        allowed_actions=frozenset({"isolate_program"}),
    )
    assert calls == ["fence"]
    assert [action.action for action in result] == ["isolate_program"]


@pytest.mark.parametrize("mode, process_action, allowed", [
    ("contain", "terminate", {"terminate_process", "suspend_process", "isolate_program"}),
    ("maximum", "suspend", {"terminate_process", "suspend_process", "isolate_program"}),
    ("maximum", "terminate", {"suspend_process", "isolate_program"}),
])
def test_contain_and_exact_suspend_keep_network_first_semantics(
    monkeypatch, tmp_path, mode, process_action, allowed,
):
    module, _process, _state, calls, event = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "_terminate_process_transaction",
                        lambda *_args: pytest.fail("suspend permission must not become kill"))
    result = module._act_on_process(
        999999, combat.CombatPolicy(mode=mode, process_action=process_action), event,
        "combat-aaaaaaaaaaaa", allowed_actions=frozenset(allowed),
    )
    assert calls == ["fence", "intent:suspend_process", "suspend"]
    assert [action.action for action in result] == ["isolate_program", "suspend_process"]


@pytest.mark.parametrize("invalid", ["birth", "protected"])
def test_identity_and_protected_process_checks_precede_both_effects(
    monkeypatch, tmp_path, invalid,
):
    module, _process, state, calls, event = _fixture(monkeypatch, tmp_path)
    if invalid == "birth":
        state["birth"] += 1
    else:
        monkeypatch.setattr(module, "_is_system_path", lambda _path: True)
    monkeypatch.setattr(module, "_terminate_process_transaction",
                        lambda *_args: pytest.fail("invalid target must not be killed"))
    assert module._act_on_process(999999, combat.CombatPolicy(), event,
                                  "combat-aaaaaaaaaaaa") is None
    assert calls == []


def test_completed_slow_firewall_substeps_renew_current_worker_progress(
    monkeypatch, tmp_path,
):
    module = combat.AdversaryCombat(tmp_path, rollback_anchor={})
    clock = [100.0]
    monkeypatch.setattr(module_base, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(combat, "os", SimpleNamespace(name="nt"))
    calls, result, deadlines = [], [], []
    present = [False]

    def provider(command, **kwargs):
        assert kwargs["timeout"] == 15
        # Progress must reflect an actual completed step, never an early pulse.
        assert clock[0] < module._watchdog_deadline_at
        cycle = module._cycle_count
        clock[0] += 15
        assert module._cycle_count == cycle
        calls.append(tuple(command[3:5]))
        if command[3] == "add":
            present[0] = True
        elif command[3] == "delete":
            present[0] = False
        return SimpleNamespace(returncode=0,
                               stdout="Rule Name: Fixture" if present[0] else "No rules match.",
                               stderr="")

    monkeypatch.setattr(win, "run_hidden", provider)
    original_mark = module.mark_cycle_complete

    def mark(**kwargs):
        original_mark(**kwargs)
        deadlines.append((clock[0], module._watchdog_deadline_at))

    monkeypatch.setattr(module, "mark_cycle_complete", mark)
    module.status = "running"
    module._response_initialized = True
    module.mark_cycle_complete(interval_seconds=1)

    def work():
        result.append(module._run_firewall(["add", "rule", "name=Fixture"]))
        result.append(module._run_firewall(["delete", "rule", "name=Fixture"]))

    worker = threading.Thread(target=work)
    module._thread = worker
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert result == [True, True]
    assert calls == [("add", "rule"), ("show", "rule"),
                     ("delete", "rule"), ("show", "rule")]
    assert deadlines == [(100, 131), (115, 146), (130, 161), (145, 176), (160, 191)]
    assert module._cycle_count == 5


@pytest.mark.parametrize("call", ["mutation", "query"])
@pytest.mark.parametrize("state", ["active", "uninitialized", "stopped", "retired", "retired-token", "other-thread"])
def test_failed_bounded_firewall_step_never_fabricates_worker_readiness(
    monkeypatch, tmp_path, call, state,
):
    module = combat.AdversaryCombat(tmp_path, rollback_anchor={})
    monkeypatch.setattr(combat, "os", SimpleNamespace(name="nt"))

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("inert-netsh", 15)

    monkeypatch.setattr(win, "run_hidden", timeout)
    module.status = "stopped" if state == "stopped" else "running"
    module._response_initialized = state != "uninitialized"
    module._thread = threading.Thread() if state == "other-thread" else threading.current_thread()
    if state == "retired":
        module._stop.set()
    elif state == "retired-token":
        module._run_context.stop_event = threading.Event()
        module._run_context.stop_event.set()
    result = (module._run_firewall(["delete", "rule", "name=Fixture"])
              if call == "mutation" else module._firewall_rule_exists("Fixture"))
    assert result is (False if call == "mutation" else None)
    assert module._cycle_count == (1 if state == "active" else 0)
    assert module._first_cycle_complete.is_set() is (state == "active")
