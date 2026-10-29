"""All network/process providers below are inert; real host mutation forbidden."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
import time
import json

import pytest

from angerona.core import breach_state as breach
from angerona.core.eventbus import Event, Severity
from angerona.core.response_contract import authorize_response
from angerona.modules.adversary_combat import _BreachCommand
from test_breach_state import emit, execute_next, native_graph


@pytest.fixture(autouse=True)
def installed_protect_for_inert_combat(monkeypatch):
    """Explicit native-authority DI; every effect provider stays inert.

    Legacy Combat unit modules import this fixture when their subject is the
    transaction algorithm under an accepted installed authority. Source/STOP
    regressions explicitly replace the provider with a held native result.
    This is test-only monkeypatching, never a production flag or constructor
    override that could authorize a host mutation.
    """
    monkeypatch.setattr(breach, "protect_authority", lambda: (True, "Inert installed native authority"))


class FakeFirewall:
    def __init__(self):
        self.rules = {"User existing allow rule": {"action": "allow"}}
        self.calls = []
        self.profiles_enabled = True
        self.fail_direction = ""
        self.fail_delete = False
        self.narrow = False
        self.effective_policy = {"version": 1, "store": "ActiveStore", "modify_state": 0,
            "profiles": [dict(name=name, enabled="True", local_rules="True", inbound_rules="True", disabled_interfaces=[])
                         for name in ("Domain", "Private", "Public")]}

    def policy_query(self, *, cancel=None):
        return None if cancel is not None and cancel.is_set() else json.dumps(self.effective_policy)

    def query(self, arguments, *, cancel=None):
        if cancel is not None and cancel.is_set():
            return None
        self.calls.append(list(arguments))
        if arguments == ["show", "allprofiles", "state"]:
            return "\n".join(f"{name} Profile Settings:\nState {'ON' if self.profiles_enabled else 'OFF'}"
                             for name in ("Domain", "Private", "Public"))
        assert arguments[0] == "firewall"
        operation = arguments[1]
        values = dict(value.split("=", 1) for value in arguments if "=" in value)
        name = values["name"]
        if operation == "add":
            if values["dir"] == self.fail_direction:
                return None
            self.rules[name] = values
            return "Ok."
        if operation == "delete":
            assert name.startswith("Angerona-Combat-Host-")
            if self.fail_delete:
                return None
            self.rules.pop(name, None)
            return "Deleted 1 rule(s)."
        assert operation == "show"
        if name not in self.rules:
            return "No rules match the specified criteria."
        rule = self.rules[name]
        return f"""Rule Name: {name}
Enabled: Yes
Direction: {rule['dir']}
Profiles: Domain,Private,Public
Grouping:
LocalIP: Any
RemoteIP: Any
Protocol: Any
InterfaceTypes: {'Wireless' if self.narrow else 'All'}
Program: Any
Service: Any
LocalPort: Any
RemotePort: Any
Action: Block
"""


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setattr(breach, "protect_authority", lambda: (True, "Inert installed authority fixture"))
    return FakeFirewall()


def bind_provider(graph, provider, monkeypatch):
    monkeypatch.setattr(graph.combat, "_lockdown_query", provider.query)
    monkeypatch.setattr(graph.combat, "_lockdown_effective_policy_query", provider.policy_query)
    monkeypatch.setattr(graph.combat, "_run_firewall", lambda *_: pytest.fail("Legacy firewall path used"))


def admitted(graph, event, action="isolate", automatic=True, request_id="a" * 32, reviewed_cases=()):
    proof = breach.verified_breach(event, graph.bus, graph.manager.modules)
    assert proof
    assert graph.combat.request_breach_action(event, proof.case_id, action, request_id,
                                             automatic=automatic, reviewed_cases=reviewed_cases)
    return proof.case_id


def test_auto_isolation_uses_same_worker_scope_receipt_and_never_changes_general_policy(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        event = emit(graph)
        case_id = admitted(graph, event)
        assert graph.combat._queue.qsize() == 1
        assert graph.config.adversary_combat_mode == "contain"
        assert graph.config.adversary_combat_process_action == "suspend"
        result = execute_next(graph.combat)
        assert result["state"] == "applied" and result["scope_verified"] is True
        assert len(provider.rules) == 3
        receipt = graph.combat.list_actions()[0]
        assert receipt["integrity_status"] == "verified"
        assert receipt["details"]["breach_case_id"] == case_id
        assert receipt["details"]["lockdown_scope_verified"] is True
        assert receipt["details"]["lockdown_policy_verified"] is True
        assert receipt["details"]["postcondition_verified"] is True
        adds = [call for call in provider.calls if call[:2] == ["firewall", "add"]]
        assert len(adds) == 2
        assert all(set(["profile=any", "interfacetype=any", "localip=any", "remoteip=any", "protocol=any"]).issubset(call) for call in adds)
        assert not any(call[:2] == ["firewall", "delete"] for call in provider.calls)


def test_lift_requires_explicit_request_and_exact_verified_undo_preserves_user_policy(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        event = emit(graph)
        case_id = admitted(graph, event)
        assert execute_next(graph.combat)["state"] == "applied"
        assert graph.combat.request_breach_action(None, case_id, "lift_lockdown", "b" * 32)
        result = execute_next(graph.combat)
        assert result["state"] == "lifted"
        assert provider.rules == {"User existing allow rule": {"action": "allow"}}
        assert graph.config.breach_lifted_cases == [case_id]
        assert graph.combat.list_actions()[0]["undone"] is True
        # General Maximum host response observes the same lifted case too.
        graph.config.adversary_combat_mode = "maximum"
        old = emit(graph, ts=time.time() - 50)
        before = list(provider.calls)
        assert graph.combat._isolate_host(old, "test-old") is None
        assert provider.calls == before
        admitted(graph, emit(graph), request_id="c" * 32)
        assert execute_next(graph.combat)["state"] == "held"
        # A distinct process generation is a new case and may isolate again.
        new = emit(graph, process_create_time=12346.5,
                   **authorize_response(["isolate_host", "terminate_process"], local_host=True, pid=41000, process_create_time=12346.5))
        assert admitted(graph, new, request_id="d" * 32) != case_id
        assert execute_next(graph.combat)["state"] == "applied"


def test_unknown_or_disabled_scope_never_claims_lockdown_and_rolls_back_owned_partial(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        provider.fail_direction = "in"
        admitted(graph, emit(graph))
        assert execute_next(graph.combat)["state"] == "held"
        assert provider.rules == {"User existing allow rule": {"action": "allow"}}
        assert not any(row.get("status") == "applied" for row in graph.combat.list_actions())
        provider.fail_direction = ""
        provider.profiles_enabled = False
        before = len(provider.calls)
        admitted(graph, emit(graph), request_id="b" * 32)
        assert execute_next(graph.combat)["state"] == "held"
        assert not any(call[:2] == ["firewall", "add"] for call in provider.calls[before:])


def test_narrow_interface_scope_cannot_commit_and_partial_undo_does_not_lift(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        provider.narrow = True
        case_id = admitted(graph, emit(graph))
        assert execute_next(graph.combat)["state"] == "held"
        assert len(provider.rules) == 1
        provider.narrow = False
        admitted(graph, emit(graph), request_id="b" * 32)
        assert execute_next(graph.combat)["state"] == "applied"
        provider.fail_delete = True
        assert graph.combat.request_breach_action(None, case_id, "lift_lockdown", "c" * 32)
        assert execute_next(graph.combat)["state"] == "unknown"
        assert graph.config.breach_lifted_cases == []
        assert len(provider.rules) == 3


def test_receipt_recovery_latches_without_inventing_fresh_targets_and_lift_stays_red_until_review(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        case_id = admitted(graph, emit(graph))
        assert execute_next(graph.combat)["state"] == "applied"
        controller = breach.BreachStateController(graph.manager, start=False)
        try:
            controller.process_once()
            snapshot = controller.snapshot()
            assert snapshot.active and snapshot.case_id == case_id
            assert snapshot.containment_state == "locked-down"
            actions = {row.action: row.enabled for row in snapshot.actions}
            assert actions["lift_lockdown"] and not actions["kill"] and not actions["isolate"]
            assert controller.request_action(case_id, "lift_lockdown")
            controller.process_once()
            assert execute_next(graph.combat)["state"] == "lifted"
            controller.process_once()
            assert controller.snapshot().active and controller.snapshot().containment_state == "lifted"
            assert controller.request_action(case_id, "review_resolved")
            controller.process_once()
            assert not controller.snapshot().active and controller.snapshot().state == "resolved"
        finally:
            controller.close()


def test_failed_admission_cannot_erase_existing_lockdown_and_stop_cancels_queue(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        controller = breach.BreachStateController(graph.manager, start=False)
        try:
            emit(graph)
            controller.process_once()
            assert execute_next(graph.combat)["state"] == "applied"
            controller.process_once()
            case_id = controller.snapshot().case_id
            assert controller.snapshot().containment_state == "locked-down"
            graph.combat.status = "stopped"
            controller._process_request(case_id, "lift_lockdown")
            assert controller.snapshot().containment_state == "locked-down"
            graph.combat.status = "running"
            assert graph.combat.request_breach_action(None, case_id, "lift_lockdown", "d" * 32)
            command = graph.combat._queue.get_nowait()
            graph.combat._forget_unhandled_submission(command)
            graph.combat._queue.task_done()
            assert graph.combat.breach_action_result("d" * 32)["state"] == "cancelled"
            assert not graph.combat._breach_pending
            assert len(provider.rules) == 3  # STOP never silently lifts protection.
        finally:
            controller.close()


def test_fresh_original_evidence_is_rechecked_after_queue_and_host_scope_is_not_added(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        event = emit(graph)
        admitted(graph, event)
        graph.bus.freeze_mesh()
        assert execute_next(graph.combat)["state"] == "held"
        assert provider.calls == []
    with native_graph(tmp_path / "other") as graph:
        bind_provider(graph, provider, monkeypatch)
        event = emit(graph, **authorize_response(["terminate_process"], pid=41000, process_create_time=12345.5))
        admitted(graph, event)
        assert execute_next(graph.combat)["state"] == "held"
        assert provider.calls == []


def test_queue_is_bounded_deduplicated_urgent_and_ui_never_waits_for_journal(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        graph.combat._queue.put_nowait(Event("background", "inert", Severity.INFO))
        event = emit(graph)
        case_id = admitted(graph, event)
        assert not graph.combat.request_breach_action(event, case_id, "isolate", "b" * 32)
        assert type(graph.combat._queue.get_nowait()) is _BreachCommand
        graph.combat._queue.task_done()
        for malformed in (None, [], {"name": "isolate"}):
            assert not graph.combat.request_breach_action(event, case_id, malformed, "f" * 32)
        monkeypatch.setattr(graph.combat, "list_actions", lambda **_: pytest.fail("Journal on admission"))
        assert graph.combat.request_breach_action(None, case_id, "lift_lockdown", "c" * 32)


@pytest.mark.parametrize("field,value", [
    ("Enabled: Yes", "Enabled: No"), ("Profiles: Domain,Private,Public", "Profiles: Private"),
    ("Protocol: Any", "Protocol: TCP"), ("InterfaceTypes: All", "InterfaceTypes: Wireless"),
    ("RemoteIP: Any", "RemoteIP: 192.0.2.1"), ("LocalIP: Any", "LocalIP: 127.0.0.1"),
    ("RemotePort: Any", "RemotePort: 443"), ("Action: Block", "Action: Allow"),
    ("Program: Any", "Program: C:\\fake.exe"), ("Service: Any", "Service: fake"),
])
def test_native_scope_projection_rejects_restricted_or_disabled_fields(tmp_path, provider, field, value):
    with native_graph(tmp_path) as graph:
        name = "Angerona-Combat-Host-0123456789-out"
        provider.rules[name] = {"dir": "out"}
        output = provider.query(["firewall", "show", "rule", f"name={name}", "verbose"])
        assert graph.combat._lockdown_rule_fields(output, name, "out")
        assert not graph.combat._lockdown_rule_fields(output.replace(field, value), name, "out")
        assert not graph.combat._lockdown_rule_fields(output + "\nAction: Block", name, "out")


def test_source_authority_and_unsigned_or_foreign_receipts_cannot_lift(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        case_id = admitted(graph, emit(graph))
        monkeypatch.setattr(breach, "protect_authority", lambda: (False, "Source Observe"))
        assert execute_next(graph.combat)["state"] == "held"
        assert provider.calls == []
        monkeypatch.setattr(breach, "protect_authority", lambda: (True, "Inert"))
        monkeypatch.setattr(graph.combat, "list_actions", lambda **_: [dict(action="isolate_host", status="applied",
            integrity_status="legacy-untrusted", undone=False, action_id="fake", details={"breach_case_id": case_id})])
        assert graph.combat.request_breach_action(None, case_id, "lift_lockdown", "b" * 32)
        assert execute_next(graph.combat)["state"] == "held"
        assert provider.calls == []


def test_manual_process_action_passes_only_original_generation_to_existing_backend(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        observed = []
        monkeypatch.setattr(graph.combat, "_act_on_process", lambda pid, policy, event, *_args, **kwargs:
                            observed.append((pid, policy, event, kwargs)) or [])
        event = emit(graph)
        admitted(graph, event, "kill", automatic=False)
        assert execute_next(graph.combat)["state"] == "held"
        pid, policy, original, kwargs = observed[0]
        assert pid == 41000 and original.details["process_create_time"] == 12345.5
        assert kwargs["allowed_actions"] == {"terminate_process"}
        assert policy.process_action == "terminate" and not policy.isolate_host and not policy.block_network
        assert graph.config.adversary_combat_process_action == "suspend"


def test_worker_command_rejects_tampered_original_and_never_calls_os(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        event = emit(graph)
        case_id = admitted(graph, event)
        command = graph.combat._queue.get_nowait()
        graph.combat._queue.task_done()
        forged = replace(command, event=replace(command.event, details={**command.event.details, "pid": 22}))
        graph.combat._execute_breach_command(forged)
        assert graph.combat.breach_action_result(command.request_id)["state"] == "held"
        assert provider.calls == []
        assert case_id not in graph.config.breach_lifted_cases


def test_pending_isolation_cannot_be_resolved_before_worker_completion(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        controller = breach.BreachStateController(graph.manager, start=False)
        try:
            emit(graph)
            controller.process_once()
            snapshot = controller.snapshot()
            assert snapshot.containment_state == "requested"
            assert not controller.request_action(snapshot.case_id, "review_resolved")
            controller._process_request(snapshot.case_id, "review_resolved")
            assert controller.snapshot().active
            assert execute_next(graph.combat)["state"] == "applied"
            controller.process_once()
            assert controller.snapshot().active and controller.snapshot().containment_state == "locked-down"
        finally:
            controller.close()


def test_global_lift_binds_displayed_cases_but_cannot_suppress_later_new_case(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        controller = breach.BreachStateController(graph.manager, start=False)
        try:
            emit(graph)
            controller.process_once()
            assert execute_next(graph.combat)["state"] == "applied"
            controller.process_once()
            first = controller.snapshot().case_id
            second_event = emit(graph, process_create_time=12346.5,
                **authorize_response(["isolate_host", "terminate_process"], local_host=True, pid=41000, process_create_time=12346.5))
            second = breach.verified_breach(second_event, graph.bus, graph.manager.modules).case_id
            controller.process_once()
            assert execute_next(graph.combat)["state"] == "held"  # Already managed by the first receipt.
            controller.process_once()
            assert controller.snapshot().case_id == first
            assert {first, second} == set(controller._published_cases)
            assert second in dict(controller.snapshot().details)["Verified cases in this review 1"]
            assert controller.request_action(first, "lift_lockdown")
            controller.process_once()
            assert execute_next(graph.combat)["state"] == "lifted"
            controller.process_once()
            assert set(graph.config.breach_lifted_cases) == {first, second}
            third_event = emit(graph, process_create_time=12347.5,
                **authorize_response(["isolate_host", "terminate_process"], local_host=True, pid=41000, process_create_time=12347.5))
            third = breach.verified_breach(third_event, graph.bus, graph.manager.modules).case_id
            controller.process_once()
            assert execute_next(graph.combat)["state"] == "applied"
            controller.process_once()
            assert controller.snapshot().case_id == third and controller.snapshot().containment_state == "locked-down"
        finally:
            controller.close()


def test_terminal_scope_change_never_leaves_a_successful_commit(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        query = provider.query
        reads = []
        def changed_scope(arguments):
            if arguments[:3] == ["firewall", "show", "rule"] and arguments[-1] == "verbose":
                reads.append(arguments)
                if len(reads) > 2:
                    provider.narrow = True
            return query(arguments)
        monkeypatch.setattr(graph.combat, "_lockdown_query", changed_scope)
        admitted(graph, emit(graph))
        result = execute_next(graph.combat)
        assert result["state"] == "held"
        assert len(provider.rules) == 1
        assert not any(row.get("status") == "applied" for row in graph.combat.list_actions())


def test_durable_undo_recovers_suppression_without_recreating_mutation_targets(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        case_id = admitted(graph, emit(graph))
        assert execute_next(graph.combat)["state"] == "applied"
        assert graph.combat.request_breach_action(None, case_id, "lift_lockdown", "b" * 32)
        assert execute_next(graph.combat)["state"] == "lifted"
        graph.config.breach_lifted_cases = []
        controller = breach.BreachStateController(graph.manager, start=False)
        try:
            controller.process_once()
            assert graph.config.breach_lifted_cases == [case_id]
            assert controller.snapshot().containment_state == "lifted"
            assert controller._cases[case_id]["evidence"] is None
            assert graph.combat._queue.empty()
        finally:
            controller.close()


@pytest.mark.parametrize("raw,code,expected", [
    (b"Ok.\r\n", 0, "Ok.\r\n"),
    (b"No rules match the specified criteria.\r\n", 1, "No rules match the specified criteria.\r\n"),
    (b"Unknown failure", 1, None), (b"x" * 32769, 0, None),
], ids=["success", "verified-absence", "provider-error", "output-budget"])
@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows redirected OEM output provider")
def test_owned_native_query_bounds_output_and_closes_disposable_custody(tmp_path, monkeypatch, raw, code, expected):
    import angerona.startup as startup
    instances = []
    class InertProbe:
        def __init__(self, command, *, cwd, env, stdout):
            self.returncode = code
            self.closed = False
            self.command = command
            stdout.write(raw)
            stdout.flush()
            instances.append(self)
        def poll(self):
            return self.returncode
        def wait_tree(self, timeout):
            return True
        def close(self):
            self.closed = True
    monkeypatch.setattr(startup, "_WindowsProbe", InertProbe)
    with native_graph(tmp_path) as graph:
        monkeypatch.setattr(graph.combat, "_lockdown_netsh", lambda: "C:\\Windows\\System32\\netsh.exe")
        result = graph.combat._lockdown_query(["firewall", "show", "rule", "name=Angerona-Combat-Host-0123456789-in"])
        assert result == expected
        assert len(instances) == 1 and instances[0].closed
        assert instances[0].command[0] == "C:\\Windows\\System32\\netsh.exe"


def test_unowned_rule_names_are_rejected_before_native_mutation(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        assert not graph.combat._run_lockdown_firewall(["delete", "rule", "name=User existing allow rule"])
        assert not graph.combat._run_lockdown_firewall(["reset", "name=Angerona-Combat-Host-0123456789-in"])
        assert provider.calls == []


def test_receipt_query_honors_controller_stop_and_retires_only_owned_probe(tmp_path, monkeypatch):
    import angerona.startup as startup
    import threading
    cancelled = threading.Event()
    instances = []
    class InertProbe:
        def __init__(self, *_args, **_kwargs):
            self.closed = False
            instances.append(self)
        def poll(self):
            cancelled.set()
            return None
        def close(self):
            self.closed = True
    monkeypatch.setattr(startup, "_WindowsProbe", InertProbe)
    with native_graph(tmp_path) as graph:
        monkeypatch.setattr(graph.combat, "_lockdown_netsh", lambda: "C:\\Windows\\System32\\netsh.exe")
        assert graph.combat._lockdown_query(["show", "allprofiles", "state"], cancel=cancelled) is None
        assert len(instances) == 1 and instances[0].closed
        # Cancellation already set: do not even construct a new native owner.
        assert graph.combat._lockdown_query(["show", "allprofiles", "state"], cancel=cancelled) is None
        assert len(instances) == 1


def test_case_arriving_after_lift_request_cannot_borrow_older_operator_override(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        controller = breach.BreachStateController(graph.manager, start=False)
        try:
            emit(graph)
            controller.process_once()
            assert execute_next(graph.combat)["state"] == "applied"
            controller.process_once()
            first = controller.snapshot().case_id
            assert controller.request_action(first, "lift_lockdown")
            late = emit(graph, process_create_time=98765.5,
                **authorize_response(["isolate_host", "terminate_process"], local_host=True, pid=41000, process_create_time=98765.5))
            late_id = breach.verified_breach(late, graph.bus, graph.manager.modules).case_id
            controller.process_once()
            assert execute_next(graph.combat)["state"] == "lifted"
            assert first in graph.config.breach_lifted_cases and late_id not in graph.config.breach_lifted_cases
            assert execute_next(graph.combat)["state"] == "applied"
            assert len(provider.rules) == 3
        finally:
            controller.close()


def test_partial_global_lift_promotes_remaining_receipt_and_keeps_retry_available(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        first = admitted(graph, emit(graph))
        assert execute_next(graph.combat)["state"] == "applied"
        older_rules = set(graph.combat.list_actions()[0]["details"]["rules"])
        # Model two recovered historical receipts, without touching a real OS.
        graph.combat._host_isolated = False
        second = admitted(graph, emit(graph, process_create_time=12346.5,
            **authorize_response(["isolate_host", "terminate_process"], local_host=True, pid=41000, process_create_time=12346.5)), request_id="b" * 32)
        assert execute_next(graph.combat)["state"] == "applied"
        controller = breach.BreachStateController(graph.manager, start=False)
        try:
            controller.process_once()
            assert controller.snapshot().case_id == second
            query = provider.query
            def partial_delete(arguments, **kwargs):
                if arguments[:2] == ["firewall", "delete"] and any(f"name={name}" in arguments for name in older_rules):
                    return None
                return query(arguments, **kwargs)
            monkeypatch.setattr(graph.combat, "_lockdown_query", partial_delete)
            assert controller.request_action(second, "lift_lockdown")
            controller.process_once()
            assert execute_next(graph.combat)["state"] == "unknown"
            controller._last_sync = 0
            controller.process_once()
            snapshot = controller.snapshot()
            assert snapshot.active and snapshot.case_id == first
            assert snapshot.containment_state in {"locked-down", "unknown"}
            assert any(row.action == "lift_lockdown" and row.enabled for row in snapshot.actions)
            assert older_rules.issubset(provider.rules)
        finally:
            controller.close()


@pytest.mark.parametrize("profile", ["Domain", "Private", "Public"])
@pytest.mark.parametrize("value", ["False", "NotConfigured", "", None])
def test_any_unmerged_or_unknown_effective_profile_holds_before_rule_add(tmp_path, provider, monkeypatch, profile, value):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        next(row for row in provider.effective_policy["profiles"] if row["name"] == profile)["local_rules"] = value
        admitted(graph, emit(graph))
        result = execute_next(graph.combat)
        assert result["state"] == "held" and "Effective firewall policy" in result["message"]
        assert provider.rules == {"User existing allow rule": {"action": "allow"}}
        assert not any(call[:2] == ["firewall", "add"] for call in provider.calls)


@pytest.mark.parametrize("change", ["gp-override", "inbound-blocked", "inactive-store", "duplicate-profile", "disabled-interface", "disabled-inbound"])
def test_effective_policy_requires_all_profiles_and_current_modification_permission(tmp_path, provider, monkeypatch, change):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        if change == "gp-override":
            provider.effective_policy["modify_state"] = 1
        elif change == "inbound-blocked":
            provider.effective_policy["modify_state"] = 2
        elif change == "inactive-store":
            provider.effective_policy["store"] = "PersistentStore"
        elif change == "duplicate-profile":
            provider.effective_policy["profiles"][0]["name"] = "Private"
        elif change == "disabled-interface":
            provider.effective_policy["profiles"][0]["disabled_interfaces"] = ["Ethernet"]
        elif change == "disabled-inbound":
            provider.effective_policy["profiles"][0]["inbound_rules"] = "False"
        assert graph.combat._lockdown_effective_policy() is False
        assert "Effective" in graph.combat._lockdown_policy_reason


def test_recovery_never_keeps_verified_lockdown_when_effective_policy_changes(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        admitted(graph, emit(graph))
        assert execute_next(graph.combat)["state"] == "applied"
        provider.effective_policy["profiles"][2]["local_rules"] = "False"
        controller = breach.BreachStateController(graph.manager, start=False)
        try:
            controller.process_once()
            assert controller.snapshot().active
            assert controller.snapshot().containment_state == "unknown"
            assert "Effective firewall policy" in dict(controller.snapshot().details)["Review"]
            assert any(row.action == "lift_lockdown" and row.enabled for row in controller.snapshot().actions)
        finally:
            controller.close()


def test_description_absence_phrase_never_skips_owned_rule_deletion(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        case_id = admitted(graph, emit(graph))
        assert execute_next(graph.combat)["state"] == "applied"
        query = provider.query
        def described(arguments, **kwargs):
            output = query(arguments, **kwargs)
            return output + "\nDescription: no rules match the specified criteria." if arguments[:3] == ["firewall", "show", "rule"] and "Rule Name:" in (output or "") else output
        monkeypatch.setattr(graph.combat, "_lockdown_query", described)
        own_rule = next(name for name in provider.rules if name.startswith("Angerona-Combat-Host-"))
        assert graph.combat._lockdown_rule_present(own_rule) is True
        assert graph.combat.request_breach_action(None, case_id, "lift_lockdown", "b" * 32)
        assert execute_next(graph.combat)["state"] == "lifted"
        assert provider.rules == {"User existing allow rule": {"action": "allow"}}
        assert len([call for call in provider.calls if call[:2] == ["firewall", "delete"]]) == 2


@pytest.mark.parametrize("mode", ["maximum", "contain"])
def test_legacy_same_event_queue_is_observation_only_in_source_mode(tmp_path, provider, monkeypatch, mode):
    import angerona.modules.adversary_combat as combat_module
    with native_graph(tmp_path, adversary_combat_mode=mode, adversary_combat_quarantine_files=True,
                      adversary_combat_block_network=True,
                      adversary_combat_process_action="terminate" if mode == "maximum" else "suspend") as graph:
        bind_provider(graph, provider, monkeypatch)
        path = tmp_path / "inert.bin"
        path.write_bytes(b"inert fixture")
        event = emit(graph, path=str(path), remote_ip="192.0.2.25",
            **authorize_response(["isolate_host", "terminate_process", "suspend_process", "quarantine_file", "block_remote_ip"],
                local_host=True, pid=41000, process_create_time=12345.5, path=path, remote_ips=["192.0.2.25"]))
        monkeypatch.setattr(breach, "protect_authority", lambda: (False, "Source Observe"))
        monkeypatch.setattr(combat_module, "psutil", SimpleNamespace(Process=lambda *_: pytest.fail("Source process access")))
        graph.combat._submit(event)
        queued = graph.combat._queue.get_nowait()
        try:
            graph.combat._handle(queued)
        finally:
            graph.combat._queue.task_done()
        assert provider.calls == [] and path.read_bytes() == b"inert fixture"
        assert graph.combat.list_actions() == []
        assert graph.combat.response_snapshot()["state"] == "AUTHORITY HELD"
        assert graph.combat._response_counts["authority_held"] == 1


def test_classifier_rejection_cannot_select_legacy_host_mutation_in_source(tmp_path, provider, monkeypatch):
    with native_graph(tmp_path) as graph:
        bind_provider(graph, provider, monkeypatch)
        event = emit(graph, spyware_confirmed=False)
        assert breach.verified_breach(event, graph.bus, graph.manager.modules) is None
        monkeypatch.setattr(breach, "protect_authority", lambda: (False, "Source Observe"))
        assert graph.combat._isolate_host(event, "inert-legacy") is None
        assert graph.combat._block_remote_ip("192.0.2.25", event, "inert-legacy") is None
        assert graph.combat._block_program("C:/inert.exe", 41000, 12345.5, event, "inert-legacy") is None
        assert provider.calls == []


@pytest.mark.parametrize("change", ["stop", "source-authority", "disabled-policy"])
def test_blocking_intent_persistence_cannot_outlive_stop_or_authority(tmp_path, provider, monkeypatch, change):
    import angerona.modules.adversary_combat as combat_module
    # This fixture changes saved policy. An inherited CLI/environment override
    # legitimately takes precedence, so remove it to exercise that exact source.
    monkeypatch.delenv("ANGERONA_ADVERSARY_COMBAT_ENABLED", raising=False)
    with native_graph(tmp_path) as graph:
        assert graph.combat.policy().enabled is True
        event = emit(graph)
        action = graph.combat._action("terminate_process", "inert generation", event, "inert",
            reversible=False, details={"pid": 41000, "create_time": 12345.5, "name": "inert.exe", "exe": "C:/inert.exe"})
        calls = []
        process = SimpleNamespace(kill=lambda: calls.append("kill"))
        monkeypatch.setattr(combat_module, "_WINDOWS_PROCESS_CUSTODY", False)
        original_intent = graph.combat._journal_intent
        intent_entered = False
        def blocked_intent(record):
            nonlocal intent_entered
            original_intent(record)
            intent_entered = True
            if change == "stop":
                graph.combat._stop.set()
            elif change == "source-authority":
                monkeypatch.setattr(breach, "protect_authority", lambda: (False, "Source Observe"))
            else:
                graph.config.adversary_combat_enabled = False
                assert graph.combat.policy().enabled is False
        monkeypatch.setattr(graph.combat, "_journal_intent", blocked_intent)
        assert graph.combat._terminate_process_transaction(process, action) is None
        assert intent_entered is True
        assert calls == []
        assert not any(row.get("status") == "applied" for row in graph.combat.list_actions())


def test_stop_after_native_validation_is_rechecked_before_irreversible_dispatch(tmp_path, provider, monkeypatch):
    import angerona.modules.adversary_combat as combat_module
    with native_graph(tmp_path) as graph:
        event = emit(graph)
        action = graph.combat._action("terminate_process", "inert generation", event, "inert",
            reversible=False, details={"pid": 41000, "create_time": 12345.5, "name": "inert.exe", "exe": "C:/inert.exe"})
        calls = []
        class Lease:
            identity = SimpleNamespace(pid=41000, birth_ticks=1, image="C:/inert.exe")
            dispatch_started = False
            def validate(self, *, alive):
                calls.append("validate")
                graph.combat._stop.set()
            def terminate(self):
                calls.append("terminate")
            def close(self):
                calls.append("close")
        monkeypatch.setattr(combat_module, "_WINDOWS_PROCESS_CUSTODY", True)
        monkeypatch.setattr(graph.combat, "_acquire_termination_lease", lambda *_: Lease())
        assert graph.combat._terminate_process_transaction(SimpleNamespace(), action) is None
        assert calls == ["validate", "close"]


@pytest.mark.parametrize("revoked", ["producer", "policy"])
def test_dispatch_rechecks_original_producer_contract_and_admitted_policy(tmp_path, provider, monkeypatch, revoked):
    import angerona.modules.adversary_combat as combat_module
    from angerona.core.windows_process_lease import WindowsProcessLease, ProcessObjectIdentity
    from test_windows_process_lease import FakeNative
    with native_graph(tmp_path) as graph:
        event = emit(graph)
        action = graph.combat._action("terminate_process", "inert generation", event, "inert",
            reversible=False, details={"pid": 41000, "create_time": 12345.5, "name": "inert.exe", "exe": "C:/fixture/target.exe"})
        native = FakeNative()
        native.target = ProcessObjectIdentity(41000, 116444859455000000, "c:/fixture/target.exe")
        identity = native.identity
        reads = []
        def final_read(handle):
            reads.append(handle)
            result = identity(handle)
            if len(reads) == 4:
                if revoked == "producer":
                    graph.bus.freeze_mesh()
                else:
                    graph.config.adversary_combat_process_action = "terminate"
            return result
        monkeypatch.setattr(native, "identity", final_read)
        monkeypatch.setattr(combat_module, "_WINDOWS_PROCESS_CUSTODY", True)
        monkeypatch.setattr(graph.combat, "_acquire_termination_lease",
            lambda *_: WindowsProcessLease(41000, 12345.5, "C:/fixture/target.exe", _native=native))
        baseline = graph.combat.policy()
        assert graph.combat._terminate_process_transaction(SimpleNamespace(), action, event=event, expected_policy=baseline) is None
        assert len(reads) == 4 and not native.exited
        assert not any(call[0] == "terminate" for call in native.calls)
