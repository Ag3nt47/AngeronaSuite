"""Program-rule mutations are modeled in memory; real journal phases remain."""
from __future__ import annotations

from dataclasses import replace
import os
from types import SimpleNamespace

import pytest
from test_breach_lockdown import installed_protect_for_inert_combat
from test_program_firewall_lease import FakeNative

from angerona.core import program_firewall_lease as custody
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.response_contract import authorize_response
from angerona.modules import adversary_combat as combat


@pytest.fixture
def transaction(tmp_path, monkeypatch, installed_protect_for_inert_combat):
    module = combat.AdversaryCombat(tmp_path, rollback_anchor={})
    module.bind(EventBus())
    assert module._reconcile_state() is True
    native, clock, leases = FakeNative(), [0.0], []
    original = custody.ProgramFirewallLease

    def lease(pid, born, image):
        current = original(pid, born, image, _native=native, _monotonic=lambda: clock[0])
        leases.append(current)
        return current

    monkeypatch.setattr(custody, "ProgramFirewallLease", lease)
    monkeypatch.setattr(combat, "_WINDOWS_PROCESS_CUSTODY", True)
    # Any legacy PID re-query is a failure. All native file/process operations
    # are the in-memory adapter; no system firewall command is permitted.
    monkeypatch.setattr(combat, "psutil", SimpleNamespace(Process=lambda *_args:
        pytest.fail("Program transaction reselected a PID")))
    rules, calls = set(), []

    def firewall(arguments):
        calls.append(list(arguments))
        name = next(value[5:] for value in arguments if value.startswith("name="))
        if arguments[0] == "add":
            assert leases and not leases[0]._closed
            rules.add(name)
        else:
            assert leases and not leases[0]._closed
            rules.discard(name)
        return True

    monkeypatch.setattr(module, "_run_firewall", firewall)
    monkeypatch.setattr(module, "_firewall_rule_exists", lambda name: name in rules)
    event = Event("Owned Inert Detector", "Owned fixture", Severity.HIGH,
        details={"pid": 4242, "process_create_time": 50.0,
                 **authorize_response(["isolate_program"], pid=4242, process_create_time=50.0)})
    return SimpleNamespace(module=module, native=native, clock=clock, leases=leases,
                           rules=rules, calls=calls, firewall=firewall, event=event)


def execute(fixture):
    return fixture.module._block_program(r"c:\fixture\target.exe", 4242, 50.0,
        fixture.event, "combat-aaaaaaaaaaaa")


def records(fixture):
    return fixture.module._read_journal(strict=True)[0]


def test_same_objects_remain_held_through_real_intent_terminal_writer_and_close(transaction, monkeypatch):
    fixture = transaction
    original = fixture.module._append_journal
    phases = []

    def append(candidate):
        phases.append(candidate["record_type"])
        assert fixture.leases and not fixture.leases[0]._closed
        assert 99 not in fixture.native.closed
        return original(candidate)

    monkeypatch.setattr(fixture.module, "_append_journal", append)
    result = execute(fixture)
    assert result is not None and result.status == "applied"
    assert phases == ["intent", "commit"]
    assert result.details["program_file_id"] == "3" * 32
    assert "not mapped image or socket" in result.details["program_custody_scope"]
    assert len(fixture.calls) == 1 and fixture.calls[0][:2] == ["add", "rule"]
    assert fixture.leases[0]._closed and fixture.native.closed[-1] == 99
    history = records(fixture)
    assert history[0]["details"]["program_file_id"] == history[1]["details"]["program_file_id"]


def test_real_process_action_caller_preserves_psutil_spelling_but_dispatches_native_path(transaction, monkeypatch):
    fixture = transaction
    caller_path = r"C:\FiXtUrE\TaRgEt.ExE"
    process = SimpleNamespace(create_time=lambda: 50.0, name=lambda: "target.exe", exe=lambda: caller_path)
    lookups = []

    def lookup(pid):
        lookups.append(pid)
        return process

    monkeypatch.setattr(combat, "psutil", SimpleNamespace(Process=lookup))
    # This test concerns the real caller -> custody boundary. Native program
    # and firewall effects remain entirely modeled by the fixture.
    monkeypatch.setattr(fixture.module, "_is_system_path", lambda _path: False)
    policy = fixture.module.policy()
    result = fixture.module._act_on_process(4242, policy, fixture.event, "combat-aaaaaaaaaaaa",
        allowed_actions=frozenset({"isolate_program"}), expected_policy=policy)
    assert result and len(result) == 1 and result[0].details["exe"] == caller_path
    assert lookups == [4242]
    assert fixture.leases[0].path == fixture.native.process.image == r"c:\fixture\target.exe"
    assert "program=c:\\fixture\\target.exe" in fixture.calls[0]
    assert f"program={caller_path}" not in fixture.calls[0]
    assert all(call[1] != caller_path for call in fixture.native.calls if call[0] == "file")


@pytest.mark.parametrize("boundary", ["after_intent", "dispatch", "before_terminal", "after_fsync"])
def test_expiry_at_every_durable_boundary_never_returns_success(transaction, monkeypatch, boundary):
    fixture = transaction
    original_intent = fixture.module._journal_intent
    original_append = fixture.module._append_journal

    def intent(candidate):
        original_intent(candidate)
        if boundary == "after_intent":
            fixture.clock[0] = 60.0

    def firewall(arguments):
        result = fixture.firewall(arguments)
        if arguments[0] == "add" and boundary == "dispatch":
            fixture.clock[0] = 60.0
        return result

    def append(candidate):
        if candidate["record_type"] == "commit" and boundary == "before_terminal":
            fixture.clock[0] = 60.0
        result = original_append(candidate)
        if candidate["record_type"] == "commit" and boundary == "after_fsync":
            fixture.clock[0] = 60.0
        return result

    monkeypatch.setattr(fixture.module, "_journal_intent", intent)
    monkeypatch.setattr(fixture.module, "_run_firewall", firewall)
    monkeypatch.setattr(fixture.module, "_append_journal", append)
    assert execute(fixture) is None
    assert not fixture.rules and fixture.leases[0]._closed
    phases = [record["record_type"] for record in records(fixture)]
    if boundary == "after_intent":
        assert not fixture.calls and phases == ["intent", "failure"]
    else:
        assert "orphan" in phases and "undo_commit" in phases and phases[-1] == "failure"
        if boundary == "after_fsync":
            assert phases[:3] == ["intent", "commit", "orphan"]  # Preserve durable history.


@pytest.mark.parametrize("boundary", ["after_intent", "before_terminal", "after_fsync"])
def test_case_metadata_change_at_durable_barriers_refuses_and_compensates(transaction, monkeypatch, boundary):
    fixture = transaction
    original_intent = fixture.module._journal_intent
    original_append = fixture.module._append_journal

    def intent(candidate):
        original_intent(candidate)
        if boundary == "after_intent":
            fixture.native.case_flags[r"c:\fixture"] = 1

    def append(candidate):
        if candidate["record_type"] == "commit" and boundary == "before_terminal":
            fixture.native.case_flags[r"c:\fixture"] = 1
        result = original_append(candidate)
        if candidate["record_type"] == "commit" and boundary == "after_fsync":
            fixture.native.case_flags[r"c:\fixture"] = 1
        return result

    monkeypatch.setattr(fixture.module, "_journal_intent", intent)
    monkeypatch.setattr(fixture.module, "_append_journal", append)
    assert execute(fixture) is None
    assert not fixture.rules and fixture.leases[0]._closed
    phases = [record["record_type"] for record in records(fixture)]
    if boundary == "after_intent":
        assert not fixture.calls and phases == ["intent", "failure"]
    else:
        assert [call[0] for call in fixture.calls] == ["add", "delete"]
        assert "orphan" in phases and "undo_commit" in phases
        if boundary == "after_fsync":
            assert phases[:3] == ["intent", "commit", "orphan"]


@pytest.mark.parametrize("change", ["exit", "birth", "same_name", "ancestor", "case_sensitive"])
def test_identity_loss_after_possible_effect_requires_exact_rule_compensation(transaction, monkeypatch, change):
    fixture = transaction

    def firewall(arguments):
        result = fixture.firewall(arguments)
        if arguments[0] == "add":
            if change == "exit":
                fixture.native.exited = True
            elif change == "birth":
                fixture.native.process = replace(fixture.native.process, birth_ticks=1)
            elif change == "case_sensitive":
                fixture.native.case_flags[r"c:\fixture"] = 1
            else:
                path = r"c:\fixture" if change == "ancestor" else r"c:\fixture\target.exe"
                fixture.native.identities[path] = replace(fixture.native.identities[path], file_id="4" * 32)
        return result

    monkeypatch.setattr(fixture.module, "_run_firewall", firewall)
    assert execute(fixture) is None
    assert not fixture.rules
    assert [call[0] for call in fixture.calls] == ["add", "delete"]
    assert not fixture.module._mutation_blocked
    assert fixture.leases[0]._closed


@pytest.mark.parametrize("outcome", ["false", "exception"])
@pytest.mark.parametrize("rollback_fails", [False, True])
def test_ambiguous_dispatch_keeps_custody_through_rollback_or_recovery(transaction, monkeypatch, outcome, rollback_fails):
    fixture = transaction

    def firewall(arguments):
        if arguments[0] == "add":
            fixture.firewall(arguments)
            if outcome == "exception":
                raise OSError("inert command reply lost after effect")
            return False
        if rollback_fails:
            return False
        return fixture.firewall(arguments)

    monkeypatch.setattr(fixture.module, "_run_firewall", firewall)
    assert execute(fixture) is None
    phases = [record["record_type"] for record in records(fixture)]
    assert "orphan" in phases and "undo_intent" in phases
    assert fixture.module._mutation_blocked is rollback_fails
    assert bool(fixture.rules) is rollback_fails
    assert ("failure" in phases) is not rollback_fails
    assert fixture.leases[0]._closed


def test_commit_write_failure_retains_handles_until_exact_compensation(transaction, monkeypatch):
    fixture = transaction
    original = fixture.module._append_journal

    def append(candidate):
        assert not fixture.leases[0]._closed
        if candidate["record_type"] == "commit":
            raise OSError("inert terminal write failure")
        return original(candidate)

    monkeypatch.setattr(fixture.module, "_append_journal", append)
    assert execute(fixture) is None
    assert not fixture.rules
    assert "undo_commit" in [record["record_type"] for record in records(fixture)]
    assert fixture.leases[0]._closed


@pytest.mark.parametrize("change", ["stop", "policy", "contract"])
def test_last_dispatch_authority_is_rechecked_after_native_identity_reads(transaction, monkeypatch, change):
    fixture = transaction
    original = fixture.module._journal_intent

    def intent(candidate):
        original(candidate)
        if change == "stop":
            fixture.module._stop.set()
        elif change == "policy":
            monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_BLOCK_NETWORK", "0")
        else:
            fixture.event.details["response_authorized"] = False

    monkeypatch.setattr(fixture.module, "_journal_intent", intent)
    assert execute(fixture) is None
    assert not fixture.calls and not fixture.rules
    assert fixture.leases[0]._closed


def test_denied_installed_authority_does_not_acquire_or_persist(transaction, monkeypatch):
    from angerona.core import breach_state

    fixture = transaction
    monkeypatch.setattr(breach_state, "protect_authority", lambda: (False, "Source Observe"))
    assert execute(fixture) is None
    assert fixture.leases == fixture.calls == []
    assert records(fixture) == []


def test_missing_exact_contract_cannot_even_acquire_a_program_path_lease(transaction):
    fixture = transaction
    fixture.event.details["response_authorized"] = False
    assert execute(fixture) is None
    assert fixture.leases == fixture.calls == []
    assert [record["record_type"] for record in records(fixture)] == ["failure"]


def test_native_acquisition_failure_never_requeries_pid_or_dispatches(transaction, monkeypatch):
    fixture = transaction
    fixture.native.open_error = r"c:\fixture\target.exe"
    assert execute(fixture) is None
    assert fixture.calls == []
    assert [record["record_type"] for record in records(fixture)] == ["failure"]
    assert len(fixture.native.closed) == len(fixture.native.handles)


def test_close_uncertainty_keeps_recovery_visible_and_does_not_retry_raw_handles(transaction, monkeypatch):
    fixture = transaction
    original = fixture.module._append_journal

    def append(candidate):
        result = original(candidate)
        if candidate["record_type"] == "commit":
            fixture.native.close_error = fixture.leases[0]._files[-1][1]
        return result

    # Exact-rule compensation does not need a file handle after close failure.
    def firewall(arguments):
        if arguments[0] == "delete":
            name = next(value[5:] for value in arguments if value.startswith("name="))
            fixture.calls.append(list(arguments))
            fixture.rules.discard(name)
            return True
        return fixture.firewall(arguments)

    monkeypatch.setattr(fixture.module, "_append_journal", append)
    monkeypatch.setattr(fixture.module, "_run_firewall", firewall)
    assert execute(fixture) is None
    assert fixture.module._mutation_blocked and fixture.module._recovery_required
    assert not fixture.rules
    assert len(fixture.native.closed) == len(set(fixture.native.closed))
    assert records(fixture)[-1]["record_type"] == "orphan"


def test_unsupported_platform_preserves_no_effect_hold(transaction, monkeypatch):
    monkeypatch.setattr(combat, "_WINDOWS_PROCESS_CUSTODY", False)
    assert execute(transaction) is None
    assert transaction.calls == transaction.leases == []
    assert records(transaction) == []
