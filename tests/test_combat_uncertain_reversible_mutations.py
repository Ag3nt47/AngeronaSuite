"""Model host effects in memory; never issue firewall or process operations."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import Event, Severity
from angerona.modules import adversary_combat as combat


def _fixture(monkeypatch, tmp_path):
    module = combat.AdversaryCombat(tmp_path, rollback_anchor={})
    records = []

    def append(payload):
        record = {**payload, "sequence": len(records) + 1, "record_hmac": "a" * 64}
        records.append(record)
        return record

    @contextmanager
    def transaction(action):
        append({**asdict(action), "record_type": "intent", "status": "pending"})
        yield

    monkeypatch.setattr(module, "_append_journal", append)
    monkeypatch.setattr(module, "_journaled_mutation", transaction)
    monkeypatch.setattr(module, "set_health", lambda *_args: None)
    monkeypatch.setattr(module, "emit", lambda *_args, **_kwargs: None)
    return module, records


@pytest.mark.parametrize("kind", ["block_remote_ip", "isolate_host", "isolate_program"])
@pytest.mark.parametrize("rollback_fails", [False, True])
def test_uncertain_firewall_effects_close_only_after_verified_rollback(
    monkeypatch, tmp_path, kind, rollback_fails,
):
    module, records = _fixture(monkeypatch, tmp_path)
    rules = set()
    add_count = 0

    def firewall(arguments):
        nonlocal add_count
        name = next(value[5:] for value in arguments if value.startswith("name="))
        if arguments[0] == "add":
            add_count += 1
            rules.add(name)
            # A failed command/postcondition can still have created its rule.
            return kind == "isolate_program" or add_count == 1
        if rollback_fails:
            return False
        rules.discard(name)
        return True

    monkeypatch.setattr(module, "_run_firewall", firewall)
    monkeypatch.setattr(module, "_firewall_rule_exists", lambda name: name in rules)
    monkeypatch.setattr(combat, "psutil", SimpleNamespace(Process=lambda _pid: SimpleNamespace(
        exe=lambda: "C:/fixture/inert.exe", create_time=lambda: 22.0)))
    event = Event("Inert Detector", "fixture", Severity.HIGH)
    if kind == "block_remote_ip":
        result = module._block_remote_ip("203.0.113.8", event, "combat-aaaaaaaaaaaa")
    elif kind == "isolate_host":
        result = module._isolate_host(event, "combat-aaaaaaaaaaaa")
    else:
        result = module._block_program("C:/fixture/inert.exe", 999999, 11.0,
                                       event, "combat-aaaaaaaaaaaa")
    assert result is None
    phases = [record["record_type"] for record in records]
    assert "orphan" in phases and "undo_intent" in phases
    if rollback_fails:
        assert rules
        assert "failure" not in phases
        assert "undo_failure" in phases
        assert module._mutation_blocked and module._recovery_required
    else:
        assert not rules
        assert phases[-2:] == ["undo_commit", "failure"]
        assert not module._mutation_blocked


def test_suspend_unknown_postcondition_keeps_pending_recovery(monkeypatch, tmp_path):
    module, records = _fixture(monkeypatch, tmp_path)
    calls = []

    def status():
        raise RuntimeError("inert postcondition read failure")

    process = SimpleNamespace(create_time=lambda: 10.0, name=lambda: "inert-worker.exe",
                              exe=lambda: "C:/fixture/inert.exe", status=status,
                              suspend=lambda: calls.append("suspend"),
                              resume=lambda: calls.append("resume"))
    monkeypatch.setattr(combat, "psutil", SimpleNamespace(Process=lambda _pid: process,
                                                        STATUS_STOPPED="stopped"))
    monkeypatch.setattr(combat.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(module, "_is_system_path", lambda _path: False)
    event = Event("Inert Detector", "fixture", Severity.HIGH,
                  details={"pid": 999999, "process_create_time": 10.0})
    result = module._act_on_process(
        999999, combat.CombatPolicy(mode="contain", block_network=False), event,
        "combat-aaaaaaaaaaaa", allowed_actions=frozenset({"suspend_process"}),
    )
    assert not result
    assert calls == ["suspend"]  # unknown state must not cause a blind resume
    assert module._mutation_blocked
    assert "failure" not in [record["record_type"] for record in records]
    assert records[-1]["record_type"] == "undo_failure"


def test_rollback_undo_receipt_failure_disarms_even_when_host_restored(monkeypatch, tmp_path):
    module, records = _fixture(monkeypatch, tmp_path)
    action = module._action("suspend_process", "inert", Event("Fixture", "x", Severity.HIGH),
                            "combat-aaaaaaaaaaaa", reversible=True,
                            details={"pid": 999999, "create_time": 10.0})
    monkeypatch.setattr(module, "_undo_record", lambda _record: (True, ""))
    original_append = module._append_journal

    def append(payload):
        if payload["record_type"] == "undo_commit":
            raise OSError("inert durable receipt failure")
        return original_append(payload)

    monkeypatch.setattr(module, "_append_journal", append)
    module._rollback_uncertain_reversible_mutation(action, "uncertain fixture",
                                                  release_custody=lambda: None)
    assert module._mutation_blocked
    assert "failure" not in [record["record_type"] for record in records]


@pytest.mark.parametrize("state", [None, False])
def test_firewall_rollback_requires_proven_absence(monkeypatch, tmp_path, state):
    module, records = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "_run_firewall", lambda _args: False)
    monkeypatch.setattr(module, "_firewall_rule_exists", lambda _name: state)
    module._block_remote_ip("203.0.113.8", Event("Fixture", "x", Severity.HIGH),
                            "combat-aaaaaaaaaaaa")
    phases = [record["record_type"] for record in records]
    assert module._mutation_blocked is (state is None)
    assert ("failure" in phases) is (state is False)
    assert ("undo_failure" in phases) is (state is None)


@pytest.mark.parametrize("returncode, output, expected", [
    (0, "Rule Name: AngeronaCombat-test", True),
    (1, "No rules match the specified criteria.", False),
    (1, "The service is not running.", None),
    (0, "", None),
])
def test_firewall_query_distinguishes_absence_from_unavailable(
    monkeypatch, returncode, output, expected,
):
    from angerona.core import win

    # Replace only this module's os binding; do not change pathlib's platform.
    monkeypatch.setattr(combat, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(win, "run_hidden", lambda *_args, **_kwargs: SimpleNamespace(
        returncode=returncode, stdout=output, stderr=""))
    assert combat.AdversaryCombat._firewall_rule_exists("AngeronaCombat-test") is expected


def test_pending_firewall_recovery_waits_for_query_evidence(monkeypatch, tmp_path):
    module, records = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "_run_firewall", lambda _args: False)
    monkeypatch.setattr(module, "_firewall_rule_exists", lambda _name: None)
    module._block_remote_ip("203.0.113.8", Event("Fixture", "x", Severity.HIGH),
                            "combat-aaaaaaaaaaaa")
    original = list(records)
    monkeypatch.setattr(module, "_read_journal", lambda **_kwargs: (list(records), []))
    with pytest.raises(combat.JournalIntegrityError, match="postcondition is unavailable"):
        module._recover_orphaned_journal()
    assert records == original
    assert module._mutation_blocked
    monkeypatch.setattr(module, "_firewall_rule_exists", lambda _name: False)
    module._recover_orphaned_journal()
    assert records[-1]["record_type"] == "failure"
