from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import privilege
from angerona.resilience import deadman


NAMES = tuple(name for name, _direction in deadman.RULES)
ENABLED = {"enabled": True, "threshold_s": 300.0}


class Firewall:
    """In-memory presence provider and fixed-rule mutations only."""

    def __init__(self, rules=()):
        self.rules = set(rules)
        self.unknown = set()
        self.unknown_after_delete = False
        self.fail_add = ""
        self.fail_delete = False
        self.calls = []
        self.queries = 0

    def probe(self):
        self.queries += 1
        return {name: deadman.UNAVAILABLE if name in self.unknown else
                deadman.PRESENT if name in self.rules else deadman.ABSENT for name in NAMES}

    def run(self, arguments):
        self.calls.append(list(arguments))
        verb = arguments[2]
        name = next(value.removeprefix("name=") for value in arguments if value.startswith("name="))
        assert name in NAMES and verb in {"add", "delete"}  # No Boolean show result is consumed.
        if verb == "add":
            if name == self.fail_add:
                return False
            self.rules.add(name)
            return True
        if self.fail_delete:
            return False
        self.rules.discard(name)
        if self.unknown_after_delete:
            self.unknown.update(NAMES)
        return True


def module(firewall, *, policy=None, admin=True):
    clock, events = [0.0], []
    value = deadman.DeadMan(lambda *args: events.append(args), policy=lambda: policy,
                           is_admin=lambda: admin, runner=firewall.run, probe=firewall.probe,
                           clock=lambda: clock[0])
    return value, clock, events


def test_disabled_unknown_query_never_grants_firewall_writes_or_release():
    firewall = Firewall()
    firewall.unknown.update(NAMES)
    value, clock, events = module(firewall)
    for _index in range(4):
        assert value.tick("dead") == "failed"
        clock[0] += 16
    assert value._cleanup_pending and not value.engaged
    assert firewall.calls == []
    assert firewall.queries <= 1 + 2 * 4
    assert not any(details["deadman"] == "released" for _level, _message, details in events)


def test_partial_restart_residue_only_deletes_positively_present_owned_rule():
    firewall = Firewall((NAMES[0],))
    firewall.unknown.add(NAMES[1])
    value, clock, events = module(firewall)
    assert value._cleanup_pending and not value.engaged
    assert value.tick("dead") == "failed"
    assert [call[4] for call in firewall.calls] == ["name=" + NAMES[0]]
    assert not firewall.rules and value._cleanup_pending
    assert events[-1][2]["deadman"] == "release_failed"
    firewall.unknown.clear()
    clock[0] += 16
    assert value.tick("dead") == "disabled"
    assert not value._cleanup_pending and not value.engaged
    assert events[-1][2]["deadman"] == "released"


def test_successful_delete_with_unavailable_readback_never_reports_released():
    firewall = Firewall(NAMES)
    value, clock, events = module(firewall)
    firewall.unknown_after_delete = True
    assert value.tick("stopped", standdown=True) == "failed"
    assert not firewall.rules and value._cleanup_pending
    assert events[-1][2]["deadman"] == "release_failed"
    before = (len(firewall.calls), firewall.queries)
    clock[0] += 1
    assert value.tick("stopped", standdown=True) == "failed"
    assert (len(firewall.calls), firewall.queries) == before
    firewall.unknown.clear()
    firewall.unknown_after_delete = False
    clock[0] += 15
    assert value.tick("stopped", standdown=True) == "standdown"
    assert not value._cleanup_pending and not value.engaged
    assert events[-1][2]["deadman"] == "released"


def test_failed_partial_rollback_remains_pending_through_unknown_query():
    firewall = Firewall()
    firewall.fail_add, firewall.fail_delete = NAMES[1], True
    value, clock, events = module(firewall, policy=ENABLED)
    assert value.tick("dead") == "armed"
    clock[0] += 301
    assert value.tick("dead") == "failed"
    assert firewall.rules == {NAMES[0]} and value._cleanup_pending
    assert events[-1][2]["rolled_back"] is False
    firewall.unknown.update(NAMES)
    clock[0] += 16
    before = len(firewall.calls)
    assert value.tick("dead") == "failed"
    assert len(firewall.calls) == before  # Unknown queries authorize no retry mutation.
    firewall.unknown.clear()
    firewall.fail_delete = False
    clock[0] += 16
    assert value.tick("dead") == "failed"
    assert not firewall.rules and not value._cleanup_pending
    assert value.tick("alive") == "idle"


def test_legacy_injected_bool_runner_remains_compatible():
    calls = []

    def legacy(arguments):
        calls.append(arguments)
        assert arguments[2] == "show"
        return False  # This fixture positively reports absence.

    value = deadman.DeadMan(lambda *_args: None, policy=lambda: None,
                           is_admin=lambda: True, runner=legacy, clock=lambda: 0.0)
    assert value.tick("dead") == "disabled"
    assert len(calls) == 2


@pytest.fixture
def native_probe(monkeypatch):
    # All subprocess execution and system-directory resolution are replaced.
    host = Path("Q:/Owned Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
    calls = []
    monkeypatch.setattr(deadman, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(privilege, "trusted_powershell_path", lambda: host)
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda: {"PATH": "inert system path"})

    def result(returncode=0, stdout=None, error=None):
        def run(arguments, **kwargs):
            calls.append((arguments, kwargs))
            assert arguments[0] == str(host)
            assert kwargs["timeout"] == deadman._QUERY_TIMEOUT_S
            assert kwargs["env"]["PSModulePath"] == str(host.parent / "Modules")
            script = base64.b64decode(arguments[-1]).decode("utf-16-le")
            assert "'CimCmdlets','CimCmdlets.psd1'" in script
            assert "'NetSecurity','NetSecurity.psd1'" in script
            assert "NetSecurity\\Get-NetFirewallRule -PolicyStore PersistentStore" in script
            assert "$PSModuleAutoLoadingPreference='None'" in script and "4096" in script
            assert "-ComputerName" not in script and "-CimSession" not in script
            if error:
                raise error
            return SimpleNamespace(returncode=returncode, stdout=stdout)
        monkeypatch.setattr(deadman.subprocess, "run", run)
    return result, calls


@pytest.mark.parametrize("states", [
    {name: deadman.ABSENT for name in NAMES},
    {NAMES[0]: deadman.PRESENT, NAMES[1]: deadman.ABSENT},
])
def test_successful_structured_local_query_distinguishes_presence_from_absence(native_probe, states):
    result, calls = native_probe
    result(stdout=json.dumps({"schema": 1, "states": states}).encode())
    assert deadman._query_owned_rules() == states
    assert len(calls) == 1


@pytest.mark.parametrize("case", ["permission", "timeout", "provider", "localized-error", "oversize", "bad-schema"])
def test_native_query_failure_is_unavailable_never_absent(native_probe, case):
    result, calls = native_probe
    absent = json.dumps({"schema": 1, "states": {name: deadman.ABSENT for name in NAMES}}).encode()
    if case == "permission":
        result(returncode=5, stdout=absent)
    elif case == "timeout":
        result(error=deadman.subprocess.TimeoutExpired("inert fixed query", 5))
    elif case == "provider":
        result(error=OSError("inert CIM provider unavailable"))
    elif case == "localized-error":
        result(stdout=b"No rules match the specified criteria")
    elif case == "oversize":
        result(stdout=b"x" * (deadman._MAX_QUERY_BYTES + 1))
    else:
        result(stdout=b'{"schema":1,"states":{}}')
    assert deadman._query_owned_rules() == {name: deadman.UNAVAILABLE for name in NAMES}
    assert len(calls) == 1


def test_disabled_unknown_source_coverage_has_bounded_medium_notices_and_queries():
    firewall = Firewall()
    firewall.unknown.update(NAMES)
    value, clock, events = module(firewall, admin=False)
    for second in range(901):
        clock[0] = float(second)
        assert value.tick("dead") == "failed"
    assert firewall.calls == []
    assert firewall.queries <= 5  # Constructor, first tick, then 300/600/900.
    assert len(events) == 2 and all(level == "MEDIUM" for level, _message, _details in events)
    assert events[-1][2]["repeats_since_last_report"] > 0
    assert all(details["owned_rule_evidence"] is False for _level, _message, details in events)
    assert value._cleanup_pending and not value.engaged
    # Explicit first stand-down rechecks immediately; newly observed residue
    # cannot inherit the old unknown-coverage advisory's severity/cooldown.
    firewall.unknown.remove(NAMES[0])
    firewall.rules.add(NAMES[0])
    clock[0] = 901.0
    assert value.tick("stopped", standdown=True) == "failed"
    assert events[-1][0] == "CRITICAL" and events[-1][2]["owned_rule_evidence"] is True
    assert firewall.calls == []  # Unelevated owner still cannot mutate.


def test_default_constructor_does_not_start_a_native_probe(monkeypatch):
    calls = []
    host = Path("Q:/Owned Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
    monkeypatch.setattr(deadman, "os", SimpleNamespace(name="nt"))

    def authority():
        calls.append("authority-query")
        return host

    def native(*_args, **_kwargs):
        calls.append("subprocess")
        raise AssertionError("No native probe belongs to construction")

    monkeypatch.setattr(privilege, "trusted_powershell_path", authority)
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda: {})
    monkeypatch.setattr(deadman.subprocess, "run", native)
    value = deadman.DeadMan(lambda *_args: None, policy=lambda: None, is_admin=lambda: False)
    assert calls == []
    assert value._cleanup_pending and not value.engaged and not value._owned_rule_evidence


def test_default_native_probe_first_runs_on_tick_then_obeys_unknown_retry(monkeypatch):
    probes, events, clock = [], [], [0.0]

    def unavailable():
        probes.append(clock[0])
        return {name: deadman.UNAVAILABLE for name in NAMES}

    monkeypatch.setattr(deadman, "_query_owned_rules", unavailable)
    monkeypatch.setattr(deadman, "_netsh", lambda *_args: pytest.fail("Unknown rules authorize no writes"))
    value = deadman.DeadMan(lambda *args: events.append(args), policy=lambda: None,
                           is_admin=lambda: False, clock=lambda: clock[0])
    assert probes == []
    value.tick("dead")
    assert probes == [0.0] and events[0][0] == "MEDIUM"
    clock[0] = deadman._UNKNOWN_QUERY_RETRY_S - 1
    value.tick("dead")
    assert probes == [0.0]
    clock[0] += 1
    value.tick("dead")
    assert probes == [0.0, deadman._UNKNOWN_QUERY_RETRY_S]
    assert all(level == "MEDIUM" for level, _message, _details in events)
