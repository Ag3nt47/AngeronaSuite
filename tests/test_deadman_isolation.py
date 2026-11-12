"""Dead-man isolation: off by default, admin-signed, fixed, verified, reversible."""
from __future__ import annotations

import pytest

from angerona.resilience import control_authority as ca
from angerona.resilience.deadman import RULES, DeadMan


class Firewall:
    """In-memory netsh stand-in; no host firewall access."""

    def __init__(self, fail_add: str = "", fail_delete: bool = False):
        self.rules: set[str] = set()
        self.calls: list[list[str]] = []
        self.fail_add, self.fail_delete = fail_add, fail_delete

    def __call__(self, arguments):
        self.calls.append(arguments)
        verb = arguments[2]
        name = next(a for a in arguments if a.startswith("name=")).split("=", 1)[1]
        if verb == "show":
            return name in self.rules
        if verb == "add":
            if name == self.fail_add:
                return False
            assert {"action=block", "remoteip=any", "profile=any"} <= set(arguments)
            self.rules.add(name)
            return True
        if verb == "delete":
            if self.fail_delete:
                return False
            self.rules.discard(name)
            return True
        raise AssertionError(arguments)


def _deadman(policy=None, admin=True, firewall=None):
    clock, events = [0.0], []
    firewall = firewall or Firewall()
    dm = DeadMan(lambda *a: events.append(a), policy=lambda: policy, is_admin=lambda: admin,
                 runner=firewall, clock=lambda: clock[0])
    return dm, clock, events, firewall


ENABLED = {"enabled": True, "threshold_s": 300.0}


def test_disabled_by_default_never_touches_the_firewall():
    dm, clock, events, firewall = _deadman(policy=None)
    for _ in range(10):
        clock[0] += 600
        assert dm.tick("dead") == "disabled"
    assert not firewall.rules and not events
    assert all(call[2] == "show" for call in firewall.calls)


def test_engages_only_after_threshold_and_releases_when_core_returns():
    dm, clock, events, firewall = _deadman(policy=ENABLED)
    assert dm.tick("dead") == "armed"
    clock[0] += 299
    assert dm.tick("suspended") == "armed" and not firewall.rules
    clock[0] += 2
    assert dm.tick("dead") == "engaged"
    assert firewall.rules == {name for name, _ in RULES}
    assert events[-1][0] == "CRITICAL" and events[-1][2]["deadman"] == "engaged"
    assert dm.tick("alive") == "engaged"  # Not released on the first live sample.
    clock[0] += 16
    assert dm.tick("alive") == "idle" and not firewall.rules
    assert events[-1][2]["deadman"] == "released"


def test_brief_outage_and_unknown_states_never_engage():
    dm, clock, _events, firewall = _deadman(policy=ENABLED)
    dm.tick("dead")
    clock[0] += 200
    dm.tick("alive")
    clock[0] += 200
    assert dm.tick("dead") == "armed"  # Outage clock restarted.
    clock[0] += 1000
    assert dm.tick("unknown") in {"idle"} and not firewall.rules


def test_unelevated_watchdog_reports_once_and_does_not_act():
    dm, clock, events, firewall = _deadman(policy=ENABLED, admin=False)
    dm.tick("dead")
    clock[0] += 301
    assert dm.tick("dead") == "not_elevated"
    assert dm.tick("dead") == "not_elevated"
    assert [e[2]["deadman"] for e in events] == ["not_elevated"] and not firewall.rules


def test_partial_apply_is_rolled_back_and_not_retried_every_tick():
    firewall = Firewall(fail_add="Angerona-DeadMan-in")
    dm, clock, events, _ = _deadman(policy=ENABLED, firewall=firewall)
    dm.tick("dead")
    clock[0] += 301
    assert dm.tick("dead") == "failed"
    assert not firewall.rules and events[-1][2] == {"deadman": "failed", "rolled_back": True}
    adds = sum(1 for c in firewall.calls if c[2] == "add")
    assert dm.tick("dead") == "failed"
    assert sum(1 for c in firewall.calls if c[2] == "add") == adds


def test_standdown_never_engages_and_releases_an_existing_hold():
    dm, clock, events, firewall = _deadman(policy=ENABLED)
    dm.tick("dead")
    clock[0] += 301
    dm.tick("dead")
    assert dm.engaged
    assert dm.tick("stopped", standdown=True) == "standdown"
    assert not firewall.rules and not dm.engaged


def test_existing_rules_are_adopted_after_a_watchdog_restart_and_release_failure_is_loud():
    firewall = Firewall(fail_delete=True)
    firewall.rules = {name for name, _ in RULES}
    dm, clock, events, _ = _deadman(policy=None, firewall=firewall)
    assert dm.engaged
    dm.tick("alive")
    clock[0] += 16
    dm.tick("alive")
    assert dm.engaged and events[-1][0] == "CRITICAL" and events[-1][2]["deadman"] == "release_failed"


def test_policy_is_admin_signed_bounded_and_fails_closed(tmp_path, monkeypatch):
    root = tmp_path / "control"
    ca.provision(root, require_admin=False)
    assert ca.deadman_policy(root) is None  # Off by default.
    ca.set_deadman(True, 300, root=root, require_admin=False)
    assert ca.deadman_policy(root) == {"enabled": True, "threshold_s": 300.0}
    with pytest.raises(ValueError):
        ca.set_deadman(True, 30, root=root, require_admin=False)
    text = (root / "deadman.json").read_text().replace("300.0", "120.0")
    (root / "deadman.json").write_text(text)  # Edited without the admin key.
    assert ca.deadman_policy(root) is None
    ca.set_deadman(False, root=root, require_admin=False)
    assert ca.deadman_policy(root) is None
    monkeypatch.setattr(ca, "is_admin", lambda: False)
    with pytest.raises(ca.AdminApprovalRequired):
        ca.set_deadman(True, 300, root=root)
