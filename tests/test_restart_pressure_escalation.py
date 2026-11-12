"""Restart-loop bypass: paced kills that dodge 3-in-60 s SAFE_MODE still escalate."""
from __future__ import annotations

from angerona.core.module_manager import ModuleManager
from angerona.resilience import supervisor as supervisor_module
from angerona.resilience.supervisor import Component, ProcessSupervisor


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def _supervisor():
    clock, events = Clock(), []
    sup = ProcessSupervisor(on_event=lambda level, msg, details: events.append((level, msg, details)),
                            clock=clock)
    return sup, clock, events


def _component() -> Component:
    return Component(name="core", argv=["inert"])


def test_pressure_hint_survives_the_sidecar_environment_allowlist():
    from angerona.core.privilege import sanitized_child_environment

    source = {"PATH": "/usr/bin", "ANGERONA_SUPERVISED_RECOVERY": "1",
              "ANGERONA_RECOVERY_PRESSURE": "attack", "ANGERONA_UNREVIEWED": "x"}
    child = sanitized_child_environment(source=source)
    # Without this the relaunched core never learns it is under restart pressure.
    assert child["ANGERONA_RECOVERY_PRESSURE"] == "attack"
    assert child["ANGERONA_SUPERVISED_RECOVERY"] == "1"
    assert "ANGERONA_UNREVIEWED" not in child


def test_paced_kills_every_61_seconds_escalate_to_attack_without_safe_mode():
    sup, clock, events = _supervisor()
    c = _component()
    for _ in range(5):
        sup._record_unexpected_stop(c, "dead")
        assert not sup._register_failure(c)  # Never 3 within 60 s: SAFE_MODE never trips.
        clock.now += 61.0
    levels = [(level, details.get("restart_pressure")) for level, _m, details in events]
    assert levels == [("HIGH", "elevated"), ("CRITICAL", "attack")]
    assert c.pressure_level == "attack"
    assert events[-1][2]["stops_3600s"] == 5


def test_slow_drip_over_a_day_still_reaches_attack():
    sup, clock, events = _supervisor()
    c = _component()
    for _ in range(12):
        sup._record_unexpected_stop(c, "dead")
        clock.now += 1900.0  # ~32 min apart: never 3 per 10 min or 5 per hour.
    assert c.pressure_level == "attack"
    assert [e[0] for e in events] == ["CRITICAL"]


def test_escalation_is_not_repeated_and_pressure_decays_after_a_quiet_day():
    sup, clock, events = _supervisor()
    c = _component()
    for _ in range(8):
        sup._record_unexpected_stop(c, "dead")
        clock.now += 30.0
    assert [e[0] for e in events] == ["HIGH", "CRITICAL"]  # One alert per level rise.
    clock.now += 86_401.0
    assert sup._pressure_level(c)[0] == ""
    assert not c._pressure


def test_attack_pressure_shortens_safe_mode_and_flags_priority_relaunch(monkeypatch):
    assert supervisor_module._SAFE_MODE_PRESSURE_COOLDOWN < supervisor_module._SAFE_MODE_COOLDOWN
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    monkeypatch.setenv("ANGERONA_RECOVERY_PRESSURE", "attack")
    assert ModuleManager._recovery_pressure() == "attack"
    monkeypatch.setenv("ANGERONA_RECOVERY_PRESSURE", "anything-else")
    assert ModuleManager._recovery_pressure() == ""


def test_priority_relaunch_cannot_be_forced_outside_supervised_recovery(monkeypatch):
    monkeypatch.delenv("ANGERONA_SUPERVISED_RECOVERY", raising=False)
    monkeypatch.setenv("ANGERONA_RECOVERY_PRESSURE", "attack")
    assert ModuleManager._recovery_pressure() == ""
    assert {"Process Monitor", "Persistence Sweep", "File Integrity Monitor"} <= ModuleManager._PRESSURE_PRIORITY


def test_pressure_history_round_trips_through_authenticated_recovery_state(tmp_path, monkeypatch):
    from angerona.resilience import recovery_state
    clock = Clock()
    monkeypatch.setattr(recovery_state.RecoveryStateStore, "_authority", lambda self: b"k" * 32, raising=False)
    store = recovery_state.RecoveryStateStore("pressure-test", clock=clock)
    store.path = tmp_path / "state.json"
    store.update_component("core", {"failures": [], "pressure": [clock.now - 10, clock.now - 5]})
    assert store.component("core")["pressure"] == [clock.now - 10, clock.now - 5]
    store.update_component("legacy", {"failures": []})
    assert store.component("legacy")["pressure"] == []
