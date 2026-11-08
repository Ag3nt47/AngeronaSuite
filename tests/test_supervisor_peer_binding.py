"""Inert authenticated peer observations never confer destructive authority."""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest

from angerona.resilience import heartbeat, supervisor


@pytest.fixture
def peer(tmp_path, monkeypatch):
    key, mono, wall = bytes(range(32)), [10.0], [1000 * 10**9]
    path = tmp_path / "core.hb"
    monkeypatch.setattr(supervisor.time, "time_ns", lambda: wall[0])
    writer = heartbeat.HeartbeatWriter("core", token_raw=key, path=path)
    reader = heartbeat.HeartbeatReader("core", path=path, key_raw=key)
    component = supervisor.Component("core", [sys.executable, "-m", "angerona"], reader=reader)
    events, effects = [], []
    instance = supervisor.ProcessSupervisor(
        monotonic_clock=lambda: mono[0],
        on_event=lambda level, message, details: events.append((level, message, details)),
    )
    instance.components["core"] = component
    identity = {"pid": os.getpid(), "birth": 990.0, "image": sys.executable, "parent": None}
    monkeypatch.setattr(supervisor, "_heartbeat_process_identity", lambda *_: dict(identity))
    monkeypatch.setattr(supervisor.hb, "pid_alive", lambda _: True)
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(instance, "_terminate", lambda _: effects.append("terminate") or True)
    monkeypatch.setattr(supervisor, "spawn_detached", lambda *_a, **_k: effects.append("spawn"))
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _: effects.append("spawn-lock") or True)
    monkeypatch.setattr(instance, "_persist", lambda _: True)
    monkeypatch.setattr(instance, "_capture_recovery_snapshot", lambda *_: None)
    try:
        yield SimpleNamespace(instance=instance, component=component, writer=writer,
                              mono=mono, wall=wall, events=events, effects=effects,
                              identity=identity)
    finally:
        writer.close()


def test_valid_mac_and_pid_require_native_bound_counter_progress(peer):
    p = peer
    assert p.instance._assess(p.component) == "heartbeat-pending"
    assert p.instance._is_running(p.component) is False
    assert p.instance._spawn(p.component) is False
    assert p.effects == []
    p.writer.beat()
    assert p.instance._assess(p.component) == "alive"
    assert p.instance._spawn(p.component) is True
    assert p.component.adopted and p.effects == []


@pytest.mark.parametrize("failure", [ValueError, PermissionError, OSError])
def test_unavailable_or_wrong_role_identity_holds_without_spawning_or_killing(peer, monkeypatch, failure):
    p = peer

    def reject(*_):
        raise failure("inert wrong role or unavailable native identity")

    monkeypatch.setattr(supervisor, "_heartbeat_process_identity", reject)
    for _ in range(3):
        assert p.instance.tick()["core"] == "identity-unverified"
        assert p.instance._spawn(p.component) is False
    assert p.effects == [] and not p.component._failures
    assert sum("heartbeat_identity" in details for _, _, details in p.events) == 1


def test_same_pid_with_new_birth_needs_new_progress(peer):
    p = peer
    assert p.instance._assess(p.component) == "heartbeat-pending"
    p.writer.beat()
    assert p.instance._assess(p.component) == "alive"
    p.identity["birth"] += 1
    assert p.instance._assess(p.component) == "heartbeat-pending"
    assert not p.instance._spawn(p.component) and p.effects == []
    p.writer.beat()
    assert p.instance._assess(p.component) == "alive"


def test_wall_clock_refresh_does_not_hide_frozen_authenticated_counter(peer):
    p = peer
    assert p.instance._assess(p.component) == "heartbeat-pending"
    p.writer.beat()
    assert p.instance._assess(p.component) == "alive"
    # A still-fresh signed record cannot renew a monotonic progress deadline.
    p.mono[0] += p.component.stale_after_s
    assert p.instance._assess(p.component) == "suspended"
    assert not p.instance._spawn(p.component) and p.effects == []


def test_identity_failure_requires_new_progress_after_recovery(peer, monkeypatch):
    p = peer
    check = supervisor._heartbeat_process_identity
    p.instance._assess(p.component)
    p.writer.beat()
    assert p.instance._assess(p.component) == "alive"
    monkeypatch.setattr(supervisor, "_heartbeat_process_identity", lambda *_: (_ for _ in ()).throw(OSError()))
    assert p.instance._assess(p.component) == "identity-unverified"
    monkeypatch.setattr(supervisor, "_heartbeat_process_identity", check)
    assert p.instance._assess(p.component) == "heartbeat-pending"
    p.writer.beat()
    assert p.instance._assess(p.component) == "alive"


@pytest.mark.parametrize("wrong", ["role", "image", "birth"])
def test_process_observer_rejects_role_image_or_replayed_birth(monkeypatch, wrong):
    import psutil

    argv = [sys.executable, "-m", "angerona"]
    component = supervisor.Component("core", argv)
    process = SimpleNamespace(pid=123, cmdline=lambda: argv, create_time=lambda: 990.0,
                              exe=lambda: sys.executable, is_running=lambda: True)
    if wrong == "role":
        process.cmdline = lambda: [sys.executable, "-m", "unrelated.application"]
    elif wrong == "image":
        process.exe = lambda: os.path.join(os.path.dirname(sys.executable), "unrelated.exe")
    else:
        process.create_time = lambda: 1001.0
    monkeypatch.setattr(psutil, "Process", lambda _: process)
    with pytest.raises((ValueError, AttributeError)):
        supervisor._heartbeat_process_identity(component, {"pid": 123, "ts_ns": 1000 * 10**9})


@pytest.mark.skipif(os.name != "nt", reason="Windows retained query-only native custody")
def test_process_observer_uses_query_only_native_handle(monkeypatch):
    import psutil
    from angerona.core import windows_process_lease

    argv = [sys.executable, "-m", "angerona"]
    process = SimpleNamespace(pid=123, cmdline=lambda: argv, create_time=lambda: 990.0,
                              exe=lambda: sys.executable, is_running=lambda: True)
    calls = []

    class Lease:
        def __init__(self, pid, birth, image, *, lifetime, query_only):
            calls.append((pid, birth, image, lifetime, query_only))

        def __enter__(self):
            return self

        def validate(self, *, alive):
            calls.append(("validate", alive))

        def __exit__(self, *_):
            calls.append("close")

    monkeypatch.setattr(psutil, "Process", lambda _: process)
    monkeypatch.setattr(windows_process_lease, "WindowsProcessLease", Lease)
    component = supervisor.Component("core", argv + ["--chill"])
    result = supervisor._heartbeat_process_identity(component, {"pid": 123, "ts_ns": 1000 * 10**9})
    assert result["pid"] == 123
    assert calls == [(123, 990.0, sys.executable, 5.0, True), ("validate", True), "close"]


@pytest.mark.parametrize("guard", [lambda _: False, lambda _: (_ for _ in ()).throw(OSError())])
def test_source_guard_hold_adds_no_crash_debt_or_destructive_effects(monkeypatch, guard):
    effects, events = [], []
    instance = supervisor.ProcessSupervisor(
        launch_guard=guard, on_event=lambda *args: events.append(args))
    component = supervisor.Component("core", ["inert-runtime"])
    instance.components["core"] = component
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(instance, "_assess", lambda _: "dead")
    monkeypatch.setattr(instance, "_terminate", lambda _: effects.append("terminate"))
    monkeypatch.setattr(instance, "_spawn", lambda _: effects.append("spawn"))
    for _ in range(3):
        assert instance.tick() == {"core": "source-integrity-held"}
    assert component.launch_held and component.last_state == "dead"
    assert not component._failures and effects == [] and len(events) == 1


def test_stop_raised_during_launch_guard_prevents_dispatch(monkeypatch):
    effects = []
    instance = supervisor.ProcessSupervisor(launch_guard=lambda _: instance.request_stop() or True)
    component = supervisor.Component("core", ["inert-runtime"])
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_is_running", lambda _: False)
    monkeypatch.setattr(instance, "_authenticated_record", lambda _: (None, "missing"))
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _: True)
    monkeypatch.setattr(instance, "_release_when_up", lambda _: None)
    monkeypatch.setattr(supervisor, "spawn_detached", lambda *_a, **_kw: effects.append("spawn"))
    assert instance._spawn(component) is False
    assert effects == [] and component.restarts == 0


def test_manual_restart_source_hold_preserves_live_generation(monkeypatch):
    effects = []
    instance = supervisor.ProcessSupervisor(launch_guard=lambda _: False)
    component = supervisor.Component("core", ["inert-runtime"])
    instance.components["core"] = component
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: {"core"})
    monkeypatch.setattr(instance, "_terminate", lambda _: effects.append("terminate"))
    assert instance.tick() == {"core": "source-integrity-held"}
    assert effects == [] and not component._failures


def test_assigning_guard_controls_the_next_tick_and_spawn(monkeypatch):
    instance = supervisor.ProcessSupervisor()
    component = supervisor.Component("core", ["inert-runtime"])
    instance.components["core"] = component
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(instance, "_assess", lambda _: "dead")
    monkeypatch.setattr(instance, "_is_running", lambda _: False)
    monkeypatch.setattr(instance, "_authenticated_record", lambda _: (None, "missing"))
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _: True)
    monkeypatch.setattr(instance, "_release_when_up", lambda _: None)
    monkeypatch.setattr(supervisor, "spawn_detached", lambda *_a, **_kw: pytest.fail("guard bypass"))
    instance.launch_guard = lambda _: False
    assert instance.launch_guard is instance._launch_guard
    assert instance.tick() == {"core": "source-integrity-held"}
    assert instance._spawn(component) is False
    assert not component._failures
    with pytest.raises(ValueError):
        instance.launch_guard = True
    assert instance.launch_guard(component) is False


def test_backoff_wait_does_not_run_source_verification(monkeypatch):
    checks = []
    instance = supervisor.ProcessSupervisor(clock=lambda: 10.0,
                                            launch_guard=lambda _: checks.append(True) or False)
    component = supervisor.Component("core", ["inert-runtime"], next_restart_at=20.0)
    instance.components["core"] = component
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(instance, "_assess", lambda _: "dead")
    monkeypatch.setattr(instance, "_persist", lambda _: True)
    assert instance.tick() == {"core": "backoff(dead)"}
    assert checks == [] and not component._failures


@pytest.mark.parametrize("state,manual,expected_checks", [
    ("dead", False, 1), ("suspended", False, 2), ("alive", True, 2),
])
def test_due_dead_checks_once_but_destructive_restarts_keep_both_guards(
    monkeypatch, state, manual, expected_checks,
):
    checks, effects = [], []
    instance = supervisor.ProcessSupervisor(clock=lambda: 10.0,
                                            launch_guard=lambda _: checks.append(True) or True)
    component = supervisor.Component("core", ["inert-runtime"], next_restart_at=10.0)
    component._failures.append(1.0)
    instance.components["core"] = component
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: {"core"} if manual else set())
    monkeypatch.setattr(instance, "_assess", lambda _: state)
    monkeypatch.setattr(instance, "_is_running", lambda _: False)
    monkeypatch.setattr(instance, "_authenticated_record", lambda _: (None, "missing"))
    monkeypatch.setattr(instance, "_terminate", lambda _: effects.append("terminate") or True)
    monkeypatch.setattr(instance, "_persist", lambda _: True)
    monkeypatch.setattr(instance, "_capture_recovery_snapshot", lambda *_: None)
    monkeypatch.setattr(instance, "_arm_startup", lambda _: None)
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _: True)
    monkeypatch.setattr(supervisor.threading, "Thread", lambda **_: SimpleNamespace(start=lambda: None))
    monkeypatch.setattr(supervisor, "spawn_detached",
                        lambda *_a, **_kw: effects.append("spawn") or SimpleNamespace(pid=123))
    result = instance.tick()["core"]
    assert result == ("manual_restart" if manual else f"respawned({state})")
    assert len(checks) == expected_checks
    assert effects == (["terminate", "spawn"] if manual or state == "suspended" else ["spawn"])
    assert list(component._failures) == ([] if manual else [1.0])
    assert component.restarts == 1


def test_due_dead_dispatch_denial_keeps_prior_debt_without_effect(monkeypatch):
    checks, effects = [], []
    instance = supervisor.ProcessSupervisor(clock=lambda: 10.0,
                                            launch_guard=lambda _: checks.append(True) or False)
    component = supervisor.Component("core", ["inert-runtime"], next_restart_at=10.0)
    component._failures.append(1.0)
    instance.components["core"] = component
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(instance, "_assess", lambda _: "dead")
    monkeypatch.setattr(instance, "_is_running", lambda _: False)
    monkeypatch.setattr(instance, "_authenticated_record", lambda _: (None, "missing"))
    monkeypatch.setattr(instance, "_terminate", lambda _: effects.append("terminate"))
    monkeypatch.setattr(instance, "_persist", lambda _: True)
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _: True)
    monkeypatch.setattr(instance, "_release_when_up", lambda _: None)
    monkeypatch.setattr(supervisor, "spawn_detached", lambda *_a, **_kw: effects.append("spawn"))
    assert instance.tick() == {"core": "source-integrity-held"}
    assert checks == [True] and effects == []
    assert list(component._failures) == [1.0] and component.restarts == 0


def test_source_change_during_manual_termination_never_claims_replacement(monkeypatch):
    allowed, effects, events = [True], [], []
    instance = supervisor.ProcessSupervisor(launch_guard=lambda _: allowed[0],
                                            on_event=lambda *args: events.append(args))
    component = supervisor.Component("core", ["inert-runtime"])
    instance.components["core"] = component
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: {"core"})
    monkeypatch.setattr(instance, "_capture_recovery_snapshot", lambda *_: None)
    monkeypatch.setattr(instance, "_is_running", lambda _: False)
    monkeypatch.setattr(instance, "_authenticated_record", lambda _: (None, "missing"))
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _: True)
    monkeypatch.setattr(instance, "_release_when_up", lambda _: None)
    monkeypatch.setattr(supervisor, "spawn_detached", lambda *_a, **_kw: pytest.fail("changed source launched"))

    def terminate(_):
        effects.append("terminate")
        allowed[0] = False
        return True

    monkeypatch.setattr(instance, "_terminate", terminate)
    assert instance.tick() == {"core": "source-integrity-held"}
    assert effects == ["terminate"] and component.restarts == 0
    assert not any(level == "INFO" and "launch/adoption accepted" in text for level, text, _ in events)


def test_supervisor_progress_uses_completed_ticks_not_thread_presence(monkeypatch):
    clock = [10.0]
    instance = supervisor.ProcessSupervisor(monotonic_clock=lambda: clock[0])
    monkeypatch.setattr(instance, "_tick_locked", lambda: {})
    assert instance.heartbeat_allowed()
    assert instance.supervision_status()["state"] == "starting"
    clock[0] += supervisor._STARTUP_HEARTBEAT_SECONDS
    assert not instance.heartbeat_allowed()
    assert instance.supervision_status()["state"] == "startup-timeout"
    assert instance.tick() == {}
    assert instance.heartbeat_allowed()
    assert instance.supervision_status()["tick_count"] == 1
    clock[0] += supervisor._SUPERVISION_PROGRESS_SECONDS
    assert not instance.heartbeat_allowed()
    assert instance.supervision_status()["state"] == "stalled"
    instance.tick()
    assert instance.heartbeat_allowed()
    assert instance.supervision_status()["tick_count"] == 2
    instance.request_stop()
    assert not instance.heartbeat_allowed()
    assert instance.supervision_status()["state"] == "stopped"


def test_failed_supervision_tick_cannot_refresh_progress(monkeypatch):
    clock = [10.0]
    instance = supervisor.ProcessSupervisor(monotonic_clock=lambda: clock[0])
    monkeypatch.setattr(instance, "_tick_locked", lambda: {})
    instance.tick()
    clock[0] += supervisor._SUPERVISION_PROGRESS_SECONDS
    monkeypatch.setattr(instance, "_tick_locked", lambda: (_ for _ in ()).throw(OSError()))
    with pytest.raises(OSError):
        instance.tick()
    assert not instance.heartbeat_allowed()
    assert instance.supervision_status() == {
        "state": "stalled", "tick_count": 1, "last_tick_completed_at": 10.0, "error": "OSError"}


@pytest.mark.parametrize("clock_value", [True, float("nan"), -1.0, 9.0])
def test_invalid_or_regressed_supervision_clock_cannot_publish_health(monkeypatch, clock_value):
    clock = [10.0]
    instance = supervisor.ProcessSupervisor(monotonic_clock=lambda: clock[0])
    monkeypatch.setattr(instance, "_tick_locked", lambda: {})
    instance.tick()
    clock[0] = clock_value
    instance.tick()
    assert not instance.heartbeat_allowed()
    assert instance.supervision_status()["tick_count"] == 1
    assert instance.supervision_status()["state"] == "clock-unavailable"
