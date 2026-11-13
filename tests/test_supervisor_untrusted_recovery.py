from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from angerona.resilience import shutdown_token, supervisor
from angerona.resilience.recovery_state import RecoveryStateStore


def harness(monkeypatch, tmp_path, *, corrupt=False, max_backoff=60.0):
    clock, events, launches = [1000.0, 0.0], [], []
    path = tmp_path / "recovery.json"
    store = RecoveryStateStore("fixture", path=path, key=b"r" * 32, clock=lambda: clock[0])
    if corrupt:
        path.write_bytes(b"preserve these malformed original bookkeeping bytes")

    class Reader:
        def __init__(self, _name):
            self.path = tmp_path / "fixture.hb"

        def read(self):
            return None

    class Thread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass  # No background process waiters or native work in this fixture.

    monkeypatch.setattr(supervisor.hb, "HeartbeatReader", Reader)
    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(supervisor, "threading", SimpleNamespace(
        Lock=threading.Lock, RLock=threading.RLock, Event=threading.Event, Thread=Thread))
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _name: True)
    monkeypatch.setattr(supervisor.hb, "pid_alive", lambda _pid: pytest.fail("claimed heartbeat PID lookup"))

    def spawn(*_args, **_kwargs):
        launches.append(clock[1])
        return SimpleNamespace(pid=4242, poll=lambda: 0)

    monkeypatch.setattr(supervisor, "spawn_detached", spawn)
    value = supervisor.ProcessSupervisor(state_store=store, state_namespace="fixture",
        clock=lambda: clock[0], monotonic_clock=lambda: clock[1], max_backoff_s=max_backoff)
    value.on_event = lambda *args: events.append(args)
    monkeypatch.setattr(value, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(value, "_capture_recovery_snapshot", lambda *_args: None)
    monkeypatch.setattr(value, "_arm_startup", lambda _component: None)
    monkeypatch.setattr(value, "_is_running", lambda _component: False)
    component = value.add("core", ["fixture-python", "-m", "angerona"])
    monkeypatch.setattr(value, "_assess", lambda _component: "dead")
    return SimpleNamespace(value=value, component=component, clock=clock, store=store,
                           path=path, events=events, launches=launches)


def advance(h, seconds):
    h.clock[0] += seconds
    h.clock[1] += seconds


def test_corrupt_bookkeeping_preserves_original_and_allows_bounded_memory_recovery(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path, corrupt=True)
    original = h.path.read_bytes()
    assert h.component.state_fault and not h.component.safe_mode
    assert h.value.tick()["core"] == "backoff(durability_gap)"
    assert not h.launches
    advance(h, 60.1)
    assert h.value.tick()["core"].startswith("respawned")
    assert len(h.launches) == 1
    for _index in range(10):
        advance(h, 1.0)
        assert h.value.tick()["core"] == "backoff(durability_gap)"
    assert len(h.launches) == 1 and h.path.read_bytes() == original
    assert len(list(tmp_path.glob("recovery.json*"))) == 1
    gaps = [details for _level, _message, details in h.events if details.get("in_memory_recovery_budget") is True]
    assert len(gaps) == 1 and gaps[0]["original_preserved"] is True
    assert len(h.component._failures) == 1


def test_save_failure_is_a_budgeted_gap_and_reviewed_storage_recovery_can_resume(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    writer = h.store.update_component
    monkeypatch.setattr(h.store, "update_component", lambda *_args: (_ for _ in ()).throw(OSError("inert disk failure")))
    assert h.value.tick()["core"] == "backoff(durability_gap)"
    assert h.component.state_fault and not h.component.safe_mode
    monkeypatch.setattr(h.store, "update_component", writer)
    advance(h, 61.0)
    h.value.tick()
    assert len(h.launches) == 1
    assert h.component.state_fault is False
    assert any(details.get("durable_recovery_state") is True for _level, _message, details in h.events)


@pytest.mark.parametrize("gate", ["stop", "source"])
def test_durability_fallback_does_not_override_stop_or_source_gate(monkeypatch, tmp_path, gate):
    h = harness(monkeypatch, tmp_path, corrupt=True)
    advance(h, 100.0)
    if gate == "stop":
        monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: True)
    else:
        h.value.launch_guard = lambda _component: False
    h.value.tick()
    assert not h.launches and h.path.read_bytes().startswith(b"preserve")


def test_loaded_future_cooldowns_are_clamped_to_now_and_configured_backoff(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path, max_backoff=10.0)
    h.store.update_component("core", dict(safe_mode=True, safe_mode_since=h.clock[0] + 600000,
                                         next_restart_at=h.clock[0] + 600000))
    record = h.store.component("core")
    assert record["safe_mode_since"] == h.clock[0]
    h.value.components.clear()
    c = h.value.add("core", ["fixture-python", "-m", "angerona"])
    assert c.next_restart_at <= h.clock[0] + 10.0
    advance(h, 121.0)
    h.value.tick()
    assert c.safe_mode is False


@pytest.mark.parametrize("exit_state,expected", [
    (True, "dead"), (False, "unauthenticated_invalid"), (None, "unauthenticated_invalid"),
])
def test_rejected_heartbeat_uses_only_retained_exit_observation(monkeypatch, tmp_path, exit_state, expected):
    h = harness(monkeypatch, tmp_path)
    h.component._peer_exit_owner = SimpleNamespace(role=tuple(h.component.argv), exited=lambda: exit_state)
    monkeypatch.setattr(h.value, "_authenticated_record", lambda _component: ({"pid": 99999999}, "invalid"))
    assert supervisor.ProcessSupervisor._assess(h.value, h.component) == expected
    assert h.component._retained_exit_proven is (exit_state is True)


def test_proven_exit_can_dispatch_without_trusting_an_invalid_claimed_pid(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    h.component._retained_exit_proven = True
    h.component._peer_exit_owner = SimpleNamespace(close=lambda: True)
    monkeypatch.setattr(h.value, "_authenticated_record", lambda _component: ({"pid": 99999999}, "invalid"))
    assert h.value._spawn(h.component) is True
    assert len(h.launches) == 1 and h.component._retained_exit_proven is False


@pytest.mark.parametrize("signaled,birth,code,expected", [
    (True, 1234, 0, True), (False, 1234, 259, False), (0, 1234, 0, None),
    (True, 9999, 0, None), (True, 1234, False, None),
])
def test_retained_native_exit_requires_signal_raw_identity_and_typed_exit_code(signaled, birth, code, expected):
    calls = []
    identity = SimpleNamespace(pid=4242, birth_ticks=1234)
    native = SimpleNamespace(wait=lambda handle, _ms: signaled,
        object_identity=lambda handle: (4242, birth), exit_code=lambda handle: code,
        close=lambda handle: calls.append(handle))
    handle = 0x100000123
    lease = SimpleNamespace(identity=identity, _native=native, _handle=handle)
    owner = supervisor._RetainedPeerExit(lease, ("fixture-python",))
    assert lease._handle is None and owner.exited() is expected
    assert owner.close() and owner.close()
    assert calls == [handle] and owner.exited() is None


def test_ambiguous_native_close_is_not_retried_and_blocks_new_retention(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    calls = []

    def close(handle):
        calls.append(handle)
        raise OSError("inert close failure")

    lease = SimpleNamespace(identity=SimpleNamespace(pid=4242, birth_ticks=1),
                            _native=SimpleNamespace(close=close), _handle=0x100000124)
    owner = supervisor._RetainedPeerExit(lease, tuple(h.component.argv))
    h.component._peer_exit_owner = owner
    assert h.value._close_peer_exit_owner(h.component) is False
    assert h.value._close_peer_exit_owner(h.component) is False
    assert calls == [0x100000124] and h.component._peer_exit_close_failed
    assert owner.exited() is None


def startup(h, monkeypatch):
    identity = object()
    proc = SimpleNamespace(owns_descendants=True, poll=lambda: None)
    h.component.proc = proc
    h.component._startup = supervisor._StartupAttempt(proc, (proc, identity), 0.0, 180.0, 0.0)
    monkeypatch.setattr(supervisor, "_retained_startup_identity", lambda current: (current, identity))
    monkeypatch.setattr(h.value, "_authenticated_record", lambda _component: ({"pid": 99999999}, "invalid"))
    monkeypatch.setattr(h.value, "_assess", lambda c: supervisor.ProcessSupervisor._assess(h.value, c))
    advance(h, 181.0)
    return proc


def test_expired_owned_startup_retires_and_restarts_without_fresh_heartbeat(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    proc = startup(h, monkeypatch)
    retired = []

    def terminate(c):
        assert c.proc is proc
        retired.append(proc)
        c.proc, c._startup, c._dead = None, None, True
        return True

    monkeypatch.setattr(h.value, "_terminate", terminate)
    h.value.tick()
    assert retired == [proc] and not h.launches
    assert len(h.component._failures) == 1 and len(h.component._pressure) == 1
    advance(h, 1.1)
    h.value.tick()
    assert len(h.launches) == 1


def test_failed_startup_retirement_keeps_original_custody_and_counts_only_once(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    proc = startup(h, monkeypatch)
    attempts = []
    monkeypatch.setattr(h.value, "_terminate", lambda c: attempts.append(c.proc) or False)
    assert h.value.tick()["core"] == "startup-retirement-held"
    advance(h, 1.0)
    h.component._dead = True  # Process exit alone does not retire its private Job.
    assert h.value.tick()["core"] == "startup-retirement-held"
    assert h.component.proc is proc and h.component._startup.retirement_pending
    assert attempts == [proc] and len(h.component._failures) == 1
    assert not h.launches


def test_startup_timeout_with_unknown_owner_never_terminates_claimed_pid(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    proc = startup(h, monkeypatch)
    monkeypatch.setattr(supervisor, "_retained_startup_identity", lambda _proc: None)
    monkeypatch.setattr(h.value, "_terminate", lambda _c: pytest.fail("unverified startup termination"))
    assert h.value.tick()["core"] not in ("dead", "respawned(dead)")
    assert h.component.proc is proc and not h.launches


def test_authenticated_manual_recovery_preserves_corrupt_component_original(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path, corrupt=True)
    original = h.path.read_bytes()
    monkeypatch.setattr(h.value, "_pop_restart_requests", lambda: {"core"})
    monkeypatch.setattr(h.value, "_terminate", lambda _component: True)
    assert h.value.tick()["core"] == "manual_restart"
    assert h.path.read_bytes() == original and len(h.launches) == 1
    assert h.component.state_fault is True
