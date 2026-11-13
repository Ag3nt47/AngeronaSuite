from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from angerona.resilience import heartbeat as hb, shutdown_token, supervisor
from angerona.resilience.recovery_state import RecoveryStateStore


def _supervisor(monkeypatch, tmp_path):
    clock = [1000.0]
    monkeypatch.setattr(supervisor.time, "time", lambda: clock[0])
    monkeypatch.setattr(supervisor, "_ipc_dir", lambda: tmp_path)
    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: False)
    store = RecoveryStateStore("fixture", path=tmp_path / "recovery.json", key=b"k" * 32,
                               clock=lambda: clock[0])
    instance = supervisor.ProcessSupervisor(clock=lambda: clock[0], monotonic_clock=lambda: 100.0,
                                            state_store=store)
    component = supervisor.Component(name="core", argv=["fixture-python", "-m", "angerona"])
    instance.components["core"] = component
    monkeypatch.setattr(instance, "_capture_recovery_snapshot", lambda *_args: None)
    monkeypatch.setattr(instance, "_persist", lambda *_args: True)
    monkeypatch.setattr(instance, "_terminate", lambda *_args: pytest.fail("live process termination"))
    monkeypatch.setattr(instance, "_spawn", lambda *_args: pytest.fail("native process spawn"))
    events = []
    instance.on_event = lambda *args: events.append(args)
    return instance, component, clock, events


@pytest.mark.parametrize("known,alive,expected", [
    (True, False, "backoff(dead)"),
    (True, True, "stopped"),
    (False, False, "identity-unverified"),
    (False, True, "identity-unverified"),
])
def test_stopped_heartbeat_never_becomes_operator_stop(monkeypatch, tmp_path, known, alive, expected):
    instance, component, _clock, events = _supervisor(monkeypatch, tmp_path)
    key = b"s" * 32
    reader = hb.HeartbeatReader("core", path=tmp_path / "core.hb", key_raw=key)
    flags, stamp, pid, counter = hb._FLAG_V2_AUTH, 1000_000_000_000, 4242, 7
    record = dict(version=2, wire_flags=flags, flags=0, ts_ns=stamp, pid=pid, counter=counter,
                  proof=hb.proof_for(hb._component_key("core", key), "core", stamp, pid, counter, flags))
    monkeypatch.setattr(reader, "read", lambda: dict(record))
    component.reader = reader
    component.adopted = True
    component._heartbeat_identity = dict(pid=pid, birth=900.0, image="fixture-python", parent=None) if known else None
    monkeypatch.setattr(hb, "pid_alive", lambda target: alive)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: set())
    assert instance.tick()["core"] == expected
    if known and not alive:
        assert len(component._pressure) == len(component._failures) == 1
        assert any(details.get("unexpected_stop") is True for _level, _msg, details in events)
    else:
        assert not component._pressure and not component._failures
        assert all(details.get("response_authorized") is not True for _level, _msg, details in events)
    monkeypatch.setattr(shutdown_token, "is_standdown_requested", lambda: True)
    assert instance.tick()["core"] == "standdown"


def _command(nonce, stamp, *, targets=None):
    targets = ["core"] if targets is None else targets
    payload = f"{nonce}\0{stamp}\0{','.join(targets)}"
    return dict(nonce=nonce, ts=stamp, targets=targets,
                sig=hmac.new(b"k" * 32, payload.encode(), hashlib.sha256).hexdigest())


def test_restart_nonce_is_admitted_once_and_input_is_bounded(monkeypatch, tmp_path):
    instance, _component, _clock, _events = _supervisor(monkeypatch, tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: b"k" * 32)
    path = tmp_path / "restart.core.cmd"
    raw = json.dumps(_command("a" * 32, 1000)).encode()
    path.write_bytes(raw)
    assert instance._pop_restart_requests() == {"core"}
    path.write_bytes(raw)
    assert instance._pop_restart_requests() == set()
    path.write_bytes(b"x" * (supervisor._MAX_RESTART_BYTES + 100))
    assert instance._pop_restart_requests() == set()
    assert not path.exists()


@pytest.mark.parametrize("stamp", [969, 1006, 99999999])
def test_restart_rejects_old_and_future_signed_commands(monkeypatch, tmp_path, stamp):
    instance, _component, _clock, _events = _supervisor(monkeypatch, tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: b"k" * 32)
    (tmp_path / "restart.core.cmd").write_text(json.dumps(_command("b" * 32, stamp)))
    assert instance._pop_restart_requests() == set()
    assert not instance._restart_seen


def test_restart_nonce_budget_fails_closed_without_evicting_live_nonces(monkeypatch, tmp_path):
    instance, _component, clock, _events = _supervisor(monkeypatch, tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: b"k" * 32)
    monkeypatch.setattr(supervisor, "_RESTART_NONCES_MAX", 2)
    path = tmp_path / "restart.core.cmd"
    for index in range(3):
        path.write_text(json.dumps(_command(f"{index:032x}", 1000)))
        assert instance._pop_restart_requests() == ({"core"} if index < 2 else set())
    assert len(instance._restart_nonce_store.load()["restart_nonces"]) == 2
    clock[0] += 36
    path.write_text(json.dumps(_command("f" * 32, 1036)))
    assert instance._pop_restart_requests() == {"core"}
    assert len(instance._restart_nonce_store.load()["restart_nonces"]) == 1


def test_consumed_restart_nonce_survives_a_second_supervisor(monkeypatch, tmp_path):
    first, _component, _clock, _events = _supervisor(monkeypatch, tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: b"k" * 32)
    path = tmp_path / "restart.core.cmd"
    captured = json.dumps(_command("e" * 32, 1000))
    path.write_text(captured)
    assert first._pop_restart_requests() == {"core"}
    second, _component, _clock, _events = _supervisor(monkeypatch, tmp_path)
    path.write_text(captured)
    assert second._pop_restart_requests() == set()


def test_failed_nonce_save_holds_only_optional_restart(monkeypatch, tmp_path):
    instance, component, _clock, events = _supervisor(monkeypatch, tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: b"k" * 32)

    def failed_save(_document):
        raise OSError("fixture state storage unavailable")

    monkeypatch.setattr(RecoveryStateStore, "_write_document", lambda _self, document: failed_save(document))
    (tmp_path / "restart.core.cmd").write_text(json.dumps(_command("d" * 32, 1000)))
    assert instance._pop_restart_requests() == set()
    assert any("Optional restart request held" in message for _level, message, _details in events)
    assert instance.tick()["core"] == "backoff(dead)"
    assert len(component._pressure) == 1  # Ordinary recovery still runs.


@pytest.mark.parametrize("clock_problem", ["wall-rollback", "monotonic-rollback"])
def test_restart_clock_regression_holds_optional_request(monkeypatch, tmp_path, clock_problem):
    instance, _component, clock, _events = _supervisor(monkeypatch, tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: b"k" * 32)
    path = tmp_path / "restart.core.cmd"
    path.write_text(json.dumps(_command("c" * 32, 1000)))
    assert instance._pop_restart_requests() == {"core"}
    if clock_problem == "wall-rollback":
        clock[0] = 990.0
    else:
        instance._monotonic_clock = lambda: 90.0
    path.write_text(json.dumps(_command("b" * 32, int(clock[0]))))
    assert instance._pop_restart_requests() == set()
    assert len(instance._restart_nonce_store.load()["restart_nonces"]) == 1


def test_component_state_corruption_does_not_block_nonce_admission(monkeypatch, tmp_path):
    instance, _component, _clock, _events = _supervisor(monkeypatch, tmp_path)
    monkeypatch.setattr(shutdown_token, "_load_key", lambda: b"k" * 32)
    instance._state_store.path.write_bytes(b"untrusted component state; retain for manual recovery")
    (tmp_path / "restart.core.cmd").write_text(json.dumps(_command("a" * 32, 1000)))
    assert instance._pop_restart_requests() == {"core"}
    assert instance._state_store.path.read_bytes().startswith(b"untrusted component state")
