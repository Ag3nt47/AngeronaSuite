from __future__ import annotations

import threading

import pytest

from angerona.modules import ipc_guard


class _BrokenListener:
    def setsockopt(self, *_args) -> None:
        return None

    def bind(self, _address) -> None:
        return None

    def listen(self, _backlog) -> None:
        return None

    def settimeout(self, _timeout) -> None:
        return None

    def getsockname(self):
        return ipc_guard._HOST, 43210

    def accept(self):
        raise OSError("listener revoked")

    def close(self) -> None:
        return None


def test_unexpected_accept_exit_is_latched_as_generation_failure() -> None:
    module = ipc_guard.IpcGuardModule()
    generation = ipc_guard._IpcGeneration(threading.Event())
    generation.srv = _BrokenListener()  # type: ignore[assignment]

    module._accept_loop(generation)

    assert generation.helper_stop.is_set()
    assert "listener accept failed" in generation.fatal_error
    assert "listener revoked" in generation.fatal_error


def test_listener_failure_cannot_be_overwritten_with_health_100(monkeypatch) -> None:
    module = ipc_guard.IpcGuardModule()
    generation = ipc_guard._IpcGeneration(threading.Event())
    listener = _BrokenListener()
    monkeypatch.setattr(ipc_guard, "_load_or_create_key", lambda _path: b"k" * 32)
    monkeypatch.setattr(ipc_guard.socket, "socket", lambda *_args: listener)
    monkeypatch.setattr(ipc_guard, "authenticate", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(module, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="listener accept failed"):
        module._run_generation(generation)

    assert module.health == 20
    assert "listener" in module.health_note
    assert generation.fatal_error
