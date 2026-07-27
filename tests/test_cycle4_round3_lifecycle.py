from __future__ import annotations

import socket
import threading
import time
from types import SimpleNamespace

from angerona.core.module_base import BaseModule


def _wait_until(predicate, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return bool(predicate())


def _stop_and_join(module: BaseModule) -> None:
    module.stop()
    thread = module._thread
    if thread is not None:
        thread.join(timeout=3.0)
    waiter = module._restart_waiter
    if waiter is not None:
        waiter.join(timeout=3.0)


class _InterruptibleProbe(BaseModule):
    name = "interruptible-lifecycle-probe"

    def __init__(self) -> None:
        super().__init__()
        self.entries: list[tuple[int, threading.Thread]] = []

    def run(self) -> None:
        self.entries.append((self.lifecycle_generation, threading.current_thread()))
        while not self.stopping:
            self.sleep(60.0)


class _SlowExitProbe(BaseModule):
    name = "slow-exit-lifecycle-probe"
    _RESTART_JOIN_TIMEOUT = 0.02

    def __init__(self) -> None:
        super().__init__()
        self.first_entered = threading.Event()
        self.release_first = threading.Event()
        self.entries = 0
        self.active = 0
        self.max_active = 0
        self.lock = threading.Lock()

    def run(self) -> None:
        with self.lock:
            self.entries += 1
            entry = self.entries
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if entry == 1:
                self.first_entered.set()
                self.release_first.wait(timeout=3.0)
            while not self.stopping:
                self.sleep(60.0)
        finally:
            with self.lock:
                self.active -= 1


def test_immediate_restart_replaces_interruptible_main_thread() -> None:
    module = _InterruptibleProbe()
    module.start()
    try:
        assert _wait_until(lambda: len(module.entries) == 1)
        old_thread = module._thread

        module.stop()
        module.start()

        assert _wait_until(
            lambda: module.lifecycle_generation == 2
            and len(module.entries) == 2
            and module._thread is not old_thread
        )
        assert old_thread is not None and not old_thread.is_alive()
        assert module._thread is not None and module._thread.is_alive()
        assert module.status == "running"
        assert not module.stopping
    finally:
        _stop_and_join(module)


def test_slow_exit_restart_is_bounded_deferred_and_nonoverlapping() -> None:
    module = _SlowExitProbe()
    module.start()
    try:
        assert module.first_entered.wait(timeout=1.0)
        old_thread = module._thread
        module.stop()

        started = time.monotonic()
        module.start()
        elapsed = time.monotonic() - started

        assert elapsed < 0.20
        assert module.status == "restarting"
        assert module.lifecycle_generation == 1
        assert module._thread is old_thread
        module.release_first.set()

        assert _wait_until(
            lambda: module.lifecycle_generation == 2
            and module._thread is not old_thread
            and module.entries == 2
        )
        assert module.max_active == 1
    finally:
        module.release_first.set()
        _stop_and_join(module)


def test_stop_cancels_a_deferred_restart() -> None:
    module = _SlowExitProbe()
    module.start()
    try:
        assert module.first_entered.wait(timeout=1.0)
        old_thread = module._thread
        module.stop()
        module.start()
        assert module.status == "restarting"

        module.stop()
        module.release_first.set()
        assert old_thread is not None
        old_thread.join(timeout=2.0)
        waiter = module._restart_waiter
        if waiter is not None:
            waiter.join(timeout=2.0)

        assert module.lifecycle_generation == 1
        assert module.entries == 1
        assert module.status == "stopped"
        assert not old_thread.is_alive()
    finally:
        module.release_first.set()
        _stop_and_join(module)


def test_spec_restart_never_retains_old_workers() -> None:
    from angerona.modules.speculative_triage import SpeculativeTriageModule

    module = SpeculativeTriageModule()
    module._WORKER_IDLE_POLL = 0.01
    module.start()
    try:
        assert _wait_until(
            lambda: len(module._workers) == module._MAX_INFLIGHT
            and all(worker.is_alive() for worker in module._workers)
        )
        old_workers = list(module._workers)

        module.stop()
        module.start()

        assert _wait_until(
            lambda: module.lifecycle_generation == 2
            and len(module._workers) == module._MAX_INFLIGHT
            and all(worker.is_alive() for worker in module._workers)
        )
        assert all(not worker.is_alive() for worker in old_workers)
        assert not any(worker in module._workers for worker in old_workers)
    finally:
        _stop_and_join(module)
    assert module._workers == []


def test_ai_recovery_pinger_cannot_overlap_after_restart() -> None:
    from angerona.modules.ai_triage import AITriageModule

    module = AITriageModule()
    module._RESTART_JOIN_TIMEOUT = 0.02
    module._CB_RECOVERY_S = 0.01
    module._cb_state = "open"
    module._check_health = lambda: None

    entered = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    calls = 0
    active = 0
    max_active = 0

    def blocking_ping() -> bool:
        nonlocal calls, active, max_active
        with lock:
            calls += 1
            call = calls
            active += 1
            max_active = max(max_active, active)
        try:
            if call == 1:
                entered.set()
                release.wait(timeout=3.0)
            else:
                time.sleep(0.005)
            return False
        finally:
            with lock:
                active -= 1

    module._ping_ollama = blocking_ping
    module.start()
    try:
        assert entered.wait(timeout=1.0)
        old_pinger = module._recovery_thread

        module.stop()
        module.start()

        assert module.status == "restarting"
        assert module.lifecycle_generation == 1
        with lock:
            assert calls == 1
            assert max_active == 1

        release.set()
        assert _wait_until(
            lambda: module.lifecycle_generation == 2 and calls >= 2
        )
        assert old_pinger is not None and not old_pinger.is_alive()
        with lock:
            assert max_active == 1
    finally:
        release.set()
        _stop_and_join(module)


def test_ipc_restart_retires_accept_and_connection_helpers(
    monkeypatch, tmp_path
) -> None:
    from angerona.core import config as config_module
    from angerona.modules import ipc_guard

    monkeypatch.setattr(
        config_module,
        "Config",
        lambda: SimpleNamespace(data_dir=tmp_path),
    )
    monkeypatch.setattr(ipc_guard, "_PORT", 0)

    module = ipc_guard.IpcGuardModule()
    module.start()
    client: socket.socket | None = None
    try:
        assert _wait_until(
            lambda: module._server_generation is not None
            and module._server_generation.srv is not None
            and module._server_generation.accept_thread is not None
            and module._server_generation.accept_thread.is_alive()
        )
        old_generation = module._server_generation
        assert old_generation is not None and old_generation.srv is not None
        old_accept = old_generation.accept_thread
        port = old_generation.srv.getsockname()[1]

        client = socket.create_connection((ipc_guard._HOST, port), timeout=1.0)
        client.settimeout(1.0)
        assert client.recv(256).startswith(b"CHALLENGE ")
        assert _wait_until(lambda: len(old_generation.helpers) == 1)
        old_helpers = list(old_generation.helpers)

        module.stop()
        module.start()

        assert _wait_until(
            lambda: module.lifecycle_generation == 2
            and module._server_generation is not None
            and module._server_generation is not old_generation
            and module._server_generation.accept_thread is not None
            and module._server_generation.accept_thread.is_alive()
        )
        assert old_accept is not None and not old_accept.is_alive()
        assert all(not helper.is_alive() for helper in old_helpers)
        assert old_generation.helpers == set()
        assert old_generation.connections == set()
    finally:
        if client is not None:
            client.close()
        _stop_and_join(module)
