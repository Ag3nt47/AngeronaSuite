from __future__ import annotations

import builtins
import sys
import threading
import time
from types import ModuleType, SimpleNamespace

import pytest

from angerona.core.process_snapshot_lifecycle import ProcessSnapshotLifecycle


class Provider:
    def __init__(self, *, ready=True, held=False, retire_after=1):
        self.ready = ready
        self.entered = threading.Event()
        self.release = threading.Event()
        if not held:
            self.release.set()
        self.calls = []
        self.retire_after = retire_after

    def start(self):
        self.calls.append(("start", threading.get_ident()))
        self.entered.set()
        assert self.release.wait(3)
        return self.ready

    def stop(self, *, timeout):
        assert timeout == 3.0
        self.calls.append(("stop", threading.get_ident()))
        return sum(action == "stop" for action, _ in self.calls) >= self.retire_after

    def lifecycle_snapshot(self):
        return {"ready": self.ready, "advisory_only": True}


def retired(owner):
    assert owner._retired.wait(4)
    if owner._thread is not None:
        owner._thread.join(1)
        assert not owner._thread.is_alive()


def background(call):
    values, errors = [], []
    def run():
        try:
            values.append(call())
        except BaseException as exc:
            errors.append(exc)
    thread = threading.Thread(target=run)
    thread.start()
    thread.join(4)
    assert not thread.is_alive()
    assert not errors, errors
    return values[0]


def test_constructor_registers_only_and_stopping_before_start_spawns_nothing():
    provider = Provider()
    configured = []
    owner = ProcessSnapshotLifecycle(provider, configure=configured.append)
    assert configured == [provider]
    assert provider.calls == []
    assert owner._thread is None
    owner.request_stop()
    assert not owner.start()
    assert provider.calls == []
    assert owner.lifecycle_snapshot()["retired"] is True


def test_one_owner_starts_once_and_retires_only_after_explicit_stop():
    provider = Provider()
    configured = []
    owner = ProcessSnapshotLifecycle(provider, configure=configured.append)
    try:
        assert owner.start()
        assert background(owner.wait_started)
        for _ in range(3):
            assert owner.start()
        assert [name for name, _ in provider.calls] == ["start"]
        assert owner._thread.daemon is False
        assert not owner.lifecycle_snapshot()["retired"]
    finally:
        owner.request_stop()
        retired(owner)
    assert [name for name, _ in provider.calls] == ["start", "stop"]
    assert configured == [provider]  # Never unregister and select a local fallback.
    assert not owner.start()


def test_failed_start_keeps_provider_registered_and_does_not_respawn():
    provider = Provider(ready=False)
    configured = []
    owner = ProcessSnapshotLifecycle(provider, configure=configured.append)
    assert owner.start()
    assert not background(owner.wait_started)
    retired(owner)
    assert not owner.start()
    assert configured == [provider]
    assert [name for name, _ in provider.calls] == ["start", "stop"]


def test_uncertain_retirement_stays_owned_without_starting_another_child():
    provider = Provider(retire_after=3)
    owner = ProcessSnapshotLifecycle(provider, configure=lambda _: None)
    assert owner.start()
    assert background(owner.wait_started)
    owner.request_stop()
    retired(owner)
    assert [name for name, _ in provider.calls] == ["start", "stop", "stop", "stop"]
    assert len({thread for _, thread in provider.calls}) == 1


def test_qt_remains_responsive_during_stalled_start_and_stop_only_signals():
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    qt = QApplication.instance()
    assert qt is not None
    gui_thread = threading.get_ident()
    provider = Provider(held=True)
    owner = ProcessSnapshotLifecycle(provider, configure=lambda _: None)
    beats = []
    timer = QTimer()
    timer.setInterval(2)
    timer.timeout.connect(lambda: beats.append(time.monotonic()))
    try:
        timer.start()
        assert owner.start()
        assert provider.entered.wait(1)
        with pytest.raises(RuntimeError, match="GUI thread"):
            owner.wait_started(.01)
        with pytest.raises(RuntimeError, match="GUI thread"):
            owner.wait_retired(.01)
        deadline = time.monotonic() + .08
        while time.monotonic() < deadline:
            qt.processEvents()
            time.sleep(.001)
        assert len(beats) >= 4
        started = time.monotonic()
        owner.request_stop()
        assert time.monotonic() - started < .1
        assert not owner.lifecycle_snapshot()["retired"]
    finally:
        timer.stop()
        provider.release.set()
        owner.request_stop()
        retired(owner)
    assert all(identity != gui_thread for _, identity in provider.calls)


def test_app_start_barrier_does_not_hold_teardown_lock_or_load_after_cancel():
    from angerona.app import AngeronaApp

    provider = Provider(held=True)
    owner = ProcessSnapshotLifecycle(provider, configure=lambda _: None)
    app = AngeronaApp.__new__(AngeronaApp)
    app._process_snapshot_lifecycle = owner
    app._startup_lifecycle_lock = threading.Lock()
    app._shutdown_requested = threading.Event()
    calls = []
    app._load_modules = lambda: calls.append("modules")
    app._record_startup_degradation = lambda *_args: calls.append("degraded")
    loader = threading.Thread(target=app._load_modules_guarded)
    loader.start()
    try:
        assert provider.entered.wait(1)
        assert app._startup_lifecycle_lock.acquire(blocking=False)
        app._startup_lifecycle_lock.release()
        assert calls == []
        app._shutdown_requested.set()
        owner.request_stop()
        loader.join(1)
        assert not loader.is_alive()
        assert calls == []
    finally:
        provider.release.set()
        owner.request_stop()
        retired(owner)
        loader.join(3)


def test_app_provider_stop_follows_modules_even_when_module_stop_raises():
    from angerona.app import AngeronaApp

    calls = []
    app = AngeronaApp.__new__(AngeronaApp)
    app.reporter = SimpleNamespace(stop=lambda: None)
    app._mcp = app._fleet_service = app._fleet_plane = None
    app._process_snapshot_lifecycle = SimpleNamespace(
        request_stop=lambda: calls.append("inventory-stop"),
    )
    def stop_modules():
        calls.append("module-stop")
        raise RuntimeError("inert stop failure")
    app.manager = SimpleNamespace(stop_all=stop_modules)
    with pytest.raises(RuntimeError, match="inert stop failure"):
        app._shutdown_owned()
    assert calls == ["module-stop", "inventory-stop"]


@pytest.mark.parametrize("suffix", [
    ["--process-snapshot-worker", "--process-snapshot-worker"],
    ["--process-snapshot-worker", "--headless"],
    ["--process-snapshot-worker", "--chill"],
    ["--process-snapshot-worker", "--engine-serve"],
])
def test_internal_worker_rejects_extra_or_duplicate_arguments(monkeypatch, suffix):
    import angerona.__main__ as entry
    monkeypatch.setattr(sys, "argv", ["Angerona.exe", *suffix])
    assert entry.main() == 2


@pytest.mark.parametrize("frozen,trusted,administrator,expected", [
    (False, True, False, 19),
    (False, True, True, 2),
    (True, False, False, 2),
    (True, True, False, 19),
    (True, True, True, 19),
])
def test_worker_keeps_package_and_source_guards_without_qt_or_uac(
    monkeypatch, frozen, trusted, administrator, expected,
):
    import angerona.__main__ as entry
    from angerona.core import privilege, windows_package_identity

    calls = []
    worker = ModuleType("angerona.telemetry.process_snapshot_worker")
    worker.worker_main = lambda: calls.append("worker") or 19
    monkeypatch.setitem(sys.modules, worker.__name__, worker)
    monkeypatch.setattr(sys, "argv", ["Angerona.exe", "--process-snapshot-worker"])
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: administrator)
    monkeypatch.setattr(privilege, "ensure_admin", lambda: pytest.fail("worker requested UAC"))
    monkeypatch.setattr(windows_package_identity, "verify_current_msix_authority", lambda: (
        calls.append("package") or SimpleNamespace(trusted=trusted, reason="inert fixture")
    ))
    original_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        if name in {"angerona.app", "angerona.core.config", "angerona.core.singleton"} or name.startswith("PySide6"):
            pytest.fail("internal worker reached GUI/config/singleton startup")
        return original_import(name, *args, **kwargs)
    # Restore the import guard before the repository's shared Qt teardown.
    # Only the internal entry itself must avoid constructing the GUI.
    with monkeypatch.context() as guarded:
        guarded.setattr(builtins, "__import__", guarded_import)
        assert entry.main() == expected
    assert ("package" in calls) is frozen
    assert ("worker" in calls) is (expected == 19)
