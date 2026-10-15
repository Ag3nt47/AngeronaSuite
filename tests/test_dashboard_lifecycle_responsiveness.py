"""Periodic dashboard policy work cannot wait for lifecycle operations on Qt."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer
from PySide6.QtWidgets import QApplication, QMainWindow

from angerona.core.module_manager import ModuleManager
from angerona.core import module_manager
from angerona.gui.main_window import MainWindow


class Probe:
    name = "inert lifecycle probe"
    enabled_by_default = True

    def __init__(self):
        self.starts = self.stops = 0
        self.start_entered = threading.Event()
        self.start_release = threading.Event()
        self.start_release.set()
        self.threads = []

    def start(self):
        self.threads.append(threading.get_ident())
        self.start_entered.set()
        assert self.start_release.wait(5)
        self.starts += 1

    def stop(self):
        self.threads.append(threading.get_ident())
        self.stops += 1


class DashboardHarness(QMainWindow):
    _init_usage_reconciler = MainWindow._init_usage_reconciler
    _prepare_usage_reconciliation = MainWindow._prepare_usage_reconciliation
    _refresh_body = MainWindow._refresh_body
    closeEvent = QMainWindow.closeEvent

    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self._tick_count = 1
        self.timer = QTimer(self)
        self.timer.setInterval(1_000)
        self.shark_engine = self.red_team_engine = SimpleNamespace(is_running=False)
        self.red_swords = SimpleNamespace(set_active=lambda _active: None)
        self.security_checks = 0
        self._init_usage_reconciler()

    def _quiet_chill_active(self):
        return False

    def _current_refresh_plan(self):
        return (1_000, 100, 100, 100, 100)

    def _check_threat_animation(self):
        self.security_checks += 1


def pump_until(predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(0.002)
    assert predicate()


def fixture_manager(monkeypatch):
    probe = Probe()
    config = SimpleNamespace(module_states={}, save=lambda: None)
    manager = ModuleManager(None, config, target_platform="windows")
    manager.modules = {probe.name: probe}
    manager._runtime_active = True
    manager._optional_enabled[probe.name] = False
    monkeypatch.setattr(module_manager, "has_optional_policy", lambda _module: True)
    return manager, probe


@pytest.mark.parametrize("obstruction", ["manager-lock", "module-start"])
def test_periodic_refresh_stays_responsive_and_reconciles_latest_policy(monkeypatch, obstruction):
    manager, probe = fixture_manager(monkeypatch)
    locked, release = threading.Event(), threading.Event()
    holder = None
    if obstruction == "manager-lock":
        def hold():
            with manager._module_control_lock:
                locked.set()
                assert release.wait(5)
        holder = threading.Thread(target=hold)
        holder.start()
        assert locked.wait(2)
    else:
        probe.start_release.clear()
    owner = DashboardHarness(manager)
    beats = []
    timer = QTimer()
    timer.setInterval(5)
    timer.timeout.connect(lambda: beats.append(1))
    timer.start()
    reader = owner._usage_reconciler
    try:
        owner._refresh_body()
        if obstruction == "module-start":
            assert probe.start_entered.wait(2)
        for _ in range(50):
            owner._refresh_body()
        pump_until(lambda: len(beats) >= 3)
        assert reader.busy
        assert reader._pending
        assert reader._requests.qsize() <= 1
        assert owner.security_checks == 51
        assert reader.thread.ident != threading.get_ident()

        # A changed policy while lifecycle work is blocked is applied by the
        # single coalesced follow-up, rather than a stale per-tick job queue.
        manager.config.module_states[probe.name] = False
        release.set()
        probe.start_release.set()
        pump_until(lambda: not reader.busy)
        assert probe.starts == (1 if obstruction == "module-start" else 0)
        assert probe.stops == (1 if obstruction == "module-start" else 0)
        assert all(ident == reader.thread.ident for ident in probe.threads)
        assert manager._optional_enabled[probe.name] is False
    finally:
        release.set()
        probe.start_release.set()
        timer.stop()
        reader.close()
        if holder is not None:
            holder.join(2)
        reader.thread.join(2)
        owner.close()
        owner.deleteLater()


def test_destroying_dashboard_does_not_cancel_or_revive_lifecycle_work(monkeypatch):
    manager, probe = fixture_manager(monkeypatch)
    probe.start_release.clear()
    owner = DashboardHarness(manager)
    reader = owner._usage_reconciler
    owner._refresh_body()
    assert probe.start_entered.wait(2)
    owner._refresh_body()
    try:
        owner.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert reader._closed
        assert reader._prepare is reader._apply is None
        probe.start_release.set()
        reader.thread.join(2)
        assert not reader.thread.is_alive()
        assert probe.starts == 1
        assert probe.stops == 0
        assert not reader._pending
        assert reader._results.empty()
    finally:
        probe.start_release.set()
        reader.close()


def test_explicit_policy_reconciliation_remains_synchronous(monkeypatch):
    manager, probe = fixture_manager(monkeypatch)
    manager.reconcile_usage()
    assert probe.starts == 1
    assert probe.threads == [threading.get_ident()]
