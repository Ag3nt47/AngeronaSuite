"""Inert selection/lifecycle regressions; never start a real sensor."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.core.module_base import BaseModule
from angerona.core.module_manager import ModuleManager
from angerona.core.module_usage import module_counts, usage_for


class Probe(BaseModule):
    def __init__(self, name="probe"):
        super().__init__()
        self.name = name
        self.starts = 0
        self.stops = 0

    def start(self):
        self.starts += 1
        self.status = "running"

    def stop(self):
        self.stops += 1
        self.status = "stopped"

    def wait_for_first_cycle(self, timeout):
        return True


def manager_for(*modules, platform="windows"):
    config = SimpleNamespace(module_states={}, mobile_enabled=False,
                             ebpf_enabled=False, save=lambda: None)
    manager = ModuleManager(None, config, target_platform=platform)
    manager.modules = {mod.name: mod for mod in modules}
    return manager


def inert_real_module(cls):
    # Use the actual builtin class identity without its constructor or worker.
    module = cls.__new__(cls)
    BaseModule.__init__(module)
    module.starts = module.stops = 0
    module.start = lambda: Probe.start(module)
    module.stop = lambda: Probe.stop(module)
    module.wait_for_first_cycle = lambda timeout: True
    return module


@pytest.mark.parametrize("flag,platform", [("mobile_enabled", "windows"),
                                          ("ebpf_enabled", "linux")])
def test_unused_integrations_park_and_follow_live_policy(flag, platform):
    from angerona.modules.mobile_bridge import MobileResponseBridge
    from angerona.modules.ebpf_sensor import EbpfSensorNode
    cls = MobileResponseBridge if flag == "mobile_enabled" else EbpfSensorNode
    module = inert_real_module(cls)
    manager = manager_for(module, platform=platform)
    manager.start_enabled(min_settle=0)
    assert module.starts == 0
    assert manager.module_usage(module.name).state == "not_configured"
    assert module_counts(manager)["enabled"] == 0
    setattr(manager.config, flag, True)
    manager.reconcile_usage()
    manager.reconcile_usage()
    assert module.starts == 1
    module.status = "stopped"  # A cadence pause must not be undone by polling.
    manager.reconcile_usage()
    assert module.starts == 1
    assert module_counts(manager)["enabled"] == 1
    setattr(manager.config, flag, False)
    manager.reconcile_usage()
    assert module.stops == 1
    assert manager.config.module_states == {}  # preserved operator preference
    manager.set_enabled(module.name, False)
    setattr(manager.config, flag, True)
    manager.reconcile_usage()
    assert module.starts == 1


def test_unarmed_soar_has_no_worker_and_reconciles_before_drill(monkeypatch):
    from angerona.modules.soar_engine import ActiveResponseSOAR
    module = inert_real_module(ActiveResponseSOAR)
    manager = manager_for(module)
    monkeypatch.delenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", raising=False)
    manager.start_enabled(min_settle=0)
    assert module.starts == 0
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    manager.reconcile_usage()
    assert module.starts == 1
    monkeypatch.delenv("ANGERONA_SOAR_KILL_AND_ROLLBACK")
    manager.reconcile_usage()
    assert module.stops == 1
    manager.stop_all()
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    manager.reconcile_usage()
    assert module.starts == 1


def test_kernel_absence_parks_default_but_unknown_or_explicit_request_stays_visible():
    from angerona.modules.kernel_bridge import KernelBridgeModule
    module = inert_real_module(KernelBridgeModule)
    manager = manager_for(module)
    manager._kernel_installed = False
    assert not manager.is_enabled(module.name)
    assert manager.module_usage(module.name).state == "not_installed"
    manager.set_enabled(module.name, True)
    assert module.starts == 1 and manager.is_enabled(module.name)
    manager.config.module_states.clear()
    manager._kernel_installed = None  # access denied / unknown is not absence
    assert manager.is_enabled(module.name)


def test_counts_exclude_off_and_unsupported_but_keep_failed_and_paused():
    healthy, failed, paused, disabled, foreign = [Probe(n) for n in
                                                ("up", "bad", "pause", "off", "linux")]
    healthy.status = disabled.status = "running"
    failed.status, failed.health = "error", 0
    foreign.supported_platforms = ("linux",)
    manager = manager_for(healthy, failed, paused, disabled, foreign)
    manager.config.module_states[disabled.name] = False
    assert module_counts(manager) == {"running": 1, "enabled": 3, "off": 2, "discovered": 5}
    assert manager.module_usage(foreign.name).state == "unsupported"
    assert manager.module_usage(failed.name).enabled
    assert not usage_for(disabled, manager.config, "windows").enabled


@pytest.mark.parametrize("interruption", ["disable", "shutdown", "replace"])
def test_staged_start_cannot_revive_disabled_or_replaced_modules(interruption):
    first, second = Probe("first"), Probe("second")
    manager = manager_for(first, second)

    def interrupt(timeout):
        if interruption == "disable":
            manager.set_enabled(second.name, False)
        elif interruption == "shutdown":
            manager.stop_all()
        else:
            manager.modules[second.name] = Probe(second.name)
        return True

    first.wait_for_first_cycle = interrupt
    manager.start_enabled(min_settle=0)
    assert first.starts == 1
    assert second.starts == 0


def test_shared_display_counts_match_manager_selection():
    from angerona.core.flow_metrics import _running
    from angerona.gui.live_defense_activity import LiveDefenseActivityCard
    healthy, off = Probe("up"), Probe("off")
    healthy.status = off.status = "running"
    manager = manager_for(healthy, off)
    manager.set_enabled("off", False)
    assert _running(manager, {"up", "off"}) == (1, 1)
    _, running, degraded, total = LiveDefenseActivityCard._module_snapshot(manager)
    assert (running, degraded, total) == (1, 0, 1)


def test_usage_gate_ignores_untrusted_display_name():
    module = Probe("Mobile Response Bridge")
    manager = manager_for(module)
    assert manager.is_enabled(module.name)


def test_eco_wake_uses_current_policy_after_queueing(monkeypatch):
    from angerona.core.eco_wakeup import EcoWakeupWorker
    first, second = Probe("first"), Probe("second")
    manager = manager_for(first, second)
    worker = EcoWakeupWorker([first, second], min_settle=0,
                             start_module=manager.start_if_enabled)

    def gate(module):
        manager.set_enabled(second.name, False)
        return "complete"

    monkeypatch.setattr(worker, "_gate", gate)
    worker.run()
    assert first.starts == 1
    assert second.starts == 0
    manager.stop_all()
    assert not manager.start_if_enabled(first)
    assert first.starts == 1


def test_console_cannot_restart_an_off_module():
    from angerona.core.commands import CommandConsole
    module = Probe("fixture")
    manager = manager_for(module)
    manager.config.module_states[module.name] = False
    router = SimpleNamespace(manager=manager)
    assert "off" in CommandConsole._module(router, ["fixture", "restart"])
    assert module.starts == 0
