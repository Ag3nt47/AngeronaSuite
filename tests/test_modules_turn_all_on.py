"""Bulk module startup uses real manager policy and never blocks Qt on I/O."""
from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QApplication
import pytest
import shiboken6

from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule
from angerona.core.module_manager import ModuleManager
from angerona.gui import pages
from angerona.gui.pages import ModuleInspector, ModulesPanel, ModulesStatusWindow


class _InertModule(BaseModule):
    def __init__(self, name, *, fail=False, complete=True):
        super().__init__()
        self.name, self.fail, self.complete = name, fail, complete
        self.started = []
        self.eco_cycle_timeout = 0.2

    def start(self, initial_delay=0):
        self.started.append(threading.get_ident())
        if self.fail:
            raise RuntimeError("inert startup failure")
        self.status = "running"
        if self.complete:
            self._first_cycle_complete.set()

    def stop(self):
        self.status = "stopped"

    def run(self):
        raise AssertionError("The inert fixture must never create a real sensor")


def _optional(name, module_path, class_name):
    fixture_type = type(class_name, (_InertModule,), {"__module__": module_path})
    return fixture_type(name)


def _manager(modules, **settings):
    saves = []
    config = SimpleNamespace(module_states={}, ugcap_enabled=False, eco_mode=False,
                             mobile_enabled=False, ebpf_enabled=False,
                             adversary_combat_enabled=False, runtime_chill_active=False,
                             runtime_chill_ai_blocked=False)
    for key, value in settings.items():
        setattr(config, key, value)
    config.save = lambda: saves.append((threading.get_ident(), dict(config.module_states)))
    manager = ModuleManager(EventBus(), config, target_platform="windows")
    manager.modules = {module.name: module for module in modules}
    manager._kernel_installed = False
    return manager, saves


def _pump(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(0.005)
    assert predicate()


def _dispose(window):
    job = window._bulk_job
    window.close()
    if job is not None:
        job.cancel.set()
        job.thread.join(2)
        assert not job.thread.is_alive()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_turn_all_on_reviews_filtered_modules_without_overriding_policy(monkeypatch):
    monkeypatch.delenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", raising=False)
    available, failed, already = _InertModule("Available"), _InertModule("Failure", fail=True), _InertModule("Already")
    already.status = "running"
    unsupported = _InertModule("Linux only")
    unsupported.supported_platforms = {"linux"}
    mobile = _optional("Mobile", "angerona.modules.mobile_bridge", "MobileResponseBridge")
    kernel = _optional("Kernel", "angerona.modules.kernel_bridge", "KernelBridgeModule")
    soar = _optional("SOAR", "angerona.modules.soar_engine", "ActiveResponseSOAR")
    deep = _InertModule("File Integrity Monitor")
    modules = [available, failed, already, unsupported, mobile, kernel, soar, deep]
    manager, saves = _manager(modules, runtime_chill_active=True, eco_mode=True,
                              module_states={"Available": False})
    window = ModulesStatusWindow(manager, manager.bus)
    window._timer.stop()
    window.search.setText("Available")
    try:
        assert window.table.rowCount() == 1
        assert window.turn_all_on_btn.text() == "Turn all on"
        window.turn_all_on_btn.click()
        _pump(lambda: window._bulk_job.progress[-1] and window.turn_all_on_btn.isEnabled())
        records = {name: (outcome, detail) for name, outcome, detail in window._bulk_job.progress[4]}
        assert records["Available"][0] == "running"
        assert records["Failure"][0] == "failed"
        assert "inert startup failure" in records["Failure"][1]
        assert records["Already"][0] == "already on"
        assert all(records[module.name][0] == "held" for module in [unsupported, mobile, kernel, soar, deep])
        assert all(not module.started for module in [already, unsupported, mobile, kernel, soar, deep])
        assert manager.config.module_states == {"Available": True, "Failure": True}
        assert saves and all(tid != threading.get_ident() for tid, _state in saves)
        assert available.started and all(tid != threading.get_ident() for tid in available.started)
        assert manager.config.eco_mode is True and manager.config.adversary_combat_enabled is False
        assert manager.config.mobile_enabled is False and "ANGERONA_SOAR_KILL_AND_ROLLBACK" not in os.environ
        assert "held" in window.bulk_status.text() and "Failure" in window.bulk_details.toPlainText()
    finally:
        _dispose(window)


@pytest.mark.parametrize("gate", ["attestation", "shutdown", "AI consent"])
def test_bulk_does_not_clear_runtime_holds(gate):
    module = _InertModule("AI Triage (Ollama)" if gate == "AI consent" else "Inert")
    manager, saves = _manager([module], runtime_chill_ai_blocked=gate == "AI consent")
    manager._ugcap_paused = gate == "attestation"
    manager._shutdown = gate == "shutdown"
    window = ModulesStatusWindow(manager, manager.bus)
    window._timer.stop()
    try:
        window.turn_all_on_btn.click()
        _pump(lambda: window._bulk_job.progress[-1] and window.turn_all_on_btn.isEnabled())
        assert window._bulk_job.progress[3] == {"held": 1}
        assert not module.started and not saves and manager.config.module_states == {}
        assert manager._ugcap_paused == (gate == "attestation")
        assert manager._shutdown == (gate == "shutdown")
        assert manager.config.runtime_chill_ai_blocked == (gate == "AI consent")
    finally:
        _dispose(window)


def test_blocked_save_keeps_competing_qt_controls_responsive_and_close_cancels(monkeypatch):
    first, second = _InertModule("A first"), _InertModule("B next")
    manager, _saves = _manager([first, second])
    entered, release = threading.Event(), threading.Event()

    def blocked_save():
        entered.set()
        assert release.wait(5)

    manager.config.save = blocked_save
    window = ModulesStatusWindow(manager, manager.bus)
    window._timer.stop()
    panel = ModulesPanel(manager, manager.bus)
    inspector = ModuleInspector(manager, manager.bus, first)
    inspector._timer.stop()
    beats = []
    pulse = QTimer()
    pulse.setInterval(5)
    pulse.timeout.connect(lambda: beats.append(1))
    pulse.start()
    safety_release = threading.Timer(2, release.set)
    safety_release.daemon = True
    try:
        window.turn_all_on_btn.click()
        _pump(entered.is_set)
        job = window._bulk_job
        window._turn_all_on()  # duplicate requests attach to the same worker
        assert window._bulk_job is job
        _pump(lambda: len(beats) >= 5)
        safety_release.start()  # a regression fails rather than hanging pytest
        start = time.monotonic()
        inspector._toggle()
        inspector._restart()
        item = panel.table.item(0, 0)
        item.setCheckState(Qt.Unchecked)

        def choose_disabled_toggle(menu, _position):
            actions = {action.text(): action for action in menu.actions()}
            toggle = actions.get("Disable") or actions["Enable"]
            assert not toggle.isEnabled() and not actions["Restart module"].isEnabled()
            return toggle  # also exercise the dispatch-time race guard

        class InertMenu:
            def __init__(self, parent):
                self.parent, self._actions = parent, []

            def addAction(self, text):  # noqa: N802 - QMenu API
                action = QAction(text, self.parent)
                self._actions.append(action)
                return action

            def addSeparator(self):  # noqa: N802 - QMenu API
                return None

            def actions(self):
                return self._actions

            def exec(self, position):
                return choose_disabled_toggle(self, position)

        monkeypatch.setattr(pages, "QMenu", InertMenu)
        window._context_menu(window.table.visualItemRect(window.table.item(0, 0)).center())
        assert time.monotonic() - start < 0.1
        assert "startup is active" in inspector.test_lbl.text()
        assert "startup is active" in panel.table.toolTip()
        assert not first.started and not second.started
        start = time.monotonic()
        window.close()
        assert time.monotonic() - start < 0.1
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert not shiboken6.isValid(window)
        release.set()  # persistence may finish; startup must recheck cancellation
        job.thread.join(2)
        assert not job.thread.is_alive()
        assert not first.started and not second.started
        assert "B next" not in manager.config.module_states
        assert job.cancel.is_set() and job.progress[-1]
    finally:
        release.set()
        safety_release.cancel()
        if safety_release.ident is not None:
            safety_release.join(1)
        pulse.stop()
        for view in (inspector, panel):
            view.close()
            view.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        if shiboken6.isValid(window):
            _dispose(window)


def test_late_operator_selection_change_is_not_overwritten():
    first, second = _InertModule("A first", complete=False), _InertModule("B next")
    first.eco_cycle_timeout = 2
    manager, _saves = _manager([first, second], module_states={"B next": True})
    window = ModulesStatusWindow(manager, manager.bus)
    window._timer.stop()
    try:
        window.turn_all_on_btn.click()
        _pump(lambda: bool(first.started))
        manager.config.module_states["B next"] = False
        first._first_cycle_complete.set()
        _pump(lambda: window._bulk_job.progress[-1] and window.turn_all_on_btn.isEnabled())
        assert not second.started and manager.config.module_states["B next"] is False
        records = {name: (outcome, detail) for name, outcome, detail in window._bulk_job.progress[4]}
        assert records["B next"][0] == "held" and "selection changed" in records["B next"][1]
    finally:
        _dispose(window)


@pytest.mark.parametrize("transition", [
    "Chill", "Chill transition mark", "cancel", "generation", "shutdown",
    "attestation", "AI hold", "eligibility", "platform", "registration", "selection", "module stop",
])
def test_blocked_persistence_revalidates_every_bulk_start_hold(transition):
    name = ("File Integrity Monitor" if transition.startswith("Chill") else
            "AI Triage (Ollama)" if transition == "AI hold" else "Inert")
    module = (_optional(name, "angerona.modules.mobile_bridge", "MobileResponseBridge")
              if transition == "eligibility" else _InertModule(name))
    manager, _saves = _manager([module], module_states={name: False}, mobile_enabled=True)
    entered, release = threading.Event(), threading.Event()

    def blocked_save():
        entered.set()
        assert release.wait(5)

    manager.config.save = blocked_save
    window = ModulesStatusWindow(manager, manager.bus)
    window._timer.stop()
    beats = []
    pulse = QTimer()
    pulse.setInterval(5)
    pulse.timeout.connect(lambda: beats.append(1))
    pulse.start()
    replacement = None
    try:
        window.turn_all_on_btn.click()
        _pump(entered.is_set)
        _pump(lambda: len(beats) >= 3)
        job = window._bulk_job
        if transition == "Chill":
            manager.config.runtime_chill_active = manager.config.eco_mode = True
            module.stop()
        elif transition == "Chill transition mark":
            module.stop()
            module._chill_paused = True  # MainWindow marks this before publishing runtime Chill
        elif transition == "cancel":
            start = time.monotonic()
            window.close()
            assert time.monotonic() - start < 0.1
        elif transition == "generation":
            manager._control_generation += 1
        elif transition == "shutdown":
            manager._shutdown = True
        elif transition == "attestation":
            manager._ugcap_paused = True
        elif transition == "AI hold":
            manager.config.runtime_chill_ai_blocked = True
        elif transition == "eligibility":
            manager.config.mobile_enabled = False
        elif transition == "platform":
            module.supported_platforms = {"linux"}
        elif transition == "registration":
            replacement = _InertModule(name)
            manager.modules[name] = replacement
        elif transition == "selection":
            manager.config.module_states[name] = False
        elif transition == "module stop":
            BaseModule.stop(module)  # stop admission changes before any Chill marker is published
        release.set()
        _pump(lambda: not job.thread.is_alive())
        assert not module.started
        assert replacement is None or not replacement.started
        assert job.progress[3] == {"held": 1}, job.progress
        assert job.progress[-1]
        assert len(beats) >= 3
    finally:
        release.set()
        pulse.stop()
        _dispose(window)


def test_start_admission_runs_after_save_and_can_only_veto():
    module = _InertModule("Inert")
    manager, _saves = _manager([module])
    events = []
    manager.config.save = lambda: events.append("saved")

    def refuse(current):
        assert current is module and events == ["saved"]
        events.append("checked")
        return False

    module.status = "running"
    manager.set_enabled(module.name, True, start_admission=refuse)
    assert events == ["saved", "checked"]
    assert not module.started and module.status == "running"
    assert manager.config.module_states[module.name] is True


@pytest.mark.parametrize("changed_authority", ["shutdown", "generation", "registration", "selection", "attestation"])
def test_positive_admission_cannot_override_manager_authority(changed_authority):
    module = _InertModule("Inert")
    manager, _saves = _manager([module])

    def admit(_current):
        if changed_authority == "shutdown":
            manager._shutdown = True
        elif changed_authority == "generation":
            manager._control_generation += 1
        elif changed_authority == "registration":
            manager.modules[module.name] = _InertModule(module.name)
        elif changed_authority == "selection":
            manager.config.module_states[module.name] = False
        elif changed_authority == "attestation":
            manager._ugcap_paused = True
        return True

    manager.set_enabled(module.name, True, start_admission=admit)
    assert not module.started


def test_default_enable_still_forces_required_ugcap_guard_selection():
    guard = _optional("UGCAP Integrity Guard", "angerona.modules.ugcap_guard", "UGCAPGuardModule")
    manager, _saves = _manager([guard], ugcap_enabled=True)
    # This fixture owns the control authority started by UGCAP enrollment.
    authority = manager.bus._control_mesh
    rotator = authority._rotator
    try:
        manager.set_enabled(guard.name, False)
        assert manager.config.module_states[guard.name] is True and guard.started
    finally:
        try:
            manager.bus.close_mesh()
        finally:
            # close_mesh() has released its locks before this bounded join.
            rotator.join(timeout=2.0)
            assert not rotator.is_alive(), "test-owned mesh rotator did not retire"
        assert authority.snapshot()["closed"] is True
