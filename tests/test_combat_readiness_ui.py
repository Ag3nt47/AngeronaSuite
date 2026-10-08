"""The visible Combat arm control and drill preflight share real authority."""
from __future__ import annotations

import json
import os
import threading
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Signal, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QMainWindow, QWidget

from angerona.core.config import Config
from angerona.gui import main_window
from angerona.gui.main_window import MainWindow
from angerona.gui.pages import SettingsDialog


class _Combat:
    def __init__(self, *, running: bool = False):
        self.status = "running" if running else "stopped"
        self.stop_calls = 0

    def response_snapshot(self):
        ready = self.status == "running"
        return {"state": "ARMED" if ready else "DISABLED", "ready": ready}

    def list_actions(self, *, limit):
        return []

    def start(self):
        raise AssertionError("Settings bypassed the module manager")

    def stop(self):
        self.stop_calls += 1
        self.status = "stopped"


class _Manager:
    def __init__(self, config, combat):
        self.config = config
        self.modules = {"Adversary Combat": combat}
        self.start_calls = 0

    def start_if_enabled(self, combat):
        self.start_calls += 1
        assert combat is self.modules["Adversary Combat"]
        if (not self.config.adversary_combat_enabled
                or self.config.module_states.get("Adversary Combat") is not True):
            return False
        combat.status = "running"
        return True


class _Parent(QWidget):
    _settings_combat_status = Signal(str, str)

    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.statuses = []
        self._settings_combat_status.connect(
            lambda state, message: self.statuses.append((state, message))
        )


def _process_until(predicate, *, timeout=5.0):
    app = QApplication.instance()
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert predicate()


def _dialog(
    tmp_path, monkeypatch, *, policy=True, selected=False, running=False,
    combat=None,
):
    from angerona.core import autostart

    QApplication.instance() or QApplication([])
    monkeypatch.setattr(autostart, "is_enabled", lambda: False)
    config = Config(
        data_dir=tmp_path,
        autostart_enabled=False,
        adversary_combat_enabled=policy,
        module_states={"Adversary Combat": selected},
    )
    combat = combat or _Combat(running=running)
    manager = _Manager(config, combat)
    parent = _Parent(manager)
    dialog = SettingsDialog(config, lambda: None, lambda _: None, parent)
    return dialog, parent, config, combat, manager


def test_arm_selects_disabled_module_and_uses_manager_start(tmp_path, monkeypatch):
    dialog, parent, config, combat, manager = _dialog(tmp_path, monkeypatch)
    try:
        assert not dialog._combat_enabled_chk.isChecked()
        dialog._combat_enabled_chk.setChecked(True)
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        assert config.adversary_combat_enabled is True
        assert config.module_states["Adversary Combat"] is True
        _process_until(lambda: any(state == "ready" for state, _ in parent.statuses))
        assert manager.start_calls == 1
        assert combat.status == "running"
        saved = json.loads(config.settings_path.read_text(encoding="utf-8"))
        assert saved["adversary_combat_enabled"] is True
        assert saved["module_states"]["Adversary Combat"] is True
    finally:
        dialog.close()
        parent.close()


def test_unarm_clears_both_saved_states_and_stops_combat(tmp_path, monkeypatch):
    dialog, parent, config, combat, manager = _dialog(
        tmp_path, monkeypatch, policy=True, selected=True, running=True,
    )
    try:
        assert dialog._combat_enabled_chk.isChecked()
        combat.status = "starting"
        dialog._combat_enabled_chk.setChecked(False)
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        assert config.adversary_combat_enabled is False
        assert config.module_states["Adversary Combat"] is False
        assert manager.start_calls == 0
        assert combat.stop_calls == 1
        saved = json.loads(config.settings_path.read_text(encoding="utf-8"))
        assert saved["adversary_combat_enabled"] is False
        assert saved["module_states"]["Adversary Combat"] is False
    finally:
        dialog.close()
        parent.close()


def test_async_arm_keeps_qt_live_and_disarm_revokes_blocked_start(tmp_path, monkeypatch):
    dialog, parent, config, combat, manager = _dialog(tmp_path, monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    def blocked_start(module):
        entered.set()
        assert release.wait(5)
        # Model a start that crossed the manager gate before the later disarm.
        module.status = "running"
        return True

    manager.start_if_enabled = blocked_start
    heartbeat = []
    try:
        dialog._combat_enabled_chk.setChecked(True)
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        assert entered.wait(5)
        QTimer.singleShot(0, lambda: heartbeat.append(True))
        QApplication.instance().processEvents()
        assert heartbeat == [True]
        assert parent.statuses[0][0] == "pending"

        disarm = SettingsDialog(config, lambda: None, lambda _: None, parent)
        try:
            disarm._combat_enabled_chk.setChecked(False)
            disarm._save()
            assert disarm.result() == QDialog.Accepted
        finally:
            disarm.close()
        release.set()
        _process_until(lambda: any(state == "canceled" for state, _ in parent.statuses))
        assert config.adversary_combat_enabled is False
        assert config.module_states["Adversary Combat"] is False
        assert combat.status == "stopped"
    finally:
        release.set()
        dialog.close()
        parent.close()


def test_slow_history_load_keeps_qt_live_and_undo_closed_until_verified(
    tmp_path, monkeypatch,
):
    entered = threading.Event()
    release = threading.Event()

    class SlowCombat(_Combat):
        def list_actions(self, *, limit):
            entered.set()
            assert release.wait(5)
            return [{
                "action_id": "signed-action",
                "action": "quarantine_file",
                "target": str(tmp_path / "marker.bin"),
                "applied_at": 1000.0,
                "reversible": True,
                "undone": False,
                "integrity_status": "verified",
                "status": "applied",
            }]

    dialog, parent, _, _, _ = _dialog(
        tmp_path, monkeypatch, combat=SlowCombat(),
    )
    try:
        assert entered.wait(5)
        assert not dialog._combat_undo_btn.isEnabled()
        heartbeat = []
        QTimer.singleShot(0, lambda: heartbeat.append(True))
        QApplication.instance().processEvents()
        assert heartbeat == [True]
        release.set()
        _process_until(lambda: dialog._combat_undo_btn.isEnabled())
        assert dialog._combat_undo_selector.currentData() == "signed-action"
    finally:
        release.set()
        dialog.close()
        parent.close()


def test_history_failure_keeps_all_undo_controls_disabled(tmp_path, monkeypatch):
    class BrokenCombat(_Combat):
        def list_actions(self, *, limit):
            raise RuntimeError("journal verification failed")

    dialog, parent, _, _, _ = _dialog(
        tmp_path, monkeypatch, combat=BrokenCombat(),
    )
    try:
        _process_until(
            lambda: "journal verification failed" in dialog._combat_history_status.text(),
        )
        assert not dialog._combat_undo_btn.isEnabled()
        assert not dialog._combat_undo_all_btn.isEnabled()
        assert dialog._combat_undo_selector.count() == 0
    finally:
        dialog.close()
        parent.close()


def test_failed_async_arm_surfaces_saved_but_unready_state(tmp_path, monkeypatch):
    dialog, parent, config, combat, manager = _dialog(tmp_path, monkeypatch)
    manager.start_if_enabled = lambda _module: False
    try:
        dialog._combat_enabled_chk.setChecked(True)
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        _process_until(lambda: any(state == "failed" for state, _ in parent.statuses))
        assert config.adversary_combat_enabled is True
        assert config.module_states["Adversary Combat"] is True
        assert combat.status == "stopped"
        assert "refused to start" in parent.statuses[-1][1]
    finally:
        dialog.close()
        parent.close()


def test_undo_stays_closed_while_manager_start_is_pending(tmp_path):
    QApplication.instance() or QApplication([])
    config = Config(
        data_dir=tmp_path,
        module_states={"Adversary Combat": True},
    )
    combat = _Combat(running=True)
    combat.list_actions = lambda *, limit: [{
        "action_id": "verified-action",
        "action": "quarantine_file",
        "target": str(tmp_path / "marker.bin"),
        "applied_at": 1000.0,
        "reversible": True,
        "undone": False,
        "integrity_status": "verified",
        "status": "applied",
    }]
    manager = _Manager(config, combat)
    manager._settings_combat_activation_pending = True
    parent = _Parent(manager)
    dialog = SettingsDialog(config, lambda: None, lambda _: None, parent)
    try:
        _process_until(lambda: not dialog._combat_history_loading)
        assert dialog._combat_undo_selector.count() == 1
        assert not dialog._combat_undo_btn.isEnabled()
        manager._settings_combat_activation_pending = False
        parent._settings_combat_status.emit("ready", "Combat ready")
        QApplication.instance().processEvents()
        assert dialog._combat_undo_btn.isEnabled()
    finally:
        dialog.close()
        parent.close()


def test_main_window_keeps_combat_start_failure_visible():
    QApplication.instance() or QApplication([])
    lines = []
    alerts = []
    window = QMainWindow()
    window.console = SimpleNamespace(_append=lines.append)
    window.status_strip = SimpleNamespace(refresh=lambda: None)
    window.tray = SimpleNamespace(showMessage=lambda *args: alerts.append(args))
    try:
        MainWindow._show_settings_combat_status(
            window, "failed", "Combat journal recovery blocked activation.",
        )
        assert "recovery blocked" in window.statusBar().currentMessage()
        assert "recovery blocked" in lines[-1]
        assert alerts
    finally:
        window.close()


def test_shark_only_does_not_require_redteam_process_policy(monkeypatch):
    requests = []

    def assess(_manager, *, require_process=False):
        requests.append(require_process)
        return {
            "ready": not require_process,
            "state": "ARMED" if not require_process else "POLICY BLOCKED",
            "reason": "process response unavailable" if require_process else "ready",
        }

    monkeypatch.setattr(
        "angerona.core.drill_readiness.assess_drill_response", assess,
    )
    messages = []
    window = SimpleNamespace(
        manager=object(),
        console=SimpleNamespace(_append=messages.append),
        _simulation_launch_status=lambda status, reason, cfg: {
            "status": status, "reason": reason,
        },
    )
    shark = MainWindow._check_simulation_response(
        window, {"run_shark": True, "auto_remediate": True},
    )
    assert shark["status"] == "ready"
    assert window._sim_response_require_process is False
    combined = MainWindow._check_simulation_response(
        window, {"run_shark": True, "run_redteam": True, "auto_remediate": True},
    )
    assert combined["status"] == "warning"
    assert "process response unavailable" in combined["reason"]
    assert window._sim_response_require_process is True
    assert requests == [False, True]


class _Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds > 0
        self.sleeps.append(seconds)
        self.now += seconds


def test_redteam_aar_waits_for_inflight_combat_work_after_fim_minimum(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(main_window, "time", clock)
    remaining = iter((2, 1, 0))
    combat = SimpleNamespace(
        response_snapshot=lambda: {"queue_pending": next(remaining)},
    )
    narration = []
    window = SimpleNamespace(
        manager=SimpleNamespace(modules={"Adversary Combat": combat}),
        _shark_narration=SimpleNamespace(emit=narration.append),
    )

    result = MainWindow._wait_for_redteam_response_settlement(
        window, started_at=0.0,
    )
    assert result == {"pending": 0, "timed_out": False}
    assert clock.now == 46.0
    assert clock.sleeps == [45.0, 0.5, 0.5]
    assert len(narration) == 1
    assert "queued or in-flight" in narration[0]


def test_redteam_aar_bounds_wait_and_reports_unfinished_response(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(main_window, "time", clock)
    combat = SimpleNamespace(response_snapshot=lambda: {"queue_pending": 1})
    narration = []
    window = SimpleNamespace(
        manager=SimpleNamespace(modules={"Adversary Combat": combat}),
        _shark_narration=SimpleNamespace(emit=narration.append),
    )

    result = MainWindow._wait_for_redteam_response_settlement(
        window, started_at=0.0, max_extra_seconds=1.0,
    )
    assert result == {"pending": 1, "timed_out": True}
    assert clock.now == 46.0
    assert clock.sleeps == [45.0, 0.5, 0.5]
    assert "authenticated receipts already completed" in narration[-1]


def test_detection_only_redteam_keeps_fim_wait_without_combat_delay(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(main_window, "time", clock)
    narration = []
    window = SimpleNamespace(
        _sim_auto_remediate=False,
        manager=SimpleNamespace(modules={}),
        _shark_narration=SimpleNamespace(emit=narration.append),
    )

    result = MainWindow._wait_for_redteam_response_settlement(
        window, started_at=0.0,
    )
    assert result == {"pending": None, "timed_out": False}
    assert clock.sleeps == [45.0]
    assert narration == []
