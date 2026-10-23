"""Construct real Settings; replace unrelated tabs/producers with inert widgets."""
from __future__ import annotations

from PySide6.QtCore import SIGNAL
from PySide6.QtWidgets import QWidget
from shiboken6 import delete, isValid

from angerona.core.config import Config
from angerona.gui import ollama_status
from angerona.gui.pages import SettingsDialog

from test_github_update_controller_lifecycle import owned, _owner, _producer, _until


def _settings(owned, tmp_path, monkeypatch):
    owner, controller = _owner(owned, tmp_path, enabled=True)
    config = Config(data_dir=tmp_path, github_daily_check_enabled=True)
    owner.config = controller._config = config
    for name in ("_tab_overview", "_tab_information", "_tab_system", "_tab_adversary_combat",
                 "_tab_enterprise", "_tab_integrations", "_tab_aria", "_tab_trusted_processes",
                 "_tab_mobile", "_tab_apikeys"):
        monkeypatch.setattr(SettingsDialog, name, lambda self: QWidget(self))
    monkeypatch.setattr(ollama_status, "OllamaStatusPanel", lambda host, parent=None, **kwargs: QWidget(parent))
    before = (controller.receivers(SIGNAL("status_changed(QString)")),
              controller.receivers(SIGNAL("check_busy_changed(bool)")))
    dialog = SettingsDialog(config, controller, lambda _: None, owner, initial_tab="General")
    return owner, controller, dialog, before


def test_real_settings_opt_out_completion_clears_checking_and_reenables_check_now(owned, tmp_path, monkeypatch):
    entered, release, calls, _ = _producer(owned, monkeypatch)
    owner, controller, dialog, _ = _settings(owned, tmp_path, monkeypatch)
    try:
        controller.check_daily()
        _until(entered.is_set)
        assert not dialog._btn_check.isEnabled() and "Checking" in dialog._update_status.text()
        dialog._github_daily_check.setChecked(False)
        release.set()
        _until(lambda: not controller._check.busy)
        assert dialog._btn_check.isEnabled() and "after opt-out" in dialog._update_status.text()
        assert not owner.prompts and len(calls) == 1
    finally:
        dialog.close()
        if isValid(dialog):
            delete(dialog)


def test_real_settings_close_disconnects_status_busy_and_report_receivers(owned, tmp_path, monkeypatch):
    owner, controller, dialog, before = _settings(owned, tmp_path, monkeypatch)
    assert controller.receivers(SIGNAL("status_changed(QString)")) == before[0] + 1
    assert controller.receivers(SIGNAL("check_busy_changed(bool)")) == before[1] + 1
    controller.status_changed.emit("Before closing Settings.")
    text, enabled = dialog._update_status.text(), dialog._btn_check.isEnabled()
    dialog.close()
    assert dialog._shared_update_controller is None
    assert controller.receivers(SIGNAL("status_changed(QString)")) == before[0]
    assert controller.receivers(SIGNAL("check_busy_changed(bool)")) == before[1]
    controller.status_changed.emit("After closing Settings.")
    controller.check_busy_changed.emit(True)
    assert dialog._update_status.text() == text and dialog._btn_check.isEnabled() == enabled
    delete(dialog)
    controller.status_changed.emit("After deleting Settings.")
    controller.check_busy_changed.emit(False)
    assert controller.alive() and isValid(owner)
