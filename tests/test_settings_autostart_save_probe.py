"""Settings saves query the OS startup task only when they may change it."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from angerona.core import autostart
from angerona.core.config import Config
from angerona.gui.pages import SettingsDialog


def _dialog(tmp_path, monkeypatch, *, enable_result=True):
    QApplication.instance() or QApplication([])
    probes = []
    changes = []

    def query():
        probes.append("query")
        return False

    monkeypatch.setattr(autostart, "is_enabled", query)
    monkeypatch.setattr(
        autostart, "enable_autostart",
        lambda: changes.append("enable") or enable_result,
    )
    monkeypatch.setattr(
        autostart, "disable_autostart",
        lambda: changes.append("disable") or True,
    )
    config = Config(data_dir=tmp_path, autostart_enabled=False)
    dialog = SettingsDialog(config, lambda: None, lambda _: None)
    assert probes == ["query"]  # The System tab reads the initial OS state.
    return dialog, config, probes, changes


def test_unrelated_save_does_not_repeat_windows_task_query(tmp_path, monkeypatch):
    dialog, config, probes, changes = _dialog(tmp_path, monkeypatch)
    try:
        dialog._alert_retention_days.setValue(45)
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        assert config.alert_retention_days == 45
        assert probes == ["query"]
        assert changes == []
    finally:
        dialog.close()


def test_autostart_change_still_queries_and_updates_os(tmp_path, monkeypatch):
    dialog, config, probes, changes = _dialog(tmp_path, monkeypatch)
    try:
        dialog._autostart_chk.setChecked(True)
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        assert probes == ["query", "query"]
        assert changes == ["enable"]
        assert config.autostart_enabled is True
    finally:
        dialog.close()


def test_failed_autostart_change_restores_prior_settings(tmp_path, monkeypatch):
    dialog, config, probes, changes = _dialog(
        tmp_path, monkeypatch, enable_result=False,
    )
    warnings = []
    monkeypatch.setattr(
        QMessageBox, "warning",
        lambda _parent, title, message: warnings.append((title, message)),
    )
    original = config.settings_path.read_bytes() if config.settings_path.exists() else None
    try:
        dialog._autostart_chk.setChecked(True)
        dialog._save()
        assert dialog.result() != QDialog.Accepted
        assert probes == ["query", "query"]
        assert changes == ["enable"]
        assert config.autostart_enabled is False
        if original is None:
            assert not config.settings_path.exists()
        else:
            assert config.settings_path.read_bytes() == original
        assert warnings and warnings[-1][0] == "Settings not saved"
    finally:
        dialog.close()
