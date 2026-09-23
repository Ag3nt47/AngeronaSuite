"""Settings persist a bounded policy; the GUI submits copies without filesystem work."""
from __future__ import annotations

import json
from types import SimpleNamespace

from PySide6.QtWidgets import QDialog, QLabel, QMessageBox, QVBoxLayout, QWidget

from angerona.core.alert_retention import AlertRetentionWorker, RetentionPolicy
from angerona.core.config import Config
from angerona.gui.main_window import MainWindow
from angerona.gui.pages import SettingsDialog


def test_policy_roundtrips_config_without_affecting_ledger(tmp_path, monkeypatch):
    config = Config()
    monkeypatch.delenv("ANGERONA_ARIA_PUSH_URL", raising=False)
    config.alert_retention_enabled = False
    config.alert_retention_days = 45
    config.alert_retention_max_mib = 512
    config.save()
    loaded = Config.load()
    assert RetentionPolicy.from_config(loaded) == RetentionPolicy(False, 45, 512)
    raw = json.loads(config.settings_path.read_text(encoding="utf-8"))
    assert raw["alert_retention_max_mib"] == 512
    assert "MAX_ROWS" not in raw


def test_bad_saved_retention_does_not_prevent_other_config_loading(monkeypatch):
    config = Config()
    config.settings_path.write_text(json.dumps({
        "alert_retention_enabled": "false", "alert_retention_days": None,
        "alert_retention_max_mib": 2, "ollama_model": "retention-test-model",
    }), encoding="utf-8")
    loaded = Config.load()
    assert RetentionPolicy.from_config(loaded) == RetentionPolicy()
    assert loaded.ollama_model == "retention-test-model"


def test_gui_blackbox_feed_is_a_bounded_queue_submission_only(tmp_path, monkeypatch):
    worker = AlertRetentionWorker(tmp_path)
    window = SimpleNamespace(alert_retention_worker=worker)
    MainWindow._blackbox_feed(window, "diagnostic")
    assert worker.snapshot()["queued"] == 1
    assert not list(tmp_path.iterdir())
    worker.stop()


class ControlsDialog(QDialog):
    _alert_retention_controls = SettingsDialog._alert_retention_controls
    _alert_retention_worker = SettingsDialog._alert_retention_worker
    _refresh_alert_cleanup = SettingsDialog._refresh_alert_cleanup
    _request_alert_cleanup = SettingsDialog._request_alert_cleanup


def test_settings_controls_explain_irreversible_scope_and_apply_saved_policy(tmp_path):
    parent = QWidget()
    parent.alert_retention_worker = AlertRetentionWorker(tmp_path)
    dialog = ControlsDialog(parent)
    dialog._cfg = Config(data_dir=tmp_path)
    QVBoxLayout(dialog).addWidget(dialog._alert_retention_controls())
    assert dialog._alert_retention_days.value() == 30
    assert dialog._alert_retention_mib.value() == 256
    assert dialog._alert_retention_chk.isChecked()
    labels = " ".join(item.text() for item in dialog.findChildren(QLabel))
    assert "permanently deletes" in labels and "Signed alert history" in labels
    dialog._alert_retention_chk.setChecked(False)
    assert not dialog._alert_retention_days.isEnabled()
    assert parent.alert_retention_worker.snapshot()["enabled"]  # unsaved change
    dialog._request_alert_cleanup()
    assert parent.alert_retention_worker._requested
    parent.alert_retention_worker.stop()
    dialog.close()
    parent.close()


def test_settings_retention_unavailable_status_is_explicit(tmp_path):
    dialog = ControlsDialog()
    dialog._cfg = Config(data_dir=tmp_path)
    QVBoxLayout(dialog).addWidget(dialog._alert_retention_controls())
    assert not dialog._alert_cleanup_btn.isEnabled()
    assert "unavailable" in dialog._alert_cleanup_status.text()
    dialog.close()


def test_settings_save_updates_retention_worker_only_after_commit(tmp_path, monkeypatch):
    from angerona.core import autostart
    monkeypatch.setattr(autostart, "is_enabled", lambda: False)
    parent = QWidget()
    parent.alert_retention_worker = AlertRetentionWorker(tmp_path)
    config = Config(data_dir=tmp_path, autostart_enabled=False)
    dialog = SettingsDialog(config, lambda: None, lambda _: None, parent)
    dialog._alert_retention_chk.setChecked(False)
    dialog._alert_retention_days.setValue(60)
    dialog._alert_retention_mib.setValue(128)
    dialog._save()
    assert dialog.result() == QDialog.Accepted
    assert RetentionPolicy.from_config(config) == RetentionPolicy(False, 60, 128)
    assert not parent.alert_retention_worker.snapshot()["enabled"]
    saved = json.loads(config.settings_path.read_text(encoding="utf-8"))
    assert saved["alert_retention_days"] == 60
    parent.alert_retention_worker.stop()
    dialog.close()
    parent.close()


def test_failed_settings_save_does_not_change_live_cleanup_policy(tmp_path, monkeypatch):
    from angerona.core import autostart
    monkeypatch.setattr(autostart, "is_enabled", lambda: False)
    monkeypatch.setattr(QMessageBox, "warning", lambda *_: None)
    parent = QWidget()
    parent.alert_retention_worker = AlertRetentionWorker(tmp_path)
    config = Config(data_dir=tmp_path, autostart_enabled=False)
    dialog = SettingsDialog(config, lambda: None, lambda _: None, parent)
    dialog._alert_retention_chk.setChecked(False)
    def fail_save(_):
        raise OSError("disk full")
    monkeypatch.setattr(Config, "save", fail_save)
    dialog._save()
    assert config.alert_retention_enabled
    assert parent.alert_retention_worker.snapshot()["enabled"]
    parent.alert_retention_worker.stop()
    dialog.close()
    parent.close()
