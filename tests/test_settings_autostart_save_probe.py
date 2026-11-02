"""Settings saves query the OS startup task only when they may change it."""
from __future__ import annotations

import copy
import os
from collections.abc import MutableMapping
from contextlib import contextmanager

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from angerona.core import autostart
from angerona.core import config as config_module
from angerona.core import secure_store
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


_RUNTIME_ENVIRONMENT_KEYS = (
    "ANGERONA_SIEM_HOST", "ANGERONA_SIEM_PORT", "ANGERONA_SIEM_PROTO",
    "ANGERONA_SIEM_MINSEV", "ANGERONA_SIEM_CA_FILE", "ANGERONA_BRIDGE_MODE",
    "ANGERONA_BRIDGE_PEER", "ANGERONA_BRIDGE_BIND", "ANGERONA_BRIDGE_PORT",
    "ANGERONA_BRIDGE_NODE_ID", "ANGERONA_IOC_FEED", "ANGERONA_IOC_FEED_SHA256",
    "ANGERONA_SIEM_ALLOW_PLAINTEXT", "ANGERONA_SIEM_INCLUDE_RAW",
    "ANGERONA_BRIDGE_ALLOW_NONLOOPBACK", "ANGERONA_REQUIRE_SIGNED_AAR",
    "ANGERONA_ENTROPY_POOL", "ANGERONA_ADVERSARY_COMBAT_ENABLED",
    "ANGERONA_USER_FOLDER_DECEPTION", "ANGERONA_ADVERSARY_COMBAT_MODE",
    "ANGERONA_AI_ORDER",
)


@pytest.fixture
def inert_credentials(tmp_path, monkeypatch):
    """Keep the real environment scrubber; replace only protected-store I/O."""
    protected, writes = {}, []

    @contextmanager
    def transaction(_data_root=None):
        yield

    def write(updates, _data_root=None):
        writes.append(dict(updates))
        for name, value in updates.items():
            if value:
                protected[name] = str(value)
            else:
                protected.pop(name, None)
        return tmp_path / "inert-protected-store"

    monkeypatch.setattr(secure_store, "secret_transaction", transaction)
    monkeypatch.setattr(secure_store, "_write_secret_map_locked", write)
    monkeypatch.setattr(secure_store, "read_secret_map", lambda *_args, **_kwargs: dict(protected))
    monkeypatch.setattr(config_module, "write_env_keys", lambda updates: secure_store.write_secret_map(updates, tmp_path))
    return protected, writes


def test_failed_save_preserves_unrelated_concurrent_environment_changes(
    tmp_path, monkeypatch, inert_credentials,
):
    dialog, config, _probes, _changes = _dialog(tmp_path, monkeypatch)
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _parent, title, _message: warnings.append(title))
    runtime_before = {
        name: ("legacy-value" if index % 3 == 0 else "")
        for index, name in enumerate(_RUNTIME_ENVIRONMENT_KEYS) if index % 3 != 2
    }
    environment = {**runtime_before, "UNRELATED_CHANGED": "old", "UNRELATED_REMOVED": "old"}
    monkeypatch.setattr(os, "environ", environment)

    def refuse_autostart():
        # Real Config.save already published the candidate's integration values.
        assert environment["ANGERONA_SIEM_HOST"] == "collector.example"
        environment["UNRELATED_CHANGED"] = "new"
        environment["UNRELATED_ADDED"] = "new"
        environment.pop("UNRELATED_REMOVED")
        return False

    monkeypatch.setattr(autostart, "enable_autostart", refuse_autostart)
    try:
        dialog._siem_host.setText("collector.example")
        dialog._autostart_chk.setChecked(True)
        dialog._save()
        assert environment["UNRELATED_CHANGED"] == "new"
        assert environment["UNRELATED_ADDED"] == "new"
        assert "UNRELATED_REMOVED" not in environment
        assert {name: environment[name] for name in _RUNTIME_ENVIRONMENT_KEYS if name in environment} == runtime_before
        assert config.siem_host == "" and config.autostart_enabled is False
        assert not config.settings_path.exists()
        assert warnings == ["Settings not saved"]
    finally:
        dialog.close()


def test_failed_save_does_not_resurrect_scrubbed_credentials(
    tmp_path, monkeypatch, inert_credentials,
):
    protected, writes = inert_credentials
    protected["OPENAI_API_KEY"] = "original-test-protected-value"
    dialog, config, _probes, _changes = _dialog(tmp_path, monkeypatch, enable_result=False)
    monkeypatch.setattr(QMessageBox, "warning", lambda *_args: None)
    secret_names = ("OPENAI_API_KEY", "ANGERONA_USB_PIN", "ANGERONA_BRIDGE_KEY",
                    "ANGERONA_JARVIS_CONTROL_TOKEN", "ANGERONA_RECORDER_WITNESS_PRIVATE_KEY")
    environment = {name: "inherited-test-only-value" for name in secret_names}
    monkeypatch.setattr(os, "environ", environment)
    try:
        dialog._key_fields["openai"].setText("new-test-protected-value")
        dialog._api_keys_dirty = True
        dialog._autostart_chk.setChecked(True)
        dialog._save()
        assert writes[0]["OPENAI_API_KEY"] == "new-test-protected-value"
        assert writes[-1]["OPENAI_API_KEY"] == "original-test-protected-value"
        assert protected == {"OPENAI_API_KEY": "original-test-protected-value"}
        assert all(name not in environment for name in secret_names)
        assert config.autostart_enabled is False
        assert not config.settings_path.exists()
    finally:
        dialog.close()


class _OwnedRuntimeEnvironment(MutableMapping):
    """Fail if a settings save copies/clears the process-wide environment."""
    def __init__(self, values, *, fail_once=None, fail_restore=None):
        self.values = dict(values)
        self.fail_once = fail_once
        self.fail_restore = fail_restore
        self.writes = []

    def __getitem__(self, key):
        return self.values[key]

    def __setitem__(self, key, value):
        assert key in _RUNTIME_ENVIRONMENT_KEYS
        self.writes.append((key, value))
        if key == self.fail_once:
            self.fail_once = None
            raise OSError("inert runtime setting publication failure")
        if (key, value) == self.fail_restore:
            raise OSError("inert runtime setting restoration failure")
        self.values[key] = value

    def __delitem__(self, key):
        assert key in _RUNTIME_ENVIRONMENT_KEYS
        del self.values[key]

    def __iter__(self):
        raise AssertionError("Settings must not copy the whole environment")

    def __len__(self):
        return len(self.values)

    def clear(self):
        raise AssertionError("Settings must not clear the whole environment")


def test_failed_save_never_copies_or_clears_whole_environment(
    tmp_path, monkeypatch, inert_credentials,
):
    dialog, config, _probes, _changes = _dialog(tmp_path, monkeypatch, enable_result=False)
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _parent, title, _message: warnings.append(title))
    environment = _OwnedRuntimeEnvironment({"ANGERONA_SIEM_HOST": "original", "UNRELATED": "keep"})
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(os, "environ", environment)
            dialog._autostart_chk.setChecked(True)
            dialog._save()
            assert environment.values == {"ANGERONA_SIEM_HOST": "original", "UNRELATED": "keep"}
            assert config.autostart_enabled is False
            assert warnings == ["Settings not saved"]
    finally:
        dialog.close()


def test_failed_runtime_flag_publication_restores_owned_values_only(
    tmp_path, monkeypatch, inert_credentials,
):
    dialog, config, _probes, _changes = _dialog(tmp_path, monkeypatch)
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _parent, title, _message: warnings.append(title))
    before = {name: "original-value" for name in _RUNTIME_ENVIRONMENT_KEYS}
    config_before = copy.deepcopy(vars(config))
    environment = _OwnedRuntimeEnvironment({**before, "UNRELATED": "keep"}, fail_once="ANGERONA_AI_ORDER")
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(os, "environ", environment)
            dialog._require_signed_aar_chk.setChecked(True)
            dialog._entropy_pool_chk.setChecked(True)
            dialog._combat_enabled_chk.setChecked(True)
            dialog._deception_user_folders_chk.setChecked(True)
            dialog._save()
            assert environment.fail_once is None
            assert ("ANGERONA_REQUIRE_SIGNED_AAR", "1") in environment.writes
            assert ("ANGERONA_ADVERSARY_COMBAT_MODE", "maximum") in environment.writes
            assert environment.values == {**before, "UNRELATED": "keep"}
            assert vars(config) == config_before
            assert not config.settings_path.exists()
            assert warnings == ["Settings not saved"]
    finally:
        dialog.close()


def test_runtime_rollback_reports_failed_key_and_restores_later_keys(
    tmp_path, monkeypatch, inert_credentials,
):
    dialog, config, _probes, _changes = _dialog(tmp_path, monkeypatch)
    critical = []
    monkeypatch.setattr(QMessageBox, "critical", lambda _parent, title, message: critical.append((title, message)))
    before = {name: "original-value" for name in _RUNTIME_ENVIRONMENT_KEYS}
    environment = _OwnedRuntimeEnvironment(
        {**before, "UNRELATED": "keep"}, fail_once="ANGERONA_AI_ORDER",
        fail_restore=("ANGERONA_SIEM_HOST", "original-value"),
    )
    config_before = copy.deepcopy(vars(config))
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(os, "environ", environment)
            dialog._save()
            assert environment.fail_once is None
            assert "ANGERONA_SIEM_HOST" not in environment.values
            assert environment.values == {
                **{name: value for name, value in before.items() if name != "ANGERONA_SIEM_HOST"},
                "UNRELATED": "keep",
            }
            assert vars(config) == config_before
            assert not config.settings_path.exists()
            assert len(critical) == 1 and critical[0][0] == "Settings rollback incomplete"
            assert "runtime setting ANGERONA_SIEM_HOST" in critical[0][1]
    finally:
        dialog.close()


def test_settings_rows_save_spyware_budget_without_changing_standalone_range(tmp_path, monkeypatch):
    import json

    dialog, config, _probes, _changes = _dialog(tmp_path, monkeypatch)
    try:
        standalone = dialog._github_tool_limits["github_tools_timeout_seconds"]
        spyware = dialog._github_tool_limits["spyware_scan_timeout_seconds"]
        assert (standalone.minimum(), standalone.maximum(), standalone.value()) == (30, 900, 300)
        assert (spyware.minimum(), spyware.maximum(), spyware.value()) == (30, 14400, 3600)
        standalone.setValue(45)
        spyware.setValue(7200)
        dialog._save()
        assert dialog.result() == QDialog.Accepted
        assert config.github_tools_timeout_seconds == 45
        assert config.spyware_scan_timeout_seconds == 7200
        saved = json.loads(config.settings_path.read_text(encoding="utf-8"))
        assert saved["github_tools_timeout_seconds"] == 45
        assert saved["spyware_scan_timeout_seconds"] == 7200
    finally:
        dialog.close()
