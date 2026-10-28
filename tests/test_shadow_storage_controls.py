"""Inert storage policy, nonmodal choices and worker-only volume collection."""
from __future__ import annotations

import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget
from shiboken6 import delete, isValid

from angerona.core.config import Config
from angerona.gui import storage_controls as gui


class Module:
    def __init__(self):
        self.policies = []
        self.deletions = 0
        self.state = {"used_bytes": 80 * gui.MIB, "limit_bytes": 100 * gui.MIB,
                      "held": False, "cache_enabled": True}

    def configure_storage_policy(self, **policy):
        self.policies.append(policy)

    def storage_status(self):
        return dict(self.state)

    def request_cache_cleanup(self):
        self.deletions += 1
        return True


@pytest.fixture
def setup(tmp_path):
    parent = QWidget()
    config = Config(data_dir=tmp_path)
    module = Module()
    manager = SimpleNamespace(modules={"Shadow Shield": module})
    opened = []
    controller = gui.StorageWarningController(config, manager, parent, opened.append)
    yield config, module, manager, controller, opened, parent
    controller.close()
    thread = controller._reader.thread
    if thread is not None:
        thread.join(2)
        assert not thread.is_alive()
    if isValid(parent):
        delete(parent)


def _click(dialog, text):
    next(button for button in dialog.buttons() if text in button.text()).click()
    QApplication.processEvents()


def test_defaults_bound_cache_and_require_vss_opt_in(tmp_path):
    config = Config(data_dir=tmp_path)
    assert config.shadow_cache_enabled is True
    assert config.shadow_vss_enabled is False
    assert config.shadow_cache_max_mib == config.shadow_min_free_mib == 2048
    config.save()
    values = json.loads(config.settings_path.read_text())
    assert values["shadow_cache_max_mib"] == 2048
    assert values["shadow_vss_enabled"] is False


def test_loading_untrusted_storage_values_keeps_safe_defaults_and_other_settings(tmp_path, monkeypatch):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    (tmp_path / "settings.json").write_text(json.dumps({
        "shadow_cache_enabled": "false", "shadow_vss_enabled": "true",
        "shadow_cache_max_mib": -1, "shadow_min_free_mib": "512",
        "ollama_model": "storage-test-model",
    }))
    config = Config.load()
    assert config.shadow_cache_enabled is True and config.shadow_vss_enabled is False
    assert config.shadow_cache_max_mib == config.shadow_min_free_mib == 2048
    assert config.ollama_model == "storage-test-model"
    config.shadow_cache_enabled = False
    config.shadow_cache_max_mib = 512
    config.shadow_min_free_mib = 4096
    config.save()
    loaded = Config.load()
    assert loaded.shadow_cache_enabled is False
    assert loaded.shadow_cache_max_mib == 512 and loaded.shadow_min_free_mib == 4096


@pytest.mark.parametrize("field,value", [
    ("shadow_cache_enabled", "false"), ("shadow_vss_enabled", 1),
    ("shadow_cache_max_mib", 0), ("shadow_cache_max_mib", 16385),
    ("shadow_min_free_mib", 511), ("shadow_min_free_mib", True),
])
def test_invalid_policies_refuse_before_settings_publication(tmp_path, field, value):
    config = Config(data_dir=tmp_path)
    setattr(config, field, value)
    with pytest.raises(ValueError):
        config.save()
    assert not config.settings_path.exists()


def test_warning_categories_are_stable_as_byte_counts_change():
    assert gui.storage_warning({}, 100, 200) == "drive-low"
    assert gui.storage_warning({"held": True}, 300, 200) == "cache-held"
    assert gui.storage_warning({"used_bytes": 80, "limit_bytes": 100}, 300, 200) == "cache-near-limit"
    assert gui.storage_warning({"used_bytes": 99, "limit_bytes": 100}, 300, 200) == "cache-near-limit"
    assert gui.storage_warning({"used_bytes": None, "limit_bytes": 100}, None, 200) == "drive-unavailable"
    assert gui.storage_warning({"cache_enabled": False, "used_bytes": 99, "limit_bytes": 100}, 300, 200) == ""
    assert gui.storage_warning({"used_bytes": 79, "limit_bytes": 100}, 300, 200) == ""


def test_warning_holds_writes_without_changing_saved_preference_and_deduplicates(setup):
    config, module, _, controller, _, _ = setup
    result = (module.storage_status(), 10_000 * gui.MIB, 2048 * gui.MIB)
    controller._apply(result)
    dialog = controller._warning
    assert dialog is not None and not dialog.isModal()
    assert config.shadow_cache_enabled is True
    assert module.policies[-1]["cache_enabled"] is False
    assert module.policies[-1]["review_pending"] is True
    controller._apply((dict(module.state, used_bytes=95 * gui.MIB), result[1], result[2]))
    assert controller._warning is dialog
    _click(dialog, "Block")
    assert config.shadow_cache_enabled is False and config.shadow_vss_enabled is False
    assert module.deletions == 0
    controller._apply(result)
    assert controller._warning is None


def test_delete_requires_second_explicit_confirmation_and_never_runs_on_warning(setup):
    _, module, _, controller, _, _ = setup
    controller._apply((module.storage_status(), 1, 2))
    _click(controller._warning, "Delete")
    assert module.deletions == 0
    dialog = controller._confirmation
    assert dialog.defaultButton() is dialog.button(QMessageBox.No)
    dialog.button(QMessageBox.No).click()
    QApplication.processEvents()
    assert module.deletions == 0 and controller._confirmation is None
    controller._acknowledged.clear()
    controller._apply((module.storage_status(), 1, 2))
    _click(controller._warning, "Delete")
    controller._confirmation.button(QMessageBox.Yes).click()
    QApplication.processEvents()
    assert module.deletions == 1


def test_change_opens_settings_and_never_bypasses_disk_reserve(setup):
    config, module, _, controller, opened, _ = setup
    controller._apply((module.storage_status(), 1, 2))
    _click(controller._warning, "Allow")
    assert opened == ["General"]
    assert config.shadow_cache_enabled is True
    assert module.policies[-1]["cache_enabled"] is False
    assert module.policies[-1]["min_free_mib"] == 2048


def test_settings_block_applies_immediately_but_persists_only_on_save(setup):
    config, module, manager, _, _, parent = setup
    controls = gui.StorageControls(config, manager, parent)
    controls._block()
    assert config.shadow_cache_enabled is True
    assert not controls.cache_enabled.isChecked()
    assert module.policies[-1]["cache_enabled"] is False
    controls.max_mib.setValue(512)
    controls.min_free_mib.setValue(4096)
    controls.write_candidate(config)
    assert config.shadow_cache_enabled is False
    assert config.shadow_cache_max_mib == 512 and config.shadow_min_free_mib == 4096
    config.save()
    values = json.loads(config.settings_path.read_text())
    assert values["shadow_cache_enabled"] is False


def test_settings_confirmed_delete_blocks_before_request_and_cancel_preserves_policy(setup):
    config, module, manager, _, _, parent = setup
    controls = gui.StorageControls(config, manager, parent)
    calls = []
    module.configure_storage_policy = lambda **policy: calls.append(("block", policy))
    module.request_cache_cleanup = lambda: calls.append(("delete", None)) or True
    controls._delete()
    controls._confirmation.button(QMessageBox.No).click()
    QApplication.processEvents()
    assert not calls and controls.cache_enabled.isChecked()
    controls._delete()
    controls._confirmation.button(QMessageBox.Yes).click()
    QApplication.processEvents()
    assert [item[0] for item in calls] == ["block", "delete"]
    assert not controls.cache_enabled.isChecked()
    assert config.shadow_cache_enabled is True
    controls.close()
    assert not controls._timer.isActive()


def test_volume_probe_runs_off_qt_and_polling_coalesces(setup, monkeypatch):
    config, _, _, controller, _, _ = setup
    entered, release = threading.Event(), threading.Event()
    calls = []
    gui_thread = threading.get_ident()
    def probe(_path):
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(2)
        return SimpleNamespace(free=20_000 * gui.MIB)
    monkeypatch.setattr(gui.shutil, "disk_usage", probe)
    monkeypatch.setattr(gui.tempfile, "gettempdir", lambda: str(config.data_dir))
    controller.poll()
    assert entered.wait(2)
    for _ in range(20):
        controller.poll()
    assert len(calls) == 1 and calls[0] != gui_thread
    release.set()
    deadline = time.monotonic() + 2
    while controller._reader.busy and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(.005)
    assert not controller._reader.busy
    assert len(calls) <= 2


def test_close_cancels_prompt_without_queuing_delete(setup):
    _, module, _, controller, _, _ = setup
    controller._apply((module.storage_status(), 1, 2))
    _click(controller._warning, "Delete")
    controller.close()
    assert module.deletions == 0


def test_data_and_temporary_volumes_are_probed_and_low_temp_volume_is_named(monkeypatch, setup):
    _, module, _, controller, _, _ = setup
    data, scratch = Path(r"X:\runtime"), Path(r"Y:\scratch")
    calls = []
    with monkeypatch.context() as patch:
        patch.setattr(gui.tempfile, "gettempdir", lambda: str(scratch))
        patch.setattr(gui.os, "stat", lambda path: SimpleNamespace(st_dev=11 if path == data else 22))
        def probe(path):
            calls.append(path)
            return SimpleNamespace(free=(10000 if path == data else 100) * gui.MIB)
        patch.setattr(gui.shutil, "disk_usage", probe)
        volume, free = gui._collect_volume_capacity(data, 2048 * gui.MIB)
    assert calls == [data, scratch]
    assert free == 100 * gui.MIB and volume["volume_label"] == "Y:\\"
    assert volume["volume_scopes"] == ("Temporary files",)
    controller._apply((dict(module.storage_status(), **volume), free, 2048 * gui.MIB))
    text = controller._warning.text()
    assert "Temporary files on Y:\\" in text
    assert "Runtime data on X:\\" in text
    assert module.deletions == 0


def test_capacity_deduplicates_distinct_anchors_with_same_device_identity(monkeypatch):
    data, scratch = Path(r"X:\runtime"), Path(r"Y:\scratch")
    calls = []
    with monkeypatch.context() as patch:
        patch.setattr(gui.tempfile, "gettempdir", lambda: str(scratch))
        patch.setattr(gui.os, "stat", lambda _path: SimpleNamespace(st_dev=11))
        patch.setattr(gui.shutil, "disk_usage", lambda path: calls.append(path) or SimpleNamespace(free=5000 * gui.MIB))
        volume, free = gui._collect_volume_capacity(data, 2048 * gui.MIB)
    assert calls == [data]
    assert free == 5000 * gui.MIB
    assert volume["volume_scopes"] == ("Runtime data", "Temporary files")
    assert not volume["volume_gaps"]


@pytest.mark.parametrize("failed_stage", ["identity", "capacity", "temp-discovery"])
def test_unknown_temp_capacity_stays_explicit_even_with_known_room(monkeypatch, failed_stage):
    data, scratch = Path(r"X:\runtime"), Path(r"Y:\scratch")
    def tempdir():
        if failed_stage == "temp-discovery":
            raise OSError("synthetic temporary directory unavailable")
        return str(scratch)
    def identity(path):
        if path == scratch and failed_stage == "identity":
            raise PermissionError("synthetic identity unavailable")
        return SimpleNamespace(st_dev=11 if path == data else 22)
    def probe(path):
        if path == scratch and failed_stage == "capacity":
            raise OSError("synthetic capacity unavailable")
        return SimpleNamespace(free=5000 * gui.MIB)
    with monkeypatch.context() as patch:
        patch.setattr(gui.tempfile, "gettempdir", tempdir)
        patch.setattr(gui.os, "stat", identity)
        patch.setattr(gui.shutil, "disk_usage", probe)
        volume, free = gui._collect_volume_capacity(data, 2048 * gui.MIB)
    assert free is None
    assert volume["volume_scopes"] == ("Temporary files",)
    assert volume["volume_gaps"] and "Temporary files" in volume["volume_gaps"][0]
    assert "capacity unavailable" in volume["volume_summary"]
    assert gui.storage_warning({}, free, 2048 * gui.MIB) == "drive-unavailable"
