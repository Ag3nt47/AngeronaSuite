from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("PySide6")

from angerona.core.settings_catalog import resolve_area
from angerona.gui.pages import _read_trusted_source
from angerona.gui.selftest_settings import SelfTestSettingsPanel
from angerona.modules.beacon_detector import BeaconDetectorModule


def test_settings_exposes_selected_test_source_and_stages_opt_in():
    module = BeaconDetectorModule()
    module._angerona_origin = "builtin"
    module._angerona_contract = SimpleNamespace(capability_id="angerona.builtin.beacon_detector")
    config = SimpleNamespace(selftest_auto_recover_modules=[], selftest_timeout_seconds=45)
    calls = []
    dashboard = SimpleNamespace(manager=SimpleNamespace(modules={module.name: module}),
                                _run_self_test=lambda *, names: calls.append(names) or True)
    panel = SelfTestSettingsPanel(dashboard, config, _read_trusted_source)
    try:
        assert panel.time_budget.currentData() == 45
        assert panel.source.isReadOnly()
        panel.view_source.click()
        assert "def self_test" in panel.source.toPlainText()
        assert "_beacon_score" in panel.source.toPlainText()
        assert panel.auto_recovery.isEnabled() and not panel.auto_recovery.isChecked()
        panel.auto_recovery.setChecked(True)
        assert panel.auto_recovery_modules() == ["angerona.builtin.beacon_detector"]
        assert config.selftest_auto_recover_modules == []
        panel.run_selected.click()
        panel.run_all.click()
        assert calls == [[module.name], None]
    finally:
        panel.close()
        panel.deleteLater()


def test_selftest_settings_is_searchable():
    assert resolve_area("sample test").title == "Self-Test"
