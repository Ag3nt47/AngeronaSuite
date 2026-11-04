"""Persisted bounds and inert cached-only normal log UI controls."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from PySide6.QtWidgets import QApplication, QWidget
from shiboken6 import delete, isValid

from angerona.core.config import Config
from angerona.gui import normal_log_controls as gui


def _snapshot(**updates):
    values = dict(limit_bytes=8 * gui.MIB, message_bytes=64 * 1024,
                  paused=False, suppression_counts_lower_bound=False,
                  targets=tuple(dict(role=role, reason="", reserved_bytes=0,
                                     checked_size_bytes=0, suppressed_blocks=0)
                                for role in ("logs", "diagnostics")))
    values.update(updates)
    return values


@pytest.fixture
def inert(tmp_path, monkeypatch):
    state = _snapshot()
    calls = []
    monkeypatch.setattr(gui, "normal_write_snapshot", lambda: state)
    monkeypatch.setattr(gui, "configure_normal_log_budget",
                        lambda **policy: calls.append(policy) or {"accepted": True, "reason": "configured"})
    parent = QWidget()
    config = Config(data_dir=tmp_path)
    yield config, state, calls, parent
    if isValid(parent):
        delete(parent)


def test_defaults_and_roundtrip_preserve_unrelated_preferences(tmp_path, monkeypatch):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    config = Config(data_dir=tmp_path)
    assert (config.normal_log_max_mib, config.normal_log_message_kib, config.normal_log_paused) == (8, 64, False)
    config.normal_log_max_mib = 12
    config.normal_log_message_kib = 128
    config.normal_log_paused = True
    config.ollama_model = "preserve-operator-choice"
    config.save()
    loaded = Config.load()
    assert (loaded.normal_log_max_mib, loaded.normal_log_message_kib, loaded.normal_log_paused) == (12, 128, True)
    assert loaded.ollama_model == "preserve-operator-choice"


@pytest.mark.parametrize("value", [True, False, 0, 65, -1, 8.0, "8", None])
def test_malformed_file_allowance_keeps_default(tmp_path, monkeypatch, value):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    (tmp_path / "settings.json").write_text(json.dumps({"normal_log_max_mib": value}), encoding="utf-8")
    assert Config.load().normal_log_max_mib == 8


@pytest.mark.parametrize("value", [True, 0, 3, 257, -1, 64.0, "64", None])
def test_malformed_message_allowance_keeps_default(tmp_path, monkeypatch, value):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    (tmp_path / "settings.json").write_text(json.dumps({"normal_log_message_kib": value}), encoding="utf-8")
    assert Config.load().normal_log_message_kib == 64


@pytest.mark.parametrize("field,value", [
    ("normal_log_paused", "false"), ("normal_log_paused", 1),
    ("normal_log_max_mib", True), ("normal_log_max_mib", 0), ("normal_log_max_mib", 65),
    ("normal_log_message_kib", True), ("normal_log_message_kib", 3),
    ("normal_log_message_kib", 257), ("normal_log_message_kib", "64"),
])
def test_invalid_policy_preserves_settings_before_publication(tmp_path, field, value):
    config = Config(data_dir=tmp_path)
    config.settings_path.write_bytes(b'{"original":true}\n')
    original = config.settings_path.read_bytes()
    setattr(config, field, value)
    with pytest.raises(ValueError):
        config.save()
    assert config.settings_path.read_bytes() == original


@pytest.mark.parametrize("value", ["true", 1, None, []])
def test_malformed_pause_is_not_truth_coerced(tmp_path, monkeypatch, value):
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(Config, "_load_dotenv", staticmethod(lambda *_args: None))
    (tmp_path / "settings.json").write_text(json.dumps({"normal_log_paused": value}), encoding="utf-8")
    assert Config.load().normal_log_paused is False


def test_runtime_choices_apply_without_saving_or_mutating_preferences(inert):
    config, _, calls, parent = inert
    controls = gui.NormalLogControls(config, parent)
    controls._block()
    assert calls[-1] == {"limit_mib": 8, "message_kib": 64, "paused": True}
    assert config.normal_log_paused is False
    assert not config.settings_path.exists()
    controls.max_mib.setValue(16)
    controls.message_kib.setValue(32)
    controls._allow()
    assert calls[-1] == {"limit_mib": 16, "message_kib": 32, "paused": False}
    assert "Policy accepted" in controls.result.text()
    assert "next append" in controls.result.text()
    assert config.normal_log_max_mib == 8
    controls.write_candidate(config)
    assert (config.normal_log_max_mib, config.normal_log_message_kib, config.normal_log_paused) == (16, 32, False)
    controls.close()
    assert not controls._timer.isActive()


def test_busy_writer_does_not_claim_live_policy_applied_and_retry_works(inert, monkeypatch):
    config, state, _, parent = inert
    controls = gui.NormalLogControls(config, parent)
    monkeypatch.setattr(gui, "configure_normal_log_budget", lambda **_policy: {"accepted": False, "reason": "writer-busy"})
    controls.max_mib.setValue(16)
    controls._apply()
    assert "not applied" in controls.result.text()
    assert "8 MiB" in controls.usage.text()
    assert config.normal_log_max_mib == 8
    state["limit_bytes"] = 16 * gui.MIB
    monkeypatch.setattr(gui, "configure_normal_log_budget", lambda **_policy: {"accepted": True, "reason": "configured"})
    controls._apply()
    assert "Policy accepted" in controls.result.text()
    assert "16 MiB" in controls.usage.text()


def test_apply_helper_reports_failure_without_private_exception(inert, monkeypatch):
    config, _, _, _ = inert
    def fail(**_policy):
        raise RuntimeError("private exception path")
    monkeypatch.setattr(gui, "configure_normal_log_budget", fail)
    assert gui.apply_normal_log_policy(config) == {"accepted": False, "reason": "configuration-unavailable"}


def test_warning_categories_ignore_policy_pause_and_do_not_depend_on_count_changes():
    state = _snapshot()
    assert gui.normal_log_warning(state) == ""
    state["targets"][0]["checked_size_bytes"] = 7 * gui.MIB
    assert gui.normal_log_warning(state) == "near-limit"
    state["targets"][0]["checked_size_bytes"] += 123
    assert gui.normal_log_warning(state) == "near-limit"
    state["targets"][0]["reason"] = "file-limit"
    assert gui.normal_log_warning(state) == "file-limit"
    state["targets"][1]["reason"] = "io-uncertain"
    assert gui.normal_log_warning(state) == "io-uncertain"
    state["paused"] = True
    assert gui.normal_log_warning(state) == ""


def test_display_distinguishes_policy_from_file_checks_and_lower_bound_counts():
    state = _snapshot(suppression_counts_lower_bound=True)
    state["targets"][0].update(reason="resume-check-required", suppressed_blocks=4)
    state["targets"][1].update(reason="io-uncertain")
    text = gui.normal_log_usage(state)
    assert "next opened-file check" in text
    assert "uncertain; held for this process" in text
    assert "at least 4" in text
    assert "file size can change" in text
    assert "Existing logs are preserved" in text
    assert gui.normal_log_usage(None).startswith("Normal log status unavailable")


def _click(dialog, text):
    next(button for button in dialog.buttons() if text in button.text()).click()
    QApplication.processEvents()


def test_warning_is_nonmodal_cached_only_and_shown_once_per_category(inert):
    config, state, calls, parent = inert
    opened = []
    controller = gui.NormalLogWarningController(config, parent, opened.append)
    state["targets"][0]["reason"] = "file-limit"
    controller.poll()
    dialog = controller._warning
    assert dialog is not None and not dialog.isModal()
    assert not calls
    controller.poll()
    assert controller._warning is dialog
    _click(dialog, "Keep current")
    controller.poll()
    assert controller._warning is None
    assert not calls and not opened
    assert not config.settings_path.exists()
    controller.close()


def test_inbox_normal_log_warning_rechecks_policy_and_opens_only_on_review(inert):
    config, state, calls, parent = inert
    opened = []
    inbox = Mock()
    owner = gui.NormalLogWarningController(config, parent, opened.append, notifications=inbox)
    try:
        state.update(configured_at="first")
        state["targets"][0].update(reason="file-limit")
        owner.poll()
        old_review = inbox.upsert.call_args.args[3]
        assert owner._warning is None and not calls
        state["configured_at"] = "second"
        old_review()
        assert owner._warning is None and not calls
        review = inbox.upsert.call_args.args[3]
        review()
        dialog = owner._warning
        assert dialog is not None and not dialog.isModal()
        review()
        assert owner._warning is dialog
        state["configured_at"] = "third"
        _click(dialog, "Block")
        assert owner._warning is None and not calls
        inbox.upsert.call_args.args[3]()
        _click(owner._warning, "Block")
        assert len(calls) == 1 and calls[0]["paused"] is True
        assert config.normal_log_paused is False and not opened
        inbox.remove.assert_called_with("storage:normal-logs")
    finally:
        owner.close()


def test_warning_block_does_not_persist_and_busy_result_opens_settings(inert, monkeypatch):
    config, state, calls, parent = inert
    opened = []
    controller = gui.NormalLogWarningController(config, parent, opened.append)
    state["targets"][0]["reason"] = "process-limit"
    controller.poll()
    _click(controller._warning, "Block")
    assert calls[-1]["paused"] is True
    assert config.normal_log_paused is False and not config.settings_path.exists()
    state["targets"][0]["reason"] = "io-uncertain"
    monkeypatch.setattr(gui, "configure_normal_log_budget", lambda **_policy: {"accepted": False, "reason": "writer-busy"})
    controller.poll()
    _click(controller._warning, "Block")
    assert opened == ["General"]
    controls = gui.NormalLogControls(config, parent)
    assert "not applied" in controls.result.text()
    controller.close()


def test_change_and_close_do_not_mutate_writer_policy(inert):
    config, state, calls, parent = inert
    opened = []
    controller = gui.NormalLogWarningController(config, parent, opened.append)
    state["targets"][0]["reason"] = "file-limit"
    controller.poll()
    _click(controller._warning, "change limits")
    assert opened == ["General"] and not calls
    state["targets"][0]["reason"] = "io-uncertain"
    controller.poll()
    controller.close()
    QApplication.processEvents()
    assert not controller._timer.isActive()
    assert controller._warning is None
    assert not calls and config.normal_log_paused is False


def test_widget_refresh_only_uses_cached_getter(inert, monkeypatch):
    config, state, _, parent = inert
    observed = []
    monkeypatch.setattr(gui, "normal_write_snapshot", lambda: observed.append("cached") or state)
    controls = gui.NormalLogControls(config, parent)
    observed.clear()
    controls.refresh()
    assert observed == ["cached"]


def test_apply_policy_passes_exact_settings_without_coercion(monkeypatch):
    calls = []
    monkeypatch.setattr(gui, "configure_normal_log_budget", lambda **policy: calls.append(policy) or {"accepted": True})
    gui.apply_normal_log_policy(SimpleNamespace(normal_log_max_mib=4, normal_log_message_kib=16,
                                               normal_log_paused=True))
    assert calls == [{"limit_mib": 4, "message_kib": 16, "paused": True}]


@pytest.mark.parametrize("failure", ["writer-busy", "exception"])
def test_refused_startup_policy_is_visible_below_capacity_and_retried_only_on_click(inert, monkeypatch, failure):
    from angerona.app import _apply_startup_normal_log_policy
    from angerona.core import crashlog
    config, _, _, parent = inert
    config.normal_log_paused = True
    config.normal_log_max_mib = 1
    attempts = []

    def refuse(**policy):
        attempts.append(policy)
        if failure == "exception":
            raise RuntimeError("private startup detail")
        return {"accepted": False, "reason": "writer-busy"}

    monkeypatch.setattr(crashlog, "configure_normal_log_budget", refuse)
    result = _apply_startup_normal_log_policy(config)
    assert result["accepted"] is False and len(attempts) == 1
    assert config._normal_log_policy_pending is True
    assert "not applied at startup" in config._normal_log_apply_note
    assert "private startup detail" not in config._normal_log_apply_note
    opened = []
    controller = gui.NormalLogWarningController(config, parent, opened.append)
    controller.poll()
    dialog = controller._warning
    assert dialog is not None and not dialog.isModal()
    assert "may not be active" in dialog.text() and "8 MiB" in dialog.text()
    controller.poll()
    assert len(attempts) == 1  # Cached warning never retries the writer itself.
    gui_attempts = []
    monkeypatch.setattr(gui, "configure_normal_log_budget",
                        lambda **policy: gui_attempts.append(policy) or {"accepted": True})
    _click(dialog, "Retry saved")
    assert gui_attempts == [{"limit_mib": 1, "message_kib": 64, "paused": True}]
    assert config._normal_log_policy_pending is False and config._normal_log_apply_note == ""
    controller.poll()
    assert controller._warning is None and len(gui_attempts) == 1 and not opened
    controller.close()


def test_startup_success_clears_previous_pending_note(inert, monkeypatch):
    from angerona.app import _apply_startup_normal_log_policy
    from angerona.core import crashlog
    config, _, _, _ = inert
    config._normal_log_apply_note = "old busy note"
    config._normal_log_policy_pending = True
    monkeypatch.setattr(crashlog, "configure_normal_log_budget", lambda **_policy: {"accepted": True})
    assert _apply_startup_normal_log_policy(config)["accepted"] is True
    assert config._normal_log_policy_pending is False and config._normal_log_apply_note == ""


def test_successful_save_policy_clears_busy_note_when_settings_reopened(inert):
    config, _, _, parent = inert
    config._normal_log_apply_note = "old busy note"
    config._normal_log_policy_pending = True
    assert gui.apply_normal_log_policy(config)["accepted"] is True
    reopened = gui.NormalLogControls(config, parent)
    assert reopened.result.text() == ""
    assert config._normal_log_policy_pending is False


def test_successful_warning_block_clears_note_on_actual_config_owner(inert):
    config, _, calls, parent = inert
    config._normal_log_apply_note = "old busy note"
    config._normal_log_policy_pending = True
    controller = gui.NormalLogWarningController(config, parent, lambda _tab: pytest.fail("unexpected settings request"))
    controller.poll()
    _click(controller._warning, "Block")
    assert calls[-1]["paused"] is True
    assert config.normal_log_paused is False  # This-run choice does not change saved preference.
    assert config._normal_log_policy_pending is False and config._normal_log_apply_note == ""
    reopened = gui.NormalLogControls(config, parent)
    assert reopened.result.text() == ""
    controller.close()


def test_busy_explicit_retry_opens_settings_with_current_failure_note(inert, monkeypatch):
    config, _, _, parent = inert
    config._normal_log_policy_pending = True
    monkeypatch.setattr(gui, "configure_normal_log_budget", lambda **_policy: {"accepted": False, "reason": "writer-busy"})
    opened = []
    controller = gui.NormalLogWarningController(config, parent, opened.append)
    controller.poll()
    _click(controller._warning, "Retry saved")
    assert opened == ["General"] and config._normal_log_policy_pending is True
    reopened = gui.NormalLogControls(config, parent)
    assert "not applied" in reopened.result.text()
    controller.poll()
    assert controller._warning is None  # No automatic retry or popup loop.
    controller.close()
