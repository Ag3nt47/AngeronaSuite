"""Public demo uses fixed evidence and never obtains host adaptation authority."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _demo_tool():
    path = Path(__file__).resolve().parents[1] / "tools" / "create_public_demo.py"
    spec = importlib.util.spec_from_file_location("angerona_public_demo_fixture_review", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_auto_adapt_publication_is_fixed_copy_only_and_explicitly_unverified():
    tool = _demo_tool()
    first, second = tool._adaptation_demo_payload(), tool._adaptation_demo_payload()
    assert first == second and first is not second
    assert first["synthetic"] is True and first["host_actions"] is False
    assert first["authority"] == "held"
    assert len(first["effects"]) == 3
    assert all(row["before"]["outbound"] == "Allow" and row["after"]["outbound"] == "Block"
               and "DEMO" in row["reason"] and "no native postcondition" in row["verification"]
               for row in first["effects"])
    first["effects"][0]["after"]["outbound"] = "modified fixture"
    first["transactions"][0]["status"] = "modified fixture"
    assert tool._adaptation_demo_payload() == second
    assert all("DEMO" in row["transaction_id"] and "no host mutation" in row["status"]
               for row in second["transactions"])
    assert all("verified_effects" not in row and "receipt_digest" not in row for row in second["transactions"])
    assert "not restorable" in second["snapshots"][0]["status"]
    assert json.loads(json.dumps(second)) == second


def test_auto_adapt_chapter_extends_all_existing_bounded_demo_slots():
    tool = _demo_tool()
    assert (tool.CHAPTERS, tool.FRAMES_PER_CHAPTER, tool.FRAME_COUNT) == (14, 10, 140)
    assert tool.FRAME_COUNT * tool.FRAME_DURATION_MS == 70_000
    assert tool.MAX_CAPTURE_BYTES == 96 * 1024 * 1024
    assert tool.MAX_GIF == 12 * 1024 * 1024
    assert set(tool.SCREENSHOTS) == {"github-tools-demo", "zero-breach-demo", "spyware-scan-demo",
        "breach-lockdown-demo", "after-action-demo", "github-tools-settings-demo",
        "github-tools-credits-demo", "auto-adapt-demo",
        "red-team-progress-demo", "red-team-passing-demo", "red-team-diagnostics-demo",
        "component-heartbeats-demo", "heartbeat-details-demo"}
    assert {"src/angerona/gui/adaptation_workbench.py", "src/angerona/core/host_adaptation.py",
        "src/angerona/gui/window_controls.py", "src/angerona/gui/recovery_panel.py",
        "src/angerona/gui/prevention_panel.py", "src/angerona/core/windows_prevention.py"} <= set(tool.CAPTURE_SOURCES)


def test_public_help_scene_uses_actual_modeless_owner_without_exec_shim(monkeypatch):
    from PySide6.QtWidgets import QApplication, QDialog, QMainWindow
    from angerona.gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])

    def forbidden(*_args, **_kwargs):
        pytest.fail("Help recording attempted a nested modal loop or tour")

    class Owner(QMainWindow):
        _open_help = MainWindow._open_help
        _start_tour = forbidden

    monkeypatch.setattr(QDialog, "exec", forbidden)
    owner = Owner()
    dialog = None
    try:
        dialog = _demo_tool()._help_fixture(owner)
        assert dialog.parent() is owner and not dialog.isModal()
        assert dialog.windowTitle() == "Angerona — Help & Info"
        assert QDialog.exec is forbidden
    finally:
        if dialog is not None:
            dialog.close()
        owner.close()
        app.processEvents()


def test_real_adaptation_demo_widget_has_no_native_service_worker_or_action_authority(monkeypatch):
    import socket
    import subprocess
    import threading

    from PySide6.QtWidgets import QApplication, QPushButton
    from angerona.core import data_paths, host_adaptation
    from angerona.gui import prevention_panel, recovery_panel
    from angerona.gui.adaptation_workbench import AdaptationWorkbench

    app = QApplication.instance() or QApplication([])
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append("effect attempted")
        raise AssertionError("public adaptation demo must not reach host/native/secret/worker effects")

    monkeypatch.setattr(host_adaptation.HostAdaptationService, "__init__", forbidden)
    monkeypatch.setattr(host_adaptation, "load_or_create_outbox_key", forbidden)
    monkeypatch.setattr(data_paths, "data_dir", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(threading.Thread, "start", forbidden)
    tool = _demo_tool()
    real_panel_types = recovery_panel.RecoveryPanel, prevention_panel.PreventionPanel
    dialog = tool._adaptation_fixture(forbidden)
    try:
        assert (recovery_panel.RecoveryPanel, prevention_panel.PreventionPanel) == real_panel_types
        assert isinstance(dialog.recovery_panel, real_panel_types[0])
        assert isinstance(dialog.prevention_panel, real_panel_types[1])
        assert isinstance(dialog, AdaptationWorkbench)
        assert not isinstance(dialog.service, host_adaptation.HostAdaptationService)
        assert calls == []
        assert dialog._task_thread is None and dialog._status_thread is None
        assert dialog.recovery_panel.manager is None
        assert dialog.prevention_panel._job is None and dialog.prevention_panel._client is None
        assert dialog.prevention_panel._inspect is forbidden
        assert all(not timer.isActive() for timer in (dialog._result_timer,
            dialog.recovery_panel._timer, dialog.prevention_panel._poll_timer))
        assert dialog._latest_review is None and not dialog._can_apply_review()
        assert dialog._latest_plan.plan_id == "DEMO-NOT-AN-APPROVED-PLAN"
        assert not dialog.apply_button.isEnabled()
        assert all(not button.isEnabled() for button in dialog.findChildren(QPushButton))
        assert dialog.change_table.rowCount() == 3
        assert dialog.transaction_table.rowCount() == 1 and dialog.snapshot_combo.count() == 1
        public_row = next(row for row in range(dialog.change_table.rowCount())
                          if dialog.change_table.item(row, 0).text() == "Public")
        dialog.change_table.selectRow(public_row)
        app.processEvents()
        assert dialog.prevention_panel._job is None
        assert not dialog.recovery_panel._timer.isActive()
        assert json.loads(dialog.change_details.toPlainText())["profile"] == "Public"
        first = dialog.service.transactions()
        first[0]["status"] = "modified outside service"
        assert dialog.service.transactions()[0]["status"] == "DEMO - no host mutation"
        assert calls == []
        for name in ("audit", "prepare_review", "apply_plan", "rollback", "capture_security_baseline",
                     "restore_security_baseline", "save_baseline", "export_report", "set_automation"):
            with pytest.raises(AssertionError):
                getattr(dialog.service, name)()
        assert len(calls) == 9
        with pytest.raises(AttributeError):
            getattr(dialog.service, "unknown_native_provider")
    finally:
        dialog.close()
        app.processEvents()
