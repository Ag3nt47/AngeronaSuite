"""Response warnings permit inert drills without granting mutation authority."""
from __future__ import annotations

import os
from types import MethodType, SimpleNamespace
from unittest.mock import Mock

import pytest

from angerona.gui import main_window
from angerona.gui.main_window import MainWindow


_POLICY_KEYS = (
    "ANGERONA_SOAR_KILL_AND_ROLLBACK",
    "ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY",
    "ANGERONA_SOAR_RESPONSE_SCOPE",
)


@pytest.fixture
def launch(tmp_path, monkeypatch):
    engines = []
    for kind in ("shark", "red_team"):
        engine = SimpleNamespace(
            is_running=False, run_id=f"{kind}-fixture", default_documents_dir=tmp_path / "markers",
            start=Mock(return_value=True), stop_and_clean=Mock(),
            hold_evidence_for_aar=Mock(), cancel_evidence_hold=Mock(),
        )
        engines.append(engine)
    lines = []
    window = SimpleNamespace(
        shark_engine=engines[0], red_team_engine=engines[1],
        manager=SimpleNamespace(modules={}), config=SimpleNamespace(data_dir=tmp_path),
        storage=object(), bus=object(), _eco_on=False,
        console=SimpleNamespace(_append=lines.append),
        shark_monitor=Mock(), shark_swim=Mock(), shark_banner=Mock(),
        _sim_check_done=Mock(),
    )
    for name in (
        "_simulation_launch_status", "_check_simulation_response", "_run_simulation",
        "_abort_simulation_launch", "_release_redteam_validation_lease",
        "_restore_simulation_response_policy",
    ):
        setattr(window, name, MethodType(getattr(MainWindow, name), window))
    monkeypatch.setattr(main_window, "QTimer", lambda *_: Mock())
    monkeypatch.setattr(main_window.QMessageBox, "warning", Mock())
    monkeypatch.setattr(main_window.QMessageBox, "question", Mock(
        side_effect=AssertionError("a readiness warning must not request confirmation")))
    reconcile = Mock()
    monkeypatch.setattr(main_window, "reconcile_module_usage", reconcile)
    for module_name in ("file_integrity", "yara_scanner"):
        monkeypatch.setattr(f"angerona.modules.{module_name}.register_runtime_watch", Mock(return_value=True))
        monkeypatch.setattr(f"angerona.modules.{module_name}.unregister_runtime_watch", Mock())
    preflight = Mock(return_value=SimpleNamespace(accepted=True))
    monkeypatch.setattr("angerona.shark.run_manifest.preflight_run", preflight)
    lease = SimpleNamespace(readiness={"policy_count": 37, "sensor_health": 100}, release=Mock())
    acquire = Mock(return_value=lease)
    monkeypatch.setattr("angerona.modules.purple_guard.acquire_redteam_validation_lease", acquire)
    readiness = {"ready": False, "state": "RECOVERY REQUIRED", "reason": "journal hold"}
    monkeypatch.setattr(
        "angerona.core.drill_readiness.assess_drill_response",
        lambda *_args, **_kwargs: dict(readiness),
    )
    cfg = {"run_shark": True, "run_redteam": True, "auto_remediate": True,
           "intensity": "Extreme", "complexity": 4, "campaign": True,
           "comprehensive": True, "target_dir": str(tmp_path / "selected"),
           "custom": {"name": "inert", "payload": "literal marker text"}}
    return SimpleNamespace(window=window, cfg=cfg, readiness=readiness,
                           acquire=acquire, lease=lease, reconcile=reconcile,
                           preflight=preflight, lines=lines)


@pytest.mark.parametrize("prior", [None, "0", "1"])
def test_recovery_hold_launches_all_selected_profiles_without_policy_escalation(
    launch, monkeypatch, prior,
):
    for key, value in zip(_POLICY_KEYS, (prior, "HIGH", "original scope")):
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    before = {key: os.environ.get(key) for key in _POLICY_KEYS}
    result = launch.window._run_simulation(dict(launch.cfg))
    assert result["status"] == "accepted"
    assert "RECOVERY REQUIRED" in result["response_warning"]
    assert "journal hold" in result["response_warning"]
    assert launch.window._sim_auto_remediate  # Requested containment scoring remains.
    assert not launch.window._sim_response_escalated
    assert {key: os.environ.get(key) for key in _POLICY_KEYS} == before
    launch.reconcile.assert_not_called()
    launch.acquire.assert_called_once()
    launch.window.red_team_engine.start.assert_called_once_with(
        intensity="Extreme", campaign=True, comprehensive=True,
        target_dir=launch.cfg["target_dir"], custom=launch.cfg["custom"],
        validation_lease=launch.lease,
    )
    launch.window.shark_engine.start.assert_called_once_with(
        complexity=4, target_dir=launch.cfg["target_dir"], custom=launch.cfg["custom"],
    )
    assert launch.window._sim_aar_pending == 2
    launch.window._restore_simulation_response_policy()
    assert {key: os.environ.get(key) for key in _POLICY_KEYS} == before
    launch.reconcile.assert_not_called()


def test_readiness_warning_does_not_bypass_validation_lease_refusal(launch, monkeypatch):
    monkeypatch.setenv(_POLICY_KEYS[0], "0")
    launch.acquire.side_effect = RuntimeError("authenticated recorder unavailable")
    result = launch.window._run_simulation(launch.cfg)
    assert result["status"] == "rejected"
    assert "authenticated recorder unavailable" in result["reason"]
    launch.window.red_team_engine.start.assert_not_called()
    launch.window.shark_engine.start.assert_not_called()
    assert launch.window._sim_aar_pending == 0
    assert os.environ[_POLICY_KEYS[0]] == "0"
    launch.reconcile.assert_not_called()


def test_readiness_warning_does_not_bypass_engine_safety_refusal(launch):
    launch.window.red_team_engine.start.return_value = False
    result = launch.window._run_simulation(launch.cfg)
    assert result["status"] == "rejected"
    assert "safety preflight rejected" in result["reason"]
    launch.window.shark_engine.start.assert_not_called()
    launch.lease.release.assert_called_once()
    assert launch.window._sim_aar_pending == 0


def test_readiness_warning_does_not_bypass_target_safety_preflight(launch):
    launch.preflight.return_value = SimpleNamespace(accepted=False, violations=["unsafe target"])
    result = launch.window._run_simulation(launch.cfg)
    assert result["status"] == "rejected"
    assert "unsafe target" in result["reason"]
    launch.acquire.assert_not_called()
    launch.window.red_team_engine.start.assert_not_called()
    launch.window.shark_engine.start.assert_not_called()


def test_legacy_launcher_warns_without_escalating_response(launch, monkeypatch):
    monkeypatch.setattr(main_window.QMessageBox, "question", lambda *_args: main_window.QMessageBox.Yes)
    monkeypatch.setenv(_POLICY_KEYS[0], "0")
    launch.window._red_team_check_done = Mock()
    MainWindow._start_red_team(launch.window)
    assert launch.window._legacy_redteam_active
    assert launch.window._redteam_report_pending
    assert "RECOVERY REQUIRED" in launch.window._sim_response_warning
    assert not launch.window._sim_response_escalated
    assert launch.window._sim_auto_remediate
    assert os.environ[_POLICY_KEYS[0]] == "0"
    launch.reconcile.assert_not_called()
    launch.window.red_team_engine.start.assert_called_once_with(
        target_dir=str(launch.window.red_team_engine.default_documents_dir),
        validation_lease=launch.lease,
    )


def test_ready_launch_keeps_scoped_response_and_restores_original_policy(launch, monkeypatch):
    launch.readiness.update(ready=True, state="ARMED", reason="ready")
    originals = ("0", "CRITICAL", "prior scope")
    for key, value in zip(_POLICY_KEYS, originals):
        monkeypatch.setenv(key, value)
    result = launch.window._run_simulation(launch.cfg)
    assert result["status"] == "accepted"
    assert result["response_warning"] == ""
    assert launch.window._sim_response_escalated
    assert os.environ[_POLICY_KEYS[0]] == "1"
    assert os.environ[_POLICY_KEYS[1]] == "MEDIUM"
    assert launch.cfg["target_dir"] in os.environ[_POLICY_KEYS[2]]
    launch.window._restore_simulation_response_policy()
    assert tuple(os.environ[key] for key in _POLICY_KEYS) == originals
