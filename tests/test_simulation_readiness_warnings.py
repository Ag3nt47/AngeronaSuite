"""Response warnings preserve current policy across Session admission.

The Session adapter is deliberately inert. Backend/native cohorts separately
verify leases, target safety, detector execution and signed after-action proof.
"""
from __future__ import annotations

import os
from unittest.mock import Mock

import pytest

from angerona.gui import main_window
from angerona.gui.main_window import MainWindow
from simulation_gui_fixture import build_launch, drain, retire_launch


_POLICY_KEYS = ("ANGERONA_SOAR_KILL_AND_ROLLBACK",
    "ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "ANGERONA_SOAR_RESPONSE_SCOPE")


@pytest.fixture
def launch(tmp_path, monkeypatch):
    context = build_launch(tmp_path, monkeypatch, ready=False)
    monkeypatch.setattr(main_window.QMessageBox, "question", Mock(
        side_effect=AssertionError("A readiness warning must not ask to expand authority")))
    context.cfg.update(target_dir=str(tmp_path / "selected"),
                       custom={"name": "inert", "payload": "literal marker text"})
    yield context
    retire_launch(context)


def _run(context, cfg):
    assert context.owner._run_simulation(cfg)["status"] == "preparing"
    job = context.owner._sim_launch_job
    drain(lambda: context.owner._sim_launch_job is None)
    job.thread.join(2)
    assert not job.thread.is_alive()
    return context.owner.statuses[-1]


@pytest.mark.parametrize("prior", [None, "0", "1"])
def test_recovery_warning_keeps_all_profiles_and_never_escalates_policy(launch, monkeypatch, prior):
    for key, value in zip(_POLICY_KEYS, (prior, "HIGH", "original scope")):
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    before = {key: os.environ.get(key) for key in _POLICY_KEYS}
    result = _run(launch, dict(launch.cfg))
    assert result["status"] == "accepted"
    assert "RECOVERY REQUIRED" in result["response_warning"]
    assert "journal hold" in result["response_warning"]
    assert launch.owner._sim_auto_remediate
    assert not launch.owner._sim_response_escalated
    assert {key: os.environ.get(key) for key in _POLICY_KEYS} == before
    assert launch.sessions[0].cfg == launch.cfg
    assert {run.kind for run in launch.owner._simulation_plan.runs} == {"red_team", "shark"}
    assert launch.owner._sim_aar_pending == 1
    launch.owner._restore_simulation_response_policy()
    assert {key: os.environ.get(key) for key in _POLICY_KEYS} == before
    launch.reconcile.assert_not_called()


def test_warning_does_not_bypass_exact_session_preparation_refusal(launch, monkeypatch):
    monkeypatch.setenv(_POLICY_KEYS[0], "0")
    launch.prepare_error = RuntimeError("inert authenticated recorder unavailable")
    result = _run(launch, launch.cfg)
    assert result["status"] == "rejected"
    assert "authenticated recorder unavailable" in result["reason"]
    assert not launch.started.is_set()
    assert launch.owner._sim_aar_pending == 0
    assert os.environ[_POLICY_KEYS[0]] == "0"
    launch.reconcile.assert_not_called()


def test_warning_does_not_bypass_exact_session_start_refusal(launch):
    launch.refuse_start = True
    result = _run(launch, launch.cfg)
    assert result["status"] == "rejected"
    assert not launch.started.is_set()
    assert launch.owner._sim_aar_pending == 0
    assert launch.sessions[0].cancelled.is_set()


def test_warning_does_not_replace_a_refused_target_plan(launch):
    launch.prepare_error = ValueError("Simulation preflight refused: unsafe target")
    result = _run(launch, launch.cfg)
    assert result["status"] == "rejected" and "unsafe target" in result["reason"]
    assert not launch.started.is_set()
    assert not launch.start_threads
    launch.owner.red_team_engine.start.assert_not_called()
    launch.owner.shark_engine.start.assert_not_called()


def test_legacy_launcher_uses_session_warning_without_escalating_response(launch, monkeypatch):
    monkeypatch.setattr(main_window.QMessageBox, "question", lambda *_args: main_window.QMessageBox.Yes)
    monkeypatch.setenv(_POLICY_KEYS[0], "0")
    MainWindow._start_red_team(launch.owner)
    job = launch.owner._sim_launch_job
    drain(lambda: launch.owner._sim_launch_job is None)
    job.thread.join(2)
    assert not job.thread.is_alive()
    assert launch.owner.statuses[-1]["status"] == "accepted"
    assert {run.kind for run in launch.owner._simulation_plan.runs} == {"red_team"}
    assert "RECOVERY REQUIRED" in launch.owner._sim_response_warning
    assert not launch.owner._sim_response_escalated
    assert launch.owner._sim_auto_remediate
    assert os.environ[_POLICY_KEYS[0]] == "0"
    launch.reconcile.assert_not_called()


def test_ready_launch_keeps_current_policy_instead_of_temporary_global_arming(launch, monkeypatch):
    launch.readiness.update(ready=True, state="ARMED", reason="ready")
    originals = ("0", "CRITICAL", "prior scope")
    for key, value in zip(_POLICY_KEYS, originals):
        monkeypatch.setenv(key, value)
    result = _run(launch, launch.cfg)
    assert result["status"] == "accepted" and result["response_warning"] == ""
    assert not launch.owner._sim_response_escalated
    assert tuple(os.environ[key] for key in _POLICY_KEYS) == originals
    launch.owner._restore_simulation_response_policy()
    assert tuple(os.environ[key] for key in _POLICY_KEYS) == originals
    launch.reconcile.assert_not_called()
