from __future__ import annotations

import json
import os
import threading
from types import MethodType, SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Signal
from PySide6.QtWidgets import QApplication, QMainWindow

from angerona.gui.main_window import MainWindow
from angerona.gui.red_team_console import RedTeamConsole


class _Parent(QMainWindow):
    _shark_narration = Signal(str)

    def _qss(self):
        return ""


@pytest.fixture
def console(tmp_path):
    app = QApplication.instance() or QApplication([])
    parent = _Parent()
    dialog = RedTeamConsole(parent, default_target=str(tmp_path))
    yield dialog, parent
    dialog.close()
    parent.close()
    dialog.deleteLater()
    parent.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


def _accepted(dialog, *, both=False, containment=True):
    runs = {"red_team": "redteam-current"}
    if both:
        runs["shark"] = "shark-current"
    dialog.set_launch_status(
        {"status": "accepted", "runs": runs},
        {"auto_remediate": containment},
    )


def _result(count=1, eligible=1, outcome="verified"):
    return {"outcome": outcome, "epistemic_metrics": {
        "verified_containment": {"count": count, "eligible": eligible,
                                 "rate": count / eligible if eligible else None},
    }}


@pytest.mark.parametrize("status", ["rejected", "queued"])
def test_unaccepted_launch_has_no_estimated_success_spinner(console, status):
    dialog, parent = console
    parent._run_simulation = lambda cfg: {"status": status, "reason": "Recovery required"}
    dialog._launch()
    assert "Recovery required" in dialog.live_status.text()
    assert dialog.run_spinner.isHidden()
    assert not dialog.run_spinner._est_timer.isActive()
    assert not dialog.run_spinner._done_timer.isActive()


def test_engine_completion_waits_for_authenticated_report(console):
    dialog, _ = console
    _accepted(dialog)
    dialog.finish_run()
    assert "awaiting authenticated response evidence" in dialog.live_status.text()
    assert dialog.run_spinner._pct == 0
    assert not dialog.run_spinner._done_timer.isActive()
    assert not dialog.launch_btn.isEnabled()


def test_combined_run_requires_both_matching_report_ids(console):
    dialog, _ = console
    _accepted(dialog, both=True)
    dialog.finish_run()
    dialog.record_verified_report("red_team", "old-run", _result())
    assert dialog._report_results == {}
    dialog.record_verified_report("red_team", "redteam-current", _result())
    assert "shark" in dialog.live_status.text()
    assert dialog.run_spinner._pct == 0
    dialog.record_verified_report("shark", "shark-current", _result(1, 2, "partial"))
    assert "Containment partial" in dialog.live_status.text()
    assert "2/3 verified; 1 remain unverified" in dialog.live_status.text()
    assert not dialog.run_spinner._done_timer.isActive()


@pytest.mark.parametrize("count,eligible,outcome,expected", [
    (1, 1, "verified", "Verified containment"),
    (0, 1, "failed", "Containment failed"),
    (0, 1, "inconclusive", "Containment inconclusive"),
    (0, 1, "verified", "Containment inconclusive"),
    (1, 1, "partial", "Containment inconclusive"),
    (1, 1, "failed", "Containment inconclusive"),
])
def test_only_complete_verified_containment_is_success(
    console, count, eligible, outcome, expected,
):
    dialog, _ = console
    _accepted(dialog)
    dialog.record_verified_report("red_team", "redteam-current", _result(count, eligible, outcome))
    assert expected in dialog.live_status.text()
    assert dialog.run_spinner._done_timer.isActive() == (expected == "Verified containment")


def test_report_error_cannot_turn_green(console):
    dialog, _ = console
    _accepted(dialog)
    dialog.record_verified_report("red_team", "redteam-current", None, error="signed evidence missing")
    assert "Containment inconclusive" in dialog.live_status.text()
    assert "signed evidence missing" in dialog.live_status.text()
    assert not dialog.run_spinner._done_timer.isActive()


def test_detection_only_has_no_containment_pass(console):
    dialog, _ = console
    _accepted(dialog, containment=False)
    dialog.record_verified_report("red_team", "redteam-current", _result())
    assert "Detection-only result" in dialog.live_status.text()
    assert "no containment pass assigned" in dialog.live_status.text()
    assert not dialog.run_spinner._done_timer.isActive()


def _launch_window():
    lines = []
    window = SimpleNamespace(
        shark_engine=SimpleNamespace(is_running=False),
        red_team_engine=SimpleNamespace(is_running=False),
        manager=SimpleNamespace(modules={}),
        _eco_on=False,
        console=SimpleNamespace(_append=lines.append),
    )
    for name in ("_simulation_launch_status", "_check_simulation_response", "_run_simulation"):
        setattr(window, name, MethodType(getattr(MainWindow, name), window))
    return window, lines


def test_response_gate_refuses_before_environment_or_engine_changes(monkeypatch):
    window, lines = _launch_window()
    monkeypatch.setattr(
        "angerona.core.drill_readiness.assess_drill_response",
        lambda *_args, **_kwargs: {"ready": False, "state": "RECOVERY REQUIRED",
                                  "reason": "journal hold", "checked_at": 0, "policy": {}},
    )
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "0")
    result = window._run_simulation({"run_redteam": True, "auto_remediate": True})
    assert result["status"] == "rejected"
    assert "journal hold" in result["reason"]
    assert "not necessarily armed" in result["reason"]
    assert os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] == "0"
    assert not hasattr(window, "_shark_prev_armed")
    assert "Containment test blocked" in lines[-1]


def test_detection_only_allows_readiness_hold_without_arming(monkeypatch):
    window, _ = _launch_window()
    monkeypatch.setattr(
        "angerona.core.drill_readiness.assess_drill_response",
        lambda *_args, **_kwargs: {"ready": False, "state": "DISABLED",
                                  "reason": "operator disabled", "checked_at": 0, "policy": {}},
    )
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "0")
    assert window._check_simulation_response({"auto_remediate": False})["status"] == "ready"
    assert os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] == "0"


def test_chill_queued_launch_checks_readiness_after_wake(monkeypatch):
    window, _ = _launch_window()
    window._eco_on = True
    window._chill_policy = SimpleNamespace(enabled=True, force_escalate=lambda *_: None)
    window._wake_chill_modules = lambda **_: True
    window._check_simulation_response = lambda _: pytest.fail("readiness checked before wake completed")
    result = window._run_simulation({"run_redteam": True, "auto_remediate": True})
    assert result["status"] == "queued"
    assert window._pending_simulation_cfg["auto_remediate"]
    assert not hasattr(window, "_shark_prev_armed")


def test_stop_cancels_pending_wake_launch(console):
    dialog, parent = console
    parent._pending_simulation_cfg = {"run_redteam": True}
    dialog._stop()
    assert parent._pending_simulation_cfg is None


def test_stop_keeps_late_completed_report_inconclusive(console):
    dialog, _ = console
    _accepted(dialog)
    dialog._stop()
    assert not dialog.launch_btn.isEnabled()
    dialog.record_verified_report("red_team", "redteam-current", _result())
    assert "run cancelled" in dialog.live_status.text()
    assert "cleanup does not prove response success" in dialog.live_status.text()
    assert not dialog.run_spinner._done_timer.isActive()
    assert dialog.launch_btn.isEnabled()


def test_busy_rejection_preserves_current_result_state(console):
    dialog, parent = console
    _accepted(dialog)
    parent._run_simulation = lambda cfg: pytest.fail("busy console launched again")
    dialog._launch()
    dialog.set_launch_status({"status": "rejected", "reason": "Another run is active"})
    assert dialog._run_pending
    assert not dialog.launch_btn.isEnabled()
    assert dialog._report_runs == {"red_team": "redteam-current"}
    assert "Containment test running" in dialog.live_status.text()


def test_dispatched_launch_result_is_not_rendered_twice(console):
    dialog, parent = console
    def launch(cfg):
        result = {"status": "accepted", "runs": {"red_team": "redteam-current"}}
        dialog.set_launch_status(result, cfg)
        result["dispatched"] = True
        return result
    parent._run_simulation = launch
    dialog._launch()
    assert dialog.log.toPlainText().count("Containment test running") == 1


def test_queued_wake_callback_honors_stop_before_delivery():
    cfg = {"run_redteam": True}
    launched = []
    window = SimpleNamespace(_pending_simulation_cfg=cfg, _run_simulation=launched.append)
    window._pending_simulation_cfg = None
    MainWindow._resume_pending_simulation(window, cfg)
    assert launched == []
    window._pending_simulation_cfg = cfg
    MainWindow._resume_pending_simulation(window, cfg)
    assert launched == [cfg]


def test_redteam_profile_requires_process_readiness(monkeypatch):
    window, _ = _launch_window()
    required = []
    def readiness(_manager, *, require_process=False):
        required.append(require_process)
        return {"ready": True, "state": "ARMED", "reason": "ready", "policy": {}}
    monkeypatch.setattr("angerona.core.drill_readiness.assess_drill_response", readiness)
    window._check_simulation_response({"run_redteam": True, "auto_remediate": True})
    assert required == [True]


@pytest.mark.parametrize("verified", [False, True])
def test_main_result_uses_only_verified_immutable_bytes(console, tmp_path, monkeypatch, verified):
    from angerona.shark.aar_report import AARReportResult

    dialog, _ = console
    _accepted(dialog)
    handoff = AARReportResult(
        text="test report", run_id="redteam-current", report_kind="red_team",
        report_basename="redteam_aar", report_sha256="a" * 64,
        head_sha256="b" * 64, sequence=1, text_bytes=b"test report",
        report_bytes=json.dumps(_result()).encode(), head_bytes=b"test head",
        journal_record_sha256="c" * 64, journal_record_bytes=b"test journal",
        report_directory=tmp_path,
    )
    seen = []
    def verify(exact):
        assert exact is handoff
        seen.append(exact)
        if not verified:
            raise ValueError("report authentication failed")
        return exact.text
    monkeypatch.setattr("angerona.shark.aar_report.verified_aar_handoff_text", verify)
    monkeypatch.setattr(
        "angerona.gui.main_window.AARDialog",
        lambda *_args, **_kwargs: SimpleNamespace(
            setStyleSheet=lambda *_: None, set_text=lambda *_: None,
            exec=lambda: None,
        ),
    )
    window = SimpleNamespace(
        manager=SimpleNamespace(modules={}), config=SimpleNamespace(data_dir=tmp_path),
        _rt_console=dialog, _qss=lambda: "",
    )
    MainWindow._show_aar_dialog(window, handoff)
    assert seen == [handoff]
    assert ("Verified containment" in dialog.live_status.text()) == verified
    if not verified:
        assert "report authentication failed" in dialog.live_status.text()


def test_last_report_keeps_launch_gated_during_policy_restoration(monkeypatch):
    seen = []
    window = SimpleNamespace(
        _sim_aar_lock=threading.Lock(), _sim_aar_pending=1,
        manager=SimpleNamespace(modules={}), _eco_on=False,
    )
    window._restore_simulation_response_policy = lambda: seen.append(window._sim_aar_pending)
    monkeypatch.setattr("angerona.modules.file_integrity.unregister_runtime_watch", lambda _: None)
    MainWindow._simulation_aar_finished(window)
    assert seen == [1]
    assert window._sim_aar_pending == 0
