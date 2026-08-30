from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt, Signal
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMainWindow, QPlainTextEdit

from angerona.gui.live_defense_activity import LiveDefenseActivityCard
from angerona.gui.red_team_console import RedTeamConsole
from angerona.modules.purple_guard import (
    PurpleGuard,
    REDTEAM_COMPREHENSIVE_VALIDATION_TECHNIQUES,
    classify_marker,
    ensure_redteam_validation_pack,
)
from angerona.shark.red_team import RedTeamEngine
from angerona.shark.run_manifest import (
    RED_TEAM_COMPREHENSIVE_PLAN,
    build_run_history,
    expected_red_team_plan,
    preflight_run,
)


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_comprehensive_plan_is_bounded_exact_and_honestly_scored(tmp_path: Path) -> None:
    contract = preflight_run(
        kind="red_team",
        cycles=1,
        jitter_range=(0, 0),
        noise_chance=0,
        target_dir=tmp_path / "target",
        campaign=True,
        comprehensive=True,
    )
    assert contract.accepted
    assert contract.budget["mandatory_steps"] == 38
    assert contract.budget["detection_contract_steps"] == 37
    plan = expected_red_team_plan(contract.as_dict())
    assert len(plan) == 38
    assert sum(row["category"] == "detection" for row in plan) == 37
    assert sum(row["category"] == "unmonitored" for row in plan) == 1
    assert len({attack_id for row in plan for attack_id in row["attack_ids"]}) >= 37
    assert {
        "credential-access", "discovery", "persistence", "execution",
        "lateral-movement", "command-and-control", "exfiltration",
        "defense-evasion",
    }.issubset({str(row.get("tactic")) for row in plan})

    steps = [
        {
            **row,
            "description": "fixed inert test marker",
            "ts_start": float(index + 1),
            "ts_end": float(index + 1.1),
            "artifact_paths": [],
            "pids": [],
            "correlation_tokens": [],
            "detail": "",
            "ok": True,
        }
        for index, row in enumerate(plan)
    ]
    history = build_run_history(
        kind="red_team",
        run_id="comprehensive-contract-test",
        generated="test",
        steps=steps,
        preflight=contract,
        status="completed",
    )
    assert history["campaign"]["complete"] is True
    assert history["campaign"]["expected_detection_contracts"] == 37
    assert history["status"] == "completed"


def test_comprehensive_markers_are_fixed_local_inert_and_cleanup_owned(tmp_path: Path) -> None:
    target = tmp_path / "markers"
    engine = RedTeamEngine(tmp_path / "data", documents_dir=target)
    engine.run_id = "comprehensive-inertness"
    for row in RED_TEAM_COMPREHENSIVE_PLAN:
        engine._active_plan_entry = {**row, "cycle": 1, "plan_step_id": "test"}
        getattr(engine, f"_step_{row['key']}")((0.0, 0.0))
    engine._active_plan_entry = None

    assert len(engine.steps) == len(RED_TEAM_COMPREHENSIVE_PLAN) == 24
    assert not engine._probe_processes
    markers = [Path(step.artifact_paths[0]) for step in engine.steps]
    assert all(path.parent == target.resolve(strict=False) for path in markers)
    assert all(path.name.startswith("_redteam_") and path.suffix == ".txt" for path in markers)
    assert all("No named ATT&CK behavior was executed." in path.read_text(encoding="utf-8") for path in markers)

    engine.stop_and_clean()
    assert all(not path.exists() for path in markers)


def test_comprehensive_purple_pack_matches_every_fixed_marker(tmp_path: Path) -> None:
    activated = ensure_redteam_validation_pack(tmp_path, comprehensive=True)
    assert set(activated["active"]) == REDTEAM_COMPREHENSIVE_VALIDATION_TECHNIQUES
    assert len(activated["active"]) == 37
    for row in RED_TEAM_COMPREHENSIVE_PLAN:
        marker = Path(f"_redteam_{row['marker_token']}_deadbeef.txt")
        assert classify_marker(marker) == (
            row["attack_ids"][0],
            next(
                label
                for token, technique, label in __import__(
                    "angerona.modules.purple_guard", fromlist=["_PATTERNS"]
                )._PATTERNS
                if token == row["marker_token"] and technique == row["attack_ids"][0]
            ),
        )


def test_exact_process_receipt_wakes_idle_purple_guard_immediately(
    tmp_path: Path, monkeypatch,
) -> None:
    class _WakeBus:
        callback = None

        def subscribe(self, callback, **_kwargs) -> None:
            self.callback = callback

    bus = _WakeBus()
    guard = PurpleGuard(tmp_path)
    guard.bind(bus)
    first_cycle = threading.Event()
    second_cycle = threading.Event()
    cycles = 0

    def work_cycle() -> tuple[int, int, int]:
        nonlocal cycles
        cycles += 1
        if cycles == 1:
            first_cycle.set()
        else:
            second_cycle.set()
            guard.stop()
        return 0, 0, 0

    monkeypatch.setattr(guard, "work_cycle", work_cycle)
    monkeypatch.setattr(guard, "_update_policy_health", lambda _count: None)
    try:
        guard.start()
        assert first_cycle.wait(1.0)
        assert callable(bus.callback)
        bus.callback(SimpleNamespace(details={
            "event_type": "process_creation",
            "cmdline": "python -c pass ANGERONA_REDTEAM_deadbeef",
        }))
        assert not second_cycle.wait(0.1)
        started = time.monotonic()
        bus.callback(SimpleNamespace(
            module="Process Monitor",
            details={
                "event_type": "process_creation",
                "cmdline": "python -c pass ANGERONA_REDTEAM_deadbeef",
                "redteam_detector_receipt_version": 3,
                "receipt_type": "native_process_observation",
                "producer_module": "Process Monitor",
                "producer_capability_id": "angerona.builtin.process_monitor",
                "producer_trust_boundary": "same-process-simulation-validation",
                "lease_id": "lease",
                "receipt_id": "receipt",
                "detector_receipt_mac": "00" * 64,
            },
        ))
        assert second_cycle.wait(1.0)
        assert time.monotonic() - started < 1.0
    finally:
        guard.stop()
        thread = guard._thread
        if thread is not None:
            thread.join(1.0)
        assert thread is None or not thread.is_alive()


class _Parent(QMainWindow):
    _shark_narration = Signal(str)

    def __init__(self, marker: Path) -> None:
        super().__init__()
        self.red_team_engine = SimpleNamespace(steps=[SimpleNamespace(
            stage="Credential Store (simulated)",
            technique="T1555 marker",
            ok=True,
            artifact_paths=[str(marker)],
            pids=[],
        )])
        self.shark_engine = SimpleNamespace(steps=[])

    def _qss(self) -> str:
        return ""


def test_console_defaults_to_comprehensive_and_each_stage_clicks_exact_evidence(
    tmp_path: Path,
) -> None:
    app = _app()
    marker = tmp_path / "_redteam_credential_store_probe_12345678.txt"
    parent = _Parent(marker)
    dialog = RedTeamConsole(parent, default_target=str(tmp_path))
    dialog.show()
    try:
        assert dialog.cb_shark.isChecked()
        assert dialog.cb_apt.isChecked()
        assert dialog.cb_comprehensive.isChecked()
        assert len(dialog._chips) >= 40
        text = dialog._stage_detail_text("credential_store")
        assert "T1555 marker" in text
        assert str(marker) in text
        assert "red_team.py:" in text

        chip = dialog._chips["credential_store"]
        QTest.mouseClick(chip, Qt.MouseButton.LeftButton)
        app.processEvents()
        assert dialog._stage_detail_dialog.isVisible()
        evidence = dialog._stage_detail_dialog.findChild(
            QPlainTextEdit, "RedTeamStageEvidence"
        )
        assert evidence is not None and str(marker) in evidence.toPlainText()
    finally:
        if hasattr(dialog, "_stage_detail_dialog"):
            dialog._stage_detail_dialog.close()
        dialog.close(); parent.close()


class _Bus:
    def __init__(self, event: object) -> None:
        self.event = event

    def revision(self) -> int:
        return 1

    def recent(self, _limit: int) -> list[object]:
        return [self.event]


def test_live_activity_row_emits_only_the_exact_clicked_event() -> None:
    _app()
    event = SimpleNamespace(module="FIM", message="marker changed", severity=2, ts=1.0)
    card = LiveDefenseActivityCard(_Bus(event), SimpleNamespace(modules={}))
    exact: list[object] = []
    generic: list[bool] = []
    card.event_details_requested.connect(exact.append)
    card.details_requested.connect(lambda: generic.append(True))
    card.show()

    QTest.mouseClick(card.rows[0], Qt.MouseButton.LeftButton)
    assert exact == [event]
    assert generic == []

    QTest.mouseClick(card, Qt.MouseButton.LeftButton)
    assert generic == [True]
