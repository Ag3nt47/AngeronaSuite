"""Offscreen operator clickthrough with real Red Team detector/response workers."""

from __future__ import annotations

import os
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import psutil
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox


_OS_WITNESS = r"""
import hashlib
import json
import os
import sys
from pathlib import Path

import psutil

request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
quarantine = Path(request["quarantine_root"])
verify_digest = bool(request.get("verify_digest", True))
markers = []
for expected in request["markers"]:
    source = Path(expected["source"])
    candidates = []
    matches = []
    read_errors = []
    for candidate in quarantine.rglob(source.name):
        if candidate.is_file() and not candidate.is_symlink():
            candidates.append(str(candidate))
            if verify_digest:
                try:
                    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
                except OSError as exc:
                    read_errors.append({"path": str(candidate), "error": str(exc)})
                else:
                    if digest == expected["sha256"]:
                        matches.append(str(candidate))
    markers.append({
        "source": str(source),
        "source_absent": not os.path.lexists(source),
        "sha256": expected["sha256"],
        "candidate_quarantines": sorted(candidates),
        "matching_quarantines": sorted(matches),
        "read_errors": read_errors,
    })

processes = []
for expected in request["processes"]:
    pid = int(expected["pid"])
    token = str(expected["token"])
    raw_birth = expected.get("birth")
    birth = float(raw_birth) if isinstance(raw_birth, (int, float)) else None
    original_alive = False
    status = "birth_unrecorded" if birth is None else "absent"
    current_birth = None
    if birth is not None:
        try:
            process = psutil.Process(pid)
            current_birth = float(process.create_time())
            same_birth = abs(current_birth - birth) <= 0.01
            original_alive = bool(process.is_running() and same_birth)
            status = "original_alive" if original_alive else "pid_reused_or_exited"
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            status = "access_denied"
    processes.append({"pid": pid, "token": token,
                      "expected_birth": birth, "observed_birth": current_birth,
                      "original_alive": original_alive, "status": status})

output = {
    "schema": "angerona.gui-live-os-witness.v1",
    "run_id": request["run_id"],
    "verify_digest": verify_digest,
    "markers": markers,
    "processes": processes,
}
Path(sys.argv[2]).write_text(json.dumps(output, indent=2), encoding="utf-8")
"""


@pytest.fixture
def isolated_root() -> Path:
    parent = Path(__file__).resolve().parents[1] / ".tmp"
    parent.mkdir(exist_ok=True)
    # Retain each isolated run for post-mortem review when an external witness
    # or authenticated report disagrees. The root is confined to ignored .tmp.
    yield Path(tempfile.mkdtemp(prefix="redteam_gui_live_", dir=parent))


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _os_witness_accepts(
    witness: dict, *, expected_markers: int, require_process: bool,
    require_digest: bool = True,
) -> bool:
    markers = witness.get("markers", [])
    processes = witness.get("processes", [])
    return bool(
        len(markers) == expected_markers
        and all(row["source_absent"] for row in markers)
        and all(row["candidate_quarantines"] for row in markers)
        and (
            not require_digest
            or (
                witness.get("verify_digest") is True
                and all(row["matching_quarantines"] for row in markers)
                and not any(row["read_errors"] for row in markers)
            )
        )
        and (not require_process or processes)
        and all(
            isinstance(row.get("expected_birth"), (int, float))
            and row["expected_birth"] > 0
            for row in processes
        )
        and all(row["status"] != "access_denied" for row in processes)
        and not any(row["original_alive"] for row in processes)
    )


def test_os_witness_rejects_uncontained_marker(isolated_root: Path) -> None:
    """Independent OS check rejects an AAR-like success without containment."""
    marker = isolated_root / "_redteam_negative_control.txt"
    body = b"ANGERONA RED TEAM inert negative control\n"
    marker.write_bytes(body)
    quarantine = isolated_root / "combat-quarantine"
    quarantine.mkdir()
    request = isolated_root / "negative-witness-input.json"
    output = isolated_root / "negative-witness-output.json"
    request.write_text(json.dumps({
        "run_id": "negative-control",
        "quarantine_root": str(quarantine),
        "markers": [{"source": str(marker),
                     "sha256": hashlib.sha256(body).hexdigest()}],
        "processes": [],
    }), encoding="utf-8")
    subprocess.run(
        [sys.executable, "-c", _OS_WITNESS, str(request), str(output)],
        check=True, capture_output=True, text=True, timeout=15.0,
    )
    witness = json.loads(output.read_text(encoding="utf-8"))
    assert witness["markers"][0]["source_absent"] is False
    assert witness["markers"][0]["matching_quarantines"] == []
    assert not _os_witness_accepts(
        witness, expected_markers=1, require_process=False,
    )
    marker.rename(quarantine / marker.name)
    subprocess.run(
        [sys.executable, "-c", _OS_WITNESS, str(request), str(output)],
        check=True, capture_output=True, text=True, timeout=15.0,
    )
    contained = json.loads(output.read_text(encoding="utf-8"))
    assert _os_witness_accepts(
        contained, expected_markers=1, require_process=False,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows response clickthrough")
def test_mainwindow_arm_launch_and_deliver_signed_aar_twice(
    isolated_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two UI clicks reach signed AAR and independent OS response evidence."""
    monkeypatch.setenv("ANGERONA_DATA", str(isolated_root))
    monkeypatch.setenv("ANGERONA_SOAR_RESPONSE_SCOPE", str(isolated_root / "drill-sandbox"))

    from angerona.core import report_attest
    from angerona.core.config import Config
    from angerona.core.drill_readiness import assess_drill_response
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.module_contract import build_capability_contract
    from angerona.core.module_manager import ModuleManager
    from angerona.core.storage import FlightRecorder
    from angerona.gui.main_window import MainWindow
    from angerona.gui.pages import AARDialog, SettingsDialog
    from angerona.modules.adversary_combat import AdversaryCombat
    from angerona.modules.process_monitor import ProcessMonitorModule
    from angerona.modules import purple_guard as purple_module
    from angerona.modules.purple_guard import PurpleGuard
    from angerona.modules.purple_guard import RedTeamValidationError, RedTeamValidationLease
    from angerona.shark.aar_report import AARReportResult, verified_aar_handoff_text
    from angerona.shark.red_team import INTENSITY_LEVELS, RedTeamEngine

    trace_path = (
        Path(__file__).resolve().parents[1] / ".tmp"
        / f"bug_audit_gui_trace_{os.getpid()}.jsonl"
    )

    def trace(phase: str, **details: object) -> None:
        with trace_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "wall_time": time.time(), "phase": phase, **details,
            }, default=str) + "\n")

    trace("fixture_start", isolated_root=str(isolated_root))

    # Observe the exact subcheck that fails at marker enrollment. All wrapped
    # functions call their originals and return/raise unchanged; no gate is
    # bypassed. Thread-local capture confines diagnostics to the engine thread.
    diagnostic_local = threading.local()
    diagnostic_root = Path(__file__).resolve().parents[1] / ".tmp"
    original_stat = Path.stat

    def diagnostic_stat(path: Path, *args: object, **kwargs: object):
        try:
            return original_stat(path, *args, **kwargs)
        except OSError as exc:
            if getattr(diagnostic_local, "active", False):
                diagnostic_local.stat_errors.append({
                    "path": str(path), "error": f"{type(exc).__name__}: {exc}",
                    "errno": exc.errno,
                    "winerror": getattr(exc, "winerror", None),
                })
            raise

    monkeypatch.setattr(Path, "stat", diagnostic_stat)

    def wrap_lease_helper(name: str) -> None:
        original = getattr(purple_module, name)

        def observed(*args: object, **kwargs: object):
            try:
                result = original(*args, **kwargs)
            except Exception as exc:
                if getattr(diagnostic_local, "active", False):
                    diagnostic_local.probes[name] = {
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                raise
            if getattr(diagnostic_local, "active", False):
                if name in {"_policy_identity", "validate_redteam_recorder"}:
                    expected = (
                        diagnostic_local.expected_policy
                        if name == "_policy_identity"
                        else diagnostic_local.expected_recorder
                    )
                    detail = {"matched_readiness": result == expected}
                elif name == "_runtime_targets_snapshot":
                    detail = {"contains_target": diagnostic_local.target in result}
                elif name == "_marker_path_identity":
                    detail = {"identity_valid": bool(result[1]),
                              "path": str(args[0])}
                else:
                    detail = {"result": bool(result)}
                diagnostic_local.probes[name] = detail
            return result

        monkeypatch.setattr(purple_module, name, observed)

    for helper_name in (
        "_runtime_targets_snapshot", "_target_identity_matches",
        "_validation_target_markers_safe", "_marker_path_identity",
        "_policy_identity", "validate_redteam_recorder",
    ):
        wrap_lease_helper(helper_name)

    original_register = RedTeamValidationLease.register_artifact_handle

    def diagnosed_register(
        lease: RedTeamValidationLease, path: Path, *, run_id: str,
    ) -> dict[str, object]:
        state = purple_module._lease_authority(lease)
        diagnostic_local.active = True
        diagnostic_local.target = state.target
        diagnostic_local.expected_policy = state.readiness.get("policy")
        diagnostic_local.expected_recorder = state.readiness.get("recorder_identity")
        diagnostic_local.probes = {}
        diagnostic_local.stat_errors = []
        try:
            return original_register(lease, path, run_id=run_id)
        except RedTeamValidationError as exc:
            try:
                from angerona.core.module_base import BaseModule

                modules = getattr(state.manager, "modules", {})
                snapshot = {
                    "run_id": run_id,
                    "path": str(path),
                    "error": str(exc),
                    "released": bool(state.released),
                    "artifact_custody_failed": bool(state.artifact_custody_failed),
                    "consumed": bool(state.consumed),
                    "bound_run_matches": run_id == state.bound_run_id,
                    "run_deadline_expired": time.monotonic() > state.run_deadline_monotonic,
                    "process_epoch_matches": state.process_epoch == purple_module._LEASE_PROCESS_EPOCH,
                    "manager_graph_matches": bool(
                        getattr(state.manager, "bus", None) is state.bus
                        and modules.get(state.module.name) is state.module
                        and modules.get("Process Monitor") is state.process_module
                    ),
                    "purple": BaseModule.operational_snapshot(state.module),
                    "purple_cycle": PurpleGuard.validation_cycle_snapshot(state.module),
                    "process": BaseModule.operational_snapshot(state.process_module),
                    "readiness_sensor_generation": state.readiness.get("sensor_generation"),
                    "readiness_sensor_cycle": state.readiness.get("sensor_cycle_serial"),
                    "readiness_process": state.readiness.get("process_sensor"),
                    "handoff_paths": sorted(state.artifact_handoffs or set()),
                    "helper_results": diagnostic_local.probes,
                    "stat_errors": diagnostic_local.stat_errors,
                    "stat_error_post_state": [
                        {
                            "source": item["path"],
                            "source_exists": os.path.lexists(item["path"]),
                            "quarantine_names": [
                                str(candidate)
                                for candidate in combat.quarantine_root.rglob(
                                    Path(item["path"]).name
                                )
                            ],
                        }
                        for item in diagnostic_local.stat_errors
                    ],
                }
                diagnostic_path = diagnostic_root / f"bug_audit_gui_lease_failure_{run_id}.json"
                diagnostic_path.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
            except Exception as diagnostic_exc:
                (diagnostic_root / f"bug_audit_gui_lease_failure_{run_id}.txt").write_text(
                    f"Diagnostic capture failed: {diagnostic_exc}", encoding="utf-8",
                )
            raise
        finally:
            diagnostic_local.active = False

    monkeypatch.setattr(RedTeamValidationLease, "register_artifact_handle", diagnosed_register)

    key_path = isolated_root / "bus.key"
    key_path.write_text("42" * 32, encoding="ascii")
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    config = Config(
        data_dir=isolated_root,
        autostart_enabled=False,
        eco_mode=False,
        blackbox_enabled=False,
        adversary_combat_enabled=False,
        adversary_combat_block_network=False,
        adversary_combat_isolate_host=False,
        adversary_combat_activate_honeypots=False,
        adversary_combat_quarantine_files=True,
        adversary_combat_process_action="terminate",
        adversary_combat_min_severity="MEDIUM",
        module_states={
            "Purple Remediation Guard": True,
            "Process Monitor": True,
            "Adversary Combat": False,
        },
    )
    recorder = FlightRecorder(config.db_path)
    bus = EventBus(ring_size=4096)
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    manager = ModuleManager(bus, config, recorder=recorder)
    guard = PurpleGuard(isolated_root)
    process = ProcessMonitorModule()
    combat = AdversaryCombat(data_root=isolated_root)
    assert combat.quarantine_root.parent == isolated_root
    for module in (guard, process, combat):
        module.bind(bus)
        module._angerona_contract = build_capability_contract(
            module,
            capability_id=f"angerona.builtin.{type(module).__module__.rsplit('.', 1)[-1]}",
            origin="builtin", trust="release", publisher="Angerona",
        )
        manager.modules[module.name] = module
    combat.bind_manager(manager)

    # Reduce only the inert probe's pauses; actual GUI, sensors, response,
    # authenticated recorder and AAR remain unmodified and live.
    monkeypatch.setitem(INTENSITY_LEVELS["Low"], "jitter", (0.0, 0.0))
    monkeypatch.setitem(INTENSITY_LEVELS["Low"], "noise", 0.0)
    marker_digests: dict[str, dict[str, str]] = {}
    marker_lock = threading.Lock()
    spawn_births: dict[tuple[int, str], float | None] = {}
    original_popen = subprocess.Popen

    def record_tagged_spawn(*args: object, **kwargs: object) -> subprocess.Popen:
        proc = original_popen(*args, **kwargs)
        command = args[0] if args else kwargs.get("args")
        if (
            isinstance(command, (list, tuple))
            and len(command) == 4
            and command[0] == sys.executable
            and tuple(command[1:3]) == ("-c", "import time; time.sleep(30)")
            and isinstance(command[3], str)
            and command[3].startswith("ANGERONA_REDTEAM_")
        ):
            try:
                birth = float(psutil.Process(proc.pid).create_time())
            except (psutil.Error, OSError, ValueError):
                birth = None
            with marker_lock:
                spawn_births[(int(proc.pid), command[3])] = birth
        return proc

    monkeypatch.setattr(subprocess, "Popen", record_tagged_spawn)
    original_marker = RedTeamEngine._marker

    def record_created_marker(engine: RedTeamEngine, name: str, body: str) -> Path:
        path = original_marker(engine, name, body)
        with marker_lock:
            marker_digests.setdefault(engine.run_id, {})[str(path)] = hashlib.sha256(
                body.encode("utf-8")
            ).hexdigest()
        return path

    monkeypatch.setattr(RedTeamEngine, "_marker", record_created_marker)

    app = _app()
    window = MainWindow(bus, recorder, manager, config)
    trace("mainwindow_constructed")
    window.show()
    app.processEvents()
    window.timer.stop()
    if window._ui_watchdog is not None:
        window._ui_watchdog.stop()

    visited: list[str] = []
    delivered: list[object] = []
    shown_aar: list[str] = []
    modal_errors: list[str] = []
    activation_states: list[str] = []
    witness_paths: dict[str, tuple[Path, Path]] = {}
    window._aar_ready.connect(delivered.append)
    window._settings_combat_status.connect(
        lambda state, _message: activation_states.append(state)
    )

    def arm_from_modal() -> None:
        dialog = app.activeModalWidget()
        assert isinstance(dialog, SettingsDialog)
        visited.append("settings")
        dialog._combat_enabled_chk.setChecked(True)
        dialog._combat_mode_combo.setCurrentIndex(
            dialog._combat_mode_combo.findData("aggressive")
        )
        dialog._combat_severity_combo.setCurrentIndex(
            dialog._combat_severity_combo.findData("MEDIUM")
        )
        dialog._combat_process_combo.setCurrentIndex(
            dialog._combat_process_combo.findData("terminate")
        )
        dialog._combat_quarantine_chk.setChecked(True)
        dialog._combat_block_chk.setChecked(False)
        dialog._combat_host_isolation_chk.setChecked(False)
        dialog._combat_honeypot_chk.setChecked(False)
        dialog._autostart_chk.setChecked(False)
        QTest.mouseClick(dialog._btn_save, Qt.MouseButton.LeftButton)

    try:
        QTimer.singleShot(0, arm_from_modal)
        window._show_settings("Adversary Combat")
        deadline = time.monotonic() + 60.0
        while (
            (
                not combat.response_snapshot()["ready"]
                or bool(getattr(manager, "_settings_combat_activation_pending", False))
                or "ready" not in activation_states
            )
            and time.monotonic() < deadline
        ):
            app.processEvents()
            time.sleep(0.05)
        assert visited == ["settings"]
        assert "pending" in activation_states
        assert "ready" in activation_states, activation_states
        assert not getattr(manager, "_settings_combat_activation_pending", False)
        assert config.adversary_combat_enabled is True
        assert config.module_states["Adversary Combat"] is True
        assert manager.is_enabled(combat.name)
        assert combat.response_snapshot()["ready"]
        trace("settings_armed", combat=combat.response_snapshot())
        assert config.settings_path.is_file()
        saved = json.loads(config.settings_path.read_text(encoding="utf-8"))
        assert saved["adversary_combat_enabled"] is True
        assert saved["adversary_combat_quarantine_files"] is True
        assert saved["adversary_combat_block_network"] is False
        assert saved["adversary_combat_isolate_host"] is False

        process.start()
        deadline = time.monotonic() + 10.0
        while not process.operational_snapshot()["first_cycle_complete"] and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.05)
        assert process.operational_snapshot()["first_cycle_complete"]
        assert assess_drill_response(manager, require_process=True)["ready"]
        trace("readiness_passed", process=process.operational_snapshot())

        original_settlement = window._wait_for_redteam_response_settlement

        def settle_then_witness(*, started_at: float, **kwargs: object) -> dict:
            trace("settlement_start", steps=len(window.red_team_engine.steps),
                  combat=combat.response_snapshot())
            settled = original_settlement(started_at=started_at, **kwargs)
            trace("settlement_done", settled=settled,
                  combat=combat.response_snapshot())
            engine = window.red_team_engine
            run_id = str(engine.run_id)
            with marker_lock:
                expected_markers = dict(marker_digests.get(run_id, {}))
            with marker_lock:
                expected_processes = [
                    {"pid": pid, "token": token,
                     "birth": spawn_births.get((pid, token))}
                    for step in engine.steps
                    for pid, token in zip(step.pids, step.correlation_tokens)
                ]
            evidence_root = Path(__file__).resolve().parents[1] / ".tmp"
            witness_input = evidence_root / f"bug_audit_gui_os_witness_{run_id}.pre.input.json"
            witness_output = (
                evidence_root
                / f"bug_audit_gui_os_witness_{run_id}.pre.json"
            )
            witness_input.write_text(json.dumps({
                "run_id": run_id,
                "quarantine_root": str(combat.quarantine_root),
                "verify_digest": False,
                "markers": [
                    {"source": source, "sha256": digest}
                    for source, digest in expected_markers.items()
                ],
                "processes": expected_processes,
            }), encoding="utf-8")
            witness_process = subprocess.run(
                [sys.executable, "-c", _OS_WITNESS,
                 str(witness_input), str(witness_output)],
                check=False, capture_output=True, text=True, timeout=15.0,
            )
            (evidence_root / f"bug_audit_gui_os_witness_{run_id}.pre.stderr.txt").write_text(
                witness_process.stderr, encoding="utf-8",
            )
            if witness_process.returncode:
                trace("pre_witness_failed", returncode=witness_process.returncode,
                      stderr=witness_process.stderr[-2000:])
                raise AssertionError(
                    f"OS witness exited {witness_process.returncode}: "
                    f"{witness_process.stderr[-4000:]}"
                )
            witness_paths[run_id] = witness_input, witness_output
            trace("pre_witness_done", run_id=run_id,
                  markers=len(expected_markers), processes=len(expected_processes))
            return settled

        monkeypatch.setattr(
            window, "_wait_for_redteam_response_settlement", settle_then_witness,
        )

        def close_report_dialogs() -> None:
            for widget in app.topLevelWidgets():
                if isinstance(widget, AARDialog) and widget.isVisible():
                    shown_aar.append(widget.body.toPlainText())
                    widget.accept()
                elif isinstance(widget, QMessageBox) and widget.isVisible():
                    modal_errors.append(widget.text())
                    widget.accept()

        modal_timer = QTimer()
        modal_timer.timeout.connect(close_report_dialogs)
        modal_timer.start(100)
        window._open_simulation()
        console = window._rt_console
        assert console is not None
        console.cb_shark.setChecked(False)
        console.cb_apt.setChecked(True)
        console.cb_comprehensive.setChecked(True)
        console.cb_campaign.setChecked(True)
        console.cb_remediate.setChecked(True)
        console.sld.setValue(0)
        assert console.loc_edit.text() == str(isolated_root / "drill-sandbox")

        try:
            for run_index in (1, 2):
                started = time.monotonic()
                previous_deliveries = len(delivered)
                QTest.mouseClick(console.launch_btn, Qt.MouseButton.LeftButton)
                trace("launch_clicked", run_index=run_index,
                      run_id=window.red_team_engine.run_id)
                assert console._run_pending
                assert console._report_runs.get("red_team")
                assert not console._report_runs.get("shark")
                deadline = time.monotonic() + 180.0
                next_trace = time.monotonic() + 10.0
                while len(delivered) == previous_deliveries and time.monotonic() < deadline:
                    app.processEvents()
                    if time.monotonic() >= next_trace:
                        trace("waiting_for_aar", run_index=run_index,
                              steps=len(window.red_team_engine.steps),
                              engine_running=window.red_team_engine.is_running,
                              combat=combat.response_snapshot())
                        next_trace = time.monotonic() + 10.0
                    time.sleep(0.05)
                trace("aar_signal_observed", run_index=run_index,
                      deliveries=len(delivered), steps=len(window.red_team_engine.steps))
                assert len(delivered) == previous_deliveries + 1, {
                    "console": console.live_status.text(),
                    "modal_errors": modal_errors,
                    "steps": len(window.red_team_engine.steps),
                }
                handoff = delivered[-1]
                assert type(handoff) is AARReportResult, handoff
                assert "RED TEAM ATTACK" in verified_aar_handoff_text(handoff)
                report = json.loads(handoff.report_bytes.decode("utf-8"))
                trace("signed_aar", run_index=run_index, run_id=handoff.run_id,
                      outcome=report.get("outcome"))
                assert report["run_id"] == handoff.run_id
                evidence_root = Path(__file__).resolve().parents[1] / ".tmp"
                shutil.copyfile(
                    isolated_root / "redteam_aar.json",
                    evidence_root / f"bug_audit_gui_aar_{run_index}.json",
                )

                witness_input, pre_output = witness_paths[handoff.run_id]
                pre_witness = json.loads(pre_output.read_text(encoding="utf-8"))
                assert pre_witness["run_id"] == handoff.run_id
                post_input = evidence_root / f"bug_audit_gui_os_witness_{handoff.run_id}.post.input.json"
                post_output = evidence_root / f"bug_audit_gui_os_witness_{handoff.run_id}.post.json"
                post_request = json.loads(witness_input.read_text(encoding="utf-8"))
                post_request["verify_digest"] = True
                post_input.write_text(json.dumps(post_request), encoding="utf-8")
                post_process = subprocess.run(
                    [sys.executable, "-c", _OS_WITNESS,
                     str(post_input), str(post_output)],
                    check=False, capture_output=True, text=True, timeout=15.0,
                )
                (evidence_root / f"bug_audit_gui_os_witness_{handoff.run_id}.post.stderr.txt").write_text(
                    post_process.stderr, encoding="utf-8",
                )
                assert post_process.returncode == 0, post_process.stderr
                trace("post_witness_done", run_index=run_index,
                      run_id=handoff.run_id)
                witness = json.loads(post_output.read_text(encoding="utf-8"))
                assert witness["run_id"] == handoff.run_id
                shutil.copyfile(
                    pre_output,
                    evidence_root / f"bug_audit_gui_os_witness_{run_index}.pre.json",
                )
                shutil.copyfile(
                    post_output,
                    evidence_root / f"bug_audit_gui_os_witness_{run_index}.post.json",
                )
                (evidence_root / f"bug_audit_gui_run_{run_index}.json").write_text(
                    json.dumps({
                        "run_id": handoff.run_id,
                        "duration_seconds": round(time.monotonic() - started, 3),
                        "engine_steps": len(window.red_team_engine.steps),
                        "aar_outcome": report.get("outcome"),
                        "aar_denominator": report["evidence_taxonomy"]["denominator"],
                        "aar_verified_containment": report["evidence_taxonomy"]["successful_response"]["count"],
                        "os_pre_markers": len(pre_witness["markers"]),
                        "os_pre_sources_absent": sum(row["source_absent"] for row in pre_witness["markers"]),
                        "os_pre_quarantine_names": sum(bool(row["candidate_quarantines"]) for row in pre_witness["markers"]),
                        "os_post_hash_matches": sum(bool(row["matching_quarantines"]) for row in witness["markers"]),
                        "os_witness_processes": len(witness["processes"]),
                        "console_status": console.live_status.text(),
                        "modal_errors": modal_errors,
                    }, indent=2), encoding="utf-8",
                )
                assert _os_witness_accepts(
                    pre_witness, expected_markers=36, require_process=True,
                    require_digest=False,
                ), pre_witness
                assert _os_witness_accepts(
                    witness, expected_markers=36, require_process=True,
                ), witness
                assert report["coverage_score_eligible"] is True
                assert report["evidence_taxonomy"]["denominator"] == 37
                assert report["evidence_taxonomy"]["successful_response"]["count"] == 37
                assert report["outcome"] == "verified"
                assert console._report_results["red_team"] == {
                    "count": 37, "eligible": 37, "outcome": "verified",
                }
                assert "Verified containment" in console.live_status.text()
                assert shown_aar and "RED TEAM ATTACK" in shown_aar[-1]
                assert not modal_errors
        finally:
            modal_timer.stop()
    finally:
        trace("cleanup_start")
        if window.red_team_engine.is_running:
            window.red_team_engine.stop_and_clean()
        manager.stop_all()
        for name in ("timer", "_chill_maintenance_timer", "_adaptation_timer", "_beat_timer"):
            timer = getattr(window, name, None)
            if timer is not None:
                timer.stop()
        window._flow_writer.close()
        window._posture_reader.close()
        window._panel_reveal.shutdown()
        window.tray.hide()
        window.hide()
        recorder.close()
        app.processEvents()
        trace("cleanup_done")
