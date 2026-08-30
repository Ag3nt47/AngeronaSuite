from __future__ import annotations

import hashlib
import inspect
import json
import time
from pathlib import Path
from types import SimpleNamespace

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.gui.main_window import MainWindow
from angerona.gui.pages import AARDialog
from angerona.modules.purple_guard import (
    PurpleGuard,
    acquire_redteam_validation_lease,
)
from angerona.shark.aar_report import evaluate, generate_aar
from angerona.shark.red_team import (
    REDTEAM_STAGE_CATEGORY,
    RedTeamEngine,
)
from angerona.shark.run_manifest import (
    build_run_history,
    load_verified_history,
    preflight_run,
    write_run_history,
)


_KEY = bytes.fromhex("42" * 32)


def _history(path: Path, started: float | None = None) -> dict:
    ts = time.time() if started is None else started
    return {
        "run_id": "redteam-evidence-split",
        "steps": [{
            "stage": "Credential Access (simulated)",
            "technique": "T1003 marker",
            "description": "inert marker",
            "ts_start": ts,
            "ts_end": ts + 0.1,
            "artifact_paths": [str(path)],
        }],
    }


def _event(
    module: str,
    path: Path,
    severity: Severity,
    ts: float,
    **details,
) -> Event:
    return Event(
        module,
        f"{module} evidence",
        severity,
        ts,
        {"path": str(path), **details},
        hmac_sig="stored-authenticated-event",
    )


def _install_test_keys(monkeypatch, root: Path) -> None:
    key_path = root / "bus.key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(_KEY.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))


def _validation_runtime(root: Path):
    bus = EventBus(ring_size=4096)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = PurpleGuard(root)
    guard.bind(bus)
    manager = SimpleNamespace(modules={guard.name: guard}, bus=bus)
    return bus, recorder, guard, manager


def test_strict_aar_rejects_raw_info_self_credit_and_failed_response(tmp_path) -> None:
    marker = tmp_path / "_redteam_lsass_dump_probe.txt"
    started = time.time()
    events = [
        _event("Red Team Attack Engine", marker, Severity.CRITICAL, started + 0.1),
        _event(
            "Process Monitor",
            marker,
            Severity.INFO,
            started + 0.2,
            event_type="process_creation",
        ),
        _event(
            "Active Response SOAR",
            marker,
            Severity.CRITICAL,
            started + 0.3,
            mitigated=False,
        ),
    ]

    verdict = evaluate(
        _history(marker, started),
        events,
        REDTEAM_STAGE_CATEGORY,
        require_authenticated=True,
        event_verifier=lambda _event: True,
        native_verifier=lambda _event, _step: True,
        purple_verifier=lambda _event, _step: True,
    )[0]

    assert verdict.observation is events[1]
    assert verdict.catch is None
    assert verdict.native_catch is None
    assert verdict.simulation_validation is None
    assert verdict.remediation is None


def test_strict_aar_splits_native_purple_observation_and_response(tmp_path) -> None:
    marker = tmp_path / "_redteam_lsass_dump_probe.txt"
    started = time.time()
    raw = _event(
        "Process Monitor",
        marker,
        Severity.INFO,
        started + 0.1,
        event_type="process_creation",
    )
    native = _event(
        "File Integrity Monitor",
        marker,
        Severity.MEDIUM,
        started + 0.2,
        evidence_type="native_analytic_detection",
        detector_verdict="positive",
    )
    purple = _event(
        "Purple Remediation Guard",
        marker,
        Severity.HIGH,
        started + 0.3,
        mitre="T1003",
        detector_policy="reviewed-redteam-candidate",
        evidence_type="simulation_contract_validation",
        detector_verdict="positive",
    )
    response = _event(
        "Active Response SOAR",
        marker,
        Severity.HIGH,
        started + 0.4,
        trigger_ts=purple.ts,
        mitigated=True,
    )

    verdict = evaluate(
        _history(marker, started),
        [response, purple, native, raw],
        REDTEAM_STAGE_CATEGORY,
        require_authenticated=True,
        event_verifier=lambda _event: True,
        native_verifier=lambda _event, _step: True,
        purple_verifier=lambda _event, _step: True,
    )[0]

    assert verdict.observation is raw
    assert verdict.native_catch is native
    assert verdict.simulation_validation is purple
    assert verdict.catch is native
    assert verdict.remediation is response


def test_strict_aar_rejects_spoofed_producers_and_all_raw_shapes(tmp_path) -> None:
    marker = tmp_path / "_redteam_lsass_dump_probe.txt"
    started = time.time()
    spoofed_native = _event(
        "Totally Unregistered Detector",
        marker,
        Severity.HIGH,
        started + 0.1,
        evidence_type="native_analytic_detection",
        detector_verdict="positive",
    )
    spoofed_purple = _event(
        "Purple Remediation Guard",
        marker,
        Severity.HIGH,
        started + 0.2,
        mitre="T1003",
        detector_policy="reviewed-redteam-candidate",
        evidence_type="simulation_contract_validation",
        detector_verdict="positive",
    )
    raw_events = [
        _event(
            "Registered Looking Sensor",
            marker,
            Severity.HIGH,
            started + 0.3 + index / 100,
            event_type=event_type,
            evidence_type="native_analytic_detection",
            detector_verdict="positive",
        )
        for index, event_type in enumerate(
            (
                "process_creation",
                "raw_telemetry",
                "sensor_observation",
                "network_observation",
                "file_observation",
                "etw_observation",
            )
        )
    ]

    verdict = evaluate(
        _history(marker, started),
        [spoofed_native, spoofed_purple, *raw_events],
        REDTEAM_STAGE_CATEGORY,
        require_authenticated=True,
        event_verifier=lambda _event: True,
        native_verifier=lambda event, _step: event is not spoofed_native,
        purple_verifier=lambda _event, _step: False,
    )[0]

    assert verdict.observation is spoofed_native
    assert verdict.native_catch is None
    assert verdict.simulation_validation is None
    assert verdict.catch is None


def test_strict_aar_requires_cryptographic_event_verifier(tmp_path) -> None:
    marker = tmp_path / "_redteam_lsass_dump_probe.txt"
    started = time.time()
    fake_hmac = _event(
        "File Integrity Monitor",
        marker,
        Severity.HIGH,
        started + 0.1,
        evidence_type="native_analytic_detection",
        detector_verdict="positive",
    )
    verdict = evaluate(
        _history(marker, started),
        [fake_hmac],
        REDTEAM_STAGE_CATEGORY,
        require_authenticated=True,
        event_verifier=lambda _event: False,
        native_verifier=lambda _event, _step: True,
    )[0]
    assert verdict.observation is None
    assert verdict.catch is None


def test_custom_probe_is_informational_and_filename_cannot_collide(tmp_path) -> None:
    engine = RedTeamEngine(tmp_path / "data", documents_dir=tmp_path / "markers")
    engine.run_id = "custom-collision-test"
    engine._custom = {"name": "lsass_dump_T1003", "payload": "inert text"}
    engine._step_custom((0.0, 0.0))

    step = engine.steps[0]
    marker = Path(step.artifact_paths[0])
    assert marker.name.startswith("_redteam_custom_")
    assert "lsass_dump" not in marker.name.casefold()
    assert "t1003" not in marker.name.casefold()

    purple = _event(
        "Purple Remediation Guard",
        marker,
        Severity.HIGH,
        step.ts_start + 0.1,
        mitre="T1003",
        detector_policy="reviewed-redteam-candidate",
    )
    native = _event(
        "File Integrity Monitor", marker, Severity.HIGH, step.ts_start + 0.05
    )
    verdict = evaluate(
        {"run_id": engine.run_id, "steps": [step.__dict__]},
        [native, purple],
        REDTEAM_STAGE_CATEGORY,
        require_authenticated=True,
        event_verifier=lambda _event: True,
        native_verifier=lambda _event, _step: True,
        purple_verifier=lambda _event, _step: True,
    )[0]
    assert verdict.category == "informational"
    assert verdict.observation is native
    assert verdict.catch is None
    engine.stop_and_clean()


def test_engine_binds_readiness_into_signed_history_and_resets_target(
    tmp_path, monkeypatch
) -> None:
    _install_test_keys(monkeypatch, tmp_path)
    root = tmp_path / "data"
    bus, recorder, guard, manager = _validation_runtime(root)
    engine = RedTeamEngine(root)
    custom_target = tmp_path / "operator-target"
    for name in (
        "_step_initial_access",
        "_step_recon",
        "_step_credential_access",
        "_step_privilege_escalation",
        "_step_defense_evasion",
        "_step_registry_runkey",
        "_step_scheduled_task",
        "_step_wmi_persistence",
        "_step_lateral_movement",
        "_step_c2_beacon",
        "_step_exfil_staging",
        "_step_ransomware_canary",
        "_step_data_destruction",
        "_step_random_processes",
    ):
        monkeypatch.setattr(engine, name, lambda _jitter: None)

    lease = acquire_redteam_validation_lease(
        manager, bus, recorder, root, custom_target, timeout=3
    )
    try:
        assert engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            campaign=True,
            target_dir=custom_target,
            validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=5)
        assert not engine.is_running
        assert engine.documents_dir == engine.default_documents_dir

        history = load_verified_history(engine.history_path)
        receipt = history["validation_readiness"]
        assert receipt["policy_count"] == 13
        assert receipt["recorder"]["authenticated"] is True
        assert receipt["bound_run_id"] == history["run_id"]
        assert Path(receipt["bound_target"]) == custom_target.resolve(strict=False)
        assert lease.verify_run_history(history)
    finally:
        lease.release()
        guard.stop()
        recorder.close()


def test_engine_refusal_without_live_lease_preserves_prior_history(tmp_path) -> None:
    engine = RedTeamEngine(tmp_path / "data")
    engine.history_path.parent.mkdir(parents=True, exist_ok=True)
    engine.history_path.write_text("stale-history-sentinel", encoding="utf-8")
    prior_run_id = engine.run_id

    assert not engine.start(
        jitter_range=(0, 0),
        noise_chance=0,
        complexity=1,
        target_dir=tmp_path / "target",
    )
    assert engine.run_id == prior_run_id
    assert engine.history_path.read_text(encoding="utf-8") == "stale-history-sentinel"
    assert engine.cancel_evidence_hold()


def test_engine_rejects_target_mismatch_and_released_lease_replay(
    tmp_path, monkeypatch
) -> None:
    _install_test_keys(monkeypatch, tmp_path)
    root = tmp_path / "runtime"
    target = root / "target-a"
    bus, recorder, guard, manager = _validation_runtime(root)
    lease = acquire_redteam_validation_lease(
        manager, bus, recorder, root, target, timeout=3
    )
    engine = RedTeamEngine(root)
    for name in (
        "_step_initial_access",
        "_step_recon",
        "_step_credential_access",
        "_step_privilege_escalation",
        "_step_defense_evasion",
        "_step_registry_runkey",
        "_step_scheduled_task",
        "_step_wmi_persistence",
        "_step_lateral_movement",
        "_step_c2_beacon",
        "_step_exfil_staging",
        "_step_ransomware_canary",
        "_step_data_destruction",
        "_step_random_processes",
    ):
        monkeypatch.setattr(engine, name, lambda _jitter: None)
    try:
        assert not engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            target_dir=root / "target-b",
            validation_lease=lease,
        )
        assert engine.run_id == ""
        assert engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            target_dir=target,
            validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=5)
        history_before_release = engine.history_path.read_bytes()
        lease.release()
        assert not engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            target_dir=target,
            validation_lease=lease,
        )
        assert engine.history_path.read_bytes() == history_before_release
    finally:
        lease.release()
        guard.stop()
        recorder.close()


def test_generate_aar_rejects_structural_fake_recorder(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _install_test_keys(monkeypatch, root)
    marker = root / "drill-sandbox" / "_redteam_lsass_dump_probe.txt"
    started = time.time()
    contract = preflight_run(
        kind="red_team",
        cycles=1,
        jitter_range=(0, 0),
        noise_chance=0,
        target_dir=marker.parent,
    )
    history = build_run_history(
        kind="red_team",
        run_id="fake-recorder-run",
        generated="test",
        steps=_history(marker, started)["steps"],
        preflight=contract,
        status="completed",
    )
    assert write_run_history(root / "redteam_history.json", history)

    class StructuralFakeRecorder:
        def events_in_window(self, *_args, **_kwargs):
            return [_event(
                "File Integrity Monitor",
                marker,
                Severity.HIGH,
                started + 0.1,
                evidence_type="native_analytic_detection",
                detector_verdict="positive",
            )]

    result = generate_aar(
        root,
        history_name="redteam_history.json",
        stage_category=REDTEAM_STAGE_CATEGORY,
        report_basename="redteam_aar",
        recorder=StructuralFakeRecorder(),  # type: ignore[arg-type]
    )
    assert "exact built-in FlightRecorder" in result
    assert not (root / "redteam_aar.json").exists()


def test_generate_aar_ignores_instance_verifiers_that_accept_a_fake_hmac(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _install_test_keys(monkeypatch, root)
    bus, recorder, guard, manager = _validation_runtime(root)
    target = root / "target"
    marker = target / "_redteam_lsass_dump_instance-spoof.txt"
    started = time.time()
    lease = acquire_redteam_validation_lease(
        manager, bus, recorder, root, target, timeout=3
    )
    try:
        run_id = "redteam-instance-verifier-spoof"
        receipt = lease.consume_for_run(
            run_id=run_id,
            target=target,
            data_root=root,
        )
        preflight = preflight_run(
            kind="red_team",
            cycles=1,
            jitter_range=(0, 0),
            noise_chance=0,
            target_dir=target,
        )
        history = build_run_history(
            kind="red_team",
            run_id=run_id,
            generated="2026-08-28 00:00:00",
            steps=[{
                "stage": "Credential Access (simulated)",
                "technique": "T1003 marker",
                "description": "inert marker",
                "ts_start": started,
                "ts_end": started + 0.1,
                "artifact_paths": [str(marker)],
                "ok": True,
            }],
            preflight=preflight,
            status="completed",
        )
        history["validation_readiness"] = receipt
        assert write_run_history(root / "redteam_history.json", history)

        recorder.record_bus(_event(
            "Process Monitor",
            marker,
            Severity.INFO,
            started + 0.05,
            event_type="process_creation",
        ))
        # Storage decoding and the old AAR verifier both dispatched through
        # these writable instance attributes. The production verifier must use
        # the exact BusAuthority/EventBus class implementations instead.
        monkeypatch.setattr(recorder.authority, "verify", lambda _event: True)
        monkeypatch.setattr(bus, "verify", lambda _event: True)

        generate_aar(
            root,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=recorder,
            bus=bus,
            manager=manager,
            validation_lease=lease,
        )
        report = json.loads((root / "redteam_aar.json").read_text(encoding="utf-8"))
        assert report["evidence_taxonomy"]["sensor_observation"]["count"] == 0
        assert report["evidence_taxonomy"]["native_analytic_detection"]["count"] == 0
        assert report["detection_caught"] == 0
    finally:
        lease.release()
        guard.stop()
        recorder.close()


def test_redteam_refresh_reloads_attested_report_without_rescoring(
    tmp_path, monkeypatch
) -> None:
    _install_test_keys(monkeypatch, tmp_path)
    text = "RED TEAM ATTACK persisted authenticated report"
    (tmp_path / "redteam_aar.txt").write_text(text, encoding="utf-8")
    payload = report_attest.attest({
        "run_id": "redteam-persisted-001",
        "report_basename": "redteam_aar",
        "report_kind": "red_team",
        "report_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    })
    (tmp_path / "redteam_aar.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    class Body:
        value = ""

        def setPlainText(self, value):
            self.value = value

    dialog = SimpleNamespace(
        data_dir=tmp_path,
        _redteam=True,
        _report_binding={},
        body=Body(),
    )
    AARDialog.refresh(dialog)
    assert dialog.body.value == text
    assert dialog._report_binding["run_id"] == "redteam-persisted-001"
    assert not (tmp_path / "redteam_history.json").exists()
    assert not (tmp_path / "flight-recorder.db").exists()

    (tmp_path / "redteam_aar.txt").write_text(text + " tampered", encoding="utf-8")
    AARDialog.refresh(dialog)
    assert "does not match its authenticated metadata" in dialog.body.value


def test_generate_aar_uses_passed_run_recorder_not_ambient_config(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "requested-root"
    other = tmp_path / "unrelated-root"
    root.mkdir()
    other.mkdir()
    _install_test_keys(monkeypatch, root)
    target = root / "drill-sandbox"
    bus, requested, guard, manager = _validation_runtime(root)
    unrelated = FlightRecorder(other / "flight-recorder.db")
    engine = RedTeamEngine(root)
    for name in (
        "_step_initial_access",
        "_step_recon",
        "_step_privilege_escalation",
        "_step_defense_evasion",
        "_step_registry_runkey",
        "_step_scheduled_task",
        "_step_wmi_persistence",
        "_step_lateral_movement",
        "_step_c2_beacon",
        "_step_exfil_staging",
        "_step_ransomware_canary",
        "_step_data_destruction",
        "_step_random_processes",
    ):
        monkeypatch.setattr(engine, name, lambda _jitter: None)
    lease = acquire_redteam_validation_lease(
        manager, bus, requested, root, target, timeout=3
    )
    try:
        assert engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            campaign=True,
            target_dir=target,
            validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=5)

        refused = generate_aar(
            root,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=unrelated,
            bus=bus,
            manager=manager,
            validation_lease=lease,
        )
        assert "recorder integrity check failed" in refused
        assert not (root / "redteam_aar.json").exists()

        generated = generate_aar(
            root,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=requested,
            bus=bus,
            manager=manager,
            validation_lease=lease,
        )
        assert "AFTER-ACTION REPORT" in generated
        report = json.loads((root / "redteam_aar.json").read_text(encoding="utf-8"))
        taxonomy = report["evidence_taxonomy"]
        assert taxonomy["native_analytic_detection"]["count"] == 0
        assert "not real-attack" in report["coverage_interpretation"]
    finally:
        lease.release()
        guard.stop()
        requested.close()
        unrelated.close()


def test_safe_end_to_end_campaign_validates_all_13_pipeline_canaries(
    tmp_path, monkeypatch
) -> None:
    """Exercise inert files/process telemetry only; no exploit or host mutation."""
    _install_test_keys(monkeypatch, tmp_path)
    root = tmp_path / "runtime"
    target = root / "drill-sandbox"
    bus = EventBus(ring_size=2048)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = PurpleGuard(root)
    guard.bind(bus)
    manager = SimpleNamespace(
        modules={"Purple Remediation Guard": guard},
        bus=bus,
    )
    lease = acquire_redteam_validation_lease(
        manager, bus, recorder, root, target, timeout=5
    )
    engine = RedTeamEngine(root)
    engine.hold_evidence_for_aar()
    try:
        assert engine.start(
            jitter_range=(0, 0),
            noise_chance=0,
            complexity=1,
            campaign=True,
            target_dir=target,
            validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=10)
        assert not engine.is_running

        first_marker = Path(next(
            path
            for step in engine.steps
            for path in step.artifact_paths
        ))
        for module, details in (
            (
                "Totally Unregistered Detector",
                {
                    "evidence_type": "native_analytic_detection",
                    "detector_verdict": "positive",
                },
            ),
            (
                "Registered Looking Sensor",
                {
                    "event_type": "process_creation",
                    "evidence_type": "native_analytic_detection",
                    "detector_verdict": "positive",
                },
            ),
            (
                "Purple Remediation Guard",
                {
                    "mitre": "T1566.001",
                    "detector_policy": "reviewed-redteam-candidate",
                    "evidence_type": "simulation_contract_validation",
                    "detector_verdict": "positive",
                },
            ),
        ):
            bus.publish(Event(
                module,
                "adversarial producer-name spoof",
                Severity.HIGH,
                details={"path": str(first_marker), **details},
            ))

        execution = next(
            step for step in engine.steps
            if step.stage == "Benign Execution (simulated)"
        )
        assert execution.pids and execution.correlation_tokens
        bus.publish(Event(
            "Process Monitor",
            "raw tagged process observation",
            Severity.INFO,
            details={
                "event_type": "process_creation",
                "pid": execution.pids[0],
                "process_create_time": time.time(),
                "cmdline": (
                    f"python -c inert {execution.correlation_tokens[0]}"
                ),
            },
        ))

        deadline = time.monotonic() + 6
        techniques: set[str] = set()
        while time.monotonic() < deadline:
            rows = recorder.events_in_window(
                engine.steps[0].ts_start - 2,
                time.time() + 1,
            )
            techniques = {
                str((event.details or {}).get("mitre") or "")
                for event in rows
                if event.module == "Purple Remediation Guard"
            }
            if len(techniques) == 13:
                break
            time.sleep(0.05)
        assert len(techniques) == 13

        generate_aar(
            root,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=recorder,
            bus=bus,
            manager=manager,
            validation_lease=lease,
        )
        report = json.loads((root / "redteam_aar.json").read_text(encoding="utf-8"))
        taxonomy = report["evidence_taxonomy"]
        assert taxonomy["denominator"] == 13
        assert taxonomy["simulation_contract_validation"]["count"] == 13
        assert taxonomy["simulation_contract_validation"]["simulation_only"] is True
        assert taxonomy["native_analytic_detection"]["count"] == 0
        assert report["validation_readiness"]["recorder"]["authenticated"] is True
    finally:
        scope = engine.evidence_cleanup_scope()
        engine.release_evidence_after_aar(scope)
        lease.release()
        recorder.close()


def test_both_gui_launchers_fail_closed_and_honor_engine_start_boolean() -> None:
    unified = inspect.getsource(MainWindow._run_simulation)
    legacy = inspect.getsource(MainWindow._start_red_team)
    abort = inspect.getsource(MainWindow._abort_simulation_launch)

    for source in (unified, legacy):
        assert "acquire_redteam_validation_lease" in source
        assert "validation_lease" in source
        assert "if not self.red_team_engine.start" in source
    assert "auto_remediate" not in unified[unified.index("acquire_redteam_validation_lease"):]
    assert "self._sim_aar_pending = 0" in abort
    assert "cancel_evidence_hold" in abort
    assert "_release_redteam_validation_lease" in abort
