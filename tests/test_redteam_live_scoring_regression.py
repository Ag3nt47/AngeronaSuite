"""Live Red Team scoring with the actual marker custody and response workers."""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def workspace_tmp_path() -> Path:
    """Keep drill data on the repository volume, including under default pytest."""
    parent = Path(__file__).resolve().parents[1] / ".tmp"
    parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="redteam_live_", dir=parent) as path:
        yield Path(path)


@pytest.mark.skipif(os.name != "nt", reason="Windows pinned-file handoff regression")
@pytest.mark.parametrize(
    "comprehensive, expected_steps, expected_count, expected_file_count",
    [(False, 14, 13, 12), (True, 38, 37, 36)],
    ids=["base", "comprehensive"],
)
def test_live_redteam_marker_custody_allows_verified_containment(
    workspace_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    comprehensive: bool,
    expected_steps: int,
    expected_count: int,
    expected_file_count: int,
) -> None:
    """Every inert marker must reach a real, verified response receipt."""
    root = workspace_tmp_path / "isolated-runtime"
    target = root / "drill-sandbox"
    root.mkdir()
    for key, value in {
        "ANGERONA_DATA": str(root),
        "ANGERONA_ADVERSARY_COMBAT_ENABLED": "1",
        "ANGERONA_ADVERSARY_COMBAT_MODE": "balanced",
        "ANGERONA_ADVERSARY_COMBAT_MIN_SEVERITY": "MEDIUM",
        "ANGERONA_ADVERSARY_COMBAT_QUARANTINE_FILES": "1",
        "ANGERONA_ADVERSARY_COMBAT_PROCESS_ACTION": "terminate",
        "ANGERONA_ADVERSARY_COMBAT_BLOCK_NETWORK": "0",
        "ANGERONA_ADVERSARY_COMBAT_ISOLATE_HOST": "0",
        "ANGERONA_ADVERSARY_COMBAT_ACTIVATE_HONEYPOTS": "0",
        "ANGERONA_SOAR_RESPONSE_SCOPE": str(target),
    }.items():
        monkeypatch.setenv(key, value)

    from angerona.core import report_attest
    from angerona.core.drill_readiness import assess_drill_response
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.storage import FlightRecorder
    from angerona.modules.adversary_combat import AdversaryCombat
    from angerona.modules.purple_guard import (
        PurpleGuard,
        acquire_redteam_validation_lease,
    )
    from angerona.shark.aar_report import AARReportResult, generate_aar
    from angerona.shark.red_team import REDTEAM_STAGE_CATEGORY, RedTeamEngine

    key_path = root / "bus.key"
    key_path.write_text("42" * 32, encoding="ascii")
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)

    bus = EventBus(ring_size=4096)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = PurpleGuard(root)
    guard.bind(bus)
    combat = AdversaryCombat(data_root=root)
    combat.bind(bus)
    manager = SimpleNamespace(
        modules={guard.name: guard, combat.name: combat},
        bus=bus,
        config=SimpleNamespace(data_dir=root),
    )
    combat.bind_manager(manager)
    engine = RedTeamEngine(root, documents_dir=target)
    lease = None
    try:
        combat.start()
        deadline = time.monotonic() + 10.0
        while not combat.response_snapshot()["ready"] and time.monotonic() < deadline:
            time.sleep(0.05)
        assert assess_drill_response(manager, require_process=True)["ready"]

        lease = acquire_redteam_validation_lease(
            manager, bus, recorder, root, target, timeout=10.0,
            comprehensive=comprehensive,
        )
        assert lease.readiness["policy_count"] == expected_count
        engine.hold_evidence_for_aar()
        assert engine.start(
            jitter_range=(0.0, 0.0), noise_chance=0.0, complexity=1,
            campaign=True, comprehensive=comprehensive,
            target_dir=target, validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=30.0)
        assert not engine._thread.is_alive()
        assert len(engine.steps) == expected_steps, {
            "last_steps": [
                (step.plan_step_id, step.ok, step.detail)
                for step in engine.steps[-3:]
            ],
            "guard": guard.operational_snapshot(),
            "combat": combat.response_snapshot(),
        }  # one is unmonitored

        expected_paths = {
            os.path.normcase(os.path.abspath(path))
            for step in engine.steps for path in step.artifact_paths
        }
        expected_pids = {
            pid for step in engine.steps
            for pid in (step.pids or ([step.pid] if step.pid else []))
        }
        assert len(expected_paths) == expected_file_count
        assert expected_pids
        verified_paths: set[str] = set()
        verified_pids: set[int] = set()
        deadline = time.monotonic() + (100.0 if comprehensive else 45.0)
        while time.monotonic() < deadline:
            events = recorder.events_in_window(
                engine.steps[0].ts_start - 2.0, time.time() + 1.0,
            )
            validated = {
                str((event.details or {}).get("mitre") or "")
                for event in events
                if event.module == "Purple Remediation Guard"
                and (event.details or {}).get("evidence_type")
                == "simulation_contract_validation"
            }
            for event in events:
                if event.module != "Adversary Combat":
                    continue
                details = event.details or {}
                if details.get("run_id") != engine.run_id:
                    continue
                for action in details.get("verified_actions") or []:
                    if action.get("postcondition_verified") is not True:
                        continue
                    identity = action.get("details") or {}
                    if action.get("action") == "quarantine_file":
                        path = identity.get("path")
                        if path:
                            verified_paths.add(
                                os.path.normcase(os.path.abspath(path))
                            )
                    elif action.get("action") == "terminate_process":
                        pid = identity.get("pid")
                        if type(pid) is int:
                            verified_pids.add(pid)
            if (
                len(validated) == expected_count
                and expected_paths <= verified_paths
                and expected_pids <= verified_pids
            ):
                break
            time.sleep(0.1)
        assert expected_paths <= verified_paths, {
            "missing_quarantines": sorted(expected_paths - verified_paths),
            "combat": combat.response_snapshot(),
        }
        assert expected_pids <= verified_pids, {
            "missing_terminations": sorted(expected_pids - verified_pids),
            "combat": combat.response_snapshot(),
        }
        assert len(validated) == expected_count

        result = generate_aar(
            root, history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK", report_basename="redteam_aar",
            recorder=recorder, bus=bus, manager=manager,
            validation_lease=lease, return_result=True,
        )
        assert isinstance(result, AARReportResult)
        report = json.loads((root / "redteam_aar.json").read_text(encoding="utf-8"))
        taxonomy = report["evidence_taxonomy"]
        assert report["coverage_score_eligible"] is True
        assert taxonomy["denominator"] == expected_count
        assert taxonomy["simulation_contract_validation"]["count"] == expected_count
        assert taxonomy["simulation_contract_validation"]["simulation_only"] is True
        assert taxonomy["successful_response"]["count"] == expected_count, {
            "combat": combat.response_snapshot(),
            "uncontained": [
                (row["technique_id"], row["containment_reason"])
                for row in report["verdicts"]
                if row["category"] == "detection"
                and not row["target_containment_verified"]
            ],
        }
        assert report["outcome"] == "verified"
    finally:
        combat.stop()
        if engine.is_running:
            engine.stop_and_clean()
            if engine._thread is not None:
                engine._thread.join(timeout=3.0)
        try:
            scope = engine.evidence_cleanup_scope()
            engine.release_evidence_after_aar(scope)
        finally:
            if lease is not None:
                lease.release()
            guard.stop()
            recorder.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows live FIM receipt regression")
def test_live_fim_evidence_survives_later_scans_in_the_aar(
    workspace_tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An authentic native receipt remains evidence after FIM polls again."""
    root = workspace_tmp_path / "native-runtime"
    target = root / "drill-sandbox"
    target.mkdir(parents=True)
    monkeypatch.setenv("ANGERONA_DATA", str(root))
    monkeypatch.setenv("ANGERONA_FIM_WATCH_ONLY", str(target))
    # Maximum mode's production one-second FIM cadence exercises two real scans.
    monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_ENABLED", "1")
    monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_MODE", "maximum")

    from angerona.core import report_attest
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.module_contract import build_capability_contract
    from angerona.core.storage import FlightRecorder
    from angerona.modules.file_integrity import FileIntegrityModule
    from angerona.modules.purple_guard import (
        PurpleGuard,
        acquire_redteam_validation_lease,
        verify_validation_native_event,
    )
    from angerona.shark.aar_report import AARReportResult, generate_aar
    from angerona.shark.red_team import REDTEAM_STAGE_CATEGORY, RedTeamEngine

    key_path = root / "bus.key"
    key_path.write_text("42" * 32, encoding="ascii")
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)

    bus = EventBus(ring_size=4096)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = PurpleGuard(root)
    guard.bind(bus)
    fim = FileIntegrityModule()
    fim.bind(bus)
    fim._angerona_contract = build_capability_contract(
        fim, capability_id="angerona.builtin.file_integrity",
        origin="builtin", trust="release", publisher="Angerona",
    )
    manager = SimpleNamespace(modules={guard.name: guard, fim.name: fim}, bus=bus)
    engine = RedTeamEngine(root, documents_dir=target)
    lease = None
    observed: list[tuple[object, bool, int]] = []

    def capture_native(event: object) -> None:
        details = getattr(event, "details", {}) or {}
        if (
            lease is None
            or getattr(event, "module", "") != fim.name
            or details.get("evidence_type") != "native_analytic_detection"
        ):
            return
        technique = str(details.get("technique") or "")
        step = {"attack_ids": [technique], "technique": f"{technique} marker"}
        observed.append((
            event,
            verify_validation_native_event(lease, event, manager, step),
            fim._scan_generation,
        ))

    bus.subscribe(capture_native, delivery_budget_ms=60_000)
    try:
        fim.start()
        deadline = time.monotonic() + 10.0
        while not fim.operational_snapshot()["first_cycle_complete"] and time.monotonic() < deadline:
            time.sleep(0.05)
        assert fim.operational_snapshot()["first_cycle_complete"]

        lease = acquire_redteam_validation_lease(
            manager, bus, recorder, root, target, timeout=10.0,
        )
        engine.hold_evidence_for_aar()
        assert engine.start(
            jitter_range=(0.0, 0.0), noise_chance=0.0, complexity=1,
            campaign=True, target_dir=target, validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=30.0)
        assert not engine._thread.is_alive()

        # No Combat worker is enrolled here. Hold a genuinely registered
        # marker across normal FIM scans so the producer issues the receipt.
        held_marker = Path(next(
            path for completed_step in engine.steps
            for path in completed_step.artifact_paths
        ))
        held_identity = held_marker.stat(follow_symlinks=False)

        # A scan that overlaps exclusive marker creation correctly rejects
        # incomplete coverage and retries after its 30-second safety floor.
        deadline = time.monotonic() + 50.0
        while not any(valid for _event, valid, _generation in observed) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert any(valid for _event, valid, _generation in observed), {
            "signed_native_events": len(observed),
            "scan_generation": fim._scan_generation,
            "last_scan_receipt": fim._last_scan_receipt,
            "retry_floor": fim._scan_retry_floor,
            "held_marker_exists": held_marker.exists(),
        }
        authentic, _initially_valid, generation = next(
            row for row in observed if row[1]
        )
        details = authentic.details or {}
        step = {
            "attack_ids": [str(details["technique"])],
            "technique": f"{details['technique']} marker",
        }
        assert EventBus.verify(bus, authentic)
        tampered = replace(
            authentic,
            details={**details, "detector_receipt_mac": "00" * 64},
        )
        assert not EventBus.verify(bus, tampered)
        assert not verify_validation_native_event(lease, tampered, manager, step)
        assert not verify_validation_native_event(
            lease, authentic, manager,
            {"attack_ids": ["T0000"], "technique": "T0000 marker"},
        )

        deadline = time.monotonic() + 50.0
        while (
            (
                int(fim._last_scan_receipt.get("scan_generation", 0)) <= generation
                or fim._last_scan_receipt.get("complete") is not True
            )
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        assert (
            int(fim._last_scan_receipt.get("scan_generation", 0)) > generation
            and fim._last_scan_receipt.get("complete") is True
        ), fim._last_scan_receipt
        after_scan = held_marker.stat(follow_symlinks=False)
        assert (after_scan.st_dev, after_scan.st_ino) == (
            held_identity.st_dev, held_identity.st_ino,
        )
        assert verify_validation_native_event(lease, authentic, manager, step)

        result = generate_aar(
            root, history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK", report_basename="redteam_aar",
            recorder=recorder, bus=bus, manager=manager,
            validation_lease=lease, return_result=True,
        )
        assert isinstance(result, AARReportResult)
        report = json.loads((root / "redteam_aar.json").read_text(encoding="utf-8"))
        assert report["coverage_score_eligible"] is True
        assert report["evidence_taxonomy"]["native_analytic_detection"]["count"] >= 1
    finally:
        if engine.is_running:
            engine.stop_and_clean()
            if engine._thread is not None:
                engine._thread.join(timeout=3.0)
        try:
            scope = engine.evidence_cleanup_scope()
            engine.release_evidence_after_aar(scope)
        finally:
            if lease is not None:
                lease.release()
            guard.stop()
            fim.stop()
            recorder.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows held-marker disposal regression")
@pytest.mark.parametrize("replace_same_name", [False, True])
def test_stale_enrollment_discards_only_the_created_marker_and_stops(
    workspace_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replace_same_name: bool,
) -> None:
    """A producer dying after exclusive creation cannot orphan or misdelete a file."""
    root = workspace_tmp_path / "stale-runtime"
    target = root / "drill-sandbox"
    root.mkdir()
    monkeypatch.setenv("ANGERONA_DATA", str(root))

    from angerona.core import report_attest
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.storage import FlightRecorder
    from angerona.modules.purple_guard import (
        PurpleGuard,
        RedTeamValidationLease,
        acquire_redteam_validation_lease,
    )
    from angerona.shark.red_team import RedTeamEngine

    key_path = root / "bus.key"
    key_path.write_text("42" * 32, encoding="ascii")
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)

    bus = EventBus(ring_size=1024)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = PurpleGuard(root)
    guard.bind(bus)
    manager = SimpleNamespace(modules={guard.name: guard}, bus=bus)
    engine = RedTeamEngine(root, documents_dir=target)
    lease = None
    created: list[Path] = []
    displaced = target / "displaced-original.bin"
    replacement = b"unrelated same-name replacement"
    original_register = RedTeamValidationLease.register_artifact_handle

    def producer_dies_during_enrollment(
        live_lease: RedTeamValidationLease, path: Path, *, run_id: str,
    ) -> dict[str, object]:
        candidate = Path(path)
        created.append(candidate)
        assert candidate.exists()
        if replace_same_name:
            os.replace(candidate, displaced)
            candidate.write_bytes(replacement)
        guard.stop()
        return original_register(live_lease, candidate, run_id=run_id)

    try:
        lease = acquire_redteam_validation_lease(
            manager, bus, recorder, root, target, timeout=10.0,
        )
        monkeypatch.setattr(
            RedTeamValidationLease,
            "register_artifact_handle",
            producer_dies_during_enrollment,
        )
        engine.hold_evidence_for_aar()
        assert engine.start(
            jitter_range=(0.0, 0.0), noise_chance=0.0, complexity=1,
            campaign=True, target_dir=target, validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=15.0)
        assert not engine._thread.is_alive()
        assert len(created) == 1
        assert len(engine.steps) == 1
        assert engine.steps[0].ok is False

        history = json.loads(engine.history_path.read_text(encoding="utf-8"))
        assert history["status"] == "incomplete"
        assert history["campaign"]["score_eligible"] is False
        if replace_same_name:
            assert created[0].read_bytes() == replacement
            assert not displaced.exists(), "held original was not disposed"
        else:
            assert not created[0].exists(), "unenrolled marker was orphaned"
    finally:
        if engine.is_running:
            engine.stop_and_clean()
            if engine._thread is not None:
                engine._thread.join(timeout=3.0)
        try:
            scope = engine.evidence_cleanup_scope()
            engine.release_evidence_after_aar(scope)
        finally:
            if lease is not None:
                lease.release()
            guard.stop()
            recorder.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows exact marker handoff regression")
@pytest.mark.parametrize("replace_before_recapture", [False, True])
def test_failed_quarantine_commit_never_credits_replacement_marker(
    workspace_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replace_before_recapture: bool,
) -> None:
    """A failed terminal write restores exact custody or poisons the lease."""
    root = workspace_tmp_path / "failed-commit-runtime"
    target = root / "drill-sandbox"
    root.mkdir()
    monkeypatch.setenv("ANGERONA_DATA", str(root))
    monkeypatch.setenv("ANGERONA_SOAR_RESPONSE_SCOPE", str(target))

    from angerona.core import report_attest
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.storage import FlightRecorder
    from angerona.modules.adversary_combat import AdversaryCombat
    from angerona.modules.purple_guard import (
        PurpleGuard,
        RedTeamValidationLease,
        acquire_redteam_validation_lease,
    )
    from angerona.shark.red_team import RedTeamEngine

    key_path = root / "bus.key"
    key_path.write_text("42" * 32, encoding="ascii")
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)

    bus = EventBus(ring_size=2048)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = PurpleGuard(root)
    guard.bind(bus)
    combat = AdversaryCombat(data_root=root)
    combat.bind(bus)
    manager = SimpleNamespace(
        modules={guard.name: guard, combat.name: combat},
        bus=bus,
        config=SimpleNamespace(data_dir=root),
    )
    combat.bind_manager(manager)
    engine = RedTeamEngine(root, documents_dir=target)
    lease = None
    commit_attempts: list[str] = []
    displaced = target / "rolled-back-original.bin"
    try:
        lease = acquire_redteam_validation_lease(
            manager, bus, recorder, root, target, timeout=10.0,
        )
        engine.hold_evidence_for_aar()
        assert engine.start(
            jitter_range=(0.0, 0.0), noise_chance=0.0, complexity=1,
            campaign=True, target_dir=target, validation_lease=lease,
        )
        assert engine._thread is not None
        engine._thread.join(timeout=30.0)
        assert not engine._thread.is_alive()
        assert len(engine.steps) == 14

        expected_paths = {
            os.path.normcase(os.path.abspath(path))
            for step in engine.steps for path in step.artifact_paths
        }
        candidate_event = None
        deadline = time.monotonic() + 10.0
        while candidate_event is None and time.monotonic() < deadline:
            for event in recorder.events_in_window(
                engine.steps[0].ts_start - 2.0, time.time() + 1.0,
            ):
                details = event.details or {}
                path = details.get("path")
                if (
                    event.module == guard.name
                    and details.get("receipt_type") == "purple_simulation_validation"
                    and details.get("run_id") == engine.run_id
                    and path
                    and os.path.normcase(os.path.abspath(path)) in expected_paths
                    and Path(path).is_file()
                ):
                    candidate_event = event
                    break
            if candidate_event is None:
                time.sleep(0.05)
        assert candidate_event is not None
        source = Path(candidate_event.details["path"])
        original_content = source.read_bytes()
        original_stat = source.stat(follow_symlinks=False)

        original_append = combat._append_journal

        def fail_terminal_commit(payload: dict[str, object]) -> dict[str, object]:
            if (
                payload.get("record_type") == "commit"
                and payload.get("action") == "quarantine_file"
            ):
                commit_attempts.append(str(payload.get("action_id")))
                raise OSError("injected terminal journal failure")
            return original_append(payload)

        monkeypatch.setattr(combat, "_append_journal", fail_terminal_commit)
        if replace_before_recapture:
            original_abort = RedTeamValidationLease.abort_marker_containment

            def swap_same_bytes_before_recapture(
                live_lease: RedTeamValidationLease,
                worker: AdversaryCombat,
                path: Path,
                *,
                recapture: bool,
            ) -> None:
                if recapture:
                    os.replace(path, displaced)
                    Path(path).write_bytes(original_content)
                original_abort(live_lease, worker, path, recapture=recapture)

            monkeypatch.setattr(
                RedTeamValidationLease,
                "abort_marker_containment",
                swap_same_bytes_before_recapture,
            )

        action = combat._quarantine_file(
            str(source), candidate_event, "combat-000000000001",
        )
        assert commit_attempts, "quarantine did not cross the terminal writer"
        assert action is None
        assert not any(
            row.get("action") == "quarantine_file"
            and row.get("status") == "applied"
            for row in combat.list_actions(limit=None)
        )
        if replace_before_recapture:
            assert source.read_bytes() == original_content
            assert source.stat(follow_symlinks=False).st_ino != original_stat.st_ino
            assert not RedTeamValidationLease._state_matches(lease)
        else:
            restored = source.stat(follow_symlinks=False)
            assert (restored.st_dev, restored.st_ino) == (
                original_stat.st_dev, original_stat.st_ino,
            )
            assert RedTeamValidationLease._state_matches(lease)
    finally:
        if engine.is_running:
            engine.stop_and_clean()
            if engine._thread is not None:
                engine._thread.join(timeout=3.0)
        try:
            scope = engine.evidence_cleanup_scope()
            engine.release_evidence_after_aar(scope)
        finally:
            if lease is not None:
                lease.release()
            guard.stop()
            recorder.close()
