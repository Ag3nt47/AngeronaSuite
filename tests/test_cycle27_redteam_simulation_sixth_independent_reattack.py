from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.modules import file_integrity, purple_guard
from angerona.modules.file_integrity import FileIntegrityModule
from angerona.modules.purple_guard import RedTeamValidationLease
from angerona.shark import aar_report
from angerona.shark.aar_report import AARReportResult, generate_aar
from angerona.shark.red_team import REDTEAM_STAGE_CATEGORY
from angerona.shark.run_manifest import build_run_history, preflight_run, write_run_history


_KEY = bytes.fromhex("b7" * 32)
_STEP = {"attack_ids": ["T1003"], "technique": "T1003 marker"}


def _install_keys(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    key_path = root / "bus.key"
    key_path.write_text(_KEY.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))


def _runtime(root: Path, monkeypatch: pytest.MonkeyPatch, *, fim: bool = False):
    _install_keys(monkeypatch, root)
    bus = EventBus(ring_size=4096)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = purple_guard.PurpleGuard(root)
    guard.bind(bus)
    modules: dict[str, object] = {guard.name: guard}
    file_monitor = None
    if fim:
        file_monitor = FileIntegrityModule()
        file_monitor.bind(bus)
        file_monitor._angerona_contract = SimpleNamespace(  # type: ignore[attr-defined]
            capability_id="angerona.builtin.file_integrity"
        )
        modules[file_monitor.name] = file_monitor
    manager = SimpleNamespace(modules=modules, bus=bus)
    return bus, recorder, guard, file_monitor, manager


def _start_fim(
    root: Path, monkeypatch: pytest.MonkeyPatch, *, run_id: str
) -> tuple[EventBus, FlightRecorder, object, FileIntegrityModule, object, object, threading.Event, Path]:
    bus, recorder, guard, fim, manager = _runtime(root, monkeypatch, fim=True)
    assert fim is not None
    keep_alive = threading.Event()
    monkeypatch.setattr(fim, "run", lambda: keep_alive.wait(10.0))
    fim.start()
    target = root / "target"
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: [str(target)])
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, root, target, timeout=3
    )
    RedTeamValidationLease.consume_for_run(
        lease, run_id=run_id, target=target, data_root=root
    )
    return bus, recorder, guard, fim, manager, lease, keep_alive, target


def _signed_fim_event(
    bus: EventBus, fim: FileIntegrityModule, marker: Path
) -> Event:
    marker_path = os.path.normcase(os.path.abspath(marker))
    return next(
        row
        for row in reversed(bus.recent(200))
        if row.module == fim.name
        and os.path.normcase(
            os.path.abspath(str((row.details or {}).get("path") or ""))
        )
        == marker_path
        and (row.details or {}).get("detector_receipt_mac")
    )


def _stop_fim(
    recorder: FlightRecorder,
    guard: object,
    fim: FileIntegrityModule,
    lease: object,
    keep_alive: threading.Event,
) -> None:
    RedTeamValidationLease.release(lease)
    keep_alive.set()
    fim.stop()
    guard.stop()
    recorder.close()


def test_post_scan_mutation_cannot_add_an_unscanned_artifact_to_receipt_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scan receipt must describe the bytes captured during `_scan`, not later."""
    bus, recorder, guard, fim, manager, lease, keep_alive, target = _start_fim(
        tmp_path, monkeypatch, run_id="sixth-independent-post-scan-mutation"
    )
    marker = target / "_redteam_lsass_dump_post_scan_mutation.txt"
    try:
        snapshot = fim._scan()
        assert not snapshot
        assert snapshot._fim_receipt["files_recorded"] == 0

        marker.write_text("created only after the scan completed", encoding="utf-8")
        RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id="sixth-independent-post-scan-mutation"
        )
        path = str(marker.resolve())
        digest = hashlib.sha256(marker.read_bytes()).hexdigest()
        identity = fim._stat(path)
        assert identity is not None

        # Hostile same-process extension mutates every mutable field checked by
        # the claimant.  None of these values came from the completed scan.
        snapshot[path] = digest
        snapshot._fim_identities[path] = identity
        receipt = snapshot._fim_receipt
        receipt["files_visited"] = 1
        receipt["files_recorded"] = 1
        receipt["files_hashed"] = 1
        receipt["hashes_reused"] = 0
        receipt["content_bytes_hashed"] = len(marker.read_bytes())
        receipt["snapshot_sha256"] = file_integrity._fim_proof_digest(
            dict(sorted(snapshot.items()))
        )
        snapshot._fim_coverage_sha256 = file_integrity._fim_proof_digest(receipt)

        fim._evaluate_snapshot(snapshot)
        minted = [
            row
            for row in bus.recent(200)
            if row.module == fim.name
            and str((row.details or {}).get("path") or "") == path
            and (row.details or {}).get("detector_receipt_mac")
        ]
        accepted = [
            row
            for row in minted
            if purple_guard.verify_validation_native_event(lease, row, manager, _STEP)
        ]
        assert not accepted, "post-scan mutable state minted an accepted scan receipt"
        assert not minted, "post-scan mutable state minted a scan-authenticated receipt"
    finally:
        _stop_fim(recorder, guard, fim, lease, keep_alive)
        marker.unlink(missing_ok=True)


def test_consumed_scan_generation_cannot_be_rearmed_for_a_second_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One-use must be enforced by issuer custody, not a writable boolean."""
    bus, recorder, guard, fim, manager, lease, keep_alive, target = _start_fim(
        tmp_path, monkeypatch, run_id="sixth-independent-scan-replay"
    )
    marker = target / "_redteam_lsass_dump_scan_replay.txt"
    try:
        marker.write_text("one inert artifact", encoding="utf-8")
        RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id="sixth-independent-scan-replay"
        )
        snapshot = fim._scan()
        fim._evaluate_snapshot(snapshot)
        marker_path = os.path.normcase(os.path.abspath(marker))
        first_count = sum(
            bool((row.details or {}).get("detector_receipt_mac"))
            for row in bus.recent(200)
            if row.module == fim.name
            and os.path.normcase(
                os.path.abspath(str((row.details or {}).get("path") or ""))
            )
            == marker_path
        )
        assert first_count == 1

        snapshot._fim_consumed = False
        fim._pending_scan_snapshot = snapshot
        fim._evaluate_snapshot(snapshot)

        final_receipts = [
            row
            for row in bus.recent(200)
            if row.module == fim.name
            and os.path.normcase(
                os.path.abspath(str((row.details or {}).get("path") or ""))
            )
            == marker_path
            and (row.details or {}).get("detector_receipt_mac")
        ]
        assert all(
            purple_guard.verify_validation_native_event(lease, row, manager, _STEP)
            for row in final_receipts
        )
        final_count = len(final_receipts)
        assert final_count == first_count, "a consumed scan generation was rearmed"
    finally:
        _stop_fim(recorder, guard, fim, lease, keep_alive)
        marker.unlink(missing_ok=True)


def test_captured_verifier_closure_cell_cannot_redirect_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Captured callables are mutable through ordinary Python closure cells."""
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        RedTeamValidationLease.consume_for_run(
            lease, run_id="sixth-independent-closure", target=target, data_root=tmp_path
        )
        synthetic = Event(
            "File Integrity Monitor",
            "receipt-free synthetic event",
            Severity.HIGH,
            details={"path": str(target / "_redteam_lsass_dump_closure.txt")},
        )
        wrapper = purple_guard.verify_validation_native_event
        cells = dict(zip(wrapper.__code__.co_freevars, wrapper.__closure__ or ()))
        verifier_cell = cells["verify_native_impl"]
        original = verifier_cell.cell_contents
        assert not wrapper(lease, synthetic, manager, _STEP)
        try:
            verifier_cell.cell_contents = lambda *_args, **_kwargs: True
            assert not wrapper(
                lease, synthetic, manager, _STEP
            ), "mutable closure cell redirected proof acceptance"
        finally:
            verifier_cell.cell_contents = original
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


_NATIVE_RECEIPT_KEYS = {
    "redteam_detector_receipt_version",
    "receipt_type",
    "lease_id",
    "receipt_id",
    "run_id",
    "target",
    "producer_module",
    "producer_capability_id",
    "producer_generation",
    "producer_observation_serial",
    "producer_observation_site_sha256",
    "producer_trust_boundary",
    "evidence_digest",
    "technique",
    "artifact_identity_sha256",
    "observed_content_sha256",
    "change_kind",
    "process_identity_sha256",
    "fim_scan_receipt",
    "fim_scan_coverage_sha256",
    "fim_scan_coverage_root",
    "fim_scan_path_identity",
    "fim_scan_path_identity_sha256",
    "event_nonce",
    "observed_at",
    "evidence_type",
    "detector_verdict",
}


def test_module_reachable_authority_cannot_forge_a_new_native_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A private registry accessor must not expose a live signing primitive."""
    bus, recorder, guard, fim, manager, lease, keep_alive, target = _start_fim(
        tmp_path, monkeypatch, run_id="sixth-independent-forgery"
    )
    marker = target / "_redteam_lsass_dump_authority_forgery.txt"
    try:
        marker.write_text("inert signed source", encoding="utf-8")
        RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id="sixth-independent-forgery"
        )
        snapshot = fim._scan()
        fim._evaluate_snapshot(snapshot)
        source = _signed_fim_event(bus, fim, marker)
        assert purple_guard.verify_validation_native_event(
            lease, source, manager, _STEP
        )

        core = {
            key: (source.details or {}).get(key) for key in _NATIVE_RECEIPT_KEYS
        }
        core["event_nonce"] = "f0" * 16
        authority = purple_guard._lease_authority(lease)
        forged_details = {
            **(source.details or {}),
            **core,
            "detector_receipt_mac": hmac.new(
                authority.key,
                purple_guard._canonical_json(core),
                hashlib.sha256,
            ).hexdigest(),
        }
        forged = Event(
            source.module,
            source.message,
            source.severity,
            details=forged_details,
        )
        assert not purple_guard.verify_validation_native_event(
            lease, forged, manager, _STEP
        ), "module-reachable authority state forged an accepted receipt"
    finally:
        _stop_fim(recorder, guard, fim, lease, keep_alive)
        marker.unlink(missing_ok=True)


def _publish_test_report(root: Path, run_id: str) -> AARReportResult:
    text = f"authenticated report {run_id}"
    payload = report_attest.attest(
        {
            "run_id": run_id,
            "report_kind": "red_team",
            "report_basename": "redteam_aar",
            "report_text_sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
    )
    encoded = json.dumps(payload, indent=2)
    return aar_report._publish_report_bundle(
        root,
        {"run_id": run_id, "kind": "red_team"},
        basename="redteam_aar",
        text=text,
        encoded_payload=encoded,
        report_sha256=hashlib.sha256(encoded.encode()).hexdigest(),
    )


def test_fixed_head_journal_and_handoff_reject_prefix_and_field_swaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_keys(monkeypatch, tmp_path)
    first = _publish_test_report(tmp_path, "sixth-independent-aar-1")
    second = _publish_test_report(tmp_path, "sixth-independent-aar-2")
    assert aar_report.verified_aar_handoff_text(second) == second.text

    for swapped in (
        dataclasses.replace(second, text=first.text),
        dataclasses.replace(second, text_bytes=first.text_bytes),
        dataclasses.replace(
            second,
            journal_record_bytes=first.journal_record_bytes,
            journal_record_sha256=first.journal_record_sha256,
        ),
    ):
        with pytest.raises(ValueError):
            aar_report.verified_aar_handoff_text(swapped)

    journal_path = tmp_path / "redteam_aar.heads.jsonl"
    rows = [row for row in journal_path.read_bytes().splitlines() if row]
    assert len(rows) == 2
    journal_path.write_bytes(rows[1] + b"\n")
    with pytest.raises(ValueError, match="chain|predecessor|binding"):
        aar_report._load_head_journal(journal_path, "redteam_aar")
    with pytest.raises(ValueError):
        aar_report.verified_aar_handoff_text(second)


def test_native_receipt_is_bound_to_exact_module_object_and_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, fim, manager, lease, keep_alive, target = _start_fim(
        tmp_path, monkeypatch, run_id="sixth-independent-object-generation"
    )
    marker = target / "_redteam_lsass_dump_generation.txt"
    try:
        marker.write_text("inert object-bound source", encoding="utf-8")
        RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id="sixth-independent-object-generation"
        )
        snapshot = fim._scan()
        fim._evaluate_snapshot(snapshot)
        source = _signed_fim_event(bus, fim, marker)
        assert purple_guard.verify_validation_native_event(
            lease, source, manager, _STEP
        )

        replacement = FileIntegrityModule()
        manager.modules[fim.name] = replacement
        assert not purple_guard.verify_validation_native_event(
            lease, source, manager, _STEP
        )
        manager.modules[fim.name] = fim

        fim._lifecycle_generation += 1
        assert not purple_guard.verify_validation_native_event(
            lease, source, manager, _STEP
        )
    finally:
        manager.modules[fim.name] = fim
        _stop_fim(recorder, guard, fim, lease, keep_alive)
        marker.unlink(missing_ok=True)


def test_incomplete_authenticated_campaign_keeps_mandatory_13_denominator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        decision = preflight_run(
            kind="red_team",
            cycles=1,
            jitter_range=(0.0, 0.0),
            noise_chance=0,
            target_dir=target,
            campaign=True,
        )
        assert decision.accepted
        receipt = RedTeamValidationLease.consume_for_run(
            lease,
            run_id="sixth-independent-denominator",
            target=target,
            data_root=tmp_path,
            run_ttl_seconds=float(decision.budget["admitted_run_ttl_seconds"]),
        )
        started = time.time()
        history = build_run_history(
            kind="red_team",
            run_id="sixth-independent-denominator",
            generated="2026-08-28 00:00:00",
            steps=[
                {
                    "stage": "execution",
                    "technique": "T1059 - Command and Scripting Interpreter",
                    "description": "duplicate-only inert campaign row",
                    "ts_start": started,
                    "ts_end": started + 0.001,
                    "artifact_paths": [],
                    "ok": True,
                    "cycle": 1,
                    "plan_step_id": "red_team:1:execution:T1059",
                }
            ]
            * 2,
            preflight=decision,
            status="completed",
        )
        history["validation_readiness"] = receipt
        assert write_run_history(tmp_path / "redteam_history.json", history)
        result = generate_aar(
            tmp_path,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
            recorder=recorder,
            bus=bus,
            manager=manager,
            validation_lease=lease,
            return_result=True,
        )
        assert isinstance(result, AARReportResult)
        payload = json.loads(result.report_bytes)
        assert payload["detection_steps"] == 13
        assert payload["coverage_score_eligible"] is False
        assert payload["evidence_taxonomy"]["simulation_contract_validation"][
            "rate"
        ] is None
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()
