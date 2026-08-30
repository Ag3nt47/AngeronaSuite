from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.modules import purple_guard
from angerona.modules.file_integrity import FileIntegrityModule
from angerona.modules.purple_guard import RedTeamValidationLease
from angerona.shark import aar_report


_KEY = bytes.fromhex("a6" * 32)


def _install_keys(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    key_path = root / "bus.key"
    key_path.write_text(_KEY.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))


def _runtime(root: Path, monkeypatch: pytest.MonkeyPatch, *, fim: bool = False):
    _install_keys(monkeypatch, root)
    bus = EventBus(ring_size=1024)
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


def test_fim_native_proof_requires_one_real_internal_scan_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, fim, manager = _runtime(tmp_path, monkeypatch, fim=True)
    assert fim is not None
    keep_alive = threading.Event()
    monkeypatch.setattr(fim, "run", lambda: keep_alive.wait(10.0))
    fim.start()
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    marker = target / "_redteam_lsass_dump_sixth_scan.txt"
    try:
        run_id = "sixth-fim-scan"
        RedTeamValidationLease.consume_for_run(
            lease, run_id=run_id, target=target, data_root=tmp_path
        )
        marker.write_text("inert sixth-remediation marker", encoding="utf-8")
        RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id=run_id
        )
        digest = hashlib.sha256(marker.read_bytes()).hexdigest()

        fim._evaluate_snapshot({str(marker.resolve()): digest})
        assert not any(
            (row.details or {}).get("detector_receipt_mac")
            for row in bus.recent(50)
            if row.module == fim.name
        )

        monkeypatch.setattr(
            "angerona.modules.file_integrity.watch_roots",
            lambda: [str(target)],
        )
        snapshot = fim._scan()
        assert fim._last_scan_receipt["complete"] is True
        assert fim._last_scan_receipt["scan_generation"] == 1
        assert fim._last_scan_receipt["covered_roots"]
        fim._evaluate_snapshot(snapshot)

        event = next(
            row
            for row in reversed(bus.recent(100))
            if row.module == fim.name
            and (row.details or {}).get("detector_receipt_mac")
        )
        details = event.details or {}
        assert details["redteam_detector_receipt_version"] == 4
        assert details["fim_scan_receipt"]["scan_generation"] == 1
        assert details["fim_scan_coverage_root"]
        assert details["fim_scan_path_identity"]["change_token"] > 0
        assert purple_guard.verify_validation_native_event(
            lease,
            event,
            manager,
            {"attack_ids": ["T1003"], "technique": "T1003 marker"},
        )

        signed_count = sum(
            bool((row.details or {}).get("detector_receipt_mac"))
            for row in bus.recent(100)
            if row.module == fim.name
        )
        fim._evaluate_snapshot(snapshot)
        assert sum(
            bool((row.details or {}).get("detector_receipt_mac"))
            for row in bus.recent(100)
            if row.module == fim.name
        ) == signed_count
    finally:
        RedTeamValidationLease.release(lease)
        keep_alive.set()
        fim.stop()
        guard.stop()
        recorder.close()
        marker.unlink(missing_ok=True)


def test_verifier_dispatch_is_not_mutable_through_lease_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus, recorder, guard, _fim, manager = _runtime(tmp_path, monkeypatch)
    target = tmp_path / "target"
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, tmp_path, target, timeout=3
    )
    try:
        RedTeamValidationLease.consume_for_run(
            lease, run_id="sixth-dispatch", target=target, data_root=tmp_path
        )
        authority = purple_guard._lease_authority(lease)
        for name in (
            "verify_run_impl",
            "verify_native_impl",
            "verify_purple_impl",
            "authority_matches_impl",
        ):
            assert not hasattr(authority, name)
            with pytest.raises(AttributeError):
                setattr(authority, name, lambda *_args, **_kwargs: True)

        synthetic = Event(
            "File Integrity Monitor",
            "receipt-free synthetic row",
            Severity.HIGH,
            details={"path": str(target / "_redteam_lsass_dump_fake.txt")},
        )
        monkeypatch.setattr(
            RedTeamValidationLease,
            "verify_native_event",
            lambda *_args, **_kwargs: True,
        )
        assert not purple_guard.verify_validation_native_event(
            lease,
            synthetic,
            manager,
            {"attack_ids": ["T1003"], "technique": "T1003 marker"},
        )
    finally:
        RedTeamValidationLease.release(lease)
        guard.stop()
        recorder.close()


def _publish_test_report(root: Path, run_id: str) -> aar_report.AARReportResult:
    text = f"authenticated report {run_id}"
    payload = report_attest.attest(
        {
            "run_id": run_id,
            "report_kind": "red_team",
            "report_basename": "redteam_aar",
            "report_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        }
    )
    encoded = json.dumps(payload, indent=2)
    return aar_report._publish_report_bundle(
        root,
        {"run_id": run_id, "kind": "red_team"},
        basename="redteam_aar",
        text=text,
        encoded_payload=encoded,
        report_sha256=hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
    )


def test_fixed_head_detects_journal_rollback_and_blocks_gui_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_keys(monkeypatch, tmp_path)
    first = _publish_test_report(tmp_path, "sixth-aar-1")
    journal_path = tmp_path / "redteam_aar.heads.jsonl"
    journal_after_first = journal_path.read_bytes()
    second = _publish_test_report(tmp_path, "sixth-aar-2")
    assert second.sequence == 2
    assert aar_report.verified_aar_handoff_text(second) == second.text

    journal_path.write_bytes(journal_after_first)
    with pytest.raises(ValueError, match="journal rollback detected"):
        _publish_test_report(tmp_path, "sixth-aar-fork")
    assert len(aar_report._load_head_journal(journal_path, "redteam_aar")) == 1
    assert json.loads((tmp_path / "redteam_aar.head.json").read_bytes())[
        "sequence"
    ] == 2
    for handoff in (first, second):
        with pytest.raises(ValueError, match="stale|rolled back|current journal"):
            aar_report.verified_aar_handoff_text(handoff)
