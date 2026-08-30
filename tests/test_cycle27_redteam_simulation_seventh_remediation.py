from __future__ import annotations

import dataclasses
import hashlib
import hmac
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.modules import file_integrity, purple_guard
from angerona.modules.file_integrity import FileIntegrityModule
from angerona.modules.purple_guard import RedTeamValidationLease


_KEY = bytes.fromhex("c7" * 32)
_STEP = {"attack_ids": ["T1003"], "technique": "T1003 marker"}


def _install_keys(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    key_path = root / "bus.key"
    key_path.write_text(_KEY.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))


def _start_fim(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    run_id: str,
) -> tuple[
    EventBus,
    FlightRecorder,
    object,
    FileIntegrityModule,
    object,
    object,
    threading.Event,
    Path,
]:
    _install_keys(monkeypatch, root)
    bus = EventBus(ring_size=2048)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = purple_guard.PurpleGuard(root)
    guard.bind(bus)
    fim = FileIntegrityModule()
    fim.bind(bus)
    fim._angerona_contract = SimpleNamespace(  # type: ignore[attr-defined]
        capability_id="angerona.builtin.file_integrity"
    )
    manager = SimpleNamespace(
        modules={guard.name: guard, fim.name: fim},
        bus=bus,
    )
    keep_alive = threading.Event()
    monkeypatch.setattr(fim, "run", lambda: keep_alive.wait(10.0))
    fim.start()
    target = root / "target"
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: [str(target)])
    lease = purple_guard.acquire_redteam_validation_lease(
        manager, bus, recorder, root, target, timeout=3
    )
    RedTeamValidationLease.consume_for_run(
        lease,
        run_id=run_id,
        target=target,
        data_root=root,
    )
    return bus, recorder, guard, fim, manager, lease, keep_alive, target


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


def _signed_events(bus: EventBus, fim: FileIntegrityModule, marker: Path) -> list[Event]:
    normalized = os.path.normcase(os.path.abspath(marker))
    return [
        row
        for row in bus.recent(200)
        if row.module == fim.name
        and os.path.normcase(
            os.path.abspath(str((row.details or {}).get("path") or ""))
        )
        == normalized
        and bool((row.details or {}).get("detector_receipt_mac"))
    ]


def test_fim_custody_is_immutable_and_mutated_view_burns_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus, recorder, guard, fim, _manager, lease, keep_alive, target = _start_fim(
        tmp_path, monkeypatch, run_id="seventh-custody"
    )
    marker = target / "_redteam_lsass_dump_seventh_custody.txt"
    try:
        snapshot = fim._scan()
        custody = fim._pending_scan_custody
        assert custody is not None
        with pytest.raises(dataclasses.FrozenInstanceError):
            custody.scan_generation = 99  # type: ignore[misc]

        marker.write_text("created after immutable scan custody", encoding="utf-8")
        RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id="seventh-custody"
        )
        path = str(marker.resolve())
        digest = hashlib.sha256(marker.read_bytes()).hexdigest()
        identity = fim._stat(path)
        assert identity is not None
        snapshot[path] = digest
        snapshot._fim_identities[path] = identity

        fim._evaluate_snapshot(snapshot)
        assert not _signed_events(bus, fim, marker)
        assert fim._consumed_scan_generation == custody.scan_generation
        assert fim._pending_scan_custody is None

        snapshot._fim_consumed = False
        fim._pending_scan_snapshot = snapshot
        fim._evaluate_snapshot(snapshot)
        assert not _signed_events(bus, fim, marker)
    finally:
        _stop_fim(recorder, guard, fim, lease, keep_alive)
        marker.unlink(missing_ok=True)


def test_only_exact_current_scan_generation_can_issue_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus, recorder, guard, fim, manager, lease, keep_alive, target = _start_fim(
        tmp_path, monkeypatch, run_id="seventh-generation"
    )
    marker = target / "_redteam_lsass_dump_seventh_generation.txt"
    try:
        marker.write_text("inert exact-generation marker", encoding="utf-8")
        RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id="seventh-generation"
        )
        stale = fim._scan()
        current = fim._scan()
        assert stale._fim_receipt["scan_generation"] + 1 == current._fim_receipt[
            "scan_generation"
        ]

        fim._evaluate_snapshot(stale)
        assert not _signed_events(bus, fim, marker)
        fim._evaluate_snapshot(current)
        signed = _signed_events(bus, fim, marker)
        assert len(signed) == 1
        assert purple_guard.verify_validation_native_event(
            lease, signed[0], manager, _STEP
        )

        current._fim_consumed = False
        fim._pending_scan_snapshot = current
        fim._evaluate_snapshot(current)
        assert len(_signed_events(bus, fim, marker)) == 1
    finally:
        _stop_fim(recorder, guard, fim, lease, keep_alive)
        marker.unlink(missing_ok=True)


def test_native_receipts_use_public_key_verification_not_reachable_hmac_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus, recorder, guard, fim, manager, lease, keep_alive, target = _start_fim(
        tmp_path, monkeypatch, run_id="seventh-public-verifier"
    )
    marker = target / "_redteam_lsass_dump_seventh_public_verifier.txt"
    try:
        marker.write_text("inert public-verifier marker", encoding="utf-8")
        RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id="seventh-public-verifier"
        )
        fim._evaluate_snapshot(fim._scan())
        source = _signed_events(bus, fim, marker)[0]
        details = source.details or {}
        assert len(str(details["detector_receipt_mac"])) == 128
        assert details["producer_trust_boundary"] == (
            "same-process-simulation-validation"
        )
        assert purple_guard.verify_validation_native_event(
            lease, source, manager, _STEP
        )

        core_keys = {
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
        core = {key: details.get(key) for key in core_keys}
        core["event_nonce"] = "e7" * 16
        authority = purple_guard._lease_authority(lease)
        forged = Event(
            source.module,
            source.message,
            source.severity,
            details={
                **details,
                **core,
                "detector_receipt_mac": hmac.new(
                    authority.key,
                    purple_guard._canonical_json(core),
                    hashlib.sha256,
                ).hexdigest(),
            },
        )
        assert not purple_guard.verify_validation_native_event(
            lease, forged, manager, _STEP
        )
        with pytest.raises(AttributeError):
            authority.key = b"x" * 32  # type: ignore[misc]
        for opaque_name in (
            "native_modules",
            "native_generations",
            "native_capabilities",
            "native_verifiers",
            "fim_scan_claims",
        ):
            assert not hasattr(authority, opaque_name)
            with pytest.raises(AttributeError):
                setattr(authority, opaque_name, {})
    finally:
        _stop_fim(recorder, guard, fim, lease, keep_alive)
        marker.unlink(missing_ok=True)


def test_public_verifier_closure_cell_is_not_the_dispatch_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus, recorder, guard, _fim, manager, lease, keep_alive, target = _start_fim(
        tmp_path, monkeypatch, run_id="seventh-verifier-dispatch"
    )
    wrapper = purple_guard.verify_validation_native_event
    cells = dict(zip(wrapper.__code__.co_freevars, wrapper.__closure__ or ()))
    verifier_cell = cells["verify_native_impl"]
    original = verifier_cell.cell_contents
    synthetic = Event(
        "File Integrity Monitor",
        "receipt-free synthetic event",
        Severity.HIGH,
        details={"path": str(target / "_redteam_lsass_dump_seventh_fake.txt")},
    )
    try:
        assert not wrapper(lease, synthetic, manager, _STEP)
        verifier_cell.cell_contents = lambda *_args, **_kwargs: True
        assert not wrapper(lease, synthetic, manager, _STEP)
    finally:
        verifier_cell.cell_contents = original
        _stop_fim(recorder, guard, _fim, lease, keep_alive)
