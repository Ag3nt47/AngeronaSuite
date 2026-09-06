from __future__ import annotations

import dataclasses
import hashlib
import os
import threading
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.storage import FlightRecorder
from angerona.modules import file_integrity, purple_guard
from angerona.modules.file_integrity import FileIntegrityModule
from angerona.modules.purple_guard import RedTeamValidationLease


_STEP = {"attack_ids": ["T1003"], "technique": "T1003 inert marker"}


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    key_path = tmp_path / "bus.key"
    key_path.write_text((b"d" * 32).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key_path))
    bus = EventBus(ring_size=1024)
    recorder = FlightRecorder(tmp_path / "flight-recorder.db")
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    guard = purple_guard.PurpleGuard(tmp_path)
    guard.bind(bus)
    fim = FileIntegrityModule()
    fim.bind(bus)
    fim._angerona_contract = SimpleNamespace(
        capability_id="angerona.builtin.file_integrity",
    )
    manager = SimpleNamespace(modules={guard.name: guard, fim.name: fim}, bus=bus)
    keep_alive = threading.Event()
    monkeypatch.setattr(fim, "run", lambda: keep_alive.wait(30.0))
    fim.start()
    target = tmp_path / "target"
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: [str(target)])
    lease = None
    try:
        lease = purple_guard.acquire_redteam_validation_lease(
            manager, bus, recorder, tmp_path, target, timeout=3,
        )
        RedTeamValidationLease.consume_for_run(
            lease, run_id="digest-fixture", target=target, data_root=tmp_path,
        )
        marker = target / "_redteam_lsass_dump_digest.txt"
        marker.write_text("harmless marker contents", encoding="utf-8")
        identity = RedTeamValidationLease.register_artifact_handle(
            lease, marker, run_id="digest-fixture",
        )
        yield SimpleNamespace(
            lease=lease, guard=guard, marker=marker, identity=identity,
            manager=manager, fim=fim, bus=bus,
        )
    finally:
        if lease is not None:
            RedTeamValidationLease.release(lease)
        keep_alive.set()
        fim.stop()
        guard.stop()
        recorder.close()


def _purple_event(runtime):
    proof = RedTeamValidationLease.attest_purple_detection(
        runtime.lease, runtime.guard, technique="T1003",
        observed_target=str(runtime.marker), evidence_kind="inert_file_marker",
    )
    assert proof
    proof.pop("_validated_process_create_time")
    return Event(runtime.guard.name, "inert signed marker evidence", Severity.HIGH,
                 details={**proof, "path": str(runtime.marker)})


def _verify(runtime, event):
    return RedTeamValidationLease.verify_purple_event(runtime.lease, event, _STEP)


def _resign(runtime, event, **updates):
    details = {**event.details, **updates}
    core = {key: value for key, value in details.items()
            if key not in {"path", "detector_receipt_mac"}}
    details["detector_receipt_mac"] = purple_guard._lease_authority(
        runtime.lease,
    )._sign_hmac(purple_guard._canonical_json(core))
    return dataclasses.replace(event, details=details)


def test_purple_digest_is_signed_and_bound_to_enrolled_content(runtime):
    event = _purple_event(runtime)
    assert event.details["redteam_detector_receipt_version"] == 2
    assert event.details["observed_content_sha256"] == hashlib.sha256(
        runtime.marker.read_bytes(),
    ).hexdigest()
    assert _verify(runtime, event)
    altered = dataclasses.replace(event, details={
        **event.details, "observed_content_sha256": "f" * 64,
    })
    assert not _verify(runtime, altered)
    # Even a correctly signed inconsistent digest cannot describe this object.
    assert not _verify(runtime, _resign(runtime, event, observed_content_sha256="f" * 64))
    for version in (0, 3, True, "2"):
        assert not _verify(runtime, _resign(runtime, event,
                                           redteam_detector_receipt_version=version))


def test_legacy_v1_never_supplies_an_unsigned_content_digest(runtime):
    event = _purple_event(runtime)
    details = dict(event.details)
    details.pop("observed_content_sha256")
    legacy = _resign(runtime, dataclasses.replace(event, details=details),
                     redteam_detector_receipt_version=1)
    assert _verify(runtime, legacy)
    for claimed in ("", event.details["observed_content_sha256"]):
        assert not _verify(runtime, dataclasses.replace(legacy, details={
            **legacy.details, "observed_content_sha256": claimed,
        }))


def test_quarantine_like_rename_preserves_report_evidence_not_issuance(runtime):
    event = _purple_event(runtime)
    held = runtime.marker.with_name("quarantined-inert-marker.txt")
    runtime.marker.rename(held)
    assert not runtime.marker.exists()
    assert _verify(runtime, event)
    state = purple_guard._lease_authority(runtime.lease)
    assert RedTeamValidationLease._validated_artifact_identity(state, str(runtime.marker)) == {}
    assert RedTeamValidationLease.attest_purple_detection(
        runtime.lease, runtime.guard, technique="T1003",
        observed_target=str(runtime.marker), evidence_kind="inert_file_marker",
    ) == {}
    # A different object at the original path cannot borrow the held identity.
    runtime.marker.write_text("replacement marker", encoding="utf-8")
    assert not _verify(runtime, event)
    runtime.marker.unlink()
    assert _verify(runtime, event)
    # Retain size and mtime to prove that content is independently rehashed.
    before = held.stat()
    held.write_bytes(b"x" * before.st_size)
    os.utime(held, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert not _verify(runtime, event)


def test_historical_identity_rejects_aliases_and_unavailable_path_status(runtime, monkeypatch):
    event = _purple_event(runtime)
    held = runtime.marker.with_name("held-inert-marker.txt")
    runtime.marker.rename(held)
    alias = held.with_name("extra-inert-hardlink.txt")
    os.link(held, alias)
    assert not _verify(runtime, event)
    alias.unlink()
    assert _verify(runtime, event)

    original_lstat = type(runtime.marker).lstat

    def unavailable(path):
        if path == runtime.marker:
            raise PermissionError("inert test denies path inspection")
        return original_lstat(path)

    monkeypatch.setattr(type(runtime.marker), "lstat", unavailable)
    assert not _verify(runtime, event)


def test_native_fim_receipt_survives_exact_held_object_rename(runtime):
    runtime.fim._evaluate_snapshot(runtime.fim._scan())
    event = next(row for row in runtime.bus.recent(100)
                 if row.module == runtime.fim.name
                 and row.details.get("detector_receipt_mac"))
    verify = lambda: RedTeamValidationLease.verify_native_event(
        runtime.lease, event, runtime.manager, _STEP,
    )
    assert verify()
    held = runtime.marker.with_name("native-quarantined-inert-marker.txt")
    runtime.marker.rename(held)
    assert verify()
    runtime.marker.write_text("unrelated replacement", encoding="utf-8")
    assert not verify()
