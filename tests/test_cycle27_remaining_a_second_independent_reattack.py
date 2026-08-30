from __future__ import annotations

import base64
import hashlib
import hmac
import os
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.durable_outbox import DurableOutbox
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules import adversary_combat as combat_module
from angerona.modules import av_telemetry_bridge as av_module
from angerona.modules.adversary_combat import (
    AdversaryCombat,
    CombatAction,
    JournalIntegrityError,
)
from angerona.modules.av_telemetry_bridge import AVTelemetryBridgeModule
from angerona.modules.deception import DeceptionModule
from angerona.modules.driver_provenance_guard import (
    SCHEMA,
    DriverCollection,
    DriverLoadReceipt,
    DriverLoadReceiptVerifier,
    DriverProvenanceEvidence,
    DriverProvenanceGuard,
    assess_driver_provenance,
)


_CONTINUITY_KEY = b"i" * 32
_DRIVER_IDS = {
    "authority_id": "1" * 64,
    "host_id": "2" * 64,
    "install_id": "3" * 64,
    "boot_id": "4" * 64,
}
_DRIVER_NOW = 1_800_000_000.0


def _combat_action() -> CombatAction:
    return CombatAction(
        action_id="act-0000000000000001",
        combat_id="combat-000000000001",
        action="activate_honeypots",
        applied_at=100.0,
        reversible=True,
        target="Smart Deception",
        details={
            "module": "Smart Deception",
            "nested": {
                "authority": "journal-authenticated",
                "history": [{"generation": 1, "state": "trusted"}],
            },
        },
        trigger_module="inert-second-independent-reattack",
        trigger_ts=99.0,
        status="applied",
    )


def _defender_record(number: int, *, stamp: str = "2026-08-28T12:00:00Z") -> object:
    return SimpleNamespace(
        RecordNumber=number,
        EventID=1116,
        TimeGenerated=stamp,
        StringInserts=None,
    )


def _quarantine_event() -> Event:
    return Event(
        "inert-second-independent-reattack",
        "inert quarantine custody fixture",
        Severity.HIGH,
        details={"response_authorized": True},
    )


def _driver_fixture() -> tuple[
    Ed25519PrivateKey,
    DriverLoadReceipt,
    DriverProvenanceEvidence,
]:
    private = Ed25519PrivateKey.generate()
    receipt = DriverLoadReceipt.issue(
        private,
        **_DRIVER_IDS,
        load_generation=7,
        driver_token="a" * 64,
        object_identity="5" * 64,
        image_base=0x100000,
        image_size=4096,
        image_sha256="b" * 64,
        load_state="running",
        code_integrity_disposition="trusted",
        issued_at=_DRIVER_NOW,
        expires_at=_DRIVER_NOW + 60.0,
    )
    evidence = DriverProvenanceEvidence(
        schema=SCHEMA,
        driver_token="a" * 64,
        image_sha256="b" * 64,
        image_size=4096,
        load_state="running",
        binding_state="loaded-image-bound",
        binding_source="kernel-load-receipt",
        binding_receipt_sha256=receipt.digest(),
        signer_status="trusted",
        signer_thumbprint="c" * 40,
        catalog_status="trusted",
        blocklist_status="not-listed",
        blocklist_source="local-hash-policy",
        hvci_enabled=True,
        secure_boot=True,
        observed_at=_DRIVER_NOW,
        binding_receipt=receipt,
    )
    return private, receipt, evidence


def _driver_verifier(private: Ed25519PrivateKey) -> DriverLoadReceiptVerifier:
    return DriverLoadReceiptVerifier(
        private.public_key(),
        **_DRIVER_IDS,
        clock=lambda: _DRIVER_NOW,
    )


def test_a02_trusted_action_egress_cannot_mutate_nested_cache_authority(
    tmp_path: Path,
) -> None:
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    action = _combat_action()

    with module._receipt_lock:
        with module._journal_writer_lease():
            with module._pinned_journal_session(create=True):
                module._journal_intent(action)
                module._journal_commit(action)
                escaped, _undone = module._trusted_action(action.action_id)
                assert escaped is not None
                escaped["details"]["nested"]["authority"] = "forged"
                escaped["details"]["nested"]["history"][0]["state"] = "forged"
                retained, undone = module._trusted_action(action.action_id)

    assert retained is not None and undone is False
    assert retained["details"]["nested"]["authority"] == "journal-authenticated"
    assert retained["details"]["nested"]["history"] == [
        {"generation": 1, "state": "trusted"}
    ]


def test_a02_same_metadata_interior_tamper_disarms_cached_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    monkeypatch.setattr(module, "_journal_fingerprint", lambda _info: (7,))
    action = _combat_action()
    module._journal_intent(action)
    module._journal_commit(action)
    before = module.receipt_path.stat()
    raw = module.receipt_path.read_bytes()
    forged = raw.replace(
        b"journal-authenticated", b"j0urnal-authenticated", 1
    )
    assert len(forged) == len(raw) and forged != raw
    module.receipt_path.write_bytes(forged)
    os.utime(
        module.receipt_path,
        ns=(int(before.st_atime_ns), int(before.st_mtime_ns)),
    )

    with module._receipt_lock:
        with module._journal_writer_lease():
            with module._pinned_journal_session(create=False):
                with pytest.raises(JournalIntegrityError, match="interior checkpoint"):
                    module._trusted_action(action.action_id)

    assert module.response_ready() is False


def test_a03_terminal_hardlink_attempt_cannot_coexist_with_applied_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "terminal-source.bin"
    alias = tmp_path / "terminal-alias.bin"
    source.write_bytes(b"inert terminal hard-link boundary")
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    original_append = module._append_journal
    link_error: OSError | None = None

    def append_with_terminal_race(payload: dict[str, object]) -> dict[str, object]:
        nonlocal link_error
        if payload.get("record_type") == "commit":
            details = payload.get("details")
            assert isinstance(details, dict)
            try:
                os.link(Path(str(details["quarantine"])), alias)
            except OSError as exc:
                link_error = exc
        return original_append(payload)

    monkeypatch.setattr(module, "_append_journal", append_with_terminal_race)
    result = module._quarantine_file(
        str(source), _quarantine_event(), "combat-000000000001"
    )
    applied = [
        row
        for row in module.list_actions(limit=None)
        if row.get("action") == "quarantine_file"
        and row.get("status") == "applied"
    ]

    if alias.exists():
        destination = Path(str(alias))
        assert destination.read_bytes() == b"inert terminal hard-link boundary"
        assert destination.stat().st_nlink == 2
        assert result is None
        assert applied == []
    else:
        assert link_error is not None
        assert result is not None
        assert Path(result.details["quarantine"]).stat().st_nlink == 1


def test_a03_failed_terminal_proof_survives_failed_rollback_and_restart_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "orphan-source.bin"
    content = b"inert orphan restart recovery fixture"
    source.write_bytes(content)
    real_pinned = combat_module._PinnedFileMove

    class TerminalProofFailure(real_pinned):
        checks = 0

        def require_single_link(self) -> int:
            type(self).checks += 1
            if type(self).checks == 5:
                raise OSError("inert terminal proof failure")
            return super().require_single_link()

    monkeypatch.setattr(combat_module, "_PinnedFileMove", TerminalProofFailure)
    anchor: dict[str, str] = {}
    first = AdversaryCombat(tmp_path, rollback_anchor=anchor)
    monkeypatch.setattr(
        first,
        "_undo_record",
        lambda _record: (False, "inert first rollback unavailable"),
    )

    result = first._quarantine_file(
        str(source), _quarantine_event(), "combat-000000000002"
    )
    pending = first._pending_recovery_records()

    assert result is None
    assert not source.exists()
    assert len(pending) == 1
    assert first._mutation_blocked is True

    restarted = AdversaryCombat(tmp_path, rollback_anchor=anchor)
    assert restarted._reconcile_state() is True
    assert source.read_bytes() == content
    assert restarted._pending_recovery_records() == {}


def test_a07_subscriber_failure_remains_pending_across_restart(tmp_path: Path) -> None:
    bus = EventBus()
    bus.subscribe(lambda _event: (_ for _ in ()).throw(RuntimeError("inert reject")))
    first = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    first.bind(bus)
    assert first._open_continuity_state() is True
    first._stage_native_record(_defender_record(1))
    assert first._outbox is not None
    assert first._current_record_id() == 0
    assert first._outbox.stats().pending == 1
    first._close_continuity_state()

    restarted = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    restarted.bind(EventBus())
    assert restarted._open_continuity_state() is True
    assert restarted._outbox is not None
    assert restarted._current_record_id() == 0
    assert restarted._outbox.stats().pending == 1
    assert restarted.health < 100
    restarted._close_continuity_state()


def test_a07_conflicting_same_cursor_anchor_is_rejected_before_publish(
    tmp_path: Path,
) -> None:
    bus = EventBus()
    module = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    module.bind(bus)
    assert module._open_continuity_state() is True
    module._stage_native_record(_defender_record(1, stamp="2026-08-28T12:00:00Z"))
    delivered_before = sum(
        event.details.get("channel_record_id") == 1 for event in bus.recent(50)
    )

    module._stage_native_record(_defender_record(1, stamp="2026-08-28T12:00:01Z"))
    delivered_after = sum(
        event.details.get("channel_record_id") == 1 for event in bus.recent(50)
    )
    gap_count = module._continuity_gaps
    pending = module._outbox.stats().pending if module._outbox is not None else -1
    module._close_continuity_state()

    assert delivered_before == 1
    assert delivered_after == delivered_before, (
        f"conflicting anchor published: before={delivered_before} "
        f"after={delivered_after} gaps={gap_count} pending={pending}"
    )
    assert gap_count > 0
    assert module._current_record_id() == 1


def test_a07_older_retry_cannot_regress_cursor_or_republish(
    tmp_path: Path,
) -> None:
    bus = EventBus()
    module = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    module.bind(bus)
    assert module._open_continuity_state() is True
    module._stage_native_record(_defender_record(1))
    module._stage_native_record(_defender_record(2))
    delivered_before = sum(
        event.details.get("channel_record_id") == 1 for event in bus.recent(50)
    )

    module._stage_native_record(
        _defender_record(1, stamp="2026-08-28T12:00:02Z")
    )

    delivered_after = sum(
        event.details.get("channel_record_id") == 1 for event in bus.recent(50)
    )
    assert module._current_record_id() == 2
    assert delivered_after == delivered_before
    assert module.health < 100
    module._close_continuity_state()


def test_a07_authenticated_gap_remains_degraded_after_quiet_restart(
    tmp_path: Path,
) -> None:
    first = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    first.bind(EventBus())
    assert first._open_continuity_state() is True
    first._stage_native_record(_defender_record(10))
    first._continuity_gap(
        "inert retained-history discontinuity",
        reason_code="defender.inert.second_reattack_gap",
        missing_start=1,
        missing_end=9,
    )
    first._close_continuity_state()

    restarted = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    restarted.bind(EventBus())
    assert restarted._open_continuity_state() is True
    assert restarted.health == 45
    assert restarted._persisted_gap is True
    assert "gap" in restarted.health_note.casefold()
    restarted._close_continuity_state()


def test_a07_enrolled_outbox_plain_deletion_fails_closed(tmp_path: Path) -> None:
    initial = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    initial.bind(EventBus())
    assert initial._open_continuity_state() is True
    initial._close_continuity_state()
    outbox_path = tmp_path / "outbox" / "defender.sqlite3"
    outbox_path.unlink()

    restarted = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    restarted.bind(EventBus())

    assert restarted._open_continuity_state() is False
    assert restarted.health < 100
    assert restarted._continuity_gaps > 0


def test_a07_enrolled_outbox_rejects_replay_of_an_older_empty_database(
    tmp_path: Path,
) -> None:
    initial = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    initial.bind(EventBus())
    assert initial._open_continuity_state() is True
    initial._close_continuity_state()
    outbox_path = tmp_path / "outbox" / "defender.sqlite3"
    empty_snapshot = tmp_path / "captured-empty-defender.sqlite3"
    shutil.copyfile(outbox_path, empty_snapshot)

    failing_bus = EventBus()
    failing_bus.subscribe(
        lambda _event: (_ for _ in ()).throw(RuntimeError("inert reject"))
    )
    populated = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    populated.bind(failing_bus)
    assert populated._open_continuity_state() is True
    populated._stage_native_record(_defender_record(1))
    assert populated._outbox is not None
    assert populated._outbox.stats().pending == 1
    populated._close_continuity_state()

    shutil.copyfile(empty_snapshot, outbox_path)
    restarted = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    restarted.bind(EventBus())
    opened = restarted._open_continuity_state()
    health = restarted.health
    gaps = restarted._continuity_gaps
    current = restarted._current_record_id()
    pending = restarted._outbox.stats().pending if restarted._outbox is not None else -1
    restarted._close_continuity_state()

    assert opened is False, (
        f"captured empty outbox replay accepted: health={health} gaps={gaps} "
        f"cursor={current} pending={pending}"
    )
    assert health < 100
    assert gaps > 0


def _isolated_deception(tmp_path: Path) -> tuple[DeceptionModule, EventBus]:
    module = DeceptionModule()
    module._base = tmp_path / "static"
    module._shared = tmp_path / "shared"
    module._soar = module._shared / "soar-events.jsonl"
    bus = EventBus()
    module.bind(bus)
    module._plant()
    return module, bus


def test_a13_same_size_same_mtime_atomic_replacement_is_detected(
    tmp_path: Path,
) -> None:
    module, bus = _isolated_deception(tmp_path)
    target = Path(next(iter(module._canaries)))
    original = target.read_bytes()
    before = target.stat()
    replacement = tmp_path / "same-metadata-replacement.tmp"
    replacement.write_bytes(b"X" * len(original))
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.replace(replacement, target)
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert target.stat().st_size == before.st_size
    assert target.stat().st_mtime_ns == before.st_mtime_ns

    module._check_canaries()

    alerts = [
        event
        for event in bus.recent(20)
        if event.message == f"Canary file TOUCHED: {target}"
    ]
    assert len(alerts) == 1


def test_a13_zero_canaries_reports_zero_visibility(tmp_path: Path) -> None:
    module, _bus = _isolated_deception(tmp_path)
    for raw_path in tuple(module._canaries):
        Path(raw_path).unlink()

    module._check_canaries()

    assert module._canaries == {}
    assert module._canary_evidence == {}
    assert module.health == 0
    assert "zero canaries" in module.health_note.casefold()


def test_a14_forged_and_wrong_key_receipts_never_verify() -> None:
    private, receipt, evidence = _driver_fixture()
    wrong_private = Ed25519PrivateKey.generate()
    forged_receipt = replace(
        receipt,
        signature_ed25519=base64.b64encode(b"F" * 64).decode("ascii"),
    )
    forged_evidence = replace(
        evidence,
        binding_receipt=forged_receipt,
        binding_receipt_sha256=forged_receipt.digest(),
    )

    forged = assess_driver_provenance(forged_evidence, _driver_verifier(private))
    wrong_key = assess_driver_provenance(evidence, _driver_verifier(wrong_private))

    assert forged.state == "incomplete-driver-evidence"
    assert forged.evidence_complete is False
    assert wrong_key.state == "incomplete-driver-evidence"
    assert wrong_key.evidence_complete is False


def test_a14_same_verifier_rejects_receipt_replay() -> None:
    private, _receipt, evidence = _driver_fixture()
    verifier = _driver_verifier(private)

    first = assess_driver_provenance(evidence, verifier)
    replay = assess_driver_provenance(evidence, verifier)

    assert first.state == "provenance-verified"
    assert replay.state == "incomplete-driver-evidence"
    assert replay.evidence_complete is False


def test_a14_receipt_replay_cannot_cross_provider_or_verifier_instances() -> None:
    private, _receipt, evidence = _driver_fixture()

    class Provider:
        def collect(self) -> DriverCollection:
            return DriverCollection(
                (evidence,),
                True,
                "inert-complete-kernel-provider",
                total_count=1,
                truncated=False,
            )

    primary = DriverProvenanceGuard(
        Provider(), receipt_verifier=_driver_verifier(private)
    )
    secondary = DriverProvenanceGuard(
        Provider(), receipt_verifier=_driver_verifier(private)
    )

    first = primary.observe_once()[0]
    replay = secondary.observe_once()[0]

    assert first.state == "provenance-verified"
    assert replay.state == "incomplete-driver-evidence"
    assert replay.evidence_complete is False


@pytest.mark.parametrize("total_count", [None, 0, 999])
def test_a14_complete_empty_provider_never_reports_verified_health(
    total_count: int | None,
) -> None:
    class EmptyProvider:
        def collect(self) -> DriverCollection:
            return DriverCollection(
                (),
                True,
                "inert-hostile-empty-provider",
                total_count=total_count,
                truncated=False,
            )

    module = DriverProvenanceGuard(EmptyProvider())

    assert module.observe_once() == ()
    assert module.health <= 20
    assert "verified" not in module.health_note.casefold()


def test_outbox_replay_fixture_is_key_independent_after_capture(tmp_path: Path) -> None:
    """Prove the A07 replay probe needs no row-key knowledge after capture."""
    outbox_path = tmp_path / "captured.sqlite3"
    derived = hmac.new(
        _CONTINUITY_KEY,
        av_module._OUTBOX_KEY_DOMAIN,
        hashlib.sha256,
    ).digest()
    outbox = DurableOutbox(outbox_path, derived)
    outbox.close()

    raw = outbox_path.read_bytes()
    assert raw.startswith(b"SQLite format 3\x00")
    assert _CONTINUITY_KEY not in raw
    assert derived not in raw
