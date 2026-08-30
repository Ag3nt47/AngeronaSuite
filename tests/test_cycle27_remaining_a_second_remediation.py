from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core.eventbus import EventBus
from angerona.modules.adversary_combat import (
    AdversaryCombat,
    CombatAction,
    JournalIntegrityError,
)
from angerona.modules.av_telemetry_bridge import AVTelemetryBridgeModule
from angerona.modules.driver_provenance_guard import (
    SCHEMA,
    DriverLoadReceipt,
    DriverLoadReceiptVerifier,
    DriverProvenanceEvidence,
    assess_driver_provenance,
)


_CONTINUITY_KEY = b"s" * 32


def _action() -> CombatAction:
    return CombatAction(
        action_id="act-0000000000000001",
        combat_id="combat-000000000001",
        action="activate_honeypots",
        applied_at=100.0,
        reversible=True,
        target="Smart Deception",
        details={
            "module": "Smart Deception",
            "nested": {"authority": "journal-authenticated"},
        },
        trigger_module="inert-second-remediation",
        trigger_ts=99.0,
        status="applied",
    )


def _defender_record(number: int) -> SimpleNamespace:
    return SimpleNamespace(
        RecordNumber=number,
        EventID=1116,
        TimeGenerated="2026-08-28T12:00:00Z",
        StringInserts=None,
    )


def test_a02_cached_fast_path_authenticates_interior_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    monkeypatch.setattr(module, "_journal_fingerprint", lambda _info: (1,))
    with module._receipt_lock:
        with module._journal_writer_lease():
            with module._pinned_journal_session(create=True):
                module._journal_intent(_action())
                module._journal_commit(_action())

    raw = module.receipt_path.read_bytes()
    assert b"journal-authenticated" in raw
    module.receipt_path.write_bytes(
        raw.replace(b"journal-authenticated", b"j0urnal-authenticated", 1)
    )

    with module._receipt_lock:
        with module._journal_writer_lease():
            with module._pinned_journal_session(create=False):
                with pytest.raises(JournalIntegrityError, match="interior checkpoint"):
                    module._validated_active_journal_cache()


def test_a07_subscriber_failure_retains_outbox_and_cursor(
    tmp_path: Path,
) -> None:
    bus = EventBus()

    def failing_subscriber(_event: object) -> None:
        raise RuntimeError("inert subscriber failure")

    bus.subscribe(failing_subscriber)
    module = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    module.bind(bus)
    assert module._open_continuity_state() is True

    module._stage_native_record(_defender_record(1))

    assert module._current_record_id() == 0
    assert module._outbox is not None
    assert module._outbox.stats().pending == 1
    assert module.health < 100
    module._close_continuity_state()

    restarted = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    restarted.bind(EventBus())
    assert restarted._open_continuity_state() is True
    assert restarted._current_record_id() == 0
    assert restarted._outbox is not None
    assert restarted._outbox.stats().pending == 1
    assert restarted.health < 100
    restarted._close_continuity_state()


def test_a07_enrolled_outbox_deletion_fails_closed(tmp_path: Path) -> None:
    first = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    first.bind(EventBus())
    assert first._open_continuity_state() is True
    first._close_continuity_state()
    outbox_path = tmp_path / "outbox" / "defender.sqlite3"
    enrollment_path = tmp_path / "security-state" / "defender-outbox.json"
    assert outbox_path.exists() and enrollment_path.exists()
    outbox_path.unlink()

    restarted = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    restarted.bind(EventBus())

    assert restarted._open_continuity_state() is False
    assert restarted.health < 100
    assert restarted._continuity_gaps > 0


def _bound_evidence() -> tuple[
    DriverProvenanceEvidence,
    DriverLoadReceiptVerifier,
    DriverLoadReceiptVerifier,
]:
    private = Ed25519PrivateKey.generate()
    now = 1_800_000_000.0
    ids = {
        "authority_id": "1" * 64,
        "host_id": "2" * 64,
        "install_id": "3" * 64,
        "boot_id": "4" * 64,
    }
    receipt = DriverLoadReceipt.issue(
        private,
        **ids,
        load_generation=7,
        driver_token="a" * 64,
        object_identity="5" * 64,
        image_base=0x100000,
        image_size=4096,
        image_sha256="b" * 64,
        load_state="running",
        code_integrity_disposition="trusted",
        issued_at=now,
        expires_at=now + 60.0,
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
        observed_at=now,
        binding_receipt=receipt,
    )
    verifier_one = DriverLoadReceiptVerifier(
        private.public_key(), **ids, clock=lambda: now
    )
    verifier_two = DriverLoadReceiptVerifier(
        private.public_key(), **ids, clock=lambda: now
    )
    return evidence, verifier_one, verifier_two


def test_a14_signed_receipt_is_exact_bound_and_one_use() -> None:
    evidence, verifier, independent_verifier = _bound_evidence()

    accepted = assess_driver_provenance(evidence, verifier)
    replayed = assess_driver_provenance(evidence, verifier)
    wrong_image = replace(evidence, image_sha256="e" * 64)
    mismatched = assess_driver_provenance(wrong_image, independent_verifier)

    assert accepted.state == "provenance-verified"
    assert accepted.evidence_complete is True
    assert replayed.state != "provenance-verified"
    assert replayed.evidence_complete is False
    assert mismatched.state != "provenance-verified"
    assert mismatched.evidence_complete is False
