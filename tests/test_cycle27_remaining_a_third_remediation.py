from __future__ import annotations

import json
import shutil
import threading
from copy import deepcopy
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
)


_CONTINUITY_KEY = b"t" * 32
_DRIVER_NOW = 1_800_100_000.0


def _combat_action() -> CombatAction:
    return CombatAction(
        action_id="act-0000000000000012",
        combat_id="combat-000000000012",
        action="activate_honeypots",
        applied_at=120.0,
        reversible=True,
        target="Smart Deception",
        details={
            "module": "Smart Deception",
            "nested": {"authority": "journal", "history": [{"state": "trusted"}]},
        },
        trigger_module="inert-third-remediation",
        trigger_ts=119.0,
        status="applied",
    )


def _record(number: int, stamp: str = "2026-08-28T12:00:00Z") -> object:
    return SimpleNamespace(
        RecordNumber=number,
        EventID=1116,
        TimeGenerated=stamp,
        StringInserts=None,
    )


def _pending_payload(module: AVTelemetryBridgeModule, number: int) -> dict[str, object]:
    record = _record(number)
    decoded = module._decode_record(record)
    assert decoded is not None
    message, severity, details = decoded
    return {
        "schema": "angerona.defender-delivery.v1",
        "kind": "event",
        "message": message,
        "severity": int(severity),
        "details": details,
        "record_number": number,
        "record_anchor": module._record_digest(record),
    }


def _driver_authority() -> tuple[
    DriverLoadReceipt,
    DriverProvenanceEvidence,
    DriverLoadReceiptVerifier,
    DriverLoadReceiptVerifier,
]:
    private = Ed25519PrivateKey.generate()
    ids = {
        "authority_id": "6" * 64,
        "host_id": "7" * 64,
        "install_id": "8" * 64,
        "boot_id": "9" * 64,
    }
    receipt = DriverLoadReceipt.issue(
        private,
        **ids,
        load_generation=12,
        driver_token="a" * 64,
        object_identity="b" * 64,
        image_base=0x120000,
        image_size=8192,
        image_sha256="c" * 64,
        load_state="running",
        code_integrity_disposition="trusted",
        issued_at=_DRIVER_NOW,
        expires_at=_DRIVER_NOW + 60.0,
    )
    evidence = DriverProvenanceEvidence(
        schema=SCHEMA,
        driver_token="a" * 64,
        image_sha256="c" * 64,
        image_size=8192,
        load_state="running",
        binding_state="loaded-image-bound",
        binding_source="kernel-load-receipt",
        binding_receipt_sha256=receipt.digest(),
        signer_status="trusted",
        signer_thumbprint="d" * 40,
        catalog_status="trusted",
        blocklist_status="not-listed",
        blocklist_source="local-hash-policy",
        hvci_enabled=True,
        secure_boot=True,
        observed_at=_DRIVER_NOW,
        binding_receipt=receipt,
    )
    return (
        receipt,
        evidence,
        DriverLoadReceiptVerifier(
            private.public_key(), **ids, clock=lambda: _DRIVER_NOW
        ),
        DriverLoadReceiptVerifier(
            private.public_key(), **ids, clock=lambda: _DRIVER_NOW
        ),
    )


def test_a02_nested_cache_mutation_is_authenticated_and_disarms_authority(
    tmp_path: Path,
) -> None:
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    action = _combat_action()
    with module._receipt_lock:
        with module._journal_writer_lease():
            with module._pinned_journal_session(create=True):
                module._journal_intent(action)
                module._journal_commit(action)
                retained = module._journal_cache_commits[action.action_id]
                retained["details"]["nested"]["history"][0]["state"] = "forged"
                with pytest.raises(
                    JournalIntegrityError, match="authority graph changed"
                ):
                    module._trusted_action(action.action_id)
    assert module.response_ready() is False


def test_a02_equal_cache_index_object_swap_is_rejected(tmp_path: Path) -> None:
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    action = _combat_action()
    with module._receipt_lock:
        with module._journal_writer_lease():
            with module._pinned_journal_session(create=True):
                module._journal_intent(action)
                module._journal_commit(action)
                module._journal_cache_commits[action.action_id] = deepcopy(
                    module._journal_cache_commits[action.action_id]
                )
                with pytest.raises(
                    JournalIntegrityError, match="authority graph changed"
                ):
                    module._trusted_action(action.action_id)


def test_a03_terminal_proof_is_returned_from_retained_writer(tmp_path: Path) -> None:
    source = tmp_path / "inert-terminal-proof.bin"
    source.write_bytes(b"third remediation exact-object proof")
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    event = SimpleNamespace(
        module="inert-third-remediation",
        ts=1.0,
        details={"response_authorized": True},
    )

    result = module._quarantine_file(
        str(source), event, "combat-000000000012"
    )

    assert result is not None
    assert result.details["postcondition_verified"] is True
    assert result.details["destination_link_count"] == 1
    assert result.details["terminal_object_identity"] == result.details["file_identity"]


def test_a07_claim_witness_failure_prevents_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus = EventBus()
    module = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    module.bind(bus)
    assert module._open_continuity_state() is True
    payload = _pending_payload(module, 1)
    module._enqueue_outbox("defender-third-remediation-1", payload)
    delivered_before = len(bus.recent(50))
    original_write = module._write_outbox_enrollment

    def refuse_witness(_key: bytes, _core: dict[str, object]) -> None:
        raise OSError("inert witness durability failure")

    monkeypatch.setattr(module, "_write_outbox_enrollment", refuse_witness)
    module._drain_outbox()

    assert len(bus.recent(50)) == delivered_before
    assert module._current_record_id() == 0
    assert module.health == 20
    monkeypatch.setattr(module, "_write_outbox_enrollment", original_write)
    module._close_continuity_state()


def test_a07_conflicting_anchor_queues_one_nonrecursive_gap(tmp_path: Path) -> None:
    bus = EventBus()
    module = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    module.bind(bus)
    assert module._open_continuity_state() is True
    module._stage_native_record(_record(1, "2026-08-28T12:00:00Z"))

    module._stage_native_record(_record(1, "2026-08-28T12:00:01Z"))

    assert module._continuity_gaps == 1
    assert sum(
        event.details.get("reason_code") == "defender.cursor.anchor_conflict"
        for event in bus.recent(50)
    ) == 1
    assert sum(
        event.details.get("channel_record_id") == 1 for event in bus.recent(50)
    ) == 1
    module._close_continuity_state()


def test_a07_outbox_state_witness_rejects_older_database(
    tmp_path: Path,
) -> None:
    initial = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    initial.bind(EventBus())
    assert initial._open_continuity_state() is True
    initial._close_continuity_state()
    database = tmp_path / "outbox" / "defender.sqlite3"
    captured = tmp_path / "captured-empty.sqlite3"
    shutil.copyfile(database, captured)

    failing = EventBus()
    failing.subscribe(lambda _event: (_ for _ in ()).throw(RuntimeError("reject")))
    populated = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    populated.bind(failing)
    assert populated._open_continuity_state() is True
    populated._stage_native_record(_record(1))
    populated._close_continuity_state()
    marker = json.loads(
        (tmp_path / "security-state" / "defender-outbox.json").read_text(
            encoding="utf-8"
        )
    )
    assert marker["state_generation"] > 0

    shutil.copyfile(captured, database)
    replayed = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    replayed.bind(EventBus())
    assert replayed._open_continuity_state() is False
    assert replayed.health < 100
    assert replayed._continuity_gaps > 0


def test_a07_existing_database_without_witness_fails_closed(tmp_path: Path) -> None:
    enrolled = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    enrolled.bind(EventBus())
    assert enrolled._open_continuity_state() is True
    enrolled._close_continuity_state()
    marker = tmp_path / "security-state" / "defender-outbox.json"
    marker.unlink()

    restarted = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    restarted.bind(EventBus())
    assert restarted._open_continuity_state() is False
    assert restarted.health < 100
    assert restarted._continuity_gaps > 0


def test_a14_concurrent_cross_verifier_replay_has_one_winner() -> None:
    receipt, evidence, first, second = _driver_authority()
    gate = threading.Barrier(3)
    results: list[bool] = []

    def verify(verifier: DriverLoadReceiptVerifier) -> None:
        gate.wait()
        results.append(verifier.verify(evidence, receipt))

    threads = [
        threading.Thread(target=verify, args=(first,)),
        threading.Thread(target=verify, args=(second,)),
    ]
    for thread in threads:
        thread.start()
    gate.wait()
    for thread in threads:
        thread.join(timeout=5.0)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(results) == [False, True]
