from __future__ import annotations

import os
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules import adversary_combat as combat_module
from angerona.modules.adversary_combat import AdversaryCombat, CombatAction
from angerona.modules.av_telemetry_bridge import AVTelemetryBridgeModule
from angerona.modules.deception import DeceptionModule
from angerona.modules.driver_provenance_guard import (
    SCHEMA,
    DriverProvenanceEvidence,
    assess_driver_provenance,
)


_CONTINUITY_KEY = b"d" * 32


def _action(index: int = 1) -> CombatAction:
    return CombatAction(
        action_id=f"act-{index:016x}",
        combat_id=f"combat-{index:012x}",
        action="activate_honeypots",
        applied_at=100.0 + index,
        reversible=True,
        target="Smart Deception",
        details={"module": "Smart Deception", "postcondition_verified": True},
        trigger_module="inert-cycle27-remediation",
        trigger_ts=99.0 + index,
        status="applied",
    )


def test_combat_control_paths_use_every_live_action(monkeypatch: pytest.MonkeyPatch) -> None:
    module = AdversaryCombat(rollback_anchor={})
    records = [
        {
            **_action(index).__dict__,
            "record_type": "commit",
            "record_hmac": f"{index:064x}",
        }
        for index in range(1, 5002)
    ]
    monkeypatch.setattr(module, "_read_journal", lambda **_kwargs: (records, []))
    attempted: list[str] = []
    monkeypatch.setattr(
        module,
        "undo_action",
        lambda action_id: attempted.append(action_id)
        or {"ok": True, "action_id": action_id},
    )

    result = module.undo_all()

    assert result["attempted"] == 5001
    assert len(attempted) == 5001
    assert attempted[-1] == "act-0000000000000001"


def test_combat_reserves_terminal_capacity_before_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    monkeypatch.setattr(module, "_journal_has_capacity", lambda _required: False)
    effect_crossed = False

    with pytest.raises(combat_module.JournalIntegrityError):
        with module._journaled_mutation(_action()):
            effect_crossed = True

    assert effect_crossed is False
    assert module._journal_saturated is True
    assert module.health == 0


def test_combat_append_reuses_authenticated_terminal_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    assert module._reconcile_state() is True
    original = module._read_pinned_journal_bytes
    full_reads = 0

    def counted_read():
        nonlocal full_reads
        full_reads += 1
        return original()

    monkeypatch.setattr(module, "_read_pinned_journal_bytes", counted_read)
    for index in range(1, 21):
        action = _action(index)
        module._journal_intent(action)
        module._journal_failure(action, "inert fixture closed without host effect")

    assert full_reads <= 1
    assert len(module._read_journal(strict=True)[0]) == 40


def test_pinned_quarantine_rejects_preexisting_hardlink(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    alias = tmp_path / "sample-alias.bin"
    source.write_bytes(b"inert quarantine hard-link fixture")
    try:
        os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(OSError, match="hard-link alias"):
        combat_module._PinnedFileMove(source)

    assert source.exists() and alias.exists()


def test_quarantine_retains_object_custody_through_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    source = tmp_path / "fixture.bin"
    source.write_bytes(b"inert quarantine custody fixture")
    instances: list[object] = []
    real_pinned = combat_module._PinnedFileMove

    class SpyPinned(real_pinned):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            instances.append(self)

    monkeypatch.setattr(combat_module, "_PinnedFileMove", SpyPinned)
    monkeypatch.setattr(module, "_journaled_mutation", lambda _action: nullcontext())

    def commit(action, *, release_before_rollback=None):
        assert instances and instances[0]._closed is False
        assert callable(release_before_rollback)
        assert instances[0].require_single_link() == 1
        return action

    monkeypatch.setattr(module, "_commit_after_mutation", commit)
    event = Event(
        "inert detector",
        "inert quarantine request",
        Severity.HIGH,
        details={"response_authorized": True},
    )

    result = module._quarantine_file(str(source), event, "combat-000000000001")

    assert result is not None
    assert result.details["source_link_count"] == 1
    assert result.details["destination_link_count"] == 1


def test_quarantine_post_move_alias_signal_rolls_back_without_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    source = tmp_path / "rollback-fixture.bin"
    content = b"inert post-move alias signal"
    source.write_bytes(content)
    real_pinned = combat_module._PinnedFileMove

    class BoundaryPinned(real_pinned):
        checks = 0

        def require_single_link(self) -> int:
            type(self).checks += 1
            if type(self).checks == 3:
                raise OSError("secure move destination acquired a hard-link alias")
            return super().require_single_link()

    monkeypatch.setattr(combat_module, "_PinnedFileMove", BoundaryPinned)
    event = Event(
        "inert detector",
        "inert quarantine request",
        Severity.HIGH,
        details={"response_authorized": True},
    )

    result = module._quarantine_file(
        str(source), event, "combat-000000000002"
    )

    assert result is None
    assert source.read_bytes() == content
    assert not any(
        item.get("action") == "quarantine_file"
        and item.get("status") == "applied"
        for item in module.list_actions(limit=None)
    )


def _defender_record(number: int = 7) -> SimpleNamespace:
    return SimpleNamespace(
        RecordNumber=number,
        EventID=1116,
        TimeGenerated="2026-08-28T12:00:00Z",
        StringInserts=None,
    )


def test_defender_retained_record_is_delivered_and_restart_deduplicated(
    tmp_path: Path,
) -> None:
    first_bus = EventBus()
    first = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    first.bind(first_bus)
    assert first._open_continuity_state() is True
    first._stage_native_record(_defender_record())
    first._close_continuity_state()

    assert any(event.details.get("eid") == 1116 for event in first_bus.recent(20))

    second_bus = EventBus()
    second = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    second.bind(second_bus)
    assert second._open_continuity_state() is True
    second._stage_native_record(_defender_record())
    second._close_continuity_state()

    assert not any(event.details.get("eid") == 1116 for event in second_bus.recent(20))


def test_defender_first_start_processes_retained_native_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _defender_record(3)

    class FakeEventLog:
        def __init__(self) -> None:
            self.closed = 0

        def OpenEventLog(self, _server, _channel):
            return object()

        def CloseEventLog(self, _handle) -> None:
            self.closed += 1

        def GetOldestEventLogRecord(self, _handle) -> int:
            return 3

        def GetNumberOfEventLogRecords(self, _handle) -> int:
            return 1

        def ReadEventLog(self, _handle, _flags, offset):
            return [record] if offset <= 3 else []

    fake = FakeEventLog()
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)
    bus = EventBus()
    module = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    module.bind(bus)
    monkeypatch.setattr(module, "sleep", lambda _seconds: module._stop.set())

    assert module._try_evtlog_mode() is True

    assert any(event.details.get("channel_record_id") == 3 for event in bus.recent(20))
    assert module._delivered == 1
    assert fake.closed == 1


def test_defender_pending_outbox_replays_before_cursor_advances(tmp_path: Path) -> None:
    producer = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    producer.bind(EventBus())
    assert producer._open_continuity_state() is True
    decoded = producer._decode_record(_defender_record(9))
    assert decoded is not None and producer._outbox is not None
    message, severity, details = decoded
    anchor = producer._record_digest(_defender_record(9))
    producer._outbox.enqueue(
        f"defender-event-9-{anchor}",
        {
            "schema": "angerona.defender-delivery.v1",
            "kind": "event",
            "message": message,
            "severity": int(severity),
            "details": details,
            "record_number": 9,
            "record_anchor": anchor,
        },
    )
    producer._close_continuity_state()

    recovery_bus = EventBus()
    recovery = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    recovery.bind(recovery_bus)
    assert recovery._open_continuity_state() is True

    assert any(event.details.get("channel_record_id") == 9 for event in recovery_bus.recent(20))
    assert recovery._current_record_id() == 9
    recovery._close_continuity_state()


def test_defender_tampered_cursor_stays_degraded_and_emits_gap(
    tmp_path: Path,
) -> None:
    first = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    first.bind(EventBus())
    assert first._open_continuity_state() is True
    first._stage_native_record(_defender_record(11))
    first._close_continuity_state()
    cursor = tmp_path / "sensor-cursors" / "defender.json"
    body = cursor.read_text(encoding="utf-8")
    cursor.write_text(body.replace('"record_id":11', '"record_id":12'), encoding="utf-8")

    bus = EventBus()
    restarted = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    restarted.bind(bus)
    assert restarted._open_continuity_state() is True

    assert restarted._checkpoint_status == "untrusted"
    assert restarted.health == 45
    assert any(
        event.details.get("reason_code") == "defender.cursor.untrusted"
        for event in bus.recent(20)
    )
    restarted._close_continuity_state()


def test_defender_powershell_retained_detection_is_durable_across_restart(
    tmp_path: Path,
) -> None:
    threat = {
        "DetectionID": "inert-detection-1",
        "ThreatName": "Inert.Test.Fixture",
        "Resources": r"C:\Fixtures\inert.txt",
    }
    first_bus = EventBus()
    first = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    first.bind(first_bus)
    assert first._open_continuity_state() is True
    first._stage_ps_detection(threat)
    first._close_continuity_state()

    second_bus = EventBus()
    second = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    second.bind(second_bus)
    assert second._open_continuity_state() is True
    second._stage_ps_detection(threat)

    assert any(
        event.details.get("detection_id") == "inert-detection-1"
        for event in first_bus.recent(20)
    )
    assert not any(
        event.details.get("detection_id") == "inert-detection-1"
        for event in second_bus.recent(20)
    )
    second._close_continuity_state()


def test_deception_lure_claim_matches_observed_mutation_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = DeceptionModule()
    module._base = tmp_path
    monkeypatch.setattr(module, "_plant_fake_registry_cred", lambda _name: None)
    monkeypatch.setattr("angerona.modules.deception.random.choice", lambda values: values[0])

    module._restage("inert credential discovery")

    lure = next(tmp_path.glob("aws_credentials_*.txt"))
    text = lure.read_text(encoding="utf-8")
    assert "Any access is logged" not in text
    assert "File mutation or deletion is logged" in text
    assert module.health <= 100


def test_unbound_driver_path_sample_never_becomes_provenance_verified() -> None:
    evidence = DriverProvenanceEvidence(
        schema=SCHEMA,
        driver_token="a" * 64,
        image_sha256="b" * 64,
        image_size=4096,
        load_state="unknown",
        binding_state="configured-path-sample-unbound",
        binding_source="configured-service-path",
        binding_receipt_sha256=None,
        signer_status="trusted",
        signer_thumbprint="c" * 40,
        catalog_status="trusted",
        blocklist_status="not-listed",
        blocklist_source="local-hash-policy",
        hvci_enabled=True,
        secure_boot=True,
        observed_at=1_800_000_000.0,
    )

    result = assess_driver_provenance(evidence)

    assert result.state == "incomplete-driver-evidence"
    assert result.evidence_complete is False
    assert "loaded_image_binding" in result.unknown
