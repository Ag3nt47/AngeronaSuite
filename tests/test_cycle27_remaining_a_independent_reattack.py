from __future__ import annotations

import os
import sys
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
    DriverCollection,
    DriverProvenanceEvidence,
    DriverProvenanceGuard,
    assess_driver_provenance,
)


_CONTINUITY_KEY = b"r" * 32


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
            "nested": {"authority": "journal-authenticated"},
        },
        trigger_module="inert-independent-reattack",
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


def test_a02_strict_journal_snapshot_cannot_mutate_cached_authority(
    tmp_path: Path,
) -> None:
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    action = _combat_action()

    with module._receipt_lock:
        with module._journal_writer_lease():
            with module._pinned_journal_session(create=True):
                module._journal_intent(action)
                module._journal_commit(action)
                escaped, _legacy = module._read_journal(strict=True)
                escaped_commit = next(
                    item for item in escaped if item["record_type"] == "commit"
                )
                escaped_commit["details"]["module"] = "forged-in-memory"
                escaped_commit["details"]["nested"]["authority"] = "forged"
                trusted, undone = module._trusted_action(action.action_id)

    assert trusted is not None and undone is False
    assert trusted["details"]["module"] == "Smart Deception"
    assert trusted["details"]["nested"]["authority"] == "journal-authenticated"


def test_a03_quarantine_never_commits_after_terminal_hardlink_race(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    alias = tmp_path / "terminal-race-alias.bin"
    source.write_bytes(b"inert exact-object custody fixture")
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    original_commit = module._journal_commit
    attack_error: OSError | None = None

    def race_at_terminal(action: CombatAction) -> CombatAction:
        nonlocal attack_error
        try:
            os.link(Path(action.details["quarantine"]), alias)
        except OSError as exc:
            attack_error = exc
        return original_commit(action)

    module._journal_commit = race_at_terminal  # type: ignore[method-assign]
    event = Event(
        "inert-independent-reattack",
        "inert quarantine request",
        Severity.HIGH,
        details={"response_authorized": True},
    )

    result = module._quarantine_file(
        str(source), event, "combat-000000000001"
    )
    applied = [
        item
        for item in module.list_actions(limit=None)
        if item.get("action") == "quarantine_file"
        and item.get("status") == "applied"
    ]

    if attack_error is not None:
        pytest.skip(f"the host denied the terminal hard-link race: {attack_error}")
    assert alias.exists(), "the inert race fixture did not reach the target boundary"
    assert result is None
    assert applied == []


def test_a03_final_topology_failure_remains_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "final-check-source.bin"
    content = b"inert final topology failure fixture"
    source.write_bytes(content)
    real_pinned = combat_module._PinnedFileMove

    class FourthCheckFailure(real_pinned):
        checks = 0

        def require_single_link(self) -> int:
            type(self).checks += 1
            if type(self).checks == 4:
                raise OSError("inert final topology check failed")
            return super().require_single_link()

    monkeypatch.setattr(combat_module, "_PinnedFileMove", FourthCheckFailure)
    module = AdversaryCombat(tmp_path, rollback_anchor={})
    event = Event(
        "inert-independent-reattack",
        "inert quarantine request",
        Severity.HIGH,
        details={"response_authorized": True},
    )

    assert (
        module._quarantine_file(
            str(source), event, "combat-000000000002"
        )
        is None
    )
    recovery = module._pending_recovery_records()

    assert source.exists() or recovery
    if source.exists():
        assert source.read_bytes() == content


def test_a07_persisted_continuity_gap_cannot_restart_as_health_100(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    first.bind(EventBus())
    assert first._open_continuity_state() is True
    first._stage_native_record(_defender_record(10))
    first._continuity_gap(
        "inert proven retention gap",
        reason_code="defender.inert.retention_gap",
        missing_start=1,
        missing_end=9,
    )
    first._stage_native_record(_defender_record(11))
    assert first._checkpoint is not None
    assert first._checkpoint.coverage_complete is False
    first._close_continuity_state()

    class FakeEventLog:
        def OpenEventLog(self, _server: object, _channel: object) -> object:
            return object()

        def CloseEventLog(self, _handle: object) -> None:
            return None

        def GetOldestEventLogRecord(self, _handle: object) -> int:
            return 10

        def GetNumberOfEventLogRecords(self, _handle: object) -> int:
            return 2

        def ReadEventLog(
            self, _handle: object, _flags: int, offset: int
        ) -> list[SimpleNamespace]:
            return [_defender_record(11)] if offset == 11 else []

    monkeypatch.setitem(sys.modules, "win32evtlog", FakeEventLog())
    restarted = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    restarted.bind(EventBus())
    monkeypatch.setattr(restarted, "sleep", lambda _seconds: restarted._stop.set())

    assert restarted._try_evtlog_mode() is True
    assert restarted.health < 100
    assert "gap" in restarted.health_note.casefold()


def test_a07_checkpoint_cannot_regress_when_an_older_retry_finishes_late(
    tmp_path: Path,
) -> None:
    module = AVTelemetryBridgeModule(tmp_path, continuity_key=_CONTINUITY_KEY)
    module.bind(EventBus())
    assert module._open_continuity_state() is True
    assert module._save_checkpoint(2, "2" * 64) is True

    assert module._save_checkpoint(1, "1" * 64) is False
    assert module._current_record_id() == 2
    module._close_continuity_state()


def test_a13_same_timestamp_object_replacement_is_detected_or_claim_is_narrowed(
    tmp_path: Path,
) -> None:
    module = DeceptionModule()
    module._base = tmp_path / "static"
    bus = EventBus()
    module.bind(bus)
    module._plant()
    target = Path(next(iter(module._canaries)))
    before = target.stat()
    baseline = module._canaries[str(target)]
    replacement = tmp_path / "replacement.tmp"
    replacement.write_bytes(b"inert hostile same-timestamp replacement\n")
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.replace(replacement, target)
    assert target.stat().st_mtime == baseline

    module._check_canaries()

    alerts = [event for event in bus.recent(20) if "Canary file" in event.message]
    claim = f"{module.description} {module.health_note}".casefold()
    assert alerts or "mtime" in claim or "sampled" in claim


def test_a13_health_degrades_when_every_canary_is_lost(tmp_path: Path) -> None:
    module = DeceptionModule()
    module._base = tmp_path / "static"
    module.bind(EventBus())
    module._plant()
    module.set_health(70, "file mutation/deletion visibility active")
    for raw_path in tuple(module._canaries):
        Path(raw_path).unlink()

    module._check_canaries()

    assert module._canaries == {}
    assert module.health < 70
    assert "unavailable" in module.health_note.casefold()


def test_a14_receipt_digest_cannot_be_replayed_across_different_images() -> None:
    results = []
    for image_hash in ("b" * 64, "e" * 64):
        evidence = DriverProvenanceEvidence(
            schema=SCHEMA,
            driver_token="a" * 64,
            image_sha256=image_hash,
            image_size=4096,
            load_state="running",
            binding_state="loaded-image-bound",
            binding_source="kernel-load-receipt",
            binding_receipt_sha256="d" * 64,
            signer_status="trusted",
            signer_thumbprint="c" * 40,
            catalog_status="trusted",
            blocklist_status="not-listed",
            blocklist_source="local-hash-policy",
            hvci_enabled=True,
            secure_boot=True,
            observed_at=1_800_000_000.0,
        )
        results.append(assess_driver_provenance(evidence))

    assert all(result.state != "provenance-verified" for result in results)
    assert all(result.evidence_complete is False for result in results)


def test_a14_hostile_empty_provider_cannot_claim_complete_verified_coverage() -> None:
    class EmptyAuthority:
        def collect(self) -> DriverCollection:
            return DriverCollection(
                (), True, "hostile-complete", total_count=999, truncated=False
            )

    module = DriverProvenanceGuard(EmptyAuthority())

    assert module.observe_once() == ()
    assert module.health < 100
    assert "verified" not in module.health_note.casefold()


def test_a14_synthetic_receipt_digest_cannot_produce_provenance_verified() -> None:
    evidence = DriverProvenanceEvidence(
        schema=SCHEMA,
        driver_token="a" * 64,
        image_sha256="b" * 64,
        image_size=4096,
        load_state="running",
        binding_state="loaded-image-bound",
        binding_source="kernel-load-receipt",
        binding_receipt_sha256="d" * 64,
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

    assert result.state != "provenance-verified"
    assert result.evidence_complete is False
