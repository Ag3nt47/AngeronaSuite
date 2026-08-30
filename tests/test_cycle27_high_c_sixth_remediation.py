from __future__ import annotations

import hashlib
import os
import shutil
import time
from pathlib import Path

import pytest

from angerona.core.independent_high_water import (
    SCHEMA,
    HighWaterHead,
    HighWaterTransition,
)
from angerona.modules import ransomware_heuristics as ransomware
from angerona.modules import smart_deception


class _MemoryHighWater:
    def __init__(self) -> None:
        self._installation_id = "ab" * 16
        self.heads: dict[str, HighWaterHead] = {}

    @property
    def installation_id(self) -> str:
        return self._installation_id

    def read_head(self, domain: str) -> HighWaterHead | None:
        return self.heads.get(domain)

    def compare_and_advance(self, transition: HighWaterTransition) -> HighWaterHead:
        current = self.heads.get(transition.domain)
        if current is None:
            assert transition.previous_revision == 0
            assert transition.previous_head == "0" * 64
        else:
            assert transition.previous_revision == current.revision
            assert transition.previous_state_digest == current.state_digest
            assert transition.previous_head == current.head
        head = hashlib.sha256(
            (
                f"{transition.domain}|{transition.revision}|"
                f"{transition.state_digest}|{transition.previous_head}"
            ).encode("ascii")
        ).hexdigest()
        result = HighWaterHead(
            SCHEMA,
            transition.installation_id,
            transition.domain,
            transition.revision,
            transition.state_digest,
            transition.previous_head,
            head,
        )
        self.heads[transition.domain] = result
        return result


def _scan_cycle(
    module: ransomware.RansomwareHeuristicsModule, root: Path
) -> tuple[list[ransomware._EntropyCandidate], dict[str, object]]:
    module._begin_change_cycle()
    candidates, _snapshot, coverage = module._scan_root(root, time.time())
    module._coverage = coverage
    module._commit_change_cycle(complete=bool(coverage["collection_complete"]))
    module._update_coverage_health()
    return candidates, coverage


def _smart_module(
    tmp_path: Path, high_water: _MemoryHighWater | None = None
) -> smart_deception.SmartDeception:
    module = smart_deception.SmartDeception(high_water=high_water)
    target = tmp_path / "decoys"
    target.mkdir(exist_ok=True)
    module._runtime_root = target
    module._targets = (target,)
    module._manifest = tmp_path / "manifest.json"
    return module


def _archive_incident(module: smart_deception.SmartDeception, name: str) -> None:
    target = module._targets[0] / name
    assert module._write_decoy(str(target))
    with target.open("ab") as stream:
        stream.write(b"tampered-evidence")
    assert module._retire_tampered_decoy(str(target))


def test_ransomware_state_rollback_and_key_state_deletion_fail_closed(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    state = tmp_path / "state"
    root.mkdir()
    target = root / "report.bin"
    target.write_bytes(b"A" * ransomware.MIN_FILE_BYTES)
    first = ransomware.RansomwareHeuristicsModule()
    first._change_state_root = state
    first._load_change_state()
    _scan_cycle(first, root)
    old_state = first._change_state_path().read_bytes()

    target.write_bytes(b"B" * ransomware.MIN_FILE_BYTES)
    _scan_cycle(first, root)
    first._change_state_path().write_bytes(old_state)
    rolled_back = ransomware.RansomwareHeuristicsModule()
    rolled_back._change_state_root = state
    with pytest.raises(OSError, match="rollback violates"):
        rolled_back._load_change_state()

    # Restore the current authenticated bundle, then prove deletion of both
    # replaceable state objects cannot silently re-enroll while the independent
    # local witness survives.
    first._write_change_state(
        first._change_state_sequence,
        first._change_receipts,
        scan_epoch=first._change_scan_epoch,
    )
    first._change_key_path().unlink()
    first._change_state_path().unlink()
    deleted = ransomware.RansomwareHeuristicsModule()
    deleted._change_state_root = state
    with pytest.raises(OSError, match="bundle was deleted"):
        deleted._load_change_state()


def test_ransomware_receipts_drive_changed_and_missing_transitions(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    target = root / "report.bin"
    target.write_bytes(b"A" * ransomware.MIN_FILE_BYTES)
    stamp = target.stat().st_mtime_ns
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    module._load_change_state()
    _scan_cycle(module, root)
    events: list[dict[str, object]] = []
    module.emit = lambda _message, _severity, **details: events.append(details)  # type: ignore[method-assign]

    target.write_bytes(b"B" * ransomware.MIN_FILE_BYTES)
    os.utime(target, ns=(stamp, stamp))
    _scan_cycle(module, root)
    assert module._change_transition_counts["changed"] == 1
    assert any(event.get("transition") == "changed" for event in events)

    events.clear()
    target.unlink()
    _scan_cycle(module, root)
    assert module._change_transition_counts["missing"] == 1
    assert any(event.get("transition") == "missing" for event in events)


def test_ransomware_suffix_only_and_strided_encryption_are_scored(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    random_pattern = bytes(range(256))
    disguised = root / "encrypted.zip"
    disguised.write_bytes(
        random_pattern * ((4 * 1024 * 1024) // len(random_pattern))
    )
    strided = root / "strided.bin"
    with strided.open("wb") as stream:
        for _index in range(32):
            stream.write(b"A" * ransomware.CONTENT_WINDOW_BYTES)
            stream.write(random_pattern * (ransomware.CONTENT_WINDOW_BYTES // 256))
    module = ransomware.RansomwareHeuristicsModule()

    candidates, _snapshot, coverage = module._scan_root(root, time.time())

    by_name = {Path(candidate.path).name: candidate for candidate in candidates}
    assert coverage["complete"] is True
    assert by_name["encrypted.zip"].sample_entropy >= ransomware.ENTROPY_THRESHOLD
    assert by_name["strided.bin"].sample_entropy >= ransomware.ENTROPY_THRESHOLD
    assert by_name["strided.bin"].high_entropy_fraction >= 0.49


def test_ransomware_magic_and_unchanged_receipt_never_grant_exclusion(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    target = root / "reviewed.zip"
    target.write_bytes(b"PK\x03\x04" + os.urandom(ransomware.MIN_FILE_BYTES))
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    module._load_change_state()

    candidates, first = _scan_cycle(module, root)
    assert [Path(candidate.path).name for candidate in candidates] == ["reviewed.zip"]
    assert first["unproved_exclusions"] == 0

    candidates, second = _scan_cycle(module, root)
    assert [Path(candidate.path).name for candidate in candidates] == ["reviewed.zip"]
    assert second["unproved_exclusions"] == 0
    assert module._change_transition_counts["unchanged"] == 1
    assert module.health == 90
    assert "local-authenticity-only" in module.health_note


def test_ransomware_incomplete_cycle_advances_fair_epoch_without_losing_receipts(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    (root / "a.bin").write_bytes(b"A" * ransomware.MIN_FILE_BYTES)
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    module._load_change_state()
    _scan_cycle(module, root)
    receipts = dict(module._change_receipts)
    sequence = module._change_state_sequence
    epoch = module._change_scan_epoch

    module._begin_change_cycle()
    module._commit_change_cycle(complete=False)

    assert module._change_state_sequence == sequence + 1
    assert module._change_scan_epoch == epoch + 1
    assert module._change_receipts == receipts
    restarted = ransomware.RansomwareHeuristicsModule()
    restarted._change_state_root = module._change_state_root
    restarted._load_change_state()
    assert restarted._change_scan_epoch == epoch + 1
    assert restarted._change_receipts == receipts


@pytest.mark.skipif(os.name != "nt", reason="exact custody regression is Windows-only")
def test_deception_independent_high_water_blocks_total_local_deletion(
    tmp_path: Path,
) -> None:
    authority = _MemoryHighWater()
    module = _smart_module(tmp_path, authority)
    _archive_incident(module, "first.txt")
    assert module._custody_freshness.independently_fresh is True
    for evidence in module._quarantine_directory().glob("*.evidence"):
        evidence.unlink()
    for path in (
        module._custody_key_path(),
        module._custody_ledger_path(),
        module._custody_head_path(),
        module._custody_enrollment_key_path(),
        module._custody_witness_path(),
    ):
        path.unlink()

    restarted = _smart_module(tmp_path, authority)
    restarted._decoys = [str(restarted._targets[0] / "live-slot.txt")]
    assert restarted._refresh_quarantine_limits() is False
    restarted._update_health()
    assert restarted.health < 100
    assert restarted._custody_freshness.state == "local-behind"


@pytest.mark.skipif(os.name != "nt", reason="exact custody regression is Windows-only")
def test_deception_independent_high_water_blocks_coherent_local_rollback(
    tmp_path: Path,
) -> None:
    authority = _MemoryHighWater()
    module = _smart_module(tmp_path, authority)
    _archive_incident(module, "first.txt")
    backup = tmp_path / "backup"
    backup.mkdir()
    paths = (
        module._custody_key_path(),
        module._custody_ledger_path(),
        module._custody_head_path(),
        module._custody_enrollment_key_path(),
        module._custody_witness_path(),
    )
    for path in paths:
        shutil.copy2(path, backup / path.name)
    _archive_incident(module, "second.txt")
    for path in paths:
        shutil.copy2(backup / path.name, path)

    restarted = _smart_module(tmp_path, authority)
    restarted._decoys = [str(restarted._targets[0] / "live-slot.txt")]
    assert restarted._refresh_quarantine_limits() is False
    assert restarted._custody_freshness.state == "local-behind"


@pytest.mark.skipif(os.name != "nt", reason="exact custody regression is Windows-only")
def test_deception_capture_is_typed_unverified_at_userspace_boundary(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    _archive_incident(module, "token.txt")

    outcome = module.last_capture_outcome()
    assert isinstance(outcome, smart_deception.CustodyCaptureOutcome)
    assert outcome.state == "captured_unverified"
    assert outcome.source_retired is True
    assert "administrator" in outcome.reason
    module._decoys = [str(module._targets[0] / "live-slot.txt")]
    module._update_health()
    assert module.health < 100
    assert "prior_history_may_have_been_erased=1" in module.health_note


def test_deception_acl_protection_is_verified_not_assumed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    target = tmp_path / "protected.bin"
    target.write_bytes(b"sealed")
    calls: list[tuple[Path, bool]] = []
    monkeypatch.setattr(smart_deception, "key_acl_required", lambda: True)
    monkeypatch.setattr(
        smart_deception,
        "secure_sensitive_file",
        lambda path, *, required: calls.append((Path(path), required)) or True,
    )
    monkeypatch.setattr(
        smart_deception, "sensitive_file_is_protected", lambda _path: True
    )
    monkeypatch.setattr(smart_deception.os, "name", "nt")

    assert module._protect_custody_path(target) is True
    assert module._custody_namespace_protected is True
    assert calls == [(target, True)]
