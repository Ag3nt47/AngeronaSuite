from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import pytest

from angerona.modules import ransomware_heuristics as ransomware
from angerona.modules import smart_deception


def _smart_module(tmp_path: Path) -> smart_deception.SmartDeception:
    module = smart_deception.SmartDeception()
    target = tmp_path / "decoys"
    target.mkdir(exist_ok=True)
    module._runtime_root = target
    module._targets = (target,)
    module._manifest = tmp_path / "manifest.json"
    return module


def _archive_incident(
    module: smart_deception.SmartDeception, name: str = "token.txt"
) -> Path:
    target = module._targets[0] / name
    assert module._write_decoy(str(target))
    with target.open("ab") as handle:
        handle.write(b"tampered-evidence")
    assert module._retire_tampered_decoy(str(target))
    return target


def _restart_with_live_slot(tmp_path: Path) -> smart_deception.SmartDeception:
    module = _smart_module(tmp_path)
    module._decoys = [str(module._targets[0] / "logical-live-slot.txt")]
    return module


def test_ransomware_full_stream_catches_old_header_preserving_encryption(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    target = root / "report.bin"
    size = 4 * 1024 * 1024
    tail = (bytes(range(256)) * ((size - ransomware.SAMPLE_BYTES) // 256 + 1))[
        : size - ransomware.SAMPLE_BYTES
    ]
    target.write_bytes(b"A" * ransomware.SAMPLE_BYTES + tail)
    old = time.time() - 7200
    os.utime(target, (old, old))
    module = ransomware.RansomwareHeuristicsModule()

    candidates, _snapshot, coverage = module._scan_root(root, time.time())

    assert coverage["complete"] is True
    assert coverage["content_analyzed"] == 1
    assert coverage["content_incomplete"] == 0
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.content_complete is True
    assert candidate.sample_size == size
    assert candidate.sample_entropy >= ransomware.ENTROPY_THRESHOLD
    events: list[dict[str, object]] = []
    module.emit = lambda _message, _severity, **details: events.append(details)  # type: ignore[method-assign]
    assert module._evaluate_entropy(candidates, time.time()) == 0
    assert len(events) == 1
    assert events[0]["content_complete"] is True


def test_ransomware_tail_swap_is_fail_visible_then_retried_without_mtime_gate(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    target = root / "report.bin"
    size = 4 * 1024 * 1024
    target.write_bytes(b"A" * size)
    timestamp = target.stat().st_mtime_ns
    module = ransomware.RansomwareHeuristicsModule()
    stale, _snapshot, first_coverage = module._scan_root(root, time.time())
    assert first_coverage["complete"] is True

    with target.open("r+b") as handle:
        handle.seek(ransomware.SAMPLE_BYTES)
        remaining = size - ransomware.SAMPLE_BYTES
        pattern = bytes(range(256))
        while remaining:
            chunk = pattern[: min(len(pattern), remaining)]
            handle.write(chunk)
            remaining -= len(chunk)
    os.utime(target, ns=(timestamp, timestamp))
    events: list[dict[str, object]] = []
    module.emit = lambda _message, _severity, **details: events.append(details)  # type: ignore[method-assign]

    assert module._evaluate_entropy(stale, time.time()) == 1
    assert events == []
    current, _snapshot, current_coverage = module._scan_root(root, time.time())
    assert current_coverage["complete"] is True
    assert len(current) == 1
    assert current[0].sample_entropy >= ransomware.ENTROPY_THRESHOLD
    assert module._evaluate_entropy(current, time.time()) == 0
    assert len(events) == 1


def test_ransomware_large_range_proof_is_unpredictable_and_never_complete_green(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    target = root / "large.bin"
    size = ransomware.CONTENT_FULL_FILE_MAX_BYTES + ransomware.SAMPLE_BYTES
    with target.open("wb") as handle:
        handle.write(b"A" * ransomware.SAMPLE_BYTES)
        pattern = bytes(range(256))
        remaining = size - ransomware.SAMPLE_BYTES
        while remaining:
            chunk = pattern[: min(len(pattern), remaining)]
            handle.write(chunk)
            remaining -= len(chunk)
    old = time.time() - 7200
    os.utime(target, (old, old))
    module = ransomware.RansomwareHeuristicsModule()

    candidates, _snapshot, coverage = module._scan_root(root, time.time())
    module._coverage = coverage
    module._update_coverage_health()

    assert len(candidates) == 1
    assert candidates[0].content_complete is False
    assert len(candidates[0].sample_ranges) >= 3
    assert candidates[0].sample_entropy >= ransomware.ENTROPY_THRESHOLD
    assert coverage["content_incomplete"] == 1
    assert coverage["complete"] is False
    assert module.health < 100
    assert "representative range proof only" in module.health_note


def test_ransomware_content_budget_exhaustion_is_fail_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    (root / "a.bin").write_bytes(b"A" * ransomware.MIN_FILE_BYTES)
    (root / "b.bin").write_bytes(b"B" * ransomware.MIN_FILE_BYTES)
    monkeypatch.setattr(
        ransomware, "CONTENT_SCAN_MAX_BYTES", ransomware.MIN_FILE_BYTES
    )
    module = ransomware.RansomwareHeuristicsModule()

    module._collect_entropy_candidates(root, time.time())
    coverage = module.coverage_snapshot()

    assert coverage["content_analyzed"] == 1
    assert coverage["content_budget_exhausted"] == 1
    assert coverage["complete"] is False
    assert module.health < 100


def test_ransomware_authenticated_change_receipts_survive_restart_and_timestomp(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    state = tmp_path / "state"
    root.mkdir()
    target = root / "report.bin"
    target.write_bytes(b"A" * ransomware.MIN_FILE_BYTES)
    timestamp = target.stat().st_mtime_ns
    first = ransomware.RansomwareHeuristicsModule()
    first._change_state_root = state
    first._load_change_state()
    first._begin_change_cycle()
    _candidates, _snapshot, coverage = first._scan_root(root, time.time())
    first._commit_change_cycle(complete=bool(coverage["complete"]))
    first_digest = next(iter(first._change_receipts.values()))["content_sha256"]

    second = ransomware.RansomwareHeuristicsModule()
    second._change_state_root = state
    second._load_change_state()
    assert second._change_state_sequence == 1
    assert next(iter(second._change_receipts.values()))["content_sha256"] == first_digest

    target.write_bytes(b"B" * ransomware.MIN_FILE_BYTES)
    os.utime(target, ns=(timestamp, timestamp))
    second._begin_change_cycle()
    _candidates, _snapshot, coverage = second._scan_root(root, time.time())
    second._commit_change_cycle(complete=bool(coverage["complete"]))
    assert second._change_state_sequence == 2
    assert next(iter(second._change_receipts.values()))["content_sha256"] != first_digest

    second._change_state_path().unlink()
    third = ransomware.RansomwareHeuristicsModule()
    third._change_state_root = state
    with pytest.raises(OSError, match="authority is incomplete"):
        third._load_change_state()


@pytest.mark.skipif(os.name != "nt", reason="exact custody regression is Windows-only")
def test_deception_alias_topology_degradation_survives_restart(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    alias = module._targets[0] / "source-alias.txt"
    assert module._write_decoy(str(target))
    os.link(target, alias)
    with target.open("ab") as handle:
        handle.write(b"tampered-evidence")
    assert module._retire_tampered_decoy(str(target))
    assert alias.exists()

    restarted = _restart_with_live_slot(tmp_path)
    assert restarted._refresh_quarantine_limits() is True
    restarted._update_health()

    assert restarted._quarantine_alias_residue >= 1
    assert restarted._custody_topology_uncertain >= 1
    assert restarted._custody_degraded is True
    assert restarted.health < 100


@pytest.mark.skipif(os.name != "nt", reason="exact custody regression is Windows-only")
def test_deception_pending_and_eviction_loss_survive_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    assert module._refresh_quarantine_limits() is True
    root = module._quarantine_directory()
    pending = root / f"sdec-pending-{'a' * 24}.tmp"
    descriptor = module._create_evidence_file(pending)
    os.write(descriptor, b"partial")
    os.close(descriptor)
    assert module._refresh_quarantine_limits() is True

    restarted = _restart_with_live_slot(tmp_path)
    assert restarted._refresh_quarantine_limits() is True
    assert restarted._custody_loss >= 1
    prior_loss = restarted._custody_loss
    _archive_incident(restarted, "aged.txt")
    evidence = next(restarted._quarantine_directory().glob("*.evidence"))
    match = smart_deception._QUARANTINE_NAME.fullmatch(evidence.name)
    assert match is not None
    created = int(match.group(1)) / 1000.0
    monkeypatch.setattr(
        smart_deception.time,
        "time",
        lambda: created + smart_deception._QUARANTINE_MAX_AGE_S + 10,
    )
    assert restarted._refresh_quarantine_limits() is True

    final = _restart_with_live_slot(tmp_path)
    assert final._refresh_quarantine_limits() is True
    final._update_health()
    assert final._custody_loss > prior_loss
    assert final._custody_evictions >= 1
    assert final.health < 100


@pytest.mark.skipif(os.name != "nt", reason="exact custody regression is Windows-only")
def test_deception_authority_deletion_and_paired_rollback_fail_closed(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    _archive_incident(module, "first.txt")
    ledger_backup = tmp_path / "ledger-old.sqlite3"
    head_backup = tmp_path / "head-old.json"
    shutil.copy2(module._custody_ledger_path(), ledger_backup)
    shutil.copy2(module._custody_head_path(), head_backup)
    first_evidence = set(module._quarantine_directory().glob("*.evidence"))
    _archive_incident(module, "second.txt")
    second_evidence = set(module._quarantine_directory().glob("*.evidence")) - first_evidence
    assert len(second_evidence) == 1
    next(iter(second_evidence)).unlink()
    shutil.copy2(ledger_backup, module._custody_ledger_path())
    shutil.copy2(head_backup, module._custody_head_path())

    rolled_back = _restart_with_live_slot(tmp_path)
    assert rolled_back._refresh_quarantine_limits() is False
    rolled_back._update_health()
    assert rolled_back.health < 100
    assert rolled_back._quarantine_saturated is True

    deletion_root = tmp_path / "deletion-case"
    deletion_root.mkdir()
    deleted = _smart_module(deletion_root)
    _archive_incident(deleted)
    for evidence in deleted._quarantine_directory().glob("*.evidence"):
        evidence.unlink()
    deleted._custody_key_path().unlink()
    deleted._custody_ledger_path().unlink()
    deleted._custody_head_path().unlink()
    assert deleted._custody_witness_path().exists()

    after_deletion = _restart_with_live_slot(deletion_root)
    assert after_deletion._refresh_quarantine_limits() is False
    after_deletion._update_health()
    assert after_deletion.health < 100
    assert after_deletion._quarantine_saturated is True


@pytest.mark.skipif(os.name != "nt", reason="exact custody regression is Windows-only")
def test_deception_post_final_hardlink_race_is_immediately_and_durably_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    alias = tmp_path / "late-evidence-alias.bin"
    real_audit = module._audit_held_evidence
    calls = [0]

    def race_after_final_observation(
        descriptor: int,
        expected_identity: tuple[int, int],
        expected_size: int,
        expected_digest: str,
    ) -> int:
        result = real_audit(
            descriptor, expected_identity, expected_size, expected_digest
        )
        calls[0] += 1
        if calls[0] == 2:
            evidence = next(module._quarantine_directory().glob("*.evidence"))
            os.link(evidence, alias)
        return result

    monkeypatch.setattr(module, "_audit_held_evidence", race_after_final_observation)
    _archive_incident(module)
    assert alias.exists()
    with alias.open("ab") as handle:
        handle.write(b"post-publication-mutation")
    module._decoys = [str(module._targets[0] / "logical-live-slot.txt")]
    module._update_health()
    assert module.health < 100

    restarted = _restart_with_live_slot(tmp_path)
    assert restarted._refresh_quarantine_limits() is False
    restarted._update_health()
    assert restarted._quarantine_alias_residue >= 1
    assert restarted._custody_topology_uncertain >= 1
    assert restarted.health < 100


@pytest.mark.skipif(os.name != "nt", reason="exact custody regression is Windows-only")
def test_deception_reserves_terminal_ledger_capacity_before_source_retirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(smart_deception, "_CUSTODY_LEDGER_MAX_EVENTS", 8)
    monkeypatch.setattr(smart_deception, "_CUSTODY_TERMINAL_RESERVE", 2)
    module = _smart_module(tmp_path)
    assert module._refresh_quarantine_limits() is True
    root_descriptor, root_identity = module._open_quarantine_directory()
    os.close(root_descriptor)
    for index in range(6):
        module._append_custody_state_event(
            "pending_loss", f"bounded-state-{index}", root_identity
        )

    assert module._refresh_quarantine_limits() is False
    module._decoys = [str(module._targets[0] / "logical-live-slot.txt")]
    module._update_health()
    assert module._custody_remaining_events == 2
    assert module._custody_capacity_exhausted is True
    assert module.health < 100

    target = module._targets[0] / "capacity.txt"
    assert module._write_decoy(str(target))
    with target.open("ab") as handle:
        handle.write(b"tampered")
    assert module._retire_tampered_decoy(str(target)) is False
    assert target.exists()
    assert module._quarantine_dropped >= 1
