from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from angerona.core.eventbus import EventBus
from angerona.core.file_lease import ExclusiveFileLease, ExclusiveFileLeaseError
from angerona.core.independent_high_water import (
    CUSTODY_DOMAIN,
    SCHEMA,
    ZERO_DIGEST,
    HighWaterHead,
    HighWaterTransition,
    HighWaterUnavailable,
)
from angerona.core.module_manager import ModuleManager
from angerona.core.personal_sentinel_authority import DEFAULT_ALLOWED_DOMAINS
from angerona.modules import ransomware_heuristics as ransomware
from angerona.modules import smart_deception


class _MemoryHighWater:
    def __init__(self) -> None:
        self._installation_id = "ab" * 16
        self.heads: dict[str, HighWaterHead] = {}
        self.fail_reads = 0
        self.fail_advances = 0
        self.lose_response = False

    @property
    def installation_id(self) -> str:
        return self._installation_id

    def read_head(self, domain: str) -> HighWaterHead | None:
        if self.fail_reads:
            self.fail_reads -= 1
            raise HighWaterUnavailable("inert authority outage")
        return self.heads.get(domain)

    def compare_and_advance(self, transition: HighWaterTransition) -> HighWaterHead:
        if self.fail_advances:
            self.fail_advances -= 1
            raise HighWaterUnavailable("inert authority outage")
        current = self.heads.get(transition.domain)
        if current is None:
            assert transition.previous_revision == 0
            assert transition.previous_state_digest == ZERO_DIGEST
            assert transition.previous_head == ZERO_DIGEST
        else:
            assert transition.previous_revision == current.revision
            assert transition.previous_state_digest == current.state_digest
            assert transition.previous_head == current.head
        body = (
            f"{transition.domain}|{transition.revision}|"
            f"{transition.state_digest}|{transition.previous_head}"
        ).encode("ascii")
        result = HighWaterHead(
            SCHEMA,
            transition.installation_id,
            transition.domain,
            transition.revision,
            transition.state_digest,
            transition.previous_head,
            hashlib.sha256(body).hexdigest(),
        )
        self.heads[transition.domain] = result
        if self.lose_response:
            self.lose_response = False
            self.fail_reads += 1
            raise HighWaterUnavailable("committed response was lost")
        return result


class _Config:
    module_states: dict[str, bool] = {}

    def save(self) -> None:
        return None


def _smart(tmp_path: Path, authority: _MemoryHighWater) -> smart_deception.SmartDeception:
    module = smart_deception.SmartDeception(high_water=authority)
    module._runtime_root = tmp_path / "decoys"
    module._runtime_root.mkdir(exist_ok=True)
    module._targets = (module._runtime_root,)
    module._manifest = tmp_path / "manifest.json"
    return module


def _enroll(module: smart_deception.SmartDeception) -> None:
    connection, _active = module._load_custody_state(create=True)
    connection.close()
    assert module._custody_freshness.independently_fresh is True
    assert module._custody_external_revision == 1


def test_magic_and_unchanged_ticks_remain_entropy_candidates(tmp_path: Path) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    target = root / "opaque.zip"
    target.write_bytes(b"PK\x03\x04" + bytes(range(256)) * 32)
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    module._load_change_state()

    for _cycle in range(2):
        module._begin_change_cycle()
        candidates, _snapshot, coverage = module._scan_root(root, 1_900_000_000.0)
        module._commit_change_cycle(complete=bool(coverage["collection_complete"]))
        assert [Path(candidate.path).name for candidate in candidates] == ["opaque.zip"]
        assert coverage["unproved_exclusions"] == 0


def test_full_stream_reservoir_reaches_entries_beyond_enumeration_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = ransomware.RansomwareHeuristicsModule()
    module._range_key = b"R" * 32
    entries = [
        (
            f"f{index:02}.bin",
            False,
            True,
            False,
            ransomware.MIN_FILE_BYTES,
            1.0,
            index + 1,
            ("posix", 1, index + 10),
        )
        for index in range(10)
    ]
    monkeypatch.setattr(
        module,
        "_held_directory_entries",
        lambda *_args: iter(entries),
    )
    selected: set[str] = set()
    for epoch in range(64):
        module._change_scan_epoch = epoch
        rows, truncated, eligible = module._fair_directory_entries(
            "posix", 0, Path("."), ("posix", 1, 2), 5
        )
        assert truncated is True
        assert eligible == 10
        assert len(rows) == 5
        selected.update(str(row[0]) for row in rows)
    assert selected == {f"f{index:02}.bin" for index in range(10)}
    assert any(name >= "f05.bin" for name in selected)


def test_truncated_rotation_reports_full_eligibility_and_unseen_age(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    for index in range(10):
        (root / f"f{index:02}.bin").write_bytes(b"A")
    module = ransomware.RansomwareHeuristicsModule()
    monkeypatch.setattr(ransomware, "TRAVERSAL_MAX_FILES", 3)
    monkeypatch.setattr(ransomware, "TRAVERSAL_MAX_DIRS", 1)

    _rows, coverage = module._bounded_tree(root, 1_900_000_000.0)

    assert coverage["eligible_entries"] == 10
    assert coverage["selected_entries"] == 3
    assert coverage["truncated"] >= 1
    assert coverage["oldest_unseen_epochs"] == 1


def test_default_authority_policy_includes_exact_custody_domain() -> None:
    assert CUSTODY_DOMAIN == "smart-deception-custody"
    assert CUSTODY_DOMAIN in DEFAULT_ALLOWED_DOMAINS


def test_module_manager_binds_application_owned_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _MemoryHighWater()
    constructed: list[type] = []

    def factory(cls: type):
        constructed.append(cls)
        return cls()

    manager = ModuleManager(
        EventBus(),
        _Config(),  # type: ignore[arg-type]
        target_platform="windows",
        high_water_provider=authority,
        module_factory=factory,
    )
    monkeypatch.setattr(manager, "_builtin_classes", lambda: [smart_deception.SmartDeception])
    monkeypatch.setattr(manager, "_external_classes", lambda: [])

    manager.discover()

    module = manager.modules["Smart Deception"]
    assert constructed == [smart_deception.SmartDeception]
    assert module._custody_high_water is authority  # type: ignore[attr-defined]
    assert module.custody_freshness_snapshot()["authority_configured"] is True  # type: ignore[attr-defined]


def test_local_ahead_outage_replays_exact_pending_cas(tmp_path: Path) -> None:
    authority = _MemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll(module)
    authority.fail_advances = 1

    with pytest.raises(OSError, match="RECOVERY_REQUIRED"):
        module._append_custody_state_event(
            "pending_loss", "inert outage", (1, 2)
        )
    assert module._custody_transition_path().exists()
    assert authority.heads[CUSTODY_DOMAIN].revision == 1

    restarted = _smart(tmp_path, authority)
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_freshness.independently_fresh is True
    assert restarted._custody_external_revision == 2
    assert authority.heads[CUSTODY_DOMAIN].revision == 2
    assert not restarted._custody_transition_path().exists()


def test_committed_but_response_lost_is_reconciled_by_exact_remote_head(
    tmp_path: Path,
) -> None:
    authority = _MemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll(module)
    authority.lose_response = True

    with pytest.raises(OSError, match="RECOVERY_REQUIRED"):
        module._append_custody_state_event(
            "pending_loss", "inert lost response", (3, 4)
        )
    assert authority.heads[CUSTODY_DOMAIN].revision == 2
    assert module._custody_transition_path().exists()

    restarted = _smart(tmp_path, authority)
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_external_revision == 2
    assert restarted._custody_freshness.independently_fresh is True
    assert not restarted._custody_transition_path().exists()


def test_fail_before_local_commit_discards_only_exact_pending_transition(
    tmp_path: Path,
) -> None:
    authority = _MemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll(module)
    next_sequence = 1
    core = module._custody_core(
        next_sequence,
        "pending_loss",
        smart_deception._CUSTODY_STATE_NAME,
        (0, 0),
        1,
        "a" * 64,
        (1, 2),
        module._custody_ledger_head,
    )
    next_head = module._custody_mac(core)
    assert module._prepare_external_custody(next_sequence, next_head) is True
    assert module._custody_transition_path().exists()

    restarted = _smart(tmp_path, authority)
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_ledger_sequence == 0
    assert restarted._custody_external_revision == 1
    assert not restarted._custody_transition_path().exists()


def test_pending_transition_refuses_remote_fork(tmp_path: Path) -> None:
    authority = _MemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll(module)
    authority.fail_advances = 1
    with pytest.raises(OSError):
        module._append_custody_state_event("pending_loss", "inert fork", (5, 6))
    prior = authority.heads[CUSTODY_DOMAIN]
    authority.heads[CUSTODY_DOMAIN] = HighWaterHead(
        SCHEMA,
        authority.installation_id,
        CUSTODY_DOMAIN,
        2,
        "f" * 64,
        prior.head,
        "e" * 64,
    )

    restarted = _smart(tmp_path, authority)
    with pytest.raises(OSError, match="fork or gap"):
        restarted._load_custody_state(create=True)
    assert restarted._custody_transition_path().exists()
    assert restarted._custody_freshness.independently_fresh is False


def test_second_custody_writer_is_rejected_by_os_lease(tmp_path: Path) -> None:
    authority = _MemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll(module)
    with ExclusiveFileLease(module._custody_lease_path()):
        with pytest.raises(ExclusiveFileLeaseError):
            module._append_custody_state_event(
                "pending_loss", "inert concurrent writer", (7, 8)
            )
