from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from angerona.core.independent_high_water import (
    CUSTODY_DOMAIN,
    SCHEMA,
    ZERO_DIGEST,
    HighWaterHead,
    HighWaterTransition,
    HighWaterUnavailable,
)
from angerona.modules import ransomware_heuristics as ransomware
from angerona.modules import smart_deception


class _IndependentMemoryHighWater:
    """Inert exact-CAS authority used only for hostile recovery probes."""

    def __init__(self) -> None:
        self._installation_id = "cd" * 16
        self.heads: dict[str, HighWaterHead] = {}
        self.fail_advances = 0

    @property
    def installation_id(self) -> str:
        return self._installation_id

    def read_head(self, domain: str) -> HighWaterHead | None:
        return self.heads.get(domain)

    def compare_and_advance(self, transition: HighWaterTransition) -> HighWaterHead:
        if self.fail_advances:
            self.fail_advances -= 1
            raise HighWaterUnavailable("inert independent outage")
        prior = self.heads.get(transition.domain)
        if prior is None:
            assert transition.previous_revision == 0
            assert transition.previous_state_digest == ZERO_DIGEST
            assert transition.previous_head == ZERO_DIGEST
        else:
            assert transition.previous_revision == prior.revision
            assert transition.previous_state_digest == prior.state_digest
            assert transition.previous_head == prior.head
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


def _smart(
    tmp_path: Path, authority: _IndependentMemoryHighWater
) -> smart_deception.SmartDeception:
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


def test_c03_magic_polyglot_is_scored_on_new_and_unchanged_cycles(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    (root / "opaque.zip").write_bytes(b"PK\x03\x04" + bytes(range(256)) * 64)
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    module._load_change_state()
    events: list[tuple[str, object, dict[str, object]]] = []
    module.emit = lambda message, severity, **details: events.append(  # type: ignore[method-assign]
        (message, severity, details)
    )

    for now in (1_900_000_000.0, 1_900_000_000.0 + ransomware.DEDUP_TTL + 1):
        module._begin_change_cycle()
        candidates, _snapshot, coverage = module._scan_root(root, now)
        assert [Path(candidate.path).name for candidate in candidates] == ["opaque.zip"]
        assert module._evaluate_entropy(candidates, now) == 0
        module._commit_change_cycle(
            complete=bool(coverage["collection_complete"])
        )

    entropy_events = [event for event in events if "High-entropy file" in event[0]]
    assert len(entropy_events) == 2


def test_c03_reservoir_is_independent_of_adversarial_directory_order() -> None:
    entries = [
        (
            f"f{index:03}.bin",
            False,
            True,
            False,
            ransomware.MIN_FILE_BYTES,
            1.0,
            index + 1,
            ("posix", 7, index + 11),
        )
        for index in range(100)
    ]

    def selected(order: list[tuple[object, ...]]) -> set[str]:
        module = ransomware.RansomwareHeuristicsModule()
        module._range_key = b"I" * 32
        module._change_scan_epoch = 17
        module._held_directory_entries = lambda *_args: iter(order)  # type: ignore[method-assign]
        rows, truncated, eligible = module._fair_directory_entries(
            "posix", 0, Path("."), ("posix", 7, 9), 13
        )
        assert truncated is True
        assert eligible == 100
        return {str(row[0]) for row in rows}

    assert selected(entries) == selected(list(reversed(entries)))


def test_c03_full_stream_reservoir_honors_declared_traversal_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The held stream is stopped as soon as the traversal deadline expires."""
    root = tmp_path / "Documents"
    root.mkdir()
    module = ransomware.RansomwareHeuristicsModule()
    clock = [100.0]
    yielded = [0]

    def entries(*_args):
        for index in range(100):
            yielded[0] += 1
            clock[0] += 0.1
            yield (
                f"f{index:03}.bin",
                False,
                True,
                False,
                1,
                1.0,
                index + 1,
                ("posix", 1, index + 100),
            )

    monkeypatch.setattr(ransomware, "TRAVERSAL_MAX_S", 0.25)
    monkeypatch.setattr(ransomware.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module, "_held_directory_entries", entries)

    _rows, coverage = module._bounded_tree(root, 1_900_000_000.0)

    assert yielded[0] <= 3
    assert float(coverage["elapsed_ms"]) < 1_000.0
    assert int(coverage["truncated"]) >= 1


def test_c03_state_then_witness_crash_recovers_exact_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    module._load_change_state()
    module._begin_change_cycle()

    def fail_witness(*_args, **_kwargs) -> None:
        raise OSError("inert crash after state replace")

    monkeypatch.setattr(module, "_write_change_witness", fail_witness)
    with pytest.raises(OSError, match="inert crash"):
        module._commit_change_cycle(complete=True)

    restarted = ransomware.RansomwareHeuristicsModule()
    restarted._change_state_root = tmp_path / "state"
    restarted._load_change_state()
    assert restarted._change_state_sequence == 1
    assert restarted._change_scan_epoch == 1
    assert restarted._change_witness_verified is True
    assert not restarted._change_transition_path().exists()


def test_c13_first_enrollment_failure_before_outbox_leaves_no_false_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)

    def fail_pending(**_kwargs) -> None:
        raise OSError("inert pre-outbox enrollment crash")

    monkeypatch.setattr(module, "_write_pending_transition", fail_pending)
    with pytest.raises(OSError, match="pre-outbox"):
        module._load_custody_state(create=True)

    assert not module._custody_ledger_path().exists()
    assert not module._custody_head_path().exists()
    assert not module._custody_witness_path().exists()
    assert not module._custody_transition_path().exists()
    assert authority.read_head(CUSTODY_DOMAIN) is None

    restarted = _smart(tmp_path, authority)
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_freshness.independently_fresh is True
    assert authority.read_head(CUSTODY_DOMAIN).revision == 1  # type: ignore[union-attr]


def test_c13_sqlite_commit_before_head_write_is_reconciled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll(module)
    original = module._write_custody_head

    def fail_new_head(sequence: int, head: str) -> None:
        if sequence == 1:
            raise OSError("inert crash after SQLite COMMIT")
        original(sequence, head)

    monkeypatch.setattr(module, "_write_custody_head", fail_new_head)
    with pytest.raises(OSError, match="SQLite COMMIT"):
        module._append_custody_state_event(
            "pending_loss", "inert post-commit crash", (9, 10)
        )

    # The exact transition proof survives and repairs both local metadata and
    # the independent authority on restart.
    assert module._custody_transition_path().exists()
    assert authority.read_head(CUSTODY_DOMAIN).revision == 1  # type: ignore[union-attr]
    restarted = _smart(tmp_path, authority)
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_ledger_sequence == 1
    assert restarted._custody_external_revision == 2
    assert restarted._custody_freshness.independently_fresh is True
    assert not restarted._custody_transition_path().exists()
