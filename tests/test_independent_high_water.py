from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from angerona.core.event_log_integrity import (
    AuthenticatedEventLogCheckpoint,
    ChannelCheckpoint,
)
from angerona.core.independent_high_water import (
    AUDIT_DOMAIN,
    NETWORK_DOMAIN,
    SCHEMA,
    ZERO_DIGEST,
    HighWaterHead,
    HighWaterRejected,
    HighWaterTransition,
    HighWaterUnavailable,
)
from angerona.core.network_trust import NetworkTrustBaseline, NetworkTrustBaselineStore


INSTALLATION_ID = "12" * 16


class _MonotonicAuthority:
    """In-memory contract fixture; never performs network I/O."""

    installation_id = INSTALLATION_ID

    def __init__(self) -> None:
        self.heads: dict[str, HighWaterHead] = {}
        self.transitions: list[HighWaterTransition] = []
        self.offline = False

    def read_head(self, domain: str) -> HighWaterHead | None:
        if self.offline:
            raise HighWaterUnavailable("offline")
        return self.heads.get(domain)

    def compare_and_advance(self, transition: HighWaterTransition) -> HighWaterHead:
        if self.offline:
            raise HighWaterUnavailable("offline")
        current = self.heads.get(transition.domain)
        if current is None:
            expected = (0, ZERO_DIGEST, ZERO_DIGEST)
        else:
            expected = (current.revision, current.state_digest, current.head)
        supplied = (
            transition.previous_revision,
            transition.previous_state_digest,
            transition.previous_head,
        )
        if supplied != expected or transition.revision != expected[0] + 1:
            raise HighWaterRejected("behind, duplicate, or forked transition")
        opaque_head = hashlib.sha256(
            b"independent-test-authority\0"
            + json.dumps(
                asdict(transition), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        returned = HighWaterHead(
            SCHEMA,
            self.installation_id,
            transition.domain,
            transition.revision,
            transition.state_digest,
            transition.previous_head,
            opaque_head,
        )
        self.heads[transition.domain] = returned
        self.transitions.append(transition)
        return returned


def _event_store(tmp_path, authority=None):
    return AuthenticatedEventLogCheckpoint(
        tmp_path / "sensor-cursors" / "audit.json",
        authority_key=b"e" * 32,
        high_water=authority,
    )


def _network_store(tmp_path, authority=None):
    return NetworkTrustBaselineStore(
        tmp_path / "sensor-baselines" / "network.json",
        baseline_key=b"b" * 32,
        enrollment_key=b"n" * 32,
        enrollment_path=tmp_path / "continuity-epochs" / "network.json",
        high_water=authority,
    )


def test_event_pair_rollback_is_rejected_against_independent_head(tmp_path) -> None:
    authority = _MonotonicAuthority()
    store = _event_store(tmp_path, authority)
    assert store.load()[1] == "first-enrollment"
    assert store.freshness_status == "ready-first-enrollment"
    assert store.save({"Security": ChannelCheckpoint(1, "a" * 64)})
    old_cursor = store.path.read_bytes()
    old_epoch = store.enrollment_path.read_bytes()
    assert store.save({"Security": ChannelCheckpoint(2, "b" * 64)})
    assert store.independent_freshness_verified is True

    store.path.write_bytes(old_cursor)
    store.enrollment_path.write_bytes(old_epoch)
    restored = _event_store(tmp_path, authority)
    assert restored.load() == ({}, "untrusted")
    assert restored.freshness_status == "local-behind"


def test_network_pair_rollback_is_rejected_against_separate_domain(tmp_path) -> None:
    authority = _MonotonicAuthority()
    store = _network_store(tmp_path, authority)
    assert store.load() == (None, "missing")
    assert store.save(NetworkTrustBaseline(), trusted=False)
    old_cursor = store.path.read_bytes()
    old_epoch = store.enrollment_path.read_bytes()
    assert store.save(NetworkTrustBaseline(), trusted=True)

    store.path.write_bytes(old_cursor)
    store.enrollment_path.write_bytes(old_epoch)
    restored = _network_store(tmp_path, authority)
    assert restored.load() == (None, "untrusted")
    assert restored.freshness_status == "local-behind"
    assert AUDIT_DOMAIN not in authority.heads
    assert NETWORK_DOMAIN in authority.heads


def test_offline_and_legacy_migration_are_explicitly_provisional(tmp_path) -> None:
    authority = _MonotonicAuthority()
    witnessed = _event_store(tmp_path, authority)
    witnessed.load()
    assert witnessed.save({"Security": ChannelCheckpoint(3, "c" * 64)})
    authority.offline = True
    offline = _event_store(tmp_path, authority)
    checkpoints, status = offline.load()
    assert status == "provisional"
    assert checkpoints["Security"].record_id == 3
    assert offline.freshness_status == "provisional-offline"
    assert offline.save({"Security": ChannelCheckpoint(4, "d" * 64)}) is False

    legacy_root = tmp_path / "legacy"
    legacy = _event_store(legacy_root)
    legacy.load()
    assert legacy.save({"Security": ChannelCheckpoint(1, "e" * 64)})
    empty_authority = _MonotonicAuthority()
    empty_authority.installation_id = json.loads(
        legacy.enrollment_path.read_text(encoding="utf-8")
    )["enrollment_id"]
    migrated = _event_store(legacy_root, empty_authority)
    assert migrated.load()[1] == "provisional"
    assert migrated.freshness_status == "migration-required"
    assert migrated.save({"Security": ChannelCheckpoint(2, "f" * 64)}) is False


def test_fork_and_installation_clone_mismatch_fail_closed(tmp_path) -> None:
    authority = _MonotonicAuthority()
    store = _event_store(tmp_path, authority)
    store.load()
    assert store.save({"Security": ChannelCheckpoint(1, "a" * 64)})
    current = authority.heads[AUDIT_DOMAIN]
    authority.heads[AUDIT_DOMAIN] = HighWaterHead(
        current.schema,
        current.installation_id,
        current.domain,
        current.revision,
        "f" * 64,
        current.previous_head,
        current.head,
    )
    forked = _event_store(tmp_path, authority)
    assert forked.load() == ({}, "untrusted")
    assert forked.freshness_status == "fork-detected"

    clone_authority = _MonotonicAuthority()
    clone_authority.installation_id = "34" * 16
    clone = _event_store(tmp_path, clone_authority)
    assert clone.load() == ({}, "untrusted")
    assert clone.freshness_status == "installation-mismatch"


def test_external_advance_before_local_write_is_fail_visible(tmp_path, monkeypatch) -> None:
    authority = _MonotonicAuthority()
    store = _event_store(tmp_path, authority)
    store.load()

    def _fail_write(_path, _payload):
        raise OSError("simulated local crash boundary")

    monkeypatch.setattr(
        "angerona.core.event_log_integrity.AuthenticatedEventLogCheckpoint._secure_write",
        staticmethod(_fail_write),
    )
    assert store.save({"Security": ChannelCheckpoint(1, "a" * 64)}) is False
    assert store.freshness_status == "external-ahead-crash-recovery-required"
    assert authority.heads[AUDIT_DOMAIN].revision == 1

    restarted = _event_store(tmp_path, authority)
    assert restarted.load() == ({}, "untrusted")
    assert restarted.freshness_status == "local-behind"


def test_transition_contract_cannot_carry_raw_logs_or_network_identifiers(tmp_path) -> None:
    authority = _MonotonicAuthority()
    store = _network_store(tmp_path, authority)
    store.load()
    assert store.save(NetworkTrustBaseline(), trusted=False)
    transition = authority.transitions[-1]
    assert set(asdict(transition)) == {
        "schema",
        "installation_id",
        "domain",
        "previous_revision",
        "previous_state_digest",
        "previous_head",
        "revision",
        "state_digest",
    }
    representation = repr(transition)
    assert "raw_log" not in representation
    assert "ssid" not in representation
    assert "gateway" not in representation
    assert "command" not in representation
