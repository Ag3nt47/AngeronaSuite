import pytest

from angerona.core.data_governance import DataClass, EgressPolicy
from angerona.core.interop_gateway import OfflineInteropQueue


def test_interop_queue_minimizes_signs_and_retries(tmp_path):
    queue = OfflineInteropQueue(
        tmp_path / "interop.db", b"k" * 32, b"s" * 16,
    )
    policy = EgressPolicy(
        maximum_class=DataClass.INTERNAL, allow_external=True,
    )
    envelope = queue.enqueue(
        "envelope-001", "ocsf-1.3",
        {"event_id": "event-1", "username": "alice", "password": "secret"},
        purpose="siem export", destination="local-relay",
        policy=policy, external=True, now=100,
    )
    assert "password" not in envelope.payload
    assert str(envelope.payload["username"]).startswith("tok_")
    assert queue.verify(envelope)
    assert queue.ready(now=100) == (envelope,)
    queue.disposition(envelope.envelope_id, delivered=False, error="offline", now=100)
    assert queue.ready(now=101) == ()
    assert queue.ready(now=102) == (envelope,)
    queue.disposition(envelope.envelope_id, delivered=True, now=103)
    assert queue.ready(now=1000) == ()
    queue.close()


def test_external_egress_is_denied_by_default_and_ids_are_idempotent(tmp_path):
    queue = OfflineInteropQueue(
        tmp_path / "interop.db", b"k" * 32, b"s" * 16,
    )
    with pytest.raises(PermissionError, match="disabled"):
        queue.enqueue(
            "envelope-001", "stix-2.1", {"event_id": "event-1"},
            purpose="export", destination="remote",
            policy=EgressPolicy(), external=True,
        )
    policy = EgressPolicy(allow_external=True)
    first = queue.enqueue(
        "envelope-001", "stix-2.1", {"event_id": "event-1"},
        purpose="export", destination="remote", policy=policy,
        external=True, now=100,
    )
    assert queue.enqueue(
        "envelope-001", "stix-2.1", {"event_id": "event-1"},
        purpose="export", destination="remote", policy=policy,
        external=True, now=100,
    ) == first
    with pytest.raises(ValueError, match="conflicts"):
        queue.enqueue(
            "envelope-001", "stix-2.1", {"event_id": "event-2"},
            purpose="export", destination="remote", policy=policy,
            external=True, now=100,
        )
    queue.close()


def test_repeated_delivery_failure_moves_item_to_bounded_dead_letter(tmp_path):
    queue = OfflineInteropQueue(
        tmp_path / "interop.db", b"k" * 32, b"s" * 16,
    )
    policy = EgressPolicy(allow_external=True)
    envelope = queue.enqueue(
        "envelope-001", "otlp-1.0", {"event_id": "event-1"},
        purpose="export", destination="remote", policy=policy,
        external=True, now=0,
    )
    now = 0
    for _index in range(8):
        queue.disposition(
            envelope.envelope_id, delivered=False,
            error="collector unavailable", now=now,
        )
        now += 4_000
    assert queue.ready(now=100_000) == ()
    queue.close()
