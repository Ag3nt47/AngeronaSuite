from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time

import pytest

from angerona.core.durable_outbox import (
    DurableOutbox,
    OutboxFull,
    OutboxIntegrityError,
    _canonical,
)
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules.remote_bridge import RemoteBridge
from angerona.modules.siem_forwarder import SIEMForwarderModule


def test_outbox_leases_retry_and_persistent_idempotent_tombstone(tmp_path) -> None:
    path = tmp_path / "outbox.sqlite3"
    key = b"k" * 32
    queue = DurableOutbox(path, key)
    assert queue.enqueue("one", {"value": 1}, now=10)
    assert queue.enqueue("two", {"value": 2}, now=20)
    assert not queue.enqueue("one", {"value": 1}, now=10)

    first = queue.claim("worker-a", now=30, limit=1, lease_seconds=5)
    assert [item.item_id for item in first] == ["one"]
    # Worker B can lease only the other row, never worker A's live lease.
    worker_b = queue.claim("worker-b", now=30, limit=10)
    assert [item.item_id for item in worker_b] == ["two"]
    queue.retry("one", "worker-a", "offline", now=30)
    assert queue.claim("worker-c", now=31, limit=10) == ()
    replay = queue.claim("worker-c", now=32, limit=10)
    assert [item.item_id for item in replay] == ["one"]
    queue.acknowledge("one", "worker-c")
    assert queue.is_delivered("one")
    queue.close()

    reopened = DurableOutbox(path, key)
    assert reopened.is_delivered("one")
    assert not reopened.enqueue("one", {"value": 1}, now=10)
    reopened.close()


def test_outbox_capacity_and_authenticated_rows_fail_closed(tmp_path) -> None:
    queue = DurableOutbox(
        tmp_path / "bounded.sqlite3",
        b"z" * 32,
        max_items=100,
        max_bytes=1024 * 1024,
    )
    for index in range(100):
        queue.enqueue(f"item-{index}", {"index": index}, now=index)
    with pytest.raises(OutboxFull):
        queue.enqueue("overflow", {"value": "blocked"}, now=200)

    queue._db.execute(
        "UPDATE durable_outbox SET payload_json='{}' WHERE item_id='item-0'"
    )
    queue._db.commit()
    with pytest.raises(OutboxIntegrityError):
        queue.claim("integrity-test", now=1_000, limit=100)
    queue.close()


def test_pending_to_delivered_sqlite_tamper_fails_delivery_and_replay(tmp_path) -> None:
    queue = DurableOutbox(tmp_path / "state-tamper.sqlite3", b"m" * 32)
    assert queue.enqueue("pending", {"value": 1}, now=10)
    queue._db.execute(
        "UPDATE durable_outbox SET state='delivered' WHERE item_id='pending'"
    )
    queue._db.commit()

    with pytest.raises(OutboxIntegrityError, match="mutable-state authentication"):
        queue.stats()
    with pytest.raises(OutboxIntegrityError, match="mutable-state authentication"):
        queue.claim("worker", now=20)
    with pytest.raises(OutboxIntegrityError, match="mutable-state authentication"):
        queue.is_delivered("pending")
    with pytest.raises(OutboxIntegrityError, match="mutable-state authentication"):
        queue.enqueue("pending", {"value": 1}, now=10)
    queue.close()


def test_future_next_attempt_tamper_cannot_hide_from_claim_or_stats(tmp_path) -> None:
    path = tmp_path / "timer-suppression.sqlite3"
    queue = DurableOutbox(path, b"t" * 32)
    assert queue.enqueue("suppressed", {"value": 1}, now=10)
    external = sqlite3.connect(path)
    external.execute(
        "UPDATE durable_outbox SET next_attempt=9999999999 "
        "WHERE item_id='suppressed'"
    )
    external.commit()
    external.close()

    with pytest.raises(OutboxIntegrityError, match="mutable-state authentication"):
        queue.claim("worker", now=20)
    with pytest.raises(OutboxIntegrityError, match="mutable-state authentication"):
        queue.stats()
    queue.close()


@pytest.mark.parametrize(
    "assignment",
    (
        "attempts=attempts+1",
        "lease_owner='forged-worker'",
        "lease_until=lease_until+60",
        "next_attempt=next_attempt+60",
        "last_error='forged-error'",
        "size_bytes=size_bytes+1",
    ),
)
def test_lease_attempt_timer_error_and_size_tampering_fail_closed(
    tmp_path, assignment: str,
) -> None:
    queue = DurableOutbox(
        tmp_path / f"lease-tamper-{assignment.split('=')[0]}.sqlite3",
        b"l" * 32,
    )
    assert queue.enqueue("leased", {"value": 1}, now=10)
    assert queue.claim("worker", now=20, limit=1)
    queue._db.execute(
        f"UPDATE durable_outbox SET {assignment} WHERE item_id='leased'"
    )
    queue._db.commit()

    with pytest.raises(OutboxIntegrityError):
        queue.retry("leased", "worker", "offline", now=30)
    queue.close()


def test_payload_authenticated_legacy_rows_receive_one_time_state_signature(
    tmp_path,
) -> None:
    path = tmp_path / "legacy.sqlite3"
    key = b"g" * 32
    payload_json = json.dumps(
        {"value": "legacy"}, sort_keys=True, separators=(",", ":")
    )
    created_at = 10.0
    digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    signature = hmac.new(
        key,
        _canonical({
            "item_id": "legacy",
            "payload_json": payload_json,
            "created_at": created_at,
        }),
        hashlib.sha256,
    ).hexdigest()
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE durable_outbox(
          item_id TEXT PRIMARY KEY,
          payload_json TEXT NOT NULL,
          payload_sha256 TEXT NOT NULL,
          signature TEXT NOT NULL,
          state TEXT NOT NULL,
          attempts INTEGER NOT NULL,
          next_attempt REAL NOT NULL,
          lease_owner TEXT NOT NULL,
          lease_until REAL NOT NULL,
          last_error TEXT NOT NULL,
          created_at REAL NOT NULL,
          size_bytes INTEGER NOT NULL
        );
        """
    )
    connection.execute(
        "INSERT INTO durable_outbox VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "legacy", payload_json, digest, signature, "pending", 0, 0.0,
            "", 0.0, "", created_at, len(payload_json.encode("utf-8")),
        ),
    )
    connection.commit()
    connection.close()

    queue = DurableOutbox(path, key)
    migrated = queue._db.execute(
        "SELECT state_signature FROM durable_outbox WHERE item_id='legacy'"
    ).fetchone()
    assert migrated is not None and len(migrated[0]) == 64
    assert [item.item_id for item in queue.claim("worker", now=20)] == ["legacy"]
    queue.close()


def test_siem_cursor_advances_only_after_full_durable_stage(tmp_path, monkeypatch) -> None:
    bus = EventBus(ring_size=20)
    module = SIEMForwarderModule()
    module.bind(bus)
    module.min_sev = Severity.INFO
    module._outbox = DurableOutbox(tmp_path / "siem.sqlite3", b"s" * 32)
    for index in range(3):
        bus.publish(Event("sensor", f"event-{index}", Severity.HIGH, 100.0 + index, {}))

    original_enqueue = module._outbox.enqueue
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected durable write failure")
        return original_enqueue(*args, **kwargs)

    monkeypatch.setattr(module._outbox, "enqueue", fail_second)
    with pytest.raises(OSError, match="injected"):
        module._stage_bus_delta()
    assert module._bus_revision == 0

    monkeypatch.setattr(module._outbox, "enqueue", original_enqueue)
    assert module._stage_bus_delta() == 2  # event 0 is an idempotent replay
    assert module._bus_revision == bus.revision()
    assert module._outbox.stats().pending == 3
    module._outbox.close()


def test_siem_failed_network_delivery_remains_replayable(tmp_path, monkeypatch) -> None:
    module = SIEMForwarderModule()
    module._outbox = DurableOutbox(tmp_path / "siem.sqlite3", b"d" * 32)
    for index in range(3):
        module._outbox.enqueue(
            f"event-{index}", {"cef": f"CEF:{index}"}, now=100 + index
        )
    sent = []

    def sender(payload: str) -> None:
        sent.append(payload)
        if payload == "CEF:1":
            raise OSError("collector offline")

    monkeypatch.setattr(module, "_send", sender)
    module._drain_outbox()
    stats = module._outbox.stats()
    assert stats.pending == 1
    assert module._fails == 1
    assert "CEF:1" in sent
    module._outbox.close()

    reopened = DurableOutbox(tmp_path / "siem.sqlite3", b"d" * 32)
    replay = reopened.claim("after-restart", now=time.time() + 10, limit=10)
    assert [item.payload["cef"] for item in replay] == ["CEF:1"]
    reopened.close()


def test_exporters_stage_explicit_receipt_when_bus_ingress_overflows(tmp_path) -> None:
    bus = EventBus(ring_size=2, priority_ring_size=2)
    siem = SIEMForwarderModule()
    siem.bind(bus)
    siem.min_sev = Severity.INFO
    siem._outbox = DurableOutbox(tmp_path / "siem-gap.sqlite3", b"s" * 32)
    bridge = RemoteBridge()
    bridge._key = b"r" * 32
    bridge.bind(bus)
    bridge._sender_outbox = DurableOutbox(
        tmp_path / "bridge-gap.sqlite3", bridge._key
    )
    for index in range(3):
        bus.publish(Event("sensor", f"high-{index}", Severity.HIGH, 100.0 + index, {}))
    source_revision = bus.revision()

    _siem_staged = siem._stage_bus_delta()
    _bridge_staged, overflow = bridge._stage_sender_delta()

    assert overflow is True
    assert siem._ingress_gaps == 1 and siem.health == 45
    # Gap telemetry emitted while staging is a later bus revision; the durable
    # cursor must acknowledge exactly the source delta it read.
    assert siem._bus_revision == source_revision
    assert siem._outbox.stats().pending == 3  # retained suffix plus one gap receipt
    assert bridge._bus_overflow_count == 1
    assert bridge._bus_priority_revision == bus.priority_revision()
    assert bridge._sender_outbox.stats().pending == 3
    siem._outbox.close()
    bridge._sender_outbox.close()


def test_remote_sender_outbox_survives_restart_until_stored_ack(tmp_path, monkeypatch) -> None:
    bus = EventBus(ring_size=10, priority_ring_size=10)
    bridge = RemoteBridge()
    bridge._key = b"k" * 32
    bridge.bind(bus)
    path = tmp_path / "bridge.sqlite3"
    bridge._sender_outbox = DurableOutbox(path, bridge._key)
    bus.publish(Event("sensor", "critical", Severity.CRITICAL, 123.0, {"path": "C:/x"}))

    staged, overflow = bridge._stage_sender_delta()
    assert staged == 1 and overflow is False
    assert bridge._bus_priority_revision == bus.priority_revision()
    assert bridge._sender_outbox.stats().pending == 1
    bridge._sender_outbox.close()

    replay = RemoteBridge()
    replay._key = bridge._key
    replay._sender_outbox = DurableOutbox(path, replay._key)
    acknowledged: list[str] = []
    monkeypatch.setattr(
        replay,
        "_forward_payload",
        lambda _peer, _payload, event_id: acknowledged.append(event_id) or True,
    )
    replay._drain_sender(("127.0.0.1", 47924))

    assert len(acknowledged) == 1
    assert replay._sender_outbox.stats().pending == 0
    assert replay._sender_outbox.stats().delivered_tombstones == 1
    replay._sender_outbox.close()


def test_same_instance_exporter_restart_stages_events_published_while_stopped(tmp_path) -> None:
    bus = EventBus(ring_size=20, priority_ring_size=20)
    siem = SIEMForwarderModule()
    siem.bind(bus)
    siem.min_sev = Severity.INFO
    siem._outbox = DurableOutbox(tmp_path / "siem-restart.sqlite3", b"s" * 32)
    bridge = RemoteBridge()
    bridge._key = b"r" * 32
    bridge.bind(bus)
    bridge._sender_outbox = DurableOutbox(tmp_path / "bridge-restart.sqlite3", b"b" * 32)

    bus.publish(Event("sensor", "before-enrollment", Severity.HIGH, 100.0, {}))
    siem._enroll_cursor_once()
    bridge._enroll_sender_cursor_once()
    enrolled_general = siem._bus_revision
    enrolled_priority = bridge._bus_priority_revision

    # Both modules are conceptually stopped here, but the shared EventBus keeps
    # receiving evidence. A second generation must not reseed over this event.
    bus.publish(Event("sensor", "while-stopped", Severity.HIGH, 101.0, {}))
    assert siem._enroll_cursor_once() == enrolled_general
    assert bridge._enroll_sender_cursor_once() == enrolled_priority

    assert siem._stage_bus_delta() == 1
    assert bridge._stage_sender_delta() == (1, False)
    assert siem._outbox.stats().pending == 1
    assert bridge._sender_outbox.stats().pending == 1
    siem._outbox.close()
    bridge._sender_outbox.close()
