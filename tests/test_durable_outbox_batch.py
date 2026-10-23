from __future__ import annotations

import sqlite3

import pytest

from angerona.core.durable_outbox import (
    MAX_ENQUEUE_BATCH_ITEMS,
    MAX_ITEM_BYTES,
    DurableOutbox,
    OutboxFull,
    OutboxIntegrityError,
    _canonical,
)
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules.remote_bridge import RemoteBridge
from angerona.modules.siem_forwarder import SIEMForwarderModule


class _ConnectionFault:
    """Delegate to the real SQLite connection; fail before the selected commit."""

    def __init__(self, connection, *, commit=False, insert=False):
        self.connection = connection
        self.fail_commit = commit
        self.fail_insert = insert
        self.rollbacks = 0

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def commit(self):
        if self.fail_commit:
            raise sqlite3.OperationalError("injected batch commit failure")
        return self.connection.commit()

    def executemany(self, sql, rows):
        if self.fail_insert:
            self.connection.execute(sql, rows[0])
            raise sqlite3.OperationalError("injected partial insert failure")
        return self.connection.executemany(sql, rows)

    def rollback(self):
        self.rollbacks += 1
        return self.connection.rollback()


def test_batch_one_full_sync_commit_reopens_authenticated_rows(tmp_path):
    path = tmp_path / "batch.sqlite3"
    queue = DurableOutbox(path, b"b" * 32)
    statements = []
    queue._db.set_trace_callback(statements.append)
    try:
        assert queue.enqueue_many([
            ("one", {"value": 1}, 10.0),
            ("two", {"value": 2}, 20.0),
            ("three", {"value": 3}, 30.0),
        ]) == 3
        assert statements.count("BEGIN IMMEDIATE") == 1
        assert statements.count("COMMIT") == 1
        assert queue._db.execute("PRAGMA synchronous").fetchone() == (2,)
        assert queue._db.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        statements.clear()
        for index in range(3):
            queue.enqueue(f"single-{index}", {"value": index}, now=40 + index)
        assert statements.count("COMMIT") == 3
    finally:
        queue.close()
    reopened = DurableOutbox(path, b"b" * 32)
    try:
        items = reopened.claim("reader", now=100, limit=100)
        assert [item.item_id for item in items] == [
            "one", "two", "three", "single-0", "single-1", "single-2"
        ]
        assert [item.created_at for item in items[:3]] == [10.0, 20.0, 30.0]
    finally:
        reopened.close()


def test_batch_duplicates_preserve_first_timestamp_and_existing_delivery_state(tmp_path):
    queue = DurableOutbox(tmp_path / "duplicates.sqlite3", b"d" * 32)
    try:
        assert queue.enqueue_many([
            ("same", {"value": 1}, 10.0),
            ("same", {"value": 1}, 99.0),
        ]) == 1
        assert queue.claim("worker", now=20, limit=1)[0].created_at == 10.0
        assert queue.enqueue_many([("same", {"value": 1}, 200.0)]) == 0
        assert queue.stats().leased == 1
        queue.acknowledge("same", "worker")
        assert queue.enqueue_many([
            ("same", {"value": 1}, 300.0),
            ("new", {"value": 2}, 400.0),
        ]) == 1
        assert queue.is_delivered("same")
        assert queue.stats().pending == 1
    finally:
        queue.close()


@pytest.mark.parametrize("retained", [False, True])
def test_batch_conflicting_later_id_rolls_back_valid_first_entry(tmp_path, retained):
    queue = DurableOutbox(tmp_path / "conflict.sqlite3", b"c" * 32)
    try:
        if retained:
            queue.enqueue("conflict", {"value": "original"}, now=1)
        entries = [("new-first", {"value": "must-roll-back"}, 2.0)]
        if not retained:
            entries.append(("conflict", {"value": "original"}, 3.0))
        entries.append(("conflict", {"value": "changed"}, 4.0))
        with pytest.raises(ValueError, match="conflicts"):
            queue.enqueue_many(entries)
        assert queue.stats().pending == int(retained)
        assert not queue._db.execute(
            "SELECT 1 FROM durable_outbox WHERE item_id='new-first'"
        ).fetchone()
    finally:
        queue.close()


@pytest.mark.parametrize("bound", ["items", "bytes"])
def test_batch_enforces_aggregate_capacity_without_partial_additions(tmp_path, bound):
    queue = DurableOutbox(tmp_path / "capacity.sqlite3", b"a" * 32,
                          max_items=100, max_bytes=MAX_ITEM_BYTES)
    try:
        if bound == "items":
            queue.enqueue_many([(f"seed-{i}", {"i": i}, float(i)) for i in range(99)])
            entries = [("one", {}, 100.0), ("two", {}, 101.0)]
        else:
            entries = [("one", {"data": "x" * 140_000}, 1.0),
                       ("two", {"data": "y" * 140_000}, 2.0)]
        before = queue.stats()
        with pytest.raises(OutboxFull):
            queue.enqueue_many(entries)
        assert queue.stats() == before
        assert not queue._db.execute(
            "SELECT 1 FROM durable_outbox WHERE item_id IN ('one','two')"
        ).fetchone()
    finally:
        queue.close()


@pytest.mark.parametrize("external", [False, True])
def test_batch_authenticates_unrelated_tampered_retained_rows(tmp_path, external):
    path = tmp_path / "tamper.sqlite3"
    queue = DurableOutbox(path, b"t" * 32)
    try:
        queue.enqueue("unrelated", {"value": 1}, now=1)
        writer = sqlite3.connect(path) if external else queue._db
        try:
            writer.execute("UPDATE durable_outbox SET next_attempt=12345")
            writer.commit()
        finally:
            if external:
                writer.close()
        with pytest.raises(OutboxIntegrityError, match="mutable-state authentication"):
            queue.enqueue_many([("new", {"value": 2}, 2.0)])
        assert not queue._db.execute(
            "SELECT 1 FROM durable_outbox WHERE item_id='new'"
        ).fetchone()
    finally:
        queue.close()


@pytest.mark.parametrize("fault", ["commit", "insert"])
def test_batch_commit_or_partial_insert_failure_rolls_back_and_reopens(tmp_path, fault):
    path = tmp_path / "rollback.sqlite3"
    queue = DurableOutbox(path, b"r" * 32)
    real = queue._db
    failing = _ConnectionFault(real, commit=fault == "commit", insert=fault == "insert")
    queue._db = failing
    try:
        with pytest.raises(sqlite3.OperationalError, match="injected"):
            queue.enqueue_many([("one", {"value": 1}, 1.0),
                                ("two", {"value": 2}, 2.0)])
        assert failing.rollbacks == 1
        assert not real.in_transaction
    finally:
        queue._db = real
        queue.close()
    reopened = DurableOutbox(path, b"r" * 32)
    try:
        assert reopened.stats().pending == 0
        assert reopened.enqueue_many([("one", {"value": 1}, 1.0),
                                      ("two", {"value": 2}, 2.0)]) == 2
    finally:
        reopened.close()


@pytest.mark.parametrize("bad", [
    ("", {}, 1.0),
    ("bad", [], 1.0),
    ("bad", {"value": "x" * MAX_ITEM_BYTES}, 1.0),
    ("first", {}, float("nan")),
])
def test_batch_invalid_later_entry_never_opens_transaction(tmp_path, bad):
    queue = DurableOutbox(tmp_path / "invalid.sqlite3", b"v" * 32)
    statements = []
    queue._db.set_trace_callback(statements.append)
    try:
        with pytest.raises((TypeError, ValueError)):
            queue.enqueue_many([("first", {}, 1.0), bad])
        assert "BEGIN IMMEDIATE" not in statements
        assert queue.stats().pending == 0
    finally:
        queue.close()


def test_batch_count_bound_empty_and_unbounded_iterator_refusal(tmp_path):
    queue = DurableOutbox(tmp_path / "bound.sqlite3", b"n" * 32)
    statements = []
    queue._db.set_trace_callback(statements.append)
    try:
        assert queue.enqueue_many([]) == 0
        with pytest.raises(ValueError, match="100 entries"):
            queue.enqueue_many([(str(i), {}, float(i))
                                for i in range(MAX_ENQUEUE_BATCH_ITEMS + 1)])
        with pytest.raises(TypeError, match="bounded sequence"):
            queue.enqueue_many(iter([("one", {}, 1.0)]))
        assert "BEGIN IMMEDIATE" not in statements
        assert queue.stats().pending == 0
    finally:
        queue.close()


def _exporter(kind, tmp_path, *, ring_size=300, outbox_options=None):
    options = outbox_options or {}
    bus = EventBus(ring_size=ring_size, priority_ring_size=ring_size)
    if kind == "siem":
        module = SIEMForwarderModule()
        module.min_sev = Severity.INFO
        module._outbox = DurableOutbox(tmp_path / "siem.sqlite3", b"s" * 32, **options)
        queue = module._outbox
        stage = module._stage_bus_delta
        cursor = lambda: module._bus_revision
    else:
        module = RemoteBridge()
        module._key = b"r" * 32
        module._sender_outbox = DurableOutbox(
            tmp_path / "remote.sqlite3", b"r" * 32, **options
        )
        queue = module._sender_outbox
        stage = module._stage_sender_delta
        cursor = lambda: module._bus_priority_revision
    module.bind(bus)
    return bus, module, queue, stage, cursor


@pytest.mark.parametrize("kind", ["siem", "remote"])
def test_exporter_chunks_bounded_transactions_before_cursor(tmp_path, monkeypatch, kind):
    bus, _module, queue, stage, cursor = _exporter(kind, tmp_path)
    for i in range(205):
        bus.publish(Event("sensor", f"event-{i}", Severity.HIGH, float(i + 1), {}))
    original = queue.enqueue_many
    chunks = []
    statements = []
    queue._db.set_trace_callback(statements.append)

    def record(entries):
        assert cursor() == 0
        chunks.append(len(entries))
        return original(entries)

    monkeypatch.setattr(queue, "enqueue_many", record)
    try:
        result = stage()
        assert (result if kind == "siem" else result[0]) == 205
        assert chunks == [100, 100, 5]
        assert statements.count("COMMIT") == 3
        assert cursor() == 205
        assert queue.stats().pending == 205
    finally:
        queue.close()


@pytest.mark.parametrize("kind", ["siem", "remote"])
def test_exporter_commit_failure_cannot_advance_cursor(tmp_path, kind):
    bus, _module, queue, stage, cursor = _exporter(kind, tmp_path)
    bus.publish(Event("sensor", "must remain replayable", Severity.HIGH, 1.0, {}))
    real = queue._db
    failing = _ConnectionFault(real, commit=True)
    queue._db = failing
    try:
        with pytest.raises(sqlite3.OperationalError, match="commit failure"):
            stage()
        assert cursor() == 0
        assert queue.stats().pending == 0
        assert failing.rollbacks == 1
        queue._db = real
        stage()
        assert cursor() == bus.revision()
        assert queue.stats().pending == 1
    finally:
        queue._db = real
        queue.close()


@pytest.mark.parametrize("kind", ["siem", "remote"])
def test_exporter_gap_receipt_failure_keeps_entire_delta_replayable(
    tmp_path, monkeypatch, kind,
):
    bus, module, queue, stage, cursor = _exporter(kind, tmp_path, ring_size=100)
    for i in range(101):
        bus.publish(Event("sensor", f"event-{i}", Severity.HIGH, float(i + 1), {}))
    original = queue.enqueue_many
    calls = 0

    def fail_receipt(entries):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected mandatory gap receipt failure")
        return original(entries)

    monkeypatch.setattr(queue, "enqueue_many", fail_receipt)
    try:
        with pytest.raises(OSError, match="mandatory gap receipt"):
            stage()
        assert cursor() == 0
        assert queue.stats().pending == 100
        if kind == "siem":
            assert module._ingress_gaps == 0
        retry_revision = bus.revision() if kind == "siem" else bus.priority_revision()
        monkeypatch.setattr(queue, "enqueue_many", original)
        result = stage()
        assert (result if kind == "siem" else result[0]) == 1
        assert cursor() == retry_revision
        assert queue.stats().pending == 101
        payloads = [item.payload for item in queue.claim("review", now=10_000, limit=200)]
        if kind == "siem":
            receipts = [p for p in payloads if p.get("ingress_gap") is True]
            assert module._ingress_gaps == 1
        else:
            receipts = [p for p in payloads if p["event"]["details"].get(
                "finding_code") == "remote_bridge.eventbus.capacity_gap"]
        assert len(receipts) == 1
    finally:
        queue.close()


@pytest.mark.parametrize("kind", ["siem", "remote"])
@pytest.mark.parametrize("bound", ["items", "bytes"])
def test_exporter_partial_capacity_preserves_progress_past_dead_letters(
    tmp_path, monkeypatch, kind, bound,
):
    bus, module, queue, _stage, cursor = _exporter(
        kind, tmp_path, outbox_options={
            "max_items": 100, "max_bytes": MAX_ITEM_BYTES, "max_attempts": 1,
        },
    )
    events = [Event("sensor", f"event-{i}", Severity.HIGH, float(i + 1), {})
              for i in range(4)]
    # Bind actual signed event identities before measuring each staged payload.
    for event in events:
        bus.publish(event)
    _, retained, _ = module.read_bus_events(priority=kind == "remote")
    if kind == "siem":
        payloads = [{"cef": module._format_event(event)} for event in retained]
    else:
        payloads = [{"event": module._event_document(event)[1]} for event in retained]
    payload_sizes = [len(_canonical(payload)) for payload in payloads]
    assert len(set(payload_sizes)) == 1
    one_slot_bytes = payload_sizes[0]
    if bound == "items":
        seeds = [(f"dead-{i}", {"value": i}, float(i)) for i in range(99)]
    else:
        pad_length = MAX_ITEM_BYTES - one_slot_bytes - len(_canonical({"pad": ""}))
        assert pad_length > 0
        seeds = [("dead-bytes", {"pad": "x" * pad_length}, 0.0)]
    queue.enqueue_many(seeds)
    for item in queue.claim("seed", now=1_000, limit=100):
        queue.retry(item.item_id, "seed", "retained evidence", now=1_000)
    assert queue.stats().dead_letter == len(seeds)
    sent = []
    if kind == "siem":
        monkeypatch.setattr(module, "_send", lambda payload: sent.append(payload))
        cycle = module._delivery_cycle
    else:
        monkeypatch.setattr(module, "_forward_payload",
                            lambda _peer, _payload, event_id: sent.append(event_id) or True)
        cycle = lambda: module._sender_delivery_cycle(("127.0.0.1", 47924))
    try:
        # One reusable slot permits one new item per tick. A failed aggregate
        # batch must retain the old committed-prefix/drain/replay behavior.
        for _ in range(3):
            with pytest.raises(OutboxFull):
                cycle()
            assert cursor() == 0
            assert queue.stats().pending == 1
        cycle()
        assert cursor() == 4
        assert queue.stats().pending == 0
        assert queue.stats().dead_letter == len(seeds)
        assert len(sent) == len(set(sent)) == 4
    finally:
        queue.close()


@pytest.mark.parametrize("kind", ["siem", "remote"])
@pytest.mark.parametrize("error", [
    OutboxIntegrityError("injected authentication refusal"),
    ValueError("injected conflicting ID"),
    sqlite3.OperationalError("injected database failure"),
])
def test_exporter_noncapacity_failure_never_falls_back_to_single_enqueue(
    tmp_path, monkeypatch, kind, error,
):
    bus, _module, queue, stage, cursor = _exporter(kind, tmp_path)
    bus.publish(Event("sensor", "event", Severity.HIGH, 1.0, {}))
    single_calls = []

    def fail_batch(_entries):
        raise error

    def forbidden_single(*_args, **_kwargs):
        single_calls.append(True)
        raise AssertionError("noncapacity fallback is forbidden")

    monkeypatch.setattr(queue, "enqueue_many", fail_batch)
    monkeypatch.setattr(queue, "enqueue", forbidden_single)
    try:
        with pytest.raises(type(error)) as caught:
            stage()
        assert caught.value is error
        assert single_calls == []
        assert cursor() == 0
        assert queue.stats().pending == 0
    finally:
        queue.close()
