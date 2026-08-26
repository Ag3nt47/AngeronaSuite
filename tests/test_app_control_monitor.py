from __future__ import annotations

import hashlib
import json
from pathlib import Path

from angerona.core.eventbus import EventBus
from angerona.modules.app_control_monitor import AppControlDecisionSensor


ACTIVITY = "{22222222-2222-2222-2222-222222222222}"


def _xml(event_id: int, record_id: int, fields: dict[str, object]) -> str:
    data = "".join(
        f"<Data Name='{name}'>{value}</Data>" for name, value in fields.items()
    )
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System><EventID>{event_id}</EventID><EventRecordID>{record_id}</EventRecordID>
      <Correlation ActivityID='{ACTIVITY}'/></System><EventData>{data}</EventData></Event>"""


def _record_id(xml: str) -> int:
    marker = "<EventRecordID>"
    start = xml.index(marker) + len(marker)
    return int(xml[start:xml.index("</EventRecordID>", start)])


class FakeSource:
    def __init__(self, rows: list[str] | None = None) -> None:
        self.rows = list(rows or [])
        self.closed = False

    def newest_record_id(self) -> int:
        return max((_record_id(row) for row in self.rows), default=0)

    def oldest_record_id(self) -> int:
        return min((_record_id(row) for row in self.rows), default=0)

    def record_anchor(self, record_id: int) -> str:
        row = next(
            (item for item in self.rows if _record_id(item) == record_id),
            "",
        )
        return hashlib.sha256(row.encode("utf-8")).hexdigest() if row else ""

    def read_after(self, record_id: int, limit: int) -> list[str]:
        return [row for row in self.rows if _record_id(row) > record_id][:limit]

    def close(self) -> None:
        self.closed = True


class ClearBetweenWatermarksSource(FakeSource):
    """Model a channel clear after the oldest query but before newest."""

    def oldest_record_id(self) -> int:
        return 20

    def newest_record_id(self) -> int:
        return 0


class ClearAfterFirstAnchorSource(FakeSource):
    """Replace the channel after admission but before read_after()."""

    def __init__(self, rows: list[str], replacement: list[str]) -> None:
        super().__init__(rows)
        self.replacement = replacement
        self.anchor_calls = 0

    def record_anchor(self, record_id: int) -> str:
        self.anchor_calls += 1
        anchor = super().record_anchor(record_id)
        # Call 1 creates the baseline. Call 2 is the next poll's initial
        # admission check; replace immediately after returning that old anchor.
        if self.anchor_calls == 2:
            self.rows[:] = self.replacement
        return anchor


class ClearDuringCheckpointSource(FakeSource):
    """Replace the channel after expected-anchor admission inside checkpoint."""

    def __init__(self, rows: list[str], replacement: list[str]) -> None:
        super().__init__(rows)
        self.replacement = replacement
        self.anchor_calls = 0

    def record_anchor(self, record_id: int) -> str:
        self.anchor_calls += 1
        anchor = super().record_anchor(record_id)
        if self.anchor_calls == 6:
            self.rows[:] = self.replacement
        return anchor


def test_sensor_establishes_baseline_then_emits_non_authorizing_decision(
    tmp_path: Path,
) -> None:
    source = FakeSource([_xml(3099, 10, {"PolicyName": "Existing"})])
    sensor = AppControlDecisionSensor(
        source, tmp_path, cursor_key=b"k" * 32, correlation_ttl=0.01
    )
    bus = EventBus()
    sensor.bind(bus)
    assert sensor.poll_once() == 0
    assert bus.recent() == []

    source.rows.extend([
        _xml(3077, 11, {
            "FileName": r"C:\Temp\blocked.exe", "PolicyName": "Enforced",
            "SHA256Hash": "a" * 64,
        }),
        _xml(3089, 12, {
            "TotalSignatureCount": "0", "Signature": "0", "Hash": "a" * 64,
        }),
    ])
    assert sensor.poll_once() == 2
    event = bus.recent(1)[0]
    assert "blocked blocked.exe" in event.message
    assert event.details["decision"] == "enforced-block"
    assert event.details["correlation_status"] == "complete"
    assert event.details["response_authorized"] is False
    assert event.details["response_authority"] == "observe-only"
    assert event.details["raw_sensor_evidence"] is True


def test_cursor_tamper_and_channel_regression_are_visible(tmp_path: Path) -> None:
    source = FakeSource([_xml(3099, 10, {"PolicyName": "P"})])
    sensor = AppControlDecisionSensor(source, tmp_path, cursor_key=b"z" * 32)
    bus = EventBus()
    sensor.bind(bus)
    sensor.poll_once()
    cursor = tmp_path / "sensor-cursors" / "app-control.json"
    document = json.loads(cursor.read_text(encoding="utf-8"))
    document["record_id"] = 99
    cursor.write_text(json.dumps(document), encoding="utf-8")

    restarted = AppControlDecisionSensor(source, tmp_path, cursor_key=b"z" * 32)
    restarted.bind(bus)
    restarted.poll_once()
    messages = [event.message for event in bus.recent()]
    assert any("authentication failed" in message for message in messages)

    source.rows.clear()
    restarted.poll_once()
    messages = [event.message for event in bus.recent()]
    assert any("visibility gap" in message for message in messages)


def test_module_self_test_and_cursor_are_bounded(tmp_path: Path) -> None:
    sensor = AppControlDecisionSensor(FakeSource(), tmp_path, cursor_key=b"q" * 32)
    assert sensor.self_test()[0]
    sensor.poll_once()
    cursor = tmp_path / "sensor-cursors" / "app-control.json"
    assert cursor.stat().st_size < 4096


def test_cursor_authority_failure_never_becomes_false_healthy(tmp_path: Path) -> None:
    sensor = AppControlDecisionSensor(
        FakeSource(), tmp_path, cursor_key=b"too-short"
    )
    bus = EventBus()
    sensor.bind(bus)
    assert sensor.poll_once() == 0
    assert sensor.health == 55
    assert not (tmp_path / "sensor-cursors" / "app-control.json").exists()

    # A second idle poll used to overwrite the failure with health=100 despite
    # still having no authenticated restart checkpoint.
    assert sensor.poll_once() == 0
    assert sensor.health == 55
    assert "checkpoint authority unavailable" in sensor.health_note


def test_untrusted_cursor_is_repaired_but_gap_stays_visible_for_poll(
    tmp_path: Path,
) -> None:
    source = FakeSource()
    key = b"r" * 32
    sensor = AppControlDecisionSensor(source, tmp_path, cursor_key=key)
    sensor.bind(EventBus())
    sensor.poll_once()
    cursor = tmp_path / "sensor-cursors" / "app-control.json"
    cursor.write_text("{}", encoding="utf-8")

    restarted = AppControlDecisionSensor(source, tmp_path, cursor_key=key)
    restarted.bind(EventBus())
    restarted.poll_once()
    assert restarted.health == 35
    assert restarted._cursor.load() == (0, "authenticated", "")
    restarted.poll_once()
    assert restarted.health == 100


def test_owned_source_is_detached_after_close_for_clean_restart(
    tmp_path: Path,
) -> None:
    source = FakeSource()
    sensor = AppControlDecisionSensor(
        None, tmp_path, cursor_key=b"s" * 32
    )
    sensor._source = source
    sensor._stop.set()
    sensor.run()
    assert source.closed is True
    assert sensor._source is None


def test_pending_activity_join_survives_restart(tmp_path: Path) -> None:
    source = FakeSource()
    key = b"t" * 32
    first = AppControlDecisionSensor(
        source, tmp_path, correlation_ttl=60, cursor_key=key
    )
    first.bind(EventBus())
    first.poll_once()
    source.rows.append(_xml(3077, 1, {
        "FileName": r"C:\Private\restart.exe", "PolicyName": "Enforced",
    }))
    assert first.poll_once() == 1

    bus = EventBus()
    restarted = AppControlDecisionSensor(
        source, tmp_path, correlation_ttl=60, cursor_key=key
    )
    restarted.bind(bus)
    source.rows.append(_xml(3089, 2, {
        "TotalSignatureCount": "0", "Signature": "0",
    }))
    assert restarted.poll_once() == 1
    decisions = [event for event in bus.recent() if "restart.exe" in event.message]
    assert len(decisions) == 1
    assert decisions[0].details["correlation_status"] == "complete"
    assert r"C:\Private" not in json.dumps(decisions[0].details)


def test_tampered_pending_state_is_visible_and_replayed(tmp_path: Path) -> None:
    source = FakeSource()
    key = b"u" * 32
    first = AppControlDecisionSensor(
        source, tmp_path, correlation_ttl=60, cursor_key=key
    )
    first.bind(EventBus())
    first.poll_once()
    source.rows.append(_xml(3077, 1, {"FileName": "recover.exe"}))
    first.poll_once()

    pending = tmp_path / "sensor-cursors" / "app-control.pending.json"
    document = json.loads(pending.read_text(encoding="utf-8"))
    document["state"]["groups"] = []
    pending.write_text(json.dumps(document), encoding="utf-8")
    source.rows.append(_xml(3089, 2, {
        "TotalSignatureCount": "0", "Signature": "0",
    }))

    bus = EventBus()
    restarted = AppControlDecisionSensor(
        source, tmp_path, correlation_ttl=60, cursor_key=key
    )
    restarted.bind(bus)
    restarted.poll_once()
    messages = [event.message for event in bus.recent()]
    assert any("checkpoint is untrusted" in message for message in messages)
    assert sum("recover.exe" in message for message in messages) == 1


def test_retention_gap_reports_exact_missing_interval(tmp_path: Path) -> None:
    source = FakeSource([_xml(3099, 20, {"PolicyName": "Retained"})])
    sensor = AppControlDecisionSensor(source, tmp_path, cursor_key=b"v" * 32)
    sensor.bind(EventBus())
    assert sensor._pending.save(sensor._correlator.export_state())
    assert sensor._cursor.save(10, "a" * 64)

    bus = EventBus()
    restarted = AppControlDecisionSensor(source, tmp_path, cursor_key=b"v" * 32)
    restarted.bind(bus)
    restarted.poll_once()
    gap = next(
        event for event in bus.recent()
        if "retained channel history" in event.message
    )
    assert gap.details["missing_record_start"] == 11
    assert gap.details["missing_record_end"] == 19
    assert gap.details["oldest_retained_record"] == 20


def test_channel_clear_resets_dedupe_before_record_ids_are_reused(
    tmp_path: Path,
) -> None:
    source = FakeSource()
    sensor = AppControlDecisionSensor(
        source, tmp_path, cursor_key=b"w" * 32, correlation_ttl=60
    )
    bus = EventBus()
    sensor.bind(bus)
    sensor.poll_once()
    source.rows.extend([
        _xml(3077, 1, {"FileName": "old.exe"}),
        _xml(3089, 2, {
            "TotalSignatureCount": "0", "Signature": "0", "Hash": "old",
        }),
    ])
    sensor.poll_once()

    source.rows.clear()
    sensor.poll_once()
    source.rows.extend([
        _xml(3077, 1, {"FileName": "new.exe"}),
        _xml(3089, 2, {
            "TotalSignatureCount": "0", "Signature": "0", "Hash": "replacement",
        }),
    ])
    sensor.poll_once()
    messages = [event.message for event in bus.recent()]
    assert sum("old.exe" in message for message in messages) == 1
    assert sum("new.exe" in message for message in messages) == 1
    decision_events = [
        event for event in bus.recent()
        if event.details.get("decision") == "enforced-block"
    ]
    assert all(
        event.details["correlation_status"] != "record-id-conflict"
        for event in decision_events
    )


def test_checkpoint_anchor_detects_clear_and_refill_past_old_cursor(
    tmp_path: Path,
) -> None:
    source = FakeSource([
        _xml(3077, 1, {"FileName": "old.exe"}),
        _xml(3089, 2, {
            "TotalSignatureCount": "0", "Signature": "0", "Hash": "old-anchor",
        }),
    ])
    key = b"a" * 32
    sensor = AppControlDecisionSensor(source, tmp_path, cursor_key=key)
    sensor.bind(EventBus())
    sensor.poll_once()

    # Replace the entire channel and refill beyond cursor 2 before the next
    # poll. Range-only continuity checks cannot distinguish this from growth.
    source.rows[:] = [
        _xml(3077, 1, {"FileName": "replacement.exe"}),
        _xml(3089, 2, {
            "TotalSignatureCount": "0", "Signature": "0", "Hash": "new-anchor",
        }),
        _xml(3099, 3, {"PolicyName": "Replacement"}),
        _xml(3096, 4, {"PolicyName": "Replacement"}),
    ]
    bus = EventBus()
    restarted = AppControlDecisionSensor(source, tmp_path, cursor_key=key)
    restarted.bind(bus)
    restarted.poll_once()

    messages = [event.message for event in bus.recent()]
    assert any("record anchor changed" in message for message in messages)
    assert sum("replacement.exe" in message for message in messages) == 1
    assert restarted._cursor.load()[0] == 4


def test_mid_poll_clear_is_rejected_before_staged_rows_are_emitted(
    tmp_path: Path,
) -> None:
    old_rows = [
        _xml(3077, 1, {"FileName": "old.exe"}),
        _xml(3089, 2, {
            "TotalSignatureCount": "0", "Signature": "0", "Hash": "old",
        }),
    ]
    replacement = [
        _xml(3077, 1, {"FileName": "midpoll.exe"}),
        _xml(3089, 2, {
            "TotalSignatureCount": "0", "Signature": "0", "Hash": "new",
        }),
        _xml(3099, 3, {"PolicyName": "New"}),
        _xml(3096, 4, {"PolicyName": "New"}),
    ]
    source = ClearAfterFirstAnchorSource(old_rows, replacement)
    key = b"m" * 32
    sensor = AppControlDecisionSensor(source, tmp_path, cursor_key=key)
    sensor.bind(EventBus())
    sensor.poll_once()

    bus = EventBus()
    restarted = AppControlDecisionSensor(source, tmp_path, cursor_key=key)
    restarted.bind(bus)
    assert restarted.poll_once() == 0
    assert any(
        "changed during event query" in event.message
        for event in bus.recent()
    )
    assert not any("midpoll.exe" in event.message for event in bus.recent())

    # The next poll starts at the replacement generation's oldest retained ID.
    assert restarted.poll_once() == 4
    assert sum(
        "midpoll.exe" in event.message for event in bus.recent()
    ) == 1


def test_clear_during_checkpoint_cannot_bind_replacement_anchor(
    tmp_path: Path,
) -> None:
    source = ClearDuringCheckpointSource(
        [
            _xml(3077, 1, {"FileName": "baseline.exe"}),
            _xml(3089, 2, {
                "TotalSignatureCount": "0", "Signature": "0", "Hash": "base",
            }),
        ],
        [
            _xml(3077, 1, {"FileName": "checkpoint-replacement.exe"}),
            _xml(3089, 2, {
                "TotalSignatureCount": "0", "Signature": "0",
                "Hash": "replacement",
            }),
            _xml(3099, 3, {"PolicyName": "New"}),
            _xml(3096, 4, {"PolicyName": "New"}),
            _xml(3099, 5, {"PolicyName": "New"}),
            _xml(3096, 6, {"PolicyName": "New"}),
        ],
    )
    sensor = AppControlDecisionSensor(source, tmp_path, cursor_key=b"c" * 32)
    bus = EventBus()
    sensor.bind(bus)
    sensor.poll_once()
    source.rows.extend([
        _xml(3077, 3, {"FileName": "old-tail.exe"}),
        _xml(3089, 4, {
            "TotalSignatureCount": "0", "Signature": "0", "Hash": "old-tail",
        }),
    ])

    assert sensor.poll_once() == 2
    assert any(
        "changed during checkpoint" in event.message
        for event in bus.recent()
    )
    assert sensor._cursor_value == 0
    assert sensor.poll_once() == 6
    assert sum(
        "checkpoint-replacement.exe" in event.message
        for event in bus.recent()
    ) == 1


def test_channel_clear_between_watermarks_never_persists_cursor_above_newest(
    tmp_path: Path,
) -> None:
    source = ClearBetweenWatermarksSource()
    key = b"y" * 32
    prepared = AppControlDecisionSensor(source, tmp_path, cursor_key=key)
    assert prepared._pending.save(prepared._correlator.export_state())
    assert prepared._cursor.save(10, "a" * 64)

    bus = EventBus()
    restarted = AppControlDecisionSensor(source, tmp_path, cursor_key=key)
    restarted.bind(bus)
    assert restarted.poll_once() == 0
    assert restarted._cursor.load() == (0, "authenticated", "")
    gaps = [event for event in bus.recent() if "visibility gap" in event.message]
    assert len(gaps) == 1

    # A subsequent poll is clean rather than repeating the same stale gap.
    restarted.poll_once()
    assert len([
        event for event in bus.recent() if "visibility gap" in event.message
    ]) == 1


def test_pending_checkpoint_failure_does_not_advance_cursor(
    tmp_path: Path, monkeypatch
) -> None:
    source = FakeSource()
    sensor = AppControlDecisionSensor(source, tmp_path, cursor_key=b"x" * 32)
    sensor.bind(EventBus())
    sensor.poll_once()
    source.rows.append(_xml(3077, 1, {"FileName": "pending.exe"}))
    monkeypatch.setattr(sensor._pending, "save", lambda _state: False)
    assert sensor.poll_once() == 1
    assert sensor._cursor.load() == (0, "authenticated", "")
    assert sensor.health == 55


def test_idle_poll_does_not_rewrite_unchanged_pending_state(
    tmp_path: Path, monkeypatch
) -> None:
    sensor = AppControlDecisionSensor(
        FakeSource(), tmp_path, cursor_key=b"i" * 32
    )
    sensor.bind(EventBus())
    sensor.poll_once()
    writes = 0
    original_save = sensor._pending.save

    def counted_save(state: dict) -> bool:
        nonlocal writes
        writes += 1
        return original_save(state)

    monkeypatch.setattr(sensor._pending, "save", counted_save)
    sensor.poll_once()
    assert writes == 0
