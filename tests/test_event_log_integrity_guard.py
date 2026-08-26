from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

import pytest

from angerona.core.event_log_integrity import (
    AuditEventRejected,
    AuthenticatedEventLogCheckpoint,
    ChannelCheckpoint,
    assess_continuity,
    parse_audit_integrity_xml,
)
from angerona.core.windows_event_log import WindowsEventLogSource
from angerona.core.eventbus import EventBus, Severity
from angerona.modules.audit_log_guard import AuditLogIntegrityGuard


def _xml(
    event_id: int,
    record_id: int,
    *,
    provider: str | None = None,
    channel: str = "Security",
    xml_channel: str | None = None,
    extra_fields: str = "",
) -> str:
    created = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if provider is None:
        provider = (
            "Microsoft-Windows-Security-Auditing"
            if event_id in {4612, 4719, 4902, 4906, 4907, 4912}
            else "Microsoft-Windows-Sysmon"
            if channel == "Microsoft-Windows-Sysmon/Operational"
            else "Microsoft-Windows-Eventlog"
        )
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System><Provider Name='{provider}'/><EventID>{event_id}</EventID>
      <TimeCreated SystemTime='{created}'/><EventRecordID>{record_id}</EventRecordID>
      <Channel>{xml_channel or channel}</Channel></System>
      <EventData><Data Name='Channel'>Security</Data>
      <Data Name='SubjectUserName'>sensitive-user</Data>
      <Data Name='SubjectUserSid'>S-1-5-21-secret</Data>{extra_fields}</EventData></Event>"""


class _Source:
    def __init__(self, rows: list[str] | None = None) -> None:
        self.rows = list(rows or [])

    @staticmethod
    def _record(xml: str) -> int:
        start = xml.index("<EventRecordID>") + len("<EventRecordID>")
        return int(xml[start:xml.index("</EventRecordID>", start)])

    def oldest_record_id(self) -> int:
        return min((self._record(row) for row in self.rows), default=0)

    def newest_record_id(self) -> int:
        return max((self._record(row) for row in self.rows), default=0)

    def record_anchor(self, record_id: int) -> str:
        for row in self.rows:
            if self._record(row) == int(record_id):
                return hashlib.sha256(row.encode()).hexdigest()
        return ""

    def read_after(self, record_id: int, limit: int) -> list[str]:
        return [
            row for row in sorted(self.rows, key=self._record)
            if self._record(row) > int(record_id)
        ][:_max(1, int(limit))]

    def close(self) -> None:
        return None


def _max(first: int, second: int) -> int:
    # A named helper keeps FakeSource behavior explicit in tracebacks.
    return max(first, second)


def test_audit_parser_classifies_clear_and_redacts_identity() -> None:
    record = parse_audit_integrity_xml(_xml(1102, 8), "Security")
    assert record.classification == "audit-log-cleared"
    assert record.severity == "critical"
    assert record.fields == {}
    assert "sensitive-user" not in repr(record)


def test_audit_parser_requires_authoritative_identity_and_fixed_output_keys() -> None:
    with pytest.raises(AuditEventRejected, match="provider-rejected"):
        parse_audit_integrity_xml(
            _xml(104, 9, provider="ForeignProvider", channel="System"), "System"
        )
    with pytest.raises(AuditEventRejected, match="channel-mismatch"):
        parse_audit_integrity_xml(
            _xml(104, 10, channel="System", xml_channel="Application"), "System"
        )
    record = parse_audit_integrity_xml(
        _xml(
            104,
            11,
            channel="System",
            extra_fields="<Data Name='Status'>C:\\secret\\operator.txt</Data>",
        ),
        "System",
    )
    assert record.fields == {"affected_channel": "[REDACTED]"}
    assert "Status" not in record.fields
    assert "secret" not in repr(record)


def test_windows_event_query_binds_event_ids_to_fixed_providers() -> None:
    class _Api:
        EvtQueryChannelPath = 1
        EvtQueryForwardDirection = 2

        def __init__(self) -> None:
            self.expression = ""

        def EvtQuery(self, _channel, _flags, expression):
            self.expression = expression
            return object()

        @staticmethod
        def EvtNext(_query, _count):
            return []

        @staticmethod
        def EvtClose(_handle):
            return None

    api = _Api()
    source = object.__new__(WindowsEventLogSource)
    source.channel = "System"
    source.event_ids = (104,)
    source.providers_by_event = {104: ("Microsoft-Windows-Eventlog",)}
    source._api = api
    assert source.read_after(7) == []
    assert "EventID=104" in api.expression
    assert "Provider[@Name='Microsoft-Windows-Eventlog']" in api.expression


def test_audit_parser_rejects_oversize_and_future_timestamp() -> None:
    with pytest.raises(ValueError, match="admission bound"):
        parse_audit_integrity_xml("x" * (1024 * 1024 + 1), "Security")
    future = re.sub(
        r"SystemTime='[^']+'", "SystemTime='2999-01-01T00:00:00Z'", _xml(1102, 1)
    )
    with pytest.raises(ValueError, match="future"):
        parse_audit_integrity_xml(future, "Security")


def test_authenticated_checkpoint_roundtrip_and_tamper(tmp_path) -> None:
    path = tmp_path / "sensor-cursors" / "audit.json"
    store = AuthenticatedEventLogCheckpoint(path, authority_key=b"k" * 32)
    state = {"Security": ChannelCheckpoint(7, "a" * 64)}
    assert store.load() == ({}, "first-enrollment")
    assert store.save(state)
    loaded, status = store.load()
    assert status == "authenticated"
    assert loaded == state

    document = json.loads(path.read_text(encoding="utf-8"))
    document["channels"]["Security"]["record_id"] = 8
    path.write_text(json.dumps(document), encoding="utf-8")
    assert store.load() == ({}, "untrusted")


def test_checkpoint_epoch_detects_cursor_loss_and_compare_swap_race(tmp_path) -> None:
    path = tmp_path / "sensor-cursors" / "audit.json"
    first = AuthenticatedEventLogCheckpoint(path, authority_key=b"c" * 32)
    assert first.load()[1] == "first-enrollment"
    assert first.save({"Security": ChannelCheckpoint(1, "a" * 64)})

    stale = AuthenticatedEventLogCheckpoint(path, authority_key=b"c" * 32)
    assert stale.load()[1] == "authenticated"
    assert first.save({"Security": ChannelCheckpoint(2, "b" * 64)})
    assert stale.save({"Security": ChannelCheckpoint(3, "c" * 64)}) is False

    path.unlink()
    missing = AuthenticatedEventLogCheckpoint(path, authority_key=b"c" * 32)
    assert missing.load() == ({}, "untrusted")


def test_checkpoint_rejects_link_or_reparse_backed_parent(tmp_path) -> None:
    real_parent = tmp_path / "real-cursors"
    real_parent.mkdir()
    linked_parent = tmp_path / "sensor-cursors"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory links are unavailable on this test host")
    store = AuthenticatedEventLogCheckpoint(
        linked_parent / "audit.json", authority_key=b"l" * 32
    )
    assert store.load() == ({}, "untrusted")


def test_continuity_assessment_fails_closed_on_clear_gap_and_anchor_change() -> None:
    assert assess_continuity(None, oldest=1, newest=9).state == "baseline"
    checkpoint = ChannelCheckpoint(7, "a" * 64)
    assert assess_continuity(
        checkpoint, oldest=1, newest=9, retained_anchor="a" * 64
    ).state == "live"
    cleared = assess_continuity(checkpoint, oldest=1, newest=3)
    assert cleared.state == "gap" and "cleared" in cleared.reason
    rolled = assess_continuity(checkpoint, oldest=9, newest=12)
    assert rolled.state == "gap" and rolled.missing_start == 8
    replaced = assess_continuity(
        checkpoint, oldest=1, newest=9, retained_anchor="b" * 64
    )
    assert replaced.state == "gap" and "replaced" in replaced.reason
    assert assess_continuity(
        checkpoint, oldest=1, newest=9, checkpoint_status="untrusted"
    ).state == "untrusted"


def test_guard_replays_first_enrollment_then_emits_clear_without_raw_identity(tmp_path) -> None:
    sources = {
        "Security": _Source([_xml(4719, 1)]),
        "System": _Source(),
        "Microsoft-Windows-Sysmon/Operational": _Source(),
    }
    bus = EventBus()
    guard = AuditLogIntegrityGuard(
        sources=sources, data_root=tmp_path, checkpoint_key=b"z" * 32
    )
    guard.bind(bus)
    assert guard.poll_once() == 1
    sources["Security"].rows.append(_xml(1102, 2))
    assert guard.poll_once() == 1

    clear_events = [
        event for event in bus.recent(50)
        if event.details.get("classification") == "audit-log-cleared"
    ]
    assert len(clear_events) == 1
    event = clear_events[0]
    assert event.severity == Severity.CRITICAL
    assert event.details["response_authorized"] is False
    assert event.details["attribution"] == "not-assessed"
    assert "sensitive-user" not in event.message
    assert "sensitive-user" not in repr(event.details)


def test_first_enrollment_does_not_skip_retained_clear_evidence(tmp_path) -> None:
    sources = {
        "Security": _Source([_xml(1102, 7)]),
        "System": _Source(),
        "Microsoft-Windows-Sysmon/Operational": _Source(),
    }
    bus = EventBus()
    guard = AuditLogIntegrityGuard(
        sources=sources, data_root=tmp_path, checkpoint_key=b"r" * 32
    )
    guard.bind(bus)
    assert guard.poll_once() == 1
    events = bus.recent(30)
    assert any(event.details.get("classification") == "audit-log-cleared" for event in events)
    assert any(event.details.get("coverage_complete") is True for event in events)


def test_rejected_foreign_provider_advances_cursor_and_emits_bounded_reason(tmp_path) -> None:
    sources = {
        "Security": _Source([_xml(1102, 7, provider="ForeignProvider")]),
        "System": _Source(),
        "Microsoft-Windows-Sysmon/Operational": _Source(),
    }
    bus = EventBus()
    guard = AuditLogIntegrityGuard(
        sources=sources, data_root=tmp_path, checkpoint_key=b"p" * 32
    )
    guard.bind(bus)
    assert guard.poll_once() == 0
    assert guard._checkpoints is not None
    assert guard._checkpoints["Security"].record_id == 7
    rejected = [
        event for event in bus.recent(30)
        if event.details.get("rejection_reason") == "provider-rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].details["raw_event_omitted"] is True
    assert guard.poll_once() == 0
    assert len([
        event for event in bus.recent(30)
        if event.details.get("rejection_reason") == "provider-rejected"
    ]) == 1


class _LateGenerationRaceSource(_Source):
    def __init__(self, trigger_read: int = 3) -> None:
        super().__init__([_xml(4719, 1), _xml(1102, 2)])
        self._guard_reads = 0
        self._trigger_read = trigger_read

    def record_anchor(self, record_id: int) -> str:
        if int(record_id) == 1:
            self._guard_reads += 1
            if self._guard_reads == self._trigger_read:
                self.rows[:] = [_xml(4719, 1), _xml(4719, 2)]
        return super().record_anchor(record_id)


def test_late_generation_change_discards_staged_records_before_commit(tmp_path) -> None:
    sources = {
        "Security": _LateGenerationRaceSource(),
        "System": _Source(),
        "Microsoft-Windows-Sysmon/Operational": _Source(),
    }
    bus = EventBus()
    guard = AuditLogIntegrityGuard(
        sources=sources, data_root=tmp_path, checkpoint_key=b"w" * 32
    )
    guard.bind(bus)
    assert guard.poll_once() == 0
    events = bus.recent(30)
    assert not any(event.details.get("classification") == "audit-log-cleared" for event in events)
    assert any(
        event.details.get("gap_reason") == "late-generation-change" for event in events
    )


def test_post_commit_generation_change_prevents_staged_publication(tmp_path) -> None:
    sources = {
        "Security": _LateGenerationRaceSource(trigger_read=5),
        "System": _Source(),
        "Microsoft-Windows-Sysmon/Operational": _Source(),
    }
    bus = EventBus()
    guard = AuditLogIntegrityGuard(
        sources=sources, data_root=tmp_path, checkpoint_key=b"q" * 32
    )
    guard.bind(bus)
    assert guard.poll_once() == 0
    events = bus.recent(40)
    assert not any(event.details.get("classification") == "audit-log-cleared" for event in events)
    assert any(
        event.details.get("gap_reason") == "post-commit-generation-change"
        for event in events
    )


def test_guard_detects_clear_and_refill_even_without_1102(tmp_path) -> None:
    sources = {
        "Security": _Source([_xml(4719, 10)]),
        "System": _Source(),
        "Microsoft-Windows-Sysmon/Operational": _Source(),
    }
    bus = EventBus()
    guard = AuditLogIntegrityGuard(
        sources=sources, data_root=tmp_path, checkpoint_key=b"y" * 32
    )
    guard.bind(bus)
    guard.poll_once()
    # Simulate a clear/refill where the explicit 1102 evidence is no longer retained.
    sources["Security"].rows[:] = [_xml(4719, 1)]
    guard.poll_once()
    gaps = [
        event for event in bus.recent(50)
        if event.details.get("source_channel") == "Security"
        and event.details.get("sensor_state") == "gap"
    ]
    assert gaps
    assert any("cleared" in event.message for event in gaps)
    assert all(event.details.get("response_authorized") is False for event in gaps)


def test_quiescent_poll_verifies_checkpoint_without_rotating_files(tmp_path) -> None:
    sources = {
        "Security": _Source([_xml(4719, 1)]),
        "System": _Source(),
        "Microsoft-Windows-Sysmon/Operational": _Source(),
    }
    bus = EventBus()
    guard = AuditLogIntegrityGuard(
        sources=sources, data_root=tmp_path, checkpoint_key=b"i" * 32
    )
    guard.bind(bus)
    assert guard.poll_once() == 1
    cursor_path = tmp_path / "sensor-cursors" / "audit-log-integrity.json"
    epoch_path = tmp_path / "security-state" / "audit-log-enrollment.json"
    cursor = cursor_path.read_bytes()
    epoch = epoch_path.read_bytes()
    revision = guard._checkpoint.revision

    assert guard.poll_once() == 0
    assert cursor_path.read_bytes() == cursor
    assert epoch_path.read_bytes() == epoch
    assert guard._checkpoint.revision == revision

    cursor_path.write_bytes(cursor + b" ")
    assert guard.poll_once() == 0
    assert any(
        event.details.get("sensor_state") == "untrusted"
        for event in bus.recent(30)
    )


def test_guard_self_test_is_defensive_and_deterministic() -> None:
    ok, detail = AuditLogIntegrityGuard(checkpoint_key=b"x" * 32).self_test()
    assert ok, detail
    assert "privacy" in detail
