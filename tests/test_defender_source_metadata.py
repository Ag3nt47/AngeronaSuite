"""Source event age and action results remain distinct from delivery and authority."""
from __future__ import annotations

from datetime import datetime, timezone
import time
from types import SimpleNamespace
from xml.sax.saxutils import escape

import pytest

from angerona.core.eventbus import BusAuthority, EventBus, Severity
from angerona.modules import av_telemetry_bridge as defender


_TIME = "2026-09-12T12:00:00.1234567Z"
_DETECTION = "{01234567-89AB-CDEF-0123-456789ABCDEF}"


def _xml(event_id=1117, fields=()):
    rows = [("Threat Name", "Inert.Test.Fixture"), ("Path", r"C:\Fixtures\inert.txt"),
            ("Threat ID", "9223372036854775807"), ("Detection ID", _DETECTION),
            ("Action Name", "Quarantine"), ("Action ID", "2"), *fields]
    data = "".join(f'<Data Name="{name}">{escape(value)}</Data>' for name, value in rows)
    return (f'<Event xmlns="{defender._NS}"><System>'
            f'<Provider Name="{defender._DEFENDER_PROVIDER}"/><EventID>{event_id}</EventID>'
            '<EventRecordID>7</EventRecordID>'
            f'<TimeCreated SystemTime="{_TIME}"/><Channel>{defender._DEFENDER_CHANNEL}</Channel>'
            f'</System><EventData>{data}</EventData></Event>')


def _module(tmp_path):
    return defender.AVTelemetryBridgeModule(tmp_path, continuity_key=b"m" * 32)


@pytest.mark.parametrize("code", ["0x00000000", "0x80508023"])
def test_native_action_preserves_exact_ids_time_and_error_without_inventing_success(tmp_path, code):
    module = _module(tmp_path)
    record = defender._DefenderEventLogSource._record(_xml(fields=[
        ("Error Code", code), ("Error Description", "Provider-described result"),
        ("Status Code", "9"), ("Status Description", "Provider status text"),
    ]))
    original_xml = record.StringInserts[0]
    original_digest = module._record_digest(record)
    message, severity, details = module._decode_record(record)
    assert message.startswith("Defender action reported") and "remediated" not in message
    assert severity is Severity.HIGH
    assert details["defender_threat_id"] == "9223372036854775807"
    assert details["defender_detection_id"] == _DETECTION
    assert details["defender_action_id"] == "2"
    assert details["source_event_time"] == _TIME
    assert details["source_event_time_status"] == "available"
    assert details["source_metadata_advisory"] is True
    assert details["defender_error_code"] == code
    assert details["defender_error_description"] == "Provider-described result"
    assert details["defender_status_code"] == "9"
    assert details["defender_status_description"] == "Provider status text"
    assert details["result"] == f"Error Code={code}; Status Code=9"
    assert "defender_action_status" not in details and "success" not in details["result"].lower()
    assert "response_contract" not in details and "active_attack" not in details
    assert record.StringInserts[0] == original_xml
    assert details["channel_record_sha256"] == module._record_digest(record) == original_digest


def test_source_time_never_replaces_delivery_timestamp_or_event_authentication(tmp_path):
    module = _module(tmp_path)
    bus = EventBus()
    bus.arm(BusAuthority(b"e" * 32))
    module.bind(bus)
    record = defender._DefenderEventLogSource._record(_xml(1116))
    before = time.time()
    module._process_record(record)
    event = bus.recent(1)[0]
    assert before <= event.ts <= time.time()
    assert event.details["source_event_time"] == _TIME
    assert event.severity is Severity.CRITICAL
    assert bus.verify_archived(event)


def test_explicit_action_status_is_preserved_without_discarding_error_code(tmp_path):
    record = defender._DefenderEventLogSource._record(_xml(fields=[
        ("Action Status", "Provider action status"), ("Error Code", "0x80508023"),
    ]))
    _, _, details = _module(tmp_path)._decode_record(record)
    assert details["result"] == details["defender_action_status"] == "Provider action status"
    assert details["defender_error_code"] == "0x80508023"


def test_missing_result_and_ids_are_explicit_not_invented_zero_or_success(tmp_path):
    xml = _xml().replace('<Data Name="Threat ID">9223372036854775807</Data>', "")
    xml = xml.replace(f'<Data Name="Detection ID">{_DETECTION}</Data>', "")
    _, _, details = _module(tmp_path)._decode_record(defender._DefenderEventLogSource._record(xml))
    assert "defender_threat_id" not in details and "defender_detection_id" not in details
    assert "defender_error_code" not in details
    assert details["result"] == "result unavailable"
    assert "defender_threat_id:missing" in details["defender_metadata_gaps"]
    assert "defender_detection_id:missing" in details["defender_metadata_gaps"]
    assert "action-result:unavailable" in details["defender_metadata_gaps"]


@pytest.mark.parametrize("name,value,key", [
    ("Threat ID", "-1", "defender_threat_id"),
    ("Threat ID", str(2**63), "defender_threat_id"),
    ("Detection ID", "not-a-guid", "defender_detection_id"),
    ("Error Code", "x" * 257, "defender_error_code"),
    ("Action Status", "line\ncontrol", "defender_action_status"),
])
def test_invalid_source_fields_remain_explicit_without_a_default(tmp_path, name, value, key):
    xml = _xml(fields=[(name, value)])
    if name in {"Threat ID", "Detection ID"}:
        original = "9223372036854775807" if name == "Threat ID" else _DETECTION
        xml = xml.replace(f'<Data Name="{name}">{original}</Data>', "", 1)
    _, _, details = _module(tmp_path)._decode_record(defender._DefenderEventLogSource._record(xml))
    assert key not in details
    assert f"{key}:invalid-or-duplicate" in details["defender_metadata_gaps"]


def test_duplicate_identical_fields_are_ambiguous_not_silently_selected(tmp_path):
    record = defender._DefenderEventLogSource._record(_xml(fields=[("Detection ID", _DETECTION)]))
    _, _, details = _module(tmp_path)._decode_record(record)
    assert "defender_detection_id" not in details
    assert "defender_detection_id:invalid-or-duplicate" in details["defender_metadata_gaps"]


@pytest.mark.parametrize("timestamp,status", [
    (None, "missing"), ("not-a-time", "invalid"),
    ("2026-02-30T12:00:00Z", "invalid"),
    (datetime(2026, 9, 12), "invalid"), (float("nan"), "invalid"),
])
def test_missing_or_invalid_timestamp_is_not_replaced_with_delivery_time(tmp_path, timestamp, status):
    record = defender._DefenderEventLogSource._record(_xml())
    record.TimeGenerated = timestamp
    _, _, details = _module(tmp_path)._decode_record(record)
    assert "source_event_time" not in details
    assert details["source_event_time_status"] == status


def test_aware_classic_datetime_is_preserved_and_unknown_property_is_unavailable():
    value = datetime(2026, 9, 12, tzinfo=timezone.utc)
    assert defender._source_event_time(SimpleNamespace(TimeGenerated=value)) == (
        value.isoformat(), "available")
    class Unavailable:
        @property
        def TimeGenerated(self):
            raise RuntimeError("inert source timestamp unavailable")
    assert defender._source_event_time(Unavailable()) == (None, "unavailable")
