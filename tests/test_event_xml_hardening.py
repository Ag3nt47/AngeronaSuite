from __future__ import annotations

from types import SimpleNamespace

from angerona.core.eventbus import Severity
from angerona.modules import sysmon_listener
from angerona.modules.av_telemetry_bridge import AVTelemetryBridgeModule
from angerona.modules.sysmon_listener import SysmonListenerModule


_ENTITY_XML = """<!DOCTYPE event [
<!ENTITY local SYSTEM "file:///C:/Windows/win.ini">
]><Event><EventData><Data Name="Image">&local;</Data></EventData></Event>"""


def _capture(module, record):
    emitted = []
    module.emit = lambda message, severity, **details: emitted.append(
        (message, severity, details)
    )
    module._process_record(record)
    return emitted


def _sysmon_record(xml: str) -> SimpleNamespace:
    return SimpleNamespace(
        SourceName="Microsoft-Windows-Sysmon", EventID=1, StringInserts=[xml]
    )


def _assert_sysmon_unavailable(event, error_type: str) -> None:
    _message, severity, details = event
    assert severity == Severity.MEDIUM
    assert details["error_type"] == error_type
    assert details["finding_code"] == "sysmon.collector.unavailable"
    assert details["disposition"] == "health"
    assert details["coverage_state"] == "unavailable"
    assert details["active_attack"] is False
    assert details["response_authorized"] is False
    assert details["response_authority"] == "observe-only"
    assert "response_contract" not in details


def test_sysmon_rejects_external_entity_event_xml(monkeypatch) -> None:
    module = SysmonListenerModule()
    real_parse = sysmon_listener.ET.fromstring
    parsed = []

    def parse(xml):
        parsed.append(xml)
        return real_parse(xml)

    monkeypatch.setattr(sysmon_listener.ET, "fromstring", parse)
    events = _capture(module, _sysmon_record(_ENTITY_XML))
    # Prove provider admission reached the hardened parser rather than passing
    # because an incomplete fixture was rejected before XML inspection.
    assert parsed == [_ENTITY_XML]
    assert len(events) == 1
    _assert_sysmon_unavailable(events[0], "XmlUnsafe")
    assert events[0][2]["eid"] == 1
    assert "win.ini" not in repr(events[0])


def test_defender_rejects_external_entity_event_xml() -> None:
    module = AVTelemetryBridgeModule()
    events = _capture(module, SimpleNamespace(EventID=1116, StringInserts=[_ENTITY_XML]))
    assert len(events) == 1
    assert "XML parse error" in events[0][0]
    assert "win.ini" not in repr(events[0])


def test_event_xml_size_is_bounded_before_parsing(monkeypatch) -> None:
    oversized = "<Event>" + ("x" * (1024 * 1024)) + "</Event>"

    def forbidden_parse(_xml):
        raise AssertionError("Oversized event XML must never reach a parser")

    monkeypatch.setattr(sysmon_listener.ET, "fromstring", forbidden_parse)
    sysmon = _capture(
        SysmonListenerModule(),
        _sysmon_record(oversized),
    )
    defender = _capture(
        AVTelemetryBridgeModule(),
        SimpleNamespace(EventID=1116, StringInserts=[oversized]),
    )
    assert len(sysmon) == 1
    _assert_sysmon_unavailable(sysmon[0], "XmlOversized")
    assert sysmon[0][2]["eid"] == 1
    assert defender[0][2]["xml_status"] == "oversized"
