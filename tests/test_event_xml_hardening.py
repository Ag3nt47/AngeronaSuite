from __future__ import annotations

from types import SimpleNamespace

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


def test_sysmon_rejects_external_entity_event_xml() -> None:
    module = SysmonListenerModule()
    events = _capture(module, SimpleNamespace(EventID=1, StringInserts=[_ENTITY_XML]))
    assert len(events) == 1
    assert "XML parse error" in events[0][0]
    assert "win.ini" not in repr(events[0])


def test_defender_rejects_external_entity_event_xml() -> None:
    module = AVTelemetryBridgeModule()
    events = _capture(module, SimpleNamespace(EventID=1116, StringInserts=[_ENTITY_XML]))
    assert len(events) == 1
    assert "XML parse error" in events[0][0]
    assert "win.ini" not in repr(events[0])


def test_event_xml_size_is_bounded_before_parsing() -> None:
    oversized = "<Event>" + ("x" * (1024 * 1024)) + "</Event>"
    sysmon = _capture(
        SysmonListenerModule(),
        SimpleNamespace(EventID=1, StringInserts=[oversized]),
    )
    defender = _capture(
        AVTelemetryBridgeModule(),
        SimpleNamespace(EventID=1116, StringInserts=[oversized]),
    )
    assert sysmon[0][2]["xml_status"] == "oversized"
    assert defender[0][2]["xml_status"] == "oversized"
