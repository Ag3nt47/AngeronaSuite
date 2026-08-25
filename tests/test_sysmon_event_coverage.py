from defusedxml import ElementTree as ET

from angerona.core.eventbus import Severity
from angerona.modules.sysmon_listener import _EID_MAP, _build_details, _build_message


_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _xml(**fields):
    body = "".join(
        f'<Data Name="{name}">{value}</Data>' for name, value in fields.items()
    )
    return ET.fromstring(f'<Event xmlns="{_NS}"><EventData>{body}</EventData></Event>')


def test_current_sysmon_event_range_is_normalized_without_raw_auto_response():
    expected = set(range(1, 30)) | {255}
    assert expected <= set(_EID_MAP)

    root = _xml(Image=r"C:\\Tools\\writer.exe", TargetFilename=r"C:\\Temp\\drop.exe")
    label, tags, severity = _EID_MAP[29]
    details = _build_details(29, root, label, tags)

    assert severity == Severity.MEDIUM
    assert details["target_filename"].endswith("drop.exe")
    assert details["response_authorized"] is False
    assert "Executable File Detected" in _build_message(29, root)


def test_health_and_high_signal_raw_sysmon_records_are_non_authoritative():
    health = _build_details(255, _xml(Description="queue overflow"), *_EID_MAP[255][:2])
    injection = _build_details(8, _xml(TargetProcessId="42"), *_EID_MAP[8][:2])

    assert health["disposition"] == "health"
    assert health["response_authorized"] is False
    assert injection["response_authorized"] is False
    assert "response_contract" not in injection


def test_sysmon_network_events_join_on_community_id():
    root = _xml(
        SourceIp="128.232.110.120",
        DestinationIp="66.35.250.204",
        SourcePort="34855",
        DestinationPort="80",
        Protocol="tcp",
    )

    details = _build_details(3, root, *_EID_MAP[3][:2])

    assert details["community_id"] == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
