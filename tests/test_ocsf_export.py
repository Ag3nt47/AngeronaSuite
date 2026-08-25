from angerona import __version__
from angerona.core.eventbus import Event, Severity
from angerona.core.ocsf_export import to_finding, validate_finding_shape


def test_detection_finding_targets_current_ocsf_contract():
    finding = to_finding(Event(
        "Process Monitor",
        "Suspicious process opened a remote endpoint",
        Severity.HIGH,
        details={"pid": 4242, "image": "sample.exe", "dest_ip": "203.0.113.9"},
    ))

    ok, errors = validate_finding_shape(finding)

    assert ok, errors
    assert finding["metadata"]["version"] == "1.8.0"
    assert finding["metadata"]["product"]["version"] == __version__


def test_shape_validator_rejects_version_drift_and_invalid_severity():
    finding = to_finding(Event("Detector", "evidence", Severity.CRITICAL))
    finding["metadata"]["version"] = "1.3.0"
    finding["severity_id"] = 99

    ok, errors = validate_finding_shape(finding)

    assert not ok
    assert any("metadata.version" in error for error in errors)
    assert any("severity_id" in error for error in errors)
