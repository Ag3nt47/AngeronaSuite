from angerona.core.network_behavior import (
    NetworkBehaviorAnalytics, NetworkFlow,
)


def test_periodic_beacon_is_detected_without_retaining_raw_endpoint():
    now = [1000.0]
    detector = NetworkBehaviorAnalytics(b"k" * 32, clock=lambda: now[0])
    findings = ()
    for index in range(6):
        now[0] = 1000 + index * 30
        findings = detector.observe(NetworkFlow(
            now[0], "proc:123:100", "8.8.8.8", 443,
        ))
    assert any(item.rule_id.endswith("periodic_beacon") for item in findings)
    assert "8.8.8.8" not in repr(detector._flows)
    assert "proc:123:100" not in repr(detector._flows)


def test_private_lateral_and_external_fanout_thresholds():
    detector = NetworkBehaviorAnalytics(b"k" * 32, clock=lambda: 1000)
    findings = ()
    for index in range(10):
        findings = detector.observe(NetworkFlow(
            1000, "scanner", f"10.0.0.{index + 1}", 445,
        ))
    assert any(item.rule_id.endswith("lateral_fanout") for item in findings)
    for index in range(20):
        findings = detector.observe(NetworkFlow(
            1000, "browser", f"8.8.0.{index + 1}", 443,
        ))
    assert any(item.rule_id.endswith("external_fanout") for item in findings)


def test_asymmetric_upload_and_fixed_memory_bound():
    detector = NetworkBehaviorAnalytics(
        b"k" * 32, max_flows=100, clock=lambda: 1000,
    )
    findings = detector.observe(NetworkFlow(
        1000, "uploader", "8.8.4.4", 443,
        bytes_sent=51 * 1024 * 1024, bytes_received=1,
    ))
    assert any(item.rule_id.endswith("asymmetric_upload") for item in findings)
    for index in range(150):
        detector.observe(NetworkFlow(
            1000, "noise", f"9.9.0.{index % 250 + 1}", 80,
        ))
    assert detector.retained_flows == 100
