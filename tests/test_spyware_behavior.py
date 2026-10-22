"""Offline fixtures exercise correlation boundaries and telemetry redaction."""
import json

import pytest

from angerona.core.spyware_behavior import SpywareBehaviorEngine


@pytest.fixture
def detector():
    now = [1000.0]
    return SpywareBehaviorEngine(clock=lambda: now[0]), now


def event(kind, **kwargs):
    return {"event_type": kind, "pid": 123, "process_create_time": 100.0, **kwargs}


def sample_egress(engine, now, total, **kwargs):
    return engine.observe(event("network_egress", bytes_sent=total, ts=now[0], **kwargs))


def warmup(engine, now, **kwargs):
    total = 0
    assert not sample_egress(engine, now, total, **kwargs)
    for _index in range(6):
        now[0] += 10
        total += 10240
        assert not sample_egress(engine, now, total, **kwargs)
    return total


def test_encrypted_rate_requires_six_intervals_and_sudden_large_delta(detector):
    engine, now = detector
    total = warmup(engine, now, encrypted=True)
    now[0] += 10
    findings = sample_egress(engine, now, total + 20 * 1024 * 1024, encrypted=True)
    assert [item["kind"] for item in findings] == ["encrypted_egress_spike"]
    assert findings[0]["evidence"]["warmup_intervals"] == 6
    assert findings[0]["pid"] == 123
    assert findings[0]["process_create_time"] == 100.0
    assert findings[0]["response_authorized"] is False


@pytest.mark.parametrize("encrypted", [None, False, "True", 1])
def test_port_443_does_not_prove_encryption(detector, encrypted):
    engine, now = detector
    total = warmup(engine, now, encrypted=encrypted, remote_port=443)
    now[0] += 10
    assert not sample_egress(engine, now, total + 20 * 1024 * 1024,
                             encrypted=encrypted, remote_port=443)


def test_pid_reuse_cannot_inherit_egress_baseline(detector):
    engine, now = detector
    total = warmup(engine, now, encrypted=True)
    now[0] += 10
    assert not sample_egress(engine, now, total + 20 * 1024 * 1024,
                             encrypted=True, process_create_time=1065.0)


def test_counter_reset_and_unencrypted_interval_restart_warmup(detector):
    engine, now = detector
    warmup(engine, now, encrypted=True)
    now[0] += 10
    assert not sample_egress(engine, now, 1, encrypted=True)
    now[0] += 10
    assert not sample_egress(engine, now, 30 * 1024 * 1024, encrypted=True)
    now[0] += 10
    assert not sample_egress(engine, now, 31 * 1024 * 1024, encrypted=False)
    now[0] += 10
    assert not sample_egress(engine, now, 90 * 1024 * 1024, encrypted=True)


def test_ordinary_large_backup_has_no_baseline_spike(detector):
    engine, now = detector
    for index in range(12):
        now[0] += 10
        assert not sample_egress(engine, now, index * 20 * 1024 * 1024, encrypted=True)


def test_dns_needs_rapid_unique_entropy_not_single_cdn_label(detector):
    engine, now = detector
    random_label = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
    assert not engine.observe(event("dns_query", domain=random_label + ".cdn.example.com"))
    for index in range(15):
        now[0] += 1
        assert not engine.observe(event("dns_query", domain=f"static{index}.example.net"))
    findings = []
    for index in range(12):
        now[0] += 1
        findings.extend(engine.observe(event("dns_query", domain=f"{random_label}{index}.example.org")))
    assert any(item["kind"] == "dns_tunneling_candidate" for item in findings)
    assert random_label not in repr(engine._dns)
    assert "example.org" in repr(findings)


def test_slow_entropy_dns_and_replay_cannot_form_a_burst(detector):
    engine, now = detector
    for index in range(15):
        now[0] += 10
        record = event("dns_query", domain=f"a1b2c3d4e5f6g7h8i9j0k1l2m{index}.example.org", ts=now[0])
        assert not engine.observe(record)
        assert not engine.observe({**record, "event_id": str(index)})
    assert engine.stats()["duplicates"] == 15


def test_dns_process_birth_and_domains_do_not_merge(detector):
    engine, now = detector
    for index in range(12):
        now[0] += 1
        assert not engine.observe(event(
            "dns_query", process_create_time=100 + index,
            domain=f"a1b2c3d4e5f6g7h8i9j0k1l2m{index}.example.org"))


def test_renderer_shell_requires_live_parent_birth_and_correlated_media(detector):
    engine, now = detector
    assert not engine.observe(event("media_render", role="webview", ts=1000))
    child = event("process_start", pid=456, process_create_time=1001,
                  parent_pid=123, parent_create_time=101, process_name="cmd.exe", ts=1001)
    now[0] = 1001
    assert not engine.observe(child)
    findings = engine.observe({**child, "parent_create_time": 100})
    assert findings[0]["kind"] == "renderer_shell_child"
    assert findings[0]["pid"] == 456
    assert findings[0]["evidence"]["parent_create_time"] == 100


def test_renderer_ordinary_children_and_expired_media_are_not_alerts(detector):
    engine, now = detector
    engine.observe(event("media_render", role="renderer", ts=1000))
    now[0] = 1001
    assert not engine.observe(event("process_start", pid=456, process_create_time=1001,
                                    parent_pid=123, parent_create_time=100,
                                    process_name="browser-utility.exe"))
    now[0] = 1016
    assert not engine.observe(event("process_start", pid=457, process_create_time=1016,
                                    parent_pid=123, parent_create_time=100,
                                    process_name="powershell.exe"))
    # An ordinary renderer/JIT telemetry record cannot claim memory inspection.
    assert not engine.observe(event("api_access", api="VirtualAlloc", authorized=False))
    assert engine.coverage()["memory_inspection"] is False


@pytest.mark.parametrize("authorized", [None, True, 0, "False"])
def test_sensitive_api_requires_explicit_unauthorized_telemetry(detector, authorized):
    engine, _now = detector
    assert not engine.observe(event("api_access", api="BitBlt", authorized=authorized))


def test_sensitive_api_file_evidence_never_contains_path_or_username(detector):
    engine, _now = detector
    findings = engine.observe(event("api_access", api="GetAsyncKeyState", authorized=False))
    findings += engine.observe(event("file_read", authorized=False,
                                     path="C:/Users/SecretUser/AppData/Local/Google/Chrome/User Data/Default/Login Data"))
    assert {item["kind"] for item in findings} == {
        "unauthorized_sensitive_api", "unauthorized_sensitive_file_read"}
    assert "SecretUser" not in repr(findings)
    assert "Login Data" not in repr(findings)
    assert "SecretUser" not in repr(engine.__dict__)


def test_advertising_identifier_reports_type_and_host_without_values(detector):
    engine, _now = detector
    findings = engine.observe(event("http_request",
        url="http://collector.example.org/a?IDFA=extremely-secret-device-id&x=secret-token",
        headers={"GAID": "another-secret-device-id", "Authorization": "secret-auth"}))
    assert findings[0]["evidence"] == {
        "host": "collector.example.org", "identifier_types": ["gaid", "idfa"]}
    serialized = json.dumps(findings) + repr(engine.__dict__)
    assert "extremely-secret" not in serialized
    assert "another-secret" not in serialized
    assert "secret-token" not in serialized
    assert "secret-auth" not in serialized


def test_https_and_identifier_mentioned_only_as_value_do_not_alert(detector):
    engine, _now = detector
    assert not engine.observe(event("http_request", url="https://example.org/?IDFA=secret"))
    assert not engine.observe(event("http_request", url="http://example.org/?text=GAID"))


def test_ddns_unusual_port_has_literal_target_only_when_provided(detector):
    engine, now = detector
    findings = []
    for index in range(3):
        now[0] = 1000 + index * 20
        findings = engine.observe(event("network_connection", domain="host.duckdns.org",
            remote_port=4444, remote_ip="8.8.8.8"))
    assert findings[0]["kind"] == "ddns_unusual_port"
    assert findings[0]["remote_ip"] == "8.8.8.8"
    assert findings[0]["response_authorized"] is False


@pytest.mark.parametrize("change", [
    {"remote": True}, {"node_origin": "peer"}, {"origin": "remote"},
    {"response_authority": "remote-observe-only"}, {"drill": True},
    {"practice": True}, {"synthetic": True}, {"simulation": True},
    {"ts": 699}, {"ts": 1006}, {"ts": float("nan")}, {"ts": float("inf")},
    {"pid": True}, {"process_create_time": float("nan")}, {"process_create_time": 1001},
    {"event_type": []}, {"event_type": "memory_region"}, {"event_id": []},
])
def test_untrusted_stale_and_malformed_records_are_rejected(detector, change):
    engine, _now = detector
    assert not engine.observe(event("api_access", api="BitBlt", authorized=False, **change))
    assert engine.stats()["rejected"] == 1
    assert engine.stats()["processes"] == 0


def test_event_id_and_body_replay_are_rejected(detector):
    engine, now = detector
    record = event("api_access", api="BitBlt", authorized=False, event_id="event-1", ts=1000)
    assert engine.observe(record)
    assert not engine.observe({**record, "event_id": "event-2"})
    now[0] += 1
    assert not engine.observe({**record, "ts": now[0]})
    assert engine.stats()["duplicates"] == 2


def test_memory_and_payload_budgets_are_enforced():
    now = [1000.0]
    engine = SpywareBehaviorEngine(clock=lambda: now[0], max_processes=2)
    for index in range(150):
        now[0] += 1
        engine.observe(event("network_egress", pid=index + 1, bytes_sent=index, encrypted=True))
        engine.observe(event("dns_query", pid=index + 1, domain=f"host{index}.example{index}.org"))
    stats = engine.stats()
    assert stats["processes"] <= 2
    assert stats["dns_buckets"] <= 2
    assert stats["replay_entries"] <= 64
    assert stats["alert_entries"] <= 16
    assert not engine.observe({"event_type": "http_request", "url": "x" * 4097})
    assert not engine.observe(None)
    assert not engine.observe({"event_type": "http_request", "fields": {"x": {"y": {"z": []}}}})
    assert not engine.observe({"event_type": "api_access", "api": "BitBlt", "authorized": False, "extra": 10**1000})


def test_no_response_or_observation_capabilities_are_claimed(detector):
    engine, _now = detector
    coverage = engine.coverage()
    for capability in ("api_interception", "memory_inspection", "packet_capture",
                       "automatic_response", "vendor_attribution"):
        assert coverage[capability] is False
