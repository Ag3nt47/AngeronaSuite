from __future__ import annotations

import json
import hashlib
import os
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.spyware_intel import ThreatIntelStore
from angerona.modules.adversary_combat import AdversaryCombat
from angerona.modules.spyware_guard import SpywareGuardModule
from angerona.telemetry.sensors import ConnectionSnapshot, ProcessSnapshot


NOW = 1800000000.0


def make_module(**kwargs):
    kwargs.setdefault("clock", lambda: NOW)
    kwargs.setdefault("persistence_collector", lambda **_: {"findings": [], "coverage": {}})
    kwargs.setdefault("process_observer", lambda: ProcessSnapshot((), NOW, True, 0, 0))
    kwargs.setdefault("connection_observer", lambda: ConnectionSnapshot((), NOW, True, 0, 0))
    module = SpywareGuardModule(**kwargs)
    bus = EventBus()
    bus.arm(BusAuthority(b"s" * 32))
    module.bind(bus)
    return module, bus


def test_single_local_rule_requests_exact_process_containment():
    module, bus = make_module()
    module._publish({"kind": "credential_read", "severity": "LOW", "pid": 45001,
                     "process_create_time": NOW - 100}, local_authority=True)
    event = bus.recent(1)[0]
    assert event.details["response_authorized"] is True
    assert event.details["response_contract"]["targets"] == {
        "pid": 45001, "process_create_time": NOW - 100}
    assert "terminate_process" in event.details["response_contract"]["actions"]
    assert AdversaryCombat._response_actions(event) is not None
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 1


def test_single_unbound_local_rule_requests_local_host_lockdown():
    module, bus = make_module()
    module._publish({"kind": "persistence_encoded_execution", "severity": "MEDIUM"},
                    local_authority=True)
    event = bus.recent(1)[0]
    assert event.severity == Severity.CRITICAL
    assert event.details["observed_severity"] == "MEDIUM"
    assert event.details["spyware_confirmed"] is False
    assert event.details["response_contract"] == {
        "version": 1, "actions": ["isolate_host"], "targets": {"host": "local"}}
    assert AdversaryCombat._response_actions(event) is not None


def test_service_configuration_exposure_cannot_request_host_lockdown():
    from angerona.core.spyware_sensors import analyze_persistence
    findings = analyze_persistence([{"source": "windows.services", "id": "fixture",
        "command": r'C:\Program Files\Example\service.exe --service'}])
    module, bus = make_module(persistence_collector=lambda **_: {
        "findings": findings, "coverage": {}})
    module._scan_once()
    event, = bus.recent(10)
    assert event.severity == Severity.LOW
    assert event.details["disposition"] == "exposure"
    assert event.details["response_eligible"] is False
    assert event.details["active_attack"] is False
    assert event.details["response_authorized"] is False
    assert "response_contract" not in event.details
    assert module.dashboard_snapshot()["hits"][0]["status"] == "exposure-review"
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 0


def test_real_transient_execution_retains_single_rule_host_containment():
    from angerona.core.spyware_sensors import analyze_persistence
    findings = analyze_persistence([{"source": "windows.run", "id": "BingWallpaperDaemon",
        "command": r'powershell.exe -File C:\Temp\payload.ps1'}])
    module, bus = make_module(persistence_collector=lambda **_: {
        "findings": findings, "coverage": {}})
    module._scan_once()
    event, = bus.recent(10)
    assert event.severity == Severity.CRITICAL
    assert event.details["response_contract"]["actions"] == ["isolate_host"]
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 1


@pytest.mark.parametrize("override", [{"pid": True}, {"pid": os.getpid()},
    {"process_create_time": float("nan")}, {"process_create_time": True},
    {"process_create_time": -1}])
def test_invalid_process_binding_never_authorizes_process_mutation(override):
    module, _ = make_module()
    finding = dict(pid=45001, process_create_time=NOW - 1)
    finding.update(override)
    response = module._response(finding, True)
    assert response["response_contract"]["actions"] == ["isolate_host"]


def test_candidate_intelligence_and_advisory_inputs_cannot_contain():
    module, bus = make_module()
    module._intel.ingest("malicious[.]example", "fixture", now=NOW)
    module._match_indicator({"remote_ip": "8.8.8.8"}, "domain", "malicious.example",
                            local_authority=True)
    assert not bus.recent(10)
    module._publish({"kind": "advisory", "pid": 45001, "process_create_time": NOW - 1,
                     "response_authorized": True,
                     "response_contract": {"version": 1, "actions": ["isolate_host"]}},
                    local_authority=False)
    event = bus.recent(1)[0]
    assert event.details["response_authorized"] is False
    assert "response_contract" not in event.details


def test_explicit_review_enables_literal_match_and_revoke_disables_it():
    module, bus = make_module()
    module._intel.ingest("8.8.8.8", "fixture", now=NOW)
    assert module.review_indicator("ip", "8.8.8.8")
    module._process_commands()
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert bus.recent(1)[0].details["response_contract"]["actions"] == ["block_remote_ip"]
    assert module.review_indicator("ip", "8.8.8.8", approved=False)
    module._process_commands()
    assert not module.dashboard_snapshot()["indicators"][0]["approved"]


def test_changed_report_digest_requires_review_in_dashboard_and_live_match():
    module, bus = make_module()
    module._intel.ingest("8.8.8.8 first report", "fixture", now=NOW)
    assert module.review_indicator("ip", "8.8.8.8")
    module._process_commands()
    module._intel.ingest("8.8.8.8 changed report", "fixture", now=NOW)
    assert not module.dashboard_snapshot()["indicators"][0]["approved"]
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert not bus.recent(10)


def test_settings_are_queued_strictly_and_apply_after_save():
    module, _ = make_module()
    saved = []
    cfg = SimpleNamespace(spyware_auto_contain=True, save=lambda: saved.append(True))
    module.bind_manager(SimpleNamespace(config=cfg))
    assert module.configure_settings(spyware_auto_contain=False) == {"queued": True}
    assert module._settings["spyware_auto_contain"] is True
    module._process_commands()
    assert saved and module._settings["spyware_auto_contain"] is False
    assert module.configure_settings(spyware_auto_contain="false")["queued"] is False
    assert module.configure_settings(arbitrary=True)["queued"] is False


def test_failed_save_does_not_grant_settings_authority():
    module, _ = make_module()
    def fail():
        raise OSError("private settings inaccessible")
    cfg = SimpleNamespace(spyware_network_enabled=False, save=fail)
    module.bind_manager(SimpleNamespace(config=cfg))
    module.configure_settings(spyware_network_enabled=True)
    module._process_commands()
    assert not cfg.spyware_network_enabled
    assert not module._settings["spyware_network_enabled"]
    assert not module._intel.network_enabled


@pytest.mark.parametrize("url", ["http://example.org", "https://user:pass@example.org/",
    "https://example.org:8443/", "https://example.org/#fragment", "garbage"])
def test_report_url_surface_rejects_ambiguous_urls(url):
    module, _ = make_module()
    assert module.queue_report_url(url) is False


def test_disabled_report_network_never_starts_fetch(monkeypatch):
    module, _ = make_module()
    calls = []
    monkeypatch.setattr(module._intel, "refresh_url", lambda *_a, **_k: calls.append(True))
    assert module.queue_report_url("https://example.org/report")
    module._process_commands()
    assert not calls and module._report_thread is None


def test_sandbox_never_emits_response_or_real_hits():
    module, bus = make_module()
    for scenario in ("dns_tunnel", "exfiltration", "renderer_escape"):
        assert module.run_sandbox(scenario)
    module._process_commands()
    assert module.dashboard_snapshot()["stats"]["sandbox_runs"] == 3
    assert not module.dashboard_snapshot()["hits"]
    assert all(event.details["drill"] and not event.details["response_authorized"]
               for event in bus.recent(10))
    assert not module.run_sandbox("run-powershell")


def test_dedup_and_dashboard_are_bounded_and_detached():
    module, _ = make_module()
    finding = {"kind": "same", "evidence": {"value": 1}}
    module._publish(finding, local_authority=False)
    module._publish(finding, local_authority=False)
    result = module.dashboard_snapshot()
    assert len(result["hits"]) == 1
    result["hits"][0]["evidence"]["value"] = "changed"
    assert module.dashboard_snapshot()["hits"][0]["evidence"]["value"] == 1
    for _ in range(40):
        module.request_scan()
    assert module._commands.qsize() == 32
    assert module.dashboard_snapshot()["stats"]["queue_dropped"] == 8


def test_native_scan_coverage_is_visible_and_no_findings_is_not_response():
    module, bus = make_module(persistence_collector=lambda **_: {
        "findings": [], "coverage": {"windows.com": {"status": "access_denied"}}})
    module._scan_once()
    assert module.dashboard_snapshot()["coverage"]["persistence"]["windows.com"]["status"] == "access_denied"
    assert not bus.recent(10)


def test_memory_sample_retains_denied_pid_when_later_pid_is_complete():
    rows = ({"pid": 45001, "create_time": NOW - 10}, {"pid": 45002, "create_time": NOW - 10})
    module, _ = make_module(process_observer=lambda: ProcessSnapshot(rows, NOW, True, 0, 0),
        memory_collector=lambda pid, **_: {"findings": [], "coverage": {
            "process_memory": {"status": "access_denied" if pid == 45001 else "complete"}}})
    module._settings["spyware_memory_enabled"] = True
    module._scan_once()
    coverage = module.dashboard_snapshot()["coverage"]["memory"]
    assert coverage["status"] == "partial"
    assert coverage["by_pid"]["45001"]["coverage"]["process_memory"]["status"] == "access_denied"
    assert coverage["by_pid"]["45002"]["coverage"]["process_memory"]["status"] == "complete"


@pytest.mark.parametrize("grow_after_stat", [False, True])
def test_executable_hash_budget_applies_to_retained_file(tmp_path, monkeypatch, grow_after_stat):
    from angerona.modules import adversary_combat
    path = tmp_path / "fixture.bin"
    path.write_bytes(b"inert fixture")
    original = adversary_combat._PinnedFileMove
    def pin(target):
        if grow_after_stat:
            with target.open("wb") as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
        return original(target)
    monkeypatch.setattr(adversary_combat, "_PinnedFileMove", pin)
    module, _ = make_module()
    module._approved[("sha256", "a" * 64)] = "b" * 64
    matched = []
    monkeypatch.setattr(module, "_match_indicator", lambda record, kind, value, **_: matched.append(value))
    module._scan_hashes([{"exe": str(path), "pid": 45001, "create_time": NOW - 10}])
    assert matched == ([] if grow_after_stat else [hashlib.sha256(b"inert fixture").hexdigest()])


@pytest.mark.parametrize("extra", [{"drill": True}, {"practice": True},
    {"synthetic": True}, {"simulation": True}, {"remote": True}, {"remote": "forwarded"},
    {"origin": "remote"}, {"source_host": "remote-host"},
    {"node_origin": "remote"}, {"response_authority": "remote-observe-only"}])
@pytest.mark.parametrize("producer", ["ETW Core Listener", "C2 Beacon Detector"])
def test_remote_and_drill_bus_inputs_never_inherit_local_authority(extra, producer):
    module, bus = make_module()
    details = {"event_type": "api_access", "api": "BitBlt", "authorized": False,
               "pid": 45001, "process_create_time": NOW - 10, **extra}
    bus.publish(Event(producer, "fixture", Severity.HIGH, NOW, details))
    module._consume_events()
    assert not module.dashboard_snapshot()["hits"]


def test_full_research_queue_does_not_leave_news_refresh_stuck(monkeypatch):
    module, _ = make_module()
    module._settings["spyware_network_enabled"] = True
    monkeypatch.setattr(module, "_schedule_report", lambda *args: False)
    module._schedule_news()
    snapshot = module.dashboard_snapshot()
    assert not snapshot["news_status"]["refreshing"]
    assert snapshot["news_status"]["state"] == "retry-required"


def _wait_for_news(module):
    deadline = time.monotonic() + 5
    while module._news_pending and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not module._news_pending


def _stop_news_worker(module):
    module._report_stop.set()
    if module._report_thread is not None:
        module._report_thread.join(2)
        assert not module._report_thread.is_alive()


def test_news_worker_reports_partial_sources_and_never_creates_response_authority(monkeypatch):
    from angerona.core import spyware_news
    module, bus = make_module()
    module._settings["spyware_network_enabled"] = True
    observed_threads = []

    def fetch(source, **kwargs):
        observed_threads.append(threading.get_ident())
        assert kwargs["network_enabled"] is True
        if source == "cisa":
            raise ValueError("controlled unavailable source")
        return [{"source": source, "url": f"https://{source}.example/fixture", "title": "inert fixture",
                 "published": NOW - 10, "verified_at": NOW, "summary": "inert research", "advisory_only": True}]

    monkeypatch.setattr(spyware_news, "fetch_news_source", fetch)
    try:
        module._schedule_news()
        _wait_for_news(module)
        snapshot = module.dashboard_snapshot()
        assert snapshot["news_status"]["state"] == "partial"
        assert snapshot["news_status"]["sources"]["cisa"]["state"] == "failed"
        assert len(snapshot["news"]) == 2
        assert all(identity != threading.get_ident() for identity in observed_threads)
        assert snapshot["stats"]["response_requests"] == 0
        assert snapshot["indicators"] == [] and not bus.recent(10)
    finally:
        _stop_news_worker(module)


def test_failed_refresh_keeps_cache_without_claiming_it_current_then_clears_error(monkeypatch):
    from angerona.core import spyware_news
    module, _ = make_module()
    module._settings["spyware_network_enabled"] = True
    module._news = [{"source": "citizen_lab", "url": "https://citizenlab.ca/research/cache/",
                     "published": NOW - 31 * 86400, "verified_at": NOW - 30 * 86400}]
    def unavailable(*_args, **_kwargs):
        raise ValueError("controlled failure")
    monkeypatch.setattr(spyware_news, "fetch_news_source", unavailable)
    try:
        module._schedule_news()
        _wait_for_news(module)
        snapshot = module.dashboard_snapshot()
        assert snapshot["news"] and snapshot["news_status"]["state"] == "failed"
        monkeypatch.setattr(spyware_news, "fetch_news_source", lambda *_args, **_kwargs: [])
        module._schedule_news()
        _wait_for_news(module)
        snapshot = module.dashboard_snapshot()
        assert snapshot["news_status"]["state"] == "empty"
        assert snapshot["news_status"]["error"] == ""
        module._settings["spyware_network_enabled"] = False
        assert module.dashboard_snapshot()["news_status"]["state"] == "disabled"
        assert module.dashboard_snapshot()["news"]
    finally:
        _stop_news_worker(module)


def test_automatic_news_is_queued_before_host_scan_without_changing_network_gate(monkeypatch):
    module, _ = make_module()
    order = []
    module._last_refresh = NOW
    monkeypatch.setattr(module, "_scan_once", lambda: order.append("scan"))
    monkeypatch.setattr(module, "_schedule_news", lambda: order.append("news"))
    module._settings["spyware_network_enabled"] = True
    module._tick()
    assert order == ["news", "scan"]
    order.clear()
    module._settings["spyware_network_enabled"] = False
    module._tick()
    assert order == ["scan"]


def test_authenticated_single_api_rule_is_contained_without_second_hit():
    module, bus = make_module()
    bus.publish(Event("ETW Core Listener", "fixture", Severity.HIGH, NOW, {
        "event_type": "api_access", "api": "BitBlt", "authorized": False,
        "pid": 45001, "process_create_time": NOW - 10}))
    module._consume_events()
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 1


def test_advisory_replay_cannot_suppress_authenticated_local_rule():
    module, bus = make_module()
    record = {"event_type": "api_access", "api": "BitBlt", "authorized": False,
              "pid": 45001, "process_create_time": NOW - 10, "ts": NOW}
    assert module.submit_telemetry(record)
    module._process_commands()
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 0
    bus.publish(Event("ETW Core Listener", "local fixture", Severity.HIGH, NOW, record))
    module._consume_events()
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 1


def test_health_status_events_from_other_detectors_do_not_lock_down():
    module, bus = make_module()
    bus.publish(Event("API Patch / Anti-Blinding Detector", "collector unavailable",
                      Severity.HIGH, NOW, {"coverage_complete": False}))
    module._consume_events()
    assert not module.dashboard_snapshot()["hits"]


def test_api_hook_filetime_identity_binds_process_instead_of_host_fallback():
    module, bus = make_module()
    bus.publish(Event("API Patch / Anti-Blinding Detector", "hook", Severity.CRITICAL, NOW, {
        "pid": 45001, "process_birth": int((NOW - 10 + 11644473600) * 10000000)}))
    module._consume_events()
    event = next(item for item in bus.recent(10) if item.module == module.name)
    assert "isolate_host" not in event.details["response_contract"]["actions"]
    assert event.details["response_contract"]["targets"]["process_create_time"] == NOW - 10


def test_upstream_authorized_detection_is_not_submitted_twice():
    from angerona.core.response_contract import process_response
    module, bus = make_module()
    bus.publish(Event("LSASS Credential-Access Guard", "fixture", Severity.CRITICAL, NOW, {
        "pid": 45001, "process_create_time": NOW - 10, **process_response(45001, NOW - 10)}))
    module._consume_events()
    hit = module.dashboard_snapshot()["hits"][0]
    assert hit["status"] == "upstream-response-requested"
    assert not hit["response_requested"]
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 0


def test_native_sysmon_dns_and_network_schemas_are_adapted():
    module, _ = make_module()
    dns = module._adapt_event(Event("Sysmon Event Bridge", "query", ts=NOW,
        details={"eid": 22, "query_name": "malicious.example", "process_id": "45001"}))
    assert dns["event_type"] == "dns_query" and dns["domain"] == "malicious.example"
    assert "pid" not in dns
    network = module._adapt_event(Event("Network Monitor", "connection", ts=NOW,
        details={"raddr": "[2606:4700:4700::1111]:443", "pid": 45001}))
    assert network["event_type"] == "network_connection"
    assert network["remote_ip"] == "2606:4700:4700::1111" and network["remote_port"] == 443


def test_unsigned_or_undone_quarantine_receipts_never_create_encrypted_archive():
    class Vault:
        def seal_file(self, *_):
            raise AssertionError("untrusted receipt used")
    rows = [
        {"action_id": "unsigned", "trigger_module": "SpywareGuard", "status": "applied",
         "action": "quarantine_file", "integrity_status": "legacy-untrusted"},
        {"action_id": "undone", "trigger_module": "SpywareGuard", "status": "applied",
         "action": "quarantine_file", "integrity_status": "verified", "record_type": "commit", "undone": True}]
    module, _ = make_module(vault=Vault())
    module._manager = SimpleNamespace(modules={"Adversary Combat": SimpleNamespace(list_actions=lambda **_: rows)})
    module._collect_responses()
    assert module.dashboard_snapshot()["encrypted_evidence"]["status"] == "not-used"
    assert all(row["integrity_status"] == "verified" for row in module.dashboard_snapshot()["containments"])


def test_verified_quarantine_receipt_encrypts_copy_and_retains_honest_status():
    class Vault:
        def seal_file(self, path, digest):
            assert path == "fixture.bin" and digest == "a" * 64
            return {"source_removed": False, "receipt_id": "sealed"}
    action = {"action_id": "receipt-1", "trigger_module": "SpywareGuard", "status": "applied",
              "integrity_status": "verified", "record_type": "commit", "undone": False,
              "action": "quarantine_file", "details": {"quarantine": "fixture.bin", "sha256": "a" * 64}}
    module, _ = make_module(vault=Vault())
    module._manager = SimpleNamespace(modules={"Adversary Combat": SimpleNamespace(list_actions=lambda **_: [action])})
    module._collect_responses()
    module._collect_responses()
    result = module.dashboard_snapshot()
    assert result["encrypted_evidence"]["status"] == "encrypted-forensic-copy"
    assert result["encrypted_evidence"]["plaintext_quarantine_remains"] is True
    assert len(result["containments"]) == 1


def test_transient_archive_failure_retries_after_bounded_backoff():
    calls, clock = [], [NOW]
    class Vault:
        def seal_file(self, path, digest):
            calls.append(path)
            if len(calls) == 1:
                raise PermissionError("fixture")
            return {"receipt_id": "sealed"}
    action = {"action_id": "retry-1", "trigger_module": "SpywareGuard", "status": "applied",
              "integrity_status": "verified", "record_type": "commit", "action": "quarantine_file",
              "details": {"quarantine": "fixture.bin", "sha256": "a" * 64}}
    module, _ = make_module(vault=Vault(), clock=lambda: clock[0])
    module._manager = SimpleNamespace(modules={"Adversary Combat": SimpleNamespace(list_actions=lambda **_: [action])})
    module._collect_responses()
    module._collect_responses()
    assert len(calls) == 1
    clock[0] += 31
    module._collect_responses()
    module._collect_responses()
    assert len(calls) == 2
    assert module.dashboard_snapshot()["encrypted_evidence"]["status"] == "encrypted-forensic-copy"


def test_config_load_preserves_strict_boolean_and_bounded_research_urls(tmp_path, monkeypatch):
    from angerona.core.config import Config
    data = {"spyware_network_enabled": "true", "spyware_beacon_enabled": True,
            "spyware_auto_contain": False,
            "spyware_research_urls": ["https://example.org/report"] * 40}
    (tmp_path / "settings.json").write_text(json.dumps(data))
    monkeypatch.setattr(Config, "settings_path", property(lambda _self: tmp_path / "settings.json"))
    cfg = Config.load()
    assert cfg.spyware_network_enabled is False
    assert cfg.spyware_beacon_enabled is True
    assert cfg.spyware_auto_contain is False
    assert cfg.spyware_research_urls == ["https://example.org/report"]
