from __future__ import annotations

import json
import hashlib
import os
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.spyware_intel import Indicator, IndicatorReviewIdentity, ThreatIntelStore
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


def selected_review(module, *, source=None):
    return next(row["review_identity"] for row in module.dashboard_snapshot()["indicators"]
                if source is None or row["source"] == source)


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
    expected = selected_review(module)
    assert module.review_indicator("ip", "8.8.8.8", expected=expected)
    module._process_commands()
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert bus.recent(1)[0].details["response_contract"]["actions"] == ["block_remote_ip"]
    assert module.review_indicator("ip", "8.8.8.8", approved=False, expected=expected)
    module._process_commands()
    assert not module.dashboard_snapshot()["indicators"][0]["approved"]


def test_changed_report_digest_requires_review_in_dashboard_and_live_match():
    module, bus = make_module()
    module._intel.ingest("8.8.8.8 first report", "fixture", now=NOW)
    assert module.review_indicator("ip", "8.8.8.8", expected=selected_review(module))
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
    module._intel.ingest("a" * 64, "hash-scan-fixture", now=NOW)
    assert module.review_indicator("sha256", "a" * 64, expected=selected_review(module))
    module._process_commands()
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


def _memory_receipt_fixture(*, pid=45001, birth=NOW - 10, request_id="a" * 32,
                            source="memory.windows.virtualquery", expected=None,
                            finished_at=NOW, status="bound"):
    from angerona.core.spyware_sensors import MemoryIdentityReceipt, MemoryProcessIdentity
    obj = MemoryProcessIdentity(pid, 116444736000000000 + int(birth * 10000000), 0)
    return MemoryIdentityReceipt(source, request_id, pid, expected, obj, obj,
        finished_at - 1, finished_at, True, status, "Inert same-handle fixture").to_dict()


def _memory_finding_fixture():
    return {"kind": "private_executable_memory", "severity": "MEDIUM",
            "reason": "Inert private executable metadata", "response_eligible": True}


def test_memory_scan_uses_collector_receipt_instead_of_inventory_birth():
    calls = []
    row = {"pid": 45001, "create_time": NOW - 10}
    def collect(pid, **kwargs):
        calls.append((pid, kwargs))
        finding = dict(_memory_finding_fixture(), process_create_time=NOW - 999, pid=45099)
        return {"findings": [finding], "coverage": {"memory.windows.virtualquery": {"status": "partial"}},
            "memory_identity": _memory_receipt_fixture(pid=pid, request_id=kwargs["request_id"],
                expected=kwargs["expected_create_time"])}
    module, bus = make_module(process_observer=lambda: ProcessSnapshot((row,), NOW, True, 0, 0),
                              memory_collector=collect)
    module._settings["spyware_memory_enabled"] = True
    module._scan_once()
    event, = bus.recent(10)
    assert calls[0][0] == 45001 and calls[0][1]["max_regions"] == 512
    assert calls[0][1]["expected_create_time"] == NOW - 10
    assert len(calls[0][1]["request_id"]) == 32 and not calls[0][1]["cancelled"]()
    assert event.details["process_create_time"] == NOW - 10
    assert event.details["response_eligible"] is True
    assert event.details["response_contract"]["targets"] == {"pid": 45001, "process_create_time": NOW - 10}
    assert "isolate_host" not in event.details["response_contract"]["actions"]
    assert module.dashboard_snapshot()["coverage"]["memory"]["status"] == "partial"


@pytest.mark.parametrize("case", ["legacy", "wrong-request", "wrong-pid", "wrong-source",
                                  "mismatch", "no-expected-birth", "malformed"])
def test_unbound_memory_finding_is_ineligible_before_any_response_including_host_fallback(monkeypatch, case):
    row = {"pid": 45001, "create_time": NOW - 10}
    def collect(pid, **kwargs):
        receipt = _memory_receipt_fixture(pid=pid, request_id=kwargs["request_id"],
                                          expected=kwargs["expected_create_time"])
        if case == "wrong-request":
            receipt["request_id"] = "0" * 32
        elif case == "wrong-pid":
            receipt = _memory_receipt_fixture(pid=45099, request_id=kwargs["request_id"], expected=NOW - 10)
        elif case == "wrong-source":
            receipt["source"] = "memory.windows.inject_scanner"
        elif case == "mismatch":
            receipt = _memory_receipt_fixture(pid=pid, birth=NOW - 1, request_id=kwargs["request_id"],
                                               expected=NOW - 10, status="mismatch")
        elif case == "no-expected-birth":
            receipt["expected_create_time"] = None
        elif case == "malformed":
            receipt["before"]["birth_filetime"] = True
        result = {"findings": [dict(_memory_finding_fixture(), process_create_time=NOW - 10)],
                  "coverage": {"memory.windows.virtualquery": {"status": "complete"}}}
        if case != "legacy":
            result["memory_identity"] = receipt
        return result
    module, bus = make_module(process_observer=lambda: ProcessSnapshot((row,), NOW, True, 0, 0),
                              memory_collector=collect)
    module._settings["spyware_memory_enabled"] = True
    response = module._response
    def require_ineligible(finding, local_authority):
        assert finding["response_eligible"] is False
        assert finding["process_create_time"] is None
        return response(finding, local_authority)
    monkeypatch.setattr(module, "_response", require_ineligible)
    module._scan_once()
    event, = bus.recent(10)
    assert event.details["response_eligible"] is False
    assert event.details["response_authorized"] is False and event.details["active_attack"] is False
    assert "response_contract" not in event.details
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 0
    assert module.dashboard_snapshot()["coverage"]["memory"]["status"] == "partial"


def test_legacy_collector_signature_failure_is_explicit_and_never_retried():
    calls = []
    def collect(pid, max_regions):
        calls.append(pid)
        pytest.fail("Legacy signature must not be retried after protocol refusal")
    rows = ({"pid": 45001, "create_time": NOW - 10},)
    module, bus = make_module(process_observer=lambda: ProcessSnapshot(rows, NOW, True, 0, 0),
                              memory_collector=collect)
    module._settings["spyware_memory_enabled"] = True
    module._scan_once()
    assert calls == [] and bus.recent(10) == []
    coverage = module.dashboard_snapshot()["coverage"]["memory"]["by_pid"]["45001"]["coverage"]
    assert coverage["memory.provider"]["status"] == "error"
    assert "no legacy fallback" in coverage["memory.provider"]["detail"]
    assert coverage["memory.identity"]["status"] == "partial"


def test_memory_rotating_sample_keeps_four_process_and_512_region_limits():
    rows = tuple({"pid": 45001 + index, "create_time": NOW - 10} for index in range(10))
    calls = []
    def collect(pid, **kwargs):
        calls.append((pid, kwargs["max_regions"]))
        return {"findings": [], "coverage": {}, "memory_identity": _memory_receipt_fixture(
            pid=pid, request_id=kwargs["request_id"], expected=kwargs["expected_create_time"])}
    module, _ = make_module(process_observer=lambda: ProcessSnapshot(rows, NOW, True, 0, 0),
                            memory_collector=collect)
    module._settings["spyware_memory_enabled"] = True
    module._scan_once()
    module._scan_once()
    assert calls == [(45001 + index, 512) for index in range(8)]


@pytest.mark.parametrize("kind", ["private_executable_memory", "sensor_memory_injection_scanner"])
def test_direct_memory_response_requires_receipt_even_with_a_birth_hint(kind):
    module, _ = make_module()
    finding = {"kind": kind, "pid": 45001, "process_create_time": NOW - 10,
               "response_eligible": True, "remote_ip": "8.8.8.8"}
    assert module._response(finding, True) == {}


def test_authenticated_memory_source_uses_native_receipt_not_enriched_birth():
    module, bus = make_module()
    receipt = _memory_receipt_fixture(source="memory.windows.inject_scanner")
    bus.publish(Event("Memory Injection Scanner", "inert metadata", Severity.MEDIUM, NOW, {
        "pid": 45001, "process_create_time": NOW - 999, "memory_identity": receipt,
        "response_eligible": True}))
    module._consume_events()
    event = next(item for item in bus.recent(10) if item.module == module.name)
    assert event.details["process_create_time"] == NOW - 10
    assert event.details["response_contract"]["targets"]["process_create_time"] == NOW - 10
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 1


@pytest.mark.parametrize("case", ["missing", "stale", "wrong-source", "ineligible", "legacy-upstream"])
def test_authenticated_unbound_memory_source_remains_observation_and_cannot_launder_telemetry(case):
    from angerona.core.response_contract import process_response
    module, bus = make_module()
    receipt = _memory_receipt_fixture(source="memory.windows.inject_scanner",
        finished_at=NOW - 10 if case == "stale" else NOW)
    details = {"pid": 45001, "process_create_time": NOW - 10, "memory_identity": receipt,
               "response_eligible": case != "ineligible",
               "event_type": "api_access", "api": "BitBlt", "authorized": False}
    if case == "missing":
        details.pop("memory_identity")
    elif case == "wrong-source":
        receipt["source"] = "memory.windows.virtualquery"
    elif case == "legacy-upstream":
        details.pop("memory_identity")
        details.update(process_response(45001, NOW - 10))
    bus.publish(Event("Memory Injection Scanner", "inert metadata", Severity.MEDIUM, NOW, details))
    module._consume_events()
    events = [item for item in bus.recent(10) if item.module == module.name]
    assert len(events) == 1 and events[0].details["response_eligible"] is False
    assert events[0].details["process_create_time"] is None
    assert events[0].details["response_authorized"] is False
    assert "response_contract" not in events[0].details
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 0
    assert module.dashboard_snapshot()["coverage"]["memory_sensor_identity"]["status"] == "partial"


def test_authenticated_memory_receipt_replay_cannot_authorize_a_second_response():
    module, bus = make_module()
    details = {"pid": 45001, "response_eligible": True,
               "memory_identity": _memory_receipt_fixture(source="memory.windows.inject_scanner")}
    bus.publish(Event("Memory Injection Scanner", "inert metadata", Severity.MEDIUM, NOW, details))
    module._consume_events()
    bus.publish(Event("Memory Injection Scanner", "replayed receipt", Severity.MEDIUM, NOW + 1, details))
    module._consume_events()
    events = [item for item in bus.recent(10) if item.module == module.name]
    assert len(events) == 2
    assert sum(item.details["response_authorized"] is True for item in events) == 1
    replayed = next(item for item in events if item.details["evidence"]["source_event_ts"] == NOW + 1)
    assert replayed.details["response_eligible"] is False
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 1
    assert len(module._memory_receipts) == 1


@pytest.mark.parametrize("extra", [{"drill": True}, {"origin": "remote"}, {"source_host": "elsewhere"}])
def test_memory_receipt_cannot_override_remote_or_drill_provenance(extra):
    module, bus = make_module()
    bus.publish(Event("Memory Injection Scanner", "inert metadata", Severity.MEDIUM, NOW, {
        "pid": 45001, "response_eligible": True,
        "memory_identity": _memory_receipt_fixture(source="memory.windows.inject_scanner"), **extra}))
    module._consume_events()
    assert not module.dashboard_snapshot()["hits"] and not module._memory_receipts


def test_memory_receipt_cannot_override_failed_channel_authentication(monkeypatch):
    module, bus = make_module()
    bus.publish(Event("Memory Injection Scanner", "inert metadata", Severity.MEDIUM, NOW, {
        "pid": 45001, "response_eligible": True,
        "memory_identity": _memory_receipt_fixture(source="memory.windows.inject_scanner")}))
    monkeypatch.setattr(bus, "verify", lambda _event: False)
    module._consume_events()
    assert not module.dashboard_snapshot()["hits"] and not module._memory_receipts


@pytest.mark.parametrize("retirement", ["stop", "replacement", "before-publish"])
def test_retiring_memory_owner_keeps_positive_advisory_without_response_or_more_collection(monkeypatch, retirement):
    rows = ({"pid": 45001, "create_time": NOW - 10}, {"pid": 45002, "create_time": NOW - 10})
    calls = []
    def collect(pid, **kwargs):
        calls.append(pid)
        receipt = _memory_receipt_fixture(pid=pid, request_id=kwargs["request_id"],
                                          expected=kwargs["expected_create_time"])
        if retirement == "stop":
            module.stop()
        elif retirement == "replacement":
            module._stop = threading.Event()
        if retirement != "before-publish":
            assert kwargs["cancelled"]() is True
        return {"findings": [_memory_finding_fixture()], "memory_identity": receipt,
                "coverage": {"memory.windows.virtualquery": {"status": "partial"}}}
    module, bus = make_module(process_observer=lambda: ProcessSnapshot(rows, NOW, True, 0, 0),
        memory_collector=collect,
        connection_observer=lambda: pytest.fail("No further collection after memory owner retirement"))
    module._settings["spyware_memory_enabled"] = True
    if retirement == "replacement":
        module._run_context.stop_event = module._stop
    if retirement == "before-publish":
        publish_memory = module._publish_memory
        def retire_before_publish(finding, stopped, **kwargs):
            module.stop()
            return publish_memory(finding, stopped, **kwargs)
        monkeypatch.setattr(module, "_publish_memory", retire_before_publish)
    response = module._response
    admitted = []
    def require_advisory(finding, local_authority):
        admitted.append(finding["response_eligible"])
        assert finding["response_eligible"] is False
        return response(finding, local_authority)
    monkeypatch.setattr(module, "_response", require_advisory)
    module._scan_once()
    event, = bus.recent(10)
    assert calls == [45001] and admitted == [False]
    assert event.details["response_eligible"] is False
    assert event.details["response_authorized"] is False and "response_contract" not in event.details
    assert "owner generation" in event.details["eligibility_reason"]
    snapshot = module.dashboard_snapshot()
    assert snapshot["stats"]["response_requests"] == 0
    assert snapshot["coverage"]["memory"]["status"] == "partial"
    assert snapshot["coverage"]["memory"]["cancelled"] is True
    assert snapshot["coverage"]["host"] == "scan-cancelled-memory-owner-generation"


def test_stopped_owner_cannot_admit_a_fresh_authenticated_memory_response():
    module, bus = make_module()
    bus.publish(Event("Memory Injection Scanner", "inert metadata", Severity.MEDIUM, NOW, {
        "pid": 45001, "response_eligible": True,
        "memory_identity": _memory_receipt_fixture(source="memory.windows.inject_scanner")}))
    module.stop()
    module._consume_events()
    event = next(item for item in bus.recent(10) if item.module == module.name)
    assert event.details["response_eligible"] is False and event.details["response_authorized"] is False
    assert "response_contract" not in event.details
    assert module.dashboard_snapshot()["coverage"]["memory_sensor_identity"]["status"] == "partial"


def test_review_binds_selected_later_source_and_revoke_cannot_remove_another_receipt():
    module, bus = make_module()
    module._intel.ingest("8.8.8.8 source A", "https://a.example/report", now=NOW)
    module._intel.ingest("8.8.8.8 source Z", "https://z.example/report", now=NOW)
    earlier = selected_review(module, source="https://a.example/report")
    selected = selected_review(module, source="https://z.example/report")
    assert module.review_indicator("ip", "8.8.8.8", expected=selected)
    module._process_commands()
    rows = module.dashboard_snapshot()["indicators"]
    assert [(row["source"], row["approved"]) for row in rows] == [
        ("https://a.example/report", False), ("https://z.example/report", True)]
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    event, = bus.recent(10)
    assert event.details["evidence"]["source"] == "https://z.example/report"
    assert event.details["evidence"]["source_sha256"] == selected["candidate"]["source_sha256"]
    assert event.details["evidence"]["review_identity"] == selected
    assert event.details["response_contract"]["targets"] == {"remote_ips": ["8.8.8.8"]}
    assert module.review_indicator("ip", "8.8.8.8", approved=False, expected=earlier)
    module._process_commands()
    assert module.dashboard_snapshot()["indicator_review"]["state"] == "stale-review"
    assert next(row for row in module.dashboard_snapshot()["indicators"]
                if row["source"] == "https://z.example/report")["approved"]
    assert module.review_indicator("ip", "8.8.8.8", approved=False, expected=selected)
    module._process_commands()
    assert not any(row["approved"] for row in module.dashboard_snapshot()["indicators"])


@pytest.mark.parametrize("replacement", [
    pytest.param("8.8.8.8 changed report", id="changed-bytes"),
    pytest.param("8.8.8.8 original report", id="identical-bytes-no-renewal"),
    pytest.param({"ips": []}, id="literal-removed"),
    pytest.param({"type": "bundle", "objects": [{"type": "indicator", "pattern_type": "stix",
        "pattern": "[ipv4-addr:value = '8.8.8.8']", "revoked": True}]}, id="literal-revoked"),
])
def test_queued_review_refuses_replaced_removed_or_revoked_evidence(replacement):
    module, bus = make_module()
    module._intel.ingest("8.8.8.8 original report", "fixture", now=NOW)
    assert module.review_indicator("ip", "8.8.8.8", expected=selected_review(module))
    module._intel.ingest(replacement, "fixture", now=NOW)
    module._process_commands()
    assert module.dashboard_snapshot()["indicator_review"]["state"] == "stale-review"
    assert not any(row["approved"] for row in module.dashboard_snapshot()["indicators"])
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert not bus.recent(10)


def test_expired_receipt_cannot_reactivate_after_same_bytes_are_ingested_again():
    now = [NOW]
    module, bus = make_module(clock=lambda: now[0])
    module._intel.ingest("8.8.8.8", "fixture", now=now[0], ttl_seconds=1)
    previous = selected_review(module)
    assert module.review_indicator("ip", "8.8.8.8", expected=previous)
    module._process_commands()
    now[0] += 1
    assert not module.dashboard_snapshot()["indicators"]
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert not bus.recent(10)
    now[0] += 1
    module._intel.ingest("8.8.8.8", "fixture", now=now[0], ttl_seconds=1)
    current = selected_review(module)
    assert current["candidate"]["source_sha256"] == previous["candidate"]["source_sha256"]
    assert current != previous
    assert not module.dashboard_snapshot()["indicators"][0]["approved"]
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert not bus.recent(10)
    assert module.review_indicator("ip", "8.8.8.8", expected=previous)
    module._process_commands()
    assert module.dashboard_snapshot()["indicator_review"]["state"] == "stale-review"
    assert module.review_indicator("ip", "8.8.8.8", expected=current)
    module._process_commands()
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert bus.recent(1)[0].details["evidence"]["review_identity"] == current


def test_unrelated_source_preserves_receipt_but_identical_refresh_never_renews_it():
    module, bus = make_module()
    module._intel.ingest("8.8.8.8", "selected", now=NOW)
    assert module.review_indicator("ip", "8.8.8.8", expected=selected_review(module))
    module._process_commands()
    module._intel.ingest("1.1.1.1", "unrelated", now=NOW)
    assert next(row for row in module.dashboard_snapshot()["indicators"]
                if row["source"] == "selected")["approved"]
    module._intel.ingest("8.8.8.8", "selected", now=NOW)
    assert not any(row["approved"] for row in module.dashboard_snapshot()["indicators"])
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert not bus.recent(10)


def test_review_queue_copies_evidence_values_without_retaining_ui_dictionary():
    module, bus = make_module()
    module._intel.ingest("8.8.8.8", "fixture", now=NOW)
    selected = selected_review(module)
    original = json.loads(json.dumps(selected))
    assert module.review_indicator("ip", "8.8.8.8", expected=selected)
    selected["candidate"]["source"] = "changed-after-queue"
    selected["candidate"]["source_sha256"] = "f" * 64
    module._process_commands()
    assert module.dashboard_snapshot()["indicators"][0]["approved"]
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert bus.recent(1)[0].details["evidence"]["review_identity"] == original


@pytest.mark.parametrize("bad", ["legacy", "unknown", "session", "boolean-generation",
    "old-generation", "missing-candidate", "nonfinite-time", "boolean-revision", "object-source"])
def test_legacy_or_malformed_review_never_grants_authority(bad):
    module, bus = make_module()
    module._intel.ingest("8.8.8.8", "fixture", now=NOW)
    expected = selected_review(module)
    if bad == "legacy":
        expected = None
    elif bad == "unknown":
        expected["extra"] = True
    elif bad == "session":
        expected["session"] = "f" * 32
    elif bad == "boolean-generation":
        expected["generation"] = True
    elif bad == "old-generation":
        expected["generation"] -= 1
    elif bad == "missing-candidate":
        expected["candidate"].pop("source_sha256")
    elif bad == "nonfinite-time":
        expected["candidate"]["expires_at"] = float("nan")
    elif bad == "boolean-revision":
        expected["candidate"]["revision"] = True
    else:
        class Uncopyable:
            def __str__(self):
                raise AssertionError("untrusted object was converted")
            def __deepcopy__(self, memo):
                raise AssertionError("untrusted object was copied")
        expected["candidate"]["source"] = Uncopyable()
    assert not module.review_indicator("ip", "8.8.8.8", expected=expected)
    assert module._commands.empty()
    assert module.dashboard_snapshot()["indicator_review"]["state"] == "stale-review"
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert not bus.recent(10)


def test_queued_legacy_and_retired_generation_reviews_are_explicitly_stale():
    module, bus = make_module()
    module._intel.ingest("8.8.8.8", "fixture", now=NOW)
    assert module._enqueue("review", ("ip", "8.8.8.8", True))
    module._process_commands()
    assert module.dashboard_snapshot()["indicator_review"]["state"] == "stale-review"
    assert module.review_indicator("ip", "8.8.8.8", expected=selected_review(module))
    module._lifecycle_generation += 1
    module._process_commands()
    assert module.dashboard_snapshot()["indicator_review"]["state"] == "stale-review"
    assert not module.dashboard_snapshot()["indicators"][0]["approved"]
    assert not bus.recent(10)


@pytest.mark.parametrize("change", ["expiry", "store-session"])
def test_queued_review_refuses_expiry_or_replaced_store_session(change):
    now = [NOW]
    module, bus = make_module(clock=lambda: now[0])
    module._intel.ingest("8.8.8.8", "fixture", now=NOW, ttl_seconds=1)
    assert module.review_indicator("ip", "8.8.8.8", expected=selected_review(module))
    if change == "expiry":
        now[0] += 1
    else:
        module._intel = ThreatIntelStore()
        module._intel.ingest("8.8.8.8", "fixture", now=NOW, ttl_seconds=1)
    module._process_commands()
    assert module.dashboard_snapshot()["indicator_review"]["state"] == "stale-review"
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert not bus.recent(10)


def test_review_compare_and_assignment_hold_store_before_module_lock(monkeypatch):
    module, bus = make_module()
    module._intel.ingest("8.8.8.8 original", "fixture", now=NOW)
    assert module.review_indicator("ip", "8.8.8.8", expected=selected_review(module))
    active = threading.local()
    boundary, release, writer_started = threading.Event(), threading.Event(), threading.Event()
    lock_order, failures = [], []
    original_candidates = module._intel.review_candidates
    original_module_lock = module._lock

    @contextmanager
    def tracked_candidates(*args, **kwargs):
        with original_candidates(*args, **kwargs) as rows:
            active.store_held = True
            try:
                yield rows
            finally:
                active.store_held = False

    class ReviewBoundaryLock:
        intercepted = False
        def __enter__(self):
            if threading.current_thread() is reviewer and not self.intercepted:
                self.intercepted = True
                lock_order.append(getattr(active, "store_held", False))
                boundary.set()
                if not release.wait(5):
                    raise AssertionError("test did not release the review boundary")
            return original_module_lock.__enter__()
        def __exit__(self, *args):
            return original_module_lock.__exit__(*args)

    def refresh():
        writer_started.set()
        try:
            module._intel.ingest("8.8.8.8 replacement", "fixture", now=NOW)
        except Exception as exc:
            failures.append(exc)

    monkeypatch.setattr(module._intel, "review_candidates", tracked_candidates)
    monkeypatch.setattr(module, "_lock", ReviewBoundaryLock())
    reviewer = threading.Thread(target=module._process_commands, daemon=True)
    writer = threading.Thread(target=refresh, daemon=True)
    reviewer.start()
    try:
        assert boundary.wait(5)
        writer.start()
        assert writer_started.wait(5)
    finally:
        release.set()
        reviewer.join(5)
        if writer.ident is not None:
            writer.join(5)
    assert not reviewer.is_alive() and not writer.is_alive()
    assert lock_order == [True] and not failures
    assert not module.dashboard_snapshot()["indicators"][0]["approved"]
    module._match_indicator({"remote_ip": "8.8.8.8"}, "ip", "8.8.8.8", local_authority=True)
    assert not bus.recent(10)


def test_dashboard_serializes_only_first_500_fresh_indicator_rows(monkeypatch):
    from angerona.modules import spyware_guard
    module, _ = make_module()
    module._intel.ingest({"domains": [f"host-{index}.example" for index in range(650)]},
                         "bounded-dashboard-fixture", now=NOW)
    original_asdict = spyware_guard.asdict
    converted_items, converted_identities = [], []

    def counted_asdict(value):
        if type(value) is Indicator:
            converted_items.append(value.value)
        elif type(value) is IndicatorReviewIdentity:
            converted_identities.append(value.value)
        return original_asdict(value)

    monkeypatch.setattr(spyware_guard, "asdict", counted_asdict)
    rows = module.dashboard_snapshot()["indicators"]
    expected = [item.value for item in module._intel.indicators(now=NOW)[:500]]
    assert len(rows) == 500
    assert [row["value"] for row in rows] == expected
    assert converted_items == expected
    assert converted_identities == expected
    assert not any(row["approved"] for row in rows)
