"""Inert repeat-admission regressions; no live process or response action runs."""
from __future__ import annotations

import pytest

from angerona.core.eventbus import Severity
from angerona.core.spyware_sensors import MemoryProcessIdentity, memory_identity_receipt
from angerona.modules import mem_inject_scanner as memory
from test_memory_scanner_lifecycle import scanner  # reusable inert native fixture
from test_spyware_guard import NOW, make_module, _memory_finding_fixture, _memory_receipt_fixture
from angerona.telemetry.sensors import ProcessSnapshot


def _exposure(**updates):
    finding = {"kind": "service_unquoted_path", "severity": "LOW",
               "pid": 45001, "process_create_time": NOW - 100,
               "response_eligible": False, "finding_kind": "exposure",
               "evidence": {"configured_command": "inert fixture"}}
    finding.update(updates)
    return finding


@pytest.mark.parametrize("change", [
    {"severity": "HIGH"}, {"finding_kind": "detection"},
    {"response_eligible": True}, {"classification_reason": "new classification"},
    {"eligibility_reason": "fresh local evidence"},
    {"evidence": {"configured_command": "changed inert fixture"}},
    {"observed_content_sha256": "a" * 64},
    {"process_create_time": NOW - 50},
    {"memory_scan_complete": False}, {"memory_scan_limit_reason": "budget reached"},
])
def test_spyware_material_changes_bypass_standing_exposure_window(change):
    module, bus = make_module()
    original = _exposure()
    module._publish(original, local_authority=True)
    module._publish(dict(original, **change), local_authority=True)
    events = bus.recent(10)
    assert len(events) == 2
    assert all(event.details["response_authorized"] is False for event in events)
    assert all("response_contract" not in event.details for event in events)
    assert all(bus.verify(event) for event in events)
    assert original == _exposure()  # admission never edits the producer finding


def test_spyware_classification_reappearance_is_a_transition():
    module, bus = make_module()
    for severity in ("LOW", "HIGH", "LOW", "HIGH"):
        module._publish(_exposure(severity=severity), local_authority=True)
    assert len(bus.recent(10)) == 4
    assert module.dashboard_snapshot()["stats"]["repeat_suppressed"] == 0


@pytest.mark.parametrize("exposure,window", [(True, 21600), (False, 300)])
def test_spyware_identical_repeat_has_fixed_boundary_and_visible_count(exposure, window):
    now = [NOW]
    module, bus = make_module(clock=lambda: now[0])
    finding = _exposure() if exposure else _exposure(finding_kind="detection", response_eligible=True)
    module._publish(finding, local_authority=True)
    now[0] += window - 0.001
    module._publish(finding, local_authority=True)
    assert len(bus.recent(10)) == 1
    assert module.dashboard_snapshot()["stats"]["repeat_suppressed"] == 1
    now[0] = NOW + window
    module._publish(finding, local_authority=True)
    assert len(bus.recent(10)) == 2
    assert bus.recent(1)[0].details["repeat_suppressed"] == 1
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 0


@pytest.mark.parametrize("retention_failed", [False, True])
def test_spyware_new_native_response_eligibility_is_not_hidden_by_advisory(monkeypatch, retention_failed):
    module, bus = make_module()
    digest = "a" * 64
    review = {"indicator_kind": "sha256", "indicator": digest, "locally_activated": True}
    monkeypatch.setattr(module, "_current_hash_review", lambda value: review if value == digest else None)
    monkeypatch.setattr("angerona.modules.spyware_guard.time.monotonic", lambda: 100.0)
    finding = {"kind": "definition_sha256_indicator_match", "pid": 45001,
               "process_create_time": NOW - 10, "path": "C:/inert/fixture.exe",
               "observed_content_sha256": digest, "evidence": review, "severity": "HIGH"}
    module._publish(finding, local_authority=True)
    assert bus.recent(1)[0].details["response_authorized"] is False
    token = object()
    module._native_hash_samples[token] = (
        module.lifecycle_generation, module._stop, 100.0, finding["path"], digest, 45001, NOW - 10)
    if retention_failed:
        retain = module._retain_native_hash_response

        def unavailable_proof(*_args):
            raise ValueError("inert proof retention failure")

        monkeypatch.setattr(module, "_retain_native_hash_response", unavailable_proof)
        module._publish(finding, local_authority=True, native_sample=token)
        assert bus.recent(1)[0].details["response_authorized"] is False
        assert "response_contract" not in bus.recent(1)[0].details
        monkeypatch.setattr(module, "_retain_native_hash_response", retain)
    module._publish(finding, local_authority=True, native_sample=token)
    active = bus.recent(1)[0]
    assert active.details["response_authorized"] is True and module.verify_response_event(active)
    module._publish(finding, local_authority=True, native_sample=token)
    assert len(bus.recent(10)) == 2 + int(retention_failed)
    assert module.dashboard_snapshot()["stats"]["response_requests"] == 1
    module._settings["spyware_auto_contain"] = False
    module._publish(finding, local_authority=True, native_sample=token)
    assert len(bus.recent(10)) == 3 + int(retention_failed)
    assert bus.recent(1)[0].details["response_authorized"] is False
    assert "response_contract" not in bus.recent(1)[0].details


def test_spyware_repeat_cache_is_bounded_and_eviction_renews_reporting():
    module, _ = make_module()
    first = _exposure(evidence={"index": 0})
    module._publish(first, local_authority=True)
    for index in range(1, 2049):
        module._publish(_exposure(evidence={"index": index}), local_authority=True)
    assert len(module._dedup) == 2048
    stats = module.dashboard_snapshot()["stats"]
    assert stats["repeat_cache_evicted"] == 1 and stats["findings"] == 2049
    module._publish(first, local_authority=True)
    assert module.dashboard_snapshot()["stats"]["findings"] == 2050
    assert module.dashboard_snapshot()["stats"]["repeat_cache_evicted"] == 2


def _birth_ticks(birth):
    return 116444736000000000 + int(birth * 10000000)


def _receipt(pid=101, birth=900.0):
    identity = MemoryProcessIdentity(pid, _birth_ticks(birth), 0)
    return memory_identity_receipt(source="memory.windows.inject_scanner", request_id="a" * 32,
        pid=pid, expected_create_time=None, before=identity, after=identity,
        started_at=NOW, finished_at=NOW, handle_closed=True)


def _alert(scanner, regions, *, birth=900.0, pid=101, complete=True, reason=""):
    scanner._alert(pid, "inert.exe", regions, (), memory_identity=_receipt(pid, birth),
                   scan_complete=complete, scan_limit_reason=reason)


def test_memory_changed_protection_and_region_reappearance_report_immediately(scanner, monkeypatch):
    monkeypatch.setattr(memory.time, "time", lambda: NOW)
    a = (0, 8192, memory.PAGE_EXECUTE_READWRITE)
    b = (8192, 8192, memory.PAGE_EXECUTE_READWRITE)
    observations = ([a], [(0, 8192, memory.PAGE_EXECUTE_WRITECOPY)], [a, b], [a], [a, b])
    for regions in observations:
        _alert(scanner, regions)
    assert len(scanner._bus.recent(10)) == 5
    assert scanner._reported_regions[(101, _birth_ticks(900.0))].regions == frozenset([a, b])
    assert all(event.details["active_attack"] is False for event in scanner._bus.recent(10))
    assert all(event.severity == Severity.MEDIUM for event in scanner._bus.recent(10))


def test_memory_changed_coverage_and_limit_reason_report_immediately(scanner, monkeypatch):
    monkeypatch.setattr(memory.time, "time", lambda: NOW)
    regions = [(0, 8192, memory.PAGE_EXECUTE_READWRITE)]
    for complete, reason in ((True, ""), (False, "budget reached"),
                             (False, "native metadata unavailable"), (True, "")):
        _alert(scanner, regions, complete=complete, reason=reason)
    assert len(scanner._bus.recent(10)) == 4
    assert scanner._bus.recent(1)[0].details["memory_scan_complete"] is True


def test_memory_identical_repeat_boundary_counts_opportunities_without_sliding(scanner, monkeypatch):
    now = [NOW]
    monkeypatch.setattr(memory.time, "time", lambda: now[0])
    regions = [(0, 8192, memory.PAGE_EXECUTE_READWRITE)]
    _alert(scanner, regions)
    for offset in (1, 300, memory._UNCHANGED_REPEAT_S - 0.001):
        now[0] = NOW + offset
        _alert(scanner, regions)
    assert len(scanner._bus.recent(10)) == 1
    assert scanner._repeat_stats["suppressed"] == 3
    now[0] = NOW + memory._UNCHANGED_REPEAT_S
    _alert(scanner, regions)
    assert len(scanner._bus.recent(10)) == 2
    assert scanner._bus.recent(1)[0].details["repeat_suppressed"] == 3
    assert scanner._reported_regions[(101, _birth_ticks(900.0))].suppressed == 0


def test_memory_pid_birth_change_and_unbound_receipt_cannot_inherit_suppression(scanner, monkeypatch):
    monkeypatch.setattr(memory.time, "time", lambda: NOW)
    regions = [(0, 8192, memory.PAGE_EXECUTE_READWRITE)]
    _alert(scanner, regions, birth=900.0)
    _alert(scanner, regions, birth=901.0)
    for _ in range(2):
        scanner._alert(101, "inert.exe", regions, ())
    assert len(scanner._bus.recent(10)) == 4
    assert set(scanner._reported_regions) == {(101, _birth_ticks(900.0)), (101, _birth_ticks(901.0))}
    assert scanner._bus.recent(1)[0].details["response_eligible"] is False


def test_memory_evidence_changes_reach_alert_inside_short_native_gate(scanner, monkeypatch):
    monkeypatch.setattr(memory.time, "time", lambda: NOW)
    protection = [memory.PAGE_EXECUTE_READWRITE]
    scanner._k32.query = lambda address: (0, 8192, protection[0]) if address == 0 else None
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    protection[0] = memory.PAGE_EXECUTE_WRITECOPY
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    scanner._MAX_QUERIES_PER_PID = 1
    assert scanner._scan_pid(101, "inert.exe", ()).outcome == "partial"
    assert len(scanner._bus.recent(10)) == 3
    latest = scanner._bus.recent(1)[0]
    assert latest.details["memory_scan_complete"] is False
    assert latest.details["memory_scan_limit_reason"] == "native traversal budget reached"


def test_memory_partial_or_unbound_empty_scan_retains_positive_but_complete_clear_renews(scanner, monkeypatch):
    monkeypatch.setattr(memory.time, "time", lambda: NOW)
    positive = lambda address: (0, 8192, memory.PAGE_EXECUTE_READWRITE) if address == 0 else None
    clean = lambda address: (0, 8192, 0x04) if address == 0 else None
    scanner._k32.query = positive
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    key = (101, _birth_ticks(scanner._k32.birth))
    scanner._MAX_QUERIES_PER_PID = 1
    scanner._k32.query = clean
    assert scanner._scan_pid(101, "inert.exe", ()).outcome == "partial"
    assert key in scanner._reported_regions
    scanner._MAX_QUERIES_PER_PID = 32768
    scanner._k32.times_available = False
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    assert key in scanner._reported_regions
    scanner._k32.times_available = True
    scanner._k32.query = positive
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    assert len(scanner._bus.recent(10)) == 1
    scanner._k32.query = clean
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    assert key not in scanner._reported_regions and key not in scanner._seen
    scanner._k32.query = positive
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    assert len(scanner._bus.recent(10)) == 2
    assert scanner._repeat_stats["clean_resets"] == 1


def test_memory_report_cache_has_hard_process_bound_and_visible_conservative_eviction(scanner, monkeypatch):
    monkeypatch.setattr(memory.time, "time", lambda: NOW)
    monkeypatch.setattr(memory, "_REPORTED_PROCESSES_MAX", 2)
    regions = [(0, 8192, memory.PAGE_EXECUTE_READWRITE)]
    for pid in (101, 102, 103):
        _alert(scanner, regions, pid=pid)
    assert len(scanner._reported_regions) == len(scanner._seen) == 2
    assert (101, _birth_ticks(900.0)) not in scanner._reported_regions and (101, _birth_ticks(900.0)) not in scanner._seen
    assert scanner._repeat_stats["cache_evicted"] == 1
    _alert(scanner, regions, pid=101)
    assert len(scanner._bus.recent(10)) == 4
    assert len(scanner._reported_regions) == len(scanner._seen) == 2
    assert scanner._bus.recent(1)[0].details["repeat_cache_evicted"] == 2
    scanner._publish_coverage(memory.ProcessCoverage(), scanner._stop)
    assert "repeat_cache_evicted=2" in scanner.health_note
    assert "repeat_cache_keys=2" in scanner.health_note


def test_memory_oversized_region_set_is_reported_without_being_cached(scanner, monkeypatch):
    monkeypatch.setattr(memory.time, "time", lambda: NOW)
    monkeypatch.setattr(memory, "_REPORTED_REGIONS_MAX", 2)
    regions = [(index * 8192, 8192, memory.PAGE_EXECUTE_READWRITE) for index in range(3)]
    for _ in range(2):
        _alert(scanner, regions)
    assert len(scanner._bus.recent(10)) == 2
    assert scanner._reported_regions == scanner._seen == {}


def test_memory_expiry_removes_paired_gate_and_clock_rollback_cannot_hide_evidence(scanner, monkeypatch):
    now = [NOW]
    monkeypatch.setattr(memory.time, "time", lambda: now[0])
    regions = [(0, 8192, memory.PAGE_EXECUTE_READWRITE)]
    _alert(scanner, regions)
    now[0] += memory._UNCHANGED_REPEAT_S
    scanner._evict_stale_dedup()
    assert scanner._reported_regions == scanner._seen == {}
    assert scanner._repeat_stats["cache_expired"] == 1
    _alert(scanner, regions)
    now[0] -= 1
    _alert(scanner, regions)
    assert len(scanner._bus.recent(10)) == 3


def test_memory_adjacent_native_birth_ticks_with_equal_float_time_have_separate_repeat_and_clear_state(scanner, monkeypatch):
    monkeypatch.setattr(memory.time, "time", lambda: NOW)
    ticks = _birth_ticks(NOW - 10)
    first = MemoryProcessIdentity(101, ticks, 0)
    second = MemoryProcessIdentity(101, ticks + 1, 0)
    assert first.create_time == second.create_time  # 100ns precision is lost in epoch float seconds
    current = [first]
    monkeypatch.setattr(memory, "read_memory_process_identity", lambda *_args, **_kwargs: current[0])
    positive = lambda address: (0, 8192, memory.PAGE_EXECUTE_READWRITE) if address == 0 else None
    scanner._k32.query = positive
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    current[0] = second
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    assert len(scanner._bus.recent(10)) == 2
    assert set(scanner._reported_regions) == {(101, ticks), (101, ticks + 1)}
    scanner._k32.query = lambda address: (0, 8192, 0x04) if address == 0 else None
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    assert set(scanner._reported_regions) == {(101, ticks)}
    assert (101, ticks + 1) not in scanner._seen
    scanner._k32.query = positive
    assert scanner._scan_pid(101, "inert.exe", ()).scanned
    assert len(scanner._bus.recent(10)) == 3
    assert set(scanner._reported_regions) == {(101, ticks), (101, ticks + 1)}


def test_spyware_native_scan_path_reports_complete_partial_complete_transitions(monkeypatch):
    row = {"pid": 45001, "create_time": NOW - 10}
    state = ["complete"]
    collected = []

    def collect(pid, **kwargs):
        collected.append(kwargs["request_id"])
        return {"findings": [dict(_memory_finding_fixture(), evidence={"region": "same inert region"})],
                "memory_identity": _memory_receipt_fixture(pid=pid, request_id=kwargs["request_id"],
                    expected=kwargs["expected_create_time"]),
                "coverage": {"memory.windows.virtualquery": {"status": state[0],
                    "detail": "native traversal budget reached" if state[0] == "partial" else ""}}}

    module, bus = make_module(
        process_observer=lambda: ProcessSnapshot((row,), NOW, True, 0, 0), memory_collector=collect)
    module._settings["spyware_memory_enabled"] = True
    for status in ("complete", "complete", "partial", "partial", "complete"):
        state[0] = status
        assert module._scan_once()
    events = bus.recent(10)
    assert len(collected) == 5 and len(events) == 3
    assert sum(event.details["memory_scan_complete"] is True for event in events) == 2
    partial = next(event for event in events if event.details["memory_scan_complete"] is False)
    assert "native traversal budget reached" in partial.details["memory_scan_limit_reason"]
    assert bus.recent(1)[0].details["memory_scan_complete"] is True
    assert bus.recent(1)[0].details["memory_scan_limit_reason"] == ""
    assert module.dashboard_snapshot()["stats"]["repeat_suppressed"] == 2
    assert all(event.details["response_authorized"] is False for event in events)
    assert all(event.details["disposition"] == "exposure" for event in events)
    assert all(bus.verify(event) for event in events)


def test_spyware_repeat_identity_preserves_equal_float_distinct_native_birth_ticks():
    module, bus = make_module()
    ticks = _birth_ticks(NOW - 10)
    objects = [MemoryProcessIdentity(45001, ticks + offset, 0) for offset in (0, 1)]
    assert objects[0].create_time == objects[1].create_time
    receipts = [memory_identity_receipt(
        source="memory.windows.virtualquery", request_id="a" * 32, pid=45001,
        expected_create_time=None, before=obj, after=obj, started_at=NOW,
        finished_at=NOW, handle_closed=True) for obj in objects]
    for receipt in receipts:
        finding = _exposure(process_create_time=receipt.before.create_time,
                            memory_identity=receipt.to_dict())
        module._publish(finding, local_authority=True)
        module._publish(finding, local_authority=True)
    events = bus.recent(10)
    assert len(events) == 2
    assert len({event.details["incident_id"] for event in events}) == 2
    assert module.dashboard_snapshot()["stats"]["repeat_suppressed"] == 2
    assert all(event.details["response_authorized"] is False for event in events)
    assert all("response_contract" not in event.details for event in events)
    assert all(bus.verify(event) for event in events)
