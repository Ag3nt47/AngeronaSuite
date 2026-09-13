"""Inert native-API fixtures; never open or inspect a real process."""
from __future__ import annotations

from contextlib import nullcontext
from threading import Event
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus, Severity
from angerona.modules import mem_inject_scanner as memory
from angerona.modules.watchdog_monitor import WatchdogMonitor


class _Kernel:
    def __init__(self):
        self.queries = 0
        self.closed = []
        self.query = lambda _address: None

    def OpenProcess(self, flags, inherit, pid):
        assert flags == memory.PROCESS_QUERY_INFORMATION | memory.PROCESS_VM_READ
        assert inherit is False
        return pid

    def VirtualQueryEx(self, handle, address, pointer, size):
        self.queries += 1
        value = self.query(address.value or 0)
        if value is None:
            return 0
        base, length, protect = value
        mbi = pointer._obj
        mbi.BaseAddress, mbi.RegionSize = base, length
        mbi.Protect = protect
        mbi.Type, mbi.State = memory.MEM_PRIVATE, memory.MEM_COMMIT
        return size

    def CloseHandle(self, handle):
        self.closed.append(handle)


@pytest.fixture
def scanner(monkeypatch):
    module = memory.MemInjectScannerModule()
    module._k32 = _Kernel()
    module._self_pid = 999
    module.bind(EventBus())
    monkeypatch.setattr(memory, "_try_load_kernel32", lambda: module._k32)
    monkeypatch.setattr(memory, "_process_policy_snapshot", lambda: ())
    monkeypatch.setattr(memory.ctypes, "set_last_error", lambda _code: None, raising=False)
    monkeypatch.setattr(memory.ctypes, "get_last_error", lambda: 0, raising=False)
    monkeypatch.setattr(module, "_bound_image_identity", lambda _handle: {})
    monkeypatch.setattr(module, "_enrich_process", lambda _pid: {})
    return module


def test_query_budget_keeps_coverage_partial_and_closes_handle(scanner, monkeypatch):
    scanner._MAX_QUERIES_PER_PID = 3
    scanner._k32.query = lambda address: (address, 4096, 0x04)
    monkeypatch.setattr(scanner, "_get_active_processes", lambda: memory._ProcessEnumeration({101: "fixture.exe"}, True))
    coverage = scanner._scan_all_pids()
    assert scanner._k32.queries == 3
    assert scanner._k32.closed == [101]
    assert coverage.opened == 1 and coverage.scanned == 0
    assert coverage.partial == 1 and not coverage.scan_complete
    assert coverage.health == 0
    assert "scan=partial" in coverage.detail
    assert scanner.first_cycle_complete  # completed bounded work, not full coverage


def test_time_budget_preserves_observed_regions_without_full_scan_credit(scanner, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(memory.time, "monotonic", lambda: now[0])

    def query(address):
        now[0] = 2.1
        return address, 8192, memory.PAGE_EXECUTE_READWRITE

    scanner._k32.query = query
    result = scanner._scan_pid(101, "fixture.exe", ())
    assert result == memory._PidScanResult(True, False, "partial")
    assert scanner._k32.queries == 1
    event = scanner._bus.recent(1)[0]
    assert event.details["memory_scan_complete"] is False
    assert event.details["memory_scan_limit_reason"] == "native traversal budget reached"
    assert event.details["region_count"] == 1
    assert event.severity == Severity.MEDIUM
    assert event.details["active_attack"] is False
    assert "response_contract" not in event.details


def test_existing_64_region_evidence_cap_is_not_full_scan_credit(scanner):
    scanner._k32.query = lambda address: (address, 8192, memory.PAGE_EXECUTE_READWRITE)
    result = scanner._scan_pid(101, "fixture.exe", ())
    assert result == memory._PidScanResult(True, False, "partial")
    assert scanner._k32.queries == 64
    event = scanner._bus.recent(1)[0]
    assert event.details["region_count"] == 64
    assert event.details["memory_scan_complete"] is False


def test_complete_native_walk_still_counts_as_scanned(scanner):
    scanner._k32.query = lambda address: (0, 4096, 0x04) if address == 0 else None
    assert scanner._scan_pid(101, "fixture.exe", ()) == memory._PidScanResult(True, True, "scanned")
    assert scanner._k32.closed == [101]


def test_cancel_inside_native_query_stops_before_hash_or_alert(scanner, monkeypatch):
    def query(address):
        scanner.stop()
        return address, 8192, memory.PAGE_EXECUTE_READWRITE

    scanner._k32.query = query
    monkeypatch.setattr(scanner, "_bound_image_identity", lambda *_: pytest.fail("late image hash"))
    result = scanner._scan_pid(101, "fixture.exe", ())
    assert result.outcome == "cancelled" and not result.scanned
    assert scanner._k32.closed == [101]
    assert scanner._bus.recent(10) == []
    assert not scanner.first_cycle_complete


def test_cancel_during_image_identity_discards_result(scanner, monkeypatch):
    scanner._k32.query = lambda address: (0, 8192, memory.PAGE_EXECUTE_READWRITE) if address == 0 else None

    def image(_handle):
        scanner.stop()
        return {"exe": "synthetic", "image_sha256": "a" * 64}

    monkeypatch.setattr(scanner, "_bound_image_identity", image)
    assert scanner._scan_pid(101, "fixture.exe", ()).outcome == "cancelled"
    assert scanner._bus.recent(10) == []
    assert scanner._seen == {}


def test_cancel_during_enrichment_does_not_emit_or_consume_cooldown(scanner, monkeypatch):
    def enrich(_pid):
        scanner.stop()
        return {}

    monkeypatch.setattr(scanner, "_enrich_process", enrich)
    scanner._alert(101, "fixture.exe", [(0, 8192, memory.PAGE_EXECUTE_READWRITE)])
    assert scanner._bus.recent(10) == []
    assert scanner._seen == {}


def test_existing_cooldown_precedes_hash_and_enrichment_but_never_skips_memory_scan(scanner, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(memory.time, "time", lambda: now[0])
    scanner._seen[101] = now[0]
    scanner._k32.query = lambda address: (0, 8192, memory.PAGE_EXECUTE_READWRITE) if address == 0 else None
    hashes, enrichments = [], []
    monkeypatch.setattr(scanner, "_bound_image_identity", lambda _handle: hashes.append(1) or {})
    monkeypatch.setattr(scanner, "_enrich_process", lambda _pid: enrichments.append(1) or {})
    for instant in (1000.0, 1299.999):
        now[0] = instant
        assert scanner._scan_pid(101, "fixture.exe", ()).scanned
    assert scanner._k32.queries == 4
    assert hashes == enrichments == []
    now[0] = 1300.0
    assert scanner._scan_pid(101, "fixture.exe", ()).scanned
    assert hashes == enrichments == [1]
    assert len(scanner._bus.recent(10)) == 1


def test_cancelled_sweep_does_not_publish_health_or_completed_cycle(scanner, monkeypatch):
    def scan():
        scanner.stop()
        return memory.ProcessCoverage(enumerated=1, scanned=1, enumeration_complete=True)

    monkeypatch.setattr(scanner, "_scan_all_pids", scan)
    monkeypatch.setattr(scanner, "sleep", lambda *_a, **_k: pytest.fail("cancelled cadence"))
    scanner.run()
    assert scanner._coverage == memory.ProcessCoverage()
    assert scanner.health == 0
    assert "Initial" in scanner.health_note
    assert not scanner.first_cycle_complete


def test_cancelled_unsupported_idle_does_not_complete_a_late_cycle(scanner, monkeypatch):
    monkeypatch.setattr(memory, "_try_load_kernel32", lambda: None)

    def sleep(_seconds, *, cycle_complete):
        assert cycle_complete is False
        scanner.stop()

    monkeypatch.setattr(scanner, "sleep", sleep)
    scanner.run()
    assert scanner._cycle_count == 1  # the completed unsupported-capability check
    assert scanner.health == 0
    assert len(scanner._bus.recent(10)) == 1


def test_cancellation_during_loader_drops_startup_notice(scanner, monkeypatch):
    def load():
        scanner.stop()
        return scanner._k32

    monkeypatch.setattr(memory, "_try_load_kernel32", load)
    scanner.run()
    assert scanner._bus.recent(10) == []
    assert not scanner.first_cycle_complete


def test_obsolete_generation_cannot_scan_alert_or_publish_coverage(scanner):
    old_stop = scanner._stop
    scanner._run_context.stop_event = old_stop
    scanner._stop = Event()
    assert scanner._scan_pid(101, "fixture.exe", ()).outcome == "cancelled"
    scanner._alert(101, "fixture.exe", [(0, 8192, memory.PAGE_EXECUTE_READWRITE)])
    assert not scanner._publish_coverage(memory.ProcessCoverage(), old_stop)
    assert scanner._k32.queries == 0
    assert scanner._bus.recent(10) == []
    assert not scanner.first_cycle_complete


def test_repeating_native_process_records_are_bounded_and_partial(scanner):
    scanner._MAX_PROCESS_RECORDS = 3
    scanner._k32.CreateToolhelp32Snapshot = lambda *_: 77

    def record(_handle, pointer):
        pointer._obj.th32ProcessID = 101
        pointer._obj.szExeFile = "fixture.exe"
        return True

    scanner._k32.Process32FirstW = record
    scanner._k32.Process32NextW = record
    enumeration = scanner._get_active_processes()
    assert enumeration.processes == {101: "fixture.exe"}
    assert not enumeration.complete and "limit" in enumeration.error
    assert scanner._k32.closed == [77]


def test_completed_pid_progress_prevents_whole_sweep_false_deadline(scanner, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(memory.time, "monotonic", lambda: now[0])
    scanner._thread = SimpleNamespace(is_alive=lambda: True)
    scanner.status = "running"
    scanner._generation_started_at = now[0]
    scanner._watchdog_deadline_at = 130.0
    processes = {pid: "fixture.exe" for pid in range(101, 106)}
    monkeypatch.setattr(scanner, "_get_active_processes", lambda: memory._ProcessEnumeration(processes, True))

    def scan(_pid, _name, _policy):
        now[0] += 20.0  # real completed PID work in this deterministic fixture
        assert WatchdogMonitor._module_fault(scanner.operational_snapshot()) is None
        return memory._PidScanResult(True, True, "scanned")

    monkeypatch.setattr(scanner, "_scan_pid", scan)
    coverage = scanner._scan_all_pids()
    assert now[0] == 200.0  # exceeds the original 30-second whole-sweep gate
    assert coverage.scanned == 5 and coverage.health == 100 and coverage.scan_complete
    assert scanner._cycle_count == 5
    assert WatchdogMonitor._module_fault(scanner.operational_snapshot()) is None
    now[0] += 31.0
    assert "deadline missed" in WatchdogMonitor._module_fault(scanner.operational_snapshot())


def test_optional_duplicate_memory_map_walk_is_explicitly_unavailable(scanner, monkeypatch):
    import psutil

    process = SimpleNamespace(
        oneshot=nullcontext, exe=lambda: "synthetic.exe", cmdline=lambda: [],
        username=lambda: "fixture", status=lambda: "running", num_threads=lambda: 1,
        create_time=lambda: 1000.0, parent=lambda: SimpleNamespace(name=lambda: "fixture", pid=1),
        children=lambda: [], connections=lambda **_: [],
        memory_info=lambda: SimpleNamespace(rss=0, vms=0),
        memory_maps=lambda: pytest.fail("duplicate full memory-map scan"),
    )
    monkeypatch.setattr(psutil, "Process", lambda _pid: process)
    ctx = memory.MemInjectScannerModule._enrich_process(scanner, 101)
    assert "omitted" in ctx["memory_map_enrichment"]
    assert "dll_count" not in ctx
