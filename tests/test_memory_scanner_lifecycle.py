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
        self.birth = 1000.0
        self.exit_filetime = 0
        self.times_available = True
        self.identity_reads = 0

    def OpenProcess(self, flags, inherit, pid):
        assert flags == memory.PROCESS_QUERY_INFORMATION | memory.PROCESS_VM_READ
        assert inherit is False
        return pid

    def GetProcessId(self, handle):
        self.identity_reads += 1
        return handle

    def GetProcessTimes(self, handle, created, exited, kernel, user):
        if not self.times_available:
            return False
        ticks = 116444736000000000 + int(self.birth * 10000000)
        for pointer, value in ((created, ticks), (exited, self.exit_filetime)):
            pointer._obj.dwLowDateTime = value & 0xFFFFFFFF
            pointer._obj.dwHighDateTime = value >> 32
        return True

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
        return True


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


def test_native_walk_preserves_query_coverage_while_pacing_between_batches(scanner, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(memory.time, "monotonic", lambda: now[0])
    scanner._k32.query = lambda address: (address, 4096, 0x04) if address < 512 * 4096 else None
    checkpoints = []

    def checkpoint(completed, *, batch_size):
        checkpoints.append((completed, batch_size))
        if completed and completed % batch_size == 0:
            now[0] += 1.1
        return True

    monkeypatch.setattr(scanner, "background_checkpoint", checkpoint)
    result = scanner._scan_pid(101, "fixture.exe", ())
    assert result == memory._PidScanResult(True, True, "scanned")
    assert checkpoints == [(index, 256) for index in range(513)]
    assert scanner._k32.queries == 513
    assert scanner._k32.closed == [101]
    assert scanner._bus.recent(10) == []


def test_slow_native_walk_can_yield_before_256_queries_without_losing_coverage(scanner, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(memory.time, "monotonic", lambda: now[0])
    checkpoints = []

    def query(address):
        now[0] += 0.2
        return (address, 4096, 0x04) if address < 3 * 4096 else None

    def checkpoint(completed, *, batch_size):
        checkpoints.append((completed, batch_size, scanner._k32.queries))
        if completed in (1, 2):
            now[0] += 1.1
        return True

    scanner._k32.query = query
    monkeypatch.setattr(scanner, "background_checkpoint", checkpoint)

    assert scanner._scan_pid(101, "fixture.exe", ()) == memory._PidScanResult(True, True, "scanned")
    assert checkpoints == [(index, 256, index) for index in range(4)]
    assert now[0] == pytest.approx(3.0)  # 0.8s native work plus 2.2s cooperative rest
    assert scanner._k32.queries == 4
    assert scanner._k32.closed == [101]
    assert scanner._bus.recent(10) == []


def test_native_walk_pacing_allowance_is_bounded_and_never_claims_complete(scanner, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(memory.time, "monotonic", lambda: now[0])
    scanner._k32.query = lambda address: (address, 4096, 0x04)

    def checkpoint(completed, *, batch_size):
        assert batch_size == 256
        if completed:
            now[0] += 10.0
        return True

    monkeypatch.setattr(scanner, "background_checkpoint", checkpoint)
    assert scanner._scan_pid(101, "fixture.exe", ()) == memory._PidScanResult(True, False, "partial")
    assert scanner._k32.queries == 1
    assert scanner._k32.closed == [101]


def test_many_early_yields_share_one_cumulative_pacing_allowance(scanner, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(memory.time, "monotonic", lambda: now[0])
    scanner._k32.query = lambda address: (address, 4096, 0x04)
    checkpoints = []

    def checkpoint(completed, *, batch_size):
        assert batch_size == 256
        checkpoints.append(completed)
        if completed:
            now[0] += 1.0
        return True

    monkeypatch.setattr(scanner, "background_checkpoint", checkpoint)

    assert scanner._scan_pid(101, "fixture.exe", ()) == memory._PidScanResult(True, False, "partial")
    # The original 2s budget plus the single 6.4s rest allowance cannot be
    # extended indefinitely by receiving many sub-256-query checkpoints.
    assert now[0] == 9.0
    assert checkpoints == list(range(10))
    assert scanner._k32.queries == 9
    assert scanner._k32.closed == [101]
    assert scanner._bus.recent(10) == []


def test_native_walk_stop_during_cooperative_wait_closes_handle_without_more_queries(scanner, monkeypatch):
    scanner._k32.query = lambda address: (address, 4096, 0x04)

    def checkpoint(completed, *, batch_size):
        assert batch_size == 256
        if not completed:
            return True
        scanner._stop.set()
        return False

    monkeypatch.setattr(scanner, "background_checkpoint", checkpoint)
    assert scanner._scan_pid(101, "fixture.exe", ()) == memory._PidScanResult(True, False, "cancelled")
    assert scanner._k32.queries == 1
    assert scanner._k32.closed == [101]
    assert scanner._bus.recent(10) == []


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
    scanner._seen[(101, 900.0)] = now[0]
    scanner._k32.birth = 900.0
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


def test_reused_pid_has_independent_cooldown_bound_to_scanned_handle(scanner, monkeypatch):
    scanner._k32.birth = 100.0
    scanner._k32.query = lambda address: (0, 8192, memory.PAGE_EXECUTE_READWRITE) if address == 0 else None
    hashes = []
    monkeypatch.setattr(scanner, "_bound_image_identity", lambda _handle: hashes.append(1) or {})
    for created in (100.0, 200.0, 200.0):
        scanner._k32.birth = created
        assert scanner._scan_pid(101, "fixture.exe", ()).scanned
    assert scanner._k32.queries == 6
    assert len(hashes) == 2
    events = scanner._bus.recent(10)
    assert sorted(event.details["process_create_time"] for event in events) == [100.0, 200.0]
    assert set(scanner._seen) == {(101, 100.0), (101, 200.0)}


def test_missing_birth_evidence_cannot_create_pid_only_cooldown(scanner, monkeypatch):
    scanner._k32.query = lambda address: (0, 8192, memory.PAGE_EXECUTE_READWRITE) if address == 0 else None
    scanner._k32.times_available = False
    for _ in range(2):
        assert scanner._scan_pid(101, "fixture.exe", ()).scanned
    assert len(scanner._bus.recent(10)) == 2
    assert scanner._seen == {}


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


def test_memory_alert_enrichment_cannot_supply_missing_inspected_birth(scanner, monkeypatch):
    scanner._k32.times_available = False
    scanner._k32.query = lambda address: (0, 8192, memory.PAGE_EXECUTE_READWRITE) if address == 0 else None
    monkeypatch.setattr(scanner, "_enrich_process", lambda _pid: {"process_create_time": 2000.0})
    assert scanner._scan_pid(101, "fixture.exe", ()).scanned
    event, = scanner._bus.recent(10)
    assert event.details["process_create_time"] is None
    assert event.details["pid_enrichment_create_time"] == 2000.0
    assert event.details["pid_enrichment_identity_bound"] is False
    assert event.details["response_eligible"] is False
    assert event.details["memory_identity_status"] == "unavailable"
    assert scanner._seen == {} and scanner._k32.closed == [101]


def test_memory_alert_retains_native_birth_and_closes_before_pid_enrichment(scanner, monkeypatch):
    scanner._k32.query = lambda address: (0, 8192, memory.PAGE_EXECUTE_READWRITE) if address == 0 else None
    def enrich(_pid):
        assert scanner._k32.closed == [101]
        return {"process_create_time": 2000.0}
    monkeypatch.setattr(scanner, "_enrich_process", enrich)
    monkeypatch.setattr(scanner, "_bound_image_identity", lambda _handle: {"process_create_time": 3000.0})
    assert scanner._scan_pid(101, "fixture.exe", ()).scanned
    event, = scanner._bus.recent(10)
    assert event.details["process_create_time"] == 1000.0
    assert event.details["pid_enrichment_create_time"] == 2000.0
    assert event.details["response_eligible"] is True
    identity = memory.parse_memory_identity(event.details["memory_identity"])
    assert identity.bound and identity.before.pid == 101
    assert identity.before == identity.after and identity.handle_closed is True
    assert scanner._k32.identity_reads == 2


@pytest.mark.parametrize("failure", ["birth-changed", "pid-mismatch", "exited", "recheck-denied", "close-failed"])
def test_memory_scanner_unbound_native_receipt_never_uses_enriched_identity(scanner, monkeypatch, failure):
    scanner._k32.query = lambda address: (0, 8192, memory.PAGE_EXECUTE_READWRITE) if address == 0 else None
    original = scanner._k32.GetProcessId
    def get_pid(handle):
        pid = original(handle)
        if scanner._k32.identity_reads == 2:
            if failure == "birth-changed":
                scanner._k32.birth = 2000.0
            elif failure == "exited":
                scanner._k32.exit_filetime = 116444736000000001
            elif failure == "recheck-denied":
                scanner._k32.times_available = False
        return pid + 1 if failure == "pid-mismatch" else pid
    scanner._k32.GetProcessId = get_pid
    if failure == "close-failed":
        def close(handle):
            scanner._k32.closed.append(handle)
            return False
        scanner._k32.CloseHandle = close
    monkeypatch.setattr(scanner, "_enrich_process", lambda _pid: {"process_create_time": 2000.0})
    assert scanner._scan_pid(101, "fixture.exe", ()).scanned
    event, = scanner._bus.recent(10)
    assert event.details["region_count"] == 1
    assert event.details["process_create_time"] is None and event.details["response_eligible"] is False
    assert event.details["memory_identity_status"] in {"mismatch", "unavailable"}
    assert scanner._seen == {} and scanner._k32.closed == [101]


@pytest.mark.parametrize("failure", ["denied", "raised", "malformed"])
def test_memory_scanner_partial_failure_preserves_positive_metadata_and_owned_cleanup(scanner, monkeypatch, failure):
    original = scanner._k32.VirtualQueryEx
    scanner._k32.query = lambda address: (0, 8192, memory.PAGE_EXECUTE_READWRITE)
    def query(handle, address, pointer, size):
        if scanner._k32.queries:
            if failure == "raised":
                raise OSError("inert metadata failure")
            return 0 if failure == "denied" else 1
        return original(handle, address, pointer, size)
    scanner._k32.VirtualQueryEx = query
    monkeypatch.setattr(memory.ctypes, "get_last_error", lambda: 5, raising=False)
    result = scanner._scan_pid(101, "fixture.exe", ())
    assert result.outcome == "partial" and not result.scanned
    event, = scanner._bus.recent(10)
    assert event.details["region_count"] == 1 and event.details["memory_scan_complete"] is False
    assert event.details["response_eligible"] is True
    assert scanner._k32.closed == [101]


def test_direct_memory_alert_without_native_receipt_keeps_birth_hint_advisory(scanner, monkeypatch):
    monkeypatch.setattr(scanner, "_enrich_process", lambda _pid: {"process_create_time": 2000.0})
    scanner._alert(101, "fixture.exe", [(0, 8192, memory.PAGE_EXECUTE_READWRITE)],
                   bound_image={"process_create_time": 1000.0})
    event, = scanner._bus.recent(10)
    assert event.details["process_create_time"] is None
    assert event.details["pid_enrichment_create_time"] == 2000.0
    assert event.details["memory_identity"] is None and event.details["response_eligible"] is False
    assert scanner._seen == {}
