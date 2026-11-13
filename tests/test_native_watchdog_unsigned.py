"""Inert protocol tests: these never build or launch the native watchdog."""
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest

from angerona.resilience import native_watchdog as native


KEY = b"k" * 32
NONCE = "a" * 64
BIRTH = "134387267728789675"
IMAGE = r"C:\Angerona\watchdog3.exe"


def frame(**changes):
    value = {"schema": 1, "nonce": NONCE, "pid": 42, "birth_ticks": BIRTH,
             "executable_path": IMAGE, "counter": 2, "core_pid": 9, "core_birth_ticks": "123",
             "core_counter": 3, "core_state": "verified", "signature": {},
             "recovery_available": False}
    value.update(changes)
    payload = json.dumps(value, separators=(",", ":"))
    mac = hmac.new(KEY, b"angerona-watchdog3-observe-v1\0" + payload.encode(), hashlib.sha256).hexdigest()
    return json.dumps({"payload": payload, "mac": mac}).encode()


def parse(raw, previous=1):
    return native._parse_observe_frame(raw, key=KEY, nonce=NONCE, pid=42, birth=BIRTH,
        image=IMAGE, core_pid=9, core_birth="123", previous=previous)


def test_progress_binds_real_generation_and_has_no_response_authority():
    value = parse(frame())
    assert value["core_state"] == "verified"
    assert value["recovery_available"] is False


@pytest.mark.parametrize("changes", [
    {"nonce": "b" * 64}, {"pid": 43}, {"pid": True}, {"birth_ticks": "456"},
    {"executable_path": r"C:\Other\watchdog3.exe"}, {"core_pid": 8},
    {"core_birth_ticks": "456"}, {"counter": 1}, {"counter": True},
    {"counter": 2**64}, {"core_counter": -1}, {"recovery_available": True},
    {"core_state": "response-authorized"}, {"extra_authority": True},
])
def test_progress_rejects_wrong_generation_replay_or_authority(changes):
    with pytest.raises(native.NativeWatchdogError):
        parse(frame(**changes))


def test_progress_rejects_forgery_and_duplicate_json_fields():
    raw = frame().replace(b'"mac": "', b'"mac": "0', 1)
    with pytest.raises(native.NativeWatchdogError):
        parse(raw)
    with pytest.raises(native.NativeWatchdogError):
        native._closed_json(b'{"schema":1,"schema":2}', maximum=100)


def test_memory_status_flatlines_when_progress_stops(monkeypatch):
    monkeypatch.setattr(native.time, "monotonic", lambda: 25.0)
    monkeypatch.setattr(native, "_OBSERVE_CACHE", {
        "state": "active-unsigned", "last_heartbeat_monotonic": 1.0,
        "heartbeat_verified": True, "signature_verified": False,
        "signature_state": "unverified", "generation_id": "42:123:nonce", "pid": 42,
        "mode": "unsigned-observe", "reason": "active", "recovery_available": False})
    status = native.third_watchdog_status()
    assert status["state"] == "stale"
    assert status["heartbeat_verified"] is False
    assert native.third_watchdog_heartbeat()["state"] == "stale"
    assert native._OBSERVE_CACHE["state"] == "active-unsigned"  # copied, no mutable UI authority


def test_inspection_failure_is_unverified_not_false_claim_of_unsigned():
    status = native._signature_projection({"watchdog_sha256": "a" * 64,
        "signature_valid": False, "reason": "revocation status unavailable"}, "a" * 64)
    assert status["signature_verified"] is False
    assert status["signature_state"] == "unverified"
    assert status["signed"] is None


def test_signer_of_different_bytes_never_checks_running_helper_green():
    status = native._signature_projection({"watchdog_sha256": "b" * 64,
        "signature_valid": True, "certificate_sha256": "c" * 64,
        "publisher": "CN=Example", "not_after": "2099-01-01T00:00:00Z"}, "a" * 64)
    assert status["signature_verified"] is False
    assert status["activation_enrolled"] is False


def test_expired_or_stale_signature_receipt_never_stays_verified(monkeypatch):
    monkeypatch.setattr(native.time, "monotonic", lambda: 1001.0)
    monkeypatch.setattr(native, "_OBSERVE_CACHE", {
        "state": "active-reduced", "last_heartbeat_monotonic": 1000.0,
        "heartbeat_verified": True, "signature_verified": True,
        "signature_state": "verified", "signed": True, "signing_checked_monotonic": 1.0,
        "not_after": "2099-01-01T00:00:00Z"})
    assert native.third_watchdog_status()["signature_verified"] is False


def test_stop_before_admission_never_launches_a_child(monkeypatch):
    monitor = native.UnsignedWatchdogMonitor(SimpleNamespace())
    calls = []
    monkeypatch.setattr(native, "_ordinary_observer_session", lambda: calls.append("ordinary"))
    monkeypatch.setattr(native, "_query_process", lambda _pid: pytest.fail("native query after STOP"))
    monkeypatch.setattr(native, "_OBSERVE_CACHE", dict(native._OBSERVE_CACHE))
    monitor.request_stop()
    monitor._admission_committed = True  # inert model of a previously committed owner
    monitor._admission_gate.set()
    monitor._run()
    assert native.third_watchdog_status()["state"] == "stopped"
    assert native.third_watchdog_status()["heartbeat_verified"] is False
    assert calls == []


def test_unknown_or_privileged_token_holds_before_any_binary_admission(monkeypatch):
    monitor = native.UnsignedWatchdogMonitor(SimpleNamespace())
    def refused():
        raise native.NativeWatchdogError("ordinary-user token refused")
    monkeypatch.setattr(native, "_ordinary_observer_session", refused)
    monkeypatch.setattr(native, "_admit_observe_bundle", lambda: pytest.fail("binary admitted before token"))
    monkeypatch.setattr(native, "_OBSERVE_CACHE", dict(native._OBSERVE_CACHE))
    monitor._admission_committed = True  # direct inert codec/permission test
    monitor._admission_gate.set()
    monitor._run()
    assert native.third_watchdog_status()["state"] == "unavailable"
    assert "token refused" in native.third_watchdog_status()["reason"]


def test_signing_review_does_not_execute_candidate_on_gui(monkeypatch):
    from angerona.telemetry import process_snapshot_worker as worker
    monkeypatch.setattr(worker, "on_gui_thread", lambda: True)
    monkeypatch.setattr(native, "_ObserveCommand", lambda *_args: pytest.fail("native child launched on GUI"))
    result = native.inspect_watchdog_candidate(IMAGE)
    assert result["signature_valid"] is False
    assert result["activation_eligible"] is False
    assert "background" in result["reason"]


def test_unproven_child_retirement_holds_custody_without_retry(monkeypatch):
    calls = []
    class Pin:
        def retire(self, _timeout, *, terminate):
            calls.append(("retire", terminate))
            return False
    class Job:
        def members(self):
            pytest.fail("Job cannot be released before exact child retirement")
    command = native._ObserveCommand.__new__(native._ObserveCommand)
    command.closed = False
    command.pin, command.job, command.process, command.file = Pin(), Job(), None, None
    monkeypatch.setattr(native, "_OBSERVE_CLOSE_HOLDS", [])
    with pytest.raises(native.NativeWatchdogError, match="cleanup remains held"):
        command.close()
    command.close()  # Never retry an ambiguous numeric-handle cleanup.
    assert calls == [("retire", True)]
    assert native._OBSERVE_CLOSE_HOLDS == [command]


class _SourceEntries:
    def __init__(self, names):
        self.names, self.seen, self.closed = names, 0, False
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        self.closed = True
    def __iter__(self):
        for name in self.names:
            self.seen += 1
            yield SimpleNamespace(name=name)


def test_source_inventory_caps_all_entries_including_non_go(monkeypatch):
    from pathlib import Path
    entries = _SourceEntries(f"unrelated-{index}.txt" for index in range(10000))
    monkeypatch.setattr(native, "os", SimpleNamespace(scandir=lambda _source: entries))
    monkeypatch.setattr(native, "time", SimpleNamespace(monotonic=lambda: 0.0))
    with pytest.raises(native.NativeWatchdogError, match="entry budget"):
        native._observe_source_inventory(Path("source"), 5.0)
    assert entries.seen == native._OBSERVE_MAX_SOURCE_ENTRIES + 1
    assert entries.closed is True


def test_source_inventory_deadline_expires_before_more_entries_or_launch(monkeypatch):
    from pathlib import Path
    entries = _SourceEntries(["go.mod", "go.sum", "runtime_windows.go"])
    clock = iter([0.0, 6.0])
    monkeypatch.setattr(native, "os", SimpleNamespace(scandir=lambda _source: entries))
    monkeypatch.setattr(native, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    with pytest.raises(native.NativeWatchdogError, match="deadline expired; no helper was launched"):
        native._observe_source_inventory(Path("source"), 5.0)
    assert entries.seen == 1 and entries.closed is True


def test_bounded_source_inventory_preserves_exact_build_input_selection(monkeypatch):
    from pathlib import Path
    entries = _SourceEntries(["runtime_windows.go", "runtime_windows_test.go", "go.mod", "go.sum", "notes.txt"])
    monkeypatch.setattr(native, "os", SimpleNamespace(scandir=lambda _source: entries))
    monkeypatch.setattr(native, "time", SimpleNamespace(monotonic=lambda: 0.0))
    result = native._observe_source_inventory(Path("source"), 5.0)
    assert set(result) == {"runtime_windows.go", "go.mod", "go.sum"}
    assert all(path.parent == Path("source") for path in result.values())
    assert entries.closed is True


@pytest.fixture
def isolated_optional_start(monkeypatch):
    import threading
    monkeypatch.setattr(native, "_OBSERVE_OWNER", None)
    monkeypatch.setattr(native, "_OBSERVE_START_HOLD", None)
    monkeypatch.setattr(native, "_OBSERVE_OWNER_LOCK", threading.Lock())
    monkeypatch.setattr(native, "_OBSERVE_CACHE", dict(native._OBSERVE_CACHE))


def test_optional_duplicate_owner_holds_without_allocating_thread_or_stealing_owner(monkeypatch, isolated_optional_start):
    first = object()
    monkeypatch.setattr(native, "_OBSERVE_OWNER", first)
    monkeypatch.setattr(native, "_make_observe_thread", lambda _target: pytest.fail("duplicate allocated a thread"))
    monitor = native.UnsignedWatchdogMonitor(SimpleNamespace())
    assert monitor.start() is False
    assert native._OBSERVE_OWNER is first
    status = native.third_watchdog_status()
    assert status["state"] == "unavailable" and status["heartbeat_verified"] is False
    assert "another exact owner" in status["reason"]
    monitor.stop()
    assert native._OBSERVE_OWNER is first
    assert native.third_watchdog_status()["reason"] == status["reason"]


def test_optional_thread_construction_failure_releases_only_provably_unspawned_owner(monkeypatch, isolated_optional_start):
    def fail_factory(_target):
        raise RuntimeError("thread object allocation failed")
    monkeypatch.setattr(native, "_make_observe_thread", fail_factory)
    monitor = native.UnsignedWatchdogMonitor(SimpleNamespace())
    assert monitor.start() is False
    assert monitor._start_attempted is False and monitor._thread is None
    assert native._OBSERVE_OWNER is None and native._OBSERVE_START_HOLD is None
    status = native.third_watchdog_status()
    assert status["state"] == "unavailable" and status["start_custody_held"] is False
    assert "allocation failed" in status["reason"]


def test_optional_thread_start_exception_keeps_unknown_owner_and_never_retries_or_joins(monkeypatch, isolated_optional_start):
    calls = []
    class FailedThread:
        ident = None  # These attributes do not prove no late native bootstrap.
        def start(self):
            calls.append("start")
            raise RuntimeError("native start outcome unknown")
        def is_alive(self):
            return False
        def join(self, **_kwargs):
            pytest.fail("unknown thread was joined or retried")
    monkeypatch.setattr(native, "_make_observe_thread", lambda _target: FailedThread())
    monitor = native.UnsignedWatchdogMonitor(SimpleNamespace())
    assert monitor.start() is False
    assert native._OBSERVE_OWNER is monitor and native._OBSERVE_START_HOLD is monitor
    assert monitor._stop.is_set() and monitor._start_custody_held is True
    monitor.stop()
    assert monitor.start() is False
    other = native.UnsignedWatchdogMonitor(SimpleNamespace())
    assert other.start() is False
    assert calls == ["start"]
    status = native.third_watchdog_status()
    assert status["state"] == "unavailable" and status["start_custody_held"] is True
    assert status["heartbeat_verified"] is False


def test_late_bootstrap_after_failed_start_cannot_admit_child_or_release_held_owner(monkeypatch, isolated_optional_start):
    class FailedThread:
        def start(self):
            raise RuntimeError("uncertain start")
    monkeypatch.setattr(native, "_make_observe_thread", lambda _target: FailedThread())
    monkeypatch.setattr(native, "_ordinary_observer_session", lambda: pytest.fail("late bootstrap admitted native work"))
    monitor = native.UnsignedWatchdogMonitor(SimpleNamespace())
    assert monitor.start() is False
    monitor._run()  # Simulate a delayed callback; no thread or child is spawned.
    assert native._OBSERVE_OWNER is monitor and native._OBSERVE_START_HOLD is monitor
    assert native.third_watchdog_status()["state"] == "unavailable"


def test_manager_retains_explicit_failure_without_optional_start_escaping(monkeypatch, isolated_optional_start):
    from angerona.resilience.manager import ResilienceManager
    def fail_constructor(_beat):
        raise RuntimeError("optional constructor failed")
    monkeypatch.setattr(native, "UnsignedWatchdogMonitor", fail_constructor)
    manager = ResilienceManager.__new__(ResilienceManager)
    manager._unsigned_watchdog_enabled = True
    manager._unsigned_watchdog = None
    manager._unsigned_watchdog_start_failure = None
    manager._core_beat = SimpleNamespace()
    manager._component_heartbeat_cache = None
    manager._start_optional_native_watchdog()
    status = manager._native_watchdog_status()
    assert status["state"] == "unavailable" and status["response_authorized"] is False
    assert "existing Core resilience continues" in status["reason"]
    assert manager.component_heartbeats()[0]["state"] == "unavailable"
    assert manager.component_heartbeats()[0]["pid"] == 0


def test_core_heartbeat_ring_and_status_start_continue_despite_optional_start_failure(monkeypatch, isolated_optional_start):
    import threading
    from angerona.resilience.manager import ResilienceManager
    events = []
    class FailedMonitor:
        def __init__(self, _beat):
            pass
        def start(self):
            events.append("optional-start")
            raise RuntimeError("optional thread start failed")
    class ReachedSourceGuard(Exception):
        pass
    def reached_source_guard():
        events.append("source-guard")
        raise ReachedSourceGuard()
    monkeypatch.setattr(native, "UnsignedWatchdogMonitor", FailedMonitor)
    manager = ResilienceManager.__new__(ResilienceManager)
    manager._stop = threading.Event()
    manager._core_beat = SimpleNamespace(beat=lambda: events.append("core-beat"))
    manager._unsigned_watchdog_enabled = True
    manager._unsigned_watchdog = None
    manager._unsigned_watchdog_start_failure = None
    manager._spawn_thread = lambda _target, name: events.append(name)  # inert scheduling receipt
    manager._prepare_source_guard = reached_source_guard
    with pytest.raises(ReachedSourceGuard):
        manager.start()
    assert events == ["core-beat", "core-heartbeat", "ring-drain", "core-status", "optional-start", "source-guard"]
    assert manager._native_watchdog_status()["state"] == "unavailable"


def test_disabled_optional_monitor_does_not_construct_or_start(monkeypatch):
    from angerona.resilience.manager import ResilienceManager
    monkeypatch.setattr(native, "UnsignedWatchdogMonitor", lambda _beat: pytest.fail("disabled monitor constructed"))
    manager = ResilienceManager.__new__(ResilienceManager)
    manager._unsigned_watchdog_enabled = False
    manager._start_optional_native_watchdog()


class _ObservedAdmissionGate:
    """Expose the exact wait boundary to inert concurrent-start regressions."""
    def __init__(self):
        import threading
        self.event = threading.Event()
        self.waiting = threading.Event()
    def wait(self):
        self.waiting.set()
        return self.event.wait()
    def set(self):
        self.event.set()
    def is_set(self):
        return self.event.is_set()


def test_target_waits_before_failed_start_returns_and_allocates_no_native_child(monkeypatch, isolated_optional_start):
    import threading
    from contextlib import contextmanager
    from pathlib import Path
    allocations, ordinary_calls, threads = [], [], []
    finished = threading.Event()
    gate = _ObservedAdmissionGate()
    class StartsThenRaises:
        def __init__(self, target):
            self.target = target
        def start(self):
            def run_target():
                try:
                    self.target()
                finally:
                    finished.set()
            actual = threading.Thread(target=run_target, name="test-observe-start-race", daemon=True)
            threads.append(actual)
            actual.start()
            assert gate.waiting.wait(5.0), "target did not enter the admission wait"
            assert allocations == [] and ordinary_calls == []
            raise RuntimeError("start raised after target entered its gate")
        def join(self, **_kwargs):
            pytest.fail("production joined an uncertain start wrapper")
    @contextmanager
    def admitted_bundle():
        yield Path(IMAGE), "a" * 64
    def candidate_allocation(*_args):
        allocations.append("native child")
        raise native.NativeWatchdogError("inert allocation seam; no process created")
    monkeypatch.setattr(native, "_make_observe_thread", lambda target: StartsThenRaises(target))
    monkeypatch.setattr(native, "_ordinary_observer_session", lambda: ordinary_calls.append("ordinary"))
    monkeypatch.setattr(native, "_query_process", lambda _pid: SimpleNamespace(pid=9, birth_ticks=123, image=IMAGE))
    monkeypatch.setattr(native, "_admit_observe_bundle", admitted_bundle)
    monkeypatch.setattr(native, "_ObserveCommand", candidate_allocation)
    monitor = native.UnsignedWatchdogMonitor(SimpleNamespace(_key=KEY, path=Path(IMAGE)))
    monitor._admission_gate = gate
    try:
        assert monitor.start() is False
        assert gate.waiting.is_set() and gate.is_set()
        assert monitor._admission_committed is False
        assert finished.wait(5.0), "refused target did not retire"
        assert allocations == [] and ordinary_calls == []
        assert native._OBSERVE_START_HOLD is monitor and native._OBSERVE_OWNER is monitor
        monitor.stop()  # Must not join/retry the uncertain wrapper.
    finally:
        monitor._stop.set()
        gate.set()
        for actual in threads:
            actual.join(timeout=2.0)  # Exact test-owned real thread, not production's uncertain wrapper.
        assert all(not actual.is_alive() for actual in threads), "test-owned race target did not retire"


def test_successful_start_return_commits_gate_before_native_admission(monkeypatch, isolated_optional_start):
    import threading
    entered, finished = threading.Event(), threading.Event()
    gate = _ObservedAdmissionGate()
    threads = []
    class SuccessfulStart:
        def __init__(self, target):
            self.target = target
        def start(self):
            def run_target():
                try:
                    self.target()
                finally:
                    finished.set()
            actual = threading.Thread(target=run_target, name="test-observe-start-commit", daemon=True)
            threads.append(actual)
            actual.start()
            assert gate.waiting.wait(5.0), "target did not enter the admission wait"
            assert not entered.is_set(), "native work ran before start returned"
        def join(self, timeout):
            threads[0].join(timeout=timeout)
        def is_alive(self):
            return threads[0].is_alive()
    def ordinary_after_commit():
        assert monitor._admission_committed is True and gate.is_set()
        entered.set()
        raise native.NativeWatchdogError("inert success seam; no native process work")
    monkeypatch.setattr(native, "_make_observe_thread", lambda target: SuccessfulStart(target))
    monkeypatch.setattr(native, "_ordinary_observer_session", ordinary_after_commit)
    monitor = native.UnsignedWatchdogMonitor(SimpleNamespace())
    monitor._admission_gate = gate
    try:
        assert monitor.start() is True
        assert entered.wait(5.0) and finished.wait(5.0)
        assert monitor._admission_committed is True
        assert native._OBSERVE_START_HOLD is None
    finally:
        monitor._stop.set()
        gate.set()
        for actual in threads:
            actual.join(timeout=2.0)
        assert all(not actual.is_alive() for actual in threads), "test-owned commit target did not retire"


def test_monitor_is_single_use_after_first_worker_retires_and_repeated_concurrent_start_cannot_allocate(monkeypatch, isolated_optional_start):
    import threading
    from contextlib import contextmanager
    from pathlib import Path
    targets, factory_calls, allocations, result = [], [], [], []
    first_finished, second_allocated, repeat_finished = threading.Event(), threading.Event(), threading.Event()
    class OwnedTestThread:
        def __init__(self, target, number):
            self.target, self.number = target, number
        def start(self):
            def run_target():
                try:
                    self.target()
                finally:
                    if self.number == 1:
                        first_finished.set()
            actual = threading.Thread(target=run_target, name=f"test-observe-single-use-{self.number}", daemon=True)
            targets.append(actual)
            actual.start()
            if self.number > 1:
                # An old open gate would admit this second target BEFORE its
                # fake start returns. A single-use object never reaches here.
                second_allocated.wait(2.0)
        def join(self, timeout):
            targets[self.number - 1].join(timeout=timeout)
        def is_alive(self):
            return targets[self.number - 1].is_alive()
    def factory(target):
        factory_calls.append(target)
        return OwnedTestThread(target, len(factory_calls))
    @contextmanager
    def bundle():
        yield Path(IMAGE), "a" * 64
    def child_allocation(*_args):
        allocations.append("inert native-child allocation seam")
        if len(allocations) > 1:
            second_allocated.set()
        raise native.NativeWatchdogError("inert seam; no process was created")
    monkeypatch.setattr(native, "_make_observe_thread", factory)
    monkeypatch.setattr(native, "_ordinary_observer_session", lambda: None)
    monkeypatch.setattr(native, "_query_process", lambda _pid: SimpleNamespace(pid=9, birth_ticks=123, image=IMAGE))
    monkeypatch.setattr(native, "_admit_observe_bundle", bundle)
    monkeypatch.setattr(native, "_ObserveCommand", child_allocation)
    monitor = native.UnsignedWatchdogMonitor(SimpleNamespace(_key=KEY, path=Path(IMAGE)))
    repeat = None
    try:
        assert monitor.start() is True
        assert first_finished.wait(5.0), "first exact test-owned target did not retire"
        targets[0].join(timeout=2.0)
        assert not targets[0].is_alive() and native._OBSERVE_OWNER is None
        assert len(allocations) == 1 and monitor._admission_committed is True
        original_gate, original_status = monitor._admission_gate, native.third_watchdog_status()
        def repeat_start():
            try:
                result.append(monitor.start())
            finally:
                repeat_finished.set()
        repeat = threading.Thread(target=repeat_start, name="test-observe-repeat-request", daemon=True)
        repeat.start()
        assert repeat_finished.wait(5.0), "repeat request did not finish"
        repeat.join(timeout=2.0)
        assert result == [False] and len(factory_calls) == len(allocations) == 1
        assert native._OBSERVE_OWNER is None and native._OBSERVE_START_HOLD is None
        assert monitor._admission_gate is original_gate and monitor._admission_committed is True
        current = native.third_watchdog_status()
        assert (current["state"], current["reason"]) == (original_status["state"], original_status["reason"])
    finally:
        monitor._stop.set()
        monitor._admission_gate.set()
        if repeat is not None:
            repeat.join(timeout=2.0)
        for actual in targets:
            actual.join(timeout=2.0)
        assert (repeat is None or not repeat.is_alive()) and all(not actual.is_alive() for actual in targets)


def test_repeated_start_of_active_object_does_not_replace_live_status_or_owner(monkeypatch, isolated_optional_start):
    class PendingTestThread:
        def start(self):
            pass  # No thread/process is created by this inert fixture.
    calls = []
    monkeypatch.setattr(native, "_make_observe_thread", lambda _target: calls.append("factory") or PendingTestThread())
    monitor = native.UnsignedWatchdogMonitor(SimpleNamespace())
    assert monitor.start() is True
    native._cache_observe(state="active-unsigned", reason="existing actual-owner snapshot", heartbeat_verified=False)
    assert monitor.start() is False
    assert calls == ["factory"] and native._OBSERVE_OWNER is monitor
    assert native.third_watchdog_status()["reason"] == "existing actual-owner snapshot"
